"""Layer 2 Unified CapabilityEngine for SNOW V2.

Unifies capability execution, shared capability instance ownership, principal-aware
authorization, security policy enforcement, and structured results across all callers:
- Local in-process MCP (SnowMcpBridge)
- Loopback IPC (SnowIpcServer)
- Remote authenticated WebSocket dispatch (SnowWebSocketServer)
- SNOW CLI (snow cli)

Security Invariants:
1. Single Execution Boundary: All callers execute capabilities via CapabilityEngine.
2. Safe Principal Default: Missing context defaults to AI_MCP (least privilege).
3. Anti-Spoofing: Caller payloads cannot override context principal or device identity.
4. Local-First: Local Windows capabilities execute in-process without requiring the networking daemon.
"""

from __future__ import annotations

import asyncio
import ctypes
from dataclasses import dataclass, field
import logging
import os
from pathlib import Path
import secrets
import sys
import time
from typing import Any, Dict, Optional, Set

from snow.capabilities.windows.apps import WindowsAppLauncher
from snow.capabilities.windows.clipboard import WindowsClipboardManager
from snow.capabilities.windows.files import WindowsFileManager
from snow.capabilities.windows.processes import WindowsProcessMonitor
from snow.capabilities.windows.telemetry import WindowsTelemetry
from snow.capabilities.windows.terminal import (
    TerminalSecurityTier,
    WindowsTerminalExecutor,
)
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.policy import (
    ACTION_TO_CAPABILITY,
    CAPABILITY_DESKTOP_APP_LAUNCH,
    CAPABILITY_DESKTOP_CLIPBOARD_READ,
    CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    CAPABILITY_DESKTOP_EXEC,
    CAPABILITY_DESKTOP_FILES_DOWNLOAD,
    CAPABILITY_DESKTOP_FILES_LIST,
    CAPABILITY_DESKTOP_STATUS,
    CAPABILITY_FILE_TRANSFER,
    PeerCapabilityPolicy,
)

logger = logging.getLogger(__name__)

# Extended action to capability mapping for unified engine
ENGINE_ACTION_MAP: dict[str, str] = {
    # Telemetry
    "windows_system_info": CAPABILITY_DESKTOP_STATUS,
    "desktop_status": CAPABILITY_DESKTOP_STATUS,
    "system_info": CAPABILITY_DESKTOP_STATUS,
    "windows_battery": CAPABILITY_DESKTOP_STATUS,
    "desktop_battery": CAPABILITY_DESKTOP_STATUS,
    "battery": CAPABILITY_DESKTOP_STATUS,
    # Processes
    "windows_processes": CAPABILITY_DESKTOP_STATUS,
    "desktop_processes": CAPABILITY_DESKTOP_STATUS,
    "processes": CAPABILITY_DESKTOP_STATUS,
    # Apps
    "windows_launch_app": CAPABILITY_DESKTOP_APP_LAUNCH,
    "desktop_app_launch": CAPABILITY_DESKTOP_APP_LAUNCH,
    # Files
    "windows_file_read": CAPABILITY_DESKTOP_FILES_LIST,
    "desktop_file_read": CAPABILITY_DESKTOP_FILES_LIST,
    "windows_file_write": CAPABILITY_DESKTOP_FILES_LIST,
    "desktop_file_write": CAPABILITY_DESKTOP_FILES_LIST,
    "windows_file_list": CAPABILITY_DESKTOP_FILES_LIST,
    "desktop_file_list": CAPABILITY_DESKTOP_FILES_LIST,
    "windows_file_search": CAPABILITY_DESKTOP_FILES_LIST,
    "desktop_file_search": CAPABILITY_DESKTOP_FILES_LIST,
    # Terminal
    "windows_terminal_exec": CAPABILITY_DESKTOP_EXEC,
    "desktop_exec": CAPABILITY_DESKTOP_EXEC,
    # Clipboard
    "windows_clipboard_get": CAPABILITY_DESKTOP_CLIPBOARD_READ,
    "desktop_clipboard_get": CAPABILITY_DESKTOP_CLIPBOARD_READ,
    "windows_clipboard_set": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "desktop_clipboard_set": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
}


@dataclass(frozen=True)
class CapabilityRequest:
    """Standardized invocation request for any capability across local or remote paths."""

    action: str
    params: dict = field(default_factory=dict)
    target_device: str | None = None


@dataclass
class CapabilityResponse:
    """Standardized structured response returned by CapabilityEngine."""

    success: bool
    status: str
    data: dict | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert response to dictionary format for wire or IPC transmission."""
        return {
            "success": self.success,
            "status": self.status,
            "data": self.data,
            "error": self.error,
        }


class CapabilityEngine:
    """Layer 2 central capability execution engine for SNOW V2."""

    def __init__(
        self,
        telemetry: Optional[WindowsTelemetry] = None,
        processes: Optional[WindowsProcessMonitor] = None,
        files: Optional[WindowsFileManager] = None,
        apps: Optional[WindowsAppLauncher] = None,
        terminal: Optional[WindowsTerminalExecutor] = None,
        clipboard: Optional[WindowsClipboardManager] = None,
        policy: Optional[PeerCapabilityPolicy] = None,
        allowed_roots: Optional[list[Path | str]] = None,
        node_registry: Optional[Any] = None,
    ) -> None:
        self.telemetry = telemetry or WindowsTelemetry()
        self.processes = processes or WindowsProcessMonitor()
        self.files = files or WindowsFileManager(allowed_roots=allowed_roots)
        self.apps = apps or WindowsAppLauncher()
        self.terminal = terminal or WindowsTerminalExecutor()
        self.clipboard = clipboard or WindowsClipboardManager()
        self.policy = policy or PeerCapabilityPolicy()
        self.node_registry = node_registry

        # Confirmation ticket registry for trusted two-step confirmation
        self._tickets: dict[str, dict[str, Any]] = {}

    def issue_confirmation_ticket(
        self, device_id: str, command: str, ttl_seconds: float = 60.0
    ) -> str:
        """Issue a server-validated single-use confirmation ticket for an owner command."""
        ticket = secrets.token_hex(16)
        self._tickets[ticket] = {
            "device_id": device_id,
            "command": command.strip(),
            "expires_at": time.monotonic() + ttl_seconds,
        }
        return ticket

    def validate_confirmation_ticket(
        self, ticket: str, device_id: str, command: str
    ) -> bool:
        """Validate and consume a single-use confirmation ticket."""
        if not ticket or not isinstance(ticket, str):
            return False
        rec = self._tickets.pop(ticket, None)
        if not rec:
            return False
        if time.monotonic() > rec["expires_at"]:
            return False
        if rec["device_id"] != device_id or rec["command"] != command.strip():
            return False
        return True

    async def execute(
        self,
        request: CapabilityRequest,
        ctx: Optional[ExecutionContext] = None,
    ) -> CapabilityResponse:
        """Execute a capability request under the provided ExecutionContext.

        Args:
            request: The capability request (action, params, optional target).
            ctx: Immutable execution context (defaults to AI_MCP if omitted).

        Returns:
            CapabilityResponse with structured success, status, data, and error.
        """
        # 1. Ensure immutable context with safe default
        effective_ctx = ctx or ExecutionContext(
            principal=ExecutionPrincipal.AI_MCP, origin="engine_default"
        )

        action = (request.action or "").strip().lower()
        if not action:
            return CapabilityResponse(
                success=False,
                status="INVALID_ACTION",
                error="Action must be a non-empty string.",
            )

        # 2. Extract and sanitize parameters (prevent caller overriding authority)
        params = dict(request.params or {})
        params.pop("principal", None)
        params.pop("trust_tier", None)
        params.pop("execution_principal", None)

        # 3. Policy Authorization Check (for peer devices or remote contexts)
        capability = ENGINE_ACTION_MAP.get(action)
        if capability and effective_ctx.device_id and self.policy:
            if not self.policy.is_authorized(
                effective_ctx.device_id, capability, ctx=effective_ctx
            ):
                logger.warning(
                    "CapabilityEngine denied: device [%s] lacks capability '%s'",
                    effective_ctx.device_id,
                    capability,
                )
                return CapabilityResponse(
                    success=False,
                    status="UNAUTHORIZED",
                    error=f"Capability '{capability}' is not authorized for device '{effective_ctx.device_id}'.",
                )

        # 4. Route to capability implementations
        try:
            return await self._dispatch_action(action, params, effective_ctx)
        except Exception as exc:
            logger.error("Unexpected error executing capability action '%s': %s", action, exc, exc_info=True)
            return CapabilityResponse(
                success=False,
                status="INTERNAL_ERROR",
                error=f"Internal error executing '{action}': {exc}",
            )

    async def _dispatch_action(
        self, action: str, params: dict[str, Any], ctx: ExecutionContext
    ) -> CapabilityResponse:
        """Internal dispatch router executing Windows capabilities."""

        # --- Telemetry ---
        if action in ("windows_system_info", "desktop_status", "system_info"):
            data = await self.telemetry.get_system_telemetry()
            return CapabilityResponse(success=True, status="SUCCESS", data=data)

        if action in ("windows_battery", "desktop_battery", "battery"):
            res = await self.telemetry.get_battery_info()
            is_ok = res.get("status") != "ERROR" if isinstance(res, dict) else True
            return CapabilityResponse(
                success=is_ok,
                status="SUCCESS" if is_ok else "ERROR",
                data=res if isinstance(res, dict) else None,
                error=res.get("error") if isinstance(res, dict) else None,
            )

        # --- Processes ---
        if action in ("windows_processes", "desktop_processes", "processes"):
            limit = int(params.get("limit", 25))
            sort_by = str(params.get("sort_by", "memory"))
            res = await self.processes.list_processes(limit=limit, sort_by=sort_by)
            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res if is_ok else None,
                error=res.get("error"),
            )

        # --- Applications & Workstation Lock ---
        if action in ("windows_launch_app", "desktop_app_launch"):
            app_name = params.get("app_name")
            if not app_name or not isinstance(app_name, str):
                return CapabilityResponse(
                    success=False,
                    status="INVALID_ARGUMENT",
                    error="app_name must be a non-empty string.",
                )

            canonical = app_name.strip().lower()
            if canonical == "lock_screen":
                success = True
                msg = "Workstation locked successfully."
                if sys.platform == "win32":
                    try:
                        res_val = ctypes.windll.user32.LockWorkStation()
                        success = bool(res_val != 0)
                        if not success:
                            msg = "LockWorkStation returned 0."
                    except Exception as exc:
                        success = False
                        msg = str(exc)
                return CapabilityResponse(
                    success=success,
                    status="SUCCESS" if success else "LOCK_FAILED",
                    data={"app_name": "lock_screen", "message": msg},
                    error=None if success else msg,
                )

            res = await self.apps.launch_app(app_name=app_name, ctx=ctx)
            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res,
                error=res.get("error"),
            )

        # --- Files ---
        if action in ("windows_file_read", "desktop_file_read"):
            file_path = params.get("file_path", "")
            max_bytes = int(params.get("max_bytes", 256 * 1024))
            res = await self.files.read_file(file_path=file_path, max_bytes=max_bytes, ctx=ctx)
            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res,
                error=res.get("error"),
            )

        if action in ("windows_file_write", "desktop_file_write"):
            file_path = params.get("file_path", "")
            content = params.get("content", "")
            overwrite = bool(params.get("overwrite", False))
            max_bytes = int(params.get("max_bytes", 256 * 1024))
            res = await self.files.write_file(
                file_path=file_path,
                content=content,
                overwrite=overwrite,
                max_bytes=max_bytes,
                ctx=ctx,
            )
            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res,
                error=res.get("error"),
            )

        if action in ("windows_file_list", "desktop_file_list"):
            directory_path = params.get("directory_path", "")
            limit = int(params.get("limit", 50))
            res = await self.files.list_files(directory_path=directory_path, limit=limit, ctx=ctx)
            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res,
                error=res.get("error"),
            )

        if action in ("windows_file_search", "desktop_file_search"):
            query = params.get("query", "")
            root_path = params.get("root_path", "")
            limit = int(params.get("limit", 50))
            res = await self.files.search_files(query=query, root_path=root_path, limit=limit, ctx=ctx)
            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res,
                error=res.get("error"),
            )

        # --- Terminal Command Execution ---
        if action in ("windows_terminal_exec", "desktop_exec"):
            command = params.get("command")
            if not command or not isinstance(command, str) or not command.strip():
                return CapabilityResponse(
                    success=False,
                    status="INVALID_ARGUMENT",
                    error="command must be a non-empty string.",
                )

            cwd = params.get("cwd")
            timeout = 30.0
            if "timeout" in params:
                try:
                    timeout = max(1.0, min(float(params["timeout"]), 120.0))
                except (ValueError, TypeError):
                    timeout = 30.0

            confirmed = bool(params.get("confirmed", False))
            confirmation_ticket = params.get("confirmation_ticket")

            # Validate server-issued confirmation ticket if present
            if confirmation_ticket and ctx.device_id:
                if self.validate_confirmation_ticket(confirmation_ticket, ctx.device_id, command):
                    confirmed = True
                else:
                    logger.warning("Invalid or expired confirmation ticket from [%s]", ctx.device_id)
                    confirmed = False

            res = await self.terminal.execute_command(
                command=command.strip(),
                cwd=cwd,
                timeout=timeout,
                ctx=ctx,
                confirmed=confirmed,
                confirmation_ticket=confirmation_ticket,
            )

            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res,
                error=res.get("error") if not is_ok else None,
            )

        # --- Clipboard ---
        if action in ("windows_clipboard_get", "desktop_clipboard_get"):
            res = await self.clipboard.get_clipboard()
            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res if is_ok else None,
                error=res.get("error"),
            )

        if action in ("windows_clipboard_set", "desktop_clipboard_set"):
            text = params.get("text", "")
            res = await self.clipboard.set_clipboard(text=text)
            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res if is_ok else None,
                error=res.get("error"),
            )

        # --- Device Registry Queries ---
        if action in ("list_devices", "device_list", "devices"):
            if self.node_registry is not None:
                nodes = self.node_registry.list_nodes()
                res = [node.to_summary_dict() for node in nodes]
                return CapabilityResponse(
                    success=True,
                    status="SUCCESS",
                    data={"devices": res},
                )
            return CapabilityResponse(
                success=False,
                status="REGISTRY_UNAVAILABLE",
                error="NodeRegistry is not configured in CapabilityEngine.",
            )

        if action in ("get_device_status", "device_status"):
            target = params.get("target") or params.get("device_id")
            if not target:
                return CapabilityResponse(
                    success=False,
                    status="INVALID_ARGUMENT",
                    error="Target device identifier is required.",
                )
            if self.node_registry is not None:
                node, err = self.node_registry.resolve_target(target)
                if node:
                    return CapabilityResponse(
                        success=True,
                        status="SUCCESS",
                        data=node.to_dict(include_endpoints=True),
                    )
                return CapabilityResponse(
                    success=False,
                    status=err or "DEVICE_NOT_FOUND",
                    error=f"Device resolution failed: {err}",
                )
            return CapabilityResponse(
                success=False,
                status="REGISTRY_UNAVAILABLE",
                error="NodeRegistry is not configured in CapabilityEngine.",
            )

        # Unsupported Action
        return CapabilityResponse(
            success=False,
            status="UNKNOWN_ACTION",
            error=f"Unsupported capability action: '{action}'",
        )
