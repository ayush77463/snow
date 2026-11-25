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
import hashlib
import logging
import os
from pathlib import Path
import secrets
import sys
import time
from typing import Any, Dict, Optional, Set
import urllib.parse

from snow.capabilities.clipboard_buffer import ClipboardRingBuffer
from snow.capabilities.windows.apps import WindowsAppLauncher
from snow.capabilities.windows.clipboard import WindowsClipboardManager
from snow.capabilities.windows.files import WindowsFileManager
from snow.capabilities.windows.media import WindowsMediaController
from snow.capabilities.windows.processes import WindowsProcessMonitor
from snow.capabilities.windows.system import WindowsSystemControls
from snow.capabilities.windows.telemetry import WindowsTelemetry
from snow.capabilities.windows.terminal import (
    TerminalSecurityTier,
    WindowsTerminalExecutor,
)
from snow.security.approval import ApprovalPolicyEngine, ApprovalRequest, ApprovalStatus
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
    "windows_active_window": CAPABILITY_DESKTOP_STATUS,
    "snow_windows_active_window": CAPABILITY_DESKTOP_STATUS,
    "windows_list_windows": CAPABILITY_DESKTOP_STATUS,
    "snow_windows_list_windows": CAPABILITY_DESKTOP_STATUS,
    "windows_focus_window": CAPABILITY_DESKTOP_APP_LAUNCH,
    "snow_windows_focus_window": CAPABILITY_DESKTOP_APP_LAUNCH,
    "windows_notify": CAPABILITY_DESKTOP_STATUS,
    "snow_windows_notify": CAPABILITY_DESKTOP_STATUS,
    "windows_lock_screen": CAPABILITY_DESKTOP_APP_LAUNCH,
    "snow_windows_lock_screen": CAPABILITY_DESKTOP_APP_LAUNCH,
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
    "android_clipboard_push": "android.clipboard.set",
    "snow_android_clipboard_push": "android.clipboard.set",
    "clipboard_push": "android.clipboard.set",
    # Shared Clipboard Ring Buffer (Phase 26B)
    "clipboard_buffer_list": CAPABILITY_DESKTOP_CLIPBOARD_READ,
    "clipboard_buffer_add": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "clipboard_buffer_pin": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "clipboard_buffer_unpin": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "clipboard_buffer_delete": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "clipboard_buffer_clear": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "clipboard_buffer_apply": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    # Media & Share & Audit (Phase 21)
    "media_control": "media_control",
    "windows_media_control": "media_control",
    "share_link": "share_link",
    "windows_share_link": "share_link",
    "activity_history": "activity_history",
    # Capture & Workflows (Phase 24)
    "windows_screenshot": "windows_screenshot",
    "snow_windows_screenshot": "windows_screenshot",
    "android_screenshot": "android_screenshot",
    "snow_android_screenshot": "android_screenshot",
    "android_camera_capture": "android_camera_capture",
    "snow_android_camera_capture": "android_camera_capture",
    "workflow_run": "workflow_run",
    "snow_workflow_run": "workflow_run",
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


# High-frequency read-only querying actions excluded from activity audit log to prevent log noise
AUDIT_EXCLUDED_ACTIONS = {
    "windows_system_info",
    "windows_battery",
    "activity_history",
    "clipboard_buffer_list",
    "desktop_status",
    "get_device_status",
    "list_devices",
    "system_info",
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
        approval_engine: Optional[ApprovalPolicyEngine] = None,
        media_controller: Optional[WindowsMediaController] = None,
        db_manager: Optional[Any] = None,
        session_router: Optional[Any] = None,
        transfer_manager: Optional[Any] = None,
        storage_manager: Optional[Any] = None,
        http_transfer_server: Optional[Any] = None,
        core_server: Optional[Any] = None,
        clipboard_buffer: Optional[ClipboardRingBuffer] = None,
        system: Optional[WindowsSystemControls] = None,
    ) -> None:
        self.telemetry = telemetry or WindowsTelemetry()
        self.system = system or WindowsSystemControls()
        self.processes = processes or WindowsProcessMonitor()
        self.files = files or WindowsFileManager(allowed_roots=allowed_roots)
        self.apps = apps or WindowsAppLauncher()
        self.terminal = terminal or WindowsTerminalExecutor()
        self.terminal.set_ticket_validator(self.validate_confirmation_ticket)
        self.clipboard = clipboard or WindowsClipboardManager()
        self.clipboard_buffer = clipboard_buffer or ClipboardRingBuffer(db_manager=db_manager)
        self.policy = policy or PeerCapabilityPolicy()
        self.node_registry = node_registry
        self.db_manager = db_manager
        self.approval_engine = approval_engine or ApprovalPolicyEngine(db_manager=db_manager)
        self.media_controller = media_controller or WindowsMediaController()
        self.session_router = session_router
        self.transfer_manager = transfer_manager
        self.storage_manager = storage_manager
        self.http_transfer_server = http_transfer_server
        self.core_server = core_server

        # Confirmation ticket registry for trusted two-step confirmation
        self._tickets: dict[str, dict[str, Any]] = {}

    def issue_confirmation_ticket(
        self, device_id: Optional[str], command: str, ttl_seconds: float = 60.0
    ) -> str:
        """Issue a server-validated single-use confirmation ticket for an owner command."""
        target_dev = (device_id or "").strip() or "local_owner"
        ticket = secrets.token_hex(16)
        self._tickets[ticket] = {
            "device_id": target_dev,
            "command": command.strip(),
            "expires_at": time.monotonic() + ttl_seconds,
        }
        return ticket

    def validate_confirmation_ticket(
        self, ticket: str, device_id: Optional[str], command: str
    ) -> bool:
        """Validate and consume a single-use confirmation ticket."""
        if not ticket or not isinstance(ticket, str):
            return False
        rec = self._tickets.pop(ticket, None)
        if not rec:
            return False
        if time.monotonic() > rec["expires_at"]:
            return False
        target_dev = (device_id or "").strip() or "local_owner"
        if rec["device_id"] != target_dev or rec["command"] != command.strip():
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

        # 4. Catastrophic Invariants Check (Permanent hard-block regardless of caller or ticket)
        if self.approval_engine and self.approval_engine.is_catastrophic(action, params):
            logger.warning("CapabilityEngine permanently blocked catastrophic action '%s'", action)
            return CapabilityResponse(
                success=False,
                status="POLICY_DENIED",
                data={"status": "POLICY_DENIED", "tier": "RESTRICTED_BLOCKED"},
                error="Catastrophic command execution is permanently blocked by security policy.",
            )

        # Phase 26B Policy: AI_MCP is strictly forbidden from deleting or clearing clipboard buffer items
        if action in ("clipboard_buffer_delete", "clipboard_buffer_clear") and effective_ctx.principal == ExecutionPrincipal.AI_MCP:
            logger.warning("CapabilityEngine denied '%s' for AI_MCP caller", action)
            return CapabilityResponse(
                success=False,
                status="POLICY_DENIED",
                error="Principal AI_MCP is not authorized to delete or clear items from clipboard buffer.",
            )

        # 5. Shared Approval Policy Check (Phase 21 & V4.1 Gate 1B Single-Approval Hardening)
        # Terminal command authorization is governed by WindowsTerminalExecutor's 4-tier
        # security policy and confirmation tickets to preserve exact read-only & workspace scoping.
        approval_consumed = False
        if self.approval_engine and action not in ("windows_terminal_exec", "desktop_exec"):
            requires_approval, reason, risk_level = self.approval_engine.evaluate_policy(
                action=action,
                params=params,
                ctx=effective_ctx,
                target_device=request.target_device,
            )
            if requires_approval:
                approval_id = params.get("approval_id")
                if approval_id:
                    ok, msg = self.approval_engine.consume_approval(
                        request_id=approval_id,
                        principal=effective_ctx.principal,
                        action=action,
                        target_device=request.target_device,
                        params=params,
                    )
                    if not ok:
                        logger.warning(
                            "Approval consumption rejected for '%s' (principal=%s): %s",
                            action, effective_ctx.principal, msg
                        )
                        return CapabilityResponse(
                            success=False,
                            status="UNAUTHORIZED",
                            error=f"Approval validation failed: {msg}",
                        )
                    approval_consumed = True
                else:
                    # Issue pending approval request
                    app_req = self.approval_engine.create_request(
                        principal=effective_ctx.principal,
                        action=action,
                        target_device=request.target_device,
                        params=params,
                        reason=reason or "Explicit owner approval required.",
                        risk_level=risk_level or "MEDIUM",
                    )
                    logger.info(
                        "Approval required for '%s' [request_id=%s, risk=%s]",
                        action, app_req.request_id, risk_level
                    )
                    return CapabilityResponse(
                        success=False,
                        status="APPROVAL_REQUIRED",
                        data=app_req.to_dict(),
                        error="Action requires human owner approval.",
                    )

        # 6. Route to capability implementations
        try:
            resp = await self._dispatch_action(
                action, params, effective_ctx, approval_consumed=approval_consumed
            )
        except Exception as exc:
            logger.error("Unexpected error executing capability action '%s': %s", action, exc, exc_info=True)
            resp = CapabilityResponse(
                success=False,
                status="INTERNAL_ERROR",
                error=f"Internal error executing '{action}': {exc}",
            )

        # 6. Audit Activity Log (Phase 21 & Phase 31 Audit Noise Hardening)
        if action not in AUDIT_EXCLUDED_ACTIONS and self.db_manager and hasattr(self.db_manager, "log_activity"):
            try:
                p_str = effective_ctx.principal.value if hasattr(effective_ctx.principal, "value") else str(effective_ctx.principal)
                self.db_manager.log_activity(
                    event_type="CAPABILITY_EXECUTION",
                    capability=action,
                    principal=p_str,
                    target_device=request.target_device,
                    outcome=resp.status,
                    details=params,
                )
            except Exception as exc:
                logger.debug("Failed logging capability execution activity: %s", exc)

        return resp

    async def _dispatch_action(
        self,
        action: str,
        params: dict[str, Any],
        ctx: ExecutionContext,
        approval_consumed: bool = False,
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
                lock_res = await self.system.lock_workstation()
                is_ok = bool(lock_res.get("success"))
                return CapabilityResponse(
                    success=is_ok,
                    status=lock_res.get("status", "SUCCESS" if is_ok else "LOCK_FAILED"),
                    data={"app_name": "lock_screen", **lock_res},
                    error=None if is_ok else lock_res.get("error"),
                )

            res = await self.apps.launch_app(app_name=app_name, ctx=ctx)
            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res,
                error=res.get("error"),
            )

        # --- Windows Active Window / Notification / Workstation Lock ---
        if action in ("windows_active_window", "snow_windows_active_window"):
            res = await self.system.get_active_window()
            return CapabilityResponse(
                success=True,
                status=res.get("status", "SUCCESS"),
                data=res,
            )

        if action in ("windows_notify", "snow_windows_notify"):
            title = params.get("title", "")
            message = params.get("message", "")
            res = await self.system.send_notification(title=title, message=message)
            is_ok = bool(res.get("success"))
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res,
                error=res.get("error"),
            )

        if action in ("windows_lock_screen", "snow_windows_lock_screen"):
            res = await self.system.lock_workstation()
            is_ok = bool(res.get("success"))
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "LOCK_FAILED"),
                data=res,
                error=None if is_ok else res.get("error"),
            )

        if action in ("windows_hotkey", "snow_windows_hotkey"):
            shortcut = params.get("shortcut", "")
            res = await self.system.send_hotkey(shortcut)
            is_ok = bool(res.get("success"))
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "HOTKEY_FAILED"),
                data=res,
                error=None if is_ok else res.get("error"),
            )

        if action in ("windows_brightness_set", "snow_windows_brightness_set"):
            level = params.get("level")
            res = await self.system.set_brightness(level)
            is_ok = bool(res.get("success"))
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "UNSUPPORTED_DISPLAY"),
                data=res,
                error=None if is_ok else res.get("error"),
            )

        if action in ("cross_network_execute", "snow_cross_network_execute"):
            return await self._execute_cross_network_capability(params=params, ctx=ctx)

        if action in ("windows_list_windows", "snow_windows_list_windows"):
            include_empty = bool(params.get("include_empty_titles", False))
            try:
                limit = int(params.get("limit", 50) or 50)
            except (TypeError, ValueError):
                limit = 50
            res = await self.system.list_windows(include_empty_titles=include_empty, limit=limit)
            is_ok = bool(res.get("success", False))
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "LIST_WINDOWS_FAILED"),
                data=res,
                error=None if is_ok else res.get("error"),
            )

        if action in ("windows_focus_window", "snow_windows_focus_window"):
            raw_hwnd = params.get("hwnd")
            parsed_hwnd: Optional[int] = None
            if raw_hwnd is not None and raw_hwnd != "":
                if isinstance(raw_hwnd, bool):
                    return CapabilityResponse(
                        success=False,
                        status="INVALID_ARGUMENT",
                        error="'hwnd' must be a positive integer window handle.",
                    )
                try:
                    parsed_hwnd = int(raw_hwnd)
                except (TypeError, ValueError):
                    return CapabilityResponse(
                        success=False,
                        status="INVALID_ARGUMENT",
                        error="'hwnd' must be a positive integer window handle.",
                    )
            title_contains = params.get("title_contains", "")
            process_name = params.get("process_name", "")
            if title_contains is None:
                title_contains = ""
            if process_name is None:
                process_name = ""
            res = await self.system.focus_window(
                hwnd=parsed_hwnd,
                title_contains=title_contains,
                process_name=process_name,
            )
            is_ok = bool(res.get("success", False))
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "FOCUS_FAILED"),
                data=res,
                error=None if is_ok else res.get("error"),
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
            hide_hidden = bool(params.get("hide_hidden", True))
            res = await self.files.list_files(directory_path=directory_path, limit=limit, ctx=ctx, hide_hidden=hide_hidden)
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
            hide_hidden = bool(params.get("hide_hidden", True))
            res = await self.files.search_files(query=query, root_path=root_path, limit=limit, ctx=ctx, hide_hidden=hide_hidden)
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

            confirmation_ticket = params.get("confirmation_ticket")

            res = await self.terminal.execute_command(
                command=command.strip(),
                cwd=cwd,
                timeout=timeout,
                ctx=ctx,
                confirmation_ticket=confirmation_ticket,
            )

            # Stage 19A / 19B Two-Step Confirmation Ticket Flow:
            # If an OWNER_MANUAL caller requests an OWNER_CONFIRMED command without a ticket,
            # issue a secure single-use confirmation ticket for client-side user approval.
            if (
                res.get("status") == "CONFIRMATION_REQUIRED"
                and ctx
                and ctx.principal == ExecutionPrincipal.OWNER_MANUAL
            ):
                ticket = self.issue_confirmation_ticket(
                    device_id=ctx.device_id,
                    command=command.strip(),
                    ttl_seconds=300.0,
                )
                res["confirmation_ticket"] = ticket
                res["action"] = action

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
            enriched: Optional[dict[str, Any]] = None
            if is_ok and isinstance(res, dict):
                os_text = str(res.get("text") or "")
                has_image = bool(res.get("has_image", False))
                raw_img = res.get("image") if isinstance(res.get("image"), dict) else None
                forbidden_keys = ("file_path", "image_path", "storage_dir", "bytes", "raw_bytes", "image_bytes", "payload_bytes")
                os_image = (
                    {k: v for k, v in raw_img.items() if k not in forbidden_keys}
                    if raw_img is not None
                    else ({"has_image": True} if has_image else None)
                )

                recent_items: list[dict[str, Any]] = []
                if not os_text and getattr(self, "clipboard_buffer", None):
                    try:
                        for entry in self.clipboard_buffer.list_items(limit=3):
                            if isinstance(entry, dict):
                                recent_items.append({k: v for k, v in entry.items() if k not in forbidden_keys})
                    except Exception:
                        recent_items = []

                enriched = {k: v for k, v in res.items() if k not in forbidden_keys}
                enriched["image"] = os_image
                enriched["os_text"] = os_text
                enriched["has_image"] = has_image
                enriched["os_image"] = os_image
                enriched["recent_buffer_items"] = recent_items
                enriched["recent_buffer_count"] = len(recent_items)

            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=enriched,
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

        # --- Shared Clipboard Ring Buffer (Phase 26B) ---
        if action == "clipboard_buffer_list":
            limit = int(params.get("limit", 10))
            items = self.clipboard_buffer.list_items(limit=limit)
            return CapabilityResponse(
                success=True,
                status="SUCCESS",
                data={"items": items, "count": len(items)},
            )

        if action == "clipboard_buffer_add":
            text = params.get("text")
            image_bytes = params.get("image_bytes")
            mime_type = params.get("mime_type", "image/png")
            source_device = params.get("source_device") or (ctx.device_id if ctx and ctx.device_id else "pc")
            is_pinned = bool(params.get("is_pinned", False))
            if image_bytes:
                b_res = self.clipboard_buffer.add_image(
                    image_bytes=image_bytes,
                    mime_type=mime_type,
                    source_device_id=source_device,
                    pin=is_pinned,
                )
            elif text is not None:
                b_res = self.clipboard_buffer.add_text(
                    text=str(text),
                    source_device_id=source_device,
                    pin=is_pinned,
                )
            else:
                return CapabilityResponse(
                    success=False,
                    status="INVALID_ARGUMENT",
                    error="Either 'text' or 'image_bytes' is required.",
                )
            if not b_res.get("success"):
                return CapabilityResponse(
                    success=False,
                    status=b_res.get("status", "ERROR"),
                    error=b_res.get("error", "Failed adding item to clipboard buffer."),
                )
            return CapabilityResponse(
                success=True,
                status="SUCCESS",
                data={"item": b_res.get("item")},
            )

        if action == "clipboard_buffer_pin":
            item_id = params.get("item_id")
            if not item_id:
                return CapabilityResponse(success=False, status="INVALID_ARGUMENT", error="Missing 'item_id'.")
            if "is_pinned" in params and not isinstance(params["is_pinned"], bool):
                return CapabilityResponse(
                    success=False,
                    status="INVALID_ARGUMENT",
                    error="'is_pinned' must be a boolean.",
                )
            desired_pin = params.get("is_pinned", True)
            p_res = (
                self.clipboard_buffer.pin(str(item_id))
                if desired_pin
                else self.clipboard_buffer.unpin(str(item_id))
            )
            if not p_res.get("success"):
                return CapabilityResponse(
                    success=False,
                    status=p_res.get("status", "ERROR"),
                    error=p_res.get("error", f"Pin state update failed for item {item_id}"),
                )
            return CapabilityResponse(
                success=True,
                status="SUCCESS",
                data={"item": p_res.get("item")},
            )

        if action == "clipboard_buffer_unpin":
            item_id = params.get("item_id")
            if not item_id:
                return CapabilityResponse(success=False, status="INVALID_ARGUMENT", error="Missing 'item_id'.")
            u_res = self.clipboard_buffer.unpin(str(item_id))
            if not u_res.get("success"):
                return CapabilityResponse(
                    success=False,
                    status=u_res.get("status", "ERROR"),
                    error=u_res.get("error", f"Unpin failed for item {item_id}"),
                )
            return CapabilityResponse(
                success=True,
                status="SUCCESS",
                data={"item": u_res.get("item")},
            )

        if action == "clipboard_buffer_delete":
            item_id = params.get("item_id")
            if not item_id:
                return CapabilityResponse(success=False, status="INVALID_ARGUMENT", error="Missing 'item_id'.")
            d_res = self.clipboard_buffer.delete(str(item_id))
            if not d_res.get("success"):
                return CapabilityResponse(
                    success=False,
                    status=d_res.get("status", "ITEM_NOT_FOUND"),
                    error=d_res.get("error", f"Item '{item_id}' not found."),
                )
            return CapabilityResponse(
                success=True,
                status="SUCCESS",
                data={"deleted": True, "item_id": item_id},
            )

        if action == "clipboard_buffer_clear":
            unpinned_only = bool(params.get("unpinned_only", True))
            c_res = self.clipboard_buffer.clear(unpinned_only=unpinned_only)
            return CapabilityResponse(
                success=c_res.get("success", True),
                status="SUCCESS",
                data=c_res,
            )

        if action == "clipboard_buffer_apply":
            item_id = params.get("item_id")
            target = str(params.get("target") or params.get("target_device") or "pc").strip().lower()
            if not item_id:
                items = self.clipboard_buffer.list_items()
                if not items:
                    return CapabilityResponse(success=False, status="BUFFER_EMPTY", error="Clipboard buffer is empty.")
                item_meta = items[0]
                target_id = item_meta["item_id"]
            else:
                target_id = str(item_id)

            item = self.clipboard_buffer.get_item(target_id, include_content=True)
            if not item:
                return CapabilityResponse(success=False, status="ITEM_NOT_FOUND", error=f"Item '{target_id}' not found.")

            c_type = item.get("content_type", "text")
            if target in ("pc", "windows", "local"):
                if c_type == "image":
                    img_path = self.clipboard_buffer.get_image_path(target_id)
                    if not img_path or not img_path.exists():
                        return CapabilityResponse(success=False, status="FILE_NOT_FOUND", error="Image file missing on disk.")
                    res = self.clipboard.set_image_sync(img_path)
                else:
                    res = await self.clipboard.set_clipboard(text=item.get("text_content", ""))
                is_ok = res.get("success", False)
                return CapabilityResponse(
                    success=is_ok,
                    status="SUCCESS" if is_ok else res.get("status", "ERROR"),
                    data={"applied": is_ok, "item_id": target_id, "type": c_type, "target": "pc"},
                    error=res.get("error"),
                )
            else:
                router = getattr(self, "session_router", None)
                if not router or not hasattr(router, "route_request"):
                    return CapabilityResponse(success=False, status="DEVICE_OFFLINE", error="Session router not available.")

                resolved_target = target
                if resolved_target in ("android", "phone", "mobile", ""):
                    if ctx and ctx.device_id and ctx.device_id not in ("unknown", "desktop_windows", "local"):
                        resolved_target = ctx.device_id

                reg = self.node_registry or getattr(self.session_router, "node_registry", None)
                if resolved_target in ("android", "phone", "mobile", "") and reg and hasattr(reg, "resolve_target"):
                    try:
                        res = reg.resolve_target(resolved_target if resolved_target not in ("pc", "windows", "local") else "")
                        if isinstance(res, tuple) and len(res) == 2:
                            node, err = res
                            if node:
                                resolved_target = node.device_id
                            elif err and resolved_target in ("android", "phone", "mobile", ""):
                                return CapabilityResponse(success=False, status=err, error=f"Target device resolution failed: {err}")
                    except Exception:
                        pass
                elif resolved_target in ("android", "phone", "mobile", "") and self.core_server and hasattr(self.core_server, "session_manager"):
                    sm = self.core_server.session_manager
                    sessions = sm.get_all_sessions()
                    if len(sessions) == 1:
                        resolved_target = list(sessions.values())[0].device_id
                    elif len(sessions) > 1:
                        return CapabilityResponse(success=False, status="DEVICE_REQUIRED", error="Multiple active devices. Explicit target required.")
                    else:
                        return CapabilityResponse(success=False, status="DEVICE_NOT_FOUND", error="No active connected device found.")

                stage_only = bool(params.get("stage_only", False))
                if c_type == "text":
                    route_res = await router.route_request(
                        action="clipboard_push",
                        target=resolved_target,
                        data={"text": item.get("text_content", "")},
                        ctx=ctx,
                    )
                else:
                    img_path = self.clipboard_buffer.get_image_path(target_id)
                    if not img_path or not img_path.exists():
                        return CapabilityResponse(success=False, status="FILE_NOT_FOUND", error="Image file missing on disk.")

                    file_size = img_path.stat().st_size
                    file_sha256 = item.get("sha256")
                    if not file_sha256:
                        h = hashlib.sha256()
                        with open(img_path, "rb") as f:
                            while chunk := f.read(65536):
                                h.update(chunk)
                        file_sha256 = h.hexdigest()

                    # Stage image into storage manager so HTTPS transfer route can serve it
                    if self.storage_manager and hasattr(self.storage_manager, "resolve_destination_path"):
                        try:
                            dest_path = self.storage_manager.resolve_destination_path(img_path.name)
                            if dest_path.resolve() != img_path.resolve():
                                import shutil
                                shutil.copy2(img_path, dest_path)
                        except Exception as sc_err:
                            logger.warning("Failed staging clipboard transfer file '%s': %s", img_path.name, sc_err)

                    from snow.transfer.manager import TransferDirection
                    tm = self.transfer_manager
                    if tm and hasattr(tm, "create_transfer"):
                        record = tm.create_transfer(
                            device_id=resolved_target,
                            file_name=img_path.name,
                            file_size=file_size,
                            sha256=file_sha256,
                            direction=TransferDirection.DOWNLOAD,
                        )
                        transfer_id = record.transfer_id
                    else:
                        import secrets
                        transfer_id = secrets.token_hex(16)

                    transfer_port = 8766
                    if self.http_transfer_server and hasattr(self.http_transfer_server, "bound_port"):
                        transfer_port = self.http_transfer_server.bound_port or 8766
                    elif self.core_server and hasattr(self.core_server, "config"):
                        transfer_port = getattr(self.core_server.config, "transfer_port", 8766)

                    push_data = {
                        "type": "image",
                        "transfer_id": transfer_id,
                        "transfer_port": transfer_port,
                        "sha256": file_sha256,
                        "mime_type": item.get("mime_type") or "image/png",
                        "file_name": img_path.name,
                        "size": file_size,
                    }

                    if stage_only:
                        route_res = {"success": True, "status": "SUCCESS"}
                    else:
                        route_res = await router.route_request(
                            action="clipboard_push",
                            target=resolved_target,
                            data=push_data,
                            ctx=ctx,
                        )
                is_ok = route_res.get("success", False)
                res_data = {"applied": is_ok, "item_id": target_id, "type": c_type, "target": target}
                if c_type == "image":
                    res_data.update({
                        "transfer_id": transfer_id,
                        "transfer_port": transfer_port,
                        "sha256": file_sha256,
                        "file_name": img_path.name,
                        "mime_type": item.get("mime_type") or "image/png",
                    })
                return CapabilityResponse(
                    success=is_ok,
                    status=route_res.get("status", "SUCCESS" if is_ok else "ERROR"),
                    data=res_data,
                    error=route_res.get("error"),
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

        # --- Media Controls (Phase 21) ---
        if action in ("media_control", "windows_media_control"):
            media_act = str(params.get("action", ""))
            vol_value = params.get("value")
            if vol_value is not None:
                res = self.media_controller.handle_action(media_act, value=vol_value)
            else:
                res = self.media_controller.handle_action(media_act)
            is_ok = res.get("success", False)
            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res,
                error=res.get("error"),
            )

        # --- Safe Link & Text Sharing (Phase 21) ---
        if action in ("share_link", "windows_share_link"):
            url = str(params.get("url", "")).strip()
            text = str(params.get("text", "")).strip()
            if url:
                parsed = urllib.parse.urlparse(url)
                if (
                    parsed.scheme.lower() not in ("http", "https")
                    or not parsed.netloc
                    or any(c in url for c in ("\r", "\n", "\0"))
                    or any(c.isspace() for c in url)
                ):
                    return CapabilityResponse(
                        success=False,
                        status="INVALID_URL_SCHEME",
                        error="Only http:// and https:// URL schemes with a valid host are permitted.",
                    )
                import webbrowser
                opened = webbrowser.open(url)
                return CapabilityResponse(
                    success=True,
                    status="SUCCESS",
                    data={"opened": opened, "url": url, "action": "opened_browser"},
                )
            elif text:
                res = await self.clipboard.set_clipboard(text=text)
                is_ok = res.get("success", False)
                return CapabilityResponse(
                    success=is_ok,
                    status="SUCCESS" if is_ok else "ERROR",
                    data={"copied": is_ok, "text_length": len(text), "action": "copied_to_clipboard"},
                    error=res.get("error"),
                )
            else:
                return CapabilityResponse(
                    success=False,
                    status="INVALID_ARGUMENT",
                    error="Either 'url' or 'text' must be provided.",
                )

        # --- Activity History (Phase 21) ---
        if action in ("activity_history", "audit_history"):
            if self.db_manager and hasattr(self.db_manager, "query_activity_history"):
                limit = int(params.get("limit", 50))
                offset = int(params.get("offset", 0))
                event_type = params.get("event_type")
                principal = params.get("principal")
                since = params.get("since")
                events = self.db_manager.query_activity_history(
                    limit=limit,
                    offset=offset,
                    event_type=event_type,
                    principal=principal,
                    since=since,
                )
                return CapabilityResponse(
                    success=True,
                    status="SUCCESS",
                    data={"events": events, "history": events, "count": len(events)},
                )
            return CapabilityResponse(
                success=False,
                status="DATABASE_UNAVAILABLE",
                error="Database manager is not configured for activity history queries.",
            )

        # --- Screen Capture (Phase 24 Repair A2) ---
        if action in ("windows_screenshot", "snow_windows_screenshot"):
            from snow.capabilities.windows.screenshot import WindowsScreenshotCapture
            cap = WindowsScreenshotCapture()
            try:
                res = await asyncio.to_thread(cap.capture_screen)
            except Exception as exc:
                logger.error("Async Windows screenshot execution failed: %s", exc, exc_info=True)
                return CapabilityResponse(
                    success=False,
                    status="CAPTURE_FAILED",
                    error=f"Screenshot thread exception: {exc}",
                )
            is_ok = res.get("success", False)
            if is_ok and self.clipboard_buffer and res.get("file_path"):
                try:
                    fpath = Path(res["file_path"])
                    if fpath.exists():
                        img_bytes = fpath.read_bytes()
                        buf_res = self.clipboard_buffer.add_image(
                            image_bytes=img_bytes,
                            mime_type="image/png",
                            source_device_id="desktop_windows",
                            source_device_name="Windows PC",
                        )
                        if buf_res.get("success") and buf_res.get("item"):
                            res["buffer_item_id"] = buf_res["item"]["item_id"]
                            if self.core_server and hasattr(self.core_server, "broadcast_clipboard_buffer_event"):
                                asyncio.create_task(self.core_server.broadcast_clipboard_buffer_event(buf_res["item"]))
                except Exception as b_err:
                    logger.warning("Failed adding screenshot to clipboard buffer: %s", b_err)

            return CapabilityResponse(
                success=is_ok,
                status=res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=res,
                error=res.get("error"),
            )

        # --- Workflows (Phase 24 Repair A1 & Single-Approval Hardening) ---
        if action in ("workflow_run", "snow_workflow_run"):
            workflow_id = str(params.get("workflow_id", "")).strip()
            wf_params = params.get("arguments") or params.get("params") or {}
            from snow.capabilities.workflows import WorkflowOrchestrator
            orchestrator = WorkflowOrchestrator(capability_engine=self)
            rep = await orchestrator.run_workflow(
                workflow_id,
                params=wf_params,
                ctx=ctx,
                workflow_approved=approval_consumed,
            )
            rep_dict = rep.to_dict()
            is_ok = rep.status in ("COMPLETED", "PARTIAL")
            return CapabilityResponse(
                success=is_ok,
                status=rep.status,
                data=rep_dict,
                error=rep.error,
            )

        # --- File Delivery to Peer Device (Phase 24 Repair B4) ---
        if action in ("android_file_send", "snow_android_file_send"):
            raw_path = params.get("file_path") or params.get("path") or ""
            target_device = (
                params.get("device_id")
                or params.get("target")
                or getattr(request, "target_device", None)
                or "android"
            )
            timeout = float(params.get("timeout", 30.0))

            if not raw_path or not isinstance(raw_path, str):
                return CapabilityResponse(
                    success=False,
                    status="INVALID_ARGUMENT",
                    error="file_path parameter is required for file delivery.",
                )

            # Prevent traversal or null byte injection
            if "\0" in raw_path:
                return CapabilityResponse(
                    success=False,
                    status="INVALID_ARGUMENT",
                    error="Path traversal or invalid characters detected in file_path.",
                )

            safe_path = Path(raw_path).resolve()
            if not safe_path.is_file():
                return CapabilityResponse(
                    success=False,
                    status="FILE_NOT_FOUND",
                    error=f"File not found on local system: '{safe_path.name}'.",
                )

            file_size = safe_path.stat().st_size
            hasher = hashlib.sha256()
            try:
                with open(safe_path, "rb") as f:
                    while chunk := f.read(65536):
                        hasher.update(chunk)
            except Exception as read_err:
                return CapabilityResponse(
                    success=False,
                    status="READ_ERROR",
                    error=f"Failed reading file for transfer: {read_err}",
                )
            file_sha256 = hasher.hexdigest()

            # Dynamic resolution of target Android device ID if generic
            if target_device in ("android", "phone", ""):
                if self.node_registry and hasattr(self.node_registry, "resolve_target"):
                    resolved_node, _ = self.node_registry.resolve_target("android")
                    if resolved_node:
                        target_device = resolved_node.device_id
                elif self.session_router and hasattr(self.session_router, "node_registry"):
                    sr_reg = getattr(self.session_router, "node_registry", None)
                    if sr_reg and hasattr(sr_reg, "resolve_target"):
                        resolved_node, _ = sr_reg.resolve_target("android")
                        if resolved_node:
                            target_device = resolved_node.device_id

            from snow.transfer.manager import TransferDirection, TransferState

            tm = self.transfer_manager
            # Pre-check SHA-256 duplicate for already completed transfer
            if tm and hasattr(tm, "list_transfers_for_device"):
                for t in tm.list_transfers_for_device(target_device):
                    if (
                        getattr(t, "sha256", None) == file_sha256
                        and getattr(t, "status", None) == TransferState.COMPLETED
                        and getattr(t, "direction", None) == TransferDirection.DOWNLOAD
                    ):
                        logger.info(
                            "File '%s' (sha256: %s) already transferred to [%s]; skipping duplicate.",
                            safe_path.name,
                            file_sha256[:12],
                            target_device,
                        )
                        return CapabilityResponse(
                            success=True,
                            status="ALREADY_EXISTS",
                            data={
                                "success": True,
                                "status": "ALREADY_EXISTS",
                                "transfer_id": getattr(t, "transfer_id", ""),
                                "file_name": safe_path.name,
                                "sha256": file_sha256,
                                "bytes_transferred": 0,
                                "skipped_duplicate": True,
                                "message": f"File '{safe_path.name}' already exists on destination; transfer skipped.",
                            },
                        )

            # Ensure file is staged in storage manager so HTTPS transfer route can serve it
            if self.storage_manager and hasattr(self.storage_manager, "resolve_destination_path"):
                try:
                    dest_path = self.storage_manager.resolve_destination_path(safe_path.name)
                    if dest_path.resolve() != safe_path.resolve():
                        import shutil
                        shutil.copy2(safe_path, dest_path)
                except Exception as sc_err:
                    logger.warning("Failed staging transfer file '%s': %s", safe_path.name, sc_err)

            record = None
            if tm and hasattr(tm, "create_transfer"):
                record = tm.create_transfer(
                    device_id=target_device,
                    file_name=safe_path.name,
                    file_size=file_size,
                    sha256=file_sha256,
                    direction=TransferDirection.DOWNLOAD,
                )
                transfer_id = record.transfer_id
            else:
                transfer_id = params.get("transfer_id") or secrets.token_hex(16)

            transfer_port = 8766
            if self.http_transfer_server and hasattr(self.http_transfer_server, "bound_port"):
                transfer_port = self.http_transfer_server.bound_port or 8766
            elif self.core_server and hasattr(self.core_server, "config"):
                transfer_port = getattr(self.core_server.config, "transfer_port", 8766)

            req_data = {
                "transfer_id": transfer_id,
                "file_name": safe_path.name,
                "file_size": file_size,
                "sha256": file_sha256,
                "transfer_port": transfer_port,
            }

            router = getattr(self, "session_router", None)
            if not router or not hasattr(router, "route_request"):
                if tm and record and hasattr(tm, "fail_transfer"):
                    tm.fail_transfer(transfer_id, "Router unavailable")
                return CapabilityResponse(
                    success=False,
                    status="ROUTER_UNAVAILABLE",
                    error="No SessionRouter configured for file delivery to peer.",
                )

            route_res = await router.route_request(
                action="file_send_request",
                target=target_device,
                data=req_data,
                timeout=timeout,
                ctx=ctx,
            )

            if route_res.get("success"):
                if tm and record and hasattr(tm, "complete_transfer"):
                    tm.complete_transfer(transfer_id)
                return CapabilityResponse(
                    success=True,
                    status="SUCCESS",
                    data={
                        "transfer_id": transfer_id,
                        "file_name": safe_path.name,
                        "sha256": file_sha256,
                        "bytes_transferred": file_size,
                        "skipped_duplicate": False,
                        "target_device": target_device,
                        "data": route_res.get("data"),
                    },
                )
            else:
                err_msg = route_res.get("error") or "File transfer failed on target device."
                if tm and record and hasattr(tm, "fail_transfer"):
                    tm.fail_transfer(transfer_id, err_msg)
                return CapabilityResponse(
                    success=False,
                    status=route_res.get("status") or "TRANSFER_FAILED",
                    error=err_msg,
                    data={
                        "transfer_id": transfer_id,
                        "file_name": safe_path.name,
                        "sha256": file_sha256,
                        "bytes_transferred": 0,
                        "skipped_duplicate": False,
                    },
                )

        # --- Cross-Device Capabilities Dispatch via SessionRouter (Phase 24 Repair B3) ---
        CROSS_DEVICE_ACTIONS = {
            "android_battery", "snow_android_battery", "battery_status",
            "android_screenshot", "snow_android_screenshot",
            "android_camera_capture", "snow_android_camera_capture",
            "file_send_request",
            "android_file_receive", "snow_android_file_receive", "file_receive_request",
            "android_file_list", "snow_android_file_list", "file_list",
            "android_notifications_list", "snow_android_notifications_list", "notifications_list",
            "android_notification_dismiss", "snow_android_notification_dismiss", "notification_dismiss",
            "android_notification_reply", "snow_android_notification_reply", "notification_reply",
            "android_launch_app", "snow_android_launch_app", "launch_app",
            "android_list_apps", "snow_android_list_apps", "list_apps",
            "android_send_message", "snow_android_send_message", "send_message",
            "android_ring", "snow_android_ring", "ring_phone",
            "android_clipboard_push", "snow_android_clipboard_push", "clipboard_push",
            "android_whatsapp_send", "snow_android_whatsapp_send", "whatsapp_send",
            "android_dnd_toggle", "snow_android_dnd_toggle", "dnd_toggle",
        }
        if action in CROSS_DEVICE_ACTIONS:
            router = getattr(self, "session_router", None)
            target = params.get("target") or params.get("device_id") or "android"
            if router and hasattr(router, "route_request"):
                try:
                    route_res = await router.route_request(
                        action=action,
                        target=target,
                        data=params,
                        ctx=ctx,
                    )
                    is_ok = route_res.get("success", False)
                    return CapabilityResponse(
                        success=is_ok,
                        status=route_res.get("status", "SUCCESS" if is_ok else "ERROR"),
                        data=route_res.get("data") if "data" in route_res else route_res,
                        error=route_res.get("error"),
                    )
                except Exception as r_exc:
                    logger.warning("SessionRouter dispatch error for '%s': %s", action, r_exc)
                    return CapabilityResponse(
                        success=False,
                        status="ROUTING_ERROR",
                        error=f"Cross-device dispatch failed: {r_exc}",
                    )
            else:
                return CapabilityResponse(
                    success=False,
                    status="DEVICE_OFFLINE",
                    error=f"No SessionRouter available to route cross-device action '{action}'.",
                )

        # Unsupported Action
        return CapabilityResponse(
            success=False,
            status="UNKNOWN_ACTION",
            error=f"Unsupported capability action: '{action}'",
        )

    async def _execute_cross_network_capability(
        self,
        params: dict[str, Any],
        ctx: ExecutionContext,
    ) -> CapabilityResponse:
        """Validate active federation grant, 5-tier intersection, ACLs, and route safely."""
        from snow.network.federation import (
            FederationManager,
            is_capability_forbidden_for_federation,
        )
        from snow.network.router import is_action_allowed_by_tier_intersection

        target_network_id = str(params.get("target_network_id") or "").strip()
        target_device_id = str(params.get("target_device_id") or "").strip()
        capability = str(params.get("capability") or "").strip()
        grant_token = str(params.get("grant_token") or "").strip()
        sub_params = dict(params.get("params") or {}) if isinstance(params.get("params"), dict) else {}

        if not target_network_id or not target_device_id or target_device_id == "*" or not capability:
            return CapabilityResponse(
                success=False,
                status="INVALID_ARGUMENT",
                error="Explicit 'target_network_id', non-wildcard 'target_device_id', and 'capability' are required.",
            )

        # Reject shell execution / forbidden administrative capabilities immediately
        if is_capability_forbidden_for_federation(capability) or capability.lower() in (
            "desktop_exec", "windows_terminal", "cmd", "powershell", "bash", "sh", "cross_network_execute", "snow_cross_network_execute"
        ):
            return CapabilityResponse(
                success=False,
                status="CAPABILITY_NOT_PERMITTED",
                error=f"Capability '{capability}' is strictly forbidden for cross-network execution.",
            )

        if not self.db_manager or not hasattr(self.db_manager, "list_federation_grants"):
            return CapabilityResponse(
                success=False,
                status="FEDERATION_UNAVAILABLE",
                error="Federation grant database is unavailable.",
            )

        fed_mgr = FederationManager(db_manager=self.db_manager)
        grants = fed_mgr.list_grants(active_only=False)
        matching_grant = next(
            (g for g in grants if g.get("network_id") == target_network_id),
            None,
        )
        if not matching_grant:
            return CapabilityResponse(
                success=False,
                status="GRANT_NOT_FOUND",
                error=f"No federation grant found for target network '{target_network_id}'.",
            )

        if matching_grant.get("status") != "ACTIVE":
            return CapabilityResponse(
                success=False,
                status=f"FEDERATION_GRANT_{matching_grant.get('status', 'INACTIVE')}",
                error=f"Federation grant for network '{target_network_id}' is {matching_grant.get('status')}.",
            )

        allowed_devs = matching_grant.get("allowed_device_ids") or []
        if not allowed_devs or "*" in allowed_devs or target_device_id not in allowed_devs:
            return CapabilityResponse(
                success=False,
                status="DEVICE_ACCESS_DENIED",
                error=f"Device '{target_device_id}' is outside federation grant scope.",
            )

        allowed_caps = matching_grant.get("allowed_capabilities") or []
        if not allowed_caps or "*" in allowed_caps or capability not in allowed_caps:
            return CapabilityResponse(
                success=False,
                status="CAPABILITY_NOT_PERMITTED",
                error=f"Capability '{capability}' is not allowed by federation grant.",
            )

        # Check 5-tier intersection (grant tier ∩ device tier)
        grant_tier = matching_grant.get("permission_tier")
        device_tier = self.db_manager.get_setting(f"device_profile:{target_device_id}") if hasattr(self.db_manager, "get_setting") else None
        if grant_tier and grant_tier != "custom":
            eff_dev_tier = device_tier or "full_control"
            if not is_action_allowed_by_tier_intersection(grant_tier, eff_dev_tier, capability):
                return CapabilityResponse(
                    success=False,
                    status="PERMISSION_DENIED",
                    error=f"Capability '{capability}' denied by 5-tier intersection (grant={grant_tier}, device={eff_dev_tier}).",
                )
        elif device_tier:
            from snow.network.router import is_action_allowed_by_profile
            if not is_action_allowed_by_profile(device_tier, capability):
                return CapabilityResponse(
                    success=False,
                    status="PERMISSION_DENIED",
                    error=f"Capability '{capability}' denied by device permission tier '{device_tier}'.",
                )

        if grant_token:
            valid, val_err = fed_mgr.validate_federated_request(
                token=grant_token,
                target_network_id="",
                target_device_id=target_device_id,
                capability=capability,
                target_device_tier=device_tier,
            )
            if not valid:
                return CapabilityResponse(
                    success=False,
                    status="PERMISSION_DENIED",
                    error=val_err or "Federated grant token validation failed.",
                )

        # Strip caller override fields from nested params and execute through router/engine cleanly
        clean_sub = dict(sub_params)
        clean_sub.pop("principal", None)
        clean_sub.pop("trust_tier", None)
        clean_sub["target_network_id"] = target_network_id
        clean_sub["federation_grant_id"] = matching_grant.get("grant_id")

        hop_limit = params.get("hop_limit", 2)
        visited_peers = params.get("visited_peers") if isinstance(params.get("visited_peers"), list) else []

        router = getattr(self, "session_router", None)
        if router and hasattr(router, "route_request"):
            route_res = await router.route_request(
                action=capability,
                target=target_device_id,
                data=clean_sub,
                ctx=ctx,
                hop_limit=hop_limit,
                visited_peers=visited_peers,
            )
            is_ok = bool(route_res.get("success"))
            return CapabilityResponse(
                success=is_ok,
                status=route_res.get("status", "SUCCESS" if is_ok else "ERROR"),
                data=route_res.get("data") if "data" in route_res else route_res,
                error=route_res.get("error"),
            )

        return CapabilityResponse(
            success=False,
            status="ROUTER_UNAVAILABLE",
            error="No active SessionRouter available for federated execution.",
        )
