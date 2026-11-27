"""Authenticated loopback IPC bridge connecting the SNOW MCP server to SNOW Core.

In Phase 8 (SNOW V2), the bridge implements dual-tier capability execution:
1. Local Windows Execution (In-Process):
   For local Windows capabilities (telemetry, processes, files, apps, terminal, clipboard),
   the bridge executes directly in-process against local Windows capability instances.
   The absence of the Core daemon or an offline phone NEVER prevents local execution.
   If Core IPC is actively running, requests may seamlessly leverage the Core or in-process
   execution without distinction.
2. Cross-Device Execution (Auto-Daemon Lifecycle):
   For tools that genuinely require cross-device state (Android operations, device list,
   status, clipboard sync), the bridge checks IPC readiness and automatically spawns the
   headless Core daemon via CoreDaemonManager if Core is currently offline.

SECURITY INVARIANTS:
1. Local Loopback Only: Connects exclusively to 127.0.0.1.
2. Secret Authentication: Automatically loads and presents ~/.snow/ipc.secret for IPC.
3. Strict Stdio Isolation: Daemon output is directed to log files; MCP stdio is never polluted.
4. Fail-Safe Error Handling: Converts transport dropouts and offline states into structured errors.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional
import urllib.parse
import uuid

from snow.capabilities.engine import CapabilityEngine, CapabilityRequest, CapabilityResponse
from snow.capabilities.windows.apps import WindowsAppLauncher
from snow.capabilities.windows.clipboard import WindowsClipboardManager
from snow.capabilities.windows.files import WindowsFileManager
from snow.capabilities.windows.processes import WindowsProcessMonitor
from snow.capabilities.windows.telemetry import WindowsTelemetry
from snow.capabilities.windows.terminal import WindowsTerminalExecutor
from snow.core.ipc import (
    DEFAULT_IPC_SECRET_FILENAME,
    IPC_PROTOCOL_VERSION,
    MAX_IPC_MESSAGE_SIZE,
    get_default_secret_path,
)
from snow.daemon import CoreDaemonManager
from snow.mcp.registry import ToolCategory, get_tool_category, is_local_windows_tool
from snow.security import ExecutionContext, ExecutionPrincipal

logger = logging.getLogger(__name__)


def resolve_target_device(
    devices: list[dict[str, Any]],
    target_query: str = "",
    platform: Optional[str] = None,
) -> tuple[Optional[str], Optional[dict[str, Any]]]:
    """Resolve a target device query into a concrete device_id or structured error.

    Resolution rules:
    - If platform is specified (e.g., 'android'):
      - Exclude local Windows host node.
      - Exclude nodes where is_local == True.
      - Exclude nodes whose transport is 'local'.
      - Exclude reserved local IDs such as 'local' and 'desktop-core'.
      - Exclude non-matching platforms (e.g. windows when targeting android).
      - Never silently route an Android operation to the Windows host.
    - If target_query is empty, 'default', or None:
      - Filter to paired devices among eligible candidates.
      - If 0 paired devices:
        - Check connected devices among eligible candidates.
        - If exactly 1 connected: return (device_id, None).
        - If > 1 connected: return DEVICE_REQUIRED.
        - If 0 connected: return NO_DEVICES_PAIRED.
      - If exactly 1 paired device: return (device_id, None).
      - If > 1 paired devices:
        - Check connected devices among paired devices.
        - If exactly 1 is connected: return (device_id, None).
        - If > 1 connected: return DEVICE_REQUIRED with available_devices: connected.
        - If 0 connected: return DEVICE_REQUIRED with available_devices: paired.
    - If target_query is specified:
      - If target_query specifically targets an excluded local Windows node when targeting android:
        return (None, {"success": False, "status": "DEVICE_NOT_FOUND", "error": f"Cannot route Android operation to local Windows node '{clean_q}'."}).
      - Check exact device_id match among eligible devices.
      - Check exact device_name match (case-insensitive) among eligible devices.
      - Check substring or prefix match (case-insensitive, min 3 chars) among eligible devices.
      - If multiple matches: return AMBIGUOUS_DEVICE.
      - If no matches: return DEVICE_NOT_FOUND.
    """
    clean_q = (target_query or "").strip()

    def is_local_windows_node(d: dict[str, Any]) -> bool:
        dev_id = str(d.get("device_id") or "").lower()
        return bool(
            d.get("is_local") is True
            or str(d.get("transport") or "").lower() == "local"
            or dev_id in ("local", "desktop-core")
        )

    # Determine candidate devices based on platform constraints and local node exclusion
    eligible: list[dict[str, Any]] = []
    for d in devices:
        if platform and platform.lower() == "android":
            if is_local_windows_node(d):
                continue
            p = str(d.get("platform") or "").lower()
            if p in ("windows", "desktop", "pc"):
                continue
            eligible.append(d)
        else:
            if not clean_q and is_local_windows_node(d):
                continue
            eligible.append(d)

    if not clean_q or clean_q.lower() == "default":
        paired = [d for d in eligible if d.get("is_paired")]
        if not paired:
            connected = [d for d in eligible if d.get("is_connected")]
            if len(connected) == 1:
                return connected[0]["device_id"], None
            elif len(connected) > 1:
                return None, {
                    "success": False,
                    "status": "DEVICE_REQUIRED",
                    "error": f"Multiple {platform + ' ' if platform else ''}devices available ({len(connected)} connected). Please specify device ID or name.",
                    "data": {"available_devices": connected},
                }
            return None, {
                "success": False,
                "status": "NO_DEVICES_PAIRED",
                "error": f"No paired {platform + ' ' if platform else ''}devices found. Pair a device with SNOW first.",
            }

        if len(paired) == 1:
            return paired[0]["device_id"], None

        connected = [d for d in paired if d.get("is_connected")]
        if len(connected) == 1:
            return connected[0]["device_id"], None
        elif len(connected) > 1:
            return None, {
                "success": False,
                "status": "DEVICE_REQUIRED",
                "error": f"Multiple {platform + ' ' if platform else ''}devices available ({len(paired)} paired, {len(connected)} connected). Please specify device ID or name.",
                "data": {"available_devices": connected},
            }

        return None, {
            "success": False,
            "status": "DEVICE_REQUIRED",
            "error": f"Multiple {platform + ' ' if platform else ''}devices available ({len(paired)} paired). Please specify device ID or name.",
            "data": {"available_devices": paired},
        }

    # Explicit query provided
    # Check if query specifically targeted an excluded local/windows node
    if platform and platform.lower() == "android":
        for d in devices:
            if d.get("device_id") == clean_q or str(d.get("device_name") or "").lower() == clean_q.lower():
                if is_local_windows_node(d) or str(d.get("platform") or "").lower() in ("windows", "desktop", "pc"):
                    return None, {
                        "success": False,
                        "status": "DEVICE_NOT_FOUND",
                        "error": f"Cannot route Android operation to local Windows node '{clean_q}'.",
                    }

    # 1. Exact match on device_id among eligible
    for d in eligible:
        if d.get("device_id") == clean_q:
            return d["device_id"], None

    # 2. Exact match on device_name (case-insensitive) among eligible
    exact_names = [d for d in eligible if str(d.get("device_name") or "").lower() == clean_q.lower()]
    if len(exact_names) == 1:
        return exact_names[0]["device_id"], None
    elif len(exact_names) > 1:
        return None, {
            "success": False,
            "status": "AMBIGUOUS_DEVICE",
            "error": f"Target '{clean_q}' matches multiple devices with the same name.",
            "data": {"matches": exact_names},
        }

    # 3. Substring match on name or ID (minimum 3 characters) among eligible
    if len(clean_q) >= 3:
        matches = [
            d for d in eligible
            if clean_q.lower() in str(d.get("device_name") or "").lower()
            or clean_q.lower() in str(d.get("device_id") or "").lower()
        ]
        if len(matches) == 1:
            return matches[0]["device_id"], None
        elif len(matches) > 1:
            return None, {
                "success": False,
                "status": "AMBIGUOUS_DEVICE",
                "error": f"Target '{clean_q}' matches multiple devices.",
                "data": {"matches": matches},
            }

    return None, {
        "success": False,
        "status": "DEVICE_NOT_FOUND",
        "error": f"No device found matching '{clean_q}'.",
    }


class SnowMcpBridge:
    """IPC and in-process execution bridge allowing MCP tool handlers to command SNOW."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8767,
        secret: Optional[str] = None,
        secret_path: Optional[Path | str] = None,
        allowed_roots: Optional[list[Path | str]] = None,
        auto_start_core: bool = True,
        is_owner_channel: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.auto_start_core = auto_start_core
        self.is_owner_channel = is_owner_channel
        self._explicit_secret = secret
        self.secret_path = Path(secret_path) if secret_path else get_default_secret_path()

        # In-process CapabilityEngine for local Windows execution
        from snow.security.db import DatabaseManager
        db_mgr = DatabaseManager()
        self.capability_engine = CapabilityEngine(allowed_roots=allowed_roots, db_manager=db_mgr)
        self.local_telemetry = self.capability_engine.telemetry
        self.local_processes = self.capability_engine.processes
        self.local_files = self.capability_engine.files
        self.local_apps = self.capability_engine.apps
        self.local_terminal = self.capability_engine.terminal
        self.local_clipboard = self.capability_engine.clipboard

        # Daemon lifecycle manager for cross-device requests
        self.daemon_manager = CoreDaemonManager(
            host=self.host,
            port=self.port,
            secret=secret,
            secret_path=secret_path,
        )

        # Idempotent clipboard sync state: (device_id, direction) -> last_synced_sha256
        self._clipboard_sync_hashes: dict[tuple[str, str], str] = {}
        self._clipboard_sync_lock = asyncio.Lock()
        self._is_paused: bool = False

    @property
    def is_paused(self) -> bool:
        """Return whether the bridge currently considers the system paused."""
        return self._is_paused

    def _get_secret(self) -> Optional[str]:
        """Resolve the IPC authentication secret."""
        if self._explicit_secret:
            return self._explicit_secret

        env_secret = os.environ.get("SNOW_IPC_SECRET")
        if env_secret and env_secret.strip():
            return env_secret.strip()

        if self.secret_path.is_file():
            try:
                secret_text = self.secret_path.read_text(encoding="utf-8").strip()
                if secret_text:
                    return secret_text
            except Exception as exc:
                logger.warning("Could not read IPC secret from %s: %s", self.secret_path, exc)

        return None

    async def call(
        self, op: str, payload: Optional[dict[str, Any]] = None, timeout: float = 10.0
    ) -> dict[str, Any]:
        """Dispatch a single authenticated request to the SNOW Core IPC server.

        Opens an ephemeral TCP connection, transmits the request, receives the correlated
        response, and cleanly closes the connection. Returns structured errors on failure.
        """
        secret = self._get_secret()
        if not secret:
            return {
                "success": False,
                "status": "CORE_OFFLINE",
                "error": (
                    f"IPC secret not found at {self.secret_path}. "
                    "Ensure SNOW Desktop Core is running."
                ),
            }

        request_id = str(uuid.uuid4())
        request_obj = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": request_id,
            "op": op,
            "auth_token": secret,
            "payload": payload or {},
        }
        if self.is_owner_channel:
            request_obj["owner_token"] = hmac.new(
                secret.encode("utf-8"), b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256
            ).hexdigest()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=min(timeout, 5.0),
            )
        except (ConnectionRefusedError, OSError) as conn_err:
            return {
                "success": False,
                "status": "CORE_OFFLINE",
                "error": f"SNOW Desktop Core is offline or unreachable at {self.host}:{self.port} ({conn_err}).",
            }
        except asyncio.TimeoutError:
            return {
                "success": False,
                "status": "CORE_OFFLINE",
                "error": f"Connection to SNOW Desktop Core at {self.host}:{self.port} timed out.",
            }

        try:
            # Transmit serialized frame
            frame = json.dumps(request_obj, separators=(",", ":")).encode("utf-8") + b"\n"
            writer.write(frame)
            await writer.drain()

            # Await response frame
            raw_response = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not raw_response:
                return {
                    "success": False,
                    "status": "CONNECTION_RESET",
                    "error": "SNOW Desktop Core closed IPC connection without replying.",
                }

            if len(raw_response) > MAX_IPC_MESSAGE_SIZE:
                return {
                    "success": False,
                    "status": "MESSAGE_TOO_LARGE",
                    "error": f"IPC response exceeded maximum frame size ({MAX_IPC_MESSAGE_SIZE} bytes).",
                }

            response_obj = json.loads(raw_response.decode("utf-8").strip())
            if not isinstance(response_obj, dict):
                return {
                    "success": False,
                    "status": "INVALID_RESPONSE",
                    "error": "Received malformed non-object IPC response.",
                }

            return response_obj

        except asyncio.TimeoutError:
            return {
                "success": False,
                "status": "REQUEST_TIMEOUT",
                "error": f"IPC operation '{op}' timed out waiting for response after {timeout:.1f}s.",
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "INTERNAL_ERROR",
                "error": f"IPC error communicating with core: {exc}",
            }
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def call_cross_device(
        self, op: str, payload: Optional[dict[str, Any]] = None, timeout: float = 30.0
    ) -> dict[str, Any]:
        """Dispatch a cross-device request, auto-spawning the Core daemon if offline."""
        if self.auto_start_core:
            if not await self.daemon_manager.is_ipc_ready(timeout=0.2):
                logger.info("Core IPC offline; auto-spawning background Core daemon for op '%s'...", op)
                spawn_res = await self.daemon_manager.ensure_core_running()
                if not spawn_res.get("success"):
                    return {
                        "success": False,
                        "status": "CORE_OFFLINE",
                        "error": f"SNOW Desktop Core is offline or unreachable at {self.host}:{self.port} ({spawn_res.get('error')}).",
                    }

        # Dispatch request over IPC
        return await self.call(op, payload=payload, timeout=timeout)

    async def ping(self) -> dict[str, Any]:
        """Test IPC transport reachability."""
        return await self.call("ping", timeout=3.0)

    # =========================================================================
    # General / Cross-Device Tools
    # =========================================================================

    async def get_device_status(self) -> dict[str, Any]:
        """Query live core server and connected device overview."""
        return await self.call_cross_device("get_device_status", timeout=5.0)

    async def list_devices(self) -> dict[str, Any]:
        """Query all known paired devices and their connection states."""
        return await self.call_cross_device("list_devices", timeout=5.0)

    async def list_discovered_peers(self, snow_id: str = "") -> dict[str, Any]:
        """Query active LAN UDP discovery candidates from the Core discovery service."""
        payload = {"snow_id": snow_id} if snow_id else {}
        return await self.call("list_discovered_peers", payload=payload, timeout=2.0)

    async def send_device_request(
        self,
        device_id: str,
        action: str,
        data: Optional[dict[str, Any]] = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Route a request action to a connected, authenticated Android device."""
        payload = {
            "device_id": device_id,
            "action": action,
            "data": data,
            "timeout": timeout,
        }
        return await self.call_cross_device("device_request", payload=payload, timeout=timeout + 5.0)

    async def send_request(
        self,
        device_id: str = "",
        action: str = "",
        payload: Optional[dict[str, Any]] = None,
        data: Optional[dict[str, Any]] = None,
        timeout: float = 30.0,
        connection_id: str = "",
    ) -> dict[str, Any]:
        """Backward-compatible alias for send_device_request."""
        target_id = device_id or connection_id
        return await self.send_device_request(
            device_id=target_id,
            action=action,
            data=data if data is not None else payload,
            timeout=timeout,
        )

    async def _execute_local_or_ipc(
        self, op: str, payload: Optional[dict[str, Any]] = None
    ) -> dict[str, Any]:
        """Dual-path execution for local Windows tools.

        If Core IPC is online and reachable, leverages Core IPC.
        If Core is offline or unavailable, executes in-process directly via CapabilityEngine.
        """
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            ipc_res = await self.call(op, payload=payload, timeout=10.0)
            if ipc_res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return ipc_res

        # In-process execution via shared CapabilityEngine
        if self.is_owner_channel:
            ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="dashboard_owner")
        else:
            ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="mcp_in_process")
        req = CapabilityRequest(action=op, params=payload or {})
        res = await self.capability_engine.execute(req, ctx=ctx)
        return res.to_dict()

    # =========================================================================
    # Local Windows Tools (Standalone In-Process with IPC Fallback / Dual-Path)
    # =========================================================================

    async def windows_battery(self) -> dict[str, Any]:
        """Query host battery telemetry via Core IPC or in-process."""
        return await self._execute_local_or_ipc("windows_battery", {})

    async def windows_active_window(self) -> dict[str, Any]:
        """Query currently focused foreground window title and process on Windows."""
        return await self._execute_local_or_ipc("windows_active_window", {})

    async def windows_notify(self, title: str, message: str) -> dict[str, Any]:
        """Display a bounded Windows desktop notification via Core IPC or in-process."""
        return await self._execute_local_or_ipc("windows_notify", {"title": title, "message": message})

    async def windows_lock_screen(self, approval_id: str = "") -> dict[str, Any]:
        """Lock the Windows workstation (OWNER_MANUAL direct, AI_MCP approval-gated)."""
        params: dict[str, Any] = {}
        if approval_id:
            params["approval_id"] = approval_id
        return await self._execute_local_or_ipc("windows_lock_screen", params)

    async def snow_mesh_health_summary(self, ctx: Optional[ExecutionContext] = None) -> dict[str, Any]:
        """Compute compact secret-redacted SNOW mesh health and node reachability summary."""
        topo, dev_res = await asyncio.gather(
            self.snow_mesh_topology(ctx=ctx),
            self.list_devices(),
            return_exceptions=True,
        )
        topo_dict = topo if isinstance(topo, dict) else {}
        devs_raw: list[dict[str, Any]] = []
        if isinstance(dev_res, dict):
            data = dev_res.get("data")
            if isinstance(data, dict) and isinstance(data.get("devices"), list):
                devs_raw = data["devices"]
            elif isinstance(dev_res.get("devices"), list):
                devs_raw = dev_res["devices"]

        core_online = bool(
            isinstance(dev_res, dict) and dev_res.get("success", False)
        )
        online_count = 0
        offline_count = 0
        transport_counts: dict[str, int] = {}
        compact_nodes: list[dict[str, Any]] = []

        for d in devs_raw:
            is_conn = bool(d.get("is_connected"))
            if is_conn:
                online_count += 1
            else:
                offline_count += 1
            tr = str(d.get("transport") or "unknown").lower()
            transport_counts[tr] = transport_counts.get(tr, 0) + 1
            compact_nodes.append({
                "device_id": d.get("device_id"),
                "device_name": d.get("device_name"),
                "platform": d.get("platform", "unknown"),
                "is_connected": is_conn,
                "transport": tr,
                "reachability_state": d.get("reachability_state", "UNKNOWN"),
            })

        remote_online = sum(
            1 for d in devs_raw if bool(d.get("is_connected")) and not bool(d.get("is_local")) and d.get("transport") != "local"
        )
        health_status = "HEALTHY" if (core_online and remote_online > 0) else ("STANDBY" if core_online else "DEGRADED")

        return {
            "success": True,
            "status": health_status,
            "core_running": core_online,
            "total_nodes": len(compact_nodes),
            "online_nodes": online_count,
            "offline_nodes": offline_count,
            "remote_online_nodes": remote_online,
            "transports": transport_counts,
            "mesh_tier": topo_dict.get("network_name", "Local Mesh"),
            "nodes": compact_nodes,
        }

    async def windows_system_info(self) -> dict[str, Any]:
        """Query host system and hardware telemetry via Core IPC or in-process."""
        return await self._execute_local_or_ipc("windows_system_info", {})

    async def windows_processes(
        self, limit: int = 25, sort_by: str = "memory"
    ) -> dict[str, Any]:
        """Query host active processes via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_processes", {"limit": limit, "sort_by": sort_by}
        )

    async def windows_launch_app(self, app_name: str) -> dict[str, Any]:
        """Launch an allowlisted Windows desktop app via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_launch_app", {"app_name": app_name}
        )

    async def windows_file_read(
        self, file_path: str, max_bytes: int = 256 * 1024
    ) -> dict[str, Any]:
        """Read a scoped text file via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_file_read", {"file_path": file_path, "max_bytes": max_bytes}
        )

    async def windows_file_write(
        self,
        file_path: str,
        content: str,
        overwrite: bool = False,
        max_bytes: int = 256 * 1024,
    ) -> dict[str, Any]:
        """Write a scoped text file atomically via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_file_write",
            {
                "file_path": file_path,
                "content": content,
                "overwrite": overwrite,
                "max_bytes": max_bytes,
            },
        )

    async def windows_file_list(
        self, directory_path: str = "", limit: int = 50
    ) -> dict[str, Any]:
        """List contents of a scoped directory via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_file_list", {"directory_path": directory_path, "limit": limit}
        )

    async def windows_file_search(
        self, query: str, root_path: str = "", limit: int = 50
    ) -> dict[str, Any]:
        """Search files recursively via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_file_search",
            {"query": query, "root_path": root_path, "limit": limit},
        )

    async def windows_terminal_exec(
        self,
        command: str,
        cwd: Optional[str] = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Execute a shell command via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_terminal_exec",
            {"command": command, "cwd": cwd, "timeout": timeout},
        )

    async def windows_clipboard_get(self) -> dict[str, Any]:
        """Read text from Windows clipboard via Core IPC or in-process."""
        return await self._execute_local_or_ipc("windows_clipboard_get", {})

    async def windows_clipboard_set(self, text: str) -> dict[str, Any]:
        """Write text to Windows clipboard via Core IPC or in-process."""
        return await self._execute_local_or_ipc("windows_clipboard_set", {"text": text})

    # =========================================================================
    # Android Tools (Cross-Device via Core IPC)
    # =========================================================================

    async def resolve_target(
        self, target_query: str = "", platform: Optional[str] = None
    ) -> tuple[Optional[str], Optional[dict[str, Any]]]:
        """Resolve a device query against currently paired and discovered devices."""
        res = await self.list_devices()
        if not res.get("success"):
            return None, res
        devices = res.get("data", {}).get("devices", [])
        return resolve_target_device(devices, target_query, platform=platform)

    async def _resolve_target_device_id(
        self, target_query: str = "", platform: str = "android"
    ) -> Optional[str]:
        """Helper to resolve a target device ID using unified resolution rules."""
        target_id, _ = await self.resolve_target(target_query, platform=platform)
        return target_id

    async def _resolve_android_target(
        self, device_id: str = ""
    ) -> tuple[Optional[str], Optional[dict[str, Any]]]:
        """Resolve an Android target device, checking explicit ID or defaulting to eligible peer."""
        target_id = (device_id or "").strip()
        if target_id and target_id.lower() not in ("default", "local", "desktop-core"):
            dev_res = await self.list_devices()
            if dev_res.get("success"):
                devices = dev_res.get("data", {}).get("devices", [])
                for d in devices:
                    d_id = str(d.get("device_id") or "")
                    d_name = str(d.get("device_name") or "")
                    if d_id == target_id or d_name.lower() == target_id.lower():
                        dev_id_lower = d_id.lower()
                        if (
                            d.get("is_local") is True
                            or str(d.get("transport") or "").lower() == "local"
                            or dev_id_lower in ("local", "desktop-core")
                            or str(d.get("platform") or "").lower() in ("windows", "desktop", "pc")
                        ):
                            return None, {
                                "success": False,
                                "status": "DEVICE_NOT_FOUND",
                                "error": f"Cannot route Android operation to local Windows node '{target_id}'.",
                            }
                        return d_id, None
                t_id, err = resolve_target_device(devices, target_id, platform="android")
                if t_id:
                    return t_id, None
                if err and err.get("status") in ("AMBIGUOUS_DEVICE", "DEVICE_REQUIRED"):
                    return None, err
            return target_id, None

        target_id, err = await self.resolve_target(target_id, platform="android")
        if not target_id:
            # Check if _resolve_target_device_id was overridden/mocked in tests
            override = await self._resolve_target_device_id(device_id, platform="android")
            if override and override != target_id:
                return override, None
            return None, err or {"success": False, "status": "DEVICE_OFFLINE", "error": "No connected Android device found."}
        return target_id, None

    async def android_battery(self, device_id: str = "") -> dict[str, Any]:
        """Query paired Android phone battery telemetry."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.send_device_request(target_id, "battery_status", {})

    async def android_ring(self, duration_seconds: int = 5, device_id: str = "") -> dict[str, Any]:
        """Trigger audible alert / ringtone on Android phone."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.send_device_request(
            target_id, "ring_phone", {"duration_seconds": duration_seconds}
        )

    async def android_clipboard_push(self, text: str, device_id: str = "") -> dict[str, Any]:
        """Push text to Android clipboard."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.send_device_request(target_id, "clipboard_push", {"text": text})

    async def android_launch_app(self, package_name: str, device_id: str = "") -> dict[str, Any]:
        """Launch an application on Android phone."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.send_device_request(target_id, "launch_app", {"package_name": package_name})

    async def android_list_apps(self, limit: int = 50, device_id: str = "") -> dict[str, Any]:
        """List launchable applications on Android phone."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.send_device_request(target_id, "list_apps", {"limit": limit})

    async def android_file_send(self, file_path: str, device_id: str = "") -> dict[str, Any]:
        """Send a local file from Desktop to Android phone."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.call_cross_device(
            "android_file_send",
            payload={"file_path": file_path, "device_id": target_id or ""},
            timeout=60.0,
        )

    async def android_file_send_async(self, file_path: str, device_id: str = "") -> dict[str, Any]:
        """Initiate an async decoupled Desktop -> Android file transfer returning ACCEPTED + transfer_id."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.call_cross_device(
            "android_file_send",
            payload={"file_path": file_path, "device_id": target_id or "", "async_transfer": True},
            timeout=30.0,
        )

    async def transfer_status(self, transfer_id: str, device_id: str = "") -> dict[str, Any]:
        """Query Core transfer progress and lifecycle status."""
        return await self.call_cross_device(
            "transfer_status",
            payload={"transfer_id": transfer_id, "device_id": device_id or ""},
            timeout=15.0,
        )

    async def transfer_cancel(self, transfer_id: str, device_id: str = "") -> dict[str, Any]:
        """Cancel an in-flight Core/Android transfer and clean partial staging."""
        return await self.call_cross_device(
            "transfer_cancel",
            payload={"transfer_id": transfer_id, "device_id": device_id or ""},
            timeout=15.0,
        )

    async def android_file_receive(
        self, file_name: str, subpath: str = "", device_id: str = ""
    ) -> dict[str, Any]:
        """Request and download a file from Android phone to Desktop."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        payload = {"file_name": file_name, "device_id": target_id or ""}
        if subpath:
            payload["subpath"] = subpath
        return await self.call_cross_device(
            "android_file_receive",
            payload=payload,
            timeout=60.0,
        )

    async def android_send_message(
        self,
        recipient: str,
        message: str,
        mode: str = "intent",
        device_id: str = "",
    ) -> dict[str, Any]:
        """Send an SMS or compose a message on the paired Android phone.

        Safety Policy:
        - intent: Opens the SMS compose app on phone with recipient and message pre-filled.
          Final dispatch remains under deliberate user control.
        - sms: Direct background SMS dispatch is restricted for AI/MCP requests to prevent
          unauthorized communication. Use mode='intent' instead.
        """
        clean_mode = (mode or "").strip().lower()
        if clean_mode == "sms":
            return {
                "success": False,
                "status": "SMS_DISPATCH_RESTRICTED",
                "error": (
                    "Direct background SMS dispatch is restricted for AI/MCP requests to prevent "
                    "unauthorized communication. Use mode='intent' to open the messaging composer "
                    "with pre-filled content, leaving dispatch under the user's explicit control."
                ),
            }

        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.send_device_request(
            device_id=target_id,
            action="send_message",
            data={"recipient": recipient, "message": message, "mode": "intent"},
            timeout=30.0,
        )

    async def android_file_list(
        self, subpath: str = "", device_id: str = "", scope: str = "saf", show_hidden: bool = False
    ) -> dict[str, Any]:
        """List files and subdirectories within Android storage (SAF tree for AI/MCP, or Full Storage when authorized)."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.send_device_request(
            device_id=target_id,
            action="file_list",
            data={
                "subpath": subpath,
                "scope": scope,
                "show_hidden": show_hidden,
            },
            timeout=30.0,
        )

    async def android_notifications_list(self, device_id: str = "") -> dict[str, Any]:
        """List active non-sensitive notifications from the connected Android phone."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.send_device_request(
            device_id=target_id,
            action="notifications_list",
            data={},
            timeout=15.0,
        )

    async def android_notification_dismiss(self, key: str, device_id: str = "") -> dict[str, Any]:
        """Dismiss a notification on the connected Android phone by key."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.send_device_request(
            device_id=target_id,
            action="notification_dismiss",
            data={"key": key},
            timeout=15.0,
        )

    async def android_notification_reply(
        self, key: str, text: str, device_id: str = ""
    ) -> dict[str, Any]:
        """Send a Quick Reply to an active notification on the connected Android phone."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        return await self.send_device_request(
            device_id=target_id,
            action="notification_reply",
            data={"key": key, "text": text},
            timeout=15.0,
        )

    async def media_control(
        self, action: str, target: str = "windows", device_id: str = "", value: Optional[int] = None
    ) -> dict[str, Any]:
        """Send media playback and volume control commands."""
        clean_target = (target or "windows").strip().lower()
        payload: dict[str, Any] = {"action": action}
        if value is not None:
            payload["value"] = value
        if clean_target in ("windows", "desktop", "local"):
            return await self._execute_local_or_ipc("media_control", payload)
        else:
            target_id, err = await self._resolve_android_target(device_id)
            if not target_id:
                return err
            return await self.send_device_request(
                device_id=target_id,
                action="media_control",
                data=payload,
                timeout=15.0,
            )

    async def share_link(
        self, url: str = "", text: str = "", target: str = "windows", device_id: str = ""
    ) -> dict[str, Any]:
        """Safely share an HTTP/HTTPS link or text note with target device."""
        clean_target = (target or "windows").strip().lower()
        if clean_target in ("windows", "desktop", "local"):
            return await self._execute_local_or_ipc("share_link", {"url": url, "text": text})
        else:
            target_id, err = await self._resolve_android_target(device_id)
            if not target_id:
                return err
            return await self.send_device_request(
                device_id=target_id,
                action="share_link",
                data={"url": url, "text": text},
                timeout=15.0,
            )

    async def activity_history(
        self, limit: int = 50, offset: int = 0, event_type: str = "", principal: str = ""
    ) -> dict[str, Any]:
        """Query secret-redacted audit activity history."""
        payload = {
            "limit": limit,
            "offset": offset,
            "event_type": event_type,
            "principal": principal,
        }
        return await self._execute_local_or_ipc("activity_history", payload)

    async def windows_screenshot(self, approval_id: str = "") -> dict[str, Any]:
        """Capture the primary Windows screen via Win32 GDI/GDI+."""
        payload = {"approval_id": approval_id} if approval_id else {}
        return await self._execute_local_or_ipc("windows_screenshot", payload)

    async def android_screenshot(self, device_id: str = "", approval_id: str = "") -> dict[str, Any]:
        """Capture the connected Android phone screen via MediaProjection consent."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        data = {"approval_id": approval_id} if approval_id else {}
        return await self.send_device_request(device_id=target_id, action="android_screenshot", data=data)

    async def android_camera_capture(self, device_id: str = "", approval_id: str = "") -> dict[str, Any]:
        """Capture a photograph using the connected Android camera."""
        target_id, err = await self._resolve_android_target(device_id)
        if not target_id:
            return err
        data = {"approval_id": approval_id} if approval_id else {}
        return await self.send_device_request(device_id=target_id, action="android_camera_capture", data=data)

    async def workflow_run(
        self, workflow_id: str, arguments: Optional[dict[str, Any]] = None, approval_id: str = ""
    ) -> dict[str, Any]:
        """Execute an authorized declarative multi-step workflow."""
        payload: dict[str, Any] = {
            "workflow_id": workflow_id,
            "params": arguments or {},
        }
        if approval_id:
            payload["approval_id"] = approval_id
        return await self._execute_local_or_ipc("workflow_run", payload)

    async def sync_clipboard(
        self,
        direction: str = "laptop_to_phone",
        device_id: str = "",
        source_device: str = "",
        target_device: str = "",
    ) -> dict[str, Any]:
        """Synchronize clipboard across participating mesh devices (Windows, Android, peer nodes).

        Supports explicit source_device and target_device selection (Laptop A -> Laptop B,
        Phone A -> Phone B, Laptop -> Phone, Phone -> Laptop), falling back to direction
        and device_id when omitted.
        """
        # If source_device or target_device is specified, use multi-device selection
        if source_device or target_device:
            local_names = {"local", "localhost", "me", "this", "local_desktop"}

            # Determine source
            src_clean = (source_device or "").strip()
            src_is_local = (not src_clean) or (src_clean.lower() in local_names)
            src_id = "local_desktop" if src_is_local else None
            if not src_is_local:
                src_id, src_err = await self.resolve_target(src_clean)
                if not src_id:
                    return src_err or {
                        "success": False,
                        "status": "DEVICE_NOT_FOUND",
                        "error": f"Source device '{src_clean}' not found or unreachable.",
                    }

            # Determine target
            tgt_clean = (target_device or "").strip()
            tgt_is_local = (not tgt_clean) or (tgt_clean.lower() in local_names)
            tgt_id = "local_desktop" if tgt_is_local else None
            if not tgt_is_local:
                tgt_id, tgt_err = await self.resolve_target(tgt_clean)
                if not tgt_id:
                    return tgt_err or {
                        "success": False,
                        "status": "DEVICE_NOT_FOUND",
                        "error": f"Target device '{tgt_clean}' not found or unreachable.",
                    }

            if src_id == tgt_id:
                return {
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Source and target devices cannot be the same device.",
                }

            # 1. Read clipboard from source
            clip_text = ""
            if src_is_local:
                clip_res = await self.windows_clipboard_get()
                if not clip_res.get("success"):
                    return {
                        "success": False,
                        "status": "CLIPBOARD_READ_FAILED",
                        "source_device": src_id,
                        "target_device": tgt_id,
                        "error": f"Failed reading local Windows clipboard: {clip_res.get('error')}",
                    }
                clip_text = clip_res.get("data", {}).get("text", "")
            else:
                pull_res = await self.send_device_request(src_id, "desktop_clipboard_get", {})
                if not pull_res.get("success"):
                    pull_res = await self.send_device_request(src_id, "clipboard_pull", {})
                if not pull_res.get("success"):
                    return {
                        "success": False,
                        "status": pull_res.get("status", "CLIPBOARD_PULL_FAILED"),
                        "source_device": src_id,
                        "target_device": tgt_id,
                        "error": f"Failed retrieving clipboard from source device [{src_id}]: {pull_res.get('error')}",
                    }
                data = pull_res.get("data") or {}
                clip_text = data.get("text", "")

            if not clip_text:
                return {
                    "success": True,
                    "status": "EMPTY_CLIPBOARD",
                    "source_device": src_id,
                    "target_device": tgt_id,
                    "message": "Source clipboard is empty; nothing to synchronize.",
                    "characters_synced": 0,
                    "skipped_duplicate": False,
                }

            # Check SHA-256 idempotency cache scoped by (src_id, tgt_id)
            payload_sha256 = hashlib.sha256(clip_text.encode("utf-8")).hexdigest()
            cache_key = (src_id, tgt_id)

            async with self._clipboard_sync_lock:
                if self._clipboard_sync_hashes.get(cache_key) == payload_sha256:
                    return {
                        "success": True,
                        "status": "ALREADY_IN_SYNC",
                        "source_device": src_id,
                        "target_device": tgt_id,
                        "skipped_duplicate": True,
                        "sha256": payload_sha256,
                        "characters_synced": 0,
                        "message": "Clipboard content is already identical; synchronization skipped.",
                    }

            # 2. Write clipboard to target
            if tgt_is_local:
                set_res = await self.windows_clipboard_set(text=clip_text)
                if not set_res.get("success"):
                    return {
                        "success": False,
                        "status": "WINDOWS_CLIPBOARD_WRITE_FAILED",
                        "source_device": src_id,
                        "target_device": tgt_id,
                        "error": f"Failed writing to local Windows clipboard: {set_res.get('error')}",
                    }
            else:
                push_res = await self.send_device_request(tgt_id, "desktop_clipboard_set", {"text": clip_text})
                if not push_res.get("success"):
                    push_res = await self.send_device_request(tgt_id, "clipboard_push", {"text": clip_text})
                if not push_res.get("success"):
                    return {
                        "success": False,
                        "status": push_res.get("status", "SYNC_FAILED"),
                        "source_device": src_id,
                        "target_device": tgt_id,
                        "error": f"Failed pushing clipboard to target device [{tgt_id}]: {push_res.get('error')}",
                    }

            async with self._clipboard_sync_lock:
                self._clipboard_sync_hashes[cache_key] = payload_sha256

            return {
                "success": True,
                "status": "SUCCESS",
                "source_device": src_id,
                "target_device": tgt_id,
                "skipped_duplicate": False,
                "sha256": payload_sha256,
                "characters_synced": len(clip_text),
                "message": f"Successfully synchronized {len(clip_text)} characters from '{src_id}' to '{tgt_id}'.",
            }

        # Fallback to classic 2-node direction mode
        clean_dir = (direction or "").strip().lower()

        if clean_dir == "laptop_to_phone":
            target_id = device_id or await self._resolve_target_device_id() or "local_or_default"

            # 1. Read Windows clipboard
            clip_res = await self.windows_clipboard_get()
            if not clip_res.get("success"):
                return {
                    "success": False,
                    "status": "CLIPBOARD_READ_FAILED",
                    "direction": "laptop_to_phone",
                    "error": f"Failed reading Windows clipboard: {clip_res.get('error')}",
                }

            clip_text = clip_res.get("data", {}).get("text", "")
            if not clip_text:
                return {
                    "success": True,
                    "status": "EMPTY_CLIPBOARD",
                    "direction": "laptop_to_phone",
                    "message": "Windows clipboard is empty; nothing to synchronize.",
                    "characters_synced": 0,
                    "skipped_duplicate": False,
                }

            payload_sha256 = hashlib.sha256(clip_text.encode("utf-8")).hexdigest()
            cache_key = (target_id, clean_dir)

            async with self._clipboard_sync_lock:
                if self._clipboard_sync_hashes.get(cache_key) == payload_sha256:
                    return {
                        "success": True,
                        "status": "ALREADY_IN_SYNC",
                        "direction": "laptop_to_phone",
                        "skipped_duplicate": True,
                        "sha256": payload_sha256,
                        "characters_synced": 0,
                        "message": "Clipboard content is already identical; synchronization skipped.",
                    }

            # 2. Push to Android clipboard via Core
            push_res = await self.android_clipboard_push(text=clip_text, device_id=device_id)
            if not push_res.get("success"):
                return {
                    "success": False,
                    "status": push_res.get("status", "SYNC_FAILED"),
                    "direction": "laptop_to_phone",
                    "error": f"Failed syncing to Android: {push_res.get('error')}",
                }

            async with self._clipboard_sync_lock:
                self._clipboard_sync_hashes[cache_key] = payload_sha256

            return {
                "success": True,
                "status": "SUCCESS",
                "direction": "laptop_to_phone",
                "skipped_duplicate": False,
                "sha256": payload_sha256,
                "characters_synced": len(clip_text),
                "message": f"Successfully synchronized {len(clip_text)} characters from Windows to Android.",
            }

        elif clean_dir == "phone_to_laptop":
            target_id = device_id or await self._resolve_target_device_id()
            if not target_id:
                return {
                    "success": False,
                    "status": "DEVICE_OFFLINE",
                    "direction": "phone_to_laptop",
                    "error": "No connected Android device found.",
                }

            # 1. Request clipboard pull from Android device
            pull_res = await self.send_device_request(target_id, "clipboard_pull", {})
            if not pull_res.get("success"):
                err_status = pull_res.get("status", "CLIPBOARD_PULL_FAILED")
                err_msg = pull_res.get("error") or "Failed retrieving clipboard from Android."
                remediation_hint = (pull_res.get("data") or {}).get("remediation_hint") or pull_res.get("remediation_hint")
                ret = {
                    "success": False,
                    "status": err_status,
                    "direction": "phone_to_laptop",
                    "error": f"Failed pulling clipboard from Android: {err_msg}",
                }
                if remediation_hint:
                    ret["remediation_hint"] = remediation_hint
                return ret

            data = pull_res.get("data") or {}
            clip_text = data.get("text", "")
            if not clip_text:
                return {
                    "success": False,
                    "status": "EMPTY_CLIPBOARD",
                    "direction": "phone_to_laptop",
                    "error": "Android clipboard returned no text content.",
                }

            payload_sha256 = hashlib.sha256(clip_text.encode("utf-8")).hexdigest()
            cache_key = (target_id, clean_dir)

            async with self._clipboard_sync_lock:
                if self._clipboard_sync_hashes.get(cache_key) == payload_sha256:
                    return {
                        "success": True,
                        "status": "ALREADY_IN_SYNC",
                        "direction": "phone_to_laptop",
                        "skipped_duplicate": True,
                        "sha256": payload_sha256,
                        "characters_synced": 0,
                        "message": "Clipboard content is already identical; synchronization skipped.",
                    }

            # 2. Write to Windows clipboard
            set_res = await self.windows_clipboard_set(text=clip_text)
            if not set_res.get("success"):
                return {
                    "success": False,
                    "status": "WINDOWS_CLIPBOARD_WRITE_FAILED",
                    "direction": "phone_to_laptop",
                    "error": f"Failed writing Android clipboard content to Windows: {set_res.get('error')}",
                }

            async with self._clipboard_sync_lock:
                self._clipboard_sync_hashes[cache_key] = payload_sha256

            return {
                "success": True,
                "status": "SUCCESS",
                "direction": "phone_to_laptop",
                "skipped_duplicate": False,
                "sha256": payload_sha256,
                "characters_synced": len(clip_text),
                "message": f"Successfully synchronized {len(clip_text)} characters from Android to Windows.",
            }
        else:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "direction": direction,
                "error": f"Invalid direction '{direction}'. Must be 'laptop_to_phone' or 'phone_to_laptop'.",
            }

    async def transfer_file(
        self,
        source_path: str,
        destination_path: str = "",
        direction: str = "to_device",
        target_device: str = "",
        source_device: str = "",
    ) -> dict[str, Any]:
        """Unified cross-device file transfer between Windows, Android, and mesh peer devices."""
        local_names = {"local", "localhost", "me", "this", "local_desktop"}
        if source_device:
            src_clean = source_device.strip()
            src_is_local = src_clean.lower() in local_names
            tgt_clean = (target_device or "").strip()
            tgt_is_local = (not tgt_clean) or (tgt_clean.lower() in local_names)

            if src_is_local and not tgt_is_local:
                return await self.transfer_file(
                    source_path=source_path,
                    destination_path=destination_path,
                    direction="to_device",
                    target_device=tgt_clean,
                )
            elif not src_is_local and tgt_is_local:
                return await self.transfer_file(
                    source_path=source_path,
                    destination_path=destination_path,
                    direction="from_device",
                    target_device=src_clean,
                )
            elif not src_is_local and not tgt_is_local:
                src_id, s_err = await self.resolve_target(src_clean)
                if not src_id:
                    return s_err or {"success": False, "status": "DEVICE_NOT_FOUND", "error": f"Source '{src_clean}' not found."}
                tgt_id, t_err = await self.resolve_target(tgt_clean)
                if not tgt_id:
                    return t_err or {"success": False, "status": "DEVICE_NOT_FOUND", "error": f"Target '{tgt_clean}' not found."}

                recv_res = await self.android_file_receive(file_name=source_path, device_id=src_id)
                if not recv_res.get("success"):
                    return {
                        "success": False,
                        "status": recv_res.get("status", "TRANSFER_FAILED"),
                        "error": f"Failed receiving file from source [{src_id}]: {recv_res.get('error')}",
                    }
                downloaded_file = (recv_res.get("data") or {}).get("destination_path") or source_path
                send_res = await self.android_file_send(file_path=downloaded_file, device_id=tgt_id)
                return {
                    "success": send_res.get("success", False),
                    "status": send_res.get("status", "TRANSFER_FAILED"),
                    "source_device": src_id,
                    "target_device": tgt_id,
                    "data": send_res.get("data"),
                    "error": send_res.get("error"),
                }
            else:
                return {
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Source and target devices cannot both be local Windows desktop.",
                }

        # Classic 2-device mode
        clean_dir = (direction or "").strip().lower()
        if clean_dir not in ("to_device", "from_device"):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": f"Invalid direction '{direction}'. Must be 'to_device' or 'from_device'.",
            }

        target_id, err = await self.resolve_target(target_device)
        if not target_id:
            return err or {
                "success": False,
                "status": "DEVICE_OFFLINE",
                "error": "No target device resolved for transfer.",
            }

        if clean_dir == "to_device":
            return await self.android_file_send(file_path=source_path, device_id=target_id)
        else:
            return await self.android_file_receive(file_name=source_path, device_id=target_id)

    async def mesh_list_peers(self, device_id: str = "") -> dict[str, Any]:
        """Discover connected and paired peers across the SNOW mesh."""
        if not device_id:
            res = await self.list_devices()
            if not res.get("success"):
                return res
            devices = (res.get("data") or {}).get("devices", [])
            peers = [
                {
                    "device_id": d.get("device_id"),
                    "device_name": d.get("device_name"),
                    "device_type": d.get("platform") or d.get("device_type", "unknown"),
                    "reachability_state": d.get("reachability_state", "CONNECTED_SESSION" if d.get("is_connected") else "LAN_DISCOVERABLE"),
                    "reachability_profile": d.get("reachability_profile", "ACTIVE_SESSION_PEER"),
                    "supported_capabilities": d.get("capabilities", []),
                }
                for d in devices
            ]
            return {
                "success": True,
                "status": "SUCCESS",
                "data": {"peers": peers, "count": len(peers)},
            }
        else:
            target_id, err = await self.resolve_target(device_id)
            if not target_id:
                return err or {"success": False, "status": "DEVICE_OFFLINE", "error": f"Device '{device_id}' not found."}
            return await self.send_device_request(target_id, "mesh_list_peers", {})

    async def peer_relay_request(
        self,
        target_device: str,
        action: str,
        data: Optional[dict[str, Any]] = None,
        hop_limit: int = 3,
        intermediary_device: str = "",
    ) -> dict[str, Any]:
        """Relay an authorized capability request across the mesh via an intermediate peer."""
        target_id, err = await self.resolve_target(target_device)
        if not target_id:
            return err or {"success": False, "status": "DEVICE_NOT_FOUND", "error": f"Target '{target_device}' not found."}

        relay_payload = {
            "target_device_id": target_id,
            "action": action,
            "data": data or {},
            "hop_limit": hop_limit,
            "visited_nodes": [],
        }
        if intermediary_device:
            inter_id, ierr = await self.resolve_target(intermediary_device)
            if not inter_id:
                return ierr or {"success": False, "status": "DEVICE_NOT_FOUND", "error": f"Intermediary '{intermediary_device}' not found."}
            return await self.send_device_request(inter_id, "peer_relay_request", relay_payload)
        else:
            return await self.send_device_request(target_id, action, data or {})

    async def mesh_connect_peer(
        self,
        host: str,
        port: int = 8765,
        pin: str = "",
        expected_fingerprint: str = "",
    ) -> dict[str, Any]:
        """Federate with another SNOW Desktop Core peer on the LAN."""
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call(
                "mesh_connect_peer",
                payload={
                    "host": host,
                    "port": port,
                    "pin": pin,
                    "expected_fingerprint": expected_fingerprint,
                },
                timeout=15.0,
            )
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res

        from snow.network.peer_client import SnowPeerClient

        client = SnowPeerClient(
            host=host,
            port=port,
            expected_fingerprint=expected_fingerprint or None,
            use_tls=True,
        )
        res = await client.connect(pin=pin, timeout=10.0)
        if res.success and res.remote_device_id:
            remote_id = res.remote_device_id
            remote_name = res.remote_device_name or "Connected Peer"
            token_hash = hashlib.sha256((res.auth_token or "").encode("utf-8")).hexdigest() if res.auth_token else ""
            db_mgr = getattr(self.capability_engine, "db_manager", None)
            if db_mgr:
                try:
                    existing = db_mgr.get_paired_device(remote_id)
                    if not existing:
                        db_mgr.insert_paired_device(
                            device_id=remote_id,
                            device_name=remote_name,
                            auth_token_hash=token_hash,
                            trust_tier="peer",
                            platform="windows",
                            reachability_profile="ACTIVE_SESSION_PEER",
                            last_known_host=host,
                            last_known_port=port,
                            capabilities_json=json.dumps(res.manifest or {}),
                        )
                    else:
                        db_mgr.update_device_endpoint(remote_id, host, port)
                        db_mgr.update_last_seen(remote_id)
                except Exception as db_err:
                    logger.debug("Failed saving peer to DB in bridge: %s", db_err)
            node_reg = getattr(self.capability_engine, "node_registry", None)
            if node_reg:
                node_reg.on_session_authenticated(
                    device_id=remote_id,
                    connection_id=res.session_id or f"peer_{remote_id}",
                    host=host,
                    port=port,
                    manifest_data=res.manifest,
                    transport="peer_link",
                )
            if not hasattr(self, "_peer_clients"):
                self._peer_clients = {}
            self._peer_clients[remote_id] = client
            return {
                "success": True,
                "status": res.status,
                "data": {
                    "remote_device_id": res.remote_device_id,
                    "remote_device_name": res.remote_device_name,
                    "session_id": res.session_id,
                    "cert_fingerprint": res.cert_fingerprint,
                },
            }
        else:
            await client.close()
            return {
                "success": False,
                "status": res.status,
                "error": res.error,
            }

    async def mesh_disconnect_peer(self, device_id: str) -> dict[str, Any]:
        """Disconnect an active peer session."""
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call(
                "mesh_disconnect_peer",
                payload={"device_id": device_id},
                timeout=5.0,
            )
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res

        if hasattr(self, "_peer_clients") and device_id in self._peer_clients:
            client = self._peer_clients.pop(device_id)
            try:
                await client.close()
            except Exception:
                pass
            node_reg = getattr(self.capability_engine, "node_registry", None)
            if node_reg:
                node_reg.on_session_disconnected(device_id)
            return {"success": True, "status": "DISCONNECTED", "device_id": device_id}
        return {"success": False, "status": "NOT_CONNECTED", "error": f"Peer '{device_id}' is not connected."}

    async def disconnect_all_devices(self, reason: str = "Disconnected by desktop owner") -> dict[str, Any]:
        """Disconnect all currently active device sessions while preserving pairings and Core daemon."""
        if await self.daemon_manager.is_ipc_ready(timeout=0.15):
            res = await self.call(
                "devices_disconnect_all",
                payload={"reason": reason},
                timeout=5.0,
            )
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res
        return {
            "success": True,
            "status": "DISCONNECTED_ALL",
            "disconnected_count": 0,
            "disconnected_device_ids": [],
            "data": {"disconnected_count": 0, "disconnected_device_ids": []},
        }

    # =========================================================================
    # Phase 26B: Shared Clipboard Buffer Methods
    # =========================================================================

    async def clipboard_buffer_list(self, limit: int = 15) -> dict[str, Any]:
        """List metadata for the latest items in the shared clipboard buffer."""
        return await self._execute_local_or_ipc(
            "clipboard_buffer_list",
            {"limit": limit},
        )

    async def clipboard_buffer_add(
        self,
        text: str,
        is_pinned: bool = False,
        approval_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Add text content to the shared clipboard buffer."""
        params: dict[str, Any] = {"text": text, "is_pinned": is_pinned}
        if approval_id:
            params["approval_id"] = approval_id
        return await self._execute_local_or_ipc("clipboard_buffer_add", params)

    async def clipboard_buffer_apply(
        self,
        item_id: str = "",
        target: str = "pc",
        approval_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Apply a buffer item to the local Windows clipboard or remote Android device."""
        params: dict[str, Any] = {"item_id": item_id, "target": target}
        if approval_id:
            params["approval_id"] = approval_id
        return await self._execute_local_or_ipc("clipboard_buffer_apply", params)

    async def clipboard_buffer_get(self, item_id: str) -> dict[str, Any]:
        """Retrieve metadata for a specific item in the shared clipboard buffer."""
        return await self._execute_local_or_ipc("clipboard_buffer_get", {"item_id": item_id})

    async def snow_mesh_topology(self, ctx: Optional[ExecutionContext] = None) -> dict[str, Any]:
        """Inspect reachable SNOW network nodes, transport status, and effective principal permissions."""
        principal = ctx.principal if ctx else (ExecutionPrincipal.OWNER_MANUAL if self.is_owner_channel else ExecutionPrincipal.AI_MCP)
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call("mesh_topology", payload={}, timeout=5.0)
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION") and res.get("data"):
                return res.get("data", {})

        # In-process fallback via SnowNetworkManager
        from snow.network.network_model import SnowNetworkManager
        network_mgr = SnowNetworkManager(db_manager=self.capability_engine.db_manager)
        return network_mgr.build_topology(principal=principal)

    # =========================================================================
    # V5.2.0 Stage 6A Capabilities (WS12 / WS13 -> 48 Total Tools)
    # =========================================================================

    @staticmethod
    def _normalize_target_platform(target: str) -> Optional[str]:
        clean = (target or "windows").strip().lower()
        if clean in ("windows", "desktop", "local"):
            return "windows"
        if clean in ("android", "phone", "mobile"):
            return "android"
        return None

    async def windows_list_windows(
        self, include_empty_titles: bool = False, limit: int = 50
    ) -> dict[str, Any]:
        """List visible top-level windows on the Windows host."""
        return await self._execute_local_or_ipc(
            "windows_list_windows",
            {"include_empty_titles": bool(include_empty_titles), "limit": int(limit)},
        )

    async def windows_focus_window(
        self,
        hwnd: Optional[int] = None,
        title_contains: str = "",
        process_name: str = "",
    ) -> dict[str, Any]:
        """Focus an existing visible Windows desktop window cleanly."""
        if hwnd is not None and (isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'hwnd' must be a positive integer window handle.",
            }
        if not hwnd and not str(title_contains or "").strip() and not str(process_name or "").strip():
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Provide at least one selector: 'hwnd', 'title_contains', or 'process_name'.",
            }
        return await self._execute_local_or_ipc(
            "windows_focus_window",
            {
                "hwnd": hwnd,
                "title_contains": str(title_contains or ""),
                "process_name": str(process_name or ""),
            },
        )

    async def web_open(
        self, url: str, target: str = "windows", device_id: str = ""
    ) -> dict[str, Any]:
        """Validate and open an HTTP/HTTPS URL on Windows or Android."""
        platform = self._normalize_target_platform(target)
        if not platform:
            return {
                "success": False,
                "status": "INVALID_TARGET",
                "error": f"Unsupported target '{target}'. Use 'windows' or 'android'.",
            }
        if not isinstance(url, str) or not url.strip():
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'url' must be a non-empty http:// or https:// URL.",
            }
        clean_url = url.strip()
        if any(c in clean_url for c in ("\r", "\n", "\0")) or any(c.isspace() for c in clean_url):
            return {
                "success": False,
                "status": "INVALID_URL_SCHEME",
                "error": "URL contains invalid control or whitespace characters.",
            }
        parsed = urllib.parse.urlparse(clean_url)
        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc or not parsed.hostname:
            return {
                "success": False,
                "status": "INVALID_URL_SCHEME",
                "error": "Only http:// and https:// URLs with a valid host are permitted.",
            }
        return await self.share_link(url=clean_url, target=platform, device_id=device_id)

    async def youtube_play(
        self, query: str = "", url: str = "", target: str = "windows", device_id: str = ""
    ) -> dict[str, Any]:
        """Open a validated YouTube URL or search query on Windows or Android."""
        platform = self._normalize_target_platform(target)
        if not platform:
            return {
                "success": False,
                "status": "INVALID_TARGET",
                "error": f"Unsupported target '{target}'. Use 'windows' or 'android'.",
            }
        allowed_hosts = {
            "youtube.com",
            "www.youtube.com",
            "m.youtube.com",
            "music.youtube.com",
            "youtu.be",
        }
        clean_url = str(url or "").strip()
        clean_query = str(query or "").strip()

        if clean_url:
            if any(c in clean_url for c in ("\r", "\n", "\0")) or any(c.isspace() for c in clean_url):
                return {
                    "success": False,
                    "status": "INVALID_YOUTUBE_URL",
                    "error": "YouTube URL contains illegal control or whitespace characters.",
                }
            parsed = urllib.parse.urlparse(clean_url)
            host = (parsed.hostname or "").lower()
            if parsed.scheme.lower() not in ("http", "https") or host not in allowed_hosts:
                return {
                    "success": False,
                    "status": "INVALID_YOUTUBE_URL",
                    "error": "Only http:// or https:// URLs on youtube.com or youtu.be are permitted.",
                }
            resolved_url = clean_url
        elif clean_query:
            if any(c in clean_query for c in ("\r", "\n", "\0")):
                return {
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Search query contains illegal control characters.",
                }
            bounded_q = clean_query[:200]
            resolved_url = f"https://www.youtube.com/results?search_query={urllib.parse.quote_plus(bounded_q)}"
            clean_query = bounded_q
        else:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Either 'query' or 'url' must be provided.",
            }

        res = await self.share_link(url=resolved_url, target=platform, device_id=device_id)
        if isinstance(res, dict) and res.get("success"):
            data = dict(res.get("data") or {})
            data.setdefault("url", resolved_url)
            if clean_query:
                data["query"] = clean_query
            res = dict(res)
            res["data"] = data
        return res

    async def system_volume_set(
        self, level: int, target: str = "windows", device_id: str = ""
    ) -> dict[str, Any]:
        """Set master system volume percentage (0-100) on Windows or Android."""
        platform = self._normalize_target_platform(target)
        if not platform:
            return {
                "success": False,
                "status": "INVALID_TARGET",
                "error": f"Unsupported target '{target}'. Use 'windows' or 'android'.",
            }
        if isinstance(level, bool) or not isinstance(level, (int, float)):
            return {
                "success": False,
                "status": "INVALID_VOLUME_LEVEL",
                "error": "Volume 'level' must be an integer between 0 and 100.",
            }
        numeric = float(level)
        if numeric != numeric or numeric < 0.0 or numeric > 100.0 or numeric in (float("inf"), float("-inf")):
            return {
                "success": False,
                "status": "INVALID_VOLUME_LEVEL",
                "error": "Volume 'level' must be between 0 and 100.",
            }
        bounded_level = int(round(numeric))
        return await self.media_control(
            action="volume_set",
            target=platform,
            device_id=device_id,
            value=bounded_level,
        )

    async def federation_peers(
        self, include_revoked: bool = False, ctx: Optional[ExecutionContext] = None
    ) -> dict[str, Any]:
        """Inspect secret-redacted federation grants and peer reachability."""
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call(
                "federation_peers",
                payload={"include_revoked": bool(include_revoked)},
                timeout=5.0,
            )
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res

        from snow.network.network_model import SnowNetworkManager
        from snow.network.federation import FederationManager

        principal = ctx.principal if ctx else (
            ExecutionPrincipal.OWNER_MANUAL if self.is_owner_channel else ExecutionPrincipal.AI_MCP
        )
        db_mgr = getattr(self.capability_engine, "db_manager", None)
        node_reg = getattr(self.capability_engine, "node_registry", None)
        network_mgr = SnowNetworkManager(db_manager=db_mgr, node_registry=node_reg)
        topo = network_mgr.build_topology(principal=principal)
        mesh_peers = [
            n for n in (topo.get("nodes") or [])
            if isinstance(n, dict) and n.get("federated")
        ]

        grants: list[dict[str, Any]] = []
        local_network_id: Optional[str] = None
        local_network_name: Optional[str] = None
        if db_mgr and hasattr(db_mgr, "list_federation_grants"):
            fed_mgr = FederationManager(db_manager=db_mgr, local_node_id="desktop-core")
            local_network_id = getattr(fed_mgr, "local_network_id", None)
            local_network_name = getattr(fed_mgr, "local_network_name", None)
            forbidden = {"auth_token", "auth_token_hash", "token", "secret", "pairing_token", "ticket", "ipc_secret"}
            for g in fed_mgr.list_grants(active_only=not include_revoked):
                clean_g = {k: v for k, v in g.items() if k not in forbidden}
                peer_id = clean_g.get("peer_node_id")
                reg_node = node_reg.get_node(peer_id) if (node_reg and peer_id) else None
                clean_g["is_connected"] = bool(getattr(reg_node, "is_connected", False)) if reg_node else False
                clean_g["reachability_state"] = "active" if clean_g["is_connected"] else "offline"
                grants.append(clean_g)

        return {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "local_node_id": topo.get("local_node_id", "desktop-core"),
                "local_network_id": local_network_id,
                "local_network_name": local_network_name,
                "grants": grants,
                "mesh_peers": mesh_peers,
                "active_count": sum(1 for g in grants if g.get("status") == "ACTIVE"),
                "total_count": len(grants),
            },
        }

    # =========================================================================
    # Phase 28A: Connection Mode & Relay Management Methods
    # =========================================================================

    async def set_device_connection_mode(self, device_id: str, connection_mode: str) -> dict[str, Any]:
        """Update connection mode ('auto', 'local_only', 'remote_only') for a paired device."""
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call(
                "device_set_connection_mode",
                payload={"device_id": device_id, "connection_mode": connection_mode},
                timeout=5.0,
            )
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res

        # In-process fallback
        db = self.capability_engine.db_manager
        if db:
            ok = db.update_device_connection_mode(device_id, connection_mode)
            if ok:
                node_reg = getattr(self.capability_engine, "node_registry", None)
                if node_reg:
                    node = node_reg.get_node(device_id)
                    if node:
                        node.connection_mode = connection_mode
                return {"success": True, "status": "SUCCESS", "data": {"device_id": device_id, "connection_mode": connection_mode}}
            return {"success": False, "status": "DEVICE_NOT_FOUND", "error": f"Device '{device_id}' not found."}
        return {"success": False, "status": "DATABASE_UNAVAILABLE", "error": "Database unavailable."}

    async def get_relay_config(self) -> dict[str, Any]:
        """Query live relay client configuration and status."""
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call("relay_status", payload={}, timeout=5.0)
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res

        return {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "enabled": False,
                "connected": False,
                "relay_url": "",
                "group_id": "",
                "active_tunnels": [],
            },
        }

    async def set_relay_config(
        self, enabled: bool, relay_url: str = "", group_id: str = "", ticket: str = ""
    ) -> dict[str, Any]:
        """Configure or toggle outbound relay tunnel connectivity."""
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call(
                "relay_config",
                payload={"enabled": enabled, "relay_url": relay_url, "group_id": group_id, "ticket": ticket},
                timeout=10.0,
            )
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res

        return {"success": False, "status": "CORE_OFFLINE", "error": "Desktop Core daemon is offline."}

    # =========================================================================
    # Phase 30: Cross-Network Federation Operations
    # =========================================================================

    async def system_pause(self, reason: str = "Paused by owner via bridge") -> dict[str, Any]:
        """Put the desktop core into pause mode via Core IPC."""
        self._is_paused = True
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call("system_pause", payload={"reason": reason}, timeout=5.0)
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res
        return {"success": True, "status": "PAUSED", "state": "PAUSED", "reason": reason}

    async def system_resume(self) -> dict[str, Any]:
        """Restore desktop core from pause mode via Core IPC."""
        self._is_paused = False
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call("system_resume", payload={}, timeout=5.0)
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res
        return {"success": True, "status": "RESUMED", "state": "ACTIVE"}

    async def system_shutdown(self, reason: str = "Shutdown initiated by owner via bridge") -> dict[str, Any]:
        """Trigger coordinated desktop core shutdown via Core IPC."""
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call("system_shutdown", payload={"reason": reason}, timeout=5.0)
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res
        return {"success": True, "status": "SHUTTING_DOWN", "state": "STOPPING"}

    async def federation_revoke(self, grant_id: str, reason: str = "Revoked by network owner") -> dict[str, Any]:
        """Revoke a cross-network federation grant and terminate active sessions via Core IPC."""
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call(
                "federation_revoke",
                payload={"grant_id": grant_id, "reason": reason},
                timeout=5.0,
            )
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res

        # Fallback to local DB and peer clients if Core daemon IPC is offline
        cap_engine = getattr(self, "capability_engine", None)
        db_mgr = getattr(cap_engine, "db_manager", None)
        if db_mgr:
            from snow.network.federation import FederationManager
            fed_mgr = FederationManager(db_manager=db_mgr)
            return fed_mgr.revoke_grant(grant_id, reason=reason, principal="OWNER_MANUAL")
        return {"success": False, "status": "CORE_OFFLINE", "error": "Core daemon IPC offline and database unavailable."}

    async def federation_kill_switch(self, reason: str = "Emergency Global Kill Switch Activated") -> dict[str, Any]:
        """Immediately terminate all active federation grants, pending invitations, and federated sessions via Core IPC."""
        if await self.daemon_manager.is_ipc_ready(timeout=0.1):
            res = await self.call(
                "federation_kill_switch",
                payload={"reason": reason},
                timeout=5.0,
            )
            if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return res

        # Fallback to local DB if Core daemon IPC is offline
        cap_engine = getattr(self, "capability_engine", None)
        db_mgr = getattr(cap_engine, "db_manager", None)
        if db_mgr:
            from snow.network.federation import FederationManager
            fed_mgr = FederationManager(db_manager=db_mgr)
            return fed_mgr.global_kill_switch(reason=reason, principal="OWNER_MANUAL")
        return {"success": False, "status": "CORE_OFFLINE", "error": "Core daemon IPC offline and database unavailable."}

    # =========================================================================
    # V5.2.0 Stage 6B Capabilities (6 new tools -> 54 Total Tools)
    # =========================================================================

    async def android_whatsapp_send(
        self,
        recipient: str,
        message: str,
        user_confirmed: bool = False,
        target_device: str = "",
    ) -> dict[str, Any]:
        """Prepare an explicit-consent WhatsApp draft on a connected Android phone."""
        if not isinstance(recipient, str) or not recipient.strip():
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'recipient' must be a non-empty contact name or phone number.",
            }
        clean_recipient = recipient.strip()
        if len(clean_recipient) > 64 or any(ord(ch) < 32 or ord(ch) == 127 for ch in clean_recipient):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'recipient' contains illegal control characters or exceeds 64 characters.",
            }
        if not isinstance(message, str) or not message.strip():
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'message' must be a non-empty string.",
            }
        clean_msg = message.strip()
        if len(clean_msg) > 2000 or "\x00" in clean_msg:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'message' must not contain null bytes or exceed 2000 characters.",
            }
        params: dict[str, Any] = {
            "recipient": clean_recipient,
            "message": clean_msg,
            "user_confirmed": bool(user_confirmed),
        }
        if target_device and str(target_device).strip():
            params["target"] = str(target_device).strip()
            params["device_id"] = str(target_device).strip()
        return await self._execute_local_or_ipc("android_whatsapp_send", params)

    async def android_notification_reply(
        self,
        notification_key: str,
        reply_text: str,
        target_device: str = "",
    ) -> dict[str, Any]:
        """Reply directly to an active Android notification supporting RemoteInput."""
        if not isinstance(notification_key, str) or not notification_key.strip():
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'notification_key' must be a non-empty notification key string.",
            }
        clean_key = notification_key.strip()
        if len(clean_key) > 512 or any(ord(ch) < 32 for ch in clean_key):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'notification_key' contains illegal control characters or exceeds 512 characters.",
            }
        if not isinstance(reply_text, str) or not reply_text.strip():
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'reply_text' must be a non-empty string.",
            }
        clean_reply = reply_text.strip()
        if len(clean_reply) > 2000 or "\x00" in clean_reply:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'reply_text' contains null bytes or exceeds 2000 characters.",
            }
        params: dict[str, Any] = {
            "key": clean_key,
            "notification_key": clean_key,
            "text": clean_reply,
            "reply_text": clean_reply,
        }
        if target_device and str(target_device).strip():
            params["target"] = str(target_device).strip()
            params["device_id"] = str(target_device).strip()
        return await self._execute_local_or_ipc("android_notification_reply", params)

    async def windows_hotkey(self, shortcut: str) -> dict[str, Any]:
        """Trigger an allowlisted Windows keyboard shortcut safely via SendInput."""
        from snow.capabilities.windows.system import ALLOWED_HOTKEYS, normalize_hotkey_shortcut

        if not isinstance(shortcut, str) or not shortcut.strip():
            return {
                "success": False,
                "status": "INVALID_HOTKEY",
                "error": "'shortcut' must be a non-empty allowlisted hotkey string.",
            }
        norm = normalize_hotkey_shortcut(shortcut)
        if norm not in ALLOWED_HOTKEYS:
            return {
                "success": False,
                "status": "INVALID_HOTKEY",
                "error": f"Hotkey '{shortcut}' is not in the explicit allowlist: {', '.join(sorted(ALLOWED_HOTKEYS.keys()))}.",
            }
        return await self._execute_local_or_ipc("windows_hotkey", {"shortcut": norm})

    async def windows_brightness_set(self, level: int) -> dict[str, Any]:
        """Set Windows primary display brightness cleanly between 0 and 100."""
        if isinstance(level, bool) or not isinstance(level, int) or level < 0 or level > 100:
            return {
                "success": False,
                "status": "INVALID_BRIGHTNESS_LEVEL",
                "error": "'level' must be an integer between 0 and 100.",
            }
        return await self._execute_local_or_ipc("windows_brightness_set", {"level": int(level)})

    async def android_dnd_toggle(self, enabled: bool, target_device: str = "") -> dict[str, Any]:
        """Toggle Do Not Disturb mode on a connected Android phone."""
        if not isinstance(enabled, bool):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'enabled' must be a strict boolean (true or false).",
            }
        params: dict[str, Any] = {"enabled": enabled}
        if target_device and str(target_device).strip():
            params["target"] = str(target_device).strip()
            params["device_id"] = str(target_device).strip()
        return await self._execute_local_or_ipc("android_dnd_toggle", params)

    async def cross_network_execute(
        self,
        target_network_id: str,
        target_device_id: str,
        capability: str,
        params: Optional[dict[str, Any]] = None,
        grant_token: str = "",
    ) -> dict[str, Any]:
        """Execute a permitted capability across a federated SNOW network boundary."""
        if not isinstance(target_network_id, str) or not target_network_id.strip():
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "'target_network_id' is required."}
        if not isinstance(target_device_id, str) or not target_device_id.strip() or target_device_id.strip() == "*":
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'target_device_id' must be an explicit non-wildcard device identifier.",
            }
        if not isinstance(capability, str) or not capability.strip():
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "'capability' is required."}
        if params is not None and not isinstance(params, dict):
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "'params' must be a JSON object if provided."}

        return await self._execute_local_or_ipc(
            "cross_network_execute",
            {
                "target_network_id": target_network_id.strip(),
                "target_device_id": target_device_id.strip(),
                "capability": capability.strip(),
                "params": dict(params) if params else {},
                "grant_token": str(grant_token or "").strip(),
            },
        )
