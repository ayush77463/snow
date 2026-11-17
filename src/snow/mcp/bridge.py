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
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional
import uuid

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

logger = logging.getLogger(__name__)


def resolve_target_device(
    devices: list[dict[str, Any]], target_query: str = ""
) -> tuple[Optional[str], Optional[dict[str, Any]]]:
    """Resolve a target device query into a concrete device_id or structured error.

    Resolution rules:
    1. If target_query is empty, 'default', or None:
       - Filter to paired devices.
       - If 0 paired devices: return (None, {"success": False, "status": "NO_DEVICES_PAIRED", "error": "No paired devices found. Pair a device with SNOW first."})
       - If exactly 1 paired device: return (device_id, None)
       - If > 1 paired devices:
         - Check connected devices among paired devices.
         - If exactly 1 is connected: return (device_id, None)
         - Otherwise: return (None, {"success": False, "status": "DEVICE_REQUIRED", "error": f"Multiple devices available ({len(paired)} paired). Please specify device ID or name.", "data": {"available_devices": paired}})
    2. If target_query is specified:
       - Check exact device_id match.
       - Check exact device_name match (case-insensitive).
       - Check substring or prefix match (case-insensitive, min 3 chars).
       - If multiple matches: return (None, {"success": False, "status": "AMBIGUOUS_DEVICE", "error": f"Target '{target_query}' matches multiple devices.", "data": {"matches": matches}})
       - If no matches: return (None, {"success": False, "status": "DEVICE_NOT_FOUND", "error": f"No device found matching '{target_query}'."})
    """
    clean_q = (target_query or "").strip()
    paired = [d for d in devices if d.get("is_paired")]

    if not clean_q or clean_q.lower() == "default":
        if not paired:
            return None, {
                "success": False,
                "status": "NO_DEVICES_PAIRED",
                "error": "No paired devices found. Pair a device with SNOW first.",
            }
        if len(paired) == 1:
            return paired[0]["device_id"], None

        connected = [d for d in paired if d.get("is_connected")]
        if len(connected) == 1:
            return connected[0]["device_id"], None

        return None, {
            "success": False,
            "status": "DEVICE_REQUIRED",
            "error": f"Multiple devices available ({len(paired)} paired, {len(connected)} connected). Please specify device ID or name.",
            "data": {"available_devices": paired},
        }

    # Explicit query provided
    # 1. Exact match on device_id
    for d in devices:
        if d.get("device_id") == clean_q:
            return d["device_id"], None

    # 2. Exact match on device_name (case-insensitive)
    exact_names = [d for d in devices if d.get("device_name", "").lower() == clean_q.lower()]
    if len(exact_names) == 1:
        return exact_names[0]["device_id"], None
    elif len(exact_names) > 1:
        return None, {
            "success": False,
            "status": "AMBIGUOUS_DEVICE",
            "error": f"Target '{clean_q}' matches multiple devices with the same name.",
            "data": {"matches": exact_names},
        }

    # 3. Substring match on name or ID (minimum 3 characters)
    if len(clean_q) >= 3:
        matches = [
            d for d in devices
            if clean_q.lower() in d.get("device_name", "").lower()
            or clean_q.lower() in d.get("device_id", "").lower()
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
    ) -> None:
        self.host = host
        self.port = port
        self.auto_start_core = auto_start_core
        self._explicit_secret = secret
        self.secret_path = Path(secret_path) if secret_path else get_default_secret_path()

        # In-process Windows capability instances
        self.local_telemetry = WindowsTelemetry()
        self.local_processes = WindowsProcessMonitor()
        self.local_files = WindowsFileManager(allowed_roots=allowed_roots)
        self.local_apps = WindowsAppLauncher()
        self.local_terminal = WindowsTerminalExecutor()
        self.local_clipboard = WindowsClipboardManager()

        # Daemon lifecycle manager for cross-device requests
        self.daemon_manager = CoreDaemonManager(host=self.host, port=self.port)

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

    async def _execute_local_or_ipc(
        self, op: str, payload: Optional[dict[str, Any]], local_coro_fn: Any
    ) -> dict[str, Any]:
        """Dual-path execution for local Windows tools.

        If Core IPC is online and reachable, leverages Core IPC.
        If Core is offline or unavailable, executes in-process directly without error.
        """
        if await self.daemon_manager.is_ipc_ready(timeout=0.05):
            ipc_res = await self.call(op, payload=payload, timeout=5.0)
            if ipc_res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION"):
                return ipc_res

        # In-process execution fallback
        res = await local_coro_fn()
        # Normalize in-process result
        if "data" in res and "success" in res:
            return res
        is_success = res.get("success", True) if isinstance(res, dict) else True
        if isinstance(res, dict) and "status" in res and res.get("status") in ("ERROR", "PATH_NOT_ALLOWED", "APP_NOT_ALLOWED", "INVALID_ARGUMENT", "FILE_NOT_FOUND", "FILE_ALREADY_EXISTS", "POLICY_DENIED"):
            is_success = False

        return {
            "success": is_success,
            "status": res.get("status", "SUCCESS" if is_success else "ERROR") if isinstance(res, dict) else "SUCCESS",
            "data": res if is_success else None,
            "error": res.get("error") if isinstance(res, dict) else None,
        }

    # =========================================================================
    # Local Windows Tools (Standalone In-Process with IPC Fallback / Dual-Path)
    # =========================================================================

    async def windows_battery(self) -> dict[str, Any]:
        """Query host battery telemetry via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_battery",
            {},
            self.local_telemetry.get_battery_info,
        )

    async def windows_system_info(self) -> dict[str, Any]:
        """Query host system and hardware telemetry via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_system_info",
            {},
            self.local_telemetry.get_system_telemetry,
        )

    async def windows_processes(
        self, limit: int = 25, sort_by: str = "memory"
    ) -> dict[str, Any]:
        """Query host active processes via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_processes",
            {"limit": limit, "sort_by": sort_by},
            lambda: self.local_processes.list_processes(limit=limit, sort_by=sort_by),
        )

    async def windows_launch_app(self, app_name: str) -> dict[str, Any]:
        """Launch an allowlisted Windows desktop app via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_launch_app",
            {"app_name": app_name},
            lambda: self.local_apps.launch_app(app_name=app_name),
        )

    async def windows_file_read(
        self, file_path: str, max_bytes: int = 256 * 1024
    ) -> dict[str, Any]:
        """Read a scoped text file via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_file_read",
            {"file_path": file_path, "max_bytes": max_bytes},
            lambda: self.local_files.read_file(file_path=file_path, max_bytes=max_bytes),
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
            lambda: self.local_files.write_file(
                file_path=file_path,
                content=content,
                overwrite=overwrite,
                max_bytes=max_bytes,
            ),
        )

    async def windows_file_list(
        self, directory_path: str = "", limit: int = 50
    ) -> dict[str, Any]:
        """List contents of a scoped directory via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_file_list",
            {"directory_path": directory_path, "limit": limit},
            lambda: self.local_files.list_files(directory_path=directory_path, limit=limit),
        )

    async def windows_file_search(
        self, query: str, root_path: str = "", limit: int = 50
    ) -> dict[str, Any]:
        """Search files recursively via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_file_search",
            {"query": query, "root_path": root_path, "limit": limit},
            lambda: self.local_files.search_files(query=query, root_path=root_path, limit=limit),
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
            lambda: self.local_terminal.execute_command(command=command, cwd=cwd, timeout=timeout),
        )

    async def windows_clipboard_get(self) -> dict[str, Any]:
        """Read text from Windows clipboard via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_clipboard_get",
            {},
            self.local_clipboard.get_clipboard,
        )

    async def windows_clipboard_set(self, text: str) -> dict[str, Any]:
        """Write text to Windows clipboard via Core IPC or in-process."""
        return await self._execute_local_or_ipc(
            "windows_clipboard_set",
            {"text": text},
            lambda: self.local_clipboard.set_clipboard(text=text),
        )

    # =========================================================================
    # Android Tools (Cross-Device via Core IPC)
    # =========================================================================

    async def resolve_target(self, target_query: str = "") -> tuple[Optional[str], Optional[dict[str, Any]]]:
        """Resolve a device query against currently paired and discovered devices."""
        res = await self.list_devices()
        if not res.get("success"):
            return None, res
        devices = res.get("data", {}).get("devices", [])
        return resolve_target_device(devices, target_query)

    async def _resolve_target_device_id(self, target_query: str = "") -> Optional[str]:
        """Helper to resolve a target device ID using unified resolution rules."""
        target_id, _ = await self.resolve_target(target_query)
        return target_id

    async def android_battery(self, device_id: str = "") -> dict[str, Any]:
        """Query paired Android phone battery telemetry."""
        target_id = device_id or await self._resolve_target_device_id()
        if not target_id:
            return {"success": False, "status": "DEVICE_OFFLINE", "error": "No connected Android device found."}
        return await self.send_device_request(target_id, "battery_status", {})

    async def android_ring(self, duration_seconds: int = 5, device_id: str = "") -> dict[str, Any]:
        """Trigger audible alert / ringtone on Android phone."""
        target_id = device_id or await self._resolve_target_device_id()
        if not target_id:
            return {"success": False, "status": "DEVICE_OFFLINE", "error": "No connected Android device found."}
        return await self.send_device_request(
            target_id, "ring_phone", {"duration_seconds": duration_seconds}
        )

    async def android_clipboard_push(self, text: str, device_id: str = "") -> dict[str, Any]:
        """Push text to Android clipboard."""
        target_id = device_id or await self._resolve_target_device_id()
        if not target_id:
            return {"success": False, "status": "DEVICE_OFFLINE", "error": "No connected Android device found."}
        return await self.send_device_request(target_id, "clipboard_push", {"text": text})

    async def android_launch_app(self, package_name: str, device_id: str = "") -> dict[str, Any]:
        """Launch an application on Android phone."""
        target_id = device_id or await self._resolve_target_device_id()
        if not target_id:
            return {"success": False, "status": "DEVICE_OFFLINE", "error": "No connected Android device found."}
        return await self.send_device_request(target_id, "launch_app", {"package_name": package_name})

    async def android_list_apps(self, limit: int = 50, device_id: str = "") -> dict[str, Any]:
        """List launchable applications on Android phone."""
        target_id = device_id or await self._resolve_target_device_id()
        if not target_id:
            return {"success": False, "status": "DEVICE_OFFLINE", "error": "No connected Android device found."}
        return await self.send_device_request(target_id, "list_apps", {"limit": limit})

    async def android_file_send(self, file_path: str, device_id: str = "") -> dict[str, Any]:
        """Send a local file from Desktop to Android phone."""
        target_id = device_id or await self._resolve_target_device_id()
        return await self.call_cross_device(
            "android_file_send",
            payload={"file_path": file_path, "device_id": target_id or ""},
            timeout=60.0,
        )

    async def android_file_receive(self, file_name: str, device_id: str = "") -> dict[str, Any]:
        """Request and download a file from Android phone to Desktop."""
        target_id = device_id or await self._resolve_target_device_id()
        return await self.call_cross_device(
            "android_file_receive",
            payload={"file_name": file_name, "device_id": target_id or ""},
            timeout=60.0,
        )

    async def sync_clipboard(
        self, direction: str = "laptop_to_phone", device_id: str = ""
    ) -> dict[str, Any]:
        """Synchronize clipboard between Windows laptop and Android phone.

        Directions:
        - laptop_to_phone: Reads Windows clipboard and pushes content to Android phone.
        - phone_to_laptop: Reports unsupported status due to Android OS background
          clipboard restrictions and write-only client architecture.
        """
        clean_dir = (direction or "").strip().lower()

        if clean_dir == "laptop_to_phone":
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

            return {
                "success": True,
                "status": "SUCCESS",
                "direction": "laptop_to_phone",
                "characters_synced": len(clip_text),
                "message": f"Successfully synchronized {len(clip_text)} characters from Windows to Android.",
            }

        elif clean_dir == "phone_to_laptop":
            # Inspect Android capabilities: Android OS blocks background clipboard reading
            # and our Android client runtime is strictly write-only.
            return {
                "success": False,
                "status": "UNSUPPORTED_DIRECTION",
                "direction": "phone_to_laptop",
                "error": (
                    "Clipboard sync from phone_to_laptop is not currently supported. "
                    "The Android client runtime enforces a write-only clipboard security policy "
                    "(ClipboardHandler is strictly push-only), and Android 10+ (API 29+) prevents "
                    "background services from reading clipboard contents without active IME focus."
                ),
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
    ) -> dict[str, Any]:
        """Unified cross-device file transfer between Windows and connected peers/phones.

        Args:
            source_path: Local path (for to_device) or remote filename (for from_device).
            destination_path: Optional destination name/path.
            direction: 'to_device' or 'from_device'.
            target_device: Optional target device ID, name, or substring.
        """
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

    async def mesh_connect_peer(
        self,
        host: str,
        port: int = 8765,
        pin: str = "",
        expected_fingerprint: str = "",
    ) -> dict[str, Any]:
        """Federate with another SNOW Desktop Core peer on the LAN."""
        from snow.network.peer_client import SnowPeerClient

        client = SnowPeerClient(
            host=host,
            port=port,
            expected_fingerprint=expected_fingerprint or None,
            use_tls=True,
        )
        try:
            res = await client.connect(pin=pin, timeout=10.0)
            return {
                "success": res.success,
                "status": res.status,
                "data": {
                    "remote_device_id": res.remote_device_id,
                    "remote_device_name": res.remote_device_name,
                    "session_id": res.session_id,
                    "cert_fingerprint": res.cert_fingerprint,
                },
                "error": res.error,
            }
        finally:
            await client.close()
