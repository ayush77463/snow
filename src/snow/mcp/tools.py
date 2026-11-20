"""Unified static MCP tool registry for SNOW.

Exposes standardized MCP tools for both Windows and Android capabilities to AI assistants.
All 30 tools are statically discoverable via list_tools, even when the Core or Android
device is currently offline.

In Phase 8:
- Windows capabilities (telemetry, processes, files, apps, terminal, clipboard) execute
  directly in-process without requiring Core to be running.
- Cross-device capabilities (Android operations, device list, status, clipboard sync)
  automatically start the background Core daemon on-demand.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.registry import get_mcp_annotations, list_capabilities

# Dynamic catalog of all registered SNOW MCP tool names
ALL_TOOL_NAMES: List[str] = [meta.name for meta in list_capabilities()]


def register_all_tools(server: FastMCP, bridge: SnowMcpBridge) -> None:
    """Register all 30 static MCP tools onto the provided FastMCP server instance."""
    # Wrap server.tool to automatically populate MCP ToolAnnotations (readOnlyHint, destructiveHint)
    _orig_tool = server.tool

    def _annotated_tool(*args: Any, **kwargs: Any) -> Any:
        tool_name = kwargs.get("name")
        if tool_name and "annotations" not in kwargs:
            ann = get_mcp_annotations(tool_name)
            if ann is not None:
                kwargs["annotations"] = ann
        return _orig_tool(*args, **kwargs)

    server.tool = _annotated_tool

    # =========================================================================
    # 1. General Tools (Core Daemon via IPC)
    # =========================================================================

    @server.tool(
        name="snow_get_device_status",
        description=(
            "Retrieve the current operational status of the SNOW Windows Desktop Core daemon "
            "and a summary of connected and paired Android devices."
        ),
    )
    async def snow_get_device_status() -> str:
        """Get SNOW Desktop Core running status and connected device summary."""
        result = await bridge.get_device_status()
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "CORE_OFFLINE"),
                "error": result.get("error", "SNOW Desktop Core is unreachable."),
                "hint": "Ensure 'snow daemon start' or 'python -m snow' is running.",
            }, indent=2)

        data = result.get("data", {})
        return json.dumps({
            "success": True,
            "status": "ONLINE",
            "core": {
                "running": data.get("core_running", False),
                "app_name": data.get("app_name", "SNOW Desktop Core"),
                "version": data.get("version", "0.1.0"),
                "ports": {
                    "wss": data.get("ws_port"),
                    "http_transfer": data.get("transfer_port"),
                    "ipc": data.get("ipc_port"),
                },
                "active_connections": data.get("active_connections_count", 0),
                "paired_devices": data.get("paired_devices_count", 0),
                "active_sessions": data.get("active_sessions_count", 0),
            },
            "devices": data.get("devices", []),
        }, indent=2)

    @server.tool(
        name="snow_list_devices",
        description=(
            "List all known paired Android devices along with their real-time connection "
            "and authenticated session status."
        ),
    )
    async def snow_list_devices() -> str:
        """List paired devices and their connection status."""
        result = await bridge.list_devices()
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "CORE_OFFLINE"),
                "error": result.get("error", "SNOW Desktop Core is unreachable."),
            }, indent=2)

        data = result.get("data", {})
        devices = data.get("devices", [])
        return json.dumps({
            "success": True,
            "count": len(devices),
            "devices": devices,
        }, indent=2)

    # =========================================================================
    # 2. Windows Tools (Standalone Local Execution)
    # =========================================================================

    @server.tool(
        name="snow_windows_battery",
        description="Retrieve battery percentage, power line status, and battery health of the Windows laptop.",
    )
    async def snow_windows_battery() -> str:
        """Query Windows laptop battery telemetry."""
        result = await bridge.windows_battery()
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed retrieving battery telemetry."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_windows_system_info",
        description="Retrieve Windows system hardware specifications, OS build, and CPU/RAM utilization.",
    )
    async def snow_windows_system_info() -> str:
        """Query Windows system and hardware telemetry."""
        result = await bridge.windows_system_info()
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed retrieving system telemetry."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_windows_processes",
        description="List running Windows processes with PID, name, and resource usage.",
    )
    async def snow_windows_processes(limit: int = 25, sort_by: str = "memory") -> str:
        """Query running Windows processes."""
        result = await bridge.windows_processes(limit=limit, sort_by=sort_by)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed retrieving processes."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_windows_launch_app",
        description=(
            "Launch an explicitly permitted Windows application from the approved whitelist "
            "(notepad, calc, explorer, taskmgr, mspaint, code, chrome, msedge, powershell, wt)."
        ),
    )
    async def snow_windows_launch_app(app_name: str) -> str:
        """Launch an approved Windows application."""
        result = await bridge.windows_launch_app(app_name=app_name)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed launching application '{app_name}'."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_windows_file_read",
        description="Read UTF-8 text file contents from authorized directories on the Windows laptop (up to 256 KiB).",
    )
    async def snow_windows_file_read(file_path: str, max_bytes: int = 262144) -> str:
        """Read a file in approved Windows directories."""
        result = await bridge.windows_file_read(file_path=file_path, max_bytes=max_bytes)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed reading file '{file_path}'."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_windows_file_write",
        description="Write UTF-8 text content atomically to a file in authorized directories on the Windows laptop (up to 256 KiB).",
    )
    async def snow_windows_file_write(
        file_path: str, content: str, overwrite: bool = False, max_bytes: int = 262144
    ) -> str:
        """Write content to an approved Windows file path."""
        result = await bridge.windows_file_write(
            file_path=file_path, content=content, overwrite=overwrite, max_bytes=max_bytes
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed writing file '{file_path}'."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_windows_file_list",
        description="List files within authorized directories on the Windows laptop.",
    )
    async def snow_windows_file_list(directory_path: str = "", limit: int = 50) -> str:
        """List files in approved Windows directories."""
        result = await bridge.windows_file_list(directory_path=directory_path, limit=limit)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed listing directory '{directory_path}'."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_windows_file_search",
        description="Search files recursively matching a query string within authorized directories on the Windows laptop.",
    )
    async def snow_windows_file_search(
        query: str, root_path: str = "", limit: int = 50
    ) -> str:
        """Search files recursively within authorized Windows directories."""
        result = await bridge.windows_file_search(query=query, root_path=root_path, limit=limit)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed searching for '{query}'."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_windows_terminal_exec",
        description=(
            "Execute a shell command on the Windows laptop with output bounds (128 KiB), "
            "execution timeout, and safety policies preventing catastrophic commands."
        ),
    )
    async def snow_windows_terminal_exec(
        command: str, cwd: str = "", timeout: float = 30.0
    ) -> str:
        """Execute a controlled shell command on Windows."""
        result = await bridge.windows_terminal_exec(
            command=command, cwd=cwd or None, timeout=timeout
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Command execution failed."),
                "details": result.get("data", {}),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_windows_clipboard_get",
        description="Read the current text contents of the Windows laptop clipboard.",
    )
    async def snow_windows_clipboard_get() -> str:
        """Read text from Windows clipboard."""
        result = await bridge.windows_clipboard_get()
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed reading Windows clipboard."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_windows_clipboard_set",
        description="Write text to the Windows laptop clipboard.",
    )
    async def snow_windows_clipboard_set(text: str) -> str:
        """Write text to Windows clipboard."""
        result = await bridge.windows_clipboard_set(text=text)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed setting Windows clipboard."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    # =========================================================================
    # 3. Cross-Device Synchronization Tools
    # =========================================================================

    @server.tool(
        name="snow_sync_clipboard",
        description=(
            "Synchronize clipboard across participating mesh devices (Windows, Android, peer nodes). "
            "Supports explicit source_device and target_device selection (Laptop A -> Laptop B, "
            "Phone A -> Phone B, Laptop -> Phone, Phone -> Laptop), falling back to direction "
            "('laptop_to_phone' or 'phone_to_laptop') and device_id when omitted."
        ),
    )
    async def snow_sync_clipboard(
        direction: str = "laptop_to_phone",
        device_id: str = "",
        source_device: str = "",
        target_device: str = "",
    ) -> str:
        """Synchronize clipboard between devices."""
        result = await bridge.sync_clipboard(
            direction=direction,
            device_id=device_id,
            source_device=source_device,
            target_device=target_device,
        )
        return json.dumps(result, indent=2)

    # =========================================================================
    # 4. Android Tools (Cross-Device via Core IPC)
    # =========================================================================

    @server.tool(
        name="snow_android_battery",
        description="Query battery level, temperature, and charging status from paired Android phone.",
    )
    async def snow_android_battery(device_id: str = "") -> str:
        """Query Android phone battery telemetry via Core."""
        result = await bridge.android_battery(device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed querying Android battery telemetry."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_android_ring",
        description="Trigger an audible alert/ringtone on the paired Android phone to locate it.",
    )
    async def snow_android_ring(duration_seconds: int = 5, device_id: str = "") -> str:
        """Trigger audible ringtone on Android phone via Core."""
        result = await bridge.android_ring(duration_seconds=duration_seconds, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed triggering ringtone on Android phone."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_android_clipboard_push",
        description="Push text content to the Android device clipboard.",
    )
    async def snow_android_clipboard_push(text: str, device_id: str = "") -> str:
        """Push text to Android clipboard via Core."""
        result = await bridge.android_clipboard_push(text=text, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed pushing text to Android clipboard."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_android_launch_app",
        description="Launch an application on the paired Android device from the approved package whitelist.",
    )
    async def snow_android_launch_app(package_name: str, device_id: str = "") -> str:
        """Launch an approved application on Android via Core."""
        result = await bridge.android_launch_app(package_name=package_name, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed launching application '{package_name}' on Android."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_android_list_apps",
        description="List installed applications on the paired Android phone.",
    )
    async def snow_android_list_apps(limit: int = 50, device_id: str = "") -> str:
        """List installed applications on Android via Core."""
        result = await bridge.android_list_apps(limit=limit, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed listing applications on Android phone."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_android_file_send",
        description="Send a file from Windows to the paired Android phone's Downloads/SNOW directory.",
    )
    async def snow_android_file_send(source_path: str, device_id: str = "") -> str:
        """Send a file to the paired Android device via Core."""
        result = await bridge.android_file_send(file_path=source_path, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed sending file '{source_path}' to Android phone."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_android_file_receive",
        description="Request a file from the paired Android phone to the Windows transfer directory.",
    )
    async def snow_android_file_receive(remote_file_name: str, device_id: str = "") -> str:
        """Request a file from the paired Android device via Core."""
        result = await bridge.android_file_receive(file_name=remote_file_name, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed receiving file '{remote_file_name}' from Android phone."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    @server.tool(
        name="snow_transfer_file",
        description=(
            "Unified cross-device file transfer tool. Coordinates file transfers between Windows, "
            "remote Android phones, or peer devices. Direction must be 'to_device' or 'from_device' "
            "when source_device is omitted, or explicit source_device and target_device may be provided."
        ),
    )
    async def snow_transfer_file(
        source_path: str,
        destination_path: str = "",
        direction: str = "to_device",
        target_device: str = "",
        source_device: str = "",
    ) -> str:
        """Transfer file between devices."""
        result = await bridge.transfer_file(
            source_path=source_path,
            destination_path=destination_path,
            direction=direction,
            target_device=target_device,
            source_device=source_device,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "File transfer operation failed."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_mesh_connect_peer",
        description=(
            "Connect, authenticate, or pair with a remote SNOW Desktop Core peer on the local network."
        ),
    )
    async def snow_mesh_connect_peer(
        host: str,
        port: int = 8765,
        pin: str = "",
        expected_fingerprint: str = "",
    ) -> str:
        """Connect to a peer SNOW Desktop Core."""
        result = await bridge.mesh_connect_peer(
            host=host,
            port=port,
            pin=pin,
            expected_fingerprint=expected_fingerprint,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Peer connection to {host}:{port} failed."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_android_send_message",
        description=(
            "Open the SMS compose interface on paired Android phone with prefilled recipient "
            "and message. The final dispatch remains under deliberate user control on the device. "
            "Direct background SMS dispatch is restricted for AI safety."
        ),
    )
    async def snow_android_send_message(
        recipient: str,
        message: str,
        mode: str = "intent",
        device_id: str = "",
    ) -> str:
        """Compose SMS on paired Android phone via system intent."""
        result = await bridge.android_send_message(
            recipient=recipient,
            message=message,
            mode=mode,
            device_id=device_id,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed preparing message for '{recipient}'."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    # =========================================================================
    # 5. Phase 21 P1 Capabilities
    # =========================================================================

    @server.tool(
        name="snow_android_file_list",
        description=(
            "Enumerate files and directories within the Android user's persisted SAF-granted folder. "
            "Returns SAF_FOLDER_NOT_CONFIGURED if no directory grant exists."
        ),
    )
    async def snow_android_file_list(subpath: str = "", device_id: str = "") -> str:
        """List files in Android SAF-granted folder."""
        result = await bridge.android_file_list(subpath=subpath, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed retrieving Android SAF file list."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_android_notifications_list",
        description=(
            "List active in-memory non-sensitive notifications received from the Android device. "
            "Sensitive banking, authenticator, and OTP apps are excluded."
        ),
    )
    async def snow_android_notifications_list(device_id: str = "") -> str:
        """List active non-sensitive notifications from Android."""
        result = await bridge.android_notifications_list(device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed retrieving notifications."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_android_notification_dismiss",
        description="Dismiss an active notification on the connected Android phone by notification key.",
    )
    async def snow_android_notification_dismiss(key: str, device_id: str = "") -> str:
        """Dismiss Android notification by key."""
        result = await bridge.android_notification_dismiss(key=key, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed dismissing notification '{key}'."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_media_control",
        description=(
            "Send media playback and volume control commands (play_pause, next, previous, volume_up, "
            "volume_down, mute) to Windows or Android."
        ),
    )
    async def snow_media_control(
        action: str, target: str = "windows", device_id: str = ""
    ) -> str:
        """Send media playback or volume command to Windows or Android."""
        result = await bridge.media_control(action=action, target=target, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed dispatching media control '{action}'."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_share_link",
        description=(
            "Safely share a validated HTTP/HTTPS URL or text note with the target device. "
            "Unsafe schemes (javascript:, file:, intent:) are rejected."
        ),
    )
    async def snow_share_link(
        url: str = "", text: str = "", target: str = "windows", device_id: str = ""
    ) -> str:
        """Share HTTP/HTTPS link or text note with Windows or Android."""
        result = await bridge.share_link(url=url, text=text, target=target, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed sharing link or text."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_activity_history",
        description="Query the secret-redacted audit activity log of capability executions and approval decisions.",
    )
    async def snow_activity_history(
        limit: int = 50, offset: int = 0, event_type: str = "", principal: str = ""
    ) -> str:
        """Query secret-redacted audit activity log."""
        result = await bridge.activity_history(
            limit=limit, offset=offset, event_type=event_type, principal=principal
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed querying activity history."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)
