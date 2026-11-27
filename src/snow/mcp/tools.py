"""Unified static MCP tool registry for SNOW.

Exposes standardized MCP tools for both Windows and Android capabilities to AI assistants.
All 60 tools are statically discoverable via list_tools, even when the Core or Android
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
    """Register all 60 static MCP tools onto the provided FastMCP server instance."""
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
        description=(
            "Read text from the Windows laptop clipboard, plus OS image metadata and up to "
            "3 latest shared clipboard buffer entries when text is empty."
        ),
    )
    async def snow_windows_clipboard_get() -> str:
        """Read text, image metadata, and recent buffer items from Windows clipboard."""
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
        """List files in Android SAF-granted folder (strictly scoped to SAF for AI callers)."""
        result = await bridge.android_file_list(subpath=subpath, device_id=device_id, scope="saf")
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

    # =========================================================================
    # 7. Capture & Workflow Tools (Phase 24)
    # =========================================================================

    @server.tool(
        name="snow_windows_screenshot",
        description="Capture the primary Windows desktop screen as an authenticated, bounded PNG image staged in captures directory.",
    )
    async def snow_windows_screenshot(approval_id: str = "") -> str:
        """Capture the primary Windows screen via native Win32 GDI/GDI+."""
        result = await bridge.windows_screenshot(approval_id=approval_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed capturing Windows screen."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_android_screenshot",
        description="Capture the connected Android phone screen via OS-mediated MediaProjection user consent.",
    )
    async def snow_android_screenshot(device_id: str = "", approval_id: str = "") -> str:
        """Capture the connected Android phone screen via MediaProjection consent."""
        result = await bridge.android_screenshot(device_id=device_id, approval_id=approval_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed capturing Android screen."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_android_camera_capture",
        description="Capture a photograph using the connected Android device camera requiring foreground user confirmation.",
    )
    async def snow_android_camera_capture(device_id: str = "", approval_id: str = "") -> str:
        """Capture a photograph using the connected Android camera."""
        result = await bridge.android_camera_capture(device_id=device_id, approval_id=approval_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed capturing Android camera photograph."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_workflow_run",
        description="Execute an authorized declarative multi-step workflow with bounded step execution and approval checks.",
    )
    async def snow_workflow_run(
        workflow_id: str,
        arguments: Optional[dict[str, Any]] = None,
        approval_id: str = "",
    ) -> str:
        """Execute a predefined declarative multi-step workflow."""
        result = await bridge.workflow_run(
            workflow_id=workflow_id,
            arguments=arguments,
            approval_id=approval_id,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed running workflow '{workflow_id}'."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    # =========================================================================
    # Phase 26B: Shared Clipboard Buffer Tools
    # =========================================================================

    @server.tool(
        name="snow_clipboard_buffer_list",
        description="List metadata of up to 15 most recent items in the SNOW shared clipboard ring buffer.",
    )
    async def snow_clipboard_buffer_list(limit: int = 15) -> str:
        """List metadata for items in the shared clipboard buffer."""
        result = await bridge.clipboard_buffer_list(limit=limit)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed listing clipboard buffer items."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_clipboard_buffer_add",
        description="Add a text entry to the SNOW shared clipboard ring buffer (requires owner approval for AI).",
    )
    async def snow_clipboard_buffer_add(
        text: str,
        is_pinned: bool = False,
        approval_id: str = "",
    ) -> str:
        """Add text content to the shared clipboard buffer."""
        result = await bridge.clipboard_buffer_add(
            text=text,
            is_pinned=is_pinned,
            approval_id=approval_id or None,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed adding item to clipboard buffer."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_clipboard_buffer_apply",
        description="Apply an item from the shared clipboard buffer to Windows or Android (requires approval).",
    )
    async def snow_clipboard_buffer_apply(
        item_id: str = "",
        target: str = "pc",
        approval_id: str = "",
    ) -> str:
        """Apply a shared clipboard buffer item to local Windows or remote Android device."""
        result = await bridge.clipboard_buffer_apply(
            item_id=item_id,
            target=target,
            approval_id=approval_id or None,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed applying clipboard buffer item."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_mesh_topology",
        description="Inspect reachable SNOW network nodes, transport status, and effective principal permissions.",
    )
    async def snow_mesh_topology() -> str:
        """Inspect reachable SNOW network topology and principal-scoped capabilities."""
        from snow.security.context import ExecutionContext, ExecutionPrincipal
        ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="fastmcp_stdio")
        result = await bridge.snow_mesh_topology(ctx=ctx)
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_mesh_health_summary",
        description="Return a compact summary of SNOW mesh health, connected/offline nodes, active transports, and core status.",
    )
    async def snow_mesh_health_summary() -> str:
        """Summarize SNOW mesh health and node connectivity without exposing credentials."""
        from snow.security.context import ExecutionContext, ExecutionPrincipal
        ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="fastmcp_stdio")
        result = await bridge.snow_mesh_health_summary(ctx=ctx)
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_windows_active_window",
        description="Query the active foreground window title and process name on the Windows host.",
    )
    async def snow_windows_active_window() -> str:
        """Return currently focused foreground window title and process metadata."""
        result = await bridge.windows_active_window()
        return json.dumps(result.get("data") if isinstance(result.get("data"), dict) else result, indent=2)

    @server.tool(
        name="snow_windows_notify",
        description="Display a bounded Windows desktop toast notification with title and message.",
    )
    async def snow_windows_notify(title: str, message: str) -> str:
        """Show a native Windows desktop notification."""
        result = await bridge.windows_notify(title=title, message=message)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "NOTIFICATION_FAILED"),
                "error": result.get("error", "Failed displaying Windows notification."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_windows_lock_screen",
        description="Lock the Windows workstation session cleanly (requires explicit owner approval for AI calls).",
    )
    async def snow_windows_lock_screen(approval_id: str = "") -> str:
        """Lock the Windows host screen via LockWorkStation (approval-gated for AI)."""
        result = await bridge.windows_lock_screen(approval_id=approval_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed locking Windows workstation."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    # =========================================================================
    # V5.2.0 Stage 6A Additions (43..48)
    # =========================================================================

    @server.tool(
        name="snow_youtube_play",
        description="Open a validated YouTube video/URL or YouTube search query on Windows or Android.",
    )
    async def snow_youtube_play(
        query: str = "",
        url: str = "",
        target: str = "windows",
        device_id: str = "",
    ) -> str:
        """Open a YouTube URL or search query safely on Windows or Android."""
        result = await bridge.youtube_play(
            query=query, url=url, target=target, device_id=device_id
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed opening YouTube."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_web_open",
        description="Safely open an HTTP or HTTPS URL in the browser on Windows or Android.",
    )
    async def snow_web_open(
        url: str,
        target: str = "windows",
        device_id: str = "",
    ) -> str:
        """Open a validated HTTP/HTTPS URL cleanly on Windows or Android."""
        result = await bridge.web_open(url=url, target=target, device_id=device_id)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed opening web URL."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_windows_list_windows",
        description="List open visible top-level desktop windows on Windows with hwnd, title, and process metadata.",
    )
    async def snow_windows_list_windows(
        include_empty_titles: bool = False,
        limit: int = 50,
    ) -> str:
        """Enumerate visible top-level windows on the Windows host."""
        result = await bridge.windows_list_windows(
            include_empty_titles=include_empty_titles,
            limit=limit,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed listing Windows windows."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_windows_focus_window",
        description="Bring an open Windows desktop window to focus by hwnd, title_contains, or process_name.",
    )
    async def snow_windows_focus_window(
        hwnd: Optional[int] = None,
        title_contains: str = "",
        process_name: str = "",
    ) -> str:
        """Focus a matching visible window on the Windows host."""
        result = await bridge.windows_focus_window(
            hwnd=hwnd,
            title_contains=title_contains,
            process_name=process_name,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed focusing Windows window."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_system_volume_set",
        description="Set the master system audio volume percentage (0-100) on Windows or Android.",
    )
    async def snow_system_volume_set(
        level: int,
        target: str = "windows",
        device_id: str = "",
    ) -> str:
        """Set system volume level (0-100) on Windows or connected Android device."""
        result = await bridge.system_volume_set(
            level=level,
            target=target,
            device_id=device_id,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed setting system volume."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_federation_peers",
        description="List secret-redacted federation grants, trusted remote peers, and reachability state.",
    )
    async def snow_federation_peers(include_revoked: bool = False) -> str:
        """Return redacted federation grants and peer reachability state."""
        result = await bridge.federation_peers(include_revoked=include_revoked)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed querying federation peers."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    # =========================================================================
    # V5.2.0 Stage 6B Additions (49..54 -> 54 Total Tools)
    # =========================================================================

    @server.tool(
        name="snow_android_whatsapp_send",
        description=(
            "Prepare a WhatsApp draft on a connected Android phone for explicit user review and tap-to-send. "
            "Requires recipient, non-empty message, and explicit owner approval for AI calls."
        ),
    )
    async def snow_android_whatsapp_send(
        recipient: str,
        message: str,
        user_confirmed: bool = False,
        target_device: str = "",
    ) -> str:
        """Prepare an explicit-consent WhatsApp draft on the target Android phone."""
        result = await bridge.android_whatsapp_send(
            recipient=recipient,
            message=message,
            user_confirmed=user_confirmed,
            target_device=target_device,
        )
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_android_notification_reply",
        description="Reply directly to a connected Android notification supporting RemoteInput direct reply.",
    )
    async def snow_android_notification_reply(
        notification_key: str,
        reply_text: str,
        target_device: str = "",
    ) -> str:
        """Send a direct reply to an active Android notification key."""
        result = await bridge.android_notification_reply(
            notification_key=notification_key,
            reply_text=reply_text,
            target_device=target_device,
        )
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_windows_hotkey",
        description=(
            "Dispatch an allowlisted Windows keyboard shortcut (win+d, alt+tab, ctrl+shift+s, win+tab, "
            "ctrl+c, ctrl+v, win+e, or approval-gated alt+f4)."
        ),
    )
    async def snow_windows_hotkey(shortcut: str) -> str:
        """Trigger an allowlisted Windows shortcut chord."""
        result = await bridge.windows_hotkey(shortcut=shortcut)
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_windows_brightness_set",
        description="Set the Windows display brightness level cleanly between 0 and 100.",
    )
    async def snow_windows_brightness_set(level: int) -> str:
        """Adjust Windows display brightness percentage (0-100)."""
        result = await bridge.windows_brightness_set(level=level)
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_android_dnd_toggle",
        description=(
            "Enable or disable Do Not Disturb on a connected Android device when Notification Policy Access is granted."
        ),
    )
    async def snow_android_dnd_toggle(enabled: bool, target_device: str = "") -> str:
        """Toggle Android Do Not Disturb mode."""
        result = await bridge.android_dnd_toggle(enabled=enabled, target_device=target_device)
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_cross_network_execute",
        description=(
            "Execute an explicitly permitted capability on a peer device in a federated SNOW network "
            "enforcing 5-tier grant ∩ device intersections and explicit approval gates."
        ),
    )
    async def snow_cross_network_execute(
        target_network_id: str,
        target_device_id: str,
        capability: str,
        params: Optional[dict[str, Any]] = None,
        grant_token: str = "",
    ) -> str:
        """Execute a capability across a federated SNOW network boundary."""
        result = await bridge.cross_network_execute(
            target_network_id=target_network_id,
            target_device_id=target_device_id,
            capability=capability,
            params=params,
            grant_token=grant_token,
        )
        return json.dumps(result, indent=2)

    # =========================================================================
    # M4.4 Stage 5 Additions (55..60 -> 60 Total Tools)
    # =========================================================================

    @server.tool(
        name="snow_android_file_read",
        description="Read a UTF-8 text file (up to 256 KiB) inside Android's persisted SAF folder using a strict relative path.",
    )
    async def snow_android_file_read(path: str, device_id: str = "") -> str:
        """Read UTF-8 file text inside the configured SAF folder on a connected Android device."""
        result = await bridge.android_file_read(path=path, device_id=device_id)
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_android_file_write",
        description=(
            "Write a UTF-8 text file (up to 256 KiB) inside Android's persisted SAF folder. "
            "Requires explicit owner approval for AI callers and explicit overwrite=True to replace existing files."
        ),
    )
    async def snow_android_file_write(
        path: str,
        content: str,
        overwrite: bool = False,
        approval_id: str = "",
        device_id: str = "",
    ) -> str:
        """Write UTF-8 text into Android's persisted SAF folder subject to approval and overwrite controls."""
        result = await bridge.android_file_write(
            path=path,
            content=content,
            overwrite=overwrite,
            approval_id=approval_id,
            device_id=device_id,
        )
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_android_file_search",
        description="Search filenames inside Android's persisted SAF folder with bounded depth and result count.",
    )
    async def snow_android_file_search(
        query: str,
        subpath: str = "",
        max_results: int = 25,
        max_depth: int = 3,
        device_id: str = "",
    ) -> str:
        """Search filenames in Android's configured SAF folder."""
        result = await bridge.android_file_search(
            query=query,
            subpath=subpath,
            max_results=max_results,
            max_depth=max_depth,
            device_id=device_id,
        )
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_android_device_info",
        description="Read Android device model, OS version, RAM, storage summary, lock state, and live M4.3 transport state.",
    )
    async def snow_android_device_info(device_id: str = "") -> str:
        """Query read-only Android device and transport info."""
        result = await bridge.android_device_info(device_id=device_id)
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_android_audio_status",
        description="Read Android media/ring/alarm volume levels, ringer mode, and Do Not Disturb status without altering audio settings.",
    )
    async def snow_android_audio_status(device_id: str = "") -> str:
        """Query read-only Android audio and DND state."""
        result = await bridge.android_audio_status(device_id=device_id)
        return json.dumps(result, indent=2)

    @server.tool(
        name="snow_android_clipboard_get",
        description="Read text from the paired Android clipboard strictly when SNOW is in the visible foreground.",
    )
    async def snow_android_clipboard_get(device_id: str = "") -> str:
        """Read current Android clipboard text subject to foreground lifecycle enforcement."""
        result = await bridge.android_clipboard_get(device_id=device_id)
        return json.dumps(result, indent=2)


def register_clipboard_buffer_tools(server: FastMCP, bridge: SnowMcpBridge) -> None:
    """Register Phase 26B shared clipboard buffer tools independently if needed."""
    _orig_tool = server.tool

    def _annotated_tool(*args: Any, **kwargs: Any) -> Any:
        tool_name = kwargs.get("name")
        if tool_name and "annotations" not in kwargs:
            ann = get_mcp_annotations(tool_name)
            if ann is not None:
                kwargs["annotations"] = ann
        return _orig_tool(*args, **kwargs)

    server.tool = _annotated_tool

    @server.tool(
        name="snow_clipboard_buffer_list",
        description="List metadata of up to 15 most recent items in the SNOW shared clipboard ring buffer.",
    )
    async def snow_clipboard_buffer_list(limit: int = 15) -> str:
        result = await bridge.clipboard_buffer_list(limit=limit)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed listing clipboard buffer items."),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_clipboard_buffer_add",
        description="Add a text entry to the SNOW shared clipboard ring buffer (requires owner approval for AI).",
    )
    async def snow_clipboard_buffer_add(
        text: str,
        is_pinned: bool = False,
        approval_id: str = "",
    ) -> str:
        result = await bridge.clipboard_buffer_add(
            text=text,
            is_pinned=is_pinned,
            approval_id=approval_id or None,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed adding item to clipboard buffer."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)

    @server.tool(
        name="snow_clipboard_buffer_apply",
        description="Apply an item from the shared clipboard buffer to Windows or Android (requires approval).",
    )
    async def snow_clipboard_buffer_apply(
        item_id: str = "",
        target: str = "pc",
        approval_id: str = "",
    ) -> str:
        result = await bridge.clipboard_buffer_apply(
            item_id=item_id,
            target=target,
            approval_id=approval_id or None,
        )
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", "Failed applying clipboard buffer item."),
                "data": result.get("data"),
            }, indent=2)
        return json.dumps(result.get("data", {}) or result, indent=2)
