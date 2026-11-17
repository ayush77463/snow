"""Unified static MCP tool registry for SNOW.

Exposes standardized MCP tools for both Windows and Android capabilities to AI assistants.
All 21 tools are statically discoverable via list_tools, even when the Core or Android
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

# Complete static catalog of the 21 SNOW tool names
ALL_TOOL_NAMES: List[str] = [
    # General (Live Core)
    "snow_get_device_status",
    "snow_list_devices",
    # Windows Capabilities
    "snow_windows_battery",
    "snow_windows_system_info",
    "snow_windows_processes",
    "snow_windows_launch_app",
    "snow_windows_file_read",
    "snow_windows_file_write",
    "snow_windows_file_list",
    "snow_windows_file_search",
    "snow_windows_terminal_exec",
    "snow_windows_clipboard_get",
    "snow_windows_clipboard_set",
    # Cross-Device Synchronization
    "snow_sync_clipboard",
    # Android Capabilities
    "snow_android_battery",
    "snow_android_ring",
    "snow_android_clipboard_push",
    "snow_android_launch_app",
    "snow_android_list_apps",
    "snow_android_file_send",
    "snow_android_file_receive",
    # Mesh and Unified Transfer (Phase 9)
    "snow_transfer_file",
    "snow_mesh_connect_peer",
]


def register_all_tools(server: FastMCP, bridge: SnowMcpBridge) -> None:
    """Register all 21 static MCP tools onto the provided FastMCP server instance."""

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
            "Synchronize clipboard between Windows laptop and Android phone. "
            "Directions: 'laptop_to_phone' pushes Windows clipboard to Android. "
            "'phone_to_laptop' reports unsupported due to Android OS background restrictions."
        ),
    )
    async def snow_sync_clipboard(
        direction: str = "laptop_to_phone", device_id: str = ""
    ) -> str:
        """Synchronize clipboard between laptop and phone."""
        result = await bridge.sync_clipboard(direction=direction, device_id=device_id)
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
            "Unified cross-device file transfer tool. Coordinates file transfers between Windows "
            "and a remote Android phone or peer device. Direction must be 'to_device' or 'from_device'."
        ),
    )
    async def snow_transfer_file(
        source_path: str,
        destination_path: str = "",
        direction: str = "to_device",
        target_device: str = "",
    ) -> str:
        """Transfer file between devices."""
        result = await bridge.transfer_file(
            source_path=source_path,
            destination_path=destination_path,
            direction=direction,
            target_device=target_device,
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
