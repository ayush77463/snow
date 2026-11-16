"""Unified static MCP tool registry for SNOW.

Exposes standardized MCP tools for both Windows and Android capabilities to AI assistants.
All 16 tools are statically discoverable via list_tools, even when the Core or Android
device is currently offline.

Deferred tools (Phase 5 Windows and Phase 6 Android) return structured NOT_IMPLEMENTED_YET
responses without failing discovery or crashing the MCP server.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from snow.mcp.bridge import SnowMcpBridge

# Complete static catalog of the 16 SNOW tool names
ALL_TOOL_NAMES: List[str] = [
    # General (Live Core)
    "snow_get_device_status",
    "snow_list_devices",
    # Windows Capabilities (Phase 5 Deferred)
    "snow_windows_battery",
    "snow_windows_system_info",
    "snow_windows_processes",
    "snow_windows_launch_app",
    "snow_windows_file_read",
    "snow_windows_file_write",
    "snow_windows_file_list",
    # Android Capabilities (Phase 6 Deferred)
    "snow_android_battery",
    "snow_android_ring",
    "snow_android_clipboard_push",
    "snow_android_launch_app",
    "snow_android_list_apps",
    "snow_android_file_send",
    "snow_android_file_receive",
]


def register_all_tools(server: FastMCP, bridge: SnowMcpBridge) -> None:
    """Register all 16 static MCP tools onto the provided FastMCP server instance."""

    # =========================================================================
    # 1. General Tools (Live Core via IPC)
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
                "hint": "Ensure 'python -m snow' is running on the host machine.",
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
    # 2. Windows Tools (Phase 5 Live Capabilities via Core IPC)
    # =========================================================================

    @server.tool(
        name="snow_windows_battery",
        description="Retrieve battery percentage, power line status, and battery health of the Windows laptop.",
    )
    async def snow_windows_battery() -> str:
        """Query Windows laptop battery telemetry via Core."""
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
        """Query Windows system and hardware telemetry via Core."""
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
        """Query running Windows processes via Core."""
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
        description="Launch an explicitly permitted Windows application from the approved whitelist (notepad, calc, explorer, taskmgr, mspaint).",
    )
    async def snow_windows_launch_app(app_name: str) -> str:
        """Launch an approved Windows application via Core."""
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
        description="Read UTF-8 text file contents from configured approved directories on the Windows laptop (up to 256 KiB).",
    )
    async def snow_windows_file_read(file_path: str, max_bytes: int = 262144) -> str:
        """Read a file in approved Windows directories via Core."""
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
        description="Write UTF-8 text content atomically to a file in configured approved directories on the Windows laptop (up to 256 KiB).",
    )
    async def snow_windows_file_write(
        file_path: str, content: str, overwrite: bool = False, max_bytes: int = 262144
    ) -> str:
        """Write content to an approved Windows file path via Core."""
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
        description="List files within approved directories on the Windows laptop.",
    )
    async def snow_windows_file_list(directory_path: str = "", limit: int = 50) -> str:
        """List files in approved Windows directories via Core."""
        result = await bridge.windows_file_list(directory_path=directory_path, limit=limit)
        if not result.get("success", False):
            return json.dumps({
                "success": False,
                "status": result.get("status", "ERROR"),
                "error": result.get("error", f"Failed listing directory '{directory_path}'."),
            }, indent=2)
        return json.dumps(result.get("data", {}), indent=2)

    # =========================================================================
    # 3. Android Tools (Phase 6 Implementation Deferred)
    # =========================================================================

    @server.tool(
        name="snow_android_battery",
        description="Query battery level, temperature, and charging status from paired Android phone.",
    )
    async def snow_android_battery(device_id: str = "") -> str:
        """Query Android phone battery telemetry (Phase 6)."""
        return json.dumps({
            "success": False,
            "status": "NOT_IMPLEMENTED_YET",
            "capability": "snow_android_battery",
            "planned_phase": "Phase 6 (Android Capabilities)",
            "message": "Android battery status query capability is planned for Phase 6.",
        }, indent=2)

    @server.tool(
        name="snow_android_ring",
        description="Trigger an audible alert/ringtone on the paired Android phone to locate it.",
    )
    async def snow_android_ring(duration_seconds: int = 10, device_id: str = "") -> str:
        """Trigger audible ringtone on Android phone (Phase 6)."""
        return json.dumps({
            "success": False,
            "status": "NOT_IMPLEMENTED_YET",
            "capability": "snow_android_ring",
            "planned_phase": "Phase 6 (Android Capabilities)",
            "message": "Find My Phone audible alert capability is planned for Phase 6.",
        }, indent=2)

    @server.tool(
        name="snow_android_clipboard_push",
        description="Push text content to the Android device clipboard.",
    )
    async def snow_android_clipboard_push(text: str, device_id: str = "") -> str:
        """Push text to Android clipboard (Phase 6)."""
        return json.dumps({
            "success": False,
            "status": "NOT_IMPLEMENTED_YET",
            "capability": "snow_android_clipboard_push",
            "planned_phase": "Phase 6 (Android Capabilities)",
            "message": "Android clipboard push capability is planned for Phase 6.",
        }, indent=2)

    @server.tool(
        name="snow_android_launch_app",
        description="Launch an application on the paired Android device from the approved package whitelist.",
    )
    async def snow_android_launch_app(package_name: str, device_id: str = "") -> str:
        """Launch an approved application on Android (Phase 6)."""
        return json.dumps({
            "success": False,
            "status": "NOT_IMPLEMENTED_YET",
            "capability": "snow_android_launch_app",
            "planned_phase": "Phase 6 (Android Capabilities)",
            "message": f"Android application launch for '{package_name}' is planned for Phase 6.",
        }, indent=2)

    @server.tool(
        name="snow_android_list_apps",
        description="List installed applications on the paired Android phone.",
    )
    async def snow_android_list_apps(device_id: str = "") -> str:
        """List installed applications on Android (Phase 6)."""
        return json.dumps({
            "success": False,
            "status": "NOT_IMPLEMENTED_YET",
            "capability": "snow_android_list_apps",
            "planned_phase": "Phase 6 (Android Capabilities)",
            "message": "Android application listing capability is planned for Phase 6.",
        }, indent=2)

    @server.tool(
        name="snow_android_file_send",
        description="Send a file from Windows to the paired Android phone's Downloads/SNOW directory.",
    )
    async def snow_android_file_send(source_path: str, device_id: str = "") -> str:
        """Send a file to the paired Android device (Phase 6 capability integration)."""
        return json.dumps({
            "success": False,
            "status": "NOT_IMPLEMENTED_YET",
            "capability": "snow_android_file_send",
            "planned_phase": "Phase 6 (Android Capabilities)",
            "message": "Autonomous AI-driven file push capability is planned for Phase 6 capability integration.",
        }, indent=2)

    @server.tool(
        name="snow_android_file_receive",
        description="Request a file from the paired Android phone to the Windows transfer directory.",
    )
    async def snow_android_file_receive(remote_file_name: str, device_id: str = "") -> str:
        """Request a file from the paired Android device (Phase 6 capability integration)."""
        return json.dumps({
            "success": False,
            "status": "NOT_IMPLEMENTED_YET",
            "capability": "snow_android_file_receive",
            "planned_phase": "Phase 6 (Android Capabilities)",
            "message": "Autonomous AI-driven file pull capability is planned for Phase 6 capability integration.",
        }, indent=2)
