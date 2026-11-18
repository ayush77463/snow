"""Tool classification registry for SNOW MCP.

Explicitly categorizes MCP tools into execution tiers:
- LOCAL_WINDOWS: Capabilities that execute directly in-process against local
  Windows APIs without requiring the Core daemon or an online phone.
- CROSS_DEVICE: Capabilities that coordinate cross-device state or communicate
  with the Android device, requiring the SNOW Core daemon.

Unknown tools fail safely with a structured rejection rather than being routed
to an arbitrary execution path.
"""

from __future__ import annotations

from enum import Enum
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ToolCategory(str, Enum):
    """Execution category for SNOW MCP tools."""

    LOCAL_WINDOWS = "LOCAL_WINDOWS"
    CROSS_DEVICE = "CROSS_DEVICE"


# Explicit static mapping of all registered SNOW MCP tools to their execution tier.
TOOL_REGISTRY: dict[str, ToolCategory] = {
    # -------------------------------------------------------------------------
    # Local Windows Capabilities (In-Process Execution)
    # -------------------------------------------------------------------------
    "snow_windows_battery": ToolCategory.LOCAL_WINDOWS,
    "snow_windows_system_info": ToolCategory.LOCAL_WINDOWS,
    "snow_windows_processes": ToolCategory.LOCAL_WINDOWS,
    "snow_windows_launch_app": ToolCategory.LOCAL_WINDOWS,
    "snow_windows_file_read": ToolCategory.LOCAL_WINDOWS,
    "snow_windows_file_write": ToolCategory.LOCAL_WINDOWS,
    "snow_windows_file_list": ToolCategory.LOCAL_WINDOWS,
    "snow_windows_file_search": ToolCategory.LOCAL_WINDOWS,
    "snow_windows_terminal_exec": ToolCategory.LOCAL_WINDOWS,
    "snow_windows_clipboard_get": ToolCategory.LOCAL_WINDOWS,
    "snow_windows_clipboard_set": ToolCategory.LOCAL_WINDOWS,

    # -------------------------------------------------------------------------
    # Cross-Device / Core Daemon Capabilities (IPC Required)
    # -------------------------------------------------------------------------
    "snow_get_device_status": ToolCategory.CROSS_DEVICE,
    "snow_list_devices": ToolCategory.CROSS_DEVICE,
    "snow_sync_clipboard": ToolCategory.CROSS_DEVICE,
    "snow_android_battery": ToolCategory.CROSS_DEVICE,
    "snow_android_ring": ToolCategory.CROSS_DEVICE,
    "snow_android_clipboard_push": ToolCategory.CROSS_DEVICE,
    "snow_android_launch_app": ToolCategory.CROSS_DEVICE,
    "snow_android_list_apps": ToolCategory.CROSS_DEVICE,
    "snow_android_file_send": ToolCategory.CROSS_DEVICE,
    "snow_android_file_receive": ToolCategory.CROSS_DEVICE,
    "snow_transfer_file": ToolCategory.CROSS_DEVICE,
    "snow_mesh_connect_peer": ToolCategory.CROSS_DEVICE,
    "snow_android_send_message": ToolCategory.CROSS_DEVICE,
}


def get_tool_category(tool_name: str) -> Optional[ToolCategory]:
    """Retrieve the execution category for a given MCP tool name.

    Returns None if the tool is unrecognized, enabling callers to enforce
    fail-safe unknown tool handling.
    """
    if not tool_name or not isinstance(tool_name, str):
        return None
    return TOOL_REGISTRY.get(tool_name.strip())


def is_local_windows_tool(tool_name: str) -> bool:
    """Return True if the tool executes as a local Windows capability."""
    return get_tool_category(tool_name) == ToolCategory.LOCAL_WINDOWS


def is_cross_device_tool(tool_name: str) -> bool:
    """Return True if the tool requires Core IPC or cross-device coordination."""
    return get_tool_category(tool_name) == ToolCategory.CROSS_DEVICE
