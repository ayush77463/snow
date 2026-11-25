"""Tool classification and dynamic capability registry for SNOW MCP.

Explicitly categorizes MCP tools into execution tiers:
- LOCAL_WINDOWS: Capabilities that execute directly in-process against local
  Windows APIs without requiring the Core daemon or an online phone.
- CROSS_DEVICE: Capabilities that coordinate cross-device state or communicate
  with the Android device, requiring the SNOW Core daemon.

In Phase 21:
- Replaces fixed-count static assumptions with a dynamic, metadata-rich capability registry.
- Every capability exposes structured metadata: tier, read_only_hint, destructive_hint,
  requires_approval, os_classification, and description.
- Retains full backward compatibility with TOOL_REGISTRY and category helpers.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class ToolCategory(str, Enum):
    """Execution category for SNOW MCP tools."""

    LOCAL_WINDOWS = "LOCAL_WINDOWS"
    CROSS_DEVICE = "CROSS_DEVICE"


@dataclass(frozen=True)
class CapabilityMetadata:
    """Structured metadata defining capability execution and safety characteristics."""

    name: str
    category: ToolCategory
    tier: str
    read_only_hint: bool
    destructive_hint: bool
    requires_approval: bool
    os_classification: str  # "windows", "android", "cross_platform"
    description: str

    def to_dict(self) -> dict[str, Any]:
        """Convert metadata to dictionary representation."""
        res = asdict(self)
        res["category"] = self.category.value
        return res


# Dynamic internal storage of registered capability metadata
_CAPABILITY_REGISTRY: dict[str, CapabilityMetadata] = {}

# Phase 26B Shared Clipboard Buffer Capabilities
CLIPBOARD_BUFFER_CAPABILITIES: dict[str, CapabilityMetadata] = {
    "snow_clipboard_buffer_list": CapabilityMetadata(
        name="snow_clipboard_buffer_list",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="List the 10 most recent items in the SNOW shared clipboard ring buffer.",
    ),
    "snow_clipboard_buffer_add": CapabilityMetadata(
        name="snow_clipboard_buffer_add",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=True,
        os_classification="cross_platform",
        description="Add a text entry to the SNOW shared clipboard ring buffer.",
    ),
    "snow_clipboard_buffer_apply": CapabilityMetadata(
        name="snow_clipboard_buffer_apply",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=True,
        os_classification="cross_platform",
        description="Apply a specific item from the shared clipboard buffer to Windows or Android.",
    ),
}


def register_capability(meta: CapabilityMetadata) -> None:
    """Register or update a capability in the dynamic registry."""
    if not meta.name or not isinstance(meta.name, str):
        raise ValueError("Capability name must be a non-empty string.")
    _CAPABILITY_REGISTRY[meta.name.strip()] = meta


def get_capability_metadata(tool_name: str) -> Optional[CapabilityMetadata]:
    """Retrieve metadata for a given capability name."""
    if not tool_name or not isinstance(tool_name, str):
        return None
    name = tool_name.strip()
    if name in _CAPABILITY_REGISTRY:
        return _CAPABILITY_REGISTRY[name]
    return CLIPBOARD_BUFFER_CAPABILITIES.get(name)


def list_capabilities() -> list[CapabilityMetadata]:
    """Return an ordered list of all registered capabilities."""
    return list(_CAPABILITY_REGISTRY.values())


PROHIBITED_FABRICATED_TOOLS: set[str] = {
    "snow_android_send_sms",
    "snow_android_take_photo",
    "snow_windows_file_delete",
}


def get_mcp_annotations(tool_name: str) -> Optional[Any]:
    """Retrieve FastMCP ToolAnnotations hint object for the specified tool if available."""
    meta = get_capability_metadata(tool_name)
    if not meta:
        return None
    try:
        from mcp.types import ToolAnnotations

        return ToolAnnotations(
            readOnlyHint=meta.read_only_hint,
            destructiveHint=meta.destructive_hint,
        )
    except Exception:
        return None


def validate_registry() -> tuple[bool, list[str]]:
    """Validate registry consistency, checking for missing metadata, strict types, and prohibited names."""
    errors: list[str] = []
    if not _CAPABILITY_REGISTRY:
        errors.append("Capability registry is empty.")

    valid_categories = {ToolCategory.LOCAL_WINDOWS, ToolCategory.CROSS_DEVICE}
    valid_os = {"windows", "android", "cross_platform"}

    for name, meta in _CAPABILITY_REGISTRY.items():
        if name in PROHIBITED_FABRICATED_TOOLS:
            errors.append(f"Prohibited fabricated tool '{name}' detected in registry.")
        if meta.name != name:
            errors.append(f"Name mismatch for capability '{name}': metadata has '{meta.name}'")
        if meta.category not in valid_categories:
            errors.append(f"Capability '{name}' has invalid category '{meta.category}'")
        if meta.os_classification not in valid_os:
            errors.append(f"Capability '{name}' has invalid os_classification '{meta.os_classification}'")
        if not meta.description or not meta.description.strip():
            errors.append(f"Capability '{name}' is missing a description.")

        # Strict type validations (no truthy/falsy coercion)
        if type(meta.read_only_hint) is not bool:
            errors.append(f"Capability '{name}': read_only_hint must be strict bool, got {type(meta.read_only_hint)}")
        if type(meta.destructive_hint) is not bool:
            errors.append(f"Capability '{name}': destructive_hint must be strict bool, got {type(meta.destructive_hint)}")
        if type(meta.requires_approval) is not bool:
            errors.append(f"Capability '{name}': requires_approval must be strict bool, got {type(meta.requires_approval)}")
        if not isinstance(meta.tier, str) or not meta.tier.strip():
            errors.append(f"Capability '{name}': tier must be non-empty string.")

    if len(_CAPABILITY_REGISTRY) != 54:
        errors.append(f"Expected exactly 54 registered capabilities (48 Stage 6A baseline + 6 V5.2 Stage 6B additions), found {len(_CAPABILITY_REGISTRY)}.")

    return (len(errors) == 0, errors)


# =============================================================================
# Initial Capability Registrations (24 baseline + 6 Phase 21 P1 tools)
# =============================================================================

_INITIAL_CAPABILITIES: list[CapabilityMetadata] = [
    # -------------------------------------------------------------------------
    # 1. Local Windows Capabilities (11 baseline tools)
    # -------------------------------------------------------------------------
    CapabilityMetadata(
        name="snow_windows_battery",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Retrieve battery percentage, power line status, and battery health of the Windows laptop.",
    ),
    CapabilityMetadata(
        name="snow_windows_system_info",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Retrieve Windows system hardware specifications, OS build, and CPU/RAM utilization.",
    ),
    CapabilityMetadata(
        name="snow_windows_processes",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="List active Windows processes sorted by memory or CPU usage.",
    ),
    CapabilityMetadata(
        name="snow_windows_launch_app",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Launch a whitelisted Windows application or lock the workstation screen.",
    ),
    CapabilityMetadata(
        name="snow_windows_file_read",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Read the contents of a file within permitted Windows directory roots.",
    ),
    CapabilityMetadata(
        name="snow_windows_file_write",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=False,
        destructive_hint=True,
        requires_approval=False,
        os_classification="windows",
        description="Write text content to a file within permitted Windows directory roots.",
    ),
    CapabilityMetadata(
        name="snow_windows_file_list",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="List directory contents within permitted Windows directory roots.",
    ),
    CapabilityMetadata(
        name="snow_windows_file_search",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Search for files by query name within permitted Windows directory roots.",
    ),
    CapabilityMetadata(
        name="snow_windows_terminal_exec",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=False,
        destructive_hint=True,
        requires_approval=True,
        os_classification="windows",
        description="Execute a bounded shell command on Windows subject to policy and confirmation.",
    ),
    CapabilityMetadata(
        name="snow_windows_clipboard_get",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Get text, OS image metadata, and up to 3 latest shared clipboard buffer entries from Windows clipboard.",
    ),
    CapabilityMetadata(
        name="snow_windows_clipboard_set",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Copy text content to the Windows system clipboard.",
    ),

    # -------------------------------------------------------------------------
    # 2. Cross-Device / Core Daemon Capabilities (13 baseline tools)
    # -------------------------------------------------------------------------
    CapabilityMetadata(
        name="snow_get_device_status",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="Retrieve the operational status of SNOW Desktop Core daemon and connected devices.",
    ),
    CapabilityMetadata(
        name="snow_list_devices",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="List all known paired Android devices with connection and session status.",
    ),
    CapabilityMetadata(
        name="snow_sync_clipboard",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="Synchronize clipboard content between Windows and connected Android phone.",
    ),
    CapabilityMetadata(
        name="snow_android_battery",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="android",
        description="Retrieve battery level and charging status from the connected Android phone.",
    ),
    CapabilityMetadata(
        name="snow_android_ring",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="android",
        description="Trigger the Android device ringer or alert to help locate the phone.",
    ),
    CapabilityMetadata(
        name="snow_android_clipboard_push",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="android",
        description="Push text directly to the Android device clipboard.",
    ),
    CapabilityMetadata(
        name="snow_android_launch_app",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="android",
        description="Launch an authorized application on the Android device by package name.",
    ),
    CapabilityMetadata(
        name="snow_android_list_apps",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="android",
        description="List installed user-launchable applications on the Android device.",
    ),
    CapabilityMetadata(
        name="snow_android_file_send",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=True,
        requires_approval=True,
        os_classification="android",
        description="Initiate sending a file from Windows to the Android device.",
    ),
    CapabilityMetadata(
        name="snow_android_file_receive",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="android",
        description="Request a file from the Android device to be received on Windows.",
    ),
    CapabilityMetadata(
        name="snow_transfer_file",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=True,
        requires_approval=True,
        os_classification="cross_platform",
        description="Unified bidirectional file transfer across devices via HTTPS transfer server.",
    ),
    CapabilityMetadata(
        name="snow_mesh_connect_peer",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="Establish an authenticated mesh peer connection with another SNOW device node.",
    ),
    CapabilityMetadata(
        name="snow_android_send_message",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=True,
        os_classification="android",
        description="Send an SMS or compose a messaging draft on the Android device.",
    ),

    # -------------------------------------------------------------------------
    # 3. Phase 21 P1 Capabilities (6 new tools)
    # -------------------------------------------------------------------------
    CapabilityMetadata(
        name="snow_android_file_list",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="android",
        description="List files and directories within the Android user's persisted SAF-granted folder.",
    ),
    CapabilityMetadata(
        name="snow_android_notifications_list",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="android",
        description="List active in-memory non-sensitive notifications received from the Android device.",
    ),
    CapabilityMetadata(
        name="snow_android_notification_dismiss",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="android",
        description="Dismiss an active notification on the connected Android device by notification key.",
    ),
    CapabilityMetadata(
        name="snow_media_control",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="Send media playback and volume control commands (play_pause, next, previous, volume_up, volume_down, mute) to Windows or Android.",
    ),
    CapabilityMetadata(
        name="snow_share_link",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="Safely share a validated HTTP/HTTPS URL or text note with the target device.",
    ),
    CapabilityMetadata(
        name="snow_activity_history",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Query the secret-redacted audit activity log of capability executions and approval decisions.",
    ),
    CapabilityMetadata(
        name="snow_windows_screenshot",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=True,
        os_classification="windows",
        description="Capture the primary Windows desktop screen as an authenticated, bounded PNG image staged in captures directory.",
    ),
    CapabilityMetadata(
        name="snow_android_screenshot",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=True,
        os_classification="android",
        description="Capture the connected Android phone screen via OS-mediated MediaProjection user consent.",
    ),
    CapabilityMetadata(
        name="snow_android_camera_capture",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=True,
        os_classification="android",
        description="Capture a photograph using the connected Android device camera requiring foreground user confirmation.",
    ),
    CapabilityMetadata(
        name="snow_workflow_run",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=True,
        os_classification="cross_platform",
        description="Execute an authorized declarative multi-step workflow with bounded step execution and approval checks.",
    ),
    CapabilityMetadata(
        name="snow_clipboard_buffer_list",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="List the 10 most recent items in the SNOW shared clipboard ring buffer.",
    ),
    CapabilityMetadata(
        name="snow_clipboard_buffer_add",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=True,
        os_classification="cross_platform",
        description="Add a text entry to the SNOW shared clipboard ring buffer.",
    ),
    CapabilityMetadata(
        name="snow_clipboard_buffer_apply",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=True,
        os_classification="cross_platform",
        description="Apply a specific item from the shared clipboard buffer to Windows or Android.",
    ),
    CapabilityMetadata(
        name="snow_mesh_topology",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="Inspect reachable SNOW network nodes, transport status, and effective principal permissions.",
    ),
    CapabilityMetadata(
        name="snow_mesh_health_summary",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="Return a compact summary of SNOW mesh health, connected/offline nodes, active transports, and core reachability.",
    ),
    CapabilityMetadata(
        name="snow_windows_active_window",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Query the currently active foreground window title and owning process name on the Windows desktop.",
    ),
    CapabilityMetadata(
        name="snow_windows_notify",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Display a bounded Windows desktop toast notification with title and message.",
    ),
    CapabilityMetadata(
        name="snow_windows_lock_screen",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=False,
        destructive_hint=True,
        requires_approval=True,
        os_classification="windows",
        description="Lock the Windows workstation session cleanly (requires owner approval for AI callers).",
    ),
    # -------------------------------------------------------------------------
    # V5.2.0 Stage 6A Additions (6 new tools -> 48 total)
    # -------------------------------------------------------------------------
    CapabilityMetadata(
        name="snow_youtube_play",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="Open a validated YouTube video/URL or YouTube search query on Windows or connected Android device.",
    ),
    CapabilityMetadata(
        name="snow_web_open",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="Safely open an HTTP/HTTPS URL in the browser on Windows or connected Android device.",
    ),
    CapabilityMetadata(
        name="snow_windows_list_windows",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="List open visible top-level windows on the Windows desktop with hwnd, title, and process metadata.",
    ),
    CapabilityMetadata(
        name="snow_windows_focus_window",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Focus an open Windows desktop window by hwnd, window title substring, or process name.",
    ),
    CapabilityMetadata(
        name="snow_system_volume_set",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="Set the master system volume percentage (0-100) on Windows or connected Android device.",
    ),
    CapabilityMetadata(
        name="snow_federation_peers",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=True,
        destructive_hint=False,
        requires_approval=False,
        os_classification="cross_platform",
        description="List secret-redacted cross-network federation grants and peer reachability state.",
    ),
    # -------------------------------------------------------------------------
    # V5.2.0 Stage 6B Additions (6 new tools -> 54 total)
    # -------------------------------------------------------------------------
    CapabilityMetadata(
        name="snow_android_whatsapp_send",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=True,
        requires_approval=True,
        os_classification="android",
        description="Prepare an explicit-consent WhatsApp message draft on a connected Android phone (requires user tap to send).",
    ),
    CapabilityMetadata(
        name="snow_android_notification_reply",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=True,
        requires_approval=True,
        os_classification="android",
        description="Reply directly to an active Android notification supporting RemoteInput direct reply.",
    ),
    CapabilityMetadata(
        name="snow_windows_hotkey",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=False,
        destructive_hint=True,
        requires_approval=False,
        os_classification="windows",
        description="Trigger an allowlisted Windows keyboard shortcut (win+d, alt+tab, ctrl+shift+s, win+tab, ctrl+c, ctrl+v, win+e, alt+f4 [approval gated]).",
    ),
    CapabilityMetadata(
        name="snow_windows_brightness_set",
        category=ToolCategory.LOCAL_WINDOWS,
        tier=ToolCategory.LOCAL_WINDOWS.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="windows",
        description="Set the primary Windows display brightness percentage cleanly between 0 and 100.",
    ),
    CapabilityMetadata(
        name="snow_android_dnd_toggle",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=False,
        requires_approval=False,
        os_classification="android",
        description="Toggle Do Not Disturb mode on a connected Android phone when Notification Policy Access is granted.",
    ),
    CapabilityMetadata(
        name="snow_cross_network_execute",
        category=ToolCategory.CROSS_DEVICE,
        tier=ToolCategory.CROSS_DEVICE.value,
        read_only_hint=False,
        destructive_hint=True,
        requires_approval=True,
        os_classification="cross_platform",
        description="Execute an authorized capability on an explicit federated peer device within active 5-tier grant boundaries.",
    ),
]

for _meta in _INITIAL_CAPABILITIES:
    register_capability(_meta)


class _ToolRegistryDict(dict):
    """Dynamic dict proxy maintaining backward compatibility with TOOL_REGISTRY."""

    def __getitem__(self, key: str) -> ToolCategory:
        meta = get_capability_metadata(key)
        if meta:
            return meta.category
        raise KeyError(key)

    def get(self, key: str, default: Any = None) -> Any:
        meta = get_capability_metadata(key)
        if meta:
            return meta.category
        return default

    def __contains__(self, key: object) -> bool:
        if isinstance(key, str):
            return get_capability_metadata(key) is not None
        return False

    def __len__(self) -> int:
        return len(_CAPABILITY_REGISTRY)

    def keys(self):
        return _CAPABILITY_REGISTRY.keys()

    def values(self):
        return [m.category for m in _CAPABILITY_REGISTRY.values()]

    def items(self):
        return [(m.name, m.category) for m in _CAPABILITY_REGISTRY.values()]


# Backward-compatible TOOL_REGISTRY proxy
TOOL_REGISTRY: dict[str, ToolCategory] = _ToolRegistryDict()
CAPABILITY_REGISTRY: dict[str, CapabilityMetadata] = _CAPABILITY_REGISTRY


def get_tool_category(tool_name: str) -> Optional[ToolCategory]:
    """Retrieve the execution category for a given MCP tool name."""
    meta = get_capability_metadata(tool_name)
    return meta.category if meta else None


def is_local_windows_tool(tool_name: str) -> bool:
    """Return True if the tool executes as a local Windows capability."""
    return get_tool_category(tool_name) == ToolCategory.LOCAL_WINDOWS


def is_cross_device_tool(tool_name: str) -> bool:
    """Return True if the tool requires Core IPC or cross-device coordination."""
    return get_tool_category(tool_name) == ToolCategory.CROSS_DEVICE
