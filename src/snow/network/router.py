"""Layer 3 SessionRouter for SNOW V2.

Coordinates NodeRegistry, SnowWebSocketServer, SnowPeerClient, and SnowDiscoveryService
to establish on-demand transport sessions and route capability requests across heterogeneous peers.

Routing Tiers:
- Step 1: Pre-flight target and capability resolution (immediate failure on invalid target/capability).
- Tier 1: Active session routing (inbound WSS or outbound SnowPeerClient).
- Tier 2: Outbound direct connection (for PERSISTENT_DAEMON peers with known LAN/cached endpoint).
- Tier 3: Android active-session peer recovery (targeted wake burst + broadcast, awaiting inbound WSS).
- Tier 4: Structured failure (DEVICE_UNREACHABLE with full diagnostic payload).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from snow.capabilities.engine import CapabilityEngine, ExecutionContext, ExecutionPrincipal
from snow.network.discovery import SnowDiscoveryService
from snow.network.node import (
    DeviceNode,
    ReachabilityProfile,
    ReachabilityState,
)
from snow.network.peer_client import PeerConnectionResult, SnowPeerClient
from snow.network.registry import NodeRegistry
from snow.network.ws_server import ACTION_TO_CAPABILITY, SnowWebSocketServer
from snow.protocol.models import MessageType, SnowMessage
from snow.security.db import DatabaseManager
from snow.network.transport import (
    DEFAULT_PROBE_COOLDOWN_SEC,
    DEFAULT_PROBE_TIMEOUT_SEC,
    DEFAULT_ROUTE_VERIFICATION_TTL_SEC,
    MANUAL_SINGLE_TRANSPORT_MODES,
    RouteCandidate,
    RouteStatus,
    TRANSPORT_PRIORITY_ORDER,
    TransportType,
    VALID_TRANSPORT_MODES,
    classify_transfer_socket_route,
    is_hotspot_host_or_hint,
    is_loopback_host,
    normalize_transport_mode,
    normalize_transport_type,
    sanitize_transport_error,
    transport_badge_for,
    transport_priority_for,
)

logger = logging.getLogger(__name__)

# Complete mapping from capability actions to required capability identifiers for pre-flight resolution
ROUTER_ACTION_TO_CAPABILITY: dict[str, str] = {
    **ACTION_TO_CAPABILITY,
    "windows_terminal": "desktop.exec",
    "windows_terminal_exec": "desktop.exec",
    "desktop_exec": "desktop.exec",
    "desktop_status": "desktop.status",
    "desktop_battery": "desktop.battery",
    "desktop_clipboard_get": "desktop.clipboard.read",
    "desktop_clipboard_set": "desktop.clipboard.write",
    "desktop_clipboard_sync_toggle": "desktop.clipboard.read",
    "desktop_file_list": "desktop.file.list",
    "windows_clipboard_get": "desktop.clipboard.read",
    "windows_clipboard_set": "desktop.clipboard.write",
    "windows_file_list": "desktop.file.list",
    "windows_system_info": "desktop.status",
    "windows_battery": "desktop.battery",
    "desktop.system.info": "desktop.status",
    "desktop.file.list": "desktop.file.list",
    "desktop.file.read": "desktop.file.list",
    "android.status": "android.telemetry.get",
    "desktop_file_stage_download": "desktop.file.transfer",
    "desktop_app_launch": "desktop.apps.launch",
    "mesh_list_peers": "mesh.list_peers",
    "peer_relay_request": "mesh.peer_relay",
    "android_battery": "android.telemetry.get",
    "snow_android_battery": "android.telemetry.get",
    "android_battery_status": "android.telemetry.get",
    "snow_android_battery_status": "android.telemetry.get",
    "android_clipboard_get": "android.clipboard.get",
    "android_clipboard_set": "android.clipboard.set",
    "android_clipboard_push": "android.clipboard.set",
    "snow_android_clipboard_push": "android.clipboard.set",
    "android_notification": "android.notification.post",
    "android_sms_send": "android.telephony.sms",
    "android_torch": "android.hardware.flashlight",
    "android_device_info": "android.telemetry.get",
    "file_send_request": "android.files.transfer",
    "file_receive_request": "android.files.transfer",
    "clipboard_pull": "android.clipboard.get",
    "clipboard_push": "android.clipboard.set",
    "battery_status": "android.telemetry.get",
    "ring_phone": "android.ringer.ring",
    "list_apps": "android.apps.list",
    "launch_app": "android.apps.launch",
    "send_message": "android.messaging.send_intent",
    "file_list": "android.files.transfer",
    "notifications_list": "android.notifications.list",
    "android_notifications_list": "android.notifications.list",
    "snow_android_notifications_list": "android.notifications.list",
    "notification_dismiss": "android.notifications.dismiss",
    "android_notification_dismiss": "android.notifications.dismiss",
    "snow_android_notification_dismiss": "android.notifications.dismiss",
    "notification_reply": "android.notifications.reply",
    "android_notification_reply": "android.notifications.reply",
    "snow_android_notification_reply": "android.notifications.reply",
    "media_control": "android.media.control",
    "desktop_media_control": "desktop.media.control",
    "windows_media_control": "desktop.media.control",
    "windows_screenshot": "desktop.media.capture",
    "snow_windows_screenshot": "desktop.media.capture",
    "desktop_screenshot": "desktop.media.capture",
    "share_link": "android.link.share",
    "android_share_link": "android.link.share",
    "snow_android_share_link": "android.link.share",
    "android_screenshot": "android.screen.capture",
    "snow_android_screenshot": "android.screen.capture",
    "screen_capture": "android.screen.capture",
    "screen_stream_start": "android.screen.stream",
    "screen_stream_stop": "android.screen.stream",
    "android_screen_stream_stop": "android.screen.stream",
    "android_camera_capture": "android.camera.capture",
    "snow_android_camera_capture": "android.camera.capture",
    "camera_capture": "android.camera.capture",
    "clipboard_buffer_list": "desktop.clipboard.read",
    "clipboard_buffer_add": "desktop.clipboard.write",
    "clipboard_buffer_apply": "desktop.clipboard.write",
    "whatsapp_send": "android.messaging.whatsapp",
    "android_whatsapp_send": "android.messaging.whatsapp",
    "snow_android_whatsapp_send": "android.messaging.whatsapp",
    "dnd_toggle": "android.system.dnd",
    "android_dnd_toggle": "android.system.dnd",
    "snow_android_dnd_toggle": "android.system.dnd",
    "windows_hotkey": "desktop.input.hotkey",
    "snow_windows_hotkey": "desktop.input.hotkey",
    "windows_brightness_set": "desktop.display.brightness",
    "snow_windows_brightness_set": "desktop.display.brightness",
    "cross_network_execute": "network.federation.execute",
    "snow_cross_network_execute": "network.federation.execute",
}

# Mapping from high-level unified actions to physical peer wire actions
ACTION_TO_WIRE_ACTION: dict[str, str] = {
    "clipboard_buffer_list": "clipboard_buffer_list",
    "clipboard_buffer_get": "clipboard_buffer_get",
    "clipboard_buffer_add": "clipboard_buffer_add",
    "clipboard_buffer_apply": "clipboard_buffer_apply",
    "screen_stream_stop": "screen_stream_stop",
    "android_screen_stream_stop": "screen_stream_stop",
    "snow_android_battery": "battery_status",
    "android_battery_status": "battery_status",
    "snow_android_battery_status": "battery_status",
    "android_ring": "ring_phone",
    "snow_android_ring": "ring_phone",
    "android_list_apps": "list_apps",
    "snow_android_list_apps": "list_apps",
    "android_launch_app": "launch_app",
    "snow_android_launch_app": "launch_app",
    "android_send_message": "send_message",
    "snow_android_send_message": "send_message",
    "android_whatsapp_send": "whatsapp_send",
    "snow_android_whatsapp_send": "whatsapp_send",
    "whatsapp_send": "whatsapp_send",
    "android_dnd_toggle": "android_dnd_toggle",
    "snow_android_dnd_toggle": "android_dnd_toggle",
    "dnd_toggle": "android_dnd_toggle",
    "android_clipboard_push": "clipboard_push",
    "snow_android_clipboard_push": "clipboard_push",
    "android_clipboard_pull": "clipboard_pull",
    "snow_android_clipboard_pull": "clipboard_pull",
    "android_notifications_list": "notifications_list",
    "snow_android_notifications_list": "notifications_list",
    "android_notification_dismiss": "notification_dismiss",
    "snow_android_notification_dismiss": "notification_dismiss",
    "android_notification_reply": "notification_reply",
    "snow_android_notification_reply": "notification_reply",
    "android_file_list": "file_list",
    "snow_android_file_list": "file_list",
    "android_file_receive": "file_receive_request",
    "snow_android_file_receive": "file_receive_request",
    "windows_screenshot": "windows_screenshot",
    "snow_windows_screenshot": "windows_screenshot",
    "desktop_screenshot": "windows_screenshot",
    "desktop_media_control": "media_control",
    "windows_media_control": "media_control",
    "media_control": "media_control",
}

# Alias for backward-compatible routing lookups
ACTION_ROUTING = ROUTER_ACTION_TO_CAPABILITY

# Canonical 5-tier cross-network permission presets (V5.2 Stage 6B WS4)
PERMISSION_PROFILE_ORDER: tuple[str, ...] = (
    "full_control",
    "files_and_clipboard",
    "files_only",
    "clipboard_only",
    "not_allowed",
)
VALID_PERMISSION_PROFILES: frozenset[str] = frozenset(PERMISSION_PROFILE_ORDER)

PERMISSION_PROFILES: dict[str, dict[str, Any]] = {
    "full_control": {
        "name": "Full Control",
        "description": "Full access to all permitted capabilities.",
        "allowed_categories": {"telemetry", "clipboard", "files", "apps", "execution", "media", "screen", "system", "cross_network"},
    },
    "files_and_clipboard": {
        "name": "Files & Clipboard",
        "description": "Access to file transfers, clipboard sync, and device telemetry. Execution, apps, screen and camera are blocked.",
        "allowed_categories": {"telemetry", "clipboard", "files"},
    },
    "files_only": {
        "name": "Files Only",
        "description": "Access restricted strictly to file operations and basic telemetry.",
        "allowed_categories": {"telemetry", "files"},
    },
    "clipboard_only": {
        "name": "Clipboard Only",
        "description": "Access restricted strictly to clipboard synchronization and telemetry.",
        "allowed_categories": {"telemetry", "clipboard"},
    },
    "not_allowed": {
        "name": "Not Allowed",
        "description": "All remote and AI capabilities are blocked for this peer.",
        "allowed_categories": set(),
    },
}

CAPABILITY_CATEGORY_MAP: dict[str, str] = {
    # Telemetry
    "desktop_status": "telemetry",
    "desktop.status": "telemetry",
    "desktop.system.info": "telemetry",
    "windows_system_info": "telemetry",
    "desktop_battery": "telemetry",
    "desktop.battery": "telemetry",
    "windows_battery": "telemetry",
    "android_battery": "telemetry",
    "snow_android_battery": "telemetry",
    "android_battery_status": "telemetry",
    "snow_android_battery_status": "telemetry",
    "battery_status": "telemetry",
    "ring_phone": "telemetry",
    "android_ring": "telemetry",
    "snow_android_ring": "telemetry",
    "mesh_list_peers": "telemetry",
    "android.telemetry.get": "telemetry",
    "android.status": "telemetry",
    "android.ringer.ring": "telemetry",
    # Clipboard
    "desktop_clipboard_get": "clipboard",
    "desktop_clipboard_set": "clipboard",
    "windows_clipboard_get": "clipboard",
    "windows_clipboard_set": "clipboard",
    "desktop.clipboard.read": "clipboard",
    "desktop.clipboard.write": "clipboard",
    "android_clipboard_get": "clipboard",
    "android_clipboard_set": "clipboard",
    "android_clipboard_push": "clipboard",
    "snow_android_clipboard_push": "clipboard",
    "android_clipboard_pull": "clipboard",
    "snow_android_clipboard_pull": "clipboard",
    "clipboard_pull": "clipboard",
    "clipboard_push": "clipboard",
    "android.clipboard.get": "clipboard",
    "android.clipboard.set": "clipboard",
    "clipboard_buffer_list": "clipboard",
    "clipboard_buffer_get": "clipboard",
    "clipboard_buffer_add": "clipboard",
    "clipboard_buffer_apply": "clipboard",
    "clipboard_ack": "clipboard",
    "clipboard_history_sync": "clipboard",
    # Files
    "desktop_file_list": "files",
    "windows_file_list": "files",
    "windows_file_search": "files",
    "desktop_file_search": "files",
    "desktop_file_stage_download": "files",
    "desktop.file.list": "files",
    "desktop.file.read": "files",
    "desktop.file.write": "files",
    "desktop.file.search": "files",
    "desktop.file.transfer": "files",
    "android_file_list": "files",
    "snow_android_file_list": "files",
    "android_file_receive": "files",
    "snow_android_file_receive": "files",
    "file_list": "files",
    "file_send_request": "files",
    "file_receive_request": "files",
    "android.files.transfer": "files",
    # Apps
    "desktop_app_launch": "apps",
    "desktop.apps.launch": "apps",
    "android_list_apps": "apps",
    "snow_android_list_apps": "apps",
    "list_apps": "apps",
    "android.apps.list": "apps",
    "android_launch_app": "apps",
    "snow_android_launch_app": "apps",
    "launch_app": "apps",
    "android.apps.launch": "apps",
    "share_link": "apps",
    "android_share_link": "apps",
    "snow_android_share_link": "apps",
    "android.link.share": "apps",
    # Execution
    "desktop_exec": "execution",
    "desktop.exec": "execution",
    "windows_terminal": "execution",
    "windows_terminal_exec": "execution",
    # Media
    "media_control": "media",
    "desktop_media_control": "media",
    "windows_media_control": "media",
    "desktop.media.control": "media",
    "android.media.control": "media",
    "windows_screenshot": "media",
    "snow_windows_screenshot": "media",
    "desktop_screenshot": "media",
    "desktop.media.capture": "media",
    "android_screenshot": "media",
    "snow_android_screenshot": "media",
    "screen_capture": "media",
    "android.screen.capture": "media",
    "screen_stream_start": "screen",
    "screen_stream_stop": "screen",
    "android_screen_stream_stop": "screen",
    "screen_stream_status": "screen",
    "screen_stream_subscribe": "screen",
    "screen_stream_unsubscribe": "screen",
    "screen_stream_senders": "screen",
    "windows_screen_share": "screen",
    "android_screen_share": "screen",
    "screen_share": "screen",
    "android.screen.stream": "screen",
    "android.media.projection": "screen",
    "android_camera_capture": "media",
    "snow_android_camera_capture": "media",
    "camera_capture": "media",
    "android.camera.capture": "media",
    # System
    "android_notification": "system",
    "android.notification.post": "system",
    "android.notifications.push": "system",
    "android_notifications_list": "system",
    "snow_android_notifications_list": "system",
    "notifications_list": "system",
    "android.notifications.list": "system",
    "android_notification_dismiss": "system",
    "snow_android_notification_dismiss": "system",
    "notification_dismiss": "system",
    "android.notifications.dismiss": "system",
    "android_notification_reply": "system",
    "snow_android_notification_reply": "system",
    "notification_reply": "system",
    "android.notifications.reply": "system",
    "android_sms_send": "system",
    "android.telephony.sms": "system",
    "send_message": "system",
    "android_send_message": "system",
    "snow_android_send_message": "system",
    "android.messaging.send_intent": "system",
    "whatsapp_send": "system",
    "android_whatsapp_send": "system",
    "snow_android_whatsapp_send": "system",
    "android.messaging.whatsapp": "system",
    "android_dnd_toggle": "system",
    "snow_android_dnd_toggle": "system",
    "dnd_toggle": "system",
    "android.system.dnd": "system",
    "windows_hotkey": "execution",
    "snow_windows_hotkey": "execution",
    "desktop.input.hotkey": "execution",
    "windows_brightness_set": "system",
    "snow_windows_brightness_set": "system",
    "desktop.display.brightness": "system",
    "windows_notify": "system",
    "snow_windows_notify": "system",
    "windows_lock_screen": "execution",
    "snow_windows_lock_screen": "execution",
    "windows_active_window": "telemetry",
    "snow_windows_active_window": "telemetry",
    "windows_list_windows": "telemetry",
    "snow_windows_list_windows": "telemetry",
    "windows_focus_window": "apps",
    "snow_windows_focus_window": "apps",
    "web_open": "apps",
    "snow_web_open": "apps",
    "youtube_play": "media",
    "snow_youtube_play": "media",
    "system_volume_set": "media",
    "snow_system_volume_set": "media",
    "cross_network_execute": "cross_network",
    "snow_cross_network_execute": "cross_network",
    "network.federation.execute": "cross_network",
}


def normalize_permission_tier(profile: Optional[str]) -> Optional[str]:
    """Normalize a permission tier string or return None if unknown/invalid (fail-closed)."""
    if not isinstance(profile, str):
        return None
    clean = profile.strip().lower()
    if clean in VALID_PERMISSION_PROFILES:
        return clean
    return None


def intersect_tier_categories(tier_a: Optional[str], tier_b: Optional[str]) -> set[str]:
    """Compute effective allowed capability categories from device tier ∩ grant tier.

    Unknown or missing tiers fail closed (empty set).
    """
    norm_a = normalize_permission_tier(tier_a)
    norm_b = normalize_permission_tier(tier_b)
    if norm_a is None or norm_b is None:
        return set()
    return set(PERMISSION_PROFILES[norm_a]["allowed_categories"]) & set(
        PERMISSION_PROFILES[norm_b]["allowed_categories"]
    )


def is_action_allowed_by_profile(profile: Optional[str], action: str) -> bool:
    """Determine whether an action is permitted under the given permission profile.

    Fails closed on unknown/empty tiers or 'not_allowed'.
    """
    clean_prof = normalize_permission_tier(profile)
    if clean_prof is None:
        return False
    allowed_cats = PERMISSION_PROFILES[clean_prof]["allowed_categories"]
    if not allowed_cats:
        return False
    cat = CAPABILITY_CATEGORY_MAP.get(action, "system")
    return cat in allowed_cats


def is_action_allowed_by_tier_intersection(
    tier_a: Optional[str], tier_b: Optional[str], action: str
) -> bool:
    """Evaluate action allowance under the intersection of two 5-tier profiles."""
    allowed_cats = intersect_tier_categories(tier_a, tier_b)
    if not allowed_cats:
        return False
    cat = CAPABILITY_CATEGORY_MAP.get(action, "system")
    return cat in allowed_cats


def classify_transport_badge(
    transport: Optional[str] = None,
    host: Optional[str] = None,
    connection_mode: Optional[str] = None,
    interface_name: Optional[str] = None,
    is_hotspot: bool = False,
) -> str:
    """Return the unified Web/Android transport badge label."""
    ttype = normalize_transport_type(
        transport=transport,
        host=host,
        connection_mode=connection_mode,
        interface_name=interface_name,
        is_hotspot=is_hotspot,
    )
    return transport_badge_for(ttype)


def classify_route_priority(
    transport: Optional[str] = None,
    host: Optional[str] = None,
    connection_mode: Optional[str] = None,
    interface_name: Optional[str] = None,
    is_hotspot: bool = False,
) -> int:
    """Return canonical route priority: 0=USB, 1=Hotspot, 2=Wi-Fi LAN, 3=Remote Relay."""
    ttype = normalize_transport_type(
        transport=transport,
        host=host,
        connection_mode=connection_mode,
        interface_name=interface_name,
        is_hotspot=is_hotspot,
    )
    return transport_priority_for(ttype)


def evaluate_preferred_route(
    candidates: list[dict[str, Any]],
    connection_mode: str = "auto",
) -> Optional[dict[str, Any]]:
    """Select the highest-priority verified/active route honoring zero-data priority and mode policy.

    Priority order: 0=USB, 1=Hotspot, 2=Wi-Fi LAN, 3=Remote Relay.
    Never promotes unverified routes (cand.get('verified') is False).
    """
    mode = normalize_transport_mode(connection_mode) or "auto"
    eligible: list[tuple[int, dict[str, Any]]] = []
    for cand in candidates:
        if not cand or cand.get("active") is False or cand.get("verified") is False:
            continue
        prio = classify_route_priority(
            transport=cand.get("transport"),
            host=cand.get("host"),
            connection_mode=cand.get("connection_mode"),
            interface_name=cand.get("interface_name"),
            is_hotspot=bool(cand.get("is_hotspot", False)),
        )
        if mode == "local_only" and prio == 3:
            continue
        if mode in ("remote_only", "remote_relay") and prio != 3:
            continue
        if mode == "usb" and prio != 0:
            continue
        if mode == "hotspot" and prio != 1:
            continue
        if mode == "wifi_lan" and prio != 2:
            continue
        enriched = dict(cand)
        enriched["priority"] = prio
        enriched["transport_badge"] = classify_transport_badge(
            transport=cand.get("transport"),
            host=cand.get("host"),
            connection_mode="remote_only" if mode in ("remote_only", "remote_relay") else cand.get("connection_mode"),
            interface_name=cand.get("interface_name"),
            is_hotspot=bool(cand.get("is_hotspot", False)),
        )
        eligible.append((prio, enriched))
    if not eligible:
        return None
    eligible.sort(key=lambda item: item[0])
    return eligible[0][1]


class SessionRouter:
    """Layer 3 unified cross-device routing and session lifecycle coordinator."""

    def __init__(
        self,
        node_registry: NodeRegistry,
        ws_server: Optional[SnowWebSocketServer] = None,
        discovery_service: Optional[SnowDiscoveryService] = None,
        capability_engine: Optional[CapabilityEngine] = None,
        db_manager: Optional[DatabaseManager] = None,
        direct_dial_timeout: float = 2.5,
        wake_grace_period: float = 6.0,
        relay_client: Optional[Any] = None,
        relay_enabled: bool = False,
        usb_status_provider: Optional[Any] = None,
    ) -> None:
        self.node_registry = node_registry
        self.ws_server = ws_server
        self.discovery_service = discovery_service
        self.capability_engine = capability_engine
        self.db_manager = db_manager or (node_registry.db_manager if node_registry else DatabaseManager())
        self.direct_dial_timeout = direct_dial_timeout
        self.wake_grace_period = wake_grace_period
        self.relay_client = relay_client
        self.relay_enabled = relay_enabled
        self.usb_status_provider = usb_status_provider

        # Active outbound peer client sessions: device_id -> SnowPeerClient
        self._outbound_clients: dict[str, SnowPeerClient] = {}
        # Tracks which TransportType an active outbound client belongs to
        self._outbound_transports: dict[str, TransportType] = {}
        # Outbound peer tokens for direct dials: device_id -> token
        self._peer_tokens: dict[str, str] = {}
        # Bounded transfer idempotency cache across route failover switches: (device_id, transfer_id) -> result
        self._completed_transfer_routes: dict[tuple[str, str], dict[str, Any]] = {}
        # Active multi-GB transfer sticky route pins: transfer_id -> dict metadata
        self._pinned_transfer_routes: dict[str, dict[str, Any]] = {}
        # Track verified local route promotions: device_id -> diagnostics dict
        self._route_promotion_status: dict[str, dict[str, Any]] = {}
        # Per-device candidate & verified transport state
        self._route_candidates: dict[str, dict[TransportType, RouteCandidate]] = {}
        self._active_route_type: dict[str, TransportType] = {}
        self._route_generation: dict[str, int] = {}
        self._switching_devices: set[str] = set()
        self._last_switch_reason: dict[str, str] = {}
        self._device_locks: dict[str, asyncio.Lock] = {}
        self._probe_semaphore = asyncio.Semaphore(4)
        self._retire_tasks: set[asyncio.Task[Any]] = set()
        self._lock = asyncio.Lock()

    @staticmethod
    def _is_loopback_host(host: Optional[str]) -> bool:
        return is_loopback_host(host)

    def _get_device_lock(self, device_id: str) -> asyncio.Lock:
        lock = self._device_locks.get(device_id)
        if lock is None:
            lock = asyncio.Lock()
            self._device_locks[device_id] = lock
        return lock

    async def _retire_client_safely(self, client: Optional[SnowPeerClient], drain_grace: float = 1.5) -> None:
        """Close an old peer client without aborting in-flight requests where possible."""
        if client is None:
            return
        pending = getattr(client, "_pending_requests", None)
        if not pending:
            try:
                await client.close()
            except Exception:
                pass
            return

        async def _drain_and_close() -> None:
            deadline = time.monotonic() + max(0.1, drain_grace)
            try:
                while getattr(client, "_pending_requests", None) and time.monotonic() < deadline:
                    await asyncio.sleep(0.05)
            except Exception:
                pass
            try:
                await client.close()
            except Exception:
                pass

        task = asyncio.create_task(_drain_and_close())
        self._retire_tasks.add(task)
        task.add_done_callback(lambda t: self._retire_tasks.discard(t))

    def _with_transport_badge(
        self,
        res: dict[str, Any],
        transport: Optional[str] = None,
        host: Optional[str] = None,
        connection_mode: Optional[str] = None,
    ) -> dict[str, Any]:
        enriched = dict(res)
        eff_transport = transport or enriched.get("transport")
        eff_host = host or enriched.get("last_known_endpoint")
        if not enriched.get("transport_badge"):
            enriched["transport_badge"] = classify_transport_badge(
                transport=eff_transport,
                host=eff_host,
                connection_mode=connection_mode,
            )
        return enriched

    def _resolve_effective_profile(self, device_id: str, node: DeviceNode) -> str:
        """Resolve latest device permission profile, prioritizing DB over stale cache."""
        raw_profile = getattr(node, "permission_profile", None)
        if self.db_manager is not None and hasattr(self.db_manager, "get_setting"):
            try:
                saved = self.db_manager.get_setting(f"device_profile:{device_id}")
                if isinstance(saved, str):
                    raw_profile = saved
            except Exception:
                pass
        if raw_profile is None:
            return "full_control"
        clean = normalize_permission_tier(str(raw_profile))
        return clean if clean is not None else "invalid"

    def _resolve_effective_transport_mode(
        self,
        device_id: str,
        paired_rec: Optional[Any] = None,
    ) -> str:
        """Resolve effective transport mode, honoring M4.3 manual single-route overrides safely."""
        if paired_rec is None and self.db_manager is not None and hasattr(self.db_manager, "get_paired_device"):
            try:
                paired_rec = self.db_manager.get_paired_device(device_id)
            except Exception:
                paired_rec = None
        if self.db_manager is not None and hasattr(self.db_manager, "get_setting"):
            try:
                override = self.db_manager.get_setting(f"device_transport_override:{device_id}")
                norm_override = normalize_transport_mode(override) if override else None
                if norm_override and norm_override in MANUAL_SINGLE_TRANSPORT_MODES:
                    return norm_override
            except Exception:
                pass
        raw_conn = getattr(paired_rec, "connection_mode", "auto") if paired_rec else "auto"
        return normalize_transport_mode(raw_conn) or "auto"

    def _ensure_candidate_map(self, device_id: str) -> dict[TransportType, RouteCandidate]:
        cmap = self._route_candidates.get(device_id)
        if cmap is None:
            cmap = {
                tt: RouteCandidate(
                    device_id=device_id,
                    transport=tt,
                    state=RouteStatus.UNAVAILABLE,
                    verified=False,
                    suitable_for_transfer=(tt != TransportType.REMOTE_RELAY),
                )
                for tt in TRANSPORT_PRIORITY_ORDER
            }
            self._route_candidates[device_id] = cmap
        return cmap

    def register_discovered_route(
        self,
        device_id: str,
        *,
        transport: Optional[str] = None,
        host: str = "",
        port: int = 8765,
        transfer_port: int = 8766,
        interface_name: Optional[str] = None,
        is_hotspot: bool = False,
        direction: str = "discovered",
    ) -> RouteCandidate:
        """Record a discovered/unverified candidate route (never marks verified or active alone)."""
        clean_id = (device_id or "").strip()
        cmap = self._ensure_candidate_map(clean_id)
        ttype = normalize_transport_type(
            transport=transport,
            host=host,
            interface_name=interface_name,
            is_hotspot=is_hotspot,
        )
        existing = cmap[ttype]
        now = time.monotonic()
        if not existing.is_usable(now):
            existing.state = RouteStatus.DISCOVERED
            existing.verified = False
        existing.host = (host or "").strip() or existing.host
        existing.port = int(port or existing.port or 8765)
        existing.transfer_port = int(transfer_port or existing.transfer_port or 8766)
        existing.interface_name = interface_name or existing.interface_name
        existing.is_hotspot = bool(is_hotspot or ttype == TransportType.HOTSPOT)
        existing.direction = direction
        return existing

    def mark_route_verified(
        self,
        device_id: str,
        transport: TransportType | str,
        *,
        host: str = "",
        port: int = 8765,
        transfer_port: int = 8766,
        is_active: bool = False,
        direction: str = "outbound",
        ttl_sec: float = DEFAULT_ROUTE_VERIFICATION_TTL_SEC,
        interface_name: Optional[str] = None,
        is_hotspot: bool = False,
    ) -> RouteCandidate:
        """Mark a route verified after mutual auth/readiness confirmation, or promote to ACTIVE."""
        clean_id = (device_id or "").strip()
        cmap = self._ensure_candidate_map(clean_id)
        ttype = transport if isinstance(transport, TransportType) else normalize_transport_type(
            transport=str(transport),
            host=host,
            interface_name=interface_name,
            is_hotspot=is_hotspot,
        )
        now = time.monotonic()
        gen = self._route_generation.get(clean_id, 0)
        if is_active:
            for other_tt, other_cand in cmap.items():
                if other_tt != ttype and other_cand.state == RouteStatus.ACTIVE:
                    other_cand.state = (
                        RouteStatus.VERIFIED_AVAILABLE if other_cand.is_usable(now) else RouteStatus.CANDIDATE
                    )
            self._active_route_type[clean_id] = ttype
            self._route_generation[clean_id] = gen + 1

        cand = cmap[ttype]
        cand.host = (host or "").strip() or cand.host
        cand.port = int(port or cand.port or 8765)
        cand.transfer_port = int(transfer_port or cand.transfer_port or 8766)
        cand.interface_name = interface_name or cand.interface_name
        cand.is_hotspot = bool(is_hotspot or ttype == TransportType.HOTSPOT)
        cand.verified = True
        cand.verified_at = now
        cand.last_checked_at = now
        cand.expires_at = now + max(1.0, ttl_sec)
        cand.cooldown_until = 0.0
        cand.last_failure_reason = None
        cand.direction = direction
        cand.generation = self._route_generation.get(clean_id, gen)
        cand.state = RouteStatus.ACTIVE if is_active else RouteStatus.VERIFIED_AVAILABLE
        return cand

    def mark_route_unavailable(
        self,
        device_id: str,
        transport: TransportType | str,
        reason: str = "Route unavailable.",
        cooldown_sec: float = DEFAULT_PROBE_COOLDOWN_SEC,
    ) -> RouteCandidate:
        """Demote a transport candidate to UNAVAILABLE with cooldown and sanitized diagnostics."""
        clean_id = (device_id or "").strip()
        cmap = self._ensure_candidate_map(clean_id)
        ttype = transport if isinstance(transport, TransportType) else normalize_transport_type(transport=str(transport))
        now = time.monotonic()
        cand = cmap[ttype]
        cand.verified = False
        cand.expires_at = 0.0
        cand.last_checked_at = now
        cand.cooldown_until = now + max(0.0, cooldown_sec)
        cand.last_failure_reason = sanitize_transport_error(reason)
        cand.state = RouteStatus.UNAVAILABLE
        if self._active_route_type.get(clean_id) == ttype:
            self._active_route_type.pop(clean_id, None)
        return cand

    def refresh_transport_candidates(self, device_id: str) -> dict[TransportType, RouteCandidate]:
        """Synchronize candidate table with live sessions, outbound clients, discovery, and relay."""
        clean_id = (device_id or "").strip()
        cmap = self._ensure_candidate_map(clean_id)
        node = self.node_registry.get_node(clean_id) if hasattr(self.node_registry, "get_node") else None

        # Active inbound WSS session
        if self.ws_server is not None:
            sess = self.ws_server.session_manager.get_session_by_device(clean_id)
            if sess and sess.connection_id:
                conn = self.ws_server.connection_manager.get(sess.connection_id)
                if conn and conn.is_active:
                    sess_host = (getattr(node, "host", None) or getattr(conn, "remote_ip", None) or "").strip()
                    sess_tr = (getattr(node, "transport", None) or "").strip()
                    ttype = normalize_transport_type(transport=sess_tr, host=sess_host)
                    self.mark_route_verified(
                        clean_id,
                        ttype,
                        host=sess_host,
                        port=int(getattr(node, "wss_port", 8765) or 8765),
                        is_active=(self._active_route_type.get(clean_id) in (None, ttype)),
                        direction="inbound",
                    )

        # Active outbound SnowPeerClient
        out_client = self._outbound_clients.get(clean_id)
        if out_client is not None and getattr(out_client, "is_connected", False):
            out_host = (getattr(out_client, "host", None) or getattr(node, "host", None) or "").strip()
            out_tr = self._outbound_transports.get(clean_id) or normalize_transport_type(host=out_host)
            self.mark_route_verified(
                clean_id,
                out_tr,
                host=out_host,
                port=int(getattr(out_client, "port", 8765) or 8765),
                is_active=(self._active_route_type.get(clean_id) in (None, out_tr)),
                direction="outbound",
            )

        # Discovery LAN / Hotspot candidate
        if self.discovery_service is not None and hasattr(self.discovery_service, "get_discovered_peer"):
            try:
                disc = self.discovery_service.get_discovered_peer(clean_id)
                disc_ip = (getattr(disc, "ip_address", None) or "").strip() if disc else ""
                if disc_ip:
                    disc_tt = normalize_transport_type(
                        transport=getattr(disc, "transport", None),
                        host=disc_ip,
                        interface_name=getattr(disc, "interface_name", None),
                        is_hotspot=bool(getattr(disc, "is_hotspot", False)),
                    )
                    self.register_discovered_route(
                        clean_id,
                        transport=disc_tt.value,
                        host=disc_ip,
                        port=int(getattr(disc, "port", 8765) or 8765),
                        transfer_port=int(getattr(disc, "transfer_port", 8766) or 8766),
                        interface_name=getattr(disc, "interface_name", None),
                        is_hotspot=(disc_tt == TransportType.HOTSPOT),
                        direction="discovered",
                    )
            except Exception:
                pass

        # Cached local endpoint fallback candidate
        if node is not None and getattr(node, "host", None):
            nhost = str(node.host).strip()
            ntt = normalize_transport_type(transport=getattr(node, "transport", None), host=nhost)
            if ntt != TransportType.REMOTE_RELAY and cmap[ntt].state == RouteStatus.UNAVAILABLE and not cmap[ntt].host:
                self.register_discovered_route(
                    clean_id,
                    transport=ntt.value,
                    host=nhost,
                    port=int(getattr(node, "wss_port", 8765) or 8765),
                    direction="cached",
                )

        # USB ADB candidate when USB reverse/forward mapping is confirmed active
        if self.usb_status_provider is not None:
            try:
                usb_info = self.usb_status_provider(clean_id)
                if isinstance(usb_info, dict) and usb_info.get("usb_ready"):
                    self.register_discovered_route(
                        clean_id,
                        transport=TransportType.USB.value,
                        host="127.0.0.1",
                        port=int(usb_info.get("port", 8765) or 8765),
                        transfer_port=int(usb_info.get("transfer_port", 8766) or 8766),
                        direction="usb",
                    )
            except Exception:
                pass

        # Remote Relay readiness
        relay_ok = bool(self.relay_enabled and self.relay_client and getattr(self.relay_client, "_is_connected", False))
        if relay_ok:
            if not cmap[TransportType.REMOTE_RELAY].is_usable():
                self.mark_route_verified(
                    clean_id,
                    TransportType.REMOTE_RELAY,
                    host="relay",
                    port=443,
                    is_active=False,
                    direction="relay",
                )
        elif cmap[TransportType.REMOTE_RELAY].verified:
            self.mark_route_unavailable(clean_id, TransportType.REMOTE_RELAY, "Relay tunnel disconnected.", cooldown_sec=2.0)

        return cmap

    async def probe_candidate_route(
        self,
        device_id: str,
        transport: TransportType | str,
        *,
        host: Optional[str] = None,
        port: int = 8765,
        expected_fingerprint: Optional[str] = None,
        timeout: Optional[float] = None,
        verify_ping: bool = True,
        force: bool = False,
    ) -> tuple[bool, RouteCandidate, Optional[SnowPeerClient]]:
        """Actively verify a transport candidate using TLS pinning, peer auth, and ping readiness."""
        clean_id = (device_id or "").strip()
        ttype = transport if isinstance(transport, TransportType) else normalize_transport_type(transport=str(transport), host=host)
        cmap = self.refresh_transport_candidates(clean_id)
        cand = cmap[ttype]
        now = time.monotonic()

        if not force and cand.cooldown_until > now and not cand.is_usable(now):
            return False, cand, None

        if ttype == TransportType.REMOTE_RELAY:
            relay_ok = bool(self.relay_enabled and self.relay_client and getattr(self.relay_client, "_is_connected", False))
            if not relay_ok:
                self.mark_route_unavailable(clean_id, ttype, "Remote relay is not connected.")
                return False, cmap[ttype], None
            verified = self.mark_route_verified(clean_id, ttype, host="relay", port=443, direction="relay")
            return True, verified, None

        probe_host = (host or cand.host or "").strip()
        if ttype == TransportType.USB and not probe_host:
            probe_host = "127.0.0.1"
        probe_port = int(port or cand.port or 8765)
        if not probe_host:
            self.mark_route_unavailable(clean_id, ttype, f"No reachable {ttype.value} host known.")
            return False, cmap[ttype], None

        # Reuse existing verified active session on exact same transport/host
        out_client = self._outbound_clients.get(clean_id)
        if out_client is not None and getattr(out_client, "is_connected", False):
            existing_tt = self._outbound_transports.get(clean_id) or normalize_transport_type(host=getattr(out_client, "host", None))
            if existing_tt == ttype and (getattr(out_client, "host", "") == probe_host or ttype == TransportType.USB):
                verified = self.mark_route_verified(clean_id, ttype, host=probe_host, port=probe_port, direction="outbound")
                return True, verified, out_client

        if self.ws_server is not None:
            sess = self.ws_server.session_manager.get_session_by_device(clean_id)
            if sess and sess.connection_id:
                conn = self.ws_server.connection_manager.get(sess.connection_id)
                node_existing = self.node_registry.get_node(clean_id) if hasattr(self.node_registry, "get_node") else None
                sess_host = (getattr(node_existing, "host", None) or "").strip()
                sess_tt = normalize_transport_type(transport=getattr(node_existing, "transport", None), host=sess_host)
                if conn and conn.is_active and sess_tt == ttype and (not sess_host or sess_host == probe_host or ttype == TransportType.USB):
                    verified = self.mark_route_verified(
                        clean_id,
                        ttype,
                        host=probe_host,
                        port=probe_port,
                        is_active=(self._active_route_type.get(clean_id) == ttype),
                        direction="inbound",
                    )
                    return True, verified, None

        paired_rec = self.db_manager.get_paired_device(clean_id) if self.db_manager else None
        if not paired_rec:
            self.mark_route_unavailable(clean_id, ttype, f"Device '{clean_id}' is not paired.")
            return False, cmap[ttype], None

        pinned_fp = (getattr(paired_rec, "cert_fingerprint", None) or "").strip()
        provided_fp = (expected_fingerprint or "").strip()
        if pinned_fp and provided_fp and pinned_fp.replace(":", "").lower() != provided_fp.replace(":", "").lower():
            self.mark_route_unavailable(clean_id, ttype, "Certificate fingerprint mismatch.")
            return False, cmap[ttype], None
        effective_fp = pinned_fp or provided_fp or None

        dial_timeout = min(timeout if timeout is not None else self.direct_dial_timeout, DEFAULT_PROBE_TIMEOUT_SEC)
        cand.state = RouteStatus.PROBING
        client = SnowPeerClient(
            host=probe_host,
            port=probe_port,
            expected_fingerprint=effective_fp,
            use_tls=True,
        )
        try:
            async with self._probe_semaphore:
                dial_token = self.get_peer_token(clean_id)
                conn_res = await client.connect(auth_token=dial_token, timeout=dial_timeout)
                if not conn_res.success or getattr(conn_res, "status", "") == "CONNECTED_UNAUTHENTICATED":
                    await self._retire_client_safely(client, drain_grace=0.1)
                    reason = conn_res.error or conn_res.status or "Peer handshake failed."
                    self.mark_route_unavailable(clean_id, ttype, reason)
                    return False, cmap[ttype], None
                if conn_res.remote_device_id and conn_res.remote_device_id != clean_id:
                    await self._retire_client_safely(client, drain_grace=0.1)
                    self.mark_route_unavailable(
                        clean_id,
                        ttype,
                        f"Identity mismatch (got '{conn_res.remote_device_id}').",
                    )
                    return False, cmap[ttype], None
                if verify_ping:
                    try:
                        ping_msg = SnowMessage.create_request(action="ping", data={})
                        ping_resp = await client.send_message(ping_msg, timeout=min(dial_timeout, 2.0))
                        if ping_resp is None or ping_resp.type == MessageType.ERROR:
                            await self._retire_client_safely(client, drain_grace=0.1)
                            self.mark_route_unavailable(clean_id, ttype, "Readiness ping failed.")
                            return False, cmap[ttype], None
                    except Exception as ping_exc:
                        await self._retire_client_safely(client, drain_grace=0.1)
                        self.mark_route_unavailable(clean_id, ttype, f"Readiness ping failed: {ping_exc}")
                        return False, cmap[ttype], None
        except Exception as exc:
            await self._retire_client_safely(client, drain_grace=0.1)
            self.mark_route_unavailable(clean_id, ttype, str(exc))
            return False, cmap[ttype], None

        verified = self.mark_route_verified(clean_id, ttype, host=probe_host, port=probe_port, direction="outbound")
        return True, verified, client

    async def handle_transport_loss(
        self,
        device_id: str,
        lost_transport: TransportType | str,
        reason: str = "Active transport lost.",
    ) -> dict[str, Any]:
        """Handle drop of an active transport: demote dead route and fail over cleanly if allowed."""
        clean_id = (device_id or "").strip()
        ttype = (
            lost_transport
            if isinstance(lost_transport, TransportType)
            else normalize_transport_type(transport=str(lost_transport))
        )
        async with self._get_device_lock(clean_id):
            self.mark_route_unavailable(clean_id, ttype, reason=reason, cooldown_sec=DEFAULT_PROBE_COOLDOWN_SEC)
            old_client = self._outbound_clients.get(clean_id)
            old_tt = self._outbound_transports.get(clean_id)
            if old_client is not None and (old_tt == ttype or old_tt is None):
                self._outbound_clients.pop(clean_id, None)
                self._outbound_transports.pop(clean_id, None)
                await self._retire_client_safely(old_client, drain_grace=0.5)

            eff_mode = self._resolve_effective_transport_mode(clean_id)
            if eff_mode == ttype.value:
                self._last_switch_reason[clean_id] = f"Manual {ttype.value} route lost."
                return {
                    "success": False,
                    "status": "MANUAL_ROUTE_UNAVAILABLE",
                    "device_id": clean_id,
                    "lost_transport": ttype.value,
                    "active_transport": None,
                    "mode": eff_mode,
                    "error": f"Manually selected '{ttype.value}' route lost ({sanitize_transport_error(reason)}).",
                }

        fallback_order = [
            tt
            for tt in TRANSPORT_PRIORITY_ORDER
            if tt != ttype
            and not (eff_mode == "local_only" and tt == TransportType.REMOTE_RELAY)
            and not (eff_mode in ("remote_only", "remote_relay") and tt != TransportType.REMOTE_RELAY)
        ]
        for next_tt in fallback_order:
            ok, cand, standby = await self.probe_candidate_route(clean_id, next_tt, verify_ping=True, force=True)
            if ok:
                async with self._get_device_lock(clean_id):
                    if standby is not None:
                        prev_client = self._outbound_clients.get(clean_id)
                        self._outbound_clients[clean_id] = standby
                        self._outbound_transports[clean_id] = next_tt
                        if prev_client is not None and prev_client is not standby:
                            await self._retire_client_safely(prev_client)
                    self.mark_route_verified(
                        clean_id,
                        next_tt,
                        host=cand.host,
                        port=cand.port,
                        is_active=True,
                        direction=cand.direction or "fallback",
                    )
                    self._last_switch_reason[clean_id] = f"Failover {ttype.value} -> {next_tt.value}"
                    node = self.node_registry.get_node(clean_id) if hasattr(self.node_registry, "get_node") else None
                    if node is not None:
                        node.transport = next_tt.value
                        if cand.host and next_tt != TransportType.REMOTE_RELAY:
                            node.host = cand.host
                        node.reachability_state = (
                            ReachabilityState.ONLINE_RELAYED
                            if next_tt == TransportType.REMOTE_RELAY
                            else ReachabilityState.CONNECTED_SESSION
                        )
                return {
                    "success": True,
                    "status": "FAILOVER_COMPLETE",
                    "device_id": clean_id,
                    "lost_transport": ttype.value,
                    "active_transport": next_tt.value,
                    "badge": cand.badge,
                    "mode": eff_mode,
                }

        return {
            "success": False,
            "status": "ALL_FALLBACK_ROUTES_UNAVAILABLE",
            "device_id": clean_id,
            "lost_transport": ttype.value,
            "active_transport": None,
            "mode": eff_mode,
            "error": "No fallback route is currently reachable.",
        }

    async def set_manual_transport_mode(
        self,
        device_id: str,
        mode: str,
        *,
        allow_probe: bool = True,
    ) -> dict[str, Any]:
        """Set Auto/policy/manual transport mode; fails closed if selected manual route is unverified."""
        clean_id = (device_id or "").strip()
        norm_mode = normalize_transport_mode(mode)
        if not clean_id or not norm_mode:
            return {
                "success": False,
                "status": "INVALID_TRANSPORT_MODE",
                "error": f"Unsupported transport mode '{mode}'. Valid modes: {', '.join(VALID_TRANSPORT_MODES)}.",
            }
        paired_rec = self.db_manager.get_paired_device(clean_id) if self.db_manager else None
        if not paired_rec:
            return {
                "success": False,
                "status": "DEVICE_NOT_PAIRED",
                "error": f"Device '{clean_id}' is not paired.",
            }

        prev_mode = self._resolve_effective_transport_mode(clean_id, paired_rec)
        prev_active = self._active_route_type.get(clean_id)

        if norm_mode in MANUAL_SINGLE_TRANSPORT_MODES:
            target_tt = TransportType(norm_mode)
            self._switching_devices.add(clean_id)
            try:
                cmap = self.refresh_transport_candidates(clean_id)
                cand = cmap[target_tt]
                standby_client: Optional[SnowPeerClient] = None
                if not cand.is_usable() and allow_probe:
                    ok, cand, standby_client = await self.probe_candidate_route(
                        clean_id, target_tt, verify_ping=True, force=True
                    )
                else:
                    ok = cand.is_usable()
                    if ok and allow_probe and target_tt != TransportType.REMOTE_RELAY:
                        ok, cand, standby_client = await self.probe_candidate_route(
                            clean_id, target_tt, host=cand.host, port=cand.port, verify_ping=False, force=True
                        )

                if not ok:
                    return {
                        "success": False,
                        "status": "ROUTE_UNAVAILABLE",
                        "error": cand.last_failure_reason or f"Route '{target_tt.value}' is not verified or reachable.",
                        "device_id": clean_id,
                        "requested_mode": norm_mode,
                        "mode": prev_mode,
                        "active_transport": prev_active.value if prev_active else None,
                        "transport_state": self.get_device_transport_state(clean_id),
                    }

                async with self._get_device_lock(clean_id):
                    if standby_client is not None:
                        old_client = self._outbound_clients.get(clean_id)
                        self._outbound_clients[clean_id] = standby_client
                        self._outbound_transports[clean_id] = target_tt
                        if old_client is not None and old_client is not standby_client:
                            await self._retire_client_safely(old_client)
                    self.mark_route_verified(
                        clean_id,
                        target_tt,
                        host=cand.host,
                        port=cand.port,
                        is_active=True,
                        direction=cand.direction or "manual",
                    )
                    if self.db_manager:
                        db_conn_mode = "remote_only" if target_tt == TransportType.REMOTE_RELAY else "local_only"
                        self.db_manager.update_device_connection_mode(clean_id, db_conn_mode)
                        self.db_manager.set_setting(f"device_transport_override:{clean_id}", norm_mode)
                    self._last_switch_reason[clean_id] = f"Manual switch to {target_tt.value}"
            finally:
                self._switching_devices.discard(clean_id)

            return {
                "success": True,
                "status": "MODE_UPDATED",
                "device_id": clean_id,
                "mode": norm_mode,
                "active_transport": target_tt.value,
                "transport_badge": transport_badge_for(target_tt),
                "transport_state": self.get_device_transport_state(clean_id),
            }

        # Policy / Auto modes: "auto", "local_only", "remote_only"
        if norm_mode == "remote_only":
            ok, cand, _ = await self.probe_candidate_route(clean_id, TransportType.REMOTE_RELAY, verify_ping=False, force=True)
            if not ok:
                return {
                    "success": False,
                    "status": "ROUTE_UNAVAILABLE",
                    "error": cand.last_failure_reason or "Remote relay is unavailable.",
                    "device_id": clean_id,
                    "mode": prev_mode,
                    "transport_state": self.get_device_transport_state(clean_id),
                }

        if self.db_manager:
            self.db_manager.update_device_connection_mode(clean_id, norm_mode)
            self.db_manager.set_setting(f"device_transport_override:{clean_id}", "")

        # Immediately re-evaluate highest priority eligible route when switching to auto or local_only
        if norm_mode in ("auto", "local_only"):
            cmap = self.refresh_transport_candidates(clean_id)
            candidates_order = [
                tt for tt in TRANSPORT_PRIORITY_ORDER
                if not (norm_mode == "local_only" and tt == TransportType.REMOTE_RELAY)
            ]
            for cand_tt in candidates_order:
                c = cmap[cand_tt]
                if c.state in (RouteStatus.DISCOVERED, RouteStatus.CANDIDATE, RouteStatus.VERIFIED_AVAILABLE, RouteStatus.ACTIVE) or (
                    cand_tt == TransportType.REMOTE_RELAY and c.is_usable()
                ):
                    if not allow_probe and c.is_usable():
                        ok, verified_c, standby_c = True, c, None
                    elif not allow_probe:
                        continue
                    else:
                        ok, verified_c, standby_c = await self.probe_candidate_route(
                            clean_id, cand_tt, host=c.host, port=c.port, verify_ping=False, force=True
                        )
                    if ok:
                        async with self._get_device_lock(clean_id):
                            if standby_c is not None:
                                old_client = self._outbound_clients.get(clean_id)
                                self._outbound_clients[clean_id] = standby_c
                                self._outbound_transports[clean_id] = cand_tt
                                if old_client is not None and old_client is not standby_c:
                                    await self._retire_client_safely(old_client)
                            self.mark_route_verified(
                                clean_id,
                                cand_tt,
                                host=verified_c.host,
                                port=verified_c.port,
                                is_active=True,
                                direction=verified_c.direction or "auto",
                            )
                        break

        self._last_switch_reason[clean_id] = f"Policy mode set to {norm_mode}"
        cur_active = self._active_route_type.get(clean_id)
        return {
            "success": True,
            "status": "MODE_UPDATED",
            "device_id": clean_id,
            "mode": norm_mode,
            "active_transport": cur_active.value if cur_active else None,
            "transport_state": self.get_device_transport_state(clean_id),
        }

    def pin_transfer_route(
        self,
        transfer_id: str,
        device_id: str,
        transport: TransportType | str,
        *,
        host: str = "",
        port: int = 8766,
    ) -> dict[str, Any]:
        """Pin an in-flight large transfer to its active healthy socket until completion or failure."""
        ttype = transport if isinstance(transport, TransportType) else normalize_transport_type(transport=str(transport), host=host)
        rec = {
            "transfer_id": transfer_id,
            "device_id": device_id,
            "transport": ttype.value,
            "badge": transport_badge_for(ttype),
            "host": host,
            "port": int(port),
            "pinned_at": time.monotonic(),
        }
        self._pinned_transfer_routes[transfer_id] = rec
        return dict(rec)

    def get_pinned_transfer_route(self, transfer_id: str) -> Optional[dict[str, Any]]:
        rec = self._pinned_transfer_routes.get(transfer_id)
        return dict(rec) if rec else None

    def clear_pinned_transfer_route(self, transfer_id: str) -> None:
        self._pinned_transfer_routes.pop(transfer_id, None)

    def get_device_transport_state(self, device_id: str) -> dict[str, Any]:
        """Return safe, authoritative transport state snapshot for API/Web/Android UIs."""
        clean_id = (device_id or "").strip()
        cmap = self.refresh_transport_candidates(clean_id)
        mode = self._resolve_effective_transport_mode(clean_id)
        paired_rec = self.db_manager.get_paired_device(clean_id) if self.db_manager else None
        conn_mode = getattr(paired_rec, "connection_mode", "auto") if paired_rec else "auto"
        active_tt = self._active_route_type.get(clean_id)
        now = time.monotonic()

        # Infer active transport from active session/node only when explicit active_tt is absent
        if active_tt is None:
            out_client = self._outbound_clients.get(clean_id)
            if out_client is not None and getattr(out_client, "is_connected", False):
                active_tt = self._outbound_transports.get(clean_id) or normalize_transport_type(
                    host=getattr(out_client, "host", None)
                )

        routes = [
            cmap[tt].to_public_dict(
                is_active=(active_tt == tt),
                is_manual=(mode == tt.value),
                now=now,
            )
            for tt in TRANSPORT_PRIORITY_ORDER
        ]
        recommended = next((r["transport"] for r in routes if r["verified"]), None)
        return {
            "device_id": clean_id,
            "mode": mode,
            "connection_mode": conn_mode or "auto",
            "active_transport": active_tt.value if active_tt else None,
            "active_badge": transport_badge_for(active_tt) if active_tt else None,
            "switching": clean_id in self._switching_devices,
            "recommended_transport": recommended,
            "last_switch_reason": self._last_switch_reason.get(clean_id),
            "generation": self._route_generation.get(clean_id, 0),
            "routes": routes,
        }

    def register_peer_token(self, device_id: str, token: str) -> None:
        """Register an authentication token for outbound direct dials to a peer."""
        self._peer_tokens[device_id] = token

    def get_peer_token(self, device_id: str) -> str:
        """Retrieve the outbound authentication token for a peer."""
        return self._peer_tokens.get(device_id, "")

    def register_outbound_client(self, device_id: str, client: SnowPeerClient) -> None:
        """Register an active outbound SnowPeerClient."""
        self._outbound_clients[device_id] = client

    def get_route_promotion_status(self, device_id: str) -> Optional[dict[str, Any]]:
        """Return latest local route promotion diagnostics for a paired device."""
        rec = self._route_promotion_status.get(device_id)
        return dict(rec) if rec else None

    async def promote_local_route(
        self,
        device_id: str,
        host: str,
        port: int = 8765,
        transport: Optional[str] = None,
        expected_fingerprint: Optional[str] = None,
        timeout: Optional[float] = None,
        verify_ping: bool = False,
    ) -> dict[str, Any]:
        """Promote a paired peer from Remote Relay to a local USB, Hotspot, or Wi-Fi LAN link.

        Implements Make-Before-Break: dials and authenticates the new socket first, checks peer
        identity and certificate fingerprint, enforces epoch generation, and retires the prior
        session cleanly only after promotion succeeds. Never drops fallback on failure.
        """
        clean_id = (device_id or "").strip()
        clean_host = (host or "").strip()
        if not clean_id or not clean_host:
            return {
                "promoted": False,
                "status": "INVALID_ARGUMENT",
                "error": "Device ID and local host are required for promotion.",
                "fallback_retained": True,
            }

        paired_rec = self.db_manager.get_paired_device(clean_id) if self.db_manager else None
        if not paired_rec:
            return {
                "promoted": False,
                "status": "DEVICE_NOT_PAIRED",
                "error": f"Device '{clean_id}' is not paired.",
                "fallback_retained": True,
            }

        eff_mode = self._resolve_effective_transport_mode(clean_id, paired_rec)
        if eff_mode in ("remote_only", "remote_relay"):
            return {
                "promoted": False,
                "status": "POLICY_REMOTE_ONLY",
                "error": f"Local promotion blocked by '{eff_mode}' policy for '{clean_id}'.",
                "fallback_retained": True,
            }

        target_tt = normalize_transport_type(transport=transport, host=clean_host)
        if eff_mode in MANUAL_SINGLE_TRANSPORT_MODES and eff_mode != target_tt.value:
            return {
                "promoted": False,
                "status": "POLICY_MANUAL_PINNED",
                "error": f"Promotion to '{target_tt.value}' blocked by manual '{eff_mode}' selection.",
                "fallback_retained": True,
            }

        pinned_fp = (getattr(paired_rec, "cert_fingerprint", None) or "").strip()
        provided_fp = (expected_fingerprint or "").strip()
        if pinned_fp and provided_fp and pinned_fp.replace(":", "").lower() != provided_fp.replace(":", "").lower():
            return {
                "promoted": False,
                "status": "FINGERPRINT_MISMATCH",
                "error": "Candidate peer certificate fingerprint does not match pinned trust record.",
                "fallback_retained": True,
            }
        effective_fp = pinned_fp or provided_fp or None

        target_transport = "usb_adb" if target_tt == TransportType.USB else target_tt.value
        dial_timeout = timeout if timeout is not None else self.direct_dial_timeout

        # Reuse an already-authenticated inbound local WSS session matching the same host if live.
        if self.ws_server is not None:
            sess = self.ws_server.session_manager.get_session_by_device(clean_id)
            if sess and sess.connection_id:
                conn = self.ws_server.connection_manager.get(sess.connection_id)
                node_existing = (
                    self.node_registry.get_node(clean_id)
                    if hasattr(self.node_registry, "get_node")
                    else None
                )
                sess_host = (getattr(node_existing, "host", None) or "").strip()
                if conn and conn.is_active and sess_host == clean_host and "relay" not in (getattr(node_existing, "transport", "") or "").lower():
                    self.mark_route_verified(
                        clean_id,
                        target_tt,
                        host=clean_host,
                        port=int(port),
                        is_active=True,
                        direction="inbound",
                    )
                    status_rec = {
                        "promoted": True,
                        "status": "PROMOTED",
                        "device_id": clean_id,
                        "transport": target_transport,
                        "transport_type": target_tt.value,
                        "transport_badge": transport_badge_for(target_tt),
                        "host": clean_host,
                        "port": int(port),
                        "promoted_at": time.time(),
                        "fallback_retained": True,
                    }
                    self._route_promotion_status[clean_id] = status_rec
                    return dict(status_rec)

        gen_before = self._route_generation.get(clean_id, 0)
        self._switching_devices.add(clean_id)
        try:
            client = SnowPeerClient(
                host=clean_host,
                port=int(port),
                expected_fingerprint=effective_fp,
                use_tls=True,
            )
            try:
                async with self._probe_semaphore:
                    dial_token = self.get_peer_token(clean_id)
                    conn_res = await client.connect(auth_token=dial_token, timeout=dial_timeout)
                    if not conn_res.success or getattr(conn_res, "status", "") == "CONNECTED_UNAUTHENTICATED":
                        await self._retire_client_safely(client, drain_grace=0.1)
                        fail_reason = conn_res.error or conn_res.status or "Local handshake failed; keeping relay fallback."
                        self.mark_route_unavailable(clean_id, target_tt, fail_reason)
                        return {
                            "promoted": False,
                            "status": conn_res.status or "LOCAL_PROBE_FAILED",
                            "error": sanitize_transport_error(fail_reason),
                            "fallback_retained": True,
                        }
                    if conn_res.remote_device_id and conn_res.remote_device_id != clean_id:
                        await self._retire_client_safely(client, drain_grace=0.1)
                        self.mark_route_unavailable(clean_id, target_tt, "Peer identity mismatch.")
                        return {
                            "promoted": False,
                            "status": "IDENTITY_MISMATCH",
                            "error": f"Expected device '{clean_id}', got '{conn_res.remote_device_id}'.",
                            "fallback_retained": True,
                        }
                    if verify_ping:
                        ping_msg = SnowMessage.create_request(action="ping", data={})
                        ping_resp = await client.send_message(ping_msg, timeout=min(dial_timeout, 2.0))
                        if ping_resp is None or ping_resp.type == MessageType.ERROR:
                            await self._retire_client_safely(client, drain_grace=0.1)
                            self.mark_route_unavailable(clean_id, target_tt, "Readiness ping failed.")
                            return {
                                "promoted": False,
                                "status": "LOCAL_PROBE_PING_FAILED",
                                "error": "Local route readiness check failed; keeping existing fallback.",
                                "fallback_retained": True,
                            }
            except Exception as exc:
                await self._retire_client_safely(client, drain_grace=0.1)
                self.mark_route_unavailable(clean_id, target_tt, str(exc))
                return {
                    "promoted": False,
                    "status": "LOCAL_PROBE_ERROR",
                    "error": sanitize_transport_error(exc),
                    "fallback_retained": True,
                }

            async with self._get_device_lock(clean_id):
                if self._route_generation.get(clean_id, 0) != gen_before:
                    await self._retire_client_safely(client, drain_grace=0.1)
                    return {
                        "promoted": False,
                        "status": "STALE_GENERATION",
                        "error": "Newer route promotion superseded this attempt.",
                        "fallback_retained": True,
                    }
                async with self._lock:
                    old_client = self._outbound_clients.get(clean_id)
                    self._outbound_clients[clean_id] = client
                    self._outbound_transports[clean_id] = target_tt
                if old_client is not None and old_client is not client:
                    await self._retire_client_safely(old_client, drain_grace=1.5)

                try:
                    if self.db_manager and hasattr(self.db_manager, "update_device_endpoint"):
                        self.db_manager.update_device_endpoint(clean_id, clean_host, int(port))
                except Exception:
                    pass

                node = self.node_registry.get_node(clean_id) if hasattr(self.node_registry, "get_node") else None
                if node is not None:
                    node.transport = target_transport
                    node.host = clean_host
                    node.wss_port = int(port)
                    node.reachability_state = ReachabilityState.CONNECTED_SESSION
                if hasattr(self.node_registry, "on_session_authenticated"):
                    try:
                        self.node_registry.on_session_authenticated(
                            device_id=clean_id,
                            connection_id=f"promoted_{clean_id}",
                            host=clean_host,
                            port=int(port),
                            transport=target_transport,
                        )
                    except Exception:
                        pass

                self.mark_route_verified(
                    clean_id,
                    target_tt,
                    host=clean_host,
                    port=int(port),
                    is_active=True,
                    direction="outbound",
                )
                self._last_switch_reason[clean_id] = f"Promoted to {target_tt.value}"
        finally:
            self._switching_devices.discard(clean_id)

        badge = transport_badge_for(target_tt)
        status_rec = {
            "promoted": True,
            "status": "PROMOTED",
            "device_id": clean_id,
            "transport": target_transport,
            "transport_type": target_tt.value,
            "transport_badge": badge,
            "host": clean_host,
            "port": int(port),
            "promoted_at": time.time(),
            "fallback_retained": True,
        }
        self._route_promotion_status[clean_id] = status_rec
        logger.info("Promoted route for [%s] to %s (%s:%d)", clean_id, badge, clean_host, int(port))
        return dict(status_rec)

    async def route_request(
        self,
        action: str,
        target: Optional[str] = None,
        data: Optional[dict[str, Any]] = None,
        required_capability: Optional[str] = None,
        ctx: Optional[ExecutionContext] = None,
        timeout: float = 30.0,
        hop_limit: int = 3,
        visited_peers: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        """Resolve target, establish transport session if needed, and dispatch capability action.

        Args:
            action: Capability action identifier (e.g. 'android_battery', 'file_transfer_offer').
            target: Query string for device resolution (UUID, name, prefix, or None for default).
            data: Payload dictionary for the request.
            required_capability: Explicit capability string, or derived from action if omitted.
            ctx: Immutable execution context (defaults to AI_MCP for cross-device calls).
            timeout: Dispatch response timeout in seconds.
            hop_limit: Remaining mesh hop budget for peer relay requests.
            visited_peers: Already-visited node IDs to prevent routing loops.

        Returns:
            Structured dictionary with success, status, data/error, and routing diagnostics.
        """
        # Ensure immutable execution context; remote cross-device requests default to AI_MCP
        effective_ctx = ctx or ExecutionContext(
            principal=ExecutionPrincipal.AI_MCP,
            origin="router_dispatch",
        )

        attempted_transports: list[str] = []

        # Loop and hop-limit enforcement
        try:
            remaining_hops = int(hop_limit)
        except (TypeError, ValueError):
            remaining_hops = 3
        traversed = [str(p) for p in (visited_peers or []) if isinstance(p, str) and p.strip()]
        local_node_id = getattr(getattr(self.node_registry, "local_identity", None), "device_id", None)
        if local_node_id and local_node_id in traversed:
            return {
                "success": False,
                "status": "ROUTING_LOOP_DETECTED",
                "error": f"Routing loop detected: node '{local_node_id}' is already in visited peers.",
                "target_device_id": None,
                "attempted_transports": attempted_transports,
            }
        if remaining_hops <= 0:
            return {
                "success": False,
                "status": "HOP_LIMIT_EXCEEDED",
                "error": "Mesh routing hop limit exceeded.",
                "target_device_id": None,
                "attempted_transports": attempted_transports,
            }

        # =====================================================================
        # Step 1: Pre-flight Capability and Target Resolution
        # =====================================================================
        # Immediate validation: fail fast without any network delays or wake bursts
        req_cap = required_capability or ROUTER_ACTION_TO_CAPABILITY.get(action)
        node, resolve_err = self.node_registry.resolve_target(target, required_capability=req_cap)

        if resolve_err:
            logger.warning(
                "Router pre-flight rejected for target query '%s' and action '%s': %s",
                target,
                action,
                resolve_err,
            )
            return {
                "success": False,
                "status": resolve_err,
                "error": f"Target resolution failed: {resolve_err}",
                "target_device_id": None,
                "attempted_transports": [],
                "last_reachability_state": None,
                "last_known_endpoint": None,
            }

        assert node is not None
        device_id = node.device_id
        target_name = node.device_name
        last_state = str(node.reachability_state)
        last_endpoint = f"{node.host}:{node.wss_port}" if node.host else None

        # Step 1B: Live Permission Profile Backend Enforcement (Fail-Closed 5-Tier)
        profile = self._resolve_effective_profile(device_id, node)
        if not is_action_allowed_by_profile(profile, action):
            logger.warning(
                "Action '%s' blocked for device [%s] by permission profile '%s'",
                action,
                device_id,
                profile,
            )
            return {
                "success": False,
                "status": "PERMISSION_DENIED",
                "error": f"Operation '{action}' is blocked by device permission profile '{profile}'.",
                "target_device_id": device_id,
                "attempted_transports": attempted_transports,
                "last_reachability_state": last_state,
                "last_known_endpoint": last_endpoint,
            }

        # Clean payload: strip caller-supplied authority overrides
        clean_data = dict(data) if isinstance(data, dict) else {}
        clean_data.pop("principal", None)
        clean_data.pop("trust_tier", None)
        clean_data.pop("execution_principal", None)
        if action in (
            "file_list",
            "file_receive_request",
            "launch_app",
            "android_launch_app",
            "snow_android_launch_app",
        ) and effective_ctx.principal == ExecutionPrincipal.OWNER_MANUAL:
            clean_data["principal"] = effective_ctx.principal.value

        # Transfer idempotency check across route failovers (Stage 6B WS3)
        transfer_id = str(clean_data.get("transfer_id") or "").strip()
        is_transfer_op = bool(
            transfer_id
            and action in ("file_send_request", "file_receive_request", "android_file_receive", "desktop_file_stage_download")
        )
        if is_transfer_op:
            cached_tx = self._completed_transfer_routes.get((device_id, transfer_id))
            if cached_tx is not None:
                return dict(cached_tx, idempotent_replay=True)

        # Query persisted connection mode policy & manual override for target device
        paired_rec = self.db_manager.get_paired_device(device_id) if self.db_manager else None
        conn_mode = getattr(paired_rec, "connection_mode", "auto") if paired_rec else "auto"
        if not conn_mode:
            conn_mode = "auto"
        eff_mode = self._resolve_effective_transport_mode(device_id, paired_rec)

        # Policy Rule: remote_only or manual remote_relay forces relay tunnel directly, bypassing local LAN/USB tiers
        if eff_mode in ("remote_only", "remote_relay"):
            attempted_transports.append("remote_relay_tunnel")
            logger.info("Router Policy: '%s' configured for [%s]. Skipping local tiers.", eff_mode, device_id)
            if self.relay_enabled and self.relay_client is not None:
                relay_tunnel_res = await self._attempt_remote_relay_tunnel(
                    node=node,
                    action=action,
                    clean_data=clean_data,
                    timeout=timeout,
                    attempted_transports=attempted_transports,
                )
                if relay_tunnel_res is not None:
                    relay_tunnel_res = self._with_transport_badge(
                        relay_tunnel_res, transport="remote_relay", connection_mode="remote_only"
                    )
                    if is_transfer_op and relay_tunnel_res.get("success"):
                        self._record_transfer_route(device_id, transfer_id, relay_tunnel_res)
                    return relay_tunnel_res

            status_val = (
                "RELAY_UNAVAILABLE"
                if not (self.relay_enabled and self.relay_client and getattr(self.relay_client, "_is_connected", False))
                else "DEVICE_UNREACHABLE"
            )
            return self._with_transport_badge(
                {
                    "success": False,
                    "status": status_val,
                    "error": f"Remote relay routing failed or is unavailable for device '{device_id}' (mode: {eff_mode}).",
                    "target_device_id": device_id,
                    "attempted_transports": attempted_transports,
                    "last_reachability_state": last_state,
                    "last_known_endpoint": last_endpoint,
                    "connection_mode": eff_mode,
                },
                transport="remote_relay",
                connection_mode="remote_only",
            )

        # =====================================================================
        # Tier 1: Hybrid Active Session Routing (USB > Hotspot > Wi-Fi LAN > Remote)
        # =====================================================================
        candidate_dispatches: list[tuple[int, str, TransportType, Any]] = []
        if self.ws_server is not None:
            session = self.ws_server.session_manager.get_session_by_device(device_id)
            if session and session.connection_id:
                conn = self.ws_server.connection_manager.get(session.connection_id)
                if conn and conn.is_active:
                    sess_transport = (getattr(node, "transport", None) or "").strip().lower()
                    sess_host = (getattr(node, "host", None) or "").strip().lower()
                    tt = normalize_transport_type(transport=sess_transport, host=sess_host)
                    prio = transport_priority_for(tt)
                    candidate_dispatches.append((prio, "active_inbound_wss", tt, ("inbound", session)))

        outbound_client = self._outbound_clients.get(device_id)
        if outbound_client is not None and outbound_client.is_connected:
            out_host = getattr(out_client := outbound_client, "host", None) or getattr(node, "host", None)
            tt = self._outbound_transports.get(device_id) or normalize_transport_type(host=out_host)
            prio = transport_priority_for(tt)
            candidate_dispatches.append((prio, "active_outbound_peer", tt, ("outbound", out_client)))

        candidate_dispatches.sort(key=lambda item: item[0])
        # Automatic Relay -> Local promotion check: if only Remote active routes exist, probe live local discovery candidate first
        if (
            candidate_dispatches
            and all(prio == 3 for prio, _, _, _ in candidate_dispatches)
            and eff_mode not in ("remote_only", "remote_relay")
        ):
            disc_peer = None
            if self.discovery_service is not None and hasattr(self.discovery_service, "get_discovered_peer"):
                try:
                    disc_peer = self.discovery_service.get_discovered_peer(device_id)
                except Exception:
                    disc_peer = None
            if disc_peer and getattr(disc_peer, "ip_address", None):
                disc_tt = normalize_transport_type(
                    transport=getattr(disc_peer, "transport", None),
                    host=disc_peer.ip_address,
                    interface_name=getattr(disc_peer, "interface_name", None),
                    is_hotspot=bool(getattr(disc_peer, "is_hotspot", False)),
                )
                if eff_mode not in MANUAL_SINGLE_TRANSPORT_MODES or disc_tt.value == eff_mode:
                    attempted_transports.append("local_route_promotion")
                    promo = await self.promote_local_route(
                        device_id=device_id,
                        host=disc_peer.ip_address,
                        port=getattr(disc_peer, "port", None) or 8765,
                        transport=disc_tt.value,
                        expected_fingerprint=getattr(disc_peer, "cert_fingerprint", None),
                    )
                    if promo.get("promoted") and device_id in self._outbound_clients:
                        promoted_client = self._outbound_clients[device_id]
                        candidate_dispatches.insert(
                            0, (transport_priority_for(disc_tt), "promoted_local_peer", disc_tt, ("outbound", promoted_client))
                        )

        for prio, label, cand_tt, (kind, handle) in candidate_dispatches:
            if prio == 3 and eff_mode == "local_only":
                continue
            if eff_mode in MANUAL_SINGLE_TRANSPORT_MODES and cand_tt.value != eff_mode:
                continue
            attempted_transports.append(label)
            logger.debug(
                "Router Tier 1 (prio=%d, route=%s): Dispatching '%s' to [%s] via %s",
                prio,
                cand_tt.value,
                action,
                device_id,
                label,
            )
            if kind == "inbound":
                res = await self._dispatch_over_inbound_wss(
                    handle.connection_id, action, clean_data, timeout, node, attempted_transports
                )
            else:
                res = await self._dispatch_over_peer_client(
                    handle, action, clean_data, timeout, node, attempted_transports
                )
            badge_transport = "usb_adb" if cand_tt == TransportType.USB else cand_tt.value
            res["transport"] = badge_transport
            res["transport_type"] = cand_tt.value
            res = self._with_transport_badge(res, transport=badge_transport, host=getattr(node, "host", None))
            if is_transfer_op and res.get("success"):
                self._record_transfer_route(device_id, transfer_id, res)
            if res.get("success") or res.get("status") not in ("TIMEOUT", "TRANSPORT_ERROR", "DEVICE_UNREACHABLE"):
                return res

        # =====================================================================
        # Tier 2: Outbound Direct Connection (for PERSISTENT_DAEMON or FOREGROUND_HOST peers)
        # =====================================================================
        # For targets that listen on inbound ports (Windows desktop core / server nodes / Android host)
        if node.reachability_profile in (ReachabilityProfile.PERSISTENT_DAEMON, ReachabilityProfile.FOREGROUND_HOST):
            dial_host = "127.0.0.1" if eff_mode == "usb" else node.host
            dial_port = node.wss_port or 8765
            dial_tt = normalize_transport_type(transport=getattr(node, "transport", None), host=dial_host)
            if dial_host and (eff_mode not in MANUAL_SINGLE_TRANSPORT_MODES or dial_tt.value == eff_mode):
                attempted_transports.append("outbound_direct")
                logger.info(
                    "Router Tier 2: Outbound dialing [%s] at %s:%d (profile=%s, route=%s)...",
                    device_id,
                    dial_host,
                    dial_port,
                    node.reachability_profile,
                    dial_tt.value,
                )
                direct_res = await self._attempt_outbound_direct_dial(
                    node=node,
                    host=dial_host,
                    port=dial_port,
                    action=action,
                    clean_data=clean_data,
                    timeout=timeout,
                    attempted_transports=attempted_transports,
                )
                if direct_res is not None:
                    tr = "usb_adb" if dial_tt == TransportType.USB else dial_tt.value
                    direct_res["transport"] = tr
                    direct_res["transport_type"] = dial_tt.value
                    direct_res = self._with_transport_badge(direct_res, transport=tr, host=dial_host)
                    if is_transfer_op and direct_res.get("success"):
                        self._record_transfer_route(device_id, transfer_id, direct_res)
                    return direct_res
            else:
                logger.debug("Router Tier 2 skipped: No matching endpoint for [%s] (mode=%s)", device_id, eff_mode)

        # =====================================================================
        # Tier 3: Android Active-Session Peer Recovery
        # =====================================================================
        # For Android peers whose connection was terminated or dormant
        if node.reachability_profile == ReachabilityProfile.ACTIVE_SESSION_PEER:
            attempted_transports.append("android_wake_and_await")
            logger.info(
                "Router Tier 3: Attempting wake-and-await for Android peer [%s] (grace_period=%.1fs)...",
                device_id,
                self.wake_grace_period,
            )

            # 3A: Send discovery wake beacons (unicast if last known host is available + broadcast)
            if self.discovery_service is not None and self.discovery_service.is_running:
                try:
                    await self.discovery_service.send_wake_burst(device_id)
                except Exception as wake_exc:
                    logger.debug("Failed sending wake burst to [%s]: %s", device_id, wake_exc)

            # 3B: Await authenticated reconnection within bounded grace period
            start_wait = time.time()
            reconnected_session = None

            while time.time() - start_wait < self.wake_grace_period:
                await asyncio.sleep(0.2)
                if self.ws_server is not None:
                    sess = self.ws_server.session_manager.get_session_by_device(device_id)
                    if sess and sess.connection_id:
                        conn = self.ws_server.connection_manager.get(sess.connection_id)
                        if conn and conn.is_active:
                            reconn_tt = normalize_transport_type(
                                transport=getattr(node, "transport", None),
                                host=getattr(node, "host", None),
                            )
                            if eff_mode in MANUAL_SINGLE_TRANSPORT_MODES and reconn_tt.value != eff_mode:
                                continue
                            reconnected_session = sess
                            break

            if reconnected_session and reconnected_session.connection_id:
                elapsed = time.time() - start_wait
                logger.info(
                    "Router Tier 3: Android peer [%s] reconnected successfully after %.2fs. Dispatching '%s'...",
                    device_id,
                    elapsed,
                    action,
                )
                res = await self._dispatch_over_inbound_wss(
                    reconnected_session.connection_id, action, clean_data, timeout, node, attempted_transports
                )
                reconn_tt = normalize_transport_type(
                    transport=getattr(node, "transport", None),
                    host=getattr(node, "host", None),
                )
                tr = "usb_adb" if reconn_tt == TransportType.USB else reconn_tt.value
                res["transport"] = tr
                res["transport_type"] = reconn_tt.value
                res = self._with_transport_badge(res, transport=tr, host=getattr(node, "host", None))
                if is_transfer_op and res.get("success"):
                    self._record_transfer_route(device_id, transfer_id, res)
                return res

        # Fail closed when manually pinned to a specific local transport (do NOT silently bypass to relay)
        if eff_mode in MANUAL_SINGLE_TRANSPORT_MODES and eff_mode != TransportType.REMOTE_RELAY.value:
            return {
                "success": False,
                "status": "MANUAL_ROUTE_UNAVAILABLE",
                "error": f"Manually selected '{eff_mode}' transport is unavailable for device '{device_id}'.",
                "target_device_id": device_id,
                "attempted_transports": attempted_transports,
                "last_reachability_state": last_state,
                "last_known_endpoint": last_endpoint,
                "connection_mode": eff_mode,
            }

        # Policy Rule: local_only strictly forbids relay hops or remote tunnels
        if eff_mode == "local_only":
            logger.info("Router Policy: 'local_only' configured for [%s]. Rejecting remote relay fallback.", device_id)
            return {
                "success": False,
                "status": "REMOTE_DISABLED_BY_POLICY",
                "error": f"Remote relay routing is disabled by policy for device '{device_id}'.",
                "target_device_id": device_id,
                "attempted_transports": attempted_transports,
                "last_reachability_state": last_state,
                "last_known_endpoint": last_endpoint,
                "connection_mode": "local_only",
            }

        # =====================================================================
        # Tier 3.5: Authenticated Peer Relay (bounded hops + loop guard)
        # =====================================================================
        next_visited = list(traversed)
        if local_node_id and local_node_id not in next_visited:
            next_visited.append(local_node_id)
        if remaining_hops > 1:
            relay_res = await self._attempt_peer_relay(
                node=node,
                action=action,
                clean_data=clean_data,
                timeout=timeout,
                attempted_transports=attempted_transports,
                hop_limit=remaining_hops - 1,
                visited_nodes=next_visited,
            )
            if relay_res is not None:
                relay_res = self._with_transport_badge(relay_res, transport="remote_relay")
                if is_transfer_op and relay_res.get("success"):
                    self._record_transfer_route(device_id, transfer_id, relay_res)
                return relay_res

        # =====================================================================
        # Tier 3.75: Dedicated Remote E2E Relay Tunnel
        # =====================================================================
        if self.relay_enabled and self.relay_client is not None:
            attempted_transports.append("remote_relay_tunnel")
            logger.info("Router Tier 3.75: Attempting remote E2E relay tunnel for [%s]...", device_id)
            relay_tunnel_res = await self._attempt_remote_relay_tunnel(
                node=node,
                action=action,
                clean_data=clean_data,
                timeout=timeout,
                attempted_transports=attempted_transports,
            )
            if relay_tunnel_res is not None:
                relay_tunnel_res = self._with_transport_badge(relay_tunnel_res, transport="remote_relay")
                if is_transfer_op and relay_tunnel_res.get("success"):
                    self._record_transfer_route(device_id, transfer_id, relay_tunnel_res)
                return relay_tunnel_res

        # =====================================================================
        # Tier 4: Structured Failure
        # =====================================================================
        logger.warning(
            "Router Tier 4: All transport attempts exhausted for device [%s] (%s). Transports attempted: %s",
            device_id,
            target_name,
            attempted_transports,
        )
        return {
            "success": False,
            "status": "DEVICE_UNREACHABLE",
            "error": f"Device '{device_id}' ({target_name}) is unreachable across all attempted transports.",
            "attempted_transports": attempted_transports,
            "last_reachability_state": last_state,
            "target_device_id": device_id,
            "last_known_endpoint": last_endpoint,
        }

    def _record_transfer_route(self, device_id: str, transfer_id: str, res: dict[str, Any]) -> None:
        while len(self._completed_transfer_routes) >= 512:
            oldest = next(iter(self._completed_transfer_routes))
            self._completed_transfer_routes.pop(oldest, None)
        self._completed_transfer_routes[(device_id, transfer_id)] = dict(res)

    # =========================================================================
    # Internal Dispatch & Transport Helpers
    # =========================================================================

    async def _dispatch_over_inbound_wss(
        self,
        connection_id: str,
        action: str,
        data: dict[str, Any],
        timeout: float,
        node: DeviceNode,
        attempted_transports: list[str],
    ) -> dict[str, Any]:
        """Dispatch a request over an established inbound WebSocket connection."""
        if not self.ws_server:
            return {
                "success": False,
                "status": "SERVER_ERROR",
                "error": "SnowWebSocketServer is not available for dispatch.",
                "target_device_id": node.device_id,
                "attempted_transports": attempted_transports,
            }

        wire_action = ACTION_TO_WIRE_ACTION.get(action, action)
        try:
            response = await self.ws_server.send_request(
                connection_id=connection_id,
                action=wire_action,
                payload=data,
                timeout=timeout,
            )

            is_ok = response.type == MessageType.RESPONSE and (
                response.payload is None or (
                    response.payload.get("status") not in (
                        "error",
                        "FOREGROUND_REQUIRED",
                        "UNSUPPORTED_MODE",
                        "PERMISSION_DENIED",
                        "RUNTIME_PERMISSION_REQUIRED",
                        "USER_CONFIRMATION_REQUIRED",
                    )
                    and response.payload.get("success") is not False
                )
            )
            err_msg = None
            if response.error:
                err_msg = response.error.get("message") if isinstance(response.error, dict) else str(response.error)
            elif not is_ok and response.payload:
                err_msg = response.payload.get("message") or response.payload.get("error")

            payload_status = response.payload.get("status") if (response.payload and isinstance(response.payload, dict)) else None
            err_code = response.error.get("code") if (response.error and isinstance(response.error, dict)) else None

            if not is_ok:
                if payload_status and payload_status != "error":
                    status_val = payload_status
                elif err_msg and "FOREGROUND_REQUIRED" in err_msg:
                    status_val = "FOREGROUND_REQUIRED"
                elif err_code and err_code != "INTERNAL_ERROR":
                    status_val = err_code
                else:
                    status_val = "DEVICE_ERROR"
            else:
                status_val = "SUCCESS"

            return {
                "success": is_ok,
                "status": status_val,
                "data": response.payload,
                "error": err_msg,
                "target_device_id": node.device_id,
                "attempted_transports": attempted_transports,
            }
        except asyncio.TimeoutError:
            return {
                "success": False,
                "status": "TIMEOUT",
                "error": f"Device '{node.device_id}' timed out after {timeout:.1f}s waiting for '{action}' response.",
                "target_device_id": node.device_id,
                "attempted_transports": attempted_transports,
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "TRANSPORT_ERROR",
                "error": f"Failed dispatching to device '{node.device_id}': {exc}",
                "target_device_id": node.device_id,
                "attempted_transports": attempted_transports,
            }

    async def _dispatch_over_peer_client(
        self,
        client: SnowPeerClient,
        action: str,
        data: dict[str, Any],
        timeout: float,
        node: DeviceNode,
        attempted_transports: list[str],
    ) -> dict[str, Any]:
        """Dispatch a request over an active outbound SnowPeerClient connection."""
        wire_action = ACTION_TO_WIRE_ACTION.get(action, action)
        try:
            req = SnowMessage.create_request(action=wire_action, data=data)
            response = await client.send_message(req, timeout=timeout)

            is_ok = response.type == MessageType.RESPONSE and (
                response.payload is None or (
                    response.payload.get("status") not in (
                        "error",
                        "FOREGROUND_REQUIRED",
                        "UNSUPPORTED_MODE",
                        "PERMISSION_DENIED",
                        "RUNTIME_PERMISSION_REQUIRED",
                        "USER_CONFIRMATION_REQUIRED",
                    )
                    and response.payload.get("success") is not False
                )
            )
            err_msg = None
            if response.error:
                err_msg = response.error.get("message") if isinstance(response.error, dict) else str(response.error)
            elif not is_ok and response.payload:
                err_msg = response.payload.get("message") or response.payload.get("error")

            payload_status = response.payload.get("status") if (response.payload and isinstance(response.payload, dict)) else None
            err_code = response.error.get("code") if (response.error and isinstance(response.error, dict)) else None

            if not is_ok:
                if payload_status and payload_status != "error":
                    status_val = payload_status
                elif err_msg and "FOREGROUND_REQUIRED" in err_msg:
                    status_val = "FOREGROUND_REQUIRED"
                elif err_code and err_code != "INTERNAL_ERROR":
                    status_val = err_code
                else:
                    status_val = "DEVICE_ERROR"
            else:
                status_val = "SUCCESS"

            return {
                "success": is_ok,
                "status": status_val,
                "data": response.payload,
                "error": err_msg,
                "target_device_id": node.device_id,
                "attempted_transports": attempted_transports,
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "TRANSPORT_ERROR",
                "error": f"Outbound peer dispatch error: {exc}",
                "target_device_id": node.device_id,
                "attempted_transports": attempted_transports,
            }

    async def _attempt_outbound_direct_dial(
        self,
        node: DeviceNode,
        host: str,
        port: int,
        action: str,
        clean_data: dict[str, Any],
        timeout: float,
        attempted_transports: list[str],
    ) -> Optional[dict[str, Any]]:
        """Attempt outbound direct connection, authentication, and execution with a peer."""
        # Retrieve pairing token from DB
        paired_rec = self.db_manager.get_paired_device(node.device_id)
        if not paired_rec:
            logger.debug("Cannot direct dial [%s]: not in paired devices database", node.device_id)
            return None

        # Look up expected certificate fingerprint if known
        expected_fp = getattr(paired_rec, "cert_fingerprint", None) or ""

        # Create peer client with bounded dial timeout
        client = SnowPeerClient(
            host=host,
            port=port,
            expected_fingerprint=expected_fp if expected_fp else None,
            use_tls=True,
        )

        try:
            # Look up registered or cached outbound auth token
            dial_token = self.get_peer_token(node.device_id)

            conn_res: PeerConnectionResult = await client.connect(
                auth_token=dial_token,
                timeout=self.direct_dial_timeout,
            )

            if not conn_res.success:
                logger.debug("Direct dial to %s:%d failed: %s", host, port, conn_res.error)
                return None

            # Verify peer identity matches expected device_id
            if conn_res.remote_device_id and conn_res.remote_device_id != node.device_id:
                logger.warning(
                    "Identity mismatch on direct dial! Expected [%s], got [%s]. Aborting.",
                    node.device_id,
                    conn_res.remote_device_id,
                )
                await client.close()
                return None

            # Register authenticated outbound session
            async with self._lock:
                self._outbound_clients[node.device_id] = client

            # Update DB endpoint only after successful verified connection
            self.db_manager.update_device_endpoint(node.device_id, host, port)

            # Dispatch request
            return await self._dispatch_over_peer_client(
                client, action, clean_data, timeout, node, attempted_transports
            )
        except Exception as dial_exc:
            logger.debug("Outbound direct dial exception for [%s]: %s", node.device_id, dial_exc)
            try:
                await client.close()
            except Exception:
                pass
            return None

    async def _attempt_peer_relay(
        self,
        node: DeviceNode,
        action: str,
        clean_data: dict[str, Any],
        timeout: float,
        attempted_transports: list[str],
        hop_limit: int = 2,
        visited_nodes: Optional[list[str]] = None,
    ) -> Optional[dict[str, Any]]:
        """Attempt to route request through an active intermediate peer (Tier 3.5)."""
        visited = list(visited_nodes or [])
        # 1. Check active outbound clients
        for peer_id, client in list(self._outbound_clients.items()):
            if peer_id == node.device_id or peer_id in visited or not client.is_connected:
                continue
            attempted_transports.append(f"relay_outbound:{peer_id}")
            try:
                relay_msg = SnowMessage.create_request(
                    action="peer_relay_request",
                    payload={
                        "target_device_id": node.device_id,
                        "action": action,
                        "data": clean_data,
                        "hop_limit": hop_limit,
                        "visited_nodes": visited,
                    },
                )
                resp = await client.send_message(relay_msg, timeout=timeout)
                if resp.type == MessageType.RESPONSE and resp.payload and resp.payload.get("status") == "success":
                    node.reachability_state = ReachabilityState.ONLINE_ROUTED
                    return {
                        "success": True,
                        "status": "SUCCESS",
                        "data": (resp.payload.get("data") or {}).get("data") or resp.payload.get("data"),
                        "target_device_id": node.device_id,
                        "attempted_transports": attempted_transports,
                        "relayed_by": peer_id,
                    }
            except Exception as exc:
                logger.debug("Relay attempt via outbound [%s] failed: %s", peer_id, exc)

        # 2. Check active inbound sessions
        if self.ws_server is not None:
            active_sessions = self.ws_server.session_manager.list_active_sessions()
            for sess in active_sessions:
                if sess.device_id == node.device_id or sess.device_id in visited or not sess.connection_id:
                    continue
                conn = self.ws_server.connection_manager.get(sess.connection_id)
                if not conn or not conn.is_active:
                    continue
                attempted_transports.append(f"relay_inbound:{sess.device_id}")
                try:
                    relay_resp = await self.ws_server.send_request(
                        connection_id=sess.connection_id,
                        action="peer_relay_request",
                        payload={
                            "target_device_id": node.device_id,
                            "action": action,
                            "data": clean_data,
                            "hop_limit": hop_limit,
                            "visited_nodes": visited,
                        },
                        timeout=timeout,
                    )
                    if relay_resp.type == MessageType.RESPONSE and relay_resp.payload and relay_resp.payload.get("status") == "success":
                        node.reachability_state = ReachabilityState.ONLINE_ROUTED
                        return {
                            "success": True,
                            "status": "SUCCESS",
                            "data": (relay_resp.payload.get("data") or {}).get("data") or relay_resp.payload.get("data"),
                            "target_device_id": node.device_id,
                            "attempted_transports": attempted_transports,
                            "relayed_by": sess.device_id,
                        }
                except Exception as exc:
                    logger.debug("Relay attempt via inbound [%s] failed: %s", sess.device_id, exc)

        return None

    async def _attempt_remote_relay_tunnel(
        self,
        node: DeviceNode,
        action: str,
        clean_data: dict[str, Any],
        timeout: float,
        attempted_transports: list[str],
    ) -> Optional[dict[str, Any]]:
        """Attempt to route request through dedicated remote E2E encrypted relay tunnel (Tier 3.75)."""
        if not self.relay_client or not getattr(self.relay_client, "_is_connected", False):
            logger.debug("Remote relay tunnel skipped: Relay client is not connected.")
            return None

        device_id = node.device_id
        msg = SnowMessage.create_request(action=action, data=clean_data)

        try:
            sent = await self.relay_client.send_message(device_id, msg)
            if not sent:
                return None

            resp = await self.relay_client.receive_message(device_id, timeout=timeout)
            if resp:
                node.reachability_state = ReachabilityState.ONLINE_RELAYED
                node.transport = "remote_relay"
                err_text = None
                if resp.error:
                    err_text = resp.error.get("message") if isinstance(resp.error, dict) else (resp.error.message if hasattr(resp.error, "message") else str(resp.error))
                data_val = (resp.payload.get("data") if (isinstance(resp.payload, dict) and "data" in resp.payload) else (resp.payload or {})) if resp.payload else resp.data
                payload_status = resp.payload.get("status") if (isinstance(resp.payload, dict) and "status" in resp.payload) else None
                is_ok = resp.type != MessageType.ERROR and (resp.payload is None or (payload_status != "error" and resp.payload.get("success") is not False))
                if not is_ok and not err_text and isinstance(resp.payload, dict):
                    err_text = resp.payload.get("message") or resp.payload.get("error")
                status_val = payload_status if (payload_status and payload_status != "error") else ("SUCCESS" if is_ok else "REMOTE_ERROR")
                return {
                    "success": is_ok,
                    "status": status_val,
                    "data": data_val,
                    "error": err_text,
                    "target_device_id": device_id,
                    "attempted_transports": attempted_transports,
                    "routing": {
                        "tier": "Tier 3.75 (Remote E2E Relay Tunnel)",
                        "transport": "remote_relay",
                        "reachability": "ONLINE_RELAYED",
                        "target_device_id": device_id,
                    },
                }
        except Exception as e:
            logger.warning("Remote relay tunnel dispatch to [%s] failed: %s", device_id, e)
            return None

        return None
