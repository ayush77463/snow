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
) -> str:
    """Return the unified Web/Android transport badge label."""
    t = (transport or "").strip().lower()
    h = (host or "").strip().lower()
    m = (connection_mode or "").strip().lower()
    if "usb" in t or t == "adb" or (h in ("127.0.0.1", "localhost", "::1") and "relay" not in t and "remote" not in m):
        return "USB • Zero Data"
    if any(k in t for k in ("relay", "remote", "hub", "federated")) or m == "remote_only":
        return "Remote • Uses Data"
    return "Wi-Fi • Zero Data"


def classify_route_priority(
    transport: Optional[str] = None,
    host: Optional[str] = None,
    connection_mode: Optional[str] = None,
) -> int:
    """Return canonical route priority: 0=USB, 1=Wi-Fi LAN, 2=Remote Relay."""
    badge = classify_transport_badge(transport=transport, host=host, connection_mode=connection_mode)
    if badge == "USB • Zero Data":
        return 0
    if badge == "Wi-Fi • Zero Data":
        return 1
    return 2


def evaluate_preferred_route(
    candidates: list[dict[str, Any]],
    connection_mode: str = "auto",
) -> Optional[dict[str, Any]]:
    """Select the highest-priority active route honoring zero-data preference and mode policy."""
    mode = (connection_mode or "auto").strip().lower()
    eligible: list[tuple[int, dict[str, Any]]] = []
    for cand in candidates:
        if not cand or cand.get("active") is False:
            continue
        prio = classify_route_priority(
            transport=cand.get("transport"),
            host=cand.get("host"),
            connection_mode=cand.get("connection_mode"),
        )
        if mode == "local_only" and prio == 2:
            continue
        if mode == "remote_only" and prio != 2:
            continue
        enriched = dict(cand)
        enriched["priority"] = prio
        enriched["transport_badge"] = classify_transport_badge(
            transport=cand.get("transport"),
            host=cand.get("host"),
            connection_mode=mode if mode == "remote_only" else cand.get("connection_mode"),
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

        # Active outbound peer client sessions: device_id -> SnowPeerClient
        self._outbound_clients: dict[str, SnowPeerClient] = {}
        # Outbound peer tokens for direct dials: device_id -> token
        self._peer_tokens: dict[str, str] = {}
        # Bounded transfer idempotency cache across route failover switches: (device_id, transfer_id) -> result
        self._completed_transfer_routes: dict[tuple[str, str], dict[str, Any]] = {}
        # Track verified local route promotions: device_id -> diagnostics dict
        self._route_promotion_status: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _is_loopback_host(host: Optional[str]) -> bool:
        clean = (host or "").strip().lower()
        return clean in ("127.0.0.1", "::1", "localhost")

    def _with_transport_badge(
        self,
        res: dict[str, Any],
        transport: Optional[str] = None,
        host: Optional[str] = None,
        connection_mode: Optional[str] = None,
    ) -> dict[str, Any]:
        enriched = dict(res)
        if not enriched.get("transport_badge"):
            enriched["transport_badge"] = classify_transport_badge(
                transport=transport or enriched.get("transport"),
                host=host or enriched.get("last_known_endpoint"),
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
    ) -> dict[str, Any]:
        """Promote a paired peer from Remote Relay to a local USB or Wi-Fi LAN link.

        Strictly requires peer authentication and certificate fingerprint verification
        before claiming promotion, retaining the relay fallback if local verification fails.
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

        conn_mode = (getattr(paired_rec, "connection_mode", "auto") or "auto").strip().lower()
        if conn_mode == "remote_only":
            return {
                "promoted": False,
                "status": "POLICY_REMOTE_ONLY",
                "error": f"Local promotion blocked by 'remote_only' policy for '{clean_id}'.",
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

        target_transport = transport or ("usb_adb" if self._is_loopback_host(clean_host) else "wifi_lan")
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
                    status_rec = {
                        "promoted": True,
                        "status": "PROMOTED",
                        "device_id": clean_id,
                        "transport": target_transport,
                        "transport_badge": classify_transport_badge(transport=target_transport, host=clean_host),
                        "host": clean_host,
                        "port": int(port),
                        "promoted_at": time.time(),
                        "fallback_retained": True,
                    }
                    self._route_promotion_status[clean_id] = status_rec
                    return dict(status_rec)

        client = SnowPeerClient(
            host=clean_host,
            port=int(port),
            expected_fingerprint=effective_fp,
            use_tls=True,
        )
        try:
            dial_token = self.get_peer_token(clean_id)
            conn_res = await client.connect(auth_token=dial_token, timeout=dial_timeout)
            if not conn_res.success:
                try:
                    await client.close()
                except Exception:
                    pass
                return {
                    "promoted": False,
                    "status": conn_res.status or "LOCAL_PROBE_FAILED",
                    "error": conn_res.error or "Local handshake failed; keeping relay fallback.",
                    "fallback_retained": True,
                }
            if conn_res.remote_device_id and conn_res.remote_device_id != clean_id:
                try:
                    await client.close()
                except Exception:
                    pass
                return {
                    "promoted": False,
                    "status": "IDENTITY_MISMATCH",
                    "error": f"Expected device '{clean_id}', got '{conn_res.remote_device_id}'.",
                    "fallback_retained": True,
                }
        except Exception as exc:
            try:
                await client.close()
            except Exception:
                pass
            return {
                "promoted": False,
                "status": "LOCAL_PROBE_ERROR",
                "error": str(exc),
                "fallback_retained": True,
            }

        async with self._lock:
            old_client = self._outbound_clients.get(clean_id)
            self._outbound_clients[clean_id] = client
        if old_client is not None and old_client is not client:
            try:
                await old_client.close()
            except Exception:
                pass

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

        badge = classify_transport_badge(transport=target_transport, host=clean_host)
        status_rec = {
            "promoted": True,
            "status": "PROMOTED",
            "device_id": clean_id,
            "transport": target_transport,
            "transport_badge": badge,
            "host": clean_host,
            "port": int(port),
            "promoted_at": time.time(),
            "fallback_retained": True,
        }
        self._route_promotion_status[clean_id] = status_rec
        logger.info("Promoted route for [%s] to local %s (%s:%d)", clean_id, badge, clean_host, int(port))
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

        # Query persisted connection mode policy for target device
        paired_rec = self.db_manager.get_paired_device(device_id) if self.db_manager else None
        conn_mode = getattr(paired_rec, "connection_mode", "auto") if paired_rec else "auto"
        if not conn_mode:
            conn_mode = "auto"

        # Policy Rule: remote_only forces relay tunnel directly, bypassing local LAN/USB tiers
        if conn_mode == "remote_only":
            attempted_transports.append("remote_relay_tunnel")
            logger.info("Router Policy: 'remote_only' configured for [%s]. Skipping local tiers.", device_id)
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

            status_val = "RELAY_UNAVAILABLE" if not (self.relay_enabled and self.relay_client and getattr(self.relay_client, "_is_connected", False)) else "DEVICE_UNREACHABLE"
            return self._with_transport_badge({
                "success": False,
                "status": status_val,
                "error": f"Remote relay routing failed or is unavailable for device '{device_id}' (mode: remote_only).",
                "target_device_id": device_id,
                "attempted_transports": attempted_transports,
                "last_reachability_state": last_state,
                "last_known_endpoint": last_endpoint,
                "connection_mode": "remote_only",
            }, transport="remote_relay", connection_mode="remote_only")

        # =====================================================================
        # Tier 1: Hybrid Active Session Routing (USB > Wi-Fi LAN > Remote)
        # =====================================================================
        candidate_dispatches: list[tuple[int, str, Any]] = []
        if self.ws_server is not None:
            session = self.ws_server.session_manager.get_session_by_device(device_id)
            if session and session.connection_id:
                conn = self.ws_server.connection_manager.get(session.connection_id)
                if conn and conn.is_active:
                    sess_transport = (getattr(node, "transport", None) or "").strip().lower()
                    sess_host = (getattr(node, "host", None) or "").strip().lower()
                    if sess_transport == "usb_adb" or (self._is_loopback_host(sess_host) and "relay" not in sess_transport):
                        prio, label = 0, "active_inbound_wss"
                    elif "relay" in sess_transport or "remote" in sess_transport:
                        prio, label = 2, "active_inbound_wss"
                    else:
                        prio, label = 1, "active_inbound_wss"
                    candidate_dispatches.append((prio, label, ("inbound", session)))

        outbound_client = self._outbound_clients.get(device_id)
        if outbound_client is not None and outbound_client.is_connected:
            out_host = getattr(outbound_client, "host", None) or getattr(node, "host", None)
            if self._is_loopback_host(out_host):
                prio, label = 0, "active_outbound_peer"
            else:
                prio, label = 1, "active_outbound_peer"
            candidate_dispatches.append((prio, label, ("outbound", outbound_client)))

        candidate_dispatches.sort(key=lambda item: item[0])
        # Automatic Relay -> Local promotion check: if only Remote active routes exist, probe live local discovery candidate first
        if candidate_dispatches and all(prio == 2 for prio, _, _ in candidate_dispatches) and conn_mode != "remote_only":
            disc_peer = None
            if self.discovery_service is not None and hasattr(self.discovery_service, "get_discovered_peer"):
                try:
                    disc_peer = self.discovery_service.get_discovered_peer(device_id)
                except Exception:
                    disc_peer = None
            if disc_peer and getattr(disc_peer, "ip_address", None):
                attempted_transports.append("local_route_promotion")
                promo = await self.promote_local_route(
                    device_id=device_id,
                    host=disc_peer.ip_address,
                    port=getattr(disc_peer, "port", None) or 8765,
                    expected_fingerprint=getattr(disc_peer, "cert_fingerprint", None),
                )
                if promo.get("promoted") and device_id in self._outbound_clients:
                    promoted_client = self._outbound_clients[device_id]
                    candidate_dispatches.insert(0, (1, "promoted_local_peer", ("outbound", promoted_client)))

        for prio, label, (kind, handle) in candidate_dispatches:
            if prio == 2 and conn_mode == "local_only":
                continue
            attempted_transports.append(label)
            logger.debug(
                "Router Tier 1 (prio=%d): Dispatching '%s' to [%s] via %s",
                prio,
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
            badge_transport = "usb_adb" if prio == 0 else ("remote_relay" if prio == 2 else "wifi_lan")
            res["transport"] = badge_transport
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
            attempted_transports.append("outbound_direct")
            dial_host = node.host
            dial_port = node.wss_port or 8765

            if dial_host:
                logger.info(
                    "Router Tier 2: Outbound dialing [%s] at %s:%d (profile=%s)...",
                    device_id,
                    dial_host,
                    dial_port,
                    node.reachability_profile,
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
                    tr = "usb_adb" if self._is_loopback_host(dial_host) else "wifi_lan"
                    direct_res["transport"] = tr
                    direct_res = self._with_transport_badge(direct_res, transport=tr, host=dial_host)
                    if is_transfer_op and direct_res.get("success"):
                        self._record_transfer_route(device_id, transfer_id, direct_res)
                    return direct_res
            else:
                logger.debug("Router Tier 2 skipped: No known IP endpoint for [%s]", device_id)

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
                tr = "usb_adb" if self._is_loopback_host(getattr(node, "host", None)) else "wifi_lan"
                res["transport"] = tr
                res = self._with_transport_badge(res, transport=tr, host=getattr(node, "host", None))
                if is_transfer_op and res.get("success"):
                    self._record_transfer_route(device_id, transfer_id, res)
                return res

        # Policy Rule: local_only strictly forbids relay hops or remote tunnels
        if conn_mode == "local_only":
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
