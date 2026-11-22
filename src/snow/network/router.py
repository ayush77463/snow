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
    "ring_phone": "android.telemetry.get",
    "list_apps": "android.apps.list",
    "launch_app": "android.apps.launch",
    "send_message": "android.messaging.send_intent",
    "file_list": "android.files.transfer",
    "notifications_list": "android.notifications.push",
    "notification_dismiss": "android.notifications.push",
    "notification_reply": "android.notifications.push",
    "media_control": "android.ringer.ring",
    "share_link": "android.apps.launch",
    "android_screenshot": "android.media.projection",
    "snow_android_screenshot": "android.media.projection",
    "screen_stream_stop": "android.media.projection",
    "android_camera_capture": "android.camera.capture",
    "snow_android_camera_capture": "android.camera.capture",
    "clipboard_buffer_list": "desktop.clipboard.read",
    "clipboard_buffer_add": "desktop.clipboard.write",
    "clipboard_buffer_apply": "desktop.clipboard.write",
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
}

# Alias for backward-compatible routing lookups
ACTION_ROUTING = ROUTER_ACTION_TO_CAPABILITY


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
        self._lock = asyncio.Lock()

    def register_peer_token(self, device_id: str, token: str) -> None:
        """Register an authentication token for outbound direct dials to a peer."""
        self._peer_tokens[device_id] = token

    def get_peer_token(self, device_id: str) -> str:
        """Retrieve the outbound authentication token for a peer."""
        return self._peer_tokens.get(device_id, "")

    def register_outbound_client(self, device_id: str, client: SnowPeerClient) -> None:
        """Register an active outbound SnowPeerClient."""
        self._outbound_clients[device_id] = client

    async def route_request(
        self,
        action: str,
        target: Optional[str] = None,
        data: Optional[dict[str, Any]] = None,
        required_capability: Optional[str] = None,
        ctx: Optional[ExecutionContext] = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Resolve target, establish transport session if needed, and dispatch capability action.

        Args:
            action: Capability action identifier (e.g. 'android_battery', 'file_transfer_offer').
            target: Query string for device resolution (UUID, name, prefix, or None for default).
            data: Payload dictionary for the request.
            required_capability: Explicit capability string, or derived from action if omitted.
            ctx: Immutable execution context (defaults to AI_MCP for cross-device calls).
            timeout: Dispatch response timeout in seconds.

        Returns:
            Structured dictionary with success, status, data/error, and routing diagnostics.
        """
        # Ensure immutable execution context; remote cross-device requests default to AI_MCP
        effective_ctx = ctx or ExecutionContext(
            principal=ExecutionPrincipal.AI_MCP,
            origin="router_dispatch",
        )

        attempted_transports: list[str] = []

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

        # Clean payload: strip caller-supplied authority overrides
        clean_data = dict(data) if isinstance(data, dict) else {}
        clean_data.pop("principal", None)
        clean_data.pop("trust_tier", None)
        clean_data.pop("execution_principal", None)
        if action in ("file_list", "file_receive_request") and effective_ctx.principal == ExecutionPrincipal.OWNER_MANUAL:
            clean_data["principal"] = effective_ctx.principal.value

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
                    return relay_tunnel_res

            status_val = "RELAY_UNAVAILABLE" if not (self.relay_enabled and self.relay_client and getattr(self.relay_client, "_is_connected", False)) else "DEVICE_UNREACHABLE"
            return {
                "success": False,
                "status": status_val,
                "error": f"Remote relay routing failed or is unavailable for device '{device_id}' (mode: remote_only).",
                "target_device_id": device_id,
                "attempted_transports": attempted_transports,
                "last_reachability_state": last_state,
                "last_known_endpoint": last_endpoint,
                "connection_mode": "remote_only",
            }

        # =====================================================================
        # Tier 1: Active Session Routing
        # =====================================================================
        # Check 1A: Inbound active WebSocket session
        if self.ws_server is not None:
            session = self.ws_server.session_manager.get_session_by_device(device_id)
            if session and session.connection_id:
                conn = self.ws_server.connection_manager.get(session.connection_id)
                if conn and conn.is_active:
                    attempted_transports.append("active_inbound_wss")
                    logger.debug(
                        "Router Tier 1: Dispatching '%s' to [%s] via active inbound WSS session [%s]",
                        action,
                        device_id,
                        session.session_id,
                    )
                    return await self._dispatch_over_inbound_wss(
                        session.connection_id, action, clean_data, timeout, node, attempted_transports
                    )

        # Check 1B: Active outbound peer client session
        outbound_client = self._outbound_clients.get(device_id)
        if outbound_client is not None and outbound_client.is_connected:
            attempted_transports.append("active_outbound_peer")
            logger.debug(
                "Router Tier 1: Dispatching '%s' to [%s] via active outbound peer connection",
                action,
                device_id,
            )
            return await self._dispatch_over_peer_client(
                outbound_client, action, clean_data, timeout, node, attempted_transports
            )

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
                return await self._dispatch_over_inbound_wss(
                    reconnected_session.connection_id, action, clean_data, timeout, node, attempted_transports
                )

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
        # Tier 3.5: Authenticated Peer Relay
        # =====================================================================
        relay_res = await self._attempt_peer_relay(
            node=node,
            action=action,
            clean_data=clean_data,
            timeout=timeout,
            attempted_transports=attempted_transports,
        )
        if relay_res is not None:
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
    ) -> Optional[dict[str, Any]]:
        """Attempt to route request through an active intermediate peer (Tier 3.5)."""
        # 1. Check active outbound clients
        for peer_id, client in list(self._outbound_clients.items()):
            if peer_id == node.device_id or not client.is_connected:
                continue
            attempted_transports.append(f"relay_outbound:{peer_id}")
            try:
                relay_msg = SnowMessage.create_request(
                    action="peer_relay_request",
                    payload={
                        "target_device_id": node.device_id,
                        "action": action,
                        "data": clean_data,
                        "hop_limit": 2,
                        "visited_nodes": [],
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
                if sess.device_id == node.device_id or not sess.connection_id:
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
                            "hop_limit": 2,
                            "visited_nodes": [],
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
