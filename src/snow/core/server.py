"""Asynchronous core server lifecycle for SNOW."""

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, List, Optional

from snow.capabilities.engine import CapabilityEngine
from snow.capabilities.windows import (
    WindowsAppLauncher,
    WindowsClipboardManager,
    WindowsFileManager,
    WindowsProcessMonitor,
    WindowsTelemetry,
    WindowsTerminalExecutor,
)
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.core.network import NetworkInterfaceInfo, detect_usable_ipv4_addresses
from snow.core.usb import UsbWatcher
from snow.network.connection_manager import ConnectionManager
from snow.network.discovery import SnowDiscoveryService
from snow.network.registry import NodeRegistry
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.security.policy import PeerCapabilityPolicy
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferManager
from snow.transfer.storage import (
    TransferStorageManager,
    get_default_pc_transfer_dir,
    resolve_configured_pc_transfer_dir,
)

logger = logging.getLogger(__name__)


class SnowCoreServer:
    """Headless asynchronous core server for SNOW.

    Coordinates the core lifecycle: configuration loading, network interface
    enumeration, WebSocket server hosting, and graceful shutdown.
    """

    def __init__(
        self,
        config: Optional[CoreConfig] = None,
        db_manager: Optional[DatabaseManager] = None,
        device_identity: Optional[DeviceIdentity] = None,
    ) -> None:
        self.config = config or CoreConfig.from_env()
        self._is_running = False
        self._shutdown_event = asyncio.Event()
        self._detected_interfaces: List[NetworkInterfaceInfo] = []
        self.connection_manager = ConnectionManager()
        self.transfer_manager = TransferManager()
        self.storage_manager = TransferStorageManager(root_dir=self.config.transfer_root)
        self._maintenance_task: Optional[asyncio.Task] = None
        self.ws_server = SnowWebSocketServer(
            config=self.config,
            connection_manager=self.connection_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
            db_manager=db_manager,
            device_identity=device_identity,
        )
        self.http_transfer_server: Optional[SnowHttpTransferServer] = None
        self.windows_telemetry = WindowsTelemetry()
        self.windows_processes = WindowsProcessMonitor()
        roots = [self.config.transfer_root] if self.config.transfer_root else None
        self.windows_files = WindowsFileManager(allowed_roots=roots)
        self.windows_apps = WindowsAppLauncher()
        self.windows_terminal = WindowsTerminalExecutor()
        self.windows_clipboard = WindowsClipboardManager()
        data_dir = os.environ.get("SNOW_DATA_DIR")
        base_dir = Path(data_dir).resolve() if data_dir else Path.home() / ".snow"
        self.capability_policy = PeerCapabilityPolicy(policy_file=base_dir / "peer_policy.json")
        self.capability_engine = CapabilityEngine(
            telemetry=self.windows_telemetry,
            processes=self.windows_processes,
            files=self.windows_files,
            apps=self.windows_apps,
            terminal=self.windows_terminal,
            clipboard=self.windows_clipboard,
            policy=self.capability_policy,
            db_manager=self.db_manager,
        )
        self.ws_server.core_server = self
        self.ws_server.windows_telemetry = self.windows_telemetry
        self.ws_server.windows_processes = self.windows_processes
        self.ws_server.windows_files = self.windows_files
        self.ws_server.windows_apps = self.windows_apps
        self.ws_server.windows_terminal = self.windows_terminal
        self.ws_server.windows_clipboard = self.windows_clipboard
        self.ws_server.capability_policy = self.capability_policy
        self.ws_server.capability_engine = self.capability_engine
        self.clipboard_buffer = self.capability_engine.clipboard_buffer
        self.ws_server.clipboard_buffer = self.capability_engine.clipboard_buffer
        self.node_registry = NodeRegistry(
            db_manager=self.db_manager,
            connection_manager=self.ws_server.connection_manager,
            local_identity=self.device_identity,
            port=self.config.port,
            transfer_port=self.config.transfer_port,
        )
        self.ws_server.node_registry = self.node_registry
        self.capability_engine.node_registry = self.node_registry
        self.capability_engine.db_manager = self.db_manager
        self.capability_engine.transfer_manager = self.transfer_manager
        self.capability_engine.storage_manager = self.storage_manager
        self.capability_engine.http_transfer_server = self.http_transfer_server
        self.capability_engine.core_server = self

        configured_root = resolve_configured_pc_transfer_dir(
            db_manager=self.db_manager,
            explicit_root=self.config.transfer_root,
        )
        try:
            self.storage_manager.set_root_dir(configured_root)
        except Exception as exc:
            logger.warning(
                "Invalid configured PC transfer directory '%s'; falling back to default: %s",
                configured_root,
                exc,
            )
            self.storage_manager.set_root_dir(get_default_pc_transfer_dir())
        if hasattr(self.windows_files, "add_allowed_root"):
            self.windows_files.add_allowed_root(self.storage_manager.root_dir)

        from snow.network.router import SessionRouter

        self.session_router = SessionRouter(
            node_registry=self.node_registry,
            ws_server=self.ws_server,
            discovery_service=None,
            capability_engine=self.capability_engine,
            db_manager=self.db_manager,
            wake_grace_period=getattr(self.config, "device_connect_grace_period", 6.0),
        )
        self.capability_engine.session_router = self.session_router

        # Attach approval notification broadcast listener to approval engine
        app_engine = getattr(self.capability_engine, "approval_engine", None)
        if app_engine and hasattr(app_engine, "add_listener"):
            def _approval_event_listener(event_type: str, data: dict) -> None:
                if self.ws_server and hasattr(self.ws_server, "broadcast_approval_event"):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(self.ws_server.broadcast_approval_event(event_type, data))
                    except RuntimeError:
                        pass
            app_engine.add_listener(_approval_event_listener)

        self.ipc_server: SnowIpcServer = SnowIpcServer(core_server=self, config=self.config)
        self.ipc_server.capability_engine = self.capability_engine
        self.ipc_server.node_registry = self.node_registry
        self.ipc_server.session_router = self.session_router
        self.discovery_service: Optional[SnowDiscoveryService] = None

        from snow.network.network_model import SnowNetworkManager
        self.network_manager = SnowNetworkManager(
            db_manager=self.db_manager,
            local_identity=self.device_identity,
            node_registry=self.node_registry,
        )
        self.peer_clients: dict[str, Any] = {}
        self.usb_watcher = UsbWatcher(port=self.config.port)
        self.relay_client: Optional[Any] = None
        self.relay_enabled: bool = getattr(self.config, "relay_enabled", False)
        self.relay_url: str = getattr(self.config, "relay_url", "")
        self.relay_group_id: str = getattr(self.config, "relay_group_id", "")
        self.relay_ticket: str = getattr(self.config, "relay_ticket", "")
        self.session_router.relay_enabled = self.relay_enabled
        self.screen_stream_manager: Optional[Any] = None
        self._is_paused: bool = False
        self._paused_state: dict[str, Any] = {}

    def _ensure_screen_stream_manager(self):
        """Lazily initialize the PC WindowsScreenStreamManager without loading Pillow at startup."""
        if self.screen_stream_manager is not None:
            return self.screen_stream_manager
        from snow.capabilities.windows.screen_stream import WindowsScreenStreamManager

        local_id = getattr(self.device_identity, "device_id", None) or "desktop-core"
        local_name = getattr(self.device_identity, "device_name", None) or "Windows PC"
        network_id = getattr(self.config, "network_id", None)

        def _is_full_control(dev_id: str) -> bool:
            if not dev_id:
                return False
            if dev_id == "local_dashboard" or dev_id == local_id:
                return True
            if self.db_manager:
                saved = self.db_manager.get_setting(f"device_profile:{dev_id}")
                if saved is not None and str(saved).strip().lower() != "full_control":
                    return False
                paired = self.db_manager.get_paired_device(dev_id)
                if paired is not None:
                    return True
            node = self.node_registry.get_node(dev_id) if getattr(self, "node_registry", None) else None
            if node is not None and getattr(node, "permission_profile", None) is not None:
                return str(node.permission_profile).strip().lower() == "full_control"
            # Check active full_control federation grant
            fed = getattr(self.ws_server, "federation_manager", None) if getattr(self, "ws_server", None) else None
            if fed is not None and hasattr(fed, "has_active_full_control_grant"):
                try:
                    return bool(fed.has_active_full_control_grant(dev_id))
                except Exception:
                    return False
            return node is not None

        self.screen_stream_manager = WindowsScreenStreamManager(
            sender_device_id=local_id,
            sender_name=local_name,
            sender_network_id=network_id,
            transfer_server=self.http_transfer_server,
            permission_checker=_is_full_control,
            on_frame_ready=self._on_pc_screen_frame_ready,
            on_state_change=self._on_pc_screen_state_change,
        )
        if getattr(self, "ws_server", None):
            self.ws_server.screen_stream_manager = self.screen_stream_manager
        if getattr(self, "http_transfer_server", None):
            self.http_transfer_server.screen_stream_manager = self.screen_stream_manager
        return self.screen_stream_manager

    def list_eligible_screen_targets(self) -> list[dict[str, Any]]:
        """List currently connected, paired/federated, and Full Control authorized targets for PC sharing."""
        eligible: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        local_id = getattr(self.device_identity, "device_id", None) or "desktop-core"

        def _profile_for(dev_id: str) -> str:
            if self.db_manager:
                saved = self.db_manager.get_setting(f"device_profile:{dev_id}")
                if saved is not None:
                    return str(saved).strip().lower()
            node = self.node_registry.get_node(dev_id) if getattr(self, "node_registry", None) else None
            if node and getattr(node, "permission_profile", None):
                return str(node.permission_profile).strip().lower()
            return "full_control"

        # 1. Inbound connected sessions (Android USB/Wi-Fi or remote inbound)
        sess_mgr = getattr(self, "session_manager", None) or getattr(self.ws_server, "session_manager", None)
        conn_mgr = getattr(self, "connection_manager", None) or getattr(self.ws_server, "connection_manager", None)
        if sess_mgr and conn_mgr:
            for s in sess_mgr.all_sessions() if hasattr(sess_mgr, "all_sessions") else []:
                did = getattr(s, "device_id", None)
                cid = getattr(s, "connection_id", None)
                if not did or did == local_id or did in seen_ids:
                    continue
                conn = conn_mgr.get(cid) if cid else None
                if not conn or not getattr(conn, "is_active", False):
                    continue
                if _profile_for(did) != "full_control":
                    continue
                node = self.node_registry.get_node(did) if getattr(self, "node_registry", None) else None
                paired = self.db_manager.get_paired_device(did) if self.db_manager else None
                from snow.network.router import classify_transport_badge
                tr = getattr(node, "transport", None) or "wifi_lan"
                host = getattr(node, "host", None) or getattr(paired, "last_known_host", None)
                badge = classify_transport_badge(transport=tr, host=host)
                eligible.append({
                    "device_id": did,
                    "device_name": (getattr(paired, "device_name", None) or getattr(node, "device_name", None) or did),
                    "platform": (getattr(paired, "platform", None) or getattr(node, "platform", None) or "android"),
                    "route_badge": badge,
                    "transport": tr,
                    "permission_profile": "full_control",
                    "online": True,
                })
                seen_ids.add(did)

        # 2. Outbound connected peer PCs
        for did, client in list(getattr(self, "peer_clients", {}).items()):
            if not did or did == local_id or did in seen_ids or not getattr(client, "is_connected", False):
                continue
            if _profile_for(did) != "full_control":
                continue
            paired = self.db_manager.get_paired_device(did) if self.db_manager else None
            from snow.network.router import classify_transport_badge
            host = getattr(client, "host", None)
            badge = classify_transport_badge(transport="wifi_lan", host=host)
            eligible.append({
                "device_id": did,
                "device_name": getattr(paired, "device_name", None) or getattr(client, "remote_device_name", None) or did,
                "platform": getattr(paired, "platform", None) or "windows",
                "route_badge": badge,
                "transport": "peer_link",
                "permission_profile": "full_control",
                "online": True,
            })
            seen_ids.add(did)

        # 3. Relay-connected paired peers when E2E relay is active
        if self.relay_enabled and self.relay_client and getattr(self.relay_client, "_is_connected", False) and self.db_manager:
            for p in self.db_manager.list_paired_devices():
                did = p.device_id
                if did == local_id or did in seen_ids or _profile_for(did) != "full_control":
                    continue
                tun = getattr(self.relay_client, "_tunnels", {}).get(did)
                if tun is not None and getattr(tun, "handshake_done", False):
                    eligible.append({
                        "device_id": did,
                        "device_name": p.device_name or did,
                        "platform": p.platform or "android",
                        "route_badge": "Remote • Uses Data",
                        "transport": "remote_relay",
                        "permission_profile": "full_control",
                        "online": True,
                    })
                    seen_ids.add(did)

        return eligible

    def get_pc_screen_share_status(self) -> dict[str, Any]:
        """Return current local PC live screen share state."""
        if self.screen_stream_manager is None:
            return {"state": "IDLE", "target_device_ids": [], "viewer_count": 0}
        return self.screen_stream_manager.get_status()

    async def start_pc_screen_share(
        self,
        target_device_ids: list[str],
        fps: float = 4.0,
    ) -> dict[str, Any]:
        """Start sharing this PC's screen to explicit Full Control target devices."""
        if not target_device_ids:
            return {
                "success": False,
                "status": "NO_TARGETS_SELECTED",
                "error": "Select at least one connected Full Control device to share with.",
            }
        mgr = self._ensure_screen_stream_manager()
        if getattr(self, "http_transfer_server", None):
            mgr.transfer_server = self.http_transfer_server
            self.http_transfer_server.screen_stream_manager = mgr
        # Pre-register connected target devices as authorized initial viewers; targets can unsubscribe cleanly
        connected_ids = {t["device_id"] for t in self.list_eligible_screen_targets()}
        valid_targets = [tid for tid in target_device_ids if tid in connected_ids]
        if not valid_targets:
            return {
                "success": False,
                "status": "NO_ELIGIBLE_TARGETS",
                "error": "No connected Full Control target device matched the selection.",
            }
        res = await mgr.start(
            target_device_ids=valid_targets,
            fps=fps,
            initial_viewers=valid_targets,
        )
        return res

    async def stop_pc_screen_share(self, reason: str = "STOPPED") -> dict[str, Any]:
        """Stop local PC screen share cleanly."""
        if self.screen_stream_manager is None:
            return {"success": True, "status": "IDLE", "state": "IDLE"}
        return await self.screen_stream_manager.stop(reason=reason)

    async def revoke_screen_target(self, device_id: str) -> None:
        """Immediately remove a downgraded/revoked device from PC live sharing and stop if empty."""
        mgr = getattr(self, "screen_stream_manager", None)
        if mgr is not None and mgr.state == "STREAMING":
            mgr.revoke_target(device_id)
            if not mgr.target_device_ids or mgr.active_viewer_count() == 0:
                await mgr.stop(reason="REVOKED")
            elif getattr(self, "ws_server", None):
                await self.ws_server.broadcast_screen_stream_event(
                    "STREAM_STOPPED",
                    {"sender_device_id": mgr.sender_device_id, "reason": "PERMISSION_REVOKED"},
                    target_device_ids=[device_id],
                )

    @staticmethod
    async def execute_device_removal(
        *,
        device_id: str,
        reason: str = "Revoked by desktop owner",
        notify_client: bool = True,
        exclude_connection_id: Optional[str] = None,
        db_manager: Any = None,
        session_manager: Any = None,
        connection_manager: Any = None,
        node_registry: Any = None,
        ws_server: Any = None,
        core_server: Any = None,
        discovery_service: Any = None,
        relay_client: Any = None,
        session_router: Any = None,
        peer_clients: Optional[dict[str, Any]] = None,
        http_transfer_server: Any = None,
        screen_stream_manager: Any = None,
        audit_event_type: Optional[str] = "DEVICE_REVOKED",
        audit_details: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Consolidated, idempotent, fail-closed device removal across persistence and runtime state.

        Ordering invariant:
          1. Snapshot active targets for best-effort revocation notifications and check runtime presence.
          2. First revoke persistent DB credentials, permission profiles, and active sessions so a
             failing secondary cleanup step can never leave a revoked device authorized.
          3. Independently execute each secondary runtime cleanup step in isolation.
        """
        import inspect

        clean_id = (device_id or "").strip()
        if not clean_id:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "device_id": clean_id,
                "removed": False,
                "already_removed": True,
                "revoked": False,
                "error": "Missing 'device_id'.",
                "cleanup_errors": [],
            }

        local_ident = getattr(core_server, "device_identity", None) or getattr(ws_server, "device_identity", None)
        local_dev_id = getattr(local_ident, "device_id", None)
        if isinstance(local_dev_id, str) and clean_id == local_dev_id:
            return {
                "success": False,
                "status": "FORBIDDEN",
                "device_id": clean_id,
                "removed": False,
                "already_removed": False,
                "revoked": False,
                "error": "Cannot remove the local desktop host identity.",
                "cleanup_errors": [],
            }

        cleanup_errors: list[str] = []

        # Collect active sessions and WebSocket connections for clean shutdown before invalidation
        matched_sessions: list[Any] = []
        seen_session_ids: set[str] = set()
        if session_manager is not None:
            try:
                primary_sess = session_manager.get_session_by_device(clean_id)
                # Treat single-session lookup carefully for MagicMock compatibility in unit tests
                if primary_sess is not None:
                    sid = getattr(primary_sess, "session_id", None)
                    if sid is not None:
                        matched_sessions.append(primary_sess)
                        if isinstance(sid, str):
                            seen_session_ids.add(sid)
            except Exception as exc:
                cleanup_errors.append(f"snapshot_primary_session: {exc}")
                logger.warning("Device removal snapshot failed for [%s] (primary_session): %s", clean_id, exc)
            try:
                list_fn = getattr(session_manager, "list_active_sessions", None)
                if callable(list_fn):
                    all_sess = list_fn()
                    if isinstance(all_sess, (list, tuple, set)):
                        for s in all_sess:
                            if getattr(s, "device_id", None) == clean_id:
                                sid = getattr(s, "session_id", None)
                                if not isinstance(sid, str) or sid not in seen_session_ids:
                                    matched_sessions.append(s)
                                    if isinstance(sid, str):
                                        seen_session_ids.add(sid)
            except Exception as exc:
                cleanup_errors.append(f"snapshot_sessions: {exc}")
                logger.warning("Device removal snapshot failed for [%s] (list_active_sessions): %s", clean_id, exc)

        target_conn_ids: list[str] = []
        for s in matched_sessions:
            cid = getattr(s, "connection_id", None)
            if isinstance(cid, str) and cid and cid not in target_conn_ids:
                target_conn_ids.append(cid)

        # Detect orphan runtime state cleanly (preserving MagicMock test safety)
        ws_manual_set = getattr(ws_server, "manually_disconnected_devices", None)
        ws_notifs = getattr(ws_server, "live_notifications", None)
        ws_pairing = getattr(ws_server, "_pairing_in_progress", None)
        router_outbound = getattr(session_router, "_outbound_clients", None)
        router_tokens = getattr(session_router, "_peer_tokens", None)

        relay_clients: list[Any] = []
        seen_relay_ids: set[int] = set()
        for rc in (relay_client, getattr(session_router, "relay_client", None)):
            if rc is not None and id(rc) not in seen_relay_ids:
                close_fn = getattr(rc, "close_tunnel", None)
                # Guard against unconfigured bare MagicMock child attributes while supporting explicit AsyncMock/RelayTunnelClient
                has_real_tunnels = isinstance(getattr(rc, "_tunnels", None), dict)
                has_explicit_close = callable(close_fn) and (
                    inspect.iscoroutinefunction(close_fn) or has_real_tunnels
                )
                if has_explicit_close:
                    relay_clients.append(rc)
                    seen_relay_ids.add(id(rc))

        registries: list[Any] = []
        seen_reg_ids: set[int] = set()
        for reg in (node_registry, getattr(ws_server, "node_registry", None)):
            if reg is not None and id(reg) not in seen_reg_ids and callable(getattr(reg, "remove_node", None)):
                registries.append(reg)
                seen_reg_ids.add(id(reg))

        discoveries: list[Any] = []
        seen_disc_ids: set[int] = set()
        candidates_disc = [
            discovery_service,
            getattr(ws_server, "udp_discovery", None),
            *(getattr(r, "discovery_service", None) for r in registries),
        ]
        for ds in candidates_disc:
            if ds is not None and id(ds) not in seen_disc_ids and isinstance(getattr(ds, "_discovered_peers", None), dict):
                discoveries.append(ds)
                seen_disc_ids.add(id(ds))

        had_runtime = bool(matched_sessions)
        if isinstance(peer_clients, dict) and clean_id in peer_clients:
            had_runtime = True
        if isinstance(ws_manual_set, set) and clean_id in ws_manual_set:
            had_runtime = True
        if isinstance(ws_notifs, dict) and clean_id in ws_notifs:
            had_runtime = True
        if isinstance(router_outbound, dict) and clean_id in router_outbound:
            had_runtime = True
        if isinstance(router_tokens, dict) and clean_id in router_tokens:
            had_runtime = True
        for rc in relay_clients:
            if any(
                isinstance(getattr(rc, attr, None), dict) and clean_id in getattr(rc, attr)
                for attr in ("_tunnels", "_pinned_fingerprints", "_peer_cert_paths", "_incoming_queues", "_handshake_events")
            ):
                had_runtime = True
        for reg in registries:
            if any(
                isinstance(getattr(reg, attr, None), dict) and clean_id in getattr(reg, attr)
                for attr in ("_registered_nodes", "_active_sessions", "_discovered_candidates", "_manifest_cache", "_permission_profiles")
            ):
                had_runtime = True
        for ds in discoveries:
            if clean_id in ds._discovered_peers:
                had_runtime = True
        if screen_stream_manager is not None:
            t_ids = getattr(screen_stream_manager, "target_device_ids", None)
            s_viewers = getattr(screen_stream_manager, "subscribed_viewers", None)
            if (isinstance(t_ids, (list, set, tuple)) and clean_id in t_ids) or (
                isinstance(s_viewers, (list, set, tuple)) and clean_id in s_viewers
            ):
                had_runtime = True

        # Check HTTP transfer stream registry cleanly
        try:
            from snow.transfer.http_server import SnowHttpTransferServer

            http_streams = getattr(SnowHttpTransferServer, "_screen_sessions", None)
            if isinstance(http_streams, dict):
                if clean_id in http_streams or any(
                    isinstance(sess, dict) and clean_id in (sess.get("target_device_ids") or [])
                    for sess in http_streams.values()
                ):
                    had_runtime = True
            had_db_profile = False
            if db_manager is not None and callable(getattr(db_manager, "get_setting", None)):
                prof_val = db_manager.get_setting(f"device_profile:{clean_id}")
                if isinstance(prof_val, str) and prof_val:
                    had_db_profile = True
                    had_runtime = True
        except Exception as exc:
            logger.debug("Runtime presence check note for [%s]: %s", clean_id, exc)

        # Snapshot inbound WebSocket client objects before unregistering connections
        ws_clients_to_close: list[tuple[Optional[str], Any]] = []
        if connection_manager is not None:
            for cid in target_conn_ids:
                if exclude_connection_id and cid == exclude_connection_id:
                    continue
                try:
                    cli = connection_manager.get(cid)
                    ws_clients_to_close.append((cid, cli))
                except Exception as exc:
                    cleanup_errors.append(f"lookup_ws_client: {exc}")
                    ws_clients_to_close.append((cid, None))

        # =====================================================================
        # PHASE 1: Revoke authorization FIRST (DB credentials, profile, sessions)
        # =====================================================================
        db_deleted = False
        if db_manager is not None:
            try:
                db_deleted = bool(db_manager.delete_paired_device(clean_id))
            except Exception as exc:
                cleanup_errors.append(f"db_delete_paired_device: {exc}")
                logger.error("Failed deleting DB record during device removal for [%s]: %s", clean_id, exc)
            try:
                del_setting = getattr(db_manager, "delete_setting", None)
                if callable(del_setting):
                    del_setting(f"device_profile:{clean_id}")
            except Exception as exc:
                cleanup_errors.append(f"db_delete_device_profile: {exc}")
                logger.warning("Failed deleting permission profile for [%s]: %s", clean_id, exc)

        if session_manager is not None:
            for s in matched_sessions:
                sid = getattr(s, "session_id", None)
                if sid:
                    try:
                        session_manager.revoke_session(sid)
                    except Exception as exc:
                        cleanup_errors.append(f"revoke_session: {exc}")
                        logger.warning("Failed revoking session for [%s]: %s", clean_id, exc)
            try:
                rev_dev = getattr(session_manager, "revoke_device_sessions", None)
                if callable(rev_dev):
                    rev_dev(clean_id)
            except Exception as exc:
                cleanup_errors.append(f"revoke_device_sessions: {exc}")
                logger.warning("Failed revoking device sessions for [%s]: %s", clean_id, exc)

        # =====================================================================
        # PHASE 2: Isolated best-effort runtime & transport cleanup
        # =====================================================================
        # 1. Best-effort device_revoked notification
        if notify_client and ws_clients_to_close:
            try:
                from snow.protocol.models import SnowMessage
                revoke_msg_json = SnowMessage.create_request(
                    action="device_revoked",
                    data={"device_id": clean_id, "reason": reason},
                ).to_json()
            except Exception as exc:
                revoke_msg_json = None
                cleanup_errors.append(f"build_device_revoked_msg: {exc}")
            if revoke_msg_json:
                for cid, cli in ws_clients_to_close:
                    ws_obj = getattr(cli, "websocket", None) if cli is not None else None
                    if ws_obj is None:
                        continue
                    try:
                        send_res = ws_obj.send(revoke_msg_json)
                        if inspect.isawaitable(send_res):
                            await asyncio.wait_for(send_res, timeout=1.5)
                    except Exception as exc:
                        cleanup_errors.append(f"notify_client: {exc}")
                        logger.warning("Best-effort device_revoked notify failed for [%s]: %s", clean_id, exc)

        # 3. Revoke active PC screen-sharing authorization
        try:
            revoke_screen_fn = getattr(core_server, "revoke_screen_target", None)
            if callable(revoke_screen_fn):
                r_res = revoke_screen_fn(clean_id)
                if inspect.isawaitable(r_res):
                    await r_res
            elif screen_stream_manager is not None and callable(getattr(screen_stream_manager, "revoke_target", None)):
                screen_stream_manager.revoke_target(clean_id)
        except Exception as exc:
            cleanup_errors.append(f"revoke_screen_target: {exc}")
            logger.warning("Failed revoking screen-sharing target [%s]: %s", clean_id, exc)

        # 4. Revoke active HTTP transfer screen/file stream targets
        try:
            from snow.transfer.http_server import SnowHttpTransferServer

            SnowHttpTransferServer.revoke_target_from_streams(clean_id)
        except Exception as exc:
            cleanup_errors.append(f"revoke_http_streams: {exc}")
            logger.warning("Failed revoking HTTP stream state for [%s]: %s", clean_id, exc)

        # 5 & 6. Unregister from connection_manager & close active WebSocket connection(s)
        if connection_manager is not None:
            for cid, cli in ws_clients_to_close:
                if not cid:
                    continue
                unreg_client = None
                try:
                    unreg_client = connection_manager.unregister(cid)
                except Exception as exc:
                    cleanup_errors.append(f"unregister_connection: {exc}")
                    logger.warning("Failed unregistering connection [%s] for [%s]: %s", cid, clean_id, exc)
                close_target = unreg_client or cli
                ws_obj = getattr(close_target, "websocket", None) if close_target is not None else None
                if ws_obj is not None:
                    try:
                        close_res = ws_obj.close(code=1000, reason=reason)
                        if inspect.isawaitable(close_res):
                            await close_res
                    except Exception as exc:
                        cleanup_errors.append(f"close_websocket: {exc}")
                        logger.warning("Failed closing WebSocket [%s] for [%s]: %s", cid, clean_id, exc)

        # 7. Close outbound peer_clients (on CoreServer & SessionRouter) & drop cached peer tokens
        if isinstance(peer_clients, dict) and clean_id in peer_clients:
            p_cli = peer_clients.pop(clean_id, None)
            if p_cli is not None:
                try:
                    c_res = p_cli.close()
                    if inspect.isawaitable(c_res):
                        await c_res
                except Exception as exc:
                    cleanup_errors.append(f"close_peer_client: {exc}")
                    logger.warning("Failed closing peer_client for [%s]: %s", clean_id, exc)

        if isinstance(router_tokens, dict):
            try:
                router_tokens.pop(clean_id, None)
            except Exception as exc:
                cleanup_errors.append(f"clear_router_token: {exc}")
        if isinstance(router_outbound, dict) and clean_id in router_outbound:
            r_cli = router_outbound.pop(clean_id, None)
            if r_cli is not None:
                try:
                    c_res = r_cli.close()
                    if inspect.isawaitable(c_res):
                        await c_res
                except Exception as exc:
                    cleanup_errors.append(f"close_router_outbound: {exc}")
                    logger.warning("Failed closing SessionRouter outbound client for [%s]: %s", clean_id, exc)

        # 8. Close relay tunnel via relay_client.close_tunnel(clean_id)
        for rc in relay_clients:
            try:
                c_res = rc.close_tunnel(clean_id)
                if inspect.isawaitable(c_res):
                    await c_res
            except Exception as exc:
                cleanup_errors.append(f"close_relay_tunnel: {exc}")
                logger.warning("Failed closing relay tunnel for [%s]: %s", clean_id, exc)

        # 9. Remove device from NodeRegistry(s)
        for reg in registries:
            try:
                reg.remove_node(clean_id)
            except Exception as exc:
                cleanup_errors.append(f"remove_node_registry: {exc}")
                logger.warning("Failed removing [%s] from NodeRegistry: %s", clean_id, exc)

        # 10. Remove from manually_disconnected_devices
        if isinstance(ws_manual_set, set):
            try:
                ws_manual_set.discard(clean_id)
            except Exception as exc:
                cleanup_errors.append(f"clear_manual_disconnect: {exc}")

        # 11. Remove device-specific entries from live_notifications
        if isinstance(ws_notifs, dict):
            try:
                ws_notifs.pop(clean_id, None)
            except Exception as exc:
                cleanup_errors.append(f"clear_live_notifications: {exc}")

        # 12 & 13. Purge discovery service cache & remaining orphan runtime state
        for ds in discoveries:
            try:
                if callable(getattr(ds, "remove_peer", None)):
                    ds.remove_peer(clean_id)
                elif isinstance(getattr(ds, "_discovered_peers", None), dict):
                    ds._discovered_peers.pop(clean_id, None)
            except Exception as exc:
                cleanup_errors.append(f"purge_discovery_cache: {exc}")
                logger.warning("Failed purging discovery cache for [%s]: %s", clean_id, exc)

        if isinstance(ws_pairing, set) and target_conn_ids:
            for cid in target_conn_ids:
                if cid != exclude_connection_id:
                    ws_pairing.discard(cid)

        removed = bool(db_deleted or had_runtime)
        already_removed = not removed

        if removed and audit_event_type and db_manager is not None:
            try:
                details_payload = dict(audit_details or {})
                details_payload.setdefault("reason", reason)
                details_payload["db_deleted"] = db_deleted
                details_payload["runtime_cleaned"] = had_runtime
                if cleanup_errors:
                    details_payload["cleanup_error_count"] = len(cleanup_errors)
                db_manager.log_audit_event(
                    event_type=audit_event_type,
                    device_id=clean_id,
                    details=details_payload,
                )
            except Exception as exc:
                cleanup_errors.append(f"log_audit_event: {exc}")
                logger.warning("Failed logging revocation audit event for [%s]: %s", clean_id, exc)

        return {
            "success": removed,
            "status": "SUCCESS" if removed else "DEVICE_NOT_FOUND",
            "device_id": clean_id,
            "removed": removed,
            "already_removed": already_removed,
            "revoked": removed,
            "db_deleted": db_deleted,
            "runtime_cleaned": had_runtime,
            "cleanup_errors": cleanup_errors,
            "error": None if removed else f"Device [{clean_id}] not found in paired database or runtime state.",
        }

    async def remove_device_everywhere(
        self,
        device_id: str,
        reason: str = "Revoked by desktop owner",
        notify_client: bool = True,
        *,
        exclude_connection_id: Optional[str] = None,
        audit_event_type: Optional[str] = "DEVICE_REVOKED",
        audit_details: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Remove a device across SQLite persistence, auth/session state, transports, and discovery caches."""
        ws = getattr(self, "ws_server", None)
        return await SnowCoreServer.execute_device_removal(
            device_id=device_id,
            reason=reason,
            notify_client=notify_client,
            exclude_connection_id=exclude_connection_id,
            db_manager=self.db_manager,
            session_manager=self.session_manager,
            connection_manager=getattr(self, "connection_manager", None) or getattr(ws, "connection_manager", None),
            node_registry=getattr(self, "node_registry", None),
            ws_server=ws,
            core_server=self,
            discovery_service=getattr(self, "discovery_service", None),
            relay_client=getattr(self, "relay_client", None),
            session_router=getattr(self, "session_router", None),
            peer_clients=getattr(self, "peer_clients", None),
            http_transfer_server=getattr(self, "http_transfer_server", None),
            screen_stream_manager=getattr(self, "screen_stream_manager", None),
            audit_event_type=audit_event_type,
            audit_details=audit_details,
        )

    async def _on_pc_screen_state_change(self, status_meta: dict[str, Any]) -> None:
        """Broadcast metadata-only PC screen stream start/stop events across WSS and E2E Relay."""
        ev_type = "STREAM_AVAILABLE" if status_meta.get("state") == "STREAMING" else "STREAM_STOPPED"
        targets = list(status_meta.get("target_device_ids") or [])
        transfer_port = (
            getattr(self.http_transfer_server, "bound_port", None)
            or getattr(self.config, "transfer_port", 8766)
        )
        payload = {
            **status_meta,
            "transfer_port": transfer_port,
        }
        if getattr(self, "ws_server", None):
            await self.ws_server.broadcast_screen_stream_event(
                ev_type,
                payload,
                target_device_ids=targets if targets else None,
            )
        if self.relay_enabled and self.relay_client and getattr(self.relay_client, "_is_connected", False):
            for tid in targets:
                if tid in getattr(self.relay_client, "_tunnels", {}):
                    try:
                        await self.relay_client.send_message(
                            tid,
                            SnowMessage.create_request(
                                action="screen_stream_event",
                                data={"event_type": ev_type, **payload},
                            ),
                        )
                    except Exception as exc:
                        logger.debug("Relay screen event notify failed for [%s]: %s", tid, exc)

    async def _on_pc_screen_frame_ready(self, meta: dict[str, Any], jpeg_bytes: bytes) -> None:
        """Deliver bounded PC JPEG frames to E2E Relay and peer PC HTTPS targets (WSS stays media-free)."""
        targets = list(meta.get("target_device_ids") or [])
        if not targets:
            return
        local_sessions = getattr(self.ws_server, "session_manager", None) if getattr(self, "ws_server", None) else None
        for tid in targets:
            # Verify Full Control permission remains intact on every delivery cycle
            saved = self.db_manager.get_setting(f"device_profile:{tid}") if self.db_manager else None
            if saved is not None and str(saved).strip().lower() != "full_control":
                continue
            # If peer PC connected via outbound SnowPeerClient, push over its HTTPS transfer server
            peer_client = getattr(self, "peer_clients", {}).get(tid)
            if peer_client is not None and getattr(peer_client, "is_connected", False):
                asyncio.create_task(self._push_frame_to_peer_https(tid, peer_client, meta, jpeg_bytes))
                continue
            # If target has no local inbound WSS connection and E2E Relay tunnel is active, push over E2E Relay media plane
            has_local_wss = False
            if local_sessions:
                sess = local_sessions.get_session_by_device(tid)
                conn_mgr = getattr(self.ws_server, "connection_manager", None)
                if sess and sess.connection_id and conn_mgr:
                    c = conn_mgr.get(sess.connection_id)
                    has_local_wss = bool(c and getattr(c, "is_active", False))
            if (not has_local_wss) and self.relay_enabled and self.relay_client and getattr(self.relay_client, "_is_connected", False):
                tun = getattr(self.relay_client, "_tunnels", {}).get(tid)
                if tun is not None and getattr(tun, "handshake_done", False):
                    await self.relay_client.send_screen_frame(tid, {**meta, "route_badge": "Remote • Uses Data"}, jpeg_bytes)

    async def _push_frame_to_peer_https(self, target_id: str, peer_client: Any, meta: dict[str, Any], jpeg_bytes: bytes) -> None:
        """Push bounded JPEG frame to a connected peer PC's authenticated HTTPS transfer server."""
        try:
            import ssl
            import aiohttp
            host = getattr(peer_client, "host", None)
            token = getattr(peer_client, "auth_token", None) or (self.session_router.get_peer_token(target_id) if hasattr(self, "session_router") else "")
            if not host or not token:
                return
            node = self.node_registry.get_node(target_id) if getattr(self, "node_registry", None) else None
            transfer_port = getattr(node, "transfer_port", None) or 8766
            use_tls = bool(getattr(peer_client, "use_tls", True))
            scheme = "https" if use_tls else "http"
            url = f"{scheme}://{host}:{transfer_port}/api/v1/screen/frame"
            ssl_ctx = None
            if use_tls:
                ssl_ctx = ssl.create_default_context()
                ssl_ctx.check_hostname = False
                ssl_ctx.verify_mode = ssl.CERT_NONE
            headers = {
                "Authorization": f"Bearer {token}",
                "X-Snow-Device-Id": str(meta.get("sender_device_id") or "desktop-core"),
                "X-Snow-Sender-Id": str(meta.get("sender_device_id") or "desktop-core"),
                "X-Snow-Sender-Name": str(meta.get("sender_name") or "Windows PC"),
                "X-Snow-Sender-Platform": str(meta.get("sender_platform") or "windows"),
                "X-Snow-Session-Id": str(meta.get("session_id") or ""),
                "X-Snow-Frame-Seq": str(meta.get("frame_seq") or 0),
                "X-Snow-Frame-Width": str(meta.get("frame_width") or 0),
                "X-Snow-Frame-Height": str(meta.get("frame_height") or 0),
                "X-Snow-FPS": str(meta.get("fps") or 4.0),
                "X-Snow-Target-Device-Ids": target_id,
                "Content-Type": "image/jpeg",
            }
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=2.0)) as session:
                async with session.post(url, data=jpeg_bytes, headers=headers, ssl=ssl_ctx):
                    pass
        except Exception as exc:
            logger.debug("Peer HTTPS frame push error to [%s]: %s", target_id, exc)

    async def _handle_incoming_relay_media_frame(
        self, source_id: str, meta: dict[str, Any], jpeg_bytes: bytes
    ) -> None:
        """Accept bounded E2E encrypted screen frame over Relay ONLY from paired Full Control peers."""
        if not self.http_transfer_server or not self.db_manager:
            return
        paired = self.db_manager.get_paired_device(source_id)
        if not paired:
            return
        saved = self.db_manager.get_setting(f"device_profile:{source_id}")
        if saved is not None and str(saved).strip().lower() != "full_control":
            return
        enriched_meta = {
            **meta,
            "sender_device_id": source_id,
            "sender_name": meta.get("sender_name") or paired.device_name or source_id,
            "sender_platform": meta.get("sender_platform") or paired.platform or "remote",
            "route_badge": "Remote • Uses Data",
        }
        self.http_transfer_server.publish_screen_frame(
            sender_device_id=source_id,
            frame_bytes=jpeg_bytes,
            meta=enriched_meta,
        )

    async def connect_peer(
        self,
        host: str,
        port: int = 8765,
        pin: str = "",
        expected_fingerprint: str = "",
    ) -> dict[str, Any]:
        """Establish outbound TLS/WSS peer connection, register in NodeRegistry and DB, and retain session."""
        from snow.network.peer_client import SnowPeerClient

        client = SnowPeerClient(
            host=host,
            port=port,
            identity=self.device_identity,
            expected_fingerprint=expected_fingerprint or None,
            use_tls=True,
        )
        res = await client.connect(pin=pin, timeout=10.0)
        if not res.success or not res.remote_device_id:
            await client.close()
            return {
                "success": False,
                "status": res.status,
                "error": res.error or "Failed connecting to peer.",
            }

        remote_id = res.remote_device_id
        remote_name = res.remote_device_name or "Connected Peer"
        session_id = res.session_id or f"peer_{remote_id}"
        auth_token = res.auth_token or ""
        cert_fp = res.cert_fingerprint or ""

        # Close existing client for this device if any
        old_client = self.peer_clients.get(remote_id)
        if old_client:
            try:
                await old_client.close()
            except Exception:
                pass

        self.peer_clients[remote_id] = client

        # 1. Register in NodeRegistry
        self.node_registry.on_session_authenticated(
            device_id=remote_id,
            connection_id=session_id,
            host=host,
            port=port,
            manifest_data=res.manifest,
            transport="peer_link",
        )

        # 2. Persist in paired_devices with detected platform
        token_hash = hashlib.sha256(auth_token.encode("utf-8")).hexdigest() if auth_token else hashlib.sha256(remote_id.encode("utf-8")).hexdigest()
        manifest_dict = res.manifest if isinstance(res.manifest, dict) else {}
        caps = manifest_dict.get("supported_capabilities") or []
        caps_str = " ".join(caps) if isinstance(caps, list) else str(caps)
        raw_platform = str(
            getattr(res, "platform", None)
            or manifest_dict.get("platform")
            or manifest_dict.get("os")
            or manifest_dict.get("os_name")
            or ""
        ).strip().lower()

        if "android" in raw_platform or ("android." in caps_str and "desktop." not in caps_str):
            detected_platform = "android"
        elif "win" in raw_platform or "desktop." in caps_str:
            detected_platform = "windows"
        elif "linux" in raw_platform:
            detected_platform = "linux"
        elif "mac" in raw_platform or "darwin" in raw_platform:
            detected_platform = "macos"
        else:
            detected_platform = raw_platform or "windows"

        existing = self.db_manager.get_paired_device(remote_id)
        if not existing:
            self.db_manager.insert_paired_device(
                device_id=remote_id,
                device_name=remote_name,
                auth_token_hash=token_hash,
                trust_tier="peer",
                platform=detected_platform,
                reachability_profile="ACTIVE_SESSION_PEER",
                last_known_host=host,
                last_known_port=port,
                capabilities_json=json.dumps(res.manifest or {}),
            )
        else:
            self.db_manager.update_device_endpoint(remote_id, host, port)
            self.db_manager.update_last_seen(remote_id)

        # 3. Record in network_endpoints ring buffer
        self.network_manager.record_endpoint(device_id=remote_id, host=host, port=port)

        return {
            "success": True,
            "status": res.status,
            "data": {
                "remote_device_id": remote_id,
                "remote_device_name": remote_name,
                "session_id": session_id,
                "cert_fingerprint": cert_fp,
            },
        }

    async def disconnect_peer(self, device_id: str) -> dict[str, Any]:
        """Disconnect an active peer session, updating registry without forgetting pairing."""
        client = self.peer_clients.pop(device_id, None)
        if client:
            try:
                await client.close()
            except Exception:
                pass
            self.node_registry.on_session_disconnected(device_id)
            return {"success": True, "status": "DISCONNECTED", "device_id": device_id}
        return {"success": False, "status": "NOT_CONNECTED", "error": f"Peer '{device_id}' is not connected."}

    def set_pc_transfer_dir(self, path_str: str) -> dict[str, Any]:
        """Validate, persist in SQLite app_settings, and activate a new PC transfers destination."""
        resolved = self.storage_manager.set_root_dir(path_str)
        if self.db_manager is not None and hasattr(self.db_manager, "set_setting"):
            self.db_manager.set_setting("pc_transfer_dir", str(resolved))
        if hasattr(self.windows_files, "add_allowed_root"):
            self.windows_files.add_allowed_root(resolved)
        return {
            "success": True,
            "status": "UPDATED",
            "pc_transfers_dir": str(resolved),
            "default_pc_transfers_dir": str(get_default_pc_transfer_dir()),
        }

    async def disconnect_device(self, device_id: str) -> dict[str, Any]:
        """Disconnect any active session for device_id while preserving its SQLite pairing."""
        target_id = (device_id or "").strip()
        if not target_id:
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "Missing 'device_id'."}

        local_id = getattr(self.device_identity, "device_id", "") if hasattr(self, "device_identity") and self.device_identity else ""
        if target_id in ("local", "desktop-core", local_id):
            return {"success": False, "status": "FORBIDDEN", "error": "Cannot disconnect local desktop host."}

        paired = self.db_manager.get_paired_device(target_id) if self.db_manager else None
        ws_manual_set = getattr(self.ws_server, "manually_disconnected_devices", None)
        if isinstance(ws_manual_set, set):
            ws_manual_set.add(target_id)

        closed_inbound = False
        session_mgr = getattr(self, "session_manager", None) or getattr(self.ws_server, "session_manager", None)
        conn_mgr = getattr(self, "connection_manager", None) or getattr(self.ws_server, "connection_manager", None)

        matching_conn_ids: list[str] = []
        if session_mgr and hasattr(session_mgr, "_sessions"):
            for sess in list(session_mgr._sessions.values()):
                if getattr(sess, "device_id", None) == target_id and getattr(sess, "connection_id", None):
                    matching_conn_ids.append(sess.connection_id)

        for conn_id in matching_conn_ids:
            client = conn_mgr.get(conn_id) if conn_mgr else None
            if client and getattr(client, "websocket", None) is not None:
                try:
                    disconnect_msg = SnowMessage.create_request(
                        action="session_disconnect",
                        data={"device_id": target_id, "reason": "Disconnected by desktop owner"},
                    )
                    send_res = client.websocket.send(disconnect_msg.to_json())
                    if asyncio.iscoroutine(send_res) or hasattr(send_res, "__await__"):
                        await asyncio.wait_for(send_res, timeout=1.0)
                except Exception as exc:
                    logger.debug("Best-effort session_disconnect send failed for %s: %s", target_id, exc)
            unreg_client = conn_mgr.unregister(conn_id) if conn_mgr else None
            close_target = unreg_client or client
            if close_target and getattr(close_target, "websocket", None) is not None:
                try:
                    close_res = close_target.websocket.close(code=1000, reason="Disconnected by desktop owner")
                    if asyncio.iscoroutine(close_res) or hasattr(close_res, "__await__"):
                        await close_res
                    closed_inbound = True
                except Exception as exc:
                    logger.debug("Error closing socket for %s: %s", target_id, exc)

        if session_mgr and hasattr(session_mgr, "revoke_device_sessions"):
            session_mgr.revoke_device_sessions(target_id)

        if getattr(self, "node_registry", None):
            self.node_registry.on_session_disconnected(target_id)

        closed_peer = False
        if target_id in self.peer_clients:
            peer_res = await self.disconnect_peer(target_id)
            closed_peer = bool(peer_res.get("success"))

        if not paired and not closed_inbound and not closed_peer:
            if isinstance(ws_manual_set, set):
                ws_manual_set.discard(target_id)
            return {
                "success": False,
                "status": "DEVICE_NOT_FOUND",
                "error": f"Device '{target_id}' is neither paired nor currently connected.",
            }

        try:
            if self.db_manager:
                self.db_manager.log_audit_event(
                    event_type="DEVICE_DISCONNECTED",
                    device_id=target_id,
                    details={"inbound": closed_inbound, "peer": closed_peer, "paired_preserved": bool(paired)},
                )
        except Exception:
            pass

        return {
            "success": True,
            "status": "DISCONNECTED",
            "device_id": target_id,
            "paired": bool(paired),
            "was_connected": bool(closed_inbound or closed_peer),
        }

    async def reconnect_device(self, device_id: str) -> dict[str, Any]:
        """Clear manual disconnect hold and trigger clean reconnection for a paired device."""
        target_id = (device_id or "").strip()
        if not target_id:
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "Missing 'device_id'."}

        ws_manual_set = getattr(self.ws_server, "manually_disconnected_devices", None)
        if isinstance(ws_manual_set, set):
            ws_manual_set.discard(target_id)

        paired = self.db_manager.get_paired_device(target_id) if self.db_manager else None
        if not paired:
            return {
                "success": False,
                "status": "DEVICE_NOT_PAIRED",
                "error": f"Device '{target_id}' is not paired.",
            }

        session_mgr = getattr(self, "session_manager", None) or getattr(self.ws_server, "session_manager", None)
        conn_mgr = getattr(self, "connection_manager", None) or getattr(self.ws_server, "connection_manager", None)
        existing_sess = session_mgr.get_session_by_device(target_id) if session_mgr else None
        if existing_sess and existing_sess.connection_id and conn_mgr:
            conn = conn_mgr.get(existing_sess.connection_id)
            if conn and conn.is_active:
                return {"success": True, "status": "CONNECTED", "device_id": target_id, "is_connected": True}

        if target_id in self.peer_clients:
            return {"success": True, "status": "CONNECTED", "device_id": target_id, "is_connected": True}

        # Send targeted UDP discovery wake burst if discovery is active
        disc = getattr(self, "discovery_service", None)
        if disc and getattr(disc, "is_running", False):
            try:
                await disc.send_wake_burst(target_id, count=3, interval=0.1)
            except Exception as exc:
                logger.debug("Wake burst failed during reconnect for %s: %s", target_id, exc)

        # If target is a federated/peer host with known endpoint, attempt direct peer connect
        host = getattr(paired, "last_known_host", None)
        port = getattr(paired, "last_known_port", None)
        platform = str(getattr(paired, "platform", "") or "").lower()
        trust_tier = str(getattr(paired, "trust_tier", "") or "").lower()
        if host and port and (trust_tier == "peer" or platform == "windows" or int(port) == 8767):
            try:
                peer_res = await asyncio.wait_for(
                    self.connect_peer(
                        host=host,
                        port=int(port),
                        expected_fingerprint=getattr(paired, "cert_fingerprint", "") or "",
                    ),
                    timeout=5.0,
                )
                if peer_res.get("success"):
                    return {
                        "success": True,
                        "status": "CONNECTED",
                        "device_id": target_id,
                        "is_connected": True,
                        "data": peer_res.get("data"),
                    }
            except Exception as exc:
                logger.debug("Direct peer reconnect failed for %s (%s:%s): %s", target_id, host, port, exc)

        return {
            "success": True,
            "status": "RECONNECT_AUTHORIZED",
            "device_id": target_id,
            "is_connected": False,
            "message": f"Disconnect hold cleared and reconnect signal sent to '{target_id}'.",
        }

    def get_relay_status(self) -> dict[str, Any]:
        """Query live relay client connection state and active tunnels."""
        connected = bool(self.relay_client and getattr(self.relay_client, "_is_connected", False))
        tunnels = list(self.relay_client._tunnels.keys()) if self.relay_client else []
        return {
            "success": True,
            "status": "SUCCESS",
            "enabled": self.relay_enabled,
            "connected": connected,
            "relay_url": self.relay_url,
            "group_id": self.relay_group_id,
            "active_tunnels": tunnels,
            "tunnel_count": len(tunnels),
        }

    async def configure_relay(
        self,
        enabled: bool,
        relay_url: Optional[str] = None,
        group_id: Optional[str] = None,
        ticket: Optional[str] = None,
        clear_ticket: bool = False,
    ) -> dict[str, Any]:
        """Configure, enable, or disable the outbound relay tunnel client."""
        self.relay_enabled = bool(enabled)
        if relay_url is not None and relay_url.strip():
            self.relay_url = relay_url.strip()
        if group_id is not None and group_id.strip():
            self.relay_group_id = group_id.strip()
        if clear_ticket:
            self.relay_ticket = ""
        elif ticket is not None:
            clean_ticket = ticket.strip()
            # Submitting an empty dashboard ticket must not overwrite an already configured valid relay ticket.
            if clean_ticket:
                self.relay_ticket = clean_ticket

        # Update SessionRouter relay state
        self.session_router.relay_enabled = self.relay_enabled

        if not self.relay_enabled:
            # Drain and disconnect active relay client
            if self.relay_client:
                try:
                    await self.relay_client.disconnect()
                except Exception as exc:
                    logger.debug("Error disconnecting relay client: %s", exc)
                self.relay_client = None
                self.session_router.relay_client = None
            return self.get_relay_status()

        # Disconnect existing relay client if already running
        if self.relay_client:
            try:
                await self.relay_client.disconnect()
            except Exception:
                pass
            self.relay_client = None

        if not self.relay_url or not self.relay_ticket:
            logger.warning("Relay enabled but missing relay_url or ticket.")
            return self.get_relay_status()

        # Resolve cert & key paths safely using config attributes
        from snow.security.tls import DEFAULT_CERT_FILE, DEFAULT_KEY_FILE, DEFAULT_TLS_DIR
        data_dir = os.environ.get("SNOW_DATA_DIR")
        tls_dir = (Path(data_dir) / "tls") if data_dir else DEFAULT_TLS_DIR
        cert_candidate = (
            getattr(self.config, "tls_cert_path", None)
            or getattr(self.config, "tls_cert_file", None)
            or str(tls_dir / DEFAULT_CERT_FILE)
        )
        key_candidate = (
            getattr(self.config, "tls_key_path", None)
            or getattr(self.config, "tls_key_file", None)
            or str(tls_dir / DEFAULT_KEY_FILE)
        )
        cert_path = str(cert_candidate)
        key_path = str(key_candidate)

        if not os.path.exists(cert_path) or not os.path.exists(key_path):
            logger.warning(
                "Relay enabled but TLS certificate or key file not found: cert=%s, key=%s",
                cert_path,
                key_path,
            )
            return self.get_relay_status()

        from snow.network.relay_client import RelayTunnelClient
        local_dev_id = getattr(self.device_identity, "device_id", "desktop-core") if hasattr(self, "device_identity") and self.device_identity else "desktop-core"

        client = RelayTunnelClient(
            relay_url=self.relay_url,
            device_id=local_dev_id,
            group_id=self.relay_group_id or "default_group",
            ticket=self.relay_ticket,
            cert_path=cert_path,
            key_path=key_path,
        )

        # Pin fingerprints for all paired devices
        if self.db_manager:
            for p in self.db_manager.list_paired_devices():
                if p.cert_fingerprint:
                    client.set_peer_pinned_fingerprint(p.device_id, p.cert_fingerprint)

        # Wire incoming request and E2E media frame handlers
        async def _relay_request_dispatcher(source_id: str, req: SnowMessage) -> Optional[SnowMessage]:
            return await self._handle_incoming_relay_request(source_id, req)

        client.request_dispatcher = _relay_request_dispatcher
        client.media_frame_handler = self._handle_incoming_relay_media_frame

        connected = await client.connect()
        if connected:
            self.relay_client = client
            self.session_router.relay_client = client
            logger.info("Outbound relay tunnel client connected and registered with router.")
        else:
            logger.warning("Failed connecting to relay at %s", self.relay_url)

        return self.get_relay_status()

    async def _handle_incoming_relay_request(self, source_id: str, req: SnowMessage) -> Optional[SnowMessage]:
        """Dispatch incoming capability request received over inner E2E relay tunnel."""
        action = req.action
        data = req.data
        paired = self.db_manager.get_paired_device(source_id) if self.db_manager else None
        if not paired:
            # Bootstrap rendezvous peers may ONLY complete cryptographic pairing verification
            # via the real PairingManager path; all other capability requests remain strictly denied.
            if action in ("pair_request", "pair_verify") and self.ws_server is not None:
                captured_responses: list[str] = []

                class _RelayCaptureWs:
                    async def send(self, payload_text: str) -> None:
                        captured_responses.append(payload_text)

                    async def close(self, *args: Any, **kwargs: Any) -> None:
                        return None

                class _RelayCaptureClient:
                    def __init__(self) -> None:
                        self.connection_id = f"relay:{source_id}"
                        self.remote_address = ("relay", 0)
                        self.websocket = _RelayCaptureWs()

                pair_data = dict(data) if isinstance(data, dict) else {}
                pair_data.setdefault("device_id", source_id)
                await self.ws_server._handle_pairing_request(
                    _RelayCaptureClient(), req, action, pair_data
                )
                if captured_responses:
                    try:
                        return SnowMessage.from_json(captured_responses[-1])
                    except Exception:
                        pass
            logger.warning("Incoming relay request from unpaired peer [%s] rejected.", source_id)
            return SnowMessage.create_error(
                code="UNAUTHORIZED",
                message="Unpaired peer not authorized to execute capabilities via relay.",
                correlation_id=req.id,
            )

        if not action:
            return SnowMessage.create_error(
                code="INVALID_ARGUMENT",
                message="Missing capability action.",
                correlation_id=req.id,
            )

        # Derive execution principal strictly from authenticated paired-device trust
        from snow.security.context import ExecutionContext, ExecutionPrincipal
        from snow.capabilities.engine import CapabilityRequest, CapabilityResponse

        trust_tier = getattr(paired, "trust_tier", "peer")
        principal = (
            ExecutionPrincipal.OWNER_MANUAL
            if str(trust_tier).lower() == "owner"
            else ExecutionPrincipal.AI_MCP
        )

        ctx = ExecutionContext(
            principal=principal,
            device_id=source_id,
            origin=f"relay:{source_id}",
        )

        try:
            # Clean data: reject caller-supplied authority overrides
            clean_params = dict(data) if isinstance(data, dict) else {}
            clean_params.pop("principal", None)
            clean_params.pop("trust_tier", None)
            clean_params.pop("execution_principal", None)

            req_obj = CapabilityRequest(action=action, params=clean_params)
            res: CapabilityResponse = await self.capability_engine.execute(req_obj, ctx=ctx)

            if res.success:
                return SnowMessage.create_response(
                    correlation_id=req.id,
                    payload={
                        "status": "success",
                        "action": action,
                        "data": res.data if res.data is not None else {},
                    },
                )
            else:
                return SnowMessage.create_error(
                    code=res.status or "ERROR",
                    message=res.error or "Capability execution failed.",
                    correlation_id=req.id,
                )
        except Exception as exc:
            return SnowMessage.create_error(
                code="INTERNAL_ERROR",
                message=str(exc),
                correlation_id=req.id,
            )

    @property
    def is_running(self) -> bool:
        """Return True if the server is currently in the running state."""
        return self._is_running

    @property
    def detected_interfaces(self) -> List[NetworkInterfaceInfo]:
        """Return the list of detected network interfaces."""
        return list(self._detected_interfaces)

    @property
    def pairing_manager(self):
        """Return the core server's pairing manager."""
        return self.ws_server.pairing_manager

    @property
    def device_identity(self):
        """Return the core server's device identity."""
        return self.ws_server.device_identity

    @property
    def db_manager(self):
        """Return the core server's SQLite database manager."""
        return self.ws_server.db_manager

    @property
    def session_manager(self):
        """Return the core server's active session manager."""
        return self.ws_server.session_manager

    @property
    def clipboard_listener(self):
        """Return the core server's active Windows clipboard listener."""
        return getattr(self.ws_server, "_clipboard_listener", None)

    async def start(self) -> None:
        """Initialize the server lifecycle, enumerate interfaces, and start WebSocket listener.

        Idempotent: Repeated invocations when the server is already running log a warning
        and return without re-initialization.
        """
        if self._is_running:
            logger.warning("%s is already running; start() call ignored.", self.config.app_name)
            return

        logger.info("Starting %s v%s...", self.config.app_name, self.config.version)

        # Clear any prior shutdown event in case of server restart
        self._shutdown_event.clear()

        # Enumerate usable local IPv4 addresses
        self._detected_interfaces = detect_usable_ipv4_addresses()

        if self._detected_interfaces:
            active = [iface for iface in self._detected_interfaces if iface.is_up]
            logger.info("Detected %d usable network interface(s):", len(self._detected_interfaces))
            for iface in self._detected_interfaces:
                status = "ACTIVE" if iface.is_up else "INACTIVE"
                logger.info(
                    "  - [%s] %s: %s (WebSocket port %d)",
                    status,
                    iface.interface_name,
                    iface.ip_address,
                    self.config.port,
                )
            if not active:
                logger.warning(
                    "No active (UP) interface found. Connect laptop to Wi-Fi or phone hotspot."
                )
        else:
            logger.warning("No usable IPv4 addresses detected.")
            logger.warning("Please connect this laptop to Wi-Fi or an Android mobile hotspot.")

        # Start the WebSocket server
        active_ips = [iface.ip_address for iface in self._detected_interfaces if iface.is_up]
        await self.ws_server.start(active_ips=active_ips)

        # Start the HTTP/HTTPS file transfer server reusing WSS ssl_context
        self.http_transfer_server = SnowHttpTransferServer(
            config=self.config,
            db_manager=self.db_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
            ssl_context=self.ws_server.ssl_context,
        )
        self.ws_server.http_transfer_server = self.http_transfer_server
        self.capability_engine.http_transfer_server = self.http_transfer_server
        await self.http_transfer_server.start()

        # Start the authenticated loopback IPC server for MCP subprocess communication
        await self.ipc_server.start()

        # Start zero-touch UDP discovery service
        if self.config.discovery_enabled:
            def _check_paired(dev_id: str, cert_fp: str) -> bool:
                paired = self.db_manager.get_paired_device(dev_id)
                if not paired:
                    return False
                if paired.cert_fingerprint and cert_fp:
                    return paired.cert_fingerprint.lower() == cert_fp.lower()
                return True

            self.discovery_service = SnowDiscoveryService(
                config=self.config,
                device_identity=self.device_identity,
                cert_fingerprint=getattr(self.ws_server, "cert_fingerprint", ""),
                paired_device_checker=_check_paired,
            )
            await self.discovery_service.start()
            self.node_registry.discovery_service = self.discovery_service
            self.session_router.discovery_service = self.discovery_service

        # F31: Perform startup cleanup of abandoned partial transfer files
        try:
            self._run_maintenance_once()
        except Exception as exc:
            logger.warning("Startup cleanup of stale parts encountered error: %s", exc)

        # F31: Start periodic background maintenance loop
        self._maintenance_task = asyncio.create_task(self._periodic_maintenance_loop())

        # Start automatic USB ADB watcher
        if getattr(self, "usb_watcher", None):
            try:
                await self.usb_watcher.start()
            except Exception as exc:
                logger.debug("UsbWatcher failed to start: %s", exc)

        self._is_running = True
        actual_port = self.ws_server.bound_port or self.config.port
        actual_http_port = self.http_transfer_server.bound_port or self.config.transfer_port
        actual_ipc_port = self.ipc_server.bound_port or self.config.ipc_port
        logger.info(
            "%s started successfully (listening on WSS port %d, HTTP transfer port %d, IPC port %d).",
            self.config.app_name,
            actual_port,
            actual_http_port,
            actual_ipc_port,
        )

    async def run(self) -> None:
        """Execute the asynchronous server loop until shutdown is signaled."""
        await self.start()
        try:
            # Wait asynchronously until a shutdown request is signaled
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            logger.debug("Server run loop received CancelledError.")
            raise
        finally:
            await self.stop()

    def _run_maintenance_once(self) -> int:
        """Execute one maintenance cycle: clean up abandoned .part files protecting active transfers."""
        try:
            active_ids = self.transfer_manager.get_active_transfer_ids()
            cleaned = self.storage_manager.cleanup_stale_parts(active_transfer_ids=active_ids)
            if cleaned > 0:
                logger.info("Maintenance cycle removed %d stale partial transfer file(s).", cleaned)
            return cleaned
        except Exception as exc:
            logger.warning("Error during transfer storage maintenance: %s", exc)
            return 0

    async def _periodic_maintenance_loop(self) -> None:
        """Periodically clean up abandoned .part files and maintain transfer storage."""
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(3600)  # Hourly maintenance
                if self._shutdown_event.is_set():
                    break
                self._run_maintenance_once()
        except asyncio.CancelledError:
            pass

    @property
    def is_paused(self) -> bool:
        """Return True if system is in pause mode."""
        return self._is_paused

    async def pause_system(self, reason: str = "Paused by owner") -> dict[str, Any]:
        """Put the desktop core into pause mode.

        Idempotent:
        - If already paused, returns ALREADY_PAUSED.
        - Pauses USB watcher.
        - Pauses clipboard sync if enabled.
        - Cleanly disconnects all active peer connections.
        - Cleanly disconnects relay client if connected.
        - Retains pre-pause state so resume restores valid services.
        """
        if self._is_paused:
            return {"success": True, "status": "ALREADY_PAUSED", "state": "PAUSED", "reason": reason}

        logger.info("System pause requested: %s", reason)
        self._is_paused = True
        self._paused_state.clear()

        # 1. Pause USB watcher
        if getattr(self, "usb_watcher", None):
            self.usb_watcher.pause()
            self._paused_state["usb_watcher"] = True

        # 2. Pause clipboard sync
        if hasattr(self, "capability_engine") and hasattr(self.capability_engine, "clipboard"):
            cb = self.capability_engine.clipboard
            if getattr(cb, "sync_enabled", False):
                self._paused_state["clipboard_sync"] = True
                cb.set_sync_enabled(False)

        # 3. Disconnect active peers cleanly
        if hasattr(self, "peer_clients"):
            for p_id, p_client in list(self.peer_clients.items()):
                try:
                    await p_client.close()
                except Exception:
                    pass
            self.peer_clients.clear()

        # 4. Disconnect relay client
        if getattr(self, "relay_client", None):
            try:
                await self.relay_client.disconnect()
            except Exception:
                pass
            self.relay_client = None
            self._paused_state["relay"] = True

        # 5. Audit log
        try:
            self.db_manager.log_activity(
                event_type="SYSTEM_PAUSED",
                principal="OWNER_MANUAL",
                target_device=self.config.device_id,
                capability="core.system.pause",
                outcome="SUCCESS",
                details={"reason": reason},
            )
        except Exception:
            pass

        return {"success": True, "status": "PAUSED", "state": "PAUSED", "reason": reason}

    async def resume_system(self) -> dict[str, Any]:
        """Restore desktop core from pause mode to active mode.

        Idempotent:
        - If not paused, returns ALREADY_ACTIVE.
        - Restores USB watcher.
        - Restores clipboard sync if it was active before pause.
        """
        if not self._is_paused:
            return {"success": True, "status": "ALREADY_ACTIVE", "state": "ACTIVE"}

        logger.info("System resume requested.")
        self._is_paused = False

        # 1. Resume USB watcher
        if getattr(self, "usb_watcher", None):
            self.usb_watcher.resume()

        # 2. Restore clipboard sync if it was active
        if self._paused_state.get("clipboard_sync"):
            if hasattr(self, "capability_engine") and hasattr(self.capability_engine, "clipboard"):
                self.capability_engine.clipboard.set_sync_enabled(True)

        self._paused_state.clear()

        # 3. Audit log
        try:
            self.db_manager.log_activity(
                event_type="SYSTEM_RESUMED",
                principal="OWNER_MANUAL",
                target_device=self.config.device_id,
                capability="core.system.resume",
                outcome="SUCCESS",
                details={},
            )
        except Exception:
            pass

        return {"success": True, "status": "RESUMED", "state": "ACTIVE"}

    def request_shutdown(self) -> None:
        """Signal the running server loop to terminate gracefully.

        Idempotent: Safe to call multiple times or after the server has already stopped.
        """
        if not self._is_running and self._shutdown_event.is_set():
            logger.debug("Server is already stopped or shutting down; request_shutdown() ignored.")
            return

        logger.info("Shutdown signal received; initiating graceful termination.")
        self._shutdown_event.set()

    async def stop(self) -> None:
        """Perform graceful shutdown and resource cleanup.

        Idempotent: Safe to call multiple times; redundant invocations exit immediately.
        """
        if not self._is_running:
            logger.debug("%s is already stopped or not running; stop() ignored.", self.config.app_name)
            return

        logger.info("Stopping %s...", self.config.app_name)
        self._is_running = False
        self._shutdown_event.set()

        # F31: Cancel and await background maintenance task
        if self._maintenance_task:
            self._maintenance_task.cancel()
            try:
                await self._maintenance_task
            except asyncio.CancelledError:
                pass
            self._maintenance_task = None

        # Stop automatic USB ADB watcher
        if getattr(self, "usb_watcher", None):
            try:
                await self.usb_watcher.stop()
            except Exception as exc:
                logger.debug("Error stopping UsbWatcher: %s", exc)

        # Stop live PC screen stream cleanly if running
        if getattr(self, "screen_stream_manager", None) is not None:
            try:
                await self.screen_stream_manager.stop(reason="STOPPED")
            except Exception as exc:
                logger.debug("Error stopping screen_stream_manager: %s", exc)

        # Stop IPC server first so external tool requests terminate cleanly before core shuts down
        if self.ipc_server:
            await self.ipc_server.stop()

        # Stop discovery service
        if self.discovery_service:
            await self.discovery_service.stop()
            self.discovery_service = None

        # Stop HTTP transfer server
        if self.http_transfer_server:
            await self.http_transfer_server.stop()
            self.http_transfer_server = None

        # Close all active peer clients
        if hasattr(self, "peer_clients"):
            for p_id, p_client in list(self.peer_clients.items()):
                try:
                    await p_client.close()
                except Exception:
                    pass
            self.peer_clients.clear()

        # Disconnect relay client
        if getattr(self, "relay_client", None):
            try:
                await self.relay_client.disconnect()
            except Exception:
                pass
            self.relay_client = None

        # Stop WebSocket server and close client connections
        await self.ws_server.stop()

        logger.info("%s stopped cleanly.", self.config.app_name)


if __name__ == "__main__":
    import sys
    from snow.main import main
    sys.exit(main())
