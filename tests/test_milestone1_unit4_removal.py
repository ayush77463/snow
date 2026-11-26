"""Unit 1.4 Regression Tests: Consolidated Idempotent Device Removal & Ghost Prevention."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock
import uuid

import aiohttp
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from snow.capabilities.windows.screen_stream import WindowsScreenStreamManager
from snow.core.config import CoreConfig
from snow.core.ipc import IPC_PROTOCOL_VERSION, SnowIpcServer
from snow.core.server import SnowCoreServer
from snow.mcp.bridge import SnowMcpBridge
from snow.network.discovery import DiscoveredPeerRecord, SnowDiscoveryService
from snow.network.relay_client import RelayTunnelClient
from snow.protocol.models import SnowMessage
from snow.relay.auth import create_relay_ticket
from snow.relay.config import RelayConfig
from snow.relay.server import SnowRelayServer
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import DeviceIdentity
from snow.security.tls import ensure_tls_certificate
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferManager
from snow.transfer.storage import TransferStorageManager
from snow.web.server import SnowWebServer


class _FakeWs:
    def __init__(self, remote_addr=("192.168.1.50", 51111)) -> None:
        self.remote_address = remote_addr
        self.sent: list[dict] = []
        self.closed = False
        self.close_args: tuple | None = None

    async def send(self, payload: str) -> None:
        self.sent.append(json.loads(payload))

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = True
        self.close_args = (code, reason)


class TestMilestone1Unit4DeviceRemoval(unittest.IsolatedAsyncioTestCase):
    """Comprehensive verification of consolidated idempotent device removal across all transports."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m1_u14_"))
        self.db = DatabaseManager(self.tmp_dir / "u14.db")
        self.host_ident = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Desktop-U14",
            created_at="2026-11-26T00:00:00Z",
            snow_id="SNW-HOST-1400",
        )
        self.cert_info = ensure_tls_certificate(
            self.tmp_dir / "host.crt",
            self.tmp_dir / "host.key",
            active_ips=["127.0.0.1", "192.168.1.10"],
        )
        self.cfg = CoreConfig(
            port=8765,
            ipc_port=0,
            transfer_port=0,
            discovery_enabled=True,
            tls_cert_path=str(self.cert_info.cert_path),
            tls_key_path=str(self.cert_info.key_path),
        )
        self.core = SnowCoreServer(
            config=self.cfg,
            device_identity=self.host_ident,
            db_manager=self.db,
        )
        self.core.discovery_service = SnowDiscoveryService(self.cfg, self.host_ident)
        self.ipc = SnowIpcServer(core_server=self.core, config=self.cfg)
        self.ipc._secret = "u14-ipc-secret"
        self.owner_token = hmac.new(
            self.ipc._secret.encode("utf-8"),
            b"SNOW_OWNER_AUTHORIZATION",
            hashlib.sha256,
        ).hexdigest()
        SnowHttpTransferServer._screen_sessions.clear()

    async def asyncTearDown(self) -> None:
        SnowHttpTransferServer._screen_sessions.clear()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def _ipc_revoke(self, device_id: str) -> dict:
        req = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": str(uuid.uuid4()),
            "op": "device_revoke",
            "auth_token": self.ipc._secret,
            "owner_token": self.owner_token,
            "payload": {"device_id": device_id},
        }
        res, _ = await self.ipc._dispatch_request(req, is_connection_authenticated=True)
        return res

    def _seed_connected_device(
        self,
        device_id: str,
        remote_addr=("192.168.1.60", 52222),
        transport: str = "wifi_lan",
    ) -> tuple[_FakeWs, str, str]:
        raw_tok = f"tok-{device_id}"
        self.db.insert_paired_device(
            device_id=device_id,
            device_name="Realme Phone",
            auth_token_hash=hash_token(raw_tok),
            trust_tier="owner",
            last_known_host=remote_addr[0],
            last_known_port=remote_addr[1],
        )
        self.db.set_setting(f"device_profile:{device_id}", "full_control")
        ws = _FakeWs(remote_addr=remote_addr)
        conn = self.core.connection_manager.register(ws)
        sess = self.core.session_manager.create_session(
            device_id=device_id,
            connection_id=conn.connection_id,
            trust_tier="owner",
        )
        self.core.node_registry.on_session_authenticated(
            device_id=device_id,
            connection_id=conn.connection_id,
            host=remote_addr[0],
            port=8765,
            transport=transport,
        )
        self.core.ws_server.manually_disconnected_devices.add(device_id)
        self.core.ws_server.live_notifications[device_id] = [{"key": "n1", "title": "Hi"}]
        self.core.discovery_service._discovered_peers[device_id] = DiscoveredPeerRecord(
            device_id=device_id,
            device_name="Realme Phone",
            device_type="android",
            ip_address=remote_addr[0],
            port=8765,
            transfer_port=8766,
            cert_fingerprint="CC" * 32,
            last_seen_timestamp=time.time(),
            is_paired=True,
        )
        return ws, conn.connection_id, raw_tok

    async def test_01_revoke_connected_lan_device_and_10_wss_blocked(self) -> None:
        dev_id = str(uuid.uuid4())
        ws, conn_id, raw_tok = self._seed_connected_device(dev_id, ("192.168.1.60", 52222), "wifi_lan")

        res = await self._ipc_revoke(dev_id)
        self.assertTrue(res["success"])
        self.assertTrue(res["data"]["removed"])
        self.assertFalse(res["data"]["already_removed"])

        # Notify + close + unregister + session + DB + profile + registry + manual/notif/discovery purged
        self.assertTrue(any(m.get("payload", {}).get("action") == "device_revoked" for m in ws.sent))
        self.assertTrue(ws.closed)
        self.assertIsNone(self.core.connection_manager.get(conn_id))
        self.assertIsNone(self.core.session_manager.get_session_by_device(dev_id))
        self.assertIsNone(self.db.get_paired_device(dev_id))
        self.assertIsNone(self.db.get_setting(f"device_profile:{dev_id}"))
        self.assertIsNone(self.core.node_registry.get_node(dev_id))
        self.assertNotIn(dev_id, self.core.ws_server.manually_disconnected_devices)
        self.assertNotIn(dev_id, self.core.ws_server.live_notifications)
        self.assertIsNone(self.core.discovery_service.get_peer(dev_id))

        # 10. Revoked device cannot authenticate new WSS requests
        self.assertFalse(self.core.ws_server.authorize_request(dev_id, raw_tok))
        ws2 = _FakeWs()
        c2 = self.core.connection_manager.register(ws2)
        await self.core.ws_server._handle_request(
            c2,
            SnowMessage.create_request("auth_request", {"device_id": dev_id, "auth_token": raw_tok}),
        )
        self.assertEqual(ws2.sent[0]["type"], "error")
        self.assertIsNone(self.core.session_manager.get_session_by_device(dev_id))

    async def test_02_revoke_connected_usb_local_device(self) -> None:
        dev_id = str(uuid.uuid4())
        ws, conn_id, raw_tok = self._seed_connected_device(dev_id, ("127.0.0.1", 53333), "usb_adb")

        res = await self._ipc_revoke(dev_id)
        self.assertTrue(res["success"])
        self.assertTrue(ws.closed)
        self.assertIsNone(self.core.connection_manager.get(conn_id))
        self.assertIsNone(self.db.get_paired_device(dev_id))
        self.assertFalse(self.core.ws_server.authorize_request(dev_id, raw_tok))

    async def test_03_12_revoke_connected_relay_device_closes_tunnel_and_blocks_requests(self) -> None:
        relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="u14-relay-secret"))
        await relay.start()
        try:
            relay_port = int(relay._site._server.sockets[0].getsockname()[1])
            ws_url = f"ws://127.0.0.1:{relay_port}/v1/tunnel"
            peer_id = str(uuid.uuid4())
            peer_tls = ensure_tls_certificate(self.tmp_dir / "peer.crt", self.tmp_dir / "peer.key")

            self.db.insert_paired_device(peer_id, "Relay Phone", hash_token("tok-relay-1"))
            t_host = create_relay_ticket(self.host_ident.device_id, "grp-u14", "u14-relay-secret")
            t_peer = create_relay_ticket(peer_id, "grp-u14", "u14-relay-secret")

            host_rc = RelayTunnelClient(
                ws_url, self.host_ident.device_id, "grp-u14", t_host,
                str(self.cert_info.cert_path), str(self.cert_info.key_path),
            )
            peer_rc = RelayTunnelClient(
                ws_url, peer_id, "grp-u14", t_peer,
                str(peer_tls.cert_path), str(peer_tls.key_path),
            )
            host_rc.set_peer_pinned_fingerprint(peer_id, peer_tls.fingerprint_sha256)
            peer_rc.set_peer_pinned_fingerprint(self.host_ident.device_id, self.cert_info.fingerprint_sha256)
            self.core.relay_client = host_rc
            self.core.session_router.relay_client = host_rc

            self.assertTrue(await host_rc.connect())
            self.assertTrue(await peer_rc.connect())
            self.assertTrue(await peer_rc.initiate_e2e_tunnel(self.host_ident.device_id, timeout=5.0))
            self.assertIn(peer_id, host_rc._tunnels)

            res = await self.core.remove_device_everywhere(peer_id, reason="Revoked relay peer")
            self.assertTrue(res["removed"])
            self.assertNotIn(peer_id, host_rc._tunnels)
            self.assertNotIn(peer_id, host_rc._pinned_fingerprints)
            self.assertIsNone(self.db.get_paired_device(peer_id))

            # 12. Revoked device cannot execute capabilities via relay request handler
            denied = await self.core._handle_incoming_relay_request(
                peer_id,
                SnowMessage.create_request("windows_system_info", {}),
            )
            self.assertIsNotNone(denied)
            self.assertEqual((denied.error or {}).get("code"), "UNAUTHORIZED")

            await peer_rc.disconnect()
            await host_rc.disconnect()
        finally:
            await relay.stop()

    async def test_04_revoke_disconnected_paired_device(self) -> None:
        dev_id = str(uuid.uuid4())
        self.db.insert_paired_device(dev_id, "Offline Phone", hash_token("tok-offline"), last_known_host="192.168.1.99")
        self.db.set_setting(f"device_profile:{dev_id}", "files_only")

        res = await self._ipc_revoke(dev_id)
        self.assertTrue(res["success"])
        self.assertTrue(res["data"]["removed"])
        self.assertIsNone(self.db.get_paired_device(dev_id))
        self.assertIsNone(self.db.get_setting(f"device_profile:{dev_id}"))
        self.assertIsNone(self.core.node_registry.get_node(dev_id))

    async def test_05_revoke_non_database_ghost_device(self) -> None:
        ghost_id = str(uuid.uuid4())
        # Exist ONLY in discovery + NodeRegistry + manual disconnect + live notifications
        self.core.discovery_service._discovered_peers[ghost_id] = DiscoveredPeerRecord(
            device_id=ghost_id,
            device_name="Unknown Node",
            device_type="android",
            ip_address="192.168.1.123",
            port=8765,
            transfer_port=8766,
            cert_fingerprint="",
            last_seen_timestamp=time.time(),
            is_paired=False,
        )
        self.core.node_registry.on_discovery_beacon(ghost_id, "Unknown Node", "android", "192.168.1.123", 8765, 8766)
        self.core.ws_server.manually_disconnected_devices.add(ghost_id)
        self.core.ws_server.live_notifications[ghost_id] = [{"key": "ghost"}]

        res = await self.core.remove_device_everywhere(ghost_id, reason="Purge ghost")
        self.assertTrue(res["success"])
        self.assertTrue(res["removed"])
        self.assertFalse(res["db_deleted"])
        self.assertTrue(res["runtime_cleaned"])
        self.assertIsNone(self.core.node_registry.get_node(ghost_id))
        self.assertIsNone(self.core.discovery_service.get_peer(ghost_id))
        self.assertNotIn(ghost_id, self.core.ws_server.manually_disconnected_devices)
        self.assertNotIn(ghost_id, self.core.ws_server.live_notifications)

    async def test_06_07_android_initiated_unpair_closes_ws_registry_and_relay(self) -> None:
        dev_id = str(uuid.uuid4())
        ws, conn_id, raw_tok = self._seed_connected_device(dev_id)

        mock_rc = MagicMock()
        mock_rc._tunnels = {dev_id: object()}
        mock_rc.close_tunnel = AsyncMock(return_value=True)
        self.core.relay_client = mock_rc

        client = self.core.connection_manager.get(conn_id)
        unpair_msg = SnowMessage.create_request(
            "unpair_request",
            {"device_id": dev_id, "auth_token": raw_tok},
        )
        await self.core.ws_server._handle_request(client, unpair_msg)

        # Client received ACK, socket closed & unregistered, registry/DB/relay/discovery cleaned
        self.assertEqual(ws.sent[0]["type"], "response")
        self.assertTrue(ws.sent[0]["payload"]["data"]["unpaired"])
        self.assertTrue(ws.closed)
        self.assertIsNone(self.core.connection_manager.get(conn_id))
        self.assertIsNone(self.db.get_paired_device(dev_id))
        self.assertIsNone(self.core.node_registry.get_node(dev_id))
        mock_rc.close_tunnel.assert_awaited_once_with(dev_id)

    async def test_08_repeated_revoke_is_idempotent(self) -> None:
        dev_id = str(uuid.uuid4())
        self.db.insert_paired_device(dev_id, "Phone", hash_token("tok-idem"))

        first = await self.core.remove_device_everywhere(dev_id)
        self.assertTrue(first["success"])
        self.assertTrue(first["removed"])
        self.assertFalse(first["already_removed"])

        second = await self.core.remove_device_everywhere(dev_id)
        self.assertFalse(second["success"])
        self.assertFalse(second["removed"])
        self.assertTrue(second["already_removed"])
        self.assertEqual(second["status"], "DEVICE_NOT_FOUND")

    async def test_09_secondary_cleanup_exception_does_not_interrupt_remaining_cleanup(self) -> None:
        dev_id = str(uuid.uuid4())
        ws, conn_id, raw_tok = self._seed_connected_device(dev_id)

        # Inject failures into notify send, screen revoke, and relay tunnel close
        async def _boom_send(*args, **kwargs):
            raise RuntimeError("socket send failed")

        ws.send = _boom_send  # type: ignore[method-assign]
        self.core.revoke_screen_target = AsyncMock(side_effect=RuntimeError("screen stop crashed"))
        mock_rc = MagicMock()
        mock_rc._tunnels = {dev_id: object()}
        mock_rc.close_tunnel = AsyncMock(side_effect=RuntimeError("relay close crashed"))
        self.core.relay_client = mock_rc

        res = await self.core.remove_device_everywhere(dev_id, notify_client=True)
        # DB auth revoked FIRST and remaining steps STILL ran cleanly
        self.assertTrue(res["removed"])
        self.assertIsNone(self.db.get_paired_device(dev_id))
        self.assertIsNone(self.db.get_setting(f"device_profile:{dev_id}"))
        self.assertIsNone(self.core.session_manager.get_session_by_device(dev_id))
        self.assertIsNone(self.core.node_registry.get_node(dev_id))
        self.assertIsNone(self.core.discovery_service.get_peer(dev_id))
        self.assertTrue(ws.closed)
        self.assertIsNone(self.core.connection_manager.get(conn_id))
        self.assertGreaterEqual(len(res["cleanup_errors"]), 3)
        self.assertFalse(self.core.ws_server.authorize_request(dev_id, raw_tok))

    async def test_11_revoked_device_cannot_access_protected_https_transfer_resources(self) -> None:
        dev_id = str(uuid.uuid4())
        _, _, raw_tok = self._seed_connected_device(dev_id)

        http_srv = SnowHttpTransferServer(
            CoreConfig(auth_required=True),
            self.db,
            TransferManager(),
            TransferStorageManager(root_dir=self.tmp_dir / "transfers"),
        )
        async with TestClient(TestServer(http_srv.app)) as cli:
            hdrs = {"Authorization": f"Bearer {raw_tok}", "X-Snow-Device-Id": dev_id}
            ok_resp = await cli.get("/api/v1/transfers", headers=hdrs)
            self.assertEqual(ok_resp.status, 200)

            await self.core.remove_device_everywhere(dev_id)

            denied_transfers = await cli.get("/api/v1/transfers", headers=hdrs)
            self.assertEqual(denied_transfers.status, 401)
            denied_screen = await cli.get("/api/v1/screen/senders", headers=hdrs)
            self.assertEqual(denied_screen.status, 401)

    async def test_13_screen_sharing_authorization_is_revoked(self) -> None:
        dev_id = str(uuid.uuid4())
        self._seed_connected_device(dev_id)
        http_srv = SnowHttpTransferServer(
            CoreConfig(auth_required=True),
            self.db,
            TransferManager(),
            TransferStorageManager(root_dir=self.tmp_dir / "screen_tr"),
        )
        self.core.http_transfer_server = http_srv
        self.core.screen_stream_manager = WindowsScreenStreamManager(
            sender_device_id=self.host_ident.device_id,
            sender_name="Host PC",
            transfer_server=http_srv,
            permission_checker=lambda d: True,
        )
        await self.core.screen_stream_manager.start(target_device_ids=[dev_id], initial_viewers=[dev_id], spawn_loop=False)
        self.assertTrue(http_srv._is_screen_authorized(dev_id))
        self.assertEqual(self.core.screen_stream_manager.state, "STREAMING")

        await self.core.remove_device_everywhere(dev_id)

        self.assertEqual(self.core.screen_stream_manager.state, "REVOKED")
        self.assertFalse(http_srv._is_screen_authorized(dev_id))
        self.assertEqual(SnowHttpTransferServer.list_active_screen_streams(requester_device_id=dev_id), [])

    async def test_14_unpaired_udp_discovery_candidates_do_not_pollute_paired_device_api(self) -> None:
        paired_id = str(uuid.uuid4())
        ghost_id = str(uuid.uuid4())
        stranger_id = str(uuid.uuid4())
        self.db.insert_paired_device(paired_id, "Real Phone", hash_token("tok-real"))
        self.core.node_registry.on_discovery_beacon(stranger_id, "Stranger Laptop", "windows", "192.168.1.201", 8765, 8766)
        self.core.node_registry._active_sessions[ghost_id] = {
            "connection_id": "orphan-conn",
            "host": "192.168.1.202",
            "port": 8765,
            "last_seen": time.time(),
            "transport": "wifi_lan",
        }
        self.core.discovery_service._discovered_peers[stranger_id] = DiscoveredPeerRecord(
            device_id=stranger_id,
            device_name="Stranger Laptop",
            device_type="windows",
            ip_address="192.168.1.201",
            port=8765,
            transfer_port=8766,
            cert_fingerprint="",
            last_seen_timestamp=time.time(),
            is_paired=False,
        )

        # Bridge using IPC list_devices + list_discovered_peers -> Web /api/devices
        bridge = SnowMcpBridge(auto_start_core=False, is_owner_channel=True)

        async def _ipc_call(op: str, payload=None, timeout: float = 5.0):
            req = {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": str(uuid.uuid4()),
                "op": op,
                "auth_token": self.ipc._secret,
                "payload": payload or {},
            }
            res, _ = await self.ipc._dispatch_request(req, is_connection_authenticated=True)
            return res

        bridge.call = AsyncMock(side_effect=_ipc_call)
        bridge.call_cross_device = AsyncMock(side_effect=_ipc_call)
        bridge.android_battery = AsyncMock(return_value={"success": False})

        web = SnowWebServer(host="127.0.0.1", port=0, bridge=bridge, auto_open_browser=False)
        req = make_mocked_request("GET", "/api/devices")
        resp = await web.handle_api_devices(req)
        self.assertEqual(resp.status, 200)
        body = json.loads(resp.text)

        device_ids = {d["device_id"] for d in body["devices"]}
        device_names = {d.get("device_name") for d in body["devices"]}
        self.assertIn(paired_id, device_ids)
        self.assertNotIn(stranger_id, device_ids)
        self.assertNotIn(ghost_id, device_ids)
        self.assertNotIn("Unknown Node", device_names)
        # Discovery view still works separately
        self.assertEqual({d["device_id"] for d in body["discovered_peers"]}, {stranger_id})

    async def test_15_repair_pre_cleanup_preserves_newly_authorized_device(self) -> None:
        client_uuid = str(uuid.uuid4())
        # Old stale state before re-pair
        self.db.insert_paired_device(client_uuid, "Old Phone Name", hash_token("old-stale-token"))
        self.db.set_setting(f"device_profile:{client_uuid}", "clipboard_only")
        self.core.ws_server.manually_disconnected_devices.add(client_uuid)
        self.core.ws_server.live_notifications[client_uuid] = [{"key": "stale-notif"}]

        pin = self.core.ws_server.pairing_manager.generate_pin(display_to_stderr=False, trust_tier="owner")
        new_ws = _FakeWs(("192.168.1.88", 54444))
        new_conn = self.core.connection_manager.register(new_ws)

        await self.core.ws_server._handle_request(
            new_conn,
            SnowMessage.create_request(
                "pair_request",
                {"device_id": client_uuid, "device_name": "Fresh Phone", "pin": pin},
            ),
        )

        # Newly authorized device MUST exist, hold new token, active WS open, and old stale state gone
        self.assertFalse(new_ws.closed)
        self.assertEqual(new_ws.sent[0]["payload"]["status"], "success")
        new_token = new_ws.sent[0]["payload"]["data"]["auth_token"]
        self.assertFalse(self.core.ws_server.authorize_request(client_uuid, "old-stale-token"))
        self.assertTrue(self.core.ws_server.authorize_request(client_uuid, new_token))
        rec = self.db.get_paired_device(client_uuid)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.device_name, "Fresh Phone")
        self.assertIsNotNone(self.core.session_manager.get_session_by_device(client_uuid))
        self.assertNotIn(client_uuid, self.core.ws_server.manually_disconnected_devices)
        self.assertNotIn(client_uuid, self.core.ws_server.live_notifications)


if __name__ == "__main__":
    unittest.main()
