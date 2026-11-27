"""Milestone 4.3 Regression Tests — Intelligent Transport Priority, MBB Switching, Bidirectional USB, and Accurate Transfer Routing."""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from snow.core.usb import (
    UsbWatcher,
    get_usb_bidirectional_status,
    get_usb_forward_mappings,
    remove_usb_forward,
    setup_usb_forward,
)
from snow.network.node import DeviceNode, ReachabilityProfile, ReachabilityState
from snow.network.peer_client import PeerConnectionResult
from snow.network.registry import NodeRegistry
from snow.network.router import (
    SessionRouter,
    classify_route_priority,
    classify_transport_badge,
    evaluate_preferred_route,
)
from snow.network.transport import (
    RouteCandidate,
    RouteStatus,
    TransportType,
    classify_transfer_socket_route,
    is_hotspot_host_or_hint,
    normalize_transport_mode,
    normalize_transport_type,
    sanitize_transport_error,
)
from snow.protocol.models import MessageType, SnowMessage
from snow.security.db import DatabaseManager
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferDirection, TransferManager
from snow.transfer.storage import TransferStorageManager


class TestM43UnifiedTransportModel(unittest.TestCase):
    """Stage 2: Verify strict USB > Hotspot > Wi-Fi > Remote priority and socket truth."""

    def test_canonical_priority_and_hotspot_classification(self) -> None:
        p_usb = classify_route_priority(transport="usb", host="127.0.0.1")
        p_hotspot = classify_route_priority(host="192.168.43.1")
        p_wifi = classify_route_priority(host="192.168.1.25")
        p_relay = classify_route_priority(transport="remote_relay", host="relay.snow.example")

        self.assertEqual((p_usb, p_hotspot, p_wifi, p_relay), (0, 1, 2, 3))
        self.assertEqual(classify_transport_badge(host="192.168.43.1"), "Hotspot • Zero Data")
        self.assertEqual(classify_transport_badge(interface_name="swlan0", host="10.0.0.5"), "Hotspot • Zero Data")
        self.assertTrue(is_hotspot_host_or_hint("192.168.137.1"))
        self.assertTrue(is_hotspot_host_or_hint("172.20.10.2"))

        candidates = [
            {"transport": "wifi_lan", "host": "192.168.1.5", "active": True},
            {"transport": "hotspot", "host": "192.168.43.1", "active": True},
            {"transport": "remote_relay", "host": "relay", "active": True},
        ]
        chosen = evaluate_preferred_route(candidates, connection_mode="auto")
        self.assertIsNotNone(chosen)
        self.assertEqual(chosen["priority"], 1)
        self.assertEqual(chosen["transport_badge"], "Hotspot • Zero Data")

        # Never pick unverified candidate
        unverified_usb = [
            {"transport": "usb", "host": "127.0.0.1", "verified": False},
            {"transport": "wifi_lan", "host": "192.168.1.5", "verified": True},
        ]
        chosen2 = evaluate_preferred_route(unverified_usb, connection_mode="auto")
        self.assertIsNotNone(chosen2)
        self.assertEqual(chosen2["transport"], "wifi_lan")

    def test_transfer_socket_classification_never_guesses_usb(self) -> None:
        # Even if USB mapping is active on system, socket coming from Wi-Fi IP stays Wi-Fi
        tt, badge = classify_transfer_socket_route(
            peer_ip="192.168.1.88",
            usb_mapping_verified=True,
        )
        self.assertEqual(tt, TransportType.WIFI_LAN)
        self.assertEqual(badge, "Wi-Fi • Zero Data")

        # Hotspot IP stays Hotspot even if USB mapping is active
        tt_hs, badge_hs = classify_transfer_socket_route(
            peer_ip="192.168.43.12",
            usb_mapping_verified=True,
        )
        self.assertEqual(tt_hs, TransportType.HOTSPOT)
        self.assertEqual(badge_hs, "Hotspot • Zero Data")

        # Loopback without verified ADB mapping cannot claim USB
        tt_no_adb, _ = classify_transfer_socket_route(
            peer_ip="127.0.0.1",
            usb_mapping_verified=False,
        )
        self.assertEqual(tt_no_adb, TransportType.WIFI_LAN)

        # Loopback WITH verified ADB mapping IS USB
        tt_usb, badge_usb = classify_transfer_socket_route(
            peer_ip="127.0.0.1",
            usb_mapping_verified=True,
        )
        self.assertEqual(tt_usb, TransportType.USB)
        self.assertEqual(badge_usb, "USB • Zero Data")

    def test_error_sanitization_redacts_secrets(self) -> None:
        clean = sanitize_transport_error("Bearer eyJhbGciOi failed auth_token=secret")
        self.assertNotIn("eyJhbGciOi", clean)
        self.assertNotIn("secret", clean)


class TestM43SessionRouterMBBAndManualSelection(unittest.IsolatedAsyncioTestCase):
    """Stage 3 & 5: Make-Before-Break probing, failure retention, failover, and manual lock."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(db_path=Path(self.tmpdir.name) / "test.db")
        self.db.insert_paired_device(
            device_id="dev-android-1",
            device_name="Pixel Phone",
            auth_token_hash=hashlib.sha256(b"tok-1").hexdigest(),
            last_known_host="192.168.1.50",
            last_known_port=8765,
            cert_fingerprint="aa" * 32,
        )
        self.registry = NodeRegistry(db_manager=self.db)
        self.registry.register_node(
            DeviceNode(
                device_id="dev-android-1",
                device_name="Pixel Phone",
                platform="android",
                host="192.168.1.50",
                wss_port=8765,
                transport="remote_relay",
                reachability_profile=ReachabilityProfile.ACTIVE_SESSION_PEER,
                reachability_state=ReachabilityState.ONLINE_RELAYED,
                is_paired=True,
            )
        )

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    async def test_mbb_failed_standby_preserves_existing_healthy_session(self) -> None:
        relay = MagicMock()
        relay._is_connected = True
        router = SessionRouter(
            node_registry=self.registry,
            db_manager=self.db,
            relay_client=relay,
            relay_enabled=True,
        )
        router.register_peer_token("dev-android-1", "tok-1")
        existing_wifi = MagicMock()
        existing_wifi.host = "192.168.1.50"
        existing_wifi.port = 8765
        existing_wifi.is_connected = True
        existing_wifi._pending_requests = {}
        router._outbound_clients["dev-android-1"] = existing_wifi
        router._outbound_transports["dev-android-1"] = TransportType.WIFI_LAN
        router.mark_route_verified("dev-android-1", TransportType.WIFI_LAN, host="192.168.1.50", is_active=True)

        bad_client = MagicMock()
        bad_client.connect = unittest.mock.AsyncMock(
            return_value=PeerConnectionResult(success=True, status="CONNECTED_UNAUTHENTICATED")
        )
        bad_client.close = unittest.mock.AsyncMock()

        with patch("snow.network.router.SnowPeerClient", return_value=bad_client):
            res = await router.promote_local_route("dev-android-1", host="127.0.0.1", transport="usb")

        self.assertFalse(res["promoted"])
        self.assertTrue(res["fallback_retained"])
        # Existing healthy Wi-Fi session MUST remain active and untouched
        self.assertIs(router._outbound_clients["dev-android-1"], existing_wifi)
        existing_wifi.close.assert_not_called()
        snap = router.get_device_transport_state("dev-android-1")
        self.assertEqual(snap["active_transport"], "wifi_lan")

    async def test_mbb_success_drains_inflight_and_switches_to_higher_priority(self) -> None:
        router = SessionRouter(node_registry=self.registry, db_manager=self.db)
        router.register_peer_token("dev-android-1", "tok-1")
        old_client = MagicMock()
        old_client.host = "192.168.1.50"
        old_client.is_connected = True
        old_client._pending_requests = {"req1": object()}
        old_client.close = unittest.mock.AsyncMock()
        router._outbound_clients["dev-android-1"] = old_client
        router._outbound_transports["dev-android-1"] = TransportType.WIFI_LAN
        router.mark_route_verified("dev-android-1", TransportType.WIFI_LAN, host="192.168.1.50", is_active=True)

        new_usb_client = MagicMock()
        new_usb_client.host = "127.0.0.1"
        new_usb_client.port = 8765
        new_usb_client.is_connected = True
        new_usb_client.connect = unittest.mock.AsyncMock(
            return_value=PeerConnectionResult(success=True, status="AUTHENTICATED", remote_device_id="dev-android-1")
        )
        new_usb_client.send_message = unittest.mock.AsyncMock(
            return_value=SnowMessage.create_response(correlation_id="1", payload={"status": "success", "action": "pong"})
        )
        new_usb_client.close = unittest.mock.AsyncMock()

        with patch("snow.network.router.SnowPeerClient", return_value=new_usb_client):
            promo = await router.promote_local_route(
                "dev-android-1", host="127.0.0.1", transport="usb", verify_ping=True
            )

        self.assertTrue(promo["promoted"])
        self.assertEqual(promo["transport_badge"], "USB • Zero Data")
        self.assertIs(router._outbound_clients["dev-android-1"], new_usb_client)
        # In-flight pending request kept old client open immediately upon cutover
        old_client.close.assert_not_called()
        # Drain finishes cleanly once pending clears
        old_client._pending_requests.clear()
        await asyncio.sleep(0.12)
        old_client.close.assert_called_once()

    async def test_manual_mode_fails_closed_when_unverified_and_prevents_silent_bypass(self) -> None:
        router = SessionRouter(node_registry=self.registry, db_manager=self.db)
        router.register_peer_token("dev-android-1", "tok-1")
        wifi_client = MagicMock()
        wifi_client.host = "192.168.1.50"
        wifi_client.port = 8765
        wifi_client.is_connected = True
        wifi_client._pending_requests = {}
        wifi_client.close = unittest.mock.AsyncMock()
        router._outbound_clients["dev-android-1"] = wifi_client
        router._outbound_transports["dev-android-1"] = TransportType.WIFI_LAN
        router.mark_route_verified("dev-android-1", TransportType.WIFI_LAN, host="192.168.1.50", is_active=True)

        # Fail closed when requesting unverified USB manual mode
        bad = await router.set_manual_transport_mode("dev-android-1", "usb", allow_probe=False)
        self.assertFalse(bad["success"])
        self.assertEqual(bad["status"], "ROUTE_UNAVAILABLE")
        self.assertEqual(router.get_device_transport_state("dev-android-1")["mode"], "auto")
        self.assertEqual(router.get_device_transport_state("dev-android-1")["active_transport"], "wifi_lan")

        # Manual switch to verified Wi-Fi succeeds, and on Wi-Fi loss does NOT silently jump to relay
        ok = await router.set_manual_transport_mode("dev-android-1", "wifi_lan", allow_probe=False)
        self.assertTrue(ok["success"])
        self.assertEqual(router.get_device_transport_state("dev-android-1")["mode"], "wifi_lan")

        relay_mock = MagicMock()
        relay_mock._is_connected = True
        router.relay_client = relay_mock
        router.relay_enabled = True
        loss = await router.handle_transport_loss("dev-android-1", "wifi_lan", "AP dropped")
        self.assertFalse(loss["success"])
        self.assertEqual(loss["status"], "MANUAL_ROUTE_UNAVAILABLE")

        # Reset back to auto allows automatic failover to relay
        await router.set_manual_transport_mode("dev-android-1", "auto", allow_probe=False)
        loss_auto = await router.handle_transport_loss("dev-android-1", "wifi_lan", "AP dropped")
        self.assertTrue(loss_auto["success"])
        self.assertEqual(loss_auto["active_transport"], "remote_relay")


class TestM43BidirectionalUsbAdb(unittest.IsolatedAsyncioTestCase):
    """Stage 4: Bidirectional ADB forward+reverse, conflict safety, unauthorized state & selective cleanup."""

    def test_forward_conflict_safety_and_selective_cleanup(self) -> None:
        calls: list[list[str]] = []

        def fake_run(cmd, **kwargs):
            calls.append(list(cmd))
            if "forward" in cmd and "--list" in cmd:
                # tcp:8767 already belongs to an external debugger on tcp:9999!
                return SimpleNamespace(returncode=0, stdout="ser123 tcp:8767 tcp:9999\n", stderr="")
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("snow.core.usb.get_connected_adb_devices", return_value=[{"serial": "ser123", "status": "device", "model": "Pixel"}]), \
             patch("subprocess.run", side_effect=fake_run):
            ok, msg, owned = setup_usb_forward(serial="ser123", adb_bin=Path("fake_adb"))

        self.assertFalse(ok)
        self.assertIn("tcp:8767", msg)
        # Only non-conflicting tcp:8769 should be mapped and owned by SNOW
        self.assertEqual(owned, ["tcp:8769"])

        remove_calls: list[list[str]] = []
        def fake_remove(cmd, **kwargs):
            remove_calls.append(list(cmd))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_remove):
            rm_ok, _ = remove_usb_forward(serial="ser123", adb_bin=Path("fake_adb"), owned_locals=owned)
        self.assertTrue(rm_ok)
        self.assertEqual(len(remove_calls), 1)
        self.assertEqual(remove_calls[0][-1], "tcp:8769")

    def test_unauthorized_and_offline_never_ready(self) -> None:
        with patch("snow.core.usb.get_connected_adb_devices", return_value=[{"serial": "u1", "status": "unauthorized", "model": "Phone"}]):
            stat = get_usb_bidirectional_status(adb_bin=Path("fake_adb"))
        self.assertFalse(stat["connected"])
        self.assertFalse(stat["usb_ready"])
        self.assertEqual(len(stat["unauthorized_devices"]), 1)

    async def test_usb_watcher_detach_triggers_loss_callback(self) -> None:
        detached: list[str] = []
        watcher = UsbWatcher(
            port=8765,
            adb_bin=Path("/mock/adb"),
            on_usb_detached=lambda s: detached.append(s),
        )
        with patch("snow.core.usb.get_connected_adb_devices", return_value=[{"serial": "dev1", "status": "device", "model": "Test"}]), \
             patch("snow.core.usb.get_usb_status", return_value={"reverse_active": True}), \
             patch("snow.core.usb.setup_usb_forward", return_value=(True, "ok", ["tcp:8769"])):
            await watcher._poll_once()
        self.assertIn("dev1", watcher._configured_serials)

        with patch("snow.core.usb.get_connected_adb_devices", return_value=[{"serial": "dev1", "status": "unauthorized", "model": "Test"}]), \
             patch("snow.core.usb.remove_usb_forward", return_value=(True, "removed")):
            await watcher._poll_once()
        self.assertEqual(detached, ["dev1"])
        self.assertNotIn("dev1", watcher._configured_serials)


class TestM43TransferSocketAttributionAndQuota(AioHTTPTestCase):
    """Stage 6: Verify HTTP transfer server socket attribution and relay quota enforcement."""

    async def get_application(self) -> web.Application:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(db_path=Path(self.tmpdir.name) / "tx.db")
        self.token_hash = hashlib.sha256(b"secret-tok").hexdigest()
        self.db.insert_paired_device(
            device_id="phone-1",
            device_name="Pixel",
            auth_token_hash=self.token_hash,
            last_known_host="192.168.43.1",
            last_known_port=8765,
        )
        # Inject auth token record via DatabaseManager token API if available, or mock validate
        self.tm = TransferManager()
        self.sm = TransferStorageManager(root_dir=Path(self.tmpdir.name) / "files")
        cfg = MagicMock()
        cfg.max_transfer_size = 16 * 1024 * 1024 * 1024
        cfg.auth_required = True
        self.srv = SnowHttpTransferServer(
            config=cfg,
            db_manager=self.db,
            transfer_manager=self.tm,
            storage_manager=self.sm,
            usb_ready_checker=lambda: False,
            max_relay_transfer_bytes=1024,
        )
        return self.srv.app

    async def tearDownAsync(self) -> None:
        await super().tearDownAsync()
        self.tmpdir.cleanup()

    async def test_socket_route_attribution_never_fakes_usb_and_enforces_relay_quota(self) -> None:
        headers = {
            "X-Snow-Device-Id": "phone-1",
            "Authorization": "Bearer secret-tok",
        }
        # Over 127.0.0.1 WITHOUT usb_ready_checker=True -> must NOT say USB
        resp = await self.client.post(
            "/api/v1/transfers/init",
            headers=headers,
            json={
                "file_name": "video.mp4",
                "file_size": 100,
                "sha256": "a" * 64,
                "direction": "UPLOAD",
            },
        )
        self.assertEqual(resp.status, 200)
        body = await resp.json()
        self.assertEqual(body["transport"], "wifi_lan")
        self.assertEqual(body["transport_badge"], "Wi-Fi • Zero Data")

        # Hotspot transport hint -> Hotspot • Zero Data even if USB checker returns True
        self.srv.usb_ready_checker = lambda: True
        resp_hs = await self.client.post(
            "/api/v1/transfers/init",
            headers={**headers, "X-Snow-Transport-Hint": "hotspot"},
            json={
                "file_name": "hs.bin",
                "file_size": 100,
                "sha256": "b" * 64,
                "direction": "UPLOAD",
            },
        )
        self.assertEqual(resp_hs.status, 200)
        body_hs = await resp_hs.json()
        self.assertEqual(body_hs["transport"], "hotspot")
        self.assertEqual(body_hs["transport_badge"], "Hotspot • Zero Data")

        # Oversized Remote Relay transfer rejected upfront with HTTP 413 + actionable guidance
        resp_relay = await self.client.post(
            "/api/v1/transfers/init",
            headers={**headers, "X-Snow-Relay": "1"},
            json={
                "file_name": "huge.iso",
                "file_size": 4096,
                "sha256": "c" * 64,
                "direction": "UPLOAD",
            },
        )
        self.assertEqual(resp_relay.status, 413)
        body_relay = await resp_relay.json()
        self.assertEqual(body_relay["status"], "RELAY_QUOTA_EXCEEDED")
        self.assertIn("USB, Hotspot, or Wi-Fi LAN", body_relay["error"])

        # Verify DOWNLOAD streaming headers stay HTTP Latin-1 safe and carry route truth
        dl_path = self.sm.root_dir / "dl_sample.bin"
        dl_bytes = b"0123456789ABCDEF" * 8
        dl_path.write_bytes(dl_bytes)
        dl_sha = hashlib.sha256(dl_bytes).hexdigest()
        dl_rec = self.tm.create_transfer(
            device_id="phone-1",
            file_name="dl_sample.bin",
            file_size=len(dl_bytes),
            sha256=dl_sha,
            direction=TransferDirection.DOWNLOAD,
            file_path=str(dl_path),
        )
        dl_resp = await self.client.get(
            f"/api/v1/transfers/download/{dl_rec.transfer_id}",
            headers={**headers, "X-Snow-Transport-Hint": "hotspot"},
        )
        self.assertEqual(dl_resp.status, 200)
        self.assertEqual(dl_resp.headers.get("X-Snow-Transport-Route"), "hotspot")
        self.assertEqual(dl_resp.headers.get("X-Snow-Transport-Badge"), "Hotspot - Zero Data")
        self.assertEqual(await dl_resp.read(), dl_bytes)


class TestM43ManualTransportApiAndIpc(AioHTTPTestCase):
    """Stage 5: Verify /api/devices/transport, /api/devices, and IPC transport_state exposure."""

    async def get_application(self) -> web.Application:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(db_path=Path(self.tmpdir.name) / "api.db")
        self.db.insert_paired_device(
            device_id="phone-api-1",
            device_name="Galaxy S24",
            auth_token_hash=hashlib.sha256(b"api-tok").hexdigest(),
            last_known_host="192.168.43.5",
            last_known_port=8765,
        )
        self.registry = NodeRegistry(db_manager=self.db)
        self.registry.register_node(
            DeviceNode(
                device_id="phone-api-1",
                device_name="Galaxy S24",
                platform="android",
                host="192.168.43.5",
                wss_port=8765,
                transport="hotspot",
                is_paired=True,
                reachability_state=ReachabilityState.CONNECTED_SESSION,
            )
        )
        self.router = SessionRouter(node_registry=self.registry, db_manager=self.db)
        self.router.mark_route_verified("phone-api-1", TransportType.WIFI_LAN, host="192.168.1.25", is_active=True)
        self.router.mark_route_verified("phone-api-1", TransportType.HOTSPOT, host="192.168.43.5", is_active=False)

        router_ref = self.router
        reg_ref = self.registry

        class _FakeBridge:
            async def set_device_connection_mode(self, device_id: str, connection_mode: str, allow_probe: bool = True):
                return await router_ref.set_manual_transport_mode(device_id, connection_mode, allow_probe=False)

            async def list_devices(self):
                devs = []
                for n in reg_ref.list_nodes(filter_paired=True):
                    d = n.to_summary_dict()
                    d["transport_state"] = router_ref.get_device_transport_state(n.device_id)
                    devs.append(d)
                return {"success": True, "status": "SUCCESS", "data": {"devices": devs}}

        from snow.web.server import SnowWebServer
        self.web_srv = SnowWebServer.__new__(SnowWebServer)
        self.web_srv.bridge = _FakeBridge()

        app = web.Application()
        app.router.add_get("/api/devices", self.web_srv.handle_api_devices)
        app.router.add_post("/api/devices/transport", self.web_srv.handle_api_devices_transport)
        app.router.add_post("/api/devices/connection-mode", self.web_srv.handle_api_devices_connection_mode)
        return app

    async def tearDownAsync(self) -> None:
        await super().tearDownAsync()
        self.tmpdir.cleanup()

    async def test_manual_transport_endpoint_and_devices_snapshot(self) -> None:
        # Unverified USB rejected fail-closed with HTTP 409 and preserves wifi_lan active
        r_bad = await self.client.post(
            "/api/devices/transport",
            json={"device_id": "phone-api-1", "mode": "usb", "allow_probe": False},
        )
        self.assertEqual(r_bad.status, 409)
        b_bad = await r_bad.json()
        self.assertFalse(b_bad["success"])
        self.assertEqual(b_bad["status"], "ROUTE_UNAVAILABLE")

        # Verified Hotspot switch succeeds with HTTP 200 and accurate badge
        r_ok = await self.client.post(
            "/api/devices/transport",
            json={"device_id": "phone-api-1", "mode": "hotspot", "allow_probe": False},
        )
        self.assertEqual(r_ok.status, 200)
        b_ok = await r_ok.json()
        self.assertTrue(b_ok["success"])
        self.assertEqual(b_ok["active_transport"], "hotspot")
        self.assertEqual(b_ok["transport_badge"], "Hotspot • Zero Data")

        # /api/devices exposes transport_state cleanly without secret leakage
        r_devs = await self.client.get("/api/devices")
        self.assertEqual(r_devs.status, 200)
        b_devs = await r_devs.json()
        dev = next(d for d in b_devs["devices"] if d["device_id"] == "phone-api-1")
        self.assertEqual(dev["transport_state"]["mode"], "hotspot")
        self.assertEqual(dev["transport_state"]["active_transport"], "hotspot")
        self.assertEqual(len(dev["transport_state"]["routes"]), 4)
        self.assertNotIn("auth_token", json.dumps(dev))

        # IPC _handle_list_devices & _handle_android_file_send relay quota check
        from snow.core.ipc import SnowIpcServer
        fake_cs = SimpleNamespace(
            session_router=self.router,
            db_manager=self.db,
            config=SimpleNamespace(max_transfer_size=16 * 1024 * 1024 * 1024, max_relay_transfer_bytes=128),
            windows_files=MagicMock(),
            transfer_manager=TransferManager(),
            storage_manager=MagicMock(),
            session_manager=MagicMock(),
            connection_manager=MagicMock(),
            ws_server=MagicMock(),
            http_transfer_server=None,
        )
        sample_file = Path(self.tmpdir.name) / "big_relay.bin"
        sample_file.write_bytes(b"X" * 512)
        fake_cs.windows_files.resolve_safe_path.return_value = (sample_file, None)

        ipc = SnowIpcServer.__new__(SnowIpcServer)
        ipc.core_server = fake_cs
        ipc.node_registry = self.registry
        ipc.session_router = self.router

        listed = ipc._handle_list_devices()
        phone_ipc = next(d for d in listed if d["device_id"] == "phone-api-1")
        self.assertEqual(phone_ipc["transport_badge"], "Hotspot • Zero Data")
        self.assertEqual(phone_ipc["transport_state"]["mode"], "hotspot")

        # Force Remote Relay active and confirm IPC send enforces relay quota cleanly
        self.router.relay_enabled = True
        self.router.relay_client = SimpleNamespace(_is_connected=True)
        self.router.mark_route_verified("phone-api-1", TransportType.REMOTE_RELAY, host="relay", is_active=True)
        set_relay_res = await self.router.set_manual_transport_mode("phone-api-1", "remote_relay", allow_probe=False)
        self.assertTrue(set_relay_res["success"])
        quota_res = await ipc._handle_android_file_send({"device_id": "phone-api-1", "file_path": str(sample_file)})
        self.assertFalse(quota_res["success"])
        self.assertEqual(quota_res["status"], "RELAY_QUOTA_EXCEEDED")
        self.assertIn("USB, Hotspot, or Wi-Fi LAN", quota_res["error"])


if __name__ == "__main__":
    unittest.main()
