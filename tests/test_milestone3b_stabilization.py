"""Milestone 3B physical-QA stabilization regression tests."""

import os
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from snow.core.config import CoreConfig
from snow.core.server import SnowCoreServer
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import DeviceIdentity
from snow.security.session import SessionManager


class TestMilestone3BSection2ScreenTargets(unittest.IsolatedAsyncioTestCase):
    """Section 2: Verify list_eligible_screen_targets & SessionManager enumerate real sessions."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m3b_s2_"))
        self._prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = str(self.tmp_dir / "data")
        self.db_path = self.tmp_dir / "snow.db"
        self.db = DatabaseManager(self.db_path)
        self.local_uuid = str(uuid.uuid4())
        self.identity = DeviceIdentity(
            device_id=self.local_uuid,
            device_name="Lenovo V15",
            created_at="2026-01-01T00:00:00Z",
        )
        self.cfg = CoreConfig(
            transfer_root=str(self.tmp_dir / "transfers"),
        )
        self.server = SnowCoreServer(config=self.cfg, db_manager=self.db, device_identity=self.identity)

    def tearDown(self) -> None:
        if self._prev_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self._prev_data_dir
        try:
            self.db.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def _register_paired_and_connect(
        self,
        device_id: str,
        name: str,
        platform: str,
        profile: str,
        *,
        remote_address: str = "('192.168.1.42', 55000)",
        conn_id: str = "conn-1",
    ) -> SimpleNamespace:
        self.db.insert_paired_device(device_id, name, hash_token(f"tok-{device_id}"), platform=platform)
        self.db.set_setting(f"device_profile:{device_id}", profile)
        conn = SimpleNamespace(connection_id=conn_id, remote_address=remote_address, is_active=True, websocket=MagicMock())
        self.server.ws_server.connection_manager._connections[conn_id] = conn
        self.server.ws_server.session_manager.create_session(device_id=device_id, connection_id=conn_id, trust_tier="peer")
        return conn

    async def test_pc_to_phone_pc_to_pc_and_phone_to_phone_enumeration_and_disconnect(self) -> None:
        # 1. Android phone connected over USB 127.0.0.1 with full_control
        conn_phone_a = self._register_paired_and_connect(
            "phone-a",
            "Realme P4",
            "android",
            "full_control",
            remote_address="('127.0.0.1', 54321)",
            conn_id="c-phone-a",
        )
        # 2. Second Android phone connected over Wi-Fi with full_control
        self._register_paired_and_connect(
            "phone-b",
            "Pixel Backup",
            "android",
            "full_control",
            remote_address="('192.168.1.77', 54322)",
            conn_id="c-phone-b",
        )
        # 3. Restricted phone (files_only) MUST be excluded
        self._register_paired_and_connect(
            "phone-restricted",
            "Guest Phone",
            "android",
            "files_only",
            remote_address="('192.168.1.88', 54323)",
            conn_id="c-phone-restricted",
        )
        # 4. Outbound peer PC (PC -> PC) with full_control + inbound peer PC
        self.db.insert_paired_device("pc-peer-out", "Office Workstation", hash_token("tok-pc-out"), platform="windows")
        self.db.set_setting("device_profile:pc-peer-out", "full_control")
        self.server.peer_clients["pc-peer-out"] = SimpleNamespace(
            is_connected=True,
            host="192.168.1.99",
            remote_device_name="Office Workstation",
        )

        # 5. Relay-connected paired device with full_control & completed E2E handshake
        self.db.insert_paired_device("phone-relay", "Travel Phone", hash_token("tok-relay"), platform="android")
        self.db.set_setting("device_profile:phone-relay", "full_control")
        self.server.relay_enabled = True
        self.server.relay_client = SimpleNamespace(
            _is_connected=True,
            _tunnels={"phone-relay": SimpleNamespace(handshake_done=True)},
        )

        # Verify SessionManager exposes get_all_sessions compatibly with list_active_sessions
        sess_mgr = self.server.ws_server.session_manager
        self.assertEqual(len(sess_mgr.list_active_sessions()), 3)
        self.assertEqual(len(sess_mgr.get_all_sessions()), 3)

        targets = self.server.list_eligible_screen_targets()
        ids = {t["device_id"] for t in targets}
        self.assertEqual(ids, {"phone-a", "phone-b", "pc-peer-out", "phone-relay"})
        self.assertNotIn("phone-restricted", ids)
        self.assertNotIn(self.local_uuid, ids)

        phone_a_entry = next(t for t in targets if t["device_id"] == "phone-a")
        self.assertIn("USB", phone_a_entry["route_badge"])

        # Attempting to start screen share to restricted profile fails closed
        denied = await self.server.start_pc_screen_share(target_device_ids=["phone-restricted"])
        self.assertFalse(denied["success"])
        self.assertEqual(denied["status"], "NO_ELIGIBLE_TARGETS")

        # Disconnecting phone-a removes it immediately from eligible targets
        conn_phone_a.is_active = False
        sess_mgr.revoke_device_sessions("phone-a")
        after_disconnect_ids = {t["device_id"] for t in self.server.list_eligible_screen_targets()}
        self.assertNotIn("phone-a", after_disconnect_ids)
        self.assertEqual(after_disconnect_ids, {"phone-b", "pc-peer-out", "phone-relay"})


class TestMilestone3BSection3ClipboardImageDeduplication(unittest.IsolatedAsyncioTestCase):
    """Section 3.3: Verify desktop_clipboard_set suppresses duplicate/echoed images vs top item."""

    def setUp(self) -> None:
        from snow.capabilities.clipboard_buffer import ClipboardRingBuffer
        from snow.network.ws_server import SnowWebSocketServer

        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m3b_s3_"))
        self.db = DatabaseManager(self.tmp_dir / "snow.db")
        self.ident = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Desktop V15",
            created_at="2026-01-01T00:00:00Z",
        )
        self.cfg = CoreConfig(transfer_root=str(self.tmp_dir / "transfers"))
        self.ws = SnowWebSocketServer(config=self.cfg, db_manager=self.db, device_identity=self.ident)
        self.cb_buf = ClipboardRingBuffer(storage_dir=self.tmp_dir / "cb_buf", db_manager=self.db)
        self.ws.clipboard_buffer = self.cb_buf
        self.ws.capability_engine.clipboard_buffer = self.cb_buf

    def tearDown(self) -> None:
        try:
            self.db.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    @staticmethod
    def _make_png(color: tuple[int, int, int], size: tuple[int, int] = (24, 24)) -> bytes:
        from io import BytesIO
        from PIL import Image

        buf = BytesIO()
        Image.new("RGB", size, color).save(buf, format="PNG")
        return buf.getvalue()

    async def test_echoed_identical_and_canonical_image_suppressed_distinct_passes(self) -> None:
        import hashlib
        import json
        from io import BytesIO
        from PIL import Image, PngImagePlugin
        from snow.protocol.models import SnowMessage
        from snow.security.session import SessionRecord

        png_a = self._make_png((220, 40, 40))
        sha_a = hashlib.sha256(png_a).hexdigest()

        # Re-encoded PNG with different metadata / palette representation of same visual image
        img = Image.open(BytesIO(png_a))
        meta = PngImagePlugin.PngInfo()
        meta.add_text("Comment", "re-encoded-on-android")
        buf2 = BytesIO()
        img.save(buf2, format="PNG", pnginfo=meta, compress_level=1)
        png_a_reencoded = buf2.getvalue()
        self.assertNotEqual(png_a, png_a_reencoded)
        sha_a_re = hashlib.sha256(png_a_reencoded).hexdigest()

        # Distinct image B
        png_b = self._make_png((20, 180, 90))
        sha_b = hashlib.sha256(png_b).hexdigest()

        # Seed top buffer item with image A from desktop
        seed = self.cb_buf.add_image(
            image_bytes=png_a,
            mime_type="image/png",
            source_device_id=self.ident.device_id,
            source_device_name="Desktop V15",
        )
        self.assertTrue(seed["success"])
        initial_count = len(self.cb_buf.list_items())
        self.assertEqual(initial_count, 1)

        # Stage both echoed files via transfer manager
        up_dir = self.ws.storage_manager.root_dir
        up_dir.mkdir(parents=True, exist_ok=True)
        (up_dir / "echo_exact.png").write_bytes(png_a)
        (up_dir / "echo_reencoded.png").write_bytes(png_a_reencoded)
        (up_dir / "distinct_b.png").write_bytes(png_b)

        set_image_mock = MagicMock(return_value={"success": True, "status": "COPIED"})
        self.ws.capability_engine.clipboard.set_image_sync = set_image_mock
        broadcast_mock = AsyncMock(return_value=None)
        self.ws.broadcast_clipboard_buffer_event = broadcast_mock

        sent_msgs: list[str] = []

        async def cap_send(raw: str) -> None:
            sent_msgs.append(raw)

        fake_client = SimpleNamespace(
            connection_id="c-android-1",
            websocket=SimpleNamespace(send=cap_send),
        )
        session = SessionRecord(
            session_id="sess-1",
            device_id="phone-android-1",
            connection_id="c-android-1",
            created_at="2026-01-01T00:00:00Z",
            last_seen="2026-01-01T00:00:00Z",
            trust_tier="peer",
        )

        # 1. Exact SHA-256 echo suppressed
        msg1 = SnowMessage.create_request(
            "desktop_clipboard_set",
            data={"type": "image", "sha256": sha_a, "file_name": "echo_exact.png"},
        )
        await self.ws._handle_desktop_clipboard_set(fake_client, msg1, msg1.data, session)
        resp1 = json.loads(sent_msgs[-1])
        self.assertEqual(resp1["payload"]["status"], "success")
        self.assertTrue(resp1["payload"]["data"]["deduplicated"])
        set_image_mock.assert_not_called()
        broadcast_mock.assert_not_called()
        self.assertEqual(len(self.cb_buf.list_items()), 1)

        # 2. Canonical re-encoded PNG echo suppressed too
        msg2 = SnowMessage.create_request(
            "desktop_clipboard_set",
            data={"type": "image", "sha256": sha_a_re, "file_name": "echo_reencoded.png"},
        )
        await self.ws._handle_desktop_clipboard_set(fake_client, msg2, msg2.data, session)
        resp2 = json.loads(sent_msgs[-1])
        self.assertEqual(resp2["payload"]["status"], "success")
        self.assertTrue(resp2["payload"]["data"]["deduplicated"])
        set_image_mock.assert_not_called()
        broadcast_mock.assert_not_called()
        self.assertEqual(len(self.cb_buf.list_items()), 1)

        # 3. Distinct image B still applies normally and updates buffer
        msg3 = SnowMessage.create_request(
            "desktop_clipboard_set",
            data={"type": "image", "sha256": sha_b, "file_name": "distinct_b.png"},
        )
        await self.ws._handle_desktop_clipboard_set(fake_client, msg3, msg3.data, session)
        resp3 = json.loads(sent_msgs[-1])
        self.assertEqual(resp3["payload"]["status"], "success")
        set_image_mock.assert_called_once()
        self.assertEqual(len(self.cb_buf.list_items()), 2)


class TestMilestone3BSection4WebUiDisconnectAllAndRemoteAiLink(unittest.IsolatedAsyncioTestCase):
    """Section 4: Web UI timeouts, Disconnect All, Remote AI Link auto-start/persistence, Notification cleanup."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m3b_s4_"))
        self._prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = str(self.tmp_dir / "data")
        (self.tmp_dir / "data").mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        if self._prev_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self._prev_data_dir
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_web_ui_disconnect_all_and_notification_cleanup_preserving_quick_reply_and_pairing(self) -> None:
        static_dir = Path(__file__).resolve().parents[1] / "src" / "snow" / "web" / "static"
        html = (static_dir / "index.html").read_text(encoding="utf-8")
        js = (static_dir / "app.js").read_text(encoding="utf-8")

        # 4.2 Pause replaced with Disconnect All in Web sidebar
        self.assertNotIn("btn-desktop-pause", html)
        self.assertNotIn("btn-desktop-pause", js)
        self.assertIn("btn-desktop-disconnect-all", html)
        self.assertIn("Disconnect All", html)
        self.assertIn("/api/devices/disconnect-all", js)

        # 4.4 Clear All & Dismiss removed while Quick Reply & Pairing controls remain intact
        self.assertNotIn("btn-notifications-clear-all", html)
        self.assertNotIn("btn-notifications-clear-all", js)
        self.assertNotIn("btn-notif-dismiss", js)
        self.assertIn("btn-toggle-reply", js)
        self.assertIn("notif-inline-reply", js)
        self.assertIn("/api/notifications/reply", js)
        self.assertIn("btn-pairing-refresh-qr", html)
        self.assertIn("btn-pairing-connect", html)

        # 4.1 AbortController timeout + sequence guards in app.js
        self.assertIn("AbortController", js)
        self.assertIn("homeWidgetsSeq", js)
        self.assertIn("pollStateSeq", js)

    async def test_disconnect_all_closes_sessions_and_preserves_pairings_and_core(self) -> None:
        import uuid as _uuid

        db = DatabaseManager(self.tmp_dir / "snow.db")
        try:
            db.insert_paired_device("phone-1", "Phone One", hash_token("tok-p1"), platform="android")
            local_uuid = str(_uuid.uuid4())
            ident = DeviceIdentity(device_id=local_uuid, device_name="Lenovo V15", created_at="2026-01-01T00:00:00Z")
            cfg = CoreConfig(transfer_root=str(self.tmp_dir / "transfers"))
            core = SnowCoreServer(config=cfg, db_manager=db, device_identity=ident)

            db.insert_paired_device("pc-2", "Peer PC", hash_token("tok-pc2"), platform="windows")

            ws1 = MagicMock()
            ws1.send = AsyncMock(return_value=None)
            ws1.close = AsyncMock(return_value=None)
            conn1 = SimpleNamespace(connection_id="c1", remote_address="('192.168.1.5', 1234)", is_active=True, websocket=ws1)
            core.ws_server.connection_manager._connections["c1"] = conn1
            core.ws_server.session_manager.create_session(device_id="phone-1", connection_id="c1", trust_tier="owner")

            peer_client = SimpleNamespace(is_connected=True, close=AsyncMock(return_value=None))
            core.peer_clients["pc-2"] = peer_client
            core.disconnect_peer = AsyncMock(return_value={"success": True, "status": "DISCONNECTED"})

            relay_closed: list[str] = []

            async def close_tunnel_mock(did: str) -> None:
                relay_closed.append(did)
                core.relay_client._tunnels.pop(did, None)

            core.relay_client = SimpleNamespace(
                _tunnels={"phone-1": SimpleNamespace(handshake_done=True)},
                close_tunnel=close_tunnel_mock,
            )

            res = await core.disconnect_all_devices(reason="Owner sidebar click")
            self.assertTrue(res["success"])
            self.assertEqual(res["disconnected_count"], 2)
            self.assertEqual(set(res["disconnected_device_ids"]), {"phone-1", "pc-2"})
            self.assertEqual(relay_closed, ["phone-1"])
            ws1.close.assert_awaited_once()
            self.assertEqual(len(core.ws_server.session_manager.list_active_sessions()), 0)

            # Pairings in SQLite MUST remain intact!
            self.assertIsNotNone(db.get_paired_device("phone-1"))
            self.assertIsNotNone(db.get_paired_device("pc-2"))
        finally:
            pass

    async def test_web_notifications_timeout_bounded_and_disconnect_all_route(self) -> None:
        import asyncio
        from aiohttp.test_utils import TestClient, TestServer
        from snow.web.server import SnowWebServer

        bridge = MagicMock()
        bridge.capability_engine = MagicMock(db_manager=None)
        bridge.daemon_manager = MagicMock()
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)
        bridge.disconnect_all_devices = AsyncMock(return_value={"success": True, "status": "DISCONNECTED_ALL", "disconnected_count": 2})

        async def _hang_notifications(device_id: str = ""):
            await asyncio.sleep(10)
            return {"success": True, "notifications": []}

        bridge.android_notifications_list = _hang_notifications

        web_srv = SnowWebServer(host="127.0.0.1", port=0, bridge=bridge, auto_open_browser=False)
        async with TestClient(TestServer(web_srv._build_app())) as cli:
            auth = await (await cli.post("/api/auth/session", json={"token": web_srv.bootstrap_token})).json()
            csrf = auth["csrf_token"]

            r_notif = await cli.get("/api/notifications")
            j_notif = await r_notif.json()
            self.assertFalse(j_notif["success"])
            self.assertEqual(j_notif["status"], "TIMEOUT")

            r_disc = await cli.post("/api/devices/disconnect-all", json={}, headers={"X-CSRF-Token": csrf})
            j_disc = await r_disc.json()
            self.assertTrue(j_disc["success"])
            self.assertEqual(j_disc["disconnected_count"], 2)

            # Shared HTTP session creation + cleanup
            s1 = await web_srv._get_http_session()
            s2 = await web_srv._get_http_session()
            self.assertIs(s1, s2)
        await web_srv.stop()
        self.assertIsNone(web_srv._http_session)

    async def test_remote_ai_link_autostart_dedup_transient_outage_and_manual_stop(self) -> None:
        import asyncio
        import socket
        from unittest.mock import patch
        from aiohttp.test_utils import TestClient, TestServer
        from snow.mcp.tunnel import is_remote_ai_link_enabled, load_tunnel_config
        from snow.web.server import SnowWebServer

        self.assertTrue(is_remote_ai_link_enabled())

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_web:
            s_web.bind(("127.0.0.1", 0))
            web_port = int(s_web.getsockname()[1])

        bridge = MagicMock()
        bridge.capability_engine = MagicMock(db_manager=None)
        bridge.daemon_manager = MagicMock()
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)

        web_srv = SnowWebServer(host="127.0.0.1", port=web_port, bridge=bridge, auto_open_browser=False)

        gw_starts = 0
        gw_public_urls: list[str | None] = []

        async def _fake_start_gateway(host: str = "127.0.0.1", port: int = 8771, bridge=None):
            nonlocal gw_starts
            gw_starts += 1
            fake_runner = SimpleNamespace(cleanup=AsyncMock(return_value=None))
            fake_site = SimpleNamespace()
            fake_gateway = SimpleNamespace(set_public_url=lambda u: gw_public_urls.append(u))
            return fake_runner, fake_site, fake_gateway

        start_calls = 0

        async def _fake_forwarder_start(self_fwd, timeout: float = 12.0):
            nonlocal start_calls
            start_calls += 1
            self_fwd.is_connected = True
            return True, None

        async def _fake_forwarder_stop(self_fwd):
            self_fwd.is_connected = False

        try:
            with patch("snow.mcp.remote_gateway.start_gateway_async", new=_fake_start_gateway), \
                 patch("snow.relay.mcp_forwarder.RelayMcpForwarder.start", new=_fake_forwarder_start), \
                 patch("snow.relay.mcp_forwarder.RelayMcpForwarder.stop", new=_fake_forwarder_stop):
                await web_srv.start()
                if web_srv._remote_ai_autostart_task:
                    await asyncio.wait_for(web_srv._remote_ai_autostart_task, timeout=5.0)
                self.assertEqual(gw_starts, 1)
                self.assertEqual(start_calls, 1)
                self.assertTrue(web_srv.tunnel_manager.get_status()["active"])

                # Deduplication: repeat call does NOT spawn duplicate gateway or forwarder
                dup_res = await web_srv.ensure_remote_ai_link_running(provider="render", mark_enabled=False)
                self.assertTrue(dup_res["success"])
                self.assertEqual(dup_res["status"], "ALREADY_RUNNING")
                self.assertEqual(gw_starts, 1)
                self.assertEqual(start_calls, 1)
        finally:
            await web_srv.stop()

        # Transient network outage MUST preserve remote_ai_link_enabled=True
        web_srv2 = SnowWebServer(host="127.0.0.1", port=0, bridge=bridge, auto_open_browser=False)

        async def _fake_forwarder_fail(self_fwd, timeout: float = 12.0):
            self_fwd.is_connected = False
            return False, "Simulated Render Hub offline"

        try:
            with patch("snow.mcp.remote_gateway.start_gateway_async", new=_fake_start_gateway), \
                 patch("snow.relay.mcp_forwarder.RelayMcpForwarder.start", new=_fake_forwarder_fail):
                fail_res = await web_srv2.ensure_remote_ai_link_running(provider="render", mark_enabled=False)
                self.assertFalse(fail_res["success"])
                self.assertTrue(is_remote_ai_link_enabled())
                self.assertTrue(bool(web_srv2._remote_ai_link_last_error))
        finally:
            await web_srv2.stop()

        # Explicit user Stop sets remote_ai_link_enabled=False and next SnowWebServer.start() skips autostart
        web_srv3 = SnowWebServer(host="127.0.0.1", port=web_port, bridge=bridge, auto_open_browser=False)
        try:
            async with TestClient(TestServer(web_srv3._build_app())) as cli:
                auth = await (await cli.post("/api/auth/session", json={"token": web_srv3.bootstrap_token})).json()
                csrf = auth["csrf_token"]
                stop_resp = await cli.post("/api/mcp/tunnel/stop", json={}, headers={"X-CSRF-Token": csrf})
                self.assertEqual(stop_resp.status, 200)
                self.assertFalse(is_remote_ai_link_enabled())
                self.assertIs(load_tunnel_config().get("remote_ai_link_enabled"), False)
        finally:
            await web_srv3.stop()

        # Next SnowWebServer.start() MUST NOT auto-start when user explicitly stopped
        autostart_count = 0

        async def _count_start(self_fwd, timeout: float = 12.0):
            nonlocal autostart_count
            autostart_count += 1
            return True, None

        web_srv4 = SnowWebServer(host="127.0.0.1", port=web_port, bridge=bridge, auto_open_browser=False)
        try:
            with patch("snow.mcp.remote_gateway.start_gateway_async", new=_fake_start_gateway), \
                 patch("snow.relay.mcp_forwarder.RelayMcpForwarder.start", new=_count_start):
                await web_srv4.start()
                self.assertIsNone(web_srv4._remote_ai_autostart_task)
                self.assertEqual(autostart_count, 0)
        finally:
            await web_srv4.stop()


class TestMilestone3BSection5RenderHubDesktopRemoteAccess(unittest.IsolatedAsyncioTestCase):
    """Section 5.2: Desktop Remote Access defaults to Render Hub with Ed25519 hub auth (zero cloudflared)."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m3b_s5_"))
        self._prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = str(self.tmp_dir / "data")
        (self.tmp_dir / "data").mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        if self._prev_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self._prev_data_dir
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_web_remote_access_defaults_to_render_hub_and_core_authenticates_with_hub_token(self) -> None:
        from aiohttp.test_utils import TestClient, TestServer
        from snow.core.config import CoreConfig
        from snow.core.server import SnowCoreServer
        from snow.web.server import SnowWebServer

        tls_dir = self.tmp_dir / "data" / "tls"
        tls_dir.mkdir(parents=True, exist_ok=True)
        cert_path = tls_dir / "server.crt"
        key_path = tls_dir / "server.key"
        cert_path.write_text("dummy-cert", encoding="utf-8")
        key_path.write_text("dummy-key", encoding="utf-8")

        fake_db = MagicMock()
        settings_store: dict[str, str] = {}
        fake_db.set_setting.side_effect = lambda k, v: settings_store.__setitem__(str(k), str(v))
        fake_db.get_setting.side_effect = lambda k, default="": settings_store.get(str(k), default)
        fake_db.list_paired_devices.return_value = []

        cfg = CoreConfig(
            tls_cert_path=str(cert_path),
            tls_key_path=str(key_path),
            transfer_root=str(self.tmp_dir / "transfers"),
        )
        core = SnowCoreServer(config=cfg, db_manager=fake_db)
        core.session_router = SimpleNamespace(relay_enabled=False, relay_client=None)

        created_clients: list[Any] = []

        from typing import Any

        class _FakeRelayClient:
            def __init__(self, **kwargs: Any) -> None:
                self.kwargs = kwargs
                self.relay_url = kwargs["relay_url"]
                self.group_id = kwargs["group_id"]
                self._is_connected = False
                self._tunnels = {}
                self.request_dispatcher = None
                self.media_frame_handler = None
                created_clients.append(self)

            def set_peer_pinned_fingerprint(self, did: str, fp: str) -> None:
                pass

            async def connect(self) -> bool:
                self._is_connected = True
                return True

            async def disconnect(self) -> None:
                self._is_connected = False

        async def _fake_acquire_hub(hub_http_url: str, timeout: float = 8.0):
            return True, "hub_sess_tok_3b", "SNW-NET-TEST01", ""

        bridge = MagicMock()
        bridge.capability_engine = SimpleNamespace(db_manager=fake_db)

        async def _set_relay_config(enabled: bool, relay_url: str = "", group_id: str = "", ticket: str = ""):
            res = await core.configure_relay(enabled=enabled, relay_url=relay_url, group_id=group_id, ticket=ticket)
            return {"success": True, "status": "SUCCESS", "data": res}

        async def _get_relay_config():
            return {"success": True, "status": "SUCCESS", "data": core.get_relay_status()}

        bridge.set_relay_config = AsyncMock(side_effect=_set_relay_config)
        bridge.get_relay_config = AsyncMock(side_effect=_get_relay_config)

        web_srv = SnowWebServer(host="127.0.0.1", port=0, bridge=bridge, auto_open_browser=False)

        with patch.object(core, "_acquire_relay_hub_session", side_effect=_fake_acquire_hub), \
             patch("snow.network.relay_client.RelayTunnelClient", _FakeRelayClient):
            async with TestClient(TestServer(web_srv._build_app())) as cli:
                auth = await (await cli.post("/api/auth/session", json={"token": web_srv.bootstrap_token})).json()
                csrf = auth["csrf_token"]

                # Calling /api/relay/tunnel/start with no cloudflared binary defaults cleanly to Render Hub
                start_resp = await cli.post("/api/relay/tunnel/start", json={}, headers={"X-CSRF-Token": csrf})
                self.assertEqual(start_resp.status, 200)
                start_data = await start_resp.json()
                self.assertTrue(start_data["success"])
                self.assertEqual(start_data["provider"], "render")
                self.assertTrue(start_data["active"])
                self.assertEqual(start_data["public_url"], "wss://snow-relay.onrender.com/v1/tunnel")
                self.assertEqual(settings_store.get("remote_relay_enabled"), "true")

                self.assertEqual(len(created_clients), 1)
                self.assertEqual(created_clients[0].kwargs.get("hub_token"), "hub_sess_tok_3b")
                self.assertEqual(created_clients[0].kwargs.get("network_id"), "SNW-NET-TEST01")

                # Status reflects active Render Hub relay
                stat_resp = await cli.get("/api/relay/tunnel/status")
                self.assertEqual(stat_resp.status, 200)
                stat_data = await stat_resp.json()
                self.assertTrue(stat_data["active"])
                self.assertEqual(stat_data["provider"], "render")

                # Stop disables relay cleanly
                stop_resp = await cli.post("/api/relay/tunnel/stop", json={}, headers={"X-CSRF-Token": csrf})
                self.assertEqual(stop_resp.status, 200)
                stop_data = await stop_resp.json()
                self.assertFalse(stop_data["active"])
                self.assertEqual(settings_store.get("remote_relay_enabled"), "false")

        # Verify web app.js toggle uses render provider instead of hardcoded cloudflared
        app_js = (Path(__file__).resolve().parents[1] / "src" / "snow" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('/api/relay/tunnel/start", "POST", { provider: "render" }', app_js)
        self.assertNotIn('/api/relay/tunnel/start", "POST", { provider: "cloudflared" }', app_js)


if __name__ == "__main__":
    unittest.main()
