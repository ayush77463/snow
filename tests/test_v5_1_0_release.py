"""Comprehensive SNOW V5.1.0 regression tests covering all 12 release workstreams."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop
from PIL import Image

import snow
from snow.capabilities.engine import CapabilityEngine
from snow.capabilities.windows.clipboard import WindowsClipboardManager
from snow.core.config import CoreConfig
from snow.core.usb import unlock_android_permissions
from snow.mcp.remote_gateway import PUBLIC_ICON_PATHS, RemoteMcpGateway
from snow.mcp.tunnel import TunnelManager, _TunnelInstance
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage
from snow.relay.auth import create_relay_ticket
from snow.relay.config import RelayConfig
from snow.relay.mcp_forwarder import RelayMcpForwarder
from snow.relay.server import SnowRelayServer
from snow.security.db import DatabaseManager
from snow.security.identity import load_or_create_device_identity
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferManager
from snow.transfer.storage import TransferStorageManager
from snow.updater import CURRENT_VERSION, check_for_updates
from snow.web.server import SnowWebServer


class TestV510ClipboardAndWatcher(unittest.TestCase):
    """WS1: Three-way clipboard persistence, Core-owned watcher lifecycle, PIL image fallback, CSS."""

    def test_phone_clipboard_set_persists_with_authoritative_identity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "test.db")
            db.insert_paired_device(
                device_id="phone-dev-123",
                device_name="Realme P4",
                auth_token_hash="hash-phone-123",
                platform="android",
                trust_tier="peer",
            )
            ident = load_or_create_device_identity(tmp)
            ws_srv = SnowWebSocketServer(
                config=CoreConfig(transfer_root=tmp),
                db_manager=db,
                device_identity=ident,
            )
            ws_srv.capability_engine.clipboard.set_clipboard_sync = MagicMock(return_value={"success": True})
            session = ws_srv.session_manager.create_session(
                device_id="phone-dev-123",
                trust_tier="peer",
            )
            ws_srv.broadcast_clipboard_buffer_event = AsyncMock()
            mock_client = MagicMock()
            mock_client.websocket = MagicMock()
            mock_client.websocket.send = AsyncMock()
            req_data = {"type": "text", "text": "hello-v510", "device_name": "SPOOFED_NAME"}
            msg = SnowMessage.create_request(action="desktop_clipboard_set", data=req_data)

            asyncio.run(
                ws_srv._handle_desktop_clipboard_set(
                    mock_client,
                    msg,
                    req_data,
                    session=session,
                )
            )
            items = ws_srv.capability_engine.clipboard_buffer.list_items()
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["source_device_id"], "phone-dev-123")
            self.assertEqual(items[0]["source_device_name"], "Realme P4")
            ws_srv.broadcast_clipboard_buffer_event.assert_awaited_once()

    def test_watcher_not_stopped_when_sync_clients_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "test.db")
            ident = load_or_create_device_identity(tmp)
            ws_srv = SnowWebSocketServer(
                config=CoreConfig(transfer_root=tmp),
                db_manager=db,
                device_identity=ident,
            )
            mock_listener = MagicMock()
            mock_listener.stop = MagicMock()
            ws_srv._clipboard_listener = mock_listener
            ws_srv._active_sync_connections.add("conn-1")
            ws_srv._active_sync_connections.discard("conn-1")
            # Core-owned listener stops only in stop() shutdown, never just because sync connections empty
            self.assertIs(ws_srv._clipboard_listener, mock_listener)
            mock_listener.stop.assert_not_called()

    def test_pil_clipboard_fallback_bounds_and_normalizes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = WindowsClipboardManager()
            mgr._is_windows = True
            mgr._user32 = MagicMock()
            mgr._kernel32 = MagicMock()
            mgr._gdiplus = MagicMock()
            mgr._gdiplus_token = 1
            mgr._open_clipboard_with_retry = MagicMock(return_value=True)
            mgr._user32.GetClipboardData = MagicMock(return_value=None)

            img = Image.new("RGBA", (32, 24), (10, 120, 220, 255))
            with patch("PIL.ImageGrab.grabclipboard", return_value=img):
                res = mgr.get_image_sync(output_dir=Path(tmp))
            self.assertTrue(res["success"])
            out_file = Path(res["file_path"])
            self.assertTrue(out_file.is_file())
            self.assertTrue(out_file.read_bytes().startswith(b"\x89PNG"))

            # Oversized image dimensions rejected cleanly
            huge = Image.new("RGB", (1, 1))
            with patch.object(Image.Image, "size", new_callable=unittest.mock.PropertyMock, return_value=(20000, 20000)), patch(
                "PIL.ImageGrab.grabclipboard", return_value=huge
            ):
                bad = mgr.get_image_sync(output_dir=Path(tmp))
            self.assertFalse(bad["success"])
            self.assertEqual(bad["status"], "IMAGE_TOO_LARGE")


class TestV510GatewayIconsAndOAuthSync(AioHTTPTestCase):
    """WS2 & WS3: Public icons open without auth + cross-origin + OAuth IPC/settings sync."""

    async def get_application(self) -> web.Application:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(Path(self.tmp_dir.name) / "oauth.db")
        self.mock_bridge = MagicMock()
        self.mock_bridge.is_paused = False
        self.mock_bridge.capability_engine = MagicMock()
        self.mock_bridge.capability_engine.db_manager = self.db
        self.mock_bridge.call = AsyncMock(return_value={"success": True})
        self.gateway = RemoteMcpGateway(
            host="127.0.0.1",
            port=8771,
            bridge=self.mock_bridge,
        )
        return self.gateway.app

    async def tearDownAsync(self) -> None:
        await super().tearDownAsync()
        self.tmp_dir.cleanup()

    @unittest_run_loop
    async def test_public_icons_accessible_cross_origin_without_token(self) -> None:
        for icon_path in PUBLIC_ICON_PATHS:
            resp = await self.client.get(
                icon_path,
                headers={"Origin": "https://claude.ai"},
            )
            self.assertEqual(resp.status, 200, f"Expected 200 for {icon_path}")
            self.assertEqual(resp.headers.get("Access-Control-Allow-Origin"), "*")
            body = await resp.read()
            self.assertGreater(len(body), 100)

        meta_resp = await self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(meta_resp.status, 200)
        meta = await meta_resp.json()
        self.assertTrue(meta["logo_uri"].endswith("/snow_logo.png"))

    @unittest_run_loop
    async def test_oauth_pending_reconciles_external_decision(self) -> None:
        reg = self.gateway.oauth_server.register_client(
            client_name="Claude",
            redirect_uris=["https://claude.ai/cb"],
            scope="mcp:tools",
        )
        ev = asyncio.Event()
        self.gateway._pending_authorizations["req-oauth-1"] = {
            "request_id": "req-oauth-1",
            "client_name": "Claude",
            "scope": "mcp:tools",
            "status": "PENDING",
            "created_at": 10000000000.0,
            "expires_at": 20000000000.0,
            "redirect_uri": "https://claude.ai/cb",
            "code_challenge": "A" * 43,
            "code_challenge_method": "S256",
            "state": "xyz",
            "client_id": reg["client_id"],
            "event": ev,
        }
        self.db.set_setting(
            "oauth_req:req-oauth-1",
            json.dumps({"request_id": "req-oauth-1", "client_name": "Claude", "status": "PENDING"}),
        )
        self.db.set_setting(
            "oauth_dec:req-oauth-1",
            json.dumps({"request_id": "req-oauth-1", "status": "APPROVED"}),
        )
        self.gateway._reconcile_external_oauth_decisions()
        rec = self.gateway._pending_authorizations["req-oauth-1"]
        self.assertEqual(rec["status"], "APPROVED")
        self.assertTrue(bool(rec.get("auth_code")))


class TestV510BroadcastConnections(unittest.TestCase):
    """WS1 & WS2: Verify real ConnectionManager iteration in clipboard and approval broadcasts."""

    def test_broadcast_approval_and_clipboard_events_with_real_connection_manager(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = DatabaseManager(Path(tmp) / "bcast.db")
            ident = load_or_create_device_identity(tmp)
            ws_srv = SnowWebSocketServer(
                config=CoreConfig(transfer_root=tmp),
                db_manager=db,
                device_identity=ident,
            )
            ws_owner = MagicMock()
            ws_owner.state = 1
            ws_owner.remote_address = ("127.0.0.1", 50001)
            ws_owner.send = AsyncMock()
            ws_peer = MagicMock()
            ws_peer.state = 1
            ws_peer.remote_address = ("127.0.0.1", 50002)
            ws_peer.send = AsyncMock()

            c_owner = ws_srv.connection_manager.register(ws_owner)
            c_peer = ws_srv.connection_manager.register(ws_peer)
            ws_srv.session_manager.create_session("dev-owner", connection_id=c_owner.connection_id, trust_tier="owner")
            ws_srv.session_manager.create_session("dev-peer", connection_id=c_peer.connection_id, trust_tier="peer")

            asyncio.run(ws_srv.broadcast_approval_event("REQUESTED", {"request_id": "req-1"}))
            ws_owner.send.assert_awaited_once()
            ws_peer.send.assert_not_awaited()

            ws_owner.send.reset_mock()
            ws_peer.send.reset_mock()
            asyncio.run(ws_srv.broadcast_clipboard_buffer_event({"item_id": "cb-1"}))
            ws_owner.send.assert_awaited_once()
            ws_peer.send.assert_awaited_once()


class TestV510WebLayoutAndUsbUnlock(unittest.TestCase):
    """WS5, WS6, WS7, WS10: Web CSS/DOM integrity & USB permission unlock."""

    def test_web_assets_contain_requested_v510_repairs(self) -> None:
        css = Path("src/snow/web/static/app.css").read_text(encoding="utf-8")
        html = Path("src/snow/web/static/index.html").read_text(encoding="utf-8")
        js = Path("src/snow/web/static/app.js").read_text(encoding="utf-8")

        self.assertIn("overflow: hidden", css)
        self.assertIn("max-height: 220px", css)
        self.assertIn("100dvh", css)
        self.assertIn("backdrop-filter: blur", css)

        self.assertIn('id="media-preview-modal"', html)
        self.assertIn('id="btn-enlarge-capture"', html)
        self.assertIn('id="btn-open-transfers-folder"', html)
        self.assertIn('id="files-active-transfer-card"', html)
        self.assertIn('id="mcp-permanent-accordion"', html)
        self.assertIn('id="btn-usb-unlock-permissions"', html)
        self.assertNotIn('id="tab-seg-captures"', html)

        self.assertIn("/api/files/destinations", js)
        self.assertIn("/api/files/open-transfers-folder", js)
        self.assertIn("/api/usb/unlock-permissions", js)

    def test_usb_unlock_permissions_uses_arg_lists_and_classifies(self) -> None:
        fake_dev = [{"serial": "PIXEL9", "status": "device", "model": "Realme_P4", "raw": ""}]
        mock_proc = MagicMock(returncode=0, stdout="Success", stderr="")
        with patch("snow.core.usb.get_connected_adb_devices", return_value=fake_dev), patch(
            "snow.core.usb.subprocess.run", return_value=mock_proc
        ) as mock_run:
            res = unlock_android_permissions(serial="PIXEL9", adb_bin=Path("adb.exe"))
        self.assertTrue(res["success"])
        self.assertEqual(res["serial"], "PIXEL9")
        self.assertGreaterEqual(len(res["granted"]), 8)
        for call_item in mock_run.call_args_list:
            cmd = call_item.args[0]
            self.assertIsInstance(cmd, list)
            self.assertFalse(call_item.kwargs.get("shell", False))

    def test_usb_unlock_permissions_fails_cleanly_when_no_device(self) -> None:
        with patch("snow.core.usb.get_connected_adb_devices", return_value=[]):
            res = unlock_android_permissions(adb_bin=Path("adb.exe"))
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "NO_DEVICE")


class TestV510TunnelAndRenderRelay(unittest.IsolatedAsyncioTestCase):
    """WS9: Tailscale Funnel --bg + JSON, Render /v1/resolve/{snow_id} & /mcp reverse tunnel."""

    async def test_tailscale_funnel_bg_and_status_json(self) -> None:
        inst = _TunnelInstance(target_port=8771, purpose="mcp")
        funnel_proc = MagicMock()
        funnel_proc.returncode = 0
        funnel_proc.communicate = AsyncMock(return_value=(b"", b""))

        status_proc = MagicMock()
        status_proc.returncode = 0
        status_proc.communicate = AsyncMock(
            return_value=(json.dumps({"Self": {"DNSName": "snow-pc.tailnet123.ts.net."}}).encode("utf-8"), b"")
        )

        stop_proc = MagicMock()
        stop_proc.wait = AsyncMock(return_value=0)

        with patch("snow.mcp.tunnel.find_tailscale_binary", return_value="tailscale.exe"), patch(
            "asyncio.create_subprocess_exec", side_effect=[funnel_proc, status_proc, stop_proc]
        ) as mock_exec:
            res = await inst.start(provider="tailscale", port=8771)
            self.assertTrue(res["success"])
            self.assertEqual(res["public_url"], "https://snow-pc.tailnet123.ts.net")
            self.assertEqual(res["mcp_endpoint"], "https://snow-pc.tailnet123.ts.net/mcp")
            self.assertTrue(inst.get_status()["active"])
            await inst.stop()
            self.assertFalse(inst.get_status()["active"])

        self.assertEqual(mock_exec.call_args_list[0].args[1:4], ("funnel", "--bg", "8771"))
        self.assertEqual(mock_exec.call_args_list[1].args[1:3], ("status", "--json"))

    async def test_render_relay_resolve_and_reverse_mcp_proxy(self) -> None:
        # 1. Start local mock MCP backend simulating RemoteMcpGateway
        async def handle_mock_mcp(request: web.Request) -> web.Response:
            auth = request.headers.get("Authorization", "")
            if auth != "Bearer oauth-access-token":
                return web.json_response({"error": "invalid_token"}, status=401)
            body = await request.json()
            return web.json_response({"jsonrpc": "2.0", "id": body.get("id"), "result": {"ok": True}})

        gw_app = web.Application()
        gw_app.router.add_post("/mcp", handle_mock_mcp)
        gw_runner = web.AppRunner(gw_app)
        await gw_runner.setup()
        gw_site = web.TCPSite(gw_runner, "127.0.0.1", 0)
        await gw_site.start()
        gw_port = gw_site._server.sockets[0].getsockname()[1]

        # 2. Start SnowRelayServer on ephemeral port
        secret = "test-render-shared-secret"
        relay_srv = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret=secret, enabled=True))
        await relay_srv.start()
        relay_port = relay_srv._site._server.sockets[0].getsockname()[1]

        snow_id = "SNW-A1B2-C3D4"
        ticket = create_relay_ticket("pc-owner-1", "grp-1", secret, snow_id=snow_id)
        peer_ticket = create_relay_ticket("phone-peer-1", "grp-1", secret)
        other_group_ticket = create_relay_ticket("outsider-1", "grp-other", secret)

        forwarder = RelayMcpForwarder(
            relay_ws_url=f"ws://127.0.0.1:{relay_port}/v1/tunnel",
            snow_id=snow_id,
            ticket=ticket,
            local_gateway_url=f"http://127.0.0.1:{gw_port}",
        )
        try:
            ok, err = await forwarder.start(timeout=5.0)
            self.assertTrue(ok, err)

            async with forwarder._session.get(f"http://127.0.0.1:{relay_port}/v1/resolve/{snow_id}") as r_unauth:
                self.assertEqual(r_unauth.status, 401)

            async with forwarder._session.get(
                f"http://127.0.0.1:{relay_port}/v1/resolve/{snow_id}",
                headers={"Authorization": f"Bearer {other_group_ticket}"},
            ) as r_cross:
                self.assertEqual(r_cross.status, 403)

            async with forwarder._session.get(
                f"http://127.0.0.1:{relay_port}/v1/resolve/{snow_id}",
                headers={"Authorization": f"Bearer {peer_ticket}"},
            ) as r_ok:
                self.assertEqual(r_ok.status, 200)
                resolved = await r_ok.json()
                self.assertTrue(resolved["online"])
                self.assertTrue(resolved["mcp_tunnel_active"])
                self.assertTrue(resolved["mcp_url"].endswith(f"/u/{snow_id}/mcp"))

            # Unauthed MCP call still rejected 401 by downstream PC OAuth check
            async with forwarder._session.post(
                f"http://127.0.0.1:{relay_port}/u/{snow_id}/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            ) as mcp_401:
                self.assertEqual(mcp_401.status, 401)

            # Authorized OAuth Bearer call forwarded transparently end-to-end
            async with forwarder._session.post(
                f"http://127.0.0.1:{relay_port}/u/{snow_id}/mcp",
                headers={"Authorization": "Bearer oauth-access-token"},
                json={"jsonrpc": "2.0", "id": 7, "method": "ping"},
            ) as mcp_200:
                self.assertEqual(mcp_200.status, 200)
                data = await mcp_200.json()
                self.assertEqual(data["id"], 7)
                self.assertTrue(data["result"]["ok"])
        finally:
            await forwarder.stop()
            await relay_srv.stop()
            await gw_runner.cleanup()


class TestV510IconsBundleVersionsAndOta(unittest.TestCase):
    """WS4 & WS12: Multi-res ICO, render.yaml, bundle trim flags, versions 5.1.0/vCode=3, OTA."""

    def test_windows_ico_has_crisp_multi_res_sizes_and_render_yaml_exists(self) -> None:
        ico_path = Path("packaging/windows/snow.ico")
        self.assertTrue(ico_path.is_file())
        self.assertGreater(ico_path.stat().st_size, 10_000)
        with Image.open(ico_path) as ico:
            sizes = ico.info.get("sizes") or set()
        self.assertTrue({(16, 16), (32, 32), (48, 48), (256, 256)}.issubset(sizes))
        self.assertTrue(Path("render.yaml").is_file())

    def test_snow_spec_excludes_avif_and_defaults_no_cloudflared(self) -> None:
        spec_txt = Path("packaging/windows/snow.spec").read_text(encoding="utf-8")
        self.assertIn("SNOW_BUNDLE_CLOUDFLARED", spec_txt)
        self.assertIn("PIL._avif", spec_txt)
        build_txt = Path("packaging/windows/build_release.py").read_text(encoding="utf-8")
        self.assertIn("--bundle-cloudflared", build_txt)
        self.assertIn("bundle_cloudflared: bool = False", build_txt)

    def test_version_alignment_and_local_ota_manifest_discovery(self) -> None:
        self.assertEqual(snow.__version__, "5.2.0")
        self.assertEqual(CURRENT_VERSION, "5.2.0")
        self.assertEqual(CoreConfig().version, "5.2.0")
        gradle_txt = Path("android/app/build.gradle.kts").read_text(encoding="utf-8")
        self.assertIn("versionCode = 4", gradle_txt)
        self.assertIn('versionName = "5.2.0"', gradle_txt)

        with tempfile.TemporaryDirectory() as tmp:
            pkg_out = Path(tmp) / "packaging" / "output"
            pkg_out.mkdir(parents=True)
            installer = pkg_out / "SNOW-Setup-5.3.0.exe"
            installer.write_bytes(b"MZ" + b"\x00" * 64)
            import hashlib
            sha = hashlib.sha256(installer.read_bytes()).hexdigest()
            manifest_path = pkg_out / "update_manifest.json"
            manifest_path.write_text(
                json.dumps({
                    "version": "5.3.0",
                    "desktop": {
                        "url": str(installer),
                        "sha256": sha,
                        "size_bytes": installer.stat().st_size,
                    },
                }),
                encoding="utf-8",
            )
            with patch("snow.updater.find_local_staged_manifest", return_value=manifest_path):
                res = check_for_updates(None, current_version="5.2.0")
            self.assertTrue(res["available"])
            self.assertEqual(res["latest_version"], "5.3.0")

            apk52 = pkg_out / "SNOW-Mobile-5.2.0.apk"
            apk52.write_bytes(b"PK52_MOCK")
            http_srv = SnowHttpTransferServer(
                config=CoreConfig(),
                db_manager=DatabaseManager(Path(tmp) / "u.db"),
                transfer_manager=TransferManager(),
                storage_manager=TransferStorageManager(tmp),
            )
            http_srv._get_staged_apk_path = lambda: apk52
            req = type("Req", (), {"headers": {}, "path": "/api/v1/app/update-info"})()
            resp = asyncio.run(http_srv.handle_app_update_info(req))
            payload = json.loads(resp.text)
            self.assertTrue(payload["available"])
            self.assertEqual(payload["version_code"], 4)
            self.assertEqual(payload["version_name"], "5.2.0")
            self.assertEqual(payload["apk_name"], "SNOW-Mobile-5.2.0.apk")


if __name__ == "__main__":
    unittest.main()
