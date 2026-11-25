"""Comprehensive Stage 6A stabilization and capability expansion regression suite (WS1-WS13)."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp.test_utils import AioHTTPTestCase
from PIL import Image

from snow.capabilities.clipboard_buffer import ClipboardRingBuffer
from snow.capabilities.engine import CapabilityEngine, CapabilityRequest
from snow.capabilities.windows.clipboard import (
    CF_BITMAP,
    WindowsClipboardManager,
    compute_canonical_image_digest,
    get_default_clipboard_temp_dir,
)
from snow.capabilities.windows.files import WindowsFileManager, pick_folder_dialog_win32
from snow.capabilities.windows.system import WindowsSystemControls
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.core.server import SnowCoreServer
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.registry import (
    CAPABILITY_REGISTRY,
    get_capability_metadata,
    get_mcp_annotations,
    list_capabilities,
    validate_registry,
)
from snow.mcp.remote_gateway import RemoteMcpGateway
from snow.mcp.server import create_snow_mcp_server
from snow.mcp.tools import ALL_TOOL_NAMES
from snow.network.federation import FederationManager
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import MessageType, SnowMessage
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager, hash_token
from snow.security.pairing import PairingManager
from snow.security.tls import ensure_tls_certificate
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferManager
from snow.transfer.storage import (
    TransferStorageManager,
    get_default_pc_transfer_dir,
    resolve_configured_pc_transfer_dir,
    validate_pc_transfer_dir,
)
from snow.web.server import SnowWebServer


def _make_png_bytes(color: tuple[int, int, int, int] = (20, 120, 220, 255), size: tuple[int, int] = (8, 8)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGBA", size, color).save(buf, format="PNG")
    return buf.getvalue()


class TestStage6AClipboardAndDedup(unittest.TestCase):
    """WS1 & WS11: Canonical image dedup, temp isolation, CF_BITMAP/PNG support, metadata exposure."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_s6a_clip_"))
        self.prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = str(self.tmp_dir)

    def tearDown(self) -> None:
        if self.prev_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self.prev_data_dir
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_ws1_temp_dir_isolation_under_snow_data_dir(self) -> None:
        clip_tmp = get_default_clipboard_temp_dir()
        self.assertTrue(clip_tmp.is_dir())
        self.assertEqual(clip_tmp, (Path(tempfile.gettempdir()) / "snow_clip_tmp").resolve())
        self.assertNotEqual(clip_tmp.parent, Path.home())

    def test_ws1_canonical_rgba_digest_matches_across_png_and_rgb_conversions(self) -> None:
        img_rgba = Image.new("RGBA", (6, 6), (11, 22, 33, 255))
        img_rgb = Image.new("RGB", (6, 6), (11, 22, 33))
        b1 = io.BytesIO()
        b2 = io.BytesIO()
        img_rgba.save(b1, format="PNG", compress_level=1)
        img_rgb.save(b2, format="PNG", compress_level=9)
        self.assertNotEqual(b1.getvalue(), b2.getvalue())

        d1, w1, h1 = compute_canonical_image_digest(b1.getvalue())
        d2, w2, h2 = compute_canonical_image_digest(b2.getvalue())
        self.assertIsNotNone(d1)
        self.assertEqual(len(d1 or ""), 64)
        self.assertEqual((w1, h1), (6, 6))
        self.assertEqual(d1, d2)
        self.assertEqual((w2, h2), (6, 6))

    def test_ws1_clipboard_ring_buffer_dedups_visually_identical_reencoded_pngs(self) -> None:
        db = DatabaseManager(self.tmp_dir / "clip.db")
        buf = ClipboardRingBuffer(storage_dir=self.tmp_dir / "buf", db_manager=db)

        raw_png_1 = io.BytesIO()
        raw_png_2 = io.BytesIO()
        Image.new("RGBA", (6, 6), (40, 80, 120, 255)).save(raw_png_1, format="PNG", compress_level=0)
        Image.new("RGB", (6, 6), (40, 80, 120)).save(raw_png_2, format="PNG", compress_level=9)
        self.assertNotEqual(
            hashlib.sha256(raw_png_1.getvalue()).hexdigest(),
            hashlib.sha256(raw_png_2.getvalue()).hexdigest(),
        )

        res1 = buf.add_image(
            image_bytes=raw_png_1.getvalue(),
            source_device_id="desktop_windows",
            source_device_name="PC",
            mime_type="image/png",
        )
        self.assertTrue(res1["success"])
        self.assertEqual(res1["status"], "ADDED")

        res2 = buf.add_image(
            image_bytes=raw_png_2.getvalue(),
            source_device_id="phone-1",
            source_device_name="Phone",
            mime_type="image/png",
        )
        self.assertTrue(res2["success"])
        self.assertEqual(res2["status"], "DEDUPLICATED")
        self.assertEqual(res2["item"]["item_id"], res1["item"]["item_id"])
        self.assertEqual(len(buf.list_items()), 1)

    def test_ws1_cf_bitmap_detection_and_metadata_cleans_up_temp_file(self) -> None:
        mgr = WindowsClipboardManager()
        mgr._is_windows = True
        mgr._user32 = MagicMock()
        mgr._user32.RegisterClipboardFormatW.return_value = 0
        # Return False except for CF_BITMAP (2)
        mgr._user32.IsClipboardFormatAvailable.side_effect = lambda fmt: 1 if fmt == CF_BITMAP else 0
        self.assertTrue(mgr.has_image_sync())

        def fake_get_image(output_dir: Path | None = None) -> dict:
            out_dir = Path(output_dir or get_default_clipboard_temp_dir())
            out_dir.mkdir(parents=True, exist_ok=True)
            fp = out_dir / "clip_tmp_test.png"
            fp.write_bytes(_make_png_bytes(size=(16, 12)))
            return {
                "success": True,
                "status": "SUCCESS",
                "file_path": str(fp),
                "width": 16,
                "height": 12,
                "format": "PNG",
                "mime_type": "image/png",
                "size": fp.stat().st_size,
            }

        mgr.get_image_sync = fake_get_image  # type: ignore[method-assign]
        meta = mgr.get_image_metadata_sync()
        self.assertTrue(meta["has_image"])
        self.assertEqual(meta["width"], 16)
        self.assertEqual(meta["height"], 12)
        self.assertEqual(meta["format"], "PNG")
        self.assertFalse((get_default_clipboard_temp_dir() / "clip_tmp_test.png").exists())

    def test_ws11_windows_clipboard_get_image_and_buffer_without_paths_or_bytes(self) -> None:
        db = DatabaseManager(self.tmp_dir / "ws11.db")
        cb_buf = ClipboardRingBuffer(storage_dir=self.tmp_dir / "cb_buf", db_manager=db)
        cb_buf.add_text("Pinned clip A", source_device_id="phone-1", source_device_name="Phone")
        cb_buf.add_image(_make_png_bytes(), source_device_id="desktop_windows", source_device_name="PC")
        cb_buf.add_text("Latest note B", source_device_id="desktop_windows", source_device_name="PC")
        cb_buf.add_text("Oldest clip Z", source_device_id="phone-1", source_device_name="Phone")

        clipboard_mgr = MagicMock()
        clipboard_mgr.get_clipboard = AsyncMock(return_value={
            "success": True,
            "status": "IMAGE",
            "text": "",
            "has_image": True,
            "image": {
                "has_image": True,
                "width": 32,
                "height": 24,
                "format": "PNG",
                "mime_type": "image/png",
                "size_bytes": 256,
                "file_path": "C:/secret/leak/path.png",
                "raw_bytes": b"\x89PNG",
            },
        })
        engine = CapabilityEngine(
            allowed_roots=[self.tmp_dir],
            db_manager=db,
            clipboard=clipboard_mgr,
            clipboard_buffer=cb_buf,
        )
        res = asyncio.run(
            engine.execute(
                CapabilityRequest(action="windows_clipboard_get"),
                ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="test"),
            )
        )
        self.assertTrue(res.success)
        data = res.data or {}
        self.assertTrue(data["has_image"])
        self.assertEqual(data["os_image"]["width"], 32)
        self.assertEqual(data["os_image"]["height"], 24)
        self.assertEqual(data["os_image"]["format"], "PNG")
        self.assertNotIn("file_path", data["os_image"])
        self.assertNotIn("raw_bytes", data["os_image"])

        recent = data["recent_buffer_items"]
        self.assertEqual(len(recent), 3)
        dumped = json.dumps(data)
        self.assertNotIn("file_path", dumped)
        self.assertNotIn("image_path", dumped)
        self.assertNotIn("raw_bytes", dumped)
        self.assertNotIn("storage_dir", dumped)


class TestStage6ADisconnectAndTransferConfig(unittest.TestCase):
    """WS4 & WS7: Manual disconnect lock vs revoke, configurable pc_transfer_dir without tkinter."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_s6a_ws47_"))
        self.prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = str(self.tmp_dir)

    def tearDown(self) -> None:
        if self.prev_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self.prev_data_dir
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_ws4_disconnect_keeps_pairing_and_blocks_auto_reconnect_until_reconnect(self) -> None:
        db = DatabaseManager(self.tmp_dir / "ws4.db")
        pairing = PairingManager()
        tls_dir = self.tmp_dir / "tls"
        tls_dir.mkdir(parents=True, exist_ok=True)
        ensure_tls_certificate(
            cert_path=tls_dir / "server.crt",
            key_path=tls_dir / "server.key",
        )
        config = CoreConfig(transfer_root=str(self.tmp_dir))
        core = SnowCoreServer(config=config, db_manager=db)
        ws_srv = core.ws_server
        ws_srv.pairing_manager = pairing
        ws_srv.db_manager = db
        ipc = core.ipc_server
        ipc._secret = "a" * 32

        raw_token = "tok-device-secret-value-123"
        token_hash = hash_token(raw_token)
        db.insert_paired_device(
            device_id="phone-pixel",
            device_name="Pixel Phone",
            auth_token_hash=token_hash,
            trust_tier="owner",
        )

        class FakeWs:
            remote_address = ("127.0.0.1", 55111)

            def __init__(self) -> None:
                self.sent: list[str] = []
                self.closed = False

            async def send(self, payload: str) -> None:
                self.sent.append(payload)

            async def close(self, code: int = 1000, reason: str = "") -> None:
                self.closed = True

        async def _run() -> None:
            ws_conn = FakeWs()
            conn_rec = ws_srv.connection_manager.register(ws_conn)
            session = ws_srv.session_manager.create_session(
                device_id="phone-pixel",
                trust_tier="owner",
                connection_id=conn_rec.connection_id,
            )
            disc_res = await core.disconnect_device("phone-pixel")
            self.assertTrue(disc_res["success"])
            self.assertTrue(ws_conn.closed)
            self.assertTrue(any("session_disconnect" in s for s in ws_conn.sent))
            self.assertIsNotNone(db.get_paired_device("phone-pixel"))
            self.assertIn("phone-pixel", ws_srv.manually_disconnected_devices)

            # Subsequent auth attempt from phone must fail with MANUAL_DISCONNECT while locked
            ws_retry = FakeWs()
            retry_client = ws_srv.connection_manager.register(ws_retry)
            auth_msg = SnowMessage.create_request(
                action="auth_request",
                data={"device_id": "phone-pixel", "auth_token": raw_token},
            )
            await ws_srv._handle_auth_request(retry_client, auth_msg, auth_msg.payload["data"])
            self.assertTrue(any("MANUAL_DISCONNECT" in s for s in ws_retry.sent))

            # Explicit host reconnect clears lock
            ws_srv.udp_discovery = MagicMock()
            rec_res = await core.reconnect_device("phone-pixel")
            self.assertTrue(rec_res["success"])
            self.assertNotIn("phone-pixel", ws_srv.manually_disconnected_devices)

            ws_retry2 = FakeWs()
            retry_client2 = ws_srv.connection_manager.register(ws_retry2)
            auth_msg2 = SnowMessage.create_request(
                action="auth_request",
                data={"device_id": "phone-pixel", "auth_token": raw_token},
            )
            await ws_srv._handle_auth_request(retry_client2, auth_msg2, auth_msg2.payload["data"])
            self.assertTrue(any("session_id" in s and "success" in s for s in ws_retry2.sent))

        asyncio.run(_run())

    def test_ws7_default_transfer_dir_validation_and_persistence(self) -> None:
        default_dir = get_default_pc_transfer_dir()
        self.assertEqual(default_dir.name, "SNOW")
        self.assertEqual(default_dir.parent.name, "Downloads")

        custom_dest = self.tmp_dir / "IncomingMedia"
        custom_dest.mkdir(parents=True, exist_ok=True)
        existing_file = self.tmp_dir / "not_a_dir.txt"
        existing_file.write_text("file", encoding="utf-8")

        with self.assertRaises(ValueError):
            validate_pc_transfer_dir("")

        with self.assertRaises(ValueError):
            validate_pc_transfer_dir(str(existing_file))

        resolved = validate_pc_transfer_dir(str(custom_dest))
        self.assertEqual(resolved, custom_dest.resolve())

        db = DatabaseManager(self.tmp_dir / "ws7.db")
        core = SnowCoreServer(config=CoreConfig(transfer_root=str(default_dir)), db_manager=db)
        core.storage_manager = TransferStorageManager(root_dir=default_dir)
        core.capability_engine.files = WindowsFileManager(allowed_roots=[default_dir])

        res = core.set_pc_transfer_dir(str(custom_dest))
        self.assertTrue(res["success"])
        self.assertEqual(db.get_setting("pc_transfer_dir"), str(custom_dest.resolve()))
        self.assertEqual(core.storage_manager.root_dir, custom_dest.resolve())
        self.assertEqual(resolve_configured_pc_transfer_dir(db), custom_dest.resolve())

    def test_ws7_files_module_never_imports_tkinter(self) -> None:
        files_src = (
            Path(__file__).resolve().parents[1] / "src" / "snow" / "capabilities" / "windows" / "files.py"
        ).read_text("utf-8")
        self.assertNotIn("tkinter", files_src.lower())
        with patch("sys.platform", "linux"):
            res = pick_folder_dialog_win32()
            self.assertFalse(res["success"])
            self.assertEqual(res["status"], "UNSUPPORTED_PLATFORM")


class TestStage6AWebOAuthPairingAndDeclutter(AioHTTPTestCase):
    """WS5, WS7, WS8, WS9, WS10: Web API, OAuth Stitch UI, PIN cancel, IPC secret endpoint."""

    async def get_application(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_s6a_web_"))
        self.prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = str(self.tmp_dir)

        self.db = DatabaseManager(self.tmp_dir / "web.db")
        self.pairing = PairingManager()
        tls_dir = self.tmp_dir / "tls"
        tls_dir.mkdir(parents=True, exist_ok=True)
        cert_info = ensure_tls_certificate(
            cert_path=tls_dir / "server.crt",
            key_path=tls_dir / "server.key",
        )
        self.storage = TransferStorageManager(root_dir=self.tmp_dir / "transfers")
        self.core = SnowCoreServer(config=CoreConfig(transfer_root=str(self.storage.root_dir)), db_manager=self.db)
        self.core.ws_server.pairing_manager = self.pairing
        self.core.ws_server.certificate_info = cert_info
        self.core.ws_server.tls_cert_fingerprint = cert_info.fingerprint_sha256
        self.core.cert_fingerprint = cert_info.fingerprint_sha256
        self.core.storage_manager = self.storage
        self.ipc_secret = "ipc-test-secret-0123456789abcdef"
        self.ipc = self.core.ipc_server
        self.ipc._secret = self.ipc_secret

        import hashlib
        import hmac as _hmac
        owner_tok = _hmac.new(
            self.ipc_secret.encode("utf-8"), b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256
        ).hexdigest()

        async def _ipc_call(op: str, payload: dict | None = None, **_kw):
            resp, _ = await self.ipc._dispatch_request(
                {
                    "version": 1,
                    "request_id": "test-req",
                    "op": op,
                    "payload": payload or {},
                    "owner_token": owner_tok,
                },
                True,
            )
            return resp

        self.bridge = MagicMock()
        self.bridge.daemon_manager = MagicMock()
        self.bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)
        self.bridge.ipc_client = MagicMock()
        self.bridge.ipc_client.secret = self.ipc_secret
        self.bridge.capability_engine = self.core.capability_engine
        self.bridge.call = AsyncMock(side_effect=_ipc_call)
        self.bridge.list_devices = AsyncMock(side_effect=lambda: _ipc_call("list_devices", {}))

        self.web_srv = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            auto_open_browser=False,
            bridge=self.bridge,
        )
        self.web_srv.db_manager = self.db
        return self.web_srv.create_app()

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        if self.prev_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self.prev_data_dir
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def _auth_headers(self) -> dict[str, str]:
        origin = f"http://127.0.0.1:{self.web_srv.port}"
        r = await self.client.post(
            "/api/auth/session",
            json={"token": self.web_srv.bootstrap_token},
            headers={"Origin": origin},
        )
        self.assertEqual(r.status, 200)
        data = await r.json()
        return {"X-CSRF-Token": data["csrf_token"], "Origin": origin}

    async def test_ws8_declutter_invariants_and_zero_emoji(self) -> None:
        static_dir = Path(__file__).resolve().parents[1] / "src" / "snow" / "web" / "static"
        html = (static_dir / "index.html").read_text("utf-8")
        js = (static_dir / "app.js").read_text("utf-8")

        removed_ids = (
            "btn-capture-screen-trigger",
            "btn-capture-camera-trigger",
            "home-bridge-status",
            "file-upload-dropzone",
            "btn-clip-capture-pc",
            "btn-clip-pull-phone",
            "btn-diag-copy-logs",
            "btn-diag-clear-logs",
            "diag-log-box",
            "workflow-steps-details",
        )
        for rid in removed_ids:
            self.assertNotIn(f'id="{rid}"', html)
            self.assertNotIn(rid, js)

        # Notification poll must reconcile in-place cleanly without CSS.escape crash
        self.assertNotIn("CSS.escape", js)
        self.assertIn("data-notif-key", js)
        self.assertIn(".notif-inline-reply", js)

    async def test_ws9_pairing_state_fp_and_pin_cancel_and_no_passive_qr_call(self) -> None:
        headers = await self._auth_headers()
        state_before = await self.client.get("/api/pair/state", headers=headers)
        self.assertEqual(state_before.status, 200)
        s0_wrap = await state_before.json()
        self.assertTrue(s0_wrap["success"])
        s0 = s0_wrap["data"]
        self.assertFalse(s0["has_active_pin"])
        self.assertTrue(s0.get("fp"))
        self.assertEqual(s0.get("fp"), s0.get("cert_fingerprint"))

        qr_resp = await self.client.post("/api/pair/qr", json={"trust_tier": "owner"}, headers=headers)
        self.assertEqual(qr_resp.status, 200)
        qr_wrap = await qr_resp.json()
        self.assertTrue(qr_wrap["success"])
        qr_data = qr_wrap.get("data") or qr_wrap
        pin = qr_data.get("pin") or qr_wrap.get("pin")
        self.assertEqual(len(str(pin or "")), 6)

        state_active = await self.client.get("/api/pair/state", headers=headers)
        s1_wrap = await state_active.json()
        s1 = s1_wrap["data"]
        self.assertTrue(s1["has_active_pin"])
        self.assertEqual(s1["pin"], pin)

        cancel_resp = await self.client.post("/api/pair/cancel", json={}, headers=headers)
        self.assertEqual(cancel_resp.status, 200)
        c_wrap = await cancel_resp.json()
        self.assertTrue(c_wrap["success"])
        c_data = c_wrap.get("data") or c_wrap
        self.assertTrue(c_data["cancelled"])

        state_after = await self.client.get("/api/pair/state", headers=headers)
        s2_wrap = await state_after.json()
        s2 = s2_wrap["data"]
        self.assertFalse(s2["has_active_pin"])
        self.assertIsNone(s2.get("pin"))

        js = (Path(__file__).resolve().parents[1] / "src" / "snow" / "web" / "static" / "app.js").read_text("utf-8")
        self.assertIn("refreshPairingState()", js)
        self.assertIn("res?.data?.fp || res?.fp", js)

    async def test_ws10_ipc_secret_requires_owner_session_and_disables_caching(self) -> None:
        unauth = await self.client.get("/api/system/ipc-secret")
        self.assertEqual(unauth.status, 401)

        headers = await self._auth_headers()
        auth_resp = await self.client.get("/api/system/ipc-secret", headers=headers)
        self.assertEqual(auth_resp.status, 200)
        self.assertIn("no-store", auth_resp.headers.get("Cache-Control", ""))
        body = await auth_resp.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["ipc_secret"], "ipc-test-secret-0123456789abcdef")

        js = (Path(__file__).resolve().parents[1] / "src" / "snow" / "web" / "static" / "app.js").read_text("utf-8")
        self.assertIn("clearRevealedIpcSecret", js)
        self.assertIn("beforeunload", js)

    async def test_ws7_web_destination_endpoints_and_camera_latest(self) -> None:
        headers = await self._auth_headers()
        new_dest = self.tmp_dir / "CustomDownloads"
        new_dest.mkdir(parents=True, exist_ok=True)

        post_resp = await self.client.post(
            "/api/files/destination",
            json={"path": str(new_dest)},
            headers=headers,
        )
        self.assertEqual(post_resp.status, 200)
        pdata = await post_resp.json()
        self.assertTrue(pdata["success"])
        self.assertEqual(pdata["pc_transfers_dir"], str(new_dest.resolve()))

        bad_file = self.tmp_dir / "bad_dest_file.txt"
        bad_file.write_text("nope", encoding="utf-8")
        bad_resp = await self.client.post(
            "/api/files/destination",
            json={"path": str(bad_file)},
            headers=headers,
        )
        self.assertEqual(bad_resp.status, 400)

        sample_photo = new_dest / "android_photo_stage6a.jpg"
        sample_photo.write_bytes(b"\xff\xd8\xff\xe0stage6acamera")
        cam_resp = await self.client.get("/api/camera/latest", headers=headers)
        self.assertEqual(cam_resp.status, 200)
        self.assertEqual(await cam_resp.read(), b"\xff\xd8\xff\xe0stage6acamera")

    async def test_ws5_ota_semver_metadata(self) -> None:
        staging_dir = self.tmp_dir / "ota"
        staging_dir.mkdir(parents=True, exist_ok=True)
        apk_path = staging_dir / "SNOW-Mobile-5.10.0.apk"
        apk_path.write_bytes(b"PK\x03\x04fakeapkcontent")
        http_srv = SnowHttpTransferServer(
            config=CoreConfig(transfer_root=str(self.tmp_dir)),
            db_manager=self.db,
            transfer_manager=TransferManager(),
            storage_manager=self.storage,
        )
        http_srv._get_staged_apk_path = lambda: apk_path  # type: ignore[method-assign]
        resp = await http_srv.handle_app_update_info(MagicMock())
        self.assertEqual(resp.status, 200)
        meta = json.loads(resp.text)
        self.assertTrue(meta["available"])
        self.assertEqual(meta["version_name"], "5.10.0")
        self.assertGreaterEqual(meta["version_code"], 4)


class TestStage6AOAuthAuthorizePage(AioHTTPTestCase):
    """WS10: RemoteMcpGateway GET /oauth/authorize Stitch redesign & CSP nonces."""

    async def get_application(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_s6a_oauth_"))
        self.db = DatabaseManager(self.tmp_dir / "oauth.db")
        self.bridge = MagicMock()
        self.bridge._get_secret.return_value = "secret-test-val"
        self.bridge.capability_engine.db_manager = self.db
        self.gateway = RemoteMcpGateway(host="127.0.0.1", port=8771, bridge=self.bridge)
        reg = self.gateway.oauth_server.register_client(
            client_name="Example Client",
            redirect_uris=["https://example-client.test/callback"],
        )
        self.client_id = reg["client_id"]
        return self.gateway.app

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_ws10_oauth_page_stitch_ui_csp_nonce_and_no_cdn(self) -> None:
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": "https://example-client.test/callback",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "state": "xyz123",
            "scope": "snow:mcp",
            "resource": "http://127.0.0.1:8771/mcp",
        }
        r1 = await self.client.get("/oauth/authorize", params=params)
        r2 = await self.client.get("/oauth/authorize", params=params)

        self.assertEqual(r1.status, 200)
        csp1 = r1.headers.get("Content-Security-Policy", "")
        csp2 = r2.headers.get("Content-Security-Policy", "")
        self.assertIn("style-src 'self' 'nonce-", csp1)
        self.assertNotIn("unsafe-inline", csp1)
        self.assertNotEqual(csp1, csp2)
        self.assertIn("no-store", r1.headers.get("Cache-Control", ""))

        html = await r1.text()
        self.assertIn("Owner Authentication", html)
        self.assertIn("prefers-color-scheme: dark", html)
        self.assertIn("/snow_logo.png", html)
        self.assertNotIn("cdn.", html.lower())
        self.assertNotIn("fonts.googleapis", html.lower())

        logo = await self.client.get("/snow_logo.png")
        self.assertEqual(logo.status, 200)


class TestStage6AExpandedMcpTools(unittest.TestCase):
    """WS12 & WS13: 48-tool catalog parity and functional/security checks for all 6 new tools."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_s6a_mcp_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_48_tool_exact_parity_across_registry_all_tools_and_server(self) -> None:
        ok, errs = validate_registry()
        self.assertTrue(ok, f"validate_registry failed: {errs}")
        self.assertEqual(len(CAPABILITY_REGISTRY), 48)
        self.assertEqual(len(ALL_TOOL_NAMES), 48)
        self.assertEqual(len(list_capabilities()), 48)

        srv = create_snow_mcp_server()
        srv_tools = asyncio.run(srv.list_tools())
        self.assertEqual(len(srv_tools), 48)
        srv_names = {t.name for t in srv_tools}
        self.assertEqual(srv_names, set(CAPABILITY_REGISTRY.keys()))

        expected_new = (
            "snow_youtube_play",
            "snow_web_open",
            "snow_windows_list_windows",
            "snow_windows_focus_window",
            "snow_system_volume_set",
            "snow_federation_peers",
        )
        for name in expected_new:
            self.assertIn(name, srv_names)
            meta = get_capability_metadata(name)
            ann = get_mcp_annotations(name)
            self.assertIsNotNone(meta)
            self.assertIsNotNone(ann)
            self.assertIs(type(ann.readOnlyHint), bool)
            self.assertIs(type(ann.destructiveHint), bool)

    def test_windows_list_and_focus_windows_validation_and_execution(self) -> None:
        sample_windows = [
            {"hwnd": 1001, "window_title": "SNOW Dashboard", "process_id": 123, "process_name": "chrome.exe", "is_foreground": True, "is_minimized": False},
            {"hwnd": 2002, "window_title": "Notepad - Notes.txt", "process_id": 456, "process_name": "notepad.exe", "is_foreground": False, "is_minimized": True},
        ]
        sys_ctrl = WindowsSystemControls(
            list_windows_fn=lambda inc, lim: {"success": True, "status": "SUCCESS", "count": len(sample_windows), "windows": sample_windows[:lim]},
            focus_window_fn=lambda hwnd, title, proc: {"success": True, "status": "SUCCESS", "hwnd": hwnd or 2002, "focused": True, "title_matched": title or proc},
        )
        engine = CapabilityEngine(allowed_roots=[self.tmp_dir], system=sys_ctrl)
        bridge = SnowMcpBridge(auto_start_core=False)
        bridge.capability_engine = engine
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)

        list_res = asyncio.run(bridge.windows_list_windows(limit=10))
        self.assertTrue(list_res["success"])
        self.assertEqual(list_res["data"]["count"], 2)

        bad_focus = asyncio.run(bridge.windows_focus_window())
        self.assertFalse(bad_focus["success"])
        self.assertEqual(bad_focus["status"], "INVALID_ARGUMENT")

        bad_hwnd = asyncio.run(bridge.windows_focus_window(hwnd=-5))
        self.assertFalse(bad_hwnd["success"])
        self.assertEqual(bad_hwnd["status"], "INVALID_ARGUMENT")

        ok_focus = asyncio.run(bridge.windows_focus_window(title_contains="Notepad"))
        self.assertTrue(ok_focus["success"])
        self.assertTrue(ok_focus["data"]["focused"])

    def test_youtube_play_and_web_open_validation_and_dispatch(self) -> None:
        bridge = SnowMcpBridge(auto_start_core=False)
        bridge.capability_engine = CapabilityEngine(allowed_roots=[self.tmp_dir])
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)
        bridge.share_link = AsyncMock(return_value={"success": True, "status": "SUCCESS", "data": {"opened": True}})

        for bad_url in ("javascript:alert(1)", "file:///C:/Windows/win.ini", "ftp://example.com", "https://not youtube.com/a", "http:///missinghost"):
            bad = asyncio.run(bridge.web_open(url=bad_url))
            self.assertFalse(bad["success"], f"Expected rejection for {bad_url}")
            self.assertEqual(bad["status"], "INVALID_URL_SCHEME")

        bad_yt = asyncio.run(bridge.youtube_play(url="https://evil.example.com/watch?v=1"))
        self.assertFalse(bad_yt["success"])
        self.assertEqual(bad_yt["status"], "INVALID_YOUTUBE_URL")

        bad_target = asyncio.run(bridge.web_open(url="https://example.com", target="mars"))
        self.assertFalse(bad_target["success"])
        self.assertEqual(bad_target["status"], "INVALID_TARGET")

        ok_yt_q = asyncio.run(bridge.youtube_play(query="lofi coding", target="android"))
        self.assertTrue(ok_yt_q["success"])
        bridge.share_link.assert_awaited_with(
            url="https://www.youtube.com/results?search_query=lofi+coding",
            target="android",
            device_id="",
        )

        ok_web = asyncio.run(bridge.web_open(url="https://docs.python.org/3/", target="windows"))
        self.assertTrue(ok_web["success"])
        bridge.share_link.assert_awaited_with(url="https://docs.python.org/3/", target="windows", device_id="")

    def test_system_volume_set_bounds_and_federation_peers_redaction(self) -> None:
        db = DatabaseManager(self.tmp_dir / "fed.db")
        fed = FederationManager(db_manager=db, local_node_id="desktop-core")
        exp = (datetime.now(timezone.utc) + timedelta(hours=4)).isoformat()
        db.create_federation_grant(
            grant_id="grant-1",
            network_id="net-peer-1",
            network_name="Lab Mesh",
            peer_node_id="peer-host-1",
            peer_node_name="Workstation B",
            peer_cert_fingerprint="AA:BB",
            direction="OUTBOUND",
            auth_token_hash="super-secret-hash-value",
            allowed_capabilities_json=json.dumps(["desktop.status"]),
            allowed_device_ids_json=json.dumps(["phone-1"]),
            created_timestamp=datetime.now(timezone.utc).isoformat(),
            expires_timestamp=exp,
        )

        bridge = SnowMcpBridge(auto_start_core=False)
        bridge.capability_engine = CapabilityEngine(allowed_roots=[self.tmp_dir], db_manager=db)
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)
        bridge.media_control = AsyncMock(return_value={"success": True, "status": "SUCCESS", "data": {"volume_percent": 65}})

        for bad_level in (-1, 101, True, False, "50"):  # type: ignore[arg-type]
            bad_vol = asyncio.run(bridge.system_volume_set(level=bad_level))
            self.assertFalse(bad_vol["success"], f"Expected rejection for {bad_level!r}")
            self.assertEqual(bad_vol["status"], "INVALID_VOLUME_LEVEL")

        ok_vol = asyncio.run(bridge.system_volume_set(level=65, target="windows"))
        self.assertTrue(ok_vol["success"])
        bridge.media_control.assert_awaited_with(action="volume_set", target="windows", device_id="", value=65)

        fed_res = asyncio.run(bridge.federation_peers())
        self.assertTrue(fed_res["success"])
        fed_data = fed_res["data"]
        self.assertEqual(fed_data["active_count"], 1)
        self.assertEqual(fed_data["grants"][0]["grant_id"], "grant-1")
        raw_fed = json.dumps(fed_res)
        self.assertNotIn("super-secret-hash-value", raw_fed)
        self.assertNotIn("auth_token", raw_fed)


if __name__ == "__main__":
    unittest.main()
