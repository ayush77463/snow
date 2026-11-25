"""Stage 5C Closure Behavioral & Security Regression Tests.

Verifies:
1. Authenticated WSS capability parity (`clipboard_buffer_pin`/`unpin`/`delete`/`clear`,
   `media_control`, `share_link`) with fail-closed auth, policy, AI_MCP denial,
   PAUSE mode enforcement, and payload validation.
2. Live `/api/system/status` wiring -> `get_device_status` and `"status"` IPC alias.
3. Web V5 override completeness (requiring all 5 assets including `tokens.css` and `theme-init.js`).
4. Updater `stop_core` invocation + hidden console kwargs for Authenticode subprocesses.
5. `WindowsMediaController` bounded `volume_set` (0..100), COM scalar math, and `/api/media`.
6. `/api/mcp/tunnel/config` GET/POST redaction and write-only token preservation.
7. `SNOW-Mobile-5.0.0.apk` priority and `5.0.0` / `version_code = 2` consistency.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp.test_utils import AioHTTPTestCase

import snow
from snow.capabilities.clipboard_buffer import ClipboardRingBuffer
from snow.capabilities.engine import ExecutionContext, ExecutionPrincipal
from snow.capabilities.windows.media import WindowsMediaController
from snow.core.config import CoreConfig
from snow.core.ipc import IPC_PROTOCOL_VERSION, SnowIpcServer
from snow.network.connection_manager import ClientConnection, ConnectionManager
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode
from snow.protocol.models import SnowMessage
from snow.security.db import DatabaseManager
from snow.security.policy import (
    ACTION_TO_CAPABILITY,
    CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    PeerCapabilityPolicy,
)
from snow.security.session import SessionManager
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferManager
from snow.transfer.storage import TransferStorageManager
from snow.updater import CURRENT_VERSION, REQUIRED_UI_ASSETS, apply_desktop_installer_update, verify_authenticode_or_pe
from snow.web.server import STATIC_DIR, SnowWebServer


class _FakeWebSocket:
    def __init__(self) -> None:
        self.sent: list[str] = []

    async def send(self, payload: str) -> None:
        self.sent.append(payload)

    def last_json(self) -> dict:
        assert self.sent, "No WebSocket frames were sent"
        return json.loads(self.sent[-1])


class TestStage5CWssCapabilityParity(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self._prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = self.temp_dir.name

        self.db_mgr = DatabaseManager(Path(self.temp_dir.name) / "test.db")
        self.conn_mgr = ConnectionManager()
        self.session_mgr = SessionManager()
        self.policy = PeerCapabilityPolicy()

        self.core_server = MagicMock()
        self.core_server.is_paused = False
        self.core_server.capability_policy = self.policy

        self.config = CoreConfig(
            bind_host="127.0.0.1",
            port=8765,
            tls_enabled=False,
            auth_required=True,
        )
        self.server = SnowWebSocketServer(
            config=self.config,
            connection_manager=self.conn_mgr,
            db_manager=self.db_mgr,
            session_manager=self.session_mgr,
            core_server=self.core_server,
        )
        # Replace engine's clipboard buffer with a clean temp-backed instance
        self.clip_buf = ClipboardRingBuffer(storage_dir=Path(self.temp_dir.name) / "clips")
        self.server.capability_engine.clipboard_buffer = self.clip_buf

        # Mock OS side effects on WindowsMediaController and ClipboardManager
        self.server.capability_engine.media_controller.is_windows = False
        self.server.capability_engine.clipboard = MagicMock()
        self.server.capability_engine.clipboard.set_clipboard = AsyncMock(
            return_value={"success": True, "status": "SUCCESS"}
        )

        # Seed one text item in the authoritative shared clipboard buffer
        add_res = self.clip_buf.add_text("Hello SNOW V5", source_device_id="seed")
        self.assertTrue(add_res["success"])
        self.item_id = add_res["item"]["item_id"]

        # Register owner device + session and peer device + session
        self.owner_id = "dev-owner-01"
        self.peer_id = "dev-peer-01"
        self.db_mgr.insert_paired_device(
            device_id=self.owner_id,
            device_name="Owner Phone",
            auth_token_hash="hash_owner",
            trust_tier="owner",
            platform="android",
        )
        self.db_mgr.insert_paired_device(
            device_id=self.peer_id,
            device_name="Peer Phone",
            auth_token_hash="hash_peer",
            trust_tier="peer",
            platform="android",
        )

        self.owner_ws = _FakeWebSocket()
        self.owner_client = ClientConnection(
            connection_id="conn-owner",
            websocket=self.owner_ws,
            remote_address="127.0.0.1:50001",
            connected_at=0.0,
            last_heartbeat_at=0.0,
        )
        self.session_mgr.create_session(device_id=self.owner_id, connection_id="conn-owner")

        self.peer_ws = _FakeWebSocket()
        self.peer_client = ClientConnection(
            connection_id="conn-peer",
            websocket=self.peer_ws,
            remote_address="127.0.0.1:50002",
            connected_at=0.0,
            last_heartbeat_at=0.0,
        )
        self.session_mgr.create_session(device_id=self.peer_id, connection_id="conn-peer")

    async def asyncTearDown(self) -> None:
        self.server.stop_clipboard_listener()
        if self._prev_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self._prev_data_dir
        self.temp_dir.cleanup()

    async def test_unauthenticated_wss_actions_fail_closed(self) -> None:
        anon_ws = _FakeWebSocket()
        anon_client = ClientConnection(
            connection_id="conn-anon",
            websocket=anon_ws,
            remote_address="127.0.0.1:50099",
            connected_at=0.0,
            last_heartbeat_at=0.0,
        )
        for action, data in [
            ("clipboard_buffer_pin", {"item_id": self.item_id, "is_pinned": True}),
            ("clipboard_buffer_unpin", {"item_id": self.item_id}),
            ("clipboard_buffer_delete", {"item_id": self.item_id}),
            ("clipboard_buffer_clear", {"unpinned_only": True}),
            ("media_control", {"action": "play_pause"}),
            ("share_link", {"url": "https://example.com"}),
        ]:
            msg = SnowMessage.create_request(action=action, data=data)
            await self.server._handle_request(anon_client, msg)
            frame = anon_ws.last_json()
            self.assertEqual(frame["error"]["code"], ErrorCode.UNAUTHORIZED)

    async def test_owner_pin_unpin_delete_clear_over_wss(self) -> None:
        # Pin with is_pinned=True
        await self.server._handle_request(
            self.owner_client,
            SnowMessage.create_request("clipboard_buffer_pin", {"item_id": self.item_id, "is_pinned": True}),
        )
        res = self.owner_ws.last_json()
        self.assertEqual(res["payload"]["status"], "success")
        self.assertTrue(res["payload"]["item"]["pinned"])

        # Toggle unpin via clipboard_buffer_pin(is_pinned=False)
        await self.server._handle_request(
            self.owner_client,
            SnowMessage.create_request("clipboard_buffer_pin", {"item_id": self.item_id, "is_pinned": False}),
        )
        res = self.owner_ws.last_json()
        self.assertEqual(res["payload"]["status"], "success")
        self.assertFalse(res["payload"]["item"]["pinned"])

        # Pin then explicit unpin action
        await self.server._handle_request(
            self.owner_client,
            SnowMessage.create_request("clipboard_buffer_pin", {"item_id": self.item_id}),
        )
        await self.server._handle_request(
            self.owner_client,
            SnowMessage.create_request("clipboard_buffer_unpin", {"item_id": self.item_id}),
        )
        res = self.owner_ws.last_json()
        self.assertFalse(res["payload"]["item"]["pinned"])

        # Delete item
        await self.server._handle_request(
            self.owner_client,
            SnowMessage.create_request("clipboard_buffer_delete", {"item_id": self.item_id}),
        )
        res = self.owner_ws.last_json()
        self.assertEqual(res["payload"]["status"], "success")
        self.assertEqual(len(self.clip_buf.list_items()), 0)

        # Seed pinned + unpinned and verify clear(unpinned_only=True) preserves pinned
        r1 = self.clip_buf.add_text("Pinned Note", source_device_id="seed", pin=True)
        r2 = self.clip_buf.add_text("Temp Note", source_device_id="seed", pin=False)
        await self.server._handle_request(
            self.owner_client,
            SnowMessage.create_request("clipboard_buffer_clear", {"unpinned_only": True}),
        )
        res = self.owner_ws.last_json()
        self.assertEqual(res["payload"]["status"], "success")
        remaining_ids = [i["item_id"] for i in self.clip_buf.list_items()]
        self.assertEqual(remaining_ids, [r1["item"]["item_id"]])
        self.assertNotIn(r2["item"]["item_id"], remaining_ids)

    async def test_peer_ai_mcp_authorization_and_owner_only_denials(self) -> None:
        # AI_MCP peer is denied destructive clipboard delete/clear even though write capability exists
        for action, payload in [
            ("clipboard_buffer_delete", {"item_id": self.item_id}),
            ("clipboard_buffer_clear", {"unpinned_only": False}),
        ]:
            await self.server._handle_request(self.peer_client, SnowMessage.create_request(action, payload))
            frame = self.peer_ws.last_json()
            self.assertEqual(frame["error"]["code"], ErrorCode.UNAUTHORIZED)

        # Peer is denied media_control & share_link by default (not in DEFAULT_PAIRED_CAPABILITIES)
        await self.server._handle_request(
            self.peer_client, SnowMessage.create_request("media_control", {"action": "play_pause"})
        )
        self.assertEqual(self.peer_ws.last_json()["error"]["code"], ErrorCode.UNAUTHORIZED)

        await self.server._handle_request(
            self.peer_client, SnowMessage.create_request("share_link", {"url": "https://example.com"})
        )
        self.assertEqual(self.peer_ws.last_json()["error"]["code"], ErrorCode.UNAUTHORIZED)

        # Explicitly grant peer device media_control & share_link -> succeeds
        self.policy.device_overrides[self.peer_id] = {"media_control", "share_link"}
        await self.server._handle_request(
            self.peer_client, SnowMessage.create_request("media_control", {"action": "volume_set", "value": 60})
        )
        res_media = self.peer_ws.last_json()
        self.assertEqual(res_media["payload"]["status"], "success")
        self.assertEqual(res_media["payload"]["data"]["volume_percent"], 60)

        with patch("webbrowser.open", return_value=True) as mock_open:
            await self.server._handle_request(
                self.peer_client, SnowMessage.create_request("share_link", {"url": "https://example.org/docs"})
            )
            mock_open.assert_called_once_with("https://example.org/docs")
            res_share = self.peer_ws.last_json()
            self.assertEqual(res_share["payload"]["status"], "success")

    async def test_pause_mode_blocks_peer_allows_owner(self) -> None:
        self.core_server.is_paused = True
        await self.server._handle_request(
            self.peer_client,
            SnowMessage.create_request("clipboard_buffer_pin", {"item_id": self.item_id, "is_pinned": True}),
        )
        self.assertEqual(self.peer_ws.last_json()["error"]["code"], ErrorCode.UNAUTHORIZED)

        await self.server._handle_request(
            self.owner_client,
            SnowMessage.create_request("clipboard_buffer_pin", {"item_id": self.item_id, "is_pinned": True}),
        )
        self.assertEqual(self.owner_ws.last_json()["payload"]["status"], "success")

    async def test_wss_input_validation_rejects_malformed_ids_schemes_and_volumes(self) -> None:
        # Malformed item_id
        await self.server._handle_request(
            self.owner_client,
            SnowMessage.create_request("clipboard_buffer_pin", {"item_id": "bad-id"}),
        )
        self.assertEqual(self.owner_ws.last_json()["error"]["code"], ErrorCode.INVALID_PAYLOAD)

        # Non-bool is_pinned
        await self.server._handle_request(
            self.owner_client,
            SnowMessage.create_request("clipboard_buffer_pin", {"item_id": self.item_id, "is_pinned": "yes"}),
        )
        self.assertEqual(self.owner_ws.last_json()["error"]["code"], ErrorCode.INVALID_PAYLOAD)

        # Missing item_id on delete
        await self.server._handle_request(
            self.owner_client,
            SnowMessage.create_request("clipboard_buffer_delete", {"item_id": "cb_abcdef123456_654321"}),
        )
        self.assertEqual(self.owner_ws.last_json()["error"]["code"], ErrorCode.FILE_NOT_FOUND)

        # Bool / out-of-range volume
        for bad_val in (True, -5, 105):
            await self.server._handle_request(
                self.owner_client,
                SnowMessage.create_request("media_control", {"action": "volume_set", "value": bad_val}),
            )
            self.assertEqual(self.owner_ws.last_json()["error"]["code"], ErrorCode.INVALID_PAYLOAD)

        # Dangerous URL scheme
        with patch("webbrowser.open") as mock_open:
            await self.server._handle_request(
                self.owner_client,
                SnowMessage.create_request("share_link", {"url": "javascript:alert(1)"}),
            )
            mock_open.assert_not_called()
            self.assertEqual(self.owner_ws.last_json()["error"]["code"], ErrorCode.INVALID_PAYLOAD)


class TestStage5CUpdaterMediaAndVersionUnit(unittest.TestCase):
    def test_required_ui_assets_enforces_tokens_and_theme_init_fallback(self) -> None:
        for asset in ("index.html", "app.js", "app.css", "tokens.css", "theme-init.js"):
            self.assertIn(asset, REQUIRED_UI_ASSETS)

        with tempfile.TemporaryDirectory() as tmp:
            fake_home = Path(tmp)
            override_dir = fake_home / ".snow" / "web_override"
            override_dir.mkdir(parents=True)
            # Populate only legacy 3 files (missing tokens.css and theme-init.js)
            for name in ("index.html", "app.js", "app.css"):
                (override_dir / name).write_text("legacy", encoding="utf-8")

            server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)
            with patch("pathlib.Path.home", return_value=fake_home):
                self.assertEqual(server._get_active_static_dir(), STATIC_DIR)
                # Adding tokens.css + theme-init.js activates override cleanly
                (override_dir / "tokens.css").write_text(":root{}", encoding="utf-8")
                (override_dir / "theme-init.js").write_text("(()=>{})()", encoding="utf-8")
                self.assertEqual(server._get_active_static_dir().resolve(), override_dir.resolve())

    def test_updater_calls_stop_core_and_passes_no_window_kwargs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fake_exe = Path(tmp) / "SNOW-Setup-5.0.0.exe"
            fake_exe.write_bytes(b"MZ" + b"\x00" * 128)
            import hashlib
            sha = hashlib.sha256(fake_exe.read_bytes()).hexdigest()

            daemon_mgr = MagicMock()
            daemon_mgr.stop_core = MagicMock()

            with patch("snow.updater.verify_authenticode_or_pe", return_value=True), \
                 patch("snow.updater.subprocess.Popen") as mock_popen:
                apply_desktop_installer_update(
                    installer_path=str(fake_exe),
                    expected_sha256=sha,
                    execute=True,
                    daemon_manager=daemon_mgr,
                )
                daemon_mgr.stop_core.assert_called_once()
                mock_popen.assert_called_once()
                kwargs = mock_popen.call_args.kwargs
                self.assertIn("creationflags", kwargs)

            with patch("snow.updater.subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0, stdout="Valid\n")
                self.assertTrue(verify_authenticode_or_pe(fake_exe))
                mock_run.assert_called_once()
                self.assertIn("creationflags", mock_run.call_args.kwargs)

    def test_windows_media_controller_bounded_volume_and_stop_mute(self) -> None:
        ctrl = WindowsMediaController()
        ctrl.is_windows = False

        res_ok = ctrl.handle_action("volume_set", 75)
        self.assertTrue(res_ok["success"])
        self.assertEqual(res_ok["action"], "volume_set")

        res_stop = ctrl.handle_action("stop")
        self.assertTrue(res_stop["success"])
        self.assertEqual(res_stop["action"], "stop")

        res_mute = ctrl.handle_action("volume_mute")
        self.assertTrue(res_mute["success"])
        self.assertEqual(res_mute["action"], "volume_mute")

        for bad in (True, False, -1, 101, "50", float("nan"), float("inf")):
            err = ctrl.handle_action("volume_set", bad)
            self.assertFalse(err["success"])
            self.assertEqual(err["status"], "INVALID_VOLUME_LEVEL")

    def test_apk_5_0_0_priority_and_version_alignment(self) -> None:
        self.assertEqual(snow.__version__, "5.1.0")
        self.assertEqual(CoreConfig().version, "5.1.0")
        self.assertEqual(CURRENT_VERSION, "5.1.0")
        self.assertEqual(ACTION_TO_CAPABILITY["clipboard_buffer_pin"], CAPABILITY_DESKTOP_CLIPBOARD_WRITE)

        with tempfile.TemporaryDirectory() as tmp:
            pkg_out = Path(tmp) / "packaging" / "output"
            pkg_out.mkdir(parents=True)
            apk4 = pkg_out / "SNOW-Mobile-4.1.0.apk"
            apk50 = pkg_out / "SNOW-Mobile-5.0.0.apk"
            apk5 = pkg_out / "SNOW-Mobile-5.1.0.apk"
            apk4.write_bytes(b"PK41")
            apk50.write_bytes(b"PK50")
            apk5.write_bytes(b"PK51")

            cfg = CoreConfig(version="5.1.0")
            db = DatabaseManager(Path(tmp) / "t.db")
            http_srv = SnowHttpTransferServer(
                config=cfg,
                db_manager=db,
                transfer_manager=TransferManager(),
                storage_manager=TransferStorageManager(tmp),
            )
            fake_exe = Path(tmp) / "snow.exe"
            fake_http_mod = Path(tmp) / "src" / "snow" / "transfer" / "http_server.py"
            fake_http_mod.parent.mkdir(parents=True, exist_ok=True)
            fake_http_mod.touch()
            import snow.transfer.http_server as http_mod
            with patch("sys.executable", str(fake_exe)), \
                 patch.object(http_mod, "__file__", str(fake_http_mod)):
                self.assertEqual(http_srv._get_staged_apk_path().resolve(), apk5.resolve())
                web_srv = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)
                self.assertEqual(web_srv._find_candidate_apk().resolve(), apk5.resolve())

    def test_core_ipc_dispatches_status_and_get_device_status(self) -> None:
        ipc = SnowIpcServer(core_server=MagicMock(), config=CoreConfig(port=8765, ipc_port=0))
        ipc._handle_get_device_status = MagicMock(
            return_value={"core_running": True, "is_paused": False}
        )
        res1, _ = asyncio.run(
            ipc._dispatch_request(
                {"version": IPC_PROTOCOL_VERSION, "op": "get_device_status", "request_id": "1"},
                is_connection_authenticated=True,
            )
        )
        res2, _ = asyncio.run(
            ipc._dispatch_request(
                {"version": IPC_PROTOCOL_VERSION, "op": "status", "request_id": "2"},
                is_connection_authenticated=True,
            )
        )
        self.assertTrue(res1["success"])
        self.assertTrue(res1["data"]["core_running"])
        self.assertTrue(res2["success"])
        self.assertTrue(res2["data"]["core_running"])
        self.assertEqual(ipc._handle_get_device_status.call_count, 2)


class TestStage5CWebClosureEndpoints(AioHTTPTestCase):
    async def get_application(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self._prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = self.temp_dir.name

        self.bridge = MagicMock()
        self.bridge.call = AsyncMock(
            return_value={"success": True, "data": {"core_running": True, "is_paused": True}}
        )
        self.bridge.media_control = AsyncMock(
            return_value={"success": True, "status": "SUCCESS", "action": "volume_set", "volume_percent": 42}
        )
        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.bridge,
            auto_open_browser=False,
        )
        return self.web_server.create_app()

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        if self._prev_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self._prev_data_dir
        self.temp_dir.cleanup()

    async def _authenticate(self) -> str:
        resp = await self.client.post(
            "/api/auth/session",
            json={"token": self.web_server.bootstrap_token},
        )
        self.assertEqual(resp.status, 200)
        body = await resp.json()
        return body["csrf_token"]

    async def test_live_system_status_media_validation_and_tunnel_config(self) -> None:
        csrf = await self._authenticate()
        headers = {"X-CSRF-Token": csrf}

        # 1. /api/system/status calls bridge.call("get_device_status") and reports live paused state
        st_resp = await self.client.get("/api/system/status")
        self.assertEqual(st_resp.status, 200)
        st_body = await st_resp.json()
        self.assertTrue(st_body["success"])
        self.assertTrue(st_body["core_running"])
        self.assertTrue(st_body["is_paused"])
        self.bridge.call.assert_awaited_with("get_device_status")

        # 2. /api/media bounded volume_set & invalid rejections
        m_ok = await self.client.post(
            "/api/media",
            json={"action": "volume_set", "value": 42, "target": "windows"},
            headers=headers,
        )
        self.assertEqual(m_ok.status, 200)
        self.bridge.media_control.assert_awaited_with(
            action="volume_set", target="windows", device_id="", value=42
        )

        for bad in (-1, 101, True):
            m_bad = await self.client.post(
                "/api/media",
                json={"action": "volume_set", "value": bad, "target": "windows"},
                headers=headers,
            )
            self.assertEqual(m_bad.status, 400)

        for non_finite in ("NaN", "Infinity", "-Infinity"):
            m_nf = await self.client.post(
                "/api/media",
                data=f'{{"action": "volume_set", "value": {non_finite}, "target": "windows"}}',
                headers={**headers, "Content-Type": "application/json"},
            )
            self.assertEqual(m_nf.status, 400)

        # 3. /api/mcp/tunnel/config write, redaction, and non-clobbering update
        t_save = await self.client.post(
            "/api/mcp/tunnel/config",
            json={
                "provider": "cloudflared",
                "mcp_public_url": "https://snow-test.example.com",
                "mcp_cloudflare_token": "cf-secret-token-987654321",
            },
            headers=headers,
        )
        self.assertEqual(t_save.status, 200)
        t_save_body = await t_save.json()
        self.assertNotIn("987654321", json.dumps(t_save_body))

        t_get = await self.client.get("/api/mcp/tunnel/config")
        self.assertEqual(t_get.status, 200)
        t_get_body = await t_get.json()
        self.assertEqual(t_get_body["config"]["provider"], "cloudflared")
        self.assertEqual(t_get_body["config"]["mcp_public_url"], "https://snow-test.example.com")
        self.assertNotIn("987654321", json.dumps(t_get_body))

        # Saving without token must preserve stored token on disk
        t_update = await self.client.post(
            "/api/mcp/tunnel/config",
            json={"provider": "custom", "mcp_public_url": "https://snow-custom.example.com"},
            headers=headers,
        )
        self.assertEqual(t_update.status, 200)
        from snow.mcp.tunnel import load_tunnel_config
        stored = load_tunnel_config()
        self.assertEqual(stored.get("mcp_cloudflare_token"), "cf-secret-token-987654321")
        self.assertEqual(stored.get("provider"), "custom")
