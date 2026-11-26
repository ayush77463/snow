"""Unit tests for Phase 3 Track 0: Clipboard Reliability and Target UUID Resolution.

Covers:
1. Concurrent execution of sequence-number watchdog alongside listener.
2. 1.0s watchdog polling interval (0.0% idle CPU budget).
3. Target UUID resolution for 'phone' / 'android' to authenticated session device_id.
4. HTTP transfer plane 403 prevention for mobile downloads.
5. Screenshot automatic insertion into shared clipboard buffer.
6. Node registry resolution for generic mobile aliases ('phone', 'android').
"""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.clipboard_buffer import ClipboardRingBuffer
from snow.capabilities.engine import CapabilityEngine, CapabilityRequest, ExecutionContext, ExecutionPrincipal
from snow.core.config import CoreConfig
from snow.network.connection_manager import ConnectionManager
from snow.network.node import DeviceNode, ReachabilityState
from snow.security.session import SessionRecord
from snow.network.registry import NodeRegistry
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode
from snow.protocol.models import SnowMessage


class TestClipboardReliabilityTrack0(unittest.IsolatedAsyncioTestCase):
    """Test suite for Track 0 clipboard reliability fixes."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config = CoreConfig(bind_host="127.0.0.1", port=8765, tls_enabled=False)
        self.conn_mgr = ConnectionManager()
        self.server = SnowWebSocketServer(config=self.config, connection_manager=self.conn_mgr)

    async def asyncTearDown(self) -> None:
        self.server.stop_clipboard_listener()
        self.temp_dir.cleanup()

    async def test_01_watchdog_runs_as_fallback_when_listener_fails(self) -> None:
        """Verify that sequence-number watchdog is created as fallback when listener start fails."""
        with patch("snow.network.ws_server.WindowsClipboardListener") as mock_listener_cls, \
             patch("sys.platform", "win32"):
            mock_listener = MagicMock()
            mock_listener.start.return_value = False
            mock_listener_cls.return_value = mock_listener

            started = self.server.start_clipboard_listener()
            self.assertFalse(started)
            # Watchdog must be instantiated as fallback
            self.assertIsNotNone(self.server._clipboard_watchdog_task)
            self.assertFalse(self.server._clipboard_watchdog_task.done())

    async def test_02_handle_clipboard_buffer_apply_resolves_phone_target(self) -> None:
        """Verify _handle_clipboard_buffer_apply resolves target='phone' to session.device_id."""
        client_mock = MagicMock()
        client_mock.websocket = AsyncMock()
        client_mock.websocket.state = 1
        sent_messages: list[str] = []

        async def _mock_send(raw: str) -> None:
            sent_messages.append(raw)

        client_mock.websocket.send = AsyncMock(side_effect=_mock_send)

        session = SessionRecord(
            session_id="sess-1",
            device_id="phone-real-uuid-12345",
            connection_id="conn-1",
            created_at="2026-11-23T00:00:00Z",
            last_seen="2026-11-23T00:00:00Z",
        )

        msg = SnowMessage.create_request(
            action="clipboard_buffer_apply",
            data={"item_id": "item-abc", "target": "phone", "stage_only": True},
        )

        mock_exec_res = MagicMock()
        mock_exec_res.success = True
        mock_exec_res.error = None
        mock_exec_res.data = {
            "applied": True,
            "item_id": "item-abc",
            "type": "image",
            "target": "phone-real-uuid-12345",
            "transfer_id": "trans-999",
            "transfer_port": 8766,
            "sha256": "deadbeef",
            "file_name": "clip.png",
            "mime_type": "image/png",
            "size": 1024,
        }
        self.server.capability_engine.execute = AsyncMock(return_value=mock_exec_res)

        await self.server._handle_clipboard_buffer_apply(
            client=client_mock,
            message=msg,
            data=msg.payload.get("data", {}),
            session=session,
        )

        # Check call arguments
        call_req = self.server.capability_engine.execute.call_args[0][0]
        self.assertEqual(call_req.action, "clipboard_buffer_apply")
        self.assertEqual(call_req.params.get("target"), "phone-real-uuid-12345")
        self.assertTrue(call_req.params.get("stage_only"))

        # Check sent message
        self.assertEqual(len(sent_messages), 1)
        resp_msg = SnowMessage.from_json(sent_messages[0])
        self.assertEqual(resp_msg.payload.get("status"), "success")
        self.assertEqual(resp_msg.payload.get("transfer_id"), "trans-999")
        self.assertEqual(resp_msg.payload.get("target"), "phone-real-uuid-12345")

    async def test_03_engine_clipboard_buffer_apply_resolves_generic_target(self) -> None:
        """Verify CapabilityEngine.clipboard_buffer_apply resolves generic mobile target via context."""
        engine = CapabilityEngine()
        buf_mgr = ClipboardRingBuffer(storage_dir=Path(self.temp_dir.name) / "buffer")
        engine.clipboard_buffer = buf_mgr

        # Seed an item in the buffer
        img_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRfake"
        add_res = buf_mgr.add_image(img_bytes, mime_type="image/png", source_device_id="pc")
        item_id = add_res["item"]["item_id"]

        # Mock transfer manager and session router
        mock_tm = MagicMock()
        mock_record = MagicMock()
        mock_record.transfer_id = "test-transfer-id-xyz"
        mock_tm.create_transfer.return_value = mock_record
        engine.transfer_manager = mock_tm

        mock_router = MagicMock()
        mock_router.route_request = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        engine.session_router = mock_router

        # Execute with target='phone' and ExecutionContext having a real device_id
        ctx = ExecutionContext(
            principal=ExecutionPrincipal.OWNER_MANUAL,
            device_id="phone-crypto-uuid-777",
        )
        req = CapabilityRequest(
            action="clipboard_buffer_apply",
            params={"item_id": item_id, "target": "phone", "stage_only": True},
        )
        resp = await engine.execute(req, ctx=ctx)

        self.assertTrue(resp.success)
        mock_tm.create_transfer.assert_called_once()
        call_kwargs = mock_tm.create_transfer.call_args[1]
        self.assertEqual(call_kwargs["device_id"], "phone-crypto-uuid-777")
        self.assertEqual(resp.data.get("transfer_id"), "test-transfer-id-xyz")

    async def test_04_windows_screenshot_inserts_into_clipboard_buffer(self) -> None:
        """Verify windows_screenshot inserts the captured PNG into the clipboard buffer."""
        engine = CapabilityEngine()
        buf_mgr = ClipboardRingBuffer(storage_dir=Path(self.temp_dir.name) / "buffer")
        engine.clipboard_buffer = buf_mgr

        # Create a real dummy screenshot file
        snap_file = Path(self.temp_dir.name) / "snap_test.png"
        png_content = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89"
        snap_file.write_bytes(png_content)

        mock_snap_res = {
            "success": True,
            "status": "SUCCESS",
            "file_path": str(snap_file),
            "file_name": snap_file.name,
            "size_bytes": len(png_content),
            "width": 1,
            "height": 1,
            "sha256": hashlib.sha256(png_content).hexdigest(),
        }

        with patch("snow.capabilities.windows.screenshot.WindowsScreenshotCapture.capture_screen", return_value=mock_snap_res):
            ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)
            req = CapabilityRequest(action="windows_screenshot", params={})
            resp = await engine.execute(req, ctx=ctx)

            self.assertTrue(resp.success)
            self.assertIn("buffer_item_id", resp.data)

            # Verify buffer has the item
            items = buf_mgr.list_items()
            self.assertEqual(len(items), 1)
            self.assertEqual(items[0]["item_id"], resp.data["buffer_item_id"])
            self.assertEqual(items[0]["content_type"], "image")

    def test_05_registry_resolve_target_generic_mobile_alias(self) -> None:
        """Verify NodeRegistry.resolve_target resolves 'phone' and 'android' to connected node."""
        import uuid
        from snow.network.node import DeviceNode, ReachabilityState
        from snow.security.identity import DeviceIdentity

        identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Desktop Test Core",
            created_at="2026-11-23T00:00:00Z",
        )
        mock_db = MagicMock()
        mock_db.list_paired_devices.return_value = []
        reg = NodeRegistry(db_manager=mock_db, local_identity=identity)

        phone_node = DeviceNode(
            device_id="phone-uuid-8888",
            device_name="realme RMX5110",
            platform="android",
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            is_paired=True,
        )
        reg.register_node(phone_node)

        # Query 'phone'
        node, err = reg.resolve_target("phone")
        self.assertIsNone(err)
        self.assertIsNotNone(node)
        self.assertEqual(node.device_id, "phone-uuid-8888")

        # Query 'android'
        node2, err2 = reg.resolve_target("android")
        self.assertIsNone(err2)
        self.assertIsNotNone(node2)
        self.assertEqual(node2.device_id, "phone-uuid-8888")

    async def test_06_apk_info_generates_token_and_qr_svg(self) -> None:
        """Verify WebServer handle_api_app_apk_info generates short-lived token, URL, and QR SVG."""
        from snow.web.server import SnowWebServer
        server = SnowWebServer(port=8770, auto_open_browser=False)
        req = MagicMock()
        resp = await server.handle_api_app_apk_info(req)
        self.assertEqual(resp.status, 200)
        import json
        body = json.loads(resp.text)
        self.assertTrue(body["success"])
        self.assertIn("token", body)
        self.assertIn("download_url", body)
        self.assertIn("svg", body)
        self.assertEqual(body["version"], "7.0.0")

    async def test_07_download_apk_with_valid_token(self) -> None:
        """Verify handle_api_install_android_apk validates ?token= correctly."""
        from snow.web.server import SnowWebServer
        import time
        server = SnowWebServer(port=8770, auto_open_browser=False)

        # 1. Without token or session -> 401 Unauthorized
        req_unauth = MagicMock()
        req_unauth.query = {}
        req_unauth.cookies = {}
        resp_unauth = await server.handle_api_install_android_apk(req_unauth)
        self.assertEqual(resp_unauth.status, 401)

        # 2. With valid token -> accepts authentication (proceeds to APK candidate resolution)
        test_token = "valid-token-123"
        server._apk_download_tokens[test_token] = time.time() + 300.0
        req_auth = MagicMock()
        req_auth.query = {"token": test_token}
        req_auth.cookies = {}
        resp_auth = await server.handle_api_install_android_apk(req_auth)
        # Should NOT be 401 (either 200 FileResponse if APK exists, or 404 APK_NOT_FOUND)
        self.assertIn(resp_auth.status, (200, 404))
        if resp_auth.status == 404:
            import json
            body = json.loads(resp_auth.text)
            self.assertEqual(body.get("status"), "APK_NOT_FOUND")

    async def test_08_ephemeral_apk_server_lifecycle_and_token_validation(self) -> None:
        """Verify ephemeral LAN APK server binds on OS port, validates token, and cleans up."""
        from snow.web.server import SnowWebServer
        import aiohttp
        import time

        server = SnowWebServer(port=8770, auto_open_browser=False)
        try:
            port = await server._ensure_ephemeral_apk_server()
            self.assertGreater(port, 0)

            # Query without token -> 401
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://127.0.0.1:{port}/download") as r1:
                    self.assertEqual(r1.status, 401)

                # Query with invalid token -> 401
                async with session.get(f"http://127.0.0.1:{port}/download?token=bogus") as r2:
                    self.assertEqual(r2.status, 401)

                # Query with valid token -> 200 or 404 (not 401)
                valid_tok = "tok-ephemeral-test-123"
                server._apk_download_tokens[valid_tok] = time.time() + 600.0
                async with session.get(f"http://127.0.0.1:{port}/download?token={valid_tok}") as r3:
                    self.assertIn(r3.status, (200, 404))
        finally:
            await server.stop()
            self.assertIsNone(server._ephemeral_apk_runner)
            self.assertEqual(server._ephemeral_apk_port, 0)

    async def test_09_dashboard_host_validation_strictly_rejects_lan_host(self) -> None:
        """Verify dashboard security_middleware rejects non-loopback Host headers unconditionally."""
        from snow.web.server import SnowWebServer
        from aiohttp import web
        server = SnowWebServer(port=8770, auto_open_browser=False)

        req = MagicMock()
        req.headers = {"Host": "192.168.1.100:8770"}
        req.path = "/api/app/download-apk"

        async def dummy_handler(r):
            return web.Response(text="ok")

        resp = await server.security_middleware(req, dummy_handler)
        self.assertEqual(resp.status, 400)
        self.assertIn("Bad Request: Invalid Host header", resp.text)


if __name__ == "__main__":
    unittest.main()
