"""Unit and integration test suite for SNOW Phase 26A:
Live Screen Sharing, Camera Auto-Push, and Web Dashboard Polish.

Covers:
1. Bounded screen frame ingest (POST /api/v1/screen/frame) on port 8766.
2. Content-Type enforcement (strictly image/jpeg).
3. Frame size bounding (max 512 KiB; rejects oversized frames with 413).
4. Bearer token authentication enforcement on frame ingest.
5. In-memory single-slot frame buffer lifecycle (overwrites, clears on stop).
6. Screen stream status query (GET /api/v1/screen/status).
7. Screen frame retrieval (GET /api/v1/screen/frame) with Cache-Control: no-store.
8. Empty buffer returns 204 No Content.
9. Control plane WSS actions: screen_stream_start, screen_stream_stop, screen_stream_status.
10. Strict 64 KiB WSS message size limit preserved (zero image bytes over WSS).
11. Camera photo delivery acknowledgement (camera_photo_delivered).
12. Dashboard screen endpoints (GET /api/screen/status, GET /api/screen/frame, POST /api/screen/stop).
13. Dashboard latest camera photo endpoint (GET /api/camera/latest).
14. Dashboard CSRF enforcement on mutating screen endpoints.
15. Idempotent stream stop and cleanup.
"""

from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from snow.core.config import CoreConfig
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager
from snow.transfer.http_server import MAX_SCREEN_FRAME_BYTES, SnowHttpTransferServer
from snow.transfer.manager import TransferManager
from snow.transfer.storage import TransferStorageManager
from snow.web.server import SnowWebServer


class TestScreenFrameHttpServer(AioHTTPTestCase):
    """Test suite for HTTP transfer server screen streaming endpoints (port 8766)."""

    async def get_application(self) -> web.Application:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_http_")
        self.config = CoreConfig(
            bind_host="127.0.0.1",
            transfer_port=0,
            auth_required=True,
        )
        self.db_manager = MagicMock(spec=DatabaseManager)
        # Mock token verification: "valid_token" succeeds for "device_1"
        self.db_manager.verify_device_token.side_effect = (
            lambda dev_id, tok: dev_id == "device_1" and tok == "valid_token"
        )
        self.transfer_manager = MagicMock(spec=TransferManager)
        self.storage_manager = MagicMock(spec=TransferStorageManager)

        # Clear in-memory screen sessions before each test
        SnowHttpTransferServer._screen_sessions.clear()

        self.server = SnowHttpTransferServer(
            config=self.config,
            db_manager=self.db_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
        )
        return self.server.app

    async def tearDownAsync(self) -> None:
        SnowHttpTransferServer._screen_sessions.clear()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @unittest_run_loop
    async def test_frame_ingest_success(self):
        """Test that a valid bounded JPEG frame is accepted with 200."""
        fake_jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 1024  # 1 KiB fake JPEG
        headers = {
            "Content-Type": "image/jpeg",
            "X-Snow-Device-Id": "device_1",
            "Authorization": "Bearer valid_token",
            "X-Snow-Session-Id": "sess_123",
            "X-Snow-Frame-Width": "720",
            "X-Snow-Frame-Height": "1280",
            "X-Snow-FPS": "2.0",
        }
        resp = await self.client.post("/api/v1/screen/frame", data=fake_jpeg, headers=headers)
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertEqual(data["status"], "ACCEPTED")
        self.assertEqual(data["frame_size"], len(fake_jpeg))
        self.assertEqual(data["session_id"], "sess_123")

        # Verify stored in buffer
        stored = SnowHttpTransferServer.get_latest_screen_frame("device_1")
        self.assertIsNotNone(stored)
        self.assertEqual(stored["frame_bytes"], fake_jpeg)
        self.assertEqual(stored["frame_width"], 720)
        self.assertEqual(stored["fps"], 2.0)

    @unittest_run_loop
    async def test_frame_ingest_rejects_unauthenticated(self):
        """Test that unauthenticated frame ingest requests are rejected with 401."""
        fake_jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * 512
        headers = {
            "Content-Type": "image/jpeg",
            "X-Snow-Device-Id": "device_1",
            "Authorization": "Bearer WRONG_TOKEN",
        }
        resp = await self.client.post("/api/v1/screen/frame", data=fake_jpeg, headers=headers)
        self.assertEqual(resp.status, 401)

    @unittest_run_loop
    async def test_frame_ingest_rejects_non_jpeg(self):
        """Test that non-JPEG Content-Type is rejected with 415."""
        fake_png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 512
        headers = {
            "Content-Type": "image/png",
            "X-Snow-Device-Id": "device_1",
            "Authorization": "Bearer valid_token",
        }
        resp = await self.client.post("/api/v1/screen/frame", data=fake_png, headers=headers)
        self.assertEqual(resp.status, 415)

    @unittest_run_loop
    async def test_frame_ingest_rejects_oversized_frame(self):
        """Test that frames exceeding 512 KiB are rejected with 413."""
        oversized_jpeg = b"\xff\xd8\xff\xe0" + b"\x00" * (MAX_SCREEN_FRAME_BYTES + 10)
        headers = {
            "Content-Type": "image/jpeg",
            "X-Snow-Device-Id": "device_1",
            "Authorization": "Bearer valid_token",
        }
        resp = await self.client.post("/api/v1/screen/frame", data=oversized_jpeg, headers=headers)
        self.assertEqual(resp.status, 413)

    @unittest_run_loop
    async def test_single_slot_buffer_overwrite(self):
        """Test that new frames overwrite previous frames in the single-slot buffer."""
        headers = {
            "Content-Type": "image/jpeg",
            "X-Snow-Device-Id": "device_1",
            "Authorization": "Bearer valid_token",
        }
        frame1 = b"\xff\xd8\xff\xe0FRAME1"
        frame2 = b"\xff\xd8\xff\xe0FRAME2_NEW"

        await self.client.post("/api/v1/screen/frame", data=frame1, headers=headers)
        first_stored = SnowHttpTransferServer.get_latest_screen_frame("device_1")
        self.assertEqual(first_stored["frame_bytes"], frame1)

        await self.client.post("/api/v1/screen/frame", data=frame2, headers=headers)
        second_stored = SnowHttpTransferServer.get_latest_screen_frame("device_1")
        self.assertEqual(second_stored["frame_bytes"], frame2)

    @unittest_run_loop
    async def test_frame_retrieval_and_empty_204(self):
        """Test retrieving the latest frame returns JPEG, and 204 when empty."""
        headers = {
            "X-Snow-Device-Id": "device_1",
            "Authorization": "Bearer valid_token",
        }
        # Empty buffer returns 204
        resp = await self.client.get("/api/v1/screen/frame", headers=headers)
        self.assertEqual(resp.status, 204)

        # Ingest a frame
        fake_jpeg = b"\xff\xd8\xff\xe0IMAGE_DATA"
        post_headers = {
            "Content-Type": "image/jpeg",
            "X-Snow-Device-Id": "device_1",
            "Authorization": "Bearer valid_token",
        }
        await self.client.post("/api/v1/screen/frame", data=fake_jpeg, headers=post_headers)

        # Retrieve frame
        get_resp = await self.client.get("/api/v1/screen/frame", headers=headers)
        self.assertEqual(get_resp.status, 200)
        self.assertEqual(get_resp.headers.get("Content-Type"), "image/jpeg")
        self.assertIn("no-store", get_resp.headers.get("Cache-Control", ""))
        body = await get_resp.read()
        self.assertEqual(body, fake_jpeg)

    @unittest_run_loop
    async def test_screen_status_endpoint(self):
        """Test querying screen status via GET /api/v1/screen/status."""
        headers = {
            "X-Snow-Device-Id": "device_1",
            "Authorization": "Bearer valid_token",
        }
        resp = await self.client.get("/api/v1/screen/status", headers=headers)
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertEqual(data["state"], "IDLE")
        self.assertFalse(data["has_frame"])

        # Start stream
        start_resp = await self.client.post(
            "/api/v1/screen/start",
            json={"session_id": "test_sess", "fps": 3.0, "frame_width": 720, "frame_height": 1280},
            headers=headers,
        )
        self.assertEqual(start_resp.status, 200)

        status_resp = await self.client.get("/api/v1/screen/status", headers=headers)
        st_data = await status_resp.json()
        self.assertEqual(st_data["state"], "STREAMING")
        self.assertEqual(st_data["session_id"], "test_sess")
        self.assertEqual(st_data["fps"], 3.0)

    @unittest_run_loop
    async def test_screen_stop_endpoint(self):
        """Test stopping screen stream via POST /api/v1/screen/stop clears buffer."""
        headers = {
            "X-Snow-Device-Id": "device_1",
            "Authorization": "Bearer valid_token",
        }
        # First ingest a frame
        fake_jpeg = b"\xff\xd8\xff\xe0TEST"
        post_headers = {
            "Content-Type": "image/jpeg",
            "X-Snow-Device-Id": "device_1",
            "Authorization": "Bearer valid_token",
        }
        await self.client.post("/api/v1/screen/frame", data=fake_jpeg, headers=post_headers)
        self.assertIsNotNone(SnowHttpTransferServer.get_latest_screen_frame("device_1"))

        # Stop stream
        stop_resp = await self.client.post("/api/v1/screen/stop", headers=headers)
        self.assertEqual(stop_resp.status, 200)

        # Buffer should be cleared
        self.assertIsNone(SnowHttpTransferServer.get_latest_screen_frame("device_1"))
        status = SnowHttpTransferServer.get_screen_stream_status("device_1")
        self.assertEqual(status["state"], "STOPPED")


class TestScreenStreamWssControlPlane(unittest.IsolatedAsyncioTestCase):
    """Test suite for WSS control-plane screen stream metadata actions (port 8765)."""

    async def asyncSetUp(self):
        self.config = CoreConfig(bind_host="127.0.0.1", port=8765)
        self.mock_transfer_server = MagicMock()
        self.ws_server = SnowWebSocketServer(
            config=self.config,
            core_server=None,
        )
        self.ws_server.http_transfer_server = self.mock_transfer_server

    async def test_screen_stream_start_action(self):
        """Test screen_stream_start handles metadata and responds with success."""
        mock_ws = AsyncMock()
        client = MagicMock()
        client.websocket = mock_ws
        client.connection_id = "test_conn_1"

        session = MagicMock()
        session.device_id = "phone_android_1"

        data = {"session_id": "sess_abc", "fps": 2.5, "frame_width": 720, "frame_height": 1280}
        msg = SnowMessage.create_request(action="screen_stream_start", data=data)

        await self.ws_server._handle_screen_stream_start(client, msg, data, session)

        # Verify response sent
        mock_ws.send.assert_called_once()
        sent_raw = mock_ws.send.call_args[0][0]
        sent_data = json.loads(sent_raw)

        self.assertEqual(sent_data["type"], MessageType.RESPONSE.value)
        self.assertEqual(sent_data["payload"]["status"], "success")
        self.assertEqual(sent_data["payload"]["state"], "STREAMING")
        self.assertEqual(sent_data["payload"]["session_id"], "sess_abc")
        self.assertEqual(sent_data["payload"]["fps"], 2.5)

        # Verify state in ws_server
        meta = self.ws_server._screen_stream_sessions["phone_android_1"]
        self.assertEqual(meta["state"], "STREAMING")

        # Verify transfer server notified
        self.mock_transfer_server.set_session_state.assert_called_with(
            device_id="phone_android_1",
            state="STREAMING",
            session_id="sess_abc",
            fps=2.5,
            width=720,
            height=1280,
        )

    async def test_screen_stream_stop_action(self):
        """Test screen_stream_stop updates state to STOPPED."""
        mock_ws = AsyncMock()
        client = MagicMock()
        client.websocket = mock_ws

        session = MagicMock()
        session.device_id = "phone_android_1"
        self.ws_server._screen_stream_sessions["phone_android_1"] = {"state": "STREAMING"}

        data = {}
        msg = SnowMessage.create_request(action="screen_stream_stop", data=data)

        await self.ws_server._handle_screen_stream_stop(client, msg, data, session)

        mock_ws.send.assert_called_once()
        sent_data = json.loads(mock_ws.send.call_args[0][0])
        self.assertEqual(sent_data["payload"]["status"], "success")
        self.assertEqual(sent_data["payload"]["state"], "STOPPED")
        self.assertEqual(self.ws_server._screen_stream_sessions["phone_android_1"]["state"], "STOPPED")

    async def test_camera_photo_delivered_action(self):
        """Test camera_photo_delivered control event acknowledgement."""
        mock_ws = AsyncMock()
        client = MagicMock()
        client.websocket = mock_ws

        session = MagicMock()
        session.device_id = "phone_android_1"

        data = {
            "file_name": "android_photo_20261121_120000_abc.jpg",
            "size_bytes": 102400,
            "sha256": "abcdef1234567890",
        }
        msg = SnowMessage.create_request(action="camera_photo_delivered", data=data)

        await self.ws_server._handle_camera_photo_delivered(client, msg, data, session)

        mock_ws.send.assert_called_once()
        sent_data = json.loads(mock_ws.send.call_args[0][0])
        self.assertTrue(sent_data["payload"]["acknowledged"])
        self.assertEqual(sent_data["payload"]["file_name"], "android_photo_20261121_120000_abc.jpg")

    async def test_control_plane_strictly_metadata_no_images(self):
        """Verify that screen stream control messages contain zero image data."""
        mock_ws = AsyncMock()
        client = MagicMock()
        client.websocket = mock_ws

        session = MagicMock()
        session.device_id = "phone_android_1"

        data = {}
        msg = SnowMessage.create_request(action="screen_stream_status", data=data)

        await self.ws_server._handle_screen_stream_status(client, msg, data, session)

        mock_ws.send.assert_called_once()
        sent_raw = mock_ws.send.call_args[0][0]
        # Frame size must be strictly < 1024 bytes (metadata only)
        self.assertLess(len(sent_raw), 1024)
        self.assertNotIn("base64", sent_raw.lower())
        self.assertNotIn("image/jpeg", sent_raw.lower())


class TestDashboardScreenEndpoints(AioHTTPTestCase):
    """Test suite for Web Dashboard server screen/camera endpoints (port 8769)."""

    async def get_application(self) -> web.Application:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_dash_")
        self.bridge = MagicMock()
        self.bridge.call = AsyncMock(return_value={"success": True, "status": "STOPPED", "data": {}})
        self.mock_transfer_server = MagicMock()
        self.mock_transfer_server.get_screen_stream_status.return_value = {
            "state": "STREAMING",
            "fps": 2.0,
            "frame_width": 720,
            "frame_height": 1280,
            "timestamp": time.time(),
            "has_frame": True,
            "frame_size": 2048,
        }
        self.mock_transfer_server.get_latest_screen_frame.return_value = {
            "frame_bytes": b"\xff\xd8\xff\xe0DASHBOARD_FRAME",
            "session_id": "sess_dash_1",
            "timestamp": time.time(),
        }

        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.bridge,
            auto_open_browser=False,
            transfer_server=self.mock_transfer_server,
        )
        return self.web_server._build_app()

    async def tearDownAsync(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _authenticate_session(self) -> str:
        """Helper to exchange bootstrap token for session cookie and CSRF token."""
        token = self.web_server.bootstrap_token
        resp = await self.client.post("/api/auth/session", json={"token": token})
        data = await resp.json()
        return data["csrf_token"]

    @unittest_run_loop
    async def test_dashboard_screen_status_authenticated(self):
        """Test GET /api/screen/status returns stream status when authenticated."""
        csrf_token = await self._authenticate_session()

        resp = await self.client.get("/api/screen/status")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["state"], "STREAMING")
        self.assertEqual(data["fps"], 2.0)

    @unittest_run_loop
    async def test_dashboard_screen_frame_authenticated(self):
        """Test GET /api/screen/frame serves the latest JPEG frame."""
        await self._authenticate_session()

        resp = await self.client.get("/api/screen/frame")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers.get("Content-Type"), "image/jpeg")
        self.assertIn("no-store", resp.headers.get("Cache-Control", ""))
        body = await resp.read()
        self.assertEqual(body, b"\xff\xd8\xff\xe0DASHBOARD_FRAME")

    @unittest_run_loop
    async def test_dashboard_screen_stop_requires_csrf(self):
        """Test POST /api/screen/stop requires a valid CSRF token."""
        csrf_token = await self._authenticate_session()

        # Without CSRF token -> 403
        bad_resp = await self.client.post("/api/screen/stop")
        self.assertEqual(bad_resp.status, 403)

        # With valid CSRF token -> 200
        headers = {"X-CSRF-Token": csrf_token}
        good_resp = await self.client.post("/api/screen/stop", headers=headers)
        self.assertEqual(good_resp.status, 200)
        data = await good_resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "STOPPED")

    @unittest_run_loop
    async def test_dashboard_camera_latest_endpoint(self):
        """Test GET /api/camera/latest serves the latest photo."""
        await self._authenticate_session()

        fake_mgr = MagicMock()
        fake_mgr.root_dir = Path(self.temp_dir).resolve()

        # Empty captures directory returns 204
        with patch("snow.capabilities.windows.screenshot.DEFAULT_CAPTURES_DIR", Path(self.temp_dir)), \
             patch("snow.transfer.storage.TransferStorageManager", return_value=fake_mgr):
            resp = await self.client.get("/api/camera/latest")
            self.assertEqual(resp.status, 204)

            # Create fake camera photo
            photo_file = Path(self.temp_dir) / "android_photo_20261121_120000_abc.jpg"
            photo_file.write_bytes(b"\xff\xd8\xff\xe0CAMERA_PHOTO_TEST")

            resp2 = await self.client.get("/api/camera/latest")
            self.assertEqual(resp2.status, 200)
            self.assertEqual(resp2.headers.get("Content-Type"), "image/jpeg")
            body = await resp2.read()
            self.assertEqual(body, b"\xff\xd8\xff\xe0CAMERA_PHOTO_TEST")

    @unittest_run_loop
    async def test_camera_latest_recursive_discovery(self):
        """Test recursive discovery of camera uploads in nested subdirectories."""
        await self._authenticate_session()

        nested_dir = Path(self.temp_dir) / "transfers" / "devices" / "phone_1" / "nested"
        nested_dir.mkdir(parents=True, exist_ok=True)
        photo_file = nested_dir / "android_photo_20261121_143000_nested.jpeg"
        photo_file.write_bytes(b"\xff\xd8\xff\xe0NESTED_CAMERA_PHOTO")

        fake_mgr = MagicMock()
        fake_mgr.root_dir = Path(self.temp_dir).resolve()

        with patch("snow.capabilities.windows.screenshot.DEFAULT_CAPTURES_DIR", Path(self.temp_dir)), \
             patch("snow.transfer.storage.TransferStorageManager", return_value=fake_mgr):
            resp = await self.client.get("/api/camera/latest")
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Content-Type"), "image/jpeg")
            body = await resp.read()
            self.assertEqual(body, b"\xff\xd8\xff\xe0NESTED_CAMERA_PHOTO")

    @unittest_run_loop
    async def test_csp_allows_blob_images(self):
        """Test Content-Security-Policy allows blob: in img-src for live previews."""
        resp = await self.client.get("/")
        csp = resp.headers.get("Content-Security-Policy", "")
        self.assertIn("img-src 'self' data: blob:;", csp)
        self.assertIn("connect-src 'self';", csp)
        self.assertNotIn("unsafe-eval", csp)

    @unittest_run_loop
    async def test_workflow_steps_details_collapsed(self):
        """Test Stage 6A diagnostics keeps Technical Ports collapsed while decluttering legacy workflow steps."""
        index_html_path = Path(__file__).resolve().parent.parent / "src" / "snow" / "web" / "static" / "index.html"
        content = index_html_path.read_text(encoding="utf-8")
        self.assertNotIn('id="workflow-steps-details"', content)
        self.assertNotIn('id="workflow-steps-list"', content)
        self.assertIn('<details class="advanced-accordion">', content)
        self.assertIn("Advanced Settings", content)
        self.assertIn(":8765 Control WSS", content)


class TestPhase26AMultiProcessIntegration(AioHTTPTestCase):
    """End-to-end integration test proving the cross-process screen bridge.

    Validates:
    - SnowHttpTransferServer running as independent HTTP server.
    - SnowIpcServer handling screen_stream_status and screen_stream_stop operations.
    - SnowWebServer running with transfer_server=None (separate process emulation).
    - Live frame retrieval via authenticated loopback HTTP proxy using X-Snow-Ipc-Secret.
    - Dashboard stop request dispatched through IPC to router and Android client.
    - Zero access to transfer server in-memory session dictionary by SnowWebServer.
    """

    async def get_application(self) -> web.Application:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_multiprocess_")
        self.secret_dir = Path(self.temp_dir) / ".snow"
        self.secret_dir.mkdir(parents=True, exist_ok=True)
        self.test_secret = "test_multiprocess_secret_64bytes_long_random_hex_token_snow_v4"
        self.secret_file = self.secret_dir / "ipc.secret"
        self.secret_file.write_text(self.test_secret, encoding="utf-8")

        # 1. Start live transfer server
        self.transfer_config = CoreConfig(
            bind_host="127.0.0.1",
            transfer_port=0,
            auth_required=True,
            ipc_host="127.0.0.1",
            ipc_port=0,
            ipc_secret_path=str(self.secret_file),
        )
        self.db_manager = MagicMock(spec=DatabaseManager)
        self.transfer_manager = MagicMock(spec=TransferManager)
        self.storage_manager = MagicMock(spec=TransferStorageManager)

        SnowHttpTransferServer._screen_sessions.clear()
        self.transfer_server = SnowHttpTransferServer(
            config=self.transfer_config,
            db_manager=self.db_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
        )
        await self.transfer_server.start()
        self.transfer_port = self.transfer_server.bound_port

        # 2. Mock core server and session router for IPC
        self.mock_router = AsyncMock()
        self.mock_router.route_request.return_value = {"success": True, "status": "SUCCESS"}

        self.mock_core_server = MagicMock()
        self.mock_core_server.http_transfer_server = self.transfer_server
        self.mock_core_server.session_router = self.mock_router
        self.mock_core_server.config = self.transfer_config
        self.mock_core_server.db_manager = self.db_manager

        # 3. Start live IPC server on dynamic port
        from snow.core.ipc import SnowIpcServer
        self.ipc_server = SnowIpcServer(
            core_server=self.mock_core_server,
            config=self.transfer_config,
        )
        await self.ipc_server.start()
        self.ipc_port = self.ipc_server.bound_port
        self.test_secret = self.ipc_server.secret

        # 4. Instantiate bridge pointing to live IPC server
        from snow.mcp.bridge import SnowMcpBridge
        self.bridge = SnowMcpBridge(
            host="127.0.0.1",
            port=self.ipc_port,
            secret=self.test_secret,
            auto_start_core=False,
            is_owner_channel=True,
        )

        # 5. Instantiate SnowWebServer with transfer_server=None (production mode!)
        with patch("snow.core.ipc.get_default_secret_path", return_value=self.secret_file):
            self.web_server = SnowWebServer(
                host="127.0.0.1",
                port=0,
                bridge=self.bridge,
                auto_open_browser=False,
                transfer_server=None,  # STRICT SEPARATE PROCESS REQUIREMENT
            )
            return self.web_server._build_app()

    async def tearDownAsync(self) -> None:
        if hasattr(self, "ipc_server"):
            await self.ipc_server.stop()
        if hasattr(self, "transfer_server"):
            await self.transfer_server.stop()
        SnowHttpTransferServer._screen_sessions.clear()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _authenticate_session(self) -> str:
        token = self.web_server.bootstrap_token
        resp = await self.client.post("/api/auth/session", json={"token": token})
        data = await resp.json()
        return data["csrf_token"]

    @unittest_run_loop
    async def test_cross_process_frame_proxy_and_stop(self):
        """Test genuine separate-process screen frame proxy and IPC stop dispatch."""
        csrf_token = await self._authenticate_session()

        # Phase A: Initial status when idle
        with patch("snow.core.ipc.get_default_secret_path", return_value=self.secret_file):
            status_resp = await self.client.get("/api/screen/status")
            self.assertEqual(status_resp.status, 200)
            status_data = await status_resp.json()
            self.assertTrue(status_data["success"])
            self.assertEqual(status_data["state"], "IDLE")

            # Initial frame request returns 204
            frame_resp_idle = await self.client.get("/api/screen/frame")
            self.assertEqual(frame_resp_idle.status, 204)

        # Phase B: Ingest a real bounded JPEG frame into the transfer server using IPC secret
        test_frame = b"\xff\xd8\xff\xe0" + b"MULTIPROCESS_FRAME_TEST" * 50
        import aiohttp
        async with aiohttp.ClientSession() as http_client:
            ingest_url = f"http://127.0.0.1:{self.transfer_port}/api/v1/screen/frame"
            headers = {
                "Content-Type": "image/jpeg",
                "X-Snow-Ipc-Secret": self.test_secret,
                "X-Snow-Device-Id": "realme_rmx5110",
                "X-Snow-Frame-Width": "720",
                "X-Snow-Frame-Height": "1600",
                "X-Snow-FPS": "2.0",
            }
            async with http_client.post(ingest_url, data=test_frame, headers=headers) as resp:
                self.assertEqual(resp.status, 200)

        # Phase C: Retrieve the frame through the web dashboard proxy (transfer_server=None)
        with patch("snow.core.ipc.get_default_secret_path", return_value=self.secret_file):
            # Check status via dashboard (queried via IPC)
            status_resp2 = await self.client.get("/api/screen/status")
            self.assertEqual(status_resp2.status, 200)
            status_data2 = await status_resp2.json()
            self.assertEqual(status_data2["state"], "STREAMING")
            self.assertEqual(status_data2["transfer_port"], self.transfer_port)

            # Retrieve frame via proxy
            frame_resp = await self.client.get("/api/screen/frame")
            self.assertEqual(frame_resp.status, 200)
            self.assertEqual(frame_resp.headers.get("Content-Type"), "image/jpeg")
            body = await frame_resp.read()
            self.assertEqual(body, test_frame)

        # Phase D: Stop stream through dashboard
        with patch("snow.core.ipc.get_default_secret_path", return_value=self.secret_file):
            stop_headers = {"X-CSRF-Token": csrf_token}
            stop_resp = await self.client.post("/api/screen/stop", headers=stop_headers)
            self.assertEqual(stop_resp.status, 200)
            stop_data = await stop_resp.json()
            self.assertTrue(stop_data["success"])
            self.assertEqual(stop_data["status"], "STOPPED")

            # Verify router was invoked to stop the physical Android device
            self.mock_router.route_request.assert_called_once()
            call_kwargs = self.mock_router.route_request.call_args[1]
            self.assertEqual(call_kwargs.get("action"), "screen_stream_stop")

            # Subsequent frame fetch returns 204
            frame_resp_post_stop = await self.client.get("/api/screen/frame")
            self.assertEqual(frame_resp_post_stop.status, 204)

    @unittest_run_loop
    async def test_cross_process_frame_proxy_https_with_verified_tls_and_missing_cert(self):
        """Test real loopback HTTPS frame retrieval with verified TLS, and secure failure on missing/invalid cert."""
        csrf_token = await self._authenticate_session()

        # 1. Generate real self-signed TLS cert for 127.0.0.1
        from snow.security.tls import ensure_tls_certificate, create_server_ssl_context
        tls_dir = Path(self.temp_dir) / "tls"
        tls_dir.mkdir(parents=True, exist_ok=True)
        cert_file = tls_dir / "test_server.crt"
        key_file = tls_dir / "test_server.key"
        ensure_tls_certificate(cert_file, key_file, active_ips=["127.0.0.1"])
        server_ssl = create_server_ssl_context(cert_file, key_file)

        # 2. Start a second real transfer server over HTTPS
        https_config = CoreConfig(
            bind_host="127.0.0.1",
            transfer_port=0,
            auth_required=True,
            ipc_host="127.0.0.1",
            ipc_port=0,
            ipc_secret_path=str(self.secret_file),
        )
        https_server = SnowHttpTransferServer(
            config=https_config,
            db_manager=self.db_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
            ssl_context=server_ssl,
            cert_path=cert_file,
        )
        await https_server.start()
        https_port = https_server.bound_port

        try:
            # 3. Ingest frame into HTTPS transfer server using real verified client SSL context
            client_ssl = ssl.create_default_context(cafile=str(cert_file))
            test_frame = b"\xff\xd8\xff\xe0" + b"HTTPS_FRAME_TEST" * 50
            import aiohttp
            async with aiohttp.ClientSession() as http_client:
                ingest_url = f"https://127.0.0.1:{https_port}/api/v1/screen/frame"
                headers = {
                    "Content-Type": "image/jpeg",
                    "X-Snow-Ipc-Secret": self.test_secret,
                    "X-Snow-Device-Id": "realme_rmx5110",
                }
                async with http_client.post(ingest_url, data=test_frame, headers=headers, ssl=client_ssl) as resp:
                    self.assertEqual(resp.status, 200)

            # 4. Configure core mock to return the HTTPS transfer server and cert path
            self.mock_core_server.http_transfer_server = https_server

            with patch("snow.core.ipc.get_default_secret_path", return_value=self.secret_file):
                # Frame proxy retrieval over verified HTTPS
                frame_resp = await self.client.get("/api/screen/frame")
                self.assertEqual(frame_resp.status, 200)
                self.assertEqual(frame_resp.headers.get("Content-Type"), "image/jpeg")
                body = await frame_resp.read()
                self.assertEqual(body, test_frame)

                # 5. Verify that missing certificate returns 502 Bad Gateway
                missing_cert_file = tls_dir / "nonexistent.crt"
                https_server.cert_path = missing_cert_file
                frame_resp_missing = await self.client.get("/api/screen/frame")
                self.assertEqual(frame_resp_missing.status, 502)

                # 6. Verify that an invalid/untrusted certificate returns 502 Bad Gateway
                untrusted_dir = Path(self.temp_dir) / "untrusted"
                untrusted_dir.mkdir(parents=True, exist_ok=True)
                untrusted_cert = untrusted_dir / "untrusted.crt"
                untrusted_key = untrusted_dir / "untrusted.key"
                ensure_tls_certificate(untrusted_cert, untrusted_key, active_ips=["127.0.0.1"])
                https_server.cert_path = untrusted_cert
                frame_resp_invalid = await self.client.get("/api/screen/frame")
                self.assertEqual(frame_resp_invalid.status, 502)
        finally:
            await https_server.stop()


if __name__ == "__main__":
    unittest.main()
