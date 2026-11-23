"""Tests for Windows desktop wallpaper preview, caching, and transfer endpoints.

Verifies:
- Wallpaper acquisition, downscaling, caching, and SHA-256 ETag generation.
- Authenticated HTTPS transfer endpoint (/api/v1/desktop/wallpaper) on port 8766.
- ETag caching and HTTP 304 Not Modified behavior.
- Authentication rejection (HTTP 401) for unauthorized requests.
- Dashboard Web endpoint (/api/desktop/wallpaper) session gating.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from snow.capabilities.windows import wallpaper
from snow.transfer.http_server import SnowHttpTransferServer
from snow.web.server import SnowWebServer


class TestDesktopWallpaperModule(unittest.TestCase):
    """Targeted tests for snow.capabilities.windows.wallpaper functions."""

    def setUp(self):
        # Reset cache
        wallpaper._cached_path = None
        wallpaper._cached_mtime = 0.0
        wallpaper._cached_jpeg = None
        wallpaper._cached_etag = None

    def test_get_desktop_wallpaper_preview_missing(self):
        """Returns (None, None) when active wallpaper path is None or does not exist."""
        with patch.object(wallpaper, "get_active_wallpaper_path", return_value=None):
            jpeg, etag = wallpaper.get_desktop_wallpaper_preview()
            self.assertIsNone(jpeg)
            self.assertIsNone(etag)

    def test_get_desktop_wallpaper_preview_caching(self):
        """Verifies in-memory caching and SHA-256 ETag calculation."""
        fake_path = r"C:\fake\wallpaper.jpg"
        fake_jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIFfakejpegbytes"
        expected_etag = f'"{hashlib.sha256(fake_jpeg).hexdigest()}"'

        with patch.object(wallpaper, "get_active_wallpaper_path", return_value=fake_path), \
             patch("os.path.isfile", return_value=True), \
             patch("os.path.getmtime", return_value=123456.78), \
             patch.object(wallpaper, "_render_scaled_jpeg_gdiplus", return_value=fake_jpeg) as mock_render:

            # First call -> renders
            jpeg1, etag1 = wallpaper.get_desktop_wallpaper_preview()
            self.assertEqual(jpeg1, fake_jpeg)
            self.assertEqual(etag1, expected_etag)
            self.assertEqual(mock_render.call_count, 1)

            # Second call with same mtime -> served from cache
            jpeg2, etag2 = wallpaper.get_desktop_wallpaper_preview()
            self.assertEqual(jpeg2, fake_jpeg)
            self.assertEqual(etag2, expected_etag)
            self.assertEqual(mock_render.call_count, 1)  # not called again

            # Third call with updated mtime -> re-renders
            with patch("os.path.getmtime", return_value=999999.99):
                jpeg3, etag3 = wallpaper.get_desktop_wallpaper_preview()
                self.assertEqual(jpeg3, fake_jpeg)
                self.assertEqual(etag3, expected_etag)
                self.assertEqual(mock_render.call_count, 2)


class TestTransferWallpaperEndpoint(AioHTTPTestCase):
    """Test authenticated /api/v1/desktop/wallpaper on HTTPS transfer server."""

    async def get_application(self):
        config = MagicMock()
        config.host = "127.0.0.1"
        config.port = 8766
        config.transfer_dir = "/tmp/transfers"
        config.auth_required = True
        config.ipc_secret_path = None

        db = MagicMock()
        # Mock token verification against database
        db.verify_device_token.side_effect = lambda dev_id, tok: (dev_id == "device-123" and tok == "valid_token")

        transfer_mgr = MagicMock()
        storage_mgr = MagicMock()

        self.transfer_server = SnowHttpTransferServer(config, db, transfer_mgr, storage_mgr)
        return self.transfer_server.app

    @unittest_run_loop
    async def test_wallpaper_unauthenticated_rejected(self):
        """Requests without Authorization and X-Snow-Device-Id are rejected with HTTP 401."""
        resp = await self.client.get("/api/v1/desktop/wallpaper")
        self.assertEqual(resp.status, 401)

    @unittest_run_loop
    async def test_wallpaper_invalid_token_rejected(self):
        """Requests with mismatched token are rejected with HTTP 401."""
        headers = {
            "X-Snow-Device-Id": "device-123",
            "Authorization": "Bearer wrong_token",
        }
        resp = await self.client.get("/api/v1/desktop/wallpaper", headers=headers)
        self.assertEqual(resp.status, 401)

    @unittest_run_loop
    async def test_wallpaper_authenticated_success_and_304(self):
        """Authenticated request returns 200 JPEG with ETag, then 304 Not Modified on match."""
        fake_jpeg = b"\xff\xd8\xff\xe0test_wallpaper_bytes"
        fake_etag = f'"{hashlib.sha256(fake_jpeg).hexdigest()}"'

        headers = {
            "X-Snow-Device-Id": "device-123",
            "Authorization": "Bearer valid_token",
        }

        with patch("snow.capabilities.windows.wallpaper.get_desktop_wallpaper_preview", return_value=(fake_jpeg, fake_etag)):
            # 1. First fetch -> 200 OK
            resp = await self.client.get("/api/v1/desktop/wallpaper", headers=headers)
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Content-Type"), "image/jpeg")
            self.assertEqual(resp.headers.get("ETag"), fake_etag)
            body = await resp.read()
            self.assertEqual(body, fake_jpeg)

            # 2. Subsequent fetch with matching If-None-Match -> 304 Not Modified
            cached_headers = dict(headers)
            cached_headers["If-None-Match"] = fake_etag
            resp_304 = await self.client.get("/api/v1/desktop/wallpaper", headers=cached_headers)
            self.assertEqual(resp_304.status, 304)
            self.assertEqual(resp_304.headers.get("ETag"), fake_etag)
            body_304 = await resp_304.read()
            self.assertEqual(len(body_304), 0)

    @unittest_run_loop
    async def test_wallpaper_not_available_404(self):
        """Returns 404 when wallpaper is unavailable."""
        headers = {
            "X-Snow-Device-Id": "device-123",
            "Authorization": "Bearer valid_token",
        }
        with patch("snow.capabilities.windows.wallpaper.get_desktop_wallpaper_preview", return_value=(None, None)):
            resp = await self.client.get("/api/v1/desktop/wallpaper", headers=headers)
            self.assertEqual(resp.status, 404)


class TestWebWallpaperEndpoint(AioHTTPTestCase):
    """Test dashboard web endpoint /api/desktop/wallpaper."""

    async def get_application(self):
        bridge = MagicMock()
        bridge.port = 8767
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)

        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=bridge,
            auto_open_browser=False,
        )
        return self.web_server._build_app()

    @unittest_run_loop
    async def test_web_wallpaper_unauthenticated_rejected(self):
        """Web endpoint returns 401 when unauthenticated."""
        resp = await self.client.get("/api/desktop/wallpaper")
        self.assertEqual(resp.status, 401)

    @unittest_run_loop
    async def test_web_wallpaper_authenticated_success_and_304(self):
        """Web endpoint returns 200 with ETag when authenticated, and 304 on match."""
        # Exchange bootstrap token for session cookie
        token = self.web_server.bootstrap_token
        bootstrap_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": token},
        )
        self.assertEqual(bootstrap_resp.status, 200)

        fake_jpeg = b"\xff\xd8\xff\xe0web_wallpaper_test"
        fake_etag = f'"{hashlib.sha256(fake_jpeg).hexdigest()}"'

        with patch("snow.capabilities.windows.wallpaper.get_desktop_wallpaper_preview", return_value=(fake_jpeg, fake_etag)):
            # 1. Fetch wallpaper -> 200 OK
            resp = await self.client.get(
                "/api/desktop/wallpaper",
                headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            )
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.headers.get("Content-Type"), "image/jpeg")
            self.assertEqual(resp.headers.get("ETag"), fake_etag)

            # 2. Fetch with matching If-None-Match -> 304 Not Modified
            resp_304 = await self.client.get(
                "/api/desktop/wallpaper",
                headers={
                    "Host": f"127.0.0.1:{self.web_server.port}",
                    "If-None-Match": fake_etag,
                },
            )
            self.assertEqual(resp_304.status, 304)
            self.assertEqual(resp_304.headers.get("ETag"), fake_etag)


class TestDesktopLockEndpoint(AioHTTPTestCase):
    """Test authenticated OWNER_MANUAL desktop lock endpoint /api/desktop/lock."""

    async def get_application(self):
        bridge = MagicMock()
        bridge.port = 8767
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)

        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=bridge,
            auto_open_browser=False,
        )
        return self.web_server._build_app()

    @unittest_run_loop
    async def test_lock_unauthenticated_rejected(self):
        """Unauthenticated request to lock PC is rejected with 401."""
        resp = await self.client.post("/api/desktop/lock")
        self.assertEqual(resp.status, 401)

    @unittest_run_loop
    async def test_lock_missing_csrf_rejected(self):
        """Request without CSRF token is rejected with 403."""
        token = self.web_server.bootstrap_token
        bootstrap_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": token},
        )
        self.assertEqual(bootstrap_resp.status, 200)

        resp = await self.client.post(
            "/api/desktop/lock",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={},
        )
        self.assertEqual(resp.status, 403)

    @unittest_run_loop
    async def test_lock_authorized_success(self):
        """Authorized request invokes native LockWorkStation and returns success."""
        token = self.web_server.bootstrap_token
        bootstrap_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": token},
        )
        self.assertEqual(bootstrap_resp.status, 200)
        data = await bootstrap_resp.json()
        csrf_token = data["csrf_token"]

        with patch("sys.platform", "win32"), \
             patch("ctypes.windll.user32.LockWorkStation", return_value=1) as mock_lock:
            resp = await self.client.post(
                "/api/desktop/lock",
                headers={
                    "Host": f"127.0.0.1:{self.web_server.port}",
                    "X-CSRF-Token": csrf_token,
                },
                json={},
            )
            self.assertEqual(resp.status, 200)
            res_json = await resp.json()
            self.assertTrue(res_json.get("success"))
            self.assertEqual(res_json.get("message"), "Workstation locked successfully.")

    @unittest_run_loop
    async def test_lock_native_failure_handled(self):
        """When native LockWorkStation returns 0, returns 500 with error."""
        token = self.web_server.bootstrap_token
        bootstrap_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": token},
        )
        self.assertEqual(bootstrap_resp.status, 200)
        data = await bootstrap_resp.json()
        csrf_token = data["csrf_token"]

        with patch("sys.platform", "win32"), \
             patch("ctypes.windll.user32.LockWorkStation", return_value=0):
            resp = await self.client.post(
                "/api/desktop/lock",
                headers={
                    "Host": f"127.0.0.1:{self.web_server.port}",
                    "X-CSRF-Token": csrf_token,
                },
                json={},
            )
            self.assertEqual(resp.status, 500)
            res_json = await resp.json()
            self.assertFalse(res_json.get("success"))


if __name__ == "__main__":
    unittest.main()
