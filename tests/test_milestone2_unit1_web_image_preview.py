"""Milestone 2 — Unit 2.1 Regression Tests: Cross-Process Web Clipboard Image Preview."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from snow.capabilities.clipboard_buffer import (
    ClipboardRingBuffer,
    JPEG_SIGNATURE,
    MAX_IMAGE_BYTES,
    PNG_SIGNATURE,
)
from snow.capabilities.engine import CapabilityEngine
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.mcp.bridge import SnowMcpBridge
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.web.server import SnowWebServer


class TestUnit21CrossProcessWebImagePreview(AioHTTPTestCase):
    """Verify Web prefers Core IPC for clipboard image preview and enforces containment/MIME/size bounds."""

    async def get_application(self) -> web.Application:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m2_u21_"))
        self.core_storage = (self.tmp_dir / "transfers" / "clipboard_buffer").resolve()
        self.core_storage.mkdir(parents=True, exist_ok=True)
        self.web_local_storage = (self.tmp_dir / "web_empty_storage").resolve()
        self.web_local_storage.mkdir(parents=True, exist_ok=True)

        # Core process owns the authoritative buffer and image files; Web's in-process buffer stays empty.
        self.core_db = DatabaseManager(self.tmp_dir / "core.db")
        self.core_buf = ClipboardRingBuffer(storage_dir=self.core_storage, db_manager=self.core_db)
        self.core_engine = CapabilityEngine(db_manager=self.core_db, clipboard_buffer=self.core_buf)

        self.core_mock = MagicMock()
        self.core_mock.capability_engine = self.core_engine
        self.core_mock.db_manager = self.core_db
        self.core_mock.device_identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Core-Host",
            created_at="2026-11-26T00:00:00Z",
            snow_id="SNW-CORE-2100",
        )
        self.ipc_secret = "u21-ipc-secret"
        self.ipc_server = SnowIpcServer(
            core_server=self.core_mock,
            config=CoreConfig(port=8765, ipc_port=0, discovery_enabled=False),
        )
        self.ipc_server._secret = self.ipc_secret
        await self.ipc_server.start()
        self.ipc_port = self.ipc_server._server.sockets[0].getsockname()[1]

        # Real SnowMcpBridge pointing to Core IPC, with an explicitly empty isolated in-process buffer.
        with patch.dict(os.environ, {"SNOW_DATA_DIR": str(self.tmp_dir)}):
            self.bridge = SnowMcpBridge(
                host="127.0.0.1",
                port=self.ipc_port,
                secret=self.ipc_secret,
                auto_start_core=False,
            )
            self.bridge.capability_engine.clipboard_buffer = ClipboardRingBuffer(storage_dir=self.web_local_storage)
        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=0,
            bridge=self.bridge,
            auto_open_browser=False,
        )
        return self.web_server._build_app()

    async def tearDownAsync(self) -> None:
        try:
            await self.ipc_server.stop()
        except Exception:
            pass
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        await super().tearDownAsync()

    async def _auth(self) -> None:
        resp = await self.client.post("/api/auth/session", json={"token": self.web_server.bootstrap_token})
        self.assertEqual(resp.status, 200)

    @unittest_run_loop
    async def test_01_core_ipc_preferred_when_web_local_buffer_is_empty(self) -> None:
        await self._auth()
        # Add PNG only inside Core daemon buffer; Web's bridge.capability_engine.clipboard_buffer has 0 items!
        png_bytes = PNG_SIGNATURE + b"\x00\x00\x00\rIHDR" + os.urandom(128)
        added = self.core_buf.add_image(png_bytes, mime_type="image/png", source_device_id="pc")
        self.assertTrue(added["success"])
        item_id = added["item"]["item_id"]
        self.assertEqual(len(self.bridge.capability_engine.clipboard_buffer.list_items()), 0)

        with patch.dict(os.environ, {"SNOW_DATA_DIR": str(self.tmp_dir)}):
            resp = await self.client.get(f"/api/clipboard/image/{item_id}")
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.content_type, "image/png")
            self.assertIn("no-store", resp.headers.get("Cache-Control", ""))
            self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
            self.assertEqual(await resp.read(), png_bytes)

        # Also test JPEG Content-Type header accuracy across IPC
        jpg_bytes = JPEG_SIGNATURE + b"\xe0\x00\x10JFIF" + os.urandom(128)
        added_jpg = self.core_buf.add_image(jpg_bytes, mime_type="image/jpeg", source_device_id="phone")
        jpg_id = added_jpg["item"]["item_id"]
        with patch.dict(os.environ, {"SNOW_DATA_DIR": str(self.tmp_dir)}):
            resp_jpg = await self.client.get(f"/api/clipboard/image/{jpg_id}")
            self.assertEqual(resp_jpg.status, 200)
            self.assertEqual(resp_jpg.content_type, "image/jpeg")
            self.assertIn("no-store", resp_jpg.headers.get("Cache-Control", ""))
            self.assertEqual(await resp_jpg.read(), jpg_bytes)

    @unittest_run_loop
    async def test_02_online_ipc_missing_item_returns_404_without_reading_stale_local_buffer(self) -> None:
        await self._auth()
        fake_png = PNG_SIGNATURE + os.urandom(64)
        local_item = self.bridge.capability_engine.clipboard_buffer.add_image(fake_png, mime_type="image/png")
        local_id = local_item["item"]["item_id"]
        # Item does NOT exist in authoritative Core IPC buffer, so Core returns NOT_FOUND -> Web must return 404.
        with patch.dict(os.environ, {"SNOW_DATA_DIR": str(self.tmp_dir)}):
            resp = await self.client.get(f"/api/clipboard/image/{local_id}")
            self.assertEqual(resp.status, 404)

    @unittest_run_loop
    async def test_03_in_process_fallback_used_only_when_core_ipc_offline(self) -> None:
        await self._auth()
        local_png = PNG_SIGNATURE + os.urandom(96)
        local_buf = ClipboardRingBuffer(storage_dir=self.web_local_storage)
        added = local_buf.add_image(local_png, mime_type="image/png", source_device_id="pc")
        item_id = added["item"]["item_id"]
        self.bridge.capability_engine.clipboard_buffer = local_buf

        with patch.object(
            self.bridge,
            "call",
            new=AsyncMock(return_value={"success": False, "status": "CORE_OFFLINE", "error": "Daemon stopped"}),
        ):
            resp = await self.client.get(f"/api/clipboard/image/{item_id}")
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.content_type, "image/png")
            self.assertIn("no-store", resp.headers.get("Cache-Control", ""))
            self.assertEqual(await resp.read(), local_png)

    @unittest_run_loop
    async def test_04_path_traversal_and_symlink_escape_rejected(self) -> None:
        await self._auth()
        item_id = f"cb_{'a' * 12}_{'b' * 6}"
        outside_file = self.tmp_dir / "outside_secret.png"
        outside_file.write_bytes(PNG_SIGNATURE + b"SECRET_OUTSIDE")

        # Path traversal image_filename from untrusted IPC payload -> 403
        for bad_name in ("../outside_secret.png", "..\\outside_secret.png", "sub/file.png", "C:\\temp\\a.png", "a\x00.png"):
            with patch.object(
                self.bridge,
                "call",
                new=AsyncMock(
                    return_value={
                        "success": True,
                        "status": "SUCCESS",
                        "data": {
                            "item": {"item_id": item_id, "type": "image", "mime_type": "image/png"},
                            "image_filename": bad_name,
                        },
                    }
                ),
            ), patch.dict(os.environ, {"SNOW_DATA_DIR": str(self.tmp_dir)}):
                resp = await self.client.get(f"/api/clipboard/image/{item_id}")
                self.assertEqual(resp.status, 403, f"Expected 403 for {bad_name!r}, got {resp.status}")

        # Symlink escape inside storage_dir -> 403 (patched cleanly if OS denies symlink privilege)
        link_name = "clip_symlink_escape.png"
        link_path = self.core_storage / link_name
        created_real_symlink = False
        try:
            os.symlink(outside_file, link_path)
            created_real_symlink = True
        except OSError:
            link_path.write_bytes(PNG_SIGNATURE + b"placeholder")

        with patch.object(
            self.bridge,
            "call",
            new=AsyncMock(
                return_value={
                    "success": True,
                    "status": "SUCCESS",
                    "data": {
                        "item": {"item_id": item_id, "type": "image", "mime_type": "image/png"},
                        "image_filename": link_name,
                    },
                }
            ),
        ), patch.dict(os.environ, {"SNOW_DATA_DIR": str(self.tmp_dir)}):
            if created_real_symlink:
                resp = await self.client.get(f"/api/clipboard/image/{item_id}")
                self.assertEqual(resp.status, 403)
            else:
                with patch.object(Path, "is_symlink", return_value=True):
                    resp = await self.client.get(f"/api/clipboard/image/{item_id}")
                    self.assertEqual(resp.status, 403)

    @unittest_run_loop
    async def test_05_unsupported_mime_and_corrupted_binary_rejected_with_415(self) -> None:
        await self._auth()
        item_id = f"cb_{'c' * 12}_{'d' * 6}"
        svg_file = self.core_storage / "clip_svg_1.svg"
        svg_file.write_bytes(b"<svg><script>alert(1)</script></svg>")

        with patch.object(
            self.bridge,
            "call",
            new=AsyncMock(
                return_value={
                    "success": True,
                    "status": "SUCCESS",
                    "data": {
                        "item": {"item_id": item_id, "type": "image", "mime_type": "image/svg+xml"},
                        "image_filename": svg_file.name,
                    },
                }
            ),
        ), patch.dict(os.environ, {"SNOW_DATA_DIR": str(self.tmp_dir)}):
            resp = await self.client.get(f"/api/clipboard/image/{item_id}")
            self.assertEqual(resp.status, 415)

        # HTML disguised as image/png -> rejected via magic-byte mismatch with 415
        bad_png = self.core_storage / "clip_bad_1.png"
        bad_png.write_bytes(b"<html>not a png</html>")
        with patch.object(
            self.bridge,
            "call",
            new=AsyncMock(
                return_value={
                    "success": True,
                    "status": "SUCCESS",
                    "data": {
                        "item": {"item_id": item_id, "type": "image", "mime_type": "image/png"},
                        "image_filename": bad_png.name,
                    },
                }
            ),
        ), patch.dict(os.environ, {"SNOW_DATA_DIR": str(self.tmp_dir)}):
            resp = await self.client.get(f"/api/clipboard/image/{item_id}")
            self.assertEqual(resp.status, 415)

    @unittest_run_loop
    async def test_06_oversized_file_rejected_before_unbounded_read(self) -> None:
        await self._auth()
        item_id = f"cb_{'e' * 12}_{'f' * 6}"
        big_file = self.core_storage / "clip_huge_1.png"
        # Sparse file > MAX_IMAGE_BYTES so stat checks fail fast with 413 without allocating full file in RAM
        with big_file.open("wb") as fh:
            fh.seek(MAX_IMAGE_BYTES + 4096)
            fh.write(b"\x00")

        with patch.object(
            self.bridge,
            "call",
            new=AsyncMock(
                return_value={
                    "success": True,
                    "status": "SUCCESS",
                    "data": {
                        "item": {"item_id": item_id, "type": "image", "mime_type": "image/png"},
                        "image_filename": big_file.name,
                    },
                }
            ),
        ), patch.dict(os.environ, {"SNOW_DATA_DIR": str(self.tmp_dir)}):
            resp = await self.client.get(f"/api/clipboard/image/{item_id}")
            self.assertEqual(resp.status, 413)


if __name__ == "__main__":
    unittest.main()
