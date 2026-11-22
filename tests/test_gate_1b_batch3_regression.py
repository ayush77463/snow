"""Regression and adversarial verification suite for SNOW V4.1 Phase 1 Gate 1B Batch 3.

Covers the authorized Batch 3 Work Packages:
- WP1: Common Synced Clipboard (CF_DIBV5 decoding, SQLite ring-buffer persistence & startup reconciliation)
- WP1: Windows clipboard listener lifecycle, debouncing (~200ms) and echo loop prevention
- WP4: Daemon log file handle cleanup in parent process
"""

import asyncio
from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
import struct
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.clipboard_buffer import ClipboardItem, ClipboardRingBuffer
from snow.capabilities.windows.clipboard import WindowsClipboardManager
from snow.core.config import CoreConfig
from snow.security.db import DatabaseManager


class TestWP1DIBV5Decoding(unittest.TestCase):
    """Test WP1: CF_DIBV5 to PNG decoding and boundary validation."""

    def _create_synthetic_dibv5(self, width=2, height=2, bpp=32):
        """Construct a minimal valid BITMAPV5HEADER byte stream (124 bytes header)."""
        header_size = 124  # BITMAPV5HEADER size
        compression = 3    # BI_BITFIELDS
        image_size = width * height * 4
        red_mask = 0x00FF0000
        green_mask = 0x0000FF00
        blue_mask = 0x000000FF
        alpha_mask = 0xFF000000
        cs_type = 0x73524742  # sRGB

        # Pack BITMAPV5HEADER (24 items = 124 bytes):
        header = struct.pack(
            "<IiiHHIIiiIIIIIII36sIIIIIII",
            header_size,      # 1: bV5Size
            width,            # 2: bV5Width
            height,           # 3: bV5Height (positive = bottom-up)
            1,                # 4: bV5Planes
            bpp,              # 5: bV5BitCount
            compression,      # 6: bV5Compression
            image_size,       # 7: bV5SizeImage
            2835,             # 8: bV5XPelsPerMeter
            2835,             # 9: bV5YPelsPerMeter
            0,                # 10: bV5ClrUsed
            0,                # 11: bV5ClrImportant
            red_mask,         # 12: bV5RedMask
            green_mask,       # 13: bV5GreenMask
            blue_mask,        # 14: bV5BlueMask
            alpha_mask,       # 15: bV5AlphaMask
            cs_type,          # 16: bV5CSType
            b"\x00" * 36,     # 17: bV5Endpoints (CIEXYZTRIPLE)
            0,                # 18: bV5GammaRed
            0,                # 19: bV5GammaGreen
            0,                # 20: bV5GammaBlue
            0,                # 21: bV5Intent
            0,                # 22: bV5ProfileData
            0,                # 23: bV5ProfileSize
            0                 # 24: bV5Reserved
        )
        self.assertEqual(len(header), 124)

        # 2x2 32-bit BGRA pixels (4 pixels * 4 bytes = 16 bytes)
        pixels = bytes([
            0x00, 0x00, 0xFF, 0xFF,  # Red (BGRA)
            0x00, 0xFF, 0x00, 0xFF,  # Green
            0xFF, 0x00, 0x00, 0xFF,  # Blue
            0xFF, 0xFF, 0xFF, 0xFF   # White
        ])
        return header + pixels

    def test_decode_synthetic_dibv5_produces_valid_png(self):
        clip = WindowsClipboardManager()
        if not clip._is_windows:
            self.skipTest("Windows-only test")
        with tempfile.TemporaryDirectory() as td:
            dib_data = self._create_synthetic_dibv5(2, 2, 32)
            res = clip.decode_dib_bytes_to_png(dib_data, output_dir=Path(td))
            self.assertTrue(res["success"])
            self.assertEqual(res["mime_type"], "image/png")
            saved_bytes = Path(res["file_path"]).read_bytes()
            # Verify PNG magic signature
            self.assertTrue(saved_bytes.startswith(b"\x89PNG\r\n\x1a\n"))

    def test_decode_short_header_returns_none(self):
        clip = WindowsClipboardManager()
        if not clip._is_windows:
            self.skipTest("Windows-only test")
        short_bytes = b"BM" + b"\x00" * 20
        res = clip.decode_dib_bytes_to_png(short_bytes)
        self.assertFalse(res["success"])

    def test_decode_invalid_header_size_returns_error(self):
        clip = WindowsClipboardManager()
        if not clip._is_windows:
            self.skipTest("Windows-only test")
        # Header size 20 is invalid (< 40)
        invalid_header = struct.pack("<I", 20) + b"\x00" * 40
        res = clip.decode_dib_bytes_to_png(invalid_header)
        self.assertFalse(res["success"])


class TestWP1DatabaseClipboardPersistence(unittest.TestCase):
    """Test SQLite persistence schema v7 and CRUD operations for clipboard buffer."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_snow.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_schema_version_7_applied(self):
        with self.db._get_connection() as conn:
            row = conn.execute("PRAGMA user_version").fetchone()
            self.assertEqual(row[0], 7)

            # Verify clipboard_buffer_items table exists
            cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='clipboard_buffer_items'")
            self.assertIsNotNone(cur.fetchone())

    def test_clipboard_buffer_crud_operations(self):
        # 1. Insert item 1 (text)
        self.db.save_clipboard_item(
            item_id="item-txt-1",
            content_type="text",
            preview="Hello SNOW",
            source_device_id="desktop_windows",
            source_device_name="Windows PC",
            timestamp=100.0,
            sha256="hash-1",
            size_bytes=10,
            pinned=False,
            text_content="Hello SNOW",
            image_rel_path=None,
            mime_type="text/plain; charset=utf-8",
        )

        # 2. Insert item 2 (image)
        self.db.save_clipboard_item(
            item_id="item-img-2",
            content_type="image",
            preview="PNG Image (0.5 KiB)",
            source_device_id="desktop_windows",
            source_device_name="Windows PC",
            timestamp=200.0,
            sha256="hash-2",
            size_bytes=500,
            pinned=True,
            text_content=None,
            image_rel_path="clip_test_img.png",
            mime_type="image/png",
        )

        # 3. Load all - should be sorted descending by timestamp (item-img-2 first)
        items = self.db.load_all_clipboard_items()
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["item_id"], "item-img-2")
        self.assertEqual(items[0]["content_type"], "image")
        self.assertTrue(items[0]["pinned"])
        self.assertEqual(items[1]["item_id"], "item-txt-1")
        self.assertFalse(items[1]["pinned"])

        # 4. Update pin status
        self.db.update_clipboard_pinned("item-txt-1", True)
        updated = self.db.load_all_clipboard_items()
        item1 = next(i for i in updated if i["item_id"] == "item-txt-1")
        self.assertTrue(item1["pinned"])

        # 5. Delete single item
        self.db.delete_clipboard_item("item-img-2")
        remaining = self.db.load_all_clipboard_items()
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["item_id"], "item-txt-1")

        # 6. Clear unpinned only
        self.db.update_clipboard_pinned("item-txt-1", False)
        self.db.clear_clipboard_items(unpinned_only=True)
        self.assertEqual(len(self.db.load_all_clipboard_items()), 0)


class TestWP1ClipboardRingBufferReconciliation(unittest.TestCase):
    """Test ClipboardRingBuffer startup reconciliation and bounded eviction."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage_dir = Path(self.temp_dir.name) / "cache"
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_startup_reconciliation_prunes_missing_image_records(self):
        # Seed DB with an image item pointing to non-existent disk file
        self.db.save_clipboard_item(
            item_id="missing-img-1",
            content_type="image",
            preview="Image",
            source_device_id="desktop_windows",
            source_device_name="Windows PC",
            timestamp=100.0,
            sha256="hash-missing",
            size_bytes=123,
            pinned=False,
            text_content=None,
            image_rel_path="clip_nonexistent.png",
            mime_type="image/png",
        )
        # Also seed a valid text item
        self.db.save_clipboard_item(
            item_id="valid-txt-1",
            content_type="text",
            preview="Valid Text",
            source_device_id="desktop_windows",
            source_device_name="Windows PC",
            timestamp=200.0,
            sha256="hash-valid",
            size_bytes=10,
            pinned=False,
            text_content="Valid Text",
            image_rel_path=None,
            mime_type="text/plain",
        )

        # Initialize ring buffer - should reconcile on startup
        buffer = ClipboardRingBuffer(storage_dir=self.storage_dir, capacity=10, db_manager=self.db)
        items = buffer.list_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["item_id"], "valid-txt-1")

        # Verify DB pruned the invalid record
        db_items = self.db.load_all_clipboard_items()
        self.assertEqual(len(db_items), 1)
        self.assertEqual(db_items[0]["item_id"], "valid-txt-1")

    def test_startup_reconciliation_prunes_orphaned_disk_cache(self):
        # Create orphaned file in storage dir not recorded in DB
        orphan = self.storage_dir / "clip_orphan_123.png"
        orphan.write_bytes(b"\x89PNG\r\n\x1a\nFakePngData")
        self.assertTrue(orphan.exists())

        # Initialize ring buffer
        buffer = ClipboardRingBuffer(storage_dir=self.storage_dir, capacity=10, db_manager=self.db)
        # Orphaned file should be removed from disk
        self.assertFalse(orphan.exists())

    def test_ring_buffer_eviction_and_pin_protection(self):
        buffer = ClipboardRingBuffer(storage_dir=self.storage_dir, capacity=3, db_manager=self.db)

        # Add 3 items
        res1 = buffer.add_text("First item")
        time.sleep(0.01)
        res2 = buffer.add_text("Second item")
        time.sleep(0.01)
        res3 = buffer.add_text("Third item")

        item1_id = res1["item"]["item_id"]
        item2_id = res2["item"]["item_id"]
        item3_id = res3["item"]["item_id"]

        # Pin the oldest item (item1)
        buffer.pin(item1_id)

        # Add 4th item -> should evict item2 (oldest UNPINNED), keeping item1!
        time.sleep(0.01)
        res4 = buffer.add_text("Fourth item")
        item4_id = res4["item"]["item_id"]

        items = buffer.list_items()
        self.assertEqual(len(items), 3)
        item_ids = [i["item_id"] for i in items]
        self.assertIn(item1_id, item_ids)  # Pinned item preserved
        self.assertNotIn(item2_id, item_ids) # Evicted
        self.assertIn(item3_id, item_ids)
        self.assertIn(item4_id, item_ids)


class TestWP1ClipboardDebounceAndEchoLoop(unittest.IsolatedAsyncioTestCase):
    """Test core server clipboard debounce and echo loop prevention."""

    async def test_debounce_cancels_previous_and_schedules_latest(self):
        from snow.network.ws_server import SnowWebSocketServer

        server = SnowWebSocketServer(config=CoreConfig())

        call_count = 0
        def fake_handler():
            nonlocal call_count
            call_count += 1

        with patch.object(server, "_broadcast_clipboard_update", side_effect=fake_handler):
            # Fire multiple rapid updates within debounce window
            for _ in range(5):
                await server._schedule_debounced_clipboard_update()
            
            self.assertIsNotNone(server._clipboard_debounce_task)
            # Wait for debounce duration (~200ms + buffer)
            await asyncio.sleep(0.35)
            self.assertEqual(call_count, 1)

    async def test_echo_loop_suppression_on_same_hash(self):
        from snow.network.ws_server import SnowWebSocketServer

        server = SnowWebSocketServer(config=CoreConfig())

        test_hash = hashlib.sha256(b"same_content").hexdigest()
        server._last_processed_clipboard_hash = test_hash

        # Mock windows_clipboard get_content_sync
        with patch.object(
            server.windows_clipboard,
            "get_content_sync",
            return_value={
                "success": True,
                "type": "text",
                "sha256": test_hash,
                "text": "same_content",
            },
        ):
            server.broadcast_clipboard_buffer_event = AsyncMock()
            await server._broadcast_clipboard_update()
            # Should NOT broadcast because hash matches _last_processed_clipboard_hash
            server.broadcast_clipboard_buffer_event.assert_not_called()


class TestWP4DaemonLogFileHandleClosure(unittest.IsolatedAsyncioTestCase):
    """Test WP4: Parent daemon process closes log_file handle after subprocess.Popen."""

    @patch("subprocess.Popen")
    @patch("builtins.open")
    async def test_parent_process_closes_log_handle(self, mock_open, mock_popen):
        from snow.daemon import CoreDaemonManager

        mgr = CoreDaemonManager(spawn_timeout=0.01)
        mock_file = MagicMock()
        mock_file.closed = False
        mock_open.return_value = mock_file
        mock_proc = MagicMock()
        mock_proc.pid = 99999
        mock_popen.return_value = mock_proc

        with patch.object(mgr, "is_ipc_ready", new_callable=AsyncMock, return_value=False):
            with patch.object(mgr, "_write_pid"):
                with patch("asyncio.sleep", new_callable=AsyncMock):
                    await mgr.ensure_core_running()

        # Verify open was called for log file
        mock_open.assert_called()
        # Crucial WP4 requirement: log_file handle must be closed in parent process!
        mock_file.close.assert_called()


class TestBatch3MicroPatches(unittest.IsolatedAsyncioTestCase):
    """Regression tests for the 5 Batch 3 micro-patches."""

    def test_capability_engine_receives_db_manager(self):
        from snow.core.server import SnowCoreServer
        from snow.core.config import CoreConfig
        with tempfile.TemporaryDirectory() as td:
            db_path = Path(td) / "test.db"
            db = DatabaseManager(db_path)
            server = SnowCoreServer(config=CoreConfig(), db_manager=db)
            self.assertIsNotNone(server.capability_engine.db_manager)
            self.assertIsNotNone(server.capability_engine.clipboard_buffer.db_manager)

    async def test_clipboard_buffer_apply_stage_only_suppresses_push(self):
        from snow.capabilities.engine import CapabilityEngine, CapabilityRequest, ExecutionContext
        from snow.capabilities.clipboard_buffer import ClipboardRingBuffer
        from snow.transfer.manager import TransferManager
        from snow.transfer.storage import TransferStorageManager

        valid_png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\rIDATx\x9cc`\x00\x00\x00"
            b"\x02\x00\x01H\xaf\xa4q\x00\x00\x00\x00IEND\xaeB`\x82"
        )

        with tempfile.TemporaryDirectory() as td:
            storage_dir = Path(td) / "cb"
            transfer_dir = Path(td) / "transfers"
            storage_dir.mkdir()
            transfer_dir.mkdir()

            buf = ClipboardRingBuffer(storage_dir=storage_dir, capacity=10)
            res = buf.add_image(image_bytes=valid_png, mime_type="image/png")
            item_id = res["item"]["item_id"]

            tm = TransferManager()
            sm = TransferStorageManager(root_dir=str(transfer_dir))

            mock_router = AsyncMock()
            mock_router.route_request = AsyncMock()

            engine = CapabilityEngine(
                clipboard_buffer=buf,
                transfer_manager=tm,
                storage_manager=sm,
                session_router=mock_router,
            )

            # Stage only = True with LOCAL_OWNER context
            req = CapabilityRequest(
                action="clipboard_buffer_apply",
                params={"item_id": item_id, "target": "phone-device-1", "stage_only": True},
            )
            resp = await engine.execute(req, ctx=ExecutionContext(principal="LOCAL_OWNER"))
            self.assertTrue(resp.success)
            self.assertEqual(resp.status, "SUCCESS")
            self.assertIn("transfer_id", resp.data)
            self.assertIn("sha256", resp.data)
            # Crucial: route_request must NOT have been called with clipboard_push!
            mock_router.route_request.assert_not_called()

    async def test_watchdog_spawned_only_when_listener_fails(self):
        from snow.network.ws_server import SnowWebSocketServer
        server = SnowWebSocketServer(config=CoreConfig())

        # Case 1: Listener starts successfully -> Watchdog MUST NOT spawn
        with patch("snow.network.ws_server.WindowsClipboardListener") as mock_listener_cls:
            mock_inst = MagicMock()
            mock_listener_cls.return_value = mock_inst
            mock_inst.start.return_value = True
            server._clipboard_watchdog_task = None

            started = server.start_clipboard_listener()
            self.assertTrue(started)
            self.assertIsNone(server._clipboard_watchdog_task)

        # Case 2: Listener fails to start -> Watchdog MUST spawn as fallback
        server._clipboard_listener = None
        with patch("snow.network.ws_server.WindowsClipboardListener") as mock_listener_cls:
            mock_inst = MagicMock()
            mock_listener_cls.return_value = mock_inst
            mock_inst.start.return_value = False

            with patch.object(server, "_clipboard_sequence_watchdog", new_callable=AsyncMock):
                started = server.start_clipboard_listener()
                self.assertFalse(started)
                self.assertIsNotNone(server._clipboard_watchdog_task)
                server._clipboard_watchdog_task.cancel()

    async def test_temporary_capture_png_deleted_after_broadcast(self):
        from snow.network.ws_server import SnowWebSocketServer
        server = SnowWebSocketServer(config=CoreConfig())

        with tempfile.TemporaryDirectory() as td:
            # Create a mock temporary file in system tempdir
            temp_file = Path(tempfile.gettempdir()) / f"test_snow_cap_{time.time_ns()}.png"
            temp_file.write_bytes(b"\x89PNG\r\n\x1a\nFakeCapture")
            self.assertTrue(temp_file.is_file())

            h = hashlib.sha256(b"\x89PNG\r\n\x1a\nFakeCapture").hexdigest()
            with patch.object(
                server.windows_clipboard,
                "get_content_sync",
                return_value={
                    "success": True,
                    "type": "image",
                    "file_path": str(temp_file),
                    "size": len(b"\x89PNG\r\n\x1a\nFakeCapture"),
                    "sha256": h,
                    "mime_type": "image/png",
                },
            ):
                server.broadcast_clipboard_buffer_event = AsyncMock()
                await server._broadcast_clipboard_update()

            # Verify temp capture file was deleted
            self.assertFalse(temp_file.is_file())


if __name__ == "__main__":
    unittest.main()
