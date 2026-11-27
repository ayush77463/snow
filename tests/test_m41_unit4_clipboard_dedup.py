from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import sqlite3
import struct
import tempfile
import threading
import time
import unittest
import uuid
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from PIL import Image, PngImagePlugin

from snow.capabilities.clipboard_buffer import (
    DEFAULT_DEBOUNCE_SECONDS,
    IMAGE_BURST_WINDOW_SECONDS,
    ClipboardRingBuffer,
)
from snow.capabilities.engine import CapabilityEngine, CapabilityRequest
from snow.capabilities.windows.clipboard import compute_canonical_image_digest
from snow.core.config import CoreConfig
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import SCHEMA_VERSION, DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.security.session import SessionRecord


def _make_png(color: tuple[int, int, int], size: tuple[int, int] = (24, 24), comment: str | None = None, compress: int = 6) -> bytes:
    buf = BytesIO()
    img = Image.new("RGBA", size, (*color, 255))
    kwargs: dict = {"format": "PNG", "compress_level": compress}
    if comment:
        meta = PngImagePlugin.PngInfo()
        meta.add_text("Comment", comment)
        kwargs["pnginfo"] = meta
    img.save(buf, **kwargs)
    return buf.getvalue()


def _make_fake_oversized_png_header(width: int, height: int) -> bytes:
    # Minimal PNG signature + IHDR chunk declaring oversized dimensions without allocating pixels
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr_len = struct.pack(">I", len(ihdr_data))
    ihdr_crc = struct.pack(">I", 0)
    return b"\x89PNG\r\n\x1a\n" + ihdr_len + b"IHDR" + ihdr_data + ihdr_crc


class TestM41Unit4SchemaAndLazyHydration(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m41_u4_db_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_01_fresh_db_keeps_schema_v7_and_has_canonical_columns(self) -> None:
        db_path = self.tmp_dir / "fresh.db"
        db = DatabaseManager(db_path)
        self.assertEqual(SCHEMA_VERSION, 7)
        with sqlite3.connect(db_path) as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(clipboard_buffer_items);").fetchall()}
            indexes = {row[1] for row in conn.execute("PRAGMA index_list(clipboard_buffer_items);").fetchall()}
        self.assertIn("canonical_sha256", cols)
        self.assertIn("width", cols)
        self.assertIn("height", cols)
        self.assertIn("idx_clipboard_canonical_sha256", indexes)

    def test_02_legacy_v7_table_migration_is_idempotent_and_preserves_rows(self) -> None:
        db_path = self.tmp_dir / "legacy_v7.db"
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                """
            )
            conn.execute("INSERT INTO schema_version (version, applied_at) VALUES (7, '2026-01-01T00:00:00Z');")
            conn.execute(
                """
                CREATE TABLE clipboard_buffer_items (
                    item_id TEXT PRIMARY KEY,
                    content_type TEXT NOT NULL,
                    preview TEXT NOT NULL,
                    text_content TEXT,
                    image_rel_path TEXT,
                    mime_type TEXT NOT NULL,
                    source_device_id TEXT NOT NULL,
                    source_device_name TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    pinned INTEGER NOT NULL DEFAULT 0,
                    event_id TEXT,
                    seq INTEGER NOT NULL DEFAULT 0,
                    file_manifest_json TEXT
                );
                """
            )
            conn.execute(
                """
                INSERT INTO clipboard_buffer_items (
                    item_id, content_type, preview, text_content, image_rel_path, mime_type,
                    source_device_id, source_device_name, timestamp, sha256, size_bytes, pinned, event_id, seq
                ) VALUES (
                    'legacy_img_1', 'image', 'PNG', NULL, 'legacy.png', 'image/png',
                    'desktop_windows', 'Desktop', 100.0, ?, 123, 0, 'ev-1', 1
                );
                """,
                ("a" * 64,),
            )

        DatabaseManager(db_path)
        # Run migration check a second time (idempotency)
        DatabaseManager(db_path)
        with sqlite3.connect(db_path) as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(clipboard_buffer_items);").fetchall()}
            rows = conn.execute("SELECT item_id, canonical_sha256, width, height FROM clipboard_buffer_items;").fetchall()
        self.assertTrue({"canonical_sha256", "width", "height"}.issubset(cols))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0], ("legacy_img_1", None, None, None))

    def test_03_startup_is_lazy_and_single_item_hydration_caches_canonical_metadata(self) -> None:
        db_path = self.tmp_dir / "lazy.db"
        storage_dir = self.tmp_dir / "buf"
        storage_dir.mkdir(parents=True, exist_ok=True)
        png_bytes = _make_png((33, 99, 200), size=(12, 8))
        raw_sha = hashlib.sha256(png_bytes).hexdigest()
        expected_canon, exp_w, exp_h = compute_canonical_image_digest(png_bytes)
        self.assertIsNotNone(expected_canon)
        self.assertEqual((exp_w, exp_h), (12, 8))

        (storage_dir / "legacy_clip.png").write_bytes(png_bytes)
        (storage_dir / "corrupt_clip.png").write_bytes(b"\x89PNG\r\n\x1a\ncorrupt-payload")

        db = DatabaseManager(db_path)
        db.save_clipboard_item(
            item_id="img_null_1",
            content_type="image",
            preview="PNG Image",
            text_content=None,
            image_rel_path="legacy_clip.png",
            mime_type="image/png",
            source_device_id="desktop_windows",
            source_device_name="Desktop",
            timestamp=time.time(),
            sha256=raw_sha,
            size_bytes=len(png_bytes),
            pinned=False,
            event_id="ev-null-1",
            seq=2,
        )
        db.save_clipboard_item(
            item_id="img_missing_2",
            content_type="image",
            preview="Missing PNG",
            text_content=None,
            image_rel_path="does_not_exist.png",
            mime_type="image/png",
            source_device_id="desktop_windows",
            source_device_name="Desktop",
            timestamp=time.time() - 10,
            sha256="b" * 64,
            size_bytes=10,
            pinned=False,
            event_id="ev-miss-2",
            seq=1,
        )
        db.save_clipboard_item(
            item_id="img_corrupt_3",
            content_type="image",
            preview="Corrupt PNG",
            text_content=None,
            image_rel_path="corrupt_clip.png",
            mime_type="image/png",
            source_device_id="desktop_windows",
            source_device_name="Desktop",
            timestamp=time.time() - 20,
            sha256="c" * 64,
            size_bytes=20,
            pinned=False,
            event_id="ev-corrupt-3",
            seq=0,
        )

        # Startup MUST NOT decode images in bulk
        with patch("snow.capabilities.windows.clipboard.compute_canonical_image_digest") as spy_digest:
            buf = ClipboardRingBuffer(storage_dir=storage_dir, db_manager=db)
            spy_digest.assert_not_called()

        # Reconcile removes missing files; valid and corrupt remain without canonical_sha256 yet
        self.assertIsNone(buf.get_item("img_missing_2"))
        corrupt_detail = buf.get_item("img_corrupt_3")
        self.assertIsNotNone(corrupt_detail)
        self.assertIsNone(corrupt_detail.get("canonical_sha256"))

        # Calling get_item on unhydrated valid item lazily hydrates and writes back to DB once
        valid_detail = buf.get_item("img_null_1")
        self.assertIsNotNone(valid_detail)
        self.assertEqual(valid_detail["canonical_sha256"], expected_canon)
        self.assertEqual(valid_detail["width"], 12)
        self.assertEqual(valid_detail["height"], 8)

        # Corrupt item attempted once and will not spin on subsequent accesses
        with patch("snow.capabilities.windows.clipboard.compute_canonical_image_digest") as spy_after:
            self.assertIsNone((buf.get_item("img_corrupt_3") or {}).get("canonical_sha256"))
            self.assertEqual(buf.get_item("img_null_1")["canonical_sha256"], expected_canon)
            spy_after.assert_not_called()

        # Verify persisted in SQLite on restart without needing re-decode
        buf2 = ClipboardRingBuffer(storage_dir=storage_dir, db_manager=db)
        with patch("snow.capabilities.windows.clipboard.compute_canonical_image_digest") as spy_restart:
            reloaded = buf2.get_item("img_null_1")
            spy_restart.assert_not_called()
        self.assertEqual(reloaded["canonical_sha256"], expected_canon)

    def test_04_canonical_digest_parity_bounds_and_invalid_image_safety(self) -> None:
        img = Image.new("RGBA", (2, 1))
        img.putdata([(0x11, 0x22, 0x33, 0xFF), (0xAA, 0xBB, 0xCC, 0x80)])
        b1, b2 = BytesIO(), BytesIO()
        img.save(b1, format="PNG", compress_level=1)
        img.save(b2, format="PNG", compress_level=9)
        png1, png2 = b1.getvalue(), b2.getvalue()
        self.assertNotEqual(hashlib.sha256(png1).hexdigest(), hashlib.sha256(png2).hexdigest())

        expected_pixel_hex = hashlib.sha256(
            b"2x1:" + bytes([0x11, 0x22, 0x33, 0xFF, 0xAA, 0xBB, 0xCC, 0x80])
        ).hexdigest()
        c1, w1, h1 = compute_canonical_image_digest(png1)
        c2, w2, h2 = compute_canonical_image_digest(png2)
        self.assertEqual(c1, expected_pixel_hex)
        self.assertEqual(c2, expected_pixel_hex)
        self.assertEqual((w1, h1), (2, 1))
        self.assertEqual((w2, h2), (2, 1))

        # Safety bounds and invalid formats return (None, None, None) cleanly
        self.assertEqual(compute_canonical_image_digest(b""), (None, None, None))
        self.assertEqual(compute_canonical_image_digest(b"not-an-image"), (None, None, None))
        self.assertEqual(compute_canonical_image_digest(_make_fake_oversized_png_header(8193, 1)), (None, None, None))
        self.assertEqual(compute_canonical_image_digest(_make_fake_oversized_png_header(8192, 4097)), (None, None, None))

        # Add invalid image to ClipboardRingBuffer returns INVALID_IMAGE_FORMAT cleanly
        db = DatabaseManager(self.tmp_dir / "inv.db")
        buf = ClipboardRingBuffer(storage_dir=self.tmp_dir / "inv_buf", db_manager=db)
        bad = buf.add_image(b"not-a-valid-png-or-jpeg")
        self.assertFalse(bad["success"])
        self.assertEqual(bad["status"], "INVALID_IMAGE_FORMAT")


class TestM41Unit4ThreeWayDedupAndRestart(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m41_u4_ws_"))
        self.db_path = self.tmp_dir / "snow.db"
        self.buf_dir = self.tmp_dir / "cb_buf"
        self.transfer_dir = self.tmp_dir / "transfers"
        self.db = DatabaseManager(self.db_path)
        self.ident = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Desktop V15",
            created_at="2026-01-01T00:00:00Z",
        )
        self.cfg = CoreConfig(transfer_root=str(self.transfer_dir))
        self.ws = SnowWebSocketServer(config=self.cfg, db_manager=self.db, device_identity=self.ident)
        self.cb_buf = ClipboardRingBuffer(storage_dir=self.buf_dir, db_manager=self.db)
        self.ws.clipboard_buffer = self.cb_buf
        self.ws.capability_engine.clipboard_buffer = self.cb_buf
        self.ws.core_server = SimpleNamespace(ws_server=self.ws, session_manager=self.ws.session_manager)

    def tearDown(self) -> None:
        try:
            self.db.close()
        except Exception:
            pass
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_05_constants_and_class1_os_burst_vs_distinct_and_explicit_bypass(self) -> None:
        self.assertEqual(DEFAULT_DEBOUNCE_SECONDS, 0.5)
        self.assertEqual(IMAGE_BURST_WINDOW_SECONDS, 1.0)

        png_a1 = _make_png((200, 30, 30), comment="format1", compress=1)
        png_a2 = _make_png((200, 30, 30), comment="format2", compress=9)
        png_b = _make_png((20, 200, 90))

        r1 = self.cb_buf.add_image(png_a1, source_device_id="desktop_windows")
        self.assertEqual(r1["status"], "ADDED")

        # Simulate 0.7s elapsed (beyond 0.5s text debounce, still inside 1.0s OS image burst window!)
        with self.cb_buf._lock:
            self.cb_buf._items[0].timestamp = time.time() - 0.7
        r2 = self.cb_buf.add_image(png_a2, source_device_id="desktop_windows")
        self.assertEqual(r2["status"], "DEDUPLICATED")
        self.assertTrue(r2["deduplicated"])
        self.assertEqual(len(self.cb_buf.list_items()), 1)

        # Distinct image within 1.0s window succeeds
        r3 = self.cb_buf.add_image(png_b, source_device_id="desktop_windows")
        self.assertEqual(r3["status"], "ADDED")
        self.assertEqual(len(self.cb_buf.list_items()), 2)

        # Class 3 explicit user action bypasses burst debounce cleanly
        r4 = self.cb_buf.add_image(png_b, source_device_id="desktop_windows", bypass_debounce=True)
        self.assertEqual(r4["status"], "ADDED")
        self.assertFalse(r4["deduplicated"])

    async def test_06_class2_and_class3_across_restart_and_apply_target(self) -> None:
        png_a = _make_png((220, 50, 50), compress=1)
        png_a_re = _make_png((220, 50, 50), comment="android-reencode", compress=9)
        canon_a, _, _ = compute_canonical_image_digest(png_a)
        sha_a_re = hashlib.sha256(png_a_re).hexdigest()

        added = self.cb_buf.add_image(png_a, source_device_id="desktop_windows")
        item_id = added["item"]["item_id"]

        # Class 2: clipboard_buffer_apply to PC updates canonical echo state + persistent DB marker
        engine = self.ws.capability_engine
        engine.clipboard_buffer = self.cb_buf
        engine.core_server = self.ws.core_server
        engine.clipboard.set_image_sync = MagicMock(return_value={"success": True, "status": "COPIED"})
        ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="dashboard")
        apply_pc = await engine.execute(
            CapabilityRequest(action="clipboard_buffer_apply", params={"item_id": item_id, "target": "pc"}),
            ctx=ctx,
        )
        self.assertTrue(apply_pc.success, msg=f"apply_pc failed: {apply_pc}")
        self.assertEqual(self.ws._last_processed_canonical_hash, canon_a)
        self.assertIsNotNone(self.db.get_setting("clip_last_snow_write"))

        # Verify remote Android clipboard_buffer_apply propagates canonical_sha256 & user_initiated=True
        mock_router = MagicMock()
        mock_router.route_request = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        engine.session_router = mock_router
        apply_android = await engine.execute(
            CapabilityRequest(action="clipboard_buffer_apply", params={"item_id": item_id, "target": "phone-1"}),
            ctx=ctx,
        )
        self.assertTrue(apply_android.success)
        push_data = mock_router.route_request.call_args.kwargs["data"]
        self.assertEqual(push_data["canonical_sha256"], canon_a)
        self.assertTrue(push_data["user_initiated"])

        # Simulate Core restart + legacy SQLite row missing canonical_sha256 column value
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE clipboard_buffer_items SET canonical_sha256 = NULL WHERE item_id = ?;", (item_id,))

        restarted_db = DatabaseManager(self.db_path)
        self.db = restarted_db
        restarted_buf = ClipboardRingBuffer(storage_dir=self.buf_dir, db_manager=restarted_db)
        restarted_ws = SnowWebSocketServer(config=self.cfg, db_manager=restarted_db, device_identity=self.ident)
        restarted_ws.clipboard_buffer = restarted_buf
        restarted_ws.capability_engine.clipboard_buffer = restarted_buf

        up_dir = restarted_ws.storage_manager.root_dir
        up_dir.mkdir(parents=True, exist_ok=True)
        (up_dir / "re_after_restart.png").write_bytes(png_a_re)

        set_img_mock = MagicMock(return_value={"success": True, "status": "COPIED"})
        restarted_ws.capability_engine.clipboard.set_image_sync = set_img_mock
        sent_msgs: list[str] = []

        async def cap_send(raw: str) -> None:
            sent_msgs.append(raw)

        fake_client = SimpleNamespace(connection_id="c-1", websocket=SimpleNamespace(send=cap_send))
        session = SessionRecord(
            session_id="s-1",
            device_id="phone-1",
            connection_id="c-1",
            created_at="2026-01-01T00:00:00Z",
            last_seen="2026-01-01T00:00:00Z",
            trust_tier="peer",
        )

        # Class 2 incoming re-encoded image after Core restart MUST be deduplicated cleanly!
        echo_msg = SnowMessage.create_request(
            "desktop_clipboard_set",
            data={"type": "image", "sha256": sha_a_re, "file_name": "re_after_restart.png"},
        )
        await restarted_ws._handle_desktop_clipboard_set(fake_client, echo_msg, echo_msg.data, session)
        resp_echo = json.loads(sent_msgs[-1])
        self.assertTrue(resp_echo["payload"]["data"]["deduplicated"])
        set_img_mock.assert_not_called()

        # Watcher broadcast echo immediately after restart is also suppressed via persisted clip_last_snow_write
        tmp_img_file = self.tmp_dir / "watch_echo.png"
        tmp_img_file.write_bytes(png_a_re)
        restarted_ws.capability_engine.clipboard.get_content_sync = MagicMock(
            return_value={
                "success": True,
                "type": "image",
                "sha256": sha_a_re,
                "canonical_sha256": canon_a,
                "file_path": str(tmp_img_file),
            }
        )
        restarted_ws.broadcast_clipboard_buffer_event = AsyncMock()
        await restarted_ws._broadcast_clipboard_update()
        restarted_ws.broadcast_clipboard_buffer_event.assert_not_called()

        # Class 3 explicit user action (user_initiated=True) on same image MUST bypass suppression!
        explicit_msg = SnowMessage.create_request(
            "desktop_clipboard_set",
            data={
                "type": "image",
                "sha256": sha_a_re,
                "file_name": "re_after_restart.png",
                "user_initiated": True,
            },
        )
        await restarted_ws._handle_desktop_clipboard_set(fake_client, explicit_msg, explicit_msg.data, session)
        resp_explicit = json.loads(sent_msgs[-1])
        self.assertEqual(resp_explicit["payload"]["status"], "success")
        self.assertFalse(resp_explicit["payload"]["data"].get("deduplicated", False))
        set_img_mock.assert_called_once()

    def test_07_concurrent_image_adds_and_lazy_hydration_thread_safe(self) -> None:
        errors: list[Exception] = []
        base_pngs = [_make_png((i * 20, i * 10, 50), size=(8, 8)) for i in range(6)]

        def worker(idx: int) -> None:
            try:
                for step in range(4):
                    png = base_pngs[(idx + step) % len(base_pngs)]
                    res = self.cb_buf.add_image(
                        png,
                        source_device_id=f"dev-{idx}",
                        bypass_debounce=(step == 3),
                    )
                    self.assertTrue(res["success"])
                    if res.get("item"):
                        self.cb_buf.get_item(res["item"]["item_id"])
                    self.cb_buf.hydrate_latest_image_canonical()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
