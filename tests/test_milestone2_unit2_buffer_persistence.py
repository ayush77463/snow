"""Milestone 2 — Unit 2.2 regression tests:
15-Item / 5-Pin / 100 MiB Media Budget / RLock Thread-Safety / Multi-Format Buffer /
Additive SQLite Schema v7 Persistence / Durable Monotonic Acknowledgements.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
import uuid
from unittest.mock import MagicMock

from PIL import Image

from snow.capabilities.clipboard_buffer import (
    DEFAULT_DEBOUNCE_SECONDS,
    JPEG_SIGNATURE,
    MAX_BUFFER_ITEMS,
    MAX_BUFFER_MEDIA_BYTES,
    MAX_BUNDLE_BYTES,
    MAX_BUNDLE_FILES,
    MAX_FILE_BYTES,
    MAX_IMAGE_BYTES,
    MAX_PINNED_ITEMS,
    MAX_TEXT_BYTES,
    PNG_SIGNATURE,
    ClipboardItem,
    ClipboardRingBuffer,
    validate_file_manifest,
)
from snow.capabilities.engine import CapabilityEngine, CapabilityRequest
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager, SCHEMA_VERSION


def _png_bytes(color: tuple[int, int, int, int] = (12, 34, 56, 255), size: tuple[int, int] = (8, 8)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGBA", size, color).save(buf, format="PNG")
    return buf.getvalue()


class TestMilestone2Unit2ClipboardBufferV7(unittest.TestCase):
    """Comprehensive tests for V7 Universal Clipboard buffer persistence and safety."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="snow_m2_u2_")
        self.root = Path(self.tmp_dir.name)
        self.storage_dir = self.root / "clipboard_buffer"
        self.db_path = self.root / "snow_devices.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_01_constants_and_concurrent_rlock_safety(self) -> None:
        """Concurrent threads safely mutate and read buffer state under RLock."""
        self.assertEqual(MAX_BUFFER_ITEMS, 15)
        self.assertEqual(MAX_PINNED_ITEMS, 5)
        self.assertEqual(MAX_TEXT_BYTES, 64 * 1024)
        self.assertEqual(MAX_IMAGE_BYTES, 15 * 1024 * 1024)
        self.assertEqual(MAX_FILE_BYTES, 15 * 1024 * 1024)
        self.assertEqual(MAX_BUNDLE_BYTES, 15 * 1024 * 1024)
        self.assertEqual(MAX_BUNDLE_FILES, 5)
        self.assertEqual(MAX_BUFFER_MEDIA_BYTES, 100 * 1024 * 1024)
        self.assertEqual(DEFAULT_DEBOUNCE_SECONDS, 0.5)

        buf = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db, debounce_seconds=0.0)
        errors: list[Exception] = []

        def worker(tid: int) -> None:
            try:
                for step in range(5):
                    r = buf.add_text(f"thread-{tid}-step-{step}", source_device_id=f"dev-{tid}")
                    if not r.get("success"):
                        raise AssertionError(f"Unexpected add_text failure: {r}")
                    if step == 2:
                        buf.add_files(
                            [{"name": f"f_{tid}_{step}.txt", "data": f"payload-{tid}".encode("utf-8")}],
                            source_device_id=f"dev-{tid}",
                        )
                    _ = buf.list_items(limit=15)
                    _ = buf.get_persisted_media_bytes()
                    buf.record_device_ack(f"dev-{tid}", r["item"]["seq"], r["item"]["event_id"])
            except Exception as exc:
                errors.append(exc)

        with ThreadPoolExecutor(max_workers=6) as pool:
            futures = [pool.submit(worker, tid) for tid in range(6)]
            for fut in futures:
                fut.result()

        self.assertEqual(errors, [])
        items = buf.list_items(limit=15)
        self.assertEqual(len(items), 15)
        seqs = [it["seq"] for it in items]
        self.assertEqual(seqs, sorted(seqs, reverse=True))
        self.assertEqual(len(set(seqs)), 15)
        self.assertEqual(len({it["event_id"] for it in items}), 15)

    def test_02_capacity_15_and_pinned_limit_5_protection(self) -> None:
        """Buffer retains 15 items, caps pinned items at 5, and preserves pinned during eviction."""
        buf = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db)
        pinned_ids: list[str] = []
        for i in range(5):
            r = buf.add_text(f"Pinned #{i}", pin=True)
            self.assertTrue(r["success"])
            pinned_ids.append(r["item"]["item_id"])

        extra_pin = buf.add_text("Pinned #5 should fail", pin=True)
        self.assertFalse(extra_pin["success"])
        self.assertEqual(extra_pin["status"], "MAX_PINNED_REACHED")

        # Fill remaining 10 unpinned slots + add 5 more to overflow
        for i in range(15):
            r = buf.add_text(f"Unpinned #{i}")
            self.assertTrue(r["success"])

        items = buf.list_items(limit=20)
        self.assertEqual(len(items), 15)
        live_ids = {it["item_id"] for it in items}
        for pid in pinned_ids:
            self.assertIn(pid, live_ids)

    def test_03_100mib_media_budget_and_atomic_pinned_rejection(self) -> None:
        """Persisted media enforces <= 100 MiB budget, evicts oldest unpinned, and rejects atomically if pinned."""
        # Test real 100 MiB constant with large synthetic images <= 15 MiB each (8 x 14 MiB = 112 MiB > 100 MiB)
        buf = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db)
        chunk_14m = JPEG_SIGNATURE + b"\xe0\x00\x10JFIF"
        created_paths: list[Path] = []
        for i in range(8):
            payload = chunk_14m + bytes([i]) * (14 * 1024 * 1024 - len(chunk_14m))
            res = buf.add_image(payload, source_device_id="desktop_windows")
            self.assertTrue(res["success"], res)
            p = buf.get_image_path(res["item"]["item_id"])
            if p is not None:
                created_paths.append(p)

        self.assertLessEqual(buf.get_persisted_media_bytes(), MAX_BUFFER_MEDIA_BYTES)
        self.assertLessEqual(len(buf.list_items()), 7)
        # First 14 MiB image had to be evicted to keep 7 * 14 = 98 MiB <= 100 MiB
        self.assertFalse(created_paths[0].exists())

        # Atomic rejection check with small custom max_media_bytes when blockers are pinned
        small_dir = self.root / "small_budget_buf"
        small_buf = ClipboardRingBuffer(storage_dir=small_dir, max_media_bytes=2000)
        p1 = _png_bytes((1, 1, 1, 255), size=(32, 32))
        r1 = small_buf.add_image(JPEG_SIGNATURE + b"\xe0" + b"A" * 900, pin=True)
        r2 = small_buf.add_image(JPEG_SIGNATURE + b"\xe0" + b"B" * 900, pin=True)
        r3 = small_buf.add_image(JPEG_SIGNATURE + b"\xe0" + b"C" * 100, pin=False)
        self.assertTrue(r1["success"] and r2["success"] and r3["success"])
        before_count = len(small_buf.list_items())
        before_media = small_buf.get_persisted_media_bytes()

        # Adding 500-byte image cannot fit even if 100-byte unpinned r3 were evicted -> must reject WITHOUT evicting r3
        fail_add = small_buf.add_image(JPEG_SIGNATURE + b"\xe0" + b"D" * 500)
        self.assertFalse(fail_add["success"])
        self.assertEqual(fail_add["status"], "MEDIA_BUDGET_EXCEEDED")
        self.assertEqual(len(small_buf.list_items()), before_count)
        self.assertEqual(small_buf.get_persisted_media_bytes(), before_media)
        self.assertIsNotNone(small_buf.get_image_path(r3["item"]["item_id"]))

    def test_04_exact_size_and_bundle_bounds_rejection(self) -> None:
        """Exact enforcement: 64 KiB text, 15 MiB image/file/bundle, max 5 files."""
        buf = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db)

        self.assertTrue(buf.add_text("x" * MAX_TEXT_BYTES)["success"])
        over_txt = buf.add_text("x" * (MAX_TEXT_BYTES + 1))
        self.assertFalse(over_txt["success"])
        self.assertEqual(over_txt["status"], "CONTENT_TOO_LARGE")

        ok_img = JPEG_SIGNATURE + b"\x00" * (MAX_IMAGE_BYTES - len(JPEG_SIGNATURE))
        self.assertTrue(buf.add_image(ok_img)["success"])
        over_img = JPEG_SIGNATURE + b"\x00" * (MAX_IMAGE_BYTES + 1 - len(JPEG_SIGNATURE))
        res_over_img = buf.add_image(over_img)
        self.assertFalse(res_over_img["success"])
        self.assertEqual(res_over_img["status"], "CONTENT_TOO_LARGE")

        over_file = buf.add_files([{"name": "big.bin", "data": b"a" * (MAX_FILE_BYTES + 1)}])
        self.assertFalse(over_file["success"])
        self.assertEqual(over_file["status"], "CONTENT_TOO_LARGE")

        too_many = buf.add_files([{"name": f"f{i}.txt", "data": b"ok"} for i in range(6)])
        self.assertFalse(too_many["success"])
        self.assertEqual(too_many["status"], "TOO_MANY_FILES")

        bundle_over = buf.add_files(
            [
                {"name": "part1.bin", "data": b"1" * (8 * 1024 * 1024)},
                {"name": "part2.bin", "data": b"2" * (8 * 1024 * 1024)},
            ]
        )
        self.assertFalse(bundle_over["success"])
        self.assertEqual(bundle_over["status"], "CONTENT_TOO_LARGE")

    def test_05_file_and_bundle_persistence_reconciliation_and_manifest_security(self) -> None:
        """Single files & 5-file bundles persist cleanly, validate manifests, and survive restart."""
        buf = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db)

        # Path traversal filename must fail closed
        bad_name = buf.add_files([{"name": "../evil.txt", "data": b"nope"}])
        self.assertFalse(bad_name["success"])
        self.assertEqual(bad_name["status"], "SECURITY_ERROR")

        # Symlink or directory source_path must fail closed if platform allows symlinks
        sub_dir = self.root / "dir_not_file"
        sub_dir.mkdir()
        dir_res = buf.add_files([{"source_path": sub_dir}])
        self.assertFalse(dir_res["success"])

        # Add single file + 5-file bundle
        single = buf.add_files([{"name": "notes.txt", "data": b"hello world"}])
        self.assertTrue(single["success"])
        self.assertEqual(single["item"]["content_type"], "file")
        self.assertEqual(single["item"]["file_count"], 1)
        self.assertNotIn("stored_filename", single["item"]["file_manifest"][0])

        bundle = buf.add_files(
            [{"name": f"doc_{i}.txt", "data": f"body-{i}".encode("utf-8")} for i in range(5)],
            pin=True,
        )
        self.assertTrue(bundle["success"])
        self.assertEqual(bundle["item"]["content_type"], "file_bundle")
        self.assertEqual(bundle["item"]["file_count"], 5)

        entries = buf.get_file_entries(bundle["item"]["item_id"])
        self.assertEqual(len(entries), 5)
        self.assertTrue(all(e["path"].is_file() for e in entries))

        # Reopen fresh buffer from DB & disk
        reopened = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db)
        reopened_items = reopened.list_items()
        self.assertEqual(len(reopened_items), 2)
        self.assertEqual(reopened_items[0]["item_id"], bundle["item"]["item_id"])
        self.assertEqual(len(reopened.get_file_entries(bundle["item"]["item_id"])), 5)

        # Delete missing file on disk -> startup reconciliation must prune corrupt bundle row
        entries[0]["path"].unlink()
        reopened_after_missing = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db)
        self.assertEqual(len(reopened_after_missing.list_items()), 1)
        self.assertEqual(reopened_after_missing.list_items()[0]["item_id"], single["item"]["item_id"])

        # Manifest validator strictness
        with self.assertRaises(ValueError):
            validate_file_manifest([])
        with self.assertRaises(ValueError):
            validate_file_manifest([{"name": "a/b.txt", "size_bytes": 1, "mime_type": "text/plain", "sha256": "a" * 64}])

    def test_06_debounce_collapse_vs_post_debounce_distinct_events_and_restart_seq(self) -> None:
        """Copies within debounce collapse cleanly; copies after debounce produce new event_id & higher seq."""
        buf = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db, debounce_seconds=0.06)

        r1 = buf.add_text("Repeat Me", source_device_id="pc")
        self.assertTrue(r1["success"])
        self.assertEqual(r1["status"], "ADDED")
        uuid.UUID(r1["item"]["event_id"], version=4)
        self.assertEqual(r1["item"]["seq"], 1)

        # Immediate duplicate inside 0.06s debounce -> collapses without inflating seq
        r2 = buf.add_text("Repeat Me", source_device_id="pc")
        self.assertTrue(r2["deduplicated"])
        self.assertEqual(r2["item"]["event_id"], r1["item"]["event_id"])
        self.assertEqual(r2["item"]["seq"], 1)

        # Wait past debounce -> creates brand new event_id and higher seq
        time.sleep(0.09)
        r3 = buf.add_text("Repeat Me", source_device_id="pc")
        self.assertFalse(r3["deduplicated"])
        self.assertEqual(r3["status"], "ADDED")
        self.assertNotEqual(r3["item"]["event_id"], r1["item"]["event_id"])
        self.assertEqual(r3["item"]["seq"], 2)

        # Delete latest item & restart DB -> seq must remain strictly monotonic (seq = 3, never reusing 2)
        buf.delete(r3["item"]["item_id"])
        reopened = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db, debounce_seconds=0.06)
        r4 = reopened.add_text("Brand New After Delete", source_device_id="pc")
        self.assertGreater(r4["item"]["seq"], 2)

    def test_07_ref_counted_media_cleanup_preserves_live_references(self) -> None:
        """Deleting an entry never unlinks a disk file still referenced by another live buffer entry."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        shared_name = "clip_shared_ref_test.png"
        shared_path = self.storage_dir / shared_name
        raw = _png_bytes((200, 100, 50, 255))
        shared_path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()

        self.db.save_clipboard_item(
            item_id="shared-1",
            content_type="image",
            preview="Shared PNG 1",
            source_device_id="pc",
            source_device_name="PC",
            timestamp=10.0,
            sha256=digest,
            size_bytes=len(raw),
            image_rel_path=shared_name,
            mime_type="image/png",
            event_id=str(uuid.uuid4()),
            seq=1,
        )
        self.db.save_clipboard_item(
            item_id="shared-2",
            content_type="image",
            preview="Shared PNG 2",
            source_device_id="pc",
            source_device_name="PC",
            timestamp=20.0,
            sha256=digest,
            size_bytes=len(raw),
            image_rel_path=shared_name,
            mime_type="image/png",
            event_id=str(uuid.uuid4()),
            seq=2,
        )

        buf = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db)
        self.assertEqual(len(buf.list_items()), 2)

        # Delete shared-1 -> shared_path must STILL exist for shared-2
        buf.delete("shared-1")
        self.assertTrue(shared_path.exists())
        self.assertIsNotNone(buf.get_image_path("shared-2"))

        # Delete shared-2 -> now zero live references, shared_path is cleaned up
        buf.delete("shared-2")
        self.assertFalse(shared_path.exists())

    def test_08_additive_schema_v7_migration_preserves_existing_rows_idempotently(self) -> None:
        """Opening a legacy Schema v7 DB without V7 columns migrates additively and preserves data."""
        legacy_db_path = self.root / "legacy_v7.db"
        conn = sqlite3.connect(str(legacy_db_path))
        try:
            conn.execute("PRAGMA user_version = 7;")
            conn.execute(
                """
                CREATE TABLE clipboard_buffer_items (
                    item_id TEXT PRIMARY KEY,
                    content_type TEXT NOT NULL,
                    preview TEXT NOT NULL,
                    source_device_id TEXT NOT NULL,
                    source_device_name TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    pinned INTEGER NOT NULL DEFAULT 0,
                    text_content TEXT,
                    image_rel_path TEXT,
                    mime_type TEXT
                );
                """
            )
            conn.execute(
                """
                INSERT INTO clipboard_buffer_items (
                    item_id, content_type, preview, source_device_id, source_device_name,
                    timestamp, sha256, size_bytes, pinned, text_content, image_rel_path, mime_type
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                ("legacy-item-1", "text", "Legacy note", "pc", "PC", 1234.5, "a" * 64, 11, 1, "Legacy note", None, "text/plain"),
            )
            conn.commit()
        finally:
            conn.close()

        # Run initialization twice (idempotent check)
        db1 = DatabaseManager(legacy_db_path)
        db2 = DatabaseManager(legacy_db_path)
        self.assertEqual(SCHEMA_VERSION, 7)

        with db2._get_connection() as check_conn:
            ver = check_conn.execute("PRAGMA user_version;").fetchone()[0]
            self.assertEqual(ver, 7)
            cols = {row[1] for row in check_conn.execute("PRAGMA table_info(clipboard_buffer_items);").fetchall()}
            self.assertIn("event_id", cols)
            self.assertIn("seq", cols)
            self.assertIn("file_manifest_json", cols)

        buf = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=db2)
        items = buf.list_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["item_id"], "legacy-item-1")
        self.assertTrue(items[0]["pinned"])
        self.assertTrue(bool(items[0]["event_id"]))
        self.assertEqual(items[0]["seq"], 0)

    def test_09_durable_monotonic_clipboard_ack_and_corrupt_rejection(self) -> None:
        """Per-device clipboard ack persists monotonically, rejects regressions/corrupt JSON."""
        r1 = self.db.save_clipboard_ack("android-1", last_acked_seq=5, last_acked_event_id="evt-5")
        self.assertTrue(r1["updated"])
        self.assertEqual(r1["last_acked_seq"], 5)

        # Regression must not overwrite monotonic high-water mark
        r2 = self.db.save_clipboard_ack("android-1", last_acked_seq=3, last_acked_event_id="evt-3")
        self.assertFalse(r2["updated"])
        self.assertTrue(r2["monotonic_retained"])
        self.assertEqual(r2["last_acked_seq"], 5)
        self.assertEqual(r2["last_acked_event_id"], "evt-5")

        # Higher seq persists cleanly across DB reopen
        r3 = self.db.save_clipboard_ack("android-1", last_acked_seq=9, last_acked_event_id="evt-9")
        self.assertTrue(r3["updated"])
        reopened_db = DatabaseManager(self.db_path)
        loaded = reopened_db.get_clipboard_ack("android-1")
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded["last_acked_seq"], 9)
        self.assertEqual(loaded["last_acked_event_id"], "evt-9")

        # Invalid inputs fail closed
        with self.assertRaises(ValueError):
            self.db.save_clipboard_ack("android-1", last_acked_seq=-1, last_acked_event_id="evt")
        with self.assertRaises(ValueError):
            self.db.save_clipboard_ack("../escape", last_acked_seq=1, last_acked_event_id="evt")

        # Corrupt stored JSON fails closed to None
        self.db.set_setting("clip_ack:android-corrupt", "{not valid json")
        self.assertIsNone(self.db.get_clipboard_ack("android-corrupt"))
        self.db.set_setting("clip_ack:android-neg", json.dumps({"last_acked_seq": -5}))
        self.assertIsNone(self.db.get_clipboard_ack("android-neg"))

    def test_10_capability_engine_lists_15_items_and_eligible_apply_is_latest_only(self) -> None:
        """Engine exposes 15 items; eligible OS apply selects only latest unacked non-self item."""
        buf = ClipboardRingBuffer(storage_dir=self.storage_dir, db_manager=self.db, debounce_seconds=0.0)
        for i in range(15):
            buf.add_text(f"Item {i}", source_device_id="desktop_windows")

        import asyncio

        engine = CapabilityEngine(clipboard=MagicMock(), clipboard_buffer=buf)
        ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="test")
        resp = asyncio.run(engine.execute(CapabilityRequest(action="clipboard_buffer_list", params={}), ctx=ctx))
        self.assertTrue(resp.success)
        self.assertEqual(resp.data["count"], 15)

        # Latest item is seq 15; if peer last_acked_seq is 10, ONLY latest (seq 15) is eligible
        eligible = buf.get_eligible_apply_item("android-peer", last_acked_seq=10)
        self.assertIsNotNone(eligible)
        self.assertEqual(eligible["seq"], 15)

        # Once acked at 15, nothing applies on reconnect
        buf.record_device_ack("android-peer", 15, eligible["event_id"])
        self.assertIsNone(buf.get_eligible_apply_item("android-peer"))

        # Self-originated item never triggers echo back to origin
        own = buf.add_text("From Phone", source_device_id="android-peer")
        self.assertIsNone(buf.get_eligible_apply_item("android-peer"))
        self.assertEqual(own["item"]["seq"], 16)


if __name__ == "__main__":
    unittest.main()
