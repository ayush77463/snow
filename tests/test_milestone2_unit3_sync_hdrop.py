"""Milestone 2 — Unit 2.3 regression tests:
Windows CF_HDROP capture/apply, zero-echo metadata WSS broadcast, durable clipboard_ack,
separated 15-item history sync vs latest-only OS apply, real port 8766 SHA-256 transfer,
post-debounce repeat copy broadcast, and MCP multi-format behavior.
"""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from aiohttp import ClientSession

from snow.capabilities.clipboard_buffer import ClipboardRingBuffer
from snow.capabilities.engine import CapabilityEngine, CapabilityRequest
from snow.capabilities.windows.clipboard import (
    CF_HDROP,
    DROPFILES,
    MAX_CLIPBOARD_BUNDLE_BYTES,
    MAX_CLIPBOARD_FILES,
    WindowsClipboardManager,
)
from snow.core.config import CoreConfig
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.server import create_snow_mcp_server
from snow.network.connection_manager import ConnectionManager
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import DEFAULT_MAX_MESSAGE_SIZE
from snow.protocol.models import SnowMessage
from snow.protocol.validator import validate_raw_message
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import load_or_create_device_identity
from snow.security.session import SessionRecord
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferDirection, TransferManager, TransferState
from snow.transfer.storage import TransferStorageManager, commit_verified_clipboard_files


class _MockWsClient:
    def __init__(self, connection_id: str) -> None:
        self.connection_id = connection_id
        self.is_active = True
        self.sent_messages: list[str] = []
        self.websocket = AsyncMock()
        self.websocket.state = 1

        async def _record(raw: str) -> None:
            self.sent_messages.append(raw)

        self.websocket.send = AsyncMock(side_effect=_record)

    def parsed(self) -> list[SnowMessage]:
        return [validate_raw_message(m) for m in self.sent_messages]


class TestMilestone2Unit3CFHdropAndSafety(unittest.TestCase):
    """Test Windows CF_HDROP capture, security exclusions, and verified staging commit."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="snow_m2_u3_clip_")
        self.root = Path(self.tmp_dir.name)
        self.files_dir = self.root / "user_files"
        self.files_dir.mkdir(parents=True, exist_ok=True)
        self.snow_dir = self.root / ".snow_state"
        self.snow_dir.mkdir(parents=True, exist_ok=True)
        self._old_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = str(self.snow_dir)

    def tearDown(self) -> None:
        if self._old_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self._old_data_dir
        self.tmp_dir.cleanup()

    def _make_mgr(self) -> WindowsClipboardManager:
        mgr = WindowsClipboardManager()
        mgr._is_windows = True
        mgr._user32 = MagicMock()
        mgr._kernel32 = MagicMock()
        mgr._user32.OpenClipboard.return_value = 1
        mgr._user32.CloseClipboard.return_value = 1
        mgr._user32.IsClipboardFormatAvailable.side_effect = lambda fmt: 1 if fmt == CF_HDROP else 0
        mgr._user32.GetClipboardData.return_value = 1234
        return mgr

    def test_01_cf_hdrop_single_file_and_5_file_bundle_capture(self) -> None:
        """CF_HDROP captures single file and 5-file bundles cleanly without mutating OS clipboard."""
        f1 = self.files_dir / "report.pdf"
        f1.write_bytes(b"%PDF-1.4\nhello")
        mgr = self._make_mgr()

        with patch.object(mgr, "_extract_hdrop_paths", return_value=[str(f1)]):
            res = mgr.get_content_sync()
        self.assertTrue(res["success"])
        self.assertEqual(res["type"], "file")
        self.assertEqual(len(res["files"]), 1)
        self.assertEqual(res["files"][0]["name"], "report.pdf")
        mgr._user32.EmptyClipboard.assert_not_called()

        bundle_paths = []
        for idx in range(5):
            fp = self.files_dir / f"doc_{idx}.txt"
            fp.write_text(f"payload-{idx}", encoding="utf-8")
            bundle_paths.append(str(fp))

        with patch.object(mgr, "_extract_hdrop_paths", return_value=bundle_paths):
            res_bundle = mgr.get_files_sync()
        self.assertTrue(res_bundle["success"])
        self.assertEqual(res_bundle["type"], "file_bundle")
        self.assertEqual(len(res_bundle["files"]), MAX_CLIPBOARD_FILES)

    def test_02_cf_hdrop_rejects_over_5_oversized_dir_sensitive_and_symlinks(self) -> None:
        """CF_HDROP fails closed for >5 files, >15 MiB, directories, symlinks, and sensitive files."""
        mgr = self._make_mgr()

        # 6 files -> TOO_MANY_FILES
        six_files = []
        for idx in range(6):
            p = self.files_dir / f"extra_{idx}.txt"
            p.write_text("ok", encoding="utf-8")
            six_files.append(str(p))
        with patch.object(mgr, "_extract_hdrop_paths", return_value=six_files):
            r6 = mgr.get_content_sync()
        self.assertFalse(r6["success"])
        self.assertEqual(r6["status"], "TOO_MANY_FILES")
        mgr._user32.EmptyClipboard.assert_not_called()

        # Directory -> INVALID_FILE_TYPE
        sub_dir = self.files_dir / "folder"
        sub_dir.mkdir()
        with patch.object(mgr, "_extract_hdrop_paths", return_value=[str(sub_dir)]):
            r_dir = mgr.get_content_sync()
        self.assertFalse(r_dir["success"])
        self.assertEqual(r_dir["status"], "INVALID_FILE_TYPE")

        # Internal SNOW state file -> SECURITY_ERROR
        internal_db = self.snow_dir / "snow_devices.db"
        internal_db.write_bytes(b"sqlite")
        with patch.object(mgr, "_extract_hdrop_paths", return_value=[str(internal_db)]):
            r_sec = mgr.get_content_sync()
        self.assertFalse(r_sec["success"])
        self.assertEqual(r_sec["status"], "SECURITY_ERROR")

        # Credential/key extension -> SECURITY_ERROR
        key_file = self.files_dir / "private.pem"
        key_file.write_text("SECRET", encoding="utf-8")
        with patch.object(mgr, "_extract_hdrop_paths", return_value=[str(key_file)]):
            r_key = mgr.get_content_sync()
        self.assertFalse(r_key["success"])
        self.assertEqual(r_key["status"], "SECURITY_ERROR")

        # Oversized (> 15 MiB) -> CONTENT_TOO_LARGE
        huge = self.files_dir / "huge.bin"
        with open(huge, "wb") as fh:
            fh.seek(MAX_CLIPBOARD_BUNDLE_BYTES)
            fh.write(b"\x00")
        with patch.object(mgr, "_extract_hdrop_paths", return_value=[str(huge)]):
            r_huge = mgr.get_content_sync()
        self.assertFalse(r_huge["success"])
        self.assertEqual(r_huge["status"], "CONTENT_TOO_LARGE")

        # Symlink if supported on host OS -> SECURITY_ERROR
        link_path = self.files_dir / "link.txt"
        target_f = self.files_dir / "real.txt"
        target_f.write_text("hello", encoding="utf-8")
        try:
            link_path.symlink_to(target_f)
        except OSError:
            link_path = None
        if link_path is not None:
            with patch.object(mgr, "_extract_hdrop_paths", return_value=[str(link_path)]):
                r_link = mgr.get_content_sync()
            self.assertFalse(r_link["success"])
            self.assertEqual(r_link["status"], "SECURITY_ERROR")

    def test_03_commit_verified_files_collision_safe_and_integrity_checked(self) -> None:
        """commit_verified_clipboard_files checks SHA-256 before committing and deduplicates or disambiguates collisions."""
        dest_dir = self.root / "Downloads_SNOW"
        data_a = b"alpha-file-bytes"
        sha_a = hashlib.sha256(data_a).hexdigest()

        # Commit 1 -> report.txt
        c1 = commit_verified_clipboard_files(
            dest_dir,
            [{"name": "report.txt", "size_bytes": len(data_a), "sha256": sha_a, "data": data_a}],
        )
        self.assertEqual(c1[0].name, "report.txt")
        self.assertEqual(c1[0].read_bytes(), data_a)

        # Identical SHA-256 re-save reuses report.txt without creating duplicate
        c2 = commit_verified_clipboard_files(
            dest_dir,
            [{"name": "report.txt", "size_bytes": len(data_a), "sha256": sha_a, "data": data_a}],
        )
        self.assertEqual(c2[0], c1[0])
        self.assertFalse((dest_dir / "report (1).txt").exists())

        # Different content with same filename gets conflict-safe name report (1).txt
        data_b = b"beta-file-bytes-updated"
        sha_b = hashlib.sha256(data_b).hexdigest()
        c3 = commit_verified_clipboard_files(
            dest_dir,
            [{"name": "report.txt", "size_bytes": len(data_b), "sha256": sha_b, "data": data_b}],
        )
        self.assertEqual(c3[0].name, "report (1).txt")
        self.assertEqual(c3[0].read_bytes(), data_b)

        # Bad SHA-256 -> fails closed before committing anything and leaves no .part clutter
        with self.assertRaises(ValueError):
            commit_verified_clipboard_files(
                dest_dir,
                [
                    {"name": "good.txt", "size_bytes": 4, "sha256": hashlib.sha256(b"good").hexdigest(), "data": b"good"},
                    {"name": "bad.txt", "size_bytes": 3, "sha256": "0" * 64, "data": b"bad"},
                ],
            )
        self.assertFalse((dest_dir / "good.txt").exists())
        self.assertFalse((dest_dir / "bad.txt").exists())
        self.assertEqual(list((dest_dir / ".parts").iterdir()), [])

    def test_04_set_files_sync_builds_valid_utf16_dropfiles_hdrop(self) -> None:
        """set_files_sync constructs a double-NUL UTF-16LE DROPFILES structure and sets CF_HDROP."""
        f1 = self.files_dir / "one.txt"
        f1.write_text("1", encoding="utf-8")
        mgr = self._make_mgr()
        mgr._kernel32.GlobalAlloc.return_value = 777
        buf_mem = ctypes.create_string_buffer(2048)
        mgr._kernel32.GlobalLock.return_value = ctypes.addressof(buf_mem)
        mgr._user32.SetClipboardData.return_value = 999

        res = mgr.set_files_sync([f1])
        self.assertTrue(res["success"])
        mgr._user32.SetClipboardData.assert_called_once_with(CF_HDROP, 777)
        p_files, _, _, f_wide = struct.unpack("<I8sII", buf_mem.raw[:20])
        self.assertEqual(p_files, ctypes.sizeof(DROPFILES))
        self.assertEqual(f_wide, 1)


class TestMilestone2Unit3SyncAckAndPort8766(unittest.IsolatedAsyncioTestCase):
    """Test zero-echo broadcasts, separated history sync vs latest-only apply, durable ack, and 8766 transfer."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory(prefix="snow_m2_u3_srv_")
        self.root = Path(self.tmp_dir.name)
        self.snow_dir = self.root / "snow_data"
        self.snow_dir.mkdir(parents=True, exist_ok=True)
        self._old_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = str(self.snow_dir)

        self.db = DatabaseManager(self.snow_dir / "snow_devices.db")
        self.dev_a = str(uuid.uuid4())
        self.dev_b = str(uuid.uuid4())
        self.dev_c_files_only = str(uuid.uuid4())
        self.token_a = "tok-device-a-12345"
        self.token_b = "tok-device-b-67890"
        self.db.insert_paired_device(self.dev_a, "Pixel A", hash_token(self.token_a), trust_tier="owner")
        self.db.insert_paired_device(self.dev_b, "Galaxy B", hash_token(self.token_b), trust_tier="peer")
        self.db.insert_paired_device(self.dev_c_files_only, "Files Only", hash_token("tok-c"), trust_tier="peer")
        self.db.set_setting(f"device_profile:{self.dev_c_files_only}", "files_only")

        self.storage_dir = self.root / "pc_downloads"
        self.cb_dir = self.root / "cb_storage"
        self.storage_mgr = TransferStorageManager(self.storage_dir)
        self.transfer_mgr = TransferManager()
        self.conn_mgr = ConnectionManager()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            free_transfer_port = probe.getsockname()[1]
        self.config = CoreConfig(
            bind_host="127.0.0.1",
            port=8765,
            transfer_port=free_transfer_port,
            tls_enabled=False,
            auth_required=True,
        )

        self.cb_buf = ClipboardRingBuffer(storage_dir=self.cb_dir, db_manager=self.db, debounce_seconds=0.05)
        self.clip_mgr = MagicMock()
        self.clip_mgr.set_clipboard = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        self.clip_mgr.set_clipboard_sync = MagicMock(return_value={"success": True, "status": "SUCCESS"})
        self.clip_mgr.set_image_sync = MagicMock(return_value={"success": True, "status": "SUCCESS"})
        self.clip_mgr.set_files_sync = MagicMock(return_value={"success": True, "status": "SUCCESS"})

        self.engine = CapabilityEngine(
            clipboard=self.clip_mgr,
            clipboard_buffer=self.cb_buf,
            db_manager=self.db,
            transfer_manager=self.transfer_mgr,
            storage_manager=self.storage_mgr,
        )
        self.engine.session_router = MagicMock()
        self.engine.session_router.route_request = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        self.identity = load_or_create_device_identity(self.snow_dir / "device_key.json")
        self.ws_server = SnowWebSocketServer(
            config=self.config,
            db_manager=self.db,
            connection_manager=self.conn_mgr,
            transfer_manager=self.transfer_mgr,
            storage_manager=self.storage_mgr,
            device_identity=self.identity,
        )
        self.ws_server._capability_engine = self.engine
        self.ws_server.clipboard_buffer = self.cb_buf
        self.ws_server.windows_clipboard = self.clip_mgr
        self.http_server = SnowHttpTransferServer(
            config=self.config,
            db_manager=self.db,
            transfer_manager=self.transfer_mgr,
            storage_manager=self.storage_mgr,
        )
        self.ws_server.http_transfer_server = self.http_server
        self.engine.http_transfer_server = self.http_server
        await self.http_server.start()

        # Register 3 authenticated peer connections
        self.cli_a = self._attach_peer("conn-a", self.dev_a)
        self.cli_b = self._attach_peer("conn-b", self.dev_b)
        self.cli_c = self._attach_peer("conn-c", self.dev_c_files_only)

    async def asyncTearDown(self) -> None:
        await self.http_server.stop()
        if self._old_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self._old_data_dir
        self.tmp_dir.cleanup()

    def _attach_peer(self, conn_id: str, dev_id: str) -> _MockWsClient:
        cli = _MockWsClient(conn_id)
        self.conn_mgr._connections[conn_id] = cli
        self.ws_server.session_manager.create_session(
            device_id=dev_id,
            connection_id=conn_id,
            trust_tier="owner" if dev_id == self.dev_a else "peer",
        )
        return cli

    async def test_01_zero_echo_metadata_only_and_permission_filtering(self) -> None:
        """Broadcasts omit raw secrets/paths, respect <=64KiB WSS limit, suppress origin echo, and respect files_only."""
        # Phone A adds a file bundle -> Phone A MUST NOT get echo, Phone C (files_only) MUST NOT get clipboard, Phone B MUST
        add_res = self.cb_buf.add_files(
            [{"name": "spec.txt", "data": b"confidential spec body"}],
            source_device_id=self.dev_a,
            source_device_name="Pixel A",
        )
        self.assertTrue(add_res["success"])
        await self.ws_server.broadcast_clipboard_buffer_event(add_res["item"])

        self.assertEqual(len(self.cli_a.sent_messages), 0)
        self.assertEqual(len(self.cli_c.sent_messages), 0)
        self.assertEqual(len(self.cli_b.sent_messages), 1)
        raw_json = self.cli_b.sent_messages[0]
        self.assertLessEqual(len(raw_json.encode("utf-8")), DEFAULT_MAX_MESSAGE_SIZE)
        msg = validate_raw_message(raw_json)
        self.assertEqual(msg.payload["action"], "clipboard_buffer_updated")
        item_payload = msg.payload["data"]["item"]
        self.assertEqual(item_payload["origin_device_id"], self.dev_a)
        self.assertNotIn("stored_filename", json.dumps(item_payload))
        self.assertNotIn("text_content", item_payload)
        self.assertEqual(item_payload["file_manifest"][0]["name"], "spec.txt")

    async def test_02_reconnect_history_sync_vs_latest_only_apply_and_durable_ack(self) -> None:
        """History sync exposes all items without OS overwrite; reconnect pushes ONLY latest unacked non-self event until acked."""
        # Phone B previously acked seq 1
        self.db.save_clipboard_ack(self.dev_b, last_acked_seq=1, last_acked_event_id="evt-1")

        # While Phone B was offline, PC added seq 1 (old), 2, 3, 4, 5
        self.cb_buf.add_text("clip-1", source_device_id="desktop_windows")
        self.cb_buf.add_text("clip-2", source_device_id="desktop_windows")
        self.cb_buf.add_text("clip-3", source_device_id="desktop_windows")
        self.cb_buf.add_text("clip-4", source_device_id="desktop_windows")
        r5 = self.cb_buf.add_text("clip-5-latest", source_device_id="desktop_windows")
        seq5 = r5["item"]["seq"]
        evt5 = r5["item"]["event_id"]
        self.assertEqual(seq5, 5)

        # 1. History sync request -> gets all 5 items cleanly without any clipboard_push
        req_hist = SnowMessage.create_request("clipboard_history_sync", {"limit": 15})
        sess_b = self.ws_server.session_manager.get_session_by_connection("conn-b")
        await self.ws_server._handle_clipboard_buffer_list(self.cli_b, req_hist, {}, sess_b)
        msgs = self.cli_b.parsed()
        self.assertEqual(len(msgs), 1)
        self.assertEqual(msgs[0].payload["count"], 5)
        self.assertEqual(msgs[0].payload["last_acked_seq"], 1)
        self.cli_b.sent_messages.clear()

        # 2. Reconnect enabling instant sync -> pushes ONLY latest (seq 5), NOT seq 2, 3, 4
        req_toggle = SnowMessage.create_request("desktop_clipboard_sync_toggle", {"enabled": True})
        await self.ws_server._handle_desktop_clipboard_sync_toggle(
            self.cli_b, req_toggle, {"enabled": True}, sess_b
        )
        msgs_after = self.cli_b.parsed()
        push_msgs = [m for m in msgs_after if m.payload.get("action") == "clipboard_push"]
        self.assertEqual(len(push_msgs), 1)
        self.assertEqual(push_msgs[0].payload["data"]["seq"], 5)
        self.assertEqual(push_msgs[0].payload["data"]["text"], "clip-5-latest")

        # Because Phone B has NOT sent clipboard_ack yet, durable ack in SQLite MUST still be 1 (disconnect retry!)
        self.assertEqual(self.db.get_clipboard_ack(self.dev_b)["last_acked_seq"], 1)

        # Simulate disconnect and reconnect before ack -> must retry seq 5 cleanly
        self.ws_server._last_synced_clipboard_event.pop("conn-b", None)
        self.cli_b.sent_messages.clear()
        await self.ws_server._handle_desktop_clipboard_sync_toggle(
            self.cli_b, req_toggle, {"enabled": True}, sess_b
        )
        retry_pushes = [m for m in self.cli_b.parsed() if m.payload.get("action") == "clipboard_push"]
        self.assertEqual(len(retry_pushes), 1)
        self.assertEqual(retry_pushes[0].payload["data"]["seq"], 5)

        # 3. Phone B actually commits and sends clipboard_ack for seq 5 -> durable monotonic persist
        ack_msg = SnowMessage.create_request("clipboard_ack", {"seq": seq5, "event_id": evt5})
        await self.ws_server._handle_clipboard_ack(self.cli_b, ack_msg, {"seq": seq5, "event_id": evt5}, sess_b)
        self.assertEqual(self.db.get_clipboard_ack(self.dev_b)["last_acked_seq"], 5)

        # Subsequent reconnect after ack -> ZERO clipboard_push overwrite!
        self.ws_server._last_synced_clipboard_event.pop("conn-b", None)
        self.cli_b.sent_messages.clear()
        await self.ws_server._handle_desktop_clipboard_sync_toggle(
            self.cli_b, req_toggle, {"enabled": True}, sess_b
        )
        pushes_after_ack = [m for m in self.cli_b.parsed() if m.payload.get("action") == "clipboard_push"]
        self.assertEqual(len(pushes_after_ack), 0)

        # 4. If latest item (seq 6) originated from Phone B itself, Phone B reconnects -> ZERO self-echo push!
        self.cb_buf.add_text("originated-on-phone-b", source_device_id=self.dev_b, source_device_name="Galaxy B")
        self.ws_server._last_synced_clipboard_event.pop("conn-b", None)
        self.cli_b.sent_messages.clear()
        await self.ws_server._handle_desktop_clipboard_sync_toggle(
            self.cli_b, req_toggle, {"enabled": True}, sess_b
        )
        self.assertEqual([m for m in self.cli_b.parsed() if m.payload.get("action") == "clipboard_push"], [])

    async def test_03_port_8766_upload_desktop_clipboard_set_file_and_download_resume(self) -> None:
        """Full 8766 HTTPS file upload -> SHA-256 verify -> desktop CF_HDROP -> zero-echo -> 8766 Range download."""
        port = self.http_server.bound_port
        self.assertTrue(port)
        file_bytes = b"SNOW-V7-CLIPBOARD-FILE-CONTENT-" * 512
        file_sha = hashlib.sha256(file_bytes).hexdigest()
        base_url = f"http://127.0.0.1:{port}"
        headers_a = {
            "Authorization": f"Bearer {self.token_a}",
            "X-Snow-Device-Id": self.dev_a,
        }
        headers_b = {
            "Authorization": f"Bearer {self.token_b}",
            "X-Snow-Device-Id": self.dev_b,
        }

        async with ClientSession() as http:
            # 1. Phone A initiates and uploads file to port 8766
            async with http.post(
                f"{base_url}/api/v1/transfers/init",
                json={"file_name": "bundle_doc.txt", "file_size": len(file_bytes), "sha256": file_sha, "direction": "UPLOAD"},
                headers=headers_a,
            ) as resp_init:
                self.assertEqual(resp_init.status, 200)
                t_id = (await resp_init.json())["transfer_id"]

            async with http.post(
                f"{base_url}/api/v1/transfers/upload/{t_id}",
                data=file_bytes,
                headers={**headers_a, "Content-Range": f"bytes 0-{len(file_bytes)-1}/{len(file_bytes)}"},
            ) as resp_up:
                self.assertEqual(resp_up.status, 200)

            # 2. Phone A sends desktop_clipboard_set type="file"
            sess_a = self.ws_server.session_manager.get_session_by_connection("conn-a")
            set_msg = SnowMessage.create_request(
                "desktop_clipboard_set",
                {
                    "type": "file",
                    "files": [
                        {
                            "transfer_id": t_id,
                            "file_name": "bundle_doc.txt",
                            "sha256": file_sha,
                            "size_bytes": len(file_bytes),
                            "mime_type": "text/plain",
                        }
                    ],
                },
            )
            await self.ws_server._handle_desktop_clipboard_set(self.cli_a, set_msg, set_msg.payload["data"], sess_a)

            self.clip_mgr.set_files_sync.assert_called_once()
            committed_arg = self.clip_mgr.set_files_sync.call_args[0][0]
            self.assertEqual(len(committed_arg), 1)
            self.assertEqual(committed_arg[0].read_bytes(), file_bytes)

            # Phone A got only the response frame (no clipboard_buffer_updated echo), while Phone B got metadata broadcast
            self.assertEqual(len(self.cli_a.parsed()), 1)
            self.assertEqual(self.cli_a.parsed()[0].payload["status"], "success")
            self.assertEqual(len(self.cli_b.parsed()), 1)
            b_item = self.cli_b.parsed()[0].payload["data"]["item"]
            self.assertEqual(b_item["content_type"], "file")

            # 3. Apply that buffered item to Phone B (stage_only or via engine) & verify HTTP Range download on 8766
            apply_res = await self.engine.execute(
                CapabilityRequest(
                    action="clipboard_buffer_apply",
                    params={"item_id": b_item["item_id"], "target": self.dev_b, "stage_only": True},
                ),
                ctx=ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, device_id=self.dev_b),
            )
            self.assertTrue(apply_res.success)
            dl_tid = apply_res.data["files"][0]["transfer_id"]

            # Resumable HTTP Range download: first half + second half
            mid = len(file_bytes) // 2
            async with http.get(
                f"{base_url}/api/v1/transfers/download/{dl_tid}",
                headers={**headers_b, "Range": f"bytes=0-{mid-1}"},
            ) as r_p1:
                self.assertEqual(r_p1.status, 206)
                part1 = await r_p1.read()
            async with http.get(
                f"{base_url}/api/v1/transfers/download/{dl_tid}",
                headers={**headers_b, "Range": f"bytes={mid}-{len(file_bytes)-1}"},
            ) as r_p2:
                self.assertEqual(r_p2.status, 206)
                part2 = await r_p2.read()
            downloaded = part1 + part2
            self.assertEqual(hashlib.sha256(downloaded).hexdigest(), file_sha)

    async def test_04_post_debounce_windows_copy_broadcasts_distinct_event_and_mcp_54_tools_intact(self) -> None:
        """Intentional repeat Windows copy after debounce broadcasts new seq & event_id; MCP keeps 54 tools with multi-format support."""
        self.ws_server._active_sync_connections.add("conn-b")
        self.cb_buf.debounce_seconds = 0.35
        text = "Repeated copy string"
        text_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
        self.clip_mgr.get_content_sync = MagicMock(
            return_value={"success": True, "type": "text", "text": text, "sha256": text_sha}
        )

        # Copy 1
        await self.ws_server._broadcast_clipboard_update()
        # Immediate poll inside debounce (0.35s) -> suppressed
        await self.ws_server._broadcast_clipboard_update()
        self.assertEqual(len([m for m in self.cli_b.parsed() if m.payload.get("action") == "clipboard_push"]), 1)

        # Wait past 0.35s debounce -> intentional repeat copy emits seq 2 & new event_id!
        await asyncio.sleep(0.42)
        await self.ws_server._broadcast_clipboard_update()
        pushes = [m for m in self.cli_b.parsed() if m.payload.get("action") == "clipboard_push"]
        self.assertEqual(len(pushes), 2)
        self.assertEqual(pushes[0].payload["data"]["seq"], 1)
        self.assertEqual(pushes[1].payload["data"]["seq"], 2)
        self.assertNotEqual(pushes[0].payload["data"]["event_id"], pushes[1].payload["data"]["event_id"])

        # MCP 54-tool count & multi-format metadata check
        bridge = SnowMcpBridge(auto_start_core=False)
        bridge.capability_engine = self.engine
        mcp = create_snow_mcp_server(bridge)
        tools = await mcp.list_tools()
        self.assertEqual(len(tools), 60)
        self.cb_buf.add_files([{"name": "mcp_doc.txt", "data": b"mcp-body"}], source_device_id="desktop_windows")
        list_res = await bridge.clipboard_buffer_list(limit=15)
        self.assertTrue(list_res["success"])
        self.assertEqual(list_res["data"]["items"][0]["content_type"], "file")
        self.assertNotIn("stored_filename", json.dumps(list_res["data"]["items"][0]))


if __name__ == "__main__":
    unittest.main()
