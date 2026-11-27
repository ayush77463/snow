"""Unit & regression tests for SNOW M4.2 Section 2 (M4.1 Carry-Forward Fixes)."""

from __future__ import annotations

import asyncio
import errno
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from aiohttp import FormData
from aiohttp.test_utils import AioHTTPTestCase

from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferDirection, TransferManager, TransferState
from snow.transfer.storage import TransferStorageManager, finalize_staged_file
from snow.web.server import SnowWebServer


class TestM42TransferManagerStateAndHandoff(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m42_cf_"))
        self.db = DatabaseManager(self.tmp_dir / "snow.db")
        self.cfg = CoreConfig(
            auth_required=False,
            transfer_root=str(self.tmp_dir / "transfers"),
            ipc_secret_path=str(self.tmp_dir / "ipc.secret"),
        )
        self.sm = TransferStorageManager(root_dir=self.tmp_dir / "transfers")
        self.tm = TransferManager()
        self.phone_id = str(uuid.uuid4())
        self.db.insert_paired_device(
            self.phone_id,
            "Phone CF",
            auth_token_hash=hashlib.sha256(b"tok").hexdigest(),
            role="peer",
        )
        self.session_mgr = SimpleNamespace(
            get_session_by_device=lambda dev_id: SimpleNamespace(connection_id="conn-1")
            if dev_id == self.phone_id
            else None
        )
        self.conn_mgr = SimpleNamespace(
            get=lambda cid: SimpleNamespace(is_active=True) if cid == "conn-1" else None
        )
        self.ws_srv = MagicMock()
        self.core_mock = SimpleNamespace(
            db_manager=self.db,
            config=self.cfg,
            transfer_manager=self.tm,
            storage_manager=self.sm,
            http_transfer_server=SimpleNamespace(bound_port=8766),
            ws_server=self.ws_srv,
            session_manager=self.session_mgr,
            connection_manager=self.conn_mgr,
            windows_files=SimpleNamespace(
                resolve_safe_path=lambda p, must_exist=True: (Path(p).resolve(), None)
            ),
        )
        self.ipc = SnowIpcServer(self.core_mock, self.cfg)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_terminal_transitions_are_strictly_once_only(self) -> None:
        rec = self.tm.create_transfer(
            device_id=self.phone_id,
            file_name="a.bin",
            file_size=128,
            sha256="a" * 64,
            direction=TransferDirection.DOWNLOAD,
        )
        self.assertTrue(self.tm.update_offset(rec.transfer_id, 64))
        self.assertTrue(self.tm.mark_completed(rec.transfer_id))
        self.assertFalse(self.tm.mark_failed(rec.transfer_id, "late failure ignored"))
        self.assertFalse(self.tm.mark_completed(rec.transfer_id))
        self.assertFalse(self.tm.cancel_transfer(rec.transfer_id, self.phone_id))
        self.assertFalse(self.tm.update_offset(rec.transfer_id, 10))
        self.assertEqual(rec.status, TransferState.COMPLETED)

        rec2 = self.tm.create_transfer(
            device_id=self.phone_id,
            file_name="b.bin",
            file_size=128,
            sha256="b" * 64,
            direction=TransferDirection.DOWNLOAD,
        )
        self.assertTrue(self.tm.mark_failed(rec2.transfer_id, "boom"))
        self.assertFalse(self.tm.mark_completed(rec2.transfer_id))
        self.assertFalse(self.tm.mark_failed(rec2.transfer_id, "second boom"))
        self.assertEqual(rec2.status, TransferState.FAILED)
        self.assertEqual(rec2.error_message, "boom")

    async def test_bg_async_dispatch_success_failure_and_injected_exception(self) -> None:
        # Wrap a strict spec around TransferManager so any invalid method call raises AttributeError
        strict_tm = MagicMock(spec=TransferManager)
        backing_tm = TransferManager()
        strict_tm.list_transfers_for_device.side_effect = backing_tm.list_transfers_for_device
        strict_tm.create_transfer.side_effect = backing_tm.create_transfer
        strict_tm.update_offset.side_effect = backing_tm.update_offset
        strict_tm.mark_completed.side_effect = backing_tm.mark_completed
        strict_tm.mark_failed.side_effect = backing_tm.mark_failed
        strict_tm.cancel_transfer.side_effect = backing_tm.cancel_transfer
        strict_tm.get_transfer.side_effect = backing_tm.get_transfer
        strict_tm.get_transfer_for_device.side_effect = backing_tm.get_transfer_for_device
        # Deliberately delete legacy alias on strict mock to verify canonical mark_* calls
        del strict_tm.fail_transfer
        del strict_tm.complete_transfer
        self.core_mock.transfer_manager = strict_tm

        f1 = self.tmp_dir / "ok.bin"
        f1.write_bytes(b"ok-data")
        self.ws_srv.send_request = AsyncMock(
            return_value=SimpleNamespace(
                type="response",
                payload={"status": "success", "data": {"status": "COMPLETED"}},
                error=None,
            )
        )
        r_ok = await self.ipc._handle_android_file_send(
            {"device_id": self.phone_id, "file_path": str(f1), "async_transfer": True}
        )
        self.assertTrue(r_ok["success"])
        task_ok = self.ipc._async_transfer_tasks.get(r_ok["transfer_id"])
        if task_ok:
            await task_ok
        self.assertEqual(backing_tm.get_transfer(r_ok["transfer_id"]).status, TransferState.COMPLETED)

        f2 = self.tmp_dir / "reject.bin"
        f2.write_bytes(b"rej-data")
        self.ws_srv.send_request = AsyncMock(
            return_value=SimpleNamespace(
                type="error",
                payload=None,
                error={"code": "REJECTED", "message": "User declined"},
            )
        )
        r_fail = await self.ipc._handle_android_file_send(
            {"device_id": self.phone_id, "file_path": str(f2), "async_transfer": True}
        )
        task_fail = self.ipc._async_transfer_tasks.get(r_fail["transfer_id"])
        if task_fail:
            await task_fail
        rec_fail = backing_tm.get_transfer(r_fail["transfer_id"])
        self.assertEqual(rec_fail.status, TransferState.FAILED)
        self.assertIn("declined", rec_fail.error_message.lower())

        f3 = self.tmp_dir / "exc.bin"
        f3.write_bytes(b"exc-data")
        self.ws_srv.send_request = AsyncMock(side_effect=RuntimeError("socket boom"))
        r_exc = await self.ipc._handle_android_file_send(
            {"device_id": self.phone_id, "file_path": str(f3), "async_transfer": True}
        )
        task_exc = self.ipc._async_transfer_tasks.get(r_exc["transfer_id"])
        if task_exc:
            await task_exc
        rec_exc = backing_tm.get_transfer(r_exc["transfer_id"])
        self.assertEqual(rec_exc.status, TransferState.FAILED)
        self.assertIn("socket boom", rec_exc.error_message)

    async def test_staged_handoff_reuses_sha256_avoids_rehash_and_returns_promptly(self) -> None:
        stage_dir = Path(tempfile.gettempdir()) / "snow_web_uploads"
        stage_dir.mkdir(parents=True, exist_ok=True)
        staged = stage_dir / f"handoff_{uuid.uuid4().hex[:8]}.bin"
        payload_bytes = b"M42-SINGLE-HASH-" * 512
        staged.write_bytes(payload_bytes)
        expected_sha = hashlib.sha256(payload_bytes).hexdigest()
        self.addCleanup(lambda: staged.unlink(missing_ok=True))

        self.ws_srv.send_request = AsyncMock(
            return_value=SimpleNamespace(
                type="response",
                payload={"status": "success", "data": {"status": "COMPLETED"}},
                error=None,
            )
        )

        with patch("snow.transfer.storage.compute_stream_sha256", side_effect=AssertionError("Must not re-hash!")) as no_hash:
            t0 = asyncio.get_running_loop().time()
            acc = await self.ipc._handle_android_file_send(
                {
                    "device_id": self.phone_id,
                    "file_path": str(staged),
                    "file_name": "clean_name.bin",
                    "precomputed_sha256": expected_sha,
                    "precomputed_size": len(payload_bytes),
                    "staged_handoff": True,
                    "async_transfer": True,
                }
            )
            elapsed = asyncio.get_running_loop().time() - t0
            self.assertLess(elapsed, 0.5)
            self.assertTrue(acc["success"])
            self.assertEqual(acc["status"], "ACCEPTED")
            self.assertEqual(acc["sha256"], expected_sha)
            no_hash.assert_not_called()

            task = self.ipc._async_transfer_tasks.get(acc["transfer_id"])
            if task:
                await task

        dest = self.sm.resolve_destination_path("clean_name.bin")
        self.assertTrue(dest.is_file())
        self.assertEqual(dest.read_bytes(), payload_bytes)
        self.assertFalse(staged.exists())

    def test_finalize_staged_file_atomic_exdev_and_failure_preserves_source(self) -> None:
        src = self.tmp_dir / "src_stage.bin"
        dest_dir = self.tmp_dir / "dest"
        dest_dir.mkdir()
        body = os.urandom(200_000)
        src.write_bytes(body)
        sha = hashlib.sha256(body).hexdigest()

        # 1) Same-volume atomic move
        dest1 = dest_dir / "same_vol.bin"
        with patch("snow.transfer.storage.stream_copy_file", side_effect=AssertionError("Should use os.replace")):
            method, got_sha = finalize_staged_file(src, dest1, precomputed_sha256=sha, remove_source=True)
        self.assertEqual(method, "atomic_move")
        self.assertEqual(got_sha, sha)
        self.assertFalse(src.exists())
        self.assertEqual(dest1.read_bytes(), body)

        # 2) EXDEV cross-volume fallback copies in bounded chunks then unlinks source
        dest2 = dest_dir / "cross_vol.bin"
        real_replace = os.replace
        with patch("snow.transfer.storage.os.replace") as mock_rep:
            calls = {"n": 0}

            def _exdev_first(a, b):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise OSError(errno.EXDEV, "Invalid cross-device link")
                return real_replace(a, b)

            mock_rep.side_effect = _exdev_first
            method2, got_sha2 = finalize_staged_file(dest1, dest2, precomputed_sha256=sha, remove_source=True)
        self.assertEqual(method2, "stream_copy")
        self.assertEqual(got_sha2, sha)
        self.assertFalse(dest1.exists())
        self.assertEqual(dest2.read_bytes(), body)

        # 3) Failure during cross-volume copy NEVER deletes the source file
        dest3 = dest_dir / "fail_vol.bin"
        with patch("snow.transfer.storage.stream_copy_file", side_effect=OSError("disk full")), \
             patch("snow.transfer.storage.os.replace", side_effect=OSError(errno.EXDEV, "cross")):
            with self.assertRaises(OSError):
                finalize_staged_file(dest2, dest3, precomputed_sha256=sha, remove_source=True)
        self.assertTrue(dest2.exists())
        self.assertFalse(dest3.exists())
        self.assertEqual(self.sm.cleanup_stale_parts(max_age_seconds=0.0, active_transfer_ids=set()), 0)


class TestM42WebUploadStagedHandoff(AioHTTPTestCase):
    async def asyncSetUp(self) -> None:
        self._prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m42_web_up_"))
        os.environ["SNOW_DATA_DIR"] = str(self.tmp_dir)
        self.received_calls: list[dict] = []
        self.next_response: dict = {"success": True, "status": "ACCEPTED", "transfer_id": "tx-web-1"}

        outer = self

        class _DummyBridge:
            async def android_file_send_async(self, **kwargs):
                outer.received_calls.append(dict(kwargs))
                return dict(outer.next_response)

            async def android_file_send(self, **kwargs):
                outer.received_calls.append(dict(kwargs))
                return dict(outer.next_response)

            def is_core_connected(self) -> bool:
                return True

        self.dummy_bridge = _DummyBridge()
        await super().asyncSetUp()
        self.web_srv.port = self.server.port

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        if self._prev_data_dir is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self._prev_data_dir
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def get_application(self):
        self.web_srv = SnowWebServer(
            host="127.0.0.1",
            port=0,
            bridge=self.dummy_bridge,
            auto_open_browser=False,
        )
        return self.web_srv._build_app()

    async def test_web_upload_staged_handoff_preserves_file_and_cleans_on_error(self) -> None:
        auth_resp = await self.client.post(
            "/api/auth/session",
            json={"token": self.web_srv.bootstrap_token},
        )
        self.assertEqual(auth_resp.status, 200)
        csrf = (await auth_resp.json())["csrf_token"]

        payload = b"SNOW-WEB-UPLOAD-HANDOFF-" * 2048
        expected_sha = hashlib.sha256(payload).hexdigest()
        device_id = str(uuid.uuid4())

        # 1) ACCEPTED handoff forwards precomputed digest/size + staged_handoff=True and avoids deletion by WebServer
        form1 = FormData()
        form1.add_field("file", payload, filename="handoff_movie.bin", content_type="application/octet-stream")
        resp1 = await self.client.post(
            f"/api/files/upload?device_id={device_id}&async=1&sha256={expected_sha}",
            data=form1,
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(resp1.status, 202)
        body1 = await resp1.json()
        self.assertTrue(body1.get("success"))
        self.assertEqual(len(self.received_calls), 1)
        call1 = self.received_calls[0]
        self.assertTrue(call1["staged_handoff"])
        self.assertEqual(call1["precomputed_sha256"], expected_sha)
        self.assertEqual(call1["precomputed_size"], len(payload))
        self.assertEqual(call1["file_name"], "handoff_movie.bin")
        staged_path = Path(call1["file_path"])
        try:
            self.assertTrue(staged_path.is_file(), "Web server must leave staged file intact for Core background move")
        finally:
            staged_path.unlink(missing_ok=True)

        # 2) Rejected handoff cleans up staged file immediately
        self.next_response = {"success": False, "status": "ERROR", "error": "Device offline"}
        form2 = FormData()
        form2.add_field("file", payload, filename="failed_handoff.bin", content_type="application/octet-stream")
        resp2 = await self.client.post(
            f"/api/files/upload?device_id={device_id}&async=1",
            data=form2,
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(resp2.status, 500)
        staged_path_2 = Path(self.received_calls[1]["file_path"])
        self.assertFalse(staged_path_2.exists(), "Staged file must be cleaned up when Core handoff fails")
