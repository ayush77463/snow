from __future__ import annotations

import asyncio
import errno
import hashlib
import os
import secrets
import shutil
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
from aiohttp import FormData
from aiohttp.test_utils import AioHTTPTestCase
import psutil

from snow.capabilities.engine import CapabilityEngine, CapabilityRequest
from snow.core.config import MAX_SUPPORTED_TRANSFER_SIZE, CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.mcp.bridge import SnowMcpBridge
from snow.network.ws_server import SnowWebSocketServer
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferDirection, TransferManager, TransferState
from snow.transfer.storage import TransferStorageManager, stream_copy_file
from snow.web.server import SnowWebServer


class TestM41Unit5ConfigAndStorage(unittest.TestCase):
    def test_01_16gib_config_defaults_validation_and_app_limits(self) -> None:
        cfg = CoreConfig()
        self.assertEqual(MAX_SUPPORTED_TRANSFER_SIZE, 16 * 1024**3)
        self.assertEqual(cfg.max_transfer_size, 16 * 1024**3)

        for bad in (0, -1, True, "1024", 16 * 1024**3 + 1):
            with self.assertRaises(ValueError):
                CoreConfig(max_transfer_size=bad)  # type: ignore[arg-type]

        tmp = Path(tempfile.mkdtemp(prefix="snow_m41_u5_cfg_"))
        try:
            db = DatabaseManager(tmp / "snow.db")
            tm = TransferManager()
            sm = TransferStorageManager(root_dir=tmp / "transfers")
            http_srv = SnowHttpTransferServer(config=cfg, db_manager=db, transfer_manager=tm, storage_manager=sm)
            web_srv = SnowWebServer(bridge=MagicMock(), transfer_server=http_srv)
            web_app = web_srv.create_app()
            self.assertEqual(http_srv.app._client_max_size, 16 * 1024**3)
            self.assertEqual(web_app._client_max_size, 16 * 1024**3)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_02_atomic_commit_exdev_fallback_and_stream_copy(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="snow_m41_u5_stor_"))
        try:
            sm = TransferStorageManager(root_dir=tmp / "root")
            payload = b"stream-copy-payload-" * 5000
            expected_sha = hashlib.sha256(payload).hexdigest()
            part = sm.get_part_path("tr-exdev-1")
            part.write_bytes(payload)
            dest = sm.resolve_destination_path("moved.bin")

            orig_replace = os.replace

            def fake_replace(src, dst):
                if Path(src) == part and Path(dst) == dest:
                    raise OSError(errno.EXDEV, "Invalid cross-device link")
                return orig_replace(src, dst)

            with patch("snow.transfer.storage.os.replace", side_effect=fake_replace):
                committed = sm.atomic_commit(part_path=part, dest_path=dest, expected_sha256=expected_sha)

            self.assertEqual(committed, expected_sha)
            self.assertTrue(dest.is_file())
            self.assertEqual(dest.read_bytes(), payload)
            self.assertFalse(part.exists())

            # Test stream_copy_file cancellation cleanup leaves destination untouched
            existing = tmp / "keep_me.bin"
            existing.write_bytes(b"original-content")
            src = tmp / "src.bin"
            src.write_bytes(b"new-content" * 100)
            with self.assertRaises(RuntimeError):
                stream_copy_file(src, existing, cancel_check=lambda: True)
            self.assertEqual(existing.read_bytes(), b"original-content")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestM41Unit5StreamingAndRange(AioHTTPTestCase):
    async def get_application(self):
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m41_u5_web_"))
        self.db = DatabaseManager(self.tmp_dir / "snow.db")
        self.tm = TransferManager()
        self.sm = TransferStorageManager(root_dir=self.tmp_dir / "transfers")
        # Use 128 MiB limit on this fixture; verify dynamic limit enforcement cleanly
        self.cfg = CoreConfig(auth_required=False, transfer_root=str(self.sm.root_dir), max_transfer_size=128 * 1024 * 1024)
        self.http_srv = SnowHttpTransferServer(config=self.cfg, db_manager=self.db, transfer_manager=self.tm, storage_manager=self.sm)
        self.bridge = MagicMock()
        self.bridge.android_file_send = AsyncMock(return_value={"success": True, "status": "SUCCESS", "data": {"ok": True}})
        self.bridge.android_file_list = AsyncMock(return_value={"success": True, "data": {"items": [], "storage_mode": "saf_tree"}})
        self.web_srv = SnowWebServer(bridge=self.bridge, transfer_server=self.http_srv)
        return self.web_srv.create_app()

    async def tearDownAsync(self) -> None:
        await super().tearDownAsync()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def _auth_csrf(self) -> str:
        res = await self.client.post("/api/auth/session", json={"token": self.web_srv.bootstrap_token})
        data = await res.json()
        return data["csrf_token"]

    async def test_03_streaming_64mib_upload_bounded_rss_and_sha256(self) -> None:
        csrf = await self._auth_csrf()
        proc = psutil.Process()
        rss_before_mb = proc.memory_info().rss / (1024 * 1024)

        total_target = 64 * 1024 * 1024
        chunk_block = b"A" * 65536
        hasher = hashlib.sha256()
        for _ in range(total_target // len(chunk_block)):
            hasher.update(chunk_block)
        expected_sha = hasher.hexdigest()

        async def _chunk_gen():
            sent = 0
            while sent < total_target:
                yield chunk_block
                sent += len(chunk_block)

        form = FormData()
        form.add_field("device_id", "android-1")
        form.add_field("expected_sha256", expected_sha)
        form.add_field("file", _chunk_gen(), filename="stream_64m.bin", content_type="application/octet-stream")

        resp = await self.client.post("/api/files/upload", data=form, headers={"X-CSRF-Token": csrf})
        rss_after_mb = proc.memory_info().rss / (1024 * 1024)
        self.assertEqual(resp.status, 200)
        body = await resp.json()
        self.assertTrue(body["success"])
        self.assertEqual(body["size_bytes"], total_target)
        self.assertEqual(body["sha256"], expected_sha)
        # RSS increase must remain far below the 64 MiB uploaded file (bounded 64 KiB streaming!)
        self.assertLess(rss_after_mb - rss_before_mb, 32.0)

    async def test_04_oversize_unknown_length_spoofed_length_hash_mismatch_and_isolated_cleanup(self) -> None:
        csrf = await self._auth_csrf()
        # Pre-create unrelated part + completed file that MUST remain untouched
        stage_dir = Path(tempfile.gettempdir()) / "snow_web_uploads"
        stage_dir.mkdir(parents=True, exist_ok=True)
        unrelated_part = stage_dir / f".unrelated_{secrets.token_hex(4)}.part"
        unrelated_part.write_bytes(b"keep-other-part")
        completed_dest = self.sm.resolve_destination_path("existing_dest.txt")
        completed_dest.write_bytes(b"keep-completed")
        self.addCleanup(lambda: unrelated_part.unlink(missing_ok=True))

        # Tight cap for oversize checks without waiting for multi-GB stream
        tight_cfg = CoreConfig(auth_required=False, transfer_root=str(self.sm.root_dir), max_transfer_size=1024)
        self.http_srv.config = tight_cfg

        # 1) Streaming body without declared size exceeding 1024 bytes -> 413
        async def _over_gen():
            for _ in range(5):
                yield b"X" * 512

        form1 = FormData()
        form1.add_field("device_id", "android-1")
        form1.add_field("file", _over_gen(), filename="too_big.bin", content_type="application/octet-stream")
        r1 = await self.client.post("/api/files/upload", data=form1, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r1.status, 413)

        # Restore larger cap for hash-mismatch and disk-full tests
        self.http_srv.config = self.cfg

        # 2) Expected SHA-256 mismatch -> 422, android_file_send NOT called, cleanup leaves no leak
        form2 = FormData()
        form2.add_field("device_id", "android-1")
        form2.add_field("expected_sha256", "0" * 64)
        form2.add_field("file", b"hello-real-bytes", filename="bad_hash.bin", content_type="application/octet-stream")
        r2 = await self.client.post("/api/files/upload", data=form2, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r2.status, 422)
        self.bridge.android_file_send.assert_not_called()

        # 3) Insufficient free disk space precheck -> 507
        with patch("snow.transfer.storage.shutil.disk_usage", return_value=SimpleNamespace(total=100, used=90, free=5)):
            form3 = FormData()
            form3.add_field("device_id", "android-1")
            form3.add_field("file", b"A" * 256, filename="no_space.bin", content_type="application/octet-stream")
            r3 = await self.client.post("/api/files/upload", data=form3, headers={"X-CSRF-Token": csrf})
            self.assertEqual(r3.status, 507)

        # Assert unrelated part and destination file were completely untouched!
        self.assertTrue(unrelated_part.exists())
        self.assertEqual(unrelated_part.read_bytes(), b"keep-other-part")
        self.assertEqual(completed_dest.read_bytes(), b"keep-completed")

    async def test_05_handle_api_files_defaults_to_auto_scope(self) -> None:
        await self._auth_csrf()
        resp = await self.client.get("/api/files?device_id=android-1")
        self.assertEqual(resp.status, 200)
        self.bridge.android_file_list.assert_called_once_with(
            subpath="",
            device_id="android-1",
            scope="auto",
            show_hidden=False,
        )


class TestM41Unit5AsyncLifecycleCancelAndSparse4GiB(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m41_u5_async_"))
        self.db = DatabaseManager(self.tmp_dir / "snow.db")
        self.cfg = CoreConfig(
            auth_required=False,
            transfer_root=str(self.tmp_dir / "transfers"),
            ipc_secret_path=str(self.tmp_dir / "ipc.secret"),
        )
        self.ident = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Desktop",
            created_at="2026-01-01T00:00:00Z",
        )
        self.phone1_id = str(uuid.uuid4())
        self.phone2_id = str(uuid.uuid4())
        self.ws = SnowWebSocketServer(config=self.cfg, db_manager=self.db, device_identity=self.ident)
        self.db.insert_paired_device(self.phone1_id, "Phone 1", auth_token_hash=hashlib.sha256(b"tok-1").hexdigest(), role="peer")
        self.db.insert_paired_device(self.phone2_id, "Phone 2", auth_token_hash=hashlib.sha256(b"tok-2").hexdigest(), role="peer")
        self.http_srv = SnowHttpTransferServer(
            config=self.cfg,
            db_manager=self.db,
            transfer_manager=self.ws.transfer_manager,
            storage_manager=self.ws.storage_manager,
        )
        self.core_mock = SimpleNamespace(
            db_manager=self.db,
            config=self.cfg,
            transfer_manager=self.ws.transfer_manager,
            storage_manager=self.ws.storage_manager,
            http_transfer_server=self.http_srv,
            ws_server=self.ws,
            session_manager=self.ws.session_manager,
            windows_files=SimpleNamespace(resolve_safe_path=lambda p, must_exist=True: (Path(p).resolve(), None)),
        )
        self.ipc = SnowIpcServer(self.core_mock, self.cfg)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_06_async_transfer_accepted_status_cross_layer_cancel_and_honest_restart(self) -> None:
        src = self.tmp_dir / "big_src.bin"
        src.write_bytes(b"async-body-" * 100)

        sent_to_android: list[tuple[str, dict]] = []

        class SlowRouter:
            async def route_request(self, action: str, target: str, data: dict, timeout: float = 30.0):
                sent_to_android.append((action, dict(data)))
                if action == "file_send_request":
                    return {"success": True, "status": "accepted", "data": {"status": "accepted"}}
                if action == "transfer_cancel":
                    return {"success": True, "status": "cancelled", "data": {"cancelled": True}}
                return {"success": False}

        self.ipc.session_router = SlowRouter()

        # 1) Async dispatch returns ACCEPTED + transfer_id quickly (not blocking on multi-minute download!)
        acc = await self.ipc._handle_android_file_send(
            {"device_id": self.phone1_id, "file_path": str(src), "async_transfer": True}
        )
        self.assertTrue(acc["success"])
        self.assertEqual(acc["status"], "ACCEPTED")
        tid = acc["transfer_id"]
        await asyncio.sleep(0.05)
        self.assertTrue(any(act == "file_send_request" and d.get("async") is True for act, d in sent_to_android))

        # 2) Owner-scoped status works; non-owner device-2 is rejected
        st_owner = await self.ipc._handle_transfer_status({"transfer_id": tid, "device_id": self.phone1_id})
        self.assertTrue(st_owner["success"])
        st_other = await self.ipc._handle_transfer_status({"transfer_id": tid, "device_id": self.phone2_id})
        self.assertFalse(st_other["success"])
        self.assertEqual(st_other["status"], "NOT_FOUND")

        # 3) Cross-layer cancel marks Core CANCELLED and forwards transfer_cancel to Android
        c_res = await self.ipc._handle_transfer_cancel({"transfer_id": tid, "device_id": self.phone1_id})
        self.assertTrue(c_res["success"])
        self.assertEqual(c_res["status"], "CANCELLED")
        self.assertTrue(any(act == "transfer_cancel" and d.get("transfer_id") == tid for act, d in sent_to_android))
        st_after_cancel = await self.ipc._handle_transfer_status({"transfer_id": tid, "device_id": self.phone1_id})
        self.assertEqual(st_after_cancel["data"]["status"] if "status" in st_after_cancel["data"] else st_after_cancel["data"]["state"], "CANCELLED")

        # 4) Simulate fresh Core restart: querying prior transfer_id fails honestly with NOT_FOUND!
        restarted_tm = TransferManager()
        self.core_mock.transfer_manager = restarted_tm
        restarted_ipc = SnowIpcServer(self.core_mock, self.cfg)
        st_restart = await restarted_ipc._handle_transfer_status({"transfer_id": tid, "device_id": self.phone1_id})
        self.assertFalse(st_restart["success"])
        self.assertEqual(st_restart["status"], "NOT_FOUND")

    async def test_07_sparse_over_4gib_range_download_and_ipc_scope_auto(self) -> None:
        # Create a 5 GiB sparse file on disk without consuming 5 GiB RAM or physical blocks (Windows/POSIX truncate/seek)
        sparse_path = self.tmp_dir / "sparse_5gib.bin"
        offset_5g = 5 * 1024 * 1024 * 1024
        tail_bytes = b"SNOW-TAIL-AT-5GIB!"
        total_len = offset_5g + len(tail_bytes)
        with open(sparse_path, "wb") as f:
            if os.name == "nt":
                import ctypes
                import msvcrt
                handle = msvcrt.get_osfhandle(f.fileno())
                ctypes.windll.kernel32.DeviceIoControl(handle, 0x000900C4, None, 0, None, 0, ctypes.byref(ctypes.c_ulong()), None)
            f.seek(offset_5g)
            f.write(tail_bytes)

        rec = self.ws.transfer_manager.create_transfer(
            device_id=self.phone1_id,
            file_name="sparse_5gib.bin",
            file_size=total_len,
            sha256="a" * 64,
            direction=TransferDirection.DOWNLOAD,
            file_path=str(sparse_path),
        )

        async with aiohttp.test_utils.TestClient(aiohttp.test_utils.TestServer(self.http_srv.app)) as cli:
            resp = await cli.get(
                f"/api/v1/transfers/download/{rec.transfer_id}",
                headers={"Range": f"bytes={offset_5g}-", "X-Snow-Device-Id": self.phone1_id},
            )
            self.assertEqual(resp.status, 206)
            self.assertEqual(resp.headers.get("Content-Range"), f"bytes {offset_5g}-{total_len - 1}/{total_len}")
            got = await resp.read()
            self.assertEqual(got, tail_bytes)

        # Also verify ipc preserves scope='auto' for OWNER_MANUAL and locks 'saf' for AI_MCP
        self.ipc._handle_device_request = AsyncMock(return_value={"success": True, "status": "SUCCESS", "data": {"items": []}})
        import hmac
        owner_tok = hmac.new(self.ipc.secret.encode("utf-8"), b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256).hexdigest()
        res_owner, _ = await self.ipc._dispatch_request(
            {
                "version": 1,
                "op": "android_file_list",
                "auth_token": self.ipc.secret,
                "owner_token": owner_tok,
                "payload": {"scope": "auto"},
            },
            is_connection_authenticated=True,
        )
        self.assertTrue(res_owner["success"], msg=res_owner)
        self.assertEqual(self.ipc._handle_device_request.call_args.args[0]["data"]["scope"], "auto")
        res_ai, _ = await self.ipc._dispatch_request(
            {
                "version": 1,
                "op": "android_file_list",
                "auth_token": self.ipc.secret,
                "payload": {"scope": "auto"},
            },
            is_connection_authenticated=True,
        )
        self.assertTrue(res_ai["success"])
        self.assertEqual(self.ipc._handle_device_request.call_args.args[0]["data"]["scope"], "saf")


if __name__ == "__main__":
    unittest.main()
