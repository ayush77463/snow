"""Tests for Phase 3: Reliable Bidirectional File Transfer Subsystem (3.1 - 3.4).

Covers:
- 3.1 Authenticated HTTP streaming & path traversal protection
- 3.2 Streaming SHA-256 integrity verification & corrupt payload rejection
- 3.3 Interrupted transfer handling, .part file lifecycle & stale cleanup
- 3.4 Resumable uploads/downloads & duplicate detection
- WebSocket transfer coordination messages (offer, list, status, cancel)
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import aiohttp

from snow.core.config import CoreConfig
from snow.security.db import DatabaseManager, hash_token
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferDirection, TransferManager, TransferState
from snow.transfer.storage import (
    CHUNK_SIZE,
    TransferStorageManager,
    compute_stream_sha256,
    sanitize_filename,
)


class TestTransferStorage(unittest.TestCase):
    """Unit tests for TransferStorageManager and filename sanitization."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.storage = TransferStorageManager(root_dir=self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_sanitize_filename_valid(self) -> None:
        self.assertEqual(sanitize_filename("photo.jpg"), "photo.jpg")
        self.assertEqual(sanitize_filename("document-v1.2.pdf"), "document-v1.2.pdf")

    def test_sanitize_filename_strips_path(self) -> None:
        self.assertEqual(sanitize_filename("../../../etc/passwd"), "passwd")
        self.assertEqual(sanitize_filename("C:\\Windows\\System32\\calc.exe"), "calc.exe")

    def test_sanitize_filename_rejects_empty_or_reserved(self) -> None:
        with self.assertRaises(ValueError):
            sanitize_filename("")
        with self.assertRaises(ValueError):
            sanitize_filename("..")
        with self.assertRaises(ValueError):
            sanitize_filename("CON")

    def test_resolve_destination_path_contained(self) -> None:
        dest = self.storage.resolve_destination_path("test_file.txt")
        self.assertTrue(dest.is_relative_to(self.storage.root_dir))
        self.assertEqual(dest.name, "test_file.txt")

    def test_part_path_generation(self) -> None:
        part = self.storage.get_part_path("test-transfer-123")
        self.assertTrue(part.is_relative_to(self.storage.parts_dir))
        self.assertEqual(part.name, "test-transfer-123.part")

    def test_duplicate_detection(self) -> None:
        content = b"SNOW file content for testing duplicate detection"
        expected_hash = hashlib.sha256(content).hexdigest()
        file_path = Path(self.temp_dir) / "sample.txt"
        file_path.write_bytes(content)

        # Exact match
        exists, conflict, existing_hash = self.storage.check_duplicate("sample.txt", expected_hash)
        self.assertTrue(exists)
        self.assertFalse(conflict)
        self.assertEqual(existing_hash, expected_hash)

        # Hash conflict
        diff_hash = hashlib.sha256(b"different content").hexdigest()
        exists, conflict, existing_hash = self.storage.check_duplicate("sample.txt", diff_hash)
        self.assertFalse(exists)
        self.assertTrue(conflict)
        self.assertEqual(existing_hash, expected_hash)

        # File does not exist
        exists, conflict, existing_hash = self.storage.check_duplicate("non_existent.txt", expected_hash)
        self.assertFalse(exists)
        self.assertFalse(conflict)
        self.assertIsNone(existing_hash)

    def test_atomic_commit_success(self) -> None:
        content = b"Hello, SNOW Phase 3 file transfer!"
        sha256 = hashlib.sha256(content).hexdigest()

        part_path = self.storage.get_part_path("test-commit")
        part_path.write_bytes(content)

        dest_path = self.storage.resolve_destination_path("committed.txt")
        verified_hash = self.storage.atomic_commit(part_path, dest_path, sha256)

        self.assertEqual(verified_hash, sha256)
        self.assertTrue(dest_path.exists())
        self.assertFalse(part_path.exists())
        self.assertEqual(dest_path.read_bytes(), content)

    def test_atomic_commit_mismatch_removes_part(self) -> None:
        content = b"Corrupted content"
        wrong_hash = hashlib.sha256(b"Expected different content").hexdigest()

        part_path = self.storage.get_part_path("test-mismatch")
        part_path.write_bytes(content)

        dest_path = self.storage.resolve_destination_path("corrupt.txt")
        with self.assertRaises(ValueError):
            self.storage.atomic_commit(part_path, dest_path, wrong_hash)

        self.assertFalse(dest_path.exists())
        self.assertFalse(part_path.exists())  # Part file must be cleaned up on mismatch


class TestHttpTransferServer(unittest.IsolatedAsyncioTestCase):
    """End-to-end integration tests for SnowHttpTransferServer."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_devices.db"
        self.db_manager = DatabaseManager(db_path=self.db_path)
        self.storage_manager = TransferStorageManager(root_dir=Path(self.temp_dir) / "transfers")
        self.transfer_manager = TransferManager()

        self.config = CoreConfig(
            port=8765,
            transfer_port=0,  # Ephemeral port
            bind_host="127.0.0.1",
            auth_required=True,
            transfer_root=str(self.storage_manager.root_dir),
        )

        self.server = SnowHttpTransferServer(
            config=self.config,
            db_manager=self.db_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
            ssl_context=None,
        )
        await self.server.start()
        self.base_url = f"http://127.0.0.1:{self.server.bound_port}"

        # Register a paired test device
        self.test_device_id = "test-android-device-1"
        self.raw_token = "snow_auth_secret_token_12345"
        self.db_manager.insert_paired_device(
            device_id=self.test_device_id,
            device_name="Test Android",
            auth_token_hash=hash_token(self.raw_token),
        )

        self.auth_headers = {
            "Authorization": f"Bearer {self.raw_token}",
            "X-Snow-Device-Id": self.test_device_id,
        }

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_auth_middleware_rejects_missing_headers(self) -> None:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/api/v1/transfers") as resp:
                self.assertEqual(resp.status, 401)
                data = await resp.json()
                self.assertIn("error", data)

    async def test_auth_middleware_rejects_invalid_token(self) -> None:
        headers = {
            "Authorization": "Bearer wrong_token_value",
            "X-Snow-Device-Id": self.test_device_id,
        }
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.base_url}/api/v1/transfers", headers=headers) as resp:
                self.assertEqual(resp.status, 401)

    async def test_duplicate_check_endpoint(self) -> None:
        # Pre-create file in storage root
        content = b"Pre-existing payload for duplicate test"
        file_sha256 = hashlib.sha256(content).hexdigest()
        file_path = self.storage_manager.root_dir / "duplicate_target.txt"
        file_path.write_bytes(content)

        async with aiohttp.ClientSession() as session:
            payload = {"file_name": "duplicate_target.txt", "sha256": file_sha256}
            async with session.post(
                f"{self.base_url}/api/v1/transfers/check-duplicate",
                headers=self.auth_headers,
                json=payload,
            ) as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertTrue(data["already_exists"])
                self.assertFalse(data["is_conflict"])
                self.assertEqual(data["existing_sha256"], file_sha256)

    async def test_streaming_upload_and_integrity_verification(self) -> None:
        # Generate 256 KiB test payload (4 x 64 KiB chunks)
        content = b"A" * (256 * 1024)
        file_sha256 = hashlib.sha256(content).hexdigest()
        file_name = "test_large_upload.bin"

        # 1. Initialize transfer
        init_payload = {
            "file_name": file_name,
            "file_size": len(content),
            "sha256": file_sha256,
            "direction": "UPLOAD",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/v1/transfers/init",
                headers=self.auth_headers,
                json=init_payload,
            ) as resp:
                self.assertEqual(resp.status, 200)
                init_data = await resp.json()
                transfer_id = init_data["transfer_id"]

            # 2. Upload file stream
            upload_url = f"{self.base_url}/api/v1/transfers/upload/{transfer_id}"
            async with session.post(
                upload_url,
                headers=self.auth_headers,
                data=content,
            ) as resp:
                self.assertEqual(resp.status, 200)
                upload_data = await resp.json()
                self.assertEqual(upload_data["status"], "COMPLETED")
                self.assertEqual(upload_data["sha256"], file_sha256)

        # 3. Verify file on disk
        dest_path = self.storage_manager.resolve_destination_path(file_name)
        self.assertTrue(dest_path.exists())
        self.assertEqual(dest_path.stat().st_size, len(content))
        self.assertEqual(compute_stream_sha256(dest_path), file_sha256)

    async def test_streaming_upload_corrupt_rejected_with_422(self) -> None:
        content = b"Actual file content sent by client"
        wrong_sha256 = hashlib.sha256(b"Tampered or mismatched digest").hexdigest()
        file_name = "corrupt_upload.bin"

        init_payload = {
            "file_name": file_name,
            "file_size": len(content),
            "sha256": wrong_sha256,
            "direction": "UPLOAD",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/v1/transfers/init",
                headers=self.auth_headers,
                json=init_payload,
            ) as resp:
                self.assertEqual(resp.status, 200)
                init_data = await resp.json()
                transfer_id = init_data["transfer_id"]

            # Upload the mismatched content
            upload_url = f"{self.base_url}/api/v1/transfers/upload/{transfer_id}"
            async with session.post(
                upload_url,
                headers=self.auth_headers,
                data=content,
            ) as resp:
                self.assertEqual(resp.status, 422)
                err_data = await resp.json()
                self.assertIn("error", err_data)

        # Dest file must NOT exist; part file must be cleaned up
        dest_path = self.storage_manager.resolve_destination_path(file_name)
        part_path = self.storage_manager.get_part_path(transfer_id)
        self.assertFalse(dest_path.exists())
        self.assertFalse(part_path.exists())

    async def test_resumable_upload_via_content_range(self) -> None:
        content = b"0123456789" * 1000  # 10,000 bytes
        file_sha256 = hashlib.sha256(content).hexdigest()
        file_name = "resumable_upload.bin"

        init_payload = {
            "file_name": file_name,
            "file_size": len(content),
            "sha256": file_sha256,
            "direction": "UPLOAD",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/v1/transfers/init",
                headers=self.auth_headers,
                json=init_payload,
            ) as resp:
                self.assertEqual(resp.status, 200)
                transfer_id = (await resp.json())["transfer_id"]

            upload_url = f"{self.base_url}/api/v1/transfers/upload/{transfer_id}"

            # Chunk 1: first 4000 bytes
            chunk1 = content[:4000]
            headers1 = {
                **self.auth_headers,
                "Content-Range": f"bytes 0-3999/{len(content)}",
            }
            async with session.post(upload_url, headers=headers1, data=chunk1) as resp:
                self.assertEqual(resp.status, 206)
                data = await resp.json()
                self.assertEqual(data["current_offset"], 4000)

            # Check status endpoint
            status_url = f"{self.base_url}/api/v1/transfers/upload/{transfer_id}/status"
            async with session.get(status_url, headers=self.auth_headers) as resp:
                self.assertEqual(resp.status, 200)
                status_data = await resp.json()
                self.assertEqual(status_data["current_offset"], 4000)

            # Chunk 2: remaining 6000 bytes
            chunk2 = content[4000:]
            headers2 = {
                **self.auth_headers,
                "Content-Range": f"bytes 4000-{len(content)-1}/{len(content)}",
            }
            async with session.post(upload_url, headers=headers2, data=chunk2) as resp:
                self.assertEqual(resp.status, 200)
                data = await resp.json()
                self.assertEqual(data["status"], "COMPLETED")
                self.assertEqual(data["sha256"], file_sha256)

        dest_path = self.storage_manager.resolve_destination_path(file_name)
        self.assertTrue(dest_path.exists())
        self.assertEqual(dest_path.read_bytes(), content)

    async def test_resumable_download_via_http_range(self) -> None:
        content = b"DOWNLOAD_TEST_BYTES_" * 500  # 10,000 bytes
        file_sha256 = hashlib.sha256(content).hexdigest()
        file_name = "test_download.bin"

        dest_path = self.storage_manager.resolve_destination_path(file_name)
        dest_path.write_bytes(content)

        # Register download transfer
        record = self.transfer_manager.create_transfer(
            device_id=self.test_device_id,
            file_name=file_name,
            file_size=len(content),
            sha256=file_sha256,
            direction=TransferDirection.DOWNLOAD,
        )

        download_url = f"{self.base_url}/api/v1/transfers/download/{record.transfer_id}"
        async with aiohttp.ClientSession() as session:
            # 1. Full download
            async with session.get(download_url, headers=self.auth_headers) as resp:
                self.assertEqual(resp.status, 200)
                self.assertEqual(resp.headers.get("Accept-Ranges"), "bytes")
                self.assertEqual(resp.headers.get("X-Snow-SHA256"), file_sha256)
                body = await resp.read()
                self.assertEqual(body, content)

            # 2. Resumed / Range download: bytes=2000-
            range_headers = {**self.auth_headers, "Range": "bytes=2000-"}
            async with session.get(download_url, headers=range_headers) as resp:
                self.assertEqual(resp.status, 206)
                self.assertEqual(
                    resp.headers.get("Content-Range"),
                    f"bytes 2000-{len(content)-1}/{len(content)}",
                )
                range_body = await resp.read()
                self.assertEqual(range_body, content[2000:])


import json
from websockets.asyncio.client import connect
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage


class TestWebSocketTransferCoordination(unittest.IsolatedAsyncioTestCase):
    """Integration tests for WebSocket transfer coordination actions."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_devices.db"
        self.db_manager = DatabaseManager(db_path=self.db_path)
        self.storage_manager = TransferStorageManager(root_dir=Path(self.temp_dir) / "transfers")
        self.transfer_manager = TransferManager()

        # Get an ephemeral port for ws
        import socket
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        ws_port = sock.getsockname()[1]
        sock.close()

        self.config = CoreConfig(
            port=ws_port,
            transfer_port=0,
            bind_host="127.0.0.1",
            auth_required=True,
            tls_enabled=False,
            transfer_root=str(self.storage_manager.root_dir),
        )

        self.ws_server = SnowWebSocketServer(
            config=self.config,
            db_manager=self.db_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
        )
        await self.ws_server.start()

        self.http_server = SnowHttpTransferServer(
            config=self.config,
            db_manager=self.db_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
        )
        self.ws_server.http_transfer_server = self.http_server
        await self.http_server.start()

        self.test_device_id = "test-ws-device-1"
        self.raw_auth_token = "secret_ws_token_xyz"
        self.db_manager.insert_paired_device(
            device_id=self.test_device_id,
            device_name="Test WS Phone",
            auth_token_hash=hash_token(self.raw_auth_token),
        )

        self.ws_url = f"ws://127.0.0.1:{self.ws_server.bound_port}"

    async def asyncTearDown(self) -> None:
        await self.http_server.stop()
        await self.ws_server.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_websocket_file_transfer_coordination_flow(self) -> None:
        async with connect(self.ws_url) as ws:
            # 1. Authenticate session
            auth_req = SnowMessage.create_request(
                action="auth_request",
                data={
                    "device_id": self.test_device_id,
                    "auth_token": self.raw_auth_token,
                },
            )
            await ws.send(auth_req.to_json())
            auth_resp = json.loads(await ws.recv())
            self.assertEqual(auth_resp["type"], "response")
            self.assertEqual(auth_resp["payload"]["status"], "success")

            # 2. Offer file transfer
            offer_req = SnowMessage.create_request(
                action="file_transfer_offer",
                data={
                    "file_name": "ws_test_doc.pdf",
                    "file_size": 10240,
                    "sha256": "a" * 64,
                    "direction": "UPLOAD",
                },
            )
            await ws.send(offer_req.to_json())
            offer_resp = json.loads(await ws.recv())
            self.assertEqual(offer_resp["type"], "response")
            self.assertEqual(offer_resp["payload"]["status"], "success")
            data = offer_resp["payload"]["data"]
            transfer_id = data["transfer_id"]
            self.assertIn("transfer_url", data)
            self.assertEqual(data["resume_offset"], 0)
            self.assertFalse(data["already_exists"])

            # 3. List transfers
            list_req = SnowMessage.create_request(action="file_list_transfers")
            await ws.send(list_req.to_json())
            list_resp = json.loads(await ws.recv())
            self.assertEqual(list_resp["type"], "response")
            transfers = list_resp["payload"]["data"]["transfers"]
            self.assertEqual(len(transfers), 1)
            self.assertEqual(transfers[0]["transfer_id"], transfer_id)

            # 4. Check transfer status
            status_req = SnowMessage.create_request(
                action="file_transfer_status",
                data={"transfer_id": transfer_id},
            )
            await ws.send(status_req.to_json())
            status_resp = json.loads(await ws.recv())
            self.assertEqual(status_resp["type"], "response")
            status_data = status_resp["payload"]["data"]
            self.assertEqual(status_data["transfer_id"], transfer_id)
            self.assertEqual(status_data["status"], "QUEUED")

            # 5. Cancel transfer
            cancel_req = SnowMessage.create_request(
                action="file_transfer_cancel",
                data={"transfer_id": transfer_id},
            )
            await ws.send(cancel_req.to_json())
            cancel_resp = json.loads(await ws.recv())
            self.assertEqual(cancel_resp["type"], "response")
            cancel_data = cancel_resp["payload"]["data"]
            self.assertTrue(cancel_data["cancelled"])


if __name__ == "__main__":
    unittest.main()
