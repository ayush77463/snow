"""Unit tests for Phase 15: Android 17 OS Execution Contract, Permission Matrix & Cross-Device Sync Hardening.

Covers:
1. Live Capability Manifest Updates:
   - NodeRegistry.on_manifest_updated updates in-memory cache and DB
   - WebSocket server handles authenticated manifest_update
   - Unauthenticated or forged manifest_update requests rejected
   - Anti-spoofing authority stripping
2. Idempotent Bidirectional Clipboard Synchronization:
   - Duplicate clipboard sync returns ALREADY_IN_SYNC with skipped_duplicate=True
   - Failed clipboard write does NOT update sync cache
   - Direction-scoped hashing prevents collision between laptop_to_phone and phone_to_laptop
   - Propagates FOREGROUND_REQUIRED and remediation_hint when Android is backgrounded
3. Router-Backed Bidirectional File Transfer & Deduplication:
   - File send pre-checks SHA-256 duplicate and returns ALREADY_EXISTS with skipped_duplicate=True
   - File send dispatches via SessionRouter and returns structured telemetry
   - File receive pre-checks local existing file SHA-256 duplicate and returns ALREADY_EXISTS
   - File receive dispatches via SessionRouter and returns structured telemetry
"""

import asyncio
import hashlib
import json
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.engine import CapabilityEngine, ExecutionContext, ExecutionPrincipal
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.mcp.bridge import SnowMcpBridge
from snow.network.connection_manager import ClientConnection, ConnectionManager
from snow.network.node import (
    CapabilityExecutionClassification,
    CapabilityManifest,
    DeviceNode,
    ReachabilityProfile,
    ReachabilityState,
    build_windows_manifest,
)
from snow.network.registry import NodeRegistry
from snow.network.router import SessionRouter
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode
from snow.protocol.models import MessageType, SnowMessage
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.security.session import SessionRecord, SessionManager
from snow.transfer.manager import TransferDirection, TransferManager, TransferState


class TestPhase15ManifestUpdates(unittest.TestCase):
    """Test live capability manifest updates on NodeRegistry and WebSocket server."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_snow.db"
        self.db = DatabaseManager(self.db_path)
        self.conn_mgr = ConnectionManager()
        self.identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Desktop-Host",
            created_at="2026-01-01T00:00:00Z",
        )
        self.registry = NodeRegistry(
            db_manager=self.db,
            connection_manager=self.conn_mgr,
            local_identity=self.identity,
        )

        # Insert a paired Android peer
        self.android_id = str(uuid.uuid4())
        self.db.insert_paired_device(
            device_id=self.android_id,
            device_name="Ayush Phone",
            auth_token_hash="valid-token-hash-123",
            reachability_profile="ACTIVE_SESSION_PEER",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_node_registry_on_manifest_updated(self) -> None:
        """NodeRegistry updates in-memory cache and persists updated manifest to SQLite DB."""
        # Authenticate session
        self.registry.on_session_authenticated(
            device_id=self.android_id,
            connection_id="conn-1",
            host="192.168.1.100",
            port=8765,
        )

        new_manifest = {
            "manifest_version": "2.0",
            "supported_capabilities": ["android.telemetry.get", "android.clipboard.get"],
            "permission_states": {"android.clipboard.get": "GRANTED"},
            "classifications": {"android.clipboard.get": "FOREGROUND_USER_INTERACTION_REQUIRED"},
        }

        updated_node = self.registry.on_manifest_updated(self.android_id, new_manifest)
        self.assertIsNotNone(updated_node)
        self.assertEqual(len(updated_node.capabilities.supported_capabilities), 2)
        self.assertTrue(updated_node.supports_capability("android.clipboard.get"))

        # Verify DB persistence
        paired = self.db.get_paired_device(self.android_id)
        self.assertIsNotNone(paired)
        self.assertIsNotNone(paired.capabilities_json)
        self.assertIn("android.clipboard.get", paired.capabilities_json)

    def test_node_registry_on_manifest_updated_invalid_data_safe(self) -> None:
        """Empty or invalid manifest data is handled safely without crashing."""
        node = self.registry.on_manifest_updated(self.android_id, None)
        self.assertIsNotNone(node)


class TestPhase15WsServerManifestUpdate(unittest.IsolatedAsyncioTestCase):
    """Test ws_server manifest_update protocol handling and security."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_snow.db"
        self.db = DatabaseManager(self.db_path)
        self.conn_mgr = ConnectionManager()
        self.session_mgr = SessionManager()
        self.identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Desktop-Host",
            created_at="2026-01-01T00:00:00Z",
        )
        self.registry = NodeRegistry(
            db_manager=self.db,
            connection_manager=self.conn_mgr,
            local_identity=self.identity,
        )

        config = CoreConfig(
            port=8765,
            bind_host="127.0.0.1",
            auth_required=True,
            tls_enabled=False,
        )
        self.server = SnowWebSocketServer(
            config=config,
            connection_manager=self.conn_mgr,
            session_manager=self.session_mgr,
            db_manager=self.db,
            node_registry=self.registry,
        )

        self.android_id = str(uuid.uuid4())
        self.db.insert_paired_device(
            device_id=self.android_id,
            device_name="Test Phone",
            auth_token_hash="auth-tok-hash-42",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_ws_server_manifest_update_authenticated(self) -> None:
        """Authenticated client sending manifest_update successfully updates registry."""
        mock_ws = AsyncMock()
        now = time.time()
        client = ClientConnection(
            connection_id="conn-42",
            websocket=mock_ws,
            remote_address="127.0.0.1:12345",
            connected_at=now,
            last_heartbeat_at=now,
        )
        self.conn_mgr.register(client)
        session = self.session_mgr.create_session(connection_id="conn-42", device_id=self.android_id)

        req = SnowMessage.create_request(
            action="manifest_update",
            data={
                "device_id": self.android_id,
                "manifest": {
                    "manifest_version": "2.0",
                    "supported_capabilities": ["android.telemetry.get", "android.apps.list"],
                    "permission_states": {},
                    "classifications": {},
                },
            },
        )

        await self.server._handle_request(client, req)

        # Verify response sent back
        mock_ws.send.assert_called_once()
        raw_resp = mock_ws.send.call_args[0][0]
        parsed = json.loads(raw_resp)
        self.assertEqual(parsed.get("type"), "response")
        self.assertEqual(parsed.get("payload", {}).get("status"), "success")
        self.assertEqual(parsed.get("payload", {}).get("device_id"), self.android_id)

        # Verify registry was updated
        node = self.registry.get_node(self.android_id)
        self.assertIsNotNone(node)
        self.assertTrue(node.supports_capability("android.apps.list"))

    async def test_ws_server_manifest_update_unauthenticated_rejected(self) -> None:
        """Unauthenticated client sending manifest_update is rejected with UNAUTHORIZED."""
        mock_ws = AsyncMock()
        now = time.time()
        client = ClientConnection(
            connection_id="unauth-conn",
            websocket=mock_ws,
            remote_address="127.0.0.1:12345",
            connected_at=now,
            last_heartbeat_at=now,
        )
        self.conn_mgr.register(client)

        req = SnowMessage.create_request(
            action="manifest_update",
            data={
                "device_id": self.android_id,
                "manifest": {"supported_capabilities": ["android.telemetry.get"]},
            },
        )

        await self.server._handle_request(client, req)

        mock_ws.send.assert_called_once()
        raw_resp = mock_ws.send.call_args[0][0]
        parsed = json.loads(raw_resp)
        self.assertEqual(parsed.get("type"), "error")
        self.assertEqual(parsed.get("error", {}).get("code"), ErrorCode.UNAUTHORIZED)

    async def test_ws_server_manifest_update_anti_spoofing(self) -> None:
        """Client trying to inject authority fields in manifest_update has them stripped."""
        mock_ws = AsyncMock()
        now = time.time()
        client = ClientConnection(
            connection_id="conn-42",
            websocket=mock_ws,
            remote_address="127.0.0.1:12345",
            connected_at=now,
            last_heartbeat_at=now,
        )
        self.conn_mgr.register(client)
        session = self.session_mgr.create_session(connection_id="conn-42", device_id=self.android_id)

        manifest_payload = {
            "manifest_version": "2.0",
            "supported_capabilities": ["android.telemetry.get"],
            "principal": "OWNER_MANUAL",  # Malicious injection
            "trust_tier": "owner",         # Malicious injection
        }

        req = SnowMessage.create_request(
            action="manifest_update",
            data={
                "device_id": self.android_id,
                "manifest": manifest_payload,
                "principal": "OWNER_MANUAL",
            },
        )

        await self.server._handle_request(client, req)
        mock_ws.send.assert_called_once()
        raw_resp = mock_ws.send.call_args[0][0]
        parsed = json.loads(raw_resp)
        self.assertEqual(parsed.get("type"), "response")
        self.assertEqual(parsed.get("payload", {}).get("status"), "success")

        # Verify injected keys were stripped from the payload dict
        self.assertNotIn("principal", manifest_payload)
        self.assertNotIn("trust_tier", manifest_payload)


class TestPhase15ClipboardSyncHardening(unittest.IsolatedAsyncioTestCase):
    """Test idempotent clipboard sync, duplicate suppression, and error propagation."""

    def setUp(self) -> None:
        self.bridge = SnowMcpBridge(auto_start_core=False)
        self.target_id = "android-target-99"

    async def test_clipboard_sync_duplicate_suppression_laptop_to_phone(self) -> None:
        """Identical Windows clipboard text is synced once; second call returns ALREADY_IN_SYNC."""
        sample_text = "Universal Clipboard Test String ❄️"

        with patch.object(self.bridge, "windows_clipboard_get", new_callable=AsyncMock) as mock_get, \
             patch.object(self.bridge, "android_clipboard_push", new_callable=AsyncMock) as mock_push, \
             patch.object(self.bridge, "_resolve_target_device_id", new_callable=AsyncMock, return_value=self.target_id):

            mock_get.return_value = {"success": True, "data": {"text": sample_text}}
            mock_push.return_value = {"success": True, "status": "SUCCESS"}

            # 1. First sync: executes push
            res1 = await self.bridge.sync_clipboard(direction="laptop_to_phone", device_id=self.target_id)
            self.assertTrue(res1["success"])
            self.assertEqual(res1["status"], "SUCCESS")
            self.assertFalse(res1.get("skipped_duplicate"))
            self.assertEqual(res1["characters_synced"], len(sample_text))
            self.assertEqual(mock_push.call_count, 1)

            # 2. Second sync with identical content: suppressed
            res2 = await self.bridge.sync_clipboard(direction="laptop_to_phone", device_id=self.target_id)
            self.assertTrue(res2["success"])
            self.assertEqual(res2["status"], "ALREADY_IN_SYNC")
            self.assertTrue(res2.get("skipped_duplicate"))
            self.assertEqual(res2["characters_synced"], 0)
            self.assertEqual(mock_push.call_count, 1)  # NOT called again

    async def test_clipboard_sync_failed_write_does_not_cache_hash(self) -> None:
        """Failed clipboard write does not update cache; subsequent attempt retries push."""
        sample_text = "Retry Text 123"

        with patch.object(self.bridge, "windows_clipboard_get", new_callable=AsyncMock) as mock_get, \
             patch.object(self.bridge, "android_clipboard_push", new_callable=AsyncMock) as mock_push, \
             patch.object(self.bridge, "_resolve_target_device_id", new_callable=AsyncMock, return_value=self.target_id):

            mock_get.return_value = {"success": True, "data": {"text": sample_text}}
            # First attempt fails
            mock_push.return_value = {"success": False, "status": "SYNC_FAILED", "error": "Device error"}

            res1 = await self.bridge.sync_clipboard(direction="laptop_to_phone", device_id=self.target_id)
            self.assertFalse(res1["success"])
            self.assertEqual(mock_push.call_count, 1)

            # Cache key must NOT be stored
            cache_key = (self.target_id, "laptop_to_phone")
            self.assertNotIn(cache_key, self.bridge._clipboard_sync_hashes)

            # Second attempt succeeds
            mock_push.return_value = {"success": True, "status": "SUCCESS"}
            res2 = await self.bridge.sync_clipboard(direction="laptop_to_phone", device_id=self.target_id)
            self.assertTrue(res2["success"])
            self.assertEqual(res2["status"], "SUCCESS")
            self.assertEqual(mock_push.call_count, 2)

    async def test_clipboard_sync_duplicate_suppression_phone_to_laptop(self) -> None:
        """Identical phone clipboard text is synced once; second call returns ALREADY_IN_SYNC."""
        sample_text = "Phone to Laptop Clipboard Content"

        with patch.object(self.bridge, "send_device_request", new_callable=AsyncMock) as mock_pull, \
             patch.object(self.bridge, "windows_clipboard_set", new_callable=AsyncMock) as mock_set, \
             patch.object(self.bridge, "_resolve_target_device_id", new_callable=AsyncMock, return_value=self.target_id):

            mock_pull.return_value = {"success": True, "data": {"text": sample_text}}
            mock_set.return_value = {"success": True}

            # 1. First sync
            res1 = await self.bridge.sync_clipboard(direction="phone_to_laptop", device_id=self.target_id)
            self.assertTrue(res1["success"])
            self.assertEqual(res1["status"], "SUCCESS")
            self.assertFalse(res1.get("skipped_duplicate"))
            self.assertEqual(mock_set.call_count, 1)

            # 2. Second sync with identical content
            res2 = await self.bridge.sync_clipboard(direction="phone_to_laptop", device_id=self.target_id)
            self.assertTrue(res2["success"])
            self.assertEqual(res2["status"], "ALREADY_IN_SYNC")
            self.assertTrue(res2.get("skipped_duplicate"))
            self.assertEqual(res2["characters_synced"], 0)
            self.assertEqual(mock_set.call_count, 1)  # Windows clipboard not rewritten

    async def test_clipboard_sync_phone_to_laptop_foreground_required_remediation(self) -> None:
        """When Android returns FOREGROUND_REQUIRED, status and remediation hint are propagated."""
        with patch.object(self.bridge, "send_device_request", new_callable=AsyncMock) as mock_pull, \
             patch.object(self.bridge, "_resolve_target_device_id", new_callable=AsyncMock, return_value=self.target_id):

            mock_pull.return_value = {
                "success": False,
                "status": "FOREGROUND_REQUIRED",
                "error": "Android OS requires SNOW to be in the foreground to access the clipboard.",
                "remediation_hint": "Bring SNOW to the foreground on the Android device.",
            }

            res = await self.bridge.sync_clipboard(direction="phone_to_laptop", device_id=self.target_id)
            self.assertFalse(res["success"])
            self.assertEqual(res["status"], "FOREGROUND_REQUIRED")
            self.assertIn("foreground", res["error"].lower())
            self.assertEqual(res.get("remediation_hint"), "Bring SNOW to the foreground on the Android device.")


class TestPhase15FileTransferHardening(unittest.IsolatedAsyncioTestCase):
    """Test router-backed file transfer, duplicate pre-checking, and structured telemetry."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_path = Path(self.temp_dir.name)

        # Mock CoreServer and components
        self.core = MagicMock()
        self.core.config.transfer_port = 8766
        self.core.http_transfer_server = None

        from snow.capabilities.windows.files import WindowsFileManager
        self.core.windows_files = WindowsFileManager(allowed_roots=[self.temp_path])
        self.core.storage_manager.resolve_destination_path = lambda name: self.temp_path / name

        self.transfer_mgr = TransferManager()
        self.core.transfer_manager = self.transfer_mgr

        self.db = MagicMock()
        self.core.db_manager = self.db

        self.session_router = MagicMock()
        self.session_router._is_router_mock = True
        self.core.session_router = self.session_router

        self.config = CoreConfig(ipc_secret_path=str(self.temp_path / "ipc.secret"))
        self.ipc_server = SnowIpcServer(core_server=self.core, config=self.config)
        self.ipc_server.session_router = self.session_router

        # Create a sample test file
        self.test_file = self.temp_path / "sample_doc.txt"
        self.test_content = b"SNOW Phase 15 File Transfer Hardening Content 12345"
        self.test_file.write_bytes(self.test_content)
        self.test_sha256 = hashlib.sha256(self.test_content).hexdigest()

        self.device_id = "device-test-100"
        self.db.get_paired_device.return_value = {"device_id": self.device_id}

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_file_send_duplicate_pre_check(self) -> None:
        """File send detects already completed transfer with identical SHA-256 and returns ALREADY_EXISTS."""
        # Create an already-completed transfer in the transfer manager
        existing_record = self.transfer_mgr.create_transfer(
            device_id=self.device_id,
            file_name=self.test_file.name,
            file_size=len(self.test_content),
            sha256=self.test_sha256,
            direction=TransferDirection.DOWNLOAD,
        )
        self.transfer_mgr.complete_transfer(existing_record.transfer_id)

        payload = {
            "device_id": self.device_id,
            "file_path": str(self.test_file),
        }

        res = await self.ipc_server._handle_android_file_send(payload)

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "ALREADY_EXISTS")
        self.assertTrue(res["skipped_duplicate"])
        self.assertEqual(res["bytes_transferred"], 0)
        self.assertEqual(res["sha256"], self.test_sha256)
        self.assertEqual(res["transfer_id"], existing_record.transfer_id)

        # Verify SessionRouter was NOT invoked for duplicate
        self.session_router.route_request.assert_not_called()

    async def test_file_send_dispatches_via_session_router(self) -> None:
        """File send routes via SessionRouter.route_request and returns structured telemetry."""
        self.session_router.route_request = AsyncMock(return_value={
            "success": True,
            "status": "SUCCESS",
            "data": {"status": "success"},
        })

        payload = {
            "device_id": self.device_id,
            "file_path": str(self.test_file),
        }

        res = await self.ipc_server._handle_android_file_send(payload)

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "SUCCESS")
        self.assertFalse(res["skipped_duplicate"])
        self.assertEqual(res["bytes_transferred"], len(self.test_content))
        self.assertEqual(res["sha256"], self.test_sha256)
        self.assertIn("transfer_id", res)

        self.session_router.route_request.assert_called_once()
        call_kwargs = self.session_router.route_request.call_args[1]
        self.assertEqual(call_kwargs["action"], "file_send_request")
        self.assertEqual(call_kwargs["target"], self.device_id)

    async def test_file_receive_duplicate_pre_check(self) -> None:
        """File receive detects already existing local file with matching hash and returns ALREADY_EXISTS."""
        # File already exists at storage destination
        dest_file = self.temp_path / "already_uploaded.txt"
        dest_file.write_bytes(self.test_content)

        existing_record = self.transfer_mgr.create_transfer(
            device_id=self.device_id,
            file_name="already_uploaded.txt",
            file_size=len(self.test_content),
            sha256=self.test_sha256,
            direction=TransferDirection.UPLOAD,
        )
        self.transfer_mgr.complete_transfer(existing_record.transfer_id)

        payload = {
            "device_id": self.device_id,
            "file_name": "already_uploaded.txt",
        }

        res = await self.ipc_server._handle_android_file_receive(payload)

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "ALREADY_EXISTS")
        self.assertTrue(res["skipped_duplicate"])
        self.assertEqual(res["bytes_transferred"], 0)
        self.assertEqual(res["sha256"], self.test_sha256)
        self.session_router.route_request.assert_not_called()

    async def test_file_receive_dispatches_via_session_router(self) -> None:
        """File receive routes via SessionRouter.route_request and returns structured telemetry."""
        self.session_router.route_request = AsyncMock(return_value={
            "success": True,
            "status": "SUCCESS",
            "data": {"status": "success"},
        })

        payload = {
            "device_id": self.device_id,
            "file_name": "new_remote_photo.jpg",
        }

        res = await self.ipc_server._handle_android_file_receive(payload)

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "SUCCESS")
        self.assertFalse(res["skipped_duplicate"])
        self.session_router.route_request.assert_called_once()
        call_kwargs = self.session_router.route_request.call_args[1]
        self.assertEqual(call_kwargs["action"], "file_receive_request")
        self.assertEqual(call_kwargs["target"], self.device_id)


if __name__ == "__main__":
    unittest.main()
