"""Tests for Sub-Milestone 2.2: SQLite Pairing Records, Session Management, and Authenticated Unpairing."""

import asyncio
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
import uuid

from snow.core.config import CoreConfig
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.security.db import (
    AuditEventRecord,
    DatabaseManager,
    PairedDeviceRecord,
    current_utc_timestamp,
    hash_token,
)
from snow.security.identity import DeviceIdentity
from snow.security.pairing import PairingManager
from snow.security.session import SessionManager, SessionRecord


class TestDatabaseManager(unittest.TestCase):
    """Test the SQLite database manager persistence, schema, and security invariants."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_devices.db"
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_schema_initialization(self) -> None:
        """Verify tables and version pragma are initialized correctly."""
        with self.db._get_connection() as conn:
            cursor = conn.execute("PRAGMA user_version;")
            ver = cursor.fetchone()[0]
            self.assertIn(ver, (1, 2))

            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
            )
            tables = [row[0] for row in cursor.fetchall()]
            self.assertIn("paired_devices", tables)
            self.assertIn("pairing_audit_log", tables)

    def test_token_hashing(self) -> None:
        """Verify SHA-256 token hashing function."""
        raw_token = "snow-super-secret-auth-token-12345"
        expected = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        self.assertEqual(hash_token(raw_token), expected)

    def test_insert_and_get_paired_device(self) -> None:
        """Verify inserting and retrieving a paired device record."""
        dev_id = str(uuid.uuid4())
        dev_name = "Realme RMX5110 Test"
        raw_token = "client-token-abc"
        token_h = hash_token(raw_token)

        record = self.db.insert_paired_device(
            device_id=dev_id,
            device_name=dev_name,
            auth_token_hash=token_h,
        )

        self.assertEqual(record.device_id, dev_id)
        self.assertEqual(record.device_name, dev_name)
        self.assertEqual(record.auth_token_hash, token_h)

        retrieved = self.db.get_paired_device(dev_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.device_id, dev_id)
        self.assertEqual(retrieved.device_name, dev_name)
        self.assertEqual(retrieved.auth_token_hash, token_h)

        by_hash = self.db.get_paired_device_by_token_hash(token_h)
        self.assertIsNotNone(by_hash)
        self.assertEqual(by_hash.device_id, dev_id)

    def test_verify_device_token(self) -> None:
        """Verify constant-time token verification."""
        dev_id = str(uuid.uuid4())
        raw_token = "correct-raw-token-123"
        token_h = hash_token(raw_token)

        self.db.insert_paired_device(dev_id, "Test Phone", token_h)

        # Correct token
        self.assertTrue(self.db.verify_device_token(dev_id, raw_token))

        # Incorrect token
        self.assertFalse(self.db.verify_device_token(dev_id, "wrong-raw-token"))

        # Non-existent device
        self.assertFalse(self.db.verify_device_token(str(uuid.uuid4()), raw_token))

    def test_update_last_seen(self) -> None:
        """Verify updating last_seen_timestamp."""
        dev_id = str(uuid.uuid4())
        self.db.insert_paired_device(dev_id, "Phone", hash_token("token"))

        custom_ts = "2026-11-16T12:00:00+00:00"
        updated = self.db.update_last_seen(dev_id, custom_ts)
        self.assertTrue(updated)

        record = self.db.get_paired_device(dev_id)
        self.assertEqual(record.last_seen_timestamp, custom_ts)

    def test_delete_paired_device(self) -> None:
        """Verify device deletion on unpairing."""
        dev_id = str(uuid.uuid4())
        self.db.insert_paired_device(dev_id, "Phone", hash_token("token"))

        deleted = self.db.delete_paired_device(dev_id)
        self.assertTrue(deleted)

        self.assertIsNone(self.db.get_paired_device(dev_id))

        # Deleting non-existent device returns False
        self.assertFalse(self.db.delete_paired_device(dev_id))

    def test_audit_logging_persists_after_unpair(self) -> None:
        """Audit records must persist even after the device is unpaired."""
        dev_id = str(uuid.uuid4())
        self.db.insert_paired_device(dev_id, "Phone", hash_token("token"))

        self.db.log_audit_event("PAIR_SUCCESS", device_id=dev_id, details={"via": "PIN"})
        self.db.log_audit_event("UNPAIR", device_id=dev_id, details={"by": "client"})

        # Delete device
        self.db.delete_paired_device(dev_id)
        self.assertIsNone(self.db.get_paired_device(dev_id))

        # Audit records must remain intact
        logs = self.db.get_audit_logs(device_id=dev_id)
        self.assertEqual(len(logs), 2)
        event_types = [entry.event_type for entry in logs]
        self.assertIn("PAIR_SUCCESS", event_types)
        self.assertIn("UNPAIR", event_types)


class TestSessionManager(unittest.TestCase):
    """Test in-memory session tracking and lifecycle."""

    def setUp(self) -> None:
        self.sessions = SessionManager()

    def test_session_creation_and_lookup(self) -> None:
        dev_id = str(uuid.uuid4())
        conn_id = "conn-1"

        session = self.sessions.create_session(dev_id, conn_id)
        self.assertEqual(session.device_id, dev_id)
        self.assertEqual(session.connection_id, conn_id)

        by_sid = self.sessions.get_session(session.session_id)
        self.assertEqual(by_sid, session)

        by_dev = self.sessions.get_session_by_device(dev_id)
        self.assertEqual(by_dev, session)

        by_conn = self.sessions.get_session_by_connection(conn_id)
        self.assertEqual(by_conn, session)

    def test_supersede_previous_session(self) -> None:
        """Creating a new session for a device revokes the old session."""
        dev_id = str(uuid.uuid4())
        sess1 = self.sessions.create_session(dev_id, "conn-1")
        sess2 = self.sessions.create_session(dev_id, "conn-2")

        self.assertIsNone(self.sessions.get_session(sess1.session_id))
        self.assertEqual(self.sessions.get_session(sess2.session_id), sess2)
        self.assertEqual(len(self.sessions.list_active_sessions()), 1)

    def test_cleanup_connection_detaches_connection_id(self) -> None:
        """Connection close removes socket association but leaves session intact."""
        dev_id = str(uuid.uuid4())
        conn_id = "conn-temp"
        session = self.sessions.create_session(dev_id, conn_id)

        self.sessions.cleanup_connection(conn_id)

        # Connection ID lookup is None
        self.assertIsNone(self.sessions.get_session_by_connection(conn_id))

        # But device session remains
        active = self.sessions.get_session_by_device(dev_id)
        self.assertIsNotNone(active)
        self.assertIsNone(active.connection_id)

    def test_revoke_device_sessions(self) -> None:
        dev_id = str(uuid.uuid4())
        self.sessions.create_session(dev_id, "conn-1")
        revoked = self.sessions.revoke_device_sessions(dev_id)
        self.assertEqual(revoked, 1)
        self.assertIsNone(self.sessions.get_session_by_device(dev_id))


class TestServerPairingAndUnpairing(unittest.IsolatedAsyncioTestCase):
    """Integration test for WebSocket server pairing, token issuance, and unpairing."""

    async def asyncSetUp(self) -> None:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            test_port = s.getsockname()[1]

        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "snow_test.db"
        self.db_manager = DatabaseManager(db_path=self.db_path)
        self.session_manager = SessionManager()
        self.pairing_manager = PairingManager(pin_lifetime=60.0)
        self.device_identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Test Desktop Core",
            created_at=current_utc_timestamp(),
        )

        self.config = CoreConfig(
            app_name="SNOW Test Core",
            version="1.0.0",
            bind_host="127.0.0.1",
            port=test_port,
            heartbeat_interval=30.0,
            heartbeat_timeout=60.0,
        )

        self.server = SnowWebSocketServer(
            config=self.config,
            pairing_manager=self.pairing_manager,
            device_identity=self.device_identity,
            db_manager=self.db_manager,
            session_manager=self.session_manager,
        )
        await self.server.start()

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        self.temp_dir.cleanup()

    async def test_pair_request_issues_token_and_persists(self) -> None:
        """Successful PIN verification stores token hash in SQLite and returns raw token."""
        pin = self.pairing_manager.generate_pin()
        client_device_id = str(uuid.uuid4())

        class MockClient:
            connection_id = "test-client-conn-1"
            websocket = None

        class MockWs:
            def __init__(self):
                self.sent_messages = []

            async def send(self, msg: str):
                self.sent_messages.append(msg)

        mock_client = MockClient()
        mock_ws = MockWs()
        mock_client.websocket = mock_ws

        pair_msg = SnowMessage.create_request(
            action="pair_request",
            data={
                "device_id": client_device_id,
                "device_name": "Realme RMX5110",
                "pin": pin,
            },
        )

        await self.server._handle_request(mock_client, pair_msg)

        self.assertEqual(len(mock_ws.sent_messages), 1)
        resp_json = json.loads(mock_ws.sent_messages[0])
        self.assertEqual(resp_json["type"], "response")
        data = resp_json["payload"]["data"]
        self.assertIn("auth_token", data)
        raw_token = data["auth_token"]
        self.assertGreater(len(raw_token), 20)

        # Verify persisted in SQLite
        db_record = self.db_manager.get_paired_device(client_device_id)
        self.assertIsNotNone(db_record)
        self.assertEqual(db_record.device_name, "Realme RMX5110")
        self.assertEqual(db_record.auth_token_hash, hash_token(raw_token))

        # Verify active session created
        session = self.session_manager.get_session_by_device(client_device_id)
        self.assertIsNotNone(session)

        # Verify authorize_request
        self.assertTrue(self.server.authorize_request(client_device_id, raw_token))
        self.assertFalse(self.server.authorize_request(client_device_id, "bad-token"))

    async def test_unpair_request_flow(self) -> None:
        """Valid unpair_request removes DB record and active session."""
        client_device_id = str(uuid.uuid4())
        raw_token = "valid-unpair-token-999"
        self.db_manager.insert_paired_device(
            client_device_id, "Realme RMX5110", hash_token(raw_token)
        )
        self.session_manager.create_session(client_device_id, "conn-unpair")

        class MockClient:
            connection_id = "conn-unpair"
            websocket = None

        class MockWs:
            def __init__(self):
                self.sent_messages = []

            async def send(self, msg: str):
                self.sent_messages.append(msg)

        mock_client = MockClient()
        mock_ws = MockWs()
        mock_client.websocket = mock_ws

        unpair_msg = SnowMessage.create_request(
            action="unpair_request",
            data={
                "device_id": client_device_id,
                "auth_token": raw_token,
            },
        )

        await self.server._handle_request(mock_client, unpair_msg)

        self.assertEqual(len(mock_ws.sent_messages), 1)
        resp = json.loads(mock_ws.sent_messages[0])
        self.assertEqual(resp["type"], "response")
        self.assertTrue(resp["payload"]["data"]["unpaired"])

        # Device is gone from DB
        self.assertIsNone(self.db_manager.get_paired_device(client_device_id))

        # Session is revoked
        self.assertIsNone(self.session_manager.get_session_by_device(client_device_id))

        # Subsequent authorize_request returns False
        self.assertFalse(self.server.authorize_request(client_device_id, raw_token))

    async def test_unpair_invalid_token_returns_unauthorized(self) -> None:
        """Unpair with incorrect token fails with UNAUTHORIZED."""
        client_device_id = str(uuid.uuid4())
        raw_token = "good-token"
        self.db_manager.insert_paired_device(
            client_device_id, "Realme RMX5110", hash_token(raw_token)
        )

        class MockClient:
            connection_id = "conn-test"
            websocket = None

        class MockWs:
            def __init__(self):
                self.sent_messages = []

            async def send(self, msg: str):
                self.sent_messages.append(msg)

        mock_client = MockClient()
        mock_ws = MockWs()
        mock_client.websocket = mock_ws

        unpair_msg = SnowMessage.create_request(
            action="unpair_request",
            data={
                "device_id": client_device_id,
                "auth_token": "wrong-token",
            },
        )

        await self.server._handle_request(mock_client, unpair_msg)

        self.assertEqual(len(mock_ws.sent_messages), 1)
        resp = json.loads(mock_ws.sent_messages[0])
        self.assertEqual(resp["type"], "error")
        self.assertEqual(resp["error"]["code"], ErrorCode.UNAUTHORIZED)

        # Device is still in DB
        self.assertIsNotNone(self.db_manager.get_paired_device(client_device_id))

    async def test_persistence_across_server_restarts(self) -> None:
        """Paired records in SQLite persist across server stop and restart."""
        client_device_id = str(uuid.uuid4())
        raw_token = "restart-token-123"
        self.db_manager.insert_paired_device(
            client_device_id, "Realme RMX5110", hash_token(raw_token)
        )

        # Stop first server
        await self.server.stop()

        # Start new server pointing to identical DB file
        new_db = DatabaseManager(db_path=self.db_path)
        new_server = SnowWebSocketServer(
            config=self.config,
            db_manager=new_db,
        )
        await new_server.start()
        try:
            # Device record exists and token verifies
            self.assertTrue(new_server.authorize_request(client_device_id, raw_token))
            record = new_server.db_manager.get_paired_device(client_device_id)
            self.assertIsNotNone(record)
            self.assertEqual(record.device_name, "Realme RMX5110")
        finally:
            await new_server.stop()


if __name__ == "__main__":
    unittest.main()
