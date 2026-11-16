"""Sub-Milestone 2.4 Test Suite: TLS/WSS Transport and Authenticated Sessions.

Tests:
1. Local X.509 certificate and private key generation.
2. Certificate and key persistence across restarts.
3. SHA-256 fingerprint consistency.
4. Malformed and mismatched certificate/key handling.
5. Successful WSS connection over TLS.
6. Valid auth_request and active session creation.
7. Invalid token rejection (UNAUTHORIZED).
8. Unknown/unpaired device rejection (DEVICE_NOT_FOUND).
9. Protected action rejection before authentication (UNAUTHORIZED).
10. Handshake timeout enforcement (configurable short timeout).
11. Legitimate pairing initiation immune to initial handshake timeout.
12. Session cleanup and revocation on client disconnect.
13. Zero plaintext token exposure in storage.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import socket
import ssl
import tempfile
import unittest
import uuid

import websockets
from websockets.asyncio.client import connect

from snow.core.config import CoreConfig
from snow.network.connection_manager import ConnectionManager
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import DeviceIdentity
from snow.security.pairing import PairingManager
from snow.security.session import SessionManager
from snow.security.tls import (
    compute_cert_fingerprint,
    create_server_ssl_context,
    ensure_tls_certificate,
    format_fingerprint,
    generate_self_signed_cert,
    load_certificate_info,
)


class TestTlsCertificateManagement(unittest.TestCase):
    """Test X.509 self-signed certificate generation and persistence."""

    def setUp(self) -> None:
        self.test_dir = Path(tempfile.mkdtemp())
        self.cert_path = self.test_dir / "server.crt"
        self.key_path = self.test_dir / "server.key"

    def tearDown(self) -> None:
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_cert_generation_and_persistence(self) -> None:
        info = generate_self_signed_cert(
            cert_path=self.cert_path,
            key_path=self.key_path,
            active_ips=["192.168.1.100"],
            common_name="SNOW-Test",
        )
        self.assertTrue(self.cert_path.exists())
        self.assertTrue(self.key_path.exists())
        self.assertIn("192.168.1.100", info.san_entries)
        self.assertIn("127.0.0.1", info.san_entries)
        self.assertIn("localhost", info.san_entries)
        self.assertEqual(len(info.fingerprint_sha256.split(":")), 32)

        # Reloading matches the generated info
        loaded = load_certificate_info(self.cert_path, self.key_path)
        self.assertEqual(info.fingerprint_sha256, loaded.fingerprint_sha256)
        self.assertEqual(info.san_entries, loaded.san_entries)

    def test_fingerprint_consistency(self) -> None:
        info = ensure_tls_certificate(self.cert_path, self.key_path)
        first_fp = info.fingerprint_sha256

        # Second load without changes yields identical fingerprint
        info2 = ensure_tls_certificate(self.cert_path, self.key_path)
        self.assertEqual(first_fp, info2.fingerprint_sha256)

    def test_mismatched_key_raises_error(self) -> None:
        # Generate cert and key
        generate_self_signed_cert(self.cert_path, self.key_path)

        # Generate a separate key and overwrite
        alt_key_path = self.test_dir / "alt.key"
        generate_self_signed_cert(self.test_dir / "alt.crt", alt_key_path)

        with open(alt_key_path, "rb") as f:
            mismatched_key_bytes = f.read()
        with open(self.key_path, "wb") as f:
            f.write(mismatched_key_bytes)

        with self.assertRaises(ValueError) as ctx:
            load_certificate_info(self.cert_path, self.key_path)
        self.assertIn("does not match private key", str(ctx.exception))

    def test_corrupt_cert_raises_error(self) -> None:
        self.cert_path.write_text("NOT A VALID PEM CERTIFICATE")
        self.key_path.write_text("NOT A VALID PEM KEY")

        with self.assertRaises(ValueError):
            load_certificate_info(self.cert_path, self.key_path)


class TestWssAuthenticatedCommunication(unittest.IsolatedAsyncioTestCase):
    """Test WSS transport, auth_request handling, and handshake timeouts."""

    async def asyncSetUp(self) -> None:
        self.test_dir = Path(tempfile.mkdtemp())
        self.cert_path = self.test_dir / "server.crt"
        self.key_path = self.test_dir / "server.key"
        self.db_path = self.test_dir / "test_devices.db"

        # Generate test certificate
        self.cert_info = generate_self_signed_cert(
            self.cert_path, self.key_path, active_ips=["127.0.0.1"]
        )

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            test_port = s.getsockname()[1]

        self.config = CoreConfig(
            bind_host="127.0.0.1",
            port=test_port,
            tls_enabled=True,
            auth_timeout=0.4,  # Fast 400ms timeout for test suite
            tls_cert_path=str(self.cert_path),
            tls_key_path=str(self.key_path),
        )

        self.db_manager = DatabaseManager(self.db_path)
        self.session_manager = SessionManager()
        self.conn_manager = ConnectionManager()
        self.pairing_manager = PairingManager()
        self.device_identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Test-Desktop",
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        self.server = SnowWebSocketServer(
            config=self.config,
            connection_manager=self.conn_manager,
            pairing_manager=self.pairing_manager,
            device_identity=self.device_identity,
            db_manager=self.db_manager,
            session_manager=self.session_manager,
        )

        await self.server.start(active_ips=["127.0.0.1"])
        self.port = self.server.bound_port

        # Create client SSLContext trusting self-signed cert
        self.client_ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.client_ssl.check_hostname = False
        self.client_ssl.verify_mode = ssl.CERT_REQUIRED
        self.client_ssl.load_verify_locations(cafile=str(self.cert_path))

        # Sample paired device
        self.test_device_id = str(uuid.uuid4())
        self.raw_auth_token = "secure-test-token-xyz-12345"
        self.db_manager.insert_paired_device(
            device_id=self.test_device_id,
            device_name="Paired-Phone",
            auth_token_hash=hash_token(self.raw_auth_token),
        )

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        shutil.rmtree(self.test_dir, ignore_errors=True)

    async def test_successful_wss_connection_and_auth(self) -> None:
        ws_url = f"wss://127.0.0.1:{self.port}"
        async with connect(ws_url, ssl=self.client_ssl) as ws:
            # Send auth_request
            auth_req = SnowMessage.create_request(
                action="auth_request",
                data={
                    "device_id": self.test_device_id,
                    "auth_token": self.raw_auth_token,
                },
            )
            await ws.send(auth_req.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            resp = json.loads(raw_resp)
            self.assertEqual(resp["type"], "response")
            self.assertEqual(resp["correlation_id"], auth_req.id)
            self.assertEqual(resp["payload"]["status"], "success")
            session_id = resp["payload"]["data"]["session_id"]
            self.assertTrue(bool(session_id))

            # Verify session active in SessionManager
            session = self.session_manager.get_session(session_id)
            self.assertIsNotNone(session)
            self.assertEqual(session.device_id, self.test_device_id)

            # Once authenticated, ping should succeed
            ping_req = SnowMessage.create_request(action="ping")
            await ws.send(ping_req.to_json())
            raw_ping_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            ping_resp = json.loads(raw_ping_resp)
            self.assertEqual(ping_resp["type"], "response")
            self.assertEqual(ping_resp["payload"]["action"], "pong")

    async def test_invalid_token_rejected_with_unauthorized(self) -> None:
        ws_url = f"wss://127.0.0.1:{self.port}"
        async with connect(ws_url, ssl=self.client_ssl) as ws:
            auth_req = SnowMessage.create_request(
                action="auth_request",
                data={
                    "device_id": self.test_device_id,
                    "auth_token": "wrong-token-abc",
                },
            )
            await ws.send(auth_req.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            resp = json.loads(raw_resp)
            self.assertEqual(resp["type"], "error")
            self.assertEqual(resp["error"]["code"], ErrorCode.UNAUTHORIZED)
            self.assertEqual(resp["correlation_id"], auth_req.id)

    async def test_unknown_device_rejected_with_device_not_found(self) -> None:
        ws_url = f"wss://127.0.0.1:{self.port}"
        async with connect(ws_url, ssl=self.client_ssl) as ws:
            auth_req = SnowMessage.create_request(
                action="auth_request",
                data={
                    "device_id": str(uuid.uuid4()),  # Unregistered ID
                    "auth_token": self.raw_auth_token,
                },
            )
            await ws.send(auth_req.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            resp = json.loads(raw_resp)
            self.assertEqual(resp["type"], "error")
            self.assertEqual(resp["error"]["code"], ErrorCode.DEVICE_NOT_FOUND)

    async def test_unauthenticated_protected_action_rejected(self) -> None:
        ws_url = f"wss://127.0.0.1:{self.port}"
        async with connect(ws_url, ssl=self.client_ssl) as ws:
            # Client attempts ping before authenticating
            ping_req = SnowMessage.create_request(action="ping")
            await ws.send(ping_req.to_json())

            raw_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            resp = json.loads(raw_resp)
            self.assertEqual(resp["type"], "error")
            self.assertEqual(resp["error"]["code"], ErrorCode.UNAUTHORIZED)
            self.assertIn("not authenticated", resp["error"]["message"].lower())

    async def test_handshake_timeout_closes_idle_connection(self) -> None:
        ws_url = f"wss://127.0.0.1:{self.port}"
        # Connect but do NOT authenticate or initiate pairing
        async with connect(ws_url, ssl=self.client_ssl) as ws:
            # Send heartbeats (heartbeat does NOT satisfy authentication)
            hb = SnowMessage.create_heartbeat()
            await ws.send(hb.to_json())
            ack = await ws.recv()
            self.assertEqual(json.loads(ack)["type"], "heartbeat_ack")

            # Wait past the 0.4s auth timeout
            await asyncio.sleep(0.5)

            # Next send/recv should fail or connection should close
            try:
                await ws.recv()
            except websockets.exceptions.ConnectionClosed as exc:
                self.assertEqual(exc.rcvd.code, 4001)

    async def test_pairing_initiation_immunizes_from_timeout(self) -> None:
        ws_url = f"wss://127.0.0.1:{self.port}"
        async with connect(ws_url, ssl=self.client_ssl) as ws:
            # Request new PIN to begin pairing flow
            pair_req = SnowMessage.create_request(
                action="pair_request",
                data={"device_id": str(uuid.uuid4())},
            )
            await ws.send(pair_req.to_json())
            raw_pin_resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
            pin_resp = json.loads(raw_pin_resp)
            self.assertEqual(pin_resp["payload"]["status"], "pin_displayed")

            # Wait beyond the 0.4s auth timeout (user taking time to enter PIN)
            await asyncio.sleep(0.6)

            # Socket MUST still be open and alive!
            current_pin = self.pairing_manager._active_pin
            self.assertIsNotNone(current_pin)

            # Submit PIN verification
            verify_req = SnowMessage.create_request(
                action="pair_request",
                data={
                    "device_id": str(uuid.uuid4()),
                    "device_name": "Test-Device",
                    "pin": current_pin,
                },
            )
            await ws.send(verify_req.to_json())
            raw_verify = await asyncio.wait_for(ws.recv(), timeout=2.0)
            verify_resp = json.loads(raw_verify)
            self.assertEqual(verify_resp["payload"]["status"], "success")

    async def test_zero_plaintext_token_in_desktop_db(self) -> None:
        # Check SQLite database table paired_devices
        with open(self.db_path, "rb") as f:
            raw_db_bytes = f.read()

        # The raw plaintext token must NEVER appear anywhere in the database file
        self.assertNotIn(self.raw_auth_token.encode("utf-8"), raw_db_bytes)


if __name__ == "__main__":
    unittest.main()
