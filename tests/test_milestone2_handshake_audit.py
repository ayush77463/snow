"""Milestone 2 — Pre-implementation Handshake Audit (Unit 1.5 Permission Profile Wiring).

Verifies that desktop `_handle_pairing_request` and `_handle_auth_request` include
the authoritative per-device `permission_profile` alongside separate `trust_tier`,
defaulting newly paired devices to `full_control` while failing closed on corrupt
database profile entries.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock
import uuid

from snow.capabilities.engine import CapabilityEngine
from snow.core.config import CoreConfig
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.security.pairing import PairingManager
from snow.security.session import SessionManager


class TestMilestone2HandshakeAudit(unittest.TestCase):
    """Verify desktop handshake emits authoritative permission_profile."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_m2_audit_")
        self.db_path = Path(self.temp_dir) / "audit.db"
        self.db_manager = DatabaseManager(self.db_path)
        self.identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Authoritative-Host-PC",
            created_at="2026-11-26T00:00:00Z",
            snow_id="SNW-HOST-1111",
        )
        self.cfg = CoreConfig(
            port=8765,
            ipc_port=0,
            transfer_port=0,
            discovery_enabled=False,
        )
        self.pairing_manager = PairingManager()
        self.session_manager = SessionManager()
        self.capability_engine = CapabilityEngine(db_manager=self.db_manager)
        self.ws_server = SnowWebSocketServer(
            config=self.cfg,
            device_identity=self.identity,
            pairing_manager=self.pairing_manager,
            session_manager=self.session_manager,
            db_manager=self.db_manager,
        )
        self.ws_server.capability_engine = self.capability_engine

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_client(self, conn_id: str = "conn-audit"):
        client = MagicMock()
        client.connection_id = conn_id
        client.remote_address = ("192.168.1.55", 50000)
        client.websocket = MagicMock()
        client.websocket.send = AsyncMock()
        client.websocket.close = AsyncMock()
        return client

    def test_01_pairing_response_includes_authoritative_permission_profile(self) -> None:
        async def run():
            client_dev_id = str(uuid.uuid4())
            pin = self.pairing_manager.generate_pin(display_to_stderr=False, trust_tier="owner")
            client = self._make_client("conn-pair")
            req = SnowMessage.create_request(
                "pair_request",
                {"device_id": client_dev_id, "device_name": "Realme P4", "pin": pin},
            )
            await self.ws_server._handle_pairing_request(client, req, "pair_request", req.data)
            self.assertEqual(client.websocket.send.call_count, 1)
            sent = json.loads(client.websocket.send.call_args[0][0])
            self.assertEqual(sent["payload"]["status"], "success")
            data = sent["payload"]["data"]
            self.assertEqual(data["trust_tier"], "owner")
            self.assertEqual(data["permission_profile"], "full_control")
            return data["auth_token"], client_dev_id

        auth_token, client_dev_id = asyncio.run(run())
        self.assertTrue(bool(auth_token))
        self.assertIsNotNone(self.db_manager.get_paired_device(client_dev_id))

    def test_02_auth_response_includes_explicit_and_corrupt_fail_closed_profiles(self) -> None:
        async def run():
            dev_id = str(uuid.uuid4())
            raw_token = "tok_" + uuid.uuid4().hex
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            self.db_manager.insert_paired_device(
                device_id=dev_id,
                device_name="Android Test",
                auth_token_hash=token_hash,
                trust_tier="peer",
            )
            # Case A: explicit files_and_clipboard stored on desktop DB
            self.db_manager.set_setting(f"device_profile:{dev_id}", "files_and_clipboard")
            client = self._make_client("conn-auth-1")
            req = SnowMessage.create_request(
                "auth_request",
                {"device_id": dev_id, "auth_token": raw_token},
            )
            await self.ws_server._handle_auth_request(client, req, req.data)
            sent_a = json.loads(client.websocket.send.call_args[0][0])
            self.assertEqual(sent_a["payload"]["data"]["trust_tier"], "peer")
            self.assertEqual(sent_a["payload"]["data"]["permission_profile"], "files_and_clipboard")

            # Case B: corrupted profile string in DB fails closed as not_allowed
            self.db_manager.set_setting(f"device_profile:{dev_id}", "superuser_override")
            client2 = self._make_client("conn-auth-2")
            req2 = SnowMessage.create_request(
                "auth_request",
                {"device_id": dev_id, "auth_token": raw_token},
            )
            await self.ws_server._handle_auth_request(client2, req2, req2.data)
            sent_b = json.loads(client2.websocket.send.call_args[0][0])
            self.assertEqual(sent_b["payload"]["data"]["permission_profile"], "not_allowed")

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
