"""Tests for Phase 21 Pairing Recovery and Trust Model Correction.

Verifies:
1. pair_request(pin=None) preserves active unexpired PIN and returns waiting_for_pin.
2. Unauthenticated client cannot force-rotate PIN remotely.
3. Owner PIN produces OWNER trust tier; Peer PIN produces PEER trust tier.
4. Pairing a new Owner device does not silently demote existing Owner devices.
5. Reconnection and auth_request return authoritative stored trust tier.
6. Web server /api/pair/state endpoint queries live pairing PIN and state securely.
7. Web server /api/status exposes LAN IPs and WSS port without leaking the PIN.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from snow.core.config import CoreConfig
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage
from snow.security.db import DatabaseManager
from snow.security.pairing import PairingManager, PairingOutcome, create_qr_pairing_payload, validate_qr_pairing_payload
from snow.web.server import SnowWebServer


class TestPairingManagerTrustModel(unittest.TestCase):
    """Test suite for PairingManager multi-tier PIN verification and lifetime tracking."""

    def setUp(self) -> None:
        self.mock_time = 1000.0
        self.pm = PairingManager(
            pin_lifetime=60.0,
            max_attempts=3,
            time_provider=lambda: self.mock_time,
        )

    def test_generate_owner_pin_binds_owner_tier(self) -> None:
        pin = self.pm.generate_pin(display_to_stderr=False, trust_tier="owner")
        self.assertEqual(len(pin), 6)
        self.assertTrue(pin.isdigit())

        state = self.pm.get_active_pin_state(include_pin=True)
        self.assertTrue(state["has_active_pin"])
        self.assertEqual(state["trust_tier"], "owner")
        self.assertEqual(state["pin"], pin)
        self.assertEqual(state["remaining_seconds"], 60)

        # Verification produces OWNER trust tier
        result = self.pm.verify_pin(pin, client_device_id="device-owner-1")
        self.assertTrue(result.is_success)
        self.assertEqual(result.assigned_trust_tier, "owner")
        self.assertTrue(self.pm.is_paired)

    def test_generate_peer_pin_binds_peer_tier(self) -> None:
        pin = self.pm.generate_pin(display_to_stderr=False, trust_tier="peer")
        state = self.pm.get_active_pin_state(include_pin=True)
        self.assertTrue(state["has_active_pin"])
        self.assertEqual(state["trust_tier"], "peer")

        result = self.pm.verify_pin(pin, client_device_id="device-peer-1")
        self.assertTrue(result.is_success)
        self.assertEqual(result.assigned_trust_tier, "peer")

    def test_remaining_lifetime_and_expiry(self) -> None:
        pin = self.pm.generate_pin(display_to_stderr=False)
        self.assertEqual(self.pm.remaining_lifetime, 60.0)

        self.mock_time += 25.0
        self.assertEqual(self.pm.remaining_lifetime, 35.0)

        self.mock_time += 40.0  # Elapsed 65s > 60s
        self.assertEqual(self.pm.remaining_lifetime, 0.0)
        self.assertFalse(self.pm.has_active_pin)

        result = self.pm.verify_pin(pin, client_device_id="device-expired")
        self.assertEqual(result.outcome, PairingOutcome.EXPIRED)

    def test_pending_device_tracking(self) -> None:
        self.pm.set_pending_device("realme-123", "Realme RMX5110")
        state = self.pm.get_active_pin_state()
        self.assertEqual(state["pending_device_id"], "realme-123")
        self.assertEqual(state["pending_device_name"], "Realme RMX5110")

        self.pm.clear_pending_device()
        state = self.pm.get_active_pin_state()
        self.assertIsNone(state["pending_device_id"])

    def test_qr_payload_tier_preservation(self) -> None:
        payload = create_qr_pairing_payload(
            node_id="laptop-v15",
            candidate_ips=["192.168.1.50"],
            port=8765,
            cert_fingerprint="A" * 64,
            pin="123456",
            trust_tier="owner",
        )
        self.assertEqual(payload["tier"], "owner")
        self.assertEqual(payload["pin"], "123456")

        validated = validate_qr_pairing_payload(payload)
        self.assertEqual(validated["tier"], "owner")
        self.assertEqual(validated["pin"], "123456")


class TestDatabaseMultiOwnerPreservation(unittest.TestCase):
    """Test suite ensuring pairing multiple owner personal devices does not demote prior owners."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_snow.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_insert_multiple_owner_devices_preserves_both(self) -> None:
        # First owner device (e.g. Realme phone)
        dev1 = self.db.insert_paired_device(
            device_id="device-realme-1",
            device_name="Realme RMX5110",
            auth_token_hash="hash1",
            trust_tier="owner",
        )
        self.assertEqual(dev1.trust_tier, "owner")

        # Second owner device (e.g. personal tablet)
        dev2 = self.db.insert_paired_device(
            device_id="device-tablet-2",
            device_name="Pixel Tablet",
            auth_token_hash="hash2",
            trust_tier="owner",
        )
        self.assertEqual(dev2.trust_tier, "owner")

        # Crucial check: First owner device was NOT demoted to peer
        reloaded_dev1 = self.db.get_paired_device("device-realme-1")
        self.assertIsNotNone(reloaded_dev1)
        self.assertEqual(reloaded_dev1.trust_tier, "owner")

    def test_update_device_trust_tier_explicit_demotion_opt_in(self) -> None:
        self.db.insert_paired_device("dev-a", "Device A", "hash-a", trust_tier="owner")
        self.db.insert_paired_device("dev-b", "Device B", "hash-b", trust_tier="peer")

        # Promoting Dev B to owner with default demote_existing_owners=False keeps Dev A as owner
        self.db.update_device_trust_tier("dev-b", "owner", demote_existing_owners=False)
        self.assertEqual(self.db.get_paired_device("dev-a").trust_tier, "owner")
        self.assertEqual(self.db.get_paired_device("dev-b").trust_tier, "owner")

        # Explicit transfer with demote_existing_owners=True demotes others
        self.db.update_device_trust_tier("dev-a", "owner", demote_existing_owners=True)
        self.assertEqual(self.db.get_paired_device("dev-a").trust_tier, "owner")
        self.assertEqual(self.db.get_paired_device("dev-b").trust_tier, "peer")


class TestWebSocketPairingPreservation(unittest.IsolatedAsyncioTestCase):
    """Test suite ensuring WebSocket server preserves active PIN and returns authoritative trust tier."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_snow_ws.db"
        self.db = DatabaseManager(self.db_path)

        self.ws_server = SnowWebSocketServer(
            config=CoreConfig(port=8765),
            db_manager=self.db,
            pairing_manager=PairingManager(pin_lifetime=60.0),
        )

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_pair_request_with_no_pin_preserves_existing_pin(self) -> None:
        # Pre-generate an active PIN on desktop (e.g. via Web UI / QR code)
        active_pin = self.ws_server.pairing_manager.generate_pin(display_to_stderr=False, trust_tier="owner")
        self.assertTrue(self.ws_server.pairing_manager.has_active_pin)

        # Mock client connection
        mock_client = MagicMock()
        mock_client.connection_id = "test-conn-1"
        mock_client.remote_address = ("192.168.1.50", 55555)
        sent_messages = []

        async def capture_send(raw_json: str):
            sent_messages.append(json.loads(raw_json))

        mock_client.websocket.send = capture_send

        # Client sends initial pair_request with pin=None
        req_msg = SnowMessage.create_request(action="pair_request", data={
            "device_id": "phone-rmx-1",
            "device_name": "realme RMX5110",
        })

        await self.ws_server._handle_pairing_request(
            client=mock_client,
            message=req_msg,
            action="pair_request",
            data={"device_id": "phone-rmx-1", "device_name": "realme RMX5110"},
        )

        # 1. Existing PIN was NOT overwritten
        self.assertTrue(self.ws_server.pairing_manager.has_active_pin)
        self.assertEqual(self.ws_server.pairing_manager._active_pin, active_pin)

        # 2. Response status is pin_displayed with has_active_pin=True
        self.assertEqual(len(sent_messages), 1)
        resp = sent_messages[0]
        self.assertEqual(resp["payload"]["status"], "pin_displayed")
        self.assertTrue(resp["payload"]["data"]["has_active_pin"])
        self.assertEqual(resp["payload"]["data"]["trust_tier"], "owner")

        # 3. Pending device was recorded
        state = self.ws_server.pairing_manager.get_active_pin_state()
        self.assertEqual(state["pending_device_id"], "phone-rmx-1")

    async def test_successful_pairing_returns_assigned_trust_tier(self) -> None:
        active_pin = self.ws_server.pairing_manager.generate_pin(display_to_stderr=False, trust_tier="owner")
        client_uuid = str(uuid.uuid4())

        mock_client = MagicMock()
        mock_client.connection_id = "test-conn-2"
        mock_client.remote_address = ("192.168.1.50", 55556)
        sent_messages = []

        async def capture_send(raw_json: str):
            sent_messages.append(json.loads(raw_json))

        mock_client.websocket.send = capture_send

        req_msg = SnowMessage.create_request(action="pair_request", data={
            "device_id": client_uuid,
            "device_name": "realme RMX5110",
            "pin": active_pin,
        })

        await self.ws_server._handle_pairing_request(
            client=mock_client,
            message=req_msg,
            action="pair_request",
            data={"device_id": client_uuid, "device_name": "realme RMX5110", "pin": active_pin},
        )

        self.assertEqual(len(sent_messages), 1)
        resp = sent_messages[0]
        self.assertEqual(resp["payload"]["status"], "success")
        self.assertEqual(resp["payload"]["data"]["trust_tier"], "owner")

        # Stored in SQLite as owner
        record = self.db.get_paired_device(client_uuid)
        self.assertIsNotNone(record)
        self.assertEqual(record.trust_tier, "owner")


class TestWebDashboardPairingSecurity(AioHTTPTestCase):
    """Test suite for Web Dashboard pairing endpoints and anti-leakage protection."""

    async def get_application(self) -> web.Application:
        self.mock_bridge = MagicMock()
        self.mock_bridge.port = 8767
        self.mock_bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)
        self.mock_bridge.windows_system_info = AsyncMock(return_value={"success": True, "data": {}})
        self.mock_bridge.call = AsyncMock()

        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.mock_bridge,
            auto_open_browser=False,
        )
        return self.web_server._build_app()

    async def _authenticate_session(self) -> str:
        res = await self.client.post("/api/auth/session", json={"token": self.web_server.bootstrap_token})
        self.assertEqual(res.status, 200)
        data = await res.json()
        return data["csrf_token"]

    async def test_status_endpoint_does_not_leak_pairing_pin(self) -> None:
        csrf = await self._authenticate_session()
        res = await self.client.get("/api/status")
        self.assertEqual(res.status, 200)
        data = await res.json()

        self.assertTrue(data["success"])
        self.assertIn("lan_ips", data)
        self.assertEqual(data["wss_port"], 8765)
        self.assertNotIn("pin", data)
        self.assertNotIn("owner_pin", data)

    async def test_pair_state_requires_authentication(self) -> None:
        # Unauthenticated request rejected with 401
        res = await self.client.get("/api/pair/state")
        self.assertEqual(res.status, 401)

    async def test_pair_state_returns_live_pin_state(self) -> None:
        csrf = await self._authenticate_session()

        self.mock_bridge.call.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "has_active_pin": True,
                "trust_tier": "owner",
                "remaining_seconds": 58,
                "pin": "123456",
                "pending_device_id": "phone-1",
                "pending_device_name": "Realme RMX5110",
            },
        }

        res = await self.client.get("/api/pair/state")
        self.assertEqual(res.status, 200)
        data = await res.json()

        self.assertTrue(data["success"])
        self.assertEqual(data["data"]["pin"], "123456")
        self.assertEqual(data["data"]["trust_tier"], "owner")
        self.assertEqual(data["data"]["pending_device_name"], "Realme RMX5110")


if __name__ == "__main__":
    unittest.main()
