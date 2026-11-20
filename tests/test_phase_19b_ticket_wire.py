"""Wire-level integration test suite for SNOW Phase 19B two-step terminal confirmation.

Verifies the end-to-end confirmation ticket lifecycle across the WebSocket wire:
1. Step 1: Initial Tier C command from an authenticated OWNER_MANUAL client
   returns CONFIRMATION_REQUIRED with a server-issued single-use confirmation ticket.
2. Step 2: Resubmitting the same command with the ticket executes successfully.
3. Step 3: Replaying the consumed ticket is strictly rejected (single-use semantics).
4. Command mismatch: A ticket issued for Command A cannot authorize Command B.
5. Expired tickets are rejected.
6. Fabricated/invalid tickets are rejected.
7. Unconfirmed requests without the confirmed flag are rejected at the protocol layer.
8. Catastrophic Tier D commands are blocked with POLICY_DENIED even for the owner.
9. Peer devices (AI_MCP principal) are strictly denied for Tier C commands.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import AsyncMock

from snow.core.config import CoreConfig
from snow.network.connection_manager import ConnectionManager
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.protocol.validator import validate_raw_message
from snow.security.db import DatabaseManager, hash_token
from snow.security.session import SessionManager


class MockWsClient:
    """Mock WebSocket client connection recording wire-level transmissions."""

    def __init__(self, connection_id: str = "conn-p19b-owner") -> None:
        self.connection_id = connection_id
        self.remote_address = ("127.0.0.1", 54321)
        self.websocket = AsyncMock()
        self.sent_messages: list[SnowMessage] = []

        async def _mock_send(raw_text: str) -> None:
            msg = validate_raw_message(raw_text)
            self.sent_messages.append(msg)

        self.websocket.send = AsyncMock(side_effect=_mock_send)


class TestPhase19BTicketWireIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration test suite for the Phase 19B confirmation ticket wire protocol."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_p19b_wire_")
        self.db_path = Path(self.temp_dir) / "test_devices.db"
        self.transfer_dir = Path(self.temp_dir) / "transfers"
        self.transfer_dir.mkdir(parents=True, exist_ok=True)

        self.config = CoreConfig(
            port=8765,
            bind_host="127.0.0.1",
            auth_required=True,
            tls_enabled=False,
            transfer_root=str(self.transfer_dir),
        )

        self.db_manager = DatabaseManager(db_path=self.db_path)
        self.connection_manager = ConnectionManager()
        self.session_manager = SessionManager()

        self.server = SnowWebSocketServer(
            config=self.config,
            connection_manager=self.connection_manager,
            db_manager=self.db_manager,
            session_manager=self.session_manager,
        )

        # Owner device setup
        self.owner_device_id = "device-owner-p19b"
        self.owner_token = "secret-owner-token-p19b"
        self.db_manager.insert_paired_device(
            device_id=self.owner_device_id,
            device_name="Owner Android Phone",
            auth_token_hash=hash_token(self.owner_token),
            trust_tier="owner",
        )
        self.server.capability_policy.grant_capability(self.owner_device_id, "desktop.exec")

        # Peer device setup
        self.peer_device_id = "device-peer-p19b"
        self.peer_token = "secret-peer-token-p19b"
        self.db_manager.insert_paired_device(
            device_id=self.peer_device_id,
            device_name="Peer Android Phone",
            auth_token_hash=hash_token(self.peer_token),
            trust_tier="peer",
        )
        self.server.capability_policy.grant_capability(self.peer_device_id, "desktop.exec")

        # Register owner connection
        self.client = MockWsClient(connection_id="conn-p19b-owner")
        self.connection_manager.register(self.client)
        self.session_manager.create_session(
            device_id=self.owner_device_id,
            connection_id=self.client.connection_id,
        )

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. Step 1: Initial Tier C request generates confirmation ticket
    # -------------------------------------------------------------------------

    async def test_step1_initial_tier_c_requires_confirmation_and_issues_ticket(self) -> None:
        """Step 1: First invocation of Tier C command yields CONFIRMATION_REQUIRED and ticket."""
        cmd = 'powershell.exe -Command "Write-Output wire_step1_ok"'
        req = SnowMessage.create_request(
            "desktop_exec",
            {"command": cmd, "confirmed": True},
        )
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.RESPONSE)
        payload = resp.payload
        self.assertEqual(payload.get("action"), "desktop_exec")

        data = payload.get("data", {})
        self.assertEqual(data.get("status"), "CONFIRMATION_REQUIRED")
        ticket = data.get("confirmation_ticket")
        self.assertIsInstance(ticket, str)
        self.assertEqual(len(ticket), 32)
        # Verify no execution occurred yet
        self.assertIsNone(data.get("exit_code"))
        self.assertEqual(data.get("stdout"), "")

    # -------------------------------------------------------------------------
    # 2. Step 2: Resubmission with valid ticket executes command
    # -------------------------------------------------------------------------

    async def test_step2_resubmit_with_ticket_executes_successfully(self) -> None:
        """Step 2: Resubmission with the server-issued ticket executes and returns stdout."""
        cmd = 'cmd /c echo wire_step2_executed'

        # Step 1: Get ticket
        req1 = SnowMessage.create_request("desktop_exec", {"command": cmd, "confirmed": True})
        await self.server._handle_request(self.client, req1)
        ticket = self.client.sent_messages[-1].payload["data"]["confirmation_ticket"]

        # Step 2: Resubmit with ticket
        req2 = SnowMessage.create_request(
            "desktop_exec",
            {"command": cmd, "confirmed": True, "confirmation_ticket": ticket},
        )
        await self.server._handle_request(self.client, req2)

        resp2 = self.client.sent_messages[-1]
        self.assertEqual(resp2.type, MessageType.RESPONSE)
        payload2 = resp2.payload
        self.assertEqual(payload2.get("status"), "success")
        data2 = payload2.get("data", {})
        self.assertEqual(data2.get("status"), "SUCCESS")
        self.assertEqual(data2.get("exit_code"), 0)
        self.assertIn("wire_step2_executed", data2.get("stdout", ""))

    # -------------------------------------------------------------------------
    # 3. Step 3: Ticket replay is rejected
    # -------------------------------------------------------------------------

    async def test_step3_ticket_replay_rejected(self) -> None:
        """Step 3: Replaying an already-consumed ticket fails and does not execute."""
        cmd = 'cmd /c echo wire_replay_attempt'

        # Step 1: Get ticket
        req1 = SnowMessage.create_request("desktop_exec", {"command": cmd, "confirmed": True})
        await self.server._handle_request(self.client, req1)
        ticket = self.client.sent_messages[-1].payload["data"]["confirmation_ticket"]

        # Step 2: Consume ticket
        req2 = SnowMessage.create_request(
            "desktop_exec",
            {"command": cmd, "confirmed": True, "confirmation_ticket": ticket},
        )
        await self.server._handle_request(self.client, req2)
        self.assertEqual(self.client.sent_messages[-1].payload["data"]["status"], "SUCCESS")

        # Step 3: Replay same ticket
        req3 = SnowMessage.create_request(
            "desktop_exec",
            {"command": cmd, "confirmed": True, "confirmation_ticket": ticket},
        )
        await self.server._handle_request(self.client, req3)

        resp3 = self.client.sent_messages[-1]
        data3 = resp3.payload.get("data", {})
        self.assertEqual(data3.get("status"), "CONFIRMATION_REQUIRED")
        self.assertIsNone(data3.get("exit_code"))

    # -------------------------------------------------------------------------
    # 4. Command Mismatch Rejection
    # -------------------------------------------------------------------------

    async def test_ticket_with_different_command_rejected(self) -> None:
        """A ticket issued for Command A cannot authorize Command B."""
        cmd_a = 'cmd /c echo original_command'
        cmd_b = 'cmd /c echo hijacked_command'

        # Request ticket for cmd_a
        req1 = SnowMessage.create_request("desktop_exec", {"command": cmd_a, "confirmed": True})
        await self.server._handle_request(self.client, req1)
        ticket = self.client.sent_messages[-1].payload["data"]["confirmation_ticket"]

        # Attempt to redeem ticket for cmd_b
        req2 = SnowMessage.create_request(
            "desktop_exec",
            {"command": cmd_b, "confirmed": True, "confirmation_ticket": ticket},
        )
        await self.server._handle_request(self.client, req2)

        resp2 = self.client.sent_messages[-1]
        data2 = resp2.payload.get("data", {})
        self.assertEqual(data2.get("status"), "CONFIRMATION_REQUIRED")
        self.assertIsNone(data2.get("exit_code"))
        self.assertEqual(data2.get("stdout"), "")

    # -------------------------------------------------------------------------
    # 5. Expired Ticket Rejection
    # -------------------------------------------------------------------------

    async def test_expired_ticket_rejected(self) -> None:
        """An expired confirmation ticket is strictly rejected."""
        cmd = 'cmd /c echo expired_test'

        req1 = SnowMessage.create_request("desktop_exec", {"command": cmd, "confirmed": True})
        await self.server._handle_request(self.client, req1)
        ticket = self.client.sent_messages[-1].payload["data"]["confirmation_ticket"]

        # Force ticket expiration
        self.server.capability_engine._tickets[ticket]["expires_at"] = time.monotonic() - 1.0

        # Resubmit with expired ticket
        req2 = SnowMessage.create_request(
            "desktop_exec",
            {"command": cmd, "confirmed": True, "confirmation_ticket": ticket},
        )
        await self.server._handle_request(self.client, req2)

        resp2 = self.client.sent_messages[-1]
        data2 = resp2.payload.get("data", {})
        self.assertEqual(data2.get("status"), "CONFIRMATION_REQUIRED")
        self.assertIsNone(data2.get("exit_code"))

    # -------------------------------------------------------------------------
    # 6. Fabricated / Bogus Ticket Rejection
    # -------------------------------------------------------------------------

    async def test_fabricated_ticket_rejected(self) -> None:
        """A fabricated or unissued ticket string is rejected."""
        cmd = 'cmd /c echo bogus_ticket_test'
        req = SnowMessage.create_request(
            "desktop_exec",
            {"command": cmd, "confirmed": True, "confirmation_ticket": "deadbeefcafebabe1234567890abcdef"},
        )
        await self.server._handle_request(self.client, req)

        resp = self.client.sent_messages[-1]
        data = resp.payload.get("data", {})
        self.assertEqual(data.get("status"), "CONFIRMATION_REQUIRED")
        self.assertIsNone(data.get("exit_code"))

    # -------------------------------------------------------------------------
    # 7. Unconfirmed Request Rejection at Protocol Layer
    # -------------------------------------------------------------------------

    async def test_unconfirmed_request_rejected_at_protocol_layer(self) -> None:
        """desktop_exec without confirmed: true is rejected immediately with UNAUTHORIZED."""
        cmd = 'cmd /c echo unconfirmed_test'
        req = SnowMessage.create_request("desktop_exec", {"command": cmd})
        await self.server._handle_request(self.client, req)

        resp = self.client.sent_messages[-1]
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertIsNotNone(resp.error)
        self.assertEqual(resp.error.get("code"), ErrorCode.UNAUTHORIZED)
        self.assertIn("confirmation", resp.error.get("message", "").lower())

    # -------------------------------------------------------------------------
    # 8. Catastrophic Command Blocked Even for Owner with Ticket
    # -------------------------------------------------------------------------

    async def test_catastrophic_command_blocked_for_owner_even_with_ticket(self) -> None:
        """Tier D catastrophic destructive commands are blocked with POLICY_DENIED even for owner."""
        catastrophic_cmds = [
            "format c: /fs:ntfs /q",
            "diskpart /s script.txt",
            "del /f /q C:\\Windows\\System32",
            "rmdir /s /q C:\\Windows",
            "del /f /q C:\\Users\\user\\.snow\\server.key",
        ]

        for cat_cmd in catastrophic_cmds:
            self.client.sent_messages.clear()
            req = SnowMessage.create_request(
                "desktop_exec",
                {
                    "command": cat_cmd,
                    "confirmed": True,
                    "confirmation_ticket": "any_ticket_value",
                },
            )
            await self.server._handle_request(self.client, req)

            self.assertEqual(len(self.client.sent_messages), 1)
            resp = self.client.sent_messages[0]
            data = resp.payload.get("data", {})
            self.assertEqual(
                data.get("status"),
                "POLICY_DENIED",
                f"Catastrophic command '{cat_cmd}' was not blocked with POLICY_DENIED",
            )
            self.assertIsNone(data.get("exit_code"))

    # -------------------------------------------------------------------------
    # 9. Peer Device (AI_MCP) Denied for Tier C Commands
    # -------------------------------------------------------------------------

    async def test_peer_principal_denied_for_tier_c_command(self) -> None:
        """A paired peer device (non-owner) cannot execute Tier C commands."""
        peer_client = MockWsClient(connection_id="conn-p19b-peer")
        self.connection_manager.register(peer_client)
        self.session_manager.create_session(
            device_id=self.peer_device_id,
            connection_id=peer_client.connection_id,
        )

        cmd = "taskkill /f /im notepad.exe"
        req = SnowMessage.create_request(
            "desktop_exec",
            {"command": cmd, "confirmed": True},
        )
        await self.server._handle_request(peer_client, req)

        self.assertEqual(len(peer_client.sent_messages), 1)
        resp = peer_client.sent_messages[0]
        data = resp.payload.get("data", {})
        self.assertEqual(data.get("status"), "POLICY_DENIED")
        self.assertIsNone(data.get("exit_code"))


if __name__ == "__main__":
    unittest.main()
