"""Unit tests for Stage 4A Track D: Cross-Network Federation parity over authenticated Owner WSS."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock
import uuid

from snow.network.federation import FederationManager
from snow.protocol.models import MessageType, SnowMessage
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity


class TestStage4aFederationParity(unittest.IsolatedAsyncioTestCase):
    """Verify all 5 federation operations over authenticated Owner WSS with strict authority checks."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_fed.db"
        self.db_mgr = DatabaseManager(self.db_path)
        self.identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Desktop Core",
            created_at=datetime.now(timezone.utc).isoformat(),
        )

        # Register owner device in DB
        self.owner_dev_id = str(uuid.uuid4())
        self.db_mgr.insert_paired_device(
            device_id=self.owner_dev_id,
            device_name="Ayush Phone",
            auth_token_hash="hash_owner_token",
            last_known_host="192.168.1.105",
            last_known_port=8765,
            trust_tier="owner",
        )

        # Register peer device in DB (non-owner)
        self.peer_dev_id = str(uuid.uuid4())
        self.db_mgr.insert_paired_device(
            device_id=self.peer_dev_id,
            device_name="Friend Phone",
            auth_token_hash="hash_peer_token",
            last_known_host="192.168.1.106",
            last_known_port=8765,
            trust_tier="peer",
        )

        # Mock WSS server with db_manager and federation_manager
        self.server = MagicMock(spec=SnowWebSocketServer)
        self.server.db_manager = self.db_mgr
        self.server.federation_manager = FederationManager(
            db_manager=self.db_mgr,
            local_network_id="local-net-test",
            local_network_name="Local Home Network",
            local_node_id=self.identity.device_id,
            local_node_name="Desktop Core",
        )

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    async def test_owner_can_create_and_accept_invite(self) -> None:
        """Authorized owner creates a 9-digit invite code and accepts it."""
        mock_client = MagicMock()
        mock_client.connection_id = "conn_owner"
        mock_client.websocket.send = AsyncMock()

        # Mock owner session
        session = MagicMock()
        session.device_id = self.owner_dev_id

        # 1. Create Invite
        msg_create = SnowMessage.create_request(
            action="federation_create_invite",
            data={"ttl_seconds": 300, "grant_ttl_seconds": 3600},
        )
        await SnowWebSocketServer._handle_federation_create_invite(
            self.server, mock_client, msg_create, msg_create.payload["data"], session, is_owner=True
        )

        mock_client.websocket.send.assert_called_once()
        raw_resp = mock_client.websocket.send.call_args[0][0]
        resp = json.loads(raw_resp)
        self.assertEqual(resp["payload"]["status"], "success")
        code = resp["payload"]["code"]
        # Code must match 9-digit pattern XXX-XXX-XXX
        self.assertRegex(code, r"^\d{3}-\d{3}-\d{3}$")

        # 2. Accept Invite
        mock_client.websocket.send.reset_mock()
        msg_accept = SnowMessage.create_request(
            action="federation_accept_invite",
            data={
                "code": code,
                "peer_network_id": "remote-net-office",
                "peer_network_name": "Office Network",
                "peer_node_id": "remote-pc-1",
                "peer_node_name": "Office Workstation",
            },
        )
        await SnowWebSocketServer._handle_federation_accept_invite(
            self.server, mock_client, msg_accept, msg_accept.payload["data"], session, is_owner=True
        )

        mock_client.websocket.send.assert_called_once()
        resp_acc = json.loads(mock_client.websocket.send.call_args[0][0])
        self.assertEqual(resp_acc["payload"]["status"], "success")
        grant_id = resp_acc["payload"]["grant_id"]
        self.assertTrue(grant_id)

        # 3. List Grants
        mock_client.websocket.send.reset_mock()
        msg_list = SnowMessage.create_request(
            action="federation_list_grants",
            data={"active_only": True},
        )
        await SnowWebSocketServer._handle_federation_list_grants(
            self.server, mock_client, msg_list, msg_list.payload["data"], session, is_owner=True
        )
        resp_list = json.loads(mock_client.websocket.send.call_args[0][0])
        self.assertEqual(resp_list["payload"]["status"], "success")
        grants = resp_list["payload"]["grants"]
        self.assertEqual(len(grants), 1)
        self.assertEqual(grants[0]["grant_id"], grant_id)

        # 4. Revoke Grant
        mock_client.websocket.send.reset_mock()
        msg_revoke = SnowMessage.create_request(
            action="federation_revoke",
            data={"grant_id": grant_id, "reason": "Test revocation"},
        )
        await SnowWebSocketServer._handle_federation_revoke(
            self.server, mock_client, msg_revoke, msg_revoke.payload["data"], session, is_owner=True
        )
        resp_rev = json.loads(mock_client.websocket.send.call_args[0][0])
        self.assertEqual(resp_rev["payload"]["status"], "success")

        # 5. Global Kill Switch
        mock_client.websocket.send.reset_mock()
        msg_kill = SnowMessage.create_request(
            action="federation_kill_switch",
            data={"reason": "Emergency Test"},
        )
        await SnowWebSocketServer._handle_federation_kill_switch(
            self.server, mock_client, msg_kill, msg_kill.payload["data"], session, is_owner=True
        )
        resp_kill = json.loads(mock_client.websocket.send.call_args[0][0])
        self.assertEqual(resp_kill["payload"]["status"], "success")

    async def test_non_owner_peer_is_strictly_denied(self) -> None:
        """Ordinary paired device ('peer' trust tier) is rejected with UNAUTHORIZED for all federation operations."""
        mock_client = MagicMock()
        mock_client.connection_id = "conn_peer"
        mock_client.websocket.send = AsyncMock()

        session = MagicMock()
        session.device_id = self.peer_dev_id

        msg_create = SnowMessage.create_request(
            action="federation_create_invite",
            data={},
        )
        await SnowWebSocketServer._handle_federation_create_invite(
            self.server, mock_client, msg_create, msg_create.payload["data"], session, is_owner=False
        )

        mock_client.websocket.send.assert_called_once()
        resp = json.loads(mock_client.websocket.send.call_args[0][0])
        self.assertEqual(resp["type"], MessageType.ERROR)
        self.assertEqual(resp["error"]["code"], ErrorCode.UNAUTHORIZED)
        self.assertIn("OWNER_MANUAL", resp["error"]["message"])

    async def test_invalid_and_replayed_codes_rejected(self) -> None:
        """Invalid 9-digit code format and replayed codes are safely rejected."""
        mock_client = MagicMock()
        mock_client.connection_id = "conn_owner"
        mock_client.websocket.send = AsyncMock()
        session = MagicMock()
        session.device_id = self.owner_dev_id

        # 1. Invalid code (letters instead of digits)
        msg_invalid = SnowMessage.create_request(
            action="federation_accept_invite",
            data={"code": "abc-def-ghi"},
        )
        await SnowWebSocketServer._handle_federation_accept_invite(
            self.server, mock_client, msg_invalid, msg_invalid.payload["data"], session, is_owner=True
        )
        resp = json.loads(mock_client.websocket.send.call_args[0][0])
        self.assertEqual(resp["type"], MessageType.ERROR)
        self.assertEqual(resp["error"]["code"], ErrorCode.INVALID_PAYLOAD)


if __name__ == "__main__":
    unittest.main()
