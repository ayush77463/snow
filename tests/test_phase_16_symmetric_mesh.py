"""Phase 16 Integration Test Suite: Symmetric Peer-to-Peer Mesh.

Tests:
A. Windows <-> Windows symmetric peer capability routing and manifest exchange.
B. Multi-device selection for clipboard and file transfers (Laptop A -> Laptop B, Phone A -> Phone B).
C. Android <-> Android simulated direct peer routing and foreground host mode.
D. Authenticated mesh routing, peer listing, and relay security.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import tempfile
import unittest
import uuid
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.engine import (
    CapabilityEngine,
    CapabilityRequest,
    CapabilityResponse,
    ExecutionContext,
    ExecutionPrincipal,
)
from snow.core.config import CoreConfig
from snow.mcp.bridge import SnowMcpBridge
from snow.network.connection_manager import ConnectionManager
from snow.network.node import (
    CapabilityExecutionClassification,
    CapabilityManifest,
    DeviceNode,
    ReachabilityProfile,
    ReachabilityState,
    build_windows_manifest,
)
from snow.network.peer_client import PeerConnectionResult, SnowPeerClient
from snow.network.registry import NodeRegistry
from snow.network.router import ROUTER_ACTION_TO_CAPABILITY, SessionRouter
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.security.context import ExecutionContext as SecContext
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.security.policy import (
    CAPABILITY_DESKTOP_EXEC,
    CAPABILITY_DESKTOP_STATUS,
    CAPABILITY_MESH_LIST_PEERS,
    CAPABILITY_PEER_RELAY,
    DEFAULT_PAIRED_CAPABILITIES,
    PeerCapabilityPolicy,
)
from snow.security.session import SessionManager


class TestWindowsToWindowsPeerCapabilities(unittest.IsolatedAsyncioTestCase):
    """Test Windows <-> Windows federation, capability manifests, and direct execution."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_mesh_p16_")
        self.db_path = os.path.join(self.temp_dir, "test_mesh.db")
        self.db_manager = DatabaseManager(self.db_path)
        self.registry = NodeRegistry(self.db_manager)

        self.policy = PeerCapabilityPolicy(policy_file=os.path.join(self.temp_dir, "policy.json"))
        self.engine = CapabilityEngine(policy=self.policy)

        self.node_a_identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Workstation-Alpha",
            created_at="2026-11-18T00:00:00Z",
        )
        self.node_b_identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Laptop-Beta",
            created_at="2026-11-18T00:00:00Z",
        )

        self.router_a = SessionRouter(
            node_registry=self.registry,
            capability_engine=self.engine,
            db_manager=self.db_manager,
        )

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_windows_manifest_exchange_and_support_resolution(self) -> None:
        """Verify Windows manifest build, capability advertisement, and alias support."""
        manifest_b = build_windows_manifest()
        self.assertTrue(manifest_b.supports_capability("desktop.status"))
        self.assertTrue(manifest_b.supports_capability("desktop.clipboard.read"))
        self.assertTrue(manifest_b.supports_capability("desktop.clipboard.write"))
        self.assertTrue(manifest_b.supports_capability("desktop.file.list"))
        # Check bidirectional alias support
        self.assertTrue(manifest_b.supports_capability("desktop.files.list"))
        self.assertTrue(manifest_b.supports_capability("desktop.apps.launch"))
        self.assertTrue(manifest_b.supports_capability("desktop.app_launch"))

        node_b = DeviceNode(
            device_id=self.node_b_identity.device_id,
            device_name=self.node_b_identity.device_name,
            platform="windows",
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            reachability_profile=ReachabilityProfile.PERSISTENT_DAEMON,
            capabilities=manifest_b,
            is_paired=True,
        )
        self.registry.register_node(node_b)

        resolved_node, err = self.registry.resolve_target(
            "Beta", required_capability="desktop.file.list"
        )
        self.assertIsNone(err)
        self.assertIsNotNone(resolved_node)
        self.assertEqual(resolved_node.device_id, self.node_b_identity.device_id)

    async def test_router_dispatches_desktop_status_to_peer(self) -> None:
        """SessionRouter dispatches desktop_status across active peer connection."""
        node_b = DeviceNode(
            device_id=self.node_b_identity.device_id,
            device_name=self.node_b_identity.device_name,
            platform="windows",
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            reachability_profile=ReachabilityProfile.PERSISTENT_DAEMON,
            capabilities=build_windows_manifest(),
            is_paired=True,
        )
        self.registry.register_node(node_b)

        # Mock active outbound peer client
        mock_peer_client = MagicMock(spec=SnowPeerClient)
        mock_peer_client.is_connected = True

        async def fake_send_message(msg: SnowMessage, timeout: float = 30.0) -> SnowMessage:
            self.assertEqual(msg.payload.get("action"), "desktop_status")
            return SnowMessage.create_response(
                correlation_id=msg.id,
                payload={
                    "status": "success",
                    "action": "desktop_status",
                    "data": {
                        "hostname": "Laptop-Beta",
                        "cpu_percent": 15.5,
                        "memory_percent": 42.0,
                    },
                },
            )

        mock_peer_client.send_message = AsyncMock(side_effect=fake_send_message)
        self.router_a.register_outbound_client(node_b.device_id, mock_peer_client)

        res = await self.router_a.route_request("desktop_status", target=node_b.device_id)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("status"), "SUCCESS")
        self.assertIn("active_outbound_peer", res.get("attempted_transports", []))
        data = res.get("data", {})
        self.assertEqual(data.get("data", {}).get("hostname"), "Laptop-Beta")

    async def test_router_enforces_policy_denying_unauthorized_desktop_exec(self) -> None:
        """Remote desktop_exec is denied when peer lacks explicit CAPABILITY_DESKTOP_EXEC grant."""
        ws_server = SnowWebSocketServer(
            config=CoreConfig(bind_host="127.0.0.1", port=8765),
            db_manager=self.db_manager,
            node_registry=self.registry,
            device_identity=self.node_b_identity,
        )
        ws_server.capability_policy = self.policy

        # Paired device without desktop.exec grant
        self.db_manager.insert_paired_device(
            device_id=self.node_a_identity.device_id,
            device_name=self.node_a_identity.device_name,
            auth_token_hash="dummy_hash",
            trust_tier="peer",
        )

        mock_ws = AsyncMock()
        mock_client = MagicMock()
        mock_client.websocket = mock_ws
        mock_client.connection_id = "conn-alpha-1"

        session = ws_server.session_manager.create_session(
            device_id=self.node_a_identity.device_id,
            connection_id=mock_client.connection_id,
        )

        exec_msg = SnowMessage.create_request(
            action="desktop_exec",
            data={"command": "dir"},
        )

        await ws_server._handle_request(mock_client, exec_msg)

        self.assertTrue(mock_ws.send.called)
        sent_raw = mock_ws.send.call_args[0][0]
        sent_msg = json.loads(sent_raw)
        self.assertEqual(sent_msg.get("type"), "error")
        self.assertEqual(sent_msg.get("error", {}).get("code"), ErrorCode.UNAUTHORIZED)


class TestMultiDeviceOperationSelection(unittest.IsolatedAsyncioTestCase):
    """Test explicit source_device and target_device selection across heterogeneous nodes."""

    async def asyncSetUp(self) -> None:
        self.bridge = SnowMcpBridge()
        self.bridge.list_devices = AsyncMock(return_value={
            "success": True,
            "data": {
                "devices": [
                    {
                        "device_id": "laptop-a-id",
                        "device_name": "Laptop A",
                        "platform": "windows",
                        "is_paired": True,
                        "is_connected": True,
                        "capabilities": ["desktop.status", "desktop.clipboard.read", "desktop.clipboard.write"],
                    },
                    {
                        "device_id": "laptop-b-id",
                        "device_name": "Laptop B",
                        "platform": "windows",
                        "is_paired": True,
                        "is_connected": True,
                        "capabilities": ["desktop.status", "desktop.clipboard.read", "desktop.clipboard.write"],
                    },
                    {
                        "device_id": "phone-a-id",
                        "device_name": "Pixel 9 Pro",
                        "platform": "android",
                        "is_paired": True,
                        "is_connected": True,
                        "capabilities": ["android.telemetry.get", "android.clipboard.set", "android.clipboard.get"],
                    },
                ]
            }
        })

    async def test_clipboard_sync_laptop_a_to_laptop_b(self) -> None:
        """Explicit source_device='laptop-a-id', target_device='laptop-b-id' synchronizes content."""
        self.bridge.send_device_request = AsyncMock()

        # Mock source reading from Laptop A
        async def fake_device_request(device_id: str, action: str, data: dict) -> dict:
            if device_id == "laptop-a-id" and action in ("desktop_clipboard_get", "clipboard_pull"):
                return {"success": True, "data": {"text": "Hello Mesh Federation"}}
            elif device_id == "laptop-b-id" and action in ("desktop_clipboard_set", "clipboard_push"):
                return {"success": True, "data": {"written": True}}
            return {"success": False, "status": "UNKNOWN"}

        self.bridge.send_device_request.side_effect = fake_device_request

        res = await self.bridge.sync_clipboard(
            source_device="Laptop A",
            target_device="Laptop B",
        )
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("status"), "SUCCESS")
        self.assertEqual(res.get("source_device"), "laptop-a-id")
        self.assertEqual(res.get("target_device"), "laptop-b-id")
        self.assertEqual(res.get("characters_synced"), len("Hello Mesh Federation"))
        self.assertFalse(res.get("skipped_duplicate"))

        # Test idempotency: second sync with same content reports ALREADY_IN_SYNC
        res_dup = await self.bridge.sync_clipboard(
            source_device="Laptop A",
            target_device="Laptop B",
        )
        self.assertTrue(res_dup.get("success"))
        self.assertEqual(res_dup.get("status"), "ALREADY_IN_SYNC")
        self.assertTrue(res_dup.get("skipped_duplicate"))

    async def test_clipboard_sync_same_device_rejected(self) -> None:
        """Setting source_device and target_device to same node returns INVALID_ARGUMENT."""
        res = await self.bridge.sync_clipboard(
            source_device="Laptop A",
            target_device="Laptop A",
        )
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "INVALID_ARGUMENT")

    async def test_clipboard_sync_missing_or_ambiguous_device_returns_error(self) -> None:
        """Unknown or ambiguous device targets return structured errors without raising."""
        # Non-existent device
        res_missing = await self.bridge.sync_clipboard(
            source_device="NonExistentDevice",
            target_device="Laptop B",
        )
        self.assertFalse(res_missing.get("success"))
        self.assertEqual(res_missing.get("status"), "DEVICE_NOT_FOUND")

        # Ambiguous query matching multiple devices
        res_ambig = await self.bridge.sync_clipboard(
            source_device="Laptop",  # Matches Laptop A and Laptop B
            target_device="Pixel 9 Pro",
        )
        self.assertFalse(res_ambig.get("success"))
        self.assertEqual(res_ambig.get("status"), "AMBIGUOUS_DEVICE")

    async def test_file_transfer_multi_device_selection(self) -> None:
        """transfer_file with source_device='Pixel 9 Pro' routes via android_file_receive."""
        self.bridge.android_file_receive = AsyncMock(return_value={
            "success": True,
            "status": "SUCCESS",
            "data": {"destination_path": "C:\\transfers\\report.pdf", "bytes": 1024},
        })

        res = await self.bridge.transfer_file(
            source_path="report.pdf",
            source_device="Pixel 9 Pro",
            target_device="local",
        )
        self.assertTrue(res.get("success"))
        self.bridge.android_file_receive.assert_called_once_with(
            file_name="report.pdf",
            device_id="phone-a-id",
        )


class TestAndroidSimulatedDirectPeerRouting(unittest.IsolatedAsyncioTestCase):
    """Test simulated Android-to-Android foreground host discovery and direct routing."""

    async def asyncSetUp(self) -> None:
        self.db_manager = MagicMock(spec=DatabaseManager)
        self.registry = NodeRegistry(self.db_manager)
        self.router = SessionRouter(node_registry=self.registry, db_manager=self.db_manager)

        # Android node advertising FOREGROUND_HOST reachability profile
        self.android_host_node = DeviceNode(
            device_id="android-host-uuid",
            device_name="Pixel Host Device",
            platform="android",
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            reachability_profile=ReachabilityProfile.FOREGROUND_HOST,
            host="192.168.1.150",
            wss_port=8767,
            capabilities=CapabilityManifest(
                manifest_version="2.0",
                supported_capabilities=["android.telemetry.get", "android.clipboard.get"],
            ),
            is_paired=True,
        )
        self.registry.register_node(self.android_host_node)

    async def test_router_recognizes_foreground_host_profile(self) -> None:
        """SessionRouter recognizes FOREGROUND_HOST profile for outbound direct dial attempt."""
        self.router.get_peer_token = MagicMock(return_value="valid-peer-token")
        self.router._attempt_outbound_direct_dial = AsyncMock(return_value={
            "success": True,
            "status": "SUCCESS",
            "data": {"level": 92, "is_charging": False},
            "target_device_id": self.android_host_node.device_id,
            "attempted_transports": ["outbound_direct"],
        })

        res = await self.router.route_request(
            action="battery_status",
            target=self.android_host_node.device_id,
        )
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("status"), "SUCCESS")
        self.router._attempt_outbound_direct_dial.assert_called_once()

    async def test_unreachable_android_host_returns_structured_device_unreachable(self) -> None:
        """When Android host endpoint cannot be dialed, router returns structured DEVICE_UNREACHABLE."""
        self.router._attempt_outbound_direct_dial = AsyncMock(return_value=None)

        res = await self.router.route_request(
            action="battery_status",
            target=self.android_host_node.device_id,
        )
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "DEVICE_UNREACHABLE")
        self.assertIn("outbound_direct", res.get("attempted_transports", []))


class TestMeshPeerListingAndRelaySecurity(unittest.IsolatedAsyncioTestCase):
    """Test mesh_list_peers sanitization and peer_relay_request security invariants."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_relay_p16_")
        self.db_path = os.path.join(self.temp_dir, "test_relay.db")
        self.db_manager = DatabaseManager(self.db_path)
        self.registry = NodeRegistry(self.db_manager)
        self.policy = PeerCapabilityPolicy(policy_file=os.path.join(self.temp_dir, "policy.json"))

        self.local_identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Central Coordinator",
            created_at="2026-11-18T00:00:00Z",
        )

        self.server = SnowWebSocketServer(
            config=CoreConfig(bind_host="127.0.0.1", port=8765),
            db_manager=self.db_manager,
            node_registry=self.registry,
            device_identity=self.local_identity,
        )
        self.server.capability_policy = self.policy

        # Register target node in mesh
        self.target_node = DeviceNode(
            device_id="target-leaf-node-uuid",
            device_name="Leaf Sensor Node",
            platform="android",
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            reachability_profile=ReachabilityProfile.ACTIVE_SESSION_PEER,
            capabilities=CapabilityManifest(
                manifest_version="2.0",
                supported_capabilities=["android.telemetry.get"],
            ),
            is_paired=True,
        )
        self.registry.register_node(self.target_node)

        # Register caller peer in database and session
        self.caller_id = "caller-peer-uuid"
        self.db_manager.insert_paired_device(
            device_id=self.caller_id,
            device_name="Originating Peer",
            auth_token_hash="hash-caller",
            trust_tier="peer",
        )

        self.mock_ws = AsyncMock()
        self.client_conn = MagicMock()
        self.client_conn.websocket = self.mock_ws
        self.client_conn.connection_id = "conn-caller-1"

        self.session = self.server.session_manager.create_session(
            device_id=self.caller_id,
            connection_id=self.client_conn.connection_id,
        )

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_mesh_list_peers_redacts_credentials(self) -> None:
        """mesh_list_peers returns sanitized node descriptors without tokens or secrets."""
        msg = SnowMessage.create_request(action="mesh_list_peers", data={})
        await self.server._handle_request(self.client_conn, msg)

        self.assertTrue(self.mock_ws.send.called)
        sent = json.loads(self.mock_ws.send.call_args[0][0])
        self.assertEqual(sent.get("type"), "response")
        payload = sent.get("payload", {})
        self.assertEqual(payload.get("status"), "success")
        peers = payload.get("data", {}).get("peers", [])
        self.assertGreaterEqual(len(peers), 1)

        for p in peers:
            self.assertIn("device_id", p)
            self.assertIn("device_name", p)
            self.assertIn("supported_capabilities", p)
            # Guarantee zero credential exposure
            self.assertNotIn("auth_token", p)
            self.assertNotIn("pairing_token", p)
            self.assertNotIn("private_key", p)
            self.assertNotIn("file_path", p)

    async def test_peer_relay_prevents_routing_loops(self) -> None:
        """peer_relay_request detects visited local host and rejects with ROUTING_LOOP_DETECTED."""
        msg = SnowMessage.create_request(
            action="peer_relay_request",
            data={
                "target_device_id": self.target_node.device_id,
                "action": "battery_status",
                "visited_nodes": [self.local_identity.device_id],  # Local node already visited
            },
        )
        await self.server._handle_request(self.client_conn, msg)

        self.assertTrue(self.mock_ws.send.called)
        sent = json.loads(self.mock_ws.send.call_args[0][0])
        self.assertEqual(sent.get("type"), "error")
        self.assertIn("loop", sent.get("error", {}).get("message", "").lower())

    async def test_peer_relay_enforces_hop_limit(self) -> None:
        """peer_relay_request rejects request when hop_limit <= 0."""
        msg = SnowMessage.create_request(
            action="peer_relay_request",
            data={
                "target_device_id": self.target_node.device_id,
                "action": "battery_status",
                "hop_limit": 0,
            },
        )
        await self.server._handle_request(self.client_conn, msg)

        self.assertTrue(self.mock_ws.send.called)
        sent = json.loads(self.mock_ws.send.call_args[0][0])
        self.assertEqual(sent.get("type"), "error")
        self.assertIn("hop limit", sent.get("error", {}).get("message", "").lower())

    async def test_peer_relay_rejects_oversized_payload(self) -> None:
        """peer_relay_request rejects payloads exceeding 64KB boundary."""
        huge_data = {"chunk": "X" * 70000}
        msg = SnowMessage.create_request(
            action="peer_relay_request",
            data={
                "target_device_id": self.target_node.device_id,
                "action": "battery_status",
                "data": huge_data,
            },
        )
        await self.server._handle_request(self.client_conn, msg)

        self.assertTrue(self.mock_ws.send.called)
        sent = json.loads(self.mock_ws.send.call_args[0][0])
        self.assertEqual(sent.get("type"), "error")
        self.assertEqual(sent.get("error", {}).get("code"), ErrorCode.INVALID_PAYLOAD)

    async def test_peer_relay_strips_caller_authority_spoofing(self) -> None:
        """peer_relay_request strips spoofed principal claims and executes under PEER authority."""
        # Request relay to local coordinator itself
        msg = SnowMessage.create_request(
            action="peer_relay_request",
            data={
                "target_device_id": self.local_identity.device_id,
                "action": "desktop_status",
                "data": {
                    "principal": "OWNER_MANUAL",  # Attempted privilege escalation
                    "trust_tier": "owner",
                },
            },
        )
        await self.server._handle_request(self.client_conn, msg)

        self.assertTrue(self.mock_ws.send.called)
        sent = json.loads(self.mock_ws.send.call_args[0][0])
        self.assertEqual(sent.get("type"), "response")
        payload = sent.get("payload", {})
        self.assertEqual(payload.get("status"), "success")
        self.assertEqual(payload.get("action"), "peer_relay_request")
        self.assertEqual(payload.get("relayed_by"), self.local_identity.device_id)


if __name__ == "__main__":
    unittest.main()
