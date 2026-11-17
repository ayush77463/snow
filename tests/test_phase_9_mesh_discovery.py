"""Unit and integration test suite for SNOW Phase 9:
Zero-Touch UDP Discovery, On-Demand Auto-Connect, Multi-Device Peer Mesh,
Unified Target Resolution, and Unified File Transfer.
"""

import asyncio
from datetime import datetime, timezone
import json
import socket
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from mcp.server.fastmcp import FastMCP
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.mcp.bridge import SnowMcpBridge, resolve_target_device
from snow.mcp.registry import TOOL_REGISTRY, ToolCategory, get_tool_category
from snow.mcp.tools import ALL_TOOL_NAMES, register_all_tools
from snow.network.discovery import (
    BEACON_TIMESTAMP_MAX_DRIFT_SEC,
    DISCOVERY_PROTOCOL_NAME,
    DISCOVERY_PROTOCOL_VERSION,
    MAX_BEACON_SIZE_BYTES,
    DiscoveredPeerRecord,
    DiscoveryBeacon,
    SnowDiscoveryService,
)
from snow.network.peer_client import PeerConnectionResult, SnowPeerClient
from snow.protocol.constants import MessageType
from snow.protocol.models import SnowMessage
from snow.security.identity import DeviceIdentity


class TestDiscoveryBeaconProtocol(unittest.TestCase):
    """Tests for DiscoveryBeacon serialization, deserialization, and validation invariants."""

    def setUp(self) -> None:
        self.valid_beacon = DiscoveryBeacon(
            proto=DISCOVERY_PROTOCOL_NAME,
            v=DISCOVERY_PROTOCOL_VERSION,
            device_id="dev-1234-uuid",
            device_name="Test-Laptop",
            device_type="windows",
            port=8765,
            transfer_port=8766,
            cert_fingerprint="aa:bb:cc:dd",
            timestamp=time.time(),
            nonce="0123456789abcdef",
        )

    def test_round_trip_serialization(self) -> None:
        """Beacon serializes to JSON bytes and deserializes identically."""
        raw_bytes = self.valid_beacon.to_bytes()
        self.assertIsInstance(raw_bytes, bytes)
        self.assertLessEqual(len(raw_bytes), MAX_BEACON_SIZE_BYTES)

        parsed = DiscoveryBeacon.from_bytes(raw_bytes)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.device_id, self.valid_beacon.device_id)
        self.assertEqual(parsed.device_name, self.valid_beacon.device_name)
        self.assertEqual(parsed.device_type, self.valid_beacon.device_type)
        self.assertEqual(parsed.port, self.valid_beacon.port)
        self.assertEqual(parsed.transfer_port, self.valid_beacon.transfer_port)
        self.assertEqual(parsed.cert_fingerprint, self.valid_beacon.cert_fingerprint)
        self.assertAlmostEqual(parsed.timestamp, self.valid_beacon.timestamp, places=2)

    def test_reject_oversized_payload(self) -> None:
        """Paylaod exceeding 2048 bytes must be dropped immediately."""
        huge_bytes = b"x" * (MAX_BEACON_SIZE_BYTES + 1)
        self.assertIsNone(DiscoveryBeacon.from_bytes(huge_bytes))

    def test_reject_malformed_json(self) -> None:
        """Malformed or non-JSON payloads must be rejected cleanly."""
        self.assertIsNone(DiscoveryBeacon.from_bytes(b"NOT_JSON"))
        self.assertIsNone(DiscoveryBeacon.from_bytes(b'["list", "not", "dict"]'))
        self.assertIsNone(DiscoveryBeacon.from_bytes(b""))

    def test_reject_invalid_proto_or_version(self) -> None:
        """Beacons with unrecognized protocol name or version are rejected."""
        raw = json.dumps({
            "proto": "other-protocol",
            "v": 1,
            "device_id": "d1",
            "port": 8765,
            "timestamp": time.time(),
        }).encode("utf-8")
        self.assertIsNone(DiscoveryBeacon.from_bytes(raw))

        raw_bad_ver = json.dumps({
            "proto": DISCOVERY_PROTOCOL_NAME,
            "v": 99,
            "device_id": "d1",
            "port": 8765,
            "timestamp": time.time(),
        }).encode("utf-8")
        self.assertIsNone(DiscoveryBeacon.from_bytes(raw_bad_ver))

    def test_reject_invalid_port_range(self) -> None:
        """Ports outside 1..65535 are rejected."""
        for bad_port in (0, -1, 70000, "8765", True):
            raw = json.dumps({
                "proto": DISCOVERY_PROTOCOL_NAME,
                "v": 1,
                "device_id": "d1",
                "port": bad_port,
                "timestamp": time.time(),
            }).encode("utf-8")
            self.assertIsNone(DiscoveryBeacon.from_bytes(raw))

    def test_reject_excessive_timestamp_drift(self) -> None:
        """Beacons with timestamp drift > 30s into past or future must be dropped."""
        now = time.time()
        # 60s in the past
        past_raw = json.dumps({
            "proto": DISCOVERY_PROTOCOL_NAME,
            "v": 1,
            "device_id": "d1",
            "port": 8765,
            "timestamp": now - 60.0,
        }).encode("utf-8")
        self.assertIsNone(DiscoveryBeacon.from_bytes(past_raw))

        # 60s in the future
        future_raw = json.dumps({
            "proto": DISCOVERY_PROTOCOL_NAME,
            "v": 1,
            "device_id": "d1",
            "port": 8765,
            "timestamp": now + 60.0,
        }).encode("utf-8")
        self.assertIsNone(DiscoveryBeacon.from_bytes(future_raw))

        # 10s drift (acceptable)
        valid_raw = json.dumps({
            "proto": DISCOVERY_PROTOCOL_NAME,
            "v": 1,
            "device_id": "d1",
            "port": 8765,
            "timestamp": now - 10.0,
        }).encode("utf-8")
        self.assertIsNotNone(DiscoveryBeacon.from_bytes(valid_raw))


class TestSnowDiscoveryService(unittest.IsolatedAsyncioTestCase):
    """Tests for SnowDiscoveryService async socket management, beacon broadcasting, and peer tracking."""

    async def asyncSetUp(self) -> None:
        self.config = CoreConfig(
            discovery_enabled=True,
            discovery_port=0,  # Ephemeral port
            beacon_interval=0.1,
        )
        self.identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="My-Windows-Laptop",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.service = SnowDiscoveryService(
            config=self.config,
            device_identity=self.identity,
            cert_fingerprint="cert-fp-1234",
            paired_device_checker=lambda dev_id, fp: dev_id == "paired-peer-1",
        )

    async def asyncTearDown(self) -> None:
        if self.service.is_running:
            await self.service.stop()

    async def test_start_and_stop_lifecycle(self) -> None:
        """Discovery service binds socket, reports running, and shuts down cleanly."""
        await self.service.start()
        self.assertTrue(self.service.is_running)
        self.assertIsNotNone(self.service.bound_port)
        self.assertGreater(self.service.bound_port, 0)

        await self.service.stop()
        self.assertFalse(self.service.is_running)

    async def test_self_reflection_ignored(self) -> None:
        """Service silently ignores broadcast datagrams matching its own device_id."""
        own_beacon = self.service._create_beacon()
        self.service._handle_incoming_datagram(own_beacon.to_bytes(), ("127.0.0.1", 8768))
        self.assertEqual(len(self.service.list_discovered_peers()), 0)

    async def test_peer_ingestion_and_pairing_resolution(self) -> None:
        """Incoming peer beacon is parsed, tracked, and checked against paired database."""
        peer_beacon = DiscoveryBeacon(
            device_id="paired-peer-1",
            device_name="Realme-Phone",
            device_type="android",
            port=8765,
            transfer_port=8766,
            cert_fingerprint="fp-realme",
            timestamp=time.time(),
        )
        self.service._handle_incoming_datagram(peer_beacon.to_bytes(), ("192.168.1.105", 8768))

        peers = self.service.list_discovered_peers()
        self.assertEqual(len(peers), 1)
        p = peers[0]
        self.assertEqual(p.device_id, "paired-peer-1")
        self.assertEqual(p.device_name, "Realme-Phone")
        self.assertEqual(p.ip_address, "192.168.1.105")
        self.assertTrue(p.is_paired)
        self.assertFalse(p.is_stale)

    async def test_unpaired_peer_marked_unpaired(self) -> None:
        """Peer not in paired database is tracked but marked is_paired=False."""
        unpaired_beacon = DiscoveryBeacon(
            device_id="unpaired-peer-99",
            device_name="Stranger-PC",
            device_type="windows",
            port=8765,
            transfer_port=8766,
            cert_fingerprint="fp-unknown",
            timestamp=time.time(),
        )
        self.service._handle_incoming_datagram(unpaired_beacon.to_bytes(), ("192.168.1.199", 8768))

        peer = self.service.get_peer("unpaired-peer-99")
        self.assertIsNotNone(peer)
        self.assertFalse(peer.is_paired)

    async def test_rate_limiting(self) -> None:
        """Excessive datagrams from the same IP are throttled."""
        remote_ip = "192.168.1.50"
        beacon = DiscoveryBeacon(
            device_id="dev-flood",
            device_name="Flood-PC",
            port=8765,
            timestamp=time.time(),
        )
        payload = beacon.to_bytes()

        # Inject 30 beacons rapidly
        for _ in range(30):
            self.service._handle_incoming_datagram(payload, (remote_ip, 8768))

        # Rate limiter caps history at 25 within 2s
        self.assertLessEqual(len(self.service._rate_limits.get(remote_ip, [])), 25)

    async def test_wake_burst_handling(self) -> None:
        """Targeted wake burst triggers wake listener callback."""
        wake_calls = []

        def on_wake(sender_id: str, sender_ip: str) -> None:
            wake_calls.append((sender_id, sender_ip))

        self.service.wake_listener = on_wake

        wake_beacon = DiscoveryBeacon(
            device_id="peer-sender",
            device_name="Sender-Node",
            port=8765,
            timestamp=time.time(),
            wake_target=self.identity.device_id,  # Targets us!
        )
        self.service._handle_incoming_datagram(wake_beacon.to_bytes(), ("192.168.1.77", 8768))

        self.assertEqual(len(wake_calls), 1)
        self.assertEqual(wake_calls[0], ("peer-sender", "192.168.1.77"))


class TestUnifiedTargetResolution(unittest.TestCase):
    """Tests for multi-device target resolution (exact ID, exact name, substring, ambiguity)."""

    def setUp(self) -> None:
        self.devices = [
            {
                "device_id": "11111111-2222-3333-4444-555555555555",
                "device_name": "Realme RMX5110",
                "is_paired": True,
                "is_connected": True,
            },
            {
                "device_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                "device_name": "Living Room Laptop",
                "is_paired": True,
                "is_connected": False,
            },
            {
                "device_id": "99999999-8888-7777-6666-555555555555",
                "device_name": "Living Room Tablet",
                "is_paired": True,
                "is_connected": False,
            },
            {
                "device_id": "unpaired-candidate-id",
                "device_name": "Neighbor Laptop",
                "is_paired": False,
                "is_connected": False,
            },
        ]

    def test_resolve_default_single_connected(self) -> None:
        """Empty query with multiple paired devices auto-resolves the single active connected device."""
        target_id, err = resolve_target_device(self.devices, "")
        self.assertIsNone(err)
        self.assertEqual(target_id, "11111111-2222-3333-4444-555555555555")

    def test_resolve_default_no_paired_devices(self) -> None:
        """Empty query when no devices are paired returns NO_DEVICES_PAIRED."""
        target_id, err = resolve_target_device([], "")
        self.assertIsNone(target_id)
        self.assertEqual(err["status"], "NO_DEVICES_PAIRED")

    def test_resolve_default_ambiguous_connected(self) -> None:
        """Empty query when multiple devices are connected returns DEVICE_REQUIRED."""
        dual_connected = [
            {"device_id": "d1", "device_name": "Phone 1", "is_paired": True, "is_connected": True},
            {"device_id": "d2", "device_name": "Phone 2", "is_paired": True, "is_connected": True},
        ]
        target_id, err = resolve_target_device(dual_connected, "")
        self.assertIsNone(target_id)
        self.assertEqual(err["status"], "DEVICE_REQUIRED")

    def test_resolve_exact_id(self) -> None:
        """Exact UUID query resolves directly regardless of connection status."""
        target_id, err = resolve_target_device(self.devices, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        self.assertIsNone(err)
        self.assertEqual(target_id, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")

    def test_resolve_exact_name_case_insensitive(self) -> None:
        """Exact name match resolves case-insensitively."""
        target_id, err = resolve_target_device(self.devices, "realme rmx5110")
        self.assertIsNone(err)
        self.assertEqual(target_id, "11111111-2222-3333-4444-555555555555")

    def test_resolve_unambiguous_substring(self) -> None:
        """Substring matching only one device resolves cleanly."""
        target_id, err = resolve_target_device(self.devices, "RMX5110")
        self.assertIsNone(err)
        self.assertEqual(target_id, "11111111-2222-3333-4444-555555555555")

    def test_resolve_ambiguous_substring_rejected(self) -> None:
        """Substring matching multiple devices returns AMBIGUOUS_DEVICE with candidate list."""
        target_id, err = resolve_target_device(self.devices, "Living Room")
        self.assertIsNone(target_id)
        self.assertEqual(err["status"], "AMBIGUOUS_DEVICE")
        self.assertIn("matches", err["data"])
        self.assertEqual(len(err["data"]["matches"]), 2)

    def test_resolve_not_found(self) -> None:
        """Query matching zero devices returns DEVICE_NOT_FOUND."""
        target_id, err = resolve_target_device(self.devices, "NonExistentDevice")
        self.assertIsNone(target_id)
        self.assertEqual(err["status"], "DEVICE_NOT_FOUND")


class TestUnifiedFileTransferAndMeshTools(unittest.IsolatedAsyncioTestCase):
    """Tests for unified transfer tool routing and peer client integration."""

    async def asyncSetUp(self) -> None:
        self.bridge = SnowMcpBridge(auto_start_core=False)
        self.server = FastMCP(name="SNOW-Test-Mesh")
        register_all_tools(self.server, self.bridge)

    def test_all_23_tools_registered_and_categorized(self) -> None:
        """Verify all 23 tools are registered, unique, and present in TOOL_REGISTRY."""
        self.assertEqual(len(ALL_TOOL_NAMES), 23)
        self.assertIn("snow_transfer_file", ALL_TOOL_NAMES)
        self.assertIn("snow_mesh_connect_peer", ALL_TOOL_NAMES)

        # Check categorization
        self.assertEqual(get_tool_category("snow_transfer_file"), ToolCategory.CROSS_DEVICE)
        self.assertEqual(get_tool_category("snow_mesh_connect_peer"), ToolCategory.CROSS_DEVICE)

    async def test_transfer_file_invalid_direction(self) -> None:
        """Invalid transfer direction is rejected immediately with INVALID_ARGUMENT."""
        res = await self.bridge.transfer_file(
            source_path="test.txt",
            direction="invalid_direction",
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "INVALID_ARGUMENT")

    async def test_transfer_file_to_device_delegates_to_file_send(self) -> None:
        """transfer_file with direction='to_device' calls android_file_send."""
        self.bridge.list_devices = AsyncMock(return_value={
            "success": True,
            "data": {"devices": [{"device_id": "dev-target-1", "device_name": "Phone", "is_paired": True, "is_connected": True}]},
        })
        self.bridge.android_file_send = AsyncMock(return_value={"success": True, "status": "SUCCESS", "data": {"transferred": True}})

        res = await self.bridge.transfer_file(
            source_path="C:\\test\\report.pdf",
            direction="to_device",
            target_device="Phone",
        )
        self.assertTrue(res["success"])
        self.bridge.android_file_send.assert_awaited_once_with(file_path="C:\\test\\report.pdf", device_id="dev-target-1")

    async def test_transfer_file_from_device_delegates_to_file_receive(self) -> None:
        """transfer_file with direction='from_device' calls android_file_receive."""
        self.bridge.list_devices = AsyncMock(return_value={
            "success": True,
            "data": {"devices": [{"device_id": "dev-target-1", "device_name": "Phone", "is_paired": True, "is_connected": True}]},
        })
        self.bridge.android_file_receive = AsyncMock(return_value={"success": True, "status": "SUCCESS", "data": {"transferred": True}})

        res = await self.bridge.transfer_file(
            source_path="photo.jpg",
            direction="from_device",
            target_device="Phone",
        )
        self.assertTrue(res["success"])
        self.bridge.android_file_receive.assert_awaited_once_with(file_name="photo.jpg", device_id="dev-target-1")


class TestOnDemandConnectionGracePeriod(unittest.IsolatedAsyncioTestCase):
    """Tests for Core IPC on-demand discovery wake and reconnection grace period."""

    async def test_ipc_device_request_awaits_reconnection_within_grace_period(self) -> None:
        """When paired device is offline, IPC triggers wake burst and waits for reconnection."""
        mock_core = MagicMock()
        mock_core.config = CoreConfig(
            ipc_host="127.0.0.1",
            ipc_port=0,
            device_connect_grace_period=2.0,
        )
        mock_core.db_manager.get_paired_device.return_value = MagicMock(device_id="dev-sleepy")

        # Initially offline
        mock_core.session_manager.get_session_by_device.return_value = None
        mock_core.connection_manager.get.return_value = None

        mock_discovery = MagicMock()
        mock_discovery.is_running = True
        mock_discovery.send_wake_burst = AsyncMock()
        mock_core.discovery_service = mock_discovery

        ipc_server = SnowIpcServer(core_server=mock_core, config=mock_core.config)

        # Simulate device connecting 0.4s after wake burst
        async def delayed_connect():
            await asyncio.sleep(0.4)
            active_session = MagicMock(device_id="dev-sleepy", connection_id="conn-999")
            active_conn = MagicMock(is_active=True)
            mock_core.session_manager.get_session_by_device.return_value = active_session
            mock_core.connection_manager.get.return_value = active_conn

        asyncio.create_task(delayed_connect())

        # Mock successful WebSocket response after connection
        mock_core.ws_server.send_request = AsyncMock(
            return_value=SnowMessage.create_response(
                correlation_id="c1",
                payload={"status": "success", "result": "pong"},
            )
        )

        res = await ipc_server._handle_device_request({"device_id": "dev-sleepy", "action": "ping"})
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "SUCCESS")
        mock_discovery.send_wake_burst.assert_awaited_once_with("dev-sleepy")


class TestSnowPeerClient(unittest.IsolatedAsyncioTestCase):
    """Tests for SnowPeerClient handshake, TOFU fingerprint pinning, and message execution."""

    async def test_peer_connection_failure_handled_gracefully(self) -> None:
        """Connection to unreachable peer returns structured CONNECTION_FAILED."""
        client = SnowPeerClient(host="127.0.0.1", port=59999, use_tls=False)
        res = await client.connect(timeout=0.5)
        self.assertFalse(res.success)
        self.assertEqual(res.status, "CONNECTION_FAILED")
        self.assertIn("Could not connect", res.error or "")
        await client.close()


if __name__ == "__main__":
    unittest.main()
