"""Unit and integration test suite for SNOW Phase 27:
V4.2 Multi-Device Local SNOW Network.

Covers:
1. Test Group A: Network Identity, Persistence & Database Migration (Schema v5).
2. Test Group B: Multi-Node Routing & Topology Synthesis.
3. Test Group C: Peer Connection & Windows-to-Windows Federation.
4. Test Group D: Ambiguous Multi-Android Target Resolution (DEVICE_REQUIRED, Windows Exclusion).
5. Test Group E: MCP Security, 38-Tool Dynamic Catalog & Secret Redaction.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import socket
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from snow.core.config import CoreConfig
from snow.core.server import SnowCoreServer
from snow.mcp.bridge import SnowMcpBridge, resolve_target_device
from snow.mcp.registry import (
    CAPABILITY_REGISTRY,
    get_capability_metadata,
    get_mcp_annotations,
    list_capabilities,
)
from snow.mcp.tools import ALL_TOOL_NAMES
from snow.mcp.server import create_snow_mcp_server
from snow.network.network_model import (
    DEFAULT_NETWORK_NAME,
    MAX_ENDPOINT_HISTORY,
    NetworkIdentity,
    NetworkMember,
    SAFE_TRANSPORT_DISPLAY,
    SnowNetworkManager,
)
from snow.network.peer_client import PeerConnectionResult
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager, SCHEMA_VERSION, VALID_CONNECTION_MODES
from snow.security.identity import DeviceIdentity


def _get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestGroupANetworkIdentityAndPersistence(unittest.TestCase):
    """Test Group A: Network Identity, Database Migration (Schema v5), and Persistence."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_phase27_db_")
        self.db_path = Path(self.temp_dir) / "test_snow.db"
        self.db = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_schema_v5_migration_and_tables(self) -> None:
        """Verify database initializes or migrates to SCHEMA_VERSION >= 5 (now v8) with all mesh tables."""
        self.assertIn(SCHEMA_VERSION, (5, 6, 7, 8))
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Verify network_identity table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='network_identity';")
            self.assertIsNotNone(cursor.fetchone(), "Table 'network_identity' must exist.")

            # Verify network_endpoints table
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='network_endpoints';")
            self.assertIsNotNone(cursor.fetchone(), "Table 'network_endpoints' must exist.")

            # Verify paired_devices columns
            cursor.execute("PRAGMA table_info(paired_devices);")
            cols = {row[1] for row in cursor.fetchall()}
            self.assertIn("role", cols, "paired_devices must have 'role' column.")
            self.assertIn("cert_fingerprint", cols, "paired_devices must have 'cert_fingerprint' column.")
            self.assertIn("endpoints_json", cols, "paired_devices must have 'endpoints_json' column.")

    def test_02_network_identity_dataclass(self) -> None:
        """Verify NetworkIdentity dataclass round-trip serialization and standalone None default."""
        standalone = NetworkIdentity(network_name="Standalone Host", owner_id="owner-fp-123")
        self.assertIsNone(standalone.network_id)
        ident = NetworkIdentity(
            network_id="SNW-NET-CAFE1234",
            network_name="Home Mesh",
            owner_id="owner-fp-123",
        )
        self.assertEqual(ident.network_id, "SNW-NET-CAFE1234")
        self.assertEqual(ident.network_name, "Home Mesh")
        self.assertEqual(ident.owner_id, "owner-fp-123")

        data = ident.to_dict()
        restored = NetworkIdentity.from_dict(data)
        self.assertEqual(restored.network_id, ident.network_id)
        self.assertEqual(restored.network_name, "Home Mesh")
        self.assertEqual(restored.owner_id, "owner-fp-123")

    def test_03_snow_network_manager_identity_persistence(self) -> None:
        """Verify SnowNetworkManager stays standalone (None) until formed, then persists canonical SNW-NET-XXXXXXXX."""
        mgr = SnowNetworkManager(db_manager=self.db)
        ident_standalone = mgr.get_network_identity()
        self.assertEqual(ident_standalone.network_name, DEFAULT_NETWORK_NAME)
        self.assertIsNone(ident_standalone.network_id)

        # Form canonical network & update name
        formed = mgr.form_network(network_name="Ayush's Lab Mesh", owner_device_id="owner-pc-1", network_id="SNW-NET-A1B2C3D4")
        self.assertEqual(formed.network_id, "SNW-NET-A1B2C3D4")
        updated = mgr.update_network_name("Ayush's Lab Mesh")
        self.assertEqual(updated.network_name, "Ayush's Lab Mesh")

        # Create new manager against same DB: identity must persist
        mgr2 = SnowNetworkManager(db_manager=self.db)
        ident2 = mgr2.get_network_identity()
        self.assertEqual(ident2.network_id, "SNW-NET-A1B2C3D4")
        self.assertEqual(ident2.network_name, "Ayush's Lab Mesh")
        self.assertEqual(ident2.owner_id, "owner-pc-1")

    def test_04_endpoint_ring_buffer_history(self) -> None:
        """Verify endpoint history records endpoints up to MAX_ENDPOINT_HISTORY (5)."""
        mgr = SnowNetworkManager(db_manager=self.db)
        dev_id = "device-pixel-8"

        # Record 6 endpoints
        for i in range(1, 7):
            mgr.record_endpoint(device_id=dev_id, host=f"192.168.1.{100 + i}", port=8765)
            time.sleep(0.01)

        endpoints = mgr.get_endpoints(dev_id)
        self.assertLessEqual(len(endpoints), MAX_ENDPOINT_HISTORY)
        self.assertEqual(len(endpoints), 5)

        # Most recent endpoint should be first (192.168.1.106)
        self.assertEqual(endpoints[0], ("192.168.1.106", 8765))
        # Oldest (192.168.1.101) must have been evicted from the top 5
        hosts = [h for h, _ in endpoints]
        self.assertNotIn("192.168.1.101", hosts)

    def test_05_connection_mode_validation_and_migration_idempotence(self) -> None:
        """Verify VALID_CONNECTION_MODES, update_device_connection_mode, validation, and migration idempotence."""
        self.assertEqual(VALID_CONNECTION_MODES, ("auto", "local_only", "remote_only"))

        dev_id = "device-test-mode"
        self.db.insert_paired_device(
            device_id=dev_id,
            device_name="Test Phone",
            auth_token_hash="token_hash_abc",
            trust_tier="owner",
            platform="android",
        )

        # Initial default must be auto
        rec = self.db.get_paired_device(dev_id)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.connection_mode, "auto")

        # Update to local_only
        self.db.update_device_connection_mode(dev_id, "local_only")
        rec = self.db.get_paired_device(dev_id)
        self.assertEqual(rec.connection_mode, "local_only")

        # Update to remote_only
        self.db.update_device_connection_mode(dev_id, "remote_only")
        rec = self.db.get_paired_device(dev_id)
        self.assertEqual(rec.connection_mode, "remote_only")

        # Update back to auto
        self.db.update_device_connection_mode(dev_id, "auto")
        rec = self.db.get_paired_device(dev_id)
        self.assertEqual(rec.connection_mode, "auto")

        # Rejection of invalid modes
        with self.assertRaises(ValueError):
            self.db.update_device_connection_mode(dev_id, "satellite")
        with self.assertRaises(ValueError):
            self.db.update_device_connection_mode(dev_id, "")

        # Migration and init_schema idempotence check
        self.db.init_schema()
        rec_after = self.db.get_paired_device(dev_id)
        self.assertIsNotNone(rec_after)
        self.assertEqual(rec_after.connection_mode, "auto")

    def test_06_remote_relay_transport_mapping(self) -> None:
        """Verify remote_relay transport is safely mapped to display name in SAFE_TRANSPORT_DISPLAY."""
        self.assertIn("remote_relay", SAFE_TRANSPORT_DISPLAY)
        self.assertEqual(SAFE_TRANSPORT_DISPLAY["remote_relay"], "Remote Relay")
        self.assertEqual(SAFE_TRANSPORT_DISPLAY.get("wifi_lan"), "Wi-Fi LAN")


class TestGroupBMultiNodeRoutingAndTopology(unittest.TestCase):
    """Test Group B: Multi-Node Routing & Topology Synthesis."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_phase27_topo_")
        self.db = DatabaseManager(Path(self.temp_dir) / "test.db")
        self.node_registry = MagicMock()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_topology_synthesis_with_mixed_nodes(self) -> None:
        """Verify build_topology incorporates local Windows coordinator and connected peers."""
        # Setup mock active nodes
        class MockNode:
            def __init__(self, dev_id, name, platform, tr, connected=True):
                self.device_id = dev_id
                self.device_name = name
                self.platform = platform
                self.transport = tr
                self.is_connected = connected
                self.reachability_state = "active" if connected else "offline"
                self.trust_tier = "owner"
                self.role = "member"
                self.supported_capabilities = ["android.telemetry", "android.camera"]
                self.last_seen_timestamp = time.time()

        phone_node = MockNode("dev-phone-1", "Realme Phone", "android", "wifi_lan", True)
        laptop2_node = MockNode("dev-laptop-2", "Secondary PC", "windows", "peer_link", True)
        self.node_registry.list_nodes.return_value = [phone_node, laptop2_node]

        mgr = SnowNetworkManager(db_manager=self.db, node_registry=self.node_registry)
        topo = mgr.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)

        self.assertTrue(topo["success"])
        self.assertEqual(topo["network_name"], DEFAULT_NETWORK_NAME)
        dev_ids = [d["device_id"] for d in topo["devices"]]

        # Coordinator desktop-core must be synthesized if not present
        self.assertIn("desktop-core", dev_ids)
        self.assertIn("dev-phone-1", dev_ids)
        self.assertIn("dev-laptop-2", dev_ids)

    def test_02_topology_persisted_devices_fallback(self) -> None:
        """Verify DB paired devices are listed even when node_registry is empty."""
        self.db.insert_paired_device(
            device_id="dev-phone-paired",
            device_name="Ayush Phone",
            auth_token_hash="hash123",
            trust_tier="owner",
            platform="android",
        )

        mgr = SnowNetworkManager(db_manager=self.db, node_registry=None)
        topo = mgr.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)

        dev_ids = [d["device_id"] for d in topo["devices"]]
        self.assertIn("desktop-core", dev_ids)
        self.assertIn("dev-phone-paired", dev_ids)

        paired_entry = next(d for d in topo["devices"] if d["device_id"] == "dev-phone-paired")
        self.assertFalse(paired_entry["is_connected"])
        self.assertEqual(paired_entry["reachability_state"], "offline")

    def test_03_platform_scoped_capabilities_exclusion(self) -> None:
        """Verify Windows and Android capabilities are mutually exclusive in synthesized topology."""
        class MockNode:
            def __init__(self, dev_id, name, platform, tr, connected=True):
                self.device_id = dev_id
                self.device_name = name
                self.platform = platform
                self.transport = tr
                self.is_connected = connected
                self.reachability_state = "active" if connected else "offline"
                self.trust_tier = "owner"
                self.role = "member"
                self.supported_capabilities = ["android.telemetry", "android.camera"]
                self.last_seen_timestamp = time.time()

        phone_node = MockNode("dev-phone-1", "Realme Phone", "android", "wifi_lan", True)
        self.node_registry.list_nodes.return_value = [phone_node]

        mgr = SnowNetworkManager(db_manager=self.db, node_registry=self.node_registry)
        topo = mgr.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)

        self.assertTrue(topo["success"])
        win_dev = next(d for d in topo["devices"] if d["platform"] == "windows")
        android_dev = next(d for d in topo["devices"] if d["platform"] == "android")

        win_caps = win_dev.get("supported_capabilities", [])
        android_caps = android_dev.get("supported_capabilities", [])

        # Windows must have desktop.* and zero android.*
        self.assertTrue(any(c.startswith("desktop.") for c in win_caps), "Windows node must contain desktop.* capabilities")
        self.assertTrue(all(not c.startswith("android.") for c in win_caps), "Windows node must NOT contain android.* capabilities")

        # Android must have android.* and zero desktop.*
        self.assertTrue(any(c.startswith("android.") for c in android_caps), "Android node must contain android.* capabilities")
        self.assertTrue(all(not c.startswith("desktop.") for c in android_caps), "Android node must NOT contain desktop.* capabilities")


class TestGroupCPeerConnectionAndFederation(unittest.IsolatedAsyncioTestCase):
    """Test Group C: Peer Connection & Windows-to-Windows Federation."""

    async def test_01_bridge_mesh_connect_peer_mock(self) -> None:
        """Verify bridge.mesh_connect_peer connects via SnowPeerClient and returns structured metadata."""
        bridge = SnowMcpBridge(auto_start_core=False)

        mock_result = PeerConnectionResult(
            success=True,
            status="CONNECTED",
            remote_device_id="dev-peer-windows-2",
            remote_device_name="Lenovo Secondary",
            session_id="sess-abc-123",
            cert_fingerprint="sha256:aabbccddeeff",
        )

        with patch("snow.network.peer_client.SnowPeerClient.connect", new=AsyncMock(return_value=mock_result)), \
             patch("snow.network.peer_client.SnowPeerClient.close", new=AsyncMock()):
            res = await bridge.mesh_connect_peer(host="192.168.1.150", port=8765, pin="123456")
            self.assertTrue(res["success"])
            self.assertEqual(res["status"], "CONNECTED")
            self.assertEqual(res["data"]["remote_device_id"], "dev-peer-windows-2")
            self.assertEqual(res["data"]["remote_device_name"], "Lenovo Secondary")
            self.assertEqual(res["data"]["cert_fingerprint"], "sha256:aabbccddeeff")

    async def test_02_web_connect_peer_endpoint_validation_and_recording(self) -> None:
        """Verify Web Dashboard POST /api/devices/connect-peer validates input and records endpoint."""
        from snow.web.server import SnowWebServer

        bridge = SnowMcpBridge(auto_start_core=False)
        server = SnowWebServer(bridge=bridge, port=0, auto_open_browser=False)

        # Mock successful peer connection
        bridge.mesh_connect_peer = AsyncMock(return_value={
            "success": True,
            "status": "CONNECTED",
            "data": {
                "remote_device_id": "dev-peer-pc",
                "remote_device_name": "Living Room PC",
                "session_id": "sess-xyz",
            },
        })

        # Mock request
        mock_req = MagicMock()
        mock_req.json = AsyncMock(return_value={
            "host": "192.168.1.200",
            "port": 8765,
            "pin": "654321",
        })

        with patch.object(SnowNetworkManager, "record_endpoint") as mock_record:
            resp = await server.handle_api_devices_connect_peer(mock_req)
            self.assertEqual(resp.status, 200)
            mock_record.assert_called_once_with(device_id="dev-peer-pc", host="192.168.1.200", port=8765)

    async def test_03_ipc_principal_derivation_mesh_topology(self) -> None:
        """Verify IPC mesh_topology derives principal from context and rejects spoofing."""
        from snow.core.ipc import SnowIpcServer

        temp_dir = tempfile.mkdtemp(prefix="snow_test_phase27_ipc_")
        try:
            db = DatabaseManager(Path(temp_dir) / "test.db")
            core_mock = MagicMock()
            core_mock.db_manager = db
            core_mock.node_registry = None
            core_mock.network_manager = SnowNetworkManager(db_manager=db)

            ipc_config = CoreConfig(
                ipc_secret_path=str(Path(temp_dir) / "ipc.secret"),
            )
            ipc_server = SnowIpcServer(core_server=core_mock, config=ipc_config)
            expected_owner_token = hmac.new(
                ipc_server._secret.encode("utf-8"), b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256
            ).hexdigest()

            # 1. OWNER_MANUAL caller receives unredacted topology (has network_id, owner_id)
            req_owner = {
                "version": 1,
                "op": "mesh_topology",
                "auth_token": ipc_server._secret,
                "payload": {"owner_token": expected_owner_token},
            }
            res_owner, _ = await ipc_server._dispatch_request(req_owner, is_connection_authenticated=True)
            self.assertEqual(res_owner["status"].upper(), "SUCCESS")
            self.assertIn("network_id", res_owner["data"])
            self.assertIn("owner_id", res_owner["data"])

            # 2. AI_MCP caller receives redacted topology (network_id and owner_id excluded)
            req_mcp = {
                "version": 1,
                "op": "mesh_topology",
                "auth_token": ipc_server._secret,
                "payload": {},
            }
            res_mcp, _ = await ipc_server._dispatch_request(req_mcp, is_connection_authenticated=True)
            self.assertEqual(res_mcp["status"].upper(), "SUCCESS")
            self.assertNotIn("network_id", res_mcp["data"])
            self.assertNotIn("owner_id", res_mcp["data"])

            # 3. Privilege escalation attempt: AI_MCP caller supplies {"principal": "OWNER_MANUAL"}
            req_spoofed = {
                "version": 1,
                "op": "mesh_topology",
                "auth_token": ipc_server._secret,
                "payload": {"principal": "OWNER_MANUAL", "trust_tier": "owner"},
            }
            res_spoofed, _ = await ipc_server._dispatch_request(req_spoofed, is_connection_authenticated=True)
            self.assertEqual(res_spoofed["status"].upper(), "SUCCESS")
            # Must STILL be redacted because principal is derived by HMAC token, not spoofed payload
            self.assertNotIn("network_id", res_spoofed["data"])
            self.assertNotIn("owner_id", res_spoofed["data"])

            # 4. Empty payload does not downgrade OWNER context
            req_empty_owner = {
                "version": 1,
                "op": "mesh_topology",
                "auth_token": ipc_server._secret,
                "owner_token": expected_owner_token,
                "payload": {},
            }
            res_empty_owner, _ = await ipc_server._dispatch_request(req_empty_owner, is_connection_authenticated=True)
            self.assertEqual(res_empty_owner["status"].upper(), "SUCCESS")
            self.assertIn("network_id", res_empty_owner["data"])
            self.assertIn("owner_id", res_empty_owner["data"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    async def test_04_real_two_core_tls_wss_federation_integration(self) -> None:
        """Verify real TLS/WSS federation between two live loopback SnowCoreServer instances."""
        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            db1 = DatabaseManager(Path(td1) / "db1.db")
            db2 = DatabaseManager(Path(td2) / "db2.db")

            cfg1 = CoreConfig(
                bind_host="127.0.0.1",
                port=_get_free_port(),
                transfer_port=_get_free_port(),
                ipc_port=_get_free_port(),
                ipc_secret_path=str(Path(td1) / "ipc.secret"),
                tls_enabled=True,
                tls_cert_path=str(Path(td1) / "server.crt"),
                tls_key_path=str(Path(td1) / "server.key"),
                discovery_enabled=False,
            )
            cfg2 = CoreConfig(
                bind_host="127.0.0.1",
                port=_get_free_port(),
                transfer_port=_get_free_port(),
                ipc_port=_get_free_port(),
                ipc_secret_path=str(Path(td2) / "ipc.secret"),
                tls_enabled=True,
                tls_cert_path=str(Path(td2) / "server.crt"),
                tls_key_path=str(Path(td2) / "server.key"),
                discovery_enabled=False,
            )

            id1 = DeviceIdentity(
                device_id=str(uuid.uuid4()),
                device_name="Lenovo Primary",
                created_at="2026-11-21T00:00:00Z",
            )
            id2 = DeviceIdentity(
                device_id=str(uuid.uuid4()),
                device_name="Lenovo Secondary",
                created_at="2026-11-21T00:00:00Z",
            )

            srv1 = SnowCoreServer(cfg1, db_manager=db1, device_identity=id1)
            srv2 = SnowCoreServer(cfg2, db_manager=db2, device_identity=id2)

            await srv1.start()
            await srv2.start()
            try:
                # Core B generates an owner pairing PIN
                pin = srv2.ws_server.pairing_manager.generate_pin(display_to_stderr=False, trust_tier="owner")
                self.assertEqual(len(pin), 6)

                # Core A initiates peer connection to Core B
                res = await srv1.connect_peer(host="127.0.0.1", port=cfg2.port, pin=pin)
                self.assertTrue(res["success"], f"Connect peer failed: {res.get('error')}")
                self.assertEqual(res["data"]["remote_device_id"], id2.device_id)

                # Assert Core B appears in Core A's NodeRegistry as active peer_link
                node_b = srv1.node_registry.get_node(id2.device_id)
                self.assertIsNotNone(node_b)
                self.assertTrue(node_b.is_connected)
                self.assertEqual(node_b.transport, "peer_link")

                # Assert Core B appears in Core A's topology
                topo = srv1.network_manager.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)
                device_ids = [d["device_id"] for d in topo["devices"]]
                self.assertIn(id2.device_id, device_ids)

                # Assert Core B is persisted in Core A's paired_devices SQLite table
                paired_dev = srv1.db_manager.get_paired_device(id2.device_id)
                self.assertIsNotNone(paired_dev)
                self.assertEqual(paired_dev.platform, "windows")

                # Disconnect peer
                dis_res = await srv1.disconnect_peer(id2.device_id)
                self.assertTrue(dis_res["success"])

                # Core B in NodeRegistry must now be marked offline
                node_b_after = srv1.node_registry.get_node(id2.device_id)
                self.assertTrue(node_b_after is None or not node_b_after.is_connected)

                # SQLite record is NOT deleted on disconnect
                self.assertIsNotNone(srv1.db_manager.get_paired_device(id2.device_id))
            finally:
                await srv1.stop()
                await srv2.stop()


class TestGroupDAmbiguousMultiAndroidTargetResolution(unittest.IsolatedAsyncioTestCase):
    """Test Group D: Ambiguous Multi-Android Target Resolution (DEVICE_REQUIRED, Windows Exclusion)."""

    async def test_01_multi_android_auto_resolution_requires_target(self) -> None:
        """When 2 Android phones are connected, auto-resolution with platform='android' returns DEVICE_REQUIRED."""
        devices = [
            {"device_id": "desktop-core", "device_name": "Host PC", "platform": "windows", "is_local": True, "is_connected": True},
            {"device_id": "dev-phone-1", "device_name": "Realme RMX5110", "platform": "android", "is_connected": True, "is_paired": True},
            {"device_id": "dev-phone-2", "device_name": "Samsung S24", "platform": "android", "is_connected": True, "is_paired": True},
        ]

        target_id, err = resolve_target_device(devices, target_query="", platform="android")
        self.assertIsNone(target_id)
        self.assertIsNotNone(err)
        self.assertEqual(err["status"], "DEVICE_REQUIRED")
        avail_names = [d["device_name"] for d in err["data"]["available_devices"]]
        self.assertIn("Realme RMX5110", avail_names)
        self.assertIn("Samsung S24", avail_names)
        self.assertNotIn("Host PC", avail_names)

    async def test_02_explicit_android_target_resolution(self) -> None:
        """Explicit query matching one of the connected Android phones successfully resolves."""
        devices = [
            {"device_id": "desktop-core", "device_name": "Host PC", "platform": "windows", "is_local": True, "is_connected": True},
            {"device_id": "dev-phone-1", "device_name": "Realme RMX5110", "platform": "android", "is_connected": True, "is_paired": True},
            {"device_id": "dev-phone-2", "device_name": "Samsung S24", "platform": "android", "is_connected": True, "is_paired": True},
        ]

        target_id, err = resolve_target_device(devices, target_query="Realme", platform="android")
        self.assertEqual(target_id, "dev-phone-1")
        self.assertIsNone(err)

    async def test_03_rejection_of_windows_host_for_android_op(self) -> None:
        """Targeting the local Windows host node for an Android operation returns structured error."""
        devices = [
            {"device_id": "desktop-core", "device_name": "Host PC", "platform": "windows", "is_local": True, "is_connected": True},
            {"device_id": "dev-phone-1", "device_name": "Realme RMX5110", "platform": "android", "is_connected": True, "is_paired": True},
        ]

        target_id, err = resolve_target_device(devices, target_query="desktop-core", platform="android")
        self.assertIsNone(target_id)
        self.assertIsNotNone(err)
        self.assertEqual(err["status"], "DEVICE_NOT_FOUND")
        self.assertIn("Cannot route Android operation to local Windows node", err["error"])


class TestGroupEMcpTopologySecurityAnd38Tools(unittest.IsolatedAsyncioTestCase):
    """Test Group E: MCP Security, 38-Tool Dynamic Catalog & Secret Redaction."""

    def test_01_exact_38_capabilities_in_registry(self) -> None:
        """Verify dynamic registry contains exactly 48 capabilities including snow_mesh_topology and Stage 6A tools."""
        caps = list_capabilities()
        self.assertEqual(len(caps), 60)
        self.assertEqual(len(ALL_TOOL_NAMES), 60)
        self.assertEqual(len(CAPABILITY_REGISTRY), 60)

        meta = get_capability_metadata("snow_mesh_topology")
        self.assertIsNotNone(meta)
        self.assertTrue(meta.read_only_hint)
        self.assertFalse(meta.destructive_hint)
        self.assertFalse(meta.requires_approval)
        self.assertEqual(meta.os_classification, "cross_platform")

        ann = get_mcp_annotations("snow_mesh_topology")
        self.assertIsNotNone(ann)
        self.assertTrue(ann.readOnlyHint)
        self.assertFalse(ann.destructiveHint)

    async def test_02_ai_mcp_topology_view_redaction(self) -> None:
        """Verify AI_MCP caller gets secret-redacted topology (no raw IPs, ports, tokens, PINs)."""
        temp_dir = tempfile.mkdtemp(prefix="snow_test_phase27_sec_")
        try:
            db = DatabaseManager(Path(temp_dir) / "test.db")
            mgr = SnowNetworkManager(db_manager=db)
            mgr.record_endpoint("dev-phone", "192.168.1.155", 8765)

            topo = mgr.build_topology(principal=ExecutionPrincipal.AI_MCP)
            self.assertTrue(topo["success"])
            self.assertIn("network_name", topo)
            self.assertNotIn("network_id", topo)
            self.assertNotIn("owner_id", topo)

            raw_dump = json.dumps(topo)
            # Must NEVER leak private credentials, raw IPs, ports, or PINs
            self.assertNotIn("192.168.1.155", raw_dump)
            self.assertNotIn("8765", raw_dump)
            self.assertNotIn("auth_token", raw_dump)
            self.assertNotIn("pin", raw_dump)
            self.assertNotIn("private_key", raw_dump)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    async def test_03_owner_manual_topology_view_metadata(self) -> None:
        """Verify OWNER_MANUAL caller receives network ID, owner ID, and device roles."""
        temp_dir = tempfile.mkdtemp(prefix="snow_test_phase27_owner_")
        try:
            db = DatabaseManager(Path(temp_dir) / "test.db")
            mgr = SnowNetworkManager(db_manager=db)
            topo = mgr.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)

            self.assertTrue(topo["success"])
            self.assertIn("network_id", topo)
            self.assertIn("owner_id", topo)
            self.assertIn("network_name", topo)
            self.assertIn("created_timestamp", topo)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    async def test_04_official_fastmcp_registers_all_38_tools(self) -> None:
        """Verify create_snow_mcp_server exposes all 38 tools and the mesh topology resource."""
        server = create_snow_mcp_server()
        tools = await server.list_tools()
        self.assertEqual(len(tools), 60)
        tool_names = {t.name for t in tools}
        self.assertIn("snow_mesh_topology", tool_names)

        # Verify snow://mesh/topology resource exists
        resources = await server.list_resources()
        res_uris = [str(r.uri) for r in resources]
        self.assertIn("snow://mesh/topology", res_uris)


if __name__ == "__main__":
    unittest.main()
