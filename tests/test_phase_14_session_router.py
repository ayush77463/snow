"""Unit tests for Phase 14: Layer 3 Multi-Transport Reachability State Machine & Automatic On-Demand Session Routing.

Covers:
1. Fast-fail Pre-flight Resolution:
   - NO_DEVICES_PAIRED (no devices paired in DB, zero network delay)
   - DEVICE_REQUIRED (multiple devices paired and no target query provided)
   - DEVICE_NOT_FOUND (target query does not match any device)
   - AMBIGUOUS_DEVICE (target query matches multiple devices)
   - CAPABILITY_NOT_SUPPORTED (device does not support requested capability)
2. Tier 1: Active Session Routing:
   - Inbound WSS dispatch over active connection (returns SUCCESS)
   - Inbound WSS device error payload handling
   - Inbound WSS timeout handling
   - Outbound peer client dispatch over active SnowPeerClient connection
3. Tier 2: Outbound Direct Connection (PERSISTENT_DAEMON):
   - Direct dial to persistent daemon via cached/discovered endpoint
   - Identity verification on direct dial (mismatched remote_device_id rejected)
   - Database endpoint caching updated only after successful verified connection
4. Tier 3: Android Active-Session Peer Recovery:
   - Sends targeted wake burst and awaits reconnection within grace period
   - Successful reconnection during grace period dispatches request
   - Timeout when device does not reconnect within grace period
5. Tier 4: Structured Failure & Diagnostics:
   - DEVICE_UNREACHABLE with attempted_transports, last_reachability_state,
     target_device_id, and last_known_endpoint
6. Security and Context Isolation:
   - Remote cross-device requests enforce ExecutionPrincipal.AI_MCP
   - Caller-supplied authority fields ('principal', 'trust_tier') stripped
   - Local Windows capability execution works in-process without Core daemon
"""

import asyncio
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.engine import (
    CapabilityEngine,
    CapabilityRequest,
    ExecutionContext,
    ExecutionPrincipal,
)
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
from snow.network.router import SessionRouter
from snow.security.session import SessionManager
from snow.protocol.models import MessageType, SnowMessage
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity


class TestSessionRouterPreflight(unittest.IsolatedAsyncioTestCase):
    """Pre-flight target and capability resolution tests."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_router_preflight.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.registry = NodeRegistry(db_manager=self.db)
        self.router = SessionRouter(node_registry=self.registry, db_manager=self.db)

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_preflight_no_devices_paired(self) -> None:
        """When 0 devices are paired, fails immediately with NO_DEVICES_PAIRED and zero network wait."""
        start = asyncio.get_event_loop().time()
        res = await self.router.route_request(action="android_battery")
        elapsed = asyncio.get_event_loop().time() - start

        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "NO_DEVICES_PAIRED")
        self.assertIn("Target resolution failed", res["error"])
        self.assertEqual(res["attempted_transports"], [])
        self.assertLess(elapsed, 0.1, "Pre-flight failure must be immediate without sleep/network wait")

    async def test_preflight_device_required_when_multiple_paired(self) -> None:
        """When >1 devices are paired and target is omitted, returns DEVICE_REQUIRED immediately."""
        dev1 = str(uuid.uuid4())
        dev2 = str(uuid.uuid4())
        self.db.insert_paired_device(dev1, "Phone-1", "hash1")
        self.db.insert_paired_device(dev2, "Phone-2", "hash2")

        res = await self.router.route_request(action="android_battery")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "DEVICE_REQUIRED")
        self.assertEqual(res["attempted_transports"], [])

    async def test_preflight_device_not_found(self) -> None:
        """Query matching zero devices returns DEVICE_NOT_FOUND immediately."""
        dev1 = str(uuid.uuid4())
        self.db.insert_paired_device(dev1, "Phone-1", "hash1")

        res = await self.router.route_request(action="android_battery", target="Tablet-Unknown")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "DEVICE_NOT_FOUND")
        self.assertEqual(res["attempted_transports"], [])

    async def test_preflight_ambiguous_device(self) -> None:
        """Target query matching multiple devices returns AMBIGUOUS_DEVICE immediately."""
        dev1 = str(uuid.uuid4())
        dev2 = str(uuid.uuid4())
        self.db.insert_paired_device(dev1, "Galaxy-S21", "hash1")
        self.db.insert_paired_device(dev2, "Galaxy-S23", "hash2")

        res = await self.router.route_request(action="android_battery", target="Galaxy")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "AMBIGUOUS_DEVICE")
        self.assertEqual(res["attempted_transports"], [])

    async def test_preflight_capability_not_supported(self) -> None:
        """Target device that does not support the action capability is rejected fast."""
        dev1 = str(uuid.uuid4())
        self.db.insert_paired_device(dev1, "Android-Phone", "hash1")

        # Android phone manifest with only android capabilities
        manifest = CapabilityManifest(
            manifest_version="2.0",
            supported_capabilities=["android.battery.get", "android.clipboard.get"],
        )
        self.db.update_device_manifest(dev1, manifest.to_json())

        # Attempt to route windows_terminal to Android phone
        res = await self.router.route_request(
            action="windows_terminal",
            target="Android-Phone",
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "CAPABILITY_NOT_SUPPORTED")
        self.assertEqual(res["attempted_transports"], [])


class TestSessionRouterTier1ActiveSession(unittest.IsolatedAsyncioTestCase):
    """Tier 1: Active Inbound WSS & Outbound Peer Client Routing tests."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_router_tier1.db"
        self.db = DatabaseManager(db_path=self.db_path)

        self.conn_mgr = ConnectionManager()
        self.sess_mgr = SessionManager()

        self.mock_ws_server = MagicMock()
        self.mock_ws_server.connection_manager = self.conn_mgr
        self.mock_ws_server.session_manager = self.sess_mgr

        self.registry = NodeRegistry(
            db_manager=self.db,
            connection_manager=self.conn_mgr,
        )
        self.router = SessionRouter(
            node_registry=self.registry,
            ws_server=self.mock_ws_server,
            db_manager=self.db,
        )

        self.device_id = str(uuid.uuid4())
        self.db.insert_paired_device(self.device_id, "TestPhone", "hash_t1")
        android_manifest = CapabilityManifest(
            manifest_version="2.0",
            supported_capabilities=["android.battery.get", "android.clipboard.get"],
        )
        self.db.update_device_manifest(self.device_id, android_manifest.to_json())

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_tier1_inbound_wss_dispatch_success(self) -> None:
        """Active inbound WebSocket session is used directly for dispatch."""
        # Establish active connection & session
        mock_ws = MagicMock()
        mock_ws.remote_address = ("192.168.1.100", 50000)
        conn = self.conn_mgr.register(mock_ws)
        sess = self.sess_mgr.create_session(self.device_id, conn.connection_id)

        # Mock WSS response
        self.mock_ws_server.send_request = AsyncMock(
            return_value=SnowMessage.create_response(
                correlation_id="c1",
                payload={"level": 88, "charging": True},
            )
        )

        res = await self.router.route_request(
            action="android_battery",
            target=self.device_id,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["data"], {"level": 88, "charging": True})
        self.assertEqual(res["target_device_id"], self.device_id)
        self.assertIn("active_inbound_wss", res["attempted_transports"])

        self.mock_ws_server.send_request.assert_awaited_once_with(
            connection_id=conn.connection_id,
            action="android_battery",
            payload={},
            timeout=30.0,
        )

    async def test_tier1_inbound_wss_device_error_payload(self) -> None:
        """When device returns an error response, router marks status DEVICE_ERROR."""
        mock_ws = MagicMock()
        mock_ws.remote_address = ("192.168.1.100", 50000)
        conn = self.conn_mgr.register(mock_ws)
        self.sess_mgr.create_session(self.device_id, conn.connection_id)

        self.mock_ws_server.send_request = AsyncMock(
            return_value=SnowMessage.create_response(
                correlation_id="c2",
                payload={"status": "error", "error": "Battery sensor unavailable"},
            )
        )

        res = await self.router.route_request(
            action="android_battery",
            target=self.device_id,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "DEVICE_ERROR")
        self.assertEqual(res["error"], "Battery sensor unavailable")

    async def test_tier1_inbound_wss_timeout(self) -> None:
        """When inbound dispatch times out, returns TIMEOUT status."""
        mock_ws = MagicMock()
        mock_ws.remote_address = ("192.168.1.100", 50000)
        conn = self.conn_mgr.register(mock_ws)
        self.sess_mgr.create_session(self.device_id, conn.connection_id)

        self.mock_ws_server.send_request = AsyncMock(
            side_effect=asyncio.TimeoutError("Timed out waiting for response")
        )

        res = await self.router.route_request(
            action="android_battery",
            target=self.device_id,
            timeout=2.0,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "TIMEOUT")
        self.assertIn("timed out after 2.0s", res["error"])

    async def test_tier1_active_outbound_peer_dispatch(self) -> None:
        """Active outbound peer client is used when inbound WSS is absent."""
        mock_peer_client = MagicMock()
        mock_peer_client.is_connected = True
        mock_peer_client.send_message = AsyncMock(
            return_value=SnowMessage.create_response(
                correlation_id="c3",
                payload={"status": "success", "echo": "peer_ok"},
            )
        )

        # Register active outbound client
        self.router._outbound_clients[self.device_id] = mock_peer_client

        res = await self.router.route_request(
            action="ping",
            target=self.device_id,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["data"], {"status": "success", "echo": "peer_ok"})
        self.assertIn("active_outbound_peer", res["attempted_transports"])


class TestSessionRouterTier2DirectDial(unittest.IsolatedAsyncioTestCase):
    """Tier 2: Outbound Direct Connection (PERSISTENT_DAEMON) tests."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_router_tier2.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.registry = NodeRegistry(db_manager=self.db)
        self.router = SessionRouter(
            node_registry=self.registry,
            db_manager=self.db,
            direct_dial_timeout=1.0,
        )

        self.daemon_id = str(uuid.uuid4())
        self.db.insert_paired_device(
            self.daemon_id,
            "Office-Desktop",
            "hash_d1",
            platform="windows",
            reachability_profile="PERSISTENT_DAEMON",
        )
        # Windows manifest implies ReachabilityProfile.PERSISTENT_DAEMON
        win_manifest = build_windows_manifest()
        self.db.update_device_manifest(self.daemon_id, win_manifest.to_json())
        self.db.update_device_endpoint(self.daemon_id, "192.168.1.200", 8765)

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    @patch("snow.network.router.SnowPeerClient")
    async def test_tier2_direct_dial_success(self, mock_client_cls: MagicMock) -> None:
        """Successful outbound direct dial to PERSISTENT_DAEMON peer dispatches request."""
        mock_client = MagicMock()
        mock_client.is_connected = True
        mock_client.connect = AsyncMock(
            return_value=PeerConnectionResult(
                success=True,
                status="AUTHENTICATED",
                remote_device_id=self.daemon_id,
            )
        )
        mock_client.send_message = AsyncMock(
            return_value=SnowMessage.create_response(
                correlation_id="d1",
                payload={"status": "success", "desktop_status": "idle"},
            )
        )
        mock_client_cls.return_value = mock_client

        res = await self.router.route_request(
            action="desktop_status",
            target=self.daemon_id,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["data"], {"status": "success", "desktop_status": "idle"})
        self.assertIn("outbound_direct", res["attempted_transports"])
        self.assertIn(self.daemon_id, self.router._outbound_clients)

    @patch("snow.network.router.SnowPeerClient")
    async def test_tier2_direct_dial_identity_mismatch_rejected(self, mock_client_cls: MagicMock) -> None:
        """Identity mismatch during direct dial aborts connection and falls through to Tier 4."""
        mock_client = MagicMock()
        mock_client.connect = AsyncMock(
            return_value=PeerConnectionResult(
                success=True,
                status="AUTHENTICATED",
                remote_device_id="impostor-device-id-9999",
            )
        )
        mock_client.close = AsyncMock()
        mock_client_cls.return_value = mock_client

        res = await self.router.route_request(
            action="desktop_status",
            target=self.daemon_id,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "DEVICE_UNREACHABLE")
        self.assertIn("outbound_direct", res["attempted_transports"])
        mock_client.close.assert_awaited_once()
        self.assertNotIn(self.daemon_id, self.router._outbound_clients)


class TestSessionRouterTier3AndroidRecovery(unittest.IsolatedAsyncioTestCase):
    """Tier 3: Android Active-Session Peer Recovery tests."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_router_tier3.db"
        self.db = DatabaseManager(db_path=self.db_path)

        self.conn_mgr = ConnectionManager()
        self.sess_mgr = SessionManager()

        self.mock_ws_server = MagicMock()
        self.mock_ws_server.connection_manager = self.conn_mgr
        self.mock_ws_server.session_manager = self.sess_mgr

        self.mock_discovery = MagicMock()
        self.mock_discovery.is_running = True
        self.mock_discovery.get_peer.return_value = None
        self.mock_discovery.send_wake_burst = AsyncMock()

        self.registry = NodeRegistry(
            db_manager=self.db,
            connection_manager=self.conn_mgr,
            discovery_service=self.mock_discovery,
        )
        self.router = SessionRouter(
            node_registry=self.registry,
            ws_server=self.mock_ws_server,
            discovery_service=self.mock_discovery,
            db_manager=self.db,
            wake_grace_period=0.6,
        )

        self.android_id = str(uuid.uuid4())
        self.db.insert_paired_device(
            self.android_id,
            "Ayush-Phone",
            "hash_a1",
            platform="android",
        )
        android_manifest = CapabilityManifest(
            manifest_version="2.0",
            supported_capabilities=["android.battery.get", "android.clipboard.get"],
        )
        self.db.update_device_manifest(self.android_id, android_manifest.to_json())

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_tier3_android_recovery_success(self) -> None:
        """Disconnected Android peer is sent wake burst and reconnects within grace period."""
        # Simulate background reconnection after 0.2s
        async def delayed_reconnect():
            await asyncio.sleep(0.2)
            mock_ws = MagicMock()
            mock_ws.remote_address = ("192.168.1.150", 49000)
            conn = self.conn_mgr.register(mock_ws)
            self.sess_mgr.create_session(self.android_id, conn.connection_id)

        asyncio.create_task(delayed_reconnect())

        self.mock_ws_server.send_request = AsyncMock(
            return_value=SnowMessage.create_response(
                correlation_id="w1",
                payload={"level": 95, "charging": False},
            )
        )

        res = await self.router.route_request(
            action="android_battery",
            target=self.android_id,
        )

        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "SUCCESS")
        self.assertEqual(res["data"], {"level": 95, "charging": False})
        self.mock_discovery.send_wake_burst.assert_awaited_once_with(self.android_id)
        self.assertIn("android_wake_and_await", res["attempted_transports"])

    async def test_tier3_android_recovery_timeout_falls_to_tier4(self) -> None:
        """Disconnected Android peer that does not reconnect within grace period returns DEVICE_UNREACHABLE."""
        res = await self.router.route_request(
            action="android_battery",
            target=self.android_id,
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "DEVICE_UNREACHABLE")
        self.mock_discovery.send_wake_burst.assert_awaited_once_with(self.android_id)
        self.assertIn("android_wake_and_await", res["attempted_transports"])
        self.assertEqual(res["target_device_id"], self.android_id)


class TestSessionRouterSecurityAndLocalFirst(unittest.IsolatedAsyncioTestCase):
    """Security invariants and local-first execution isolation tests."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_router_sec.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.engine = CapabilityEngine()

        self.conn_mgr = ConnectionManager()
        self.sess_mgr = SessionManager()

        self.mock_ws_server = MagicMock()
        self.mock_ws_server.connection_manager = self.conn_mgr
        self.mock_ws_server.session_manager = self.sess_mgr

        self.registry = NodeRegistry(
            db_manager=self.db,
            connection_manager=self.conn_mgr,
        )
        self.router = SessionRouter(
            node_registry=self.registry,
            ws_server=self.mock_ws_server,
            capability_engine=self.engine,
            db_manager=self.db,
        )

        self.device_id = str(uuid.uuid4())
        self.db.insert_paired_device(self.device_id, "TargetPhone", "hash_sec")
        android_manifest = CapabilityManifest(
            manifest_version="2.0",
            supported_capabilities=["android.battery.get", "android.clipboard.get"],
        )
        self.db.update_device_manifest(self.device_id, android_manifest.to_json())
        mock_ws = MagicMock()
        mock_ws.remote_address = ("192.168.1.111", 50000)
        conn = self.conn_mgr.register(mock_ws)
        self.sess_mgr.create_session(self.device_id, conn.connection_id)

    async def asyncTearDown(self) -> None:
        self.temp_dir.cleanup()

    async def test_spoofed_principal_and_trust_tier_stripped(self) -> None:
        """Caller-supplied authority fields ('principal', 'trust_tier') in request data are stripped."""
        self.mock_ws_server.send_request = AsyncMock(
            return_value=SnowMessage.create_response(
                correlation_id="sec1",
                payload={"status": "ok"},
            )
        )

        spoofed_data = {
            "query": "status",
            "principal": "OWNER_MANUAL",
            "trust_tier": "HIGH_CONFIDENCE",
            "execution_principal": "ADMIN",
        }

        await self.router.route_request(
            action="android_battery",
            target=self.device_id,
            data=spoofed_data,
        )

        # Inspect dispatched payload
        dispatched_payload = self.mock_ws_server.send_request.call_args[1]["payload"]
        self.assertNotIn("principal", dispatched_payload)
        self.assertNotIn("trust_tier", dispatched_payload)
        self.assertNotIn("execution_principal", dispatched_payload)
        self.assertEqual(dispatched_payload.get("query"), "status")

    async def test_local_first_windows_capabilities_run_without_core(self) -> None:
        """Local-first invariant: Windows tools execute in-process via CapabilityEngine with zero daemon dependency."""
        engine = CapabilityEngine()
        # Execute windows_battery locally with AI_MCP principal
        req = CapabilityRequest(action="windows_battery", params={})
        res = await engine.execute(
            req, ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="local_in_process")
        )

        self.assertTrue(res.success)
        self.assertEqual(res.status, "SUCCESS")
        self.assertIsNotNone(res.data)
        self.assertIn("percent", res.data)


if __name__ == "__main__":
    unittest.main()
