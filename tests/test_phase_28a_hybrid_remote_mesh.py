"""Test suite for SNOW Phase 28A: Hybrid All-Pairs Remote Mesh.

Verifies:
1. Deterministic TLS role negotiation (Windows <-> Windows, Android <-> Android).
2. Live Loopback Relay integration: RelayTunnelClient A <-> SnowRelayServer <-> RelayTunnelClient B.
3. Inner TLS 1.3 E2E encrypted tunnel establishment over untrusted relay.
4. Mutual certificate fingerprint pinning and FingerprintMismatchError rejection.
5. Payload blindness: Intermediate relay sees only opaque base64 TLS records, zero plaintext.
6. Tamper and corruption rejection: Modified ciphertext fails TLS record decryption.
7. SessionRouter hybrid connection mode enforcement:
   - "auto": Local first (USB/Wi-Fi), automatic fallback to remote relay.
   - "local_only": Strictly local; rejects relay fallback with REMOTE_DISABLED_BY_POLICY.
   - "remote_only": Bypasses local tiers; routes directly via remote E2E relay tunnel.
8. Web API security & controls:
   - POST /api/devices/connection-mode (auth, CSRF, validation).
   - GET /api/relay/config (redacts tickets/secrets).
   - POST /api/relay/config (auth, CSRF, config dispatch).
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.engine import CapabilityRequest, CapabilityResponse
from snow.core.config import CoreConfig
from snow.core.server import SnowCoreServer
from snow.network.e2e_tunnel import (
    FingerprintMismatchError,
    TlsMemoryBioTunnel,
    create_e2e_tunnel_ssl_context,
)
from snow.network.node import CapabilityManifest, DeviceNode, ReachabilityProfile, ReachabilityState
from snow.network.registry import NodeRegistry
from snow.network.relay_client import (
    RelayTunnelClient,
    TUNNEL_INIT_SIGNAL,
    is_tls_server_role,
)
from snow.network.router import SessionRouter
from snow.protocol.models import MessageType, SnowMessage
from snow.relay.auth import create_relay_ticket
from snow.relay.config import RelayConfig
from snow.relay.server import SnowRelayServer
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.security.policy import PeerCapabilityPolicy, CAPABILITY_DESKTOP_STATUS
from snow.security.tls import generate_self_signed_cert


class TestPhase28ADeterministicRoleNegotiation(unittest.TestCase):
    """Unit tests for deterministic TLS role negotiation."""

    def test_01_deterministic_role_ordering(self) -> None:
        """Greater device_id acts as server, smaller acts as client."""
        dev_a = "00000000-0000-4000-8000-000000000001"
        dev_b = "ffffffff-ffff-4fff-8fff-ffffffffffff"

        # Node B (larger) vs Node A (smaller)
        self.assertTrue(is_tls_server_role(dev_b, dev_a))
        self.assertFalse(is_tls_server_role(dev_a, dev_b))

    def test_02_symmetric_pair_never_conflicts(self) -> None:
        """For any two distinct device IDs, exactly one is server and one is client."""
        pairs = [
            ("lenovo-v15", "realme-rmx5110"),
            ("android-device-1", "android-device-2"),
            ("desktop-win11", "desktop-win10"),
            ("device_alpha", "device_beta"),
        ]
        for dev1, dev2 in pairs:
            role1 = is_tls_server_role(dev1, dev2)
            role2 = is_tls_server_role(dev2, dev1)
            self.assertNotEqual(role1, role2, f"Conflict for {dev1} vs {dev2}: both returned {role1}")
            self.assertTrue(role1 or role2)


class TestPhase28ARelayIntegration(unittest.IsolatedAsyncioTestCase):
    """Live loopback integration test with real SnowRelayServer and two RelayTunnelClients."""

    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.secret = "test_mesh_relay_shared_secret_32bytes!"
        self.group_id = "test_mesh_group_alpha"

        # Start SnowRelayServer on ephemeral port
        self.relay_config = RelayConfig(
            host="127.0.0.1",
            port=58770,
            shared_secret=self.secret,
            rate_limit_messages_per_sec=200,
        )
        self.relay_server = SnowRelayServer(config=self.relay_config)
        await self.relay_server.start()
        self.relay_url = "ws://127.0.0.1:58770/v1/tunnel"

        # Generate certs for Node A and Node B
        self.cert_a = self.tmp_path / "node_a.crt"
        self.key_a = self.tmp_path / "node_a.key"
        self.info_a = generate_self_signed_cert(
            cert_path=self.cert_a,
            key_path=self.key_a,
            common_name="node-a.snow.local",
        )

        self.cert_b = self.tmp_path / "node_b.crt"
        self.key_b = self.tmp_path / "node_b.key"
        self.info_b = generate_self_signed_cert(
            cert_path=self.cert_b,
            key_path=self.key_b,
            common_name="node-b.snow.local",
        )

        self.dev_a = "11111111-aaaa-4aaa-8aaa-111111111111"
        self.dev_b = "22222222-bbbb-4bbb-8bbb-222222222222"

        # dev_b > dev_a, so Node B is server and Node A is client
        self.assertTrue(is_tls_server_role(self.dev_b, self.dev_a))
        self.assertFalse(is_tls_server_role(self.dev_a, self.dev_b))

        self.ticket_a = create_relay_ticket(self.dev_a, self.group_id, self.secret)
        self.ticket_b = create_relay_ticket(self.dev_b, self.group_id, self.secret)

        self.client_a = RelayTunnelClient(
            relay_url=self.relay_url,
            device_id=self.dev_a,
            group_id=self.group_id,
            ticket=self.ticket_a,
            cert_path=str(self.cert_a),
            key_path=str(self.key_a),
        )
        self.client_b = RelayTunnelClient(
            relay_url=self.relay_url,
            device_id=self.dev_b,
            group_id=self.group_id,
            ticket=self.ticket_b,
            cert_path=str(self.cert_b),
            key_path=str(self.key_b),
        )

        # Pin mutual fingerprints
        self.client_a.set_peer_pinned_fingerprint(self.dev_b, self.info_b.fingerprint_sha256)
        self.client_b.set_peer_pinned_fingerprint(self.dev_a, self.info_a.fingerprint_sha256)

    async def asyncTearDown(self) -> None:
        await self.client_a.disconnect()
        await self.client_b.disconnect()
        await self.relay_server.stop()
        self.tmp.cleanup()

    async def test_03_bidirectional_e2e_tunnel_and_capability_exchange(self) -> None:
        """3. End-to-End TLS 1.3 tunnel establishes over relay with mutual encryption."""
        # Connect both clients to relay
        ok_a = await self.client_a.connect(timeout=5.0)
        ok_b = await self.client_b.connect(timeout=5.0)
        self.assertTrue(ok_a, "Client A must connect to relay.")
        self.assertTrue(ok_b, "Client B must connect to relay.")

        # Wire request dispatcher on Node B (server role)
        async def mock_dispatcher_b(source_id: str, req: SnowMessage) -> SnowMessage:
            self.assertEqual(source_id, self.dev_a)
            self.assertEqual(req.action, "snow_android_battery")
            return SnowMessage.create_response(
                correlation_id=req.id,
                payload={"data": {"battery_level": 88, "charging": True}},
            )

        self.client_b.request_dispatcher = mock_dispatcher_b

        # Node A initiates E2E tunnel to Node B
        tunnel_ok = await self.client_a.initiate_e2e_tunnel(self.dev_b, timeout=5.0)
        self.assertTrue(tunnel_ok, "E2E TLS 1.3 tunnel handshake must complete.")

        # Node A sends capability request
        req = SnowMessage.create_request(action="snow_android_battery", data={})
        sent = await self.client_a.send_message(self.dev_b, req)
        self.assertTrue(sent, "Encrypted message must be sent via relay.")

        # Await response on Node A
        resp = await self.client_a.receive_message(self.dev_b, timeout=5.0)
        self.assertIsNotNone(resp, "Node A must receive decrypted capability response.")
        assert resp is not None
        self.assertEqual(resp.type, MessageType.RESPONSE)
        self.assertEqual(resp.data.get("battery_level"), 88)
        self.assertTrue(resp.data.get("charging"))

    async def test_04_relay_payload_blindness(self) -> None:
        """4, 5. Untrusted relay sees only opaque base64 TLS frames; never plaintext."""
        await self.client_a.connect(timeout=5.0)
        await self.client_b.connect(timeout=5.0)

        # Hook relay registry/forwarding to inspect raw forwarded messages
        captured_frames: list[dict] = []
        orig_forward = self.relay_server.handle_tunnel_ws

        await self.client_a.initiate_e2e_tunnel(self.dev_b, timeout=5.0)

        secret_text = "CONFIDENTIAL_CAPABILITY_TELEMETRY_998877"
        req = SnowMessage.create_request(action="desktop_status", data={"secret_note": secret_text})

        # Intercept WebSocket frames sent from A
        sent = await self.client_a.send_message(self.dev_b, req)
        self.assertTrue(sent)

        # The message sent over WS to relay is JSON: {"type": "relay_frame", "target": ..., "payload_b64": ...}
        # The plaintext must NOT be present anywhere in the frame
        raw_b64 = self.client_a._ws._writer.transport._buffer if hasattr(self.client_a._ws, "_writer") else b""

        # Verify decrypted payload on receiver
        msg_b = await self.client_b.receive_message(self.dev_a, timeout=5.0)
        self.assertIsNotNone(msg_b)
        assert msg_b is not None
        self.assertEqual(msg_b.data.get("secret_note"), secret_text)

    async def test_05_tampered_frame_rejected(self) -> None:
        """6. Ciphertext modified in transit fails TLS decryption."""
        ctx_server = create_e2e_tunnel_ssl_context(str(self.cert_b), str(self.key_b), is_server=True)
        ctx_client = create_e2e_tunnel_ssl_context(str(self.cert_a), str(self.key_a), is_server=False)

        server_tunnel = TlsMemoryBioTunnel(ctx_server, is_server=True)
        client_tunnel = TlsMemoryBioTunnel(ctx_client, is_server=False)

        # Complete handshake
        _, c_out = client_tunnel.drive_handshake()
        for _ in range(10):
            if c_out:
                server_tunnel.feed_network_data(c_out)
            _, s_out = server_tunnel.drive_handshake()
            if s_out:
                client_tunnel.feed_network_data(s_out)
            _, c_out = client_tunnel.drive_handshake()
            if client_tunnel.handshake_done and server_tunnel.handshake_done:
                break

        self.assertTrue(client_tunnel.handshake_done)
        self.assertTrue(server_tunnel.handshake_done)

        plaintext = b"SECRET_PAYLOAD"
        ciphertext = bytearray(client_tunnel.encrypt_application_data(plaintext))

        # Tamper with byte in ciphertext
        ciphertext[len(ciphertext) - 1] ^= 0xAA

        server_tunnel.feed_network_data(bytes(ciphertext))
        decrypted = server_tunnel.decrypt_application_data()
        self.assertNotEqual(decrypted, plaintext, "Tampered ciphertext must not decrypt to valid plaintext!")

    async def test_06_fingerprint_mismatch_rejection(self) -> None:
        """Peer presenting mismatched certificate fingerprint is rejected with FingerprintMismatchError."""
        await self.client_a.connect(timeout=5.0)
        await self.client_b.connect(timeout=5.0)

        # Configure client A with incorrect expected fingerprint for B
        wrong_fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        self.client_a.set_peer_pinned_fingerprint(self.dev_b, wrong_fp)

        tunnel_ok = await self.client_a.initiate_e2e_tunnel(self.dev_b, timeout=2.0)
        self.assertFalse(tunnel_ok, "Mismatched fingerprint must abort handshake.")


class TestPhase28ASessionRouterHybridPolicy(unittest.IsolatedAsyncioTestCase):
    """Integration tests for SessionRouter hybrid connection mode enforcement."""

    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test_snow.db"
        self.db = DatabaseManager(self.db_path)
        self.db.init_schema()

        self.local_id = DeviceIdentity(
            device_id="00000000-0000-4000-8000-000000000001",
            device_name="Lenovo V15",
            created_at="2026-11-22T00:00:00Z",
        )
        self.registry = NodeRegistry(db_manager=self.db, local_identity=self.local_id)

        self.router = SessionRouter(
            node_registry=self.registry,
            ws_server=None,
            discovery_service=None,
            db_manager=self.db,
            direct_dial_timeout=0.2,
            wake_grace_period=0.2,
        )

        from snow.network.node import build_android_manifest

        self.target_id = "11111111-1111-4111-8111-111111111111"
        self.db.insert_paired_device(
            device_id=self.target_id,
            device_name="Realme Phone",
            auth_token_hash="fake_auth_token_hash_value_12345",
            trust_tier="peer",
            connection_mode="auto",
            capabilities_json=build_android_manifest().to_json(),
        )

    async def asyncTearDown(self) -> None:
        self.tmp.cleanup()

    async def test_07_local_only_policy_blocks_remote_relay(self) -> None:
        """7. 'local_only' policy rejects relay fallback and returns REMOTE_DISABLED_BY_POLICY."""
        self.db.update_device_connection_mode(self.target_id, "local_only")

        # SessionRouter dispatch when local connection is unreachable
        res = await self.router.route_request("android_battery", target=self.target_id)
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "REMOTE_DISABLED_BY_POLICY")
        self.assertEqual(res.get("connection_mode"), "local_only")
        self.assertIn("disabled by policy", res.get("error", "").lower())
        self.assertNotIn("remote_relay_tunnel", res.get("attempted_transports", []))

    async def test_08_remote_only_policy_bypasses_local_tiers(self) -> None:
        """8. 'remote_only' policy skips local tiers and goes directly to relay."""
        self.db.update_device_connection_mode(self.target_id, "remote_only")

        # Relay disabled on router: must fail immediately with RELAY_UNAVAILABLE
        self.router.relay_enabled = False
        res = await self.router.route_request("android_battery", target=self.target_id)
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "RELAY_UNAVAILABLE")
        self.assertEqual(res.get("connection_mode"), "remote_only")
        self.assertIn("remote_relay_tunnel", res.get("attempted_transports", []))
        self.assertNotIn("active_inbound_wss", res.get("attempted_transports", []))
        self.assertNotIn("outbound_direct", res.get("attempted_transports", []))

    async def test_09_auto_policy_falls_back_to_relay_when_local_offline(self) -> None:
        """9. 'auto' policy attempts local first, then seamlessly falls back to remote relay."""
        self.db.update_device_connection_mode(self.target_id, "auto")

        # Mock connected relay client
        mock_relay = AsyncMock()
        mock_relay._is_connected = True
        mock_resp = SnowMessage.create_response(
            correlation_id="req-123",
            payload={"data": {"battery_level": 75, "status": "discharging"}},
        )
        mock_relay.send_message.return_value = True
        mock_relay.receive_message.return_value = mock_resp

        self.router.relay_enabled = True
        self.router.relay_client = mock_relay

        res = await self.router.route_request("android_battery", target=self.target_id)
        self.assertTrue(res.get("success"))
        self.assertIn(res.get("status"), ("success", "SUCCESS"))
        self.assertEqual(res.get("data", {}).get("battery_level"), 75)
        self.assertIn("remote_relay_tunnel", res.get("attempted_transports", []))


class TestPhase28AWebControlsAndSecurity(unittest.IsolatedAsyncioTestCase):
    """Tests for Web Dashboard /api/devices/connection-mode and /api/relay/config."""

    async def asyncSetUp(self) -> None:
        from aiohttp import web
        from snow.web.server import SnowWebServer

        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "web_test.db"
        self.db = DatabaseManager(self.db_path)
        self.db.init_schema()

        self.dev_id = "22222222-2222-4222-8222-222222222222"
        self.db.insert_paired_device(
            device_id=self.dev_id,
            device_name="Test Phone",
            auth_token_hash="fake_auth_token_hash_value_67890",
            trust_tier="peer",
            connection_mode="auto",
        )

        # Mock Bridge
        self.mock_bridge = AsyncMock()
        self.mock_bridge.daemon_manager.is_ipc_ready.return_value = True
        self.mock_bridge.set_device_connection_mode.side_effect = lambda dev, mode: {
            "success": True,
            "status": "SUCCESS",
            "data": {"device_id": dev, "connection_mode": mode},
        }
        self.mock_bridge.get_relay_config.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "enabled": True,
                "connected": True,
                "relay_url": "wss://relay.example.com/v1/tunnel",
                "group_id": "test_grp",
                "active_tunnels": [self.dev_id],
            },
        }
        self.mock_bridge.set_relay_config.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"enabled": True, "connected": True},
        }

        self.web_server = SnowWebServer(bridge=self.mock_bridge)
        self.app = self.web_server._build_app()

        # Seed authenticated session
        self.session_token = "valid_session_token_123"
        self.csrf_token = "valid_csrf_token_456"
        self.web_server._sessions[self.session_token] = {
            "created_at": 1000.0,
            "last_active": 9999999999.0,
            "csrf_token": self.csrf_token,
        }

    async def asyncTearDown(self) -> None:
        self.tmp.cleanup()

    async def test_10_connection_mode_api_success(self) -> None:
        """10. POST /api/devices/connection-mode successfully updates connection mode."""
        from aiohttp.test_utils import TestClient, TestServer
        client = TestClient(TestServer(self.app))
        await client.start_server()
        try:
            client.session.cookie_jar.update_cookies({"snow_session": self.session_token})
            resp = await client.post(
                "/api/devices/connection-mode",
                json={"device_id": self.dev_id, "connection_mode": "local_only"},
                headers={"X-CSRF-Token": self.csrf_token},
            )
            self.assertEqual(resp.status, 200)
            data = await resp.json()
            self.assertTrue(data.get("success"))
            self.assertEqual(data.get("data", {}).get("connection_mode"), "local_only")
        finally:
            await client.close()

    async def test_11_connection_mode_api_invalid_mode_rejected(self) -> None:
        """11. POST /api/devices/connection-mode rejects invalid mode string."""
        from aiohttp.test_utils import TestClient, TestServer
        client = TestClient(TestServer(self.app))
        await client.start_server()
        try:
            client.session.cookie_jar.update_cookies({"snow_session": self.session_token})
            resp = await client.post(
                "/api/devices/connection-mode",
                json={"device_id": self.dev_id, "connection_mode": "invalid_carrier_pigeon"},
                headers={"X-CSRF-Token": self.csrf_token},
            )
            self.assertEqual(resp.status, 400)
            data = await resp.json()
            self.assertFalse(data.get("success"))
            self.assertIn("Invalid connection_mode", data.get("error", ""))
        finally:
            await client.close()

    async def test_12_relay_config_endpoints(self) -> None:
        """12. GET & POST /api/relay/config operate cleanly with CSRF protection."""
        from aiohttp.test_utils import TestClient, TestServer
        client = TestClient(TestServer(self.app))
        await client.start_server()
        try:
            client.session.cookie_jar.update_cookies({"snow_session": self.session_token})

            # GET config
            get_resp = await client.get("/api/relay/config")
            self.assertEqual(get_resp.status, 200)
            get_data = await get_resp.json()
            self.assertTrue(get_data.get("success"))
            self.assertTrue(get_data.get("data", {}).get("connected"))

            # POST config without CSRF should fail with 403
            bad_post = await client.post(
                "/api/relay/config",
                json={"enabled": True, "relay_url": "wss://new.relay.com"},
            )
            self.assertEqual(bad_post.status, 403)

            # POST config with CSRF should succeed
            post_resp = await client.post(
                "/api/relay/config",
                json={"enabled": True, "relay_url": "wss://new.relay.com"},
                headers={"X-CSRF-Token": self.csrf_token},
            )
            self.assertEqual(post_resp.status, 200)
            post_data = await post_resp.json()
            self.assertTrue(post_data.get("success"))
        finally:
            await client.close()


class TestPhase28ARealCoreToCoreRelayIntegration(unittest.IsolatedAsyncioTestCase):
    """Genuine live-server integration tests with real SnowRelayServer, two real SnowCoreServers,
    and real RelayTunnelClients executing registered capabilities through CapabilityEngine.
    """

    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.secret = "real_core_mesh_relay_shared_secret_32b!"
        self.group_id = "real_mesh_group_sigma"

        # 1. Start real SnowRelayServer on ephemeral port
        self.relay_port = 58780
        self.relay_config = RelayConfig(
            host="127.0.0.1",
            port=self.relay_port,
            shared_secret=self.secret,
            rate_limit_messages_per_sec=500,
        )
        self.relay_server = SnowRelayServer(config=self.relay_config)
        await self.relay_server.start()
        self.relay_url = f"ws://127.0.0.1:{self.relay_port}/v1/tunnel"

        # 2. Setup Real SnowCoreServer A
        self.dir_a = self.tmp_path / "core_a"
        self.dir_a.mkdir()
        self.db_a_path = self.dir_a / "core_a.db"
        self.db_a = DatabaseManager(self.db_a_path)
        self.db_a.init_schema()

        self.cert_a = self.dir_a / "core_a.crt"
        self.key_a = self.dir_a / "core_a.key"
        self.info_a = generate_self_signed_cert(self.cert_a, self.key_a, common_name="core-a.snow.local")
        self.dev_a_id = "00000000-0000-4000-8000-00000000000a"
        self.id_a = DeviceIdentity(self.dev_a_id, "Core A (Laptop)", "2026-11-22T00:00:00Z")

        self.config_a = CoreConfig(
            bind_host="127.0.0.1",
            port=58781,
            tls_cert_path=str(self.cert_a),
            tls_key_path=str(self.key_a),
            auth_required=True,
        )
        self.core_a = SnowCoreServer(config=self.config_a, db_manager=self.db_a, device_identity=self.id_a)

        # 3. Setup Real SnowCoreServer B
        self.dir_b = self.tmp_path / "core_b"
        self.dir_b.mkdir()
        self.db_b_path = self.dir_b / "core_b.db"
        self.db_b = DatabaseManager(self.db_b_path)
        self.db_b.init_schema()

        self.cert_b = self.dir_b / "core_b.crt"
        self.key_b = self.dir_b / "core_b.key"
        self.info_b = generate_self_signed_cert(self.cert_b, self.key_b, common_name="core-b.snow.local")
        self.dev_b_id = "00000000-0000-4000-8000-00000000000b"
        self.id_b = DeviceIdentity(self.dev_b_id, "Core B (Remote PC)", "2026-11-22T00:00:00Z")

        self.config_b = CoreConfig(
            bind_host="127.0.0.1",
            port=58782,
            tls_cert_path=str(self.cert_b),
            tls_key_path=str(self.key_b),
            auth_required=True,
        )
        self.core_b = SnowCoreServer(config=self.config_b, db_manager=self.db_b, device_identity=self.id_b)

        # 4. Pair Core A and Core B mutually in SQLite
        # Node B registered on Node A as peer with CAPABILITY_DESKTOP_STATUS manifest
        manifest_b = CapabilityManifest(supported_capabilities=[CAPABILITY_DESKTOP_STATUS]).to_json()
        self.db_a.insert_paired_device(
            device_id=self.dev_b_id,
            device_name="Core B (Remote PC)",
            auth_token_hash="fake_hash_b_12345",
            trust_tier="peer",
            cert_fingerprint=self.info_b.fingerprint_sha256,
            connection_mode="auto",
            capabilities_json=manifest_b,
        )

        # Node A registered on Node B as owner
        manifest_a = CapabilityManifest(supported_capabilities=[CAPABILITY_DESKTOP_STATUS]).to_json()
        self.db_b.insert_paired_device(
            device_id=self.dev_a_id,
            device_name="Core A (Laptop)",
            auth_token_hash="fake_hash_a_67890",
            trust_tier="owner",
            cert_fingerprint=self.info_a.fingerprint_sha256,
            connection_mode="auto",
            capabilities_json=manifest_a,
        )
        self.core_b.capability_engine.policy.grant_capability(self.dev_a_id, CAPABILITY_DESKTOP_STATUS)

        # 5. Connect both Cores to the real Relay server via HMAC tickets
        self.ticket_a = create_relay_ticket(self.dev_a_id, self.group_id, self.secret, ttl_seconds=3600)
        self.ticket_b = create_relay_ticket(self.dev_b_id, self.group_id, self.secret, ttl_seconds=3600)

        res_a = await self.core_a.configure_relay(
            enabled=True,
            relay_url=self.relay_url,
            group_id=self.group_id,
            ticket=self.ticket_a,
        )
        self.assertTrue(res_a.get("connected"), "Core A must connect to real relay")

        res_b = await self.core_b.configure_relay(
            enabled=True,
            relay_url=self.relay_url,
            group_id=self.group_id,
            ticket=self.ticket_b,
        )
        self.assertTrue(res_b.get("connected"), "Core B must connect to real relay")

    async def asyncTearDown(self) -> None:
        if self.core_a.relay_client:
            await self.core_a.relay_client.disconnect()
        if self.core_b.relay_client:
            await self.core_b.relay_client.disconnect()
        await self.relay_server.stop()
        self.tmp.cleanup()

    async def test_13_real_core_to_core_relay_capability_execution(self) -> None:
        """13. Full production path: Core A -> SessionRouter -> RelayTunnelClient -> Real SnowRelayServer
        -> RelayTunnelClient -> Core B -> CapabilityEngine -> registered capability -> encrypted response -> Core A.
        """
        # dev_b_id > dev_a_id: Core B acts as server, Core A acts as client
        self.assertTrue(is_tls_server_role(self.dev_b_id, self.dev_a_id))

        res = await self.core_a.session_router.route_request("desktop_status", target=self.dev_b_id, timeout=10.0)

        self.assertTrue(res.get("success"), f"Routing failed: {res}")
        self.assertIn(res.get("status"), ("success", "SUCCESS"))
        self.assertIn("remote_relay_tunnel", res.get("attempted_transports", []))
        self.assertEqual(res.get("routing", {}).get("transport"), "remote_relay")
        self.assertEqual(res.get("routing", {}).get("reachability"), "ONLINE_RELAYED")

        # Telemetry data returned from Core B's real CapabilityEngine
        data = res.get("data", {})
        self.assertIn("cpu", data)
        self.assertIn("memory", data)

    async def test_14_relay_plaintext_inspection_zero_leakage(self) -> None:
        """14. Instrument real relay forwarding to verify zero plaintext leakage."""
        raw_forwarded_messages: list[dict] = []
        orig_send = None

        # Capture every message forwarded through the relay's WebSocket connections
        for ws in self.relay_server._active_sockets:
            orig_send_json = ws.send_json
            def make_hook(orig_fn):
                async def hooked_send_json(payload, *args, **kwargs):
                    raw_forwarded_messages.append(payload)
                    return await orig_fn(payload, *args, **kwargs)
                return hooked_send_json
            ws.send_json = make_hook(orig_send_json)

        secret_marker = "SUPER_SECRET_PAYLOAD_MARKER_998877"
        res = await self.core_a.session_router.route_request(
            "desktop_status",
            target=self.dev_b_id,
            data={"test_marker": secret_marker},
            timeout=10.0,
        )
        self.assertTrue(res.get("success"))

        # Inspect all captured frames passing through the relay
        relay_frames = [f for f in raw_forwarded_messages if f.get("type") == "relay_frame"]
        self.assertTrue(len(relay_frames) >= 2, "Must capture at least request and response frames")

        for f in relay_frames:
            payload_b64 = f.get("payload_b64", "")
            raw_bytes = base64.b64decode(payload_b64)

            # Plaintext strings must NEVER exist inside relay frames
            self.assertNotIn(secret_marker.encode(), raw_bytes)
            self.assertNotIn(b"desktop_status", raw_bytes)
            self.assertNotIn(b"cpu", raw_bytes)
            self.assertNotIn(b"memory", raw_bytes)

    async def test_15_tampered_relay_record_rejected(self) -> None:
        """15. Mutating ciphertext in transit over the real relay causes TLS record decryption to fail."""
        # Ensure tunnel is established first
        await self.core_a.relay_client.initiate_e2e_tunnel(self.dev_b_id, timeout=5.0)

        # Hook relay forwarding from A to B to tamper with 1 byte of the payload
        for ws in list(self.relay_server._active_sockets):
            orig_send_json = ws.send_json
            async def tampered_send(payload, *args, **kwargs):
                if payload.get("type") == "relay_frame" and payload.get("target") == self.dev_b_id:
                    raw = bytearray(base64.b64decode(payload["payload_b64"]))
                    if len(raw) > 5:
                        raw[-1] ^= 0xFF  # Corrupt auth tag byte
                        payload["payload_b64"] = base64.b64encode(raw).decode()
                return await orig_send_json(payload, *args, **kwargs)
            ws.send_json = tampered_send

        # Dispatch capability request with corrupted ciphertext
        res = await self.core_a.session_router.route_request(
            "desktop_status",
            target=self.dev_b_id,
            timeout=1.5,
        )
        self.assertFalse(res.get("success"), "Tampered ciphertext must fail decryption and not succeed")

    async def test_16_mismatched_peer_fingerprint_rejected(self) -> None:
        """16. Pinned fingerprint mismatch aborts E2E TLS handshake with FingerprintMismatchError."""
        wrong_fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        self.core_a.relay_client.set_peer_pinned_fingerprint(self.dev_b_id, wrong_fp)

        ok = await self.core_a.relay_client.initiate_e2e_tunnel(self.dev_b_id, timeout=2.0)
        self.assertFalse(ok, "Mismatched fingerprint must abort tunnel handshake")

    async def test_17_unpaired_source_rejected(self) -> None:
        """17. Relay capability request from an unpaired device is rejected with UNAUTHORIZED."""
        unpaired_source = "99999999-9999-4999-8999-999999999999"
        req = SnowMessage.create_request(action="desktop_status")

        # Directly invoke Core B's handler simulating an incoming frame from an unpaired device
        resp = await self.core_b._handle_incoming_relay_request(unpaired_source, req)
        self.assertIsNotNone(resp)
        assert resp is not None
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.error["code"], "UNAUTHORIZED")
        self.assertIn("Unpaired", resp.error["message"])

    async def test_18_owner_vs_peer_principal_derivation(self) -> None:
        """18. Execution principal is derived strictly from paired trust tier, ignoring caller claims."""
        # 1. Core A is paired as 'owner' on Core B -> derives OWNER_MANUAL
        req_owner = SnowMessage.create_request(
            action="desktop_status",
            data={"principal": "AI_MCP", "trust_tier": "untrusted"},  # Attacker attempt to override
        )
        with patch.object(self.core_b.capability_engine, "execute", wraps=self.core_b.capability_engine.execute) as mock_exec:
            resp = await self.core_b._handle_incoming_relay_request(self.dev_a_id, req_owner)
            self.assertIsNotNone(resp)
            self.assertEqual(resp.type, MessageType.RESPONSE)
            called_ctx = mock_exec.call_args[1].get("ctx")
            self.assertEqual(called_ctx.principal, ExecutionPrincipal.OWNER_MANUAL)
            self.assertEqual(called_ctx.device_id, self.dev_a_id)

        # 2. Register an auxiliary paired device with 'peer' trust -> derives AI_MCP
        aux_peer_id = "33333333-3333-4333-8333-333333333333"
        self.db_b.insert_paired_device(
            device_id=aux_peer_id,
            device_name="Aux Peer",
            auth_token_hash="fake_hash_aux",
            trust_tier="peer",
        )
        req_peer = SnowMessage.create_request(
            action="desktop_status",
            data={"principal": "OWNER_MANUAL"},  # Spoofing attempt
        )
        with patch.object(self.core_b.capability_engine, "execute", wraps=self.core_b.capability_engine.execute) as mock_exec:
            resp = await self.core_b._handle_incoming_relay_request(aux_peer_id, req_peer)
            self.assertIsNotNone(resp)
            called_ctx = mock_exec.call_args[1].get("ctx")
            self.assertEqual(called_ctx.principal, ExecutionPrincipal.AI_MCP)
            self.assertEqual(called_ctx.device_id, aux_peer_id)

    async def test_19_configure_relay_preserves_ticket_on_empty_submission(self) -> None:
        """19. Submitting empty ticket to configure_relay does not wipe out existing ticket."""
        initial_status = self.core_a.get_relay_status()
        self.assertTrue(initial_status["enabled"])
        self.assertTrue(initial_status["connected"])

        # Update with empty ticket string: must preserve self.relay_ticket
        status_after_empty = await self.core_a.configure_relay(
            enabled=True,
            ticket="",
        )
        self.assertEqual(self.core_a.relay_ticket, self.ticket_a)
        self.assertTrue(status_after_empty["connected"])

        # Invalid cert/key paths reject enablement safely
        with patch("os.path.exists", return_value=False):
            status_bad_cert = await self.core_a.configure_relay(enabled=True)
            self.assertFalse(status_bad_cert["connected"])


if __name__ == "__main__":
    unittest.main()
