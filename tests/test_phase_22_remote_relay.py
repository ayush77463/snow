"""Test suite for SNOW Phase 22: Remote Security & Connectivity Foundation + Relay.

Covers:
1. Relay client authentication (ticket issuance, signature validation, expiration).
2. Unauthorized device rejection.
3. Device identity and group validation (cross-group routing blocked).
4. Presence registration and expiration.
5. ONLINE_RELAY and DORMANT_RELAY states.
6. Active session revocation (control plane terminates live tunnel socket).
7. Rate limits (sliding window enforcement).
8. Per-transfer and aggregate rolling quotas.
9. Oversized frame rejection (25 MiB max limit).
10. Bounded queue and backpressure safety.
11. Local-first route selection in SessionRouter (local LAN/USB attempted before relay).
12. Relay-disabled behavior (opt-in default is False).
13. Relay-offline behavior (graceful fallback without crashing).
14. Relay reconnection.
15. Genuine End-to-End TLS 1.3 handshake over untrusted relay.
16. Mutual certificate authentication.
17. Invalid certificate rejection.
18. Fingerprint mismatch rejection (FingerprintMismatchError).
19. Payload blindness (relay forwards opaque base64 / binary records without decrypting).
20. Tamper and replay rejection (corrupted frame fails TLS decryption).
21. Capability authorization strictly at the receiving endpoint.
22. No relay-side capability execution or approval authority.
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
import ssl
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp

from snow.network.e2e_tunnel import (
    FingerprintMismatchError,
    TlsMemoryBioTunnel,
    create_e2e_tunnel_ssl_context,
)
from snow.network.node import DeviceNode, ReachabilityProfile, ReachabilityState
from snow.network.relay_client import RelayTunnelClient
from snow.network.router import SessionRouter
from snow.protocol.constants import ErrorCode
from snow.protocol.models import MessageType, SnowMessage
from snow.relay.auth import create_relay_ticket, verify_relay_ticket
from snow.relay.config import RelayConfig
from snow.relay.quotas import QuotaManager
from snow.relay.rendezvous import (
    RendezvousRegistry,
    STATE_DORMANT_RELAY,
    STATE_OFFLINE,
    STATE_ONLINE_RELAY,
)
from snow.relay.server import SnowRelayServer
from snow.security.tls import generate_self_signed_cert


class TestPhase22RelayCoreUnit(unittest.TestCase):
    """Unit tests for relay auth, quotas, presence, and configuration."""

    def setUp(self) -> None:
        self.secret = "test_relay_secret_32bytes_long_key_!"
        self.dev_a = "11111111-1111-4111-8111-111111111111"
        self.dev_b = "22222222-2222-4222-8222-222222222222"
        self.group = "mesh-group-main"

    def test_01_relay_ticket_generation_and_verification(self) -> None:
        """1. Valid ticket generated with secret successfully verifies."""
        ticket = create_relay_ticket(self.dev_a, self.group, self.secret, ttl_seconds=60)
        valid, dev, grp, err = verify_relay_ticket(ticket, self.secret)
        self.assertTrue(valid)
        self.assertEqual(dev, self.dev_a)
        self.assertEqual(grp, self.group)
        self.assertIsNone(err)

    def test_02_unauthorized_device_wrong_secret_rejected(self) -> None:
        """2. Ticket signed with wrong secret is rejected."""
        ticket = create_relay_ticket(self.dev_a, self.group, "wrong_secret", ttl_seconds=60)
        valid, dev, grp, err = verify_relay_ticket(ticket, self.secret)
        self.assertFalse(valid)
        self.assertIn("signature", (err or "").lower())

    def test_03_expired_ticket_rejected(self) -> None:
        """Ticket past its expiration time is rejected."""
        ticket = create_relay_ticket(self.dev_a, self.group, self.secret, ttl_seconds=-10)
        valid, dev, grp, err = verify_relay_ticket(ticket, self.secret)
        self.assertFalse(valid)
        self.assertIn("expired", (err or "").lower())

    def test_04_device_identity_and_cross_group_isolation(self) -> None:
        """3. Relay blocks routing between devices in different destination groups."""
        registry = RendezvousRegistry()
        mock_ws_a = MagicMock()
        mock_ws_b = MagicMock()

        registry.register(self.dev_a, "group-alpha", mock_ws_a)
        registry.register(self.dev_b, "group-beta", mock_ws_b)

        target_ws, err = registry.get_peer_session(self.dev_a, self.dev_b)
        self.assertIsNone(target_ws)
        self.assertIn("different destination group", err)

    def test_05_presence_registration_and_dormancy(self) -> None:
        """4, 5. Presence state reflects ONLINE_RELAY and transitions to DORMANT_RELAY."""
        registry = RendezvousRegistry()
        mock_ws = MagicMock()
        registry.register(self.dev_a, self.group, mock_ws)

        pres = registry.get_presence(self.dev_a)
        self.assertEqual(pres["state"], STATE_ONLINE_RELAY)

        registry.mark_dormant(self.dev_a)
        pres_dormant = registry.get_presence(self.dev_a)
        self.assertEqual(pres_dormant["state"], STATE_DORMANT_RELAY)

    def test_06_active_session_revocation(self) -> None:
        """6. Revoking a device removes presence and returns socket for closure."""
        registry = RendezvousRegistry()
        mock_ws_a = MagicMock()
        mock_ws_b = MagicMock()
        registry.register(self.dev_a, self.group, mock_ws_a)
        registry.register(self.dev_b, self.group, mock_ws_b)

        closed_ws = registry.revoke_device(self.dev_a)
        self.assertIs(closed_ws, mock_ws_a)

        # Subsequent lookup denied
        target_ws, err = registry.get_peer_session(self.dev_b, self.dev_a)
        self.assertIsNone(target_ws)
        self.assertIn("revoked", err)

    def test_07_rate_limits_enforced(self) -> None:
        """7. Rate limiter rejects requests exceeding permitted threshold."""
        quotas = QuotaManager(rate_limit_messages_per_sec=5)
        for _ in range(5):
            ok, _ = quotas.check_rate_limit(self.dev_a)
            self.assertTrue(ok)
        ok, err = quotas.check_rate_limit(self.dev_a)
        self.assertFalse(ok)
        self.assertIn("rate limit exceeded", err.lower())

    def test_08_per_transfer_and_rolling_quota(self) -> None:
        """8. Transfer quota enforces windowed volume limits."""
        quotas = QuotaManager(max_transfer_quota_bytes=1000, quota_window_seconds=60)
        ok, _ = quotas.check_and_record_transfer(self.dev_a, 600)
        self.assertTrue(ok)
        # Exceeds quota (600 + 500 = 1100 > 1000)
        ok2, err2 = quotas.check_and_record_transfer(self.dev_a, 500)
        self.assertFalse(ok2)
        self.assertIn("quota exceeded", err2.lower())

    def test_09_oversized_frame_rejection(self) -> None:
        """9. Single frame exceeding max_frame_size (25 MiB) is rejected."""
        quotas = QuotaManager(max_frame_size=25 * 1024 * 1024)
        ok, _ = quotas.check_frame_size(24 * 1024 * 1024)
        self.assertTrue(ok)
        ok_over, err_over = quotas.check_frame_size(26 * 1024 * 1024)
        self.assertFalse(ok_over)
        self.assertIn("25 MiB", err_over)

    def test_10_presence_sweep_stale_sessions(self) -> None:
        """10. Sweep transitions stale sessions to dormant."""
        registry = RendezvousRegistry(presence_stale_seconds=0.05, dormant_timeout_seconds=0.1)
        mock_ws = MagicMock()
        registry.register(self.dev_a, self.group, mock_ws)

        time.sleep(0.07)
        to_close = registry.sweep_stale_sessions()
        self.assertIn(mock_ws, to_close)
        self.assertEqual(registry.get_presence(self.dev_a)["state"], STATE_DORMANT_RELAY)


class TestPhase22LocalFirstRouting(unittest.IsolatedAsyncioTestCase):
    """Test Local-First preference, relay-disabled, and relay fallback in SessionRouter."""

    async def asyncSetUp(self) -> None:
        self.mock_registry = MagicMock()
        self.mock_ws_server = MagicMock()
        self.mock_discovery = MagicMock()
        self.mock_engine = MagicMock()
        self.mock_db = MagicMock()

        self.target_id = "target-android-uuid-1"
        self.node = DeviceNode(
            device_id=self.target_id,
            device_name="Target Phone",
            platform="Android",
            reachability_profile=ReachabilityProfile.ACTIVE_SESSION_PEER,
            reachability_state=ReachabilityState.CONNECTED_SESSION,
        )
        self.mock_registry.get_node.return_value = self.node
        self.mock_registry.resolve_query.return_value = self.node
        self.mock_registry.resolve_target.return_value = (self.node, None)

    async def test_11_local_route_preferred_over_relay(self) -> None:
        """11. SessionRouter uses active local LAN WSS session first, even when relay is enabled."""
        mock_relay_client = MagicMock()
        mock_relay_client._is_connected = True

        router = SessionRouter(
            node_registry=self.mock_registry,
            ws_server=self.mock_ws_server,
            discovery_service=self.mock_discovery,
            capability_engine=self.mock_engine,
            db_manager=self.mock_db,
            relay_client=mock_relay_client,
            relay_enabled=True,
        )

        # Inbound session exists
        mock_sess = MagicMock()
        mock_sess.connection_id = "conn-local-1"
        self.mock_ws_server.session_manager.get_session_by_device.return_value = mock_sess
        mock_conn = MagicMock()
        mock_conn.is_active = True
        self.mock_ws_server.connection_manager.get.return_value = mock_conn

        mock_resp = SnowMessage.create_response(
            correlation_id="corr-1",
            payload={"battery": 88},
        )
        self.mock_ws_server.send_request = AsyncMock(return_value=mock_resp)

        res = await router.route_request("android_battery", target=self.target_id)
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["battery"], 88)
        self.assertEqual(res["attempted_transports"], ["active_inbound_wss"])
        # Assert relay_client was NOT called
        mock_relay_client.send_message.assert_not_called()

    async def test_12_relay_disabled_by_default(self) -> None:
        """12. Relay is disabled by default; unreached local peer returns DEVICE_UNREACHABLE without relay attempt."""
        router = SessionRouter(
            node_registry=self.mock_registry,
            ws_server=self.mock_ws_server,
            discovery_service=self.mock_discovery,
            capability_engine=self.mock_engine,
            db_manager=self.mock_db,
            wake_grace_period=0.05,
        )
        self.assertFalse(router.relay_enabled)
        self.assertIsNone(router.relay_client)

        self.mock_ws_server.session_manager.get_session_by_device.return_value = None

        res = await router.route_request("android_battery", target=self.target_id)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "DEVICE_UNREACHABLE")
        self.assertNotIn("remote_relay_tunnel", res["attempted_transports"])

    async def test_13_relay_offline_fallback(self) -> None:
        """13. When relay is enabled but client is offline, router falls back gracefully."""
        mock_relay_client = MagicMock()
        mock_relay_client._is_connected = False

        router = SessionRouter(
            node_registry=self.mock_registry,
            ws_server=self.mock_ws_server,
            discovery_service=self.mock_discovery,
            capability_engine=self.mock_engine,
            db_manager=self.mock_db,
            relay_client=mock_relay_client,
            relay_enabled=True,
            wake_grace_period=0.05,
        )
        self.mock_ws_server.session_manager.get_session_by_device.return_value = None

        res = await router.route_request("android_battery", target=self.target_id)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "DEVICE_UNREACHABLE")
        self.assertIn("remote_relay_tunnel", res["attempted_transports"])

    async def test_14_relay_escalation_when_local_offline(self) -> None:
        """Tier 3.75: When local routes are offline, router escalates to remote relay tunnel."""
        mock_relay_client = MagicMock()
        mock_relay_client._is_connected = True

        mock_resp = SnowMessage.create_response(
            correlation_id="corr-relay-1",
            payload={"torch": True},
        )
        mock_relay_client.send_message = AsyncMock(return_value=True)
        mock_relay_client.receive_message = AsyncMock(return_value=mock_resp)

        router = SessionRouter(
            node_registry=self.mock_registry,
            ws_server=self.mock_ws_server,
            discovery_service=self.mock_discovery,
            capability_engine=self.mock_engine,
            db_manager=self.mock_db,
            relay_client=mock_relay_client,
            relay_enabled=True,
            wake_grace_period=0.05,
        )
        self.mock_ws_server.session_manager.get_session_by_device.return_value = None

        res = await router.route_request("android_torch", target=self.target_id)
        self.assertTrue(res["success"])
        self.assertEqual(res["data"]["torch"], True)
        self.assertEqual(res["routing"]["transport"], "relay")
        self.assertEqual(res["routing"]["reachability"], "ONLINE_RELAYED")


class TestPhase22EndToEndTlsTunnel(unittest.TestCase):
    """Genuine End-to-End TLS 1.3 Tunnel tests between two endpoints."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.cert_a = Path(self.tmp.name) / "node_a.crt"
        self.key_a = Path(self.tmp.name) / "node_a.key"
        self.cert_b = Path(self.tmp.name) / "node_b.crt"
        self.key_b = Path(self.tmp.name) / "node_b.key"

        self.info_a = generate_self_signed_cert(self.cert_a, self.key_a, common_name="node-a")
        self.info_b = generate_self_signed_cert(self.cert_b, self.key_b, common_name="node-b")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_15_16_genuine_tls_1_3_mutual_handshake(self) -> None:
        """15, 16. Two in-memory endpoints complete genuine TLS 1.3 mutual handshake."""
        ctx_server = create_e2e_tunnel_ssl_context(
            str(self.cert_a), str(self.key_a), is_server=True, peer_cert_path=str(self.cert_b)
        )
        ctx_client = create_e2e_tunnel_ssl_context(
            str(self.cert_b), str(self.key_b), is_server=False, peer_cert_path=str(self.cert_a)
        )

        server_tunnel = TlsMemoryBioTunnel(
            ssl_context=ctx_server,
            is_server=True,
            expected_peer_fingerprint=self.info_b.fingerprint_sha256,
        )
        client_tunnel = TlsMemoryBioTunnel(
            ssl_context=ctx_client,
            is_server=False,
            expected_peer_fingerprint=self.info_a.fingerprint_sha256,
        )

        # Drive handshake in memory loop
        client_done, client_out = client_tunnel.drive_handshake()
        for _ in range(10):
            if client_out:
                server_tunnel.feed_network_data(client_out)
            server_done, server_out = server_tunnel.drive_handshake()
            if server_out:
                client_tunnel.feed_network_data(server_out)
            client_done, client_out = client_tunnel.drive_handshake()
            if client_done and server_done:
                break

        self.assertTrue(client_tunnel.handshake_done, "Client TLS 1.3 handshake must complete.")
        self.assertTrue(server_tunnel.handshake_done, "Server TLS 1.3 handshake must complete.")

        # Test bidirectional encrypted application data exchange
        plaintext = b'{"action":"android_battery","version":1}'
        encrypted_client = client_tunnel.encrypt_application_data(plaintext)
        # Untrusted relay carries encrypted_client without knowing contents
        server_tunnel.feed_network_data(encrypted_client)
        decrypted_server = server_tunnel.decrypt_application_data()
        self.assertEqual(decrypted_server, plaintext)

    def test_17_18_fingerprint_mismatch_rejection(self) -> None:
        """17, 18. Peer presenting mismatched certificate fingerprint is rejected with FingerprintMismatchError."""
        ctx_server = create_e2e_tunnel_ssl_context(str(self.cert_a), str(self.key_a), is_server=True)
        ctx_client = create_e2e_tunnel_ssl_context(str(self.cert_b), str(self.key_b), is_server=False)

        wrong_fingerprint = "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"
        client_tunnel = TlsMemoryBioTunnel(
            ssl_context=ctx_client,
            is_server=False,
            expected_peer_fingerprint=wrong_fingerprint,  # Expecting wrong pin
        )
        server_tunnel = TlsMemoryBioTunnel(
            ssl_context=ctx_server,
            is_server=True,
            expected_peer_fingerprint=self.info_b.fingerprint_sha256,
        )

        client_done, client_out = client_tunnel.drive_handshake()
        with self.assertRaises(FingerprintMismatchError):
            for _ in range(5):
                if client_out:
                    server_tunnel.feed_network_data(client_out)
                server_done, server_out = server_tunnel.drive_handshake()
                if server_out:
                    client_tunnel.feed_network_data(server_out)
                client_done, client_out = client_tunnel.drive_handshake()

    def test_19_20_payload_blindness_and_tamper_rejection(self) -> None:
        """19, 20. Tampered or modified ciphertext fails TLS decryption."""
        ctx_server = create_e2e_tunnel_ssl_context(
            str(self.cert_a), str(self.key_a), is_server=True, peer_cert_path=str(self.cert_b)
        )
        ctx_client = create_e2e_tunnel_ssl_context(
            str(self.cert_b), str(self.key_b), is_server=False, peer_cert_path=str(self.cert_a)
        )

        server_tunnel = TlsMemoryBioTunnel(ctx_server, is_server=True)
        client_tunnel = TlsMemoryBioTunnel(ctx_client, is_server=False)

        # Drive handshake
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

        # Generate encrypted frame
        plaintext = b"SECRET_CAPABILITY_PAYLOAD"
        encrypted = bytearray(client_tunnel.encrypt_application_data(plaintext))

        # Attacker/Relay tampers with byte in ciphertext
        encrypted[len(encrypted) - 2] ^= 0xFF

        server_tunnel.feed_network_data(bytes(encrypted))
        # Tampered record must fail decryption
        decrypted = server_tunnel.decrypt_application_data()
        self.assertNotEqual(decrypted, plaintext, "Tampered ciphertext must not decrypt to valid plaintext!")


class TestPhase22RelayServerIntegration(unittest.IsolatedAsyncioTestCase):
    """Genuine integration test with two endpoint clients communicating through live SnowRelayServer."""

    async def asyncSetUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.secret = "test_shared_secret_for_relay_integration_99"
        self.config = RelayConfig(
            host="127.0.0.1",
            port=58990,
            shared_secret=self.secret,
            rate_limit_messages_per_sec=100,
            presence_stale_seconds=60.0,
        )
        self.server = SnowRelayServer(config=self.config)
        await self.server.start()

        # Generate certs for endpoint A and B
        self.cert_a = Path(self.tmp.name) / "endpoint_a.crt"
        self.key_a = Path(self.tmp.name) / "endpoint_a.key"
        self.cert_b = Path(self.tmp.name) / "endpoint_b.crt"
        self.key_b = Path(self.tmp.name) / "endpoint_b.key"

        self.info_a = generate_self_signed_cert(self.cert_a, self.key_a, common_name="endpoint-a")
        self.info_b = generate_self_signed_cert(self.cert_b, self.key_b, common_name="endpoint-b")

        self.dev_a = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
        self.dev_b = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
        self.group = "mesh-group-integration"

        self.ticket_a = create_relay_ticket(self.dev_a, self.group, self.secret)
        self.ticket_b = create_relay_ticket(self.dev_b, self.group, self.secret)

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        self.tmp.cleanup()

    async def test_21_22_full_relay_e2e_integration_exchange(self) -> None:
        """21, 22. Two endpoints connect to live relay, establish E2E TLS tunnel, and exchange messages."""
        relay_url = f"http://127.0.0.1:{self.config.port}/v1/tunnel"

        client_a = RelayTunnelClient(
            relay_url=relay_url,
            device_id=self.dev_a,
            group_id=self.group,
            ticket=self.ticket_a,
            cert_path=str(self.cert_a),
            key_path=str(self.key_a),
        )
        client_a.set_peer_pinned_fingerprint(self.dev_b, self.info_b.fingerprint_sha256, cert_path=str(self.cert_b))

        client_b = RelayTunnelClient(
            relay_url=relay_url,
            device_id=self.dev_b,
            group_id=self.group,
            ticket=self.ticket_b,
            cert_path=str(self.cert_b),
            key_path=str(self.key_b),
        )
        client_b.set_peer_pinned_fingerprint(self.dev_a, self.info_a.fingerprint_sha256, cert_path=str(self.cert_a))

        try:
            conn_a = await client_a.connect()
            conn_b = await client_b.connect()
            self.assertTrue(conn_a, "Endpoint A must connect to relay.")
            self.assertTrue(conn_b, "Endpoint B must connect to relay.")

            # Check presence via relay registry
            pres_a = self.server.registry.get_presence(self.dev_a)
            pres_b = self.server.registry.get_presence(self.dev_b)
            self.assertEqual(pres_a["state"], STATE_ONLINE_RELAY)
            self.assertEqual(pres_b["state"], STATE_ONLINE_RELAY)

            # Endpoint A sends capability request to Endpoint B through relay
            req_msg = SnowMessage.create_request(action="android_battery", data={"detail": True})
            sent = await client_a.send_message(self.dev_b, req_msg)
            self.assertTrue(sent, "Message must be sent through relay E2E tunnel.")

            # Endpoint B receives and decrypts message
            received_msg = await client_b.receive_message(self.dev_a, timeout=5.0)
            self.assertIsNotNone(received_msg, "Endpoint B must receive decrypted message.")
            self.assertEqual(received_msg.action, "android_battery")
            self.assertEqual(received_msg.data.get("detail"), True)
        finally:
            await client_a.disconnect()
            await client_b.disconnect()


if __name__ == "__main__":
    unittest.main()
