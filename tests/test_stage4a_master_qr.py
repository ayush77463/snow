"""Unit tests for Stage 4A Track A3: Master QR pairing and cryptographic relay tickets."""

from __future__ import annotations

import asyncio
import json
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp.test_utils import make_mocked_request

from snow.relay.auth import create_relay_ticket, verify_relay_ticket
from snow.security.pairing import (
    create_qr_pairing_payload,
    validate_qr_pairing_payload,
)
from snow.web.server import SnowWebServer


class TestMasterQrPairing(unittest.TestCase):
    """Verify Master QR pairing payload extension, backward compatibility, and relay security."""

    def setUp(self) -> None:
        self.node_id = "desktop-node-stage4a"
        self.candidate_ips = ["192.168.1.100", "10.0.0.5"]
        self.port = 8765
        self.cert_fp = "A1" * 32  # 64-character SHA-256 hex string
        self.pin = "123456"

    def test_backward_compatibility_local_only_payload(self) -> None:
        """Standard Wi-Fi / USB local pairing payloads without relay fields work identically."""
        payload = create_qr_pairing_payload(
            node_id=self.node_id,
            candidate_ips=self.candidate_ips,
            port=self.port,
            cert_fingerprint=self.cert_fp,
            pin=self.pin,
            trust_tier="owner",
        )
        self.assertEqual(payload["v"], 1)
        self.assertEqual(payload["id"], self.node_id)
        self.assertEqual(payload["port"], 8765)
        self.assertEqual(payload["fp"], self.cert_fp)
        self.assertEqual(payload["pin"], "123456")
        self.assertNotIn("relay_url", payload)
        self.assertNotIn("relay_ticket", payload)
        self.assertNotIn("group_id", payload)

        # Deserialization / validation
        validated = validate_qr_pairing_payload(payload)
        self.assertEqual(validated["id"], self.node_id)
        self.assertNotIn("relay_url", validated)
        self.assertNotIn("relay_ticket", validated)

    def test_master_qr_serialization_and_roundtrip(self) -> None:
        """Master QR containing optional relay_url, relay_ticket, and group_id roundtrips cleanly."""
        relay_url = "wss://relay.snow.example.com:8770/v1/tunnel"
        ticket = create_relay_ticket(
            device_id="client-phone-1",
            group_id="group-alpha-99",
            secret="master-relay-secret-test-key",
            ttl_seconds=300,
        )
        group_id = "group-alpha-99"

        payload = create_qr_pairing_payload(
            node_id=self.node_id,
            candidate_ips=self.candidate_ips,
            port=self.port,
            cert_fingerprint=self.cert_fp,
            pin=self.pin,
            relay_url=relay_url,
            relay_ticket=ticket,
            group_id=group_id,
        )

        self.assertEqual(payload["relay_url"], relay_url)
        self.assertEqual(payload["relay_ticket"], ticket)
        self.assertEqual(payload["group_id"], group_id)

        # JSON wire round-trip
        wire_json = json.dumps(payload)
        validated = validate_qr_pairing_payload(wire_json)

        self.assertEqual(validated["id"], self.node_id)
        self.assertEqual(validated["relay_url"], relay_url)
        self.assertEqual(validated["relay_ticket"], ticket)
        self.assertEqual(validated["group_id"], group_id)

        # Verify cryptographic relay ticket payload and signature
        valid, dev_id, grp_id, err = verify_relay_ticket(ticket, "master-relay-secret-test-key")
        self.assertTrue(valid)
        self.assertEqual(dev_id, "client-phone-1")
        self.assertEqual(grp_id, "group-alpha-99")
        self.assertIsNone(err)

    def test_master_qr_strict_validation_rejects_malformed_fields(self) -> None:
        """Master QR strictly rejects malicious schemes, spaces, or malformed credentials."""
        # 1. Invalid relay_url scheme (e.g. javascript: or file:)
        with self.assertRaises(ValueError):
            create_qr_pairing_payload(
                node_id=self.node_id,
                candidate_ips=self.candidate_ips,
                port=self.port,
                cert_fingerprint=self.cert_fp,
                pin=self.pin,
                relay_url="javascript:alert(1)",
            )

        # 2. Malformed relay_url with space
        with self.assertRaises(ValueError):
            create_qr_pairing_payload(
                node_id=self.node_id,
                candidate_ips=self.candidate_ips,
                port=self.port,
                cert_fingerprint=self.cert_fp,
                pin=self.pin,
                relay_url="wss://relay.example.com/bad url",
            )

        # 3. Invalid relay_ticket (too short or bad characters)
        with self.assertRaises(ValueError):
            create_qr_pairing_payload(
                node_id=self.node_id,
                candidate_ips=self.candidate_ips,
                port=self.port,
                cert_fingerprint=self.cert_fp,
                pin=self.pin,
                relay_ticket="short",
            )

        # 4. In validate_qr_pairing_payload, untrusted payload with bad relay_url rejected
        bad_payload = {
            "v": 1,
            "id": self.node_id,
            "ips": ["192.168.1.50"],
            "port": 8765,
            "fp": self.cert_fp,
            "pin": "123456",
            "relay_url": "ftp://unsupported.com",
        }
        with self.assertRaises(ValueError):
            validate_qr_pairing_payload(bad_payload)

    def test_expired_relay_ticket_fails_verification(self) -> None:
        """Expired relay tickets are rejected by verification."""
        expired_ticket = create_relay_ticket(
            device_id="dev-1",
            group_id="group-1",
            secret="sec",
            ttl_seconds=-10,  # Expired in past
        )
        valid, dev, grp, err = verify_relay_ticket(expired_ticket, "sec")
        self.assertFalse(valid)
        self.assertIn("expired", str(err).lower())


class TestMasterQrWebEndpoints(unittest.TestCase):
    """Verify SnowWebServer /api/pairing/qr and /api/relay/tunnel/* endpoints."""

    def test_pair_qr_relay_enrichment_active_and_inactive(self) -> None:
        server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)
        server.bridge = MagicMock()
        server.bridge.call = AsyncMock(return_value={"success": True, "data": {"pin": "654321", "id": "pc-node"}})

        # Case 1: Relay tunnel is INACTIVE
        with patch.object(server.tunnel_manager, "get_status", return_value={"active": False}):
            req1 = make_mocked_request("GET", "/api/pair/qr")
            resp1 = asyncio.run(server.handle_api_pair_qr(req1))
            self.assertEqual(resp1.status, 200)
            data1 = json.loads(resp1.text)
            self.assertTrue(data1["success"])
            self.assertIn("data", data1)
            parsed_qr1 = data1["data"]
            self.assertEqual(parsed_qr1["pin"], "654321")
            self.assertNotIn("relay_url", parsed_qr1)
            self.assertNotIn("relay_ticket", parsed_qr1)
            self.assertNotIn("group_id", parsed_qr1)

        # Case 2: Relay tunnel is ACTIVE
        fake_relay_status = {
            "active": True,
            "public_url": "https://snow-relay-stage4a.trycloudflare.com",
            "relay_endpoint": "wss://snow-relay-stage4a.trycloudflare.com/v1/tunnel",
        }
        with patch.object(server.tunnel_manager, "get_status", return_value=fake_relay_status):
            req2 = make_mocked_request("GET", "/api/pair/qr")
            resp2 = asyncio.run(server.handle_api_pair_qr(req2))
            self.assertEqual(resp2.status, 200)
            data2 = json.loads(resp2.text)
            self.assertTrue(data2["success"])
            parsed_qr2 = data2["data"]
            self.assertEqual(parsed_qr2["pin"], "654321")
            self.assertEqual(parsed_qr2["relay_url"], "wss://snow-relay-stage4a.trycloudflare.com/v1/tunnel")
            self.assertIn("relay_ticket", parsed_qr2)
            self.assertEqual(parsed_qr2["group_id"], "default_group")

    def test_relay_tunnel_web_api_routes(self) -> None:
        server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)

        # 1. Status endpoint
        with patch.object(
            server.tunnel_manager,
            "get_status",
            return_value={"active": True, "public_url": "https://xyz.trycloudflare.com", "relay_endpoint": "wss://xyz.trycloudflare.com/v1/tunnel"}
        ):
            req_stat = make_mocked_request("GET", "/api/relay/tunnel/status")
            resp_stat = asyncio.run(server.handle_api_relay_tunnel_status(req_stat))
            self.assertEqual(resp_stat.status, 200)
            data_stat = json.loads(resp_stat.text)
            self.assertTrue(data_stat["active"])
            self.assertEqual(data_stat["relay_endpoint"], "wss://xyz.trycloudflare.com/v1/tunnel")

        # 2. Start endpoint
        with patch.object(
            server.tunnel_manager,
            "start_relay_tunnel",
            new_callable=AsyncMock,
            return_value={"success": True, "active": True, "public_url": "https://abc.trycloudflare.com", "relay_endpoint": "wss://abc.trycloudflare.com/v1/tunnel"}
        ):
            req_start = make_mocked_request("POST", "/api/relay/tunnel/start")
            resp_start = asyncio.run(server.handle_api_relay_tunnel_start(req_start))
            self.assertEqual(resp_start.status, 200)
            data_start = json.loads(resp_start.text)
            self.assertTrue(data_start["active"])

        # 3. Stop endpoint
        with patch.object(
            server.tunnel_manager,
            "stop_tunnel",
            new_callable=AsyncMock,
            return_value={"success": True, "active": False}
        ):
            req_stop = make_mocked_request("POST", "/api/relay/tunnel/stop")
            resp_stop = asyncio.run(server.handle_api_relay_tunnel_stop(req_stop))
            self.assertEqual(resp_stop.status, 200)
            data_stop = json.loads(resp_stop.text)
            self.assertFalse(data_stop["active"])


if __name__ == "__main__":
    unittest.main()
