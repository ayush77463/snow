"""Unit 1.3 Regression Tests: Fail-Closed Relay Secret Handling."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp.test_utils import make_mocked_request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from snow.relay.auth import create_relay_ticket, verify_relay_ticket
from snow.web.server import SnowWebServer


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestMilestone1Unit3RelaySecretHandling(unittest.TestCase):
    """Verify static fallback secret removal, Ed25519 QR continuity, and fail-closed ticket signing."""

    def test_01_source_scan_removes_static_fallback_secret(self) -> None:
        src_root = REPO_ROOT / "src"
        hits: list[str] = []
        for py_file in src_root.rglob("*.py"):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            if "snow_relay_default_key" in content:
                hits.append(str(py_file.relative_to(REPO_ROOT)))
        self.assertEqual(hits, [], f"Static fallback secret still present in: {hits}")

    def test_02_03_qr_generation_succeeds_without_secret_and_omits_legacy_ticket(self) -> None:
        server = SnowWebServer(host="127.0.0.1", port=0, auto_open_browser=False)
        server.bridge = MagicMock()
        server.bridge.call = AsyncMock(return_value={
            "success": True,
            "data": {
                "v": 1,
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "ips": ["192.168.1.50"],
                "port": 8765,
                "fp": "AA" * 32,
                "pin": "654321",
                "handshake_token": "htok_u13_valid_token_0123456",
            },
        })
        fake_tunnel_status = {
            "active": True,
            "public_url": "https://snow-u13-relay.trycloudflare.com",
            "relay_endpoint": "wss://snow-u13-relay.trycloudflare.com/v1/tunnel",
        }
        with patch.dict("os.environ", {"SNOW_RELAY_SECRET": ""}, clear=False), \
             patch.object(server.tunnel_manager, "get_status", return_value=fake_tunnel_status):
            req = make_mocked_request("GET", "/api/pair/qr")
            resp = asyncio.run(server.handle_api_pair_qr(req))
            self.assertEqual(resp.status, 200)
            body = json.loads(resp.text)
            self.assertTrue(body["success"])
            self.assertFalse(body["legacy_relay_available"])
            qr = body["data"]
            self.assertNotIn("relay_ticket", qr)
            self.assertNotIn("group_id", qr)
            self.assertTrue(str(qr.get("hub_url", "")).startswith("https://"))
            self.assertTrue(str(qr.get("network_id", "")).startswith("SNW-NET-"))

            # Explicit legacy ticket request without secret fails closed
            req_explicit = make_mocked_request("POST", "/api/pair/qr")
            req_explicit.json = AsyncMock(return_value={"require_relay_ticket": True})
            resp_explicit = asyncio.run(server.handle_api_pair_qr(req_explicit))
            self.assertEqual(resp_explicit.status, 400)
            err_body = json.loads(resp_explicit.text)
            self.assertFalse(err_body["success"])
            self.assertEqual(err_body["status"], "RELAY_SECRET_MISSING")
            self.assertNotIn("relay_ticket", err_body)

    def test_04_legacy_ticket_signing_and_verify_fail_closed_on_empty_secret(self) -> None:
        for empty_secret in ("", "   ", None):  # type: ignore[arg-type]
            with self.assertRaises(ValueError):
                create_relay_ticket("dev-1", "grp-1", empty_secret)

        valid_ticket = create_relay_ticket("dev-1", "grp-1", "strong-explicit-secret")
        for empty_secret in ("", "   "):
            ok, dev_id, grp_id, err = verify_relay_ticket(valid_ticket, empty_secret)
            self.assertFalse(ok)
            self.assertIsNone(dev_id)
            self.assertIsNone(grp_id)
            self.assertIsNotNone(err)

    def test_05_explicit_valid_secret_retains_legacy_ticket_functionality(self) -> None:
        server = SnowWebServer(host="127.0.0.1", port=0, auto_open_browser=False)
        server.bridge = MagicMock()
        server.bridge.call = AsyncMock(return_value={
            "success": True,
            "data": {"v": 1, "id": "550e8400-e29b-41d4-a716-446655440000", "ips": ["192.168.1.50"], "port": 8765, "fp": "BB" * 32, "pin": "112233"},
        })
        fake_tunnel_status = {
            "active": True,
            "public_url": "https://snow-u13-relay.trycloudflare.com",
            "relay_endpoint": "wss://snow-u13-relay.trycloudflare.com/v1/tunnel",
        }
        secret = "unit13-explicit-strong-secret-key"
        with patch.dict("os.environ", {"SNOW_RELAY_SECRET": secret, "SNOW_RELAY_GROUP_ID": "u13_grp"}, clear=False), \
             patch.object(server.tunnel_manager, "get_status", return_value=fake_tunnel_status):
            req = make_mocked_request("GET", "/api/pair/qr")
            resp = asyncio.run(server.handle_api_pair_qr(req))
        self.assertEqual(resp.status, 200)
        body = json.loads(resp.text)
        self.assertTrue(body["success"])
        self.assertTrue(body["legacy_relay_available"])
        qr = body["data"]
        self.assertEqual(qr["group_id"], "u13_grp")
        ok, dev_id, grp_id, err = verify_relay_ticket(qr["relay_ticket"], secret)
        self.assertTrue(ok, msg=err)
        self.assertEqual(dev_id, "mobile-pairing-client")
        self.assertEqual(grp_id, "u13_grp")

    def test_06_deployment_configs_have_no_insecure_fallback_secret(self) -> None:
        compose_txt = (REPO_ROOT / "deploy" / "docker-compose.yml").read_text("utf-8")
        env_example_txt = (REPO_ROOT / "deploy" / ".env.example").read_text("utf-8")
        render_txt = (REPO_ROOT / "render.yaml").read_text("utf-8")

        for txt in (compose_txt, env_example_txt, render_txt):
            self.assertNotIn("snow_relay_default_key", txt)
        self.assertIn("SNOW_RELAY_SECRET=${SNOW_RELAY_SECRET:-}", compose_txt)
        self.assertIn("SNOW_RELAY_SECRET=replace_with_strong_random_secret_in_production", env_example_txt)
        self.assertIn("generateValue: true", render_txt)


if __name__ == "__main__":
    unittest.main()
