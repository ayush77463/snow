"""Unit tests for SNOW V5 Stage 5A: Permanent AI MCP, Non-Destructive Pause, and Unified SNOW ID."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from snow.mcp.remote_gateway import RemoteMcpGateway
from snow.mcp.tunnel import (
    ALLOWED_TUNNEL_PORT,
    TunnelManager,
    load_tunnel_config,
    redact_tunnel_config,
    save_tunnel_config,
)
from snow.network.discovery import DiscoveryBeacon
from snow.security.identity import (
    DeviceIdentity,
    generate_snow_id,
    is_valid_snow_id,
    load_or_create_device_identity,
)
from snow.security.pairing import (
    create_qr_pairing_payload,
    validate_qr_pairing_payload,
)


class TestSnowIdAndIdentity(unittest.TestCase):
    """Verify Canonical SNOW ID format, uniqueness, persistence, and protocol envelope integration."""

    def test_snow_id_validation(self) -> None:
        self.assertTrue(is_valid_snow_id("SNW-A1B2-C3D4"))
        self.assertTrue(is_valid_snow_id("SNW-0000-9999"))
        self.assertTrue(is_valid_snow_id("snw-a1b2-c3d4"))  # Case-insensitive
        self.assertFalse(is_valid_snow_id("SNOW-A1B2-C3D4"))  # Wrong prefix
        self.assertFalse(is_valid_snow_id("SNW-A1B2C3D4"))    # Missing hyphen
        self.assertFalse(is_valid_snow_id("SNW-A1B-C3D4"))     # Too short
        self.assertFalse(is_valid_snow_id(""))
        self.assertFalse(is_valid_snow_id(None))

    def test_snow_id_generation(self) -> None:
        # Cryptographic random generation
        sid1 = generate_snow_id()
        sid2 = generate_snow_id()
        self.assertTrue(is_valid_snow_id(sid1))
        self.assertTrue(is_valid_snow_id(sid2))
        self.assertNotEqual(sid1, sid2)

        # Deterministic generation from seed
        seed_id1 = generate_snow_id("device-uuid-12345")
        seed_id2 = generate_snow_id("device-uuid-12345")
        self.assertEqual(seed_id1, seed_id2)
        self.assertTrue(is_valid_snow_id(seed_id1))

    def test_device_identity_auto_snow_id(self) -> None:
        # Constructing DeviceIdentity without snow_id auto-assigns valid deterministic SNOW ID
        dev_id = str(uuid.uuid4())
        ident = DeviceIdentity(device_id=dev_id, device_name="Test Host", created_at="2026-01-01T00:00:00Z")
        self.assertTrue(is_valid_snow_id(ident.snow_id))
        self.assertEqual(ident.to_dict()["snow_id"], ident.snow_id)

    def test_identity_persistence_and_reload(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            ident1 = load_or_create_device_identity(data_dir=tmp_dir)
            self.assertTrue(is_valid_snow_id(ident1.snow_id))

            ident2 = load_or_create_device_identity(data_dir=tmp_dir)
            self.assertEqual(ident1.device_id, ident2.device_id)
            self.assertEqual(ident1.snow_id, ident2.snow_id)

    def test_qr_pairing_payload_with_snow_id(self) -> None:
        dev_id = str(uuid.uuid4())
        sid = "SNW-FA12-34BC"
        payload = create_qr_pairing_payload(
            node_id=dev_id,
            candidate_ips=["192.168.1.50"],
            port=8765,
            cert_fingerprint="A" * 64,
            pin="123456",
            snow_id=sid,
        )
        self.assertEqual(payload["snow_id"], sid)

        validated = validate_qr_pairing_payload(payload)
        self.assertEqual(validated["snow_id"], sid)

    def test_discovery_beacon_with_snow_id(self) -> None:
        sid = "SNW-99AA-BB88"
        beacon = DiscoveryBeacon(
            device_id=str(uuid.uuid4()),
            device_name="Test Desktop",
            device_type="windows",
            port=8765,
            transfer_port=8766,
            cert_fingerprint="F" * 64,
            timestamp=1700000000.0,
            snow_id=sid,
        )
        raw = beacon.to_bytes()
        self.assertIn(b"snow_id", raw)

        # Ensure from_bytes decodes snow_id
        with patch("time.time", return_value=1700000000.0):
            parsed = DiscoveryBeacon.from_bytes(raw)
            self.assertIsNotNone(parsed)
            self.assertEqual(parsed.snow_id, sid)


class TestPermanentTunnelConfig(unittest.TestCase):
    """Verify ~/.snow/tunnel_config.json persistence, named tunnel support, and secret redaction."""

    def test_save_and_load_tunnel_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg_path = Path(tmp_dir) / "tunnel_config.json"
            cfg_data = {
                "provider": "cloudflared",
                "cloudflare_token": "cf_sec_token_1234567890abcdef",
                "public_url": "https://mcp.mycustomdomain.com",
            }
            save_tunnel_config(cfg_data, config_path=cfg_path)
            loaded = load_tunnel_config(config_path=cfg_path)
            self.assertEqual(loaded, cfg_data)

    def test_redact_tunnel_config(self) -> None:
        cfg = {
            "provider": "cloudflared",
            "cloudflare_token": "cf_sec_token_1234567890abcdef",
            "public_url": "https://mcp.example.com",
            "nested": {
                "shared_secret": "supersecretpassword",
                "normal_field": 42,
            },
        }
        redacted = redact_tunnel_config(cfg)
        self.assertNotIn("cf_sec_token_1234567890abcdef", json.dumps(redacted))
        self.assertNotIn("supersecretpassword", json.dumps(redacted))
        self.assertTrue(redacted["cloudflare_token"].startswith("cf_s***"))
        self.assertEqual(redacted["nested"]["shared_secret"], "supe***rd")
        self.assertEqual(redacted["public_url"], "https://mcp.example.com")


class TestNonDestructivePauseGateway(AioHTTPTestCase):
    """Verify non-destructive pause HTTP 503 response on /mcp endpoints."""

    async def get_application(self) -> web.Application:
        mock_bridge = MagicMock()
        mock_bridge.is_paused = False
        self.gateway = RemoteMcpGateway(
            host="127.0.0.1",
            port=8771,
            bridge=mock_bridge,
        )
        return self.gateway.app

    @unittest_run_loop
    async def test_mcp_pause_lifecycle(self) -> None:
        # Initially not paused: /mcp returns 401 (since no auth provided) rather than 503
        resp_unauthed = await self.client.post("/mcp", json={"jsonrpc": "2.0", "method": "ping", "id": 1})
        self.assertEqual(resp_unauthed.status, 401)

        # Set gateway to paused state
        self.gateway.set_paused(True)
        self.assertTrue(self.gateway.is_paused)

        # When paused, /mcp immediately returns HTTP 503 with exact text
        resp_paused = await self.client.post("/mcp", json={"jsonrpc": "2.0", "method": "ping", "id": 1})
        self.assertEqual(resp_paused.status, 503)
        body = await resp_paused.text()
        self.assertEqual(body.strip(), "SNOW is paused by owner")

        # GET SSE to /mcp also returns HTTP 503
        resp_sse_paused = await self.client.get("/mcp")
        self.assertEqual(resp_sse_paused.status, 503)
        sse_body = await resp_sse_paused.text()
        self.assertEqual(sse_body.strip(), "SNOW is paused by owner")

        # Resume gateway
        self.gateway.set_paused(False)
        self.assertFalse(self.gateway.is_paused)

        # Request to /mcp resumes normal processing without 503
        resp_resumed = await self.client.post("/mcp", json={"jsonrpc": "2.0", "method": "ping", "id": 1})
        self.assertEqual(resp_resumed.status, 401)  # Auth check reached, not 503


class TestWindowsSubprocessNoConsole(unittest.TestCase):
    """Verify that all subprocess calls in usb.py and helpers enforce CREATE_NO_WINDOW and SW_HIDE."""

    def test_subprocess_helper_kwargs(self) -> None:
        import sys
        from snow.core.subprocess_util import get_no_window_subprocess_kwargs

        kwargs = get_no_window_subprocess_kwargs()
        if sys.platform == "win32":
            self.assertIn("creationflags", kwargs)
            self.assertTrue(kwargs["creationflags"] & 0x08000000)
            self.assertIn("startupinfo", kwargs)
            si = kwargs["startupinfo"]
            self.assertTrue(si.dwFlags & 1)  # STARTF_USESHOWWINDOW
            self.assertEqual(si.wShowWindow, 0)  # SW_HIDE
        else:
            self.assertEqual(kwargs, {})

    def test_usb_subprocess_calls_use_no_window_flags(self) -> None:
        import sys
        from unittest.mock import MagicMock, patch
        from snow.core import usb
        from snow.core.subprocess_util import get_no_window_subprocess_kwargs

        expected_kwargs = get_no_window_subprocess_kwargs()

        mock_completed = MagicMock()
        mock_completed.returncode = 0
        mock_completed.stdout = "List of devices attached\nserial123 device model:TestPhone\n"
        mock_completed.stderr = ""

        with patch("subprocess.run", return_value=mock_completed) as mock_run:
            # 1. get_connected_adb_devices
            devs = usb.get_connected_adb_devices(adb_bin=Path("fake_adb"))
            self.assertTrue(len(devs) > 0)
            self.assertEqual(mock_run.call_count, 1)
            call_kwargs = mock_run.call_args.kwargs
            if sys.platform == "win32":
                self.assertIn("creationflags", call_kwargs)
                self.assertTrue(call_kwargs["creationflags"] & 0x08000000)
                self.assertIn("startupinfo", call_kwargs)

        mock_reverse_list = MagicMock()
        mock_reverse_list.returncode = 0
        mock_reverse_list.stdout = "tcp:8765 tcp:8765\ntcp:8766 tcp:8766\n"
        mock_reverse_list.stderr = ""

        with patch("subprocess.run", return_value=mock_reverse_list) as mock_run:
            with patch("snow.core.usb.get_connected_adb_devices", return_value=[{"serial": "serial123", "status": "device", "model": "Test"}]):
                # 2. get_usb_status
                status = usb.get_usb_status(adb_bin=Path("fake_adb"), serial="serial123")
                self.assertTrue(status["reverse_active"])
                self.assertEqual(mock_run.call_count, 1)
                call_kwargs = mock_run.call_args.kwargs
                if sys.platform == "win32":
                    self.assertIn("creationflags", call_kwargs)
                    self.assertIn("startupinfo", call_kwargs)

        with patch("subprocess.run", return_value=mock_completed) as mock_run:
            with patch("snow.core.usb.get_connected_adb_devices", return_value=[{"serial": "serial123", "status": "device", "model": "Test"}]):
                # 3 & 4. setup_usb_reverse (makes two subprocess.run calls)
                ok, msg = usb.setup_usb_reverse(serial="serial123", adb_bin=Path("fake_adb"))
                self.assertTrue(ok)
                self.assertEqual(mock_run.call_count, 2)
                for call in mock_run.call_args_list:
                    ck = call.kwargs
                    if sys.platform == "win32":
                        self.assertIn("creationflags", ck)
                        self.assertIn("startupinfo", ck)

        with patch("subprocess.run", return_value=mock_completed) as mock_run:
            with patch("snow.core.usb.get_connected_adb_devices", return_value=[{"serial": "serial123", "status": "device", "model": "Test"}]):
                # 5 & 6. remove_usb_reverse (makes two subprocess.run calls)
                ok, msg = usb.remove_usb_reverse(serial="serial123", adb_bin=Path("fake_adb"))
                self.assertTrue(ok)
                self.assertEqual(mock_run.call_count, 2)
                for call in mock_run.call_args_list:
                    ck = call.kwargs
                    if sys.platform == "win32":
                        self.assertIn("creationflags", ck)
                        self.assertIn("startupinfo", ck)


class TestNamedTunnelValidation(unittest.IsolatedAsyncioTestCase):
    """Verify named tunnel credential separation and public URL validation."""

    async def test_named_tunnel_requires_https_url(self) -> None:
        from snow.mcp.tunnel import _TunnelInstance

        inst = _TunnelInstance(target_port=8771, purpose="mcp")
        # Named tunnel without public_url returns INVALID_URL
        res = await inst.start(
            provider="cloudflared",
            token="cf_test_token_12345",
            custom_url="",
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "INVALID_URL")

        # Named tunnel with fabricated .snow.internal returns INVALID_URL
        res_internal = await inst.start(
            provider="cloudflared",
            token="cf_test_token_12345",
            custom_url="https://mcp-tunnel.snow.internal",
        )
        self.assertFalse(res_internal["success"])
        self.assertEqual(res_internal["status"], "INVALID_URL")

    async def test_credential_separation_mcp_and_relay(self) -> None:
        from snow.mcp.tunnel import _TunnelInstance, save_tunnel_config
        with tempfile.TemporaryDirectory() as tmp_dir:
            cfg_path = Path(tmp_dir) / "tunnel_config.json"
            save_tunnel_config({
                "mcp_cloudflare_token": "cf_mcp_token_abc",
                "relay_cloudflare_token": "cf_relay_token_xyz",
                "mcp_public_url": "https://mcp.custom.org",
                "relay_public_url": "https://relay.custom.org",
            }, config_path=cfg_path)

            with patch("snow.mcp.tunnel.load_tunnel_config", return_value={
                "mcp_cloudflare_token": "cf_mcp_token_abc",
                "relay_cloudflare_token": "cf_relay_token_xyz",
                "mcp_public_url": "https://mcp.custom.org",
                "relay_public_url": "https://relay.custom.org",
            }):
                mcp_inst = _TunnelInstance(target_port=8771, purpose="mcp")
                relay_inst = _TunnelInstance(target_port=8770, purpose="relay")

                # Verify relay instance does not inherit MCP token
                with patch("snow.mcp.tunnel.load_tunnel_config", return_value={"mcp_cloudflare_token": "cf_mcp_token_only"}):
                    # Relay instance has no relay token and should not use mcp_cloudflare_token
                    res_relay = await relay_inst.start(provider="cloudflared")
                    # Should attempt quick tunnel (or fail binary) rather than use mcp token as named tunnel
                    self.assertNotEqual(res_relay.get("mode"), "named")


class TestWebStaticAssetsAndTunnelApi(AioHTTPTestCase):
    """Verify public access to static favicon/logo and secured /api/mcp/tunnel/config."""

    async def get_application(self) -> web.Application:
        from snow.web.server import SnowWebServer
        self.web_server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)
        return self.web_server._build_app()

    @unittest_run_loop
    async def test_public_static_assets_unauthenticated(self) -> None:
        # GET /favicon.ico should return 200 without authentication
        resp_fav = await self.client.get("/favicon.ico")
        self.assertEqual(resp_fav.status, 200)

        # GET /snow_logo.png should return 200 without authentication
        resp_logo = await self.client.get("/snow_logo.png")
        self.assertEqual(resp_logo.status, 200)

        # Protected API should reject unauthenticated request with 401
        resp_api = await self.client.get("/api/status")
        self.assertEqual(resp_api.status, 401)

    @unittest_run_loop
    async def test_tunnel_config_api_security(self) -> None:
        # 1. Unauthenticated GET /api/mcp/tunnel/config returns 401
        resp_get_unauth = await self.client.get("/api/mcp/tunnel/config")
        self.assertEqual(resp_get_unauth.status, 401)

        # 2. Authenticate session
        session_token = "test_valid_session_token_12345"
        csrf_token = "test_csrf_token_abcdef"
        self.web_server._sessions[session_token] = {
            "token": session_token,
            "csrf_token": csrf_token,
            "created_at": time.time(),
            "last_active": time.time(),
        }
        self.client.session.cookie_jar.update_cookies({"snow_session": session_token})

        # 3. Authenticated GET returns 200 and redacted config
        with patch("snow.mcp.tunnel.load_tunnel_config", return_value={"cloudflare_token": "cf_secret_token_12345678"}):
            resp_get_auth = await self.client.get("/api/mcp/tunnel/config")
            self.assertEqual(resp_get_auth.status, 200)
            data = await resp_get_auth.json()
            self.assertTrue(data["success"])
            self.assertIn("cf_s***", data["config"]["cloudflare_token"])

        # 4. POST without CSRF header returns 403
        resp_post_no_csrf = await self.client.post("/api/mcp/tunnel/config", json={"provider": "cloudflared"})
        self.assertEqual(resp_post_no_csrf.status, 403)

        # 5. POST with invalid provider returns 400
        headers = {"X-CSRF-Token": csrf_token}
        resp_invalid_prov = await self.client.post(
            "/api/mcp/tunnel/config",
            json={"provider": "unsupported_provider"},
            headers=headers,
        )
        self.assertEqual(resp_invalid_prov.status, 400)

        # 6. POST with invalid URL returns 400
        resp_invalid_url = await self.client.post(
            "/api/mcp/tunnel/config",
            json={"public_url": "ftp://invalid-url.com"},
            headers=headers,
        )
        self.assertEqual(resp_invalid_url.status, 400)

        # 7. Valid POST persists config and returns 200 with redacted config
        with patch("snow.mcp.tunnel.save_tunnel_config") as mock_save:
            with patch("snow.mcp.tunnel.load_tunnel_config", return_value={}):
                resp_valid = await self.client.post(
                    "/api/mcp/tunnel/config",
                    json={
                        "provider": "cloudflared",
                        "mcp_cloudflare_token": "cf_sec_token_99999999",
                        "public_url": "https://custom.snow.example.com",
                    },
                    headers=headers,
                )
                self.assertEqual(resp_valid.status, 200)
                mock_save.assert_called_once()
                res_body = await resp_valid.json()
                self.assertTrue(res_body["success"])
                self.assertIn("cf_s***", res_body["config"]["mcp_cloudflare_token"])

