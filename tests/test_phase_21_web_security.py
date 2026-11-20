"""Security and protocol isolation test suite for SNOW Phase 21 Web Dashboard.

Tests:
1. Loopback-only binding invariant (host strictly 127.0.0.1).
2. Host header enforcement (rejects malicious external Host headers).
3. Security response headers (CSP, nosniff, DENY frames, no-referrer).
4. Single-use bootstrap token exchange & expiration (60s lifetime, cannot be reused).
5. HttpOnly, SameSite=Strict session cookie validation.
6. CSRF token validation on state-modifying POST requests.
7. Origin validation on POST requests.
8. API route allowlisting (unknown authenticated endpoints return 404).
9. Safe URL scheme validation for link sharing (only http/https allowed).
"""

from __future__ import annotations

import asyncio
import secrets
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from snow.web.server import (
    DEFAULT_DASHBOARD_PORT,
    BOOTSTRAP_TOKEN_LIFETIME_SECONDS,
    SnowWebServer,
)


class TestWebDashboardSecurity(AioHTTPTestCase):
    """Rigorous HTTP-level security test suite for SnowWebServer."""

    async def get_application(self) -> web.Application:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.secret_path = Path(self.tmp_dir.name) / ".ipc_secret"
        self.secret_path.write_text(secrets.token_hex(32), encoding="utf-8")

        # Mock SnowMcpBridge
        self.mock_bridge = MagicMock()
        self.mock_bridge.port = 8767
        self.mock_bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)
        self.mock_bridge.windows_system_info = AsyncMock(return_value={"success": True, "data": {"os": "Windows"}})
        self.mock_bridge.list_devices = AsyncMock(return_value={"success": True, "devices": []})
        self.mock_bridge.call = AsyncMock(return_value={"success": True, "data": {}})
        self.mock_bridge.android_file_list = AsyncMock(return_value={"success": True, "items": []})
        self.mock_bridge.android_notifications_list = AsyncMock(return_value={"success": True, "notifications": []})
        self.mock_bridge.media_control = AsyncMock(return_value={"success": True})
        self.mock_bridge.share_link = AsyncMock(return_value={"success": True})
        self.mock_bridge.activity_history = AsyncMock(return_value={"success": True, "records": []})

        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=DEFAULT_DASHBOARD_PORT,
            bridge=self.mock_bridge,
            auto_open_browser=False,
        )
        return self.web_server._build_app()

    def tearDown(self) -> None:
        super().tearDown()
        self.tmp_dir.cleanup()

    # 1. Loopback-only binding invariant
    def test_loopback_only_binding_invariant(self) -> None:
        """Dashboard must reject binding to non-loopback interfaces (e.g. 0.0.0.0 or LAN IP)."""
        with self.assertRaises(ValueError) as ctx:
            SnowWebServer(host="0.0.0.0")
        self.assertIn("Dashboard may only bind to loopback", str(ctx.exception))

        with self.assertRaises(ValueError) as ctx2:
            SnowWebServer(host="192.168.1.50")
        self.assertIn("Dashboard may only bind to loopback", str(ctx2.exception))

    # 2. Host header enforcement
    @unittest_run_loop
    async def test_host_header_validation_rejects_external_hosts(self) -> None:
        """Requests with unauthorized Host headers (e.g., DNS rebinding attacks) must be rejected."""
        resp = await self.client.get(
            "/",
            headers={"Host": "attacker.com"},
        )
        self.assertIn(resp.status, (400, 403))

        resp_valid = await self.client.get(
            "/",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
        )
        self.assertEqual(resp_valid.status, 200)

    # 3. Security response headers
    @unittest_run_loop
    async def test_security_headers_present(self) -> None:
        """Every response must contain strict CSP, nosniff, DENY frames, and no-referrer."""
        resp = await self.client.get("/", headers={"Host": f"127.0.0.1:{self.web_server.port}"})
        self.assertEqual(resp.status, 200)

        self.assertIn("Content-Security-Policy", resp.headers)
        csp = resp.headers["Content-Security-Policy"]
        self.assertIn("default-src 'self'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("object-src 'none'", csp)

        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("X-Frame-Options"), "DENY")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")

    # 4. Bootstrap token exchange & single-use consumption
    @unittest_run_loop
    async def test_bootstrap_token_exchange_and_single_use_consumption(self) -> None:
        """Bootstrap token can be exchanged once for a session; second attempt is rejected."""
        valid_token = self.web_server.bootstrap_token

        # Invalid token rejection
        bad_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": "invalid_token_123"},
        )
        self.assertEqual(bad_resp.status, 403)

        # First exchange: Success
        good_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": valid_token},
        )
        self.assertEqual(good_resp.status, 200)
        data = await good_resp.json()
        self.assertTrue(data.get("success"))
        self.assertIn("csrf_token", data)
        self.assertTrue(self.web_server.bootstrap_consumed)

        # Verify HttpOnly session cookie
        self.assertIn("snow_session", good_resp.cookies)
        cookie = good_resp.cookies["snow_session"]
        self.assertTrue(cookie["httponly"])
        self.assertEqual(cookie["samesite"].lower(), "strict")

        # Second exchange: Must fail because bootstrap token is single-use
        replay_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": valid_token},
        )
        self.assertEqual(replay_resp.status, 403)
        replay_data = await replay_resp.json()
        self.assertEqual(replay_data.get("status"), "BOOTSTRAP_EXPIRED")

    # 5. Bootstrap token expiration
    @unittest_run_loop
    async def test_bootstrap_token_expiration(self) -> None:
        """Expired bootstrap token (>60s) must be rejected."""
        self.web_server.bootstrap_expires_at = time.time() - 5.0  # Force expired

        resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": self.web_server.bootstrap_token},
        )
        self.assertEqual(resp.status, 403)
        data = await resp.json()
        self.assertEqual(data.get("status"), "BOOTSTRAP_EXPIRED")

    # 6. CSRF validation on mutating POST requests
    @unittest_run_loop
    async def test_csrf_validation_on_mutating_requests(self) -> None:
        """POST requests without valid CSRF token and session cookie return 403."""
        # Exchange bootstrap token first
        token_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": self.web_server.bootstrap_token},
        )
        self.assertEqual(token_resp.status, 200)
        csrf_token = (await token_resp.json())["csrf_token"]

        # POST without CSRF token header
        unauthed_post = await self.client.post(
            "/api/media",
            headers={
                "Host": f"127.0.0.1:{self.web_server.port}",
                "Origin": f"http://127.0.0.1:{self.web_server.port}",
            },
            json={"action": "play_pause", "target": "windows"},
        )
        self.assertEqual(unauthed_post.status, 403)
        self.assertEqual((await unauthed_post.json()).get("status"), "CSRF_ERROR")

        # POST with wrong CSRF token
        bad_csrf_post = await self.client.post(
            "/api/media",
            headers={
                "Host": f"127.0.0.1:{self.web_server.port}",
                "Origin": f"http://127.0.0.1:{self.web_server.port}",
                "X-CSRF-Token": "bogus_token",
            },
            json={"action": "play_pause", "target": "windows"},
        )
        self.assertEqual(bad_csrf_post.status, 403)

        # POST with valid CSRF token and valid Origin
        valid_post = await self.client.post(
            "/api/media",
            headers={
                "Host": f"127.0.0.1:{self.web_server.port}",
                "Origin": f"http://127.0.0.1:{self.web_server.port}",
                "X-CSRF-Token": csrf_token,
            },
            json={"action": "play_pause", "target": "windows"},
        )
        self.assertEqual(valid_post.status, 200)
        self.assertTrue((await valid_post.json()).get("success"))

    # 7. Origin validation on POST requests
    @unittest_run_loop
    async def test_origin_validation_rejects_cross_origin_mutations(self) -> None:
        """POST with untrusted external Origin must be rejected with 403."""
        # Authenticate session
        token_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": self.web_server.bootstrap_token},
        )
        csrf_token = (await token_resp.json())["csrf_token"]

        cross_origin_resp = await self.client.post(
            "/api/share",
            headers={
                "Host": f"127.0.0.1:{self.web_server.port}",
                "Origin": "http://evil-site.com",
                "X-CSRF-Token": csrf_token,
            },
            json={"url": "https://example.com", "target": "phone"},
        )
        self.assertEqual(cross_origin_resp.status, 403)
        self.assertEqual((await cross_origin_resp.json()).get("status"), "CROSS_ORIGIN_FORBIDDEN")

    # 8. API Allowlist & 404 enforcement
    @unittest_run_loop
    async def test_unknown_endpoints_return_404(self) -> None:
        """Authenticated requests to unrecognized endpoints return 404."""
        token_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": self.web_server.bootstrap_token},
        )
        self.assertEqual(token_resp.status, 200)

        resp = await self.client.get(
            "/api/nonexistent_route_test",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
        )
        self.assertEqual(resp.status, 404)

    # 9. Safe URL scheme validation for share_link
    @unittest_run_loop
    async def test_share_link_scheme_validation(self) -> None:
        """Sharing must strictly enforce http/https and reject file:, javascript:, intent: schemes."""
        token_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": self.web_server.bootstrap_token},
        )
        csrf_token = (await token_resp.json())["csrf_token"]

        # Malicious javascript: scheme
        js_resp = await self.client.post(
            "/api/share",
            headers={
                "Host": f"127.0.0.1:{self.web_server.port}",
                "Origin": f"http://127.0.0.1:{self.web_server.port}",
                "X-CSRF-Token": csrf_token,
            },
            json={"url": "javascript:alert(1)", "target": "phone"},
        )
        self.assertEqual(js_resp.status, 400)
        self.assertEqual((await js_resp.json()).get("status"), "INVALID_SCHEME")

        # Disallowed file: scheme
        file_resp = await self.client.post(
            "/api/share",
            headers={
                "Host": f"127.0.0.1:{self.web_server.port}",
                "Origin": f"http://127.0.0.1:{self.web_server.port}",
                "X-CSRF-Token": csrf_token,
            },
            json={"url": "file:///C:/Windows/System32/cmd.exe", "target": "phone"},
        )
        self.assertEqual(file_resp.status, 400)
        self.assertEqual((await file_resp.json()).get("status"), "INVALID_SCHEME")

        # Valid https: scheme
        valid_resp = await self.client.post(
            "/api/share",
            headers={
                "Host": f"127.0.0.1:{self.web_server.port}",
                "Origin": f"http://127.0.0.1:{self.web_server.port}",
                "X-CSRF-Token": csrf_token,
            },
            json={"url": "https://github.com/project-snow", "target": "phone"},
        )
        self.assertEqual(valid_resp.status, 200)
        self.assertTrue((await valid_resp.json()).get("success"))

    @unittest_run_loop
    async def test_devices_list_hoisting_and_qr_methods(self) -> None:
        """Verify /api/devices hoists devices array and /api/pair/qr supports both GET and POST."""
        # 1. Establish session
        bootstrap_token = self.web_server.bootstrap_token
        auth_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": bootstrap_token},
        )
        self.assertEqual(auth_resp.status, 200)

        # 2. Configure mock bridge to return nested devices in data.devices
        self.mock_bridge.list_devices.return_value = {
            "version": "1.0",
            "success": True,
            "data": {
                "devices": [
                    {
                        "device_id": "test-phone-1",
                        "device_name": "Realme RMX5110",
                        "is_connected": True,
                        "transport": "usb_adb",
                    }
                ]
            },
        }

        dev_resp = await self.client.get(
            "/api/devices",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
        )
        self.assertEqual(dev_resp.status, 200)
        dev_json = await dev_resp.json()
        self.assertTrue(dev_json.get("success"))
        self.assertIn("devices", dev_json)
        self.assertEqual(len(dev_json["devices"]), 1)
        self.assertEqual(dev_json["devices"][0]["device_id"], "test-phone-1")

        # 3. Test /api/pair/qr via GET and POST
        self.mock_bridge.call.return_value = {
            "version": "1.0",
            "success": True,
            "data": {
                "id": "desktop-core",
                "pin": "123456",
                "ips": ["127.0.0.1"],
                "port": 8765,
                "fp": "AABBCC",
            },
        }

        # GET
        qr_get = await self.client.get(
            "/api/pair/qr",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
        )
        self.assertEqual(qr_get.status, 200)
        qr_get_json = await qr_get.json()
        self.assertTrue(qr_get_json.get("success"))
        self.assertIn("data", qr_get_json)
        self.assertEqual(qr_get_json["data"]["pin"], "123456")

        # POST (with CSRF token)
        csrf_token = (await auth_resp.json())["csrf_token"]
        qr_post = await self.client.post(
            "/api/pair/qr",
            headers={
                "Host": f"127.0.0.1:{self.web_server.port}",
                "Origin": f"http://127.0.0.1:{self.web_server.port}",
                "X-CSRF-Token": csrf_token,
            },
        )
        self.assertEqual(qr_post.status, 200)
        qr_post_json = await qr_post.json()
        self.assertTrue(qr_post_json.get("success"))
        self.assertEqual(qr_post_json["data"]["pin"], "123456")

    @unittest_run_loop
    async def test_status_endpoint_returns_csrf_token_for_authenticated_session(self) -> None:
        """GET /api/status returns csrf_token when authenticated session cookie is present."""
        bootstrap_token = self.web_server.bootstrap_token
        auth_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": bootstrap_token},
        )
        self.assertEqual(auth_resp.status, 200)
        auth_csrf = (await auth_resp.json())["csrf_token"]

        status_resp = await self.client.get(
            "/api/status",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
        )
        self.assertEqual(status_resp.status, 200)
        status_json = await status_resp.json()
        self.assertTrue(status_json.get("success"))
        self.assertEqual(status_json.get("csrf_token"), auth_csrf)

    @unittest_run_loop
    async def test_devices_revoke_endpoint_and_local_protection(self) -> None:
        """POST /api/devices/revoke revokes peers but rejects revoking the local desktop node."""
        bootstrap_token = self.web_server.bootstrap_token
        auth_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": bootstrap_token},
        )
        csrf_token = (await auth_resp.json())["csrf_token"]

        # 1. Attempt to revoke local desktop node -> Forbidden
        for bad_id in ("desktop-core", "local"):
            local_revoke_resp = await self.client.post(
                "/api/devices/revoke",
                headers={
                    "Host": f"127.0.0.1:{self.web_server.port}",
                    "Origin": f"http://127.0.0.1:{self.web_server.port}",
                    "X-CSRF-Token": csrf_token,
                },
                json={"device_id": bad_id},
            )
            self.assertEqual(local_revoke_resp.status, 400)
            bad_data = await local_revoke_resp.json()
            self.assertEqual(bad_data.get("status"), "FORBIDDEN")

        # 2. Revoke a valid offline peer
        self.mock_bridge.call.return_value = {"success": True, "status": "REVOKED", "data": {"device_id": "ghost-peer-1"}}
        peer_revoke_resp = await self.client.post(
            "/api/devices/revoke",
            headers={
                "Host": f"127.0.0.1:{self.web_server.port}",
                "Origin": f"http://127.0.0.1:{self.web_server.port}",
                "X-CSRF-Token": csrf_token,
            },
            json={"device_id": "ghost-peer-1"},
        )
        self.assertEqual(peer_revoke_resp.status, 200)
        self.mock_bridge.call.assert_called_with("device_revoke", {"device_id": "ghost-peer-1"})

    @unittest_run_loop
    async def test_file_download_dispatch_with_subpath(self) -> None:
        """POST /api/files/download forwards subpath and device_id to bridge.android_file_receive."""
        bootstrap_token = self.web_server.bootstrap_token
        auth_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": bootstrap_token},
        )
        csrf_token = (await auth_resp.json())["csrf_token"]

        self.mock_bridge.android_file_receive = AsyncMock(return_value={"success": True, "file_name": "sample.pdf"})

        dl_resp = await self.client.post(
            "/api/files/download",
            headers={
                "Host": f"127.0.0.1:{self.web_server.port}",
                "Origin": f"http://127.0.0.1:{self.web_server.port}",
                "X-CSRF-Token": csrf_token,
            },
            json={
                "device_id": "phone-1",
                "file_name": "sample.pdf",
                "subpath": "Documents/Work",
            },
        )
        self.assertEqual(dl_resp.status, 200)
        self.mock_bridge.android_file_receive.assert_called_once_with(
            file_name="sample.pdf",
            subpath="Documents/Work",
            device_id="phone-1",
        )

    @unittest_run_loop
    async def test_approvals_and_activity_contract_hoisting(self) -> None:
        """Verify /api/approvals and /api/activity hoist data structures properly."""
        bootstrap_token = self.web_server.bootstrap_token
        auth_resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
            json={"token": bootstrap_token},
        )
        self.assertEqual(auth_resp.status, 200)

        # 1. Approvals hoisting
        self.mock_bridge.call.return_value = {
            "success": True,
            "data": {
                "requests": [
                    {
                        "request_id": "req-1",
                        "action": "remote_fs",
                        "risk_level": "medium",
                    }
                ],
                "count": 1,
            },
        }
        appr_resp = await self.client.get(
            "/api/approvals",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
        )
        self.assertEqual(appr_resp.status, 200)
        appr_data = await appr_resp.json()
        self.assertTrue(appr_data.get("success"))
        self.assertIn("requests", appr_data)
        self.assertEqual(len(appr_data["requests"]), 1)
        self.assertEqual(appr_data["requests"][0]["request_id"], "req-1")

        # 2. Activity hoisting
        self.mock_bridge.activity_history = AsyncMock(return_value={
            "success": True,
            "data": {
                "events": [
                    {
                        "event_id": "ev-1",
                        "capability": "snow_media_control",
                        "outcome": "SUCCESS",
                    }
                ],
                "count": 1,
            },
        })
        act_resp = await self.client.get(
            "/api/activity",
            headers={"Host": f"127.0.0.1:{self.web_server.port}"},
        )
        self.assertEqual(act_resp.status, 200)
        act_data = await act_resp.json()
        self.assertTrue(act_data.get("success"))
        self.assertIn("events", act_data)
        self.assertEqual(len(act_data["events"]), 1)
        self.assertEqual(act_data["events"][0]["capability"], "snow_media_control")

    def test_remote_address_parsing_and_transport_classification(self) -> None:
        """Unit test remote address parsing and transport classification logic."""
        from snow.network.ws_server import parse_remote_address, SnowWebSocketServer

        # Address parsing
        self.assertEqual(parse_remote_address(("127.0.0.1", 8765)), ("127.0.0.1", 8765))
        self.assertEqual(parse_remote_address("192.168.1.100:8765"), ("192.168.1.100", 8765))
        self.assertEqual(parse_remote_address("192.168.1.100"), ("192.168.1.100", 8765))
        self.assertEqual(parse_remote_address("[::1]:8765"), ("::1", 8765))
        self.assertEqual(parse_remote_address(None), ("127.0.0.1", 8765))

        # Transport classification
        mock_srv = MagicMock(spec=SnowWebSocketServer)
        determine_fn = SnowWebSocketServer._determine_transport.__get__(mock_srv, SnowWebSocketServer)

        # Loopback with verified ADB assertion -> usb_adb
        with patch("snow.cli.find_adb_binary", return_value="adb.exe"), \
             patch("snow.cli.get_connected_adb_devices", return_value=[{"serial": "123", "status": "device"}]):
            self.assertEqual(determine_fn("127.0.0.1", "usb_adb"), "usb_adb")

        # Loopback with unverified ADB assertion -> fallback loopback
        with patch("snow.cli.find_adb_binary", return_value="adb.exe"), \
             patch("snow.cli.get_connected_adb_devices", return_value=[]):
            self.assertEqual(determine_fn("127.0.0.1", "usb_adb"), "loopback")

        # Contradiction: Wi-Fi on loopback -> unknown
        self.assertEqual(determine_fn("127.0.0.1", "wifi_lan"), "unknown")
        # Non-loopback network -> wifi_lan
        self.assertEqual(determine_fn("192.168.1.50", "usb_adb"), "wifi_lan")
        # Wi-Fi on non-loopback -> wifi_lan
        self.assertEqual(determine_fn("192.168.1.50", "wifi_lan"), "wifi_lan")
        # Default non-loopback -> wifi_lan
        self.assertEqual(determine_fn("192.168.1.50", None), "wifi_lan")


if __name__ == "__main__":
    unittest.main()
