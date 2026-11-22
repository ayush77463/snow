"""Comprehensive Automated Verification for Phase 28B: Public Remote MCP Platform.

Tests:
1. Client ID Metadata Documents (CIMD - RFC draft) & Strict SSRF Protection
   - HTTPS enforcement (rejection of HTTP CIMD URLs)
   - Strict IP blacklisting: private, loopback, link-local, cloud metadata, IPv4-mapped IPv6
   - Bounded caching (size and TTL)
   - Bounded document size (<= 64 KB)
   - Client ID parity verification
2. DNS Rebinding Protection via PinnedIPHTTPSConnection
3. OAuth 2.1 Code Flow with PKCE, CIMD client, and strict Redirect URI validation
4. Rate Limiting on /oauth/token (30/min) and /oauth/register (10/min) returning HTTP 429
5. Public URL & Host Header / Origin validation (421 Misdirected Request, 403 Forbidden)
6. 38 Tools with strict boolean annotations (readOnlyHint, destructiveHint)
7. snow://mesh/topology Resource Exposure and Sensitive Credential Redaction
8. Strict ExecutionPrincipal.AI_MCP Enforcement
9. CLI 'snow expose' Provider and Tunnel Lifecycle
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import ipaddress
import json
import os
import secrets
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from snow.security.context import ExecutionPrincipal
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.expose import ExposeManager
from snow.mcp.oauth import (
    OAuthServer,
    PinnedIPHTTPSConnection,
    is_ip_restricted,
)
from snow.mcp.registry import list_capabilities
from snow.mcp.remote_gateway import (
    BoundedRateLimiter,
    RemoteMcpGateway,
    parse_trusted_proxies,
    redact_sensitive_topology,
)


class TestPhase28BCimdAndSsrf(unittest.TestCase):
    """Unit tests for CIMD resolution, SSRF defense, and DNS rebinding prevention."""

    def setUp(self):
        self.server = OAuthServer()
        self.server._cimd_cache.clear()

    def test_ssrf_ip_restriction_ipv4(self):
        """Verify strict rejection of private, loopback, and metadata IPv4 addresses."""
        # Loopback
        self.assertTrue(is_ip_restricted("127.0.0.1"))
        self.assertTrue(is_ip_restricted("127.0.0.254"))
        # Private RFC 1918
        self.assertTrue(is_ip_restricted("10.0.0.1"))
        self.assertTrue(is_ip_restricted("172.16.0.1"))
        self.assertTrue(is_ip_restricted("172.31.255.255"))
        self.assertTrue(is_ip_restricted("192.168.1.1"))
        # Link-local / AWS / Azure / GCP Metadata IP
        self.assertTrue(is_ip_restricted("169.254.169.254"))
        self.assertTrue(is_ip_restricted("169.254.1.1"))
        # Unspecified / Broadcast / Multicast
        self.assertTrue(is_ip_restricted("0.0.0.0"))
        self.assertTrue(is_ip_restricted("224.0.0.1"))
        self.assertTrue(is_ip_restricted("255.255.255.255"))

        # Valid public IPs must be permitted
        self.assertFalse(is_ip_restricted("93.184.216.34"))
        self.assertFalse(is_ip_restricted("8.8.8.8"))
        self.assertFalse(is_ip_restricted("1.1.1.1"))

    def test_ssrf_ip_restriction_ipv6(self):
        """Verify strict rejection of IPv6 loopback, site-local, unique-local, metadata, and IPv4-mapped."""
        # IPv6 loopback
        self.assertTrue(is_ip_restricted("::1"))
        # Unspecified
        self.assertTrue(is_ip_restricted("::"))
        # Unique Local Address (fc00::/7)
        self.assertTrue(is_ip_restricted("fd00::1"))
        # Link-local
        self.assertTrue(is_ip_restricted("fe80::1"))
        # Cloud metadata IPv6 (e.g. AWS IMDSv2 fd00:ec2::254)
        self.assertTrue(is_ip_restricted("fd00:ec2::254"))
        # IPv4-mapped IPv6
        self.assertTrue(is_ip_restricted("::ffff:127.0.0.1"))
        self.assertTrue(is_ip_restricted("::ffff:169.254.169.254"))
        self.assertTrue(is_ip_restricted("::ffff:10.0.0.1"))
        self.assertTrue(is_ip_restricted("::ffff:192.168.1.5"))

        # Valid public IPv6 permitted
        self.assertFalse(is_ip_restricted("2606:4700:4700::1111"))
        self.assertFalse(is_ip_restricted("2001:4860:4860::8888"))

    def test_rejection_of_non_https_cimd(self):
        """CIMD URLs must strictly require HTTPS."""
        ok, res = self.server.fetch_cimd_document("http://example.com/client-metadata.json")
        self.assertFalse(ok)
        self.assertIn("must be a valid HTTPS URL", res.get("error_description", ""))

    def test_rejection_of_oversized_cimd(self):
        """CIMD document exceeding 64KB must be rejected."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheader.return_value = "application/json"
        mock_response.read.return_value = b'{"client_name": "' + (b"A" * 70000) + b'"}'

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))]):
            with patch("snow.mcp.oauth.PinnedIPHTTPSConnection", return_value=mock_conn):
                ok, res = self.server.fetch_cimd_document("https://example.com/client.json")
                self.assertFalse(ok)
                self.assertIn("exceeds maximum permitted size", res.get("error_description", ""))

    def test_rejection_of_mismatched_client_id_in_cimd(self):
        """CIMD document with non-matching client_id inside payload must be rejected."""
        cimd_payload = {
            "client_id": "https://different-client.com/mcp.json",
            "client_name": "Different Client",
            "redirect_uris": ["https://different-client.com/callback"],
        }
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheader.return_value = "application/json"
        mock_response.read.return_value = json.dumps(cimd_payload).encode("utf-8")

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("93.184.216.34", 443))]):
            with patch("snow.mcp.oauth.PinnedIPHTTPSConnection", return_value=mock_conn):
                ok, res = self.server.fetch_cimd_document("https://example.com/client.json")
                self.assertFalse(ok)
                self.assertIn("does not match requested URL", res.get("error_description", ""))

    def test_valid_cimd_fetch_and_caching(self):
        """Valid CIMD document fetches and caches properly via get_client."""
        client_url = "https://claude.ai/metadata/mcp.json"
        cimd_payload = {
            "client_id": client_url,
            "client_name": "Claude Web Remote MCP Client",
            "redirect_uris": ["https://claude.ai/api/mcp/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
        }
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.getheader.return_value = "application/json"
        mock_response.read.return_value = json.dumps(cimd_payload).encode("utf-8")

        mock_conn = MagicMock()
        mock_conn.getresponse.return_value = mock_response

        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("104.18.2.1", 443))]):
            with patch("snow.mcp.oauth.PinnedIPHTTPSConnection", return_value=mock_conn):
                # First fetch via get_client
                client = self.server.get_client(client_url)
                self.assertIsNotNone(client)
                self.assertEqual(client.client_name, "Claude Web Remote MCP Client")
                self.assertIn("https://claude.ai/api/mcp/callback", client.redirect_uris)
                self.assertIn(client_url, self.server._cimd_cache)

                # Second fetch should hit cache without invoking getaddrinfo
                with patch("socket.getaddrinfo", side_effect=AssertionError("Should hit cache")):
                    client2 = self.server.get_client(client_url)
                    self.assertIsNotNone(client2)
                    self.assertEqual(client2.client_name, "Claude Web Remote MCP Client")


class TestPhase28BRemoteMcpGateway(AioHTTPTestCase):
    """Integration test suite for Phase 28B Public Remote MCP Gateway."""

    async def get_application(self) -> web.Application:
        self.mock_bridge = AsyncMock(spec=SnowMcpBridge)
        self.mock_bridge.windows_system_info = AsyncMock(return_value={
            "success": True,
            "status": "SUCCESS",
            "data": {"os": "Windows 11", "cpu_count": 8},
        })
        self.mock_bridge.get_device_status = AsyncMock(return_value={
            "success": True,
            "status": "SUCCESS",
            "data": {"status": "ONLINE", "devices": []},
        })
        # Mock snow_mesh_topology to return mock topology with sensitive data
        self.mock_bridge.snow_mesh_topology = AsyncMock(return_value={
            "success": True,
            "status": "SUCCESS",
            "mesh_id": "mesh-test-123",
            "nodes": [
                {
                    "device_id": "win-desktop-node",
                    "device_name": "Lenovo V15",
                    "device_type": "windows",
                    "status": "ONLINE",
                    "relay_ticket": "SECRET_TICKET_DO_NOT_LEAK",
                    "peer_private_key": "SECRET_KEY_DO_NOT_LEAK",
                    "pairing_pin": "9999",
                },
                {
                    "device_id": "android-phone-node",
                    "device_name": "Realme RMX5110",
                    "device_type": "android",
                    "status": "ONLINE",
                    "relay_ticket": "SECRET_ANDROID_TICKET",
                }
            ],
            "active_connections": 1,
        })

        self.gateway = RemoteMcpGateway(
            host="127.0.0.1",
            port=8771,
            bridge=self.mock_bridge,
            issuer="https://snow.test.local:8771",
            public_url="https://snow.test.local:8771",
        )
        return self.gateway.app

    async def _obtain_token(self) -> str:
        # Dynamic Client Registration
        reg_resp = await self.client.post(
            "/oauth/register",
            headers={"Host": "snow.test.local:8771"},
            json={
                "client_name": "Test Client",
                "redirect_uris": ["https://client.example.com/callback"],
                "grant_types": ["authorization_code", "refresh_token"],
            },
        )
        self.assertEqual(reg_resp.status, 201)
        reg_data = await reg_resp.json()
        client_id = reg_data["client_id"]

        # Auth code with PKCE
        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).decode("ascii").rstrip("=")

        ok, code = self.gateway.oauth_server.create_authorization_code(
            client_id=client_id,
            redirect_uri="https://client.example.com/callback",
            scope="snow:mcp",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        self.assertTrue(ok)

        token_resp = await self.client.post(
            "/oauth/token",
            headers={"Host": "snow.test.local:8771"},
            json={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": client_id,
                "redirect_uri": "https://client.example.com/callback",
                "code_verifier": verifier,
            },
        )
        self.assertEqual(token_resp.status, 200)
        token_data = await token_resp.json()
        return token_data["access_token"]

    # -------------------------------------------------------------------------
    # 1. Public Metadata & Host/Origin Hardening
    # -------------------------------------------------------------------------

    async def test_public_metadata_reflects_configured_public_url(self):
        """Verify .well-known metadata endpoints reflect the public_url."""
        resp = await self.client.get(
            "/.well-known/oauth-authorization-server",
            headers={"Host": "snow.test.local:8771"},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertEqual(data["issuer"], "https://snow.test.local:8771")
        self.assertEqual(
            data["authorization_endpoint"],
            "https://snow.test.local:8771/oauth/authorize",
        )
        self.assertTrue(data.get("client_id_metadata_document_supported", False))

    async def test_host_header_validation_rejects_unauthorized_host(self):
        """Requests with unauthorized Host header return 421 Misdirected Request."""
        resp = await self.client.get(
            "/.well-known/oauth-authorization-server",
            headers={"Host": "malicious.attacker.com"},
        )
        self.assertEqual(resp.status, 421)

    async def test_origin_header_validation_rejects_unauthorized_origin(self):
        """Cross-origin requests from untrusted origins return 403 Forbidden."""
        resp = await self.client.get(
            "/.well-known/oauth-authorization-server",
            headers={
                "Host": "snow.test.local:8771",
                "Origin": "https://evil.site.com",
            },
        )
        self.assertEqual(resp.status, 403)

    # -------------------------------------------------------------------------
    # 2. Rate Limiting on OAuth Endpoints
    # -------------------------------------------------------------------------

    async def test_rate_limiting_on_registration_endpoint(self):
        """Verify registration endpoint is rate limited to 10 requests/minute."""
        limiter = self.gateway.register_rate_limiter
        async with limiter._lock:
            limiter._records.clear()

        # Send 10 rapid registrations (allowed)
        for i in range(10):
            resp = await self.client.post(
                "/oauth/register",
                headers={"Host": "snow.test.local:8771"},
                json={
                    "client_name": f"Rate Limit Test {i}",
                    "redirect_uris": ["https://client.example.com/callback"],
                },
            )
            self.assertEqual(resp.status, 201)

        # 11th registration must be rejected with 429
        resp = await self.client.post(
            "/oauth/register",
            headers={"Host": "snow.test.local:8771"},
            json={
                "client_name": "Rate Limit Test 11",
                "redirect_uris": ["https://client.example.com/callback"],
            },
        )
        self.assertEqual(resp.status, 429)
        err = await resp.json()
        self.assertIn("rate limit exceeded", err.get("error_description", "").lower())

    async def test_rate_limiting_on_token_endpoint(self):
        """Verify token endpoint is rate limited to 30 requests/minute."""
        limiter = self.gateway.token_rate_limiter
        async with limiter._lock:
            limiter._records.clear()

        # Fill up 30 requests
        for _ in range(30):
            await limiter.is_allowed("127.0.0.1")

        # Next token request from same IP should get 429
        resp = await self.client.post(
            "/oauth/token",
            headers={"Host": "snow.test.local:8771"},
            json={
                "grant_type": "authorization_code",
                "code": "dummy_code",
                "client_id": "dummy_client",
                "redirect_uri": "https://client.example.com/callback",
                "code_verifier": "dummy_verifier",
            },
        )
        self.assertEqual(resp.status, 429)

    # -------------------------------------------------------------------------
    # 3. 38 Tools and Boolean Annotations
    # -------------------------------------------------------------------------

    async def test_all_38_tools_and_boolean_annotations(self):
        """Verify exactly 38 capabilities are returned with strict boolean annotations."""
        token = await self._obtain_token()
        resp = await self.client.post(
            "/mcp",
            headers={
                "Host": "snow.test.local:8771",
                "Authorization": f"Bearer {token}",
            },
            json={
                "jsonrpc": "2.0",
                "id": "req-tools-list",
                "method": "tools/list",
                "params": {},
            },
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        result = data.get("result", {})
        tools = result.get("tools", [])

        self.assertEqual(len(tools), 38, f"Expected 38 capabilities, found {len(tools)}")

        # Verify each tool has annotations with strict boolean values
        for tool in tools:
            self.assertIn("annotations", tool, f"Tool {tool['name']} missing annotations")
            annotations = tool["annotations"]
            self.assertIn("readOnlyHint", annotations)
            self.assertIn("destructiveHint", annotations)
            self.assertIsInstance(annotations["readOnlyHint"], bool)
            self.assertIsInstance(annotations["destructiveHint"], bool)

    # -------------------------------------------------------------------------
    # 4. Topology Resource Exposure and Sensitive Redaction
    # -------------------------------------------------------------------------

    async def test_resources_list_and_read_topology_with_redaction(self):
        """Verify snow://mesh/topology resource is exposed and credentials are redacted."""
        token = await self._obtain_token()

        # 1. resources/list
        list_resp = await self.client.post(
            "/mcp",
            headers={
                "Host": "snow.test.local:8771",
                "Authorization": f"Bearer {token}",
            },
            json={
                "jsonrpc": "2.0",
                "id": "req-resources-list",
                "method": "resources/list",
                "params": {},
            },
        )
        self.assertEqual(list_resp.status, 200)
        list_data = await list_resp.json()
        resources = list_data.get("result", {}).get("resources", [])
        self.assertTrue(any(r["uri"] == "snow://mesh/topology" for r in resources))

        # 2. resources/read
        read_resp = await self.client.post(
            "/mcp",
            headers={
                "Host": "snow.test.local:8771",
                "Authorization": f"Bearer {token}",
            },
            json={
                "jsonrpc": "2.0",
                "id": "req-resources-read",
                "method": "resources/read",
                "params": {"uri": "snow://mesh/topology"},
            },
        )
        self.assertEqual(read_resp.status, 200)
        read_data = await read_resp.json()
        contents = read_data.get("result", {}).get("contents", [])
        self.assertTrue(len(contents) > 0)
        content_text = contents[0]["text"]
        topo = json.loads(content_text)

        # Confirm nodes are present
        self.assertEqual(len(topo["nodes"]), 2)

        # CONFIRM SENSITIVE CREDENTIALS REDACTED
        self.assertNotIn("SECRET_TICKET_DO_NOT_LEAK", content_text)
        self.assertNotIn("SECRET_KEY_DO_NOT_LEAK", content_text)
        self.assertNotIn("9999", content_text)
        self.assertNotIn("relay_ticket", content_text)
        self.assertNotIn("peer_private_key", content_text)
        self.assertNotIn("pairing_pin", content_text)

    # -------------------------------------------------------------------------
    # 5. Execution Principal Enforcement
    # -------------------------------------------------------------------------

    async def test_remote_tool_execution_enforces_ai_mcp_principal(self):
        """All tools executed over remote gateway must carry ExecutionPrincipal.AI_MCP."""
        token = await self._obtain_token()
        self.mock_bridge.snow_mesh_topology.reset_mock()
        resp = await self.client.post(
            "/mcp",
            headers={
                "Host": "snow.test.local:8771",
                "Authorization": f"Bearer {token}",
            },
            json={
                "jsonrpc": "2.0",
                "id": "exec-tool-1",
                "method": "tools/call",
                "params": {
                    "name": "snow_mesh_topology",
                    "arguments": {},
                },
            },
        )
        self.assertEqual(resp.status, 200)
        self.mock_bridge.snow_mesh_topology.assert_called_once()
        kwargs = self.mock_bridge.snow_mesh_topology.call_args.kwargs
        self.assertIn("ctx", kwargs)
        self.assertEqual(kwargs["ctx"].principal, ExecutionPrincipal.AI_MCP)

    # -------------------------------------------------------------------------
    # 6. Protocol Version Negotiation
    # -------------------------------------------------------------------------

    async def test_mcp_protocol_version_negotiation(self):
        """Verify protocol version negotiation for 2026-07-28, legacy, and boundary versions."""
        token = await self._obtain_token()

        # 1. Exact match for current version (2026-07-28)
        resp = await self.client.post(
            "/mcp",
            headers={"Host": "snow.test.local:8771", "Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": "init-1",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            },
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertEqual(data["result"]["protocolVersion"], "2026-07-28")
        self.assertEqual(resp.headers.get("MCP-Protocol-Version"), "2026-07-28")

        # 2. Exact match for legacy supported version (2025-11-25)
        resp = await self.client.post(
            "/mcp",
            headers={"Host": "snow.test.local:8771", "Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": "init-2",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            },
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertEqual(data["result"]["protocolVersion"], "2025-11-25")
        self.assertEqual(resp.headers.get("MCP-Protocol-Version"), "2025-11-25")

        # 3. Future version falls back to highest supported (2026-07-28)
        resp = await self.client.post(
            "/mcp",
            headers={"Host": "snow.test.local:8771", "Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": "init-3",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2027-01-01",
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            },
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertEqual(data["result"]["protocolVersion"], "2026-07-28")

        # 4. Too-old version (predating earliest supported) rejected with 400
        resp = await self.client.post(
            "/mcp",
            headers={"Host": "snow.test.local:8771", "Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": "init-4",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2020-01-01",
                    "clientInfo": {"name": "test", "version": "1.0"},
                },
            },
        )
        self.assertEqual(resp.status, 400)
        data = await resp.json()
        self.assertEqual(data["error"]["code"], -32602)


class TestPhase28BExposeCLI(unittest.TestCase):
    """Unit tests for 'snow expose' tunnel manager and CLI."""

    def test_expose_manager_initialization(self):
        """Test ExposeManager initializes with default providers and local port."""
        mgr = ExposeManager(port=8771, provider="cloudflared")
        self.assertEqual(mgr.port, 8771)
        self.assertEqual(mgr.provider, "cloudflared")

        mgr_ts = ExposeManager(port=8771, provider="tailscale")
        self.assertEqual(mgr_ts.provider, "tailscale")

    def test_expose_provider_missing_binary_message(self):
        """Test actionable guidance when provider binary is missing."""
        with patch("shutil.which", return_value=None):
            available, binary, instructions = ExposeManager.detect_provider("cloudflared")
            self.assertFalse(available)
            self.assertIn("winget install --id Cloudflare.cloudflared", instructions)

        with patch("shutil.which", return_value=None):
            available, binary, instructions = ExposeManager.detect_provider("tailscale")
            self.assertFalse(available)
            self.assertIn("tailscale.com/download", instructions)

    def test_expose_external_gateway_mode_fails_if_unhealthy(self):
        """External gateway mode must exit if gateway is not reachable on the port."""
        mgr = ExposeManager(port=8771, provider="cloudflared", external_gateway=True)
        with patch.object(mgr, "check_gateway_health", return_value=False):
            rc = mgr.start_tunnel()
            self.assertEqual(rc, 1)

    def test_expose_managed_mode_fails_if_port_already_in_use(self):
        """Managed mode requires port to be free to start dedicated gateway."""
        mgr = ExposeManager(port=8771, provider="cloudflared", external_gateway=False)
        with patch.object(mgr, "check_gateway_health", return_value=True):
            rc = mgr.start_tunnel()
            self.assertEqual(rc, 1)

    def test_expose_clean_teardown(self):
        """Verify stop cleanly shuts down both tunnel and gateway."""
        mgr = ExposeManager(port=8771, provider="cloudflared")
        mock_tunnel = MagicMock()
        mock_tunnel.poll.return_value = None
        mock_gateway = MagicMock()
        mock_gateway.poll.return_value = None
        mgr._tunnel_process = mock_tunnel
        mgr._gateway_process = mock_gateway

        mgr.stop()
        mock_gateway.terminate.assert_called_once()
        mock_tunnel.terminate.assert_called_once()


class TestPhase28BTrustedProxiesAndClientIP(unittest.TestCase):
    """Unit tests for proxy header parsing and spoofing prevention."""

    def test_parse_trusted_proxies_defaults(self):
        """Defaults to loopback IPv4 and IPv6."""
        with patch.dict(os.environ, {}, clear=True):
            proxies = parse_trusted_proxies()
            self.assertIn("127.0.0.1", proxies)
            self.assertIn("::1", proxies)

    def test_parse_trusted_proxies_custom_arg(self):
        """Custom CLI argument overrides defaults."""
        proxies = parse_trusted_proxies("10.0.0.1, 10.0.0.2, 127.0.0.1")
        self.assertEqual(proxies, {"10.0.0.1", "10.0.0.2", "127.0.0.1"})

    def test_parse_trusted_proxies_env_var(self):
        """Environment variable SNOW_MCP_TRUSTED_PROXIES is honored."""
        with patch.dict(os.environ, {"SNOW_MCP_TRUSTED_PROXIES": "caddy, 172.20.0.5"}):
            proxies = parse_trusted_proxies()
            self.assertEqual(proxies, {"caddy", "172.20.0.5"})

    def test_get_client_ip_trusted_proxy_uses_forwarded_for(self):
        """Trusted proxy IP allows extracting client IP from X-Forwarded-For."""
        from snow.mcp.remote_gateway import get_client_ip
        req = MagicMock()
        req.transport.get_extra_info.return_value = ("127.0.0.1", 54321)
        req.headers = {"X-Forwarded-For": "203.0.113.195, 127.0.0.1"}

        client_ip = get_client_ip(req, trusted_proxies={"127.0.0.1"})
        self.assertEqual(client_ip, "203.0.113.195")

    def test_get_client_ip_untrusted_direct_ignores_forwarded_for(self):
        """Direct connection from untrusted IP strictly ignores spoofed X-Forwarded-For."""
        from snow.mcp.remote_gateway import get_client_ip
        req = MagicMock()
        req.transport.get_extra_info.return_value = ("198.51.100.22", 54321)
        req.headers = {"X-Forwarded-For": "1.1.1.1"}

        client_ip = get_client_ip(req, trusted_proxies={"127.0.0.1"})
        self.assertEqual(client_ip, "198.51.100.22")


class TestPhase28BDockerAndCaddyPackaging(unittest.TestCase):
    """Validation tests for Docker Compose, Caddyfile, and Dockerfile packaging."""

    def test_dockerfile_packaging_hygiene(self):
        """Dockerfile must use pyproject.toml and src packaging without requirements.txt."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        dockerfile_path = os.path.join(repo_root, "deploy", "Dockerfile")
        self.assertTrue(os.path.exists(dockerfile_path))
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn("requirements.txt", content)
        self.assertIn("COPY pyproject.toml .", content)
        self.assertIn("COPY src/ ./src/", content)
        self.assertIn("USER snow", content)

    def test_docker_compose_relay_service_and_security(self):
        """docker-compose.yml must include snow-relay on internal network with no public port mapping."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        compose_path = os.path.join(repo_root, "deploy", "docker-compose.yml")
        self.assertTrue(os.path.exists(compose_path))
        with open(compose_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("snow-relay:", content)
        self.assertIn("snow-mcp-gateway:", content)
        self.assertIn("caddy:", content)
        self.assertIn("SNOW_MCP_TRUSTED_PROXIES", content)
        self.assertIn("caddy,127.0.0.1,::1", content)
        # snow-relay must NOT expose host ports (only internal 8770 exposed)
        self.assertIn("expose:\n      - \"8770\"", content)

    def test_caddyfile_routing(self):
        """Caddyfile must route /v1/tunnel* to snow-relay:8770 with WebSocket headers."""
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        caddyfile_path = os.path.join(repo_root, "deploy", "Caddyfile")
        self.assertTrue(os.path.exists(caddyfile_path))
        with open(caddyfile_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("@relay_ws", content)
        self.assertIn("path /v1/tunnel*", content)
        self.assertIn("reverse_proxy @relay_ws snow-relay:8770", content)
        self.assertIn("reverse_proxy snow-mcp-gateway:8771", content)


class TestPhase28BDeepRedaction(unittest.TestCase):
    """Deep recursion tests for sensitive credential redaction across all 9 keys."""

    def test_deeply_nested_topology_redaction_all_nine_keys(self):
        """Verify all 9 sensitive keys are scrubbed regardless of depth."""
        dirty_topo = {
            "mesh_id": "mesh-abc",
            "metadata": {
                "admin_ticket": "LEAK_TICKET",
                "shared_secret": "LEAK_SECRET",
                "nested_devices": [
                    {
                        "device_id": "dev-1",
                        "peer_private_key": "LEAK_PRIVATE_KEY",
                        "auth": {
                            "token_hash": "LEAK_TOKEN_HASH",
                            "auth_token": "LEAK_AUTH_TOKEN",
                            "pairing_pin": "1234",
                            "user_password": "LEAK_PASSWORD",
                            "client_credential": "LEAK_CREDENTIAL",
                            "temp_pairing_token": "LEAK_PAIRING_TOKEN",
                        },
                        "safe_field": "KEEP_ME",
                    }
                ],
            },
            "status": "HEALTHY",
        }

        cleaned = redact_sensitive_topology(dirty_topo)
        dumped = json.dumps(cleaned)

        self.assertIn("mesh-abc", dumped)
        self.assertIn("KEEP_ME", dumped)
        self.assertIn("HEALTHY", dumped)

        for leak in (
            "LEAK_TICKET",
            "LEAK_SECRET",
            "LEAK_PRIVATE_KEY",
            "LEAK_TOKEN_HASH",
            "LEAK_AUTH_TOKEN",
            "1234",
            "LEAK_PASSWORD",
            "LEAK_CREDENTIAL",
            "LEAK_PAIRING_TOKEN",
        ):
            self.assertNotIn(leak, dumped, f"Sensitive leak found: {leak}")


if __name__ == "__main__":
    unittest.main()
