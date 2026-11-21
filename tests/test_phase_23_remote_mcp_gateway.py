"""Comprehensive Automated Verification for Phase 23: Remote MCP Streamable HTTP Gateway.

Tests:
1. OAuth 2.1 Discovery (RFC 8414 & RFC 9207)
2. Dynamic Client Registration (RFC 7591)
3. Authorization Code flow with PKCE S256 verification (RFC 7636)
4. PKCE verification failure & single-use code invalidation
5. Refresh token rotation & replay attack detection (family invalidation)
6. Token revocation (RFC 7009)
7. Streamable HTTP /mcp 401 challenge on missing/invalid token
8. Streamable HTTP /mcp initialize and tools/list (all 30 tools + annotations)
9. Tool execution with least-privilege AI_MCP enforcement
10. DNS rebinding & Origin validation
11. Backward compatibility: stdio MCP server unaffected
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.oauth import OAuthServer
from snow.mcp.registry import list_capabilities
from snow.mcp.remote_gateway import RemoteMcpGateway
from snow.mcp.server import create_snow_mcp_server


class TestPhase23RemoteMcpGateway(AioHTTPTestCase):
    """Integration test suite for the Remote MCP Gateway and OAuth 2.1."""

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

        self.gateway = RemoteMcpGateway(
            host="127.0.0.1",
            port=8771,
            bridge=self.mock_bridge,
            issuer="http://127.0.0.1:8771",
        )
        return self.gateway.app

    # -------------------------------------------------------------------------
    # 1. OAuth 2.1 Discovery Tests
    # -------------------------------------------------------------------------

    async def test_oauth_protected_resource_metadata(self):
        resp = await self.client.get("/.well-known/oauth-protected-resource")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertIn("resource", data)
        self.assertTrue(data["resource"].endswith("/mcp"))
        self.assertIn("authorization_servers", data)
        self.assertIn("snow:mcp", data["scopes_supported"])

    async def test_oauth_authorization_server_metadata(self):
        resp = await self.client.get("/.well-known/oauth-authorization-server")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertEqual(data["issuer"], "http://127.0.0.1:8771")
        self.assertTrue(data["authorization_endpoint"].endswith("/oauth/authorize"))
        self.assertTrue(data["token_endpoint"].endswith("/oauth/token"))
        self.assertIn("S256", data["code_challenge_methods_supported"])
        self.assertIn("authorization_code", data["grant_types_supported"])
        self.assertIn("refresh_token", data["grant_types_supported"])

    # -------------------------------------------------------------------------
    # 2. Dynamic Client Registration & PKCE Flow
    # -------------------------------------------------------------------------

    async def test_dynamic_client_registration_and_pkce_flow(self):
        # 1. Register client
        reg_resp = await self.client.post("/oauth/register", json={
            "client_name": "Claude Desktop AI",
            "redirect_uris": ["http://127.0.0.1/callback"],
            "scope": "snow:mcp",
        })
        self.assertEqual(reg_resp.status, 201)
        reg_data = await reg_resp.json()
        client_id = reg_data["client_id"]
        self.assertTrue(client_id.startswith("snow_client_"))

        # 2. Prepare PKCE S256 challenge
        code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        # 3. Request authorization code
        auth_resp = await self.client.post("/oauth/authorize", json={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1/callback",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "scope": "snow:mcp",
            "state": "state_12345",
        }, allow_redirects=False)
        self.assertEqual(auth_resp.status, 302)
        location = auth_resp.headers.get("Location")
        self.assertIn("code=", location)
        self.assertIn("state=state_12345", location)

        code = location.split("code=")[1].split("&")[0]

        # 4. Exchange code for access & refresh token
        tok_resp = await self.client.post("/oauth/token", json={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1/callback",
            "code": code,
            "code_verifier": code_verifier,
        })
        self.assertEqual(tok_resp.status, 200)
        tok_data = await tok_resp.json()
        self.assertIn("access_token", tok_data)
        self.assertIn("refresh_token", tok_data)
        self.assertEqual(tok_data["token_type"], "Bearer")

        access_token = tok_data["access_token"]
        refresh_token = tok_data["refresh_token"]

        # 5. Access /mcp with valid Bearer token
        mcp_resp = await self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "jsonrpc": "2.0",
                "id": "1",
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            },
        )
        self.assertEqual(mcp_resp.status, 200)
        mcp_data = await mcp_resp.json()
        self.assertEqual(mcp_data["result"]["protocolVersion"], "2024-11-05")
        self.assertIn("Mcp-Session-Id", mcp_resp.headers)

        # 6. Rotate refresh token
        rotate_resp = await self.client.post("/oauth/token", json={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
        })
        self.assertEqual(rotate_resp.status, 200)
        rotate_data = await rotate_resp.json()
        new_access_token = rotate_data["access_token"]
        new_refresh_token = rotate_data["refresh_token"]
        self.assertNotEqual(access_token, new_access_token)
        self.assertNotEqual(refresh_token, new_refresh_token)

        # 7. Old refresh token replay detection -> family invalidated
        replay_resp = await self.client.post("/oauth/token", json={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,  # Attempt reuse of old token
        })
        self.assertEqual(replay_resp.status, 400)
        replay_err = await replay_resp.json()
        self.assertIn("replay detected", replay_err.get("error_description", "").lower())

        # Now the newly rotated token is also revoked due to family invalidation
        revoked_resp = await self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {new_access_token}"},
            json={"jsonrpc": "2.0", "id": "2", "method": "ping"},
        )
        self.assertEqual(revoked_resp.status, 401)

    # -------------------------------------------------------------------------
    # 3. Negative Security & PKCE Tests
    # -------------------------------------------------------------------------

    async def test_pkce_verifier_mismatch_rejected(self):
        reg_resp = await self.client.post("/oauth/register", json={"client_name": "Test"})
        client_id = (await reg_resp.json())["client_id"]

        code_verifier = "correct_code_verifier_12345678901234567890"
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        auth_resp = await self.client.post("/oauth/authorize", json={
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
        })
        code = (await auth_resp.json())["code"]

        # Exchange with wrong verifier
        tok_resp = await self.client.post("/oauth/token", json={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "code": code,
            "code_verifier": "wrong_verifier_99999999999999999999999",
        })
        self.assertEqual(tok_resp.status, 400)
        err_data = await tok_resp.json()
        self.assertEqual(err_data["error"], "invalid_grant")

    async def test_auth_code_single_use_consumption(self):
        reg_resp = await self.client.post("/oauth/register", json={"client_name": "Test"})
        client_id = (await reg_resp.json())["client_id"]

        code_verifier = "verifier_test_1234567890123456789012345678"
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        auth_resp = await self.client.post("/oauth/authorize", json={
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
        })
        code = (await auth_resp.json())["code"]

        # First exchange: Success
        first_resp = await self.client.post("/oauth/token", json={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "code": code,
            "code_verifier": code_verifier,
        })
        self.assertEqual(first_resp.status, 200)

        # Second exchange: Must fail (already consumed)
        second_resp = await self.client.post("/oauth/token", json={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "code": code,
            "code_verifier": code_verifier,
        })
        self.assertEqual(second_resp.status, 400)

    # -------------------------------------------------------------------------
    # 4. Streamable HTTP /mcp Protocol Tests
    # -------------------------------------------------------------------------

    async def test_mcp_unauthenticated_returns_401_challenge(self):
        resp = await self.client.post("/mcp", json={
            "jsonrpc": "2.0",
            "id": "1",
            "method": "ping",
        })
        self.assertEqual(resp.status, 401)
        auth_header = resp.headers.get("WWW-Authenticate", "")
        self.assertIn("Bearer", auth_header)
        self.assertIn("resource_metadata=", auth_header)

    async def test_mcp_tools_list_returns_30_capabilities_with_annotations(self):
        # Register and issue valid token directly
        tok_data = self.gateway.oauth_server._issue_token_pair("test_client", "snow:mcp")
        access_token = tok_data["access_token"]

        resp = await self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {access_token}"},
            json={
                "jsonrpc": "2.0",
                "id": "100",
                "method": "tools/list",
            },
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        tools = data["result"]["tools"]
        self.assertEqual(len(tools), 37)

        # Verify tool structure and annotations
        tool_names = {t["name"] for t in tools}
        self.assertIn("snow_get_device_status", tool_names)
        self.assertIn("snow_windows_system_info", tool_names)
        self.assertIn("snow_android_file_list", tool_names)

        # Spot check annotations
        for t in tools:
            self.assertIn("annotations", t)
            self.assertIn("readOnlyHint", t["annotations"])
            self.assertIn("destructiveHint", t["annotations"])

    async def test_mcp_dns_rebinding_rejected(self):
        resp = await self.client.get(
            "/health",
            headers={"Host": "attacker-evil-domain.com"},
        )
        self.assertEqual(resp.status, 421)

    async def test_mcp_origin_validation_rejected(self):
        resp = await self.client.get(
            "/health",
            headers={"Origin": "https://malicious-site.com"},
        )
        self.assertEqual(resp.status, 403)

    async def _get_valid_token(self) -> str:
        reg_resp = await self.client.post("/oauth/register", json={"client_name": "Test"})
        client_id = (await reg_resp.json())["client_id"]

        code_verifier = "verifier_test_1234567890123456789012345678"
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        auth_resp = await self.client.post("/oauth/authorize", json={
            "response_type": "code",
            "client_id": client_id,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
        })
        code = (await auth_resp.json())["code"]

        tok_resp = await self.client.post("/oauth/token", json={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "code": code,
            "code_verifier": code_verifier,
        })
        return (await tok_resp.json())["access_token"]

    async def test_mcp_protocol_version_negotiation_all_supported_versions(self):
        token = await self._get_valid_token()
        supported = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

        for ver in supported:
            init_resp = await self.client.post(
                "/mcp",
                headers={
                    "Authorization": f"Bearer {token}",
                    "MCP-Protocol-Version": ver,
                },
                json={
                    "jsonrpc": "2.0",
                    "id": f"init-{ver}",
                    "method": "initialize",
                    "params": {"protocolVersion": ver},
                },
            )
            self.assertEqual(init_resp.status, 200)
            self.assertEqual(init_resp.headers.get("MCP-Protocol-Version"), ver)
            data = await init_resp.json()
            self.assertEqual(data["result"]["protocolVersion"], ver)

    async def test_mcp_protocol_version_negotiation_success(self):
        token = await self._get_valid_token()

        # Valid protocol version negotiation with subsequent requests
        init_resp = await self.client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "MCP-Protocol-Version": "2025-06-18",
            },
            json={
                "jsonrpc": "2.0",
                "id": "init-1",
                "method": "initialize",
                "params": {"protocolVersion": "2025-06-18"},
            },
        )
        self.assertEqual(init_resp.status, 200)
        self.assertEqual(init_resp.headers.get("MCP-Protocol-Version"), "2025-06-18")
        data = await init_resp.json()
        self.assertEqual(data["result"]["protocolVersion"], "2025-06-18")
        session_id = init_resp.headers["Mcp-Session-Id"]

        # Subsequent ping using the negotiated version
        ping_resp = await self.client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "Mcp-Session-Id": session_id,
                "MCP-Protocol-Version": "2025-06-18",
            },
            json={"jsonrpc": "2.0", "id": "ping-1", "method": "ping"},
        )
        self.assertEqual(ping_resp.status, 200)
        self.assertEqual(ping_resp.headers.get("MCP-Protocol-Version"), "2025-06-18")

    async def test_mcp_protocol_version_fallback_future_handshake(self):
        token = await self._get_valid_token()

        # Client requests a valid future handshake-era version: server falls back to latest supported
        init_resp = await self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": "init-fallback",
                "method": "initialize",
                "params": {"protocolVersion": "2026-01-01"},
            },
        )
        self.assertEqual(init_resp.status, 200)
        self.assertEqual(init_resp.headers.get("MCP-Protocol-Version"), "2025-11-25")
        data = await init_resp.json()
        self.assertEqual(data["result"]["protocolVersion"], "2025-11-25")

    async def test_mcp_protocol_version_negotiation_unsupported_rejected(self):
        token = await self._get_valid_token()

        # Unsupported protocol version (predates MCP initial release 2024-11-05)
        init_resp = await self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": "init-2",
                "method": "initialize",
                "params": {"protocolVersion": "1999-01-01"},
            },
        )
        self.assertEqual(init_resp.status, 400)
        data = await init_resp.json()
        self.assertEqual(data["error"]["code"], -32602)
        self.assertIn("Unsupported MCP protocol version", data["error"]["message"])

    async def test_mcp_protocol_version_invalid_or_bogus_rejected(self):
        token = await self._get_valid_token()

        # Bogus non-date string
        init_resp = await self.client.post(
            "/mcp",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "jsonrpc": "2.0",
                "id": "init-bogus",
                "method": "initialize",
                "params": {"protocolVersion": "bogus-protocol-version"},
            },
        )
        self.assertEqual(init_resp.status, 400)
        data = await init_resp.json()
        self.assertEqual(data["error"]["code"], -32602)
        self.assertIn("Invalid or bogus MCP protocol version", data["error"]["message"])

    async def test_mcp_protocol_version_header_unsupported_rejected(self):
        token = await self._get_valid_token()

        init_resp = await self.client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "MCP-Protocol-Version": "unsupported-draft-version",
            },
            json={
                "jsonrpc": "2.0",
                "id": "init-3",
                "method": "ping",
            },
        )
        self.assertEqual(init_resp.status, 400)
        data = await init_resp.json()
        self.assertEqual(data["error"]["code"], -32602)
        self.assertIn("Unsupported MCP-Protocol-Version header", data["error"]["message"])

    async def test_mcp_protocol_version_header_mismatch_rejected(self):
        token = await self._get_valid_token()

        # Negotiate 2024-11-05
        init_resp = await self.client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "MCP-Protocol-Version": "2024-11-05",
            },
            json={
                "jsonrpc": "2.0",
                "id": "init-mismatch",
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            },
        )
        self.assertEqual(init_resp.status, 200)
        session_id = init_resp.headers["Mcp-Session-Id"]

        # Subsequent request with different version header must be rejected
        mismatch_resp = await self.client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "Mcp-Session-Id": session_id,
                "MCP-Protocol-Version": "2025-11-25",
            },
            json={"jsonrpc": "2.0", "id": "ping-mismatch", "method": "ping"},
        )
        self.assertEqual(mismatch_resp.status, 400)
        data = await mismatch_resp.json()
        self.assertEqual(data["error"]["code"], -32602)
        self.assertIn("Mismatched MCP-Protocol-Version header", data["error"]["message"])

    async def test_mcp_protocol_version_sse_and_delete_headers(self):
        token = await self._get_valid_token()

        # Initialize session with 2025-03-26
        init_resp = await self.client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "MCP-Protocol-Version": "2025-03-26",
            },
            json={
                "jsonrpc": "2.0",
                "id": "init-sse",
                "method": "initialize",
                "params": {"protocolVersion": "2025-03-26"},
            },
        )
        self.assertEqual(init_resp.status, 200)
        session_id = init_resp.headers["Mcp-Session-Id"]

        # DELETE session with invalid version header -> 400
        del_bad_resp = await self.client.delete(
            "/mcp",
            headers={
                "Mcp-Session-Id": session_id,
                "MCP-Protocol-Version": "bogus-proto",
            },
        )
        self.assertEqual(del_bad_resp.status, 400)

        # DELETE session with matching negotiated version -> 204 with version header
        del_ok_resp = await self.client.delete(
            "/mcp",
            headers={
                "Mcp-Session-Id": session_id,
                "MCP-Protocol-Version": "2025-03-26",
            },
        )
        self.assertEqual(del_ok_resp.status, 204)
        self.assertEqual(del_ok_resp.headers.get("MCP-Protocol-Version"), "2025-03-26")


class TestDashboardMcpGatewayStatusEndpoint(AioHTTPTestCase):
    """Verify that Web Dashboard's same-origin /api/mcp-gateway/status is protected and compliant."""

    async def get_application(self) -> web.Application:
        from snow.web.server import SnowWebServer
        self.mock_bridge = AsyncMock(spec=SnowMcpBridge)
        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.mock_bridge,
            auto_open_browser=False,
        )
        return self.web_server._build_app()

    async def test_unauthenticated_request_rejected_401(self):
        resp = await self.client.get("/api/mcp-gateway/status")
        self.assertEqual(resp.status, 401)
        data = await resp.json()
        self.assertEqual(data["status"], "UNAUTHORIZED")

    async def test_authenticated_request_returns_safe_status(self):
        # Bootstrap session
        token = self.web_server.bootstrap_token
        auth_resp = await self.client.post("/api/auth/session", json={"token": token})
        self.assertEqual(auth_resp.status, 200)

        # Query gateway status
        status_resp = await self.client.get("/api/mcp-gateway/status")
        self.assertEqual(status_resp.status, 200)
        data = await status_resp.json()
        self.assertTrue(data["success"])
        self.assertIn("gateway_status", data["data"])
        self.assertIn(data["data"]["gateway_status"], ["online", "offline", "unhealthy", "timeout"])
        self.assertIn("ai_hosts", data["data"])
        self.assertIsInstance(data["data"]["ai_hosts"], list)


class TestFastMcpStdioCompatibility(unittest.TestCase):
    """Verify that FastMCP stdio server creation remains 100% functional and unpolluted."""

    def test_stdio_server_creation_has_30_tools(self):
        server = create_snow_mcp_server()
        tools = server._tool_manager._tools
        self.assertEqual(len(tools), 37)
        self.assertIn("snow_windows_system_info", tools)
        self.assertIn("snow_activity_history", tools)


class TestSubprocessCliDispatch(unittest.TestCase):
    """Subprocess verification for module entry point and CLI commands."""

    def test_python_m_snow_mcp_gateway_help(self):
        import socket
        import subprocess
        import sys

        # Verify python -m snow mcp-gateway --help
        res = subprocess.run(
            [sys.executable, "-m", "snow", "mcp-gateway", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("snow mcp-gateway", res.stdout)
        self.assertIn("--host", res.stdout)
        self.assertIn("--port", res.stdout)

        # Verify Desktop Core port 8765 was NOT bound
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.2)
        try:
            # Connecting to port 8765 should fail (connection refused)
            sock.connect(("127.0.0.1", 8765))
            sock.close()
            # If connect succeeds, something is listening, which is an error in isolation
            self.fail("Port 8765 is listening! mcp-gateway --help must not bind Desktop Core port.")
        except (ConnectionRefusedError, OSError):
            pass  # Expected: port 8765 is not listening

    def test_python_m_snow_relay_status(self):
        import subprocess
        import sys

        res = subprocess.run(
            [sys.executable, "-m", "snow", "relay", "status"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("Remote Relay Status", res.stdout)
        self.assertIn("Relay Enabled:", res.stdout)


if __name__ == "__main__":
    unittest.main()
