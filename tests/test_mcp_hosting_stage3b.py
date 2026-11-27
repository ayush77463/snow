"""Unit and Integration Tests for Phase 3 Stage 3B: Local and Remote AI MCP Hosting.

Covers:
1. Executable-aware canonical MCP command generation (packaged vs dev).
2. Host onboarding adapters non-destructive configuration with .bak backups.
3. TunnelManager port isolation, deadlock-free lifecycle, and drain reader.
4. OAuth 2.1 pending approval queue (1-click approve, reject, PKCE binding).
5. Web Dashboard local MCP stdio handshake verification (38 tools purity).
6. Web Dashboard tunnel live URL synchronization and OAuth discovery metadata.
7. OAuth security: removal of approval-ticket bypass, request-bound poll_token, single-read consumption.
8. Front-end integrity: Antigravity button, showNotificationToast availability, and JS syntax parsing.
"""

from __future__ import annotations

import asyncio
from collections import deque
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.mcp.tunnel import TunnelManager, ALLOWED_TUNNEL_PORT, CLOUDFLARED_URL_REGEX
from snow.mcp.oauth import OAuthServer
from snow.mcp.remote_gateway import RemoteMcpGateway
from snow.onboarding import (
    HostOnboardingManager,
    ClaudeAdapter,
    CursorAdapter,
    GeminiAdapter,
    AntigravityAdapter,
    ChatGPTAdapter,
    get_canonical_mcp_entry,
)
from snow.web.server import SnowWebServer
from snow.security.db import DatabaseManager


class TestMcpHostingStage3B(unittest.IsolatedAsyncioTestCase):
    """Test suite for Stage 3B Local and Remote MCP Hosting."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temp_dir.name)
        self.web_server = SnowWebServer(port=8789, auto_open_browser=False)

    async def asyncTearDown(self) -> None:
        await self.web_server.stop()
        self.temp_dir.cleanup()

    def test_01_canonical_mcp_entry_executable_aware(self) -> None:
        """Verify get_canonical_mcp_entry differentiates standalone binary from python module."""
        # Standalone binary
        entry_exe = get_canonical_mcp_entry(python_exe=r"C:\Program Files\SNOW\snow.exe")
        self.assertTrue(entry_exe["command"].endswith("snow.exe"))
        self.assertEqual(entry_exe["args"], ["mcp"])

        # Python interpreter
        entry_py = get_canonical_mcp_entry(python_exe=r"C:\Python313\python.exe")
        self.assertTrue(entry_py["command"].endswith("python.exe"))
        self.assertEqual(entry_py["args"], ["-m", "snow.mcp"])

    def test_02_host_adapters_non_destructive_merge_and_backup(self) -> None:
        """Verify host onboarding creates .bak backup and merges without overwriting siblings."""
        config_path = self.test_root / "test_mcp_config.json"
        # Seed existing config with a sibling server
        initial_data = {
            "mcpServers": {
                "existing_service": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-everything"],
                }
            },
            "userPreferences": {"theme": "dark"},
        }
        config_path.write_text(json.dumps(initial_data, indent=2), encoding="utf-8")

        adapter = ClaudeAdapter()
        # Configure SNOW
        res = adapter.configure(target_path=config_path, dry_run=False, python_exe="C:\\bin\\snow.exe")
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "CONFIGURED")
        self.assertIsNotNone(res["backup_path"])
        self.assertTrue(Path(res["backup_path"]).is_file())

        # Verify merge
        updated = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertIn("existing_service", updated["mcpServers"])
        self.assertIn("snow", updated["mcpServers"])
        self.assertEqual(updated["userPreferences"]["theme"], "dark")
        self.assertEqual(updated["mcpServers"]["snow"]["command"], "C:\\bin\\snow.exe")
        self.assertEqual(updated["mcpServers"]["snow"]["args"], ["mcp"])

        # Antigravity adapter verification
        antigravity_path = self.test_root / "antigravity_config.json"
        ag_adapter = AntigravityAdapter()
        ag_res = ag_adapter.configure(target_path=antigravity_path, dry_run=False, python_exe="C:\\bin\\snow.exe")
        self.assertTrue(ag_res["success"])
        self.assertEqual(ag_res["status"], "CONFIGURED")
        ag_data = json.loads(antigravity_path.read_text(encoding="utf-8"))
        self.assertIn("snow", ag_data["mcpServers"])

        # Remove SNOW
        rem_res = adapter.remove(target_path=config_path, dry_run=False)
        self.assertTrue(rem_res["success"])
        self.assertEqual(rem_res["status"], "REMOVED")

        post_rem = json.loads(config_path.read_text(encoding="utf-8"))
        self.assertNotIn("snow", post_rem["mcpServers"])
        self.assertIn("existing_service", post_rem["mcpServers"])

    async def test_03_tunnel_manager_port_restriction_and_deadlock_free_lifecycle(self) -> None:
        """Verify TunnelManager strictly restricts exposed ports and avoids lock deadlocks."""
        tm = TunnelManager(target_port=8771)

        # 1. Attempt to expose Web Dashboard (:8769 or :8770) -> Must be rejected
        res_bad_69 = await tm.start_tunnel(provider="cloudflared", port=8769)
        self.assertFalse(res_bad_69["success"])
        self.assertEqual(res_bad_69["status"], "PORT_RESTRICTED")

        res_bad_70 = await tm.start_tunnel(provider="cloudflared", port=8770)
        self.assertFalse(res_bad_70["success"])
        self.assertEqual(res_bad_70["status"], "PORT_RESTRICTED")

        # 2. Custom provider setup
        res_custom = await tm.start_tunnel(provider="custom", port=8771, custom_url="https://snow-remote.example.com")
        self.assertTrue(res_custom["success"])
        self.assertEqual(res_custom["public_url"], "https://snow-remote.example.com")
        self.assertEqual(res_custom["mcp_endpoint"], "https://snow-remote.example.com/mcp")

        stat = tm.get_status()
        self.assertTrue(stat["active"])
        self.assertEqual(stat["provider"], "custom")

        # 3. Replacing an active tunnel MUST NOT deadlock
        res_replace = await tm.start_tunnel(provider="custom", port=8771, custom_url="https://snow-replace.example.com")
        self.assertTrue(res_replace["success"])
        self.assertEqual(res_replace["public_url"], "https://snow-replace.example.com")

        # 4. Stop is idempotent and releases lock
        stop_res_1 = await tm.stop_tunnel()
        self.assertTrue(stop_res_1["success"])
        self.assertFalse(tm.get_status()["active"])

        stop_res_2 = await tm.stop_tunnel()
        self.assertTrue(stop_res_2["success"])

        # 5. Lock release upon startup timeout
        res_timeout = await tm.start_tunnel(provider="cloudflared", port=8771, timeout=0.01)
        self.assertFalse(res_timeout["success"])
        # Verify lock is freed
        self.assertFalse(tm._lock.locked())

    def test_04_oauth_pending_queue_approve_and_reject(self) -> None:
        """Verify RemoteMcpGateway pending authorization queue approve/reject workflow."""
        db = DatabaseManager(self.test_root / "test_oauth.db")
        mock_bridge = MagicMock()
        mock_bridge._get_secret.return_value = "test-secret"
        mock_bridge.capability_engine.db_manager = db
        gateway = RemoteMcpGateway(host="127.0.0.1", port=8771, bridge=mock_bridge)

        # Register dynamic client
        client_res = gateway.oauth_server.register_client(
            client_name="TestAssistant",
            redirect_uris=["https://ai.example.com/oauth/callback"],
        )
        client_id = client_res["client_id"]

        # Simulate incoming request in pending authorizations
        req_id = "test_req_1"
        gateway._pending_authorizations[req_id] = {
            "request_id": req_id,
            "poll_token": "poll_token_123",
            "client_id": client_id,
            "client_name": "TestAssistant",
            "redirect_uri": "https://ai.example.com/oauth/callback",
            "scope": "snow:mcp",
            "state": "state_123",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "created_at": time.time(),
            "expires_at": time.time() + 600.0,
            "status": "PENDING",
            "auth_code": None,
            "redirect_url": None,
        }

        # List pending
        pending = gateway.list_pending_authorizations()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["request_id"], req_id)
        # Ensure poll_token is NOT leaked in pending list
        self.assertNotIn("poll_token", pending[0])

        # Owner 1-click approve
        app_res = gateway.approve_authorization(req_id)
        self.assertTrue(app_res["success"])
        self.assertEqual(app_res["status"], "APPROVED")
        self.assertIsNotNone(app_res["code"])
        self.assertIn("code=", app_res["redirect_url"])

        # Attempt to approve again -> error (already approved)
        app_res_dup = gateway.approve_authorization(req_id)
        self.assertFalse(app_res_dup["success"])

        # Simulate second request and reject
        req_id_2 = "test_req_2"
        gateway._pending_authorizations[req_id_2] = {
            "request_id": req_id_2,
            "poll_token": "poll_token_456",
            "client_id": client_id,
            "client_name": "TestAssistant2",
            "redirect_uri": "https://ai.example.com/oauth/callback",
            "scope": "snow:mcp",
            "state": "state_456",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "created_at": time.time(),
            "expires_at": time.time() + 600.0,
            "status": "PENDING",
            "auth_code": None,
            "redirect_url": None,
        }
        rej_res = gateway.reject_authorization(req_id_2)
        self.assertTrue(rej_res["success"])
        self.assertEqual(rej_res["status"], "REJECTED")

    async def test_05_web_server_test_local_mcp_handshake(self) -> None:
        """Verify handle_api_mcp_test_local executes live stdio handshake and verifies 48 tools."""
        req = MagicMock()
        resp = await self.web_server.handle_api_mcp_test_local(req)
        self.assertEqual(resp.status, 200)

        data = json.loads(resp.text)
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "SUCCESS")
        self.assertEqual(data["tools_count"], 60)
        self.assertEqual(data["expected_count"], 60)
        self.assertIn("snow_windows_system_info", data["tools"])
        self.assertIn("snow_android_battery", data["tools"])
        self.assertGreater(data["latency_ms"], 0.0)

    async def test_06_web_server_tunnel_and_oauth_metadata_synchronization(self) -> None:
        """Verify WebServer tunnel start synchronizes RemoteMcpGateway public_url and OAuth discovery metadata."""
        db = DatabaseManager(self.test_root / "test_oauth.db")
        mock_bridge = MagicMock()
        mock_bridge._get_secret.return_value = "test-secret"
        mock_bridge.capability_engine.db_manager = db
        gateway = RemoteMcpGateway(host="127.0.0.1", port=8771, bridge=mock_bridge)
        self.web_server._mcp_gateway_instance = gateway
        mock_runner = AsyncMock()
        mock_runner.cleanup = AsyncMock()
        self.web_server._mcp_gateway_runner = mock_runner

        # 1. Start custom tunnel via web endpoint
        req_start = MagicMock()
        req_start.json = AsyncMock(return_value={"provider": "custom", "custom_url": "https://mcp-live.example.com"})
        resp_start = await self.web_server.handle_api_mcp_tunnel_start(req_start)
        self.assertEqual(resp_start.status, 200)
        data_start = json.loads(resp_start.text)
        self.assertTrue(data_start["success"])
        self.assertEqual(data_start["public_url"], "https://mcp-live.example.com")

        # 2. Verify gateway instance received the synchronized live URL
        self.assertEqual(gateway.public_url, "https://mcp-live.example.com")
        self.assertEqual(gateway.issuer, "https://mcp-live.example.com")

        # 3. Verify RFC 8414 metadata reflects live tunnel URL
        auth_meta = gateway.oauth_server.get_authorization_server_metadata()
        self.assertEqual(auth_meta["issuer"], "https://mcp-live.example.com")
        self.assertEqual(auth_meta["authorization_endpoint"], "https://mcp-live.example.com/oauth/authorize")

        prot_meta = gateway.oauth_server.get_protected_resource_metadata()
        self.assertEqual(prot_meta["resource"], "https://mcp-live.example.com/mcp")
        self.assertIn("https://mcp-live.example.com", prot_meta["authorization_servers"])

        # 4. Stop tunnel and verify public URL clears
        req_stop = MagicMock()
        resp_stop = await self.web_server.handle_api_mcp_tunnel_stop(req_stop)
        self.assertEqual(resp_stop.status, 200)
        self.assertIsNone(gateway.public_url)
        self.assertEqual(gateway.issuer, "http://127.0.0.1:8771")

        # 5. Metadata reverts to loopback after tunnel teardown
        revert_meta = gateway.oauth_server.get_authorization_server_metadata()
        self.assertEqual(revert_meta["issuer"], "http://127.0.0.1:8771")

    async def test_07_oauth_security_and_polling_protection(self) -> None:
        """Verify removal of approval-ticket bypass, request-bound poll_token, and atomic single-read."""
        db = DatabaseManager(self.test_root / "test_oauth_sec.db")
        mock_bridge = MagicMock()
        mock_bridge._get_secret.return_value = "super-secret"
        mock_bridge.capability_engine.db_manager = db
        gateway = RemoteMcpGateway(host="127.0.0.1", port=8771, bridge=mock_bridge)

        # 1. Register client and create pending authorization
        client_res = gateway.oauth_server.register_client(
            client_name="SecurityTestClient",
            redirect_uris=["https://client.example.com/cb"],
        )
        client_id = client_res["client_id"]
        req_id = "sec_req_1"
        poll_tok = secrets.token_urlsafe(32)
        gateway._pending_authorizations[req_id] = {
            "request_id": req_id,
            "poll_token": poll_tok,
            "client_id": client_id,
            "client_name": "SecurityTestClient",
            "redirect_uri": "https://client.example.com/cb",
            "scope": "snow:mcp",
            "state": "st_999",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "code_challenge_method": "S256",
            "created_at": time.time(),
            "expires_at": time.time() + 600.0,
            "status": "PENDING",
            "auth_code": None,
            "redirect_url": None,
        }

        # 2. Prove approved ticket CANNOT bypass owner authentication
        gateway.approve_authorization(req_id)
        mock_req = MagicMock()
        mock_req.headers = {}
        # Replaying request_id or approval_ticket must return False
        self.assertFalse(gateway._is_owner_authenticated(mock_req, {"approval_ticket": req_id}))
        self.assertFalse(gateway._is_owner_authenticated(mock_req, {"request_id": req_id}))

        # 3. Status polling requires poll_token
        req_no_tok = MagicMock()
        req_no_tok.query = {"request_id": req_id}
        res_no_tok = await gateway.handle_oauth_status(req_no_tok)
        self.assertEqual(res_no_tok.status, 400)

        # Wrong token rejected with 404
        req_bad_tok = MagicMock()
        req_bad_tok.query = {"request_id": req_id, "poll_token": "wrong-token-1234"}
        res_bad_tok = await gateway.handle_oauth_status(req_bad_tok)
        self.assertEqual(res_bad_tok.status, 404)

        # 4. Atomic Single-Read: First poll with valid poll_token retrieves result
        req_ok_poll = MagicMock()
        req_ok_poll.query = {"request_id": req_id, "poll_token": poll_tok}
        res_first = await gateway.handle_oauth_status(req_ok_poll)
        self.assertEqual(res_first.status, 200)
        data_first = json.loads(res_first.text)
        self.assertEqual(data_first["status"], "APPROVED")
        self.assertIsNotNone(data_first["code"])
        self.assertIsNotNone(data_first["redirect_url"])

        # Second poll must NOT return the code or redirect_url (returns 410 CONSUMED)
        res_second = await gateway.handle_oauth_status(req_ok_poll)
        self.assertEqual(res_second.status, 410)
        data_second = json.loads(res_second.text)
        self.assertEqual(data_second["status"], "CONSUMED")
        self.assertNotIn("code", data_second)
        self.assertNotIn("redirect_url", data_second)

        # 5. Pending authorization queue limit (capped at 50)
        for i in range(50):
            gateway._pending_authorizations[f"filler_req_{i}"] = {
                "request_id": f"filler_req_{i}",
                "poll_token": f"tok_{i}",
                "expires_at": time.time() + 600.0,
                "status": "PENDING",
            }

        # Attempting 51st GET authorize must return 429
        req_auth = MagicMock()
        req_auth.method = "GET"
        req_auth.query = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": "https://client.example.com/cb",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        }
        res_overflow = await gateway.handle_oauth_authorize(req_auth)
        self.assertEqual(res_overflow.status, 429)

    def test_08_js_and_html_integrity(self) -> None:
        """Verify Antigravity button presence, showNotificationToast availability, and JS delimiter balance."""
        html_path = Path("src/snow/web/static/index.html")
        js_path = Path("src/snow/web/static/app.js")

        self.assertTrue(html_path.is_file())
        self.assertTrue(js_path.is_file())

        html_text = html_path.read_text(encoding="utf-8")
        js_text = js_path.read_text(encoding="utf-8")

        # 1. Antigravity button and siblings in index.html
        self.assertIn('id="btn-setup-antigravity"', html_text)
        self.assertIn('id="btn-setup-claude"', html_text)
        self.assertIn('id="btn-setup-cursor"', html_text)
        self.assertIn('id="btn-setup-gemini"', html_text)

        # 2. Host setup in app.js includes antigravity
        self.assertIn('"antigravity"', js_text)

        # 3. showNotificationToast is defined and zero undefined showNotification calls exist
        self.assertIn("function showNotificationToast(", js_text)
        # Search for exact undefined call: showNotification(
        stray_calls = re.findall(r"(?<!\bshowNotificationToast)\bshowNotification\(", js_text)
        self.assertEqual(len(stray_calls), 0, f"Found undefined showNotification calls: {stray_calls}")

        # 4. Rigorous JavaScript delimiter and bracket validation
        idx = 0
        n = len(js_text)
        stack: list[tuple[str, int]] = []
        last_token_char = ''

        while idx < n:
            ch = js_text[idx]

            # 1. Comments
            if ch == '/' and idx + 1 < n and js_text[idx+1] == '/':
                idx = js_text.find('\n', idx)
                if idx == -1:
                    break
                continue
            if ch == '/' and idx + 1 < n and js_text[idx+1] == '*':
                end_idx = js_text.find('*/', idx + 2)
                self.assertTrue(end_idx != -1, "Unclosed block comment in app.js")
                idx = end_idx + 2
                continue

            # 2. Regular Expression literal vs division
            if ch == '/' and last_token_char in '(=:[!&|?{;,':
                idx += 1
                while idx < n:
                    if js_text[idx] == '\\':
                        idx += 2
                    elif js_text[idx] == '/':
                        idx += 1
                        while idx < n and js_text[idx].isalpha():
                            idx += 1
                        break
                    elif js_text[idx] == '\n':
                        break
                    else:
                        idx += 1
                continue

            # 3. Single / Double strings
            if ch in ("'", '"'):
                quote = ch
                idx += 1
                while idx < n:
                    if js_text[idx] == '\\':
                        idx += 2
                    elif js_text[idx] == quote:
                        idx += 1
                        break
                    elif js_text[idx] == '\n':
                        break
                    else:
                        idx += 1
                last_token_char = quote
                continue

            # 4. Template literals
            if ch == '`':
                idx += 1
                while idx < n:
                    if js_text[idx] == '\\':
                        idx += 2
                    elif js_text[idx] == '`':
                        idx += 1
                        break
                    elif js_text[idx:idx+2] == '${':
                        stack.append(('${', idx))
                        idx += 2
                        break
                    else:
                        idx += 1
                continue

            # 5. Delimiters
            if ch in '({[':
                stack.append((ch, idx))
                last_token_char = ch
            elif ch in ')}]':
                self.assertTrue(len(stack) > 0, f"Unmatched closing '{ch}' at index {idx}")
                top, top_idx = stack.pop()
                if top == '${':
                    self.assertEqual(ch, '}', f"Mismatched closing '{ch}' for '${{' at index {top_idx}")
                    while idx + 1 < n:
                        idx += 1
                        if js_text[idx] == '\\':
                            idx += 1
                        elif js_text[idx] == '`':
                            break
                        elif js_text[idx:idx+2] == '${':
                            stack.append(('${', idx))
                            idx += 1
                            break
                else:
                    expected = {'(': ')', '{': '}', '[': ']'}[top]
                    self.assertEqual(ch, expected, f"Mismatched closing '{ch}' for '{top}' opened at index {top_idx}")
                last_token_char = ch
            elif not ch.isspace():
                last_token_char = ch

            idx += 1

        self.assertEqual(len(stack), 0, f"Unclosed delimiters remaining in app.js: {stack}")


if __name__ == "__main__":
    unittest.main()
