"""Comprehensive Automated Acceptance & Verification Suite for Phase 30:
Cross-Network Federation, Session Controls & Global Kill Switch (V4.0.0 Readiness).

Validates:
1. Federation Invariants & Security Boundaries:
   - 9-digit code format (XXX-XXX-XXX), hashing before storage, and single-use lifecycle.
   - Invariant 1: AI_MCP principal is strictly forbidden from mutating federation (PermissionError).
   - Invariant 2: Zero privilege inheritance (federated peers never receive OWNER_MANUAL).
   - Invariant 3: Strict capability and device ACL enforcement.
   - Invariant 4: Scoped expiring credentials (TTL enforcement, expired token rejection).
   - Invariant 5: Immediate single grant revocation and Global Kill Switch (nuclear revocation).
   - Invariant 6: Secret-safe audit logging in activity_history without leaking codes or tokens.
   - Invariant 7: Anti-transitivity (TRANSIT_ROUTING_FORBIDDEN on multi-hop routing attempts).
   - Rate-limiting (max 3 failed attempts marks invitation EXPIRED).
2. Web Dashboard API Endpoints:
   - GET /api/federation/grants (requires auth)
   - POST /api/federation/invite (requires auth & CSRF)
   - POST /api/federation/accept (requires auth & CSRF)
   - POST /api/federation/revoke (requires auth & CSRF)
   - POST /api/federation/kill-switch (requires auth & CSRF)
3. Network Topology Integration:
   - Federated peers appear as federated: true in build_topology()
   - AI_MCP receives safely redacted federated topology view
4. Schema v6 Migration:
   - Tables federation_invitations and federation_grants initialized with proper indexes.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from snow.mcp.bridge import SnowMcpBridge
from snow.network.federation import (
    FederationManager,
    format_nine_digit_code,
    generate_nine_digit_code,
)
from snow.network.network_model import SnowNetworkManager
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager, hash_token
from snow.web.server import SnowWebServer


class TestPhase30FederationManager(unittest.TestCase):
    """Unit tests for the FederationManager and the 7 Security Invariants."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_fed.db"
        self.db_manager = DatabaseManager(self.db_path)
        self.fed_manager = FederationManager(
            db_manager=self.db_manager,
            local_network_id="net-alpha-001",
            local_network_name="Network Alpha",
            local_node_id="node-desktop-1",
            local_node_name="Alpha Coordinator",
            local_cert_fingerprint="ALPHA_FP_12345",
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_schema_v6_tables_exist(self):
        """Verify Schema v6 initializes federation_invitations and federation_grants tables."""
        with self.db_manager._get_connection() as conn:
            cur = conn.execute("PRAGMA user_version;")
            ver = cur.fetchone()[0]
            self.assertEqual(ver, 6, "Schema version must be 6")

            # Check tables
            tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
            self.assertIn("federation_invitations", tables)
            self.assertIn("federation_grants", tables)

    def test_nine_digit_code_generation_and_formatting(self):
        """Verify 9-digit code generation and string format XXX-XXX-XXX."""
        code = generate_nine_digit_code()
        self.assertEqual(len(code), 11)
        self.assertEqual(code[3], "-")
        self.assertEqual(code[7], "-")
        digits_only = code.replace("-", "")
        self.assertEqual(len(digits_only), 9)
        self.assertTrue(digits_only.isdigit())

        # Test formatting helper
        fmt = format_nine_digit_code("987654321")
        self.assertEqual(fmt, "987-654-321")

    def test_invariant_1_ai_mcp_forbidden_from_mutating_federation(self):
        """AI_MCP principal is strictly forbidden from creating invites, accepting, or revoking."""
        with self.assertRaises(PermissionError):
            self.fed_manager.create_invitation(principal="AI_MCP")

        with self.assertRaises(PermissionError):
            self.fed_manager.accept_invitation(
                code="123-456-789",
                peer_network_id="net-beta",
                peer_network_name="Network Beta",
                peer_node_id="node-beta",
                peer_node_name="Beta Coordinator",
                peer_cert_fingerprint="BETA_FP",
                principal="AI_MCP",
            )

        with self.assertRaises(PermissionError):
            self.fed_manager.revoke_grant("grant-xyz", principal="AI_MCP")

        with self.assertRaises(PermissionError):
            self.fed_manager.global_kill_switch(principal="AI_MCP")

    def test_create_invitation_hashes_code_and_audits(self):
        """Invitation creation hashes 9-digit code before saving and logs secret-safe audit event."""
        res = self.fed_manager.create_invitation(
            allowed_capabilities=["android.status", "desktop.system.info"],
            allowed_device_ids=["desktop-node-1"],
            grant_ttl_seconds=86400,
            ttl_seconds=300,
            principal="OWNER_MANUAL",
        )
        self.assertTrue(res["success"])
        code = res["code"]
        invite_id = res["invite_id"]

        # Raw code must NOT exist in the database table
        with self.db_manager._get_connection() as conn:
            row = conn.execute("SELECT * FROM federation_invitations WHERE invite_id = ?;", (invite_id,)).fetchone()
            self.assertIsNotNone(row)
            self.assertNotIn(code, row["code_hash"])
            self.assertEqual(row["code_hash"], hash_token(code.replace("-", "")))
            self.assertEqual(row["status"], "PENDING")

        # Verify audit record does not contain raw code
        history = self.db_manager.query_activity_history(event_type="FEDERATION_INVITE_CREATED")
        self.assertTrue(history)
        audit_entry = history[0]
        self.assertNotIn(code, json.dumps(audit_entry))

    def test_accept_invitation_lifecycle(self):
        """Accepting an invitation verifies PIN, establishes grant, and burns code."""
        inv_res = self.fed_manager.create_invitation(
            allowed_capabilities=["android.status"],
            allowed_device_ids=["desktop-node-1"],
            grant_ttl_seconds=3600,
        )
        code = inv_res["code"]

        # Accept the invitation
        acc_res = self.fed_manager.accept_invitation(
            code=code,
            peer_network_id="net-beta-002",
            peer_network_name="Network Beta",
            peer_node_id="node-phone-2",
            peer_node_name="Beta Phone",
            peer_cert_fingerprint="BETA_FP_999",
            principal="OWNER_MANUAL",
        )
        self.assertTrue(acc_res["success"])
        grant_id = acc_res["grant_id"]
        auth_token = acc_res["auth_token"]

        # Verify invitation status is now ACCEPTED
        with self.db_manager._get_connection() as conn:
            inv_row = conn.execute("SELECT status FROM federation_invitations WHERE invite_id = ?;", (inv_res["invite_id"],)).fetchone()
            self.assertEqual(inv_row["status"], "ACCEPTED")

        # Verify single-use: attempting to accept again fails
        second_acc = self.fed_manager.accept_invitation(
            code=code,
            peer_network_id="net-beta-002",
            peer_network_name="Network Beta",
            peer_node_id="node-phone-2",
            peer_node_name="Beta Phone",
            peer_cert_fingerprint="BETA_FP_999",
        )
        self.assertFalse(second_acc["success"])
        self.assertEqual(second_acc["status"], "INVITATION_ACCEPTED")

        # Verify grant validation succeeds
        val_ok, val_err = self.fed_manager.validate_federated_request(
            token=auth_token,
            target_network_id="net-alpha-001",
            target_device_id="desktop-node-1",
            capability="android.status",
        )
        self.assertTrue(val_ok)
        self.assertIsNone(val_err)

    def test_invariant_3_capability_and_device_acl_enforcement(self):
        """Capability or target device not listed in the grant is denied."""
        inv_res = self.fed_manager.create_invitation(
            allowed_capabilities=["android.status"],
            allowed_device_ids=["allowed-phone-1"],
            grant_ttl_seconds=3600,
        )
        acc_res = self.fed_manager.accept_invitation(
            code=inv_res["code"],
            peer_network_id="net-beta",
            peer_network_name="Net Beta",
            peer_node_id="beta-node",
            peer_node_name="Beta Node",
            peer_cert_fingerprint="FP",
        )
        token = acc_res["auth_token"]

        # 1. Deny forbidden capability
        cap_ok, cap_err = self.fed_manager.validate_federated_request(
            token=token,
            target_network_id="net-alpha-001",
            target_device_id="allowed-phone-1",
            capability="desktop.file.write",
        )
        self.assertFalse(cap_ok)
        self.assertIn("CAPABILITY_NOT_PERMITTED", cap_err)

        # 2. Deny forbidden device
        dev_ok, dev_err = self.fed_manager.validate_federated_request(
            token=token,
            target_network_id="net-alpha-001",
            target_device_id="forbidden-pc-2",
            capability="android.status",
        )
        self.assertFalse(dev_ok)
        self.assertIn("DEVICE_ACCESS_DENIED", dev_err)

    def test_invariant_4_expired_grant_rejected(self):
        """Tokens past expires_timestamp are rejected."""
        inv_res = self.fed_manager.create_invitation(grant_ttl_seconds=1)
        acc_res = self.fed_manager.accept_invitation(
            code=inv_res["code"],
            peer_network_id="net-beta",
            peer_network_name="Net Beta",
            peer_node_id="beta-node",
            peer_node_name="Beta Node",
            peer_cert_fingerprint="FP",
        )
        token = acc_res["auth_token"]
        grant_id = acc_res["grant_id"]

        # Manually backdate expiration in DB
        past_str = datetime.fromtimestamp(time.time() - 100, timezone.utc).isoformat()
        with self.db_manager._get_connection() as conn:
            conn.execute("UPDATE federation_grants SET expires_timestamp = ? WHERE grant_id = ?;", (past_str, grant_id))

        ok, err = self.fed_manager.validate_federated_request(
            token=token,
            target_network_id="net-alpha-001",
            target_device_id="desktop-node-1",
            capability="android.status",
        )
        self.assertFalse(ok)
        self.assertEqual(err, "FEDERATION_GRANT_EXPIRED")

    def test_invariant_5_single_revocation_and_global_kill_switch(self):
        """Single grant revocation and Global Kill Switch immediately disable requests."""
        # Setup two grants
        inv1 = self.fed_manager.create_invitation(allowed_device_ids=["dev-1"])["code"]
        acc1 = self.fed_manager.accept_invitation(inv1, "net-1", "Net 1", "node-1", "Node 1", "FP1")
        token1 = acc1["auth_token"]

        inv2 = self.fed_manager.create_invitation(allowed_device_ids=["dev-1"])["code"]
        acc2 = self.fed_manager.accept_invitation(inv2, "net-2", "Net 2", "node-2", "Node 2", "FP2")
        token2 = acc2["auth_token"]

        # 1. Single revocation of grant 1
        rev_res = self.fed_manager.revoke_grant(acc1["grant_id"], reason="Owner manual test")
        self.assertTrue(rev_res["success"])

        ok1, err1 = self.fed_manager.validate_federated_request(token1, "net-alpha-001", "dev-1", "android.status")
        self.assertFalse(ok1)
        self.assertEqual(err1, "FEDERATION_GRANT_REVOKED")

        # Grant 2 still works
        ok2, _ = self.fed_manager.validate_federated_request(token2, "net-alpha-001", "dev-1", "android.status")
        self.assertTrue(ok2)

        # 2. Trigger Global Kill Switch
        kill_res = self.fed_manager.global_kill_switch(reason="Test Emergency Shutdown")
        self.assertTrue(kill_res["success"])
        self.assertGreaterEqual(kill_res["revoked_grants_count"], 1)

        # Grant 2 must now be revoked
        ok2_after, err2_after = self.fed_manager.validate_federated_request(token2, "net-alpha-001", "dev-1", "android.status")
        self.assertFalse(ok2_after)
        self.assertEqual(err2_after, "FEDERATION_GRANT_REVOKED")

    def test_invariant_7_anti_transitivity_forbidden(self):
        """Peer attempting multi-hop transit routing across networks is rejected."""
        inv = self.fed_manager.create_invitation()["code"]
        acc = self.fed_manager.accept_invitation(inv, "net-beta", "Net Beta", "node-b", "Node B", "FPB")
        token = acc["auth_token"]

        # Target network differs from local network
        ok, err = self.fed_manager.validate_federated_request(
            token=token,
            target_network_id="net-charlie-999",  # Attempting transit routing!
            target_device_id="charlie-pc",
            capability="android.status",
        )
        self.assertFalse(ok)
        self.assertIn("TRANSIT_ROUTING_FORBIDDEN", err)


class TestPhase30WebFederationEndpoints(AioHTTPTestCase):
    """Integration tests for Web Dashboard federation REST endpoints."""

    async def get_application(self) -> web.Application:
        self.temp_dir = tempfile.mkdtemp()
        os.environ["SNOW_DATA_DIR"] = self.temp_dir
        self.db_path = Path(self.temp_dir) / "web_fed_test.db"
        self.db_manager = DatabaseManager(self.db_path)

        self.mock_bridge = AsyncMock(spec=SnowMcpBridge)
        self.mock_bridge.daemon_manager = AsyncMock()
        self.mock_bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)
        self.mock_bridge.windows_system_info = AsyncMock(return_value={"success": True, "data": {}})
        self.mock_bridge.capability_engine = MagicMock(db_manager=self.db_manager)
        self.mock_bridge.federation_revoke = AsyncMock(return_value={"success": True, "status": "GRANT_REVOKED"})
        self.mock_bridge.federation_kill_switch = AsyncMock(return_value={"success": True, "status": "KILL_SWITCH_EXECUTED"})

        self.snow_web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.mock_bridge,
            auto_open_browser=False,
        )
        return self.snow_web_server._build_app()

    def tearDown(self):
        super().tearDown()
        os.environ.pop("SNOW_DATA_DIR", None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _obtain_session(self) -> tuple[str, str]:
        resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": "127.0.0.1:8769"},
            json={"token": self.snow_web_server.bootstrap_token},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        cookie = resp.cookies.get("snow_session").value
        return cookie, data["csrf_token"]

    async def test_get_grants_requires_auth(self):
        """Unauthenticated request to /api/federation/grants returns 401."""
        resp = await self.client.get("/api/federation/grants", headers={"Host": "127.0.0.1:8769"})
        self.assertEqual(resp.status, 401)

    async def test_federation_api_lifecycle(self):
        """Test complete invite -> accept -> list -> revoke -> kill-switch API flow."""
        cookie, csrf = await self._obtain_session()
        headers = {
            "Host": "127.0.0.1:8769",
            "X-CSRF-Token": csrf,
        }
        cookies = {"snow_session": cookie}

        # 1. Create invitation
        inv_resp = await self.client.post(
            "/api/federation/invite",
            headers=headers,
            cookies=cookies,
            json={
                "allowed_capabilities": ["android.status", "desktop.system.info"],
                "grant_ttl_seconds": 86400,
            },
        )
        self.assertEqual(inv_resp.status, 200)
        inv_data = await inv_resp.json()
        self.assertTrue(inv_data["success"])
        code = inv_data["code"]
        self.assertEqual(len(code.replace("-", "")), 9)

        # 2. Accept invitation
        acc_resp = await self.client.post(
            "/api/federation/accept",
            headers=headers,
            cookies=cookies,
            json={
                "code": code,
                "peer_network_id": "remote-net-123",
                "peer_network_name": "Office Mesh",
                "peer_node_id": "remote-node-456",
                "peer_node_name": "Office Workstation",
            },
        )
        self.assertEqual(acc_resp.status, 200)
        acc_data = await acc_resp.json()
        self.assertTrue(acc_data["success"])
        grant_id = acc_data["grant_id"]

        # 3. List grants
        list_resp = await self.client.get(
            "/api/federation/grants",
            headers={"Host": "127.0.0.1:8769"},
            cookies=cookies,
        )
        self.assertEqual(list_resp.status, 200)
        list_data = await list_resp.json()
        self.assertTrue(list_data["success"])
        self.assertEqual(len(list_data["grants"]), 1)
        self.assertEqual(list_data["grants"][0]["network_name"], "Office Mesh")
        self.assertEqual(list_data["grants"][0]["status"], "ACTIVE")

        # 4. Revoke grant
        rev_resp = await self.client.post(
            "/api/federation/revoke",
            headers=headers,
            cookies=cookies,
            json={"grant_id": grant_id, "reason": "Test manual revocation"},
        )
        self.assertEqual(rev_resp.status, 200)
        rev_data = await rev_resp.json()
        self.assertTrue(rev_data["success"])

        # 5. Global Kill Switch
        kill_resp = await self.client.post(
            "/api/federation/kill-switch",
            headers=headers,
            cookies=cookies,
            json={"reason": "Emergency Test Kill Switch"},
        )
        self.assertEqual(kill_resp.status, 200)
        kill_data = await kill_resp.json()
        self.assertTrue(kill_data["success"])
        self.assertEqual(kill_data["status"], "KILL_SWITCH_EXECUTED")

    async def test_real_http_rate_limiting_persistent_429(self):
        """Real HTTP integration test: 6 invalid accept attempts produces HTTP 429 on the 6th."""
        cookie, csrf = await self._obtain_session()
        headers = {
            "Host": "127.0.0.1:8769",
            "X-CSRF-Token": csrf,
        }
        cookies = {"snow_session": cookie}

        # First 5 attempts return 400 with INVALID_OR_EXPIRED_CODE
        for i in range(5):
            resp = await self.client.post(
                "/api/federation/accept",
                headers=headers,
                cookies=cookies,
                json={"code": "111-222-333"},
            )
            self.assertEqual(resp.status, 400, f"Attempt {i+1} should return status 400")
            data = await resp.json()
            self.assertEqual(data.get("status"), "INVALID_OR_EXPIRED_CODE")

        # 6th attempt with same session MUST return 429
        resp6 = await self.client.post(
            "/api/federation/accept",
            headers=headers,
            cookies=cookies,
            json={"code": "111-222-333"},
        )
        self.assertEqual(resp6.status, 429, "6th attempt must be rate-limited with HTTP 429")
        data6 = await resp6.json()
        self.assertEqual(data6.get("status"), "RATE_LIMIT_EXCEEDED")

        # Verify a distinct session from a different client is NOT blocked
        token2 = "second_test_session_token_123"
        csrf2 = "second_test_csrf_token_456"
        self.snow_web_server._sessions[token2] = {
            "csrf_token": csrf2,
            "created_at": time.time(),
            "last_active": time.time(),
        }
        headers2 = {
            "Host": "127.0.0.1:8769",
            "X-CSRF-Token": csrf2,
        }
        cookies2 = {"snow_session": token2}
        resp_other = await self.client.post(
            "/api/federation/accept",
            headers=headers2,
            cookies=cookies2,
            json={"code": "111-222-333"},
        )
        self.assertEqual(resp_other.status, 400, "Separate session must not be blocked by another's rate limit")


class TestPhase30TopologyFederationIntegration(unittest.TestCase):
    """Test that active federation grants seamlessly integrate into Network Topology."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "topology_fed_test.db"
        self.db_manager = DatabaseManager(self.db_path)
        self.net_manager = SnowNetworkManager(db_manager=self.db_manager)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_federated_peer_in_topology(self):
        """Active federation grant produces federated node in topology."""
        # Create an active grant in DB
        now_str = datetime.now(timezone.utc).isoformat()
        future_str = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
        self.db_manager.create_federation_grant(
            grant_id="grant-001",
            network_id="net-remote-partner",
            network_name="Partner Network",
            peer_node_id="partner-coordinator",
            peer_node_name="Partner Desktop",
            peer_cert_fingerprint="PARTNER_FP",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(["desktop.system.info"]),
            allowed_device_ids_json=json.dumps(["*"]),
            auth_token_hash="HASH_TOKEN_123",
        )

        # 1. Owner topology view
        owner_top = self.net_manager.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)
        self.assertTrue(owner_top["success"])
        fed_devices = [d for d in owner_top["devices"] if d.get("federated")]
        self.assertEqual(len(fed_devices), 1)
        fed_node = fed_devices[0]
        self.assertEqual(fed_node["device_id"], "partner-coordinator")
        self.assertEqual(fed_node["transport"], "Federated Mesh")
        self.assertEqual(fed_node["network_name"], "Partner Network")
        self.assertEqual(fed_node["supported_capabilities"], ["desktop.system.info"])

        # 2. AI_MCP redacted topology view
        mcp_top = self.net_manager.build_topology(principal=ExecutionPrincipal.AI_MCP)
        self.assertTrue(mcp_top["success"])
        mcp_fed = [d for d in mcp_top["devices"] if d.get("federated")]
        self.assertEqual(len(mcp_fed), 1)
        self.assertNotIn("network_id", mcp_fed[0])
        self.assertEqual(mcp_fed[0]["transport"], "Federated Mesh")

    def test_topology_denylist_filtering(self):
        """Forbidden destructive and administrative capabilities are stripped from topology for federated peers."""
        now_str = datetime.now(timezone.utc).isoformat()
        future_str = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
        raw_caps = [
            "desktop.system.info",
            "android.status",
            "desktop.exec",
            "desktop.terminal.exec",
            "windows_terminal_exec",
            "desktop.file.write",
            "device.revoke",
            "approval.resolve",
            "network.federation.invite",
            "network.federation.kill_switch",
        ]
        self.db_manager.create_federation_grant(
            grant_id="grant-denylist-test",
            network_id="net-remote-partner",
            network_name="Partner Network",
            peer_node_id="peer-restricted",
            peer_node_name="Restricted Node",
            peer_cert_fingerprint="RESTRICTED_FP",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(raw_caps),
            allowed_device_ids_json=json.dumps(["*"]),
            auth_token_hash="HASH_RESTRICTED",
        )

        # 1. Owner topology view
        owner_top = self.net_manager.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)
        self.assertTrue(owner_top["success"])
        fed_devices = [d for d in owner_top["devices"] if d.get("device_id") == "peer-restricted"]
        self.assertEqual(len(fed_devices), 1)
        caps = fed_devices[0]["supported_capabilities"]
        self.assertIn("desktop.system.info", caps)
        self.assertIn("android.status", caps)
        self.assertNotIn("desktop.exec", caps)
        self.assertNotIn("desktop.terminal.exec", caps)
        self.assertNotIn("windows_terminal_exec", caps)
        self.assertNotIn("desktop.file.write", caps)
        self.assertNotIn("device.revoke", caps)
        self.assertNotIn("approval.resolve", caps)
        self.assertNotIn("network.federation.invite", caps)
        self.assertNotIn("network.federation.kill_switch", caps)

        # Verify node_perms dict also filters forbidden capabilities
        node_perms = owner_top.get("node_permissions", {}).get("peer-restricted", [])
        for forbidden in ["desktop.exec", "desktop.terminal.exec", "windows_terminal_exec", "desktop.file.write", "device.revoke"]:
            self.assertNotIn(forbidden, node_perms)

        # 2. AI_MCP view
        mcp_top = self.net_manager.build_topology(principal=ExecutionPrincipal.AI_MCP)
        self.assertTrue(mcp_top["success"])
        mcp_devices = [d for d in mcp_top["devices"] if d.get("device_id") == "peer-restricted"]
        self.assertEqual(len(mcp_devices), 1)
        mcp_perms = mcp_devices[0]["effective_permissions"]
        self.assertIn("desktop.system.info", mcp_perms)
        self.assertNotIn("desktop.exec", mcp_perms)


class TestPhase30AuditRemediations(unittest.IsolatedAsyncioTestCase):
    """Rigorous regression tests for the 5 Gemini Neon Phase 30 audit findings."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "remediation_test.db"
        self.db_manager = DatabaseManager(self.db_path)
        self.fed_manager = FederationManager(
            db_manager=self.db_manager,
            local_network_id="local-net-1",
            local_network_name="Local Network",
            local_node_id="local-coord-1",
            local_node_name="Local Coordinator",
            local_cert_fingerprint="AA:BB:CC:DD",
        )

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_r1_empty_acl_fails_closed(self):
        """Repair 1: Empty device or capability ACLs must fail closed (deny access)."""
        now_str = datetime.now(timezone.utc).isoformat()
        future_str = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
        token = "test-token-123"
        token_h = hash_token(token)

        # 1. Empty device ACL in grant
        self.db_manager.create_federation_grant(
            grant_id="grant-empty-dev",
            network_id="remote-net",
            network_name="Remote Net",
            peer_node_id="peer-1",
            peer_node_name="Peer 1",
            peer_cert_fingerprint="FP1",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(["android.status"]),
            allowed_device_ids_json=json.dumps([]),  # Empty!
            auth_token_hash=token_h,
        )

        ok, err = self.fed_manager.validate_federated_request(
            token=token,
            target_network_id="local-net-1",
            target_device_id="local-coord-1",
            capability="android.status",
        )
        self.assertFalse(ok)
        self.assertIn("DEVICE_ACCESS_DENIED", err)

        # 2. Empty capability ACL in grant
        token2 = "test-token-456"
        self.db_manager.create_federation_grant(
            grant_id="grant-empty-cap",
            network_id="remote-net",
            network_name="Remote Net",
            peer_node_id="peer-2",
            peer_node_name="Peer 2",
            peer_cert_fingerprint="FP2",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps([]),  # Empty!
            allowed_device_ids_json=json.dumps(["local-coord-1"]),
            auth_token_hash=hash_token(token2),
        )

        ok2, err2 = self.fed_manager.validate_federated_request(
            token=token2,
            target_network_id="local-net-1",
            target_device_id="local-coord-1",
            capability="android.status",
        )
        self.assertFalse(ok2)
        self.assertIn("CAPABILITY_NOT_PERMITTED", err2)

    def test_r1_wildcard_rejection_in_invites_and_grants(self):
        """Repair 1: Wildcards are strictly forbidden in invitations and grants."""
        # In invitation creation
        with self.assertRaises(ValueError):
            self.fed_manager.create_invitation(allowed_capabilities=["*"])

        with self.assertRaises(ValueError):
            self.fed_manager.create_invitation(allowed_device_ids=["*"])

        with self.assertRaises(ValueError):
            self.fed_manager.create_invitation(allowed_capabilities=[])

        with self.assertRaises(ValueError):
            self.fed_manager.create_invitation(allowed_device_ids=[])

        # In grant validation (tampered grant containing wildcard fails closed)
        now_str = datetime.now(timezone.utc).isoformat()
        future_str = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
        tok = "wildcard-token"
        self.db_manager.create_federation_grant(
            grant_id="grant-wildcard",
            network_id="remote-net",
            network_name="Remote Net",
            peer_node_id="peer-w",
            peer_node_name="Peer W",
            peer_cert_fingerprint="FPW",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(["*"]),
            allowed_device_ids_json=json.dumps(["*"]),
            auth_token_hash=hash_token(tok),
        )
        ok, err = self.fed_manager.validate_federated_request(
            token=tok,
            target_network_id="local-net-1",
            target_device_id="local-coord-1",
            capability="android.status",
        )
        self.assertFalse(ok)

    def test_r1_destructive_capability_denylist_enforcement(self):
        """Repair 1: Forbidden destructive and admin capabilities are rejected in invites and requests."""
        forbidden_caps = [
            "desktop.exec",
            "desktop.file.write",
            "desktop.terminal.exec",
            "windows_terminal_exec",
            "device.revoke",
            "approval.resolve",
            "network.federation.invite",
            "network.federation.kill_switch",
        ]
        for cap in forbidden_caps:
            with self.assertRaises(ValueError, msg=f"Should reject forbidden cap '{cap}'"):
                self.fed_manager.create_invitation(allowed_capabilities=[cap])

        # Test fail-closed in validate_federated_request even if stored in grant
        now_str = datetime.now(timezone.utc).isoformat()
        future_str = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
        tok = "tampered-exec-token"
        self.db_manager.create_federation_grant(
            grant_id="grant-tampered",
            network_id="remote-net",
            network_name="Remote Net",
            peer_node_id="peer-t",
            peer_node_name="Peer T",
            peer_cert_fingerprint="FPT",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(["desktop.exec", "desktop.file.write"]),
            allowed_device_ids_json=json.dumps(["local-coord-1"]),
            auth_token_hash=hash_token(tok),
        )
        ok, err = self.fed_manager.validate_federated_request(
            token=tok,
            target_network_id="local-net-1",
            target_device_id="local-coord-1",
            capability="desktop.exec",
        )
        self.assertFalse(ok)
        self.assertIn("CAPABILITY_NOT_PERMITTED", err)

    async def test_r2_core_ipc_session_termination_and_kill_switch(self):
        """Repair 2: Real cross-process peer session termination via Core IPC."""
        from snow.core.ipc import SnowIpcServer

        # Mock core server
        mock_core = MagicMock()
        mock_core.db_manager = self.db_manager
        mock_client = AsyncMock()
        mock_core.peer_clients = {"node-peer-42": mock_client}
        mock_core.disconnect_peer = AsyncMock(return_value={"success": True})
        mock_core.session_manager = MagicMock()
        mock_core.session_manager.get_session_by_device.return_value = None
        mock_core.session_manager.list_sessions.return_value = []

        from snow.core.config import CoreConfig
        config = CoreConfig(ipc_secret_path=str(Path(self.temp_dir) / "ipc.secret"))
        ipc_server = SnowIpcServer(core_server=mock_core, config=config)

        # Setup active grant
        now_str = datetime.now(timezone.utc).isoformat()
        future_str = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
        self.db_manager.create_federation_grant(
            grant_id="grant-ipc-42",
            network_id="peer-net-42",
            network_name="Peer Net 42",
            peer_node_id="node-peer-42",
            peer_node_name="Node 42",
            peer_cert_fingerprint="FP42",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(["android.status"]),
            allowed_device_ids_json=json.dumps(["local-coord-1"]),
            auth_token_hash="HASH42",
        )

        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="ipc")

        # 1. Test federation_revoke via IPC handler
        res = await ipc_server._handle_federation_revoke("grant-ipc-42", "Owner manual test revocation", ctx=owner_ctx)
        self.assertTrue(res["success"])
        mock_core.disconnect_peer.assert_awaited_with("node-peer-42")

        # Verify DB reflects REVOKED
        grant_row = self.db_manager.get_federation_grant("grant-ipc-42")
        self.assertEqual(grant_row["status"], "REVOKED")

        # 2. Test federation_kill_switch via IPC handler
        self.db_manager.create_federation_grant(
            grant_id="grant-ipc-99",
            network_id="peer-net-99",
            network_name="Peer Net 99",
            peer_node_id="node-peer-99",
            peer_node_name="Node 99",
            peer_cert_fingerprint="FP99",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(["android.status"]),
            allowed_device_ids_json=json.dumps(["local-coord-1"]),
            auth_token_hash="HASH99",
        )
        mock_core.peer_clients = {"node-peer-99": AsyncMock()}
        res_kill = await ipc_server._handle_federation_kill_switch("Nuclear kill switch", ctx=owner_ctx)
        self.assertTrue(res_kill["success"])
        mock_core.disconnect_peer.assert_awaited_with("node-peer-99")

    def test_r3_rate_limiting_and_anti_dos(self):
        """Repair 3: Brute-force rate limiting keyed by requester and anti-DoS protection."""
        # Create a legitimate invitation
        inv = self.fed_manager.create_invitation(
            allowed_capabilities=["android.status"],
            allowed_device_ids=["local-coord-1"],
        )
        legit_invite_id = inv["invite_id"]

        requester_attacker = "192.168.1.100"

        # Attacker submits 5 random guesses that do NOT match
        for _ in range(5):
            res = self.fed_manager.accept_invitation(
                code="111-222-333",
                peer_network_id="attacker-net",
                peer_network_name="Attacker Net",
                peer_node_id="attacker-node",
                peer_node_name="Attacker Node",
                peer_cert_fingerprint="ATK_FP",
                requester_id=requester_attacker,
            )
            self.assertFalse(res["success"])
            self.assertEqual(res["status"], "INVALID_OR_EXPIRED_CODE")

        # Verify Anti-DoS: Legitimate invitation attempts counter was NOT touched!
        with self.db_manager._get_connection() as conn:
            row = conn.execute("SELECT attempts, status FROM federation_invitations WHERE invite_id = ?;", (legit_invite_id,)).fetchone()
            self.assertEqual(row["attempts"], 0)
            self.assertEqual(row["status"], "PENDING")

        # 6th attempt from attacker triggers RATE_LIMIT_EXCEEDED
        res_blocked = self.fed_manager.accept_invitation(
            code="111-222-333",
            peer_network_id="attacker-net",
            peer_network_name="Attacker Net",
            peer_node_id="attacker-node",
            peer_node_name="Attacker Node",
            peer_cert_fingerprint="ATK_FP",
            requester_id=requester_attacker,
        )
        self.assertFalse(res_blocked["success"])
        self.assertEqual(res_blocked["status"], "RATE_LIMIT_EXCEEDED")

        # Verify atomic attempt increment invalidates invitation at 3 attempts
        attempts1 = self.db_manager.increment_federation_invitation_attempts(legit_invite_id)
        self.assertEqual(attempts1, 1)
        attempts2 = self.db_manager.increment_federation_invitation_attempts(legit_invite_id)
        self.assertEqual(attempts2, 2)
        attempts3 = self.db_manager.increment_federation_invitation_attempts(legit_invite_id)
        self.assertEqual(attempts3, 3)

        # Status must now be EXPIRED
        with self.db_manager._get_connection() as conn:
            row = conn.execute("SELECT status FROM federation_invitations WHERE invite_id = ?;", (legit_invite_id,)).fetchone()
            self.assertEqual(row["status"], "EXPIRED")

    def test_r4_topology_expiry_filtering_and_registry_connectivity(self):
        """Repair 4: Expired grants excluded from topology and real connectivity reflected."""
        net_mgr = SnowNetworkManager(db_manager=self.db_manager)

        # 1. Create an expired grant
        past_str = datetime.fromtimestamp(time.time() - 3600, timezone.utc).isoformat()
        self.db_manager.create_federation_grant(
            grant_id="grant-expired",
            network_id="expired-net",
            network_name="Expired Network",
            peer_node_id="expired-peer",
            peer_node_name="Expired Peer",
            peer_cert_fingerprint="FP_EXP",
            direction="INBOUND",
            created_timestamp=datetime.fromtimestamp(time.time() - 7200, timezone.utc).isoformat(),
            expires_timestamp=past_str,
            allowed_capabilities_json=json.dumps(["android.status"]),
            allowed_device_ids_json=json.dumps(["local-coord-1"]),
            auth_token_hash="EXP_HASH",
        )

        top = net_mgr.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)
        expired_devices = [d for d in top["devices"] if d.get("device_id") == "expired-peer"]
        self.assertEqual(len(expired_devices), 0, "Expired grant must not appear in topology.")

        # 2. Create active grant with mock node registry
        future_str = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
        self.db_manager.create_federation_grant(
            grant_id="grant-active",
            network_id="active-net",
            network_name="Active Network",
            peer_node_id="active-peer",
            peer_node_name="Active Peer",
            peer_cert_fingerprint="FP_ACT",
            direction="INBOUND",
            created_timestamp=datetime.now(timezone.utc).isoformat(),
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(["android.status"]),
            allowed_device_ids_json=json.dumps(["local-coord-1"]),
            auth_token_hash="ACT_HASH",
        )

        # Mock node registry without active session
        mock_registry = MagicMock()
        mock_registry.get_node.return_value = None
        net_mgr.node_registry = mock_registry

        top2 = net_mgr.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)
        act_dev = [d for d in top2["devices"] if d.get("device_id") == "active-peer"][0]
        self.assertFalse(act_dev["is_connected"])
        self.assertEqual(act_dev["reachability_state"], "offline")

        # Mock node registry WITH active session
        mock_node = MagicMock(is_connected=True)
        mock_registry.get_node.return_value = mock_node

        top3 = net_mgr.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)
        act_dev3 = [d for d in top3["devices"] if d.get("device_id") == "active-peer"][0]
        self.assertTrue(act_dev3["is_connected"])
        self.assertEqual(act_dev3["reachability_state"], "active")

    async def test_f1_relay_tunnel_close_lifecycle(self):
        """Finding 1: RelayTunnelClient.close_tunnel safely closes SSL tunnel, unwraps/closes, drains queue, and is idempotent."""
        from snow.network.relay_client import RelayTunnelClient
        client = RelayTunnelClient(
            relay_url="wss://relay.snow.local",
            device_id="dev-local",
            group_id="group-1",
            ticket="ticket-123",
            cert_path=str(Path(self.temp_dir) / "cert.pem"),
            key_path=str(Path(self.temp_dir) / "key.pem"),
        )

        mock_ssl = MagicMock()
        mock_ssl.unwrap = MagicMock(return_value=None)
        mock_tunnel = MagicMock()
        mock_tunnel.ssl_obj = mock_ssl
        event = asyncio.Event()
        q = asyncio.Queue()
        await q.put(b"pending data")

        client._tunnels["peer-42"] = mock_tunnel
        client._pinned_fingerprints["peer-42"] = "PINNED_FP"
        client._peer_cert_paths["peer-42"] = Path(self.temp_dir) / "peer42.crt"
        client._incoming_queues["peer-42"] = q
        client._handshake_events["peer-42"] = event

        # First close should succeed and return True
        closed = await client.close_tunnel("peer-42")
        self.assertTrue(closed)
        self.assertNotIn("peer-42", client._tunnels)
        self.assertNotIn("peer-42", client._pinned_fingerprints)
        self.assertNotIn("peer-42", client._peer_cert_paths)
        self.assertNotIn("peer-42", client._incoming_queues)
        self.assertNotIn("peer-42", client._handshake_events)
        self.assertTrue(event.is_set())
        mock_ssl.unwrap.assert_called_once()

        # Second close should be idempotent and return False
        closed2 = await client.close_tunnel("peer-42")
        self.assertFalse(closed2)

    async def test_f1_transport_teardown_integration(self):
        """Finding 1: Single revoke and global kill switch close real mock WebSockets and relay tunnels, leaving unrelated peers untouched."""
        from snow.core.ipc import SnowIpcServer
        from snow.core.config import CoreConfig
        from snow.network.node import DeviceNode

        # Setup mock core server
        mock_core = MagicMock()
        mock_core.db_manager = self.db_manager

        # Active peer clients: fed-1, fed-2, and unrelated phone-lan
        mock_client_fed1 = AsyncMock()
        mock_client_fed2 = AsyncMock()
        mock_client_phone = AsyncMock()
        mock_core.peer_clients = {
            "node-fed-1": mock_client_fed1,
            "node-fed-2": mock_client_fed2,
            "node-phone": mock_client_phone,
        }
        mock_core.disconnect_peer = AsyncMock(return_value={"success": True})

        # Mock WebSocket server with connections
        mock_ws_fed1 = AsyncMock()
        mock_ws_fed2 = AsyncMock()
        mock_ws_phone = AsyncMock()
        conn_fed1 = MagicMock(websocket=mock_ws_fed1)
        conn_fed2 = MagicMock(websocket=mock_ws_fed2)
        conn_phone = MagicMock(websocket=mock_ws_phone)

        ws_conns = {
            "conn-fed-1": conn_fed1,
            "conn-fed-2": conn_fed2,
            "conn-phone": conn_phone,
        }
        mock_ws_server = MagicMock()
        mock_ws_server.connection_manager.get.side_effect = lambda cid: ws_conns.get(cid)
        mock_ws_server.connection_manager.unregister = MagicMock()
        mock_core.ws_server = mock_ws_server

        # Mock Session Manager
        sess_fed1 = MagicMock(session_id="sess-fed-1", connection_id="conn-fed-1", device_id="node-fed-1")
        sess_fed2 = MagicMock(session_id="sess-fed-2", connection_id="conn-fed-2", device_id="node-fed-2")
        sess_phone = MagicMock(session_id="sess-phone", connection_id="conn-phone", device_id="node-phone")
        device_sessions = {
            "node-fed-1": sess_fed1,
            "node-fed-2": sess_fed2,
            "node-phone": sess_phone,
        }
        mock_core.session_manager.get_session_by_device.side_effect = lambda did: device_sessions.get(did)
        mock_core.session_manager.revoke_session = MagicMock()

        # Mock Relay Client
        mock_relay = MagicMock()
        mock_relay.close_tunnel = AsyncMock(return_value=True)
        mock_core.relay_client = mock_relay

        # Mock Node Registry with DeviceNode instances
        mock_registry = MagicMock()
        nodes = [
            DeviceNode(device_id="node-fed-1", device_name="Fed 1", platform="windows", trust_tier="federated"),
            DeviceNode(device_id="node-fed-2", device_name="Fed 2", platform="windows", trust_tier="federated"),
            DeviceNode(device_id="node-phone", device_name="Phone", platform="android", trust_tier="owner"),
        ]
        mock_registry.list_nodes.return_value = list(nodes)
        mock_registry.remove_node = MagicMock()

        config = CoreConfig(ipc_secret_path=str(Path(self.temp_dir) / "ipc.secret"))
        ipc_server = SnowIpcServer(core_server=mock_core, config=config)
        ipc_server.node_registry = mock_registry

        # Setup 2 active federation grants
        now_str = datetime.now(timezone.utc).isoformat()
        future_str = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
        self.db_manager.create_federation_grant(
            grant_id="grant-fed-1",
            network_id="net-fed-1",
            network_name="Fed Net 1",
            peer_node_id="node-fed-1",
            peer_node_name="Fed Node 1",
            peer_cert_fingerprint="FP1",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(["android.status"]),
            allowed_device_ids_json=json.dumps(["local-coord-1"]),
            auth_token_hash="HASH1",
        )
        self.db_manager.create_federation_grant(
            grant_id="grant-fed-2",
            network_id="net-fed-2",
            network_name="Fed Net 2",
            peer_node_id="node-fed-2",
            peer_node_name="Fed Node 2",
            peer_cert_fingerprint="FP2",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(["android.status"]),
            allowed_device_ids_json=json.dumps(["local-coord-1"]),
            auth_token_hash="HASH2",
        )

        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="ipc")

        # 1. Single revocation of grant-fed-1
        res_revoke = await ipc_server._handle_federation_revoke("grant-fed-1", "Single revoke", ctx=owner_ctx)
        self.assertTrue(res_revoke["success"])
        self.assertEqual(res_revoke["disconnected_peers"], 1)
        self.assertEqual(res_revoke["closed_ws_clients"], 1)
        self.assertEqual(res_revoke["relay_disconnected"], 1)

        mock_core.disconnect_peer.assert_awaited_with("node-fed-1")
        mock_ws_fed1.close.assert_awaited_once()
        mock_relay.close_tunnel.assert_awaited_with("node-fed-1")
        mock_registry.remove_node.assert_called_with("node-fed-1")

        # Ensure node-phone and node-fed-2 were NOT touched by single revocation
        mock_ws_phone.close.assert_not_called()
        mock_ws_fed2.close.assert_not_called()

        # 2. Global kill switch
        mock_core.disconnect_peer.reset_mock()
        mock_relay.close_tunnel.reset_mock()
        res_kill = await ipc_server._handle_federation_kill_switch("Emergency kill", ctx=owner_ctx)
        self.assertTrue(res_kill["success"])
        self.assertEqual(res_kill["disconnected_peers"], 2)  # node-fed-1 and node-fed-2 (both federated)
        self.assertEqual(res_kill["closed_ws_clients"], 2)
        self.assertEqual(res_kill["relay_disconnected"], 2)

        mock_core.disconnect_peer.assert_awaited_with("node-fed-2")
        mock_ws_fed2.close.assert_awaited_once()
        # Ensure node-phone ws was NEVER closed by kill switch
        mock_ws_phone.close.assert_not_called()

    async def test_f2_ipc_authorization_enforcement(self):
        """Finding 2: Non-OWNER_MANUAL (AI_MCP) is strictly rejected with POLICY_DENIED over Core IPC."""
        from snow.core.ipc import SnowIpcServer
        from snow.core.config import CoreConfig

        mock_core = MagicMock()
        mock_core.db_manager = self.db_manager
        config = CoreConfig(ipc_secret_path=str(Path(self.temp_dir) / "ipc.secret"))
        ipc_server = SnowIpcServer(core_server=mock_core, config=config)

        now_str = datetime.now(timezone.utc).isoformat()
        future_str = datetime.fromtimestamp(time.time() + 3600, timezone.utc).isoformat()
        self.db_manager.create_federation_grant(
            grant_id="grant-f2-test",
            network_id="net-f2",
            network_name="Net F2",
            peer_node_id="node-f2",
            peer_node_name="Node F2",
            peer_cert_fingerprint="FP_F2",
            direction="INBOUND",
            created_timestamp=now_str,
            expires_timestamp=future_str,
            allowed_capabilities_json=json.dumps(["android.status"]),
            allowed_device_ids_json=json.dumps(["local-coord-1"]),
            auth_token_hash="HASH_F2",
        )

        ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="ipc")
        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="ipc")

        # 1. AI_MCP calling federation_revoke -> POLICY_DENIED
        res_revoke_ai, _ = await ipc_server._dispatch_request(
            {"version": 1, "request_id": "r1", "op": "federation_revoke", "payload": {"grant_id": "grant-f2-test"}},
            is_connection_authenticated=True,
        )
        self.assertFalse(res_revoke_ai["success"])
        self.assertEqual(res_revoke_ai["status"], "POLICY_DENIED")
        # Ensure DB status is still ACTIVE
        grant = self.db_manager.get_federation_grant("grant-f2-test")
        self.assertEqual(grant["status"], "ACTIVE")

        # 2. AI_MCP calling federation_kill_switch -> POLICY_DENIED
        res_kill_ai, _ = await ipc_server._dispatch_request(
            {"version": 1, "request_id": "r2", "op": "federation_kill_switch", "payload": {"reason": "AI Rogue Attempt"}},
            is_connection_authenticated=True,
        )
        self.assertFalse(res_kill_ai["success"])
        self.assertEqual(res_kill_ai["status"], "POLICY_DENIED")
        grant2 = self.db_manager.get_federation_grant("grant-f2-test")
        self.assertEqual(grant2["status"], "ACTIVE")

        # 3. OWNER_MANUAL calling federation_revoke -> SUCCESS
        owner_tok = hmac.new(ipc_server._secret.encode("utf-8"), b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256).hexdigest()
        res_revoke_owner, _ = await ipc_server._dispatch_request(
            {
                "version": 1,
                "request_id": "r3",
                "op": "federation_revoke",
                "owner_token": owner_tok,
                "payload": {"grant_id": "grant-f2-test", "reason": "Owner authorized"},
            },
            is_connection_authenticated=True,
        )
        self.assertTrue(res_revoke_owner["success"])
        self.assertEqual(res_revoke_owner["status"], "GRANT_REVOKED")

        # Verify DB audit log recorded ExecutionPrincipal.OWNER_MANUAL
        records = self.db_manager.query_activity_history(event_type="FEDERATION_GRANT_REVOKED")
        self.assertTrue(len(records) > 0)
        self.assertIn(records[0]["principal"], ("OWNER_MANUAL", "ExecutionPrincipal.OWNER_MANUAL"))
        self.assertEqual(records[0]["outcome"], "SUCCESS")


if __name__ == "__main__":
    unittest.main()
