"""Phase 25 — V3 Release Acceptance, Security Integrity, Chaos & Resilience Suite.

Validates the full SNOW V3 four-layer architecture contracts:
1. Dynamic 34-tool catalog, annotations, schemas, and security principal boundaries (AI_MCP vs OWNER_MANUAL).
2. Chaos and resilience: connection churn, Wi-Fi <-> USB replacement, frame bounds (>64 KiB), approval replay, and protocol boundaries.
3. Multi-peer federation: Windows Core A <-> Windows Core B isolated instance state, registries, and routing.
4. Android peer host RFC 6455 quarantine verification.
5. Local-first zero-cloud independence without relay or remote gateway dependencies.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import socket
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.engine import (
    CapabilityEngine,
    CapabilityRequest,
    CapabilityResponse,
)
from snow.capabilities.workflows import WorkflowOrchestrator, WORKFLOW_REGISTRY
from snow.core.config import CoreConfig
from snow.security.db import DatabaseManager
from snow.mcp.registry import (
    CAPABILITY_REGISTRY,
    get_capability_metadata,
    get_mcp_annotations,
    list_capabilities,
)
from snow.network.node import DeviceNode, CapabilityManifest
from snow.network.registry import NodeRegistry
from snow.network.router import SessionRouter
from snow.protocol.constants import DEFAULT_MAX_MESSAGE_SIZE, ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.protocol.validator import ProtocolValidationError, validate_raw_message
from snow.security.approval import (
    ApprovalPolicyEngine,
    ApprovalRequest,
    ApprovalStatus,
)
from snow.security.context import ExecutionContext, ExecutionPrincipal


class TestDynamicCatalogAndSecurityIntegrity(unittest.TestCase):
    """Group A: Dynamic 38-tool catalog and security principal boundaries."""

    def test_dynamic_catalog_exact_count_and_uniqueness(self) -> None:
        """Verify dynamic registry contains exactly 38 tools with unique names."""
        caps = list_capabilities()
        self.assertEqual(len(caps), 38, f"Expected exactly 38 registered capabilities, got {len(caps)}")
        names = [c.name for c in caps]
        self.assertEqual(len(names), len(set(names)), "Tool names must be globally unique across all categories.")

    def test_strict_boolean_tool_annotations(self) -> None:
        """Verify ToolAnnotations enforce strict boolean fields and accurate metadata."""
        for cap in list_capabilities():
            ann = get_mcp_annotations(cap.name)
            self.assertIsNotNone(ann, f"Missing MCP annotations for {cap.name}")
            self.assertIsInstance(ann.readOnlyHint, bool, f"readOnlyHint must be bool for {cap.name}")
            self.assertIsInstance(ann.destructiveHint, bool, f"destructiveHint must be bool for {cap.name}")
            # Mutually exclusive: a read-only tool cannot be destructive
            if ann.readOnlyHint:
                self.assertFalse(
                    ann.destructiveHint,
                    f"Tool {cap.name} is marked read-only and destructive simultaneously.",
                )

    def test_ai_mcp_least_privilege_enforcement(self) -> None:
        """Verify AI_MCP principal cannot execute approval-gated or mutating tools without ticket."""
        tmp_dir = tempfile.TemporaryDirectory()
        try:
            db_path = Path(tmp_dir.name) / "snow_sec.db"
            db = DatabaseManager(str(db_path))
            pol = ApprovalPolicyEngine(db_manager=db)
            engine = CapabilityEngine(approval_engine=pol, db_manager=db)

            # AI_MCP execution without approval ticket
            ctx_ai = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="claude_desktop")
            req = CapabilityRequest(
                action="windows_screenshot",
                params={},
            )
            resp = asyncio.run(engine.execute(req, ctx=ctx_ai))
            self.assertFalse(resp.success)
            self.assertEqual(resp.status, "APPROVAL_REQUIRED")
            self.assertIsNotNone(resp.data.get("request_id"))

            # Verify policy strictly requires OWNER_MANUAL to approve or deny
            app_id = resp.data["request_id"]
            ok, msg = pol.approve_request(app_id, approver_principal=ExecutionPrincipal.AI_MCP)
            self.assertFalse(ok)
            self.assertEqual(msg, "Only OWNER_MANUAL principal is authorized to resolve approvals.")
            req_obj = pol.get_request(app_id)
            self.assertEqual(req_obj.status, ApprovalStatus.PENDING)

            # Verify AI self-denial attempt is also rejected and leaves status PENDING
            ok_deny, msg_deny = pol.deny_request(app_id, approver_principal=ExecutionPrincipal.AI_MCP)
            self.assertFalse(ok_deny)
            self.assertEqual(msg_deny, "Only OWNER_MANUAL principal is authorized to resolve approvals.")
            req_obj = pol.get_request(app_id)
            self.assertEqual(req_obj.status, ApprovalStatus.PENDING)

            # Verify valid OWNER_MANUAL approval succeeds
            ok_owner, _ = pol.approve_request(app_id, approver_principal=ExecutionPrincipal.OWNER_MANUAL)
            self.assertTrue(ok_owner)
            self.assertEqual(req_obj.status, ApprovalStatus.APPROVED)
        finally:
            tmp_dir.cleanup()

    def test_owner_manual_authorized_execution(self) -> None:
        """Verify OWNER_MANUAL principal can resolve approvals and execute authorized operations."""
        tmp_dir = tempfile.TemporaryDirectory()
        try:
            db_path = Path(tmp_dir.name) / "snow_owner.db"
            db = DatabaseManager(str(db_path))
            pol = ApprovalPolicyEngine(db_manager=db)
            engine = CapabilityEngine(approval_engine=pol, db_manager=db)

            ticket = pol.create_request(
                principal=ExecutionPrincipal.AI_MCP,
                action="windows_screenshot",
                target_device="local",
                params={},
                reason="Screenshot requested by assistant",
            )
            # Owner approves
            ok, msg = pol.approve_request(
                request_id=ticket.request_id,
                approver_principal=ExecutionPrincipal.OWNER_MANUAL,
            )
            self.assertTrue(ok)
            req_obj = pol.get_request(ticket.request_id)
            self.assertEqual(req_obj.status, ApprovalStatus.APPROVED)

            # Now execute with valid approval
            ctx_owner = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="snow_web")
            with patch("snow.capabilities.windows.screenshot.WindowsScreenshotCapture.capture_screen") as mock_cap:
                mock_cap.return_value = {
                    "success": True,
                    "status": "SUCCESS",
                    "file_name": "test_owner.png",
                    "file_path": str(Path(tmp_dir.name) / "test_owner.png"),
                    "sha256": "abc123owner",
                }
                req = CapabilityRequest(
                    action="windows_screenshot",
                    params={"approval_id": ticket.request_id},
                )
                resp = asyncio.run(engine.execute(req, ctx=ctx_owner))
                self.assertTrue(resp.success)
        finally:
            tmp_dir.cleanup()


class TestChaosAndResilience(unittest.TestCase):
    """Group B: Chaos, resilience, bounds, and replay attack prevention."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(str(Path(self.tmp_dir.name) / "snow_chaos.db"))

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_approval_replay_and_duplicate_resolution(self) -> None:
        """Verify replaying or doubly resolving approval tickets is strictly rejected."""
        pol = ApprovalPolicyEngine(db_manager=self.db)
        ticket = pol.create_request(
            principal=ExecutionPrincipal.AI_MCP,
            action="android_file_send",
            target_device="realme-phone",
            params={"file_name": "photo.png"},
            reason="Transfer photo to phone",
        )
        # First approval succeeds
        ok1, msg1 = pol.approve_request(ticket.request_id, approver_principal=ExecutionPrincipal.OWNER_MANUAL)
        self.assertTrue(ok1)

        # Duplicate approval attempt must be rejected (already approved)
        ok2, msg2 = pol.approve_request(ticket.request_id, approver_principal=ExecutionPrincipal.OWNER_MANUAL)
        self.assertFalse(ok2)
        self.assertIn("not pending", msg2)

        # Ticket cannot be consumed twice (replay protection)
        consumed, c_msg = pol.consume_approval(
            request_id=ticket.request_id,
            principal=ExecutionPrincipal.AI_MCP,
            action="android_file_send",
            target_device="realme-phone",
            params={"file_name": "photo.png"},
        )
        self.assertTrue(consumed)

        consumed_again, c_msg2 = pol.consume_approval(
            request_id=ticket.request_id,
            principal=ExecutionPrincipal.AI_MCP,
            action="android_file_send",
            target_device="realme-phone",
            params={"file_name": "photo.png"},
        )
        self.assertFalse(consumed_again, "Approval ticket must not be consumable multiple times.")
        self.assertIn("already been consumed", c_msg2)

    def test_stale_disconnect_race_protection(self) -> None:
        """Verify stale disconnect callbacks with mismatched connection_id do not disconnect new session."""
        reg = NodeRegistry(self.db)
        # Add to paired devices DB so reachability synthesizes from active sessions
        self.db.insert_paired_device(
            device_id="phone-realme",
            device_name="Realme RMX5110",
            auth_token_hash="thash123",
            platform="android",
            trust_tier="peer",
        )

        # Session A connects on Wi-Fi (conn-id A)
        reg.on_session_authenticated("phone-realme", "conn-id-aaa", host="192.168.1.50")
        active_a = reg._active_sessions.get("phone-realme")
        self.assertIsNotNone(active_a)
        self.assertEqual(active_a.get("connection_id"), "conn-id-aaa")

        # Session B replaces Session A on USB (conn-id B)
        reg.on_session_authenticated("phone-realme", "conn-id-bbb", host="127.0.0.1")
        active_b = reg._active_sessions.get("phone-realme")
        self.assertIsNotNone(active_b)
        self.assertEqual(active_b.get("connection_id"), "conn-id-bbb")

        # Delayed disconnect event from old Wi-Fi connection arrives (conn-id A)
        reg.on_session_disconnected("phone-realme", connection_id="conn-id-aaa")

        # Session B must STILL be active!
        active_still = reg._active_sessions.get("phone-realme")
        self.assertIsNotNone(active_still, "Stale disconnect event must not disconnect active replaced session.")
        self.assertEqual(active_still.get("connection_id"), "conn-id-bbb")

        # Clean disconnect with current connection_id works
        reg.on_session_disconnected("phone-realme", connection_id="conn-id-bbb")
        self.assertIsNone(reg._active_sessions.get("phone-realme"))

    def test_oversized_payload_boundary_rejection(self) -> None:
        """Verify control protocol strictly enforces 64 KiB frame boundary."""
        self.assertEqual(DEFAULT_MAX_MESSAGE_SIZE, 65536)

        # 65537 bytes frame exceeds limit
        oversized_str = "x" * 65537
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message(oversized_str)
        self.assertEqual(ctx.exception.code, ErrorCode.OVERSIZED_MESSAGE)

    def test_malformed_json_rejection(self) -> None:
        """Verify malformed JSON envelopes are cleanly rejected without server crash."""
        with self.assertRaises(ProtocolValidationError) as ctx:
            validate_raw_message("{not_valid_json: 123")
        self.assertEqual(ctx.exception.code, ErrorCode.INVALID_JSON)


class TestMultiPeerFederation(unittest.TestCase):
    """Group C: Windows Core A <-> Windows Core B isolated peer federation."""

    def test_two_core_instance_isolation_and_handshake(self) -> None:
        """Verify two Core instances with isolated SQLite, ports, and identities can coexist and route."""
        dir_a = tempfile.TemporaryDirectory()
        dir_b = tempfile.TemporaryDirectory()
        try:
            db_a = DatabaseManager(str(Path(dir_a.name) / "core_a.db"))
            db_b = DatabaseManager(str(Path(dir_b.name) / "core_b.db"))

            reg_a = NodeRegistry(db_a)
            reg_b = NodeRegistry(db_b)

            manifest_b = CapabilityManifest(supported_capabilities=["desktop.status", "desktop_status"])
            # Node A registers Node B as PEER with supported capabilities
            node_b = DeviceNode(
                device_id="desktop-node-b",
                device_name="Windows Laptop B",
                platform="windows",
                trust_tier="PEER",
                capabilities=manifest_b,
                supported_capabilities=["desktop.status", "desktop_status"],
            )
            reg_a.register_node(node_b)

            # Node B registers Node A as PEER
            node_a = DeviceNode(
                device_id="desktop-node-a",
                device_name="Windows Laptop A",
                platform="windows",
                trust_tier="PEER",
                supported_capabilities=["desktop.status", "desktop_status"],
            )
            reg_b.register_node(node_a)

            # Route test message from A to B via mocked transport
            fake_resp = MagicMock()
            fake_resp.type = MessageType.RESPONSE
            fake_resp.payload = {"status": "SUCCESS", "hostname": "Windows Laptop B"}
            fake_resp.error = None

            mock_ws_server = MagicMock()
            mock_ws_server.send_request = AsyncMock(return_value=fake_resp)
            mock_session = MagicMock()
            mock_session.connection_id = "ws-b-session-1"
            mock_ws_server.session_manager.get_session_by_device.return_value = mock_session
            mock_conn = MagicMock()
            mock_conn.is_active = True
            mock_ws_server.connection_manager.get.return_value = mock_conn

            router_a = SessionRouter(node_registry=reg_a, ws_server=mock_ws_server)
            reg_a.on_session_authenticated(
                "desktop-node-b", "ws-b-session-1", host="127.0.0.1", port=9765, manifest_data=manifest_b
            )

            route_res = asyncio.run(
                router_a.route_request(
                    action="desktop_status",
                    target="desktop-node-b",
                    data={"ping": "federation_handshake"},
                )
            )
            self.assertTrue(route_res.get("success"))
            self.assertEqual(route_res.get("status"), "SUCCESS")
        finally:
            dir_a.cleanup()
            dir_b.cleanup()


class TestAndroidPeerHostQuarantine(unittest.TestCase):
    """Group D: Verify Android peer host remains quarantined pending physical verification."""

    def test_android_peer_host_quarantine_invariant(self) -> None:
        """Verify Android peer host is explicitly quarantined in source and architecture."""
        android_mgr_path = Path("android/app/src/main/java/org/snow/network/AndroidPeerHostManager.kt")
        if android_mgr_path.is_file():
            content = android_mgr_path.read_text(encoding="utf-8")
            self.assertIn(
                "IS_QUARANTINED",
                content,
                "AndroidPeerHostManager must declare IS_QUARANTINED constant.",
            )
            self.assertIn(
                "const val IS_QUARANTINED",
                content,
                "AndroidPeerHostManager.IS_QUARANTINED must be declared.",
            )


class TestLocalFirstZeroCloudIndependence(unittest.TestCase):
    """Group E: Local-first operations remain 100% operational with relay and gateway offline."""

    def test_local_capabilities_run_without_cloud_or_relay(self) -> None:
        """Verify local capabilities (system info, clipboard, files) execute with relay disabled."""
        tmp_dir = tempfile.TemporaryDirectory()
        try:
            db = DatabaseManager(str(Path(tmp_dir.name) / "local_first.db"))
            pol = ApprovalPolicyEngine(db_manager=db)
            engine = CapabilityEngine(approval_engine=pol, db_manager=db)

            ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="snow_local")
            req = CapabilityRequest(action="windows_system_info", params={})
            resp = asyncio.run(engine.execute(req, ctx=ctx))
            self.assertTrue(resp.success)
            self.assertIsNotNone(resp.data)
            self.assertIn("cpu", resp.data)
            self.assertIn("memory", resp.data)
            self.assertIn("hostname", resp.data)
        finally:
            tmp_dir.cleanup()


if __name__ == "__main__":
    unittest.main()
