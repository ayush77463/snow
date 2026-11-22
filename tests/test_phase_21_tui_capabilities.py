"""Comprehensive test suite for SNOW Phase 21.

Covers:
1. Pillar 1: Dynamic Capability Registry & Metadata Validation.
2. Pillar 2: Shared Approval Policy Engine, State Transitions, Cryptographic Binding,
             Single-Use Consumption, and Centralized Secret Redaction in Activity History.
3. Pillar 3: Media Control, Safe Link Sharing Scheme Validation, and Activity Audit Queries.
4. Pillar 4: TUI Lazy Import Invariants and Missing Dependency Graceful Handling.
"""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import os
import subprocess
from snow.capabilities.engine import CapabilityEngine, CapabilityRequest, CapabilityResponse
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer, DEFAULT_IPC_SECRET_FILENAME
from snow.mcp.bridge import SnowMcpBridge
from snow.capabilities.windows.media import WindowsMediaController
from snow.mcp.registry import (
    CapabilityMetadata,
    ToolCategory,
    get_capability_metadata,
    get_tool_category,
    is_cross_device_tool,
    is_local_windows_tool,
    list_capabilities,
    validate_registry,
    TOOL_REGISTRY,
)
from snow.mcp.tools import ALL_TOOL_NAMES
from snow.security.approval import (
    ApprovalPolicyEngine,
    ApprovalRequest,
    ApprovalStatus,
    compute_args_hash,
)
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager, redact_sensitive_data


class TestPillar1DynamicCapabilityRegistry(unittest.IsolatedAsyncioTestCase):
    """Test dynamic capability registry, metadata validation, and catalog consistency."""

    def test_registry_validation_passes(self) -> None:
        """Dynamic capability registry passes self-consistency validation."""
        is_valid, errors = validate_registry()
        self.assertTrue(is_valid, f"Registry validation failed with errors: {errors}")
        self.assertEqual(len(errors), 0)

    def test_all_24_baseline_tools_preserved(self) -> None:
        """All 24 original baseline tools remain registered and discoverable."""
        baseline_tools = [
            "snow_get_device_status", "snow_list_devices", "snow_windows_battery",
            "snow_windows_system_info", "snow_windows_processes", "snow_windows_launch_app",
            "snow_windows_file_read", "snow_windows_file_write", "snow_windows_file_list",
            "snow_windows_file_search", "snow_windows_terminal_exec", "snow_windows_clipboard_get",
            "snow_windows_clipboard_set", "snow_sync_clipboard", "snow_android_battery",
            "snow_android_ring", "snow_android_clipboard_push", "snow_android_launch_app",
            "snow_android_list_apps", "snow_android_file_send", "snow_android_file_receive",
            "snow_transfer_file", "snow_mesh_connect_peer", "snow_android_send_message",
        ]
        for tool_name in baseline_tools:
            self.assertIn(tool_name, ALL_TOOL_NAMES)
            meta = get_capability_metadata(tool_name)
            self.assertNotNull = meta is not None
            self.assertTrue(bool(meta), f"Missing metadata for baseline tool: {tool_name}")

    def test_six_new_p1_capabilities_registered(self) -> None:
        """All 6 new Phase 21 P1 capabilities are registered with correct metadata."""
        p1_tools = [
            ("snow_android_file_list", ToolCategory.CROSS_DEVICE, True, False, "android"),
            ("snow_android_notifications_list", ToolCategory.CROSS_DEVICE, True, False, "android"),
            ("snow_android_notification_dismiss", ToolCategory.CROSS_DEVICE, False, False, "android"),
            ("snow_media_control", ToolCategory.CROSS_DEVICE, False, False, "cross_platform"),
            ("snow_share_link", ToolCategory.CROSS_DEVICE, False, False, "cross_platform"),
            ("snow_activity_history", ToolCategory.LOCAL_WINDOWS, True, False, "windows"),
        ]
        for name, category, read_only, destructive, os_cls in p1_tools:
            self.assertIn(name, ALL_TOOL_NAMES)
            meta = get_capability_metadata(name)
            self.assertIsNotNone(meta, f"Metadata missing for {name}")
            self.assertEqual(meta.category, category)
            self.assertEqual(meta.read_only_hint, read_only)
            self.assertEqual(meta.destructive_hint, destructive)
            self.assertEqual(meta.os_classification, os_cls)
            self.assertTrue(len(meta.description) > 10)

    def test_tool_registry_backward_compatibility_dict(self) -> None:
        """TOOL_REGISTRY proxy dict provides backward compatible access."""
        self.assertEqual(len(TOOL_REGISTRY), 38)
        self.assertEqual(TOOL_REGISTRY["snow_windows_battery"], ToolCategory.LOCAL_WINDOWS)
        self.assertEqual(TOOL_REGISTRY["snow_android_file_list"], ToolCategory.CROSS_DEVICE)
        self.assertTrue("snow_activity_history" in TOOL_REGISTRY)

    def test_exact_30_tools_and_prohibited_names_absent(self) -> None:
        """Catalog has exactly 38 tools (24 baseline + 6 P1 + 4 Phase 24 + 3 Phase 26B + 1 Phase 27) with zero fabricated names."""
        self.assertEqual(len(ALL_TOOL_NAMES), 38)
        self.assertEqual(len(list_capabilities()), 38)
        prohibited = [
            "snow_android_send_sms",
            "snow_android_take_photo",
            "snow_windows_file_delete",
        ]
        for name in prohibited:
            self.assertNotIn(name, ALL_TOOL_NAMES)
            self.assertIsNone(get_capability_metadata(name))

    def test_capability_metadata_strict_types(self) -> None:
        """CapabilityMetadata fields strictly validate bool and str types without truthy coercion."""
        for meta in list_capabilities():
            self.assertIs(type(meta.read_only_hint), bool, f"{meta.name}: read_only_hint not strict bool")
            self.assertIs(type(meta.destructive_hint), bool, f"{meta.name}: destructive_hint not strict bool")
            self.assertIs(type(meta.requires_approval), bool, f"{meta.name}: requires_approval not strict bool")
            self.assertIsInstance(meta.tier, str, f"{meta.name}: tier not str")
            self.assertTrue(len(meta.tier) > 0, f"{meta.name}: tier is empty")

    async def test_fastmcp_list_tools_exposes_annotations(self) -> None:
        """FastMCP tool registration attaches ToolAnnotations (readOnlyHint, destructiveHint) to all 38 tools."""
        from mcp.server.fastmcp import FastMCP
        from snow.mcp.bridge import SnowMcpBridge
        from snow.mcp.tools import register_all_tools

        server = FastMCP("snow_annotation_test")
        bridge = SnowMcpBridge(auto_start_core=False)
        register_all_tools(server, bridge)

        tools = await server.list_tools()
        self.assertEqual(len(tools), 38)
        for t in tools:
            self.assertIsNotNone(t.annotations, f"Tool '{t.name}' is missing MCP ToolAnnotations")
            self.assertIs(type(t.annotations.readOnlyHint), bool, f"Tool '{t.name}': readOnlyHint not bool")
            self.assertIs(type(t.annotations.destructiveHint), bool, f"Tool '{t.name}': destructiveHint not bool")


class TestPillar2ApprovalPolicyEngineAndAudit(unittest.TestCase):
    """Test authorization policy, approval state machine, cryptographic binding, and audit."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_snow.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.engine = ApprovalPolicyEngine(db_manager=self.db)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_canonical_args_hash_consistency(self) -> None:
        """compute_args_hash produces deterministic SHA-256 digests independent of key ordering."""
        p1 = {"command": "dir", "cwd": "C:\\Users", "timeout": 30.0}
        p2 = {"timeout": 30.0, "command": "dir", "cwd": "C:\\Users"}
        self.assertEqual(compute_args_hash(p1), compute_args_hash(p2))

        # Different parameter changes hash
        p3 = {"command": "dir /s", "cwd": "C:\\Users", "timeout": 30.0}
        self.assertNotEqual(compute_args_hash(p1), compute_args_hash(p3))

    def test_ai_mcp_policy_evaluation(self) -> None:
        """AI_MCP principal requires approval for shell, cross-device writes, and file writes."""
        ctx_ai = ExecutionContext(principal=ExecutionPrincipal.AI_MCP)

        # Read-only operation auto-allowed
        req_app, _, risk = self.engine.evaluate_policy("windows_system_info", {}, ctx_ai)
        self.assertFalse(req_app)
        self.assertEqual(risk, "LOW")

        # Terminal execution requires approval
        req_app, reason, risk = self.engine.evaluate_policy("windows_terminal_exec", {"command": "whoami"}, ctx_ai)
        self.assertTrue(req_app)
        self.assertEqual(risk, "HIGH")

        # Cross-device file send requires approval
        req_app, _, risk = self.engine.evaluate_policy("android_file_send", {"file_path": "test.txt"}, ctx_ai)
        self.assertTrue(req_app)
        self.assertEqual(risk, "HIGH")

    def test_catastrophic_operation_hard_blocked(self) -> None:
        """Catastrophic destructive operations are permanently blocked with CRITICAL risk."""
        ctx_ai = ExecutionContext(principal=ExecutionPrincipal.AI_MCP)
        req_app, reason, risk = self.engine.evaluate_policy(
            "windows_terminal_exec", {"command": "rm -rf /"}, ctx_ai
        )
        self.assertTrue(req_app)
        self.assertEqual(risk, "CRITICAL")
        self.assertIn("Catastrophic", reason)

    def test_approval_lifecycle_approve_and_single_use_consumption(self) -> None:
        """Full approval lifecycle: PENDING -> APPROVED -> CONSUMED (single-use invariant)."""
        params = {"command": "ipconfig", "timeout": 10.0}
        req = self.engine.create_request(
            principal=ExecutionPrincipal.AI_MCP,
            action="windows_terminal_exec",
            target_device="local",
            params=params,
            reason="Network inspection",
            risk_level="HIGH",
        )
        self.assertEqual(req.status, ApprovalStatus.PENDING)
        self.assertFalse(req.consumed)

        # 1. Approve via owner
        ok, status_msg = self.engine.approve_request(req.request_id, ExecutionPrincipal.OWNER_MANUAL)
        self.assertTrue(ok)
        self.assertEqual(status_msg, "APPROVED")
        self.assertEqual(req.status, ApprovalStatus.APPROVED)

        # 2. First consumption succeeds
        ok_consume, msg_consume = self.engine.consume_approval(
            request_id=req.request_id,
            principal=ExecutionPrincipal.AI_MCP,
            action="windows_terminal_exec",
            target_device="local",
            params=params,
        )
        self.assertTrue(ok_consume)
        self.assertEqual(msg_consume, "OK")
        self.assertTrue(req.consumed)

        # 3. Second consumption attempt fails (single-use anti-replay check)
        ok_consume2, msg_consume2 = self.engine.consume_approval(
            request_id=req.request_id,
            principal=ExecutionPrincipal.AI_MCP,
            action="windows_terminal_exec",
            target_device="local",
            params=params,
        )
        self.assertFalse(ok_consume2)
        self.assertIn("already been consumed", msg_consume2)

    def test_approval_tampering_and_mismatch_rejection(self) -> None:
        """Tampered arguments, target device mismatch, or principal mismatch are rejected."""
        params = {"command": "ping 127.0.0.1"}
        req = self.engine.create_request(
            principal=ExecutionPrincipal.AI_MCP,
            action="windows_terminal_exec",
            target_device="local",
            params=params,
        )
        self.engine.approve_request(req.request_id)

        # Argument tampering rejection
        tampered_params = {"command": "ping 8.8.8.8"}
        ok, msg = self.engine.consume_approval(
            req.request_id, ExecutionPrincipal.AI_MCP, "windows_terminal_exec", "local", tampered_params
        )
        self.assertFalse(ok)
        self.assertIn("integrity violation", msg)

        # Target device mismatch rejection
        ok_dev, msg_dev = self.engine.consume_approval(
            req.request_id, ExecutionPrincipal.AI_MCP, "windows_terminal_exec", "device_other", params
        )
        self.assertFalse(ok_dev)
        self.assertIn("Target device mismatch", msg_dev)

        # Principal mismatch rejection
        ok_pr, msg_pr = self.engine.consume_approval(
            req.request_id, ExecutionPrincipal.OWNER_MANUAL, "windows_terminal_exec", "local", params
        )
        self.assertFalse(ok_pr)
        self.assertIn("Principal mismatch", msg_pr)

    def test_approval_expiration_rejection(self) -> None:
        """Expired approval requests cannot be approved or consumed."""
        req = self.engine.create_request(
            principal=ExecutionPrincipal.AI_MCP,
            action="windows_terminal_exec",
            target_device="local",
            params={},
            ttl_seconds=-1.0,  # Pre-expired
        )
        # Attempt approve on expired request
        ok, msg = self.engine.approve_request(req.request_id)
        self.assertFalse(ok)
        self.assertIn("expired", msg.lower())

    def test_centralized_secret_redaction(self) -> None:
        """redact_sensitive_data recursively removes PINs, tokens, keys, clipboard, and bodies."""
        sensitive_payload = {
            "pairing_pin": "123456",
            "auth_token": "secret_abc_123",
            "nested": {
                "private_key": "MIIEvgIBADANBg...",
                "normal_field": "safe_value",
                "notification_body": "Your bank OTP is 987654",
                "clipboard_text": "Sensitive copy content",
            },
            "array_items": [
                {"auth_token_hash": "abcdef", "id": 1},
                {"cert_fingerprint": "AA:BB:CC", "device_name": "Pixel"},
            ]
        }
        scrubbed = redact_sensitive_data(sensitive_payload)

        self.assertEqual(scrubbed["pairing_pin"], "[REDACTED]")
        self.assertEqual(scrubbed["auth_token"], "[REDACTED]")
        self.assertEqual(scrubbed["nested"]["private_key"], "[REDACTED]")
        self.assertEqual(scrubbed["nested"]["normal_field"], "safe_value")
        self.assertEqual(scrubbed["nested"]["notification_body"], "[REDACTED]")
        self.assertEqual(scrubbed["nested"]["clipboard_text"], "[REDACTED]")
        self.assertEqual(scrubbed["array_items"][0]["auth_token_hash"], "[REDACTED]")
        self.assertEqual(scrubbed["array_items"][0]["id"], 1)
        self.assertEqual(scrubbed["array_items"][1]["cert_fingerprint"], "[REDACTED]")
        self.assertEqual(scrubbed["array_items"][1]["device_name"], "Pixel")

    def test_activity_history_logging_and_query_pagination(self) -> None:
        """Activity history table records redacted events with bounded pagination and filtering."""
        # Insert 15 events
        for i in range(15):
            self.db.log_activity(
                event_type="CAPABILITY_EXECUTION" if i % 2 == 0 else "APPROVAL_REQUESTED",
                capability=f"cap_{i}",
                principal="AI_MCP" if i < 10 else "OWNER_MANUAL",
                outcome="SUCCESS",
                details={"step": i, "auth_token": f"token_{i}"},
            )

        # Bounded pagination (page 1: limit 5)
        page1 = self.db.query_activity_history(limit=5, offset=0)
        self.assertEqual(len(page1), 5)
        # Verify secret was scrubbed in logged details
        self.assertEqual(page1[0]["details"]["auth_token"], "[REDACTED]")

        # Filtering by principal
        owner_events = self.db.query_activity_history(principal="OWNER_MANUAL")
        self.assertEqual(len(owner_events), 5)


class TestPillar3CapabilitiesExecution(unittest.IsolatedAsyncioTestCase):
    """Test CapabilityEngine execution for media control, safe link sharing, and activity history."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_engine.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.engine = CapabilityEngine(db_manager=self.db)

    async def asyncTearDown(self) -> None:
        self.tmp_dir.cleanup()

    async def test_windows_media_controller_action_validation(self) -> None:
        """WindowsMediaController validates actions and dispatches supported keys."""
        ctrl = WindowsMediaController()
        # Supported actions
        for act in ("play_pause", "next", "previous", "volume_up", "volume_down", "mute"):
            res = ctrl.handle_action(act)
            self.assertTrue(res.get("success"), f"Failed for {act}: {res}")
            self.assertEqual(res.get("platform"), "windows")

        # Unsupported action
        res_bad = ctrl.handle_action("unsupported_scratch_key")
        self.assertFalse(res_bad.get("success"))
        self.assertEqual(res_bad.get("status"), "UNSUPPORTED_MEDIA_ACTION")

    async def test_share_link_scheme_validation(self) -> None:
        """share_link strictly enforces http/https schemes and rejects dangerous schemes."""
        ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP)

        # Valid HTTPS link
        with patch("webbrowser.open", return_value=True):
            req_valid = CapabilityRequest(action="share_link", params={"url": "https://google.com"})
            resp_valid = await self.engine.execute(req_valid, ctx=ctx)
            self.assertTrue(resp_valid.success)
            self.assertEqual(resp_valid.data.get("action"), "opened_browser")

        # Unsafe scheme: javascript
        req_js = CapabilityRequest(action="share_link", params={"url": "javascript:alert(1)"})
        resp_js = await self.engine.execute(req_js, ctx=ctx)
        self.assertFalse(resp_js.success)
        self.assertEqual(resp_js.status, "INVALID_URL_SCHEME")

        # Unsafe scheme: file
        req_file = CapabilityRequest(action="share_link", params={"url": "file:///C:/Windows/System32"})
        resp_file = await self.engine.execute(req_file, ctx=ctx)
        self.assertFalse(resp_file.success)
        self.assertEqual(resp_file.status, "INVALID_URL_SCHEME")

        # Unsafe control characters in URL
        req_crlf = CapabilityRequest(action="share_link", params={"url": "https://example.com/\r\nevil"})
        resp_crlf = await self.engine.execute(req_crlf, ctx=ctx)
        self.assertFalse(resp_crlf.success)
        self.assertEqual(resp_crlf.status, "INVALID_URL_SCHEME")

    async def test_activity_history_capability_query(self) -> None:
        """activity_history capability returns recorded audit entries."""
        self.db.log_activity(event_type="TEST_EVENT", capability="test_cap", outcome="SUCCESS")
        ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP)

        req = CapabilityRequest(action="activity_history", params={"limit": 10})
        resp = await self.engine.execute(req, ctx=ctx)
        self.assertTrue(resp.success)
        events = resp.data.get("events", [])
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "TEST_EVENT")


class TestPillar4TuiLazyImportAndPackaging(unittest.TestCase):
    """Test strict TUI lazy import invariants and optional dependency decoupling."""

    def test_normal_startup_does_not_import_textual(self) -> None:
        """Importing snow.cli or snow.daemon or snow.mcp does NOT import snow.tui.app."""
        # Clean from sys.modules
        sys.modules.pop("snow.tui.app", None)

        import snow.cli
        import snow.daemon
        import snow.mcp.tools

        # Invariant: snow.tui.app must remain unimported
        self.assertNotIn("snow.tui.app", sys.modules, "snow.tui.app was eagerly imported during standard CLI/daemon import!")

    def test_run_ui_deprecated_notice(self) -> None:
        """run_ui outputs deprecation notice directing the user to 'snow web'."""
        from snow.cli import run_ui

        stderr_buf = io.StringIO()
        with patch("sys.stderr", stderr_buf):
            code = run_ui()
            self.assertEqual(code, 0)
            output = stderr_buf.getvalue()
            self.assertIn("retired in favor of the lightweight SNOW Web Dashboard", output)
            self.assertIn("snow web", output)

    def test_subprocess_fresh_process_no_textual_in_core_or_mcp(self) -> None:
        """In fresh Python processes, importing snow.core.server or snow.mcp.server does not load textual/rich."""
        cmd_core = [
            sys.executable, "-c",
            "import sys; import snow.core.server; "
            "assert 'textual' not in sys.modules, f'textual loaded: {sys.modules.get(\"textual\")}'; "
            "assert 'rich' not in sys.modules, f'rich loaded: {sys.modules.get(\"rich\")}'; "
            "assert 'snow.tui' not in sys.modules, 'snow.tui loaded';"
        ]
        res_core = subprocess.run(cmd_core, capture_output=True, text=True, env=dict(os.environ, PYTHONPATH="src"))
        self.assertEqual(res_core.returncode, 0, f"Core import loaded TUI modules: {res_core.stderr}")

        # snow.mcp.server: zero textual, zero snow.tui (rich is pulled only by upstream fastmcp)
        cmd_mcp = [
            sys.executable, "-c",
            "import sys; import snow.mcp.server; "
            "assert 'textual' not in sys.modules, f'textual loaded: {sys.modules.get(\"textual\")}'; "
            "assert 'snow.tui' not in sys.modules, 'snow.tui loaded';"
        ]
        res_mcp = subprocess.run(cmd_mcp, capture_output=True, text=True, env=dict(os.environ, PYTHONPATH="src"))
        self.assertEqual(res_mcp.returncode, 0, f"MCP import loaded TUI modules: {res_mcp.stderr}")


class TestRealLoopbackIpcIntegration(unittest.IsolatedAsyncioTestCase):
    """Integration test proving real authenticated TCP loopback IPC protocol for TUI."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.secret_path = Path(self.tmp_dir.name) / DEFAULT_IPC_SECRET_FILENAME
        self.db_path = Path(self.tmp_dir.name) / "test_ipc.db"
        self.db = DatabaseManager(db_path=self.db_path)

        # Build mock core server with real engine & DB
        self.mock_core = MagicMock()
        self.mock_core.is_running = True
        self.mock_core.config = CoreConfig(
            ipc_host="127.0.0.1",
            ipc_port=0,  # Ephemeral port
            ipc_secret_path=str(self.secret_path),
        )
        self.mock_core.ws_server = MagicMock()
        self.mock_core.ws_server.bound_port = 8765
        self.mock_core.ws_server.live_notifications = {}
        self.mock_core.http_transfer_server = MagicMock()
        self.mock_core.http_transfer_server.bound_port = 8766
        self.mock_core.connection_manager = MagicMock()
        self.mock_core.connection_manager.all_connections.return_value = []
        self.mock_core.db_manager = self.db
        self.mock_core.session_manager = MagicMock()
        self.mock_core.session_manager._sessions = {}
        self.mock_core.capability_engine = CapabilityEngine(db_manager=self.db)

        self.server = SnowIpcServer(self.mock_core, self.mock_core.config)
        await self.server.start()
        self.port = self.server.bound_port
        self.secret = self.server.secret

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        self.tmp_dir.cleanup()

    async def test_real_loopback_ipc_live_query_roundtrip(self) -> None:
        """TUI bridge connects via real raw TCP line-delimited JSON-RPC and queries core."""
        bridge = SnowMcpBridge(
            host="127.0.0.1",
            port=self.port,
            secret=self.secret,
            auto_start_core=False,
        )

        # 1. Device list
        dev_res = await bridge.list_devices()
        self.assertTrue(dev_res.get("success"), f"list_devices failed: {dev_res}")
        self.assertIn(dev_res.get("status"), ("SUCCESS", "ONLINE"))
        self.assertIn("devices", dev_res.get("data", {}))

        # 2. Pending approvals
        app_res = await bridge.call("approval_list")
        self.assertTrue(app_res.get("success"), f"approval_list failed: {app_res}")
        self.assertEqual(app_res.get("status"), "SUCCESS")
        self.assertIn("requests", app_res.get("data", {}))

        # 3. Activity history
        self.db.log_activity(event_type="TUI_IPC_TEST", capability="test", outcome="SUCCESS")
        act_res = await bridge.call("activity_history", payload={"limit": 5})
        self.assertTrue(act_res.get("success"), f"activity_history failed: {act_res}")
        self.assertEqual(act_res.get("status"), "SUCCESS")
        events = act_res.get("data", {}).get("events", [])
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "TUI_IPC_TEST")


if __name__ == "__main__":
    unittest.main()
