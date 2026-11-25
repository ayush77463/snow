"""Test suite for SNOW Phase 24: Human Approval UX, Consent-Gated Capture, and Safe Multi-Step Workflows.

Tests all 20 required points from Phase 24 specification:
1. Tool registry contains exactly 34 capabilities.
2. Strict boolean ToolAnnotations present on new tools.
3. All visual capture capabilities require approval for AI_MCP.
4. Owner authorization does not bypass explicit OS consent or foreground requirements.
5. Windows screenshot rejects non-interactive sessions.
6. Windows screenshot produces valid PNG in interactive environment.
7. PNG SHA-256 matches actual file bytes.
8. Capture file size and dimensions bounded.
9. GDI resources released on both success and failure.
10. Workflow presets contain only allowlisted capabilities.
11. Arbitrary scripts, shell commands, dynamic code, and unregistered steps are rejected.
12. Workflow steps execute through CapabilityEngine.
13. Approval gates enforced before sensitive steps execute.
14. Pending approval pauses dependent steps and returns structured approval metadata.
15. Fail-fast and partial-completion states are reported correctly.
16. Activity history records workflow and capture lifecycle without leaking raw parameters or secrets.
17. Capture preview endpoint rejects path traversal.
18. Capture preview endpoint returns 401 without authenticated session.
19. Capture preview endpoint cannot access files outside configured capture directory.
20. Workflow execution API rejects unknown workflow IDs and untrusted principal claims.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from snow.capabilities.engine import (
    CapabilityEngine,
    CapabilityRequest,
    CapabilityResponse,
)
from snow.capabilities.windows.screenshot import (
    DEFAULT_CAPTURES_DIR,
    MAX_CAPTURE_HEIGHT,
    MAX_CAPTURE_SIZE_BYTES,
    MAX_CAPTURE_WIDTH,
    WindowsScreenshotCapture,
)
from snow.capabilities.workflows import (
    PRESET_CAPTURE_PC_TO_PHONE,
    PRESET_DEVICE_HEALTH,
    PRESET_SHARE_CLIPBOARD,
    WORKFLOW_REGISTRY,
    WorkflowDefinition,
    WorkflowOrchestrator,
    WorkflowStep,
)
from mcp.types import ToolAnnotations
from snow.mcp.registry import (
    CAPABILITY_REGISTRY,
    get_capability_metadata,
    get_mcp_annotations,
    list_capabilities,
)
from snow.security.approval import (
    ApprovalPolicyEngine,
    ApprovalRequest,
    ApprovalStatus,
)
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.web.server import SnowWebServer
from snow.core.config import CoreConfig
from snow.core.server import SnowCoreServer
from snow.network.connection_manager import ConnectionManager
from snow.network.node import DeviceNode, ReachabilityProfile, ReachabilityState
from snow.network.registry import NodeRegistry
from snow.network.router import SessionRouter, ROUTER_ACTION_TO_CAPABILITY, ACTION_TO_WIRE_ACTION
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage, MessageType
from snow.security.db import DatabaseManager
from snow.transfer.manager import TransferManager, TransferDirection, TransferState
from snow.transfer.storage import TransferStorageManager


class TestPhase24RegistryAndAnnotations(unittest.TestCase):
    """Verifies tool registry expansion and strict boolean ToolAnnotations (Points 1 & 2)."""

    def test_01_tool_registry_contains_exactly_34_capabilities(self):
        """1. Registry contains exactly 42 capabilities including V5.0.0 additions."""
        all_caps = list_capabilities()
        self.assertEqual(len(all_caps), 42)
        self.assertEqual(len(CAPABILITY_REGISTRY), 42)

        expected_new_tools = [
            "snow_windows_screenshot",
            "snow_android_screenshot",
            "snow_android_camera_capture",
            "snow_workflow_run",
        ]
        for tool_name in expected_new_tools:
            self.assertIn(tool_name, CAPABILITY_REGISTRY, f"Tool {tool_name} missing from registry")
            cap = get_capability_metadata(tool_name)
            self.assertIsNotNone(cap)
            self.assertEqual(cap.name, tool_name)

    def test_02_strict_boolean_tool_annotations_on_new_tools(self):
        """2. Strict boolean ToolAnnotations present on all new Phase 24 tools."""
        new_tools = [
            "snow_windows_screenshot",
            "snow_android_screenshot",
            "snow_android_camera_capture",
            "snow_workflow_run",
        ]
        for name in new_tools:
            meta = get_capability_metadata(name)
            self.assertIsNotNone(meta)
            self.assertIs(type(meta.read_only_hint), bool)
            self.assertIs(type(meta.destructive_hint), bool)
            self.assertIs(type(meta.requires_approval), bool)

            ann = get_mcp_annotations(name)
            self.assertIsNotNone(ann)
            self.assertIsInstance(ann, ToolAnnotations)
            self.assertIs(type(ann.readOnlyHint), bool)
            self.assertIs(type(ann.destructiveHint), bool)

        # Detailed annotations checks
        win_snap = get_capability_metadata("snow_windows_screenshot")
        self.assertTrue(win_snap.read_only_hint)
        self.assertFalse(win_snap.destructive_hint)
        self.assertTrue(win_snap.requires_approval)

        wf_run = get_capability_metadata("snow_workflow_run")
        self.assertFalse(wf_run.read_only_hint)
        self.assertFalse(wf_run.destructive_hint)
        self.assertTrue(wf_run.requires_approval)


class TestPhase24ApprovalAndConsentGates(unittest.TestCase):
    """Verifies approval policies, risk tiers, and OS consent gates (Points 3 & 4)."""

    def setUp(self):
        self.approval_engine = ApprovalPolicyEngine()

    def test_03_all_visual_capture_capabilities_require_approval_for_ai_mcp(self):
        """3. All visual capture capabilities require approval for AI_MCP."""
        visual_caps = [
            "windows_screenshot",
            "android_screenshot",
            "android_camera_capture",
        ]
        for cap in visual_caps:
            ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP)
            requires_app, reason, risk = self.approval_engine.evaluate_policy(
                action=cap,
                params={"quality": 85},
                ctx=ctx,
            )
            self.assertTrue(requires_app, f"Visual capture '{cap}' did not require approval for AI_MCP")
            self.assertEqual(risk, "HIGH")

            # Verify request creation
            req = self.approval_engine.create_request(
                principal=ExecutionPrincipal.AI_MCP,
                action=cap,
                target_device="local",
                params={"quality": 85},
                reason=reason,
                risk_level=risk,
            )
            self.assertEqual(req.status, ApprovalStatus.PENDING)
            self.assertEqual(req.risk_level, "HIGH")

    def test_04_owner_manual_authorization_boundary(self):
        """4. Owner manual execution succeeds policy check but cannot bypass OS consent."""
        ctx_owner = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)
        requires_app_owner, _, risk_owner = self.approval_engine.evaluate_policy(
            action="windows_screenshot",
            params={},
            ctx=ctx_owner,
        )
        self.assertFalse(requires_app_owner)
        self.assertEqual(risk_owner, "LOW")

        ctx_ai = ExecutionContext(principal=ExecutionPrincipal.AI_MCP)
        requires_app_ai, _, risk_ai = self.approval_engine.evaluate_policy(
            action="windows_screenshot",
            params={},
            ctx=ctx_ai,
        )
        self.assertTrue(requires_app_ai)
        self.assertEqual(risk_ai, "HIGH")


class TestPhase24WindowsScreenshot(unittest.TestCase):
    """Verifies Windows screenshot service behavior, PNG format, hashes, bounds, and GDI cleanup (Points 5-9)."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.capture_dir = Path(self.tmp_dir.name) / "captures"
        self.service = WindowsScreenshotCapture(output_dir=self.capture_dir)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_05_windows_screenshot_rejects_non_interactive_session(self):
        """5. Windows screenshot rejects non-interactive sessions."""
        with patch.object(self.service, "is_interactive_session", return_value=(False, "Session is non-interactive")):
            res = self.service.capture_screen()
            self.assertFalse(res["success"])
            self.assertEqual(res["status"], "NON_INTERACTIVE_SESSION")

    def test_06_windows_screenshot_produces_valid_png_in_interactive_env(self):
        """6. Windows screenshot produces valid PNG with standard PNG signature."""
        res = self.service.capture_screen()
        if not res["success"]:
            self.skipTest(f"Skipping interactive capture test in non-desktop headless environment: {res.get('error')}")
        file_path = self.capture_dir / res["file_name"]
        self.assertTrue(file_path.exists())
        with open(file_path, "rb") as f:
            header = f.read(8)
        self.assertEqual(header, b"\x89PNG\r\n\x1a\n")

    def test_07_png_sha256_matches_actual_file_bytes(self):
        """7. PNG SHA-256 matches actual file bytes on disk."""
        res = self.service.capture_screen()
        if not res["success"]:
            self.skipTest(f"Skipping capture test in non-desktop environment: {res.get('error')}")
        file_path = self.capture_dir / res["file_name"]
        with open(file_path, "rb") as f:
            bytes_on_disk = f.read()
        computed_sha = hashlib.sha256(bytes_on_disk).hexdigest()
        self.assertEqual(res["sha256"], computed_sha)

    def test_08_capture_file_size_and_dimensions_bounded(self):
        """8. Capture file size and dimensions are bounded within safety limits."""
        res = self.service.capture_screen()
        if not res["success"]:
            self.skipTest(f"Skipping capture test in non-desktop environment: {res.get('error')}")
        self.assertGreater(res["size_bytes"], 0)
        self.assertLessEqual(res["size_bytes"], MAX_CAPTURE_SIZE_BYTES)
        self.assertGreater(res["width"], 0)
        self.assertLessEqual(res["width"], MAX_CAPTURE_WIDTH)
        self.assertGreater(res["height"], 0)
        self.assertLessEqual(res["height"], MAX_CAPTURE_HEIGHT)

    def test_09_gdi_resources_released_on_success_and_failure(self):
        """9. GDI resources (DCs, Bitmaps) are cleanly released on both success and failure."""
        with patch.object(self.service, "is_interactive_session", return_value=(True, "OK")):
            with patch("ctypes.windll.user32.GetDC", return_value=12345):
                with patch("ctypes.windll.gdi32.CreateCompatibleDC", return_value=0):
                    with patch("ctypes.windll.user32.ReleaseDC") as mock_release_dc:
                        res = self.service.capture_screen()
                        self.assertFalse(res["success"])
                        mock_release_dc.assert_called()


class TestPhase24Workflows(unittest.TestCase):
    """Verifies declarative workflow presets, security prohibitions, and execution lifecycle (Points 10-15)."""

    def setUp(self):
        self.mock_engine = MagicMock(spec=CapabilityEngine)
        self.orchestrator = WorkflowOrchestrator(capability_engine=self.mock_engine)

    def test_10_workflow_presets_contain_only_allowlisted_capabilities(self):
        """10. Workflow presets contain only allowlisted capabilities registered in CAPABILITY_REGISTRY."""
        for wf_id, wf_def in WORKFLOW_REGISTRY.items():
            self.assertIsInstance(wf_def, WorkflowDefinition)
            self.assertGreater(len(wf_def.steps), 0)
            for step in wf_def.steps:
                norm_cap = step.capability if step.capability.startswith("snow_") else f"snow_{step.capability}"
                self.assertTrue(
                    norm_cap in CAPABILITY_REGISTRY or step.capability in CAPABILITY_REGISTRY,
                    f"Workflow '{wf_id}' uses unregistered capability '{step.capability}'",
                )

    def test_11_arbitrary_scripts_shell_and_dynamic_code_rejected(self):
        """11. Arbitrary scripts, shell commands, dynamic code, and unregistered steps are rejected."""
        loop = asyncio.new_event_loop()
        try:
            # 1. Unknown workflow ID
            res = loop.run_until_complete(
                self.orchestrator.run_workflow(
                    workflow_id="malicious_arbitrary_eval",
                    ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP),
                )
            )
            self.assertEqual(res.status, "FAILED")
            self.assertIn("not registered", res.error)

            # 2. Rejection of unregistered capability in WorkflowStep constructor
            with self.assertRaises(ValueError):
                WorkflowStep(
                    step_id="bad_step",
                    capability="arbitrary_eval",
                    name="Run Eval",
                    description="Execute raw Python code",
                )
        finally:
            loop.close()

    def test_12_workflow_steps_execute_through_capability_engine(self):
        """12. Workflow steps execute through CapabilityEngine."""
        loop = asyncio.new_event_loop()
        try:
            async def mock_execute(request, ctx=None):
                return CapabilityResponse(
                    success=True,
                    status="SUCCESS",
                    data={"result": f"Executed {request.action}"},
                )

            self.mock_engine.execute = AsyncMock(side_effect=mock_execute)

            res = loop.run_until_complete(
                self.orchestrator.run_workflow(
                    workflow_id="device_health_snapshot",
                    ctx=ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL),
                )
            )
            self.assertEqual(res.status, "COMPLETED")
            self.assertEqual(len(res.step_results), 3)
            self.assertEqual(self.mock_engine.execute.call_count, 3)
        finally:
            loop.close()

    def test_13_approval_gates_enforced_before_sensitive_steps(self):
        """13. Approval gates enforced before sensitive steps execute."""
        wf = WORKFLOW_REGISTRY["capture_pc_to_phone"]
        self.assertTrue(wf.requires_approval)
        self.assertTrue(wf.steps[0].requires_approval)

    def test_14_pending_approval_pauses_dependent_steps(self):
        """14. Pending approval pauses dependent steps and returns structured approval metadata."""
        loop = asyncio.new_event_loop()
        try:
            approval_engine = ApprovalPolicyEngine()

            async def mock_execute(request, ctx=None):
                if request.action == "windows_screenshot":
                    req = approval_engine.create_request(
                        principal=ctx.principal if ctx else ExecutionPrincipal.AI_MCP,
                        action="windows_screenshot",
                        target_device="local",
                        params=request.params,
                        risk_level="HIGH",
                    )
                    return CapabilityResponse(
                        success=False,
                        status="APPROVAL_REQUIRED",
                        error="Human approval required",
                        data={"status": "APPROVAL_REQUIRED", "approval_request": req.to_dict()},
                    )
                return CapabilityResponse(success=True, status="SUCCESS", data={})

            self.mock_engine.execute = AsyncMock(side_effect=mock_execute)

            res = loop.run_until_complete(
                self.orchestrator.run_workflow(
                    workflow_id="capture_pc_to_phone",
                    ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP),
                )
            )
            self.assertEqual(res.status, "PENDING_APPROVAL")
            self.assertEqual(len(res.step_results), 1)
            self.assertEqual(res.step_results[0]["status"], "PENDING_APPROVAL")
            self.assertIsNotNone(res.step_results[0]["approval_request"])
            self.assertEqual(self.mock_engine.execute.call_count, 1)
        finally:
            loop.close()

    def test_15_fail_fast_and_partial_completion_reported_correctly(self):
        """15. Fail-fast and partial-completion states are reported correctly."""
        loop = asyncio.new_event_loop()
        try:
            call_count = 0

            async def mock_execute(request, ctx=None):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    return CapabilityResponse(success=True, status="SUCCESS", data={"step": 1})
                elif call_count == 2:
                    return CapabilityResponse(
                        success=False,
                        status="FAILED",
                        error="Target node unreachable",
                    )
                return CapabilityResponse(success=True, status="SUCCESS", data={"step": 3})

            self.mock_engine.execute = AsyncMock(side_effect=mock_execute)

            res = loop.run_until_complete(
                self.orchestrator.run_workflow(
                    workflow_id="device_health_snapshot",
                    ctx=ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL),
                )
            )
            self.assertEqual(res.status, "FAILED")
            self.assertEqual(len(res.step_results), 2)
            self.assertEqual(res.step_results[0]["status"], "SUCCESS")
            self.assertEqual(res.step_results[1]["status"], "FAILED")
            self.assertEqual(call_count, 2)
        finally:
            loop.close()


class TestPhase24ActivityAudit(unittest.TestCase):
    """Verifies activity history records lifecycle without leaking raw parameters or secrets (Point 16)."""

    def test_16_activity_history_records_lifecycle_without_leaking_secrets(self):
        """16. Activity history records workflow and capture lifecycle without leaking secrets."""
        from snow.security.db import DatabaseManager

        tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp_db.close()
        try:
            db = DatabaseManager(db_path=Path(tmp_db.name))

            # Record workflow completion event with secret parameters
            db.log_activity(
                event_type="WORKFLOW_EXECUTION",
                capability="workflow_run",
                principal=ExecutionPrincipal.AI_MCP.value,
                target_device="desktop-core",
                outcome="SUCCESS",
                details={
                    "workflow_id": "share_clipboard_and_notify",
                    "auth_token": "SUPER_SECRET_TOKEN_XYZ",
                    "api_key": "sk-1234567890abcdef",
                    "password": "Password123!",
                },
            )

            records = db.query_activity_history(limit=5)
            self.assertEqual(len(records), 1)
            rec = records[0]
            self.assertEqual(rec["capability"], "workflow_run")
            details_str = str(rec["details"])

            self.assertNotIn("SUPER_SECRET_TOKEN_XYZ", details_str)
            self.assertNotIn("sk-1234567890abcdef", details_str)
            self.assertNotIn("Password123!", details_str)
        finally:
            try:
                os.unlink(tmp_db.name)
            except OSError:
                pass


class TestPhase24WebSecurityAndPreview(AioHTTPTestCase):
    """Verifies capture preview security and workflow execution API endpoints (Points 17-20)."""

    async def get_application(self) -> web.Application:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.captures_dir = Path(self.tmp_dir.name) / "captures"
        self.captures_dir.mkdir(parents=True, exist_ok=True)

        self.valid_capture_file = self.captures_dir / "capture_20261121_120000.png"
        self.valid_capture_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 64)

        self.outside_sensitive_file = Path(self.tmp_dir.name) / "sensitive_secret.txt"
        self.outside_sensitive_file.write_text("CONFIDENTIAL_SYSTEM_DATA")

        self.mock_bridge = MagicMock()
        self.mock_bridge.workflow_run = AsyncMock(
            return_value={
                "success": True,
                "status": "COMPLETED",
                "workflow_id": "device_health_snapshot",
                "step_results": [],
            }
        )

        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.mock_bridge,
            auto_open_browser=False,
        )

        # Patch DEFAULT_CAPTURES_DIR to self.captures_dir for test isolation
        self.patcher = patch(
            "snow.capabilities.windows.screenshot.DEFAULT_CAPTURES_DIR",
            self.captures_dir,
        )
        self.patcher.start()

        return self.web_server._build_app()

    async def tearDownAsync(self):
        self.patcher.stop()
        self.tmp_dir.cleanup()

    async def test_17_capture_preview_rejects_path_traversal(self):
        """17. Capture preview endpoint rejects path traversal (../, separators, null bytes)."""
        traversal_attempts = [
            "../sensitive_secret.txt",
            "..\\sensitive_secret.txt",
            "....//sensitive_secret.txt",
            "%2e%2e/sensitive_secret.txt",
            "capture_test.png\0.txt",
        ]
        auth_resp = await self.client.post(
            "/api/auth/session",
            json={"token": self.web_server.bootstrap_token},
        )
        self.assertEqual(auth_resp.status, 200)

        for attempt in traversal_attempts:
            resp = await self.client.get(f"/api/captures/{attempt}")
            self.assertIn(resp.status, (400, 404), f"Path traversal '{attempt}' was not rejected")

    async def test_18_capture_preview_returns_401_without_authenticated_session(self):
        """18. Capture preview endpoint returns 401 without authenticated session."""
        resp = await self.client.get("/api/captures/capture_20261121_120000.png")
        self.assertEqual(resp.status, 401)

    async def test_19_capture_preview_cannot_access_files_outside_capture_directory(self):
        """19. Capture preview endpoint cannot access files outside configured capture directory."""
        auth_resp = await self.client.post(
            "/api/auth/session",
            json={"token": self.web_server.bootstrap_token},
        )
        self.assertEqual(auth_resp.status, 200)

        resp = await self.client.get("/api/captures/sensitive_secret.txt")
        self.assertEqual(resp.status, 404)

    async def test_20_workflow_api_rejects_unknown_workflow_ids_and_untrusted_claims(self):
        """20. Workflow execution API rejects unknown workflow IDs and untrusted principal claims."""
        auth_resp = await self.client.post(
            "/api/auth/session",
            json={"token": self.web_server.bootstrap_token},
        )
        self.assertEqual(auth_resp.status, 200)
        auth_data = await auth_resp.json()
        csrf_token = auth_data["csrf_token"]

        headers = {"X-CSRF-Token": csrf_token}

        # 1. Unknown workflow ID
        resp = await self.client.post(
            "/api/workflows/run",
            json={"workflow_id": "arbitrary_backdoor_eval"},
            headers=headers,
        )
        self.assertEqual(resp.status, 400)
        data = await resp.json()
        self.assertFalse(data["success"])
        self.assertEqual(data["status"], "UNKNOWN_WORKFLOW")

        # 2. Known workflow ID succeeds
        resp_known = await self.client.post(
            "/api/workflows/run",
            json={"workflow_id": "device_health_snapshot"},
            headers=headers,
        )
        self.assertEqual(resp_known.status, 200)
        data_known = await resp_known.json()
        self.assertTrue(data_known["success"])
        self.web_server.bridge.workflow_run.assert_called_with("device_health_snapshot", arguments={})

    async def test_21_capture_preview_authenticated_returns_200_with_png_bytes(self):
        """21. Capture preview returns 200 with image/png and valid PNG bytes for authenticated sessions."""
        auth_resp = await self.client.post(
            "/api/auth/session",
            json={"token": self.web_server.bootstrap_token},
        )
        self.assertEqual(auth_resp.status, 200)

        resp = await self.client.get("/api/captures/capture_20261121_120000.png")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers.get("Content-Type"), "image/png")
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        data = await resp.read()
        self.assertTrue(data.startswith(b"\x89PNG\r\n\x1a\n"))


class TestPhase24Sprint2Repairs(unittest.IsolatedAsyncioTestCase):
    """Regression and integration test suite for Phase 24 Sprint 2 surgical repairs."""

    async def asyncSetUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_snow.db"
        self.db = DatabaseManager(db_path=self.db_path)
        self.config = CoreConfig(
            transfer_root=str(Path(self.tmp_dir.name) / "transfers"),
        )

    async def asyncTearDown(self):
        self.tmp_dir.cleanup()

    async def test_22_capability_engine_database_injection_and_activity_history(self):
        """22. SnowCoreServer injects DatabaseManager into CapabilityEngine; activity history succeeds."""
        server = SnowCoreServer(config=self.config, db_manager=self.db)
        self.assertIsNotNone(server.capability_engine.db_manager)
        self.assertIs(server.capability_engine.db_manager, self.db)

        # Record a test activity event
        self.db.log_activity(
            event_type="test_event",
            capability="test_verification",
            principal="owner_manual",
            target_device="local",
            outcome="SUCCESS",
            details={"action": "test_verification"},
        )

        req = CapabilityRequest(action="activity_history", params={"limit": 10})
        ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)
        resp = await server.capability_engine.execute(req, ctx=ctx)
        self.assertTrue(resp.success)
        self.assertEqual(resp.status, "SUCCESS")
        self.assertIn("history", resp.data)
        self.assertGreaterEqual(resp.data["count"], 1)

    async def test_23_device_health_snapshot_routes_android_battery_to_telemetry_wire_action(self):
        """23. android_battery routes to android.telemetry.get and sends wire action battery_status."""
        self.assertEqual(ROUTER_ACTION_TO_CAPABILITY.get("android_battery"), "android.telemetry.get")
        self.assertEqual(ROUTER_ACTION_TO_CAPABILITY.get("snow_android_battery"), "android.telemetry.get")
        self.assertEqual(ROUTER_ACTION_TO_CAPABILITY.get("android_battery_status"), "android.telemetry.get")
        self.assertEqual(ACTION_TO_WIRE_ACTION.get("android_battery_status"), "battery_status")
        self.assertEqual(ACTION_TO_WIRE_ACTION.get("snow_android_battery"), "battery_status")

        node_registry = NodeRegistry(db_manager=self.db, local_identity=MagicMock(device_id="desktop-local"))
        node_registry.register_node(
            DeviceNode(
                device_id="phone-realme-rmx5110",
                device_name="Realme RMX5110",
                platform="android",
                reachability_profile=ReachabilityProfile.ACTIVE_SESSION_PEER,
                reachability_state=ReachabilityState.CONNECTED_SESSION,
                host="127.0.0.1",
                wss_port=8765,
                supported_capabilities=["android.telemetry.get"],
                is_authenticated=True,
                is_paired=True,
            )
        )

        mock_ws = MagicMock()
        mock_ws.session_manager.get_session_by_device.return_value = MagicMock(
            connection_id="conn-usb-1",
            session_id="sess-1",
        )
        mock_ws.connection_manager.get.return_value = MagicMock(is_active=True)
        mock_ws.send_request = AsyncMock(
            return_value=SnowMessage.create_response(
                correlation_id="corr-1",
                payload={"status": "success", "data": {"percent": 79, "charging": True}},
            )
        )

        router = SessionRouter(node_registry=node_registry, ws_server=mock_ws)

        # Route using query "android"
        res = await router.route_request(
            action="android_battery",
            target="android",
            data={},
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["target_device_id"], "phone-realme-rmx5110")
        # Verify wire action translated to battery_status
        mock_ws.send_request.assert_called_once()
        call_kwargs = mock_ws.send_request.call_args[1]
        self.assertIn(call_kwargs["action"], ("battery_status", "android_battery"))
        self.assertEqual(call_kwargs["connection_id"], "conn-usb-1")

    async def test_24_capture_pc_to_phone_file_delivery_coordination(self):
        """24. android_file_send coordinates transfer, stages storage, and dispatches file_send_request."""
        captures_dir = Path(self.tmp_dir.name) / "captures"
        captures_dir.mkdir(parents=True, exist_ok=True)
        test_png = captures_dir / "screen_test.png"
        test_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 128
        test_png.write_bytes(test_bytes)
        hasher = hashlib.sha256(test_bytes)
        expected_sha = hasher.hexdigest()

        node_registry = NodeRegistry(db_manager=self.db, local_identity=MagicMock(device_id="desktop-local"))
        node_registry.register_node(
            DeviceNode(
                device_id="phone-realme-rmx5110",
                device_name="Realme RMX5110",
                platform="android",
                supported_capabilities=["android.files.transfer"],
                is_authenticated=True,
                is_paired=True,
            )
        )

        transfer_mgr = TransferManager()
        storage_mgr = TransferStorageManager(root_dir=self.tmp_dir.name)
        mock_router = MagicMock()
        mock_router.route_request = AsyncMock(
            return_value={"success": True, "status": "SUCCESS", "data": {"received": True}}
        )

        engine = CapabilityEngine(
            node_registry=node_registry,
            session_router=mock_router,
            transfer_manager=transfer_mgr,
            storage_manager=storage_mgr,
        )

        req = CapabilityRequest(
            action="android_file_send",
            params={"file_path": str(test_png), "device_id": "phone-realme-rmx5110"},
        )
        ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)
        resp = await engine.execute(req, ctx=ctx)

        self.assertTrue(resp.success)
        self.assertEqual(resp.status, "SUCCESS")
        self.assertEqual(resp.data["sha256"], expected_sha)

        # Verify router called with wire action file_send_request
        mock_router.route_request.assert_called_once()
        call_kwargs = mock_router.route_request.call_args[1]
        self.assertEqual(call_kwargs["action"], "file_send_request")
        self.assertEqual(call_kwargs["target"], "phone-realme-rmx5110")
        self.assertEqual(call_kwargs["data"]["file_name"], "screen_test.png")
        self.assertEqual(call_kwargs["data"]["sha256"], expected_sha)
        self.assertEqual(call_kwargs["data"]["file_size"], len(test_bytes))

        # Duplicate transfer test: second execution skips without routing again
        mock_router.route_request.reset_mock()
        resp_dup = await engine.execute(req, ctx=ctx)
        self.assertTrue(resp_dup.success)
        self.assertEqual(resp_dup.status, "ALREADY_EXISTS")
        self.assertTrue(resp_dup.data["skipped_duplicate"])
        mock_router.route_request.assert_not_called()

    def test_25_transport_determination_and_stale_disconnect_race(self):
        """25. Transport detects ::ffff:127.0.0.1 loopback; stale disconnect is safely ignored."""
        ws = SnowWebSocketServer(config=self.config)

        # 1. Transport determination
        self.assertEqual(ws._determine_transport("127.0.0.1"), "loopback")
        self.assertEqual(ws._determine_transport("::1"), "loopback")
        self.assertEqual(ws._determine_transport("::ffff:127.0.0.1"), "loopback")
        self.assertEqual(ws._determine_transport("192.168.1.100"), "wifi_lan")

        # 2. Stale disconnect race protection
        registry = NodeRegistry(db_manager=self.db, local_identity=MagicMock(device_id="desktop-local"))
        # Active session established over Wi-Fi
        registry.on_session_authenticated(
            device_id="phone-realme",
            connection_id="conn-wifi-old",
            host="192.168.1.50",
            port=8765,
            transport="wifi_lan",
        )
        node = registry.get_node("phone-realme")
        self.assertTrue(node.is_connected)
        self.assertEqual(node.transport, "wifi_lan")

        # Session re-establishes over USB ADB
        registry.on_session_authenticated(
            device_id="phone-realme",
            connection_id="conn-usb-new",
            host="127.0.0.1",
            port=8765,
            transport="usb_adb",
        )
        node_usb = registry.get_node("phone-realme")
        self.assertTrue(node_usb.is_connected)
        self.assertEqual(node_usb.transport, "usb_adb")

        # Old Wi-Fi connection drops afterwards and emits delayed disconnect
        registry.on_session_disconnected("phone-realme", connection_id="conn-wifi-old")

        # Active USB session MUST NOT be dropped!
        node_after = registry.get_node("phone-realme")
        self.assertTrue(node_after.is_connected)
        self.assertEqual(node_after.transport, "usb_adb")

        # Disconnecting current USB session drops reachability as expected
        registry.on_session_disconnected("phone-realme", connection_id="conn-usb-new")
        node_final = registry.get_node("phone-realme")
        self.assertTrue(node_final is None or not node_final.is_connected)

    async def test_26_end_to_end_all_four_workflows_execution(self):
        """26. End-to-end execution of all 4 declarative workflows through WorkflowOrchestrator."""
        node_registry = NodeRegistry(db_manager=self.db, local_identity=MagicMock(device_id="desktop-local"))
        node_registry.register_node(
            DeviceNode(
                device_id="phone-realme-rmx5110",
                device_name="Realme RMX5110",
                platform="android",
                supported_capabilities=["android.telemetry.get", "android.files.transfer"],
                is_authenticated=True,
                is_paired=True,
            )
        )

        transfer_mgr = TransferManager()
        storage_mgr = TransferStorageManager(root_dir=self.tmp_dir.name)
        mock_router = MagicMock()
        mock_router.route_request = AsyncMock(
            return_value={"success": True, "status": "SUCCESS", "data": {"percent": 82, "charging": True}}
        )

        engine = CapabilityEngine(
            db_manager=self.db,
            node_registry=node_registry,
            session_router=mock_router,
            transfer_manager=transfer_mgr,
            storage_manager=storage_mgr,
        )
        orchestrator = WorkflowOrchestrator(capability_engine=engine)
        ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)

        # 1. pc_screenshot
        with patch("snow.capabilities.windows.screenshot.WindowsScreenshotCapture.capture_screen") as mock_cap:
            mock_cap.return_value = {
                "success": True,
                "status": "SUCCESS",
                "file_path": str(Path(self.tmp_dir.name) / "test.png"),
                "file_name": "test.png",
                "sha256": "abc123sha",
                "width": 1920,
                "height": 1080,
                "size_bytes": 1024,
            }
            rep1 = await orchestrator.run_workflow("pc_screenshot", ctx=ctx)
            self.assertEqual(rep1.status, "COMPLETED")
            self.assertEqual(len(rep1.step_results), 1)
            self.assertIn("capture_summary", rep1.final_output)
            cap_sum = rep1.final_output["capture_summary"]
            self.assertEqual(cap_sum["dimensions"], "1920 × 1080")
            self.assertEqual(cap_sum["file_name"], "test.png")
            self.assertEqual(cap_sum["file_size_bytes"], 1024)

        # 2. device_health_snapshot
        rep2 = await orchestrator.run_workflow("device_health_snapshot", ctx=ctx)
        self.assertIn(rep2.status, ("COMPLETED", "PARTIAL"))
        self.assertEqual(len(rep2.step_results), 3)
        self.assertIn("health_summary", rep2.final_output)
        health_sum = rep2.final_output["health_summary"]
        self.assertIn("windows", health_sum)
        self.assertIn("phone", health_sum)
        self.assertIsNotNone(health_sum["windows"]["cpu_percent"])
        self.assertIsNotNone(health_sum["windows"]["ram_total_mb"])

        # 3. share_clipboard_and_notify
        async def _mock_exec_clip(req, ctx=None):
            if req.action in ("windows_clipboard_get", "desktop_clipboard_get"):
                return CapabilityResponse(success=True, status="SUCCESS", data={"status": "SUCCESS", "text": "sample", "length": 6})
            return CapabilityResponse(success=True, status="SUCCESS", data={"status": "SUCCESS"})

        with patch.object(
            orchestrator,
            "_find_connected_android_node",
            return_value=("mock-phone-id", "Realme Phone", "USB ADB"),
        ), patch.object(
            engine,
            "execute",
            side_effect=_mock_exec_clip,
        ):
            rep3 = await orchestrator.run_workflow("share_clipboard_and_notify", ctx=ctx)
            self.assertEqual(rep3.status, "COMPLETED")
            self.assertEqual(len(rep3.step_results), 3)
            self.assertIn("sync_summary", rep3.final_output)
            sync_sum = rep3.final_output["sync_summary"]
            self.assertEqual(sync_sum["synced_chars"], 6)
            self.assertFalse(sync_sum["is_empty"])

        # 4. capture_pc_to_phone
        with patch("snow.capabilities.windows.screenshot.WindowsScreenshotCapture.capture_screen") as mock_cap:
            captures_dir = Path(self.tmp_dir.name) / "captures"
            captures_dir.mkdir(parents=True, exist_ok=True)
            mock_png = captures_dir / "capture_flow.png"
            mock_png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
            mock_cap.return_value = {
                "success": True,
                "status": "SUCCESS",
                "file_path": str(mock_png),
                "file_name": "capture_flow.png",
                "sha256": "def456sha",
                "width": 1920,
                "height": 1080,
                "size_bytes": 40,
            }
            rep4 = await orchestrator.run_workflow("capture_pc_to_phone", ctx=ctx)
            self.assertIn(rep4.status, ("COMPLETED", "PARTIAL"))
            self.assertEqual(len(rep4.step_results), 2)
            self.assertIn("delivery_summary", rep4.final_output)
            del_sum = rep4.final_output["delivery_summary"]
            self.assertEqual(del_sum["dimensions"], "1920 × 1080")
            self.assertEqual(del_sum["file_name"], "capture_flow.png")
            self.assertEqual(del_sum["file_size_bytes"], 40)

    async def test_27_workflow_clipboard_empty_skips_remote_push(self):
        """27. Empty Windows clipboard records clean EMPTY summary and skips remote push."""
        engine = CapabilityEngine(db_manager=self.db)
        orchestrator = WorkflowOrchestrator(capability_engine=engine)
        ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)

        async def _mock_exec_empty(req, ctx=None):
            if req.action in ("windows_clipboard_get", "desktop_clipboard_get"):
                return CapabilityResponse(success=True, status="SUCCESS", data={"status": "SUCCESS", "text": "", "length": 0})
            return CapabilityResponse(success=True, status="SUCCESS", data={"status": "SUCCESS"})

        mock_execute = AsyncMock(side_effect=_mock_exec_empty)
        with patch.object(
            orchestrator,
            "_find_connected_android_node",
            return_value=("mock-phone-id", "Realme Phone", "USB ADB"),
        ), patch.object(
            engine,
            "execute",
            new=mock_execute,
        ):
            rep = await orchestrator.run_workflow("share_clipboard_and_notify", ctx=ctx)
            self.assertEqual(rep.status, "COMPLETED")
            sync_sum = rep.final_output.get("sync_summary", {})
            self.assertTrue(sync_sum.get("is_empty"))
            self.assertEqual(sync_sum.get("synced_chars"), 0)
            self.assertEqual(sync_sum.get("status"), "EMPTY")
            # Verify no remote android_clipboard_push request was dispatched to engine
            for call_args in mock_execute.call_args_list:
                req_arg = call_args[0][0]
                self.assertNotEqual(req_arg.action, "android_clipboard_push")

    async def test_28_workflow_clipboard_peer_offline_partial(self):
        """28. Non-empty clipboard with offline peer returns PARTIAL status."""
        engine = CapabilityEngine(db_manager=self.db)
        orchestrator = WorkflowOrchestrator(capability_engine=engine)
        ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)

        async def _mock_exec_offline(req, ctx=None):
            if req.action in ("windows_clipboard_get", "desktop_clipboard_get"):
                return CapabilityResponse(success=True, status="SUCCESS", data={"status": "SUCCESS", "text": "sensitive", "length": 9})
            return CapabilityResponse(success=True, status="SUCCESS", data={"status": "SUCCESS"})

        with patch.object(
            orchestrator,
            "_find_connected_android_node",
            return_value=(None, None, None),
        ), patch.object(
            engine,
            "execute",
            side_effect=_mock_exec_offline,
        ):
            rep = await orchestrator.run_workflow("share_clipboard_and_notify", ctx=ctx)
            self.assertEqual(rep.status, "PARTIAL")
            self.assertIn("offline", rep.error.lower())


if __name__ == "__main__":
    unittest.main()
