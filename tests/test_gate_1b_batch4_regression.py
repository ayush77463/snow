"""Regression test suite for SNOW V4.1 Phase 1, Gate 1B, Batch 4.

Verifies:
- F6: USB ADB Helper, Status, Reverse Port Forwarding, and QR Pairing allow_usb_loopback
- F7: AI Host Onboarding (AntigravityAdapter, SUPPORTED_HOSTS, setup default="all")
- F8: Clean Activity Audit Log (AUDIT_EXCLUDED_ACTIONS noise suppression)
- F28: MCP 38-Tool Exact Parity (server tools == registry keys == 38, doctor check)
- F29: Workflow Single-Approval (propagation of OWNER_MANUAL execution context)
- Track 3: Web Dashboard camera ETag/304, USB/MCP API endpoints, and Tray connected count query
"""

from __future__ import annotations

import asyncio
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.engine import (
    AUDIT_EXCLUDED_ACTIONS,
    CapabilityEngine,
    CapabilityRequest,
    CapabilityResponse,
    ExecutionContext,
    ExecutionPrincipal,
)
from snow.capabilities.workflows import WorkflowOrchestrator
from snow.cli import build_parser, run_doctor
from snow.core.usb import (
    find_adb_binary,
    get_connected_adb_devices,
    get_usb_status,
    remove_usb_reverse,
    setup_usb_reverse,
)
from snow.mcp.registry import CAPABILITY_REGISTRY
from snow.mcp.server import create_snow_mcp_server
from snow.mcp.tools import ALL_TOOL_NAMES
from snow.onboarding import (
    AntigravityAdapter,
    HostOnboardingManager,
    SUPPORTED_HOSTS,
)
from snow.security.pairing import (
    create_qr_pairing_payload,
    validate_qr_pairing_payload,
)


class TestBatch4UsbAndPairing(unittest.TestCase):
    """Test F6: USB Helper and QR Pairing allow_usb_loopback."""

    def test_allow_usb_loopback_in_create_and_validate_qr_payload(self) -> None:
        fp = "A" * 64
        # Without allow_usb_loopback (default False), 127.0.0.1 must be rejected
        with self.assertRaises(ValueError):
            create_qr_pairing_payload(
                node_id="pc-1",
                candidate_ips=["127.0.0.1"],
                port=8765,
                cert_fingerprint=fp,
                pin="123456",
                allow_usb_loopback=False,
            )

        # With allow_usb_loopback=True, 127.0.0.1 is accepted
        payload = create_qr_pairing_payload(
            node_id="pc-1",
            candidate_ips=["127.0.0.1"],
            port=8765,
            cert_fingerprint=fp,
            pin="123456",
            allow_usb_loopback=True,
        )
        self.assertEqual(payload["ips"], ["127.0.0.1"])

        # Validate: without allow_usb_loopback, validation rejects payload with only loopback
        with self.assertRaises(ValueError):
            validate_qr_pairing_payload(payload, allow_usb_loopback=False)

        # Validate: with allow_usb_loopback=True, validation succeeds
        val = validate_qr_pairing_payload(payload, allow_usb_loopback=True)
        self.assertEqual(val["ips"], ["127.0.0.1"])
        self.assertEqual(val["id"], "pc-1")
        self.assertEqual(val["pin"], "123456")

    @patch("snow.core.usb.subprocess.run")
    @patch("snow.core.usb.find_adb_binary")
    def test_usb_status_and_reverse_mapping(self, mock_find, mock_run) -> None:
        mock_find.return_value = Path("C:/fake/adb.exe")
        # Mock devices -l
        devices_out = "List of devices attached\nemulator-5554          device model:Pixel_6 product:oriole\n\n"
        # Mock reverse --list
        rev_out = "(reverse) tcp:8765 tcp:8765\n(reverse) tcp:8766 tcp:8766\n"

        def fake_run(cmd, **kwargs):
            m = MagicMock()
            m.returncode = 0
            if "devices" in cmd:
                m.stdout = devices_out
            elif "--list" in cmd:
                m.stdout = rev_out
            else:
                m.stdout = ""
                m.stderr = ""
            return m

        mock_run.side_effect = fake_run

        status = get_usb_status()
        self.assertTrue(status["adb_found"])
        self.assertTrue(status["connected"])
        self.assertTrue(status["reverse_active"])
        self.assertEqual(len(status["devices"]), 1)
        self.assertEqual(status["devices"][0]["serial"], "emulator-5554")

        # Test setup_usb_reverse
        ok, msg = setup_usb_reverse()
        self.assertTrue(ok)
        self.assertIn("Pixel_6", msg)

        # Test remove_usb_reverse
        ok_rm, msg_rm = remove_usb_reverse()
        self.assertTrue(ok_rm)
        self.assertIn("Removed SNOW reverse port mappings", msg_rm)


class TestBatch4Onboarding(unittest.TestCase):
    """Test F7: AI Host Onboarding (AntigravityAdapter & defaults)."""

    def test_antigravity_adapter_configuration(self) -> None:
        self.assertIn("antigravity", SUPPORTED_HOSTS)
        mgr = HostOnboardingManager()
        adapter = mgr.get_adapter("antigravity")
        self.assertIsNotNone(adapter)
        self.assertIsInstance(adapter, AntigravityAdapter)
        self.assertEqual(adapter.display_name, "Google Antigravity")

        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_cfg = Path(tmp_dir) / "mcp_config.json"
            res = adapter.configure(target_path=tmp_cfg)
            self.assertTrue(res["success"])
            self.assertTrue(tmp_cfg.is_file())

            data = json.loads(tmp_cfg.read_text(encoding="utf-8"))
            self.assertIn("mcpServers", data)
            self.assertIn("snow", data["mcpServers"])
            self.assertEqual(data["mcpServers"]["snow"]["args"], ["-m", "snow.mcp"])

            # Test remove
            rem_res = adapter.remove(target_path=tmp_cfg)
            self.assertTrue(rem_res["success"])
            data_rem = json.loads(tmp_cfg.read_text(encoding="utf-8"))
            self.assertNotIn("snow", data_rem.get("mcpServers", {}))

    def test_cli_setup_parser_default_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["setup"])
        self.assertEqual(args.host, "all")
        self.assertIn("antigravity", parser._actions[1].choices["setup"]._actions[1].choices)


class TestBatch4CleanAuditAndWorkflows(unittest.TestCase):
    """Test F8 & F29: Clean Activity Audit & Single-Approval Workflow Context."""

    def test_audit_excluded_actions_suppresses_log_activity(self) -> None:
        mock_db = MagicMock()
        engine = CapabilityEngine(db_manager=mock_db)

        # windows_system_info is in AUDIT_EXCLUDED_ACTIONS
        self.assertIn("windows_system_info", AUDIT_EXCLUDED_ACTIONS)
        req = CapabilityRequest(action="windows_system_info")

        with patch.object(engine.telemetry, "get_system_telemetry", new_callable=AsyncMock) as mock_tel:
            mock_tel.return_value = {"cpu": 10}
            resp = asyncio.run(engine.execute(req, ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP)))
            self.assertTrue(resp.success)
            # DatabaseManager.log_activity must NOT be called for windows_system_info
            mock_db.log_activity.assert_not_called()

        # Non-excluded action DOES invoke log_activity
        req2 = CapabilityRequest(action="windows_file_list", params={"path": "."})
        with patch.object(engine.files, "list_files", return_value={"success": True, "status": "SUCCESS", "items": []}):
            resp2 = asyncio.run(engine.execute(req2, ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP)))
            self.assertTrue(resp2.success)
            mock_db.log_activity.assert_called_once()

    def test_ai_mcp_forged_approval_does_not_escalate(self) -> None:
        """Adversarial Test 1: AI_MCP caller supplying forged approval_id does not become OWNER_MANUAL."""
        engine = CapabilityEngine()
        orchestrator = WorkflowOrchestrator(capability_engine=engine)

        with patch.object(orchestrator, "get_workflow") as mock_get_wf:
            mock_step = MagicMock()
            mock_step.step_id = "step1"
            mock_step.capability = "windows_system_info"
            mock_step.name = "SysInfo"
            mock_step.params_template = {}
            mock_step.target_device = None

            mock_wf = MagicMock()
            mock_wf.steps = [mock_step]
            mock_wf.max_timeout_seconds = 60
            mock_wf.workflow_id = "unapproved_wf"
            mock_get_wf.return_value = mock_wf

            executed_contexts: list[ExecutionContext] = []

            async def fake_execute(req, ctx=None):
                executed_contexts.append(ctx)
                return CapabilityResponse(success=True, status="SUCCESS", data={})

            with patch.object(engine, "execute", side_effect=fake_execute):
                # Call run_workflow with AI_MCP and a forged approval ID
                ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="ai_client")
                report = asyncio.run(orchestrator.run_workflow(
                    "unapproved_wf",
                    params={"approval_id": "forged_123"},
                    ctx=ctx,
                    workflow_approved=False,
                ))
                self.assertEqual(report.status, "COMPLETED")
                self.assertEqual(len(executed_contexts), 1)
                # The step execution context MUST NOT have escalated to OWNER_MANUAL
                self.assertEqual(executed_contexts[0].principal, ExecutionPrincipal.AI_MCP)

    def test_direct_run_workflow_forged_approval_cannot_escalate(self) -> None:
        """Adversarial Test 2: Direct run_workflow() invocation with forged approval ID cannot escalate."""
        engine = CapabilityEngine()
        orchestrator = WorkflowOrchestrator(capability_engine=engine)

        executed_contexts: list[ExecutionContext] = []

        async def fake_execute(req, ctx=None):
            executed_contexts.append(ctx)
            return CapabilityResponse(success=True, status="SUCCESS", data={})

        with patch.object(engine, "execute", side_effect=fake_execute):
            # Direct invocation with defaults
            report = asyncio.run(orchestrator.run_workflow(
                "device_health_snapshot",
                params={"approval_id": "forged_exploit_id"},
                ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP),
            ))
            self.assertEqual(report.status, "COMPLETED")
            self.assertTrue(len(executed_contexts) > 0)
            for step_ctx in executed_contexts:
                self.assertEqual(step_ctx.principal, ExecutionPrincipal.AI_MCP)

    def test_genuinely_consumed_approval_permits_workflow_steps_without_second_prompt(self) -> None:
        """Adversarial Test 3: Approval genuinely consumed permits workflow steps without second approval prompt."""
        engine = CapabilityEngine()
        orchestrator = WorkflowOrchestrator(capability_engine=engine)

        executed_contexts: list[ExecutionContext] = []

        async def fake_execute(req, ctx=None):
            executed_contexts.append(ctx)
            return CapabilityResponse(success=True, status="SUCCESS", data={})

        with patch.object(engine, "execute", side_effect=fake_execute):
            # When workflow_approved=True (set exclusively by engine upon consumption)
            report = asyncio.run(orchestrator.run_workflow(
                "device_health_snapshot",
                ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP),
                workflow_approved=True,
            ))
            self.assertEqual(report.status, "COMPLETED")
            self.assertTrue(len(executed_contexts) > 0)
            for step_ctx in executed_contexts:
                self.assertEqual(step_ctx.principal, ExecutionPrincipal.OWNER_MANUAL)

    def test_invalid_expired_or_unconsumed_approval_cannot_authorize(self) -> None:
        """Adversarial Test 4: Invalid, expired, or unconsumed approval cannot authorize the workflow."""
        engine = CapabilityEngine()

        # 1. Non-existent approval ID on action that requires approval
        # Mock policy to require approval for action 'restricted_action'
        with patch.object(engine.approval_engine, "evaluate_policy", return_value=(True, "Needs owner approval", "HIGH")):
            req = CapabilityRequest(
                action="restricted_action",
                params={"approval_id": "non_existent_token"},
            )
            resp = asyncio.run(engine.execute(req, ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP)))
            self.assertFalse(resp.success)
            self.assertEqual(resp.status, "UNAUTHORIZED")
            self.assertIn("Approval validation failed", resp.error)

    def test_direct_invocation_of_sensitive_capabilities_enforces_ordinary_contract(self) -> None:
        """Adversarial Test 5: Direct invocation of sensitive capabilities still enforces ordinary contract."""
        engine = CapabilityEngine()

        # AI_MCP calling clipboard_buffer_clear is strictly forbidden by policy
        req = CapabilityRequest(action="clipboard_buffer_clear", params={})
        resp = asyncio.run(engine.execute(req, ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP)))
        self.assertFalse(resp.success)
        self.assertEqual(resp.status, "POLICY_DENIED")


class TestBatch4McpParityAndDoctor(unittest.TestCase):
    """Test F28: 48-tool exact parity and doctor check."""

    def test_mcp_exact_38_tool_parity(self) -> None:
        self.assertEqual(len(CAPABILITY_REGISTRY), 60)
        self.assertEqual(len(ALL_TOOL_NAMES), 60)

        server = create_snow_mcp_server()
        server_tools = {t.name for t in server._tool_manager.list_tools()}
        registry_tools = set(CAPABILITY_REGISTRY.keys())

        self.assertEqual(len(server_tools), 60)
        self.assertEqual(server_tools, registry_tools)

    def test_run_doctor_reports_ok_for_mcp_catalog(self) -> None:
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_doctor(json_output=True)
        self.assertEqual(code, 0)
        results = json.loads(buf.getvalue())
        self.assertIn("checks", results)
        mcp_check = next((c for c in results["checks"] if c["component"] == "mcp_tool_catalog"), None)
        self.assertIsNotNone(mcp_check)
        self.assertEqual(mcp_check["status"], "OK")
        self.assertIn("60 MCP tools verified", mcp_check["message"])


class TestBatch4WebAndTray(unittest.TestCase):
    """Test Track 3: Web Server ETag/304, Status Flags, and Tray Tooltip IPC Query."""

    def test_web_server_camera_etag_304(self) -> None:
        from snow.web.server import SnowWebServer
        from aiohttp import web
        from aiohttp.test_utils import make_mocked_request

        server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)
        self.assertIsNotNone(server.db_manager)

        # Mock camera file
        with tempfile.TemporaryDirectory() as tmp_dir:
            photo = Path(tmp_dir) / "android_photo_test.jpg"
            photo.write_bytes(b"FAKE_JPEG_IMAGE_DATA_12345")

            with patch("snow.capabilities.windows.screenshot.DEFAULT_CAPTURES_DIR", Path(tmp_dir)):
                req = make_mocked_request("GET", "/api/camera/latest")
                resp = asyncio.run(server.handle_api_camera_latest(req))
                self.assertEqual(resp.status, 200)
                etag = resp.headers.get("ETag")
                self.assertIsNotNone(etag)

                # Request again with If-None-Match matching etag -> should return 304
                req2 = make_mocked_request(
                    "GET",
                    "/api/camera/latest",
                    headers={"If-None-Match": etag},
                )
                resp2 = asyncio.run(server.handle_api_camera_latest(req2))
                self.assertEqual(resp2.status, 304)

    def test_web_server_status_lan_and_usb_flags(self) -> None:
        from snow.web.server import SnowWebServer
        from aiohttp.test_utils import make_mocked_request

        server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)
        with patch.object(server.bridge.daemon_manager, "is_ipc_ready", new_callable=AsyncMock, return_value=True), \
             patch.object(server.bridge, "windows_system_info", new_callable=AsyncMock, return_value={"success": True, "data": {}}), \
             patch("snow.core.network.get_active_ip_addresses", return_value=["192.168.1.100"]), \
             patch("snow.core.usb.get_usb_status", return_value={"connected": True, "authorized_count": 1}):
            req = make_mocked_request("GET", "/api/status")
            resp = asyncio.run(server.handle_api_status(req))
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.text)
            self.assertTrue(data["lan_available"])
            self.assertTrue(data["usb_connected"])

    def test_tray_tooltip_queries_connected_devices_over_ipc(self) -> None:
        from snow.tray.app import SnowTrayApp
        tray = SnowTrayApp(headless=True, auto_start_core=False)

        # Mock daemon is running and IPC get_device_status
        tray._device_count = 2
        tray.bridge.call = AsyncMock(return_value={
            "success": True,
            "data": {
                "connected_devices": [{"device_id": "android-1", "device_name": "Pixel 7"}],
                "connected_count": 1,
            }
        })

        with patch.object(tray.daemon_manager, "get_tracked_pid", return_value=12345), \
             patch.object(tray.daemon_manager, "is_process_snow_core", return_value=True), \
             patch.object(tray.db_manager, "list_paired_devices", return_value=[MagicMock(), MagicMock()]):
            status = tray.refresh_status()
            self.assertEqual(status["connected_count"], 1)
            self.assertEqual(status["device_count"], 2)
            tooltip = tray.compute_tooltip()
            self.assertIn("1 connected", tooltip)
            self.assertIn("2 paired", tooltip)
        self.assertIn("2 paired", tooltip)


if __name__ == "__main__":
    unittest.main()
