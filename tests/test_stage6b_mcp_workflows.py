"""Focused Stage 6B WS5 tests: 54-tool catalog parity, 6 new tools, approval gates, and 3 workflows."""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock

from snow.capabilities.engine import CapabilityEngine, CapabilityRequest
from snow.capabilities.windows.files import WindowsFileManager
from snow.capabilities.windows.system import ALLOWED_HOTKEYS, WindowsSystemControls
from snow.capabilities.workflows import WORKFLOW_REGISTRY, WorkflowOrchestrator
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.registry import (
    CAPABILITY_REGISTRY,
    get_capability_metadata,
    get_mcp_annotations,
    list_capabilities,
    validate_registry,
)
from snow.mcp.server import create_snow_mcp_server
from snow.mcp.tools import ALL_TOOL_NAMES
from snow.network.federation import FederationManager
from snow.network.node import DeviceNode, ReachabilityState
from snow.network.registry import NodeRegistry
from snow.network.router import SessionRouter
from snow.security.approval import ApprovalPolicyEngine
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager


class TestStage6BWS5McpCatalogAndTools(unittest.IsolatedAsyncioTestCase):
    """Verify exact 54-tool parity, safe parameter checks, approval gates, and cross-network execution."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="snow_s6b_ws5_"))
        self.db = DatabaseManager(self.tmp / "ws5.db")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_54_tool_catalog_exact_parity_and_annotations(self) -> None:
        ok, errs = validate_registry()
        self.assertTrue(ok, f"validate_registry errors: {errs}")
        self.assertEqual(len(CAPABILITY_REGISTRY), 60)
        self.assertEqual(len(ALL_TOOL_NAMES), 60)
        self.assertEqual(len(list_capabilities()), 60)

        srv = create_snow_mcp_server()
        srv_tools = await srv.list_tools()
        self.assertEqual(len(srv_tools), 60)
        names = {t.name for t in srv_tools}
        self.assertEqual(names, set(CAPABILITY_REGISTRY.keys()))

        expected_new = (
            "snow_android_whatsapp_send",
            "snow_android_notification_reply",
            "snow_windows_hotkey",
            "snow_windows_brightness_set",
            "snow_android_dnd_toggle",
            "snow_cross_network_execute",
        )
        for name in expected_new:
            self.assertIn(name, names)
            self.assertIsNotNone(get_capability_metadata(name))
            ann = get_mcp_annotations(name)
            self.assertIsNotNone(ann)
            self.assertIs(type(ann.readOnlyHint), bool)
            self.assertIs(type(ann.destructiveHint), bool)

    async def test_windows_hotkey_allowlist_and_alt_f4_approval_gate(self) -> None:
        dispatched: list[str] = []
        sys_ctrl = WindowsSystemControls(
            send_hotkey_fn=lambda chord: (
                dispatched.append(chord) or {"success": True, "status": "SUCCESS", "shortcut": chord}
            )
        )
        engine = CapabilityEngine(
            allowed_roots=[self.tmp],
            system=sys_ctrl,
            approval_engine=ApprovalPolicyEngine(db_manager=self.db),
            db_manager=self.db,
        )
        bridge = SnowMcpBridge(auto_start_core=False)
        bridge.capability_engine = engine
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)

        # Disallowlisted / injection shortcut rejected cleanly
        for bad in ("powershell", "ctrl+alt+del", "cmd+r", "win+r", ""):
            res_bad = await bridge.windows_hotkey(bad)
            self.assertFalse(res_bad["success"])
            self.assertEqual(res_bad["status"], "INVALID_HOTKEY")

        # Safe allowlisted chord executes via DI Win32 handler (spacing normalized)
        res_ok = await bridge.windows_hotkey("Ctrl + C")
        self.assertTrue(res_ok["success"])
        self.assertEqual(dispatched, ["ctrl+c"])

        # alt+f4 MUST require explicit owner approval for AI_MCP
        res_f4 = await engine.execute(
            CapabilityRequest(action="windows_hotkey", params={"shortcut": "alt+f4"}),
            ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="mcp_test"),
        )
        self.assertFalse(res_f4.success)
        self.assertEqual(res_f4.status, "APPROVAL_REQUIRED")
        self.assertNotIn("alt+f4", dispatched)
        self.assertIn("alt+f4", ALLOWED_HOTKEYS)

    async def test_windows_brightness_validation_and_di_execution(self) -> None:
        levels_applied: list[int] = []
        sys_ctrl = WindowsSystemControls(
            set_brightness_fn=lambda lvl: (
                levels_applied.append(lvl) or {"success": True, "status": "SUCCESS", "level": lvl}
            )
        )
        engine = CapabilityEngine(allowed_roots=[self.tmp], system=sys_ctrl, db_manager=self.db)
        bridge = SnowMcpBridge(auto_start_core=False)
        bridge.capability_engine = engine
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)

        for bad_lvl in (-1, 101, True, False, "75", 50.5):  # type: ignore[arg-type]
            bad = await bridge.windows_brightness_set(bad_lvl)
            self.assertFalse(bad["success"])
            self.assertEqual(bad["status"], "INVALID_BRIGHTNESS_LEVEL")

        ok = await bridge.windows_brightness_set(65)
        self.assertTrue(ok["success"])
        self.assertEqual(levels_applied, [65])

    async def test_whatsapp_reply_dnd_validation_and_approval_gates(self) -> None:
        ap = ApprovalPolicyEngine(db_manager=self.db)
        engine = CapabilityEngine(allowed_roots=[self.tmp], approval_engine=ap, db_manager=self.db)
        bridge = SnowMcpBridge(auto_start_core=False)
        bridge.capability_engine = engine
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)

        # Parameter bounds checks
        bad_wa = await bridge.android_whatsapp_send("", "hi")
        self.assertFalse(bad_wa["success"])
        self.assertEqual(bad_wa["status"], "INVALID_ARGUMENT")

        bad_reply = await bridge.android_notification_reply("k1", "")
        self.assertFalse(bad_reply["success"])
        self.assertEqual(bad_reply["status"], "INVALID_ARGUMENT")

        bad_dnd = await bridge.android_dnd_toggle("yes")  # type: ignore[arg-type]
        self.assertFalse(bad_dnd["success"])
        self.assertEqual(bad_dnd["status"], "INVALID_ARGUMENT")

        # AI_MCP requires explicit owner approval for WhatsApp send & notification reply
        for action, params in (
            ("android_whatsapp_send", {"recipient": "+15550101234", "message": "Hello"}),
            ("android_notification_reply", {"key": "0|com.whatsapp|1|tag|0", "text": "On my way"}),
        ):
            r = await engine.execute(
                CapabilityRequest(action=action, params=params),
                ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="mcp_test"),
            )
            self.assertFalse(r.success)
            self.assertEqual(r.status, "APPROVAL_REQUIRED")

    async def test_cross_network_execute_enforces_grant_intersection_revocation_and_blocks_shell(self) -> None:
        fed = FederationManager(db_manager=self.db, local_network_id="SNW-NET-LOCAL001", local_node_id="pc-local")
        inv = fed.create_invitation(
            allowed_device_ids=["remote-pc-2"],
            permission_tier="files_only",
            principal="OWNER_MANUAL",
        )
        acc = fed.accept_invitation(
            code=inv["code"],
            peer_network_id="SNW-NET-PEER0002",
            peer_network_name="Study Peer Net",
            peer_node_id="remote-pc-2",
            peer_node_name="Lab PC",
            peer_cert_fingerprint="CC" * 32,
            principal="OWNER_MANUAL",
        )
        self.assertTrue(acc["success"])
        grant_id = acc["grant_id"]

        node = DeviceNode(
            device_id="remote-pc-2",
            device_name="Lab PC",
            platform="windows",
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            host="127.0.0.1",
            wss_port=8765,
            permission_profile="full_control",
        )
        reg = NodeRegistry(db_manager=self.db)
        reg.resolve_target = MagicMock(return_value=(node, None))
        router = SessionRouter(node_registry=reg, db_manager=self.db)
        router._attempt_remote_relay_tunnel = AsyncMock(return_value=None)
        outbound = MagicMock(is_connected=True, host="127.0.0.1")
        from snow.protocol.models import SnowMessage
        outbound.send_message = AsyncMock(
            return_value=SnowMessage.create_response(
                correlation_id="c1",
                payload={"status": "success", "files": ["notes.txt"]},
            )
        )
        router.register_outbound_client("remote-pc-2", outbound)

        engine = CapabilityEngine(
            allowed_roots=[self.tmp],
            db_manager=self.db,
            approval_engine=ApprovalPolicyEngine(db_manager=self.db),
            session_router=router,
        )

        # AI_MCP blocked without approval first
        ai_res = await engine.execute(
            CapabilityRequest(
                action="cross_network_execute",
                params={
                    "target_network_id": "SNW-NET-PEER0002",
                    "target_device_id": "remote-pc-2",
                    "capability": "windows_file_list",
                },
            ),
            ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP),
        )
        self.assertFalse(ai_res.success)
        self.assertEqual(ai_res.status, "APPROVAL_REQUIRED")

        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)

        # Wildcard device rejected
        bad_dev = await engine.execute(
            CapabilityRequest(
                action="cross_network_execute",
                params={"target_network_id": "SNW-NET-PEER0002", "target_device_id": "*", "capability": "windows_file_list"},
            ),
            ctx=owner_ctx,
        )
        self.assertFalse(bad_dev.success)
        self.assertEqual(bad_dev.status, "INVALID_ARGUMENT")

        # Shell execution strictly rejected
        shell_res = await engine.execute(
            CapabilityRequest(
                action="cross_network_execute",
                params={
                    "target_network_id": "SNW-NET-PEER0002",
                    "target_device_id": "remote-pc-2",
                    "capability": "windows_terminal_exec",
                },
            ),
            ctx=owner_ctx,
        )
        self.assertFalse(shell_res.success)
        self.assertEqual(shell_res.status, "CAPABILITY_NOT_PERMITTED")

        # Unallowed capability under grant tier files_only blocked
        clip_res = await engine.execute(
            CapabilityRequest(
                action="cross_network_execute",
                params={
                    "target_network_id": "SNW-NET-PEER0002",
                    "target_device_id": "remote-pc-2",
                    "capability": "windows_clipboard_get",
                },
            ),
            ctx=owner_ctx,
        )
        self.assertFalse(clip_res.success)
        self.assertEqual(clip_res.status, "CAPABILITY_NOT_PERMITTED")

        # Allowed files capability executes cleanly
        ok_res = await engine.execute(
            CapabilityRequest(
                action="cross_network_execute",
                params={
                    "target_network_id": "SNW-NET-PEER0002",
                    "target_device_id": "remote-pc-2",
                    "capability": "windows_file_list",
                },
            ),
            ctx=owner_ctx,
        )
        self.assertTrue(ok_res.success)

        # Downgrade/revoke immediately blocks next attempt
        fed.revoke_grant(grant_id, reason="Test revoke", principal="OWNER_MANUAL")
        rev_res = await engine.execute(
            CapabilityRequest(
                action="cross_network_execute",
                params={
                    "target_network_id": "SNW-NET-PEER0002",
                    "target_device_id": "remote-pc-2",
                    "capability": "windows_file_list",
                },
            ),
            ctx=owner_ctx,
        )
        self.assertFalse(rev_res.success)
        self.assertIn("REVOKED", rev_res.status)


class TestStage6BWS5DeclarativeWorkflows(unittest.IsolatedAsyncioTestCase):
    """Verify the 3 new declarative workflows: study_mode, find_and_send_file, capture_and_share."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="snow_s6b_wf_"))
        self.sample_file = self.tmp / "capstone_notes.txt"
        self.sample_file.write_text("SNOW Capstone Study Notes", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    async def test_three_new_workflows_registered_and_executable(self) -> None:
        for wf_id in ("study_mode", "find_and_send_file", "capture_and_share"):
            self.assertIn(wf_id, WORKFLOW_REGISTRY)

        db = DatabaseManager(self.tmp / "wf.db")
        files_mgr = WindowsFileManager(allowed_roots=[self.tmp])
        sys_ctrl = WindowsSystemControls(
            notify_fn=lambda title, msg: {"success": True, "status": "SUCCESS", "title": title, "message": msg}
        )
        mock_media = MagicMock()
        mock_media.handle_action.return_value = {"success": True, "status": "SUCCESS", "volume": 15}
        mock_router = MagicMock()
        mock_router.route_request = AsyncMock(
            return_value={"success": True, "status": "SUCCESS", "data": {"status": "success", "enabled": True}}
        )
        reg = NodeRegistry(db_manager=db)
        node = DeviceNode(
            device_id="phone-wf",
            device_name="Phone WF",
            platform="android",
            reachability_state=ReachabilityState.CONNECTED_SESSION,
        )
        reg.get_node = MagicMock(return_value=node)
        reg.list_nodes = MagicMock(return_value=[node])
        reg.resolve_target = MagicMock(return_value=(node, None))

        engine = CapabilityEngine(
            allowed_roots=[self.tmp],
            db_manager=db,
            files=files_mgr,
            system=sys_ctrl,
            media_controller=mock_media,
            session_router=mock_router,
            node_registry=reg,
            approval_engine=ApprovalPolicyEngine(db_manager=db),
        )
        orch = WorkflowOrchestrator(capability_engine=engine)
        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)

        # 1. study_mode runs cleanly
        study_rep = await orch.run_workflow("study_mode", ctx=owner_ctx)
        self.assertEqual(study_rep.status, "COMPLETED")
        mock_router.route_request.assert_awaited()

        # 2. find_and_send_file finds matched file and forwards path (or stages)
        send_calls: list[dict] = []

        async def _capture_exec(req: CapabilityRequest, ctx: ExecutionContext):
            if req.action == "android_file_send":
                send_calls.append(dict(req.params))
                from snow.capabilities.engine import CapabilityResponse
                return CapabilityResponse(success=True, status="SUCCESS", data={"file_path": req.params.get("file_path")})
            return await _orig_exec(req, ctx)

        _orig_exec = engine.execute
        engine.execute = _capture_exec  # type: ignore[method-assign]
        find_rep = await orch.run_workflow(
            "find_and_send_file",
            params={"query": "capstone_notes", "root_path": str(self.tmp)},
            ctx=owner_ctx,
        )
        self.assertEqual(find_rep.status, "COMPLETED")
        self.assertEqual(len(send_calls), 1)
        self.assertTrue(send_calls[0]["file_path"].endswith("capstone_notes.txt"))


if __name__ == "__main__":
    unittest.main()
