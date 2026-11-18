"""Unit and integration test suite for Phase 12: Layer 2 Unified CapabilityEngine.

Tests:
1. CapabilityEngine contracts, request routing, structured responses, unknown action handling.
2. Unified dispatch across WSS, IPC, and MCP bridge delegating to CapabilityEngine.
3. Local-first execution: MCP tools succeed in-process when the Core daemon is stopped.
4. Principal isolation: AI_MCP vs OWNER_MANUAL, anti-spoofing, missing context defaults.
5. Structured Terminal Security Tiers:
   - READ_ONLY (inspection commands allowed for AI).
   - WORKSPACE_SCOPED (workspace bounded execution for AI).
   - OWNER_CONFIRMED (owner execution with server-validated confirmation).
   - RESTRICTED_BLOCKED (catastrophic commands, encoded powershell, registry tampering, credential access).
   - Confirmation spoofing rejection & single-use ticket validation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.engine import (
    CapabilityEngine,
    CapabilityRequest,
    CapabilityResponse,
)
from snow.capabilities.windows.apps import WindowsAppLauncher
from snow.capabilities.windows.clipboard import WindowsClipboardManager
from snow.capabilities.windows.files import WindowsFileManager
from snow.capabilities.windows.processes import WindowsProcessMonitor
from snow.capabilities.windows.telemetry import WindowsTelemetry
from snow.capabilities.windows.terminal import (
    TerminalSecurityPolicy,
    TerminalSecurityTier,
    WindowsTerminalExecutor,
)
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.core.server import SnowCoreServer
from snow.mcp.bridge import SnowMcpBridge
from snow.network.ws_server import SnowWebSocketServer
from snow.security.db import DatabaseManager
from snow.protocol.constants import ErrorCode
from snow.protocol.models import SnowMessage
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.policy import (
    CAPABILITY_DESKTOP_EXEC,
    CAPABILITY_DESKTOP_STATUS,
    PeerCapabilityPolicy,
)


class TestCapabilityEngineContracts(unittest.IsolatedAsyncioTestCase):
    """Test CapabilityRequest, CapabilityResponse, and engine initialization."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_engine_")
        self.engine = CapabilityEngine(allowed_roots=[self.temp_dir])

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_request_contract(self) -> None:
        """Verify CapabilityRequest immutable contract."""
        req = CapabilityRequest(action="windows_battery", params={"foo": "bar"}, target_device="node-1")
        self.assertEqual(req.action, "windows_battery")
        self.assertEqual(req.params, {"foo": "bar"})
        self.assertEqual(req.target_device, "node-1")

    def test_response_contract_and_dict_serialization(self) -> None:
        """Verify CapabilityResponse to_dict() serialization."""
        resp = CapabilityResponse(success=True, status="SUCCESS", data={"cpu": 12.5}, error=None)
        self.assertTrue(resp.success)
        d = resp.to_dict()
        self.assertEqual(d["status"], "SUCCESS")
        self.assertEqual(d["data"], {"cpu": 12.5})
        self.assertIsNone(d["error"])

    async def test_unknown_action_returns_structured_error(self) -> None:
        """Unknown action returns UNKNOWN_ACTION error without raising."""
        req = CapabilityRequest(action="non_existent_capability_xyz")
        res = await self.engine.execute(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status, "UNKNOWN_ACTION")
        self.assertIn("Unsupported", res.error)

    async def test_empty_action_returns_invalid_action(self) -> None:
        """Empty or whitespace action returns INVALID_ACTION."""
        req = CapabilityRequest(action="   ")
        res = await self.engine.execute(req)
        self.assertFalse(res.success)
        self.assertEqual(res.status, "INVALID_ACTION")


class TestLocalFirstExecution(unittest.IsolatedAsyncioTestCase):
    """Verify that local Windows MCP capabilities execute in-process without daemon."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_local_first_")
        self.bridge = SnowMcpBridge(
            host="127.0.0.1",
            port=59998,  # Offline port
            secret="test_secret",
            allowed_roots=[self.temp_dir],
            auto_start_core=False,  # Strictly disallow daemon auto-spawn
        )

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_local_battery_succeeds_offline(self) -> None:
        """Local battery query succeeds in-process with daemon offline."""
        res = await self.bridge.windows_battery()
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("status"), "SUCCESS")

    async def test_local_system_info_succeeds_offline(self) -> None:
        """Local system telemetry succeeds in-process with daemon offline."""
        res = await self.bridge.windows_system_info()
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("status"), "SUCCESS")
        self.assertIn("hostname", res.get("data", {}))

    async def test_local_file_read_write_succeeds_offline(self) -> None:
        """Local file operations succeed in-process with daemon offline."""
        target_file = Path(self.temp_dir) / "test_local.txt"
        write_res = await self.bridge.windows_file_write(
            file_path=str(target_file), content="snow_local_first_verified"
        )
        self.assertTrue(write_res.get("success"))

        read_res = await self.bridge.windows_file_read(file_path=str(target_file))
        self.assertTrue(read_res.get("success"))
        self.assertEqual(read_res.get("data", {}).get("content"), "snow_local_first_verified")

    async def test_local_clipboard_succeeds_offline(self) -> None:
        """Local clipboard get/set succeeds in-process with daemon offline."""
        # Use mocked clipboard boundary to prevent polluting real host clipboard
        with patch.object(self.bridge.local_clipboard, "set_clipboard_sync", return_value={"success": True, "status": "SUCCESS"}), \
             patch.object(self.bridge.local_clipboard, "get_clipboard_sync", return_value={"success": True, "status": "SUCCESS", "text": "mock_clip", "length": 9}):
            set_res = await self.bridge.windows_clipboard_set(text="mock_clip")
            self.assertTrue(set_res.get("success"))
            get_res = await self.bridge.windows_clipboard_get()
            self.assertTrue(get_res.get("success"))
            self.assertEqual(get_res.get("data", {}).get("text"), "mock_clip")

    async def test_local_terminal_exec_succeeds_offline(self) -> None:
        """Local terminal read-only execution succeeds in-process with daemon offline."""
        res = await self.bridge.windows_terminal_exec("whoami")
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("status"), "SUCCESS")
        self.assertEqual(res.get("data", {}).get("tier"), "READ_ONLY")


class TestPrincipalIsolationAndAntiSpoofing(unittest.IsolatedAsyncioTestCase):
    """Verify dual-principal model, anti-spoofing, and privilege boundaries."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_principal_")
        self.engine = CapabilityEngine(allowed_roots=[self.temp_dir])

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_missing_context_defaults_to_restricted_ai(self) -> None:
        """When ctx is None, CapabilityEngine strictly defaults to AI_MCP principal."""
        # AI_MCP is blocked from format or destructive commands
        req = CapabilityRequest(action="windows_terminal_exec", params={"command": "format C: /y"})
        res = await self.engine.execute(req, ctx=None)
        self.assertFalse(res.success)
        self.assertEqual(res.status, "POLICY_DENIED")
        self.assertEqual(res.data.get("tier"), "RESTRICTED_BLOCKED")

    async def test_client_payload_cannot_spoof_principal(self) -> None:
        """Parameters cannot spoof principal to OWNER_MANUAL."""
        spoofed_params = {
            "command": "powershell -Command \"Get-Service\"",
            "principal": "OWNER_MANUAL",
            "trust_tier": "owner",
            "execution_principal": "OWNER_MANUAL",
            "confirmed": True,
        }
        ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="untrusted_client")
        req = CapabilityRequest(action="windows_terminal_exec", params=spoofed_params)
        res = await self.engine.execute(req, ctx=ai_ctx)

        # AI_MCP cannot run OWNER_CONFIRMED commands outside approved roots even with confirmed=True
        self.assertFalse(res.success)
        self.assertEqual(res.status, "POLICY_DENIED")
        self.assertIn("AI callers are restricted", res.error)

    async def test_owner_context_with_confirmation_executes(self) -> None:
        """OWNER_MANUAL context with confirmation is authorized."""
        owner_ctx = ExecutionContext(
            principal=ExecutionPrincipal.OWNER_MANUAL,
            device_id="owner-phone-1",
            origin="wss",
        )
        req = CapabilityRequest(
            action="windows_terminal_exec",
            params={"command": "whoami", "confirmed": True},
        )
        res = await self.engine.execute(req, ctx=owner_ctx)
        self.assertTrue(res.success)
        self.assertEqual(res.status, "SUCCESS")
        self.assertIn(res.data.get("tier"), ("READ_ONLY", "OWNER_CONFIRMED"))


class TestTerminalSecurityTiers(unittest.IsolatedAsyncioTestCase):
    """Comprehensive test of all 4 structured terminal security tiers."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_tiers_")
        self.policy = TerminalSecurityPolicy(
            allowed_working_directories=[Path(self.temp_dir)]
        )
        self.executor = WindowsTerminalExecutor(policy=self.policy)
        self.engine = CapabilityEngine(
            terminal=self.executor,
            allowed_roots=[self.temp_dir],
        )
        self.ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="test")
        self.owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="test")

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    # --- Tier A: READ_ONLY ---
    async def test_tier_a_read_only_commands(self) -> None:
        """Safe inspection commands classify as READ_ONLY and execute for AI_MCP."""
        inspection_cmds = ["whoami", "hostname", "ipconfig", "systeminfo", "python --version"]
        for cmd in inspection_cmds:
            tier = self.executor.classify_command(cmd, ctx=self.ai_ctx)
            self.assertEqual(tier, TerminalSecurityTier.READ_ONLY, f"Command '{cmd}' should be READ_ONLY")

            req = CapabilityRequest(action="windows_terminal_exec", params={"command": cmd})
            res = await self.engine.execute(req, ctx=self.ai_ctx)
            self.assertTrue(res.success, f"Command '{cmd}' should succeed")
            self.assertEqual(res.data.get("tier"), "READ_ONLY")

    async def test_tier_a_git_status_read_only(self) -> None:
        """Git read-only subcommands classify as READ_ONLY."""
        tier = self.executor.classify_command("git status", ctx=self.ai_ctx)
        self.assertEqual(tier, TerminalSecurityTier.READ_ONLY)

    # --- Tier B: WORKSPACE_SCOPED ---
    async def test_tier_b_workspace_scoped_execution(self) -> None:
        """Workspace operations within authorized roots classify as WORKSPACE_SCOPED."""
        cmd = "echo hello_workspace > test_tier_b.txt"
        tier = self.executor.classify_command(cmd, cwd=self.temp_dir, ctx=self.ai_ctx)
        self.assertEqual(tier, TerminalSecurityTier.WORKSPACE_SCOPED)

        req = CapabilityRequest(
            action="windows_terminal_exec",
            params={"command": cmd, "cwd": self.temp_dir},
        )
        res = await self.engine.execute(req, ctx=self.ai_ctx)
        self.assertTrue(res.success)
        self.assertEqual(res.data.get("tier"), "WORKSPACE_SCOPED")

    async def test_tier_b_working_directory_escape_blocked(self) -> None:
        """AI_MCP attempting to execute in unauthorized directory is rejected."""
        unauthorized_dir = "C:\\Windows\\System32"
        req = CapabilityRequest(
            action="windows_terminal_exec",
            params={"command": "dir", "cwd": unauthorized_dir},
        )
        res = await self.engine.execute(req, ctx=self.ai_ctx)
        self.assertFalse(res.success)
        self.assertIn(res.status, ("INVALID_ARGUMENT", "PATH_NOT_ALLOWED", "POLICY_DENIED"))

    # --- Tier C: OWNER_CONFIRMED ---
    async def test_tier_c_owner_unconfirmed_rejected(self) -> None:
        """Owner command requiring confirmation is rejected if unconfirmed."""
        cmd = "powershell -Command \"Get-Process\""
        req = CapabilityRequest(
            action="desktop_exec",
            params={"command": cmd, "confirmed": False},
        )
        res = await self.engine.execute(req, ctx=self.owner_ctx)
        self.assertFalse(res.success)
        self.assertEqual(res.status, "CONFIRMATION_REQUIRED")
        self.assertIn("explicit user confirmation", res.error)

    async def test_tier_c_owner_confirmed_ticket_validation(self) -> None:
        """Owner command with server-issued single-use confirmation ticket executes."""
        device_id = "trusted-owner-phone"
        owner_ctx = ExecutionContext(
            principal=ExecutionPrincipal.OWNER_MANUAL,
            device_id=device_id,
            origin="wss",
        )
        cmd = "whoami"
        # Issue ticket
        ticket = self.engine.issue_confirmation_ticket(device_id, cmd, ttl_seconds=30.0)
        self.assertIsNotNone(ticket)

        # Execute using ticket
        req = CapabilityRequest(
            action="desktop_exec",
            params={"command": cmd, "confirmation_ticket": ticket},
        )
        res = await self.engine.execute(req, ctx=owner_ctx)
        self.assertTrue(res.success)

        # Ticket must be single-use (replay should fail)
        replay_req = CapabilityRequest(
            action="desktop_exec",
            params={"command": cmd, "confirmation_ticket": ticket, "confirmed": False},
        )
        is_valid = self.engine.validate_confirmation_ticket(ticket, device_id, cmd)
        self.assertFalse(is_valid, "Ticket must not be reusable after consumption")

    # --- Tier D: RESTRICTED_BLOCKED ---
    async def test_tier_d_catastrophic_commands_blocked(self) -> None:
        """Destructive disk commands are hard-blocked for AI_MCP."""
        destructive = [
            "format C: /y",
            "diskpart /s script.txt",
            "del /f /s /q C:\\Windows",
            "rmdir /s /q C:\\Windows\\System32",
            "Remove-Item -Recurse -Force C:\\Windows",
        ]
        for cmd in destructive:
            tier = self.executor.classify_command(cmd, ctx=self.ai_ctx)
            self.assertEqual(tier, TerminalSecurityTier.RESTRICTED_BLOCKED, f"Cmd '{cmd}' must be RESTRICTED_BLOCKED")
            req = CapabilityRequest(action="windows_terminal_exec", params={"command": cmd})
            res = await self.engine.execute(req, ctx=self.ai_ctx)
            self.assertFalse(res.success)
            self.assertEqual(res.status, "POLICY_DENIED")

    async def test_tier_d_encoded_powershell_blocked(self) -> None:
        """Encoded PowerShell commands are blocked for AI_MCP."""
        encoded_cmds = [
            "powershell -EncodedCommand aW52b2tl...",
            "powershell -enc aW52...",
            "pwsh -e aW52...",
        ]
        for cmd in encoded_cmds:
            tier = self.executor.classify_command(cmd, ctx=self.ai_ctx)
            self.assertEqual(tier, TerminalSecurityTier.RESTRICTED_BLOCKED)
            req = CapabilityRequest(action="windows_terminal_exec", params={"command": cmd})
            res = await self.engine.execute(req, ctx=self.ai_ctx)
            self.assertFalse(res.success)
            self.assertEqual(res.status, "POLICY_DENIED")

    async def test_tier_d_registry_tampering_blocked(self) -> None:
        """Registry modification commands are blocked for AI_MCP."""
        reg_cmds = [
            "reg add HKLM\\Software\\Test",
            "reg delete HKCU\\Software\\Test /f",
            "powershell Set-ItemProperty -Path HKLM:\\Software\\Test",
        ]
        for cmd in reg_cmds:
            tier = self.executor.classify_command(cmd, ctx=self.ai_ctx)
            self.assertEqual(tier, TerminalSecurityTier.RESTRICTED_BLOCKED)
            req = CapabilityRequest(action="windows_terminal_exec", params={"command": cmd})
            res = await self.engine.execute(req, ctx=self.ai_ctx)
            self.assertFalse(res.success)
            self.assertEqual(res.status, "POLICY_DENIED")

    async def test_tier_d_credential_tampering_blocked_for_all(self) -> None:
        """Access or deletion of .snow credentials is blocked even for OWNER_MANUAL."""
        cred_cmds = [
            "del ~/.snow/ipc.secret",
            "rmdir /s /q .snow",
            "del .snow\\tls\\server.key",
            "remove-item .snow/snow_devices.db",
        ]
        for cmd in cred_cmds:
            ai_tier = self.executor.classify_command(cmd, ctx=self.ai_ctx)
            self.assertEqual(ai_tier, TerminalSecurityTier.RESTRICTED_BLOCKED)
            owner_tier = self.executor.classify_command(cmd, ctx=self.owner_ctx)
            self.assertEqual(owner_tier, TerminalSecurityTier.RESTRICTED_BLOCKED)


class TestUnifiedDispatch(unittest.IsolatedAsyncioTestCase):
    """Verify that WSS and IPC both delegate to CapabilityEngine."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_unified_")
        self._prev_env = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = self.temp_dir
        self.db_path = Path(self.temp_dir) / "test_devices.db"
        self.db = DatabaseManager(self.db_path)
        self.config = CoreConfig(
            port=59997,
            transfer_port=59996,
            ipc_port=59995,
            transfer_root=self.temp_dir,
        )
        self.server = SnowCoreServer(config=self.config, db_manager=self.db)

    async def asyncTearDown(self) -> None:
        if self._prev_env is not None:
            os.environ["SNOW_DATA_DIR"] = self._prev_env
        else:
            os.environ.pop("SNOW_DATA_DIR", None)
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_core_server_initializes_shared_capability_engine(self) -> None:
        """SnowCoreServer initializes and shares CapabilityEngine with ws_server and ipc_server."""
        self.assertIsNotNone(self.server.capability_engine)
        self.assertIs(self.server.ws_server.capability_engine, self.server.capability_engine)
        self.assertIs(self.server.ipc_server.capability_engine, self.server.capability_engine)

    async def test_ipc_delegates_to_capability_engine(self) -> None:
        """IPC server dispatches windows_battery via capability_engine.execute()."""
        spy = AsyncMock(return_value=CapabilityResponse(success=True, status="SUCCESS", data={"mock_battery": 99}))
        with patch.object(self.server.capability_engine, "execute", spy):
            res = await self.server.ipc_server._dispatch_request(
                {"version": 1, "op": "windows_battery", "auth_token": self.server.ipc_server.secret},
                is_connection_authenticated=True,
            )
            self.assertTrue(res[0]["success"])
            self.assertEqual(res[0]["data"], {"mock_battery": 99})
            self.assertEqual(spy.call_count, 1)
            # Verify request was stamped as AI_MCP
            called_ctx = spy.call_args[1].get("ctx")
            self.assertEqual(called_ctx.principal, ExecutionPrincipal.AI_MCP)

    async def test_ws_server_delegates_to_capability_engine(self) -> None:
        """WebSocket server dispatches desktop_exec via capability_engine.execute()."""
        spy = AsyncMock(return_value=CapabilityResponse(
            success=True,
            status="SUCCESS",
            data={"command": "whoami", "stdout": "test_user\n", "exit_code": 0},
        ))
        mock_client = MagicMock()
        mock_client.connection_id = "conn-1"
        mock_client.websocket = AsyncMock()

        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="wss")
        msg = SnowMessage.create_request(action="desktop_exec", data={"command": "whoami", "confirmed": True})

        with patch.object(self.server.capability_engine, "execute", spy):
            await self.server.ws_server._handle_desktop_exec(
                client=mock_client,
                message=msg,
                data={"command": "whoami", "confirmed": True},
                session=None,
                ctx=owner_ctx,
            )
            self.assertEqual(spy.call_count, 1)
            called_ctx = spy.call_args[1].get("ctx")
            self.assertEqual(called_ctx.principal, ExecutionPrincipal.OWNER_MANUAL)


if __name__ == "__main__":
    unittest.main()
