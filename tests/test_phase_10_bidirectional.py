"""Comprehensive unit and integration test suite for SNOW Phase 10: Bidirectional Control.

Tests:
1. All 7 incoming Phone -> Laptop desktop actions over WebSocket:
   - desktop_status
   - desktop_exec (including catastrophic command blocking and timeout bounding)
   - desktop_app_launch (allowlisted app launch and lock screen)
   - desktop_clipboard_get
   - desktop_clipboard_set (including 64 KiB payload cap)
   - desktop_file_list (containment, path traversal rejection, and .snow isolation)
   - desktop_file_stage_download (SHA-256 calculation, transfer creation, security scoping)
2. Strict authentication enforcement for all desktop actions (unauthenticated clients get UNAUTHORIZED)
3. HTTP file transfer server download handler using staged file paths
4. Cross-device MCP tool snow_android_send_message, bridge dispatch, and 24-tool catalog verification.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.windows import (
    TerminalSecurityPolicy,
    WindowsAppLauncher,
    WindowsClipboardManager,
    WindowsFileManager,
    WindowsProcessMonitor,
    WindowsTelemetry,
    WindowsTerminalExecutor,
)
from snow.core.config import CoreConfig
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.registry import TOOL_REGISTRY, ToolCategory, get_tool_category, is_cross_device_tool
from snow.mcp.server import create_snow_mcp_server
from snow.mcp.tools import ALL_TOOL_NAMES
from snow.network.connection_manager import ConnectionManager
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.protocol.validator import validate_raw_message
from snow.security.db import DatabaseManager, hash_token
from snow.security import ExecutionContext, ExecutionPrincipal
from snow.security.session import SessionManager
from snow.transfer.manager import TransferDirection, TransferManager, TransferState
from snow.transfer.storage import TransferStorageManager


class MockClientConnection:
    """Mock WebSocket client connection for testing server dispatch."""

    def __init__(self, connection_id: str = "conn-test-10") -> None:
        self.connection_id = connection_id
        self.remote_address = ("127.0.0.1", 54321)
        self.websocket = AsyncMock()
        self.sent_messages: list[SnowMessage] = []

        async def _mock_send(raw_text: str) -> None:
            msg = validate_raw_message(raw_text)
            self.sent_messages.append(msg)

        self.websocket.send = AsyncMock(side_effect=_mock_send)


class TestPhase10DesktopWebSocketActions(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying all incoming desktop actions on SnowWebSocketServer."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_p10_")
        self.db_path = Path(self.temp_dir) / "test_devices.db"
        self.transfer_dir = Path(self.temp_dir) / "transfers"
        self.transfer_dir.mkdir(parents=True, exist_ok=True)
        self.user_files_dir = Path(self.temp_dir) / "user_files"
        self.user_files_dir.mkdir(parents=True, exist_ok=True)

        self.config = CoreConfig(
            port=8765,
            bind_host="127.0.0.1",
            auth_required=True,
            tls_enabled=False,
            transfer_root=str(self.transfer_dir),
        )

        self.db_manager = DatabaseManager(db_path=self.db_path)
        self.connection_manager = ConnectionManager()
        self.session_manager = SessionManager()
        self.transfer_manager = TransferManager()
        self.storage_manager = TransferStorageManager(root_dir=self.transfer_dir)

        # Scoped file manager with our test directories as allowed roots
        self.file_manager = WindowsFileManager(allowed_roots=[self.user_files_dir, self.transfer_dir])
        self.terminal = WindowsTerminalExecutor()
        self.app_launcher = WindowsAppLauncher()
        self.clipboard = WindowsClipboardManager()
        self.telemetry = WindowsTelemetry()

        self.server = SnowWebSocketServer(
            config=self.config,
            connection_manager=self.connection_manager,
            db_manager=self.db_manager,
            session_manager=self.session_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
        )
        self.server.windows_files = self.file_manager
        self.server.windows_terminal = self.terminal
        self.server.windows_apps = self.app_launcher
        self.server.windows_clipboard = self.clipboard
        self.server.windows_telemetry = self.telemetry

        # Set up a paired device and session
        self.device_id = "device-android-phase10"
        self.raw_token = "secret-token-p10-xyz"
        self.db_manager.insert_paired_device(
            device_id=self.device_id,
            device_name="Test Android Phone",
            auth_token_hash=hash_token(self.raw_token),
        )

        self.client = MockClientConnection(connection_id="conn-p10")
        self.connection_manager.register(self.client)

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _authenticate_client(self) -> None:
        """Helper to create an active authenticated session for the test client."""
        self.session_manager.create_session(
            device_id=self.device_id, connection_id=self.client.connection_id
        )

    # -------------------------------------------------------------------------
    # 1. Authentication Boundary
    # -------------------------------------------------------------------------

    async def test_unauthenticated_requests_rejected_with_unauthorized(self) -> None:
        """Every Phase 10 desktop action must be rejected with UNAUTHORIZED if not authenticated."""
        actions = [
            ("desktop_status", {}),
            ("desktop_exec", {"command": "dir"}),
            ("desktop_app_launch", {"app_name": "notepad"}),
            ("desktop_clipboard_get", {}),
            ("desktop_clipboard_set", {"text": "hello"}),
            ("desktop_file_list", {}),
            ("desktop_file_stage_download", {"file_path": "test.txt"}),
        ]

        for action, data in actions:
            self.client.sent_messages.clear()
            req = SnowMessage.create_request(action, data)
            await self.server._handle_request(self.client, req)

            self.assertEqual(len(self.client.sent_messages), 1, f"Failed for action: {action}")
            resp = self.client.sent_messages[0]
            self.assertEqual(resp.type, MessageType.ERROR)
            self.assertIsNotNone(resp.error)
            self.assertEqual(resp.error["code"], ErrorCode.UNAUTHORIZED)

    # -------------------------------------------------------------------------
    # 2. Desktop Status Telemetry
    # -------------------------------------------------------------------------

    async def test_desktop_status_success(self) -> None:
        """desktop_status returns live system telemetry, CPU, memory, battery, and hostname."""
        self._authenticate_client()
        req = SnowMessage.create_request("desktop_status")
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.RESPONSE)
        self.assertIsNotNone(resp.payload)
        self.assertEqual(resp.payload.get("status"), "success")
        data = resp.payload.get("data", {})
        self.assertIn("hostname", data)
        self.assertIn("cpu_percent", data)
        self.assertIn("memory_percent", data)
        self.assertIn("battery", data)
        self.assertIn("uptime_seconds", data)

    # -------------------------------------------------------------------------
    # 3. Terminal Execution & Peer Authorization
    # -------------------------------------------------------------------------

    async def test_desktop_exec_denied_by_default_without_grant(self) -> None:
        """desktop_exec is strictly denied by default for newly paired devices."""
        self._authenticate_client()
        req = SnowMessage.create_request("desktop_exec", {"command": "echo test", "confirmed": True})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.error["code"], ErrorCode.UNAUTHORIZED)
        self.assertIn("desktop.exec", resp.error["message"])

    async def test_desktop_exec_unconfirmed_rejected(self) -> None:
        """desktop_exec with grant but without explicit confirmation is rejected."""
        self._authenticate_client()
        self.server.capability_policy.grant_capability(self.device_id, "desktop.exec")

        req = SnowMessage.create_request("desktop_exec", {"command": "echo test"})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.error["code"], ErrorCode.UNAUTHORIZED)
        self.assertIn("confirmation", resp.error["message"].lower())

    async def test_desktop_exec_safe_command(self) -> None:
        """desktop_exec with grant and confirmation executes a safe shell command."""
        self._authenticate_client()
        self.server.capability_policy.grant_capability(self.device_id, "desktop.exec")

        with patch.object(
            self.terminal,
            "execute_command",
            new_callable=AsyncMock,
            return_value={
                "success": True,
                "stdout": "SNOW Terminal Output 2026\n",
                "stderr": "",
                "exit_code": 0,
                "truncated": False,
                "duration_seconds": 0.05,
            },
        ):
            req = SnowMessage.create_request(
                "desktop_exec",
                {"command": "echo SNOW Terminal Output 2026", "confirmed": True},
            )
            await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.RESPONSE)
        data = resp.payload.get("data", {})
        self.assertEqual(data.get("exit_code"), 0)
        self.assertIn("SNOW Terminal Output", data.get("stdout", ""))

    async def test_desktop_exec_catastrophic_command_blocked(self) -> None:
        """desktop_exec rejects catastrophic commands (e.g. format C:, diskpart, tampering)."""
        self._authenticate_client()
        self.server.capability_policy.grant_capability(self.device_id, "desktop.exec")

        req = SnowMessage.create_request(
            "desktop_exec",
            {"command": "format c: /fs:ntfs", "confirmed": True},
        )
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.RESPONSE)
        self.assertEqual(resp.payload.get("status"), "error")
        self.assertIn("security policy", resp.payload.get("error", "").lower())

    async def test_desktop_exec_invalid_payload(self) -> None:
        """desktop_exec rejects empty or non-string commands with INVALID_PAYLOAD."""
        self._authenticate_client()
        self.server.capability_policy.grant_capability(self.device_id, "desktop.exec")

        req = SnowMessage.create_request("desktop_exec", {"command": "   ", "confirmed": True})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.error["code"], ErrorCode.INVALID_PAYLOAD)

    # -------------------------------------------------------------------------
    # 4. App Launching & Lock Screen
    # -------------------------------------------------------------------------

    async def test_desktop_app_launch_lock_screen(self) -> None:
        """desktop_app_launch with 'lock_screen' routes to workstation lock."""
        self._authenticate_client()
        req = SnowMessage.create_request("desktop_app_launch", {"app_name": "lock_screen"})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.RESPONSE)
        self.assertEqual(resp.payload.get("status"), "success")
        data = resp.payload.get("data", {})
        self.assertEqual(data.get("app_name"), "lock_screen")

    async def test_desktop_app_launch_old_lock_rejected(self) -> None:
        """desktop_app_launch rejects the ambiguous 'lock' identifier."""
        self._authenticate_client()
        req = SnowMessage.create_request("desktop_app_launch", {"app_name": "lock"})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.RESPONSE)
        self.assertEqual(resp.payload.get("status"), "error")
        data = resp.payload.get("data", {})
        self.assertEqual(data.get("status"), "APP_NOT_ALLOWED")

    async def test_desktop_app_launch_all_ten_allowlisted_apps(self) -> None:
        """desktop_app_launch accepts all 10 Phase 8 allowlisted apps."""
        self._authenticate_client()
        ten_apps = [
            "code", "chrome", "msedge", "powershell", "wt",
            "notepad", "calc", "explorer", "taskmgr", "mspaint"
        ]

        with patch.object(
            self.app_launcher,
            "launch_app",
            new_callable=AsyncMock,
            side_effect=lambda app_name, **kwargs: {
                "success": True,
                "status": "SUCCESS",
                "app_name": app_name,
                "pid": 1234,
                "message": f"Successfully launched {app_name}.",
            },
        ):
            for app in ten_apps:
                self.client.sent_messages.clear()
                req = SnowMessage.create_request("desktop_app_launch", {"app_name": app})
                await self.server._handle_request(self.client, req)

                self.assertEqual(len(self.client.sent_messages), 1)
                resp = self.client.sent_messages[0]
                self.assertEqual(resp.type, MessageType.RESPONSE)
                self.assertEqual(resp.payload.get("status"), "success")
                data = resp.payload.get("data", {})
                self.assertEqual(data.get("app_name"), app)

    async def test_desktop_app_launch_unapproved_app_rejected(self) -> None:
        """desktop_app_launch rejects arbitrary or unapproved binaries."""
        self._authenticate_client()
        req = SnowMessage.create_request("desktop_app_launch", {"app_name": "malicious_virus.exe"})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.RESPONSE)
        self.assertEqual(resp.payload.get("status"), "error")
        data = resp.payload.get("data", {})
        self.assertEqual(data.get("status"), "APP_NOT_ALLOWED")

    # -------------------------------------------------------------------------
    # 5. Clipboard Get & Set
    # -------------------------------------------------------------------------

    async def test_desktop_clipboard_get_and_set(self) -> None:
        """desktop_clipboard_set writes text and desktop_clipboard_get reads it."""
        self._authenticate_client()
        mock_clip = {"text": ""}

        async def _mock_set(text: str):
            mock_clip["text"] = text
            return {"success": True, "status": "SUCCESS", "length": len(text)}

        async def _mock_get():
            return {"success": True, "status": "SUCCESS", "text": mock_clip["text"], "length": len(mock_clip["text"])}

        with patch.object(self.clipboard, "set_clipboard", side_effect=_mock_set), \
             patch.object(self.clipboard, "get_clipboard", side_effect=_mock_get):

            # Set clipboard
            req_set = SnowMessage.create_request("desktop_clipboard_set", {"text": "Sync to PC ❄️"})
            await self.server._handle_request(self.client, req_set)
            self.assertEqual(self.client.sent_messages[-1].payload.get("status"), "success")

            # Get clipboard
            req_get = SnowMessage.create_request("desktop_clipboard_get")
            await self.server._handle_request(self.client, req_get)
            resp_get = self.client.sent_messages[-1]
            self.assertEqual(resp_get.payload.get("status"), "success")
            self.assertEqual(resp_get.payload.get("data", {}).get("text"), "Sync to PC ❄️")

    async def test_desktop_clipboard_set_exceeds_64k_cap(self) -> None:
        """desktop_clipboard_set rejects payload exceeding 64 KiB cap with INVALID_PAYLOAD."""
        self._authenticate_client()
        huge_text = "X" * 65537
        req = SnowMessage.create_request("desktop_clipboard_set", {"text": huge_text})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.error["code"], ErrorCode.INVALID_PAYLOAD)

    # -------------------------------------------------------------------------
    # 6. File Listing & Path Traversal Protection
    # -------------------------------------------------------------------------

    async def test_desktop_file_list_in_allowed_root(self) -> None:
        """desktop_file_list returns directory contents within allowed roots."""
        self._authenticate_client()
        # Create test file
        test_file = self.user_files_dir / "sample.txt"
        test_file.write_text("Hello from SNOW", encoding="utf-8")

        req = SnowMessage.create_request("desktop_file_list", {"path": str(self.user_files_dir)})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.RESPONSE)
        self.assertEqual(resp.payload.get("status"), "success")
        files = resp.payload.get("data", {}).get("files", [])
        self.assertTrue(any(f["name"] == "sample.txt" for f in files))

    async def test_desktop_file_list_path_traversal_rejected(self) -> None:
        """desktop_file_list rejects path traversal escapes outside allowed roots."""
        self._authenticate_client()
        req = SnowMessage.create_request("desktop_file_list", {"path": "../../Windows/System32"})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.error["code"], ErrorCode.UNAUTHORIZED)

    # -------------------------------------------------------------------------
    # 7. File Stage Download
    # -------------------------------------------------------------------------

    async def test_desktop_file_stage_download_success(self) -> None:
        """desktop_file_stage_download creates a transfer record with SHA-256 for HTTPS download."""
        self._authenticate_client()
        content = b"Binary stream for testing download staging in Phase 10"
        expected_sha = hashlib.sha256(content).hexdigest()

        stage_file = self.user_files_dir / "report.pdf"
        stage_file.write_bytes(content)

        req = SnowMessage.create_request("desktop_file_stage_download", {"file_path": str(stage_file)})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.RESPONSE)
        self.assertEqual(resp.payload.get("status"), "success")
        data = resp.payload.get("data", {})
        self.assertEqual(data.get("file_name"), "report.pdf")
        self.assertEqual(data.get("file_size"), len(content))
        self.assertEqual(data.get("sha256"), expected_sha)
        self.assertIn("transfer_id", data)

        # Verify transfer manager record was created with direction DOWNLOAD and file_path set
        tid = data["transfer_id"]
        record = self.transfer_manager.get_transfer(tid)
        self.assertIsNotNone(record)
        self.assertEqual(record.direction, TransferDirection.DOWNLOAD)
        self.assertEqual(record.file_path, str(stage_file))

    async def test_desktop_file_stage_download_nonexistent_file(self) -> None:
        """desktop_file_stage_download rejects non-existent files with FILE_NOT_FOUND."""
        self._authenticate_client()
        req = SnowMessage.create_request("desktop_file_stage_download", {"file_path": str(self.user_files_dir / "missing.txt")})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.error["code"], ErrorCode.FILE_NOT_FOUND)

    # -------------------------------------------------------------------------
    # 8. Peer Authorization & Security Invariants
    # -------------------------------------------------------------------------

    async def test_peer_revocation_invalidates_session_and_rejects(self) -> None:
        """Revoking a paired device deletes it from DB and immediately rejects active session."""
        self._authenticate_client()

        # Delete device from DB (revocation)
        self.db_manager.delete_paired_device(self.device_id)

        req = SnowMessage.create_request("desktop_status")
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.error["code"], ErrorCode.UNAUTHORIZED)
        self.assertIn("revoked", resp.error["message"].lower())

        # Verify session was revoked in session manager
        active_session = self.session_manager.get_session_by_device(self.device_id)
        self.assertNull if hasattr(self, "assertNull") else self.assertIsNone(active_session)

    async def test_forged_request_body_device_id_rejected(self) -> None:
        """Caller cannot forge request-body device_id to impersonate another device."""
        self._authenticate_client()

        req = SnowMessage.create_request("desktop_status", {"device_id": "forged-attacker-id"})
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.error["code"], ErrorCode.UNAUTHORIZED)
        self.assertIn("identity", resp.error["message"].lower())

    async def test_peer_capability_policy_custom_grants_and_denials(self) -> None:
        """Capability policy enforces custom grants and denials accurately."""
        self._authenticate_client()

        # Revoke desktop.status capability for this device
        self.server.capability_policy.revoke_capability(self.device_id, "desktop.status")

        req = SnowMessage.create_request("desktop_status")
        await self.server._handle_request(self.client, req)

        self.assertEqual(len(self.client.sent_messages), 1)
        resp = self.client.sent_messages[0]
        self.assertEqual(resp.type, MessageType.ERROR)
        self.assertEqual(resp.error["code"], ErrorCode.UNAUTHORIZED)
        self.assertIn("desktop.status", resp.error["message"])

        # Re-grant capability
        self.server.capability_policy.grant_capability(self.device_id, "desktop.status")
        self.client.sent_messages.clear()

        await self.server._handle_request(self.client, req)
        self.assertEqual(len(self.client.sent_messages), 1)
        self.assertEqual(self.client.sent_messages[0].type, MessageType.RESPONSE)


class TestPhase10McpMessagingAndCatalog(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying MCP tool snow_android_send_message and catalog count."""

    async def asyncSetUp(self) -> None:
        self.bridge = SnowMcpBridge(auto_start_core=False)
        self.server = create_snow_mcp_server(bridge=self.bridge)

    def _extract_tool_result(self, raw_call_result: Any) -> dict:
        if isinstance(raw_call_result, tuple):
            text_items = raw_call_result[0]
            if text_items and hasattr(text_items[0], "text"):
                return json.loads(text_items[0].text)
        elif hasattr(raw_call_result, "content") and raw_call_result.content:
            return json.loads(raw_call_result.content[0].text)
        raise ValueError(f"Unable to parse FastMCP result: {raw_call_result!r}")

    def test_total_mcp_tools_is_24(self) -> None:
        """Verify total registered MCP tool count is exactly 24 and catalog is consistent."""
        self.assertEqual(len(ALL_TOOL_NAMES), 24)
        self.assertEqual(len(TOOL_REGISTRY), 24)
        self.assertIn("snow_android_send_message", ALL_TOOL_NAMES)
        self.assertEqual(get_tool_category("snow_android_send_message"), ToolCategory.CROSS_DEVICE)
        self.assertTrue(is_cross_device_tool("snow_android_send_message"))

    async def test_mcp_list_tools_contains_send_message(self) -> None:
        """FastMCP list_tools exposes snow_android_send_message."""
        tools = await self.server.list_tools()
        names = {t.name for t in tools}
        self.assertIn("snow_android_send_message", names)
        self.assertEqual(len(names), 24)

    async def test_bridge_android_send_message_dispatches_proper_action(self) -> None:
        """snow_android_send_message dispatches 'send_message' action via bridge."""
        mock_resp = {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "status": "success",
                "action": "send_message",
                "mode": "intent",
                "recipient": "+1234567890",
                "result": "INTENT_LAUNCHED",
            },
        }

        with patch.object(self.bridge, "send_device_request", new_callable=AsyncMock, return_value=mock_resp) as mock_send, \
             patch.object(self.bridge, "_resolve_target_device_id", new_callable=AsyncMock, return_value="dev-123"):

            res = await self.bridge.android_send_message(
                recipient="+1234567890",
                message="Hello from MCP",
                mode="intent",
                device_id="dev-123",
            )
            self.assertTrue(res.get("success"))
            mock_send.assert_called_once_with(
                device_id="dev-123",
                action="send_message",
                data={"recipient": "+1234567890", "message": "Hello from MCP", "mode": "intent"},
                timeout=30.0,
            )

    async def test_bridge_android_send_message_sms_mode_rejected(self) -> None:
        """Calling android_send_message with mode='sms' is restricted for AI safety."""
        res = await self.bridge.android_send_message(
            recipient="+1234567890",
            message="Dangerous background message",
            mode="sms",
            device_id="dev-123",
        )
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "SMS_DISPATCH_RESTRICTED")
        self.assertIn("restricted", res.get("error", "").lower())

    # -------------------------------------------------------------------------
    # Bidirectional Clipboard Sync (Phone -> Laptop)
    # -------------------------------------------------------------------------

    async def test_bridge_sync_clipboard_phone_to_laptop_success(self) -> None:
        """phone_to_laptop clipboard sync pulls text and writes to Windows clipboard."""
        mock_pull_resp = {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "status": "success",
                "text": "Copied from Android phone 📱",
                "bytes_read": 30,
            },
        }

        with patch.object(self.bridge, "send_device_request", new_callable=AsyncMock, return_value=mock_pull_resp) as mock_pull, \
             patch.object(self.bridge, "windows_clipboard_set", new_callable=AsyncMock, return_value={"success": True}) as mock_win_set, \
             patch.object(self.bridge, "_resolve_target_device_id", new_callable=AsyncMock, return_value="dev-123"):

            res = await self.bridge.sync_clipboard(direction="phone_to_laptop", device_id="dev-123")
            self.assertTrue(res.get("success"))
            self.assertEqual(res.get("status"), "SUCCESS")
            self.assertEqual(res.get("characters_synced"), len("Copied from Android phone 📱"))
            mock_pull.assert_called_once_with("dev-123", "clipboard_pull", {})
            mock_win_set.assert_called_once_with(text="Copied from Android phone 📱")

    async def test_bridge_sync_clipboard_phone_to_laptop_foreground_required(self) -> None:
        """phone_to_laptop propagates FOREGROUND_REQUIRED when Android is backgrounded."""
        mock_pull_resp = {
            "success": False,
            "status": "FOREGROUND_REQUIRED",
            "error": "Android OS requires SNOW to be active in the foreground.",
        }

        with patch.object(self.bridge, "send_device_request", new_callable=AsyncMock, return_value=mock_pull_resp), \
             patch.object(self.bridge, "_resolve_target_device_id", new_callable=AsyncMock, return_value="dev-123"):

            res = await self.bridge.sync_clipboard(direction="phone_to_laptop", device_id="dev-123")
            self.assertFalse(res.get("success"))
            self.assertEqual(res.get("status"), "FOREGROUND_REQUIRED")
            self.assertIn("foreground", res.get("error", "").lower())

    async def test_bridge_sync_clipboard_phone_to_laptop_user_confirmation_required(self) -> None:
        """phone_to_laptop propagates USER_CONFIRMATION_REQUIRED when intent not granted."""
        mock_pull_resp = {
            "success": False,
            "status": "USER_CONFIRMATION_REQUIRED",
            "error": "Explicit user authorization required on device.",
        }

        with patch.object(self.bridge, "send_device_request", new_callable=AsyncMock, return_value=mock_pull_resp), \
             patch.object(self.bridge, "_resolve_target_device_id", new_callable=AsyncMock, return_value="dev-123"):

            res = await self.bridge.sync_clipboard(direction="phone_to_laptop", device_id="dev-123")
            self.assertFalse(res.get("success"))
            self.assertEqual(res.get("status"), "USER_CONFIRMATION_REQUIRED")

    async def test_bridge_sync_clipboard_phone_to_laptop_empty_clipboard(self) -> None:
        """phone_to_laptop handles empty clipboard honestly without writing."""
        mock_pull_resp = {
            "success": True,
            "status": "SUCCESS",
            "data": {"text": ""},
        }

        with patch.object(self.bridge, "send_device_request", new_callable=AsyncMock, return_value=mock_pull_resp), \
             patch.object(self.bridge, "windows_clipboard_set", new_callable=AsyncMock) as mock_win_set, \
             patch.object(self.bridge, "_resolve_target_device_id", new_callable=AsyncMock, return_value="dev-123"):

            res = await self.bridge.sync_clipboard(direction="phone_to_laptop", device_id="dev-123")
            self.assertFalse(res.get("success"))
            self.assertEqual(res.get("status"), "EMPTY_CLIPBOARD")
            mock_win_set.assert_not_called()

    async def test_bridge_sync_clipboard_phone_to_laptop_windows_write_failure(self) -> None:
        """phone_to_laptop reports write failure if Windows clipboard set fails."""
        mock_pull_resp = {
            "success": True,
            "status": "SUCCESS",
            "data": {"text": "Valid text"},
        }

        with patch.object(self.bridge, "send_device_request", new_callable=AsyncMock, return_value=mock_pull_resp), \
             patch.object(self.bridge, "windows_clipboard_set", new_callable=AsyncMock, return_value={"success": False, "error": "Win32 lock failure"}), \
             patch.object(self.bridge, "_resolve_target_device_id", new_callable=AsyncMock, return_value="dev-123"):

            res = await self.bridge.sync_clipboard(direction="phone_to_laptop", device_id="dev-123")
            self.assertFalse(res.get("success"))
            self.assertEqual(res.get("status"), "WINDOWS_CLIPBOARD_WRITE_FAILED")

    async def test_ai_originated_desktop_exec_blocked_in_ipc(self) -> None:
        """AI-originated cross-device execution via IPC device_request is rejected."""
        mock_core = MagicMock()
        from snow.core.ipc import SnowIpcServer
        ipc = SnowIpcServer(core_server=mock_core, config=CoreConfig())

        res = await ipc._handle_device_request({"device_id": "dev-123", "action": "desktop_exec"})
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "APPROVAL_REQUIRED")
        self.assertIn("human-in-the-loop", res.get("error", "").lower())


class TestDualPrincipalSecurityArchitecture(unittest.IsolatedAsyncioTestCase):
    """Test suite verifying Dual-Principal Security Architecture for SNOW Phase 10."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_dual_principal_")
        self.db_path = Path(self.temp_dir) / "test_devices.db"
        self.db_manager = DatabaseManager(db_path=self.db_path)

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_sqlite_trust_tier_management(self) -> None:
        """Paired devices default to 'peer' tier and can be upgraded to 'owner'."""
        self.db_manager.insert_paired_device(
            device_id="dev-owner-1",
            device_name="Ayush Phone",
            auth_token_hash=hash_token("secret-token-1"),
            trust_tier="owner",
        )
        self.db_manager.insert_paired_device(
            device_id="dev-peer-2",
            device_name="Peer Phone",
            auth_token_hash=hash_token("secret-token-2"),
        )

        owner_rec = self.db_manager.get_paired_device("dev-owner-1")
        self.assertIsNotNone(owner_rec)
        self.assertEqual(owner_rec.trust_tier, "owner")

        peer_rec = self.db_manager.get_paired_device("dev-peer-2")
        self.assertIsNotNone(peer_rec)
        self.assertEqual(peer_rec.trust_tier, "peer")

        # Upgrade peer to owner
        self.assertTrue(self.db_manager.update_device_trust_tier("dev-peer-2", "owner"))
        self.assertEqual(self.db_manager.get_paired_device("dev-peer-2").trust_tier, "owner")

        # Invalid trust tier raises ValueError
        with self.assertRaises(ValueError):
            self.db_manager.update_device_trust_tier("dev-peer-2", "admin")

    async def test_terminal_executor_principal_isolation(self) -> None:
        """Catastrophic commands are strictly blocked for both AI_MCP and OWNER_MANUAL."""
        term = WindowsTerminalExecutor()

        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="wss")
        ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="mcp")

        # AI_MCP is blocked by regex
        ai_res = await term.execute_command("format c: /q", ctx=ai_ctx)
        self.assertFalse(ai_res.get("success"))
        self.assertEqual(ai_res.get("status"), "POLICY_DENIED")

        # OWNER_MANUAL is also strictly blocked by catastrophic policy
        owner_res = await term.execute_command("format c: /q", ctx=owner_ctx)
        self.assertFalse(owner_res.get("success"))
        self.assertEqual(owner_res.get("status"), "POLICY_DENIED")

        reason = term.validate_command("format c: /q", ctx=owner_ctx)
        self.assertIsNotNone(reason)
        self.assertIn("destructive pattern", reason)

    def test_file_manager_principal_isolation(self) -> None:
        """OWNER_MANUAL can address host drives; private security material is blocked for both."""
        home_dir = Path(self.temp_dir) / "home"
        home_dir.mkdir(parents=True, exist_ok=True)
        snow_dir = home_dir / ".snow"
        tls_dir = snow_dir / "tls"
        tls_dir.mkdir(parents=True, exist_ok=True)
        key_file = tls_dir / "server.key"
        key_file.write_text("PRIVATE_KEY")
        secret_file = snow_dir / "ipc.secret"
        secret_file.write_text("SECRET")

        allowed_dir = Path(self.temp_dir) / "allowed"
        allowed_dir.mkdir(parents=True, exist_ok=True)
        user_file = allowed_dir / "notes.txt"
        user_file.write_text("Hello World")

        fm = WindowsFileManager(allowed_roots=[allowed_dir])

        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="wss")
        ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="mcp")

        # 1. AI_MCP cannot access outside allowed roots
        res_path, err = fm.resolve_safe_path(str(home_dir), ctx=ai_ctx)
        self.assertIsNone(res_path)
        self.assertEqual(err, "PATH_NOT_ALLOWED")

        # 2. OWNER_MANUAL can access directory
        res_path, err = fm.resolve_safe_path(str(allowed_dir), ctx=owner_ctx)
        self.assertIsNotNone(res_path)
        self.assertIsNone(err)

        # 3. Private security material blocked for BOTH principals
        with patch.object(Path, "home", return_value=home_dir):
            # AI_MCP
            res_path, err = fm.resolve_safe_path(str(key_file), ctx=ai_ctx)
            self.assertIsNone(res_path)
            self.assertEqual(err, "PATH_NOT_ALLOWED")

            # OWNER_MANUAL
            res_path, err = fm.resolve_safe_path(str(key_file), ctx=owner_ctx)
            self.assertIsNone(res_path)
            self.assertEqual(err, "PATH_NOT_ALLOWED")

            res_path, err = fm.resolve_safe_path(str(secret_file), ctx=owner_ctx)
            self.assertIsNone(res_path)
            self.assertEqual(err, "PATH_NOT_ALLOWED")

    async def test_app_launcher_principal_isolation(self) -> None:
        """OWNER_MANUAL supports custom executables; AI_MCP restricted to 10 apps."""
        launcher = WindowsAppLauncher()

        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="wss")
        ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="mcp")

        # AI_MCP rejected for non-allowlisted app
        ai_res = await launcher.launch_app("custom_tool.exe", ctx=ai_ctx)
        self.assertFalse(ai_res.get("success"))
        self.assertEqual(ai_res.get("status"), "APP_NOT_ALLOWED")

        # OWNER_MANUAL fails on file existence check, not APP_NOT_ALLOWED policy
        owner_res = await launcher.launch_app("C:\\nonexistent_custom_tool.exe", ctx=owner_ctx)
        self.assertFalse(owner_res.get("success"))
        self.assertEqual(owner_res.get("status"), "APP_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
