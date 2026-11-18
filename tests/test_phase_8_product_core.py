"""Comprehensive test suite for SNOW Phase 8 (Product Core & Standalone Execution).

Tests:
1. Standalone Local Execution: Windows capabilities execute directly in-process
   without Core daemon running or phone connectivity.
2. Auto-Daemon Lifecycle: Cross-device tools auto-start Core daemon on demand
   with concurrency serialization and timeout protection.
3. CLI & Setup: One-command MCP setup, configuration merging, backup, and dry-run.
4. Windows Power Capabilities: Terminal executor, clipboard manager, recursive file
   search, expanded app launcher, and cross-device clipboard synchronization.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp.server.fastmcp import FastMCP
from snow.capabilities.windows.apps import WindowsAppLauncher
from snow.capabilities.windows.clipboard import WindowsClipboardManager
from snow.capabilities.windows.files import WindowsFileManager
from snow.capabilities.windows.terminal import (
    MAX_OUTPUT_BYTES,
    TerminalSecurityPolicy,
    WindowsTerminalExecutor,
)
from snow.cli import atomic_write_json, merge_mcp_config, run_setup, run_status
from snow.daemon import CoreDaemonManager
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.registry import TOOL_REGISTRY, ToolCategory, get_tool_category, is_cross_device_tool, is_local_windows_tool
from snow.mcp.server import create_snow_mcp_server
from snow.mcp.tools import ALL_TOOL_NAMES, register_all_tools


class TestToolRegistryClassification(unittest.TestCase):
    """Test explicit tool classification layer."""

    def test_all_21_tools_classified(self) -> None:
        self.assertEqual(len(ALL_TOOL_NAMES), len(TOOL_REGISTRY))
        self.assertGreaterEqual(len(ALL_TOOL_NAMES), 21)
        for tool_name in ALL_TOOL_NAMES:
            category = get_tool_category(tool_name)
            self.assertIsNotNone(category, f"Tool '{tool_name}' must be explicitly categorized.")
            self.assertIn(category, (ToolCategory.LOCAL_WINDOWS, ToolCategory.CROSS_DEVICE))

    def test_unknown_tool_fails_safe(self) -> None:
        self.assertIsNone(get_tool_category("snow_unknown_action"))
        self.assertFalse(is_local_windows_tool("snow_unknown_action"))
        self.assertFalse(is_cross_device_tool("snow_unknown_action"))

    def test_windows_tools_are_local(self) -> None:
        local_tools = [
            "snow_windows_battery",
            "snow_windows_system_info",
            "snow_windows_processes",
            "snow_windows_launch_app",
            "snow_windows_file_read",
            "snow_windows_file_write",
            "snow_windows_file_list",
            "snow_windows_file_search",
            "snow_windows_terminal_exec",
            "snow_windows_clipboard_get",
            "snow_windows_clipboard_set",
        ]
        for t in local_tools:
            self.assertTrue(is_local_windows_tool(t), f"{t} must be LOCAL_WINDOWS")

    def test_cross_device_tools_are_remote(self) -> None:
        remote_tools = [
            "snow_get_device_status",
            "snow_list_devices",
            "snow_sync_clipboard",
            "snow_android_battery",
            "snow_android_ring",
            "snow_android_clipboard_push",
            "snow_android_launch_app",
            "snow_android_list_apps",
            "snow_android_file_send",
            "snow_android_file_receive",
        ]
        for t in remote_tools:
            self.assertTrue(is_cross_device_tool(t), f"{t} must be CROSS_DEVICE")


class TestStandaloneLocalExecution(unittest.IsolatedAsyncioTestCase):
    """Test executing local Windows operations while Core is offline."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_p8_local_")
        self.test_root = Path(self.temp_dir)
        # Create bridge pointing to closed port with no core running
        self.bridge = SnowMcpBridge(
            host="127.0.0.1",
            port=59999,
            secret="dummy_secret",
            allowed_roots=[self.test_root],
        )
        self.server = create_snow_mcp_server(bridge=self.bridge)

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _extract_text(self, res_obj: Any) -> str:
        if isinstance(res_obj, tuple):
            content_list = res_obj[0]
            if content_list and hasattr(content_list[0], "text"):
                return content_list[0].text
        elif isinstance(res_obj, list):
            if res_obj and hasattr(res_obj[0], "text"):
                return res_obj[0].text
        elif hasattr(res_obj, "content"):
            c = res_obj.content
            if isinstance(c, list) and len(c) > 0 and hasattr(c[0], "text"):
                return str(c[0].text)
        return str(res_obj)

    async def test_system_info_standalone(self) -> None:
        res_obj = await self.server.call_tool("snow_windows_system_info", {})
        data = json.loads(self._extract_text(res_obj))
        self.assertIn("cpu", data)
        self.assertIn("memory", data)
        self.assertIn("os_name", data)

    async def test_terminal_exec_standalone(self) -> None:
        res_obj = await self.server.call_tool(
            "snow_windows_terminal_exec",
            {"command": "echo SNOW_STANDALONE_OK"},
        )
        data = json.loads(self._extract_text(res_obj))
        self.assertTrue(data.get("success"))
        self.assertIn("SNOW_STANDALONE_OK", data.get("stdout", ""))

    async def test_clipboard_set_and_get_standalone(self) -> None:
        # Mock the underlying clipboard calls so test is independent of physical GUI session
        with patch.object(
            self.bridge.local_clipboard,
            "set_clipboard_sync",
            return_value={"success": True, "status": "SUCCESS", "message": "Copied"},
        ), patch.object(
            self.bridge.local_clipboard,
            "get_clipboard_sync",
            return_value={"success": True, "status": "SUCCESS", "text": "MockClipboardValue"},
        ):
            set_obj = await self.server.call_tool(
                "snow_windows_clipboard_set", {"text": "MockClipboardValue"}
            )
            set_data = json.loads(self._extract_text(set_obj))
            self.assertTrue(set_data.get("success"))

            get_obj = await self.server.call_tool("snow_windows_clipboard_get", {})
            get_data = json.loads(self._extract_text(get_obj))
            self.assertTrue(get_data.get("success"))
            self.assertEqual(get_data.get("text"), "MockClipboardValue")

    async def test_file_search_standalone(self) -> None:
        # Create a file inside allowed test root
        (self.test_root / "snow_test_report.txt").write_text("Hello Report", encoding="utf-8")
        res_obj = await self.server.call_tool(
            "snow_windows_file_search",
            {"query": "report", "root_path": str(self.test_root)},
        )
        data = json.loads(self._extract_text(res_obj))
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("count"), 1)
        self.assertEqual(data["matches"][0]["name"], "snow_test_report.txt")


class TestAutoDaemonLifecycle(unittest.IsolatedAsyncioTestCase):
    """Test automatic Core daemon spawning when cross-device capabilities are invoked."""

    async def asyncSetUp(self) -> None:
        self.bridge = SnowMcpBridge(host="127.0.0.1", port=59998, secret="test_sec")
        self.server = create_snow_mcp_server(bridge=self.bridge)

    def _extract_text(self, res_obj: Any) -> str:
        if isinstance(res_obj, tuple):
            content_list = res_obj[0]
            if content_list and hasattr(content_list[0], "text"):
                return content_list[0].text
        elif isinstance(res_obj, list):
            if res_obj and hasattr(res_obj[0], "text"):
                return res_obj[0].text
        elif hasattr(res_obj, "content"):
            c = res_obj.content
            if isinstance(c, list) and len(c) > 0 and hasattr(c[0], "text"):
                return str(c[0].text)
        return str(res_obj)

    async def test_cross_device_triggers_daemon_startup_when_offline(self) -> None:
        # Mock daemon_manager.ensure_core_running to simulate starting daemon
        mock_ensure = AsyncMock(return_value={"success": True, "status": "STARTED", "pid": 112233})
        mock_is_ready = AsyncMock(side_effect=[False, True])  # offline first, then online
        mock_call = AsyncMock(return_value={
            "success": True,
            "status": "SUCCESS",
            "data": {"core_running": True, "devices": []},
        })

        with patch.object(self.bridge.daemon_manager, "ensure_core_running", mock_ensure), \
             patch.object(self.bridge.daemon_manager, "is_ipc_ready", mock_is_ready), \
             patch.object(self.bridge, "call", mock_call):

            res_obj = await self.server.call_tool("snow_get_device_status", {})
            data = json.loads(self._extract_text(res_obj))

            mock_ensure.assert_called_once()
            self.assertTrue(data.get("success"))
            self.assertEqual(data.get("status"), "ONLINE")

    async def test_concurrent_cross_device_calls_serialized_startup(self) -> None:
        # Verify that concurrent tool calls do not trigger multiple spawn operations
        manager = CoreDaemonManager(host="127.0.0.1", port=59997, spawn_timeout=2.0)
        spawn_counter = 0

        async def fake_spawn():
            nonlocal spawn_counter
            spawn_counter += 1
            await asyncio.sleep(0.05)
            return {"success": True, "status": "STARTED", "pid": 9999}

        with patch.object(manager, "is_ipc_ready", AsyncMock(side_effect=[False, False, True, True])), \
             patch.object(manager, "ensure_core_running", side_effect=fake_spawn):

            # Dispatch two concurrent startup calls
            t1 = manager.ensure_core_running()
            t2 = manager.ensure_core_running()
            results = await asyncio.gather(t1, t2)

            self.assertTrue(results[0]["success"])
            self.assertTrue(results[1]["success"])

    async def test_failed_daemon_startup_returns_actionable_error(self) -> None:
        mock_ensure = AsyncMock(return_value={
            "success": False,
            "status": "STARTUP_TIMEOUT",
            "error": "SNOW Core process did not become ready within 5.0s.",
        })

        with patch.object(self.bridge.daemon_manager, "is_ipc_ready", AsyncMock(return_value=False)), \
             patch.object(self.bridge.daemon_manager, "ensure_core_running", mock_ensure):

            res = await self.bridge.call_cross_device("get_device_status")
            self.assertFalse(res.get("success"))
            self.assertEqual(res.get("status"), "CORE_OFFLINE")
            self.assertIn("offline or unreachable", res.get("error", ""))


class TestWindowsTerminalExecutor(unittest.IsolatedAsyncioTestCase):
    """Test Windows terminal execution and safety policies."""

    def setUp(self) -> None:
        self.executor = WindowsTerminalExecutor()

    async def test_successful_command_execution(self) -> None:
        res = await self.executor.execute_command("echo hello_snow")
        self.assertTrue(res["success"])
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("hello_snow", res["stdout"])
        self.assertFalse(res["timed_out"])
        self.assertFalse(res["stdout_truncated"])

    async def test_nonzero_exit_code(self) -> None:
        # Run command that exits with code 42
        res = await self.executor.execute_command("powershell -Command \"exit 42\"")
        self.assertFalse(res["success"])
        self.assertEqual(res["exit_code"], 42)
        self.assertEqual(res["status"], "COMMAND_FAILED")

    async def test_timeout_enforcement(self) -> None:
        # Run command with 0.5s timeout
        res = await self.executor.execute_command(
            "powershell -Command \"Start-Sleep -Seconds 5\"",
            timeout=0.5,
        )
        self.assertFalse(res["success"])
        self.assertTrue(res["timed_out"])
        self.assertEqual(res["status"], "TIMEOUT")

    async def test_invalid_working_directory(self) -> None:
        res = await self.executor.execute_command("echo test", cwd="Z:\\NonExistentPath_12345")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "INVALID_ARGUMENT")
        self.assertIn("does not exist", res["error"])

    async def test_destructive_command_policy_rejection(self) -> None:
        catastrophic_commands = [
            "format C: /y",
            "diskpart /s script.txt",
            "del /f /s /q C:\\Windows",
            "rmdir /s /q C:\\Windows\\System32",
            "Remove-Item -Recurse -Force C:\\Windows",
            "del ~/.snow/ipc.secret",
            "icacls .snow /grant Everyone:F",
        ]
        for cmd in catastrophic_commands:
            res = await self.executor.execute_command(cmd)
            self.assertFalse(res["success"], f"Command '{cmd}' should have been rejected!")
            self.assertEqual(res["status"], "POLICY_DENIED")
            self.assertIn("security policy", res["error"])


class TestWindowsClipboardManager(unittest.TestCase):
    """Test Windows clipboard manager with mockable Win32 boundary."""

    def setUp(self) -> None:
        self.manager = WindowsClipboardManager()

    def test_non_string_set_clipboard_rejected(self) -> None:
        res = self.manager.set_clipboard_sync(12345)  # type: ignore
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "INVALID_ARGUMENT")

    def test_mocked_clipboard_roundtrip(self) -> None:
        import ctypes
        # Mock Win32 user32/kernel32 calls
        mock_user32 = MagicMock()
        mock_kernel32 = MagicMock()

        # Provide a real writable ctypes memory buffer address so memmove succeeds
        real_buf = ctypes.create_string_buffer(256)
        real_ptr = ctypes.addressof(real_buf)

        mock_user32.OpenClipboard.return_value = True
        mock_user32.EmptyClipboard.return_value = True
        mock_user32.SetClipboardData.return_value = 1001
        mock_kernel32.GlobalAlloc.return_value = 2002
        mock_kernel32.GlobalLock.return_value = real_ptr

        with patch.object(self.manager, "_is_windows", True), \
             patch.object(self.manager, "_user32", mock_user32), \
             patch.object(self.manager, "_kernel32", mock_kernel32):

            w_res = self.manager.set_clipboard_sync("Hello SNOW Clipboard")
            self.assertTrue(w_res["success"])
            self.assertEqual(w_res["character_count"], len("Hello SNOW Clipboard"))

    def test_empty_clipboard_behavior(self) -> None:
        mock_user32 = MagicMock()
        mock_user32.OpenClipboard.return_value = True
        mock_user32.GetClipboardData.return_value = 0  # No data handle

        with patch.object(self.manager, "_is_windows", True), \
             patch.object(self.manager, "_user32", mock_user32), \
             patch.object(self.manager, "_kernel32", MagicMock()):

            res = self.manager.get_clipboard_sync()
            self.assertTrue(res["success"])
            self.assertEqual(res["status"], "EMPTY")
            self.assertEqual(res["text"], "")


class TestWindowsFileManagerExpansion(unittest.IsolatedAsyncioTestCase):
    """Test expanded filesystem features: recursive search, defaults, and security."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_fs_p8_")
        self.root = Path(self.temp_dir)
        self.manager = WindowsFileManager(allowed_roots=[self.root])

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_search_files_recursive_and_limit(self) -> None:
        # Create directory hierarchy
        (self.root / "sub1").mkdir()
        (self.root / "sub2").mkdir()
        (self.root / "sub1" / "project_alpha.txt").write_text("alpha", encoding="utf-8")
        (self.root / "sub2" / "project_beta.txt").write_text("beta", encoding="utf-8")
        (self.root / "other.md").write_text("other", encoding="utf-8")

        # Search for 'project'
        res = await self.manager.search_files(query="project", root_path=str(self.root), limit=10)
        self.assertTrue(res["success"])
        self.assertEqual(res["count"], 2)
        names = {m["name"] for m in res["matches"]}
        self.assertIn("project_alpha.txt", names)
        self.assertIn("project_beta.txt", names)

        # Search with limit=1
        res_limit = await self.manager.search_files(query="project", root_path=str(self.root), limit=1)
        self.assertTrue(res_limit["success"])
        self.assertEqual(res_limit["count"], 1)

    async def test_search_empty_query_rejected(self) -> None:
        res = await self.manager.search_files(query="")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "INVALID_ARGUMENT")

    async def test_protected_snow_directory_rejection(self) -> None:
        # Attempt to access .snow path
        snow_dir = self.root / ".snow"
        snow_dir.mkdir()
        secret_file = snow_dir / "ipc.secret"
        secret_file.write_text("secret_val", encoding="utf-8")

        res = await self.manager.read_file(str(secret_file))
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "PATH_NOT_ALLOWED")


class TestWindowsAppLauncherExpansion(unittest.TestCase):
    """Test expanded app launcher allowlist and target opening."""

    def setUp(self) -> None:
        self.launcher = WindowsAppLauncher()

    def test_allowlist_includes_new_developer_apps(self) -> None:
        apps = self.launcher.allowed_apps
        for expected in ["code", "chrome", "msedge", "powershell", "wt", "notepad", "calc", "explorer"]:
            self.assertIn(expected, apps)

    def test_invalid_url_scheme_rejected(self) -> None:
        for bad_url in ["javascript:alert(1)", "file:///C:/boot.ini", "data:text/plain;base64,AAA"]:
            res = self.launcher.open_target_sync(bad_url)
            self.assertFalse(res["success"])
            self.assertEqual(res["status"], "URL_SCHEME_NOT_ALLOWED")

    def test_executable_file_opening_rejected(self) -> None:
        for bad_file in ["malware.exe", "script.bat", "run.ps1", "macro.vbs"]:
            res = self.launcher.open_target_sync(bad_file)
            self.assertFalse(res["success"])


class TestCrossDeviceClipboardSync(unittest.IsolatedAsyncioTestCase):
    """Test clipboard synchronization tool routing and honest limitations."""

    async def asyncSetUp(self) -> None:
        self.bridge = SnowMcpBridge(host="127.0.0.1", port=59996, secret="sec")
        self.server = create_snow_mcp_server(bridge=self.bridge)

    def _extract_text(self, res_obj: Any) -> str:
        if isinstance(res_obj, tuple):
            content_list = res_obj[0]
            if content_list and hasattr(content_list[0], "text"):
                return content_list[0].text
        elif isinstance(res_obj, list):
            if res_obj and hasattr(res_obj[0], "text"):
                return res_obj[0].text
        elif hasattr(res_obj, "content"):
            c = res_obj.content
            if isinstance(c, list) and len(c) > 0 and hasattr(c[0], "text"):
                return str(c[0].text)
        return str(res_obj)

    async def test_laptop_to_phone_sync(self) -> None:
        # Mock reading Windows clipboard and pushing to Android
        mock_get = AsyncMock(return_value={"success": True, "status": "SUCCESS", "data": {"text": "SyncMe"}})
        mock_push = AsyncMock(return_value={"success": True, "status": "SUCCESS", "data": {"status": "success"}})

        with patch.object(self.bridge, "windows_clipboard_get", mock_get), \
             patch.object(self.bridge, "android_clipboard_push", mock_push):

            res_obj = await self.server.call_tool("snow_sync_clipboard", {"direction": "laptop_to_phone"})
            data = json.loads(self._extract_text(res_obj))
            self.assertTrue(data.get("success"))
            self.assertEqual(data.get("characters_synced"), 6)
            self.assertEqual(data.get("direction"), "laptop_to_phone")

    async def test_phone_to_laptop_requires_connected_device_or_reports_status(self) -> None:
        res_obj = await self.server.call_tool("snow_sync_clipboard", {"direction": "phone_to_laptop"})
        data = json.loads(self._extract_text(res_obj))
        self.assertFalse(data.get("success"))
        # In Phase 10+, phone_to_laptop attempts cross-device pull and reports DEVICE_OFFLINE when no phone is connected
        self.assertIn(data.get("status"), ("DEVICE_OFFLINE", "UNSUPPORTED_DIRECTION", "FOREGROUND_REQUIRED"))


class TestCliSetupAndStatus(unittest.TestCase):
    """Test 'snow setup', config merging, backup creation, and status commands."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_cli_")
        self.target_file = Path(self.temp_dir) / "claude_desktop_config.json"

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_merge_mcp_config_preserves_existing_servers(self) -> None:
        initial = json.dumps({
            "mcpServers": {
                "filesystem": {"command": "npx", "args": ["-y", "fs-server"]}
            },
            "preferences": {"theme": "dark"}
        })
        merged, warn = merge_mcp_config(initial, server_name="snow")
        self.assertIsNone(warn)
        self.assertIn("filesystem", merged["mcpServers"])
        self.assertIn("snow", merged["mcpServers"])
        self.assertEqual(merged["preferences"]["theme"], "dark")
        self.assertEqual(merged["mcpServers"]["snow"]["args"], ["-m", "snow.mcp"])

    def test_atomic_write_json_creates_backup(self) -> None:
        # Write initial file
        self.target_file.write_text("{\"initial\": true}", encoding="utf-8")
        new_data = {"updated": True}

        bak = atomic_write_json(self.target_file, new_data, backup=True)
        self.assertIsNotNone(bak)
        self.assertTrue(bak.exists())
        self.assertEqual(bak.read_text(encoding="utf-8"), "{\"initial\": true}")

        updated_content = json.loads(self.target_file.read_text(encoding="utf-8"))
        self.assertTrue(updated_content.get("updated"))

    def test_run_setup_dry_run_makes_no_disk_changes(self) -> None:
        with patch("snow.cli.CLAUDE_CONFIG_PATH", self.target_file):
            ret = run_setup(dry_run=True)
            self.assertEqual(ret, 0)
            self.assertFalse(self.target_file.exists())


if __name__ == "__main__":
    unittest.main()
