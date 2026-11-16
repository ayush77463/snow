"""Comprehensive unit and integration test suite for SNOW Phase 5 Windows capabilities.

Tests all four Windows capability modules (telemetry, processes, files, apps)
as well as their loopback IPC routing and FastMCP end-to-end tool execution.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from snow.capabilities.windows.apps import (
    ALLOWLIST_CANDIDATES,
    WindowsAppLauncher,
)
from snow.capabilities.windows.files import (
    DEFAULT_MAX_FILE_BYTES,
    WindowsFileManager,
)
from snow.capabilities.windows.processes import (
    DEFAULT_PROCESS_LIMIT,
    MAX_PROCESS_LIMIT,
    WindowsProcessMonitor,
)
from snow.capabilities.windows.telemetry import WindowsTelemetry
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.server import create_snow_mcp_server


class TestWindowsTelemetry(unittest.IsolatedAsyncioTestCase):
    """Test telemetry capability module."""

    def setUp(self) -> None:
        self.telemetry = WindowsTelemetry()

    def test_battery_no_battery(self) -> None:
        with patch("psutil.sensors_battery", return_value=None):
            res = self.telemetry.get_battery_sync()
            self.assertFalse(res["available"])
            self.assertEqual(res["status"], "NO_BATTERY")
            self.assertIsNone(res["percent"])
            self.assertIn("No system battery detected", res["message"])

    def test_battery_charging(self) -> None:
        mock_battery = MagicMock(
            percent=85.5,
            power_plugged=True,
            secsleft=-1,
        )
        with patch("psutil.sensors_battery", return_value=mock_battery):
            res = self.telemetry.get_battery_sync()
            self.assertTrue(res["available"])
            self.assertEqual(res["status"], "CHARGING")
            self.assertEqual(res["percent"], 85.5)
            self.assertTrue(res["power_plugged"])

    def test_battery_discharging(self) -> None:
        mock_battery = MagicMock(
            percent=42.0,
            power_plugged=False,
            secsleft=3600,
        )
        with patch("psutil.sensors_battery", return_value=mock_battery):
            res = self.telemetry.get_battery_sync()
            self.assertTrue(res["available"])
            self.assertEqual(res["status"], "DISCHARGING")
            self.assertEqual(res["percent"], 42.0)
            self.assertFalse(res["power_plugged"])
            self.assertEqual(res["secsleft"], 3600)

    def test_battery_query_exception(self) -> None:
        with patch("psutil.sensors_battery", side_effect=RuntimeError("WMI error")):
            res = self.telemetry.get_battery_sync()
            self.assertFalse(res["available"])
            self.assertEqual(res["status"], "ERROR")
            self.assertIn("WMI error", res["error"])

    async def test_async_battery_info(self) -> None:
        mock_battery = MagicMock(percent=100.0, power_plugged=True, secsleft=-1)
        with patch("psutil.sensors_battery", return_value=mock_battery):
            res = await self.telemetry.get_battery_info()
            self.assertTrue(res["available"])
            self.assertEqual(res["status"], "FULL")

    async def test_async_system_telemetry(self) -> None:
        res = await self.telemetry.get_system_telemetry()
        self.assertIn("hostname", res)
        self.assertIn("os_name", res)
        self.assertIn("cpu", res)
        self.assertIn("memory", res)
        self.assertIn("disk", res)
        self.assertIn("uptime_seconds", res)
        self.assertGreaterEqual(res["cpu"]["logical_cores"], 1)
        self.assertGreater(res["memory"]["total_mb"], 0)


class TestWindowsProcessMonitor(unittest.IsolatedAsyncioTestCase):
    """Test process monitoring capability module."""

    def setUp(self) -> None:
        self.monitor = WindowsProcessMonitor()

    async def test_list_processes_default(self) -> None:
        res = await self.monitor.list_processes()
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "SUCCESS")
        self.assertLessEqual(res["count"], DEFAULT_PROCESS_LIMIT)
        self.assertGreater(res["total_enumerated"], 0)
        self.assertEqual(res["sort_by"], "memory")
        for p in res["processes"]:
            self.assertIn("pid", p)
            self.assertIn("name", p)
            self.assertIn("cpu_percent", p)
            self.assertIn("memory_mb", p)
            self.assertIn("status", p)
            # Ensure sensitive information is never included
            self.assertNotIn("cmdline", p)
            self.assertNotIn("environ", p)
            self.assertNotIn("cwd", p)

    async def test_list_processes_limit_and_sort(self) -> None:
        res = await self.monitor.list_processes(limit=5, sort_by="cpu")
        self.assertTrue(res["success"])
        self.assertLessEqual(res["count"], 5)
        self.assertEqual(res["sort_by"], "cpu")

        # Test name sort
        res_name = await self.monitor.list_processes(limit=5, sort_by="name")
        self.assertTrue(res_name["success"])
        self.assertEqual(res_name["sort_by"], "name")

    async def test_list_processes_invalid_args(self) -> None:
        # Invalid limit
        res_neg = await self.monitor.list_processes(limit=0)
        self.assertFalse(res_neg["success"])
        self.assertEqual(res_neg["status"], "INVALID_ARGUMENT")

        res_over = await self.monitor.list_processes(limit=MAX_PROCESS_LIMIT + 1)
        self.assertFalse(res_over["success"])
        self.assertEqual(res_over["status"], "INVALID_ARGUMENT")

        # Invalid sort key
        res_sort = await self.monitor.list_processes(sort_by="invalid_key")
        self.assertFalse(res_sort["success"])
        self.assertEqual(res_sort["status"], "INVALID_ARGUMENT")

    def test_read_only_invariants(self) -> None:
        """Confirm no process modification methods exist on the monitor."""
        forbidden_attrs = ["kill", "terminate", "suspend", "resume", "kill_process", "stop_process"]
        for attr in forbidden_attrs:
            self.assertFalse(hasattr(self.monitor, attr), f"Forbidden method '{attr}' found on monitor!")


class TestWindowsFileManager(unittest.IsolatedAsyncioTestCase):
    """Test filesystem scoped operations capability module."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_fs_")
        self.manager = WindowsFileManager(allowed_roots=[self.temp_dir])
        self.root = Path(self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_read_write_file_roundtrip(self) -> None:
        # Write
        w_res = await self.manager.write_file("test.txt", "Hello SNOW!")
        self.assertTrue(w_res["success"])
        self.assertEqual(w_res["status"], "SUCCESS")
        self.assertEqual(w_res["name"], "test.txt")
        self.assertEqual(w_res["bytes_written"], 11)

        # Read
        r_res = await self.manager.read_file("test.txt")
        self.assertTrue(r_res["success"])
        self.assertEqual(r_res["status"], "SUCCESS")
        self.assertEqual(r_res["content"], "Hello SNOW!")
        self.assertEqual(r_res["size_bytes"], 11)

    async def test_write_no_implicit_overwrite(self) -> None:
        # Write initially
        await self.manager.write_file("existing.txt", "Original")

        # Attempt write without overwrite=True
        fail_res = await self.manager.write_file("existing.txt", "New content", overwrite=False)
        self.assertFalse(fail_res["success"])
        self.assertEqual(fail_res["status"], "FILE_ALREADY_EXISTS")

        # Verify content unmodified
        r_res = await self.manager.read_file("existing.txt")
        self.assertEqual(r_res["content"], "Original")

        # Explicit overwrite succeeds
        ok_res = await self.manager.write_file("existing.txt", "New content", overwrite=True)
        self.assertTrue(ok_res["success"])
        r_res2 = await self.manager.read_file("existing.txt")
        self.assertEqual(r_res2["content"], "New content")

    async def test_file_size_limits(self) -> None:
        # Exceeds max write
        large_content = "X" * (DEFAULT_MAX_FILE_BYTES + 1)
        w_res = await self.manager.write_file("large.txt", large_content)
        self.assertFalse(w_res["success"])
        self.assertEqual(w_res["status"], "FILE_TOO_LARGE")

        # Exceeds max read limit
        await self.manager.write_file("small.txt", "1234567890")
        r_res = await self.manager.read_file("small.txt", max_bytes=5)
        self.assertFalse(r_res["success"])
        self.assertEqual(r_res["status"], "FILE_TOO_LARGE")

    async def test_list_files(self) -> None:
        await self.manager.write_file("file1.txt", "1")
        await self.manager.write_file("file2.txt", "2")
        (self.root / "subfolder").mkdir()

        res = await self.manager.list_files()
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "SUCCESS")
        names = {item["name"] for item in res["items"]}
        self.assertIn("file1.txt", names)
        self.assertIn("file2.txt", names)
        self.assertIn("subfolder", names)

    async def test_path_traversal_rejection(self) -> None:
        traversal_attempts = [
            "../secret.txt",
            "../../windows/system32/cmd.exe",
            "subfolder/../../secret.txt",
            "..\\..\\boot.ini",
        ]
        for path in traversal_attempts:
            w_res = await self.manager.write_file(path, "attack")
            self.assertFalse(w_res["success"], f"Path traversal {path} was not rejected!")
            self.assertEqual(w_res["status"], "PATH_NOT_ALLOWED")

            r_res = await self.manager.read_file(path)
            self.assertFalse(r_res["success"], f"Path traversal {path} was not rejected!")
            self.assertEqual(r_res["status"], "PATH_NOT_ALLOWED")

    async def test_forbidden_sensitive_files(self) -> None:
        forbidden = [
            "ipc.secret",
            "server.key",
            "server.crt",
            "snow_devices.db",
            "device.key",
            "cert.pem",
            "tls/cert.pem",
        ]
        for name in forbidden:
            w_res = await self.manager.write_file(name, "secret_data")
            self.assertFalse(w_res["success"], f"Forbidden file {name} was not rejected!")
            self.assertEqual(w_res["status"], "PATH_NOT_ALLOWED")

    async def test_unc_and_device_paths_rejected(self) -> None:
        dangerous_paths = [
            r"\\localhost\c$\windows",
            r"\\192.168.1.1\share",
            r"CON",
            r"PRN",
            r"file.txt:$DATA",
        ]
        for p in dangerous_paths:
            w_res = await self.manager.write_file(p, "data")
            self.assertFalse(w_res["success"], f"Dangerous path {p} was not rejected!")
            self.assertEqual(w_res["status"], "PATH_NOT_ALLOWED")

    async def test_binary_file_encoding_rejection(self) -> None:
        bin_file = self.root / "binary.bin"
        bin_file.write_bytes(b"\x80\x81\xff\xfe\x00\x01")

        r_res = await self.manager.read_file("binary.bin")
        self.assertFalse(r_res["success"])
        self.assertEqual(r_res["status"], "INVALID_ENCODING")


class TestWindowsAppLauncher(unittest.IsolatedAsyncioTestCase):
    """Test allowlisted application launcher capability module."""

    def setUp(self) -> None:
        self.launcher = WindowsAppLauncher()

    def test_allowed_apps_catalog(self) -> None:
        expected = ["calc", "explorer", "mspaint", "notepad", "taskmgr"]
        self.assertEqual(self.launcher.allowed_apps, expected)

    async def test_disallowed_apps_rejected(self) -> None:
        disallowed = [
            "cmd",
            "cmd.exe",
            "powershell",
            "powershell.exe",
            "bash",
            "calc.exe; rm -rf /",
            "notepad.exe && dir",
            "C:\\Windows\\System32\\cmd.exe",
            "unknown_game",
        ]
        for app in disallowed:
            res = await self.launcher.launch_app(app)
            self.assertFalse(res["success"], f"Disallowed app '{app}' was not rejected!")
            self.assertEqual(res["status"], "APP_NOT_ALLOWED")

    async def test_invalid_app_argument(self) -> None:
        res = await self.launcher.launch_app("")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "INVALID_ARGUMENT")

    async def test_missing_executable_handling(self) -> None:
        # Create launcher with mock allowlist pointing to non-existent executable
        dummy_allowlist = {
            "dummy_app": [Path(r"C:\Windows\System32\non_existent_dummy_app_xyz.exe")]
        }
        launcher = WindowsAppLauncher(custom_allowlist=dummy_allowlist)
        res = await launcher.launch_app("dummy_app")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "APP_NOT_FOUND")

    async def test_launch_app_mock_popen(self) -> None:
        mock_proc = MagicMock(pid=12345)
        with patch("subprocess.Popen", return_value=mock_proc) as mock_popen, \
             patch.object(Path, "exists", return_value=True), \
             patch.object(Path, "is_file", return_value=True):
            res = await self.launcher.launch_app("notepad")
            self.assertTrue(res["success"])
            self.assertEqual(res["status"], "SUCCESS")
            self.assertEqual(res["pid"], 12345)
            self.assertEqual(res["app_name"], "notepad")

            # Verify subprocess.Popen invariants: shell=False, DEVNULL streams
            mock_popen.assert_called_once()
            call_args, call_kwargs = mock_popen.call_args
            self.assertFalse(call_kwargs.get("shell"), "shell must be False!")
            self.assertEqual(call_kwargs.get("stdin"), subprocess.DEVNULL)
            self.assertEqual(call_kwargs.get("stdout"), subprocess.DEVNULL)
            self.assertEqual(call_kwargs.get("stderr"), subprocess.DEVNULL)


class TestPhase5EndToEndIntegration(unittest.IsolatedAsyncioTestCase):
    """End-to-end integration tests: FastMCP Tool -> SnowMcpBridge -> Core IPC Server -> Capabilities."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_e2e_")
        self.secret_path = Path(self.temp_dir) / "ipc.secret"
        self.transfer_dir = Path(self.temp_dir) / "transfers"
        self.transfer_dir.mkdir(parents=True, exist_ok=True)

        self.config = CoreConfig(
            ipc_host="127.0.0.1",
            ipc_port=0,
            ipc_secret_path=str(self.secret_path),
            transfer_root=str(self.transfer_dir),
        )

        # Mock CoreServer with capability managers
        self.mock_core = MagicMock()
        self.mock_core.config = self.config
        self.mock_core.windows_telemetry = WindowsTelemetry()
        self.mock_core.windows_processes = WindowsProcessMonitor()
        self.mock_core.windows_files = WindowsFileManager(allowed_roots=[self.transfer_dir])
        self.mock_core.windows_apps = WindowsAppLauncher()

        # Start real loopback IPC server
        self.ipc_server = SnowIpcServer(core_server=self.mock_core, config=self.config)
        await self.ipc_server.start()
        self.bound_port = self.ipc_server.bound_port
        self.assertIsNotNone(self.bound_port)

        # Create bridge connected to bound port
        self.bridge = SnowMcpBridge(
            host="127.0.0.1",
            port=self.bound_port,
            secret=self.ipc_server.secret,
        )

        # Create FastMCP server with registered tools
        self.mcp_server = create_snow_mcp_server(bridge=self.bridge)

    async def asyncTearDown(self) -> None:
        await self.ipc_server.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _extract_tool_result(self, raw_call_result: Any) -> dict:
        """Helper to extract JSON payload from FastMCP call_tool return value."""
        if isinstance(raw_call_result, tuple):
            text_items = raw_call_result[0]
            if text_items and hasattr(text_items[0], "text"):
                return json.loads(text_items[0].text)
        elif hasattr(raw_call_result, "content") and raw_call_result.content:
            return json.loads(raw_call_result.content[0].text)
        raise ValueError(f"Unable to parse FastMCP result: {raw_call_result!r}")

    async def test_all_16_tools_registered(self) -> None:
        tools = await self.mcp_server.list_tools()
        tool_names = {t.name for t in tools}
        expected_phase_5_tools = {
            "snow_windows_battery",
            "snow_windows_system_info",
            "snow_windows_processes",
            "snow_windows_launch_app",
            "snow_windows_file_read",
            "snow_windows_file_write",
            "snow_windows_file_list",
        }
        for name in expected_phase_5_tools:
            self.assertIn(name, tool_names)
        self.assertEqual(len(tool_names), 16)

    async def test_mcp_windows_system_info(self) -> None:
        res_raw = await self.mcp_server.call_tool("snow_windows_system_info", {})
        data = self._extract_tool_result(res_raw)
        self.assertIn("hostname", data)
        self.assertIn("cpu", data)
        self.assertIn("memory", data)
        self.assertIn("disk", data)

    async def test_mcp_windows_battery(self) -> None:
        res_raw = await self.mcp_server.call_tool("snow_windows_battery", {})
        data = self._extract_tool_result(res_raw)
        self.assertIn("status", data)
        self.assertIn("message", data)

    async def test_mcp_windows_processes(self) -> None:
        res_raw = await self.mcp_server.call_tool(
            "snow_windows_processes", {"limit": 5, "sort_by": "memory"}
        )
        data = self._extract_tool_result(res_raw)
        self.assertTrue(data.get("success", False))
        self.assertLessEqual(data["count"], 5)
        self.assertEqual(data["sort_by"], "memory")

    async def test_mcp_windows_file_operations_roundtrip(self) -> None:
        # Write
        w_raw = await self.mcp_server.call_tool(
            "snow_windows_file_write",
            {"file_path": "mcp_test.txt", "content": "From MCP!"},
        )
        w_data = self._extract_tool_result(w_raw)
        self.assertTrue(w_data.get("success", False))
        self.assertEqual(w_data["name"], "mcp_test.txt")

        # List
        l_raw = await self.mcp_server.call_tool("snow_windows_file_list", {})
        l_data = self._extract_tool_result(l_raw)
        self.assertTrue(l_data.get("success", False))
        names = [item["name"] for item in l_data["items"]]
        self.assertIn("mcp_test.txt", names)

        # Read
        r_raw = await self.mcp_server.call_tool(
            "snow_windows_file_read", {"file_path": "mcp_test.txt"}
        )
        r_data = self._extract_tool_result(r_raw)
        self.assertTrue(r_data.get("success", False))
        self.assertEqual(r_data["content"], "From MCP!")

    async def test_mcp_windows_file_security_rejection(self) -> None:
        # Traversal attempt through MCP
        res_raw = await self.mcp_server.call_tool(
            "snow_windows_file_read", {"file_path": "../../../boot.ini"}
        )
        data = self._extract_tool_result(res_raw)
        self.assertFalse(data.get("success", False))
        self.assertEqual(data["status"], "PATH_NOT_ALLOWED")

    async def test_mcp_windows_launch_app_security(self) -> None:
        # Disallowed command through MCP
        res_raw = await self.mcp_server.call_tool(
            "snow_windows_launch_app", {"app_name": "cmd.exe"}
        )
        data = self._extract_tool_result(res_raw)
        self.assertFalse(data.get("success", False))
        self.assertEqual(data["status"], "APP_NOT_ALLOWED")

    async def test_mcp_offline_core_handling(self) -> None:
        # Bridge pointing to offline port
        offline_bridge = SnowMcpBridge(
            host="127.0.0.1",
            port=59999,
            secret="some_secret",
        )
        offline_server = create_snow_mcp_server(bridge=offline_bridge)
        res_raw = await offline_server.call_tool("snow_windows_system_info", {})
        data = self._extract_tool_result(res_raw)
        self.assertFalse(data.get("success", False))
        self.assertEqual(data["status"], "CORE_OFFLINE")


if __name__ == "__main__":
    unittest.main()
