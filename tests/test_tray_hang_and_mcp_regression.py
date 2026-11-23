"""Regression test suite for SNOW Phase 2, Stage 2A — Track A: Windows Runtime, Tray & Local MCP.

Verifies:
- Tray startup without silent hang or deadlocks.
- Context menu command dispatch.
- Clean shutdown on exit command.
- MCP stdio protocol compliance: 38 registered tools, tool execution, zero stdout pollution.
"""

from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.tray.app import (
    SnowTrayApp,
    CMD_OPEN_DASHBOARD,
    CMD_PAIR_DEVICE,
    CMD_START_CORE,
    CMD_STOP_CORE,
    CMD_TOGGLE_AUTOSTART,
    CMD_EXIT,
)
from snow.mcp.server import create_snow_mcp_server


class TestTrayLifecycleAndDispatch(unittest.TestCase):
    """Test Win32 Tray companion lifecycle and command dispatch."""

    def test_tray_headless_execution(self) -> None:
        """Verify tray runs cleanly in headless mode without blocking."""
        app = SnowTrayApp(headless=True, auto_start_core=False)
        rc = app.run()
        self.assertEqual(rc, 0)
        self.assertTrue(app._is_running)
        app.stop()
        self.assertFalse(app._is_running)

    def test_tray_command_dispatch_exit(self) -> None:
        """Verify CMD_EXIT cleanly signals stop."""
        app = SnowTrayApp(headless=True, auto_start_core=False)
        app.run()
        self.assertTrue(app._is_running)
        app.dispatch_command(CMD_EXIT)
        self.assertFalse(app._is_running)

    def test_tray_command_dispatch_dashboard(self) -> None:
        """Verify CMD_OPEN_DASHBOARD triggers dashboard ensure worker."""
        app = SnowTrayApp(headless=True, auto_start_core=False)
        with patch.object(app, "ensure_dashboard_running_and_open") as mock_dash:
            app.dispatch_command(CMD_OPEN_DASHBOARD)
            mock_dash.assert_called_once()

    def test_tray_command_dispatch_pair(self) -> None:
        """Verify CMD_PAIR_DEVICE triggers dashboard with pairing action."""
        app = SnowTrayApp(headless=True, auto_start_core=False)
        with patch.object(app, "ensure_dashboard_running_and_open") as mock_dash:
            app.dispatch_command(CMD_PAIR_DEVICE)
            mock_dash.assert_called_once_with("/?action=pair")


class TestLocalMcpStdioProtocol(unittest.TestCase):
    """Verify local FastMCP stdio server protocol correctness."""

    def test_all_38_tools_registered(self) -> None:
        """Verify create_snow_mcp_server registers exactly 38 static tools."""
        server = create_snow_mcp_server()
        tools = asyncio.run(server.list_tools())
        self.assertEqual(len(tools), 38)
        tool_names = {t.name for t in tools}
        self.assertIn("snow_get_device_status", tool_names)
        self.assertIn("snow_windows_system_info", tool_names)
        self.assertIn("snow_android_screenshot", tool_names)
        self.assertIn("snow_android_battery", tool_names)

    def test_mcp_stdio_subprocess_e2e(self) -> None:
        """Verify real MCP stdio subprocess initialize, list_tools, call_tool, and stderr isolation."""
        proc = subprocess.Popen(
            [sys.executable, "-m", "snow.mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # 1. Initialize
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test_client", "version": "1.0"},
                },
            }
            proc.stdin.write(json.dumps(init_req) + "\n")
            proc.stdin.flush()
            init_line = proc.stdout.readline()
            self.assertTrue(init_line.strip(), "Init response must not be empty")
            init_resp = json.loads(init_line)
            self.assertEqual(init_resp.get("id"), 1)
            self.assertIn("serverInfo", init_resp.get("result", {}))

            # 2. Initialized notification
            notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
            proc.stdin.write(json.dumps(notif) + "\n")
            proc.stdin.flush()

            # 3. List tools
            list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            proc.stdin.write(json.dumps(list_req) + "\n")
            proc.stdin.flush()
            list_line = proc.stdout.readline()
            list_resp = json.loads(list_line)
            tools = list_resp.get("result", {}).get("tools", [])
            self.assertEqual(len(tools), 38)

            # 4. Safe read-only call
            call_req = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "snow_windows_system_info",
                    "arguments": {},
                },
            }
            proc.stdin.write(json.dumps(call_req) + "\n")
            proc.stdin.flush()
            call_line = proc.stdout.readline()
            call_resp = json.loads(call_line)
            self.assertEqual(call_resp.get("id"), 3)
            self.assertFalse(call_resp.get("result", {}).get("isError", True))

        finally:
            proc.stdin.close()
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


class TestFrozenCommandResolution(unittest.TestCase):
    """Regression test suite for frozen executable command resolution."""

    def test_daemon_get_core_command_from_tray_frozen(self) -> None:
        """When running frozen as snow-tray.exe, _get_core_command must target sibling snow.exe with 'core'."""
        from pathlib import Path
        from snow.daemon import CoreDaemonManager

        mgr = CoreDaemonManager()
        fake_tray = "C:\\Program Files\\SNOW\\snow-tray.exe"
        fake_core = "C:\\Program Files\\SNOW\\snow.exe"

        def fake_is_file(path_obj: Path) -> bool:
            return str(path_obj).lower() == fake_core.lower()

        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "executable", fake_tray), \
             patch.object(Path, "is_file", fake_is_file):
            cmd = mgr._get_core_command()

        self.assertEqual(len(cmd), 2)
        self.assertEqual(cmd[0].lower(), fake_core.lower())
        self.assertEqual(cmd[1], "core")
        self.assertNotIn("snow-tray.exe", cmd[0].lower())
        self.assertNotIn("-m", cmd)

    def test_daemon_get_core_command_from_core_frozen(self) -> None:
        """When running frozen as snow.exe, _get_core_command returns [snow.exe, core]."""
        from pathlib import Path
        from snow.daemon import CoreDaemonManager

        mgr = CoreDaemonManager()
        fake_core = "C:\\Program Files\\SNOW\\snow.exe"

        def fake_is_file(path_obj: Path) -> bool:
            return str(path_obj).lower() == fake_core.lower()

        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "executable", fake_core), \
             patch.object(Path, "is_file", fake_is_file):
            cmd = mgr._get_core_command()

        self.assertEqual(len(cmd), 2)
        self.assertEqual(cmd[0].lower(), fake_core.lower())
        self.assertEqual(cmd[1], "core")

    def test_daemon_get_core_command_missing_raises(self) -> None:
        """When frozen and sibling snow.exe is missing, _get_core_command raises FileNotFoundError."""
        from pathlib import Path
        from snow.daemon import CoreDaemonManager

        mgr = CoreDaemonManager()
        fake_tray = "C:\\Program Files\\SNOW\\snow-tray.exe"

        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "executable", fake_tray), \
             patch.object(Path, "is_file", return_value=False):
            with self.assertRaises(FileNotFoundError):
                mgr._get_core_command()

    def test_tray_dashboard_worker_spawns_sibling_snow_web(self) -> None:
        """When frozen in tray, dashboard worker launches sibling snow.exe web ..."""
        from pathlib import Path
        from snow.tray.app import SnowTrayApp

        app = SnowTrayApp(headless=True, auto_start_core=False)
        fake_tray = "C:\\Program Files\\SNOW\\snow-tray.exe"
        fake_core = "C:\\Program Files\\SNOW\\snow.exe"

        def fake_is_file(path_obj: Path) -> bool:
            return str(path_obj).lower() == fake_core.lower()

        spawned_cmd = None

        def fake_popen(cmd, **kwargs):
            nonlocal spawned_cmd
            spawned_cmd = cmd
            mock_proc = MagicMock()
            return mock_proc

        with patch.object(sys, "frozen", True, create=True), \
             patch.object(sys, "executable", fake_tray), \
             patch.object(Path, "is_file", fake_is_file), \
             patch.object(app, "is_dashboard_listening", side_effect=[False, True]), \
             patch("subprocess.Popen", side_effect=fake_popen):
            app._dashboard_startup_worker()

        self.assertIsNotNone(spawned_cmd)
        self.assertEqual(spawned_cmd[0].lower(), fake_core.lower())
        self.assertEqual(spawned_cmd[1], "web")
        self.assertIn("--port", spawned_cmd)
        self.assertIn("--no-browser", spawned_cmd)


class TestCliCoreAndLegacyShims(unittest.TestCase):
    """Test 'snow core' CLI subcommand and backward-compatible invocation shims."""

    def test_parser_recognizes_core_subcommand(self) -> None:
        """Verify build_parser recognizes 'core' subcommand."""
        from snow.cli import build_parser

        parser = build_parser()
        parsed = parser.parse_args(["core"])
        self.assertEqual(parsed.command, "core")

    def test_cli_main_dispatches_core(self) -> None:
        """Verify main(['core']) dispatches to snow.main.main."""
        from snow.cli import main

        with patch("snow.main.main", return_value=0) as mock_core:
            rc = main(["core"])
            self.assertEqual(rc, 0)
            mock_core.assert_called_once()

    def test_cli_legacy_shim_dash_m_main(self) -> None:
        """Verify main(['-m', 'snow.main']) normalizes to core and dispatches cleanly."""
        from snow.cli import main

        with patch("snow.main.main", return_value=0) as mock_core:
            rc = main(["-m", "snow.main"])
            self.assertEqual(rc, 0)
            mock_core.assert_called_once()

    def test_cli_legacy_shim_dash_m_mcp(self) -> None:
        """Verify main(['-m', 'snow.mcp']) normalizes to mcp and dispatches cleanly."""
        from snow.cli import main

        with patch("snow.mcp.__main__.main", return_value=0) as mock_mcp:
            rc = main(["-m", "snow.mcp"])
            self.assertEqual(rc, 0)
            mock_mcp.assert_called_once()

    def test_cli_legacy_shim_dash_m_web(self) -> None:
        """Verify main(['-m', 'snow.web']) normalizes to web and dispatches cleanly."""
        from snow.cli import main

        with patch("snow.cli.run_web", return_value=0) as mock_web:
            rc = main(["-m", "snow.web"])
            self.assertEqual(rc, 0)
            mock_web.assert_called_once()


if __name__ == "__main__":
    unittest.main()
