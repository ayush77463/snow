"""Unit, integration, and security tests for Phase 4 MCP server and loopback IPC bridge."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp.server.fastmcp import FastMCP
from snow.core.config import CoreConfig
from snow.core.ipc import (
    DEFAULT_IPC_SECRET_FILENAME,
    IPC_PROTOCOL_VERSION,
    MAX_IPC_MESSAGE_SIZE,
    SnowIpcServer,
    enforce_file_permissions,
    get_or_create_ipc_secret,
)
from snow.core.server import SnowCoreServer
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.server import create_snow_mcp_server
from snow.mcp.tools import ALL_TOOL_NAMES, register_all_tools


class TestIpcSecurityAndServer(unittest.IsolatedAsyncioTestCase):
    """Tests for SnowIpcServer security, authentication, and framing."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_ipc_")
        self.secret_path = Path(self.temp_dir) / DEFAULT_IPC_SECRET_FILENAME

        # Mock core server
        self.mock_core = MagicMock()
        self.mock_core.is_running = True
        self.mock_core.config = CoreConfig(
            ipc_host="127.0.0.1",
            ipc_port=0,  # Ephemeral port
            ipc_secret_path=str(self.secret_path),
        )
        self.mock_core.ws_server = MagicMock()
        self.mock_core.ws_server.bound_port = 8765
        self.mock_core.http_transfer_server = MagicMock()
        self.mock_core.http_transfer_server.bound_port = 8766
        self.mock_core.connection_manager = MagicMock()
        self.mock_core.connection_manager.all_connections.return_value = []
        self.mock_core.db_manager = MagicMock()
        self.mock_core.db_manager.list_paired_devices.return_value = []
        self.mock_core.session_manager = MagicMock()
        self.mock_core.session_manager._sessions = {}

        self.server = SnowIpcServer(self.mock_core, self.mock_core.config)
        await self.server.start()
        self.port = self.server.bound_port
        self.secret = self.server.secret

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _send_raw_line(self, line: bytes) -> bytes:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        try:
            writer.write(line if line.endswith(b"\n") else line + b"\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=3.0)
            return resp
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_ipc_binds_to_loopback_only(self) -> None:
        """Verify IPC server binds to 127.0.0.1 and rejects non-loopback hosts."""
        self.assertEqual(self.mock_core.config.ipc_host, "127.0.0.1")
        self.assertTrue(self.server.is_running)
        self.assertIsNotNone(self.port)

        invalid_config = CoreConfig(ipc_host="localhost", ipc_port=0)
        # Verify post_init enforces loopback
        with self.assertRaises(ValueError):
            CoreConfig(ipc_host="0.0.0.0", ipc_port=8767)

    def test_secret_generation_and_permissions(self) -> None:
        """Verify secret file creation, user ACL permissions, and idempotency."""
        self.assertTrue(self.secret_path.is_file())
        secret1 = self.secret_path.read_text(encoding="utf-8").strip()
        self.assertTrue(len(secret1) >= 32)

        # Calling again should NOT overwrite existing secret
        secret2 = get_or_create_ipc_secret(self.secret_path)
        self.assertEqual(secret1, secret2)

        # Test permission enforcement helper
        res = enforce_file_permissions(self.secret_path)
        self.assertTrue(res)

    async def test_unauthenticated_request_rejected(self) -> None:
        """Requests without auth_token or with invalid token must be rejected."""
        req = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": "test-1",
            "op": "get_device_status",
            "payload": {},
        }
        raw_resp = await self._send_raw_line(json.dumps(req).encode("utf-8"))
        resp = json.loads(raw_resp.decode("utf-8"))
        self.assertFalse(resp["success"])
        self.assertEqual(resp["status"], "UNAUTHORIZED")

        # Wrong token
        req["auth_token"] = "wrong-secret-token"
        raw_resp = await self._send_raw_line(json.dumps(req).encode("utf-8"))
        resp = json.loads(raw_resp.decode("utf-8"))
        self.assertFalse(resp["success"])
        self.assertEqual(resp["status"], "UNAUTHORIZED")

    async def test_authenticated_ping(self) -> None:
        """Valid secret allows ping and returns success."""
        req = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": "test-ping",
            "op": "ping",
            "auth_token": self.secret,
            "payload": {},
        }
        raw_resp = await self._send_raw_line(json.dumps(req).encode("utf-8"))
        resp = json.loads(raw_resp.decode("utf-8"))
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "SUCCESS")
        self.assertEqual(resp["data"], {"status": "pong"})

    async def test_malformed_json_handling(self) -> None:
        """Malformed JSON payloads are rejected safely with INVALID_JSON."""
        raw_resp = await self._send_raw_line(b"{not-valid-json\n")
        resp = json.loads(raw_resp.decode("utf-8"))
        self.assertFalse(resp["success"])
        self.assertEqual(resp["status"], "INVALID_JSON")

    async def test_oversized_message_rejected(self) -> None:
        """Messages exceeding MAX_IPC_MESSAGE_SIZE are rejected."""
        giant_payload = b"A" * (MAX_IPC_MESSAGE_SIZE + 100)
        raw_resp = await self._send_raw_line(giant_payload)
        resp = json.loads(raw_resp.decode("utf-8"))
        self.assertFalse(resp["success"])
        self.assertEqual(resp["status"], "MESSAGE_TOO_LARGE")

    async def test_invalid_protocol_version(self) -> None:
        """Invalid protocol versions are rejected."""
        req = {
            "version": 999,
            "request_id": "v-test",
            "op": "ping",
            "auth_token": self.secret,
        }
        raw_resp = await self._send_raw_line(json.dumps(req).encode("utf-8"))
        resp = json.loads(raw_resp.decode("utf-8"))
        self.assertFalse(resp["success"])
        self.assertEqual(resp["status"], "INVALID_PROTOCOL_VERSION")

    async def test_unknown_operation_rejected(self) -> None:
        """Unknown ops return UNKNOWN_OPERATION error."""
        req = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": "op-test",
            "op": "nonexistent_op",
            "auth_token": self.secret,
        }
        raw_resp = await self._send_raw_line(json.dumps(req).encode("utf-8"))
        resp = json.loads(raw_resp.decode("utf-8"))
        self.assertFalse(resp["success"])
        self.assertEqual(resp["status"], "UNKNOWN_OPERATION")


class TestMcpBridge(unittest.IsolatedAsyncioTestCase):
    """Tests for SnowMcpBridge communicating with IPC server and handling failures."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_bridge_")
        self.secret_path = Path(self.temp_dir) / DEFAULT_IPC_SECRET_FILENAME

        self.mock_core = MagicMock()
        self.mock_core.is_running = True
        self.mock_core.config = CoreConfig(
            ipc_host="127.0.0.1",
            ipc_port=0,
            ipc_secret_path=str(self.secret_path),
        )
        self.mock_core.ws_server = MagicMock()
        self.mock_core.ws_server.bound_port = 8765
        self.mock_core.http_transfer_server = MagicMock()
        self.mock_core.http_transfer_server.bound_port = 8766
        self.mock_core.connection_manager = MagicMock()
        self.mock_core.connection_manager.all_connections.return_value = []
        self.mock_core.db_manager = MagicMock()
        self.mock_core.db_manager.list_paired_devices.return_value = []
        self.mock_core.session_manager = MagicMock()
        self.mock_core.session_manager._sessions = {}

        self.server = SnowIpcServer(self.mock_core, self.mock_core.config)
        await self.server.start()

        self.bridge = SnowMcpBridge(
            host="127.0.0.1",
            port=self.server.bound_port,
            secret=self.server.secret,
            secret_path=self.secret_path,
        )

    async def asyncTearDown(self) -> None:
        await self.server.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_bridge_ping_success(self) -> None:
        """Bridge ping to running core succeeds."""
        resp = await self.bridge.ping()
        self.assertTrue(resp.get("success"))
        self.assertEqual(resp.get("status"), "SUCCESS")

    async def test_bridge_get_device_status(self) -> None:
        """Bridge get_device_status returns core status snapshot."""
        resp = await self.bridge.get_device_status()
        self.assertTrue(resp.get("success"))
        data = resp.get("data", {})
        self.assertTrue(data.get("core_running"))
        self.assertEqual(data.get("ws_port"), 8765)
        self.assertEqual(data.get("transfer_port"), 8766)

    async def test_bridge_offline_core_returns_core_offline(self) -> None:
        """When core is stopped, bridge call returns CORE_OFFLINE without crashing."""
        await self.server.stop()
        resp = await self.bridge.get_device_status()
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp.get("status"), "CORE_OFFLINE")
        self.assertIn("offline or unreachable", resp.get("error", ""))

    async def test_bridge_device_request_routing(self) -> None:
        """Device request checks pairing and active session."""
        # Unpaired device
        self.mock_core.db_manager.get_paired_device.return_value = None
        resp = await self.bridge.send_device_request("dev-1", "ping")
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp.get("status"), "DEVICE_NOT_PAIRED")

        # Paired but offline device
        self.mock_core.db_manager.get_paired_device.return_value = MagicMock(device_id="dev-1")
        self.mock_core.session_manager.get_session_by_device.return_value = None
        resp = await self.bridge.send_device_request("dev-1", "ping")
        self.assertFalse(resp.get("success"))
        self.assertEqual(resp.get("status"), "DEVICE_OFFLINE")


class TestMcpToolsRegistry(unittest.IsolatedAsyncioTestCase):
    """Tests for all 16 static MCP tools."""

    async def asyncSetUp(self) -> None:
        self.mock_bridge = AsyncMock()
        self.server = FastMCP(name="SNOW-Test")
        register_all_tools(self.server, self.mock_bridge)

    async def test_all_16_tools_registered_and_unique(self) -> None:
        """Verify exactly 16 unique tools are registered with valid schemas."""
        tools = await self.server.list_tools()
        self.assertEqual(len(tools), 16)
        tool_names = [t.name for t in tools]
        self.assertEqual(len(set(tool_names)), 16)
        self.assertEqual(sorted(tool_names), sorted(ALL_TOOL_NAMES))

        # Check that descriptions are populated for every tool
        for t in tools:
            self.assertTrue(bool(t.description), f"Tool {t.name} has empty description")
            self.assertIsNotNone(t.inputSchema)

    def _extract_text(self, res_obj: Any) -> str:
        if isinstance(res_obj, tuple):
            content_list = res_obj[0]
            if content_list and hasattr(content_list[0], "text"):
                return content_list[0].text
        elif isinstance(res_obj, list):
            if res_obj and hasattr(res_obj[0], "text"):
                return res_obj[0].text
        return str(res_obj)

    async def test_snow_get_device_status_online(self) -> None:
        """snow_get_device_status returns formatted status when core is online."""
        self.mock_bridge.get_device_status.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "core_running": True,
                "app_name": "SNOW Desktop Core",
                "version": "0.1.0",
                "ws_port": 8765,
                "transfer_port": 8766,
                "ipc_port": 8767,
                "active_connections_count": 1,
                "paired_devices_count": 1,
                "active_sessions_count": 1,
                "devices": [{"device_id": "test-dev", "is_connected": True}],
            },
        }
        res_obj = await self.server.call_tool("snow_get_device_status", {})
        text = self._extract_text(res_obj)
        res = json.loads(text)
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "ONLINE")
        self.assertEqual(res["core"]["ports"]["wss"], 8765)

    async def test_snow_get_device_status_core_offline(self) -> None:
        """snow_get_device_status returns CORE_OFFLINE when core is not reachable."""
        self.mock_bridge.get_device_status.return_value = {
            "success": False,
            "status": "CORE_OFFLINE",
            "error": "Core unreachable",
        }
        res_obj = await self.server.call_tool("snow_get_device_status", {})
        text = self._extract_text(res_obj)
        res = json.loads(text)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "CORE_OFFLINE")
        self.assertIn("hint", res)

    async def test_windows_tools_route_to_bridge(self) -> None:
        """Windows tools in Phase 5 route to bridge methods and format output."""
        self.mock_bridge.windows_battery.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"available": True, "percent": 90.0, "status": "FULL"},
        }
        res_obj = await self.server.call_tool("snow_windows_battery", {})
        text = self._extract_text(res_obj)
        res = json.loads(text)
        self.assertTrue(res.get("available"))
        self.assertEqual(res.get("percent"), 90.0)

        self.mock_bridge.windows_system_info.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"hostname": "TEST-PC", "os_name": "Windows"},
        }
        res_obj = await self.server.call_tool("snow_windows_system_info", {})
        text = self._extract_text(res_obj)
        res = json.loads(text)
        self.assertEqual(res.get("hostname"), "TEST-PC")

        self.mock_bridge.windows_processes.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"count": 1, "processes": [{"pid": 100, "name": "test.exe"}]},
        }
        res_obj = await self.server.call_tool("snow_windows_processes", {"limit": 10})
        text = self._extract_text(res_obj)
        res = json.loads(text)
        self.assertEqual(res.get("count"), 1)

        self.mock_bridge.windows_launch_app.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"app_name": "notepad", "pid": 1234},
        }
        res_obj = await self.server.call_tool("snow_windows_launch_app", {"app_name": "notepad"})
        text = self._extract_text(res_obj)
        res = json.loads(text)
        self.assertEqual(res.get("app_name"), "notepad")

        self.mock_bridge.windows_file_read.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"content": "hello", "size_bytes": 5},
        }
        res_obj = await self.server.call_tool("snow_windows_file_read", {"file_path": "test.txt"})
        text = self._extract_text(res_obj)
        res = json.loads(text)
        self.assertEqual(res.get("content"), "hello")

        self.mock_bridge.windows_file_write.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"name": "test.txt", "bytes_written": 5},
        }
        res_obj = await self.server.call_tool("snow_windows_file_write", {"file_path": "test.txt", "content": "hello"})
        text = self._extract_text(res_obj)
        res = json.loads(text)
        self.assertEqual(res.get("name"), "test.txt")

        self.mock_bridge.windows_file_list.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"count": 0, "items": []},
        }
        res_obj = await self.server.call_tool("snow_windows_file_list", {"directory_path": ""})
        text = self._extract_text(res_obj)
        res = json.loads(text)
        self.assertEqual(res.get("count"), 0)

    async def test_deferred_android_tools_return_not_implemented(self) -> None:
        """Android tools must return NOT_IMPLEMENTED_YET (Phase 6)."""
        android_tools = [
            ("snow_android_battery", {}),
            ("snow_android_ring", {"duration_seconds": 5}),
            ("snow_android_clipboard_push", {"text": "hello"}),
            ("snow_android_launch_app", {"package_name": "org.snow"}),
            ("snow_android_list_apps", {}),
            ("snow_android_file_send", {"source_path": "doc.pdf"}),
            ("snow_android_file_receive", {"remote_file_name": "pic.jpg"}),
        ]
        for name, args in android_tools:
            res_obj = await self.server.call_tool(name, args)
            text = self._extract_text(res_obj)
            res = json.loads(text)
            self.assertFalse(res["success"], f"Tool {name} should report success=False")
            self.assertEqual(res["status"], "NOT_IMPLEMENTED_YET", f"Tool {name} should return NOT_IMPLEMENTED_YET")
            self.assertIn("Phase 6", res["planned_phase"])


class TestMcpSubprocessStdoutIsolation(unittest.TestCase):
    """Subprocess-level tests verifying strict stdout isolation and MCP stdio protocol compliance."""

    def test_mcp_subprocess_stdout_isolation_and_initialization(self) -> None:
        """Launch python -m snow.mcp, verify zero non-protocol bytes on stdout, and valid JSON-RPC frames."""
        python_exe = sys.executable
        proc = subprocess.Popen(
            [python_exe, "-m", "snow.mcp"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # 1. Send JSON-RPC initialize request
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "test-ai-host", "version": "1.0.0"},
                },
            }
            proc.stdin.write(json.dumps(init_req) + "\n")
            proc.stdin.flush()

            init_line = proc.stdout.readline()
            self.assertTrue(init_line, "Expected JSON-RPC response from stdout, got EOF")

            # Verify response is valid JSON-RPC without stray log text
            init_resp = json.loads(init_line.strip())
            self.assertEqual(init_resp.get("jsonrpc"), "2.0")
            self.assertEqual(init_resp.get("id"), 1)
            self.assertIn("result", init_resp)
            self.assertEqual(init_resp["result"]["serverInfo"]["name"], "SNOW")

            # 2. Send initialized notification
            proc.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
            proc.stdin.flush()

            # 3. Request tools/list
            tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            proc.stdin.write(json.dumps(tools_req) + "\n")
            proc.stdin.flush()

            tools_line = proc.stdout.readline()
            tools_resp = json.loads(tools_line.strip())
            self.assertEqual(tools_resp.get("id"), 2)
            tools_list = tools_resp.get("result", {}).get("tools", [])
            self.assertEqual(len(tools_list), 16)

            # 4. Invoke snow_get_device_status when core is not running
            call_req = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "snow_get_device_status", "arguments": {}},
            }
            proc.stdin.write(json.dumps(call_req) + "\n")
            proc.stdin.flush()

            call_line = proc.stdout.readline()
            call_resp = json.loads(call_line.strip())
            self.assertEqual(call_resp.get("id"), 3)
            content_text = call_resp["result"]["content"][0]["text"]
            self.assertIn("CORE_OFFLINE", content_text)

        finally:
            if proc.stdin and not proc.stdin.closed:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            stderr_output = ""
            if proc.stderr and not proc.stderr.closed:
                stderr_output = proc.stderr.read()
                proc.stderr.close()
            if proc.stdout and not proc.stdout.closed:
                proc.stdout.close()

        # Verify stderr captured logs and stdout had no stray print lines
        self.assertIn("Initializing SNOW MCP stdio server...", stderr_output)


if __name__ == "__main__":
    unittest.main()
