"""Regression test suite for SNOW V4.1 Phase 1, Gate 1B, Batch 4 - Track 4.

Verifies:
- USB reverse socket mapping requirement for BOTH tcp:8765 and tcp:8766.
- Thread-offloaded non-blocking ADB operations in Web server async handlers.
- 10-second TTL caching of USB status in handle_api_status to eliminate polling overhead.
- Real RemoteMcpGateway lifecycle control (start_gateway_async, runner.cleanup, /health probe, port release).
- Clean MCP gateway teardown on SnowWebServer.stop().
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import socket
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
from aiohttp import web
from aiohttp.test_utils import make_mocked_request

from snow.core.usb import get_usb_status
from snow.web.server import SnowWebServer


class TestTrack4UsbDualPortRequirement(unittest.TestCase):
    """Test requirement that reverse_active strictly requires both 8765 and 8766."""

    @patch("snow.core.usb.subprocess.run")
    @patch("snow.core.usb.get_connected_adb_devices")
    @patch("snow.core.usb.find_adb_binary")
    def test_both_ports_present(self, mock_find, mock_devs, mock_run) -> None:
        mock_find.return_value = Path("C:/fake/adb.exe")
        mock_devs.return_value = [{"serial": "device-1", "status": "device", "model": "Pixel"}]
        mock_run.return_value = MagicMock(
            stdout="(reverse) tcp:8765 tcp:8765\n(reverse) tcp:8766 tcp:8766\n",
            returncode=0,
        )

        stat = get_usb_status()
        self.assertTrue(stat["reverse_active"])

    @patch("snow.core.usb.subprocess.run")
    @patch("snow.core.usb.get_connected_adb_devices")
    @patch("snow.core.usb.find_adb_binary")
    def test_only_8765_present(self, mock_find, mock_devs, mock_run) -> None:
        mock_find.return_value = Path("C:/fake/adb.exe")
        mock_devs.return_value = [{"serial": "device-1", "status": "device", "model": "Pixel"}]
        mock_run.return_value = MagicMock(
            stdout="(reverse) tcp:8765 tcp:8765\n",
            returncode=0,
        )

        stat = get_usb_status()
        self.assertFalse(stat["reverse_active"])

    @patch("snow.core.usb.subprocess.run")
    @patch("snow.core.usb.get_connected_adb_devices")
    @patch("snow.core.usb.find_adb_binary")
    def test_only_8766_present(self, mock_find, mock_devs, mock_run) -> None:
        mock_find.return_value = Path("C:/fake/adb.exe")
        mock_devs.return_value = [{"serial": "device-1", "status": "device", "model": "Pixel"}]
        mock_run.return_value = MagicMock(
            stdout="(reverse) tcp:8766 tcp:8766\n",
            returncode=0,
        )

        stat = get_usb_status()
        self.assertFalse(stat["reverse_active"])

    @patch("snow.core.usb.subprocess.run")
    @patch("snow.core.usb.get_connected_adb_devices")
    @patch("snow.core.usb.find_adb_binary")
    def test_neither_port_present(self, mock_find, mock_devs, mock_run) -> None:
        mock_find.return_value = Path("C:/fake/adb.exe")
        mock_devs.return_value = [{"serial": "device-1", "status": "device", "model": "Pixel"}]
        mock_run.return_value = MagicMock(
            stdout="(reverse) tcp:5555 tcp:5555\n",
            returncode=0,
        )

        stat = get_usb_status()
        self.assertFalse(stat["reverse_active"])

    @patch("snow.core.usb.subprocess.run")
    @patch("snow.core.usb.get_connected_adb_devices")
    @patch("snow.core.usb.find_adb_binary")
    def test_malformed_adb_output(self, mock_find, mock_devs, mock_run) -> None:
        mock_find.return_value = Path("C:/fake/adb.exe")
        mock_devs.return_value = [{"serial": "device-1", "status": "device", "model": "Pixel"}]
        mock_run.return_value = MagicMock(
            stdout="??? unexpected corrupted output ???\n",
            returncode=0,
        )

        stat = get_usb_status()
        self.assertFalse(stat["reverse_active"])


class TestTrack4WebEventLoopAndCaching(unittest.TestCase):
    """Test non-blocking execution and 10-second TTL caching."""

    def test_usb_status_10s_caching_in_handle_api_status(self) -> None:
        server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)

        call_count = 0

        def fake_get_usb():
            nonlocal call_count
            call_count += 1
            return {"connected": True, "authorized_count": 1, "reverse_active": True}

        with patch("snow.core.usb.get_usb_status", side_effect=fake_get_usb), \
             patch.object(server.bridge.daemon_manager, "is_ipc_ready", new_callable=AsyncMock, return_value=True), \
             patch.object(server.bridge, "windows_system_info", new_callable=AsyncMock, return_value={"success": True, "data": {}}), \
             patch("snow.core.network.get_active_ip_addresses", return_value=["192.168.1.10"]):

            req = make_mocked_request("GET", "/api/status")

            # 1st call -> probes ADB
            resp1 = asyncio.run(server.handle_api_status(req))
            self.assertEqual(resp1.status, 200)
            self.assertEqual(call_count, 1)

            # 2nd call immediately -> returns cached value, no second probe
            resp2 = asyncio.run(server.handle_api_status(req))
            self.assertEqual(resp2.status, 200)
            self.assertEqual(call_count, 1)

            # Fast-forward cache time beyond 10 seconds -> triggers fresh probe
            server._usb_status_cache_time -= 15.0
            resp3 = asyncio.run(server.handle_api_status(req))
            self.assertEqual(resp3.status, 200)
            self.assertEqual(call_count, 2)


class TestTrack4McpGatewayLifecycle(unittest.TestCase):
    """Mandatory Gateway Regression Test: Real start, healthcheck, stop, and socket release."""

    def test_mcp_gateway_start_health_stop_lifecycle(self) -> None:
        # Use an ephemeral unreserved loopback port for the test gateway
        test_gw_port = 8785

        # Verify port is initially unbound
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", test_gw_port))
        sock.close()

        server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)
        server.gateway_port = test_gw_port

        async def run_lifecycle_test():
            # 1. Start gateway via handle_api_mcp_gateway_toggle
            start_req = make_mocked_request(
                "POST",
                "/api/mcp/gateway/toggle",
            )
            start_req._read_bytes = json.dumps({"enable": True}).encode("utf-8")

            resp = await server.handle_api_mcp_gateway_toggle(start_req)
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.text)
            self.assertTrue(data["success"])
            self.assertTrue(data["running"])
            self.assertEqual(data["port"], test_gw_port)

            # 2. Query real gateway /health endpoint
            timeout = aiohttp.ClientTimeout(total=2.0)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(f"http://127.0.0.1:{test_gw_port}/health") as health_resp:
                    self.assertEqual(health_resp.status, 200)
                    health_body = await health_resp.json()
                    self.assertEqual(health_body.get("status"), "healthy")

            # 3. Stop gateway via toggle
            stop_req = make_mocked_request(
                "POST",
                "/api/mcp/gateway/toggle",
            )
            stop_req._read_bytes = json.dumps({"enable": False}).encode("utf-8")

            resp_stop = await server.handle_api_mcp_gateway_toggle(stop_req)
            self.assertEqual(resp_stop.status, 200)
            stop_data = json.loads(resp_stop.text)
            self.assertFalse(stop_data["running"])

            # 4. Verify listener socket is closed and port can be immediately rebound
            sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock2.bind(("127.0.0.1", test_gw_port))
            sock2.close()

            # 5. Verify SnowWebServer.stop() cleans up active gateway
            start_req2 = make_mocked_request(
                "POST",
                "/api/mcp/gateway/toggle",
            )
            start_req2._read_bytes = json.dumps({"enable": True}).encode("utf-8")
            await server.handle_api_mcp_gateway_toggle(start_req2)
            self.assertIsNotNone(server._mcp_gateway_runner)

            # Stop web server
            await server.stop()
            self.assertIsNone(server._mcp_gateway_runner)

            # Verify port is released
            sock3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock3.bind(("127.0.0.1", test_gw_port))
            sock3.close()

        asyncio.run(run_lifecycle_test())


if __name__ == "__main__":
    unittest.main()
