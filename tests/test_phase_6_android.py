"""Comprehensive unit and integration test suite for SNOW Phase 6 Android capabilities.

Tests all seven Android MCP tools, loopback IPC routing, correlation, offline/unpaired
handling, timeout boundaries, and simulated Device Protocol v1 exchanges.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.server import create_snow_mcp_server
from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage


class TestPhase6AndroidMcpTools(unittest.IsolatedAsyncioTestCase):
    """Test MCP tool definitions, arguments, and bridge routing for Android capabilities."""

    async def asyncSetUp(self) -> None:
        self.mock_bridge = AsyncMock()
        self.server = create_snow_mcp_server(bridge=self.mock_bridge)

    def _extract_tool_result(self, raw_call_result: Any) -> dict:
        if isinstance(raw_call_result, tuple):
            text_items = raw_call_result[0]
            if text_items and hasattr(text_items[0], "text"):
                return json.loads(text_items[0].text)
        elif hasattr(raw_call_result, "content") and raw_call_result.content:
            return json.loads(raw_call_result.content[0].text)
        raise ValueError(f"Unable to parse FastMCP result: {raw_call_result!r}")

    async def test_all_android_tools_registered(self) -> None:
        tools = await self.server.list_tools()
        names = {t.name for t in tools}
        expected = {
            "snow_android_battery",
            "snow_android_ring",
            "snow_android_clipboard_push",
            "snow_android_launch_app",
            "snow_android_list_apps",
            "snow_android_file_send",
            "snow_android_file_receive",
        }
        for name in expected:
            self.assertIn(name, names)

    async def test_android_battery_tool_success(self) -> None:
        self.mock_bridge.android_battery.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "level": 88,
                "charging": True,
                "power_source": "AC",
                "health": "GOOD",
                "device_model": "RMX5110",
            },
        }
        res_raw = await self.server.call_tool("snow_android_battery", {})
        data = self._extract_tool_result(res_raw)
        self.assertEqual(data["level"], 88)
        self.assertTrue(data["charging"])
        self.assertEqual(data["device_model"], "RMX5110")

    async def test_android_ring_tool_success(self) -> None:
        self.mock_bridge.android_ring.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"duration_seconds": 5, "message": "Audible alert initiated."},
        }
        res_raw = await self.server.call_tool("snow_android_ring", {"duration_seconds": 5})
        data = self._extract_tool_result(res_raw)
        self.assertEqual(data["duration_seconds"], 5)

    async def test_android_clipboard_push_tool_success(self) -> None:
        self.mock_bridge.android_clipboard_push.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"bytes_written": 12, "message": "Copied."},
        }
        res_raw = await self.server.call_tool("snow_android_clipboard_push", {"text": "Hello phone!"})
        data = self._extract_tool_result(res_raw)
        self.assertEqual(data["bytes_written"], 12)

    async def test_android_app_listing_and_launch(self) -> None:
        self.mock_bridge.android_list_apps.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "count": 2,
                "apps": [
                    {"package_name": "org.snow", "label": "SNOW"},
                    {"package_name": "com.android.settings", "label": "Settings"},
                ],
            },
        }
        res_list = await self.server.call_tool("snow_android_list_apps", {})
        data_list = self._extract_tool_result(res_list)
        self.assertEqual(data_list["count"], 2)

        self.mock_bridge.android_launch_app.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {"package_name": "org.snow", "message": "Launched."},
        }
        res_launch = await self.server.call_tool("snow_android_launch_app", {"package_name": "org.snow"})
        data_launch = self._extract_tool_result(res_launch)
        self.assertEqual(data_launch["package_name"], "org.snow")

    async def test_android_file_tools_routing(self) -> None:
        self.mock_bridge.android_file_send.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "file_name": "test.txt",
                "bytes_downloaded": 100,
                "saved_path": "/storage/emulated/0/Download/SNOW/test.txt",
            },
        }
        res_send = await self.server.call_tool("snow_android_file_send", {"source_path": "test.txt"})
        data_send = self._extract_tool_result(res_send)
        self.assertEqual(data_send["file_name"], "test.txt")

        self.mock_bridge.android_file_receive.return_value = {
            "success": True,
            "status": "SUCCESS",
            "data": {
                "file_name": "phone_photo.jpg",
                "bytes_uploaded": 5000,
            },
        }
        res_recv = await self.server.call_tool("snow_android_file_receive", {"remote_file_name": "phone_photo.jpg"})
        data_recv = self._extract_tool_result(res_recv)
        self.assertEqual(data_recv["file_name"], "phone_photo.jpg")

    async def test_device_offline_error_handling(self) -> None:
        self.mock_bridge.android_battery.return_value = {
            "success": False,
            "status": "DEVICE_OFFLINE",
            "error": "Device 'phone-1' is not connected.",
        }
        res_raw = await self.server.call_tool("snow_android_battery", {"device_id": "phone-1"})
        data = self._extract_tool_result(res_raw)
        self.assertFalse(data.get("success", True))
        self.assertEqual(data["status"], "DEVICE_OFFLINE")


class TestPhase6IpcAndProtocolExecution(unittest.IsolatedAsyncioTestCase):
    """Integration tests verifying Core IPC request routing to simulated Android WebSocket."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_p6_")
        self.secret_path = Path(self.temp_dir) / "ipc.secret"
        self.transfer_dir = Path(self.temp_dir) / "transfers"
        self.transfer_dir.mkdir(parents=True, exist_ok=True)

        self.config = CoreConfig(
            ipc_host="127.0.0.1",
            ipc_port=0,
            ipc_secret_path=str(self.secret_path),
            transfer_root=str(self.transfer_dir),
        )

        # Mock CoreServer dependencies
        self.mock_core = MagicMock()
        self.mock_core.config = self.config

        from snow.capabilities.windows.files import WindowsFileManager
        self.mock_core.windows_files = WindowsFileManager(allowed_roots=[self.transfer_dir])

        # Mock Database & Session managers
        self.mock_device_id = "test-device-uuid-1"
        self.mock_core.db_manager.get_paired_device.return_value = MagicMock(
            device_id=self.mock_device_id,
            device_name="Test Android Phone",
        )
        self.mock_core.session_manager.get_session_by_device.return_value = MagicMock(
            session_id="session-1",
            device_id=self.mock_device_id,
            connection_id="conn-1",
        )
        self.mock_core.session_manager._sessions = {
            "session-1": self.mock_core.session_manager.get_session_by_device.return_value
        }
        self.mock_core.connection_manager.get.return_value = MagicMock(
            is_active=True,
            remote_address=("127.0.0.1", 55555),
        )

        # Start IPC server
        self.ipc_server = SnowIpcServer(core_server=self.mock_core, config=self.config)
        await self.ipc_server.start()
        self.bound_port = self.ipc_server.bound_port

        self.bridge = SnowMcpBridge(
            host="127.0.0.1",
            port=self.bound_port,
            secret=self.ipc_server.secret,
        )

    async def asyncTearDown(self) -> None:
        await self.ipc_server.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_ipc_device_request_action_mapping(self) -> None:
        # Simulate correlated response from ws_server.send_request
        mock_response = SnowMessage.create_response(
            correlation_id="req-123",
            payload={"status": "success", "level": 92, "charging": True},
        )
        self.mock_core.ws_server.send_request = AsyncMock(return_value=mock_response)

        res = await self.bridge.send_device_request(
            device_id=self.mock_device_id,
            action="battery_status",
            data={},
        )
        self.assertTrue(res.get("success", False))
        self.assertEqual(res["data"]["level"], 92)

        # Verify ws_server.send_request received exact action and connection_id
        self.mock_core.ws_server.send_request.assert_called_once_with(
            connection_id="conn-1",
            action="battery_status",
            payload={},
            timeout=30.0,
        )

    async def test_ipc_device_offline_rejection(self) -> None:
        # Simulate device disconnected
        self.mock_core.connection_manager.get.return_value = None

        res = await self.bridge.send_device_request(
            device_id=self.mock_device_id,
            action="ring_phone",
            data={"duration_seconds": 5},
        )
        self.assertFalse(res.get("success", True))
        self.assertEqual(res.get("status"), "DEVICE_OFFLINE")

    async def test_ipc_device_not_paired_rejection(self) -> None:
        self.mock_core.db_manager.get_paired_device.return_value = None

        res = await self.bridge.send_device_request(
            device_id="unknown-device",
            action="ring_phone",
            data={"duration_seconds": 5},
        )
        self.assertFalse(res.get("success", True))
        self.assertEqual(res.get("status"), "DEVICE_NOT_PAIRED")

    async def test_ipc_android_file_send_success(self) -> None:
        # Create test file in transfer root
        test_file = self.transfer_dir / "sample.pdf"
        test_file.write_bytes(b"PDF CONTENT FOR ANDROID")

        self.mock_core.storage_manager.resolve_destination_path.return_value = test_file
        self.mock_core.http_transfer_server.bound_port = 8766

        mock_record = MagicMock(transfer_id="transfer-send-1")
        self.mock_core.transfer_manager.create_transfer.return_value = mock_record

        # Simulate Android client downloading successfully
        mock_response = SnowMessage.create_response(
            correlation_id="req-send-1",
            payload={
                "status": "success",
                "transfer_id": "transfer-send-1",
                "file_name": "sample.pdf",
                "bytes_downloaded": test_file.stat().st_size,
                "saved_path": "/storage/emulated/0/Download/SNOW/sample.pdf",
            },
        )
        self.mock_core.ws_server.send_request = AsyncMock(return_value=mock_response)

        res = await self.bridge.android_file_send("sample.pdf", device_id=self.mock_device_id)
        self.assertTrue(res.get("success", False))
        self.assertEqual(res["data"]["file_name"], "sample.pdf")
        self.mock_core.transfer_manager.complete_transfer.assert_called_once_with("transfer-send-1")


if __name__ == "__main__":
    unittest.main()
