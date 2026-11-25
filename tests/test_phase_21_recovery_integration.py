"""Live IPC integration and backend capability recovery test suite for SNOW Phase 21.

Covers:
1. Win32 media keys ctypes ABI verification (unsigned byte ctypes, no signed byte overflow).
2. MCP Bridge dual-path execution without _ctx and with real DatabaseManager.
3. SnowIpcServer dynamic node_registry wiring and default device resolution.
4. Action routing for Phase 21 capabilities in router.py.
5. Authoritative transport detection matrix in ws_server.py.
"""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.windows.media import WindowsMediaController, VK_VOLUME_MUTE, VK_MEDIA_PLAY_PAUSE
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer, DEFAULT_IPC_SECRET_FILENAME
from snow.mcp.bridge import SnowMcpBridge
from snow.network.node import DeviceNode
from snow.network.registry import NodeRegistry
from snow.network.router import ACTION_ROUTING, SessionRouter
from snow.network.ws_server import SnowWebSocketServer
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager


class TestWin32MediaKeysCtypesAbi(unittest.TestCase):
    """Verify ctypes signature and virtual key range safety for WindowsMediaController."""

    def test_ctypes_user32_keybd_event_argtypes_and_values(self) -> None:
        """VK codes 0xAD-0xB3 (173-179) must pass safely through ctypes unsigned byte without overflow."""
        controller = WindowsMediaController()
        if not controller.is_windows:
            self.skipTest("Windows-only ctypes ABI test.")

        # Test that volume mute (0xAD = 173) and play/pause (0xB3 = 179) fit in c_ubyte
        val_mute = ctypes.c_ubyte(VK_VOLUME_MUTE).value
        self.assertEqual(val_mute, 173)

        val_play = ctypes.c_ubyte(VK_MEDIA_PLAY_PAUSE).value
        self.assertEqual(val_play, 179)

        # Execute dispatch on controller (mocked user32 to avoid playing live media during test)
        with patch.object(ctypes.windll.user32, "keybd_event") as mock_keybd:
            res = controller.handle_action("mute")
            self.assertTrue(res.get("success"))
            self.assertEqual(mock_keybd.call_count, 2)  # Down and Up


class TestMcpBridgeExecutionContextAndRecovery(unittest.IsolatedAsyncioTestCase):
    """Verify SnowMcpBridge recovery fixes (no _ctx, valid ExecutionContext, real DB)."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp_dir.name) / "test_audit.db"
        self.db = DatabaseManager(db_path=self.db_path)

        self.bridge = SnowMcpBridge(auto_start_core=False)
        self.bridge.capability_engine.db_manager = self.db

    async def asyncTearDown(self) -> None:
        self.tmp_dir.cleanup()

    async def test_media_control_standalone_execution(self) -> None:
        """media_control for windows executes in-process without crashing on _ctx."""
        with patch("snow.capabilities.windows.media.WindowsMediaController.handle_action", return_value={"success": True, "action": "mute"}):
            res = await self.bridge.media_control(action="mute", target="windows")
            self.assertTrue(res.get("success"))

    async def test_share_link_standalone_execution(self) -> None:
        """share_link for windows executes in-process without crashing on _ctx."""
        with patch("webbrowser.open", return_value=True):
            res = await self.bridge.share_link(url="https://example.com", target="windows")
            self.assertTrue(res.get("success"))

    async def test_activity_history_queries_real_database(self) -> None:
        """activity_history executes against real DB without crashing on _ctx."""
        self.db.log_activity(
            event_type="TEST_RECOVERY_OP",
            capability="test",
            outcome="SUCCESS",
            details={"key": "val"},
        )
        with patch.object(self.bridge.daemon_manager, "is_ipc_ready", new_callable=AsyncMock, return_value=False):
            res = await self.bridge.activity_history(limit=10)
            self.assertTrue(res.get("success"), f"Query failed: {res}")
            records = res.get("data", {}).get("events", [])
            self.assertGreaterEqual(len(records), 1)
            self.assertEqual(records[0]["event_type"], "TEST_RECOVERY_OP")

    async def test_send_request_backward_compatibility_alias(self) -> None:
        """send_request alias must delegate cleanly to send_device_request."""
        with patch.object(self.bridge, "send_device_request", new_callable=AsyncMock) as mock_sdr:
            mock_sdr.return_value = {"success": True, "dispatched": True}
            res = await self.bridge.send_request(
                device_id="dev-123",
                action="test_action",
                data={"k": "v"},
            )
            self.assertTrue(res.get("success"))
            mock_sdr.assert_awaited_once_with(
                device_id="dev-123",
                action="test_action",
                data={"k": "v"},
                timeout=30.0,
            )


class TestIpcNodeRegistryWiringAndDeviceResolution(unittest.IsolatedAsyncioTestCase):
    """Verify SnowIpcServer wires node_registry and correctly resolves default connected target."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.secret_path = Path(self.tmp_dir.name) / DEFAULT_IPC_SECRET_FILENAME
        self.db_path = Path(self.tmp_dir.name) / "test_ipc.db"
        self.db = DatabaseManager(db_path=self.db_path)

        self.mock_core = MagicMock()
        self.mock_core.is_running = True
        self.mock_core.config = CoreConfig(
            ipc_host="127.0.0.1",
            ipc_port=0,
            ipc_secret_path=str(self.secret_path),
        )
        self.mock_core.db_manager = self.db
        self.mock_core.session_manager = MagicMock()
        self.mock_core.session_manager._sessions = {}
        self.mock_core.ws_server = MagicMock()
        self.mock_core.ws_server.bound_port = 8765
        mock_resp = MagicMock()
        mock_resp.type = "response"
        mock_resp.payload = {"status": "ok"}
        mock_resp.error = None
        self.mock_core.ws_server.send_request = AsyncMock(return_value=mock_resp)
        self.mock_core.http_transfer_server = MagicMock()
        self.mock_core.http_transfer_server.bound_port = 8766
        self.mock_core.connection_manager = MagicMock()
        self.mock_core.connection_manager.all_connections.return_value = []

        # Real NodeRegistry wired on mock core
        self.node_registry = NodeRegistry(self.db)
        self.mock_core.node_registry = self.node_registry

        self.ipc_server = SnowIpcServer(self.mock_core, self.mock_core.config)
        await self.ipc_server.start()
        self.port = self.ipc_server.bound_port
        self.secret = self.ipc_server.secret

    async def asyncTearDown(self) -> None:
        await self.ipc_server.stop()
        self.tmp_dir.cleanup()

    def test_node_registry_is_wired_on_ipc_server(self) -> None:
        """SnowIpcServer.__init__ must store self.node_registry from core_server."""
        self.assertIsNotNone(self.ipc_server.node_registry)
        self.assertIs(self.ipc_server.node_registry, self.node_registry)

    async def test_handle_device_request_resolves_default_connected_device(self) -> None:
        """When device_id is omitted, _handle_device_request resolves the single connected node."""
        self.db.insert_paired_device(
            device_id="phone-realme-001",
            device_name="Realme RMX5110",
            auth_token_hash="a" * 64,
            last_known_host="10.15.72.100",
        )
        node = DeviceNode(
            device_id="phone-realme-001",
            device_name="Realme RMX5110",
            platform="android",
            host="10.15.72.100",
            is_authenticated=True,
            is_paired=True,
            transport="wifi_lan",
        )
        self.node_registry.register_node(node)
        self.node_registry.on_session_authenticated("phone-realme-001", "conn-1", "wifi_lan")

        bridge = SnowMcpBridge(
            host="127.0.0.1",
            port=self.port,
            secret=self.secret,
            auto_start_core=False,
        )
        res = await bridge.call("device_request", payload={"action": "media_control", "data": {"action": "play_pause"}})
        self.assertTrue(res.get("success"), f"Request failed: {res}")
        self.mock_core.ws_server.send_request.assert_awaited()

    async def test_handle_device_request_reports_device_offline_when_not_connected(self) -> None:
        """When no active device is connected, returns structured status."""
        bridge = SnowMcpBridge(
            host="127.0.0.1",
            port=self.port,
            secret=self.secret,
            auto_start_core=False,
        )
        res = await bridge.call("device_request", payload={"action": "media_control", "data": {"action": "play_pause"}})
        self.assertFalse(res.get("success"))
        self.assertIn(res.get("status"), ("NO_DEVICES_PAIRED", "DEVICE_OFFLINE"))


class TestActionRoutingAndNotifications(unittest.TestCase):
    """Verify Phase 21 action routing mappings and transport detection."""

    def test_phase_21_action_mappings_exist_in_router(self) -> None:
        """ACTION_ROUTING must contain Phase 21 actions."""
        expected_mappings = {
            "file_list": "android.files.transfer",
            "notifications_list": "android.notifications.list",
            "notification_dismiss": "android.notifications.dismiss",
            "notification_reply": "android.notifications.reply",
            "media_control": "android.media.control",
            "share_link": "android.link.share",
            "android_screenshot": "android.screen.capture",
            "screen_stream_stop": "android.screen.stream",
            "android_camera_capture": "android.camera.capture",
        }
        for action, capability in expected_mappings.items():
            self.assertIn(action, ACTION_ROUTING, f"Missing mapping for action {action}")
            self.assertEqual(ACTION_ROUTING[action], capability)

    def test_authoritative_transport_determination_matrix(self) -> None:
        """ws_server._determine_transport cross-checks client host and declaration."""
        cfg = CoreConfig(transfer_root=str(tempfile.gettempdir()))
        ws_server = SnowWebSocketServer(core_server=None, config=cfg, db_manager=None)

        # Non-loopback host is always wifi_lan
        tr1 = ws_server._determine_transport("192.168.1.100", "wifi_lan")
        self.assertEqual(tr1, "wifi_lan")

        tr2 = ws_server._determine_transport("10.0.0.5", "usb_adb")
        self.assertEqual(tr2, "wifi_lan")

        # Loopback without ADB verification falls back to loopback
        with patch("snow.cli.find_adb_binary", return_value=None):
            tr3 = ws_server._determine_transport("127.0.0.1", "usb_adb")
            self.assertEqual(tr3, "loopback")

        # Loopback with verified ADB device is usb_adb
        with patch("snow.cli.find_adb_binary", return_value="adb.exe"), patch(
            "snow.cli.get_connected_adb_devices", return_value=[{"status": "device"}]
        ):
            tr4 = ws_server._determine_transport("127.0.0.1", "usb_adb")
            self.assertEqual(tr4, "usb_adb")


if __name__ == "__main__":
    unittest.main()
