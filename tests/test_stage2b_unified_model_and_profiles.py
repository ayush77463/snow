"""Unit test suite for SNOW Phase 2, Stage 2B: Unified Device Model & Permission Profiles.

Verifies:
- DeviceNode unified model fields (permission_profile, display_name, online_state, active_transport).
- Permission profile presets: full_control, files_and_clipboard, clipboard_only.
- Backend enforcement in SessionRouter rejecting actions outside the active profile.
- NodeRegistry profile getter and setter methods.
- Web API endpoint POST /api/devices/permission-profile.
"""

from __future__ import annotations

import asyncio
import json
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.network.node import (
    DeviceNode,
    ReachabilityProfile,
    ReachabilityState,
)
from snow.network.registry import NodeRegistry
from snow.network.router import (
    PERMISSION_PROFILES,
    SessionRouter,
    is_action_allowed_by_profile,
)
from snow.web.server import SnowWebServer


class TestUnifiedDeviceModel(unittest.TestCase):
    """Test DeviceNode unified representation across platforms."""

    def test_unified_model_fields(self) -> None:
        node = DeviceNode(
            device_id="phone_abc",
            device_name="Pixel 9 Pro",
            platform="android",
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            transport="wifi_lan",
            permission_profile="files_and_clipboard",
        )

        # In-memory properties
        self.assertEqual(node.permission_profile, "files_and_clipboard")
        self.assertTrue(node.is_connected)

        # Summary dict serialization
        summary = node.to_summary_dict()
        self.assertEqual(summary["device_id"], "phone_abc")
        self.assertEqual(summary["display_name"], "Pixel 9 Pro")
        self.assertEqual(summary["online_state"], "CONNECTED_SESSION")
        self.assertEqual(summary["active_transport"], "wifi_lan")
        self.assertEqual(summary["permission_profile"], "files_and_clipboard")

        # Full dict serialization & round-trip
        d = node.to_dict()
        self.assertEqual(d["permission_profile"], "files_and_clipboard")
        self.assertEqual(d["display_name"], "Pixel 9 Pro")

        recovered = DeviceNode.from_dict(d)
        self.assertEqual(recovered.device_id, "phone_abc")
        self.assertEqual(recovered.permission_profile, "files_and_clipboard")


class TestPermissionProfiles(unittest.TestCase):
    """Test permission profile logic and category filters."""

    def test_profile_presets_exist(self) -> None:
        self.assertIn("full_control", PERMISSION_PROFILES)
        self.assertIn("files_and_clipboard", PERMISSION_PROFILES)
        self.assertIn("clipboard_only", PERMISSION_PROFILES)

    def test_clipboard_only_profile_rules(self) -> None:
        # Allowed
        self.assertTrue(is_action_allowed_by_profile("clipboard_only", "desktop_clipboard_get"))
        self.assertTrue(is_action_allowed_by_profile("clipboard_only", "android_clipboard_push"))
        self.assertTrue(is_action_allowed_by_profile("clipboard_only", "battery_status"))
        self.assertTrue(is_action_allowed_by_profile("clipboard_only", "android_battery"))

        # Denied
        self.assertFalse(is_action_allowed_by_profile("clipboard_only", "file_list"))
        self.assertFalse(is_action_allowed_by_profile("clipboard_only", "android_file_receive"))
        self.assertFalse(is_action_allowed_by_profile("clipboard_only", "desktop_exec"))
        self.assertFalse(is_action_allowed_by_profile("clipboard_only", "android_screenshot"))
        self.assertFalse(is_action_allowed_by_profile("clipboard_only", "launch_app"))

    def test_files_and_clipboard_profile_rules(self) -> None:
        # Allowed
        self.assertTrue(is_action_allowed_by_profile("files_and_clipboard", "desktop_clipboard_get"))
        self.assertTrue(is_action_allowed_by_profile("files_and_clipboard", "android_clipboard_pull"))
        self.assertTrue(is_action_allowed_by_profile("files_and_clipboard", "battery_status"))
        self.assertTrue(is_action_allowed_by_profile("files_and_clipboard", "file_list"))
        self.assertTrue(is_action_allowed_by_profile("files_and_clipboard", "desktop_file_list"))
        self.assertTrue(is_action_allowed_by_profile("files_and_clipboard", "file_receive_request"))

        # Denied
        self.assertFalse(is_action_allowed_by_profile("files_and_clipboard", "desktop_exec"))
        self.assertFalse(is_action_allowed_by_profile("files_and_clipboard", "windows_terminal"))
        self.assertFalse(is_action_allowed_by_profile("files_and_clipboard", "android_screenshot"))
        self.assertFalse(is_action_allowed_by_profile("files_and_clipboard", "windows_screenshot"))
        self.assertFalse(is_action_allowed_by_profile("files_and_clipboard", "desktop_screenshot"))
        self.assertFalse(is_action_allowed_by_profile("files_and_clipboard", "media_control"))
        self.assertFalse(is_action_allowed_by_profile("files_and_clipboard", "desktop_media_control"))
        self.assertFalse(is_action_allowed_by_profile("files_and_clipboard", "android_camera_capture"))
        self.assertFalse(is_action_allowed_by_profile("files_and_clipboard", "launch_app"))

    def test_full_control_profile_rules(self) -> None:
        self.assertTrue(is_action_allowed_by_profile("full_control", "desktop_exec"))
        self.assertTrue(is_action_allowed_by_profile("full_control", "android_screenshot"))
        self.assertTrue(is_action_allowed_by_profile("full_control", "windows_screenshot"))
        self.assertTrue(is_action_allowed_by_profile("full_control", "desktop_screenshot"))
        self.assertTrue(is_action_allowed_by_profile("full_control", "media_control"))
        self.assertTrue(is_action_allowed_by_profile("full_control", "desktop_media_control"))
        self.assertTrue(is_action_allowed_by_profile("full_control", "file_list"))
        self.assertTrue(is_action_allowed_by_profile("full_control", "launch_app"))


class TestSessionRouterProfileEnforcement(unittest.IsolatedAsyncioTestCase):
    """Test backend enforcement in SessionRouter."""

    async def test_router_blocks_unauthorized_action_under_profile(self) -> None:
        mock_registry = MagicMock(spec=NodeRegistry)
        mock_registry.db_manager = MagicMock()
        restricted_node = DeviceNode(
            device_id="phone_restricted",
            device_name="Restricted Phone",
            platform="android",
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            permission_profile="clipboard_only",
            host="127.0.0.1",
            wss_port=8765,
        )
        mock_registry.resolve_target.return_value = (restricted_node, None)

        router = SessionRouter(node_registry=mock_registry)
        # Attempting file_list under clipboard_only must be rejected before transport
        res = await router.route_request(
            action="file_list",
            target="phone_restricted",
            data={},
        )

        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "PERMISSION_DENIED")
        self.assertIn("blocked by device permission profile 'clipboard_only'", res["error"])

    async def test_node_registry_profile_get_set(self) -> None:
        registry = NodeRegistry(db_manager=MagicMock())
        registry.set_permission_profile("dev_123", "files_and_clipboard")
        self.assertEqual(registry.get_permission_profile("dev_123"), "files_and_clipboard")

        # Invalid profile defaults safely to full_control
        registry.set_permission_profile("dev_123", "invalid_custom_profile")
        self.assertEqual(registry.get_permission_profile("dev_123"), "full_control")


class TestPermissionProfileApiEndpoint(unittest.IsolatedAsyncioTestCase):
    """Test Web Dashboard API endpoint for permission profiles."""

    async def test_api_devices_permission_profile(self) -> None:
        from aiohttp import web
        server = SnowWebServer(host="127.0.0.1", port=18765, auto_open_browser=False)
        server.bridge = MagicMock()
        server.bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)
        server.db_manager = MagicMock()
        server.db_manager.get_paired_device.return_value = {"device_id": "phone_test", "device_name": "Test Phone"}

        req = MagicMock(spec=web.Request)
        req.json = AsyncMock(return_value={"device_id": "phone_test", "profile": "clipboard_only"})

        res = await server.handle_api_devices_permission_profile(req)
        data = json.loads(res.body.decode("utf-8"))

        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("permission_profile"), "clipboard_only")
        self.assertEqual(data.get("device_id"), "phone_test")


class TestIpcPermissionProfiles(unittest.IsolatedAsyncioTestCase):
    """Test IPC set_permission_profile authority check and DB persistence."""

    @patch("snow.core.ipc.get_or_create_ipc_secret", return_value="test_secret")
    async def test_set_permission_profile_owner_manual(self, _mock_secret: MagicMock) -> None:
        import hashlib
        import hmac
        from snow.core.ipc import SnowIpcServer

        mock_core = MagicMock()
        mock_core.db_manager.get_device.return_value = {"device_id": "phone_1", "device_name": "Test Phone"}
        mock_core.node_registry.set_permission_profile = MagicMock()
        ipc_server = SnowIpcServer(core_server=mock_core, config=MagicMock())

        owner_token = hmac.new(
            b"test_secret", b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256
        ).hexdigest()

        res, _ = await ipc_server._dispatch_request({
            "version": 1,
            "op": "set_permission_profile",
            "request_id": "req-1",
            "owner_token": owner_token,
            "payload": {"device_id": "phone_1", "profile": "clipboard_only"},
        }, is_connection_authenticated=True)

        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("status"), "SUCCESS")
        mock_core.db_manager.set_setting.assert_called_with("device_profile:phone_1", "clipboard_only")
        mock_core.node_registry.set_permission_profile.assert_called_with("phone_1", "clipboard_only")

    @patch("snow.core.ipc.get_or_create_ipc_secret", return_value="test_secret")
    async def test_set_permission_profile_ai_mcp_rejected(self, _mock_secret: MagicMock) -> None:
        from snow.core.ipc import SnowIpcServer

        mock_core = MagicMock()
        ipc_server = SnowIpcServer(core_server=mock_core, config=MagicMock())

        # No owner_token supplied -> treated as AI_MCP principal
        res, _ = await ipc_server._dispatch_request({
            "version": 1,
            "op": "set_permission_profile",
            "request_id": "req-2",
            "payload": {"device_id": "phone_1", "profile": "full_control"},
        }, is_connection_authenticated=True)

        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "POLICY_DENIED")


if __name__ == "__main__":
    unittest.main()
