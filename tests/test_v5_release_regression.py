"""Behavioral & regression tests for SNOW V5.0.0 stabilization and capability expansion.

Covers:
1. Phase 1: Android capability manifest & SessionRouter alignment + permission profiles.
2. Phase 3 & 6: Web V5 /api/captures, /api/screen/capture-latest, /api/status normalized
   telemetry, and /api/devices local host deduplication + phone telemetry.
3. Phase 7: All MCP tools (48 total) including approval gating and dual-path IPC.
4. Structural invariants: Web Shared Clipboard preserved, Activity Timeline card removed,
   FastMCP 48 Tools badge updated.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from snow.capabilities.engine import CapabilityEngine, CapabilityRequest
from snow.capabilities.windows.system import WindowsSystemControls
from snow.core.ipc import SnowIpcServer
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.registry import CAPABILITY_REGISTRY, get_mcp_annotations, list_capabilities, validate_registry
from snow.mcp.server import create_snow_mcp_server
from snow.mcp.tools import ALL_TOOL_NAMES
from snow.network.node import ANDROID_CAPABILITIES, CAPABILITY_ALIASES, build_android_manifest
from snow.network.router import ACTION_ROUTING, is_action_allowed_by_profile
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager
from snow.security.identity import load_or_create_device_identity
from snow.web.server import SnowWebServer


class TestV5Phase1ManifestAndRouter(unittest.TestCase):
    """Verify Android manifest and SessionRouter alignment."""

    def test_android_manifest_contains_all_implemented_capabilities(self) -> None:
        manifest = build_android_manifest()
        expected = {
            "android.telemetry.get",
            "android.notifications.push",
            "android.notifications.list",
            "android.notifications.reply",
            "android.notifications.dismiss",
            "android.clipboard.set",
            "android.clipboard.get",
            "android.apps.list",
            "android.apps.launch",
            "android.messaging.send_intent",
            "android.files.transfer",
            "android.ringer.ring",
            "android.media.control",
            "android.link.share",
            "android.screen.capture",
            "android.screen.stream",
            "android.camera.capture",
        }
        self.assertTrue(expected.issubset(ANDROID_CAPABILITIES))
        self.assertTrue(expected.issubset(set(manifest.supported_capabilities)))
        self.assertEqual(CAPABILITY_ALIASES.get("android.media.projection"), "android.screen.capture")
        self.assertTrue(manifest.supports_capability("android.media.projection"))

    def test_router_mappings_and_profile_boundaries(self) -> None:
        self.assertEqual(ACTION_ROUTING["notifications_list"], "android.notifications.list")
        self.assertEqual(ACTION_ROUTING["notification_dismiss"], "android.notifications.dismiss")
        self.assertEqual(ACTION_ROUTING["notification_reply"], "android.notifications.reply")
        self.assertEqual(ACTION_ROUTING["media_control"], "android.media.control")
        self.assertEqual(ACTION_ROUTING["share_link"], "android.link.share")
        self.assertEqual(ACTION_ROUTING["android_screenshot"], "android.screen.capture")
        self.assertEqual(ACTION_ROUTING["screen_stream_stop"], "android.screen.stream")
        self.assertEqual(ACTION_ROUTING["android_camera_capture"], "android.camera.capture")

        # Profile enforcement
        for action in ("media_control", "share_link", "notifications_list", "android_screenshot", "screen_stream_stop", "android_camera_capture"):
            self.assertFalse(is_action_allowed_by_profile("clipboard_only", action))
            self.assertFalse(is_action_allowed_by_profile("files_and_clipboard", action))
            self.assertTrue(is_action_allowed_by_profile("full_control", action))


class TestV5Phase7McpFourNewTools(unittest.IsolatedAsyncioTestCase):
    """Verify exact 42-tool catalog, execution behavior, and security gates."""

    def setUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="snow_v5_mcp_"))
        self.db = DatabaseManager(self.temp_dir / "v5_test.db")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_42_tool_catalog_and_annotations_parity(self) -> None:
        is_valid, errs = validate_registry()
        self.assertTrue(is_valid, f"Registry validation failed: {errs}")
        self.assertEqual(len(CAPABILITY_REGISTRY), 54)
        self.assertEqual(len(ALL_TOOL_NAMES), 54)

        server = create_snow_mcp_server()
        tools = await server.list_tools()
        tool_names = {t.name for t in tools}
        self.assertEqual(len(tools), 54)
        for new_tool in (
            "snow_mesh_health_summary",
            "snow_windows_active_window",
            "snow_windows_notify",
            "snow_windows_lock_screen",
        ):
            self.assertIn(new_tool, tool_names)
            ann = get_mcp_annotations(new_tool)
            self.assertIsNotNone(ann)
            self.assertIs(type(ann.readOnlyHint), bool)
            self.assertIs(type(ann.destructiveHint), bool)

        lock_ann = get_mcp_annotations("snow_windows_lock_screen")
        self.assertFalse(lock_ann.readOnlyHint)
        self.assertTrue(lock_ann.destructiveHint)

    async def test_windows_system_controls_active_window_and_notify_validation(self) -> None:
        posted: list[tuple[str, str]] = []
        sys_ctrl = WindowsSystemControls(
            active_window_fn=lambda: {
                "available": True,
                "status": "SUCCESS",
                "window_title": "SNOW — Visual Studio Code",
                "process_id": 4242,
                "process_name": "Code.exe",
            },
            notify_fn=lambda title, msg: posted.append((title, msg)) or {
                "success": True,
                "status": "SUCCESS",
                "title": title,
                "message": msg,
            },
            lock_fn=lambda: {"success": True, "status": "SUCCESS", "locked": True},
        )
        engine = CapabilityEngine(db_manager=self.db, system=sys_ctrl)
        ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="test")

        # Active window read-only
        win_res = await engine.execute(CapabilityRequest("windows_active_window", {}), ctx=ai_ctx)
        self.assertTrue(win_res.success)
        self.assertEqual(win_res.data["process_name"], "Code.exe")

        # Notify rejects invalid / NUL payloads
        bad_nul = await engine.execute(CapabilityRequest("windows_notify", {"title": "Hi\x00", "message": "Ok"}), ctx=ai_ctx)
        self.assertFalse(bad_nul.success)
        self.assertEqual(bad_nul.status, "INVALID_ARGUMENT")

        bad_empty = await engine.execute(CapabilityRequest("windows_notify", {"title": "  ", "message": "Ok"}), ctx=ai_ctx)
        self.assertFalse(bad_empty.success)

        # Notify sanitizes newlines & succeeds without shell
        ok_res = await engine.execute(
            CapabilityRequest("windows_notify", {"title": "Build\nDone", "message": "Line1\r\nLine2"}),
            ctx=ai_ctx,
        )
        self.assertTrue(ok_res.success)
        self.assertEqual(posted, [("Build Done", "Line1 Line2")])

    async def test_windows_lock_screen_approval_gate_and_owner_bypass(self) -> None:
        lock_calls = 0

        def fake_lock() -> dict:
            nonlocal lock_calls
            lock_calls += 1
            return {"success": True, "status": "SUCCESS", "locked": True}

        engine = CapabilityEngine(db_manager=self.db, system=WindowsSystemControls(lock_fn=fake_lock))
        ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="mcp_test")
        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="dashboard_owner")

        # 1. AI caller without approval -> blocked, never locks
        blocked = await engine.execute(CapabilityRequest("snow_windows_lock_screen", {}), ctx=ai_ctx)
        self.assertFalse(blocked.success)
        self.assertEqual(blocked.status, "APPROVAL_REQUIRED")
        self.assertEqual(lock_calls, 0)
        req_id = blocked.data["request_id"]
        self.assertEqual(blocked.data["risk_level"], "HIGH")

        # 2. Approve and retry as AI caller -> locks once
        ok_approve, _ = engine.approval_engine.approve_request(req_id)
        self.assertTrue(ok_approve)
        approved = await engine.execute(
            CapabilityRequest("snow_windows_lock_screen", {"approval_id": req_id}),
            ctx=ai_ctx,
        )
        self.assertTrue(approved.success)
        self.assertTrue(approved.data.get("locked"))
        self.assertEqual(lock_calls, 1)

        # 3. OWNER_MANUAL executes directly without approval
        direct = await engine.execute(CapabilityRequest("windows_lock_screen", {}), ctx=owner_ctx)
        self.assertTrue(direct.success)
        self.assertEqual(lock_calls, 2)

    async def test_mesh_health_summary_redacts_secrets_and_counts_nodes(self) -> None:
        mock_dm = MagicMock()
        mock_dm.is_ipc_ready = AsyncMock(return_value=False)
        engine = CapabilityEngine(db_manager=self.db)
        bridge = SnowMcpBridge(auto_start_core=False)
        bridge.capability_engine = engine
        bridge.daemon_manager = mock_dm
        bridge.list_devices = AsyncMock(return_value={
            "success": True,
            "data": {
                "devices": [
                    {"device_id": "local-pc", "device_name": "Workstation", "platform": "windows", "is_connected": True, "is_local": True, "transport": "local", "reachability_state": "CONNECTED_SESSION"},
                    {"device_id": "phone-1", "device_name": "Realme P4", "platform": "android", "is_connected": True, "is_local": False, "transport": "usb_adb", "reachability_state": "CONNECTED_SESSION"},
                    {"device_id": "phone-2", "device_name": "Backup", "platform": "android", "is_connected": False, "is_local": False, "transport": "offline", "reachability_state": "UNREACHABLE_OFFLINE"},
                ]
            },
        })
        summary = await bridge.snow_mesh_health_summary()
        self.assertTrue(summary["success"])
        self.assertEqual(summary["status"], "HEALTHY")
        self.assertEqual(summary["total_nodes"], 3)
        self.assertEqual(summary["online_nodes"], 2)
        self.assertEqual(summary["offline_nodes"], 1)
        self.assertEqual(summary["remote_online_nodes"], 1)

    def test_ipc_exposes_new_local_ops(self) -> None:
        src = Path(SnowIpcServer.__module__.replace(".", "/") + ".py")
        ipc_path = Path(__file__).resolve().parents[1] / "src" / "snow" / "core" / "ipc.py"
        text = ipc_path.read_text("utf-8")
        for op in ("windows_active_window", "windows_notify", "windows_lock_screen"):
            self.assertIn(f'"{op}"', text)


class TestV5Phase3And6WebEndpoints(unittest.IsolatedAsyncioTestCase):
    """Verify Web V5 deduplication, normalized telemetry, and screen capture endpoints."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = Path(tempfile.mkdtemp(prefix="snow_v5_web_"))
        self.ident = load_or_create_device_identity()
        self.mock_bridge = MagicMock()
        self.mock_bridge.port = 8767
        self.mock_bridge.daemon_manager = MagicMock()
        self.mock_bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)
        self.mock_bridge.windows_system_info = AsyncMock(return_value={
            "success": True,
            "data": {
                "hostname": "TEST-LAPTOP",
                "os_name": "Windows",
                "cpu": {"utilization_percent": 27.5, "logical_cores": 8},
                "memory": {"total_mb": 16384.0, "used_mb": 8192.0, "percent": 50.0},
                "disk": {"total_gb": 512.0, "used_gb": 256.0, "percent": 50.0},
            },
        })
        self.mock_bridge.windows_battery = AsyncMock(return_value={
            "success": True,
            "data": {"available": True, "percent": 82.0, "power_plugged": True, "status": "CHARGING"},
        })
        self.mock_bridge.list_devices = AsyncMock(return_value={
            "success": True,
            "status": "SUCCESS",
            "devices": [
                {
                    "device_id": self.ident.device_id,
                    "device_name": self.ident.device_name,
                    "platform": "windows",
                    "transport": "local",
                    "is_connected": True,
                },
                {
                    "device_id": "local",
                    "device_name": f"{self.ident.device_name} (This PC)",
                    "platform": "windows",
                    "transport": "local",
                    "is_connected": True,
                },
                {
                    "device_id": "phone-realmep4",
                    "device_name": "Realme P4",
                    "platform": "android",
                    "transport": "usb_adb",
                    "is_connected": True,
                },
            ],
        })
        self.mock_bridge.android_battery = AsyncMock(return_value={
            "success": True,
            "data": {
                "level": 91,
                "charging": False,
                "temperature_celsius": 31.4,
                "ram_total_bytes": 8 * 1024**3,
                "ram_available_bytes": 4 * 1024**3,
                "storage_available_bytes": 64 * 1024**3,
            },
        })

        self.web_server = SnowWebServer(bridge=self.mock_bridge, port=0)
        self.app = self.web_server.create_app()
        self.client = TestClient(TestServer(self.app))
        await self.client.start_server()
        try:
            # Authenticate test session
            bs_res = await self.client.post("/api/auth/session", json={"token": self.web_server.bootstrap_token})
            self.assertEqual(bs_res.status, 200)
        except Exception:
            await self.client.close()
            raise

    async def asyncTearDown(self) -> None:
        await self.client.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_api_status_returns_normalized_host_telemetry(self) -> None:
        resp = await self.client.get("/api/status")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["success"])
        tel = data["telemetry"]
        self.assertEqual(tel["cpu_percent"], 27.5)
        self.assertEqual(tel["battery_percent"], 82.0)
        self.assertTrue(tel["battery_charging"])
        self.assertEqual(tel["ram_percent"], 50.0)
        self.assertGreater(tel["ram_total_bytes"], 0)
        self.assertGreater(tel["storage_available_bytes"], 0)

    async def test_api_devices_deduplicates_local_host_and_populates_phone_telemetry(self) -> None:
        resp = await self.client.get("/api/devices")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        devs = data["devices"]
        local_hosts = [d for d in devs if d.get("is_local")]
        self.assertEqual(len(local_hosts), 1)
        phones = [d for d in devs if d.get("platform") == "android"]
        self.assertEqual(len(phones), 1)
        self.assertEqual(phones[0]["telemetry"]["battery_level"], 91)
        self.assertEqual(phones[0]["telemetry"]["temperature_celsius"], 31.4)

    async def test_capture_preview_and_latest_serves_transfer_root_and_rejects_traversal(self) -> None:
        cap_file = self.temp_dir / "android_screen_20261125_101500_ab12cd34.png"
        png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
        cap_file.write_bytes(png_bytes)

        mock_storage = MagicMock()
        mock_storage.root_dir = self.temp_dir
        with patch("snow.capabilities.windows.screenshot.DEFAULT_CAPTURES_DIR", self.temp_dir / "empty_cap"), \
             patch("snow.transfer.storage.TransferStorageManager", return_value=mock_storage):
            r_ok = await self.client.get(f"/api/captures/{cap_file.name}")
            self.assertEqual(r_ok.status, 200)
            self.assertEqual(await r_ok.read(), png_bytes)

            r_latest = await self.client.get("/api/screen/capture-latest")
            self.assertEqual(r_latest.status, 200)
            self.assertEqual(r_latest.headers.get("X-Snow-Filename"), cap_file.name)

            r_trav = await self.client.get("/api/captures/..%2fsecrets.png")
            self.assertEqual(r_trav.status, 404)

    def test_web_ui_structure_invariants_preserved(self) -> None:
        html_path = Path(__file__).resolve().parents[1] / "src" / "snow" / "web" / "static" / "index.html"
        html = html_path.read_text("utf-8")
        self.assertIn("FastMCP 54 Tools", html)
        self.assertNotIn("activity-timeline-container", html)
        self.assertIn('id="section-clipboard"', html)
        self.assertIn('id="btn-stop-screen-stream"', html)


if __name__ == "__main__":
    unittest.main()
