"""Regression and adversarial verification suite for SNOW V4.1 Phase 1 Gate 1B Batch 2.

Covers the seven authorized findings:
- F1: Onboarding QR contract & device count filtering
- F3: Android App Launcher friendly names & principal-aware authorization
- F10: OS identity, peer platform detection & version unification (4.1.0)
- F15: Management IPC authorization, active transport closure & context propagation
- F16: Relay polling overwrite prevention, dashboard metadata & Connect Peer card
- F17: Remote Android clipboard image transfer with TransferDirection.DOWNLOAD
- F20: Owner authority propagation, CLI peer connection & DB record mapping
"""

import asyncio
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.core.config import CoreConfig
from snow.core.ipc import IPC_PROTOCOL_VERSION, SnowIpcServer
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager, PairedDeviceRecord
from snow.transfer.manager import TransferDirection, TransferManager


class TestF1OnboardingQRAndCount(unittest.TestCase):
    """Test F1: Onboarding QR contract and remote device count filtering."""

    def test_app_js_wizard_pairing_contract(self):
        app_js_path = Path(__file__).parent.parent / "src" / "snow" / "web" / "static" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")
        # Verify request sends trust_tier: owner
        self.assertIn('apiRequest("/api/pair/qr", "POST", { trust_tier: "owner" })', content)
        # Verify svg handling
        self.assertIn("res?.svg || res?.qr_svg || res?.data?.svg", content)
        # Verify pin handling
        self.assertIn("res?.data?.pin || res?.pin", content)
        # Verify filtering of remote connected devices
        self.assertIn("!isLocalNode(d) && d.is_connected", content)


class TestF3PrincipalAwareAppLaunching(unittest.IsolatedAsyncioTestCase):
    """Test F3: Principal-aware Android app launching and allowlist bypass for OWNER_MANUAL."""

    async def test_ipc_device_request_injects_owner_manual_for_owner_context(self):
        ipc = SnowIpcServer(core_server=MagicMock(), config=CoreConfig())
        ipc._secret = "test_secret"
        ipc.session_router = MagicMock()
        ipc.session_router._is_router_mock = True
        ipc.session_router.route_request = AsyncMock(return_value={"success": True, "status": "SUCCESS"})

        # 1. OWNER_MANUAL caller
        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="dashboard_owner")
        await ipc._handle_device_request(
            payload={"device_id": "phone-1", "action": "launch_app", "data": {"package_name": "com.any.app"}},
            ctx=owner_ctx,
        )

        call_args = ipc.session_router.route_request.call_args
        self.assertIsNotNone(call_args)
        data_sent = call_args.kwargs.get("data") or call_args[1].get("data")
        self.assertEqual(data_sent.get("principal"), "OWNER_MANUAL")

        # 2. AI_MCP caller cannot spoof OWNER_MANUAL
        ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="ipc")
        await ipc._handle_device_request(
            payload={
                "device_id": "phone-1",
                "action": "launch_app",
                "data": {"package_name": "com.any.app", "principal": "OWNER_MANUAL"},
            },
            ctx=ai_ctx,
        )
        call_args2 = ipc.session_router.route_request.call_args
        data_sent2 = call_args2.kwargs.get("data") or call_args2[1].get("data")
        self.assertEqual(data_sent2.get("principal"), "AI_MCP")

    def test_app_js_uses_label_for_app_names(self):
        app_js_path = Path(__file__).parent.parent / "src" / "snow" / "web" / "static" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")
        self.assertIn("app.label || app.app_name || app.name || app.package_name", content)


class TestF10OSIdentityAndVersionConsistency(unittest.TestCase):
    """Test F10: OS identity, peer platform detection, and version unification."""

    def test_version_unification_to_4_1_0(self):
        repo_root = Path(__file__).parent.parent

        # 1. src/snow/__init__.py
        init_file = repo_root / "src" / "snow" / "__init__.py"
        self.assertIn('__version__ = "5.2.0"', init_file.read_text(encoding="utf-8"))

        # 2. pyproject.toml
        pyproject_file = repo_root / "pyproject.toml"
        self.assertIn('version = "5.2.0"', pyproject_file.read_text(encoding="utf-8"))

        # 3. src/snow/core/config.py
        config_file = repo_root / "src" / "snow" / "core" / "config.py"
        self.assertIn('version: str = "5.2.0"', config_file.read_text(encoding="utf-8"))

        # 4. src/snow/cli.py
        cli_file = repo_root / "src" / "snow" / "cli.py"
        cli_text = cli_file.read_text(encoding="utf-8")
        self.assertIn("Version:           5.2.0", cli_text)
        self.assertIn("5.2.0", cli_text)

        # 5. src/snow/mcp/remote_gateway.py
        gw_file = repo_root / "src" / "snow" / "mcp" / "remote_gateway.py"
        gw_text = gw_file.read_text(encoding="utf-8")
        self.assertTrue('"version": "5.2.0"' in gw_text or '"version": SNOW_VERSION' in gw_text)

        # 6. android/app/build.gradle.kts
        gradle_file = repo_root / "android" / "app" / "build.gradle.kts"
        gradle_text = gradle_file.read_text(encoding="utf-8")
        self.assertIn('versionName = "5.2.0"', gradle_text)
        self.assertIn('versionCode = 4', gradle_text)

        # 7. packaging/windows/snow_setup.iss
        iss_file = repo_root / "packaging" / "windows" / "snow_setup.iss"
        self.assertIn('#define MyAppVersion "5.2.0"', iss_file.read_text(encoding="utf-8"))

    def test_peer_platform_detection_in_server(self):
        from snow.core.server import SnowCoreServer

        server = SnowCoreServer(CoreConfig())
        server.ws_server = MagicMock()
        server.ws_server.db_manager = MagicMock()
        server.network_manager = MagicMock()
        server.node_registry = MagicMock()

        # Mock SnowPeerClient
        with patch("snow.network.peer_client.SnowPeerClient") as mock_client_cls:
            mock_client = MagicMock()
            mock_res = MagicMock()
            mock_res.success = True
            mock_res.remote_device_id = "phone-android-1"
            mock_res.remote_device_name = "Pixel 8"
            mock_res.session_id = "sess-1"
            mock_res.auth_token = "tok-1"
            mock_res.cert_fingerprint = "fp-1"
            mock_res.status = "SUCCESS"
            mock_res.platform = "android"
            mock_res.manifest = {"platform": "android", "os": "Android 14"}
            mock_client.connect = AsyncMock(return_value=mock_res)
            mock_client_cls.return_value = mock_client

            server.ws_server.db_manager.get_paired_device.return_value = None

            asyncio.run(server.connect_peer(host="192.168.1.50", port=8765, pin="123456"))

            server.ws_server.db_manager.insert_paired_device.assert_called_once()
            call_kwargs = server.ws_server.db_manager.insert_paired_device.call_args.kwargs
            self.assertEqual(call_kwargs.get("platform"), "android")


class TestF15ManagementIPCAuthorization(unittest.IsolatedAsyncioTestCase):
    """Test F15: Management IPC authorization, active transport closure & context propagation."""

    async def asyncSetUp(self):
        self.core_server = MagicMock()
        self.core_server.db_manager = MagicMock()
        self.core_server.session_manager = MagicMock()
        self.core_server.connection_manager = MagicMock()
        self.core_server.peer_clients = {}
        self.core_server.connect_peer = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        self.core_server.configure_relay = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        self.ipc = SnowIpcServer(core_server=self.core_server, config=CoreConfig())
        self.ipc._secret = "test_secret"

    async def test_management_ops_reject_ai_mcp_with_policy_denied(self):
        mgmt_ops = [
            ("mesh_connect_peer", {"host": "127.0.0.1", "port": 8765}),
            ("mesh_disconnect_peer", {"device_id": "dev-1"}),
            ("device_set_connection_mode", {"device_id": "dev-1", "connection_mode": "auto"}),
            ("relay_config", {"enabled": True}),
            ("device_trust", {"device_id": "dev-1", "tier": "peer"}),
            ("device_revoke", {"device_id": "dev-1"}),
        ]

        for op, payload in mgmt_ops:
            req = {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": f"req_{op}",
                "op": op,
                "auth_token": "test_secret",
                "payload": payload,
            }
            # AI_MCP request has no owner_token
            res, _ = await self.ipc._dispatch_request(req, is_connection_authenticated=True)
            self.assertFalse(res["success"], f"Op {op} should fail for AI_MCP")
            self.assertEqual(res["status"], "POLICY_DENIED", f"Op {op} should return POLICY_DENIED for AI_MCP")

    async def test_device_revoke_closes_active_inbound_websocket_and_outbound_peer(self):
        import hmac

        # Mock active session and connection
        mock_session = MagicMock()
        mock_session.session_id = "sess-123"
        mock_session.connection_id = "conn-456"
        self.core_server.session_manager.get_session_by_device.return_value = mock_session

        mock_client_conn = MagicMock()
        mock_client_conn.websocket = MagicMock()
        mock_client_conn.websocket.close = AsyncMock()
        self.core_server.connection_manager.unregister.return_value = mock_client_conn

        # Mock active peer client
        mock_peer = MagicMock()
        mock_peer.close = AsyncMock()
        self.core_server.peer_clients["target-dev"] = mock_peer
        self.core_server.db_manager.delete_paired_device.return_value = True

        owner_token = hmac.new(
            b"test_secret", b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256
        ).hexdigest()

        req = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": "rev_1",
            "op": "device_revoke",
            "auth_token": "test_secret",
            "owner_token": owner_token,
            "payload": {"device_id": "target-dev"},
        }

        res, _ = await self.ipc._dispatch_request(req, is_connection_authenticated=True)

        self.assertTrue(res["success"])
        self.core_server.connection_manager.unregister.assert_called_with("conn-456")
        mock_client_conn.websocket.close.assert_called_once()
        mock_peer.close.assert_called_once()
        self.assertNotIn("target-dev", self.core_server.peer_clients)


class TestF16DashboardMetadataAndWorkflows(unittest.TestCase):
    """Test F16: Relay polling overwrite prevention, dashboard metadata, and Connect Peer UI."""

    def test_css_variables_defined(self):
        css_path = Path(__file__).parent.parent / "src" / "snow" / "web" / "static" / "app.css"
        css_text = css_path.read_text(encoding="utf-8")
        self.assertIn("--bg-card:", css_text)
        self.assertIn("--bg-hover:", css_text)
        self.assertIn("--bg-base:", css_text)
        self.assertIn("--accent-color:", css_text)

    def test_title_map_includes_clipboard_and_apps(self):
        app_js_path = Path(__file__).parent.parent / "src" / "snow" / "web" / "static" / "app.js"
        app_js = app_js_path.read_text(encoding="utf-8")
        self.assertIn('clipboard: "Clipboard History"', app_js)
        self.assertIn('apps: "Android Applications"', app_js)

    def test_workflow_id_is_not_prefixed_with_workflow(self):
        app_js_path = Path(__file__).parent.parent / "src" / "snow" / "web" / "static" / "app.js"
        app_js = app_js_path.read_text(encoding="utf-8")
        self.assertNotIn('"workflow_capture_pc_to_phone"', app_js)
        self.assertIn('workflow_id: "capture_pc_to_phone"', app_js)

    def test_index_html_has_connect_peer_card(self):
        html_path = Path(__file__).parent.parent / "src" / "snow" / "web" / "static" / "index.html"
        html_text = html_path.read_text(encoding="utf-8")
        self.assertIn("Connect to Peer Host", html_text)
        self.assertIn("connect-peer-host", html_text)
        self.assertIn("btn-connect-peer-submit", html_text)


class TestF17RemoteClipboardImageTransfer(unittest.IsolatedAsyncioTestCase):
    """Test F17: Remote Android clipboard image transfer with TransferDirection.DOWNLOAD."""

    async def test_clipboard_buffer_apply_image_to_remote_creates_download_transfer(self):
        from snow.capabilities.engine import CapabilityEngine, CapabilityRequest

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        storage_root = Path(temp_dir.name)

        tm = TransferManager()
        engine = CapabilityEngine(allowed_roots=[storage_root])
        engine.transfer_manager = tm

        # Mock image in clipboard buffer
        img_file = storage_root / "test_clip.png"
        img_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 100)
        file_sha256 = hashlib.sha256(img_file.read_bytes()).hexdigest()

        mock_buffer = MagicMock()
        mock_buffer.get_item.return_value = {
            "item_id": "clip-img-1",
            "content_type": "image",
            "mime_type": "image/png",
            "sha256": file_sha256,
        }
        mock_buffer.get_image_path.return_value = img_file
        engine.clipboard_buffer = mock_buffer

        mock_router = MagicMock()
        mock_router.route_request = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        engine.session_router = mock_router

        req = CapabilityRequest(
            action="clipboard_buffer_apply",
            params={"item_id": "clip-img-1", "target": "phone-remote-1"},
        )
        ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="dashboard")
        resp = await engine.execute(req, ctx=ctx)

        self.assertTrue(resp.success)
        mock_router.route_request.assert_called_once()
        call_kwargs = mock_router.route_request.call_args.kwargs
        self.assertEqual(call_kwargs.get("action"), "clipboard_push")
        data = call_kwargs.get("data") or {}
        self.assertEqual(data.get("type"), "image")
        self.assertEqual(data.get("sha256"), file_sha256)
        self.assertTrue(data.get("transfer_id"))

        # Verify transfer was registered in TransferManager as DOWNLOAD
        transfers = tm.list_transfers_for_device("phone-remote-1")
        self.assertEqual(len(transfers), 1)
        self.assertEqual(transfers[0].direction, TransferDirection.DOWNLOAD)
        self.assertEqual(transfers[0].file_size, len(img_file.read_bytes()))


class TestF20OwnerAuthorityAndDbRecordMapping(unittest.IsolatedAsyncioTestCase):
    """Test F20: Owner authority propagation, CLI peer connection, and DB record mapping."""

    def test_database_manager_get_owner_device_returns_complete_record(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        db_path = Path(temp_dir.name) / "test_snow.db"

        db = DatabaseManager(db_path=db_path)
        db.insert_paired_device(
            device_id="phone-owner-1",
            device_name="Ayush Phone",
            auth_token_hash="hash123",
            trust_tier="owner",
            platform="android",
            reachability_profile="ACTIVE_SESSION_PEER",
            role="owner",
        )

        owner = db.get_owner_device()
        self.assertIsNotNone(owner)
        self.assertIsInstance(owner, PairedDeviceRecord)
        self.assertEqual(owner.device_id, "phone-owner-1")
        self.assertEqual(owner.device_name, "Ayush Phone")
        self.assertEqual(owner.trust_tier, "owner")
        self.assertEqual(owner.platform, "android")
        self.assertEqual(owner.reachability_profile, "ACTIVE_SESSION_PEER")
        self.assertEqual(owner.role, "owner")

    async def test_mcp_bridge_owner_channel_uses_owner_manual_principal(self):
        from snow.mcp.bridge import SnowMcpBridge

        bridge = SnowMcpBridge(is_owner_channel=True)
        bridge.capability_engine = MagicMock()
        bridge.capability_engine.execute = AsyncMock(return_value=MagicMock(to_dict=lambda: {"success": True}))
        bridge.daemon_manager = MagicMock()
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)

        await bridge._execute_local_or_ipc("windows_battery", {})
        call_args = bridge.capability_engine.execute.call_args
        self.assertIsNotNone(call_args)
        ctx = call_args.kwargs.get("ctx") or call_args[1].get("ctx")
        self.assertEqual(ctx.principal, ExecutionPrincipal.OWNER_MANUAL)

    def test_cli_devices_connect_uses_bridge_mesh_connect_peer(self):
        from snow.cli import run_devices_connect

        with patch("snow.mcp.bridge.SnowMcpBridge") as mock_bridge_cls:
            mock_bridge = MagicMock()
            mock_bridge.mesh_connect_peer = AsyncMock(return_value={
                "success": True,
                "data": {"remote_device_id": "peer-99", "remote_device_name": "Office Laptop"}
            })
            mock_bridge_cls.return_value = mock_bridge

            ret = run_devices_connect(host="192.168.1.100", port=8765, pin="999888")
            self.assertEqual(ret, 0)
            mock_bridge.mesh_connect_peer.assert_called_once_with(host="192.168.1.100", port=8765, pin="999888")


class TestMicroPatchesRegression(unittest.IsolatedAsyncioTestCase):
    """Regression tests for the four Gate 1B Stage 1 micro-patches."""

    # Micro-patch 1: Local desktop identity in device revocation
    async def test_handle_api_devices_revoke_blocks_local_desktop(self):
        from aiohttp import web
        from snow.web.server import SnowWebServer
        from snow.security.identity import load_or_create_device_identity

        local_ident = load_or_create_device_identity()
        local_id = local_ident.device_id

        server = SnowWebServer(bridge=MagicMock())

        # Attempt to revoke local desktop node ID
        mock_req = MagicMock(spec=web.Request)
        mock_req.json = AsyncMock(return_value={"device_id": local_id})

        resp = await server.handle_api_devices_revoke(mock_req)
        self.assertEqual(resp.status, 400)
        body = json.loads(resp.text)
        self.assertFalse(body["success"])
        self.assertEqual(body["status"], "FORBIDDEN")
        self.assertIn("local desktop node", body["error"])

    async def test_handle_api_devices_revoke_allows_paired_owner_phone(self):
        from aiohttp import web
        from snow.web.server import SnowWebServer

        mock_bridge = MagicMock()
        mock_bridge.call = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        server = SnowWebServer(bridge=mock_bridge)

        # Paired owner phone ID can be revoked
        mock_req = MagicMock(spec=web.Request)
        mock_req.json = AsyncMock(return_value={"device_id": "phone-owner-uuid-123"})

        resp = await server.handle_api_devices_revoke(mock_req)
        self.assertEqual(resp.status, 200)
        body = json.loads(resp.text)
        self.assertTrue(body["success"])
        mock_bridge.call.assert_called_once_with("device_revoke", {"device_id": "phone-owner-uuid-123"})

    # Micro-patch 2: Preserve OWNER_MANUAL through SessionRouter for launch_app
    async def test_session_router_preserves_owner_manual_for_launch_app(self):
        from snow.network.router import SessionRouter
        from snow.network.node import DeviceNode

        mock_reg = MagicMock()
        router = SessionRouter(node_registry=mock_reg, db_manager=MagicMock())
        mock_node = DeviceNode(
            device_id="phone-1",
            device_name="Pixel",
            platform="android",
            reachability_state="LAN_DIRECT",
            host="192.168.1.50",
            wss_port=8765,
        )
        mock_reg.resolve_target.return_value = (mock_node, None)

        mock_client = MagicMock()
        mock_client.is_connected = True
        router._outbound_clients["phone-1"] = mock_client
        router._dispatch_over_peer_client = AsyncMock(return_value={"success": True, "status": "SUCCESS"})

        # 1. OWNER_MANUAL context: principal is preserved in clean_data
        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="dashboard_owner")
        res = await router.route_request(
            action="launch_app",
            target="phone-1",
            data={"package_name": "com.android.chrome"},
            ctx=owner_ctx,
        )
        self.assertTrue(res["success"])
        call_args = router._dispatch_over_peer_client.call_args
        dispatched_data = call_args.args[2]
        self.assertEqual(dispatched_data.get("principal"), "OWNER_MANUAL")

        # 2. AI_MCP context attempting spoofing: principal is stripped and not set to OWNER_MANUAL
        ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="mcp")
        res = await router.route_request(
            action="launch_app",
            target="phone-1",
            data={"package_name": "com.android.chrome", "principal": "OWNER_MANUAL"},
            ctx=ai_ctx,
        )
        self.assertTrue(res["success"])
        call_args2 = router._dispatch_over_peer_client.call_args
        dispatched_data2 = call_args2.args[2]
        self.assertNotEqual(dispatched_data2.get("principal"), "OWNER_MANUAL")

    # Micro-patch 3: Clipboard transfer UUID resolution
    async def test_clipboard_buffer_apply_resolves_generic_target_to_concrete_uuid(self):
        from snow.capabilities.engine import CapabilityEngine, CapabilityRequest
        from snow.network.node import DeviceNode

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        storage_root = Path(temp_dir.name)

        tm = TransferManager()
        engine = CapabilityEngine(allowed_roots=[storage_root])
        engine.transfer_manager = tm

        img_file = storage_root / "test_clip.png"
        img_bytes = b"\x89PNG\r\n\x1a\n" + b"0" * 100
        img_file.write_bytes(img_bytes)
        file_sha256 = hashlib.sha256(img_bytes).hexdigest()

        mock_buffer = MagicMock()
        mock_buffer.get_item.return_value = {
            "item_id": "clip-img-1",
            "content_type": "image",
            "mime_type": "image/png",
            "sha256": file_sha256,
        }
        mock_buffer.get_image_path.return_value = img_file
        engine.clipboard_buffer = mock_buffer

        mock_node = DeviceNode(
            device_id="resolved-phone-uuid-999",
            device_name="Pixel 8",
            platform="android",
            reachability_state="LAN_DIRECT",
        )
        mock_reg = MagicMock()
        mock_reg.resolve_target.return_value = (mock_node, None)
        engine.node_registry = mock_reg

        mock_router = MagicMock()
        mock_router.route_request = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        engine.session_router = mock_router

        req = CapabilityRequest(
            action="clipboard_buffer_apply",
            params={"item_id": "clip-img-1", "target": "android"},
        )
        resp = await engine.execute(req, ctx=ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL))
        self.assertTrue(resp.success)

        # Check that transfer was created with the resolved UUID, not "android"
        transfers = tm.list_transfers_for_device("resolved-phone-uuid-999")
        self.assertEqual(len(transfers), 1)
        self.assertEqual(transfers[0].device_id, "resolved-phone-uuid-999")
        self.assertEqual(len(tm.list_transfers_for_device("android")), 0)

    async def test_clipboard_buffer_apply_fails_when_generic_target_cannot_be_resolved(self):
        from snow.capabilities.engine import CapabilityEngine, CapabilityRequest

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        storage_root = Path(temp_dir.name)

        tm = TransferManager()
        engine = CapabilityEngine(allowed_roots=[storage_root])
        engine.transfer_manager = tm

        img_file = storage_root / "test_clip.png"
        img_bytes = b"\x89PNG\r\n\x1a\n" + b"0" * 100
        img_file.write_bytes(img_bytes)
        file_sha256 = hashlib.sha256(img_bytes).hexdigest()

        mock_buffer = MagicMock()
        mock_buffer.get_item.return_value = {
            "item_id": "clip-img-1",
            "content_type": "image",
            "mime_type": "image/png",
            "sha256": file_sha256,
        }
        mock_buffer.get_image_path.return_value = img_file
        engine.clipboard_buffer = mock_buffer

        mock_reg = MagicMock()
        mock_reg.resolve_target.return_value = (None, "NO_DEVICES_PAIRED")
        engine.node_registry = mock_reg

        mock_router = MagicMock()
        mock_router.route_request = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        engine.session_router = mock_router

        req = CapabilityRequest(
            action="clipboard_buffer_apply",
            params={"item_id": "clip-img-1", "target": "android"},
        )
        resp = await engine.execute(req, ctx=ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL))
        self.assertFalse(resp.success)
        self.assertEqual(resp.status, "NO_DEVICES_PAIRED")
        self.assertEqual(len(tm.list_transfers_for_device("android")), 0)

    # Micro-patch 4: CLI administrative commands instantiate bridge with is_owner_channel=True
    def test_cli_devices_trust_and_revoke_use_owner_channel(self):
        from snow.cli import run_devices_trust, run_devices_revoke

        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        db_path = Path(temp_dir.name) / "test.db"

        db = DatabaseManager(db_path=db_path)
        db.insert_paired_device(
            device_id="dev-test-1",
            device_name="Test Dev",
            auth_token_hash="hash",
            trust_tier="peer",
        )

        with patch("snow.cli.SnowMcpBridge") as mock_bridge_cls:
            mock_bridge = MagicMock()
            mock_bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)
            mock_bridge.call = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
            mock_bridge_cls.return_value = mock_bridge

            # Test run_devices_trust
            ret_trust = run_devices_trust(device_id="dev-test-1", tier="owner", yes=True, db_path=db_path)
            self.assertEqual(ret_trust, 0)
            mock_bridge_cls.assert_called_with(auto_start_core=False, is_owner_channel=True)
            mock_bridge.call.assert_called_with("device_trust", {"device_id": "dev-test-1", "tier": "owner"})

            mock_bridge_cls.reset_mock()
            mock_bridge.call.reset_mock()

            # Test run_devices_revoke
            ret_revoke = run_devices_revoke(device_id="dev-test-1", yes=True, db_path=db_path)
            self.assertEqual(ret_revoke, 0)
            mock_bridge_cls.assert_called_with(auto_start_core=False, is_owner_channel=True)
            mock_bridge.call.assert_called_with("device_revoke", {"device_id": "dev-test-1"})


if __name__ == "__main__":
    unittest.main()
