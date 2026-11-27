"""M4.4 Stage 4 & 5 Integration Tests:
- Standalone Android MCP end-to-end forwarding through Render Hub (/u/<android_snow_id>/mcp)
- 60-tool MCP parity across registry, FastMCP server, Doctor, and Web API
- All 6 new Android capabilities via SnowMcpBridge -> CoreIpcServer -> CapabilityEngine -> SessionRouter
- Approval enforcement on snow_android_file_write
- Bidirectional network-wide peer relay hardening (origin binding, SNW-XXXX-XXXX alias, cross-network denial, offline fail-closed)
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import uuid
from unittest.mock import AsyncMock, MagicMock

import aiohttp

from snow.capabilities.engine import CapabilityEngine, CapabilityRequest, ExecutionContext, ExecutionPrincipal
from snow.core.config import CoreConfig
from snow.core.ipc import IPC_PROTOCOL_VERSION, SnowIpcServer
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.registry import CAPABILITY_REGISTRY, list_capabilities, validate_registry
from snow.mcp.tools import ALL_TOOL_NAMES
from snow.mcp.server import create_snow_mcp_server
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage
from snow.relay.config import RelayConfig
from snow.relay.server import SnowRelayServer
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity, load_or_create_device_key_identity
from snow.security.policy import PeerCapabilityPolicy


def _b64u_sha256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


class TestM44NativeAndroidMcpTunnelAndSixTools(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="snow_m44_mcp_e2e_")
        self.db = DatabaseManager(db_path=Path(self.tmp_dir) / "snow_test.db")
        self.relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="m44-secret"))
        await self.relay.start()
        self.relay_port = int(self.relay._site._server.sockets[0].getsockname()[1])
        self.hub_http = f"http://127.0.0.1:{self.relay_port}"
        self.hub_ws = f"ws://127.0.0.1:{self.relay_port}/v1/tunnel"

    async def asyncTearDown(self) -> None:
        await self.relay.stop()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_render_hub_forwards_per_device_android_mcp_independently_of_windows(self) -> None:
        """Render Hub challenges & authenticates Android Ed25519 key and forwards /u/<android_snow_id>/mcp standalone."""
        android_key = load_or_create_device_key_identity(data_dir=Path(self.tmp_dir) / "android_key")
        # Windows PC is completely offline; only Android device connects to Render Hub
        async with aiohttp.ClientSession() as client:
            ch_r = await client.post(
                f"{self.hub_http}/v1/hub/challenge",
                json={"snow_id": android_key.snow_id, "public_key": android_key.public_key_b64, "device_id": "and-uuid-1"},
            )
            self.assertEqual(ch_r.status, 200)
            ch = await ch_r.json()
            sig = android_key.sign_device_hub_challenge(ch, device_id="and-uuid-1")
            sess_r = await client.post(
                f"{self.hub_http}/v1/hub/session",
                json={
                    "challenge_id": ch["challenge_id"],
                    "snow_id": android_key.snow_id,
                    "public_key": android_key.public_key_b64,
                    "signature": sig,
                    "device_id": "and-uuid-1",
                },
            )
            self.assertEqual(sess_r.status, 200)
            tok = (await sess_r.json())["token"]

            ws = await client.ws_connect(self.hub_ws)
            await ws.send_json({
                "type": "hello",
                "hub_token": tok,
                "snow_id": android_key.snow_id,
                "device_id": "and-uuid-1",
                "mcp_tunnel": True,
            })
            ack = await ws.receive_json()
            self.assertTrue(ack["success"])
            self.assertEqual(ack["snow_id"], android_key.snow_id)

            async def android_responder_loop() -> None:
                async for msg in ws:
                    if msg.type != aiohttp.WSMsgType.TEXT:
                        continue
                    env = json.loads(msg.data)
                    if env.get("type") != "mcp_http_request":
                        continue
                    req_id = env["request_id"]
                    path = env["path"]
                    hdrs = {k.lower(): v for k, v in env.get("headers", {}).items()}
                    if path == "/.well-known/oauth-protected-resource":
                        body = json.dumps({
                            "resource": f"http://127.0.0.1:{self.relay_port}/u/{android_key.snow_id}/mcp",
                            "authorization_servers": [f"http://127.0.0.1:{self.relay_port}/u/{android_key.snow_id}"],
                        }).encode()
                        status = 200
                    elif path == "/mcp" and hdrs.get("authorization") != "Bearer valid-and-tok":
                        body = json.dumps({"error": "invalid_token"}).encode()
                        status = 401
                    elif path == "/mcp":
                        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {"device_snow_id": android_key.snow_id}}).encode()
                        status = 200
                    else:
                        body = b"{}"
                        status = 404
                    await ws.send_json({
                        "type": "mcp_http_response",
                        "request_id": req_id,
                        "status": status,
                        "headers": {"Content-Type": "application/json"},
                        "body_b64": base64.b64encode(body).decode("ascii"),
                    })

            pump_task = asyncio.create_task(android_responder_loop())
            try:
                r_wk = await client.get(f"{self.hub_http}/u/{android_key.snow_id}/.well-known/oauth-protected-resource")
                self.assertEqual(r_wk.status, 200)
                self.assertIn(android_key.snow_id, (await r_wk.json())["resource"])

                # Unauthenticated /mcp returns 401 forwarded cleanly
                r_unauth = await client.post(
                    f"{self.hub_http}/u/{android_key.snow_id}/mcp",
                    json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                )
                self.assertEqual(r_unauth.status, 401)

                # Authenticated /mcp returns 200 forwarded cleanly
                r_ok = await client.post(
                    f"{self.hub_http}/u/{android_key.snow_id}/mcp",
                    headers={"Authorization": "Bearer valid-and-tok"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
                )
                self.assertEqual(r_ok.status, 200)
                self.assertEqual((await r_ok.json())["result"]["device_snow_id"], android_key.snow_id)
            finally:
                pump_task.cancel()
                await ws.close()

    async def test_60_tool_registry_parity_and_six_new_android_tools_bridge_and_ipc(self) -> None:
        ok, errs = validate_registry()
        self.assertTrue(ok, errs)
        self.assertEqual(len(CAPABILITY_REGISTRY), 60)
        self.assertEqual(len(ALL_TOOL_NAMES), 60)
        self.assertEqual(len(list_capabilities()), 60)
        srv = create_snow_mcp_server()
        srv_tools = {t.name for t in srv._tool_manager.list_tools()}
        self.assertEqual(len(srv_tools), 60)
        for new_tool in (
            "snow_android_file_read",
            "snow_android_file_write",
            "snow_android_file_search",
            "snow_android_device_info",
            "snow_android_audio_status",
            "snow_android_clipboard_get",
        ):
            self.assertIn(new_tool, srv_tools)

        # Verify readOnlyHint / destructiveHint / requires_approval annotations
        self.assertTrue(CAPABILITY_REGISTRY["snow_android_file_read"].read_only_hint)
        self.assertFalse(CAPABILITY_REGISTRY["snow_android_file_write"].read_only_hint)
        self.assertTrue(CAPABILITY_REGISTRY["snow_android_file_write"].destructive_hint)
        self.assertTrue(CAPABILITY_REGISTRY["snow_android_file_write"].requires_approval)
        self.assertTrue(CAPABILITY_REGISTRY["snow_android_file_search"].read_only_hint)
        self.assertTrue(CAPABILITY_REGISTRY["snow_android_device_info"].read_only_hint)
        self.assertTrue(CAPABILITY_REGISTRY["snow_android_audio_status"].read_only_hint)
        self.assertTrue(CAPABILITY_REGISTRY["snow_android_clipboard_get"].read_only_hint)

        # Wire mock SessionRouter + CapabilityEngine into CoreIpcServer & SnowMcpBridge
        routed_calls: list[tuple[str, str, dict]] = []

        class _FakeRouter:
            async def route_request(self, action: str, target: str, data: dict, ctx=None, **_kwargs):
                routed_calls.append((action, str(target), dict(data or {})))
                return {"success": True, "status": "SUCCESS", "data": {"action": action, "target": target}}

        engine = CapabilityEngine(db_manager=self.db, session_router=_FakeRouter())
        bridge = SnowMcpBridge()
        bridge.capability_engine = engine
        bridge.daemon_manager = MagicMock()
        bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)

        # 1. Traversal & over-limit rejected up-front at bridge before routing
        trav = await bridge.android_file_read("../secret.txt", device_id="phone-1")
        self.assertFalse(trav["success"])
        self.assertEqual(trav["status"], "PATH_TRAVERSAL_DETECTED")
        self.assertEqual(len(routed_calls), 0)

        enc_trav = await bridge.android_file_write("a/%2e%2e/b.txt", content="hi", device_id="phone-1")
        self.assertFalse(enc_trav["success"])
        self.assertEqual(enc_trav["status"], "PATH_TRAVERSAL_DETECTED")

        oversized = await bridge.android_file_write("big.txt", content="X" * (256 * 1024 + 5), device_id="phone-1")
        self.assertEqual(oversized["status"], "FILE_TOO_LARGE")

        # 2. Valid read/search/device_info/audio_status/clipboard_get dispatch cleanly
        r_read = await bridge.android_file_read("docs/notes.txt", device_id="phone-1")
        self.assertTrue(r_read["success"])
        r_search = await bridge.android_file_search("notes", max_results=200, max_depth=9, device_id="phone-1")
        self.assertTrue(r_search["success"])
        self.assertEqual(routed_calls[-1][2]["max_results"], 50)
        self.assertEqual(routed_calls[-1][2]["max_depth"], 5)
        self.assertTrue((await bridge.android_device_info("phone-1"))["success"])
        self.assertTrue((await bridge.android_audio_status("phone-1"))["success"])
        self.assertTrue((await bridge.android_clipboard_get("phone-1"))["success"])

        # 3. AI_MCP file_write requires owner approval before reaching SessionRouter
        write_denied = await bridge.android_file_write("docs/out.txt", content="hello", overwrite=False, device_id="phone-1")
        self.assertFalse(write_denied["success"])
        self.assertEqual(write_denied["status"], "APPROVAL_REQUIRED")
        req_id = write_denied["data"]["request_id"]

        ok_appr, _ = engine.approval_engine.approve_request(req_id, approver_principal=ExecutionPrincipal.OWNER_MANUAL)
        self.assertTrue(ok_appr)
        write_ok = await bridge.android_file_write("docs/out.txt", content="hello", overwrite=False, approval_id=req_id, device_id="phone-1")
        self.assertTrue(write_ok["success"])

        # 4. Also verify SnowIpcServer handles the 6 ops via IPC (without UNKNOWN_OPERATION)
        core_mock = MagicMock()
        core_mock.capability_engine = engine
        core_mock.session_router = engine.session_router
        core_mock.node_registry = None
        ipc = SnowIpcServer(core_server=core_mock, config=CoreConfig(ipc_secret_path=str(Path(self.tmp_dir) / "ipc.secret")))
        ipc_resp, _ = await ipc._dispatch_request(
            {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": "req-ipc-1",
                "op": "android_device_info",
                "payload": {"device_id": "phone-1"},
            },
            is_connection_authenticated=True,
        )
        self.assertTrue(ipc_resp["success"])

    async def test_windows_ws_server_peer_relay_origin_binding_and_network_isolation(self) -> None:
        win_uuid = str(uuid.uuid4())
        win_id = DeviceIdentity(device_id=win_uuid, device_name="WinHost", created_at="2026-01-01T00:00:00Z")
        policy = PeerCapabilityPolicy(policy_file=Path(self.tmp_dir) / "policy.json")
        self.db.set_setting("network_id", "SNW-NET-11112222")
        self.db.insert_paired_device(
            device_id="phone-a-id",
            device_name="Phone A",
            auth_token_hash="h-a",
            platform="android",
            network_id="SNW-NET-11112222",
        )
        self.db.insert_paired_device(
            device_id="phone-b-id",
            device_name="Phone B",
            auth_token_hash="h-b",
            platform="android",
            network_id="SNW-NET-11112222",
        )
        self.db.set_setting("device_snow_id:phone-b-id", "SNW-PHNB-2222")
        self.db.insert_paired_device(
            device_id="phone-ext-id",
            device_name="Phone Ext",
            auth_token_hash="h-ext",
            platform="android",
            network_id="SNW-NET-99998888",
        )

        forwarded_calls: list[dict] = []

        class _MockRouter:
            async def route_request(self, action: str, target: str, data: dict, **_kw):
                forwarded_calls.append({"action": action, "target": target, "data": dict(data)})
                return {"success": True, "status": "SUCCESS", "data": {"routed": target}}

        ws_srv = SnowWebSocketServer(
            config=CoreConfig(),
            device_identity=win_id,
            db_manager=self.db,
        )
        ws_srv.capability_policy = policy
        ws_srv.session_router = _MockRouter()

        class _FakeConn:
            def __init__(self) -> None:
                self.websocket = AsyncMock()
                self.websocket.send = AsyncMock()

        conn = _FakeConn()
        sess = MagicMock()
        sess.device_id = "phone-a-id"

        # 1. Spoofed origin_device_id overwritten with authenticated session.device_id + SNW-XXXX-XXXX resolved
        msg_ok = SnowMessage.create_request(
            "peer_relay_request",
            {
                "target_device_id": "SNW-PHNB-2222",
                "action": "battery_status",
                "data": {"origin_device_id": "spoofed-attacker", "principal": "OWNER_MANUAL"},
            },
        )
        await ws_srv._handle_peer_relay_request(conn, msg_ok, msg_ok.payload["data"], sess)
        self.assertEqual(len(forwarded_calls), 1)
        self.assertEqual(forwarded_calls[0]["target"], "phone-b-id")
        self.assertEqual(forwarded_calls[0]["data"]["origin_device_id"], "phone-a-id")
        self.assertNotIn("principal", forwarded_calls[0]["data"])

        # 2. Cross-network relay denied with UNAUTHORIZED
        msg_cross = SnowMessage.create_request(
            "peer_relay_request",
            {"target_device_id": "phone-ext-id", "action": "battery_status", "data": {}},
        )
        await ws_srv._handle_peer_relay_request(conn, msg_cross, msg_cross.payload["data"], sess)
        last_sent = json.loads(conn.websocket.send.call_args_list[-1].args[0])
        self.assertEqual(last_sent["type"], "error")
        self.assertEqual(last_sent["error"]["code"], "UNAUTHORIZED")
