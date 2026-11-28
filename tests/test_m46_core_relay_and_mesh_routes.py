"""Unit and integration tests for SNOW Milestone 4.6 backend, relay, discovery, router, IPC, USB, and Web APIs."""

import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from aiohttp.test_utils import TestClient, TestServer, make_mocked_request

from snow.core.config import CoreConfig
from snow.core.ipc import IPC_PROTOCOL_VERSION, SnowIpcServer
from snow.core.server import SnowCoreServer
from snow.core.usb import unlock_android_permissions
from snow.mcp.bridge import SnowMcpBridge
from snow.network.discovery import SnowDiscoveryService
from snow.network.node import DeviceNode, ReachabilityProfile
from snow.network.registry import NodeRegistry
from snow.network.relay_client import RelayTunnelClient
from snow.network.router import SessionRouter
from snow.protocol.models import SnowMessage
from snow.relay.server import RelayConfig, SnowRelayServer
from snow.security.db import DatabaseManager
from snow.security.identity import (
    DeviceIdentity,
    generate_snow_id,
    load_or_create_device_key_identity,
    load_or_create_network_key_identity,
    resolve_canonical_device_snow_id,
)
from snow.security.policy import ExecutionContext, ExecutionPrincipal
from snow.security.tls import generate_self_signed_cert
from snow.web.server import SnowWebServer


def _make_identity(name: str, device_id: str | None = None) -> DeviceIdentity:
    did = device_id or str(uuid.uuid4())
    return DeviceIdentity(
        device_id=did,
        device_name=name,
        created_at="2026-01-01T00:00:00Z",
        snow_id=generate_snow_id(seed=did),
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class TestM46PassivePollsAndCoreOnline(unittest.IsolatedAsyncioTestCase):
    """Requirement 1: Core online stability and non-blocking passive polls."""

    async def test_router_passive_skips_tier3_and_tier375_and_strips_flag(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db = DatabaseManager(Path(tmpdir) / "snow.db")
            local_id = _make_identity("PC-Host")
            reg = NodeRegistry(db_manager=db, local_identity=local_id, port=8765, transfer_port=8766)
            db.insert_paired_device(
                device_id="phone-1",
                device_name="Pixel",
                auth_token_hash="tok-hash-1",
                platform="android",
                reachability_profile="ACTIVE_SESSION_PEER",
            )
            reg.register_node(
                DeviceNode(
                    device_id="phone-1",
                    device_name="Pixel",
                    platform="android",
                    reachability_profile=ReachabilityProfile.ACTIVE_SESSION_PEER,
                    supported_capabilities=["android.telemetry.get", "android.notifications.list"],
                    is_paired=True,
                )
            )

            disc_mock = MagicMock()
            disc_mock.is_running = True
            disc_mock.send_wake_burst = AsyncMock()

            fake_relay = MagicMock()
            fake_relay._is_connected = False
            fake_relay._tunnels = {}

            router = SessionRouter(
                node_registry=reg,
                ws_server=None,
                discovery_service=disc_mock,
                db_manager=db,
                wake_grace_period=6.0,
                relay_enabled=True,
                relay_client=fake_relay,
            )
            router._attempt_remote_relay_tunnel = AsyncMock(return_value=None)

            t0 = time.monotonic()
            res = await router.route_request(
                action="android_battery",
                target="phone-1",
                data={"passive": True},
                passive=True,
            )
            elapsed = time.monotonic() - t0
            self.assertLess(elapsed, 0.5)
            self.assertFalse(res["success"])
            self.assertEqual(res["status"], "DEVICE_UNREACHABLE")
            self.assertTrue(res.get("passive_skipped"))
            self.assertNotIn("android_wake_and_await", res.get("attempted_transports", []))
            self.assertNotIn("remote_relay_tunnel", res.get("attempted_transports", []))
            disc_mock.send_wake_burst.assert_not_awaited()
            router._attempt_remote_relay_tunnel.assert_not_awaited()

            # Even remote_only skips _attempt_remote_relay_tunnel when passive=True and no verified relay tunnel exists
            db.update_device_connection_mode("phone-1", "remote_only")
            res_remote = await router.route_request(
                action="notifications_list",
                target="phone-1",
                data={"passive": True},
                passive=True,
            )
            self.assertFalse(res_remote["success"])
            self.assertTrue(res_remote.get("passive_skipped"))
            router._attempt_remote_relay_tunnel.assert_not_awaited()

            # When active verified relay session exists, passive=True dispatches and strips passive from wire data
            verified_tun = MagicMock()
            verified_tun.handshake_done = True
            fake_relay._is_connected = True
            fake_relay._tunnels = {"phone-1": verified_tun}
            captured_wire = {}

            async def _fake_relay_dispatch(node, action, clean_data, timeout, attempted_transports):
                captured_wire["data"] = dict(clean_data)
                return {
                    "success": True,
                    "status": "SUCCESS",
                    "data": {"level": 88},
                    "attempted_transports": attempted_transports,
                }

            router._attempt_remote_relay_tunnel = AsyncMock(side_effect=_fake_relay_dispatch)
            res_live = await router.route_request(
                action="android_battery",
                target="phone-1",
                data={"passive": True, "detail": "quick"},
                passive=True,
            )
            self.assertTrue(res_live["success"])
            self.assertNotIn("passive", captured_wire["data"])
            self.assertEqual(captured_wire["data"], {"detail": "quick"})

            # Non-passive caller STILL invokes normal Tier 3 wake-and-await & Tier 3.75
            db.update_device_connection_mode("phone-1", "auto")
            router.wake_grace_period = 0.05
            fake_relay._is_connected = False
            fake_relay._tunnels = {}
            router._attempt_remote_relay_tunnel = AsyncMock(
                return_value={
                    "success": True,
                    "status": "SUCCESS",
                    "data": {"level": 77},
                    "attempted_transports": ["android_wake_and_await", "remote_relay_tunnel"],
                }
            )
            res_direct = await router.route_request(action="android_battery", target="phone-1")
            self.assertTrue(res_direct["success"])
            disc_mock.send_wake_burst.assert_awaited_once()
            router._attempt_remote_relay_tunnel.assert_awaited_once()

    async def test_ipc_device_request_passes_passive_and_strips_wire_flag(self):
        fake_router = MagicMock()
        fake_router._is_router_mock = True
        captured = {}

        async def _fake_route_request(action, target=None, data=None, ctx=None, timeout=30.0, passive=False):
            captured["action"] = action
            captured["target"] = target
            captured["data"] = data
            captured["passive"] = passive
            return {"success": True, "status": "SUCCESS", "data": {}}

        fake_router.route_request = _fake_route_request
        ipc = SnowIpcServer(core_server=MagicMock(), config=CoreConfig())
        ipc.session_router = fake_router

        ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="test")
        res = await ipc._handle_device_request(
            {"device_id": "phone-1", "action": "notifications_list", "data": {"passive": True, "limit": 5}, "passive": True},
            ctx=ctx,
        )
        self.assertTrue(res["success"])
        self.assertTrue(captured["passive"])
        self.assertEqual(captured["data"], {"limit": 5})

        # Short poll hint on battery_status without explicit passive=False
        captured.clear()
        await ipc._handle_device_request(
            {"device_id": "phone-1", "action": "android_battery", "data": {}, "timeout": 1.5},
            ctx=ctx,
        )
        self.assertTrue(captured["passive"])

        # Direct normal request retains passive=False
        captured.clear()
        await ipc._handle_device_request(
            {"device_id": "phone-1", "action": "android_battery", "data": {}},
            ctx=ctx,
        )
        self.assertFalse(captured["passive"])

    async def test_web_api_status_uses_1s_ipc_timeout_recent_cache_and_passive_polls(self):
        bridge = MagicMock()
        dm = MagicMock()
        dm.is_ipc_ready = AsyncMock(return_value=True)
        bridge.daemon_manager = dm
        bridge.windows_system_info = AsyncMock(return_value={"cpu_percent": 10})
        bridge.windows_battery = AsyncMock(return_value={"percent": 90})
        bridge.list_devices = AsyncMock(
            return_value={
                "success": True,
                "data": {"devices": [{"device_id": "dev-1", "device_name": "Pixel", "is_connected": True}]},
            }
        )
        bridge.android_notifications_list = AsyncMock(return_value={"success": True, "data": {"notifications": []}})
        bridge.android_battery = AsyncMock(return_value={"success": True, "data": {"percent": 85, "is_charging": False}})

        web_srv = SnowWebServer(bridge=bridge)
        app = web_srv._build_app()
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            web_srv.port = int(client.port)
            sess_resp = await client.post("/api/auth/session", json={"token": web_srv.bootstrap_token})
            self.assertEqual(sess_resp.status, 200)

            resp1 = await client.get("/api/status")
            self.assertEqual(resp1.status, 200)
            body1 = await resp1.json()
            self.assertTrue(body1["daemon_online"])
            dm.is_ipc_ready.assert_awaited_with(timeout=1.0)

            # Transient timeout on is_ipc_ready keeps daemon_online=True within 3s after recent IPC success
            dm.is_ipc_ready = AsyncMock(return_value=False)
            resp2 = await client.get("/api/status")
            body2 = await resp2.json()
            self.assertTrue(body2["daemon_online"])

            # Expired > 3s with is_ipc_ready=False returns daemon_online=False
            web_srv._last_ipc_success_ts = time.monotonic() - 10.0
            resp3 = await client.get("/api/status")
            body3 = await resp3.json()
            self.assertFalse(body3["daemon_online"])

            # Subsequent call to /api/devices marks IPC success again AND passes passive=True to android_battery
            await client.get("/api/devices")
            bridge.android_battery.assert_awaited_with(device_id="dev-1", passive=True)
            resp4 = await client.get("/api/status")
            body4 = await resp4.json()
            self.assertTrue(body4["daemon_online"])

            # /api/notifications passes passive=True when supported
            notif_resp = await client.get("/api/notifications?device_id=dev-1")
            self.assertEqual(notif_resp.status, 200)
            bridge.android_notifications_list.assert_awaited_with(device_id="dev-1", passive=True)
        finally:
            await client.close()

    async def test_real_bridge_call_cross_device_receives_passive_true(self):
        real_bridge = SnowMcpBridge.__new__(SnowMcpBridge)
        captured_cross = {}

        async def _fake_resolve(self, dev_id=""):
            return dev_id or "dev-real-1"

        async def _fake_cross(self, op, payload=None, timeout=10.0):
            captured_cross["op"] = op
            captured_cross["payload"] = payload
            return {"success": True, "status": "SUCCESS", "data": {"notifications": []}}

        with patch.object(SnowMcpBridge, "_resolve_android_target", new=_fake_resolve), patch.object(
            SnowMcpBridge, "call_cross_device", new=_fake_cross
        ):
            web_srv = SnowWebServer(bridge=real_bridge)
            req = make_mocked_request("GET", "/api/notifications?device_id=dev-real-1")
            resp = await web_srv.handle_api_notifications(req)
            self.assertEqual(resp.status, 200)
            self.assertEqual(captured_cross["op"], "device_request")
            self.assertTrue(captured_cross["payload"]["passive"])
            self.assertEqual(captured_cross["payload"]["action"], "notifications_list")


class TestM46AlwaysOnRelayAndMesh(unittest.IsolatedAsyncioTestCase):
    """Requirement 2: Always-on Hosted Render Relay + standalone & shared Ed25519 routing."""

    async def test_relay_standalone_rendezvous_and_paired_device_tunnel(self):
        cfg = RelayConfig(host="127.0.0.1", port=0, shared_secret="m46-secret")
        relay = SnowRelayServer(config=cfg)
        await relay.start()
        try:
            relay_port = int(relay._site._server.sockets[0].getsockname()[1])
            base_http = f"http://127.0.0.1:{relay_port}"
            base_ws = f"ws://127.0.0.1:{relay_port}/v1/tunnel"

            with tempfile.TemporaryDirectory() as key_tmp:
                dev_a_key = load_or_create_device_key_identity(data_dir=key_tmp, file_name="dev_a.json")
                dev_b_key = load_or_create_device_key_identity(data_dir=key_tmp, file_name="dev_b.json")
                net_key = load_or_create_network_key_identity(data_dir=key_tmp, file_name="net_k.json")

                import aiohttp

                async with aiohttp.ClientSession() as http_cli:
                    async def _auth_device(dk, dev_id: str, net_id: str = "") -> str:
                        async with http_cli.post(
                            f"{base_http}/v1/hub/challenge",
                            json={
                                "auth_kind": "device",
                                "network_id": net_id,
                                "public_key": dk.public_key_b64,
                                "device_id": dev_id,
                                "snow_id": dk.snow_id,
                            },
                        ) as r1:
                            self.assertEqual(r1.status, 200)
                            ch = await r1.json()
                        sig = dk.sign_device_hub_challenge(ch, device_id=dev_id, network_id=net_id)
                        async with http_cli.post(
                            f"{base_http}/v1/hub/session",
                            json={
                                "challenge_id": ch["challenge_id"],
                                "network_id": net_id,
                                "public_key": dk.public_key_b64,
                                "signature": sig,
                                "device_id": dev_id,
                                "snow_id": dk.snow_id,
                            },
                        ) as r2:
                            self.assertEqual(r2.status, 200)
                            return (await r2.json())["token"]

                    tok_a = await _auth_device(dev_a_key, "dev-a", "")
                    tok_b = await _auth_device(dev_b_key, "dev-b", "")

                    # Network key token strictly rejects mismatched network on /v1/rendezvous/open
                    async with http_cli.post(
                        f"{base_http}/v1/hub/challenge",
                        json={"network_id": net_key.network_id, "public_key": net_key.public_key_b64, "device_id": "net-dev"},
                    ) as r_net_ch:
                        ch_net = await r_net_ch.json()
                    async with http_cli.post(
                        f"{base_http}/v1/hub/session",
                        json={
                            "challenge_id": ch_net["challenge_id"],
                            "network_id": net_key.network_id,
                            "public_key": net_key.public_key_b64,
                            "signature": net_key.sign_hub_challenge(ch_net, device_id="net-dev"),
                            "device_id": "net-dev",
                        },
                    ) as r_net_sess:
                        net_tok = (await r_net_sess.json())["token"]
                    async with http_cli.post(
                        f"{base_http}/v1/rendezvous/open",
                        headers={"Authorization": f"Bearer {net_tok}"},
                        json={
                            "network_id": "SNW-NET-WRONG1",
                            "host_device_id": "net-dev",
                            "host_snow_id": dev_a_key.snow_id,
                            "pin": "123456",
                        },
                    ) as bad_open:
                        self.assertEqual(bad_open.status, 403)

                    # Standalone auth_kind="device" can open rendezvous slot scoped to host_snow_id + host_device_id
                    async with http_cli.post(
                        f"{base_http}/v1/rendezvous/open",
                        headers={"Authorization": f"Bearer {tok_a}"},
                        json={"network_id": "", "host_device_id": "dev-a", "host_snow_id": dev_b_key.snow_id, "pin": "654321"},
                    ) as spoof_open:
                        self.assertEqual(spoof_open.status, 403)

                    async with http_cli.post(
                        f"{base_http}/v1/rendezvous/open",
                        headers={"Authorization": f"Bearer {tok_a}"},
                        json={
                            "network_id": "",
                            "host_device_id": "dev-a",
                            "host_snow_id": dev_a_key.snow_id,
                            "pin": "654321",
                            "ttl_seconds": 60,
                        },
                    ) as ok_open:
                        self.assertEqual(ok_open.status, 200)
                        rdv_id = (await ok_open.json())["rendezvous_id"]

                    # Another standalone device cannot cancel Device A's opening
                    async with http_cli.post(
                        f"{base_http}/v1/rendezvous/cancel",
                        headers={"Authorization": f"Bearer {tok_b}"},
                        json={"rendezvous_id": rdv_id},
                    ) as bad_cancel:
                        self.assertEqual(bad_cancel.status, 403)

                    # Directory resolve returns 403 for Device B (signals PIN required on Render Hub)
                    async with http_cli.get(
                        f"{base_http}/v1/directory/resolve/{dev_a_key.snow_id}",
                        headers={"Authorization": f"Bearer {tok_b}"},
                    ) as dir_resp:
                        self.assertEqual(dir_resp.status, 403)

                    # Join standalone opening -> issues bootstrap token with host_snow_id mapped into dev_<host_snow_id>
                    async with http_cli.post(
                        f"{base_http}/v1/rendezvous/join",
                        json={"client_device_id": "dev-b", "snow_id": dev_a_key.snow_id, "pin": "654321"},
                    ) as join_resp:
                        self.assertEqual(join_resp.status, 200)
                        join_data = await join_resp.json()
                        self.assertEqual(join_data["host_snow_id"], dev_a_key.snow_id)
                        bs_tok = join_data["bootstrap_token"]

                    ca_cert = Path(key_tmp) / "a.crt"
                    ca_key = Path(key_tmp) / "a.key"
                    cb_cert = Path(key_tmp) / "b.crt"
                    cb_key = Path(key_tmp) / "b.key"
                    generate_self_signed_cert(ca_cert, ca_key, common_name="dev-a")
                    generate_self_signed_cert(cb_cert, cb_key, common_name="dev-b")

                    host_cli = RelayTunnelClient(
                        relay_url=base_ws,
                        device_id="dev-a",
                        group_id=f"dev_{dev_a_key.snow_id}",
                        ticket="",
                        cert_path=str(ca_cert),
                        key_path=str(ca_key),
                        hub_token=tok_a,
                        network_id="",
                    )
                    bs_cli = RelayTunnelClient(
                        relay_url=base_ws,
                        device_id="dev-b",
                        group_id=f"dev_{dev_a_key.snow_id}",
                        ticket="",
                        cert_path=str(cb_cert),
                        key_path=str(cb_key),
                        bootstrap_token=bs_tok,
                        network_id="",
                    )
                    received = []

                    async def _on_req(src_id: str, msg: SnowMessage):
                        received.append((src_id, msg.action))
                        return SnowMessage.create_response(
                            correlation_id=msg.id, payload={"status": "success", "ok": True}
                        )

                    host_cli.request_dispatcher = _on_req
                    self.assertTrue(await host_cli.connect())
                    self.assertTrue(await bs_cli.connect())

                    sent_bs = await bs_cli.send_message(
                        "dev-a", SnowMessage.create_request(action="pair_request", data={"hello": 1})
                    )
                    self.assertTrue(sent_bs)
                    echo_resp = await bs_cli.receive_message("dev-a", timeout=5.0)
                    self.assertIsNotNone(echo_resp)
                    self.assertTrue(echo_resp.payload.get("ok"))
                    self.assertEqual(received, [("dev-b", "pair_request")])

                    await bs_cli.disconnect()
                    await host_cli.disconnect()

                    # Paired devices with auth_kind="device" + shared network_id map to same group_id and allow dual mcp_tunnel + data tunnel
                    shared_net = "SNW-NET-AABB4646"
                    tok_a_shared = await _auth_device(dev_a_key, "dev-a", shared_net)
                    tok_b_shared = await _auth_device(dev_b_key, "dev-b", shared_net)

                    cli_a = RelayTunnelClient(
                        relay_url=base_ws,
                        device_id="dev-a",
                        group_id=shared_net,
                        ticket="",
                        cert_path=str(ca_cert),
                        key_path=str(ca_key),
                        hub_token=tok_a_shared,
                        network_id=shared_net,
                    )
                    cli_b = RelayTunnelClient(
                        relay_url=base_ws,
                        device_id="dev-b",
                        group_id=shared_net,
                        ticket="",
                        cert_path=str(cb_cert),
                        key_path=str(cb_key),
                        hub_token=tok_b_shared,
                        network_id=shared_net,
                    )
                    cli_b.request_dispatcher = _on_req
                    self.assertTrue(await cli_a.connect())
                    self.assertTrue(await cli_b.connect())

                    ws_tok_fwd = await _auth_device(dev_a_key, "dev-a", shared_net)
                    async with http_cli.ws_connect(base_ws) as mcp_ws:
                        await mcp_ws.send_json({
                            "type": "hello",
                            "device_id": "dev-a",
                            "network_id": shared_net,
                            "snow_id": dev_a_key.snow_id,
                            "hub_token": ws_tok_fwd,
                            "mcp_tunnel": True,
                            "register_network_coordinator": True,
                        })
                        ack = await mcp_ws.receive_json()
                        self.assertEqual(ack["type"], "hello_ack")

                        # Data-plane cli_a <-> cli_b works simultaneously with mcp_tunnel!
                        self.assertTrue(
                            await cli_a.send_message("dev-b", SnowMessage.create_request(action="ping", data={}))
                        )
                        e2e_msg = await cli_a.receive_message("dev-b", timeout=5.0)
                        self.assertIsNotNone(e2e_msg)
                        self.assertTrue(e2e_msg.payload.get("ok"))

                    await cli_b.disconnect()
                    await cli_a.disconnect()
        finally:
            await relay.stop()

    async def test_core_start_autostart_relay_defaults_and_resync_membership(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old_data_dir = os.environ.get("SNOW_DATA_DIR")
            os.environ["SNOW_DATA_DIR"] = tmpdir
            try:
                db = DatabaseManager(Path(tmpdir) / "core.db")
                cfg = CoreConfig(
                    port=_free_port(),
                    transfer_port=_free_port(),
                    ipc_port=_free_port(),
                    relay_enabled=False,
                    relay_url="http://127.0.0.1:19999",
                )
                core = SnowCoreServer(config=cfg, db_manager=db)
                core.configure_relay = AsyncMock(return_value={"enabled": True, "connected": True})
                with patch("snow.network.ws_server.SnowWebSocketServer.start", new=AsyncMock()), patch(
                    "snow.transfer.http_server.SnowHttpTransferServer.start", new=AsyncMock()
                ), patch("snow.core.ipc.SnowIpcServer.start", new=AsyncMock()), patch(
                    "snow.core.usb.UsbWatcher.start", new=AsyncMock()
                ), patch("snow.network.discovery.SnowDiscoveryService.start", new=AsyncMock()):
                    await core.start()
                    await asyncio.sleep(0.05)
                    self.assertTrue(core.relay_enabled)
                    self.assertTrue(core.session_router.relay_enabled)
                    core.configure_relay.assert_awaited()
                    await core.stop()

                # Explicit "false" in DB disables autostart
                db2 = DatabaseManager(Path(tmpdir) / "core2.db")
                db2.set_setting("remote_relay_enabled", "false")
                cfg2 = CoreConfig(
                    port=_free_port(),
                    transfer_port=_free_port(),
                    ipc_port=_free_port(),
                    relay_enabled=False,
                    relay_url="http://127.0.0.1:19999",
                )
                core2 = SnowCoreServer(config=cfg2, db_manager=db2)
                core2.configure_relay = AsyncMock(return_value={"enabled": False, "connected": False})
                with patch("snow.network.ws_server.SnowWebSocketServer.start", new=AsyncMock()), patch(
                    "snow.transfer.http_server.SnowHttpTransferServer.start", new=AsyncMock()
                ), patch("snow.core.ipc.SnowIpcServer.start", new=AsyncMock()), patch(
                    "snow.core.usb.UsbWatcher.start", new=AsyncMock()
                ), patch("snow.network.discovery.SnowDiscoveryService.start", new=AsyncMock()):
                    await core2.start()
                    await asyncio.sleep(0.05)
                    self.assertFalse(core2.relay_enabled)
                    self.assertFalse(core2.session_router.relay_enabled)
                    core2.configure_relay.assert_not_awaited()
                    await core2.stop()

                # Standalone never uses network_key.json; resync pins fingerprints and re-joins when network adopted
                core3 = SnowCoreServer(
                    config=CoreConfig(
                        port=_free_port(),
                        transfer_port=_free_port(),
                        ipc_port=_free_port(),
                        relay_url="ws://127.0.0.1:8888/v1/tunnel",
                    ),
                    db_manager=db,
                )
                dev_key = load_or_create_device_key_identity()
                fake_relay_cli = MagicMock()
                fake_relay_cli._is_connected = True
                fake_relay_cli.group_id = f"dev_{dev_key.snow_id}"
                fake_relay_cli.network_id = ""
                core3.relay_enabled = True
                core3.relay_client = fake_relay_cli
                core3.configure_relay = AsyncMock(return_value={"enabled": True, "connected": True})

                db.insert_paired_device("peer-x", "Pixel", "hash-x", cert_fingerprint="AB" * 32)
                await core3.resync_relay_group_membership()
                fake_relay_cli.set_peer_pinned_fingerprint.assert_called_with("peer-x", "AB" * 32)
                core3.configure_relay.assert_not_awaited()

                db.ensure_active_network("My Net", core3.device_identity.device_id, network_id="SNW-NET-A1B2C3D4")
                await core3.resync_relay_group_membership()
                core3.configure_relay.assert_awaited_once_with(enabled=True, group_id="SNW-NET-A1B2C3D4")

                # Verify resolve_network_merge triggers resync_relay_group_membership on commit
                core3.resync_relay_group_membership = AsyncMock(return_value={"enabled": True})
                db.insert_paired_device(
                    "peer-y",
                    "Other-PC",
                    "hash-y",
                    trust_tier="owner",
                    network_id="SNW-NET-99887766",
                    relationship="external_network",
                )
                prop = db.propose_network_merge(
                    tx_id="mtx-1",
                    source_network_id="SNW-NET-A1B2C3D4",
                    target_network_id="SNW-NET-99887766",
                    surviving_network_id="SNW-NET-A1B2C3D4",
                    source_owner_device_id="peer-y",
                    target_owner_device_id=core3.device_identity.device_id,
                )
                db.approve_network_merge(prop["tx_id"], "peer-y")
                owner_tok = hmac.new(
                    core3.ipc_server._secret.encode("utf-8"),
                    b"SNOW_OWNER_AUTHORIZATION",
                    hashlib.sha256,
                ).hexdigest()
                ipc_res, _ = await core3.ipc_server._dispatch_request(
                    {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": "r-merge",
                        "op": "resolve_network_merge",
                        "owner_token": owner_tok,
                        "payload": {"tx_id": prop["tx_id"], "decision": "merge"},
                    },
                    True,
                )
                self.assertTrue(ipc_res["success"], msg=f"resolve_network_merge failed: {ipc_res}")
                self.assertTrue(ipc_res["data"]["committed"])
                core3.resync_relay_group_membership.assert_awaited()
            finally:
                if old_data_dir is None:
                    os.environ.pop("SNOW_DATA_DIR", None)
                else:
                    os.environ["SNOW_DATA_DIR"] = old_data_dir


class TestM46DiscoveryRendezvousPairingAndUsb(unittest.IsolatedAsyncioTestCase):
    """Requirements 3 & 4: Canonical SNOW ID discovery, 2-step resolution, rendezvous pairing, and USB appops."""

    async def test_discovery_broadcasts_canonical_snow_id_and_alias_lookup(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old_data_dir = os.environ.get("SNOW_DATA_DIR")
            os.environ["SNOW_DATA_DIR"] = tmpdir
            try:
                dev_id = _make_identity("Win-Beacon")
                expected_snow, _ = resolve_canonical_device_snow_id(fallback_identity=dev_id)
                svc = SnowDiscoveryService(config=CoreConfig(), device_identity=dev_id, cert_fingerprint="AA" * 32)
                beacon = svc._create_beacon()
                self.assertEqual(beacon.snow_id, expected_snow)

                # Legacy alias lookup works in IPC list_discovered_peers
                peer_mock = MagicMock()
                peer_mock.device_id = "peer-alias-1"
                peer_mock.device_name = "Alias Phone"
                peer_mock.device_type = "android"
                peer_mock.snow_id = "SNW-CANO-1234"
                peer_mock.ip_address = "192.168.1.55"
                peer_mock.port = 8765
                peer_mock.transfer_port = 8766
                peer_mock.cert_fingerprint = "CC" * 32
                peer_mock.is_paired = False
                disc_mock = MagicMock()
                disc_mock.list_discovered_peers.return_value = [peer_mock]
                core_stub = MagicMock()
                core_stub.discovery_service = disc_mock
                ipc = SnowIpcServer(core_server=core_stub, config=CoreConfig())

                legacy_snow = generate_snow_id(seed="peer-alias-1").upper()
                res, _ = await ipc._dispatch_request(
                    {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": "req-alias",
                        "op": "list_discovered_peers",
                        "payload": {"snow_id": legacy_snow},
                    },
                    True,
                )
                self.assertTrue(res["success"])
                self.assertEqual(len(res["data"]["peers"]), 1)
                self.assertEqual(res["data"]["peers"][0]["snow_id"], "SNW-CANO-1234")

                with patch("snow.security.identity.resolve_canonical_device_snow_id", side_effect=RuntimeError("boom")):
                    beacon_fb = svc._create_beacon()
                    self.assertEqual(beacon_fb.snow_id, dev_id.snow_id)
            finally:
                if old_data_dir is None:
                    os.environ.pop("SNOW_DATA_DIR", None)
                else:
                    os.environ["SNOW_DATA_DIR"] = old_data_dir

    async def test_web_connect_peer_two_step_resolve_pin_errors_and_rendezvous_e2e(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old_data_dir = os.environ.get("SNOW_DATA_DIR")
            os.environ["SNOW_DATA_DIR"] = tmpdir
            try:
                with patch.dict("os.environ", {"SNOW_ALLOW_DEV_HUB_HTTP": "1"}, clear=False):
                    relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="m46-e2e"))
                    await relay.start()
                    try:
                        relay_port = int(relay._site._server.sockets[0].getsockname()[1])
                        hub_base = f"http://127.0.0.1:{relay_port}"
                        host_dir = Path(tmpdir) / "host"
                        cli_dir = Path(tmpdir) / "client"
                        host_dir.mkdir()
                        cli_dir.mkdir()

                        host_uuid = str(uuid.uuid4())
                        cli_uuid = str(uuid.uuid4())
                        db_host = DatabaseManager(host_dir / "host.db")
                        cert_h = host_dir / "h.crt"
                        key_h = host_dir / "h.key"
                        generate_self_signed_cert(cert_h, key_h, common_name="host-pc-1")

                        os.environ["SNOW_DATA_DIR"] = str(host_dir)
                        host_ident = _make_identity("Host-PC", device_id=host_uuid)
                        host_cfg = CoreConfig(
                            port=_free_port(),
                            transfer_port=_free_port(),
                            ipc_port=_free_port(),
                            relay_enabled=True,
                            relay_url=hub_base,
                            tls_cert_path=str(cert_h),
                            tls_key_path=str(key_h),
                        )
                        host_core = SnowCoreServer(config=host_cfg, db_manager=db_host, device_identity=host_ident)
                        host_key = load_or_create_device_key_identity()
                        await host_core.ws_server.start()
                        host_core.relay_enabled = True
                        with patch("snow.core.config.resolve_default_hub_url", return_value=hub_base):
                            await host_core.configure_relay(
                                enabled=True, relay_url=f"ws://127.0.0.1:{relay_port}/v1/tunnel"
                            )
                            pin_code = host_core.ws_server.pairing_manager.generate_pin()
                            rdv_id = await host_core.open_rendezvous_for_pairing(
                                pin=pin_code, ttl_seconds=60, await_sync=True
                            )
                            self.assertTrue(rdv_id)

                        # Switch to client environment & connect remotely via Render Hub rendezvous
                        os.environ["SNOW_DATA_DIR"] = str(cli_dir)
                        db_cli = DatabaseManager(cli_dir / "client.db")
                        cert_c = cli_dir / "c.crt"
                        key_c = cli_dir / "c.key"
                        generate_self_signed_cert(cert_c, key_c, common_name="client-pc-2")
                        cli_ident = _make_identity("Client-PC", device_id=cli_uuid)
                        cli_cfg = CoreConfig(
                            port=_free_port(),
                            transfer_port=_free_port(),
                            ipc_port=_free_port(),
                            relay_enabled=True,
                            relay_url=hub_base,
                            tls_cert_path=str(cert_c),
                            tls_key_path=str(key_c),
                        )
                        cli_core = SnowCoreServer(config=cli_cfg, db_manager=db_cli, device_identity=cli_ident)

                        with patch("snow.core.config.resolve_default_hub_url", return_value=hub_base):
                            fake_bridge = MagicMock()
                            fake_bridge.capability_engine = cli_core.capability_engine
                            fake_bridge.list_devices = AsyncMock(return_value={"success": True, "data": {"devices": []}})

                            async def _bridge_call(op, payload=None, timeout=10.0):
                                owner_tok = hmac.new(
                                    cli_core.ipc_server._secret.encode("utf-8"),
                                    b"SNOW_OWNER_AUTHORIZATION",
                                    hashlib.sha256,
                                ).hexdigest()
                                resp, _ = await cli_core.ipc_server._dispatch_request(
                                    {
                                        "version": IPC_PROTOCOL_VERSION,
                                        "request_id": "req-1",
                                        "op": op,
                                        "owner_token": owner_tok,
                                        "payload": payload or {},
                                    },
                                    True,
                                )
                                return resp

                            fake_bridge.call = _bridge_call
                            fake_bridge.mesh_connect_peer = AsyncMock(side_effect=cli_core.connect_peer)

                            web_srv = SnowWebServer(bridge=fake_bridge)
                            web_srv.db_manager = db_cli
                            app = web_srv._build_app()
                            web_client = TestClient(TestServer(app))
                            await web_client.start_server()
                            try:
                                web_srv.port = int(web_client.port)
                                sess_resp = await web_client.post(
                                    "/api/auth/session",
                                    json={"token": web_srv.bootstrap_token},
                                )
                                self.assertEqual(sess_resp.status, 200)
                                csrf = (await sess_resp.json())["csrf_token"]

                                # 1. Invalid SNOW ID -> 400 INVALID_SNOW_ID
                                bad_id = await web_client.post(
                                    "/api/devices/connect-peer",
                                    headers={"X-CSRF-Token": csrf},
                                    json={"step": "resolve", "snow_id": "BAD"},
                                )
                                self.assertEqual(bad_id.status, 400)
                                self.assertEqual((await bad_id.json())["status"], "INVALID_SNOW_ID")

                                # 2. step == "resolve" finds host on Render Hub -> requires_pin=True
                                step1 = await web_client.post(
                                    "/api/devices/connect-peer",
                                    headers={"X-CSRF-Token": csrf},
                                    json={"step": "resolve", "snow_id": host_key.snow_id},
                                )
                                self.assertEqual(step1.status, 200)
                                step1_body = await step1.json()
                                self.assertTrue(step1_body["success"])
                                self.assertTrue(step1_body["requires_pin"])
                                self.assertEqual(step1_body["source"], "render_hub")

                                # 3. Wrong PIN -> HTTP 400 INVALID_PIN + remaining_attempts
                                wrong_pin = "000000" if pin_code != "000000" else "999999"
                                bad_pin_resp = await web_client.post(
                                    "/api/devices/connect-peer",
                                    headers={"X-CSRF-Token": csrf},
                                    json={"snow_id": host_key.snow_id, "pin": wrong_pin},
                                )
                                self.assertEqual(bad_pin_resp.status, 400)
                                bad_pin_body = await bad_pin_resp.json()
                                self.assertEqual(bad_pin_body["status"], "INVALID_PIN")
                                self.assertIn("remaining_attempts", bad_pin_body)
                                self.assertIn("Incorrect PIN", bad_pin_body["error"])

                                # 4. Correct PIN -> completes full Render Hub E2E TLS tunnel pairing!
                                os.environ["SNOW_DATA_DIR"] = str(cli_dir)
                                good_resp = await web_client.post(
                                    "/api/devices/connect-peer",
                                    headers={"X-CSRF-Token": csrf},
                                    json={"snow_id": host_key.snow_id, "pin": pin_code},
                                )
                                self.assertEqual(good_resp.status, 200)
                                good_body = await good_resp.json()
                                self.assertTrue(good_body["success"], msg=f"Pairing failed: {good_body}")
                                paired_rec = db_cli.get_paired_device(host_uuid)
                                self.assertIsNotNone(paired_rec)
                                self.assertTrue(paired_rec.cert_fingerprint)

                                # 5. Re-resolving already paired peer -> zero PIN, auto-reconnects
                                fake_bridge.list_devices = AsyncMock(
                                    return_value={
                                        "success": True,
                                        "data": {"devices": [{"device_id": host_uuid, "snow_id": host_key.snow_id, "is_connected": True}]},
                                    }
                                )
                                already = await web_client.post(
                                    "/api/devices/connect-peer",
                                    headers={"X-CSRF-Token": csrf},
                                    json={"step": "resolve", "snow_id": host_key.snow_id},
                                )
                                self.assertEqual(already.status, 200)
                                already_body = await already.json()
                                self.assertTrue(already_body["success"], msg=f"already_body: {already_body}")
                                self.assertTrue(already_body.get("already_paired"), msg=f"already_body: {already_body}")
                                self.assertEqual(already_body["status"], "CONNECTED")
                            finally:
                                if web_srv._http_session and not web_srv._http_session.closed:
                                    await web_srv._http_session.close()
                                await web_client.close()
                        await host_core.stop()
                        await cli_core.stop()
                    finally:
                        await relay.stop()
            finally:
                if old_data_dir is None:
                    os.environ.pop("SNOW_DATA_DIR", None)
                else:
                    os.environ["SNOW_DATA_DIR"] = old_data_dir

    async def test_usb_unlock_android_permissions_includes_restricted_settings_safely(self):
        import subprocess
        calls = []

        def _fake_run(cmd, *args, **kwargs):
            self.assertFalse(kwargs.get("shell", False))
            calls.append(list(cmd))
            cmd_str = " ".join(cmd)
            if "ACCESS_RESTRICTED_SETTINGS" in cmd_str:
                return subprocess.CompletedProcess(
                    args=cmd, returncode=1, stdout="", stderr="Unknown operation ACCESS_RESTRICTED_SETTINGS"
                )
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

        with patch("snow.core.usb.find_adb_binary", return_value=Path("C:/adb/adb.exe")), patch(
            "snow.core.usb.get_connected_adb_devices",
            return_value=[{"serial": "SERIAL123", "status": "device", "model": "Pixel"}],
        ), patch("subprocess.run", side_effect=_fake_run):
            res = unlock_android_permissions(serial="SERIAL123", package_name="org.snow")
            self.assertTrue(res["success"])
            restricted_cmds = [c for c in calls if "ACCESS_RESTRICTED_SETTINGS" in c]
            self.assertEqual(len(restricted_cmds), 1)
            self.assertEqual(
                restricted_cmds[0],
                ["C:\\adb\\adb.exe", "-s", "SERIAL123", "shell", "appops", "set", "org.snow", "ACCESS_RESTRICTED_SETTINGS", "allow"],
            )
            step_item = [s for s in res["skipped"] if s["permission"] == "Restricted Settings Access"][0]
            self.assertEqual(step_item["permission"], "Restricted Settings Access")

    async def test_acquire_relay_hub_session_uses_device_key_and_ws_resync_triggers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            old_data_dir = os.environ.get("SNOW_DATA_DIR")
            os.environ["SNOW_DATA_DIR"] = tmpdir
            try:
                db = DatabaseManager(Path(tmpdir) / "hub.db")
                # Poison network_key.json with a stale self-generated network to prove it NEVER overrides shared active_net
                stale_net_key = load_or_create_network_key_identity(data_dir=tmpdir)
                dev_key = load_or_create_device_key_identity(data_dir=tmpdir)
                relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="m46-sec"))
                await relay.start()
                try:
                    relay_port = int(relay._site._server.sockets[0].getsockname()[1])
                    hub_http = f"http://127.0.0.1:{relay_port}"
                    cfg = CoreConfig(
                        port=_free_port(),
                        transfer_port=_free_port(),
                        ipc_port=_free_port(),
                        relay_url=hub_http,
                    )
                    core = SnowCoreServer(config=cfg, db_manager=db)

                    # Standalone -> empty network_id, device key identity (NOT stale_net_key.network_id)
                    ok1, tok1, net1, err1 = await core._acquire_relay_hub_session(hub_http)
                    self.assertTrue(ok1, msg=err1)
                    self.assertEqual(net1, "")
                    self.assertTrue(tok1.startswith("shs1_"))

                    # Shared DB active network -> uses shared active_net["network_id"], never network_key.json
                    shared_net = "SNW-NET-11223344"
                    self.assertNotEqual(shared_net, stale_net_key.network_id)
                    db.ensure_active_network("Shared Net", core.device_identity.device_id, network_id=shared_net)
                    ok2, tok2, net2, err2 = await core._acquire_relay_hub_session(hub_http)
                    self.assertTrue(ok2, msg=err2)
                    self.assertEqual(net2, shared_net)
                    self.assertTrue(tok2.startswith("shs1_"))

                    # ws_server._handle_pairing_request & _handle_network_merge_decision invoke resync_relay_group_membership
                    core.relay_enabled = True
                    core.resync_relay_group_membership = AsyncMock(return_value={"enabled": True})
                    pin_val = core.ws_server.pairing_manager.generate_pin()
                    fake_ws = AsyncMock()
                    fake_client = MagicMock()
                    fake_client.connection_id = "ws-lan-1"
                    fake_client.remote_address = ("192.168.1.99", 55555)
                    fake_client.websocket = fake_ws
                    peer_uuid = str(uuid.uuid4())
                    pair_req = SnowMessage.create_request(
                        action="pair_request",
                        data={
                            "device_id": peer_uuid,
                            "device_name": "Peer-LAN",
                            "pin": pin_val,
                            "device_type": "android",
                            "cert_fingerprint": "DD" * 32,
                            "client_network_id": shared_net,
                        },
                    )
                    await core.ws_server._handle_pairing_request(fake_client, pair_req, "pair_request", pair_req.data)
                    core.resync_relay_group_membership.assert_awaited()

                    # Test _handle_network_merge_decision commit triggers resync
                    core.resync_relay_group_membership.reset_mock()
                    peer_merge_uuid = str(uuid.uuid4())
                    db.insert_paired_device(
                        peer_merge_uuid,
                        "Peer-Owner",
                        "hash-o",
                        trust_tier="owner",
                        network_id="SNW-NET-55667788",
                        relationship="external_network",
                    )
                    prop = db.propose_network_merge(
                        tx_id="mtx-ws-1",
                        source_network_id=shared_net,
                        target_network_id="SNW-NET-55667788",
                        surviving_network_id=shared_net,
                        source_owner_device_id=core.device_identity.device_id,
                        target_owner_device_id=peer_merge_uuid,
                    )
                    db.approve_network_merge(prop["tx_id"], core.device_identity.device_id)
                    session_obj = MagicMock()
                    session_obj.device_id = peer_merge_uuid
                    core.ws_server.session_manager.get_session_by_connection = MagicMock(return_value=session_obj)
                    merge_msg = SnowMessage.create_request(
                        action="network_merge_decision",
                        data={"tx_id": prop["tx_id"], "decision": "merge"},
                    )
                    await core.ws_server._handle_network_merge_decision(
                        fake_client, merge_msg, merge_msg.data, session_obj
                    )
                    core.resync_relay_group_membership.assert_awaited_once()
                finally:
                    await relay.stop()
            finally:
                if old_data_dir is None:
                    os.environ.pop("SNOW_DATA_DIR", None)
                else:
                    os.environ["SNOW_DATA_DIR"] = old_data_dir

    async def test_web_connect_peer_lan_resolve_and_pin_expired_locked_status_400(self):
        bridge = MagicMock()
        bridge.list_devices = AsyncMock(return_value={"success": True, "data": {"devices": []}})

        async def _fake_call(op, payload=None, timeout=5.0):
            if op == "list_discovered_peers":
                return {
                    "success": True,
                    "data": {
                        "peers": [
                            {
                                "device_id": "lan-phone-1",
                                "device_name": "LAN Pixel",
                                "device_type": "android",
                                "snow_id": "SNW-LAN1-2233",
                                "host": "192.168.1.44",
                                "port": 8765,
                                "cert_fingerprint": "EE" * 32,
                                "is_paired": False,
                            }
                        ]
                    },
                }
            return {"success": False}

        bridge.call = _fake_call
        web_srv = SnowWebServer(bridge=bridge)
        app = web_srv._build_app()
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            web_srv.port = int(client.port)
            sess_resp = await client.post("/api/auth/session", json={"token": web_srv.bootstrap_token})
            self.assertEqual(sess_resp.status, 200)
            csrf = (await sess_resp.json())["csrf_token"]

            # LAN step == "resolve" -> requires_pin=True with LAN host & port
            r_lan = await client.post(
                "/api/devices/connect-peer",
                headers={"X-CSRF-Token": csrf},
                json={"step": "resolve", "snow_id": "SNW-LAN1-2233"},
            )
            self.assertEqual(r_lan.status, 200)
            lan_body = await r_lan.json()
            self.assertTrue(lan_body["requires_pin"])
            self.assertEqual(lan_body["source"], "lan_discovery")
            self.assertEqual(lan_body["host"], "192.168.1.44")

            # PIN_EXPIRED -> HTTP 400
            bridge.mesh_connect_peer = AsyncMock(
                return_value={"success": False, "status": "PIN_EXPIRED", "error": "Pairing PIN has expired."}
            )
            r_exp = await client.post(
                "/api/devices/connect-peer",
                headers={"X-CSRF-Token": csrf},
                json={"host": "192.168.1.44", "pin": "111111"},
            )
            self.assertEqual(r_exp.status, 400)
            self.assertEqual((await r_exp.json())["status"], "PIN_EXPIRED")

            # PAIRING_LOCKED -> HTTP 400 with remaining_attempts=0
            bridge.mesh_connect_peer = AsyncMock(
                return_value={"success": False, "status": "PAIRING_LOCKED", "error": "Too many failed attempts; locked."}
            )
            r_lock = await client.post(
                "/api/devices/connect-peer",
                headers={"X-CSRF-Token": csrf},
                json={"host": "192.168.1.44", "pin": "111111"},
            )
            self.assertEqual(r_lock.status, 400)
            lock_body = await r_lock.json()
            self.assertEqual(lock_body["status"], "PAIRING_LOCKED")
            self.assertEqual(lock_body["remaining_attempts"], 0)
        finally:
            await client.close()


if __name__ == "__main__":
    unittest.main()
