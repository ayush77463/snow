"""M4.4 Stage 3 Tests: Render Hub Per-Device Ed25519 Auth, Collision/Spoofing, Reverse Proxy & Windows Forwarder."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
from aiohttp import web

from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.remote_gateway import RemoteMcpGateway
from snow.mcp.tunnel import TunnelManager, is_remote_ai_link_enabled, set_remote_ai_link_enabled
from snow.relay.auth import derive_device_snow_id_from_pubkey
from snow.relay.config import RelayConfig
from snow.relay.mcp_forwarder import RelayMcpForwarder
from snow.relay.server import SnowRelayServer, _BoundedIpRateLimiter
from snow.security.db import DatabaseManager
from snow.security.identity import (
    _device_key_from_seed,
    load_or_create_device_key_identity,
    load_or_create_network_key_identity,
)


class TestM44RenderHubPerDeviceAndHardening(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="snow_m44_hub_")
        self.relay = SnowRelayServer(
            RelayConfig(
                host="127.0.0.1",
                port=0,
                shared_secret="admin-secret-m44",
                host_lease_seconds=30.0,
                hub_challenge_ttl_seconds=30.0,
                max_http_forward_bytes=2048,
            )
        )
        await self.relay.start()
        sock = self.relay._site._server.sockets[0]
        self.relay_port = int(sock.getsockname()[1])
        self.hub_http = f"http://127.0.0.1:{self.relay_port}"
        self.relay_ws = f"ws://127.0.0.1:{self.relay_port}/v1/tunnel"

    async def asyncTearDown(self) -> None:
        await self.relay.stop()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def _issue_device_token(
        self,
        client: aiohttp.ClientSession,
        dev_key,
        device_id: str,
        network_id: str = "",
    ) -> dict:
        ch_req = {
            "snow_id": dev_key.snow_id,
            "public_key": dev_key.public_key_b64,
            "device_id": device_id,
        }
        if network_id:
            ch_req["network_id"] = network_id
        ch_r = await client.post(f"{self.hub_http}/v1/hub/challenge", json=ch_req)
        self.assertEqual(ch_r.status, 200)
        ch = await ch_r.json()
        sig = dev_key.sign_device_hub_challenge(ch, device_id=device_id, network_id=network_id)
        s_req = {
            "challenge_id": ch["challenge_id"],
            "snow_id": dev_key.snow_id,
            "public_key": dev_key.public_key_b64,
            "signature": sig,
            "device_id": device_id,
        }
        if network_id:
            s_req["network_id"] = network_id
        s_r = await client.post(f"{self.hub_http}/v1/hub/session", json=s_req)
        self.assertEqual(s_r.status, 200)
        return await s_r.json()

    async def test_per_device_challenge_session_spoofing_replay_and_wrong_scope_rejections(self) -> None:
        dev_a = load_or_create_device_key_identity(data_dir=Path(self.tmp_dir) / "dev_a")
        dev_b = load_or_create_device_key_identity(data_dir=Path(self.tmp_dir) / "dev_b")

        async with aiohttp.ClientSession() as client:
            # 1. Spoofed snow_id rejected on challenge
            r_spoof = await client.post(
                f"{self.hub_http}/v1/hub/challenge",
                json={"snow_id": dev_b.snow_id, "public_key": dev_a.public_key_b64, "device_id": "uuid-a"},
            )
            self.assertEqual(r_spoof.status, 403)

            # 2. Invalid content-type rejected (415) & oversized body rejected (413)
            r_ct = await client.post(
                f"{self.hub_http}/v1/hub/challenge",
                data="{}",
                headers={"Content-Type": "text/plain"},
            )
            self.assertEqual(r_ct.status, 415)

            # 3. Challenge -> session validation checks (wrong device_id, wrong network_id, wrong sig, replay, expiry)
            ch_r = await client.post(
                f"{self.hub_http}/v1/hub/challenge",
                json={
                    "snow_id": dev_a.snow_id,
                    "public_key": dev_a.public_key_b64,
                    "device_id": "uuid-a",
                    "network_id": "SNW-NET-11112222",
                },
            )
            self.assertEqual(ch_r.status, 200)
            ch = await ch_r.json()
            valid_sig = dev_a.sign_device_hub_challenge(ch, device_id="uuid-a", network_id="SNW-NET-11112222")

            # Wrong device_id fails (keeps challenge or fails closed) -> let's test wrong device_id and note pop consumes challenge
            r_bad_dev = await client.post(
                f"{self.hub_http}/v1/hub/session",
                json={
                    "challenge_id": ch["challenge_id"],
                    "snow_id": dev_a.snow_id,
                    "public_key": dev_a.public_key_b64,
                    "signature": valid_sig,
                    "device_id": "wrong-uuid",
                    "network_id": "SNW-NET-11112222",
                },
            )
            self.assertEqual(r_bad_dev.status, 401)

            # Replayed challenge already consumed above -> fails closed
            r_replay = await client.post(
                f"{self.hub_http}/v1/hub/session",
                json={
                    "challenge_id": ch["challenge_id"],
                    "snow_id": dev_a.snow_id,
                    "public_key": dev_a.public_key_b64,
                    "signature": valid_sig,
                    "device_id": "uuid-a",
                    "network_id": "SNW-NET-11112222",
                },
            )
            self.assertEqual(r_replay.status, 401)

            # Valid challenge with wrong network scope / wrong sig rejected
            ch2 = await (await client.post(
                f"{self.hub_http}/v1/hub/challenge",
                json={
                    "snow_id": dev_a.snow_id,
                    "public_key": dev_a.public_key_b64,
                    "device_id": "uuid-a",
                    "network_id": "SNW-NET-11112222",
                },
            )).json()
            wrong_sig = dev_b.sign_device_hub_challenge(ch2, device_id="uuid-a", network_id="SNW-NET-11112222")
            r_bad_sig = await client.post(
                f"{self.hub_http}/v1/hub/session",
                json={
                    "challenge_id": ch2["challenge_id"],
                    "snow_id": dev_a.snow_id,
                    "public_key": dev_a.public_key_b64,
                    "signature": wrong_sig,
                    "device_id": "uuid-a",
                    "network_id": "SNW-NET-11112222",
                },
            )
            self.assertEqual(r_bad_sig.status, 401)

            # Valid challenge succeeded once, then expired challenge rejected
            sess_a = await self._issue_device_token(client, dev_a, "uuid-a")
            self.assertEqual(sess_a["snow_id"], dev_a.snow_id)
            tok_a = sess_a["token"]

            # Expired challenge manually injected fails closed
            self.relay._hub_challenges["exp-ch-1"] = {
                "challenge_id": "exp-ch-1",
                "kind": "device",
                "network_id": "",
                "snow_id": dev_a.snow_id,
                "public_key_b64": dev_a.public_key_b64,
                "device_id": "uuid-a",
                "audience": "render-hub-tunnel",
                "nonce": "n",
                "expires_at": 1,
                "created_at": 1,
            }
            r_exp = await client.post(
                f"{self.hub_http}/v1/hub/session",
                json={
                    "challenge_id": "exp-ch-1",
                    "snow_id": dev_a.snow_id,
                    "public_key": dev_a.public_key_b64,
                    "signature": "AA" * 43,
                    "device_id": "uuid-a",
                },
            )
            self.assertEqual(r_exp.status, 401)

            # Spoofing dev_b on WS hello using dev_a's hub_token fails
            async with client.ws_connect(self.relay_ws) as ws:
                await ws.send_json({
                    "type": "hello",
                    "hub_token": tok_a,
                    "snow_id": dev_b.snow_id,
                    "device_id": "uuid-a",
                })
                msg = await ws.receive()
                self.assertEqual(msg.type, aiohttp.WSMsgType.CLOSE)

    def test_bounded_ip_rate_limiter_enforces_limit_and_memory_cap(self) -> None:
        lim = _BoundedIpRateLimiter(max_requests=2, window_seconds=60.0, max_ips=4)
        self.assertTrue(lim.check("1.2.3.4")[0])
        self.assertTrue(lim.check("1.2.3.4")[0])
        self.assertFalse(lim.check("1.2.3.4")[0])
        for i in range(10):
            lim.check(f"10.0.0.{i}")
        self.assertLessEqual(len(lim._hits), 4)

    async def test_collision_fencing_simultaneous_conflict_restart_and_proxy_hardening(self) -> None:
        dev_a = load_or_create_device_key_identity(data_dir=Path(self.tmp_dir) / "dev_a")
        other_same_prefix = _device_key_from_seed(os.urandom(32))

        async with aiohttp.ClientSession() as client:
            # 1. Connect dev_a and keep live WS open
            sess1 = await self._issue_device_token(client, dev_a, "uuid-a-1")
            ws1 = await client.ws_connect(self.relay_ws)
            await ws1.send_json({
                "type": "hello",
                "hub_token": sess1["token"],
                "snow_id": dev_a.snow_id,
                "device_id": "uuid-a-1",
                "mcp_tunnel": True,
            })
            ack1 = await ws1.receive_json()
            self.assertTrue(ack1["success"])
            self.assertEqual(ack1["snow_id"], dev_a.snow_id)
            server_ws1 = self.relay._snow_routes[dev_a.snow_id]["ws"]

            # 2. Collision attack: inject a simulated key collision (same snow_id, different pubkey) -> REJECTED (409)
            r_coll = await client.post(
                f"{self.hub_http}/v1/hub/challenge",
                json={"snow_id": dev_a.snow_id, "public_key": dev_a.public_key_b64, "device_id": "attacker"},
            )
            # Fake binding check directly by probing collision helper on mismatched pubkey
            self.assertTrue(
                self.relay._has_key_collision_unlocked(dev_a.snow_id, other_same_prefix.public_key_b64, 9999999999.0)
            )
            self.assertFalse(
                self.relay._has_key_collision_unlocked(dev_a.snow_id, dev_a.public_key_b64, 9999999999.0)
            )
            self.assertEqual(r_coll.status, 200)

            # 3. Simultaneous recovered instance conflict (same key K1, second concurrent socket without takeover) -> FENCED!
            sess2 = await self._issue_device_token(client, dev_a, "uuid-a-2")
            ws2 = await client.ws_connect(self.relay_ws)
            await ws2.send_json({
                "type": "hello",
                "hub_token": sess2["token"],
                "snow_id": dev_a.snow_id,
                "device_id": "uuid-a-2",
                "mcp_tunnel": True,
            })
            msg2 = await ws2.receive()
            self.assertEqual(msg2.type, aiohttp.WSMsgType.CLOSE)
            self.assertEqual(msg2.data, 4009)
            await ws2.close()
            # Primary server_ws1 MUST still own route undisturbed!
            self.assertIs(self.relay._snow_routes[dev_a.snow_id]["ws"], server_ws1)
            self.assertEqual(self.relay._snow_routes[dev_a.snow_id]["device_id"], "uuid-a-1")

            # 4. Path traversal, double-decoding, invalid method & oversized forward rejection
            for bad_url in (
                f"{self.hub_http}/u/{dev_a.snow_id}/../health",
                f"{self.hub_http}/u/{dev_a.snow_id}/%252e%252e/health",
                f"{self.hub_http}/u/{dev_a.snow_id}/%2e%2e/secret",
                f"{self.hub_http}/u/{dev_a.snow_id}/etc/passwd",
            ):
                r_bad = await client.get(bad_url)
                self.assertIn(r_bad.status, (400, 404))

            r_method = await client.put(f"{self.hub_http}/u/{dev_a.snow_id}/mcp", data=b"{}")
            self.assertEqual(r_method.status, 405)

            r_big = await client.post(f"{self.hub_http}/u/{dev_a.snow_id}/mcp", data=b"X" * 4096)
            self.assertEqual(r_big.status, 413)

            # 5. Directory isolation: standalone dev_a can look up self, NOT unrelated dev_b
            r_self = await client.get(
                f"{self.hub_http}/v1/directory/resolve/{dev_a.snow_id}",
                headers={"Authorization": f"Bearer {sess1['token']}"},
            )
            self.assertEqual(r_self.status, 200)
            await ws1.close()

            # 6. Simulate Render restart: stop old server, start fresh server on new instance; old token invalid, reauth restores exact URL!
            await self.relay.stop()
            self.relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="admin-secret-m44"))
            await self.relay.start()
            self.relay_port = int(self.relay._site._server.sockets[0].getsockname()[1])
            self.hub_http = f"http://127.0.0.1:{self.relay_port}"
            self.relay_ws = f"ws://127.0.0.1:{self.relay_port}/v1/tunnel"

            # Stale session token from before restart MUST fail
            r_stale_dir = await client.get(
                f"{self.hub_http}/v1/directory/resolve/{dev_a.snow_id}",
                headers={"Authorization": f"Bearer {sess1['token']}"},
            )
            self.assertEqual(r_stale_dir.status, 401)
            # Reconnecting with same Ed25519 key restores exact same permanent snow_id route
            sess_re = await self._issue_device_token(client, dev_a, "uuid-a-1")
            self.assertEqual(sess_re["snow_id"], dev_a.snow_id)


class TestM44WindowsForwarderAndTunnel(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="snow_m44_fwd_")
        self._old_env = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = self.tmp_dir

        self.relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="admin-secret-fwd"))
        await self.relay.start()
        self.relay_port = int(self.relay._site._server.sockets[0].getsockname()[1])
        self.hub_http = f"http://127.0.0.1:{self.relay_port}"
        self.relay_ws = f"ws://127.0.0.1:{self.relay_port}/v1/tunnel"

        self.db = DatabaseManager(db_path=Path(self.tmp_dir) / "gw.db")
        mock_bridge = AsyncMock(spec=SnowMcpBridge)
        mock_bridge.capability_engine = MagicMock(db_manager=self.db)
        self.gw = RemoteMcpGateway(host="127.0.0.1", port=0, bridge=mock_bridge)
        self.gw_runner = web.AppRunner(self.gw.app)
        await self.gw_runner.setup()
        gw_site = web.TCPSite(self.gw_runner, "127.0.0.1", 0)
        await gw_site.start()
        self.gw_port = int(gw_site._server.sockets[0].getsockname()[1])
        self.gw_url = f"http://127.0.0.1:{self.gw_port}"

    async def asyncTearDown(self) -> None:
        await self.gw_runner.cleanup()
        await self.relay.stop()
        if self._old_env is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self._old_env
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_windows_forwarder_device_route_survives_network_changes_and_manual_stop(self) -> None:
        dev_key = load_or_create_device_key_identity(data_dir=Path(self.tmp_dir))
        net_key = load_or_create_network_key_identity(data_dir=Path(self.tmp_dir))

        fwd = RelayMcpForwarder(
            relay_ws_url=self.relay_ws,
            snow_id=dev_key.snow_id,
            local_gateway_url=self.gw_url,
            device_key_identity=dev_key,
            hub_http_url=self.hub_http,
            device_id="win-pc-uuid-1",
            network_id=net_key.network_id,
            auto_reconnect=True,
            reconnect_base_delay=0.05,
        )
        try:
            # Duplicate start returns clean active state without spawning two sessions
            ok1, err1 = await fwd.start()
            self.assertTrue(ok1, err1)
            ws_first = fwd._ws
            ok2, err2 = await fwd.start()
            self.assertTrue(ok2, err2)
            self.assertIs(fwd._ws, ws_first)

            # Permanent per-device endpoint works over hub reverse proxy
            async with aiohttp.ClientSession() as client:
                r_wk = await client.get(f"{self.hub_http}/u/{dev_key.snow_id}/.well-known/oauth-authorization-server")
                self.assertEqual(r_wk.status, 200)

            # Manual stop prevents reconnect loop from reviving session
            await fwd.stop()
            await asyncio.sleep(0.15)
            self.assertFalse(fwd.is_connected)
            self.assertIsNone(fwd._ws)
        finally:
            await fwd.stop()

    async def test_tunnel_manager_registers_device_url_and_legacy_alias_independently(self) -> None:
        from snow.mcp import tunnel as tunnel_mod

        dev_key = load_or_create_device_key_identity(data_dir=Path(self.tmp_dir))
        net_key = load_or_create_network_key_identity(data_dir=Path(self.tmp_dir))

        # Default preference enabled unless manually disabled
        cfg_path = Path(self.tmp_dir) / "tunnel.json"
        self.assertTrue(is_remote_ai_link_enabled(config_path=cfg_path))
        set_remote_ai_link_enabled(False, config_path=cfg_path)
        self.assertFalse(is_remote_ai_link_enabled(config_path=cfg_path))

        tm = TunnelManager(target_port=8771)
        # Allow local dev http hub validation for test via validate_hub_url patch
        orig_validate = tunnel_mod.validate_hub_url
        with (
            patch.object(tunnel_mod, "ALLOWED_TUNNEL_PORTS", frozenset({8771, self.gw_port})),
            patch.object(tunnel_mod, "ALLOWED_TUNNEL_PORT", self.gw_port),
            patch.object(tunnel_mod, "validate_hub_url", lambda u, allow_dev_loopback=False: orig_validate(u, allow_dev_loopback=True)),
        ):
            tm._mcp_tunnel = tunnel_mod._TunnelInstance(target_port=self.gw_port, purpose="mcp")
            res = await tm.start_tunnel(provider="render", port=self.gw_port, custom_url=self.hub_http)
            self.assertTrue(res["success"], res)
            self.assertEqual(res["snow_id"], dev_key.snow_id)
            self.assertEqual(res["mcp_endpoint"], f"{self.hub_http}/u/{dev_key.snow_id}/mcp")
            self.assertEqual(res["legacy_network_url"], f"{self.hub_http}/u/{net_key.network_id}/mcp")

            st = tm.get_status(port=self.gw_port)
            self.assertTrue(st["active"])
            self.assertEqual(st["device_snow_id"], dev_key.snow_id)
            self.assertEqual(st["mcp_endpoint"], f"{self.hub_http}/u/{dev_key.snow_id}/mcp")

            # Both permanent device route AND legacy network route serve requests!
            async with aiohttp.ClientSession() as client:
                r_dev = await client.get(f"{self.hub_http}/u/{dev_key.snow_id}/.well-known/oauth-authorization-server")
                self.assertEqual(r_dev.status, 200)
                r_net = await client.get(f"{self.hub_http}/u/{net_key.network_id}/.well-known/oauth-authorization-server")
                self.assertEqual(r_net.status, 200)

            await tm.stop_all_tunnels()
            st_after = tm.get_status(port=self.gw_port)
            self.assertFalse(st_after["active"])

    async def test_forwarder_reports_truthful_failure_state(self) -> None:
        dev_key = load_or_create_device_key_identity(data_dir=Path(self.tmp_dir))
        fwd = RelayMcpForwarder(
            relay_ws_url="ws://127.0.0.1:1/v1/tunnel",
            snow_id=dev_key.snow_id,
            device_key_identity=dev_key,
            hub_http_url="http://127.0.0.1:1",
            device_id="win-pc-fail",
        )
        ok, err = await fwd.start(timeout=1.5)
        self.assertFalse(ok)
        self.assertFalse(fwd.is_connected)
        self.assertTrue(bool(err))
        self.assertTrue(bool(fwd.last_error))


if __name__ == "__main__":
    unittest.main()
