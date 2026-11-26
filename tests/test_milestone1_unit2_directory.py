"""Unit 1.2 Regression Tests: Authenticated SNOW ID Directory Resolution."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from aiohttp.test_utils import make_mocked_request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from snow.core.config import CoreConfig
from snow.core.ipc import IPC_PROTOCOL_VERSION, SnowIpcServer
from snow.core.server import SnowCoreServer
from snow.mcp.bridge import SnowMcpBridge
from snow.network.discovery import DiscoveredPeerRecord, SnowDiscoveryService
from snow.relay.config import RelayConfig
from snow.relay.mcp_forwarder import RelayMcpForwarder
from snow.relay.server import SnowRelayServer
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import DeviceIdentity, generate_snow_id, load_or_create_network_key_identity
from snow.web.server import SnowWebServer


class TestMilestone1Unit2DirectoryResolution(unittest.IsolatedAsyncioTestCase):
    """Verify local DB -> Core IPC LAN discovery -> Ed25519 authenticated hub resolution."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m1_u12_"))
        self.db = DatabaseManager(self.tmp_dir / "u12.db")
        self.local_ident = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Local-PC",
            created_at="2026-11-26T00:00:00Z",
            snow_id="SNW-AAAA-1111",
        )
        self.net_ident = load_or_create_network_key_identity(data_dir=self.tmp_dir / "net")
        self.cfg = CoreConfig(
            port=8765,
            ipc_port=0,
            transfer_port=0,
            discovery_enabled=False,
        )
        self.core = SnowCoreServer(
            config=self.cfg,
            device_identity=self.local_ident,
            db_manager=self.db,
        )
        self.core.discovery_service = SnowDiscoveryService(
            config=self.cfg,
            device_identity=self.local_ident,
        )
        self.ipc = SnowIpcServer(core_server=self.core, config=self.cfg)
        self.ipc._secret = "u12-ipc-secret"

        self.bridge = SnowMcpBridge(auto_start_core=False, is_owner_channel=True)
        self.bridge.capability_engine.db_manager = self.db

        async def _in_proc_ipc(op: str, payload=None, timeout: float = 10.0):
            req = {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": str(uuid.uuid4()),
                "op": op,
                "auth_token": self.ipc._secret,
                "payload": payload or {},
            }
            res, _ = await self.ipc._dispatch_request(req, is_connection_authenticated=True)
            return res

        self.bridge.call = AsyncMock(side_effect=_in_proc_ipc)
        self.web = SnowWebServer(host="127.0.0.1", port=0, bridge=self.bridge, auto_open_browser=False)
        self.web.db_manager = self.db

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_01_lan_udp_discovery_match_through_core_ipc(self) -> None:
        peer_id = str(uuid.uuid4())
        peer_snow = "SNW-LAN1-9988"
        self.core.discovery_service._discovered_peers[peer_id] = DiscoveredPeerRecord(
            device_id=peer_id,
            device_name="Buddy Laptop",
            device_type="windows",
            ip_address="192.168.1.44",
            port=8765,
            transfer_port=8766,
            cert_fingerprint="AA" * 32,
            last_seen_timestamp=time.time(),
            is_paired=False,
            snow_id=peer_snow,
        )

        with patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
             patch("snow.core.config.resolve_default_hub_url", return_value=""):
            res = await self.web._resolve_snow_id_directory(peer_snow.lower())

        self.assertTrue(res["found"], msg=f"Expected LAN discovery match, got: {res}")
        self.assertEqual(res["source"], "lan_discovery")
        self.assertEqual(res["device_id"], peer_id)
        self.assertEqual(res["host"], "192.168.1.44")
        self.assertEqual(res["port"], 8765)
        self.bridge.call.assert_called()

    async def test_02_existing_paired_database_match_short_circuits_before_hub(self) -> None:
        paired_id = str(uuid.uuid4())
        paired_snow = generate_snow_id(seed=paired_id)
        self.db.insert_paired_device(
            device_id=paired_id,
            device_name="Paired Phone",
            auth_token_hash=hash_token("tok-paired-123"),
            last_known_host="192.168.1.77",
            last_known_port=8765,
        )

        with patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
             patch("snow.core.config.resolve_default_hub_url", return_value="https://should-not-be-called.example"):
            res = await self.web._resolve_snow_id_directory(paired_snow)

        self.assertTrue(res["found"], msg=f"Expected LAN discovery match, got: {res}")
        self.assertEqual(res["source"], "paired_db")
        self.assertEqual(res["device_id"], paired_id)
        self.assertEqual(res["host"], "192.168.1.77")
        self.bridge.call.assert_not_called()

    async def test_03_04_authenticated_hub_directory_lookup_sends_bearer_token(self) -> None:
        relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="relay-u12-secret"))
        await relay.start()
        try:
            sock = relay._site._server.sockets[0]
            hub_port = int(sock.getsockname()[1])
            hub_http = f"http://127.0.0.1:{hub_port}"
            hub_ws = f"ws://127.0.0.1:{hub_port}/v1/tunnel"

            remote_id = str(uuid.uuid4())
            remote_snow = "SNW-REM1-2233"
            fwd = RelayMcpForwarder(
                relay_ws_url=hub_ws,
                snow_id=remote_snow,
                local_gateway_url="http://127.0.0.1:8771",
                network_key_identity=self.net_ident,
                hub_http_url=hub_http,
                device_id=remote_id,
                device_name="Remote Workstation",
                lan_endpoints=["10.20.30.40:8765"],
            )
            ok, err = await fwd.start(timeout=5.0)
            self.assertTrue(ok, msg=f"Forwarder failed starting: {err}")

            captured_auth_tokens: list[str] = []
            orig_auth_or_ctrl = relay._authenticate_hub_or_control

            def _spy_auth(request):
                captured_auth_tokens.append(request.headers.get("Authorization", ""))
                return orig_auth_or_ctrl(request)

            with patch.object(relay, "_authenticate_hub_or_control", side_effect=_spy_auth), \
                 patch.dict("os.environ", {"SNOW_ALLOW_DEV_HUB_HTTP": "1"}, clear=False), \
                 patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
                 patch("snow.security.identity.load_or_create_network_key_identity", return_value=self.net_ident), \
                 patch("snow.core.config.resolve_default_hub_url", return_value=hub_http):
                res = await self.web._resolve_snow_id_directory(remote_snow)

            await fwd.stop()

            self.assertTrue(res["found"], msg=f"Hub directory resolve failed: {res}")
            self.assertEqual(res["source"], "hub_directory")
            self.assertEqual(res["network_id"], self.net_ident.network_id)
            self.assertEqual(res["host"], "10.20.30.40")
            self.assertEqual(len(captured_auth_tokens), 1)
            self.assertTrue(captured_auth_tokens[0].startswith("Bearer shs1_"))
        finally:
            await relay.stop()

    async def test_05_unauthenticated_hub_resolution_fails_closed(self) -> None:
        relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="relay-u12-secret"))
        await relay.start()
        try:
            sock = relay._site._server.sockets[0]
            hub_port = int(sock.getsockname()[1])
            hub_http = f"http://127.0.0.1:{hub_port}"

            # Force hub challenge to reject with 401 by returning broken signature
            bad_ident = MagicMock()
            bad_ident.network_id = self.net_ident.network_id
            bad_ident.public_key_b64 = self.net_ident.public_key_b64
            bad_ident.sign_hub_challenge.return_value = "invalid_signature_b64=="

            with patch.dict("os.environ", {"SNOW_ALLOW_DEV_HUB_HTTP": "1"}, clear=False), \
                 patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
                 patch("snow.security.identity.load_or_create_network_key_identity", return_value=bad_ident), \
                 patch("snow.core.config.resolve_default_hub_url", return_value=hub_http):
                req = make_mocked_request("GET", "/api/directory/resolve/SNW-REM9-9999", match_info={"snow_id": "SNW-REM9-9999"})
                resp = await self.web.handle_api_directory_resolve(req)

            self.assertEqual(resp.status, 401)
            body = json.loads(resp.text)
            self.assertFalse(body["found"])
            self.assertEqual(body["status"], "HUB_AUTH_FAILED")
        finally:
            await relay.stop()

    async def test_06_hub_offline_returns_structured_error(self) -> None:
        with patch.dict("os.environ", {"SNOW_ALLOW_DEV_HUB_HTTP": "1"}, clear=False), \
             patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
             patch("snow.security.identity.load_or_create_network_key_identity", return_value=self.net_ident), \
             patch("snow.core.config.resolve_default_hub_url", return_value="http://127.0.0.1:59999"):
            req = make_mocked_request("GET", "/api/directory/resolve/SNW-OFFL-1111", match_info={"snow_id": "SNW-OFFL-1111"})
            resp = await self.web.handle_api_directory_resolve(req)

        self.assertEqual(resp.status, 503)
        body = json.loads(resp.text)
        self.assertFalse(body["found"])
        self.assertEqual(body["status"], "HUB_UNAVAILABLE")

    async def test_07_remote_device_not_found_returns_structured_error(self) -> None:
        relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="relay-u12-secret"))
        await relay.start()
        try:
            sock = relay._site._server.sockets[0]
            hub_port = int(sock.getsockname()[1])
            hub_http = f"http://127.0.0.1:{hub_port}"

            with patch.dict("os.environ", {"SNOW_ALLOW_DEV_HUB_HTTP": "1"}, clear=False), \
                 patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
                 patch("snow.security.identity.load_or_create_network_key_identity", return_value=self.net_ident), \
                 patch("snow.core.config.resolve_default_hub_url", return_value=hub_http):
                req = make_mocked_request("GET", "/api/directory/resolve/SNW-MISS-0000", match_info={"snow_id": "SNW-MISS-0000"})
                resp = await self.web.handle_api_directory_resolve(req)

            self.assertEqual(resp.status, 404)
            body = json.loads(resp.text)
            self.assertFalse(body["found"])
            self.assertEqual(body["status"], "REMOTE_DEVICE_NOT_FOUND")
        finally:
            await relay.stop()

    async def test_08_local_discovery_failure_does_not_crash_web_server(self) -> None:
        # Remove discovery_service and force bridge.call to fail with error
        self.core.discovery_service = None
        with patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
             patch("snow.core.config.resolve_default_hub_url", return_value=""):
            req = make_mocked_request("GET", "/api/directory/resolve/SNW-NODS-1234", match_info={"snow_id": "SNW-NODS-1234"})
            resp = await self.web.handle_api_directory_resolve(req)

        self.assertEqual(resp.status, 503)
        body = json.loads(resp.text)
        self.assertFalse(body["found"])
        self.assertEqual(body["status"], "DISCOVERY_UNAVAILABLE")

        # Even if bridge.call raises directly, web server must not crash
        self.bridge.call = AsyncMock(side_effect=RuntimeError("ipc socket exploded"))
        with patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
             patch("snow.core.config.resolve_default_hub_url", return_value=""):
            res = await self.web._resolve_snow_id_directory("SNW-NODS-1234")
        self.assertFalse(res["found"])
        self.assertEqual(res["status"], "DISCOVERY_UNAVAILABLE")

    async def test_09_unresolved_remote_id_never_falls_back_to_loopback(self) -> None:
        self.bridge.mesh_connect_peer = AsyncMock()
        with patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
             patch("snow.core.config.resolve_default_hub_url", return_value=""):
            req = make_mocked_request("POST", "/api/devices/connect-peer")
            req.json = AsyncMock(return_value={"snow_id": "SNW-ZZZZ-9999"})
            resp = await self.web.handle_api_devices_connect_peer(req)

        self.assertNotEqual(resp.status, 200)
        body = json.loads(resp.text)
        self.assertFalse(body["success"])
        self.bridge.mesh_connect_peer.assert_not_called()

        # Also assert Android SnowUiRepository.connectByInput no longer falls back to 127.0.0.1 on unresolved SNOW ID
        repo_kt = (Path(__file__).resolve().parents[1] / "android/app/src/main/java/org/snow/ui/SnowUiRepository.kt").read_text("utf-8")
        snow_id_section = repo_kt.substring if False else repo_kt.split("val snowIdRegex")[1].split("// 2. Check 6-digit PIN")[0]
        self.assertNotIn('connect("127.0.0.1", 8765)', snow_id_section)

    async def test_10_invalid_id_offline_and_invalid_endpoint_structured_errors(self) -> None:
        # Invalid SNOW ID -> 400 INVALID_SNOW_ID
        bad_req = make_mocked_request("GET", "/api/directory/resolve/NOT-A-SNOW-ID", match_info={"snow_id": "NOT-A-SNOW-ID"})
        bad_resp = await self.web.handle_api_directory_resolve(bad_req)
        self.assertEqual(bad_resp.status, 400)
        self.assertEqual(json.loads(bad_resp.text)["status"], "INVALID_SNOW_ID")

        # Offline & invalid-endpoint responses from hub fail closed
        relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="relay-u12-secret"))
        await relay.start()
        try:
            sock = relay._site._server.sockets[0]
            hub_http = f"http://127.0.0.1:{int(sock.getsockname()[1])}"
            snow_offline = "SNW-OFF9-0001"
            relay._snow_routes[snow_offline] = {
                "group_id": self.net_ident.network_id,
                "device_id": "dev-offline-1",
                "ws": None,
                "mcp_tunnel": False,
                "lan_endpoints": ["192.168.1.90:8765"],
                "last_seen": 100.0,
            }
            with patch.dict("os.environ", {"SNOW_ALLOW_DEV_HUB_HTTP": "1"}, clear=False), \
                 patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
                 patch("snow.security.identity.load_or_create_network_key_identity", return_value=self.net_ident), \
                 patch("snow.core.config.resolve_default_hub_url", return_value=hub_http):
                off_res = await self.web._resolve_snow_id_directory(snow_offline)
                self.assertFalse(off_res["found"])
                self.assertEqual(off_res["status"], "REMOTE_DEVICE_OFFLINE")

                # Invalid endpoint (malformed relay scheme / missing lan_endpoints) over real HTTP hub route
                from aiohttp import web as aio_web

                async def _ch_h(r):
                    return aio_web.json_response({"success": True, "challenge_id": "ch-bad", "nonce": "n", "expires_at": int(time.time()) + 60})

                async def _sess_h(r):
                    return aio_web.json_response({"success": True, "token": "shs1_test_tok"})

                async def _dir_h(r):
                    return aio_web.json_response({
                        "success": True,
                        "online": True,
                        "snow_id": "SNW-BAD9-0002",
                        "lan_endpoints": [],
                        "relay_ws_url": "ftp://invalid-scheme.example",
                    })

                bad_hub = aio_web.Application()
                bad_hub.router.add_post("/v1/hub/challenge", _ch_h)
                bad_hub.router.add_post("/v1/hub/session", _sess_h)
                bad_hub.router.add_get("/v1/directory/resolve/SNW-BAD9-0002", _dir_h)
                bad_runner = aio_web.AppRunner(bad_hub)
                await bad_runner.setup()
                bad_site = aio_web.TCPSite(bad_runner, "127.0.0.1", 0)
                await bad_site.start()
                bad_port = int(bad_site._server.sockets[0].getsockname()[1])
                try:
                    with patch.dict("os.environ", {"SNOW_ALLOW_DEV_HUB_HTTP": "1"}, clear=False), \
                         patch("snow.security.identity.load_or_create_device_identity", return_value=self.local_ident), \
                         patch("snow.security.identity.load_or_create_network_key_identity", return_value=self.net_ident), \
                         patch("snow.core.config.resolve_default_hub_url", return_value=f"http://127.0.0.1:{bad_port}"):
                        inv_res = await self.web._resolve_snow_id_directory("SNW-BAD9-0002")
                        self.assertFalse(inv_res["found"])
                        self.assertEqual(inv_res["status"], "INVALID_ENDPOINT")
                finally:
                    await bad_runner.cleanup()
        finally:
            await relay.stop()


if __name__ == "__main__":
    unittest.main()
