"""Stage 6B WS1 & WS2 Regression Tests: Render Dockerfile, Health Endpoint, Ed25519 Hub & Failover."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from aiohttp.test_utils import AioHTTPTestCase

from snow.relay.config import RelayConfig
from snow.relay.server import SnowRelayServer


REPO_ROOT = Path(__file__).resolve().parents[1]


class TestStage6BWS1DockerfileAndConfig(unittest.TestCase):
    """Verify Render Free Tier Dockerfile build order, minimal deps, and PORT binding."""

    def test_dockerfile_minimal_dependencies_and_order(self) -> None:
        dockerfile = (REPO_ROOT / "src" / "snow" / "relay" / "Dockerfile").read_text(encoding="utf-8")
        self.assertIn("FROM python:3.13-slim", dockerfile)
        self.assertIn("aiohttp>=3.10.0", dockerfile)
        self.assertIn("cryptography>=43.0.0", dockerfile)
        self.assertNotIn("pip install --no-cache-dir .", dockerfile)
        for desktop_dep in ("psutil", "mcp>=", "qrcode", "websockets", "Pillow", "pywin32"):
            self.assertNotIn(desktop_dep, dockerfile)

        self.assertIn('ENV PYTHONPATH="/app/src"', dockerfile)
        self.assertIn('ENV SNOW_RELAY_HOST="0.0.0.0"', dockerfile)
        self.assertIn('ENV SNOW_RELAY_ENABLED="1"', dockerfile)
        self.assertIn("USER snow", dockerfile)
        self.assertIn('ENTRYPOINT ["python", "-m", "snow.relay"]', dockerfile)
        self.assertIn("COPY --chown=snow:snow src/snow/__init__.py /app/src/snow/__init__.py", dockerfile)
        self.assertIn("COPY --chown=snow:snow src/snow/relay/ /app/src/snow/relay/", dockerfile)

        # Render healthCheckPath & autoDeploy
        render_yaml = (REPO_ROOT / "render.yaml").read_text(encoding="utf-8")
        self.assertIn("autoDeploy: true", render_yaml)
        self.assertIn("healthCheckPath: /health", render_yaml)

        # .dockerignore must exclude local state, secrets, DBs, and desktop assets
        dockerignore = (REPO_ROOT / ".dockerignore").read_text(encoding="utf-8")
        for pat in (".snow/", "*.db", "*.key", "*.keystore", "keystore.properties", ".venv", "android/"):
            self.assertIn(pat, dockerignore)

    def test_relay_port_respects_render_injected_port_env(self) -> None:
        prev_port = os.environ.get("PORT")
        prev_relay_port = os.environ.get("SNOW_RELAY_PORT")
        try:
            os.environ["PORT"] = "10042"
            os.environ["SNOW_RELAY_PORT"] = "8770"
            cfg = RelayConfig.from_env()
            self.assertEqual(cfg.port, 10042)
        finally:
            if prev_port is None:
                os.environ.pop("PORT", None)
            else:
                os.environ["PORT"] = prev_port
            if prev_relay_port is None:
                os.environ.pop("SNOW_RELAY_PORT", None)
            else:
                os.environ["SNOW_RELAY_PORT"] = prev_relay_port

    def test_relay_runtime_imports_without_desktop_packages(self) -> None:
        """Simulate the minimal Dockerfile layout (/app/src/snow/relay only) in an isolated PYTHONPATH."""
        import subprocess
        import sys

        with tempfile.TemporaryDirectory(prefix="snow_relay_isolated_") as tmp:
            src_snow = Path(tmp) / "src" / "snow"
            (src_snow / "relay").mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPO_ROOT / "src" / "snow" / "__init__.py", src_snow / "__init__.py")
            for py_file in (REPO_ROOT / "src" / "snow" / "relay").glob("*.py"):
                if py_file.name == "client.py":
                    continue
                shutil.copy2(py_file, src_snow / "relay" / py_file.name)

            env = dict(os.environ)
            env["PYTHONPATH"] = str(Path(tmp) / "src")
            proc = subprocess.run(
                [sys.executable, "-c", "from snow.relay import RelayConfig, SnowRelayServer; s = SnowRelayServer(RelayConfig()); print(s.config.port)"],
                env=env,
                cwd=tmp,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(proc.returncode, 0, f"Isolated relay import failed: {proc.stderr}")
            self.assertEqual(proc.stdout.strip(), "8770")


class TestStage6BWS1HealthEndpoint(AioHTTPTestCase):
    """Verify unauthenticated GET and HEAD /health behavior for UptimeRobot & Render."""

    async def get_application(self):
        self.relay = SnowRelayServer(RelayConfig(shared_secret="test-secret-for-isolation"))
        return self.relay._build_app()

    async def test_health_get_and_head_unauthenticated_no_store_no_leaks(self) -> None:
        resp_get = await self.client.get("/health")
        self.assertEqual(resp_get.status, 200)
        self.assertEqual(resp_get.headers.get("Cache-Control"), "no-store")
        body = await resp_get.json()
        self.assertEqual(body.get("status"), "healthy")
        self.assertEqual(body.get("service"), "snow-relay")
        # Must not leak secrets, peer IDs, or device counts
        serialized = json.dumps(body)
        self.assertNotIn("test-secret", serialized)
        self.assertNotIn("online_devices", body)
        self.assertNotIn("peers", body)

        resp_head = await self.client.head("/health")
        self.assertEqual(resp_head.status, 200)
        self.assertEqual(resp_head.headers.get("Cache-Control"), "no-store")
        self.assertEqual(resp_head.headers.get("Content-Type", "").split(";")[0].strip(), "application/json")
        head_bytes = await resp_head.read()
        self.assertEqual(head_bytes, b"")


class TestStage6BWS2Ed25519NetworkIdentity(unittest.TestCase):
    """Verify persistent Ed25519 network identity, derivation, concurrency, corruption fail-closed, and secret hygiene."""

    def test_persistent_ed25519_identity_derivation_concurrency_and_corruption_recovery(self) -> None:
        from concurrent.futures import ThreadPoolExecutor
        import hashlib
        from snow.relay.auth import (
            decode_ed25519_pubkey,
            derive_network_id_from_pubkey,
            is_valid_network_id,
            verify_ed25519_signature,
        )
        from snow.security.identity import (
            NetworkIdentityError,
            load_or_create_network_key_identity,
            recover_network_identity,
        )

        with tempfile.TemporaryDirectory(prefix="snow_netid_") as tmp:
            tmp_path = Path(tmp)

            # Concurrent initialization across 8 threads must converge to identical network_id/pubkey
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda _: load_or_create_network_key_identity(data_dir=tmp_path), range(8)))

            first = results[0]
            self.assertTrue(is_valid_network_id(first.network_id))
            raw_pub = decode_ed25519_pubkey(first.public_key_b64)
            expected_id = "SNW-NET-" + hashlib.sha256(raw_pub).hexdigest()[:8].upper()
            self.assertEqual(first.network_id, expected_id)
            self.assertEqual(derive_network_id_from_pubkey(first.public_key_b64), first.network_id)
            for item in results[1:]:
                self.assertEqual(item.network_id, first.network_id)
                self.assertEqual(item.public_key_b64, first.public_key_b64)

            # Reload persists same identity
            reloaded = load_or_create_network_key_identity(data_dir=tmp_path)
            self.assertEqual(reloaded.network_id, first.network_id)

            # Sign & verify
            msg = b"snow-stage6b-challenge-test"
            sig = reloaded.sign_message(msg)
            self.assertTrue(verify_ed25519_signature(reloaded.public_key_b64, msg, sig))
            self.assertFalse(verify_ed25519_signature(reloaded.public_key_b64, b"tampered", sig))
            self.assertFalse(verify_ed25519_signature("not-a-valid-key", msg, sig))
            self.assertFalse(verify_ed25519_signature(reloaded.public_key_b64, msg, "not-valid-sig"))

            # Zero private key leakage in public dict and repr
            pub_dict = reloaded.to_dict()
            self.assertNotIn("private_key", json.dumps(pub_dict))
            self.assertNotIn("_private_key_bytes", repr(reloaded))

            # Corrupted key file MUST raise NetworkIdentityError instead of silently overwriting
            key_file = tmp_path / "network_key.json"
            key_file.write_text("{corrupted-json", encoding="utf-8")
            with self.assertRaises(NetworkIdentityError):
                load_or_create_network_key_identity(data_dir=tmp_path)

            # Explicit recovery archives corrupt file and creates clean new identity
            recovered, backup = recover_network_identity(data_dir=tmp_path)
            self.assertIsNotNone(backup)
            self.assertTrue(backup.is_file())
            self.assertTrue(is_valid_network_id(recovered.network_id))

    def test_default_hub_url_validation_rules(self) -> None:
        from snow.core.config import validate_hub_url

        self.assertEqual(validate_hub_url("https://snow-hub.onrender.com/"), "https://snow-hub.onrender.com")
        for bad in (
            "",
            "ftp://snow-hub.onrender.com",
            "http://snow-hub.onrender.com",
            "https://user:pass@snow-hub.onrender.com",
            "https://snow-hub.onrender.com/arbitrary/path",
            "https://snow-hub.onrender.com?x=1",
            "https://snow-hub.onrender.com#frag",
            "https://127.0.0.1:8770/bad",
        ):
            with self.assertRaises(ValueError, msg=f"Expected rejection for {bad!r}"):
                validate_hub_url(bad, allow_dev_loopback=False)

        # Loopback HTTP permitted ONLY with explicit dev opt-in
        self.assertEqual(
            validate_hub_url("http://127.0.0.1:8770/", allow_dev_loopback=True),
            "http://127.0.0.1:8770",
        )


class TestStage6BWS2HubAuthRoutingAndFailover(unittest.IsolatedAsyncioTestCase):
    """End-to-end tests for stateless Ed25519 hub challenge-response, /u/{network_id}/* proxy, and failover."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="snow_s6b_hub_")
        self.relay = SnowRelayServer(
            RelayConfig(
                host="127.0.0.1",
                port=0,
                shared_secret="admin-secret-only",
                host_lease_seconds=30.0,
                hub_challenge_ttl_seconds=30.0,
            )
        )
        await self.relay.start()
        sock = self.relay._site._server.sockets[0]
        self.relay_port = int(sock.getsockname()[1])
        self.hub_http_url = f"http://127.0.0.1:{self.relay_port}"
        self.relay_ws_url = f"ws://127.0.0.1:{self.relay_port}/v1/tunnel"

    async def asyncTearDown(self) -> None:
        await self.relay.stop()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_hub_challenge_session_replay_and_isolation(self) -> None:
        import aiohttp
        from snow.security.identity import load_or_create_network_key_identity

        net_a = load_or_create_network_key_identity(data_dir=Path(self.tmp_dir) / "net_a")
        net_b = load_or_create_network_key_identity(data_dir=Path(self.tmp_dir) / "net_b")

        async with aiohttp.ClientSession() as client:
            # 1. Mismatched network_id & public_key rejected
            bad_ch = await client.post(
                f"{self.hub_http_url}/v1/hub/challenge",
                json={"network_id": net_b.network_id, "public_key": net_a.public_key_b64, "device_id": "pc-a"},
            )
            self.assertEqual(bad_ch.status, 403)

            # 2. Valid challenge + concurrent redemption (only 1 succeeds, 4 fail replay)
            ch_resp = await client.post(
                f"{self.hub_http_url}/v1/hub/challenge",
                json={"network_id": net_a.network_id, "public_key": net_a.public_key_b64, "device_id": "pc-a"},
            )
            self.assertEqual(ch_resp.status, 200)
            ch_data = await ch_resp.json()
            sig_a = net_a.sign_hub_challenge(ch_data, device_id="pc-a")

            session_req = {
                "challenge_id": ch_data["challenge_id"],
                "network_id": net_a.network_id,
                "public_key": net_a.public_key_b64,
                "signature": sig_a,
                "device_id": "pc-a",
                "snow_id": "SNW-HOST-AAA1",
            }
            concurrent = await asyncio.gather(*[
                client.post(f"{self.hub_http_url}/v1/hub/session", json=session_req)
                for _ in range(5)
            ])
            statuses = sorted([r.status for r in concurrent])
            self.assertEqual(statuses, [200, 401, 401, 401, 401])

            # 3. Wrong signature rejected
            ch2 = await (await client.post(
                f"{self.hub_http_url}/v1/hub/challenge",
                json={"network_id": net_a.network_id, "public_key": net_a.public_key_b64, "device_id": "pc-a"},
            )).json()
            wrong_sig = net_b.sign_hub_challenge(ch2, device_id="pc-a")
            bad_sess = await client.post(
                f"{self.hub_http_url}/v1/hub/session",
                json={
                    "challenge_id": ch2["challenge_id"],
                    "network_id": net_a.network_id,
                    "public_key": net_a.public_key_b64,
                    "signature": wrong_sig,
                    "device_id": "pc-a",
                },
            )
            self.assertEqual(bad_sess.status, 401)

            # 4. Valid hub token cannot impersonate Network B on WS hello
            ch3 = await (await client.post(
                f"{self.hub_http_url}/v1/hub/challenge",
                json={"network_id": net_a.network_id, "public_key": net_a.public_key_b64, "device_id": "pc-a"},
            )).json()
            s3 = await (await client.post(
                f"{self.hub_http_url}/v1/hub/session",
                json={
                    "challenge_id": ch3["challenge_id"],
                    "network_id": net_a.network_id,
                    "public_key": net_a.public_key_b64,
                    "signature": net_a.sign_hub_challenge(ch3, device_id="pc-a"),
                    "device_id": "pc-a",
                },
            )).json()
            token_a = s3["token"]

            async with client.ws_connect(self.relay_ws_url) as ws:
                await ws.send_json({
                    "type": "hello",
                    "hub_token": token_a,
                    "network_id": net_b.network_id,
                    "device_id": "pc-a",
                })
                closed_msg = await ws.receive()
                self.assertEqual(closed_msg.type, aiohttp.WSMsgType.CLOSE)

    async def test_multi_pc_coordinator_failover_fencing_and_network_mcp_proxy(self) -> None:
        import aiohttp
        from unittest.mock import AsyncMock, MagicMock
        from snow.mcp.bridge import SnowMcpBridge
        from snow.mcp.remote_gateway import RemoteMcpGateway
        from snow.relay.mcp_forwarder import RelayMcpForwarder
        from snow.security.db import DatabaseManager
        from snow.security.identity import load_or_create_network_key_identity

        net_a = load_or_create_network_key_identity(data_dir=Path(self.tmp_dir) / "net_a")
        net_b = load_or_create_network_key_identity(data_dir=Path(self.tmp_dir) / "net_b")

        db_mgr = DatabaseManager(db_path=Path(self.tmp_dir) / "gw.db")
        mock_bridge = AsyncMock(spec=SnowMcpBridge)
        mock_bridge.capability_engine = MagicMock(db_manager=db_mgr)
        gw = RemoteMcpGateway(
            host="127.0.0.1",
            port=0,
            bridge=mock_bridge,
            public_url=f"{self.hub_http_url}/u/{net_a.network_id}",
        )
        from aiohttp import web as aio_web
        gw_runner = aio_web.AppRunner(gw.app)
        await gw_runner.setup()
        gw_site = aio_web.TCPSite(gw_runner, "127.0.0.1", 0)
        await gw_site.start()
        gw_port = int(gw_site._server.sockets[0].getsockname()[1])
        gw_url = f"http://127.0.0.1:{gw_port}"

        fwd_primary = RelayMcpForwarder(
            relay_ws_url=self.relay_ws_url,
            snow_id="SNW-PC01-AAAA",
            local_gateway_url=gw_url,
            network_key_identity=net_a,
            hub_http_url=self.hub_http_url,
            device_id="pc-1",
            priority=200,
            lan_endpoints=["192.168.1.10:8765"],
            device_name="Primary PC",
        )
        fwd_standby = RelayMcpForwarder(
            relay_ws_url=self.relay_ws_url,
            snow_id="SNW-PC02-BBBB",
            local_gateway_url=gw_url,
            network_key_identity=net_a,
            hub_http_url=self.hub_http_url,
            device_id="pc-2",
            priority=100,
            lan_endpoints=["192.168.1.11:8765"],
            device_name="Standby PC",
        )
        try:
            ok1, e1 = await fwd_primary.start()
            ok2, e2 = await fwd_standby.start()
            self.assertTrue(ok1, e1)
            self.assertTrue(ok2, e2)
            self.assertEqual(self.relay._network_coordinators[net_a.network_id].primary_device_id, "pc-1")
            initial_epoch = self.relay._network_coordinators[net_a.network_id].epoch
            self.assertGreaterEqual(initial_epoch, 1)

            async with aiohttp.ClientSession() as client:
                # 1. Network-scoped OAuth metadata, consent page prefix, and path traversal safety
                meta_r = await client.get(f"{self.hub_http_url}/u/{net_a.network_id}/.well-known/oauth-authorization-server")
                self.assertEqual(meta_r.status, 200)
                meta_j = await meta_r.json()
                self.assertEqual(meta_j["issuer"], f"{self.hub_http_url}/u/{net_a.network_id}")
                self.assertEqual(meta_j["authorization_endpoint"], f"{self.hub_http_url}/u/{net_a.network_id}/oauth/authorize")

                icon_r = await client.get(f"{self.hub_http_url}/u/{net_a.network_id}/snow_logo.png")
                self.assertEqual(icon_r.status, 200)

                # Register OAuth client and inspect consent HTML action/logo prefixing
                reg_r = await client.post(
                    f"{self.hub_http_url}/u/{net_a.network_id}/oauth/register",
                    json={"client_name": "Render Test", "redirect_uris": ["https://client.test/cb"]},
                )
                self.assertEqual(reg_r.status, 201)
                cid = (await reg_r.json())["client_id"]
                auth_r = await client.get(
                    f"{self.hub_http_url}/u/{net_a.network_id}/oauth/authorize"
                    f"?response_type=code&client_id={cid}&redirect_uri=https://client.test/cb"
                    f"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
                )
                self.assertEqual(auth_r.status, 200)
                auth_html = await auth_r.text()
                self.assertIn(f'action="/u/{net_a.network_id}/oauth/authorize"', auth_html)
                self.assertIn(f'src="/u/{net_a.network_id}/snow_logo.png"', auth_html)
                self.assertIn(f'var apiPrefix = "/u/{net_a.network_id}";', auth_html)

                trav_r = await client.get(f"{self.hub_http_url}/u/{net_a.network_id}/../secret")
                self.assertNotEqual(trav_r.status, 200)
                arb_r = await client.get(f"{self.hub_http_url}/u/{net_a.network_id}/etc/passwd")
                self.assertEqual(arb_r.status, 404)

                # Unrelated network_id B has zero hosts -> must return 503 cleanly (no cross-network leakage)
                netb_r = await client.get(f"{self.hub_http_url}/u/{net_b.network_id}/.well-known/oauth-authorization-server")
                self.assertEqual(netb_r.status, 503)

                # Directory resolve scoped to authenticated network A
                dir_a = await client.get(
                    f"{self.hub_http_url}/v1/directory/resolve/SNW-PC02-BBBB",
                    headers={"Authorization": f"Bearer {fwd_primary.hub_token}"},
                )
                self.assertEqual(dir_a.status, 200)
                dir_j = await dir_a.json()
                self.assertEqual(dir_j["network_id"], net_a.network_id)
                self.assertEqual(dir_j["lan_endpoints"], ["192.168.1.11:8765"])

                # 2. Simulate primary lease expiry -> sweep promotes standby pc-2 with monotonic epoch
                coord = self.relay._network_coordinators[net_a.network_id]
                coord.hosts["pc-1"].lease_expires_at = 0.0
                await self.relay.sweep_expired_leases()
                self.assertEqual(coord.primary_device_id, "pc-2")
                self.assertGreater(coord.epoch, initial_epoch)

                # Stale epoch heartbeat/claim from secondary/stale epoch is fenced
                await fwd_standby._ws.send_json({
                    "type": "coordinator_claim",
                    "epoch": initial_epoch - 1,
                })
                await asyncio.sleep(0.05)

                # MCP metadata route still works seamlessly via promoted pc-2!
                meta_after = await client.get(f"{self.hub_http_url}/u/{net_a.network_id}/.well-known/oauth-authorization-server")
                self.assertEqual(meta_after.status, 200)
        finally:
            await fwd_standby.stop()
            await fwd_primary.stop()
            await gw_runner.cleanup()

