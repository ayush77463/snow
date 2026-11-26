"""Stage 6C WS1 Regression Tests: Built-in Render Hub Default, Relay Root/Icons, Rendezvous Onboarding, and WMI Brightness Fallback."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import uuid

from aiohttp.test_utils import AioHTTPTestCase

from snow.capabilities.windows.system import WindowsSystemControls, _default_set_brightness_wmi
from snow.core.config import CoreConfig, DEFAULT_BUILTIN_HUB_URL, resolve_default_hub_url, validate_hub_url
from snow.core.server import SnowCoreServer
from snow.network.relay_client import RelayTunnelClient
from snow.relay.config import RelayConfig
from snow.relay.server import SnowRelayServer
from snow.security.db import DatabaseManager
from snow.security.identity import load_or_create_device_identity, load_or_create_network_key_identity
from snow.security.tls import ensure_tls_certificate


class TestStage6CWS1DefaultHubUrlAndPrecedence(unittest.TestCase):
    """WS1 3.1: Built-in Render Hub URL default, validation, and deterministic precedence."""

    def test_builtin_default_and_precedence_order(self) -> None:
        self.assertEqual(DEFAULT_BUILTIN_HUB_URL, "https://snow-relay.onrender.com")
        self.assertEqual(CoreConfig().default_hub_url, "https://snow-relay.onrender.com")

        with tempfile.TemporaryDirectory(prefix="snow_6c_hub_cfg_") as tmp:
            db = DatabaseManager(db_path=Path(tmp) / "test.db")
            prev_env = os.environ.pop("SNOW_DEFAULT_HUB_URL", None)
            try:
                # 1. Fresh install with no DB setting and no env uses built-in default
                self.assertEqual(resolve_default_hub_url(db_manager=db), DEFAULT_BUILTIN_HUB_URL)
                self.assertEqual(CoreConfig.from_env().default_hub_url, DEFAULT_BUILTIN_HUB_URL)

                # 2. Environment override applies when no persisted custom setting exists
                os.environ["SNOW_DEFAULT_HUB_URL"] = "https://env-hub.example.com/"
                self.assertEqual(resolve_default_hub_url(db_manager=db), "https://env-hub.example.com")
                self.assertEqual(CoreConfig.from_env().default_hub_url, "https://env-hub.example.com")

                # 3. Persisted user setting overrides environment & survives upgrade untouched
                db.set_setting("default_hub_url", "https://custom-user-hub.example.com/")
                self.assertEqual(resolve_default_hub_url(db_manager=db), "https://custom-user-hub.example.com")

                # 4. Explicit override wins highest priority
                self.assertEqual(
                    resolve_default_hub_url(db_manager=db, explicit="https://explicit-hub.example.com"),
                    "https://explicit-hub.example.com",
                )

                # 5. Invalid env var rejected cleanly
                os.environ["SNOW_DEFAULT_HUB_URL"] = "http://user:pass@evil.example.com/bad"
                with self.assertRaises(ValueError):
                    CoreConfig.from_env()
            finally:
                if prev_env is None:
                    os.environ.pop("SNOW_DEFAULT_HUB_URL", None)
                else:
                    os.environ["SNOW_DEFAULT_HUB_URL"] = prev_env


class TestStage6CWS1RelayRootIconsAndRendezvous(AioHTTPTestCase):
    """WS1 3.2 & 3.3: Root JSON, favicon/icon allowlisting, and authenticated remote rendezvous."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="snow_6c_rdv_")
        await super().asyncSetUp()

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def get_application(self):
        self.relay = SnowRelayServer(
            RelayConfig(
                host="127.0.0.1",
                port=0,
                shared_secret="test-relay-secret",
                host_lease_seconds=30.0,
            )
        )
        return self.relay._build_app()

    async def _auth_hub_host(self, net_ident, device_id: str, snow_id: str) -> str:
        ch_resp = await self.client.post(
            "/v1/hub/challenge",
            json={"network_id": net_ident.network_id, "public_key": net_ident.public_key_b64, "device_id": device_id},
        )
        self.assertEqual(ch_resp.status, 200)
        ch = await ch_resp.json()
        sig = net_ident.sign_hub_challenge(ch, device_id=device_id)
        sess_resp = await self.client.post(
            "/v1/hub/session",
            json={
                "challenge_id": ch["challenge_id"],
                "network_id": net_ident.network_id,
                "public_key": net_ident.public_key_b64,
                "signature": sig,
                "device_id": device_id,
                "snow_id": snow_id,
            },
        )
        self.assertEqual(sess_resp.status, 200)
        return (await sess_resp.json())["token"]

    async def test_root_response_and_allowed_icon_subpaths(self) -> None:
        from snow.relay.server import _ALLOWED_MCP_SUBPATHS_EXACT, _sanitize_forwarded_subpath

        resp = await self.client.get("/")
        self.assertEqual(resp.status, 200)
        self.assertEqual(resp.headers.get("Cache-Control"), "no-store")
        body = await resp.json()
        self.assertEqual(body, {"service": "snow-relay", "status": "online", "health": "/health"})
        serialized = json.dumps(body)
        self.assertNotIn("test-relay-secret", serialized)

        resp_head = await self.client.head("/")
        self.assertEqual(resp_head.status, 200)
        self.assertEqual(resp_head.headers.get("Cache-Control"), "no-store")

        # Existing /health still works cleanly
        h = await self.client.get("/health")
        self.assertEqual(h.status, 200)
        self.assertEqual((await h.json())["status"], "healthy")

        self.assertIn("icon.png", _ALLOWED_MCP_SUBPATHS_EXACT)
        self.assertIn("apple-touch-icon.png", _ALLOWED_MCP_SUBPATHS_EXACT)
        self.assertEqual(_sanitize_forwarded_subpath("icon.png"), (True, "/icon.png"))
        self.assertEqual(_sanitize_forwarded_subpath("apple-touch-icon.png"), (True, "/apple-touch-icon.png"))
        self.assertEqual(_sanitize_forwarded_subpath("../icon.png")[0], False)
        self.assertEqual(_sanitize_forwarded_subpath("static/icon.png")[0], False)

    async def test_rendezvous_open_join_security_limits_and_e2e_pairing(self) -> None:
        net_a = load_or_create_network_key_identity(data_dir=Path(self.tmp_dir) / "net_a")
        net_b = load_or_create_network_key_identity(data_dir=Path(self.tmp_dir) / "net_b")
        tok_a = await self._auth_hub_host(net_a, "host-pc-a", "SNW-HOST-1111")

        # 1. Unauthenticated open rejected
        unauth = await self.client.post(
            "/v1/rendezvous/open",
            json={"mode": "pairing", "host_snow_id": "SNW-HOST-1111", "pin": "123456"},
        )
        self.assertEqual(unauth.status, 401)

        # 2. Wrong network denied
        wrong_net = await self.client.post(
            "/v1/rendezvous/open",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"network_id": net_b.network_id, "mode": "pairing", "host_snow_id": "SNW-HOST-1111", "pin": "123456"},
        )
        self.assertEqual(wrong_net.status, 403)

        # 3. Authenticated open succeeds with capped TTL <= 120s and zero secret leaks
        open_pin = await self.client.post(
            "/v1/rendezvous/open",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={
                "network_id": net_a.network_id,
                "mode": "pairing",
                "host_device_id": "host-pc-a",
                "host_snow_id": "SNW-HOST-1111",
                "pin": "654321",
                "ttl_seconds": 9999,  # Must clamp to 120
            },
        )
        self.assertEqual(open_pin.status, 200)
        pin_data = await open_pin.json()
        self.assertLessEqual(pin_data["expires_in"], 120)
        self.assertNotIn("654321", json.dumps(pin_data))
        self.assertNotIn("private_key", json.dumps(pin_data))

        # 4. Wrong federation scope rejected for pairing entry
        wrong_scope = await self.client.post(
            "/v1/rendezvous/join",
            json={
                "rendezvous_id": pin_data["rendezvous_id"],
                "federation_code": "123-456-789",
                "client_device_id": "phone-1",
            },
        )
        self.assertEqual(wrong_scope.status, 403)

        # 5. Wrong PIN 5 times locks and purges entry (brute force protection)
        for idx in range(4):
            bad_pin = await self.client.post(
                "/v1/rendezvous/join",
                json={"snow_id": "SNW-HOST-1111", "pin": f"00000{idx}", "client_device_id": "phone-1"},
            )
            self.assertEqual(bad_pin.status, 401)
        locked = await self.client.post(
            "/v1/rendezvous/join",
            json={"snow_id": "SNW-HOST-1111", "pin": "999999", "client_device_id": "phone-1"},
        )
        self.assertEqual(locked.status, 429)
        # Even the previously valid PIN now fails cleanly after lockout!
        after_lock = await self.client.post(
            "/v1/rendezvous/join",
            json={"snow_id": "SNW-HOST-1111", "pin": "654321", "client_device_id": "phone-1"},
        )
        self.assertEqual(after_lock.status, 401)

        # 6. Cancellation test
        open_cancel = await self.client.post(
            "/v1/rendezvous/open",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"mode": "pairing", "host_snow_id": "SNW-HOST-1111", "handshake_token": "tok_cancel_1234567890"},
        )
        self.assertEqual(open_cancel.status, 200)
        cancel_id = (await open_cancel.json())["rendezvous_id"]
        c_res = await self.client.post(
            "/v1/rendezvous/cancel",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"rendezvous_id": cancel_id},
        )
        self.assertEqual(c_res.status, 200)
        after_cancel = await self.client.post(
            "/v1/rendezvous/join",
            json={"handshake_token": "tok_cancel_1234567890", "client_device_id": "phone-1"},
        )
        self.assertEqual(after_cancel.status, 401)

        # 7. Valid QR handshake_token + concurrent joins (only 1 wins, 4 rejected; replay rejected)
        open_qr = await self.client.post(
            "/v1/rendezvous/open",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={
                "mode": "pairing",
                "host_snow_id": "SNW-HOST-1111",
                "handshake_token": "htok_concurrent_valid_1234567",
            },
        )
        self.assertEqual(open_qr.status, 200)
        concurrent = await asyncio.gather(*[
            self.client.post(
                "/v1/rendezvous/join",
                json={
                    "snow_id": "SNW-HOST-1111",
                    "handshake_token": "htok_concurrent_valid_1234567",
                    "client_device_id": f"phone-{i}",
                },
            )
            for i in range(5)
        ])
        codes = sorted([r.status for r in concurrent])
        self.assertEqual(codes, [200, 401, 401, 401, 401])
        win_resp = next(r for r in concurrent if r.status == 200)
        win_json = await win_resp.json()
        self.assertEqual(win_json["trust_completed"], False)
        self.assertEqual(win_json["requires_end_to_end_verification"], True)
        self.assertTrue(str(win_json["bootstrap_token"]).startswith("rbs1_"))
        self.assertNotIn("private_key", json.dumps(win_json))
        # Bootstrap token MUST NOT authenticate hub admin/directory endpoints!
        hub_abuse = await self.client.get(
            "/v1/directory/resolve/SNW-HOST-1111",
            headers={"Authorization": f"Bearer {win_json['bootstrap_token']}"},
        )
        self.assertEqual(hub_abuse.status, 401)

        # 8. Valid federation code mode
        open_fed = await self.client.post(
            "/v1/rendezvous/open",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"mode": "federation", "host_snow_id": "SNW-HOST-1111", "federation_code": "123-456-789"},
        )
        self.assertEqual(open_fed.status, 200)
        join_fed = await self.client.post(
            "/v1/rendezvous/join",
            json={"federation_code": "123456789", "client_device_id": "remote-pc-1"},
        )
        self.assertEqual(join_fed.status, 200)
        fed_json = await join_fed.json()
        self.assertEqual(fed_json["mode"], "federation")
        self.assertEqual(fed_json["trust_completed"], False)

        # 9. TTL expiry cleanup test
        open_exp = await self.client.post(
            "/v1/rendezvous/open",
            headers={"Authorization": f"Bearer {tok_a}"},
            json={"mode": "pairing", "host_snow_id": "SNW-HOST-1111", "pin": "112233"},
        )
        exp_id = (await open_exp.json())["rendezvous_id"]
        self.relay._rendezvous_openings[exp_id]["expires_at"] = 1.0
        exp_join = await self.client.post(
            "/v1/rendezvous/join",
            json={"snow_id": "SNW-HOST-1111", "pin": "112233", "client_device_id": "phone-exp"},
        )
        self.assertEqual(exp_join.status, 401)
        self.assertNotIn(exp_id, self.relay._rendezvous_openings)


class TestStage6CWS1RendezvousEndToEndPairing(unittest.IsolatedAsyncioTestCase):
    """Prove /v1/rendezvous/join cannot pair on its own and completes trust ONLY via real E2E PairingManager."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = tempfile.mkdtemp(prefix="snow_6c_e2e_rdv_")
        self.relay = SnowRelayServer(RelayConfig(host="127.0.0.1", port=0, shared_secret="s"))
        await self.relay.start()
        sock = self.relay._site._server.sockets[0]
        self.relay_port = int(sock.getsockname()[1])
        self.hub_url = f"http://127.0.0.1:{self.relay_port}"
        self.ws_url = f"ws://127.0.0.1:{self.relay_port}/v1/tunnel"

    async def asyncTearDown(self) -> None:
        await self.relay.stop()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_rendezvous_bootstraps_real_e2e_tls_pairing_flow(self) -> None:
        import aiohttp

        host_dir = Path(self.tmp_dir) / "host"
        client_dir = Path(self.tmp_dir) / "client"
        host_tls = ensure_tls_certificate(host_dir / "tls" / "server.crt", host_dir / "tls" / "server.key")
        client_tls = ensure_tls_certificate(client_dir / "tls" / "client.crt", client_dir / "tls" / "client.key")

        net_id_obj = load_or_create_network_key_identity(data_dir=host_dir)
        host_ident = load_or_create_device_identity(data_dir=host_dir)
        client_uuid = str(uuid.uuid4())
        host_db = DatabaseManager(db_path=host_dir / "host.db")
        cfg = CoreConfig(
            bind_host="127.0.0.1",
            port=18765,
            transfer_port=0,
            ipc_port=0,
            discovery_enabled=False,
            tls_enabled=True,
            tls_cert_path=str(host_tls.cert_path),
            tls_key_path=str(host_tls.key_path),
        )
        core = SnowCoreServer(config=cfg, db_manager=host_db, device_identity=host_ident)
        real_pin = core.pairing_manager.generate_pin(display_to_stderr=False)

        async with aiohttp.ClientSession() as http:
            ch = await (await http.post(
                f"{self.hub_url}/v1/hub/challenge",
                json={"network_id": net_id_obj.network_id, "public_key": net_id_obj.public_key_b64, "device_id": host_ident.device_id},
            )).json()
            sess = await (await http.post(
                f"{self.hub_url}/v1/hub/session",
                json={
                    "challenge_id": ch["challenge_id"],
                    "network_id": net_id_obj.network_id,
                    "public_key": net_id_obj.public_key_b64,
                    "signature": net_id_obj.sign_hub_challenge(ch, device_id=host_ident.device_id),
                    "device_id": host_ident.device_id,
                    "snow_id": host_ident.snow_id,
                },
            )).json()
            hub_token = sess["token"]

            rdv_open = await (await http.post(
                f"{self.hub_url}/v1/rendezvous/open",
                headers={"Authorization": f"Bearer {hub_token}"},
                json={
                    "mode": "pairing",
                    "host_device_id": host_ident.device_id,
                    "host_snow_id": host_ident.snow_id,
                    "cert_fingerprint": host_tls.fingerprint_sha256,
                    "pin": real_pin,
                },
            )).json()
            self.assertTrue(rdv_open["success"])

            # Joining phone is NOT in host_db yet!
            join_res = await (await http.post(
                f"{self.hub_url}/v1/rendezvous/join",
                json={"snow_id": host_ident.snow_id, "pin": real_pin, "client_device_id": client_uuid},
            )).json()
            self.assertTrue(join_res["success"])
            self.assertIsNone(host_db.get_paired_device(client_uuid))

        host_tunnel = RelayTunnelClient(
            relay_url=self.ws_url,
            device_id=host_ident.device_id,
            group_id=net_id_obj.network_id,
            ticket="",
            cert_path=str(host_tls.cert_path),
            key_path=str(host_tls.key_path),
            hub_token=hub_token,
            network_id=net_id_obj.network_id,
        )
        host_tunnel.set_peer_pinned_fingerprint(client_uuid, client_tls.fingerprint_sha256)
        host_tunnel.request_dispatcher = core._handle_incoming_relay_request

        phone_tunnel = RelayTunnelClient(
            relay_url=self.ws_url,
            device_id=client_uuid,
            group_id=net_id_obj.network_id,
            ticket="",
            cert_path=str(client_tls.cert_path),
            key_path=str(client_tls.key_path),
            bootstrap_token=join_res["bootstrap_token"],
            network_id=net_id_obj.network_id,
        )
        phone_tunnel.set_peer_pinned_fingerprint(host_ident.device_id, join_res["host_cert_fingerprint"])

        try:
            self.assertTrue(await host_tunnel.connect())
            self.assertTrue(await phone_tunnel.connect())
            self.assertTrue(await phone_tunnel.initiate_e2e_tunnel(host_ident.device_id, timeout=5.0))

            # Bootstrap session MUST be blocked from addressing any peer other than bound host_device_id
            await phone_tunnel._ws.send_json({
                "type": "relay_frame",
                "target": "other-pc-2",
                "payload_b64": "AAAA",
            })

            # Unpaired phone MUST be denied normal capability even inside E2E tunnel
            from snow.protocol.models import SnowMessage
            await phone_tunnel.send_message(
                host_ident.device_id,
                SnowMessage.create_request("windows_system_info", {}),
            )
            denied = await phone_tunnel.receive_message(host_ident.device_id, timeout=5.0)
            self.assertIsNotNone(denied)
            self.assertEqual((denied.error or {}).get("code"), "UNAUTHORIZED")
            self.assertIsNone(host_db.get_paired_device(client_uuid))

            # Real pair_request via E2E tunnel verifies real PIN via PairingManager & pairs device!
            await phone_tunnel.send_message(
                host_ident.device_id,
                SnowMessage.create_request(
                    "pair_request",
                    {"device_id": client_uuid, "device_name": "Remote Phone", "pin": real_pin},
                ),
            )
            paired_resp = await phone_tunnel.receive_message(host_ident.device_id, timeout=5.0)
            self.assertIsNotNone(paired_resp)
            self.assertEqual(paired_resp.payload.get("status"), "success")
            auth_tok = paired_resp.payload["data"]["auth_token"]
            self.assertTrue(len(auth_tok) >= 16)
            self.assertIsNotNone(host_db.get_paired_device(client_uuid))
        finally:
            await phone_tunnel.disconnect()
            await host_tunnel.disconnect()


class TestStage6CWS1BrightnessWmiFallback(unittest.TestCase):
    """WS1 3.4: DDC/CI first, WMI fallback, strict input bounds, no console window, never fake success."""

    def test_ddc_success_skips_wmi_fallback(self) -> None:
        wmi_called = []
        ctrl = WindowsSystemControls(
            set_brightness_fn=lambda lvl: {"success": True, "status": "SUCCESS", "level": lvl},
            wmi_brightness_fn=lambda lvl: wmi_called.append(lvl) or {"success": True, "status": "SUCCESS", "level": lvl},
        )
        res = ctrl.set_brightness_sync(65)
        self.assertTrue(res["success"])
        self.assertEqual(res["level"], 65)
        self.assertEqual(wmi_called, [])

    def test_wmi_fallback_succeeds_when_ddc_unsupported(self) -> None:
        wmi_called = []
        ctrl = WindowsSystemControls(
            set_brightness_fn=lambda lvl: {"success": False, "status": "UNSUPPORTED_DISPLAY", "error": "no ddc"},
            wmi_brightness_fn=lambda lvl: wmi_called.append(lvl) or {
                "success": True,
                "status": "SUCCESS",
                "level": lvl,
                "method": "wmi",
            },
        )
        res = ctrl.set_brightness_sync(42)
        self.assertTrue(res["success"])
        self.assertEqual(res["method"], "wmi")
        self.assertEqual(wmi_called, [42])

    def test_both_fail_never_fakes_success_and_rejects_malformed_inputs(self) -> None:
        ctrl = WindowsSystemControls(
            set_brightness_fn=lambda _: {"success": False, "status": "UNSUPPORTED_DISPLAY", "error": "no ddc"},
            wmi_brightness_fn=lambda _: {"success": False, "status": "UNSUPPORTED_DISPLAY", "error": "no wmi"},
        )
        res = ctrl.set_brightness_sync(50)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "UNSUPPORTED_DISPLAY")

        for bad in (True, False, -1, 101, 50.5, "50", None):
            r = ctrl.set_brightness_sync(bad)
            self.assertFalse(r["success"])
            self.assertEqual(r["status"], "INVALID_BRIGHTNESS_LEVEL")

    def test_default_wmi_subprocess_uses_no_window_and_env_passing(self) -> None:
        captured: dict = {}

        def _fake_run(cmd, env=None, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = env
            captured["kwargs"] = kwargs
            return subprocess.CompletedProcess(cmd, 0, stdout="1\n", stderr="")

        with patch("sys.platform", "win32"), patch("subprocess.run", side_effect=_fake_run):
            res = _default_set_brightness_wmi(75)
        self.assertTrue(res["success"])
        self.assertEqual(res["method"], "wmi")
        self.assertEqual(captured["env"]["SNOW_BRIGHTNESS_LEVEL"], "75")
        self.assertFalse(captured["kwargs"].get("shell", False))
        # Creationflags / STARTF_USESHOWWINDOW passed on win32
        self.assertEqual(captured["cmd"][0], "powershell.exe")
