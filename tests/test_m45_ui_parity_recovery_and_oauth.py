"""Milestone 4.5 comprehensive regression & headless browser UI/UX parity suite."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
import unittest

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from snow.core.config import CoreConfig
from snow.core.ipc import IPC_PROTOCOL_VERSION, SnowIpcServer
from snow.mcp.oauth import OAuthServer
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import (
    DeviceIdentity,
    export_device_recovery_key,
    generate_snow_id,
    load_or_create_device_key_identity,
    resolve_canonical_device_snow_id,
)
import hashlib
import hmac
from snow.security.pairing import PairingManager, create_qr_pairing_payload
from snow.web.server import SnowWebServer
from tests.test_m41_unit2_lifecycle_web import _CdpClient, _find_chromium_binary

REPO_ROOT = Path(__file__).resolve().parents[1]
STATIC_DIR = REPO_ROOT / "src" / "snow" / "web" / "static"
SNOW_ID_PATTERN = re.compile(r"^SNW-[A-F0-9]{4}-[A-F0-9]{4}$")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class TestM45CanonicalIdentityZeroPinAndLegacyAlias(unittest.IsolatedAsyncioTestCase):
    """Verify M4.5 item 2.1 (canonical Ed25519 SNOW ID + legacy alias) & item 5.1 (zero-PIN QR v2)."""

    async def asyncSetUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmpdir.name) / "data"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._env_patch = patch.dict(os.environ, {"SNOW_DATA_DIR": str(self.data_dir)}, clear=False)
        self._env_patch.start()
        self.db = DatabaseManager(self.data_dir / "snow_devices.db")
        self.pairing = PairingManager()
        self.key_ident = load_or_create_device_key_identity(data_dir=self.data_dir)

    async def asyncTearDown(self) -> None:
        self._env_patch.stop()
        shutil.rmtree(self._tmpdir.name, ignore_errors=True)

    async def test_canonical_snow_id_matches_ed25519_and_resolves_legacy_alias(self) -> None:
        legacy_uuid = "550e8400-e29b-41d4-a716-446655440000"
        legacy_ident = DeviceIdentity(
            device_id=legacy_uuid,
            snow_id=generate_snow_id(seed=legacy_uuid),
            device_name="TestPC",
            created_at="2026-01-01T00:00:00Z",
        )
        canonical_id, legacy_alias = resolve_canonical_device_snow_id(
            data_dir=self.data_dir,
            fallback_identity=legacy_ident,
        )
        self.assertEqual(canonical_id, self.key_ident.snow_id)
        self.assertRegex(canonical_id, SNOW_ID_PATTERN)
        self.assertEqual(legacy_alias, legacy_ident.snow_id)
        self.assertNotEqual(canonical_id, legacy_alias)

        secret_file = self.data_dir / ".ipc_secret"
        secret_file.write_text("m45-ipc-test-secret-0123456789", encoding="utf-8")
        cfg = CoreConfig(
            port=8765,
            transfer_port=8766,
            ipc_secret_path=str(secret_file),
        )
        core = SimpleNamespace(
            config=cfg,
            device_identity=legacy_ident,
            db_manager=self.db,
            tls_manager=SimpleNamespace(get_certificate_fingerprint=lambda: "A" * 64),
            node_registry=MagicMock(get_all_devices=lambda: []),
            ws_server=SimpleNamespace(
                _relay_client=None,
                active_clients={},
                pairing_manager=self.pairing,
                certificate_info=SimpleNamespace(fingerprint_sha256="A" * 64),
            ),
            capability_engine=SimpleNamespace(db_manager=self.db),
            transfer_server=None,
            transfer_manager=None,
            http_transfer_server=None,
            app_registry=None,
            is_paused=False,
        )
        ipc = SnowIpcServer(core, cfg)
        owner_tok = hmac.new(
            ipc.secret.encode("utf-8"), b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256
        ).hexdigest()

        async def _call(op: str, payload: dict | None = None) -> dict:
            resp, _ = await ipc._dispatch_request(
                {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": f"req-{op}",
                    "op": op,
                    "auth_token": ipc.secret,
                    "owner_token": owner_tok,
                    "payload": payload or {},
                },
                True,
            )
            return resp

        # Live zero-PIN pairing state issues handshake_token without active PIN
        state_res = await _call("get_pairing_state")
        self.assertTrue(state_res["success"], state_res)
        state_data = state_res["data"]
        self.assertEqual(state_data["snow_id"], self.key_ident.snow_id)
        self.assertEqual(state_data["legacy_snow_id"], legacy_ident.snow_id)
        self.assertFalse(state_data["has_active_pin"])
        self.assertNotIn("pin", state_data)
        qr_v2 = state_data["qr_payload"] if isinstance(state_data["qr_payload"], dict) else json.loads(state_data["qr_payload"])
        self.assertEqual(qr_v2["v"], 2)
        self.assertEqual(qr_v2["snow_id"], self.key_ident.snow_id)
        self.assertTrue(qr_v2.get("handshake_token"))
        self.assertNotIn("pin", qr_v2)

        # Explicit zero_pin QR generation never leaks PIN
        zero_res = await _call("generate_pairing_qr", {"trust_tier": "owner", "include_pin": False})
        self.assertTrue(zero_res["success"], zero_res)
        zero_qr = zero_res["data"] if isinstance(zero_res["data"], dict) else json.loads(zero_res["data"])
        self.assertEqual(zero_qr["v"], 2)
        self.assertEqual(zero_qr["snow_id"], self.key_ident.snow_id)
        self.assertTrue(zero_qr.get("handshake_token"))
        self.assertNotIn("pin", zero_qr)

        # Optional 6-digit PIN QR generation produces 6-digit PIN + canonical SNOW ID
        pin_res = await _call("generate_pairing_qr", {"trust_tier": "owner", "include_pin": True})
        self.assertTrue(pin_res["success"], pin_res)
        pin_qr = pin_res["data"] if isinstance(pin_res["data"], dict) else json.loads(pin_res["data"])
        self.assertRegex(pin_qr["pin"], r"^\d{6}$")
        self.assertEqual(pin_qr["snow_id"], self.key_ident.snow_id)

        # Cancelling PIN keeps zero-PIN live QR operational
        cancel_res = await _call("cancel_pairing_pin")
        self.assertTrue(cancel_res["success"], cancel_res)
        after_cancel = await _call("get_pairing_state")
        after_data = after_cancel["data"]
        self.assertFalse(after_data["has_active_pin"])
        self.assertEqual(after_data["snow_id"], self.key_ident.snow_id)
        after_qr = after_data["qr_payload"] if isinstance(after_data["qr_payload"], dict) else json.loads(after_data["qr_payload"])
        self.assertTrue(after_qr.get("handshake_token"))

    async def test_ws_peer_relay_lookup_accepts_canonical_and_legacy_alias(self) -> None:
        self.db.insert_paired_device(
            device_id="phone-m45",
            device_name="Realme Phone",
            platform="android",
            trust_tier="owner",
            auth_token_hash=hash_token("peer-tok-m45"),
        )
        self.db.set_setting("device_snow_id:phone-m45", "SNW-CAFE-BABE")
        self.db.set_setting("device_legacy_snow_id:phone-m45", "SNW-1111-2222")

        by_canon = self.db.find_paired_device_by_identifier("SNW-CAFE-BABE")
        by_alias = self.db.find_paired_device_by_identifier("SNW-1111-2222")
        self.assertIsNotNone(by_canon)
        self.assertIsNotNone(by_alias)
        self.assertEqual(by_canon.device_id, "phone-m45")
        self.assertEqual(by_alias.device_id, "phone-m45")


class TestM45WebRecoveryQrAndOAuthEndpoints(AioHTTPTestCase):
    """Verify M4.5 item 2.3 (recovery takeover), 3.2 (OAuth client list/revoke), 5.1/5.3 (/api/pair/qr/*)."""

    async def get_application(self):
        self._tmpdir = tempfile.mkdtemp(prefix="snow_m45_web_")
        self._prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = self._tmpdir
        self.addCleanup(shutil.rmtree, self._tmpdir, True)
        self.addCleanup(
            lambda: os.environ.__setitem__("SNOW_DATA_DIR", self._prev_data_dir)
            if self._prev_data_dir is not None
            else os.environ.pop("SNOW_DATA_DIR", None)
        )

        self.db = DatabaseManager(Path(self._tmpdir) / "snow_devices.db")
        self.oauth = OAuthServer(db_manager=self.db)
        self.key_ident = load_or_create_device_key_identity(data_dir=Path(self._tmpdir))

        self.bridge = MagicMock()
        self.bridge.capability_engine = MagicMock(db_manager=self.db)
        self.bridge.daemon_manager = MagicMock()
        self.bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)
        self.bridge.call = AsyncMock(return_value={"success": True, "data": {}})
        self.bridge.mesh_connect_peer = AsyncMock(
            return_value={
                "success": True,
                "status": "CONNECTED",
                "data": {
                    "host": "192.168.1.44",
                    "port": 8765,
                    "network_conflict": True,
                    "merge_tx_id": "tx-m45-1",
                    "source_network_id": "SNW-NET-11112222",
                    "target_network_id": "SNW-NET-AAAABBBB",
                },
            }
        )

        self.web_srv = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.bridge,
            auto_open_browser=False,
        )
        self.web_srv.db_manager = self.db
        self.web_srv._mcp_gateway_instance = MagicMock(
            oauth_server=self.oauth,
            _pending_authorizations={"req-1": {"id": "req-1"}},
            set_public_url=MagicMock(),
        )
        return self.web_srv._build_app()

    async def _auth(self) -> str:
        resp = await self.client.post("/api/auth/session", json={"token": self.web_srv.bootstrap_token})
        data = await resp.json()
        self.assertTrue(data["success"], data)
        return data["csrf_token"]

    async def test_oauth_clients_list_ownership_and_revocation(self) -> None:
        csrf = await self._auth()
        client_rec = self.oauth.register_client(
            redirect_uris=["http://127.0.0.1:49100/callback"],
            client_name="Claude Desktop M45",
            scope="snow:mcp",
            owner_snow_id=self.key_ident.snow_id,
        )
        client_id = str(client_rec["client_id"])
        acc_hash = hash_token("raw-access-m45")
        ref_hash = hash_token("raw-refresh-m45")
        self.db.save_oauth_token_record(
            access_token_hash=acc_hash,
            refresh_token_hash=ref_hash,
            client_id=client_id,
            scope="snow:mcp",
            family_id="fam-m45",
            expires_at=time.time() + 3600,
            refresh_expires_at=time.time() + 86400,
        )

        # Ownership mismatch must fail closed with 403
        r_wrong = await self.client.get("/api/mcp/oauth/clients?device_snow_id=SNW-0000-0000")
        self.assertEqual(r_wrong.status, 403)

        r_list = await self.client.get("/api/mcp/oauth/clients")
        self.assertEqual(r_list.status, 200)
        j_list = await r_list.json()
        self.assertTrue(j_list["success"])
        self.assertEqual(j_list["device_snow_id"], self.key_ident.snow_id)
        self.assertEqual(j_list["count"], 1)
        self.assertEqual(j_list["clients"][0]["client_id"], client_id)
        self.assertGreaterEqual(j_list["clients"][0]["active_token_count"], 1)

        # Missing CSRF rejected
        r_nocsrf = await self.client.post(
            "/api/mcp/oauth/clients/revoke",
            json={"client_id": client_id, "confirm": True},
        )
        self.assertEqual(r_nocsrf.status, 403)

        # Missing confirm=true rejected
        r_noconfirm = await self.client.post(
            "/api/mcp/oauth/clients/revoke",
            json={"client_id": client_id, "confirm": False},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(r_noconfirm.status, 400)

        # Wrong device owner rejected with 403
        r_bad_owner = await self.client.post(
            "/api/mcp/oauth/clients/revoke",
            json={"client_id": client_id, "confirm": True, "device_snow_id": "SNW-9999-9999"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(r_bad_owner.status, 403)

        # Authorized revocation wipes client + access + refresh tokens/families immediately
        r_rev = await self.client.post(
            "/api/mcp/oauth/clients/revoke",
            json={"client_id": client_id, "confirm": True},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(r_rev.status, 200)
        j_rev = await r_rev.json()
        self.assertEqual(j_rev["status"], "CLIENT_REVOKED")
        self.assertIsNone(self.db.get_oauth_client(client_id))
        self.assertIsNone(self.db.get_oauth_access_token(acc_hash))
        with self.db._get_connection() as conn:
            rem = conn.execute(
                "SELECT COUNT(*) FROM oauth_tokens WHERE client_id = ? AND revoked = 0;",
                (client_id,),
            ).fetchone()[0]
        self.assertEqual(rem, 0)

    async def test_web_recovery_triggers_recovery_takeover_via_mcp_gateway_instance(self) -> None:
        csrf = await self._auth()
        rec_key = export_device_recovery_key(self.key_ident)

        fake_tm = MagicMock()
        fake_tm.get_status.return_value = {"active": True, "provider": "render"}
        fake_tm.stop_tunnel = AsyncMock(return_value={"success": True})
        self.web_srv.tunnel_manager = fake_tm
        self.web_srv.ensure_remote_ai_link_running = AsyncMock(
            return_value={"success": True, "public_url": f"https://hub.example/u/{self.key_ident.snow_id}/mcp"}
        )

        with patch("snow.mcp.tunnel.is_remote_ai_link_enabled", return_value=True):
            r_restore = await self.client.post(
                "/api/identity/recovery/restore",
                json={"recovery_key": rec_key, "confirm": True},
                headers={"X-CSRF-Token": csrf},
            )
        self.assertEqual(r_restore.status, 200)
        j_restore = await r_restore.json()
        self.assertTrue(j_restore["success"])
        self.assertEqual(j_restore["gateway_takeover"], "TAKEN_OVER")
        self.assertTrue(j_restore["gateway_active"])
        self.web_srv.ensure_remote_ai_link_running.assert_awaited_once_with(
            mark_enabled=False,
            recovery_takeover=True,
        )
        self.assertEqual(self.web_srv._mcp_gateway_instance._pending_authorizations, {})

    async def test_qr_validate_and_accept_and_canonical_tunnel_qr(self) -> None:
        csrf = await self._auth()
        payload_json = create_qr_pairing_payload(
            node_id="phone-m45",
            candidate_ips=["192.168.1.44"],
            port=8765,
            cert_fingerprint="C" * 64,
            handshake_token="m45-handshake-token-0123456789abcdef",
            snow_id="SNW-AAAA-BBBB",
            network_id="SNW-NET-11112222",
            device_type="android",
        )

        # Validate QR JSON
        r_val = await self.client.post(
            "/api/pair/qr/validate",
            json={"qr_json": payload_json},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(r_val.status, 200)
        j_val = await r_val.json()
        self.assertTrue(j_val["valid"])
        self.assertEqual(j_val["summary"]["snow_id"], "SNW-AAAA-BBBB")
        self.assertTrue(j_val["summary"]["has_handshake_token"])

        # Bad QR JSON rejected cleanly
        r_bad = await self.client.post(
            "/api/pair/qr/validate",
            json={"qr_json": '{"v":2}'},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(r_bad.status, 400)

        # Accept QR JSON connects peer & returns merge conflict details
        r_acc = await self.client.post(
            "/api/pair/qr/accept",
            json={"qr_json": payload_json},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(r_acc.status, 200)
        j_acc = await r_acc.json()
        self.assertTrue(j_acc["success"])
        self.assertEqual(j_acc["snow_id"], "SNW-AAAA-BBBB")
        self.assertTrue(j_acc["network_conflict"])
        self.assertEqual(j_acc["merge_tx_id"], "tx-m45-1")

        # Remote AI Link QR must embed canonical permanent device SNOW ID
        r_mcp_qr = await self.client.get("/api/mcp/tunnel/qr")
        self.assertEqual(r_mcp_qr.status, 200)
        j_mcp_qr = await r_mcp_qr.json()
        self.assertIn(f"/u/{self.key_ident.snow_id}/mcp", j_mcp_qr["url"])


class TestM45WebUiHeadlessEdgeCDPAudit(unittest.IsolatedAsyncioTestCase):
    """Execute actual Web UI (index.html + app.css + app.js) in headless Microsoft Edge / Chromium V8 DOM."""

    async def test_light_and_dark_themes_viewports_and_m45_interactions(self) -> None:
        browser_bin = _find_chromium_binary()
        if not browser_bin:
            self.skipTest("No Chrome/Edge browser binary available for M4.5 CDP audit")

        app = web.Application()
        app.router.add_get("/", lambda req: web.FileResponse(STATIC_DIR / "index.html"))
        app.router.add_static("/static", STATIC_DIR)
        app.router.add_route("*", "/{tail:.*}", lambda req: web.json_response({"success": True}))

        runner = web.AppRunner(app)
        await runner.setup()
        port = _find_free_port()
        site = web.TCPSite(runner, "127.0.0.1", port)
        await site.start()

        user_data_dir = tempfile.mkdtemp(prefix="snow_m45_cdp_")
        browser_proc: subprocess.Popen | None = None
        cdp: _CdpClient | None = None
        try:
            browser_proc = subprocess.Popen(
                [
                    browser_bin,
                    "--headless=new",
                    "--remote-debugging-port=0",
                    f"--user-data-dir={user_data_dir}",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-gpu",
                    "about:blank",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            devtools_port = None
            devtools_file = Path(user_data_dir) / "DevToolsActivePort"
            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                if devtools_file.exists():
                    lines = devtools_file.read_text(encoding="utf-8").splitlines()
                    if lines and lines[0].strip().isdigit():
                        devtools_port = int(lines[0].strip())
                        break
                await asyncio.sleep(0.1)
            self.assertIsNotNone(devtools_port, "Headless Edge/Chromium did not publish DevToolsActivePort")

            with urllib.request.urlopen(f"http://127.0.0.1:{devtools_port}/json/list", timeout=3.0) as resp:
                targets = json.loads(resp.read().decode("utf-8"))
            page_ws = next(t["webSocketDebuggerUrl"] for t in targets if t.get("type") == "page")

            cdp = _CdpClient(page_ws)
            await cdp.connect()
            await cdp.call("Page.enable")
            await cdp.call("Runtime.enable")
            await cdp.call("Emulation.setDeviceMetricsOverride", {
                "width": 1366, "height": 768, "deviceScaleFactor": 1, "mobile": False,
            })

            live_svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><rect width="100" height="100" fill="#000"/></svg>'
            harness = rf"""
(() => {{
    window.__AUDIT_STATE__ = {{
        oauthClients: [
            {{
                client_id: "claude-client-m45",
                client_name: "Claude Desktop M45",
                scope: "snow:mcp",
                active_token_count: 2,
                owner_snow_id: "SNW-ABCD-EF01",
            }}
        ],
        hasPin: false,
        tunnelEnabled: true,
        clipboardWrites: [],
        calls: [],
    }};
    Object.defineProperty(navigator, "clipboard", {{
        configurable: true,
        value: {{
            writeText: async (text) => {{
                window.__AUDIT_STATE__.clipboardWrites.push(String(text));
            }},
        }},
    }});
    window.fetch = async (url, opts = {{}}) => {{
        const urlStr = String(url);
        const body = opts && opts.body && typeof opts.body === "string" ? opts.body : "";
        window.__AUDIT_STATE__.calls.push({{ url: urlStr, method: (opts && opts.method) || "GET", body }});
        const ok = (obj) => new Response(JSON.stringify({{ success: true, ...obj }}), {{
            status: 200, headers: {{ "Content-Type": "application/json" }},
        }});
        if (urlStr.startsWith("/api/status")) {{
            return ok({{
                daemon_online: true,
                csrf_token: "m45-csrf",
                snow_id: "SNW-ABCD-EF01",
                device_id: "550e8400-e29b-41d4-a716-446655440000",
                device_name: "Lenovo V15",
                lan_ips: ["192.168.1.10"],
                telemetry: {{ cpu_percent: 12, ram_percent: 45 }},
            }});
        }}
        if (urlStr.startsWith("/api/identity/device")) {{
            return ok({{
                snow_id: "SNW-ABCD-EF01",
                permanent_mcp_url: "https://snow-relay.onrender.com/u/SNW-ABCD-EF01/mcp",
                device_identity: {{ snow_id: "SNW-ABCD-EF01", public_key_b64: "pubB64KeyTest" }},
            }});
        }}
        if (urlStr.startsWith("/api/identity/recovery/export")) {{
            const parsed = JSON.parse(body || "{{}}");
            if (parsed.passphrase) {{
                return ok({{ snow_id: "SNW-ABCD-EF01", encrypted_backup_json: JSON.stringify({{ kdf: "PBKDF2-SHA256", ct: "test" }}) }});
            }}
            return ok({{ snow_id: "SNW-ABCD-EF01", recovery_key: "SNW-REC-V1-TEST-SECRET-0123456789ABCDEF" }});
        }}
        if (urlStr.startsWith("/api/network/identity")) {{
            return ok({{ identity: {{ network_id: "SNW-NET-12345678", network_formed: true }} }});
        }}
        if (urlStr.startsWith("/api/network/merge/pending")) {{
            return ok({{ proposals: [] }});
        }}
        if (urlStr.startsWith("/api/devices")) {{
            return ok({{
                devices: [
                    {{ device_id: "local", is_local: true, is_connected: true, platform: "windows", snow_id: "SNW-ABCD-EF01", device_name: "Lenovo V15" }},
                    {{ device_id: "realme-p4", is_local: false, is_connected: true, platform: "android", device_type: "phone", snow_id: "SNW-9876-5432", device_name: "Realme P4", telemetry: {{ battery_level: 91 }} }},
                ],
            }});
        }}
        if (urlStr.startsWith("/api/pair/state")) {{
            return ok({{
                snow_id: "SNW-ABCD-EF01",
                network_id: "SNW-NET-12345678",
                has_active_pin: window.__AUDIT_STATE__.hasPin,
                pin: window.__AUDIT_STATE__.hasPin ? "654321" : "",
                remaining_seconds: window.__AUDIT_STATE__.hasPin ? 59 : 0,
                svg: {json.dumps(live_svg)},
            }});
        }}
        if (urlStr.startsWith("/api/pair/qr/validate")) {{
            return ok({{
                valid: true,
                summary: {{ snow_id: "SNW-PEER-2026", network_id: "SNW-NET-87654321", has_handshake_token: true }},
            }});
        }}
        if (urlStr.startsWith("/api/pair/qr/accept")) {{
            return ok({{
                snow_id: "SNW-PEER-2026",
                network_conflict: true,
                merge_tx_id: "tx-cdp-merge-1",
                source_network_id: "SNW-NET-12345678",
                target_network_id: "SNW-NET-87654321",
            }});
        }}
        if (urlStr.startsWith("/api/pair/qr")) {{
            window.__AUDIT_STATE__.hasPin = true;
            return ok({{
                snow_id: "SNW-ABCD-EF01",
                network_id: "SNW-NET-12345678",
                pin: "654321",
                remaining_seconds: 60,
                svg: {json.dumps(live_svg)},
            }});
        }}
        if (urlStr.startsWith("/api/mcp/oauth/clients/revoke")) {{
            window.__AUDIT_STATE__.oauthClients = [];
            return ok({{ status: "CLIENT_REVOKED" }});
        }}
        if (urlStr.startsWith("/api/mcp/oauth/clients")) {{
            return ok({{ device_snow_id: "SNW-ABCD-EF01", clients: window.__AUDIT_STATE__.oauthClients, count: window.__AUDIT_STATE__.oauthClients.length }});
        }}
        if (urlStr.startsWith("/api/mcp/tunnel/qr")) {{
            return ok({{ endpoint_url: "https://snow-relay.onrender.com/u/SNW-ABCD-EF01/mcp", svg: {json.dumps(live_svg)} }});
        }}
        if (urlStr.startsWith("/api/mcp/tunnel/status")) {{
            const en = window.__AUDIT_STATE__.tunnelEnabled;
            return ok({{
                enabled: en,
                active: en,
                provider: "render",
                configured_render_url: "https://snow-relay.onrender.com/u/SNW-ABCD-EF01/mcp",
                mcp_endpoint: en ? "https://snow-relay.onrender.com/u/SNW-ABCD-EF01/mcp" : null,
            }});
        }}
        if (urlStr.startsWith("/api/mcp/tunnel/stop")) {{
            window.__AUDIT_STATE__.tunnelEnabled = false;
            return ok({{ enabled: false, active: false }});
        }}
        if (urlStr.startsWith("/api/mcp/tunnel/start")) {{
            window.__AUDIT_STATE__.tunnelEnabled = true;
            return ok({{ enabled: true, active: true, mcp_endpoint: "https://snow-relay.onrender.com/u/SNW-ABCD-EF01/mcp" }});
        }}
        if (urlStr.startsWith("/api/mcp-gateway/status")) {{
            return ok({{
                data: {{
                    ai_hosts: [
                        {{ host: "claude", is_configured: true }},
                        {{ host: "chatgpt", is_configured: false }},
                        {{ host: "gemini", is_configured: true }},
                    ],
                }},
            }});
        }}
        if (urlStr.startsWith("/api/clipboard/buffer")) {{
            return ok({{ data: {{ items: [], count: 0 }} }});
        }}
        return ok({{ pending: [], grants: [], files: [], apps: [] }});
    }};
}})();
"""
            await cdp.call("Page.addScriptToEvaluateOnNewDocument", {"source": harness})
            await cdp.call("Page.navigate", {"url": f"http://127.0.0.1:{port}/?token=cdp"})
            await asyncio.sleep(0.8)

            # Check Light and Dark themes across 1366x768, 1280x720, and 390x844 across all 5 tabs + zero overlap
            for theme in ("light", "dark"):
                await cdp.eval(f'document.documentElement.setAttribute("data-theme", "{theme}");')
                for vw, vh in ((1366, 768), (1280, 720), (390, 844)):
                    await cdp.call("Emulation.setDeviceMetricsOverride", {
                        "width": vw, "height": vh, "deviceScaleFactor": 1, "mobile": vw < 600,
                    })
                    for tab in ("overview", "clipboard", "files", "devices", "settings"):
                        metrics = await cdp.eval(rf"""
(async () => {{
    const btn = document.querySelector('.nav-item[data-tab="{tab}"]');
    if (btn) btn.click();
    await new Promise(r => setTimeout(r, 80));
    const doc = document.documentElement;
    const checkOverlaps = (selector) => {{
        const els = Array.from(document.querySelectorAll(selector)).filter(el => {{
            const s = getComputedStyle(el);
            const r = el.getBoundingClientRect();
            return s.display !== 'none' && s.visibility !== 'hidden' && r.width > 0 && r.height > 0;
        }});
        const overlaps = [];
        for (let i = 0; i < els.length; i++) {{
            const a = els[i].getBoundingClientRect();
            for (let j = i + 1; j < els.length; j++) {{
                const b = els[j].getBoundingClientRect();
                const ix = Math.min(a.right, b.right) - Math.max(a.left, b.left);
                const iy = Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top);
                if (ix > 2 && iy > 2) overlaps.push([els[i].id || els[i].tagName, els[j].id || els[j].tagName]);
            }}
        }}
        return overlaps;
    }};
    const overlaps = [
        ...checkOverlaps('#pair-pane-qr button, #pair-pane-qr input'),
        ...checkOverlaps('.ai-assistant-grid .ai-card'),
        ...checkOverlaps('#remote-ai-link-card input, #remote-ai-link-card button'),
    ];
    return {{
        scrollWidth: doc.scrollWidth,
        clientWidth: doc.clientWidth,
        overlaps,
    }};
}})()
""")
                        self.assertLessEqual(
                            metrics["scrollWidth"],
                            metrics["clientWidth"] + 2,
                            f"Horizontal overflow in theme={theme} viewport={vw}x{vh} tab={tab}: {metrics}",
                        )
                        self.assertEqual(
                            metrics["overlaps"],
                            [],
                            f"Overlapping controls in theme={theme} viewport={vw}x{vh} tab={tab}: {metrics['overlaps']}",
                        )

            # Desktop 1366x768 interactive functional verification on Devices + AI & Settings
            await cdp.call("Emulation.setDeviceMetricsOverride", {
                "width": 1366, "height": 768, "deviceScaleFactor": 1, "mobile": False,
            })
            dev_check = await cdp.eval(r"""
(async () => {
    document.querySelector('.nav-item[data-tab="devices"]')?.click();
    await new Promise(r => setTimeout(r, 150));
    const qrHasSvg = Boolean(document.querySelector('#pairing-qr-box svg'));
    const mySnowId = document.getElementById('pairing-snow-id')?.textContent?.trim();
    const myNetId = document.getElementById('pairing-network-id')?.textContent?.trim();
    const hasFedCard = Boolean(document.getElementById('cross-network-federation-card'));
    const bodyText = document.body.innerText;

    document.getElementById('btn-pairing-refresh-qr')?.click();
    await new Promise(r => setTimeout(r, 150));
    const pinAfter = document.getElementById('pairing-pin-display')?.textContent?.trim();

    const acc = document.getElementById('paste-qr-json-accordion');
    if (acc) acc.open = true;
    document.getElementById('pairing-qr-json-input').value = JSON.stringify({
        v: 2, snow_id: "SNW-PEER-2026", handshake_token: "tok", ips: ["192.168.1.50"], port: 8765, fp: "C".repeat(64)
    });
    document.getElementById('btn-validate-qr-json')?.click();
    await new Promise(r => setTimeout(r, 120));
    const valPreview = document.getElementById('pairing-qr-json-preview')?.textContent?.trim();

    document.getElementById('btn-accept-qr-json')?.click();
    await new Promise(r => setTimeout(r, 150));
    const mergeModalEl = document.getElementById('network-merge-decision-modal');
    const mergeModalOpen = Boolean(mergeModalEl) && !mergeModalEl.classList.contains('d-none');
    document.getElementById('btn-close-merge-modal')?.click();

    return {
        qrHasSvg, mySnowId, myNetId, hasFedCard, pinAfter, valPreview, mergeModalOpen,
        rawUuidInDevices: /\b550e8400-e29b-41d4-a716-446655440000\b/i.test(bodyText),
    };
})()
""")
            self.assertTrue(dev_check["qrHasSvg"], dev_check)
            self.assertEqual(dev_check["mySnowId"], "SNW-ABCD-EF01")
            self.assertEqual(dev_check["myNetId"], "SNW-NET-12345678")
            self.assertFalse(dev_check["hasFedCard"])
            self.assertIn("654", dev_check["pinAfter"])
            self.assertIn("Valid QR v2", dev_check["valPreview"])
            self.assertTrue(dev_check["mergeModalOpen"])
            self.assertFalse(dev_check["rawUuidInDevices"])

            settings_check = await cdp.eval(r"""
(async () => {
    document.querySelector('.nav-item[data-tab="settings"]')?.click();
    await new Promise(r => setTimeout(r, 180));
    const aiCardCount = document.querySelectorAll('.ai-assistant-grid .ai-card').length;
    const hasCursor = Boolean(document.getElementById('btn-setup-cursor'));
    const hasHandledAuto = document.body.innerText.includes('Handled automatically');
    const advOpen = Boolean(document.querySelector('#advanced-diagnostics-card details.advanced-accordion')?.open);
    const mcpUrl = document.getElementById('mcp-tunnel-url-display')?.value;

    // Top-level Remote AI Link Copy, Show QR, and Toggle
    document.getElementById('btn-mcp-copy-url')?.click();
    await new Promise(r => setTimeout(r, 60));
    const copiedMcpUrl = window.__AUDIT_STATE__.clipboardWrites.includes(mcpUrl);

    document.getElementById('btn-mcp-tunnel-show-qr')?.click();
    await new Promise(r => setTimeout(r, 120));
    const mcpQrModalEl = document.getElementById('mcp-qr-modal');
    const mcpQrModalOpen = Boolean(mcpQrModalEl) && !mcpQrModalEl.classList.contains('d-none');
    const mcpQrHasSvg = Boolean(document.querySelector('#mcp-qr-svg-container svg'));
    document.getElementById('btn-close-mcp-qr')?.click();

    const chk = document.getElementById('chk-mcp-tunnel-toggle');
    chk.checked = false;
    chk.dispatchEvent(new Event('change'));
    await new Promise(r => setTimeout(r, 150));
    const statusAfterStop = document.getElementById('mcp-tunnel-status')?.textContent?.trim();

    // Revoke OAuth client via confirm modal
    const oauthCardsBefore = document.querySelectorAll('#oauth-clients-list-container .btn-revoke-oauth-client').length;
    document.querySelector('#oauth-clients-list-container .btn-revoke-oauth-client')?.click();
    await new Promise(r => setTimeout(r, 80));
    const revokeModalEl = document.getElementById('oauth-revoke-modal');
    const revokeModalOpen = Boolean(revokeModalEl) && !revokeModalEl.classList.contains('d-none');
    document.getElementById('btn-oauth-revoke-confirm')?.click();
    await new Promise(r => setTimeout(r, 150));
    const oauthCardsAfter = document.querySelectorAll('#oauth-clients-list-container .btn-revoke-oauth-client').length;

    // Open Advanced Settings -> Recovery key reveal does NOT auto-copy and clears on close
    const advDetails = document.querySelector('#advanced-diagnostics-card details.advanced-accordion');
    if (advDetails) advDetails.open = true;
    const writesBeforeReveal = window.__AUDIT_STATE__.clipboardWrites.length;
    document.getElementById('btn-open-recovery-key')?.click();
    await new Promise(r => setTimeout(r, 80));
    document.getElementById('btn-recovery-reveal-confirm')?.click();
    await new Promise(r => setTimeout(r, 150));
    const revealedKey = document.getElementById('recovery-key-secret-output')?.textContent?.trim();
    const writesAfterReveal = window.__AUDIT_STATE__.clipboardWrites.length;
    document.getElementById('btn-recovery-close-key')?.click();
    await new Promise(r => setTimeout(r, 80));
    const clearedKey = document.getElementById('recovery-key-secret-output')?.textContent?.trim();

    return {
        aiCardCount, hasCursor, hasHandledAuto, advOpen, mcpUrl,
        copiedMcpUrl, mcpQrModalOpen, mcpQrHasSvg, statusAfterStop,
        oauthCardsBefore, revokeModalOpen, oauthCardsAfter,
        revealedKey, autoCopiedOnReveal: writesAfterReveal > writesBeforeReveal, clearedKey,
    };
})()
""")
            self.assertEqual(settings_check["aiCardCount"], 3)
            self.assertFalse(settings_check["hasCursor"])
            self.assertFalse(settings_check["hasHandledAuto"])
            self.assertFalse(settings_check["advOpen"])
            self.assertEqual(settings_check["mcpUrl"], "https://snow-relay.onrender.com/u/SNW-ABCD-EF01/mcp")
            self.assertTrue(settings_check["copiedMcpUrl"])
            self.assertTrue(settings_check["mcpQrModalOpen"])
            self.assertTrue(settings_check["mcpQrHasSvg"])
            self.assertEqual(settings_check["statusAfterStop"], "Off")
            self.assertEqual(settings_check["oauthCardsBefore"], 1)
            self.assertTrue(settings_check["revokeModalOpen"])
            self.assertEqual(settings_check["oauthCardsAfter"], 0)
            self.assertTrue(settings_check["revealedKey"].startswith("SNW-REC-V1-"))
            self.assertFalse(settings_check["autoCopiedOnReveal"])
            self.assertEqual(settings_check["clearedKey"], "")

            self.assertEqual(cdp.exceptions, [], f"Uncaught JS exceptions in CDP audit: {cdp.exceptions}")
            self.assertEqual(cdp.console_errors, [], f"Console errors in CDP audit: {cdp.console_errors}")
        finally:
            if cdp is not None:
                await cdp.close()
            if browser_proc is not None and browser_proc.poll() is None:
                browser_proc.terminate()
                try:
                    browser_proc.wait(timeout=3)
                except Exception:
                    browser_proc.kill()
            shutil.rmtree(user_data_dir, ignore_errors=True)
            await runner.cleanup()


if __name__ == "__main__":
    unittest.main()
