"""M4.2 Matrix & Rendezvous Tests: QR v2/v1, Unified 60s 6-Digit PIN, Win<->Win & Real Render Hub Rendezvous."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import json
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch
import uuid

import aiohttp
from aiohttp.test_utils import AioHTTPTestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from snow.core.config import CoreConfig
from snow.core.ipc import IPC_PROTOCOL_VERSION, SnowIpcServer
from snow.core.server import SnowCoreServer
from snow.network.peer_client import SnowPeerClient
from snow.network.relay_client import RelayTunnelClient
from snow.protocol.models import SnowMessage
from snow.relay.auth import is_valid_network_id
from snow.relay.config import RelayConfig
from snow.relay.server import SnowRelayServer
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity, load_or_create_network_key_identity
from snow.security.pairing import (
    PairingManager,
    PairingOutcome,
    create_qr_pairing_payload,
    validate_qr_pairing_payload,
)
from snow.security.tls import ensure_tls_certificate


class TestM42UnifiedPinAndQrV2(unittest.TestCase):
    """Deterministic unified 6-digit 60s PIN & QR v2/v1 contract validation."""

    def test_unified_60s_pin_expiry_single_use_cancel_lockout_and_stderr_only(self) -> None:
        now = [2000.0]
        pm = PairingManager(pin_lifetime=60.0, max_attempts=3, time_provider=lambda: now[0])

        out_buf = io.StringIO()
        err_buf = io.StringIO()
        old_out, old_err = sys.stdout, sys.stderr
        try:
            sys.stdout, sys.stderr = out_buf, err_buf
            pin = pm.generate_pin(display_to_stderr=True, trust_tier="owner")
        finally:
            sys.stdout, sys.stderr = old_out, old_err

        self.assertEqual(out_buf.getvalue(), "")
        self.assertIn(pin, err_buf.getvalue())
        self.assertEqual(len(pin), 6)
        self.assertTrue(pin.isdigit())

        state = pm.get_active_pin_state(include_pin=True)
        self.assertEqual(state["pin"], pin)
        self.assertNotIn("owner_pin", state)
        self.assertNotIn("peer_pin", state)

        # Cancel clears both PIN and handshake token immediately
        tok = pm.issue_handshake_token("host-1", network_id="", ttl_seconds=60.0)
        cancel_res = pm.cancel_pin()
        self.assertTrue(cancel_res["cancelled"])
        self.assertFalse(pm.has_active_pin)
        self.assertEqual(pm.verify_handshake_token(tok, "host-1").outcome, PairingOutcome.INVALID_PIN)

        # Expiry at exactly 60s
        pin2 = pm.generate_pin(display_to_stderr=False)
        now[0] = 2059.0
        self.assertTrue(pm.has_active_pin)
        now[0] = 2060.0
        self.assertFalse(pm.has_active_pin)
        exp_res = pm.verify_pin(pin2, "peer-1")
        self.assertEqual(exp_res.outcome, PairingOutcome.EXPIRED)

        # 3-attempt lockout
        pm.generate_pin(display_to_stderr=False)
        r1 = pm.verify_pin("000001", "peer-2")
        r2 = pm.verify_pin("000002", "peer-2")
        r3 = pm.verify_pin("000003", "peer-2")
        self.assertEqual(r1.remaining_attempts, 2)
        self.assertEqual(r2.remaining_attempts, 1)
        self.assertEqual(r3.outcome, PairingOutcome.LOCKED)

    def test_qr_v2_fields_expiry_and_v1_compat(self) -> None:
        fp = "AB" * 32
        qr_v2 = create_qr_pairing_payload(
            node_id="pc-host-uuid",
            candidate_ips=["192.168.10.2", "10.0.0.5"],
            port=8765,
            cert_fingerprint=fp,
            handshake_token="t" * 24,
            version=2,
            device_type="windows",
            transfer_port=8766,
            network_id=None,
            rdv_id="rdv_test_1234",
            hub_url="https://snow-relay.onrender.com",
            expires_at=5060,
        )
        self.assertEqual(qr_v2["v"], 2)
        self.assertEqual(qr_v2["device_id"], "pc-host-uuid")
        self.assertIsNone(qr_v2["network_id"])
        self.assertEqual(qr_v2["ips"], ["192.168.10.2", "10.0.0.5"])

        parsed_ok = validate_qr_pairing_payload(json.dumps(qr_v2), now_ts=5059.0)
        self.assertEqual(parsed_ok["transfer_port"], 8766)
        self.assertEqual(parsed_ok["rdv_id"], "rdv_test_1234")
        self.assertIsNone(parsed_ok["network_id"])

        with self.assertRaises(ValueError):
            validate_qr_pairing_payload(json.dumps(qr_v2), now_ts=5061.0)

        qr_v1 = create_qr_pairing_payload(
            node_id="pc-host-uuid",
            candidate_ips=["192.168.10.2"],
            port=8765,
            cert_fingerprint=fp,
            pin="123456",
            version=1,
            network_id="SNW-NET-AABBCCDD",
        )
        parsed_v1 = validate_qr_pairing_payload(qr_v1)
        self.assertEqual(parsed_v1["v"], 1)
        self.assertEqual(parsed_v1["network_id"], "SNW-NET-AABBCCDD")

    def test_9digit_code_retired_from_primary_onboarding_prompts(self) -> None:
        root = Path(__file__).resolve().parents[1]
        html = (root / "src" / "snow" / "web" / "static" / "index.html").read_text(encoding="utf-8")
        connect_sheet = (root / "android" / "app" / "src" / "main" / "java" / "org" / "snow" / "ui" / "connect" / "SnowConnectSheet.kt").read_text(encoding="utf-8")
        self.assertNotIn("9-digit network", html)
        self.assertNotIn("9-digit", connect_sheet)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class TestM42WinToWinAndRenderHubRendezvous(AioHTTPTestCase):
    """End-to-end Win<->Win WSS pairing and Render Hub /v1/rendezvous/open + /cancel + /join + E2E TLS checks."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m42_rdv_"))
        await super().asyncSetUp()
        self.relay_port = self.server.port
        self.hub_url = f"http://127.0.0.1:{self.relay_port}"
        self.ws_url = f"ws://127.0.0.1:{self.relay_port}/v1/tunnel"

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def get_application(self):
        self.relay = SnowRelayServer(
            RelayConfig(host="127.0.0.1", port=0, shared_secret="m42-test-secret", host_lease_seconds=30.0)
        )
        return self.relay._build_app()

    async def test_win_to_win_qr_v2_multi_ip_fallback_and_cert_pinning(self) -> None:
        host_dir = self.tmp_dir / "win_host"
        peer_dir = self.tmp_dir / "win_peer"
        host_tls = ensure_tls_certificate(host_dir / "cert.pem", host_dir / "key.pem", active_ips=["127.0.0.1"])
        host_db = DatabaseManager(host_dir / "host.db")
        host_ident = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Host-Win-Laptop",
            created_at="2026-11-27T00:00:00Z",
            snow_id="SNW-HOST-W2W1",
        )
        cfg = CoreConfig(
            bind_host="127.0.0.1",
            port=_free_port(),
            ipc_port=_free_port(),
            transfer_port=_free_port(),
            discovery_enabled=False,
            tls_enabled=True,
            tls_cert_path=str(host_tls.cert_path),
            tls_key_path=str(host_tls.key_path),
        )
        core = SnowCoreServer(config=cfg, db_manager=host_db, device_identity=host_ident)
        core.ws_server.certificate_info = host_tls
        await core.ws_server.start()
        ws_port = core.ws_server.bound_port
        self.assertGreater(ws_port, 0)

        try:
            pin = core.ws_server.pairing_manager.generate_pin(display_to_stderr=False)
            htok = core.ws_server.pairing_manager.issue_handshake_token(host_ident.device_id, network_id="")
            qr = create_qr_pairing_payload(
                node_id=host_ident.device_id,
                candidate_ips=["10.255.255.1", "127.0.0.1"],
                port=ws_port,
                cert_fingerprint=host_tls.fingerprint_sha256,
                pin=pin,
                version=2,
                allow_usb_loopback=True,
                handshake_token=htok,
                network_id=None,
                device_type="windows",
                transfer_port=8766,
            )

            peer_ident = DeviceIdentity(
                device_id=str(uuid.uuid4()),
                device_name="Peer-Win-Desktop",
                created_at="2026-11-27T00:00:00Z",
                snow_id="SNW-PEER-W2W2",
            )

            # Wrong fingerprint blocked before trust
            bad_client = SnowPeerClient(
                host="127.0.0.1",
                port=ws_port,
                identity=peer_ident,
                expected_fingerprint="FF" * 32,
                use_tls=True,
            )
            bad_res = await bad_client.connect(handshake_token=htok, timeout=3.0)
            self.assertFalse(bad_res.success)
            self.assertEqual(bad_res.status, "FINGERPRINT_MISMATCH")

            # Sequential multi-IP QR v2 fallback succeeds on valid candidate IP
            real_ws_connect = sys.modules["snow.network.peer_client"].ws_connect

            async def _fast_fail_first_connect(uri, *args, **kwargs):
                if "10.255.255.1" in uri:
                    raise OSError("Simulated unreachable adapter")
                return await real_ws_connect(uri, *args, **kwargs)

            with patch("snow.network.peer_client.ws_connect", side_effect=_fast_fail_first_connect):
                client, pair_res = await SnowPeerClient.connect_from_qr(
                    qr,
                    local_identity=peer_ident,
                    allow_usb_loopback=True,
                    timeout=3.0,
                )
            self.assertIsNotNone(client)
            self.assertTrue(pair_res.success, msg=pair_res.error)
            self.assertEqual(pair_res.network_action, "FORMED")
            self.assertTrue(is_valid_network_id(pair_res.network_id))
            await client.close()

            # Replayed single-use handshake_token fails
            replay_client = SnowPeerClient(
                host="127.0.0.1",
                port=ws_port,
                identity=peer_ident,
                expected_fingerprint=host_tls.fingerprint_sha256,
                use_tls=True,
            )
            replay_res = await replay_client.connect(handshake_token=htok, timeout=3.0)
            self.assertFalse(replay_res.success)
        finally:
            await core.ws_server.stop()

    async def test_ipc_qr_v2_opens_and_cancels_hub_rendezvous_with_mitm_block(self) -> None:
        host_dir = self.tmp_dir / "hub_host"
        client_dir = self.tmp_dir / "hub_client"
        host_tls = ensure_tls_certificate(host_dir / "cert.pem", host_dir / "key.pem", active_ips=["127.0.0.1"])
        client_tls = ensure_tls_certificate(client_dir / "cert.pem", client_dir / "key.pem", active_ips=["127.0.0.1"])
        host_db = DatabaseManager(host_dir / "host.db")
        host_db.set_setting("default_hub_url", self.hub_url)
        host_ident = DeviceIdentity(
            device_id=f"ffffffff-{str(uuid.uuid4())[9:]}",
            device_name="Hub-Host-PC",
            created_at="2026-11-27T00:00:00Z",
            snow_id="SNW-HUBH-1234",
        )
        net_key = load_or_create_network_key_identity(data_dir=host_dir)

        with patch.dict("os.environ", {"SNOW_ALLOW_DEV_HUB_HTTP": "1"}, clear=False):
            cfg = CoreConfig(
                bind_host="127.0.0.1",
                port=_free_port(),
                ipc_port=_free_port(),
                transfer_port=_free_port(),
                discovery_enabled=False,
                tls_enabled=True,
                tls_cert_path=str(host_tls.cert_path),
                tls_key_path=str(host_tls.key_path),
                default_hub_url=self.hub_url,
            )
            core = SnowCoreServer(config=cfg, db_manager=host_db, device_identity=host_ident)
            core.ws_server.certificate_info = host_tls
            ipc = SnowIpcServer(core_server=core, config=cfg)
            ipc._secret = "m42-ipc-secret"
            owner_token = hmac.new(ipc._secret.encode("utf-8"), b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256).hexdigest()

            async def _ipc(op: str, payload: dict | None = None) -> dict:
                req = {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": str(uuid.uuid4()),
                    "op": op,
                    "auth_token": ipc._secret,
                    "owner_token": owner_token,
                    "payload": payload or {},
                }
                res, _ = await ipc._dispatch_request(req, is_connection_authenticated=True)
                return res

            with patch("snow.core.network.get_active_ip_addresses", return_value=["192.168.1.50"]), \
                 patch("snow.security.identity.load_or_create_network_key_identity", return_value=net_key), \
                 patch("snow.security.identity.load_or_create_device_identity", return_value=host_ident):
                qr_res = await _ipc("generate_pairing_qr", {"trust_tier": "owner"})
            self.assertTrue(qr_res["success"], msg=qr_res)
            qr_data = qr_res["data"]
            self.assertEqual(qr_data["v"], 2)
            self.assertIsNone(qr_data["network_id"])
            rdv_id_1 = qr_data.get("rdv_id")
            self.assertTrue(rdv_id_1)

            # Cancel PIN + rendezvous revokes the Hub rendezvous slot
            cancel_res = await _ipc("cancel_pairing_pin")
            self.assertTrue(cancel_res["success"])
            await asyncio.sleep(0.05)

            client_uuid = f"11111111-{str(uuid.uuid4())[9:]}"
            async with aiohttp.ClientSession() as http:
                r_revoked = await http.post(
                    f"{self.hub_url}/v1/rendezvous/join",
                    json={"rendezvous_id": rdv_id_1, "handshake_token": qr_data["handshake_token"], "client_device_id": client_uuid},
                )
                self.assertEqual(r_revoked.status, 401)

            # Re-open QR v2 -> join -> MITM wrong cert rejected before trust -> valid E2E TLS tunnel pairs!
            with patch("snow.core.network.get_active_ip_addresses", return_value=["192.168.1.50"]), \
                 patch("snow.security.identity.load_or_create_network_key_identity", return_value=net_key), \
                 patch("snow.security.identity.load_or_create_device_identity", return_value=host_ident):
                qr_res2 = await _ipc("generate_pairing_qr", {"trust_tier": "owner"})
            qr_2 = qr_res2["data"]
        async with aiohttp.ClientSession() as http:
            join_resp = await (await http.post(
                f"{self.hub_url}/v1/rendezvous/join",
                json={"rendezvous_id": qr_2["rdv_id"], "handshake_token": qr_2["handshake_token"], "client_device_id": client_uuid},
            )).json()
        self.assertTrue(join_resp["success"], msg=join_resp)
        self.assertFalse(join_resp["trust_completed"])
        self.assertIsNone(host_db.get_paired_device(client_uuid))

        host_rc = RelayTunnelClient(
            relay_url=self.ws_url,
            device_id=host_ident.device_id,
            group_id=join_resp["network_id"],
            ticket="",
            cert_path=str(host_tls.cert_path),
            key_path=str(host_tls.key_path),
            hub_token=core._active_rendezvous["hub_token"],
            network_id=join_resp["network_id"],
        )
        host_rc.set_peer_pinned_fingerprint(client_uuid, client_tls.fingerprint_sha256)
        host_rc.request_dispatcher = core._handle_incoming_relay_request

        # MITM fingerprint mismatch MUST block inner E2E TLS tunnel before any pair_request
        mitm_phone = RelayTunnelClient(
            relay_url=self.ws_url,
            device_id=client_uuid,
            group_id=join_resp["network_id"],
            ticket="",
            cert_path=str(client_tls.cert_path),
            key_path=str(client_tls.key_path),
            bootstrap_token=join_resp["bootstrap_token"],
            network_id=join_resp["network_id"],
        )
        mitm_phone.set_peer_pinned_fingerprint(host_ident.device_id, "00" * 32)
        try:
            self.assertTrue(await host_rc.connect())
            self.assertTrue(await mitm_phone.connect())
            tunnel_ok = await mitm_phone.initiate_e2e_tunnel(host_ident.device_id, timeout=3.0)
            self.assertFalse(tunnel_ok)
            self.assertIsNone(host_db.get_paired_device(client_uuid))
        finally:
            await mitm_phone.disconnect()
            await host_rc.disconnect()

        # Legitimate pinned fingerprint establishes E2E TLS tunnel & completes pairing
        host_rc2 = RelayTunnelClient(
            relay_url=self.ws_url,
            device_id=host_ident.device_id,
            group_id=join_resp["network_id"],
            ticket="",
            cert_path=str(host_tls.cert_path),
            key_path=str(host_tls.key_path),
            hub_token=core._active_rendezvous["hub_token"],
            network_id=join_resp["network_id"],
        )
        host_rc2.set_peer_pinned_fingerprint(client_uuid, client_tls.fingerprint_sha256)
        host_rc2.request_dispatcher = core._handle_incoming_relay_request

        real_phone = RelayTunnelClient(
            relay_url=self.ws_url,
            device_id=client_uuid,
            group_id=join_resp["network_id"],
            ticket="",
            cert_path=str(client_tls.cert_path),
            key_path=str(client_tls.key_path),
            bootstrap_token=join_resp["bootstrap_token"],
            network_id=join_resp["network_id"],
        )
        real_phone.set_peer_pinned_fingerprint(host_ident.device_id, join_resp["host_cert_fingerprint"])
        try:
            self.assertTrue(await host_rc2.connect())
            self.assertTrue(await real_phone.connect())
            self.assertTrue(await real_phone.initiate_e2e_tunnel(host_ident.device_id, timeout=4.0))
            await real_phone.send_message(
                host_ident.device_id,
                SnowMessage.create_request(
                    "pair_request",
                    {
                        "device_id": client_uuid,
                        "device_name": "Remote Phone",
                        "pin": qr_2["pin"],
                    },
                ),
            )
            resp = await real_phone.receive_message(host_ident.device_id, timeout=4.0)
            self.assertIsNotNone(resp)
            self.assertEqual(resp.payload.get("status"), "success")
            self.assertTrue(is_valid_network_id(resp.payload["data"].get("network_id")))
            self.assertIsNotNone(host_db.get_paired_device(client_uuid))
        finally:
            await real_phone.disconnect()
            await host_rc2.disconnect()


if __name__ == "__main__":
    unittest.main()
