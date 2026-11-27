"""Unit 1.1 Regression Tests: Authoritative QR Pairing & Strict Token/PIN Separation."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path
import shutil
import sys
import tempfile
import threading
import unittest
from unittest.mock import MagicMock, patch
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from snow.core.config import CoreConfig
from snow.core.ipc import IPC_PROTOCOL_VERSION, SnowIpcServer
from snow.core.server import SnowCoreServer
from snow.protocol.constants import ErrorCode
from snow.protocol.models import SnowMessage
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import DeviceIdentity, is_valid_uuidv4, load_or_create_network_key_identity
from snow.relay.auth import is_valid_network_id
from snow.security.pairing import (
    PairingManager,
    PairingOutcome,
    create_qr_pairing_payload,
    validate_qr_pairing_payload,
)
from snow.security.tls import ensure_tls_certificate


def _make_fake_client(conn_id: str = "conn-u11"):
    client = MagicMock()
    client.connection_id = conn_id
    client.remote_address = ("192.168.1.55", 51234)
    sent: list[dict] = []

    async def _send(raw: str) -> None:
        sent.append(json.loads(raw))

    client.websocket = MagicMock()
    client.websocket.send = _send
    return client, sent


class TestMilestone1Unit1QrPairingAndSeparation(unittest.IsolatedAsyncioTestCase):
    """Verify IPC-to-WSS identity binding, strict network binding, token/PIN exclusion, and UUIDv4 checks."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m1_u11_"))
        self.db = DatabaseManager(self.tmp_dir / "u11.db")
        self.host_identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Authoritative-Host-PC",
            created_at="2026-11-26T00:00:00Z",
            snow_id="SNW-HOST-1111",
        )
        self.net_identity = load_or_create_network_key_identity(data_dir=self.tmp_dir)
        self.cert_info = ensure_tls_certificate(
            self.tmp_dir / "cert.pem",
            self.tmp_dir / "key.pem",
            active_ips=["192.168.1.10"],
        )
        self.cfg = CoreConfig(
            port=8765,
            ipc_port=0,
            transfer_port=0,
            discovery_enabled=False,
            tls_cert_path=str(self.cert_info.cert_path),
            tls_key_path=str(self.cert_info.key_path),
        )
        self.core = SnowCoreServer(
            config=self.cfg,
            device_identity=self.host_identity,
            db_manager=self.db,
        )
        self.core.ws_server.certificate_info = self.cert_info
        self.ipc = SnowIpcServer(core_server=self.core, config=self.cfg)
        self.ipc._secret = "unit11-ipc-secret"
        self.owner_token = hmac.new(
            self.ipc._secret.encode("utf-8"),
            b"SNOW_OWNER_AUTHORIZATION",
            hashlib.sha256,
        ).hexdigest()

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def _ipc_call(self, op: str, payload: dict | None = None, owner: bool = True) -> dict:
        req = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": str(uuid.uuid4()),
            "op": op,
            "auth_token": self.ipc._secret,
            "payload": payload or {},
        }
        if owner:
            req["owner_token"] = self.owner_token
        res, _ = await self.ipc._dispatch_request(req, is_connection_authenticated=True)
        return res

    async def _generate_qr_via_ipc(self, trust_tier: str = "owner") -> dict:
        with patch("snow.core.network.get_active_ip_addresses", return_value=["192.168.1.10"]), \
             patch("snow.security.identity.load_or_create_network_key_identity", return_value=self.net_identity):
            res = await self._ipc_call("generate_pairing_qr", {"trust_tier": trust_tier})
        self.assertTrue(res["success"], msg=f"IPC generate_pairing_qr failed: {res}")
        return res["data"]

    async def test_01_02_end_to_end_ipc_qr_to_websocket_uses_authoritative_host_uuid(self) -> None:
        qr = await self._generate_qr_via_ipc(trust_tier="owner")
        # 2. Must use authoritative cs.device_identity.device_id, never "desktop-core"
        self.assertEqual(qr["v"], 2)
        self.assertEqual(qr["id"], self.host_identity.device_id)
        self.assertEqual(qr["device_id"], self.host_identity.device_id)
        self.assertTrue(is_valid_uuidv4(qr["id"]))
        # Standalone host has no shared mesh network until first pairing succeeds
        self.assertIsNone(qr.get("network_id"))
        self.assertIn("handshake_token", qr)
        self.assertIn("exp", qr)

        state_res = await self._ipc_call("get_pairing_state")
        self.assertTrue(state_res["success"])
        self.assertEqual(state_res["data"]["node_id"], self.host_identity.device_id)
        self.assertEqual(state_res["data"]["qr_payload"]["v"], 2)
        self.assertEqual(state_res["data"]["qr_payload"]["id"], self.host_identity.device_id)

        validated = validate_qr_pairing_payload(json.dumps(qr))
        self.assertEqual(validated["id"], self.host_identity.device_id)
        self.assertIsNone(validated.get("network_id"))

        # 1. End-to-end WS pair_request using QR v2 handshake_token forms canonical SNW-NET-XXXXXXXX
        client_uuid = str(uuid.uuid4())
        fake_client, sent = _make_fake_client("conn-qr-e2e")
        req_msg = SnowMessage.create_request(
            action="pair_request",
            data={
                "device_id": client_uuid,
                "device_name": "Realme P4",
                "handshake_token": validated["handshake_token"],
            },
        )
        await self.core.ws_server._handle_request(fake_client, req_msg)

        self.assertEqual(len(sent), 1)
        resp = sent[0]
        self.assertEqual(resp["type"], "response")
        self.assertEqual(resp["payload"]["status"], "success")
        self.assertEqual(resp["payload"]["data"]["device_id"], self.host_identity.device_id)
        self.assertTrue(is_valid_network_id(resp["payload"]["data"].get("network_id")))
        raw_auth_tok = resp["payload"]["data"]["auth_token"]

        rec = self.db.get_paired_device(client_uuid)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.auth_token_hash, hash_token(raw_auth_tok))
        self.assertIsNotNone(self.core.session_manager.get_session_by_device(client_uuid))
        self.assertIsNotNone(self.core.node_registry.get_node(client_uuid))

    async def test_02b_legacy_v1_qr_backward_compatibility(self) -> None:
        v1_qr = create_qr_pairing_payload(
            node_id=self.host_identity.device_id,
            candidate_ips=["192.168.1.10"],
            port=8765,
            cert_fingerprint=self.cert_info.fingerprint_sha256,
            pin=self.core.ws_server.pairing_manager.generate_pin(display_to_stderr=False),
            version=1,
            network_id=self.net_identity.network_id,
        )
        self.assertEqual(v1_qr["v"], 1)
        parsed = validate_qr_pairing_payload(json.dumps(v1_qr))
        self.assertEqual(parsed["v"], 1)
        self.assertEqual(parsed["network_id"], self.net_identity.network_id)

    async def test_03_host_identity_mismatch_rejected(self) -> None:
        qr = await self._generate_qr_via_ipc()
        # Simulate another host WS server with a different device_id trying to accept token
        other_identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Other-PC",
            created_at="2026-11-26T00:00:00Z",
            snow_id="SNW-HOST-2222",
        )
        self.core.ws_server.device_identity = other_identity
        client_uuid = str(uuid.uuid4())
        fake_client, sent = _make_fake_client("conn-host-mismatch")
        req_msg = SnowMessage.create_request(
            action="pair_request",
            data={
                "device_id": client_uuid,
                "handshake_token": qr["handshake_token"],
                "network_id": self.net_identity.network_id,
            },
        )
        await self.core.ws_server._handle_request(fake_client, req_msg)

        self.assertEqual(sent[0]["type"], "error")
        self.assertEqual(sent[0]["error"]["code"], ErrorCode.INVALID_PIN)
        self.assertIsNone(self.db.get_paired_device(client_uuid))

    async def test_04_05_06_strict_network_binding_rejects_missing_empty_and_mismatched(self) -> None:
        self.db.ensure_active_network(
            network_name="Strict Binding Mesh",
            owner_device_id=self.host_identity.device_id,
            network_id=self.net_identity.network_id,
        )
        qr = await self._generate_qr_via_ipc()
        self.assertEqual(qr["network_id"], self.net_identity.network_id)
        token = qr["handshake_token"]
        client_uuid = str(uuid.uuid4())

        # 4. Missing network_id
        c1, s1 = _make_fake_client("conn-missing-net")
        m1 = SnowMessage.create_request(
            action="pair_request",
            data={"device_id": client_uuid, "handshake_token": token},
        )
        await self.core.ws_server._handle_request(c1, m1)
        self.assertEqual(s1[0]["type"], "error")
        self.assertIsNone(self.db.get_paired_device(client_uuid))

        # 5. Empty network_id (and whitespace)
        c2, s2 = _make_fake_client("conn-empty-net")
        m2 = SnowMessage.create_request(
            action="pair_request",
            data={"device_id": client_uuid, "handshake_token": token, "network_id": "   "},
        )
        await self.core.ws_server._handle_request(c2, m2)
        self.assertEqual(s2[0]["type"], "error")
        self.assertIsNone(self.db.get_paired_device(client_uuid))

        # 6. Mismatched network_id
        c3, s3 = _make_fake_client("conn-mismatch-net")
        m3 = SnowMessage.create_request(
            action="pair_request",
            data={"device_id": client_uuid, "handshake_token": token, "network_id": "SNW-NET-FFFFFFFF"},
        )
        await self.core.ws_server._handle_request(c3, m3)
        self.assertEqual(s3[0]["type"], "error")
        self.assertIsNone(self.db.get_paired_device(client_uuid))

        # Genuine network_id still works because prior rejections did not consume it
        c4, s4 = _make_fake_client("conn-valid-net")
        m4 = SnowMessage.create_request(
            action="pair_request",
            data={"device_id": client_uuid, "handshake_token": token, "network_id": self.net_identity.network_id},
        )
        await self.core.ws_server._handle_request(c4, m4)
        self.assertEqual(s4[0]["type"], "response")
        self.assertEqual(s4[0]["payload"]["status"], "success")

    async def test_07_expired_token_rejected_over_ws(self) -> None:
        now = [1000.0]
        pm = PairingManager(pin_lifetime=60.0, time_provider=lambda: now[0])
        self.core.ws_server.pairing_manager = pm
        qr = await self._generate_qr_via_ipc()
        now[0] = 1500.0

        client_uuid = str(uuid.uuid4())
        c, s = _make_fake_client("conn-expired-tok")
        msg = SnowMessage.create_request(
            action="pair_request",
            data={
                "device_id": client_uuid,
                "handshake_token": qr["handshake_token"],
                "network_id": qr["network_id"],
            },
        )
        await self.core.ws_server._handle_request(c, msg)
        self.assertEqual(s[0]["type"], "error")
        self.assertEqual(s[0]["error"]["code"], ErrorCode.PIN_EXPIRED)
        self.assertIsNone(self.db.get_paired_device(client_uuid))

    async def test_08_replayed_token_rejected_over_ws(self) -> None:
        qr = await self._generate_qr_via_ipc()
        first_uuid = str(uuid.uuid4())
        second_uuid = str(uuid.uuid4())

        c1, s1 = _make_fake_client("conn-replay-1")
        await self.core.ws_server._handle_request(
            c1,
            SnowMessage.create_request(
                action="pair_request",
                data={
                    "device_id": first_uuid,
                    "handshake_token": qr["handshake_token"],
                    "network_id": qr["network_id"],
                },
            ),
        )
        self.assertEqual(s1[0]["type"], "response")

        c2, s2 = _make_fake_client("conn-replay-2")
        await self.core.ws_server._handle_request(
            c2,
            SnowMessage.create_request(
                action="pair_request",
                data={
                    "device_id": second_uuid,
                    "handshake_token": qr["handshake_token"],
                    "network_id": qr["network_id"],
                },
            ),
        )
        self.assertEqual(s2[0]["type"], "error")
        self.assertEqual(s2[0]["error"]["code"], ErrorCode.INVALID_PIN)
        self.assertIsNone(self.db.get_paired_device(second_uuid))

    async def test_09_token_plus_pin_cannot_downgrade_to_pin_verification(self) -> None:
        qr = await self._generate_qr_via_ipc()
        real_pin = qr["pin"]
        attacker_uuid = str(uuid.uuid4())

        # Supply invalid handshake_token ALONGSIDE genuine active PIN -> must NEVER fall back to verify_pin
        c1, s1 = _make_fake_client("conn-downgrade-badtok")
        await self.core.ws_server._handle_request(
            c1,
            SnowMessage.create_request(
                action="pair_request",
                data={
                    "device_id": attacker_uuid,
                    "handshake_token": "forged_invalid_handshake_token_1234",
                    "network_id": qr["network_id"],
                    "pin": real_pin,
                },
            ),
        )
        self.assertEqual(s1[0]["type"], "error")
        self.assertEqual(s1[0]["error"]["code"], ErrorCode.INVALID_PIN)
        self.assertIsNone(self.db.get_paired_device(attacker_uuid))

        # Supply empty handshake_token ALONGSIDE genuine active PIN -> must STILL reject, not downgrade
        c2, s2 = _make_fake_client("conn-downgrade-emptytok")
        await self.core.ws_server._handle_request(
            c2,
            SnowMessage.create_request(
                action="pair_request",
                data={
                    "device_id": attacker_uuid,
                    "handshake_token": "",
                    "pin": real_pin,
                },
            ),
        )
        self.assertEqual(s2[0]["type"], "error")
        self.assertEqual(s2[0]["error"]["code"], ErrorCode.INVALID_PIN)
        self.assertIsNone(self.db.get_paired_device(attacker_uuid))

    async def test_10_11_missing_and_malformed_client_device_id_rejected(self) -> None:
        qr = await self._generate_qr_via_ipc()
        active_pin = self.core.ws_server.pairing_manager._active_pin

        bad_ids = [
            None,                  # missing
            "",                    # empty
            "   ",                 # whitespace
            "phone-not-a-uuid",    # arbitrary string
            str(uuid.uuid1()),     # UUIDv1 (not v4)
        ]

        for idx, bad_id in enumerate(bad_ids):
            c, s = _make_fake_client(f"conn-bad-id-{idx}")
            payload: dict = {"handshake_token": qr["handshake_token"], "network_id": qr["network_id"]}
            if bad_id is not None:
                payload["device_id"] = bad_id
            await self.core.ws_server._handle_request(
                c, SnowMessage.create_request(action="pair_request", data=payload)
            )
            self.assertEqual(s[0]["type"], "error", msg=f"bad_id={bad_id!r} should be rejected")
            self.assertEqual(s[0]["error"]["code"], ErrorCode.INVALID_PAYLOAD)
            self.assertIsNone(self.core.node_registry.get_node(str(bad_id)))

            # Also verify manual PIN rejects missing/malformed device_id without pairing
            c_pin, s_pin = _make_fake_client(f"conn-bad-pin-id-{idx}")
            pin_payload: dict = {"pin": active_pin}
            if bad_id is not None:
                pin_payload["device_id"] = bad_id
            await self.core.ws_server._handle_request(
                c_pin, SnowMessage.create_request(action="pair_request", data=pin_payload)
            )
            self.assertEqual(s_pin[0]["type"], "error")
            self.assertEqual(s_pin[0]["error"]["code"], ErrorCode.INVALID_PAYLOAD)

        # Ensure DB remained completely empty throughout all invalid-id attempts
        self.assertEqual(self.db.list_paired_devices(), [])

    async def test_12_cancel_pin_invalidates_all_active_handshake_tokens_thread_safe(self) -> None:
        qr1 = await self._generate_qr_via_ipc()
        qr2 = await self._generate_qr_via_ipc()

        cancel_res = await self._ipc_call("cancel_pairing_pin")
        self.assertTrue(cancel_res["success"])
        self.assertTrue(cancel_res["data"]["cancelled"])
        self.assertEqual(cancel_res["data"]["revoked_handshake_tokens"], 2)

        client_uuid = str(uuid.uuid4())
        for idx, qr in enumerate((qr1, qr2)):
            c, s = _make_fake_client(f"conn-cancelled-{idx}")
            await self.core.ws_server._handle_request(
                c,
                SnowMessage.create_request(
                    action="pair_request",
                    data={
                        "device_id": client_uuid,
                        "handshake_token": qr["handshake_token"],
                        "network_id": qr["network_id"],
                    },
                ),
            )
            self.assertEqual(s[0]["type"], "error")
            self.assertIsNone(self.db.get_paired_device(client_uuid))

        # Thread-safety stress: concurrent token issuance and revoke_all_handshake_tokens
        pm = self.core.ws_server.pairing_manager
        errors: list[Exception] = []

        def _worker():
            try:
                for _ in range(25):
                    pm.issue_handshake_token(self.host_identity.device_id, self.net_identity.network_id)
                    pm.revoke_all_handshake_tokens()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    async def test_13_manual_pin_pairing_continues_independently(self) -> None:
        pin = self.core.ws_server.pairing_manager.generate_pin(display_to_stderr=False, trust_tier="peer")
        client_uuid = str(uuid.uuid4())
        c, s = _make_fake_client("conn-manual-pin")
        await self.core.ws_server._handle_request(
            c,
            SnowMessage.create_request(
                action="pair_request",
                data={"device_id": client_uuid, "device_name": "Manual PIN Phone", "pin": pin},
            ),
        )
        self.assertEqual(s[0]["type"], "response")
        self.assertEqual(s[0]["payload"]["status"], "success")
        self.assertEqual(s[0]["payload"]["data"]["trust_tier"], "peer")
        rec = self.db.get_paired_device(client_uuid)
        self.assertIsNotNone(rec)
        self.assertEqual(rec.trust_tier, "peer")


if __name__ == "__main__":
    unittest.main()
