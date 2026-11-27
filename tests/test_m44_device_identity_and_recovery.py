"""M4.4 Stage 2 Tests: Permanent Ed25519 DeviceKeyIdentity, Persistence, Migration & Recovery."""

from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import MagicMock

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from snow.relay.auth import (
    canonical_device_hub_challenge_message,
    derive_device_snow_id_from_pubkey,
    verify_ed25519_signature,
)
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import (
    DeviceIdentityError,
    DeviceKeyIdentity,
    export_device_recovery_key,
    export_encrypted_device_backup,
    import_encrypted_device_backup,
    load_or_create_device_identity,
    load_or_create_device_key_identity,
    load_or_create_network_key_identity,
    parse_device_recovery_key,
    recover_device_key_identity,
    restore_device_key_identity,
)


class TestM44DeviceKeyIdentity(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.tmpdir.name)

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_creation_canonical_derivation_and_rfc8032_vector(self) -> None:
        ident = load_or_create_device_key_identity(data_dir=self.data_dir)
        key_file = self.data_dir / "device_key.json"
        self.assertTrue(key_file.is_file())
        self.assertRegex(ident.snow_id, r"^SNW-[A-F0-9]{4}-[A-F0-9]{4}$")
        self.assertEqual(len(ident._private_key_bytes), 32)

        raw_pub = base64.urlsafe_b64decode(ident.public_key_b64 + "=")
        self.assertEqual(len(raw_pub), 32)
        expected_hex = hashlib.sha256(raw_pub).hexdigest()[:8].upper()
        self.assertEqual(ident.snow_id, f"SNW-{expected_hex[:4]}-{expected_hex[4:]}")
        self.assertEqual(derive_device_snow_id_from_pubkey(ident.public_key_b64), ident.snow_id)

        # Deterministic persistence across restarts
        ident_reloaded = load_or_create_device_key_identity(data_dir=self.data_dir)
        self.assertEqual(ident_reloaded.snow_id, ident.snow_id)
        self.assertEqual(ident_reloaded.public_key_b64, ident.public_key_b64)

        # RFC 8032 vector 1 (seed = 0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60)
        vec_seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        from snow.security.identity import _device_key_from_seed
        vec_ident = _device_key_from_seed(vec_seed)
        expected_vec_pub = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        self.assertEqual(
            vec_ident.public_key_b64,
            base64.urlsafe_b64encode(expected_vec_pub).decode("ascii").rstrip("="),
        )
        self.assertEqual(
            vec_ident.snow_id,
            derive_device_snow_id_from_pubkey(expected_vec_pub),
        )

        # POSIX 0600 check where supported
        if os.name != "nt":
            mode = stat.S_IMODE(key_file.stat().st_mode)
            self.assertEqual(mode, 0o600)

    def test_no_secret_leakage_in_repr_str_dicts_or_logs(self) -> None:
        ident = load_or_create_device_key_identity(data_dir=self.data_dir)
        raw_priv_b64 = base64.urlsafe_b64encode(ident._private_key_bytes).decode("ascii").rstrip("=")
        rec_key = export_device_recovery_key(ident)

        self.assertNotIn(raw_priv_b64, repr(ident))
        self.assertNotIn(raw_priv_b64, str(ident))
        self.assertNotIn(raw_priv_b64, json.dumps(ident.to_dict()))
        self.assertNotIn(raw_priv_b64, json.dumps(ident.to_public_dict()))
        self.assertNotIn("private_key", ident.to_public_dict())

        # Ensure capture of logger output contains zero private seed or recovery key
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        sec_logger = logging.getLogger("snow.security.identity")
        sec_logger.addHandler(handler)
        try:
            _ = export_device_recovery_key(ident)
            restore_device_key_identity(rec_key, data_dir=self.data_dir)
        finally:
            sec_logger.removeHandler(handler)
        logs_text = buf.getvalue()
        self.assertNotIn(raw_priv_b64, logs_text)
        self.assertNotIn(rec_key, logs_text)

    def test_corrupt_device_key_files_fail_closed_never_regenerate(self) -> None:
        ident = load_or_create_device_key_identity(data_dir=self.data_dir)
        key_path = self.data_dir / "device_key.json"
        original_doc = json.loads(key_path.read_text(encoding="utf-8"))

        # 1. Corrupt JSON
        key_path.write_text("{not valid json", encoding="utf-8")
        with self.assertRaises(DeviceIdentityError):
            load_or_create_device_key_identity(data_dir=self.data_dir)

        # 2. Invalid schema version
        bad_ver = dict(original_doc, version=99)
        key_path.write_text(json.dumps(bad_ver), encoding="utf-8")
        with self.assertRaises(DeviceIdentityError):
            load_or_create_device_key_identity(data_dir=self.data_dir)

        # 3. Invalid seed length
        bad_len = dict(original_doc, private_key_b64=base64.urlsafe_b64encode(b"short").decode("ascii").rstrip("="))
        key_path.write_text(json.dumps(bad_len), encoding="utf-8")
        with self.assertRaises(DeviceIdentityError):
            load_or_create_device_key_identity(data_dir=self.data_dir)

        # 4. Public-key / seed mismatch
        other_pub = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii").rstrip("=")
        bad_pub = dict(original_doc, public_key_b64=other_pub)
        key_path.write_text(json.dumps(bad_pub), encoding="utf-8")
        with self.assertRaises(DeviceIdentityError):
            load_or_create_device_key_identity(data_dir=self.data_dir)

        # 5. Mismatched snow_id
        bad_id = dict(original_doc, snow_id="SNW-0000-0000" if ident.snow_id != "SNW-0000-0000" else "SNW-1111-1111")
        key_path.write_text(json.dumps(bad_id), encoding="utf-8")
        with self.assertRaises(DeviceIdentityError):
            load_or_create_device_key_identity(data_dir=self.data_dir)

        # File must still NOT be silently regenerated to a working random key
        with self.assertRaises(DeviceIdentityError):
            load_or_create_device_key_identity(data_dir=self.data_dir)

        # Explicit recover creates a fresh key and archives corrupt file
        new_ident, backup = recover_device_key_identity(data_dir=self.data_dir)
        self.assertIsNotNone(backup)
        self.assertTrue(backup.exists())
        self.assertNotEqual(new_ident.snow_id, ident.snow_id)

    def test_migration_preserves_legacy_device_and_network_identities(self) -> None:
        # Existing install already has legacy UUID identity.json and network_key.json
        legacy_dev = load_or_create_device_identity(data_dir=self.data_dir, device_name="LegacyPC")
        net_key = load_or_create_network_key_identity(data_dir=self.data_dir)

        dev_key = load_or_create_device_key_identity(data_dir=self.data_dir)
        dev_key_2 = load_or_create_device_key_identity(data_dir=self.data_dir)
        self.assertEqual(dev_key.snow_id, dev_key_2.snow_id)
        self.assertEqual(dev_key.public_key_b64, dev_key_2.public_key_b64)

        # Legacy UUID and NetworkKeyIdentity remain completely unchanged and separate
        legacy_after = load_or_create_device_identity(data_dir=self.data_dir)
        net_after = load_or_create_network_key_identity(data_dir=self.data_dir)
        self.assertEqual(legacy_after.device_id, legacy_dev.device_id)
        self.assertEqual(net_after.network_id, net_key.network_id)
        self.assertEqual(net_after.public_key_b64, net_key.public_key_b64)
        self.assertNotEqual(dev_key.snow_id, net_key.network_id)

    def test_recovery_export_restore_checksum_encryption_and_trust_separation(self) -> None:
        ident = load_or_create_device_key_identity(data_dir=self.data_dir)
        rec_key = export_device_recovery_key(ident)
        self.assertTrue(rec_key.startswith("SNW-REC-V1-"))

        # Ambiguous chars I, L, O, U must never appear or validate
        for bad_ch in ("I", "L", "O", "U"):
            corrupted = rec_key[:-1] + bad_ch
            with self.assertRaises(DeviceIdentityError):
                parse_device_recovery_key(corrupted)

        # Single-char transcription error caught by SHA-256 checksum
        flipped_char = "A" if rec_key[-1] != "A" else "B"
        with self.assertRaises(DeviceIdentityError):
            parse_device_recovery_key(rec_key[:-1] + flipped_char)

        # Encrypted backup round-trip + wrong passphrase rejection
        backup_json = export_encrypted_device_backup(ident, "CorrectHorseBattery123!")
        parsed_backup = import_encrypted_device_backup(backup_json, "CorrectHorseBattery123!")
        self.assertEqual(parsed_backup.snow_id, ident.snow_id)
        self.assertEqual(parsed_backup.public_key_b64, ident.public_key_b64)
        with self.assertRaises(DeviceIdentityError):
            import_encrypted_device_backup(backup_json, "WrongPassphrase999!")
        with self.assertRaises(DeviceIdentityError):
            export_encrypted_device_backup(ident, "short")

        # Restore into brand-new directory with populated DB peer/OAuth trust -> trust MUST be wiped
        restore_dir = Path(self.tmpdir.name) / "restored"
        db = DatabaseManager(db_path=restore_dir / "snow_devices.db")
        db.insert_paired_device(
            device_id="old-trusted-phone",
            device_name="OldPhone",
            auth_token_hash=hash_token("old-secret-token"),
            trust_tier="owner",
            cert_fingerprint="AA:BB:CC",
        )
        db.save_oauth_client(
            client_id="cli_old_1",
            client_name="Old AI Client",
            redirect_uris=["https://claude.ai/api/mcp/auth_callback"],
        )
        db.save_oauth_token_record(
            access_token_hash=hash_token("tok-1"),
            refresh_token_hash=hash_token("ref-1"),
            client_id="cli_old_1",
            scope="snow:tools",
            family_id="fam-1",
            expires_at=9999999999.0,
            refresh_expires_at=9999999999.0,
        )
        db.save_network_identity("SNW-NET-12345678", "OldNet", "old-owner", "2026-01-01T00:00:00+00:00")
        (restore_dir / "tunnel.json").write_text(json.dumps({"relay_ticket": "leak", "default_hub_url": "https://snow-relay.onrender.com"}), encoding="utf-8")

        restored, _ = restore_device_key_identity(rec_key, data_dir=restore_dir, db_manager=db)
        self.assertEqual(restored.snow_id, ident.snow_id)
        self.assertEqual(restored.public_key_b64, ident.public_key_b64)

        # Canonical challenge signature matches between original & restored keys
        challenge_msg = canonical_device_hub_challenge_message(
            challenge_id="ch-1",
            nonce="nonce-1",
            expires_at=1999999999,
            snow_id=ident.snow_id,
            public_key_b64=ident.public_key_b64,
            device_id="dev-uuid-1",
        )
        sig = restored.sign_message(challenge_msg)
        self.assertTrue(verify_ed25519_signature(ident.public_key_b64, challenge_msg, sig))

        # Critical trust separation: old peer, network ownership, and OAuth tokens MUST NOT remain trusted
        self.assertIsNone(db.get_paired_device("old-trusted-phone"))
        self.assertEqual(db.list_paired_devices(), [])
        self.assertIsNone(db.get_network_identity())
        self.assertIsNone(db.get_oauth_client("cli_old_1"))
        self.assertIsNone(db.get_oauth_access_token(hash_token("tok-1")))
        tunnel_after = json.loads((restore_dir / "tunnel.json").read_text(encoding="utf-8"))
        self.assertNotIn("relay_ticket", tunnel_after)


class TestM44WebRecoveryApi(AioHTTPTestCase):
    async def get_application(self) -> web.Application:
        self.tmpdir = tempfile.TemporaryDirectory()
        self._old_env = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = self.tmpdir.name
        self.db = DatabaseManager(db_path=Path(self.tmpdir.name) / "web.db")
        self.db.insert_paired_device(
            device_id="peer-before-restore",
            device_name="Phone",
            auth_token_hash=hash_token("tok-peer"),
        )
        self.oauth_revoked_count = 0

        class _FakeOAuth:
            def __init__(self, test_ref) -> None:
                self._test_ref = test_ref

            def revoke_all_on_recovery(self) -> None:
                self._test_ref.oauth_revoked_count += 1

        from snow.web.server import SnowWebServer
        from types import SimpleNamespace

        self.web_srv = SnowWebServer.__new__(SnowWebServer)
        self.web_srv.db_manager = self.db
        self.web_srv.bridge = SimpleNamespace(capability_engine=SimpleNamespace(db_manager=self.db))
        self.web_srv.remote_gateway = SimpleNamespace(oauth_server=_FakeOAuth(self))

        app = web.Application()
        app.router.add_get("/api/identity/device", self.web_srv.handle_api_device_identity)
        app.router.add_post("/api/identity/recovery/export", self.web_srv.handle_api_device_recovery_export)
        app.router.add_post("/api/identity/recovery/restore", self.web_srv.handle_api_device_recovery_restore)
        return app

    async def tearDownAsync(self) -> None:
        await super().tearDownAsync()
        if self._old_env is None:
            os.environ.pop("SNOW_DATA_DIR", None)
        else:
            os.environ["SNOW_DATA_DIR"] = self._old_env
        self.tmpdir.cleanup()

    async def test_web_recovery_requires_confirmation_and_resets_trust(self) -> None:
        r_ident = await self.client.get("/api/identity/device")
        self.assertEqual(r_ident.status, 200)
        b_ident = await r_ident.json()
        self.assertTrue(b_ident["success"])
        self.assertTrue(b_ident["permanent_mcp_url"].endswith(f"/u/{b_ident['snow_id']}/mcp"))
        self.assertNotIn("private_key_b64", json.dumps(b_ident))

        # Unconfirmed export refused
        r_unconfirmed = await self.client.post("/api/identity/recovery/export", json={"confirm": False})
        self.assertEqual(r_unconfirmed.status, 400)

        # Confirmed export returns recovery key once
        r_exp = await self.client.post("/api/identity/recovery/export", json={"confirm": True})
        self.assertEqual(r_exp.status, 200)
        b_exp = await r_exp.json()
        rec_key = b_exp["recovery_key"]
        self.assertTrue(rec_key.startswith("SNW-REC-V1-"))

        # Restore wipes peer DB & invokes OAuth revocation
        r_res = await self.client.post(
            "/api/identity/recovery/restore",
            json={"recovery_key": rec_key, "confirm": True},
        )
        self.assertEqual(r_res.status, 200)
        b_res = await r_res.json()
        self.assertEqual(b_res["snow_id"], b_ident["snow_id"])
        self.assertTrue(b_res["trust_reset"])
        self.assertIsNone(self.db.get_paired_device("peer-before-restore"))
        self.assertEqual(self.oauth_revoked_count, 1)


if __name__ == "__main__":
    unittest.main()
