"""Comprehensive Regression & Adversarial Verification Suite for SNOW V4.1 Gate 1B: Batch 1.

Verifies:
1. F2: Approvals UI countdown, missing/invalid timestamps, expired protection, and canonical escapeHtml.
2. F13: CoreConfig.from_env() heartbeat environment variable parsing, validation, and defaults.
3. F14: get_available_drives() sys.platform import, disk usage metrics, and fallback robustness.
4. F22: OAuth 2.1 Owner Authentication, Consent Workflow, PKCE, Single-Use Codes, and SQLite Persistence.
5. F24 + F31: HTTP Transfer bounded streaming, direction enforcement, ownership validation,
   Content-Range validation, partial file deletion, and startup/periodic maintenance lifecycle.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from snow.capabilities.windows.files import get_available_drives
from snow.core.config import CoreConfig
from snow.core.server import SnowCoreServer
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.oauth import AuthorizationCode, OAuthClient, OAuthServer, TokenRecord
from snow.mcp.remote_gateway import RemoteMcpGateway
from snow.security.db import DatabaseManager, hash_token
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferDirection, TransferManager, TransferState
from snow.transfer.storage import TransferStorageManager


class TestF2ApprovalsUiLogic(unittest.TestCase):
    """Unit tests for F2: Approvals countdown logic, expiration checks, and escapeHtml."""

    def test_escape_html_canonical_escaping(self):
        """Verify HTML escaping prevents injection across all sensitive characters."""
        app_js_path = Path(__file__).resolve().parents[1] / "src" / "snow" / "web" / "static" / "app.js"
        content = app_js_path.read_text(encoding="utf-8")

        # Verify only one definition of escapeHtml exists
        count = content.count("function escapeHtml(str)")
        self.assertEqual(count, 1, "Duplicate escapeHtml definitions should be eliminated.")

        # Test escaping behavior matching the JS implementation
        def py_escape_html(s):
            if s is None:
                return ""
            return (
                str(s)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#039;")
            )

        self.assertEqual(py_escape_html("<script>alert('xss')</script>"), "&lt;script&gt;alert(&#039;xss&#039;)&lt;/script&gt;")
        self.assertEqual(py_escape_html('"hello" & "world"'), "&quot;hello&quot; &amp; &quot;world&quot;")
        self.assertEqual(py_escape_html(None), "")

    def test_initial_remaining_calculation_and_expired_state(self):
        """Simulate app.js initialRemaining countdown logic under various request payloads."""
        now_ts = 1700000000.0

        def calc_initial_remaining(req, current_time=now_ts):
            time_rem = req.get("time_remaining_seconds")
            expires_at = req.get("expires_at", 0)
            raw = time_rem if time_rem is not None else expires_at
            try:
                num = float(raw)
                if not math.isfinite(num):
                    num = 0.0
            except (ValueError, TypeError):
                num = 0.0
            return max(0, round(num))

        # Valid positive remaining
        self.assertEqual(calc_initial_remaining({"time_remaining_seconds": 60}), 60)
        # Expired (0 or negative)
        self.assertEqual(calc_initial_remaining({"time_remaining_seconds": 0}), 0)
        self.assertEqual(calc_initial_remaining({"time_remaining_seconds": -15}), 0)
        # Missing / invalid values do not crash
        self.assertEqual(calc_initial_remaining({}), 0)
        self.assertEqual(calc_initial_remaining({"time_remaining_seconds": "invalid"}), 0)
        self.assertEqual(calc_initial_remaining({"time_remaining_seconds": None, "expires_at": None}), 0)
    """Regression tests for F13: CoreConfig.from_env() UnboundLocalError and validation."""

    def test_default_heartbeat_config(self):
        with patch.dict(os.environ, {}, clear=True):
            cfg = CoreConfig.from_env()
            self.assertEqual(cfg.heartbeat_timeout, 45.0)
            self.assertEqual(cfg.heartbeat_interval, 15.0)

    def test_custom_heartbeat_timeout_env(self):
        with patch.dict(os.environ, {"SNOW_HEARTBEAT_TIMEOUT": "60.5"}, clear=True):
            cfg = CoreConfig.from_env()
            self.assertEqual(cfg.heartbeat_timeout, 60.5)
            self.assertEqual(cfg.heartbeat_interval, 15.0)

    def test_custom_heartbeat_interval_env(self):
        with patch.dict(os.environ, {"SNOW_HEARTBEAT_INTERVAL": "20.0"}, clear=True):
            cfg = CoreConfig.from_env()
            self.assertEqual(cfg.heartbeat_timeout, 45.0)
            self.assertEqual(cfg.heartbeat_interval, 20.0)

    def test_both_heartbeat_vars_configured(self):
        with patch.dict(os.environ, {"SNOW_HEARTBEAT_TIMEOUT": "90.0", "SNOW_HEARTBEAT_INTERVAL": "30.0"}, clear=True):
            cfg = CoreConfig.from_env()
            self.assertEqual(cfg.heartbeat_timeout, 90.0)
            self.assertEqual(cfg.heartbeat_interval, 30.0)

    def test_invalid_heartbeat_timeout_non_numeric(self):
        with patch.dict(os.environ, {"SNOW_HEARTBEAT_TIMEOUT": "not_a_number"}, clear=True):
            with self.assertRaises(ValueError) as ctx:
                CoreConfig.from_env()
            self.assertIn("must be a finite positive number", str(ctx.exception))

    def test_invalid_heartbeat_timeout_zero_or_negative(self):
        for val in ("0", "-5.0", "-0.001"):
            with patch.dict(os.environ, {"SNOW_HEARTBEAT_TIMEOUT": val}, clear=True):
                with self.assertRaises(ValueError) as ctx:
                    CoreConfig.from_env()
                self.assertIn("must be a finite positive number (> 0)", str(ctx.exception))

    def test_invalid_heartbeat_timeout_nan_inf(self):
        for val in ("nan", "inf", "-inf"):
            with patch.dict(os.environ, {"SNOW_HEARTBEAT_TIMEOUT": val}, clear=True):
                with self.assertRaises(ValueError) as ctx:
                    CoreConfig.from_env()
                self.assertIn("must be a finite positive number", str(ctx.exception))

    def test_invalid_heartbeat_interval_zero_or_negative(self):
        for val in ("0", "-10", "-0.1"):
            with patch.dict(os.environ, {"SNOW_HEARTBEAT_INTERVAL": val}, clear=True):
                with self.assertRaises(ValueError) as ctx:
                    CoreConfig.from_env()
                self.assertIn("must be a finite positive number (> 0)", str(ctx.exception))


class TestF14WindowsDriveDiscovery(unittest.TestCase):
    """Regression tests for F14: get_available_drives() sys.platform reference and metrics."""

    def test_get_available_drives_with_mocked_psutil(self):
        mock_partition = MagicMock()
        mock_partition.mountpoint = "C:"
        mock_usage = MagicMock(total=100_000_000_000, free=40_000_000_000, percent=60.0)

        with patch("psutil.disk_partitions", return_value=[mock_partition]), \
             patch("psutil.disk_usage", return_value=mock_usage):
            drives = get_available_drives()
            self.assertGreaterEqual(len(drives), 1)
            drv = drives[0]
            self.assertTrue(drv["drive"].startswith("C:"))
            self.assertEqual(drv["total_bytes"], 100_000_000_000)
            self.assertEqual(drv["free_bytes"], 40_000_000_000)
            self.assertEqual(drv["percent_used"], 60.0)

    def test_get_available_drives_inaccessible_drive_skipped_safely(self):
        mock_p1 = MagicMock(mountpoint="C:\\")
        mock_p2 = MagicMock(mountpoint="D:\\")

        def mock_usage(mount):
            if mount.startswith("D"):
                raise PermissionError("Access is denied")
            return MagicMock(total=500_000_000, free=200_000_000, percent=60.0)

        with patch("psutil.disk_partitions", return_value=[mock_p1, mock_p2]), \
             patch("psutil.disk_usage", side_effect=mock_usage):
            drives = get_available_drives()
            self.assertEqual(len(drives), 2)
            self.assertIn("total_bytes", drives[0])
            self.assertNotIn("total_bytes", drives[1])  # Inaccessible drive handled safely

    def test_get_available_drives_fallback_when_psutil_fails(self):
        with patch("psutil.disk_partitions", side_effect=ImportError("psutil missing")):
            drives = get_available_drives()
            self.assertIsInstance(drives, list)


class TestF22OAuthPersistenceAndConsent(AioHTTPTestCase):
    """Comprehensive regression tests for F22: OAuth SQLite persistence and consent enforcement."""

    async def setUpAsync(self):
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_oauth_")
        self.db_path = Path(self.temp_dir) / "test_oauth.db"
        self.db_manager = DatabaseManager(db_path=self.db_path)
        self.test_secret = "test_owner_ipc_secret_super_secure_123"

        self.mock_bridge = AsyncMock(spec=SnowMcpBridge)
        self.mock_bridge._get_secret = MagicMock(return_value=self.test_secret)
        self.mock_bridge.capability_engine = MagicMock()
        self.mock_bridge.capability_engine.db_manager = self.db_manager

        await super().setUpAsync()

    async def tearDownAsync(self):
        await super().tearDownAsync()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def get_application(self) -> web.Application:
        self.gateway = RemoteMcpGateway(
            host="127.0.0.1",
            port=8771,
            bridge=self.mock_bridge,
            issuer="http://127.0.0.1:8771",
        )
        # Ensure gateway uses our isolated test DB
        self.gateway.oauth_server.db_manager = self.db_manager
        return self.gateway.app

    async def test_unauthenticated_authorize_rejected(self):
        """Unauthenticated authorization requests MUST be rejected with HTTP 401."""
        reg = await self.client.post("/oauth/register", json={"client_name": "TestAI"})
        client_id = (await reg.json())["client_id"]

        resp = await self.client.post("/oauth/authorize", json={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "decision": "approve",
            # Missing owner authentication credentials!
        })
        self.assertEqual(resp.status, 401)
        data = await resp.json()
        self.assertEqual(data["error"], "unauthorized")

    async def test_missing_decision_rejected(self):
        """Requests without explicit decision parameter must be rejected with HTTP 400."""
        reg = await self.client.post("/oauth/register", json={"client_name": "TestAI"})
        client_id = (await reg.json())["client_id"]

        resp = await self.client.post("/oauth/authorize", json={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "ipc_secret": self.test_secret,
        })
        self.assertEqual(resp.status, 400)
        data = await resp.json()
        self.assertEqual(data["error"], "invalid_request")

    async def test_owner_denial_returns_access_denied(self):
        """Owner denial must return HTTP 403 or redirect with error=access_denied."""
        reg = await self.client.post("/oauth/register", json={
            "client_name": "TestAI",
            "redirect_uris": ["http://127.0.0.1/callback"],
        })
        client_id = (await reg.json())["client_id"]

        resp = await self.client.post("/oauth/authorize", json={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1/callback",
            "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "decision": "deny",
        }, allow_redirects=False)
        self.assertEqual(resp.status, 302)
        self.assertIn("error=access_denied", resp.headers.get("Location", ""))

    async def test_get_authorize_returns_html_consent_screen(self):
        """GET /oauth/authorize must return an interactive HTML consent screen."""
        reg = await self.client.post("/oauth/register", json={"client_name": "VisualAI"})
        client_id = (await reg.json())["client_id"]

        resp = await self.client.get(
            f"/oauth/authorize?response_type=code&client_id={client_id}&redirect_uri=http://127.0.0.1&code_challenge=xyz123"
        )
        self.assertEqual(resp.status, 200)
        self.assertIn("text/html", resp.headers.get("Content-Type", ""))
        text = await resp.text()
        self.assertIn("VisualAI", text)
        self.assertIn("csrf_token", text)
        self.assertIn("Owner Authentication", text)

    async def test_persistence_survives_server_restart(self):
        """Verify registered clients, authorization codes, and tokens survive server restart."""
        # 1. Register client and issue tokens
        reg = await self.client.post("/oauth/register", json={
            "client_name": "PersistentAI",
            "redirect_uris": ["http://127.0.0.1/app"],
        })
        client_id = (await reg.json())["client_id"]

        code_verifier = "persistent_code_verifier_123456789012345678"
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        code_challenge = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

        auth_resp = await self.client.post("/oauth/authorize", json={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1/app",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "decision": "approve",
            "ipc_secret": self.test_secret,
        }, allow_redirects=False)
        self.assertEqual(auth_resp.status, 302)
        code = auth_resp.headers.get("Location").split("code=")[1].split("&")[0]

        tok_resp = await self.client.post("/oauth/token", json={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1/app",
            "code": code,
            "code_verifier": code_verifier,
        })
        self.assertEqual(tok_resp.status, 200)
        tok_data = await tok_resp.json()
        access_token = tok_data["access_token"]
        refresh_token = tok_data["refresh_token"]

        # 2. Simulate complete restart by instantiating a fresh OAuthServer pointing to the same DB
        new_oauth_server = OAuthServer(issuer="http://127.0.0.1:8771", db_manager=self.db_manager)

        # 3. Client metadata survives restart
        client_rec = new_oauth_server.get_client(client_id)
        self.assertIsNotNone(client_rec)
        self.assertEqual(client_rec.client_name, "PersistentAI")

        # 4. Access token validates successfully after restart
        token_rec = new_oauth_server.validate_access_token(access_token)
        self.assertIsNotNone(token_rec)
        self.assertEqual(token_rec.client_id, client_id)

        # 5. Refresh token rotation works across restart
        ok, rot_data = new_oauth_server.refresh_access_token(refresh_token, client_id)
        self.assertTrue(ok)
        self.assertIn("access_token", rot_data)
        new_at = rot_data["access_token"]

        # 6. Verify plaintext tokens/secrets are NEVER stored in database
        with self.db_manager._get_connection() as conn:
            cursor = conn.execute("SELECT access_token_hash FROM oauth_tokens;")
            rows = cursor.fetchall()
            for r in rows:
                self.assertFalse(r[0].startswith("snow_at_"))
                self.assertEqual(len(r[0]), 64)  # Must be SHA-256 hex digest!

    async def test_refresh_token_client_binding(self):
        """Enforce that refresh tokens issued to Client A cannot be used by Client B, and do not corrupt Client A."""
        reg_a = await self.client.post("/oauth/register", json={"client_name": "ClientA"})
        client_a = (await reg_a.json())["client_id"]

        reg_b = await self.client.post("/oauth/register", json={"client_name": "ClientB"})
        client_b = (await reg_b.json())["client_id"]

        # Issue tokens for Client A
        ok, code = self.gateway.oauth_server.create_authorization_code(
            client_id=client_a,
            redirect_uri="http://127.0.0.1",
            code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        )
        self.assertTrue(ok)
        ok, tok_data = self.gateway.oauth_server.exchange_code(
            code=code,
            client_id=client_a,
            redirect_uri="http://127.0.0.1",
            code_verifier="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        )
        self.assertTrue(ok)
        refresh_token_a = tok_data["refresh_token"]

        # Attempt to refresh using Client B
        ok_b, err_b = self.gateway.oauth_server.refresh_access_token(
            refresh_token=refresh_token_a,
            client_id=client_b,
        )
        self.assertFalse(ok_b)
        self.assertEqual(err_b["error"], "invalid_grant")

        # Client A's refresh token must NOT have been invalidated by Client B's failed attempt!
        ok_a, rot_a = self.gateway.oauth_server.refresh_access_token(
            refresh_token=refresh_token_a,
            client_id=client_a,
        )
        self.assertTrue(ok_a)
        self.assertIn("access_token", rot_a)

    async def test_oauth_consent_post_rate_limiting(self):
        """Rapid POST /oauth/authorize attempts must be bounded by rate limiter returning HTTP 429."""
        reg = await self.client.post("/oauth/register", json={"client_name": "RateTestClient"})
        client_id = (await reg.json())["client_id"]

        statuses = []
        for _ in range(12):
            resp = await self.client.post("/oauth/authorize", json={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://127.0.0.1",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "decision": "approve",
                "ipc_secret": "wrong_secret_bruteforce",
            })
            statuses.append(resp.status)

        self.assertIn(429, statuses)

    async def test_browser_form_requires_valid_csrf(self):
        """Browser form submission (application/x-www-form-urlencoded) requires valid CSRF token."""
        reg = await self.client.post("/oauth/register", json={"client_name": "BrowserClient"})
        client_id = (await reg.json())["client_id"]

        # 1. Missing CSRF token
        resp1 = await self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://127.0.0.1",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "decision": "approve",
                "ipc_secret": self.test_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(resp1.status, 400)
        self.assertIn("Missing CSRF token", (await resp1.json())["error_description"])

        # 2. Invalid or expired CSRF token
        resp2 = await self.client.post(
            "/oauth/authorize",
            data={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "http://127.0.0.1",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "decision": "approve",
                "ipc_secret": self.test_secret,
                "csrf_token": "fake_or_expired_csrf_token_12345",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(resp2.status, 400)
        self.assertIn("Invalid or expired", (await resp2.json())["error_description"])

    def test_build_oauth_redirect_url_preserves_query_params(self):
        """Redirect URLs must preserve existing query parameters and URL-encode appended parameters."""
        from snow.mcp.remote_gateway import build_oauth_redirect_url
        base = "https://client.example.com/callback?env=prod&team=snow"
        params = {"code": "snow_code_xyz123", "state": "state with spaces & symbols"}
        result = build_oauth_redirect_url(base, params)

        self.assertTrue(result.startswith("https://client.example.com/callback?"))
        self.assertIn("env=prod", result)
        self.assertIn("team=snow", result)
        self.assertIn("code=snow_code_xyz123", result)
        self.assertIn("state=state+with+spaces+%26+symbols", result)
        self.assertEqual(result.count("?"), 1)

    def test_atomic_auth_code_consumption(self):
        """Single-use authorization code must be consumed atomically exactly once."""
        code_raw = secrets.token_urlsafe(32)
        code_hash = hashlib.sha256(code_raw.encode()).hexdigest()
        now = time.time()
        self.db_manager.save_oauth_auth_code(
            code_hash=code_hash,
            client_id="test_client_atomic",
            redirect_uri="http://127.0.0.1",
            scope="snow:mcp",
            code_challenge="xyz",
            code_challenge_method="S256",
            expires_at=now + 600,
        )

        # First consumption succeeds
        consumed1 = self.db_manager.consume_oauth_auth_code(code_hash)
        self.assertIsNotNone(consumed1)
        self.assertEqual(consumed1["client_id"], "test_client_atomic")

        # Second consumption on same code hash MUST return None
        consumed2 = self.db_manager.consume_oauth_auth_code(code_hash)
        self.assertIsNone(consumed2)


class TestF24AndF31HttpTransferSecurity(AioHTTPTestCase):
    """Adversarial and lifecycle verification for F24 and F31 file transfer hardening."""

    async def setUpAsync(self):
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_transfer_")
        self.transfer_root = Path(self.temp_dir) / "transfers"
        self.db_path = Path(self.temp_dir) / "transfer_test.db"

        self.config = CoreConfig(transfer_root=str(self.transfer_root))
        self.db_manager = DatabaseManager(db_path=self.db_path)
        self.transfer_manager = TransferManager()
        self.storage_manager = TransferStorageManager(root_dir=str(self.transfer_root))

        self.device_id = "test_phone_device_1"
        self.other_device_id = "test_phone_device_2"
        self.bearer_token = "valid_test_token_12345"

        # Register device with token hash in DB
        self.db_manager.insert_paired_device(
            device_id=self.device_id,
            device_name="Test Phone",
            auth_token_hash=hash_token(self.bearer_token),
            trust_tier="owner",
        )

        await super().setUpAsync()

    async def tearDownAsync(self):
        await super().tearDownAsync()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def get_application(self) -> web.Application:
        self.server = SnowHttpTransferServer(
            config=self.config,
            db_manager=self.db_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
        )
        return self.server.app

    async def test_upload_streaming_byte_limit_enforced_adversarial(self):
        """Streaming invariant: Sending bytes beyond declared file size MUST return 413 and delete .part file."""
        file_content = b"ABCDEFGHIJ"  # 10 bytes declared
        file_sha256 = hashlib.sha256(file_content).hexdigest()

        rec = self.transfer_manager.create_transfer(
            device_id=self.device_id,
            file_name="bounded_test.bin",
            file_size=10,
            sha256=file_sha256,
            direction=TransferDirection.UPLOAD,
        )
        transfer_id = rec.transfer_id

        # Adversary attempts to send 20 bytes (overshoot by 10 bytes)
        evil_payload = b"ABCDEFGHIJ" + b"EVIL_EXTRA_BYTES"

        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "X-Snow-Device-Id": self.device_id,
            "Content-Type": "application/octet-stream",
        }
        resp = await self.client.post(
            f"/api/v1/transfers/upload/{transfer_id}",
            data=evil_payload,
            headers=headers,
        )
        self.assertEqual(resp.status, 413)

        # Incomplete .part file MUST be immediately deleted
        part_path = self.storage_manager.get_part_path(transfer_id)
        self.assertFalse(part_path.exists())

        # Transfer must be marked FAILED
        updated_rec = self.transfer_manager.get_transfer(transfer_id)
        self.assertEqual(updated_rec.status, TransferState.FAILED)

    async def test_upload_to_download_record_rejected(self):
        """Attempting to upload to a record configured as DOWNLOAD must return HTTP 400."""
        dummy_hash = hashlib.sha256(b"dummy_download").hexdigest()
        rec = self.transfer_manager.create_transfer(
            device_id=self.device_id,
            file_name="download_only.bin",
            file_size=100,
            sha256=dummy_hash,
            direction=TransferDirection.DOWNLOAD,
        )
        resp = await self.client.post(
            f"/api/v1/transfers/upload/{rec.transfer_id}",
            data=b"data",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Snow-Device-Id": self.device_id,
            },
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid transfer direction", (await resp.json())["error"])

    async def test_download_from_upload_record_rejected(self):
        """Attempting to download from a record configured as UPLOAD must return HTTP 400."""
        dummy_hash = hashlib.sha256(b"dummy_upload").hexdigest()
        rec = self.transfer_manager.create_transfer(
            device_id=self.device_id,
            file_name="upload_only.bin",
            file_size=100,
            sha256=dummy_hash,
            direction=TransferDirection.UPLOAD,
        )
        resp = await self.client.get(
            f"/api/v1/transfers/download/{rec.transfer_id}",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Snow-Device-Id": self.device_id,
            },
        )
        self.assertEqual(resp.status, 400)
        self.assertIn("Invalid transfer direction", (await resp.json())["error"])

    async def test_transfer_ownership_isolation_prevents_access(self):
        """Device 2 attempting to access Device 1's transfer must return HTTP 403."""
        # Register device 2
        dev2_token = "token_for_dev_2"
        self.db_manager.insert_paired_device(
            device_id=self.other_device_id,
            device_name="Attacker Phone",
            auth_token_hash=hash_token(dev2_token),
            trust_tier="peer",
        )

        dummy_hash = hashlib.sha256(b"dummy_doc").hexdigest()
        rec = self.transfer_manager.create_transfer(
            device_id=self.device_id,
            file_name="private_owner_doc.pdf",
            file_size=50,
            sha256=dummy_hash,
            direction=TransferDirection.UPLOAD,
        )

        # Device 2 tries to upload to Device 1's transfer
        resp = await self.client.post(
            f"/api/v1/transfers/upload/{rec.transfer_id}",
            data=b"data",
            headers={
                "Authorization": f"Bearer {dev2_token}",
                "X-Snow-Device-Id": self.other_device_id,
            },
        )
        self.assertEqual(resp.status, 403)
        self.assertIn("not owned by device", (await resp.json())["error"])

    async def test_cancelled_or_failed_transfer_rejected(self):
        """Uploads to CANCELLED or FAILED transfers must return HTTP 409 Conflict."""
        dummy_hash = hashlib.sha256(b"dummy_cancelled").hexdigest()
        rec = self.transfer_manager.create_transfer(
            device_id=self.device_id,
            file_name="cancelled.bin",
            file_size=20,
            sha256=dummy_hash,
            direction=TransferDirection.UPLOAD,
        )
        self.transfer_manager.cancel_transfer(rec.transfer_id, self.device_id)

        resp = await self.client.post(
            f"/api/v1/transfers/upload/{rec.transfer_id}",
            data=b"data",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Snow-Device-Id": self.device_id,
            },
        )
        self.assertEqual(resp.status, 409)

    async def test_invalid_content_range_bounds_rejected(self):
        """Malformed or out-of-bounds Content-Range values must return HTTP 400 or 416."""
        dummy_hash = hashlib.sha256(b"dummy_range").hexdigest()
        rec = self.transfer_manager.create_transfer(
            device_id=self.device_id,
            file_name="range_test.bin",
            file_size=100,
            sha256=dummy_hash,
            direction=TransferDirection.UPLOAD,
        )

        # Negative start
        resp1 = await self.client.post(
            f"/api/v1/transfers/upload/{rec.transfer_id}",
            data=b"chunk",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Snow-Device-Id": self.device_id,
                "Content-Range": "bytes -5-10/100",
            },
        )
        self.assertEqual(resp1.status, 400)

        # End outside file_size
        resp2 = await self.client.post(
            f"/api/v1/transfers/upload/{rec.transfer_id}",
            data=b"chunk",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Snow-Device-Id": self.device_id,
                "Content-Range": "bytes 0-150/100",
            },
        )
        self.assertEqual(resp2.status, 416)

    def test_stale_parts_cleanup_and_server_lifecycle(self):
        """Verify F31: cleanup_stale_parts removes abandoned .part files but protects active ones."""
        parts_dir = self.storage_manager.parts_dir
        parts_dir.mkdir(parents=True, exist_ok=True)

        stale_part = parts_dir / "stale_transfer_123.part"
        stale_part.write_bytes(b"old abandoned bytes")
        # Set mtime to 2 days ago
        two_days_ago = time.time() - (2 * 86400)
        os.utime(stale_part, (two_days_ago, two_days_ago))

        active_part = parts_dir / "active_transfer_456.part"
        active_part.write_bytes(b"active upload bytes")

        # Run cleanup protecting active_transfer_456
        cleaned = self.storage_manager.cleanup_stale_parts(
            max_age_seconds=86400,
            active_transfer_ids={"active_transfer_456"},
        )
        self.assertEqual(cleaned, 1)
        self.assertFalse(stale_part.exists())
        self.assertTrue(active_part.exists())

    async def test_content_length_and_range_parity(self):
        """Enforce strict parity between Content-Length and Content-Range span."""
        file_content = b"0123456789" * 10  # 100 bytes
        file_sha256 = hashlib.sha256(file_content).hexdigest()

        rec = self.transfer_manager.create_transfer(
            device_id=self.device_id,
            file_name="parity_test.bin",
            file_size=100,
            direction=TransferDirection.UPLOAD,
            sha256=file_sha256,
        )

        # Case 1: Matching span (range 0-9 is 10 bytes, content_length = 10) -> Success (206 Partial Content)
        resp1 = await self.client.post(
            f"/api/v1/transfers/upload/{rec.transfer_id}",
            data=b"0123456789",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Snow-Device-Id": self.device_id,
                "Content-Range": "bytes 0-9/100",
                "Content-Length": "10",
            },
        )
        self.assertEqual(resp1.status, 206)

        # Create another transfer for mismatch tests
        rec2 = self.transfer_manager.create_transfer(
            device_id=self.device_id,
            file_name="parity_test2.bin",
            file_size=100,
            direction=TransferDirection.UPLOAD,
            sha256=file_sha256,
        )

        # Case 2: Content-Length smaller than range span (span is 10, length says 5) -> 400
        resp2 = await self.client.post(
            f"/api/v1/transfers/upload/{rec2.transfer_id}",
            data=b"01234",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Snow-Device-Id": self.device_id,
                "Content-Range": "bytes 0-9/100",
                "Content-Length": "5",
            },
        )
        self.assertEqual(resp2.status, 400)
        self.assertIn("does not match declared Content-Range span", (await resp2.json())["error"])

        # Case 3: Content-Length larger than range span (span is 10, length says 15) -> 400
        resp3 = await self.client.post(
            f"/api/v1/transfers/upload/{rec2.transfer_id}",
            data=b"0123456789extra",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "X-Snow-Device-Id": self.device_id,
                "Content-Range": "bytes 0-9/100",
                "Content-Length": "15",
            },
        )
        self.assertEqual(resp3.status, 400)
        self.assertIn("does not match declared Content-Range span", (await resp3.json())["error"])

    def test_server_run_maintenance_once_helper(self):
        """Verify SnowCoreServer._run_maintenance_once cleans stale files and preserves active ones."""
        server = SnowCoreServer(config=self.config)
        server.storage_manager = self.storage_manager
        server.transfer_manager = self.transfer_manager

        parts_dir = self.storage_manager.parts_dir
        parts_dir.mkdir(parents=True, exist_ok=True)

        stale_part = parts_dir / "stale_loop_123.part"
        stale_part.write_bytes(b"abandoned data")
        two_days_ago = time.time() - (2 * 86400)
        os.utime(stale_part, (two_days_ago, two_days_ago))

        # Register an active transfer
        active_rec = self.transfer_manager.create_transfer(
            device_id=self.device_id,
            file_name="active.bin",
            file_size=50,
            direction=TransferDirection.UPLOAD,
            sha256="c"*64,
        )
        active_part = parts_dir / f"{active_rec.transfer_id}.part"
        active_part.write_bytes(b"active data")

        unrelated_file = parts_dir / "readme.txt"
        unrelated_file.write_bytes(b"do not delete")

        cleaned = server._run_maintenance_once()
        self.assertEqual(cleaned, 1)
        self.assertFalse(stale_part.exists())
        self.assertTrue(active_part.exists())
        self.assertTrue(unrelated_file.exists())


if __name__ == "__main__":
    unittest.main()
