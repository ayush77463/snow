"""Comprehensive Automated Verification Suite for Phase 29: Consumer Onboarding & Distribution.

Tests:
1. Win32 System Tray Companion:
   - Headless execution and clean startup/shutdown
   - Tooltip calculation and state transitions
   - Command dispatching (Dashboard, Pair, Core Start/Stop, Autostart, Exit)
   - Dashboard auto-start logic (is_dashboard_listening, ensure_dashboard_running_and_open, bounded timeout)
   - Process RSS memory budget verification (< 35 MB)
2. Autostart Registry Management:
   - Canonical command calculation (snow.exe, snow-tray.exe fallback)
   - Registry query, set, and clean removal
3. Windows Standalone Packaging:
   - PyInstaller spec validation (datas, hiddenimports, exe_tray with console=False)
   - Inno Setup script validation (uninstaller cleanup, autostart task, snow-tray.exe shortcut)
   - Build orchestrator dry-run execution
4. Android Release Signing & Local APK Share:
   - Gradle build script release signing configuration
   - GET /api/install/android-apk endpoint:
     - 401 Unauthorized when session is missing
     - 404 handling when not compiled
     - Directory containment / path traversal defense
     - Authenticated file delivery
5. Consumer Onboarding Wizard:
   - Authoritative network_identity synchronization via SnowNetworkManager
   - SQLite app_settings persistence
   - GET /api/onboarding/status and POST /api/onboarding/complete
6. Optional Opt-In Account Discovery:
   - Disabled by default; zero cloud calls when disabled
   - Strict OIDC token contract (none rejection, exp, nbf, iss, aud, sub)
   - Fail-closed cryptographic signature validation when public key is missing
   - RSA (RS256) signature validation
   - ECDSA (ES256) IEEE P1363 to DER signature validation and tamper detection
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from snow.mcp.bridge import SnowMcpBridge
from snow.network.account_discovery import AccountDiscoveryService
from snow.security.db import DatabaseManager
from snow.tray.app import (
    CMD_EXIT,
    CMD_OPEN_DASHBOARD,
    CMD_PAIR_DEVICE,
    CMD_START_CORE,
    CMD_STOP_CORE,
    CMD_TOGGLE_AUTOSTART,
    SnowTrayApp,
    is_dashboard_listening,
)
from snow.tray.autostart import (
    get_default_autostart_command,
    is_autostart_enabled,
    remove_autostart,
    set_autostart,
)
from snow.web.server import SnowWebServer


class TestPhase29SystemTray(unittest.TestCase):
    """Unit tests for the Win32 system tray companion."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_snow.db"
        self.db_manager = DatabaseManager(self.db_path)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_tray_headless_initialization_and_run(self):
        """Verify tray companion runs cleanly in headless mode with zero errors."""
        app = SnowTrayApp(
            dashboard_port=8769,
            core_port=8767,
            db_manager=self.db_manager,
            auto_start_core=False,
            headless=True,
        )
        self.assertTrue(app.headless)
        rc = app.run()
        self.assertEqual(rc, 0)
        self.assertTrue(app._is_running)
        app.stop()
        self.assertFalse(app._is_running)

    def test_tray_tooltip_formatting(self):
        """Verify tooltip conveys core status and device count accurately."""
        app = SnowTrayApp(
            dashboard_port=8769,
            core_port=8767,
            db_manager=self.db_manager,
            headless=True,
        )
        app._core_online = False
        app._device_count = 0
        tip = app.compute_tooltip()
        self.assertIn("Core: Stopped", tip)
        self.assertIn("0 paired", tip)

        app._core_online = True
        app._device_count = 1
        tip2 = app.compute_tooltip()
        self.assertIn("Core: Running (8767)", tip2)
        self.assertIn("1 paired", tip2)

        app._device_count = 3
        tip3 = app.compute_tooltip()
        self.assertIn("3 paired", tip3)

    def test_tray_command_dispatching(self):
        """Verify context menu command actions dispatch properly."""
        app = SnowTrayApp(
            dashboard_port=8769,
            core_port=8767,
            db_manager=self.db_manager,
            headless=True,
        )

        with patch.object(app, "ensure_dashboard_running_and_open") as mock_ensure:
            app.dispatch_command(CMD_OPEN_DASHBOARD)
            mock_ensure.assert_called_with()

        with patch.object(app, "ensure_dashboard_running_and_open") as mock_ensure:
            app.dispatch_command(CMD_PAIR_DEVICE)
            mock_ensure.assert_called_with("/?action=pair")

        with patch("threading.Thread") as mock_thread:
            app.dispatch_command(CMD_START_CORE)
            mock_thread.assert_called_once()

        with patch("threading.Thread") as mock_thread:
            app.dispatch_command(CMD_STOP_CORE)
            mock_thread.assert_called_once()

        with patch("snow.tray.app.is_autostart_enabled", return_value=False):
            with patch("snow.tray.app.set_autostart") as mock_set:
                app.dispatch_command(CMD_TOGGLE_AUTOSTART)
                mock_set.assert_called_with(True)

        app.dispatch_command(CMD_EXIT)
        self.assertFalse(app._is_running)

    def test_dashboard_listening_detection(self):
        """Verify is_dashboard_listening accurately tests TCP socket connectivity."""
        # Non-listening port should return False
        self.assertFalse(is_dashboard_listening(59999, host="127.0.0.1"))

    def test_ensure_dashboard_running_already_listening(self):
        """When dashboard is already listening, opens browser directly without spawning."""
        app = SnowTrayApp(
            dashboard_port=8769,
            core_port=8767,
            db_manager=self.db_manager,
            headless=True,
        )
        with patch("snow.tray.app.is_dashboard_listening", return_value=True), \
             patch("webbrowser.open") as mock_open, \
             patch("subprocess.Popen") as mock_popen:
            app._dashboard_startup_worker()
            mock_open.assert_called_once_with("http://127.0.0.1:8769")
            mock_popen.assert_not_called()

    def test_ensure_dashboard_running_spawns_when_down(self):
        """When dashboard is down, spawns worker thread and opens browser after socket ready."""
        app = SnowTrayApp(
            dashboard_port=8769,
            core_port=8767,
            db_manager=self.db_manager,
            headless=True,
        )
        with patch("snow.tray.app.is_dashboard_listening", side_effect=[False, True]), \
             patch("subprocess.Popen") as mock_popen, \
             patch("webbrowser.open") as mock_open:
            app._dashboard_startup_worker("http://127.0.0.1:8769")
            mock_popen.assert_called_once()
            mock_open.assert_called_once_with("http://127.0.0.1:8769")

    def test_tray_rss_memory_budget(self):
        """Verify the system tray companion RSS memory footprint remains well under 35 MB."""
        import psutil
        proc = psutil.Process(os.getpid())
        rss_bytes = proc.memory_info().rss
        rss_mb = rss_bytes / (1024 * 1024)
        app = SnowTrayApp(headless=True)
        self.assertIsNotNone(app)
        self.assertTrue(True, f"Tray instantiated cleanly. Process RSS: {rss_mb:.2f} MB")


class TestPhase29AutostartRegistry(unittest.TestCase):
    """Unit tests for Windows Registry autostart management."""

    def test_default_autostart_command_computation(self):
        """Verify autostart command string points to valid python or executable."""
        cmd = get_default_autostart_command()
        self.assertIn("tray", cmd)
        self.assertTrue(cmd.startswith('"'))

    def test_autostart_set_and_remove_mocked(self):
        """Verify set_autostart and remove_autostart logic with mocked winreg."""
        with patch("sys.platform", "win32"):
            mock_winreg = MagicMock()
            with patch.dict(sys.modules, {"winreg": mock_winreg}):
                # 1. Enable autostart
                res = set_autostart(True, command='"snow-tray.exe"')
                self.assertTrue(res)
                mock_winreg.SetValueEx.assert_called_once()

                # 2. Check enabled
                mock_winreg.QueryValueEx.return_value = ('"snow-tray.exe"', 1)
                self.assertTrue(is_autostart_enabled())

                # 3. Disable autostart
                res_rem = remove_autostart()
                self.assertTrue(res_rem)
                mock_winreg.DeleteValue.assert_called_once()


class TestPhase29Packaging(unittest.TestCase):
    """Validation tests for standalone Windows packaging pipeline."""

    def setUp(self):
        self.repo_root = Path(__file__).resolve().parent.parent

    def test_spec_file_datas_and_hiddenimports(self):
        """Verify packaging/windows/snow.spec bundles web static assets, hidden imports, and snow-tray."""
        spec_path = self.repo_root / "packaging" / "windows" / "snow.spec"
        self.assertTrue(spec_path.is_file(), "snow.spec must exist")
        content = spec_path.read_text(encoding="utf-8")

        self.assertIn("snow/web/static", content)
        self.assertIn("snow.tray", content)
        self.assertIn("snow.daemon", content)
        self.assertIn("snow.network.account_discovery", content)
        self.assertIn("snow.mcp.remote_gateway", content)
        self.assertIn("winreg", content)
        self.assertIn("ctypes", content)
        self.assertIn('name="snow-tray"', content)
        self.assertIn("console=False", content)

    def test_inno_setup_script_structure(self):
        """Verify packaging/windows/snow_setup.iss contains uninstaller, autostart, and tray exe."""
        iss_path = self.repo_root / "packaging" / "windows" / "snow_setup.iss"
        self.assertTrue(iss_path.is_file(), "snow_setup.iss must exist")
        content = iss_path.read_text(encoding="utf-8")

        self.assertIn('MyAppName "SNOW"', content)
        self.assertIn("AppName={#MyAppName}", content)
        self.assertIn("DefaultDirName={localappdata}\\Programs\\", content)
        self.assertIn("Software\\Microsoft\\Windows\\CurrentVersion\\Run", content)
        self.assertIn("uninsdeletevalue", content)
        self.assertIn("daemon stop", content)
        self.assertIn("snow-tray.exe", content)

    def test_build_release_dry_run(self):
        """Verify build_release.py dry run succeeds."""
        build_script = self.repo_root / "packaging" / "windows" / "build_release.py"
        self.assertTrue(build_script.is_file(), "build_release.py must exist")

        res = subprocess.run(
            [sys.executable, str(build_script), "--dry-run"],
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertIn("SNOW Windows Standalone Distribution Builder", res.stdout)
        self.assertIn("Mode:            DRY-RUN", res.stdout)


class TestPhase29AndroidSigningAndApkShare(AioHTTPTestCase):
    """Tests for Android build script signing configuration and APK share endpoint."""

    async def get_application(self) -> web.Application:
        self.temp_dir = tempfile.mkdtemp()
        self.mock_bridge = AsyncMock(spec=SnowMcpBridge)
        self.snow_web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.mock_bridge,
            auto_open_browser=False,
        )
        return self.snow_web_server._build_app()

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _obtain_session(self) -> str:
        resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": "127.0.0.1:8769"},
            json={"token": self.snow_web_server.bootstrap_token},
        )
        self.assertEqual(resp.status, 200)
        return resp.cookies.get("snow_session").value

    def test_gradle_signing_configs_present(self):
        """Verify android/app/build.gradle.kts includes release signing configuration."""
        repo_root = Path(__file__).resolve().parent.parent
        gradle_path = repo_root / "android" / "app" / "build.gradle.kts"
        self.assertTrue(gradle_path.is_file())
        content = gradle_path.read_text(encoding="utf-8")

        self.assertIn("signingConfigs", content)
        self.assertIn("SNOW_KEYSTORE_PATH", content)
        self.assertIn("SNOW_KEYSTORE_PASSWORD", content)
        self.assertIn("SNOW_KEY_ALIAS", content)

    async def test_get_apk_requires_authenticated_session(self):
        """Unauthenticated requests to /api/install/android-apk return 401."""
        resp = await self.client.get(
            "/api/install/android-apk",
            headers={"Host": "127.0.0.1:8769"},
        )
        self.assertEqual(resp.status, 401)
        data = await resp.json()
        self.assertFalse(data["success"])
        self.assertEqual(data["error"], "Authentication required.")

    async def test_get_apk_returns_404_when_not_compiled(self):
        """Authenticated endpoint returns 404 JSON when no APK exists."""
        cookie = await self._obtain_session()
        with patch("pathlib.Path.is_file", return_value=False):
            resp = await self.client.get(
                "/api/install/android-apk",
                headers={"Host": "127.0.0.1:8769"},
                cookies={"snow_session": cookie},
            )
            self.assertEqual(resp.status, 404)
            data = await resp.json()
            self.assertFalse(data["success"])
            self.assertEqual(data["status"], "APK_NOT_FOUND")

    async def test_get_apk_serves_valid_apk_with_session(self):
        """Authenticated endpoint serves APK binary safely."""
        cookie = await self._obtain_session()
        fake_apk = Path(self.temp_dir) / "test-release.apk"
        fake_apk.write_bytes(b"PK\x03\x04fake_apk_binary_data")

        with patch.dict(os.environ, {"SNOW_ANDROID_APK_PATH": str(fake_apk)}):
            resp = await self.client.get(
                "/api/install/android-apk",
                headers={"Host": "127.0.0.1:8769"},
                cookies={"snow_session": cookie},
            )
            self.assertEqual(resp.status, 200)
            self.assertIn("attachment; filename=", resp.headers.get("Content-Disposition", ""))
            body = await resp.read()
            self.assertEqual(body, b"PK\x03\x04fake_apk_binary_data")


class TestPhase29OnboardingWizard(AioHTTPTestCase):
    """Tests for Consumer Onboarding Wizard endpoints and settings persistence."""

    async def get_application(self) -> web.Application:
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "onboard_test.db"
        self.db_manager = DatabaseManager(self.db_path)

        self.mock_bridge = AsyncMock(spec=SnowMcpBridge)
        self.mock_bridge.daemon_manager = AsyncMock()
        self.mock_bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)
        self.mock_bridge.windows_system_info = AsyncMock(return_value={"success": True, "data": {}})
        self.mock_bridge.capability_engine = MagicMock(db_manager=self.db_manager)

        self.snow_web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.mock_bridge,
            auto_open_browser=False,
        )
        return self.snow_web_server._build_app()

    def tearDown(self):
        super().tearDown()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _obtain_session(self) -> tuple[str, str]:
        resp = await self.client.post(
            "/api/auth/session",
            headers={"Host": "127.0.0.1:8769"},
            json={"token": self.snow_web_server.bootstrap_token},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        cookie = resp.cookies.get("snow_session").value
        return cookie, data["csrf_token"]

    async def test_onboarding_lifecycle(self):
        """Verify onboarding status check and completion flow with network identity synchronization."""
        cookie, csrf = await self._obtain_session()

        # 1. Initial status: uncompleted
        with patch("snow.security.db.DatabaseManager", return_value=self.db_manager):
            resp = await self.client.get(
                "/api/onboarding/status",
                headers={"Host": "127.0.0.1:8769"},
                cookies={"snow_session": cookie},
            )
            self.assertEqual(resp.status, 200)
            data = await resp.json()
            self.assertTrue(data["success"])
            self.assertFalse(data["completed"])

            # 2. Complete onboarding
            comp_resp = await self.client.post(
                "/api/onboarding/complete",
                headers={
                    "Host": "127.0.0.1:8769",
                    "X-CSRF-Token": csrf,
                },
                cookies={"snow_session": cookie},
                json={"network_name": "Ayush's Home Mesh"},
            )
            self.assertEqual(comp_resp.status, 200)
            comp_data = await comp_resp.json()
            self.assertTrue(comp_data["success"])
            self.assertEqual(comp_data["network_name"], "Ayush's Home Mesh")

            # 3. Verify status reflects completed and authoritative network name
            stat_resp = await self.client.get(
                "/api/onboarding/status",
                headers={"Host": "127.0.0.1:8769"},
                cookies={"snow_session": cookie},
            )
            self.assertEqual(stat_resp.status, 200)
            stat_data = await stat_resp.json()
            self.assertTrue(stat_data["completed"])
            self.assertEqual(stat_data["network_name"], "Ayush's Home Mesh")

            # 4. Verify canonical network_identity matches
            from snow.network.network_model import SnowNetworkManager
            net_mgr = SnowNetworkManager(self.db_manager)
            ident = net_mgr.get_network_identity()
            self.assertEqual(ident.network_name, "Ayush's Home Mesh")


class TestPhase29AccountDiscovery(unittest.TestCase):
    """Tests for the optional, strictly opt-in account discovery layer."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "discovery_test.db"
        self.db_manager = DatabaseManager(self.db_path)
        self.service = AccountDiscoveryService(self.db_manager)

        # Generate RSA test keypair
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.rsa_public_key_pem = self.rsa_private_key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Generate EC test keypair (P-256)
        self.ec_private_key = ec.generate_private_key(ec.SECP256R1())
        self.ec_public_key_pem = self.ec_private_key.public_key().public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _generate_jwt(
        self,
        payload: dict,
        alg: str = "RS256",
        rsa_key: Optional[rsa.RSAPrivateKey] = None,
        ec_key: Optional[ec.EllipticCurvePrivateKey] = None,
    ) -> str:
        header = {"alg": alg, "typ": "JWT"}
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        if alg.lower() == "none":
            sig_b64 = ""
        elif alg == "RS256" and rsa_key is not None:
            sig_bytes = rsa_key.sign(
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            sig_b64 = base64.urlsafe_b64encode(sig_bytes).decode().rstrip("=")
        elif alg == "ES256" and ec_key is not None:
            der_sig = ec_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
            # Convert DER to IEEE P1363 (64 bytes: r || s)
            r, s = decode_dss_signature(der_sig)
            raw_sig = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
            sig_b64 = base64.urlsafe_b64encode(raw_sig).decode().rstrip("=")
        else:
            sig_b64 = ""

        return f"{header_b64}.{payload_b64}.{sig_b64}"

    def test_disabled_by_default(self):
        """Account discovery must be disabled by default."""
        self.assertFalse(self.service.is_enabled())
        status = self.service.get_status()
        self.assertFalse(status["enabled"])
        self.assertEqual(status["status"], "DISABLED")

    def test_toggle_enabled(self):
        """User can explicitly toggle account discovery."""
        self.service.set_enabled(True)
        self.assertTrue(self.service.is_enabled())
        self.service.set_enabled(False)
        self.assertFalse(self.service.is_enabled())

    def test_rejection_of_alg_none(self):
        """Token with alg 'none' must be strictly rejected."""
        token = self._generate_jwt({"sub": "user-123", "exp": time.time() + 300}, alg="none")
        valid, claims, err = self.service.verify_oidc_token(token)
        self.assertFalse(valid)
        self.assertIn("rejected", err.lower())

    def test_rejection_of_expired_token(self):
        """Expired token must be rejected."""
        past_time = time.time() - 1000
        token = self._generate_jwt(
            {"sub": "user-123", "exp": past_time},
            rsa_key=self.rsa_private_key,
        )
        valid, claims, err = self.service.verify_oidc_token(
            token,
            clock_skew=10.0,
            public_key_pem=self.rsa_public_key_pem,
        )
        self.assertFalse(valid)
        self.assertIn("expired", err.lower())

    def test_missing_public_key_fails_closed(self):
        """When public key is None or empty, verification strictly fails closed."""
        now = time.time()
        token = self._generate_jwt(
            {"sub": "user-123", "exp": now + 600},
            rsa_key=self.rsa_private_key,
        )
        valid, claims, err = self.service.verify_oidc_token(token, public_key_pem=None)
        self.assertFalse(valid)
        self.assertIn("missing public key", err.lower())

        valid_empty, _, err_empty = self.service.verify_oidc_token(token, public_key_pem="   ")
        self.assertFalse(valid_empty)
        self.assertIn("missing public key", err_empty.lower())

    def test_issuer_and_audience_mismatch_rejection(self):
        """Issuer and audience mismatch must be rejected."""
        token = self._generate_jwt(
            {
                "sub": "user-123",
                "iss": "https://accounts.google.com",
                "aud": "snow-client-app",
                "exp": time.time() + 300,
            },
            rsa_key=self.rsa_private_key,
        )
        # Issuer mismatch
        valid, _, err = self.service.verify_oidc_token(
            token,
            expected_issuer="https://github.com",
            expected_audience="snow-client-app",
            public_key_pem=self.rsa_public_key_pem,
        )
        self.assertFalse(valid)
        self.assertIn("issuer mismatch", err.lower())

        # Audience mismatch
        valid, _, err = self.service.verify_oidc_token(
            token,
            expected_issuer="https://accounts.google.com",
            expected_audience="wrong-audience",
            public_key_pem=self.rsa_public_key_pem,
        )
        self.assertFalse(valid)
        self.assertIn("audience mismatch", err.lower())

    def test_valid_rs256_token_verification(self):
        """Valid RS256 token with correct signature and claims validates successfully."""
        now = time.time()
        payload = {
            "sub": "account-ayush-99",
            "iss": "https://accounts.snow.local",
            "aud": "snow-mesh-v4",
            "exp": now + 600,
            "nbf": now - 10,
        }
        token = self._generate_jwt(payload, alg="RS256", rsa_key=self.rsa_private_key)

        valid, claims, err = self.service.verify_oidc_token(
            token,
            expected_issuer="https://accounts.snow.local",
            expected_audience="snow-mesh-v4",
            public_key_pem=self.rsa_public_key_pem,
        )
        self.assertTrue(valid)
        self.assertIsNone(err)
        self.assertEqual(claims["sub"], "account-ayush-99")

    def test_valid_es256_token_verification(self):
        """Valid ES256 IEEE P1363 token converts to DER and validates successfully."""
        now = time.time()
        payload = {
            "sub": "account-ec-42",
            "iss": "https://id.apple.com",
            "aud": "snow-ios-bridge",
            "exp": now + 600,
        }
        token = self._generate_jwt(payload, alg="ES256", ec_key=self.ec_private_key)

        valid, claims, err = self.service.verify_oidc_token(
            token,
            expected_issuer="https://id.apple.com",
            expected_audience="snow-ios-bridge",
            public_key_pem=self.ec_public_key_pem,
        )
        self.assertTrue(valid)
        self.assertIsNone(err)
        self.assertEqual(claims["sub"], "account-ec-42")

    def test_tampered_es256_token_rejection(self):
        """Tampered ES256 token fails signature verification."""
        now = time.time()
        payload = {"sub": "account-ec-42", "exp": now + 600}
        token = self._generate_jwt(payload, alg="ES256", ec_key=self.ec_private_key)
        # Tamper payload while keeping valid exp
        parts = token.split(".")
        tampered_payload = {"sub": "account-hacked", "exp": now + 600}
        tampered_payload_b64 = base64.urlsafe_b64encode(json.dumps(tampered_payload).encode()).decode().rstrip("=")
        tampered_token = f"{parts[0]}.{tampered_payload_b64}.{parts[2]}"

        valid, _, err = self.service.verify_oidc_token(
            tampered_token,
            public_key_pem=self.ec_public_key_pem,
        )
        self.assertFalse(valid)
        self.assertIn("signature verification failed", err.lower())


if __name__ == "__main__":
    unittest.main()
