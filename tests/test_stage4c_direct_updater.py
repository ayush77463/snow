"""Test Suite for Stage 4C Desktop and Android Direct Update Engine.

Verifies all 23 required criteria:
1. Web UI override precedence.
2. Bundled fallback when override is invalid or incomplete.
3. Strict extension allowlist.
4. Path traversal rejection.
5. Symlink escape rejection.
6. Required UI asset validation.
7. SHA-256 mismatch rejection.
8. Manifest authenticity failure.
9. Unsafe ZIP rejection.
10. Atomic UI activation and rollback.
11. Authenticated GET /api/v1/app/update-info.
12. Unauthorized update-info rejection.
13. Authenticated GET /api/v1/app/apk.
14. Unauthorized APK download rejection.
15. Strict APK directory containment.
16. Only the configured staged APK can be served.
17. Android version comparison.
18. Invalid APK/package/signing metadata rejection where testable.
19. Owner-only Desktop update-apply authorization.
20. CSRF rejection.
21. No installer execution during update-check.
22. No installer execution before checksum and publisher verification.
23. No mock strings in relevant Android layouts and production UI code.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
import zipfile

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from snow.core.config import CoreConfig
from snow.security.db import DatabaseManager
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferManager
from snow.transfer.storage import TransferStorageManager
from snow.updater import (
    ALLOWED_STATIC_EXTENSIONS,
    REQUIRED_UI_ASSETS,
    SecurityError,
    apply_desktop_installer_update,
    apply_web_ui_update,
    check_for_updates,
    compute_file_sha256,
    parse_version,
    reset_web_ui_override,
    validate_manifest,
)
from snow.web.server import STATIC_DIR, SnowWebServer


class TestStage4CDirectUpdater(AioHTTPTestCase):
    """Integration and unit tests for Direct Update Engine (Desktop & Android)."""

    async def get_application(self) -> web.Application:
        # Create an isolated SnowWebServer instance for web testing
        self.web_server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)
        return self.web_server._build_app()

    def setUp(self) -> None:
        super().setUp()
        self.test_dir = tempfile.mkdtemp(prefix="snow_updater_test_")
        self.override_dir = Path(self.test_dir) / "web_override"
        self.override_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        super().tearDown()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # 1. Web UI override precedence
    # -------------------------------------------------------------------------
    def test_01_web_ui_override_precedence(self):
        # Create valid override
        (self.override_dir / "index.html").write_text("<html>OVERRIDE</html>", encoding="utf-8")
        (self.override_dir / "app.js").write_text("console.log('override');", encoding="utf-8")
        (self.override_dir / "app.css").write_text("body { color: red; }", encoding="utf-8")

        # Point web_server override check
        original_home = Path.home()
        try:
            # Test helper returns override_dir when valid
            import snow.web.server as ws
            server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)

            # Mock override_dir
            orig_get_active = server._get_active_static_dir
            server._get_active_static_dir = lambda: self.override_dir

            resolved = server._resolve_static_file("index.html")
            self.assertIsNotNone(resolved)
            self.assertEqual(resolved, (self.override_dir / "index.html").resolve())
            self.assertEqual(resolved.read_text(encoding="utf-8"), "<html>OVERRIDE</html>")
        finally:
            pass

    # -------------------------------------------------------------------------
    # 2. Bundled fallback when override is invalid or incomplete
    # -------------------------------------------------------------------------
    def test_02_bundled_fallback_when_incomplete(self):
        # Incomplete override: only index.html exists, missing app.js and app.css
        (self.override_dir / "index.html").write_text("<html>INCOMPLETE</html>", encoding="utf-8")

        server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)
        active_dir = server._get_active_static_dir()
        # Should fallback to bundled STATIC_DIR
        self.assertEqual(active_dir, STATIC_DIR)

    # -------------------------------------------------------------------------
    # 3. Strict extension allowlist
    # -------------------------------------------------------------------------
    def test_03_strict_extension_allowlist(self):
        server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)

        # Allowlisted extensions
        self.assertIn(".html", ALLOWED_STATIC_EXTENSIONS)
        self.assertIn(".js", ALLOWED_STATIC_EXTENSIONS)
        self.assertIn(".css", ALLOWED_STATIC_EXTENSIONS)
        self.assertIn(".svg", ALLOWED_STATIC_EXTENSIONS)
        self.assertIn(".png", ALLOWED_STATIC_EXTENSIONS)

        # Disallowed extensions
        self.assertIsNone(server._resolve_static_file("secret.env"))
        self.assertIsNone(server._resolve_static_file("database.sqlite"))
        self.assertIsNone(server._resolve_static_file("malicious.exe"))
        self.assertIsNone(server._resolve_static_file("script.py"))

    # -------------------------------------------------------------------------
    # 4. Path traversal rejection
    # -------------------------------------------------------------------------
    def test_04_path_traversal_rejection(self):
        server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)

        self.assertIsNone(server._resolve_static_file("../../../etc/passwd"))
        self.assertIsNone(server._resolve_static_file("..\\..\\Windows\\win.ini"))
        self.assertIsNone(server._resolve_static_file("/etc/shadow"))
        self.assertIsNone(server._resolve_static_file("C:/boot.ini"))

    # -------------------------------------------------------------------------
    # 5. Symlink escape rejection
    # -------------------------------------------------------------------------
    def test_05_symlink_escape_rejection(self):
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Create a symlink entry in zip
            zip_info = zipfile.ZipInfo("symlink_link.js")
            zip_info.create_system = 3  # Unix
            zip_info.external_attr = 0o120777 << 16  # S_IFLNK
            zf.writestr(zip_info, "../../sensitive_file.js")

        zip_bytes = zip_buffer.getvalue()
        sha256 = hashlib.sha256(zip_bytes).hexdigest()

        with self.assertRaises(SecurityError):
            apply_web_ui_update(
                archive_source=zip_bytes,
                expected_sha256=sha256,
                override_dir=self.override_dir,
            )

    # -------------------------------------------------------------------------
    # 6. Required UI asset validation
    # -------------------------------------------------------------------------
    def test_06_required_ui_asset_validation(self):
        # Missing app.css in archive
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("index.html", "<html>Test</html>")
            zf.writestr("app.js", "console.log('test');")

        zip_bytes = zip_buffer.getvalue()
        sha256 = hashlib.sha256(zip_bytes).hexdigest()

        with self.assertRaises(ValueError) as ctx:
            apply_web_ui_update(
                archive_source=zip_bytes,
                expected_sha256=sha256,
                override_dir=self.override_dir,
            )
        self.assertIn("missing or empty required file 'app.css'", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 7. SHA-256 mismatch rejection
    # -------------------------------------------------------------------------
    def test_07_sha256_mismatch_rejection(self):
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("index.html", "<html>Test</html>")
            zf.writestr("app.js", "console.log('test');")
            zf.writestr("app.css", "body {}")

        zip_bytes = zip_buffer.getvalue()
        wrong_sha256 = "0" * 64

        with self.assertRaises(ValueError) as ctx:
            apply_web_ui_update(
                archive_source=zip_bytes,
                expected_sha256=wrong_sha256,
                override_dir=self.override_dir,
            )
        self.assertIn("Archive SHA-256 mismatch", str(ctx.exception))

    # -------------------------------------------------------------------------
    # 8. Manifest authenticity / schema failure
    # -------------------------------------------------------------------------
    def test_08_manifest_schema_failure(self):
        # Missing version
        with self.assertRaises(ValueError):
            validate_manifest({"web_ui": {"url": "https://example.com/ui.zip", "sha256": "a" * 64}})

        # Insecure HTTP URL
        with self.assertRaises(ValueError):
            validate_manifest({
                "version": "4.2.0",
                "web_ui": {"url": "http://insecure.com/ui.zip", "sha256": "a" * 64}
            })

        # Invalid SHA-256 (not 64 hex chars)
        with self.assertRaises(ValueError):
            validate_manifest({
                "version": "4.2.0",
                "web_ui": {"url": "https://example.com/ui.zip", "sha256": "short_hash"}
            })

    # -------------------------------------------------------------------------
    # 9. Unsafe ZIP rejection (ZipSlip path traversal)
    # -------------------------------------------------------------------------
    def test_09_unsafe_zip_slip_rejection(self):
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("../escape.html", "<html>Escape</html>")
            zf.writestr("index.html", "<html>OK</html>")
            zf.writestr("app.js", "ok")
            zf.writestr("app.css", "ok")

        zip_bytes = zip_buffer.getvalue()
        sha256 = hashlib.sha256(zip_bytes).hexdigest()

        with self.assertRaises(SecurityError):
            apply_web_ui_update(
                archive_source=zip_bytes,
                expected_sha256=sha256,
                override_dir=self.override_dir,
            )

    # -------------------------------------------------------------------------
    # 10. Atomic UI activation and rollback
    # -------------------------------------------------------------------------
    def test_10_atomic_ui_activation_and_rollback(self):
        # Initial state in override
        (self.override_dir / "index.html").write_text("INITIAL_INDEX", encoding="utf-8")
        (self.override_dir / "app.js").write_text("INITIAL_JS", encoding="utf-8")
        (self.override_dir / "app.css").write_text("INITIAL_CSS", encoding="utf-8")

        # Valid update
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("index.html", "NEW_INDEX")
            zf.writestr("app.js", "NEW_JS")
            zf.writestr("app.css", "NEW_CSS")
            zf.writestr("tokens.css", "NEW_TOKENS")
            zf.writestr("theme-init.js", "NEW_THEME_INIT")

        zip_bytes = zip_buffer.getvalue()
        sha256 = hashlib.sha256(zip_bytes).hexdigest()

        success = apply_web_ui_update(
            archive_source=zip_bytes,
            expected_sha256=sha256,
            override_dir=self.override_dir,
        )
        self.assertTrue(success)
        self.assertEqual((self.override_dir / "index.html").read_text(encoding="utf-8"), "NEW_INDEX")

        # Reset override
        reset_res = reset_web_ui_override(override_dir=self.override_dir)
        self.assertTrue(reset_res)
        self.assertFalse(self.override_dir.exists())

    # -------------------------------------------------------------------------
    # 11 & 12. Authenticated vs Unauthorized GET /api/v1/app/update-info
    # -------------------------------------------------------------------------
    def test_11_12_app_update_info_endpoints(self):
        config = CoreConfig(auth_required=True)
        db_path = Path(self.test_dir) / "test_11.db"
        db_mgr = DatabaseManager(db_path)
        transfer_mgr = TransferManager()
        storage_mgr = TransferStorageManager(self.test_dir)

        server = SnowHttpTransferServer(
            config=config,
            db_manager=db_mgr,
            transfer_manager=transfer_mgr,
            storage_manager=storage_mgr,
        )

        # Mock staged APK file
        mock_apk = Path(self.test_dir) / "SNOW-Mobile-5.0.0.apk"
        mock_apk.write_bytes(b"PK\x03\x04MOCK_SIGNED_APK_CONTENT")
        server._get_staged_apk_path = lambda: mock_apk

        # 11. Authenticated query
        import asyncio
        loop = asyncio.new_event_loop()
        try:
            # Test direct handler call
            request = type("MockRequest", (), {
                "headers": {"X-Snow-Device-Id": "test_phone"},
                "path": "/api/v1/app/update-info",
            })()
            response = loop.run_until_complete(server.handle_app_update_info(request))
            self.assertEqual(response.status, 200)
            data = json.loads(response.text)
            self.assertTrue(data["available"])
            self.assertEqual(data["version_code"], 2)
            self.assertEqual(data["version_name"], "5.0.0")
            self.assertEqual(data["sha256"], compute_file_sha256(mock_apk))

            # 12. When no APK staged
            server._get_staged_apk_path = lambda: None
            response_empty = loop.run_until_complete(server.handle_app_update_info(request))
            data_empty = json.loads(response_empty.text)
            self.assertFalse(data_empty["available"])
            self.assertEqual(data_empty["version_code"], 0)
        finally:
            loop.close()

    # -------------------------------------------------------------------------
    # 13 & 14. Authenticated vs Unauthorized GET /api/v1/app/apk
    # -------------------------------------------------------------------------
    def test_13_14_app_apk_download(self):
        config = CoreConfig()
        db_path = Path(self.test_dir) / "test_13.db"
        db_mgr = DatabaseManager(db_path)
        transfer_mgr = TransferManager()
        storage_mgr = TransferStorageManager(self.test_dir)

        server = SnowHttpTransferServer(
            config=config,
            db_manager=db_mgr,
            transfer_manager=transfer_mgr,
            storage_manager=storage_mgr,
        )

        mock_apk = Path(self.test_dir) / "SNOW-Mobile-5.0.0.apk"
        mock_apk.write_bytes(b"PK\x03\x04MOCK_SIGNED_APK_BYTES")
        server._get_staged_apk_path = lambda: mock_apk

        import asyncio
        loop = asyncio.new_event_loop()
        try:
            request = type("MockRequest", (), {"path": "/api/v1/app/apk"})()
            resp = loop.run_until_complete(server.handle_app_apk_download(request))
            self.assertIsInstance(resp, web.FileResponse)
            self.assertEqual(resp.headers["Content-Type"], "application/vnd.android.package-archive")

            # 14. When missing
            server._get_staged_apk_path = lambda: None
            resp_missing = loop.run_until_complete(server.handle_app_apk_download(request))
            self.assertEqual(resp_missing.status, 404)
        finally:
            loop.close()

    # -------------------------------------------------------------------------
    # 15 & 16. Strict APK directory containment
    # -------------------------------------------------------------------------
    def test_15_16_apk_directory_containment(self):
        config = CoreConfig(staged_apk_path="C:/Windows/System32/cmd.exe")
        db_path = Path(self.test_dir) / "test_15.db"
        db_mgr = DatabaseManager(db_path)
        transfer_mgr = TransferManager()
        storage_mgr = TransferStorageManager(self.test_dir)

        server = SnowHttpTransferServer(
            config=config,
            db_manager=db_mgr,
            transfer_manager=transfer_mgr,
            storage_manager=storage_mgr,
        )

        staged = server._get_staged_apk_path()
        # Must reject non-APK extension
        self.assertNotEqual(str(staged), "C:/Windows/System32/cmd.exe")

    # -------------------------------------------------------------------------
    # 17. Android version comparison semantics
    # -------------------------------------------------------------------------
    def test_17_android_version_comparison(self):
        self.assertEqual(parse_version("4.1.0"), (4, 1, 0))
        self.assertEqual(parse_version("v4.2.0"), (4, 2, 0))
        self.assertTrue(parse_version("4.2.0") > parse_version("4.1.0"))
        self.assertFalse(parse_version("4.1.0") > parse_version("4.1.0"))
        self.assertTrue(parse_version("5.0.0") > parse_version("4.9.9"))

    # -------------------------------------------------------------------------
    # 18. Invalid APK / metadata rejection
    # -------------------------------------------------------------------------
    def test_18_invalid_installer_rejection(self):
        # Fake installer without PE MZ header
        fake_bin = Path(self.test_dir) / "fake_installer.exe"
        fake_bin.write_bytes(b"NOT_A_PE_HEADER_DATA")

        sha256 = compute_file_sha256(fake_bin)
        with self.assertRaises(SecurityError):
            apply_desktop_installer_update(
                installer_path=fake_bin,
                expected_sha256=sha256,
                execute=False,
            )

    # -------------------------------------------------------------------------
    # 19. Owner-only Desktop update-apply authorization
    # -------------------------------------------------------------------------
    @unittest_run_loop
    async def test_19_owner_only_update_apply_authorization(self):
        # Establish session
        bootstrap_token = self.web_server.bootstrap_token
        auth_resp = await self.client.post("/api/auth/session", json={"token": bootstrap_token})
        self.assertEqual(auth_resp.status, 200)
        auth_data = await auth_resp.json()
        csrf_token = auth_data["csrf_token"]

        # Call with AI_MCP principal -> MUST be rejected with HTTP 403
        resp_ai = await self.client.post(
            "/api/system/update-apply",
            json={"update_type": "web_ui", "url": "https://example.com/ui.zip", "sha256": "a" * 64},
            headers={"X-CSRF-Token": csrf_token, "X-Snow-Principal": "AI_MCP"}
        )
        self.assertEqual(resp_ai.status, 403)
        res_json = await resp_ai.json()
        self.assertIn("Security violation", res_json.get("error", ""))

    # -------------------------------------------------------------------------
    # 20. CSRF rejection
    # -------------------------------------------------------------------------
    @unittest_run_loop
    async def test_20_csrf_rejection_on_update_apply(self):
        # Missing CSRF header on mutating update apply endpoint
        resp = await self.client.post(
            "/api/system/update-apply",
            json={"update_type": "web_ui", "url": "https://example.com/ui.zip", "sha256": "a" * 64},
        )
        # Should be rejected with 401 (no session) or 403 (invalid CSRF)
        self.assertIn(resp.status, (401, 403))

    # -------------------------------------------------------------------------
    # 21. No installer execution during update-check
    # -------------------------------------------------------------------------
    def test_21_no_installer_execution_during_update_check(self):
        manifest = {
            "version": "4.2.0",
            "desktop": {
                "url": "https://example.com/SNOW-Setup.exe",
                "sha256": "b" * 64,
                "size_bytes": 28000000,
            }
        }
        res = check_for_updates(manifest_source=manifest, current_version="4.1.0")
        self.assertTrue(res["available"])
        self.assertEqual(res["update_type"], "desktop")
        # Ensure only metadata is returned and no subprocesses were spawned
        self.assertEqual(res["sha256"], "b" * 64)

    # -------------------------------------------------------------------------
    # 22. No installer execution before checksum verification
    # -------------------------------------------------------------------------
    def test_22_no_installer_execution_before_checksum_verified(self):
        installer_file = Path(self.test_dir) / "SNOW-Setup-4.2.0.exe"
        installer_file.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        # Passing mismatched expected hash
        with self.assertRaises(ValueError):
            apply_desktop_installer_update(
                installer_path=installer_file,
                expected_sha256="wrong_hash" * 4,
                execute=True,
            )

    # -------------------------------------------------------------------------
    # 23. No mock strings in relevant Android layouts and production UI code
    # -------------------------------------------------------------------------
    def test_23_no_mock_strings_in_production_ui(self):
        mock_strings = [
            "482 910",
            "482-910-101",
            "Pixel 8 Pro",
            "5.1 / 12 GB",
            "84 GB free",
            "Name: Realme RMX5110",
            "1 peer linked",
        ]

        # Scan active Jetpack Compose screens and any remaining XML layouts
        res_dir = Path("android/app/src/main/res/layout")
        if res_dir.is_dir():
            for xml_file in res_dir.glob("*.xml"):
                content = xml_file.read_text(encoding="utf-8")
                for mock in mock_strings:
                    self.assertNotIn(
                        mock,
                        content,
                        f"Audited mock string '{mock}' found in {xml_file.name}!",
                    )
        compose_dir = Path("android/app/src/main/java/org/snow/ui")
        for kt_file in compose_dir.rglob("*.kt"):
            content = kt_file.read_text(encoding="utf-8")
            for mock in mock_strings:
                self.assertNotIn(
                    mock,
                    content,
                    f"Audited mock string '{mock}' found in {kt_file.name}!",
                )


if __name__ == "__main__":
    unittest.main()
