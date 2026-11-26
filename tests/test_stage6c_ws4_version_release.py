"""Stage 6C WS4 verification tests: V5.2.0 version parity, updater, packaging, and frozen invariants."""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path
import re
import sys
import tempfile
import unittest
import zipfile

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

import snow
from snow.core.config import CoreConfig
from snow.mcp.registry import CAPABILITY_REGISTRY, validate_registry
from snow.mcp.server import create_snow_mcp_server
from snow.mcp.tools import ALL_TOOL_NAMES
from snow.protocol.constants import PROTOCOL_VERSION
from snow.security.db import SCHEMA_VERSION
from snow.updater import (
    CURRENT_VERSION,
    REQUIRED_UI_ASSETS,
    apply_web_ui_update,
    compute_file_sha256,
    parse_version,
    validate_manifest,
)

# Match common Unicode emoji blocks (pictographs, symbols, transport, dingbats, variation selector)
_EMOJI_RE = re.compile(
    r"[\U0001F300-\U0001FAFF\u2600-\u26FF\u2700-\u27BF\uFE0F]"
)


class TestStage6CWS4VersionAndFrozenInvariants(unittest.TestCase):
    """Verify V7.0.0 version alignment across Python, Windows installer, Web UI, Android, and frozen invariants."""

    def test_v700_version_alignment_across_all_surfaces(self) -> None:
        self.assertEqual(snow.__version__, "7.0.0")
        self.assertEqual(CURRENT_VERSION, "7.0.0")
        self.assertEqual(CoreConfig().version, "7.0.0")
        self.assertEqual(CoreConfig.from_env().version, "7.0.0")

        pyproject_txt = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "7.0.0"', pyproject_txt)

        iss_txt = (REPO_ROOT / "packaging" / "windows" / "snow_setup.iss").read_text(encoding="utf-8")
        self.assertIn('#define MyAppVersion "7.0.0"', iss_txt)
        self.assertIn('#define MyAppURL "https://github.com/ayush77463/snow"', iss_txt)

        gradle_txt = (REPO_ROOT / "android" / "app" / "build.gradle.kts").read_text(encoding="utf-8")
        self.assertIn("versionCode = 5", gradle_txt)
        self.assertIn('versionName = "7.0.0"', gradle_txt)

        index_html = (REPO_ROOT / "src" / "snow" / "web" / "static" / "index.html").read_text(encoding="utf-8")
        self.assertIn("v7.0.0", index_html)
        self.assertNotIn("v5.2.0", index_html)

        app_js = (REPO_ROOT / "src" / "snow" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn('"7.0.0"', app_js)
        self.assertNotIn('"5.2.0"', app_js)

        settings_kt = (
            REPO_ROOT / "android" / "app" / "src" / "main" / "java" / "org" / "snow" / "ui" / "settings" / "SettingsScreen.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("7.0.0", settings_kt)

        snow_app_kt = (
            REPO_ROOT / "android" / "app" / "src" / "main" / "java" / "org" / "snow" / "ui" / "SnowApp.kt"
        ).read_text(encoding="utf-8")
        self.assertIn("7.0.0", snow_app_kt)

    def test_frozen_protocol_schema_and_54_fastmcp_tools(self) -> None:
        self.assertEqual(PROTOCOL_VERSION, 1)
        self.assertEqual(SCHEMA_VERSION, 7)

        ok, errors = validate_registry()
        self.assertTrue(ok, f"Registry validation failed: {errors}")
        self.assertEqual(len(CAPABILITY_REGISTRY), 54)
        self.assertEqual(len(ALL_TOOL_NAMES), 54)

        srv = create_snow_mcp_server()
        srv_tools = asyncio.run(srv.list_tools())
        self.assertEqual(len(srv_tools), 54)
        self.assertEqual({t.name for t in srv_tools}, set(CAPABILITY_REGISTRY.keys()))

    def test_ui_files_have_zero_emojis_and_zero_external_cdns(self) -> None:
        index_html = (REPO_ROOT / "src" / "snow" / "web" / "static" / "index.html").read_text(encoding="utf-8")
        app_js = (REPO_ROOT / "src" / "snow" / "web" / "static" / "app.js").read_text(encoding="utf-8")
        tools_kt = (
            REPO_ROOT / "android" / "app" / "src" / "main" / "java" / "org" / "snow" / "ui" / "tools" / "ToolsScreen.kt"
        ).read_text(encoding="utf-8")
        snow_app_kt = (
            REPO_ROOT / "android" / "app" / "src" / "main" / "java" / "org" / "snow" / "ui" / "SnowApp.kt"
        ).read_text(encoding="utf-8")

        for name, content in (
            ("index.html", index_html),
            ("app.js", app_js),
            ("ToolsScreen.kt", tools_kt),
            ("SnowApp.kt", snow_app_kt),
        ):
            matches = _EMOJI_RE.findall(content)
            self.assertEqual(matches, [], f"Found forbidden UI emoji chars in {name}: {matches[:5]}")

        # Ensure zero external CDN script/stylesheet links in index.html
        external_links = re.findall(r'(?:src|href)\s*=\s*["\']https?://', index_html, flags=re.IGNORECASE)
        self.assertEqual(external_links, [], f"Unexpected external CDN references: {external_links}")


class TestStage6CWS4UpdaterAndWebUiArchive(unittest.TestCase):
    """Verify semver comparison, build_web_ui_archive packaging, and manifest validation."""

    def test_numeric_semver_ordering(self) -> None:
        self.assertGreater(parse_version("7.0.0"), parse_version("5.2.0"))
        self.assertGreater(parse_version("5.10.0"), parse_version("5.2.0"))
        self.assertGreater(parse_version("v10.0.0"), parse_version("7.0.0"))

    def test_dynamic_apk_version_code_without_ceiling(self) -> None:
        import asyncio
        import json
        from snow.core.config import CoreConfig
        from snow.security.db import DatabaseManager
        from snow.transfer.http_server import SnowHttpTransferServer
        from snow.transfer.manager import TransferManager
        from snow.transfer.storage import TransferStorageManager

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            srv = SnowHttpTransferServer(
                config=CoreConfig(),
                db_manager=DatabaseManager(tmp_path / "ver.db"),
                transfer_manager=TransferManager(),
                storage_manager=TransferStorageManager(tmp),
            )
            req = type("Req", (), {"headers": {}, "path": "/api/v1/app/update-info"})()

            apk_70 = tmp_path / "SNOW-Mobile-7.0.0.apk"
            apk_70.write_bytes(b"PK70")
            srv._get_staged_apk_path = lambda: apk_70
            meta_70 = json.loads(asyncio.run(srv.handle_app_update_info(req)).text)
            self.assertEqual(meta_70["version_name"], "7.0.0")
            self.assertEqual(meta_70["version_code"], 5)

            apk_71 = tmp_path / "SNOW-Mobile-7.1.0.apk"
            apk_71.write_bytes(b"PK71")
            srv._get_staged_apk_path = lambda: apk_71
            meta_71 = json.loads(asyncio.run(srv.handle_app_update_info(req)).text)
            self.assertEqual(meta_71["version_name"], "7.1.0")
            self.assertGreater(meta_71["version_code"], meta_70["version_code"])

    def test_build_web_ui_archive_and_atomic_updater_apply(self) -> None:
        build_spec = importlib.util.spec_from_file_location(
            "build_release", REPO_ROOT / "packaging" / "windows" / "build_release.py"
        )
        assert build_spec is not None and build_spec.loader is not None
        build_mod = importlib.util.module_from_spec(build_spec)
        build_spec.loader.exec_module(build_mod)

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            zip_out = tmp_path / "snow-web-ui-7.0.0.zip"
            build_mod.build_web_ui_archive(REPO_ROOT / "src" / "snow" / "web" / "static", zip_out)
            self.assertTrue(zip_out.is_file())
            self.assertGreater(zip_out.stat().st_size, 10_000)

            with zipfile.ZipFile(zip_out, "r") as zf:
                names = set(zf.namelist())
            for req in REQUIRED_UI_ASSETS:
                self.assertIn(req, names)

            sha_zip = compute_file_sha256(zip_out)
            override_dir = tmp_path / "web_override"
            applied = apply_web_ui_update(zip_out, expected_sha256=sha_zip, override_dir=override_dir)
            self.assertTrue(applied)
            for req in REQUIRED_UI_ASSETS:
                self.assertTrue((override_dir / req).is_file())

            manifest = validate_manifest({
                "version": "7.0.0",
                "release_notes": "SNOW V7.0.0 release",
                "web_ui": {
                    "url": f"https://github.com/ayush77463/snow/releases/download/v7.0.0/{zip_out.name}",
                    "filename": zip_out.name,
                    "sha256": sha_zip,
                    "size_bytes": zip_out.stat().st_size,
                },
                "desktop": {
                    "url": "https://github.com/ayush77463/snow/releases/download/v7.0.0/SNOW-Setup-7.0.0.exe",
                    "filename": "SNOW-Setup-7.0.0.exe",
                    "sha256": "a" * 64,
                    "size_bytes": 123456,
                },
                "android": {
                    "version_code": 5,
                    "version_name": "7.0.0",
                    "apk_name": "SNOW-Mobile-7.0.0.apk",
                    "sha256": "b" * 64,
                    "size_bytes": 15700000,
                },
            })
            self.assertEqual(manifest["version"], "7.0.0")
            self.assertEqual(manifest["android"]["version_code"], 5)


if __name__ == "__main__":
    unittest.main()
