"""Unit and integration test suite for Phase 17: One-Command Onboarding & Device CLI.

Tests:
1. Multi-Host Onboarding (Claude, Gemini, Cursor, ChatGPT, --dry-run, --remove, backups, merges).
2. Device & Trust Management CLI (snow devices list, trust, revoke, connect, --json, single-owner invariant).
3. System Health & Readiness Diagnostics (snow doctor, --json, 24-tool invariant, dependency checks).
4. CLI parser, dispatch, and exit codes.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.cli import (
    build_parser,
    main,
    run_devices_connect,
    run_devices_list,
    run_devices_revoke,
    run_devices_trust,
    run_doctor,
    run_setup,
)
from snow.mcp.tools import ALL_TOOL_NAMES
from snow.onboarding import (
    ChatGPTAdapter,
    ClaudeAdapter,
    CursorAdapter,
    GeminiAdapter,
    HostOnboardingManager,
    atomic_write_json,
    safe_read_json,
)
from snow.security.db import DatabaseManager


class TestHostOnboarding(unittest.TestCase):
    """Test AI assistant configuration generation, merging, backups, and removal."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_onboarding_")
        self.claude_path = Path(self.temp_dir) / "claude.json"
        self.gemini_path = Path(self.temp_dir) / "gemini.json"
        self.cursor_path = Path(self.temp_dir) / "cursor.json"
        self.chatgpt_path = Path(self.temp_dir) / "chatgpt.json"

        self.custom_paths = {
            "claude": self.claude_path,
            "gemini": self.gemini_path,
            "cursor": self.cursor_path,
            "chatgpt": self.chatgpt_path,
        }
        self.fake_python = "C:\\Program Files\\Python313\\python.exe"
        self.manager = HostOnboardingManager(
            custom_paths=self.custom_paths,
            python_exe=self.fake_python,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_claude_setup_creates_new_config(self) -> None:
        """Configuring Claude when no file exists creates valid JSON with mcpServers.snow."""
        res = self.manager.setup_host("claude")
        self.assertTrue(res["success"])
        self.assertEqual(res["action"], "CREATE")
        self.assertTrue(self.claude_path.exists())

        data, err = safe_read_json(self.claude_path)
        self.assertIsNone(err)
        self.assertIn("mcpServers", data)
        self.assertIn("snow", data["mcpServers"])
        self.assertEqual(data["mcpServers"]["snow"]["command"], self.fake_python)
        self.assertEqual(data["mcpServers"]["snow"]["args"], ["-m", "snow.mcp"])

    def test_claude_setup_merges_preserving_existing_keys_and_siblings(self) -> None:
        """Configuring Claude preserves unrelated settings and sibling MCP servers."""
        initial_data = {
            "theme": "dark",
            "fontSize": 14,
            "mcpServers": {
                "filesystem": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\projects"],
                }
            },
        }
        self.claude_path.write_text(json.dumps(initial_data, indent=2), encoding="utf-8")

        res = self.manager.setup_host("claude")
        self.assertTrue(res["success"])
        self.assertEqual(res["action"], "UPDATE")
        self.assertIsNotNone(res.get("backup_path"))
        self.assertTrue(Path(res["backup_path"]).exists())

        data, err = safe_read_json(self.claude_path)
        self.assertIsNone(err)
        # Preserved top-level keys
        self.assertEqual(data.get("theme"), "dark")
        self.assertEqual(data.get("fontSize"), 14)
        # Preserved sibling MCP server
        self.assertIn("filesystem", data["mcpServers"])
        # Added SNOW MCP server
        self.assertIn("snow", data["mcpServers"])
        self.assertEqual(data["mcpServers"]["snow"]["command"], self.fake_python)

    def test_gemini_and_cursor_setup_creates_and_merges(self) -> None:
        """Gemini and Cursor adapters successfully create and update configurations."""
        res_g = self.manager.setup_host("gemini")
        self.assertTrue(res_g["success"])
        self.assertTrue(self.gemini_path.exists())

        res_c = self.manager.setup_host("cursor")
        self.assertTrue(res_c["success"])
        self.assertTrue(self.cursor_path.exists())

        # Verify Cursor preserves sibling
        cursor_data, _ = safe_read_json(self.cursor_path)
        self.assertIn("snow", cursor_data["mcpServers"])

    def test_chatgpt_setup_creates_documented_artifact(self) -> None:
        """ChatGPT adapter creates documented artifact file and includes note."""
        res = self.manager.setup_host("chatgpt")
        self.assertTrue(res["success"])
        self.assertTrue(self.chatgpt_path.exists())
        self.assertIn("notes", res)

    def test_setup_host_all_configures_all_hosts(self) -> None:
        """--host all configures all supported hosts in a single call."""
        res = self.manager.setup_host("all")
        self.assertTrue(res["success"])
        self.assertEqual(len(res["results"]), 4)
        self.assertTrue(self.claude_path.exists())
        self.assertTrue(self.gemini_path.exists())
        self.assertTrue(self.cursor_path.exists())
        self.assertTrue(self.chatgpt_path.exists())

    def test_dry_run_makes_zero_filesystem_changes(self) -> None:
        """--dry-run simulates changes and creates zero files on disk."""
        res = self.manager.setup_host("claude", dry_run=True)
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "DRY_RUN")
        self.assertFalse(self.claude_path.exists())

    def test_remove_removes_snow_entry_preserving_siblings(self) -> None:
        """--remove removes only the SNOW entry, preserving sibling servers."""
        initial_data = {
            "mcpServers": {
                "snow": {"command": "python", "args": ["-m", "snow.mcp"]},
                "other_server": {"command": "node", "args": ["server.js"]},
            }
        }
        self.claude_path.write_text(json.dumps(initial_data, indent=2), encoding="utf-8")

        res = self.manager.remove_host("claude")
        self.assertTrue(res["success"])
        self.assertEqual(res["status"], "REMOVED")

        data, _ = safe_read_json(self.claude_path)
        self.assertNotIn("snow", data["mcpServers"])
        self.assertIn("other_server", data["mcpServers"])

    def test_remove_repeated_is_idempotent(self) -> None:
        """Removing SNOW when already removed succeeds safely (ALREADY_REMOVED)."""
        self.claude_path.write_text(json.dumps({"mcpServers": {}}), encoding="utf-8")
        res1 = self.manager.remove_host("claude")
        self.assertTrue(res1["success"])
        self.assertEqual(res1["status"], "ALREADY_REMOVED")

        # Removing when file does not exist
        res2 = self.manager.remove_host("gemini")
        self.assertTrue(res2["success"])
        self.assertEqual(res2["status"], "NOT_PRESENT")

    def test_corrupt_json_handled_without_crashing_or_data_loss(self) -> None:
        """Invalid JSON in existing config produces structured error without crashing."""
        self.claude_path.write_text("{ unclosed invalid json ...", encoding="utf-8")
        res = self.manager.setup_host("claude")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "INVALID_EXISTING_CONFIG")
        self.assertIn("Failed parsing JSON", res["error"])
        # Original file left intact
        self.assertTrue(self.claude_path.read_text(encoding="utf-8").startswith("{ unclosed"))


class TestDevicesCLI(unittest.TestCase):
    """Test 'snow devices' subcommands (list, trust, revoke, connect)."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_devices_cli_")
        self.db_path = Path(self.temp_dir) / "test_devices.db"
        self.db = DatabaseManager(db_path=self.db_path)

        # Seed two paired devices (one owner, one peer)
        self.db.insert_paired_device(
            device_id="dev-owner-1111",
            device_name="Primary Pixel 8",
            auth_token_hash="hash_owner_1",
            trust_tier="owner",
            platform="android",
            reachability_profile="ACTIVE_SESSION_PEER",
            last_known_host="192.168.1.100",
            last_known_port=8765,
        )
        self.db.insert_paired_device(
            device_id="dev-peer-2222",
            device_name="Secondary Workstation",
            auth_token_hash="hash_peer_2",
            trust_tier="peer",
            platform="windows",
            reachability_profile="PERSISTENT_DAEMON",
            last_known_host="192.168.1.101",
            last_known_port=8765,
        )

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_devices_list_offline_database(self) -> None:
        """'snow devices list' reads from offline database when daemon is not running."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_devices_list(json_output=False, db_path=self.db_path)
        self.assertEqual(code, 0)
        out = buf.getvalue()
        self.assertIn("SNOW Devices (2 registered)", out)
        self.assertIn("Primary Pixel 8", out)
        self.assertIn("Secondary Workstation", out)
        self.assertIn("Trust Tier:   OWNER", out)
        self.assertIn("Trust Tier:   PEER", out)
        # Verify no token hashes leaked
        self.assertNotIn("hash_owner_1", out)
        self.assertNotIn("hash_peer_2", out)

    def test_devices_list_json_format(self) -> None:
        """'snow devices list --json' outputs valid machine-readable JSON."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_devices_list(json_output=True, db_path=self.db_path)
        self.assertEqual(code, 0)
        out = buf.getvalue()
        data = json.loads(out)
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("count"), 2)
        devs = data.get("devices", [])
        self.assertEqual(len(devs), 2)
        dev_ids = {d["device_id"] for d in devs}
        self.assertIn("dev-owner-1111", dev_ids)
        self.assertIn("dev-peer-2222", dev_ids)

    def test_devices_trust_update_with_yes_flag(self) -> None:
        """'snow devices trust <id> --tier <tier> --yes' updates trust without prompting."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_devices_trust("dev-peer-2222", "owner", yes=True, db_path=self.db_path)
        self.assertEqual(code, 0)

        # Verify single owner invariant: dev-peer-2222 became OWNER, dev-owner-1111 demoted to PEER
        dev2 = self.db.get_paired_device("dev-peer-2222")
        dev1 = self.db.get_paired_device("dev-owner-1111")
        self.assertEqual(dev2.trust_tier, "owner")
        self.assertEqual(dev1.trust_tier, "peer")

    def test_devices_trust_online_daemon_ipc(self) -> None:
        """When daemon is online, 'snow devices trust' notifies daemon via IPC."""
        buf = io.StringIO()
        with patch("snow.cli.SnowMcpBridge") as mock_bridge_cls:
            mock_bridge = MagicMock()
            mock_bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)
            mock_bridge.call = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
            mock_bridge_cls.return_value = mock_bridge

            with patch("sys.stdout", buf):
                code = run_devices_trust("dev-peer-2222", "owner", yes=True, db_path=self.db_path)
            self.assertEqual(code, 0)
            mock_bridge.call.assert_called_once_with("device_trust", {"device_id": "dev-peer-2222", "tier": "owner"})
            self.assertIn("via Core IPC", buf.getvalue())

    def test_devices_revoke_online_daemon_ipc(self) -> None:
        """When daemon is online, 'snow devices revoke' notifies daemon via IPC."""
        buf = io.StringIO()
        with patch("snow.cli.SnowMcpBridge") as mock_bridge_cls:
            mock_bridge = MagicMock()
            mock_bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=True)
            mock_bridge.call = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
            mock_bridge_cls.return_value = mock_bridge

            with patch("sys.stdout", buf):
                code = run_devices_revoke("dev-peer-2222", yes=True, db_path=self.db_path)
            self.assertEqual(code, 0)
            mock_bridge.call.assert_called_once_with("device_revoke", {"device_id": "dev-peer-2222"})
            self.assertIn("credentials deleted", buf.getvalue())

    def test_devices_trust_unknown_device_returns_error(self) -> None:
        """Updating trust for an unknown device ID produces error and exit code 1."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_devices_trust("non-existent-device-uuid", "owner", yes=True, db_path=self.db_path)
        self.assertEqual(code, 1)
        self.assertIn("not registered", buf.getvalue())

    def test_devices_trust_invalid_tier_rejected(self) -> None:
        """Invalid tier value is rejected."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_devices_trust("dev-peer-2222", "superadmin", yes=True, db_path=self.db_path)
        self.assertEqual(code, 1)
        self.assertIn("Invalid tier", buf.getvalue())

    def test_devices_revoke_with_yes_flag(self) -> None:
        """'snow devices revoke <id> --yes' permanently removes device from database."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_devices_revoke("dev-peer-2222", yes=True, db_path=self.db_path)
        self.assertEqual(code, 0)
        self.assertIn("credentials deleted", buf.getvalue())

        # Device is gone from database
        self.assertIsNone(self.db.get_paired_device("dev-peer-2222"))
        # Audit log is preserved
        audit_logs = self.db.get_audit_logs()
        self.assertTrue(any(log.event_type == "DEVICE_REVOKED" for log in audit_logs))

    def test_devices_revoke_unknown_device_returns_error(self) -> None:
        """Revoking non-existent device returns exit code 1."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_devices_revoke("unknown-dev-id", yes=True, db_path=self.db_path)
        self.assertEqual(code, 1)
        self.assertIn("not registered", buf.getvalue())

    def test_devices_connect_validation_and_pin_redaction(self) -> None:
        """'snow devices connect' validates port and never logs PIN in cleartext."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            # Out-of-bounds port
            code = run_devices_connect("127.0.0.1", port=99999, pin="123456")
        self.assertEqual(code, 1)
        self.assertIn("Invalid port", buf.getvalue())
        self.assertNotIn("123456", buf.getvalue())


class TestDoctorCLI(unittest.TestCase):
    """Test 'snow doctor' diagnostic readiness checks."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_doctor_")
        self.db_path = Path(self.temp_dir) / "test_doctor.db"
        self.db = DatabaseManager(db_path=self.db_path)

        self.cert_path = Path(self.temp_dir) / "server.crt"
        self.key_path = Path(self.temp_dir) / "server.key"
        self.cert_path.write_text("DUMMY CERTIFICATE", encoding="utf-8")
        self.key_path.write_text("DUMMY PRIVATE KEY", encoding="utf-8")

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_doctor_healthy_environment(self) -> None:
        """Doctor reports READY when database and core dependencies are healthy."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_doctor(
                json_output=False,
                db_path=self.db_path,
                cert_path=self.cert_path,
                key_path=self.key_path,
            )
        self.assertEqual(code, 0)
        out = buf.getvalue()
        self.assertIn("Overall Health: READY", out)
        self.assertIn("[OK]               Python Environment", out)
        self.assertIn("[OK]               Core Dependencies", out)
        self.assertIn("[OK]               SQLite Database", out)
        self.assertIn("[OK]               MCP Tool Catalog", out)

    def test_doctor_json_output_format(self) -> None:
        """Doctor with --json returns structured JSON with all 9 checks."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_doctor(
                json_output=True,
                db_path=self.db_path,
                cert_path=self.cert_path,
                key_path=self.key_path,
            )
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["overall_health"], "READY")
        self.assertEqual(len(data["checks"]), 9)
        components = {c["component"] for c in data["checks"]}
        self.assertIn("python_environment", components)
        self.assertIn("package_installation", components)
        self.assertIn("dependencies", components)
        self.assertIn("sqlite_database", components)
        self.assertIn("tls_certificates", components)
        self.assertIn("capability_engine", components)
        self.assertIn("daemon_ipc", components)
        self.assertIn("mcp_tool_catalog", components)
        self.assertIn("ai_host_integrations", components)

    def test_doctor_detects_corrupt_database(self) -> None:
        """Corrupt or non-SQLite database is detected and reported as FAILED."""
        bad_db_path = Path(self.temp_dir) / "corrupt.db"
        bad_db_path.write_text("NOT A SQLITE DATABASE", encoding="utf-8")

        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = run_doctor(
                json_output=True,
                db_path=bad_db_path,
                cert_path=self.cert_path,
                key_path=self.key_path,
            )
        self.assertEqual(code, 1)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["overall_health"], "ACTION_REQUIRED")
        db_check = next(c for c in data["checks"] if c["component"] == "sqlite_database")
        self.assertEqual(db_check["status"], "FAILED")

    def test_doctor_enforces_exactly_24_mcp_tools(self) -> None:
        """Doctor asserts that the registered MCP tool count is exactly 24."""
        self.assertEqual(len(ALL_TOOL_NAMES), 24)


class TestCliParserAndDispatch(unittest.TestCase):
    """Test top-level CLI argument parsing, subcommands, and help flags."""

    def test_cli_help_flags(self) -> None:
        """'snow --help' and subcommands --help return exit code 0."""
        for cmd in (["--help"], ["setup", "--help"], ["devices", "--help"], ["doctor", "--help"]):
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                with self.assertRaises(SystemExit) as cm:
                    main(cmd)
                self.assertEqual(cm.exception.code, 0)

    def test_cli_setup_dry_run_dispatch(self) -> None:
        """'snow setup --dry-run' dispatches cleanly through main()."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["setup", "--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("DRY RUN MODE", buf.getvalue())

    def test_cli_doctor_dispatch(self) -> None:
        """'snow doctor --json' dispatches cleanly through main()."""
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            code = main(["doctor", "--json"])
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertIn("overall_health", data)


if __name__ == "__main__":
    unittest.main()
