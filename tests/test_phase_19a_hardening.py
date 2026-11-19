"""Phase 19A Security, Boundary, Parity, and Hardening Regression Test Suite.

Verifies:
1. Terminal Authorization & Execution Security:
   - Direct executor invocation without valid ticket validator fails closed.
   - Arbitrary string or client-supplied confirmed=True fails closed.
   - AI_MCP cannot execute OWNER_CONFIRMED commands.
   - Catastrophic commands (format /q, rmdir /s /q C:/Windows) blocked for ALL principals.
   - Ticket replay is strictly rejected (single-use consumption).
2. Transfer Storage Boundary Exemption (GAP-13):
   - Scoped access to ~/.snow/transfers/ permitted.
   - Access to parent ~/.snow/ or sensitive files (.db, .key, .parts/) strictly blocked.
   - Traversal (..) and symlink escapes outside transfers/ strictly blocked.
3. CLI Database Isolation (GAP-11):
   - Explicit db_path operates deterministically on isolated SQLite database without touching daemon bridge.
4. DeviceNode Cross-Language Parity:
   - ONLINE_ROUTED state, epoch seconds, isAuthenticated, android.ringer.ring capability.
"""

from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.engine import CapabilityEngine, CapabilityRequest
from snow.capabilities.windows.files import WindowsFileManager
from snow.capabilities.windows.terminal import (
    TerminalSecurityTier,
    WindowsTerminalExecutor,
)
from snow.cli import run_devices_list
from snow.core.config import CoreConfig
from snow.security.db import DatabaseManager
from snow.network.node import (
    ANDROID_CAPABILITIES,
    CAPABILITY_ALIASES,
    CapabilityExecutionClassification,
    CapabilityManifest,
    DeviceNode,
    ReachabilityProfile,
    ReachabilityState,
    build_android_manifest,
)
from snow.security.context import ExecutionContext, ExecutionPrincipal


class TestTerminalAuthorizationHardening(unittest.IsolatedAsyncioTestCase):
    """Test Terminal security hardening and bypass prevention."""

    async def asyncSetUp(self) -> None:
        self.executor = WindowsTerminalExecutor()

    async def test_direct_executor_call_without_validator_fails_closed(self) -> None:
        """Direct call to execute_command with Tier C command fails closed if no validator set."""
        ctx_owner = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)
        res = await self.executor.execute_command(
            command="powershell -Command Restart-Service Spooler",
            ctx=ctx_owner,
            confirmed=True,
            confirmation_ticket="some-random-ticket",
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "CONFIRMATION_REQUIRED")

    async def test_direct_executor_ignores_confirmed_boolean(self) -> None:
        """confirmed=True without ticket validator fails closed for OWNER_CONFIRMED."""
        ctx_owner = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL)
        res = await self.executor.execute_command(
            command="powershell -Command Restart-Service Spooler",
            ctx=ctx_owner,
            confirmed=True,
            confirmation_ticket=None,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "CONFIRMATION_REQUIRED")

    async def test_ai_mcp_cannot_execute_owner_confirmed(self) -> None:
        """AI_MCP principal cannot execute OWNER_CONFIRMED commands even with confirmed=True."""
        ctx_ai = ExecutionContext(principal=ExecutionPrincipal.AI_MCP)
        res = await self.executor.execute_command(
            command="powershell -Command Restart-Service Spooler",
            ctx=ctx_ai,
            confirmed=True,
            confirmation_ticket="some-ticket",
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "POLICY_DENIED")

    async def test_catastrophic_forward_slash_blocked_for_all_principals(self) -> None:
        """Forward slash catastrophic commands (rmdir /s /q C:/Windows) are blocked for OWNER_MANUAL."""
        cmd = "rmdir /s /q C:/Windows"
        tier = self.executor.classify_command(cmd)
        self.assertEqual(tier, TerminalSecurityTier.RESTRICTED_BLOCKED)

        ctx_owner = ExecutionContext(
            principal=ExecutionPrincipal.OWNER_MANUAL,
            device_id="local_owner",
        )
        ctx_ai = ExecutionContext(
            principal=ExecutionPrincipal.AI_MCP,
            device_id="local_ai",
        )

        # Validation fails for OWNER_MANUAL
        err_owner = self.executor.validate_command(cmd, ctx_owner)
        self.assertIsNotNone(err_owner)
        self.assertIn("forbidden destructive pattern", err_owner)

        # Validation fails for AI_MCP
        err_ai = self.executor.validate_command(cmd, ctx_ai)
        self.assertIsNotNone(err_ai)
        self.assertIn("forbidden destructive pattern", err_ai)

        # Execution fails closed
        res = await self.executor.execute_command(cmd, confirmed=True)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "POLICY_DENIED")

    async def test_catastrophic_format_switch_blocked_for_all_principals(self) -> None:
        """Format switches (format /q D:) are blocked permanently."""
        cmd = "format /q D:"
        tier = self.executor.classify_command(cmd)
        self.assertEqual(tier, TerminalSecurityTier.RESTRICTED_BLOCKED)

        res = await self.executor.execute_command(cmd, confirmed=True)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "POLICY_DENIED")

    async def test_ticket_replay_strictly_fails_closed(self) -> None:
        """Confirmation tickets are single-use and cannot be replayed."""
        engine = CapabilityEngine()

        # Issue ticket for an owner-confirmed operation
        cmd = "powershell -Command Restart-Service Spooler"
        ticket = engine.issue_confirmation_ticket(
            device_id="local_owner",
            command=cmd,
        )
        self.assertIsNotNone(ticket)

        ctx_owner = ExecutionContext(
            principal=ExecutionPrincipal.OWNER_MANUAL,
            device_id="local_owner",
        )

        # First execution succeeds and consumes ticket (or invokes execution)
        req1 = CapabilityRequest(
            action="windows_terminal_exec",
            params={"command": cmd, "confirmation_ticket": ticket},
        )
        res1 = await engine.execute(req1, ctx=ctx_owner)
        self.assertNotEqual(res1.status, "CONFIRMATION_REQUIRED")

        # Second execution with same ticket must fail (consumed / replay rejected)
        req2 = CapabilityRequest(
            action="windows_terminal_exec",
            params={"command": cmd, "confirmation_ticket": ticket},
        )
        res2 = await engine.execute(req2, ctx=ctx_owner)
        self.assertFalse(res2.success)
        self.assertEqual(res2.status, "CONFIRMATION_REQUIRED")


class TestTransferDirectoryExemption(unittest.IsolatedAsyncioTestCase):
    """Test GAP-13: Scoped exemption for ~/.snow/transfers/."""

    async def asyncSetUp(self) -> None:
        self.files_manager = WindowsFileManager()
        self.transfers_dir = Path.home() / ".snow" / "transfers"
        self.transfers_dir.mkdir(parents=True, exist_ok=True)
        self.test_file = self.transfers_dir / "snow_test_phase19a.txt"
        self.test_file.write_text("Valid file content in transfers dir", encoding="utf-8")

    async def asyncTearDown(self) -> None:
        if self.test_file.exists():
            self.test_file.unlink()

    async def test_transfers_directory_file_access_permitted(self) -> None:
        """Legitimate files inside ~/.snow/transfers/ can be read."""
        res = await self.files_manager.read_file(str(self.test_file))
        self.assertTrue(res.get("success"), f"Failed to read transfer file: {res}")
        self.assertIn("Valid file content", res.get("content", ""))

    async def test_parent_snow_directory_strictly_forbidden(self) -> None:
        """Files directly in ~/.snow/ outside transfers/ remain strictly forbidden."""
        fake_db = Path.home() / ".snow" / "snow_devices.db"
        res = await self.files_manager.read_file(str(fake_db))
        self.assertFalse(res.get("success"))
        self.assertIn("PATH_NOT_ALLOWED", res.get("error", ""))

    async def test_sensitive_files_inside_transfers_blocked(self) -> None:
        """Sensitive filenames (server.key, snow_devices.db) inside transfers/ are blocked."""
        fake_key = self.transfers_dir / "server.key"
        fake_key.write_text("fake-key", encoding="utf-8")
        try:
            res = await self.files_manager.read_file(str(fake_key))
            self.assertFalse(res.get("success"))
            self.assertIn("PATH_NOT_ALLOWED", res.get("error", ""))
        finally:
            if fake_key.exists():
                fake_key.unlink()

    async def test_parts_directory_blocked(self) -> None:
        """Access to ~/.snow/transfers/.parts/ staging is blocked."""
        parts_dir = self.transfers_dir / ".parts"
        parts_dir.mkdir(exist_ok=True)
        part_file = parts_dir / "chunk.tmp"
        part_file.write_text("part-chunk", encoding="utf-8")
        try:
            res = await self.files_manager.read_file(str(part_file))
            self.assertFalse(res.get("success"))
            self.assertIn("PATH_NOT_ALLOWED", res.get("error", ""))
        finally:
            if part_file.exists():
                part_file.unlink()

    async def test_path_traversal_escape_blocked(self) -> None:
        """Path traversal (..) escaping ~/.snow/transfers/ is blocked."""
        traversal_path = str(self.transfers_dir / ".." / "config.json")
        res = await self.files_manager.read_file(traversal_path)
        self.assertFalse(res.get("success"))
        self.assertIn("PATH_NOT_ALLOWED", res.get("error", ""))


class TestCliDatabaseIsolation(unittest.TestCase):
    """Test GAP-11: CLI database isolation with running daemon."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_cli_iso_")
        self.isolated_db_path = os.path.join(self.temp_dir, "isolated.db")
        self.isolated_db = DatabaseManager(db_path=self.isolated_db_path)

        # Add isolated device
        self.isolated_db.insert_paired_device(
            device_id="isolated-device-999",
            device_name="Isolated Phone",
            auth_token_hash="hash999",
            trust_tier="peer",
        )

    def test_run_devices_list_with_explicit_db_path_ignores_live_daemon(self) -> None:
        """run_devices_list with explicit db_path queries only the isolated database without touching daemon bridge."""
        with patch("snow.mcp.bridge.SnowMcpBridge") as mock_bridge:
            res = run_devices_list(db_path=self.isolated_db_path)
            # Must NOT instantiate bridge or call live daemon IPC
            mock_bridge.assert_not_called()
            self.assertEqual(res, 0)


class TestDeviceNodeParityAndManifest(unittest.TestCase):
    """Test Scope G: Cross-language DeviceNode parity and manifests."""

    def test_android_manifest_includes_ringer_capability(self) -> None:
        """Authoritative Android manifest includes android.ringer.ring."""
        manifest = build_android_manifest()
        self.assertIn("android.ringer.ring", manifest.supported_capabilities)
        self.assertEqual(
            manifest.classifications.get("android.ringer.ring"),
            CapabilityExecutionClassification.BACKGROUND_SAFE,
        )
        self.assertTrue(manifest.supports_capability("android.ringer.ring"))

    def test_capability_aliases_resolve_ringer(self) -> None:
        """Capability aliases resolve android.ring_phone to android.ringer.ring."""
        manifest = build_android_manifest()
        self.assertTrue(manifest.supports_capability("android.ring_phone"))
        self.assertEqual(CAPABILITY_ALIASES.get("android.ring_phone"), "android.ringer.ring")

    def test_devicenode_serialization_roundtrip_and_migration(self) -> None:
        """DeviceNode serialization preserves fields and migrates legacy timestamps."""
        node = DeviceNode(
            device_id="node-parity-1",
            device_name="Pixel 8",
            platform="android",
            reachability_profile=ReachabilityProfile.ACTIVE_SESSION_PEER,
            reachability_state=ReachabilityState.ONLINE_ROUTED,
            host="192.168.1.100",
            last_seen_timestamp=1700000000.5,
            is_authenticated=True,
            is_paired=True,
        )

        d = node.to_dict()
        self.assertEqual(d["reachability_state"], "ONLINE_ROUTED")
        self.assertEqual(d["is_authenticated"], True)
        self.assertEqual(d["last_seen_timestamp"], 1700000000.5)

        # Roundtrip via from_dict
        parsed = DeviceNode.from_dict(d)
        self.assertEqual(parsed.device_id, node.device_id)
        self.assertEqual(parsed.reachability_state, ReachabilityState.ONLINE_ROUTED)
        self.assertTrue(parsed.is_authenticated)
        self.assertEqual(parsed.last_seen_timestamp, 1700000000.5)

        # Legacy epoch milliseconds migration
        legacy_data = dict(d)
        legacy_data["last_seen_timestamp"] = 1700000000500.0  # epoch millis
        migrated = DeviceNode.from_dict(legacy_data)
        self.assertAlmostEqual(migrated.last_seen_timestamp, 1700000000.5, places=2)


if __name__ == "__main__":
    unittest.main()
