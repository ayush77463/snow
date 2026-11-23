"""Unit tests for Stage 4A Track B: Desktop Pause, Resume, and complete Power-Off lifecycle."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
import uuid

from snow.core.config import CoreConfig
from snow.core.ipc import IPC_PROTOCOL_VERSION, SnowIpcServer
from snow.core.server import SnowCoreServer
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity


class TestPauseResumePowerOffLifecycle(unittest.IsolatedAsyncioTestCase):
    """Verify owner-gated IPC operations, pause state transitions, and coordinated shutdown."""

    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.secret = "test-ipc-secret-key-32bytes-long"
        secret_file = Path(self.tmp_dir.name) / "ipc.secret"
        secret_file.write_text(self.secret, encoding="utf-8")
        self.config = CoreConfig(
            port=58900,
            ipc_port=58901,
            transfer_port=58902,
            ipc_secret_path=str(secret_file),
            log_level="DEBUG",
        )
        self.identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Desktop Core",
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self.db_path = Path(self.tmp_dir.name) / "test_core.db"
        self.db_mgr = DatabaseManager(self.db_path)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def _generate_owner_token(self) -> str:
        return hmac.new(
            self.secret.encode("utf-8"), b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256
        ).hexdigest()

    async def test_ipc_system_pause_requires_owner_manual(self) -> None:
        """system_pause is rejected if caller does not possess OWNER_MANUAL credentials."""
        mock_core = MagicMock()
        mock_core.pause_system = AsyncMock(return_value={"success": True, "status": "PAUSED"})

        server = SnowIpcServer(core_server=mock_core, config=self.config)
        server._secret = self.secret

        # 1. Non-owner call (valid auth_token but missing owner_token) -> must fail
        req_non_owner = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": "req-1",
            "op": "system_pause",
            "auth_token": self.secret,
            "payload": {},
        }
        resp, _ = await server._dispatch_request(req_non_owner, is_connection_authenticated=False)
        self.assertFalse(resp["success"])
        self.assertEqual(resp["status"], "UNAUTHORIZED")
        self.assertIn("OWNER_MANUAL required", resp["error"])
        mock_core.pause_system.assert_not_called()

        # 2. Owner call with valid owner_token -> must succeed
        req_owner = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": "req-2",
            "op": "system_pause",
            "auth_token": self.secret,
            "payload": {"owner_token": self._generate_owner_token(), "reason": "Testing pause"},
        }
        resp_owner, _ = await server._dispatch_request(req_owner, is_connection_authenticated=False)
        self.assertTrue(resp_owner["success"])
        self.assertEqual(resp_owner["status"], "PAUSED")
        mock_core.pause_system.assert_called_once()

    async def test_ipc_system_resume_requires_owner_manual(self) -> None:
        """system_resume is rejected for non-owner and succeeds for owner."""
        mock_core = MagicMock()
        mock_core.resume_system = AsyncMock(return_value={"success": True, "status": "RESUMED"})

        server = SnowIpcServer(core_server=mock_core, config=self.config)
        server._secret = self.secret

        # Non-owner fails
        req_bad = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": "req-bad",
            "op": "system_resume",
            "auth_token": self.secret,
            "payload": {},
        }
        resp_bad, _ = await server._dispatch_request(req_bad, is_connection_authenticated=False)
        self.assertFalse(resp_bad["success"])
        self.assertEqual(resp_bad["status"], "UNAUTHORIZED")

        # Owner succeeds
        req_good = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": "req-good",
            "op": "system_resume",
            "auth_token": self.secret,
            "payload": {"owner_token": self._generate_owner_token()},
        }
        resp_good, _ = await server._dispatch_request(req_good, is_connection_authenticated=False)
        self.assertTrue(resp_good["success"])
        self.assertEqual(resp_good["status"], "RESUMED")
        mock_core.resume_system.assert_called_once()

    async def test_ipc_system_shutdown_triggers_coordinated_shutdown(self) -> None:
        """system_shutdown requires owner authority and invokes core shutdown request."""
        mock_core = MagicMock()
        mock_core.request_shutdown = MagicMock()

        server = SnowIpcServer(core_server=mock_core, config=self.config)
        server._secret = self.secret

        req_shutdown = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": "req-shut",
            "op": "system_shutdown",
            "auth_token": self.secret,
            "payload": {"owner_token": self._generate_owner_token(), "reason": "Power-off test"},
        }
        resp, _ = await server._dispatch_request(req_shutdown, is_connection_authenticated=False)
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "SHUTTING_DOWN")
        # Ensure request_shutdown was invoked or scheduled
        await asyncio.sleep(0.05)
        mock_core.request_shutdown.assert_called()

    async def test_core_server_pause_and_resume_idempotency(self) -> None:
        """CoreServer pause_system and resume_system transition states idempotently and restore services."""
        core = SnowCoreServer(config=self.config, device_identity=self.identity, db_manager=self.db_mgr)

        # Mock USB watcher and clipboard
        core.usb_watcher = MagicMock()
        mock_cb = MagicMock()
        mock_cb.sync_enabled = True
        core.capability_engine.clipboard = mock_cb

        # Initial state: not paused
        self.assertFalse(core.is_paused)

        # 1. Pause system
        res_pause = await core.pause_system(reason="Maintenance")
        self.assertTrue(res_pause["success"])
        self.assertEqual(res_pause["status"], "PAUSED")
        self.assertTrue(core.is_paused)
        core.usb_watcher.pause.assert_called_once()
        mock_cb.set_sync_enabled.assert_called_with(False)

        # 2. Idempotent pause
        res_pause_dup = await core.pause_system()
        self.assertTrue(res_pause_dup["success"])
        self.assertEqual(res_pause_dup["status"], "ALREADY_PAUSED")

        # 3. Resume system
        res_resume = await core.resume_system()
        self.assertTrue(res_resume["success"])
        self.assertEqual(res_resume["status"], "RESUMED")
        self.assertFalse(core.is_paused)
        core.usb_watcher.resume.assert_called_once()
        mock_cb.set_sync_enabled.assert_called_with(True)

        # 4. Idempotent resume
        res_resume_dup = await core.resume_system()
        self.assertTrue(res_resume_dup["success"])
        self.assertEqual(res_resume_dup["status"], "ALREADY_ACTIVE")

    async def test_ipc_get_device_status_returns_is_paused(self) -> None:
        """get_device_status IPC op exposes real Core is_paused boolean."""
        mock_core = MagicMock()
        mock_core.is_paused = True
        mock_core._paused_state = {"paused_at": 123456789.0, "reason": "Owner requested"}
        mock_core.device_identity.device_id = "mock-dev-id"
        mock_core.device_identity.device_name = "Mock PC"

        server = SnowIpcServer(core_server=mock_core, config=self.config)
        server._secret = self.secret

        req = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": "req-stat",
            "op": "get_device_status",
            "auth_token": self.secret,
            "payload": {},
        }
        resp, _ = await server._dispatch_request(req, is_connection_authenticated=False)
        self.assertTrue(resp["success"])
        self.assertTrue(resp["data"]["is_paused"])
        self.assertEqual(resp["data"]["paused_state"]["reason"], "Owner requested")


if __name__ == "__main__":
    unittest.main()
