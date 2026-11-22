"""Regression test suite for SNOW V4.1 Phase 1, Gate 1B, Batch 4 - Track 3.

Verifies:
- Accurate extraction of active connected device count from real IPC get_device_status payload.
- Filtering of paired-only devices (is_connected=False).
- Graceful fallbacks for missing/unusable devices list (active_sessions_count / connected_count).
- Graceful handling of malformed payloads and core IPC unavailability.
- Proper tooltip formatting based on extracted counts.
"""

from __future__ import annotations

import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.tray.app import SnowTrayApp


class TestTrayConnectedCountRegression(unittest.TestCase):
    """Test realistic IPC get_device_status response parsing and fallback behaviors."""

    def test_realistic_ipc_payload_two_connected_one_offline(self) -> None:
        """Verify 2 connected out of 3 paired devices from real IPC payload format."""
        payload = {
            "core_running": True,
            "app_name": "SNOW",
            "version": "4.1.0",
            "ws_port": 8765,
            "transfer_port": 8766,
            "ipc_port": 8767,
            "active_connections_count": 2,
            "paired_devices_count": 3,
            "active_sessions_count": 2,
            "devices": [
                {
                    "device_id": "phone-1",
                    "device_name": "Pixel 7 Pro",
                    "is_connected": True,
                    "is_paired": True,
                    "last_seen": 1700000000.0,
                },
                {
                    "device_id": "phone-2",
                    "device_name": "Galaxy S23",
                    "is_connected": False,
                    "is_paired": True,
                    "last_seen": 1699990000.0,
                },
                {
                    "device_id": "tablet-1",
                    "device_name": "Pixel Tablet",
                    "is_connected": True,
                    "is_paired": True,
                    "last_seen": 1700000100.0,
                },
            ],
        }
        count = SnowTrayApp.extract_connected_count(payload)
        self.assertEqual(count, 2)

    def test_empty_device_list(self) -> None:
        """Verify empty device list results in 0 connected devices."""
        payload = {
            "core_running": True,
            "devices": [],
            "active_sessions_count": 0,
        }
        self.assertEqual(SnowTrayApp.extract_connected_count(payload), 0)

    def test_missing_device_list_with_active_sessions_fallback(self) -> None:
        """Verify fallback to active_sessions_count when devices list is absent."""
        payload = {
            "core_running": True,
            "active_sessions_count": 3,
            "active_connections_count": 3,
        }
        self.assertEqual(SnowTrayApp.extract_connected_count(payload), 3)

    def test_fallback_to_connected_count_compatibility(self) -> None:
        """Verify fallback to legacy connected_count if present."""
        payload = {
            "core_running": True,
            "connected_count": 4,
        }
        self.assertEqual(SnowTrayApp.extract_connected_count(payload), 4)

    def test_malformed_payload(self) -> None:
        """Verify malformed payloads return 0 without raising exceptions."""
        self.assertEqual(SnowTrayApp.extract_connected_count(None), 0)
        self.assertEqual(SnowTrayApp.extract_connected_count("not a dict"), 0)
        self.assertEqual(SnowTrayApp.extract_connected_count({"devices": "not a list"}), 0)
        self.assertEqual(SnowTrayApp.extract_connected_count({"devices": [{"no_is_connected": True}]}), 0)

    def test_tray_refresh_status_with_ipc_bridge(self) -> None:
        """Verify full tray refresh_status integration with realistic IPC payload."""
        tray = SnowTrayApp(headless=True, auto_start_core=False)
        tray._device_count = 3

        realistic_ipc_resp = {
            "success": True,
            "data": {
                "core_running": True,
                "active_sessions_count": 2,
                "devices": [
                    {"device_id": "dev-1", "is_connected": True},
                    {"device_id": "dev-2", "is_connected": False},
                    {"device_id": "dev-3", "is_connected": True},
                ],
            },
        }

        tray.bridge.call = AsyncMock(return_value=realistic_ipc_resp)

        with patch.object(tray.daemon_manager, "get_tracked_pid", return_value=12345), \
             patch.object(tray.daemon_manager, "is_process_snow_core", return_value=True), \
             patch("snow.security.db.DatabaseManager.list_paired_devices", return_value=[MagicMock(), MagicMock(), MagicMock()]):
            status = tray.refresh_status()
            self.assertEqual(status["connected_count"], 2)
            self.assertEqual(status["device_count"], 3)
            tooltip = tray.compute_tooltip()
            self.assertIn("3 paired", tooltip)
            self.assertIn("2 connected", tooltip)

    def test_tray_core_ipc_unavailable(self) -> None:
        """Verify graceful fallback when Core IPC is unavailable."""
        tray = SnowTrayApp(headless=True, auto_start_core=False)
        tray._device_count = 1
        tray.bridge.call = AsyncMock(side_effect=OSError("IPC socket closed"))

        with patch.object(tray.daemon_manager, "get_tracked_pid", return_value=None), \
             patch("socket.create_connection", side_effect=OSError("Connection refused")):
            status = tray.refresh_status()
            self.assertFalse(status["core_online"])
            self.assertEqual(status["connected_count"], 0)
            tooltip = tray.compute_tooltip()
            self.assertIn("Stopped", tooltip)
            self.assertNotIn("connected", tooltip)


if __name__ == "__main__":
    unittest.main()
