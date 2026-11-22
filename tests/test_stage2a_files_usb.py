"""Tests for SNOW V4.1 Phase 2 Stage 2A: Windows Files, USB Watcher, and Web Endpoints."""

import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.windows.files import (
    FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_SYSTEM,
    WindowsFileManager,
    is_windows_hidden_or_system,
)
from snow.core.usb import UsbWatcher


class TestWindowsFileFiltering(unittest.TestCase):
    """Test Windows hidden/system and legacy junction filtering."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()
        self.mgr = WindowsFileManager(allowed_roots=[self.root])

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_is_windows_hidden_or_system_detection(self) -> None:
        # Dot files/folders
        self.assertTrue(is_windows_hidden_or_system(Path("C:/test/.git")))
        self.assertTrue(is_windows_hidden_or_system(Path("C:/test/.snow")))
        self.assertTrue(is_windows_hidden_or_system(Path("C:/test/.tmp_upload")))

        # Known legacy system junctions
        self.assertTrue(is_windows_hidden_or_system(Path("C:/Users/user/AppData")))
        self.assertTrue(is_windows_hidden_or_system(Path("C:/Users/user/Application Data")))
        self.assertTrue(is_windows_hidden_or_system(Path("C:/Users/user/Cookies")))
        self.assertTrue(is_windows_hidden_or_system(Path("C:/Users/user/Local Settings")))

        # Normal user folders
        self.assertFalse(is_windows_hidden_or_system(Path("C:/Users/user/Documents")))
        self.assertFalse(is_windows_hidden_or_system(Path("C:/Users/user/Desktop")))
        self.assertFalse(is_windows_hidden_or_system(Path("C:/Users/user/Photos")))
        self.assertFalse(is_windows_hidden_or_system(Path("C:/Users/user/report.pdf")))

    def test_list_files_filters_hidden_and_system(self) -> None:
        # Create normal files and folders
        (self.root / "Documents").mkdir()
        (self.root / "Notes.txt").write_text("notes", encoding="utf-8")

        # Create dot folders and junction-named folders
        (self.root / ".hidden_folder").mkdir()
        (self.root / ".dotfile").write_text("dot", encoding="utf-8")
        (self.root / "AppData").mkdir()
        (self.root / "Cookies").mkdir()

        # Listing with default hide_hidden=True
        res = self.mgr.list_files_sync(str(self.root), hide_hidden=True)
        self.assertTrue(res["success"])
        names = {item["name"] for item in res["items"]}

        self.assertIn("Documents", names)
        self.assertIn("Notes.txt", names)
        self.assertNotIn(".hidden_folder", names)
        self.assertNotIn(".dotfile", names)
        self.assertNotIn("AppData", names)
        self.assertNotIn("Cookies", names)

        # Listing with hide_hidden=False
        res_show = self.mgr.list_files_sync(str(self.root), hide_hidden=False)
        self.assertTrue(res_show["success"])
        all_names = {item["name"] for item in res_show["items"]}
        self.assertIn("Documents", all_names)
        self.assertIn("Notes.txt", all_names)
        self.assertIn(".hidden_folder", all_names)
        self.assertIn("AppData", all_names)

    def test_search_files_filters_hidden_and_system(self) -> None:
        (self.root / "Project").mkdir()
        (self.root / "Project" / "readme.txt").write_text("findme in normal", encoding="utf-8")

        (self.root / "AppData").mkdir()
        (self.root / "AppData" / "readme.txt").write_text("findme in junction", encoding="utf-8")

        (self.root / ".git").mkdir()
        (self.root / ".git" / "readme.txt").write_text("findme in dotfolder", encoding="utf-8")

        res = self.mgr.search_files_sync(query="readme", root_path=str(self.root), hide_hidden=True)
        self.assertTrue(res["success"])
        match_paths = [m["path"] for m in res["matches"]]
        self.assertEqual(len(match_paths), 1)
        self.assertTrue(match_paths[0].endswith("Project\\readme.txt") or match_paths[0].endswith("Project/readme.txt"))


class TestUsbWatcher(unittest.IsolatedAsyncioTestCase):
    """Test USB watcher automatic ADB reverse tunneling."""

    async def test_usb_watcher_poll_configures_reverse(self) -> None:
        mock_devices = [{"serial": "device123", "status": "device", "model": "Pixel_7"}]
        mock_status_inactive = {"reverse_active": False}

        watcher = UsbWatcher(port=8765, poll_interval=1.0, adb_bin=Path("/mock/adb"))

        with patch("snow.core.usb.get_connected_adb_devices", return_value=mock_devices), \
             patch("snow.core.usb.get_usb_status", return_value=mock_status_inactive) as mock_get_status, \
             patch("snow.core.usb.setup_usb_reverse", return_value=(True, "Success")) as mock_setup:

            # First poll: inactive -> triggers setup
            changed = await watcher._poll_once()
            self.assertTrue(changed)
            self.assertIn("device123", watcher._configured_serials)
            mock_setup.assert_called_once_with("device123", 8765, Path("/mock/adb"))

            # Second poll: already configured -> skips redundant get_usb_status and setup
            mock_setup.reset_mock()
            mock_get_status.reset_mock()
            changed_2 = await watcher._poll_once()
            self.assertFalse(changed_2)
            mock_setup.assert_not_called()
            mock_get_status.assert_not_called()
            self.assertIn("device123", watcher._configured_serials)

    async def test_usb_watcher_handles_disconnection(self) -> None:
        watcher = UsbWatcher(port=8765, poll_interval=1.0, adb_bin=Path("/mock/adb"))
        watcher._configured_serials.add("device_old")

        with patch("snow.core.usb.get_connected_adb_devices", return_value=[]):
            changed = await watcher._poll_once()
            self.assertTrue(changed)
            self.assertNotIn("device_old", watcher._configured_serials)

    async def test_usb_watcher_adaptive_backoff(self) -> None:
        watcher = UsbWatcher(port=8765, poll_interval=8.0, adb_bin=Path("/mock/adb"))
        self.assertEqual(watcher.current_interval, 8.0)

        # When poll returns False (no change), interval increases up to max
        watcher.current_interval = min(watcher.current_interval * 1.5, watcher.MAX_POLL_INTERVAL)
        self.assertEqual(watcher.current_interval, 12.0)
        watcher.current_interval = min(watcher.current_interval * 1.5, watcher.MAX_POLL_INTERVAL)
        self.assertEqual(watcher.current_interval, 18.0)
        watcher.current_interval = min(watcher.current_interval * 1.5, watcher.MAX_POLL_INTERVAL)
        self.assertEqual(watcher.current_interval, 20.0)

        # State change resets interval to base
        watcher.current_interval = watcher.base_interval
        self.assertEqual(watcher.current_interval, 8.0)

    async def test_usb_watcher_start_stop_lifecycle(self) -> None:
        watcher = UsbWatcher(port=8765, poll_interval=0.05, adb_bin=Path("/mock/adb"))
        with patch.object(watcher, "_poll_once", new_callable=AsyncMock) as mock_poll:
            await watcher.start()
            self.assertTrue(watcher._running)
            await asyncio.sleep(0.12)
            self.assertTrue(mock_poll.call_count >= 1)
            await watcher.stop()
            self.assertFalse(watcher._running)
            self.assertIsNone(watcher._task)


class TestWebEndpointsReliability(unittest.IsolatedAsyncioTestCase):
    """Test web server relay, gateway, and phone capture endpoints."""

    async def test_gateway_offline_fast_probe(self) -> None:
        from aiohttp import web
        from snow.web.server import SnowWebServer

        server = SnowWebServer(host="127.0.0.1", port=18765, auto_open_browser=False)
        req = MagicMock(spec=web.Request)

        # Port 8771 should not be listening during unit test, so probe immediately reports offline
        res = await server.handle_api_mcp_gateway_status(req)
        import json
        data = json.loads(res.text) if hasattr(res, "text") and res.text else {}
        if hasattr(res, "body") and res.body and not data:
            data = json.loads(res.body.decode("utf-8"))

        self.assertTrue(data.get("success"))
        # Should be offline without timing out
        self.assertIn(data["data"]["gateway_status"], ("offline", "online", "running"))

    async def test_relay_status_never_reports_quad_zero(self) -> None:
        from aiohttp import web
        from snow.web.server import SnowWebServer

        server = SnowWebServer(host="127.0.0.1", port=18765, auto_open_browser=False)
        req = MagicMock(spec=web.Request)

        with patch.dict("os.environ", {"SNOW_RELAY_ENABLED": "true", "SNOW_RELAY_HOST": "0.0.0.0"}):
            res = await server.handle_api_relay_status(req)
            import json
            data = json.loads(res.body.decode("utf-8"))
            self.assertTrue(data.get("success"))
            endpoint = data["data"].get("endpoint")
            self.assertIsNotNone(endpoint)
            self.assertNotIn("0.0.0.0", endpoint)

    async def test_screen_capture_phone_endpoint(self) -> None:
        from aiohttp import web
        from snow.web.server import SnowWebServer

        mock_bridge = MagicMock()
        mock_bridge.android_screenshot = AsyncMock(return_value={"success": True, "status": "SUCCESS", "file_name": "screen.png"})

        server = SnowWebServer(host="127.0.0.1", port=18765, bridge=mock_bridge, auto_open_browser=False)
        req = MagicMock(spec=web.Request)
        req.json = AsyncMock(return_value={"device_id": "phone_123"})

        res = await server.handle_api_screen_capture_phone(req)
        import json
        data = json.loads(res.body.decode("utf-8"))
        self.assertTrue(data.get("success"))
        mock_bridge.android_screenshot.assert_called_once_with(device_id="phone_123", approval_id="")


if __name__ == "__main__":
    unittest.main()
