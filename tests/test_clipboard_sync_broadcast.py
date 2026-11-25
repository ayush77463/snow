"""Unit tests for SNOW Phase 19B clipboard sync broadcast and Windows clipboard handling."""

from __future__ import annotations

import asyncio
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.windows.clipboard import WindowsClipboardManager
from snow.core.config import CoreConfig
from snow.network.connection_manager import ConnectionManager
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage
from snow.protocol.validator import validate_raw_message


class MockClient:
    """Mock WebSocket client with connection ID and recording websocket."""

    def __init__(self, connection_id: str) -> None:
        self.connection_id = connection_id
        self.is_active = True
        self.websocket = AsyncMock()
        self.websocket.state = 1
        self.sent_messages: list[str] = []

        async def _mock_send(text: str) -> None:
            self.sent_messages.append(text)

        self.websocket.send = AsyncMock(side_effect=_mock_send)


class TestClipboardSyncBroadcast(unittest.IsolatedAsyncioTestCase):
    """Test suite for server-side clipboard push broadcast logic."""

    async def asyncSetUp(self) -> None:
        self.config = CoreConfig(bind_host="127.0.0.1", port=8765, tls_enabled=False)
        self.conn_mgr = ConnectionManager()
        self.server = SnowWebSocketServer(config=self.config, connection_manager=self.conn_mgr)

    async def test_server_init_last_local_write_seq(self) -> None:
        """Verify _last_local_write_seq is properly initialized."""
        self.assertEqual(self.server._last_local_write_seq, 0)

    async def test_broadcast_clipboard_uses_connection_manager(self) -> None:
        """Verify broadcast resolves client via connection_manager and transmits clipboard_push."""
        client_mock = MockClient("conn-test-1")
        self.conn_mgr._connections["conn-test-1"] = client_mock
        self.server._active_sync_connections.add("conn-test-1")

        # Mock capability_engine.clipboard.get_content_sync
        self.server.capability_engine.clipboard.get_content_sync = MagicMock(
            return_value={
                "success": True,
                "type": "text",
                "text": "Hello Snow Instant Sync",
                "sha256": "abc123hash",
            }
        )

        # Mock session
        session_mock = MagicMock()
        session_mock.is_authenticated = True
        self.server.session_manager.get_session_by_connection = MagicMock(return_value=session_mock)

        # Perform broadcast
        await self.server._broadcast_clipboard_update()

        # Verify client received clipboard_buffer_updated and clipboard_push via ConnectionManager
        parsed_msgs = [validate_raw_message(raw) for raw in client_mock.sent_messages]
        actions = [m.payload.get("action") for m in parsed_msgs]
        self.assertIn("clipboard_buffer_updated", actions)
        push_msgs = [m for m in parsed_msgs if m.payload.get("action") == "clipboard_push"]
        self.assertEqual(len(push_msgs), 1)
        data = push_msgs[0].payload.get("data", {})
        self.assertEqual(data.get("type"), "text")
        self.assertEqual(data.get("text"), "Hello Snow Instant Sync")
        self.assertEqual(data.get("sha256"), "abc123hash")

    async def test_broadcast_clipboard_suppresses_local_write_echo(self) -> None:
        """Verify broadcast skips push when sequence matches _last_local_write_seq on Win32."""
        if sys.platform != "win32":
            self.skipTest("Win32 sequence number test")

        import ctypes
        curr_seq = ctypes.windll.user32.GetClipboardSequenceNumber()
        self.server._last_local_write_seq = curr_seq

        client_mock = MockClient("conn-test-echo")
        self.conn_mgr._connections["conn-test-echo"] = client_mock
        self.server._active_sync_connections.add("conn-test-echo")

        self.server.capability_engine.clipboard.get_content_sync = MagicMock(
            return_value={
                "success": True,
                "type": "text",
                "text": "Locally Written Echo",
                "sha256": "echo_hash",
            }
        )

        await self.server._broadcast_clipboard_update()

        # Should be suppressed (0 sent messages)
        self.assertEqual(len(client_mock.sent_messages), 0)

    async def test_broadcast_prunes_inactive_clients(self) -> None:
        """Verify inactive or missing clients are pruned from active sync set."""
        self.server._active_sync_connections.add("conn-dead")
        self.server.capability_engine.clipboard.get_content_sync = MagicMock(
            return_value={"success": True, "type": "text", "text": "test", "sha256": "123"}
        )

        await self.server._broadcast_clipboard_update()

        self.assertNotIn("conn-dead", self.server._active_sync_connections)


class TestWindowsClipboardManager(unittest.TestCase):
    """Test suite for WindowsClipboardManager Win32 DIB and text functions."""

    def setUp(self) -> None:
        if sys.platform != "win32":
            self.skipTest("WindowsClipboardManager requires Windows")
        self.clipboard = WindowsClipboardManager()
        if not self.clipboard._is_windows or not self.clipboard._user32 or not self.clipboard._open_clipboard_with_retry():
            self.skipTest("Interactive desktop window station clipboard unavailable in current session")
        self.clipboard._user32.CloseClipboard()

    def test_text_roundtrip(self) -> None:
        """Test reading and writing text to Windows clipboard."""
        test_text = "SNOW V3 Phase 19B Test"
        set_res = self.clipboard.set_clipboard_sync(test_text)
        self.assertTrue(set_res.get("success"), f"Set failed: {set_res}")

        get_res = self.clipboard.get_clipboard_sync()
        self.assertTrue(get_res.get("success"), f"Get failed: {get_res}")
        self.assertEqual(get_res.get("text"), test_text)

    def test_image_roundtrip_with_sample(self) -> None:
        """Test setting an image on clipboard and reading it back via CF_DIB."""
        sample_path = Path("snow.png")
        if not sample_path.exists():
            sample_path = Path("test_sample.png")
        if not sample_path.exists():
            self.skipTest("No test image available")

        set_img = self.clipboard.set_image_sync(sample_path)
        self.assertTrue(set_img.get("success"), f"Set image failed: {set_img}")
        self.assertTrue(self.clipboard.has_image_sync())

        with tempfile.TemporaryDirectory() as tmp_dir:
            get_img = self.clipboard.get_image_sync(Path(tmp_dir))
            self.assertTrue(get_img.get("success"), f"Get image failed: {get_img}")
            self.assertEqual(get_img.get("type"), "image")
            self.assertTrue(Path(get_img["file_path"]).exists())
