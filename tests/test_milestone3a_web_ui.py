"""Milestone 3A Unit 3.2: Windows Web UI structure, API parity, and layout tests."""

from __future__ import annotations

import json
import re
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from aiohttp.test_utils import AioHTTPTestCase

from snow.web.server import SnowWebServer


STATIC_DIR = Path(__file__).resolve().parents[1] / "src" / "snow" / "web" / "static"


class TestMilestone3AWebUiStructure(unittest.TestCase):
    """Verify Unit 3.2 HTML/CSS/JS requirements statically and deterministically."""

    def setUp(self) -> None:
        self.html = (STATIC_DIR / "index.html").read_text(encoding="utf-8")
        self.css = (STATIC_DIR / "app.css").read_text(encoding="utf-8")
        self.js = (STATIC_DIR / "app.js").read_text(encoding="utf-8")

    def test_01_sidebar_navigation_order_exact(self) -> None:
        nav_block = re.search(r'<nav class="nav-menu"[\s\S]*?</nav>', self.html)
        self.assertIsNotNone(nav_block)
        tabs = re.findall(r'data-tab="([^"]+)"', nav_block.group(0))
        labels = re.findall(r'<span class="nav-label">([^<]+)</span>', nav_block.group(0))
        self.assertEqual(tabs, ["overview", "clipboard", "files", "devices", "settings"])
        self.assertEqual(
            [lbl.replace("&amp;", "&") for lbl in labels],
            ["Home", "Clipboard", "Files & Apps", "Devices", "AI & Settings"],
        )

    def test_02_devices_layout_and_remote_access_relocated(self) -> None:
        devices_sec = re.search(
            r'<section id="section-devices"[\s\S]*?</section>',
            self.html,
        )
        self.assertIsNotNone(devices_sec)
        devices_html = devices_sec.group(0)

        # Remote Access and Cross-Network Federation must NOT appear in Devices view
        self.assertNotIn('id="chk-relay-tunnel-toggle"', devices_html)
        self.assertNotIn('id="relay-tunnel-badge"', devices_html)
        self.assertNotIn('id="cross-network-federation-card"', self.html)

        # Connect & Pair lives alongside device list & network summary
        connect_pos = devices_html.find('id="pair-pane-qr"')
        dev_list_pos = devices_html.find('id="devices-list-container"')
        net_info_pos = devices_html.find('id="devices-network-info-card"')
        self.assertGreater(dev_list_pos, 0)
        self.assertGreater(net_info_pos, dev_list_pos)
        self.assertGreater(connect_pos, net_info_pos)
        self.assertIn('id="pairing-step1-container"', devices_html)
        self.assertIn('id="pairing-step2-container"', devices_html)
        self.assertNotIn('id="paste-qr-json-accordion"', devices_html)
        self.assertNotIn('id="connect-advanced-accordion"', self.html)
        self.assertNotIn("Fingerprint:", devices_html)

        # Remote Access lives in AI & Settings without "Handled automatically"
        settings_sec = re.search(r'<section id="section-settings"[\s\S]*?</section>', self.html)
        self.assertIsNotNone(settings_sec)
        settings_html = settings_sec.group(0)
        self.assertIn('id="remote-access-settings-card"', settings_html)
        self.assertIn('id="chk-relay-tunnel-toggle"', settings_html)
        self.assertNotIn("Handled automatically", settings_html)

    def test_03_qr_placeholders_themed_and_modal_button_consistent(self) -> None:
        for box_id in ("pairing-qr-box", "modal-qr-container", "apk-qr-box", "mcp-qr-svg-container"):
            m = re.search(rf'<div id="{box_id}"([^>]*)>', self.html)
            self.assertIsNotNone(m, f"Missing {box_id}")
            attrs = m.group(1)
            self.assertIn("qr-surface", attrs)
            self.assertNotIn("#FFF", attrs.upper())

        self.assertIn("Generate 6-Digit PIN", self.html)
        self.assertNotIn("Generate Pairing QR &amp; PIN", self.html)
        self.assertNotIn(">Generate PIN<", self.html)
        for btn_id in (
            "btn-usb-unlock-permissions",
            "btn-pairing-refresh-qr",
            "btn-pairing-cancel-pin",
            "btn-modal-generate-pin",
        ):
            m = re.search(rf'id="{btn_id}"[^>]*class="([^"]+)"', self.html)
            self.assertIsNotNone(m)
            self.assertIn("btn-radius-md", m.group(1))
        self.assertIn("--snow-radius-md", self.css)
        self.assertIn(".qr-surface.qr-active", self.css)

    def test_04_files_apps_8fr_4fr_and_no_unwanted_1400px_flatten(self) -> None:
        files_css = re.search(r"\.files-v5-layout\s*\{[^}]+\}", self.css)
        self.assertIsNotNone(files_css)
        self.assertIn("8fr", files_css.group(0))
        self.assertIn("4fr", files_css.group(0))
        media_1400 = re.search(r"@media\s*\(max-width:\s*1400px\)\s*\{[\s\S]*?\n\}", self.css)
        self.assertIsNotNone(media_1400)
        self.assertNotIn(".files-v5-layout", media_1400.group(0))

    def test_05_clipboard_15_limit_and_multiformat_support(self) -> None:
        self.assertIn("/api/clipboard/buffer?limit=15", self.js)
        for fmt in ("text", "image", "file", "file_bundle"):
            self.assertIn(f'"{fmt}"', self.js)
        self.assertIn("clipboard-manifest-list", self.js)
        self.assertIn("withButtonLoading", self.js)

    def test_06_ai_settings_render_hub_default_and_no_hardcoded_id(self) -> None:
        self.assertNotIn("SNW-NET-XXXXXXXX", self.html)
        self.assertNotIn("SNW-NET-XXXXXXXX", self.js)
        self.assertNotIn("btn-setup-cursor", self.html)
        remote_card = re.search(r'<div id="remote-ai-link-card"[\s\S]*?<div class="ai-settings-layout">', self.html)
        self.assertIsNotNone(remote_card)
        card_html = remote_card.group(0)
        self.assertIn('id="chk-mcp-tunnel-toggle"', card_html)
        self.assertIn('id="btn-mcp-copy-url"', card_html)
        self.assertIn('id="btn-mcp-tunnel-show-qr"', card_html)
        self.assertNotIn('id="btn-mcp-tunnel-start"', card_html)
        self.assertNotIn('id="btn-mcp-tunnel-stop"', card_html)
        # Permanent URL override accordion & diagnostics live inside collapsed details.advanced-accordion
        self.assertNotIn('id="mcp-permanent-accordion"', card_html)
        adv_card = re.search(
            r'<div id="advanced-diagnostics-card"[\s\S]*?<div class="flex flex-col gap-4 approvals-activity-card">',
            self.html,
        )
        self.assertIsNotNone(adv_card)
        adv_html = adv_card.group(0)
        self.assertIn('<details class="advanced-accordion">', adv_html)
        self.assertNotIn('class="advanced-accordion" open', adv_html)
        self.assertIn('id="mcp-permanent-accordion"', adv_html)
        self.assertIn('id="oauth-authorized-clients-card"', self.html)
        # Redundant setting-default-hub-url and diagnostic copy duplicate removed
        self.assertNotIn('id="setting-default-hub-url"', self.html)
        self.assertNotIn('id="diag-hub-permanent-mcp"', self.html)
        self.assertNotIn('id="btn-copy-diag-ai-url"', self.html)


class TestMilestone3AWebServerRenderAndClipboardEndpoints(AioHTTPTestCase):
    """Verify server endpoints for Render Hub default and 15-item multi-format clipboard."""

    async def get_application(self):
        import os
        import shutil
        import tempfile

        self._tmp_data = Path(tempfile.mkdtemp(prefix="snow_m3a_web_"))
        self._prev_data_dir = os.environ.get("SNOW_DATA_DIR")
        os.environ["SNOW_DATA_DIR"] = str(self._tmp_data)
        self.addCleanup(shutil.rmtree, self._tmp_data, True)
        self.addCleanup(
            lambda: os.environ.__setitem__("SNOW_DATA_DIR", self._prev_data_dir)
            if self._prev_data_dir is not None
            else os.environ.pop("SNOW_DATA_DIR", None)
        )

        self.bridge = MagicMock()
        self.bridge.capability_engine = MagicMock(db_manager=None)
        self.bridge.daemon_manager = MagicMock()
        self.bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)
        self.bridge.call = AsyncMock(return_value={"success": True, "data": {"items": [], "count": 0}})
        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.bridge,
            auto_open_browser=False,
        )
        return self.web_server._build_app()

    async def _auth(self) -> str:
        resp = await self.client.post("/api/auth/session", json={"token": self.web_server.bootstrap_token})
        data = await resp.json()
        self.assertTrue(data["success"])
        return data["csrf_token"]

    async def test_mcp_tunnel_status_exposes_dynamic_render_route_and_stop_clears_active(self) -> None:
        csrf = await self._auth()
        r_status = await self.client.get("/api/mcp/tunnel/status")
        self.assertEqual(r_status.status, 200)
        j_status = await r_status.json()
        self.assertFalse(j_status["active"])
        self.assertRegex(j_status["configured_render_url"], r"^https://.+/u/SNW-[A-Z0-9]{4}-[A-Z0-9]{4}/mcp$")

        r_start = await self.client.post(
            "/api/mcp/tunnel/start",
            json={"provider": "custom", "custom_url": "https://hub.example.test"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(r_start.status, 200)
        r_active = await self.client.get("/api/mcp/tunnel/status")
        j_active = await r_active.json()
        self.assertTrue(j_active["active"])
        self.assertEqual(j_active["mcp_endpoint"], "https://hub.example.test/mcp")

        r_stop = await self.client.post("/api/mcp/tunnel/stop", json={}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_stop.status, 200)
        r_after = await self.client.get("/api/mcp/tunnel/status")
        j_after = await r_after.json()
        self.assertFalse(j_after["active"])
        self.assertIsNone(j_after["mcp_endpoint"])

    async def test_clipboard_buffer_limit_15_passed_to_core(self) -> None:
        await self._auth()
        resp = await self.client.get("/api/clipboard/buffer?limit=15")
        self.assertEqual(resp.status, 200)
        self.bridge.call.assert_called_with("clipboard_buffer_list", {"limit": 15})


if __name__ == "__main__":
    unittest.main()
