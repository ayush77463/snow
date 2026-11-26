"""Web UI structure and theme parity tests for Stage 2C Material 3 architecture.

Verifies:
- 5-view navigation in index.html (Home, Devices, Files & Apps, Clipboard, AI & Settings).
- Exact theme choices (System, Light Mode, Dark Mode) with no fancy/legacy labels.
- Desktop hero card with wallpaper preview, Lock PC, and Send Files buttons.
- Command palette (Ctrl+K) overlay and Topbar Approvals Bell.
- Collapsed Advanced & Diagnostics accordion hiding raw ports and debug info.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest


class TestWebUiStage2C(unittest.TestCase):
    """Structural assertions on Web UI assets."""

    def setUp(self):
        self.html_path = Path("src/snow/web/static/index.html")
        self.css_path = Path("src/snow/web/static/app.css")
        self.js_path = Path("src/snow/web/static/app.js")

        self.assertTrue(self.html_path.exists())
        self.assertTrue(self.css_path.exists())
        self.assertTrue(self.js_path.exists())

        self.html_content = self.html_path.read_text("utf-8")
        self.css_content = self.css_path.read_text("utf-8")
        self.js_content = self.js_path.read_text("utf-8")

    def test_five_view_navigation_structure(self):
        """Web navigation must have exactly 5 primary views in SNOW V7 order."""
        nav_pattern = re.compile(r'<nav class="nav-menu"[^>]*>(.*?)</nav>', re.DOTALL)
        match = nav_pattern.search(self.html_content)
        self.assertIsNotNone(match, "nav-menu not found in index.html")

        nav_body = match.group(1)
        buttons = re.findall(r'<button class="nav-item[^"]*" data-tab="([^"]+)"[^>]*>', nav_body)
        self.assertEqual(len(buttons), 5, f"Expected exactly 5 nav items, found {len(buttons)}: {buttons}")
        self.assertEqual(buttons, ["overview", "clipboard", "files", "devices", "settings"])

    def test_theme_options_labels(self):
        """Theme options must be exactly System, Light Mode, Dark Mode without legacy names."""
        self.assertNotIn("Glacier Crisp", self.html_content)
        self.assertNotIn("Obsidian Frost", self.html_content)

        # Must have radio buttons for system, light, and dark
        self.assertIn('value="system"', self.html_content)
        self.assertIn('value="light"', self.html_content)
        self.assertIn('value="dark"', self.html_content)

    def test_hero_desktop_card(self):
        """Home must feature the Material 3 Hero card with wallpaper preview and actions."""
        self.assertIn('class="hero-desktop-card"', self.html_content)
        self.assertIn('id="desktop-wallpaper-img"', self.html_content)
        self.assertIn('id="btn-hero-lock-pc"', self.html_content)
        self.assertIn('id="btn-hero-send-file"', self.html_content)

    def test_command_palette_and_bell(self):
        """Topbar must include Ctrl+K Command Palette and Activity & Approvals Bell with badge."""
        self.assertIn('id="btn-topbar-command-palette"', self.html_content)
        self.assertIn('id="btn-topbar-approvals"', self.html_content)
        self.assertIn('id="topbar-approvals-badge"', self.html_content)
        self.assertIn('id="command-palette-overlay"', self.html_content)
        self.assertIn('id="command-palette-input"', self.html_content)

    def test_collapsed_advanced_accordion(self):
        """Raw ports and developer environment must be collapsed inside Advanced & Diagnostics."""
        self.assertIn('class="advanced-accordion', self.html_content)
        # Verify diag-port is inside details
        details_match = re.search(r'<details class="advanced-accordion[^"]*">(.*?)</details>', self.html_content, re.DOTALL)
        self.assertIsNotNone(details_match, "advanced-accordion details block not found")
        self.assertIn('id="diag-port"', details_match.group(1))

    def test_css_material3_palette_tokens(self):
        """CSS must define exact Light and Dark palette tokens."""
        # Light mode
        self.assertIn("#F8FAFC", self.css_content)
        self.assertIn("#2563EB", self.css_content)
        # Dark mode
        self.assertIn("#0B0E17", self.css_content)
        self.assertIn("#111827", self.css_content)
        self.assertIn("#00E5FF", self.css_content)

    def test_dynamic_hero_card_script_contracts(self):
        """app.js must define updateHeroCard and applyOfflineUsbDimming."""
        self.assertIn("function updateHeroCard(", self.js_content)
        self.assertIn("function applyOfflineUsbDimming(", self.js_content)
        self.assertIn("hero-device-icon", self.js_content)
        self.assertIn("hero-device-name", self.js_content)
        self.assertIn("hero-transport-pill", self.js_content)

    def test_offline_usb_and_phone_bezel_css(self):
        """app.css must define .offline-dimmed and .phone-bezel classes."""
        self.assertIn(".offline-dimmed", self.css_content)
        self.assertIn(".laptop-bezel.phone-bezel", self.css_content)


if __name__ == "__main__":
    unittest.main()
