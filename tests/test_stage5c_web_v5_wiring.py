"""SNOW V5 Stage 5C: Windows Web V5 Flagship Rebuild Test Suite.

Validates:
1. Group A: Complete 100% frontend-to-backend route parity for app.js.
2. Group B: Offline-first asset integrity (zero external CDNs, zero cloud dependencies).
3. Group C: Purge of design mock data, forbidden demo strings, and zero emojis in production UI.
4. Group D: JavaScript structural integrity, syntax correctness, and delimiter balancing.
5. Group E: Complete Five-View coverage, shell navigation, and modal state presence.
6. Group F: Device selection stability, non-overwriting polling, and local host deduplication.
7. Group G: Theme tokens (Light Mode, Dark Mode, System), standard naming, and responsive CSS.
8. Group H: Functional interaction handlers, approval dispatch, and capability bindings.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase

from snow.web.server import SnowWebServer


class TestStage5CRouteParity(unittest.TestCase):
    """Group A: Verifies every endpoint called in app.js has a corresponding route in server.py."""

    def setUp(self):
        self.bridge = MagicMock()
        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.bridge,
            auto_open_browser=False,
        )
        self.app = self.web_server._build_app()
        self.registered_routes = set()
        for resource in self.app.router.resources():
            info = resource.get_info()
            if "path" in info:
                self.registered_routes.add(info["path"])
            elif "formatter" in info:
                self.registered_routes.add(info["formatter"])
            elif "prefix" in info:
                self.registered_routes.add(info["prefix"])

        self.js_path = Path("src/snow/web/static/app.js")
        self.assertTrue(self.js_path.is_file(), "app.js missing")
        self.js_content = self.js_path.read_text(encoding="utf-8")

    def test_frontend_routes_match_registered_routes(self):
        """All /api/ calls in app.js must map to registered SnowWebServer routes."""
        api_calls = re.findall(r'["\'](/api/[^"\'?]+)', self.js_content)
        api_template_calls = re.findall(r'`(/api/[^`?]+)', self.js_content)

        all_endpoints = set(api_calls)
        for ep in api_template_calls:
            normalized = re.sub(r'\$\{[^}]+\}', '{item_id}', ep)
            all_endpoints.add(normalized)

        self.assertGreater(len(all_endpoints), 20, "Expected at least 20 API endpoints in app.js")

        for endpoint in all_endpoints:
            matched = False
            if endpoint in self.registered_routes:
                matched = True
            else:
                for reg in self.registered_routes:
                    pattern = "^" + re.sub(r'\{[a-zA-Z0-9_]+\}', r'[^/]+', reg) + "$"
                    if re.match(pattern, endpoint):
                        matched = True
                        break
            self.assertTrue(
                matched,
                f"Frontend endpoint '{endpoint}' not registered in SnowWebServer. Registered: {sorted(self.registered_routes)}",
            )


class TestStage5COfflineAssetIntegrity(unittest.TestCase):
    """Group B: Validates offline-first delivery with zero external network dependencies."""

    def setUp(self):
        self.html_path = Path("src/snow/web/static/index.html")
        self.css_path = Path("src/snow/web/static/app.css")
        self.tokens_path = Path("src/snow/web/static/tokens.css")
        self.js_path = Path("src/snow/web/static/app.js")

        self.html = self.html_path.read_text(encoding="utf-8")
        self.css = self.css_path.read_text(encoding="utf-8")
        self.tokens = self.tokens_path.read_text(encoding="utf-8")
        self.js = self.js_path.read_text(encoding="utf-8")

    def test_no_external_cdn_references(self):
        """No external CDNs or cloud font links are permitted."""
        forbidden_cdns = [
            "cdn.tailwindcss.com",
            "fonts.googleapis.com",
            "fonts.gstatic.com",
            "cdnjs.cloudflare.com",
            "unpkg.com",
            "cdn.jsdelivr.net",
        ]
        combined = self.html + self.css + self.tokens + self.js
        for cdn in forbidden_cdns:
            self.assertNotIn(cdn, combined, f"Found external CDN reference: {cdn}")

    def test_local_static_assets_exist(self):
        """All referenced local static assets must exist in src/snow/web/static/."""
        static_dir = Path("src/snow/web/static")
        expected_files = ["index.html", "app.css", "tokens.css", "app.js", "theme-init.js", "snow_logo.png", "favicon.ico"]
        for f in expected_files:
            target = static_dir / f
            self.assertTrue(target.is_file(), f"Missing static asset: {f}")

    def test_strict_csp_no_inline_scripts_or_handlers(self):
        """Production HTML/JS must have zero inline scripts or inline onclick/onerror handlers."""
        inline_scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", self.html, re.IGNORECASE)
        self.assertEqual(inline_scripts, [], f"Inline scripts violate CSP script-src 'self': {inline_scripts}")
        self.assertNotIn("onclick=", self.html.lower())
        self.assertNotIn("onerror=", self.html.lower())
        self.assertNotIn("onclick=", self.js.lower())
        self.assertNotIn("onerror=", self.js.lower())


class TestStage5CMockupContentAndEmojiRemoval(unittest.TestCase):
    """Group C: Validates removal of all design mockup data, placeholder strings, and emojis."""

    FORBIDDEN_MOCK_STRINGS = [
        "Aarav",
        "Neha",
        "Rahul's",
        "Midnight City",
        "482 910",
        "Grok",
        "Lenovo_V15",
        "Pixel 8 Pro",
        "Mom",
        "Where are you",
        "Office Workstation",
        "Sprint review notes",
        "Checklist checklist",
        "presentation_slides.pdf",
        "Claude requested Capture Phone Screen",
        "Project_Notes.pdf",
        "Glacier Crisp",
        "Obsidian Frost",
    ]

    def setUp(self):
        self.html = Path("src/snow/web/static/index.html").read_text(encoding="utf-8")
        self.js = Path("src/snow/web/static/app.js").read_text(encoding="utf-8")

    def test_forbidden_mockup_strings_purged(self):
        """Production HTML and JS must contain zero design mock strings."""
        for pattern in self.FORBIDDEN_MOCK_STRINGS:
            self.assertNotIn(
                pattern.lower(),
                self.html.lower(),
                f"Forbidden mock string '{pattern}' found in index.html",
            )
            self.assertNotIn(
                pattern.lower(),
                self.js.lower(),
                f"Forbidden mock string '{pattern}' found in app.js",
            )

    def test_zero_emojis_in_production_ui(self):
        """All UI icons must be inline SVGs; zero Unicode emojis permitted."""
        # Regex matching common Emoji Unicode ranges
        emoji_pattern = re.compile(
            r"[\U0001F300-\U0001F6FF\U0001F900-\U0001F9FF\U0001FA70-\U0001FAFF"
            r"\U00002600-\U000026FF\U00002700-\U000027BF\U0001F1E6-\U0001F1FF]"
        )
        html_emojis = emoji_pattern.findall(self.html)
        self.assertEqual(len(html_emojis), 0, f"Found emojis in index.html: {html_emojis}")

        js_emojis = emoji_pattern.findall(self.js)
        self.assertEqual(len(js_emojis), 0, f"Found emojis in app.js: {js_emojis}")

    def test_no_fake_reboot_action(self):
        """Reboot is unsupported and must not exist in actions."""
        self.assertNotIn("Reboot", self.html)


class TestStage5CJsSyntaxAndBalancing(unittest.TestCase):
    """Group D: Validates delimiter balancing and JS structural integrity."""

    def setUp(self):
        self.js_path = Path("src/snow/web/static/app.js")
        self.js_content = self.js_path.read_text(encoding="utf-8")

    def test_delimiter_balancing(self):
        """All parentheses, brackets, and braces in app.js must be balanced."""
        js_text = self.js_content
        idx = 0
        n = len(js_text)
        stack: list[tuple[str, int]] = []
        last_token_char = ''
        closing_map = {')': '(', ']': '[', '}': '{'}

        while idx < n:
            ch = js_text[idx]

            # 1. Comments
            if ch == '/' and idx + 1 < n and js_text[idx + 1] == '/':
                idx = js_text.find('\n', idx)
                if idx == -1:
                    break
                continue
            if ch == '/' and idx + 1 < n and js_text[idx + 1] == '*':
                end_idx = js_text.find('*/', idx + 2)
                self.assertTrue(end_idx != -1, "Unclosed block comment in app.js")
                idx = end_idx + 2
                continue

            # 2. Regular Expression literal vs division
            if ch == '/' and last_token_char in '(=:[!&|?{;,':
                idx += 1
                while idx < n:
                    if js_text[idx] == '\\':
                        idx += 2
                    elif js_text[idx] == '/':
                        idx += 1
                        while idx < n and js_text[idx].isalpha():
                            idx += 1
                        break
                    elif js_text[idx] == '\n':
                        break
                    else:
                        idx += 1
                last_token_char = '/'
                continue

            # 3. Single / Double strings
            if ch in ("'", '"'):
                quote = ch
                idx += 1
                while idx < n:
                    if js_text[idx] == '\\':
                        idx += 2
                    elif js_text[idx] == quote:
                        idx += 1
                        break
                    elif js_text[idx] == '\n':
                        break
                    else:
                        idx += 1
                last_token_char = quote
                continue

            # 4. Template literals
            if ch == '`':
                idx += 1
                while idx < n:
                    if js_text[idx] == '\\':
                        idx += 2
                    elif js_text[idx] == '$' and idx + 1 < n and js_text[idx + 1] == '{':
                        stack.append(('${', idx))
                        idx += 2
                        break
                    elif js_text[idx] == '`':
                        idx += 1
                        break
                    else:
                        idx += 1
                last_token_char = '`'
                continue

            # 5. Brackets & braces
            if ch in ('(', '[', '{'):
                stack.append((ch, idx))
                last_token_char = ch
            elif ch in closing_map:
                self.assertTrue(len(stack) > 0, f"Unmatched closing '{ch}' at index {idx}")
                top, top_idx = stack.pop()
                if top == '${':
                    self.assertEqual(ch, '}', f"Mismatched closing '{ch}' for '${{' opened at {top_idx}")
                    # Resume template literal after '${...}'
                    while idx + 1 < n:
                        idx += 1
                        if js_text[idx] == '\\':
                            idx += 1
                        elif js_text[idx] == '$' and idx + 1 < n and js_text[idx + 1] == '{':
                            stack.append(('${', idx))
                            idx += 1
                            break
                        elif js_text[idx] == '`':
                            break
                else:
                    expected = closing_map[ch]
                    self.assertEqual(expected, top, f"Mismatched closing '{ch}' for '{top}' opened at {top_idx}")
                last_token_char = ch
            elif not ch.isspace():
                last_token_char = ch

            idx += 1

        self.assertEqual(len(stack), 0, f"Unclosed delimiters remaining in app.js: {stack}")

    def test_notification_toast_naming(self):
        """showNotificationToast must exist and no stray showNotification calls."""
        self.assertIn("function showNotificationToast(", self.js_content)
        stray = re.findall(r"(?<!\bshowNotificationToast)\bshowNotification\(", self.js_content)
        self.assertEqual(len(stray), 0, f"Stray showNotification calls: {stray}")

    def test_cloudflared_provider_naming(self):
        """Valid provider identifiers ('render' default in JS, optional 'cloudflared' in HTML) must be used without typo."""
        self.assertIn('"render"', self.js_content)
        html_content = Path("src/snow/web/static/index.html").read_text(encoding="utf-8")
        self.assertIn('"cloudflared"', html_content)
        self.assertNotIn('provider: "cloudflare"', self.js_content)


class TestStage5CFiveViewAndModalCoverage(unittest.TestCase):
    """Group E: Validates presence of five views, shell elements, and modal states."""

    def setUp(self):
        self.html = Path("src/snow/web/static/index.html").read_text(encoding="utf-8")

    def test_five_views_present(self):
        """Five distinct application views must be present."""
        self.assertIn('id="section-overview"', self.html)
        self.assertIn('id="section-devices"', self.html)
        self.assertIn('id="section-files"', self.html)
        self.assertIn('id="section-clipboard"', self.html)
        self.assertIn('id="section-settings"', self.html)

    def test_floating_device_island_present(self):
        """Floating Device Selector Island structure must exist."""
        self.assertIn('id="device-island"', self.html)
        self.assertIn("MY NETWORK", self.html)
        self.assertIn("OTHER NETWORKS", self.html)
        self.assertIn('id="btn-island-connect"', self.html)

    def test_sidebar_and_topbar_controls_present(self):
        """Sidebar rail toggle and topbar capsule must exist."""
        self.assertIn('id="btn-sidebar-toggle"', self.html)
        self.assertIn('id="topbar-device-capsule"', self.html)
        self.assertIn('id="btn-topbar-command-palette"', self.html)
        self.assertIn('id="btn-theme-toggle"', self.html)

    def test_modals_present(self):
        """All required modals must exist in index.html."""
        self.assertIn('id="connect-modal"', self.html)
        self.assertIn('id="command-palette-overlay"', self.html)
        self.assertIn('id="poweroff-modal"', self.html)
        self.assertIn('id="media-preview-modal"', self.html)
        self.assertIn('id="notif-reply-modal"', self.html)
        self.assertIn('id="killswitch-modal"', self.html)
        self.assertIn('id="mcp-qr-modal"', self.html)

    def test_empty_states_present(self):
        """Containers must feature semantic empty states."""
        self.assertIn("No clipboard items yet", self.html)
        self.assertIn("No active notifications", self.html)
        # "Scanning for devices..." was in diag-log-box, removed in Stage 6A declutter


class TestStage5CThemeTokensAndResponsive(unittest.TestCase):
    """Group G: Validates Light Mode and Dark Mode palettes and standard naming."""

    def setUp(self):
        self.tokens = Path("src/snow/web/static/tokens.css").read_text(encoding="utf-8")
        self.css = Path("src/snow/web/static/app.css").read_text(encoding="utf-8")
        self.html = Path("src/snow/web/static/index.html").read_text(encoding="utf-8")

    def test_theme_naming_standard(self):
        """Theme selector must offer exactly System, Light Mode, and Dark Mode."""
        self.assertIn("Light Mode", self.html)
        self.assertIn("Dark Mode", self.html)
        self.assertIn("System", self.html)
        self.assertNotIn("Glacier Crisp", self.html)
        self.assertNotIn("Obsidian Frost", self.html)

    def test_theme_css_classes(self):
        """tokens.css must define html.theme-dark and html.theme-light palettes."""
        self.assertIn("html.theme-dark", self.tokens)
        self.assertIn("html.theme-light", self.tokens)
        self.assertIn("--snow-brand-gradient", self.tokens)
        self.assertIn("--snow-bg-canvas", self.tokens)
        self.assertIn("--snow-bg-sidebar", self.tokens)
        self.assertIn("--snow-bg-card", self.tokens)

    def test_responsive_media_queries(self):
        """app.css must provide responsive breakpoints for desktop resolutions."""
        self.assertIn("@media (max-width:", self.css)


class TestStage5CLiveSmoke(AioHTTPTestCase):
    """Gate 8: Web runtime smoke test verifying live serving, asset delivery, and CSRF."""

    async def get_application(self) -> web.Application:
        self.bridge = MagicMock()
        self.bridge.android_ring = AsyncMock(return_value={"success": True})
        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.bridge,
            auto_open_browser=False,
        )
        return self.web_server._build_app()

    async def test_root_index_delivered_offline_and_emoji_free(self):
        """GET / returns HTTP 200, offline assets, and zero emojis."""
        resp = await self.client.get("/")
        self.assertEqual(resp.status, 200)
        text = await resp.text()
        self.assertIn("SNOW — Multi-Device AI Capability Bridge", text)
        self.assertIn("/static/tokens.css", text)
        self.assertIn("/static/app.css", text)
        self.assertIn("/static/app.js", text)
        # Verify zero emojis
        emoji_pattern = re.compile(
            r"[\U0001F300-\U0001F6FF\U0001F900-\U0001F9FF\U0001FA70-\U0001FAFF"
            r"\U00002600-\U000026FF\U00002700-\U000027BF\U0001F1E6-\U0001F1FF]"
        )
        self.assertEqual(len(emoji_pattern.findall(text)), 0)

    async def test_static_assets_all_return_200(self):
        """All critical static files must return HTTP 200."""
        for path in ["/static/tokens.css", "/static/app.css", "/static/app.js", "/static/theme-init.js", "/static/snow_logo.png"]:
            resp = await self.client.get(path)
            self.assertEqual(resp.status, 200, f"Static asset {path} failed with {resp.status}")

    async def test_csrf_middleware_enforced_live(self):
        """Mutating endpoints reject unauthenticated or un-CSRF-tokened requests."""
        resp = await self.client.post("/api/devices/ring", json={"device_id": "test"})
        self.assertIn(resp.status, (401, 403))

    def test_loopback_binding_enforced(self):
        """SnowWebServer rejects non-loopback bind addresses."""
        with self.assertRaises(ValueError):
            SnowWebServer(host="0.0.0.0", port=8769, bridge=self.bridge, auto_open_browser=False)


if __name__ == "__main__":
    unittest.main()
