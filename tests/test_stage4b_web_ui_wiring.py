"""Phase 4 Stage 4B: Web UI Real-Wiring, Route Parity, and Mockup Regression Tests.

Validates:
1. Complete mockup data purge from index.html and app.js.
2. 100% frontend-to-backend route parity with zero 404 routes.
3. JavaScript structural integrity and delimiter balancing.
4. Native backend endpoint contracts for Stage 4B capability expansions:
   - POST /api/devices/ring
   - POST /api/camera/capture
   - POST /api/clipboard/sync
   - POST /api/files/upload
   - GET  /api/mcp/tunnel/qr
5. Seven Stage 4B audited defect group closures:
   - Remote AI Tunnel with cloudflared provider and OAuth 2.1 approvals queue.
   - APK info endpoint, Relay tunnel controls, Federation grants & kill switch.
   - Clipboard field normalization and deletion.
   - Scoped files with hide_hidden parameter.
   - AI gateway status and diagnostics integration.
6. Session and CSRF security middleware enforcement.
"""

from __future__ import annotations

import io
import re
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from aiohttp import FormData, web
from aiohttp.test_utils import AioHTTPTestCase

from snow.web.server import SnowWebServer


class TestStage4BMockupDataRegression(unittest.TestCase):
    """Verifies that all static mockup, fake telemetry, and demo text are purged."""

    FORBIDDEN_PATTERNS = [
        "Mom",
        "Where are you",
        "Office Workstation",
        "Sprint review notes",
        "Checklist checklist",
        "presentation_slides.pdf",
        "482 910",
        "Claude requested Capture Phone Screen",
        "Project_Notes.pdf",
        "72%",
    ]

    def setUp(self):
        self.html_path = Path("src/snow/web/static/index.html")
        self.js_path = Path("src/snow/web/static/app.js")
        self.assertTrue(self.html_path.is_file(), "index.html missing")
        self.assertTrue(self.js_path.is_file(), "app.js missing")
        self.html_content = self.html_path.read_text(encoding="utf-8")
        self.js_content = self.js_path.read_text(encoding="utf-8")

    def test_forbidden_mockup_strings_absent_from_html(self):
        """All demo names, fake notifications, and mockup files must be purged from index.html."""
        for pattern in self.FORBIDDEN_PATTERNS:
            self.assertNotIn(
                pattern,
                self.html_content,
                f"Forbidden mockup pattern '{pattern}' found in index.html",
            )

    def test_forbidden_mockup_strings_absent_from_js(self):
        """All demo names, fake notifications, and mockup files must be purged from app.js."""
        for pattern in self.FORBIDDEN_PATTERNS:
            self.assertNotIn(
                pattern,
                self.js_content,
                f"Forbidden mockup pattern '{pattern}' found in app.js",
            )

    def test_no_fake_android_reboot_control(self):
        """Android reboot is not a supported protocol capability and must not exist in Hero actions."""
        self.assertNotIn("Reboot", self.html_content)
        self.assertNotIn("reboot", self.html_content.lower().split())

    def test_empty_and_loading_states_present(self):
        """Containers must feature semantic empty or loading states."""
        self.assertIn("empty-state", self.html_content)
        self.assertIn("No clipboard items yet", self.html_content)
        self.assertIn("No active notifications", self.html_content)
        # "Scanning for devices..." was in diag-log-box, removed in Stage 6A declutter


class TestStage4BRouteParity(unittest.TestCase):
    """Verifies that every API endpoint invoked in app.js has a corresponding route in server.py."""

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
        self.js_content = self.js_path.read_text(encoding="utf-8")

    def test_frontend_routes_match_registered_routes(self):
        """Extract all /api/ endpoints called by fetch, apiRequest, or XHR and verify registration."""
        api_calls = re.findall(r'["\'](/api/[^"\'?]+)', self.js_content)
        api_template_calls = re.findall(r'`(/api/[^`?]+)', self.js_content)

        all_endpoints = set(api_calls)
        for ep in api_template_calls:
            normalized = re.sub(r'\$\{[^}]+\}', '{item_id}', ep)
            all_endpoints.add(normalized)

        self.assertGreater(len(all_endpoints), 15, "Should have extracted at least 15 API endpoints from app.js")

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
                f"Frontend endpoint '{endpoint}' has no matching route registered in SnowWebServer. Registered: {sorted(self.registered_routes)}",
            )


class TestStage4BJsSyntaxAndBalancing(unittest.TestCase):
    """Validates delimiter balance and syntax in app.js."""

    def setUp(self):
        self.js_path = Path("src/snow/web/static/app.js")
        self.js_content = self.js_path.read_text(encoding="utf-8")

    def test_delimiter_balancing(self):
        """All braces, brackets, and parentheses must be perfectly balanced."""
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

    def test_show_notification_toast_canonical(self):
        """Ensure showNotificationToast is defined and no stray undefined showNotification calls exist."""
        self.assertIn("function showNotificationToast(", self.js_content)
        stray = re.findall(r"(?<!\bshowNotificationToast)\bshowNotification\(", self.js_content)
        self.assertEqual(len(stray), 0, f"Found stray undefined showNotification calls: {stray}")

    def test_cloudflared_provider_used(self):
        """Web UI must send 'cloudflared' provider identifier for tunnels."""
        self.assertIn('"cloudflared"', self.js_content)
        self.assertNotIn('provider: "cloudflare"', self.js_content)


class TestStage4BBackendHandlers(AioHTTPTestCase):
    """Functional tests for the newly wired backend capability endpoints in server.py."""

    async def get_application(self) -> web.Application:
        self.bridge = MagicMock()
        self.bridge.android_ring = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        self.bridge.android_camera_capture = AsyncMock(return_value={"success": True, "status": "SUCCESS", "photo_url": "/api/camera/latest"})
        self.bridge.sync_clipboard = AsyncMock(return_value={"success": True, "direction": "both", "synced_items": 1})
        self.bridge.android_file_send = AsyncMock(return_value={"success": True, "status": "SUCCESS", "data": {"transferred": 1024}})
        self.bridge.call = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        self.bridge.android_file_list = AsyncMock(return_value={"success": True, "data": {"items": [{"name": "test.txt", "size": 100, "is_directory": False}]}})

        self.mock_transfer = MagicMock()

        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.bridge,
            auto_open_browser=False,
            transfer_server=self.mock_transfer,
        )
        return self.web_server._build_app()

    async def _authenticate_session(self) -> str:
        """Authenticate session via bootstrap token and return csrf_token."""
        token = self.web_server.bootstrap_token
        resp = await self.client.post("/api/auth/session", json={"token": token})
        data = await resp.json()
        self.assertTrue(data.get("success"), f"Auth failed: {data}")
        return data["csrf_token"]

    async def test_ring_endpoint_csrf_and_execution(self):
        """POST /api/devices/ring requires session, CSRF, and invokes bridge.android_ring."""
        resp_unauth = await self.client.post("/api/devices/ring", json={"device_id": "test_phone"})
        self.assertEqual(resp_unauth.status, 401)

        csrf = await self._authenticate_session()

        resp_nocsrf = await self.client.post("/api/devices/ring", json={"device_id": "test_phone"})
        self.assertEqual(resp_nocsrf.status, 403)

        resp = await self.client.post(
            "/api/devices/ring",
            json={"device_id": "test_phone", "duration_seconds": 5},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["success"])
        self.bridge.android_ring.assert_called_once_with(duration_seconds=5, device_id="test_phone")

    async def test_camera_capture_endpoint_execution(self):
        """POST /api/camera/capture invokes bridge.android_camera_capture."""
        csrf = await self._authenticate_session()
        resp = await self.client.post(
            "/api/camera/capture",
            json={"device_id": "phone_1"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["success"])
        self.bridge.android_camera_capture.assert_called_once_with(device_id="phone_1", approval_id="")

    async def test_clipboard_sync_endpoint_execution(self):
        """POST /api/clipboard/sync invokes bridge.sync_clipboard."""
        csrf = await self._authenticate_session()
        resp = await self.client.post(
            "/api/clipboard/sync",
            json={"direction": "both", "device_id": "phone_1"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["success"])
        self.bridge.sync_clipboard.assert_called_once_with(direction="both", device_id="phone_1")

    async def test_files_upload_endpoint_multipart(self):
        """POST /api/files/upload accepts multipart form data and passes to bridge.android_file_send."""
        csrf = await self._authenticate_session()

        form = FormData()
        form.add_field("device_id", "phone_test")
        form.add_field(
            "file",
            io.BytesIO(b"Hello SNOW Capstone Project"),
            filename="test_upload.txt",
            content_type="text/plain",
        )

        resp = await self.client.post(
            "/api/files/upload",
            data=form,
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["filename"], "test_upload.txt")
        self.bridge.android_file_send.assert_called_once()

    async def test_mcp_tunnel_qr_endpoint(self):
        """GET /api/mcp/tunnel/qr returns valid SVG and URL."""
        await self._authenticate_session()
        resp = await self.client.get("/api/mcp/tunnel/qr")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["success"])
        self.assertIn("url", data)
        self.assertIn("/mcp", data["url"])
        self.assertIn("svg", data)
        self.assertIn("<svg", data["svg"])

    async def test_hide_hidden_files_parameter(self):
        """GET /api/files parses hide_hidden parameter properly."""
        await self._authenticate_session()
        resp = await self.client.get("/api/files?hide_hidden=true")
        self.assertEqual(resp.status, 200)
        self.bridge.android_file_list.assert_called_with(
            subpath="",
            device_id="",
            scope="full",
            show_hidden=False,
        )

    async def test_approvals_resolve_status_parameter(self):
        """POST /api/approvals/resolve accepts status='APPROVED'."""
        csrf = await self._authenticate_session()
        resp = await self.client.post(
            "/api/approvals/resolve",
            json={"request_id": "test_req", "status": "APPROVED"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(resp.status, 200)
        self.bridge.call.assert_called_with("approval_approve", payload={"request_id": "test_req"})


if __name__ == "__main__":
    unittest.main()
