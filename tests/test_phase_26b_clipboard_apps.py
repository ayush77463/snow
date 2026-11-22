"""Unit and integration test suite for SNOW Phase 26B:
Shared Clipboard Buffer, Unified Capture Hub & Authorized Remote App Launcher.

Covers:
1. Ring buffer capacity (10 items), newest-first ordering.
2. Oldest-unpinned eviction and pinned item protection.
3. Max 5 pinned items limit and rejection when all pinned.
4. Delete and clear behavior (unpinned preservation vs full clear).
5. Text (64 KiB) and Image (10 MiB) size limits and format validation.
6. SHA-256 deduplication and echo-loop suppression.
7. Image file lifecycle (canonical storage containment, unlinking on delete/evict/clear).
8. Safe metadata generation and redaction.
9. Security & policy: OWNER_MANUAL vs AI_MCP permissions.
10. IPC and WSS metadata control plane actions.
11. Dashboard endpoints: CSRF, auth, image retrieval (401/404/containment).
12. Remote App Launcher: Windows allowlist enforcement and Android app routing.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from snow.capabilities.clipboard_buffer import (
    ClipboardRingBuffer,
    ClipboardItem,
    MAX_BUFFER_ITEMS,
    MAX_PINNED_ITEMS,
    MAX_TEXT_BYTES,
    MAX_IMAGE_BYTES,
    JPEG_SIGNATURE,
    PNG_SIGNATURE,
)
from snow.core.config import CoreConfig
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.mcp.registry import (
    CLIPBOARD_BUFFER_CAPABILITIES,
    get_capability_metadata,
    get_mcp_annotations,
)


class TestClipboardRingBufferSemantics(unittest.TestCase):
    """Test suite for ClipboardRingBuffer memory semantics, limits, and file lifecycle."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_cb_buffer_")
        self.buffer = ClipboardRingBuffer(storage_dir=self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_01_add_text_and_ordering_newest_at_zero(self) -> None:
        """New items appear at index 0 (newest-first)."""
        res1 = self.buffer.add_text("First item")
        self.assertTrue(res1["success"])
        self.assertEqual(res1["status"], "ADDED")

        time.sleep(0.01)
        res2 = self.buffer.add_text("Second item")
        self.assertTrue(res2["success"])

        items = self.buffer.list_items()
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["preview"], "Second item")
        self.assertEqual(items[1]["preview"], "First item")

    def test_02_capacity_limit_and_oldest_unpinned_eviction(self) -> None:
        """Buffer caps at 10 items, evicting the oldest unpinned item when full."""
        for i in range(10):
            res = self.buffer.add_text(f"Item {i}")
            self.assertTrue(res["success"])
            time.sleep(0.005)

        self.assertEqual(len(self.buffer.list_items()), 10)
        self.assertEqual(self.buffer.list_items()[0]["preview"], "Item 9")
        self.assertEqual(self.buffer.list_items()[9]["preview"], "Item 0")

        # 11th item should evict "Item 0"
        res11 = self.buffer.add_text("Item 10")
        self.assertTrue(res11["success"])
        items = self.buffer.list_items()
        self.assertEqual(len(items), 10)
        self.assertEqual(items[0]["preview"], "Item 10")
        previews = [it["preview"] for it in items]
        self.assertNotIn("Item 0", previews)
        self.assertIn("Item 1", previews)

    def test_03_pinned_item_protection_from_eviction(self) -> None:
        """Pinned items are protected from eviction when buffer overflows."""
        # Add Item 0 and pin it
        res0 = self.buffer.add_text("Item 0 (Pinned)", pin=True)
        self.assertTrue(res0["success"])
        item0_id = res0["item"]["item_id"]

        # Add 9 more items
        for i in range(1, 10):
            self.buffer.add_text(f"Item {i}")
            time.sleep(0.005)

        self.assertEqual(len(self.buffer.list_items()), 10)

        # Adding Item 10 should evict Item 1 (oldest unpinned), preserving Item 0 (pinned)
        res_overflow = self.buffer.add_text("Item 10")
        self.assertTrue(res_overflow["success"])

        items = self.buffer.list_items()
        self.assertEqual(len(items), 10)
        previews = [it["preview"] for it in items]
        self.assertIn("Item 0 (Pinned)", previews)
        self.assertNotIn("Item 1", previews)

    def test_04_max_pinned_limit_and_all_pinned_overflow(self) -> None:
        """Buffer enforces max 5 pinned items and rejects addition if all eligible items pinned."""
        # Pin 5 items
        for i in range(5):
            res = self.buffer.add_text(f"Pinned {i}", pin=True)
            self.assertTrue(res["success"])

        # 6th pinned addition fails with MAX_PINNED_REACHED
        res6 = self.buffer.add_text("Pinned 5", pin=True)
        self.assertFalse(res6["success"])
        self.assertEqual(res6["status"], "MAX_PINNED_REACHED")

        # Explicit pin operation on unpinned item also enforces limit of 5
        res_unpinned = self.buffer.add_text("Normal item")
        self.assertTrue(res_unpinned["success"])
        pin_res = self.buffer.pin(res_unpinned["item"]["item_id"])
        self.assertFalse(pin_res["success"])
        self.assertEqual(pin_res["status"], "MAX_PINNED_REACHED")

    def test_05_all_items_pinned_rejects_addition(self) -> None:
        """If all items in a buffer configured with capacity are pinned, reject additions."""
        # Manually force all items in buffer to pinned state
        for i in range(5):
            self.buffer.add_text(f"Pin {i}", pin=True)
        # Fill rest to max 5 items total for test
        self.buffer._items = self.buffer._items[:5]
        # Simulate edge case where every item in buffer is pinned and buffer is full
        self.buffer.capacity = 5
        res = self.buffer.add_text("Overflow item")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "BUFFER_FULL_ALL_PINNED")

    def test_06_text_size_limit_64kib(self) -> None:
        """Text exceeding 64 KiB is rejected with CONTENT_TOO_LARGE."""
        allowed_text = "A" * (64 * 1024)
        res_ok = self.buffer.add_text(allowed_text)
        self.assertTrue(res_ok["success"])

        oversized_text = "A" * ((64 * 1024) + 1)
        res_fail = self.buffer.add_text(oversized_text)
        self.assertFalse(res_fail["success"])
        self.assertEqual(res_fail["status"], "CONTENT_TOO_LARGE")

    def test_07_image_size_limit_and_signature_validation(self) -> None:
        """Images must be valid PNG or JPEG under 10 MiB."""
        # Invalid format (text disguised as image)
        bad_img = b"NOT_AN_IMAGE_PAYLOAD"
        res_bad = self.buffer.add_image(bad_img)
        self.assertFalse(res_bad["success"])
        self.assertEqual(res_bad["status"], "INVALID_IMAGE_FORMAT")

        # Valid PNG
        valid_png = PNG_SIGNATURE + b"\x00\x00\x00\rIHDR" + b"TEST_PNG_DATA"
        res_png = self.buffer.add_image(valid_png)
        self.assertTrue(res_png["success"])
        self.assertEqual(res_png["item"]["content_type"], "image")
        self.assertEqual(res_png["item"]["mime_type"], "image/png")

        # Valid JPEG
        valid_jpg = JPEG_SIGNATURE + b"\xe0\x00\x10JFIF" + b"TEST_JPEG_DATA"
        res_jpg = self.buffer.add_image(valid_jpg)
        self.assertTrue(res_jpg["success"])
        self.assertEqual(res_jpg["item"]["content_type"], "image")
        self.assertEqual(res_jpg["item"]["mime_type"], "image/jpeg")

        # Oversized image (> 10 MiB)
        oversized_jpg = JPEG_SIGNATURE + b"\x00" * (10 * 1024 * 1024 + 1)
        res_oversized = self.buffer.add_image(oversized_jpg)
        self.assertFalse(res_oversized["success"])
        self.assertEqual(res_oversized["status"], "CONTENT_TOO_LARGE")

    def test_08_image_file_lifecycle_eviction_and_delete(self) -> None:
        """Image files are created on disk and safely deleted upon eviction, delete, and clear."""
        valid_png = PNG_SIGNATURE + b"\x00\x00\x00\rIHDR" + b"TEST_IMAGE"
        res = self.buffer.add_image(valid_png)
        self.assertTrue(res["success"])
        item_id = res["item"]["item_id"]

        img_path = self.buffer.get_image_path(item_id)
        self.assertIsNotNone(img_path)
        self.assertTrue(img_path.is_file())
        self.assertTrue(img_path.is_relative_to(Path(self.temp_dir)))

        # Explicit delete removes image from disk
        del_res = self.buffer.delete(item_id)
        self.assertTrue(del_res["success"])
        self.assertFalse(img_path.exists())

        # Test eviction deletes image
        res_evict = self.buffer.add_image(valid_png)
        evict_item_id = res_evict["item"]["item_id"]
        evict_img_path = self.buffer.get_image_path(evict_item_id)
        self.assertTrue(evict_img_path.is_file())

        # Fill buffer with 10 text items to force eviction of the image
        for i in range(10):
            self.buffer.add_text(f"Fill item {i}")
        self.assertFalse(evict_img_path.exists())

    def test_09_clear_unpinned_preserves_pinned(self) -> None:
        """Clear with unpinned_only=True clears normal items but keeps pinned items and files."""
        # Add 1 pinned image
        valid_png = PNG_SIGNATURE + b"PINNED_IMAGE"
        img_res = self.buffer.add_image(valid_png, pin=True)
        img_id = img_res["item"]["item_id"]
        img_path = self.buffer.get_image_path(img_id)

        # Add 3 unpinned items
        self.buffer.add_text("Unpinned 1")
        self.buffer.add_text("Unpinned 2")

        self.assertEqual(len(self.buffer.list_items()), 3)

        # Clear unpinned only
        clear_res = self.buffer.clear(unpinned_only=True)
        self.assertTrue(clear_res["success"])
        self.assertEqual(clear_res["cleared_count"], 2)
        self.assertEqual(len(self.buffer.list_items()), 1)
        self.assertEqual(self.buffer.list_items()[0]["item_id"], img_id)
        self.assertTrue(img_path.is_file())

        # Full clear removes everything
        full_clear_res = self.buffer.clear(unpinned_only=False)
        self.assertTrue(full_clear_res["success"])
        self.assertEqual(len(self.buffer.list_items()), 0)
        self.assertFalse(img_path.exists())

    def test_10_sha256_deduplication_and_echo_suppression(self) -> None:
        """Duplicate content updates timestamp and moves to index 0 without creating duplicates."""
        text = "Identical Clipboard Text"
        res1 = self.buffer.add_text(text, source_device_id="phone_1")
        self.assertFalse(res1["deduplicated"])
        item_id1 = res1["item"]["item_id"]

        self.buffer.add_text("Different item")
        self.assertEqual(self.buffer.list_items()[1]["item_id"], item_id1)

        # Add identical text again
        res2 = self.buffer.add_text(text, source_device_id="desktop_windows")
        self.assertTrue(res2["deduplicated"])
        self.assertEqual(res2["status"], "DEDUPLICATED")
        self.assertEqual(len(self.buffer.list_items()), 2)
        # Now at index 0
        self.assertEqual(self.buffer.list_items()[0]["item_id"], item_id1)

        # Echo-loop tracking
        digest = res1["item"]["sha256"]
        self.assertTrue(self.buffer.has_device_received(digest, "phone_1"))
        self.assertTrue(self.buffer.has_device_received(digest, "desktop_windows"))
        self.assertFalse(self.buffer.has_device_received(digest, "tablet_android"))

    def test_11_metadata_omits_raw_secrets_and_paths(self) -> None:
        """Safe metadata avoids exposing full text payloads or internal disk paths."""
        secret_text = "PRIVATE_AUTH_TOKEN_BEARER_XYZ"
        res = self.buffer.add_text(secret_text)
        meta = res["item"]
        self.assertNotIn("text_content", meta)
        self.assertNotIn("PRIVATE_AUTH_TOKEN_BEARER_XYZ", meta.get("image_path", ""))

        # Detail query includes text
        detail = self.buffer.get_item(meta["item_id"], include_content=True)
        self.assertEqual(detail["text_content"], secret_text)


# =============================================================================
# Phase 26B Integration Tests: CapabilityEngine, Policy, Endpoints, Apps
# =============================================================================

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from snow.capabilities.engine import (
    CapabilityEngine,
    CapabilityRequest,
    CapabilityResponse,
)
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.web.server import SnowWebServer


class TestClipboardEngineAndPolicyIntegration(unittest.IsolatedAsyncioTestCase):
    """Test suite for Layer 2 CapabilityEngine clipboard buffer integration and security policies."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_engine_cb_")
        self.buffer = ClipboardRingBuffer(storage_dir=self.temp_dir)
        self.mock_clipboard = MagicMock()
        self.mock_clipboard.set_clipboard = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        self.mock_clipboard.set_image_sync = MagicMock(return_value={"success": True, "status": "SUCCESS"})

        self.engine = CapabilityEngine(
            clipboard=self.mock_clipboard,
            clipboard_buffer=self.buffer,
        )

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def test_01_owner_manual_full_crud_lifecycle(self) -> None:
        """OWNER_MANUAL principal can perform add, list, pin, unpin, apply, delete, and clear."""
        owner_ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="test_owner")

        # 1. Add text
        add_req = CapabilityRequest(action="clipboard_buffer_add", params={"text": "Hello Owner Buffer"})
        add_res = await self.engine.execute(add_req, ctx=owner_ctx)
        self.assertTrue(add_res.success)
        self.assertEqual(add_res.status, "SUCCESS")
        item_id = add_res.data["item"]["item_id"]

        # 2. List
        list_req = CapabilityRequest(action="clipboard_buffer_list", params={"limit": 10})
        list_res = await self.engine.execute(list_req, ctx=owner_ctx)
        self.assertTrue(list_res.success)
        self.assertEqual(list_res.data["count"], 1)

        # 3. Pin
        pin_req = CapabilityRequest(action="clipboard_buffer_pin", params={"item_id": item_id})
        pin_res = await self.engine.execute(pin_req, ctx=owner_ctx)
        self.assertTrue(pin_res.success)
        self.assertTrue(pin_res.data["item"]["is_pinned"])

        # 4. Unpin
        unpin_req = CapabilityRequest(action="clipboard_buffer_unpin", params={"item_id": item_id})
        unpin_res = await self.engine.execute(unpin_req, ctx=owner_ctx)
        self.assertTrue(unpin_res.success)
        self.assertFalse(unpin_res.data["item"]["is_pinned"])

        # 5. Apply (PC)
        apply_req = CapabilityRequest(action="clipboard_buffer_apply", params={"item_id": item_id, "target": "pc"})
        apply_res = await self.engine.execute(apply_req, ctx=owner_ctx)
        self.assertTrue(apply_res.success)
        self.mock_clipboard.set_clipboard.assert_awaited_with(text="Hello Owner Buffer")

        # 6. Delete
        del_req = CapabilityRequest(action="clipboard_buffer_delete", params={"item_id": item_id})
        del_res = await self.engine.execute(del_req, ctx=owner_ctx)
        self.assertTrue(del_res.success)

        # 7. Clear
        clear_req = CapabilityRequest(action="clipboard_buffer_clear", params={})
        clear_res = await self.engine.execute(clear_req, ctx=owner_ctx)
        self.assertTrue(clear_res.success)

    async def test_02_ai_mcp_policy_restrictions(self) -> None:
        """AI_MCP principal can list, but delete and clear are strictly denied with POLICY_DENIED."""
        ai_ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="test_ai")

        # List is allowed
        list_req = CapabilityRequest(action="clipboard_buffer_list", params={})
        list_res = await self.engine.execute(list_req, ctx=ai_ctx)
        self.assertTrue(list_res.success)

        # Delete is denied
        del_req = CapabilityRequest(action="clipboard_buffer_delete", params={"item_id": "fake_id"})
        del_res = await self.engine.execute(del_req, ctx=ai_ctx)
        self.assertFalse(del_res.success)
        self.assertEqual(del_res.status, "POLICY_DENIED")

        # Clear is denied
        clear_req = CapabilityRequest(action="clipboard_buffer_clear", params={})
        clear_res = await self.engine.execute(clear_req, ctx=ai_ctx)
        self.assertFalse(clear_res.success)
        self.assertEqual(clear_res.status, "POLICY_DENIED")


class TestDashboardClipboardAndAppsEndpoints(AioHTTPTestCase):
    """Test suite for Web Dashboard clipboard buffer and remote app endpoints."""

    async def get_application(self) -> web.Application:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_web_cb_")
        self.bridge = MagicMock()
        self.bridge.port = 8767
        self.bridge.windows_system_info = AsyncMock(return_value={"success": True, "data": {}})
        self.bridge.list_devices = AsyncMock(return_value={"success": True, "data": {"devices": []}})
        self.bridge.call = AsyncMock(side_effect=self._mock_bridge_call)
        self.bridge.windows_launch_app = AsyncMock(return_value={"success": True, "status": "LAUNCHED", "app_name": "notepad"})
        self.bridge.android_list_apps = AsyncMock(return_value={"success": True, "apps": [{"app_name": "Camera", "package_name": "com.android.camera"}]})
        self.bridge.android_launch_app = AsyncMock(return_value={"success": True, "status": "LAUNCHED", "package_name": "com.android.camera"})

        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.bridge,
            auto_open_browser=False,
        )
        return self.web_server._build_app()

    async def _mock_bridge_call(self, op: str, payload: dict = None) -> dict:
        payload = payload or {}
        if op == "clipboard_buffer_list":
            return {"success": True, "status": "SUCCESS", "items": [{"item_id": "test_1", "type": "text", "preview_text": "sample"}]}
        if op == "clipboard_buffer_add":
            return {"success": True, "status": "SUCCESS", "item": {"item_id": "test_2", "type": "text"}}
        if op == "clipboard_buffer_pin":
            return {"success": True, "status": "SUCCESS", "item": {"item_id": payload.get("item_id"), "is_pinned": True}}
        if op == "clipboard_buffer_unpin":
            return {"success": True, "status": "SUCCESS", "item": {"item_id": payload.get("item_id"), "is_pinned": False}}
        if op == "clipboard_buffer_delete":
            return {"success": True, "status": "SUCCESS", "deleted": True}
        if op == "clipboard_buffer_clear":
            return {"success": True, "status": "SUCCESS", "cleared_count": 1}
        if op == "clipboard_buffer_apply":
            return {"success": True, "status": "SUCCESS", "applied": True}
        if op == "clipboard_capture_pc":
            return {"success": True, "status": "SUCCESS", "item": {"item_id": "test_cap"}}
        if op == "clipboard_pull_from_phone":
            return {"success": True, "status": "SUCCESS", "item": {"item_id": "test_pull"}}
        return {"success": True, "status": "SUCCESS"}

    async def tearDownAsync(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _authenticate_session(self) -> str:
        token = self.web_server.bootstrap_token
        resp = await self.client.post("/api/auth/session", json={"token": token})
        data = await resp.json()
        return data["csrf_token"]

    @unittest_run_loop
    async def test_01_clipboard_buffer_list_endpoint(self):
        """GET /api/clipboard/buffer returns items list when authenticated."""
        await self._authenticate_session()
        resp = await self.client.get("/api/clipboard/buffer")
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(len(data["items"]), 1)

    @unittest_run_loop
    async def test_02_clipboard_buffer_add_with_csrf(self):
        """POST /api/clipboard/buffer/add succeeds with valid CSRF."""
        csrf = await self._authenticate_session()
        resp = await self.client.post(
            "/api/clipboard/buffer/add",
            json={"text": "New Item"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        self.assertTrue(data["success"])

    @unittest_run_loop
    async def test_03_csrf_rejection_on_mutating_requests(self):
        """POST requests without valid CSRF return 403."""
        await self._authenticate_session()
        resp = await self.client.post("/api/clipboard/buffer/add", json={"text": "Bad"})
        self.assertEqual(resp.status, 403)

    @unittest_run_loop
    async def test_04_windows_apps_endpoints(self):
        """GET /api/apps/windows returns allowlisted apps; rejects shell binaries; POST launches."""
        csrf = await self._authenticate_session()
        get_resp = await self.client.get("/api/apps/windows")
        self.assertEqual(get_resp.status, 200)
        data = await get_resp.json()
        self.assertIn("notepad", data["apps"])
        self.assertIn("calc", data["apps"])
        # Shell binaries must NOT appear in allowed remote apps list
        self.assertNotIn("powershell", data["apps"])
        self.assertNotIn("cmd", data["apps"])
        self.assertNotIn("wt", data["apps"])

        launch_resp = await self.client.post(
            "/api/apps/windows/launch",
            json={"app_name": "notepad"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(launch_resp.status, 200)
        l_data = await launch_resp.json()
        self.assertTrue(l_data["success"])

        # Attempting to launch shell executable must be rejected with 403
        bad_launch = await self.client.post(
            "/api/apps/windows/launch",
            json={"app_name": "powershell"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(bad_launch.status, 403)
        b_data = await bad_launch.json()
        self.assertFalse(b_data["success"])
        self.assertEqual(b_data.get("status"), "FORBIDDEN")

    @unittest_run_loop
    async def test_05_android_apps_endpoints(self):
        """GET /api/apps/android and POST /api/apps/android/launch route to bridge."""
        csrf = await self._authenticate_session()
        list_resp = await self.client.get("/api/apps/android")
        self.assertEqual(list_resp.status, 200)
        data = await list_resp.json()
        self.assertEqual(len(data["apps"]), 1)

        launch_resp = await self.client.post(
            "/api/apps/android/launch",
            json={"package_name": "com.android.camera"},
            headers={"X-CSRF-Token": csrf},
        )
        self.assertEqual(launch_resp.status, 200)
        l_data = await launch_resp.json()
        self.assertTrue(l_data["success"])


class TestRealBufferIpcAndWssIntegration(unittest.IsolatedAsyncioTestCase):
    """Direct integration test suite exercising real ClipboardRingBuffer with IPC and WSS handlers."""

    async def asyncSetUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp(prefix="snow_test_real_buf_")
        self.buffer = ClipboardRingBuffer(storage_dir=self.temp_dir)
        self.engine = MagicMock()
        self.engine.clipboard_buffer = self.buffer
        self.engine.clipboard = MagicMock()
        self.engine.transfer_manager = MagicMock()

        # Create IPC server with real buffer
        from snow.core.ipc import SnowIpcServer
        self.config = CoreConfig(ipc_secret_path=str(Path(self.temp_dir) / "ipc.secret"))
        self.ipc_server = SnowIpcServer(core_server=None, config=self.config)
        self.ipc_server.capability_engine = self.engine

    async def asyncTearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    async def _send_ipc(self, op: str, payload: dict = None, request_id: str = "req_1") -> dict:
        req = {
            "version": 1,
            "request_id": request_id,
            "op": op,
            "payload": payload or {},
            "auth_token": self.ipc_server.secret,
        }
        resp, _ = await self.ipc_server._dispatch_request(req, is_connection_authenticated=True)
        return resp

    async def test_01_real_buffer_clipboard_capture_pc_text(self) -> None:
        """IPC clipboard_capture_pc ingests text into real ClipboardRingBuffer."""
        self.engine.clipboard.get_content_sync.return_value = {
            "success": True,
            "type": "text",
            "text": "Captured desktop snippet via real buffer",
        }
        resp = await self._send_ipc("clipboard_capture_pc", {}, "req_1")
        self.assertTrue(resp["success"])
        self.assertEqual(resp["status"], "SUCCESS")
        item = resp["data"]["item"]
        self.assertEqual(item["source_device"], "pc")

        # Verify real buffer state
        items = self.buffer.list_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["preview_text"], "Captured desktop snippet via real buffer")

    async def test_02_real_buffer_clipboard_capture_pc_image(self) -> None:
        """IPC clipboard_capture_pc ingests image into real ClipboardRingBuffer."""
        fake_img_path = Path(self.temp_dir) / "temp_shot.png"
        fake_png_bytes = PNG_SIGNATURE + os.urandom(64)
        with open(fake_img_path, "wb") as f:
            f.write(fake_png_bytes)

        self.engine.clipboard.get_content_sync.return_value = {
            "success": True,
            "type": "image",
            "file_path": str(fake_img_path),
        }
        resp = await self._send_ipc("clipboard_capture_pc", {}, "req_2")
        self.assertTrue(resp["success"])
        item = resp["data"]["item"]
        self.assertEqual(item["type"], "image")

        items = self.buffer.list_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["type"], "image")

    async def test_03_real_buffer_clipboard_pull_from_phone(self) -> None:
        """IPC clipboard_pull_from_phone ingests phone text into real buffer."""
        self.ipc_server._handle_device_request = AsyncMock(return_value={
            "success": True,
            "status": "SUCCESS",
            "data": {"text": "Pulled text from phone"},
        })
        resp = await self._send_ipc("clipboard_pull_from_phone", {"device_id": "phone_node_1"}, "req_3")
        self.assertTrue(resp["success"])
        self.assertEqual(resp["data"]["text"], "Pulled text from phone")

        items = self.buffer.list_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["source_device"], "phone_node_1")

    async def test_04_real_buffer_clipboard_push_to_phone_text(self) -> None:
        """IPC clipboard_push_to_phone dispatches item text from real buffer."""
        add_res = self.buffer.add_text("Pushable text content", source_device="pc")
        item_id = add_res["item"]["item_id"]

        self.ipc_server._handle_device_request = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        resp = await self._send_ipc(
            "clipboard_push_to_phone",
            {"device_id": "phone_node_1", "item_id": item_id},
            "req_4",
        )
        self.assertTrue(resp["success"])
        call_arg = self.ipc_server._handle_device_request.call_args[0][0]
        self.assertEqual(call_arg["data"]["text"], "Pushable text content")

    async def test_05_real_buffer_clipboard_push_to_phone_image_staging(self) -> None:
        """IPC clipboard_push_to_phone stages image transfer through transfer manager."""
        add_res = self.buffer.add_image(PNG_SIGNATURE + os.urandom(128), source_device="pc")
        item_id = add_res["item"]["item_id"]

        mock_tm = MagicMock()
        mock_record = MagicMock()
        mock_record.transfer_id = "test_trans_img_001"
        mock_tm.create_transfer.return_value = mock_record
        self.engine.transfer_manager = mock_tm

        self.ipc_server._handle_device_request = AsyncMock(return_value={"success": True, "status": "SUCCESS"})
        resp = await self._send_ipc(
            "clipboard_push_to_phone",
            {"device_id": "phone_node_1", "item_id": item_id},
            "req_5",
        )
        self.assertTrue(resp["success"])
        call_arg = self.ipc_server._handle_device_request.call_args[0][0]
        self.assertEqual(call_arg["data"]["type"], "image")
        self.assertEqual(call_arg["data"]["transfer_id"], "test_trans_img_001")

    async def test_06_real_buffer_ipc_get_metadata_only(self) -> None:
        """IPC clipboard_buffer_get returns metadata without raw image bytes."""
        add_res = self.buffer.add_image(PNG_SIGNATURE + os.urandom(100), source_device="pc")
        item_id = add_res["item"]["item_id"]

        resp = await self._send_ipc("clipboard_buffer_get", {"item_id": item_id}, "req_6")
        self.assertTrue(resp["success"])
        item = resp["data"]["item"]
        self.assertEqual(item["item_id"], item_id)
        self.assertIn("sha256", item)
        self.assertNotIn("text_content", item)
        self.assertNotIn("image_bytes", item)

    async def test_07_real_buffer_wss_add_and_get_handler(self) -> None:
        """WSS _handle_clipboard_buffer_add and _handle_clipboard_buffer_get with real buffer."""
        from snow.network.ws_server import SnowWebSocketServer
        from snow.protocol.models import SnowMessage

        ws_server = SnowWebSocketServer.__new__(SnowWebSocketServer)
        ws_server.clipboard_buffer = self.buffer

        mock_client = MagicMock()
        mock_client.websocket = AsyncMock()

        # 1. Add text via WSS
        add_msg = SnowMessage.create_request("clipboard_buffer_add", {"text": "WSS buffer entry text"})
        await ws_server._handle_clipboard_buffer_add(mock_client, add_msg, add_msg.data, None)

        sent_json = mock_client.websocket.send.call_args[0][0]
        sent_data = json.loads(sent_json)
        self.assertTrue(sent_data.get("success", True))
        item_id = sent_data["payload"]["item"]["item_id"]

        # 2. Get full text via WSS clipboard_buffer_get
        get_msg = SnowMessage.create_request("clipboard_buffer_get", {"item_id": item_id})
        await ws_server._handle_clipboard_buffer_get(mock_client, get_msg, get_msg.data, None)

        sent_get_json = mock_client.websocket.send.call_args[0][0]
        sent_get_data = json.loads(sent_get_json)
        self.assertEqual(sent_get_data["payload"]["text_content"], "WSS buffer entry text")
        self.assertEqual(sent_get_data["payload"]["item_id"], item_id)


class TestCrossProcessClipboardImageEndpoint(AioHTTPTestCase):
    """Integration test verifying GET /api/clipboard/image/{item_id} across process boundaries."""

    async def get_application(self) -> web.Application:
        self.temp_storage = tempfile.mkdtemp(prefix="snow_test_cross_img_")
        self.buffer = ClipboardRingBuffer(storage_dir=self.temp_storage)

        # Bridge mock simulating authenticated loopback IPC client to Core daemon
        self.bridge = MagicMock()
        self.bridge.port = 8767
        self.bridge.call = AsyncMock(side_effect=self._mock_ipc_call)

        self.web_server = SnowWebServer(
            host="127.0.0.1",
            port=8769,
            bridge=self.bridge,
            auto_open_browser=False,
        )
        return self.web_server._build_app()

    async def tearDownAsync(self) -> None:
        shutil.rmtree(self.temp_storage, ignore_errors=True)
        await super().tearDownAsync()

    async def _mock_ipc_call(self, op: str, payload: dict = None) -> dict:
        payload = payload or {}
        if op == "clipboard_buffer_get":
            item_id = payload.get("item_id", "")
            import re
            if not re.match(r"^cb_[0-9a-f]{12}_[0-9a-f]{6}$", item_id):
                return {"success": False, "status": "INVALID_ARGUMENT", "error": "Invalid item ID"}
            item = self.buffer.get_item(item_id, include_content=False)
            if not item:
                return {"success": False, "status": "NOT_FOUND", "error": "Item not found"}
            return {"success": True, "status": "SUCCESS", "data": {"item": item}}
        return {"success": False, "error": "Unknown op"}

    async def _authenticate_session(self) -> str:
        resp = await self.client.post("/api/auth/session", json={"token": self.web_server.bootstrap_token})
        self.assertEqual(resp.status, 200)
        data = await resp.json()
        return data["csrf_token"]

    @unittest_run_loop
    async def test_cross_process_image_retrieval_success_and_failures(self) -> None:
        """Verify image retrieval: HTTP 200 PNG bytes, 401 unauth, 400 invalid ID, 404 unknown ID."""
        # 1. Add valid PNG image to real buffer
        png_data = PNG_SIGNATURE + os.urandom(256)
        add_res = self.buffer.add_image(png_data, mime_type="image/png", source_device="pc")
        item_id = add_res["item"]["item_id"]

        # 2. Unauthenticated request returns 401
        unauth_resp = await self.client.get(f"/api/clipboard/image/{item_id}")
        self.assertEqual(unauth_resp.status, 401)

        # Authenticate session
        await self._authenticate_session()

        # 3. Invalid item ID format returns 400
        bad_id_resp = await self.client.get("/api/clipboard/image/invalid_id_123")
        self.assertEqual(bad_id_resp.status, 400)

        # 4. Unknown valid-format item ID returns 404
        unknown_resp = await self.client.get("/api/clipboard/image/cb_112233445566_778899")
        self.assertEqual(unknown_resp.status, 404)

        # Patch get_default_clipboard_storage_dir to point to our test storage
        with patch("snow.capabilities.clipboard_buffer.get_default_clipboard_storage_dir", return_value=Path(self.temp_storage)):
            # 5. Valid request returns 200 and PNG bytes
            ok_resp = await self.client.get(f"/api/clipboard/image/{item_id}")
            self.assertEqual(ok_resp.status, 200)
            self.assertEqual(ok_resp.content_type, "image/png")
            body = await ok_resp.read()
            self.assertTrue(body.startswith(PNG_SIGNATURE))


class TestMcpClipboardBufferTools(unittest.IsolatedAsyncioTestCase):
    """Test FastMCP tool integration for all 37 tools including Phase 26B shared clipboard buffer."""

    async def test_clipboard_buffer_metadata_and_annotations(self) -> None:
        """Verify strict boolean ToolAnnotations and metadata attributes for buffer capabilities."""
        self.assertEqual(len(CLIPBOARD_BUFFER_CAPABILITIES), 3)
        for name in ["snow_clipboard_buffer_list", "snow_clipboard_buffer_add", "snow_clipboard_buffer_apply"]:
            meta = get_capability_metadata(name)
            self.assertIsNotNone(meta, f"Missing metadata for {name}")
            self.assertIsInstance(meta.read_only_hint, bool)
            self.assertIsInstance(meta.destructive_hint, bool)
            self.assertIsInstance(meta.requires_approval, bool)
            self.assertEqual(meta.os_classification, "cross_platform")

            ann = get_mcp_annotations(name)
            self.assertIsNotNone(ann, f"Missing ToolAnnotations for {name}")
            self.assertIs(type(ann.readOnlyHint), bool)
            self.assertIs(type(ann.destructiveHint), bool)

        # Destructive operations are not exposed to AI_MCP
        self.assertIsNone(get_capability_metadata("snow_clipboard_buffer_delete"))
        self.assertIsNone(get_capability_metadata("snow_clipboard_buffer_clear"))

    async def test_all_37_tools_registered_in_server(self) -> None:
        """Verify official FastMCP server registers all tools."""
        from snow.mcp.server import create_snow_mcp_server

        server = create_snow_mcp_server()
        tools = await server.list_tools()
        self.assertGreaterEqual(len(tools), 37)
        tool_names = [t.name for t in tools]
        self.assertEqual(len(set(tool_names)), len(tools))

        # Verify new clipboard tools are present
        self.assertIn("snow_clipboard_buffer_list", tool_names)
        self.assertIn("snow_clipboard_buffer_add", tool_names)
        self.assertIn("snow_clipboard_buffer_apply", tool_names)

        # Verify baseline tools are preserved
        self.assertIn("snow_windows_system_info", tool_names)
        self.assertIn("snow_android_screenshot", tool_names)
        self.assertIn("snow_workflow_run", tool_names)


class TestAndroidTargetResolution(unittest.IsolatedAsyncioTestCase):
    """Regression test suite for Android device target auto-resolution and security boundaries."""

    async def asyncSetUp(self) -> None:
        from snow.mcp.bridge import SnowMcpBridge
        self.bridge = SnowMcpBridge(auto_start_core=False)
        self.windows_node = {
            "device_id": "desktop-core",
            "device_name": "Lenovo V15",
            "platform": "windows",
            "is_local": True,
            "transport": "local",
            "is_connected": True,
            "is_paired": True,
        }
        self.realme_phone = {
            "device_id": "dev_realme_rmx5110",
            "device_name": "Realme RMX5110",
            "platform": "android",
            "is_local": False,
            "transport": "wifi_lan",
            "is_connected": True,
            "is_paired": True,
        }
        self.second_phone = {
            "device_id": "dev_pixel_9",
            "device_name": "Pixel 9 Pro",
            "platform": "android",
            "is_local": False,
            "transport": "wifi_lan",
            "is_connected": True,
            "is_paired": True,
        }

    async def test_single_android_with_local_windows_auto_resolves(self) -> None:
        """One local Windows node and one connected Android peer -> resolves to Android peer."""
        self.bridge.list_devices = AsyncMock(return_value={
            "success": True,
            "data": {"devices": [self.windows_node, self.realme_phone]},
        })
        self.bridge.send_device_request = AsyncMock(return_value={
            "success": True,
            "data": {"apps": [{"name": "Calculator", "package": "com.android.calculator2"}]},
        })

        res = await self.bridge.android_list_apps(device_id="")
        self.assertTrue(res.get("success"), f"Failed: {res}")
        self.bridge.send_device_request.assert_called_once_with(
            "dev_realme_rmx5110", "list_apps", {"limit": 50}
        )

    async def test_dual_android_with_no_target_returns_device_required(self) -> None:
        """Two connected Android peers with empty device_id -> structured DEVICE_REQUIRED."""
        self.bridge.list_devices = AsyncMock(return_value={
            "success": True,
            "data": {"devices": [self.windows_node, self.realme_phone, self.second_phone]},
        })
        self.bridge.send_device_request = AsyncMock()

        res = await self.bridge.android_list_apps(device_id="")
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "DEVICE_REQUIRED")
        self.assertIn("Multiple android devices available", res.get("error", ""))
        available = res.get("data", {}).get("available_devices", [])
        self.assertEqual(len(available), 2)
        dev_ids = [d["device_id"] for d in available]
        self.assertIn("dev_realme_rmx5110", dev_ids)
        self.assertIn("dev_pixel_9", dev_ids)
        self.assertNotIn("desktop-core", dev_ids)
        self.bridge.send_device_request.assert_not_called()

    async def test_explicit_android_device_id_selects_exact_node(self) -> None:
        """Explicit Android device_id selects that exact node among multiple devices."""
        self.bridge.list_devices = AsyncMock(return_value={
            "success": True,
            "data": {"devices": [self.windows_node, self.realme_phone, self.second_phone]},
        })
        self.bridge.send_device_request = AsyncMock(return_value={"success": True, "data": {"apps": []}})

        res = await self.bridge.android_list_apps(device_id="dev_pixel_9")
        self.assertTrue(res.get("success"))
        self.bridge.send_device_request.assert_called_once_with(
            "dev_pixel_9", "list_apps", {"limit": 50}
        )

    async def test_local_windows_node_never_selected_for_android_operations(self) -> None:
        """Explicitly targeting Windows host for Android operations is rejected."""
        self.bridge.list_devices = AsyncMock(return_value={
            "success": True,
            "data": {"devices": [self.windows_node, self.realme_phone]},
        })
        self.bridge.send_device_request = AsyncMock()

        # Try targeting local by ID
        res = await self.bridge.android_list_apps(device_id="desktop-core")
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "DEVICE_NOT_FOUND")
        self.bridge.send_device_request.assert_not_called()

        # Try targeting local by name
        res2 = await self.bridge.android_list_apps(device_id="Lenovo V15")
        self.assertFalse(res2.get("success"))
        self.assertEqual(res2.get("status"), "DEVICE_NOT_FOUND")
        self.bridge.send_device_request.assert_not_called()

    def test_direct_resolve_target_device_rules(self) -> None:
        """Verify resolve_target_device core rules for Android platform targeting."""
        from snow.mcp.bridge import resolve_target_device
        devices = [self.windows_node, self.realme_phone]

        # Empty target with platform="android" excludes Windows node
        target, err = resolve_target_device(devices, "", platform="android")
        self.assertEqual(target, "dev_realme_rmx5110")
        self.assertIsNone(err)

        # Explicit Windows ID with platform="android" is rejected
        target, err = resolve_target_device(devices, "desktop-core", platform="android")
        self.assertIsNone(target)
        self.assertIsNotNone(err)
        self.assertEqual(err.get("status"), "DEVICE_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()
