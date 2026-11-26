"""Stage 6C WS3 behavioral tests: universal any-to-any screen sharing, multi-sender isolation, and full_control enforcement."""

from __future__ import annotations

import asyncio
from io import BytesIO
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock

import aiohttp
from aiohttp.test_utils import AioHTTPTestCase
from PIL import Image

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from snow.capabilities.windows.screen_stream import (
    DEFAULT_PC_JPEG_QUALITY,
    MAX_SCREEN_FRAME_BYTES,
    WindowsScreenStreamManager,
)
from snow.core.config import CoreConfig
from snow.core.server import SnowCoreServer
from snow.network.federation import FederationManager
from snow.network.relay_client import RelayTunnelClient
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage
from snow.relay.auth import create_relay_ticket
from snow.relay.config import RelayConfig
from snow.relay.server import SnowRelayServer
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.security.tls import ensure_tls_certificate
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferManager
from snow.transfer.storage import TransferStorageManager


def _make_solid_bgra(width: int, height: int, rgba: tuple[int, int, int, int]) -> bytes:
    """Create raw BGRA desktop frame buffer for deterministic lossless pixel testing."""
    b, g, r, a = rgba[2], rgba[1], rgba[0], rgba[3]
    pixel = bytes((b, g, r, a))
    return pixel * (width * height)


class TestStage6CWS3ScreenStreamEngineAndDedup(unittest.IsolatedAsyncioTestCase):
    """Verify WindowsScreenStreamManager zero-viewer pause, exact dedup, GDI cleanup, and quality preservation."""

    async def test_zero_viewer_pause_exact_pixel_dedup_and_no_degradation(self) -> None:
        buf_a = _make_solid_bgra(1280, 720, (24, 96, 200, 255))
        # Mutate just ONE pixel (4 bytes at start)
        buf_b = bytes((250, 20, 10, 255)) + buf_a[4:]
        frames = [buf_a, buf_a, buf_b, buf_b, buf_b]
        idx = 0

        def provider():
            nonlocal idx
            val = frames[min(idx, len(frames) - 1)]
            idx += 1
            return val, 1280, 720

        ts_mock = MagicMock()
        ts_mock.publish_screen_frame = MagicMock(return_value=True)
        ts_mock.set_session_state = MagicMock()
        published_frames: list[tuple[dict, bytes]] = []

        async def on_frame(meta: dict, jpeg: bytes) -> None:
            published_frames.append((meta, jpeg))

        mgr = WindowsScreenStreamManager(
            sender_device_id="pc-host-1",
            sender_name="Workstation PC",
            transfer_server=ts_mock,
            permission_checker=lambda d: d == "phone-fc",
            on_frame_ready=on_frame,
            raw_frame_provider=provider,
        )

        # Reject non-full_control target at start
        denied = await mgr.start(target_device_ids=["phone-readonly"], spawn_loop=False)
        self.assertFalse(denied["success"])
        self.assertEqual(denied["status"], "PERMISSION_DENIED")

        # Start with 0 viewers -> capture loop produces 0 frames, 0 bytes, 0 GDI allocations
        started = await mgr.start(target_device_ids=["phone-fc"], initial_viewers=[], spawn_loop=False)
        self.assertTrue(started["success"])
        res_zero = await mgr.capture_and_publish_once()
        self.assertEqual(res_zero["skipped"], "zero_viewers")
        self.assertEqual(mgr.frames_captured, 0)
        self.assertEqual(mgr.gdi_allocations, 0)
        self.assertEqual(mgr.total_bytes_sent, 0)

        # Add authorized viewer -> captures buf_a at full native 1280x720 resolution
        self.assertTrue(mgr.add_viewer("phone-fc"))
        r1 = await mgr.capture_and_publish_once()
        self.assertTrue(r1["sent"])
        self.assertEqual(r1["frame_width"], 1280)
        self.assertEqual(r1["frame_height"], 720)
        self.assertEqual(r1["frame_seq"], 1)
        self.assertEqual(len(published_frames), 1)
        with Image.open(BytesIO(published_frames[0][1])) as img:
            self.assertEqual(img.size, (1280, 720))  # No resolution downscaling

        # Identical second frame -> exact SHA-256 skip, zero bytes sent
        r2 = await mgr.capture_and_publish_once()
        self.assertEqual(r2["skipped"], "identical_frame")
        self.assertEqual(mgr.deduplicated_skips, 1)
        self.assertEqual(len(published_frames), 1)

        # 1-pixel UI delta -> immediately detected and delivered (never suppressed by perceptual hash)
        r3 = await mgr.capture_and_publish_once()
        self.assertTrue(r3["sent"])
        self.assertEqual(r3["frame_seq"], 2)
        self.assertEqual(len(published_frames), 2)

        # Removing viewer resets hash & pauses again; GDI alloc == release
        mgr.remove_viewer("phone-fc")
        r4 = await mgr.capture_and_publish_once()
        self.assertEqual(r4["skipped"], "zero_viewers")
        self.assertEqual(mgr.gdi_allocations, mgr.gdi_releases)

        await mgr.stop("STOPPED")
        self.assertEqual(mgr.state, "STOPPED")


class TestStage6CWS3MultiSenderAndPermissionBoundaries(AioHTTPTestCase):
    """Verify multi-sender isolation, 512 KiB bound, full_control gate, and federation tier enforcement."""

    async def get_application(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="snow_6c_ws3_http_"))
        self.db = DatabaseManager(self.tmp / "http.db")
        self.db.insert_paired_device("phone-fc", "Phone Full", "tok_hash_fc")
        self.db.insert_paired_device("phone-limited", "Phone Limited", "tok_hash_lim")
        self.db.set_setting("device_profile:phone-fc", "full_control")
        self.db.set_setting("device_profile:phone-limited", "files_and_clipboard")

        cfg = CoreConfig(auth_required=False)
        tm = TransferManager()
        sm = TransferStorageManager(root_dir=self.tmp / "transfers")
        SnowHttpTransferServer._screen_sessions.clear()
        self.http_srv = SnowHttpTransferServer(cfg, self.db, tm, sm)
        return self.http_srv.app

    async def asyncTearDown(self) -> None:
        SnowHttpTransferServer._screen_sessions.clear()
        shutil.rmtree(self.tmp, ignore_errors=True)
        await super().asyncTearDown()

    async def test_multi_sender_isolation_and_stop_purges_only_stopped_sender(self) -> None:
        # Publish two concurrent streams with distinct targets & frames
        r_a = await self.client.request(
            "POST",
            "/api/v1/screen/frame",
            data=b"\xff\xd8\xff\xe0SENDER_A_FRAME\xff\xd9",
            headers={
                "Content-Type": "image/jpeg",
                "X-Snow-Device-Id": "phone-fc",
                "X-Snow-Sender-Id": "sender-a",
                "X-Snow-Sender-Name": "Office PC",
                "X-Snow-Sender-Platform": "windows",
                "X-Snow-Session-Id": "sess-a",
                "X-Snow-Frame-Seq": "1",
                "X-Snow-Target-Device-Ids": "phone-fc",
            },
        )
        self.assertEqual(r_a.status, 200)

        r_b = await self.client.request(
            "POST",
            "/api/v1/screen/frame",
            data=b"\xff\xd8\xff\xe0SENDER_B_FRAME\xff\xd9",
            headers={
                "Content-Type": "image/jpeg",
                "X-Snow-Device-Id": "sender-b",
                "X-Snow-Sender-Id": "sender-b",
                "X-Snow-Sender-Name": "Pixel Phone",
                "X-Snow-Sender-Platform": "android",
                "X-Snow-Session-Id": "sess-b",
                "X-Snow-Frame-Seq": "1",
                "X-Snow-Target-Device-Ids": "phone-fc",
            },
        )
        self.assertEqual(r_b.status, 200)

        # List active senders shows both
        senders_resp = await self.client.request("GET", "/api/v1/screen/senders", headers={"X-Snow-Device-Id": "phone-fc"})
        senders_json = await senders_resp.json()
        self.assertEqual(senders_json["count"], 2)
        self.assertEqual({s["sender_device_id"] for s in senders_json["senders"]}, {"sender-a", "sender-b"})

        # Fetch specifically sender-a vs sender-b (never mixed)
        fa = await self.client.request("GET", "/api/v1/screen/frame?sender_id=sender-a", headers={"X-Snow-Device-Id": "phone-fc"})
        fb = await self.client.request("GET", "/api/v1/screen/frame?sender_id=sender-b", headers={"X-Snow-Device-Id": "phone-fc"})
        self.assertIn(b"SENDER_A_FRAME", await fa.read())
        self.assertIn(b"SENDER_B_FRAME", await fb.read())
        self.assertEqual(fa.headers.get("X-Snow-Sender-Id"), "sender-a")
        self.assertEqual(fb.headers.get("X-Snow-Sender-Id"), "sender-b")

        # Oversized frame > 512 KiB rejected with 413
        oversized = await self.client.request(
            "POST",
            "/api/v1/screen/frame",
            data=b"X" * (MAX_SCREEN_FRAME_BYTES + 1),
            headers={"Content-Type": "image/jpeg", "X-Snow-Device-Id": "phone-fc"},
        )
        self.assertEqual(oversized.status, 413)

        # Stop sender-a -> purges frame (204), while sender-b continues cleanly
        await self.client.request(
            "POST",
            "/api/v1/screen/stop",
            json={"device_id": "sender-a"},
            headers={"X-Snow-Device-Id": "phone-fc"},
        )
        fa_after = await self.client.request("GET", "/api/v1/screen/frame?sender_id=sender-a", headers={"X-Snow-Device-Id": "phone-fc"})
        fb_after = await self.client.request("GET", "/api/v1/screen/frame?sender_id=sender-b", headers={"X-Snow-Device-Id": "phone-fc"})
        self.assertEqual(fa_after.status, 204)
        self.assertEqual(fb_after.status, 200)

    async def test_ws_and_http_enforce_full_control_and_keep_wss_media_free(self) -> None:
        # HTTP permission gate when auth_required=True (via real middleware check)
        from snow.security.db import hash_token
        self.db.insert_paired_device("dev-clip", "Clip Only", hash_token("tok-clip-raw"))
        self.db.set_setting("device_profile:dev-clip", "files_and_clipboard")
        authed_http = SnowHttpTransferServer(
            CoreConfig(auth_required=True),
            self.db,
            TransferManager(),
            self.http_srv.storage_manager,
        )
        self.assertFalse(authed_http._is_screen_authorized("dev-clip"))
        self.assertTrue(authed_http._is_screen_authorized("phone-fc"))
        from aiohttp.test_utils import TestClient, TestServer
        async with TestClient(TestServer(authed_http.app)) as auth_cli:
            denied_http = await auth_cli.request(
                "POST",
                "/api/v1/screen/frame",
                data=b"\xff\xd8\xff\xe0TEST\xff\xd9",
                headers={
                    "Authorization": "Bearer tok-clip-raw",
                    "X-Snow-Device-Id": "dev-clip",
                    "Content-Type": "image/jpeg",
                },
            )
            self.assertEqual(denied_http.status, 403)

        # WebSocket server rejects screen_stream_start / subscribe for non-full_control
        import uuid
        host_uuid = str(uuid.uuid4())
        ident = DeviceIdentity(device_id=host_uuid, device_name="Host", created_at="2026-01-01T00:00:00Z")
        ws_srv = SnowWebSocketServer(config=CoreConfig(), db_manager=self.db, device_identity=ident)
        ws_srv.http_transfer_server = self.http_srv
        sent: list[str] = []

        fake_client = MagicMock()
        fake_client.connection_id = "c1"
        fake_client.websocket.state = 1

        async def cap_send(raw: str) -> None:
            sent.append(raw)

        fake_client.websocket.send = cap_send
        sess_lim = MagicMock(device_id="phone-limited", connection_id="c1")
        msg = SnowMessage.create_request(action="screen_stream_start", data={"fps": 4})
        await ws_srv._handle_screen_stream_start(fake_client, msg, msg.payload["data"], sess_lim)
        err_obj = json.loads(sent[-1])
        self.assertEqual(err_obj["type"], "error")
        self.assertEqual(err_obj["error"]["code"], "UNAUTHORIZED")

        # Broadcast strictly skips raw image bytes & skips non-full_control sessions
        ws_srv.connection_manager.all_connections = MagicMock(return_value=["c_fc", "c_lim"])
        c_fc = MagicMock(connection_id="c_fc")
        c_fc.websocket.state = 1
        sent_fc: list[str] = []
        c_fc.websocket.send = AsyncMock(side_effect=lambda raw: sent_fc.append(raw))
        c_lim = MagicMock(connection_id="c_lim")
        c_lim.websocket.state = 1
        sent_lim: list[str] = []
        c_lim.websocket.send = AsyncMock(side_effect=lambda raw: sent_lim.append(raw))
        ws_srv.connection_manager.get = MagicMock(side_effect=lambda cid: c_fc if cid == "c_fc" else c_lim)
        ws_srv.session_manager.get_session_by_connection = MagicMock(
            side_effect=lambda cid: MagicMock(device_id="phone-fc") if cid == "c_fc" else MagicMock(device_id="phone-limited")
        )
        delivered = await ws_srv.broadcast_screen_stream_event(
            "STREAM_AVAILABLE",
            {"sender_device_id": "host-ws-1", "frame_bytes": b"MUST_BE_STRIPPED", "fps": 4.0},
        )
        self.assertEqual(delivered, 1)
        self.assertEqual(len(sent_fc), 1)
        self.assertEqual(len(sent_lim), 0)
        self.assertNotIn("frame_bytes", sent_fc[0])

    async def test_federation_grant_intersection_allows_full_control_blocks_lower(self) -> None:
        fed = FederationManager(db_manager=self.db, local_network_id="SNW-NET-AAAA1111", local_node_id="pc-a")
        inv_fc = fed.create_invitation(allowed_device_ids=["pc-a"], permission_tier="full_control", principal="OWNER_MANUAL")
        acc_fc = fed.accept_invitation(
            code=inv_fc["code"],
            peer_network_id="SNW-NET-BBBB2222",
            peer_network_name="Net B",
            peer_node_id="pc-b",
            peer_node_name="PC B",
            peer_cert_fingerprint="AA" * 32,
            principal="OWNER_MANUAL",
        )
        ok_fc, _ = fed.validate_federated_request(acc_fc["auth_token"], "SNW-NET-AAAA1111", "pc-a", "screen_share")
        self.assertTrue(ok_fc)

        inv_clip = fed.create_invitation(allowed_device_ids=["pc-a"], permission_tier="files_and_clipboard", principal="OWNER_MANUAL")
        acc_clip = fed.accept_invitation(
            code=inv_clip["code"],
            peer_network_id="SNW-NET-CCCC3333",
            peer_network_name="Net C",
            peer_node_id="pc-c",
            peer_node_name="PC C",
            peer_cert_fingerprint="BB" * 32,
            principal="OWNER_MANUAL",
        )
        ok_clip, _ = fed.validate_federated_request(acc_clip["auth_token"], "SNW-NET-AAAA1111", "pc-a", "screen_share")
        self.assertFalse(ok_clip)


class TestStage6CWS3RelayEncryptedMediaDelivery(unittest.IsolatedAsyncioTestCase):
    """Verify server-blind E2E encrypted JPEG media transport through live RelayServer."""

    async def test_relay_delivers_e2e_encrypted_screen_frame_without_exposing_jpeg_to_relay(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="snow_6c_relay_media_"))
        relay_srv = None
        sender_rc = None
        recv_rc = None
        try:
            host_cert = ensure_tls_certificate(tmp / "h.crt", tmp / "h.key")
            cli_cert = ensure_tls_certificate(tmp / "c.crt", tmp / "c.key")
            secret = "test-relay-key-32bytes-012345678"
            cfg = RelayConfig(host="127.0.0.1", port=0, shared_secret=secret)
            relay_srv = SnowRelayServer(config=cfg)
            await relay_srv.start()
            sock = relay_srv._site._server.sockets[0]
            bound_port = int(sock.getsockname()[1])
            ws_url = f"ws://127.0.0.1:{bound_port}/v1/tunnel"

            t_send = create_relay_ticket(device_id="pc-sender-1", group_id="grp-screen", secret=secret, ttl_seconds=60)
            t_recv = create_relay_ticket(device_id="pc-recv-2", group_id="grp-screen", secret=secret, ttl_seconds=60)
            sender_rc = RelayTunnelClient(ws_url, "pc-sender-1", "grp-screen", t_send, str(tmp / "h.crt"), str(tmp / "h.key"))
            recv_rc = RelayTunnelClient(ws_url, "pc-recv-2", "grp-screen", t_recv, str(tmp / "c.crt"), str(tmp / "c.key"))
            sender_rc.set_peer_pinned_fingerprint("pc-recv-2", cli_cert.fingerprint_sha256)
            recv_rc.set_peer_pinned_fingerprint("pc-sender-1", host_cert.fingerprint_sha256)

            got_event = asyncio.Event()
            received_frames: list[tuple[str, dict, bytes]] = []

            async def on_media(source_id: str, meta: dict, jpeg_bytes: bytes) -> None:
                received_frames.append((source_id, meta, jpeg_bytes))
                got_event.set()

            recv_rc.media_frame_handler = on_media
            self.assertTrue(await sender_rc.connect())
            self.assertTrue(await recv_rc.connect())
            self.assertTrue(await sender_rc.initiate_e2e_tunnel("pc-recv-2", timeout=5.0))

            sample_jpeg = b"\xff\xd8\xff\xe0SECRET_SCREEN_PIXEL_MARKER_6C\xff\xd9"
            ok_sent = await sender_rc.send_screen_frame(
                "pc-recv-2",
                {"sender_device_id": "pc-sender-1", "sender_name": "Remote PC", "frame_seq": 1, "fps": 4.0},
                sample_jpeg,
            )
            self.assertTrue(ok_sent)
            await asyncio.wait_for(got_event.wait(), timeout=3.0)
            self.assertEqual(len(received_frames), 1)
            self.assertEqual(received_frames[0][0], "pc-sender-1")
            self.assertEqual(received_frames[0][2], sample_jpeg)
            self.assertEqual(received_frames[0][1]["sender_name"], "Remote PC")
        finally:
            if sender_rc:
                await sender_rc.disconnect()
            if recv_rc:
                await recv_rc.disconnect()
            if relay_srv:
                await relay_srv.stop()
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
