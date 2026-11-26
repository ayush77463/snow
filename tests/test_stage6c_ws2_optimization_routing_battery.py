"""Stage 6C WS2 behavioral tests: zero-degradation RSS/lazy imports, route promotion, and permissions."""

from __future__ import annotations

import asyncio
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from snow.network.node import DeviceNode, ReachabilityProfile, ReachabilityState
from snow.network.registry import NodeRegistry
from snow.network.router import (
    SessionRouter,
    classify_route_priority,
    evaluate_preferred_route,
    is_action_allowed_by_profile,
)
from snow.protocol.models import SnowMessage
from snow.security.db import DatabaseManager


class TestStage6CWS2OptimizationAndRouting(unittest.IsolatedAsyncioTestCase):
    """Verify RSS budget, zero-data route preference, verified local promotion, and screen permission tier."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="snow_6c_ws2_"))
        self.db = DatabaseManager(self.tmp / "ws2.db")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_idle_core_imports_do_not_eager_load_aiohttp_or_heavy_crypto(self) -> None:
        """Fresh Python process importing CapabilityEngine + DatabaseManager stays lean (< 48 MB RSS) without aiohttp."""
        code = (
            "import sys, os, psutil; "
            "from snow.security.db import DatabaseManager; "
            "from snow.capabilities.engine import CapabilityEngine; "
            "assert 'aiohttp' not in sys.modules, 'aiohttp eagerly imported'; "
            "rss = psutil.Process(os.getpid()).memory_info().rss / (1024*1024); "
            "assert rss < 48.0, f'RSS {rss:.2f} MB >= 48 MB'; "
            "print(f'{rss:.2f}')"
        )
        proc = subprocess.run(
            [sys.executable, "-c", code],
            cwd=str(Path(__file__).resolve().parents[1]),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr} stdout={proc.stdout}")

    def test_zero_data_route_priority_hierarchy_and_mode_filters(self) -> None:
        candidates = [
            {"id": "r1", "transport": "remote_relay", "host": "snow-relay.onrender.com", "active": True},
            {"id": "w1", "transport": "wifi_lan", "host": "192.168.1.25", "active": True},
            {"id": "u1", "transport": "usb_adb", "host": "127.0.0.1", "active": True},
        ]
        chosen = evaluate_preferred_route(candidates, connection_mode="auto")
        self.assertIsNotNone(chosen)
        assert chosen is not None
        self.assertEqual(chosen["id"], "u1")
        self.assertEqual(chosen["transport_badge"], "USB • Zero Data")

        chosen_no_usb = evaluate_preferred_route(candidates[:2], connection_mode="auto")
        assert chosen_no_usb is not None
        self.assertEqual(chosen_no_usb["id"], "w1")
        self.assertEqual(chosen_no_usb["transport_badge"], "Wi-Fi • Zero Data")

        chosen_remote = evaluate_preferred_route(candidates, connection_mode="remote_only")
        assert chosen_remote is not None
        self.assertEqual(chosen_remote["id"], "r1")
        self.assertEqual(chosen_remote["transport_badge"], "Remote • Uses Data")

        self.assertIsNone(evaluate_preferred_route(candidates[:1], connection_mode="local_only"))
        self.assertLess(classify_route_priority("usb_adb", "127.0.0.1"), classify_route_priority("wifi_lan", "192.168.1.5"))
        self.assertLess(classify_route_priority("wifi_lan", "192.168.1.5"), classify_route_priority("remote_relay", "10.0.0.1"))

    def test_screen_sharing_strictly_restricted_to_full_control(self) -> None:
        for action in (
            "screen_stream_start",
            "screen_stream_stop",
            "screen_stream_status",
            "screen_stream_subscribe",
            "windows_screen_share",
            "android_screen_share",
        ):
            self.assertTrue(is_action_allowed_by_profile("full_control", action), msg=action)
            for restricted in ("files_and_clipboard", "files_only", "clipboard_only", "not_allowed"):
                self.assertFalse(is_action_allowed_by_profile(restricted, action), msg=f"{restricted}/{action}")

    async def test_promote_local_route_requires_verified_handshake_and_retains_relay_on_failure(self) -> None:
        self.db.insert_paired_device(
            device_id="phone-promo-1",
            device_name="Moto Phone",
            platform="android",
            auth_token_hash="hash123",
            cert_fingerprint="AA" * 32,
            capabilities_json='{"supported_capabilities": ["android.files.transfer", "android.telemetry.get"]}',
        )
        reg = NodeRegistry(db_manager=self.db)
        reg.set_permission_profile("phone-promo-1", "full_control")
        reg._registered_nodes["phone-promo-1"] = DeviceNode(
            device_id="phone-promo-1",
            device_name="Moto Phone",
            platform="android",
            reachability_profile=ReachabilityProfile.ACTIVE_SESSION_PEER,
            reachability_state=ReachabilityState.ONLINE_RELAYED,
            transport="remote_relay",
            host="snow-relay.onrender.com",
            permission_profile="full_control",
            supported_capabilities=["android.files.transfer", "android.telemetry.get"],
        )
        router = SessionRouter(node_registry=reg, db_manager=self.db)
        router.register_peer_token("phone-promo-1", "tok-secret")

        # 1. Fingerprint mismatch must reject promotion and preserve relay fallback
        bad_fp = await router.promote_local_route(
            device_id="phone-promo-1",
            host="192.168.1.77",
            port=8765,
            expected_fingerprint="BB" * 32,
        )
        self.assertFalse(bad_fp["promoted"])
        self.assertEqual(bad_fp["status"], "FINGERPRINT_MISMATCH")
        self.assertTrue(bad_fp["fallback_retained"])

        # 2. Failed local dial never falsely claims promoted
        failed_client = MagicMock()
        failed_client.connect = AsyncMock(return_value=MagicMock(success=False, status="TIMEOUT", error="connect timeout"))
        failed_client.close = AsyncMock()
        with patch("snow.network.router.SnowPeerClient", return_value=failed_client):
            fail_res = await router.promote_local_route(
                device_id="phone-promo-1",
                host="192.168.1.77",
                port=8765,
                expected_fingerprint="AA" * 32,
            )
        self.assertFalse(fail_res["promoted"])
        self.assertTrue(fail_res["fallback_retained"])
        self.assertNotIn("phone-promo-1", router._outbound_clients)

        # 3. Verified authenticated dial promotes route, updates node, and preserves transfer idempotency
        ok_client = MagicMock()
        ok_client.is_connected = True
        ok_client.host = "192.168.1.77"
        ok_client.connect = AsyncMock(
            return_value=MagicMock(
                success=True,
                status="AUTHENTICATED",
                remote_device_id="phone-promo-1",
                error=None,
            )
        )
        ok_client.send_message = AsyncMock(
            return_value=SnowMessage.create_response(correlation_id="c1", payload={"status": "success"})
        )
        router._record_transfer_route("phone-promo-1", "tx-keep-1", {"success": True, "status": "SUCCESS"})

        with patch("snow.network.router.SnowPeerClient", return_value=ok_client):
            promo_res = await router.promote_local_route(
                device_id="phone-promo-1",
                host="192.168.1.77",
                port=8765,
                expected_fingerprint="AA" * 32,
            )
        self.assertTrue(promo_res["promoted"])
        self.assertEqual(promo_res["transport"], "wifi_lan")
        self.assertEqual(promo_res["transport_badge"], "Wi-Fi • Zero Data")

        # Next transfer_id replay still deduplicates after promotion
        replay = await router.route_request(
            action="file_send_request",
            target="phone-promo-1",
            data={"transfer_id": "tx-keep-1", "file_name": "a.txt"},
        )
        self.assertTrue(replay.get("idempotent_replay"))
        ok_client.send_message.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
