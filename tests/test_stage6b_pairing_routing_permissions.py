"""Focused verification tests for Stage 6B WS3 (Pairing & Hybrid Routing) and WS4 (5-Tier Permissions)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import AsyncMock, MagicMock

from snow.network.federation import FEDERATION_TIER_CAPABILITIES, FederationManager
from snow.network.node import DeviceNode, ReachabilityProfile, ReachabilityState
from snow.network.registry import NodeRegistry
from snow.network.router import (
    PERMISSION_PROFILE_ORDER,
    PERMISSION_PROFILES,
    SessionRouter,
    classify_transport_badge,
    intersect_tier_categories,
    is_action_allowed_by_profile,
    is_action_allowed_by_tier_intersection,
    normalize_permission_tier,
)
from snow.network.ws_server import SnowWebSocketServer
from snow.protocol.models import SnowMessage
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.security.pairing import (
    PairingManager,
    PairingOutcome,
    create_qr_pairing_payload,
    validate_qr_pairing_payload,
)
from snow.core.config import CoreConfig


class TestStage6BWS3PairingSecurityAndRouting(unittest.TestCase):
    """WS3: Single-use QR handshake tokens, USB trust enforcement, hybrid priority, loop/hop guard."""

    def test_single_use_qr_handshake_token_lifecycle_and_replay_rejection(self) -> None:
        now = [100.0]
        pm = PairingManager(pin_lifetime=60.0, time_provider=lambda: now[0])
        tok = pm.issue_handshake_token(
            host_device_id="host-pc-1",
            network_id="SNW-NET-1234ABCD",
            trust_tier="owner",
            ttl_seconds=90.0,
        )
        qr = create_qr_pairing_payload(
            node_id="host-pc-1",
            candidate_ips=["192.168.1.50"],
            port=8765,
            cert_fingerprint="AA" * 32,
            handshake_token=tok,
            network_id="SNW-NET-1234ABCD",
            hub_url="https://snow-relay.onrender.com",
        )
        parsed = validate_qr_pairing_payload(json.dumps(qr))
        self.assertEqual(parsed["handshake_token"], tok)
        self.assertEqual(parsed["network_id"], "SNW-NET-1234ABCD")
        self.assertEqual(parsed["hub_url"], "https://snow-relay.onrender.com")
        self.assertNotIn("pin", parsed)

        # Wrong host rejected cleanly without consuming valid host token
        wrong_host = pm.verify_handshake_token(
            tok, host_device_id="other-host", client_device_id="phone-1", network_id="SNW-NET-1234ABCD"
        )
        self.assertEqual(wrong_host.outcome, PairingOutcome.INVALID_PIN)

        # Valid host consumes once
        ok = pm.verify_handshake_token(
            tok, host_device_id="host-pc-1", client_device_id="phone-1", network_id="SNW-NET-1234ABCD"
        )
        self.assertTrue(ok.is_success)
        self.assertEqual(ok.assigned_trust_tier, "owner")

        # Replay rejected immediately
        replay = pm.verify_handshake_token(
            tok, host_device_id="host-pc-1", client_device_id="phone-2", network_id="SNW-NET-1234ABCD"
        )
        self.assertFalse(replay.is_success)
        self.assertEqual(replay.outcome, PairingOutcome.INVALID_PIN)

    def test_expired_handshake_token_rejected(self) -> None:
        now = [50.0]
        pm = PairingManager(pin_lifetime=60.0, time_provider=lambda: now[0])
        tok = pm.issue_handshake_token(host_device_id="host-pc-1", ttl_seconds=30.0)
        now[0] = 85.0
        expired = pm.verify_handshake_token(tok, host_device_id="host-pc-1", client_device_id="phone-1")
        self.assertEqual(expired.outcome, PairingOutcome.EXPIRED)

    def test_usb_connection_alone_without_pin_or_handshake_token_never_grants_pairing(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="snow_ws3_usb_"))
        try:
            db = DatabaseManager(tmp / "test.db")
            import uuid
            ident = DeviceIdentity(
                device_id=str(uuid.uuid4()),
                device_name="HostPC",
                created_at="2026-01-01T00:00:00Z",
            )
            ws_srv = SnowWebSocketServer(
                config=CoreConfig(),
                db_manager=db,
                device_identity=ident,
            )
            fake_client = MagicMock()
            fake_client.connection_id = "conn-usb-1"
            fake_client.remote_address = ("127.0.0.1", 55000)
            sent_payloads: list[str] = []

            async def fake_send(raw: str) -> None:
                sent_payloads.append(raw)

            fake_client.websocket.send = fake_send

            msg = SnowMessage.create_request(
                action="pair_request",
                data={
                    "device_id": "untrusted-usb-phone",
                    "device_name": "Unknown USB Phone",
                    "connection_mode": "usb_adb",
                    "usb_auto": True,
                },
            )
            asyncio.run(ws_srv._handle_pairing_request(fake_client, msg, "pair_request", msg.payload["data"]))
            # Must NEVER insert paired device or grant auth token solely because socket is USB loopback!
            self.assertIsNone(db.get_paired_device("untrusted-usb-phone"))
            self.assertEqual(len(sent_payloads), 1)
            resp_obj = json.loads(sent_payloads[0])
            self.assertEqual(resp_obj["payload"]["status"], "pin_displayed")
            self.assertNotIn("auth_token", resp_obj["payload"].get("data", {}))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_transport_badges_unified_labels(self) -> None:
        self.assertEqual(classify_transport_badge(transport="usb_adb", host="127.0.0.1"), "USB • Zero Data")
        self.assertEqual(classify_transport_badge(transport="wifi_lan", host="192.168.1.42"), "Wi-Fi • Zero Data")
        self.assertEqual(classify_transport_badge(transport="remote_relay", host="192.168.1.42"), "Remote • Uses Data")
        self.assertEqual(classify_transport_badge(connection_mode="remote_only"), "Remote • Uses Data")


class TestStage6BWS3HybridRoutingLoopAndIdempotency(unittest.IsolatedAsyncioTestCase):
    """Verify USB > Wi-Fi > Remote priority, loop/hop guard, and transfer idempotency."""

    async def test_hybrid_route_prefers_usb_outbound_over_remote_inbound_and_deduplicates_transfers(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="snow_ws3_router_"))
        try:
            db = DatabaseManager(tmp / "router.db")
            node = DeviceNode(
                device_id="phone-hybrid",
                device_name="Hybrid Phone",
                platform="android",
                reachability_state=ReachabilityState.CONNECTED_SESSION,
                transport="remote_relay",
                host="10.0.0.5",
                wss_port=8765,
                permission_profile="full_control",
            )
            mock_reg = MagicMock(spec=NodeRegistry)
            mock_reg.db_manager = db
            mock_reg.local_identity = MagicMock(device_id="local-pc-1")
            mock_reg.resolve_target.return_value = (node, None)

            mock_ws = MagicMock()
            sess = MagicMock(session_id="sess-remote", connection_id="conn-remote")
            mock_ws.session_manager.get_session_by_device.return_value = sess
            mock_ws.connection_manager.get.return_value = MagicMock(is_active=True)
            mock_ws.send_request = AsyncMock()

            router = SessionRouter(node_registry=mock_reg, ws_server=mock_ws, db_manager=db)
            usb_client = MagicMock()
            usb_client.is_connected = True
            usb_client.host = "127.0.0.1"
            usb_client.send_message = AsyncMock(
                return_value=SnowMessage.create_response(
                    correlation_id="c1",
                    payload={"status": "success", "received": True},
                )
            )
            router.register_outbound_client("phone-hybrid", usb_client)

            res1 = await router.route_request(
                action="file_send_request",
                target="phone-hybrid",
                data={"transfer_id": "tx-idem-01", "file_name": "notes.pdf"},
            )
            self.assertTrue(res1["success"])
            self.assertEqual(res1["transport"], "usb_adb")
            self.assertEqual(res1["transport_badge"], "USB • Zero Data")
            usb_client.send_message.assert_awaited_once()
            mock_ws.send_request.assert_not_awaited()

            # Retry same transfer_id after route state change -> idempotent cache returns without duplicate dispatch!
            res2 = await router.route_request(
                action="file_send_request",
                target="phone-hybrid",
                data={"transfer_id": "tx-idem-01", "file_name": "notes.pdf"},
            )
            self.assertTrue(res2["success"])
            self.assertTrue(res2.get("idempotent_replay"))
            self.assertEqual(usb_client.send_message.await_count, 1)

            # Loop detection and hop-limit enforcement
            loop_res = await router.route_request(
                action="battery_status",
                target="phone-hybrid",
                visited_peers=["local-pc-1"],
            )
            self.assertFalse(loop_res["success"])
            self.assertEqual(loop_res["status"], "ROUTING_LOOP_DETECTED")

            hop_res = await router.route_request(
                action="battery_status",
                target="phone-hybrid",
                hop_limit=0,
            )
            self.assertFalse(hop_res["success"])
            self.assertEqual(hop_res["status"], "HOP_LIMIT_EXCEEDED")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestStage6BWS4FiveTierPermissions(unittest.IsolatedAsyncioTestCase):
    """WS4: Exact 5-tier model, intersection, unknown rejection, AI elevation block, instant downgrade."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="snow_ws4_perm_"))
        self.db = DatabaseManager(self.tmp / "fed.db")

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_five_canonical_tiers_and_unknown_tier_rejection(self) -> None:
        self.assertEqual(
            PERMISSION_PROFILE_ORDER,
            ("full_control", "files_and_clipboard", "files_only", "clipboard_only", "not_allowed"),
        )
        self.assertEqual(set(PERMISSION_PROFILES.keys()), set(PERMISSION_PROFILE_ORDER))

        # files_only allows files & telemetry, blocks clipboard and execution/system
        self.assertTrue(is_action_allowed_by_profile("files_only", "file_list"))
        self.assertTrue(is_action_allowed_by_profile("files_only", "battery_status"))
        self.assertFalse(is_action_allowed_by_profile("files_only", "clipboard_pull"))
        self.assertFalse(is_action_allowed_by_profile("files_only", "windows_clipboard_get"))
        self.assertFalse(is_action_allowed_by_profile("files_only", "android_whatsapp_send"))

        # not_allowed blocks everything including battery and clipboard
        for act in ("battery_status", "clipboard_pull", "file_list", "windows_hotkey", "android_dnd_toggle"):
            self.assertFalse(is_action_allowed_by_profile("not_allowed", act))

        # Unknown tier fails closed (NEVER silently defaults to full_control)
        self.assertIsNone(normalize_permission_tier("super_admin"))
        self.assertFalse(is_action_allowed_by_profile("super_admin", "battery_status"))
        self.assertFalse(is_action_allowed_by_profile("", "battery_status"))

        # Registry rejects unknown tiers
        reg = NodeRegistry(db_manager=self.db)
        reg.set_permission_profile("dev-a", "files_only")
        self.assertEqual(reg.get_permission_profile("dev-a"), "files_only")
        with self.assertRaises(ValueError):
            reg.set_permission_profile("dev-a", "bogus_tier")
        self.assertEqual(reg.get_permission_profile("dev-a"), "files_only")

    def test_device_and_network_tier_intersection_and_ai_elevation_blocked(self) -> None:
        # files_only intersect clipboard_only => neither files nor clipboard!
        self.assertTrue(is_action_allowed_by_tier_intersection("files_only", "clipboard_only", "battery_status"))
        self.assertFalse(is_action_allowed_by_tier_intersection("files_only", "clipboard_only", "file_list"))
        self.assertFalse(is_action_allowed_by_tier_intersection("files_only", "clipboard_only", "clipboard_pull"))
        self.assertEqual(intersect_tier_categories("full_control", "not_allowed"), set())

        fed = FederationManager(db_manager=self.db, local_network_id="SNW-NET-AAAA1111", local_node_id="pc-local")

        # AI_MCP cannot create or mutate federation tier
        with self.assertRaises(PermissionError):
            fed.create_invitation(principal="AI_MCP", permission_tier="full_control")

        inv = fed.create_invitation(
            allowed_device_ids=["pc-local"],
            permission_tier="files_and_clipboard",
            principal="OWNER_MANUAL",
        )
        acc = fed.accept_invitation(
            code=inv["code"],
            peer_network_id="SNW-NET-BBBB2222",
            peer_network_name="Remote Net",
            peer_node_id="pc-remote",
            peer_node_name="Remote PC",
            peer_cert_fingerprint="BB" * 32,
            principal="OWNER_MANUAL",
        )
        self.assertTrue(acc["success"])
        token = acc["auth_token"]
        grant_id = acc["grant_id"]

        # Under files_and_clipboard grant + files_only device tier => clipboard must be BLOCKED, files allowed
        self.db.set_setting("device_profile:pc-local", "files_only")
        ok_files, _ = fed.validate_federated_request(token, "SNW-NET-AAAA1111", "pc-local", "windows_file_list")
        self.assertTrue(ok_files)
        ok_clip, err_clip = fed.validate_federated_request(token, "SNW-NET-AAAA1111", "pc-local", "windows_clipboard_get")
        self.assertFalse(ok_clip)
        self.assertIn("files_only", err_clip or "")

        # AI_MCP blocked from elevating grant tier
        with self.assertRaises(PermissionError):
            fed.update_grant_permission_tier(grant_id, "full_control", principal="AI_MCP")

        # Owner downgrade to not_allowed immediately revokes & blocks all access
        upd = fed.update_grant_permission_tier(grant_id, "not_allowed", principal="OWNER_MANUAL")
        self.assertTrue(upd["success"])
        ok_after, _ = fed.validate_federated_request(token, "SNW-NET-AAAA1111", "pc-local", "windows_file_list")
        self.assertFalse(ok_after)

        # Forbidden capabilities never permitted even under full_control preset
        self.assertNotIn("desktop.exec", FEDERATION_TIER_CAPABILITIES["full_control"])
        self.assertNotIn("windows_terminal_exec", FEDERATION_TIER_CAPABILITIES["full_control"])

    async def test_immediate_downgrade_enforced_in_session_router(self) -> None:
        node = DeviceNode(
            device_id="phone-downgrade",
            device_name="Target Phone",
            platform="android",
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            permission_profile="full_control",
            host="127.0.0.1",
            wss_port=8765,
        )
        reg = NodeRegistry(db_manager=self.db)
        reg.resolve_target = MagicMock(return_value=(node, None))
        router = SessionRouter(node_registry=reg, db_manager=self.db)

        # Immediate DB downgrade to not_allowed blocks dispatch even before cached Node object updates
        self.db.set_setting("device_profile:phone-downgrade", "not_allowed")
        res = await router.route_request(action="battery_status", target="phone-downgrade")
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "PERMISSION_DENIED")


if __name__ == "__main__":
    unittest.main()
