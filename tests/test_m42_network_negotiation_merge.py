"""M4.2 4-Case Network Negotiation, Dual-Owner Merge Authorization & Non-Transitive External Isolation Tests."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import socket
import sys
import tempfile
import unittest
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp.test_utils import AioHTTPTestCase

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from snow.core.config import CoreConfig
from snow.core.server import SnowCoreServer
from snow.network.federation import FederationManager
from snow.network.peer_client import SnowPeerClient
from snow.relay.auth import is_valid_network_id
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.security.tls import ensure_tls_certificate
from snow.web.server import SnowWebServer


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class TestM42NetworkNegotiationAndDualOwnerMerge(unittest.IsolatedAsyncioTestCase):
    """Verify all 4 negotiation cases, owner-only merge authorization, and Keep Separate isolation."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m42_neg_"))
        self.tls = ensure_tls_certificate(
            self.tmp_dir / "cert.pem", self.tmp_dir / "key.pem", active_ips=["127.0.0.1"]
        )
        self.db = DatabaseManager(self.tmp_dir / "neg.db")
        self.host_ident = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Negotiation-Host-PC",
            created_at="2026-11-27T00:00:00Z",
            snow_id="SNW-NEGH-0001",
        )
        self.cfg = CoreConfig(
            bind_host="127.0.0.1",
            port=_free_port(),
            ipc_port=_free_port(),
            transfer_port=_free_port(),
            discovery_enabled=False,
            tls_enabled=True,
            tls_cert_path=str(self.tls.cert_path),
            tls_key_path=str(self.tls.key_path),
        )
        self.core = SnowCoreServer(config=self.cfg, db_manager=self.db, device_identity=self.host_ident)
        self.core.ws_server.certificate_info = self.tls
        await self.core.ws_server.start()
        self.port = self.core.ws_server.bound_port
        self.assertGreater(self.port, 0)

    async def asyncTearDown(self) -> None:
        await self.core.ws_server.stop()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def test_all_four_negotiation_cases_and_dual_owner_merge_and_keep_separate(self) -> None:
        peer_a = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Peer-A",
            created_at="2026-11-27T00:00:00Z",
            snow_id="SNW-PRAA-0001",
        )
        # Case 1: Standalone + Standalone -> FORMED
        pin1 = self.core.ws_server.pairing_manager.generate_pin(display_to_stderr=False)
        c1 = SnowPeerClient(
            host="127.0.0.1",
            port=self.port,
            identity=peer_a,
            expected_fingerprint=self.tls.fingerprint_sha256,
        )
        res1 = await c1.connect(pin=pin1, client_network_id=None)
        await c1.close()
        self.assertTrue(res1.success, msg=res1.error)
        self.assertEqual(res1.network_action, "FORMED")
        self.assertEqual(res1.relationship, "member")
        self.assertTrue(is_valid_network_id(res1.network_id))
        formed_net = res1.network_id

        # Case 2a: Existing host network + Standalone client -> JOINED
        peer_b = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Peer-B",
            created_at="2026-11-27T00:00:00Z",
            snow_id="SNW-PRBB-0002",
        )
        pin2 = self.core.ws_server.pairing_manager.generate_pin(display_to_stderr=False)
        c2 = SnowPeerClient(
            host="127.0.0.1",
            port=self.port,
            identity=peer_b,
            expected_fingerprint=self.tls.fingerprint_sha256,
        )
        res2 = await c2.connect(pin=pin2, client_network_id=None)
        await c2.close()
        self.assertTrue(res2.success)
        self.assertEqual(res2.network_action, "JOINED")
        self.assertEqual(res2.network_id, formed_net)

        # Case 3: Existing host + Same network client -> SAME_NETWORK
        peer_c = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Peer-C",
            created_at="2026-11-27T00:00:00Z",
            snow_id="SNW-PRCC-0003",
        )
        pin3 = self.core.ws_server.pairing_manager.generate_pin(display_to_stderr=False)
        c3 = SnowPeerClient(
            host="127.0.0.1",
            port=self.port,
            identity=peer_c,
            expected_fingerprint=self.tls.fingerprint_sha256,
        )
        res3 = await c3.connect(pin=pin3, client_network_id=formed_net)
        await c3.close()
        self.assertTrue(res3.success)
        self.assertEqual(res3.network_action, "SAME_NETWORK")

        # Case 4: Host in formed_net vs Peer-D owning distinct canonical SNW-NET-BBBB2222 -> CONFLICT (never silent overwrite!)
        other_net = "SNW-NET-BBBB2222"
        peer_d = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Peer-D-Owner",
            created_at="2026-11-27T00:00:00Z",
            snow_id="SNW-PRDD-0004",
        )
        pin4 = self.core.ws_server.pairing_manager.generate_pin(display_to_stderr=False, trust_tier="owner")
        c4 = SnowPeerClient(
            host="127.0.0.1",
            port=self.port,
            identity=peer_d,
            expected_fingerprint=self.tls.fingerprint_sha256,
        )
        res4 = await c4.connect(pin=pin4, client_network_id=other_net)
        self.assertTrue(res4.success)
        self.assertEqual(res4.network_action, "DECISION_REQUIRED")
        self.assertTrue(res4.network_conflict)
        self.assertEqual(res4.relationship, "external_network")
        self.assertEqual(res4.network_id, formed_net)
        tx_id = res4.merge_tx_id
        self.assertTrue(tx_id)
        await c4.close()

        # Host network MUST NOT be silently overwritten
        self.assertEqual(self.db.get_active_network()["network_id"], formed_net)
        rec_d = self.db.get_paired_device(peer_d.device_id)
        self.assertEqual(rec_d.relationship, "external_network")

        # Non-owner ('peer') MUST NOT be permitted to approve merge
        non_owner_dev = str(uuid.uuid4())
        self.db.insert_paired_device(non_owner_dev, "Guest", "tok-g", trust_tier="peer")
        with self.assertRaises(PermissionError):
            self.db.approve_network_merge(tx_id, non_owner_dev)

        # Single owner approval is NOT committed yet
        step1 = self.db.approve_network_merge(tx_id, peer_d.device_id)
        self.assertEqual(int(step1["target_owner_approved"]), 1)
        self.assertEqual(int(step1["source_owner_approved"]), 0)
        self.assertEqual(step1["status"], "PENDING")
        with self.assertRaises(PermissionError):
            self.db.commit_network_merge(tx_id)

        # Second owner approves -> atomic commit merges Peer-D into formed_net!
        self.db.approve_network_merge(tx_id, self.host_ident.device_id)
        committed = self.db.commit_network_merge(tx_id)
        self.assertEqual(committed["status"], "COMMITTED")
        rec_d_merged = self.db.get_paired_device(peer_d.device_id)
        self.assertEqual(rec_d_merged.relationship, "member")
        self.assertEqual(rec_d_merged.network_id, committed["surviving_network_id"])

        # Keep Separate explicit decision isolates Peer-E as non-transitive external_network
        peer_e = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Peer-E-External",
            created_at="2026-11-27T00:00:00Z",
            snow_id="SNW-PREE-0005",
        )
        pin5 = self.core.ws_server.pairing_manager.generate_pin(display_to_stderr=False)
        c5 = SnowPeerClient(
            host="127.0.0.1",
            port=self.port,
            identity=peer_e,
            expected_fingerprint=self.tls.fingerprint_sha256,
        )
        res5 = await c5.connect(pin=pin5, client_network_id="SNW-NET-CCCC3333", network_decision="keep_separate")
        await c5.close()
        self.assertTrue(res5.success)
        self.assertEqual(res5.network_action, "KEEP_SEPARATE")
        self.assertFalse(res5.network_conflict)
        self.assertEqual(res5.relationship, "external_network")
        self.assertEqual(self.db.get_paired_device(peer_e.device_id).relationship, "external_network")

        # Anti-transitive federation routing check for external peers
        fed_mgr = FederationManager(
            db_manager=self.db,
            local_network_id=formed_net,
            local_network_name="Formed Net",
            local_node_id=self.host_ident.device_id,
            local_node_name=self.host_ident.device_name,
            local_cert_fingerprint=self.tls.fingerprint_sha256,
        )
        inv = fed_mgr.create_invitation(
            principal=ExecutionPrincipal.OWNER_MANUAL,
            allowed_capabilities=["system.info"],
            allowed_device_ids=[self.host_ident.device_id],
            ttl_seconds=300,
        )
        self.assertTrue(inv.get("success"), inv)
        grant = fed_mgr.accept_invitation(
            code=inv["code"],
            peer_network_id="SNW-NET-CCCC3333",
            peer_network_name="Net C",
            peer_node_id=peer_e.device_id,
            peer_node_name=peer_e.device_name,
            peer_cert_fingerprint="AA" * 32,
            principal=ExecutionPrincipal.OWNER_MANUAL,
        )
        self.assertTrue(grant.get("success"), grant)
        self.assertEqual(grant["network_id"], "SNW-NET-CCCC3333")
        # Authorized local capability succeeds, while transitive routing to another network or ungranted capability is blocked
        allowed_ok, _ = fed_mgr.validate_federated_request(
            token=grant["auth_token"],
            target_network_id=formed_net,
            target_device_id=self.host_ident.device_id,
            capability="system.info",
        )
        self.assertTrue(allowed_ok)
        transit_ok, transit_err = fed_mgr.validate_federated_request(
            token=grant["auth_token"],
            target_network_id="SNW-NET-OTHER999",
            target_device_id=self.host_ident.device_id,
            capability="system.info",
        )
        self.assertFalse(transit_ok)
        self.assertIn("TRANSIT_ROUTING_FORBIDDEN", transit_err or "")
        ungranted_ok, _ = fed_mgr.validate_federated_request(
            token=grant["auth_token"],
            target_network_id=formed_net,
            target_device_id=self.host_ident.device_id,
            capability="desktop.files.read",
        )
        self.assertFalse(ungranted_ok)

    async def test_case_2b_standalone_host_adopts_client_canonical_network(self) -> None:
        peer_x = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Existing-Net-Phone",
            created_at="2026-11-27T00:00:00Z",
            snow_id="SNW-PRXX-0009",
        )
        pin = self.core.ws_server.pairing_manager.generate_pin(display_to_stderr=False)
        cx = SnowPeerClient(
            host="127.0.0.1",
            port=self.port,
            identity=peer_x,
            expected_fingerprint=self.tls.fingerprint_sha256,
        )
        res = await cx.connect(pin=pin, client_network_id="SNW-NET-DDDD4444")
        await cx.close()
        self.assertTrue(res.success)
        self.assertEqual(res.network_action, "ADOPTED")
        self.assertEqual(res.network_id, "SNW-NET-DDDD4444")
        self.assertEqual(self.db.get_active_network()["network_id"], "SNW-NET-DDDD4444")


class TestM42WebMergeRoutesEndToEnd(AioHTTPTestCase):
    """Verify Web Server /api/network/merge/{pending,approve,keep-separate} routes cleanly."""

    async def asyncSetUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m42_web_mrg_"))
        self.db = DatabaseManager(self.tmp_dir / "web_mrg.db")
        self.host_ident = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="Web-Host-PC",
            created_at="2026-11-27T00:00:00Z",
            snow_id="SNW-WEBH-0001",
        )
        await super().asyncSetUp()

    async def asyncTearDown(self) -> None:
        await super().asyncTearDown()
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    async def get_application(self):
        self.web_srv = SnowWebServer(host="127.0.0.1", port=0, auto_open_browser=False)
        self.web_srv.db_manager = self.db
        self.web_srv.bridge = MagicMock()
        self.web_srv.bridge.daemon_manager = MagicMock()
        self.web_srv.bridge.daemon_manager.is_ipc_ready = AsyncMock(return_value=False)
        self.web_srv.bridge.capability_engine = MagicMock()
        self.web_srv.bridge.capability_engine.db_manager = self.db
        return self.web_srv._build_app()

    async def test_web_merge_pending_approve_and_keep_separate(self) -> None:
        auth = await self.client.post("/api/auth/session", json={"token": self.web_srv.bootstrap_token})
        csrf = (await auth.json())["csrf_token"]
        self.db.ensure_active_network("Host Mesh", self.host_ident.device_id, "SNW-NET-1111AAAA")
        self.db.insert_paired_device("peer-owner-2", "Phone 2", "tok-p2", trust_tier="owner", network_id="SNW-NET-2222BBBB", relationship="external_network")
        prop = self.db.propose_network_merge(
            tx_id="mrg-web-1",
            source_network_id="SNW-NET-1111AAAA",
            target_network_id="SNW-NET-2222BBBB",
            surviving_network_id="SNW-NET-1111AAAA",
            source_owner_device_id=self.host_ident.device_id,
            target_owner_device_id="peer-owner-2",
        )
        self.db.approve_network_merge("mrg-web-1", "peer-owner-2")

        r_pend = await self.client.get("/api/network/merge/pending")
        self.assertEqual(r_pend.status, 200)
        self.assertEqual(len((await r_pend.json())["proposals"]), 1)

        with patch("snow.security.identity.load_or_create_device_identity", return_value=self.host_ident):
            r_app = await self.client.post("/api/network/merge/approve", json={"tx_id": prop["tx_id"]}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_app.status, 200)
        app_body = await r_app.json()
        self.assertTrue(app_body["success"])
        self.assertTrue(app_body["committed"])

        # Reject path
        self.db.propose_network_merge(
            tx_id="mrg-web-2",
            source_network_id="SNW-NET-1111AAAA",
            target_network_id="SNW-NET-3333CCCC",
            surviving_network_id="SNW-NET-1111AAAA",
            source_owner_device_id=self.host_ident.device_id,
            target_owner_device_id="peer-owner-3",
        )
        r_sep = await self.client.post("/api/network/merge/keep-separate", json={"tx_id": "mrg-web-2"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r_sep.status, 200)
        self.assertTrue((await r_sep.json())["rejected"])


if __name__ == "__main__":
    unittest.main()
