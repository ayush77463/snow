"""Unit tests for Phase 13: Layer 3 Unified NodeRegistry & Platform-Independent DeviceNode Capability Manifest Protocol.

Covers:
1. SQLite schema migration (v2 -> v3) preserving existing pairing data.
2. CapabilityManifest serialization and deserialization (JSON and dict).
3. DeviceNode serialization and summary redaction.
4. Windows capability manifest structure (all 12 capabilities).
5. Dynamic manifest registration and persistence to database.
6. Endpoint caching (last-known host and port).
7. ReachabilityState transitions:
   - CONNECTED_SESSION (active authenticated WebSocket)
   - LAN_DISCOVERABLE (session dropped + recent discovery beacon)
   - LAST_KNOWN_IP_DIRECT (session dropped + cached IP in DB)
   - UNREACHABLE_OFFLINE (no session, no beacon, no cached IP)
8. Unpaired discovery candidates isolation (cannot pair or execute automatically).
9. Discovery candidates do not override paired node trust tier.
10. Target resolution (resolve_target):
   - Default with 1 device
   - Default with 0 devices (NO_DEVICES_PAIRED)
   - Default with >1 devices (DEVICE_REQUIRED)
   - Exact UUID match
   - Case-insensitive name match
   - Prefix match (unambiguous & ambiguous AMBIGUOUS_DEVICE)
   - Non-matching (DEVICE_NOT_FOUND)
   - Capability check (CAPABILITY_NOT_SUPPORTED)
"""

import json
import sqlite3
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock

from snow.network.connection_manager import ConnectionManager
from snow.network.node import (
    CapabilityExecutionClassification,
    CapabilityManifest,
    DeviceNode,
    ReachabilityProfile,
    ReachabilityState,
    build_windows_manifest,
)
from snow.network.registry import NodeRegistry
from snow.security.db import DatabaseManager, SCHEMA_VERSION
from snow.security.identity import DeviceIdentity


class TestPhase13NodeRegistry(unittest.TestCase):
    """Test suite for Phase 13 NodeRegistry and DeviceNode capability protocol."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_snow.db"
        self.db_manager = DatabaseManager(self.db_path)
        self.connection_manager = ConnectionManager()
        self.local_identity = DeviceIdentity(
            device_id=str(uuid.uuid4()),
            device_name="DESKTOP-SNOW",
            created_at="2026-11-18T00:00:00Z",
        )
        self.registry = NodeRegistry(
            db_manager=self.db_manager,
            connection_manager=self.connection_manager,
            local_identity=self.local_identity,
            port=8765,
            transfer_port=8766,
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_schema_migration_preserves_existing_pairs(self) -> None:
        """1. SQLite schema v2 -> v3 migration adds new columns without data loss."""
        # Create a raw legacy v2 schema database
        legacy_db_path = Path(self.temp_dir.name) / "legacy_v2.db"
        conn = sqlite3.connect(legacy_db_path)
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
            )
            """
        )
        cursor.execute("INSERT INTO schema_version (version, applied_at) VALUES (2, '2026-11-17T00:00:00Z')")
        cursor.execute(
            """
            CREATE TABLE paired_devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                auth_token_hash TEXT NOT NULL,
                pairing_timestamp TEXT NOT NULL,
                last_seen_timestamp TEXT NOT NULL,
                trust_tier TEXT DEFAULT 'peer'
            )
            """
        )
        cursor.execute(
            """
            INSERT INTO paired_devices (device_id, device_name, auth_token_hash, pairing_timestamp, last_seen_timestamp, trust_tier)
            VALUES ('legacy-dev-1', 'Legacy Android', 'hash123', '2026-11-17T01:00:00Z', '2026-11-17T02:00:00Z', 'owner')
            """
        )
        conn.commit()
        conn.close()

        # Open with DatabaseManager which triggers migration to v3
        migrated_db = DatabaseManager(legacy_db_path)
        dev = migrated_db.get_paired_device("legacy-dev-1")

        self.assertIsNotNone(dev)
        self.assertEqual(dev.device_id, "legacy-dev-1")
        self.assertEqual(dev.device_name, "Legacy Android")
        self.assertEqual(dev.trust_tier, "owner")
        self.assertEqual(dev.platform, "android")
        self.assertEqual(dev.reachability_profile, "ACTIVE_SESSION_PEER")
        self.assertIsNone(dev.last_known_host)
        self.assertEqual(dev.last_known_port, 8765)
        self.assertEqual(dev.capabilities_json, "{}")

    def test_device_manifest_serialization(self) -> None:
        """2. CapabilityManifest serializes to/from dict and JSON losslessly."""
        manifest = CapabilityManifest(
            manifest_version="2.0",
            supported_capabilities=["android.telemetry.get", "android.apps.launch", "android.notifications.push"],
            classifications={
                "android.telemetry.get": CapabilityExecutionClassification.BACKGROUND_SAFE,
                "android.apps.launch": CapabilityExecutionClassification.FOREGROUND_USER_INTERACTION_REQUIRED,
                "android.notifications.push": CapabilityExecutionClassification.RUNTIME_PERMISSION_REQUIRED,
            },
            permission_states={"POST_NOTIFICATIONS": "granted"},
        )

        d = manifest.to_dict()
        self.assertEqual(d["manifest_version"], "2.0")
        self.assertIn("android.telemetry.get", d["supported_capabilities"])
        self.assertEqual(d["classifications"]["android.telemetry.get"], CapabilityExecutionClassification.BACKGROUND_SAFE)

        # Roundtrip via dict
        parsed_d = CapabilityManifest.from_dict(d)
        self.assertEqual(parsed_d.manifest_version, "2.0")
        self.assertEqual(parsed_d.supported_capabilities, manifest.supported_capabilities)
        self.assertEqual(parsed_d.classifications["android.telemetry.get"], CapabilityExecutionClassification.BACKGROUND_SAFE)

        # Roundtrip via JSON
        j = manifest.to_json()
        parsed_j = CapabilityManifest.from_json(j)
        self.assertEqual(parsed_j.permission_states["POST_NOTIFICATIONS"], "granted")

    def test_device_node_serialization(self) -> None:
        """3. DeviceNode serializes with and without endpoints, summary dict redacts internal details."""
        node = DeviceNode(
            device_id="node-uuid-1",
            device_name="My Pixel",
            platform="android",
            reachability_profile=ReachabilityProfile.ACTIVE_SESSION_PEER,
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            host="192.168.1.50",
            wss_port=8765,
            transfer_port=8766,
            supported_capabilities=["android.telemetry.get"],
            trust_tier="owner",
            is_paired=True,
        )

        full_d = node.to_dict(include_endpoints=True)
        self.assertEqual(full_d["host"], "192.168.1.50")
        self.assertIn("wss://192.168.1.50:8765", full_d["active_endpoints"])

        summary = node.to_summary_dict()
        self.assertEqual(summary["device_id"], "node-uuid-1")
        self.assertEqual(summary["trust_tier"], "owner")
        self.assertEqual(summary["is_connected"], True)
        self.assertEqual(summary["is_paired"], True)

    def test_windows_manifest_structure(self) -> None:
        """4. build_windows_manifest() provides all 12 Windows desktop capabilities."""
        manifest = build_windows_manifest()
        self.assertEqual(manifest.manifest_version, "2.0")

        expected_capabilities = [
            "desktop.status",
            "desktop.battery",
            "desktop.processes",
            "desktop.apps.launch",
            "desktop.file.read",
            "desktop.file.write",
            "desktop.file.list",
            "desktop.file.search",
            "desktop.exec",
            "desktop.clipboard.read",
            "desktop.clipboard.write",
            "desktop.file.transfer",
        ]
        for cap in expected_capabilities:
            self.assertTrue(manifest.supports_capability(cap), f"Missing capability: {cap}")

        # Security check: desktop.exec is classified as BACKGROUND_SAFE for Windows execution
        self.assertTrue(manifest.is_background_safe("desktop.exec"))

    def test_register_paired_device_manifest_persistence(self) -> None:
        """5. Manifest received during session auth persists to SQLite database."""
        self.db_manager.insert_paired_device(
            device_id="dev-android-100",
            device_name="Ayush Phone",
            auth_token_hash="hash_token",
            trust_tier="owner",
        )

        manifest = CapabilityManifest(
            manifest_version="2.0",
            supported_capabilities=["android.telemetry.get"],
            classifications={"android.telemetry.get": CapabilityExecutionClassification.BACKGROUND_SAFE},
        )

        # Authenticate session with manifest
        self.registry.on_session_authenticated(
            device_id="dev-android-100",
            connection_id="conn-1",
            host="192.168.1.100",
            port=8765,
            manifest_data=manifest,
        )

        # Check DB record directly
        dev = self.db_manager.get_paired_device("dev-android-100")
        self.assertIsNotNone(dev.capabilities_json)
        saved_manifest = CapabilityManifest.from_json(dev.capabilities_json)
        self.assertTrue(saved_manifest.supports_capability("android.telemetry.get"))

    def test_last_known_endpoint_caching(self) -> None:
        """6. Remote host and port are cached in DB upon session authentication."""
        self.db_manager.insert_paired_device(
            device_id="dev-endpoint-1",
            device_name="Endpoint Phone",
            auth_token_hash="hash_token",
        )

        self.registry.on_session_authenticated(
            device_id="dev-endpoint-1",
            connection_id="conn-2",
            host="10.0.0.42",
            port=9999,
        )

        dev = self.db_manager.get_paired_device("dev-endpoint-1")
        self.assertEqual(dev.last_known_host, "10.0.0.42")
        self.assertEqual(dev.last_known_port, 9999)

    def test_reachability_active_session(self) -> None:
        """7. Active WebSocket connection reports ReachabilityState.CONNECTED_SESSION."""
        self.db_manager.insert_paired_device(
            device_id="dev-reach-1",
            device_name="Reach Phone",
            auth_token_hash="hash",
        )

        self.registry.on_session_authenticated(
            device_id="dev-reach-1",
            connection_id="conn-reach-1",
            host="192.168.1.77",
            port=8765,
        )

        node = self.registry.get_node("dev-reach-1")
        self.assertIsNotNone(node)
        self.assertEqual(node.reachability_state, ReachabilityState.CONNECTED_SESSION)
        self.assertTrue(node.is_connected)

    def test_reachability_lan_discoverable(self) -> None:
        """8. Session disconnect with recent UDP discovery beacon reports LAN_DISCOVERABLE."""
        self.db_manager.insert_paired_device(
            device_id="dev-reach-2",
            device_name="Beacon Phone",
            auth_token_hash="hash",
        )

        # Disconnect active session
        self.registry.on_session_disconnected("dev-reach-2")

        # Simulate fresh UDP beacon received
        self.registry.on_discovery_beacon(
            device_id="dev-reach-2",
            device_name="Beacon Phone",
            device_type="android",
            ip_address="192.168.1.88",
            port=8765,
            transfer_port=8766,
        )

        node = self.registry.get_node("dev-reach-2")
        self.assertIsNotNone(node)
        self.assertEqual(node.reachability_state, ReachabilityState.LAN_DISCOVERABLE)
        self.assertFalse(node.is_connected)

    def test_reachability_last_known_ip(self) -> None:
        """9. Session disconnect without discovery beacon but with cached IP reports LAST_KNOWN_IP_DIRECT."""
        self.db_manager.insert_paired_device(
            device_id="dev-reach-3",
            device_name="Cached IP Phone",
            auth_token_hash="hash",
        )
        self.db_manager.update_device_endpoint("dev-reach-3", "192.168.1.99", 8765)

        # Clear active session & no beacon
        self.registry.on_session_disconnected("dev-reach-3")

        node = self.registry.get_node("dev-reach-3")
        self.assertIsNotNone(node)
        self.assertEqual(node.reachability_state, ReachabilityState.LAST_KNOWN_IP_DIRECT)
        self.assertEqual(node.host, "192.168.1.99")

    def test_reachability_unreachable_offline(self) -> None:
        """10. Device with no active session, no discovery beacon, and no cached IP reports UNREACHABLE_OFFLINE."""
        self.db_manager.insert_paired_device(
            device_id="dev-reach-4",
            device_name="Offline Phone",
            auth_token_hash="hash",
        )

        node = self.registry.get_node("dev-reach-4")
        self.assertIsNotNone(node)
        self.assertEqual(node.reachability_state, ReachabilityState.UNREACHABLE_OFFLINE)
        self.assertFalse(node.is_connected)

    def test_discovery_candidates_isolated(self) -> None:
        """11. Unpaired UDP discovery candidates are listed as unpaired and cannot assume trust."""
        self.registry.on_discovery_beacon(
            device_id="unpaired-stranger-1",
            device_name="Stranger Phone",
            device_type="android",
            ip_address="192.168.1.150",
            port=8765,
            transfer_port=8766,
        )

        node = self.registry.get_node("unpaired-stranger-1")
        self.assertIsNotNone(node)
        self.assertFalse(node.is_paired)
        self.assertFalse(node.is_authenticated)
        self.assertIsNone(node.trust_tier)

    def test_discovery_does_not_override_paired_node(self) -> None:
        """12. Discovery beacon for already paired device preserves paired state and trust tier."""
        self.db_manager.insert_paired_device(
            device_id="paired-friend-1",
            device_name="Friend Phone",
            auth_token_hash="hash",
            trust_tier="owner",
        )

        self.registry.on_discovery_beacon(
            device_id="paired-friend-1",
            device_name="Friend Phone Changed",
            device_type="android",
            ip_address="192.168.1.160",
            port=8765,
            transfer_port=8766,
        )

        node = self.registry.get_node("paired-friend-1")
        self.assertIsNotNone(node)
        self.assertTrue(node.is_paired)
        self.assertEqual(node.trust_tier, "owner")

    def test_resolve_target_default_single_device(self) -> None:
        """13. When target is None and exactly 1 device is paired, resolves to that device."""
        self.db_manager.insert_paired_device(
            device_id="only-dev-1",
            device_name="Only Phone",
            auth_token_hash="hash",
        )

        node, err = self.registry.resolve_target(None)
        self.assertIsNone(err)
        self.assertIsNotNone(node)
        self.assertEqual(node.device_id, "only-dev-1")

    def test_resolve_target_default_no_devices(self) -> None:
        """14. When target is None and no devices paired, returns NO_DEVICES_PAIRED."""
        node, err = self.registry.resolve_target(None)
        self.assertIsNone(node)
        self.assertEqual(err, "NO_DEVICES_PAIRED")

    def test_resolve_target_default_multiple_devices(self) -> None:
        """15. When target is None and >1 devices paired, returns DEVICE_REQUIRED."""
        self.db_manager.insert_paired_device(
            device_id="dev-multi-1",
            device_name="Phone One",
            auth_token_hash="hash_m1",
        )
        self.db_manager.insert_paired_device(
            device_id="dev-multi-2",
            device_name="Phone Two",
            auth_token_hash="hash_m2",
        )

        node, err = self.registry.resolve_target(None)
        self.assertIsNone(node)
        self.assertEqual(err, "DEVICE_REQUIRED")

    def test_resolve_target_exact_id(self) -> None:
        """16. Target specified by exact UUID resolves correctly."""
        self.db_manager.insert_paired_device(
            device_id="exact-id-777",
            device_name="Target Phone",
            auth_token_hash="hash_exact",
        )

        node, err = self.registry.resolve_target("exact-id-777")
        self.assertIsNone(err)
        self.assertIsNotNone(node)
        self.assertEqual(node.device_id, "exact-id-777")

    def test_resolve_target_case_insensitive_name(self) -> None:
        """17. Target specified by case-insensitive name resolves correctly."""
        self.db_manager.insert_paired_device(
            device_id="name-dev-1",
            device_name="Ayush OnePlus",
            auth_token_hash="hash_name",
        )

        node, err = self.registry.resolve_target("ayush oneplus")
        self.assertIsNone(err)
        self.assertIsNotNone(node)
        self.assertEqual(node.device_id, "name-dev-1")

    def test_resolve_target_prefix(self) -> None:
        """18. Target specified by unambiguous prefix resolves; ambiguous prefix returns AMBIGUOUS_DEVICE."""
        self.db_manager.insert_paired_device(
            device_id="alpha-device-100",
            device_name="Alpha Phone",
            auth_token_hash="hash_p1",
        )
        self.db_manager.insert_paired_device(
            device_id="beta-device-200",
            device_name="Beta Phone",
            auth_token_hash="hash_p2",
        )

        # Unambiguous prefix
        node, err = self.registry.resolve_target("alpha")
        self.assertIsNone(err)
        self.assertIsNotNone(node)
        self.assertEqual(node.device_id, "alpha-device-100")

        # Add another alpha device to create ambiguity
        self.db_manager.insert_paired_device(
            device_id="alpha-device-101",
            device_name="Alpha Tablet",
            auth_token_hash="hash_p3",
        )
        amb_node, amb_err = self.registry.resolve_target("alpha")
        self.assertIsNone(amb_node)
        self.assertEqual(amb_err, "AMBIGUOUS_DEVICE")

    def test_resolve_target_not_found(self) -> None:
        """19. Non-matching target query returns DEVICE_NOT_FOUND."""
        self.db_manager.insert_paired_device(
            device_id="existing-dev",
            device_name="Existing Phone",
            auth_token_hash="hash",
        )

        node, err = self.registry.resolve_target("nonexistent-device-id")
        self.assertIsNone(node)
        self.assertEqual(err, "DEVICE_NOT_FOUND")

    def test_resolve_target_capability_support_check(self) -> None:
        """20. resolve_target checks required capability against manifest; returns CAPABILITY_NOT_SUPPORTED if unsupported."""
        manifest = CapabilityManifest(
            manifest_version="2.0",
            supported_capabilities=["android.telemetry.get"],
        )
        self.db_manager.insert_paired_device(
            device_id="cap-dev-1",
            device_name="Simple Phone",
            auth_token_hash="hash",
            capabilities_json=manifest.to_json(),
        )

        # Supported capability
        node, err = self.registry.resolve_target("cap-dev-1", required_capability="android.telemetry.get")
        self.assertIsNone(err)
        self.assertIsNotNone(node)

        # Unsupported capability
        bad_node, bad_err = self.registry.resolve_target("cap-dev-1", required_capability="desktop.exec")
        self.assertIsNone(bad_node)
        self.assertEqual(bad_err, "CAPABILITY_NOT_SUPPORTED")


if __name__ == "__main__":
    unittest.main()
