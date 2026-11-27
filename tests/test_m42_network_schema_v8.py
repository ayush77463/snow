"""M4.2 Network Identity, SQLite Schema v8 Migration & Lifecycle Regression Tests."""

from __future__ import annotations

import json
from pathlib import Path
import re
import shutil
import sqlite3
import sys
import tempfile
import unittest
import uuid
from unittest.mock import AsyncMock, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from snow.network.network_model import NetworkIdentity, SnowNetworkManager
from snow.relay.auth import is_valid_network_id
from snow.security.db import DatabaseManager, SCHEMA_VERSION
from snow.web.server import SnowWebServer


class TestM42SchemaV8AndNetworkLifecycle(unittest.TestCase):
    """Verify Schema v7->v8 upgrade, standalone None default, and dissolution on final unpair."""

    def setUp(self) -> None:
        self.tmp_dir = Path(tempfile.mkdtemp(prefix="snow_m42_v8_"))
        self.db_path = self.tmp_dir / "snow.db"

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_v7_to_v8_migration_preserves_devices_and_scrubs_fabricated_standalone_ids(self) -> None:
        raw_conn = sqlite3.connect(str(self.db_path))
        raw_conn.executescript(
            """
            PRAGMA user_version = 7;
            CREATE TABLE paired_devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                pairing_timestamp TEXT NOT NULL,
                last_seen_timestamp TEXT NOT NULL,
                auth_token_hash TEXT UNIQUE NOT NULL,
                trust_tier TEXT NOT NULL DEFAULT 'peer',
                platform TEXT DEFAULT 'android',
                reachability_profile TEXT NOT NULL DEFAULT 'ACTIVE_SESSION_PEER',
                last_known_host TEXT,
                last_known_port INTEGER DEFAULT 8765,
                capabilities_json TEXT NOT NULL DEFAULT '{}',
                connection_mode TEXT NOT NULL DEFAULT 'auto',
                permission_profile TEXT DEFAULT 'full_control'
            );
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_timestamp REAL NOT NULL DEFAULT 0.0
            );
            INSERT INTO paired_devices (device_id, device_name, pairing_timestamp, last_seen_timestamp, auth_token_hash, trust_tier, platform)
            VALUES ('peer-existing-1', 'Pixel 8', '2026-11-26T00:00:00Z', '2026-11-26T00:00:00Z', 'hash-existing-1', 'owner', 'android');
            INSERT INTO settings (key, value, updated_timestamp)
            VALUES ('network_identity', '{"network_id": "default_group", "network_name": "Old Group"}', 100.0);
            INSERT INTO settings (key, value, updated_timestamp)
            VALUES ('last_known_network_id', 'local-network', 100.0);
            """
        )
        raw_conn.commit()
        raw_conn.close()

        db = DatabaseManager(self.db_path)
        self.assertEqual(SCHEMA_VERSION, 8)

        with db._get_connection() as conn:
            ver_row = conn.execute("PRAGMA user_version;").fetchone()
            self.assertEqual(int(ver_row[0]), 8)
            tables = {
                r[0]
                for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()
            }
            self.assertIn("networks", tables)
            self.assertIn("network_merge_proposals", tables)
            cols = {r[1] for r in conn.execute("PRAGMA table_info(paired_devices);").fetchall()}
            self.assertIn("network_id", cols)
            self.assertIn("relationship", cols)

        preserved = db.get_paired_device("peer-existing-1")
        self.assertIsNotNone(preserved)
        self.assertEqual(preserved.device_name, "Pixel 8")
        self.assertEqual(preserved.relationship, "member")
        # Legacy DB WITH an existing paired member upgrades to canonical SNW-NET-XXXXXXXX
        migrated_net = db.get_active_network()
        self.assertIsNotNone(migrated_net)
        self.assertTrue(is_valid_network_id(migrated_net["network_id"]))

        # Standalone v7 DB (no paired devices) with stale fabricated settings upgrades to None (standalone)
        standalone_db_path = self.tmp_dir / "standalone_v7.db"
        raw_s = sqlite3.connect(str(standalone_db_path))
        raw_s.executescript(
            """
            PRAGMA user_version = 7;
            CREATE TABLE paired_devices (
                device_id TEXT PRIMARY KEY,
                device_name TEXT NOT NULL,
                pairing_timestamp TEXT NOT NULL,
                last_seen_timestamp TEXT NOT NULL,
                auth_token_hash TEXT UNIQUE NOT NULL,
                trust_tier TEXT NOT NULL DEFAULT 'peer',
                platform TEXT DEFAULT 'android'
            );
            CREATE TABLE settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_timestamp REAL NOT NULL DEFAULT 0.0
            );
            INSERT INTO settings (key, value, updated_timestamp)
            VALUES ('network_identity', '{"network_id": "default_group", "network_name": "Fake"}', 100.0);
            INSERT INTO settings (key, value, updated_timestamp)
            VALUES ('last_known_network_id', 'local-network', 100.0);
            """
        )
        raw_s.commit()
        raw_s.close()
        standalone_db = DatabaseManager(standalone_db_path)
        self.assertIsNone(standalone_db.get_active_network())
        self.assertIsNone(SnowNetworkManager(db_manager=standalone_db).get_active_network_id())

        # Re-opening DB is strictly idempotent
        db2 = DatabaseManager(self.db_path)
        self.assertIsNotNone(db2.get_paired_device("peer-existing-1"))

    def test_standalone_starts_none_forms_canonical_and_dissolves_on_final_unpair(self) -> None:
        db = DatabaseManager(self.db_path)
        net_mgr = SnowNetworkManager(db_manager=db)

        standalone = net_mgr.get_network_identity()
        self.assertIsNone(standalone.network_id)
        self.assertIsNone(net_mgr.get_active_network_id())

        formed = net_mgr.form_network(owner_device_id="host-pc-1", network_name="Studio Mesh")
        self.assertIsNotNone(formed.network_id)
        self.assertTrue(is_valid_network_id(formed.network_id))
        self.assertNotIn(formed.network_id, ("default_group", "local-network", "SNW-LOCAL"))

        db.insert_paired_device(
            device_id="dev-a",
            device_name="Phone A",
            auth_token_hash="tok-a",
            trust_tier="owner",
            network_id=formed.network_id,
            relationship="member",
        )
        db.insert_paired_device(
            device_id="dev-b",
            device_name="Phone B",
            auth_token_hash="tok-b",
            trust_tier="peer",
            network_id=formed.network_id,
            relationship="member",
        )

        # Removing one member keeps the network alive
        self.assertTrue(db.delete_paired_device("dev-a"))
        self.assertEqual(net_mgr.get_active_network_id(), formed.network_id)

        # Removing final member dissolves the network back to standalone None
        self.assertTrue(db.delete_paired_device("dev-b"))
        self.assertIsNone(db.get_active_network())
        self.assertIsNone(net_mgr.get_active_network_id())
        self.assertIsNone(SnowNetworkManager(db_manager=db).get_network_identity().network_id)

    def test_web_identity_endpoint_reports_standalone_none_and_no_fabricated_strings_in_sources(self) -> None:
        import asyncio
        from aiohttp.test_utils import make_mocked_request

        db = DatabaseManager(self.db_path)
        server = SnowWebServer(host="127.0.0.1", port=8769, auto_open_browser=False)
        server.db_manager = db
        server.bridge = MagicMock()
        server.bridge.capability_engine = MagicMock()
        server.bridge.capability_engine.db_manager = db

        req = make_mocked_request("GET", "/api/network/identity")
        resp = asyncio.run(server.handle_api_network_identity(req))
        self.assertEqual(resp.status, 200)
        body = json.loads(resp.text)
        self.assertTrue(body["success"])
        ident = body["identity"]
        self.assertIsNone(ident["network_id"])
        self.assertFalse(ident["network_formed"])
        self.assertTrue(is_valid_network_id(ident.get("hub_key_id")))

        repo_root = Path(__file__).resolve().parents[1]
        clean_targets = [
            repo_root / "src" / "snow" / "network" / "network_model.py",
            repo_root / "src" / "snow" / "network" / "ws_server.py",
            repo_root / "src" / "snow" / "web" / "server.py",
            repo_root / "src" / "snow" / "web" / "static" / "index.html",
            repo_root / "src" / "snow" / "web" / "static" / "app.js",
        ]
        for target in clean_targets:
            src_text = target.read_text(encoding="utf-8")
            self.assertNotIn("default_group", src_text, f"Stale default_group found in {target}")
            self.assertNotIn('"local-network"', src_text, f"Stale local-network fallback found in {target}")


if __name__ == "__main__":
    unittest.main()
