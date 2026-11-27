"""Persistent SQLite database manager for SNOW pairing records and audit logging.

CRITICAL ARCHITECTURAL DIRECTIVES:
----------------------------------
1. Python standard-library sqlite3 ONLY: No third-party ORMs, SQLCipher, or C extensions.
2. Windows File-Handle Safety: Python's connection context manager only manages transaction
   scope, not connection closure. Every connection MUST be explicitly closed in a `finally` block
   to prevent persistent open file handles on Windows that block directory cleanup.
3. Zero Stdout Pollution: All logging routed exclusively through standard logging / sys.stderr
   to preserve the MCP stdio JSON-RPC transport stream.
4. Security: Never store or log raw authentication tokens. Only SHA-256 hexadecimal digests are stored.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import sqlite3
import threading
import time
from typing import Any, Generator, List, Optional
import uuid

logger = logging.getLogger(__name__)

DEFAULT_DB_FILENAME = "snow_devices.db"
SCHEMA_VERSION = 7

VALID_TRUST_TIERS = ("owner", "peer")
VALID_CONNECTION_MODES = ("auto", "local_only", "remote_only")


def current_utc_timestamp() -> str:
    """Generate a strict UTC ISO-8601 formatted timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def hash_token(raw_token: str) -> str:
    """Calculate the SHA-256 hexadecimal digest of an authentication token."""
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class PairedDeviceRecord:
    """Immutable representation of a paired device record stored in SQLite."""

    device_id: str
    device_name: str
    pairing_timestamp: str
    last_seen_timestamp: str
    auth_token_hash: str
    trust_tier: str = "peer"
    platform: str = "android"
    reachability_profile: str = "ACTIVE_SESSION_PEER"
    last_known_host: Optional[str] = None
    last_known_port: Optional[int] = 8765
    capabilities_json: str = "{}"
    role: str = "member"
    cert_fingerprint: Optional[str] = None
    endpoints_json: str = "[]"
    connection_mode: str = "auto"


@dataclass(frozen=True)
class AuditEventRecord:
    """Immutable representation of a security audit log event."""

    event_id: str
    device_id: Optional[str]
    event_type: str
    timestamp: str
    details: Optional[str]


class DatabaseManager:
    """Thread-safe SQLite database manager for pairing records and audit history.

    Uses explicit connection lifecycle management (`try ... finally: conn.close()`) to ensure
    no leaked file locks on Windows and reliable transaction handling with WAL mode.
    """

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        if db_path is not None:
            self.db_path = Path(db_path).resolve()
        else:
            data_dir = os.environ.get("SNOW_DATA_DIR")
            if data_dir:
                base_dir = Path(data_dir).resolve()
            else:
                base_dir = Path.home() / ".snow"
            self.db_path = base_dir / DEFAULT_DB_FILENAME

        # Ensure parent directory exists
        self._lock = threading.RLock()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_schema()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide an isolated, transactional SQLite connection with guaranteed closure.

        Guarantees that `conn.close()` is always executed in a `finally` block,
        preventing Windows file-handle lockups during temporary directory teardown.
        """
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA busy_timeout = 5000;")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def init_schema(self) -> None:
        """Initialize the SQLite schema and indexes if they do not exist."""
        with self._get_connection() as conn:
            # Enable Write-Ahead Logging for high concurrency and resilience
            try:
                conn.execute("PRAGMA journal_mode = WAL;")
            except Exception as e:
                logger.debug("WAL mode pragma warning: %s", e)

            # Check user_version for schema migrations
            cursor = conn.execute("PRAGMA user_version;")
            row = cursor.fetchone()
            current_ver = row[0] if row else 0

            if current_ver < SCHEMA_VERSION:
                logger.info("Initializing SQLite schema (version %d) at %s", SCHEMA_VERSION, self.db_path)

                # Paired devices table
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS paired_devices (
                        device_id TEXT PRIMARY KEY,
                        device_name TEXT NOT NULL,
                        pairing_timestamp TEXT NOT NULL,
                        last_seen_timestamp TEXT NOT NULL,
                        auth_token_hash TEXT UNIQUE NOT NULL,
                        trust_tier TEXT NOT NULL DEFAULT 'peer',
                        platform TEXT NOT NULL DEFAULT 'android',
                        reachability_profile TEXT NOT NULL DEFAULT 'ACTIVE_SESSION_PEER',
                        last_known_host TEXT,
                        last_known_port INTEGER DEFAULT 8765,
                        capabilities_json TEXT NOT NULL DEFAULT '{}',
                        connection_mode TEXT NOT NULL DEFAULT 'auto'
                    );
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_paired_devices_token_hash
                    ON paired_devices(auth_token_hash);
                """)

                # Schema migration for existing tables created under versions 1 or 2
                cursor = conn.execute("PRAGMA table_info(paired_devices);")
                columns = [row["name"] for row in cursor.fetchall()]
                if "trust_tier" not in columns:
                    logger.info("Migrating paired_devices table: adding trust_tier column")
                    conn.execute("ALTER TABLE paired_devices ADD COLUMN trust_tier TEXT NOT NULL DEFAULT 'peer';")
                if "platform" not in columns:
                    logger.info("Migrating paired_devices table: adding platform column")
                    conn.execute("ALTER TABLE paired_devices ADD COLUMN platform TEXT NOT NULL DEFAULT 'android';")
                if "reachability_profile" not in columns:
                    logger.info("Migrating paired_devices table: adding reachability_profile column")
                    conn.execute("ALTER TABLE paired_devices ADD COLUMN reachability_profile TEXT NOT NULL DEFAULT 'ACTIVE_SESSION_PEER';")
                if "last_known_host" not in columns:
                    logger.info("Migrating paired_devices table: adding last_known_host column")
                    conn.execute("ALTER TABLE paired_devices ADD COLUMN last_known_host TEXT;")
                if "last_known_port" not in columns:
                    logger.info("Migrating paired_devices table: adding last_known_port column")
                    conn.execute("ALTER TABLE paired_devices ADD COLUMN last_known_port INTEGER DEFAULT 8765;")
                if "capabilities_json" not in columns:
                    logger.info("Migrating paired_devices table: adding capabilities_json column")
                    conn.execute("ALTER TABLE paired_devices ADD COLUMN capabilities_json TEXT NOT NULL DEFAULT '{}';")
                if "role" not in columns:
                    logger.info("Migrating paired_devices table: adding role column")
                    conn.execute("ALTER TABLE paired_devices ADD COLUMN role TEXT NOT NULL DEFAULT 'member';")
                if "cert_fingerprint" not in columns:
                    logger.info("Migrating paired_devices table: adding cert_fingerprint column")
                    conn.execute("ALTER TABLE paired_devices ADD COLUMN cert_fingerprint TEXT;")
                if "endpoints_json" not in columns:
                    logger.info("Migrating paired_devices table: adding endpoints_json column")
                    conn.execute("ALTER TABLE paired_devices ADD COLUMN endpoints_json TEXT NOT NULL DEFAULT '[]';")
                if "connection_mode" not in columns:
                    logger.info("Migrating paired_devices table: adding connection_mode column")
                    conn.execute("ALTER TABLE paired_devices ADD COLUMN connection_mode TEXT NOT NULL DEFAULT 'auto';")

                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_paired_devices_trust_tier
                    ON paired_devices(trust_tier);
                """)

                # Phase 27: Network identity and persistent endpoints
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS network_identity (
                        network_id TEXT PRIMARY KEY,
                        network_name TEXT NOT NULL,
                        owner_id TEXT NOT NULL,
                        created_timestamp TEXT NOT NULL
                    );
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS network_endpoints (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        device_id TEXT NOT NULL,
                        host TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        success_count INTEGER DEFAULT 1,
                        last_success_timestamp TEXT NOT NULL,
                        UNIQUE(device_id, host, port)
                    );
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_network_endpoints_device
                    ON network_endpoints(device_id);
                """)

                # Security audit log table (intentionally independent of paired_devices foreign key
                # so audit trail is preserved after device unpairing)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS pairing_audit_log (
                        event_id TEXT PRIMARY KEY,
                        device_id TEXT,
                        event_type TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        details TEXT
                    );
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_pairing_audit_device
                    ON pairing_audit_log(device_id);
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_pairing_audit_timestamp
                    ON pairing_audit_log(timestamp);
                """)

                # Phase 21: Activity History table with secret redaction
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS activity_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT UNIQUE NOT NULL,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        capability TEXT,
                        principal TEXT NOT NULL,
                        target_device TEXT,
                        outcome TEXT NOT NULL,
                        details_json TEXT NOT NULL DEFAULT '{}'
                    );
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_activity_history_timestamp
                    ON activity_history(timestamp);
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_activity_history_event_type
                    ON activity_history(event_type);
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_activity_history_principal
                    ON activity_history(principal);
                """)

                # Phase 29: Application configuration and onboarding settings
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS app_settings (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    );
                """)

                # Phase 30: Cross-Network Federation (Schema v6)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS federation_invitations (
                        invite_id TEXT PRIMARY KEY,
                        network_id TEXT NOT NULL,
                        network_name TEXT NOT NULL,
                        code_hash TEXT UNIQUE NOT NULL,
                        cert_fingerprint TEXT NOT NULL,
                        created_timestamp TEXT NOT NULL,
                        expires_timestamp TEXT NOT NULL,
                        ttl_seconds INTEGER NOT NULL DEFAULT 600,
                        status TEXT NOT NULL DEFAULT 'PENDING',
                        allowed_capabilities_json TEXT NOT NULL DEFAULT '[]',
                        allowed_device_ids_json TEXT NOT NULL DEFAULT '[]',
                        grant_ttl_seconds INTEGER NOT NULL DEFAULT 86400,
                        attempts INTEGER NOT NULL DEFAULT 0
                    );
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_federation_invites_hash
                    ON federation_invitations(code_hash);
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_federation_invites_status
                    ON federation_invitations(status);
                """)

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS federation_grants (
                        grant_id TEXT PRIMARY KEY,
                        network_id TEXT NOT NULL,
                        network_name TEXT NOT NULL,
                        peer_node_id TEXT NOT NULL,
                        peer_node_name TEXT NOT NULL,
                        peer_cert_fingerprint TEXT NOT NULL,
                        direction TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'ACTIVE',
                        created_timestamp TEXT NOT NULL,
                        expires_timestamp TEXT NOT NULL,
                        allowed_capabilities_json TEXT NOT NULL DEFAULT '[]',
                        allowed_device_ids_json TEXT NOT NULL DEFAULT '[]',
                        auth_token_hash TEXT UNIQUE NOT NULL,
                        last_used_timestamp TEXT,
                        revoked_timestamp TEXT,
                        revocation_reason TEXT
                    );
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_federation_grants_network
                    ON federation_grants(network_id);
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_federation_grants_token
                    ON federation_grants(auth_token_hash);
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_federation_grants_status
                    ON federation_grants(status);
                """)

                conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION};")

            # Guarantee connection_mode exists even on already-versioned databases
            col_cursor = conn.execute("PRAGMA table_info(paired_devices);")
            existing_cols = [row["name"] for row in col_cursor.fetchall()]
            if existing_cols and "connection_mode" not in existing_cols:
                logger.info("Ensuring connection_mode column in paired_devices")
                conn.execute("ALTER TABLE paired_devices ADD COLUMN connection_mode TEXT NOT NULL DEFAULT 'auto';")

            # Guarantee app_settings and federation tables exist on existing databases
            conn.execute("""
                CREATE TABLE IF NOT EXISTS app_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS federation_invitations (
                    invite_id TEXT PRIMARY KEY,
                    network_id TEXT NOT NULL,
                    network_name TEXT NOT NULL,
                    code_hash TEXT UNIQUE NOT NULL,
                    cert_fingerprint TEXT NOT NULL,
                    created_timestamp TEXT NOT NULL,
                    expires_timestamp TEXT NOT NULL,
                    ttl_seconds INTEGER NOT NULL DEFAULT 600,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    allowed_capabilities_json TEXT NOT NULL DEFAULT '[]',
                    allowed_device_ids_json TEXT NOT NULL DEFAULT '[]',
                    grant_ttl_seconds INTEGER NOT NULL DEFAULT 86400,
                    attempts INTEGER NOT NULL DEFAULT 0
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS federation_grants (
                    grant_id TEXT PRIMARY KEY,
                    network_id TEXT NOT NULL,
                    network_name TEXT NOT NULL,
                    peer_node_id TEXT NOT NULL,
                    peer_node_name TEXT NOT NULL,
                    peer_cert_fingerprint TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'ACTIVE',
                    created_timestamp TEXT NOT NULL,
                    expires_timestamp TEXT NOT NULL,
                    allowed_capabilities_json TEXT NOT NULL DEFAULT '[]',
                    allowed_device_ids_json TEXT NOT NULL DEFAULT '[]',
                    auth_token_hash TEXT UNIQUE NOT NULL,
                    last_used_timestamp TEXT,
                    revoked_timestamp TEXT,
                    revocation_reason TEXT
                );
            """)

            # OAuth 2.1 persistent storage tables (F22)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS oauth_clients (
                    client_id TEXT PRIMARY KEY,
                    client_name TEXT NOT NULL,
                    client_secret_hash TEXT,
                    redirect_uris_json TEXT NOT NULL DEFAULT '[]',
                    scope TEXT NOT NULL DEFAULT 'snow:mcp',
                    is_confidential INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS oauth_auth_codes (
                    code_hash TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    redirect_uri TEXT NOT NULL,
                    code_challenge TEXT NOT NULL,
                    code_challenge_method TEXT NOT NULL DEFAULT 'S256',
                    scope TEXT NOT NULL DEFAULT 'snow:mcp',
                    expires_at REAL NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_client
                ON oauth_auth_codes(client_id);
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS oauth_tokens (
                    access_token_hash TEXT PRIMARY KEY,
                    refresh_token_hash TEXT UNIQUE,
                    client_id TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT 'snow:mcp',
                    family_id TEXT NOT NULL,
                    expires_at REAL NOT NULL,
                    refresh_expires_at REAL NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_oauth_tokens_refresh
                ON oauth_tokens(refresh_token_hash);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_oauth_tokens_family
                ON oauth_tokens(family_id);
            """)

            # Clipboard Ring Buffer persistence (Batch 3 + V7 additive columns)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS clipboard_buffer_items (
                    item_id TEXT PRIMARY KEY,
                    content_type TEXT NOT NULL,
                    preview TEXT NOT NULL,
                    source_device_id TEXT NOT NULL,
                    source_device_name TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    sha256 TEXT NOT NULL,
                    size_bytes INTEGER NOT NULL,
                    pinned INTEGER NOT NULL DEFAULT 0,
                    text_content TEXT,
                    image_rel_path TEXT,
                    mime_type TEXT,
                    event_id TEXT,
                    seq INTEGER NOT NULL DEFAULT 0,
                    file_manifest_json TEXT NOT NULL DEFAULT '[]',
                    canonical_sha256 TEXT,
                    width INTEGER,
                    height INTEGER
                );
            """)
            cur_cb = conn.execute("PRAGMA table_info(clipboard_buffer_items);")
            cb_columns = {row[1] for row in cur_cb.fetchall()}
            if "event_id" not in cb_columns:
                conn.execute("ALTER TABLE clipboard_buffer_items ADD COLUMN event_id TEXT;")
            if "seq" not in cb_columns:
                conn.execute(
                    "ALTER TABLE clipboard_buffer_items ADD COLUMN seq INTEGER NOT NULL DEFAULT 0;"
                )
            if "file_manifest_json" not in cb_columns:
                conn.execute(
                    "ALTER TABLE clipboard_buffer_items ADD COLUMN file_manifest_json TEXT NOT NULL DEFAULT '[]';"
                )
            if "canonical_sha256" not in cb_columns:
                conn.execute("ALTER TABLE clipboard_buffer_items ADD COLUMN canonical_sha256 TEXT;")
            if "width" not in cb_columns:
                conn.execute("ALTER TABLE clipboard_buffer_items ADD COLUMN width INTEGER;")
            if "height" not in cb_columns:
                conn.execute("ALTER TABLE clipboard_buffer_items ADD COLUMN height INTEGER;")
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_clipboard_timestamp
                ON clipboard_buffer_items(timestamp DESC);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_clipboard_seq
                ON clipboard_buffer_items(seq DESC, timestamp DESC);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_clipboard_sha256
                ON clipboard_buffer_items(sha256);
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_clipboard_canonical_sha256
                ON clipboard_buffer_items(canonical_sha256);
            """)

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> PairedDeviceRecord:
        """Convert a database row into an immutable PairedDeviceRecord."""
        keys = row.keys()
        return PairedDeviceRecord(
            device_id=row["device_id"],
            device_name=row["device_name"],
            pairing_timestamp=row["pairing_timestamp"],
            last_seen_timestamp=row["last_seen_timestamp"],
            auth_token_hash=row["auth_token_hash"],
            trust_tier=row["trust_tier"] if "trust_tier" in keys else "peer",
            platform=row["platform"] if "platform" in keys else "android",
            reachability_profile=row["reachability_profile"] if "reachability_profile" in keys else "ACTIVE_SESSION_PEER",
            last_known_host=row["last_known_host"] if "last_known_host" in keys else None,
            last_known_port=row["last_known_port"] if "last_known_port" in keys else 8765,
            capabilities_json=row["capabilities_json"] if "capabilities_json" in keys else "{}",
            role=row["role"] if "role" in keys else "member",
            cert_fingerprint=row["cert_fingerprint"] if "cert_fingerprint" in keys else None,
            endpoints_json=row["endpoints_json"] if "endpoints_json" in keys else "[]",
            connection_mode=row["connection_mode"] if "connection_mode" in keys else "auto",
        )

    def insert_paired_device(
        self,
        device_id: str,
        device_name: str,
        auth_token_hash: str,
        pairing_timestamp: Optional[str] = None,
        last_seen_timestamp: Optional[str] = None,
        trust_tier: str = "peer",
        platform: str = "android",
        reachability_profile: str = "ACTIVE_SESSION_PEER",
        last_known_host: Optional[str] = None,
        last_known_port: Optional[int] = 8765,
        capabilities_json: str = "{}",
        connection_mode: str = "auto",
        role: str = "member",
        cert_fingerprint: Optional[str] = None,
        endpoints_json: str = "[]",
    ) -> PairedDeviceRecord:
        """Insert a newly paired device record.

        Args:
            device_id: Valid UUIDv4 of the paired client device.
            device_name: Human-readable device name.
            auth_token_hash: SHA-256 hexadecimal digest of the authorization token.
            pairing_timestamp: Optional UTC ISO-8601 timestamp (defaults to now).
            last_seen_timestamp: Optional UTC ISO-8601 timestamp (defaults to now).
            trust_tier: Authorization tier ('owner' or 'peer', defaults to 'peer').
            platform: Platform name ('android', 'windows', etc.).
            reachability_profile: Default profile ('ACTIVE_SESSION_PEER', 'PERSISTENT_DAEMON').
            last_known_host: Optional IP or host.
            last_known_port: Optional port number.
            capabilities_json: Serialized JSON capability manifest.
            connection_mode: Connection mode ('auto', 'local_only', 'remote_only').

        Returns:
            The created PairedDeviceRecord.

        Raises:
            ValueError: If trust_tier or connection_mode is invalid.
            sqlite3.IntegrityError: If device_id or auth_token_hash is not unique.
        """
        if trust_tier not in VALID_TRUST_TIERS:
            raise ValueError(
                f"Invalid trust_tier '{trust_tier}'. Must be one of: {', '.join(VALID_TRUST_TIERS)}"
            )
        if connection_mode not in VALID_CONNECTION_MODES:
            raise ValueError(
                f"Invalid connection_mode '{connection_mode}'. Must be one of: {', '.join(VALID_CONNECTION_MODES)}"
            )

        now = current_utc_timestamp()
        p_time = pairing_timestamp or now
        ls_time = last_seen_timestamp or now

        query = """
            INSERT INTO paired_devices (
                device_id, device_name, pairing_timestamp, last_seen_timestamp, auth_token_hash,
                trust_tier, platform, reachability_profile, last_known_host, last_known_port, capabilities_json,
                connection_mode, role, cert_fingerprint, endpoints_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._get_connection() as conn:
            conn.execute(
                query,
                (
                    device_id,
                    device_name,
                    p_time,
                    ls_time,
                    auth_token_hash,
                    trust_tier,
                    platform,
                    reachability_profile,
                    last_known_host,
                    last_known_port,
                    capabilities_json,
                    connection_mode,
                    role,
                    cert_fingerprint,
                    endpoints_json,
                ),
            )

        return PairedDeviceRecord(
            device_id=device_id,
            device_name=device_name,
            pairing_timestamp=p_time,
            last_seen_timestamp=ls_time,
            auth_token_hash=auth_token_hash,
            trust_tier=trust_tier,
            platform=platform,
            reachability_profile=reachability_profile,
            last_known_host=last_known_host,
            last_known_port=last_known_port,
            capabilities_json=capabilities_json,
            connection_mode=connection_mode,
            role=role,
            cert_fingerprint=cert_fingerprint,
            endpoints_json=endpoints_json,
        )

    def update_device_cert_fingerprint(self, device_id: str, cert_fingerprint: str) -> bool:
        """Update certificate fingerprint for a paired device."""
        now = current_utc_timestamp()
        query = "UPDATE paired_devices SET cert_fingerprint = ?, last_seen_timestamp = ? WHERE device_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (cert_fingerprint, now, device_id))
            return cursor.rowcount > 0

    def update_device_connection_mode(self, device_id: str, connection_mode: str) -> bool:
        """Update connection mode ('auto', 'local_only', 'remote_only') for a paired device."""
        if connection_mode not in VALID_CONNECTION_MODES:
            raise ValueError(
                f"Invalid connection_mode '{connection_mode}'. Must be one of: {', '.join(VALID_CONNECTION_MODES)}"
            )
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE paired_devices SET connection_mode = ? WHERE device_id = ?;",
                (connection_mode, device_id),
            )
            return cursor.rowcount > 0

    def get_paired_device(self, device_id: str) -> Optional[PairedDeviceRecord]:
        """Retrieve a paired device record by device_id."""
        query = "SELECT * FROM paired_devices WHERE device_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (device_id,))
            row = cursor.fetchone()
            if row:
                return self._row_to_record(row)
        return None

    def get_paired_device_by_token_hash(self, token_hash: str) -> Optional[PairedDeviceRecord]:
        """Retrieve a paired device record by its auth_token_hash."""
        query = "SELECT * FROM paired_devices WHERE auth_token_hash = ?;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (token_hash,))
            row = cursor.fetchone()
            if row:
                return self._row_to_record(row)
        return None

    def list_paired_devices(self) -> List[PairedDeviceRecord]:
        """Return all registered paired devices."""
        query = "SELECT * FROM paired_devices ORDER BY pairing_timestamp ASC;"
        devices: List[PairedDeviceRecord] = []
        with self._get_connection() as conn:
            cursor = conn.execute(query)
            for row in cursor.fetchall():
                devices.append(self._row_to_record(row))
        return devices

    def get_all_paired_devices(self) -> List[PairedDeviceRecord]:
        """Alias for list_paired_devices."""
        return self.list_paired_devices()

    def update_device_endpoint(self, device_id: str, host: str, port: int) -> bool:
        """Update last known host and port for a paired device."""
        now = current_utc_timestamp()
        query = "UPDATE paired_devices SET last_known_host = ?, last_known_port = ?, last_seen_timestamp = ? WHERE device_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (host, port, now, device_id))
            return cursor.rowcount > 0

    def update_device_manifest(self, device_id: str, capabilities_json: str) -> bool:
        """Update the capability manifest JSON for a paired device."""
        now = current_utc_timestamp()
        query = "UPDATE paired_devices SET capabilities_json = ?, last_seen_timestamp = ? WHERE device_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (capabilities_json, now, device_id))
            return cursor.rowcount > 0

    def update_device_profile(self, device_id: str, platform: str, reachability_profile: str) -> bool:
        """Update the platform and reachability profile for a paired device."""
        now = current_utc_timestamp()
        query = "UPDATE paired_devices SET platform = ?, reachability_profile = ?, last_seen_timestamp = ? WHERE device_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (platform, reachability_profile, now, device_id))
            return cursor.rowcount > 0

    def update_device_trust_tier(
        self, device_id: str, trust_tier: str, demote_existing_owners: bool = False
    ) -> bool:
        """Update the trust tier for a registered paired device.

        Args:
            device_id: UUID of the paired device.
            trust_tier: New trust tier ('owner' or 'peer').
            demote_existing_owners: Whether to demote other owner devices to peer
                                   (preserves multi-owner personal devices by default).

        Returns:
            True if updated, False if device not found.

        Raises:
            ValueError: If trust_tier is not 'owner' or 'peer'.
        """
        if trust_tier not in VALID_TRUST_TIERS:
            raise ValueError(
                f"Invalid trust_tier '{trust_tier}'. Must be one of: {', '.join(VALID_TRUST_TIERS)}"
            )

        query = "UPDATE paired_devices SET trust_tier = ? WHERE device_id = ?;"
        with self._get_connection() as conn:
            if trust_tier == "owner" and demote_existing_owners:
                # Explicit single primary owner transfer requested
                conn.execute(
                    "UPDATE paired_devices SET trust_tier = 'peer' WHERE trust_tier = 'owner' AND device_id != ?;",
                    (device_id,),
                )
            cursor = conn.execute(query, (trust_tier, device_id))
            updated = cursor.rowcount > 0

        if updated:
            self.log_audit_event(
                event_type="TRUST_TIER_UPDATED",
                device_id=device_id,
                details={"trust_tier": trust_tier},
            )
            logger.info("Updated device [%s] trust tier to '%s'", device_id, trust_tier)
        return updated

    def get_owner_device(self) -> Optional[PairedDeviceRecord]:
        """Retrieve the primary owner device record if one has been provisioned."""
        query = "SELECT * FROM paired_devices WHERE trust_tier = 'owner' LIMIT 1;"
        with self._get_connection() as conn:
            cursor = conn.execute(query)
            row = cursor.fetchone()
            if row:
                return self._row_to_record(row)
        return None

    def update_last_seen(self, device_id: str, last_seen_timestamp: Optional[str] = None) -> bool:
        """Update the last-seen timestamp for an active paired device."""
        now = last_seen_timestamp or current_utc_timestamp()
        query = "UPDATE paired_devices SET last_seen_timestamp = ? WHERE device_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (now, device_id))
            return cursor.rowcount > 0

    def delete_paired_device(self, device_id: str) -> bool:
        """Remove a paired device from the database (unpairing).

        Audit logs are intentionally preserved.
        """
        query = "DELETE FROM paired_devices WHERE device_id = ?;"
        with self._get_connection() as conn:
            cursor = conn.execute(query, (device_id,))
            return cursor.rowcount > 0

    def verify_device_token(self, device_id: str, raw_token: str) -> bool:
        """Verify a device's raw token against its stored SHA-256 hash in constant time.

        Args:
            device_id: The UUID of the device claiming authentication.
            raw_token: The raw authentication token presented by the client.

        Returns:
            True if the device exists and the token hash matches; False otherwise.
        """
        record = self.get_paired_device(device_id)
        if record is None:
            return False

        calculated_hash = hash_token(raw_token)
        return hmac.compare_digest(calculated_hash, record.auth_token_hash)

    def log_audit_event(
        self,
        event_type: str,
        device_id: Optional[str] = None,
        details: Optional[Any] = None,
        timestamp: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> str:
        """Record a security-critical audit event.

        Args:
            event_type: Type of event (e.g. PAIR_SUCCESS, PAIR_FAILED, PAIR_LOCKOUT, UNPAIR, SESSION_REVOKED).
            device_id: Optional UUID of the device involved.
            details: Optional metadata (will be serialized to JSON if dict).
            timestamp: Optional UTC ISO-8601 timestamp.
            event_id: Optional UUIDv4 string.

        Returns:
            The event_id recorded.
        """
        eid = event_id or str(uuid.uuid4())
        ts = timestamp or current_utc_timestamp()

        details_str: Optional[str] = None
        if details is not None:
            if isinstance(details, (dict, list)):
                details_str = json.dumps(details, separators=(",", ":"))
            else:
                details_str = str(details)

        query = """
            INSERT INTO pairing_audit_log (event_id, device_id, event_type, timestamp, details)
            VALUES (?, ?, ?, ?, ?);
        """
        with self._get_connection() as conn:
            conn.execute(query, (eid, device_id, event_type, ts, details_str))

        logger.info("Security audit log: event=%s device=%s", event_type, device_id or "none")
        return eid

    def get_audit_logs(
        self, device_id: Optional[str] = None, limit: int = 100
    ) -> List[AuditEventRecord]:
        """Retrieve audit history records in reverse chronological order."""
        if device_id:
            query = "SELECT * FROM pairing_audit_log WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?;"
            params = (device_id, limit)
        else:
            query = "SELECT * FROM pairing_audit_log ORDER BY timestamp DESC LIMIT ?;"
            params = (limit,)

        logs: List[AuditEventRecord] = []
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            for row in cursor.fetchall():
                logs.append(
                    AuditEventRecord(
                        event_id=row["event_id"],
                        device_id=row["device_id"],
                        event_type=row["event_type"],
                        timestamp=row["timestamp"],
                        details=row["details"],
                    )
                )
        return logs

    def log_activity(
        self,
        event_type: str,
        capability: Optional[str] = None,
        principal: str = "AI_MCP",
        target_device: Optional[str] = None,
        outcome: str = "SUCCESS",
        details: Optional[dict[str, Any]] = None,
        timestamp: Optional[str] = None,
    ) -> str:
        """Record an activity event into activity_history with centralized secret redaction."""
        eid = str(uuid.uuid4())
        ts = timestamp or current_utc_timestamp()
        target = target_device or "local"
        redacted_details = redact_sensitive_data(details or {})
        details_json = json.dumps(redacted_details, sort_keys=True, separators=(",", ":"))

        query = """
            INSERT INTO activity_history (
                event_id, timestamp, event_type, capability, principal, target_device, outcome, details_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._get_connection() as conn:
            conn.execute(
                query,
                (eid, ts, event_type, capability, principal, target, outcome, details_json),
            )
        return eid

    def query_activity_history(
        self,
        limit: int = 50,
        offset: int = 0,
        event_type: Optional[str] = None,
        principal: Optional[str] = None,
        since: Optional[str] = None,
    ) -> List[dict[str, Any]]:
        """Query bounded activity history in reverse chronological order."""
        bounded_limit = max(1, min(int(limit), 200))
        bounded_offset = max(0, int(offset))

        clauses = []
        params: list[Any] = []

        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type.strip())
        if principal:
            clauses.append("principal = ?")
            params.append(principal.strip())
        if since:
            clauses.append("timestamp >= ?")
            params.append(since.strip())

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"""
            SELECT event_id, timestamp, event_type, capability, principal, target_device, outcome, details_json
            FROM activity_history
            {where_sql}
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?;
        """
        params.extend([bounded_limit, bounded_offset])

        results = []
        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            for row in cursor.fetchall():
                try:
                    det = json.loads(row["details_json"])
                except Exception:
                    det = {}
                results.append({
                    "event_id": row["event_id"],
                    "timestamp": row["timestamp"],
                    "event_type": row["event_type"],
                    "capability": row["capability"],
                    "principal": row["principal"],
                    "target_device": row["target_device"],
                    "outcome": row["outcome"],
                    "details": det,
                })
        return results

    def get_network_identity(self) -> Optional[dict[str, Any]]:
        """Retrieve the local SNOW Network identity record if present."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT network_id, network_name, owner_id, created_timestamp FROM network_identity LIMIT 1;"
            )
            row = cur.fetchone()
            if row:
                return dict(row)
            return None

    def save_network_identity(
        self, network_id: str, network_name: str, owner_id: str, created_timestamp: str
    ) -> None:
        """Persist or update the SNOW Network identity."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO network_identity (network_id, network_name, owner_id, created_timestamp)
                VALUES (?, ?, ?, ?);
                """,
                (network_id, network_name, owner_id, created_timestamp),
            )

    def update_network_name(self, network_name: str) -> None:
        """Update the user-facing network name."""
        with self._get_connection() as conn:
            conn.execute("UPDATE network_identity SET network_name = ?;", (network_name,))

    def record_endpoint(
        self, device_id: str, host: str, port: int, last_success_timestamp: str
    ) -> None:
        """Record or refresh a successfully reached endpoint for a device."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO network_endpoints (device_id, host, port, success_count, last_success_timestamp)
                VALUES (?, ?, ?, 1, ?)
                ON CONFLICT(device_id, host, port) DO UPDATE SET
                    success_count = success_count + 1,
                    last_success_timestamp = excluded.last_success_timestamp;
                """,
                (device_id, host, port, last_success_timestamp),
            )

    def get_endpoints(self, device_id: str, limit: int = 5) -> list[dict[str, Any]]:
        """Retrieve bounded endpoint history for a device, newest first."""
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                SELECT host, port, success_count, last_success_timestamp
                FROM network_endpoints
                WHERE device_id = ?
                ORDER BY last_success_timestamp DESC
                LIMIT ?;
                """,
                (device_id, limit),
            )
            return [dict(r) for r in cur.fetchall()]

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieve a persistent configuration setting by key."""
        with self._get_connection() as conn:
            cur = conn.execute("SELECT value FROM app_settings WHERE key = ?;", (key,))
            row = cur.fetchone()
            return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        """Persist or update a configuration setting by key."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO app_settings (key, value)
                VALUES (?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                """,
                (key, str(value)),
            )

    def delete_setting(self, key: str) -> bool:
        """Remove a configuration setting by key."""
        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM app_settings WHERE key = ?;", (key,))
            return cur.rowcount > 0

    def list_settings_prefix(self, prefix: str) -> dict[str, str]:
        """List configuration settings whose key starts with an exact prefix."""
        if not prefix:
            return {}
        with self._get_connection() as conn:
            cur = conn.execute("SELECT key, value FROM app_settings;")
            return {
                row["key"]: row["value"]
                for row in cur.fetchall()
                if isinstance(row["key"], str) and row["key"].startswith(prefix)
            }

    # Phase 30: Cross-Network Federation Operations

    def create_federation_invitation(
        self,
        invite_id: str,
        network_id: str,
        network_name: str,
        code_hash: str,
        cert_fingerprint: str,
        created_timestamp: str,
        expires_timestamp: str,
        ttl_seconds: int = 600,
        allowed_capabilities_json: str = "[]",
        allowed_device_ids_json: str = "[]",
        grant_ttl_seconds: int = 86400,
    ) -> None:
        """Store a new mutual federation invitation."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO federation_invitations (
                    invite_id, network_id, network_name, code_hash,
                    cert_fingerprint, created_timestamp, expires_timestamp,
                    ttl_seconds, status, allowed_capabilities_json,
                    allowed_device_ids_json, grant_ttl_seconds, attempts
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?, 0);
                """,
                (
                    invite_id,
                    network_id,
                    network_name,
                    code_hash,
                    cert_fingerprint,
                    created_timestamp,
                    expires_timestamp,
                    ttl_seconds,
                    allowed_capabilities_json,
                    allowed_device_ids_json,
                    grant_ttl_seconds,
                ),
            )

    def get_federation_invitation_by_hash(self, code_hash: str) -> Optional[dict[str, Any]]:
        """Retrieve an invitation by its SHA-256 code hash."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM federation_invitations WHERE code_hash = ?;",
                (code_hash,),
            )
            row = cur.fetchone()
            if not row:
                return None
            return dict(row)

    def update_federation_invitation_status(self, invite_id: str, status: str) -> bool:
        """Update invitation status (e.g. ACCEPTED, EXPIRED, REVOKED)."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "UPDATE federation_invitations SET status = ? WHERE invite_id = ?;",
                (status, invite_id),
            )
            return cur.rowcount > 0

    def increment_federation_invitation_attempts(self, invite_id: str) -> int:
        """Atomically increment the verification attempts counter for a specific invitation.

        If attempts reach 3 or more, automatically marks status as 'EXPIRED'.
        Returns the updated attempts count.
        """
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE federation_invitations SET attempts = attempts + 1 WHERE invite_id = ?;",
                (invite_id,),
            )
            cur = conn.execute(
                "SELECT attempts, status FROM federation_invitations WHERE invite_id = ?;",
                (invite_id,),
            )
            row = cur.fetchone()
            if not row:
                return 0
            attempts = int(row["attempts"])
            if attempts >= 3 and row["status"] == "PENDING":
                conn.execute(
                    "UPDATE federation_invitations SET status = 'EXPIRED' WHERE invite_id = ?;",
                    (invite_id,),
                )
            return attempts

    def create_federation_grant(
        self,
        grant_id: str,
        network_id: str,
        network_name: str,
        peer_node_id: str,
        peer_node_name: str,
        peer_cert_fingerprint: str,
        direction: str,
        created_timestamp: str,
        expires_timestamp: str,
        allowed_capabilities_json: str,
        allowed_device_ids_json: str,
        auth_token_hash: str,
    ) -> None:
        """Persist an authorized federation grant."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO federation_grants (
                    grant_id, network_id, network_name, peer_node_id,
                    peer_node_name, peer_cert_fingerprint, direction,
                    status, created_timestamp, expires_timestamp,
                    allowed_capabilities_json, allowed_device_ids_json,
                    auth_token_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?);
                """,
                (
                    grant_id,
                    network_id,
                    network_name,
                    peer_node_id,
                    peer_node_name,
                    peer_cert_fingerprint,
                    direction,
                    created_timestamp,
                    expires_timestamp,
                    allowed_capabilities_json,
                    allowed_device_ids_json,
                    auth_token_hash,
                ),
            )

    def get_federation_grant(self, grant_id: str) -> Optional[dict[str, Any]]:
        """Fetch a federation grant by grant ID."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM federation_grants WHERE grant_id = ?;",
                (grant_id,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def get_federation_grant_by_token_hash(self, token_hash: str) -> Optional[dict[str, Any]]:
        """Lookup an active federation grant by credential token hash."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "SELECT * FROM federation_grants WHERE auth_token_hash = ?;",
                (token_hash,),
            )
            row = cur.fetchone()
            return dict(row) if row else None

    def list_federation_grants(self, active_only: bool = False) -> list[dict[str, Any]]:
        """List federation grants."""
        query = "SELECT * FROM federation_grants"
        params: tuple[Any, ...] = ()
        if active_only:
            query += " WHERE status = 'ACTIVE'"
        query += " ORDER BY created_timestamp DESC;"

        with self._get_connection() as conn:
            cur = conn.execute(query, params)
            return [dict(r) for r in cur.fetchall()]

    def revoke_federation_grant(self, grant_id: str, reason: str = "Revoked by owner") -> bool:
        """Revoke a single active federation grant."""
        now_str = current_utc_timestamp()
        with self._get_connection() as conn:
            cur = conn.execute(
                """
                UPDATE federation_grants
                SET status = 'REVOKED',
                    revoked_timestamp = ?,
                    revocation_reason = ?
                WHERE grant_id = ? AND status = 'ACTIVE';
                """,
                (now_str, reason, grant_id),
            )
            return cur.rowcount > 0

    def update_federation_grant_last_used(self, grant_id: str, timestamp_str: str) -> bool:
        """Update last used timestamp on a federation grant."""
        with self._get_connection() as conn:
            cur = conn.execute(
                "UPDATE federation_grants SET last_used_timestamp = ? WHERE grant_id = ?;",
                (timestamp_str, grant_id),
            )
            return cur.rowcount > 0

    def kill_all_federation(self, reason: str = "Global Kill Switch Activated") -> dict[str, int]:
        """Nuclear revocation: Revoke all active federation grants and expire pending invitations."""
        now_str = current_utc_timestamp()
        with self._get_connection() as conn:
            cur_grants = conn.execute(
                """
                UPDATE federation_grants
                SET status = 'REVOKED',
                    revoked_timestamp = ?,
                    revocation_reason = ?
                WHERE status = 'ACTIVE';
                """,
                (now_str, reason),
            )
            revoked_grants = cur_grants.rowcount

            cur_invites = conn.execute(
                """
                UPDATE federation_invitations
                SET status = 'REVOKED'
                WHERE status = 'PENDING';
                """,
            )
            revoked_invites = cur_invites.rowcount

            return {
                "revoked_grants": revoked_grants,
                "revoked_invites": revoked_invites,
            }

    # =========================================================================
    # OAuth 2.1 Persistence Operations (F22)
    # =========================================================================

    def save_oauth_client(
        self,
        client_id: str,
        client_name: str,
        redirect_uris: list[str],
        scope: str = "snow:mcp",
        client_secret_hash: Optional[str] = None,
        is_confidential: bool = False,
        created_at: Optional[float] = None,
    ) -> None:
        """Persist or update an OAuth 2.1 client registration record."""
        now = created_at if created_at is not None else time.time()
        redirect_json = json.dumps(redirect_uris)
        conf_int = 1 if is_confidential else 0
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO oauth_clients (
                    client_id, client_name, client_secret_hash,
                    redirect_uris_json, scope, is_confidential, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?);
                """,
                (client_id, client_name, client_secret_hash, redirect_json, scope, conf_int, now),
            )

    def get_oauth_client(self, client_id: str) -> Optional[dict[str, Any]]:
        """Retrieve a registered OAuth client by client_id."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM oauth_clients WHERE client_id = ?;",
                (client_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            try:
                redirect_uris = json.loads(row["redirect_uris_json"])
            except Exception:
                redirect_uris = []
            return {
                "client_id": row["client_id"],
                "client_name": row["client_name"],
                "client_secret_hash": row["client_secret_hash"],
                "redirect_uris": redirect_uris,
                "scope": row["scope"],
                "is_confidential": bool(row["is_confidential"]),
                "created_at": float(row["created_at"]),
            }

    def save_oauth_auth_code(
        self,
        code_hash: str,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        code_challenge_method: str = "S256",
        scope: str = "snow:mcp",
        expires_at: float = 0.0,
        created_at: Optional[float] = None,
    ) -> None:
        """Persist a single-use authorization code with PKCE binding."""
        now = created_at if created_at is not None else time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO oauth_auth_codes (
                    code_hash, client_id, redirect_uri,
                    code_challenge, code_challenge_method, scope,
                    expires_at, used, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?);
                """,
                (
                    code_hash,
                    client_id,
                    redirect_uri,
                    code_challenge,
                    code_challenge_method,
                    scope,
                    expires_at,
                    now,
                ),
            )

    def consume_oauth_auth_code(self, code_hash: str) -> Optional[dict[str, Any]]:
        """Atomically validate and consume an authorization code. Single-use only."""
        now = time.time()
        with self._get_connection() as conn:
            # Atomic single-use test-and-set: only the request that changes 0 -> 1 succeeds
            cursor = conn.execute(
                "UPDATE oauth_auth_codes SET used = 1 WHERE code_hash = ? AND used = 0 AND expires_at > ?;",
                (code_hash, now),
            )
            if cursor.rowcount != 1:
                return None

            # Fetch the consumed record
            cur2 = conn.execute(
                "SELECT * FROM oauth_auth_codes WHERE code_hash = ?;",
                (code_hash,),
            )
            row = cur2.fetchone()
            return dict(row) if row else None

    def save_oauth_token_record(
        self,
        access_token_hash: str,
        refresh_token_hash: str,
        client_id: str,
        scope: str,
        family_id: str,
        expires_at: float,
        refresh_expires_at: float,
        created_at: Optional[float] = None,
    ) -> None:
        """Persist an issued access and refresh token pair."""
        now = created_at if created_at is not None else time.time()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO oauth_tokens (
                    access_token_hash, refresh_token_hash, client_id,
                    scope, family_id, expires_at, refresh_expires_at,
                    revoked, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?);
                """,
                (
                    access_token_hash,
                    refresh_token_hash,
                    client_id,
                    scope,
                    family_id,
                    expires_at,
                    refresh_expires_at,
                    now,
                ),
            )

    def get_oauth_access_token(self, access_token_hash: str) -> Optional[dict[str, Any]]:
        """Validate access token hash and return token record if active and unexpired."""
        now = time.time()
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM oauth_tokens WHERE access_token_hash = ? AND revoked = 0;",
                (access_token_hash,),
            )
            row = cursor.fetchone()
            if not row:
                return None
            if now > float(row["expires_at"]):
                return None
            return dict(row)

    def get_oauth_refresh_token(self, refresh_token_hash: str) -> Optional[dict[str, Any]]:
        """Retrieve token record by refresh token hash (even if revoked, for replay detection)."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM oauth_tokens WHERE refresh_token_hash = ?;",
                (refresh_token_hash,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def rotate_oauth_refresh_token(
        self,
        old_refresh_token_hash: str,
        new_access_token_hash: str,
        new_refresh_token_hash: str,
        client_id: str,
        scope: str,
        family_id: str,
        expires_at: float,
        refresh_expires_at: float,
    ) -> bool:
        """Atomically invalidate old refresh token and issue new token pair."""
        now = time.time()
        with self._get_connection() as conn:
            # Mark old token as revoked
            conn.execute(
                "UPDATE oauth_tokens SET revoked = 1 WHERE refresh_token_hash = ?;",
                (old_refresh_token_hash,),
            )
            # Insert new token pair
            conn.execute(
                """
                INSERT INTO oauth_tokens (
                    access_token_hash, refresh_token_hash, client_id,
                    scope, family_id, expires_at, refresh_expires_at,
                    revoked, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?);
                """,
                (
                    new_access_token_hash,
                    new_refresh_token_hash,
                    client_id,
                    scope,
                    family_id,
                    expires_at,
                    refresh_expires_at,
                    now,
                ),
            )
            return True

    def revoke_oauth_family(self, family_id: str) -> int:
        """Revoke all tokens associated with a compromised token family."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "UPDATE oauth_tokens SET revoked = 1 WHERE family_id = ?;",
                (family_id,),
            )
            return cursor.rowcount

    def revoke_oauth_token(self, token_hash: str) -> bool:
        """Revoke an access token or refresh token by its hash."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                UPDATE oauth_tokens SET revoked = 1
                WHERE access_token_hash = ? OR refresh_token_hash = ?;
                """,
                (token_hash, token_hash),
            )
            return cursor.rowcount > 0

    # -------------------------------------------------------------------------
    # Clipboard Ring Buffer Persistence Methods (Batch 3)
    # -------------------------------------------------------------------------

    def save_clipboard_item(
        self,
        item_id: str,
        content_type: str,
        preview: str,
        source_device_id: str,
        source_device_name: str,
        timestamp: float,
        sha256: str,
        size_bytes: int,
        pinned: bool = False,
        text_content: Optional[str] = None,
        image_rel_path: Optional[str] = None,
        mime_type: Optional[str] = None,
        event_id: Optional[str] = None,
        seq: int = 0,
        file_manifest_json: Optional[str] = None,
        file_manifest: Optional[List[dict[str, Any]]] = None,
        canonical_sha256: Optional[str] = None,
        width: Optional[int] = None,
        height: Optional[int] = None,
    ) -> bool:
        """Insert or replace a clipboard ring buffer item in persistent storage."""
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise ValueError("Clipboard sequence number must be a non-negative integer.")

        if file_manifest_json is not None:
            if not isinstance(file_manifest_json, str):
                raise ValueError("file_manifest_json must be a JSON string.")
            manifest_str = file_manifest_json
        elif file_manifest is not None:
            manifest_str = json.dumps(file_manifest, separators=(",", ":"))
        else:
            manifest_str = "[]"

        clean_event_id = str(event_id).strip() if event_id is not None else None
        if clean_event_id == "":
            clean_event_id = None

        clean_canonical = str(canonical_sha256).strip().lower() if canonical_sha256 is not None else None
        if clean_canonical == "":
            clean_canonical = None

        clean_width = int(width) if isinstance(width, int) and not isinstance(width, bool) and width > 0 else None
        clean_height = int(height) if isinstance(height, int) and not isinstance(height, bool) and height > 0 else None

        query = """
            INSERT INTO clipboard_buffer_items (
                item_id, content_type, preview, source_device_id, source_device_name,
                timestamp, sha256, size_bytes, pinned, text_content, image_rel_path, mime_type,
                event_id, seq, file_manifest_json, canonical_sha256, width, height
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(item_id) DO UPDATE SET
                content_type = excluded.content_type,
                pinned = excluded.pinned,
                preview = excluded.preview,
                source_device_id = excluded.source_device_id,
                source_device_name = excluded.source_device_name,
                timestamp = excluded.timestamp,
                sha256 = excluded.sha256,
                size_bytes = excluded.size_bytes,
                text_content = excluded.text_content,
                image_rel_path = excluded.image_rel_path,
                mime_type = excluded.mime_type,
                event_id = excluded.event_id,
                seq = excluded.seq,
                file_manifest_json = excluded.file_manifest_json,
                canonical_sha256 = COALESCE(excluded.canonical_sha256, clipboard_buffer_items.canonical_sha256),
                width = COALESCE(excluded.width, clipboard_buffer_items.width),
                height = COALESCE(excluded.height, clipboard_buffer_items.height);
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    query,
                    (
                        item_id,
                        content_type,
                        preview,
                        source_device_id,
                        source_device_name,
                        timestamp,
                        sha256,
                        size_bytes,
                        1 if pinned else 0,
                        text_content,
                        image_rel_path,
                        mime_type,
                        clean_event_id,
                        seq,
                        manifest_str,
                        clean_canonical,
                        clean_width,
                        clean_height,
                    ),
                )
                return cursor.rowcount > 0

    def update_clipboard_canonical_metadata(
        self,
        item_id: str,
        canonical_sha256: Optional[str],
        width: Optional[int],
        height: Optional[int],
    ) -> bool:
        """Persist lazily hydrated canonical image metadata without overwriting other fields."""
        clean_canonical = str(canonical_sha256).strip().lower() if canonical_sha256 else None
        clean_w = int(width) if isinstance(width, int) and not isinstance(width, bool) and width > 0 else None
        clean_h = int(height) if isinstance(height, int) and not isinstance(height, bool) and height > 0 else None
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    """
                    UPDATE clipboard_buffer_items
                    SET canonical_sha256 = ?, width = ?, height = ?
                    WHERE item_id = ?;
                    """,
                    (clean_canonical, clean_w, clean_h, item_id),
                )
                return cursor.rowcount > 0

    def delete_clipboard_item(self, item_id: str) -> bool:
        """Delete a clipboard item from persistent storage."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute("DELETE FROM clipboard_buffer_items WHERE item_id = ?;", (item_id,))
                return cursor.rowcount > 0

    def update_clipboard_pinned(self, item_id: str, pinned: bool) -> bool:
        """Update pinned state of a clipboard buffer item."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(
                    "UPDATE clipboard_buffer_items SET pinned = ? WHERE item_id = ?;",
                    (1 if pinned else 0, item_id),
                )
                return cursor.rowcount > 0

    def load_all_clipboard_items(self) -> List[dict[str, Any]]:
        """Load all persistent clipboard buffer items ordered newest-first."""
        query = "SELECT * FROM clipboard_buffer_items ORDER BY seq DESC, timestamp DESC;"
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.execute(query)
                return [dict(row) for row in cursor.fetchall()]

    def clear_clipboard_items(self, unpinned_only: bool = False) -> int:
        """Clear clipboard buffer items from persistent storage."""
        with self._lock:
            with self._get_connection() as conn:
                if unpinned_only:
                    cursor = conn.execute("DELETE FROM clipboard_buffer_items WHERE pinned = 0;")
                else:
                    cursor = conn.execute("DELETE FROM clipboard_buffer_items;")
                return cursor.rowcount

    @staticmethod
    def _validate_clipboard_ack_device_id(device_id: Any) -> str:
        if not isinstance(device_id, str):
            raise ValueError("device_id must be a non-empty string.")
        clean = device_id.strip()
        if not clean or len(clean) > 128:
            raise ValueError("device_id must be between 1 and 128 characters.")
        if any(ord(ch) < 32 or ch in ("/", "\\", "\x00") or ch.isspace() for ch in clean):
            raise ValueError("device_id contains invalid characters.")
        if clean in (".", "..") or ".." in clean:
            raise ValueError("device_id contains disallowed path segments.")
        return clean

    @staticmethod
    def _parse_clipboard_ack_json(raw_value: Optional[str], expected_device_id: str) -> Optional[dict[str, Any]]:
        if not raw_value or not isinstance(raw_value, str):
            return None
        try:
            parsed = json.loads(raw_value)
        except Exception:
            logger.warning("Corrupt clipboard ack JSON for device %s; failing closed.", expected_device_id)
            return None
        if not isinstance(parsed, dict):
            logger.warning("Malformed clipboard ack payload type for device %s; failing closed.", expected_device_id)
            return None
        seq = parsed.get("last_acked_seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            logger.warning("Invalid last_acked_seq in clipboard ack for device %s; failing closed.", expected_device_id)
            return None
        event_id = parsed.get("last_acked_event_id", "")
        if event_id is None:
            event_id = ""
        if not isinstance(event_id, str) or len(event_id) > 128:
            logger.warning("Invalid last_acked_event_id in clipboard ack for device %s; failing closed.", expected_device_id)
            return None
        updated_at = parsed.get("updated_at")
        if updated_at is not None and (isinstance(updated_at, bool) or not isinstance(updated_at, (int, float))):
            logger.warning("Invalid updated_at in clipboard ack for device %s; failing closed.", expected_device_id)
            return None
        return {
            "device_id": expected_device_id,
            "last_acked_seq": seq,
            "last_acked_event_id": event_id.strip(),
            "updated_at": float(updated_at) if updated_at is not None else 0.0,
        }

    def get_clipboard_ack(self, device_id: str) -> Optional[dict[str, Any]]:
        """Retrieve the durable monotonic clipboard acknowledgement state for a peer."""
        try:
            clean_id = self._validate_clipboard_ack_device_id(device_id)
        except ValueError:
            return None
        raw = self.get_setting(f"clip_ack:{clean_id}")
        return self._parse_clipboard_ack_json(raw, clean_id)

    def save_clipboard_ack(
        self,
        device_id: str,
        last_acked_seq: int,
        last_acked_event_id: str = "",
        updated_at: Optional[float] = None,
    ) -> dict[str, Any]:
        """Persist a monotonic per-device clipboard acknowledgement in app_settings."""
        clean_id = self._validate_clipboard_ack_device_id(device_id)
        if isinstance(last_acked_seq, bool) or not isinstance(last_acked_seq, int) or last_acked_seq < 0:
            raise ValueError("last_acked_seq must be a non-negative integer.")
        if last_acked_event_id is None:
            clean_event_id = ""
        elif isinstance(last_acked_event_id, str):
            clean_event_id = last_acked_event_id.strip()
            if len(clean_event_id) > 128 or any(ord(ch) < 32 for ch in clean_event_id):
                raise ValueError("last_acked_event_id is invalid.")
        else:
            raise ValueError("last_acked_event_id must be a string.")

        ts = float(updated_at) if updated_at is not None else time.time()
        setting_key = f"clip_ack:{clean_id}"

        with self._lock:
            with self._get_connection() as conn:
                cur = conn.execute("SELECT value FROM app_settings WHERE key = ?;", (setting_key,))
                row = cur.fetchone()
                existing = self._parse_clipboard_ack_json(row["value"] if row else None, clean_id)
                if existing and last_acked_seq < existing["last_acked_seq"]:
                    return {
                        **existing,
                        "updated": False,
                        "monotonic_retained": True,
                    }

                record = {
                    "device_id": clean_id,
                    "last_acked_seq": last_acked_seq,
                    "last_acked_event_id": clean_event_id or (existing["last_acked_event_id"] if existing and last_acked_seq == existing["last_acked_seq"] else ""),
                    "updated_at": ts,
                }
                conn.execute(
                    """
                    INSERT INTO app_settings (key, value)
                    VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value;
                    """,
                    (setting_key, json.dumps(record, separators=(",", ":"))),
                )
                return {
                    **record,
                    "updated": True,
                    "monotonic_retained": False,
                }

    def list_clipboard_acks(self) -> dict[str, dict[str, Any]]:
        """List all valid durable clipboard acknowledgements keyed by device_id."""
        with self._lock:
            entries = self.list_settings_prefix("clip_ack:")
        result: dict[str, dict[str, Any]] = {}
        for key, val in entries.items():
            dev_id = key[len("clip_ack:") :]
            parsed = self._parse_clipboard_ack_json(val, dev_id)
            if parsed is not None:
                result[dev_id] = parsed
        return result

    def delete_clipboard_ack(self, device_id: str) -> bool:
        """Delete stored clipboard acknowledgement state for a removed device."""
        try:
            clean_id = self._validate_clipboard_ack_device_id(device_id)
        except ValueError:
            return False
        with self._lock:
            return self.delete_setting(f"clip_ack:{clean_id}")


SENSITIVE_KEY_PATTERNS = {
    "pin",
    "token",
    "secret",
    "key",
    "password",
    "auth",
    "clipboard",
    "notification_body",
    "body",
    "cert_fingerprint",
    "auth_token_hash",
}


def redact_sensitive_data(val: Any) -> Any:
    """Recursively scrub sensitive keys and secrets from data structures.

    Guarantees raw PINs, tokens, keys, passwords, clipboard contents, and notification
    bodies are permanently redacted before activity history storage or audit inspection.
    """
    if isinstance(val, dict):
        scrubbed = {}
        for k, v in val.items():
            k_lower = str(k).lower()
            if any(p in k_lower for p in SENSITIVE_KEY_PATTERNS):
                scrubbed[k] = "[REDACTED]"
            else:
                scrubbed[k] = redact_sensitive_data(v)
        return scrubbed
    elif isinstance(val, list):
        return [redact_sensitive_data(item) for item in val]
    return val
