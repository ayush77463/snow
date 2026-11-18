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
from typing import Any, Generator, List, Optional
import uuid

logger = logging.getLogger(__name__)

DEFAULT_DB_FILENAME = "snow_devices.db"
SCHEMA_VERSION = 3

VALID_TRUST_TIERS = ("owner", "peer")


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
                        capabilities_json TEXT NOT NULL DEFAULT '{}'
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

                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_paired_devices_trust_tier
                    ON paired_devices(trust_tier);
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

                conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION};")

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

        Returns:
            The created PairedDeviceRecord.

        Raises:
            ValueError: If trust_tier is not 'owner' or 'peer'.
            sqlite3.IntegrityError: If device_id or auth_token_hash is not unique.
        """
        if trust_tier not in VALID_TRUST_TIERS:
            raise ValueError(
                f"Invalid trust_tier '{trust_tier}'. Must be one of: {', '.join(VALID_TRUST_TIERS)}"
            )

        now = current_utc_timestamp()
        p_time = pairing_timestamp or now
        ls_time = last_seen_timestamp or now

        query = """
            INSERT INTO paired_devices (
                device_id, device_name, pairing_timestamp, last_seen_timestamp, auth_token_hash,
                trust_tier, platform, reachability_profile, last_known_host, last_known_port, capabilities_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        with self._get_connection() as conn:
            if trust_tier == "owner":
                # Enforce single primary owner invariant by demoting other owners
                conn.execute(
                    "UPDATE paired_devices SET trust_tier = 'peer' WHERE trust_tier = 'owner' AND device_id != ?;",
                    (device_id,),
                )
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
        )

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

    def update_device_trust_tier(self, device_id: str, trust_tier: str) -> bool:
        """Update the trust tier for a registered paired device.

        Args:
            device_id: UUID of the paired device.
            trust_tier: New trust tier ('owner' or 'peer').

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
            if trust_tier == "owner":
                # Enforce single primary owner invariant by demoting other owners
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
                return PairedDeviceRecord(
                    device_id=row["device_id"],
                    device_name=row["device_name"],
                    pairing_timestamp=row["pairing_timestamp"],
                    last_seen_timestamp=row["last_seen_timestamp"],
                    auth_token_hash=row["auth_token_hash"],
                    trust_tier=row["trust_tier"],
                )
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
