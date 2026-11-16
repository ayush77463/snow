"""In-memory active session manager for SNOW Desktop Core.

Tracks currently authenticated, active device sessions. Does not persist across server restarts;
previously paired devices authenticate on reconnect using their retained token.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import threading
from typing import Dict, List, Optional
import uuid

logger = logging.getLogger(__name__)


def current_utc_timestamp() -> str:
    """Generate a strict UTC ISO-8601 formatted timestamp string."""
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SessionRecord:
    """Immutable representation of an active device session."""

    session_id: str
    device_id: str
    connection_id: Optional[str]
    created_at: str
    last_seen: str


class SessionManager:
    """Thread-safe in-memory session manager for authenticated connections."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sessions: Dict[str, SessionRecord] = {}
        self._device_to_session: Dict[str, str] = {}
        self._connection_to_session: Dict[str, str] = {}

    def create_session(
        self, device_id: str, connection_id: Optional[str] = None
    ) -> SessionRecord:
        """Create a new active session for a verified device.

        Any existing session for this device is superseded and revoked.
        """
        with self._lock:
            # Revoke prior session for this device if present
            prior_sid = self._device_to_session.get(device_id)
            if prior_sid and prior_sid in self._sessions:
                self._revoke_locked(prior_sid)

            now = current_utc_timestamp()
            sid = str(uuid.uuid4())
            record = SessionRecord(
                session_id=sid,
                device_id=device_id,
                connection_id=connection_id,
                created_at=now,
                last_seen=now,
            )

            self._sessions[sid] = record
            self._device_to_session[device_id] = sid
            if connection_id:
                self._connection_to_session[connection_id] = sid

            logger.info("Created active session [%s] for device [%s]", sid, device_id)
            return record

    def get_session(self, session_id: str) -> Optional[SessionRecord]:
        """Look up an active session by its session_id."""
        with self._lock:
            return self._sessions.get(session_id)

    def get_session_by_device(self, device_id: str) -> Optional[SessionRecord]:
        """Look up the active session for a given device_id."""
        with self._lock:
            sid = self._device_to_session.get(device_id)
            if sid:
                return self._sessions.get(sid)
            return None

    def get_session_by_connection(self, connection_id: str) -> Optional[SessionRecord]:
        """Look up the active session associated with a WebSocket connection_id."""
        with self._lock:
            sid = self._connection_to_session.get(connection_id)
            if sid:
                return self._sessions.get(sid)
            return None

    def touch_session(self, session_id: str) -> bool:
        """Update the last-seen timestamp of an active session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            updated = SessionRecord(
                session_id=session.session_id,
                device_id=session.device_id,
                connection_id=session.connection_id,
                created_at=session.created_at,
                last_seen=current_utc_timestamp(),
            )
            self._sessions[session_id] = updated
            return True

    def revoke_session(self, session_id: str) -> bool:
        """Explicitly revoke and remove an active session."""
        with self._lock:
            return self._revoke_locked(session_id)

    def revoke_device_sessions(self, device_id: str) -> int:
        """Revoke any active session registered for a device."""
        with self._lock:
            sid = self._device_to_session.get(device_id)
            if sid and self._revoke_locked(sid):
                return 1
            return 0

    def cleanup_connection(self, connection_id: str) -> Optional[SessionRecord]:
        """Clean up session association when a client connection closes."""
        with self._lock:
            sid = self._connection_to_session.pop(connection_id, None)
            if sid:
                # Do not immediately delete session; device may reconnect.
                # Just detach the dead connection_id.
                session = self._sessions.get(sid)
                if session:
                    updated = SessionRecord(
                        session_id=session.session_id,
                        device_id=session.device_id,
                        connection_id=None,
                        created_at=session.created_at,
                        last_seen=session.last_seen,
                    )
                    self._sessions[sid] = updated
                    return updated
            return None

    def list_active_sessions(self) -> List[SessionRecord]:
        """Return a snapshot of all active sessions."""
        with self._lock:
            return list(self._sessions.values())

    def clear_all(self) -> None:
        """Clear all active sessions (e.g. on shutdown)."""
        with self._lock:
            self._sessions.clear()
            self._device_to_session.clear()
            self._connection_to_session.clear()

    def _revoke_locked(self, session_id: str) -> bool:
        """Internal helper to remove session state while holding _lock."""
        session = self._sessions.pop(session_id, None)
        if session:
            self._device_to_session.pop(session.device_id, None)
            if session.connection_id:
                self._connection_to_session.pop(session.connection_id, None)
            logger.info("Revoked active session [%s] for device [%s]", session_id, session.device_id)
            return True
        return False
