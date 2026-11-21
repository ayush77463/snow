"""Ephemeral in-memory presence and rendezvous control plane for the SNOW Relay."""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
import time
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

STATE_ONLINE_RELAY = "ONLINE_RELAY"
STATE_DORMANT_RELAY = "DORMANT_RELAY"
STATE_OFFLINE = "OFFLINE"


@dataclass
class RelayPresenceRecord:
    """Ephemeral presence metadata for a connected device."""

    device_id: str
    group_id: str
    state: str = STATE_ONLINE_RELAY
    last_seen: float = field(default_factory=time.time)
    connected_at: float = field(default_factory=time.time)
    ws_session: Optional[Any] = None
    is_revoked: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "group_id": self.group_id,
            "state": self.state,
            "last_seen": self.last_seen,
            "connected_at": self.connected_at,
            "is_revoked": self.is_revoked,
        }


class RendezvousRegistry:
    """In-memory presence registry tracking active relay endpoints and group routing."""

    def __init__(
        self,
        presence_stale_seconds: float = 120.0,
        dormant_timeout_seconds: float = 300.0,
        max_connections_per_group: int = 10,
    ) -> None:
        self.presence_stale_seconds = presence_stale_seconds
        self.dormant_timeout_seconds = dormant_timeout_seconds
        self.max_connections_per_group = max_connections_per_group

        # device_id -> RelayPresenceRecord
        self._devices: Dict[str, RelayPresenceRecord] = {}
        # group_id -> set of device_id
        self._groups: Dict[str, Set[str]] = {}
        # set of revoked device_ids
        self._revoked_devices: Set[str] = set()

    def register(self, device_id: str, group_id: str, ws_session: Any) -> Tuple[bool, str]:
        """Register an active device connection in its authorized destination group."""
        if device_id in self._revoked_devices:
            return False, "Device is permanently revoked from this relay."

        group_members = self._groups.setdefault(group_id, set())
        if device_id not in group_members and len(group_members) >= self.max_connections_per_group:
            return False, f"Maximum connections ({self.max_connections_per_group}) reached for group."

        now = time.time()
        record = RelayPresenceRecord(
            device_id=device_id,
            group_id=group_id,
            state=STATE_ONLINE_RELAY,
            last_seen=now,
            connected_at=now,
            ws_session=ws_session,
            is_revoked=False,
        )
        self._devices[device_id] = record
        group_members.add(device_id)
        logger.info("Relay rendezvous: Device [%s] is now ONLINE_RELAY in group [%s]", device_id, group_id)
        return True, ""

    def update_last_seen(self, device_id: str) -> None:
        """Update heartbeat timestamp for an active device."""
        record = self._devices.get(device_id)
        if record:
            record.last_seen = time.time()
            if record.state == STATE_DORMANT_RELAY:
                record.state = STATE_ONLINE_RELAY

    def mark_dormant(self, device_id: str) -> None:
        """Mark an idle or disconnected device as DORMANT_RELAY without unpairing."""
        record = self._devices.get(device_id)
        if record:
            record.state = STATE_DORMANT_RELAY
            record.ws_session = None
            logger.info("Relay rendezvous: Device [%s] transitioned to DORMANT_RELAY", device_id)

    def unregister(self, device_id: str) -> None:
        """Remove a device connection upon clean disconnect."""
        record = self._devices.pop(device_id, None)
        if record:
            group = self._groups.get(record.group_id)
            if group and device_id in group:
                group.remove(device_id)
                if not group:
                    self._groups.pop(record.group_id, None)
            logger.info("Relay rendezvous: Device [%s] unregistered", device_id)

    def revoke_device(self, device_id: str) -> Optional[Any]:
        """Revoke a device. Returns its active ws_session if one was open, so caller can close it."""
        self._revoked_devices.add(device_id)
        record = self._devices.pop(device_id, None)
        ws = None
        if record:
            record.is_revoked = True
            ws = record.ws_session
            group = self._groups.get(record.group_id)
            if group and device_id in group:
                group.remove(device_id)
        logger.warning("Relay rendezvous: Device [%s] REVOKED", device_id)
        return ws

    def get_peer_session(self, source_device_id: str, target_device_id: str) -> Tuple[Optional[Any], str]:
        """Lookup active destination WebSocket session within the same authorized destination group."""
        if source_device_id in self._revoked_devices:
            return None, "Source device is revoked."
        src = self._devices.get(source_device_id)
        if not src:
            return None, "Source device is not registered on relay."
        if src.is_revoked:
            return None, "Source device is revoked."

        if target_device_id in self._revoked_devices:
            return None, f"Destination device '{target_device_id}' is revoked."
        tgt = self._devices.get(target_device_id)
        if not tgt:
            return None, f"Destination device '{target_device_id}' is OFFLINE."
        if tgt.is_revoked:
            return None, f"Destination device '{target_device_id}' is revoked."
        if tgt.group_id != src.group_id:
            return None, f"Cross-group routing denied: '{target_device_id}' is in a different destination group."
        if tgt.state == STATE_DORMANT_RELAY or tgt.ws_session is None:
            return None, f"Destination device '{target_device_id}' is DORMANT_RELAY (unreachable)."

        return tgt.ws_session, ""

    def get_presence(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve presence dictionary for a device."""
        record = self._devices.get(device_id)
        if not record:
            return {"device_id": device_id, "state": STATE_OFFLINE}
        return record.to_dict()

    def list_group_peers(self, group_id: str) -> List[Dict[str, Any]]:
        """List presence of all devices enrolled in a destination group."""
        device_ids = self._groups.get(group_id, set())
        results = []
        for did in device_ids:
            rec = self._devices.get(did)
            if rec:
                results.append(rec.to_dict())
        return results

    def sweep_stale_sessions(self) -> List[Any]:
        """Sweep expired sessions and return sockets that should be closed."""
        now = time.time()
        to_close = []
        dormant_keys = []
        expired_keys = []

        for did, rec in self._devices.items():
            age = now - rec.last_seen
            if rec.state == STATE_ONLINE_RELAY and age > self.presence_stale_seconds:
                dormant_keys.append(did)
            elif rec.state == STATE_DORMANT_RELAY and age > self.dormant_timeout_seconds:
                expired_keys.append(did)

        for did in dormant_keys:
            rec = self._devices[did]
            if rec.ws_session:
                to_close.append(rec.ws_session)
            self.mark_dormant(did)

        for did in expired_keys:
            self.unregister(did)

        return to_close
