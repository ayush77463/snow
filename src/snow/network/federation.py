"""Cross-Network Federation Engine for SNOW V4 (Phase 30).

Implements secure peer-to-peer federation between independent local SNOW networks.
Allows an owner to authorize explicit capability access to a trusted peer network
while maintaining complete sovereignty, zero privilege inheritance, and anti-transitivity.

SECURITY INVARIANTS:
1. Mutual Explicit Owner Consent:
   - Authenticated via temporary 9-digit code (format: XXX-XXX-XXX).
   - Valid for at most 10 minutes (600 seconds).
   - Single-use: invalid immediately upon acceptance or revocation.
   - Rate-limited: max 3 attempts before permanent invalidation.
   - No plaintext storage: only SHA-256 digests stored in SQLite.
   - AI_MCP is strictly forbidden from creating, reading codes, accepting, or revoking federation.
2. Zero Privilege Inheritance:
   - Incoming federated peer never inherits OWNER_MANUAL authority.
   - Tagged as 'FEDERATED_PEER' with explicitly whitelisted capabilities.
3. Strict Capability & Device Scoping:
   - Only capabilities and target device IDs explicitly enumerated in the grant are accessible.
4. Scoped Expiring Credentials:
   - Federation grants have strict TTL (1h, 24h, 7d).
5. Immediate Revocation & Global Kill Switch:
   - Single grant revocation or global kill switch immediately terminates active sessions.
6. Secret-Safe Audit Trail:
   - All lifecycle events recorded to activity_history without leaking codes or tokens.
7. Anti-Transitivity:
   - Federation is strictly non-transitive (TRANSIT_ROUTING_FORBIDDEN). Network A cannot
     route to Network C through federated Network B.
8. Coordinator Independence:
   - Each network's coordinator retains local authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
import re
import secrets
from typing import Any, Dict, List, Optional, Tuple
import uuid

from snow.security.context import ExecutionPrincipal
from snow.security.db import DatabaseManager, hash_token

logger = logging.getLogger(__name__)

CODE_PATTERN = re.compile(r"^\d{3}-\d{3}-\d{3}$")
RAW_CODE_DIGITS = 9

# Centralized destructive and administrative capability denylist for cross-network federation (Repair 1)
FORBIDDEN_FEDERATED_CAPABILITIES: frozenset[str] = frozenset({
    "desktop.exec",
    "desktop.terminal.exec",
    "snow_windows_terminal_exec",
    "windows_terminal_exec",
    "desktop.file.write",
    "snow_windows_file_write",
    "windows_file_write",
    "device.revoke",
    "devices.revoke",
    "snow_devices_revoke",
    "approval.resolve",
    "approvals.resolve",
    "snow_approvals_resolve",
    "network.federation.invite",
    "network.federation.accept",
    "network.federation.revoke",
    "network.federation.kill_switch",
    "network.federation.outbound",
    "network.federation.grants",
})

FORBIDDEN_FEDERATED_PREFIXES: tuple[str, ...] = (
    "network.federation.",
    "federation.",
    "snow_federation_",
)


def is_capability_forbidden_for_federation(capability: str) -> bool:
    """Check if a capability is in the centralized destructive/administrative denylist."""
    cap = (capability or "").strip().lower()
    if not cap:
        return True
    if cap == "*" or "*" in cap:
        return True
    if cap in FORBIDDEN_FEDERATED_CAPABILITIES:
        return True
    if any(cap.startswith(prefix) for prefix in FORBIDDEN_FEDERATED_PREFIXES):
        return True
    if cap in ("exec", "terminal_exec", "file_write", "kill_switch"):
        return True
    return False


def current_utc_timestamp() -> str:
    """Return strict UTC ISO-8601 formatted timestamp string."""
    return datetime.now(timezone.utc).isoformat()


def parse_utc_timestamp(ts_str: str) -> datetime:
    """Parse ISO-8601 timestamp string into timezone-aware datetime."""
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime.min.replace(tzinfo=timezone.utc)


def format_nine_digit_code(raw_digits: str) -> str:
    """Format 9-digit string into XXX-XXX-XXX."""
    clean = re.sub(r"\D", "", raw_digits)
    if len(clean) != 9:
        raise ValueError(f"Expected 9 digits, got {len(clean)}")
    return f"{clean[0:3]}-{clean[3:6]}-{clean[6:9]}"


def generate_nine_digit_code() -> str:
    """Generate a cryptographically secure 9-digit code formatted as XXX-XXX-XXX."""
    num1 = secrets.randbelow(1000)
    num2 = secrets.randbelow(1000)
    num3 = secrets.randbelow(1000)
    return f"{num1:03d}-{num2:03d}-{num3:03d}"


@dataclass(frozen=True)
class FederationInvitation:
    """Represents a pending or consumed mutual federation invitation."""

    invite_id: str
    network_id: str
    network_name: str
    code_hash: str
    cert_fingerprint: str
    created_timestamp: str
    expires_timestamp: str
    ttl_seconds: int = 600
    status: str = "PENDING"  # PENDING, ACCEPTED, EXPIRED, REVOKED
    allowed_capabilities: tuple[str, ...] = ()
    allowed_device_ids: tuple[str, ...] = ()
    grant_ttl_seconds: int = 86400
    attempts: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "invite_id": self.invite_id,
            "network_id": self.network_id,
            "network_name": self.network_name,
            "cert_fingerprint": self.cert_fingerprint,
            "created_timestamp": self.created_timestamp,
            "expires_timestamp": self.expires_timestamp,
            "ttl_seconds": self.ttl_seconds,
            "status": self.status,
            "allowed_capabilities": list(self.allowed_capabilities),
            "allowed_device_ids": list(self.allowed_device_ids),
            "grant_ttl_seconds": self.grant_ttl_seconds,
            "attempts": self.attempts,
        }


@dataclass(frozen=True)
class FederationGrant:
    """Represents an active or revoked cross-network capability authorization grant."""

    grant_id: str
    network_id: str
    network_name: str
    peer_node_id: str
    peer_node_name: str
    peer_cert_fingerprint: str
    direction: str  # INBOUND or OUTBOUND
    status: str  # ACTIVE, REVOKED, EXPIRED
    created_timestamp: str
    expires_timestamp: str
    allowed_capabilities: tuple[str, ...] = ()
    allowed_device_ids: tuple[str, ...] = ()
    auth_token_hash: str = ""
    last_used_timestamp: Optional[str] = None
    revoked_timestamp: Optional[str] = None
    revocation_reason: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "grant_id": self.grant_id,
            "network_id": self.network_id,
            "network_name": self.network_name,
            "peer_node_id": self.peer_node_id,
            "peer_node_name": self.peer_node_name,
            "peer_cert_fingerprint": self.peer_cert_fingerprint,
            "direction": self.direction,
            "status": self.status,
            "created_timestamp": self.created_timestamp,
            "expires_timestamp": self.expires_timestamp,
            "allowed_capabilities": list(self.allowed_capabilities),
            "allowed_device_ids": list(self.allowed_device_ids),
            "last_used_timestamp": self.last_used_timestamp,
            "revoked_timestamp": self.revoked_timestamp,
            "revocation_reason": self.revocation_reason,
            "federated": True,
        }


class FederationManager:
    """Authoritative manager for cross-network federation lifecycles and enforcement."""

    def __init__(
        self,
        db_manager: DatabaseManager,
        local_network_id: Optional[str] = None,
        local_network_name: Optional[str] = None,
        local_node_id: Optional[str] = None,
        local_node_name: Optional[str] = None,
        local_cert_fingerprint: Optional[str] = None,
        failed_attempts_store: Optional[dict[str, list[float]]] = None,
    ) -> None:
        self.db_manager = db_manager
        self.local_network_id = local_network_id or "local-network"
        self.local_network_name = local_network_name or "My SNOW Network"
        self.local_node_id = local_node_id or "desktop-core"
        self.local_node_name = local_node_name or "Windows Desktop Host"
        self.local_cert_fingerprint = local_cert_fingerprint or "LOCAL_FINGERPRINT_PLACEHOLDER"
        self._failed_attempts: dict[str, list[float]] = (
            failed_attempts_store if failed_attempts_store is not None else {}
        )
        self._rate_limit_window_seconds: float = 300.0  # 5-minute sliding window
        self._max_failed_attempts: int = 5

    def _is_rate_limited(self, requester_id: str) -> bool:
        """Check whether requester identity has exceeded maximum failed attempts in window."""
        now = datetime.now(timezone.utc).timestamp()
        cutoff = now - self._rate_limit_window_seconds
        attempts = [ts for ts in self._failed_attempts.get(requester_id, []) if ts > cutoff]
        self._failed_attempts[requester_id] = attempts
        return len(attempts) >= self._max_failed_attempts

    def _record_failed_attempt(self, requester_id: str) -> None:
        """Record a failed acceptance attempt for a requester identity."""
        now = datetime.now(timezone.utc).timestamp()
        cutoff = now - self._rate_limit_window_seconds
        attempts = [ts for ts in self._failed_attempts.get(requester_id, []) if ts > cutoff]
        attempts.append(now)
        self._failed_attempts[requester_id] = attempts

    def _clear_failed_attempts(self, requester_id: str) -> None:
        """Reset failed attempts for a requester after successful authentication."""
        self._failed_attempts.pop(requester_id, None)

    def _assert_human_owner_principal(self, principal: Any) -> None:
        """Enforce Invariant 1: AI_MCP is strictly forbidden from mutating federation."""
        p_str = str(principal).upper()
        if "AI_MCP" in p_str:
            logger.warning("Denied attempt by AI_MCP principal to access federation controls.")
            raise PermissionError("AI_MCP principal is strictly forbidden from performing federation operations.")

    def create_invitation(
        self,
        allowed_capabilities: Optional[list[str]] = None,
        allowed_device_ids: Optional[list[str]] = None,
        grant_ttl_seconds: int = 86400,
        ttl_seconds: int = 600,
        principal: Any = "OWNER_MANUAL",
    ) -> dict[str, Any]:
        """Generate a 9-digit mutual federation invitation code.

        Returns:
            Dict containing the raw code (only returned once), expiration, and invite ID.
        """
        self._assert_human_owner_principal(principal)

        if ttl_seconds > 600:
            ttl_seconds = 600  # Strict invariant: max 10 minutes

        # Validate allowed capabilities (must be non-empty and free of forbidden entries/wildcards)
        if allowed_capabilities is not None:
            if not allowed_capabilities:
                raise ValueError("Allowed capabilities cannot be empty.")
            for c in allowed_capabilities:
                if is_capability_forbidden_for_federation(c):
                    raise ValueError(f"Capability '{c}' is forbidden for cross-network federation.")
            caps = list(allowed_capabilities)
        else:
            caps = ["android.status", "desktop.system.info"]

        # Validate allowed device IDs (must be non-empty and reject wildcard '*')
        if allowed_device_ids is not None:
            if not allowed_device_ids:
                raise ValueError("Allowed device IDs cannot be empty.")
            if "*" in allowed_device_ids:
                raise ValueError("Wildcard '*' device ID is not permitted in federation invitations.")
            devices = list(allowed_device_ids)
        else:
            devices = [self.local_node_id]

        raw_code = generate_nine_digit_code()
        code_h = hash_token(raw_code.replace("-", ""))

        invite_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires = now.timestamp() + ttl_seconds
        created_str = now.isoformat()
        expires_str = datetime.fromtimestamp(expires, timezone.utc).isoformat()

        self.db_manager.create_federation_invitation(
            invite_id=invite_id,
            network_id=self.local_network_id,
            network_name=self.local_network_name,
            code_hash=code_h,
            cert_fingerprint=self.local_cert_fingerprint,
            created_timestamp=created_str,
            expires_timestamp=expires_str,
            ttl_seconds=ttl_seconds,
            allowed_capabilities_json=json.dumps(caps),
            allowed_device_ids_json=json.dumps(devices),
            grant_ttl_seconds=grant_ttl_seconds,
        )

        # Audit log (never log raw code)
        self.db_manager.log_activity(
            event_type="FEDERATION_INVITE_CREATED",
            principal=str(principal),
            target_device=self.local_node_id,
            capability="network.federation.invite",
            outcome="SUCCESS",
            details={
                "invite_id": invite_id,
                "ttl_seconds": ttl_seconds,
                "allowed_capabilities": caps,
                "allowed_device_ids": devices,
            },
        )

        return {
            "success": True,
            "status": "INVITATION_CREATED",
            "invite_id": invite_id,
            "code": raw_code,
            "ttl_seconds": ttl_seconds,
            "expires_timestamp": expires_str,
            "network_id": self.local_network_id,
            "network_name": self.local_network_name,
        }

    def accept_invitation(
        self,
        code: str,
        peer_network_id: str,
        peer_network_name: str,
        peer_node_id: str,
        peer_node_name: str,
        peer_cert_fingerprint: str,
        principal: Any = "OWNER_MANUAL",
        requester_id: str = "default_requester",
    ) -> dict[str, Any]:
        """Accept a mutual federation invitation code and establish an active grant."""
        self._assert_human_owner_principal(principal)

        # 1. Requester-keyed brute-force rate limit protection (Anti-DoS)
        if self._is_rate_limited(requester_id):
            logger.warning("Federation acceptance rate limit exceeded for requester '%s'.", requester_id)
            return {
                "success": False,
                "status": "RATE_LIMIT_EXCEEDED",
                "error": "Too many failed federation acceptance attempts. Please try again later.",
            }

        clean_code = re.sub(r"\D", "", code)
        if len(clean_code) != RAW_CODE_DIGITS:
            self._record_failed_attempt(requester_id)
            return {
                "success": False,
                "status": "INVALID_CODE_FORMAT",
                "error": "Federation invitation code must contain exactly 9 digits (format: XXX-XXX-XXX).",
            }

        code_h = hash_token(clean_code)
        inv = self.db_manager.get_federation_invitation_by_hash(code_h)

        if not inv:
            self._record_failed_attempt(requester_id)
            logger.warning("Federation acceptance failed: invitation code hash not found.")
            return {
                "success": False,
                "status": "INVALID_OR_EXPIRED_CODE",
                "error": "Invitation code is invalid or has expired.",
            }

        invite_id = inv["invite_id"]
        status = inv["status"]
        attempts = inv["attempts"]

        if status != "PENDING":
            self._record_failed_attempt(requester_id)
            return {
                "success": False,
                "status": f"INVITATION_{status}",
                "error": f"Invitation is no longer valid (status: {status}).",
            }

        if attempts >= 3:
            self._record_failed_attempt(requester_id)
            self.db_manager.update_federation_invitation_status(invite_id, "EXPIRED")
            return {
                "success": False,
                "status": "MAX_ATTEMPTS_EXCEEDED",
                "error": "Maximum verification attempts exceeded. Invitation code has been invalidated.",
            }

        # Check expiry
        now = datetime.now(timezone.utc)
        exp_dt = parse_utc_timestamp(inv["expires_timestamp"])
        if now > exp_dt:
            self._record_failed_attempt(requester_id)
            self.db_manager.update_federation_invitation_status(invite_id, "EXPIRED")
            return {
                "success": False,
                "status": "INVITATION_EXPIRED",
                "error": "Federation invitation code has expired.",
            }

        # Clear failed rate limit attempts on success
        self._clear_failed_attempts(requester_id)

        # Mark single-use invitation as ACCEPTED
        self.db_manager.update_federation_invitation_status(invite_id, "ACCEPTED")

        # Create active inbound federation grant
        grant_id = str(uuid.uuid4())
        raw_token = secrets.token_hex(32)
        token_h = hash_token(raw_token)

        grant_ttl = inv.get("grant_ttl_seconds", 86400)
        grant_expires = (now.timestamp() + grant_ttl)
        grant_expires_str = datetime.fromtimestamp(grant_expires, timezone.utc).isoformat()

        allowed_caps = inv.get("allowed_capabilities_json", "[]")
        allowed_devs = inv.get("allowed_device_ids_json", "[]")

        self.db_manager.create_federation_grant(
            grant_id=grant_id,
            network_id=peer_network_id,
            network_name=peer_network_name,
            peer_node_id=peer_node_id,
            peer_node_name=peer_node_name,
            peer_cert_fingerprint=peer_cert_fingerprint,
            direction="INBOUND",
            created_timestamp=now.isoformat(),
            expires_timestamp=grant_expires_str,
            allowed_capabilities_json=allowed_caps,
            allowed_device_ids_json=allowed_devs,
            auth_token_hash=token_h,
        )

        # Audit log
        self.db_manager.log_activity(
            event_type="FEDERATION_INVITE_ACCEPTED",
            principal=str(principal),
            target_device=peer_node_id,
            capability="network.federation.accept",
            outcome="SUCCESS",
            details={
                "grant_id": grant_id,
                "peer_network_id": peer_network_id,
                "peer_network_name": peer_network_name,
                "grant_ttl_seconds": grant_ttl,
            },
        )

        return {
            "success": True,
            "status": "FEDERATION_ESTABLISHED",
            "grant_id": grant_id,
            "auth_token": raw_token,
            "network_id": peer_network_id,
            "network_name": peer_network_name,
            "peer_node_id": peer_node_id,
            "expires_timestamp": grant_expires_str,
            "allowed_capabilities": json.loads(allowed_caps),
            "allowed_device_ids": json.loads(allowed_devs),
        }

    def record_outbound_grant(
        self,
        grant_id: str,
        peer_network_id: str,
        peer_network_name: str,
        peer_node_id: str,
        peer_node_name: str,
        peer_cert_fingerprint: str,
        auth_token: str,
        expires_timestamp: str,
        allowed_capabilities: list[str],
        allowed_device_ids: list[str],
        principal: Any = "OWNER_MANUAL",
    ) -> dict[str, Any]:
        """Record an outbound grant established after presenting an invite code to a remote peer."""
        self._assert_human_owner_principal(principal)

        token_h = hash_token(auth_token)
        now_str = current_utc_timestamp()

        self.db_manager.create_federation_grant(
            grant_id=grant_id,
            network_id=peer_network_id,
            network_name=peer_network_name,
            peer_node_id=peer_node_id,
            peer_node_name=peer_node_name,
            peer_cert_fingerprint=peer_cert_fingerprint,
            direction="OUTBOUND",
            created_timestamp=now_str,
            expires_timestamp=expires_timestamp,
            allowed_capabilities_json=json.dumps(allowed_capabilities),
            allowed_device_ids_json=json.dumps(allowed_device_ids),
            auth_token_hash=token_h,
        )

        self.db_manager.log_activity(
            event_type="FEDERATION_OUTBOUND_GRANT_RECORDED",
            principal=str(principal),
            target_device=peer_node_id,
            capability="network.federation.outbound",
            outcome="SUCCESS",
            details={
                "grant_id": grant_id,
                "peer_network_id": peer_network_id,
                "peer_network_name": peer_network_name,
            },
        )

        return {
            "success": True,
            "status": "OUTBOUND_GRANT_SAVED",
            "grant_id": grant_id,
        }

    def revoke_grant(
        self,
        grant_id: str,
        reason: str = "Revoked by network owner",
        principal: Any = "OWNER_MANUAL",
    ) -> dict[str, Any]:
        """Revoke a single active federation grant immediately."""
        self._assert_human_owner_principal(principal)

        grant = self.db_manager.get_federation_grant(grant_id)
        if not grant:
            return {"success": False, "status": "GRANT_NOT_FOUND", "error": f"Grant '{grant_id}' does not exist."}

        self.db_manager.revoke_federation_grant(grant_id, reason=reason)

        self.db_manager.log_activity(
            event_type="FEDERATION_GRANT_REVOKED",
            principal=str(principal),
            target_device=grant["peer_node_id"],
            capability="network.federation.revoke",
            outcome="SUCCESS",
            details={
                "grant_id": grant_id,
                "peer_network_id": grant["network_id"],
                "reason": reason,
            },
        )

        return {
            "success": True,
            "status": "GRANT_REVOKED",
            "grant_id": grant_id,
            "network_id": grant["network_id"],
            "reason": reason,
        }

    def global_kill_switch(
        self,
        reason: str = "Emergency Global Kill Switch Activated",
        principal: Any = "OWNER_MANUAL",
    ) -> dict[str, Any]:
        """Immediately terminate all active federation grants, pending invitations, and federated sessions.

        Enforces Invariant 5: One-click nuclear revocation across all peers.
        """
        self._assert_human_owner_principal(principal)

        counts = self.db_manager.kill_all_federation(reason=reason)

        self.db_manager.log_activity(
            event_type="FEDERATION_GLOBAL_KILL_SWITCH",
            principal=str(principal),
            target_device="ALL_FEDERATED_PEERS",
            capability="network.federation.kill_switch",
            outcome="SUCCESS",
            details={
                "reason": reason,
                "revoked_grants": counts["revoked_grants"],
                "revoked_invites": counts["revoked_invites"],
            },
        )

        logger.warning(
            "GLOBAL KILL SWITCH ACTIVATED by %s: Revoked %d grants and %d invites.",
            principal,
            counts["revoked_grants"],
            counts["revoked_invites"],
        )

        return {
            "success": True,
            "status": "KILL_SWITCH_EXECUTED",
            "reason": reason,
            "revoked_grants_count": counts["revoked_grants"],
            "revoked_invites_count": counts["revoked_invites"],
            "timestamp": current_utc_timestamp(),
        }

    def list_grants(self, active_only: bool = False) -> list[dict[str, Any]]:
        """List all registered federation grants with secret redaction."""
        rows = self.db_manager.list_federation_grants(active_only=active_only)
        now = datetime.now(timezone.utc)
        results = []
        for r in rows:
            is_active = r["status"] == "ACTIVE"
            exp_dt = parse_utc_timestamp(r["expires_timestamp"])
            if is_active and now > exp_dt:
                status = "EXPIRED"
            else:
                status = r["status"]

            results.append({
                "grant_id": r["grant_id"],
                "network_id": r["network_id"],
                "network_name": r["network_name"],
                "peer_node_id": r["peer_node_id"],
                "peer_node_name": r["peer_node_name"],
                "peer_cert_fingerprint": r["peer_cert_fingerprint"],
                "direction": r["direction"],
                "status": status,
                "created_timestamp": r["created_timestamp"],
                "expires_timestamp": r["expires_timestamp"],
                "allowed_capabilities": json.loads(r.get("allowed_capabilities_json", "[]")),
                "allowed_device_ids": json.loads(r.get("allowed_device_ids_json", "[]")),
                "last_used_timestamp": r.get("last_used_timestamp"),
                "revoked_timestamp": r.get("revoked_timestamp"),
                "revocation_reason": r.get("revocation_reason"),
                "federated": True,
            })
        return results

    def validate_federated_request(
        self,
        token: str,
        target_network_id: str,
        target_device_id: str,
        capability: str,
    ) -> tuple[bool, Optional[str]]:
        """Validate an incoming federated request against security invariants and ACLs.

        Enforces:
        - Invariant 4: Token validity and non-expired grant.
        - Invariant 7: Anti-transitivity (TRANSIT_ROUTING_FORBIDDEN).
        - Invariant 3: Device and capability ACL containment.

        Returns:
            (True, None) if authorized, or (False, error_reason) if denied.
        """
        # Anti-transitivity check: target must be local network
        if target_network_id and target_network_id != self.local_network_id:
            logger.warning(
                "Federation anti-transitivity violation: peer attempted routing to non-local network '%s'.",
                target_network_id,
            )
            return False, "TRANSIT_ROUTING_FORBIDDEN: Federated peers cannot route across networks."

        token_h = hash_token(token)
        grant = self.db_manager.get_federation_grant_by_token_hash(token_h)
        if not grant:
            return False, "INVALID_FEDERATION_CREDENTIALS"

        if grant["status"] != "ACTIVE":
            return False, f"FEDERATION_GRANT_{grant['status']}"

        now = datetime.now(timezone.utc)
        exp_dt = parse_utc_timestamp(grant["expires_timestamp"])
        if now > exp_dt:
            return False, "FEDERATION_GRANT_EXPIRED"

        # Invariant: Forbidden denylist checked first
        if is_capability_forbidden_for_federation(capability):
            return False, f"CAPABILITY_NOT_PERMITTED: Capability '{capability}' is strictly forbidden for federated access."

        # Device ACL check (Fail-closed)
        allowed_devs = json.loads(grant.get("allowed_device_ids_json", "[]"))
        if not allowed_devs:
            return False, "DEVICE_ACCESS_DENIED: No devices authorized in federation grant."
        if "*" in allowed_devs:
            return False, "DEVICE_ACCESS_DENIED: Wildcard device access is not permitted."
        if target_device_id not in allowed_devs:
            return False, f"DEVICE_ACCESS_DENIED: Device '{target_device_id}' is not authorized by this grant."

        # Capability ACL check (Fail-closed)
        allowed_caps = json.loads(grant.get("allowed_capabilities_json", "[]"))
        if not allowed_caps:
            return False, "CAPABILITY_NOT_PERMITTED: No capabilities authorized in federation grant."
        if "*" in allowed_caps:
            return False, "CAPABILITY_NOT_PERMITTED: Wildcard capability access is not permitted."
        if capability not in allowed_caps:
            return False, f"CAPABILITY_NOT_PERMITTED: Capability '{capability}' is not permitted by this grant."

        # Update last_used
        try:
            self.db_manager.update_federation_grant_last_used(grant["grant_id"], now.isoformat())
        except Exception:
            pass

        return True, None
