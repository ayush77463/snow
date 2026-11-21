"""Shared Approval Policy Engine and Authorization Lifecycle for SNOW V3.

Implements Phase 21 Pillar 2:
- Unified authorization and approval decision point for AI_MCP, OWNER_MANUAL, and peer devices.
- Server-owned ApprovalRequest state machine: PENDING -> APPROVED | DENIED | EXPIRED.
- Cryptographic binding to (request_id, principal, action, target_device, args_sha256).
- Bounded TTL and single-use consumption (anti-replay, anti-tampering).
- Prevention of client-side approval spoofing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import logging
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from snow.security.context import ExecutionContext, ExecutionPrincipal

logger = logging.getLogger(__name__)

DEFAULT_APPROVAL_TTL_SECONDS: float = 300.0  # 5 minutes


class ApprovalStatus(str, Enum):
    """Lifecycle states for an approval request."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"


def compute_args_hash(params: dict[str, Any]) -> str:
    """Calculate the canonical SHA-256 digest of request arguments."""
    clean_params = dict(params or {})
    # Strip ephemeral authorization tokens from the hash itself
    clean_params.pop("approval_id", None)
    clean_params.pop("confirmation_ticket", None)
    canonical = json.dumps(clean_params, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class ApprovalRequest:
    """Server-owned record of a capability invocation requiring explicit owner approval."""

    request_id: str
    principal: str
    action: str
    target_device: str
    args_sha256: str
    status: ApprovalStatus = ApprovalStatus.PENDING
    created_at: float = 0.0
    expires_at: float = 0.0
    reason: str = "Explicit owner approval required."
    risk_level: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    consumed: bool = False
    approved_by: Optional[str] = None
    sanitized_params: Optional[dict[str, Any]] = None

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check if request has exceeded its bounded TTL."""
        now = current_time if current_time is not None else time.monotonic()
        return now > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        """Convert approval request to structured dictionary format."""
        return {
            "request_id": self.request_id,
            "principal": self.principal,
            "action": self.action,
            "target_device": self.target_device,
            "args_sha256": self.args_sha256,
            "status": self.status.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "time_remaining_seconds": max(0.0, self.expires_at - time.monotonic()),
            "reason": self.reason,
            "risk_level": self.risk_level,
            "consumed": self.consumed,
            "approved_by": self.approved_by,
            "sanitized_params": self.sanitized_params or {},
        }


class ApprovalPolicyEngine:
    """Layer 2 central authorization and approval decision engine."""

    def __init__(self, db_manager: Optional[Any] = None) -> None:
        self.db_manager = db_manager
        self._requests: dict[str, ApprovalRequest] = {}
        self._listeners: list[Any] = []

    def add_listener(self, listener: Any) -> None:
        """Register a callback for approval lifecycle events (REQUESTED, RESOLVED)."""
        self._listeners.append(listener)

    def _notify_listeners(self, event_type: str, data: dict[str, Any]) -> None:
        """Deliver approval events asynchronously to registered listeners."""
        import asyncio
        for listener in list(self._listeners):
            try:
                res = listener(event_type, data)
                if asyncio.iscoroutine(res):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(res)
                    except RuntimeError:
                        pass
            except Exception as exc:
                logger.debug("Approval listener execution error: %s", exc)

    def is_catastrophic(self, action: str, params: dict[str, Any]) -> bool:
        """Check if action or command violates hard-blocked catastrophic invariants."""
        canonical_action = (action or "").strip().lower()
        if canonical_action in ("windows_terminal_exec", "snow_windows_terminal_exec", "desktop_exec"):
            cmd = str(params.get("command", "")).strip().lower()
            hard_blocked_patterns = ["rm -rf /", "del /f /s /q c:\\", "format c:"]
            if any(p in cmd for p in hard_blocked_patterns):
                return True
            try:
                from snow.capabilities.windows.terminal import CATASTROPHIC_PATTERNS
                for pattern in CATASTROPHIC_PATTERNS:
                    if pattern.search(cmd):
                        return True
            except Exception:
                pass
        return False

    def evaluate_policy(
        self,
        action: str,
        params: dict[str, Any],
        ctx: ExecutionContext,
        target_device: Optional[str] = None,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Evaluate declarative security policy for a capability request.

        Returns:
            Tuple of (requires_approval, reason, risk_level).
        """
        canonical_action = (action or "").strip().lower()
        principal = ctx.principal if ctx and hasattr(ctx, "principal") else ExecutionPrincipal.AI_MCP

        # 1. Catastrophic and Unrestricted Invariants (Hard blocked permanently, never approvable)
        if self.is_catastrophic(canonical_action, params):
            return True, "Catastrophic command execution is permanently blocked by policy.", "CRITICAL"

        # 2. Check metadata registry hints
        from snow.mcp.registry import get_capability_metadata
        meta = get_capability_metadata(canonical_action)
        if not meta:
            # Check with prefix stripped or common mapping
            meta = get_capability_metadata(f"snow_{canonical_action}")

        # 3. Principal-Specific Evaluation
        if principal == ExecutionPrincipal.OWNER_MANUAL:
            # Delegated to existing terminal confirmation tier / PeerCapabilityPolicy
            return False, None, "LOW"

        if principal == ExecutionPrincipal.AI_MCP:
            # If request originates from remote device (WebSocket), delegation to terminal tier / peer policy
            if ctx and ctx.device_id:
                return False, None, "LOW"

            # Visual capture operations ALWAYS require explicit owner approval for AI callers
            if canonical_action in (
                "windows_screenshot",
                "snow_windows_screenshot",
                "android_screenshot",
                "snow_android_screenshot",
                "android_camera_capture",
                "snow_android_camera_capture",
            ):
                return (
                    True,
                    f"Visual capture capability '{canonical_action}' exposes sensitive visual information and requires explicit owner approval.",
                    "HIGH",
                )

            # Workflow execution approval evaluation
            if canonical_action in ("workflow_run", "snow_workflow_run"):
                wf_id = str(params.get("workflow_id", "")).strip()
                try:
                    from snow.capabilities.workflows import WORKFLOW_REGISTRY
                    wf = WORKFLOW_REGISTRY.get(wf_id)
                    if wf and wf.requires_approval:
                        return (
                            True,
                            f"Workflow '{wf.name}' involves mutating or capture actions and requires owner approval.",
                            "HIGH",
                        )
                except Exception:
                    return True, "Workflow requires owner approval.", "HIGH"

            # Read-only operations are auto-allowed (except visual capture above)
            if meta and meta.read_only_hint:
                return False, None, "LOW"

            # Sensitive cross-device writes and transfers require owner approval
            if canonical_action in (
                "android_file_send",
                "snow_android_file_send",
                "transfer_file",
                "snow_transfer_file",
                "android_send_message",
                "snow_android_send_message",
            ):
                return True, f"AI-initiated cross-device operation '{canonical_action}' requires owner approval.", "HIGH"

            # Terminal execution: Safe echo auto-allowed; other arbitrary commands require owner approval
            if canonical_action in ("windows_terminal_exec", "snow_windows_terminal_exec", "desktop_exec"):
                cmd = str(params.get("command", "")).strip()
                tokens = cmd.split()
                first_token = tokens[0].lower().removesuffix(".exe") if tokens else ""
                if first_token in ("echo", "write-output"):
                    return False, None, "LOW"
                return True, "AI-initiated terminal command execution requires owner approval.", "HIGH"

            # Local file write within allowed_roots does not require approval unless targeting remote device
            if canonical_action in ("windows_file_write", "snow_windows_file_write", "desktop_file_write"):
                if target_device and target_device not in ("local", "windows", "desktop"):
                    return True, "AI-initiated cross-device file write requires owner approval.", "HIGH"
                return False, None, "LOW"

            # If registered tool explicitly flags requires_approval
            if meta and meta.requires_approval:
                return True, f"Capability '{canonical_action}' requires owner approval.", "MEDIUM"

            return False, None, "LOW"

        # Default fallback
        return False, None, "LOW"

    @staticmethod
    def _sanitize_params_for_preview(params: dict[str, Any]) -> dict[str, Any]:
        """Produce a bounded, secret-redacted preview of parameters for the approval UI."""
        from snow.security.db import redact_sensitive_data
        clean = dict(params or {})
        clean.pop("approval_id", None)
        clean.pop("confirmation_ticket", None)
        redacted = redact_sensitive_data(clean)
        preview: dict[str, Any] = {}
        for k, v in redacted.items():
            if isinstance(v, str) and len(v) > 200:
                preview[k] = v[:197] + "..."
            else:
                preview[k] = v
        return preview

    def create_request(
        self,
        principal: str | ExecutionPrincipal,
        action: str,
        target_device: Optional[str],
        params: dict[str, Any],
        reason: str = "Explicit owner approval required.",
        risk_level: str = "MEDIUM",
        ttl_seconds: float = DEFAULT_APPROVAL_TTL_SECONDS,
    ) -> ApprovalRequest:
        """Create and register a cryptographically bound pending approval request."""
        now = time.monotonic()
        req_id = secrets.token_hex(16)
        p_str = principal.value if isinstance(principal, ExecutionPrincipal) else str(principal)
        target = (target_device or "local").strip()
        args_hash = compute_args_hash(params)

        request = ApprovalRequest(
            request_id=req_id,
            principal=p_str,
            action=action.strip(),
            target_device=target,
            args_sha256=args_hash,
            status=ApprovalStatus.PENDING,
            created_at=now,
            expires_at=now + ttl_seconds,
            reason=reason,
            risk_level=risk_level,
            consumed=False,
            approved_by=None,
            sanitized_params=self._sanitize_params_for_preview(params),
        )
        self._requests[req_id] = request

        if self.db_manager and hasattr(self.db_manager, "log_activity"):
            try:
                self.db_manager.log_activity(
                    event_type="APPROVAL_REQUESTED",
                    capability=action,
                    principal=p_str,
                    target_device=target,
                    outcome="PENDING",
                    details={"request_id": req_id, "risk_level": risk_level, "reason": reason},
                )
            except Exception as exc:
                logger.debug("Failed logging approval requested activity: %s", exc)

        self._notify_listeners("APPROVAL_REQUESTED", request.to_dict())

        return request

    def approve_request(
        self,
        request_id: str,
        approver_principal: ExecutionPrincipal = ExecutionPrincipal.OWNER_MANUAL,
    ) -> Tuple[bool, str]:
        """Approve a pending approval request via authorized owner intervention."""
        if not request_id or not isinstance(request_id, str):
            return False, "Invalid request ID."

        req = self._requests.get(request_id.strip())
        if not req:
            return False, "Approval request not found."

        if req.status != ApprovalStatus.PENDING:
            return False, f"Request is not pending (current state: {req.status.value})."

        if req.is_expired():
            req.status = ApprovalStatus.EXPIRED
            return False, "Approval request has expired."

        req.status = ApprovalStatus.APPROVED
        req.approved_by = approver_principal.value if isinstance(approver_principal, ExecutionPrincipal) else str(approver_principal)

        if self.db_manager and hasattr(self.db_manager, "log_activity"):
            try:
                self.db_manager.log_activity(
                    event_type="APPROVAL_APPROVED",
                    capability=req.action,
                    principal=req.principal,
                    target_device=req.target_device,
                    outcome="APPROVED",
                    details={"request_id": req.request_id, "approved_by": req.approved_by},
                )
            except Exception as exc:
                logger.debug("Failed logging approval approved activity: %s", exc)

        self._notify_listeners("APPROVAL_RESOLVED", req.to_dict())

        return True, "APPROVED"

    def deny_request(
        self,
        request_id: str,
        approver_principal: ExecutionPrincipal = ExecutionPrincipal.OWNER_MANUAL,
    ) -> Tuple[bool, str]:
        """Deny a pending approval request."""
        if not request_id or not isinstance(request_id, str):
            return False, "Invalid request ID."

        req = self._requests.get(request_id.strip())
        if not req:
            return False, "Approval request not found."

        req.status = ApprovalStatus.DENIED
        approver_str = approver_principal.value if isinstance(approver_principal, ExecutionPrincipal) else str(approver_principal)

        if self.db_manager and hasattr(self.db_manager, "log_activity"):
            try:
                self.db_manager.log_activity(
                    event_type="APPROVAL_DENIED",
                    capability=req.action,
                    principal=req.principal,
                    target_device=req.target_device,
                    outcome="DENIED",
                    details={"request_id": req.request_id, "denied_by": approver_str},
                )
            except Exception as exc:
                logger.debug("Failed logging approval denied activity: %s", exc)

        self._notify_listeners("APPROVAL_RESOLVED", req.to_dict())

        return True, "DENIED"

    def consume_approval(
        self,
        request_id: str,
        principal: str | ExecutionPrincipal,
        action: str,
        target_device: Optional[str],
        params: dict[str, Any],
    ) -> Tuple[bool, str]:
        """Validate and atomically consume a single-use approval token.

        Rejects replayed, tampered, expired, or mismatched requests.
        """
        if not request_id or not isinstance(request_id, str):
            return False, "Invalid approval ID."

        req = self._requests.get(request_id.strip())
        if not req:
            return False, "Approval request not found or invalid."

        # 1. State check
        if req.status != ApprovalStatus.APPROVED:
            return False, f"Approval request is not approved (status: {req.status.value})."

        # 2. Single-use consumption check
        if req.consumed:
            return False, "Approval token has already been consumed (single-use invariant)."

        # 3. Expiration check
        if req.is_expired():
            req.status = ApprovalStatus.EXPIRED
            return False, "Approval token has expired."

        # 4. Principal binding check
        p_str = principal.value if isinstance(principal, ExecutionPrincipal) else str(principal)
        if req.principal != p_str:
            return False, f"Principal mismatch: bound to '{req.principal}', attempted by '{p_str}'."

        # 5. Action binding check
        if req.action.lower() != action.strip().lower():
            return False, f"Action mismatch: bound to '{req.action}', attempted '{action}'."

        # 6. Target device binding check
        target = (target_device or "local").strip()
        if req.target_device != target:
            return False, f"Target device mismatch: bound to '{req.target_device}', attempted '{target}'."

        # 7. Cryptographic argument hash binding check
        current_hash = compute_args_hash(params)
        if req.args_sha256 != current_hash:
            return False, "Argument integrity violation: parameters do not match approved hash."

        # Atomically consume
        req.consumed = True

        if self.db_manager and hasattr(self.db_manager, "log_activity"):
            try:
                self.db_manager.log_activity(
                    event_type="APPROVAL_CONSUMED",
                    capability=req.action,
                    principal=req.principal,
                    target_device=req.target_device,
                    outcome="CONSUMED",
                    details={"request_id": req.request_id},
                )
            except Exception as exc:
                logger.debug("Failed logging approval consumed activity: %s", exc)

        return True, "OK"

    def list_pending_requests(self) -> List[ApprovalRequest]:
        """List active pending approval requests, automatically expiring stale items."""
        now = time.monotonic()
        pending: List[ApprovalRequest] = []
        for req in self._requests.values():
            if req.status == ApprovalStatus.PENDING:
                if req.is_expired(now):
                    req.status = ApprovalStatus.EXPIRED
                else:
                    pending.append(req)
        return pending

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Retrieve an approval request by ID with automatic expiration check."""
        req = self._requests.get(request_id)
        if req and req.status == ApprovalStatus.PENDING and req.is_expired():
            req.status = ApprovalStatus.EXPIRED
        return req
