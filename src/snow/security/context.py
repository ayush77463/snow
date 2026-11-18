"""Execution principal and immutable ExecutionContext for SNOW.

Enforces strict separation between:
- OWNER_MANUAL: Authenticated, owner-trusted manual device operations.
- AI_MCP: Restricted AI-originated operations via MCP or loopback IPC.

Security Invariants:
1. Immutable: ExecutionContext is a frozen dataclass; fields cannot be mutated after instantiation.
2. Safe Default: Default principal is strictly AI_MCP (least privilege).
3. Server-Created Only: Contexts must be constructed exclusively by trusted server boundaries
   (WSS dispatcher, IPC listener, in-process MCP bridge). Client payloads cannot dictate principal.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Optional


class ExecutionPrincipal(StrEnum):
    """Logical execution principal governing capability privilege boundaries."""

    OWNER_MANUAL = "OWNER_MANUAL"
    AI_MCP = "AI_MCP"


@dataclass(frozen=True)
class ExecutionContext:
    """Immutable execution context attached to every capability invocation."""

    principal: ExecutionPrincipal = ExecutionPrincipal.AI_MCP
    device_id: Optional[str] = None
    session_id: Optional[str] = None
    origin: str = "unknown"

    @property
    def is_owner(self) -> bool:
        """Return True if this context carries trusted OWNER_MANUAL authority."""
        return self.principal == ExecutionPrincipal.OWNER_MANUAL

    @property
    def is_ai(self) -> bool:
        """Return True if this context is restricted to AI_MCP authority."""
        return self.principal == ExecutionPrincipal.AI_MCP
