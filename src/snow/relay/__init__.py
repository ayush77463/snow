"""SNOW V3 Self-Hostable Remote Relay Service.

Provides payload-blind, authenticated rendezvous and forwarding of opaque
end-to-end encrypted TLS tunnels between paired SNOW devices.
"""

from __future__ import annotations

import importlib
from typing import Any

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "RelayConfig": ("snow.relay.config", "RelayConfig"),
    "SnowRelayServer": ("snow.relay.server", "SnowRelayServer"),
}

__all__ = ["RelayConfig", "SnowRelayServer"]


def __getattr__(name: str) -> Any:
    target = _LAZY_EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    mod_name, attr_name = target
    mod = importlib.import_module(mod_name)
    val = getattr(mod, attr_name)
    globals()[name] = val
    return val


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))
