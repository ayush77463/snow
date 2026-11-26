"""Networking modules for SNOW Desktop Core (lazy-loaded)."""

from __future__ import annotations

import importlib
from typing import Any

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "ClientConnection": ("snow.network.connection_manager", "ClientConnection"),
    "ConnectionManager": ("snow.network.connection_manager", "ConnectionManager"),
    "CapabilityExecutionClassification": ("snow.network.node", "CapabilityExecutionClassification"),
    "CapabilityManifest": ("snow.network.node", "CapabilityManifest"),
    "DeviceNode": ("snow.network.node", "DeviceNode"),
    "ReachabilityProfile": ("snow.network.node", "ReachabilityProfile"),
    "ReachabilityState": ("snow.network.node", "ReachabilityState"),
    "build_windows_manifest": ("snow.network.node", "build_windows_manifest"),
    "NodeRegistry": ("snow.network.registry", "NodeRegistry"),
    "SessionRouter": ("snow.network.router", "SessionRouter"),
    "SnowWebSocketServer": ("snow.network.ws_server", "SnowWebSocketServer"),
}

__all__ = list(_LAZY_EXPORTS.keys())


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
