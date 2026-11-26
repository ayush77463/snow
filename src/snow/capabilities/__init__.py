"""SNOW Device and Host Capability Modules (lazy-loaded)."""

from __future__ import annotations

import importlib
from typing import Any

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "CapabilityEngine": ("snow.capabilities.engine", "CapabilityEngine"),
    "CapabilityRequest": ("snow.capabilities.engine", "CapabilityRequest"),
    "CapabilityResponse": ("snow.capabilities.engine", "CapabilityResponse"),
}

__all__ = ["CapabilityEngine", "CapabilityRequest", "CapabilityResponse"]


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
