"""Windows Host Capability Handlers for SNOW (lazy-loaded)."""

from __future__ import annotations

import importlib
from typing import Any

_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "TerminalSecurityPolicy": ("snow.capabilities.windows.terminal", "TerminalSecurityPolicy"),
    "WindowsAppLauncher": ("snow.capabilities.windows.apps", "WindowsAppLauncher"),
    "WindowsClipboardManager": ("snow.capabilities.windows.clipboard", "WindowsClipboardManager"),
    "WindowsFileManager": ("snow.capabilities.windows.files", "WindowsFileManager"),
    "WindowsProcessMonitor": ("snow.capabilities.windows.processes", "WindowsProcessMonitor"),
    "WindowsSystemControls": ("snow.capabilities.windows.system", "WindowsSystemControls"),
    "WindowsTelemetry": ("snow.capabilities.windows.telemetry", "WindowsTelemetry"),
    "WindowsTerminalExecutor": ("snow.capabilities.windows.terminal", "WindowsTerminalExecutor"),
}

__all__ = [
    "TerminalSecurityPolicy",
    "WindowsAppLauncher",
    "WindowsClipboardManager",
    "WindowsFileManager",
    "WindowsProcessMonitor",
    "WindowsSystemControls",
    "WindowsTelemetry",
    "WindowsTerminalExecutor",
]


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
