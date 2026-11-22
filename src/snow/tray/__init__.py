"""SNOW Windows System Tray Companion package."""

from snow.tray.app import SnowTrayApp
from snow.tray.autostart import (
    is_autostart_enabled,
    remove_autostart,
    set_autostart,
)

__all__ = [
    "SnowTrayApp",
    "is_autostart_enabled",
    "set_autostart",
    "remove_autostart",
]
