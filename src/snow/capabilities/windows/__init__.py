"""Windows Host Capability Handlers for SNOW.

Exposes authorized telemetry, process monitoring, scoped filesystem operations,
and allowlisted application launching under strict security boundaries.
"""

from snow.capabilities.windows.apps import WindowsAppLauncher
from snow.capabilities.windows.files import WindowsFileManager
from snow.capabilities.windows.processes import WindowsProcessMonitor
from snow.capabilities.windows.telemetry import WindowsTelemetry

__all__ = [
    "WindowsAppLauncher",
    "WindowsFileManager",
    "WindowsProcessMonitor",
    "WindowsTelemetry",
]
