"""Windows system and battery telemetry capability for SNOW.

Uses the official psutil dependency and Python platform standard library
to query battery, hardware specifications, and system utilization safely
without blocking the asyncio event loop.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
import platform
import time
from typing import Any, Dict, Optional

import psutil

logger = logging.getLogger(__name__)


class WindowsTelemetry:
    """Queries Windows system hardware telemetry and battery status."""

    def get_battery_sync(self) -> dict[str, Any]:
        """Synchronously query the system battery status via psutil."""
        try:
            battery = psutil.sensors_battery()
        except Exception as exc:
            logger.warning("Error querying psutil.sensors_battery: %s", exc)
            return {
                "available": False,
                "status": "ERROR",
                "error": str(exc),
                "message": f"Failed querying system battery: {exc}",
                "percent": None,
                "power_plugged": None,
                "secsleft": None,
            }

        if battery is None:
            return {
                "available": False,
                "status": "NO_BATTERY",
                "message": "No system battery detected on this Windows host (desktop or AC-only).",
                "percent": None,
                "power_plugged": None,
                "secsleft": None,
            }

        # Handle indefinite or unknown seconds left
        secsleft: Optional[int] = None
        if battery.secsleft not in (
            psutil.POWER_TIME_UNLIMITED,
            psutil.POWER_TIME_UNKNOWN,
            None,
        ):
            if battery.secsleft >= 0:
                secsleft = int(battery.secsleft)

        status = "DISCHARGING"
        if battery.power_plugged:
            status = "FULL" if battery.percent >= 100 else "CHARGING"

        return {
            "available": True,
            "status": status,
            "percent": float(battery.percent),
            "power_plugged": bool(battery.power_plugged),
            "secsleft": secsleft,
            "message": (
                f"Battery is at {battery.percent}% "
                f"({'plugged in' if battery.power_plugged else 'on battery power'})."
            ),
        }

    async def get_battery_info(self) -> dict[str, Any]:
        """Asynchronously query battery telemetry on a worker thread."""
        return await asyncio.to_thread(self.get_battery_sync)

    def get_system_info_sync(self) -> dict[str, Any]:
        """Synchronously collect system hardware, OS, memory, and disk telemetry."""
        # Non-blocking CPU percentage sampling (interval=None computes delta since last call)
        cpu_pct = psutil.cpu_percent(interval=None)
        cpu_count = psutil.cpu_count(logical=True)

        # Virtual memory telemetry
        mem = psutil.virtual_memory()
        mem_total_mb = round(mem.total / (1024 * 1024), 2)
        mem_used_mb = round(mem.used / (1024 * 1024), 2)
        mem_pct = float(mem.percent)

        # Stable disk usage for system drive anchor (e.g. C:\)
        system_drive = Path.home().anchor or "C:\\"
        try:
            disk = psutil.disk_usage(system_drive)
            disk_total_gb = round(disk.total / (1024**3), 2)
            disk_used_gb = round(disk.used / (1024**3), 2)
            disk_pct = float(disk.percent)
        except Exception as exc:
            logger.warning("Could not query disk usage for %s: %s", system_drive, exc)
            disk_total_gb = None
            disk_used_gb = None
            disk_pct = None

        # System boot time and uptime
        boot_time = psutil.boot_time()
        uptime_seconds = max(0.0, round(time.time() - boot_time, 1))

        # Operating system and platform identifiers
        hostname = platform.node()
        os_name = platform.system()
        os_version = platform.version()
        arch = platform.machine()

        return {
            "hostname": hostname,
            "os_name": os_name,
            "os_version": os_version,
            "architecture": arch,
            "cpu": {
                "logical_cores": cpu_count,
                "utilization_percent": cpu_pct,
                "sampling_mode": "non_blocking_delta",
            },
            "memory": {
                "total_mb": mem_total_mb,
                "used_mb": mem_used_mb,
                "percent": mem_pct,
            },
            "disk": {
                "drive": system_drive,
                "total_gb": disk_total_gb,
                "used_gb": disk_used_gb,
                "percent": disk_pct,
            },
            "uptime_seconds": uptime_seconds,
        }

    async def get_system_telemetry(self) -> dict[str, Any]:
        """Asynchronously query system telemetry on a worker thread."""
        return await asyncio.to_thread(self.get_system_info_sync)
