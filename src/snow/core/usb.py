"""Zero-Data USB Reverse Mode via Android Debug Bridge (ADB).

Provides core discovery, device status inspection, and port forwarding
management for local USB tethered SNOW operations.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

from snow.core.subprocess_util import get_no_window_subprocess_kwargs

logger = logging.getLogger(__name__)


def find_adb_binary() -> Optional[Path]:
    """Locate the Android Debug Bridge (adb) executable."""
    found = shutil.which("adb")
    if found:
        return Path(found)
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk" / "platform-tools" / ("adb.exe" if sys.platform == "win32" else "adb"),
        Path(os.environ.get("ANDROID_HOME", "")) / "platform-tools" / ("adb.exe" if sys.platform == "win32" else "adb"),
        Path(os.environ.get("ANDROID_SDK_ROOT", "")) / "platform-tools" / ("adb.exe" if sys.platform == "win32" else "adb"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def get_connected_adb_devices(adb_bin: Optional[Path] = None) -> list[dict[str, str]]:
    """Enumerate connected ADB devices and their authorization status."""
    bin_path = adb_bin or find_adb_binary()
    if not bin_path:
        return []
    devices: list[dict[str, str]] = []
    try:
        res = subprocess.run(
            [str(bin_path), "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=8.0,
            check=False,
            **get_no_window_subprocess_kwargs(),
        )
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices") or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                status = parts[1]
                model = "Android Device"
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.split(":", 1)[1]
                devices.append({"serial": serial, "status": status, "model": model, "raw": line})
    except Exception as exc:
        logger.debug("Failed running adb devices: %s", exc)
    return devices


def get_usb_status(
    adb_bin: Optional[Path] = None,
    serial: Optional[str] = None,
    port: int = 8765,
) -> dict[str, Any]:
    """Inspect current ADB availability, connected devices, and reverse socket mappings."""
    bin_path = adb_bin or find_adb_binary()
    if not bin_path:
        return {
            "adb_found": False,
            "adb_path": None,
            "devices": [],
            "authorized_count": 0,
            "connected": False,
            "reverse_active": False,
            "mappings": [],
            "target_device": None,
        }

    devices = get_connected_adb_devices(bin_path)
    authorized = [d for d in devices if d["status"] == "device"]

    target_device = None
    if serial:
        for d in authorized:
            if d["serial"] == serial:
                target_device = d
                break
    elif authorized:
        target_device = authorized[0]

    mappings: list[str] = []
    reverse_active = False

    if target_device:
        try:
            res = subprocess.run(
                [str(bin_path), "-s", target_device["serial"], "reverse", "--list"],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
                **get_no_window_subprocess_kwargs(),
            )
            mappings = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
            port_wss = f"tcp:{port}"
            port_http = f"tcp:{port + 1}"
            has_wss = any(port_wss in m for m in mappings)
            has_http = any(port_http in m for m in mappings)
            reverse_active = bool(has_wss and has_http)
        except Exception as exc:
            logger.debug("Failed checking reverse mappings for %s: %s", target_device["serial"], exc)

    return {
        "adb_found": True,
        "adb_path": str(bin_path),
        "devices": devices,
        "authorized_count": len(authorized),
        "connected": len(authorized) > 0,
        "reverse_active": reverse_active,
        "mappings": mappings,
        "target_device": target_device,
    }


def setup_usb_reverse(
    serial: Optional[str] = None,
    port: int = 8765,
    adb_bin: Optional[Path] = None,
) -> tuple[bool, str]:
    """Establish ADB reverse socket mappings for WSS Core and HTTPS transfers."""
    bin_path = adb_bin or find_adb_binary()
    if not bin_path:
        return False, "ADB executable not found. Ensure Android SDK platform-tools is installed or adb is on PATH."

    devices = get_connected_adb_devices(bin_path)
    authorized = [d for d in devices if d["status"] == "device"]
    if not authorized:
        if devices:
            return False, f"Detected {len(devices)} device(s), but none are authorized. Unlock phone and grant USB debugging."
        return False, "No connected Android devices detected via USB."

    target_device = None
    if serial:
        for d in authorized:
            if d["serial"] == serial:
                target_device = d
                break
        if not target_device:
            return False, f"Specified device serial '{serial}' not found among authorized devices."
    else:
        target_device = authorized[0]

    dev_serial = target_device["serial"]
    dev_name = f"{target_device['model']} ({dev_serial})"

    try:
        r1 = subprocess.run(
            [str(bin_path), "-s", dev_serial, "reverse", f"tcp:{port}", f"tcp:{port}"],
            capture_output=True,
            text=True,
            timeout=8.0,
            check=False,
            **get_no_window_subprocess_kwargs(),
        )
        r2 = subprocess.run(
            [str(bin_path), "-s", dev_serial, "reverse", f"tcp:{port + 1}", f"tcp:{port + 1}"],
            capture_output=True,
            text=True,
            timeout=8.0,
            check=False,
            **get_no_window_subprocess_kwargs(),
        )
        if r1.returncode != 0 or r2.returncode != 0:
            err = (r1.stderr + " " + r2.stderr).strip()
            return False, f"Failed establishing reverse mappings on {dev_name}: {err}"

        return True, f"SNOW Zero-Data USB Mode configured for {dev_name} (tcp:{port}, tcp:{port + 1})"
    except Exception as exc:
        return False, f"Exception establishing ADB reverse mappings: {exc}"


def remove_usb_reverse(
    serial: Optional[str] = None,
    port: int = 8765,
    adb_bin: Optional[Path] = None,
) -> tuple[bool, str]:
    """Remove SNOW reverse port mappings from target device."""
    bin_path = adb_bin or find_adb_binary()
    if not bin_path:
        return False, "ADB executable not found."

    devices = get_connected_adb_devices(bin_path)
    authorized = [d for d in devices if d["status"] == "device"]
    if not authorized:
        return False, "No authorized devices connected to remove mappings from."

    target_device = None
    if serial:
        for d in authorized:
            if d["serial"] == serial:
                target_device = d
                break
        if not target_device:
            return False, f"Specified device serial '{serial}' not found."
    else:
        target_device = authorized[0]

    dev_serial = target_device["serial"]
    dev_name = f"{target_device['model']} ({dev_serial})"

    try:
        subprocess.run(
            [str(bin_path), "-s", dev_serial, "reverse", "--remove", f"tcp:{port}"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
            **get_no_window_subprocess_kwargs(),
        )
        subprocess.run(
            [str(bin_path), "-s", dev_serial, "reverse", "--remove", f"tcp:{port + 1}"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
            **get_no_window_subprocess_kwargs(),
        )
        return True, f"Removed SNOW reverse port mappings from device {dev_name}."
    except Exception as exc:
        return False, f"Exception removing ADB reverse mappings: {exc}"


class UsbWatcher:
    """Background task monitoring connected ADB USB devices and establishing reverse tunnels.

    Periodically checks for authorized ADB devices and ensures reverse socket mappings
    for ports 8765 (WSS) and 8766 (HTTPS) exist. Uses an adaptive bounded polling interval
    (8s idle, extending to 20s if no changes; drops back to 8s on state changes), avoids
    redundant ADB status checks for already configured active serials, and runs off-thread.
    """

    MIN_POLL_INTERVAL: float = 8.0
    MAX_POLL_INTERVAL: float = 20.0

    def __init__(
        self,
        port: int = 8765,
        poll_interval: Optional[float] = None,
        adb_bin: Optional[Path] = None,
    ) -> None:
        self.port = port
        self.base_interval = poll_interval if poll_interval is not None else self.MIN_POLL_INTERVAL
        self.current_interval = self.base_interval
        self.adb_bin = adb_bin or find_adb_binary()
        self._task: Optional[asyncio.Task] = None
        self._running: bool = False
        self._paused: bool = False
        self._configured_serials: set[str] = set()

    def pause(self) -> None:
        """Temporarily suspend USB polling during system pause mode."""
        self._paused = True
        logger.info("UsbWatcher monitoring paused.")

    def resume(self) -> None:
        """Resume USB polling when restoring from system pause mode."""
        self._paused = False
        self.current_interval = self.base_interval
        logger.info("UsbWatcher monitoring resumed.")

    @property
    def is_paused(self) -> bool:
        """Return True if USB monitoring is currently suspended."""
        return self._paused

    async def start(self) -> None:
        """Start the USB device monitoring background loop."""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop(), name="snow_usb_watcher")
        logger.info("UsbWatcher started (base_interval=%.1fs, port=%d)", self.base_interval, self.port)

    async def stop(self) -> None:
        """Stop the USB device monitoring loop cleanly."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        self._configured_serials.clear()
        logger.info("UsbWatcher stopped cleanly.")

    async def _monitor_loop(self) -> None:
        """Periodic non-blocking check of USB devices and reverse mappings with adaptive backoff."""
        while self._running:
            if self._paused:
                try:
                    await asyncio.sleep(self.base_interval)
                except asyncio.CancelledError:
                    break
                continue

            state_changed = False
            try:
                state_changed = await self._poll_once()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug("UsbWatcher poll error: %s", exc)

            if state_changed:
                self.current_interval = self.base_interval
            else:
                self.current_interval = min(self.current_interval * 1.5, self.MAX_POLL_INTERVAL)

            try:
                await asyncio.sleep(self.current_interval)
            except asyncio.CancelledError:
                break

    async def _poll_once(self) -> bool:
        """Inspect connected devices and configure reverse mappings on authorized devices.

        Returns True if a relevant USB device state change occurred.
        """
        bin_path = self.adb_bin or find_adb_binary()
        if not bin_path:
            return False
        self.adb_bin = bin_path

        state_changed = False

        # Run ADB device check in thread pool to avoid blocking the event loop
        devices = await asyncio.to_thread(get_connected_adb_devices, bin_path)
        authorized = [d for d in devices if d.get("status") == "device"]
        current_serials = {d["serial"] for d in authorized if "serial" in d}

        # Clean up stale devices no longer connected
        disconnected = self._configured_serials - current_serials
        if disconnected:
            state_changed = True
            for s in disconnected:
                logger.info("USB device disconnected: %s", s)
            self._configured_serials -= disconnected

        # Inspect and setup newly connected or unconfigured authorized devices
        for dev in authorized:
            serial = dev.get("serial")
            if not serial:
                continue

            # If already configured and still connected, skip redundant status checks
            if serial in self._configured_serials:
                continue

            state_changed = True
            status = await asyncio.to_thread(get_usb_status, bin_path, serial, self.port)
            if not status.get("reverse_active"):
                success, msg = await asyncio.to_thread(setup_usb_reverse, serial, self.port, bin_path)
                if success:
                    self._configured_serials.add(serial)
                    logger.info("Automatically established USB reverse mode: %s", msg)
                else:
                    logger.debug("Failed establishing USB reverse mode for %s: %s", serial, msg)
            else:
                self._configured_serials.add(serial)

        return state_changed
