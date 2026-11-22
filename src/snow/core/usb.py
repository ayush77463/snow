"""Zero-Data USB Reverse Mode via Android Debug Bridge (ADB).

Provides core discovery, device status inspection, and port forwarding
management for local USB tethered SNOW operations.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

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
        )
        r2 = subprocess.run(
            [str(bin_path), "-s", dev_serial, "reverse", f"tcp:{port + 1}", f"tcp:{port + 1}"],
            capture_output=True,
            text=True,
            timeout=8.0,
            check=False,
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
        )
        subprocess.run(
            [str(bin_path), "-s", dev_serial, "reverse", "--remove", f"tcp:{port + 1}"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
        )
        return True, f"Removed SNOW reverse port mappings from device {dev_name}."
    except Exception as exc:
        return False, f"Exception removing ADB reverse mappings: {exc}"
