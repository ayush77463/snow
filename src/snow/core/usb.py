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


def unlock_android_permissions(
    serial: Optional[str] = None,
    adb_bin: Optional[Path] = None,
    package_name: str = "org.snow",
) -> dict[str, Any]:
    """Best-effort one-click grant of SNOW Android permissions over authorized USB ADB."""
    bin_path = adb_bin or find_adb_binary()
    if not bin_path:
        return {
            "success": False,
            "status": "ADB_NOT_FOUND",
            "error": "ADB executable not found. Install Android platform-tools or ensure adb is in PATH.",
            "granted": [],
            "skipped": [],
            "failed": [],
        }

    devices = get_connected_adb_devices(bin_path)
    authorized = [d for d in devices if d.get("status") == "device"]
    if not authorized:
        if devices:
            return {
                "success": False,
                "status": "DEVICE_NOT_AUTHORIZED",
                "error": f"Detected {len(devices)} USB device(s), but none are authorized. Unlock phone and accept USB Debugging.",
                "granted": [],
                "skipped": [],
                "failed": [],
            }
        return {
            "success": False,
            "status": "NO_DEVICE",
            "error": "No authorized Android device detected over USB.",
            "granted": [],
            "skipped": [],
            "failed": [],
        }

    target_device = None
    if serial:
        for d in authorized:
            if d.get("serial") == serial:
                target_device = d
                break
        if not target_device:
            return {
                "success": False,
                "status": "SERIAL_NOT_FOUND",
                "error": f"Authorized ADB device '{serial}' not found.",
                "granted": [],
                "skipped": [],
                "failed": [],
            }
    else:
        target_device = authorized[0]

    dev_serial = target_device["serial"]
    dev_model = target_device.get("model", "Android Device")

    commands: list[tuple[str, list[str], bool]] = [
        (
            "Notification Listener",
            [
                str(bin_path), "-s", dev_serial, "shell", "cmd", "notification",
                "allow_listener", f"{package_name}/{package_name}.service.SnowNotificationListenerService",
            ],
            True,
        ),
        (
            "Camera Permission",
            [str(bin_path), "-s", dev_serial, "shell", "pm", "grant", package_name, "android.permission.CAMERA"],
            True,
        ),
        (
            "Post Notifications",
            [str(bin_path), "-s", dev_serial, "shell", "pm", "grant", package_name, "android.permission.POST_NOTIFICATIONS"],
            False,
        ),
        (
            "Read Media Images",
            [str(bin_path), "-s", dev_serial, "shell", "pm", "grant", package_name, "android.permission.READ_MEDIA_IMAGES"],
            False,
        ),
        (
            "Read External Storage",
            [str(bin_path), "-s", dev_serial, "shell", "pm", "grant", package_name, "android.permission.READ_EXTERNAL_STORAGE"],
            False,
        ),
        (
            "Display Over Other Apps",
            [str(bin_path), "-s", dev_serial, "shell", "appops", "set", package_name, "SYSTEM_ALERT_WINDOW", "allow"],
            True,
        ),
        (
            "All Files Access",
            [str(bin_path), "-s", dev_serial, "shell", "appops", "set", package_name, "MANAGE_EXTERNAL_STORAGE", "allow"],
            False,
        ),
        (
            "Install Unknown Apps",
            [str(bin_path), "-s", dev_serial, "shell", "appops", "set", package_name, "REQUEST_INSTALL_PACKAGES", "allow"],
            False,
        ),
        (
            "Run In Background",
            [str(bin_path), "-s", dev_serial, "shell", "appops", "set", package_name, "RUN_ANY_IN_BACKGROUND", "allow"],
            False,
        ),
        (
            "Battery Optimization Whitelist",
            [str(bin_path), "-s", dev_serial, "shell", "dumpsys", "deviceidle", "whitelist", f"+{package_name}"],
            False,
        ),
    ]

    granted: list[str] = []
    skipped: list[dict[str, str]] = []
    failed: list[dict[str, str]] = []
    critical_failed = False

    for label, cmd, is_critical in commands:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8.0,
                check=False,
                **get_no_window_subprocess_kwargs(),
            )
            detail = (proc.stderr or proc.stdout or "").strip()
            if proc.returncode == 0 and "SecurityException" not in detail and "Exception" not in detail:
                granted.append(label)
            elif not is_critical or "not a changeable permission type" in detail or "Unknown operation" in detail:
                skipped.append({"permission": label, "reason": detail or f"exit {proc.returncode}"})
            else:
                failed.append({"permission": label, "reason": detail or f"exit {proc.returncode}"})
                critical_failed = True
        except Exception as exc:
            entry = {"permission": label, "reason": str(exc)}
            if is_critical:
                failed.append(entry)
                critical_failed = True
            else:
                skipped.append(entry)

    success = len(granted) > 0 and not critical_failed
    return {
        "success": success,
        "status": "SUCCESS" if success else ("PARTIAL" if granted else "FAILED"),
        "serial": dev_serial,
        "device_model": dev_model,
        "granted": granted,
        "skipped": skipped,
        "failed": failed,
        "message": (
            f"Unlocked {len(granted)} permission(s) on {dev_model} ({dev_serial})"
            + (f"; {len(skipped)} OEM/OS-gated skipped" if skipped else "")
            + (f"; {len(failed)} failed" if failed else "")
        ),
    }


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


DEFAULT_ANDROID_HOST_WSS_PORT: int = 8767
DEFAULT_ANDROID_HOST_MEDIA_PORT: int = 8769


def get_usb_forward_mappings(
    serial: str,
    adb_bin: Optional[Path] = None,
) -> list[dict[str, str]]:
    """Inspect active ADB forward mappings (`adb -s <serial> forward --list`) for a serial."""
    bin_path = adb_bin or find_adb_binary()
    if not bin_path or not serial:
        return []
    parsed: list[dict[str, str]] = []
    try:
        res = subprocess.run(
            [str(bin_path), "-s", serial, "forward", "--list"],
            capture_output=True,
            text=True,
            timeout=5.0,
            check=False,
            **get_no_window_subprocess_kwargs(),
        )
        for line in (res.stdout or "").splitlines():
            parts = line.strip().split()
            if len(parts) >= 3:
                parsed.append(
                    {
                        "serial": parts[0],
                        "local": parts[1],
                        "remote": parts[2],
                        "raw": line.strip(),
                    }
                )
    except Exception as exc:
        logger.debug("Failed checking forward mappings for %s: %s", serial, exc)
    return parsed


def setup_usb_forward(
    serial: Optional[str] = None,
    forward_wss_port: int = DEFAULT_ANDROID_HOST_WSS_PORT,
    forward_media_port: int = DEFAULT_ANDROID_HOST_MEDIA_PORT,
    adb_bin: Optional[Path] = None,
    local_wss_port: Optional[int] = None,
    local_media_port: Optional[int] = None,
    skip_if_conflict: bool = True,
) -> tuple[bool, str, list[str]]:
    """Establish ADB forward mappings (`tcp:local -> tcp:remote`) for Android Peer Host mode.

    Checks existing ADB forward mappings first to avoid silently clobbering unrelated
    third-party forwards on the same local port. Returns `(ok, message, snow_owned_locals)`.
    """
    bin_path = adb_bin or find_adb_binary()
    if not bin_path:
        return False, "ADB executable not found.", []

    devices = get_connected_adb_devices(bin_path)
    authorized = [d for d in devices if d.get("status") == "device"]
    if not authorized:
        if devices:
            return False, "USB device connected but unauthorized or offline.", []
        return False, "No connected Android devices detected via USB.", []

    target_device = None
    if serial:
        target_device = next((d for d in authorized if d.get("serial") == serial), None)
        if not target_device:
            return False, f"Specified device serial '{serial}' is not authorized.", []
    else:
        target_device = authorized[0]

    dev_serial = target_device["serial"]
    loc_wss = int(local_wss_port or forward_wss_port)
    loc_media = int(local_media_port or forward_media_port)
    desired = [
        (f"tcp:{loc_wss}", f"tcp:{int(forward_wss_port)}"),
        (f"tcp:{loc_media}", f"tcp:{int(forward_media_port)}"),
    ]

    existing = get_usb_forward_mappings(dev_serial, bin_path)
    existing_by_local = {m["local"]: m["remote"] for m in existing if m.get("serial") == dev_serial}
    owned_locals: list[str] = []
    conflicts: list[str] = []

    for loc_spec, rem_spec in desired:
        current_rem = existing_by_local.get(loc_spec)
        if current_rem == rem_spec:
            owned_locals.append(loc_spec)
            continue
        if current_rem is not None and skip_if_conflict:
            conflicts.append(f"{loc_spec} already mapped to {current_rem}")
            continue
        try:
            r = subprocess.run(
                [str(bin_path), "-s", dev_serial, "forward", loc_spec, rem_spec],
                capture_output=True,
                text=True,
                timeout=8.0,
                check=False,
                **get_no_window_subprocess_kwargs(),
            )
            if r.returncode == 0:
                owned_locals.append(loc_spec)
            else:
                conflicts.append((r.stderr or r.stdout or f"forward {loc_spec} failed").strip())
        except Exception as exc:
            conflicts.append(str(exc))

    if len(owned_locals) == len(desired):
        return (
            True,
            f"SNOW USB forward mappings active for {dev_serial} ({', '.join(owned_locals)}).",
            owned_locals,
        )
    if owned_locals:
        return (
            False,
            f"Partial USB forward setup for {dev_serial}: active={owned_locals}; conflicts={'; '.join(conflicts)}",
            owned_locals,
        )
    return (
        False,
        f"USB forward setup skipped/failed for {dev_serial}: {'; '.join(conflicts) or 'unknown error'}",
        [],
    )


def remove_usb_forward(
    serial: Optional[str] = None,
    adb_bin: Optional[Path] = None,
    owned_locals: Optional[list[str]] = None,
) -> tuple[bool, str]:
    """Remove only SNOW-owned ADB forward mappings, preserving unrelated user forwards."""
    bin_path = adb_bin or find_adb_binary()
    if not bin_path:
        return False, "ADB executable not found."
    target_locals = list(owned_locals or [])
    if not target_locals:
        return True, "No SNOW-owned USB forward mappings to remove."

    dev_serial = serial
    if not dev_serial:
        devices = get_connected_adb_devices(bin_path)
        auth = [d for d in devices if d.get("status") == "device"]
        if not auth:
            return False, "No authorized devices connected."
        dev_serial = auth[0]["serial"]

    removed = 0
    for loc_spec in target_locals:
        try:
            r = subprocess.run(
                [str(bin_path), "-s", dev_serial, "forward", "--remove", loc_spec],
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
                **get_no_window_subprocess_kwargs(),
            )
            if r.returncode == 0:
                removed += 1
        except Exception:
            pass
    return True, f"Removed {removed} SNOW-owned forward mapping(s) from {dev_serial}."


def get_usb_bidirectional_status(
    adb_bin: Optional[Path] = None,
    serial: Optional[str] = None,
    port: int = 8765,
    forward_wss_port: int = DEFAULT_ANDROID_HOST_WSS_PORT,
    forward_media_port: int = DEFAULT_ANDROID_HOST_MEDIA_PORT,
) -> dict[str, Any]:
    """Return full bidirectional USB ADB status (reverse + forward + unauthorized/offline checks)."""
    base = get_usb_status(adb_bin=adb_bin, serial=serial, port=port)
    bin_path = Path(base["adb_path"]) if base.get("adb_path") else adb_bin
    devices = base.get("devices") or []
    unauthorized = [d for d in devices if d.get("status") == "unauthorized"]
    offline = [d for d in devices if d.get("status") == "offline"]
    target_dev = base.get("target_device")
    fwd_mappings: list[dict[str, str]] = []
    forward_active = False

    if target_dev and bin_path:
        fwd_mappings = get_usb_forward_mappings(target_dev["serial"], bin_path)
        req_wss = f"tcp:{int(forward_wss_port)}"
        req_media = f"tcp:{int(forward_media_port)}"
        has_fwd_wss = any(m.get("local") == req_wss or req_wss in m.get("remote", "") for m in fwd_mappings)
        has_fwd_media = any(m.get("local") == req_media or req_media in m.get("remote", "") for m in fwd_mappings)
        forward_active = bool(has_fwd_wss and has_fwd_media)

    enriched = dict(base)
    enriched["forward_active"] = forward_active
    enriched["forward_mappings"] = fwd_mappings
    enriched["bidirectional_active"] = bool(base.get("reverse_active") and forward_active)
    enriched["unauthorized_devices"] = unauthorized
    enriched["offline_devices"] = offline
    enriched["usb_ready"] = bool(base.get("connected") and base.get("reverse_active"))
    return enriched


def setup_usb_bidirectional(
    serial: Optional[str] = None,
    port: int = 8765,
    forward_wss_port: int = DEFAULT_ANDROID_HOST_WSS_PORT,
    forward_media_port: int = DEFAULT_ANDROID_HOST_MEDIA_PORT,
    adb_bin: Optional[Path] = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Configure both ADB reverse (Android->PC) and ADB forward (PC->Android Peer Host)."""
    rev_ok, rev_msg = setup_usb_reverse(serial=serial, port=port, adb_bin=adb_bin)
    fwd_ok, fwd_msg, owned_forwards = setup_usb_forward(
        serial=serial,
        forward_wss_port=forward_wss_port,
        forward_media_port=forward_media_port,
        adb_bin=adb_bin,
    )
    meta = {
        "reverse_ok": rev_ok,
        "reverse_message": rev_msg,
        "forward_ok": fwd_ok,
        "forward_message": fwd_msg,
        "owned_forwards": owned_forwards,
        "bidirectional_active": bool(rev_ok and fwd_ok),
    }
    if rev_ok and fwd_ok:
        return True, f"{rev_msg}; forward active ({', '.join(owned_forwards)})", meta
    if rev_ok:
        return True, f"{rev_msg} (forward note: {fwd_msg})", meta
    return False, f"{rev_msg}; {fwd_msg}", meta


class UsbWatcher:
    """Background task monitoring connected ADB USB devices and establishing bidirectional tunnels.

    Periodically checks for authorized ADB devices and ensures reverse socket mappings
    (8765/8766) plus non-conflicting forward mappings (8767/8769) exist. Uses an adaptive
    bounded polling interval (8s idle, extending to 20s), skips redundant status checks on
    consecutive polls until periodic repair interval, and notifies attach/detach listeners.
    """

    MIN_POLL_INTERVAL: float = 8.0
    MAX_POLL_INTERVAL: float = 20.0
    DEFAULT_REPAIR_CHECK_POLLS: int = 4

    def __init__(
        self,
        port: int = 8765,
        poll_interval: Optional[float] = None,
        adb_bin: Optional[Path] = None,
        forward_wss_port: int = DEFAULT_ANDROID_HOST_WSS_PORT,
        forward_media_port: int = DEFAULT_ANDROID_HOST_MEDIA_PORT,
        target_serial: Optional[str] = None,
        on_usb_attached: Optional[Any] = None,
        on_usb_detached: Optional[Any] = None,
        repair_check_polls: int = DEFAULT_REPAIR_CHECK_POLLS,
    ) -> None:
        self.port = port
        self.base_interval = poll_interval if poll_interval is not None else self.MIN_POLL_INTERVAL
        self.current_interval = self.base_interval
        self.adb_bin = adb_bin or find_adb_binary()
        self.forward_wss_port = int(forward_wss_port)
        self.forward_media_port = int(forward_media_port)
        self.target_serial = target_serial
        self.on_usb_attached = on_usb_attached
        self.on_usb_detached = on_usb_detached
        self.repair_check_polls = max(2, int(repair_check_polls))
        self._task: Optional[asyncio.Task] = None
        self._running: bool = False
        self._paused: bool = False
        self._configured_serials: set[str] = set()
        self._owned_forwards: dict[str, list[str]] = {}
        self._serial_poll_counts: dict[str, int] = {}

    def get_status_snapshot(self) -> dict[str, Any]:
        """Return lightweight in-memory readiness summary without spawning blocking ADB calls."""
        return {
            "usb_ready": bool(self._configured_serials),
            "configured_serials": sorted(self._configured_serials),
            "owned_forwards": {s: list(v) for s, v in self._owned_forwards.items()},
            "port": self.port,
            "transfer_port": self.port + 1,
            "forward_wss_port": self.forward_wss_port,
            "forward_media_port": self.forward_media_port,
        }

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
        """Stop the USB device monitoring loop and clean up SNOW-owned forward mappings."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._task = None
        if self._owned_forwards:
            bin_path = self.adb_bin or find_adb_binary()
            for serial, owned in list(self._owned_forwards.items()):
                if owned and bin_path:
                    try:
                        await asyncio.to_thread(remove_usb_forward, serial, bin_path, owned)
                    except Exception:
                        pass
        self._owned_forwards.clear()
        self._configured_serials.clear()
        self._serial_poll_counts.clear()
        logger.info("UsbWatcher stopped cleanly.")

    async def _notify_callback(self, cb: Optional[Any], *args: Any) -> None:
        if cb is None:
            return
        try:
            res = cb(*args)
            if asyncio.iscoroutine(res):
                await res
        except Exception as exc:
            logger.debug("UsbWatcher callback error: %s", exc)

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
        """Inspect connected devices and configure bidirectional USB mappings on authorized devices.

        Returns True if a relevant USB device state change occurred.
        """
        bin_path = self.adb_bin or find_adb_binary()
        if not bin_path:
            return False
        self.adb_bin = bin_path

        state_changed = False

        # Run ADB device check in thread pool to avoid blocking the event loop
        devices = await asyncio.to_thread(get_connected_adb_devices, bin_path)
        authorized = [
            d
            for d in devices
            if d.get("status") == "device"
            and (not self.target_serial or d.get("serial") == self.target_serial)
        ]
        current_serials = {d["serial"] for d in authorized if "serial" in d}

        # Clean up disconnected, unauthorized, or offline serials immediately
        disconnected = self._configured_serials - current_serials
        if disconnected:
            state_changed = True
            for s in disconnected:
                logger.info("USB device disconnected or lost authorization: %s", s)
                self._serial_poll_counts.pop(s, None)
                owned = self._owned_forwards.pop(s, None)
                if owned:
                    try:
                        await asyncio.to_thread(remove_usb_forward, s, bin_path, owned)
                    except Exception:
                        pass
                await self._notify_callback(self.on_usb_detached, s)
            self._configured_serials -= disconnected

        # Inspect and setup newly connected or unconfigured authorized devices
        for dev in authorized:
            serial = dev.get("serial")
            if not serial:
                continue

            # Skip redundant status checks on immediate consecutive polls, but periodically repair dropped mappings
            if serial in self._configured_serials:
                poll_num = self._serial_poll_counts.get(serial, 0) + 1
                self._serial_poll_counts[serial] = poll_num
                if poll_num < self.repair_check_polls:
                    continue
                self._serial_poll_counts[serial] = 0
                status = await asyncio.to_thread(get_usb_status, bin_path, serial, self.port)
                if not status.get("reverse_active"):
                    logger.info("Repairing dropped USB reverse mappings for %s...", serial)
                    success, msg = await asyncio.to_thread(setup_usb_reverse, serial, self.port, bin_path)
                    if not success:
                        self._configured_serials.discard(serial)
                        await self._notify_callback(self.on_usb_detached, serial)
                        continue
                    _, _, owned_fwd = await asyncio.to_thread(
                        setup_usb_forward,
                        serial,
                        self.forward_wss_port,
                        self.forward_media_port,
                        bin_path,
                    )
                    if owned_fwd:
                        self._owned_forwards[serial] = owned_fwd
                    state_changed = True
                continue

            state_changed = True
            status = await asyncio.to_thread(get_usb_status, bin_path, serial, self.port)
            if not status.get("reverse_active"):
                success, msg = await asyncio.to_thread(setup_usb_reverse, serial, self.port, bin_path)
                if success:
                    self._configured_serials.add(serial)
                    self._serial_poll_counts[serial] = 0
                    logger.info("Automatically established USB reverse mode: %s", msg)
                    _, _, owned_fwd = await asyncio.to_thread(
                        setup_usb_forward,
                        serial,
                        self.forward_wss_port,
                        self.forward_media_port,
                        bin_path,
                    )
                    if owned_fwd:
                        self._owned_forwards[serial] = owned_fwd
                    await self._notify_callback(self.on_usb_attached, serial, self.get_status_snapshot())
                else:
                    logger.debug("Failed establishing USB reverse mode for %s: %s", serial, msg)
            else:
                self._configured_serials.add(serial)
                self._serial_poll_counts[serial] = 0
                _, _, owned_fwd = await asyncio.to_thread(
                    setup_usb_forward,
                    serial,
                    self.forward_wss_port,
                    self.forward_media_port,
                    bin_path,
                )
                if owned_fwd:
                    self._owned_forwards[serial] = owned_fwd
                await self._notify_callback(self.on_usb_attached, serial, self.get_status_snapshot())

        return state_changed
