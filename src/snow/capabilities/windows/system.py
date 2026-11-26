"""Native, zero-dependency Windows system control helpers for SNOW.

Provides shell-free Win32 active-window inspection, bounded desktop toast
notifications via Shell_NotifyIconW, and safe workstation locking via
LockWorkStation with dependency-injection seams for deterministic testing.
"""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
import logging
import os
import re
import subprocess
import sys
from typing import Any, Callable, Optional

from snow.core.subprocess_util import get_no_window_subprocess_kwargs

import psutil

logger = logging.getLogger(__name__)

MAX_NOTIFY_TITLE_CHARS = 63  # Win32 NOTIFYICONDATAW.szInfoTitle max 64 WCHAR incl NUL
MAX_NOTIFY_MESSAGE_CHARS = 255  # Win32 NOTIFYICONDATAW.szInfo max 256 WCHAR incl NUL
MAX_WINDOW_TITLE_CHARS = 512

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_text(raw: str, max_len: int) -> str:
    """Normalize whitespace and strip dangerous control characters cleanly."""
    cleaned = _CONTROL_CHAR_RE.sub("", raw).replace("\r\n", " ").replace("\n", " ").replace("\r", " ").strip()
    if len(cleaned) > max_len:
        return cleaned[: max_len - 3] + "..."
    return cleaned


class _NOTIFYICONDATAW(ctypes.Structure):
    """Win32 NOTIFYICONDATAW struct aligned for 32/64-bit Windows."""

    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("hWnd", wintypes.HWND),
        ("uID", wintypes.UINT),
        ("uFlags", wintypes.UINT),
        ("uCallbackMessage", wintypes.UINT),
        ("hIcon", wintypes.HICON),
        ("szTip", wintypes.WCHAR * 128),
        ("dwState", wintypes.DWORD),
        ("dwStateMask", wintypes.DWORD),
        ("szInfo", wintypes.WCHAR * 256),
        ("uVersion", wintypes.UINT),
        ("szInfoTitle", wintypes.WCHAR * 64),
        ("dwInfoFlags", wintypes.DWORD),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", wintypes.HICON),
    ]


def _default_active_window_win32() -> dict[str, Any]:
    """Query active foreground window title and owning process on Windows."""
    if sys.platform != "win32":
        return {
            "available": False,
            "status": "UNSUPPORTED_PLATFORM",
            "window_title": "",
            "process_id": None,
            "process_name": "",
            "error": "Active window inspection is only supported on Windows.",
        }

    user32 = ctypes.windll.user32
    hwnd = user32.GetForegroundWindow()
    if not hwnd:
        return {
            "available": False,
            "status": "NO_ACTIVE_WINDOW",
            "window_title": "",
            "process_id": None,
            "process_name": "",
            "message": "No active foreground window (desktop locked or headless session).",
        }

    title_len = int(user32.GetWindowTextLengthW(hwnd))
    window_title = ""
    if title_len > 0:
        buf = ctypes.create_unicode_buffer(min(title_len, MAX_WINDOW_TITLE_CHARS) + 1)
        user32.GetWindowTextW(hwnd, buf, len(buf))
        window_title = _sanitize_text(buf.value, MAX_WINDOW_TITLE_CHARS)

    pid_val = wintypes.DWORD(0)
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid_val))
    pid = int(pid_val.value) if pid_val.value else None

    proc_name = ""
    if pid:
        try:
            proc_name = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            proc_name = ""

    return {
        "available": True,
        "status": "SUCCESS",
        "window_title": window_title,
        "process_id": pid,
        "process_name": proc_name,
        "hwnd": int(hwnd),
    }


def _default_notify_win32(title: str, message: str) -> dict[str, Any]:
    """Send a bounded desktop balloon/toast notification via Win32 Shell_NotifyIconW."""
    if sys.platform != "win32":
        return {
            "success": False,
            "status": "UNSUPPORTED_PLATFORM",
            "error": "Windows desktop notifications are only supported on Windows.",
        }

    user32 = ctypes.windll.user32
    shell32 = ctypes.windll.shell32
    kernel32 = ctypes.windll.kernel32

    HWND_MESSAGE = wintypes.HWND(-3)
    NIM_ADD = 0x00000000
    NIM_MODIFY = 0x00000001
    NIM_DELETE = 0x00000002
    NIF_MESSAGE = 0x00000001
    NIF_ICON = 0x00000002
    NIF_TIP = 0x00000004
    NIF_INFO = 0x00000010
    NIIF_INFO = 0x00000001
    IDI_INFORMATION = 32516

    hinst = kernel32.GetModuleHandleW(None)
    hwnd = user32.CreateWindowExW(
        0, "STATIC", "SNOWNotifyTarget", 0, 0, 0, 0, 0, HWND_MESSAGE, None, hinst, None
    )
    if not hwnd:
        return {
            "success": False,
            "status": "NOTIFICATION_FAILED",
            "error": "Failed creating hidden Win32 notification window.",
        }

    nid = _NOTIFYICONDATAW()
    nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
    nid.hWnd = hwnd
    nid.uID = 1091
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_INFO
    nid.uCallbackMessage = 0x8001
    nid.hIcon = user32.LoadIconW(None, ctypes.c_void_p(IDI_INFORMATION))
    nid.szTip = "SNOW Bridge"
    nid.szInfoTitle = title[:MAX_NOTIFY_TITLE_CHARS]
    nid.szInfo = message[:MAX_NOTIFY_MESSAGE_CHARS]
    nid.dwInfoFlags = NIIF_INFO

    try:
        added = bool(shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid)))
        if not added:
            return {
                "success": False,
                "status": "NOTIFICATION_FAILED",
                "error": "Shell_NotifyIconW(NIM_ADD) returned 0.",
            }
        shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(nid))
        return {
            "success": True,
            "status": "SUCCESS",
            "title": title,
            "message": message,
            "delivery": "win32_shell_notify_icon",
        }
    finally:
        try:
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(nid))
        except Exception:
            pass
        try:
            user32.DestroyWindow(hwnd)
        except Exception:
            pass


def _default_lock_workstation_win32() -> dict[str, Any]:
    """Lock the active Windows workstation via native user32.LockWorkStation."""
    if sys.platform != "win32":
        return {
            "success": False,
            "status": "UNSUPPORTED_PLATFORM",
            "error": "Workstation lock is only supported on Windows.",
        }

    user32 = ctypes.windll.user32
    user32.LockWorkStation.argtypes = []
    user32.LockWorkStation.restype = wintypes.BOOL
    ok = bool(user32.LockWorkStation())
    if not ok:
        return {
            "success": False,
            "status": "LOCK_FAILED",
            "error": "LockWorkStation returned 0.",
        }
    return {
        "success": True,
        "status": "SUCCESS",
        "locked": True,
        "message": "Workstation locked successfully.",
    }


def _default_list_windows_win32(
    include_empty_titles: bool = False,
    limit: int = 50,
) -> dict[str, Any]:
    """Enumerate visible top-level desktop windows via Win32 EnumWindows."""
    if sys.platform != "win32":
        return {
            "success": False,
            "status": "UNSUPPORTED_PLATFORM",
            "windows": [],
            "count": 0,
            "error": "Window enumeration is only supported on Windows.",
        }

    try:
        bounded_limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        bounded_limit = 50

    user32 = ctypes.windll.user32
    fg_hwnd = int(user32.GetForegroundWindow() or 0)
    windows: list[dict[str, Any]] = []
    proc_name_cache: dict[int, str] = {}

    WNDENUMPROC = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _callback(hwnd_val: int, _lparam: int) -> bool:
        try:
            if not user32.IsWindowVisible(hwnd_val):
                return True
            title_len = int(user32.GetWindowTextLengthW(hwnd_val) or 0)
            window_title = ""
            if title_len > 0:
                buf = ctypes.create_unicode_buffer(min(title_len, MAX_WINDOW_TITLE_CHARS) + 1)
                user32.GetWindowTextW(hwnd_val, buf, len(buf))
                window_title = _sanitize_text(buf.value, MAX_WINDOW_TITLE_CHARS)
            if not include_empty_titles and not window_title:
                return True

            pid_val = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd_val, ctypes.byref(pid_val))
            pid = int(pid_val.value) if pid_val.value else None
            proc_name = ""
            if pid:
                if pid in proc_name_cache:
                    proc_name = proc_name_cache[pid]
                else:
                    try:
                        proc_name = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        proc_name = ""
                    proc_name_cache[pid] = proc_name

            hwnd_int = int(hwnd_val)
            windows.append({
                "hwnd": hwnd_int,
                "window_title": window_title,
                "process_id": pid,
                "process_name": proc_name,
                "is_foreground": hwnd_int == fg_hwnd and fg_hwnd != 0,
                "is_minimized": bool(user32.IsIconic(hwnd_val)),
            })
            if len(windows) >= bounded_limit:
                return False
        except Exception:
            return True
        return True

    user32.EnumWindows(WNDENUMPROC(_callback), 0)
    return {
        "success": True,
        "status": "SUCCESS",
        "count": len(windows),
        "foreground_hwnd": fg_hwnd if fg_hwnd else None,
        "windows": windows,
    }


def _default_focus_window_win32(
    hwnd: Optional[int] = None,
    title_contains: str = "",
    process_name: str = "",
) -> dict[str, Any]:
    """Bring an existing visible desktop window to the foreground without shell calls."""
    if sys.platform != "win32":
        return {
            "success": False,
            "status": "UNSUPPORTED_PLATFORM",
            "error": "Window focusing is only supported on Windows.",
        }

    enum_res = _default_list_windows_win32(include_empty_titles=True, limit=200)
    candidates: list[dict[str, Any]] = list(enum_res.get("windows") or [])
    target_entry: Optional[dict[str, Any]] = None

    title_needle = _sanitize_text(title_contains, MAX_WINDOW_TITLE_CHARS).lower() if title_contains else ""
    proc_needle = _sanitize_text(process_name, 128).lower() if process_name else ""

    for win in candidates:
        if hwnd is not None and win.get("hwnd") == int(hwnd):
            if title_needle and title_needle not in str(win.get("window_title") or "").lower():
                continue
            if proc_needle and proc_needle not in str(win.get("process_name") or "").lower():
                continue
            target_entry = win
            break

    if target_entry is None and hwnd is None:
        for win in candidates:
            win_title = str(win.get("window_title") or "").lower()
            win_proc = str(win.get("process_name") or "").lower()
            if title_needle and title_needle not in win_title:
                continue
            if proc_needle and proc_needle not in win_proc:
                continue
            if not win_title and not proc_needle:
                continue
            target_entry = win
            break

    if target_entry is None:
        return {
            "success": False,
            "status": "WINDOW_NOT_FOUND",
            "error": "No matching visible desktop window found for the specified selector.",
        }

    user32 = ctypes.windll.user32
    target_hwnd = wintypes.HWND(int(target_entry["hwnd"]))
    if not user32.IsWindow(target_hwnd):
        return {
            "success": False,
            "status": "WINDOW_NOT_FOUND",
            "error": "Target window handle is no longer valid.",
        }

    SW_RESTORE = 9
    try:
        if user32.IsIconic(target_hwnd):
            user32.ShowWindow(target_hwnd, SW_RESTORE)
        user32.BringWindowToTop(target_hwnd)
        focused = bool(user32.SetForegroundWindow(target_hwnd))
        now_fg = int(user32.GetForegroundWindow() or 0) == int(target_entry["hwnd"])
        if not focused and not now_fg:
            return {
                "success": False,
                "status": "FOCUS_DENIED",
                "hwnd": target_entry["hwnd"],
                "window_title": target_entry.get("window_title", ""),
                "process_name": target_entry.get("process_name", ""),
                "error": "Windows OS restricted SetForegroundWindow focus change for this window.",
            }
        return {
            "success": True,
            "status": "SUCCESS",
            "hwnd": target_entry["hwnd"],
            "window_title": target_entry.get("window_title", ""),
            "process_id": target_entry.get("process_id"),
            "process_name": target_entry.get("process_name", ""),
            "focused": True,
        }
    except Exception as exc:
        logger.error("Failed focusing window hwnd=%s: %s", target_entry.get("hwnd"), exc)
        return {
            "success": False,
            "status": "FOCUS_FAILED",
            "error": str(exc),
        }


ALLOWED_HOTKEYS: dict[str, tuple[int, ...]] = {
    "win+d": (0x5B, 0x44),
    "alt+tab": (0x12, 0x09),
    "ctrl+shift+s": (0x11, 0x10, 0x53),
    "win+tab": (0x5B, 0x09),
    "ctrl+c": (0x11, 0x43),
    "ctrl+v": (0x11, 0x56),
    "win+e": (0x5B, 0x45),
    "alt+f4": (0x12, 0x73),
}

_INPUT_KEYBOARD = 1
_KEYEVENTF_KEYUP = 0x0002
_KEYEVENTF_EXTENDEDKEY = 0x0001
_EXTENDED_VKS = frozenset({0x5B, 0x5C})


def normalize_hotkey_shortcut(shortcut: str) -> str:
    """Normalize hotkey chord formatting cleanly for strict allowlist comparison."""
    parts = [p.strip().lower() for p in (shortcut or "").split("+") if p.strip()]
    return "+".join(parts)


class _KEYBDINPUT(ctypes.Structure):
    _fields_ = [
        ("wVk", wintypes.WORD),
        ("wScan", wintypes.WORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(wintypes.ULONG)),
    ]


class _MOUSEINPUT(ctypes.Structure):
    _fields_ = [
        ("dx", wintypes.LONG),
        ("dy", wintypes.LONG),
        ("mouseData", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("time", wintypes.DWORD),
        ("dwExtraInfo", ctypes.POINTER(wintypes.ULONG)),
    ]


class _HARDWAREINPUT(ctypes.Structure):
    _fields_ = [
        ("uMsg", wintypes.DWORD),
        ("wParamL", wintypes.WORD),
        ("wParamH", wintypes.WORD),
    ]


class _INPUT_UNION(ctypes.Union):
    _fields_ = [
        ("mi", _MOUSEINPUT),
        ("ki", _KEYBDINPUT),
        ("hi", _HARDWAREINPUT),
    ]


class _INPUT(ctypes.Structure):
    _fields_ = [
        ("type", wintypes.DWORD),
        ("union", _INPUT_UNION),
    ]


class _PHYSICAL_MONITOR(ctypes.Structure):
    _fields_ = [
        ("hPhysicalMonitor", wintypes.HANDLE),
        ("szPhysicalMonitorDescription", wintypes.WCHAR * 128),
    ]


def _default_send_hotkey_win32(shortcut: str) -> dict[str, Any]:
    """Dispatch an allowlisted chord via Win32 SendInput (zero shell execution)."""
    norm = normalize_hotkey_shortcut(shortcut)
    if norm not in ALLOWED_HOTKEYS:
        return {
            "success": False,
            "status": "INVALID_HOTKEY",
            "error": f"Hotkey '{shortcut}' is not in the explicit SNOW allowlist.",
        }
    if sys.platform != "win32":
        return {
            "success": False,
            "status": "UNSUPPORTED_PLATFORM",
            "error": "Windows hotkeys are only supported on Windows.",
        }

    vkeys = ALLOWED_HOTKEYS[norm]
    inputs: list[_INPUT] = []
    for vk in vkeys:
        flags = _KEYEVENTF_EXTENDEDKEY if vk in _EXTENDED_VKS else 0
        inputs.append(_INPUT(type=_INPUT_KEYBOARD, union=_INPUT_UNION(ki=_KEYBDINPUT(wVk=vk, dwFlags=flags))))
    for vk in reversed(vkeys):
        flags = _KEYEVENTF_KEYUP | (_KEYEVENTF_EXTENDEDKEY if vk in _EXTENDED_VKS else 0)
        inputs.append(_INPUT(type=_INPUT_KEYBOARD, union=_INPUT_UNION(ki=_KEYBDINPUT(wVk=vk, dwFlags=flags))))

    user32 = ctypes.windll.user32
    arr_type = _INPUT * len(inputs)
    arr = arr_type(*inputs)
    sent = int(user32.SendInput(len(inputs), ctypes.byref(arr), ctypes.sizeof(_INPUT)))
    if sent != len(inputs):
        return {
            "success": False,
            "status": "HOTKEY_FAILED",
            "shortcut": norm,
            "error": f"Win32 SendInput dispatched {sent}/{len(inputs)} keyboard events.",
        }
    return {
        "success": True,
        "status": "SUCCESS",
        "shortcut": norm,
        "events_dispatched": sent,
        "message": f"Dispatched Windows shortcut '{norm}'.",
    }


def _default_set_brightness_win32(level: int) -> dict[str, Any]:
    """Adjust primary monitor brightness cleanly via Win32 dxva2.dll DDC/CI."""
    if sys.platform != "win32":
        return {
            "success": False,
            "status": "UNSUPPORTED_PLATFORM",
            "error": "Display brightness adjustment is only supported on Windows.",
        }

    try:
        user32 = ctypes.windll.user32
        dxva2 = ctypes.windll.dxva2
        hwnd = user32.GetForegroundWindow() or user32.GetDesktopWindow()
        hmon = user32.MonitorFromWindow(hwnd, 1)  # MONITOR_DEFAULTTOPRIMARY = 1
        if not hmon:
            return {
                "success": False,
                "status": "UNSUPPORTED_DISPLAY",
                "error": "No active physical monitor handle found.",
            }
        num_monitors = wintypes.DWORD(0)
        if not dxva2.GetNumberOfPhysicalMonitorsFromHMONITOR(hmon, ctypes.byref(num_monitors)) or num_monitors.value == 0:
            return {
                "success": False,
                "status": "UNSUPPORTED_DISPLAY",
                "error": "Display does not expose physical monitor brightness controls.",
            }
        monitors = (_PHYSICAL_MONITOR * num_monitors.value)()
        if not dxva2.GetPhysicalMonitorsFromHMONITOR(hmon, num_monitors.value, monitors):
            return {
                "success": False,
                "status": "UNSUPPORTED_DISPLAY",
                "error": "Failed enumerating physical monitor handles.",
            }
        try:
            updated = 0
            for mon in monitors:
                if dxva2.SetMonitorBrightness(mon.hPhysicalMonitor, wintypes.DWORD(level)):
                    updated += 1
            if updated == 0:
                return {
                    "success": False,
                    "status": "UNSUPPORTED_DISPLAY",
                    "error": "Monitor rejected DDC/CI brightness adjustment (unsupported hardware or virtual display).",
                }
            return {
                "success": True,
                "status": "SUCCESS",
                "level": int(level),
                "monitors_updated": updated,
                "message": f"Set display brightness to {int(level)}%.",
            }
        finally:
            dxva2.DestroyPhysicalMonitors(num_monitors.value, monitors)
    except Exception as exc:
        return {
            "success": False,
            "status": "UNSUPPORTED_DISPLAY",
            "error": f"Display brightness control unavailable: {exc}",
        }


_WMI_SET_BRIGHTNESS_SCRIPT = (
    "$ErrorActionPreference='Stop';"
    "$lvl=[int]$env:SNOW_BRIGHTNESS_LEVEL;"
    "if($lvl -lt 0 -or $lvl -gt 100){exit 2};"
    "$monitors=@(Get-CimInstance -Namespace root/WMI -ClassName WmiMonitorBrightnessMethods -ErrorAction Stop);"
    "if($monitors.Count -eq 0){$monitors=@(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods -ErrorAction Stop)};"
    "if($monitors.Count -eq 0){exit 3};"
    "foreach($m in $monitors){$null = $m.WmiSetBrightness(1, $lvl)};"
    "Write-Output $monitors.Count"
)


def _default_set_brightness_wmi(level: int) -> dict[str, Any]:
    """Adjust internal laptop panel brightness cleanly via Windows WmiMonitorBrightnessMethods."""
    if sys.platform != "win32":
        return {
            "success": False,
            "status": "UNSUPPORTED_PLATFORM",
            "error": "WMI brightness adjustment is only supported on Windows.",
        }
    if isinstance(level, bool) or not isinstance(level, int) or level < 0 or level > 100:
        return {
            "success": False,
            "status": "INVALID_BRIGHTNESS_LEVEL",
            "error": "Brightness 'level' must be an integer between 0 and 100.",
        }

    env = dict(os.environ)
    env["SNOW_BRIGHTNESS_LEVEL"] = str(int(level))
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        _WMI_SET_BRIGHTNESS_SCRIPT,
    ]
    try:
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=5.0,
            shell=False,
            **get_no_window_subprocess_kwargs(),
        )
    except FileNotFoundError as exc:
        return {
            "success": False,
            "status": "UNSUPPORTED_DISPLAY",
            "error": f"Windows PowerShell unavailable for WMI brightness fallback: {exc}",
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "status": "UNSUPPORTED_DISPLAY",
            "error": "WMI brightness fallback timed out.",
        }
    except Exception as exc:
        return {
            "success": False,
            "status": "UNSUPPORTED_DISPLAY",
            "error": f"WMI brightness fallback failed: {exc}",
        }

    stderr_txt = (proc.stderr or "").strip()
    stdout_txt = (proc.stdout or "").strip()
    if proc.returncode == 0:
        try:
            count = max(1, int(stdout_txt.splitlines()[-1])) if stdout_txt else 1
        except Exception:
            count = 1
        return {
            "success": True,
            "status": "SUCCESS",
            "level": int(level),
            "monitors_updated": count,
            "method": "wmi",
            "message": f"Set display brightness to {int(level)}% via WMI.",
        }

    low_err = stderr_txt.lower()
    if "access" in low_err and "denied" in low_err:
        return {
            "success": False,
            "status": "PERMISSION_DENIED",
            "error": f"Permission denied calling WmiMonitorBrightnessMethods: {stderr_txt}",
        }
    return {
        "success": False,
        "status": "UNSUPPORTED_DISPLAY",
        "error": stderr_txt or f"WMI brightness unavailable (exit code {proc.returncode}).",
    }


class WindowsSystemControls:
    """Thread-safe, testable Windows workstation & shell notification capabilities."""

    def __init__(
        self,
        active_window_fn: Optional[Callable[[], dict[str, Any]]] = None,
        notify_fn: Optional[Callable[[str, str], dict[str, Any]]] = None,
        lock_fn: Optional[Callable[[], dict[str, Any]]] = None,
        list_windows_fn: Optional[Callable[[bool, int], dict[str, Any]]] = None,
        focus_window_fn: Optional[Callable[[Optional[int], str, str], dict[str, Any]]] = None,
        send_hotkey_fn: Optional[Callable[[str], dict[str, Any]]] = None,
        set_brightness_fn: Optional[Callable[[int], dict[str, Any]]] = None,
        wmi_brightness_fn: Optional[Callable[[int], dict[str, Any]]] = None,
    ) -> None:
        self._active_window_fn = active_window_fn or _default_active_window_win32
        self._notify_fn = notify_fn or _default_notify_win32
        self._lock_fn = lock_fn or _default_lock_workstation_win32
        self._list_windows_fn = list_windows_fn or _default_list_windows_win32
        self._focus_window_fn = focus_window_fn or _default_focus_window_win32
        self._send_hotkey_fn = send_hotkey_fn or _default_send_hotkey_win32
        self._set_brightness_fn = set_brightness_fn or _default_set_brightness_win32
        self._wmi_brightness_fn = wmi_brightness_fn or _default_set_brightness_wmi

    def get_active_window_sync(self) -> dict[str, Any]:
        """Synchronously inspect the active foreground window title and process."""
        try:
            res = self._active_window_fn()
            return dict(res) if isinstance(res, dict) else {"available": False, "status": "ERROR"}
        except Exception as exc:
            logger.warning("Failed reading active window: %s", exc)
            return {
                "available": False,
                "status": "ERROR",
                "window_title": "",
                "process_id": None,
                "process_name": "",
                "error": str(exc),
            }

    async def get_active_window(self) -> dict[str, Any]:
        """Asynchronously inspect the active foreground window."""
        return await asyncio.to_thread(self.get_active_window_sync)

    def send_notification_sync(self, title: str, message: str) -> dict[str, Any]:
        """Validate bounds and display a shell-free Windows desktop notification."""
        if not isinstance(title, str) or not isinstance(message, str):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Both 'title' and 'message' must be strings.",
            }
        if "\x00" in title or "\x00" in message:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Null bytes are not permitted in notification fields.",
            }

        clean_title = _sanitize_text(title, MAX_NOTIFY_TITLE_CHARS)
        clean_message = _sanitize_text(message, MAX_NOTIFY_MESSAGE_CHARS)
        if not clean_title or not clean_message:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Notification 'title' and 'message' must be non-empty.",
            }

        try:
            res = self._notify_fn(clean_title, clean_message)
            return dict(res) if isinstance(res, dict) else {"success": False, "status": "NOTIFICATION_FAILED"}
        except Exception as exc:
            logger.error("Failed sending Windows desktop notification: %s", exc)
            return {
                "success": False,
                "status": "NOTIFICATION_FAILED",
                "error": str(exc),
            }

    async def send_notification(self, title: str, message: str) -> dict[str, Any]:
        """Asynchronously post a Windows desktop notification."""
        return await asyncio.to_thread(self.send_notification_sync, title, message)

    def lock_workstation_sync(self) -> dict[str, Any]:
        """Lock the Windows workstation safely via Win32 LockWorkStation."""
        try:
            res = self._lock_fn()
            return dict(res) if isinstance(res, dict) else {"success": False, "status": "LOCK_FAILED"}
        except Exception as exc:
            logger.error("Failed locking Windows workstation: %s", exc)
            return {
                "success": False,
                "status": "LOCK_FAILED",
                "error": str(exc),
            }

    async def lock_workstation(self) -> dict[str, Any]:
        """Asynchronously lock the Windows workstation."""
        return await asyncio.to_thread(self.lock_workstation_sync)

    def list_windows_sync(
        self,
        include_empty_titles: bool = False,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Synchronously list open visible top-level windows on Windows."""
        try:
            bounded_limit = max(1, min(int(limit), 200))
        except (TypeError, ValueError):
            bounded_limit = 50
        try:
            res = self._list_windows_fn(bool(include_empty_titles), bounded_limit)
            return dict(res) if isinstance(res, dict) else {"success": False, "status": "LIST_WINDOWS_FAILED", "windows": []}
        except Exception as exc:
            logger.error("Failed listing Windows desktop windows: %s", exc)
            return {
                "success": False,
                "status": "LIST_WINDOWS_FAILED",
                "windows": [],
                "error": str(exc),
            }

    async def list_windows(
        self,
        include_empty_titles: bool = False,
        limit: int = 50,
    ) -> dict[str, Any]:
        """Asynchronously list open visible top-level windows on Windows."""
        return await asyncio.to_thread(self.list_windows_sync, include_empty_titles, limit)

    def focus_window_sync(
        self,
        hwnd: Optional[int] = None,
        title_contains: str = "",
        process_name: str = "",
    ) -> dict[str, Any]:
        """Validate selector bounds and bring a matching window to the foreground."""
        parsed_hwnd: Optional[int] = None
        if hwnd is not None:
            if isinstance(hwnd, bool) or not isinstance(hwnd, int) or hwnd <= 0:
                return {
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "'hwnd' must be a positive integer window handle.",
                }
            parsed_hwnd = hwnd

        if title_contains is not None and not isinstance(title_contains, str):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'title_contains' must be a string.",
            }
        if process_name is not None and not isinstance(process_name, str):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "'process_name' must be a string.",
            }

        clean_title = _sanitize_text(title_contains or "", MAX_WINDOW_TITLE_CHARS)
        clean_proc = _sanitize_text(process_name or "", 128)
        if parsed_hwnd is None and not clean_title and not clean_proc:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Provide at least one selector: 'hwnd', 'title_contains', or 'process_name'.",
            }

        try:
            res = self._focus_window_fn(parsed_hwnd, clean_title, clean_proc)
            return dict(res) if isinstance(res, dict) else {"success": False, "status": "FOCUS_FAILED"}
        except Exception as exc:
            logger.error("Failed focusing Windows desktop window: %s", exc)
            return {
                "success": False,
                "status": "FOCUS_FAILED",
                "error": str(exc),
            }

    async def focus_window(
        self,
        hwnd: Optional[int] = None,
        title_contains: str = "",
        process_name: str = "",
    ) -> dict[str, Any]:
        """Asynchronously focus an open Windows desktop window."""
        return await asyncio.to_thread(self.focus_window_sync, hwnd, title_contains, process_name)

    def send_hotkey_sync(self, shortcut: str) -> dict[str, Any]:
        """Validate allowlisted shortcut chord and dispatch via Win32 SendInput."""
        if not isinstance(shortcut, str) or not shortcut.strip():
            return {
                "success": False,
                "status": "INVALID_HOTKEY",
                "error": "'shortcut' must be a non-empty allowlisted hotkey string.",
            }
        norm = normalize_hotkey_shortcut(shortcut)
        if norm not in ALLOWED_HOTKEYS:
            return {
                "success": False,
                "status": "INVALID_HOTKEY",
                "error": (
                    f"Hotkey '{shortcut}' is not permitted. Allowed shortcuts: "
                    f"{', '.join(sorted(ALLOWED_HOTKEYS.keys()))}."
                ),
            }
        try:
            res = self._send_hotkey_fn(norm)
            return dict(res) if isinstance(res, dict) else {"success": False, "status": "HOTKEY_FAILED"}
        except Exception as exc:
            logger.error("Failed dispatching hotkey '%s': %s", norm, exc)
            return {"success": False, "status": "HOTKEY_FAILED", "error": str(exc)}

    async def send_hotkey(self, shortcut: str) -> dict[str, Any]:
        """Asynchronously dispatch an allowlisted Windows hotkey."""
        return await asyncio.to_thread(self.send_hotkey_sync, shortcut)

    def set_brightness_sync(self, level: Any) -> dict[str, Any]:
        """Validate display brightness percentage (0..100 strict int) and apply via DDC/CI then WMI fallback."""
        if isinstance(level, bool) or not isinstance(level, int):
            return {
                "success": False,
                "status": "INVALID_BRIGHTNESS_LEVEL",
                "error": "Brightness 'level' must be an integer between 0 and 100.",
            }
        if level < 0 or level > 100:
            return {
                "success": False,
                "status": "INVALID_BRIGHTNESS_LEVEL",
                "error": "Brightness 'level' must be between 0 and 100.",
            }
        try:
            res = self._set_brightness_fn(int(level))
            if isinstance(res, dict) and res.get("success"):
                out = dict(res)
                out.setdefault("method", "ddc_ci")
                return out
            primary_status = res.get("status") if isinstance(res, dict) else "UNSUPPORTED_DISPLAY"
            if primary_status == "UNSUPPORTED_DISPLAY" and self._wmi_brightness_fn is not None:
                wmi_res = self._wmi_brightness_fn(int(level))
                if isinstance(wmi_res, dict):
                    if wmi_res.get("success"):
                        out = dict(wmi_res)
                        out.setdefault("method", "wmi")
                        return out
                    if wmi_res.get("status") == "PERMISSION_DENIED":
                        return dict(wmi_res)
            return dict(res) if isinstance(res, dict) else {"success": False, "status": "UNSUPPORTED_DISPLAY"}
        except Exception as exc:
            logger.error("Failed setting Windows brightness level %s: %s", level, exc)
            return {"success": False, "status": "UNSUPPORTED_DISPLAY", "error": str(exc)}

    async def set_brightness(self, level: Any) -> dict[str, Any]:
        """Asynchronously set primary monitor brightness (0..100)."""
        return await asyncio.to_thread(self.set_brightness_sync, level)
