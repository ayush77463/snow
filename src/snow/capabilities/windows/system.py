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
import re
import sys
from typing import Any, Callable, Optional

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


class WindowsSystemControls:
    """Thread-safe, testable Windows workstation & shell notification capabilities."""

    def __init__(
        self,
        active_window_fn: Optional[Callable[[], dict[str, Any]]] = None,
        notify_fn: Optional[Callable[[str, str], dict[str, Any]]] = None,
        lock_fn: Optional[Callable[[], dict[str, Any]]] = None,
        list_windows_fn: Optional[Callable[[bool, int], dict[str, Any]]] = None,
        focus_window_fn: Optional[Callable[[Optional[int], str, str], dict[str, Any]]] = None,
    ) -> None:
        self._active_window_fn = active_window_fn or _default_active_window_win32
        self._notify_fn = notify_fn or _default_notify_win32
        self._lock_fn = lock_fn or _default_lock_workstation_win32
        self._list_windows_fn = list_windows_fn or _default_list_windows_win32
        self._focus_window_fn = focus_window_fn or _default_focus_window_win32

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
