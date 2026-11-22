"""Lightweight Win32 System Tray Companion for SNOW.

Provides a persistent Windows notification area (system tray) icon implemented
with pure ctypes to ensure an ultra-lean memory footprint (< 35 MB RSS) without
introducing heavy GUI frameworks like PyQt, wxPython, or Electron.

Features:
- Live tooltip displaying Core daemon status and connected/paired device count.
- Context menu:
    * Open Dashboard (default browser)
    * Pair New Device (QR code in Dashboard)
    * Start Core Daemon
    * Stop Core Daemon
    * Toggle Start on Login (HKCU Run key)
    * Exit Tray
- Non-blocking background status polling thread.
- Clean icon lifecycle teardown on exit and uninstaller registry cleanup.
"""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
import logging
import os
from pathlib import Path
import sys
import threading
import time
from typing import Any, Callable, Optional
import webbrowser

from snow.tray.autostart import (
    is_autostart_enabled,
    set_autostart,
)

logger = logging.getLogger(__name__)

# Win32 Constants
WM_USER: int = 0x0400
WM_TRAYICON: int = WM_USER + 20
WM_COMMAND: int = 0x0111
WM_LBUTTONUP: int = 0x0202
WM_RBUTTONUP: int = 0x0205
WM_LBUTTONDBLCLK: int = 0x0203
WM_DESTROY: int = 0x0002

NIM_ADD: int = 0x00000000
NIM_MODIFY: int = 0x00000001
NIM_DELETE: int = 0x00000002

NIF_MESSAGE: int = 0x00000001
NIF_ICON: int = 0x00000002
NIF_TIP: int = 0x00000004

MF_STRING: int = 0x00000000
MF_SEPARATOR: int = 0x00000800
MF_CHECKED: int = 0x00000008
MF_UNCHECKED: int = 0x00000000
MF_GRAYED: int = 0x00000001

TPM_RIGHTALIGN: int = 0x0008
TPM_BOTTOMALIGN: int = 0x0020
TPM_RETURNCMD: int = 0x0100

IDI_APPLICATION: int = 32512

# Menu Command IDs
CMD_OPEN_DASHBOARD: int = 2001
CMD_PAIR_DEVICE: int = 2002
CMD_START_CORE: int = 2003
CMD_STOP_CORE: int = 2004
CMD_TOGGLE_AUTOSTART: int = 2005
CMD_EXIT: int = 2006

if sys.platform == "win32":
    LRESULT = ctypes.c_ssize_t

    WNDPROC = ctypes.WINFUNCTYPE(
        LRESULT,
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    )

    class WNDCLASSEXW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.UINT),
            ("style", wintypes.UINT),
            ("lpfnWndProc", WNDPROC),
            ("cbClsExtra", ctypes.c_int),
            ("cbWndExtra", ctypes.c_int),
            ("hInstance", wintypes.HINSTANCE),
            ("hIcon", wintypes.HICON),
            ("hCursor", wintypes.HICON),
            ("hbrBackground", wintypes.HBRUSH),
            ("lpszMenuName", wintypes.LPCWSTR),
            ("lpszClassName", wintypes.LPCWSTR),
            ("hIconSm", wintypes.HICON),
        ]

    class NOTIFYICONDATAW(ctypes.Structure):
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
            ("uTimeoutOrVersion", wintypes.UINT),
            ("szInfoTitle", wintypes.WCHAR * 64),
            ("dwInfoFlags", wintypes.DWORD),
            ("guidItem", ctypes.c_byte * 16),
            ("hBalloonIcon", wintypes.HICON),
        ]

    class POINT(ctypes.Structure):
        _fields_ = [
            ("x", wintypes.LONG),
            ("y", wintypes.LONG),
        ]

    # Explicit 64-bit-safe function prototypes
    _kernel32 = ctypes.windll.kernel32
    _user32 = ctypes.windll.user32
    _shell32 = ctypes.windll.shell32

    _kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    _kernel32.GetModuleHandleW.restype = wintypes.HMODULE

    _kernel32.GetLastError.argtypes = []
    _kernel32.GetLastError.restype = wintypes.DWORD

    _user32.LoadIconW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    _user32.LoadIconW.restype = wintypes.HICON

    _user32.LoadCursorW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR]
    _user32.LoadCursorW.restype = wintypes.HICON

    _user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
    _user32.RegisterClassExW.restype = wintypes.ATOM

    _user32.CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HMENU,
        wintypes.HINSTANCE,
        wintypes.LPVOID,
    ]
    _user32.CreateWindowExW.restype = wintypes.HWND

    _user32.DefWindowProcW.argtypes = [
        wintypes.HWND,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    _user32.DefWindowProcW.restype = LRESULT

    _user32.CreatePopupMenu.argtypes = []
    _user32.CreatePopupMenu.restype = wintypes.HMENU

    _user32.AppendMenuW.argtypes = [
        wintypes.HMENU,
        wintypes.UINT,
        ctypes.c_size_t,
        wintypes.LPCWSTR,
    ]
    _user32.AppendMenuW.restype = wintypes.BOOL

    _user32.DestroyMenu.argtypes = [wintypes.HMENU]
    _user32.DestroyMenu.restype = wintypes.BOOL

    _user32.SetForegroundWindow.argtypes = [wintypes.HWND]
    _user32.SetForegroundWindow.restype = wintypes.BOOL

    _user32.TrackPopupMenuEx.argtypes = [
        wintypes.HMENU,
        wintypes.UINT,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.LPVOID,
    ]
    _user32.TrackPopupMenuEx.restype = wintypes.UINT

    _user32.GetCursorPos.argtypes = [ctypes.POINTER(POINT)]
    _user32.GetCursorPos.restype = wintypes.BOOL

    _user32.DestroyWindow.argtypes = [wintypes.HWND]
    _user32.DestroyWindow.restype = wintypes.BOOL

    _user32.PostQuitMessage.argtypes = [ctypes.c_int]
    _user32.PostQuitMessage.restype = None

    _user32.GetMessageW.argtypes = [
        ctypes.POINTER(wintypes.MSG),
        wintypes.HWND,
        wintypes.UINT,
        wintypes.UINT,
    ]
    _user32.GetMessageW.restype = wintypes.BOOL

    _user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    _user32.TranslateMessage.restype = wintypes.BOOL

    _user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    _user32.DispatchMessageW.restype = LRESULT

    _shell32.Shell_NotifyIconW.argtypes = [
        wintypes.DWORD,
        ctypes.POINTER(NOTIFYICONDATAW),
    ]
    _shell32.Shell_NotifyIconW.restype = wintypes.BOOL


def is_dashboard_listening(port: int = 8769, host: str = "127.0.0.1") -> bool:
    """Check whether local dashboard port is actively listening."""
    import socket
    try:
        with socket.create_connection((host, port), timeout=0.3):
            return True
    except Exception:
        return False


class SnowTrayApp:
    """Manages the lifecycle, notifications, and menu of the SNOW system tray companion."""

    def __init__(
        self,
        dashboard_port: int = 8769,
        core_port: int = 8767,
        db_manager: Optional[Any] = None,
        daemon_manager: Optional[Any] = None,
        auto_start_core: bool = True,
        headless: bool = False,
    ) -> None:
        self.dashboard_port = dashboard_port
        self.core_port = core_port
        if db_manager is None:
            from snow.security.db import DatabaseManager
            db_manager = DatabaseManager()
        self.db_manager = db_manager
        self.auto_start_core = auto_start_core
        self.headless = headless or (sys.platform != "win32")

        if daemon_manager is None:
            from snow.daemon import CoreDaemonManager
            daemon_manager = CoreDaemonManager(port=self.core_port)
        self.daemon_manager = daemon_manager
        self._hwnd: Optional[int] = None
        self._nid: Optional[Any] = None
        self._is_running: bool = False
        self._core_online: bool = False
        self._device_count: int = 0
        self._status_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._dashboard_spawn_lock = threading.Lock()
        self._dashboard_proc: Optional[Any] = None

    @property
    def dashboard_url(self) -> str:
        return f"http://127.0.0.1:{self.dashboard_port}"

    def is_dashboard_listening(self) -> bool:
        """Check whether local dashboard port is actively listening."""
        return is_dashboard_listening(self.dashboard_port)

    def ensure_dashboard_running_and_open(self, path_suffix: str = "") -> None:
        """Ensure dashboard is running (spawning in background if offline) and open in browser."""
        threading.Thread(
            target=self._dashboard_startup_worker,
            args=(path_suffix,),
            daemon=True,
        ).start()

    def _dashboard_startup_worker(self, path_suffix: str = "") -> None:
        """Background worker ensuring dashboard process is online before browser launch."""
        with self._dashboard_spawn_lock:
            if path_suffix.startswith("http://") or path_suffix.startswith("https://"):
                target_url = path_suffix
            else:
                target_url = f"{self.dashboard_url}{path_suffix}"
            if not self.is_dashboard_listening():
                logger.info("Web dashboard offline on port %d; spawning background daemon...", self.dashboard_port)
                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags |= 0x08000000 | 0x00000008  # CREATE_NO_WINDOW | DETACHED_PROCESS

                try:
                    import subprocess
                    if getattr(sys, "frozen", False) and hasattr(sys, "executable"):
                        cmd = [sys.executable, "web", "--port", str(self.dashboard_port), "--no-browser"]
                    else:
                        cmd = [sys.executable, "-m", "snow.cli", "web", "--port", str(self.dashboard_port), "--no-browser"]

                    proc = subprocess.Popen(
                        cmd,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                        creationflags=creation_flags,
                        close_fds=True,
                    )
                    self._dashboard_proc = proc
                except Exception as exc:
                    logger.error("Failed spawning web dashboard process: %s", exc)
                    return

                # Bounded readiness polling (up to 5.0s)
                deadline = time.monotonic() + 5.0
                ready = False
                while time.monotonic() < deadline:
                    if self.is_dashboard_listening():
                        ready = True
                        break
                    time.sleep(0.15)

                if not ready:
                    logger.error("Timed out waiting for web dashboard readiness on port %d.", self.dashboard_port)
                    return

            try:
                webbrowser.open(target_url)
            except Exception as exc:
                logger.error("Failed opening browser to %s: %s", target_url, exc)

    def compute_tooltip(self) -> str:
        """Generate formatted tooltip string (<= 127 chars for NOTIFYICONDATAW)."""
        core_status = f"Running ({self.core_port})" if self._core_online else "Stopped"
        dev_text = f"{self._device_count} paired" if self._device_count != 1 else "1 paired"
        tip = f"SNOW Core: {core_status}\nDevices: {dev_text}"
        return tip[:127]

    def refresh_status(self) -> dict[str, Any]:
        """Poll daemon status and database device count synchronously."""
        # 1. Daemon check
        pid = self.daemon_manager.get_tracked_pid()
        is_alive = False
        if pid:
            is_alive = self.daemon_manager.is_process_snow_core(pid)

        # Quick TCP check
        try:
            import socket
            with socket.create_connection(("127.0.0.1", self.core_port), timeout=0.3):
                is_alive = True
        except Exception:
            pass

        self._core_online = is_alive

        # 2. Database devices check
        try:
            devices = self.db_manager.list_paired_devices()
            self._device_count = len(devices)
        except Exception as exc:
            logger.debug("Failed querying devices: %s", exc)
            self._device_count = 0

        return {
            "core_online": self._core_online,
            "device_count": self._device_count,
            "tooltip": self.compute_tooltip(),
        }

    def dispatch_command(self, cmd_id: int) -> None:
        """Handle execution of a context menu selection."""
        logger.info("Tray command selected: %d", cmd_id)

        if cmd_id == CMD_OPEN_DASHBOARD:
            self.ensure_dashboard_running_and_open()

        elif cmd_id == CMD_PAIR_DEVICE:
            self.ensure_dashboard_running_and_open("/?action=pair")

        elif cmd_id == CMD_START_CORE:
            threading.Thread(target=self._start_core_sync, daemon=True).start()

        elif cmd_id == CMD_STOP_CORE:
            threading.Thread(target=self._stop_core_sync, daemon=True).start()

        elif cmd_id == CMD_TOGGLE_AUTOSTART:
            current = is_autostart_enabled()
            set_autostart(not current)

        elif cmd_id == CMD_EXIT:
            self.stop()

    def _start_core_sync(self) -> None:
        try:
            asyncio.run(self.daemon_manager.ensure_core_running())
        except Exception as exc:
            logger.error("Failed starting core daemon from tray: %s", exc)
        self.refresh_status()
        self._update_icon()

    def _stop_core_sync(self) -> None:
        try:
            asyncio.run(self.daemon_manager.stop_core())
        except Exception as exc:
            logger.error("Failed stopping core daemon from tray: %s", exc)
        self.refresh_status()
        self._update_icon()

    def _show_context_menu(self) -> None:
        """Render context menu at current cursor coordinates."""
        if sys.platform != "win32" or not self._hwnd:
            return

        user32 = ctypes.windll.user32
        pt = POINT()
        user32.GetCursorPos(ctypes.byref(pt))

        hmenu = user32.CreatePopupMenu()
        try:
            # Dashboard & Pairing
            user32.AppendMenuW(hmenu, MF_STRING, CMD_OPEN_DASHBOARD, "Open Dashboard")
            user32.AppendMenuW(hmenu, MF_STRING, CMD_PAIR_DEVICE, "Pair New Device (QR)...")
            user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)

            # Core lifecycle
            if self._core_online:
                user32.AppendMenuW(hmenu, MF_GRAYED, CMD_START_CORE, "Core Running")
                user32.AppendMenuW(hmenu, MF_STRING, CMD_STOP_CORE, "Stop Core Daemon")
            else:
                user32.AppendMenuW(hmenu, MF_STRING, CMD_START_CORE, "Start Core Daemon")
                user32.AppendMenuW(hmenu, MF_GRAYED, CMD_STOP_CORE, "Core Stopped")

            user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)

            # Autostart on login toggle
            autostart_flags = MF_STRING | (MF_CHECKED if is_autostart_enabled() else MF_UNCHECKED)
            user32.AppendMenuW(hmenu, autostart_flags, CMD_TOGGLE_AUTOSTART, "Start on Windows Login")

            user32.AppendMenuW(hmenu, MF_SEPARATOR, 0, None)
            user32.AppendMenuW(hmenu, MF_STRING, CMD_EXIT, "Exit SNOW")

            # Must set foreground window before TrackPopupMenu to avoid stuck menu
            user32.SetForegroundWindow(self._hwnd)
            cmd = user32.TrackPopupMenuEx(
                hmenu,
                TPM_RETURNCMD | TPM_RIGHTALIGN | TPM_BOTTOMALIGN,
                pt.x,
                pt.y,
                self._hwnd,
                None,
            )
            if cmd:
                self.dispatch_command(cmd)

        finally:
            user32.DestroyMenu(hmenu)

    def _wnd_proc(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        """Window procedure callback for notification area messages."""
        if msg == WM_TRAYICON:
            if lparam in (WM_RBUTTONUP, WM_LBUTTONUP):
                self._show_context_menu()
            elif lparam == WM_LBUTTONDBLCLK:
                self.ensure_dashboard_running_and_open()
            return 0

        elif msg == WM_COMMAND:
            self.dispatch_command(wparam)
            return 0

        elif msg == WM_DESTROY:
            self._cleanup_icon()
            ctypes.windll.user32.PostQuitMessage(0)
            return 0

        return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _update_icon(self) -> None:
        """Update the tooltip text and icon status."""
        if sys.platform != "win32" or not self._nid or not self._hwnd:
            return

        tip = self.compute_tooltip()
        self._nid.szTip = tip
        self._nid.uFlags = NIF_TIP | NIF_MESSAGE
        ctypes.windll.shell32.Shell_NotifyIconW(NIM_MODIFY, ctypes.byref(self._nid))

    def _cleanup_icon(self) -> None:
        """Remove notification icon from system tray."""
        if sys.platform == "win32" and self._nid:
            ctypes.windll.shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
            self._nid = None

    def _background_monitor(self) -> None:
        """Periodically refresh core status and tooltip in the background."""
        while not self._stop_event.is_set():
            self.refresh_status()
            self._update_icon()
            self._stop_event.wait(timeout=3.0)

    def run(self) -> int:
        """Main entry point. Initializes system tray icon and pumps message loop."""
        if self.headless:
            logger.info("Starting SNOW tray in headless / test mode.")
            self._is_running = True
            self.refresh_status()
            if self.auto_start_core and not self._core_online:
                self._start_core_sync()
            return 0

        if sys.platform != "win32":
            logger.error("SNOW Tray is only supported natively on Windows.")
            return 1

        self._is_running = True
        self.refresh_status()

        if self.auto_start_core and not self._core_online:
            threading.Thread(target=self._start_core_sync, daemon=True).start()

        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        shell32 = ctypes.windll.shell32

        # 1. Register Window Class
        class_name = f"SNOW_Tray_Window_{os.getpid()}"
        hinstance = kernel32.GetModuleHandleW(None)

        self._wnd_proc_ref = WNDPROC(self._wnd_proc)  # Retain reference to prevent GC
        wcex = WNDCLASSEXW()
        wcex.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wcex.style = 0
        wcex.lpfnWndProc = self._wnd_proc_ref
        wcex.hInstance = hinstance
        wcex.hIcon = user32.LoadIconW(0, ctypes.c_wchar_p(IDI_APPLICATION))
        wcex.hCursor = user32.LoadCursorW(0, ctypes.c_wchar_p(32512))
        wcex.lpszClassName = class_name

        atom = user32.RegisterClassExW(ctypes.byref(wcex))
        if not atom:
            logger.error("Failed registering tray window class.")
            return 1

        # 2. Create message-only / hidden window
        self._hwnd = user32.CreateWindowExW(
            0,
            class_name,
            "SNOW Tray Host",
            0,
            0, 0, 0, 0,
            0, 0, hinstance, 0,
        )
        if not self._hwnd:
            logger.error("Failed creating tray window.")
            return 1

        # 3. Add Notification Icon
        self._nid = NOTIFYICONDATAW()
        self._nid.cbSize = ctypes.sizeof(NOTIFYICONDATAW)
        self._nid.hWnd = self._hwnd
        self._nid.uID = 1
        self._nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP
        self._nid.uCallbackMessage = WM_TRAYICON
        self._nid.hIcon = wcex.hIcon
        self._nid.szTip = self.compute_tooltip()

        res = shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(self._nid))
        if not res:
            logger.warning("Shell_NotifyIconW NIM_ADD returned False. Tray icon may not be visible.")

        # 4. Start background monitor thread
        self._status_thread = threading.Thread(target=self._background_monitor, daemon=True)
        self._status_thread.start()

        logger.info("SNOW System Tray Companion is active.")

        # 5. Win32 Message Loop
        msg = wintypes.MSG()
        p_msg = ctypes.byref(msg)
        try:
            while True:
                res = user32.GetMessageW(p_msg, None, 0, 0)
                if res == 0:  # WM_QUIT
                    break
                elif res == -1:  # Win32 Error
                    err = kernel32.GetLastError()
                    logger.error("GetMessageW error: %d", err)
                    break
                user32.TranslateMessage(p_msg)
                user32.DispatchMessageW(p_msg)
        except KeyboardInterrupt:
            self.stop()
        finally:
            self.stop()

        return 0

    def stop(self) -> None:
        """Signal exit and clean up Win32 resources."""
        self._stop_event.set()
        self._is_running = False
        if self._hwnd and sys.platform == "win32":
            ctypes.windll.user32.DestroyWindow(self._hwnd)
            self._hwnd = None
        self._cleanup_icon()
