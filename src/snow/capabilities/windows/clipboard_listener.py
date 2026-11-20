"""Event-driven Win32 clipboard change listener for SNOW.

Uses AddClipboardFormatListener with a message pump on a dedicated background
thread to detect Windows OS clipboard changes without polling.

Hardened with explicit 64-bit ctypes prototypes, persistent WNDPROC reference,
and clean window/class teardown.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import logging
import sys
import threading
from typing import Callable, Optional

logger = logging.getLogger(__name__)

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_CLIPBOARDUPDATE = 0x031D


class WindowsClipboardListener:
    """Listens for Windows clipboard changes using AddClipboardFormatListener."""

    def __init__(self, on_change: Callable[[], None]) -> None:
        self._on_change = on_change
        self._thread: Optional[threading.Thread] = None
        self._hwnd: Optional[int] = None
        self._ready_event = threading.Event()
        self._is_running = False
        self._wnd_proc_ref = None  # Prevent GC of ctypes callback

    def start(self) -> bool:
        """Start the background clipboard format listener thread."""
        if sys.platform != "win32":
            return False
        if self._is_running:
            return True

        self._ready_event.clear()
        self._thread = threading.Thread(
            target=self._run_message_pump,
            name="SnowClipboardListener",
            daemon=True,
        )
        self._thread.start()
        # Wait up to 2 seconds for window creation and listener attachment
        if not self._ready_event.wait(timeout=2.0):
            logger.warning("Clipboard listener window creation timed out.")
            return False

        self._is_running = self._hwnd is not None and self._hwnd != 0
        return self._is_running

    def stop(self) -> None:
        """Stop the listener thread and clean up Win32 resources."""
        if not self._is_running or not self._hwnd:
            return

        self._is_running = False
        try:
            user32 = ctypes.windll.user32
            user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
            user32.PostMessageW.restype = wintypes.BOOL
            user32.PostMessageW(self._hwnd, WM_CLOSE, 0, 0)
        except Exception as exc:
            logger.debug("Failed sending WM_CLOSE to clipboard listener window: %s", exc)

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.5)
        self._thread = None
        self._hwnd = None

    def _run_message_pump(self) -> None:
        """Thread worker creating the hidden top-level window and pumping Win32 messages."""
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32

        # 64-bit / 32-bit compatible WNDPROC prototype
        WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)

        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = ctypes.c_ssize_t

        class WNDCLASSEXW(ctypes.Structure):
            _fields_ = [
                ("cbSize", wintypes.UINT),
                ("style", wintypes.UINT),
                ("lpfnWndProc", WNDPROC),
                ("cbClsExtra", ctypes.c_int),
                ("cbWndExtra", ctypes.c_int),
                ("hInstance", wintypes.HINSTANCE),
                ("hIcon", wintypes.HICON),
                ("hCursor", wintypes.HANDLE),
                ("hbrBackground", wintypes.HBRUSH),
                ("lpszMenuName", wintypes.LPCWSTR),
                ("lpszClassName", wintypes.LPCWSTR),
                ("hIconSm", wintypes.HICON),
            ]

        def _py_wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            if msg == WM_CLIPBOARDUPDATE:
                try:
                    self._on_change()
                except Exception as exc:
                    logger.debug("Error in clipboard change callback: %s", exc)
                return 0
            elif msg == WM_CLOSE:
                user32.DestroyWindow(hwnd)
                return 0
            elif msg == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        self._wnd_proc_ref = WNDPROC(_py_wnd_proc)
        hinst = kernel32.GetModuleHandleW(None)
        cls_name = f"SnowClipboardListenerWnd_{id(self)}"

        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._wnd_proc_ref
        wc.hInstance = hinst
        wc.lpszClassName = cls_name

        user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
        user32.RegisterClassExW.restype = wintypes.ATOM
        atom = user32.RegisterClassExW(ctypes.byref(wc))
        if not atom:
            logger.warning("RegisterClassExW failed for clipboard listener window.")
            self._ready_event.set()
            return

        user32.CreateWindowExW.argtypes = [
            wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
            ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID
        ]
        user32.CreateWindowExW.restype = wintypes.HWND

        hwnd = user32.CreateWindowExW(
            0, cls_name, "SnowClipboardListener", 0,
            0, 0, 0, 0,
            0, 0, hinst, 0
        )
        if not hwnd:
            logger.warning("CreateWindowExW failed for clipboard listener window.")
            user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
            user32.UnregisterClassW.restype = wintypes.BOOL
            user32.UnregisterClassW(cls_name, hinst)
            self._ready_event.set()
            return

        user32.AddClipboardFormatListener.argtypes = [wintypes.HWND]
        user32.AddClipboardFormatListener.restype = wintypes.BOOL
        success = user32.AddClipboardFormatListener(hwnd)
        if not success:
            logger.warning("AddClipboardFormatListener returned false.")
            user32.DestroyWindow.argtypes = [wintypes.HWND]
            user32.DestroyWindow.restype = wintypes.BOOL
            user32.DestroyWindow(hwnd)
            user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
            user32.UnregisterClassW.restype = wintypes.BOOL
            user32.UnregisterClassW(cls_name, hinst)
            self._ready_event.set()
            return

        self._hwnd = hwnd
        self._ready_event.set()

        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        user32.GetMessageW.restype = wintypes.BOOL
        user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.TranslateMessage.restype = wintypes.BOOL
        user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
        user32.DispatchMessageW.restype = ctypes.c_ssize_t

        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        user32.RemoveClipboardFormatListener.argtypes = [wintypes.HWND]
        user32.RemoveClipboardFormatListener.restype = wintypes.BOOL
        user32.RemoveClipboardFormatListener(hwnd)

        user32.UnregisterClassW.argtypes = [wintypes.LPCWSTR, wintypes.HINSTANCE]
        user32.UnregisterClassW.restype = wintypes.BOOL
        user32.UnregisterClassW(cls_name, hinst)
