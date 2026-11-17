"""Windows clipboard management capability for SNOW.

Provides safe reading and writing to the Windows OS clipboard using
standard library ctypes and Win32 APIs without third-party dependencies.

WIN32 CLIPBOARD INVARIANTS:
1. Format: Uses CF_UNICODETEXT (13) for full Unicode UTF-16LE fidelity.
2. Contention Handling: Retries OpenClipboard with bounded exponential backoff
   to tolerate transient clipboard locking by other applications.
3. Ownership Handover: Upon successful SetClipboardData, Windows takes ownership
   of the global memory block. GlobalFree is only called if allocation succeeds
   but SetClipboardData fails.
4. Bounded Read: Caps clipboard reads to MAX_CLIPBOARD_READ_BYTES (1 MiB) to prevent
   memory exhaustion from massive binary or text buffers.
5. Interactive Session Enforcement: Returns structured errors if clipboard access
   is unavailable (e.g. running in an isolated headless non-interactive session).
"""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
import logging
import sys
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

CF_UNICODETEXT: int = 13
GMEM_MOVEABLE: int = 0x0002
GMEM_ZEROINIT: int = 0x0040
GHND: int = GMEM_MOVEABLE | GMEM_ZEROINIT

MAX_CLIPBOARD_READ_BYTES: int = 1024 * 1024  # 1 MiB read cap
MAX_OPEN_RETRIES: int = 5
RETRY_DELAY_SECONDS: float = 0.05


class WindowsClipboardManager:
    """Manages Windows clipboard reading and writing via standard Win32 ctypes."""

    def __init__(self) -> None:
        self._is_windows = sys.platform == "win32"
        self._user32 = None
        self._kernel32 = None

        if self._is_windows:
            try:
                self._user32 = ctypes.windll.user32
                self._kernel32 = ctypes.windll.kernel32
                self._configure_types()
            except Exception as exc:
                logger.warning("Could not initialize Win32 ctypes for clipboard: %s", exc)

    def _configure_types(self) -> None:
        """Set up ctypes function signatures for Win32 API functions."""
        if not self._user32 or not self._kernel32:
            return

        self._user32.OpenClipboard.argtypes = [wintypes.HWND]
        self._user32.OpenClipboard.restype = wintypes.BOOL

        self._user32.CloseClipboard.argtypes = []
        self._user32.CloseClipboard.restype = wintypes.BOOL

        self._user32.EmptyClipboard.argtypes = []
        self._user32.EmptyClipboard.restype = wintypes.BOOL

        self._user32.GetClipboardData.argtypes = [wintypes.UINT]
        self._user32.GetClipboardData.restype = wintypes.HANDLE

        self._user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
        self._user32.SetClipboardData.restype = wintypes.HANDLE

        self._kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        self._kernel32.GlobalAlloc.restype = wintypes.HGLOBAL

        self._kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
        self._kernel32.GlobalLock.restype = wintypes.LPVOID

        self._kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
        self._kernel32.GlobalUnlock.restype = wintypes.BOOL

        self._kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
        self._kernel32.GlobalFree.restype = wintypes.HGLOBAL

    def _open_clipboard_with_retry(self) -> bool:
        """Attempt to open clipboard with bounded retries for contention."""
        if not self._user32:
            return False

        for attempt in range(MAX_OPEN_RETRIES):
            if self._user32.OpenClipboard(None):
                return True
            time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))
        return False

    def get_clipboard_sync(self) -> dict[str, Any]:
        """Synchronously read text from the Windows clipboard."""
        if not self._is_windows or not self._user32 or not self._kernel32:
            return {
                "success": False,
                "status": "UNSUPPORTED_PLATFORM",
                "error": "Windows clipboard is only available on Windows platforms.",
                "text": "",
            }

        if not self._open_clipboard_with_retry():
            return {
                "success": False,
                "status": "CLIPBOARD_BUSY",
                "error": "Failed to open Windows clipboard (locked by another process or non-interactive session).",
                "text": "",
            }

        try:
            handle = self._user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                # Clipboard is empty or contains no CF_UNICODETEXT data
                return {
                    "success": True,
                    "status": "EMPTY",
                    "text": "",
                    "message": "Clipboard is empty or does not contain text.",
                }

            ptr = self._kernel32.GlobalLock(handle)
            if not ptr:
                return {
                    "success": False,
                    "status": "LOCK_FAILED",
                    "error": "Failed locking global clipboard memory handle.",
                    "text": "",
                }

            try:
                # Read null-terminated UTF-16LE string from pointer
                text_val = ctypes.wstring_at(ptr)
                # Cap maximum read length
                if len(text_val.encode("utf-8", errors="replace")) > MAX_CLIPBOARD_READ_BYTES:
                    text_val = text_val[:MAX_CLIPBOARD_READ_BYTES]

                return {
                    "success": True,
                    "status": "SUCCESS",
                    "text": text_val,
                    "length": len(text_val),
                }
            finally:
                self._kernel32.GlobalUnlock(handle)
        finally:
            self._user32.CloseClipboard()

    async def get_clipboard(self) -> dict[str, Any]:
        """Asynchronously read text from the Windows clipboard on a worker thread."""
        return await asyncio.to_thread(self.get_clipboard_sync)

    def set_clipboard_sync(self, text: str) -> dict[str, Any]:
        """Synchronously write text to the Windows clipboard."""
        if not isinstance(text, str):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": f"Clipboard text must be a string, got {type(text).__name__}.",
            }

        if not self._is_windows or not self._user32 or not self._kernel32:
            return {
                "success": False,
                "status": "UNSUPPORTED_PLATFORM",
                "error": "Windows clipboard is only available on Windows platforms.",
            }

        # Encode text as UTF-16LE with null-terminator
        encoded_bytes = text.encode("utf-16le") + b"\x00\x00"
        byte_count = len(encoded_bytes)

        # Allocate moveable global memory
        h_mem = self._kernel32.GlobalAlloc(GHND, byte_count)
        if not h_mem:
            return {
                "success": False,
                "status": "ALLOCATION_FAILED",
                "error": f"Failed allocating {byte_count} bytes for clipboard data.",
            }

        # Lock and copy memory
        ptr = self._kernel32.GlobalLock(h_mem)
        if not ptr:
            self._kernel32.GlobalFree(h_mem)
            return {
                "success": False,
                "status": "LOCK_FAILED",
                "error": "Failed locking global memory for clipboard.",
            }

        try:
            ctypes.memmove(ptr, encoded_bytes, byte_count)
        finally:
            self._kernel32.GlobalUnlock(h_mem)

        # Open and update clipboard
        if not self._open_clipboard_with_retry():
            self._kernel32.GlobalFree(h_mem)
            return {
                "success": False,
                "status": "CLIPBOARD_BUSY",
                "error": "Failed to open Windows clipboard to write.",
            }

        try:
            self._user32.EmptyClipboard()
            res_handle = self._user32.SetClipboardData(CF_UNICODETEXT, h_mem)
            if not res_handle:
                # If SetClipboardData fails, we must free the allocated memory
                self._kernel32.GlobalFree(h_mem)
                return {
                    "success": False,
                    "status": "SET_DATA_FAILED",
                    "error": "SetClipboardData returned null.",
                }

            # On success, Windows takes ownership of h_mem. Do NOT free it.
            return {
                "success": True,
                "status": "SUCCESS",
                "bytes_copied": byte_count,
                "character_count": len(text),
                "message": f"Successfully copied {len(text)} characters to Windows clipboard.",
            }
        finally:
            self._user32.CloseClipboard()

    async def set_clipboard(self, text: str) -> dict[str, Any]:
        """Asynchronously write text to the Windows clipboard on a worker thread."""
        return await asyncio.to_thread(self.set_clipboard_sync, text)
