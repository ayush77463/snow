"""Consent-gated native Windows screen capture capability for SNOW.

Uses Win32 GDI for screen acquisition and GDI+ for PNG encoding via standard library
ctypes without third-party imaging dependencies (Pillow, PyAutoGUI).
Enforces interactive session boundaries (WinSta0/default), bounded dimensions,
atomic capture staging, SHA-256 integrity, and strict resource cleanup.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import logging
import os
from pathlib import Path
import platform
import secrets
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Default storage location under ~/.snow/transfers/captures/
DEFAULT_CAPTURES_DIR = Path.home() / ".snow" / "transfers" / "captures"
MAX_CAPTURE_WIDTH = 7680
MAX_CAPTURE_HEIGHT = 4320
MAX_CAPTURE_SIZE_BYTES = 15 * 1024 * 1024  # 15 MiB
MAX_RETENTION_FILES = 50
MAX_RETENTION_AGE_SECONDS = 86400  # 24 hours


# -----------------------------------------------------------------------------
# Win32 / GDI+ ctypes structures and CLSIDs
# -----------------------------------------------------------------------------

class GdiplusStartupInput(ctypes.Structure):
    _fields_ = [
        ("GdiplusVersion", ctypes.c_uint32),
        ("DebugEventCallback", ctypes.c_void_p),
        ("SuppressBackgroundThread", wintypes.BOOL),
        ("SuppressExternalCodecs", wintypes.BOOL),
    ]


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]


# CLSID for PNG encoder: {557CF406-1A04-11D3-9A73-0000F81EF32E}
CLSID_PNG = GUID(
    0x557CF406,
    0x1A04,
    0x11D3,
    (ctypes.c_ubyte * 8)(0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E),
)


class WindowsScreenshotCapture:
    """Native Windows screen capture service using Win32 GDI and GDI+."""

    def __init__(self, output_dir: Optional[Path | str] = None) -> None:
        self.output_dir = Path(output_dir) if output_dir else DEFAULT_CAPTURES_DIR
        self._ensure_output_dir()

    def _ensure_output_dir(self) -> None:
        """Create output captures directory if missing."""
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.warning("Failed ensuring captures directory '%s': %s", self.output_dir, exc)

    def is_interactive_session(self) -> Tuple[bool, str]:
        """Verify that the current process has access to an active interactive Windows desktop.

        Checks:
        1. Host OS is Windows.
        2. Window station is interactive ('WinSta0').
        3. Input desktop is accessible (OpenInputDesktop succeeds) and not locked/service.
        """
        if platform.system() != "Windows":
            return False, f"Screenshot capability requires Windows (current: {platform.system()})."

        try:
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32

            # Configure signatures
            user32.GetProcessWindowStation.restype = ctypes.c_void_p
            user32.GetProcessWindowStation.argtypes = []

            user32.GetUserObjectInformationW.restype = wintypes.BOOL
            user32.GetUserObjectInformationW.argtypes = [
                ctypes.c_void_p,
                ctypes.c_int,
                ctypes.c_void_p,
                ctypes.c_ulong,
                ctypes.POINTER(ctypes.c_ulong),
            ]

            user32.OpenInputDesktop.restype = ctypes.c_void_p
            user32.OpenInputDesktop.argtypes = [ctypes.c_uint, wintypes.BOOL, ctypes.c_uint]

            user32.CloseDesktop.restype = wintypes.BOOL
            user32.CloseDesktop.argtypes = [ctypes.c_void_p]

            # 1. Window station check (UOI_NAME = 2)
            h_winsta = user32.GetProcessWindowStation()
            if not h_winsta:
                return False, "Failed acquiring process window station handle."

            name_buf = ctypes.create_unicode_buffer(256)
            needed = ctypes.c_ulong()
            if not user32.GetUserObjectInformationW(h_winsta, 2, name_buf, ctypes.sizeof(name_buf), ctypes.byref(needed)):
                return False, "Failed retrieving window station name."

            station_name = name_buf.value.strip().lower()
            if "winsta0" not in station_name:
                return False, f"Non-interactive window station: '{station_name}'. Must be 'WinSta0'."

            # 2. Input desktop accessibility check (e.g. not locked or switched away)
            h_input = user32.OpenInputDesktop(0, False, 0x0100)  # DESKTOP_READOBJECTS
            if not h_input:
                err = kernel32.GetLastError()
                return False, f"Interactive input desktop is locked or unavailable (error code: {err})."

            desk_buf = ctypes.create_unicode_buffer(256)
            if not user32.GetUserObjectInformationW(h_input, 2, desk_buf, ctypes.sizeof(desk_buf), ctypes.byref(needed)):
                user32.CloseDesktop(h_input)
                return False, "Failed retrieving input desktop name."

            desk_name = desk_buf.value.strip().lower()
            user32.CloseDesktop(h_input)

            # Blocked secure desktops (Winlogon, Screen-saver, etc.)
            blocked_desktops = {"winlogon", "screen-saver", "screensaver", "disconnect"}
            if desk_name in blocked_desktops:
                return False, f"Secure or inactive desktop detected: '{desk_name}'. Screen capture blocked."

            # 3. Verify screen dimensions
            user32.GetSystemMetrics.restype = ctypes.c_int
            user32.GetSystemMetrics.argtypes = [ctypes.c_int]
            width = user32.GetSystemMetrics(0)  # SM_CXSCREEN
            height = user32.GetSystemMetrics(1)  # SM_CYSCREEN
            if width <= 0 or height <= 0:
                return False, f"Invalid screen dimensions: {width}x{height}."

            return True, "Interactive desktop verified."

        except Exception as exc:
            return False, f"Session check failed with exception: {exc}"

    def prune_old_captures(self) -> None:
        """Enforce capture retention limits (file count and age)."""
        try:
            if not self.output_dir.exists():
                return
            now = time.time()
            png_files = sorted(
                self.output_dir.glob("*.png"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            for idx, p in enumerate(png_files):
                try:
                    stat = p.stat()
                    if idx >= MAX_RETENTION_FILES or (now - stat.st_mtime) > MAX_RETENTION_AGE_SECONDS:
                        p.unlink(missing_ok=True)
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("Error during capture retention pruning: %s", exc)

    def capture_screen(self) -> dict[str, Any]:
        """Capture the primary Windows screen and stage as an encoded PNG file.

        Returns:
            Structured result containing file_name, size_bytes, width, height, sha256,
            and transfer_id on success; or structured error dictionary on failure.
        """
        # 1. Verify interactive session guard
        is_interactive, session_reason = self.is_interactive_session()
        if not is_interactive:
            logger.warning("Windows screen capture rejected: %s", session_reason)
            return {
                "success": False,
                "status": "NON_INTERACTIVE_SESSION",
                "error": session_reason,
            }

        # 2. Acquire GDI and GDI+ library references
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        gdiplus = ctypes.windll.gdiplus
        kernel32 = ctypes.windll.kernel32

        # Configure 64-bit argtypes and restypes
        user32.OpenInputDesktop.restype = ctypes.c_void_p
        user32.OpenInputDesktop.argtypes = [ctypes.c_uint, wintypes.BOOL, ctypes.c_uint]

        user32.GetThreadDesktop.restype = ctypes.c_void_p
        user32.GetThreadDesktop.argtypes = [ctypes.c_ulong]

        user32.SetThreadDesktop.restype = wintypes.BOOL
        user32.SetThreadDesktop.argtypes = [ctypes.c_void_p]

        user32.CloseDesktop.restype = wintypes.BOOL
        user32.CloseDesktop.argtypes = [ctypes.c_void_p]

        kernel32.GetCurrentThreadId.restype = ctypes.c_ulong
        kernel32.GetCurrentThreadId.argtypes = []

        user32.GetDC.restype = ctypes.c_void_p
        user32.GetDC.argtypes = [ctypes.c_void_p]

        user32.ReleaseDC.restype = ctypes.c_int
        user32.ReleaseDC.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        user32.GetDesktopWindow.restype = ctypes.c_void_p
        user32.GetDesktopWindow.argtypes = []

        gdi32.CreateCompatibleDC.restype = ctypes.c_void_p
        gdi32.CreateCompatibleDC.argtypes = [ctypes.c_void_p]

        gdi32.CreateCompatibleBitmap.restype = ctypes.c_void_p
        gdi32.CreateCompatibleBitmap.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]

        gdi32.SelectObject.restype = ctypes.c_void_p
        gdi32.SelectObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        gdi32.BitBlt.restype = wintypes.BOOL
        gdi32.BitBlt.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint32,
        ]

        gdi32.DeleteDC.restype = wintypes.BOOL
        gdi32.DeleteDC.argtypes = [ctypes.c_void_p]

        gdi32.DeleteObject.restype = wintypes.BOOL
        gdi32.DeleteObject.argtypes = [ctypes.c_void_p]

        gdiplus.GdiplusStartup.restype = ctypes.c_int
        gdiplus.GdiplusStartup.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        gdiplus.GdiplusShutdown.restype = None
        gdiplus.GdiplusShutdown.argtypes = [ctypes.c_void_p]

        gdiplus.GdipCreateBitmapFromHBITMAP.restype = ctypes.c_int
        gdiplus.GdipCreateBitmapFromHBITMAP.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        gdiplus.GdipSaveImageToFile.restype = ctypes.c_int
        gdiplus.GdipSaveImageToFile.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_void_p, ctypes.c_void_p]

        gdiplus.GdipDisposeImage.restype = ctypes.c_int
        gdiplus.GdipDisposeImage.argtypes = [ctypes.c_void_p]

        # Attach thread to active input desktop if necessary
        original_thread_desk = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
        h_input_desk = user32.OpenInputDesktop(0, False, 0x01FF)
        switched_desktop = False
        if h_input_desk:
            switched_desktop = bool(user32.SetThreadDesktop(h_input_desk))

        # Determine screen bounds
        width = min(user32.GetSystemMetrics(0), MAX_CAPTURE_WIDTH)
        height = min(user32.GetSystemMetrics(1), MAX_CAPTURE_HEIGHT)

        h_screen_dc = None
        h_mem_dc = None
        h_bitmap = None
        h_old_bitmap = None
        gdiplus_token = ctypes.c_void_p()
        gp_bitmap = ctypes.c_void_p()
        gdiplus_started = False

        self._ensure_output_dir()
        temp_file: Optional[Path] = None
        final_file: Optional[Path] = None

        try:
            # Step A: GDI screen acquisition
            h_screen_dc = user32.GetDC(0)
            if not h_screen_dc:
                return {"success": False, "status": "GDI_ERROR", "error": "Failed acquiring screen DC."}

            h_mem_dc = gdi32.CreateCompatibleDC(h_screen_dc)
            if not h_mem_dc:
                return {"success": False, "status": "GDI_ERROR", "error": "Failed creating compatible memory DC."}

            h_bitmap = gdi32.CreateCompatibleBitmap(h_screen_dc, width, height)
            if not h_bitmap:
                return {"success": False, "status": "GDI_ERROR", "error": "Failed creating compatible bitmap."}

            h_old_bitmap = gdi32.SelectObject(h_mem_dc, h_bitmap)

            SRCCOPY = 0x00CC0020
            blt_ok = gdi32.BitBlt(h_mem_dc, 0, 0, width, height, h_screen_dc, 0, 0, SRCCOPY)
            if not blt_ok:
                err = kernel32.GetLastError()
                return {"success": False, "status": "GDI_ERROR", "error": f"BitBlt screen acquisition failed (code: {err})."}

            # Step B: GDI+ PNG Encoding
            startup_input = GdiplusStartupInput(1, None, False, False)
            st_res = gdiplus.GdiplusStartup(ctypes.byref(gdiplus_token), ctypes.byref(startup_input), None)
            if st_res != 0:
                return {"success": False, "status": "GDIPLUS_ERROR", "error": f"GdiplusStartup failed with code {st_res}."}
            gdiplus_started = True

            cb_res = gdiplus.GdipCreateBitmapFromHBITMAP(h_bitmap, 0, ctypes.byref(gp_bitmap))
            if cb_res != 0:
                return {"success": False, "status": "GDIPLUS_ERROR", "error": f"GdipCreateBitmapFromHBITMAP failed with code {cb_res}."}

            # Generate safe atomic file target
            timestamp_str = time.strftime("%Y%m%d_%H%M%S")
            unique_hex = secrets.token_hex(6)
            file_name = f"capture_{timestamp_str}_{unique_hex}.png"
            final_file = self.output_dir / file_name
            temp_file = self.output_dir / f".tmp_{file_name}"

            # Save PNG to temporary file path
            save_res = gdiplus.GdipSaveImageToFile(
                gp_bitmap,
                str(temp_file),
                ctypes.byref(CLSID_PNG),
                None,
            )
            if save_res != 0:
                return {"success": False, "status": "GDIPLUS_ERROR", "error": f"GdipSaveImageToFile failed with code {save_res}."}

            # Atomic replace into final target
            os.replace(str(temp_file), str(final_file))
            temp_file = None

            # Verify size and hash
            size_bytes = final_file.stat().st_size
            if size_bytes > MAX_CAPTURE_SIZE_BYTES:
                final_file.unlink(missing_ok=True)
                return {
                    "success": False,
                    "status": "IMAGE_TOO_LARGE",
                    "error": f"Captured screenshot size ({size_bytes} bytes) exceeds limit ({MAX_CAPTURE_SIZE_BYTES} bytes).",
                }

            with open(final_file, "rb") as f:
                sha256_hex = hashlib.sha256(f.read()).hexdigest()

            transfer_id = f"cap_{secrets.token_hex(16)}"

            # Trigger retention cleanup
            self.prune_old_captures()

            return {
                "success": True,
                "status": "SUCCESS",
                "file_path": str(final_file.resolve()),
                "file_name": file_name,
                "size_bytes": size_bytes,
                "width": width,
                "height": height,
                "sha256": sha256_hex,
                "transfer_id": transfer_id,
            }

        except Exception as exc:
            logger.error("Screen capture failed unexpectedly: %s", exc, exc_info=True)
            if temp_file and temp_file.exists():
                temp_file.unlink(missing_ok=True)
            if final_file and final_file.exists():
                final_file.unlink(missing_ok=True)
            return {
                "success": False,
                "status": "CAPTURE_FAILED",
                "error": f"Screen capture exception: {exc}",
            }

        finally:
            # Strict resource cleanup on every path
            if gp_bitmap and gp_bitmap.value:
                try:
                    gdiplus.GdipDisposeImage(gp_bitmap)
                except Exception:
                    pass
            if gdiplus_started and gdiplus_token and gdiplus_token.value:
                try:
                    gdiplus.GdiplusShutdown(gdiplus_token)
                except Exception:
                    pass
            if h_mem_dc and h_old_bitmap:
                try:
                    gdi32.SelectObject(h_mem_dc, h_old_bitmap)
                except Exception:
                    pass
            if h_bitmap:
                try:
                    gdi32.DeleteObject(h_bitmap)
                except Exception:
                    pass
            if h_mem_dc:
                try:
                    gdi32.DeleteDC(h_mem_dc)
                except Exception:
                    pass
            if h_screen_dc:
                try:
                    user32.ReleaseDC(0, h_screen_dc)
                except Exception:
                    pass

            # Restore original thread desktop
            if switched_desktop and original_thread_desk:
                try:
                    user32.SetThreadDesktop(original_thread_desk)
                except Exception:
                    pass
            if h_input_desk:
                try:
                    user32.CloseDesktop(h_input_desk)
                except Exception:
                    pass
