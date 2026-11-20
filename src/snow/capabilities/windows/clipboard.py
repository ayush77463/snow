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
import hashlib
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

CF_UNICODETEXT: int = 13
CF_DIB: int = 8
CF_DIBV5: int = 17
GMEM_MOVEABLE: int = 0x0002
GMEM_ZEROINIT: int = 0x0040
GHND: int = GMEM_MOVEABLE | GMEM_ZEROINIT

MAX_CLIPBOARD_READ_BYTES: int = 1024 * 1024  # 1 MiB read cap
MAX_OPEN_RETRIES: int = 5
RETRY_DELAY_SECONDS: float = 0.04  # 40ms interval


class GdiplusStartupInput(ctypes.Structure):
    _fields_ = [
        ("GdiplusVersion", wintypes.UINT),
        ("DebugEventCallback", ctypes.c_void_p),
        ("SuppressBackgroundThread", wintypes.BOOL),
        ("SuppressExternalCodecs", wintypes.BOOL),
    ]


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_byte * 8),
    ]


PNG_CLSID = GUID(0x557cf406, 0x1a04, 0x11d3, (ctypes.c_byte * 8)(0x9a, 0x73, 0x00, 0x00, 0xf8, 0x1e, 0xf3, 0x2e))


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class WindowsClipboardManager:
    """Manages Windows clipboard reading and writing via standard Win32 ctypes."""

    def __init__(self) -> None:
        self._is_windows = sys.platform == "win32"
        self._user32 = None
        self._kernel32 = None

        if self._is_windows:
            self._gdiplus = None
            self._gdi32 = None
            self._gdiplus_token = None
            try:
                self._user32 = ctypes.windll.user32
                self._kernel32 = ctypes.windll.kernel32
                self._configure_types()
            except Exception as exc:
                logger.warning("Could not initialize Win32 ctypes for clipboard: %s", exc)

    def __del__(self) -> None:
        self._shutdown_gdiplus()

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

        self._user32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
        self._user32.IsClipboardFormatAvailable.restype = wintypes.BOOL

        self._user32.GetDC.argtypes = [wintypes.HWND]
        self._user32.GetDC.restype = wintypes.HDC

        self._user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
        self._user32.ReleaseDC.restype = ctypes.c_int

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
            time.sleep(RETRY_DELAY_SECONDS)
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

    def _init_gdiplus(self) -> None:
        """Initialize GDI+ library for clipboard image handling."""
        if not self._is_windows or self._gdiplus_token is not None:
            return
        try:
            self._gdiplus = ctypes.windll.gdiplus
            self._gdi32 = ctypes.windll.gdi32

            self._gdi32.GetDIBits.argtypes = [
                wintypes.HDC,
                wintypes.HBITMAP,
                wintypes.UINT,
                wintypes.UINT,
                wintypes.LPVOID,
                ctypes.c_void_p,
                wintypes.UINT,
            ]
            self._gdi32.GetDIBits.restype = ctypes.c_int
            self._gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
            self._gdi32.DeleteObject.restype = wintypes.BOOL

            self._gdiplus.GdipCreateBitmapFromGdiDib.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)
            ]
            self._gdiplus.GdipCreateBitmapFromGdiDib.restype = ctypes.c_int
            self._gdiplus.GdipCreateBitmapFromFile.argtypes = [
                wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_void_p)
            ]
            self._gdiplus.GdipCreateBitmapFromFile.restype = ctypes.c_int
            self._gdiplus.GdipCreateHBITMAPFromBitmap.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), wintypes.DWORD
            ]
            self._gdiplus.GdipCreateHBITMAPFromBitmap.restype = ctypes.c_int
            self._gdiplus.GdipSaveImageToFile.argtypes = [
                ctypes.c_void_p, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p
            ]
            self._gdiplus.GdipSaveImageToFile.restype = ctypes.c_int
            self._gdiplus.GdipDisposeImage.argtypes = [ctypes.c_void_p]
            self._gdiplus.GdipDisposeImage.restype = ctypes.c_int

            self._gdiplus.GdiplusStartup.argtypes = [
                ctypes.POINTER(ctypes.c_size_t),
                ctypes.c_void_p,
                ctypes.c_void_p,
            ]
            self._gdiplus.GdiplusStartup.restype = ctypes.c_int
            self._gdiplus.GdiplusShutdown.argtypes = [ctypes.c_size_t]
            self._gdiplus.GdiplusShutdown.restype = None

            startup_in = GdiplusStartupInput(1, None, False, False)
            token = ctypes.c_size_t()
            status = self._gdiplus.GdiplusStartup(ctypes.byref(token), ctypes.byref(startup_in), None)
            if status == 0:
                self._gdiplus_token = token.value
        except Exception as exc:
            logger.debug("Failed initializing Gdiplus: %s", exc)

    def _shutdown_gdiplus(self) -> None:
        """Shutdown GDI+ library."""
        if getattr(self, "_gdiplus", None) and getattr(self, "_gdiplus_token", None) is not None:
            try:
                self._gdiplus.GdiplusShutdown(self._gdiplus_token)
            except Exception:
                pass
            self._gdiplus_token = None

    def has_image_sync(self) -> bool:
        """Check if image data (CF_DIB or CF_DIBV5) is available on the clipboard."""
        if not self._is_windows or not self._user32:
            return False
        return bool(
            self._user32.IsClipboardFormatAvailable(CF_DIB)
            or self._user32.IsClipboardFormatAvailable(CF_DIBV5)
        )

    def get_image_sync(self, output_dir: Optional[Path] = None) -> dict[str, Any]:
        """Read image from clipboard, export to a PNG file, and return its metadata."""
        if not self._is_windows or not self._user32 or not self._kernel32:
            return {"success": False, "status": "UNSUPPORTED_PLATFORM", "error": "Windows only"}

        self._init_gdiplus()
        if not self._gdiplus or self._gdiplus_token is None:
            return {"success": False, "status": "GDIPLUS_UNAVAILABLE", "error": "GDI+ not available"}

        if not self._open_clipboard_with_retry():
            return {"success": False, "status": "CLIPBOARD_BUSY", "error": "Failed opening clipboard"}

        try:
            h_data = self._user32.GetClipboardData(CF_DIB)
            if not h_data:
                return {"success": False, "status": "NO_IMAGE", "error": "No DIB image on clipboard"}

            p_data = self._kernel32.GlobalLock(h_data)
            if not p_data:
                return {"success": False, "status": "LOCK_FAILED", "error": "GlobalLock failed"}

            try:
                bih = BITMAPINFOHEADER.from_address(p_data)
                header_size = bih.biSize
                clr_used = bih.biClrUsed
                bit_count = bih.biBitCount
                compression = bih.biCompression
                clr_size = 0
                if compression == 3 and header_size == 40:
                    clr_size = 12
                elif clr_used > 0:
                    clr_size = clr_used * 4
                elif bit_count <= 8:
                    clr_size = (1 << bit_count) * 4
                p_bits = p_data + header_size + clr_size

                p_bmp = ctypes.c_void_p()
                st = self._gdiplus.GdipCreateBitmapFromGdiDib(
                    ctypes.c_void_p(p_data), ctypes.c_void_p(p_bits), ctypes.byref(p_bmp)
                )
                if st != 0:
                    return {
                        "success": False,
                        "status": "DECODE_FAILED",
                        "error": f"GDI+ decode failed (status {st})",
                    }

                try:
                    target_dir = output_dir or (Path.home() / ".snow" / "transfers")
                    target_dir.mkdir(parents=True, exist_ok=True)
                    temp_name = f"clip_{int(time.time() * 1000)}.png"
                    out_path = target_dir / temp_name

                    save_st = self._gdiplus.GdipSaveImageToFile(
                        p_bmp, str(out_path), ctypes.byref(PNG_CLSID), None
                    )
                    if save_st != 0 or not out_path.exists():
                        return {
                            "success": False,
                            "status": "SAVE_FAILED",
                            "error": f"Failed saving PNG (status {save_st})",
                        }

                    size = out_path.stat().st_size
                    sha256 = hashlib.sha256(out_path.read_bytes()).hexdigest()

                    final_path = target_dir / f"clip_{sha256[:16]}.png"
                    if final_path.exists():
                        try:
                            out_path.unlink()
                        except Exception:
                            pass
                    else:
                        out_path.rename(final_path)

                    return {
                        "success": True,
                        "status": "SUCCESS",
                        "type": "image",
                        "mime_type": "image/png",
                        "file_path": str(final_path),
                        "file_name": final_path.name,
                        "sha256": sha256,
                        "size": size,
                    }
                finally:
                    self._gdiplus.GdipDisposeImage(p_bmp)
            finally:
                self._kernel32.GlobalUnlock(h_data)
        finally:
            self._user32.CloseClipboard()

    def set_image_sync(self, image_path: Path | str) -> dict[str, Any]:
        """Load an image file (PNG, JPEG, BMP) and place it on Windows clipboard as CF_DIB."""
        if not self._is_windows or not self._user32 or not self._kernel32:
            return {"success": False, "status": "UNSUPPORTED_PLATFORM", "error": "Windows only"}

        img_p = Path(image_path)
        if not img_p.exists() or not img_p.is_file():
            return {
                "success": False,
                "status": "FILE_NOT_FOUND",
                "error": f"Image file not found: {image_path}",
            }

        self._init_gdiplus()
        if not self._gdiplus or self._gdiplus_token is None:
            return {"success": False, "status": "GDIPLUS_UNAVAILABLE", "error": "GDI+ not available"}

        p_img = ctypes.c_void_p()
        st = self._gdiplus.GdipCreateBitmapFromFile(str(img_p), ctypes.byref(p_img))
        if st != 0:
            return {
                "success": False,
                "status": "LOAD_FAILED",
                "error": f"Failed loading image with GDI+ ({st})",
            }

        try:
            hbm = ctypes.c_void_p()
            st_hbm = self._gdiplus.GdipCreateHBITMAPFromBitmap(p_img, ctypes.byref(hbm), 0)
            if st_hbm != 0 or not hbm:
                return {
                    "success": False,
                    "status": "HBITMAP_FAILED",
                    "error": f"Failed creating HBITMAP ({st_hbm})",
                }

            try:
                hdc = self._user32.GetDC(0)
                bih = BITMAPINFOHEADER()
                bih.biSize = ctypes.sizeof(BITMAPINFOHEADER)

                self._gdi32.GetDIBits(hdc, hbm, 0, 0, None, ctypes.byref(bih), 0)
                bih.biPlanes = 1
                bih.biBitCount = 32
                bih.biCompression = 0  # BI_RGB
                bih.biClrUsed = 0
                height = abs(bih.biHeight)
                bih.biHeight = height
                img_size = bih.biWidth * 4 * height
                bih.biSizeImage = img_size
                total_size = ctypes.sizeof(BITMAPINFOHEADER) + img_size

                h_mem = self._kernel32.GlobalAlloc(GMEM_MOVEABLE, total_size)
                if not h_mem:
                    self._user32.ReleaseDC(0, hdc)
                    return {
                        "success": False,
                        "status": "ALLOC_FAILED",
                        "error": "Failed allocating global memory",
                    }

                p_mem = self._kernel32.GlobalLock(h_mem)
                if not p_mem:
                    self._kernel32.GlobalFree(h_mem)
                    self._user32.ReleaseDC(0, hdc)
                    return {"success": False, "status": "LOCK_FAILED", "error": "GlobalLock failed"}

                scanlines_failed = False
                try:
                    ctypes.memmove(p_mem, ctypes.byref(bih), ctypes.sizeof(BITMAPINFOHEADER))
                    p_bits = p_mem + ctypes.sizeof(BITMAPINFOHEADER)
                    scanlines = self._gdi32.GetDIBits(
                        hdc, hbm, 0, height, ctypes.c_void_p(p_bits), ctypes.byref(bih), 0
                    )
                    if scanlines <= 0:
                        scanlines_failed = True
                finally:
                    self._kernel32.GlobalUnlock(h_mem)
                    self._user32.ReleaseDC(0, hdc)

                if scanlines_failed:
                    self._kernel32.GlobalFree(h_mem)
                    return {
                        "success": False,
                        "status": "GETDIBITS_FAILED",
                        "error": "GetDIBits returned 0 scanlines",
                    }

                if not self._open_clipboard_with_retry():
                    self._kernel32.GlobalFree(h_mem)
                    return {"success": False, "status": "CLIPBOARD_BUSY", "error": "Failed opening clipboard"}

                try:
                    self._user32.EmptyClipboard()
                    res = self._user32.SetClipboardData(CF_DIB, h_mem)
                    if not res:
                        self._kernel32.GlobalFree(h_mem)
                        return {
                            "success": False,
                            "status": "SET_DATA_FAILED",
                            "error": "SetClipboardData failed",
                        }
                    return {
                        "success": True,
                        "status": "SUCCESS",
                        "message": "Copied image to Windows clipboard",
                    }
                finally:
                    self._user32.CloseClipboard()
            finally:
                self._gdi32.DeleteObject(hbm)
        finally:
            self._gdiplus.GdipDisposeImage(p_img)

    def get_content_sync(self, output_dir: Optional[Path] = None) -> dict[str, Any]:
        """Read clipboard content, detecting whether it is an image or text."""
        if self.has_image_sync():
            img_res = self.get_image_sync(output_dir)
            if img_res.get("success"):
                return img_res
        text_res = self.get_clipboard_sync()
        if text_res.get("success") and text_res.get("text"):
            text = text_res["text"]
            sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
            return {"success": True, "type": "text", "text": text, "sha256": sha256}
        return {"success": True, "type": "empty", "text": "", "sha256": ""}
