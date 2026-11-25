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
import io
import logging
import os
from pathlib import Path
import sys
import tempfile
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

CF_BITMAP: int = 2
CF_UNICODETEXT: int = 13
CF_DIB: int = 8
CF_DIBV5: int = 17
GMEM_MOVEABLE: int = 0x0002
GMEM_ZEROINIT: int = 0x0040
GHND: int = GMEM_MOVEABLE | GMEM_ZEROINIT

MAX_CLIPBOARD_READ_BYTES: int = 1024 * 1024  # 1 MiB read cap
MAX_CLIPBOARD_IMAGE_DIMENSION: int = 8192
MAX_CLIPBOARD_IMAGE_PIXELS: int = 33_554_432
MAX_CLIPBOARD_IMAGE_BYTES: int = 10 * 1024 * 1024  # 10 MiB PNG export cap
MAX_OPEN_RETRIES: int = 5
RETRY_DELAY_SECONDS: float = 0.04  # 40ms interval


def get_default_clipboard_temp_dir() -> Path:
    """Return dedicated OS temporary staging directory for transient clipboard captures."""
    tmp_dir = (Path(tempfile.gettempdir()) / "snow_clip_tmp").resolve()
    tmp_dir.mkdir(parents=True, exist_ok=True)
    return tmp_dir


def compute_canonical_image_digest(image_bytes: bytes) -> tuple[Optional[str], Optional[int], Optional[int]]:
    """Compute canonical SHA-256 digest over image dimensions and RGBA pixels."""
    try:
        from PIL import Image  # type: ignore
    except Exception:
        return None, None, None

    try:
        with Image.open(io.BytesIO(image_bytes)) as img:
            width, height = img.size
            if (
                width <= 0
                or height <= 0
                or width > MAX_CLIPBOARD_IMAGE_DIMENSION
                or height > MAX_CLIPBOARD_IMAGE_DIMENSION
                or (width * height) > MAX_CLIPBOARD_IMAGE_PIXELS
            ):
                return None, width, height
            rgba = img if img.mode == "RGBA" else img.convert("RGBA")
            try:
                header = f"{width}x{height}:".encode("ascii")
                digest = hashlib.sha256(header + rgba.tobytes()).hexdigest()
                return digest, width, height
            finally:
                if rgba is not img and hasattr(rgba, "close"):
                    try:
                        rgba.close()
                    except Exception:
                        pass
    except Exception:
        return None, None, None


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

        self._user32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
        self._user32.RegisterClipboardFormatW.restype = wintypes.UINT

        self._user32.GetDC.argtypes = [wintypes.HWND]
        self._user32.GetDC.restype = wintypes.HDC

        self._user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
        self._user32.ReleaseDC.restype = ctypes.c_int

        self._kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
        self._kernel32.GlobalAlloc.restype = wintypes.HGLOBAL

        self._kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
        self._kernel32.GlobalSize.restype = ctypes.c_size_t

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

        result: dict[str, Any]
        try:
            handle = self._user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                # Clipboard is empty or contains no CF_UNICODETEXT data
                result = {
                    "success": True,
                    "status": "EMPTY",
                    "text": "",
                    "message": "Clipboard is empty or does not contain text.",
                }
            else:
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

                    result = {
                        "success": True,
                        "status": "SUCCESS",
                        "text": text_val,
                        "length": len(text_val),
                    }
                finally:
                    self._kernel32.GlobalUnlock(handle)
        finally:
            self._user32.CloseClipboard()

        # Enrich cleanly with OS clipboard image metadata after closing handle
        try:
            img_meta = self.get_image_metadata_sync()
        except Exception:
            img_meta = {"has_image": False}
        if isinstance(img_meta, dict) and img_meta.get("has_image"):
            safe_img = {
                k: v
                for k, v in img_meta.items()
                if k not in ("file_path", "image_path", "storage_dir", "bytes", "raw_bytes", "image_bytes")
            }
            result["has_image"] = True
            result["image"] = safe_img
            if result.get("status") == "EMPTY":
                result["status"] = "IMAGE"
                dims = f"{safe_img.get('width') or '?'}x{safe_img.get('height') or '?'}"
                fmt = safe_img.get("format") or "PNG"
                result["message"] = f"Clipboard currently contains an image ({dims} {fmt})."
        else:
            result["has_image"] = False
            result["image"] = None
        return result

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
            self._gdiplus.GdipCreateBitmapFromHBITMAP.argtypes = [
                wintypes.HBITMAP, wintypes.HPALETTE, ctypes.POINTER(ctypes.c_void_p)
            ]
            self._gdiplus.GdipCreateBitmapFromHBITMAP.restype = ctypes.c_int
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

    def _get_png_clipboard_formats(self) -> list[int]:
        """Return registered Win32 clipboard format IDs for modern PNG image formats."""
        if not self._is_windows or not self._user32 or not hasattr(self._user32, "RegisterClipboardFormatW"):
            return []
        formats: list[int] = []
        for fmt_name in ("PNG", "image/png"):
            try:
                fmt_id = int(self._user32.RegisterClipboardFormatW(fmt_name) or 0)
                if fmt_id > 0 and fmt_id not in formats:
                    formats.append(fmt_id)
            except Exception:
                continue
        return formats

    def has_image_sync(self) -> bool:
        """Check if supported image data (PNG, CF_DIBV5, CF_DIB, CF_BITMAP) is on the clipboard."""
        if not self._is_windows or not self._user32:
            return False
        candidate_formats = [*self._get_png_clipboard_formats(), CF_DIBV5, CF_DIB, CF_BITMAP]
        for fmt in candidate_formats:
            try:
                avail = self._user32.IsClipboardFormatAvailable(fmt)
                if isinstance(avail, (int, bool)) and bool(avail):
                    return True
            except Exception:
                continue
        return False

    def _save_bounded_image(self, img_obj: Any, output_dir: Optional[Path] = None) -> dict[str, Any]:
        """Validate dimensions/bounds, normalize mode, and write PNG atomically into temp dir."""
        from PIL import Image  # type: ignore

        if not isinstance(img_obj, Image.Image):
            return {
                "success": False,
                "status": "NO_IMAGE",
                "error": "Clipboard object is not a valid image.",
            }

        width, height = img_obj.size
        if (
            width <= 0
            or height <= 0
            or width > MAX_CLIPBOARD_IMAGE_DIMENSION
            or height > MAX_CLIPBOARD_IMAGE_DIMENSION
            or (width * height) > MAX_CLIPBOARD_IMAGE_PIXELS
        ):
            return {
                "success": False,
                "status": "IMAGE_TOO_LARGE",
                "error": f"Clipboard image dimensions ({width}x{height}) exceed safety bounds.",
            }

        normalized = None
        buf: Optional[io.BytesIO] = None
        try:
            has_alpha = "A" in (img_obj.mode or "") or "transparency" in getattr(img_obj, "info", {})
            target_mode = "RGBA" if has_alpha else "RGB"
            img_to_save = img_obj if img_obj.mode == target_mode else img_obj.convert(target_mode)
            if img_to_save is not img_obj:
                normalized = img_to_save

            buf = io.BytesIO()
            img_to_save.save(buf, format="PNG")
            png_bytes = buf.getvalue()
            if len(png_bytes) > MAX_CLIPBOARD_IMAGE_BYTES:
                return {
                    "success": False,
                    "status": "IMAGE_TOO_LARGE",
                    "error": f"Encoded clipboard image ({len(png_bytes)} bytes) exceeds 10 MiB limit.",
                }

            target_dir = Path(output_dir).resolve() if output_dir else get_default_clipboard_temp_dir()
            target_dir.mkdir(parents=True, exist_ok=True)
            sha256 = hashlib.sha256(png_bytes).hexdigest()
            canonical_sha, _, _ = compute_canonical_image_digest(png_bytes)
            final_path = target_dir / f"clip_{sha256[:16]}.png"
            if not final_path.exists():
                tmp_path = target_dir / f"clip_{int(time.time() * 1000)}_{os.getpid()}.png.tmp"
                try:
                    tmp_path.write_bytes(png_bytes)
                    tmp_path.replace(final_path)
                except Exception:
                    tmp_path.unlink(missing_ok=True)
                    raise

            return {
                "success": True,
                "status": "SUCCESS",
                "type": "image",
                "mime_type": "image/png",
                "format": "PNG",
                "width": width,
                "height": height,
                "file_path": str(final_path),
                "file_name": final_path.name,
                "sha256": sha256,
                "canonical_sha256": canonical_sha or sha256,
                "size": len(png_bytes),
            }
        finally:
            if buf is not None:
                try:
                    buf.close()
                except Exception:
                    pass
            if normalized is not None:
                try:
                    normalized.close()
                except Exception:
                    pass

    def _grab_clipboard_image_via_pil(self, output_dir: Optional[Path] = None) -> dict[str, Any]:
        """Fallback clipboard image capture using Pillow ImageGrab for CF_DIBV5/PNG/CF_BITMAP formats."""
        try:
            from PIL import Image, ImageGrab  # type: ignore
        except Exception as exc:
            return {
                "success": False,
                "status": "NO_IMAGE",
                "error": f"Pillow ImageGrab unavailable: {exc}",
            }

        grabbed: Any = None
        try:
            grabbed = ImageGrab.grabclipboard()
            if not isinstance(grabbed, Image.Image):
                return {
                    "success": False,
                    "status": "NO_IMAGE",
                    "error": "No image object returned by Pillow ImageGrab.",
                }
            return self._save_bounded_image(grabbed, output_dir=output_dir)
        except Exception as exc:
            logger.debug("Pillow clipboard image fallback failed: %s", exc)
            return {
                "success": False,
                "status": "DECODE_FAILED",
                "error": f"Clipboard image fallback failed: {exc}",
            }
        finally:
            if grabbed is not None and hasattr(grabbed, "close"):
                try:
                    grabbed.close()
                except Exception:
                    pass

    def get_image_sync(self, output_dir: Optional[Path] = None) -> dict[str, Any]:
        """Read image from clipboard, export to a bounded PNG file in temp dir, and return metadata."""
        if not self._is_windows or not self._user32 or not self._kernel32:
            return {"success": False, "status": "UNSUPPORTED_PLATFORM", "error": "Windows only"}

        target_dir = Path(output_dir).resolve() if output_dir else get_default_clipboard_temp_dir()
        target_dir.mkdir(parents=True, exist_ok=True)
        self._init_gdiplus()
        gdi_failure: Optional[dict[str, Any]] = None
        raw_png_bytes: Optional[bytes] = None

        if not self._open_clipboard_with_retry():
            return {"success": False, "status": "CLIPBOARD_BUSY", "error": "Failed opening clipboard"}

        try:
            # 1. Try modern Windows 11 registered PNG formats first
            for png_fmt in self._get_png_clipboard_formats():
                h_png = self._user32.GetClipboardData(png_fmt)
                if h_png:
                    png_size = int(self._kernel32.GlobalSize(h_png) or 0)
                    if png_size > MAX_CLIPBOARD_IMAGE_BYTES:
                        gdi_failure = {
                            "success": False,
                            "status": "IMAGE_TOO_LARGE",
                            "error": f"Clipboard PNG ({png_size} bytes) exceeds 10 MiB limit.",
                        }
                        break
                    if png_size > 8:
                        p_png = self._kernel32.GlobalLock(h_png)
                        if p_png:
                            try:
                                raw_png_bytes = ctypes.string_at(p_png, png_size)
                            finally:
                                self._kernel32.GlobalUnlock(h_png)
                    break

            # 2. If no registered PNG blob extracted, try GDI+ CF_DIBV5 / CF_DIB / CF_BITMAP
            if raw_png_bytes is None and gdi_failure is None:
                if not self._gdiplus or self._gdiplus_token is None:
                    gdi_failure = {"success": False, "status": "GDIPLUS_UNAVAILABLE", "error": "GDI+ not available"}
                else:
                    h_data = None
                    fmt_chosen = None
                    for fmt in (CF_DIBV5, CF_DIB):
                        h = self._user32.GetClipboardData(fmt)
                        if h:
                            h_data = h
                            fmt_chosen = fmt
                            break

                    p_bmp = ctypes.c_void_p()
                    if h_data:
                        p_data = self._kernel32.GlobalLock(h_data)
                        if not p_data:
                            gdi_failure = {"success": False, "status": "LOCK_FAILED", "error": "GlobalLock failed"}
                        else:
                            try:
                                bih = BITMAPINFOHEADER.from_address(p_data)
                                header_size = bih.biSize
                                width = abs(int(bih.biWidth))
                                height = abs(int(bih.biHeight))
                                if header_size < 40:
                                    gdi_failure = {
                                        "success": False,
                                        "status": "INVALID_IMAGE_HEADER",
                                        "error": f"Invalid DIB header size: {header_size}",
                                    }
                                elif (
                                    width <= 0
                                    or height <= 0
                                    or width > MAX_CLIPBOARD_IMAGE_DIMENSION
                                    or height > MAX_CLIPBOARD_IMAGE_DIMENSION
                                    or (width * height) > MAX_CLIPBOARD_IMAGE_PIXELS
                                ):
                                    gdi_failure = {
                                        "success": False,
                                        "status": "IMAGE_TOO_LARGE",
                                        "error": f"Clipboard DIB dimensions ({width}x{height}) exceed safety bounds.",
                                    }
                                else:
                                    clr_used = bih.biClrUsed
                                    bit_count = bih.biBitCount
                                    compression = bih.biCompression
                                    if header_size == 40 and compression == 3:
                                        clr_size = 12
                                    elif clr_used > 0:
                                        clr_size = clr_used * 4
                                    elif bit_count <= 8 and bit_count > 0:
                                        clr_size = (1 << bit_count) * 4
                                    else:
                                        clr_size = 0
                                    p_bits = p_data + header_size + clr_size
                                    st = self._gdiplus.GdipCreateBitmapFromGdiDib(
                                        ctypes.c_void_p(p_data), ctypes.c_void_p(p_bits), ctypes.byref(p_bmp)
                                    )
                                    if st != 0:
                                        gdi_failure = {
                                            "success": False,
                                            "status": "DECODE_FAILED",
                                            "error": f"GDI+ decode failed (status {st}) for format {fmt_chosen}",
                                        }
                            finally:
                                self._kernel32.GlobalUnlock(h_data)
                    else:
                        h_bm = self._user32.GetClipboardData(CF_BITMAP)
                        if not h_bm:
                            gdi_failure = {"success": False, "status": "NO_IMAGE", "error": "No DIB, DIBV5, PNG, or CF_BITMAP image on clipboard"}
                        elif hasattr(self._gdiplus, "GdipCreateBitmapFromHBITMAP"):
                            st = self._gdiplus.GdipCreateBitmapFromHBITMAP(
                                ctypes.c_void_p(h_bm), None, ctypes.byref(p_bmp)
                            )
                            if st != 0:
                                gdi_failure = {
                                    "success": False,
                                    "status": "DECODE_FAILED",
                                    "error": f"GDI+ CF_BITMAP decode failed (status {st})",
                                }
                        else:
                            gdi_failure = {"success": False, "status": "NO_IMAGE", "error": "GDI+ CF_BITMAP loader unavailable"}

                    if p_bmp.value and gdi_failure is None:
                        temp_name = f"clip_{int(time.time() * 1000)}_{os.getpid()}.png"
                        out_path = target_dir / temp_name
                        try:
                            save_st = self._gdiplus.GdipSaveImageToFile(
                                p_bmp, str(out_path), ctypes.byref(PNG_CLSID), None
                            )
                            if save_st != 0 or not out_path.exists():
                                gdi_failure = {
                                    "success": False,
                                    "status": "SAVE_FAILED",
                                    "error": f"Failed saving PNG (status {save_st})",
                                }
                            else:
                                png_data = out_path.read_bytes()
                                size = len(png_data)
                                if size > MAX_CLIPBOARD_IMAGE_BYTES:
                                    out_path.unlink(missing_ok=True)
                                    gdi_failure = {
                                        "success": False,
                                        "status": "IMAGE_TOO_LARGE",
                                        "error": f"Encoded clipboard image ({size} bytes) exceeds 10 MiB limit.",
                                    }
                                else:
                                    sha256 = hashlib.sha256(png_data).hexdigest()
                                    canonical_sha, img_w, img_h = compute_canonical_image_digest(png_data)
                                    if img_w and img_h and (
                                        img_w > MAX_CLIPBOARD_IMAGE_DIMENSION
                                        or img_h > MAX_CLIPBOARD_IMAGE_DIMENSION
                                        or (img_w * img_h) > MAX_CLIPBOARD_IMAGE_PIXELS
                                    ):
                                        out_path.unlink(missing_ok=True)
                                        gdi_failure = {
                                            "success": False,
                                            "status": "IMAGE_TOO_LARGE",
                                            "error": f"Clipboard image dimensions ({img_w}x{img_h}) exceed safety bounds.",
                                        }
                                    else:
                                        final_path = target_dir / f"clip_{sha256[:16]}.png"
                                        if final_path.exists():
                                            out_path.unlink(missing_ok=True)
                                        else:
                                            out_path.replace(final_path)
                                        return {
                                            "success": True,
                                            "status": "SUCCESS",
                                            "type": "image",
                                            "mime_type": "image/png",
                                            "format": "PNG",
                                            "width": img_w,
                                            "height": img_h,
                                            "file_path": str(final_path),
                                            "file_name": final_path.name,
                                            "sha256": sha256,
                                            "canonical_sha256": canonical_sha or sha256,
                                            "size": size,
                                        }
                        finally:
                            out_path.unlink(missing_ok=True) if gdi_failure and out_path.exists() else None
                            self._gdiplus.GdipDisposeImage(p_bmp)
        finally:
            self._user32.CloseClipboard()

        # Process registered PNG bytes safely outside Win32 clipboard lock
        if raw_png_bytes is not None:
            if raw_png_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
                try:
                    from PIL import Image  # type: ignore

                    with Image.open(io.BytesIO(raw_png_bytes)) as img:
                        return self._save_bounded_image(img, output_dir=target_dir)
                except Exception:
                    # Handle environments without Pillow or unusual valid PNG chunks safely
                    sha256 = hashlib.sha256(raw_png_bytes).hexdigest()
                    final_path = target_dir / f"clip_{sha256[:16]}.png"
                    if not final_path.exists():
                        final_path.write_bytes(raw_png_bytes)
                    return {
                        "success": True,
                        "status": "SUCCESS",
                        "type": "image",
                        "mime_type": "image/png",
                        "format": "PNG",
                        "file_path": str(final_path),
                        "file_name": final_path.name,
                        "sha256": sha256,
                        "canonical_sha256": sha256,
                        "size": len(raw_png_bytes),
                    }
            gdi_failure = {"success": False, "status": "DECODE_FAILED", "error": "Clipboard PNG data header invalid."}

        if gdi_failure and gdi_failure.get("status") == "IMAGE_TOO_LARGE":
            return gdi_failure

        # Fallback for modern Windows 11 PNG / CF_DIBV5 / CF_BITMAP formats after Win32 clipboard is closed
        pil_res = self._grab_clipboard_image_via_pil(output_dir=target_dir)
        if pil_res.get("success"):
            return pil_res
        return pil_res if pil_res.get("status") == "IMAGE_TOO_LARGE" else (gdi_failure or pil_res)

    def decode_dib_bytes_to_png(self, dib_bytes: bytes, output_dir: Optional[Path] = None) -> dict[str, Any]:
        """Decode raw DIB/DIBV5 bytes into a PNG file. Used for testing and headless processing."""
        if not self._is_windows or not self._kernel32:
            return {"success": False, "status": "UNSUPPORTED_PLATFORM", "error": "Windows only"}
        if len(dib_bytes) < 40:
            return {"success": False, "status": "INVALID_IMAGE_HEADER", "error": "DIB bytes too short for header"}

        self._init_gdiplus()
        if not self._gdiplus or self._gdiplus_token is None:
            return {"success": False, "status": "GDIPLUS_UNAVAILABLE", "error": "GDI+ not available"}

        buf = ctypes.create_string_buffer(dib_bytes)
        p_data = ctypes.addressof(buf)
        bih = BITMAPINFOHEADER.from_address(p_data)
        header_size = bih.biSize
        if header_size < 40:
            return {"success": False, "status": "INVALID_IMAGE_HEADER", "error": f"Invalid DIB header size: {header_size}"}

        clr_used = bih.biClrUsed
        bit_count = bih.biBitCount
        compression = bih.biCompression
        clr_size = 0
        if header_size == 40 and compression == 3:
            clr_size = 12
        elif header_size >= 124:
            if clr_used > 0:
                clr_size = clr_used * 4
            elif bit_count <= 8 and bit_count > 0:
                clr_size = (1 << bit_count) * 4
        elif clr_used > 0:
            clr_size = clr_used * 4
        elif bit_count <= 8 and bit_count > 0:
            clr_size = (1 << bit_count) * 4
        p_bits = p_data + header_size + clr_size

        p_bmp = ctypes.c_void_p()
        st = self._gdiplus.GdipCreateBitmapFromGdiDib(
            ctypes.c_void_p(p_data), ctypes.c_void_p(p_bits), ctypes.byref(p_bmp)
        )
        if st != 0:
            return {"success": False, "status": "DECODE_FAILED", "error": f"GDI+ decode failed (status {st})"}

        try:
            target_dir = output_dir or (Path.home() / ".snow" / "transfers")
            target_dir.mkdir(parents=True, exist_ok=True)
            temp_name = f"clip_{int(time.time() * 1000)}.png"
            out_path = target_dir / temp_name

            save_st = self._gdiplus.GdipSaveImageToFile(
                p_bmp, str(out_path), ctypes.byref(PNG_CLSID), None
            )
            if save_st != 0 or not out_path.exists():
                return {"success": False, "status": "SAVE_FAILED", "error": f"Failed saving PNG (status {save_st})"}

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

    def get_image_metadata_sync(self) -> dict[str, Any]:
        """Inspect current Windows clipboard image metadata without leaving temporary files behind."""
        if not self._is_windows or not self._user32:
            return {"has_image": False}
        if not self.has_image_sync():
            return {"has_image": False}

        tmp_path: Optional[Path] = None
        try:
            res = self.get_image_sync(output_dir=get_default_clipboard_temp_dir())
            if res.get("file_path"):
                tmp_path = Path(res["file_path"])
            if res.get("success"):
                return {
                    "has_image": True,
                    "width": res.get("width"),
                    "height": res.get("height"),
                    "format": res.get("format") or "PNG",
                    "mime_type": res.get("mime_type") or "image/png",
                    "size_bytes": res.get("size"),
                }
            return {
                "has_image": True,
                "status": res.get("status"),
                "error": res.get("error"),
            }
        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except Exception:
                    pass

    def get_content_sync(self, output_dir: Optional[Path] = None) -> dict[str, Any]:
        """Read clipboard content, detecting whether it is an image or text."""
        effective_dir = Path(output_dir).resolve() if output_dir else get_default_clipboard_temp_dir()
        if self.has_image_sync():
            img_res = self.get_image_sync(effective_dir)
            if img_res.get("success"):
                return img_res
        text_res = self.get_clipboard_sync()
        if text_res.get("success") and text_res.get("text"):
            text = text_res["text"]
            sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
            return {"success": True, "type": "text", "text": text, "sha256": sha256}
        # Re-check image if text is empty so modern PNG / CF_BITMAP formats never fall through as empty
        if self.has_image_sync():
            img_res = self.get_image_sync(effective_dir)
            if img_res.get("success"):
                return img_res
        return {"success": True, "type": "empty", "text": "", "sha256": ""}
