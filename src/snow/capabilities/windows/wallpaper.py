"""Windows desktop wallpaper acquisition and preview service for SNOW.

Acquires the active Windows desktop wallpaper using standard Win32 SystemParametersInfoW
and theme fallbacks, then produces an efficient scaled JPEG preview (~20-30 KB, max 480x270)
via standard Windows GDI+ without third-party imaging dependencies.
Provides SHA-256 ETag calculation and in-memory caching for HTTP 304 Not Modified support.
"""

from __future__ import annotations

import atexit
import ctypes
from ctypes import wintypes
import glob
import hashlib
import logging
import os
from pathlib import Path
import platform
import tempfile
import threading
from typing import Optional, Tuple
import uuid

logger = logging.getLogger(__name__)

SPI_GETDESKWALLPAPER = 0x0073
TARGET_PREVIEW_WIDTH = 480
TARGET_PREVIEW_HEIGHT = 270

# In-memory cache
_cache_lock = threading.Lock()
_cached_path: Optional[str] = None
_cached_mtime: float = 0.0
_cached_jpeg: Optional[bytes] = None
_cached_etag: Optional[str] = None

# Process-wide GDI+ lifecycle
_gdi_init_lock = threading.Lock()
_gdi_token = ctypes.c_void_p()
_gdi_initialized = False
_gdi_signatures_configured = False


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


# CLSID for JPEG encoder: {557CF401-1A04-11D3-9A73-0000F81EF32E}
CLSID_JPEG = GUID(
    0x557CF401,
    0x1A04,
    0x11D3,
    (ctypes.c_ubyte * 8)(0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E),
)


def _setup_gdiplus_signatures(gdiplus) -> None:
    """Explicitly configure pointer-safe 64-bit argtypes and restype for all GDI+ functions."""
    global _gdi_signatures_configured
    if _gdi_signatures_configured:
        return

    gdiplus.GdiplusStartup.argtypes = [
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(GdiplusStartupInput),
        ctypes.c_void_p,
    ]
    gdiplus.GdiplusStartup.restype = ctypes.c_int

    gdiplus.GdiplusShutdown.argtypes = [ctypes.c_void_p]
    gdiplus.GdiplusShutdown.restype = None

    gdiplus.GdipLoadImageFromFile.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    gdiplus.GdipLoadImageFromFile.restype = ctypes.c_int

    gdiplus.GdipGetImageWidth.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    gdiplus.GdipGetImageWidth.restype = ctypes.c_int

    gdiplus.GdipGetImageHeight.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    gdiplus.GdipGetImageHeight.restype = ctypes.c_int

    gdiplus.GdipCreateBitmapFromScan0.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    gdiplus.GdipCreateBitmapFromScan0.restype = ctypes.c_int

    gdiplus.GdipGetImageGraphicsContext.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    gdiplus.GdipGetImageGraphicsContext.restype = ctypes.c_int

    gdiplus.GdipSetInterpolationMode.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
    ]
    gdiplus.GdipSetInterpolationMode.restype = ctypes.c_int

    gdiplus.GdipDrawImageRectI.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
    ]
    gdiplus.GdipDrawImageRectI.restype = ctypes.c_int

    gdiplus.GdipSaveImageToFile.argtypes = [
        ctypes.c_void_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(GUID),
        ctypes.c_void_p,
    ]
    gdiplus.GdipSaveImageToFile.restype = ctypes.c_int

    gdiplus.GdipDisposeImage.argtypes = [ctypes.c_void_p]
    gdiplus.GdipDisposeImage.restype = ctypes.c_int

    gdiplus.GdipDeleteGraphics.argtypes = [ctypes.c_void_p]
    gdiplus.GdipDeleteGraphics.restype = ctypes.c_int

    _gdi_signatures_configured = True


def _ensure_gdiplus_initialized() -> bool:
    """Initialize GDI+ once per process in a thread-safe manner."""
    global _gdi_initialized, _gdi_token
    if _gdi_initialized:
        return True

    with _gdi_init_lock:
        if _gdi_initialized:
            return True

        if platform.system() != "Windows":
            return False

        try:
            gdiplus = ctypes.windll.gdiplus
            _setup_gdiplus_signatures(gdiplus)
            token = ctypes.c_void_p()
            inp = GdiplusStartupInput(1, None, False, False)
            st = gdiplus.GdiplusStartup(ctypes.byref(token), ctypes.byref(inp), None)
            if st == 0 and token.value:
                _gdi_token = token
                _gdi_initialized = True
                atexit.register(_shutdown_gdiplus)
                return True
            else:
                logger.warning("GdiplusStartup failed with code %d", st)
                return False
        except Exception as exc:
            logger.warning("Failed to initialize GDI+: %s", exc)
            return False


def _shutdown_gdiplus() -> None:
    """Process shutdown handler for GDI+."""
    global _gdi_initialized, _gdi_token
    with _gdi_init_lock:
        if _gdi_initialized and _gdi_token.value:
            try:
                ctypes.windll.gdiplus.GdiplusShutdown(_gdi_token)
            except Exception:
                pass
            _gdi_initialized = False
            _gdi_token = ctypes.c_void_p()


def get_active_wallpaper_path() -> Optional[str]:
    """Retrieve the path of the active Windows wallpaper.

    1. Uses SystemParametersInfoW(SPI_GETDESKWALLPAPER).
    2. Fallback to %APPDATA%/Microsoft/Windows/Themes/TranscodedWallpaper.
    3. Fallback to %APPDATA%/Microsoft/Windows/Themes/CachedFiles/*.
    """
    if platform.system() != "Windows":
        return None

    # Step 1: SystemParametersInfoW
    try:
        user32 = ctypes.windll.user32
        user32.SystemParametersInfoW.argtypes = [
            wintypes.UINT,
            wintypes.UINT,
            wintypes.LPWSTR,
            wintypes.UINT,
        ]
        user32.SystemParametersInfoW.restype = wintypes.BOOL

        buf = ctypes.create_unicode_buffer(512)
        if user32.SystemParametersInfoW(SPI_GETDESKWALLPAPER, 512, buf, 0):
            path = buf.value.strip()
            if path and os.path.isfile(path):
                return path
    except Exception as exc:
        logger.debug("SystemParametersInfoW failed: %s", exc)

    # Step 2: TranscodedWallpaper
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        transcoded = os.path.join(appdata, "Microsoft", "Windows", "Themes", "TranscodedWallpaper")
        if os.path.isfile(transcoded):
            return transcoded

        # Step 3: CachedFiles
        cached_dir = os.path.join(appdata, "Microsoft", "Windows", "Themes", "CachedFiles")
        if os.path.isdir(cached_dir):
            for candidate in glob.glob(os.path.join(cached_dir, "*.*")):
                if os.path.isfile(candidate) and candidate.lower().endswith((".jpg", ".jpeg", ".png", ".bmp")):
                    return candidate

    return None


def _render_scaled_jpeg_gdiplus(source_path: str, max_w: int, max_h: int) -> Optional[bytes]:
    """Use Win32 GDI+ to load, proportionally downscale, and encode image to JPEG bytes.

    Uses thread-safe unique temporary files and ensures all native handles are disposed.
    """
    if not _ensure_gdiplus_initialized():
        return None

    gdiplus = ctypes.windll.gdiplus

    image = ctypes.c_void_p()
    scaled_bitmap = ctypes.c_void_p()
    graphics = ctypes.c_void_p()

    unique_id = uuid.uuid4().hex
    temp_dir = tempfile.gettempdir()
    temp_out = os.path.join(temp_dir, f"snow_wp_preview_{unique_id}.jpg")

    try:
        load_res = gdiplus.GdipLoadImageFromFile(source_path, ctypes.byref(image))
        if load_res != 0 or not image.value:
            logger.debug("GdipLoadImageFromFile failed for '%s' with code %d", source_path, load_res)
            return None

        width = ctypes.c_uint32()
        height = ctypes.c_uint32()
        gdiplus.GdipGetImageWidth(image, ctypes.byref(width))
        gdiplus.GdipGetImageHeight(image, ctypes.byref(height))

        orig_w = width.value
        orig_h = height.value
        if orig_w <= 0 or orig_h <= 0:
            return None

        scale = min(max_w / orig_w, max_h / orig_h)
        new_w = max(1, int(orig_w * scale))
        new_h = max(1, int(orig_h * scale))

        PixelFormat24bppRGB = 137224
        create_res = gdiplus.GdipCreateBitmapFromScan0(
            new_w, new_h, 0, PixelFormat24bppRGB, None, ctypes.byref(scaled_bitmap)
        )
        if create_res != 0 or not scaled_bitmap.value:
            return None

        ctx_res = gdiplus.GdipGetImageGraphicsContext(scaled_bitmap, ctypes.byref(graphics))
        if ctx_res != 0 or not graphics.value:
            return None

        InterpolationModeHighQualityBicubic = 7
        gdiplus.GdipSetInterpolationMode(graphics, InterpolationModeHighQualityBicubic)
        gdiplus.GdipDrawImageRectI(graphics, image, 0, 0, new_w, new_h)

        save_res = gdiplus.GdipSaveImageToFile(scaled_bitmap, temp_out, ctypes.byref(CLSID_JPEG), None)
        if save_res == 0 and os.path.isfile(temp_out):
            with open(temp_out, "rb") as f:
                return f.read()
    except Exception as exc:
        logger.warning("Error rendering wallpaper preview via GDI+: %s", exc)
        return None
    finally:
        try:
            if graphics.value:
                gdiplus.GdipDeleteGraphics(graphics)
            if scaled_bitmap.value:
                gdiplus.GdipDisposeImage(scaled_bitmap)
            if image.value:
                gdiplus.GdipDisposeImage(image)
            if os.path.isfile(temp_out):
                os.remove(temp_out)
        except Exception:
            pass

    return None


def get_desktop_wallpaper_preview(
    max_w: int = TARGET_PREVIEW_WIDTH,
    max_h: int = TARGET_PREVIEW_HEIGHT,
) -> Tuple[Optional[bytes], Optional[str]]:
    """Get scaled wallpaper JPEG bytes and SHA-256 ETag.

    Returns:
        (jpeg_bytes, etag_string) or (None, None) if unavailable.
    """
    global _cached_path, _cached_mtime, _cached_jpeg, _cached_etag

    path = get_active_wallpaper_path()
    if not path or not os.path.isfile(path):
        return None, None

    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = 0.0

    with _cache_lock:
        if (
            _cached_path == path
            and _cached_mtime == mtime
            and _cached_jpeg is not None
            and _cached_etag is not None
        ):
            return _cached_jpeg, _cached_etag

    # Render scaled preview outside lock to avoid blocking concurrent readers
    jpeg = _render_scaled_jpeg_gdiplus(path, max_w, max_h)
    if not jpeg:
        return None, None

    etag = f'"{hashlib.sha256(jpeg).hexdigest()}"'

    with _cache_lock:
        _cached_path = path
        _cached_mtime = mtime
        _cached_jpeg = jpeg
        _cached_etag = etag

    return jpeg, etag
