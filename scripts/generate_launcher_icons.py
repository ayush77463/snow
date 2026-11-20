"""Generates Android launcher icon assets from snow.png using Windows GDI+.

Eliminates the artificial rounded square tile border and drop shadow from the source mockup,
seamlessly blending the cosmic galaxy nebula into #0E121E deep navy space, and centering
the 3D SNOW crystal glyph perfectly within the Android adaptive icon safe zone.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
import math
from pathlib import Path
import sys

gdiplus = ctypes.windll.gdiplus


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


class BitmapData(ctypes.Structure):
    _fields_ = [
        ("Width", wintypes.UINT),
        ("Height", wintypes.UINT),
        ("Stride", ctypes.c_int),
        ("PixelFormat", ctypes.c_int),
        ("Scan0", ctypes.c_void_p),
        ("Reserved", ctypes.POINTER(ctypes.c_uint)),
    ]


class Rect(ctypes.Structure):
    _fields_ = [
        ("X", ctypes.c_int),
        ("Y", ctypes.c_int),
        ("Width", ctypes.c_int),
        ("Height", ctypes.c_int),
    ]


PNG_CLSID = GUID(0x557CF406, 0x1A04, 0x11D3, (ctypes.c_byte * 8)(0x9A, 0x73, 0x00, 0x00, 0xF8, 0x1E, 0xF3, 0x2E))
PixelFormat32bppARGB = 0x0026200A
ImageLockModeRead = 1
ImageLockModeWrite = 2

BG_R, BG_G, BG_B = 14, 18, 30  # #0E121E


def generate_icons(src_path: Path, res_root: Path, preview: bool = False) -> None:
    startup_in = GdiplusStartupInput(1, None, False, False)
    token = ctypes.c_size_t()
    status = gdiplus.GdiplusStartup(ctypes.byref(token), ctypes.byref(startup_in), None)
    if status != 0:
        raise RuntimeError(f"GdiplusStartup failed with status {status}")

    try:
        p_src = ctypes.c_void_p()
        st = gdiplus.GdipCreateBitmapFromFile(str(src_path), ctypes.byref(p_src))
        if st != 0:
            raise RuntimeError(f"GdipCreateBitmapFromFile failed with status {st}")

        src_w = ctypes.c_uint()
        src_h = ctypes.c_uint()
        gdiplus.GdipGetImageWidth(p_src, ctypes.byref(src_w))
        gdiplus.GdipGetImageHeight(p_src, ctypes.byref(src_h))
        sw, sh = src_w.value, src_h.value

        src_rect = Rect(0, 0, sw, sh)
        src_data = BitmapData()
        gdiplus.GdipBitmapLockBits(p_src, ctypes.byref(src_rect), ImageLockModeRead, PixelFormat32bppARGB, ctypes.byref(src_data))
        src_buf = (ctypes.c_ubyte * (src_data.Stride * sh)).from_address(src_data.Scan0)
        src_stride = src_data.Stride

        def get_src_pixel(sx: int, sy: int) -> tuple[int, int, int]:
            if sx < 0 or sx >= sw or sy < 0 or sy >= sh:
                return (BG_R, BG_G, BG_B)
            offset = sy * src_stride + sx * 4
            b = src_buf[offset]
            g = src_buf[offset + 1]
            r = src_buf[offset + 2]
            return (r, g, b)

        # Center of the 3D snowflake glyph in snow.png
        cx, cy = 1374, 768

        def render_seamless_icon(sz: int, crop_sz: float, out_file: Path) -> None:
            p_dst = ctypes.c_void_p()
            gdiplus.GdipCreateBitmapFromScan0(sz, sz, 0, PixelFormat32bppARGB, None, ctypes.byref(p_dst))
            dst_rect = Rect(0, 0, sz, sz)
            dst_data = BitmapData()
            gdiplus.GdipBitmapLockBits(p_dst, ctypes.byref(dst_rect), ImageLockModeWrite, PixelFormat32bppARGB, ctypes.byref(dst_data))
            dst_buf = (ctypes.c_ubyte * (dst_data.Stride * sz)).from_address(dst_data.Scan0)
            dst_stride = dst_data.Stride

            scale = crop_sz / float(sz)

            for dy in range(sz):
                sy = int(cy + (dy - sz / 2.0) * scale)
                row_offset = dy * dst_stride
                for dx in range(sz):
                    sx = int(cx + (dx - sz / 2.0) * scale)
                    r, g, b = get_src_pixel(sx, sy)
                    dist = math.hypot(sx - cx, sy - cy)

                    in_corner = abs(sx - cx) > 460 and abs(sy - cy) > 460
                    brightness = (r + g + b) // 3
                    is_snowflake = brightness > 150 and not in_corner

                    if is_snowflake:
                        fr, fg, fb = r, g, b
                    elif in_corner or dist >= 620:
                        fr, fg, fb = BG_R, BG_G, BG_B
                    elif dist > 480:
                        t = (dist - 480.0) / (620.0 - 480.0)
                        fr = int(r * (1.0 - t) + BG_R * t)
                        fg = int(g * (1.0 - t) + BG_G * t)
                        fb = int(b * (1.0 - t) + BG_B * t)
                    else:
                        fr, fg, fb = r, g, b

                    pix_offset = row_offset + dx * 4
                    dst_buf[pix_offset] = fb
                    dst_buf[pix_offset + 1] = fg
                    dst_buf[pix_offset + 2] = fr
                    dst_buf[pix_offset + 3] = 255

            gdiplus.GdipBitmapUnlockBits(p_dst, ctypes.byref(dst_data))
            out_file.parent.mkdir(parents=True, exist_ok=True)
            gdiplus.GdipSaveImageToFile(p_dst, str(out_file), ctypes.byref(PNG_CLSID), None)
            gdiplus.GdipDisposeImage(p_dst)

        densities = [
            ("mdpi", 48, 108),
            ("hdpi", 72, 162),
            ("xhdpi", 96, 216),
            ("xxhdpi", 144, 324),
            ("xxxhdpi", 192, 432),
        ]

        # In adaptive icons (108dp canvas), the safe zone is ~66dp diameter (radius 33dp).
        # Sizing snowflake tips (radius 558px) with crop_sz = 1680px puts the tips at
        # 558 / 1680 * 108 = 35.8dp, beautifully filling the ColorOS squircle safe zone.
        ADAPTIVE_CROP = 1680.0
        # For legacy icons (full-bleed square or circle), crop_sz = 1440px gives a bold, full-bleed icon
        LEGACY_CROP = 1440.0

        for folder, legacy_sz, adaptive_sz in densities:
            folder_dir = res_root / f"mipmap-{folder}"
            # 1. Full-bleed legacy icon
            render_seamless_icon(legacy_sz, LEGACY_CROP, folder_dir / "ic_launcher.png")
            # 2. Round legacy icon
            render_seamless_icon(legacy_sz, LEGACY_CROP, folder_dir / "ic_launcher_round.png")
            # 3. Adaptive foreground icon
            render_seamless_icon(adaptive_sz, ADAPTIVE_CROP, folder_dir / "ic_launcher_foreground.png")
            print(f"Generated {folder}: legacy={legacy_sz}x{legacy_sz}, adaptive_fg={adaptive_sz}x{adaptive_sz}")

        # Previews only when explicitly requested
        if preview:
            render_seamless_icon(512, LEGACY_CROP, Path("icon_preview.png"))
            render_seamless_icon(432, ADAPTIVE_CROP, Path("adaptive_preview.png"))
            print("Generated icon_preview.png and adaptive_preview.png successfully.")

        gdiplus.GdipBitmapUnlockBits(p_src, ctypes.byref(src_data))
        gdiplus.GdipDisposeImage(p_src)
    finally:
        gdiplus.GdiplusShutdown(token)


if __name__ == "__main__":
    snow_root = Path(__file__).resolve().parent.parent
    src_img = snow_root / "snow.png"
    if not src_img.exists():
        src_img = snow_root / "snow.jpg"
    res_dir = snow_root / "android" / "app" / "src" / "main" / "res"
    generate_icons(src_img, res_dir, preview="--preview" in sys.argv)
