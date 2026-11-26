#!/usr/bin/env python3
"""SNOW V7 Universal Branding Asset Generator.

Loads the authoritative approved logo from design/snow.png (falling back to
design/snow_logo.png only when the primary source is missing or unreadable)
and deterministically generates platform assets:
1. Android Adaptive Icon foregrounds (mdpi..xxxhdpi) with 66% safe-zone sizing.
2. Android Legacy square & round launcher icons (mdpi..xxxhdpi).
3. Android in-app logo drawable (drawable/ic_snow_logo.png).
4. Windows multi-resolution icon (packaging/windows/snow.ico: 16..256).
5. Root sample & Web Dashboard branding assets (snow.png, snow_logo.png, favicon.ico).
"""

import hashlib
import math
import sys
from pathlib import Path
from PIL import Image, ImageDraw, ImageFilter

REPO_ROOT = Path(__file__).resolve().parent.parent
PRIMARY_DESIGN_LOGO = REPO_ROOT / "design" / "snow.png"
FALLBACK_DESIGN_LOGO = REPO_ROOT / "design" / "snow_logo.png"

# Adaptive icon density scales (108dp canvas)
ADAPTIVE_DENSITIES = {
    "mipmap-mdpi": 108,
    "mipmap-hdpi": 162,
    "mipmap-xhdpi": 216,
    "mipmap-xxhdpi": 324,
    "mipmap-xxxhdpi": 432,
}

# Legacy launcher icon density scales (48dp canvas)
LEGACY_DENSITIES = {
    "mipmap-mdpi": 48,
    "mipmap-hdpi": 72,
    "mipmap-xhdpi": 96,
    "mipmap-xxhdpi": 144,
    "mipmap-xxxhdpi": 192,
}

ICO_SIZES = [16, 24, 32, 48, 64, 128, 256]
BRAND_BG_RGBA = (6, 9, 40, 255)


def resolve_source_logo(
    primary_path: Path = PRIMARY_DESIGN_LOGO,
    fallback_path: Path = FALLBACK_DESIGN_LOGO,
) -> tuple[Path, Image.Image]:
    """Load design/snow.png first, falling back to design/snow_logo.png cleanly."""
    errors: list[str] = []
    for candidate in (primary_path, fallback_path):
        if not candidate.is_file():
            errors.append(f"{candidate}: file not found")
            continue
        try:
            with Image.open(candidate) as opened:
                loaded = opened.convert("RGBA")
                loaded.load()
            if loaded.width < 64 or loaded.height < 64:
                errors.append(f"{candidate}: dimensions too small ({loaded.size})")
                continue
            return candidate, loaded
        except Exception as exc:
            errors.append(f"{candidate}: failed to decode ({exc})")
    raise FileNotFoundError(
        "No valid SNOW branding source image found. Checked: " + "; ".join(errors)
    )


def prepare_square_artwork(src: Image.Image) -> Image.Image:
    """Return an undistorted 1:1 center crop preserving aspect ratio and artwork."""
    rgba = src.convert("RGBA")
    w, h = rgba.size
    if w == h:
        return rgba
    side = min(w, h)
    left = (w - side) // 2
    top = (h - side) // 2
    return rgba.crop((left, top, left + side, top + side))


def create_transparent_logo(src: Image.Image) -> Image.Image:
    """Extract the centered crystal emblem onto a crisp transparent square canvas."""
    sq = prepare_square_artwork(src)
    alpha_min, _ = sq.getchannel("A").getextrema()
    w, h = sq.size
    px = sq.load()

    # If the source already supplies genuine alpha transparency around borders, preserve it.
    border_has_alpha = any(
        px[x, y][3] < 32
        for x, y in ((0, 0), (w - 1, 0), (0, h - 1), (w - 1, h - 1))
    )
    if alpha_min < 245 and border_has_alpha:
        out = sq.copy()
    else:
        row_lr: list[tuple[float, float, float]] = []
        margin = max(8, min(120, w // 14))
        sample_xs = list(range(0, margin, 4)) + list(range(max(0, w - margin), w, 4))
        for y in range(h):
            rs = gs = bs = 0.0
            for x in sample_xs:
                r, g, b, _ = px[x, y]
                rs += r
                gs += g
                bs += b
            count = float(max(1, len(sample_xs)))
            row_lr.append((rs / count, gs / count, bs / count))

        mask = Image.new("L", (w, h), 0)
        mpx = mask.load()
        max_radius = w * 0.43
        cx = w / 2.0
        cy = h / 2.0
        for y in range(h):
            lr_r, _, _ = row_lr[y]
            for x in range(w):
                if math.hypot(x - cx, y - cy) > max_radius:
                    continue
                r, g, b, a = px[x, y]
                if a < 16:
                    continue
                is_bright_crystal = max(r, g, b) >= 120 and (r >= 40 or g >= 80)
                is_purple_facet = (
                    b >= 98
                    and r >= max(28, int(lr_r + 14))
                    and (b - r) < 135
                    and r >= g - 12
                )
                is_cyan_core = g >= 78 and b >= 120
                if is_bright_crystal or is_purple_facet or is_cyan_core:
                    mpx[x, y] = 255

        # Morphological closing removes tiny internal facet pinholes, then slight feathering smooths edges.
        closed = mask.filter(ImageFilter.MaxFilter(size=7)).filter(ImageFilter.MinFilter(size=7))
        cleaned = closed.filter(ImageFilter.MedianFilter(size=3))
        soft_mask = cleaned.filter(ImageFilter.GaussianBlur(radius=0.7))

        out = sq.copy()
        out.putalpha(soft_mask)

    bbox = out.getbbox()
    if bbox:
        cropped = out.crop(bbox)
        max_dim = max(cropped.width, cropped.height)
        square = Image.new("RGBA", (max_dim, max_dim), (0, 0, 0, 0))
        offset_x = (max_dim - cropped.width) // 2
        offset_y = (max_dim - cropped.height) // 2
        square.paste(cropped, (offset_x, offset_y), cropped)
        return square

    return out


def generate_android_assets(
    trans_logo: Image.Image,
    res_dir: Path | None = None,
) -> list[Path]:
    res_root = res_dir or (REPO_ROOT / "android" / "app" / "src" / "main" / "res")
    written: list[Path] = []

    # 1. In-app logo drawable (512x512)
    drawable_dir = res_root / "drawable"
    drawable_dir.mkdir(parents=True, exist_ok=True)
    in_app_logo = trans_logo.resize((512, 512), Image.Resampling.LANCZOS)
    drawable_path = drawable_dir / "ic_snow_logo.png"
    in_app_logo.save(drawable_path, "PNG", optimize=True)
    written.append(drawable_path)
    print(f"[+] Generated {drawable_path}")

    xml_logo = drawable_dir / "ic_snow_logo.xml"
    if xml_logo.is_file():
        xml_logo.unlink()
        print(f"[-] Removed conflicting {xml_logo}")

    # 2. Adaptive Icon Foregrounds: 66% safe zone on 108dp canvas
    for folder, canvas_size in ADAPTIVE_DENSITIES.items():
        out_folder = res_root / folder
        out_folder.mkdir(parents=True, exist_ok=True)

        target_size = int(round(canvas_size * 0.66))
        scaled_logo = trans_logo.resize((target_size, target_size), Image.Resampling.LANCZOS)

        canvas = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
        offset = (canvas_size - target_size) // 2
        canvas.paste(scaled_logo, (offset, offset), scaled_logo)

        out_path = out_folder / "ic_launcher_foreground.png"
        canvas.save(out_path, "PNG", optimize=True)
        written.append(out_path)
        print(
            f"[+] Generated adaptive foreground: {out_path} ({canvas_size}x{canvas_size}, safe logo {target_size}x{target_size})"
        )

    # 3. Legacy Launcher Icons (Square & Round)
    for folder, size in LEGACY_DENSITIES.items():
        out_folder = res_root / folder
        out_folder.mkdir(parents=True, exist_ok=True)

        sq_canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw_sq = ImageDraw.Draw(sq_canvas)
        radius = max(2, int(size * 0.18))
        draw_sq.rounded_rectangle([(0, 0), (size - 1, size - 1)], radius=radius, fill=BRAND_BG_RGBA)

        logo_sq_size = int(round(size * 0.76))
        scaled_sq_logo = trans_logo.resize((logo_sq_size, logo_sq_size), Image.Resampling.LANCZOS)
        offset_sq = (size - logo_sq_size) // 2
        sq_canvas.paste(scaled_sq_logo, (offset_sq, offset_sq), scaled_sq_logo)
        sq_path = out_folder / "ic_launcher.png"
        sq_canvas.save(sq_path, "PNG", optimize=True)
        written.append(sq_path)

        round_canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw_round = ImageDraw.Draw(round_canvas)
        draw_round.ellipse([(0, 0), (size - 1, size - 1)], fill=BRAND_BG_RGBA)

        logo_round_size = int(round(size * 0.70))
        scaled_round_logo = trans_logo.resize((logo_round_size, logo_round_size), Image.Resampling.LANCZOS)
        offset_round = (size - logo_round_size) // 2
        round_canvas.paste(scaled_round_logo, (offset_round, offset_round), scaled_round_logo)
        round_path = out_folder / "ic_launcher_round.png"
        round_canvas.save(round_path, "PNG", optimize=True)
        written.append(round_path)

        print(f"[+] Generated legacy icons: {out_folder} ({size}x{size})")

    return written


def generate_windows_assets(
    trans_logo: Image.Image,
    pkg_win_dir: Path | None = None,
) -> Path:
    pkg_win = pkg_win_dir or (REPO_ROOT / "packaging" / "windows")
    pkg_win.mkdir(parents=True, exist_ok=True)
    ico_path = pkg_win / "snow.ico"

    ico_images = []
    for s in sorted(ICO_SIZES, reverse=True):
        canvas = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        draw = ImageDraw.Draw(canvas)
        r = max(2, int(s * 0.20))
        draw.rounded_rectangle([(0, 0), (s - 1, s - 1)], radius=r, fill=BRAND_BG_RGBA)
        logo_size = max(1, int(round(s * 0.80)))
        scaled = trans_logo.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
        off = (s - logo_size) // 2
        canvas.paste(scaled, (off, off), scaled)
        ico_images.append(canvas)

    ico_images[0].save(
        ico_path,
        format="ICO",
        append_images=ico_images[1:],
    )
    with Image.open(ico_path) as check_ico:
        embedded = check_ico.info.get("sizes") or set()
    expected_sizes = {(s, s) for s in ICO_SIZES}
    if not expected_sizes.issubset(set(embedded)):
        raise RuntimeError(f"snow.ico missing expected sizes: got {embedded}, expected {expected_sizes}")
    print(f"[+] Generated Windows multi-res ICO: {ico_path} (sizes: {sorted(embedded)}, bytes: {ico_path.stat().st_size})")
    return ico_path


def generate_web_assets(
    src: Image.Image,
    ico_path: Path | None = None,
    repo_root: Path | None = None,
    static_dir: Path | None = None,
) -> list[Path]:
    root = repo_root or REPO_ROOT
    web_static = static_dir or (root / "src" / "snow" / "web" / "static")
    web_static.mkdir(parents=True, exist_ok=True)

    square_src = prepare_square_artwork(src)
    clean_png = square_src.resize((512, 512), Image.Resampling.LANCZOS)

    written: list[Path] = []

    # 1. Root snow.png (clean 512x512 optimized square PNG)
    root_logo = root / "snow.png"
    clean_png.save(root_logo, "PNG", optimize=True)
    written.append(root_logo)
    print(f"[+] Generated root {root_logo} ({root_logo.stat().st_size} bytes)")

    # 2. Web static snow_logo.png (clean 512x512 optimized square PNG)
    web_logo = web_static / "snow_logo.png"
    clean_png.save(web_logo, "PNG", optimize=True)
    written.append(web_logo)
    print(f"[+] Generated static {web_logo} ({web_logo.stat().st_size} bytes)")

    # 3. Web static favicon.ico (deterministic byte-for-byte match with snow.ico)
    src_ico = ico_path or (root / "packaging" / "windows" / "snow.ico")
    if not src_ico.is_file():
        raise FileNotFoundError(f"Expected ICO source missing at {src_ico}")
    favicon_path = web_static / "favicon.ico"
    favicon_path.write_bytes(src_ico.read_bytes())
    written.append(favicon_path)
    print(f"[+] Wrote favicon: {favicon_path} ({favicon_path.stat().st_size} bytes)")
    return written


def generate_all(
    primary_path: Path = PRIMARY_DESIGN_LOGO,
    fallback_path: Path = FALLBACK_DESIGN_LOGO,
    repo_root: Path = REPO_ROOT,
) -> dict[str, str]:
    """Generate all SNOW V7 branding assets deterministically and return SHA-256 hashes."""
    chosen_path, src = resolve_source_logo(primary_path=primary_path, fallback_path=fallback_path)
    print("=" * 60)
    print(" SNOW V7 Universal Branding Asset Generator")
    print("=" * 60)
    print(f" Source Logo: {chosen_path} ({src.size[0]}x{src.size[1]})")

    trans_logo = create_transparent_logo(src)
    print(f" Extracted transparent emblem: {trans_logo.size}")

    res_dir = repo_root / "android" / "app" / "src" / "main" / "res"
    pkg_win = repo_root / "packaging" / "windows"
    web_static = repo_root / "src" / "snow" / "web" / "static"

    android_paths = generate_android_assets(trans_logo, res_dir=res_dir)
    ico_path = generate_windows_assets(trans_logo, pkg_win_dir=pkg_win)
    web_paths = generate_web_assets(src, ico_path=ico_path, repo_root=repo_root, static_dir=web_static)

    all_outputs = [*android_paths, ico_path, *web_paths]
    hashes: dict[str, str] = {}
    for p in all_outputs:
        hashes[str(p)] = hashlib.sha256(p.read_bytes()).hexdigest()

    print("=" * 60)
    print(f"[+] Universal Branding Asset Generation COMPLETE ({len(all_outputs)} files).")
    print("=" * 60)
    return hashes


def main() -> None:
    try:
        generate_all()
    except Exception as exc:
        print(f"[!] Branding generation failed: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
