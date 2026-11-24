#!/usr/bin/env python3
"""SNOW V5 Branding Asset Generator.

Generates universal platform icons and assets from design/snow_logo.png:
1. Android Adaptive Icon foregrounds (mdpi..xxxhdpi) with ~66% safe-zone sizing.
2. Android Legacy square & round launcher icons (mdpi..xxxhdpi).
3. Android in-app logo drawable (drawable/ic_snow_logo.png).
4. Windows multi-resolution icon (packaging/windows/snow.ico: 16, 24, 32, 48, 64, 128, 256).
5. Web Dashboard branding assets (snow.png, src/snow/web/static/snow_logo.png, favicon.ico).
"""

from pathlib import Path
from PIL import Image, ImageDraw

REPO_ROOT = Path(__file__).resolve().parent.parent
DESIGN_LOGO = REPO_ROOT / "design" / "snow_logo.png"

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


def create_transparent_logo(src: Image.Image) -> Image.Image:
    """Extract transparent foreground snowflake emblem from dark background."""
    img = src.convert("RGBA")
    pixels = img.load()
    w, h = img.size

    out = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    out_pixels = out.load()

    for y in range(h):
        for x in range(w):
            r, g, b, _ = pixels[x, y]
            val = max(r, g, b)
            if val <= 30:
                out_pixels[x, y] = (0, 0, 0, 0)
            elif val >= 60:
                out_pixels[x, y] = (r, g, b, 255)
            else:
                a = int((val - 30) / 30.0 * 255)
                out_pixels[x, y] = (r, g, b, a)

    # Crop to visible bbox with balanced square padding
    bbox = out.getbbox()
    if bbox:
        cropped = out.crop(bbox)
        # Make square
        max_dim = max(cropped.width, cropped.height)
        square = Image.new("RGBA", (max_dim, max_dim), (0, 0, 0, 0))
        offset_x = (max_dim - cropped.width) // 2
        offset_y = (max_dim - cropped.height) // 2
        square.paste(cropped, (offset_x, offset_y), cropped)
        return square

    return out


def generate_android_assets(src: Image.Image, trans_logo: Image.Image) -> None:
    res_dir = REPO_ROOT / "android" / "app" / "src" / "main" / "res"

    # 1. In-app logo drawable (512x512)
    drawable_dir = res_dir / "drawable"
    drawable_dir.mkdir(parents=True, exist_ok=True)
    in_app_logo = trans_logo.resize((512, 512), Image.Resampling.LANCZOS)
    in_app_logo.save(drawable_dir / "ic_snow_logo.png", "PNG")
    print(f"[+] Generated {drawable_dir / 'ic_snow_logo.png'}")

    # Remove conflicting xml if present
    xml_logo = drawable_dir / "ic_snow_logo.xml"
    if xml_logo.is_file():
        xml_logo.unlink()
        print(f"[-] Removed conflicting {xml_logo}")

    # 2. Adaptive Icon Foregrounds: 66% safe zone on 108dp canvas
    for folder, canvas_size in ADAPTIVE_DENSITIES.items():
        out_folder = res_dir / folder
        out_folder.mkdir(parents=True, exist_ok=True)

        target_size = int(canvas_size * 0.66)  # 66% safe zone
        scaled_logo = trans_logo.resize((target_size, target_size), Image.Resampling.LANCZOS)

        canvas = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
        offset = (canvas_size - target_size) // 2
        canvas.paste(scaled_logo, (offset, offset), scaled_logo)

        out_path = out_folder / "ic_launcher_foreground.png"
        canvas.save(out_path, "PNG")
        print(f"[+] Generated adaptive foreground: {out_path} ({canvas_size}x{canvas_size}, logo {target_size}x{target_size})")

    # 3. Legacy Launcher Icons (Square & Round)
    bg_color = (3, 8, 18, 255)  # #030812
    for folder, size in LEGACY_DENSITIES.items():
        out_folder = res_dir / folder

        # Standard icon: rounded rect with #030812 background
        sq_canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw_sq = ImageDraw.Draw(sq_canvas)
        radius = max(2, int(size * 0.18))
        draw_sq.rounded_rectangle([(0, 0), (size - 1, size - 1)], radius=radius, fill=bg_color)

        logo_sq_size = int(size * 0.76)
        scaled_sq_logo = trans_logo.resize((logo_sq_size, logo_sq_size), Image.Resampling.LANCZOS)
        offset_sq = (size - logo_sq_size) // 2
        sq_canvas.paste(scaled_sq_logo, (offset_sq, offset_sq), scaled_sq_logo)
        sq_canvas.save(out_folder / "ic_launcher.png", "PNG")

        # Round icon: circle with #030812 background
        round_canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw_round = ImageDraw.Draw(round_canvas)
        draw_round.ellipse([(0, 0), (size - 1, size - 1)], fill=bg_color)

        logo_round_size = int(size * 0.68)
        scaled_round_logo = trans_logo.resize((logo_round_size, logo_round_size), Image.Resampling.LANCZOS)
        offset_round = (size - logo_round_size) // 2
        round_canvas.paste(scaled_round_logo, (offset_round, offset_round), scaled_round_logo)
        round_canvas.save(out_folder / "ic_launcher_round.png", "PNG")

        print(f"[+] Generated legacy icons: {out_folder} ({size}x{size})")


def generate_windows_assets(src: Image.Image, trans_logo: Image.Image) -> None:
    pkg_win = REPO_ROOT / "packaging" / "windows"
    pkg_win.mkdir(parents=True, exist_ok=True)
    ico_path = pkg_win / "snow.ico"

    # Create ICO using transparent logo on dark circular badge or full-bleed
    ico_images = []
    for s in ICO_SIZES:
        canvas = Image.new("RGBA", (s, s), (0, 0, 0, 0))
        draw = ImageDraw.Draw(canvas)
        # Rounded badge with #030812
        r = max(1, int(s * 0.18))
        draw.rounded_rectangle([(0, 0), (s - 1, s - 1)], radius=r, fill=(3, 8, 18, 255))
        logo_size = max(1, int(s * 0.80))
        scaled = trans_logo.resize((logo_size, logo_size), Image.Resampling.LANCZOS)
        off = (s - logo_size) // 2
        canvas.paste(scaled, (off, off), scaled)
        ico_images.append(canvas)

    # Pillow saves ICO with all provided resolutions
    ico_images[0].save(
        ico_path,
        format="ICO",
        sizes=[(s, s) for s in ICO_SIZES],
        append_images=ico_images[1:],
    )
    print(f"[+] Generated Windows multi-res ICO: {ico_path} (sizes: {ICO_SIZES})")


def generate_web_assets(src: Image.Image, trans_logo: Image.Image) -> None:
    # 1. Root snow.png
    root_logo = REPO_ROOT / "snow.png"
    src.save(root_logo, "PNG")
    print(f"[+] Generated root {root_logo}")

    # 2. Web static snow_logo.png
    static_dir = REPO_ROOT / "src" / "snow" / "web" / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    web_logo = static_dir / "snow_logo.png"
    src.save(web_logo, "PNG")
    print(f"[+] Generated static {web_logo}")

    # 3. Web static favicon.ico
    favicon_path = static_dir / "favicon.ico"
    ico_path = REPO_ROOT / "packaging" / "windows" / "snow.ico"
    if ico_path.is_file():
        import shutil
        shutil.copy2(ico_path, favicon_path)
        print(f"[+] Copied favicon: {favicon_path}")


def main() -> None:
    if not DESIGN_LOGO.is_file():
        print(f"[!] Error: {DESIGN_LOGO} not found!", file=sys.stderr)
        sys.exit(1)

    print("=" * 60)
    print(" SNOW V5 Universal Branding Asset Generator")
    print("=" * 60)
    print(f" Source Logo: {DESIGN_LOGO}")

    src = Image.open(DESIGN_LOGO)
    trans_logo = create_transparent_logo(src)
    print(f" Extracted transparent emblem: {trans_logo.size}")

    generate_android_assets(src, trans_logo)
    generate_windows_assets(src, trans_logo)
    generate_web_assets(src, trans_logo)

    print("=" * 60)
    print("[+] Universal Branding Asset Generation COMPLETE.")
    print("=" * 60)


if __name__ == "__main__":
    main()
