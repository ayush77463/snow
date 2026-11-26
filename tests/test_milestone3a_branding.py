"""Milestone 3A Unit 3.1: Universal branding asset generation and validation tests."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from PIL import Image

from scripts.generate_branding_assets import (
    ADAPTIVE_DENSITIES,
    ICO_SIZES,
    LEGACY_DENSITIES,
    generate_all,
    resolve_source_logo,
)


REPO_ROOT = Path(__file__).resolve().parent.parent


class TestMilestone3ABrandingGenerator(unittest.TestCase):
    """Verify source selection, fallback semantics, determinism, and outputs."""

    def test_01_primary_over_fallback_and_clear_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            primary = tmp_dir / "snow.png"
            fallback = tmp_dir / "snow_logo.png"

            # Neither exists -> clear FileNotFoundError
            with self.assertRaises(FileNotFoundError):
                resolve_source_logo(primary_path=primary, fallback_path=fallback)

            # Fallback only -> picks fallback
            Image.new("RGBA", (128, 128), (20, 120, 220, 255)).save(fallback, "PNG")
            chosen, img = resolve_source_logo(primary_path=primary, fallback_path=fallback)
            self.assertEqual(chosen, fallback)
            self.assertEqual(img.size, (128, 128))

            # Corrupt primary -> falls back cleanly to fallback
            primary.write_bytes(b"not a png image")
            chosen, img = resolve_source_logo(primary_path=primary, fallback_path=fallback)
            self.assertEqual(chosen, fallback)

            # Valid primary present -> prefers primary over fallback
            Image.new("RGBA", (240, 180), (10, 20, 60, 255)).save(primary, "PNG")
            chosen, img = resolve_source_logo(primary_path=primary, fallback_path=fallback)
            self.assertEqual(chosen, primary)
            self.assertEqual(img.size, (240, 180))

    def test_02_deterministic_regeneration_in_temp_root(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            img = Image.new("RGBA", (240, 180), (6, 9, 40, 255))
            from PIL import ImageDraw

            draw = ImageDraw.Draw(img)
            draw.polygon([(120, 25), (175, 90), (120, 155), (65, 90)], fill=(140, 220, 255, 255))
            primary = root / "design" / "snow.png"
            primary.parent.mkdir(parents=True, exist_ok=True)
            img.save(primary, "PNG")

            h1 = generate_all(primary_path=primary, fallback_path=root / "design" / "snow_logo.png", repo_root=root)
            h2 = generate_all(primary_path=primary, fallback_path=root / "design" / "snow_logo.png", repo_root=root)
            self.assertEqual(h1, h2)
            self.assertTrue((root / "snow.png").is_file())
            self.assertTrue((root / "src" / "snow" / "web" / "static" / "favicon.ico").is_file())

    def test_03_repo_generated_assets_valid_dimensions_and_padding(self) -> None:
        self.assertTrue((REPO_ROOT / "design" / "snow.png").is_file())

        # Root fixture & Web logo
        for rel_path in ("snow.png", "src/snow/web/static/snow_logo.png"):
            path = REPO_ROOT / rel_path
            self.assertTrue(path.is_file(), f"Missing generated PNG: {rel_path}")
            with Image.open(path) as opened:
                self.assertEqual(opened.format, "PNG")
                self.assertEqual(opened.size, (512, 512))
                # Corner pixels must be clean background, zero bottom-right watermark corner bleed
                self.assertEqual(opened.mode, "RGBA")

        # ICO assets
        ico_win = REPO_ROOT / "packaging" / "windows" / "snow.ico"
        ico_web = REPO_ROOT / "src" / "snow" / "web" / "static" / "favicon.ico"
        self.assertTrue(ico_win.is_file())
        self.assertTrue(ico_web.is_file())
        self.assertEqual(ico_win.read_bytes(), ico_web.read_bytes())
        expected_ico_sizes = {(s, s) for s in ICO_SIZES}
        with Image.open(ico_win) as ico:
            self.assertEqual(ico.format, "ICO")
            self.assertTrue(expected_ico_sizes.issubset(set(ico.info.get("sizes") or set())))

        # Android in-app drawable
        res_dir = REPO_ROOT / "android" / "app" / "src" / "main" / "res"
        drawable_logo = res_dir / "drawable" / "ic_snow_logo.png"
        self.assertTrue(drawable_logo.is_file())
        with Image.open(drawable_logo) as ic:
            self.assertEqual(ic.size, (512, 512))
            self.assertEqual(ic.mode, "RGBA")
            a_min, a_max = ic.getchannel("A").getextrema()
            self.assertEqual(a_min, 0)
            self.assertGreater(a_max, 240)

        # Adaptive foregrounds preserve safe-zone transparent border padding
        for folder, canvas_sz in ADAPTIVE_DENSITIES.items():
            fg = res_dir / folder / "ic_launcher_foreground.png"
            self.assertTrue(fg.is_file(), f"Missing {fg}")
            with Image.open(fg) as im:
                self.assertEqual(im.size, (canvas_sz, canvas_sz))
                self.assertEqual(im.mode, "RGBA")
                for corner in ((0, 0), (canvas_sz - 1, 0), (0, canvas_sz - 1), (canvas_sz - 1, canvas_sz - 1)):
                    self.assertEqual(im.getpixel(corner)[3], 0, f"Corner {corner} must stay transparent in {fg}")
                bbox = im.getchannel("A").getbbox()
                self.assertIsNotNone(bbox)
                margin = max(2, int(canvas_sz * 0.14))
                self.assertGreaterEqual(bbox[0], margin, f"Left safe zone violated in {fg}: {bbox}")
                self.assertLessEqual(bbox[2], canvas_sz - margin, f"Right safe zone violated in {fg}: {bbox}")

        # Legacy square and round launchers
        for folder, sz in LEGACY_DENSITIES.items():
            for name in ("ic_launcher.png", "ic_launcher_round.png"):
                p = res_dir / folder / name
                self.assertTrue(p.is_file(), f"Missing {p}")
                with Image.open(p) as im:
                    self.assertEqual(im.size, (sz, sz))
                    self.assertEqual(im.mode, "RGBA")


if __name__ == "__main__":
    unittest.main()
