#!/usr/bin/env python3
"""Build and packaging orchestrator for SNOW Windows Release.

Executes the standalone build pipeline:
1. Validates Python environment (requires Python 3.13).
2. Cleans previous dist/ and build/ directories.
3. Verifies and packages official pinned Cloudflare tunnel binary.
4. Invokes PyInstaller with packaging/windows/snow.spec.
5. Verifies the standalone distribution output.
6. Locates Inno Setup (ISCC.exe) and compiles the Windows installer (if available).
"""

from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Optional
import urllib.request
import zipfile

# Web UI static asset allowlist & required core assets (kept in sync with snow.updater)
ALLOWED_WEB_EXTENSIONS = {
    ".html", ".css", ".js", ".svg", ".png",
    ".jpg", ".jpeg", ".ico", ".woff", ".woff2",
}
REQUIRED_WEB_ASSETS = ("index.html", "app.js", "app.css", "tokens.css", "theme-init.js")


def _read_android_version_code(repo_root: Path, rel_ver: str) -> int:
    """Parse versionCode from android/app/build.gradle.kts with deterministic fallback."""
    gradle_file = repo_root / "android" / "app" / "build.gradle.kts"
    if gradle_file.is_file():
        m = re.search(r"\bversionCode\s*=\s*(\d+)", gradle_file.read_text(encoding="utf-8"))
        if m:
            return int(m.group(1))
    if rel_ver.startswith("7."):
        return 5
    if rel_ver.startswith("5.2"):
        return 4
    if rel_ver.startswith("5.1"):
        return 3
    return 2


def build_web_ui_archive(static_dir: Path, zip_path: Path) -> Path:
    """Package static Web UI assets into a validated ZIP matching snow.updater rules."""
    static_root = static_dir.resolve()
    if not static_root.is_dir():
        raise FileNotFoundError(f"Static Web UI directory not found: {static_root}")

    for req in REQUIRED_WEB_ASSETS:
        req_file = static_root / req
        if not req_file.is_file() or req_file.stat().st_size == 0:
            raise FileNotFoundError(f"Required Web UI asset missing or empty: {req_file}")

    zip_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_zip = zip_path.with_suffix(".zip.tmp")
    if tmp_zip.exists():
        tmp_zip.unlink()

    with zipfile.ZipFile(tmp_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(static_root.rglob("*")):
            if not file_path.is_file() or file_path.is_symlink():
                continue
            if file_path.suffix.lower() not in ALLOWED_WEB_EXTENSIONS:
                continue
            rel = file_path.relative_to(static_root).as_posix()
            if ".." in rel.split("/") or rel.startswith("/"):
                raise ValueError(f"Unsafe relative asset path: {rel}")
            zf.write(file_path, arcname=rel)

    os.replace(tmp_zip, zip_path)
    return zip_path

# Pinned official Cloudflare Windows AMD64 distribution details
CLOUDFLARED_VERSION: str = "2026.11.2"
CLOUDFLARED_URL: str = (
    f"https://github.com/cloudflare/cloudflared/releases/download/{CLOUDFLARED_VERSION}/cloudflared-windows-amd64.exe"
)
CLOUDFLARED_SHA256: str = "555b46c85582461d189cac30d14ad05480d612613801be9f110b8ce08c5b2113"


def compute_file_sha256(filepath: Path) -> str:
    """Compute the SHA-256 hex digest of a local file."""
    if not filepath.is_file():
        raise FileNotFoundError(f"File not found: {filepath}")
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest().lower()


def verify_file_sha256(filepath: Path, expected_sha256: str) -> bool:
    """Verify that a local file matches the expected SHA-256 digest."""
    try:
        digest = compute_file_sha256(filepath)
        return digest == expected_sha256.lower()
    except Exception:
        return False


def ensure_cloudflared_binary(
    repo_root: Path,
    target_dir: Optional[Path] = None,
    allow_download: bool = True,
) -> Path:
    """Ensure the verified official Cloudflare tunnel binary is available.

    Validates packaging/bin/cloudflared.exe against pinned SHA-256.
    If missing or corrupt, downloads from official Cloudflare releases,
    re-verifies cryptographic checksum, and optionally copies to target_dir.
    """
    pkg_bin_dir = repo_root / "packaging" / "bin"
    pkg_bin_dir.mkdir(parents=True, exist_ok=True)
    cf_exe = pkg_bin_dir / "cloudflared.exe"

    if cf_exe.is_file():
        if verify_file_sha256(cf_exe, CLOUDFLARED_SHA256):
            print(f"[+] Verified official cloudflared binary (SHA-256: {CLOUDFLARED_SHA256[:16]}...)")
            if target_dir:
                target_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(cf_exe, target_dir / "cloudflared.exe")
            return cf_exe
        else:
            print(f"[!] Warning: Existing {cf_exe} failed SHA-256 verification. Discarding...", file=sys.stderr)
            cf_exe.unlink()

    if not allow_download:
        raise RuntimeError(f"Official cloudflared.exe missing in {pkg_bin_dir} and downloads disabled.")

    print(f"[*] Downloading official cloudflared v{CLOUDFLARED_VERSION} from {CLOUDFLARED_URL}...")
    try:
        urllib.request.urlretrieve(CLOUDFLARED_URL, str(cf_exe))
    except Exception as exc:
        if cf_exe.exists():
            cf_exe.unlink()
        raise RuntimeError(f"Failed downloading cloudflared binary: {exc}") from exc

    if not verify_file_sha256(cf_exe, CLOUDFLARED_SHA256):
        actual_digest = compute_file_sha256(cf_exe) if cf_exe.is_file() else "missing"
        if cf_exe.exists():
            cf_exe.unlink()
        raise RuntimeError(
            f"Integrity check failed for cloudflared.exe!\n"
            f"  Expected: {CLOUDFLARED_SHA256}\n"
            f"  Actual:   {actual_digest}\n"
            f"Build aborted for supply-chain security."
        )

    print(f"[+] Downloaded and verified cloudflared v{CLOUDFLARED_VERSION} (SHA-256 verified).")
    if target_dir:
        target_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cf_exe, target_dir / "cloudflared.exe")
    return cf_exe


def find_inno_setup_compiler() -> Path | None:
    """Locate Inno Setup compiler (ISCC.exe) in PATH or standard install locations."""
    # 1. PATH search
    iscc = shutil.which("ISCC.exe") or shutil.which("iscc")
    if iscc:
        return Path(iscc)

    # 2. Standard Program Files locations
    candidates = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Inno Setup 6" / "ISCC.exe",
        Path(os.environ.get("LOCALAPPDATA", r"C:\Users\AppData\Local")) / "Programs" / "Inno Setup 6" / "ISCC.exe",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate

    return None


def run_pipeline(
    clean: bool = True,
    skip_installer: bool = False,
    dry_run: bool = False,
    bundle_cloudflared: bool = False,
) -> int:
    """Execute the release build pipeline."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    spec_file = repo_root / "packaging" / "windows" / "snow.spec"
    iss_file = repo_root / "packaging" / "windows" / "snow_setup.iss"
    dist_dir = repo_root / "dist"
    build_dir = repo_root / "build"
    output_dir = repo_root / "packaging" / "output"

    print("=" * 70)
    print(" SNOW Windows Standalone Distribution Builder")
    print("=" * 70)
    print(f" Repository Root: {repo_root}")
    print(f" Python Executable: {sys.executable} ({sys.version.split()[0]})")
    print(f" Spec File:       {spec_file}")
    print(f" Inno Setup File: {iss_file}")
    print(f" Mode:            {'DRY-RUN' if dry_run else 'BUILD'}")
    print("=" * 70)

    # Preflight Python check
    if sys.version_info < (3, 13):
        print(f"[!] Warning: SNOW requires Python 3.13+. Detected {sys.version}.", file=sys.stderr)

    if dry_run:
        print("[*] Dry run: verified configuration paths.")
        cf_present = (repo_root / "packaging" / "bin" / "cloudflared.exe").is_file()
        cf_valid = verify_file_sha256(repo_root / "packaging" / "bin" / "cloudflared.exe", CLOUDFLARED_SHA256) if cf_present else False
        print(f"[*] Cloudflare binary status: {'Verified' if cf_valid else 'Will be fetched/verified during release'}")
        iscc = find_inno_setup_compiler()
        print(f"[*] Inno Setup Compiler status: {'Found (' + str(iscc) + ')' if iscc else 'Not installed (installer step will be skipped)'}")
        return 0

    # 1. Clean previous build artifacts
    if clean:
        print("[*] Cleaning build/ and dist/ directories...")
        for d in (dist_dir / "snow", build_dir / "snow"):
            if d.exists():
                try:
                    shutil.rmtree(d)
                except Exception as exc:
                    print(f"[!] Warning: Could not remove {d}: {exc}")

    output_dir.mkdir(parents=True, exist_ok=True)

    # 2. Optionally verify/bundle cloudflared when explicitly requested
    if bundle_cloudflared:
        print("[*] Verifying optional bundled cloudflared binary...")
        try:
            ensure_cloudflared_binary(repo_root)
        except Exception as exc:
            print(f"[!] Supply-chain verification error: {exc}", file=sys.stderr)
            return 1
    else:
        print("[*] Skipping cloudflared.exe bundling to keep release lean (--bundle-cloudflared not set).")

    # 3. Check for PyInstaller
    try:
        import PyInstaller
    except ImportError:
        print("[!] Error: PyInstaller is not installed in the active environment.", file=sys.stderr)
        print("    Install it via: pip install pyinstaller", file=sys.stderr)
        return 1

    # 4. Execute PyInstaller
    print("[*] Compiling standalone SNOW distribution via PyInstaller...")
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        str(spec_file),
    ]

    pyi_env = os.environ.copy()
    pyi_env["SNOW_BUNDLE_CLOUDFLARED"] = "1" if bundle_cloudflared else "0"
    res = subprocess.run(cmd, cwd=str(repo_root), env=pyi_env)
    if res.returncode != 0:
        print(f"[!] PyInstaller build failed with exit code {res.returncode}.", file=sys.stderr)
        return res.returncode

    snow_exe = dist_dir / "snow" / "snow.exe"
    if not snow_exe.is_file():
        print(f"[!] Build verification failed: {snow_exe} was not produced.", file=sys.stderr)
        return 1

    # 5. Optionally place verified cloudflared binary into dist/snow/bin/cloudflared.exe
    if bundle_cloudflared:
        target_bin_dir = dist_dir / "snow" / "bin"
        try:
            ensure_cloudflared_binary(repo_root, target_dir=target_bin_dir)
            print(f"[+] Installed verified cloudflared.exe to {target_bin_dir / 'cloudflared.exe'}")
        except Exception as exc:
            print(f"[!] Failed staging cloudflared.exe into distribution: {exc}", file=sys.stderr)
            return 1

    # 5b. Stage release-signed Android APK and Web UI update archive
    sys.path.insert(0, str(repo_root / "src"))
    try:
        import snow as _snow_pkg
        rel_ver = getattr(_snow_pkg, "__version__", "7.0.0")
    except Exception:
        rel_ver = "7.0.0"

    staged_apk = output_dir / f"SNOW-Mobile-{rel_ver}.apk"
    if not staged_apk.is_file():
        candidates = sorted(output_dir.glob("SNOW-Mobile-*.apk"), reverse=True)
        staged_apk = candidates[0] if candidates else staged_apk
    if staged_apk.is_file():
        dst_apk_dir = dist_dir / "snow" / "packaging" / "output"
        dst_apk_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(staged_apk, dst_apk_dir / staged_apk.name)
        print(f"[+] Staged {staged_apk.name} into {dst_apk_dir / staged_apk.name}")

    dist_snow_dir = dist_dir / "snow"
    total_bytes = sum(f.stat().st_size for f in dist_snow_dir.rglob("*") if f.is_file())
    total_mb = total_bytes / (1024 * 1024)
    print(f"[+] Standalone bundle successfully built: {dist_snow_dir} ({total_mb:.2f} MB)")

    # 6. Inno Setup installer compilation
    if not skip_installer:
        iscc_path = find_inno_setup_compiler()
        if not iscc_path:
            print("[!] Note: Inno Setup (ISCC.exe) was not found in PATH or standard directories.")
            print("    Standalone directory distribution is ready at: dist/snow/")
            print("    To build the single-file installer, install Inno Setup 6: https://jrsoftware.org/isdl.php")
        else:
            print(f"[*] Compiling Windows Installer via Inno Setup ({iscc_path})...")
            iscc_cmd = [str(iscc_path), str(iss_file)]
            iscc_res = subprocess.run(iscc_cmd, cwd=str(repo_root / "packaging" / "windows"))
            if iscc_res.returncode != 0:
                print(f"[!] Inno Setup compilation failed with exit code {iscc_res.returncode}.", file=sys.stderr)
                return iscc_res.returncode
            print(f"[+] SNOW Windows Installer successfully generated in: {output_dir}")

    # 7. Package validated Web UI bundle and write/update OTA manifest
    web_ui_zip = output_dir / f"snow-web-ui-{rel_ver}.zip"
    build_web_ui_archive(repo_root / "src" / "snow" / "web" / "static", web_ui_zip)
    print(f"[+] Packaged Web UI update archive: {web_ui_zip}")

    import json
    manifest: dict[str, object] = {
        "version": rel_ver,
        "release_notes": f"SNOW V{rel_ver} release",
    }
    setup_exe = output_dir / f"SNOW-Setup-{rel_ver}.exe"
    if setup_exe.is_file():
        manifest["desktop"] = {
            "url": f"https://github.com/ayush77463/snow/releases/download/v{rel_ver}/{setup_exe.name}",
            "filename": setup_exe.name,
            "sha256": compute_file_sha256(setup_exe),
            "size_bytes": setup_exe.stat().st_size,
        }
    if web_ui_zip.is_file():
        manifest["web_ui"] = {
            "url": f"https://github.com/ayush77463/snow/releases/download/v{rel_ver}/{web_ui_zip.name}",
            "filename": web_ui_zip.name,
            "sha256": compute_file_sha256(web_ui_zip),
            "size_bytes": web_ui_zip.stat().st_size,
        }
    if staged_apk.is_file():
        manifest["android"] = {
            "version_code": _read_android_version_code(repo_root, rel_ver),
            "version_name": rel_ver,
            "apk_name": staged_apk.name,
            "sha256": compute_file_sha256(staged_apk),
            "size_bytes": staged_apk.stat().st_size,
        }
    if "desktop" in manifest or "web_ui" in manifest or "android" in manifest:
        manifest_path = output_dir / "update_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"[+] Wrote OTA manifest: {manifest_path}")
        if dist_snow_dir.is_dir():
            dist_out_dir = dist_snow_dir / "packaging" / "output"
            dist_out_dir.mkdir(parents=True, exist_ok=True)
            shutil.copy2(manifest_path, dist_out_dir / "update_manifest.json")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SNOW Windows Release Builder")
    parser.add_argument("--no-clean", action="store_true", help="Do not clean build/ and dist/ before compiling")
    parser.add_argument("--skip-installer", action="store_true", help="Skip Inno Setup compiler step")
    parser.add_argument("--dry-run", action="store_true", help="Validate build paths and environment without compiling")
    parser.add_argument("--bundle-cloudflared", action="store_true", help="Include optional cloudflared.exe binary in distribution")
    args = parser.parse_args()

    return run_pipeline(
        clean=not args.no_clean,
        skip_installer=args.skip_installer,
        dry_run=args.dry_run,
        bundle_cloudflared=args.bundle_cloudflared,
    )


if __name__ == "__main__":
    sys.exit(main())
