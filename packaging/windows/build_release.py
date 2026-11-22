#!/usr/bin/env python3
"""Build and packaging orchestrator for SNOW Windows Release.

Executes the standalone build pipeline:
1. Validates Python environment (requires Python 3.13).
2. Cleans previous dist/ and build/ directories.
3. Invokes PyInstaller with packaging/windows/snow.spec.
4. Verifies the standalone distribution output.
5. Locates Inno Setup (ISCC.exe) and compiles the Windows installer (if available).
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys


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

    # 2. Check for PyInstaller
    try:
        import PyInstaller
    except ImportError:
        print("[!] Error: PyInstaller is not installed in the active environment.", file=sys.stderr)
        print("    Install it via: pip install pyinstaller", file=sys.stderr)
        return 1

    # 3. Execute PyInstaller
    print("[*] Compiling standalone SNOW distribution via PyInstaller...")
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        str(spec_file),
    ]

    res = subprocess.run(cmd, cwd=str(repo_root))
    if res.returncode != 0:
        print(f"[!] PyInstaller build failed with exit code {res.returncode}.", file=sys.stderr)
        return res.returncode

    snow_exe = dist_dir / "snow" / "snow.exe"
    if not snow_exe.is_file():
        print(f"[!] Build verification failed: {snow_exe} was not produced.", file=sys.stderr)
        return 1

    print(f"[+] Standalone bundle successfully built: {dist_dir / 'snow'}")

    # 4. Inno Setup installer compilation
    if skip_installer:
        print("[*] Skipping Inno Setup installer compilation (--skip-installer).")
        return 0

    iscc_path = find_inno_setup_compiler()
    if not iscc_path:
        print("[!] Note: Inno Setup (ISCC.exe) was not found in PATH or standard directories.")
        print("    Standalone directory distribution is ready at: dist/snow/")
        print("    To build the single-file installer, install Inno Setup 6: https://jrsoftware.org/isdl.php")
        return 0

    print(f"[*] Compiling Windows Installer via Inno Setup ({iscc_path})...")
    iscc_cmd = [str(iscc_path), str(iss_file)]
    iscc_res = subprocess.run(iscc_cmd, cwd=str(repo_root / "packaging" / "windows"))
    if iscc_res.returncode != 0:
        print(f"[!] Inno Setup compilation failed with exit code {iscc_res.returncode}.", file=sys.stderr)
        return iscc_res.returncode

    print(f"[+] SNOW Windows Installer successfully generated in: {output_dir}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="SNOW Windows Release Builder")
    parser.add_argument("--no-clean", action="store_true", help="Do not clean build/ and dist/ before compiling")
    parser.add_argument("--skip-installer", action="store_true", help="Skip Inno Setup compiler step")
    parser.add_argument("--dry-run", action="store_true", help="Validate build paths and environment without compiling")
    args = parser.parse_args()

    return run_pipeline(
        clean=not args.no_clean,
        skip_installer=args.skip_installer,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    sys.exit(main())
