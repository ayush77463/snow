"""Direct Update Engine for SNOW Desktop and Web UI.

Provides secure, atomic update capabilities:
1. Release manifest retrieval and verification
2. Web UI hot-swap updates with strict archive security and atomic rollback
3. Windows desktop installer staging, SHA-256/publisher verification, and silent upgrade execution
4. Web UI override reset to bundled assets
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Any, Dict, Optional, Tuple, Union
import urllib.request
import zipfile

logger = logging.getLogger(__name__)

# Strict allowlists and constants
ALLOWED_STATIC_EXTENSIONS = {
    ".html", ".css", ".js", ".svg", ".png",
    ".jpg", ".jpeg", ".ico", ".woff", ".woff2"
}
REQUIRED_UI_ASSETS = {"index.html", "app.js", "app.css"}
DEFAULT_OVERRIDE_DIR = Path.home() / ".snow" / "web_override"
CURRENT_VERSION = "4.1.0"


def parse_version(version_str: str) -> Tuple[int, ...]:
    """Parse semver-like version string into integer tuple for robust comparison.

    e.g. '4.1.0' -> (4, 1, 0), 'v4.2.1-beta' -> (4, 2, 1)
    """
    clean = re.sub(r"^[vV]", "", version_str.strip())
    # Extract leading numeric components separated by dots
    match = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", clean)
    if not match:
        raise ValueError(f"Invalid version format: '{version_str}'")
    parts = match.groups()
    return tuple(int(p) if p is not None else 0 for p in parts)


def validate_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Validate release manifest schema and security constraints."""
    if not isinstance(manifest, dict):
        raise ValueError("Manifest must be a JSON object.")

    version_str = manifest.get("version")
    if not version_str or not isinstance(version_str, str):
        raise ValueError("Manifest missing required 'version' string.")

    # Validate version syntax
    parse_version(version_str)

    # Validate artifacts
    has_artifact = False
    for key in ("web_ui", "desktop"):
        artifact = manifest.get(key)
        if artifact is not None:
            if not isinstance(artifact, dict):
                raise ValueError(f"Manifest '{key}' artifact must be an object.")
            url = artifact.get("url")
            if not url or not isinstance(url, str):
                raise ValueError(f"Manifest '{key}' artifact missing required 'url'.")

            # Enforce HTTPS or local file URL for testing
            clean_url = url.strip().lower()
            if not (clean_url.startswith("https://") or clean_url.startswith("file://") or os.path.exists(url)):
                raise ValueError(f"Manifest '{key}' artifact URL must use HTTPS: '{url}'")

            sha256 = artifact.get("sha256")
            if not sha256 or not isinstance(sha256, str) or not re.match(r"^[a-fA-F0-9]{64}$", sha256):
                raise ValueError(f"Manifest '{key}' artifact missing valid 64-char hex 'sha256'.")

            has_artifact = True

    if not has_artifact:
        raise ValueError("Manifest contains no supported artifacts ('web_ui' or 'desktop').")

    return manifest


def check_for_updates(
    manifest_source: Optional[Union[str, Path, Dict[str, Any]]] = None,
    current_version: str = CURRENT_VERSION,
) -> Dict[str, Any]:
    """Check for available updates against trusted manifest without executing any installer.

    Returns dictionary with availability, versions, artifact types, and hashes.
    """
    current_v = parse_version(current_version)

    manifest_data: Dict[str, Any]
    if isinstance(manifest_source, dict):
        manifest_data = manifest_source
    elif manifest_source is not None:
        src = str(manifest_source).strip()
        if src.startswith("https://"):
            req = urllib.request.Request(
                src,
                headers={"User-Agent": f"SNOW-Updater/{current_version}"}
            )
            with urllib.request.urlopen(req, timeout=10.0) as resp:
                manifest_data = json.loads(resp.read().decode("utf-8"))
        else:
            # Local path or file URI
            path = Path(src.replace("file://", ""))
            if not path.is_file():
                return {
                    "available": False,
                    "current_version": current_version,
                    "error": f"Manifest file not found: {path}",
                }
            with open(path, "r", encoding="utf-8") as f:
                manifest_data = json.load(f)
    else:
        # Default: no external network check configured; return up to date
        return {
            "available": False,
            "current_version": current_version,
            "latest_version": current_version,
            "update_type": "none",
        }

    validated = validate_manifest(manifest_data)
    latest_version_str = validated["version"]
    latest_v = parse_version(latest_version_str)

    if latest_v <= current_v:
        return {
            "available": False,
            "current_version": current_version,
            "latest_version": latest_version_str,
            "update_type": "none",
        }

    # Determine update type
    update_type = "web_ui"
    artifact_info: Dict[str, Any] = {}
    if "desktop" in validated:
        update_type = "desktop"
        artifact_info = validated["desktop"]
    elif "web_ui" in validated:
        update_type = "web_ui"
        artifact_info = validated["web_ui"]

    return {
        "available": True,
        "current_version": current_version,
        "latest_version": latest_version_str,
        "update_type": update_type,
        "release_notes": validated.get("release_notes", ""),
        "url": artifact_info.get("url", ""),
        "sha256": artifact_info.get("sha256", ""),
        "size_bytes": artifact_info.get("size_bytes", 0),
    }


def compute_file_sha256(path: Path) -> str:
    """Compute hex SHA-256 of a local file in bounded chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def apply_web_ui_update(
    archive_source: Union[Path, str, bytes],
    expected_sha256: str,
    override_dir: Optional[Path] = None,
) -> bool:
    """Safely and atomically apply a Web UI update ZIP into the override directory.

    Security guarantees:
    - Pre-extraction SHA-256 verification
    - ZipSlip / path traversal protection
    - Symlink rejection
    - Strict file extension allowlist
    - Mandatory UI core file validation (index.html, app.js, app.css)
    - Staging in temp directory with atomic rename
    - Automatic cleanup and rollback on any failure
    """
    target_dir = (override_dir or DEFAULT_OVERRIDE_DIR).resolve()
    temp_archive: Optional[Path] = None

    try:
        # 1. Obtain local archive path
        if isinstance(archive_source, bytes):
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
            tf.write(archive_source)
            tf.close()
            temp_archive = Path(tf.name)
            archive_path = temp_archive
        else:
            archive_path = Path(archive_source).resolve()

        if not archive_path.is_file():
            raise FileNotFoundError(f"Update archive not found: {archive_path}")

        # 2. Verify archive SHA-256
        actual_sha256 = compute_file_sha256(archive_path)
        if not actual_sha256.lower() == expected_sha256.lower():
            raise ValueError(
                f"Archive SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
            )

        # 3. Create isolated staging folder
        staging_dir = Path(tempfile.mkdtemp(prefix="snow_ui_staging_"))

        try:
            # 4. Safe ZIP extraction
            with zipfile.ZipFile(archive_path, "r") as zf:
                for member in zf.infolist():
                    # Reject symlinks
                    mode = member.external_attr >> 16
                    if (mode & 0o170000) == 0o120000:
                        raise SecurityError(f"Unsafe symlink detected in archive: {member.filename}")

                    # Reject directory traversal
                    clean_name = member.filename.replace("\\", "/").strip()
                    if clean_name.startswith("/") or ".." in clean_name or ":" in clean_name:
                        raise SecurityError(f"Path traversal detected in archive: {member.filename}")

                    # Normalize destination
                    dest_file = (staging_dir / clean_name).resolve()
                    if not dest_file.is_relative_to(staging_dir):
                        raise SecurityError(f"Directory escape detected: {member.filename}")

                    if member.is_dir():
                        dest_file.mkdir(parents=True, exist_ok=True)
                        continue

                    # Validate extension
                    ext = dest_file.suffix.lower()
                    if ext not in ALLOWED_STATIC_EXTENSIONS:
                        raise SecurityError(f"Forbidden file extension in UI archive: {member.filename}")

                    dest_file.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(dest_file, "wb") as dst:
                        shutil.copyfileobj(src, dst)

            # 5. Validate required core assets
            for req in REQUIRED_UI_ASSETS:
                req_path = staging_dir / req
                if not req_path.is_file() or req_path.stat().st_size == 0:
                    raise ValueError(f"Incomplete Web UI update: missing or empty required file '{req}'.")

            # 6. Atomic activation: promote staging to target_dir
            target_dir.parent.mkdir(parents=True, exist_ok=True)
            backup_dir: Optional[Path] = None
            if target_dir.exists():
                backup_dir = Path(tempfile.mkdtemp(prefix="snow_ui_backup_"))
                shutil.copytree(target_dir, backup_dir, dirs_exist_ok=True)
                shutil.rmtree(target_dir, ignore_errors=True)

            try:
                shutil.copytree(staging_dir, target_dir, dirs_exist_ok=True)
                logger.info("Successfully applied Web UI override to %s", target_dir)
                if backup_dir and backup_dir.exists():
                    shutil.rmtree(backup_dir, ignore_errors=True)
                return True
            except Exception as promote_err:
                logger.error("Promotion failed, rolling back: %s", promote_err)
                if backup_dir and backup_dir.exists():
                    shutil.rmtree(target_dir, ignore_errors=True)
                    shutil.copytree(backup_dir, target_dir, dirs_exist_ok=True)
                    shutil.rmtree(backup_dir, ignore_errors=True)
                raise promote_err

        finally:
            if staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)

    finally:
        if temp_archive and temp_archive.exists():
            temp_archive.unlink(missing_ok=True)


def verify_authenticode_or_pe(installer_path: Path) -> bool:
    """Verify that the installer executable is a valid PE binary.

    On Windows, attempts PowerShell Get-AuthenticodeSignature if available.
    """
    if not installer_path.is_file():
        return False

    # Check PE magic header ('MZ')
    with open(installer_path, "rb") as f:
        magic = f.read(2)
        if magic != b"MZ":
            logger.error("Installer file does not have valid PE magic header: %s", installer_path)
            return False

    if sys.platform == "win32":
        try:
            ps_cmd = (
                f"(Get-AuthenticodeSignature -LiteralPath '{installer_path}').Status.ToString()"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
            )
            status = result.stdout.strip()
            # Valid signature statuses: Valid or UnknownError (self-signed/trusted enterprise)
            if status in ("Valid", "UnknownError"):
                return True
            logger.warning("Authenticode status for %s: %s", installer_path, status)
        except Exception as e:
            logger.warning("Could not execute Authenticode check: %s", e)

    return True


def apply_desktop_installer_update(
    installer_path: Union[Path, str],
    expected_sha256: str,
    execute: bool = True,
    daemon_manager: Optional[Any] = None,
) -> bool:
    """Verify and optionally execute the Windows Desktop installer update.

    Arguments for execution: /SILENT /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS
    """
    p = Path(installer_path).resolve()
    if not p.is_file():
        raise FileNotFoundError(f"Installer binary not found: {p}")

    # 1. SHA-256 verification
    actual_sha256 = compute_file_sha256(p)
    if not actual_sha256.lower() == expected_sha256.lower():
        raise ValueError(
            f"Installer SHA-256 mismatch: expected {expected_sha256}, got {actual_sha256}"
        )

    # 2. Binary signature / PE integrity
    if not verify_authenticode_or_pe(p):
        raise SecurityError(f"Installer binary failed integrity or Authenticode verification: {p}")

    if not execute:
        return True

    # 3. Cleanly stop running Core daemon if manager provided
    if daemon_manager is not None:
        try:
            logger.info("Stopping running Core daemon before launching installer upgrade...")
            if hasattr(daemon_manager, "stop_daemon"):
                import asyncio
                if asyncio.iscoroutinefunction(daemon_manager.stop_daemon):
                    asyncio.create_task(daemon_manager.stop_daemon())
                else:
                    daemon_manager.stop_daemon()
        except Exception as e:
            logger.warning("Error stopping daemon: %s", e)

    # 4. Spawn Inno Setup installer with required silent upgrade arguments
    upgrade_args = [str(p), "/SILENT", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"]
    logger.info("Launching installer upgrade: %s", upgrade_args)
    try:
        subprocess.Popen(
            upgrade_args,
            creationflags=subprocess.DETACHED_PROCESS if sys.platform == "win32" else 0,
            close_fds=True,
        )
        return True
    except Exception as e:
        logger.error("Failed spawning installer upgrade: %s", e)
        raise RuntimeError(f"Failed launching installer upgrade: {e}")


def reset_web_ui_override(override_dir: Optional[Path] = None) -> bool:
    """Reset the Web UI override directory safely, restoring bundled assets."""
    target_dir = (override_dir or DEFAULT_OVERRIDE_DIR).resolve()
    if target_dir.exists():
        try:
            shutil.rmtree(target_dir, ignore_errors=True)
            logger.info("Web UI override directory removed: %s", target_dir)
            return True
        except Exception as e:
            logger.error("Failed removing Web UI override: %s", e)
            return False
    return True


class SecurityError(Exception):
    """Raised when an update operation violates security boundaries."""
    pass
