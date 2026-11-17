"""Allowlisted Windows application launcher capability for SNOW.

Enforces strict allowlist containing authorized Windows utilities, developer tools,
browsers, and terminals. Rejects arbitrary executables, shell commands, shell
metacharacters, and unauthorized command-line arguments.

Launches applications non-blockingly using subprocess.Popen with shell=False.
Supports authorized URL opening (http/https only) and safe file opening with
file validation.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Optional
import urllib.parse

logger = logging.getLogger(__name__)

SYSTEM_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))
PROGRAM_FILES = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
PROGRAM_FILES_X86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
LOCAL_APPDATA = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))

# Base allowlist candidates for fixed-location system utilities
ALLOWLIST_CANDIDATES: dict[str, list[Path]] = {
    "notepad": [
        SYSTEM_ROOT / "System32" / "notepad.exe",
        SYSTEM_ROOT / "notepad.exe",
    ],
    "calc": [
        SYSTEM_ROOT / "System32" / "calc.exe",
    ],
    "explorer": [
        SYSTEM_ROOT / "explorer.exe",
    ],
    "taskmgr": [
        SYSTEM_ROOT / "System32" / "Taskmgr.exe",
    ],
    "mspaint": [
        SYSTEM_ROOT / "System32" / "mspaint.exe",
        SYSTEM_ROOT / "mspaint.exe",
    ],
    "powershell": [
        SYSTEM_ROOT / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
    ],
    "wt": [
        LOCAL_APPDATA / "Microsoft" / "WindowsApps" / "wt.exe",
    ],
    "code": [
        LOCAL_APPDATA / "Programs" / "Microsoft VS Code" / "Code.exe",
        PROGRAM_FILES / "Microsoft VS Code" / "Code.exe",
    ],
    "chrome": [
        PROGRAM_FILES / "Google" / "Chrome" / "Application" / "chrome.exe",
        PROGRAM_FILES_X86 / "Google" / "Chrome" / "Application" / "chrome.exe",
        LOCAL_APPDATA / "Google" / "Chrome" / "Application" / "chrome.exe",
    ],
    "msedge": [
        PROGRAM_FILES_X86 / "Microsoft" / "Edge" / "Application" / "msedge.exe",
        PROGRAM_FILES / "Microsoft" / "Edge" / "Application" / "msedge.exe",
    ],
}

ALLOWED_URL_SCHEMES = {"http", "https"}
FORBIDDEN_FILE_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi", ".reg",
    ".secret", ".key", ".crt", ".db", ".db-wal", ".db-shm",
}


class WindowsAppLauncher:
    """Manages secure launching of allowlisted Windows desktop applications and targets."""

    def __init__(self, custom_allowlist: Optional[dict[str, list[Path]]] = None) -> None:
        self._allowlist = custom_allowlist if custom_allowlist is not None else ALLOWLIST_CANDIDATES

    @property
    def allowed_apps(self) -> list[str]:
        """Return the sorted list of authorized application aliases."""
        return sorted(self._allowlist.keys())

    def _resolve_app_executable(self, alias: str) -> Optional[Path]:
        """Resolve the executable path for a given alias from candidates or PATH."""
        # 1. Check fixed candidate paths first
        candidates = self._allowlist.get(alias, [])
        for candidate in candidates:
            try:
                if candidate.exists() and candidate.is_file():
                    return candidate
            except Exception:
                continue

        # 2. Check PATH via shutil.which for developer apps (code, wt, powershell, etc.)
        which_hit = shutil.which(alias)
        if which_hit:
            p = Path(which_hit).resolve()
            if p.is_file():
                return p

        return None

    def launch_app_sync(self, app_name: str) -> dict[str, Any]:
        """Synchronously validate alias and launch the application with shell=False.

        Args:
            app_name: Allowlisted application alias (e.g. 'notepad', 'calc', 'code').

        Returns:
            Structured dictionary indicating launch outcome, PID, and status.
        """
        if not app_name or not isinstance(app_name, str):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Application name must be a non-empty string.",
            }

        # Normalize alias
        canonical_alias = app_name.strip().lower()

        # Strip .exe if user appended it (e.g. 'notepad.exe' -> 'notepad')
        if canonical_alias.endswith(".exe"):
            canonical_alias = canonical_alias[:-4]

        # Check against strict allowlist
        if canonical_alias not in self._allowlist:
            return {
                "success": False,
                "status": "APP_NOT_ALLOWED",
                "error": (
                    f"Application '{app_name}' is not authorized. "
                    f"Allowed applications: {', '.join(self.allowed_apps)}."
                ),
            }

        # Resolve executable candidate
        target_path = self._resolve_app_executable(canonical_alias)
        if target_path is None:
            return {
                "success": False,
                "status": "APP_NOT_FOUND",
                "error": (
                    f"Application '{canonical_alias}' is allowlisted but its executable "
                    f"was not found on this Windows system."
                ),
            }

        try:
            # Launch via subprocess.Popen with shell=False and no user arguments
            proc = subprocess.Popen(
                [str(target_path)],
                shell=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            logger.info(
                "Launched allowlisted app '%s' [pid=%d, path=%s]",
                canonical_alias,
                proc.pid,
                target_path,
            )
            return {
                "success": True,
                "status": "SUCCESS",
                "app_name": canonical_alias,
                "pid": proc.pid,
                "executable": str(target_path),
                "message": f"Successfully launched {canonical_alias} (PID {proc.pid}).",
            }
        except OSError as osc_err:
            logger.warning("OS error launching '%s': %s", canonical_alias, osc_err)
            return {
                "success": False,
                "status": "APP_LAUNCH_FAILED",
                "error": f"OS error launching '{canonical_alias}': {osc_err}",
            }
        except Exception as exc:
            logger.error("Unexpected error launching '%s': %s", canonical_alias, exc, exc_info=True)
            return {
                "success": False,
                "status": "APP_LAUNCH_FAILED",
                "error": f"Failed launching '{canonical_alias}': {exc}",
            }

    async def launch_app(self, app_name: str) -> dict[str, Any]:
        """Asynchronously launch allowlisted application on a worker thread."""
        return await asyncio.to_thread(self.launch_app_sync, app_name)

    def open_target_sync(self, target: str) -> dict[str, Any]:
        """Open an authorized URL (http/https) or non-executable user document.

        Args:
            target: A web URL or valid document file path.

        Returns:
            Structured dictionary indicating opening outcome.
        """
        if not target or not isinstance(target, str):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Target must be a non-empty string.",
            }

        cleaned = target.strip()

        # 1. URL Opening check
        parsed = urllib.parse.urlparse(cleaned)
        if parsed.scheme:
            if parsed.scheme.lower() not in ALLOWED_URL_SCHEMES:
                return {
                    "success": False,
                    "status": "URL_SCHEME_NOT_ALLOWED",
                    "error": f"URL scheme '{parsed.scheme}' is not allowed. Only HTTP and HTTPS are permitted.",
                }
            if not parsed.netloc:
                return {
                    "success": False,
                    "status": "INVALID_URL",
                    "error": "URL missing valid network location / domain.",
                }

            try:
                # Open with system default browser safely via explorer or os.startfile
                if hasattr(os, "startfile"):
                    os.startfile(cleaned)
                else:
                    subprocess.Popen(["explorer.exe", cleaned], shell=False)

                return {
                    "success": True,
                    "status": "SUCCESS",
                    "target_type": "url",
                    "target": cleaned,
                    "message": f"Successfully opened URL: {cleaned}",
                }
            except Exception as exc:
                return {
                    "success": False,
                    "status": "OPEN_FAILED",
                    "error": f"Failed opening URL: {exc}",
                }

        # 2. File target check
        try:
            target_path = Path(cleaned).resolve()
        except Exception as exc:
            return {
                "success": False,
                "status": "INVALID_PATH",
                "error": f"Invalid path syntax: {exc}",
            }

        if not target_path.exists():
            return {
                "success": False,
                "status": "FILE_NOT_FOUND",
                "error": f"Target file does not exist: '{cleaned}'",
            }

        # Forbid opening executable or script files directly
        if target_path.suffix.lower() in FORBIDDEN_FILE_EXTENSIONS:
            return {
                "success": False,
                "status": "FILE_TYPE_NOT_ALLOWED",
                "error": f"Opening executable or sensitive file types ({target_path.suffix}) is forbidden.",
            }

        # Forbid opening files inside sensitive dirs (like ~/.snow)
        home_snow = (Path.home() / ".snow").resolve()
        try:
            if target_path == home_snow or target_path.is_relative_to(home_snow):
                return {
                    "success": False,
                    "status": "PATH_NOT_ALLOWED",
                    "error": "Access to SNOW configuration directory is forbidden.",
                }
        except Exception:
            pass

        try:
            if hasattr(os, "startfile"):
                os.startfile(str(target_path))
            else:
                subprocess.Popen(["explorer.exe", str(target_path)], shell=False)

            return {
                "success": True,
                "status": "SUCCESS",
                "target_type": "file",
                "target": str(target_path),
                "message": f"Successfully opened file: {target_path.name}",
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "OPEN_FAILED",
                "error": f"Failed opening file: {exc}",
            }

    async def open_target(self, target: str) -> dict[str, Any]:
        """Asynchronously open authorized target on a worker thread."""
        return await asyncio.to_thread(self.open_target_sync, target)
