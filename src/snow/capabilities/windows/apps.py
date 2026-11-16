"""Allowlisted Windows application launcher capability for SNOW.

Enforces strict allowlist containing only authorized, benign Windows utility aliases.
Rejects arbitrary executables, shell commands, shell metacharacters, and command-line arguments.
Launches applications non-blockingly using subprocess.Popen with shell=False.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
import subprocess
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Canonical allowlist of permitted Windows application aliases and their candidate locations.
# Only trusted fixed paths under SystemRoot are permitted.
SYSTEM_ROOT = Path(os.environ.get("SystemRoot", r"C:\Windows"))

ALLOWLIST_CANDIDATES: dict[str, list[Path]] = {
    "notepad": [
        SYSTEM_ROOT / "System32" / "notepad.exe",
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
}


class WindowsAppLauncher:
    """Manages secure launching of allowlisted Windows desktop applications."""

    def __init__(self, custom_allowlist: Optional[dict[str, list[Path]]] = None) -> None:
        self._allowlist = custom_allowlist if custom_allowlist is not None else ALLOWLIST_CANDIDATES

    @property
    def allowed_apps(self) -> list[str]:
        """Return the sorted list of authorized application aliases."""
        return sorted(self._allowlist.keys())

    def launch_app_sync(self, app_name: str) -> dict[str, Any]:
        """Synchronously validate alias and launch the application with shell=False.

        Args:
            app_name: Allowlisted application alias (e.g. 'notepad', 'calc').

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
        target_path: Optional[Path] = None
        for candidate in self._allowlist[canonical_alias]:
            if candidate.exists() and candidate.is_file():
                target_path = candidate
                break

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
            logger.info("Launched allowlisted app '%s' [pid=%d, path=%s]",
                        canonical_alias, proc.pid, target_path)
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
