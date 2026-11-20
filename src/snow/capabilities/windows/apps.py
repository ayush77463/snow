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
import sys
from typing import Any, Dict, List, Optional
import urllib.parse

from snow.security.context import ExecutionContext, ExecutionPrincipal

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


def _is_interactive_window_station() -> bool:
    """Verify current process is attached to an interactive desktop window station (WinSta0)."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes
        user32 = ctypes.windll.user32
        hwinsta = user32.GetProcessWindowStation()
        if not hwinsta:
            return False
        # UOI_NAME = 2
        buf = ctypes.create_unicode_buffer(256)
        length = ctypes.c_ulong()
        res = user32.GetUserObjectInformationW(
            hwinsta, 2, buf, ctypes.sizeof(buf), ctypes.byref(length)
        )
        if res and "winsta0" in buf.value.lower():
            return True
        return False
    except Exception:
        return True


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
        if alias == "wt":
            # 1. shutil.which("wt.exe") or shutil.which("wt")
            which_hit = shutil.which("wt.exe") or shutil.which("wt")
            if which_hit:
                p = Path(which_hit).resolve()
                try:
                    if p.is_file():
                        return p
                except Exception:
                    pass
            # 2. %LOCALAPPDATA%\Microsoft\WindowsApps\wt.exe
            candidate = LOCAL_APPDATA / "Microsoft" / "WindowsApps" / "wt.exe"
            try:
                if candidate.exists() and candidate.is_file():
                    return candidate
            except Exception:
                pass
            return None

        # 1. Check fixed candidate paths first
        candidates = self._allowlist.get(alias, [])
        for candidate in candidates:
            try:
                if candidate.exists() and candidate.is_file():
                    return candidate
            except Exception:
                continue

        # 2. Check PATH via shutil.which for developer apps (code, powershell, etc.)
        which_hit = shutil.which(alias)
        if which_hit:
            p = Path(which_hit).resolve()
            if p.is_file():
                return p

        return None

    def launch_app_sync(
        self, app_name: str, ctx: Optional[ExecutionContext] = None
    ) -> dict[str, Any]:
        """Synchronously validate alias and launch the application with shell=False.

        Args:
            app_name: Allowlisted application alias or owner custom executable path.
            ctx: Immutable execution context (defaults to AI_MCP).

        Returns:
            Structured dictionary indicating launch outcome, PID, and status.
        """
        ctx = ctx or ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="default")

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

        target_path: Optional[Path] = None

        # 1. Check against strict allowlist first
        if canonical_alias in self._allowlist:
            target_path = self._resolve_app_executable(canonical_alias)
            if target_path is None and canonical_alias != "wt":
                return {
                    "success": False,
                    "status": "APP_NOT_FOUND",
                    "error": (
                        f"Application '{canonical_alias}' is allowlisted but its executable "
                        f"was not found on this Windows system."
                    ),
                }
        else:
            # 2. If not allowlisted, check if OWNER_MANUAL supplied a valid custom executable
            if ctx.principal == ExecutionPrincipal.OWNER_MANUAL:
                try:
                    candidate = Path(app_name.strip()).resolve()
                    if candidate.is_file() and candidate.suffix.lower() == ".exe":
                        target_path = candidate
                    else:
                        return {
                            "success": False,
                            "status": "APP_NOT_FOUND",
                            "error": f"Custom executable path not found or invalid: '{app_name}'.",
                        }
                except Exception as exc:
                    return {
                        "success": False,
                        "status": "INVALID_PATH",
                        "error": f"Invalid custom executable path syntax: {exc}",
                    }
            else:
                return {
                    "success": False,
                    "status": "APP_NOT_ALLOWED",
                    "error": (
                        f"Application '{app_name}' is not authorized. "
                        f"Allowed applications: {', '.join(self.allowed_apps)}."
                    ),
                }

        # Check interactive window station for GUI application launches
        if sys.platform == "win32" and not _is_interactive_window_station():
            return {
                "success": False,
                "status": "NON_INTERACTIVE_SESSION",
                "error": "Cannot launch graphical desktop applications in a non-interactive Windows session.",
            }

        try:
            # On Windows, Windows Terminal (wt.exe) is an execution alias that requires
            # ShellExecute with SW_SHOWNORMAL to attach to the desktop shell properly.
            if sys.platform == "win32" and canonical_alias == "wt":
                import ctypes
                from ctypes import wintypes
                shell32 = ctypes.windll.shell32
                shell32.ShellExecuteW.restype = ctypes.c_void_p
                shell32.ShellExecuteW.argtypes = [
                    wintypes.HWND, wintypes.LPCWSTR, wintypes.LPCWSTR,
                    wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_int
                ]
                SW_SHOWNORMAL = 1
                rc = 0
                wt_path = target_path or self._resolve_app_executable("wt")
                if wt_path and wt_path.exists():
                    try:
                        res = shell32.ShellExecuteW(None, "open", str(wt_path), None, None, SW_SHOWNORMAL)
                        rc = res if res is not None else 0
                    except Exception as shell_err:
                        logger.debug("ShellExecuteW failed for wt path: %s", shell_err)
                if rc <= 32:
                    apps_folder_wt = r"shell:AppsFolder\Microsoft.WindowsTerminal_8wekyb3d8bbwe!App"
                    try:
                        res = shell32.ShellExecuteW(None, "open", apps_folder_wt, None, None, SW_SHOWNORMAL)
                        rc = res if res is not None else 0
                    except Exception as shell_err:
                        logger.debug("ShellExecuteW failed for AppsFolder wt: %s", shell_err)

                if rc > 32:
                    logger.info("Launched Windows Terminal via ShellExecuteW (rc=%d)", rc)
                    return {
                        "success": True,
                        "status": "SUCCESS",
                        "app_name": "wt",
                        "pid": 0,
                        "executable": str(wt_path) if wt_path else "wt",
                        "message": "Successfully launched Windows Terminal.",
                    }
                else:
                    logger.warning("ShellExecuteW failed for wt (rc=%d)", rc)
                    return {
                        "success": False,
                        "status": "APP_NOT_FOUND" if wt_path is None else "APP_LAUNCH_FAILED",
                        "error": (
                            f"Failed launching Windows Terminal via ShellExecuteW (return code {rc})."
                        ),
                    }

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
                "Launched app '%s' [pid=%d, path=%s, principal=%s]",
                canonical_alias,
                proc.pid,
                target_path,
                ctx.principal,
            )
            return {
                "success": True,
                "status": "SUCCESS",
                "app_name": canonical_alias,
                "pid": proc.pid,
                "executable": str(target_path),
                "message": f"Successfully launched {canonical_alias} (PID {proc.pid}).",
            }
        except (PermissionError, OSError) as osc_err:
            is_perm = isinstance(osc_err, PermissionError) or getattr(osc_err, "winerror", None) == 5
            status = "OS_PERMISSION_DENIED" if is_perm else "APP_LAUNCH_FAILED"
            logger.warning("OS error launching '%s': %s", canonical_alias, osc_err)
            return {
                "success": False,
                "status": status,
                "error": f"OS permission denied: {osc_err}" if is_perm else f"OS error launching '{canonical_alias}': {osc_err}",
            }
        except Exception as exc:
            logger.error("Unexpected error launching '%s': %s", canonical_alias, exc, exc_info=True)
            return {
                "success": False,
                "status": "APP_LAUNCH_FAILED",
                "error": f"Failed launching '{canonical_alias}': {exc}",
            }

    async def launch_app(
        self, app_name: str, ctx: Optional[ExecutionContext] = None
    ) -> dict[str, Any]:
        """Asynchronously launch allowlisted application on a worker thread."""
        return await asyncio.to_thread(self.launch_app_sync, app_name, ctx)

    def open_target_sync(
        self, target: str, ctx: Optional[ExecutionContext] = None
    ) -> dict[str, Any]:
        """Open an authorized URL (http/https) or non-executable user document."""
        ctx = ctx or ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="default")
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

    async def open_target(
        self, target: str, ctx: Optional[ExecutionContext] = None
    ) -> dict[str, Any]:
        """Asynchronously open authorized target on a worker thread."""
        return await asyncio.to_thread(self.open_target_sync, target, ctx)
