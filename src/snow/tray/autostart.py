r"""Autostart management for SNOW via Windows Registry (HKCU Run).

Manages automatic startup of the SNOW system tray companion upon user login:
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
Value name: 'SNOW'
Value data: command line to launch 'snow tray'
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
import sys
from typing import Optional

logger = logging.getLogger(__name__)

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
REG_VALUE_NAME = "SNOW"


def get_default_autostart_command() -> str:
    """Determine the canonical command line string to launch the SNOW tray companion."""
    # If running as a frozen executable (e.g. PyInstaller snow.exe or snow-tray.exe)
    if getattr(sys, "frozen", False) and hasattr(sys, "executable"):
        exe_path = Path(sys.executable).resolve()
        tray_exe = exe_path.parent / "snow-tray.exe"
        if tray_exe.is_file():
            return f'"{tray_exe}"'
        if exe_path.name.lower() == "snow-tray.exe":
            return f'"{exe_path}"'
        return f'"{exe_path}" tray'

    # If running in a virtual environment or Python interpreter
    python_exe = Path(sys.executable).resolve()
    return f'"{python_exe}" -m snow.cli tray'


def is_autostart_enabled() -> bool:
    """Check whether SNOW is currently configured to start on user login."""
    if sys.platform != "win32":
        return False

    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            RUN_KEY_PATH,
            0,
            winreg.KEY_READ,
        ) as key:
            val, _ = winreg.QueryValueEx(key, REG_VALUE_NAME)
            return bool(val and str(val).strip())
    except FileNotFoundError:
        return False
    except OSError as exc:
        logger.debug("Failed querying autostart registry key: %s", exc)
        return False


def set_autostart(enabled: bool, command: Optional[str] = None) -> bool:
    """Enable or disable autostart in the Windows Registry.

    Args:
        enabled: True to register SNOW in HKCU Run, False to remove it.
        command: Optional custom command line. If None, computes default.

    Returns:
        True if the operation succeeded, False otherwise.
    """
    if sys.platform != "win32":
        logger.warning("Autostart registry configuration is only supported on Windows.")
        return False

    try:
        import winreg
        if enabled:
            cmd = command or get_default_autostart_command()
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER,
                RUN_KEY_PATH,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(
                    key,
                    REG_VALUE_NAME,
                    0,
                    winreg.REG_SZ,
                    cmd,
                )
            logger.info("Configured SNOW autostart on login: %s", cmd)
            return True
        else:
            return remove_autostart()
    except OSError as exc:
        logger.error("Failed setting autostart in registry: %s", exc)
        return False


def remove_autostart() -> bool:
    """Remove the SNOW autostart entry from HKCU Run.

    Safe to invoke during uninstallation or when disabling autostart.
    """
    if sys.platform != "win32":
        return True

    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            RUN_KEY_PATH,
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            try:
                winreg.DeleteValue(key, REG_VALUE_NAME)
                logger.info("Removed SNOW autostart registry entry.")
                return True
            except FileNotFoundError:
                # Value was already not present
                return True
    except FileNotFoundError:
        # Key does not exist
        return True
    except OSError as exc:
        logger.error("Failed removing autostart registry value: %s", exc)
        return False
