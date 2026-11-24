"""Subprocess execution utilities ensuring headless execution on Windows without console flashes."""

from __future__ import annotations

import subprocess
import sys
from typing import Any, Dict


def get_no_window_subprocess_kwargs(extra_creationflags: int = 0) -> Dict[str, Any]:
    """Return creationflags and startupinfo dictionary for headless subprocess execution on Windows.

    On Windows (sys.platform == "win32"), injects:
    - creationflags with CREATE_NO_WINDOW and any caller-specified extra flags
    - STARTUPINFO configured with STARTF_USESHOWWINDOW and SW_HIDE

    On non-Windows platforms, returns an empty dictionary (or only extra_creationflags if non-zero).
    """
    if sys.platform != "win32":
        return {"creationflags": extra_creationflags} if extra_creationflags else {}

    flags = extra_creationflags
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        flags |= subprocess.CREATE_NO_WINDOW
    else:
        flags |= 0x08000000

    kwargs: Dict[str, Any] = {"creationflags": flags}
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        startupinfo.wShowWindow = subprocess.SW_HIDE
        kwargs["startupinfo"] = startupinfo
    except Exception:
        pass
    return kwargs
