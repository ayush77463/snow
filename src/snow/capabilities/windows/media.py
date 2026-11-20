"""Windows media playback and volume control using standard ctypes Win32 key events.

Implements Phase 21 Pillar 3C:
- Uses standard ctypes user32.keybd_event without third-party audio dependencies.
- Translates virtual key events:
  - VK_MEDIA_PLAY_PAUSE (0xB3)
  - VK_MEDIA_NEXT_TRACK (0xB0)
  - VK_MEDIA_PREV_TRACK (0xB1)
  - VK_VOLUME_MUTE (0xAD)
  - VK_VOLUME_DOWN (0xAE)
  - VK_VOLUME_UP (0xAF)
"""

from __future__ import annotations

import ctypes
import logging
import sys
from typing import Any, Dict

logger = logging.getLogger(__name__)

# Virtual Key Codes for Windows Multimedia Controls
VK_VOLUME_MUTE: int = 0xAD
VK_VOLUME_DOWN: int = 0xAE
VK_VOLUME_UP: int = 0xAF
VK_MEDIA_NEXT_TRACK: int = 0xB0
VK_MEDIA_PREV_TRACK: int = 0xB1
VK_MEDIA_STOP: int = 0xB2
VK_MEDIA_PLAY_PAUSE: int = 0xB3

KEYEVENTF_KEYUP: int = 0x0002

ACTION_TO_VK: dict[str, int] = {
    "play_pause": VK_MEDIA_PLAY_PAUSE,
    "play": VK_MEDIA_PLAY_PAUSE,
    "pause": VK_MEDIA_PLAY_PAUSE,
    "next_track": VK_MEDIA_NEXT_TRACK,
    "next": VK_MEDIA_NEXT_TRACK,
    "prev_track": VK_MEDIA_PREV_TRACK,
    "previous": VK_MEDIA_PREV_TRACK,
    "prev": VK_MEDIA_PREV_TRACK,
    "volume_up": VK_VOLUME_UP,
    "vol_up": VK_VOLUME_UP,
    "volume_down": VK_VOLUME_DOWN,
    "vol_down": VK_VOLUME_DOWN,
    "mute": VK_VOLUME_MUTE,
    "unmute": VK_VOLUME_MUTE,
    "toggle_mute": VK_VOLUME_MUTE,
}


class WindowsMediaController:
    """Controls Windows media playback and volume using user32 keybd_event."""

    def __init__(self) -> None:
        self.is_windows = sys.platform == "win32"

    def send_key(self, vk_code: int) -> bool:
        """Simulate a key press and release for a virtual key code."""
        if not self.is_windows:
            logger.debug("Simulated Windows media key event 0x%02X on non-Windows host.", vk_code)
            return True

        try:
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            # Explicit 64-bit-compatible Win32 keybd_event ABI declaration
            user32.keybd_event.argtypes = [
                ctypes.c_ubyte,
                ctypes.c_ubyte,
                wintypes.DWORD,
                ctypes.c_size_t,
            ]
            user32.keybd_event.restype = None

            # Key down (unsigned byte prevents signed overflow on 0xAD-0xB3)
            user32.keybd_event(
                ctypes.c_ubyte(vk_code),
                ctypes.c_ubyte(0),
                wintypes.DWORD(0),
                ctypes.c_size_t(0),
            )
            # Key up
            user32.keybd_event(
                ctypes.c_ubyte(vk_code),
                ctypes.c_ubyte(0),
                wintypes.DWORD(KEYEVENTF_KEYUP),
                ctypes.c_size_t(0),
            )
            return True
        except Exception as exc:
            logger.error("Failed sending Win32 media key 0x%02X: %s", vk_code, exc)
            return False

    def handle_action(self, action: str) -> dict[str, Any]:
        """Dispatch a validated media control action.

        Returns structured result indicating success, canonical action, and platform.
        """
        if not action or not isinstance(action, str):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Media action must be a non-empty string.",
            }

        canonical = action.strip().lower()
        vk = ACTION_TO_VK.get(canonical)
        if vk is None:
            return {
                "success": False,
                "status": "UNSUPPORTED_MEDIA_ACTION",
                "error": f"Media action '{action}' is not supported. Supported: {sorted(list(ACTION_TO_VK.keys()))}",
            }

        ok = self.send_key(vk)
        if ok:
            return {
                "success": True,
                "status": "SUCCESS",
                "action": canonical,
                "platform": "windows",
            }
        return {
            "success": False,
            "status": "KEY_DISPATCH_FAILED",
            "action": canonical,
            "error": "Failed dispatching keybd_event to Windows user32.",
        }
