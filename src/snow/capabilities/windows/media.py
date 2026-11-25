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
import math
import sys
import uuid
from typing import Any, Dict, Optional

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
    "stop": VK_MEDIA_STOP,
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
    "volume_mute": VK_VOLUME_MUTE,
}

CLSCTX_ALL = 23
E_RENDER = 0
E_CONSOLE = 1
_CLSID_MM_DEVICE_ENUMERATOR = "{BCDE0395-E52F-467C-8E3D-C4579291692E}"
_IID_IMM_DEVICE_ENUMERATOR = "{A95664D2-9614-4F35-A746-DE8DB63617E6}"
_IID_IAUDIO_ENDPOINT_VOLUME = "{5CDF2C82-841E-4546-9722-0CF74078229A}"


class _COMGUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    @classmethod
    def from_str(cls, guid_str: str) -> "_COMGUID":
        g = cls()
        ctypes.memmove(ctypes.byref(g), uuid.UUID(guid_str).bytes_le, 16)
        return g


def _with_endpoint_volume(callback):
    """Acquire IAudioEndpointVolume on Windows default render endpoint and run callback."""
    from ctypes import POINTER, c_void_p, c_uint, wintypes

    ole32 = ctypes.windll.ole32
    co_init_hr = ole32.CoInitialize(None)
    need_uninit = co_init_hr in (0, 1)  # S_OK or S_FALSE

    def _vtbl(ptr):
        return ctypes.cast(ctypes.cast(ptr, POINTER(c_void_p))[0], POINTER(c_void_p))

    enum_p = c_void_p()
    dev_p = c_void_p()
    vol_p = c_void_p()
    try:
        clsid_mm = _COMGUID.from_str(_CLSID_MM_DEVICE_ENUMERATOR)
        iid_enum = _COMGUID.from_str(_IID_IMM_DEVICE_ENUMERATOR)
        iid_vol = _COMGUID.from_str(_IID_IAUDIO_ENDPOINT_VOLUME)

        hr = ole32.CoCreateInstance(
            ctypes.byref(clsid_mm), None, CLSCTX_ALL, ctypes.byref(iid_enum), ctypes.byref(enum_p)
        )
        if hr != 0 or not enum_p.value:
            raise OSError(f"CoCreateInstance(MMDeviceEnumerator) failed: 0x{hr & 0xFFFFFFFF:08X}")

        ev = _vtbl(enum_p)
        get_default = ctypes.WINFUNCTYPE(ctypes.c_long, c_void_p, c_uint, c_uint, POINTER(c_void_p))(ev[4])
        hr = get_default(enum_p, E_RENDER, E_CONSOLE, ctypes.byref(dev_p))
        if hr != 0 or not dev_p.value:
            raise OSError(f"GetDefaultAudioEndpoint failed: 0x{hr & 0xFFFFFFFF:08X}")

        dv = _vtbl(dev_p)
        activate = ctypes.WINFUNCTYPE(
            ctypes.c_long, c_void_p, POINTER(_COMGUID), wintypes.DWORD, c_void_p, POINTER(c_void_p)
        )(dv[3])
        hr = activate(dev_p, ctypes.byref(iid_vol), CLSCTX_ALL, None, ctypes.byref(vol_p))
        if hr != 0 or not vol_p.value:
            raise OSError(f"Activate(IAudioEndpointVolume) failed: 0x{hr & 0xFFFFFFFF:08X}")

        vv = _vtbl(vol_p)
        return callback(vol_p, vv)
    finally:
        for p in (vol_p, dev_p, enum_p):
            if p and p.value:
                try:
                    vt = _vtbl(p)
                    ctypes.WINFUNCTYPE(wintypes.ULONG, c_void_p)(vt[2])(p)
                except Exception:
                    pass
        if need_uninit:
            try:
                ole32.CoUninitialize()
            except Exception:
                pass


class WindowsMediaController:
    """Controls Windows media playback and bounded system audio volume."""

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

    def set_volume_percent(self, level: int) -> bool:
        """Set system master audio endpoint volume scalar (0..100) on Windows."""
        bounded = max(0, min(100, int(level)))
        if not self.is_windows:
            logger.debug("Simulated Windows volume_set=%d on non-Windows host.", bounded)
            return True

        scalar = float(bounded) / 100.0

        def _apply(vol_p, vv) -> bool:
            set_scalar = ctypes.WINFUNCTYPE(
                ctypes.c_long, ctypes.c_void_p, ctypes.c_float, ctypes.c_void_p
            )(vv[7])
            hr = set_scalar(vol_p, ctypes.c_float(scalar), None)
            if hr != 0:
                raise OSError(f"SetMasterVolumeLevelScalar failed: 0x{hr & 0xFFFFFFFF:08X}")
            return True

        try:
            return bool(_with_endpoint_volume(_apply))
        except Exception as exc:
            logger.error("Failed setting Windows master volume to %d%%: %s", bounded, exc)
            return False

    def get_volume_state(self) -> dict[str, Any]:
        """Query current master audio endpoint volume percent and mute flag."""
        if not self.is_windows:
            return {"available": False, "volume_percent": None, "muted": None}

        def _query(vol_p, vv) -> dict[str, Any]:
            from ctypes import POINTER, c_float, wintypes
            level = c_float()
            muted = wintypes.BOOL()
            hr_v = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, POINTER(c_float))(vv[9])(
                vol_p, ctypes.byref(level)
            )
            hr_m = ctypes.WINFUNCTYPE(ctypes.c_long, ctypes.c_void_p, POINTER(wintypes.BOOL))(vv[15])(
                vol_p, ctypes.byref(muted)
            )
            if hr_v != 0 or hr_m != 0:
                return {"available": False, "volume_percent": None, "muted": None}
            return {
                "available": True,
                "volume_percent": max(0, min(100, int(round(level.value * 100.0)))),
                "muted": bool(muted.value),
            }

        try:
            return _with_endpoint_volume(_query)
        except Exception as exc:
            logger.debug("Could not query Windows audio endpoint state: %s", exc)
            return {"available": False, "volume_percent": None, "muted": None}

    def handle_action(self, action: str, value: Optional[Any] = None) -> dict[str, Any]:
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
        if canonical in ("volume_set", "volume"):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return {
                    "success": False,
                    "status": "INVALID_VOLUME_LEVEL",
                    "error": "Volume level must be a numeric value between 0 and 100.",
                }
            numeric_val = float(value)
            if math.isnan(numeric_val) or math.isinf(numeric_val) or numeric_val < 0.0 or numeric_val > 100.0:
                return {
                    "success": False,
                    "status": "INVALID_VOLUME_LEVEL",
                    "error": "Volume level must be between 0 and 100.",
                }
            level = int(round(numeric_val))
            ok = self.set_volume_percent(level)
            if ok:
                state = self.get_volume_state()
                return {
                    "success": True,
                    "status": "SUCCESS",
                    "action": "volume_set",
                    "volume_percent": state.get("volume_percent") if state.get("available") else level,
                    "muted": state.get("muted"),
                    "platform": "windows",
                }
            return {
                "success": False,
                "status": "VOLUME_SET_FAILED",
                "action": "volume_set",
                "error": "Failed setting Windows system audio volume.",
            }

        vk = ACTION_TO_VK.get(canonical)
        if vk is None:
            return {
                "success": False,
                "status": "UNSUPPORTED_MEDIA_ACTION",
                "error": (
                    f"Media action '{action}' is not supported. "
                    f"Supported: {sorted(list(ACTION_TO_VK.keys()) + ['volume_set'])}"
                ),
            }

        ok = self.send_key(vk)
        if ok:
            state = self.get_volume_state()
            res: dict[str, Any] = {
                "success": True,
                "status": "SUCCESS",
                "action": canonical,
                "platform": "windows",
            }
            if state.get("available"):
                res["volume_percent"] = state.get("volume_percent")
                res["muted"] = state.get("muted")
            return res
        return {
            "success": False,
            "status": "KEY_DISPATCH_FAILED",
            "action": canonical,
            "error": "Failed dispatching keybd_event to Windows user32.",
        }
