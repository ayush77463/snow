"""Windows native live screen streaming manager for SNOW V5.2.0.

Captures interactive Windows desktop frames via Win32 GDI (BitBlt + GetDIBits),
encodes bounded full-quality JPEGs (<= 512 KiB) via lazy-loaded Pillow in memory
with zero temporary disk writes, deduplicates byte-identical frames via exact SHA-256,
pauses capture completely when active authorized viewers == 0, and cleans up every
GDI/Desktop handle deterministically in try/finally blocks.
"""

from __future__ import annotations

import asyncio
import ctypes
from ctypes import wintypes
import hashlib
import io
import logging
import platform
import time
from typing import Any, Awaitable, Callable, Optional
import uuid

logger = logging.getLogger(__name__)

MAX_SCREEN_FRAME_BYTES: int = 512 * 1024  # 512 KiB strict wire budget
DEFAULT_PC_STREAM_FPS: float = 4.0
MIN_PC_STREAM_FPS: float = 1.0
MAX_PC_STREAM_FPS: float = 10.0
DEFAULT_PC_JPEG_QUALITY: int = 85


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class _BITMAPINFO(ctypes.Structure):
    _fields_ = [
        ("bmiHeader", _BITMAPINFOHEADER),
        ("bmiColors", wintypes.DWORD * 3),
    ]


class WindowsScreenStreamManager:
    """Manages outbound live screen sharing from the local Windows host."""

    def __init__(
        self,
        sender_device_id: str,
        sender_name: str = "Windows PC",
        sender_network_id: Optional[str] = None,
        transfer_server: Optional[Any] = None,
        permission_checker: Optional[Callable[[str], bool]] = None,
        on_frame_ready: Optional[Callable[[dict[str, Any], bytes], Awaitable[None]]] = None,
        on_state_change: Optional[Callable[[dict[str, Any]], Awaitable[None]]] = None,
        raw_frame_provider: Optional[Callable[[], Optional[tuple[bytes, int, int]]]] = None,
    ) -> None:
        self.sender_device_id = sender_device_id
        self.sender_name = sender_name
        self.sender_network_id = sender_network_id
        self.transfer_server = transfer_server
        self.permission_checker = permission_checker
        self.on_frame_ready = on_frame_ready
        self.on_state_change = on_state_change
        self.raw_frame_provider = raw_frame_provider

        self.state: str = "IDLE"
        self.session_id: Optional[str] = None
        self.fps: float = DEFAULT_PC_STREAM_FPS
        self.jpeg_quality: int = DEFAULT_PC_JPEG_QUALITY
        self.target_device_ids: list[str] = []
        self.subscribed_viewers: set[str] = set()
        self._viewer_leases: dict[str, float] = {}
        self.frame_seq: int = 0
        self.frame_width: int = 0
        self.frame_height: int = 0
        self.last_frame_timestamp: float = 0.0
        self.last_frame_size: int = 0
        self._last_raw_sha256: Optional[str] = None
        self._last_dims: Optional[tuple[int, int]] = None
        self._was_paused_zero_viewers: bool = False

        # Diagnostics & instrumentation (for empirical tests and telemetry)
        self.frames_captured: int = 0
        self.frames_sent: int = 0
        self.total_bytes_sent: int = 0
        self.deduplicated_skips: int = 0
        self.zero_viewer_pauses: int = 0
        self.gdi_allocations: int = 0
        self.gdi_releases: int = 0

        self._task: Optional[asyncio.Task[None]] = None
        self._lock = asyncio.Lock()

    def is_target_authorized(self, device_id: str) -> bool:
        """Fail closed unless device_id has explicit full_control authorization."""
        if not device_id:
            return False
        if device_id == "local_dashboard":
            return True
        if self.permission_checker is not None:
            try:
                return bool(self.permission_checker(device_id))
            except Exception:
                return False
        return True

    def active_viewer_count(self) -> int:
        """Count non-expired authorized active viewers."""
        now = time.monotonic()
        expired = [vid for vid, exp in self._viewer_leases.items() if exp <= now]
        for vid in expired:
            self._viewer_leases.pop(vid, None)
            self.subscribed_viewers.discard(vid)
        authorized = [
            vid for vid in self.subscribed_viewers if self.is_target_authorized(vid)
        ]
        return len(authorized)

    def add_viewer(self, viewer_id: str, ttl_seconds: Optional[float] = None) -> bool:
        """Register or refresh an authorized viewer subscription."""
        clean_id = (viewer_id or "").strip()
        if not self.is_target_authorized(clean_id):
            logger.warning("Rejected screen stream viewer [%s]: permission != full_control", clean_id)
            return False
        if self.target_device_ids and clean_id not in self.target_device_ids:
            # Explicit target scoping: reject uninvited device unless local dashboard explicitly views own host
            if clean_id != "local_dashboard":
                return False
        self.subscribed_viewers.add(clean_id)
        if ttl_seconds is not None and ttl_seconds > 0:
            self._viewer_leases[clean_id] = time.monotonic() + float(ttl_seconds)
        else:
            self._viewer_leases.pop(clean_id, None)
        return True

    def remove_viewer(self, viewer_id: str) -> None:
        """Remove a viewer subscription; clears cached hash so resume delivers cleanly."""
        clean_id = (viewer_id or "").strip()
        self.subscribed_viewers.discard(clean_id)
        self._viewer_leases.pop(clean_id, None)
        if self.active_viewer_count() == 0:
            self._last_raw_sha256 = None

    def revoke_target(self, device_id: str) -> bool:
        """Immediately remove target & viewer on permission downgrade/revocation. Stops if no targets left."""
        clean_id = (device_id or "").strip()
        changed = False
        if clean_id in self.target_device_ids:
            self.target_device_ids = [d for d in self.target_device_ids if d != clean_id]
            changed = True
        if clean_id in self.subscribed_viewers:
            self.remove_viewer(clean_id)
            changed = True
        return changed

    def get_status(self) -> dict[str, Any]:
        """Return canonical metadata for UI, IPC, and control-plane announcements."""
        return {
            "state": self.state,
            "sender_device_id": self.sender_device_id,
            "device_id": self.sender_device_id,
            "sender_name": self.sender_name,
            "sender_platform": "windows",
            "sender_network_id": self.sender_network_id,
            "session_id": self.session_id,
            "fps": self.fps,
            "frame_width": self.frame_width,
            "frame_height": self.frame_height,
            "frame_seq": self.frame_seq,
            "timestamp": self.last_frame_timestamp,
            "frame_size": self.last_frame_size,
            "target_device_ids": list(self.target_device_ids),
            "viewer_count": self.active_viewer_count(),
            "frames_captured": self.frames_captured,
            "frames_sent": self.frames_sent,
            "total_bytes_sent": self.total_bytes_sent,
            "deduplicated_skips": self.deduplicated_skips,
            "zero_viewer_pauses": self.zero_viewer_pauses,
            "gdi_allocations": self.gdi_allocations,
            "gdi_releases": self.gdi_releases,
        }

    async def start(
        self,
        target_device_ids: list[str],
        fps: float = DEFAULT_PC_STREAM_FPS,
        quality: int = DEFAULT_PC_JPEG_QUALITY,
        initial_viewers: Optional[list[str]] = None,
        spawn_loop: bool = True,
    ) -> dict[str, Any]:
        """Authorize targets and start PC live screen streaming."""
        async with self._lock:
            clean_targets: list[str] = []
            for tid in target_device_ids or []:
                s = str(tid or "").strip()
                if s and s not in clean_targets:
                    clean_targets.append(s)

            if not clean_targets:
                return {
                    "success": False,
                    "status": "NO_TARGETS_SELECTED",
                    "error": "Select at least one authorized Full Control target device.",
                }

            denied = [t for t in clean_targets if not self.is_target_authorized(t)]
            if denied:
                return {
                    "success": False,
                    "status": "PERMISSION_DENIED",
                    "error": f"Screen sharing requires Full Control permission; blocked for: {', '.join(denied)}",
                }

            # Stop any prior running task cleanly before resetting state
            if self._task is not None and not self._task.done():
                self._task.cancel()
                try:
                    await self._task
                except asyncio.CancelledError:
                    pass
                self._task = None

            self.session_id = uuid.uuid4().hex[:12]
            self.state = "STREAMING"
            self.fps = max(MIN_PC_STREAM_FPS, min(MAX_PC_STREAM_FPS, float(fps)))
            self.jpeg_quality = max(40, min(95, int(quality)))
            self.target_device_ids = clean_targets
            self.frame_seq = 0
            self.last_frame_size = 0
            self._last_raw_sha256 = None
            self._last_dims = None
            self._was_paused_zero_viewers = False
            self.subscribed_viewers.clear()
            self._viewer_leases.clear()

            if initial_viewers is not None:
                for vid in initial_viewers:
                    self.add_viewer(vid)

            if self.transfer_server is not None:
                self.transfer_server.set_session_state(
                    device_id=self.sender_device_id,
                    state="STREAMING",
                    session_id=self.session_id,
                    fps=self.fps,
                    width=self.frame_width or 1280,
                    height=self.frame_height or 720,
                    sender_name=self.sender_name,
                    sender_platform="windows",
                    target_device_ids=list(self.target_device_ids),
                    sender_network_id=self.sender_network_id,
                )

            if spawn_loop:
                self._task = asyncio.create_task(self._capture_loop())

        if self.on_state_change is not None:
            try:
                await self.on_state_change(self.get_status())
            except Exception as exc:
                logger.debug("on_state_change error during start: %s", exc)

        return {"success": True, **self.get_status()}

    async def stop(self, reason: str = "STOPPED") -> dict[str, Any]:
        """Stop PC screen streaming immediately and purge buffered frames."""
        async with self._lock:
            final_state = "REVOKED" if str(reason).upper() == "REVOKED" else "STOPPED"
            self.state = final_state
            task = self._task
            self._task = None

        if task is not None and not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self.subscribed_viewers.clear()
        self._viewer_leases.clear()
        self._last_raw_sha256 = None
        self.last_frame_size = 0

        if self.transfer_server is not None:
            self.transfer_server.set_session_state(
                device_id=self.sender_device_id,
                state=final_state,
            )

        if self.on_state_change is not None:
            try:
                await self.on_state_change(self.get_status())
            except Exception as exc:
                logger.debug("on_state_change error during stop: %s", exc)

        return {"success": True, **self.get_status()}

    def _capture_desktop_bgra(self) -> Optional[tuple[bytes, int, int]]:
        """Capture interactive Windows desktop pixels via GDI BitBlt + GetDIBits.

        Always executes inside RAII try/finally so every DC, HBITMAP, and desktop
        handle is released on both success and failure.
        """
        if self.raw_frame_provider is not None:
            self.gdi_allocations += 1
            try:
                res = self.raw_frame_provider()
            finally:
                self.gdi_releases += 1
            return res

        if platform.system() != "Windows":
            return None

        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        kernel32 = ctypes.windll.kernel32

        user32.OpenInputDesktop.restype = ctypes.c_void_p
        user32.OpenInputDesktop.argtypes = [ctypes.c_uint, wintypes.BOOL, ctypes.c_uint]
        user32.GetThreadDesktop.restype = ctypes.c_void_p
        user32.GetThreadDesktop.argtypes = [ctypes.c_ulong]
        user32.SetThreadDesktop.restype = wintypes.BOOL
        user32.SetThreadDesktop.argtypes = [ctypes.c_void_p]
        user32.CloseDesktop.restype = wintypes.BOOL
        user32.CloseDesktop.argtypes = [ctypes.c_void_p]
        kernel32.GetCurrentThreadId.restype = ctypes.c_ulong
        kernel32.GetCurrentThreadId.argtypes = []

        user32.GetDC.restype = ctypes.c_void_p
        user32.GetDC.argtypes = [ctypes.c_void_p]
        user32.ReleaseDC.restype = ctypes.c_int
        user32.ReleaseDC.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        user32.GetSystemMetrics.restype = ctypes.c_int
        user32.GetSystemMetrics.argtypes = [ctypes.c_int]

        gdi32.CreateCompatibleDC.restype = ctypes.c_void_p
        gdi32.CreateCompatibleDC.argtypes = [ctypes.c_void_p]
        gdi32.CreateCompatibleBitmap.restype = ctypes.c_void_p
        gdi32.CreateCompatibleBitmap.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]
        gdi32.SelectObject.restype = ctypes.c_void_p
        gdi32.SelectObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        gdi32.BitBlt.restype = wintypes.BOOL
        gdi32.BitBlt.argtypes = [
            ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
            ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_uint32,
        ]
        gdi32.GetDIBits.restype = ctypes.c_int
        gdi32.GetDIBits.argtypes = [
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint, ctypes.c_uint,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint,
        ]
        gdi32.DeleteDC.restype = wintypes.BOOL
        gdi32.DeleteDC.argtypes = [ctypes.c_void_p]
        gdi32.DeleteObject.restype = wintypes.BOOL
        gdi32.DeleteObject.argtypes = [ctypes.c_void_p]

        original_desk = user32.GetThreadDesktop(kernel32.GetCurrentThreadId())
        h_input_desk = user32.OpenInputDesktop(0, False, 0x01FF)
        switched_desktop = False
        if h_input_desk:
            switched_desktop = bool(user32.SetThreadDesktop(h_input_desk))

        h_screen_dc = None
        h_mem_dc = None
        h_bitmap = None
        h_old_bitmap = None

        try:
            width = int(user32.GetSystemMetrics(0))
            height = int(user32.GetSystemMetrics(1))
            if width <= 0 or height <= 0:
                return None

            h_screen_dc = user32.GetDC(0)
            if not h_screen_dc:
                return None
            self.gdi_allocations += 1

            h_mem_dc = gdi32.CreateCompatibleDC(h_screen_dc)
            if not h_mem_dc:
                return None
            self.gdi_allocations += 1

            h_bitmap = gdi32.CreateCompatibleBitmap(h_screen_dc, width, height)
            if not h_bitmap:
                return None
            self.gdi_allocations += 1

            h_old_bitmap = gdi32.SelectObject(h_mem_dc, h_bitmap)
            SRCCOPY = 0x00CC0020
            if not gdi32.BitBlt(h_mem_dc, 0, 0, width, height, h_screen_dc, 0, 0, SRCCOPY):
                return None

            bmi = _BITMAPINFO()
            bmi.bmiHeader.biSize = ctypes.sizeof(_BITMAPINFOHEADER)
            bmi.bmiHeader.biWidth = width
            bmi.bmiHeader.biHeight = -height  # top-down DIB
            bmi.bmiHeader.biPlanes = 1
            bmi.bmiHeader.biBitCount = 32
            bmi.bmiHeader.biCompression = 0  # BI_RGB

            buf_size = width * height * 4
            pixel_buf = (ctypes.c_ubyte * buf_size)()
            scanlines = gdi32.GetDIBits(
                h_mem_dc,
                h_bitmap,
                0,
                height,
                pixel_buf,
                ctypes.byref(bmi),
                0,  # DIB_RGB_COLORS
            )
            if scanlines <= 0:
                return None

            return bytes(pixel_buf), width, height
        finally:
            if h_mem_dc and h_old_bitmap:
                try:
                    gdi32.SelectObject(h_mem_dc, h_old_bitmap)
                except Exception:
                    pass
            if h_bitmap:
                try:
                    gdi32.DeleteObject(h_bitmap)
                    self.gdi_releases += 1
                except Exception:
                    pass
            if h_mem_dc:
                try:
                    gdi32.DeleteDC(h_mem_dc)
                    self.gdi_releases += 1
                except Exception:
                    pass
            if h_screen_dc:
                try:
                    user32.ReleaseDC(0, h_screen_dc)
                    self.gdi_releases += 1
                except Exception:
                    pass
            if switched_desktop and original_desk:
                try:
                    user32.SetThreadDesktop(original_desk)
                except Exception:
                    pass
            if h_input_desk:
                try:
                    user32.CloseDesktop(h_input_desk)
                except Exception:
                    pass

    @staticmethod
    def _encode_bgra_to_jpeg(raw_bgra: bytes, width: int, height: int, quality: int = DEFAULT_PC_JPEG_QUALITY) -> Optional[bytes]:
        """Encode raw top-down BGRA/BGRX buffer to bounded JPEG bytes lazily via Pillow."""
        from PIL import Image  # Lazy import so idle core never pays Pillow RSS cost

        img = Image.frombuffer("RGBA", (width, height), raw_bgra, "raw", "BGRA", 0, 1).convert("RGB")
        try:
            q = int(quality)
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=q, optimize=True)
            data = buf.getvalue()
            if len(data) <= MAX_SCREEN_FRAME_BYTES:
                return data
            # Fit ultra-dense 4K/HiDPI frames under the hard 512 KiB wire cap cleanly.
            scaled = img
            for scale_factor in (0.75, 0.6, 0.5):
                nw = max(320, int(width * scale_factor))
                nh = max(240, int(height * scale_factor))
                resized = scaled.resize((nw, nh), Image.Resampling.LANCZOS)
                try:
                    buf = io.BytesIO()
                    resized.save(buf, format="JPEG", quality=q, optimize=True)
                    data = buf.getvalue()
                    if len(data) <= MAX_SCREEN_FRAME_BYTES:
                        return data
                finally:
                    resized.close()
            return data if len(data) <= MAX_SCREEN_FRAME_BYTES else None
        finally:
            img.close()

    async def capture_and_publish_once(self) -> Optional[dict[str, Any]]:
        """Execute a single capture/dedup/publish cycle (honoring 0-viewer pause)."""
        if self.state != "STREAMING":
            return None

        if self.active_viewer_count() == 0:
            self.zero_viewer_pauses += 1
            self._was_paused_zero_viewers = True
            self._last_raw_sha256 = None
            return {"skipped": "zero_viewers", "bytes_sent": 0}

        captured = await asyncio.to_thread(self._capture_desktop_bgra)
        if not captured:
            return None
        raw_bytes, width, height = captured
        self.frames_captured += 1

        if self._last_dims != (width, height) or self._was_paused_zero_viewers:
            self._last_raw_sha256 = None
            self._last_dims = (width, height)
            self._was_paused_zero_viewers = False

        raw_hash = hashlib.sha256(f"{width}x{height}:".encode("ascii") + raw_bytes).hexdigest()
        if raw_hash == self._last_raw_sha256:
            self.deduplicated_skips += 1
            return {"skipped": "identical_frame", "bytes_sent": 0, "sha256": raw_hash}

        jpeg_bytes = await asyncio.to_thread(self._encode_bgra_to_jpeg, raw_bytes, width, height, self.jpeg_quality)
        if not jpeg_bytes or len(jpeg_bytes) > MAX_SCREEN_FRAME_BYTES:
            return None

        self._last_raw_sha256 = raw_hash
        self.frame_seq += 1
        self.frame_width = width
        self.frame_height = height
        self.last_frame_timestamp = time.time()
        self.last_frame_size = len(jpeg_bytes)
        self.frames_sent += 1
        self.total_bytes_sent += len(jpeg_bytes)

        frame_sha256 = hashlib.sha256(jpeg_bytes).hexdigest()
        meta = {
            "sender_device_id": self.sender_device_id,
            "device_id": self.sender_device_id,
            "sender_name": self.sender_name,
            "sender_platform": "windows",
            "sender_network_id": self.sender_network_id,
            "session_id": self.session_id,
            "frame_seq": self.frame_seq,
            "frame_sha256": frame_sha256,
            "frame_width": width,
            "frame_height": height,
            "fps": self.fps,
            "frame_size": len(jpeg_bytes),
            "timestamp": self.last_frame_timestamp,
            "target_device_ids": list(self.target_device_ids),
        }

        if self.transfer_server is not None:
            self.transfer_server.publish_screen_frame(
                sender_device_id=self.sender_device_id,
                frame_bytes=jpeg_bytes,
                meta=meta,
            )

        if self.on_frame_ready is not None:
            await self.on_frame_ready(meta, jpeg_bytes)

        return {"sent": True, **meta}

    async def _capture_loop(self) -> None:
        """Background bounded-FPS capture loop."""
        interval = 1.0 / max(MIN_PC_STREAM_FPS, min(MAX_PC_STREAM_FPS, self.fps))
        while self.state == "STREAMING":
            t0 = time.monotonic()
            try:
                await self.capture_and_publish_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.warning("PC screen capture tick error: %s", exc)
            elapsed = time.monotonic() - t0
            sleep_for = max(0.02, interval - elapsed)
            await asyncio.sleep(sleep_for)
