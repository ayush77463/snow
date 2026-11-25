"""HTTP/HTTPS transfer server providing authenticated, streaming, resumable file transfer endpoints."""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
from pathlib import Path
import re
import ssl
import sys
import time
from typing import Any, Dict, Optional
import uuid

from aiohttp import web

from snow.core.config import CoreConfig
from snow.security.db import DatabaseManager
from snow.transfer.manager import TransferDirection, TransferManager, TransferRecord, TransferState
from snow.transfer.storage import CHUNK_SIZE, TransferStorageManager, compute_stream_sha256

logger = logging.getLogger(__name__)

# Bounded maximum size for live screen share JPEG frame (512 KiB)
MAX_SCREEN_FRAME_BYTES: int = 512 * 1024


class SnowHttpTransferServer:
    """Async HTTP/HTTPS streaming file transfer server for SNOW.

    Provides authenticated endpoints for:
    - Pre-flight duplicate check
    - Streaming chunked file upload (resumable via Content-Range)
    - Streaming chunked file download (resumable via HTTP Range)
    - Transfer status and cancellation
    - Live screen sharing frame ingest and state (Phase 26A)
    """

    # In-memory single-slot frame buffer per device for live screen streaming
    _screen_sessions: Dict[str, Dict[str, Any]] = {}

    def __init__(
        self,
        config: CoreConfig,
        db_manager: DatabaseManager,
        transfer_manager: TransferManager,
        storage_manager: TransferStorageManager,
        ssl_context: Optional[ssl.SSLContext] = None,
        cert_path: Optional[str | Path] = None,
    ) -> None:
        self.config = config
        self.db_manager = db_manager
        self.transfer_manager = transfer_manager
        self.storage_manager = storage_manager
        self.ssl_context = ssl_context
        self.cert_path = Path(cert_path) if cert_path else None

        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._bound_port: Optional[int] = None
        self._is_running = False

        # Bound client upload size (default 2 GiB or configured max_transfer_size)
        max_upload_size = getattr(config, "max_transfer_size", 2 * 1024 * 1024 * 1024)
        self.app = web.Application(
            client_max_size=max_upload_size,
            middlewares=[self._auth_middleware],
        )
        self._setup_routes()

    @property
    def is_running(self) -> bool:
        """Return True if the HTTP server is currently listening."""
        return self._is_running

    @property
    def bound_port(self) -> Optional[int]:
        """Return the actual TCP port the HTTP server is bound to."""
        return self._bound_port

    def _setup_routes(self) -> None:
        """Register API routes for the file transfer service."""
        self.app.router.add_post("/api/v1/transfers/check-duplicate", self.handle_check_duplicate)
        self.app.router.add_post("/api/v1/transfers/init", self.handle_init_transfer)
        self.app.router.add_get("/api/v1/transfers", self.handle_list_transfers)
        self.app.router.add_get("/api/v1/transfers/upload/{transfer_id}/status", self.handle_upload_status)
        self.app.router.add_post("/api/v1/transfers/upload/{transfer_id}", self.handle_upload)
        self.app.router.add_get("/api/v1/transfers/download/{transfer_id}", self.handle_download)
        self.app.router.add_post("/api/v1/transfers/{transfer_id}/cancel", self.handle_cancel)

        # Screen streaming routes (Phase 26A)
        self.app.router.add_post("/api/v1/screen/frame", self.handle_screen_frame)
        self.app.router.add_get("/api/v1/screen/status", self.handle_screen_status)
        self.app.router.add_get("/api/v1/screen/frame", self.handle_get_screen_frame)
        self.app.router.add_post("/api/v1/screen/start", self.handle_screen_start)
        self.app.router.add_post("/api/v1/screen/stop", self.handle_screen_stop)
        self.app.router.add_get("/api/v1/desktop/wallpaper", self.handle_desktop_wallpaper)

        # Direct Signed APK update routes (Port 8766)
        self.app.router.add_get("/api/v1/app/update-info", self.handle_app_update_info)
        self.app.router.add_get("/api/v1/app/apk", self.handle_app_apk_download)

    @web.middleware
    async def _auth_middleware(self, request: web.Request, handler) -> web.StreamResponse:
        """Authenticate all /api/ requests using device bearer tokens against SQLite."""
        if not request.path.startswith("/api/"):
            return await handler(request)

        # Skip auth if explicitly disabled in config (e.g. testing)
        if not self.config.auth_required:
            request["device_id"] = request.headers.get("X-Snow-Device-Id", "anonymous")
            return await handler(request)

        # Check for local loopback proxy authentication using IPC secret (Phase 26A Repair)
        ipc_secret_hdr = request.headers.get("X-Snow-Ipc-Secret")
        if ipc_secret_hdr:
            remote_ip = request.remote or ""
            is_loopback = remote_ip in ("127.0.0.1", "::1", "localhost", "testclient")
            if is_loopback:
                from snow.core.ipc import get_default_secret_path
                secret_file = (
                    Path(self.config.ipc_secret_path)
                    if getattr(self.config, "ipc_secret_path", None)
                    else get_default_secret_path()
                )
                expected_secret = secret_file.read_text("utf-8").strip() if secret_file.exists() else None
                if expected_secret and hmac.compare_digest(ipc_secret_hdr.strip(), expected_secret):
                    request["device_id"] = request.headers.get("X-Snow-Device-Id") or "local_dashboard_proxy"
                    return await handler(request)

        device_id = request.headers.get("X-Snow-Device-Id")
        auth_header = request.headers.get("Authorization")

        if not device_id or not auth_header:
            logger.warning(
                "HTTP request rejected: missing X-Snow-Device-Id or Authorization header from %s",
                request.remote,
            )
            return web.json_response(
                {"error": "Missing required authentication headers (Authorization, X-Snow-Device-Id)."},
                status=401,
            )

        if not auth_header.startswith("Bearer "):
            return web.json_response(
                {"error": "Authorization header must use Bearer scheme."},
                status=401,
            )

        token = auth_header[7:].strip()
        if not token:
            return web.json_response(
                {"error": "Empty bearer token."},
                status=401,
            )

        # Offload SQLite token hash verification to worker thread to avoid blocking event loop
        is_valid = await asyncio.to_thread(self.db_manager.verify_device_token, device_id, token)
        if not is_valid:
            logger.warning("HTTP transfer auth failed for device [%s] from %s", device_id, request.remote)
            return web.json_response(
                {"error": "Unauthorized: invalid or revoked device credentials."},
                status=401,
            )

        request["device_id"] = device_id
        return await handler(request)

    async def handle_check_duplicate(self, request: web.Request) -> web.Response:
        """Check if destination file with matching name and SHA-256 already exists."""
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body."}, status=400)

        file_name = data.get("file_name")
        sha256 = data.get("sha256")

        if not file_name or not sha256:
            return web.json_response({"error": "file_name and sha256 are required."}, status=400)

        already_exists, is_conflict, existing_hash = self.storage_manager.check_duplicate(
            file_name, sha256
        )
        return web.json_response({
            "already_exists": already_exists,
            "is_conflict": is_conflict,
            "existing_sha256": existing_hash,
        })

    async def handle_init_transfer(self, request: web.Request) -> web.Response:
        """Initialize or register a transfer session via HTTP."""
        try:
            data = await request.json()
        except Exception:
            return web.json_response({"error": "Invalid JSON body."}, status=400)

        file_name = data.get("file_name")
        file_size = data.get("file_size")
        sha256 = data.get("sha256")
        dir_str = data.get("direction", "UPLOAD").upper()

        if not file_name or file_size is None or not sha256:
            return web.json_response(
                {"error": "file_name, file_size, and sha256 are required."},
                status=400,
            )

        try:
            direction = TransferDirection(dir_str)
        except ValueError:
            return web.json_response({"error": f"Invalid direction: {dir_str}"}, status=400)

        device_id = request["device_id"]

        try:
            record = self.transfer_manager.create_transfer(
                device_id=device_id,
                file_name=file_name,
                file_size=int(file_size),
                sha256=sha256,
                direction=direction,
            )
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=400)

        # Check existing partial upload offset if any
        resume_offset = 0
        if direction == TransferDirection.UPLOAD:
            part_path = self.storage_manager.get_part_path(record.transfer_id)
            if part_path.exists() and part_path.is_file():
                resume_offset = part_path.stat().st_size

        return web.json_response({
            "transfer_id": record.transfer_id,
            "file_name": record.file_name,
            "file_size": record.file_size,
            "sha256": record.sha256,
            "direction": record.direction.value,
            "resume_offset": resume_offset,
            "status": record.status.value,
        })

    async def handle_list_transfers(self, request: web.Request) -> web.Response:
        """List all transfers associated with the authenticated device."""
        device_id = request["device_id"]
        records = self.transfer_manager.list_transfers_for_device(device_id)
        return web.json_response({
            "transfers": [rec.to_dict() for rec in records]
        })

    async def handle_upload_status(self, request: web.Request) -> web.Response:
        """Query the current byte offset of an in-flight upload."""
        transfer_id = request.match_info["transfer_id"]
        device_id = request["device_id"]

        record = self.transfer_manager.get_transfer_for_device(transfer_id, device_id)
        if not record:
            return web.json_response({"error": "Transfer not found or not owned by device."}, status=404)

        part_path = self.storage_manager.get_part_path(transfer_id)
        curr_offset = part_path.stat().st_size if part_path.exists() else 0

        return web.json_response({
            "transfer_id": transfer_id,
            "current_offset": curr_offset,
            "file_size": record.file_size,
            "status": record.status.value,
        })

    async def handle_upload(self, request: web.Request) -> web.Response:
        """Stream an incoming file or chunk into the destination .part file."""
        transfer_id = request.match_info["transfer_id"]
        device_id = request["device_id"]

        record = self.transfer_manager.get_transfer(transfer_id)
        if not record:
            return web.json_response({"error": "Transfer session not found."}, status=404)

        if record.device_id != device_id:
            return web.json_response({"error": "Forbidden: transfer not owned by device."}, status=403)

        if record.direction != TransferDirection.UPLOAD:
            return web.json_response(
                {"error": f"Invalid transfer direction: cannot upload to a {record.direction.value} transfer."},
                status=400,
            )

        if record.status in (TransferState.FAILED, TransferState.CANCELLED):
            return web.json_response(
                {"error": f"Transfer cannot proceed: transfer is in '{record.status.value}' state."},
                status=409,
            )

        if record.status == TransferState.COMPLETED:
            return web.json_response({
                "status": "COMPLETED",
                "transfer_id": transfer_id,
                "sha256": record.sha256,
            })

        try:
            dest_path = self.storage_manager.resolve_destination_path(record.file_name)
            part_path = self.storage_manager.get_part_path(transfer_id)
        except Exception as exc:
            return web.json_response({"error": str(exc)}, status=400)

        # Parse optional Content-Range header: bytes <start>-<end>/<total>
        content_range = request.headers.get("Content-Range")
        expected_start = part_path.stat().st_size if part_path.exists() else 0

        if content_range:
            match = re.match(r"^bytes\s+(\d+)-(\d+)/(\d+|\*)$", content_range.strip())
            if not match:
                return web.json_response(
                    {"error": f"Malformed Content-Range header: '{content_range}'."},
                    status=400,
                )
            range_start = int(match.group(1))
            range_end = int(match.group(2))
            total_str = match.group(3)

            # Validate range bounds
            if range_start < 0 or range_end < range_start:
                return web.json_response(
                    {"error": f"Invalid range bounds: start={range_start}, end={range_end}."},
                    status=400,
                )
            if range_end >= record.file_size:
                return web.json_response(
                    {"error": f"Range end {range_end} exceeds declared file size {record.file_size}."},
                    status=416,
                )
            if total_str != "*":
                range_total = int(total_str)
                if range_total != record.file_size:
                    return web.json_response(
                        {"error": f"Content-Range total {range_total} does not match declared file size {record.file_size}."},
                        status=400,
                    )

            # Enforce Content-Range and Content-Length parity when both are present
            if request.content_length is not None:
                expected_span = range_end - range_start + 1
                if request.content_length != expected_span:
                    logger.warning(
                        "Transfer [%s] Content-Range length (%d) does not match Content-Length (%d)",
                        transfer_id, expected_span, request.content_length
                    )
                    return web.json_response(
                        {
                            "error": f"Content-Length ({request.content_length}) does not match declared Content-Range span ({expected_span})."
                        },
                        status=400,
                    )

            if range_start != expected_start:
                logger.warning(
                    "Transfer [%s] range mismatch: client sent start=%d, disk offset=%d",
                    transfer_id, range_start, expected_start
                )
                return web.json_response(
                    {
                        "error": "Range offset mismatch.",
                        "current_offset": expected_start,
                        "received_start": range_start,
                    },
                    status=416,
                )
            write_mode = "ab" if range_start > 0 else "wb"
        else:
            # If no Content-Range header is supplied, start from offset 0
            write_mode = "wb"
            expected_start = 0

        # Enforce Content-Length before streaming if present
        if request.content_length is not None:
            if expected_start + request.content_length > record.file_size:
                self.storage_manager.delete_part_file(part_path)
                self.transfer_manager.mark_failed(transfer_id, "Upload size exceeds declared file size.")
                return web.json_response(
                    {
                        "error": f"Upload size {expected_start + request.content_length} exceeds declared file size {record.file_size}."
                    },
                    status=413,
                )

        # Stream request body into .part file in bounded 64 KiB chunks
        bytes_written = expected_start
        try:
            with open(part_path, write_mode) as f:
                while True:
                    chunk = await request.content.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    # Enforce hard upload limit against declared file_size
                    if bytes_written + len(chunk) > record.file_size:
                        f.close()
                        self.storage_manager.delete_part_file(part_path)
                        self.transfer_manager.mark_failed(
                            transfer_id,
                            f"Upload byte limit exceeded: wrote {bytes_written} bytes, received chunk of {len(chunk)} bytes exceeding file size {record.file_size}."
                        )
                        return web.json_response(
                            {"error": "Payload Too Large: upload bytes exceeded declared file size."},
                            status=413,
                        )
                    f.write(chunk)
                    bytes_written += len(chunk)
                    self.transfer_manager.update_offset(transfer_id, bytes_written)
        except Exception as exc:
            logger.error("Error streaming upload for transfer [%s]: %s", transfer_id, exc)
            self.storage_manager.delete_part_file(part_path)
            self.transfer_manager.mark_failed(transfer_id, f"I/O error during upload: {exc}")
            return web.json_response({"error": "I/O error during upload.", "details": str(exc)}, status=500)

        # If full file size reached, perform integrity verification and atomic commit
        if bytes_written >= record.file_size:
            try:
                verified_hash = self.storage_manager.atomic_commit(
                    part_path=part_path,
                    dest_path=dest_path,
                    expected_sha256=record.sha256,
                )
                record.file_path = str(dest_path)
                self.transfer_manager.mark_completed(transfer_id)
                logger.info("Upload [%s] verified and committed successfully.", transfer_id)
                return web.json_response({
                    "status": "COMPLETED",
                    "transfer_id": transfer_id,
                    "sha256": verified_hash,
                    "bytes_received": bytes_written,
                }, status=200)
            except ValueError as ve:
                self.storage_manager.delete_part_file(part_path)
                self.transfer_manager.mark_failed(transfer_id, str(ve))
                return web.json_response(
                    {"error": "SHA-256 integrity mismatch.", "details": str(ve)},
                    status=422,
                )
            except Exception as exc:
                self.storage_manager.delete_part_file(part_path)
                self.transfer_manager.mark_failed(transfer_id, str(exc))
                return web.json_response(
                    {"error": "Failed to commit completed file.", "details": str(exc)},
                    status=500,
                )
        else:
            # Bounded partial chunk completed successfully
            return web.json_response({
                "status": "IN_PROGRESS",
                "transfer_id": transfer_id,
                "current_offset": bytes_written,
                "file_size": record.file_size,
            }, status=206)

    async def handle_download(self, request: web.Request) -> web.StreamResponse:
        """Stream a file to the client with support for resumable HTTP Range requests."""
        transfer_id = request.match_info["transfer_id"]
        device_id = request["device_id"]

        record = self.transfer_manager.get_transfer(transfer_id)
        if not record:
            return web.json_response({"error": "Transfer session not found."}, status=404)

        if record.device_id != device_id:
            return web.json_response({"error": "Forbidden: transfer not owned by device."}, status=403)

        if record.direction != TransferDirection.DOWNLOAD:
            return web.json_response(
                {"error": f"Invalid transfer direction: cannot download from a {record.direction.value} transfer."},
                status=400,
            )

        if record.status in (TransferState.FAILED, TransferState.CANCELLED):
            return web.json_response(
                {"error": f"Transfer cannot proceed: transfer is in '{record.status.value}' state."},
                status=409,
            )

        if record.file_path and Path(record.file_path).exists() and Path(record.file_path).is_file():
            file_path = Path(record.file_path)
        else:
            try:
                file_path = self.storage_manager.resolve_destination_path(record.file_name)
            except Exception as exc:
                return web.json_response({"error": str(exc)}, status=400)

        if not file_path.exists() or not file_path.is_file():
            return web.json_response({"error": "File does not exist on server storage."}, status=404)

        total_size = file_path.stat().st_size
        range_header = request.headers.get("Range")

        start = 0
        end = total_size - 1
        is_range = False

        if range_header:
            match = re.match(r"^bytes[=\s]+(\d+)-(\d*)$", range_header.strip())
            if match:
                start = int(match.group(1))
                if match.group(2):
                    end = int(match.group(2))
                if start >= total_size or end < start or end >= total_size:
                    response = web.Response(status=416, headers={
                        "Content-Range": f"bytes */{total_size}"
                    })
                    return response
                is_range = True

        status_code = 206 if is_range else 200
        content_length = end - start + 1

        headers = {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(content_length),
            "Accept-Ranges": "bytes",
            "X-Snow-SHA256": record.sha256,
            "Content-Disposition": f'attachment; filename="{record.file_name}"',
        }
        if is_range:
            headers["Content-Range"] = f"bytes {start}-{end}/{total_size}"

        response = web.StreamResponse(status=status_code, headers=headers)
        await response.prepare(request)

        # Stream file in bounded chunks
        try:
            with open(file_path, "rb") as f:
                f.seek(start)
                remaining = content_length
                while remaining > 0:
                    read_size = min(CHUNK_SIZE, remaining)
                    chunk = f.read(read_size)
                    if not chunk:
                        break
                    await response.write(chunk)
                    remaining -= len(chunk)
            await response.write_eof()
        except Exception as exc:
            logger.error("Error streaming download for transfer [%s]: %s", transfer_id, exc)
            raise

        return response

    async def handle_cancel(self, request: web.Request) -> web.Response:
        """Cancel an in-flight transfer and delete its partial .part file."""
        transfer_id = request.match_info["transfer_id"]
        device_id = request["device_id"]

        record = self.transfer_manager.get_transfer_for_device(transfer_id, device_id)
        if not record:
            return web.json_response({"error": "Transfer not found."}, status=404)

        success = self.transfer_manager.cancel_transfer(transfer_id, device_id)
        part_path = self.storage_manager.get_part_path(transfer_id)
        self.storage_manager.delete_part_file(part_path)

        return web.json_response({
            "status": "CANCELLED",
            "transfer_id": transfer_id,
            "cancelled": success,
        })

    # =========================================================================
    # Live Screen Sharing Handlers (Phase 26A)
    # =========================================================================

    @classmethod
    def set_session_state(
        cls,
        device_id: Optional[str],
        state: str,
        session_id: Optional[str] = None,
        fps: float = 2.0,
        width: int = 720,
        height: int = 1280,
    ) -> None:
        """Update or register screen streaming session state for a device."""
        if not device_id or device_id == "all":
            for sess in cls._screen_sessions.values():
                sess["state"] = state
                if state == "STOPPED":
                    sess.pop("frame_bytes", None)
            return

        sess = cls._screen_sessions.setdefault(device_id, {})
        sess["state"] = state
        if session_id:
            sess["session_id"] = session_id
        sess["fps"] = fps
        sess["frame_width"] = width
        sess["frame_height"] = height
        sess["timestamp"] = time.time()
        if state == "STOPPED":
            sess.pop("frame_bytes", None)

    @classmethod
    def get_latest_screen_frame(cls, device_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve the latest frame dictionary for a device or the single active stream."""
        if device_id and device_id in cls._screen_sessions:
            sess = cls._screen_sessions[device_id]
            if sess.get("frame_bytes"):
                return sess
        for sess in cls._screen_sessions.values():
            if sess.get("state") == "STREAMING" and sess.get("frame_bytes"):
                return sess
        for sess in cls._screen_sessions.values():
            if sess.get("frame_bytes"):
                return sess
        return None

    @classmethod
    def get_screen_stream_status(cls, device_id: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve the status dictionary of the screen stream."""
        if device_id and device_id in cls._screen_sessions:
            sess = cls._screen_sessions[device_id]
            return {
                "state": sess.get("state", "IDLE"),
                "session_id": sess.get("session_id"),
                "fps": sess.get("fps", 0.0),
                "frame_width": sess.get("frame_width", 0),
                "frame_height": sess.get("frame_height", 0),
                "timestamp": sess.get("timestamp", 0.0),
                "has_frame": bool(sess.get("frame_bytes")),
                "frame_size": sess.get("frame_size", 0),
            }
        for d_id, sess in cls._screen_sessions.items():
            if sess.get("state") == "STREAMING":
                return {
                    "state": "STREAMING",
                    "device_id": d_id,
                    "session_id": sess.get("session_id"),
                    "fps": sess.get("fps", 0.0),
                    "frame_width": sess.get("frame_width", 0),
                    "frame_height": sess.get("frame_height", 0),
                    "timestamp": sess.get("timestamp", 0.0),
                    "has_frame": bool(sess.get("frame_bytes")),
                    "frame_size": sess.get("frame_size", 0),
                }
        return {"state": "IDLE", "has_frame": False}

    async def handle_screen_frame(self, request: web.Request) -> web.Response:
        """Ingest a bounded JPEG screen frame from an authenticated device."""
        device_id = request.get("device_id") or request.headers.get("X-Snow-Device-Id", "unknown")

        content_type = request.headers.get("Content-Type", "")
        if "image/jpeg" not in content_type.lower() and "image/jpg" not in content_type.lower():
            return web.json_response(
                {"error": f"Invalid Content-Type '{content_type}'. Must be image/jpeg."},
                status=415,
            )

        body = await request.read()
        if len(body) > MAX_SCREEN_FRAME_BYTES:
            return web.json_response(
                {"error": f"Frame size {len(body)} exceeds maximum allowed {MAX_SCREEN_FRAME_BYTES} bytes."},
                status=413,
            )

        session_id = request.headers.get("X-Snow-Session-Id")
        sess = self._screen_sessions.setdefault(device_id, {})
        if not session_id:
            session_id = sess.get("session_id") or str(uuid.uuid4())

        try:
            width = int(request.headers.get("X-Snow-Frame-Width", 0)) or sess.get("frame_width", 0)
            height = int(request.headers.get("X-Snow-Frame-Height", 0)) or sess.get("frame_height", 0)
            fps = float(request.headers.get("X-Snow-FPS", 0.0)) or sess.get("fps", 2.0)
        except ValueError:
            width = sess.get("frame_width", 0)
            height = sess.get("frame_height", 0)
            fps = sess.get("fps", 2.0)

        now = time.time()
        self._screen_sessions[device_id] = {
            "session_id": session_id,
            "state": "STREAMING",
            "frame_bytes": body,
            "content_type": "image/jpeg",
            "frame_width": width,
            "frame_height": height,
            "fps": fps,
            "timestamp": now,
            "frame_size": len(body),
            "device_id": device_id,
        }

        return web.json_response({
            "status": "ACCEPTED",
            "frame_size": len(body),
            "session_id": session_id,
            "timestamp": now,
        }, status=200)

    async def handle_screen_status(self, request: web.Request) -> web.Response:
        """Query live screen streaming session metadata."""
        device_id = request.query.get("device_id")
        status_dict = self.get_screen_stream_status(device_id)
        return web.json_response({"success": True, **status_dict})

    async def handle_get_screen_frame(self, request: web.Request) -> web.Response:
        """Retrieve the latest live screen JPEG frame."""
        device_id = request.query.get("device_id")
        frame_dict = self.get_latest_screen_frame(device_id)
        if not frame_dict or not frame_dict.get("frame_bytes"):
            return web.Response(status=204)

        return web.Response(
            body=frame_dict["frame_bytes"],
            content_type="image/jpeg",
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "X-Content-Type-Options": "nosniff",
                "X-Snow-Session-Id": str(frame_dict.get("session_id", "")),
                "X-Snow-Timestamp": str(frame_dict.get("timestamp", 0)),
            },
        )

    async def handle_screen_start(self, request: web.Request) -> web.Response:
        """Start or register an active screen streaming session."""
        device_id = request.get("device_id") or request.headers.get("X-Snow-Device-Id", "unknown")
        session_id = str(uuid.uuid4())
        fps = 2.0
        width = 720
        height = 1280

        try:
            body = await request.json()
            if isinstance(body, dict):
                session_id = body.get("session_id") or session_id
                device_id = body.get("device_id") or device_id
                fps = float(body.get("fps", fps))
                width = int(body.get("frame_width", width))
                height = int(body.get("frame_height", height))
        except Exception:
            pass

        self.set_session_state(
            device_id=device_id,
            state="STREAMING",
            session_id=session_id,
            fps=fps,
            width=width,
            height=height,
        )
        return web.json_response({
            "status": "STREAMING",
            "session_id": session_id,
            "fps": fps,
        })

    async def handle_screen_stop(self, request: web.Request) -> web.Response:
        """Stop an active screen streaming session."""
        device_id = request.get("device_id") or request.headers.get("X-Snow-Device-Id")
        try:
            body = await request.json()
            if isinstance(body, dict):
                device_id = body.get("device_id") or device_id
        except Exception:
            pass

        if device_id and device_id in self._screen_sessions:
            self.set_session_state(device_id, "STOPPED")
        else:
            for d in list(self._screen_sessions.keys()):
                self.set_session_state(d, "STOPPED")
        return web.json_response({"status": "STOPPED"})

    async def handle_desktop_wallpaper(self, request: web.Request) -> web.Response:
        """Serve scaled Windows desktop wallpaper preview with ETag and 304 support."""
        try:
            from snow.capabilities.windows.wallpaper import get_desktop_wallpaper_preview
            jpeg_bytes, etag = await asyncio.to_thread(get_desktop_wallpaper_preview)
            if not jpeg_bytes:
                return web.Response(status=404, text="Wallpaper not available")

            client_etag = request.headers.get("If-None-Match")
            if client_etag and client_etag.strip() == etag:
                return web.Response(status=304, headers={"ETag": etag})

            return web.Response(
                body=jpeg_bytes,
                content_type="image/jpeg",
                headers={
                    "ETag": etag,
                    "Cache-Control": "public, max-age=60, must-revalidate",
                },
            )
        except Exception as exc:
            logger.warning("Error serving wallpaper preview: %s", exc)
            return web.Response(status=500, text=str(exc))

    def _get_staged_apk_path(self) -> Optional[Path]:
        """Resolve and validate the staged signed Android APK path with strict containment."""
        import re as _re
        configured = getattr(self.config, "staged_apk_path", None)
        if configured:
            p = Path(configured).resolve()
            if p.is_file() and p.suffix.lower() == ".apk":
                return p

        def _apk_sort_key(path_obj: Path) -> tuple[int, ...]:
            m = _re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", path_obj.name)
            if m:
                return tuple(int(g or 0) for g in m.groups())
            return (0, 0, 0)

        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        search_dirs: list[Path] = [
            (repo_root / "packaging" / "output").resolve(),
            (Path.cwd() / "packaging" / "output").resolve(),
        ]
        if getattr(sys, "frozen", False):
            search_dirs.insert(0, (Path(sys.executable).resolve().parent / "packaging" / "output").resolve())

        for base_dir in search_dirs:
            try:
                if not base_dir.is_dir():
                    continue
                versioned = sorted(base_dir.glob("SNOW-Mobile-*.apk"), key=_apk_sort_key, reverse=True)
                candidates = [*versioned, base_dir / "SNOW-Mobile.apk"]
                for candidate in candidates:
                    resolved = candidate.resolve()
                    if resolved.is_relative_to(base_dir) and resolved.is_file():
                        return resolved
            except (ValueError, OSError):
                pass

        return None

    async def handle_app_update_info(self, request: web.Request) -> web.Response:
        """Return metadata for the staged signed Android APK."""
        apk_path = self._get_staged_apk_path()
        if not apk_path or not apk_path.is_file():
            return web.json_response({
                "available": False,
                "version_code": 0,
                "version_name": "",
                "size_bytes": 0,
                "sha256": ""
            })

        import hashlib
        import json as _json
        import re as _re
        h = hashlib.sha256()
        with open(apk_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        sha256 = h.hexdigest()
        size_bytes = apk_path.stat().st_size

        version_name = getattr(self.config, "version", "5.1.0") or "5.1.0"
        version_code = 3 if version_name.startswith("5.1") else 2

        name_match = _re.search(r"SNOW-Mobile-(\d+)\.(\d+)\.(\d+)\.apk$", apk_path.name, _re.IGNORECASE)
        if name_match:
            major, minor, patch = (int(name_match.group(1)), int(name_match.group(2)), int(name_match.group(3)))
            version_name = f"{major}.{minor}.{patch}"
            version_code = 4 if (major, minor) >= (5, 2) else (3 if (major, minor) == (5, 1) else (2 if (major, minor) == (5, 0) else 1))

        manifest_file = apk_path.parent / "update_manifest.json"
        if manifest_file.is_file():
            try:
                m_data = _json.loads(manifest_file.read_text(encoding="utf-8"))
                android_meta = m_data.get("android") if isinstance(m_data, dict) else None
                if isinstance(android_meta, dict) and (
                    not android_meta.get("apk_name") or android_meta.get("apk_name") == apk_path.name
                ):
                    vc = android_meta.get("version_code")
                    if isinstance(vc, int) and vc > 0:
                        version_code = vc
                    vn = android_meta.get("version_name")
                    if isinstance(vn, str) and _re.match(r"^\d+\.\d+\.\d+$", vn.strip()):
                        version_name = vn.strip()
            except Exception:
                pass

        return web.json_response({
            "available": True,
            "version_code": version_code,
            "version_name": version_name,
            "apk_name": apk_path.name,
            "size_bytes": size_bytes,
            "sha256": sha256
        })

    async def handle_app_apk_download(self, request: web.Request) -> web.StreamResponse:
        """Stream the staged signed APK to authenticated paired device."""
        apk_path = self._get_staged_apk_path()
        if not apk_path or not apk_path.is_file():
            return web.Response(status=404, text="No staged APK available for download.")

        response = web.FileResponse(
            apk_path,
            headers={
                "Content-Type": "application/vnd.android.package-archive",
                "Content-Disposition": f'attachment; filename="{apk_path.name}"'
            }
        )
        return response

    async def start(self) -> None:
        """Start listening for incoming HTTP/HTTPS transfer requests."""
        if self._is_running:
            logger.warning("SnowHttpTransferServer is already running; start() ignored.")
            return

        logger.info(
            "Starting %s transfer server on %s:%d...",
            "HTTPS" if self.ssl_context else "HTTP",
            self.config.bind_host,
            self.config.transfer_port,
        )

        self._runner = web.AppRunner(self.app)
        await self._runner.setup()

        self._site = web.TCPSite(
            self._runner,
            self.config.bind_host,
            self.config.transfer_port,
            ssl_context=self.ssl_context,
        )
        await self._site.start()
        self._is_running = True

        # Determine bound port (especially useful if transfer_port was 0)
        if self._site._server and self._site._server.sockets:
            self._bound_port = self._site._server.sockets[0].getsockname()[1]
        else:
            self._bound_port = self.config.transfer_port

        logger.info(
            "%s transfer server listening on %s:%d",
            "HTTPS" if self.ssl_context else "HTTP",
            self.config.bind_host,
            self._bound_port,
        )

    async def stop(self) -> None:
        """Stop the HTTP transfer server and release network resources."""
        if not self._is_running:
            return

        logger.info("Stopping HTTP transfer server...")
        if self._site:
            await self._site.stop()
            self._site = None

        if self._runner:
            await self._runner.cleanup()
            self._runner = None

        self._is_running = False
        self._bound_port = None
        logger.info("HTTP transfer server stopped.")
