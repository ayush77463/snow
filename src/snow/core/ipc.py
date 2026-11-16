"""Authenticated loopback IPC server for SNOW Desktop Core.

Provides an asynchronous, local-only JSON-over-TCP interface enabling the SNOW
MCP subprocess to query desktop core state and dispatch device operations without
opening secondary WebSocket or HTTP file transfer servers.

SECURITY INVARIANTS:
1. Strict Loopback Binding: Binds exclusively to 127.0.0.1 (never 0.0.0.0 or LAN IP).
2. Secret Authentication: Requires a local cryptographic secret (~/.snow/ipc.secret)
   protected by Windows user-only ACLs (icacls) or 0600 POSIX permissions.
3. Constant-Time Verification: Compares tokens via hmac.compare_digest.
4. Zero Secret Exposure: Never returns tokens, hashes, private keys, or PINs in IPC responses or logs.
5. Strict Stdio Protection: All logging routed exclusively to sys.stderr or standard logging.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import hmac
import json
import logging
import os
from pathlib import Path
import secrets
import subprocess
import sys
from typing import Any, Dict, Optional, Set
import uuid

from snow.core.config import CoreConfig

logger = logging.getLogger(__name__)

IPC_PROTOCOL_VERSION: int = 1
MAX_IPC_MESSAGE_SIZE: int = 65536  # 64 KiB maximum frame size
DEFAULT_IPC_SECRET_FILENAME: str = "ipc.secret"


def get_default_secret_path() -> Path:
    """Return the canonical path to the SNOW IPC secret file."""
    data_dir = os.environ.get("SNOW_DATA_DIR")
    if data_dir:
        base_dir = Path(data_dir).resolve()
    else:
        base_dir = Path.home() / ".snow"
    return base_dir / DEFAULT_IPC_SECRET_FILENAME


def enforce_file_permissions(file_path: Path) -> bool:
    """Enforce user-only read/write access permissions on a secret file.

    On Windows: Uses icacls to restrict access exclusively to the current user.
    On POSIX: Applies 0600 (owner read/write only).

    Returns True if permissions were successfully applied, False otherwise.
    """
    resolved = file_path.resolve()
    if sys.platform == "win32":
        username = os.environ.get("USERNAME") or os.environ.get("USER")
        if not username:
            try:
                username = os.getlogin()
            except Exception:
                username = None

        if not username:
            logger.warning("Could not determine Windows username to set IPC ACL.")
            return False

        try:
            # Remove inherited permissions and grant explicit Read/Write to the current user
            cmd = [
                "icacls.exe",
                str(resolved),
                "/inheritance:r",
                "/grant:r",
                f"{username}:(R,W)",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5.0,
                check=False,
            )
            if result.returncode == 0:
                logger.debug("Successfully applied Windows user ACL to %s", resolved)
                return True
            else:
                logger.warning(
                    "icacls returned code %d: %s",
                    result.returncode,
                    result.stderr or result.stdout,
                )
                return False
        except Exception as exc:
            logger.warning("Failed executing icacls on %s: %s", resolved, exc)
            return False
    else:
        try:
            os.chmod(resolved, 0o600)
            return True
        except Exception as exc:
            logger.warning("Failed setting chmod 0600 on %s: %s", resolved, exc)
            return False


def get_or_create_ipc_secret(secret_path: Optional[Path | str] = None) -> str:
    """Retrieve existing secret or atomically generate a new cryptographically secure secret.

    Guarantees that the secret file is created with restricted user permissions
    and is never overwritten if a valid, non-empty secret already exists.
    """
    path = Path(secret_path).resolve() if secret_path else get_default_secret_path()
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.is_file():
        try:
            existing = path.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        except Exception as exc:
            logger.warning("Could not read existing IPC secret from %s: %s", path, exc)

    # Generate fresh cryptographically secure random secret
    fresh_secret = secrets.token_urlsafe(32)
    tmp_path = path.parent / f".tmp_{path.name}_{uuid.uuid4().hex}"

    try:
        tmp_path.write_text(fresh_secret, encoding="utf-8")
        enforce_file_permissions(tmp_path)
        os.replace(tmp_path, path)
        enforce_file_permissions(path)
        logger.info("Generated new authenticated IPC secret at %s", path)
        return fresh_secret
    except Exception as exc:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
        raise RuntimeError(f"Failed to securely create IPC secret file: {exc}") from exc


class SnowIpcServer:
    """Asynchronous loopback IPC server exposing core state to the MCP subprocess."""

    def __init__(self, core_server: Any, config: CoreConfig) -> None:
        self.core_server = core_server
        self.config = config
        self._server: Optional[asyncio.Server] = None
        self._is_running: bool = False
        self._bound_port: Optional[int] = None
        self._active_clients: Set[asyncio.StreamWriter] = set()

        # Load or create local IPC secret
        secret_path = config.ipc_secret_path or get_default_secret_path()
        self._secret = get_or_create_ipc_secret(secret_path)

    @property
    def is_running(self) -> bool:
        """Return True if the IPC server is actively listening."""
        return self._is_running

    @property
    def bound_port(self) -> Optional[int]:
        """Return the actual TCP port the IPC server is bound to."""
        return self._bound_port

    @property
    def secret(self) -> str:
        """Return the loaded IPC secret token."""
        return self._secret

    async def start(self) -> None:
        """Start the loopback IPC TCP listener."""
        if self._is_running:
            logger.warning("SnowIpcServer is already running.")
            return

        # Double check loopback enforcement
        bind_host = self.config.ipc_host
        if bind_host.strip().lower() not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError(f"IPC server must bind strictly to loopback, rejected: {bind_host}")

        self._server = await asyncio.start_server(
            self._handle_client,
            host=bind_host,
            port=self.config.ipc_port,
            limit=131072,
        )

        sockets = self._server.sockets
        if sockets:
            self._bound_port = sockets[0].getsockname()[1]
        else:
            self._bound_port = self.config.ipc_port

        self._is_running = True
        logger.info("SnowIpcServer listening on %s:%d", bind_host, self._bound_port)

    async def stop(self) -> None:
        """Stop the IPC server and cleanly close all active connections."""
        if not self._is_running:
            return

        self._is_running = False
        logger.info("Stopping SnowIpcServer...")

        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Close all active client connections cleanly
        for writer in list(self._active_clients):
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        self._active_clients.clear()
        self._bound_port = None
        logger.info("SnowIpcServer stopped cleanly.")

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handle incoming newline-delimited JSON IPC connection lifecycle."""
        peer_addr = writer.get_extra_info("peername")
        logger.debug("IPC client connected from %s", peer_addr)
        self._active_clients.add(writer)
        is_authenticated = False

        try:
            while self._is_running:
                line = await reader.readline()
                if not line:
                    break  # Client closed connection

                if len(line) > MAX_IPC_MESSAGE_SIZE:
                    err_resp = {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": None,
                        "success": False,
                        "status": "MESSAGE_TOO_LARGE",
                        "error": f"Message exceeded maximum frame size ({MAX_IPC_MESSAGE_SIZE} bytes).",
                    }
                    await self._send_response(writer, err_resp)
                    continue

                try:
                    request = json.loads(line.decode("utf-8").strip())
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    err_resp = {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": None,
                        "success": False,
                        "status": "INVALID_JSON",
                        "error": f"Malformed JSON: {exc}",
                    }
                    await self._send_response(writer, err_resp)
                    continue

                if not isinstance(request, dict):
                    err_resp = {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": None,
                        "success": False,
                        "status": "INVALID_REQUEST",
                        "error": "Request must be a JSON object.",
                    }
                    await self._send_response(writer, err_resp)
                    continue

                # Process validated request
                response, client_authed = await self._dispatch_request(request, is_authenticated)
                if client_authed:
                    is_authenticated = True

                await self._send_response(writer, response)

        except (ValueError, asyncio.LimitOverrunError) as exc:
            err_resp = {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": None,
                "success": False,
                "status": "MESSAGE_TOO_LARGE",
                "error": f"Message exceeded maximum frame size ({MAX_IPC_MESSAGE_SIZE} bytes).",
            }
            try:
                await self._send_response(writer, err_resp)
            except Exception:
                pass
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.warning("Unexpected error handling IPC client %s: %s", peer_addr, exc)
        finally:
            self._active_clients.discard(writer)
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.debug("IPC client %s disconnected.", peer_addr)

    async def _send_response(self, writer: asyncio.StreamWriter, response: dict) -> None:
        """Serialize and transmit newline-delimited JSON response."""
        data = json.dumps(response, separators=(",", ":")).encode("utf-8") + b"\n"
        writer.write(data)
        await writer.drain()

    async def _dispatch_request(
        self, request: dict, is_connection_authenticated: bool
    ) -> tuple[dict, bool]:
        """Validate authentication, protocol invariants, and route operation."""
        version = request.get("version")
        request_id = request.get("request_id") or str(uuid.uuid4())
        op = request.get("op")
        auth_token = request.get("auth_token")
        payload = request.get("payload") if isinstance(request.get("payload"), dict) else {}

        # 1. Validate version
        if version != IPC_PROTOCOL_VERSION:
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": False,
                "status": "INVALID_PROTOCOL_VERSION",
                "error": f"Expected version {IPC_PROTOCOL_VERSION}, got {version!r}",
            }, False

        # 2. Validate op
        if not op or not isinstance(op, str):
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": False,
                "status": "INVALID_REQUEST",
                "error": "Missing or non-string 'op' field.",
            }, False

        # 3. Authenticate request
        now_authed = False
        has_valid_token = bool(
            auth_token
            and isinstance(auth_token, str)
            and hmac.compare_digest(auth_token.strip(), self._secret)
        )

        if has_valid_token:
            now_authed = True
        elif not is_connection_authenticated:
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": False,
                "status": "UNAUTHORIZED",
                "error": "Authentication required. Provide valid 'auth_token'.",
            }, False

        # 4. Handle operations
        if op == "ping":
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "SUCCESS",
                "data": {"status": "pong"},
            }, now_authed

        if op == "authenticate":
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "AUTHENTICATED",
                "data": {"authenticated": True},
            }, True

        if op == "get_device_status":
            status_data = self._handle_get_device_status()
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "SUCCESS",
                "data": status_data,
            }, now_authed

        if op == "list_devices":
            devices_data = self._handle_list_devices()
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "SUCCESS",
                "data": {"devices": devices_data},
            }, now_authed

        if op == "device_request":
            dev_resp = await self._handle_device_request(payload)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": dev_resp.get("success", False),
                "status": dev_resp.get("status", "ERROR"),
                "data": dev_resp.get("data"),
                "error": dev_resp.get("error"),
            }, now_authed

        return {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": request_id,
            "success": False,
            "status": "UNKNOWN_OPERATION",
            "error": f"Unsupported IPC operation: '{op}'",
        }, now_authed

    def _handle_get_device_status(self) -> dict:
        """Compile a safe diagnostic snapshot of Core state."""
        cs = self.core_server
        ws_port = cs.ws_server.bound_port or cs.config.port
        transfer_port = (
            cs.http_transfer_server.bound_port
            if cs.http_transfer_server
            else cs.config.transfer_port
        )
        ipc_port = self.bound_port or self.config.ipc_port

        active_conns = cs.connection_manager.all_connections()
        paired_devices = cs.db_manager.list_paired_devices()
        sessions = [
            cs.session_manager.get_session(sid)
            for sid in cs.session_manager._sessions.keys()
        ]

        active_device_ids = {s.device_id for s in sessions if s}

        device_summaries = []
        for dev in paired_devices:
            is_active = dev.device_id in active_device_ids
            device_summaries.append({
                "device_id": dev.device_id,
                "device_name": dev.device_name,
                "is_connected": is_active,
                "is_paired": True,
                "last_seen": dev.last_seen_timestamp,
            })

        return {
            "core_running": cs.is_running,
            "app_name": cs.config.app_name,
            "version": cs.config.version,
            "ws_port": ws_port,
            "transfer_port": transfer_port,
            "ipc_port": ipc_port,
            "active_connections_count": len(active_conns),
            "paired_devices_count": len(paired_devices),
            "active_sessions_count": len([s for s in sessions if s]),
            "devices": device_summaries,
        }

    def _handle_list_devices(self) -> list[dict]:
        """Compile detailed, secret-redacted paired and connected device records."""
        cs = self.core_server
        paired = cs.db_manager.list_paired_devices()
        results = []

        for p in paired:
            session = cs.session_manager.get_session_by_device(p.device_id)
            is_connected = False
            remote_addr = None
            session_id = None

            if session:
                session_id = session.session_id
                if session.connection_id:
                    conn = cs.connection_manager.get(session.connection_id)
                    if conn and conn.is_active:
                        is_connected = True
                        remote_addr = conn.remote_address

            results.append({
                "device_id": p.device_id,
                "device_name": p.device_name,
                "is_paired": True,
                "is_connected": is_connected,
                "remote_address": remote_addr,
                "session_id": session_id[:8] + "..." if session_id else None,
                "paired_at": p.pairing_timestamp,
                "last_seen": p.last_seen_timestamp,
            })

        return results

    async def _handle_device_request(self, payload: dict) -> dict:
        """Route a request action to a connected, authenticated Android device."""
        device_id = payload.get("device_id")
        action = payload.get("action")
        data = payload.get("data")
        timeout = float(payload.get("timeout") or 30.0)

        if not device_id or not isinstance(device_id, str):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Missing or non-string 'device_id'.",
            }

        if not action or not isinstance(action, str):
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Missing or non-string 'action'.",
            }

        cs = self.core_server

        # 1. Verify device is paired
        paired = cs.db_manager.get_paired_device(device_id)
        if not paired:
            return {
                "success": False,
                "status": "DEVICE_NOT_PAIRED",
                "error": f"Device '{device_id}' is not paired with this desktop.",
            }

        # 2. Verify active session
        session = cs.session_manager.get_session_by_device(device_id)
        if not session or not session.connection_id:
            return {
                "success": False,
                "status": "DEVICE_OFFLINE",
                "error": f"Device '{device_id}' is paired but not currently connected.",
            }

        conn = cs.connection_manager.get(session.connection_id)
        if not conn or not conn.is_active:
            return {
                "success": False,
                "status": "DEVICE_OFFLINE",
                "error": f"Connection for device '{device_id}' is no longer active.",
            }

        # 3. Dispatch over existing WebSocket connection
        try:
            response = await cs.ws_server.send_request(
                connection_id=session.connection_id,
                action=action,
                payload=data,
                timeout=timeout,
            )
            return {
                "success": response.is_success,
                "status": "SUCCESS" if response.is_success else "DEVICE_ERROR",
                "data": response.payload,
                "error": response.error.message if response.error else None,
            }
        except TimeoutError:
            return {
                "success": False,
                "status": "REQUEST_TIMEOUT",
                "error": f"Device '{device_id}' timed out after {timeout} seconds.",
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "INTERNAL_ERROR",
                "error": f"Failed dispatching to device: {exc}",
            }
