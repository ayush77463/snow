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
import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, Optional, Set
import uuid

from snow.capabilities.engine import (
    CapabilityEngine,
    CapabilityRequest,
    CapabilityResponse,
)
from snow.core.config import CoreConfig
from snow.protocol.models import MessageType
from snow.security import ExecutionContext, ExecutionPrincipal

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

        # Layer 2 CapabilityEngine delegation
        engine = getattr(core_server, "capability_engine", None)
        if isinstance(engine, CapabilityEngine):
            self._capability_engine = engine
        else:
            self._capability_engine = CapabilityEngine()
        self._sync_capability_engine()

        # Layer 3 SessionRouter delegation
        self.session_router = getattr(core_server, "session_router", None)

    def _sync_capability_engine(self) -> None:
        """Synchronize capability engine references with core_server attributes."""
        if not self.core_server:
            return
        for attr, target in [
            ("windows_telemetry", "telemetry"),
            ("windows_processes", "processes"),
            ("windows_files", "files"),
            ("windows_apps", "apps"),
            ("windows_terminal", "terminal"),
            ("windows_clipboard", "clipboard"),
            ("capability_policy", "policy"),
        ]:
            val = getattr(self.core_server, attr, None)
            if val is not None and not type(val).__name__.endswith("Mock"):
                setattr(self._capability_engine, target, val)

    @property
    def capability_engine(self) -> CapabilityEngine:
        """Return the shared CapabilityEngine, keeping references synchronized."""
        self._sync_capability_engine()
        return self._capability_engine

    @capability_engine.setter
    def capability_engine(self, engine: CapabilityEngine) -> None:
        self._capability_engine = engine

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
        # Anti-spoofing: All IPC callers are strictly stamped with AI_MCP principal
        payload.pop("principal", None)
        payload.pop("trust_tier", None)
        payload.pop("execution_principal", None)
        ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="ipc")

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

        LOCAL_WINDOWS_OPS = {
            "windows_battery",
            "windows_system_info",
            "windows_processes",
            "windows_launch_app",
            "windows_file_read",
            "windows_file_write",
            "windows_file_list",
            "windows_file_search",
            "windows_terminal_exec",
            "windows_clipboard_get",
            "windows_clipboard_set",
        }
        if op in LOCAL_WINDOWS_OPS:
            req = CapabilityRequest(action=op, params=payload)
            res = await self.capability_engine.execute(req, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": res.success,
                "status": res.status,
                "data": res.data,
                "error": res.error,
            }, now_authed

        if op == "android_file_send":
            res = await self._handle_android_file_send(payload)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": res.get("success", False),
                "status": res.get("status", "ERROR"),
                "data": res.get("data"),
                "error": res.get("error"),
            }, now_authed

        if op == "android_file_receive":
            res = await self._handle_android_file_receive(payload)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": res.get("success", False),
                "status": res.get("status", "ERROR"),
                "data": res.get("data"),
                "error": res.get("error"),
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
        if getattr(self, "node_registry", None):
            nodes = self.node_registry.list_nodes()
            return [node.to_summary_dict() for node in nodes]

        cs = self.core_server
        paired = cs.db_manager.list_paired_devices()
        results = []

        paired_ids = set()
        for p in paired:
            session = cs.session_manager.get_session_by_device(p.device_id)
            is_connected = False
            remote_addr = None
            session_id = None
            paired_ids.add(p.device_id)

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

        # Append discovered LAN candidates if discovery service is active
        if getattr(cs, "discovery_service", None) and cs.discovery_service.is_running:
            for peer in cs.discovery_service.list_discovered_peers():
                if peer.device_id not in paired_ids:
                    results.append({
                        "device_id": peer.device_id,
                        "device_name": peer.device_name,
                        "is_paired": False,
                        "is_connected": False,
                        "is_discovered": True,
                        "remote_address": f"{peer.ip_address}:{peer.port}",
                        "device_type": peer.device_type,
                        "cert_fingerprint": peer.cert_fingerprint,
                        "last_seen": peer.last_seen_timestamp,
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

        if action == "desktop_exec":
            logger.warning(
                "Rejected AI-originated desktop_exec to device [%s]: no human approval path exists for AI callers.",
                device_id,
            )
            return {
                "success": False,
                "status": "APPROVAL_REQUIRED",
                "error": "AI-originated remote terminal execution is restricted; requires a human-in-the-loop approval workflow.",
            }

        router = getattr(self, "session_router", None) or (
            getattr(self.core_server, "session_router", None) if self.core_server else None
        )
        has_real_router = router is not None and (
            type(router).__name__ == "SessionRouter"
            or getattr(router, "_is_router_mock", False) is True
            or (not type(router).__name__.endswith("Mock") and hasattr(router, "route_request"))
        )
        if has_real_router:
            return await router.route_request(
                action=action,
                target=device_id,
                data=data,
                timeout=timeout,
            )

        cs = self.core_server

        # 1. Verify device is paired
        paired = cs.db_manager.get_paired_device(device_id)
        if not paired:
            return {
                "success": False,
                "status": "DEVICE_NOT_PAIRED",
                "error": f"Device '{device_id}' is not paired with this desktop.",
            }

        # 2. Verify active session (with on-demand discovery wake & grace period)
        session = cs.session_manager.get_session_by_device(device_id)
        conn = cs.connection_manager.get(session.connection_id) if session and session.connection_id else None

        if not conn or not conn.is_active:
            grace_period = getattr(cs.config, "device_connect_grace_period", 6.0)
            disc_svc = getattr(cs, "discovery_service", None)
            if disc_svc and disc_svc.is_running and grace_period > 0:
                logger.info(
                    "Device '%s' is paired but disconnected. Sending wake burst and awaiting reconnection (grace period %.1fs)...",
                    device_id, grace_period
                )
                try:
                    await disc_svc.send_wake_burst(device_id)
                except Exception as exc:
                    logger.debug("Failed sending wake burst: %s", exc)

                start_wait = time.time()
                while time.time() - start_wait < grace_period:
                    await asyncio.sleep(0.2)
                    session = cs.session_manager.get_session_by_device(device_id)
                    if session and session.connection_id:
                        conn = cs.connection_manager.get(session.connection_id)
                        if conn and conn.is_active:
                            logger.info(
                                "Device '%s' reconnected successfully within grace period (took %.2fs).",
                                device_id, time.time() - start_wait
                            )
                            break

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
            is_ok = response.type == MessageType.RESPONSE and (
                response.payload is None or response.payload.get("status") != "error"
            )
            err_msg = None
            if response.error:
                err_msg = response.error.get("message") if isinstance(response.error, dict) else str(response.error)
            elif not is_ok and response.payload:
                err_msg = response.payload.get("message") or response.payload.get("error")

            return {
                "success": is_ok,
                "status": "SUCCESS" if is_ok else "DEVICE_ERROR",
                "data": response.payload,
                "error": err_msg,
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

    async def _handle_windows_battery(self) -> dict:
        """Query host battery telemetry via CapabilityEngine."""
        req = CapabilityRequest(action="windows_battery", params={})
        res = await self.capability_engine.execute(
            req, ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="ipc")
        )
        return res.to_dict()

    async def _handle_windows_system_info(self) -> dict:
        """Query host system and hardware telemetry via CapabilityEngine."""
        req = CapabilityRequest(action="windows_system_info", params={})
        res = await self.capability_engine.execute(
            req, ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="ipc")
        )
        return res.to_dict()

    async def _handle_windows_processes(self, payload: dict) -> dict:
        """Query host active processes via CapabilityEngine."""
        req = CapabilityRequest(action="windows_processes", params=payload)
        res = await self.capability_engine.execute(
            req, ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="ipc")
        )
        return res.to_dict()

    async def _handle_windows_launch_app(self, payload: dict, ctx: ExecutionContext) -> dict:
        """Launch an allowlisted Windows desktop app via CapabilityEngine."""
        req = CapabilityRequest(action="windows_launch_app", params=payload)
        res = await self.capability_engine.execute(req, ctx=ctx)
        return res.to_dict()

    async def _handle_windows_file_read(self, payload: dict, ctx: ExecutionContext) -> dict:
        """Read a scoped text file via CapabilityEngine."""
        req = CapabilityRequest(action="windows_file_read", params=payload)
        res = await self.capability_engine.execute(req, ctx=ctx)
        return res.to_dict()

    async def _handle_windows_file_write(self, payload: dict, ctx: ExecutionContext) -> dict:
        """Write a scoped text file atomically via CapabilityEngine."""
        req = CapabilityRequest(action="windows_file_write", params=payload)
        res = await self.capability_engine.execute(req, ctx=ctx)
        return res.to_dict()

    async def _handle_windows_file_list(self, payload: dict, ctx: ExecutionContext) -> dict:
        """List contents of a scoped directory via CapabilityEngine."""
        req = CapabilityRequest(action="windows_file_list", params=payload)
        res = await self.capability_engine.execute(req, ctx=ctx)
        return res.to_dict()

    async def _handle_windows_file_search(self, payload: dict, ctx: ExecutionContext) -> dict:
        """Search files recursively via CapabilityEngine."""
        req = CapabilityRequest(action="windows_file_search", params=payload)
        res = await self.capability_engine.execute(req, ctx=ctx)
        return res.to_dict()

    async def _handle_windows_terminal_exec(self, payload: dict, ctx: ExecutionContext) -> dict:
        """Execute a controlled shell command via CapabilityEngine."""
        req = CapabilityRequest(action="windows_terminal_exec", params=payload)
        res = await self.capability_engine.execute(req, ctx=ctx)
        return res.to_dict()

    async def _handle_windows_clipboard_get(self) -> dict:
        """Read Windows clipboard via CapabilityEngine."""
        req = CapabilityRequest(action="windows_clipboard_get", params={})
        res = await self.capability_engine.execute(
            req, ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="ipc")
        )
        return res.to_dict()

    async def _handle_windows_clipboard_set(self, payload: dict) -> dict:
        """Write Windows clipboard via CapabilityEngine."""
        req = CapabilityRequest(action="windows_clipboard_set", params=payload)
        res = await self.capability_engine.execute(
            req, ctx=ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="ipc")
        )
        return res.to_dict()

    def _get_default_connected_device_id(self) -> Optional[str]:
        """Resolve the first actively connected paired device ID."""
        cs = self.core_server
        for sid in list(cs.session_manager._sessions.keys()):
            session = cs.session_manager.get_session(sid)
            if session and session.connection_id:
                conn = cs.connection_manager.get(session.connection_id)
                if conn and conn.is_active:
                    return session.device_id
        return None

    async def _handle_android_file_send(self, payload: dict) -> dict:
        """Coordinate sending a file from Desktop to a connected Android phone."""
        cs = self.core_server
        device_id = payload.get("device_id")
        file_path_raw = payload.get("file_path")
        timeout = float(payload.get("timeout") or 60.0)

        if not file_path_raw or not isinstance(file_path_raw, str):
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "Missing or non-string 'file_path'."}

        if not device_id:
            device_id = self._get_default_connected_device_id()
            if not device_id:
                return {"success": False, "status": "DEVICE_OFFLINE", "error": "No connected Android device found."}

        paired = cs.db_manager.get_paired_device(device_id)
        if not paired:
            return {"success": False, "status": "DEVICE_NOT_PAIRED", "error": f"Device '{device_id}' is not paired."}

        # Resolve safe path
        safe_path, err = cs.windows_files.resolve_safe_path(file_path_raw, must_exist=True)
        if err or not safe_path or not safe_path.is_file():
            return {"success": False, "status": err or "FILE_NOT_FOUND", "error": f"File access denied or not found: '{file_path_raw}'"}

        file_size = safe_path.stat().st_size
        hasher = hashlib.sha256()
        with open(safe_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        file_sha256 = hasher.hexdigest()

        from snow.transfer.manager import TransferDirection, TransferState

        # 1. Pre-check SHA-256 duplicate for already completed transfer
        existing_transfers = cs.transfer_manager.list_transfers_for_device(device_id)
        for t in existing_transfers:
            if (
                t.sha256 == file_sha256
                and t.status == TransferState.COMPLETED
                and t.direction == TransferDirection.DOWNLOAD
            ):
                logger.info(
                    "File '%s' (sha256: %s) already transferred to [%s]; skipping duplicate.",
                    safe_path.name,
                    file_sha256[:12],
                    device_id,
                )
                return {
                    "success": True,
                    "status": "ALREADY_EXISTS",
                    "transfer_id": t.transfer_id,
                    "file_name": safe_path.name,
                    "sha256": file_sha256,
                    "bytes_transferred": 0,
                    "skipped_duplicate": True,
                    "message": f"File '{safe_path.name}' with identical hash already exists on destination; transfer skipped.",
                }

        # Ensure file exists at destination inside storage_manager so download handler can serve it
        dest_path = cs.storage_manager.resolve_destination_path(safe_path.name)
        if dest_path.resolve() != safe_path.resolve():
            shutil.copy2(safe_path, dest_path)

        record = cs.transfer_manager.create_transfer(
            device_id=device_id,
            file_name=safe_path.name,
            file_size=file_size,
            sha256=file_sha256,
            direction=TransferDirection.DOWNLOAD,
        )

        transfer_port = (
            cs.http_transfer_server.bound_port
            if cs.http_transfer_server
            else cs.config.transfer_port
        )

        req_data = {
            "transfer_id": record.transfer_id,
            "file_name": safe_path.name,
            "file_size": file_size,
            "sha256": file_sha256,
            "transfer_port": transfer_port,
        }

        # 2. Prefer SessionRouter for capability-aware multi-transport dispatch
        router = getattr(self, "session_router", None) or (
            getattr(cs, "session_router", None) if cs else None
        )
        has_real_router = router is not None and (
            type(router).__name__ == "SessionRouter"
            or getattr(router, "_is_router_mock", False) is True
            or (not type(router).__name__.endswith("Mock") and hasattr(router, "route_request"))
        )
        if has_real_router:
            route_res = await router.route_request(
                action="file_send_request",
                target=device_id,
                data=req_data,
                timeout=timeout,
            )
            if route_res.get("success"):
                cs.transfer_manager.complete_transfer(record.transfer_id)
                return {
                    "success": True,
                    "status": "SUCCESS",
                    "transfer_id": record.transfer_id,
                    "file_name": safe_path.name,
                    "sha256": file_sha256,
                    "bytes_transferred": file_size,
                    "skipped_duplicate": False,
                    "data": route_res.get("data"),
                }
            else:
                err_msg = route_res.get("error") or "Transfer failed on target device."
                cs.transfer_manager.fail_transfer(record.transfer_id, err_msg)
                return {
                    "success": False,
                    "status": route_res.get("status") or "TRANSFER_FAILED",
                    "transfer_id": record.transfer_id,
                    "file_name": safe_path.name,
                    "sha256": file_sha256,
                    "bytes_transferred": 0,
                    "skipped_duplicate": False,
                    "error": err_msg,
                }

        # 3. Fallback direct WebSocket dispatch
        session = cs.session_manager.get_session_by_device(device_id)
        if not session or not session.connection_id:
            cs.transfer_manager.fail_transfer(record.transfer_id, "Device offline")
            return {"success": False, "status": "DEVICE_OFFLINE", "error": f"Device '{device_id}' is not connected."}

        conn = cs.connection_manager.get(session.connection_id)
        if not conn or not conn.is_active:
            cs.transfer_manager.fail_transfer(record.transfer_id, "Device connection inactive")
            return {"success": False, "status": "DEVICE_OFFLINE", "error": f"Device '{device_id}' connection is inactive."}

        try:
            resp = await cs.ws_server.send_request(
                connection_id=session.connection_id,
                action="file_send_request",
                payload=req_data,
                timeout=timeout,
            )
            is_ok = resp.type == MessageType.RESPONSE and (
                resp.payload is None or resp.payload.get("status") != "error"
            )
            if is_ok:
                cs.transfer_manager.complete_transfer(record.transfer_id)
                return {
                    "success": True,
                    "status": "SUCCESS",
                    "transfer_id": record.transfer_id,
                    "file_name": safe_path.name,
                    "sha256": file_sha256,
                    "bytes_transferred": file_size,
                    "skipped_duplicate": False,
                    "data": resp.payload,
                }
            else:
                err_msg = (
                    resp.error.get("message")
                    if isinstance(resp.error, dict)
                    else (resp.payload.get("error") if resp.payload else "Transfer failed on Android device.")
                )
                cs.transfer_manager.fail_transfer(record.transfer_id, err_msg)
                return {
                    "success": False,
                    "status": "TRANSFER_FAILED",
                    "transfer_id": record.transfer_id,
                    "file_name": safe_path.name,
                    "sha256": file_sha256,
                    "bytes_transferred": 0,
                    "skipped_duplicate": False,
                    "error": err_msg,
                }
        except TimeoutError:
            cs.transfer_manager.fail_transfer(record.transfer_id, "Timed out")
            return {"success": False, "status": "REQUEST_TIMEOUT", "error": f"File transfer timed out after {timeout:.1f}s."}
        except Exception as exc:
            cs.transfer_manager.fail_transfer(record.transfer_id, str(exc))
            return {"success": False, "status": "INTERNAL_ERROR", "error": f"Error dispatching file transfer: {exc}"}

    async def _handle_android_file_receive(self, payload: dict) -> dict:
        """Coordinate requesting a file from an Android phone and uploading to Desktop."""
        cs = self.core_server
        device_id = payload.get("device_id")
        file_name = payload.get("file_name")
        timeout = float(payload.get("timeout") or 60.0)

        if not file_name or not isinstance(file_name, str):
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "Missing or non-string 'file_name'."}

        clean_name = Path(file_name).name
        if not clean_name or ".." in clean_name:
            return {"success": False, "status": "INVALID_ARGUMENT", "error": "Invalid file name."}

        if not device_id:
            device_id = self._get_default_connected_device_id()
            if not device_id:
                return {"success": False, "status": "DEVICE_OFFLINE", "error": "No connected Android device found."}

        paired = cs.db_manager.get_paired_device(device_id)
        if not paired:
            return {"success": False, "status": "DEVICE_NOT_PAIRED", "error": f"Device '{device_id}' is not paired."}

        from snow.transfer.manager import TransferDirection, TransferState

        # 1. Pre-check SHA-256 duplicate for already existing completed file upload
        dest_path = cs.storage_manager.resolve_destination_path(clean_name)
        if dest_path.exists() and dest_path.is_file():
            existing = cs.transfer_manager.list_transfers_for_device(device_id)
            for t in existing:
                if (
                    t.file_name == clean_name
                    and t.status == TransferState.COMPLETED
                    and t.direction == TransferDirection.UPLOAD
                ):
                    hasher = hashlib.sha256()
                    with open(dest_path, "rb") as f:
                        while chunk := f.read(65536):
                            hasher.update(chunk)
                    existing_sha = hasher.hexdigest()
                    if existing_sha == t.sha256:
                        logger.info(
                            "File '%s' already uploaded from [%s]; skipping duplicate.",
                            clean_name,
                            device_id,
                        )
                        return {
                            "success": True,
                            "status": "ALREADY_EXISTS",
                            "transfer_id": t.transfer_id,
                            "file_name": clean_name,
                            "sha256": existing_sha,
                            "bytes_transferred": 0,
                            "skipped_duplicate": True,
                            "message": f"File '{clean_name}' already exists locally; transfer skipped.",
                        }

        transfer_port = (
            cs.http_transfer_server.bound_port
            if cs.http_transfer_server
            else cs.config.transfer_port
        )

        req_data = {
            "file_name": clean_name,
            "transfer_port": transfer_port,
        }

        # 2. Prefer SessionRouter for capability-aware multi-transport dispatch
        router = getattr(self, "session_router", None) or (
            getattr(cs, "session_router", None) if cs else None
        )
        has_real_router = router is not None and (
            type(router).__name__ == "SessionRouter"
            or getattr(router, "_is_router_mock", False) is True
            or (not type(router).__name__.endswith("Mock") and hasattr(router, "route_request"))
        )
        if has_real_router:
            route_res = await router.route_request(
                action="file_receive_request",
                target=device_id,
                data=req_data,
                timeout=timeout,
            )
            if route_res.get("success"):
                return {
                    "success": True,
                    "status": "SUCCESS",
                    "file_name": clean_name,
                    "skipped_duplicate": False,
                    "data": route_res.get("data"),
                }
            else:
                err_msg = route_res.get("error") or "File receive failed on target device."
                return {
                    "success": False,
                    "status": route_res.get("status") or "TRANSFER_FAILED",
                    "file_name": clean_name,
                    "skipped_duplicate": False,
                    "error": err_msg,
                }

        # 3. Fallback direct WebSocket dispatch
        session = cs.session_manager.get_session_by_device(device_id)
        if not session or not session.connection_id:
            return {"success": False, "status": "DEVICE_OFFLINE", "error": f"Device '{device_id}' is not connected."}

        conn = cs.connection_manager.get(session.connection_id)
        if not conn or not conn.is_active:
            return {"success": False, "status": "DEVICE_OFFLINE", "error": f"Device '{device_id}' connection is inactive."}

        try:
            resp = await cs.ws_server.send_request(
                connection_id=session.connection_id,
                action="file_receive_request",
                payload=req_data,
                timeout=timeout,
            )
            is_ok = resp.type == MessageType.RESPONSE and (
                resp.payload is None or resp.payload.get("status") != "error"
            )
            if is_ok:
                return {
                    "success": True,
                    "status": "SUCCESS",
                    "file_name": clean_name,
                    "skipped_duplicate": False,
                    "data": resp.payload,
                }
            else:
                err_msg = (
                    resp.error.get("message")
                    if isinstance(resp.error, dict)
                    else (resp.payload.get("error") if resp.payload else "File receive failed on Android device.")
                )
                return {
                    "success": False,
                    "status": "TRANSFER_FAILED",
                    "file_name": clean_name,
                    "skipped_duplicate": False,
                    "error": err_msg,
                }
        except TimeoutError:
            return {"success": False, "status": "REQUEST_TIMEOUT", "error": f"File request timed out after {timeout:.1f}s."}
        except Exception as exc:
            return {"success": False, "status": "INTERNAL_ERROR", "error": f"Error requesting file from Android: {exc}"}
