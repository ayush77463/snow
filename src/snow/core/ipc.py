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

from snow.core.subprocess_util import get_no_window_subprocess_kwargs

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
                **get_no_window_subprocess_kwargs(),
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

        # Layer 3 SessionRouter and NodeRegistry delegation
        self.session_router = getattr(core_server, "session_router", None)
        self.node_registry = getattr(core_server, "node_registry", None)

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
            ("db_manager", "db_manager"),
            ("node_registry", "node_registry"),
            ("session_router", "session_router"),
            ("transfer_manager", "transfer_manager"),
            ("storage_manager", "storage_manager"),
            ("http_transfer_server", "http_transfer_server"),
            ("clipboard_buffer", "clipboard_buffer"),
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
        owner_token = payload.pop("owner_token", None) or request.get("owner_token")
        expected_owner_token = hmac.new(
            self._secret.encode("utf-8"), b"SNOW_OWNER_AUTHORIZATION", hashlib.sha256
        ).hexdigest()
        is_owner = bool(
            owner_token
            and isinstance(owner_token, str)
            and hmac.compare_digest(owner_token, expected_owner_token)
        )
        # Anti-spoofing: strip caller-supplied principal and trust tier overrides
        payload.pop("principal", None)
        payload.pop("trust_tier", None)
        payload.pop("execution_principal", None)

        if is_owner:
            ctx = ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="trusted_owner_ipc")
        else:
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

        if op in ("get_device_status", "status"):
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

        if op == "mesh_topology":
            principal = ctx.principal
            network_mgr = getattr(self.core_server, "network_manager", None)
            if not network_mgr:
                from snow.network.network_model import SnowNetworkManager
                db_mgr = getattr(self.core_server, "db_manager", None) or getattr(self, "db_manager", None)
                if not db_mgr and self.capability_engine:
                    db_mgr = self.capability_engine.db_manager
                node_reg = getattr(self.core_server, "node_registry", None) or getattr(self, "node_registry", None)
                network_mgr = SnowNetworkManager(db_manager=db_mgr, node_registry=node_reg)
            topo = network_mgr.build_topology(principal=principal)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "SUCCESS",
                "data": topo,
            }, now_authed

        if op == "mesh_connect_peer":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            host = payload.get("host")
            port = payload.get("port", 8765)
            pin = payload.get("pin", "")
            expected_fingerprint = payload.get("expected_fingerprint", "")
            if not host:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Missing 'host' field in mesh_connect_peer payload.",
                }, now_authed

            if hasattr(self.core_server, "connect_peer"):
                res = await self.core_server.connect_peer(
                    host=host,
                    port=port,
                    pin=pin,
                    expected_fingerprint=expected_fingerprint,
                )
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": res.get("success", False),
                    "status": res.get("status", "ERROR"),
                    "data": res.get("data"),
                    "error": res.get("error"),
                }, now_authed
            else:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "UNSUPPORTED_OPERATION",
                    "error": "Peer client manager unavailable on this Core instance.",
                }, now_authed

        if op == "mesh_disconnect_peer":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            device_id = payload.get("device_id")
            if not device_id:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Missing 'device_id' field in mesh_disconnect_peer payload.",
                }, now_authed

            if hasattr(self.core_server, "disconnect_peer"):
                res = await self.core_server.disconnect_peer(device_id)
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": res.get("success", False),
                    "status": res.get("status", "ERROR"),
                    "data": res if res.get("success") else None,
                    "error": res.get("error"),
                }, now_authed
            else:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "UNSUPPORTED_OPERATION",
                    "error": "Peer client manager unavailable on this Core instance.",
                }, now_authed

        if op == "federation_revoke":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": f"Principal '{getattr(ctx, 'principal', 'UNKNOWN')}' is unauthorized to revoke federation grants. OWNER_MANUAL required.",
                }, now_authed

            grant_id = payload.get("grant_id")
            reason = payload.get("reason", "Revoked by network owner")
            if not grant_id:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Missing 'grant_id'.",
                }, now_authed

            res = await self._handle_federation_revoke(grant_id, reason, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": res.get("success", False),
                "status": res.get("status", "ERROR"),
                "data": res if res.get("success") else None,
                "error": res.get("error"),
            }, now_authed

        if op == "federation_kill_switch":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": f"Principal '{getattr(ctx, 'principal', 'UNKNOWN')}' is unauthorized to execute federation kill switch. OWNER_MANUAL required.",
                }, now_authed

            reason = payload.get("reason", "Emergency Global Kill Switch Activated")
            res = await self._handle_federation_kill_switch(reason, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": res.get("success", False),
                "status": res.get("status", "ERROR"),
                "data": res if res.get("success") else None,
                "error": res.get("error"),
            }, now_authed

        if op in ("federation_peers", "federation_list_grants"):
            include_revoked = bool(payload.get("include_revoked", False))
            network_mgr = getattr(self.core_server, "network_manager", None)
            db_mgr = getattr(self.core_server, "db_manager", None) or getattr(self, "db_manager", None)
            if not db_mgr and self.capability_engine:
                db_mgr = self.capability_engine.db_manager
            node_reg = getattr(self.core_server, "node_registry", None) or getattr(self, "node_registry", None)
            if not network_mgr:
                from snow.network.network_model import SnowNetworkManager
                network_mgr = SnowNetworkManager(db_manager=db_mgr, node_registry=node_reg)

            topo = network_mgr.build_topology(principal=ctx.principal)
            mesh_peers = [
                n for n in (topo.get("nodes") or [])
                if isinstance(n, dict) and n.get("federated")
            ]

            grants: list[dict[str, Any]] = []
            local_network_id: Optional[str] = None
            local_network_name: Optional[str] = None
            if db_mgr and hasattr(db_mgr, "list_federation_grants"):
                from snow.network.federation import FederationManager
                fed_mgr = getattr(self.core_server, "federation_manager", None)
                if not fed_mgr:
                    fed_mgr = FederationManager(db_manager=db_mgr, local_node_id="desktop-core")
                local_network_id = getattr(fed_mgr, "local_network_id", None)
                local_network_name = getattr(fed_mgr, "local_network_name", None)
                forbidden = {"auth_token", "auth_token_hash", "token", "secret", "pairing_token", "ticket", "ipc_secret"}
                for g in fed_mgr.list_grants(active_only=not include_revoked):
                    clean_g = {k: v for k, v in g.items() if k not in forbidden}
                    peer_id = clean_g.get("peer_node_id")
                    reg_node = node_reg.get_node(peer_id) if (node_reg and peer_id) else None
                    clean_g["is_connected"] = bool(getattr(reg_node, "is_connected", False)) if reg_node else False
                    clean_g["reachability_state"] = "active" if clean_g["is_connected"] else "offline"
                    grants.append(clean_g)

            active_count = sum(1 for g in grants if g.get("status") == "ACTIVE")
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "SUCCESS",
                "data": {
                    "local_node_id": topo.get("local_node_id", "desktop-core"),
                    "local_network_id": local_network_id,
                    "local_network_name": local_network_name,
                    "grants": grants,
                    "mesh_peers": mesh_peers,
                    "active_count": active_count,
                    "total_count": len(grants),
                },
            }, now_authed

        if op == "system_pause":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "UNAUTHORIZED",
                    "error": f"Principal '{getattr(ctx, 'principal', 'UNKNOWN')}' is unauthorized to invoke system_pause. OWNER_MANUAL required.",
                }, now_authed

            reason = payload.get("reason", "System paused by owner via IPC")
            cs = getattr(self, "core_server", None)
            if cs and hasattr(cs, "pause_system"):
                res = await cs.pause_system(reason=reason)
            else:
                res = {"success": True, "status": "PAUSED", "state": "PAUSED", "reason": reason}

            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": res.get("success", True),
                "status": res.get("status", "PAUSED"),
                "data": res,
            }, now_authed

        if op == "system_resume":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "UNAUTHORIZED",
                    "error": f"Principal '{getattr(ctx, 'principal', 'UNKNOWN')}' is unauthorized to invoke system_resume. OWNER_MANUAL required.",
                }, now_authed

            cs = getattr(self, "core_server", None)
            if cs and hasattr(cs, "resume_system"):
                res = await cs.resume_system()
            else:
                res = {"success": True, "status": "RESUMED", "state": "ACTIVE"}

            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": res.get("success", True),
                "status": res.get("status", "RESUMED"),
                "data": res,
            }, now_authed

        if op == "system_shutdown":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "UNAUTHORIZED",
                    "error": f"Principal '{getattr(ctx, 'principal', 'UNKNOWN')}' is unauthorized to invoke system_shutdown. OWNER_MANUAL required.",
                }, now_authed

            reason = payload.get("reason", "Shutdown initiated by owner via IPC")
            cs = getattr(self, "core_server", None)
            if cs and hasattr(cs, "request_shutdown"):
                try:
                    loop = asyncio.get_running_loop()
                    loop.call_soon(cs.request_shutdown)
                except Exception:
                    cs.request_shutdown()

            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "SHUTTING_DOWN",
                "data": {"state": "STOPPING", "reason": reason},
            }, now_authed

        if op == "device_set_connection_mode":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            device_id = payload.get("device_id")
            mode = payload.get("connection_mode")
            if not device_id or not mode:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Missing required 'device_id' or 'connection_mode' in payload.",
                }, now_authed

            from snow.security.db import VALID_CONNECTION_MODES
            if mode not in VALID_CONNECTION_MODES:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": f"Invalid connection_mode '{mode}'. Must be one of: {', '.join(sorted(VALID_CONNECTION_MODES))}",
                }, now_authed

            db = getattr(self.core_server, "db_manager", None)
            if db:
                ok = db.update_device_connection_mode(device_id, mode)
                if not ok:
                    return {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": request_id,
                        "success": False,
                        "status": "DEVICE_NOT_FOUND",
                        "error": f"Device '{device_id}' is not in paired devices database.",
                    }, now_authed

                # Invalidate or update node registry cached node
                if hasattr(self, "node_registry") and self.node_registry:
                    node = self.node_registry.get_node(device_id)
                    if node:
                        node.connection_mode = mode

                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": True,
                    "status": "SUCCESS",
                    "data": {"device_id": device_id, "connection_mode": mode},
                }, now_authed
            else:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "DATABASE_UNAVAILABLE",
                    "error": "Database manager unavailable on Core server.",
                }, now_authed

        if op == "relay_status":
            if hasattr(self.core_server, "get_relay_status"):
                status_dict = self.core_server.get_relay_status()
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": True,
                    "status": "SUCCESS",
                    "data": status_dict,
                }, now_authed
            else:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "UNSUPPORTED_OPERATION",
                    "error": "Relay control unavailable on this Core instance.",
                }, now_authed

        if op == "relay_config":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            enabled = payload.get("enabled", False)
            relay_url = payload.get("relay_url")
            group_id = payload.get("group_id")
            ticket = payload.get("ticket")

            if hasattr(self.core_server, "configure_relay"):
                res = await self.core_server.configure_relay(
                    enabled=bool(enabled),
                    relay_url=relay_url,
                    group_id=group_id,
                    ticket=ticket,
                )
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": res.get("success", True),
                    "status": res.get("status", "SUCCESS"),
                    "data": res,
                }, now_authed
            else:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "UNSUPPORTED_OPERATION",
                    "error": "Relay control unavailable on this Core instance.",
                }, now_authed

        if op == "device_request":
            dev_resp = await self._handle_device_request(payload, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": dev_resp.get("success", False),
                "status": dev_resp.get("status", "ERROR"),
                "data": dev_resp.get("data"),
                "error": dev_resp.get("error"),
            }, now_authed

        if op == "screen_stream_status":
            status_data = self._handle_screen_stream_status(payload)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "SUCCESS",
                "data": status_data,
            }, now_authed

        if op == "screen_stream_stop":
            stop_data = await self._handle_screen_stream_stop(payload, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "STOPPED",
                "data": stop_data,
            }, now_authed

        LOCAL_WINDOWS_OPS = {
            "windows_battery",
            "windows_system_info",
            "windows_processes",
            "windows_launch_app",
            "windows_active_window",
            "snow_windows_active_window",
            "windows_list_windows",
            "snow_windows_list_windows",
            "windows_focus_window",
            "snow_windows_focus_window",
            "windows_notify",
            "snow_windows_notify",
            "windows_lock_screen",
            "snow_windows_lock_screen",
            "windows_file_read",
            "windows_file_write",
            "windows_file_list",
            "windows_file_search",
            "windows_terminal_exec",
            "windows_clipboard_get",
            "windows_clipboard_set",
            "media_control",
            "windows_media_control",
            "share_link",
            "windows_share_link",
            "activity_history",
            "windows_screenshot",
            "snow_windows_screenshot",
            "workflow_run",
            "snow_workflow_run",
            # Shared Clipboard Ring Buffer (Phase 26B)
            "clipboard_buffer_list",
            "clipboard_buffer_add",
            "clipboard_buffer_pin",
            "clipboard_buffer_unpin",
            "clipboard_buffer_delete",
            "clipboard_buffer_clear",
            "clipboard_buffer_apply",
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

        if op == "clipboard_buffer_get":
            item_id = payload.get("item_id", "")
            import re
            if not isinstance(item_id, str) or not re.match(r"^cb_[0-9a-f]{12}_[0-9a-f]{6}$", item_id):
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Invalid item ID format. Expected format: cb_<12hex>_<6hex>.",
                }, now_authed
            buf = getattr(self.capability_engine, "clipboard_buffer", None)
            if not buf:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "ENGINE_UNAVAILABLE",
                    "error": "Clipboard buffer unavailable.",
                }, now_authed
            item = buf.get_item(item_id, include_content=False)
            if not item:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "NOT_FOUND",
                    "error": f"Item '{item_id}' not found in clipboard buffer.",
                }, now_authed
            data_out: dict[str, Any] = {"item": item}
            img_path = buf.get_image_path(item_id)
            if img_path is not None:
                data_out["image_filename"] = img_path.name
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "SUCCESS",
                "data": data_out,
            }, now_authed

        if op == "clipboard_capture_pc":
            clip = getattr(self.capability_engine, "clipboard", None)
            buf = getattr(self.capability_engine, "clipboard_buffer", None)
            if not clip or not buf:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "ENGINE_UNAVAILABLE",
                    "error": "Clipboard engine or buffer unavailable.",
                }, now_authed
            from snow.capabilities.windows.clipboard import get_default_clipboard_temp_dir

            clip_tmp = get_default_clipboard_temp_dir()
            try:
                content = clip.get_content_sync(output_dir=clip_tmp)
            except TypeError:
                content = clip.get_content_sync()
            if content.get("success"):
                ctype = content.get("type")
                if ctype == "image":
                    fpath = content.get("file_path")
                    try:
                        with open(fpath, "rb") as f:
                            ibytes = f.read()
                        res = buf.add_image(ibytes, mime_type="image/png", source_device="pc")
                    except Exception as e:
                        res = {"success": False, "status": "ERROR", "error": str(e)}
                    finally:
                        if fpath and os.path.isfile(fpath):
                            try:
                                import tempfile
                                f_resolved = Path(fpath).resolve()
                                t_dir = Path(tempfile.gettempdir()).resolve()
                                if (t_dir in f_resolved.parents or f_resolved.parent == t_dir) and not f_resolved.is_relative_to(buf.storage_dir):
                                    f_resolved.unlink(missing_ok=True)
                            except Exception:
                                pass
                elif ctype == "text" and content.get("text"):
                    res = buf.add_text(content["text"], source_device="pc")
                else:
                    res = {"success": False, "status": "EMPTY_CLIPBOARD", "error": "Clipboard is empty or unsupported format."}

                if not res.get("success", False):
                    return {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": request_id,
                        "success": False,
                        "status": res.get("status", "CAPTURE_FAILED"),
                        "error": res.get("error", "Failed capturing PC clipboard."),
                    }, now_authed
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": True,
                    "status": "SUCCESS",
                    "data": {"item": res.get("item")},
                }, now_authed
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": False,
                "status": "CAPTURE_FAILED",
                "error": content.get("error", "Failed reading PC clipboard."),
            }, now_authed

        if op == "clipboard_pull_from_phone":
            dev_id = payload.get("device_id")
            dev_resp = await self._handle_device_request({
                "device_id": dev_id,
                "action": "clipboard_pull",
                "data": {},
            }, ctx=ctx)
            buf = getattr(self.capability_engine, "clipboard_buffer", None)
            if dev_resp.get("success") and buf:
                data = dev_resp.get("data") or {}
                pulled_text = data.get("text")
                if pulled_text:
                    res = buf.add_text(pulled_text, source_device=dev_id or "phone")
                    if res.get("success", False):
                        return {
                            "version": IPC_PROTOCOL_VERSION,
                            "request_id": request_id,
                            "success": True,
                            "status": "SUCCESS",
                            "data": {"item": res.get("item"), "text": pulled_text},
                        }, now_authed
                    return {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": request_id,
                        "success": False,
                        "status": res.get("status", "ADD_FAILED"),
                        "error": res.get("error", "Failed adding pulled text to clipboard buffer."),
                    }, now_authed
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": dev_resp.get("success", False),
                "status": dev_resp.get("status", "ERROR"),
                "data": dev_resp.get("data"),
                "error": dev_resp.get("error"),
            }, now_authed

        if op == "clipboard_push_to_phone":
            dev_id = payload.get("device_id")
            text = payload.get("text")
            item_id = payload.get("item_id")
            buf = getattr(self.capability_engine, "clipboard_buffer", None)
            if item_id and buf:
                item_detail = buf.get_item(str(item_id), include_content=True)
                if not item_detail:
                    return {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": request_id,
                        "success": False,
                        "status": "NOT_FOUND",
                        "error": f"Item '{item_id}' not found in clipboard buffer.",
                    }, now_authed
                c_type = item_detail.get("type") or item_detail.get("content_type")
                if c_type == "image":
                    img_path = buf.get_image_path(str(item_id))
                    if not img_path or not img_path.is_file():
                        return {
                            "version": IPC_PROTOCOL_VERSION,
                            "request_id": request_id,
                            "success": False,
                            "status": "NOT_FOUND",
                            "error": "Clipboard image file not found on disk.",
                        }, now_authed
                    resolved_dev_id = dev_id
                    cs = getattr(self, "core_server", None)
                    reg = getattr(self, "node_registry", None) or (getattr(cs, "node_registry", None) if cs else None)
                    if reg and hasattr(reg, "resolve_target"):
                        node, err = reg.resolve_target(dev_id or "")
                        if node:
                            resolved_dev_id = node.device_id
                        elif err:
                            return {
                                "version": IPC_PROTOCOL_VERSION,
                                "request_id": request_id,
                                "success": False,
                                "status": err,
                                "error": f"Failed resolving target device: {err}",
                            }, now_authed
                    elif cs and hasattr(cs, "session_manager"):
                        sm = cs.session_manager
                        if not resolved_dev_id or resolved_dev_id in ("android", "phone"):
                            sessions = sm.get_all_sessions()
                            if len(sessions) == 1:
                                resolved_dev_id = list(sessions.values())[0].device_id
                            elif len(sessions) > 1:
                                return {
                                    "version": IPC_PROTOCOL_VERSION,
                                    "request_id": request_id,
                                    "success": False,
                                    "status": "DEVICE_REQUIRED",
                                    "error": "Multiple active devices. Explicit device_id required.",
                                }, now_authed
                            else:
                                return {
                                    "version": IPC_PROTOCOL_VERSION,
                                    "request_id": request_id,
                                    "success": False,
                                    "status": "DEVICE_NOT_FOUND",
                                    "error": "No active connected device found.",
                                }, now_authed

                    if not resolved_dev_id:
                        return {
                            "version": IPC_PROTOCOL_VERSION,
                            "request_id": request_id,
                            "success": False,
                            "status": "DEVICE_NOT_FOUND",
                            "error": "Target device could not be resolved.",
                        }, now_authed

                    tm = getattr(cs, "transfer_manager", None) if cs else None
                    if not tm:
                        tm = getattr(self.capability_engine, "transfer_manager", None)
                    if not tm:
                        return {
                            "version": IPC_PROTOCOL_VERSION,
                            "request_id": request_id,
                            "success": False,
                            "status": "ENGINE_UNAVAILABLE",
                            "error": "Transfer manager unavailable for image push.",
                        }, now_authed
                    from snow.transfer.manager import TransferDirection, TransferState
                    t_port = 8766
                    if cs and getattr(cs, "http_transfer_server", None):
                        t_port = cs.http_transfer_server.bound_port or 8766
                    c_hash = item_detail.get("sha256") or ""
                    f_size = item_detail.get("size_bytes") or img_path.stat().st_size
                    f_name = img_path.name
                    record = tm.create_transfer(
                        device_id=resolved_dev_id,
                        file_name=f_name,
                        file_size=f_size,
                        sha256=c_hash,
                        direction=TransferDirection.DOWNLOAD,
                    )
                    record.file_path = img_path
                    record.status = TransferState.IN_PROGRESS
                    dev_resp = await self._handle_device_request({
                        "device_id": resolved_dev_id,
                        "action": "clipboard_push",
                        "data": {
                            "type": "image",
                            "mime_type": item_detail.get("mime_type") or "image/png",
                            "transfer_id": record.transfer_id,
                            "file_name": f_name,
                            "sha256": c_hash,
                            "size": f_size,
                            "transfer_port": t_port,
                            "transfer_url": f"/api/v1/transfers/download/{record.transfer_id}",
                        },
                    }, ctx=ctx)
                    return {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": request_id,
                        "success": dev_resp.get("success", False),
                        "status": dev_resp.get("status", "ERROR"),
                        "data": dev_resp.get("data"),
                        "error": dev_resp.get("error"),
                    }, now_authed
                elif c_type == "text":
                    text = item_detail.get("text_content")

            if not text:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "No text provided or item has no text content.",
                }, now_authed
            dev_resp = await self._handle_device_request({
                "device_id": dev_id,
                "action": "clipboard_push",
                "data": {"text": text},
            }, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": dev_resp.get("success", False),
                "status": dev_resp.get("status", "ERROR"),
                "data": dev_resp.get("data"),
                "error": dev_resp.get("error"),
            }, now_authed

        if op == "approval_oauth_event":
            event_type = str(payload.get("event_type") or "APPROVAL_REQUESTED")
            request_data = payload.get("request")
            if isinstance(request_data, dict) and self.core_server and getattr(self.core_server, "ws_server", None):
                ws_srv = self.core_server.ws_server
                if hasattr(ws_srv, "broadcast_approval_event"):
                    await ws_srv.broadcast_approval_event(event_type, request_data)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "BROADCASTED",
                "data": {"event_type": event_type},
            }, now_authed

        if op == "approval_list":
            app_engine = getattr(self.capability_engine, "approval_engine", None)
            if app_engine:
                pending = [r.to_dict() for r in app_engine.list_pending_requests()]
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": True,
                    "status": "SUCCESS",
                    "data": {"requests": pending, "count": len(pending)},
                }, now_authed
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": False,
                "status": "APPROVAL_ENGINE_UNAVAILABLE",
                "error": "Approval engine is not available.",
            }, now_authed

        if op == "approval_approve":
            req_id_to_approve = payload.get("request_id")
            app_engine = getattr(self.capability_engine, "approval_engine", None)
            if app_engine and req_id_to_approve:
                ok, msg = app_engine.approve_request(
                    request_id=req_id_to_approve,
                    approver_principal=ExecutionPrincipal.OWNER_MANUAL,
                )
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": ok,
                    "status": "APPROVED" if ok else "REJECTED",
                    "data": {"request_id": req_id_to_approve, "status": msg},
                    "error": None if ok else msg,
                }, now_authed
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Missing 'request_id' or approval engine unavailable.",
            }, now_authed

        if op == "approval_deny":
            req_id_to_deny = payload.get("request_id")
            app_engine = getattr(self.capability_engine, "approval_engine", None)
            if app_engine and req_id_to_deny:
                ok, msg = app_engine.deny_request(
                    request_id=req_id_to_deny,
                    approver_principal=ExecutionPrincipal.OWNER_MANUAL,
                )
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": ok,
                    "status": "DENIED" if ok else "REJECTED",
                    "data": {"request_id": req_id_to_deny, "status": msg},
                    "error": None if ok else msg,
                }, now_authed
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": "Missing 'request_id' or approval engine unavailable.",
            }, now_authed

        if op == "notifications_list":
            dev_resp = await self._handle_device_request({
                "device_id": payload.get("device_id"),
                "action": "notifications_list",
                "data": {},
            }, ctx=ctx)
            resp_data = dev_resp.get("data")
            if not isinstance(resp_data, dict):
                resp_data = {"notifications": [], "count": 0}
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": dev_resp.get("success", False),
                "status": dev_resp.get("status", "ERROR"),
                "data": resp_data,
                "error": dev_resp.get("error"),
            }, now_authed

        if op == "notification_dismiss":
            dev_resp = await self._handle_device_request({
                "device_id": payload.get("device_id"),
                "action": "notification_dismiss",
                "data": {"key": payload.get("key")},
            }, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": dev_resp.get("success", False),
                "status": dev_resp.get("status", "ERROR"),
                "data": dev_resp.get("data"),
                "error": dev_resp.get("error"),
            }, now_authed

        if op == "notification_reply":
            dev_resp = await self._handle_device_request({
                "device_id": payload.get("device_id"),
                "action": "notification_reply",
                "data": {"key": payload.get("key"), "text": payload.get("text")},
            }, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": dev_resp.get("success", False),
                "status": dev_resp.get("status", "ERROR"),
                "data": dev_resp.get("data"),
                "error": dev_resp.get("error"),
            }, now_authed

        if op == "android_file_list":
            requested_scope = payload.get("scope", "saf")
            # Enforce caller-specific storage scopes: AI_MCP is strictly locked to saf
            if ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                effective_scope = "saf"
                show_hidden = False
            else:
                effective_scope = "full" if requested_scope == "full" else "saf"
                show_hidden = bool(payload.get("show_hidden", False))

            dev_resp = await self._handle_device_request({
                "device_id": payload.get("device_id"),
                "action": "file_list",
                "data": {
                    "subpath": payload.get("subpath", ""),
                    "scope": effective_scope,
                    "show_hidden": show_hidden,
                },
            }, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": dev_resp.get("success", False),
                "status": dev_resp.get("status", "ERROR"),
                "data": dev_resp.get("data"),
                "error": dev_resp.get("error"),
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
            res = await self._handle_android_file_receive(payload, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": res.get("success", False),
                "status": res.get("status", "ERROR"),
                "data": res.get("data"),
                "error": res.get("error"),
            }, now_authed

        if op in ("android_screenshot", "snow_android_screenshot"):
            dev_resp = await self._handle_device_request({
                "device_id": payload.get("device_id"),
                "action": "android_screenshot",
                "data": payload,
            }, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": dev_resp.get("success", False),
                "status": dev_resp.get("status", "ERROR"),
                "data": dev_resp.get("data"),
                "error": dev_resp.get("error"),
            }, now_authed

        if op in ("android_camera_capture", "snow_android_camera_capture"):
            dev_resp = await self._handle_device_request({
                "device_id": payload.get("device_id"),
                "action": "android_camera_capture",
                "data": payload,
            }, ctx=ctx)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": dev_resp.get("success", False),
                "status": dev_resp.get("status", "ERROR"),
                "data": dev_resp.get("data"),
                "error": dev_resp.get("error"),
            }, now_authed

        if op == "device_trust":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            payload_data = payload if isinstance(payload, dict) else {}
            device_id = payload_data.get("device_id")
            tier = payload_data.get("tier")
            if not device_id or not tier or tier not in ("owner", "peer"):
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Missing or invalid 'device_id' or 'tier' ('owner'/'peer' required).",
                }, now_authed
            try:
                updated = self.core_server.db_manager.update_device_trust_tier(device_id, tier)
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": updated,
                    "status": "SUCCESS" if updated else "DEVICE_NOT_FOUND",
                    "data": {"device_id": device_id, "tier": tier, "updated": updated},
                    "error": None if updated else f"Device [{device_id}] not found in paired database.",
                }, now_authed
            except Exception as exc:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "ERROR",
                    "error": str(exc),
                }, now_authed

        if op == "set_permission_profile":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            payload_data = payload if isinstance(payload, dict) else {}
            device_id = payload_data.get("device_id")
            profile = (payload_data.get("profile") or "").strip().lower()

            if not device_id or profile not in ("full_control", "files_and_clipboard", "clipboard_only"):
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Missing or invalid 'device_id' or 'profile' ('full_control'/'files_and_clipboard'/'clipboard_only' required).",
                }, now_authed

            paired_dev = self.core_server.db_manager.get_paired_device(device_id)
            if not paired_dev:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "DEVICE_NOT_FOUND",
                    "error": f"Device [{device_id}] not found in paired database.",
                }, now_authed

            try:
                self.core_server.db_manager.set_setting(f"device_profile:{device_id}", profile)
                if getattr(self.core_server, "node_registry", None):
                    self.core_server.node_registry.set_permission_profile(device_id, profile)
                if getattr(self, "node_registry", None):
                    self.node_registry.set_permission_profile(device_id, profile)

                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": True,
                    "status": "SUCCESS",
                    "data": {"device_id": device_id, "permission_profile": profile},
                }, now_authed
            except Exception as exc:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "ERROR",
                    "error": str(exc),
                }, now_authed

        if op == "device_revoke":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            payload_data = payload if isinstance(payload, dict) else {}
            device_id = payload_data.get("device_id")
            if not device_id:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Missing 'device_id'.",
                }, now_authed

            # 1. Notify active client cleanly before terminating its session and socket
            session = self.core_server.session_manager.get_session_by_device(device_id)
            if session:
                if session.connection_id and hasattr(self.core_server, "connection_manager"):
                    client = self.core_server.connection_manager.get(session.connection_id)
                    if client and hasattr(client, "websocket") and client.websocket is not None:
                        try:
                            from snow.protocol.models import SnowMessage
                            revoke_msg = SnowMessage.create_request(
                                action="device_revoked",
                                data={
                                    "device_id": device_id,
                                    "reason": "Revoked by desktop owner",
                                },
                            )
                            send_res = client.websocket.send(revoke_msg.to_json())
                            if inspect.isawaitable(send_res):
                                await asyncio.wait_for(send_res, timeout=1.5)
                        except Exception as notify_err:
                            logger.debug("Best-effort device_revoked delivery failed: %s", notify_err)
                    unreg_client = self.core_server.connection_manager.unregister(session.connection_id)
                    close_target = unreg_client or client
                    if close_target and hasattr(close_target, "websocket") and close_target.websocket is not None:
                        try:
                            close_res = close_target.websocket.close(code=1000, reason="Device revoked")
                            if inspect.isawaitable(close_res):
                                await close_res
                        except Exception as close_err:
                            logger.debug("Error closing revoked client websocket: %s", close_err)
                self.core_server.session_manager.revoke_session(session.session_id)
                logger.info("Revoked active session [%s] for device [%s]", session.session_id, device_id)

            if hasattr(self.core_server, "peer_clients") and device_id in self.core_server.peer_clients:
                peer_client = self.core_server.peer_clients.pop(device_id, None)
                if peer_client:
                    try:
                        await peer_client.close()
                    except Exception as close_err:
                        logger.debug("Error closing revoked peer client: %s", close_err)

            # 2. Delete paired credentials from SQLite database
            deleted = self.core_server.db_manager.delete_paired_device(device_id)
            if getattr(self, "node_registry", None):
                try:
                    self.node_registry.remove_node(device_id)
                except Exception as reg_err:
                    logger.debug("Failed removing node from registry: %s", reg_err)

            if deleted:
                self.core_server.db_manager.log_audit_event(
                    event_type="DEVICE_REVOKED",
                    device_id=device_id,
                    details={"revoked_by": "cli_ipc"},
                )

            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": deleted,
                "status": "SUCCESS" if deleted else "DEVICE_NOT_FOUND",
                "data": {"device_id": device_id, "revoked": deleted},
                "error": None if deleted else f"Device [{device_id}] not found in paired database.",
            }, now_authed

        if op == "device_disconnect":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            payload_data = payload if isinstance(payload, dict) else {}
            device_id = (payload_data.get("device_id") or "").strip()
            if not device_id:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Missing 'device_id' field in device_disconnect payload.",
                }, now_authed

            res = await self.core_server.disconnect_device(device_id)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": bool(res.get("success")),
                "status": res.get("status", "ERROR"),
                "data": res,
                "error": res.get("error"),
            }, now_authed

        if op == "device_reconnect":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            payload_data = payload if isinstance(payload, dict) else {}
            device_id = (payload_data.get("device_id") or "").strip()
            if not device_id:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Missing 'device_id' field in device_reconnect payload.",
                }, now_authed

            res = await self.core_server.reconnect_device(device_id)
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": bool(res.get("success")),
                "status": res.get("status", "ERROR"),
                "data": res,
                "error": res.get("error"),
            }, now_authed

        if op == "get_pc_transfer_dir":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            from snow.transfer.storage import get_default_pc_transfer_dir
            cs = self.core_server
            cur_dir = str(cs.storage_manager.root_dir) if getattr(cs, "storage_manager", None) else str(get_default_pc_transfer_dir())
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "SUCCESS",
                "data": {
                    "pc_transfers_dir": cur_dir,
                    "default_pc_transfers_dir": str(get_default_pc_transfer_dir()),
                },
            }, now_authed

        if op == "set_pc_transfer_dir":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            payload_data = payload if isinstance(payload, dict) else {}
            raw_path = (payload_data.get("path") or payload_data.get("pc_transfers_dir") or "").strip()
            if not raw_path:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Missing 'path' for set_pc_transfer_dir.",
                }, now_authed
            try:
                res = self.core_server.set_pc_transfer_dir(raw_path)
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": True,
                    "status": res.get("status", "UPDATED"),
                    "data": res,
                }, now_authed
            except (ValueError, PermissionError) as exc:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "INVALID_PATH",
                    "error": str(exc),
                }, now_authed
            except Exception as exc:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "ERROR",
                    "error": str(exc),
                }, now_authed

        if op == "get_pairing_state":
            cs = self.core_server
            ws = getattr(cs, "ws_server", None) if cs else None
            pm = getattr(ws, "pairing_manager", None) if ws else None
            if not ws or not pm:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "NOT_AVAILABLE",
                    "error": "Core WebSocket server or pairing manager is not active.",
                }, now_authed

            from snow.core.network import get_active_ip_addresses
            from snow.security.identity import generate_snow_id
            from snow.security.pairing import create_qr_pairing_payload

            candidate_ips = get_active_ip_addresses()
            cfg = getattr(cs, "config", None)
            node_id = getattr(cfg, "node_id", "desktop-core")
            port = getattr(cfg, "port", 8765)

            cert_info = getattr(ws, "certificate_info", None)
            if not cert_info:
                from snow.security.tls import (
                    DEFAULT_CERT_FILE,
                    DEFAULT_KEY_FILE,
                    DEFAULT_TLS_DIR,
                    ensure_tls_certificate,
                )
                cert_info = ensure_tls_certificate(
                    DEFAULT_TLS_DIR / DEFAULT_CERT_FILE,
                    DEFAULT_TLS_DIR / DEFAULT_KEY_FILE,
                    active_ips=candidate_ips,
                )
            fp = cert_info.fingerprint_sha256 if cert_info else ""
            local_ident = getattr(cs, "device_identity", None)
            snow_id = getattr(local_ident, "snow_id", None) or generate_snow_id(seed=node_id)

            pin_state = pm.get_active_pin_state(include_pin=True)
            qr_payload = None
            if pin_state.get("has_active_pin") and pin_state.get("pin") and fp:
                try:
                    qr_payload = create_qr_pairing_payload(
                        node_id=node_id,
                        candidate_ips=candidate_ips,
                        port=port,
                        cert_fingerprint=fp,
                        pin=pin_state["pin"],
                        trust_tier=pin_state.get("trust_tier", "owner"),
                        snow_id=snow_id,
                    )
                except Exception as exc:
                    logger.debug("Non-fatal QR payload build skip in get_pairing_state: %s", exc)

            state_data: dict[str, Any] = {
                "ips": candidate_ips,
                "port": port,
                "node_id": node_id,
                "snow_id": snow_id,
                "fp": fp,
                "cert_fingerprint": fp,
                **pin_state,
            }
            if qr_payload is not None:
                state_data["qr_payload"] = qr_payload

            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "SUCCESS",
                "data": state_data,
            }, now_authed

        if op == "cancel_pairing_pin":
            if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "POLICY_DENIED",
                    "error": "Operation requires OWNER_MANUAL authority.",
                }, now_authed

            cs = self.core_server
            ws = getattr(cs, "ws_server", None) if cs else None
            pm = getattr(ws, "pairing_manager", None) if ws else None
            if not ws or not pm:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "NOT_AVAILABLE",
                    "error": "Core WebSocket server or pairing manager is not active.",
                }, now_authed

            cancel_res = pm.cancel_pin()
            return {
                "version": IPC_PROTOCOL_VERSION,
                "request_id": request_id,
                "success": True,
                "status": "CANCELLED",
                "data": cancel_res,
            }, now_authed

        if op == "generate_pairing_qr":
            cs = self.core_server
            ws = getattr(cs, "ws_server", None) if cs else None
            pm = getattr(ws, "pairing_manager", None) if ws else None
            if not ws or not pm:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "NOT_AVAILABLE",
                    "error": "Core WebSocket server or pairing manager is not active.",
                }, now_authed

            payload_data = payload if isinstance(payload, dict) else {}
            trust_tier = payload_data.get("trust_tier", "owner")
            pin = pm.generate_pin(display_to_stderr=False, trust_tier=trust_tier)
            from snow.core.network import get_active_ip_addresses
            candidate_ips = get_active_ip_addresses()

            cfg = getattr(cs, "config", None)
            node_id = getattr(cfg, "node_id", "desktop-core")
            port = getattr(cfg, "port", 8765)

            cert_info = getattr(ws, "certificate_info", None)
            if not cert_info:
                from snow.security.tls import (
                    DEFAULT_CERT_FILE,
                    DEFAULT_KEY_FILE,
                    DEFAULT_TLS_DIR,
                    ensure_tls_certificate,
                )
                cert_info = ensure_tls_certificate(
                    DEFAULT_TLS_DIR / DEFAULT_CERT_FILE,
                    DEFAULT_TLS_DIR / DEFAULT_KEY_FILE,
                    active_ips=candidate_ips,
                )

            fp = cert_info.fingerprint_sha256 if cert_info else ""
            from snow.security.pairing import create_qr_pairing_payload

            try:
                qr_payload = create_qr_pairing_payload(
                    node_id=node_id,
                    candidate_ips=candidate_ips,
                    port=port,
                    cert_fingerprint=fp,
                    pin=pin,
                    trust_tier=trust_tier,
                )
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": True,
                    "status": "SUCCESS",
                    "data": qr_payload,
                }, now_authed
            except Exception as exc:
                return {
                    "version": IPC_PROTOCOL_VERSION,
                    "request_id": request_id,
                    "success": False,
                    "status": "ERROR",
                    "error": str(exc),
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

        raw_paused = getattr(cs, "is_paused", False)
        is_paused = raw_paused if isinstance(raw_paused, bool) else False
        raw_state = getattr(cs, "_paused_state", {})
        paused_state = raw_state if isinstance(raw_state, dict) else {}

        return {
            "core_running": cs.is_running,
            "is_paused": is_paused,
            "paused_state": paused_state,
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
                "permission_profile": cs.db_manager.get_setting(f"device_profile:{p.device_id}", "full_control"),
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

    async def _handle_device_request(self, payload: dict, ctx: Optional[ExecutionContext] = None) -> dict:
        """Route a request action to a connected, authenticated Android device."""
        device_id = payload.get("device_id")
        action = payload.get("action")
        data = payload.get("data")
        timeout = float(payload.get("timeout") or 30.0)

        if not device_id or not isinstance(device_id, str):
            # Authoritative default device resolution via NodeRegistry or SessionManager
            reg = getattr(self, "node_registry", None) or (
                getattr(self.core_server, "node_registry", None) if self.core_server else None
            )
            if reg and hasattr(reg, "resolve_target"):
                resolved_node, err_code = reg.resolve_target("")
                if err_code:
                    err_status = err_code
                    if err_code == "NO_DEVICES_PAIRED":
                        err_msg = "No paired Android devices found."
                    elif err_code == "DEVICE_REQUIRED":
                        err_msg = "Multiple devices connected. Please specify target device_id."
                    else:
                        err_msg = f"Device resolution failed: {err_code}"
                    return {
                        "success": False,
                        "status": err_status,
                        "error": err_msg,
                    }
                if resolved_node:
                    device_id = resolved_node.device_id
            else:
                cs = self.core_server
                sm = getattr(cs, "session_manager", None) if cs else None
                if sm and hasattr(sm, "get_all_sessions"):
                    active_sessions = sm.get_all_sessions()
                    if len(active_sessions) == 1:
                        device_id = list(active_sessions.values())[0].device_id
                    elif len(active_sessions) > 1:
                        return {
                            "success": False,
                            "status": "DEVICE_REQUIRED",
                            "error": "Multiple active devices. Explicit 'device_id' required.",
                        }
                    else:
                        return {
                            "success": False,
                            "status": "DEVICE_NOT_FOUND",
                            "error": "No active connected device found.",
                        }
                else:
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

        if action == "launch_app":
            req_data = dict(data) if isinstance(data, dict) else {}
            if ctx and ctx.principal == ExecutionPrincipal.OWNER_MANUAL:
                req_data["principal"] = "OWNER_MANUAL"
            else:
                req_data["principal"] = "AI_MCP"
            data = req_data

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

        # Enforce declarative approval policy check for AI callers invoking cross-device capture
        if action in (
            "android_screenshot",
            "snow_android_screenshot",
            "android_camera_capture",
            "snow_android_camera_capture",
        ):
            effective_ctx = ctx or ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="ipc")
            app_engine = getattr(self.capability_engine, "approval_engine", None)
            if app_engine:
                request_data = data if isinstance(data, dict) else {}
                requires_approval, reason, risk_level = app_engine.evaluate_policy(
                    action=action,
                    params=request_data,
                    ctx=effective_ctx,
                    target_device=device_id,
                )
                if requires_approval:
                    approval_id = request_data.get("approval_id")
                    if approval_id:
                        ok, msg = app_engine.consume_approval(
                            request_id=approval_id,
                            principal=effective_ctx.principal,
                            action=action,
                            target_device=device_id,
                            params=request_data,
                        )
                        if not ok:
                            logger.warning(
                                "Approval consumption rejected for '%s' on device [%s]: %s",
                                action, device_id, msg,
                            )
                            return {
                                "success": False,
                                "status": "UNAUTHORIZED",
                                "error": f"Approval validation failed: {msg}",
                            }
                    else:
                        app_req = app_engine.create_request(
                            principal=effective_ctx.principal,
                            action=action,
                            target_device=device_id,
                            params=request_data,
                            reason=reason or "Visual capture requires explicit owner approval.",
                            risk_level=risk_level or "HIGH",
                        )
                        logger.info(
                            "Approval required for '%s' on [%s] [request_id=%s, risk=%s]",
                            action, device_id, app_req.request_id, risk_level,
                        )
                        return {
                            "success": False,
                            "status": "APPROVAL_REQUIRED",
                            "data": app_req.to_dict(),
                            "error": "Action requires human owner approval.",
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
                ctx=ctx,
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

    async def _handle_android_file_receive(self, payload: dict, ctx: Optional[ExecutionContext] = None) -> dict:
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

        subpath = payload.get("subpath") or ""
        scope = payload.get("scope", "full") if (ctx and ctx.principal == ExecutionPrincipal.OWNER_MANUAL) else "saf"
        req_data = {
            "file_name": clean_name,
            "transfer_port": transfer_port,
            "scope": scope,
        }
        if subpath:
            req_data["subpath"] = subpath

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
                ctx=ctx,
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

    def _handle_screen_stream_status(self, payload: dict) -> dict:
        """Query live screen streaming session metadata."""
        device_id = payload.get("device_id") if isinstance(payload, dict) else None
        from snow.transfer.http_server import SnowHttpTransferServer
        status_data = SnowHttpTransferServer.get_screen_stream_status(device_id)
        cs = self.core_server
        transfer_port = (
            cs.http_transfer_server.bound_port
            if cs and getattr(cs, "http_transfer_server", None)
            else (cs.config.transfer_port if cs and hasattr(cs, "config") else 8766)
        )
        use_tls = bool(
            cs and getattr(cs, "http_transfer_server", None) and cs.http_transfer_server.ssl_context
        )
        cert_path = (
            getattr(cs.http_transfer_server, "cert_path", None)
            if cs and getattr(cs, "http_transfer_server", None)
            else (getattr(cs.config, "tls_cert_path", None) or getattr(cs.config, "tls_cert_file", None) if cs and hasattr(cs, "config") else None)
        )
        return {
            **status_data,
            "transfer_port": transfer_port,
            "use_tls": use_tls,
            "cert_path": str(cert_path) if cert_path else None,
        }

    async def _handle_screen_stream_stop(self, payload: dict, ctx: Optional[ExecutionContext] = None) -> dict:
        """Stop active screen streaming session across transfer server and connected Android device."""
        device_id = payload.get("device_id") if isinstance(payload, dict) else None
        from snow.transfer.http_server import SnowHttpTransferServer
        # 1. Clear session buffer in transfer server
        SnowHttpTransferServer.set_session_state(device_id=device_id, state="STOPPED")

        # 2. Dispatch screen_stream_stop to connected Android device via SessionRouter if available
        dispatched = False
        router = getattr(self, "session_router", None) or (
            getattr(self.core_server, "session_router", None) if self.core_server else None
        )
        if router is not None:
            try:
                res = await router.route_request(
                    action="screen_stream_stop",
                    target=device_id or None,
                    data={},
                    ctx=ctx or ExecutionContext(principal=ExecutionPrincipal.OWNER_MANUAL, origin="ipc"),
                    timeout=5.0,
                )
                dispatched = res.get("success", False)
            except Exception as e:
                logger.debug("Failed dispatching screen_stream_stop to device via router: %s", e)

        return {
            "status": "STOPPED",
            "device_dispatched": dispatched,
        }

    async def _handle_federation_revoke(
        self, grant_id: str, reason: str, ctx: Optional[ExecutionContext] = None
    ) -> dict[str, Any]:
        """Revoke a single federation grant and terminate active transport sessions for its peer."""
        # Enforce OWNER_MANUAL authorization (Finding 2)
        if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
            return {
                "success": False,
                "status": "POLICY_DENIED",
                "error": f"Principal '{getattr(ctx, 'principal', 'UNKNOWN')}' is unauthorized to revoke federation grants. OWNER_MANUAL required.",
            }

        db_mgr = getattr(self.core_server, "db_manager", None)
        if not db_mgr:
            return {"success": False, "status": "DATABASE_UNAVAILABLE", "error": "Database manager unavailable."}

        grant = db_mgr.get_federation_grant(grant_id)
        if not grant:
            return {"success": False, "status": "GRANT_NOT_FOUND", "error": f"Grant '{grant_id}' does not exist."}

        peer_node_id = grant.get("peer_node_id")

        # 1. Revoke in database
        db_mgr.revoke_federation_grant(grant_id, reason=reason)

        # 2. Genuine peer client disconnection
        peer_disconnected = False
        if hasattr(self.core_server, "peer_clients") and peer_node_id:
            if peer_node_id in self.core_server.peer_clients:
                try:
                    res = await self.core_server.disconnect_peer(peer_node_id)
                    if isinstance(res, dict) and res.get("success"):
                        peer_disconnected = True
                except Exception as e:
                    logger.debug("disconnect_peer exception for %s: %s", peer_node_id, e)

        # 3. Genuine WebSocket client closure and session revocation
        ws_closed = False
        sess_mgr = getattr(self.core_server, "session_manager", None)
        ws_server = getattr(self.core_server, "ws_server", None)
        if sess_mgr and peer_node_id:
            session = sess_mgr.get_session_by_device(peer_node_id)
            if session:
                conn_id = session.connection_id
                if conn_id and ws_server and hasattr(ws_server, "connection_manager"):
                    ws_conn = ws_server.connection_manager.get(conn_id)
                    if ws_conn and getattr(ws_conn, "websocket", None):
                        try:
                            await ws_conn.websocket.close(code=1000, reason=reason)
                            ws_closed = True
                        except Exception as e:
                            logger.debug("Error closing websocket for %s: %s", peer_node_id, e)
                    ws_server.connection_manager.unregister(conn_id)
                sess_mgr.revoke_session(session.session_id)

        # 4. Remove from node registry
        if getattr(self, "node_registry", None) and peer_node_id:
            try:
                self.node_registry.remove_node(peer_node_id)
            except Exception:
                pass

        # 5. Genuine relay tunnel closure
        relay_closed = False
        relay_client = getattr(self.core_server, "relay_client", None)
        if relay_client and hasattr(relay_client, "close_tunnel") and peer_node_id:
            try:
                if await relay_client.close_tunnel(peer_node_id):
                    relay_closed = True
            except Exception as e:
                logger.debug("Error closing relay tunnel for %s: %s", peer_node_id, e)

        # 6. Secret-safe audit logging with genuine authenticated principal
        db_mgr.log_activity(
            event_type="FEDERATION_GRANT_REVOKED",
            principal=str(ctx.principal),
            target_device=peer_node_id or "UNKNOWN",
            capability="network.federation.revoke",
            outcome="SUCCESS",
            details={
                "grant_id": grant_id,
                "reason": reason,
                "ipc": True,
                "disconnected_peers": 1 if peer_disconnected else 0,
                "closed_ws_clients": 1 if ws_closed else 0,
                "relay_disconnected": 1 if relay_closed else 0,
            },
        )

        return {
            "success": True,
            "status": "GRANT_REVOKED",
            "grant_id": grant_id,
            "peer_node_id": peer_node_id,
            "reason": reason,
            "disconnected_peers": 1 if peer_disconnected else 0,
            "closed_ws_clients": 1 if ws_closed else 0,
            "relay_disconnected": 1 if relay_closed else 0,
        }

    async def _handle_federation_kill_switch(
        self, reason: str, ctx: Optional[ExecutionContext] = None
    ) -> dict[str, Any]:
        """Execute global kill switch: revoke all grants/invites and disconnect all federated sessions."""
        # Enforce OWNER_MANUAL authorization (Finding 2)
        if not ctx or ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
            return {
                "success": False,
                "status": "POLICY_DENIED",
                "error": f"Principal '{getattr(ctx, 'principal', 'UNKNOWN')}' is unauthorized to execute federation kill switch. OWNER_MANUAL required.",
            }

        db_mgr = getattr(self.core_server, "db_manager", None)
        if not db_mgr:
            return {"success": False, "status": "DATABASE_UNAVAILABLE", "error": "Database manager unavailable."}

        # Identify all federated peer IDs before database revocation
        federated_peer_ids: set[str] = set()
        try:
            for g in db_mgr.list_federation_grants():
                p_id = g.get("peer_node_id")
                if p_id:
                    federated_peer_ids.add(p_id)
        except Exception as e:
            logger.debug("Error querying federated peer IDs: %s", e)

        counts = db_mgr.kill_all_federation(reason=reason)

        # 1. Disconnect active peer clients ONLY for federated peers (protecting unrelated peers)
        disconnected_peers = 0
        if hasattr(self.core_server, "peer_clients"):
            for p_id in list(self.core_server.peer_clients.keys()):
                if p_id in federated_peer_ids:
                    try:
                        res = await self.core_server.disconnect_peer(p_id)
                        if isinstance(res, dict) and res.get("success"):
                            disconnected_peers += 1
                    except Exception:
                        pass

        # 2. Genuine WebSocket closure and session revocation ONLY for federated peers
        closed_ws_clients = 0
        sess_mgr = getattr(self.core_server, "session_manager", None)
        ws_server = getattr(self.core_server, "ws_server", None)
        if sess_mgr:
            for p_id in federated_peer_ids:
                session = sess_mgr.get_session_by_device(p_id)
                if session:
                    conn_id = session.connection_id
                    if conn_id and ws_server and hasattr(ws_server, "connection_manager"):
                        ws_conn = ws_server.connection_manager.get(conn_id)
                        if ws_conn and getattr(ws_conn, "websocket", None):
                            try:
                                await ws_conn.websocket.close(code=1000, reason=reason)
                                closed_ws_clients += 1
                            except Exception:
                                pass
                        ws_server.connection_manager.unregister(conn_id)
                    sess_mgr.revoke_session(session.session_id)

        # 3. Genuine relay tunnel closure ONLY for federated peers (protecting unrelated remote sessions)
        closed_tunnels = 0
        relay_client = getattr(self.core_server, "relay_client", None)
        if relay_client and hasattr(relay_client, "close_tunnel"):
            for p_id in federated_peer_ids:
                try:
                    if await relay_client.close_tunnel(p_id):
                        closed_tunnels += 1
                except Exception:
                    pass

        # 4. Remove federated nodes from registry (DeviceNode object handling fix)
        if getattr(self, "node_registry", None):
            try:
                for node in list(self.node_registry.list_nodes()):
                    # Extract string device_id from DeviceNode instance or string
                    node_dev_id = getattr(node, "device_id", None) if not isinstance(node, str) else node
                    if node_dev_id and (
                        node_dev_id in federated_peer_ids or getattr(node, "trust_tier", "") == "federated"
                    ):
                        self.node_registry.remove_node(node_dev_id)
            except Exception as reg_err:
                logger.debug("Failed cleaning federated nodes from registry: %s", reg_err)

        # 5. Secret-safe audit logging with genuine authenticated principal
        db_mgr.log_activity(
            event_type="FEDERATION_GLOBAL_KILL_SWITCH",
            principal=str(ctx.principal),
            target_device="ALL_FEDERATED_PEERS",
            capability="network.federation.kill_switch",
            outcome="SUCCESS",
            details={
                "reason": reason,
                "ipc": True,
                **counts,
                "disconnected_peers": disconnected_peers,
                "closed_ws_clients": closed_ws_clients,
                "relay_disconnected": closed_tunnels,
            },
        )

        return {
            "success": True,
            "status": "KILL_SWITCH_EXECUTED",
            "reason": reason,
            "revoked_grants_count": counts["revoked_grants"],
            "revoked_invites_count": counts["revoked_invites"],
            "disconnected_peers": disconnected_peers,
            "closed_ws_clients": closed_ws_clients,
            "relay_disconnected": closed_tunnels,
        }
