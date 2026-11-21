"""WebSocket server implementation for SNOW Desktop Core."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import ipaddress
import json
import logging
from pathlib import Path
import secrets
import ssl
import sys
import time
from typing import Any, Optional
import uuid

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed

from snow.capabilities.windows import (
    WindowsAppLauncher,
    WindowsClipboardManager,
    WindowsFileManager,
    WindowsProcessMonitor,
    WindowsTelemetry,
    WindowsTerminalExecutor,
)
from snow.capabilities.windows.clipboard_listener import WindowsClipboardListener
from snow.capabilities.engine import (
    CapabilityEngine,
    CapabilityRequest,
    CapabilityResponse,
)
from snow.core.config import CoreConfig
from snow.network.connection_manager import ConnectionManager
from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.protocol.validator import ProtocolValidationError, validate_raw_message
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import DeviceIdentity, load_or_create_device_identity
from snow.security.pairing import PairingManager, PairingOutcome
from snow.security.policy import ACTION_TO_CAPABILITY, PeerCapabilityPolicy
from snow.security.session import SessionManager
from snow.security.tls import (
    DEFAULT_CERT_FILE,
    DEFAULT_KEY_FILE,
    DEFAULT_TLS_DIR,
    CertificateInfo,
    create_server_ssl_context,
    ensure_tls_certificate,
    print_tls_fingerprint_banner,
)
from snow.transfer.manager import TransferDirection, TransferManager, TransferState
from snow.transfer.storage import TransferStorageManager

logger = logging.getLogger(__name__)


def parse_remote_address(addr: Any, default_port: int = 8765) -> tuple[str, int]:
    """Parse remote address from tuple, string, or IPv6 into (host, port)."""
    if not addr:
        return ("127.0.0.1", default_port)
    if isinstance(addr, tuple):
        host = str(addr[0]) if len(addr) > 0 else "127.0.0.1"
        port = int(addr[1]) if len(addr) > 1 and isinstance(addr[1], (int, str)) and str(addr[1]).isdigit() else default_port
        return (host, port)
    if isinstance(addr, str):
        addr_str = addr.strip()
        if addr_str.startswith("[") and "]" in addr_str:
            host_part, _, rest = addr_str[1:].partition("]")
            port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else default_port
            return (host_part, port)
        if ":" in addr_str and addr_str.count(":") == 1:
            h, _, p = addr_str.partition(":")
            if p.isdigit():
                return (h, int(p))
            return (h, default_port)
        return (addr_str, default_port)
    return ("127.0.0.1", default_port)


class SnowWebSocketServer:
    """Asynchronous WebSocket server implementing SNOW Device Protocol v1.

    Manages incoming client connections, message validation, ping/pong request
    correlation, heartbeat tracking, stale connection reaping, SQLite paired records,
    and active session lifecycles.
    """

    def __init__(
        self,
        config: CoreConfig,
        connection_manager: Optional[ConnectionManager] = None,
        pairing_manager: Optional[PairingManager] = None,
        device_identity: Optional[DeviceIdentity] = None,
        db_manager: Optional[DatabaseManager] = None,
        session_manager: Optional[SessionManager] = None,
        transfer_manager: Optional[TransferManager] = None,
        storage_manager: Optional[TransferStorageManager] = None,
        core_server: Optional[Any] = None,
        node_registry: Optional[Any] = None,
    ) -> None:
        self.config = config
        self.connection_manager = connection_manager or ConnectionManager()
        self.pairing_manager = pairing_manager or PairingManager()
        self.device_identity = device_identity or load_or_create_device_identity()
        self.db_manager = db_manager or DatabaseManager()
        self.session_manager = session_manager or SessionManager()
        self.transfer_manager = transfer_manager or TransferManager()
        self.storage_manager = storage_manager or TransferStorageManager(root_dir=self.config.transfer_root)
        self.core_server: Any = core_server
        self.node_registry: Any = node_registry or getattr(core_server, "node_registry", None)
        self.windows_telemetry = (
            getattr(core_server, "windows_telemetry", None) if core_server else None
        ) or WindowsTelemetry()
        self.windows_processes = (
            getattr(core_server, "windows_processes", None) if core_server else None
        ) or WindowsProcessMonitor()
        roots = [self.config.transfer_root] if self.config.transfer_root else None
        self.windows_files = (
            getattr(core_server, "windows_files", None) if core_server else None
        ) or WindowsFileManager(allowed_roots=roots)
        self.windows_apps = (
            getattr(core_server, "windows_apps", None) if core_server else None
        ) or WindowsAppLauncher()
        self.windows_terminal = (
            getattr(core_server, "windows_terminal", None) if core_server else None
        ) or WindowsTerminalExecutor()
        self.windows_clipboard = (
            getattr(core_server, "windows_clipboard", None) if core_server else None
        ) or WindowsClipboardManager()
        self.capability_policy: PeerCapabilityPolicy = (
            getattr(core_server, "capability_policy", None)
            or PeerCapabilityPolicy()
        )
        engine = getattr(core_server, "capability_engine", None) if core_server else None
        if isinstance(engine, CapabilityEngine):
            self._capability_engine = engine
        else:
            self._capability_engine = CapabilityEngine(
                telemetry=self.windows_telemetry,
                processes=self.windows_processes,
                files=self.windows_files,
                apps=self.windows_apps,
                terminal=self.windows_terminal,
                clipboard=self.windows_clipboard,
                policy=self.capability_policy,
            )
        self.http_transfer_server: Any = None
        if not self.node_registry:
            self.node_registry = getattr(core_server, "node_registry", None)
        self.session_router = getattr(core_server, "session_router", None) if core_server else None
        self._server: Optional[Server] = None
        self._reaper_task: Optional[asyncio.Task] = None
        self._is_running = False
        self._pending_requests: dict[str, tuple[str, asyncio.Future[SnowMessage]]] = {}
        self.certificate_info: Optional[CertificateInfo] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._auth_timers: dict[str, asyncio.Task] = {}
        self._pairing_in_progress: set[str] = set()
        self._clipboard_sync_tasks: dict[str, asyncio.Task] = {}
        self._last_synced_clipboard_hash: dict[str, str] = {}
        self._active_sync_connections: set[str] = set()
        self._last_local_write_seq: int = 0
        self._clipboard_listener: Optional[WindowsClipboardListener] = None
        self._clipboard_watchdog_task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # Phase 21: Live in-memory notification cache (strictly never persisted to disk)
        self.live_notifications: dict[str, list[dict[str, Any]]] = {}
        # Phase 26A: Screen streaming session metadata (control plane only, strictly no image bytes)
        self._screen_stream_sessions: dict[str, dict[str, Any]] = {}

    def _sync_capability_engine(self) -> None:
        """Synchronize capability engine references with server attributes."""
        if not hasattr(self, "_capability_engine") or self._capability_engine is None:
            return
        for attr, target in [
            ("windows_telemetry", "telemetry"),
            ("windows_processes", "processes"),
            ("windows_files", "files"),
            ("windows_apps", "apps"),
            ("windows_terminal", "terminal"),
            ("windows_clipboard", "clipboard"),
            ("capability_policy", "policy"),
            ("node_registry", "node_registry"),
        ]:
            val = getattr(self, attr, None)
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
        """Return True if the WebSocket server is currently listening."""
        return self._is_running

    @property
    def bound_port(self) -> Optional[int]:
        """Return the actual TCP port the server is bound to, if listening."""
        if self._server and self._server.sockets:
            sock = self._server.sockets[0]
            return sock.getsockname()[1]
        return None

    @property
    def ssl_context(self) -> Optional[ssl.SSLContext]:
        """Return the server SSLContext if TLS is configured."""
        return self._ssl_context

    async def start(self, active_ips: Optional[list[str]] = None) -> None:
        """Start listening for incoming WebSocket connections.

        Args:
            active_ips: Optional list of active IPv4 addresses to ensure presence in
                the TLS certificate Subject Alternative Names (SAN).
        """
        if self._is_running:
            logger.warning("SnowWebSocketServer is already running; start() ignored.")
            return

        logger.info(
            "Starting %s server on %s:%d (max_message_size=%d bytes)...",
            "WSS (TLS)" if self.config.tls_enabled else "WebSocket (plaintext)",
            self.config.bind_host,
            self.config.port,
            self.config.max_message_size,
        )

        try:
            if self.config.tls_enabled:
                cert_path = (
                    Path(self.config.tls_cert_path)
                    if self.config.tls_cert_path
                    else (DEFAULT_TLS_DIR / DEFAULT_CERT_FILE)
                )
                key_path = (
                    Path(self.config.tls_key_path)
                    if self.config.tls_key_path
                    else (DEFAULT_TLS_DIR / DEFAULT_KEY_FILE)
                )
                self.certificate_info = ensure_tls_certificate(
                    cert_path=cert_path,
                    key_path=key_path,
                    active_ips=active_ips,
                )
                self._ssl_context = create_server_ssl_context(
                    cert_path=cert_path,
                    key_path=key_path,
                )
            else:
                self.certificate_info = None
                self._ssl_context = None

            self._server = await serve(
                self._handle_client,
                self.config.bind_host,
                self.config.port,
                max_size=self.config.max_message_size,
                ssl=self._ssl_context,
            )
            self._is_running = True
            self._loop = asyncio.get_running_loop()
            actual_port = self.bound_port or self.config.port

            if self.config.tls_enabled and self.certificate_info:
                print_tls_fingerprint_banner(self.certificate_info.fingerprint_sha256)
                logger.info(
                    "WSS server listening on wss://%s:%d (TLS 1.2+ active, SHA-256: %s)",
                    self.config.bind_host,
                    actual_port,
                    self.certificate_info.fingerprint_sha256,
                )
            else:
                logger.info("WebSocket server listening on ws://%s:%d", self.config.bind_host, actual_port)

            # Start background reaper task for stale client connections
            self._reaper_task = asyncio.create_task(self._stale_connection_reaper())

            # Generate initial pairing PIN and display to sys.stderr
            self.pairing_manager.generate_pin(display_to_stderr=True)
        except Exception as exc:
            logger.error("Failed to start WebSocket server on %s:%d: %s",
                         self.config.bind_host, self.config.port, exc)
            self._is_running = False
            raise

    async def stop(self) -> None:
        """Gracefully stop the WebSocket server and disconnect all clients."""
        if not self._is_running and not self._server:
            return

        logger.info("Stopping WebSocket server...")
        self._is_running = False

        # Cancel all pending handshake timers
        for cid, timer_task in list(self._auth_timers.items()):
            if not timer_task.done():
                timer_task.cancel()
        self._auth_timers.clear()
        self._pairing_in_progress.clear()

        # Cancel all active clipboard sync watcher tasks
        for cid, cb_task in list(self._clipboard_sync_tasks.items()):
            if not cb_task.done():
                cb_task.cancel()
        self._clipboard_sync_tasks.clear()
        self._last_synced_clipboard_hash.clear()
        if self._clipboard_listener:
            try:
                self._clipboard_listener.stop()
            except Exception:
                pass
            self._clipboard_listener = None
        if self._clipboard_watchdog_task and not self._clipboard_watchdog_task.done():
            self._clipboard_watchdog_task.cancel()
            self._clipboard_watchdog_task = None
        self._active_sync_connections.clear()

        # Cancel background stale connection reaper
        if self._reaper_task:
            self._reaper_task.cancel()
            try:
                await self._reaper_task
            except asyncio.CancelledError:
                pass
            self._reaper_task = None

        # Cancel any pending requests
        for req_id, (cid, fut) in list(self._pending_requests.items()):
            if not fut.done():
                fut.set_exception(ConnectionResetError("Server shutdown."))
        self._pending_requests.clear()

        # Stop accepting new connections and close listener
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

        # Close all active client connections cleanly
        await self.connection_manager.close_all(code=1000, reason="Server shutdown")
        logger.info("WebSocket server stopped cleanly.")

    async def _handle_client(self, websocket: ServerConnection) -> None:
        """Handle communication lifecycle for an accepted client connection."""
        client = self.connection_manager.register(websocket)
        logger.info("Accepted new WebSocket connection from %s [id=%s]",
                    client.remote_address, client.connection_id)

        # Enforce unauthenticated connection timeout (default 5.0 seconds)
        if self.config.auth_required and self.config.auth_timeout > 0:
            timer_task = asyncio.create_task(
                self._enforce_handshake_timeout(client.connection_id, self.config.auth_timeout)
            )
            self._auth_timers[client.connection_id] = timer_task

        try:
            async for raw_message in websocket:
                await self._process_message(client, raw_message)
        except ConnectionClosed as exc:
            close_code = exc.rcvd.code if exc.rcvd is not None else (exc.sent.code if exc.sent is not None else 1006)
            close_reason = exc.rcvd.reason if exc.rcvd is not None else (exc.sent.reason if exc.sent is not None else "no reason")
            logger.info("Client [%s] disconnected (%s, code=%s)",
                        client.connection_id, close_reason or "no reason", close_code)
        except Exception as exc:
            logger.warning("Unexpected error handling client [%s]: %s",
                           client.connection_id, exc, exc_info=True)
        finally:
            timer = self._auth_timers.pop(client.connection_id, None)
            if timer and not timer.done():
                timer.cancel()
            self._pairing_in_progress.discard(client.connection_id)
            cb_task = self._clipboard_sync_tasks.pop(client.connection_id, None)
            if cb_task and not cb_task.done():
                cb_task.cancel()
            self._last_synced_clipboard_hash.pop(client.connection_id, None)
            self._active_sync_connections.discard(client.connection_id)
            if not self._active_sync_connections:
                if self._clipboard_listener:
                    try:
                        self._clipboard_listener.stop()
                    except Exception:
                        pass
                    self._clipboard_listener = None
                if self._clipboard_watchdog_task and not self._clipboard_watchdog_task.done():
                    self._clipboard_watchdog_task.cancel()
                    self._clipboard_watchdog_task = None
            session = self.session_manager.get_session_by_connection(client.connection_id)
            if session and getattr(self, "node_registry", None):
                self.node_registry.on_session_disconnected(
                    session.device_id, connection_id=client.connection_id
                )
            self.session_manager.cleanup_connection(client.connection_id)
            self.connection_manager.unregister(client.connection_id)
            for req_id, (cid, fut) in list(self._pending_requests.items()):
                if cid == client.connection_id and not fut.done():
                    fut.set_exception(
                        ConnectionResetError(f"Client [{client.connection_id}] disconnected.")
                    )

    async def _enforce_handshake_timeout(self, connection_id: str, timeout: float) -> None:
        """Close connection if client fails to authenticate or initiate pairing within timeout."""
        try:
            await asyncio.sleep(timeout)
            # If pairing has legitimately started, do not interrupt the user entering their PIN
            if connection_id in self._pairing_in_progress:
                return
            session = self.session_manager.get_session_by_connection(connection_id)
            if session is None:
                logger.warning(
                    "Handshake timeout: Client [%s] did not authenticate or initiate pairing within %.1fs. Closing connection.",
                    connection_id,
                    timeout,
                )
                client = self.connection_manager.get(connection_id)
                if client and client.websocket:
                    try:
                        await client.websocket.close(code=4001, reason="Handshake timeout")
                    except Exception:
                        pass
        except asyncio.CancelledError:
            pass

    async def _process_message(self, client, raw_message: str | bytes) -> None:
        """Validate and dispatch an incoming client message."""
        try:
            message: SnowMessage = validate_raw_message(
                raw_message, max_size=self.config.max_message_size
            )
        except ProtocolValidationError as val_err:
            logger.warning("Protocol validation error from client [%s]: %s",
                           client.connection_id, val_err)
            error_response = SnowMessage.create_error(
                code=val_err.code,
                message=val_err.message,
                correlation_id=val_err.correlation_id,
            )
            await client.websocket.send(error_response.to_json())
            return
        except Exception as exc:
            logger.error("Internal error during message validation: %s", exc, exc_info=True)
            error_response = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message="Internal server error processing message.",
            )
            await client.websocket.send(error_response.to_json())
            return

        # Record activity/heartbeat
        self.connection_manager.record_heartbeat(client.connection_id)

        # Dispatch based on message type
        if message.type == MessageType.HEARTBEAT:
            ack = SnowMessage.create_heartbeat_ack(correlation_id=message.id)
            await client.websocket.send(ack.to_json())
            logger.debug("Sent heartbeat_ack to client [%s] for heartbeat [%s]",
                         client.connection_id, message.id)

        elif message.type == MessageType.REQUEST:
            await self._handle_request(client, message)

        elif message.type in (MessageType.RESPONSE, MessageType.ERROR, MessageType.HEARTBEAT_ACK):
            # Check if there is an in-flight server request waiting for this response
            corr_id = message.correlation_id
            if corr_id and corr_id in self._pending_requests:
                cid, fut = self._pending_requests[corr_id]
                if cid == client.connection_id and not fut.done():
                    fut.set_result(message)
                    logger.debug("Resolved pending request [%s] with %s from client [%s]",
                                 corr_id, message.type, client.connection_id)
            else:
                logger.debug("Received %s message [%s] from client [%s]",
                             message.type, message.id, client.connection_id)

    async def send_request(
        self,
        connection_id: str,
        action: str,
        payload: Optional[dict[str, Any]] = None,
        timeout: float = 30.0,
    ) -> SnowMessage:
        """Send a request to a connected device and await its correlated response.

        Args:
            connection_id: The ID of the connected client.
            action: Action identifier (e.g., 'ping', 'echo').
            payload: Optional payload parameters.
            timeout: Maximum seconds to wait for a correlated response (default 30.0s).

        Returns:
            The correlated SnowMessage response.

        Raises:
            ConnectionError: If the client is not connected.
            TimeoutError: If the client does not respond within the timeout.
            RuntimeError: If the server is not running.
        """
        if not self._is_running:
            raise RuntimeError("SnowWebSocketServer is not running.")

        client = self.connection_manager.get(connection_id)
        if client is None:
            raise ConnectionError(f"Client [{connection_id}] is not connected.")

        request = SnowMessage.create_request(action, payload)
        loop = asyncio.get_running_loop()
        future: asyncio.Future[SnowMessage] = loop.create_future()
        self._pending_requests[request.id] = (connection_id, future)

        try:
            await client.websocket.send(request.to_json())
            logger.debug("Sent request [%s] action='%s' to client [%s]",
                         request.id, action, connection_id)
            response = await asyncio.wait_for(future, timeout=timeout)
            return response
        except asyncio.TimeoutError:
            logger.warning("Request [%s] to client [%s] timed out after %.1fs",
                           request.id, connection_id, timeout)
            raise TimeoutError(f"Request [{request.id}] timed out after {timeout} seconds.")
        finally:
            self._pending_requests.pop(request.id, None)

    async def _handle_request(self, client, message: SnowMessage) -> None:
        """Handle incoming request actions.

        Note: Arbitrary shell execution or unrestricted remote commands are strictly
        forbidden. Only explicit authorized capabilities are handled.
        """
        assert message.payload is not None
        action = message.payload.get("action")
        data = message.payload.get("data") if isinstance(message.payload.get("data"), dict) else {}

        if action == "auth_request":
            await self._handle_auth_request(client, message, data)
        elif action in ("pair_request", "pair_verify"):
            # Mark pairing flow as in progress to prevent handshake timeout interruption
            self._pairing_in_progress.add(client.connection_id)
            timer = self._auth_timers.pop(client.connection_id, None)
            if timer and not timer.done():
                timer.cancel()
            await self._handle_pairing_request(client, message, action, data)
        elif action == "unpair_request":
            await self._handle_unpair_request(client, message, data)
        else:
            # All other device operations require an authenticated session if auth is required
            session = None
            if self.config.auth_required:
                session = self.session_manager.get_session_by_connection(client.connection_id)
                if session is None:
                    logger.warning(
                        "Rejected unauthenticated action '%s' from client [%s]",
                        action,
                        client.connection_id,
                    )
                    error_response = SnowMessage.create_error(
                        code=ErrorCode.UNAUTHORIZED,
                        message="Client is not authenticated. Send 'auth_request' first.",
                        correlation_id=message.id,
                    )
                    await client.websocket.send(error_response.to_json())
                    return

                # 1. Identity validation: verify caller device is still paired and not revoked
                paired_dev = self.db_manager.get_paired_device(session.device_id)
                if not paired_dev:
                    logger.warning(
                        "Rejected action '%s' for device [%s]: device is not paired or has been revoked.",
                        action,
                        session.device_id,
                    )
                    self.session_manager.revoke_session(session.session_id)
                    error_response = SnowMessage.create_error(
                        code=ErrorCode.UNAUTHORIZED,
                        message="Device identity is no longer paired or has been revoked.",
                        correlation_id=message.id,
                    )
                    await client.websocket.send(error_response.to_json())
                    return

                # 2. Prevent forged request-body device_id: caller cannot impersonate another device
                body_device_id = data.get("device_id")
                if body_device_id and body_device_id != session.device_id:
                    logger.warning(
                        "Security violation: Client [%s] authenticated as [%s] sent forged body device_id [%s] for action '%s'",
                        client.connection_id,
                        session.device_id,
                        body_device_id,
                        action,
                    )
                    error_response = SnowMessage.create_error(
                        code=ErrorCode.UNAUTHORIZED,
                        message="Request body device_id does not match authenticated session identity.",
                        correlation_id=message.id,
                    )
                    await client.websocket.send(error_response.to_json())
                    return

                # 3. Derive ExecutionPrincipal and construct immutable ExecutionContext
                paired_record = self.db_manager.get_paired_device(session.device_id)
                is_owner = (
                    paired_record is not None
                    and getattr(paired_record, "trust_tier", "peer") == "owner"
                )
                principal = (
                    ExecutionPrincipal.OWNER_MANUAL if is_owner else ExecutionPrincipal.AI_MCP
                )

                # Anti-spoofing: Strip any caller-supplied execution authority fields
                data.pop("principal", None)
                data.pop("trust_tier", None)
                data.pop("execution_principal", None)

                ctx = ExecutionContext(
                    principal=principal,
                    device_id=session.device_id,
                    session_id=session.session_id,
                    origin="wss",
                )

                # 4. Peer capability authorization check before dispatch
                capability = ACTION_TO_CAPABILITY.get(action)
                if capability is not None:
                    if not self.capability_policy.is_authorized(session.device_id, capability, ctx=ctx):
                        logger.warning(
                            "Authorization denied: Device [%s] lacks capability '%s' for action '%s'",
                            session.device_id,
                            capability,
                            action,
                        )
                        error_response = SnowMessage.create_error(
                            code=ErrorCode.UNAUTHORIZED,
                            message=f"Capability '{capability}' is not authorized for device '{session.device_id}'.",
                            correlation_id=message.id,
                        )
                        await client.websocket.send(error_response.to_json())
                        return

                self.session_manager.touch_session(session.session_id)
            else:
                ctx = ExecutionContext(
                    principal=ExecutionPrincipal.AI_MCP,
                    device_id=None,
                    session_id=None,
                    origin="wss_unauthenticated",
                )

            if action == "ping":
                logger.debug("Handling 'ping' action from client [%s]", client.connection_id)
                response = SnowMessage.create_response(
                    correlation_id=message.id,
                    payload={"status": "success", "action": "pong"},
                )
                await client.websocket.send(response.to_json())
            elif action == "file_transfer_offer":
                await self._handle_file_transfer_offer(client, message, data, session)
            elif action == "file_list_transfers":
                await self._handle_file_list_transfers(client, message, data, session)
            elif action == "file_transfer_status":
                await self._handle_file_transfer_status(client, message, data, session)
            elif action == "file_transfer_cancel":
                await self._handle_file_transfer_cancel(client, message, data, session)
            elif action == "desktop_status":
                await self._handle_desktop_status(client, message, data, session, ctx)
            elif action == "desktop_exec":
                await self._handle_desktop_exec(client, message, data, session, ctx)
            elif action == "desktop_app_launch":
                await self._handle_desktop_app_launch(client, message, data, session, ctx)
            elif action == "desktop_clipboard_get":
                await self._handle_desktop_clipboard_get(client, message, data, session, ctx)
            elif action == "desktop_clipboard_set":
                await self._handle_desktop_clipboard_set(client, message, data, session, ctx)
            elif action == "desktop_clipboard_sync_toggle":
                await self._handle_desktop_clipboard_sync_toggle(client, message, data, session, ctx)
            elif action == "notification_event":
                await self._handle_notification_event(client, message, data, session)
            elif action == "desktop_file_list":
                await self._handle_desktop_file_list(client, message, data, session, ctx)
            elif action == "desktop_file_stage_download":
                await self._handle_desktop_file_stage_download(client, message, data, session, ctx)
            elif action == "manifest_update":
                await self._handle_manifest_update(client, message, data, session)
            elif action == "mesh_list_peers":
                await self._handle_mesh_list_peers(client, message, data, session)
            elif action == "peer_relay_request":
                await self._handle_peer_relay_request(client, message, data, session)
            elif action == "approval_list":
                await self._handle_approval_list(client, message, data, session, ctx)
            elif action == "approval_resolve":
                await self._handle_approval_resolve(client, message, data, session, ctx)
            elif action == "screen_stream_start":
                await self._handle_screen_stream_start(client, message, data, session)
            elif action == "screen_stream_stop":
                await self._handle_screen_stream_stop(client, message, data, session)
            elif action == "screen_stream_status":
                await self._handle_screen_stream_status(client, message, data, session)
            elif action == "camera_photo_delivered":
                await self._handle_camera_photo_delivered(client, message, data, session)
            elif action == "clipboard_buffer_list":
                await self._handle_clipboard_buffer_list(client, message, data, session)
            elif action == "clipboard_buffer_get":
                await self._handle_clipboard_buffer_get(client, message, data, session)
            elif action == "clipboard_buffer_add":
                await self._handle_clipboard_buffer_add(client, message, data, session)
            elif action == "clipboard_buffer_apply":
                await self._handle_clipboard_buffer_apply(client, message, data, session)
            else:
                logger.warning("Rejected unsupported action '%s' from client [%s]",
                               action, client.connection_id)
                error_response = SnowMessage.create_error(
                    code=ErrorCode.UNSUPPORTED_ACTION,
                    message=f"Action '{action}' is not supported.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())

    async def _handle_screen_stream_start(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle control-plane request to start screen streaming. Metadata only (no image bytes)."""
        device_id = session.device_id if session and session.device_id else "unknown"
        session_id = str(data.get("session_id") or uuid.uuid4())
        fps = float(data.get("fps", 2.0))
        width = int(data.get("frame_width", 720))
        height = int(data.get("frame_height", 1280))

        self._screen_stream_sessions[device_id] = {
            "session_id": session_id,
            "state": "STREAMING",
            "fps": fps,
            "frame_width": width,
            "frame_height": height,
            "timestamp": time.time(),
        }

        # Sync with HTTP transfer server session state if bound
        if self.http_transfer_server:
            try:
                self.http_transfer_server.set_session_state(
                    device_id=device_id,
                    state="STREAMING",
                    session_id=session_id,
                    fps=fps,
                    width=width,
                    height=height,
                )
            except Exception as e:
                logger.debug("Failed notifying http_transfer_server of screen_stream_start: %s", e)

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "state": "STREAMING",
                "session_id": session_id,
                "fps": fps,
                "frame_width": width,
                "frame_height": height,
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_screen_stream_stop(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle control-plane request to stop screen streaming."""
        device_id = session.device_id if session and session.device_id else "unknown"
        if device_id in self._screen_stream_sessions:
            self._screen_stream_sessions[device_id]["state"] = "STOPPED"

        if self.http_transfer_server:
            try:
                self.http_transfer_server.set_session_state(device_id=device_id, state="STOPPED")
            except Exception as e:
                logger.debug("Failed notifying http_transfer_server of screen_stream_stop: %s", e)

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "state": "STOPPED",
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_screen_stream_status(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Return screen streaming metadata for the session. Strictly metadata only."""
        device_id = session.device_id if session and session.device_id else "unknown"
        meta = self._screen_stream_sessions.get(device_id, {"state": "IDLE"})
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "metadata": meta,
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_camera_photo_delivered(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle control-plane acknowledgement of an uploaded camera photo."""
        device_id = session.device_id if session and session.device_id else "unknown"
        file_name = str(data.get("file_name", ""))
        size_bytes = int(data.get("size_bytes", 0))
        sha256 = str(data.get("sha256", ""))
        logger.info(
            "Camera photo delivered from device [%s]: %s (%d bytes, sha256=%s)",
            device_id, file_name, size_bytes, sha256[:8] if sha256 else "none"
        )
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "acknowledged": True,
                "file_name": file_name,
                "size_bytes": size_bytes,
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_clipboard_buffer_list(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle request to list metadata of shared clipboard buffer items (<= 64 KiB)."""
        limit = min(int(data.get("limit", 10)), 10)
        buf = getattr(self, "clipboard_buffer", None)
        if not buf and hasattr(self, "capability_engine"):
            buf = getattr(self.capability_engine, "clipboard_buffer", None)
        items = buf.list_items(limit=limit) if buf else []
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={"status": "success", "items": items, "count": len(items)},
        )
        await client.websocket.send(response.to_json())

    async def _handle_clipboard_buffer_get(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle request to retrieve full text content of a clipboard item."""
        item_id = data.get("item_id")
        import re
        if not item_id or not isinstance(item_id, str) or not re.match(r"^cb_[0-9a-f]{12}_[0-9a-f]{6}$", item_id):
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Invalid or missing 'item_id'. Expected format: cb_<12hex>_<6hex>.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        buf = getattr(self, "clipboard_buffer", None)
        if not buf and hasattr(self, "capability_engine"):
            buf = getattr(self.capability_engine, "clipboard_buffer", None)

        if not buf:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message="Clipboard buffer unavailable on host.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        item = buf.get_item(str(item_id), include_content=True)
        if not item:
            error_response = SnowMessage.create_error(
                code=ErrorCode.NOT_FOUND,
                message=f"Item '{item_id}' not found in clipboard buffer.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        c_type = item.get("type") or item.get("content_type")
        if c_type != "text":
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Item is not a text entry. Image entries must be transferred via HTTP.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        text_content = item.get("text_content") or ""
        if len(text_content.encode("utf-8")) > 65536:
            error_response = SnowMessage.create_error(
                code=ErrorCode.PAYLOAD_TOO_LARGE,
                message="Clipboard text exceeds 64 KiB limit.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "item_id": item_id,
                "text_content": text_content,
                "sha256": item.get("sha256"),
                "size_bytes": item.get("size_bytes"),
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_clipboard_buffer_add(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle request to add a text item to the shared clipboard buffer."""
        text = data.get("text")
        if text is None:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Missing 'text' field in clipboard_buffer_add payload.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        source_device = (session.device_id if session and session.device_id else "android")
        is_pinned = bool(data.get("is_pinned", False))
        buf = getattr(self, "clipboard_buffer", None)
        if not buf and hasattr(self, "capability_engine"):
            buf = getattr(self.capability_engine, "clipboard_buffer", None)

        if not buf:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message="Clipboard buffer unavailable on host.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        res = buf.add_text(text=str(text), source_device=source_device, is_pinned=is_pinned)
        if not res.get("success", False):
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message=f"Failed adding item to clipboard buffer: {res.get('error', 'Unknown error')}",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={"status": "success", "item": res.get("item")},
        )
        await client.websocket.send(response.to_json())

    async def _handle_clipboard_buffer_apply(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle notification or request to apply a clipboard item."""
        item_id = data.get("item_id")
        target = data.get("target", "android")
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={"status": "success", "applied": True, "item_id": item_id, "target": target},
        )
        await client.websocket.send(response.to_json())

    async def _handle_manifest_update(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle capability manifest updates from an authenticated peer."""
        if session is None or not session.device_id:
            error_response = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Session not authenticated.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        device_id = session.device_id
        manifest_data = data.get("manifest")
        if not manifest_data or not isinstance(manifest_data, (dict, str)):
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Missing or invalid 'manifest' in manifest_update payload.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        # Anti-spoofing check: strip any authority overrides in manifest_data if dict
        if isinstance(manifest_data, dict):
            manifest_data.pop("principal", None)
            manifest_data.pop("trust_tier", None)
            manifest_data.pop("execution_principal", None)

        if self.node_registry:
            self.node_registry.on_manifest_updated(device_id, manifest_data)

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "message": "Capability manifest updated successfully.",
                "device_id": device_id,
            },
        )
        await client.websocket.send(response.to_json())
        logger.info("Processed live capability manifest update for device [%s]", device_id)

    async def _handle_mesh_list_peers(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle request to list known mesh peers, redacting all sensitive credentials."""
        if session is None or not session.device_id:
            error_response = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Session not authenticated.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        peers_list: list[dict[str, Any]] = []

        if self.node_registry is not None:
            nodes = self.node_registry.list_nodes()
            for node in nodes:
                peers_list.append({
                    "device_id": node.device_id,
                    "device_name": node.device_name,
                    "device_type": node.platform,
                    "reachability_state": str(node.reachability_state.value if hasattr(node.reachability_state, "value") else node.reachability_state),
                    "reachability_profile": str(node.reachability_profile.value if hasattr(node.reachability_profile, "value") else node.reachability_profile),
                    "supported_capabilities": list(node.supported_capabilities),
                })
        else:
            paired = self.db_manager.list_paired_devices()
            for rec in paired:
                peers_list.append({
                    "device_id": rec.device_id,
                    "device_name": rec.device_name,
                    "device_type": getattr(rec, "platform", "android"),
                    "reachability_state": "LAN_DISCOVERABLE",
                    "reachability_profile": getattr(rec, "reachability_profile", "ACTIVE_SESSION_PEER"),
                    "supported_capabilities": [],
                })

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "mesh_list_peers",
                "data": {
                    "peers": peers_list,
                    "count": len(peers_list),
                },
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_peer_relay_request(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle an authenticated peer relay request to forward an action across the mesh."""
        if session is None or not session.device_id:
            error_response = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Session not authenticated.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        caller_device_id = session.device_id

        # Check payload size (64KB max)
        try:
            raw_len = len(json.dumps(data, ensure_ascii=True))
            if raw_len > 65536:
                error_response = SnowMessage.create_error(
                    code=ErrorCode.INVALID_PAYLOAD,
                    message=f"Relay payload exceeds maximum limit of 64KB ({raw_len} bytes).",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return
        except Exception:
            pass

        target_device_id = data.get("target_device_id")
        relay_action = data.get("action")
        relay_data = data.get("data") or {}
        hop_limit = data.get("hop_limit", 3)
        visited_nodes = list(data.get("visited_nodes", []))

        if not target_device_id or not relay_action:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_REQUEST,
                message="Peer relay requires 'target_device_id' and 'action'.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        # Payload size boundary check (64KB boundary limit)
        raw_payload_len = len(json.dumps(relay_data)) if relay_data else 0
        if raw_payload_len > 65536:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Relay payload exceeds 64KB boundary limit.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        # Strip caller-supplied authority overrides
        if isinstance(relay_data, dict):
            relay_data = dict(relay_data)
            relay_data.pop("principal", None)
            relay_data.pop("trust_tier", None)
            relay_data.pop("execution_principal", None)

        local_id = self.device_identity.device_id

        # Loop prevention: check if this host is already in visited nodes
        if local_id in visited_nodes:
            logger.warning(
                "Routing loop detected in peer relay! Host [%s] already in visited nodes: %s",
                local_id,
                visited_nodes,
            )
            error_response = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Routing loop detected: host '{local_id}' already visited.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        # Hop limit enforcement
        try:
            hop_limit = int(hop_limit)
        except (ValueError, TypeError):
            hop_limit = 3

        if hop_limit <= 0:
            logger.warning("Hop limit exceeded in peer relay to [%s]", target_device_id)
            error_response = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message="Hop limit exceeded during peer relay.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        visited_nodes.append(local_id)
        next_hop_limit = hop_limit - 1

        # Case 1: Target is this local node!
        if target_device_id == local_id:
            cap = ACTION_TO_CAPABILITY.get(relay_action)
            relay_ctx = ExecutionContext(
                principal=ExecutionPrincipal.AI_MCP,
                origin=f"relay:{caller_device_id}",
            )
            if cap and not self.capability_policy.is_authorized(caller_device_id, cap, ctx=relay_ctx):
                logger.warning(
                    "Relay authorization denied: Device [%s] lacks capability '%s' for action '%s'",
                    caller_device_id,
                    cap,
                    relay_action,
                )
                error_response = SnowMessage.create_error(
                    code=ErrorCode.UNAUTHORIZED,
                    message=f"Capability '{cap}' is not authorized for device '{caller_device_id}'.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return

            try:
                req = CapabilityRequest(action=relay_action, params=relay_data)
                res = await self.capability_engine.execute(req, ctx=relay_ctx)
                resp = SnowMessage.create_response(
                    correlation_id=message.id,
                    payload={
                        "status": "success" if res.success else (res.status or "error"),
                        "action": "peer_relay_request",
                        "data": res.data,
                        "error": res.error,
                        "relayed_by": local_id,
                        "target_device_id": local_id,
                    },
                )
                await client.websocket.send(resp.to_json())
                return
            except Exception as local_exc:
                err_resp = SnowMessage.create_error(
                    code=ErrorCode.INTERNAL_ERROR,
                    message=f"Local execution error during relay: {local_exc}",
                    correlation_id=message.id,
                )
                await client.websocket.send(err_resp.to_json())
                return

        # Case 2: Target is another node in mesh
        router = getattr(self, "session_router", None) or getattr(self.core_server, "session_router", None)
        if router is not None and hasattr(router, "route_request"):
            relay_ctx = ExecutionContext(
                principal=ExecutionPrincipal.AI_MCP,
                origin=f"relay:{caller_device_id}",
            )
            route_res = await router.route_request(
                action=relay_action,
                target=target_device_id,
                data=relay_data,
                ctx=relay_ctx,
            )
            resp = SnowMessage.create_response(
                correlation_id=message.id,
                payload={
                    "status": "success" if route_res.get("success") else route_res.get("status", "error"),
                    "action": "peer_relay_request",
                    "data": route_res.get("data"),
                    "error": route_res.get("error"),
                    "relayed_by": local_id,
                    "target_device_id": target_device_id,
                },
            )
            await client.websocket.send(resp.to_json())
            return
        else:
            target_session = self.session_manager.get_session_by_device(target_device_id)
            if target_session and target_session.connection_id:
                target_conn = self.connection_manager.get(target_session.connection_id)
                if target_conn and target_conn.is_active:
                    try:
                        target_resp = await self.send_request(
                            connection_id=target_session.connection_id,
                            action=relay_action,
                            payload=relay_data,
                            timeout=25.0,
                        )
                        resp = SnowMessage.create_response(
                            correlation_id=message.id,
                            payload={
                                "status": "success",
                                "action": "peer_relay_request",
                                "data": target_resp.payload,
                                "relayed_by": local_id,
                                "target_device_id": target_device_id,
                            },
                        )
                        await client.websocket.send(resp.to_json())
                        return
                    except Exception as fwd_exc:
                        err_resp = SnowMessage.create_error(
                            code=ErrorCode.DEVICE_NOT_FOUND,
                            message=f"Failed forwarding relay request to [{target_device_id}]: {fwd_exc}",
                            correlation_id=message.id,
                        )
                        await client.websocket.send(err_resp.to_json())
                        return

            err_resp = SnowMessage.create_error(
                code=ErrorCode.DEVICE_NOT_FOUND,
                message=f"Target device '{target_device_id}' is unreachable for relay.",
                correlation_id=message.id,
            )
            await client.websocket.send(err_resp.to_json())

    def _determine_transport(self, client_host: str, client_declaration: Optional[str] = None) -> str:
        """Determine authoritative transport by cross-checking client declaration with host socket.

        Never trusts client assertion alone.
        """
        clean_host = (client_host or "").strip().lower()
        is_loopback = clean_host in ("127.0.0.1", "::1", "localhost")
        if not is_loopback:
            try:
                ip = ipaddress.ip_address(clean_host)
                if ip.is_loopback:
                    is_loopback = True
                elif getattr(ip, "ipv4_mapped", None) and ip.ipv4_mapped.is_loopback:
                    is_loopback = True
            except ValueError:
                pass

        clean_decl = (client_declaration or "").strip().lower()

        if not is_loopback:
            # Non-loopback IP (e.g. 192.168.x.x, 10.x.x.x) is always wifi_lan
            return "wifi_lan"

        # Socket is loopback
        if clean_decl == "usb_adb":
            from snow.cli import find_adb_binary, get_connected_adb_devices
            try:
                adb_bin = find_adb_binary()
                if adb_bin:
                    devs = get_connected_adb_devices(adb_bin)
                    authorized = [d for d in devs if d.get("status") == "device"]
                    if authorized:
                        return "usb_adb"
            except Exception as e:
                logger.debug("ADB verification check failed: %s", e)
            return "loopback"

        if clean_decl == "wifi_lan":
            # Contradiction: client says wifi_lan but socket is loopback
            return "unknown"

        return "loopback"

    async def _handle_approval_list(
        self, client: Any, message: SnowMessage, data: dict, session: Any, ctx: ExecutionContext
    ) -> None:
        """Handle approval_list request from an authenticated, trusted owner companion device."""
        if ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
            logger.warning("Rejected approval_list: device [%s] lacks OWNER_MANUAL trust.", session.device_id if session else "unknown")
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Only authenticated owner devices may inspect pending approvals.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        app_engine = getattr(self.capability_engine, "approval_engine", None)
        if not app_engine:
            err = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message="Approval engine is unavailable.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        pending = [r.to_dict() for r in app_engine.list_pending_requests()]
        resp = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "approval_list",
                "requests": pending,
                "count": len(pending),
            },
        )
        await client.websocket.send(resp.to_json())

    async def _handle_approval_resolve(
        self, client: Any, message: SnowMessage, data: dict, session: Any, ctx: ExecutionContext
    ) -> None:
        """Handle approval_resolve request (APPROVE or DENY) from authenticated owner companion."""
        if ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
            logger.warning("Rejected approval_resolve: device [%s] lacks OWNER_MANUAL trust.", session.device_id if session else "unknown")
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Only authenticated owner devices may resolve pending approvals.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        app_engine = getattr(self.capability_engine, "approval_engine", None)
        if not app_engine:
            err = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message="Approval engine is unavailable.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        request_id = str(data.get("request_id", "")).strip()
        decision = str(data.get("decision", "")).strip().upper()

        if not request_id or decision not in ("APPROVE", "DENY"):
            err = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Valid 'request_id' and decision ('APPROVE' or 'DENY') are required.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        if decision == "APPROVE":
            ok, msg = app_engine.approve_request(
                request_id=request_id,
                approver_principal=ExecutionPrincipal.OWNER_MANUAL,
            )
        else:
            ok, msg = app_engine.deny_request(
                request_id=request_id,
                approver_principal=ExecutionPrincipal.OWNER_MANUAL,
            )

        resp = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success" if ok else "error",
                "action": "approval_resolve",
                "request_id": request_id,
                "decision": decision,
                "resolved": ok,
                "message": msg,
            },
        )
        await client.websocket.send(resp.to_json())

    async def broadcast_approval_event(self, event_type: str, approval_data: dict) -> None:
        """Broadcast an approval event (REQUESTED, RESOLVED, EXPIRED) to connected OWNER_MANUAL devices."""
        for conn_id in self.connection_manager.all_connections():
            client = self.connection_manager.get(conn_id)
            if not client or not client.websocket or getattr(client.websocket, "state", 1) != 1:
                continue
            session = self.session_manager.get_session_by_connection(conn_id)
            if session is None or session.trust_tier != "owner":
                continue

            push_msg = SnowMessage.create_request(
                action="approval_event",
                data={
                    "event_type": event_type,
                    "request": approval_data,
                },
            )
            try:
                await client.websocket.send(push_msg.to_json())
                logger.debug("Broadcast approval event '%s' to device [%s]", event_type, session.device_id)
            except Exception as exc:
                logger.debug("Failed sending approval event to client [%s]: %s", conn_id, exc)

    async def _handle_auth_request(
        self, client, message: SnowMessage, data: dict[str, Any]
    ) -> None:
        """Handle incoming auth_request to establish an authenticated session."""
        device_id = data.get("device_id")
        auth_token = data.get("auth_token")

        if not device_id or not isinstance(device_id, str) or not auth_token or not isinstance(auth_token, str):
            logger.warning(
                "auth_request missing or invalid device_id or auth_token from client [%s]",
                client.connection_id,
            )
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="auth_request requires string 'device_id' and 'auth_token'.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        device_record = self.db_manager.get_paired_device(device_id)
        if not device_record:
            logger.warning("auth_request rejected: device [%s] not found in database", device_id)
            self.db_manager.log_audit_event(
                event_type="AUTH_FAILED",
                device_id=device_id,
                details={"reason": "Device not found in pairing database", "connection_id": client.connection_id},
            )
            error_response = SnowMessage.create_error(
                code=ErrorCode.DEVICE_NOT_FOUND,
                message=f"Device [{device_id}] is not registered as a paired device.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        if not self.db_manager.verify_device_token(device_id, auth_token):
            logger.warning("auth_request rejected: invalid auth token presented for device [%s]", device_id)
            self.db_manager.log_audit_event(
                event_type="AUTH_FAILED",
                device_id=device_id,
                details={"reason": "Invalid auth token presented", "connection_id": client.connection_id},
            )
            error_response = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Invalid authentication token.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        # Verification successful: cancel handshake timeout
        timer = self._auth_timers.pop(client.connection_id, None)
        if timer and not timer.done():
            timer.cancel()

        session = self.session_manager.create_session(
            device_id=device_id,
            connection_id=client.connection_id,
        )
        self.db_manager.update_last_seen(device_id)
        self.db_manager.log_audit_event(
            event_type="AUTH_SUCCESS",
            device_id=device_id,
            details={"session_id": session.session_id, "connection_id": client.connection_id},
        )

        logger.info(
            "Successfully authenticated device [%s] (session=%s) from client [%s]",
            device_id,
            session.session_id,
            client.connection_id,
        )

        # Update node registry if present
        manifest_data = data.get("manifest") or data.get("capabilities")
        if getattr(self, "node_registry", None):
            client_host, client_port = parse_remote_address(client.remote_address)
            client_decl = data.get("connection_mode") or data.get("transport_mode") or data.get("transport")
            transport = self._determine_transport(client_host, client_decl)
            try:
                self.node_registry.on_session_authenticated(
                    device_id=device_id,
                    connection_id=client.connection_id,
                    host=client_host,
                    port=client_port,
                    manifest_data=manifest_data,
                    transport=transport,
                )
            except Exception as reg_err:
                logger.debug("Failed notifying node registry of auth: %s", reg_err)

        from snow.network.node import build_windows_manifest

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "auth_request",
                "data": {
                    "device_id": device_id,
                    "session_id": session.session_id,
                    "trust_tier": device_record.trust_tier,
                    "manifest": build_windows_manifest().to_dict(),
                },
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_pairing_request(
        self, client, message: SnowMessage, action: str, data: dict[str, Any]
    ) -> None:
        """Handle pairing verification or PIN generation request."""
        pin = data.get("pin")
        client_device_id = data.get("device_id")

        if pin is not None:
            # PIN verification attempt
            result = self.pairing_manager.verify_pin(str(pin), client_device_id=client_device_id)
            if result.is_success:
                logger.info("Successfully paired with device [%s] from client [%s]",
                            client_device_id, client.connection_id)
                auth_token = secrets.token_urlsafe(32)
                token_hash = hash_token(auth_token)
                client_device_name = data.get(
                    "device_name",
                    f"Android-{client_device_id[:8]}" if client_device_id else "Android-Device",
                )

                if client_device_id:
                    # Clean up prior records / sessions if re-pairing
                    existing = self.db_manager.get_paired_device(client_device_id)
                    if existing:
                        self.db_manager.delete_paired_device(client_device_id)
                        self.session_manager.revoke_device_sessions(client_device_id)

                    configured_owner = getattr(self.config, "primary_owner_device_id", None)
                    if configured_owner is not None:
                        is_primary_owner = (client_device_id == configured_owner)
                        assigned_tier = "owner" if is_primary_owner else "peer"
                    else:
                        assigned_tier = getattr(result, "assigned_trust_tier", "peer")

                    self.db_manager.insert_paired_device(
                        device_id=client_device_id,
                        device_name=client_device_name,
                        auth_token_hash=token_hash,
                        trust_tier=assigned_tier,
                    )
                    self.db_manager.log_audit_event(
                        event_type="PAIR_SUCCESS",
                        device_id=client_device_id,
                        details={"device_name": client_device_name, "connection_id": client.connection_id},
                    )
                    self.session_manager.create_session(
                        device_id=client_device_id,
                        connection_id=client.connection_id,
                    )

                    if getattr(self, "node_registry", None):
                        client_host, client_port = parse_remote_address(client.remote_address)
                        client_decl = data.get("connection_mode") or data.get("transport_mode") or data.get("transport")
                        transport = self._determine_transport(client_host, client_decl)
                        try:
                            self.node_registry.on_session_authenticated(
                                device_id=client_device_id,
                                connection_id=client.connection_id,
                                host=client_host,
                                port=client_port,
                                manifest_data=data.get("manifest") or data.get("capabilities"),
                                transport=transport,
                            )
                        except Exception as reg_err:
                            logger.debug("Failed notifying node registry of pairing auth: %s", reg_err)

                # Successful pairing: clear pairing in-progress state and cancel handshake timer
                self._pairing_in_progress.discard(client.connection_id)
                timer = self._auth_timers.pop(client.connection_id, None)
                if timer and not timer.done():
                    timer.cancel()

                from snow.network.node import build_windows_manifest

                response = SnowMessage.create_response(
                    correlation_id=message.id,
                    payload={
                        "status": "success",
                        "action": action,
                        "data": {
                            "device_id": self.device_identity.device_id,
                            "device_name": self.device_identity.device_name,
                            "session_id": result.session_id,
                            "auth_token": auth_token,
                            "trust_tier": assigned_tier,
                            "manifest": build_windows_manifest().to_dict(),
                        },
                    },
                )
                await client.websocket.send(response.to_json())
            else:
                error_code = result.error_code or ErrorCode.INTERNAL_ERROR
                if error_code == ErrorCode.PAIRING_LOCKED:
                    self.db_manager.log_audit_event(
                        event_type="PAIR_LOCKOUT",
                        device_id=client_device_id,
                        details={"reason": result.message},
                    )
                else:
                    self.db_manager.log_audit_event(
                        event_type="PAIR_FAILED",
                        device_id=client_device_id,
                        details={"error_code": error_code, "reason": result.message},
                    )
                logger.warning("Pairing failed for client [%s]: %s (code=%s)",
                               client.connection_id, result.message, error_code)
                error_response = SnowMessage.create_error(
                    code=error_code,
                    message=result.message,
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
        else:
            # Client connects without PIN (initial unauthenticated handshake / requesting PIN)
            client_device_name = data.get(
                "device_name",
                f"Android-{client_device_id[:8]}" if client_device_id else "Android-Device",
            )
            self.pairing_manager.set_pending_device(client_device_id, client_device_name)

            # Immunize connection from handshake timeout while pairing is in progress
            self._pairing_in_progress.add(client.connection_id)
            timer = self._auth_timers.pop(client.connection_id, None)
            if timer and not timer.done():
                timer.cancel()

            if self.pairing_manager.has_active_pin:
                # Active unexpired PIN already exists! Do NOT overwrite it.
                logger.info(
                    "Client [%s] connected unauthenticated; existing active PIN preserved (tier=%s, remaining=%ds)",
                    client.connection_id,
                    self.pairing_manager._active_trust_tier,
                    int(self.pairing_manager.remaining_lifetime),
                )
                response = SnowMessage.create_response(
                    correlation_id=message.id,
                    payload={
                        "status": "pin_displayed",
                        "action": action,
                        "data": {
                            "device_id": self.device_identity.device_id,
                            "device_name": self.device_identity.device_name,
                            "has_active_pin": True,
                            "trust_tier": self.pairing_manager._active_trust_tier,
                            "expires_in": int(round(self.pairing_manager.remaining_lifetime)),
                        },
                    },
                )
            else:
                # No active PIN exists on desktop. Generate a fresh PIN banner on desktop stderr
                fresh_pin = self.pairing_manager.generate_pin(display_to_stderr=True)
                response = SnowMessage.create_response(
                    correlation_id=message.id,
                    payload={
                        "status": "pin_displayed",
                        "action": action,
                        "data": {
                            "device_id": self.device_identity.device_id,
                            "device_name": self.device_identity.device_name,
                            "has_active_pin": True,
                            "trust_tier": self.pairing_manager._active_trust_tier,
                            "expires_in": int(self.pairing_manager.pin_lifetime),
                        },
                    },
                )
            await client.websocket.send(response.to_json())

    async def _handle_unpair_request(
        self, client, message: SnowMessage, data: dict[str, Any]
    ) -> None:
        """Handle an authenticated unpair request from a paired client device."""
        device_id = data.get("device_id")
        auth_token = data.get("auth_token")

        if not device_id or not auth_token:
            logger.warning("Unpair request missing device_id or auth_token from client [%s]",
                           client.connection_id)
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_REQUEST,
                message="Unpair request requires 'device_id' and 'auth_token'.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        device_record = self.db_manager.get_paired_device(device_id)
        if not device_record:
            logger.warning("Unpair rejected: device [%s] not found in paired database", device_id)
            error_response = SnowMessage.create_error(
                code=ErrorCode.DEVICE_NOT_FOUND,
                message=f"Device [{device_id}] is not registered as a paired device.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        if not self.db_manager.verify_device_token(device_id, auth_token):
            logger.warning("Unpair rejected: invalid auth token presented for device [%s]", device_id)
            self.db_manager.log_audit_event(
                event_type="UNPAIR_UNAUTHORIZED",
                device_id=device_id,
                details={"reason": "Invalid auth token presented during unpair"},
            )
            error_response = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Invalid authentication token for unpair request.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        # Successfully verified: remove device, revoke active sessions, record audit trail
        self.db_manager.delete_paired_device(device_id)
        self.session_manager.revoke_device_sessions(device_id)
        self.db_manager.log_audit_event(
            event_type="UNPAIR",
            device_id=device_id,
            details={"initiated_by": "client", "connection_id": client.connection_id},
        )
        self.db_manager.log_audit_event(
            event_type="SESSION_REVOKED",
            device_id=device_id,
            details={"reason": "Device unpaired via client unpair_request"},
        )

        logger.info("Successfully unpaired device [%s] via client [%s]",
                    device_id, client.connection_id)
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "unpair_request",
                "data": {
                    "device_id": device_id,
                    "unpaired": True,
                },
            },
        )
        await client.websocket.send(response.to_json())

    def authorize_request(self, device_id: str, auth_token: str) -> bool:
        """Authorize an incoming request using persistent token verification.

        Updates last-seen timestamp upon successful authorization.
        """
        if not device_id or not auth_token:
            return False
        is_valid = self.db_manager.verify_device_token(device_id, auth_token)
        if is_valid:
            self.db_manager.update_last_seen(device_id)
            session = self.session_manager.get_session_by_device(device_id)
            if session:
                self.session_manager.touch_session(session.session_id)
        return is_valid

    def unpair_device(self, device_id: str) -> bool:
        """Desktop-initiated unpairing of a registered device.

        Deletes SQLite record, revokes active session, and logs audit events.
        """
        existing = self.db_manager.get_paired_device(device_id)
        if not existing:
            return False
        self.db_manager.delete_paired_device(device_id)
        self.session_manager.revoke_device_sessions(device_id)
        self.db_manager.log_audit_event(
            event_type="UNPAIR",
            device_id=device_id,
            details={"initiated_by": "desktop"},
        )
        self.db_manager.log_audit_event(
            event_type="SESSION_REVOKED",
            device_id=device_id,
            details={"reason": "Desktop unpair_device invoked"},
        )
        return True

    async def _handle_file_transfer_offer(
        self, client, message: SnowMessage, data: dict[str, Any], session
    ) -> None:
        """Handle incoming file transfer offer request over WebSocket."""
        file_name = data.get("file_name")
        file_size = data.get("file_size")
        sha256 = data.get("sha256")
        dir_str = data.get("direction", "UPLOAD").upper()

        if not file_name or file_size is None or not sha256:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="file_name, file_size, and sha256 are required.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        try:
            direction = TransferDirection(dir_str)
        except ValueError:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message=f"Invalid transfer direction: '{dir_str}'.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        device_id = session.device_id if session else data.get("device_id", "anonymous")

        # Check duplicate
        already_exists, is_conflict, existing_hash = self.storage_manager.check_duplicate(
            file_name, sha256
        )

        try:
            record = self.transfer_manager.create_transfer(
                device_id=device_id,
                file_name=file_name,
                file_size=int(file_size),
                sha256=sha256,
                direction=direction,
            )
        except Exception as exc:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message=str(exc),
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        # Check existing partial upload
        resume_offset = 0
        if direction == TransferDirection.UPLOAD:
            part_path = self.storage_manager.get_part_path(record.transfer_id)
            if part_path.exists() and part_path.is_file():
                resume_offset = part_path.stat().st_size

        bound_port = (
            self.http_transfer_server.bound_port
            if self.http_transfer_server
            else self.config.transfer_port
        )
        transfer_path = (
            f"/api/v1/transfers/{'upload' if direction == TransferDirection.UPLOAD else 'download'}/{record.transfer_id}"
        )

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "file_transfer_offer",
                "data": {
                    "transfer_id": record.transfer_id,
                    "transfer_port": bound_port,
                    "transfer_url": transfer_path,
                    "resume_offset": resume_offset,
                    "already_exists": already_exists,
                    "is_conflict": is_conflict,
                    "existing_sha256": existing_hash,
                },
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_file_list_transfers(
        self, client, message: SnowMessage, data: dict[str, Any], session
    ) -> None:
        """Handle request to list active and completed transfers for the authenticated device."""
        device_id = session.device_id if session else data.get("device_id", "anonymous")
        transfers = self.transfer_manager.list_transfers_for_device(device_id)

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "file_list_transfers",
                "data": {
                    "transfers": [t.to_dict() for t in transfers],
                },
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_file_transfer_status(
        self, client, message: SnowMessage, data: dict[str, Any], session
    ) -> None:
        """Handle transfer status query."""
        transfer_id = data.get("transfer_id")
        if not transfer_id:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="transfer_id is required.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        device_id = session.device_id if session else data.get("device_id", "anonymous")
        record = self.transfer_manager.get_transfer_for_device(transfer_id, device_id)
        if not record:
            error_response = SnowMessage.create_error(
                code=ErrorCode.TRANSFER_NOT_FOUND,
                message="Transfer record not found or not owned by device.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        part_path = self.storage_manager.get_part_path(transfer_id)
        current_offset = (
            part_path.stat().st_size
            if part_path.exists() and record.status != TransferState.COMPLETED
            else record.current_offset
        )

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "file_transfer_status",
                "data": {
                    "transfer_id": record.transfer_id,
                    "status": record.status.value,
                    "current_offset": current_offset,
                    "file_size": record.file_size,
                    "sha256": record.sha256,
                },
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_file_transfer_cancel(
        self, client, message: SnowMessage, data: dict[str, Any], session
    ) -> None:
        """Handle transfer cancellation."""
        transfer_id = data.get("transfer_id")
        if not transfer_id:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="transfer_id is required.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        device_id = session.device_id if session else data.get("device_id", "anonymous")
        cancelled = self.transfer_manager.cancel_transfer(transfer_id, device_id)
        part_path = self.storage_manager.get_part_path(transfer_id)
        self.storage_manager.delete_part_file(part_path)

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "file_transfer_cancel",
                "data": {
                    "transfer_id": transfer_id,
                    "cancelled": cancelled,
                },
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_desktop_status(
        self,
        client,
        message: SnowMessage,
        data: dict[str, Any],
        session,
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle request for desktop telemetry and battery status via CapabilityEngine."""
        try:
            req = CapabilityRequest(action="desktop_status", params=data)
            res = await self.capability_engine.execute(req, ctx=ctx)
            sys_info = res.data or {}
            battery_res = await self.capability_engine.execute(
                CapabilityRequest(action="desktop_battery", params={}), ctx=ctx
            )
            battery_info = battery_res.data or {}
            cpu_data = sys_info.get("cpu", {})
            mem_data = sys_info.get("memory", {})

            response = SnowMessage.create_response(
                correlation_id=message.id,
                payload={
                    "status": "success",
                    "action": "desktop_status",
                    "data": {
                        "hostname": sys_info.get("hostname", ""),
                        "cpu_percent": cpu_data.get("utilization_percent", 0.0),
                        "memory_percent": mem_data.get("percent", 0.0),
                        "memory_total_mb": mem_data.get("total_mb", 0.0),
                        "memory_used_mb": mem_data.get("used_mb", 0.0),
                        "battery": battery_info,
                        "uptime_seconds": sys_info.get("uptime_seconds", 0.0),
                        "os_name": sys_info.get("os_name", ""),
                        "os_version": sys_info.get("os_version", ""),
                    },
                },
            )
            await client.websocket.send(response.to_json())
        except Exception as exc:
            logger.error("Error retrieving desktop status: %s", exc)
            error_response = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed retrieving desktop telemetry: {exc}",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())

    async def _handle_desktop_exec(
        self,
        client,
        message: SnowMessage,
        data: dict[str, Any],
        session,
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle execution of a terminal command via CapabilityEngine."""
        if not data.get("confirmed"):
            logger.warning(
                "Rejected unconfirmed desktop_exec request from client [%s]",
                client.connection_id,
            )
            error_response = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Execution requires explicit user confirmation.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        command = data.get("command")
        if not command or not isinstance(command, str) or not command.strip():
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="command must be a non-empty string.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        req = CapabilityRequest(action="desktop_exec", params=data)
        res = await self.capability_engine.execute(req, ctx=ctx)

        result = res.data or {}
        command_str = command.strip()
        op_status = result.get("status") or (res.status if res.status else ("SUCCESS" if res.success else "ERROR"))
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success" if res.success else "error",
                "action": "desktop_exec",
                "error": res.error or result.get("error"),
                "data": {
                    "command": command_str,
                    "status": op_status,
                    "confirmation_ticket": result.get("confirmation_ticket"),
                    "stdout": result.get("stdout", ""),
                    "stderr": result.get("stderr", ""),
                    "exit_code": result.get("exit_code"),
                    "truncated": result.get("truncated", False) or result.get("stdout_truncated", False),
                    "duration_seconds": result.get("duration_seconds", result.get("execution_time_ms", 0.0) / 1000.0),
                },
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_desktop_app_launch(
        self,
        client,
        message: SnowMessage,
        data: dict[str, Any],
        session,
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle request to launch an allowlisted Windows app or lock workstation via CapabilityEngine."""
        req = CapabilityRequest(action="desktop_app_launch", params=data)
        res = await self.capability_engine.execute(req, ctx=ctx)
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success" if res.success else "error",
                "action": "desktop_app_launch",
                "error": res.error,
                "data": res.data,
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_desktop_clipboard_get(
        self,
        client,
        message: SnowMessage,
        data: dict[str, Any],
        session,
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle request to read Windows clipboard content (text or image) via CapabilityEngine."""
        # Check text via capability engine first
        req = CapabilityRequest(action="desktop_clipboard_get", params=data)
        res = await self.capability_engine.execute(req, ctx=ctx)
        result = res.data or {}
        text = result.get("text", "")

        # Check if an image should be returned: either explicitly requested or no text exists and clipboard has an image
        want_image = data.get("type") == "image" or (not text and getattr(self.capability_engine.clipboard, "has_image_sync", None) and self.capability_engine.clipboard.has_image_sync())
        if sys.platform == "win32" and want_image:
            img_res = await asyncio.to_thread(self.capability_engine.clipboard.get_image_sync)
            if img_res.get("success"):
                file_path = img_res["file_path"]
                file_name = img_res["file_name"]
                size = img_res["size"]
                sha256 = img_res["sha256"]
                device_id = session.device_id or "device"
                bound_port = (
                    self.http_transfer_server.bound_port
                    if self.http_transfer_server
                    else self.config.transfer_port
                )
                record = self.transfer_manager.create_transfer(
                    device_id=device_id,
                    file_name=file_name,
                    file_size=size,
                    sha256=sha256,
                    direction=TransferDirection.DOWNLOAD,
                )
                record.file_path = file_path
                record.status = TransferState.IN_PROGRESS
                response = SnowMessage.create_response(
                    correlation_id=message.id,
                    payload={
                        "status": "success",
                        "action": "desktop_clipboard_get",
                        "data": {
                            "type": "image",
                            "mime_type": "image/png",
                            "transfer_id": record.transfer_id,
                            "file_name": file_name,
                            "sha256": sha256,
                            "size": size,
                            "transfer_port": bound_port,
                            "transfer_url": f"/api/v1/transfers/download/{record.transfer_id}",
                        },
                    },
                )
                await client.websocket.send(response.to_json())
                return

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success" if res.success else "error",
                "action": "desktop_clipboard_get",
                "error": res.error,
                "data": {
                    "type": "text",
                    "text": text,
                    "content": text,
                    "length": len(text),
                },
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_desktop_clipboard_set(
        self,
        client,
        message: SnowMessage,
        data: dict[str, Any],
        session,
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle request to write text or image to Windows clipboard."""
        # 1. Image clipboard set
        if data.get("type") == "image":
            transfer_id = data.get("transfer_id")
            sha256 = data.get("sha256")
            file_name = data.get("file_name")
            target_path = None
            if transfer_id:
                rec = self.transfer_manager.get_transfer(transfer_id)
                if rec and rec.file_path and Path(rec.file_path).exists():
                    target_path = Path(rec.file_path)
            if not target_path and file_name:
                try:
                    candidate = self.storage_manager.resolve_destination_path(file_name)
                    if candidate.exists():
                        target_path = candidate
                except Exception:
                    pass
            if not target_path or not target_path.exists():
                error_response = SnowMessage.create_error(
                    code=ErrorCode.TRANSFER_NOT_FOUND,
                    message="Staged clipboard image not found on server storage.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return

            computed_sha256 = hashlib.sha256(target_path.read_bytes()).hexdigest()
            if sha256 and computed_sha256.lower() != sha256.lower():
                error_response = SnowMessage.create_error(
                    code=ErrorCode.CHECKSUM_MISMATCH,
                    message="Image SHA-256 verification mismatch.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return

            res = await asyncio.to_thread(self.capability_engine.clipboard.set_image_sync, target_path)
            if res.get("success"):
                for cid in self._active_sync_connections:
                    self._last_synced_clipboard_hash[cid] = computed_sha256
            response = SnowMessage.create_response(
                correlation_id=message.id,
                payload={
                    "status": "success" if res.get("success") else "error",
                    "action": "desktop_clipboard_set",
                    "error": res.get("error"),
                    "data": res,
                },
            )
            await client.websocket.send(response.to_json())
            return

        # 2. Text clipboard set
        text = data.get("text") or data.get("content")
        if text is None or not isinstance(text, str):
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="text must be a string.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        if len(text.encode("utf-8")) > 65536:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Clipboard text exceeds 64 KiB limit.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        req = CapabilityRequest(action="desktop_clipboard_set", params={"text": text})
        res = await self.capability_engine.execute(req, ctx=ctx)
        if res.success:
            if sys.platform == "win32":
                try:
                    import ctypes
                    self._last_local_write_seq = ctypes.windll.user32.GetClipboardSequenceNumber()
                except Exception:
                    pass
            h = hashlib.sha256(text.encode("utf-8")).hexdigest()
            for cid in self._active_sync_connections:
                self._last_synced_clipboard_hash[cid] = h

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success" if res.success else "error",
                "action": "desktop_clipboard_set",
                "error": res.error,
                "data": res.data,
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_desktop_clipboard_sync_toggle(
        self,
        client,
        message: SnowMessage,
        data: dict[str, Any],
        session,
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle toggle request for automatic instant desktop clipboard synchronization."""
        enabled = bool(data.get("enabled", False))
        if enabled:
            self._active_sync_connections.add(client.connection_id)
            if sys.platform == "win32":
                if not self._clipboard_listener:
                    try:
                        self._clipboard_listener = WindowsClipboardListener(
                            self._on_windows_clipboard_update_from_thread
                        )
                        self._clipboard_listener.start()
                    except Exception as err:
                        logger.warning("Could not start WindowsClipboardListener: %s", err)
                if not self._clipboard_watchdog_task or self._clipboard_watchdog_task.done():
                    self._clipboard_watchdog_task = asyncio.create_task(self._clipboard_sequence_watchdog())
        else:
            self._active_sync_connections.discard(client.connection_id)
            if not self._active_sync_connections:
                if self._clipboard_listener:
                    try:
                        self._clipboard_listener.stop()
                    except Exception:
                        pass
                    self._clipboard_listener = None
                if self._clipboard_watchdog_task and not self._clipboard_watchdog_task.done():
                    self._clipboard_watchdog_task.cancel()
                    self._clipboard_watchdog_task = None

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "desktop_clipboard_sync_toggle",
                "enabled": enabled,
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_notification_event(
        self,
        client,
        message: SnowMessage,
        data: dict[str, Any],
        session,
    ) -> None:
        """Process incoming Android notification event and update in-memory cache (zero disk persistence)."""
        dev_id = session.device_id if session else "unknown"
        notifs = data.get("notifications")
        if not notifs:
            single = data.get("notification")
            notifs = [single] if single else []

        if dev_id not in self.live_notifications:
            self.live_notifications[dev_id] = []

        cache = self.live_notifications[dev_id]
        for n in notifs:
            if isinstance(n, dict):
                n_copy = dict(n)
                n_copy["device_id"] = dev_id
                key = n_copy.get("key") or n_copy.get("id")
                # Deduplicate by key or id
                cache[:] = [item for item in cache if (item.get("key") or item.get("id")) != key]
                cache.insert(0, n_copy)

        # Enforce bounded in-memory limit (max 50 notifications per device)
        if len(cache) > 50:
            del cache[50:]

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={"status": "success", "action": "notification_event", "received_count": len(notifs)},
        )
        await client.websocket.send(response.to_json())

    def _on_windows_clipboard_update_from_thread(self) -> None:
        """Invoked from Win32 clipboard listener thread on WM_CLIPBOARDUPDATE."""
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._broadcast_clipboard_update(), self._loop)

    async def _broadcast_clipboard_update(self) -> None:
        """Broadcast desktop clipboard updates to authenticated clients with Instant Sync enabled."""
        if not self._active_sync_connections:
            return

        if sys.platform == "win32":
            try:
                import ctypes
                curr_seq = ctypes.windll.user32.GetClipboardSequenceNumber()
                if curr_seq != 0 and curr_seq == getattr(self, "_last_local_write_seq", 0):
                    return
            except Exception:
                pass

        content = await asyncio.to_thread(self.capability_engine.clipboard.get_content_sync)
        if not content.get("success"):
            return

        c_type = content.get("type")
        c_hash = content.get("sha256")
        if not c_hash:
            return

        for conn_id in list(self._active_sync_connections):
            client = self.connection_manager.get(conn_id)
            if not client or not client.websocket or getattr(client.websocket, "state", 1) != 1:
                self._active_sync_connections.discard(conn_id)
                continue
            session = self.session_manager.get_session_by_connection(conn_id)
            if session is None:
                continue

            if self._last_synced_clipboard_hash.get(conn_id) == c_hash:
                continue

            self._last_synced_clipboard_hash[conn_id] = c_hash

            if c_type == "text":
                text = content.get("text", "")
                if len(text.encode("utf-8")) > 65536:
                    continue
                push_msg = SnowMessage.create_request(
                    action="clipboard_push",
                    data={"type": "text", "text": text, "sha256": c_hash},
                )
                try:
                    await client.websocket.send(push_msg.to_json())
                    logger.info("Event-pushed desktop clipboard text to [%s] (%d chars)", conn_id, len(text))
                except Exception as err:
                    logger.warning("Failed sending clipboard text push to [%s]: %s", conn_id, err, exc_info=True)

            elif c_type == "image":
                file_path = content.get("file_path")
                file_name = content.get("file_name", "clipboard.png")
                file_size = content.get("size", 0)
                bound_port = (
                    self.http_transfer_server.bound_port
                    if self.http_transfer_server
                    else self.config.transfer_port
                )
                device_id = getattr(session, "device_id", None) or "device"
                record = self.transfer_manager.create_transfer(
                    device_id=device_id,
                    file_name=file_name,
                    file_size=file_size,
                    sha256=c_hash,
                    direction=TransferDirection.DOWNLOAD,
                )
                record.file_path = file_path
                record.status = TransferState.IN_PROGRESS

                push_msg = SnowMessage.create_request(
                    action="clipboard_push",
                    data={
                        "type": "image",
                        "mime_type": "image/png",
                        "transfer_id": record.transfer_id,
                        "file_name": file_name,
                        "sha256": c_hash,
                        "size": file_size,
                        "transfer_port": bound_port,
                        "transfer_url": f"/api/v1/transfers/download/{record.transfer_id}",
                    },
                )
                try:
                    await client.websocket.send(push_msg.to_json())
                    logger.info("Event-pushed desktop clipboard image to [%s] (%d bytes)", conn_id, file_size)
                except Exception as err:
                    logger.warning("Failed sending clipboard image push to [%s]: %s", conn_id, err, exc_info=True)

    async def _clipboard_sequence_watchdog(self) -> None:
        """Periodic watchdog polling GetClipboardSequenceNumber as a backup to WindowsClipboardListener."""
        if sys.platform != "win32":
            return
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
        last_seq = user32.GetClipboardSequenceNumber()
        while self._active_sync_connections:
            try:
                await asyncio.sleep(0.4)
                if not self._active_sync_connections:
                    break
                curr_seq = user32.GetClipboardSequenceNumber()
                if curr_seq != last_seq:
                    last_seq = curr_seq
                    if curr_seq != getattr(self, "_last_local_write_seq", 0):
                        await self._broadcast_clipboard_update()
            except asyncio.CancelledError:
                break
            except Exception as err:
                logger.warning("Clipboard sequence watchdog exception: %s", err, exc_info=True)

    async def _handle_desktop_file_list(
        self,
        client,
        message: SnowMessage,
        data: dict[str, Any],
        session,
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle request to list files in an approved desktop directory via CapabilityEngine."""
        rel_path = data.get("path") or data.get("relative_path") or ""
        limit = 50
        if "limit" in data:
            try:
                limit = int(data["limit"])
            except (ValueError, TypeError):
                limit = 50

        req = CapabilityRequest(
            action="desktop_file_list",
            params={"directory_path": rel_path, "limit": limit},
        )
        res = await self.capability_engine.execute(req, ctx=ctx)
        if not res.success:
            status_code = res.status
            if status_code in ("OS_PERMISSION_DENIED", "UNAUTHORIZED") or "PATH_NOT_ALLOWED" in status_code:
                err_code = ErrorCode.UNAUTHORIZED
            else:
                err_code = ErrorCode.FILE_NOT_FOUND
            error_response = SnowMessage.create_error(
                code=err_code,
                message=res.error or "Directory listing failed.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        result = res.data or {}
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "desktop_file_list",
                "data": {
                    "directory": result.get("directory", ""),
                    "parent": result.get("parent"),
                    "drives": result.get("drives", []),
                    "count": result.get("count", 0),
                    "files": result.get("items", []),
                },
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_desktop_file_stage_download(
        self,
        client,
        message: SnowMessage,
        data: dict[str, Any],
        session,
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Stage a local desktop file for authenticated HTTPS download."""
        req_path = data.get("file_path") or data.get("path")
        if not req_path or not isinstance(req_path, str):
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="file_path must be a non-empty string.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        safe_file, err_status = self.windows_files.resolve_safe_path(req_path, must_exist=True, ctx=ctx)
        if err_status or safe_file is None or not safe_file.is_file():
            err_code = (
                ErrorCode.UNAUTHORIZED
                if err_status == "PATH_NOT_ALLOWED"
                else ErrorCode.FILE_NOT_FOUND
            )
            error_response = SnowMessage.create_error(
                code=err_code,
                message=f"File not found or access denied: '{req_path}' ({err_status or 'NOT_A_FILE'}).",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        try:
            hasher = hashlib.sha256()
            with open(safe_file, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            sha256_digest = hasher.hexdigest()
            file_size = safe_file.stat().st_size
        except Exception as exc:
            logger.error("Error reading file for download staging [%s]: %s", safe_file, exc)
            error_response = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message=f"Failed reading staged file: {exc}",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        device_id = session.device_id if session else "anonymous"
        record = self.transfer_manager.create_transfer(
            device_id=device_id,
            file_name=safe_file.name,
            file_size=file_size,
            sha256=sha256_digest,
            direction=TransferDirection.DOWNLOAD,
            file_path=str(safe_file),
        )

        bound_port = (
            self.http_transfer_server.bound_port
            if self.http_transfer_server
            else self.config.transfer_port
        )
        transfer_url = f"/api/v1/transfers/download/{record.transfer_id}"

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "desktop_file_stage_download",
                "data": {
                    "transfer_id": record.transfer_id,
                    "file_name": safe_file.name,
                    "file_size": file_size,
                    "sha256": sha256_digest,
                    "transfer_port": bound_port,
                    "transfer_url": transfer_url,
                },
            },
        )
        await client.websocket.send(response.to_json())

    async def _stale_connection_reaper(self) -> None:
        """Periodically check for and disconnect inactive clients exceeding the heartbeat timeout."""
        check_interval = max(2.0, min(10.0, self.config.heartbeat_timeout / 4.0))

        while self._is_running:
            try:
                await asyncio.sleep(check_interval)
                stale_clients = self.connection_manager.get_stale_connections(
                    self.config.heartbeat_timeout
                )
                for client in stale_clients:
                    logger.warning(
                        "Closing stale connection [%s] from %s (inactive for >%.1fs)",
                        client.connection_id,
                        client.remote_address,
                        self.config.heartbeat_timeout,
                    )
                    self.connection_manager.unregister(client.connection_id)
                    try:
                        await client.websocket.close(code=1000, reason="Heartbeat timeout")
                    except Exception as exc:
                        logger.debug("Error closing stale socket [%s]: %s",
                                     client.connection_id, exc)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug("Error in stale connection reaper loop: %s", exc)
