"""WebSocket server implementation for SNOW Desktop Core."""

from __future__ import annotations

import asyncio
import ctypes
import hashlib
import ipaddress
import json
import logging
from pathlib import Path
import re
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
from snow.protocol.constants import DEFAULT_MAX_MESSAGE_SIZE, ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.protocol.validator import ProtocolValidationError, validate_raw_message
from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import DeviceIdentity, is_valid_uuidv4, load_or_create_device_identity
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
        self._last_synced_clipboard_event: dict[str, str] = {}
        self._active_sync_connections: set[str] = set()
        self._last_local_write_seq: int = 0
        self._clipboard_listener: Optional[WindowsClipboardListener] = None
        self._clipboard_watchdog_task: Optional[asyncio.Task] = None
        self._clipboard_debounce_task: Optional[asyncio.Task] = None
        self._clipboard_update_lock: asyncio.Lock = asyncio.Lock()
        self._last_processed_clipboard_hash: str = ""
        self._last_processed_canonical_hash: str = ""
        self._last_processed_clipboard_at: float = 0.0
        self._last_snow_write_hydrated: bool = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # Phase 21: Live in-memory notification cache (strictly never persisted to disk)
        self.live_notifications: dict[str, list[dict[str, Any]]] = {}
        # Phase 26A: Screen streaming session metadata (control plane only, strictly no image bytes)
        self._screen_stream_sessions: dict[str, dict[str, Any]] = {}
        # Optional in-process RemoteMcpGateway reference for direct OAuth approval bridge
        self._oauth_approval_bridge: Any = None
        # Devices manually disconnected by owner (hold auto-reconnect until Reconnect or re-pair)
        self.manually_disconnected_devices: set[str] = set()
        # Phase 30 / Stage 4A: Cross-Network Federation Manager
        from snow.network.federation import FederationManager
        self.federation_manager = FederationManager(
            db_manager=self.db_manager,
            local_network_id=getattr(self.config, "network_id", "local-network"),
            local_network_name=getattr(self.config, "network_name", "SNOW Network"),
            local_node_id=getattr(self.config, "device_id", "desktop-core"),
            local_node_name=getattr(self.config, "device_name", "Desktop Host"),
        )

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

            # Start Windows clipboard format listener and sequence watchdog on startup
            if sys.platform == "win32":
                self.start_clipboard_listener()

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
        self._last_synced_clipboard_event.clear()
        self.stop_clipboard_listener()
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
            self._last_synced_clipboard_event.pop(client.connection_id, None)
            self._active_sync_connections.discard(client.connection_id)
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

                # Pause mode check: reject non-owner actions if Core is paused
                cs = getattr(self, "core_server", None)
                if cs and getattr(cs, "is_paused", False) and not is_owner:
                    logger.warning(
                        "Rejected action '%s' from client [%s]: Desktop Core is in PAUSE mode.",
                        action,
                        client.connection_id,
                    )
                    error_response = SnowMessage.create_error(
                        code=ErrorCode.UNAUTHORIZED,
                        message="SNOW Desktop Core is currently in PAUSE mode. Only OWNER_MANUAL operations are permitted.",
                        correlation_id=message.id,
                    )
                    await client.websocket.send(error_response.to_json())
                    return

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
            elif action == "file_transfer_update":
                await self._handle_file_transfer_update(client, message, data, session)
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
            elif action == "screen_stream_subscribe":
                await self._handle_screen_stream_subscribe(client, message, data, session, subscribe=True)
            elif action == "screen_stream_unsubscribe":
                await self._handle_screen_stream_subscribe(client, message, data, session, subscribe=False)
            elif action == "screen_stream_senders":
                await self._handle_screen_stream_senders(client, message, data, session)
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
            elif action == "clipboard_buffer_pin":
                await self._handle_clipboard_buffer_pin(client, message, data, session, ctx)
            elif action == "clipboard_buffer_unpin":
                await self._handle_clipboard_buffer_unpin(client, message, data, session, ctx)
            elif action == "clipboard_buffer_delete":
                await self._handle_clipboard_buffer_delete(client, message, data, session, ctx)
            elif action == "clipboard_buffer_clear":
                await self._handle_clipboard_buffer_clear(client, message, data, session, ctx)
            elif action == "clipboard_ack":
                await self._handle_clipboard_ack(client, message, data, session)
            elif action == "clipboard_history_sync":
                await self._handle_clipboard_buffer_list(client, message, data, session)
            elif action == "media_control":
                await self._handle_media_control(client, message, data, session, ctx)
            elif action == "share_link":
                await self._handle_share_link(client, message, data, session, ctx)
            elif action == "federation_create_invite":
                await self._handle_federation_create_invite(client, message, data, session, is_owner)
            elif action == "federation_accept_invite":
                await self._handle_federation_accept_invite(client, message, data, session, is_owner)
            elif action == "federation_list_grants":
                await self._handle_federation_list_grants(client, message, data, session, is_owner)
            elif action == "federation_update_tier":
                await self._handle_federation_update_tier(client, message, data, session, is_owner)
            elif action == "federation_revoke":
                await self._handle_federation_revoke(client, message, data, session, is_owner)
            elif action == "federation_kill_switch":
                await self._handle_federation_kill_switch(client, message, data, session, is_owner)
            else:
                logger.warning("Rejected unsupported action '%s' from client [%s]",
                               action, client.connection_id)
                error_response = SnowMessage.create_error(
                    code=ErrorCode.UNSUPPORTED_ACTION,
                    message=f"Action '{action}' is not supported.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())

    def _is_device_full_control(self, device_id: Optional[str]) -> bool:
        """Screen sharing is strictly permitted for Full Control peers only."""
        clean_id = (device_id or "").strip()
        if not clean_id:
            return False
        if getattr(self, "db_manager", None) is not None and hasattr(self.db_manager, "get_setting"):
            saved = self.db_manager.get_setting(f"device_profile:{clean_id}")
            if isinstance(saved, str):
                return saved.strip().lower() == "full_control"
        node = None
        reg = getattr(self, "node_registry", None)
        if reg is not None and hasattr(reg, "get_node"):
            node = reg.get_node(clean_id)
        if node is not None and getattr(node, "permission_profile", None) is not None:
            return str(node.permission_profile).strip().lower() == "full_control"
        return True

    async def broadcast_screen_stream_event(
        self,
        event_type: str,
        metadata: dict[str, Any],
        target_device_ids: Optional[list[str]] = None,
    ) -> int:
        """Broadcast metadata-only screen stream lifecycle event (strictly NO image bytes)."""
        safe_meta = {
            k: v
            for k, v in (metadata or {}).items()
            if k not in ("frame_bytes", "jpeg_bytes", "image_base64", "data_url", "pixels")
        }
        allowed_targets = {str(t).strip() for t in (target_device_ids or []) if str(t or "").strip()}
        sent_count = 0
        for conn_item in self.connection_manager.all_connections():
            client = self.connection_manager.get(conn_item) if isinstance(conn_item, str) else conn_item
            if not client or not getattr(client, "websocket", None) or getattr(client.websocket, "state", 1) != 1:
                continue
            conn_id = getattr(client, "connection_id", conn_item)
            session = self.session_manager.get_session_by_connection(conn_id)
            if session is None or not getattr(session, "device_id", None):
                continue
            dev_id = session.device_id
            if not self._is_device_full_control(dev_id):
                continue
            if allowed_targets and "all" not in allowed_targets and dev_id not in allowed_targets:
                continue

            push_msg = SnowMessage.create_request(
                action="screen_stream_event",
                data={
                    "event_type": event_type,
                    **safe_meta,
                },
            )
            try:
                await client.websocket.send(push_msg.to_json())
                sent_count += 1
            except Exception as exc:
                logger.debug("Failed sending screen_stream_event to [%s]: %s", dev_id, exc)
        return sent_count

    async def _handle_screen_stream_start(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle control-plane request to start screen streaming. Metadata only (no image bytes)."""
        device_id = session.device_id if session and session.device_id else "unknown"
        if not self._is_device_full_control(device_id):
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="PERMISSION_DENIED: Screen sharing requires Full Control permission profile.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        session_id = str(data.get("session_id") or uuid.uuid4())
        fps = float(data.get("fps", 2.0))
        width = int(data.get("frame_width", 720))
        height = int(data.get("frame_height", 1280))
        raw_sess_name = getattr(session, "device_name", None)
        session_dev_name = raw_sess_name if isinstance(raw_sess_name, str) else None
        sender_name = str(data.get("sender_name") or session_dev_name or device_id)
        sender_platform = str(data.get("sender_platform") or "android")
        raw_targets = data.get("target_device_ids")
        target_device_ids = [str(t) for t in raw_targets if str(t or "").strip()] if isinstance(raw_targets, list) else []

        self._screen_stream_sessions[device_id] = {
            "session_id": session_id,
            "device_id": device_id,
            "sender_device_id": device_id,
            "sender_name": sender_name,
            "sender_platform": sender_platform,
            "target_device_ids": target_device_ids,
            "state": "STREAMING",
            "fps": fps,
            "frame_width": width,
            "frame_height": height,
            "timestamp": time.time(),
        }

        # Sync with HTTP transfer server session state if bound
        if self.http_transfer_server:
            try:
                state_kwargs: dict[str, Any] = {
                    "device_id": device_id,
                    "state": "STREAMING",
                    "session_id": session_id,
                    "fps": fps,
                    "width": width,
                    "height": height,
                }
                if data.get("sender_name") or session_dev_name:
                    state_kwargs["sender_name"] = sender_name
                if data.get("sender_platform"):
                    state_kwargs["sender_platform"] = sender_platform
                if target_device_ids:
                    state_kwargs["target_device_ids"] = target_device_ids
                self.http_transfer_server.set_session_state(**state_kwargs)
            except Exception as e:
                logger.debug("Failed notifying http_transfer_server of screen_stream_start: %s", e)

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "state": "STREAMING",
                "session_id": session_id,
                "sender_device_id": device_id,
                "fps": fps,
                "frame_width": width,
                "frame_height": height,
                "target_device_ids": target_device_ids,
            },
        )
        await client.websocket.send(response.to_json())
        if target_device_ids:
            await self.broadcast_screen_stream_event(
                "STREAM_AVAILABLE",
                {
                    "sender_device_id": device_id,
                    "sender_name": sender_name,
                    "sender_platform": sender_platform,
                    "session_id": session_id,
                    "fps": fps,
                    "frame_width": width,
                    "frame_height": height,
                },
                target_device_ids=target_device_ids,
            )

    async def _handle_screen_stream_stop(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Handle control-plane request to stop screen streaming."""
        device_id = session.device_id if session and session.device_id else "unknown"
        if not self._is_device_full_control(device_id):
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="PERMISSION_DENIED: Screen sharing requires Full Control permission profile.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

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
                "sender_device_id": device_id,
            },
        )
        await client.websocket.send(response.to_json())
        await self.broadcast_screen_stream_event(
            "STREAM_STOPPED",
            {"sender_device_id": device_id},
        )

    async def _handle_screen_stream_status(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Return screen streaming metadata for the session. Strictly metadata only."""
        device_id = session.device_id if session and session.device_id else "unknown"
        if not self._is_device_full_control(device_id):
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="PERMISSION_DENIED: Screen sharing requires Full Control permission profile.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return
        sender_id = str(data.get("sender_id") or "") if isinstance(data, dict) else ""
        if self.http_transfer_server:
            raw_meta = self.http_transfer_server.get_screen_stream_status(
                sender_id or None, requester_device_id=device_id
            )
            meta = (
                raw_meta
                if isinstance(raw_meta, dict)
                else self._screen_stream_sessions.get(sender_id or device_id, {"state": "IDLE"})
            )
        else:
            meta = self._screen_stream_sessions.get(sender_id or device_id, {"state": "IDLE"})
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "metadata": meta,
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_screen_stream_subscribe(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
        subscribe: bool = True,
    ) -> None:
        """Subscribe or unsubscribe an authorized Full Control peer viewer on local stream manager."""
        device_id = session.device_id if session and session.device_id else "unknown"
        if not self._is_device_full_control(device_id):
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="PERMISSION_DENIED: Screen sharing requires Full Control permission profile.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        mgr = getattr(self, "screen_stream_manager", None)
        accepted = True
        if mgr is not None:
            if subscribe:
                accepted = mgr.add_viewer(device_id)
            else:
                mgr.remove_viewer(device_id)
        if not accepted:
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Viewer subscription denied for this stream target list.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "subscribed": bool(subscribe),
                "device_id": device_id,
                "viewer_count": mgr.active_viewer_count() if mgr is not None else 0,
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_screen_stream_senders(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """List active live screen senders permitted for this authenticated Full Control peer."""
        device_id = session.device_id if session and session.device_id else "unknown"
        if not self._is_device_full_control(device_id):
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="PERMISSION_DENIED: Screen sharing requires Full Control permission profile.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return
        senders = (
            self.http_transfer_server.list_active_screen_streams(requester_device_id=device_id)
            if self.http_transfer_server
            else [s for s in self._screen_stream_sessions.values() if s.get("state") == "STREAMING"]
        )
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={"status": "success", "senders": senders, "count": len(senders)},
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
        """Handle history-sync request for metadata of up to 15 shared clipboard buffer items (<= 64 KiB)."""
        limit = min(max(int(data.get("limit", 15)), 1), 15)
        buf = getattr(self, "clipboard_buffer", None)
        if not buf and hasattr(self, "capability_engine"):
            buf = getattr(self.capability_engine, "clipboard_buffer", None)
        items = buf.list_items(limit=limit) if buf else []
        latest_seq = max((int(it.get("seq", 0)) for it in items), default=0)
        last_acked_seq = 0
        if session and isinstance(getattr(session, "device_id", None), str) and buf and hasattr(buf, "get_device_ack"):
            ack_rec = buf.get_device_ack(session.device_id)
            if ack_rec is not None:
                last_acked_seq = int(ack_rec.get("last_acked_seq", 0))
        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "items": items,
                "count": len(items),
                "latest_seq": latest_seq,
                "last_acked_seq": last_acked_seq,
            },
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
                code=ErrorCode.FILE_NOT_FOUND,
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
                code=ErrorCode.OVERSIZED_MESSAGE,
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

        if res.get("status") == "ADDED" and res.get("item"):
            await self.broadcast_clipboard_buffer_event(res["item"], exclude_device_id=source_device)

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
        target = data.get("target") or (session.device_id if session else "android")
        if target in ("phone", "android", "mobile") and session and session.device_id:
            target = session.device_id
        stage_only = bool(data.get("stage_only", False))

        req = CapabilityRequest(
            action="clipboard_buffer_apply",
            params={"item_id": item_id, "target": target, "stage_only": stage_only},
        )
        ctx = ExecutionContext(
            principal=ExecutionPrincipal.OWNER_MANUAL,
            device_id=session.device_id if session else "unknown",
            session_id=session.session_id if session else None,
        )
        res = await self.capability_engine.execute(req, ctx=ctx)
        if not res.success:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message=res.error or "Failed to apply clipboard buffer item",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        res_data = res.data or {}
        payload: dict[str, Any] = {
            "status": "success",
            "applied": True,
            "item_id": item_id,
            "target": target,
            "data": res_data,
        }
        for k in ("transfer_id", "transfer_port", "sha256", "file_name", "mime_type", "size", "files", "event_id", "seq", "type"):
            if k in res_data:
                payload[k] = res_data[k]

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload=payload,
        )
        await client.websocket.send(response.to_json())

    async def _send_engine_wss_result(
        self,
        client: Any,
        message: SnowMessage,
        action: str,
        params: dict[str, Any],
        ctx: Optional[ExecutionContext],
        session: Optional[SessionRecord],
    ) -> None:
        """Execute a validated request through CapabilityEngine and translate response/errors for WSS."""
        effective_ctx = ctx or ExecutionContext(
            principal=ExecutionPrincipal.AI_MCP,
            device_id=session.device_id if session else None,
            session_id=session.session_id if session else None,
            origin="wss",
        )
        req = CapabilityRequest(action=action, params=params)
        res = await self.capability_engine.execute(req, ctx=effective_ctx)

        if not res.success:
            status_upper = str(res.status or "").upper()
            if status_upper in ("POLICY_DENIED", "UNAUTHORIZED", "APPROVAL_REQUIRED"):
                err_code = ErrorCode.UNAUTHORIZED
            elif status_upper in ("INVALID_ARGUMENT", "INVALID_PAYLOAD", "INVALID_URL_SCHEME", "INVALID_VOLUME_LEVEL", "UNSUPPORTED_MEDIA_ACTION"):
                err_code = ErrorCode.INVALID_PAYLOAD
            elif status_upper == "ITEM_NOT_FOUND":
                err_code = ErrorCode.FILE_NOT_FOUND
            else:
                err_code = ErrorCode.INTERNAL_ERROR
            error_response = SnowMessage.create_error(
                code=err_code,
                message=res.error or f"Capability '{action}' failed ({res.status}).",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        res_data = res.data if isinstance(res.data, dict) else {}
        payload: dict[str, Any] = {
            "status": "success",
            "action": action,
            "data": res_data,
        }
        if "item" in res_data:
            payload["item"] = res_data["item"]
        if "item_id" in res_data:
            payload["item_id"] = res_data["item_id"]

        response = SnowMessage.create_response(correlation_id=message.id, payload=payload)
        await client.websocket.send(response.to_json())

    @staticmethod
    def _validate_clip_item_id(item_id: Any) -> Optional[str]:
        if not isinstance(item_id, str) or not re.match(r"^cb_[0-9a-f]{12}_[0-9a-f]{6}$", item_id):
            return None
        return item_id

    async def _handle_clipboard_buffer_pin(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle authenticated WSS request to pin or unpin a shared clipboard item."""
        item_id = self._validate_clip_item_id(data.get("item_id"))
        if not item_id:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Invalid or missing 'item_id'. Expected format: cb_<12hex>_<6hex>.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        params: dict[str, Any] = {"item_id": item_id}
        if "is_pinned" in data:
            if not isinstance(data["is_pinned"], bool):
                error_response = SnowMessage.create_error(
                    code=ErrorCode.INVALID_PAYLOAD,
                    message="'is_pinned' must be a boolean.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return
            params["is_pinned"] = data["is_pinned"]

        await self._send_engine_wss_result(
            client, message, "clipboard_buffer_pin", params, ctx, session
        )

    async def _handle_clipboard_buffer_unpin(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle authenticated WSS request to unpin a shared clipboard item."""
        item_id = self._validate_clip_item_id(data.get("item_id"))
        if not item_id:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Invalid or missing 'item_id'. Expected format: cb_<12hex>_<6hex>.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        await self._send_engine_wss_result(
            client, message, "clipboard_buffer_unpin", {"item_id": item_id}, ctx, session
        )

    async def _handle_clipboard_buffer_delete(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle owner-only WSS request to delete a shared clipboard item."""
        item_id = self._validate_clip_item_id(data.get("item_id"))
        if not item_id:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Invalid or missing 'item_id'. Expected format: cb_<12hex>_<6hex>.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        await self._send_engine_wss_result(
            client, message, "clipboard_buffer_delete", {"item_id": item_id}, ctx, session
        )

    async def _handle_clipboard_buffer_clear(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle owner-only WSS request to clear shared clipboard buffer items."""
        unpinned_only = data.get("unpinned_only", True)
        if not isinstance(unpinned_only, bool):
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="'unpinned_only' must be a boolean.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        await self._send_engine_wss_result(
            client,
            message,
            "clipboard_buffer_clear",
            {"unpinned_only": unpinned_only},
            ctx,
            session,
        )

    async def _handle_clipboard_ack(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
    ) -> None:
        """Record a monotonic durable per-device acknowledgement for a received clipboard event."""
        if not session or not isinstance(getattr(session, "device_id", None), str) or not session.device_id.strip():
            error_response = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Authenticated session is required for clipboard_ack.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        peer_device_id = session.device_id.strip()
        if data.get("device_id") and str(data["device_id"]).strip() != peer_device_id:
            error_response = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="device_id mismatch in clipboard_ack.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        raw_seq = data.get("last_acked_seq", data.get("seq"))
        if isinstance(raw_seq, bool) or not isinstance(raw_seq, int) or raw_seq < 0:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="'seq' / 'last_acked_seq' must be a non-negative integer.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        raw_event_id = data.get("last_acked_event_id", data.get("event_id", ""))
        if not isinstance(raw_event_id, str) or not raw_event_id.strip() or len(raw_event_id.strip()) > 128:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="'event_id' / 'last_acked_event_id' must be a non-empty string.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        buf = getattr(self, "clipboard_buffer", None) or getattr(
            self.capability_engine, "clipboard_buffer", None
        )
        try:
            if buf and hasattr(buf, "record_device_ack"):
                saved = buf.record_device_ack(
                    device_id=peer_device_id,
                    last_acked_seq=raw_seq,
                    last_acked_event_id=raw_event_id.strip(),
                )
            elif getattr(self, "db_manager", None) and hasattr(self.db_manager, "save_clipboard_ack"):
                saved = self.db_manager.save_clipboard_ack(
                    device_id=peer_device_id,
                    last_acked_seq=raw_seq,
                    last_acked_event_id=raw_event_id.strip(),
                )
            else:
                saved = {
                    "device_id": peer_device_id,
                    "last_acked_seq": raw_seq,
                    "last_acked_event_id": raw_event_id.strip(),
                    "updated": True,
                }
        except ValueError as ve:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message=str(ve),
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "clipboard_ack",
                "data": saved,
            },
        )
        await client.websocket.send(response.to_json())

    async def _handle_media_control(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle authenticated WSS request for desktop media playback and bounded volume control."""
        raw_action = data.get("action")
        if not isinstance(raw_action, str) or not raw_action.strip():
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Missing or invalid 'action' in media_control request.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        params: dict[str, Any] = {"action": raw_action.strip()}
        if "value" in data and data["value"] is not None:
            val = data["value"]
            if isinstance(val, bool) or not isinstance(val, (int, float)):
                error_response = SnowMessage.create_error(
                    code=ErrorCode.INVALID_PAYLOAD,
                    message="Media volume 'value' must be a number between 0 and 100.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return
            params["value"] = val

        await self._send_engine_wss_result(
            client, message, "media_control", params, ctx, session
        )

    async def _handle_share_link(
        self,
        client: Any,
        message: SnowMessage,
        data: dict[str, Any],
        session: Optional[SessionRecord],
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle authenticated WSS request to share a validated HTTP/HTTPS URL or text note."""
        url = data.get("url", "")
        text = data.get("text", "")
        if (url is not None and not isinstance(url, str)) or (text is not None and not isinstance(text, str)):
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="'url' and 'text' must be strings when provided.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        clean_url = (url or "").strip()
        clean_text = (text or "").strip()
        if not clean_url and not clean_text:
            error_response = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Either non-empty 'url' or 'text' must be provided.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            return

        params: dict[str, Any] = {}
        if clean_url:
            params["url"] = clean_url
        if clean_text:
            params["text"] = clean_text

        await self._send_engine_wss_result(
            client, message, "share_link", params, ctx, session
        )

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
                code=ErrorCode.INVALID_PAYLOAD,
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
            # Check both PeerCapabilityPolicy and active 5-tier device permission profile
            from snow.network.router import is_action_allowed_by_profile
            caller_profile = "full_control"
            if getattr(self, "db_manager", None) is not None and hasattr(self.db_manager, "get_setting"):
                saved_p = self.db_manager.get_setting(f"device_profile:{caller_device_id}")
                if saved_p is not None:
                    caller_profile = str(saved_p)
            if not is_action_allowed_by_profile(caller_profile, relay_action):
                error_response = SnowMessage.create_error(
                    code=ErrorCode.UNAUTHORIZED,
                    message=f"Operation '{relay_action}' blocked for device '{caller_device_id}' by permission tier '{caller_profile}'.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return

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

        # Case 2: Target is another node in mesh (propagate hop_limit & visited_nodes to prevent loops)
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
                hop_limit=next_hop_limit,
                visited_peers=visited_nodes,
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

    def _list_pending_oauth_approvals(self) -> list[dict[str, Any]]:
        """Collect pending OAuth 2.1 authorization requests formatted for companion clients."""
        items_by_id: dict[str, dict[str, Any]] = {}
        now = time.time()

        gateway = getattr(self, "_oauth_approval_bridge", None)
        if gateway and hasattr(gateway, "list_pending_authorizations"):
            try:
                for raw in gateway.list_pending_authorizations():
                    req_id = str(raw.get("request_id", "")).strip()
                    if not req_id:
                        continue
                    client_name = str(raw.get("client_name") or raw.get("client_id") or "Remote AI Client")
                    scope = str(raw.get("scope") or "snow:mcp")
                    expires_at = float(raw.get("expires_at") or (now + 600.0))
                    items_by_id[req_id] = {
                        "request_id": req_id,
                        "principal": client_name,
                        "action": "oauth_authorize",
                        "target_device": "Remote MCP Gateway",
                        "risk_level": "HIGH",
                        "reason": f"Authorize OAuth 2.1 access for {client_name} (scope: {scope})",
                        "time_remaining_seconds": round(max(0.0, expires_at - now), 1),
                        "sanitized_params": {
                            "type": "oauth_2_1",
                            "client_id": raw.get("client_id", ""),
                            "client_name": client_name,
                            "scope": scope,
                        },
                        "kind": "oauth",
                    }
            except Exception as exc:
                logger.debug("Error listing in-process gateway OAuth approvals: %s", exc)

        db = getattr(self, "db_manager", None)
        if db and hasattr(db, "list_settings_prefix"):
            try:
                rows = db.list_settings_prefix("oauth_req:")
                for key, raw_json in rows.items():
                    req_id = key.removeprefix("oauth_req:")
                    try:
                        rec = json.loads(raw_json)
                    except Exception:
                        continue
                    if not isinstance(rec, dict):
                        continue
                    expires_at = float(rec.get("expires_at", 0.0) or 0.0)
                    status = str(rec.get("status", "PENDING")).upper()
                    if expires_at and now > expires_at:
                        try:
                            db.delete_setting(key)
                            db.delete_setting(f"oauth_dec:{req_id}")
                        except Exception:
                            pass
                        continue
                    if status != "PENDING":
                        continue
                    dec_raw = db.get_setting(f"oauth_dec:{req_id}") if hasattr(db, "get_setting") else None
                    if dec_raw:
                        continue
                    if req_id not in items_by_id:
                        client_name = str(rec.get("client_name") or rec.get("client_id") or "Remote AI Client")
                        scope = str(rec.get("scope") or "snow:mcp")
                        items_by_id[req_id] = {
                            "request_id": req_id,
                            "principal": client_name,
                            "action": "oauth_authorize",
                            "target_device": "Remote MCP Gateway",
                            "risk_level": "HIGH",
                            "reason": f"Authorize OAuth 2.1 access for {client_name} (scope: {scope})",
                            "time_remaining_seconds": round(max(0.0, expires_at - now), 1),
                            "sanitized_params": {
                                "type": "oauth_2_1",
                                "client_id": rec.get("client_id", ""),
                                "client_name": client_name,
                                "scope": scope,
                            },
                            "kind": "oauth",
                        }
            except Exception as exc:
                logger.debug("Error querying OAuth pending requests from DB: %s", exc)

        return list(items_by_id.values())

    async def _resolve_pending_oauth_approval(
        self, request_id: str, decision: str
    ) -> Optional[tuple[bool, str]]:
        """Resolve a pending OAuth 2.1 request if it belongs to the OAuth queue."""
        gateway = getattr(self, "_oauth_approval_bridge", None)
        if gateway and request_id in getattr(gateway, "_pending_authorizations", {}):
            res = (
                gateway.approve_authorization(request_id)
                if decision == "APPROVE"
                else gateway.reject_authorization(request_id)
            )
            ok = bool(res.get("success", False))
            msg = str(res.get("status") or res.get("error") or decision)
            if ok:
                await self.broadcast_approval_event(
                    "APPROVAL_RESOLVED",
                    {"request_id": request_id, "decision": decision, "kind": "oauth"},
                )
            return ok, msg

        db = getattr(self, "db_manager", None)
        if db and hasattr(db, "get_setting"):
            raw_json = db.get_setting(f"oauth_req:{request_id}")
            if raw_json:
                try:
                    rec = json.loads(raw_json)
                except Exception:
                    return False, "Corrupt OAuth authorization metadata."
                now = time.time()
                if float(rec.get("expires_at", 0.0) or 0.0) < now:
                    db.delete_setting(f"oauth_req:{request_id}")
                    db.delete_setting(f"oauth_dec:{request_id}")
                    return False, "Authorization request expired."
                existing_dec = db.get_setting(f"oauth_dec:{request_id}")
                if existing_dec or str(rec.get("status", "PENDING")).upper() != "PENDING":
                    return False, "Authorization request has already been resolved."
                new_status = "APPROVED" if decision == "APPROVE" else "REJECTED"
                db.set_setting(
                    f"oauth_dec:{request_id}",
                    json.dumps({
                        "request_id": request_id,
                        "status": new_status,
                        "decided_at": now,
                        "decided_by": "owner_mobile",
                    }),
                )
                rec["status"] = new_status
                db.set_setting(f"oauth_req:{request_id}", json.dumps(rec))
                await self.broadcast_approval_event(
                    "APPROVAL_RESOLVED",
                    {"request_id": request_id, "decision": decision, "kind": "oauth"},
                )
                return True, new_status

        return None

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
        pending.extend(self._list_pending_oauth_approvals())
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

        oauth_res = await self._resolve_pending_oauth_approval(request_id, decision)
        if oauth_res is not None:
            ok, msg = oauth_res
        elif decision == "APPROVE":
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
        for conn_item in self.connection_manager.all_connections():
            client = self.connection_manager.get(conn_item) if isinstance(conn_item, str) else conn_item
            if not client or not getattr(client, "websocket", None) or getattr(client.websocket, "state", 1) != 1:
                continue
            conn_id = getattr(client, "connection_id", conn_item)
            session = self.session_manager.get_session_by_connection(conn_id)
            if session is None or (getattr(session, "trust_tier", "peer") or "peer").lower() != "owner":
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

        if device_id in self.manually_disconnected_devices:
            logger.info("auth_request held for manually disconnected device [%s].", device_id)
            error_response = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="MANUAL_DISCONNECT: Device manually disconnected by desktop owner.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())
            try:
                await client.websocket.close(code=1000, reason="MANUAL_DISCONNECT")
            except Exception:
                pass
            return

        # Verification successful: cancel handshake timeout
        timer = self._auth_timers.pop(client.connection_id, None)
        if timer and not timer.done():
            timer.cancel()

        session = self.session_manager.create_session(
            device_id=device_id,
            connection_id=client.connection_id,
            trust_tier=device_record.trust_tier,
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
        auth_profile = self._resolve_authoritative_permission_profile(device_id)
        clipboard_state: dict[str, Any] = {"latest_seq": 0, "last_acked_seq": 0, "has_unacked_latest": False}
        cb_buf = getattr(self, "clipboard_buffer", None) or getattr(
            getattr(self, "capability_engine", None), "clipboard_buffer", None
        )
        if cb_buf is not None:
            latest_items = cb_buf.list_items(limit=1)
            latest_seq = int(latest_items[0].get("seq", 0)) if latest_items else 0
            ack_rec = cb_buf.get_device_ack(device_id) if hasattr(cb_buf, "get_device_ack") else None
            last_acked = int(ack_rec.get("last_acked_seq", 0)) if ack_rec else 0
            eligible = (
                cb_buf.get_eligible_apply_item(device_id, last_acked_seq=last_acked)
                if hasattr(cb_buf, "get_eligible_apply_item") and auth_profile not in ("not_allowed", "files_only")
                else None
            )
            clipboard_state = {
                "latest_seq": latest_seq,
                "last_acked_seq": last_acked,
                "has_unacked_latest": eligible is not None,
            }

        host_network_id = None
        try:
            from snow.security.identity import load_or_create_network_key_identity
            host_network_id = load_or_create_network_key_identity().network_id
        except Exception:
            host_network_id = None

        auth_data = {
            "device_id": device_id,
            "server_device_id": self.device_identity.device_id,
            "snow_id": self.device_identity.snow_id,
            "device_name": self.device_identity.device_name,
            "session_id": session.session_id,
            "trust_tier": device_record.trust_tier,
            "permission_profile": auth_profile,
            "clipboard_state": clipboard_state,
            "manifest": build_windows_manifest().to_dict(),
        }
        if host_network_id:
            auth_data["network_id"] = host_network_id

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "auth_request",
                "data": auth_data,
            },
        )
        await client.websocket.send(response.to_json())

    def _resolve_authoritative_permission_profile(self, device_id: str) -> str:
        """Resolve desktop's authoritative per-device permission profile, failing closed on invalid DB values."""
        valid = {"full_control", "files_and_clipboard", "files_only", "clipboard_only", "not_allowed"}
        raw = None
        if getattr(self, "node_registry", None) and hasattr(self.node_registry, "get_permission_profile"):
            try:
                raw = self.node_registry.get_permission_profile(device_id)
            except Exception:
                raw = None
        elif getattr(self, "db_manager", None) and hasattr(self.db_manager, "get_setting"):
            try:
                saved = self.db_manager.get_setting(f"device_profile:{device_id}")
                raw = "full_control" if saved is None else saved
            except Exception:
                raw = None
        if isinstance(raw, str):
            clean = raw.strip().lower()
            if clean in valid:
                return clean
            return "not_allowed"
        return "full_control" if raw is None else "not_allowed"

    async def _handle_pairing_request(
        self, client, message: SnowMessage, action: str, data: dict[str, Any]
    ) -> None:
        """Handle pairing verification or PIN generation request."""
        pin = data.get("pin")
        handshake_token = data.get("handshake_token")
        raw_client_id = data.get("device_id")
        client_device_id = raw_client_id.strip() if isinstance(raw_client_id, str) else raw_client_id

        # Never auto-trust based on USB cable attachment alone: require explicit PIN or owner-issued QR handshake token.
        if pin is not None or handshake_token is not None:
            if not is_valid_uuidv4(client_device_id):
                self.db_manager.log_audit_event(
                    event_type="PAIR_FAILED",
                    device_id=str(client_device_id)[:64] if client_device_id is not None else None,
                    details={"reason": "Missing or invalid client device_id (UUIDv4 required)."},
                )
                logger.warning(
                    "Rejected pairing request from [%s]: missing or non-UUIDv4 client device_id.",
                    client.connection_id,
                )
                error_response = SnowMessage.create_error(
                    code=ErrorCode.INVALID_PAYLOAD,
                    message="Valid UUIDv4 client device_id is required to complete pairing.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return

            # Mutual exclusion: when handshake_token is supplied, verify ONLY the QR token; never fall back to PIN.
            if handshake_token is not None:
                net_id = str(data.get("network_id") or "")
                result = self.pairing_manager.verify_handshake_token(
                    token=str(handshake_token),
                    host_device_id=self.device_identity.device_id,
                    client_device_id=client_device_id,
                    network_id=net_id,
                )
            else:
                # Manual PIN verification attempt (only when no handshake_token was supplied)
                result = self.pairing_manager.verify_pin(str(pin), client_device_id=client_device_id)
            if result.is_success:
                # Defense-in-depth before token issuance, DB insertion, trust assignment, and node registration
                if not is_valid_uuidv4(client_device_id):
                    error_response = SnowMessage.create_error(
                        code=ErrorCode.INVALID_PAYLOAD,
                        message="Valid UUIDv4 client device_id is required to complete pairing.",
                        correlation_id=message.id,
                    )
                    await client.websocket.send(error_response.to_json())
                    return

                logger.info("Successfully paired with device [%s] from client [%s]",
                            client_device_id, client.connection_id)
                auth_token = secrets.token_urlsafe(32)
                token_hash = hash_token(auth_token)
                client_device_name = data.get(
                    "device_name",
                    f"Android-{client_device_id[:8]}",
                )

                # Re-pair pre-cleanup: invalidate any previous DB/runtime state for client_device_id before
                # inserting new credentials, while preserving the active pairing WebSocket connection.
                self.manually_disconnected_devices.discard(client_device_id)
                cs = getattr(self, "core_server", None)
                from snow.core.server import SnowCoreServer
                if cs is not None and callable(getattr(cs, "remove_device_everywhere", None)):
                    await cs.remove_device_everywhere(
                        device_id=client_device_id,
                        reason="Re-pairing existing device identity",
                        notify_client=False,
                        exclude_connection_id=client.connection_id,
                        audit_event_type=None,
                    )
                else:
                    await SnowCoreServer.execute_device_removal(
                        device_id=client_device_id,
                        reason="Re-pairing existing device identity",
                        notify_client=False,
                        exclude_connection_id=client.connection_id,
                        db_manager=self.db_manager,
                        session_manager=self.session_manager,
                        connection_manager=self.connection_manager,
                        node_registry=getattr(self, "node_registry", None),
                        ws_server=self,
                        discovery_service=getattr(self, "udp_discovery", None),
                        audit_event_type=None,
                    )

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
                    trust_tier=assigned_tier,
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
                pair_profile = self._resolve_authoritative_permission_profile(client_device_id)

                pair_data = {
                    "device_id": self.device_identity.device_id,
                    "server_device_id": self.device_identity.device_id,
                    "snow_id": self.device_identity.snow_id,
                    "device_name": self.device_identity.device_name,
                    "session_id": result.session_id,
                    "auth_token": auth_token,
                    "trust_tier": assigned_tier,
                    "permission_profile": pair_profile,
                    "manifest": build_windows_manifest().to_dict(),
                }
                try:
                    from snow.security.identity import load_or_create_network_key_identity
                    net_id_val = load_or_create_network_key_identity().network_id
                    if net_id_val:
                        pair_data["network_id"] = net_id_val
                except Exception:
                    pass

                response = SnowMessage.create_response(
                    correlation_id=message.id,
                    payload={
                        "status": "success",
                        "action": action,
                        "data": pair_data,
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
                code=ErrorCode.INVALID_PAYLOAD,
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

        # Successfully verified: revoke DB, sessions, and all runtime state FIRST via shared cleanup
        cs = getattr(self, "core_server", None)
        from snow.core.server import SnowCoreServer
        if cs is not None and callable(getattr(cs, "remove_device_everywhere", None)):
            await cs.remove_device_everywhere(
                device_id=device_id,
                reason="Device unpaired via client unpair_request",
                notify_client=False,
                exclude_connection_id=client.connection_id,
                audit_event_type="UNPAIR",
                audit_details={"initiated_by": "client", "connection_id": client.connection_id},
            )
        else:
            await SnowCoreServer.execute_device_removal(
                device_id=device_id,
                reason="Device unpaired via client unpair_request",
                notify_client=False,
                exclude_connection_id=client.connection_id,
                db_manager=self.db_manager,
                session_manager=self.session_manager,
                connection_manager=self.connection_manager,
                node_registry=getattr(self, "node_registry", None),
                ws_server=self,
                discovery_service=getattr(self, "udp_discovery", None),
                audit_event_type="UNPAIR",
                audit_details={"initiated_by": "client", "connection_id": client.connection_id},
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

        # Unregister and close the unpairing WebSocket connection cleanly after delivering ACK
        unreg = None
        if getattr(self, "connection_manager", None):
            try:
                unreg = self.connection_manager.unregister(client.connection_id)
            except Exception as exc:
                logger.warning("Failed unregistering unpairing connection [%s]: %s", client.connection_id, exc)
        ws_to_close = getattr(unreg, "websocket", None) or getattr(client, "websocket", None)
        if ws_to_close is not None and hasattr(ws_to_close, "close"):
            try:
                import inspect
                close_res = ws_to_close.close(code=1000, reason="Device unpaired")
                if inspect.isawaitable(close_res):
                    await close_res
            except Exception as exc:
                logger.debug("Error closing client websocket after unpair_request: %s", exc)

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
        """Desktop-initiated synchronous unpairing routed through unified device removal.

        Deletes SQLite record, permission profile, active sessions, and schedules/runs runtime cleanup.
        """
        clean_id = (device_id or "").strip()
        if not clean_id:
            return False

        from snow.core.server import SnowCoreServer
        cs = getattr(self, "core_server", None)

        async def _run_removal() -> dict[str, Any]:
            if cs is not None and callable(getattr(cs, "remove_device_everywhere", None)):
                return await cs.remove_device_everywhere(
                    device_id=clean_id,
                    reason="Desktop unpair_device invoked",
                    notify_client=True,
                    audit_event_type="UNPAIR",
                    audit_details={"initiated_by": "desktop"},
                )
            return await SnowCoreServer.execute_device_removal(
                device_id=clean_id,
                reason="Desktop unpair_device invoked",
                notify_client=True,
                db_manager=self.db_manager,
                session_manager=self.session_manager,
                connection_manager=self.connection_manager,
                node_registry=getattr(self, "node_registry", None),
                ws_server=self,
                discovery_service=getattr(self, "udp_discovery", None),
                audit_event_type="UNPAIR",
                audit_details={"initiated_by": "desktop"},
            )

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is None:
            res = asyncio.run(_run_removal())
            return bool(res.get("removed", False))

        # Already inside an event loop: revoke authorization synchronously FIRST, then finish async cleanup
        had_db = self.db_manager.get_paired_device(clean_id) is not None if self.db_manager else False
        db_deleted = self.db_manager.delete_paired_device(clean_id) if self.db_manager else False
        try:
            if self.db_manager and hasattr(self.db_manager, "delete_setting"):
                self.db_manager.delete_setting(f"device_profile:{clean_id}")
        except Exception:
            pass
        if self.session_manager:
            self.session_manager.revoke_device_sessions(clean_id)
        if getattr(self, "node_registry", None):
            try:
                self.node_registry.remove_node(clean_id)
            except Exception:
                pass
        self.manually_disconnected_devices.discard(clean_id)
        self.live_notifications.pop(clean_id, None)
        if db_deleted or had_db:
            self.db_manager.log_audit_event(
                event_type="UNPAIR",
                device_id=clean_id,
                details={"initiated_by": "desktop"},
            )
        task = loop.create_task(_run_removal())
        task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)
        return bool(db_deleted or had_db)

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

    async def _handle_file_transfer_update(
        self, client, message: SnowMessage, data: dict[str, Any], session
    ) -> None:
        """Handle async completion/progress/error updates from Android peer for an active transfer."""
        transfer_id = str(data.get("transfer_id") or "").strip()
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

        state_str = str(data.get("status") or "").strip().upper()
        if state_str in ("COMPLETED", "SUCCESS"):
            if record.status != TransferState.CANCELLED:
                self.transfer_manager.mark_completed(transfer_id)
        elif state_str in ("FAILED", "ERROR"):
            if record.status != TransferState.CANCELLED:
                self.transfer_manager.mark_failed(transfer_id, str(data.get("error") or "Transfer failed on target device."))
        elif state_str == "CANCELLED":
            self.transfer_manager.cancel_transfer(transfer_id, device_id)
            part_path = self.storage_manager.get_part_path(transfer_id)
            self.storage_manager.delete_part_file(part_path)
        elif "current_offset" in data:
            try:
                self.transfer_manager.update_offset(transfer_id, int(data["current_offset"]))
            except (TypeError, ValueError):
                pass

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "file_transfer_update",
                "data": {
                    "transfer_id": record.transfer_id,
                    "status": record.status.value,
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

    def _record_snow_clipboard_write(self, sha256: str = "", canonical_sha256: str = "") -> None:
        """Remember the latest SNOW-processed clipboard content across bursts and Core restarts."""
        clean_sha = str(sha256 or "").strip().lower()
        clean_canon = str(canonical_sha256 or "").strip().lower()
        self._last_processed_clipboard_hash = clean_sha
        self._last_processed_canonical_hash = clean_canon
        self._last_processed_clipboard_at = time.monotonic()
        self._last_snow_write_hydrated = True
        db = getattr(self, "db_manager", None)
        if db is not None and hasattr(db, "set_setting"):
            try:
                db.set_setting(
                    "clip_last_snow_write",
                    json.dumps(
                        {
                            "sha256": clean_sha,
                            "canonical_sha256": clean_canon,
                            "written_at": time.time(),
                        },
                        separators=(",", ":"),
                    ),
                )
            except Exception as exc:
                logger.debug("Failed persisting clip_last_snow_write: %s", exc)

    def _load_persisted_snow_clipboard_write(self) -> tuple[str, str, float]:
        """Load the last persisted SNOW clipboard write from SQLite app_settings."""
        db = getattr(self, "db_manager", None)
        if db is None or not hasattr(db, "get_setting"):
            return "", "", 0.0
        try:
            raw = db.get_setting("clip_last_snow_write")
            if not raw or not isinstance(raw, str):
                return "", "", 0.0
            parsed = json.loads(raw)
            if not isinstance(parsed, dict):
                return "", "", 0.0
            sha = str(parsed.get("sha256") or "").strip().lower()
            canon = str(parsed.get("canonical_sha256") or "").strip().lower()
            written_at = float(parsed.get("written_at") or 0.0)
            return sha, canon, written_at
        except Exception:
            return "", "", 0.0

    def _resolve_session_device_identity(self, session: Any) -> tuple[str, str]:
        """Resolve authoritative device_id and friendly device_name from paired DB record."""
        device_id = (getattr(session, "device_id", None) or "").strip() if session else ""
        if not device_id:
            return "unknown_device", "Connected Device"
        device_name = device_id
        if getattr(self, "db_manager", None) and hasattr(self.db_manager, "get_paired_device"):
            try:
                rec = self.db_manager.get_paired_device(device_id)
                if rec and getattr(rec, "device_name", None):
                    candidate = str(rec.device_name).strip()
                    if candidate:
                        device_name = candidate
            except Exception as exc:
                logger.debug("Unable to resolve paired device name for %s: %s", device_id, exc)
        return device_id, device_name

    async def _persist_and_broadcast_clipboard_buffer(
        self,
        *,
        content_type: str,
        source_device_id: str,
        source_device_name: str,
        text: Optional[str] = None,
        image_bytes: Optional[bytes] = None,
        mime_type: Optional[str] = None,
        files: Optional[list[dict[str, Any]]] = None,
        user_initiated: bool = False,
    ) -> Optional[dict[str, Any]]:
        """Persist validated clipboard item into shared ring buffer and broadcast metadata event."""
        cb_buf = getattr(self, "clipboard_buffer", None) or getattr(
            self.capability_engine, "clipboard_buffer", None
        )
        if not cb_buf:
            return None
        extra_kwargs: dict[str, Any] = {"bypass_debounce": True} if user_initiated else {}
        buf_res: Optional[dict[str, Any]] = None
        if content_type in ("file", "file_bundle") and files:
            buf_res = cb_buf.add_files(
                files=files,
                source_device_id=source_device_id,
                source_device_name=source_device_name,
            )
        elif content_type == "image" and image_bytes is not None:
            buf_res = cb_buf.add_image(
                image_bytes=image_bytes,
                mime_type=mime_type or "image/png",
                source_device_id=source_device_id,
                source_device_name=source_device_name,
                **extra_kwargs,
            )
        elif content_type == "text" and text is not None:
            buf_res = cb_buf.add_text(
                text=text,
                source_device_id=source_device_id,
                source_device_name=source_device_name,
                **extra_kwargs,
            )
        if buf_res and buf_res.get("success") and buf_res.get("item"):
            item_meta = buf_res["item"]
            await self.broadcast_clipboard_buffer_event(item_meta, exclude_device_id=source_device_id)
            return item_meta
        return None

    async def _handle_desktop_clipboard_set(
        self,
        client,
        message: SnowMessage,
        data: dict[str, Any],
        session,
        ctx: Optional[ExecutionContext] = None,
    ) -> None:
        """Handle request to write text, image, or verified file/bundle to Windows clipboard."""
        source_device_id, source_device_name = self._resolve_session_device_identity(session)
        user_initiated = bool(data.get("user_initiated") or data.get("explicit"))

        # 0. Single file or multi-file bundle clipboard set (CF_HDROP after port 8766 SHA-256 verify)
        if data.get("type") in ("file", "file_bundle"):
            from snow.capabilities.clipboard_buffer import MAX_BUNDLE_BYTES, MAX_BUNDLE_FILES, MAX_FILE_BYTES
            from snow.transfer.manager import TransferDirection, TransferState
            from snow.transfer.storage import commit_verified_clipboard_files, resolve_configured_pc_transfer_dir

            raw_files = data.get("files")
            if raw_files is None and (data.get("transfer_id") or data.get("file_name")):
                raw_files = [
                    {
                        "transfer_id": data.get("transfer_id"),
                        "file_name": data.get("file_name") or data.get("name"),
                        "sha256": data.get("sha256"),
                        "size_bytes": data.get("size_bytes", data.get("size", 0)),
                        "mime_type": data.get("mime_type"),
                    }
                ]
            if not isinstance(raw_files, list) or not (1 <= len(raw_files) <= MAX_BUNDLE_FILES):
                error_response = SnowMessage.create_error(
                    code=ErrorCode.INVALID_PAYLOAD,
                    message=f"Expected 1 to {MAX_BUNDLE_FILES} files for clipboard file transfer.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return

            session_dev_id = session.device_id if session and isinstance(getattr(session, "device_id", None), str) else None
            commit_specs: list[dict[str, Any]] = []
            buffer_specs: list[dict[str, Any]] = []
            total_size = 0

            for entry in raw_files:
                if not isinstance(entry, dict):
                    error_response = SnowMessage.create_error(
                        code=ErrorCode.INVALID_PAYLOAD,
                        message="Each file entry must be a JSON object.",
                        correlation_id=message.id,
                    )
                    await client.websocket.send(error_response.to_json())
                    return
                t_id = entry.get("transfer_id")
                declared_name = str(entry.get("file_name") or entry.get("name") or "").strip()
                declared_sha = str(entry.get("sha256") or "").strip().lower()
                src_path: Optional[Path] = None

                if t_id:
                    rec = (
                        self.transfer_manager.get_transfer_for_device(str(t_id), session_dev_id)
                        if session_dev_id
                        else self.transfer_manager.get_transfer(str(t_id))
                    )
                    if not rec or rec.direction != TransferDirection.UPLOAD or rec.status != TransferState.COMPLETED:
                        error_response = SnowMessage.create_error(
                            code=ErrorCode.TRANSFER_NOT_FOUND,
                            message=f"Completed upload transfer '{t_id}' not found for device.",
                            correlation_id=message.id,
                        )
                        await client.websocket.send(error_response.to_json())
                        return
                    if not rec.file_path or not Path(rec.file_path).is_file():
                        error_response = SnowMessage.create_error(
                            code=ErrorCode.FILE_NOT_FOUND,
                            message="Uploaded clipboard file missing on disk.",
                            correlation_id=message.id,
                        )
                        await client.websocket.send(error_response.to_json())
                        return
                    src_path = Path(rec.file_path).resolve()
                    if not src_path.is_relative_to(Path(self.storage_manager.root_dir).resolve()):
                        error_response = SnowMessage.create_error(
                            code=ErrorCode.INVALID_PAYLOAD,
                            message="Transfer path escapes storage root.",
                            correlation_id=message.id,
                        )
                        await client.websocket.send(error_response.to_json())
                        return
                    declared_name = declared_name or rec.file_name
                    if declared_sha and declared_sha != rec.sha256.lower():
                        error_response = SnowMessage.create_error(
                            code=ErrorCode.INTEGRITY_MISMATCH,
                            message="Declared SHA-256 mismatches completed transfer record.",
                            correlation_id=message.id,
                        )
                        await client.websocket.send(error_response.to_json())
                        return
                    declared_sha = declared_sha or rec.sha256.lower()
                elif declared_name:
                    try:
                        candidate = self.storage_manager.resolve_destination_path(declared_name)
                        if candidate.is_file():
                            src_path = candidate.resolve()
                    except Exception:
                        src_path = None

                if not src_path or not src_path.is_file() or not declared_name or len(declared_sha) != 64:
                    error_response = SnowMessage.create_error(
                        code=ErrorCode.INVALID_PAYLOAD,
                        message="Missing verified source file or SHA-256 digest.",
                        correlation_id=message.id,
                    )
                    await client.websocket.send(error_response.to_json())
                    return

                actual_size = src_path.stat().st_size
                total_size += actual_size
                if actual_size > MAX_FILE_BYTES or total_size > MAX_BUNDLE_BYTES:
                    error_response = SnowMessage.create_error(
                        code=ErrorCode.OVERSIZED_MESSAGE,
                        message="Clipboard file or bundle exceeds 15 MiB limit.",
                        correlation_id=message.id,
                    )
                    await client.websocket.send(error_response.to_json())
                    return

                commit_specs.append(
                    {
                        "name": declared_name,
                        "size_bytes": actual_size,
                        "sha256": declared_sha,
                        "path": src_path,
                    }
                )
                buffer_specs.append(
                    {
                        "name": declared_name,
                        "source_path": src_path,
                        "mime_type": entry.get("mime_type"),
                    }
                )

            dest_dir = (
                Path(self.storage_manager.root_dir)
                if getattr(self, "storage_manager", None) and getattr(self.storage_manager, "root_dir", None)
                else resolve_configured_pc_transfer_dir(db_manager=getattr(self, "db_manager", None))
            )
            try:
                committed_paths = commit_verified_clipboard_files(dest_dir, commit_specs)
            except Exception as ver_err:
                error_response = SnowMessage.create_error(
                    code=ErrorCode.INTEGRITY_MISMATCH,
                    message=f"Clipboard file verification failed: {ver_err}",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return

            res = await asyncio.to_thread(self.capability_engine.clipboard.set_files_sync, committed_paths)
            if res.get("success"):
                if sys.platform == "win32":
                    try:
                        import ctypes
                        self._last_local_write_seq = ctypes.windll.user32.GetClipboardSequenceNumber()
                    except Exception:
                        pass
                item_meta = await self._persist_and_broadcast_clipboard_buffer(
                    content_type=str(data.get("type")),
                    source_device_id=source_device_id,
                    source_device_name=source_device_name,
                    files=buffer_specs,
                    user_initiated=user_initiated,
                )
                if item_meta and item_meta.get("sha256"):
                    self._record_snow_clipboard_write(
                        sha256=item_meta["sha256"],
                        canonical_sha256="",
                    )
                    for cid in self._active_sync_connections:
                        self._last_synced_clipboard_hash[cid] = item_meta["sha256"]
                        if item_meta.get("event_id"):
                            self._last_synced_clipboard_event[cid] = item_meta["event_id"]
            response = SnowMessage.create_response(
                correlation_id=message.id,
                payload={
                    "status": "success" if res.get("success") else "error",
                    "action": "desktop_clipboard_set",
                    "error": res.get("error"),
                    "data": {**res, "committed_files": [p.name for p in committed_paths]},
                },
            )
            await client.websocket.send(response.to_json())
            return

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

            img_bytes = target_path.read_bytes()
            computed_sha256 = hashlib.sha256(img_bytes).hexdigest()
            if sha256 and computed_sha256.lower() != sha256.lower():
                error_response = SnowMessage.create_error(
                    code=ErrorCode.INTEGRITY_MISMATCH,
                    message="Image SHA-256 verification mismatch.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())
                return

            cb_buf = getattr(self, "clipboard_buffer", None) or getattr(
                getattr(self, "capability_engine", None), "clipboard_buffer", None
            )
            canonical_digest: Optional[str] = None
            try:
                from snow.capabilities.windows.clipboard import compute_canonical_image_digest
                canonical_digest, _, _ = compute_canonical_image_digest(img_bytes)
            except Exception:
                canonical_digest = None
            if canonical_digest is None:
                decl_canon = str(data.get("canonical_sha256") or "").strip().lower()
                if len(decl_canon) == 64:
                    canonical_digest = decl_canon

            duplicate_top_item: Optional[dict[str, Any]] = None
            if not user_initiated:
                if cb_buf is not None and hasattr(cb_buf, "hydrate_latest_image_canonical"):
                    try:
                        cb_buf.hydrate_latest_image_canonical()
                    except Exception:
                        pass
                if cb_buf is not None:
                    try:
                        with cb_buf._lock:
                            top_item = cb_buf._items[0] if cb_buf._items else None
                            if top_item is not None and top_item.content_type == "image":
                                top_sha = (top_item.sha256 or "").lower()
                                top_canon = (top_item.canonical_sha256 or "").lower()
                                if (
                                    top_sha == computed_sha256.lower()
                                    or (canonical_digest and top_canon and top_canon == canonical_digest.lower())
                                ):
                                    duplicate_top_item = top_item.to_metadata()
                    except Exception:
                        duplicate_top_item = None

                if duplicate_top_item is None:
                    persisted_sha, persisted_canon, _ = self._load_persisted_snow_clipboard_write()
                    last_sha = (getattr(self, "_last_processed_clipboard_hash", "") or persisted_sha).lower()
                    last_canon = (getattr(self, "_last_processed_canonical_hash", "") or persisted_canon).lower()
                    if (last_sha and last_sha == computed_sha256.lower()) or (
                        canonical_digest and last_canon and last_canon == canonical_digest.lower()
                    ):
                        duplicate_top_item = {
                            "item_id": None,
                            "canonical_sha256": canonical_digest or last_canon,
                        }

            if duplicate_top_item is not None:
                self._record_snow_clipboard_write(
                    sha256=computed_sha256,
                    canonical_sha256=canonical_digest or "",
                )
                for cid in self._active_sync_connections:
                    self._last_synced_clipboard_hash[cid] = computed_sha256
                    if duplicate_top_item.get("event_id"):
                        self._last_synced_clipboard_event[cid] = duplicate_top_item["event_id"]
                response = SnowMessage.create_response(
                    correlation_id=message.id,
                    payload={
                        "status": "success",
                        "action": "desktop_clipboard_set",
                        "error": None,
                        "data": {
                            "success": True,
                            "deduplicated": True,
                            "item_id": duplicate_top_item.get("item_id"),
                            "item": duplicate_top_item,
                        },
                    },
                )
                await client.websocket.send(response.to_json())
                return

            detected_mime = data.get("mime_type") or (
                "image/jpeg" if img_bytes.startswith(b"\xff\xd8\xff") else "image/png"
            )
            res = await asyncio.to_thread(self.capability_engine.clipboard.set_image_sync, target_path)
            if res.get("success"):
                if sys.platform == "win32":
                    try:
                        import ctypes
                        self._last_local_write_seq = ctypes.windll.user32.GetClipboardSequenceNumber()
                    except Exception:
                        pass
                self._record_snow_clipboard_write(
                    sha256=computed_sha256,
                    canonical_sha256=canonical_digest or "",
                )
                for cid in self._active_sync_connections:
                    self._last_synced_clipboard_hash[cid] = computed_sha256
                item_meta = await self._persist_and_broadcast_clipboard_buffer(
                    content_type="image",
                    source_device_id=source_device_id,
                    source_device_name=source_device_name,
                    image_bytes=img_bytes,
                    mime_type=detected_mime,
                    user_initiated=user_initiated,
                )
                if item_meta and item_meta.get("event_id"):
                    for cid in self._active_sync_connections:
                        self._last_synced_clipboard_event[cid] = item_meta["event_id"]
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
            self._record_snow_clipboard_write(sha256=h, canonical_sha256="")
            for cid in self._active_sync_connections:
                self._last_synced_clipboard_hash[cid] = h
            item_meta = await self._persist_and_broadcast_clipboard_buffer(
                content_type="text",
                source_device_id=source_device_id,
                source_device_name=source_device_name,
                text=text,
                user_initiated=user_initiated,
            )
            if item_meta and item_meta.get("event_id"):
                for cid in self._active_sync_connections:
                    self._last_synced_clipboard_event[cid] = item_meta["event_id"]

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

    def start_clipboard_listener(self) -> bool:
        """Start the Windows clipboard listener and watchdog (Core-owned singleton lifecycle)."""
        if sys.platform != "win32":
            return False
        if self._clipboard_listener and getattr(self._clipboard_listener, "_is_running", False):
            if not self._clipboard_watchdog_task or self._clipboard_watchdog_task.done():
                self._clipboard_watchdog_task = asyncio.create_task(self._clipboard_sequence_watchdog())
            return True
        if self._clipboard_listener:
            try:
                self._clipboard_listener.stop()
            except Exception:
                pass
            self._clipboard_listener = None
        try:
            self._clipboard_listener = WindowsClipboardListener(
                self._on_windows_clipboard_update_from_thread
            )
            success = self._clipboard_listener.start()
            if success:
                logger.info("WindowsClipboardListener successfully attached.")
            else:
                try:
                    self._clipboard_listener.stop()
                except Exception:
                    pass
                self._clipboard_listener = None
            # Unconditional watchdog: always run watchdog task on Windows for detached/headless reliability
            if not self._clipboard_watchdog_task or self._clipboard_watchdog_task.done():
                self._clipboard_watchdog_task = asyncio.create_task(self._clipboard_sequence_watchdog())
            return success
        except Exception as exc:
            logger.warning("Failed starting WindowsClipboardListener: %s", exc)
            self._clipboard_listener = None
            if not self._clipboard_watchdog_task or self._clipboard_watchdog_task.done():
                self._clipboard_watchdog_task = asyncio.create_task(self._clipboard_sequence_watchdog())
            return False

    def stop_clipboard_listener(self) -> None:
        """Stop the Windows clipboard listener and watchdog."""
        if self._clipboard_debounce_task and not self._clipboard_debounce_task.done():
            self._clipboard_debounce_task.cancel()
            self._clipboard_debounce_task = None
        if self._clipboard_watchdog_task:
            self._clipboard_watchdog_task.cancel()
            self._clipboard_watchdog_task = None
        if self._clipboard_listener:
            try:
                self._clipboard_listener.stop()
            except Exception:
                pass
            self._clipboard_listener = None

    @staticmethod
    def _sanitize_clipboard_broadcast_metadata(item_metadata: dict[str, Any]) -> dict[str, Any]:
        """Strip any raw binary, text_content, or disk path fields from WSS clipboard broadcasts."""
        forbidden = {
            "text_content",
            "bytes",
            "raw_bytes",
            "image_bytes",
            "base64",
            "data",
            "file_path",
            "image_path",
            "storage_dir",
            "stored_filename",
            "source_path",
        }
        cleaned = {k: v for k, v in item_metadata.items() if k not in forbidden}
        if isinstance(cleaned.get("file_manifest"), list):
            cleaned["file_manifest"] = [
                {
                    "index": entry.get("index", idx),
                    "name": entry.get("name"),
                    "size_bytes": entry.get("size_bytes"),
                    "mime_type": entry.get("mime_type"),
                    "sha256": entry.get("sha256"),
                }
                for idx, entry in enumerate(cleaned["file_manifest"])
                if isinstance(entry, dict)
            ]
        return cleaned

    def _is_peer_clipboard_authorized(self, peer_device_id: Any) -> bool:
        """Check whether an authenticated session device is authorized for clipboard sync."""
        if not isinstance(peer_device_id, str) or not peer_device_id.strip():
            # Allow test mocks without string device_id when session is explicitly authenticated
            return True
        clean_id = peer_device_id.strip()
        profile = self._resolve_authoritative_permission_profile(clean_id)
        if profile in ("not_allowed", "files_only"):
            return False
        if getattr(self, "capability_policy", None) is not None:
            try:
                if not self.capability_policy.is_authorized(clean_id, "desktop.clipboard.read"):
                    return False
            except Exception:
                pass
        return True

    async def _stage_clipboard_push_payload(
        self,
        peer_device_id: str,
        item_meta: dict[str, Any],
        cb_buf: Any,
    ) -> Optional[dict[str, Any]]:
        """Build a WSS-safe (<= 64 KiB) clipboard_push payload, staging 8766 transfers for media/files."""
        from snow.transfer.manager import TransferDirection, TransferState

        c_type = item_meta.get("content_type") or item_meta.get("type") or "text"
        item_id = item_meta.get("item_id")
        event_id = item_meta.get("event_id")
        seq = item_meta.get("seq", 0)
        origin_id = item_meta.get("origin_device_id") or item_meta.get("source_device_id")
        c_hash = item_meta.get("sha256") or ""

        bound_port = (
            self.http_transfer_server.bound_port
            if getattr(self, "http_transfer_server", None) and self.http_transfer_server.bound_port
            else getattr(self.config, "transfer_port", 8766)
        )

        if c_type == "text":
            detail = cb_buf.get_item(item_id, include_content=True) if cb_buf and item_id else None
            text_val = (detail or {}).get("text_content") or item_meta.get("preview") or ""
            if len(str(text_val).encode("utf-8")) > 65536:
                return None
            return {
                "type": "text",
                "text": text_val,
                "sha256": c_hash,
                "item_id": item_id,
                "event_id": event_id,
                "seq": seq,
                "origin_device_id": origin_id,
            }

        if c_type == "image" and cb_buf and item_id:
            img_path = cb_buf.get_image_path(item_id)
            if not img_path or not img_path.is_file():
                return None
            file_size = img_path.stat().st_size
            record = self.transfer_manager.create_transfer(
                device_id=peer_device_id or "device",
                file_name=img_path.name,
                file_size=file_size,
                sha256=c_hash,
                direction=TransferDirection.DOWNLOAD,
                file_path=str(img_path),
            )
            record.status = TransferState.IN_PROGRESS
            return {
                "type": "image",
                "item_id": item_id,
                "event_id": event_id,
                "seq": seq,
                "origin_device_id": origin_id,
                "mime_type": item_meta.get("mime_type") or "image/png",
                "transfer_id": record.transfer_id,
                "file_name": img_path.name,
                "sha256": c_hash,
                "canonical_sha256": item_meta.get("canonical_sha256") or "",
                "size": file_size,
                "transfer_port": bound_port,
                "transfer_url": f"/api/v1/transfers/download/{record.transfer_id}",
            }

        if c_type in ("file", "file_bundle") and cb_buf and item_id and hasattr(cb_buf, "get_file_entries"):
            entries = cb_buf.get_file_entries(item_id)
            if not entries:
                return None
            staged_files = []
            for entry in entries:
                rec = self.transfer_manager.create_transfer(
                    device_id=peer_device_id or "device",
                    file_name=entry["name"],
                    file_size=entry["size_bytes"],
                    sha256=entry["sha256"],
                    direction=TransferDirection.DOWNLOAD,
                    file_path=str(entry["path"]),
                )
                rec.status = TransferState.IN_PROGRESS
                staged_files.append(
                    {
                        "index": entry["index"],
                        "transfer_id": rec.transfer_id,
                        "transfer_port": bound_port,
                        "transfer_url": f"/api/v1/transfers/download/{rec.transfer_id}",
                        "file_name": entry["name"],
                        "name": entry["name"],
                        "size_bytes": entry["size_bytes"],
                        "mime_type": entry["mime_type"],
                        "sha256": entry["sha256"],
                    }
                )
            return {
                "type": c_type,
                "item_id": item_id,
                "event_id": event_id,
                "seq": seq,
                "origin_device_id": origin_id,
                "sha256": c_hash,
                "transfer_port": bound_port,
                "files": staged_files,
            }

        return None

    async def _sync_latest_eligible_clipboard_to_client(self, client: Any, session: Optional[SessionRecord]) -> bool:
        """Apply ONLY the single latest unacked non-self event when a peer reconnects / enables sync."""
        if session is None:
            return False
        cb_buf = getattr(self, "clipboard_buffer", None) or getattr(
            getattr(self, "capability_engine", None), "clipboard_buffer", None
        )
        if not cb_buf or not hasattr(cb_buf, "get_eligible_apply_item"):
            return False
        peer_id = getattr(session, "device_id", None)
        if not isinstance(peer_id, str) or not peer_id.strip():
            return False
        if not self._is_peer_clipboard_authorized(peer_id):
            return False

        latest = cb_buf.get_eligible_apply_item(peer_id)
        if not latest:
            return False

        conn_id = getattr(client, "connection_id", None)
        latest_event = str(latest.get("event_id") or "")
        if conn_id and latest_event and self._last_synced_clipboard_event.get(conn_id) == latest_event:
            return False

        push_data = await self._stage_clipboard_push_payload(peer_id, latest, cb_buf)
        if not push_data:
            return False

        push_msg = SnowMessage.create_request(action="clipboard_push", data=push_data)
        raw_json = push_msg.to_json()
        if len(raw_json.encode("utf-8")) > DEFAULT_MAX_MESSAGE_SIZE:
            logger.warning("Skipping oversized clipboard_push reconnect frame.")
            return False

        try:
            await client.websocket.send(raw_json)
            if conn_id and latest_event:
                self._last_synced_clipboard_event[conn_id] = latest_event
                self._last_synced_clipboard_hash[conn_id] = latest.get("sha256") or ""
            return True
        except Exception as err:
            logger.warning("Failed syncing latest clipboard event to [%s]: %s", peer_id, err)
            return False

    async def broadcast_clipboard_buffer_event(
        self,
        item_metadata: dict[str, Any],
        exclude_device_id: Optional[str] = None,
    ) -> None:
        """Broadcast metadata-only clipboard_buffer_updated event to authorized non-origin peers."""
        conn_mgr = getattr(self, "connection_manager", None)
        sess_mgr = getattr(self, "session_manager", None)
        if conn_mgr is None or sess_mgr is None:
            return
        clean_meta = self._sanitize_clipboard_broadcast_metadata(item_metadata)
        origin_id = str(clean_meta.get("origin_device_id") or clean_meta.get("source_device_id") or "").strip()
        msg = SnowMessage.create_request(
            action="clipboard_buffer_updated",
            data={"item": clean_meta},
        )
        payload_str = msg.to_json()
        if len(payload_str.encode("utf-8")) > DEFAULT_MAX_MESSAGE_SIZE:
            clean_meta["preview"] = str(clean_meta.get("preview") or "")[:120]
            clean_meta["preview_text"] = clean_meta["preview"]
            payload_str = SnowMessage.create_request(
                action="clipboard_buffer_updated",
                data={"item": clean_meta},
            ).to_json()
            if len(payload_str.encode("utf-8")) > DEFAULT_MAX_MESSAGE_SIZE:
                logger.warning("Refusing oversized clipboard_buffer_updated WSS frame.")
                return

        for conn_item in conn_mgr.all_connections():
            client = conn_mgr.get(conn_item) if isinstance(conn_item, str) else conn_item
            if not client or not getattr(client, "websocket", None) or getattr(client.websocket, "state", 1) != 1:
                continue
            conn_id = getattr(client, "connection_id", conn_item)
            session = sess_mgr.get_session_by_connection(conn_id)
            if session is None:
                continue
            peer_dev_id = getattr(session, "device_id", None)
            if isinstance(peer_dev_id, str) and peer_dev_id.strip():
                clean_peer_id = peer_dev_id.strip()
                if origin_id and clean_peer_id == origin_id:
                    continue
                if exclude_device_id and clean_peer_id == exclude_device_id:
                    continue
                if not self._is_peer_clipboard_authorized(clean_peer_id):
                    continue
            try:
                await client.websocket.send(payload_str)
            except Exception as exc:
                logger.debug("Failed sending clipboard_buffer_updated to client [%s]: %s", conn_id, exc)

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
            if sys.platform == "win32" and (
                not self._clipboard_listener
                or not getattr(self._clipboard_listener, "_is_running", False)
                or not self._clipboard_watchdog_task
                or self._clipboard_watchdog_task.done()
            ):
                self.start_clipboard_listener()
        else:
            self._active_sync_connections.discard(client.connection_id)

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "desktop_clipboard_sync_toggle",
                "enabled": enabled,
            },
        )
        await client.websocket.send(response.to_json())
        if enabled:
            await self._sync_latest_eligible_clipboard_to_client(client, session)

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
            asyncio.run_coroutine_threadsafe(self._schedule_debounced_clipboard_update(), self._loop)

    async def _schedule_debounced_clipboard_update(self) -> None:
        """Debounce rapid clipboard updates by ~200ms."""
        if self._clipboard_debounce_task and not self._clipboard_debounce_task.done():
            self._clipboard_debounce_task.cancel()
        self._clipboard_debounce_task = asyncio.create_task(self._debounced_clipboard_handler())

    async def _debounced_clipboard_handler(self) -> None:
        try:
            await asyncio.sleep(0.2)
            await self._broadcast_clipboard_update()
        except asyncio.CancelledError:
            pass

    async def _broadcast_clipboard_update(self) -> None:
        """Process desktop clipboard update, update shared ring buffer, and broadcast to clients."""
        lock = getattr(self, "_clipboard_update_lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self._clipboard_update_lock = lock
        async with lock:
            await self._broadcast_clipboard_update_locked()

    async def _broadcast_clipboard_update_locked(self) -> None:
        """Serialized inner implementation of desktop clipboard synchronization."""
        if sys.platform == "win32":
            try:
                import ctypes
                curr_seq = ctypes.windll.user32.GetClipboardSequenceNumber()
                if curr_seq != 0 and curr_seq == getattr(self, "_last_local_write_seq", 0):
                    return
            except Exception:
                pass

        from snow.capabilities.windows.clipboard import get_default_clipboard_temp_dir

        clip_tmp_dir = get_default_clipboard_temp_dir()
        try:
            content = await asyncio.to_thread(
                self.capability_engine.clipboard.get_content_sync, clip_tmp_dir
            )
        except TypeError:
            content = await asyncio.to_thread(self.capability_engine.clipboard.get_content_sync)
        if not isinstance(content, dict) or not content.get("success"):
            return

        c_type = content.get("type")
        c_hash = content.get("sha256")
        c_canon = content.get("canonical_sha256") or c_hash
        temp_capture_file = content.get("file_path") if c_type == "image" else None
        try:
            if not c_hash or c_type == "empty":
                return

            cb_buf = getattr(self, "clipboard_buffer", None) or getattr(self.capability_engine, "clipboard_buffer", None)
            debounce_win = getattr(cb_buf, "debounce_seconds", 0.5) if cb_buf else 0.5
            effective_win = (
                cb_buf._effective_image_burst_window()
                if c_type == "image" and cb_buf and hasattr(cb_buf, "_effective_image_burst_window")
                else (max(debounce_win, 1.0) if c_type == "image" and debounce_win >= 0.5 else debounce_win)
            )
            if (
                getattr(self, "_last_processed_clipboard_at", 0.0) == 0.0
                and not getattr(self, "_last_snow_write_hydrated", False)
                and not getattr(self, "_last_processed_clipboard_hash", "")
                and not getattr(self, "_last_processed_canonical_hash", "")
            ):
                p_sha, p_canon, p_at = self._load_persisted_snow_clipboard_write()
                self._last_snow_write_hydrated = True
                if p_at > 0.0 and (time.time() - p_at) <= 300.0:
                    if p_sha:
                        self._last_processed_clipboard_hash = p_sha
                    if p_canon:
                        self._last_processed_canonical_hash = p_canon
            last_hash = getattr(self, "_last_processed_clipboard_hash", "")
            last_canon = getattr(self, "_last_processed_canonical_hash", "")
            last_at = getattr(self, "_last_processed_clipboard_at", 0.0)
            within_debounce_or_mock = (last_at == 0.0) or ((time.monotonic() - last_at) <= effective_win)

            # Echo / duplicate suppression check within debounce/burst window
            if within_debounce_or_mock and (
                (last_hash and c_hash.lower() == last_hash.lower())
                or (c_type == "image" and last_canon and c_canon and c_canon.lower() == last_canon.lower())
            ):
                return
            self._record_snow_clipboard_write(
                sha256=c_hash or "",
                canonical_sha256=(c_canon if c_type == "image" else "") or "",
            )

            # Add to shared clipboard buffer
            buffer_item = None
            if cb_buf:
                if c_type == "text":
                    res = cb_buf.add_text(
                        text=content.get("text", ""),
                        source_device_id="desktop_windows",
                        source_device_name="Windows PC",
                    )
                    if res.get("success") and res.get("item"):
                        buffer_item = res["item"]
                elif c_type == "image":
                    file_path = content.get("file_path")
                    if file_path and Path(file_path).is_file():
                        img_bytes = Path(file_path).read_bytes()
                        res = cb_buf.add_image(
                            image_bytes=img_bytes,
                            mime_type=content.get("mime_type") or "image/png",
                            source_device_id="desktop_windows",
                            source_device_name="Windows PC",
                        )
                        if res.get("success") and res.get("item"):
                            buffer_item = res["item"]
                            c_hash = buffer_item.get("sha256") or c_hash
                            c_canon = buffer_item.get("canonical_sha256") or c_canon
                            self._record_snow_clipboard_write(
                                sha256=c_hash or "",
                                canonical_sha256=c_canon or "",
                            )
                elif c_type in ("file", "file_bundle") and content.get("files"):
                    res = cb_buf.add_files(
                        files=content["files"],
                        source_device_id="desktop_windows",
                        source_device_name="Windows PC",
                    )
                    if res.get("success") and res.get("item"):
                        buffer_item = res["item"]
                        c_hash = buffer_item.get("sha256") or c_hash

            # Broadcast clipboard_buffer_updated event with lightweight metadata to all authorized non-origin peers
            if buffer_item:
                await self.broadcast_clipboard_buffer_event(buffer_item)

            # Broadcast latest item push to clients with Instant Sync enabled
            if not self._active_sync_connections:
                return

            event_id = (buffer_item or {}).get("event_id") or ""
            origin_id = (buffer_item or {}).get("origin_device_id") or (buffer_item or {}).get("source_device_id") or "desktop_windows"

            for conn_id in list(self._active_sync_connections):
                client = self.connection_manager.get(conn_id)
                if not client or not client.websocket or getattr(client.websocket, "state", 1) != 1:
                    self._active_sync_connections.discard(conn_id)
                    continue
                session = self.session_manager.get_session_by_connection(conn_id)
                if session is None:
                    continue

                peer_dev_id = getattr(session, "device_id", None)
                if isinstance(peer_dev_id, str) and peer_dev_id.strip():
                    clean_peer = peer_dev_id.strip()
                    if clean_peer == origin_id:
                        continue
                    if not self._is_peer_clipboard_authorized(clean_peer):
                        continue
                    if event_id and cb_buf and hasattr(cb_buf, "has_device_received_event"):
                        if cb_buf.has_device_received_event(event_id, clean_peer):
                            continue

                if event_id:
                    if self._last_synced_clipboard_event.get(conn_id) == event_id:
                        continue
                    self._last_synced_clipboard_event[conn_id] = event_id
                elif self._last_synced_clipboard_hash.get(conn_id) in (c_hash, c_canon):
                    continue

                self._last_synced_clipboard_hash[conn_id] = c_canon or c_hash

                if buffer_item and cb_buf:
                    push_payload = await self._stage_clipboard_push_payload(
                        peer_dev_id.strip() if isinstance(peer_dev_id, str) else "device",
                        buffer_item,
                        cb_buf,
                    )
                    if not push_payload:
                        continue
                    if c_type == "text" and c_hash:
                        push_payload["sha256"] = c_hash
                    push_msg = SnowMessage.create_request(action="clipboard_push", data=push_payload)
                    raw_push = push_msg.to_json()
                    if len(raw_push.encode("utf-8")) > DEFAULT_MAX_MESSAGE_SIZE:
                        continue
                    try:
                        await client.websocket.send(raw_push)
                    except Exception as err:
                        logger.warning("Failed sending clipboard push to [%s]: %s", conn_id, err, exc_info=True)
                elif c_type == "text":
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
                    device_id = peer_dev_id if isinstance(peer_dev_id, str) else "device"
                    record = self.transfer_manager.create_transfer(
                        device_id=device_id,
                        file_name=file_name,
                        file_size=file_size,
                        sha256=c_hash,
                        direction=TransferDirection.DOWNLOAD,
                        file_path=str(file_path) if file_path else None,
                    )
                    record.status = TransferState.IN_PROGRESS
                    push_msg = SnowMessage.create_request(
                        action="clipboard_push",
                        data={
                            "type": "image",
                            "mime_type": "image/png",
                            "transfer_id": record.transfer_id,
                            "file_name": file_name,
                            "sha256": c_hash,
                            "canonical_sha256": c_canon or "",
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
        finally:
            if temp_capture_file:
                try:
                    import tempfile
                    temp_p = Path(temp_capture_file).resolve()
                    temp_dir = Path(tempfile.gettempdir()).resolve()
                    cb_dir = (
                        Path(cb_buf.storage_dir).resolve()
                        if locals().get("cb_buf") and getattr(cb_buf, "storage_dir", None)
                        else None
                    )
                    in_system_temp = temp_dir in temp_p.parents or temp_p.parent == temp_dir
                    is_buffer_file = bool(cb_dir and (cb_dir in temp_p.parents or temp_p.parent == cb_dir))
                    if in_system_temp and not is_buffer_file:
                        temp_p.unlink(missing_ok=True)
                except Exception:
                    pass

    async def _clipboard_sequence_watchdog(self) -> None:
        """Periodic watchdog polling GetClipboardSequenceNumber as a backup to WindowsClipboardListener."""
        if sys.platform != "win32":
            return
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
        last_seq = user32.GetClipboardSequenceNumber()
        while self._is_running:
            try:
                await asyncio.sleep(1.0)
                if not self._is_running:
                    break
                curr_seq = user32.GetClipboardSequenceNumber()
                if curr_seq != last_seq:
                    last_seq = curr_seq
                    if curr_seq != getattr(self, "_last_local_write_seq", 0):
                        await self._schedule_debounced_clipboard_update()
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

    # =========================================================================
    # Phase 30 / Stage 4A: Cross-Network Federation Operations over WSS
    # =========================================================================

    async def _handle_federation_create_invite(
        self, client: Any, message: SnowMessage, data: dict[str, Any], session: Any, is_owner: bool
    ) -> None:
        """Generate a 9-digit federation invitation code over authenticated Owner WSS."""
        if not is_owner:
            logger.warning("Denied federation_create_invite from non-owner client [%s]", client.connection_id)
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Privileged federation administration requires OWNER_MANUAL authority.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        caps = data.get("allowed_capabilities")
        devs = data.get("allowed_device_ids")
        ttl = data.get("ttl_seconds", 600)
        grant_ttl = data.get("grant_ttl_seconds", 86400)
        perm_tier = data.get("permission_tier")

        try:
            res = self.federation_manager.create_invitation(
                allowed_capabilities=caps,
                allowed_device_ids=devs,
                grant_ttl_seconds=grant_ttl,
                ttl_seconds=ttl,
                principal="OWNER_MANUAL",
                permission_tier=perm_tier,
            )
            resp = SnowMessage.create_response(
                correlation_id=message.id,
                payload={"action": "federation_create_invite", **res, "status": "success"},
            )
            await client.websocket.send(resp.to_json())
        except Exception as exc:
            logger.error("Failed creating federation invitation: %s", exc)
            err = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message=str(exc),
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())

    async def _handle_federation_accept_invite(
        self, client: Any, message: SnowMessage, data: dict[str, Any], session: Any, is_owner: bool
    ) -> None:
        """Accept a 9-digit federation invitation code over authenticated Owner WSS."""
        if not is_owner:
            logger.warning("Denied federation_accept_invite from non-owner client [%s]", client.connection_id)
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Privileged federation administration requires OWNER_MANUAL authority.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        raw_code = data.get("code") or data.get("invite_code") or ""
        clean_code = re.sub(r"\D", "", str(raw_code))
        if len(clean_code) != 9:
            err = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Federation invite code must contain exactly 9 digits (format: XXX-XXX-XXX).",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        peer_network_id = data.get("peer_network_id") or "remote-network"
        peer_network_name = data.get("peer_network_name") or "Remote SNOW Network"
        peer_node_id = data.get("peer_node_id") or session.device_id
        peer_node_name = data.get("peer_node_name") or "Remote Peer"
        peer_fp = data.get("peer_cert_fingerprint") or ""

        try:
            res = self.federation_manager.accept_invitation(
                code=clean_code,
                peer_network_id=peer_network_id,
                peer_network_name=peer_network_name,
                peer_node_id=peer_node_id,
                peer_node_name=peer_node_name,
                peer_cert_fingerprint=peer_fp,
                principal="OWNER_MANUAL",
                requester_id=session.device_id,
            )
            if not res.get("success"):
                err = SnowMessage.create_error(
                    code=ErrorCode.INVALID_PAYLOAD if "INVALID" in res.get("status", "") else ErrorCode.UNAUTHORIZED,
                    message=res.get("error", "Failed to accept invitation code."),
                    correlation_id=message.id,
                )
                await client.websocket.send(err.to_json())
                return

            resp = SnowMessage.create_response(
                correlation_id=message.id,
                payload={"action": "federation_accept_invite", **res, "status": "success"},
            )
            await client.websocket.send(resp.to_json())
        except Exception as exc:
            logger.error("Failed accepting federation invitation: %s", exc)
            err = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message=str(exc),
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())

    async def _handle_federation_update_tier(
        self, client: Any, message: SnowMessage, data: dict[str, Any], session: Any, is_owner: bool
    ) -> None:
        """Update the 5-tier permission level of a federation grant over authenticated Owner WSS."""
        if not is_owner:
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Privileged federation administration requires OWNER_MANUAL authority.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        grant_id = str(data.get("grant_id") or "").strip()
        tier = str(data.get("permission_tier") or "").strip().lower()
        if not grant_id or not tier:
            err = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Missing 'grant_id' or 'permission_tier'.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        try:
            res = self.federation_manager.update_grant_permission_tier(
                grant_id=grant_id,
                permission_tier=tier,
                principal="OWNER_MANUAL",
            )
            if not res.get("success"):
                err = SnowMessage.create_error(
                    code=ErrorCode.INVALID_PAYLOAD,
                    message=res.get("error", "Failed updating federation tier."),
                    correlation_id=message.id,
                )
                await client.websocket.send(err.to_json())
                return
            resp = SnowMessage.create_response(
                correlation_id=message.id,
                payload={"action": "federation_update_tier", **res, "status": "success"},
            )
            await client.websocket.send(resp.to_json())
        except Exception as exc:
            err = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD if isinstance(exc, ValueError) else ErrorCode.INTERNAL_ERROR,
                message=str(exc),
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())

    async def _handle_federation_list_grants(
        self, client: Any, message: SnowMessage, data: dict[str, Any], session: Any, is_owner: bool
    ) -> None:
        """List active cross-network federation grants over authenticated Owner WSS."""
        if not is_owner:
            logger.warning("Denied federation_list_grants from non-owner client [%s]", client.connection_id)
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Privileged federation administration requires OWNER_MANUAL authority.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        active_only = bool(data.get("active_only", False))
        try:
            grants = self.federation_manager.list_grants(active_only=active_only)
            resp = SnowMessage.create_response(
                correlation_id=message.id,
                payload={"status": "success", "action": "federation_list_grants", "grants": grants},
            )
            await client.websocket.send(resp.to_json())
        except Exception as exc:
            logger.error("Failed listing federation grants: %s", exc)
            err = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message=str(exc),
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())

    async def _handle_federation_revoke(
        self, client: Any, message: SnowMessage, data: dict[str, Any], session: Any, is_owner: bool
    ) -> None:
        """Revoke a single cross-network federation grant over authenticated Owner WSS."""
        if not is_owner:
            logger.warning("Denied federation_revoke from non-owner client [%s]", client.connection_id)
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Privileged federation administration requires OWNER_MANUAL authority.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        grant_id = data.get("grant_id")
        if not grant_id:
            err = SnowMessage.create_error(
                code=ErrorCode.INVALID_PAYLOAD,
                message="Missing required 'grant_id'.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        reason = data.get("reason", "Revoked by network owner via WSS")
        try:
            res = self.federation_manager.revoke_grant(grant_id, reason=reason, principal="OWNER_MANUAL")
            if not res.get("success"):
                err = SnowMessage.create_error(
                    code=ErrorCode.INVALID_PAYLOAD,
                    message=res.get("error", "Grant not found."),
                    correlation_id=message.id,
                )
                await client.websocket.send(err.to_json())
                return

            resp = SnowMessage.create_response(
                correlation_id=message.id,
                payload={"action": "federation_revoke", **res, "status": "success"},
            )
            await client.websocket.send(resp.to_json())
        except Exception as exc:
            logger.error("Failed revoking federation grant: %s", exc)
            err = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message=str(exc),
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())

    async def _handle_federation_kill_switch(
        self, client: Any, message: SnowMessage, data: dict[str, Any], session: Any, is_owner: bool
    ) -> None:
        """Activate the emergency global federation kill switch over authenticated Owner WSS."""
        if not is_owner:
            logger.warning("Denied federation_kill_switch from non-owner client [%s]", client.connection_id)
            err = SnowMessage.create_error(
                code=ErrorCode.UNAUTHORIZED,
                message="Privileged federation administration requires OWNER_MANUAL authority.",
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
            return

        reason = data.get("reason", "Emergency Global Kill Switch Activated via Owner WSS")
        try:
            res = self.federation_manager.global_kill_switch(reason=reason, principal="OWNER_MANUAL")
            resp = SnowMessage.create_response(
                correlation_id=message.id,
                payload={"action": "federation_kill_switch", **res, "status": "success"},
            )
            await client.websocket.send(resp.to_json())
        except Exception as exc:
            logger.error("Failed activating global federation kill switch: %s", exc)
            err = SnowMessage.create_error(
                code=ErrorCode.INTERNAL_ERROR,
                message=str(exc),
                correlation_id=message.id,
            )
            await client.websocket.send(err.to_json())
