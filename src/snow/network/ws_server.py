"""WebSocket server implementation for SNOW Desktop Core."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
import secrets
import ssl
from typing import Any, Optional

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed

from snow.core.config import CoreConfig
from snow.network.connection_manager import ConnectionManager
from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.protocol.validator import ProtocolValidationError, validate_raw_message
from snow.security.db import DatabaseManager, hash_token
from snow.security.identity import DeviceIdentity, load_or_create_device_identity
from snow.security.pairing import PairingManager, PairingOutcome
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
    ) -> None:
        self.config = config
        self.connection_manager = connection_manager or ConnectionManager()
        self.pairing_manager = pairing_manager or PairingManager()
        self.device_identity = device_identity or load_or_create_device_identity()
        self.db_manager = db_manager or DatabaseManager()
        self.session_manager = session_manager or SessionManager()
        self.transfer_manager = transfer_manager or TransferManager()
        self.storage_manager = storage_manager or TransferStorageManager(root_dir=self.config.transfer_root)
        self.http_transfer_server: Any = None
        self._server: Optional[Server] = None
        self._reaper_task: Optional[asyncio.Task] = None
        self._is_running = False
        self._pending_requests: dict[str, tuple[str, asyncio.Future[SnowMessage]]] = {}
        self.certificate_info: Optional[CertificateInfo] = None
        self._ssl_context: Optional[ssl.SSLContext] = None
        self._auth_timers: dict[str, asyncio.Task] = {}
        self._pairing_in_progress: set[str] = set()

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

                self.session_manager.touch_session(session.session_id)

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
            else:
                logger.warning("Rejected unsupported action '%s' from client [%s]",
                               action, client.connection_id)
                error_response = SnowMessage.create_error(
                    code=ErrorCode.UNSUPPORTED_ACTION,
                    message=f"Action '{action}' is not supported.",
                    correlation_id=message.id,
                )
                await client.websocket.send(error_response.to_json())

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

        response = SnowMessage.create_response(
            correlation_id=message.id,
            payload={
                "status": "success",
                "action": "auth_request",
                "data": {
                    "device_id": device_id,
                    "session_id": session.session_id,
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

                    self.db_manager.insert_paired_device(
                        device_id=client_device_id,
                        device_name=client_device_name,
                        auth_token_hash=token_hash,
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

                # Successful pairing: clear pairing in-progress state and cancel handshake timer
                self._pairing_in_progress.discard(client.connection_id)
                timer = self._auth_timers.pop(client.connection_id, None)
                if timer and not timer.done():
                    timer.cancel()

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
            # Request to generate and display a fresh PIN on desktop stderr
            fresh_pin = self.pairing_manager.generate_pin(display_to_stderr=True)
            response = SnowMessage.create_response(
                correlation_id=message.id,
                payload={
                    "status": "pin_displayed",
                    "action": action,
                    "data": {
                        "device_id": self.device_identity.device_id,
                        "device_name": self.device_identity.device_name,
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
