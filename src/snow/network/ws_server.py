"""WebSocket server implementation for SNOW Desktop Core."""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed

from snow.core.config import CoreConfig
from snow.network.connection_manager import ConnectionManager
from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.protocol.validator import ProtocolValidationError, validate_raw_message

logger = logging.getLogger(__name__)


class SnowWebSocketServer:
    """Asynchronous WebSocket server implementing SNOW Device Protocol v1.

    Manages incoming client connections, message validation, ping/pong request
    correlation, heartbeat tracking, and stale connection reaping.
    """

    def __init__(
        self,
        config: CoreConfig,
        connection_manager: Optional[ConnectionManager] = None,
    ) -> None:
        self.config = config
        self.connection_manager = connection_manager or ConnectionManager()
        self._server: Optional[Server] = None
        self._reaper_task: Optional[asyncio.Task] = None
        self._is_running = False
        self._pending_requests: dict[str, tuple[str, asyncio.Future[SnowMessage]]] = {}

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

    async def start(self) -> None:
        """Start listening for incoming WebSocket connections."""
        if self._is_running:
            logger.warning("SnowWebSocketServer is already running; start() ignored.")
            return

        logger.info(
            "Starting WebSocket server on %s:%d (max_message_size=%d bytes)...",
            self.config.bind_host,
            self.config.port,
            self.config.max_message_size,
        )

        try:
            self._server = await serve(
                self._handle_client,
                self.config.bind_host,
                self.config.port,
                max_size=self.config.max_message_size,
            )
            self._is_running = True
            actual_port = self.bound_port or self.config.port
            logger.info("WebSocket server listening on ws://%s:%d", self.config.bind_host, actual_port)

            # Start background reaper task for stale client connections
            self._reaper_task = asyncio.create_task(self._stale_connection_reaper())
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
            self.connection_manager.unregister(client.connection_id)
            for req_id, (cid, fut) in list(self._pending_requests.items()):
                if cid == client.connection_id and not fut.done():
                    fut.set_exception(
                        ConnectionResetError(f"Client [{client.connection_id}] disconnected.")
                    )

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

        if action == "ping":
            logger.debug("Handling 'ping' action from client [%s]", client.connection_id)
            response = SnowMessage.create_response(
                correlation_id=message.id,
                payload={"status": "success", "action": "pong"},
            )
            await client.websocket.send(response.to_json())
        else:
            logger.warning("Rejected unsupported action '%s' from client [%s]",
                           action, client.connection_id)
            error_response = SnowMessage.create_error(
                code=ErrorCode.UNSUPPORTED_ACTION,
                message=f"Action '{action}' is not supported.",
                correlation_id=message.id,
            )
            await client.websocket.send(error_response.to_json())

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
