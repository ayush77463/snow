"""Connection management abstraction for SNOW WebSocket server.

SECURITY & LIFECYCLE DIRECTIVE:
-------------------------------
Phase 1.2 implements an unauthenticated development communication layer.
This transport must NOT be exposed to untrusted or public networks.
Cryptographic device pairing, token exchange, and transport security (TLS/WSS)
are strictly scheduled for Phase 2.
"""

from dataclasses import dataclass
import logging
import time
from typing import Dict, List, Optional
import uuid

from websockets.asyncio.server import ServerConnection

logger = logging.getLogger(__name__)


@dataclass
class ClientConnection:
    """Represents an active WebSocket client connection.

    Attributes:
        connection_id: Unique string identifier assigned to the connection.
        websocket: The underlying websockets ServerConnection instance.
        remote_address: Client's IP and port string representation.
        connected_at: Monotonic timestamp recording connection establishment.
        last_heartbeat_at: Monotonic timestamp recording last valid heartbeat or activity.
        is_active: Boolean indicating whether the connection is currently open.
    """

    connection_id: str
    websocket: ServerConnection
    remote_address: str
    connected_at: float
    last_heartbeat_at: float
    is_active: bool = True


class ConnectionManager:
    """Manages active WebSocket client connections, state, and heartbeats.

    Thread-safety: All methods are designed to run within the single-threaded
    asyncio event loop managing the WebSocket server.
    """

    def __init__(self) -> None:
        self._connections: Dict[str, ClientConnection] = {}

    @property
    def connection_count(self) -> int:
        """Return the number of currently registered active connections."""
        return len(self._connections)

    def register(self, websocket: ServerConnection) -> ClientConnection:
        """Register a newly accepted client connection."""
        conn_id = str(uuid.uuid4())
        remote_addr = str(websocket.remote_address) if websocket.remote_address else "unknown"
        now = time.monotonic()

        client = ClientConnection(
            connection_id=conn_id,
            websocket=websocket,
            remote_address=remote_addr,
            connected_at=now,
            last_heartbeat_at=now,
            is_active=True,
        )
        self._connections[conn_id] = client
        logger.info("Registered connection [%s] from %s (total active: %d)", conn_id, remote_addr, len(self._connections))
        return client

    def unregister(self, connection_id: str) -> Optional[ClientConnection]:
        """Unregister and return a disconnected client connection."""
        client = self._connections.pop(connection_id, None)
        if client:
            client.is_active = False
            logger.info("Unregistered connection [%s] from %s (remaining active: %d)",
                        connection_id, client.remote_address, len(self._connections))
        return client

    def get(self, connection_id: str) -> Optional[ClientConnection]:
        """Retrieve a registered client connection by ID."""
        return self._connections.get(connection_id)

    def all_connections(self) -> List[ClientConnection]:
        """Return a snapshot list of all active connections."""
        return list(self._connections.values())

    def get_active_connections(self) -> List[ClientConnection]:
        """Alias for all_connections()."""
        return self.all_connections()

    def record_heartbeat(self, connection_id: str) -> bool:
        """Update the last heartbeat timestamp for the specified connection.

        Returns:
            True if the connection exists and was updated; False otherwise.
        """
        client = self._connections.get(connection_id)
        if client and client.is_active:
            client.last_heartbeat_at = time.monotonic()
            logger.debug("Heartbeat recorded for connection [%s]", connection_id)
            return True
        return False

    def get_stale_connections(self, timeout_seconds: float) -> List[ClientConnection]:
        """Identify connections whose last heartbeat exceeds the timeout threshold."""
        now = time.monotonic()
        stale: List[ClientConnection] = []
        for client in self._connections.values():
            if (now - client.last_heartbeat_at) > timeout_seconds:
                stale.append(client)
        return stale

    async def close_all(self, code: int = 1000, reason: str = "Server shutdown") -> None:
        """Gracefully close all active client connections."""
        clients = list(self._connections.values())
        self._connections.clear()

        for client in clients:
            client.is_active = False
            try:
                await client.websocket.close(code=code, reason=reason)
            except Exception as exc:
                logger.debug("Error closing connection [%s]: %s", client.connection_id, exc)
