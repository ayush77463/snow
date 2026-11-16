"""Asynchronous core server lifecycle for SNOW."""

import asyncio
import logging
from typing import List, Optional

from snow.core.config import CoreConfig
from snow.core.network import NetworkInterfaceInfo, detect_usable_ipv4_addresses
from snow.network.connection_manager import ConnectionManager
from snow.network.ws_server import SnowWebSocketServer

logger = logging.getLogger(__name__)


class SnowCoreServer:
    """Headless asynchronous core server for SNOW.

    Coordinates the core lifecycle: configuration loading, network interface
    enumeration, WebSocket server hosting, and graceful shutdown.
    """

    def __init__(self, config: Optional[CoreConfig] = None) -> None:
        self.config = config or CoreConfig.from_env()
        self._is_running = False
        self._shutdown_event = asyncio.Event()
        self._detected_interfaces: List[NetworkInterfaceInfo] = []
        self.connection_manager = ConnectionManager()
        self.ws_server = SnowWebSocketServer(
            config=self.config,
            connection_manager=self.connection_manager,
        )

    @property
    def is_running(self) -> bool:
        """Return True if the server is currently in the running state."""
        return self._is_running

    @property
    def detected_interfaces(self) -> List[NetworkInterfaceInfo]:
        """Return the list of detected network interfaces."""
        return list(self._detected_interfaces)

    @property
    def pairing_manager(self):
        """Return the core server's pairing manager."""
        return self.ws_server.pairing_manager

    @property
    def device_identity(self):
        """Return the core server's device identity."""
        return self.ws_server.device_identity

    async def start(self) -> None:
        """Initialize the server lifecycle, enumerate interfaces, and start WebSocket listener.

        Idempotent: Repeated invocations when the server is already running log a warning
        and return without re-initialization.
        """
        if self._is_running:
            logger.warning("%s is already running; start() call ignored.", self.config.app_name)
            return

        logger.info("Starting %s v%s...", self.config.app_name, self.config.version)

        # Clear any prior shutdown event in case of server restart
        self._shutdown_event.clear()

        # Enumerate usable local IPv4 addresses
        self._detected_interfaces = detect_usable_ipv4_addresses()

        if self._detected_interfaces:
            active = [iface for iface in self._detected_interfaces if iface.is_up]
            logger.info("Detected %d usable network interface(s):", len(self._detected_interfaces))
            for iface in self._detected_interfaces:
                status = "ACTIVE" if iface.is_up else "INACTIVE"
                logger.info(
                    "  - [%s] %s: %s (WebSocket port %d)",
                    status,
                    iface.interface_name,
                    iface.ip_address,
                    self.config.port,
                )
            if not active:
                logger.warning(
                    "No active (UP) interface found. Connect laptop to Wi-Fi or phone hotspot."
                )
        else:
            logger.warning("No usable IPv4 addresses detected.")
            logger.warning("Please connect this laptop to Wi-Fi or an Android mobile hotspot.")

        # Start the WebSocket server
        await self.ws_server.start()

        self._is_running = True
        actual_port = self.ws_server.bound_port or self.config.port
        logger.info("%s started successfully (async core loop active, listening on port %d).",
                    self.config.app_name, actual_port)

    async def run(self) -> None:
        """Execute the asynchronous server loop until shutdown is signaled."""
        await self.start()
        try:
            # Wait asynchronously until a shutdown request is signaled
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            logger.debug("Server run loop received CancelledError.")
            raise
        finally:
            await self.stop()

    def request_shutdown(self) -> None:
        """Signal the running server loop to terminate gracefully.

        Idempotent: Safe to call multiple times or after the server has already stopped.
        """
        if not self._is_running and self._shutdown_event.is_set():
            logger.debug("Server is already stopped or shutting down; request_shutdown() ignored.")
            return

        logger.info("Shutdown signal received; initiating graceful termination.")
        self._shutdown_event.set()

    async def stop(self) -> None:
        """Perform graceful shutdown and resource cleanup.

        Idempotent: Safe to call multiple times; redundant invocations exit immediately.
        """
        if not self._is_running:
            logger.debug("%s is already stopped or not running; stop() ignored.", self.config.app_name)
            return

        logger.info("Stopping %s...", self.config.app_name)
        self._is_running = False
        self._shutdown_event.set()

        # Stop WebSocket server and close client connections
        await self.ws_server.stop()

        logger.info("%s stopped cleanly.", self.config.app_name)
