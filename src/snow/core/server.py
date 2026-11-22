"""Asynchronous core server lifecycle for SNOW."""

import asyncio
import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, List, Optional

from snow.capabilities.engine import CapabilityEngine
from snow.capabilities.windows import (
    WindowsAppLauncher,
    WindowsClipboardManager,
    WindowsFileManager,
    WindowsProcessMonitor,
    WindowsTelemetry,
    WindowsTerminalExecutor,
)
from snow.core.config import CoreConfig
from snow.core.ipc import SnowIpcServer
from snow.core.network import NetworkInterfaceInfo, detect_usable_ipv4_addresses
from snow.network.connection_manager import ConnectionManager
from snow.network.discovery import SnowDiscoveryService
from snow.network.registry import NodeRegistry
from snow.network.ws_server import SnowWebSocketServer
from snow.security.db import DatabaseManager
from snow.security.identity import DeviceIdentity
from snow.security.policy import PeerCapabilityPolicy
from snow.transfer.http_server import SnowHttpTransferServer
from snow.transfer.manager import TransferManager
from snow.transfer.storage import TransferStorageManager

logger = logging.getLogger(__name__)


class SnowCoreServer:
    """Headless asynchronous core server for SNOW.

    Coordinates the core lifecycle: configuration loading, network interface
    enumeration, WebSocket server hosting, and graceful shutdown.
    """

    def __init__(
        self,
        config: Optional[CoreConfig] = None,
        db_manager: Optional[DatabaseManager] = None,
        device_identity: Optional[DeviceIdentity] = None,
    ) -> None:
        self.config = config or CoreConfig.from_env()
        self._is_running = False
        self._shutdown_event = asyncio.Event()
        self._detected_interfaces: List[NetworkInterfaceInfo] = []
        self.connection_manager = ConnectionManager()
        self.transfer_manager = TransferManager()
        self.storage_manager = TransferStorageManager(root_dir=self.config.transfer_root)
        self.ws_server = SnowWebSocketServer(
            config=self.config,
            connection_manager=self.connection_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
            db_manager=db_manager,
            device_identity=device_identity,
        )
        self.http_transfer_server: Optional[SnowHttpTransferServer] = None
        self.windows_telemetry = WindowsTelemetry()
        self.windows_processes = WindowsProcessMonitor()
        roots = [self.config.transfer_root] if self.config.transfer_root else None
        self.windows_files = WindowsFileManager(allowed_roots=roots)
        self.windows_apps = WindowsAppLauncher()
        self.windows_terminal = WindowsTerminalExecutor()
        self.windows_clipboard = WindowsClipboardManager()
        data_dir = os.environ.get("SNOW_DATA_DIR")
        base_dir = Path(data_dir).resolve() if data_dir else Path.home() / ".snow"
        self.capability_policy = PeerCapabilityPolicy(policy_file=base_dir / "peer_policy.json")
        self.capability_engine = CapabilityEngine(
            telemetry=self.windows_telemetry,
            processes=self.windows_processes,
            files=self.windows_files,
            apps=self.windows_apps,
            terminal=self.windows_terminal,
            clipboard=self.windows_clipboard,
            policy=self.capability_policy,
        )
        self.ws_server.core_server = self
        self.ws_server.windows_telemetry = self.windows_telemetry
        self.ws_server.windows_processes = self.windows_processes
        self.ws_server.windows_files = self.windows_files
        self.ws_server.windows_apps = self.windows_apps
        self.ws_server.windows_terminal = self.windows_terminal
        self.ws_server.windows_clipboard = self.windows_clipboard
        self.ws_server.capability_policy = self.capability_policy
        self.ws_server.capability_engine = self.capability_engine
        self.clipboard_buffer = self.capability_engine.clipboard_buffer
        self.ws_server.clipboard_buffer = self.capability_engine.clipboard_buffer
        self.node_registry = NodeRegistry(
            db_manager=self.db_manager,
            connection_manager=self.ws_server.connection_manager,
            local_identity=self.device_identity,
            port=self.config.port,
            transfer_port=self.config.transfer_port,
        )
        self.ws_server.node_registry = self.node_registry
        self.capability_engine.node_registry = self.node_registry
        self.capability_engine.db_manager = self.db_manager
        self.capability_engine.transfer_manager = self.transfer_manager
        self.capability_engine.storage_manager = self.storage_manager
        self.capability_engine.http_transfer_server = self.http_transfer_server
        self.capability_engine.core_server = self

        from snow.network.router import SessionRouter

        self.session_router = SessionRouter(
            node_registry=self.node_registry,
            ws_server=self.ws_server,
            discovery_service=None,
            capability_engine=self.capability_engine,
            db_manager=self.db_manager,
            wake_grace_period=getattr(self.config, "device_connect_grace_period", 6.0),
        )
        self.capability_engine.session_router = self.session_router

        # Attach approval notification broadcast listener to approval engine
        app_engine = getattr(self.capability_engine, "approval_engine", None)
        if app_engine and hasattr(app_engine, "add_listener"):
            def _approval_event_listener(event_type: str, data: dict) -> None:
                if self.ws_server and hasattr(self.ws_server, "broadcast_approval_event"):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(self.ws_server.broadcast_approval_event(event_type, data))
                    except RuntimeError:
                        pass
            app_engine.add_listener(_approval_event_listener)

        self.ipc_server: SnowIpcServer = SnowIpcServer(core_server=self, config=self.config)
        self.ipc_server.capability_engine = self.capability_engine
        self.ipc_server.node_registry = self.node_registry
        self.ipc_server.session_router = self.session_router
        self.discovery_service: Optional[SnowDiscoveryService] = None

        from snow.network.network_model import SnowNetworkManager
        self.network_manager = SnowNetworkManager(
            db_manager=self.db_manager,
            local_identity=self.device_identity,
            node_registry=self.node_registry,
        )
        self.peer_clients: dict[str, Any] = {}

    async def connect_peer(
        self,
        host: str,
        port: int = 8765,
        pin: str = "",
        expected_fingerprint: str = "",
    ) -> dict[str, Any]:
        """Establish outbound TLS/WSS peer connection, register in NodeRegistry and DB, and retain session."""
        from snow.network.peer_client import SnowPeerClient

        client = SnowPeerClient(
            host=host,
            port=port,
            identity=self.device_identity,
            expected_fingerprint=expected_fingerprint or None,
            use_tls=True,
        )
        res = await client.connect(pin=pin, timeout=10.0)
        if not res.success or not res.remote_device_id:
            await client.close()
            return {
                "success": False,
                "status": res.status,
                "error": res.error or "Failed connecting to peer.",
            }

        remote_id = res.remote_device_id
        remote_name = res.remote_device_name or "Connected Peer"
        session_id = res.session_id or f"peer_{remote_id}"
        auth_token = res.auth_token or ""
        cert_fp = res.cert_fingerprint or ""

        # Close existing client for this device if any
        old_client = self.peer_clients.get(remote_id)
        if old_client:
            try:
                await old_client.close()
            except Exception:
                pass

        self.peer_clients[remote_id] = client

        # 1. Register in NodeRegistry
        self.node_registry.on_session_authenticated(
            device_id=remote_id,
            connection_id=session_id,
            host=host,
            port=port,
            manifest_data=res.manifest,
            transport="peer_link",
        )

        # 2. Persist in paired_devices
        token_hash = hashlib.sha256(auth_token.encode("utf-8")).hexdigest() if auth_token else hashlib.sha256(remote_id.encode("utf-8")).hexdigest()
        existing = self.db_manager.get_paired_device(remote_id)
        if not existing:
            self.db_manager.insert_paired_device(
                device_id=remote_id,
                device_name=remote_name,
                auth_token_hash=token_hash,
                trust_tier="peer",
                platform="windows",
                reachability_profile="ACTIVE_SESSION_PEER",
                last_known_host=host,
                last_known_port=port,
                capabilities_json=json.dumps(res.manifest or {}),
            )
        else:
            self.db_manager.update_device_endpoint(remote_id, host, port)
            self.db_manager.update_last_seen(remote_id)

        # 3. Record in network_endpoints ring buffer
        self.network_manager.record_endpoint(device_id=remote_id, host=host, port=port)

        return {
            "success": True,
            "status": res.status,
            "data": {
                "remote_device_id": remote_id,
                "remote_device_name": remote_name,
                "session_id": session_id,
                "cert_fingerprint": cert_fp,
            },
        }

    async def disconnect_peer(self, device_id: str) -> dict[str, Any]:
        """Disconnect an active peer session, updating registry without forgetting pairing."""
        client = self.peer_clients.pop(device_id, None)
        if client:
            try:
                await client.close()
            except Exception:
                pass
            self.node_registry.on_session_disconnected(device_id)
            return {"success": True, "status": "DISCONNECTED", "device_id": device_id}
        return {"success": False, "status": "NOT_CONNECTED", "error": f"Peer '{device_id}' is not connected."}

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

    @property
    def db_manager(self):
        """Return the core server's SQLite database manager."""
        return self.ws_server.db_manager

    @property
    def session_manager(self):
        """Return the core server's active session manager."""
        return self.ws_server.session_manager

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
        active_ips = [iface.ip_address for iface in self._detected_interfaces if iface.is_up]
        await self.ws_server.start(active_ips=active_ips)

        # Start the HTTP/HTTPS file transfer server reusing WSS ssl_context
        self.http_transfer_server = SnowHttpTransferServer(
            config=self.config,
            db_manager=self.db_manager,
            transfer_manager=self.transfer_manager,
            storage_manager=self.storage_manager,
            ssl_context=self.ws_server.ssl_context,
        )
        self.ws_server.http_transfer_server = self.http_transfer_server
        self.capability_engine.http_transfer_server = self.http_transfer_server
        await self.http_transfer_server.start()

        # Start the authenticated loopback IPC server for MCP subprocess communication
        await self.ipc_server.start()

        # Start zero-touch UDP discovery service
        if self.config.discovery_enabled:
            def _check_paired(dev_id: str, cert_fp: str) -> bool:
                paired = self.db_manager.get_paired_device(dev_id)
                if not paired:
                    return False
                if paired.cert_fingerprint and cert_fp:
                    return paired.cert_fingerprint.lower() == cert_fp.lower()
                return True

            self.discovery_service = SnowDiscoveryService(
                config=self.config,
                device_identity=self.device_identity,
                cert_fingerprint=getattr(self.ws_server, "cert_fingerprint", ""),
                paired_device_checker=_check_paired,
            )
            await self.discovery_service.start()
            self.node_registry.discovery_service = self.discovery_service
            self.session_router.discovery_service = self.discovery_service

        self._is_running = True
        actual_port = self.ws_server.bound_port or self.config.port
        actual_http_port = self.http_transfer_server.bound_port or self.config.transfer_port
        actual_ipc_port = self.ipc_server.bound_port or self.config.ipc_port
        logger.info(
            "%s started successfully (listening on WSS port %d, HTTP transfer port %d, IPC port %d).",
            self.config.app_name,
            actual_port,
            actual_http_port,
            actual_ipc_port,
        )

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

        # Stop IPC server first so external tool requests terminate cleanly before core shuts down
        if self.ipc_server:
            await self.ipc_server.stop()

        # Stop discovery service
        if self.discovery_service:
            await self.discovery_service.stop()
            self.discovery_service = None

        # Stop HTTP transfer server
        if self.http_transfer_server:
            await self.http_transfer_server.stop()
            self.http_transfer_server = None

        # Close all active peer clients
        if hasattr(self, "peer_clients"):
            for p_id, p_client in list(self.peer_clients.items()):
                try:
                    await p_client.close()
                except Exception:
                    pass
            self.peer_clients.clear()

        # Stop WebSocket server and close client connections
        await self.ws_server.stop()

        logger.info("%s stopped cleanly.", self.config.app_name)


if __name__ == "__main__":
    import sys
    from snow.main import main
    sys.exit(main())
