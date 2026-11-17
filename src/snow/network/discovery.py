"""Zero-touch UDP discovery service and protocol for SNOW.

Implements lightweight UDP beacon broadcasting and listening on port 8768,
enabling devices on the same local network to discover each other automatically
without manual IP entry while preserving strict cryptographic trust boundaries.
"""

import asyncio
from dataclasses import asdict, dataclass
import json
import logging
import os
import secrets
import socket
import time
from typing import Callable, Dict, List, Optional

from snow.core.config import CoreConfig
from snow.core.network import detect_usable_ipv4_addresses
from snow.security.identity import DeviceIdentity

logger = logging.getLogger(__name__)

DISCOVERY_PROTOCOL_NAME = "snow-discovery"
DISCOVERY_PROTOCOL_VERSION = 1
MAX_BEACON_SIZE_BYTES = 2048
BEACON_TIMESTAMP_MAX_DRIFT_SEC = 30.0
PEER_STALE_TIMEOUT_SEC = 10.0


@dataclass
class DiscoveryBeacon:
    """Structured representation of a SNOW UDP discovery beacon."""

    proto: str = DISCOVERY_PROTOCOL_NAME
    v: int = DISCOVERY_PROTOCOL_VERSION
    device_id: str = ""
    device_name: str = ""
    device_type: str = "windows"
    port: int = 8765
    transfer_port: int = 8766
    cert_fingerprint: str = ""
    timestamp: float = 0.0
    nonce: str = ""
    wake_target: Optional[str] = None

    def to_bytes(self) -> bytes:
        """Serialize beacon into compact JSON bytes."""
        data = asdict(self)
        if self.wake_target is None:
            data.pop("wake_target", None)
        raw = json.dumps(data, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        if len(raw) > MAX_BEACON_SIZE_BYTES:
            raise ValueError(f"Serialized beacon exceeds {MAX_BEACON_SIZE_BYTES} bytes")
        return raw

    @classmethod
    def from_bytes(cls, data: bytes) -> Optional["DiscoveryBeacon"]:
        """Parse and validate incoming beacon bytes.

        Returns None if malformed, invalid size, unparseable, or failed validation.
        """
        if not data or len(data) > MAX_BEACON_SIZE_BYTES:
            return None

        try:
            payload = json.loads(data.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None

        if not isinstance(payload, dict):
            return None

        if payload.get("proto") != DISCOVERY_PROTOCOL_NAME:
            return None

        if payload.get("v") != DISCOVERY_PROTOCOL_VERSION:
            return None

        dev_id = payload.get("device_id")
        if not dev_id or not isinstance(dev_id, str):
            return None

        dev_name = payload.get("device_name", "Unknown Device")
        if not isinstance(dev_name, str):
            dev_name = str(dev_name)

        dev_type = payload.get("device_type", "unknown")
        if not isinstance(dev_type, str):
            dev_type = "unknown"

        port = payload.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
            return None

        transfer_port = payload.get("transfer_port", 0)
        if not isinstance(transfer_port, int) or isinstance(transfer_port, bool) or not (0 <= transfer_port <= 65535):
            return None

        cert_fp = payload.get("cert_fingerprint", "")
        if not isinstance(cert_fp, str):
            cert_fp = ""

        ts = payload.get("timestamp")
        if not isinstance(ts, (int, float)) or isinstance(ts, bool):
            return None

        now = time.time()
        if abs(now - ts) > BEACON_TIMESTAMP_MAX_DRIFT_SEC:
            logger.debug("Dropped beacon with excessive timestamp drift: %.2fs (now=%.2f, ts=%.2f)", abs(now - ts), now, ts)
            return None

        nonce = payload.get("nonce", "")
        if not isinstance(nonce, str):
            nonce = ""

        wake_target = payload.get("wake_target")
        if wake_target is not None and not isinstance(wake_target, str):
            wake_target = None

        return cls(
            proto=DISCOVERY_PROTOCOL_NAME,
            v=DISCOVERY_PROTOCOL_VERSION,
            device_id=dev_id,
            device_name=dev_name,
            device_type=dev_type,
            port=port,
            transfer_port=transfer_port,
            cert_fingerprint=cert_fp,
            timestamp=float(ts),
            nonce=nonce,
            wake_target=wake_target,
        )


@dataclass
class DiscoveredPeerRecord:
    """Cached record of a discovered network peer."""

    device_id: str
    device_name: str
    device_type: str
    ip_address: str
    port: int
    transfer_port: int
    cert_fingerprint: str
    last_seen_timestamp: float
    is_paired: bool = False

    @property
    def is_stale(self) -> bool:
        """Return True if no beacon has been received within stale timeout."""
        return (time.time() - self.last_seen_timestamp) > PEER_STALE_TIMEOUT_SEC


class _UdpDiscoveryProtocol(asyncio.DatagramProtocol):
    """Internal asyncio datagram protocol for handling incoming discovery packets."""

    def __init__(self, on_packet_callback: Callable[[bytes, tuple], None]) -> None:
        self._on_packet = on_packet_callback
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        try:
            self._on_packet(data, addr)
        except Exception as exc:
            logger.debug("Error handling discovery datagram from %s: %s", addr, exc)

    def error_received(self, exc: Exception) -> None:
        logger.debug("UDP discovery protocol error: %s", exc)


class SnowDiscoveryService:
    """Async UDP broadcast announcer and listener for SNOW.

    Periodically announces the core server's presence via UDP broadcast, listens for
    incoming beacons from peers, tracks active LAN candidates, and dispatches wake bursts.
    """

    def __init__(
        self,
        config: CoreConfig,
        device_identity: DeviceIdentity,
        cert_fingerprint: str = "",
        paired_device_checker: Optional[Callable[[str, str], bool]] = None,
        wake_listener: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.config = config
        self.device_identity = device_identity
        self.cert_fingerprint = cert_fingerprint
        self.paired_device_checker = paired_device_checker
        self.wake_listener = wake_listener

        self._discovered_peers: Dict[str, DiscoveredPeerRecord] = {}
        self._rate_limits: Dict[str, List[float]] = {}
        self._is_running = False
        self._broadcast_task: Optional[asyncio.Task] = None
        self._prune_task: Optional[asyncio.Task] = None
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._protocol: Optional[_UdpDiscoveryProtocol] = None
        self._bound_port: Optional[int] = None
        self._lock = asyncio.Lock()

    @property
    def is_running(self) -> bool:
        return self._is_running

    @property
    def bound_port(self) -> Optional[int]:
        return self._bound_port

    def list_discovered_peers(self, include_stale: bool = False) -> List[DiscoveredPeerRecord]:
        """Return a snapshot of all discovered network peers."""
        now = time.time()
        results = []
        for p in self._discovered_peers.values():
            if include_stale or (now - p.last_seen_timestamp <= PEER_STALE_TIMEOUT_SEC):
                results.append(p)
        return results

    def get_peer(self, device_id: str) -> Optional[DiscoveredPeerRecord]:
        """Return the discovered record for device_id if active."""
        peer = self._discovered_peers.get(device_id)
        if peer and not peer.is_stale:
            return peer
        return None

    def _create_beacon(self, wake_target: Optional[str] = None) -> DiscoveryBeacon:
        """Build a new signed discovery beacon for this instance."""
        return DiscoveryBeacon(
            device_id=self.device_identity.device_id,
            device_name=self.device_identity.device_name,
            device_type="windows",
            port=self.config.port,
            transfer_port=self.config.transfer_port,
            cert_fingerprint=self.cert_fingerprint,
            timestamp=time.time(),
            nonce=secrets.token_hex(16),
            wake_target=wake_target,
        )

    def _get_broadcast_destinations(self) -> List[str]:
        """Compute usable IPv4 broadcast destinations for all active local subnets."""
        destinations = {"255.255.255.255"}
        try:
            ifaces = detect_usable_ipv4_addresses()
            for iface in ifaces:
                if iface.is_up and iface.ip_address and not iface.ip_address.startswith("127."):
                    # Calculate simple /24 subnet broadcast address as standard LAN default
                    parts = iface.ip_address.split(".")
                    if len(parts) == 4:
                        subnet_bcast = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
                        destinations.add(subnet_bcast)
        except Exception as exc:
            logger.debug("Failed detecting per-subnet broadcast addresses: %s", exc)

        return list(destinations)

    def _handle_incoming_datagram(self, data: bytes, addr: tuple) -> None:
        """Validate and ingest incoming UDP beacon."""
        remote_ip = addr[0]

        # Rate limiting: maximum 25 beacons per 2 seconds from the same IP
        now = time.time()
        history = self._rate_limits.setdefault(remote_ip, [])
        history[:] = [t for t in history if now - t < 2.0]
        if len(history) >= 25:
            logger.debug("Rate limit exceeded for discovery datagrams from %s", remote_ip)
            return
        history.append(now)

        beacon = DiscoveryBeacon.from_bytes(data)
        if not beacon:
            return

        # Ignore own reflected packets
        if beacon.device_id == self.device_identity.device_id:
            return

        # Check if this peer is cryptographically paired
        is_paired = False
        if self.paired_device_checker:
            try:
                is_paired = self.paired_device_checker(beacon.device_id, beacon.cert_fingerprint)
            except Exception as exc:
                logger.debug("Error checking paired status for %s: %s", beacon.device_id, exc)

        # Handle targeted wake burst
        if beacon.wake_target == self.device_identity.device_id:
            logger.info("Received wake burst from peer %s (%s)", beacon.device_name, beacon.device_id)
            if self.wake_listener:
                try:
                    self.wake_listener(beacon.device_id, remote_ip)
                except Exception as exc:
                    logger.debug("Wake listener callback error: %s", exc)

        record = DiscoveredPeerRecord(
            device_id=beacon.device_id,
            device_name=beacon.device_name,
            device_type=beacon.device_type,
            ip_address=remote_ip,
            port=beacon.port,
            transfer_port=beacon.transfer_port,
            cert_fingerprint=beacon.cert_fingerprint,
            last_seen_timestamp=now,
            is_paired=is_paired,
        )

        self._discovered_peers[beacon.device_id] = record

    async def _broadcast_loop(self) -> None:
        """Periodically broadcast discovery beacons on LAN."""
        while self._is_running:
            try:
                await self.broadcast_beacon()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug("Error in discovery broadcast iteration: %s", exc)

            try:
                await asyncio.sleep(self.config.beacon_interval)
            except asyncio.CancelledError:
                break

    async def _prune_loop(self) -> None:
        """Periodically evict stale peers from discovery cache."""
        while self._is_running:
            try:
                await asyncio.sleep(5.0)
                now = time.time()
                stale_ids = [
                    dev_id for dev_id, p in self._discovered_peers.items()
                    if now - p.last_seen_timestamp > (PEER_STALE_TIMEOUT_SEC * 2)
                ]
                for dev_id in stale_ids:
                    self._discovered_peers.pop(dev_id, None)

                # Clean up rate limits table
                for ip in list(self._rate_limits.keys()):
                    self._rate_limits[ip] = [t for t in self._rate_limits[ip] if now - t < 5.0]
                    if not self._rate_limits[ip]:
                        self._rate_limits.pop(ip, None)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.debug("Error in discovery prune loop: %s", exc)

    async def broadcast_beacon(self, wake_target: Optional[str] = None) -> None:
        """Send a discovery beacon to all LAN broadcast destinations."""
        if not self._transport:
            return

        beacon = self._create_beacon(wake_target=wake_target)
        payload = beacon.to_bytes()
        destinations = self._get_broadcast_destinations()
        target_port = self._bound_port or self.config.discovery_port

        for dst in destinations:
            try:
                self._transport.sendto(payload, (dst, target_port))
            except Exception as exc:
                logger.debug("Failed sending discovery datagram to %s:%d: %s", dst, target_port, exc)

    async def send_wake_burst(self, target_device_id: str, count: int = 3, interval: float = 0.15) -> None:
        """Send immediate burst of wake beacons to prompt a sleeping peer to reconnect."""
        logger.info("Sending %d wake burst beacons for device [%s]...", count, target_device_id)
        for i in range(count):
            await self.broadcast_beacon(wake_target=target_device_id)
            if i < count - 1:
                await asyncio.sleep(interval)

    async def start(self) -> None:
        """Bind UDP listener socket and start background broadcast and prune loops."""
        if self._is_running:
            return

        if not self.config.discovery_enabled:
            logger.info("Zero-touch UDP discovery is disabled by configuration.")
            return

        loop = asyncio.get_running_loop()

        # Create dual-purpose UDP socket with SO_BROADCAST and SO_REUSEADDR
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if hasattr(socket, "SO_REUSEADDR"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # On Windows, bind to 0.0.0.0 or the configured bind host
        bind_host = "0.0.0.0" if self.config.bind_host == "0.0.0.0" else self.config.bind_host
        try:
            sock.bind((bind_host, self.config.discovery_port))
        except OSError as exc:
            logger.warning("Could not bind UDP discovery socket on %s:%d: %s. Discovery disabled.",
                           bind_host, self.config.discovery_port, exc)
            sock.close()
            return

        sock.setblocking(False)

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _UdpDiscoveryProtocol(self._handle_incoming_datagram),
            sock=sock,
        )

        self._transport = transport
        self._protocol = protocol
        actual_port = sock.getsockname()[1]
        self._bound_port = actual_port
        self._is_running = True

        self._broadcast_task = asyncio.create_task(self._broadcast_loop())
        self._prune_task = asyncio.create_task(self._prune_loop())

        logger.info("Zero-touch UDP discovery listening and broadcasting on port %d.", actual_port)

    async def stop(self) -> None:
        """Stop background tasks and close UDP transport cleanly."""
        if not self._is_running:
            return

        self._is_running = False

        if self._broadcast_task and not self._broadcast_task.done():
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except asyncio.CancelledError:
                pass
            self._broadcast_task = None

        if self._prune_task and not self._prune_task.done():
            self._prune_task.cancel()
            try:
                await self._prune_task
            except asyncio.CancelledError:
                pass
            self._prune_task = None

        if self._transport:
            self._transport.close()
            self._transport = None
            self._protocol = None

        logger.info("Zero-touch UDP discovery stopped cleanly.")
