"""Relay Client and E2E Tunnel Orchestrator for the Desktop Core."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from typing import Any, Awaitable, Callable, Dict, Optional, Tuple

import aiohttp

from snow.network.e2e_tunnel import (
    FingerprintMismatchError,
    TlsMemoryBioTunnel,
    create_e2e_tunnel_ssl_context,
)
from snow.protocol.models import MessageType, SnowMessage

logger = logging.getLogger(__name__)

TUNNEL_INIT_SIGNAL = b"SNOW_TUNNEL_INIT"
MEDIA_FRAME_MAGIC = b"SNOW_MEDIA_JPG\x00"
MAX_RELAY_MEDIA_FRAME_BYTES = 512 * 1024


def is_tls_server_role(local_id: str, remote_id: str) -> bool:
    """Determine deterministic TLS role for end-to-end encrypted relay tunnels.

    The node with the lexicographically greater device_id acts as the TLS server.
    The node with the smaller device_id acts as the TLS client.
    Ensures symmetric pairings (Windows <-> Windows, Android <-> Android)
    never deadlock or contend for the same role.
    """
    return str(local_id) > str(remote_id)


class RelayTunnelClient:
    """Connects to a remote SNOW Relay, authenticates, and maintains E2E TLS 1.3 tunnels to peers."""

    def __init__(
        self,
        relay_url: str,
        device_id: str,
        group_id: str,
        ticket: str,
        cert_path: str,
        key_path: str,
        hub_token: Optional[str] = None,
        bootstrap_token: Optional[str] = None,
        network_id: Optional[str] = None,
    ) -> None:
        self.relay_url = relay_url
        self.device_id = device_id
        self.group_id = group_id
        self.ticket = ticket
        self.hub_token = hub_token
        self.bootstrap_token = bootstrap_token
        self.network_id = network_id
        self.cert_path = cert_path
        self.key_path = key_path

        self._session: Optional[aiohttp.ClientSession] = None
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._is_connected: bool = False
        self._receive_task: Optional[asyncio.Task] = None

        # peer_id -> TlsMemoryBioTunnel
        self._tunnels: Dict[str, TlsMemoryBioTunnel] = {}
        # peer_id -> pinned fingerprint
        self._pinned_fingerprints: Dict[str, str] = {}
        # peer_id -> optional certificate path
        self._peer_cert_paths: Dict[str, str] = {}
        # peer_id -> asyncio.Queue of decrypted SnowMessage
        self._incoming_queues: Dict[str, asyncio.Queue[SnowMessage]] = {}
        # peer_id -> handshake completion event
        self._handshake_events: Dict[str, asyncio.Event] = {}

        # Optional request dispatcher callback: async (source_id: str, msg: SnowMessage) -> Optional[SnowMessage]
        self.request_dispatcher: Optional[Callable[[str, SnowMessage], Any]] = None
        # Optional async callback for incoming E2E screen media frames: async (source_id, meta, jpeg_bytes)
        self.media_frame_handler: Optional[Callable[[str, dict[str, Any], bytes], Awaitable[None]]] = None

    def set_peer_pinned_fingerprint(
        self,
        peer_id: str,
        fingerprint: str,
        cert_path: Optional[str] = None,
    ) -> None:
        """Register the user-pinned fingerprint and optional cert path for a target peer."""
        self._pinned_fingerprints[peer_id] = fingerprint
        if cert_path:
            self._peer_cert_paths[peer_id] = cert_path

    async def connect(self, timeout: float = 10.0) -> bool:
        """Connect to the remote relay WebSocket endpoint and perform hello handshake."""
        if self._is_connected:
            return True

        self._session = aiohttp.ClientSession()
        try:
            self._ws = await asyncio.wait_for(
                self._session.ws_connect(self.relay_url, heartbeat=30.0),
                timeout=timeout,
            )
            # Send hello frame
            hello_payload: Dict[str, Any] = {
                "type": "hello",
                "device_id": self.device_id,
                "group_id": self.group_id,
            }
            if self.hub_token:
                hello_payload["hub_token"] = self.hub_token
                hello_payload["network_id"] = self.network_id or self.group_id
            elif self.bootstrap_token:
                hello_payload["bootstrap_token"] = self.bootstrap_token
                hello_payload["network_id"] = self.network_id or self.group_id
            else:
                hello_payload["ticket"] = self.ticket
            await self._ws.send_json(hello_payload)

            ack_msg = await asyncio.wait_for(self._ws.receive(), timeout=timeout)
            if ack_msg.type != aiohttp.WSMsgType.TEXT:
                await self.disconnect()
                return False

            ack_data = json.loads(ack_msg.data)
            if not ack_data.get("success"):
                await self.disconnect()
                return False

            self._is_connected = True
            self._receive_task = asyncio.create_task(self._read_loop())
            logger.info("Connected and authenticated to relay %s as [%s]", self.relay_url, self.device_id)
            return True

        except Exception as e:
            logger.warning("Failed connecting to relay %s: %s", self.relay_url, e)
            await self.disconnect()
            return False

    async def disconnect(self) -> None:
        """Disconnect from the relay and tear down active tunnels."""
        self._is_connected = False
        if self._receive_task:
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass

        if self._ws and not self._ws.closed:
            await self._ws.close()
        if self._session and not self._session.closed:
            await self._session.close()

        self._tunnels.clear()
        self._incoming_queues.clear()
        self._handshake_events.clear()

    async def close_tunnel(self, peer_id: str) -> bool:
        """Safely close and clean up an active E2E relay tunnel for a specific peer.

        Safely:
        1. Locates tunnel belonging to peer_id.
        2. Terminates active inner TLS 1.3 tunnel.
        3. Removes entries from _tunnels, _handshake_events, _incoming_queues,
           _pinned_fingerprints, and _peer_cert_paths.
        4. Releases associated BIO resources.
        5. Is idempotent and safe if tunnel does not exist or is called repeatedly.
        6. Returns True if a tunnel was located and closed, False otherwise.
        """
        tunnel = self._tunnels.pop(peer_id, None)
        self._pinned_fingerprints.pop(peer_id, None)
        self._peer_cert_paths.pop(peer_id, None)
        queue = self._incoming_queues.pop(peer_id, None)
        event = self._handshake_events.pop(peer_id, None)

        if event:
            event.set()

        if queue:
            # Drain any pending messages in incoming queue
            while not queue.empty():
                try:
                    queue.get_nowait()
                except Exception:
                    break

        if tunnel:
            try:
                ssl_obj = getattr(tunnel, "ssl_obj", tunnel)
                if hasattr(ssl_obj, "unwrap"):
                    ssl_obj.unwrap()
            except Exception:
                pass
            logger.info("Closed active E2E relay tunnel for peer [%s]", peer_id)
            return True

        return False

    async def initiate_e2e_tunnel(self, target_id: str, timeout: float = 10.0) -> bool:
        """Initiate E2E TLS 1.3 handshake with target peer through relay.

        Uses deterministic role negotiation:
        - If local_id < target_id: node is TLS client; generates ClientHello and sends frame.
        - If local_id > target_id: node is TLS server; prepares server tunnel and prompts client.
        """
        if not self._is_connected or not self._ws:
            return False

        existing = self._tunnels.get(target_id)
        if existing and existing.handshake_done:
            return True

        is_server = is_tls_server_role(self.device_id, target_id)
        pinned_fp = self._pinned_fingerprints.get(target_id)
        peer_cert = self._peer_cert_paths.get(target_id)
        ctx = create_e2e_tunnel_ssl_context(
            self.cert_path, self.key_path, is_server=is_server, peer_cert_path=peer_cert
        )
        tunnel = TlsMemoryBioTunnel(
            ssl_context=ctx,
            is_server=is_server,
            expected_peer_fingerprint=pinned_fp,
        )
        self._tunnels[target_id] = tunnel
        event = asyncio.Event()
        self._handshake_events[target_id] = event
        self._incoming_queues.setdefault(target_id, asyncio.Queue())

        if not is_server:
            # Client role: drive initial client_hello
            done, out_bytes = tunnel.drive_handshake()
            if out_bytes:
                await self._send_relay_frame(target_id, out_bytes)
        else:
            # Server role: prepare server tunnel and send init signal to prompt client ClientHello
            logger.debug("Prepared TLS server tunnel for peer [%s], sending init prompt...", target_id)
            await self._send_relay_frame(target_id, TUNNEL_INIT_SIGNAL)

        # Wait for handshake completion
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            logger.warning("E2E TLS 1.3 handshake with peer [%s] timed out.", target_id)
            self._tunnels.pop(target_id, None)
            return False

    async def send_message(self, target_id: str, message: SnowMessage) -> bool:
        """Encrypt and send a SnowMessage over the inner E2E TLS 1.3 tunnel."""
        tunnel = self._tunnels.get(target_id)
        if not tunnel or not tunnel.handshake_done:
            # Attempt to establish tunnel
            ok = await self.initiate_e2e_tunnel(target_id)
            if not ok:
                return False
            tunnel = self._tunnels.get(target_id)
            if not tunnel:
                return False

        plaintext = message.to_json().encode("utf-8")
        encrypted = tunnel.encrypt_application_data(plaintext)
        if encrypted:
            await self._send_relay_frame(target_id, encrypted)
            return True
        return False

    async def send_screen_frame(
        self, target_id: str, meta: dict[str, Any], jpeg_bytes: bytes
    ) -> bool:
        """Encrypt and send a bounded JPEG screen frame over the inner E2E TLS 1.3 tunnel."""
        if not jpeg_bytes or len(jpeg_bytes) > MAX_RELAY_MEDIA_FRAME_BYTES:
            return False
        tunnel = self._tunnels.get(target_id)
        if not tunnel or not tunnel.handshake_done:
            ok = await self.initiate_e2e_tunnel(target_id)
            if not ok:
                return False
            tunnel = self._tunnels.get(target_id)
            if not tunnel:
                return False

        header_bytes = json.dumps(meta, separators=(",", ":")).encode("utf-8")
        plaintext = MEDIA_FRAME_MAGIC + header_bytes + b"\x00" + jpeg_bytes
        encrypted = tunnel.encrypt_application_data(plaintext)
        if encrypted:
            await self._send_relay_frame(target_id, encrypted)
            return True
        return False

    async def receive_message(self, peer_id: str, timeout: Optional[float] = None) -> Optional[SnowMessage]:
        """Receive the next decrypted SnowMessage from a specific peer tunnel."""
        queue = self._incoming_queues.setdefault(peer_id, asyncio.Queue())
        try:
            if timeout is not None:
                return await asyncio.wait_for(queue.get(), timeout=timeout)
            return await queue.get()
        except asyncio.TimeoutError:
            return None

    async def _send_relay_frame(self, target_id: str, raw_payload: bytes) -> None:
        """Send an opaque frame through the relay to target_id."""
        if not self._ws or self._ws.closed:
            return
        payload_b64 = base64.b64encode(raw_payload).decode("ascii")
        await self._ws.send_json({
            "type": "relay_frame",
            "target": target_id,
            "payload_b64": payload_b64,
        })

    async def _read_loop(self) -> None:
        """Read incoming frames from relay and drive inner TLS tunnels."""
        try:
            async for msg in self._ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except Exception:
                        continue

                    mtype = data.get("type")
                    if mtype == "relay_frame":
                        source_id = data.get("source")
                        payload_b64 = data.get("payload_b64", "")
                        raw_bytes = base64.b64decode(payload_b64)
                        await self._handle_incoming_relay_bytes(source_id, raw_bytes)

                    elif mtype == "relay_error":
                        logger.warning("Relay error: %s (%s)", data.get("message"), data.get("error_code"))

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.warning("Relay client read loop terminated: %s", e)
            self._is_connected = False

    async def _handle_incoming_relay_bytes(self, source_id: str, raw_bytes: bytes) -> None:
        """Process incoming raw inner TLS bytes from a peer."""
        # Check for out-of-band tunnel init signal
        if raw_bytes == TUNNEL_INIT_SIGNAL:
            if not is_tls_server_role(self.device_id, source_id):
                # We are client: initiate handshake by sending ClientHello
                logger.debug("Received tunnel init prompt from [%s]. Initiating client handshake...", source_id)
                asyncio.create_task(self.initiate_e2e_tunnel(source_id))
            return

        tunnel = self._tunnels.get(source_id)
        if not tunnel:
            # Incoming handshake from peer: initialize tunnel with deterministic role
            is_server = is_tls_server_role(self.device_id, source_id)
            pinned_fp = self._pinned_fingerprints.get(source_id)
            peer_cert = self._peer_cert_paths.get(source_id)
            ctx = create_e2e_tunnel_ssl_context(
                self.cert_path, self.key_path, is_server=is_server, peer_cert_path=peer_cert
            )
            tunnel = TlsMemoryBioTunnel(
                ssl_context=ctx,
                is_server=is_server,
                expected_peer_fingerprint=pinned_fp,
            )
            self._tunnels[source_id] = tunnel
            self._incoming_queues.setdefault(source_id, asyncio.Queue())
            self._handshake_events.setdefault(source_id, asyncio.Event())

        tunnel.feed_network_data(raw_bytes)

        if not tunnel.handshake_done:
            try:
                done, out_bytes = tunnel.drive_handshake()
                if out_bytes:
                    await self._send_relay_frame(source_id, out_bytes)
                if done:
                    ev = self._handshake_events.get(source_id)
                    if ev:
                        ev.set()
                    logger.info("E2E TLS 1.3 handshake completed with peer [%s]", source_id)
            except FingerprintMismatchError as fe:
                logger.error("Fingerprint mismatch with peer [%s]: %s", source_id, fe)
                self._tunnels.pop(source_id, None)
                return
            except Exception as e:
                logger.error("Error during inner TLS handshake with [%s]: %s", source_id, e)
                return

        # Decrypt any application data
        if tunnel.handshake_done:
            decrypted = tunnel.decrypt_application_data()
            if decrypted:
                if decrypted.startswith(MEDIA_FRAME_MAGIC):
                    try:
                        rest = decrypted[len(MEDIA_FRAME_MAGIC):]
                        sep_idx = rest.find(b"\x00")
                        if sep_idx > 0:
                            meta = json.loads(rest[:sep_idx].decode("utf-8"))
                            jpeg_bytes = rest[sep_idx + 1:]
                            if (
                                isinstance(meta, dict)
                                and 0 < len(jpeg_bytes) <= MAX_RELAY_MEDIA_FRAME_BYTES
                                and self.media_frame_handler is not None
                            ):
                                asyncio.create_task(self.media_frame_handler(source_id, meta, jpeg_bytes))
                    except Exception as me:
                        logger.warning("Failed parsing encrypted screen frame from [%s]: %s", source_id, me)
                    return
                try:
                    msg_obj = SnowMessage.from_json(decrypted.decode("utf-8"))
                    queue = self._incoming_queues.setdefault(source_id, asyncio.Queue())
                    await queue.put(msg_obj)

                    if self.request_dispatcher and msg_obj.type == MessageType.REQUEST:
                        asyncio.create_task(self._dispatch_incoming_request(source_id, msg_obj))
                except Exception as de:
                    logger.warning("Failed parsing decrypted message from [%s]: %s", source_id, de)

    async def _dispatch_incoming_request(self, source_id: str, req: SnowMessage) -> None:
        """Asynchronously dispatch an incoming request and return the response."""
        if not self.request_dispatcher:
            return
        try:
            resp = await self.request_dispatcher(source_id, req)
            if isinstance(resp, SnowMessage):
                await self.send_message(source_id, resp)
        except Exception as exc:
            logger.warning("Error dispatching incoming relay request from [%s]: %s", source_id, exc)
