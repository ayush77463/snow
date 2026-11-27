"""Windows-to-Windows peer mesh client for SNOW.

Allows a SNOW Desktop instance to federate with other SNOW Desktop instances on the LAN,
supporting secure TLS with TOFU certificate fingerprint pinning, PIN-based pairing,
token-based session authentication, and remote capability execution.
"""

import asyncio
from dataclasses import dataclass
import hashlib
import json
import logging
import ssl
from typing import Any, Dict, Optional

import websockets
from websockets.asyncio.client import ClientConnection, connect as ws_connect

from snow.protocol.constants import ErrorCode, MessageType
from snow.protocol.models import SnowMessage
from snow.protocol.validator import validate_raw_message
from snow.security.identity import DeviceIdentity, load_or_create_device_identity
from snow.network.node import CapabilityManifest, build_windows_manifest

logger = logging.getLogger(__name__)


@dataclass
class PeerConnectionResult:
    """Outcome of a peer connection and handshake attempt."""

    success: bool
    status: str
    remote_device_id: Optional[str] = None
    remote_device_name: Optional[str] = None
    session_id: Optional[str] = None
    auth_token: Optional[str] = None
    cert_fingerprint: Optional[str] = None
    manifest: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    network_id: Optional[str] = None
    network_action: Optional[str] = None
    network_conflict: bool = False
    relationship: str = "member"
    merge_tx_id: Optional[str] = None
    host_network_id: Optional[str] = None
    client_network_id: Optional[str] = None


class SnowPeerClient:
    """Async WebSocket client for connecting to a remote SNOW peer instance."""

    def __init__(
        self,
        host: str,
        port: int = 8765,
        identity: Optional[DeviceIdentity] = None,
        expected_fingerprint: Optional[str] = None,
        use_tls: bool = True,
    ) -> None:
        self.host = host
        self.port = port
        self.identity = identity or load_or_create_device_identity()
        self.expected_fingerprint = (
            expected_fingerprint.replace(":", "").replace(" ", "").strip().lower()
            if expected_fingerprint
            else None
        )
        self.use_tls = use_tls

        self._ws: Optional[ClientConnection] = None
        self._receive_task: Optional[asyncio.Task] = None
        self._pending_requests: Dict[str, asyncio.Future[SnowMessage]] = {}
        self._connected_fingerprint: Optional[str] = None
        self._session_id: Optional[str] = None
        self._auth_token: Optional[str] = None
        self._remote_device_id: Optional[str] = None
        self._remote_device_name: Optional[str] = None
        self._remote_manifest: Optional[CapabilityManifest] = None
        self._is_connected = False

    @property
    def is_connected(self) -> bool:
        return self._is_connected and self._ws is not None

    @property
    def session_id(self) -> Optional[str]:
        return self._session_id

    @property
    def auth_token(self) -> Optional[str]:
        return self._auth_token

    @property
    def remote_device_id(self) -> Optional[str]:
        return self._remote_device_id

    @property
    def remote_device_name(self) -> Optional[str]:
        return self._remote_device_name

    @property
    def remote_manifest(self) -> Optional[CapabilityManifest]:
        return self._remote_manifest

    @property
    def connected_fingerprint(self) -> Optional[str]:
        return self._connected_fingerprint

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context for TOFU certificate pinning."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def connect(
        self,
        pin: str = "",
        auth_token: str = "",
        timeout: float = 10.0,
        handshake_token: str = "",
        network_id: Optional[str] = None,
        client_network_id: Optional[str] = None,
        network_decision: Optional[str] = None,
        merge_tx_id: Optional[str] = None,
        client_merge_approved: bool = False,
        surviving_network_id: Optional[str] = None,
    ) -> PeerConnectionResult:
        """Establish WebSocket connection, verify TLS certificate, and authenticate/pair."""
        scheme = "wss" if self.use_tls else "ws"
        uri = f"{scheme}://{self.host}:{self.port}"
        ssl_ctx = self._create_ssl_context() if self.use_tls else None

        try:
            conn = await asyncio.wait_for(
                ws_connect(uri, ssl=ssl_ctx, max_size=65536),
                timeout=timeout,
            )
            self._ws = conn
            self._is_connected = True
        except Exception as exc:
            logger.warning("Failed connecting to peer %s: %s", uri, exc)
            return PeerConnectionResult(
                success=False,
                status="CONNECTION_FAILED",
                error=f"Could not connect to peer at {uri}: {exc}",
            )

        # Inspect certificate fingerprint if TLS is active
        if self.use_tls:
            try:
                transport = conn.transport
                raw_sock = transport.get_extra_info("ssl_object") or transport.get_extra_info("socket")
                der_cert = None
                if raw_sock and hasattr(raw_sock, "getpeercert"):
                    der_cert = raw_sock.getpeercert(binary_form=True)

                if der_cert:
                    fp = hashlib.sha256(der_cert).hexdigest().lower()
                    self._connected_fingerprint = fp
                    if self.expected_fingerprint and self.expected_fingerprint != fp:
                        await self.close()
                        return PeerConnectionResult(
                            success=False,
                            status="FINGERPRINT_MISMATCH",
                            cert_fingerprint=fp,
                            error=f"Peer certificate fingerprint mismatch! Expected: {self.expected_fingerprint}, Presented: {fp}",
                        )
            except Exception as cert_err:
                logger.debug("Failed checking peer certificate fingerprint: %s", cert_err)

        # Start background receiver task
        self._receive_task = asyncio.create_task(self._receive_loop())

        # Perform authentication or pairing handshake
        try:
            if pin or handshake_token:
                pair_payload: dict[str, Any] = {
                    "device_id": self.identity.device_id,
                    "device_name": self.identity.device_name,
                    "platform": "windows",
                    "device_type": "windows",
                    "manifest": build_windows_manifest().to_dict(),
                }
                if handshake_token:
                    pair_payload["handshake_token"] = handshake_token.strip()
                    if network_id:
                        pair_payload["network_id"] = str(network_id).strip().upper()
                else:
                    pair_payload["pin"] = pin.strip()
                if client_network_id:
                    pair_payload["client_network_id"] = str(client_network_id).strip().upper()
                if network_decision:
                    pair_payload["network_decision"] = str(network_decision).strip().lower()
                if merge_tx_id:
                    pair_payload["merge_tx_id"] = str(merge_tx_id).strip()
                if client_merge_approved:
                    pair_payload["client_merge_approved"] = True
                if surviving_network_id:
                    pair_payload["surviving_network_id"] = str(surviving_network_id).strip().upper()

                pair_req = SnowMessage.create_request(
                    action="pair_request",
                    data=pair_payload,
                )
                response = await self.send_message(pair_req, timeout=timeout)
                if response.type == MessageType.ERROR:
                    err_msg = response.error.get("message") if isinstance(response.error, dict) else "Pairing failed"
                    await self.close()
                    return PeerConnectionResult(
                        success=False,
                        status="PAIRING_REJECTED",
                        error=err_msg,
                    )

                data = response.payload.get("data", {}) if response.payload else {}
                self._auth_token = data.get("auth_token")
                self._session_id = data.get("session_id")
                self._remote_device_id = data.get("device_id")
                self._remote_device_name = data.get("device_name")
                raw_manifest = data.get("manifest")
                if raw_manifest and isinstance(raw_manifest, dict):
                    try:
                        self._remote_manifest = CapabilityManifest.from_dict(raw_manifest)
                    except Exception as m_err:
                        logger.debug("Failed parsing remote manifest: %s", m_err)

                return PeerConnectionResult(
                    success=True,
                    status="PAIRED",
                    remote_device_id=self._remote_device_id,
                    remote_device_name=self._remote_device_name,
                    session_id=self._session_id,
                    auth_token=self._auth_token,
                    cert_fingerprint=self._connected_fingerprint,
                    manifest=raw_manifest if isinstance(raw_manifest, dict) else None,
                    network_id=data.get("network_id"),
                    network_action=data.get("network_action"),
                    network_conflict=bool(data.get("network_conflict", False)),
                    relationship=str(data.get("relationship") or "member"),
                    merge_tx_id=data.get("merge_tx_id"),
                    host_network_id=data.get("host_network_id"),
                    client_network_id=data.get("client_network_id"),
                )

            elif auth_token:
                auth_req = SnowMessage.create_request(
                    action="auth_request",
                    data={
                        "device_id": self.identity.device_id,
                        "auth_token": auth_token.strip(),
                        "manifest": build_windows_manifest().to_dict(),
                    },
                )
                response = await self.send_message(auth_req, timeout=timeout)
                if response.type == MessageType.ERROR:
                    err_msg = response.error.get("message") if isinstance(response.error, dict) else "Auth failed"
                    await self.close()
                    return PeerConnectionResult(
                        success=False,
                        status="AUTH_REJECTED",
                        error=err_msg,
                    )

                data = response.payload.get("data", {}) if response.payload else {}
                self._session_id = data.get("session_id")
                self._auth_token = auth_token
                raw_manifest = data.get("manifest")
                if raw_manifest and isinstance(raw_manifest, dict):
                    try:
                        self._remote_manifest = CapabilityManifest.from_dict(raw_manifest)
                    except Exception as m_err:
                        logger.debug("Failed parsing remote manifest: %s", m_err)

                return PeerConnectionResult(
                    success=True,
                    status="AUTHENTICATED",
                    remote_device_id=data.get("device_id"),
                    session_id=self._session_id,
                    auth_token=self._auth_token,
                    cert_fingerprint=self._connected_fingerprint,
                    manifest=raw_manifest if isinstance(raw_manifest, dict) else None,
                )

            else:
                # Connected without authentication (can only send ping or start pairing)
                return PeerConnectionResult(
                    success=True,
                    status="CONNECTED_UNAUTHENTICATED",
                    cert_fingerprint=self._connected_fingerprint,
                )

        except Exception as exc:
            await self.close()
            return PeerConnectionResult(
                success=False,
                status="HANDSHAKE_ERROR",
                error=f"Handshake error with peer: {exc}",
            )

    async def _receive_loop(self) -> None:
        """Background loop reading frames from peer WebSocket."""
        try:
            assert self._ws is not None
            async for raw in self._ws:
                try:
                    msg = validate_raw_message(raw)
                except Exception as exc:
                    logger.debug("Failed validating incoming message from peer: %s", exc)
                    continue

                if msg.type in (MessageType.RESPONSE, MessageType.ERROR):
                    corr_id = msg.correlation_id
                    if corr_id and corr_id in self._pending_requests:
                        fut = self._pending_requests[corr_id]
                        if not fut.done():
                            fut.set_result(msg)
                elif msg.type == MessageType.HEARTBEAT:
                    ack = SnowMessage.create_heartbeat_ack(correlation_id=msg.id)
                    await self._ws.send(ack.to_json())
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("Peer connection receive loop terminated: %s", exc)
        finally:
            self._is_connected = False
            # Cancel any pending futures
            for fut in list(self._pending_requests.values()):
                if not fut.done():
                    fut.set_exception(ConnectionResetError("Peer connection closed"))
            self._pending_requests.clear()

    async def send_message(self, message: SnowMessage, timeout: float = 30.0) -> SnowMessage:
        """Send a SnowMessage to peer and await correlated response."""
        if not self.is_connected or not self._ws:
            raise ConnectionError("Peer client is not connected.")

        loop = asyncio.get_running_loop()
        future: asyncio.Future[SnowMessage] = loop.create_future()
        self._pending_requests[message.id] = future

        try:
            await self._ws.send(message.to_json())
            return await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._pending_requests.pop(message.id, None)

    async def execute_remote_action(
        self,
        action: str,
        data: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0,
    ) -> Dict[str, Any]:
        """Execute a capability request on the remote peer and return structured response."""
        req = SnowMessage.create_request(action=action, data=data or {})
        try:
            resp = await self.send_message(req, timeout=timeout)
            is_ok = resp.type == MessageType.RESPONSE and (
                resp.payload is None or resp.payload.get("status") != "error"
            )
            err_msg = None
            if resp.error:
                err_msg = resp.error.get("message") if isinstance(resp.error, dict) else str(resp.error)
            elif not is_ok and resp.payload:
                err_msg = resp.payload.get("message") or resp.payload.get("error")

            return {
                "success": is_ok,
                "status": "SUCCESS" if is_ok else "PEER_ERROR",
                "data": resp.payload.get("data") if resp.payload else resp.payload,
                "error": err_msg,
            }
        except TimeoutError:
            return {
                "success": False,
                "status": "REQUEST_TIMEOUT",
                "error": f"Remote peer action '{action}' timed out after {timeout:.1f}s",
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "PEER_COMMUNICATION_ERROR",
                "error": str(exc),
            }

    async def close(self) -> None:
        """Cleanly close peer connection and cancel receive loop."""
        self._is_connected = False
        if self._receive_task and not self._receive_task.done():
            self._receive_task.cancel()
            try:
                await self._receive_task
            except asyncio.CancelledError:
                pass
            self._receive_task = None

        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None

        logger.debug("Closed connection to peer %s:%d", self.host, self.port)

    @classmethod
    async def connect_from_qr(
        cls,
        qr_payload: dict[str, Any] | str,
        local_identity: Optional[DeviceIdentity] = None,
        client_network_id: Optional[str] = None,
        timeout: float = 10.0,
        allow_usb_loopback: bool = False,
        use_tls: bool = True,
    ) -> tuple[Optional["SnowPeerClient"], PeerConnectionResult]:
        """Validate QR v1/v2 payload and connect sequentially across ranked candidate IPs."""
        from snow.security.pairing import validate_qr_pairing_payload

        try:
            validated = validate_qr_pairing_payload(
                qr_payload, allow_usb_loopback=allow_usb_loopback
            )
        except Exception as exc:
            return None, PeerConnectionResult(
                success=False, status="INVALID_QR", error=str(exc)
            )

        candidate_ips: list[str] = list(validated.get("ips") or [])
        port = int(validated["port"])
        fp = str(validated["fp"])
        htok = str(validated.get("handshake_token") or "")
        pin = str(validated.get("pin") or "")
        net_id = validated.get("network_id")

        last_result: Optional[PeerConnectionResult] = None
        for cand_ip in candidate_ips:
            client = cls(
                host=cand_ip,
                port=port,
                identity=local_identity,
                expected_fingerprint=fp,
                use_tls=use_tls,
            )
            res = await client.connect(
                pin="" if htok else pin,
                handshake_token=htok,
                network_id=net_id,
                client_network_id=client_network_id,
                timeout=timeout,
            )
            if res.success:
                return client, res
            last_result = res
            await client.close()
            if res.status in ("FINGERPRINT_MISMATCH", "PAIRING_REJECTED"):
                return None, res

        return None, last_result or PeerConnectionResult(
            success=False,
            status="NO_REACHABLE_CANDIDATES",
            error="No reachable candidate IPs succeeded in QR onboarding.",
        )
