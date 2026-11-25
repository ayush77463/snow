"""PC-side reverse HTTP-over-WebSocket tunnel forwarder for the SNOW Relay /mcp proxy.

Supports both:
- Zero-setup Ed25519 hub challenge-response authentication (`network_key_identity` + `hub_http_url`)
  with periodic lease heartbeat renewal and coordinator failover awareness.
- Legacy HMAC `SNOW_RELAY_SECRET` ticket authentication (`ticket`).
"""

from __future__ import annotations

import asyncio
import base64
import logging
from typing import Any, Optional

import aiohttp

logger = logging.getLogger(__name__)

_HOP_BY_HOP_HEADERS = frozenset({
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
})


class RelayMcpForwarder:
    """Connects outbound to SnowRelayServer /v1/tunnel and forwards tunneled MCP HTTP requests to 127.0.0.1."""

    def __init__(
        self,
        relay_ws_url: str,
        snow_id: str,
        ticket: str = "",
        local_gateway_url: str = "http://127.0.0.1:8771",
        network_key_identity: Optional[Any] = None,
        hub_http_url: Optional[str] = None,
        device_id: str = "",
        priority: int = 100,
        heartbeat_interval_seconds: float = 20.0,
        lan_endpoints: Optional[list[str]] = None,
        device_name: str = "",
    ) -> None:
        self.relay_ws_url = relay_ws_url
        self.snow_id = snow_id.strip().upper()
        self.ticket = ticket
        self.local_gateway_url = local_gateway_url.rstrip("/")
        self.network_key_identity = network_key_identity
        self.hub_http_url = hub_http_url.rstrip("/") if hub_http_url else self._derive_http_url(relay_ws_url)
        self.device_id = device_id or self.snow_id
        self.priority = int(priority)
        self.heartbeat_interval_seconds = max(1.0, float(heartbeat_interval_seconds))
        self.lan_endpoints = list(lan_endpoints or [])
        self.device_name = device_name

        self._session: Optional[aiohttp.ClientSession] = None
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._loop_task: Optional[asyncio.Task[None]] = None
        self._heartbeat_task: Optional[asyncio.Task[None]] = None
        self._running = False
        self.is_connected = False
        self.hub_token: str = ""
        self.network_id: str = getattr(network_key_identity, "network_id", "") if network_key_identity else ""
        self.coordinator_epoch: int = 0
        self.is_primary: bool = False
        self.primary_device_id: Optional[str] = None

    @staticmethod
    def _derive_http_url(ws_url: str) -> str:
        clean = ws_url.strip()
        if clean.startswith("wss://"):
            http_url = "https://" + clean[len("wss://"):]
        elif clean.startswith("ws://"):
            http_url = "http://" + clean[len("ws://"):]
        else:
            http_url = clean
        if http_url.endswith("/v1/tunnel"):
            http_url = http_url[: -len("/v1/tunnel")]
        return http_url.rstrip("/")

    async def _authenticate_with_hub(self, timeout: float) -> tuple[bool, str, str]:
        """Run stateless Ed25519 challenge-response against POST /v1/hub/challenge & /v1/hub/session."""
        assert self._session is not None
        assert self.network_key_identity is not None
        net_id = self.network_key_identity.network_id
        pub_b64 = self.network_key_identity.public_key_b64

        async with self._session.post(
            f"{self.hub_http_url}/v1/hub/challenge",
            json={
                "network_id": net_id,
                "public_key": pub_b64,
                "device_id": self.device_id,
                "snow_id": self.snow_id,
            },
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as ch_resp:
            ch_data = await ch_resp.json(content_type=None)
            if ch_resp.status != 200 or not ch_data.get("success"):
                return False, "", ch_data.get("error", f"Hub challenge rejected (HTTP {ch_resp.status}).")

        sig_b64 = self.network_key_identity.sign_hub_challenge(ch_data, device_id=self.device_id)
        async with self._session.post(
            f"{self.hub_http_url}/v1/hub/session",
            json={
                "challenge_id": ch_data["challenge_id"],
                "network_id": net_id,
                "public_key": pub_b64,
                "signature": sig_b64,
                "device_id": self.device_id,
                "snow_id": self.snow_id,
            },
            timeout=aiohttp.ClientTimeout(total=timeout),
        ) as sess_resp:
            sess_data = await sess_resp.json(content_type=None)
            if sess_resp.status != 200 or not sess_data.get("success") or not sess_data.get("token"):
                return False, "", sess_data.get("error", f"Hub session rejected (HTTP {sess_resp.status}).")
            return True, str(sess_data["token"]), ""

    async def start(self, timeout: float = 10.0) -> tuple[bool, str]:
        """Connect to the relay WebSocket and complete hello registration."""
        if self.is_connected:
            return True, ""

        self._session = aiohttp.ClientSession()
        try:
            hello_payload: dict[str, Any] = {
                "type": "hello",
                "snow_id": self.snow_id,
                "mcp_tunnel": True,
                "priority": self.priority,
                "lan_endpoints": self.lan_endpoints,
                "device_name": self.device_name,
            }
            if self.network_key_identity is not None and not self.ticket:
                ok_hub, token, err_hub = await self._authenticate_with_hub(timeout)
                if not ok_hub:
                    await self.stop()
                    return False, err_hub
                self.hub_token = token
                hello_payload["hub_token"] = token
                hello_payload["network_id"] = self.network_key_identity.network_id
                hello_payload["device_id"] = self.device_id
            else:
                hello_payload["ticket"] = self.ticket

            self._ws = await asyncio.wait_for(
                self._session.ws_connect(self.relay_ws_url, heartbeat=25.0),
                timeout=timeout,
            )
            await self._ws.send_json(hello_payload)
            ack = await asyncio.wait_for(self._ws.receive_json(), timeout=timeout)
            if not isinstance(ack, dict) or ack.get("type") != "hello_ack" or not ack.get("success"):
                await self.stop()
                return False, str(ack.get("message") if isinstance(ack, dict) else "") or "Relay server rejected MCP reverse tunnel handshake."

            self.network_id = str(ack.get("network_id") or self.network_id or "")
            self.coordinator_epoch = int(ack.get("epoch", 0) or 0)
            self.primary_device_id = ack.get("primary_device_id")
            self.is_primary = bool(ack.get("is_primary", True))
            self._running = True
            self.is_connected = True
            self._loop_task = asyncio.create_task(self._serve_loop(), name="snow_relay_mcp_forwarder")
            self._heartbeat_task = asyncio.create_task(self._heartbeat_loop(), name="snow_relay_mcp_heartbeat")
            return True, ""
        except Exception as exc:
            await self.stop()
            return False, f"Failed connecting to relay: {exc}"

    async def stop(self) -> None:
        """Close the reverse tunnel cleanly with deregistration."""
        self._running = False
        self.is_connected = False
        for task in (self._heartbeat_task, self._loop_task):
            if task and not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):
                    pass
        self._heartbeat_task = None
        self._loop_task = None
        if self._ws and not self._ws.closed:
            try:
                await self._ws.send_json({"type": "deregister", "epoch": self.coordinator_epoch})
            except Exception:
                pass
            try:
                await self._ws.close()
            except Exception:
                pass
        self._ws = None
        if self._session and not self._session.closed:
            try:
                await self._session.close()
            except Exception:
                pass
        self._session = None

    async def _heartbeat_loop(self) -> None:
        try:
            while self._running and self._ws is not None and not self._ws.closed:
                await asyncio.sleep(self.heartbeat_interval_seconds)
                if not self._running or self._ws is None or self._ws.closed:
                    break
                await self._ws.send_json({
                    "type": "heartbeat",
                    "epoch": self.coordinator_epoch,
                })
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("RelayMcpForwarder heartbeat ended: %s", exc)

    async def _serve_loop(self) -> None:
        assert self._ws is not None
        try:
            async for msg in self._ws:
                if not self._running:
                    break
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                try:
                    data = msg.json()
                except Exception:
                    continue
                mtype = data.get("type")
                if mtype == "mcp_http_request":
                    asyncio.create_task(self._forward_single_request(data))
                elif mtype == "coordinator_update":
                    self.coordinator_epoch = int(data.get("epoch", self.coordinator_epoch) or 0)
                    self.primary_device_id = data.get("primary_device_id")
                    self.is_primary = bool(
                        self.primary_device_id and self.primary_device_id == self.device_id
                    )
                elif mtype == "coordinator_fenced":
                    self.coordinator_epoch = int(data.get("epoch", self.coordinator_epoch) or 0)
                    self.is_primary = False
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("RelayMcpForwarder loop ended: %s", exc)
        finally:
            self.is_connected = False
            self.is_primary = False

    async def _forward_single_request(self, payload: dict[str, Any]) -> None:
        req_id = payload.get("request_id")
        if not req_id or self._ws is None or self._ws.closed or self._session is None:
            return
        method = str(payload.get("method", "GET")).upper()
        path = str(payload.get("path", "/mcp"))
        if not path.startswith("/"):
            path = f"/{path}"
        query = str(payload.get("query", "")).lstrip("?")
        target_url = f"{self.local_gateway_url}{path}" + (f"?{query}" if query else "")

        raw_headers = payload.get("headers") or {}
        fwd_headers = {
            str(k): str(v)
            for k, v in raw_headers.items()
            if str(k).lower() not in _HOP_BY_HOP_HEADERS and str(k).lower() != "host"
        }
        body_b64 = payload.get("body_b64") or ""
        req_body = base64.b64decode(body_b64) if body_b64 else None

        try:
            async with self._session.request(
                method,
                target_url,
                headers=fwd_headers,
                data=req_body,
                timeout=aiohttp.ClientTimeout(total=25.0),
            ) as resp:
                resp_bytes = await resp.read()
                resp_headers = {
                    k: v
                    for k, v in resp.headers.items()
                    if k.lower() not in _HOP_BY_HOP_HEADERS
                }
                if not self._ws.closed:
                    await self._ws.send_json({
                        "type": "mcp_http_response",
                        "request_id": req_id,
                        "status": resp.status,
                        "headers": resp_headers,
                        "body_b64": base64.b64encode(resp_bytes).decode("ascii"),
                    })
        except Exception as exc:
            if self._ws and not self._ws.closed:
                await self._ws.send_json({
                    "type": "mcp_http_response",
                    "request_id": req_id,
                    "status": 502,
                    "headers": {"Content-Type": "application/json"},
                    "body_b64": base64.b64encode(
                        f'{{"error":"Local gateway forward error: {exc}"}}'.encode("utf-8")
                    ).decode("ascii"),
                })
