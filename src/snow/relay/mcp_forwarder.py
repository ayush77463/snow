"""PC-side reverse HTTP-over-WebSocket tunnel forwarder for the SNOW Relay /mcp proxy."""

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
        ticket: str,
        local_gateway_url: str = "http://127.0.0.1:8771",
    ) -> None:
        self.relay_ws_url = relay_ws_url
        self.snow_id = snow_id.strip().upper()
        self.ticket = ticket
        self.local_gateway_url = local_gateway_url.rstrip("/")

        self._session: Optional[aiohttp.ClientSession] = None
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._loop_task: Optional[asyncio.Task[None]] = None
        self._running = False
        self.is_connected = False

    async def start(self, timeout: float = 10.0) -> tuple[bool, str]:
        """Connect to the relay WebSocket and complete hello registration."""
        if self.is_connected:
            return True, ""

        self._session = aiohttp.ClientSession()
        try:
            self._ws = await asyncio.wait_for(
                self._session.ws_connect(self.relay_ws_url, heartbeat=25.0),
                timeout=timeout,
            )
            await self._ws.send_json({
                "type": "hello",
                "ticket": self.ticket,
                "snow_id": self.snow_id,
                "mcp_tunnel": True,
            })
            ack = await asyncio.wait_for(self._ws.receive_json(), timeout=timeout)
            if not isinstance(ack, dict) or ack.get("type") != "hello_ack" or not ack.get("success"):
                await self.stop()
                return False, "Relay server rejected MCP reverse tunnel handshake."
            self._running = True
            self.is_connected = True
            self._loop_task = asyncio.create_task(self._serve_loop(), name="snow_relay_mcp_forwarder")
            return True, ""
        except Exception as exc:
            await self.stop()
            return False, f"Failed connecting to relay: {exc}"

    async def stop(self) -> None:
        """Close the reverse tunnel cleanly."""
        self._running = False
        self.is_connected = False
        if self._loop_task and not self._loop_task.done():
            self._loop_task.cancel()
            try:
                await self._loop_task
            except (asyncio.CancelledError, Exception):
                pass
        self._loop_task = None
        if self._ws and not self._ws.closed:
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
                if data.get("type") == "mcp_http_request":
                    asyncio.create_task(self._forward_single_request(data))
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("RelayMcpForwarder loop ended: %s", exc)
        finally:
            self.is_connected = False

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
