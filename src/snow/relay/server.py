"""Payload-blind asynchronous WebSocket Relay Server for SNOW V3."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import ssl
from typing import Any, Dict, Optional, Set

from aiohttp import web, WSMsgType

from snow.relay.auth import create_relay_ticket, verify_relay_ticket
from snow.relay.config import RelayConfig
from snow.relay.quotas import QuotaManager
from snow.relay.rendezvous import (
    RendezvousRegistry,
    STATE_DORMANT_RELAY,
    STATE_OFFLINE,
    STATE_ONLINE_RELAY,
)

logger = logging.getLogger(__name__)


class SnowRelayServer:
    """Self-hostable, payload-blind relay server routing opaque end-to-end TLS tunnels."""

    def __init__(self, config: Optional[RelayConfig] = None) -> None:
        self.config = config or RelayConfig.from_env()
        self.registry = RendezvousRegistry(
            presence_stale_seconds=self.config.presence_stale_seconds,
            dormant_timeout_seconds=self.config.dormant_timeout_seconds,
            max_connections_per_group=self.config.max_connections_per_group,
        )
        self.quotas = QuotaManager(
            max_frame_size=self.config.max_frame_size,
            max_transfer_quota_bytes=self.config.max_transfer_quota_bytes,
            rate_limit_messages_per_sec=self.config.rate_limit_messages_per_sec,
        )

        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._is_running: bool = False
        self._sweep_task: Optional[asyncio.Task] = None
        self._active_sockets: Set[web.WebSocketResponse] = set()

    def _build_app(self) -> web.Application:
        app = web.Application(client_max_size=self.config.max_frame_size + 1024)
        app.router.add_get("/v1/tunnel", self.handle_tunnel_ws)
        app.router.add_get("/v1/presence", self.handle_get_presence)
        app.router.add_post("/v1/auth/ticket", self.handle_post_ticket)
        app.router.add_post("/v1/revoke", self.handle_post_revoke)
        app.router.add_get("/health", self.handle_health)
        return app

    async def handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({
            "status": "healthy",
            "service": "snow-relay",
            "version": "1.0.0",
            "online_devices": len(self.registry._devices),
        })

    async def handle_post_ticket(self, request: web.Request) -> web.Response:
        """Control plane: generate an authentication ticket (requires relay shared_secret)."""
        if not self.config.shared_secret:
            return web.json_response({"success": False, "error": "Relay shared_secret not configured."}, status=500)

        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        auth_header = request.headers.get("Authorization", "")
        expected = f"Bearer {self.config.shared_secret}"
        if auth_header != expected:
            return web.json_response({"success": False, "error": "Unauthorized control plane access."}, status=401)

        device_id = body.get("device_id")
        group_id = body.get("group_id")
        ttl = int(body.get("ttl_seconds", 3600))
        if not device_id or not group_id:
            return web.json_response({"success": False, "error": "Missing device_id or group_id."}, status=400)

        ticket = create_relay_ticket(device_id=device_id, group_id=group_id, secret=self.config.shared_secret, ttl_seconds=ttl)
        return web.json_response({"success": True, "ticket": ticket, "expires_in": ttl})

    async def handle_get_presence(self, request: web.Request) -> web.Response:
        """Control plane: query presence of a device or destination group."""
        group_id = request.query.get("group_id")
        device_id = request.query.get("device_id")

        if device_id:
            pres = self.registry.get_presence(device_id)
            return web.json_response({"success": True, "presence": pres})
        elif group_id:
            peers = self.registry.list_group_peers(group_id)
            return web.json_response({"success": True, "group_id": group_id, "peers": peers})
        else:
            return web.json_response({"success": False, "error": "Specify device_id or group_id parameter."}, status=400)

    async def handle_post_revoke(self, request: web.Request) -> web.Response:
        """Control plane: revoke a device and immediately terminate active relay sessions."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        auth_header = request.headers.get("Authorization", "")
        expected = f"Bearer {self.config.shared_secret}"
        if auth_header != expected:
            return web.json_response({"success": False, "error": "Unauthorized control plane access."}, status=401)

        device_id = body.get("device_id")
        if not device_id:
            return web.json_response({"success": False, "error": "Missing device_id."}, status=400)

        ws = self.registry.revoke_device(device_id)
        self.quotas.clear_device(device_id)
        if ws and not ws.closed:
            await ws.close(code=4003, message=b"Device revoked from relay.")

        return web.json_response({"success": True, "device_id": device_id, "revoked": True})

    async def handle_tunnel_ws(self, request: web.Request) -> web.WebSocketResponse:
        """Data plane: Bidirectional payload-blind tunnel session handler."""
        ws = web.WebSocketResponse(
            max_msg_size=self.config.max_frame_size + 1024,
            heartbeat=30.0,
        )
        await ws.prepare(request)
        self._active_sockets.add(ws)

        device_id: Optional[str] = None
        group_id: Optional[str] = None

        try:
            # 1. Initial Handshake Hello message
            try:
                hello_msg = await asyncio.wait_for(ws.receive(), timeout=10.0)
            except asyncio.TimeoutError:
                await ws.close(code=4001, message=b"Authentication handshake timeout.")
                return ws

            if hello_msg.type != WSMsgType.TEXT:
                await ws.close(code=4002, message=b"Expected JSON hello frame.")
                return ws

            try:
                hello_data = json.loads(hello_msg.data)
            except Exception:
                await ws.close(code=4002, message=b"Malformed JSON in hello frame.")
                return ws

            if hello_data.get("type") != "hello":
                await ws.close(code=4002, message=b"Invalid initial frame type.")
                return ws

            ticket = hello_data.get("ticket", "")
            is_valid, claimed_dev, claimed_grp, err_msg = verify_relay_ticket(ticket, self.config.shared_secret)
            if not is_valid or not claimed_dev or not claimed_grp:
                err_bytes = f"Auth failed: {err_msg}".encode("utf-8")
                await ws.close(code=4001, message=err_bytes)
                return ws

            device_id = claimed_dev
            group_id = claimed_grp

            reg_ok, reg_err = self.registry.register(device_id, group_id, ws)
            if not reg_ok:
                await ws.close(code=4003, message=reg_err.encode("utf-8"))
                return ws

            # Send hello ack
            await ws.send_json({
                "type": "hello_ack",
                "success": True,
                "device_id": device_id,
                "group_id": group_id,
                "max_frame_size": self.config.max_frame_size,
            })

            # 2. Main data plane forwarding loop
            async for msg in ws:
                self.registry.update_last_seen(device_id)

                # Rate limit check
                rate_ok, rate_err = self.quotas.check_rate_limit(device_id)
                if not rate_ok:
                    await ws.send_json({"type": "relay_error", "error_code": "RATE_LIMIT_EXCEEDED", "message": rate_err})
                    continue

                if msg.type == WSMsgType.TEXT:
                    # JSON formatted relay frame
                    try:
                        data = json.loads(msg.data)
                    except Exception:
                        continue

                    mtype = data.get("type")
                    if mtype == "ping":
                        await ws.send_json({"type": "pong", "time": data.get("time")})
                        continue

                    if mtype == "relay_frame":
                        target_id = data.get("target")
                        payload_b64 = data.get("payload_b64", "")
                        payload_bytes = base64.b64decode(payload_b64)

                        frame_size = len(payload_bytes)
                        # Size limit check
                        size_ok, size_err = self.quotas.check_frame_size(frame_size)
                        if not size_ok:
                            await ws.send_json({"type": "relay_error", "error_code": "FRAME_TOO_LARGE", "message": size_err})
                            continue

                        # Quota check
                        q_ok, q_err = self.quotas.check_and_record_transfer(device_id, frame_size)
                        if not q_ok:
                            await ws.send_json({"type": "relay_error", "error_code": "QUOTA_EXCEEDED", "message": q_err})
                            continue

                        # Lookup target session
                        target_ws, route_err = self.registry.get_peer_session(device_id, target_id)
                        if not target_ws or target_ws.closed:
                            await ws.send_json({
                                "type": "relay_error",
                                "error_code": "DEVICE_UNREACHABLE",
                                "target": target_id,
                                "message": route_err or f"Destination device '{target_id}' unreachable.",
                            })
                            continue

                        # Forward exact payload to target (opaque)
                        await target_ws.send_json({
                            "type": "relay_frame",
                            "source": device_id,
                            "payload_b64": payload_b64,
                        })

                elif msg.type == WSMsgType.BINARY:
                    # Binary format: target_len (1 byte) + target_id (ascii bytes) + opaque payload
                    raw_bytes = msg.data
                    frame_size = len(raw_bytes)
                    size_ok, size_err = self.quotas.check_frame_size(frame_size)
                    if not size_ok:
                        await ws.send_json({"type": "relay_error", "error_code": "FRAME_TOO_LARGE", "message": size_err})
                        continue

                    if frame_size < 2:
                        continue

                    t_len = raw_bytes[0]
                    if frame_size < 1 + t_len:
                        continue

                    target_id = raw_bytes[1 : 1 + t_len].decode("ascii", errors="ignore")
                    payload = raw_bytes[1 + t_len :]

                    q_ok, q_err = self.quotas.check_and_record_transfer(device_id, len(payload))
                    if not q_ok:
                        await ws.send_json({"type": "relay_error", "error_code": "QUOTA_EXCEEDED", "message": q_err})
                        continue

                    target_ws, route_err = self.registry.get_peer_session(device_id, target_id)
                    if not target_ws or target_ws.closed:
                        await ws.send_json({
                            "type": "relay_error",
                            "error_code": "DEVICE_UNREACHABLE",
                            "target": target_id,
                            "message": route_err or f"Destination device '{target_id}' unreachable.",
                        })
                        continue

                    # Repack with source_id for recipient: src_len (1 byte) + src_id + payload
                    src_bytes = device_id.encode("ascii")
                    out_frame = bytes([len(src_bytes)]) + src_bytes + payload
                    await target_ws.send_bytes(out_frame)

                elif msg.type in (WSMsgType.CLOSE, WSMsgType.CLOSING, WSMsgType.CLOSED):
                    break

        finally:
            self._active_sockets.discard(ws)
            if device_id:
                self.registry.mark_dormant(device_id)

        return ws

    async def _sweep_loop(self) -> None:
        """Periodic background task sweeping stale or dead sessions."""
        try:
            while self._is_running:
                await asyncio.sleep(15.0)
                dead_sockets = self.registry.sweep_stale_sessions()
                for d_ws in dead_sockets:
                    if not d_ws.closed:
                        try:
                            await d_ws.close(code=4000, message=b"Session heartbeat expired.")
                        except Exception:
                            pass
        except asyncio.CancelledError:
            pass

    async def start(self) -> None:
        """Start listening on the configured host and port."""
        if self._is_running:
            return

        self._app = self._build_app()
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        ssl_ctx = None
        if self.config.tls_cert_path and self.config.tls_key_path:
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(certfile=self.config.tls_cert_path, keyfile=self.config.tls_key_path)

        self._site = web.TCPSite(self._runner, host=self.config.host, port=self.config.port, ssl_context=ssl_ctx)
        await self._site.start()
        self._is_running = True
        self._sweep_task = asyncio.create_task(self._sweep_loop())
        logger.info("SNOW Relay Server listening on %s:%d (TLS=%s)", self.config.host, self.config.port, bool(ssl_ctx))

    async def stop(self) -> None:
        """Gracefully terminate relay server and all active tunnels."""
        if not self._is_running:
            return
        self._is_running = False

        if self._sweep_task:
            self._sweep_task.cancel()
            try:
                await self._sweep_task
            except asyncio.CancelledError:
                pass

        # Close all active sockets
        for ws in list(self._active_sockets):
            if not ws.closed:
                try:
                    await ws.close(code=1001, message=b"Relay server shutting down.")
                except Exception:
                    pass
        self._active_sockets.clear()

        if self._runner:
            await self._runner.cleanup()
        logger.info("SNOW Relay Server stopped cleanly.")
