"""Payload-blind asynchronous WebSocket Relay Server for SNOW V3."""

from __future__ import annotations

import asyncio
import base64
from collections import deque
from dataclasses import dataclass, field
import hashlib
import json
import logging
import re
import secrets
import ssl
import time
from typing import Any, Dict, List, Optional, Set, Tuple
import urllib.parse
import uuid

from aiohttp import web, WSMsgType
import hmac

from snow.relay.auth import (
    canonical_device_hub_challenge_message,
    canonical_hub_challenge_message,
    create_relay_ticket,
    decode_ed25519_pubkey,
    derive_device_snow_id_from_pubkey,
    derive_network_id_from_pubkey,
    encode_ed25519_pubkey,
    extract_ticket_claims,
    is_valid_network_id,
    is_valid_snow_id,
    verify_ed25519_signature,
    verify_relay_ticket,
)
from snow.relay.config import RelayConfig
from snow.relay.quotas import QuotaManager
from snow.relay.rendezvous import (
    RendezvousRegistry,
    STATE_DORMANT_RELAY,
    STATE_OFFLINE,
    STATE_ONLINE_RELAY,
)

logger = logging.getLogger(__name__)

MAX_HUB_JSON_BYTES = 16 * 1024
MAX_RENDEZVOUS_TTL_SECONDS = 120.0
MAX_RENDEZVOUS_ENTRIES = 512
MAX_RENDEZVOUS_FAILED_ATTEMPTS = 5
_ALLOWED_MCP_SUBPATH_PREFIXES = ("mcp/", "oauth/", ".well-known/")
_ALLOWED_MCP_SUBPATHS_EXACT = frozenset({
    "mcp",
    "oauth",
    "snow_logo.png",
    "favicon.ico",
    "icon.png",
    "apple-touch-icon.png",
})


class _BoundedIpRateLimiter:
    """Bounded per-IP sliding window rate limiter for hub authentication endpoints."""

    def __init__(self, max_requests: int = 30, window_seconds: float = 60.0, max_ips: int = 2048) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.max_ips = max_ips
        self._hits: Dict[str, deque[float]] = {}

    def check(self, ip: str) -> Tuple[bool, int]:
        now = time.time()
        key = ip or "unknown"
        if key not in self._hits:
            if len(self._hits) >= self.max_ips:
                expired = [k for k, q in self._hits.items() if not q or (now - q[-1]) >= self.window_seconds]
                for k in expired:
                    self._hits.pop(k, None)
                if len(self._hits) >= self.max_ips:
                    oldest_key = min(self._hits.keys(), key=lambda k: self._hits[k][0] if self._hits[k] else 0.0)
                    self._hits.pop(oldest_key, None)
            self._hits[key] = deque()
        q = self._hits[key]
        cutoff = now - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        if len(q) >= self.max_requests:
            retry_after = max(1, int(self.window_seconds - (now - q[0])))
            return False, retry_after
        q.append(now)
        return True, 0


@dataclass
class _NetworkHostEntry:
    """Live host registration bound to one authenticated Ed25519 network_id."""

    network_id: str
    device_id: str
    snow_id: str
    ws: Optional[web.WebSocketResponse]
    mcp_tunnel: bool
    priority: int
    connected_at: float
    last_heartbeat: float
    lease_expires_at: float
    lan_endpoints: List[str] = field(default_factory=list)
    device_name: str = ""
    cert_fingerprint: str = ""

    def is_online(self, now: Optional[float] = None) -> bool:
        t = now if now is not None else time.time()
        return (
            self.ws is not None
            and not self.ws.closed
            and t <= self.lease_expires_at
        )


@dataclass
class _NetworkCoordinatorState:
    """Per-network multi-PC coordinator state with monotonic epoch fencing."""

    network_id: str
    epoch: int = 0
    primary_device_id: Optional[str] = None
    hosts: Dict[str, _NetworkHostEntry] = field(default_factory=dict)

    def elect_primary(self, now: Optional[float] = None) -> Tuple[Optional[str], bool]:
        """Deterministically elect primary host among active hosts. Returns (primary_id, changed)."""
        t = now if now is not None else time.time()
        active = [h for h in self.hosts.values() if h.is_online(t)]
        if not active:
            changed = self.primary_device_id is not None
            self.primary_device_id = None
            if changed:
                self.epoch += 1
            return None, changed

        # Keep current primary if still online AND strictly highest priority (sticky unless higher priority preempts)
        active.sort(key=lambda h: (-h.priority, h.connected_at, h.device_id))
        winner = active[0].device_id
        changed = winner != self.primary_device_id
        if changed:
            self.primary_device_id = winner
            self.epoch += 1
        return winner, changed


def _sanitize_forwarded_subpath(
    raw_subpath: Optional[str],
    raw_request_path: Optional[str] = None,
) -> Tuple[bool, str]:
    """Validate and normalize forwarded subpaths under /u/{id}/ to prevent traversal & double-decoding."""
    if raw_request_path:
        raw_path_only = raw_request_path.split("?", 1)[0]
        raw_lower = raw_path_only.lower()
        if (
            ".." in raw_path_only
            or "\\" in raw_path_only
            or "%25" in raw_lower
            or "%2e" in raw_lower
            or "%2f" in raw_lower
            or "%5c" in raw_lower
            or "%00" in raw_lower
            or "\x00" in raw_path_only
        ):
            return False, ""

    if raw_subpath is None:
        return True, "/mcp"
    decoded = urllib.parse.unquote(raw_subpath)
    twice_decoded = urllib.parse.unquote(decoded)
    if decoded != twice_decoded and "%" in raw_subpath:
        return False, ""
    if (
        ".." in raw_subpath
        or ".." in decoded
        or ".." in twice_decoded
        or "\\" in raw_subpath
        or "\\" in decoded
        or "\x00" in decoded
        or "?" in decoded
        or "#" in decoded
        or "://" in decoded
        or any(ord(c) < 32 for c in decoded)
    ):
        return False, ""
    clean = raw_subpath.lstrip("/")
    if not clean:
        return True, "/mcp"
    if "//" in clean or clean.startswith("/"):
        return False, ""
    lower = clean.lower()
    if lower in _ALLOWED_MCP_SUBPATHS_EXACT or any(lower.startswith(p) for p in _ALLOWED_MCP_SUBPATH_PREFIXES):
        return True, f"/{clean}"
    return False, ""


def _is_method_allowed_for_subpath(method: str, fwd_path: str) -> bool:
    m = method.upper().strip()
    lower = fwd_path.lower()
    if lower == "/mcp" or lower.startswith("/mcp/"):
        return m in ("GET", "POST", "DELETE", "OPTIONS")
    if lower == "/oauth" or lower.startswith("/oauth/"):
        return m in ("GET", "POST", "OPTIONS")
    if lower.startswith("/.well-known/"):
        return m in ("GET", "OPTIONS")
    if lower.lstrip("/") in _ALLOWED_MCP_SUBPATHS_EXACT:
        return m in ("GET", "HEAD", "OPTIONS")
    return False


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
        self._snow_routes: Dict[str, Dict[str, Any]] = {}
        self._device_snow_ids: Dict[str, str] = {}
        self._pending_http_forwards: Dict[str, tuple[str, asyncio.Future]] = {}

        # WS2 Stateless Hub state (in-memory only; Render Free Tier restarts reset ephemeral state cleanly)
        self._hub_lock = asyncio.Lock()
        self._hub_challenges: Dict[str, Dict[str, Any]] = {}
        self._hub_sessions: Dict[str, Dict[str, Any]] = {}
        self._device_key_bindings: Dict[str, Dict[str, Any]] = {}
        self._network_coordinators: Dict[str, _NetworkCoordinatorState] = {}
        self._rendezvous_openings: Dict[str, Dict[str, Any]] = {}
        self._bootstrap_sessions: Dict[str, Dict[str, Any]] = {}
        self._hub_challenge_limiter = _BoundedIpRateLimiter(max_requests=30, window_seconds=60.0)
        self._hub_session_limiter = _BoundedIpRateLimiter(max_requests=30, window_seconds=60.0)
        self._directory_limiter = _BoundedIpRateLimiter(max_requests=60, window_seconds=60.0)
        self._rendezvous_open_limiter = _BoundedIpRateLimiter(max_requests=20, window_seconds=60.0)
        self._rendezvous_join_limiter = _BoundedIpRateLimiter(max_requests=20, window_seconds=60.0)

    def _build_app(self) -> web.Application:
        app = web.Application(client_max_size=self.config.max_frame_size + 1024)
        app.router.add_get("/", self.handle_root)
        app.router.add_get("/v1/tunnel", self.handle_tunnel_ws)
        app.router.add_get("/v1/presence", self.handle_get_presence)
        app.router.add_get("/v1/resolve/{snow_id}", self.handle_resolve_snow_id)
        app.router.add_get("/v1/directory/resolve/{snow_id}", self.handle_directory_resolve)
        app.router.add_post("/v1/hub/challenge", self.handle_hub_challenge)
        app.router.add_post("/v1/hub/session", self.handle_hub_session)
        app.router.add_post("/v1/hub/revoke", self.handle_hub_revoke)
        app.router.add_post("/v1/rendezvous/open", self.handle_rendezvous_open)
        app.router.add_post("/v1/rendezvous/join", self.handle_rendezvous_join)
        app.router.add_post("/v1/rendezvous/cancel", self.handle_rendezvous_cancel)
        app.router.add_post("/v1/auth/ticket", self.handle_post_ticket)
        app.router.add_post("/v1/revoke", self.handle_post_revoke)
        app.router.add_route("*", "/u/{snow_id}/{subpath:.*}", self.handle_mcp_reverse_proxy)
        app.router.add_route("*", "/mcp", self.handle_mcp_reverse_proxy)
        app.router.add_route("*", "/oauth/{subpath:.*}", self.handle_mcp_reverse_proxy)
        app.router.add_get("/.well-known/{subpath:.*}", self.handle_mcp_reverse_proxy)
        app.router.add_get("/health", self.handle_health, allow_head=False)
        app.router.add_head("/health", self.handle_health)
        return app

    async def handle_root(self, request: web.Request) -> web.Response:
        """Unauthenticated root metadata endpoint for SNOW Relay / Hub."""
        headers = {"Cache-Control": "no-store"}
        if request.method == "HEAD":
            return web.Response(status=200, content_type="application/json", headers=headers)
        return web.json_response(
            {
                "service": "snow-relay",
                "status": "online",
                "health": "/health",
            },
            headers=headers,
        )

    async def handle_health(self, request: web.Request) -> web.Response:
        """Fast unauthenticated UptimeRobot & Render health endpoint (GET/HEAD)."""
        headers = {"Cache-Control": "no-store"}
        if request.method == "HEAD":
            return web.Response(
                status=200,
                content_type="application/json",
                headers=headers,
            )
        return web.json_response(
            {
                "status": "healthy",
                "service": "snow-relay",
                "version": "1.0.0",
            },
            headers=headers,
        )

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
        snow_id = body.get("snow_id")
        if snow_id and not is_valid_snow_id(str(snow_id)):
            return web.json_response({"success": False, "error": "Invalid snow_id format."}, status=400)
        if not device_id or not group_id:
            return web.json_response({"success": False, "error": "Missing device_id or group_id."}, status=400)

        ticket = create_relay_ticket(
            device_id=device_id,
            group_id=group_id,
            secret=self.config.shared_secret,
            ttl_seconds=ttl,
            snow_id=snow_id,
        )
        return web.json_response({"success": True, "ticket": ticket, "expires_in": ttl})

    def _authenticate_control_bearer(self, request: web.Request) -> tuple[bool, Optional[str], Optional[dict]]:
        """Authorize Bearer shared_secret or signed relay ticket (fail-closed if unconfigured)."""
        if not self.config.shared_secret:
            return False, "Relay shared_secret not configured.", None
        auth_header = request.headers.get("Authorization", "").strip()
        if not auth_header.startswith("Bearer "):
            return False, "Missing Bearer authorization.", None
        token = auth_header[7:].strip()
        if not token:
            return False, "Empty Bearer token.", None
        if token == self.config.shared_secret:
            return True, None, {"role": "admin", "group_id": None}
        ok, claims, err = extract_ticket_claims(token, self.config.shared_secret)
        if ok:
            return True, None, claims
        return False, err or "Unauthorized Bearer credential.", None

    def _authenticate_hub_session(
        self,
        raw_token: str,
        required_network_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Validate a scoped Ed25519 hub session token (in-memory only)."""
        clean = str(raw_token or "").strip()
        if not clean or len(clean) > 256:
            return False, None, "Invalid hub session token."
        tok_hash = hashlib.sha256(clean.encode("ascii", errors="ignore")).hexdigest()
        sess = self._hub_sessions.get(tok_hash)
        if not sess:
            return False, None, "Hub session token is invalid or expired."
        if not hmac.compare_digest(tok_hash, str(sess.get("token_hash") or tok_hash)):
            return False, None, "Hub session token is invalid or expired."
        now = time.time()
        if sess.get("revoked") or now > float(sess.get("expires_at", 0.0)):
            self._hub_sessions.pop(tok_hash, None)
            return False, None, "Hub session token has expired or been revoked."
        if required_network_id and sess.get("network_id") != required_network_id.strip().upper():
            return False, None, "Hub session token does not match target network scope."
        # Periodic cleanup ensures expired rendezvous openings do not remain in memory
        return True, sess, ""

    @staticmethod
    def _hash_rendezvous_secret(salt: str, value: str) -> str:
        return hashlib.sha256(f"{salt}:{value}".encode("utf-8")).hexdigest()

    def _authenticate_bootstrap_session(
        self,
        raw_token: str,
        required_network_id: Optional[str] = None,
        claimed_device_id: Optional[str] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]], str]:
        """Validate an ephemeral single-target rendezvous bootstrap token (never grants hub/owner privilege)."""
        clean = str(raw_token or "").strip()
        if not clean.startswith("rbs1_") or len(clean) > 256:
            return False, None, "Invalid bootstrap session token."
        tok_hash = hashlib.sha256(clean.encode("ascii", errors="ignore")).hexdigest()
        sess = self._bootstrap_sessions.get(tok_hash)
        if not sess:
            return False, None, "Bootstrap session token is invalid or expired."
        now = time.time()
        if sess.get("revoked") or now > float(sess.get("expires_at", 0.0)):
            self._bootstrap_sessions.pop(tok_hash, None)
            return False, None, "Bootstrap session token has expired or been revoked."
        if required_network_id and sess.get("network_id") != required_network_id.strip().upper():
            return False, None, "Bootstrap token network scope mismatch."
        if claimed_device_id and claimed_device_id != sess.get("client_device_id"):
            return False, None, "Bootstrap token device scope mismatch."
        return True, sess, ""

    def _authenticate_hub_or_control(self, request: web.Request) -> Tuple[bool, Optional[str], Optional[Dict[str, Any]]]:
        """Authenticate either an Ed25519 hub Bearer token or legacy control Bearer secret/ticket."""
        auth_header = request.headers.get("Authorization", "").strip()
        if not auth_header.startswith("Bearer "):
            return False, "Missing Bearer authorization.", None
        token = auth_header[7:].strip()
        ok_hub, sess, _ = self._authenticate_hub_session(token)
        if ok_hub and sess:
            return True, None, {
                "role": "hub",
                "auth_kind": sess.get("auth_kind", "network"),
                "network_id": sess.get("network_id") or "",
                "group_id": sess.get("network_id") or "",
                "snow_id": sess.get("snow_id") or "",
                "device_id": sess.get("device_id", ""),
            }
        return self._authenticate_control_bearer(request)

    def _prune_hub_stores_unlocked(self, now: Optional[float] = None) -> None:
        t = now if now is not None else time.time()
        expired_ch = [cid for cid, c in self._hub_challenges.items() if t > float(c.get("expires_at", 0.0))]
        for cid in expired_ch:
            self._hub_challenges.pop(cid, None)
        while len(self._hub_challenges) >= self.config.max_hub_challenges:
            oldest = next(iter(self._hub_challenges))
            self._hub_challenges.pop(oldest, None)

        expired_sess = [
            th for th, s in self._hub_sessions.items()
            if s.get("revoked") or t > float(s.get("expires_at", 0.0))
        ]
        for th in expired_sess:
            self._hub_sessions.pop(th, None)
        while len(self._hub_sessions) >= self.config.max_hub_sessions:
            oldest = next(iter(self._hub_sessions))
            self._hub_sessions.pop(oldest, None)

        expired_bindings = [
            sid
            for sid, b in self._device_key_bindings.items()
            if t > float(b.get("expires_at", 0.0))
            and (
                sid not in self._snow_routes
                or self._snow_routes[sid].get("ws") is None
                or self._snow_routes[sid]["ws"].closed
            )
        ]
        for sid in expired_bindings:
            self._device_key_bindings.pop(sid, None)
            route = self._snow_routes.get(sid)
            if route and (route.get("ws") is None or route["ws"].closed):
                self._snow_routes.pop(sid, None)
        while len(self._device_key_bindings) >= self.config.max_hub_sessions:
            oldest_sid = next(
                (
                    sid
                    for sid in self._device_key_bindings
                    if sid not in self._snow_routes
                    or self._snow_routes[sid].get("ws") is None
                    or self._snow_routes[sid]["ws"].closed
                ),
                None,
            )
            if oldest_sid is None:
                break
            self._device_key_bindings.pop(oldest_sid, None)

        expired_rdv = [
            rid for rid, r in self._rendezvous_openings.items()
            if r.get("revoked") or r.get("consumed") or t > float(r.get("expires_at", 0.0))
        ]
        for rid in expired_rdv:
            self._rendezvous_openings.pop(rid, None)
        while len(self._rendezvous_openings) >= MAX_RENDEZVOUS_ENTRIES:
            oldest = next(iter(self._rendezvous_openings))
            self._rendezvous_openings.pop(oldest, None)

        expired_bs = [
            bh for bh, b in self._bootstrap_sessions.items()
            if b.get("revoked") or t > float(b.get("expires_at", 0.0))
        ]
        for bh in expired_bs:
            self._bootstrap_sessions.pop(bh, None)
        while len(self._bootstrap_sessions) >= self.config.max_hub_sessions:
            oldest = next(iter(self._bootstrap_sessions))
            self._bootstrap_sessions.pop(oldest, None)

    async def _read_bounded_hub_json(self, request: web.Request) -> Tuple[Optional[Dict[str, Any]], Optional[web.Response]]:
        raw_ct = request.headers.get("Content-Type", "")
        if raw_ct:
            ct_media = raw_ct.split(";", 1)[0].strip().lower()
            if ct_media and ct_media != "application/json":
                return None, web.json_response({"success": False, "error": "Unsupported Content-Type; expected application/json."}, status=415)
        if request.content_length is not None and request.content_length > MAX_HUB_JSON_BYTES:
            return None, web.json_response({"success": False, "error": "Request body exceeds hub size limit."}, status=413)
        try:
            raw = await request.read()
        except Exception:
            return None, web.json_response({"success": False, "error": "Failed reading request body."}, status=400)
        if len(raw) > MAX_HUB_JSON_BYTES:
            return None, web.json_response({"success": False, "error": "Request body exceeds hub size limit."}, status=413)
        try:
            parsed = json.loads(raw.decode("utf-8"))
        except Exception:
            return None, web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        if not isinstance(parsed, dict):
            return None, web.json_response({"success": False, "error": "JSON object expected."}, status=400)
        return parsed, None

    @staticmethod
    def _is_clean_hub_field(val: str, max_len: int = 128) -> bool:
        if len(val) > max_len:
            return False
        return not any(c in ("|", "\n", "\r", "\x00") or ord(c) < 32 for c in val)

    def _has_key_collision_unlocked(self, snow_id: str, canonical_pub: str, now: float) -> bool:
        route = self._snow_routes.get(snow_id)
        if route and route.get("public_key_b64"):
            ws = route.get("ws")
            is_live = ws is not None and not ws.closed
            if is_live and route["public_key_b64"] != canonical_pub:
                return True
        binding = self._device_key_bindings.get(snow_id)
        if binding:
            bound_pub = str(binding.get("public_key_b64") or "")
            bound_exp = float(binding.get("expires_at", 0.0))
            if bound_pub and bound_pub != canonical_pub and (now <= bound_exp or (route and route.get("ws") is not None and not route["ws"].closed)):
                return True
        return False

    async def handle_hub_challenge(self, request: web.Request) -> web.Response:
        """Issue a cryptographically unpredictable single-use Ed25519 challenge for a device or network."""
        client_ip = request.remote or "unknown"
        allowed, retry_after = self._hub_challenge_limiter.check(client_ip)
        if not allowed:
            return web.json_response(
                {"success": False, "error": "Rate limit exceeded. Retry later."},
                status=429,
                headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"},
            )

        body, err_resp = await self._read_bounded_hub_json(request)
        if err_resp is not None:
            return err_resp
        assert body is not None

        raw_net_id = str(body.get("network_id") or "").strip().upper()
        raw_snow_id = str(body.get("snow_id") or "").strip().upper()
        raw_pub = body.get("public_key") or body.get("pubkey")
        device_id = str(body.get("device_id") or "").strip()
        audience = str(body.get("audience") or "render-hub-tunnel").strip()

        if not self._is_clean_hub_field(device_id, 128) or not self._is_clean_hub_field(audience, 64) or not isinstance(raw_pub, str):
            return web.json_response({"success": False, "error": "Invalid identity credentials."}, status=400, headers={"Cache-Control": "no-store"})
        if raw_snow_id and not is_valid_snow_id(raw_snow_id):
            return web.json_response({"success": False, "error": "Invalid snow_id format."}, status=400, headers={"Cache-Control": "no-store"})
        if raw_net_id and not is_valid_network_id(raw_net_id):
            return web.json_response({"success": False, "error": "Invalid network_id format."}, status=400, headers={"Cache-Control": "no-store"})

        try:
            raw_pub_bytes = decode_ed25519_pubkey(raw_pub)
            canonical_pub = encode_ed25519_pubkey(raw_pub_bytes)
        except Exception:
            return web.json_response({"success": False, "error": "Invalid Ed25519 public key."}, status=400, headers={"Cache-Control": "no-store"})

        # Mode A: legacy network identity when network_id matches public_key (and snow_id is absent or not per-device pubkey)
        derived_net_id = derive_network_id_from_pubkey(raw_pub_bytes)
        derived_dev_snow_id = derive_device_snow_id_from_pubkey(raw_pub_bytes)
        now = time.time()
        ttl = int(max(10.0, self.config.hub_challenge_ttl_seconds))
        expires_at = int(now + ttl)
        challenge_id = secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(32)

        if raw_net_id and derived_net_id == raw_net_id:
            auth_kind = "network"
            challenge_msg = canonical_hub_challenge_message(
                challenge_id=challenge_id,
                network_id=raw_net_id,
                nonce=nonce,
                expires_at=expires_at,
                device_id=device_id,
            ).decode("utf-8")
        elif raw_snow_id:
            if derived_dev_snow_id != raw_snow_id:
                return web.json_response({"success": False, "error": "Device SNOW ID does not match public key."}, status=403, headers={"Cache-Control": "no-store"})
            if not device_id:
                return web.json_response({"success": False, "error": "device_id is required for per-device hub authentication."}, status=400, headers={"Cache-Control": "no-store"})
            auth_kind = "device"
            challenge_msg = canonical_device_hub_challenge_message(
                challenge_id=challenge_id,
                nonce=nonce,
                expires_at=expires_at,
                snow_id=raw_snow_id,
                public_key_b64=canonical_pub,
                device_id=device_id,
                network_id=raw_net_id,
                audience=audience or "render-hub-tunnel",
            ).decode("utf-8")
        else:
            return web.json_response({"success": False, "error": "Identity verification failed."}, status=403, headers={"Cache-Control": "no-store"})

        async with self._hub_lock:
            self._prune_hub_stores_unlocked(now)
            if auth_kind == "device" and self._has_key_collision_unlocked(raw_snow_id, canonical_pub, now):
                return web.json_response(
                    {"success": False, "error": "SNOW ID collision or active ownership conflict rejected."},
                    status=409,
                    headers={"Cache-Control": "no-store"},
                )
            self._hub_challenges[challenge_id] = {
                "challenge_id": challenge_id,
                "kind": auth_kind,
                "network_id": raw_net_id,
                "snow_id": raw_snow_id,
                "public_key_b64": canonical_pub,
                "device_id": device_id,
                "audience": audience or "render-hub-tunnel",
                "nonce": nonce,
                "expires_at": expires_at,
                "created_at": now,
            }

        return web.json_response(
            {
                "success": True,
                "auth_kind": auth_kind,
                "challenge_id": challenge_id,
                "nonce": nonce,
                "network_id": raw_net_id,
                "snow_id": raw_snow_id,
                "audience": audience or "render-hub-tunnel",
                "expires_in": ttl,
                "expires_at": expires_at,
                "challenge_message": challenge_msg,
            },
            headers={"Cache-Control": "no-store"},
        )

    async def handle_hub_session(self, request: web.Request) -> web.Response:
        """Verify signed Ed25519 single-use challenge and issue scoped short-lived hub token."""
        client_ip = request.remote or "unknown"
        allowed, retry_after = self._hub_session_limiter.check(client_ip)
        if not allowed:
            return web.json_response(
                {"success": False, "error": "Rate limit exceeded. Retry later."},
                status=429,
                headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"},
            )

        body, err_resp = await self._read_bounded_hub_json(request)
        if err_resp is not None:
            return err_resp
        assert body is not None

        challenge_id = str(body.get("challenge_id") or "").strip()
        raw_net_id = str(body.get("network_id") or "").strip().upper()
        raw_pub = body.get("public_key") or body.get("pubkey")
        signature_b64 = str(body.get("signature") or "").strip()
        device_id = str(body.get("device_id") or "").strip()
        snow_id = str(body.get("snow_id") or "").strip().upper()
        audience = str(body.get("audience") or "render-hub-tunnel").strip()

        if not challenge_id or not signature_b64 or not isinstance(raw_pub, str):
            return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})
        if snow_id and not is_valid_snow_id(snow_id):
            return web.json_response({"success": False, "error": "Invalid snow_id format."}, status=400, headers={"Cache-Control": "no-store"})
        if raw_net_id and not is_valid_network_id(raw_net_id):
            return web.json_response({"success": False, "error": "Invalid network_id format."}, status=400, headers={"Cache-Control": "no-store"})
        if not self._is_clean_hub_field(device_id, 128) or not self._is_clean_hub_field(audience, 64):
            return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})

        try:
            raw_pub_bytes = decode_ed25519_pubkey(raw_pub)
            canonical_pub = encode_ed25519_pubkey(raw_pub_bytes)
        except Exception:
            return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})

        # Atomic single-use pop prevents concurrent replay
        now = time.time()
        async with self._hub_lock:
            challenge = self._hub_challenges.pop(challenge_id, None)

        if not challenge:
            return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})
        if now > float(challenge.get("expires_at", 0.0)):
            return web.json_response({"success": False, "error": "Challenge expired."}, status=401, headers={"Cache-Control": "no-store"})
        if challenge.get("public_key_b64") != canonical_pub:
            return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})

        auth_kind = str(challenge.get("kind") or "network")
        if auth_kind == "device":
            if not snow_id or snow_id != challenge.get("snow_id"):
                return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})
            if derive_device_snow_id_from_pubkey(raw_pub_bytes) != snow_id:
                return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})
            if not device_id or device_id != challenge.get("device_id"):
                return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})
            if raw_net_id != str(challenge.get("network_id") or ""):
                return web.json_response({"success": False, "error": "Challenge network scope mismatch."}, status=401, headers={"Cache-Control": "no-store"})
            if (audience or "render-hub-tunnel") != str(challenge.get("audience") or "render-hub-tunnel"):
                return web.json_response({"success": False, "error": "Challenge audience mismatch."}, status=401, headers={"Cache-Control": "no-store"})
            msg = canonical_device_hub_challenge_message(
                challenge_id=challenge_id,
                nonce=str(challenge["nonce"]),
                expires_at=int(challenge["expires_at"]),
                snow_id=snow_id,
                public_key_b64=canonical_pub,
                device_id=device_id,
                network_id=raw_net_id,
                audience=str(challenge.get("audience") or "render-hub-tunnel"),
            )
        else:
            if not is_valid_network_id(raw_net_id) or challenge.get("network_id") != raw_net_id:
                return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})
            if derive_network_id_from_pubkey(raw_pub_bytes) != raw_net_id:
                return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})
            if challenge.get("device_id") and device_id != challenge.get("device_id"):
                return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})
            msg = canonical_hub_challenge_message(
                challenge_id=challenge_id,
                network_id=raw_net_id,
                nonce=str(challenge["nonce"]),
                expires_at=int(challenge["expires_at"]),
                device_id=str(challenge.get("device_id") or ""),
            )

        if not verify_ed25519_signature(raw_pub_bytes, msg, signature_b64):
            return web.json_response({"success": False, "error": "Challenge verification failed."}, status=401, headers={"Cache-Control": "no-store"})

        ttl = int(max(60.0, self.config.hub_session_ttl_seconds))
        raw_token = f"shs1_{secrets.token_urlsafe(32)}"
        tok_hash = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
        async with self._hub_lock:
            self._prune_hub_stores_unlocked(now)
            next_gen = 1
            if auth_kind == "device":
                if self._has_key_collision_unlocked(snow_id, canonical_pub, now):
                    return web.json_response(
                        {"success": False, "error": "SNOW ID collision or active ownership conflict rejected."},
                        status=409,
                        headers={"Cache-Control": "no-store"},
                    )
                prev_binding = self._device_key_bindings.get(snow_id)
                prev_route = self._snow_routes.get(snow_id)
                prev_gen = max(
                    int((prev_binding or {}).get("session_generation", 0) or 0),
                    int((prev_route or {}).get("session_generation", 0) or 0),
                )
                next_gen = prev_gen + 1
                self._device_key_bindings[snow_id] = {
                    "snow_id": snow_id,
                    "public_key_b64": canonical_pub,
                    "device_id": device_id,
                    "session_generation": next_gen,
                    "expires_at": now + ttl,
                }
            self._hub_sessions[tok_hash] = {
                "token_hash": tok_hash,
                "auth_kind": auth_kind,
                "network_id": raw_net_id,
                "public_key_b64": canonical_pub,
                "device_id": device_id,
                "snow_id": snow_id,
                "session_generation": next_gen,
                "created_at": now,
                "expires_at": now + ttl,
                "revoked": False,
            }

        return web.json_response(
            {
                "success": True,
                "auth_kind": auth_kind,
                "token": raw_token,
                "token_type": "Bearer",
                "network_id": raw_net_id,
                "snow_id": snow_id,
                "session_generation": next_gen,
                "expires_in": ttl,
            },
            headers={"Cache-Control": "no-store"},
        )

    async def handle_hub_revoke(self, request: web.Request) -> web.Response:
        """Revoke an active scoped hub session token."""
        auth_header = request.headers.get("Authorization", "").strip()
        if not auth_header.startswith("Bearer "):
            return web.json_response({"success": False, "error": "Missing Bearer authorization."}, status=401)
        token = auth_header[7:].strip()
        tok_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
        async with self._hub_lock:
            sess = self._hub_sessions.pop(tok_hash, None)
        if not sess:
            return web.json_response({"success": False, "error": "Session not found."}, status=401)
        return web.json_response({
            "success": True,
            "revoked": True,
            "network_id": sess.get("network_id", ""),
            "snow_id": sess.get("snow_id", ""),
        })

    async def handle_rendezvous_open(self, request: web.Request) -> web.Response:
        """Open a short-lived (<=120s), network-scoped rendezvous slot for unpaired remote onboarding."""
        client_ip = request.remote or "unknown"
        allowed, retry_after = self._rendezvous_open_limiter.check(client_ip)
        if not allowed:
            return web.json_response(
                {"success": False, "error": "Rate limit exceeded. Retry later."},
                status=429,
                headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"},
            )

        auth_header = request.headers.get("Authorization", "").strip()
        if not auth_header.startswith("Bearer "):
            return web.json_response(
                {"success": False, "error": "Authenticated Ed25519 hub session required."},
                status=401,
                headers={"Cache-Control": "no-store"},
            )
        token = auth_header[7:].strip()
        ok_hub, hub_sess, hub_err = self._authenticate_hub_session(token)
        if not ok_hub or not hub_sess:
            return web.json_response(
                {"success": False, "error": hub_err or "Unauthorized hub session."},
                status=401,
                headers={"Cache-Control": "no-store"},
            )

        body, err_resp = await self._read_bounded_hub_json(request)
        if err_resp is not None:
            return err_resp
        assert body is not None

        authed_net_id = str(hub_sess["network_id"]).strip().upper()
        req_net_id = str(body.get("network_id") or authed_net_id).strip().upper()
        if not is_valid_network_id(req_net_id) or req_net_id != authed_net_id:
            return web.json_response(
                {"success": False, "error": "Forbidden: cannot open rendezvous for another network."},
                status=403,
                headers={"Cache-Control": "no-store"},
            )

        sess_dev = str(hub_sess.get("device_id") or "").strip()
        host_device_id = str(body.get("host_device_id") or sess_dev or "").strip()
        if not host_device_id or len(host_device_id) > 128 or (sess_dev and host_device_id != sess_dev):
            return web.json_response(
                {"success": False, "error": "Forbidden or invalid host_device_id."},
                status=403,
                headers={"Cache-Control": "no-store"},
            )

        mode = str(body.get("mode") or "pairing").strip().lower()
        if mode not in ("pairing", "federation"):
            return web.json_response(
                {"success": False, "error": "mode must be 'pairing' or 'federation'."},
                status=400,
                headers={"Cache-Control": "no-store"},
            )

        raw_ttl = body.get("ttl_seconds", MAX_RENDEZVOUS_TTL_SECONDS)
        if isinstance(raw_ttl, bool) or not isinstance(raw_ttl, (int, float)) or raw_ttl <= 0:
            return web.json_response(
                {"success": False, "error": "ttl_seconds must be a positive number (<= 120)."},
                status=400,
                headers={"Cache-Control": "no-store"},
            )
        ttl_seconds = min(MAX_RENDEZVOUS_TTL_SECONDS, max(10.0, float(raw_ttl)))

        host_snow_id = str(body.get("host_snow_id") or body.get("snow_id") or hub_sess.get("snow_id") or "").strip().upper()
        if host_snow_id and not is_valid_snow_id(host_snow_id):
            return web.json_response(
                {"success": False, "error": "Invalid host_snow_id format."},
                status=400,
                headers={"Cache-Control": "no-store"},
            )

        raw_fp = str(body.get("cert_fingerprint") or "").replace(":", "").replace(" ", "").strip().upper()
        if raw_fp and (len(raw_fp) != 64 or any(c not in "0123456789ABCDEF" for c in raw_fp)):
            return web.json_response(
                {"success": False, "error": "cert_fingerprint must be a 64-char hex SHA-256 fingerprint."},
                status=400,
                headers={"Cache-Control": "no-store"},
            )

        salt = secrets.token_hex(16)
        pin_hash: Optional[str] = None
        handshake_hash: Optional[str] = None
        fed_hash: Optional[str] = None

        if mode == "pairing":
            raw_pin = str(body.get("pin") or "").strip()
            raw_htok = str(body.get("handshake_token") or "").strip()
            if raw_pin:
                if len(raw_pin) != 6 or not raw_pin.isdigit():
                    return web.json_response(
                        {"success": False, "error": "Pairing PIN must be exactly 6 digits."},
                        status=400,
                        headers={"Cache-Control": "no-store"},
                    )
                if not host_snow_id:
                    return web.json_response(
                        {"success": False, "error": "host_snow_id is required when opening PIN rendezvous."},
                        status=400,
                        headers={"Cache-Control": "no-store"},
                    )
                pin_hash = self._hash_rendezvous_secret(salt, raw_pin)
            if raw_htok:
                if len(raw_htok) < 16 or len(raw_htok) > 256:
                    return web.json_response(
                        {"success": False, "error": "handshake_token must be 16..256 characters."},
                        status=400,
                        headers={"Cache-Control": "no-store"},
                    )
                handshake_hash = self._hash_rendezvous_secret(salt, raw_htok)
            if not pin_hash and not handshake_hash:
                return web.json_response(
                    {"success": False, "error": "Pairing rendezvous requires 'pin' (with snow_id) or 'handshake_token'."},
                    status=400,
                    headers={"Cache-Control": "no-store"},
                )
        else:
            raw_fed = re.sub(r"\D", "", str(body.get("federation_code") or ""))
            if len(raw_fed) != 9:
                return web.json_response(
                    {"success": False, "error": "federation_code must contain exactly 9 digits."},
                    status=400,
                    headers={"Cache-Control": "no-store"},
                )
            fed_hash = self._hash_rendezvous_secret(salt, raw_fed)

        now = time.time()
        expires_at = now + ttl_seconds
        rendezvous_id = f"rdv_{secrets.token_urlsafe(16)}"

        async with self._hub_lock:
            self._prune_hub_stores_unlocked(now)
            self._rendezvous_openings[rendezvous_id] = {
                "rendezvous_id": rendezvous_id,
                "network_id": authed_net_id,
                "host_device_id": host_device_id,
                "host_snow_id": host_snow_id,
                "host_cert_fingerprint": raw_fp,
                "mode": mode,
                "salt": salt,
                "pin_hash": pin_hash,
                "handshake_token_hash": handshake_hash,
                "federation_code_hash": fed_hash,
                "created_at": now,
                "expires_at": expires_at,
                "failed_attempts": 0,
                "consumed": False,
                "revoked": False,
            }

        return web.json_response(
            {
                "success": True,
                "rendezvous_id": rendezvous_id,
                "network_id": authed_net_id,
                "host_device_id": host_device_id,
                "host_snow_id": host_snow_id,
                "mode": mode,
                "expires_in": int(round(ttl_seconds)),
                "expires_at": int(expires_at),
            },
            headers={"Cache-Control": "no-store"},
        )

    async def handle_rendezvous_cancel(self, request: web.Request) -> web.Response:
        """Cancel an open rendezvous entry cleanly (authenticated owning hub network only)."""
        auth_header = request.headers.get("Authorization", "").strip()
        if not auth_header.startswith("Bearer "):
            return web.json_response({"success": False, "error": "Missing Bearer authorization."}, status=401, headers={"Cache-Control": "no-store"})
        ok_hub, hub_sess, hub_err = self._authenticate_hub_session(auth_header[7:].strip())
        if not ok_hub or not hub_sess:
            return web.json_response({"success": False, "error": hub_err or "Unauthorized."}, status=401, headers={"Cache-Control": "no-store"})

        body, err_resp = await self._read_bounded_hub_json(request)
        if err_resp is not None:
            return err_resp
        assert body is not None

        rdv_id = str(body.get("rendezvous_id") or "").strip()
        if not rdv_id:
            return web.json_response({"success": False, "error": "Missing rendezvous_id."}, status=400, headers={"Cache-Control": "no-store"})

        async with self._hub_lock:
            entry = self._rendezvous_openings.get(rdv_id)
            if not entry:
                return web.json_response({"success": False, "error": "Rendezvous entry not found."}, status=404, headers={"Cache-Control": "no-store"})
            if entry["network_id"] != hub_sess["network_id"]:
                return web.json_response({"success": False, "error": "Forbidden: rendezvous belongs to another network."}, status=403, headers={"Cache-Control": "no-store"})
            entry["revoked"] = True
            self._rendezvous_openings.pop(rdv_id, None)

        return web.json_response({"success": True, "cancelled": True, "rendezvous_id": rdv_id}, headers={"Cache-Control": "no-store"})

    async def handle_rendezvous_join(self, request: web.Request) -> web.Response:
        """Redeem a short-lived rendezvous credential for scoped ephemeral E2E bootstrap material only.

        CRITICAL: Never completes pairing/trust directly; only issues an ephemeral single-target
        relay bootstrap token so the joining device and host can run the real E2E TLS-pinned
        handshake + explicit owner consent flow.
        """
        client_ip = request.remote or "unknown"
        allowed, retry_after = self._rendezvous_join_limiter.check(client_ip)
        if not allowed:
            return web.json_response(
                {"success": False, "error": "Too many rendezvous join attempts. Retry later."},
                status=429,
                headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"},
            )

        body, err_resp = await self._read_bounded_hub_json(request)
        if err_resp is not None:
            return err_resp
        assert body is not None

        client_device_id = str(body.get("client_device_id") or "").strip()
        if not client_device_id or len(client_device_id) > 128:
            return web.json_response({"success": False, "error": "Valid client_device_id is required."}, status=400, headers={"Cache-Control": "no-store"})

        req_rdv_id = str(body.get("rendezvous_id") or "").strip()
        raw_snow_id = str(body.get("snow_id") or "").strip().upper()
        raw_pin = str(body.get("pin") or "").strip()
        raw_htok = str(body.get("handshake_token") or "").strip()
        raw_fed_raw = body.get("federation_code")
        raw_fed = re.sub(r"\D", "", str(raw_fed_raw)) if raw_fed_raw is not None else ""

        if raw_snow_id and not is_valid_snow_id(raw_snow_id):
            return web.json_response({"success": False, "error": "Invalid snow_id format."}, status=400, headers={"Cache-Control": "no-store"})

        provided_methods = int(bool(raw_pin)) + int(bool(raw_htok)) + int(bool(raw_fed))
        if provided_methods != 1:
            return web.json_response(
                {"success": False, "error": "Provide exactly one join credential: (snow_id + pin), handshake_token, or federation_code."},
                status=400,
                headers={"Cache-Control": "no-store"},
            )

        if raw_pin:
            if not raw_snow_id or len(raw_pin) != 6 or not raw_pin.isdigit():
                return web.json_response({"success": False, "error": "PIN onboarding requires valid snow_id and 6-digit pin."}, status=400, headers={"Cache-Control": "no-store"})
            join_kind = "pin"
            expected_mode = "pairing"
        elif raw_htok:
            if len(raw_htok) < 16 or len(raw_htok) > 256:
                return web.json_response({"success": False, "error": "Invalid handshake_token format."}, status=400, headers={"Cache-Control": "no-store"})
            join_kind = "handshake_token"
            expected_mode = "pairing"
        else:
            if len(raw_fed) != 9:
                return web.json_response({"success": False, "error": "federation_code must contain 9 digits."}, status=400, headers={"Cache-Control": "no-store"})
            join_kind = "federation_code"
            expected_mode = "federation"

        now = time.time()
        matched_snapshot: Optional[Dict[str, Any]] = None
        bootstrap_token = ""
        bootstrap_ttl = 120.0

        async with self._hub_lock:
            self._prune_hub_stores_unlocked(now)

            candidates: List[Dict[str, Any]] = []
            if req_rdv_id:
                cand = self._rendezvous_openings.get(req_rdv_id)
                if cand is not None:
                    candidates = [cand]
            else:
                for cand in self._rendezvous_openings.values():
                    if expected_mode == "pairing" and join_kind == "pin":
                        if cand.get("mode") == "pairing" and cand.get("host_snow_id") == raw_snow_id:
                            candidates.append(cand)
                    elif expected_mode == "pairing" and join_kind == "handshake_token":
                        if cand.get("mode") == "pairing" and (not raw_snow_id or cand.get("host_snow_id") == raw_snow_id):
                            candidates.append(cand)
                    else:
                        if cand.get("mode") == "federation":
                            candidates.append(cand)

            if not candidates:
                return web.json_response({"success": False, "error": "Rendezvous slot not found, expired, or already used."}, status=401, headers={"Cache-Control": "no-store"})

            saw_scope_mismatch = False
            saw_lockout = False
            for entry in candidates:
                if entry.get("revoked") or entry.get("consumed") or now > float(entry.get("expires_at", 0.0)):
                    continue
                if entry.get("mode") != expected_mode:
                    saw_scope_mismatch = True
                    continue
                if raw_snow_id and entry.get("host_snow_id") and entry.get("host_snow_id") != raw_snow_id:
                    saw_scope_mismatch = True
                    continue

                salt = str(entry["salt"])
                verified = False
                if join_kind == "pin" and entry.get("pin_hash"):
                    verified = hmac.compare_digest(
                        self._hash_rendezvous_secret(salt, raw_pin),
                        str(entry["pin_hash"]),
                    )
                elif join_kind == "handshake_token" and entry.get("handshake_token_hash"):
                    verified = hmac.compare_digest(
                        self._hash_rendezvous_secret(salt, raw_htok),
                        str(entry["handshake_token_hash"]),
                    )
                elif join_kind == "federation_code" and entry.get("federation_code_hash"):
                    verified = hmac.compare_digest(
                        self._hash_rendezvous_secret(salt, raw_fed),
                        str(entry["federation_code_hash"]),
                    )

                if verified:
                    entry["consumed"] = True
                    self._rendezvous_openings.pop(entry["rendezvous_id"], None)
                    matched_snapshot = dict(entry)
                    bootstrap_token = f"rbs1_{secrets.token_urlsafe(32)}"
                    remaining = max(30.0, min(MAX_RENDEZVOUS_TTL_SECONDS, float(entry["expires_at"]) - now + 30.0))
                    bootstrap_ttl = remaining
                    tok_hash = hashlib.sha256(bootstrap_token.encode("ascii")).hexdigest()
                    self._bootstrap_sessions[tok_hash] = {
                        "network_id": entry["network_id"],
                        "host_device_id": entry["host_device_id"],
                        "client_device_id": client_device_id,
                        "mode": entry["mode"],
                        "rendezvous_id": entry["rendezvous_id"],
                        "created_at": now,
                        "expires_at": now + bootstrap_ttl,
                        "revoked": False,
                    }
                    break
                else:
                    entry["failed_attempts"] = int(entry.get("failed_attempts", 0)) + 1
                    if entry["failed_attempts"] >= MAX_RENDEZVOUS_FAILED_ATTEMPTS:
                        entry["revoked"] = True
                        self._rendezvous_openings.pop(entry["rendezvous_id"], None)
                        saw_lockout = True

        if not matched_snapshot:
            if saw_lockout:
                return web.json_response(
                    {"success": False, "error": "Rendezvous locked after excessive failed attempts."},
                    status=429,
                    headers={"Cache-Control": "no-store"},
                )
            if saw_scope_mismatch:
                return web.json_response(
                    {"success": False, "error": "Rendezvous mode or target scope mismatch."},
                    status=403,
                    headers={"Cache-Control": "no-store"},
                )
            return web.json_response(
                {"success": False, "error": "Rendezvous verification failed."},
                status=401,
                headers={"Cache-Control": "no-store"},
            )

        proto = request.headers.get("X-Forwarded-Proto", request.scheme or "http").split(",")[0].strip()
        ws_proto = "wss" if proto == "https" else "ws"
        host = request.host

        return web.json_response(
            {
                "success": True,
                "rendezvous_id": matched_snapshot["rendezvous_id"],
                "mode": matched_snapshot["mode"],
                "network_id": matched_snapshot["network_id"],
                "host_device_id": matched_snapshot["host_device_id"],
                "host_snow_id": matched_snapshot.get("host_snow_id") or "",
                "host_cert_fingerprint": matched_snapshot.get("host_cert_fingerprint") or "",
                "relay_ws_url": f"{ws_proto}://{host}/v1/tunnel",
                "bootstrap_token": bootstrap_token,
                "expires_in": int(round(bootstrap_ttl)),
                "trust_completed": False,
                "requires_end_to_end_verification": True,
            },
            headers={"Cache-Control": "no-store"},
        )

    async def _broadcast_coordinator_update(self, coord: _NetworkCoordinatorState) -> None:
        """Push coordinator primary + epoch update to all online hosts in this network."""
        payload = {
            "type": "coordinator_update",
            "network_id": coord.network_id,
            "primary_device_id": coord.primary_device_id,
            "epoch": coord.epoch,
        }
        now = time.time()
        for entry in list(coord.hosts.values()):
            if entry.is_online(now) and entry.ws is not None:
                try:
                    await entry.ws.send_json(payload)
                except Exception:
                    pass

    async def sweep_expired_leases(self) -> List[web.WebSocketResponse]:
        """Sweep expired host leases and execute deterministic coordinator failover within each network."""
        now = time.time()
        dead_sockets: List[web.WebSocketResponse] = []
        changed_coords: List[_NetworkCoordinatorState] = []

        for net_id, coord in list(self._network_coordinators.items()):
            expired_ids = [did for did, h in coord.hosts.items() if not h.is_online(now)]
            for did in expired_ids:
                entry = coord.hosts.pop(did, None)
                if entry and entry.ws is not None and not entry.ws.closed:
                    dead_sockets.append(entry.ws)
            _, changed = coord.elect_primary(now)
            if changed:
                changed_coords.append(coord)
            if not coord.hosts:
                self._network_coordinators.pop(net_id, None)

        for d_ws in dead_sockets:
            if not d_ws.closed:
                try:
                    await d_ws.close(code=4000, message=b"Coordinator host lease expired.")
                except Exception:
                    pass

        for coord in changed_coords:
            await self._broadcast_coordinator_update(coord)

        return dead_sockets

    async def handle_directory_resolve(self, request: web.Request) -> web.Response:
        """Resolve a SNOW ID to authorized network-scoped relay/LAN endpoints without exposing tokens."""
        client_ip = request.remote or "unknown"
        allowed, retry_after = self._directory_limiter.check(client_ip)
        if not allowed:
            return web.json_response(
                {"success": False, "error": "Directory rate limit exceeded."},
                status=429,
                headers={"Retry-After": str(retry_after)},
            )

        raw_snow_id = (request.match_info.get("snow_id") or "").strip().upper()
        if not is_valid_snow_id(raw_snow_id):
            return web.json_response({"success": False, "error": "Invalid SNOW ID format."}, status=400)

        authed, auth_err, claims = self._authenticate_hub_or_control(request)
        if not authed:
            status_code = 500 if auth_err == "Relay shared_secret not configured." else 401
            return web.json_response({"success": False, "error": auth_err}, status=status_code)

        caller_net = (claims or {}).get("network_id") or (claims or {}).get("group_id")
        caller_snow_id = str((claims or {}).get("snow_id") or "").strip().upper()
        auth_kind = str((claims or {}).get("auth_kind") or "")
        is_admin = (claims or {}).get("role") == "admin"

        # 1. Search network-scoped coordinator host entries first
        now = time.time()
        matched_host: Optional[_NetworkHostEntry] = None
        for net_id, coord in self._network_coordinators.items():
            for h in coord.hosts.values():
                if h.snow_id == raw_snow_id and h.is_online(now):
                    matched_host = h
                    break
            if matched_host:
                break

        proto = request.headers.get("X-Forwarded-Proto", request.scheme or "http").split(",")[0].strip()
        ws_proto = "wss" if proto == "https" else "ws"
        host = request.host

        if matched_host is not None:
            is_self = caller_snow_id and caller_snow_id == raw_snow_id
            if not is_admin and not is_self and caller_net and matched_host.network_id != caller_net:
                return web.json_response({"success": False, "error": "Cross-network directory lookup denied."}, status=403)
            if auth_kind == "device" and not caller_net and not is_self:
                return web.json_response({"success": False, "error": "Cross-device directory lookup denied."}, status=403)
            return web.json_response(
                {
                    "success": True,
                    "snow_id": raw_snow_id,
                    "network_id": matched_host.network_id,
                    "device_id": matched_host.device_id,
                    "device_name": matched_host.device_name or matched_host.device_id,
                    "online": True,
                    "mcp_tunnel_active": matched_host.mcp_tunnel,
                    "lan_endpoints": list(matched_host.lan_endpoints),
                    "relay_ws_url": f"{ws_proto}://{host}/v1/tunnel",
                    "mcp_url": f"{proto}://{host}/u/{matched_host.network_id}/mcp",
                    "last_seen": matched_host.last_heartbeat,
                },
                headers={"Cache-Control": "no-store"},
            )

        # 2. Check per-device / legacy _snow_routes within authorized scope
        route = self._snow_routes.get(raw_snow_id)
        if not route:
            return web.json_response({"success": False, "error": f"SNOW ID '{raw_snow_id}' not found."}, status=404)
        route_group = route.get("network_id") or route.get("group_id") or ""
        is_self = caller_snow_id and caller_snow_id == raw_snow_id
        if not is_admin and not is_self:
            if not caller_net or route_group != caller_net:
                return web.json_response({"success": False, "error": "Cross-network directory lookup denied."}, status=403)
        ws = route.get("ws")
        online = bool(ws is not None and not ws.closed)
        return web.json_response(
            {
                "success": True,
                "snow_id": raw_snow_id,
                "network_id": route.get("network_id") or route.get("group_id"),
                "device_id": route.get("device_id"),
                "online": online,
                "mcp_tunnel_active": bool(online and route.get("mcp_tunnel")),
                "lan_endpoints": list(route.get("lan_endpoints") or []),
                "relay_ws_url": f"{ws_proto}://{host}/v1/tunnel",
                "mcp_url": f"{proto}://{host}/u/{raw_snow_id}/mcp",
                "last_seen": route.get("last_seen"),
            },
            headers={"Cache-Control": "no-store"},
        )

    async def handle_resolve_snow_id(self, request: web.Request) -> web.Response:
        """Authenticated lookup resolving a canonical SNOW ID to active relay/MCP endpoints."""
        raw_snow_id = (request.match_info.get("snow_id") or "").strip().upper()
        if not is_valid_snow_id(raw_snow_id):
            return web.json_response({"success": False, "error": "Invalid SNOW ID format."}, status=400)

        authed, auth_err, claims = self._authenticate_control_bearer(request)
        if not authed:
            status_code = 500 if auth_err == "Relay shared_secret not configured." else 401
            return web.json_response({"success": False, "error": auth_err}, status=status_code)

        route = self._snow_routes.get(raw_snow_id)
        if not route:
            return web.json_response({"success": False, "error": f"SNOW ID '{raw_snow_id}' is not registered."}, status=404)

        caller_group = (claims or {}).get("group_id")
        if caller_group and route.get("group_id") != caller_group:
            return web.json_response({"success": False, "error": "Cross-group SNOW ID lookup denied."}, status=403)

        ws = route.get("ws")
        online = bool(ws is not None and not ws.closed)
        mcp_active = bool(online and route.get("mcp_tunnel"))
        proto = request.headers.get("X-Forwarded-Proto", request.scheme or "http").split(",")[0].strip()
        ws_proto = "wss" if proto == "https" else "ws"
        host = request.host
        return web.json_response({
            "success": True,
            "snow_id": raw_snow_id,
            "device_id": route.get("device_id"),
            "group_id": route.get("group_id"),
            "online": online,
            "mcp_tunnel_active": mcp_active,
            "mcp_url": f"{proto}://{host}/u/{raw_snow_id}/mcp",
            "relay_ws_url": f"{ws_proto}://{host}/v1/tunnel",
            "last_seen": route.get("last_seen"),
        })

    def _resolve_mcp_target_route(self, request: web.Request) -> tuple[Optional[str], Optional[dict], str, int]:
        """Resolve which active authenticated MCP reverse-tunnel should receive this HTTP request."""
        path_target = (request.match_info.get("snow_id") or "").strip().upper()
        if path_target:
            if is_valid_network_id(path_target):
                coord = self._network_coordinators.get(path_target)
                now = time.time()
                if coord:
                    # Prefer current primary coordinator if online with MCP tunnel; otherwise fail over cleanly
                    candidates: List[_NetworkHostEntry] = []
                    if coord.primary_device_id and coord.primary_device_id in coord.hosts:
                        candidates.append(coord.hosts[coord.primary_device_id])
                    for did, h in coord.hosts.items():
                        if did != coord.primary_device_id:
                            candidates.append(h)
                    for h in candidates:
                        if h.network_id == path_target and h.is_online(now) and h.mcp_tunnel and h.ws is not None:
                            return (
                                path_target,
                                {
                                    "network_id": path_target,
                                    "device_id": h.device_id,
                                    "ws": h.ws,
                                    "mcp_tunnel": True,
                                    "epoch": coord.epoch,
                                },
                                "",
                                200,
                            )
                return None, None, f"No online MCP host available for network '{path_target}'.", 503

            if is_valid_snow_id(path_target):
                route = self._snow_routes.get(path_target)
                ws = route.get("ws") if route else None
                if not route or not route.get("mcp_tunnel") or ws is None or ws.closed:
                    return None, None, f"Remote MCP tunnel for '{path_target}' is offline.", 503
                return path_target, route, "", 200

            return None, None, "Invalid network or SNOW ID format.", 400

        header_or_query_id = (
            request.headers.get("X-Snow-Id")
            or request.query.get("snow_id")
            or ""
        ).strip().upper()
        if header_or_query_id:
            if not is_valid_snow_id(header_or_query_id) and not is_valid_network_id(header_or_query_id):
                return None, None, "Invalid SNOW ID format.", 400
            if is_valid_network_id(header_or_query_id):
                coord = self._network_coordinators.get(header_or_query_id)
                now = time.time()
                if coord and coord.primary_device_id and coord.primary_device_id in coord.hosts:
                    prim = coord.hosts[coord.primary_device_id]
                    if prim.is_online(now) and prim.mcp_tunnel and prim.ws is not None:
                        return header_or_query_id, {"device_id": prim.device_id, "ws": prim.ws, "mcp_tunnel": True}, "", 200
                return None, None, f"No online MCP host available for network '{header_or_query_id}'.", 503
            route = self._snow_routes.get(header_or_query_id)
            ws = route.get("ws") if route else None
            if not route or not route.get("mcp_tunnel") or ws is None or ws.closed:
                return None, None, f"Remote MCP tunnel for '{header_or_query_id}' is offline.", 503
            return header_or_query_id, route, "", 200

        if self.config.default_snow_id:
            route = self._snow_routes.get(self.config.default_snow_id)
            ws = route.get("ws") if route else None
            if not route or not route.get("mcp_tunnel") or ws is None or ws.closed:
                return None, None, "Configured default SNOW MCP tunnel is offline.", 503
            return self.config.default_snow_id, route, "", 200

        active_routes = [
            (sid, r)
            for sid, r in self._snow_routes.items()
            if r.get("mcp_tunnel") and r.get("ws") is not None and not r["ws"].closed
        ]
        if len(active_routes) == 1:
            sid, route = active_routes[0]
            return sid, route, "", 200
        if len(active_routes) > 1 or len(self._network_coordinators) > 0:
            return None, None, "Multiple hosts or networks active; address /u/<NETWORK-ID>/mcp.", 400
        return None, None, "No active SNOW MCP reverse tunnel connected.", 503

    async def handle_mcp_reverse_proxy(self, request: web.Request) -> web.Response:
        """Forward HTTP requests (/mcp, /oauth/*, /.well-known/*) to owning PC via reverse WS tunnel."""
        target_route_id, route, err_msg, err_status = self._resolve_mcp_target_route(request)
        if not route or not target_route_id:
            return web.json_response({"error": err_msg}, status=err_status)

        ws = route["ws"]
        target_device_id = str(route["device_id"])

        body_bytes = await request.read()
        if len(body_bytes) > self.config.max_http_forward_bytes:
            return web.json_response({"error": "Forwarded HTTP payload exceeds limit."}, status=413)

        q_ok, q_err = self.quotas.check_and_record_transfer(target_device_id, len(body_bytes))
        if not q_ok:
            return web.json_response({"error": q_err or "Quota exceeded."}, status=429)

        subpath = request.match_info.get("subpath")
        if request.path.startswith("/u/"):
            ok_sub, fwd_path = _sanitize_forwarded_subpath(subpath, raw_request_path=request.raw_path)
            if not ok_sub:
                return web.json_response({"error": "Forbidden or invalid MCP path."}, status=404)
        else:
            ok_sub, fwd_path = _sanitize_forwarded_subpath(request.path.lstrip("/"), raw_request_path=request.raw_path)
            if not ok_sub:
                return web.json_response({"error": "Forbidden or invalid MCP path."}, status=404)

        if not _is_method_allowed_for_subpath(request.method, fwd_path):
            return web.json_response({"error": f"HTTP method '{request.method}' not allowed for '{fwd_path}'."}, status=405)

        skip_req_headers = {
            "connection",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "te",
            "trailers",
            "content-length",
            "x-snow-network-id",
            "x-snow-device-snow-id",
            "x-forwarded-prefix",
        }
        fwd_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in skip_req_headers
        }
        if request.path.startswith("/u/"):
            fwd_headers["X-Forwarded-Prefix"] = f"/u/{target_route_id}"
            if is_valid_network_id(target_route_id):
                fwd_headers["X-Snow-Network-Id"] = target_route_id
            elif is_valid_snow_id(target_route_id):
                fwd_headers["X-Snow-Device-Snow-Id"] = target_route_id
        fwd_headers["X-Forwarded-Host"] = request.host
        fwd_headers["X-Forwarded-Proto"] = request.headers.get("X-Forwarded-Proto", request.scheme or "http").split(",")[0].strip()

        req_id = uuid.uuid4().hex
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending_http_forwards[req_id] = (target_device_id, fut)

        try:
            await ws.send_json({
                "type": "mcp_http_request",
                "request_id": req_id,
                "method": request.method,
                "path": fwd_path,
                "query": request.query_string,
                "headers": fwd_headers,
                "body_b64": base64.b64encode(body_bytes).decode("ascii") if body_bytes else "",
            })
            resp_payload = await asyncio.wait_for(fut, timeout=self.config.http_forward_timeout_seconds)
        except asyncio.TimeoutError:
            return web.json_response({"error": "Timed out waiting for SNOW desktop gateway response."}, status=504)
        except Exception as exc:
            return web.json_response({"error": f"Reverse tunnel forwarding error: {exc}"}, status=502)
        finally:
            self._pending_http_forwards.pop(req_id, None)

        status_code = int(resp_payload.get("status", 200))
        resp_body_b64 = resp_payload.get("body_b64") or ""
        resp_body = base64.b64decode(resp_body_b64) if resp_body_b64 else b""
        skip_resp_headers = {"connection", "keep-alive", "transfer-encoding", "content-length", "content-encoding"}
        resp_headers = {
            str(k): str(v)
            for k, v in (resp_payload.get("headers") or {}).items()
            if str(k).lower() not in skip_resp_headers
        }
        return web.Response(status=status_code, body=resp_body, headers=resp_headers)

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
        revoked_snow_id = self._device_snow_ids.pop(device_id, None)
        if revoked_snow_id and revoked_snow_id in self._snow_routes:
            if self._snow_routes[revoked_snow_id].get("device_id") == device_id:
                self._snow_routes.pop(revoked_snow_id, None)
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
        ws_registered: bool = False

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

            hub_token = str(hello_data.get("hub_token") or "").strip()
            bootstrap_token = str(hello_data.get("bootstrap_token") or "").strip()
            ticket = str(hello_data.get("ticket") or "").strip()
            authed_network_id: Optional[str] = None
            raw_hello_snow_id = ""
            authed_pub_b64 = ""
            auth_mode = "ticket"
            hub_session_gen = 1
            bootstrap_allowed_target: Optional[str] = None

            if hub_token:
                claimed_net_id = str(hello_data.get("network_id") or "").strip().upper()
                ok_hub, hub_sess, hub_err = self._authenticate_hub_session(
                    hub_token,
                    required_network_id=claimed_net_id or None,
                )
                if not ok_hub or not hub_sess:
                    await ws.close(code=4001, message=f"Auth failed: {hub_err}".encode("utf-8"))
                    return ws
                auth_kind = str(hub_sess.get("auth_kind") or "network")
                sess_dev = str(hub_sess.get("device_id") or "").strip()
                claimed_dev = str(hello_data.get("device_id") or sess_dev or "").strip()
                if not claimed_dev or (sess_dev and claimed_dev != sess_dev):
                    await ws.close(code=4003, message=b"Device identity does not match authenticated hub session.")
                    return ws
                device_id = claimed_dev
                authed_pub_b64 = str(hub_sess.get("public_key_b64") or "")
                hub_session_gen = int(hub_sess.get("session_generation", 1) or 1)

                if auth_kind == "device":
                    auth_mode = "ed25519_device"
                    authed_snow_id = str(hub_sess.get("snow_id") or "").strip().upper()
                    claimed_snow_id = str(hello_data.get("snow_id") or authed_snow_id).strip().upper()
                    if not is_valid_snow_id(authed_snow_id) or claimed_snow_id != authed_snow_id:
                        await ws.close(code=4003, message=b"SNOW ID does not match authenticated device Ed25519 session.")
                        return ws
                    raw_hello_snow_id = authed_snow_id
                    opt_net = str(hub_sess.get("network_id") or "").strip().upper()
                    authed_network_id = opt_net if (opt_net and bool(hello_data.get("register_network_coordinator", False))) else None
                    group_id = opt_net or f"dev_{authed_snow_id}"

                    existing_route = self._snow_routes.get(raw_hello_snow_id)
                    if existing_route:
                        existing_pub = str(existing_route.get("public_key_b64") or "")
                        existing_ws = existing_route.get("ws")
                        if existing_pub and existing_pub != authed_pub_b64:
                            await ws.close(code=4003, message=b"Collision rejected: SNOW ID bound to a different public key.")
                            return ws
                        if existing_ws is not None and not existing_ws.closed and existing_ws is not ws:
                            recovery_takeover = bool(hello_data.get("recovery_takeover", False))
                            try:
                                claimed_gen = int(hello_data.get("session_generation", hub_session_gen) or hub_session_gen)
                            except (TypeError, ValueError):
                                claimed_gen = 0
                            cur_gen = int(existing_route.get("session_generation", 0) or 0)
                            if recovery_takeover and claimed_gen > cur_gen:
                                try:
                                    await existing_ws.close(code=4009, message=b"SESSION_SUPERSEDED: authenticated recovery takeover.")
                                except Exception:
                                    pass
                                hub_session_gen = claimed_gen
                            else:
                                await ws.close(code=4009, message=b"IDENTITY_CONFLICT_FENCED: active session already owns this SNOW ID.")
                                return ws
                else:
                    auth_mode = "ed25519_network"
                    authed_network_id = str(hub_sess["network_id"])
                    group_id = authed_network_id
                    raw_hello_snow_id = str(hello_data.get("snow_id") or hub_sess.get("snow_id") or "").strip().upper()
                    if raw_hello_snow_id and not is_valid_snow_id(raw_hello_snow_id):
                        await ws.close(code=4002, message=b"Invalid SNOW ID format.")
                        return ws
            elif bootstrap_token:
                claimed_net_id = str(hello_data.get("network_id") or "").strip().upper()
                claimed_dev = str(hello_data.get("device_id") or "").strip()
                ok_bs, bs_sess, bs_err = self._authenticate_bootstrap_session(
                    bootstrap_token,
                    required_network_id=claimed_net_id or None,
                    claimed_device_id=claimed_dev or None,
                )
                if not ok_bs or not bs_sess:
                    await ws.close(code=4001, message=f"Auth failed: {bs_err}".encode("utf-8"))
                    return ws
                device_id = str(bs_sess["client_device_id"])
                group_id = str(bs_sess["network_id"])
                bootstrap_allowed_target = str(bs_sess["host_device_id"])
            else:
                is_valid, claimed_dev, claimed_grp, err_msg = verify_relay_ticket(ticket, self.config.shared_secret)
                if not is_valid or not claimed_dev or not claimed_grp:
                    err_bytes = f"Auth failed: {err_msg}".encode("utf-8")
                    await ws.close(code=4001, message=err_bytes)
                    return ws

                device_id = claimed_dev
                group_id = claimed_grp

                # Optional canonical SNOW ID & reverse MCP tunnel registration
                _, claims, _ = extract_ticket_claims(ticket, self.config.shared_secret)
                ticket_snow_id = (claims.get("snow_id") or "").strip().upper() if isinstance(claims, dict) else ""
                raw_hello_snow_id = str(hello_data.get("snow_id") or ticket_snow_id or "").strip().upper()
                if raw_hello_snow_id:
                    if not is_valid_snow_id(raw_hello_snow_id):
                        await ws.close(code=4002, message=b"Invalid SNOW ID format.")
                        return ws
                    if ticket_snow_id and raw_hello_snow_id != ticket_snow_id:
                        await ws.close(code=4003, message=b"SNOW ID does not match signed relay ticket.")
                        return ws
                    existing_route = self._snow_routes.get(raw_hello_snow_id)
                    if existing_route:
                        existing_ws = existing_route.get("ws")
                        if existing_route.get("auth_mode") == "ed25519_device" and existing_ws is not None and not existing_ws.closed:
                            await ws.close(code=4003, message=b"SNOW ID owned by an authenticated Ed25519 device key.")
                            return ws
                        if existing_route.get("device_id") != device_id and existing_ws is not None and not existing_ws.closed:
                            await ws.close(code=4003, message=b"SNOW ID owned by another active session.")
                            return ws

            reg_ok, reg_err = self.registry.register(device_id, group_id, ws)
            if not reg_ok:
                await ws.close(code=4003, message=reg_err.encode("utf-8"))
                return ws
            ws_registered = True

            now = time.time()
            raw_endpoints = hello_data.get("lan_endpoints") or []
            clean_endpoints = [
                str(ep).strip() for ep in raw_endpoints[:10]
                if isinstance(ep, str) and len(ep.strip()) <= 64
            ] if isinstance(raw_endpoints, list) else []

            coord_epoch = 0
            primary_device_id: Optional[str] = None
            is_primary = False
            changed = False

            if authed_network_id and not bootstrap_allowed_target:
                coord = self._network_coordinators.get(authed_network_id)
                if coord is None:
                    coord = _NetworkCoordinatorState(network_id=authed_network_id)
                    self._network_coordinators[authed_network_id] = coord
                if device_id not in coord.hosts and len(coord.hosts) >= self.config.max_hosts_per_network:
                    self.registry.unregister(device_id)
                    await ws.close(code=4003, message=b"Maximum registered hosts reached for this network.")
                    return ws

                raw_claimed_epoch = hello_data.get("epoch", 0)
                try:
                    claimed_epoch = int(raw_claimed_epoch or 0)
                except (TypeError, ValueError):
                    claimed_epoch = 0
                if hello_data.get("claim_primary") and claimed_epoch < coord.epoch:
                    self.registry.unregister(device_id)
                    await ws.close(code=4009, message=b"COORDINATOR_FENCED: stale coordinator epoch.")
                    return ws

                try:
                    priority = int(hello_data.get("priority", 100) or 100)
                except (TypeError, ValueError):
                    priority = 100
                priority = max(0, min(priority, 10000))

                entry = _NetworkHostEntry(
                    network_id=authed_network_id,
                    device_id=device_id,
                    snow_id=raw_hello_snow_id,
                    ws=ws,
                    mcp_tunnel=bool(hello_data.get("mcp_tunnel", False)),
                    priority=priority,
                    connected_at=now,
                    last_heartbeat=now,
                    lease_expires_at=now + self.config.host_lease_seconds,
                    lan_endpoints=clean_endpoints,
                    device_name=str(hello_data.get("device_name") or "")[:128],
                    cert_fingerprint=str(hello_data.get("cert_fingerprint") or "")[:128],
                )
                coord.hosts[device_id] = entry
                primary_device_id, changed = coord.elect_primary(now)
                coord_epoch = coord.epoch
                is_primary = primary_device_id == device_id

            if raw_hello_snow_id and auth_mode == "ed25519_device":
                self._device_snow_ids[device_id] = raw_hello_snow_id
                self._snow_routes[raw_hello_snow_id] = {
                    "snow_id": raw_hello_snow_id,
                    "device_id": device_id,
                    "group_id": group_id,
                    "network_id": str(hub_sess.get("network_id") or "") if hub_token else "",
                    "public_key_b64": authed_pub_b64,
                    "auth_mode": auth_mode,
                    "session_generation": hub_session_gen,
                    "ws": ws,
                    "mcp_tunnel": bool(hello_data.get("mcp_tunnel", False)),
                    "lan_endpoints": clean_endpoints,
                    "last_seen": now,
                }
            elif raw_hello_snow_id and not authed_network_id:
                self._device_snow_ids[device_id] = raw_hello_snow_id
                self._snow_routes[raw_hello_snow_id] = {
                    "snow_id": raw_hello_snow_id,
                    "device_id": device_id,
                    "group_id": group_id,
                    "auth_mode": auth_mode,
                    "ws": ws,
                    "mcp_tunnel": bool(hello_data.get("mcp_tunnel", False)),
                    "lan_endpoints": clean_endpoints,
                    "last_seen": now,
                }

            # Send hello ack
            await ws.send_json({
                "type": "hello_ack",
                "success": True,
                "device_id": device_id,
                "group_id": group_id,
                "network_id": authed_network_id or None,
                "snow_id": raw_hello_snow_id or None,
                "epoch": coord_epoch,
                "primary_device_id": primary_device_id,
                "is_primary": is_primary,
                "lease_seconds": self.config.host_lease_seconds if authed_network_id else None,
                "max_frame_size": self.config.max_frame_size,
            })
            if authed_network_id and changed:
                await self._broadcast_coordinator_update(coord)

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
                        if authed_network_id and authed_network_id in self._network_coordinators:
                            c = self._network_coordinators[authed_network_id]
                            h_entry = c.hosts.get(device_id)
                            if h_entry:
                                now_hb = time.time()
                                h_entry.last_heartbeat = now_hb
                                h_entry.lease_expires_at = now_hb + self.config.host_lease_seconds
                        await ws.send_json({"type": "pong", "time": data.get("time")})
                        continue

                    if mtype == "heartbeat":
                        if authed_network_id and authed_network_id in self._network_coordinators:
                            c = self._network_coordinators[authed_network_id]
                            try:
                                hb_epoch = int(data.get("epoch", c.epoch) or 0)
                            except (TypeError, ValueError):
                                hb_epoch = 0
                            if data.get("claim_primary") and hb_epoch < c.epoch:
                                await ws.send_json({
                                    "type": "coordinator_fenced",
                                    "network_id": authed_network_id,
                                    "epoch": c.epoch,
                                    "primary_device_id": c.primary_device_id,
                                    "error": "COORDINATOR_FENCED: stale epoch rejected.",
                                })
                                continue
                            h_entry = c.hosts.get(device_id)
                            if h_entry:
                                now_hb = time.time()
                                h_entry.last_heartbeat = now_hb
                                h_entry.lease_expires_at = now_hb + self.config.host_lease_seconds
                                await ws.send_json({
                                    "type": "heartbeat_ack",
                                    "network_id": authed_network_id,
                                    "epoch": c.epoch,
                                    "primary_device_id": c.primary_device_id,
                                    "is_primary": c.primary_device_id == device_id,
                                    "lease_expires_at": h_entry.lease_expires_at,
                                })
                        else:
                            await ws.send_json({"type": "heartbeat_ack", "time": data.get("time")})
                        continue

                    if mtype == "coordinator_claim":
                        if authed_network_id and authed_network_id in self._network_coordinators:
                            c = self._network_coordinators[authed_network_id]
                            try:
                                claim_epoch = int(data.get("epoch", 0) or 0)
                            except (TypeError, ValueError):
                                claim_epoch = -1
                            if claim_epoch < c.epoch:
                                await ws.send_json({
                                    "type": "coordinator_fenced",
                                    "network_id": authed_network_id,
                                    "epoch": c.epoch,
                                    "primary_device_id": c.primary_device_id,
                                    "error": "COORDINATOR_FENCED: cannot claim primary with stale epoch.",
                                })
                                continue
                            c.elect_primary(time.time())
                            await ws.send_json({
                                "type": "coordinator_update",
                                "network_id": authed_network_id,
                                "primary_device_id": c.primary_device_id,
                                "epoch": c.epoch,
                            })
                        continue

                    if mtype == "deregister":
                        break

                    if mtype == "mcp_http_response":
                        req_id = data.get("request_id")
                        pending = self._pending_http_forwards.get(str(req_id or ""))
                        if pending and pending[0] == device_id and not pending[1].done():
                            pending[1].set_result(data)
                        continue

                    if mtype == "relay_frame":
                        target_id = data.get("target")
                        if bootstrap_allowed_target and target_id != bootstrap_allowed_target:
                            await ws.send_json({
                                "type": "relay_error",
                                "error_code": "BOOTSTRAP_SCOPE_DENIED",
                                "target": target_id,
                                "message": "Bootstrap tunnel is restricted to the authorized onboarding host.",
                            })
                            continue
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
                    if bootstrap_allowed_target and target_id != bootstrap_allowed_target:
                        await ws.send_json({
                            "type": "relay_error",
                            "error_code": "BOOTSTRAP_SCOPE_DENIED",
                            "target": target_id,
                            "message": "Bootstrap tunnel is restricted to the authorized onboarding host.",
                        })
                        continue
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
            if device_id and ws_registered:
                self.registry.mark_dormant(device_id)
                if authed_network_id and authed_network_id in self._network_coordinators:
                    coord = self._network_coordinators[authed_network_id]
                    removed = coord.hosts.get(device_id)
                    if removed and removed.ws is ws:
                        coord.hosts.pop(device_id, None)
                        _, changed = coord.elect_primary(time.time())
                        if not coord.hosts:
                            self._network_coordinators.pop(authed_network_id, None)
                        elif changed:
                            await self._broadcast_coordinator_update(coord)
                sid = self._device_snow_ids.get(device_id)
                if sid and sid in self._snow_routes and self._snow_routes[sid].get("ws") is ws:
                    self._snow_routes[sid]["ws"] = None
                    self._snow_routes[sid]["mcp_tunnel"] = False
                    self._snow_routes[sid]["last_seen"] = time.time()
                for req_id, (owner_dev, fut) in list(self._pending_http_forwards.items()):
                    if owner_dev == device_id and not fut.done():
                        fut.set_exception(ConnectionError("Tunnel disconnected"))

        return ws

    async def _sweep_loop(self) -> None:
        """Periodic background task sweeping stale or dead sessions and failing over expired coordinators."""
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
                await self.sweep_expired_leases()
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
