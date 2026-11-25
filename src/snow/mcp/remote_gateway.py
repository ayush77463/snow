"""Remote MCP Streamable HTTP Gateway with OAuth 2.1 and FastMCP Tools for SNOW.

Exposes the standardized Model Context Protocol over Streamable HTTP (/mcp)
according to the 2024-11-05 MCP specification, secured by OAuth 2.1 with PKCE,
strict DNS-rebinding protection, origin validation, and least-privilege
AI_MCP principal enforcement.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import html
import inspect
import json
import logging
import os
from pathlib import Path
import re
import secrets
import sys
import time
from typing import Any, Dict, List, Optional
import urllib.parse
import uuid

from aiohttp import web

from snow import __version__ as SNOW_VERSION
from snow.mcp.bridge import SnowMcpBridge
from snow.mcp.oauth import OAuthServer
from snow.mcp.registry import get_capability_metadata, list_capabilities
from snow.mcp.server import create_snow_mcp_server

logger = logging.getLogger(__name__)

DEFAULT_GATEWAY_HOST: str = "127.0.0.1"
DEFAULT_GATEWAY_PORT: int = 8771
SUPPORTED_MCP_PROTOCOL_VERSIONS: list[str] = [
    "2026-07-28",
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
]
MCP_PROTOCOL_VERSION: str = SUPPORTED_MCP_PROTOCOL_VERSIONS[0]
PUBLIC_ICON_PATHS: frozenset[str] = frozenset({
    "/favicon.ico",
    "/snow_logo.png",
    "/icon.png",
    "/apple-touch-icon.png",
})


class BoundedRateLimiter:
    """Thread-safe bounded in-memory sliding-window rate limiter."""

    def __init__(self, limit: int = 30, window_seconds: float = 60.0, max_keys: int = 1000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._records: dict[str, list[float]] = {}
        self._lock = asyncio.Lock()

    async def is_allowed(self, key: str) -> tuple[bool, int]:
        now = time.time()
        async with self._lock:
            if key not in self._records:
                if len(self._records) >= self.max_keys:
                    expired = [k for k, v in self._records.items() if not v or (now - v[-1]) > self.window]
                    for k in expired:
                        self._records.pop(k, None)
                    if len(self._records) >= self.max_keys:
                        oldest = min(self._records.keys(), key=lambda k: self._records[k][0] if self._records[k] else 0)
                        self._records.pop(oldest, None)
                self._records[key] = []

            timestamps = [ts for ts in self._records[key] if now - ts < self.window]
            self._records[key] = timestamps

            if len(timestamps) >= self.limit:
                oldest_in_window = timestamps[0]
                retry_after = max(1, int(self.window - (now - oldest_in_window)))
                return False, retry_after

            self._records[key].append(now)
            return True, 0


def parse_trusted_proxies(proxies_arg: Optional[str] = None) -> set[str]:
    """Parse comma-separated trusted proxy list from CLI, environment, or default."""
    raw = proxies_arg or os.environ.get("SNOW_MCP_TRUSTED_PROXIES") or "127.0.0.1,::1"
    proxies = set()
    for item in raw.split(","):
        cleaned = item.strip().lower()
        if cleaned:
            proxies.add(cleaned)
    return proxies


def get_client_ip(request: web.Request, trusted_proxies: Optional[set[str]] = None) -> str:
    """Safely obtain client IP, ignoring untrusted X-Forwarded-For headers."""
    peername = request.transport.get_extra_info("peername") if request.transport else None
    direct_ip = peername[0] if peername and isinstance(peername, tuple) else (request.remote or "127.0.0.1")
    if trusted_proxies and direct_ip in trusted_proxies:
        xff = request.headers.get("X-Forwarded-For")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            if parts:
                return parts[0]
    return direct_ip


def redact_sensitive_topology(data: Any) -> Any:
    """Recursively scrub credentials, tickets, and keys from topology payload."""
    if isinstance(data, dict):
        clean = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            if any(s in k_lower for s in ("ticket", "secret", "private_key", "token_hash", "auth_token", "pin", "password", "credential", "pairing_token")):
                continue
            clean[k] = redact_sensitive_topology(v)
        return clean
    elif isinstance(data, list):
        return [redact_sensitive_topology(item) for item in data]
    return data


def build_oauth_redirect_url(redirect_uri: str, params: dict[str, str]) -> str:
    """Safely construct an OAuth redirect URL using urllib.parse, preserving existing query params."""
    parsed = urllib.parse.urlparse(redirect_uri)
    existing_qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    for k, v in params.items():
        if v is not None:
            existing_qs.append((k, str(v)))
    new_query = urllib.parse.urlencode(existing_qs)
    return urllib.parse.urlunparse((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        parsed.params,
        new_query,
        parsed.fragment,
    ))


class RemoteMcpGateway:
    """Streamable HTTP and SSE Gateway for SNOW MCP."""

    def __init__(
        self,
        host: str = DEFAULT_GATEWAY_HOST,
        port: int = DEFAULT_GATEWAY_PORT,
        bridge: Optional[SnowMcpBridge] = None,
        issuer: Optional[str] = None,
        public_url: Optional[str] = None,
        trusted_proxies: Optional[set[str]] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.bridge = bridge or SnowMcpBridge(is_owner_channel=False)
        env_pub = os.environ.get("SNOW_MCP_PUBLIC_URL")
        self.public_url = (public_url or env_pub or "").strip().rstrip("/") or None
        self.trusted_proxies = parse_trusted_proxies() if trusted_proxies is None else set(trusted_proxies)

        if self.public_url:
            self.issuer = self.public_url
        else:
            self.issuer = (issuer or f"http://{host}:{port}").rstrip("/")

        cap_eng = getattr(self.bridge, "capability_engine", None)
        db_mgr = getattr(cap_eng, "db_manager", None) if cap_eng else None
        self.oauth_server = OAuthServer(issuer=self.issuer, db_manager=db_mgr)
        self.fastmcp_server = create_snow_mcp_server(bridge=self.bridge)

        # Rate limiters for OAuth endpoints: token (30/min), register (10/min), authorize (10/min)
        self.token_rate_limiter = BoundedRateLimiter(limit=30, window_seconds=60.0)
        self.register_rate_limiter = BoundedRateLimiter(limit=10, window_seconds=60.0)
        self.authorize_rate_limiter = BoundedRateLimiter(limit=10, window_seconds=60.0)
        self._consent_tokens: dict[str, dict[str, Any]] = {}
        # Owner-friendly pending authorization queue and lock
        self._pending_authorizations: dict[str, dict[str, Any]] = {}
        self._pending_auth_lock = asyncio.Lock()

        self._active_sessions: dict[str, dict[str, Any]] = {}
        self._is_paused: bool = False
        self.app = web.Application(middlewares=[self._security_middleware])
        self._setup_routes()

    @property
    def is_paused(self) -> bool:
        """Query if the gateway or underlying desktop core is currently paused."""
        if self._is_paused:
            return True
        raw = getattr(self.bridge, "is_paused", False)
        if callable(raw):
            try:
                val = raw()
                return val if isinstance(val, bool) else False
            except Exception:
                return False
        return raw if isinstance(raw, bool) else False

    def set_paused(self, paused: bool) -> None:
        """Update gateway pause state."""
        self._is_paused = bool(paused)

    def set_public_url(self, public_url: Optional[str]) -> None:
        """Update active public HTTPS URL and synchronize OAuth metadata issuer."""
        clean_url = (public_url or "").strip().rstrip("/") or None
        self.public_url = clean_url
        if clean_url:
            self.issuer = clean_url
        else:
            self.issuer = f"http://{self.host}:{self.port}".rstrip("/")
        self.oauth_server.issuer = self.issuer
        logger.info("Synchronized Remote MCP Gateway public URL: %s (issuer=%s)", self.public_url, self.issuer)

    @web.middleware
    async def _security_middleware(self, request: web.Request, handler: Any) -> web.Response:
        """Enforce DNS-rebinding protection and Origin validation."""
        allowed_base_hosts = {
            self.host.split(":")[0].strip().lower(),
            "127.0.0.1",
            "localhost",
        }
        if self.public_url:
            pub_parsed = urllib.parse.urlparse(self.public_url)
            if pub_parsed.hostname:
                allowed_base_hosts.add(pub_parsed.hostname.lower())

        # Check peer IP if behind trusted reverse proxy
        direct_ip = get_client_ip(request, trusted_proxies=None)
        is_trusted_proxy = direct_ip in self.trusted_proxies

        host_header = request.headers.get("Host", "")
        forwarded_host = request.headers.get("X-Forwarded-Host", "") if is_trusted_proxy else ""
        effective_host = (forwarded_host or host_header).split(":")[0].strip().lower()

        if effective_host and effective_host not in allowed_base_hosts:
            logger.warning(
                "Rejected request with invalid Host header: '%s' (effective: '%s')",
                host_header,
                effective_host,
            )
            return web.Response(
                status=421,
                text="Misdirected Request: Invalid Host header for configured service.",
            )

        # Origin header check if present (exact-path GET/HEAD exemption for public brand icons)
        clean_path = request.path or "/"
        is_public_icon_req = request.method in ("GET", "HEAD") and clean_path in PUBLIC_ICON_PATHS
        origin_header = request.headers.get("Origin")
        if origin_header and not is_public_icon_req:
            parsed = urllib.parse.urlparse(origin_header)
            origin_host = (parsed.hostname or parsed.netloc.split(":")[0] or "").strip().lower()
            if origin_host not in allowed_base_hosts:
                logger.warning("Rejected cross-origin request from Origin: '%s'", origin_header)
                return web.Response(status=403, text="Forbidden: Cross-origin access disallowed.")

        # Check system pause for /mcp requests
        if request.path.rstrip("/") == "/mcp" and self.is_paused:
            logger.info("Rejected /mcp request: SNOW is paused by owner (HTTP 503)")
            return web.Response(
                status=503,
                text="SNOW is paused by owner",
                content_type="text/plain",
            )

        return await handler(request)

    def _setup_routes(self) -> None:
        # 1. OAuth 2.1 Discovery Endpoints
        self.app.router.add_get(
            "/.well-known/oauth-protected-resource", self.handle_well_known_protected_resource
        )
        self.app.router.add_get(
            "/.well-known/oauth-authorization-server", self.handle_well_known_authorization_server
        )

        # 2. OAuth Endpoints
        self.app.router.add_post("/oauth/register", self.handle_oauth_register)
        self.app.router.add_get("/oauth/authorize", self.handle_oauth_authorize)
        self.app.router.add_post("/oauth/authorize", self.handle_oauth_authorize)
        self.app.router.add_get("/oauth/status", self.handle_oauth_status)
        self.app.router.add_post("/oauth/token", self.handle_oauth_token)
        self.app.router.add_post("/oauth/revoke", self.handle_oauth_revoke)

        # 3. Streamable HTTP /mcp Endpoints
        self.app.router.add_post("/mcp", self.handle_mcp_post)
        self.app.router.add_get("/mcp", self.handle_mcp_get_sse)
        self.app.router.add_delete("/mcp", self.handle_mcp_delete_session)

        # 4. Public Branding Icon Routes (for OAuth & ChatGPT/Claude Connectors UI)
        for icon_path in sorted(PUBLIC_ICON_PATHS):
            self.app.router.add_get(icon_path, self.handle_public_icon)

        # Health
        self.app.router.add_get("/health", self.handle_health)

    def _resolve_icon_asset(self, request_path: str) -> tuple[Optional[Path], str]:
        """Resolve local static asset path and Content-Type for public icon routes."""
        filename = request_path.rsplit("/", 1)[-1].lower()
        module_dir = Path(__file__).resolve().parent.parent
        meipass = getattr(sys, "_MEIPASS", None)
        base_dirs = [module_dir / "web" / "static"]
        if meipass:
            base_dirs.append(Path(meipass) / "snow" / "web" / "static")
            base_dirs.append(Path(meipass))
        repo_root = module_dir.parent.parent
        if filename == "favicon.ico":
            candidates = [d / "favicon.ico" for d in base_dirs] + [repo_root / "packaging" / "windows" / "snow.ico"]
            content_type = "image/x-icon"
        else:
            candidates = [d / "snow_logo.png" for d in base_dirs] + [repo_root / "snow.png"]
            content_type = "image/png"
        for cand in candidates:
            try:
                if cand.is_file():
                    return cand, content_type
            except Exception:
                pass
        return None, content_type

    async def handle_public_icon(self, request: web.Request) -> web.Response:
        """Serve public SNOW logo/favicon with CORS headers for remote AI connectors."""
        asset_path, content_type = self._resolve_icon_asset(request.path or "/snow_logo.png")
        if asset_path is None:
            return web.Response(status=404, text="Icon not found.")
        payload = asset_path.read_bytes()
        return web.Response(
            body=payload,
            content_type=content_type,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "public, max-age=86400",
                "X-Content-Type-Options": "nosniff",
            },
        )

    async def handle_health(self, request: web.Request) -> web.Response:
        return web.json_response({
            "status": "healthy",
            "service": "snow_remote_mcp_gateway",
            "mcp_version": MCP_PROTOCOL_VERSION,
        })

    # -------------------------------------------------------------------------
    # OAuth Handlers
    # -------------------------------------------------------------------------

    async def handle_well_known_protected_resource(self, request: web.Request) -> web.Response:
        return web.json_response(self.oauth_server.get_protected_resource_metadata())

    async def handle_well_known_authorization_server(self, request: web.Request) -> web.Response:
        return web.json_response(self.oauth_server.get_authorization_server_metadata())

    async def handle_oauth_register(self, request: web.Request) -> web.Response:
        """RFC 7591 Dynamic Client Registration with bounded rate limiting."""
        client_ip = get_client_ip(request, self.trusted_proxies)
        allowed, retry_after = await self.register_rate_limiter.is_allowed(client_ip)
        if not allowed:
            return web.Response(
                status=429,
                headers={"Retry-After": str(retry_after)},
                text=json.dumps({
                    "error": "rate_limit_exceeded",
                    "error_description": "Registration rate limit exceeded. Please retry later.",
                }),
                content_type="application/json",
            )

        try:
            body = await request.json()
        except Exception:
            body = {}
        client_name = body.get("client_name", "AI Assistant Client")
        redirect_uris = body.get("redirect_uris", ["http://127.0.0.1", "http://localhost", "urn:ietf:wg:oauth:2.0:oob"])
        scope = body.get("scope", "snow:mcp")
        is_confidential = body.get("token_endpoint_auth_method") == "client_secret_post"

        res = self.oauth_server.register_client(
            client_name=client_name,
            redirect_uris=redirect_uris,
            scope=scope,
            is_confidential=is_confidential,
        )
        return web.json_response(res, status=201)

    def _is_owner_authenticated(self, request: web.Request, params: dict[str, Any]) -> bool:
        """Verify whether the incoming request carries authenticated SNOW owner authority."""
        # 1. Check IPC secret from header or request params
        provided_secret = (
            request.headers.get("X-Snow-Ipc-Secret")
            or params.get("ipc_secret")
            or params.get("owner_secret")
        )
        if provided_secret:
            expected_secret = self.bridge._get_secret()
            if expected_secret and secrets.compare_digest(str(provided_secret).strip(), expected_secret.strip()):
                return True

        # 2. Check Bearer token against paired devices with trust_tier == 'owner'
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            raw_token = auth_header[7:].strip()
            db_mgr = getattr(self.bridge.capability_engine, "db_manager", None)
            if db_mgr:
                token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
                dev = db_mgr.get_paired_device_by_token_hash(token_hash)
                if dev and dev.trust_tier == "owner":
                    return True

        return False

    async def handle_oauth_authorize(self, request: web.Request) -> web.Response:
        """OAuth 2.1 Authorization Endpoint (with PKCE, owner authentication, and explicit consent)."""
        if request.method == "GET":
            params = dict(request.query)
        else:
            try:
                params = await request.json()
            except Exception:
                try:
                    post_data = await request.post()
                    params = dict(post_data)
                except Exception:
                    params = {}

        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri", "http://localhost")
        response_type = params.get("response_type")
        code_challenge = params.get("code_challenge")
        code_challenge_method = params.get("code_challenge_method", "S256")
        scope = params.get("scope", "snow:mcp")
        state = params.get("state", "")
        decision = params.get("decision", "").strip().lower()

        # Validate mandatory OAuth 2.1 parameters
        if response_type != "code":
            return web.json_response(
                {"error": "unsupported_response_type", "error_description": "Only 'code' response_type supported"},
                status=400,
            )

        if not client_id or not code_challenge:
            return web.json_response(
                {"error": "invalid_request", "error_description": "Missing client_id or code_challenge"},
                status=400,
            )

        client = self.oauth_server.get_client(client_id)
        if not client:
            return web.json_response(
                {"error": "unauthorized_client", "error_description": f"Unknown or unregistered client_id '{client_id}'"},
                status=400,
            )

        # Exact matching of redirect URI
        if redirect_uri not in client.redirect_uris:
            return web.json_response(
                {
                    "error": "invalid_request",
                    "error_description": f"Redirect URI '{redirect_uri}' is not registered for client '{client_id}'",
                },
                status=400,
            )

        if code_challenge_method != "S256":
            return web.json_response(
                {"error": "invalid_request", "error_description": "Only 'S256' code_challenge_method is supported"},
                status=400,
            )

        # Validate scopes
        supported_scopes = {"snow:mcp", "read", "write"}
        requested_scopes = set(scope.split()) if scope else {"snow:mcp"}
        if not requested_scopes.issubset(supported_scopes):
            return web.json_response(
                {"error": "invalid_scope", "error_description": f"Requested unauthorized or unsupported scope '{scope}'"},
                status=400,
            )

        # If GET request from browser: render interactive owner consent challenge screen
        if request.method == "GET":
            # Cap pending authorizations queue to 50 entries and prune stale entries
            MAX_PENDING_AUTHORIZATIONS = 50
            now = time.time()
            expired_auth = [
                k for k, v in self._pending_authorizations.items()
                if now > v.get("expires_at", 0) or v.get("status") in ("CONSUMED", "REJECTED")
            ]
            for k in expired_auth:
                self._pending_authorizations.pop(k, None)

            if len(self._pending_authorizations) >= MAX_PENDING_AUTHORIZATIONS:
                logger.warning("Rejected OAuth authorization request: pending queue capacity (%d) reached.", MAX_PENDING_AUTHORIZATIONS)
                return web.json_response(
                    {"error": "temporarily_unavailable", "error_description": "Too many pending authorization requests. Please try again later."},
                    status=429,
                )

            # Generate anti-CSRF token for the consent transaction
            csrf_token = secrets.token_urlsafe(32)
            self._consent_tokens[csrf_token] = {
                "expires_at": now + 600.0,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
            }

            # Register in pending authorization queue for 1-click dashboard & companion approval
            req_id = f"auth_req_{secrets.token_hex(8)}"
            poll_token = secrets.token_urlsafe(32)
            pending_rec = {
                "request_id": req_id,
                "poll_token": poll_token,
                "client_id": client_id,
                "client_name": client.client_name,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "created_at": now,
                "expires_at": now + 600.0,
                "status": "PENDING",
                "auth_code": None,
                "redirect_url": None,
            }
            self._pending_authorizations[req_id] = pending_rec
            self._publish_pending_oauth_to_db(pending_rec)
            self._schedule_core_oauth_event("APPROVAL_REQUESTED", {
                "request_id": req_id,
                "principal": client.client_name or client_id,
                "action": "oauth_authorize",
                "target_device": "Remote MCP Gateway",
                "risk_level": "HIGH",
                "scope": scope,
                "kind": "oauth",
            })

            # Prune expired consent tokens
            expired_csrf = [k for k, v in self._consent_tokens.items() if now > v.get("expires_at", 0)]
            for k in expired_csrf:
                self._consent_tokens.pop(k, None)

            safe_client_name = html.escape(client.client_name)
            safe_client_id = html.escape(client_id)
            safe_redirect = html.escape(redirect_uri)
            safe_scope = html.escape(scope)
            safe_state = html.escape(state)
            safe_challenge = html.escape(code_challenge)
            safe_method = html.escape(code_challenge_method)

            csp_nonce = secrets.token_urlsafe(16)
            safe_req_id = html.escape(req_id)
            safe_poll_tok = html.escape(poll_token)

            consent_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SNOW MCP - Authorize Application</title>
  <style nonce="{csp_nonce}">
    :root {{
      --bg-canvas: #f8fafc;
      --bg-card: #ffffff;
      --bg-nested: #f1f5f9;
      --text-primary: #0f172a;
      --text-secondary: #475569;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --accent: #0284c7;
      --accent-soft: rgba(2, 132, 199, 0.10);
      --accent-border: rgba(2, 132, 199, 0.28);
      --danger: #dc2626;
      --danger-soft: rgba(220, 38, 38, 0.08);
      --shadow: 0 20px 45px rgba(15, 23, 42, 0.08);
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg-canvas: #0b1120;
        --bg-card: #111a2e;
        --bg-nested: #0d1526;
        --text-primary: #f1f5f9;
        --text-secondary: #cbd5e1;
        --text-muted: #94a3b8;
        --border: #1e293b;
        --accent: #38bdf8;
        --accent-soft: rgba(56, 189, 248, 0.12);
        --accent-border: rgba(56, 189, 248, 0.30);
        --danger: #f87171;
        --danger-soft: rgba(248, 113, 113, 0.14);
        --shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
      }}
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      padding: 24px 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      background: var(--bg-canvas);
      color: var(--text-primary);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }}
    .card {{
      width: 100%;
      max-width: 520px;
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 28px;
      box-shadow: var(--shadow);
    }}
    .brand-row {{
      display: flex;
      align-items: center;
      gap: 14px;
      margin-bottom: 18px;
    }}
    .brand-logo {{
      width: 40px;
      height: 40px;
      border-radius: 10px;
      object-fit: contain;
      flex-shrink: 0;
    }}
    h1 {{
      margin: 0;
      font-size: 1.25rem;
      font-weight: 700;
      letter-spacing: -0.01em;
    }}
    .subtitle {{
      margin: 2px 0 0;
      font-size: 0.85rem;
      color: var(--text-muted);
    }}
    .one-click-banner {{
      background: var(--accent-soft);
      border: 1px solid var(--accent-border);
      border-radius: 10px;
      padding: 12px 14px;
      font-size: 0.85rem;
      line-height: 1.45;
      color: var(--text-secondary);
      margin-bottom: 16px;
    }}
    .one-click-banner strong {{
      color: var(--accent);
    }}
    .meta-box {{
      background: var(--bg-nested);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 14px;
      margin: 14px 0 18px;
      display: grid;
      gap: 8px;
      font-size: 0.88rem;
    }}
    .meta-row {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: baseline;
    }}
    .meta-label {{
      color: var(--text-muted);
      font-weight: 600;
      flex-shrink: 0;
    }}
    .meta-val {{
      color: var(--text-primary);
      text-align: right;
      word-break: break-all;
    }}
    .scope-chip {{
      display: inline-block;
      padding: 2px 8px;
      border-radius: 999px;
      background: var(--accent-soft);
      border: 1px solid var(--accent-border);
      color: var(--accent);
      font-weight: 600;
      font-size: 0.78rem;
    }}
    code {{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.82rem;
    }}
    .field-label {{
      display: block;
      font-size: 0.84rem;
      font-weight: 600;
      color: var(--text-secondary);
      margin-bottom: 6px;
    }}
    .secret-input {{
      width: 100%;
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--bg-nested);
      color: var(--text-primary);
      font-size: 0.92rem;
      margin-bottom: 14px;
    }}
    .secret-input:focus {{
      outline: 2px solid var(--accent);
      outline-offset: 1px;
    }}
    .status-note {{
      display: none;
      padding: 10px 12px;
      border-radius: 8px;
      margin-bottom: 12px;
      font-size: 0.85rem;
      border: 1px solid var(--border);
      background: var(--bg-nested);
      color: var(--text-secondary);
    }}
    .status-note.visible {{ display: block; }}
    .status-note.rejected {{
      border-color: var(--danger);
      background: var(--danger-soft);
      color: var(--danger);
    }}
    .actions {{
      display: flex;
      gap: 12px;
      margin-top: 8px;
    }}
    button {{
      flex: 1;
      padding: 11px 16px;
      border-radius: 10px;
      font-weight: 600;
      font-size: 0.92rem;
      cursor: pointer;
    }}
    .btn-deny {{
      background: var(--bg-nested);
      color: var(--text-secondary);
      border: 1px solid var(--border);
    }}
    .btn-approve {{
      background: linear-gradient(135deg, #0ea5e9, #6366f1);
      color: #ffffff;
      border: none;
    }}
  </style>
</head>
<body>
  <main class="card">
    <div class="brand-row">
      <img src="/snow_logo.png" alt="SNOW Logo" class="brand-logo" width="40" height="40">
      <div>
        <h1>SNOW MCP Authorization</h1>
        <p class="subtitle">OAuth 2.1 + PKCE Capability Bridge</p>
      </div>
    </div>

    <div class="one-click-banner">
      <strong>Approve with 1-Click in SNOW Web Dashboard or Android App</strong>
      <div>No manual secret entry required when approving from your paired dashboard or phone. This page updates automatically.</div>
    </div>

    <div class="meta-box">
      <div class="meta-row">
        <span class="meta-label">Application</span>
        <span class="meta-val">{safe_client_name}</span>
      </div>
      <div class="meta-row">
        <span class="meta-label">Client ID</span>
        <span class="meta-val"><code>{safe_client_id}</code></span>
      </div>
      <div class="meta-row">
        <span class="meta-label">Requested Scopes</span>
        <span class="meta-val"><span class="scope-chip">{safe_scope}</span></span>
      </div>
      <div class="meta-row">
        <span class="meta-label">Redirect URI</span>
        <span class="meta-val"><code>{safe_redirect}</code></span>
      </div>
    </div>

    <div id="oauth-live-status" class="status-note" role="status" aria-live="polite"></div>

    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="client_id" value="{safe_client_id}">
      <input type="hidden" name="redirect_uri" value="{safe_redirect}">
      <input type="hidden" name="response_type" value="code">
      <input type="hidden" name="code_challenge" value="{safe_challenge}">
      <input type="hidden" name="code_challenge_method" value="{safe_method}">
      <input type="hidden" name="scope" value="{safe_scope}">
      <input type="hidden" name="state" value="{safe_state}">
      <input type="hidden" name="csrf_token" value="{csrf_token}">
      <input type="hidden" name="request_id" value="{safe_req_id}">
      <label for="ipc_secret" class="field-label">Owner Authentication (Optional IPC Secret or Dashboard Approval)</label>
      <input type="password" id="ipc_secret" name="ipc_secret" class="secret-input" autocomplete="off" placeholder="Reveal in SNOW Dashboard -> AI & Settings -> Advanced & Diagnostics">
      <div class="actions">
        <button type="submit" name="decision" value="deny" class="btn-deny">Deny</button>
        <button type="submit" name="decision" value="approve" class="btn-approve">Authorize</button>
      </div>
    </form>
  </main>
  <script nonce="{csp_nonce}">
    (function () {{
      var reqId = "{safe_req_id}";
      var pollTok = "{safe_poll_tok}";
      var statusEl = document.getElementById("oauth-live-status");
      if (!reqId || !pollTok) return;
      var pollTimer = setInterval(async function () {{
        try {{
          var res = await fetch("/oauth/status?request_id=" + encodeURIComponent(reqId) + "&poll_token=" + encodeURIComponent(pollTok));
          if (!res.ok) return;
          var data = await res.json();
          if (data.status === "APPROVED" && data.redirect_url) {{
            clearInterval(pollTimer);
            window.location.href = data.redirect_url;
          }} else if (data.status === "REJECTED" || data.status === "EXPIRED") {{
            clearInterval(pollTimer);
            if (statusEl) {{
              statusEl.textContent = data.status === "REJECTED"
                ? "Authorization request was denied by owner."
                : "Authorization request expired. Please restart sign-in.";
              statusEl.className = "status-note visible rejected";
            }}
          }}
        }} catch (e) {{}}
      }}, 1000);
    }})();
  </script>
</body>
</html>"""
            csp_header = (
                "default-src 'self'; "
                f"script-src 'self' 'nonce-{csp_nonce}'; "
                f"style-src 'self' 'nonce-{csp_nonce}'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "object-src 'none'; "
                "frame-ancestors 'none';"
            )
            return web.Response(
                text=consent_html,
                content_type="text/html",
                headers={
                    "Content-Security-Policy": csp_header,
                    "Cache-Control": "no-store, no-cache, must-revalidate",
                    "Pragma": "no-cache",
                    "X-Content-Type-Options": "nosniff",
                    "Referrer-Policy": "no-referrer",
                    "X-Frame-Options": "DENY",
                },
            )

        # POST Request Handling — Rate limit consent submissions
        client_ip = get_client_ip(request, self.trusted_proxies)
        allowed, retry_after = await self.authorize_rate_limiter.is_allowed(client_ip)
        if not allowed:
            return web.Response(
                status=429,
                text=json.dumps({"error": "slow_down", "error_description": "Rate limit exceeded for authorization attempts"}),
                content_type="application/json",
                headers={"Retry-After": str(retry_after)},
            )

        if decision == "deny":
            if redirect_uri and not redirect_uri.startswith("urn:"):
                deny_params = {"error": "access_denied", "error_description": "Owner denied authorization"}
                if state:
                    deny_params["state"] = state
                target_url = build_oauth_redirect_url(redirect_uri, deny_params)
                raise web.HTTPFound(target_url)
            return web.json_response({"error": "access_denied", "error_description": "Owner denied consent."}, status=403)

        if decision != "approve":
            return web.json_response(
                {"error": "invalid_request", "error_description": "Explicit owner decision required ('decision=approve')."},
                status=400,
            )

        # CSRF validation: Required for browser form submissions (application/x-www-form-urlencoded)
        is_form_submission = (request.content_type == "application/x-www-form-urlencoded")
        csrf_in = params.get("csrf_token")
        if is_form_submission:
            if not csrf_in:
                return web.json_response(
                    {"error": "invalid_request", "error_description": "Missing CSRF token in browser form submission."},
                    status=400,
                )
            token_meta = self._consent_tokens.pop(csrf_in, None)
            now = time.time()
            if not token_meta or now > token_meta.get("expires_at", 0):
                return web.json_response(
                    {"error": "invalid_request", "error_description": "Invalid or expired consent CSRF token."},
                    status=400,
                )
            if token_meta.get("client_id") != client_id or token_meta.get("redirect_uri") != redirect_uri:
                return web.json_response(
                    {"error": "invalid_request", "error_description": "CSRF token does not match client_id or redirect_uri."},
                    status=400,
                )
        elif csrf_in:
            token_meta = self._consent_tokens.pop(csrf_in, None)
            now = time.time()
            if not token_meta or now > token_meta.get("expires_at", 0) or token_meta.get("client_id") != client_id:
                return web.json_response(
                    {"error": "invalid_request", "error_description": "Invalid or expired consent CSRF token."},
                    status=400,
                )

        # Strictly enforce owner authentication: unauthenticated callers NEVER receive authorization codes
        if not self._is_owner_authenticated(request, params):
            return web.json_response(
                {
                    "error": "unauthorized",
                    "error_description": "Owner authentication required. Unauthenticated callers cannot receive authorization codes.",
                },
                status=401,
            )

        # Issue single-use authorization code with PKCE binding and SQLite persistence
        ok, code_or_err = self.oauth_server.create_authorization_code(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            scope=scope,
        )
        if not ok:
            err_dict = code_or_err if isinstance(code_or_err, dict) else {"error": "server_error"}
            return web.json_response(err_dict, status=400)

        code = code_or_err
        if redirect_uri and not redirect_uri.startswith("urn:"):
            target_url = build_oauth_redirect_url(redirect_uri, {"code": code, **({"state": state} if state else {})})
            raise web.HTTPFound(target_url)

        return web.json_response({"code": code, "state": state})

    async def handle_oauth_token(self, request: web.Request) -> web.Response:
        """RFC 6749 Token Exchange & Rotation Endpoint with bounded rate limiting."""
        client_ip = get_client_ip(request, self.trusted_proxies)
        allowed, retry_after = await self.token_rate_limiter.is_allowed(client_ip)
        if not allowed:
            return web.Response(
                status=429,
                headers={"Retry-After": str(retry_after)},
                text=json.dumps({
                    "error": "rate_limit_exceeded",
                    "error_description": "Token endpoint rate limit exceeded. Please retry later.",
                }),
                content_type="application/json",
            )

        try:
            body = await request.json()
        except Exception:
            body = await request.post()

        grant_type = body.get("grant_type")
        client_id = body.get("client_id")
        client_secret = body.get("client_secret")

        if not client_id:
            return web.json_response(
                {"error": "invalid_request", "error_description": "Missing client_id"}, status=400
            )

        if grant_type == "authorization_code":
            code = body.get("code")
            redirect_uri = body.get("redirect_uri", "")
            code_verifier = body.get("code_verifier", "")
            ok, tok_or_err = self.oauth_server.exchange_code(
                code=code,
                client_id=client_id,
                redirect_uri=redirect_uri,
                code_verifier=code_verifier,
                client_secret=client_secret,
            )
            status_code = 200 if ok else 400
            return web.json_response(tok_or_err, status=status_code)

        elif grant_type == "refresh_token":
            refresh_tok = body.get("refresh_token")
            ok, tok_or_err = self.oauth_server.refresh_access_token(
                refresh_token=refresh_tok,
                client_id=client_id,
                client_secret=client_secret,
            )
            status_code = 200 if ok else 400
            return web.json_response(tok_or_err, status=status_code)

        return web.json_response(
            {"error": "unsupported_grant_type", "error_description": f"Unsupported grant_type: '{grant_type}'"},
            status=400,
        )

    async def handle_oauth_revoke(self, request: web.Request) -> web.Response:
        """RFC 7009 Token Revocation Endpoint."""
        try:
            body = await request.json()
        except Exception:
            body = await request.post()

        token = body.get("token")
        if token:
            self.oauth_server.revoke_token(token)
        return web.json_response({"revoked": True})

    # -------------------------------------------------------------------------
    # Streamable HTTP MCP Handlers (/mcp)
    # -------------------------------------------------------------------------

    def _verify_mcp_auth(self, request: web.Request) -> tuple[bool, Optional[str]]:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return False, "Missing or malformed Authorization header."
        token_str = auth_header[7:].strip()
        rec = self.oauth_server.validate_access_token(token_str)
        if not rec:
            return False, "Invalid or expired OAuth access token."
        return True, None

    async def handle_mcp_post(self, request: web.Request) -> web.Response:
        """Handle incoming MCP JSON-RPC 2.0 requests over Streamable HTTP."""
        is_authed, auth_err = self._verify_mcp_auth(request)
        if not is_authed:
            auth_resource = f"{self.issuer}/.well-known/oauth-protected-resource"
            return web.Response(
                status=401,
                headers={
                    "WWW-Authenticate": f'Bearer error="invalid_token", resource_metadata="{auth_resource}"'
                },
                text=json.dumps({"error": "unauthorized", "message": auth_err}),
                content_type="application/json",
            )

        try:
            rpc_req = await request.json()
        except Exception as exc:
            return web.json_response({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {exc}"},
            }, status=400)

        method = rpc_req.get("method")
        req_id = rpc_req.get("id")
        params = rpc_req.get("params") or {}

        session_id = request.headers.get("Mcp-Session-Id") or secrets.token_hex(16)
        session = self._active_sessions.setdefault(session_id, {"created_at": asyncio.get_event_loop().time()})

        # Header protocol version check
        req_proto_header = request.headers.get("MCP-Protocol-Version")
        if req_proto_header:
            if req_proto_header not in SUPPORTED_MCP_PROTOCOL_VERSIONS:
                return web.json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602,
                            "message": f"Unsupported MCP-Protocol-Version header: '{req_proto_header}'. Supported versions: {', '.join(SUPPORTED_MCP_PROTOCOL_VERSIONS)}",
                        },
                    },
                    status=400,
                    headers={
                        "Mcp-Session-Id": session_id,
                        "MCP-Protocol-Version": session.get("protocol_version", MCP_PROTOCOL_VERSION),
                    },
                )
            if "protocol_version" in session and req_proto_header != session["protocol_version"]:
                return web.json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602,
                            "message": f"Mismatched MCP-Protocol-Version header: '{req_proto_header}'. Expected negotiated version: '{session['protocol_version']}'",
                        },
                    },
                    status=400,
                    headers={
                        "Mcp-Session-Id": session_id,
                        "MCP-Protocol-Version": session["protocol_version"],
                    },
                )

        resp_headers = {
            "Mcp-Session-Id": session_id,
            "MCP-Protocol-Version": session.get("protocol_version", MCP_PROTOCOL_VERSION),
        }

        # 1. initialize
        if method == "initialize":
            client_proto = params.get("protocolVersion")
            if not client_proto:
                negotiated_proto = MCP_PROTOCOL_VERSION
            elif not isinstance(client_proto, str) or not re.match(r"^\d{4}-\d{2}-\d{2}$", client_proto):
                return web.json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602,
                            "message": f"Invalid or bogus MCP protocol version: '{client_proto}'. Supported versions: {', '.join(SUPPORTED_MCP_PROTOCOL_VERSIONS)}",
                        },
                    },
                    status=400,
                    headers={
                        "Mcp-Session-Id": session_id,
                        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                    },
                )
            elif client_proto in SUPPORTED_MCP_PROTOCOL_VERSIONS:
                negotiated_proto = client_proto
            elif client_proto < SUPPORTED_MCP_PROTOCOL_VERSIONS[-1]:
                # Version predates the earliest supported MCP version (e.g. 1999-01-01)
                return web.json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32602,
                            "message": f"Unsupported MCP protocol version: '{client_proto}'. Supported versions: {', '.join(SUPPORTED_MCP_PROTOCOL_VERSIONS)}",
                        },
                    },
                    status=400,
                    headers={
                        "Mcp-Session-Id": session_id,
                        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
                    },
                )
            else:
                # Client requested a version newer or not directly in our list;
                # fallback to highest supported version that is <= client_proto
                candidates = [v for v in SUPPORTED_MCP_PROTOCOL_VERSIONS if v <= client_proto]
                negotiated_proto = candidates[0] if candidates else SUPPORTED_MCP_PROTOCOL_VERSIONS[0]

            session["protocol_version"] = negotiated_proto
            resp_headers["MCP-Protocol-Version"] = negotiated_proto

            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": negotiated_proto,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                    },
                    "serverInfo": {
                        "name": "SNOW Remote MCP Gateway",
                        "version": SNOW_VERSION,
                    },
                },
            }
            return web.json_response(resp, headers=resp_headers)

        # 2. notifications/initialized
        if method == "notifications/initialized":
            return web.Response(status=204, headers=resp_headers)

        # 3. ping
        if method == "ping":
            return web.json_response(
                {"jsonrpc": "2.0", "id": req_id, "result": {}},
                headers=resp_headers,
            )

        # 4. tools/list
        if method == "tools/list":
            tools_list = []
            registered_fastmcp_tools = getattr(self.fastmcp_server._tool_manager, "_tools", {})
            for meta in list_capabilities():
                fastmcp_t = registered_fastmcp_tools.get(meta.name)
                input_schema = {
                    "type": "object",
                    "properties": {},
                }
                if fastmcp_t and hasattr(fastmcp_t, "parameters"):
                    input_schema = fastmcp_t.parameters

                tools_list.append({
                    "name": meta.name,
                    "description": meta.description,
                    "inputSchema": input_schema,
                    "annotations": {
                        "readOnlyHint": meta.read_only_hint,
                        "destructiveHint": meta.destructive_hint,
                    },
                })

            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools_list},
            }
            return web.json_response(resp, headers=resp_headers)

        # 5. tools/call
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}

            meta = get_capability_metadata(tool_name)
            if not meta:
                return web.json_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method or tool not found: '{tool_name}'"},
                }, headers=resp_headers)

            try:
                # Dispatch execution through FastMCP server (which routes to bridge with AI_MCP principal)
                tool_result = await self.fastmcp_server.call_tool(tool_name, arguments)
                # Parse or normalize result
                result_text = ""
                is_error = False
                if isinstance(tool_result, list):
                    texts = []
                    for item in tool_result:
                        if hasattr(item, "text"):
                            texts.append(item.text)
                        else:
                            texts.append(str(item))
                    result_text = "\n".join(texts)
                elif isinstance(tool_result, dict):
                    result_text = json.dumps(tool_result, indent=2)
                    is_error = not tool_result.get("success", True)
                else:
                    result_text = str(tool_result)

                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": result_text}],
                        "isError": is_error,
                    },
                }
                return web.json_response(resp, headers=resp_headers)

            except Exception as call_err:
                logger.error("Error executing MCP tool '%s': %s", tool_name, call_err)
                return web.json_response({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error executing tool '{tool_name}': {call_err}"}],
                        "isError": True,
                    },
                }, headers=resp_headers)

        # 6. resources/list
        if method == "resources/list":
            resp = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "resources": [
                        {
                            "uri": "snow://mesh/topology",
                            "name": "SNOW Mesh Topology",
                            "description": "Topology of participating devices, reachability, and capability authorization",
                            "mimeType": "application/json",
                        }
                    ]
                },
            }
            return web.json_response(resp, headers=resp_headers)

        # 7. resources/read
        if method == "resources/read":
            uri = params.get("uri")
            if uri == "snow://mesh/topology":
                from snow.security.context import ExecutionContext, ExecutionPrincipal
                ctx = ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="remote_gateway_resource")
                topo_data = await self.bridge.snow_mesh_topology(ctx=ctx)
                clean_topo = redact_sensitive_topology(topo_data)
                resp = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "contents": [
                            {
                                "uri": "snow://mesh/topology",
                                "mimeType": "application/json",
                                "text": json.dumps(clean_topo, indent=2),
                            }
                        ]
                    },
                }
                return web.json_response(resp, headers=resp_headers)
            return web.json_response({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32602, "message": f"Resource not found: '{uri}'"},
            }, headers=resp_headers)

        return web.json_response({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Unsupported MCP method: '{method}'"},
        }, headers=resp_headers)

    async def handle_mcp_get_sse(self, request: web.Request) -> web.StreamResponse:
        """Server-Sent Events endpoint for MCP client notifications."""
        is_authed, auth_err = self._verify_mcp_auth(request)
        if not is_authed:
            return web.Response(status=401, text=f"Unauthorized: {auth_err}")

        session_id = request.headers.get("Mcp-Session-Id") or secrets.token_hex(16)
        session = self._active_sessions.get(session_id, {})
        proto_ver = session.get("protocol_version", MCP_PROTOCOL_VERSION)

        req_proto_header = request.headers.get("MCP-Protocol-Version")
        if req_proto_header:
            if req_proto_header not in SUPPORTED_MCP_PROTOCOL_VERSIONS:
                return web.Response(
                    status=400,
                    text=f"Unsupported MCP-Protocol-Version header: '{req_proto_header}'",
                    headers={"MCP-Protocol-Version": proto_ver},
                )
            if "protocol_version" in session and req_proto_header != session["protocol_version"]:
                return web.Response(
                    status=400,
                    text=f"Mismatched MCP-Protocol-Version header: '{req_proto_header}'",
                    headers={"MCP-Protocol-Version": session["protocol_version"]},
                )

        response = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Mcp-Session-Id": session_id,
                "MCP-Protocol-Version": proto_ver,
            },
        )
        await response.prepare(request)

        # Send initial endpoint event
        endpoint_event = f"event: endpoint\ndata: {self.issuer}/mcp\n\n"
        await response.write(endpoint_event.encode("utf-8"))

        # Keep alive
        try:
            while True:
                await asyncio.sleep(15.0)
                await response.write(b": ping\n\n")
        except asyncio.CancelledError:
            pass

        return response

    async def handle_mcp_delete_session(self, request: web.Request) -> web.Response:
        """Terminate an active MCP session."""
        session_id = request.headers.get("Mcp-Session-Id")
        session = self._active_sessions.get(session_id, {}) if session_id else {}
        proto_ver = session.get("protocol_version", MCP_PROTOCOL_VERSION)

        req_proto_header = request.headers.get("MCP-Protocol-Version")
        if req_proto_header:
            if req_proto_header not in SUPPORTED_MCP_PROTOCOL_VERSIONS:
                return web.Response(
                    status=400,
                    text=f"Unsupported MCP-Protocol-Version header: '{req_proto_header}'",
                    headers={"MCP-Protocol-Version": proto_ver},
                )
            if "protocol_version" in session and req_proto_header != session["protocol_version"]:
                return web.Response(
                    status=400,
                    text=f"Mismatched MCP-Protocol-Version header: '{req_proto_header}'",
                    headers={"MCP-Protocol-Version": session["protocol_version"]},
                )

        if session_id and session_id in self._active_sessions:
            self._active_sessions.pop(session_id, None)
            return web.Response(status=204, headers={"MCP-Protocol-Version": proto_ver})
        return web.Response(status=404, text="Session not found.", headers={"MCP-Protocol-Version": proto_ver})

    # =========================================================================
    # Owner-Friendly OAuth Approval Queue (Stage 3B + Cross-Device Sync)
    # =========================================================================

    def _publish_pending_oauth_to_db(self, rec: dict[str, Any]) -> None:
        """Persist non-secret pending OAuth metadata to SQLite app_settings for Core/Android visibility."""
        db = getattr(getattr(self, "oauth_server", None), "db_manager", None)
        if not db or not hasattr(db, "set_setting"):
            return
        req_id = rec.get("request_id")
        if not req_id:
            return
        safe_meta = {
            "request_id": req_id,
            "client_id": rec.get("client_id", ""),
            "client_name": rec.get("client_name", ""),
            "scope": rec.get("scope", "snow:mcp"),
            "redirect_uri": rec.get("redirect_uri", ""),
            "created_at": rec.get("created_at", 0.0),
            "expires_at": rec.get("expires_at", 0.0),
            "status": rec.get("status", "PENDING"),
        }
        try:
            db.set_setting(f"oauth_req:{req_id}", json.dumps(safe_meta))
        except Exception as exc:
            logger.debug("Unable to publish OAuth pending record [%s]: %s", req_id, exc)

    def _clear_oauth_db_record(self, req_id: str) -> None:
        db = getattr(getattr(self, "oauth_server", None), "db_manager", None)
        if not db or not hasattr(db, "delete_setting"):
            return
        try:
            db.delete_setting(f"oauth_req:{req_id}")
            db.delete_setting(f"oauth_dec:{req_id}")
        except Exception:
            pass

    def _schedule_core_oauth_event(self, event_type: str, req_data: dict[str, Any]) -> None:
        """Best-effort async IPC notification to Core so connected owners receive push events."""
        bridge = getattr(self, "bridge", None)
        if not bridge or not hasattr(bridge, "call"):
            return
        if not inspect.iscoroutinefunction(bridge.call):
            return
        try:
            loop = asyncio.get_running_loop()
            async def _push() -> None:
                try:
                    await bridge.call(
                        "approval_oauth_event",
                        payload={"event_type": event_type, "request": req_data},
                    )
                except Exception:
                    pass
            loop.create_task(_push())
        except RuntimeError:
            pass

    def _reconcile_external_oauth_decisions(self) -> None:
        """Apply owner decisions recorded by Core/Android via SQLite app_settings."""
        db = getattr(getattr(self, "oauth_server", None), "db_manager", None)
        if not db or not hasattr(db, "get_setting"):
            return
        for req_id, rec in list(self._pending_authorizations.items()):
            if rec.get("status") != "PENDING":
                continue
            try:
                raw_dec = db.get_setting(f"oauth_dec:{req_id}")
                if not raw_dec:
                    continue
                dec_obj = json.loads(raw_dec)
                dec_status = str(dec_obj.get("status", "")).upper()
                if dec_status == "APPROVED":
                    self.approve_authorization(req_id, notify_core=False)
                elif dec_status == "REJECTED":
                    self.reject_authorization(req_id, notify_core=False)
            except Exception as exc:
                logger.debug("Error reconciling external OAuth decision for %s: %s", req_id, exc)

    def list_pending_authorizations(self) -> list[dict[str, Any]]:
        """List active pending OAuth authorization requests awaiting owner consent."""
        self._reconcile_external_oauth_decisions()
        now = time.time()
        expired = [k for k, v in self._pending_authorizations.items() if now > v.get("expires_at", 0)]
        for k in expired:
            self._pending_authorizations.pop(k, None)
            self._clear_oauth_db_record(k)
        return [
            {
                "request_id": v["request_id"],
                "client_id": v["client_id"],
                "client_name": v["client_name"],
                "scope": v["scope"],
                "redirect_uri": v["redirect_uri"],
                "created_at": v["created_at"],
                "expires_at": v["expires_at"],
                "status": v["status"],
            }
            for v in self._pending_authorizations.values()
            if v["status"] == "PENDING"
        ]

    def approve_authorization(self, request_id: str, notify_core: bool = True) -> dict[str, Any]:
        """Approve pending authorization request from owner dashboard without raw secret typing."""
        rec = self._pending_authorizations.get(request_id)
        if not rec:
            return {"success": False, "error": "Authorization request not found or expired."}
        if rec["status"] != "PENDING":
            return {"success": False, "error": f"Request is already {rec['status']}."}

        ok, code_or_err = self.oauth_server.create_authorization_code(
            client_id=rec["client_id"],
            redirect_uri=rec["redirect_uri"],
            code_challenge=rec["code_challenge"],
            code_challenge_method=rec["code_challenge_method"],
            scope=rec["scope"],
        )
        if not ok:
            return {"success": False, "error": str(code_or_err)}

        rec["status"] = "APPROVED"
        rec["auth_code"] = code_or_err
        target_redirect = build_oauth_redirect_url(
            rec["redirect_uri"],
            {"code": code_or_err, "state": rec.get("state", "")}
        )
        rec["redirect_url"] = target_redirect
        self._clear_oauth_db_record(request_id)
        if notify_core:
            self._schedule_core_oauth_event(
                "APPROVAL_RESOLVED",
                {"request_id": request_id, "decision": "APPROVE", "kind": "oauth"},
            )
        logger.info("Owner approved OAuth request [%s] for client [%s]", request_id, rec["client_id"])
        return {
            "success": True,
            "status": "APPROVED",
            "request_id": request_id,
            "code": code_or_err,
            "redirect_url": target_redirect,
        }

    def reject_authorization(self, request_id: str, notify_core: bool = True) -> dict[str, Any]:
        """Reject pending authorization request from owner dashboard."""
        rec = self._pending_authorizations.get(request_id)
        if not rec:
            return {"success": False, "error": "Authorization request not found or expired."}
        rec["status"] = "REJECTED"
        self._clear_oauth_db_record(request_id)
        if notify_core:
            self._schedule_core_oauth_event(
                "APPROVAL_RESOLVED",
                {"request_id": request_id, "decision": "DENY", "kind": "oauth"},
            )
        logger.info("Owner rejected OAuth request [%s] for client [%s]", request_id, rec["client_id"])
        return {"success": True, "status": "REJECTED", "request_id": request_id}

    async def handle_oauth_status(self, request: web.Request) -> web.Response:
        """Poll authorization status for an active request_id with strict poll_token and single-read semantics."""
        req_id = request.query.get("request_id")
        poll_tok = request.query.get("poll_token")

        if not req_id or not poll_tok:
            return web.json_response(
                {"error": "invalid_request", "error_description": "Both request_id and poll_token are required."},
                status=400,
            )

        now = time.time()
        async with self._pending_auth_lock:
            self._reconcile_external_oauth_decisions()
            rec = self._pending_authorizations.get(req_id)
            if not rec:
                return web.json_response({"status": "NOT_FOUND"}, status=404)

            expected_token = rec.get("poll_token")
            if not expected_token or not secrets.compare_digest(poll_tok, expected_token):
                logger.warning("Rejected /oauth/status poll: invalid poll_token for request [%s]", req_id)
                return web.json_response({"status": "NOT_FOUND"}, status=404)

            if now > rec.get("expires_at", 0):
                rec["status"] = "EXPIRED"
                return web.json_response({"request_id": req_id, "status": "EXPIRED"}, status=410)

            status = rec.get("status")
            if status == "PENDING":
                return web.json_response({"request_id": req_id, "status": "PENDING"})

            if status == "REJECTED":
                return web.json_response({"request_id": req_id, "status": "REJECTED"})

            if status == "APPROVED":
                # Single-read: atomically consume redirect_url and auth_code
                redirect_url = rec.pop("redirect_url", None)
                auth_code = rec.pop("auth_code", None)
                rec["status"] = "CONSUMED"
                return web.json_response({
                    "request_id": req_id,
                    "status": "APPROVED",
                    "redirect_url": redirect_url,
                    "code": auth_code,
                })

            if status == "CONSUMED":
                return web.json_response({
                    "request_id": req_id,
                    "status": "CONSUMED",
                    "error": "Authorization result has already been delivered.",
                }, status=410)

            return web.json_response({"request_id": req_id, "status": status})


def create_gateway_app(
    host: str = DEFAULT_GATEWAY_HOST,
    port: int = DEFAULT_GATEWAY_PORT,
    bridge: Optional[SnowMcpBridge] = None,
    public_url: Optional[str] = None,
    trusted_proxies: Optional[set[str]] = None,
) -> web.Application:
    """Create and configure the Remote MCP Gateway application."""
    gateway = RemoteMcpGateway(
        host=host,
        port=port,
        bridge=bridge,
        public_url=public_url,
        trusted_proxies=trusted_proxies,
    )
    return gateway.app


async def start_gateway_async(
    host: str = DEFAULT_GATEWAY_HOST,
    port: int = DEFAULT_GATEWAY_PORT,
    bridge: Optional[SnowMcpBridge] = None,
    public_url: Optional[str] = None,
    trusted_proxies: Optional[set[str]] = None,
) -> tuple[web.AppRunner, web.TCPSite, RemoteMcpGateway]:
    """Start the Remote MCP Gateway on an aiohttp AppRunner."""
    gateway = RemoteMcpGateway(
        host=host,
        port=port,
        bridge=bridge,
        public_url=public_url,
        trusted_proxies=trusted_proxies,
    )
    runner = web.AppRunner(gateway.app)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port)
    await site.start()
    endpoint_url = gateway.public_url or f"http://{host}:{port}"
    logger.info("Remote MCP Gateway running at %s/mcp", endpoint_url)
    return runner, site, gateway


def run_gateway() -> None:
    """CLI runner for Remote MCP Gateway."""
    parser = argparse.ArgumentParser(description="SNOW Remote MCP Streamable HTTP Gateway")
    parser.add_argument("--host", default=DEFAULT_GATEWAY_HOST, help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_GATEWAY_PORT, help="Port (default: 8771)")
    parser.add_argument("--public-url", default=None, help="Configured public HTTPS URL origin for reverse proxy")
    parser.add_argument(
        "--trusted-proxies",
        default=None,
        help="Comma-separated trusted proxy IPs or hostnames (default: SNOW_MCP_TRUSTED_PROXIES or 127.0.0.1,::1)",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    trusted = parse_trusted_proxies(args.trusted_proxies)
    app = create_gateway_app(
        host=args.host,
        port=args.port,
        public_url=args.public_url,
        trusted_proxies=trusted,
    )
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    run_gateway()
