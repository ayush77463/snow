"""Remote MCP Streamable HTTP Gateway with OAuth 2.1 and FastMCP Tools for SNOW.

Exposes the standardized Model Context Protocol over Streamable HTTP (/mcp)
according to the 2024-11-05 MCP specification, secured by OAuth 2.1 with PKCE,
strict DNS-rebinding protection, origin validation, and least-privilege
AI_MCP principal enforcement.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import re
import secrets
import time
from typing import Any, Dict, List, Optional
import urllib.parse
import uuid

from aiohttp import web

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

        self.oauth_server = OAuthServer(issuer=self.issuer)
        self.fastmcp_server = create_snow_mcp_server(bridge=self.bridge)

        # Rate limiters for OAuth endpoints: token (30/min), register (10/min)
        self.token_rate_limiter = BoundedRateLimiter(limit=30, window_seconds=60.0)
        self.register_rate_limiter = BoundedRateLimiter(limit=10, window_seconds=60.0)

        self._active_sessions: dict[str, dict[str, Any]] = {}
        self.app = web.Application(middlewares=[self._security_middleware])
        self._setup_routes()

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

        # Origin header check if present
        origin_header = request.headers.get("Origin")
        if origin_header:
            parsed = urllib.parse.urlparse(origin_header)
            origin_host = (parsed.hostname or parsed.netloc.split(":")[0] or "").strip().lower()
            if origin_host not in allowed_base_hosts:
                logger.warning("Rejected cross-origin request from Origin: '%s'", origin_header)
                return web.Response(status=403, text="Forbidden: Cross-origin access disallowed.")

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
        self.app.router.add_post("/oauth/token", self.handle_oauth_token)
        self.app.router.add_post("/oauth/revoke", self.handle_oauth_revoke)

        # 3. Streamable HTTP /mcp Endpoints
        self.app.router.add_post("/mcp", self.handle_mcp_post)
        self.app.router.add_get("/mcp", self.handle_mcp_get_sse)
        self.app.router.add_delete("/mcp", self.handle_mcp_delete_session)

        # Health
        self.app.router.add_get("/health", self.handle_health)

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

    async def handle_oauth_authorize(self, request: web.Request) -> web.Response:
        """OAuth 2.1 Authorization Endpoint (with PKCE)."""
        if request.method == "GET":
            params = request.query
        else:
            try:
                params = await request.json()
            except Exception:
                params = await request.post()

        client_id = params.get("client_id")
        redirect_uri = params.get("redirect_uri", "http://localhost")
        response_type = params.get("response_type")
        code_challenge = params.get("code_challenge")
        code_challenge_method = params.get("code_challenge_method", "S256")
        scope = params.get("scope", "snow:mcp")
        state = params.get("state", "")

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
        # If client expects redirect
        if redirect_uri and not redirect_uri.startswith("urn:"):
            target_url = f"{redirect_uri}?code={code}"
            if state:
                target_url += f"&state={state}"
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
                        "version": "3.0.0",
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
