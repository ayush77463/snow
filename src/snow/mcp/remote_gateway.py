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
import re
import secrets
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
    "2025-11-25",
    "2025-06-18",
    "2025-03-26",
    "2024-11-05",
]
MCP_PROTOCOL_VERSION: str = SUPPORTED_MCP_PROTOCOL_VERSIONS[0]


class RemoteMcpGateway:
    """Streamable HTTP and SSE Gateway for SNOW MCP."""

    def __init__(
        self,
        host: str = DEFAULT_GATEWAY_HOST,
        port: int = DEFAULT_GATEWAY_PORT,
        bridge: Optional[SnowMcpBridge] = None,
        issuer: Optional[str] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.bridge = bridge or SnowMcpBridge(is_owner_channel=False)
        self.issuer = issuer or f"http://{host}:{port}"
        self.oauth_server = OAuthServer(issuer=self.issuer)
        self.fastmcp_server = create_snow_mcp_server(bridge=self.bridge)

        self._active_sessions: dict[str, dict[str, Any]] = {}
        self.app = web.Application(middlewares=[self._security_middleware])
        self._setup_routes()

    @web.middleware
    async def _security_middleware(self, request: web.Request, handler: Any) -> web.Response:
        """Enforce DNS-rebinding protection and Origin validation."""
        host_header = request.headers.get("Host", "")
        # Allow loopback variants and explicitly configured host
        allowed_base_hosts = {
            self.host.split(":")[0].strip().lower(),
            "127.0.0.1",
            "localhost",
        }
        if host_header:
            req_host = host_header.split(":")[0].strip().lower()
            if req_host not in allowed_base_hosts:
                logger.warning("Rejected request with invalid Host header: '%s'", host_header)
                return web.Response(
                    status=421,
                    text="Misdirected Request: Invalid Host header for loopback service.",
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
        """RFC 7591 Dynamic Client Registration."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        client_name = body.get("client_name", "AI Assistant Client")
        redirect_uris = body.get("redirect_uris", ["http://127.0.0.1", "http://localhost"])
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
        """RFC 6749 Token Exchange & Rotation Endpoint."""
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
) -> web.Application:
    """Create and configure the Remote MCP Gateway application."""
    gateway = RemoteMcpGateway(host=host, port=port, bridge=bridge)
    return gateway.app


async def start_gateway_async(
    host: str = DEFAULT_GATEWAY_HOST,
    port: int = DEFAULT_GATEWAY_PORT,
    bridge: Optional[SnowMcpBridge] = None,
) -> tuple[web.AppRunner, web.TCPSite, RemoteMcpGateway]:
    """Start the Remote MCP Gateway on an aiohttp AppRunner."""
    gateway = RemoteMcpGateway(host=host, port=port, bridge=bridge)
    runner = web.AppRunner(gateway.app)
    await runner.setup()
    site = web.TCPSite(runner, host=host, port=port)
    await site.start()
    logger.info("Remote MCP Gateway running at http://%s:%d/mcp", host, port)
    return runner, site, gateway


def run_gateway() -> None:
    """CLI runner for Remote MCP Gateway."""
    parser = argparse.ArgumentParser(description="SNOW Remote MCP Streamable HTTP Gateway")
    parser.add_argument("--host", default=DEFAULT_GATEWAY_HOST, help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_GATEWAY_PORT, help="Port (default: 8771)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    app = create_gateway_app(host=args.host, port=args.port)
    web.run_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    run_gateway()
