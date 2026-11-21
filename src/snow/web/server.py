"""Lightweight, localhost-only Web Dashboard server for SNOW V3.

Implements Phase 21 Recovery:
- Replaces Textual TUI with a secure Vanilla web interface on 127.0.0.1:8769.
- Uses existing authenticated Core loopback IPC and SnowMcpBridge.
- Implements strict localhost security:
  - Host and Origin header validation
  - Cryptographically secure single-use bootstrap token (60s expiry)
  - HttpOnly, SameSite=Strict session cookies
  - Anti-CSRF token verification on all mutating endpoints
  - Strict Content Security Policy (no external CDNs, scripts, or fonts)
  - Allowlisted API routes only; zero arbitrary command execution
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
from pathlib import Path
import secrets
import sys
import time
from typing import Any, Optional
import urllib.parse
import webbrowser

import aiohttp
from aiohttp import web

from snow.mcp.bridge import SnowMcpBridge

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"
DEFAULT_DASHBOARD_PORT = 8769
BOOTSTRAP_EXPIRY_SECONDS = 60.0
BOOTSTRAP_TOKEN_LIFETIME_SECONDS = BOOTSTRAP_EXPIRY_SECONDS
SESSION_IDLE_TIMEOUT_SECONDS = 3600.0  # 1 hour


class SnowWebServer:
    """Localhost-only HTTP server hosting the SNOW Web Dashboard."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = DEFAULT_DASHBOARD_PORT,
        bridge: Optional[SnowMcpBridge] = None,
        auto_open_browser: bool = True,
        transfer_server: Optional[Any] = None,
    ) -> None:
        if host not in ("127.0.0.1", "localhost"):
            raise ValueError(f"Security violation: Dashboard may only bind to loopback (127.0.0.1), got '{host}'.")

        self.host = host
        self.port = port
        self.auto_open_browser = auto_open_browser
        self.bridge = bridge or SnowMcpBridge(auto_start_core=False, is_owner_channel=True)
        self.transfer_server = transfer_server

        # Security state
        self.bootstrap_token: str = secrets.token_urlsafe(32)
        self.bootstrap_expires_at: float = time.time() + BOOTSTRAP_EXPIRY_SECONDS
        self.bootstrap_consumed: bool = False

        # Active session store: session_token -> dict
        self._sessions: dict[str, dict[str, Any]] = {}

        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._is_running: bool = False

    # =========================================================================
    # Security Middleware
    # =========================================================================

    @web.middleware
    async def security_middleware(self, request: web.Request, handler) -> web.Response:
        """Enforce Host, Origin, CSRF, and Content Security Policy headers."""
        # 1. Host header validation (DNS-rebinding prevention)
        host_header = request.headers.get("Host", "").split(":")[0].lower()
        if host_header not in ("127.0.0.1", "localhost"):
            logger.warning("Rejected request with invalid Host header: %s", request.headers.get("Host"))
            return web.Response(status=400, text="Bad Request: Invalid Host header.")

        # 2. Origin & Referer validation on mutating (POST) requests
        if request.method == "POST":
            origin = request.headers.get("Origin")
            referer = request.headers.get("Referer")
            valid_origins = (
                f"http://127.0.0.1:{self.port}",
                f"http://localhost:{self.port}",
            )
            if origin:
                clean_origin = origin.rstrip("/")
                if clean_origin not in valid_origins:
                    logger.warning("Rejected POST request with forbidden Origin: %s", origin)
                    return web.json_response(
                        {"success": False, "status": "CROSS_ORIGIN_FORBIDDEN", "error": "Forbidden: Cross-origin requests are rejected."},
                        status=403,
                    )
            elif referer:
                if not any(referer.startswith(vo) for vo in valid_origins):
                    logger.warning("Rejected POST request with forbidden Referer: %s", referer)
                    return web.json_response(
                        {"success": False, "status": "CROSS_ORIGIN_FORBIDDEN", "error": "Forbidden: Cross-origin referer rejected."},
                        status=403,
                    )

        # 3. Authentication & CSRF validation for API routes
        if request.path.startswith("/api/"):
            # Exclude bootstrap exchange endpoint from session / CSRF check
            if request.path != "/api/auth/session":
                session = self._get_valid_session(request)
                if not session:
                    return web.json_response(
                        {"success": False, "status": "UNAUTHORIZED", "error": "Authentication required."},
                        status=401,
                    )

                # Mutating endpoints require matching CSRF header
                if request.method == "POST":
                    csrf_header = request.headers.get("X-CSRF-Token", "")
                    if not csrf_header or csrf_header != session.get("csrf_token"):
                        logger.warning("Rejected mutating API request with missing or invalid CSRF token.")
                        return web.json_response(
                            {"success": False, "status": "CSRF_ERROR", "error": "Invalid or missing CSRF token."},
                            status=403,
                        )

        # Execute downstream handler
        response = await handler(request)

        # 4. Strict Security Headers
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "frame-ancestors 'none';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"

        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"

        return response

    def _get_valid_session(self, request: web.Request) -> Optional[dict[str, Any]]:
        """Validate and return active session from HttpOnly cookie."""
        cookie_token = request.cookies.get("snow_session")
        if not cookie_token or cookie_token not in self._sessions:
            return None

        session = self._sessions[cookie_token]
        now = time.time()
        if now - session["last_active"] > SESSION_IDLE_TIMEOUT_SECONDS:
            self._sessions.pop(cookie_token, None)
            return None

        session["last_active"] = now
        return session

    # =========================================================================
    # Route Handlers
    # =========================================================================

    async def handle_index(self, request: web.Request) -> web.Response:
        """Serve index.html."""
        index_file = STATIC_DIR / "index.html"
        if not index_file.is_file():
            return web.Response(status=404, text="Static index.html not found.")
        return web.FileResponse(index_file)

    async def handle_auth_session(self, request: web.Request) -> web.Response:
        """Exchange single-use bootstrap token for session cookie and CSRF token."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        token = body.get("token")
        if not token or not isinstance(token, str):
            return web.json_response({"success": False, "error": "Missing bootstrap token."}, status=400)

        now = time.time()
        if self.bootstrap_consumed or now > self.bootstrap_expires_at:
            return web.json_response(
                {"success": False, "status": "BOOTSTRAP_EXPIRED", "error": "Bootstrap token has expired or already consumed."},
                status=403,
            )

        if not secrets.compare_digest(token, self.bootstrap_token):
            return web.json_response(
                {"success": False, "status": "INVALID_TOKEN", "error": "Invalid bootstrap token."},
                status=403,
            )

        # Consume single-use bootstrap token immediately
        self.bootstrap_consumed = True

        # Generate session credentials
        session_token = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)

        self._sessions[session_token] = {
            "created_at": now,
            "last_active": now,
            "csrf_token": csrf_token,
        }

        resp = web.json_response({
            "success": True,
            "status": "AUTHENTICATED",
            "csrf_token": csrf_token,
        })
        # Set HttpOnly, SameSite=Strict cookie
        resp.set_cookie(
            "snow_session",
            session_token,
            httponly=True,
            samesite="Strict",
            path="/",
            max_age=int(SESSION_IDLE_TIMEOUT_SECONDS),
        )
        return resp

    async def handle_api_status(self, request: web.Request) -> web.Response:
        """Query Core daemon status and host telemetry."""
        session_token = request.cookies.get("snow_session")
        csrf_token = None
        if session_token and session_token in self._sessions:
            csrf_token = self._sessions[session_token].get("csrf_token")

        daemon_online = await self.bridge.daemon_manager.is_ipc_ready(timeout=0.2)
        telemetry_res = await self.bridge.windows_system_info()
        
        from snow.core.network import get_active_ip_addresses
        lan_ips = get_active_ip_addresses()

        data = {
            "success": True,
            "daemon_online": daemon_online,
            "ipc_endpoint": f"127.0.0.1:{self.bridge.port}",
            "wss_port": 8765,
            "lan_ips": lan_ips,
            "telemetry": telemetry_res.get("data") if telemetry_res.get("success") else {},
        }
        if csrf_token:
            data["csrf_token"] = csrf_token
        return web.json_response(data)

    async def handle_api_pair_state(self, request: web.Request) -> web.Response:
        """Query live pairing PIN state, countdown timer, and candidate IPs."""
        res = await self.bridge.call("get_pairing_state")
        return web.json_response(res)

    async def handle_api_devices(self, request: web.Request) -> web.Response:
        """Query connected and paired devices with authoritative transport."""
        res = await self.bridge.list_devices()
        devices = []
        if isinstance(res.get("data"), dict) and "devices" in res["data"]:
            devices = res["data"]["devices"]
        elif isinstance(res.get("devices"), list):
            devices = res["devices"]
        return web.json_response({
            "success": res.get("success", False),
            "status": res.get("status", "SUCCESS"),
            "devices": devices,
            "data": res.get("data", {}),
            "error": res.get("error"),
        })

    async def handle_api_devices_revoke(self, request: web.Request) -> web.Response:
        """Revoke a paired device from the registry."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        device_id = (body.get("device_id") or "").strip()
        if not device_id:
            return web.json_response({"success": False, "error": "Missing required field 'device_id'."}, status=400)

        # Protection: Cannot revoke local desktop node
        local_id = getattr(self.bridge.local_identity, "device_id", "desktop-core") if hasattr(self.bridge, "local_identity") else "desktop-core"
        if device_id in ("local", "desktop-core", local_id):
            return web.json_response({"success": False, "status": "FORBIDDEN", "error": "Cannot revoke the local desktop node."}, status=400)

        res = await self.bridge.call("device_revoke", {"device_id": device_id})
        return web.json_response(res)

    async def handle_api_pair_qr(self, request: web.Request) -> web.Response:
        """Generate temporary pairing PIN, QR code metadata, and vector SVG."""
        trust_tier = "owner"
        if request.method == "POST":
            try:
                body = await request.json()
                if isinstance(body, dict):
                    trust_tier = body.get("trust_tier", "owner")
            except Exception:
                pass
        elif request.method == "GET":
            trust_tier = request.query.get("trust_tier", "owner")

        res = await self.bridge.call("generate_pairing_qr", {"trust_tier": trust_tier})
        if not res.get("success"):
            return web.json_response({
                "success": False,
                "status": res.get("status", "ERROR"),
                "error": res.get("error", "Could not generate pairing QR code. Ensure SNOW daemon is running."),
            })

        payload = res.get("data", {})
        qr_text = json.dumps(payload, separators=(",", ":"))

        # Generate standalone vector SVG QR code without external dependencies
        svg_content = ""
        try:
            import qrcode
            import qrcode.image.svg
            img = qrcode.make(qr_text, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
            svg_content = img.to_string().decode("utf-8") if isinstance(img.to_string(), bytes) else str(img.to_string())
        except Exception as qre:
            logger.debug("Failed rendering QR SVG: %s", qre)

        return web.json_response({
            "success": True,
            "status": "SUCCESS",
            "data": payload,
            "svg": svg_content,
        })

    async def handle_api_files(self, request: web.Request) -> web.Response:
        """Enumerate files in the phone's storage (Full Shared Storage or SAF fallback)."""
        device_id = request.query.get("device_id", "")
        subpath = request.query.get("subpath", "")
        scope = request.query.get("scope", "full")
        show_hidden = request.query.get("show_hidden", "false").lower() in ("true", "1")
        res = await self.bridge.android_file_list(
            subpath=subpath,
            device_id=device_id,
            scope=scope,
            show_hidden=show_hidden,
        )
        items = []
        storage_mode = "saf_tree"
        folder_name = "Root"
        if isinstance(res.get("data"), dict):
            data_dict = res["data"]
            items = data_dict.get("items", [])
            storage_mode = data_dict.get("storage_mode", storage_mode)
            folder_name = data_dict.get("folder_name", folder_name)
        elif isinstance(res.get("items"), list):
            items = res["items"]
            storage_mode = res.get("storage_mode", storage_mode)
            folder_name = res.get("folder_name", folder_name)

        return web.json_response({
            "success": res.get("success", False),
            "status": res.get("status", "SUCCESS"),
            "items": items,
            "storage_mode": storage_mode,
            "folder_name": folder_name,
            "subpath": subpath,
            "data": res.get("data", {}),
            "error": res.get("error"),
        })

    async def handle_api_file_download(self, request: web.Request) -> web.Response:
        """Download a file from the phone's SAF tree to the PC transfer directory."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        device_id = body.get("device_id", "")
        file_name = body.get("file_name", "")
        subpath = body.get("subpath", "")

        if not file_name or not isinstance(file_name, str):
            return web.json_response({"success": False, "error": "Missing required field 'file_name'."}, status=400)

        res = await self.bridge.android_file_receive(
            file_name=file_name,
            subpath=subpath,
            device_id=device_id,
        )
        return web.json_response(res)

    async def handle_api_notifications(self, request: web.Request) -> web.Response:
        """List active non-sensitive notifications from the connected phone."""
        device_id = request.query.get("device_id", "")
        res = await self.bridge.android_notifications_list(device_id=device_id)
        notifications = []
        if isinstance(res.get("data"), dict) and "notifications" in res["data"]:
            notifications = res["data"]["notifications"]
        elif isinstance(res.get("notifications"), list):
            notifications = res["notifications"]
        return web.json_response({
            "success": res.get("success", False),
            "status": res.get("status", "SUCCESS"),
            "notifications": notifications,
            "data": res.get("data", {}),
            "error": res.get("error"),
        })

    async def handle_api_notification_dismiss(self, request: web.Request) -> web.Response:
        """Dismiss an active notification on the phone."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        key = body.get("key", "")
        device_id = body.get("device_id", "")
        if not key:
            return web.json_response({"success": False, "error": "Missing notification 'key'."}, status=400)

        res = await self.bridge.android_notification_dismiss(key=key, device_id=device_id)
        return web.json_response(res)

    async def handle_api_notification_reply(self, request: web.Request) -> web.Response:
        """Send a Quick Reply to an active notification on the phone."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        key = body.get("key", "")
        text = body.get("text", "")
        device_id = body.get("device_id", "")
        if not key or not text:
            return web.json_response({"success": False, "error": "Both 'key' and 'text' are required."}, status=400)

        res = await self.bridge.android_notification_reply(key=key, text=text, device_id=device_id)
        return web.json_response(res)

    async def handle_api_media(self, request: web.Request) -> web.Response:
        """Control media playback on Windows or Phone."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        action = body.get("action", "")
        target = body.get("target", "windows")
        device_id = body.get("device_id", "")

        res = await self.bridge.media_control(action=action, target=target, device_id=device_id)
        return web.json_response(res)

    async def handle_api_share(self, request: web.Request) -> web.Response:
        """Share a link or note with target device."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        url = body.get("url", "")
        text = body.get("text", "")
        target = body.get("target", "windows")
        device_id = body.get("device_id", "")

        # Scheme validation: strictly enforce http/https
        if url:
            parsed = urllib.parse.urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return web.json_response(
                    {"success": False, "status": "INVALID_SCHEME", "error": f"Disallowed URL scheme '{parsed.scheme}'. Only http and https are permitted."},
                    status=400,
                )

        res = await self.bridge.share_link(url=url, text=text, target=target, device_id=device_id)
        return web.json_response(res)

    async def handle_api_approvals(self, request: web.Request) -> web.Response:
        """Query pending human-in-the-loop approval requests."""
        res = await self.bridge.call("approval_list")
        requests_list = []
        if isinstance(res.get("data"), dict) and "requests" in res["data"]:
            requests_list = res["data"]["requests"]
        elif isinstance(res.get("requests"), list):
            requests_list = res["requests"]
        elif isinstance(res.get("data"), dict) and "approvals" in res["data"]:
            requests_list = res["data"]["approvals"]
        return web.json_response({
            "success": res.get("success", False),
            "status": res.get("status", "SUCCESS"),
            "requests": requests_list,
            "approvals": requests_list,
            "data": res.get("data", {}),
            "error": res.get("error"),
        })

    async def handle_api_approvals_resolve(self, request: web.Request) -> web.Response:
        """Approve or deny a pending security authorization request."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        request_id = request.match_info.get("request_id") or body.get("request_id", "")
        decision = (body.get("decision") or "").strip().lower()

        if not request_id or decision not in ("approve", "deny"):
            return web.json_response(
                {"success": False, "error": "Valid 'request_id' and decision ('approve' or 'deny') required."},
                status=400,
            )

        op = "approval_approve" if decision == "approve" else "approval_deny"
        res = await self.bridge.call(op, payload={"request_id": request_id})
        return web.json_response(res)

    async def handle_api_capture_preview(self, request: web.Request) -> web.Response:
        """Secure, authenticated preview endpoint for captured screenshots."""
        session = self._get_valid_session(request)
        if not session:
            return web.Response(status=401, text="Unauthorized: Authentication required.")

        file_name = request.match_info.get("file_name", "").strip()

        # Strict filename traversal and path validation
        if not file_name or "/" in file_name or "\\" in file_name or ".." in file_name or "\0" in file_name:
            logger.warning("Rejected traversal attempt in capture preview: '%s'", file_name)
            return web.Response(status=404, text="File not found.")

        raw_tail = request.rel_url.raw_path.rsplit("/", 1)[-1]
        if "%2f" in raw_tail.lower() or "%5c" in raw_tail.lower() or "%2e" in raw_tail.lower():
            logger.warning("Rejected encoded traversal in capture preview: '%s'", raw_tail)
            return web.Response(status=404, text="File not found.")

        ext = Path(file_name).suffix.lower()
        if ext not in (".png", ".jpg", ".jpeg"):
            return web.Response(status=404, text="File not found.")

        from snow.capabilities.windows.screenshot import DEFAULT_CAPTURES_DIR
        captures_dir = DEFAULT_CAPTURES_DIR.resolve()
        target_path = (captures_dir / file_name).resolve()

        # Canonical path containment verification
        if not target_path.is_relative_to(captures_dir) or not target_path.is_file():
            return web.Response(status=404, text="File not found.")

        content_type = "image/png" if ext == ".png" else "image/jpeg"
        try:
            with open(target_path, "rb") as f:
                data = f.read()
            return web.Response(
                body=data,
                content_type=content_type,
                headers={
                    "X-Content-Type-Options": "nosniff",
                    "Cache-Control": "private, no-cache, must-revalidate",
                },
            )
        except Exception as exc:
            logger.error("Error reading capture file '%s': %s", file_name, exc)
            return web.Response(status=500, text="Internal error reading capture.")

    async def handle_api_workflow_run(self, request: web.Request) -> web.Response:
        """Run an authorized declarative multi-step workflow from dashboard."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        workflow_id = str(body.get("workflow_id", "")).strip()
        from snow.capabilities.workflows import WORKFLOW_REGISTRY
        if not workflow_id or workflow_id not in WORKFLOW_REGISTRY:
            return web.json_response(
                {
                    "success": False,
                    "status": "UNKNOWN_WORKFLOW",
                    "error": f"Unknown workflow ID '{workflow_id}'. Allowed: {list(WORKFLOW_REGISTRY.keys())}",
                },
                status=400,
            )

        args = body.get("arguments") or body.get("params") or {}
        res = await self.bridge.workflow_run(workflow_id, arguments=args)
        return web.json_response(res)

    async def handle_api_workflows_list(self, request: web.Request) -> web.Response:
        """List available workflow presets."""
        from snow.capabilities.workflows import WorkflowOrchestrator
        orchestrator = WorkflowOrchestrator(capability_engine=None)
        return web.json_response({
            "success": True,
            "status": "SUCCESS",
            "workflows": orchestrator.list_workflows(),
        })

    async def handle_api_activity(self, request: web.Request) -> web.Response:
        """Query secret-redacted audit activity history."""
        limit = int(request.query.get("limit", 50))
        offset = int(request.query.get("offset", 0))
        event_type = request.query.get("event_type", "")
        principal = request.query.get("principal", "")

        res = await self.bridge.activity_history(limit=limit, offset=offset, event_type=event_type, principal=principal)
        events_list = []
        if isinstance(res.get("data"), dict) and "events" in res["data"]:
            events_list = res["data"]["events"]
        elif isinstance(res.get("events"), list):
            events_list = res["events"]
        elif isinstance(res.get("data"), list):
            events_list = res["data"]
        elif isinstance(res.get("data"), dict) and "records" in res["data"]:
            events_list = res["data"]["records"]
        return web.json_response({
            "success": res.get("success", False),
            "status": res.get("status", "SUCCESS"),
            "events": events_list,
            "records": events_list,
            "data": res.get("data", {}),
            "error": res.get("error"),
        })

    async def handle_api_relay_status(self, request: web.Request) -> web.Response:
        """Query remote relay status, endpoint, and enabled state."""
        from snow.relay.config import RelayConfig
        config = RelayConfig.from_env()
        return web.json_response({
            "success": True,
            "status": "SUCCESS",
            "data": {
                "enabled": config.enabled,
                "host": config.host,
                "port": config.port,
                "endpoint": f"wss://{config.host}:{config.port}/v1/tunnel" if config.host else None,
                "max_frame_size_mib": config.max_frame_size // (1024 * 1024),
                "quota_mib_hr": config.max_transfer_quota_bytes // (1024 * 1024),
            },
        })

    async def handle_api_mcp_gateway_status(self, request: web.Request) -> web.Response:
        """Query Remote MCP Streamable HTTP Gateway status and local host integrations."""
        gw_host = "127.0.0.1"
        gw_port = 8771
        metadata_url = f"http://{gw_host}:{gw_port}/.well-known/oauth-protected-resource"

        gw_status = "offline"
        metadata = None

        try:
            timeout = aiohttp.ClientTimeout(total=0.5, connect=0.5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(metadata_url) as resp:
                    if resp.status == 200:
                        try:
                            metadata = await resp.json()
                            if isinstance(metadata, dict) and "resource" in metadata:
                                gw_status = "online"
                            else:
                                gw_status = "unhealthy"
                        except Exception:
                            gw_status = "unhealthy"
                    else:
                        gw_status = "unhealthy"
        except asyncio.TimeoutError:
            gw_status = "timeout"
        except (aiohttp.ClientConnectorError, OSError):
            gw_status = "offline"
        except Exception:
            gw_status = "unhealthy"

        # Safe AI hosts summary from HostOnboardingManager (no secrets or sensitive paths)
        safe_hosts = []
        try:
            from snow.onboarding import HostOnboardingManager
            mgr = HostOnboardingManager()
            for h in ["claude", "gemini", "cursor", "chatgpt"]:
                adapter = mgr.get_adapter(h)
                if adapter:
                    info = adapter.check_status()
                    safe_hosts.append({
                        "host": h,
                        "display_name": getattr(adapter, "display_name", h.title()),
                        "is_configured": bool(info.get("is_configured", False)),
                        "status": "CONFIGURED" if info.get("is_configured") else "NOT_CONFIGURED"
                    })
        except Exception as he:
            logger.debug("Failed compiling AI host integrations summary: %s", he)

        # Sanitize metadata if online
        safe_metadata = None
        if metadata and isinstance(metadata, dict):
            safe_metadata = {
                "resource": metadata.get("resource"),
                "authorization_servers": metadata.get("authorization_servers", []),
                "scopes_supported": metadata.get("scopes_supported", []),
            }

        return web.json_response({
            "success": True,
            "status": "SUCCESS",
            "data": {
                "gateway_status": gw_status,
                "endpoint": f"http://{gw_host}:{gw_port}/mcp",
                "metadata": safe_metadata,
                "ai_hosts": safe_hosts,
            }
        })

    async def handle_api_screen_status(self, request: web.Request) -> web.Response:
        """Query live screen streaming session status for dashboard."""
        if self.transfer_server is not None:
            status = self.transfer_server.get_screen_stream_status()
            return web.json_response({"success": True, **status})

        # Production path: query via IPC
        try:
            res = await self.bridge.call("screen_stream_status")
            status = res.get("data") if isinstance(res.get("data"), dict) else {"state": "IDLE", "has_frame": False}
            return web.json_response({"success": True, **status})
        except Exception as e:
            logger.debug("Failed querying screen status via IPC: %s", e)
            return web.json_response({"success": True, "state": "IDLE", "has_frame": False})

    async def handle_api_screen_frame(self, request: web.Request) -> web.Response:
        """Serve latest live screen JPEG frame to authenticated dashboard."""
        # Test fallback: direct access if transfer_server injected into same process
        if self.transfer_server is not None:
            frame_dict = self.transfer_server.get_latest_screen_frame()
            if not frame_dict or not frame_dict.get("frame_bytes"):
                return web.Response(status=204)
            return web.Response(
                body=frame_dict["frame_bytes"],
                content_type="image/jpeg",
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate",
                    "X-Content-Type-Options": "nosniff",
                    "X-Snow-Session-Id": str(frame_dict.get("session_id", "")),
                    "X-Snow-Timestamp": str(frame_dict.get("timestamp", 0)),
                },
            )

        # Production path: authenticated local-only HTTP proxy to transfer server
        from snow.core.ipc import get_default_secret_path
        secret_file = get_default_secret_path()
        if not secret_file.exists():
            return web.Response(status=204)

        secret = secret_file.read_text("utf-8").strip()
        if not secret:
            return web.Response(status=204)

        try:
            # Query status via IPC to get transfer port and TLS mode
            status_res = await self.bridge.call("screen_stream_status")
            status_data = status_res.get("data") if isinstance(status_res.get("data"), dict) else {}
            transfer_port = status_data.get("transfer_port") or 8766
            use_tls = status_data.get("use_tls", False)

            scheme = "https" if use_tls else "http"
            url = f"{scheme}://127.0.0.1:{transfer_port}/api/v1/screen/frame"

            import ssl
            import aiohttp
            ssl_ctx = None
            if use_tls:
                from snow.security.tls import DEFAULT_CERT_FILE, DEFAULT_TLS_DIR
                custom_cert_path = status_data.get("cert_path")
                cert_path = Path(custom_cert_path) if custom_cert_path else (DEFAULT_TLS_DIR / DEFAULT_CERT_FILE)
                if not cert_path.is_file():
                    logger.warning("TLS enabled on transfer server but certificate not found at %s", cert_path)
                    return web.Response(status=502, text="Transfer server TLS certificate not found.")

                try:
                    ssl_ctx = ssl.create_default_context(cafile=str(cert_path))
                except Exception as ssl_err:
                    logger.error("Failed creating verified SSL context for loopback frame proxy: %s", ssl_err)
                    return web.Response(status=502, text="Invalid TLS configuration.")

            headers = {
                "X-Snow-Ipc-Secret": secret,
            }

            timeout = aiohttp.ClientTimeout(total=2.0)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(url, headers=headers, ssl=ssl_ctx) as resp:
                    if resp.status == 200:
                        frame_bytes = await resp.read()
                        if frame_bytes:
                            return web.Response(
                                body=frame_bytes,
                                content_type="image/jpeg",
                                headers={
                                    "Cache-Control": "no-store, no-cache, must-revalidate",
                                    "X-Content-Type-Options": "nosniff",
                                    "X-Snow-Session-Id": resp.headers.get("X-Snow-Session-Id", ""),
                                    "X-Snow-Timestamp": resp.headers.get("X-Snow-Timestamp", "0"),
                                },
                            )
                    return web.Response(status=204)
        except (aiohttp.ClientSSLError, ssl.SSLError) as ssl_err:
            logger.error("Screen frame proxy TLS verification failed: %s", ssl_err)
            return web.Response(status=502, text=f"TLS verification failed: {ssl_err}")
        except Exception as e:
            logger.debug("Screen frame proxy error: %s", e)
            return web.Response(status=204)

    async def handle_api_screen_stop(self, request: web.Request) -> web.Response:
        """Stop live screen streaming session from dashboard."""
        if self.transfer_server is not None:
            self.transfer_server.set_session_state("all", "STOPPED")

        try:
            if self.bridge and hasattr(self.bridge, "call"):
                res = self.bridge.call("screen_stream_stop")
                if asyncio.iscoroutine(res) or inspect.isawaitable(res):
                    res = await res
                if isinstance(res, dict):
                    if res.get("status") in (None, "SUCCESS"):
                        res["status"] = "STOPPED"
                    return web.json_response(res)
            return web.json_response({"success": True, "status": "STOPPED", "data": {}})
        except Exception as e:
            logger.debug("Could not signal stop screen sharing via bridge: %s", e)
            return web.json_response({"success": False, "status": "ERROR", "error": str(e)}, status=500)

    async def handle_api_camera_latest(self, request: web.Request) -> web.Response:
        """Serve latest delivered Android camera photo with strict path containment."""
        from snow.capabilities.windows.screenshot import DEFAULT_CAPTURES_DIR
        from snow.transfer.storage import TransferStorageManager

        # Resolve canonical storage roots
        canonical_roots: list[Path] = [
            DEFAULT_CAPTURES_DIR.resolve(),
            TransferStorageManager().root_dir.resolve(),
        ]
        if self.transfer_server is not None and hasattr(self.transfer_server, "storage_manager"):
            canonical_roots.append(self.transfer_server.storage_manager.root_dir.resolve())

        candidates: list[Path] = []
        for sdir in canonical_roots:
            if sdir.is_dir():
                for pat in ("android_photo_*.jpg", "android_photo_*.jpeg", "android_photo_*.png"):
                    for f in sdir.rglob(pat):
                        try:
                            resolved = f.resolve()
                            if any(resolved.is_relative_to(root) for root in canonical_roots) and resolved.is_file():
                                candidates.append(resolved)
                        except (PermissionError, RuntimeError, OSError):
                            pass

        if not candidates:
            return web.Response(status=204)

        # Sort by mtime descending
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        latest_file = candidates[0]

        try:
            with open(latest_file, "rb") as f:
                data = f.read()
            mime = "image/png" if latest_file.suffix.lower() == ".png" else "image/jpeg"
            return web.Response(
                body=data,
                content_type=mime,
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate",
                    "X-Content-Type-Options": "nosniff",
                    "X-Snow-Filename": latest_file.name,
                },
            )
        except Exception as exc:
            logger.error("Failed reading latest camera photo '%s': %s", latest_file, exc)
            return web.Response(status=500, text="Internal error reading camera photo.")

    # =========================================================================
    # Phase 26B: Clipboard & Capture Hub & Remote Apps Handlers
    # =========================================================================

    async def handle_api_clipboard_buffer_list(self, request: web.Request) -> web.Response:
        """List metadata for the latest items in the shared clipboard buffer."""
        limit = int(request.query.get("limit", 10))
        res = await self.bridge.call("clipboard_buffer_list", {"limit": limit})
        return web.json_response(res)

    async def handle_api_clipboard_buffer_add(self, request: web.Request) -> web.Response:
        """Add text content to the shared clipboard buffer."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        text = body.get("text", "")
        is_pinned = bool(body.get("is_pinned", False))
        res = await self.bridge.call("clipboard_buffer_add", {"text": text, "is_pinned": is_pinned})
        return web.json_response(res)

    async def handle_api_clipboard_buffer_pin(self, request: web.Request) -> web.Response:
        """Pin an item in the shared clipboard buffer."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        item_id = body.get("item_id", "")
        res = await self.bridge.call("clipboard_buffer_pin", {"item_id": item_id})
        return web.json_response(res)

    async def handle_api_clipboard_buffer_unpin(self, request: web.Request) -> web.Response:
        """Unpin an item in the shared clipboard buffer."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        item_id = body.get("item_id", "")
        res = await self.bridge.call("clipboard_buffer_unpin", {"item_id": item_id})
        return web.json_response(res)

    async def handle_api_clipboard_buffer_delete(self, request: web.Request) -> web.Response:
        """Delete an item from the shared clipboard buffer."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        item_id = body.get("item_id", "")
        res = await self.bridge.call("clipboard_buffer_delete", {"item_id": item_id})
        return web.json_response(res)

    async def handle_api_clipboard_buffer_clear(self, request: web.Request) -> web.Response:
        """Clear all unpinned items from the shared clipboard buffer."""
        res = await self.bridge.call("clipboard_buffer_clear", {})
        return web.json_response(res)

    async def handle_api_clipboard_buffer_apply(self, request: web.Request) -> web.Response:
        """Apply an item to local Windows clipboard or remote Android device."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        item_id = body.get("item_id", "")
        target = str(body.get("target", "pc")).strip().lower()
        if target in ("pc", "windows", "local"):
            res = await self.bridge.call("clipboard_buffer_apply", {"item_id": item_id, "target": target})
        else:
            res = await self.bridge.call("clipboard_push_to_phone", {"item_id": item_id, "device_id": target})
        return web.json_response(res)

    async def handle_api_clipboard_capture_pc(self, request: web.Request) -> web.Response:
        """Capture current Windows clipboard (text or image) into the shared buffer."""
        res = await self.bridge.call("clipboard_capture_pc", {})
        return web.json_response(res)

    async def handle_api_clipboard_pull_phone(self, request: web.Request) -> web.Response:
        """Pull clipboard from connected Android phone into the shared buffer."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        dev_id = body.get("device_id", "")
        res = await self.bridge.call("clipboard_pull_from_phone", {"device_id": dev_id})
        return web.json_response(res)

    PERMITTED_REMOTE_APPS: set[str] = {
        "notepad", "calc", "explorer", "mspaint", "taskmgr", "code", "chrome", "msedge"
    }

    async def handle_api_clipboard_image(self, request: web.Request) -> web.Response:
        """Serve authenticated clipboard thumbnail / full image from storage directory."""
        item_id = request.match_info.get("item_id", "").strip()
        import re
        if not item_id or not re.match(r"^cb_[0-9a-f]{12}_[0-9a-f]{6}$", item_id):
            return web.Response(status=400, text="Invalid item ID format. Expected format: cb_<12hex>_<6hex>.")

        # Metadata-only IPC query to resolve image hash without direct buffer injection
        res = await self.bridge.call("clipboard_buffer_get", {"item_id": item_id})
        if not res.get("success", False):
            return web.Response(status=404, text="Clipboard image not found.")

        item = res.get("data", {}).get("item")
        if not item or (item.get("type") != "image" and item.get("content_type") != "image"):
            return web.Response(status=404, text="Clipboard image not found or not an image.")

        sha256 = item.get("sha256", "")
        if not sha256:
            return web.Response(status=404, text="Clipboard image digest missing.")

        from snow.capabilities.clipboard_buffer import get_default_clipboard_storage_dir
        storage_dir = get_default_clipboard_storage_dir().resolve()
        matching = list(storage_dir.glob(f"clip_{sha256[:16]}_*.*"))
        if not matching:
            return web.Response(status=404, text="Clipboard image file not found.")

        target_file = matching[0].resolve()
        if not target_file.is_relative_to(storage_dir) or not target_file.is_file():
            return web.Response(status=403, text="Access denied.")

        try:
            with open(target_file, "rb") as f:
                data = f.read()
            mime = item.get("mime_type") or ("image/png" if target_file.suffix.lower() == ".png" else "image/jpeg")
            return web.Response(
                body=data,
                content_type=mime,
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate",
                    "X-Content-Type-Options": "nosniff",
                },
            )
        except Exception as exc:
            logger.error("Failed reading clipboard image '%s': %s", target_file, exc)
            return web.Response(status=500, text="Internal error reading image.")

    async def handle_api_apps_windows(self, request: web.Request) -> web.Response:
        """Return list of authorized allowlisted Windows productivity applications."""
        from snow.capabilities.windows.apps import ALLOWLIST_CANDIDATES
        apps = sorted([a for a in ALLOWLIST_CANDIDATES.keys() if a in self.PERMITTED_REMOTE_APPS])
        return web.json_response({"success": True, "apps": apps})

    async def handle_api_apps_windows_launch(self, request: web.Request) -> web.Response:
        """Launch an allowlisted Windows application."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        app_name = body.get("app_name", "").strip().lower()
        if not app_name:
            return web.json_response({"success": False, "error": "Missing app_name."}, status=400)
        if app_name not in self.PERMITTED_REMOTE_APPS:
            return web.json_response({
                "success": False,
                "status": "FORBIDDEN",
                "error": f"Launching '{app_name}' via Remote Apps is prohibited. Only productivity applications are permitted."
            }, status=403)
        res = await self.bridge.windows_launch_app(app_name=app_name)
        return web.json_response(res)

    async def handle_api_apps_android(self, request: web.Request) -> web.Response:
        """List launchable applications on the connected Android phone."""
        dev_id = request.query.get("device_id", "")
        limit = int(request.query.get("limit", 50))
        res = await self.bridge.android_list_apps(limit=limit, device_id=dev_id)
        return web.json_response(res)

    async def handle_api_apps_android_launch(self, request: web.Request) -> web.Response:
        """Launch an authorized application on the connected Android phone."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        pkg = body.get("package_name", "").strip()
        dev_id = body.get("device_id", "").strip()
        if not pkg:
            return web.json_response({"success": False, "error": "Missing package_name."}, status=400)
        res = await self.bridge.android_launch_app(package_name=pkg, device_id=dev_id)
        return web.json_response(res)

    # =========================================================================
    # Lifecycle
    # =========================================================================

    def _build_app(self) -> web.Application:
        """Build and configure the aiohttp application with routes and middleware."""
        app = web.Application(middlewares=[self.security_middleware])

        # Main static UI
        app.router.add_get("/", self.handle_index)
        app.router.add_static("/static", path=str(STATIC_DIR), name="static")

        # Allowlisted API routes
        app.router.add_post("/api/auth/session", self.handle_auth_session)
        app.router.add_get("/api/status", self.handle_api_status)
        app.router.add_get("/api/devices", self.handle_api_devices)
        app.router.add_post("/api/devices/revoke", self.handle_api_devices_revoke)
        app.router.add_get("/api/pair/state", self.handle_api_pair_state)
        app.router.add_get("/api/pair/qr", self.handle_api_pair_qr)
        app.router.add_post("/api/pair/qr", self.handle_api_pair_qr)
        app.router.add_get("/api/files", self.handle_api_files)
        app.router.add_post("/api/files/download", self.handle_api_file_download)
        app.router.add_get("/api/notifications", self.handle_api_notifications)
        app.router.add_post("/api/notifications/dismiss", self.handle_api_notification_dismiss)
        app.router.add_post("/api/notifications/reply", self.handle_api_notification_reply)
        app.router.add_post("/api/media", self.handle_api_media)
        app.router.add_post("/api/share", self.handle_api_share)
        app.router.add_get("/api/approvals", self.handle_api_approvals)
        app.router.add_post("/api/approvals/resolve", self.handle_api_approvals_resolve)
        app.router.add_post("/api/approvals/{request_id}/resolve", self.handle_api_approvals_resolve)
        app.router.add_get("/api/captures/{file_name}", self.handle_api_capture_preview)
        app.router.add_get("/api/workflows", self.handle_api_workflows_list)
        app.router.add_post("/api/workflows/run", self.handle_api_workflow_run)
        app.router.add_get("/api/activity", self.handle_api_activity)
        app.router.add_get("/api/relay/status", self.handle_api_relay_status)
        app.router.add_get("/api/mcp-gateway/status", self.handle_api_mcp_gateway_status)

        # Screen streaming & Camera delivery routes (Phase 26A)
        app.router.add_get("/api/screen/status", self.handle_api_screen_status)
        app.router.add_get("/api/screen/frame", self.handle_api_screen_frame)
        app.router.add_post("/api/screen/stop", self.handle_api_screen_stop)
        app.router.add_get("/api/camera/latest", self.handle_api_camera_latest)

        # Clipboard & Capture Hub (Phase 26B)
        app.router.add_get("/api/clipboard/buffer", self.handle_api_clipboard_buffer_list)
        app.router.add_post("/api/clipboard/buffer/add", self.handle_api_clipboard_buffer_add)
        app.router.add_post("/api/clipboard/buffer/pin", self.handle_api_clipboard_buffer_pin)
        app.router.add_post("/api/clipboard/buffer/unpin", self.handle_api_clipboard_buffer_unpin)
        app.router.add_post("/api/clipboard/buffer/delete", self.handle_api_clipboard_buffer_delete)
        app.router.add_post("/api/clipboard/buffer/clear", self.handle_api_clipboard_buffer_clear)
        app.router.add_post("/api/clipboard/buffer/apply", self.handle_api_clipboard_buffer_apply)
        app.router.add_post("/api/clipboard/buffer/capture_pc", self.handle_api_clipboard_capture_pc)
        app.router.add_post("/api/clipboard/buffer/pull_phone", self.handle_api_clipboard_pull_phone)
        app.router.add_get("/api/clipboard/image/{item_id}", self.handle_api_clipboard_image)

        # Remote Apps (Phase 26B)
        app.router.add_get("/api/apps/windows", self.handle_api_apps_windows)
        app.router.add_post("/api/apps/windows/launch", self.handle_api_apps_windows_launch)
        app.router.add_get("/api/apps/android", self.handle_api_apps_android)
        app.router.add_post("/api/apps/android/launch", self.handle_api_apps_android_launch)

        return app

    async def start(self) -> None:
        """Start the Web Dashboard listener on loopback port."""
        if self._is_running:
            return

        # Pre-flight port availability verification
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            sock.bind((self.host, self.port))
            sock.close()
        except OSError as oe:
            raise OSError(
                f"Dashboard port {self.port} on {self.host} is already in use. "
                "Specify an alternative port with --port or terminate conflicting service."
            ) from oe

        self._app = self._build_app()
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()

        self._site = web.TCPSite(self._runner, self.host, self.port)
        await self._site.start()
        self._is_running = True

        launch_url = f"http://{self.host}:{self.port}/#token={self.bootstrap_token}"
        print(f"[+] SNOW Web Dashboard listening on http://{self.host}:{self.port}")
        print(f"    Secure Bootstrap URL: {launch_url}")
        print("    (Bootstrap token expires in 60s and is consumed upon first browser connection)")

        if self.auto_open_browser:
            try:
                webbrowser.open(launch_url)
            except Exception as wbe:
                logger.debug("Could not launch default browser automatically: %s", wbe)

    async def stop(self) -> None:
        """Gracefully release server listener and invalidate sessions."""
        if not self._is_running:
            return

        logger.info("Stopping SNOW Web Dashboard...")
        self._is_running = False

        # Invalidate all credentials
        self.bootstrap_consumed = True
        self._sessions.clear()

        if self._runner:
            await self._runner.cleanup()
            self._runner = None
            self._site = None
            self._app = None

        print("[+] SNOW Web Dashboard stopped cleanly.")


def run_dashboard(port: int = DEFAULT_DASHBOARD_PORT, no_browser: bool = False) -> int:
    """Synchronous launcher for 'snow web' CLI command."""
    server = SnowWebServer(
        host="127.0.0.1",
        port=port,
        auto_open_browser=not no_browser,
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(server.start())
        print("\nPress Ctrl+C to terminate dashboard.")
        loop.run_forever()
    except KeyboardInterrupt:
        print("\nShutdown requested by user...")
    except OSError as err:
        print(f"[-] Failed launching dashboard: {err}", file=sys.stderr)
        return 1
    finally:
        loop.run_until_complete(server.stop())
        loop.close()

    return 0
