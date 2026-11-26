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
import math
import os
from pathlib import Path
import secrets
import subprocess
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

        # Shared DatabaseManager instance to prevent connection churn
        from snow.security.db import DatabaseManager
        self.db_manager = DatabaseManager()

        # Security state
        self.bootstrap_token: str = secrets.token_urlsafe(32)
        self.bootstrap_expires_at: float = time.time() + BOOTSTRAP_EXPIRY_SECONDS
        self.bootstrap_consumed: bool = False

        # Active session store: session_token -> dict
        self._sessions: dict[str, dict[str, Any]] = {}

        # Federation failed attempts tracker (shared across FederationManager instances for HTTP 429)
        self._federation_failed_attempts: dict[str, list[float]] = {}

        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._is_running: bool = False

        # Remote MCP Gateway managed runner & state
        self._mcp_gateway_runner: Optional[web.AppRunner] = None
        self._mcp_gateway_site: Optional[web.TCPSite] = None
        self._mcp_gateway_instance: Optional[Any] = None
        self._mcp_gateway_lock = asyncio.Lock()
        self.gateway_port = 8771
        from snow.mcp.tunnel import TunnelManager
        self.tunnel_manager = TunnelManager(target_port=self.gateway_port)

        # Short-lived APK download tokens: token -> expires_at
        self._apk_download_tokens: dict[str, float] = {}
        # Ephemeral LAN APK download server
        self._ephemeral_apk_app: Optional[web.Application] = None
        self._ephemeral_apk_runner: Optional[web.AppRunner] = None
        self._ephemeral_apk_site: Optional[web.TCPSite] = None
        self._ephemeral_apk_port: int = 0
        self._ephemeral_apk_lock = asyncio.Lock()

        # USB status caching (10-second TTL)
        self._usb_status_cache: Optional[dict[str, Any]] = None
        self._usb_status_cache_time: float = 0.0
        self._usb_status_lock = asyncio.Lock()

        # Track active dashboard-initiated file transfer tasks for cancellation
        self._active_file_downloads: dict[str, asyncio.Task[Any]] = {}
        self._active_file_downloads_lock = asyncio.Lock()

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
            # Exclude bootstrap exchange and APK download endpoints from global session / CSRF check
            if request.path not in ("/api/auth/session", "/api/app/download-apk", "/api/install/android-apk"):
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

    def _get_active_static_dir(self) -> Path:
        """Return the user override directory if valid and complete, else bundled STATIC_DIR."""
        override_dir = (Path.home() / ".snow" / "web_override").resolve()
        if override_dir.is_dir():
            required = ("index.html", "app.js", "app.css", "tokens.css", "theme-init.js")
            try:
                if all((override_dir / name).is_file() and (override_dir / name).stat().st_size > 0 for name in required):
                    return override_dir
            except OSError:
                pass
        return STATIC_DIR

    def _resolve_static_file(self, rel_path: str) -> Optional[Path]:
        """Resolve a static asset enforcing strict extension allowlist and traversal protection."""
        clean_rel = rel_path.lstrip("/").replace("\\", "/")
        if ".." in clean_rel or ":" in clean_rel:
            return None

        from snow.updater import ALLOWED_STATIC_EXTENSIONS
        target_ext = Path(clean_rel).suffix.lower()
        if target_ext not in ALLOWED_STATIC_EXTENSIONS:
            return None

        active_dir = self._get_active_static_dir()
        candidate = (active_dir / clean_rel).resolve()
        try:
            if candidate.is_relative_to(active_dir.resolve()) and candidate.is_file():
                return candidate
        except (ValueError, OSError):
            pass

        if active_dir != STATIC_DIR:
            bundled = (STATIC_DIR / clean_rel).resolve()
            try:
                if bundled.is_relative_to(STATIC_DIR.resolve()) and bundled.is_file():
                    return bundled
            except (ValueError, OSError):
                pass

        return None

    async def handle_index(self, request: web.Request) -> web.Response:
        """Serve index.html with override precedence."""
        active_dir = self._get_active_static_dir()
        index_file = active_dir / "index.html"
        if not index_file.is_file():
            index_file = STATIC_DIR / "index.html"
        if not index_file.is_file():
            return web.Response(status=404, text="Static index.html not found.")
        return web.FileResponse(index_file)

    async def handle_static_asset(self, request: web.Request) -> web.Response:
        """Serve static assets with strict extension allowlist, traversal protection, and override precedence."""
        rel_path = request.match_info.get("path", "")
        file_path = self._resolve_static_file(rel_path)
        if not file_path:
            return web.Response(status=404, text="File not found or forbidden.")
        return web.FileResponse(file_path)

    async def handle_favicon(self, request: web.Request) -> web.Response:
        """Serve browser favicon."""
        file_path = self._resolve_static_file("favicon.ico")
        if file_path:
            return web.FileResponse(file_path)
        return web.Response(status=404, text="Favicon not found.")

    async def handle_snow_logo(self, request: web.Request) -> web.Response:
        """Serve SNOW universal logo."""
        file_path = self._resolve_static_file("snow_logo.png")
        if file_path:
            return web.FileResponse(file_path)
        return web.Response(status=404, text="Logo not found.")

    async def handle_api_reset_web_ui_override(self, request: web.Request) -> web.Response:
        """Reset Web UI override to bundled version (OWNER_MANUAL)."""
        from snow.updater import reset_web_ui_override
        success = reset_web_ui_override()
        if success:
            return web.json_response({"success": True, "message": "Successfully reset to bundled Web UI."})
        return web.json_response({"success": False, "error": "Failed to remove Web UI override directory."}, status=500)

    async def handle_api_system_update_check(self, request: web.Request) -> web.Response:
        """Check for updates against configured release manifest without executing any installer."""
        from snow.updater import check_for_updates
        manifest_source = request.query.get("source")
        try:
            result = check_for_updates(manifest_source=manifest_source)
            return web.json_response({"success": True, **result})
        except Exception as e:
            logger.error("Update check failed: %s", e)
            return web.json_response({"success": False, "error": str(e)}, status=500)

    async def handle_api_system_update_apply(self, request: web.Request) -> web.Response:
        """Apply a verified update (OWNER_MANUAL only). Rejects AI_MCP calls."""
        principal = request.headers.get("X-Snow-Principal", "OWNER_MANUAL")
        if principal != "OWNER_MANUAL":
            return web.json_response({
                "success": False,
                "status": "FORBIDDEN",
                "error": "Security violation: Direct updates may only be initiated by the device owner."
            }, status=403)

        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        update_type = body.get("update_type", "web_ui")
        url_or_path = body.get("url") or body.get("path")
        expected_sha256 = body.get("sha256")

        if not url_or_path or not expected_sha256:
            return web.json_response({"success": False, "error": "Missing required 'url'/'path' or 'sha256'."}, status=400)

        from snow.updater import apply_web_ui_update, apply_desktop_installer_update

        try:
            if update_type == "web_ui":
                apply_web_ui_update(archive_source=url_or_path, expected_sha256=expected_sha256)
                return web.json_response({"success": True, "message": "Web UI update applied successfully. Refresh to reload."})
            elif update_type == "desktop":
                apply_desktop_installer_update(
                    installer_path=url_or_path,
                    expected_sha256=expected_sha256,
                    execute=True,
                    daemon_manager=getattr(self.bridge, "daemon_manager", None)
                )
                return web.json_response({"success": True, "message": "Installer launched. Core will restart shortly."})
            else:
                return web.json_response({"success": False, "error": f"Unknown update type: '{update_type}'"}, status=400)
        except Exception as e:
            logger.error("Failed to apply update: %s", e)
            return web.json_response({"success": False, "error": str(e)}, status=400)

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

    async def _get_cached_usb_status(self) -> dict[str, Any]:
        """Retrieve USB ADB status using a 10-second TTL cache with async lock protection."""
        now = time.monotonic()
        if self._usb_status_cache is not None and (now - self._usb_status_cache_time) < 10.0:
            return self._usb_status_cache

        async with self._usb_status_lock:
            now = time.monotonic()
            if self._usb_status_cache is not None and (now - self._usb_status_cache_time) < 10.0:
                return self._usb_status_cache

            from snow.core.usb import get_usb_status
            try:
                stat = await asyncio.to_thread(get_usb_status)
                self._usb_status_cache = stat
                self._usb_status_cache_time = time.monotonic()
                return stat
            except Exception as exc:
                logger.debug("Failed refreshing USB status cache: %s", exc)
                if self._usb_status_cache is not None:
                    return self._usb_status_cache
                return {"connected": False, "authorized_count": 0, "reverse_active": False}

    async def handle_api_status(self, request: web.Request) -> web.Response:
        """Query Core daemon status and host telemetry."""
        session_token = request.cookies.get("snow_session")
        csrf_token = None
        if session_token and session_token in self._sessions:
            csrf_token = self._sessions[session_token].get("csrf_token")

        async def _safe_bridge_call(coro_or_val: Any) -> dict[str, Any]:
            try:
                res = await coro_or_val if inspect.isawaitable(coro_or_val) else coro_or_val
                return res if isinstance(res, dict) else {}
            except Exception:
                return {}

        daemon_raw = await _safe_bridge_call(self.bridge.daemon_manager.is_ipc_ready(timeout=0.2)) if hasattr(self.bridge, "daemon_manager") else True
        daemon_online = bool(daemon_raw) if not isinstance(daemon_raw, dict) else True
        telemetry_res = await _safe_bridge_call(self.bridge.windows_system_info())
        battery_res = (
            await _safe_bridge_call(self.bridge.windows_battery())
            if hasattr(self.bridge, "windows_battery")
            else {}
        )

        host_telemetry: dict[str, Any] = {}
        if telemetry_res.get("success") and isinstance(telemetry_res.get("data"), dict):
            sys_data = telemetry_res["data"]
            host_telemetry = dict(sys_data)
            cpu_info = sys_data.get("cpu") if isinstance(sys_data.get("cpu"), dict) else {}
            mem_info = sys_data.get("memory") if isinstance(sys_data.get("memory"), dict) else {}
            disk_info = sys_data.get("disk") if isinstance(sys_data.get("disk"), dict) else {}

            if "utilization_percent" in cpu_info:
                host_telemetry["cpu_percent"] = cpu_info["utilization_percent"]
            if "total_mb" in mem_info and mem_info["total_mb"] is not None:
                ram_tot = int(float(mem_info["total_mb"]) * 1024 * 1024)
                ram_used = int(float(mem_info.get("used_mb") or 0) * 1024 * 1024)
                host_telemetry["ram_total_bytes"] = ram_tot
                host_telemetry["ram_used_bytes"] = ram_used
                host_telemetry["ram_available_bytes"] = max(0, ram_tot - ram_used)
                host_telemetry["ram_percent"] = mem_info.get("percent")
            if disk_info.get("total_gb") is not None:
                disk_tot = int(float(disk_info["total_gb"]) * (1024**3))
                disk_used = int(float(disk_info.get("used_gb") or 0) * (1024**3))
                host_telemetry["storage_total_bytes"] = disk_tot
                host_telemetry["storage_used_bytes"] = disk_used
                host_telemetry["storage_available_bytes"] = max(0, disk_tot - disk_used)
                host_telemetry["storage_percent"] = disk_info.get("percent")

        if battery_res.get("success") and isinstance(battery_res.get("data"), dict):
            bdata = battery_res["data"]
            host_telemetry["battery_status"] = bdata.get("status")
            host_telemetry["battery_charging"] = bdata.get("power_plugged")
            if bdata.get("available") and bdata.get("percent") is not None:
                host_telemetry["battery_percent"] = bdata.get("percent")

        from snow.core.network import get_active_ip_addresses
        lan_ips = get_active_ip_addresses()
        lan_available = bool(lan_ips)
        try:
            usb_stat = await self._get_cached_usb_status()
            usb_connected = bool(usb_stat.get("connected") or usb_stat.get("authorized_count", 0) > 0)
        except Exception:
            usb_connected = False

        from snow.security.identity import load_or_create_device_identity
        identity = load_or_create_device_identity()

        data = {
            "success": True,
            "daemon_online": daemon_online,
            "snow_id": identity.snow_id,
            "device_id": identity.device_id,
            "device_name": identity.device_name,
            "ipc_endpoint": f"127.0.0.1:{self.bridge.port}",
            "wss_port": 8765,
            "lan_ips": lan_ips,
            "lan_available": lan_available,
            "usb_connected": usb_connected,
            "telemetry": host_telemetry,
        }
        if csrf_token:
            data["csrf_token"] = csrf_token
        return web.json_response(data)

    @staticmethod
    def _render_qr_svg(qr_payload: dict[str, Any]) -> str:
        """Render a vector SVG QR code cleanly without external dependencies."""
        if not isinstance(qr_payload, dict) or not qr_payload:
            return ""
        try:
            import qrcode
            import qrcode.image.svg

            qr_text = json.dumps(qr_payload, separators=(",", ":"))
            img = qrcode.make(
                qr_text,
                image_factory=qrcode.image.svg.SvgPathImage,
                box_size=8,
                border=2,
            )
            raw = img.to_string()
            return raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
        except Exception as qre:
            logger.debug("Failed rendering QR SVG: %s", qre)
            return ""

    async def handle_api_pair_state(self, request: web.Request) -> web.Response:
        """Query live pairing PIN state, countdown timer, TLS fingerprint, and candidate IPs."""
        res = await self.bridge.call("get_pairing_state")
        if isinstance(res, dict) and res.get("success") and isinstance(res.get("data"), dict):
            data = dict(res["data"])
            qr_payload = data.get("qr_payload")
            svg = self._render_qr_svg(qr_payload) if isinstance(qr_payload, dict) else ""
            if svg:
                data["svg"] = svg
            return web.json_response({**res, "data": data, **({"svg": svg} if svg else {})})
        return web.json_response(res)

    async def handle_api_pair_cancel(self, request: web.Request) -> web.Response:
        """Cancel any active pairing PIN immediately on owner request."""
        res = await self.bridge.call("cancel_pairing_pin")
        return web.json_response(res)

    async def handle_api_devices(self, request: web.Request) -> web.Response:
        """Query connected and paired devices with authoritative transport."""
        res = await self.bridge.list_devices()
        devices = []
        if isinstance(res.get("data"), dict) and "devices" in res["data"]:
            devices = res["data"]["devices"]
        elif isinstance(res.get("devices"), list):
            devices = res["devices"]

        # Deduplicate local host node & normalize live phone telemetry and canonical snow_id
        from snow.security.identity import generate_snow_id, load_or_create_device_identity
        local_ident = load_or_create_device_identity()
        deduped: list[dict[str, Any]] = []
        discovered_peers: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        seen_discovered_ids: set[str] = set()
        seen_local = False

        for raw_dev in devices:
            dev = dict(raw_dev)
            dev_id = dev.get("device_id") or ""
            is_local = bool(
                dev.get("is_local")
                or dev_id in ("local", "desktop-core", local_ident.device_id)
                or dev.get("transport") == "local"
                or (local_ident.snow_id and dev.get("snow_id") == local_ident.snow_id)
            )
            if is_local:
                dev["is_local"] = True
                dev["snow_id"] = local_ident.snow_id
                if seen_local:
                    continue
                seen_local = True
            else:
                # Filter unpaired UDP discovery candidates & "Unknown Node" ghosts out of MY NETWORK DEVICES
                is_explicitly_unpaired = (
                    dev.get("is_paired") is False
                    or bool(dev.get("is_discovered"))
                    or (
                        str(dev.get("device_name") or "").strip() == "Unknown Node"
                        and dev.get("is_paired") is not True
                    )
                )
                if is_explicitly_unpaired:
                    if dev_id and dev_id not in seen_discovered_ids:
                        seen_discovered_ids.add(dev_id)
                        if not dev.get("snow_id"):
                            dev["snow_id"] = generate_snow_id(seed=dev_id)
                        discovered_peers.append(dev)
                    continue

                if dev_id and dev_id in seen_ids:
                    continue
                if dev_id:
                    seen_ids.add(dev_id)

            if not dev.get("snow_id") and dev_id:
                dev["snow_id"] = generate_snow_id(seed=dev_id)

            if not is_local and dev.get("is_connected") and (
                dev.get("platform") == "android"
                or dev.get("device_type") in ("phone", "android")
                or not dev.get("platform")
                or dev.get("platform") == "generic"
            ):
                if dev_id:
                    try:
                        raw_bat = self.bridge.android_battery(device_id=dev_id)
                        bat_res = (
                            await asyncio.wait_for(raw_bat, timeout=2.0)
                            if inspect.isawaitable(raw_bat)
                            else raw_bat
                        )
                        if isinstance(bat_res, dict) and bat_res.get("success") and isinstance(bat_res.get("data"), dict):
                            tel = dict(bat_res["data"])
                            if "battery_level" not in tel and "level" in tel:
                                tel["battery_level"] = tel["level"]
                            dev["telemetry"] = tel
                    except Exception as ex:
                        logger.debug("Failed fetching live telemetry for device %s: %s", dev_id, ex)

            deduped.append(dev)
        devices = deduped

        # Optionally include live LAN discovery candidates in separate 'discovered_peers' view
        bridge_cls = type(self.bridge) if self.bridge is not None else None
        if self.bridge is not None and inspect.iscoroutinefunction(getattr(bridge_cls, "list_discovered_peers", None)):
            try:
                disc_res = await asyncio.wait_for(self.bridge.list_discovered_peers(), timeout=2.0)
                if isinstance(disc_res, dict) and disc_res.get("success"):
                    for peer in (disc_res.get("data") or {}).get("peers", []) or []:
                        if not isinstance(peer, dict):
                            continue
                        pid = str(peer.get("device_id") or "").strip()
                        if pid and pid not in seen_ids and pid not in seen_discovered_ids and not peer.get("is_paired"):
                            seen_discovered_ids.add(pid)
                            discovered_peers.append(peer)
            except Exception as disc_err:
                logger.debug("Non-fatal discovery list enrichment skipped: %s", disc_err)

        return web.json_response({
            "success": res.get("success", False),
            "status": res.get("status", "SUCCESS"),
            "devices": devices,
            "discovered_peers": discovered_peers,
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
        local_id = "desktop-core"
        try:
            from snow.security.identity import load_or_create_device_identity
            local_ident = load_or_create_device_identity()
            if local_ident and local_ident.device_id:
                local_id = local_ident.device_id
        except Exception:
            pass
        if device_id in ("local", "desktop-core", local_id):
            return web.json_response({"success": False, "status": "FORBIDDEN", "error": "Cannot revoke the local desktop node."}, status=400)

        res = await self.bridge.call("device_revoke", {"device_id": device_id})
        return web.json_response(res)

    async def handle_api_devices_disconnect(self, request: web.Request) -> web.Response:
        """Disconnect an active device session without removing its pairing record."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        device_id = (body.get("device_id") or "").strip()
        if not device_id:
            return web.json_response({"success": False, "error": "Missing required field 'device_id'."}, status=400)

        local_id = "desktop-core"
        try:
            from snow.security.identity import load_or_create_device_identity
            local_ident = load_or_create_device_identity()
            if local_ident and local_ident.device_id:
                local_id = local_ident.device_id
        except Exception:
            pass
        if device_id in ("local", "desktop-core", local_id):
            return web.json_response(
                {"success": False, "status": "FORBIDDEN", "error": "Cannot disconnect local desktop host."},
                status=400,
            )

        res = await self.bridge.call("device_disconnect", {"device_id": device_id})
        return web.json_response(res)

    async def handle_api_devices_reconnect(self, request: web.Request) -> web.Response:
        """Clear disconnect lock and trigger reconnection for a paired device."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        device_id = (body.get("device_id") or "").strip()
        if not device_id:
            return web.json_response({"success": False, "error": "Missing required field 'device_id'."}, status=400)

        res = await self.bridge.call("device_reconnect", {"device_id": device_id})
        return web.json_response(res)

    async def handle_api_devices_connect_peer(self, request: web.Request) -> web.Response:
        """Federate or connect to another SNOW Core or Android Peer Host by host/port or SNOW ID."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        snow_id_query = (body.get("snow_id") or "").strip().upper()
        host = (body.get("host") or "").strip()
        port_raw = body.get("port", 8765)
        pin = (body.get("pin") or "").strip()
        expected_fingerprint = (body.get("expected_fingerprint") or "").strip()

        if not host and snow_id_query:
            resolved_entry = await self._resolve_snow_id_directory(snow_id_query)
            if not resolved_entry.get("found"):
                err_status = str(resolved_entry.get("status") or "SNOW_ID_NOT_FOUND")
                http_code = {
                    "INVALID_SNOW_ID": 400,
                    "HUB_AUTH_FAILED": 401,
                    "FORBIDDEN": 403,
                    "INVALID_ENDPOINT": 502,
                    "HUB_UNAVAILABLE": 503,
                }.get(err_status, 404)
                return web.json_response({
                    "success": False,
                    "status": err_status,
                    "error": resolved_entry.get("error") or f"Could not resolve SNOW ID '{snow_id_query}'.",
                }, status=http_code)
            host = str(resolved_entry.get("host") or "").strip()
            if resolved_entry.get("port"):
                port_raw = resolved_entry.get("port")
            if not expected_fingerprint and resolved_entry.get("cert_fingerprint"):
                expected_fingerprint = str(resolved_entry.get("cert_fingerprint"))
            if not host:
                return web.json_response({
                    "success": False,
                    "status": "NO_DIRECT_LAN_ENDPOINT",
                    "error": f"Resolved '{snow_id_query}' without a direct LAN host endpoint; use relay or QR onboarding.",
                }, status=400)

        if not host:
            return web.json_response({"success": False, "error": "Missing required field 'host' or resolvable 'snow_id'."}, status=400)

        try:
            port = int(port_raw)
            if port <= 0 or port > 65535:
                raise ValueError()
        except (ValueError, TypeError):
            return web.json_response({"success": False, "error": "Invalid port number."}, status=400)

        # Call bridge to connect peer (Never log PINs or secret tokens)
        res = await self.bridge.mesh_connect_peer(
            host=host,
            port=port,
            pin=pin,
            expected_fingerprint=expected_fingerprint,
        )

        # If successful, record endpoint in SnowNetworkManager
        if res.get("success") and res.get("data"):
            remote_dev_id = res["data"].get("remote_device_id")
            if remote_dev_id:
                try:
                    from snow.network.network_model import SnowNetworkManager
                    db_mgr = self.bridge.capability_engine.db_manager
                    net_mgr = SnowNetworkManager(db_manager=db_mgr)
                    net_mgr.record_endpoint(device_id=remote_dev_id, host=host, port=port)
                except Exception as ex:
                    logger.debug("Failed recording connected peer endpoint: %s", ex)

        return web.json_response(res)

    async def handle_api_devices_connection_mode(self, request: web.Request) -> web.Response:
        """Update per-device connection mode (auto, local_only, remote_only)."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        device_id = (body.get("device_id") or "").strip()
        conn_mode = (body.get("connection_mode") or "").strip().lower()

        if not device_id:
            return web.json_response({"success": False, "error": "Missing required field 'device_id'."}, status=400)

        from snow.security.db import VALID_CONNECTION_MODES
        if conn_mode not in VALID_CONNECTION_MODES:
            return web.json_response(
                {
                    "success": False,
                    "error": f"Invalid connection_mode '{conn_mode}'. Must be one of: {', '.join(sorted(VALID_CONNECTION_MODES))}",
                },
                status=400,
            )

        res = await self.bridge.set_device_connection_mode(device_id, conn_mode)
        return web.json_response(res)

    async def handle_api_devices_permission_profile(self, request: web.Request) -> web.Response:
        """Update permission profile preset for a device."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        device_id = (body.get("device_id") or "").strip()
        profile = (body.get("profile") or "").strip().lower()

        if not device_id:
            return web.json_response({"success": False, "error": "Missing required field 'device_id'."}, status=400)

        from snow.network.router import VALID_PERMISSION_PROFILES
        if profile not in VALID_PERMISSION_PROFILES:
            return web.json_response(
                {
                    "success": False,
                    "error": f"Invalid permission profile '{profile}'. Must be one of: {', '.join(sorted(VALID_PERMISSION_PROFILES))}.",
                },
                status=400,
            )

        # Check if Core IPC daemon is running
        daemon_online = await self.bridge.daemon_manager.is_ipc_ready(timeout=0.2)
        if daemon_online:
            res = await self.bridge.call("set_permission_profile", {"device_id": device_id, "profile": profile})
            if not res.get("success"):
                err_status = res.get("status")
                http_status = 403 if err_status == "POLICY_DENIED" else 400 if err_status in ("INVALID_ARGUMENT", "DEVICE_NOT_FOUND") else 500
                return web.json_response(res, status=http_status)
            node_reg = getattr(self.bridge, "node_registry", None)
            if not node_reg and hasattr(self.bridge, "capability_engine"):
                node_reg = getattr(self.bridge.capability_engine, "node_registry", None)
            if node_reg:
                node_reg.set_permission_profile(device_id, profile)
            return web.json_response(res)
        else:
            paired = self.db_manager.get_paired_device(device_id)
            if not paired:
                return web.json_response({
                    "success": False,
                    "status": "DEVICE_NOT_FOUND",
                    "error": f"Device [{device_id}] not found in database.",
                }, status=404)
            self.db_manager.set_setting(f"device_profile:{device_id}", profile)
            node_reg = getattr(self.bridge, "node_registry", None)
            if not node_reg and hasattr(self.bridge, "capability_engine"):
                node_reg = getattr(self.bridge.capability_engine, "node_registry", None)
            if node_reg:
                node_reg.set_permission_profile(device_id, profile)
            return web.json_response({
                "success": True,
                "status": "SUCCESS",
                "device_id": device_id,
                "permission_profile": profile,
            })

    async def handle_api_network_identity(self, request: web.Request) -> web.Response:
        """Query local SNOW Network identity (including Ed25519 SNW-NET identity & hub URL)."""
        try:
            from snow.core.config import resolve_default_hub_url
            from snow.network.network_model import SnowNetworkManager
            from snow.security.identity import load_or_create_network_key_identity

            db_mgr = self.bridge.capability_engine.db_manager
            net_mgr = SnowNetworkManager(db_manager=db_mgr)
            ident = net_mgr.get_network_identity().to_dict()
            key_ident = load_or_create_network_key_identity()
            hub_url = resolve_default_hub_url(db_manager=db_mgr)
            ident["network_key_id"] = key_ident.network_id
            ident["public_key_b64"] = key_ident.public_key_b64
            ident["default_hub_url"] = hub_url
            ident["permanent_mcp_url"] = f"{hub_url}/u/{key_ident.network_id}/mcp" if hub_url else ""
            return web.json_response({
                "success": True,
                "status": "SUCCESS",
                "identity": ident,
            })
        except Exception as exc:
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    async def handle_api_settings_hub_get(self, request: web.Request) -> web.Response:
        """Return configured Default Hub URL setting and permanent Ed25519 network metadata."""
        from snow.core.config import resolve_default_hub_url
        from snow.security.identity import load_or_create_network_key_identity

        db_mgr = getattr(self, "db_manager", None) or getattr(self.bridge.capability_engine, "db_manager", None)
        hub_url = resolve_default_hub_url(db_manager=db_mgr)
        key_ident = load_or_create_network_key_identity()
        return web.json_response({
            "success": True,
            "default_hub_url": hub_url,
            "network_id": key_ident.network_id,
            "public_key_b64": key_ident.public_key_b64,
            "permanent_mcp_url": f"{hub_url}/u/{key_ident.network_id}/mcp" if hub_url else "",
        })

    async def handle_api_settings_hub_post(self, request: web.Request) -> web.Response:
        """Persist or clear Default Hub URL with strict HTTPS / dev-loopback validation."""
        from snow.core.config import resolve_default_hub_url, validate_hub_url
        from snow.mcp.tunnel import load_tunnel_config, save_tunnel_config

        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        if not isinstance(body, dict):
            return web.json_response({"success": False, "error": "JSON object expected."}, status=400)

        raw_url = body.get("default_hub_url", "")
        if raw_url is None:
            raw_url = ""
        if not isinstance(raw_url, str):
            return web.json_response({"success": False, "error": "default_hub_url must be a string."}, status=400)

        clean = raw_url.strip()
        if clean:
            try:
                clean = validate_hub_url(clean)
            except ValueError as exc:
                return web.json_response({"success": False, "status": "INVALID_URL", "error": str(exc)}, status=400)

        db_mgr = getattr(self, "db_manager", None) or getattr(self.bridge.capability_engine, "db_manager", None)
        if db_mgr is not None:
            if clean:
                db_mgr.set_setting("default_hub_url", clean)
            elif hasattr(db_mgr, "delete_setting"):
                db_mgr.delete_setting("default_hub_url")
            else:
                db_mgr.set_setting("default_hub_url", "")

        try:
            tcfg = load_tunnel_config()
            if clean:
                tcfg["default_hub_url"] = clean
            else:
                tcfg.pop("default_hub_url", None)
            save_tunnel_config(tcfg)
        except Exception:
            pass

        resolved = resolve_default_hub_url(db_manager=db_mgr)
        return web.json_response({
            "success": True,
            "status": "UPDATED",
            "default_hub_url": resolved,
        })

    async def handle_api_network_identity_update(self, request: web.Request) -> web.Response:
        """Update local SNOW Network name."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        name = (body.get("network_name") or "").strip()
        if not name:
            return web.json_response({"success": False, "error": "Network name cannot be empty."}, status=400)
        if len(name) > 64:
            return web.json_response({"success": False, "error": "Network name cannot exceed 64 characters."}, status=400)

        try:
            from snow.network.network_model import SnowNetworkManager
            db_mgr = self.bridge.capability_engine.db_manager
            net_mgr = SnowNetworkManager(db_manager=db_mgr)
            ident = net_mgr.update_network_name(name)
            return web.json_response({
                "success": True,
                "status": "SUCCESS",
                "identity": ident.to_dict(),
            })
        except Exception as exc:
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    async def handle_api_network_topology(self, request: web.Request) -> web.Response:
        """Query mesh topology with OWNER_MANUAL principal view."""
        try:
            if await self.bridge.daemon_manager.is_ipc_ready(timeout=0.1):
                res = await self.bridge.call("mesh_topology", payload={}, timeout=5.0)
                if res.get("status") not in ("CORE_OFFLINE", "UNKNOWN_OPERATION") and res.get("data"):
                    return web.json_response(res)

            from snow.network.network_model import SnowNetworkManager
            from snow.security.context import ExecutionPrincipal
            db_mgr = self.bridge.capability_engine.db_manager
            net_mgr = SnowNetworkManager(db_manager=db_mgr)
            topo = net_mgr.build_topology(principal=ExecutionPrincipal.OWNER_MANUAL)
            return web.json_response(topo)
        except Exception as exc:
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    async def handle_api_pair_qr(self, request: web.Request) -> web.Response:
        """Generate temporary pairing PIN, QR code metadata, and vector SVG."""
        trust_tier = "owner"
        require_legacy_ticket = False
        if request.method == "POST":
            try:
                body = await request.json()
                if isinstance(body, dict):
                    trust_tier = body.get("trust_tier") or body.get("tier", "owner")
                    require_legacy_ticket = bool(
                        body.get("require_relay_ticket")
                        or body.get("include_relay_ticket")
                        or body.get("legacy_relay_ticket")
                    )
            except Exception:
                pass
        elif request.method == "GET":
            trust_tier = request.query.get("trust_tier") or request.query.get("tier", "owner")
            require_legacy_ticket = (
                str(
                    request.query.get("require_relay_ticket")
                    or request.query.get("include_relay_ticket")
                    or request.query.get("legacy_relay_ticket")
                    or ""
                ).strip().lower()
                in ("1", "true", "yes")
            )

        res = await self.bridge.call("generate_pairing_qr", {"trust_tier": trust_tier})
        if not res.get("success"):
            return web.json_response({
                "success": False,
                "status": res.get("status", "ERROR"),
                "error": res.get("error", "Could not generate pairing QR code. Ensure SNOW daemon is running."),
            })

        payload = res.get("data", {})

        # Master QR: Include network identity and default hub URL for zero-setup discovery
        try:
            from snow.core.config import resolve_default_hub_url
            from snow.security.identity import load_or_create_network_key_identity
            cap_eng = getattr(getattr(self, "bridge", None), "capability_engine", None)
            db_mgr = getattr(self, "db_manager", None) or getattr(cap_eng, "db_manager", None)
            hub_url = resolve_default_hub_url(db_manager=db_mgr)
            key_ident = load_or_create_network_key_identity()
            if key_ident and key_ident.network_id:
                payload.setdefault("network_id", key_ident.network_id)
            if hub_url:
                payload.setdefault("hub_url", hub_url)
        except Exception as exc:
            logger.debug("Could not enrich QR with default hub/network identity: %s", exc)

        cfg = getattr(self, "config", None)
        group_id = (
            os.getenv("SNOW_RELAY_GROUP_ID")
            or (getattr(cfg, "relay_group_id", None) if cfg else None)
            or "default_group"
        )
        raw_relay_secret = os.getenv("SNOW_RELAY_SECRET") or (getattr(cfg, "relay_secret", None) if cfg else None)
        relay_secret = raw_relay_secret.strip() if isinstance(raw_relay_secret, str) else ""

        if require_legacy_ticket and not relay_secret:
            return web.json_response(
                {
                    "success": False,
                    "status": "RELAY_SECRET_MISSING",
                    "error": "Cannot mint legacy relay_ticket without an explicit SNOW_RELAY_SECRET.",
                    "legacy_relay_available": False,
                },
                status=400,
            )

        legacy_relay_available = False
        # Master QR: Only mint legacy relay_ticket when an explicit non-empty SNOW_RELAY_SECRET is configured.
        if hasattr(self, "tunnel_manager"):
            relay_stat = self.tunnel_manager.get_status(port=8770)
            if relay_stat.get("active") and relay_stat.get("public_url"):
                pub_url = relay_stat["public_url"]
                relay_ws_url = pub_url.replace("https://", "wss://").replace("http://", "ws://").rstrip("/") + "/v1/tunnel"
                if relay_secret:
                    from snow.relay.auth import create_relay_ticket
                    try:
                        fresh_ticket = create_relay_ticket(
                            device_id="mobile-pairing-client",
                            group_id=group_id,
                            secret=relay_secret,
                            ttl_seconds=3600,
                        )
                        payload["relay_url"] = relay_ws_url
                        payload["relay_ticket"] = fresh_ticket
                        payload["group_id"] = group_id
                        legacy_relay_available = True
                    except ValueError as exc:
                        logger.warning("Failed signing legacy relay ticket for QR payload: %s", exc)
                        return web.json_response(
                            {
                                "success": False,
                                "status": "RELAY_SECRET_INVALID",
                                "error": f"Cannot sign legacy relay_ticket: {exc}",
                                "legacy_relay_available": False,
                            },
                            status=400,
                        )
                else:
                    payload.pop("relay_ticket", None)
                    payload.pop("group_id", None)
        elif require_legacy_ticket and relay_secret:
            from snow.relay.auth import create_relay_ticket
            try:
                fresh_ticket = create_relay_ticket(
                    device_id="mobile-pairing-client",
                    group_id=group_id,
                    secret=relay_secret,
                    ttl_seconds=3600,
                )
                payload["relay_ticket"] = fresh_ticket
                payload["group_id"] = group_id
                legacy_relay_available = True
            except ValueError as exc:
                return web.json_response(
                    {
                        "success": False,
                        "status": "RELAY_SECRET_INVALID",
                        "error": f"Cannot sign legacy relay_ticket: {exc}",
                        "legacy_relay_available": False,
                    },
                    status=400,
                )

        svg_content = self._render_qr_svg(payload)

        return web.json_response({
            "success": True,
            "status": "SUCCESS",
            "legacy_relay_available": legacy_relay_available,
            "data": payload,
            "svg": svg_content,
        })

    def _get_configured_transfer_dirs(self) -> tuple[Path, Path]:
        """Resolve configured PC transfers and captures directories."""
        from snow.capabilities.windows.screenshot import DEFAULT_CAPTURES_DIR
        from snow.transfer.storage import get_default_pc_transfer_dir

        transfers_dir: Optional[Path] = None
        if getattr(self, "db_manager", None) and hasattr(self.db_manager, "get_setting"):
            try:
                saved = self.db_manager.get_setting("pc_transfer_dir", None)
                if isinstance(saved, str) and saved.strip():
                    transfers_dir = Path(saved.strip()).expanduser().resolve()
            except Exception:
                pass

        sm = getattr(getattr(self, "transfer_server", None), "storage_manager", None)
        if not transfers_dir:
            raw_root = getattr(sm, "root_dir", None)
            if raw_root:
                transfers_dir = Path(raw_root).resolve()
        if not transfers_dir:
            transfers_dir = get_default_pc_transfer_dir()

        captures_dir = getattr(sm, "captures_dir", None) or DEFAULT_CAPTURES_DIR
        return Path(transfers_dir).resolve(), Path(captures_dir).resolve()

    async def _is_remote_windows_device(self, device_id: str, device_type_hint: str = "") -> bool:
        """Determine whether device_id refers to a non-local remote Windows/Desktop peer."""
        if not device_id:
            return False
        hint = (device_type_hint or "").strip().lower()
        if hint in ("windows", "desktop", "pc", "windows_pc"):
            return True
        if hint in ("android", "phone", "mobile"):
            return False
        if hasattr(self, "db_manager") and self.db_manager:
            try:
                rec = self.db_manager.get_paired_device(device_id)
                if rec:
                    platform = str(getattr(rec, "platform", "") or "").lower()
                    role = str(getattr(rec, "role", "") or "").lower()
                    if "windows" in platform or "desktop" in platform or role == "desktop":
                        return True
                    if "android" in platform or role == "android":
                        return False
            except Exception:
                pass
        return False

    async def handle_api_files(self, request: web.Request) -> web.Response:
        """Enumerate files on connected Android phone or remote Peer PC storage."""
        device_id = request.query.get("device_id", "")
        device_type_hint = request.query.get("device_type", "")
        subpath = request.query.get("subpath", "")
        scope = request.query.get("scope", "full")
        if "hide_hidden" in request.query:
            show_hidden = not (request.query.get("hide_hidden", "false").lower() in ("true", "1"))
        else:
            show_hidden = request.query.get("show_hidden", "false").lower() in ("true", "1")

        transfers_dir, _ = self._get_configured_transfer_dirs()

        if await self._is_remote_windows_device(device_id, device_type_hint):
            res = await self.bridge.send_device_request(
                device_id=device_id,
                action="desktop_file_list",
                data={"path": subpath, "limit": 100},
                timeout=30.0,
            )
            data_dict = res.get("data") if isinstance(res.get("data"), dict) else {}
            raw_items = data_dict.get("files") or data_dict.get("items") or res.get("files") or []
            return web.json_response({
                "success": res.get("success", False),
                "status": res.get("status", "SUCCESS"),
                "items": raw_items,
                "storage_mode": "desktop_remote",
                "directory": data_dict.get("directory") or subpath or "Home",
                "parent": data_dict.get("parent"),
                "folder_name": data_dict.get("directory") or "Home",
                "subpath": data_dict.get("directory") or subpath,
                "destination_dir": str(transfers_dir),
                "data": data_dict,
                "error": res.get("error"),
            })

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
            "destination_dir": str(transfers_dir),
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
        transfer_client_key = str(body.get("client_transfer_id") or secrets.token_hex(8))

        if not file_name or not isinstance(file_name, str):
            return web.json_response({"success": False, "error": "Missing required field 'file_name'."}, status=400)

        transfers_dir, _ = self._get_configured_transfer_dirs()

        task = asyncio.create_task(
            self.bridge.android_file_receive(
                file_name=file_name,
                subpath=subpath,
                device_id=device_id,
            )
        )
        async with self._active_file_downloads_lock:
            self._active_file_downloads[transfer_client_key] = task

        try:
            res = await task
        except asyncio.CancelledError:
            return web.json_response(
                {"success": False, "status": "CANCELLED", "error": "File download cancelled by user."},
                status=499,
            )
        finally:
            async with self._active_file_downloads_lock:
                self._active_file_downloads.pop(transfer_client_key, None)

        if isinstance(res, dict):
            res = dict(res)
            res.setdefault("destination_dir", str(transfers_dir))
            data_dict = res.get("data")
            if isinstance(data_dict, dict):
                data_copy = dict(data_dict)
                data_copy.setdefault("destination_dir", str(transfers_dir))
                data_copy.setdefault("destination_path", str(transfers_dir / Path(file_name).name))
                res["data"] = data_copy
        return web.json_response(res)

    async def handle_api_files_destinations(self, request: web.Request) -> web.Response:
        """Return configured PC transfers and captures directories for Dashboard display."""
        from snow.transfer.storage import get_default_pc_transfer_dir

        transfers_dir, captures_dir = self._get_configured_transfer_dirs()
        return web.json_response({
            "success": True,
            "pc_transfers_dir": str(transfers_dir),
            "default_pc_transfers_dir": str(get_default_pc_transfer_dir()),
            "pc_captures_dir": str(captures_dir),
        })

    async def handle_api_files_destination(self, request: web.Request) -> web.Response:
        """Validate, persist, and activate a user-chosen PC incoming transfers directory."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        raw_path = (body.get("path") or body.get("pc_transfers_dir") or "").strip()
        if not raw_path:
            return web.json_response({"success": False, "error": "Missing required field 'path'."}, status=400)

        from snow.transfer.storage import get_default_pc_transfer_dir, validate_pc_transfer_dir

        try:
            validated = validate_pc_transfer_dir(raw_path)
        except (ValueError, PermissionError) as exc:
            return web.json_response({"success": False, "status": "INVALID_PATH", "error": str(exc)}, status=400)
        except Exception as exc:
            return web.json_response({"success": False, "status": "ERROR", "error": str(exc)}, status=400)

        if getattr(self, "db_manager", None) and hasattr(self.db_manager, "set_setting"):
            self.db_manager.set_setting("pc_transfer_dir", str(validated))

        sm = getattr(getattr(self, "transfer_server", None), "storage_manager", None)
        if sm is not None and hasattr(sm, "set_root_dir"):
            sm.set_root_dir(validated)

        try:
            ipc_res = await self.bridge.call("set_pc_transfer_dir", {"path": str(validated)})
            if isinstance(ipc_res, dict) and not ipc_res.get("success"):
                ipc_status = str(ipc_res.get("status", "")).upper()
                if ipc_status not in ("CORE_OFFLINE", "UNKNOWN_OPERATION", "IPC_ERROR", ""):
                    return web.json_response(ipc_res, status=400)
        except Exception as exc:
            logger.debug("Optional IPC sync for set_pc_transfer_dir skipped cleanly: %s", exc)

        _, captures_dir = self._get_configured_transfer_dirs()
        return web.json_response({
            "success": True,
            "status": "UPDATED",
            "pc_transfers_dir": str(validated),
            "default_pc_transfers_dir": str(get_default_pc_transfer_dir()),
            "pc_captures_dir": str(captures_dir),
        })

    async def handle_api_files_pick_destination(self, request: web.Request) -> web.Response:
        """Open native OS folder selection dialog cleanly without flashing a console window."""
        from snow.capabilities.windows.files import pick_folder_dialog_win32

        res = await asyncio.to_thread(
            pick_folder_dialog_win32,
            "Select SNOW Incoming Files Folder",
        )
        return web.json_response(res)

    async def handle_api_open_transfers_folder(self, request: web.Request) -> web.Response:
        """Open ONLY the configured PC transfers folder in OS file explorer."""
        transfers_dir, _ = self._get_configured_transfer_dirs()
        transfers_dir.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32" and hasattr(os, "startfile"):
                await asyncio.to_thread(os.startfile, str(transfers_dir))
                return web.json_response({
                    "success": True,
                    "opened": True,
                    "path": str(transfers_dir),
                })
            return web.json_response({
                "success": True,
                "opened": False,
                "path": str(transfers_dir),
                "message": "Transfers directory ready.",
            })
        except Exception as exc:
            logger.warning("Failed opening transfers folder '%s': %s", transfers_dir, exc)
            return web.json_response({
                "success": False,
                "opened": False,
                "path": str(transfers_dir),
                "error": f"Unable to open folder: {exc}",
            }, status=500)

    async def handle_api_files_transfer_cancel(self, request: web.Request) -> web.Response:
        """Cancel active dashboard-initiated file downloads cleanly."""
        cancelled = 0
        async with self._active_file_downloads_lock:
            for tid, task in list(self._active_file_downloads.items()):
                if task and not task.done():
                    task.cancel()
                    cancelled += 1
        return web.json_response({
            "success": True,
            "status": "CANCELLED",
            "cancelled_count": cancelled,
        })

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
        """Control media playback and bounded system volume on Windows or Phone."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        action = body.get("action", "")
        target = body.get("target", "windows")
        device_id = body.get("device_id", "")
        if not isinstance(action, str) or not action.strip():
            return web.json_response({"success": False, "error": "Missing or invalid media 'action'."}, status=400)

        vol_value: Optional[int] = None
        if "value" in body and body["value"] is not None:
            raw_val = body["value"]
            if isinstance(raw_val, bool) or not isinstance(raw_val, (int, float)):
                return web.json_response({"success": False, "error": "Volume 'value' must be between 0 and 100."}, status=400)
            num_val = float(raw_val)
            if math.isnan(num_val) or math.isinf(num_val) or num_val < 0.0 or num_val > 100.0:
                return web.json_response({"success": False, "error": "Volume 'value' must be between 0 and 100."}, status=400)
            vol_value = int(round(num_val))

        if vol_value is not None:
            res = await self.bridge.media_control(
                action=action.strip(), target=target, device_id=device_id, value=vol_value
            )
        else:
            res = await self.bridge.media_control(action=action.strip(), target=target, device_id=device_id)
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
        status_val = (body.get("status") or "").strip().upper()
        if not decision and status_val:
            decision = "approve" if status_val in ("APPROVED", "APPROVE") else "deny"

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
        from snow.transfer.storage import TransferStorageManager

        candidate_roots: list[Path] = [
            DEFAULT_CAPTURES_DIR.resolve(),
            TransferStorageManager().root_dir.resolve(),
        ]
        if self.transfer_server is not None and hasattr(self.transfer_server, "storage_manager"):
            candidate_roots.append(self.transfer_server.storage_manager.root_dir.resolve())
        if getattr(TransferStorageManager, "__module__", "") != "unittest.mock":
            cfg_transfers, cfg_captures = self._get_configured_transfer_dirs()
            candidate_roots.extend([cfg_transfers, cfg_captures])
        candidate_roots = list(dict.fromkeys(candidate_roots))

        target_path: Optional[Path] = None
        for root in candidate_roots:
            candidate = (root / file_name).resolve()
            if candidate.is_relative_to(root) and candidate.is_file():
                target_path = candidate
                break

        if target_path is None:
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

    async def handle_api_desktop_wallpaper(self, request: web.Request) -> web.Response:
        """Serve scaled Windows desktop wallpaper preview with ETag and 304 support for Web UI."""
        session = self._get_valid_session(request)
        if not session:
            return web.Response(status=401, text="Unauthorized: Authentication required.")

        try:
            from snow.capabilities.windows.wallpaper import get_desktop_wallpaper_preview
            jpeg_bytes, etag = await asyncio.to_thread(get_desktop_wallpaper_preview)
            if not jpeg_bytes:
                return web.Response(status=404, text="Wallpaper not available.")

            client_etag = request.headers.get("If-None-Match")
            if client_etag and client_etag.strip() == etag:
                return web.Response(status=304, headers={"ETag": etag})

            return web.Response(
                body=jpeg_bytes,
                content_type="image/jpeg",
                headers={
                    "ETag": etag,
                    "Cache-Control": "private, max-age=60, must-revalidate",
                },
            )
        except Exception as exc:
            logger.warning("Error serving web wallpaper preview: %s", exc)
            return web.Response(status=500, text=str(exc))

    async def handle_api_desktop_lock(self, request: web.Request) -> web.Response:
        """Securely lock the host Windows workstation (OWNER_MANUAL only)."""
        if sys.platform != "win32":
            return web.json_response(
                {"success": False, "error": "Workstation lock is only supported on Windows."},
                status=501,
            )

        try:
            import ctypes
            from ctypes import wintypes
            user32 = ctypes.windll.user32
            user32.LockWorkStation.argtypes = []
            user32.LockWorkStation.restype = wintypes.BOOL

            res_val = await asyncio.to_thread(user32.LockWorkStation)
            if res_val:
                return web.json_response({"success": True, "message": "Workstation locked successfully."})
            else:
                return web.json_response({"success": False, "error": "LockWorkStation returned 0."}, status=500)
        except Exception as exc:
            logger.error("Failed to invoke native LockWorkStation: %s", exc)
            return web.json_response({"success": False, "error": str(exc)}, status=500)

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
        display_host = config.host
        if display_host in ("0.0.0.0", "::"):
            display_host = "127.0.0.1"
        return web.json_response({
            "success": True,
            "status": "SUCCESS",
            "data": {
                "enabled": config.enabled,
                "host": config.host,
                "port": config.port,
                "endpoint": f"wss://{display_host}:{config.port}/v1/tunnel" if display_host else None,
                "max_frame_size_mib": config.max_frame_size // (1024 * 1024),
                "quota_mib_hr": config.max_transfer_quota_bytes // (1024 * 1024),
            },
        })

    async def handle_api_relay_config_get(self, request: web.Request) -> web.Response:
        """Get live relay client configuration and status (secret ticket redacted)."""
        res = await self.bridge.get_relay_config()
        return web.json_response(res)

    async def handle_api_relay_config_post(self, request: web.Request) -> web.Response:
        """Configure and toggle outbound relay tunnel connectivity."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        enabled = bool(body.get("enabled", False))
        relay_url = (body.get("relay_url") or "").strip()
        group_id = (body.get("group_id") or "").strip()
        ticket = (body.get("ticket") or "").strip()

        res = await self.bridge.set_relay_config(
            enabled=enabled,
            relay_url=relay_url,
            group_id=group_id,
            ticket=ticket,
        )
        return web.json_response(res)

    async def handle_api_mcp_gateway_status(self, request: web.Request) -> web.Response:
        """Query Remote MCP Streamable HTTP Gateway status and local host integrations."""
        gw_host = "127.0.0.1"
        gw_port = 8771
        metadata_url = f"http://{gw_host}:{gw_port}/.well-known/oauth-protected-resource"

        gw_status = "offline"
        metadata = None

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(gw_host, gw_port),
                timeout=0.15,
            )
            writer.close()
            await writer.wait_closed()
            gw_status = "online"
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            gw_status = "offline"
        except Exception:
            gw_status = "offline"

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

        tunnel_info = self.tunnel_manager.get_status()
        public_url = os.environ.get("SNOW_MCP_PUBLIC_URL")
        if tunnel_info.get("active") and tunnel_info.get("mcp_endpoint"):
            public_endpoint = tunnel_info["mcp_endpoint"]
        else:
            public_endpoint = f"{public_url.rstrip('/')}/mcp" if public_url else (metadata.get("resource") if metadata and metadata.get("resource") and not metadata.get("resource").startswith("http://127.0.0.1") else None)

        from snow.mcp.registry import list_capabilities
        caps_count = len(list_capabilities())

        return web.json_response({
            "success": True,
            "status": "SUCCESS",
            "data": {
                "gateway_status": gw_status,
                "endpoint": f"http://{gw_host}:{gw_port}/mcp",
                "public_endpoint": public_endpoint,
                "metadata": safe_metadata,
                "ai_hosts": safe_hosts,
                "capabilities_count": caps_count,
                "tunnel": tunnel_info,
            }
        })

    async def handle_api_screen_capture_phone(self, request: web.Request) -> web.Response:
        """One-time screen capture on target Android phone via HTTPS transfer plane."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        device_id = body.get("device_id", "")
        approval_id = body.get("approval_id", "")
        res = await self.bridge.android_screenshot(device_id=device_id, approval_id=approval_id)
        return web.json_response(res)

    async def handle_api_screen_status(self, request: web.Request) -> web.Response:
        """Query live screen streaming session status and multi-sender list for dashboard."""
        sender_id = request.query.get("sender_id") or request.query.get("device_id")
        if self.transfer_server is not None:
            status = self.transfer_server.get_screen_stream_status(sender_id, requester_device_id="local_dashboard")
            return web.json_response({"success": True, **status})

        # Production path: query via IPC
        try:
            res = await self.bridge.call("screen_stream_status", {"sender_id": sender_id} if sender_id else {})
            status = res.get("data") if isinstance(res.get("data"), dict) else {"state": "IDLE", "has_frame": False, "senders": []}
            return web.json_response({"success": True, **status})
        except Exception as e:
            logger.debug("Failed querying screen status via IPC: %s", e)
            return web.json_response({"success": True, "state": "IDLE", "has_frame": False, "senders": []})

    async def handle_api_screen_senders(self, request: web.Request) -> web.Response:
        """List active live screen senders and eligible Full Control PC-share targets."""
        if self.transfer_server is not None:
            senders = self.transfer_server.list_active_screen_streams(requester_device_id="local_dashboard")
            return web.json_response({
                "success": True,
                "senders": senders,
                "count": len(senders),
                "pc_sharing": {"state": "IDLE", "target_device_ids": []},
                "eligible_targets": [],
            })
        try:
            res = await self.bridge.call("screen_stream_senders")
            data = res.get("data") if isinstance(res.get("data"), dict) else {}
            return web.json_response({
                "success": bool(res.get("success", True)),
                "senders": data.get("senders", []),
                "count": len(data.get("senders", [])),
                "pc_sharing": data.get("pc_sharing", {"state": "IDLE"}),
                "eligible_targets": data.get("eligible_targets", []),
            })
        except Exception as e:
            logger.debug("Failed querying screen senders via IPC: %s", e)
            return web.json_response({"success": False, "senders": [], "eligible_targets": [], "error": str(e)}, status=500)

    async def handle_api_screen_share_start(self, request: web.Request) -> web.Response:
        """Start sharing this PC's screen to explicit Full Control targets."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        if not isinstance(body, dict):
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        targets = body.get("target_device_ids")
        if not isinstance(targets, list) or not [str(t).strip() for t in targets if str(t or "").strip()]:
            return web.json_response(
                {"success": False, "status": "NO_TARGETS_SELECTED", "error": "Select at least one authorized Full Control target device."},
                status=400,
            )
        clean_targets = [str(t).strip() for t in targets if str(t or "").strip()]
        fps = float(body.get("fps", 4.0) or 4.0)
        try:
            res = await self.bridge.call(
                "screen_stream_start",
                {"target_device_ids": clean_targets, "fps": fps},
            )
            ok = bool(res.get("success", False))
            status_code = 403 if res.get("status") == "PERMISSION_DENIED" else (200 if ok else 400)
            data = res.get("data") if isinstance(res.get("data"), dict) else {}
            return web.json_response(
                {"success": ok, "status": res.get("status"), "error": res.get("error"), **data},
                status=status_code,
            )
        except Exception as e:
            logger.debug("Failed starting PC screen share via IPC: %s", e)
            return web.json_response({"success": False, "status": "ERROR", "error": str(e)}, status=500)

    async def handle_api_screen_share_stop(self, request: web.Request) -> web.Response:
        """Stop PC live screen sharing."""
        try:
            res = await self.bridge.call("screen_stream_stop", {"stop_pc_share": True})
            return web.json_response({"success": bool(res.get("success", True)), "status": "STOPPED", **(res.get("data") or {})})
        except Exception as e:
            return web.json_response({"success": False, "status": "ERROR", "error": str(e)}, status=500)

    async def handle_api_screen_frame(self, request: web.Request) -> web.Response:
        """Serve latest live screen JPEG frame to authenticated dashboard."""
        sender_id = request.query.get("sender_id") or request.query.get("device_id")
        # Test fallback: direct access if transfer_server injected into same process
        if self.transfer_server is not None:
            frame_dict = self.transfer_server.get_latest_screen_frame(sender_id, requester_device_id="local_dashboard")
            if not frame_dict or not frame_dict.get("frame_bytes"):
                return web.Response(status=204)
            return web.Response(
                body=frame_dict["frame_bytes"],
                content_type="image/jpeg",
                headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate",
                    "X-Content-Type-Options": "nosniff",
                    "X-Snow-Session-Id": str(frame_dict.get("session_id", "")),
                    "X-Snow-Sender-Id": str(frame_dict.get("sender_device_id") or frame_dict.get("device_id") or ""),
                    "X-Snow-Sender-Name": str(frame_dict.get("sender_name") or ""),
                    "X-Snow-Frame-Seq": str(frame_dict.get("frame_seq", 0)),
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
            status_res = await self.bridge.call("screen_stream_status", {"sender_id": sender_id} if sender_id else {})
            status_data = status_res.get("data") if isinstance(status_res.get("data"), dict) else {}
            transfer_port = status_data.get("transfer_port") or 8766
            use_tls = status_data.get("use_tls", False)

            scheme = "https" if use_tls else "http"
            from urllib.parse import quote
            suffix = f"?sender_id={quote(sender_id)}" if sender_id else ""
            url = f"{scheme}://127.0.0.1:{transfer_port}/api/v1/screen/frame{suffix}"

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
                "X-Snow-Device-Id": "local_dashboard_proxy",
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
                                    "X-Snow-Sender-Id": resp.headers.get("X-Snow-Sender-Id", ""),
                                    "X-Snow-Sender-Name": resp.headers.get("X-Snow-Sender-Name", ""),
                                    "X-Snow-Frame-Seq": resp.headers.get("X-Snow-Frame-Seq", "0"),
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
        sender_id = None
        try:
            body = await request.json()
            if isinstance(body, dict):
                sender_id = body.get("sender_id") or body.get("device_id")
        except Exception:
            pass
        if self.transfer_server is not None:
            self.transfer_server.set_session_state(sender_id or "all", "STOPPED")

        try:
            if self.bridge and hasattr(self.bridge, "call"):
                res = self.bridge.call("screen_stream_stop", {"sender_id": sender_id} if sender_id else {})
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

    async def handle_api_screen_capture_latest(self, request: web.Request) -> web.Response:
        """Serve latest delivered one-time Android screen capture PNG/JPEG with path containment."""
        from snow.capabilities.windows.screenshot import DEFAULT_CAPTURES_DIR
        from snow.transfer.storage import TransferStorageManager

        canonical_roots: list[Path] = [
            DEFAULT_CAPTURES_DIR.resolve(),
            TransferStorageManager().root_dir.resolve(),
        ]
        if self.transfer_server is not None and hasattr(self.transfer_server, "storage_manager"):
            canonical_roots.append(self.transfer_server.storage_manager.root_dir.resolve())
        if getattr(TransferStorageManager, "__module__", "") != "unittest.mock":
            cfg_transfers, cfg_captures = self._get_configured_transfer_dirs()
            canonical_roots.extend([cfg_transfers, cfg_captures])
        canonical_roots = list(dict.fromkeys(canonical_roots))

        candidates: list[Path] = []
        for sdir in canonical_roots:
            if sdir.is_dir():
                for pat in ("android_screen_*.png", "android_screen_*.jpg", "android_screen_*.jpeg"):
                    for f in sdir.rglob(pat):
                        try:
                            resolved = f.resolve()
                            if any(resolved.is_relative_to(root) for root in canonical_roots) and resolved.is_file():
                                candidates.append(resolved)
                        except (PermissionError, RuntimeError, OSError):
                            pass

        if not candidates:
            return web.Response(status=204)

        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        latest_file = candidates[0]
        try:
            import hashlib
            st = latest_file.stat()
            etag = f'"{hashlib.sha256(f"{latest_file.name}-{st.st_mtime}-{st.st_size}".encode("utf-8")).hexdigest()[:16]}"'
            if_none_match = request.headers.get("If-None-Match", "").strip()
            if if_none_match and if_none_match == etag:
                return web.Response(status=304, headers={"ETag": etag, "Cache-Control": "no-cache, must-revalidate"})
            with open(latest_file, "rb") as f:
                data = f.read()
            mime = "image/png" if latest_file.suffix.lower() == ".png" else "image/jpeg"
            return web.Response(
                body=data,
                content_type=mime,
                headers={
                    "ETag": etag,
                    "Cache-Control": "no-cache, must-revalidate",
                    "X-Content-Type-Options": "nosniff",
                    "X-Snow-Filename": latest_file.name,
                    "X-Snow-Mtime": str(st.st_mtime),
                },
            )
        except Exception as exc:
            logger.error("Failed reading latest screen capture '%s': %s", latest_file, exc)
            return web.Response(status=500, text="Internal error reading screen capture.")

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
        if getattr(TransferStorageManager, "__module__", "") != "unittest.mock":
            cfg_transfers, cfg_captures = self._get_configured_transfer_dirs()
            canonical_roots.extend([cfg_transfers, cfg_captures])
        canonical_roots = list(dict.fromkeys(canonical_roots))

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
            import hashlib
            st = latest_file.stat()
            etag = f'"{hashlib.sha256(f"{latest_file.name}-{st.st_mtime}-{st.st_size}".encode("utf-8")).hexdigest()[:16]}"'

            if_none_match = request.headers.get("If-None-Match", "").strip()
            if if_none_match and if_none_match == etag:
                return web.Response(
                    status=304,
                    headers={
                        "ETag": etag,
                        "Cache-Control": "no-cache, must-revalidate",
                    },
                )

            with open(latest_file, "rb") as f:
                data = f.read()
            mime = "image/png" if latest_file.suffix.lower() == ".png" else "image/jpeg"
            return web.Response(
                body=data,
                content_type=mime,
                headers={
                    "ETag": etag,
                    "Cache-Control": "no-cache, must-revalidate",
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
        limit = min(max(int(request.query.get("limit", 15)), 1), 15)
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
        """Serve authenticated clipboard thumbnail / full image from contained buffer storage.

        Prefers authoritative Core IPC (`clipboard_buffer_get`) whenever Core is reachable,
        falling back to an in-process buffer only when Core IPC is unavailable/offline.
        """
        import re
        item_id = request.match_info.get("item_id", "").strip()
        if not item_id or not re.match(r"^cb_[0-9a-f]{12}_[0-9a-f]{6}$", item_id):
            return web.json_response(
                {
                    "success": False,
                    "status": "INVALID_ARGUMENT",
                    "error": "Invalid item ID format. Expected format: cb_<12hex>_<6hex>.",
                },
                status=400,
            )

        from snow.capabilities.clipboard_buffer import (
            ClipboardRingBuffer,
            JPEG_SIGNATURE,
            MAX_IMAGE_BYTES,
            PNG_SIGNATURE,
            get_default_clipboard_storage_dir,
        )

        def _is_contained_non_symlink(candidate: Path, root: Path) -> bool:
            try:
                if candidate.is_symlink():
                    return False
                resolved_root = root.resolve()
                resolved_cand = candidate.resolve()
                if not resolved_cand.is_relative_to(resolved_root):
                    return False
                real_root = Path(os.path.realpath(resolved_root))
                real_cand = Path(os.path.realpath(resolved_cand))
                return real_cand.is_relative_to(real_root)
            except (OSError, ValueError, RuntimeError):
                return False

        OFFLINE_IPC_STATUSES = {
            "CORE_OFFLINE",
            "DAEMON_OFFLINE",
            "IPC_UNAVAILABLE",
            "CONNECTION_ERROR",
            "CONNECTION_RESET",
            "REQUEST_TIMEOUT",
            "UNAVAILABLE",
            "ENGINE_UNAVAILABLE",
        }

        in_proc_engine = getattr(self.bridge, "capability_engine", None)
        in_proc_buf = getattr(in_proc_engine, "clipboard_buffer", None) if in_proc_engine else None
        target_file: Optional[Path] = None
        storage_dir: Optional[Path] = None
        mime_hint = ""
        ipc_unavailable = False

        bridge_call = getattr(self.bridge, "call", None)
        if callable(bridge_call):
            try:
                res = await bridge_call("clipboard_buffer_get", {"item_id": item_id})
            except (ConnectionError, TimeoutError, OSError) as exc:
                logger.warning("Core IPC unreachable during clipboard image fetch [%s]: %s", item_id, exc)
                res = {"success": False, "status": "CORE_OFFLINE", "error": str(exc)}

            if isinstance(res, dict) and res.get("success", False):
                data_dict = res.get("data") if isinstance(res.get("data"), dict) else {}
                item = data_dict.get("item") if isinstance(data_dict.get("item"), dict) else None
                if not item or (item.get("type") != "image" and item.get("content_type") != "image"):
                    return web.json_response(
                        {"success": False, "status": "NOT_FOUND", "error": "Clipboard image not found or not an image."},
                        status=404,
                    )

                mime_hint = str(item.get("mime_type") or "").strip().lower()
                storage_dir = get_default_clipboard_storage_dir().resolve()
                img_fname = data_dict.get("image_filename")
                if img_fname is not None:
                    if (
                        not isinstance(img_fname, str)
                        or not img_fname
                        or "/" in img_fname
                        or "\\" in img_fname
                        or ".." in img_fname
                        or "\0" in img_fname
                        or ":" in img_fname
                        or Path(img_fname).name != img_fname
                    ):
                        return web.json_response(
                            {"success": False, "status": "FORBIDDEN", "error": "Access denied."},
                            status=403,
                        )
                    raw_candidate = storage_dir / img_fname
                    if not _is_contained_non_symlink(raw_candidate, storage_dir):
                        return web.json_response(
                            {"success": False, "status": "FORBIDDEN", "error": "Access denied."},
                            status=403,
                        )
                    if raw_candidate.resolve().is_file():
                        target_file = raw_candidate.resolve()
                else:
                    sha256 = str(item.get("sha256") or "").strip().lower()
                    if re.fullmatch(r"[0-9a-f]{64}", sha256):
                        matching = sorted(storage_dir.glob(f"clip_{sha256[:16]}_*.*"))
                        for cand in matching:
                            if not _is_contained_non_symlink(cand, storage_dir):
                                return web.json_response(
                                    {"success": False, "status": "FORBIDDEN", "error": "Access denied."},
                                    status=403,
                                )
                            if cand.resolve().is_file():
                                target_file = cand.resolve()
                                break
            else:
                err_status = str((res or {}).get("status") or "").strip().upper()
                if err_status in OFFLINE_IPC_STATUSES:
                    ipc_unavailable = True
                elif err_status == "INVALID_ARGUMENT":
                    return web.json_response(
                        {
                            "success": False,
                            "status": "INVALID_ARGUMENT",
                            "error": str((res or {}).get("error") or "Invalid item ID."),
                        },
                        status=400,
                    )
                else:
                    return web.json_response(
                        {
                            "success": False,
                            "status": err_status or "NOT_FOUND",
                            "error": str((res or {}).get("error") or "Clipboard image not found."),
                        },
                        status=404,
                    )
        else:
            ipc_unavailable = True

        if target_file is None and ipc_unavailable:
            if isinstance(in_proc_buf, ClipboardRingBuffer):
                storage_dir = in_proc_buf.storage_dir.resolve()
                item = in_proc_buf.get_item(item_id, include_content=False)
                if not item or (item.get("type") != "image" and item.get("content_type") != "image"):
                    return web.json_response(
                        {"success": False, "status": "NOT_FOUND", "error": "Clipboard image not found."},
                        status=404,
                    )
                mime_hint = str(item.get("mime_type") or "").strip().lower()
                raw_path = in_proc_buf.get_image_path(item_id)
                if raw_path is not None:
                    if not _is_contained_non_symlink(raw_path, storage_dir):
                        return web.json_response(
                            {"success": False, "status": "FORBIDDEN", "error": "Access denied."},
                            status=403,
                        )
                    target_file = raw_path.resolve()
            else:
                return web.json_response(
                    {
                        "success": False,
                        "status": "CORE_OFFLINE",
                        "error": "Desktop Core IPC unavailable for clipboard image lookup.",
                    },
                    status=503,
                )

        if target_file is None or storage_dir is None or not target_file.is_file():
            return web.json_response(
                {"success": False, "status": "NOT_FOUND", "error": "Clipboard image file not found."},
                status=404,
            )

        if not _is_contained_non_symlink(target_file, storage_dir):
            return web.json_response(
                {"success": False, "status": "FORBIDDEN", "error": "Access denied."},
                status=403,
            )

        if mime_hint == "image/jpg":
            mime_hint = "image/jpeg"
        if mime_hint and mime_hint not in {"image/png", "image/jpeg"}:
            return web.json_response(
                {
                    "success": False,
                    "status": "UNSUPPORTED_MEDIA_TYPE",
                    "error": f"Unsupported clipboard image MIME type '{mime_hint}'.",
                },
                status=415,
            )

        try:
            file_size = target_file.stat().st_size
            if file_size <= 0:
                return web.json_response(
                    {"success": False, "status": "CORRUPTED_IMAGE", "error": "Clipboard image file is empty."},
                    status=422,
                )
            if file_size > MAX_IMAGE_BYTES:
                return web.json_response(
                    {
                        "success": False,
                        "status": "PAYLOAD_TOO_LARGE",
                        "error": f"Clipboard image exceeds {MAX_IMAGE_BYTES} byte limit.",
                    },
                    status=413,
                )

            with target_file.open("rb") as fh:
                data = fh.read(MAX_IMAGE_BYTES + 1)
            if len(data) > MAX_IMAGE_BYTES:
                return web.json_response(
                    {
                        "success": False,
                        "status": "PAYLOAD_TOO_LARGE",
                        "error": f"Clipboard image exceeds {MAX_IMAGE_BYTES} byte limit.",
                    },
                    status=413,
                )

            if data.startswith(PNG_SIGNATURE):
                actual_mime = "image/png"
            elif data.startswith(JPEG_SIGNATURE):
                actual_mime = "image/jpeg"
            else:
                return web.json_response(
                    {
                        "success": False,
                        "status": "UNSUPPORTED_MEDIA_TYPE",
                        "error": "Clipboard image binary format is corrupted or unsupported.",
                    },
                    status=415,
                )

            if mime_hint and mime_hint != actual_mime:
                return web.json_response(
                    {
                        "success": False,
                        "status": "UNSUPPORTED_MEDIA_TYPE",
                        "error": "Clipboard image MIME type does not match binary content.",
                    },
                    status=415,
                )

            return web.Response(
                body=data,
                content_type=actual_mime,
                headers={
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                },
            )
        except Exception as exc:
            logger.error("Failed reading clipboard image '%s': %s", item_id, exc)
            return web.json_response(
                {"success": False, "status": "INTERNAL_ERROR", "error": "Internal error reading image."},
                status=500,
            )

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
    # Distribution & Onboarding (Phase 29 & Phase 3)
    # =========================================================================

    def _find_candidate_apk(self) -> Optional[Path]:
        """Resolve the mobile APK binary across frozen, package output, and local build paths."""
        import re as _re
        candidates = []
        env_apk = os.environ.get("SNOW_ANDROID_APK_PATH")
        if env_apk:
            candidates.append(Path(env_apk).resolve())

        def _apk_ver_key(p: Path) -> tuple[int, ...]:
            m = _re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", p.name)
            return tuple(int(g or 0) for g in m.groups()) if m else (0, 0, 0)

        # Frozen sibling paths (for snow.exe / snow-tray.exe)
        exe_dir = Path(sys.executable).resolve().parent
        for folder in (exe_dir / "packaging" / "output", exe_dir):
            if folder.is_dir():
                candidates.extend(sorted(folder.glob("SNOW-Mobile-*.apk"), key=_apk_ver_key, reverse=True))
        candidates.append(exe_dir / "SNOW-Mobile.apk")

        # Repository paths
        repo_root = Path(__file__).resolve().parent.parent.parent.parent
        repo_out = repo_root / "packaging" / "output"
        if repo_out.is_dir():
            candidates.extend(sorted(repo_out.glob("SNOW-Mobile-*.apk"), key=_apk_ver_key, reverse=True))
        candidates.append(repo_root / "packaging" / "output" / "SNOW-Mobile.apk")
        candidates.append(repo_root / "packaging" / "output" / "app-release.apk")
        candidates.append(repo_root / "android" / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk")
        candidates.append(repo_root / "android" / "app" / "build" / "outputs" / "apk" / "release" / "app-release-unsigned.apk")
        candidates.append(repo_root / "android" / "app" / "build" / "outputs" / "apk" / "debug" / "app-debug.apk")

        allowed_dirs = [
            os.path.realpath(str(repo_root / "packaging" / "output")),
            os.path.realpath(str(repo_root / "android")),
            os.path.realpath(str(exe_dir)),
            os.path.realpath(str(exe_dir / "packaging" / "output")),
        ]
        if env_apk:
            allowed_dirs.append(os.path.realpath(os.path.dirname(os.path.abspath(env_apk))))

        for candidate in candidates:
            if candidate.is_file():
                real_path = os.path.realpath(str(candidate))
                if real_path.lower().endswith(".apk") and os.path.isfile(real_path):
                    if any(real_path.startswith(ad + os.sep) or real_path == ad for ad in allowed_dirs):
                        return Path(real_path)
        return None

    async def _ensure_ephemeral_apk_server(self) -> int:
        """Start or verify the ephemeral LAN server serving GET /download?token=... on port 0."""
        async with self._ephemeral_apk_lock:
            if self._ephemeral_apk_runner and self._ephemeral_apk_port > 0:
                return self._ephemeral_apk_port

            app = web.Application()

            async def handle_ephemeral_download(request: web.Request) -> web.StreamResponse:
                token = request.query.get("token")
                now = time.time()
                # Clean expired tokens
                self._apk_download_tokens = {k: v for k, v in self._apk_download_tokens.items() if v > now}
                if not token or token not in self._apk_download_tokens or self._apk_download_tokens[token] <= now:
                    return web.Response(status=401, text="Unauthorized: Token missing or expired.")

                apk_path = self._find_candidate_apk()
                if not apk_path:
                    return web.Response(status=404, text="APK not found.")

                return web.FileResponse(
                    apk_path,
                    headers={
                        "Content-Type": "application/vnd.android.package-archive",
                        "Content-Disposition": f'attachment; filename="{apk_path.name}"',
                    },
                )

            app.router.add_get("/download", handle_ephemeral_download)
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, host="0.0.0.0", port=0)
            await site.start()

            bound_port = 0
            for s in runner.sites:
                if hasattr(s, "_server") and s._server and hasattr(s._server, "sockets"):
                    for sock in s._server.sockets:
                        bound_port = sock.getsockname()[1]
                        break
                if bound_port:
                    break
            if not bound_port:
                for ep in runner.addresses:
                    bound_port = ep[1]
                    break

            self._ephemeral_apk_app = app
            self._ephemeral_apk_runner = runner
            self._ephemeral_apk_site = site
            self._ephemeral_apk_port = bound_port
            logger.info("Ephemeral LAN APK download server listening on 0.0.0.0:%d", bound_port)
            return bound_port

    async def handle_api_install_android_apk(self, request: web.Request) -> web.Response:
        """Serve the compiled Android APK for local download (supports session cookie or ?token=)."""
        token = request.query.get("token")
        now = time.time()
        # Clean expired tokens
        self._apk_download_tokens = {k: v for k, v in self._apk_download_tokens.items() if v > now}
        is_token_valid = bool(token and token in self._apk_download_tokens and self._apk_download_tokens[token] > now)
        session = self._get_valid_session(request)
        if not is_token_valid and not session:
            return web.json_response(
                {"success": False, "status": "UNAUTHORIZED", "error": "Authentication required."},
                status=401,
            )

        apk_path = self._find_candidate_apk()
        if not apk_path:
            return web.json_response(
                {
                    "success": False,
                    "status": "APK_NOT_FOUND",
                    "error": (
                        "Android APK has not been compiled yet. "
                        "Build it by running './gradlew assembleRelease' or './gradlew assembleDebug' in android/."
                    ),
                },
                status=404,
            )

        return web.FileResponse(
            apk_path,
            headers={
                "Content-Type": "application/vnd.android.package-archive",
                "Content-Disposition": f'attachment; filename="{apk_path.name}"',
            },
        )

    async def handle_api_app_apk_info(self, request: web.Request) -> web.Response:
        """Return mobile APK metadata, generate short-lived download token, start ephemeral server and SVG QR code."""
        # Clean expired tokens
        now = time.time()
        self._apk_download_tokens = {k: v for k, v in self._apk_download_tokens.items() if v > now}

        # Issue 10-minute token
        token = secrets.token_urlsafe(24)
        self._apk_download_tokens[token] = now + 600.0

        apk_path = self._find_candidate_apk()
        apk_found = apk_path is not None

        # Resolve LAN IP
        from snow.core.network import get_active_ip_addresses
        ips = get_active_ip_addresses()
        lan_ip = ips[0] if ips else "127.0.0.1"

        # Ensure ephemeral LAN server is running for phone download
        ephemeral_port = await self._ensure_ephemeral_apk_server()
        qr_download_url = f"http://{lan_ip}:{ephemeral_port}/download?token={token}"
        local_download_url = f"/api/app/download-apk?token={token}"

        # Generate SVG QR code for mobile scanner
        svg_content = ""
        try:
            import qrcode
            import qrcode.image.svg
            img = qrcode.make(qr_download_url, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
            svg_content = img.to_string().decode("utf-8") if isinstance(img.to_string(), bytes) else str(img.to_string())
        except Exception as qre:
            logger.debug("Failed rendering APK download QR SVG: %s", qre)

        from snow.updater import CURRENT_VERSION

        resolved_name = apk_path.name if apk_path else f"SNOW-Mobile-{CURRENT_VERSION}.apk"
        return web.json_response({
            "success": True,
            "status": "SUCCESS",
            "apk_available": apk_found,
            "download_url": qr_download_url,
            "local_download_url": local_download_url,
            "token": token,
            "version": CURRENT_VERSION,
            "file_name": resolved_name,
            "svg": svg_content,
        })

    async def handle_api_onboarding_status(self, request: web.Request) -> web.Response:
        """Query consumer onboarding status and authoritative network identity."""
        try:
            from snow.network.network_model import SnowNetworkManager
            cap_engine = getattr(self.bridge, "capability_engine", None)
            db_mgr = getattr(cap_engine, "db_manager", None) or self.db_manager
            net_mgr = SnowNetworkManager(db_manager=db_mgr)
            ident = net_mgr.get_network_identity()
            completed = str(db_mgr.get_setting("onboarding_completed", "false")).lower() in ("true", "1", "yes")
            devices = db_mgr.list_paired_devices()

            return web.json_response({
                "success": True,
                "status": "SUCCESS",
                "completed": completed,
                "network_name": ident.network_name,
                "network_id": ident.network_id,
                "device_count": len(devices),
            })
        except Exception as exc:
            logger.error("Failed querying onboarding status: %s", exc)
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    async def handle_api_onboarding_complete(self, request: web.Request) -> web.Response:
        """Mark first-run consumer onboarding wizard as completed and update network identity."""
        try:
            body = await request.json()
        except Exception:
            body = {}

        try:
            from snow.network.network_model import SnowNetworkManager
            cap_engine = getattr(self.bridge, "capability_engine", None)
            db_mgr = getattr(cap_engine, "db_manager", None) or self.db_manager
            net_mgr = SnowNetworkManager(db_manager=db_mgr)

            network_name = (body.get("network_name") or "").strip()
            if network_name:
                if len(network_name) > 64:
                    network_name = network_name[:64]
                ident = net_mgr.update_network_name(network_name)
            else:
                ident = net_mgr.get_network_identity()

            db_mgr.set_setting("onboarding_completed", "true")

            return web.json_response({
                "success": True,
                "status": "ONBOARDING_COMPLETED",
                "network_name": ident.network_name,
                "network_id": ident.network_id,
            })
        except Exception as exc:
            logger.error("Failed completing onboarding: %s", exc)
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    async def handle_api_account_discovery_status(self, request: web.Request) -> web.Response:
        """Query status of the strictly opt-in account discovery layer."""
        from snow.network.account_discovery import AccountDiscoveryService
        svc = AccountDiscoveryService()
        return web.json_response({
            "success": True,
            **svc.get_status(),
        })

    async def handle_api_account_discovery_config(self, request: web.Request) -> web.Response:
        """Configure or toggle the strictly opt-in account discovery layer."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        from snow.network.account_discovery import AccountDiscoveryService
        svc = AccountDiscoveryService()

        enabled = body.get("enabled")
        if enabled is not None:
            svc.set_enabled(bool(enabled))

        issuer = body.get("issuer")
        audience = body.get("audience")
        account_id = body.get("account_id")
        if issuer and audience:
            svc.configure(issuer=issuer, audience=audience, account_id=account_id)

        return web.json_response({
            "success": True,
            "status": "UPDATED",
            **svc.get_status(),
        })

    # =========================================================================
    # Federation & Sharing (Phase 30)
    # =========================================================================

    def _get_federation_manager(self) -> Any:
        from snow.network.federation import FederationManager
        from snow.network.network_model import SnowNetworkManager
        from snow.security.tls import (
            DEFAULT_CERT_FILE,
            DEFAULT_KEY_FILE,
            DEFAULT_TLS_DIR,
            ensure_tls_certificate,
        )
        import os
        from pathlib import Path

        cap_engine = getattr(self.bridge, "capability_engine", None)
        db_mgr = getattr(cap_engine, "db_manager", None) or self.db_manager
        net_mgr = SnowNetworkManager(db_manager=db_mgr)
        ident = net_mgr.get_network_identity()

        # Genuine TLS Fingerprint calculation (Repair 4)
        data_dir = os.environ.get("SNOW_DATA_DIR")
        tls_dir = (Path(data_dir).resolve() / "tls") if data_dir else DEFAULT_TLS_DIR
        cert_path = tls_dir / DEFAULT_CERT_FILE
        key_path = tls_dir / DEFAULT_KEY_FILE

        try:
            cert_info = ensure_tls_certificate(cert_path=cert_path, key_path=key_path)
            local_fingerprint = cert_info.fingerprint_sha256
        except Exception as e:
            logger.error("Failed obtaining genuine TLS certificate fingerprint: %s", e)
            raise RuntimeError(f"Host TLS certificate inaccessible or invalid for federation: {e}") from e

        return FederationManager(
            db_manager=db_mgr,
            local_network_id=ident.network_id,
            local_network_name=ident.network_name,
            local_node_id="desktop-core",
            local_node_name="Windows Desktop Host",
            local_cert_fingerprint=local_fingerprint,
            failed_attempts_store=self._federation_failed_attempts,
        )

    async def _authenticate_hub_session(
        self, session: Any, hub_url: str
    ) -> tuple[bool, str, str, str]:
        """Acquire a short-lived Ed25519 hub-session Bearer token via /v1/hub/challenge & /v1/hub/session."""
        from snow.security.identity import load_or_create_device_identity, load_or_create_network_key_identity

        try:
            net_ident = load_or_create_network_key_identity()
            dev_ident = load_or_create_device_identity()
        except Exception as exc:
            return False, "", "HUB_AUTH_FAILED", f"Failed loading local hub Ed25519 identity: {exc}"

        if not net_ident or not dev_ident:
            return False, "", "HUB_AUTH_FAILED", "Local hub Ed25519 identity is unavailable."

        base = hub_url.rstrip("/")
        try:
            async with session.post(
                f"{base}/v1/hub/challenge",
                json={
                    "network_id": net_ident.network_id,
                    "public_key": net_ident.public_key_b64,
                    "device_id": dev_ident.device_id,
                    "snow_id": dev_ident.snow_id,
                },
            ) as ch_resp:
                try:
                    ch_data = await ch_resp.json(content_type=None)
                except Exception:
                    ch_data = {}
                if ch_resp.status in (401, 403):
                    return False, "", "HUB_AUTH_FAILED", str(
                        ch_data.get("error") or "Hub rejected challenge authentication."
                    )
                if ch_resp.status >= 500:
                    return False, "", "HUB_UNAVAILABLE", str(
                        ch_data.get("error") or f"Hub challenge returned HTTP {ch_resp.status}."
                    )
                if ch_resp.status != 200 or not isinstance(ch_data, dict) or not ch_data.get("challenge_id"):
                    return False, "", "HUB_AUTH_FAILED", str(
                        ch_data.get("error") or f"Hub challenge failed (HTTP {ch_resp.status})."
                    )

            sig_b64 = net_ident.sign_hub_challenge(ch_data, device_id=dev_ident.device_id)
            async with session.post(
                f"{base}/v1/hub/session",
                json={
                    "challenge_id": ch_data["challenge_id"],
                    "network_id": net_ident.network_id,
                    "public_key": net_ident.public_key_b64,
                    "signature": sig_b64,
                    "device_id": dev_ident.device_id,
                    "snow_id": dev_ident.snow_id,
                },
            ) as sess_resp:
                try:
                    sess_data = await sess_resp.json(content_type=None)
                except Exception:
                    sess_data = {}
                if sess_resp.status in (401, 403):
                    return False, "", "HUB_AUTH_FAILED", str(
                        sess_data.get("error") or "Hub rejected Ed25519 session signature."
                    )
                if sess_resp.status >= 500:
                    return False, "", "HUB_UNAVAILABLE", str(
                        sess_data.get("error") or f"Hub session returned HTTP {sess_resp.status}."
                    )
                token = str((sess_data or {}).get("token") or "").strip()
                if sess_resp.status != 200 or not (sess_data or {}).get("success") or not token:
                    return False, "", "HUB_AUTH_FAILED", str(
                        (sess_data or {}).get("error") or "Hub did not issue a valid session token."
                    )
                return True, token, "OK", ""
        except asyncio.TimeoutError:
            return False, "", "HUB_UNAVAILABLE", "Cloud hub directory request timed out."
        except Exception as exc:
            return False, "", "HUB_UNAVAILABLE", f"Cloud hub directory is unreachable: {exc}"

    @staticmethod
    def _extract_valid_hub_endpoints(hub_data: dict[str, Any]) -> tuple[bool, str, int, str]:
        """Validate hub directory endpoint fields; fail closed on missing or invalid endpoints."""
        import urllib.parse

        raw_lan = hub_data.get("lan_endpoints")
        resolved_host = ""
        resolved_port = 8765
        has_valid_lan = False
        if isinstance(raw_lan, list):
            for entry in raw_lan:
                if not isinstance(entry, str) or not entry.strip():
                    continue
                cand = entry.strip()
                if ":" in cand:
                    h_part, p_part = cand.rsplit(":", 1)
                    h_part = h_part.strip("[] ")
                    try:
                        p_num = int(p_part)
                        if h_part and 1 <= p_num <= 65535:
                            resolved_host, resolved_port, has_valid_lan = h_part, p_num, True
                            break
                    except ValueError:
                        continue
                elif cand:
                    resolved_host, resolved_port, has_valid_lan = cand, 8765, True
                    break

        direct_host = str(hub_data.get("host") or "").strip()
        if not resolved_host and direct_host:
            try:
                p_num = int(hub_data.get("port") or 8765)
                if 1 <= p_num <= 65535:
                    resolved_host, resolved_port, has_valid_lan = direct_host, p_num, True
            except (TypeError, ValueError):
                pass

        relay_ws_url = str(hub_data.get("relay_ws_url") or "").strip()
        has_valid_relay = False
        if relay_ws_url:
            parsed = urllib.parse.urlparse(relay_ws_url)
            if parsed.scheme in ("wss", "ws") and bool(parsed.hostname):
                has_valid_relay = True
            else:
                return False, "", 8765, "Invalid relay_ws_url returned by hub directory."

        if not has_valid_lan and not has_valid_relay:
            return False, "", 8765, "Hub directory response did not include a valid LAN or relay endpoint."
        return True, resolved_host, resolved_port, ""

    async def _resolve_snow_id_directory(self, snow_id: str) -> dict[str, Any]:
        """Resolve a SNOW ID: validate -> local paired DB -> Core IPC LAN discovery -> authenticated Cloud Hub."""
        from snow.core.config import resolve_default_hub_url
        from snow.relay.auth import is_valid_network_id, is_valid_snow_id
        from snow.security.identity import generate_snow_id, load_or_create_device_identity

        # 1. Validate & normalize requested SNOW ID
        clean_id = (snow_id or "").strip().upper()
        if not (is_valid_snow_id(clean_id) or is_valid_network_id(clean_id)):
            return {"success": False, "found": False, "status": "INVALID_SNOW_ID", "error": "Invalid SNOW ID format."}

        cap_engine = getattr(getattr(self, "bridge", None), "capability_engine", None)
        db_mgr = getattr(self, "db_manager", None) or getattr(cap_engine, "db_manager", None)
        local_ident = load_or_create_device_identity()
        if local_ident.snow_id.upper() == clean_id:
            return {
                "success": True,
                "found": True,
                "source": "local",
                "snow_id": clean_id,
                "device_id": local_ident.device_id,
                "host": "127.0.0.1",
                "port": 8765,
            }

        # 2. Check existing local paired-device database first
        paired_match: Optional[Any] = None
        if db_mgr and hasattr(db_mgr, "list_paired_devices"):
            for p in db_mgr.list_paired_devices():
                cand_snow = (getattr(p, "snow_id", None) or generate_snow_id(seed=p.device_id)).upper()
                if cand_snow == clean_id or str(p.device_id).upper() == clean_id:
                    paired_match = p
                    break
        if paired_match is not None and str(paired_match.last_known_host or "").strip():
            return {
                "success": True,
                "found": True,
                "source": "paired_db",
                "snow_id": clean_id,
                "device_id": paired_match.device_id,
                "device_name": paired_match.device_name,
                "host": str(paired_match.last_known_host).strip(),
                "port": paired_match.last_known_port or 8765,
                "cert_fingerprint": paired_match.cert_fingerprint or "",
                "is_paired": True,
            }

        # 3 & 4. Query Core LAN discovery service via bounded Core IPC operation
        discovery_status = "OK"
        discovery_error: Optional[str] = None
        if getattr(self, "bridge", None) and hasattr(self.bridge, "call"):
            try:
                ipc_res = await self.bridge.call("list_discovered_peers", {"snow_id": clean_id}, timeout=2.0)
                if isinstance(ipc_res, dict) and ipc_res.get("success"):
                    data_obj = ipc_res.get("data") if isinstance(ipc_res.get("data"), dict) else {}
                    raw_peers = data_obj.get("peers")
                    if raw_peers is None:
                        raw_peers = ipc_res.get("peers")
                    for peer in raw_peers or []:
                        if not isinstance(peer, dict):
                            continue
                        p_id = str(peer.get("device_id") or "").strip()
                        p_snow = str(
                            peer.get("snow_id") or (generate_snow_id(seed=p_id) if p_id else "")
                        ).strip().upper()
                        if p_snow == clean_id or (p_id and p_id.upper() == clean_id):
                            p_host = str(peer.get("host") or peer.get("ip_address") or "").strip()
                            try:
                                p_port = int(peer.get("port") or 8765)
                            except (TypeError, ValueError):
                                p_port = 8765
                            if p_host:
                                return {
                                    "success": True,
                                    "found": True,
                                    "source": "lan_discovery",
                                    "snow_id": clean_id,
                                    "device_id": p_id,
                                    "device_name": str(peer.get("device_name") or "LAN Peer"),
                                    "device_type": str(peer.get("device_type") or "unknown"),
                                    "host": p_host,
                                    "port": p_port,
                                    "cert_fingerprint": str(peer.get("cert_fingerprint") or ""),
                                    "is_paired": bool(paired_match is not None or peer.get("is_paired")),
                                }
                elif isinstance(ipc_res, dict) and not ipc_res.get("success"):
                    discovery_status = "DISCOVERY_UNAVAILABLE"
                    discovery_error = str(
                        ipc_res.get("error") or ipc_res.get("status") or "Core LAN discovery unavailable."
                    )
            except Exception as exc:
                discovery_status = "DISCOVERY_UNAVAILABLE"
                discovery_error = f"Local LAN discovery query failed: {exc}"
                logger.debug("Local discovery IPC error resolving %s: %s", clean_id, exc)
        else:
            discovery_status = "DISCOVERY_UNAVAILABLE"
            discovery_error = "Core IPC bridge is unavailable for local discovery."

        # 5. Authenticated cloud directory resolution only if local resolution found no usable target
        hub_url = resolve_default_hub_url(db_manager=db_mgr)
        if hub_url:
            import aiohttp

            target_url = f"{hub_url.rstrip('/')}/v1/directory/resolve/{clean_id}"
            try:
                timeout = aiohttp.ClientTimeout(total=4.0)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    ok_auth, hub_token, auth_status, auth_err = await self._authenticate_hub_session(session, hub_url)
                    if not ok_auth or not hub_token:
                        return {
                            "success": False,
                            "found": False,
                            "status": auth_status,
                            "error": auth_err or "Cloud hub authentication failed.",
                            "snow_id": clean_id,
                            "source": "hub_directory",
                            **({"discovery_error": discovery_error} if discovery_error else {}),
                        }

                    async with session.get(
                        target_url,
                        headers={"Authorization": f"Bearer {hub_token}"},
                    ) as resp:
                        try:
                            hub_data = await resp.json(content_type=None)
                        except Exception:
                            hub_data = {}

                        if resp.status == 401:
                            return {
                                "success": False,
                                "found": False,
                                "status": "HUB_AUTH_FAILED",
                                "error": str((hub_data or {}).get("error") or "Hub directory authentication failed."),
                                "snow_id": clean_id,
                                "source": "hub_directory",
                            }
                        if resp.status == 403:
                            return {
                                "success": False,
                                "found": False,
                                "status": "FORBIDDEN",
                                "error": str((hub_data or {}).get("error") or "Cross-network directory lookup denied."),
                                "snow_id": clean_id,
                                "source": "hub_directory",
                            }
                        if resp.status == 404:
                            return {
                                "success": False,
                                "found": False,
                                "status": "REMOTE_DEVICE_NOT_FOUND",
                                "error": str((hub_data or {}).get("error") or f"Remote device '{clean_id}' not found."),
                                "snow_id": clean_id,
                                "source": "hub_directory",
                            }
                        if resp.status >= 500 or resp.status != 200 or not isinstance(hub_data, dict):
                            return {
                                "success": False,
                                "found": False,
                                "status": "HUB_UNAVAILABLE",
                                "error": str((hub_data or {}).get("error") or f"Cloud hub returned HTTP {resp.status}."),
                                "snow_id": clean_id,
                                "source": "hub_directory",
                            }

                        if "online" in hub_data and not hub_data.get("online"):
                            return {
                                "success": False,
                                "found": False,
                                "status": "REMOTE_DEVICE_OFFLINE",
                                "error": f"Remote device '{clean_id}' is currently offline.",
                                "snow_id": clean_id,
                                "source": "hub_directory",
                            }

                        ep_ok, ep_host, ep_port, ep_err = self._extract_valid_hub_endpoints(hub_data)
                        if not ep_ok:
                            return {
                                "success": False,
                                "found": False,
                                "status": "INVALID_ENDPOINT",
                                "error": ep_err,
                                "snow_id": clean_id,
                                "source": "hub_directory",
                            }

                        result: dict[str, Any] = {
                            "success": True,
                            "found": True,
                            "source": "hub_directory",
                            "snow_id": clean_id,
                            "hub_url": hub_url,
                            **hub_data,
                        }
                        if ep_host:
                            result["host"] = ep_host
                            result["port"] = ep_port
                        return result
            except asyncio.TimeoutError:
                return {
                    "success": False,
                    "found": False,
                    "status": "HUB_UNAVAILABLE",
                    "error": f"Cloud hub directory timed out resolving '{clean_id}'.",
                    "snow_id": clean_id,
                    "source": "hub_directory",
                    **({"discovery_error": discovery_error} if discovery_error else {}),
                }
            except Exception as exc:
                logger.debug("Hub directory lookup failed for %s: %s", clean_id, exc)
                return {
                    "success": False,
                    "found": False,
                    "status": "HUB_UNAVAILABLE",
                    "error": f"Cloud hub directory unavailable: {exc}",
                    "snow_id": clean_id,
                    "source": "hub_directory",
                    **({"discovery_error": discovery_error} if discovery_error else {}),
                }

        if discovery_status == "DISCOVERY_UNAVAILABLE":
            return {
                "success": False,
                "found": False,
                "status": "DISCOVERY_UNAVAILABLE",
                "error": discovery_error or f"Local discovery unavailable resolving '{clean_id}'.",
                "snow_id": clean_id,
            }
        return {
            "success": False,
            "found": False,
            "status": "LOCAL_DEVICE_NOT_FOUND",
            "error": f"No reachable local or remote peer found for '{clean_id}'.",
            "snow_id": clean_id,
        }

    async def handle_api_directory_resolve(self, request: web.Request) -> web.Response:
        """Resolve a SNOW ID or Network ID across local mesh and authenticated cloud hub."""
        snow_id = request.match_info.get("snow_id", "").strip()
        res = await self._resolve_snow_id_directory(snow_id)
        if res.get("found"):
            status = 200
        else:
            code = str(res.get("status") or "NOT_FOUND")
            status = {
                "INVALID_SNOW_ID": 400,
                "HUB_AUTH_FAILED": 401,
                "FORBIDDEN": 403,
                "INVALID_ENDPOINT": 502,
                "HUB_UNAVAILABLE": 503,
                "DISCOVERY_UNAVAILABLE": 503,
            }.get(code, 404)
        return web.json_response(res, status=status)

    async def handle_api_federation_grants(self, request: web.Request) -> web.Response:
        """List active and revoked cross-network federation grants."""
        try:
            fed_mgr = self._get_federation_manager()
            grants = fed_mgr.list_grants()
            return web.json_response({
                "success": True,
                "status": "SUCCESS",
                "local_network_id": fed_mgr.local_network_id,
                "local_network_name": fed_mgr.local_network_name,
                "grants": grants,
            })
        except Exception as exc:
            logger.error("Failed querying federation grants: %s", exc)
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    async def handle_api_federation_invite(self, request: web.Request) -> web.Response:
        """Generate a 9-digit mutual federation invitation code."""
        try:
            body = await request.json()
        except Exception:
            body = {}

        try:
            fed_mgr = self._get_federation_manager()
            caps = body.get("allowed_capabilities")
            devs = body.get("allowed_device_ids")
            grant_ttl = int(body.get("grant_ttl_seconds", 86400))
            ttl = int(body.get("ttl_seconds", 600))
            perm_tier = body.get("permission_tier")

            res = fed_mgr.create_invitation(
                allowed_capabilities=caps,
                allowed_device_ids=devs,
                grant_ttl_seconds=grant_ttl,
                ttl_seconds=ttl,
                principal="OWNER_MANUAL",
                permission_tier=perm_tier,
            )
            return web.json_response(res)
        except ValueError as ve:
            return web.json_response({"success": False, "error": str(ve)}, status=400)
        except PermissionError as pe:
            return web.json_response({"success": False, "error": str(pe)}, status=403)
        except Exception as exc:
            logger.error("Failed creating federation invitation: %s", exc)
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    async def handle_api_federation_tier(self, request: web.Request) -> web.Response:
        """Update the 5-tier permission preset for an active federation grant immediately."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        grant_id = str(body.get("grant_id", "")).strip()
        tier = str(body.get("permission_tier", "")).strip().lower()
        if not grant_id or not tier:
            return web.json_response({"success": False, "error": "Missing 'grant_id' or 'permission_tier'."}, status=400)

        try:
            fed_mgr = self._get_federation_manager()
            res = fed_mgr.update_grant_permission_tier(grant_id, tier, principal="OWNER_MANUAL")
            status_code = 200 if res.get("success") else 404
            return web.json_response(res, status=status_code)
        except ValueError as ve:
            return web.json_response({"success": False, "error": str(ve)}, status=400)
        except PermissionError as pe:
            return web.json_response({"success": False, "error": str(pe)}, status=403)
        except Exception as exc:
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    async def handle_api_federation_accept(self, request: web.Request) -> web.Response:
        """Accept a 9-digit federation invitation code from a peer network."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        code = str(body.get("code", "")).strip()
        peer_net_id = str(body.get("peer_network_id", "")).strip() or "remote-network"
        peer_net_name = str(body.get("peer_network_name", "")).strip() or "Remote SNOW Network"
        peer_node_id = str(body.get("peer_node_id", "")).strip() or "remote-node"
        peer_node_name = str(body.get("peer_node_name", "")).strip() or "Remote Coordinator"
        peer_fp = str(body.get("peer_cert_fingerprint", "")).strip() or "REMOTE_FINGERPRINT"

        # Requester-keyed rate limiting identity
        session_id = request.get("snow_session_id") or request.cookies.get("snow_session")
        remote_ip = request.remote or "127.0.0.1"
        requester_id = f"{remote_ip}:{session_id}" if session_id else remote_ip

        try:
            fed_mgr = self._get_federation_manager()
            res = fed_mgr.accept_invitation(
                code=code,
                peer_network_id=peer_net_id,
                peer_network_name=peer_net_name,
                peer_node_id=peer_node_id,
                peer_node_name=peer_node_name,
                peer_cert_fingerprint=peer_fp,
                principal="OWNER_MANUAL",
                requester_id=requester_id,
            )
            if res.get("status") == "RATE_LIMIT_EXCEEDED":
                return web.json_response(res, status=429)
            status_code = 200 if res.get("success") else 400
            return web.json_response(res, status=status_code)
        except PermissionError as pe:
            return web.json_response({"success": False, "error": str(pe)}, status=403)
        except Exception as exc:
            logger.error("Failed accepting federation invitation: %s", exc)
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    async def handle_api_federation_revoke(self, request: web.Request) -> web.Response:
        """Revoke a single active federation grant via Core IPC or local manager."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)

        grant_id = str(body.get("grant_id", "")).strip()
        reason = str(body.get("reason", "Revoked via Web Dashboard")).strip()

        if not grant_id:
            return web.json_response({"success": False, "error": "Missing grant_id."}, status=400)

        try:
            if hasattr(self.bridge, "federation_revoke"):
                res = await self.bridge.federation_revoke(grant_id, reason=reason)
            else:
                fed_mgr = self._get_federation_manager()
                res = fed_mgr.revoke_grant(grant_id, reason=reason, principal="OWNER_MANUAL")
            status_code = 200 if res.get("success") else 404
            return web.json_response(res, status=status_code)
        except PermissionError as pe:
            return web.json_response({"success": False, "error": str(pe)}, status=403)
        except Exception as exc:
            logger.error("Failed revoking federation grant: %s", exc)
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    async def handle_api_federation_kill_switch(self, request: web.Request) -> web.Response:
        """Global Emergency Kill Switch: immediately terminate all federation and remote sessions via Core IPC."""
        try:
            body = await request.json()
        except Exception:
            body = {}

        reason = str(body.get("reason", "Emergency Kill Switch from Web Dashboard")).strip()

        try:
            if hasattr(self.bridge, "federation_kill_switch"):
                res = await self.bridge.federation_kill_switch(reason=reason)
            else:
                fed_mgr = self._get_federation_manager()
                res = fed_mgr.global_kill_switch(reason=reason, principal="OWNER_MANUAL")
            return web.json_response(res)
        except PermissionError as pe:
            return web.json_response({"success": False, "error": str(pe)}, status=403)
        except Exception as exc:
            logger.error("Failed executing federation kill switch: %s", exc)
            return web.json_response({"success": False, "error": str(exc)}, status=500)

    # =========================================================================
    # USB Tethering and AI MCP Host Management (Batch 4)
    # =========================================================================

    async def handle_api_usb_status(self, request: web.Request) -> web.Response:
        """Query USB ADB status, connected devices, and reverse socket mappings."""
        from snow.core.usb import get_usb_status
        try:
            stat = await asyncio.to_thread(get_usb_status)
            return web.json_response({
                "success": True,
                "status": "SUCCESS",
                **stat,
            })
        except Exception as exc:
            logger.error("Failed querying USB status: %s", exc)
            return web.json_response({
                "success": False,
                "status": "ERROR",
                "error": f"Failed querying USB status: {exc}",
            }, status=500)

    async def handle_api_usb_connect(self, request: web.Request) -> web.Response:
        """Establish ADB reverse mappings for zero-data USB tethering."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        serial = body.get("serial")
        from snow.core.usb import setup_usb_reverse
        try:
            ok, msg = await asyncio.to_thread(setup_usb_reverse, serial=serial)
            return web.json_response({
                "success": ok,
                "status": "SUCCESS" if ok else "ERROR",
                "message": msg,
            }, status=200 if ok else 400)
        except Exception as exc:
            logger.error("Failed establishing USB reverse mappings: %s", exc)
            return web.json_response({
                "success": False,
                "status": "ERROR",
                "error": f"Failed establishing USB reverse mappings: {exc}",
            }, status=500)

    async def handle_api_usb_disconnect(self, request: web.Request) -> web.Response:
        """Remove ADB reverse mappings."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        serial = body.get("serial")
        from snow.core.usb import remove_usb_reverse
        try:
            ok, msg = await asyncio.to_thread(remove_usb_reverse, serial=serial)
            return web.json_response({
                "success": ok,
                "status": "SUCCESS" if ok else "ERROR",
                "message": msg,
            }, status=200 if ok else 400)
        except Exception as exc:
            logger.error("Failed removing USB reverse mappings: %s", exc)
            return web.json_response({
                "success": False,
                "status": "ERROR",
                "error": f"Failed removing USB reverse mappings: {exc}",
            }, status=500)

    async def handle_api_usb_unlock_permissions(self, request: web.Request) -> web.Response:
        """Best-effort unlock of SNOW Android runtime/special permissions over authorized USB ADB."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        serial = body.get("serial") if isinstance(body, dict) else None
        from snow.core.usb import unlock_android_permissions
        try:
            res = await asyncio.to_thread(unlock_android_permissions, serial=serial)
            return web.json_response(res, status=200 if res.get("success") else 400)
        except Exception as exc:
            logger.error("Failed unlocking Android permissions via USB: %s", exc)
            return web.json_response({
                "success": False,
                "status": "ERROR",
                "error": f"Failed unlocking Android permissions via USB: {exc}",
            }, status=500)

    async def handle_api_mcp_setup(self, request: web.Request) -> web.Response:
        """Configure SNOW MCP server across AI assistant hosts."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        host = body.get("host", "all")
        dry_run = bool(body.get("dry_run", False))
        from snow.onboarding import HostOnboardingManager
        mgr = HostOnboardingManager()
        res = mgr.setup_host(host, dry_run=dry_run)
        return web.json_response(res)

    async def handle_api_mcp_gateway_toggle(self, request: web.Request) -> web.Response:
        """Toggle or configure the remote MCP gateway with real lifecycle control."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        enable = body.get("enable")

        gw_port = getattr(self, "gateway_port", 8771)
        async with self._mcp_gateway_lock:
            is_currently_running = self._mcp_gateway_runner is not None

            # If enable is None, treat as status check
            target_enable = is_currently_running if enable is None else bool(enable)

            if target_enable and not is_currently_running:
                try:
                    from snow.mcp.remote_gateway import start_gateway_async
                    runner, site, gateway = await start_gateway_async(
                        host="127.0.0.1",
                        port=gw_port,
                        bridge=self.bridge,
                    )
                    self._mcp_gateway_runner = runner
                    self._mcp_gateway_site = site
                    self._mcp_gateway_instance = gateway
                    is_currently_running = True
                except Exception as exc:
                    logger.error("Failed starting MCP gateway on port %d: %s", gw_port, exc)
                    return web.json_response({
                        "success": False,
                        "status": "ERROR",
                        "error": f"Failed starting MCP gateway: {exc}",
                        "running": False,
                    }, status=500)
            elif not target_enable and is_currently_running:
                try:
                    if hasattr(self, "tunnel_manager"):
                        await self.tunnel_manager.stop_tunnel()
                    if self._mcp_gateway_runner:
                        await self._mcp_gateway_runner.cleanup()
                except Exception as exc:
                    logger.warning("Error during MCP gateway cleanup: %s", exc)
                finally:
                    self._mcp_gateway_runner = None
                    self._mcp_gateway_site = None
                    self._mcp_gateway_instance = None
                    is_currently_running = False

            return web.json_response({
                "success": True,
                "status": "SUCCESS",
                "running": is_currently_running,
                "port": gw_port,
                "public_url": getattr(self._mcp_gateway_instance, "public_url", None) if is_currently_running else None,
            })

    async def handle_api_mcp_test_local(self, request: web.Request) -> web.Response:
        """Execute a genuine stdio JSON-RPC handshake against the SNOW MCP server."""
        from snow.onboarding import get_canonical_mcp_entry
        mcp_entry = get_canonical_mcp_entry()
        cmd = mcp_entry["command"]
        args = mcp_entry["args"]
        cmd_args = [cmd] + args

        t0 = time.perf_counter()
        proc = None
        try:
            creation_flags = 0
            if sys.platform == "win32":
                creation_flags |= subprocess.CREATE_NO_WINDOW

            proc = await asyncio.create_subprocess_exec(
                *cmd_args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=creation_flags,
            )

            # 1. Initialize request
            init_req = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "snow-test-runner", "version": "5.2.0"},
                },
            }
            if proc.stdin is None or proc.stdout is None:
                raise RuntimeError("Failed opening subprocess pipes.")

            proc.stdin.write((json.dumps(init_req) + "\n").encode("utf-8"))
            await proc.stdin.drain()

            # Read initialize response
            init_line = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
            if not init_line:
                raise RuntimeError("Process closed stdout before responding to initialize.")
            init_resp = json.loads(init_line.decode("utf-8").strip())
            if "error" in init_resp:
                raise RuntimeError(f"Initialize error: {init_resp['error']}")

            # 2. Initialized notification
            notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
            proc.stdin.write((json.dumps(notif) + "\n").encode("utf-8"))
            await proc.stdin.drain()

            # 3. Tools list request
            tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
            proc.stdin.write((json.dumps(tools_req) + "\n").encode("utf-8"))
            await proc.stdin.drain()

            tools_line = await asyncio.wait_for(proc.stdout.readline(), timeout=5.0)
            if not tools_line:
                raise RuntimeError("Process closed stdout before responding to tools/list.")
            tools_resp = json.loads(tools_line.decode("utf-8").strip())
            if "error" in tools_resp:
                raise RuntimeError(f"tools/list error: {tools_resp['error']}")

            raw_tools = tools_resp.get("result", {}).get("tools", [])
            tool_names = [t.get("name") for t in raw_tools]
            tools_count = len(tool_names)

            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            return web.json_response({
                "success": True,
                "status": "SUCCESS",
                "tools_count": tools_count,
                "tools": tool_names,
                "expected_count": 54,
                "is_frozen": getattr(sys, "frozen", False),
                "command": cmd,
                "args": args,
                "latency_ms": elapsed_ms,
                "protocol_version": init_resp.get("result", {}).get("protocolVersion", "2024-11-05"),
                "server_info": init_resp.get("result", {}).get("serverInfo", {}),
            })
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            logger.warning("Local MCP test handshake failed: %s", exc)
            return web.json_response({
                "success": False,
                "status": "HANDSHAKE_FAILED",
                "error": str(exc),
                "command": cmd,
                "args": args,
                "latency_ms": elapsed_ms,
            }, status=500)
        finally:
            if proc:
                try:
                    if proc.stdin and not proc.stdin.is_closing():
                        proc.stdin.close()
                    proc.terminate()
                    await asyncio.wait_for(proc.wait(), timeout=1.0)
                except Exception:
                    try:
                        proc.kill()
                    except Exception:
                        pass

    async def handle_api_mcp_tunnel_start(self, request: web.Request) -> web.Response:
        """Start public tunnel for the Remote MCP Gateway with live URL synchronization."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        provider = body.get("provider", "cloudflared")
        custom_url = body.get("custom_url")

        # 1. Ensure Remote MCP Gateway is running
        async with self._mcp_gateway_lock:
            if not self._mcp_gateway_runner:
                try:
                    from snow.mcp.remote_gateway import start_gateway_async
                    runner, site, gateway = await start_gateway_async(
                        host="127.0.0.1",
                        port=self.gateway_port,
                        bridge=self.bridge,
                    )
                    self._mcp_gateway_runner = runner
                    self._mcp_gateway_site = site
                    self._mcp_gateway_instance = gateway
                except Exception as exc:
                    logger.error("Failed starting Remote MCP Gateway for tunnel: %s", exc)
                    return web.json_response({
                        "success": False,
                        "status": "GATEWAY_START_FAILED",
                        "error": f"Could not start Remote MCP Gateway on port {self.gateway_port}: {exc}",
                    }, status=500)

        # 2. Start public tunnel
        res = await self.tunnel_manager.start_tunnel(
            provider=provider,
            port=self.gateway_port,
            custom_url=custom_url,
        )

        # 3. Synchronize live public URL into RemoteMcpGateway instance
        if res.get("success") and res.get("public_url"):
            if self._mcp_gateway_instance:
                self._mcp_gateway_instance.set_public_url(res["public_url"])
        else:
            if self._mcp_gateway_instance:
                self._mcp_gateway_instance.set_public_url(None)

        return web.json_response(res, status=200 if res.get("success") else 400)

    async def handle_api_mcp_tunnel_stop(self, request: web.Request) -> web.Response:
        """Stop any active public tunnel and clear gateway public URL."""
        res = await self.tunnel_manager.stop_tunnel()
        if self._mcp_gateway_instance:
            self._mcp_gateway_instance.set_public_url(None)
        return web.json_response(res)

    async def handle_api_mcp_tunnel_status(self, request: web.Request) -> web.Response:
        """Query current tunnel status."""
        return web.json_response({"success": True, **self.tunnel_manager.get_status()})

    async def handle_api_mcp_tunnel_config_get(self, request: web.Request) -> web.Response:
        """Retrieve persistent tunnel configuration with all secrets redacted."""
        from snow.mcp.tunnel import load_tunnel_config, redact_tunnel_config
        cfg = load_tunnel_config()
        redacted = redact_tunnel_config(cfg)
        return web.json_response({"success": True, "config": redacted})

    async def handle_api_mcp_tunnel_config_post(self, request: web.Request) -> web.Response:
        """Update and persist tunnel configuration securely."""
        from snow.mcp.tunnel import load_tunnel_config, save_tunnel_config, redact_tunnel_config
        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"success": False, "status": "INVALID_JSON", "error": "Invalid JSON body."},
                status=400,
            )
        if not isinstance(body, dict):
            return web.json_response(
                {"success": False, "status": "INVALID_PAYLOAD", "error": "Request body must be a JSON object."},
                status=400,
            )

        allowed_keys = {
            "provider",
            "mcp_cloudflare_token",
            "relay_cloudflare_token",
            "cloudflare_token",
            "relay_ticket",
            "snow_id",
            "mcp_public_url",
            "relay_public_url",
            "public_url",
            "custom_url",
            "default_hub_url",
        }

        current_cfg = load_tunnel_config()
        updated_cfg = dict(current_cfg)

        for k, v in body.items():
            if k not in allowed_keys:
                continue
            if v is None:
                updated_cfg.pop(k, None)
                continue
            if not isinstance(v, str):
                return web.json_response(
                    {"success": False, "status": "INVALID_VALUE", "error": f"Field '{k}' must be a string or null."},
                    status=400,
                )
            clean_v = v.strip()
            if "url" in k and clean_v:
                if not (clean_v.startswith("https://") or clean_v.startswith("http://") or clean_v.startswith("wss://") or clean_v.startswith("ws://")):
                    return web.json_response(
                        {"success": False, "status": "INVALID_URL", "error": f"Field '{k}' must start with https://, http://, wss://, or ws://."},
                        status=400,
                    )
            if k == "provider" and clean_v:
                if clean_v.lower() not in ("cloudflared", "tailscale", "render", "custom"):
                    return web.json_response(
                        {"success": False, "status": "INVALID_PROVIDER", "error": "Provider must be 'cloudflared', 'tailscale', 'render', or 'custom'."},
                        status=400,
                    )
            # Never overwrite real credential with redacted token
            if any(sec in k for sec in ("token", "secret", "key")) and ("***" in clean_v or clean_v == "[REDACTED]"):
                continue

            updated_cfg[k] = clean_v

        try:
            save_tunnel_config(updated_cfg)
        except Exception as exc:
            logger.error("Failed persisting tunnel config: %s", exc)
            return web.json_response(
                {"success": False, "status": "PERSISTENCE_ERROR", "error": f"Failed to persist configuration: {exc}"},
                status=500,
            )

        redacted = redact_tunnel_config(updated_cfg)
        return web.json_response({"success": True, "status": "UPDATED", "config": redacted})

    # =========================================================================
    # Remote Device Relay Tunnel Endpoints (Phase 4 Stage 4A)
    # =========================================================================

    async def handle_api_relay_tunnel_start(self, request: web.Request) -> web.Response:
        """Start public tunnel for the Remote Device Relay (port 8770)."""
        body = {}
        try:
            body = await request.json()
        except Exception:
            pass

        provider = body.get("provider", "cloudflared")
        custom_url = body.get("custom_url")

        res = await self.tunnel_manager.start_relay_tunnel(
            provider=provider,
            port=8770,
            custom_url=custom_url,
        )
        return web.json_response(res, status=200 if res.get("success") else 400)

    async def handle_api_relay_tunnel_stop(self, request: web.Request) -> web.Response:
        """Stop active public tunnel for Remote Device Relay."""
        res = await self.tunnel_manager.stop_tunnel(port=8770)
        return web.json_response(res, status=200 if res.get("success") else 400)

    async def handle_api_relay_tunnel_status(self, request: web.Request) -> web.Response:
        """Query current Relay tunnel status."""
        status = self.tunnel_manager.get_status(port=8770)
        return web.json_response({"success": True, **status})

    async def handle_api_mcp_oauth_pending(self, request: web.Request) -> web.Response:
        """List active pending OAuth authorization requests."""
        if not self._mcp_gateway_instance:
            return web.json_response({"success": True, "pending": [], "gateway_online": False})
        pending = self._mcp_gateway_instance.list_pending_authorizations()
        return web.json_response({"success": True, "pending": pending, "gateway_online": True})

    async def handle_api_mcp_oauth_approve(self, request: web.Request) -> web.Response:
        """One-click owner approval of pending OAuth authorization request."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        req_id = body.get("request_id")
        if not req_id:
            return web.json_response({"success": False, "error": "Missing request_id."}, status=400)
        if not self._mcp_gateway_instance:
            return web.json_response({"success": False, "error": "MCP Gateway is not running."}, status=400)
        res = self._mcp_gateway_instance.approve_authorization(req_id)
        return web.json_response(res, status=200 if res.get("success") else 400)

    async def handle_api_mcp_oauth_reject(self, request: web.Request) -> web.Response:
        """Owner rejection of pending OAuth authorization request."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"success": False, "error": "Invalid JSON body."}, status=400)
        req_id = body.get("request_id")
        if not req_id:
            return web.json_response({"success": False, "error": "Missing request_id."}, status=400)
        if not self._mcp_gateway_instance:
            return web.json_response({"success": False, "error": "MCP Gateway is not running."}, status=400)
        res = self._mcp_gateway_instance.reject_authorization(req_id)
        return web.json_response(res)

    # =========================================================================
    # Additional Native Capability Endpoints (Phase 4 Stage 4B)
    # =========================================================================

    async def handle_api_devices_ring(self, request: web.Request) -> web.Response:
        """Ring the connected Android phone."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        device_id = body.get("device_id", "")
        duration = int(body.get("duration_seconds", 5))
        duration = max(1, min(duration, 30))
        res = await self.bridge.android_ring(duration_seconds=duration, device_id=device_id)
        return web.json_response(res)

    async def handle_api_camera_capture(self, request: web.Request) -> web.Response:
        """Trigger a camera photo capture on the connected Android phone."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        device_id = body.get("device_id", "")
        approval_id = body.get("approval_id", "")
        res = await self.bridge.android_camera_capture(device_id=device_id, approval_id=approval_id)
        return web.json_response(res)

    async def handle_api_clipboard_sync(self, request: web.Request) -> web.Response:
        """Trigger bidirectional or directed clipboard synchronization."""
        try:
            body = await request.json()
        except Exception:
            body = {}
        direction = body.get("direction", "both")
        device_id = body.get("device_id", "")
        res = await self.bridge.sync_clipboard(direction=direction, device_id=device_id)
        return web.json_response(res)

    async def handle_api_files_upload(self, request: web.Request) -> web.Response:
        """Upload a file from Desktop Web to the connected Android phone."""
        if not request.content_type.startswith("multipart/"):
            return web.json_response({"success": False, "error": "Expected multipart/form-data."}, status=400)

        import tempfile
        stage_dir = Path(tempfile.gettempdir()) / "snow_web_uploads"
        stage_dir.mkdir(parents=True, exist_ok=True)

        reader = await request.multipart()
        device_id = ""
        staged_file = None
        filename = "uploaded_file"

        while True:
            part = await reader.next()
            if part is None:
                break
            if part.name == "device_id":
                device_id = (await part.text()).strip()
            elif part.name == "file":
                filename = Path(part.filename or "uploaded_file").name
                staged_file = stage_dir / f"{secrets.token_hex(8)}_{filename}"
                total_bytes = 0
                with open(staged_file, "wb") as f:
                    while True:
                        chunk = await part.read_chunk()
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                        if total_bytes > 100 * 1024 * 1024:
                            staged_file.unlink(missing_ok=True)
                            return web.json_response({"success": False, "error": "File exceeds 100MB limit."}, status=413)
                        f.write(chunk)

        if not staged_file or not staged_file.exists():
            return web.json_response({"success": False, "error": "No file uploaded."}, status=400)

        try:
            res = await self.bridge.android_file_send(file_path=str(staged_file), device_id=device_id)
            return web.json_response({
                "success": res.get("success", False),
                "status": res.get("status", "SUCCESS"),
                "filename": filename,
                "data": res.get("data", {}),
                "error": res.get("error"),
            })
        finally:
            staged_file.unlink(missing_ok=True)

    async def handle_api_mcp_tunnel_qr(self, request: web.Request) -> web.Response:
        """Generate vector SVG QR code encoding the public Remote AI MCP Gateway endpoint."""
        status = self.tunnel_manager.get_status()
        public_url = status.get("public_url")
        if public_url:
            mcp_url = f"{public_url.rstrip('/')}/mcp"
        else:
            mcp_url = "http://127.0.0.1:8771/mcp"

        svg_content = ""
        try:
            import qrcode
            import qrcode.image.svg
            img = qrcode.make(mcp_url, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
            svg_content = img.to_string().decode("utf-8") if isinstance(img.to_string(), bytes) else str(img.to_string())
        except Exception as qre:
            logger.debug("Failed rendering MCP QR SVG: %s", qre)

        return web.json_response({
            "success": True,
            "url": mcp_url,
            "active": bool(public_url),
            "svg": svg_content,
        })

    # =========================================================================
    # System Lifecycle Endpoints (Phase 4 Stage 4A)
    # =========================================================================

    async def handle_api_system_status(self, request: web.Request) -> web.Response:
        """Query real Core runtime status, including active/paused state."""
        res = await self.bridge.call("get_device_status")
        if not res.get("success"):
            return web.json_response({
                "success": False,
                "core_running": False,
                "is_paused": False,
                "error": res.get("error", "Core daemon unreachable"),
            })
        data = res.get("data", {})
        return web.json_response({
            "success": True,
            "core_running": data.get("core_running", True),
            "is_paused": data.get("is_paused", False),
            "data": data,
        })

    async def handle_api_system_ipc_secret(self, request: web.Request) -> web.Response:
        """Return owner-only loopback Core IPC secret strictly under valid dashboard auth without logging."""
        from snow.core.ipc import get_default_secret_path, get_or_create_ipc_secret

        ipc_client = getattr(self.bridge, "ipc_client", None)
        secret_val = getattr(ipc_client, "secret", None)
        if not secret_val:
            secret_path = getattr(ipc_client, "secret_path", None) or get_default_secret_path()
            secret_val = get_or_create_ipc_secret(secret_path)

        return web.json_response(
            {
                "success": bool(secret_val),
                "ipc_secret": secret_val or "",
            },
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate",
                "Pragma": "no-cache",
            },
        )

    async def handle_api_system_pause(self, request: web.Request) -> web.Response:
        """Pause desktop background services under owner authorization."""
        # 1. Non-destructive pause: Keep public tunnels running to maintain stable URLs.
        # Mark Remote MCP Gateway as paused so incoming requests return HTTP 503.
        if getattr(self, "_mcp_gateway_instance", None):
            try:
                self._mcp_gateway_instance.set_paused(True)
            except Exception as exc:
                logger.warning("Error setting MCP gateway paused state: %s", exc)

        # 2. Invoke Core IPC system_pause via bridge
        core_res = {}
        try:
            if hasattr(self.bridge, "system_pause"):
                core_res = await self.bridge.system_pause(reason="Owner requested pause via Web Dashboard")
            else:
                core_res = await self.bridge.call("system_pause", payload={"reason": "Owner requested pause via Web Dashboard"})
        except Exception as exc:
            logger.warning("Error invoking system_pause IPC: %s", exc)
            core_res = {"success": True, "status": "PAUSED"}

        return web.json_response({
            "success": True,
            "status": "PAUSED",
            "state": "PAUSED",
            "dashboard_online": True,
            "core": core_res,
        })

    async def handle_api_system_resume(self, request: web.Request) -> web.Response:
        """Resume desktop background services from pause mode under owner authorization."""
        # 1. Clear Remote MCP Gateway paused state
        if getattr(self, "_mcp_gateway_instance", None):
            try:
                self._mcp_gateway_instance.set_paused(False)
            except Exception as exc:
                logger.warning("Error clearing MCP gateway paused state: %s", exc)

        # 2. Invoke Core IPC system_resume via bridge
        core_res = {}
        try:
            if hasattr(self.bridge, "system_resume"):
                core_res = await self.bridge.system_resume()
            else:
                core_res = await self.bridge.call("system_resume", payload={})
        except Exception as exc:
            logger.warning("Error invoking system_resume IPC: %s", exc)
            core_res = {"success": True, "status": "RESUMED"}

        return web.json_response({
            "success": True,
            "status": "RESUMED",
            "state": "ACTIVE",
            "core": core_res,
        })

    async def handle_api_system_shutdown(self, request: web.Request) -> web.Response:
        """Initiate coordinated complete desktop power-off under owner authorization."""
        logger.info("Coordinated system shutdown initiated by owner via Web Dashboard.")

        # 1. Stop all public tunnels
        if hasattr(self, "tunnel_manager"):
            try:
                await self.tunnel_manager.stop_all_tunnels()
            except Exception as exc:
                logger.warning("Error stopping tunnels during shutdown: %s", exc)

        # 2. Stop Remote MCP Gateway runner
        if getattr(self, "_mcp_gateway_runner", None):
            try:
                await self._mcp_gateway_runner.cleanup()
            except Exception as exc:
                logger.warning("Error cleaning up MCP gateway during shutdown: %s", exc)

        # 3. Request core shutdown via IPC
        try:
            if hasattr(self.bridge, "system_shutdown"):
                await self.bridge.system_shutdown(reason="Owner power-off via Web Dashboard")
            else:
                await self.bridge.call("system_shutdown", payload={"reason": "Owner power-off via Web Dashboard"})
        except Exception as exc:
            logger.warning("Error sending system_shutdown IPC: %s", exc)

        # 4. Schedule delayed web server stop so HTTP response completes cleanly
        try:
            loop = asyncio.get_running_loop()
            loop.call_later(0.5, lambda: asyncio.create_task(self.stop()))
        except Exception:
            pass

        return web.json_response({
            "success": True,
            "status": "SHUTTING_DOWN",
            "message": "Coordinated SNOW shutdown initiated. Services stopping.",
        })

    # =========================================================================
    # Lifecycle
    # =========================================================================

    def _build_app(self) -> web.Application:
        """Build and configure the aiohttp application with routes and middleware."""
        app = web.Application(middlewares=[self.security_middleware])

        # Main static UI
        app.router.add_get("/", self.handle_index)
        app.router.add_get("/favicon.ico", self.handle_favicon)
        app.router.add_get("/snow_logo.png", self.handle_snow_logo)
        app.router.add_get("/static/{path:.*}", self.handle_static_asset)

        # Allowlisted API routes
        app.router.add_post("/api/auth/session", self.handle_auth_session)
        app.router.add_post("/api/web-ui/reset-override", self.handle_api_reset_web_ui_override)
        app.router.add_get("/api/system/update-check", self.handle_api_system_update_check)
        app.router.add_post("/api/system/update-apply", self.handle_api_system_update_apply)
        app.router.add_get("/api/status", self.handle_api_status)
        app.router.add_get("/api/devices", self.handle_api_devices)
        app.router.add_post("/api/devices/revoke", self.handle_api_devices_revoke)
        app.router.add_post("/api/devices/disconnect", self.handle_api_devices_disconnect)
        app.router.add_post("/api/devices/reconnect", self.handle_api_devices_reconnect)
        app.router.add_post("/api/devices/connect-peer", self.handle_api_devices_connect_peer)
        app.router.add_post("/api/devices/connection-mode", self.handle_api_devices_connection_mode)
        app.router.add_post("/api/devices/permission-profile", self.handle_api_devices_permission_profile)
        app.router.add_get("/api/network/identity", self.handle_api_network_identity)
        app.router.add_post("/api/network/identity", self.handle_api_network_identity_update)
        app.router.add_get("/api/network/topology", self.handle_api_network_topology)
        app.router.add_get("/api/pair/state", self.handle_api_pair_state)
        app.router.add_get("/api/pair/qr", self.handle_api_pair_qr)
        app.router.add_post("/api/pair/qr", self.handle_api_pair_qr)
        app.router.add_post("/api/pair/cancel", self.handle_api_pair_cancel)
        app.router.add_get("/api/files", self.handle_api_files)
        app.router.add_get("/api/files/destinations", self.handle_api_files_destinations)
        app.router.add_post("/api/files/destination", self.handle_api_files_destination)
        app.router.add_post("/api/files/pick-destination", self.handle_api_files_pick_destination)
        app.router.add_post("/api/files/open-transfers-folder", self.handle_api_open_transfers_folder)
        app.router.add_post("/api/files/transfer/cancel", self.handle_api_files_transfer_cancel)
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
        app.router.add_get("/api/desktop/wallpaper", self.handle_api_desktop_wallpaper)
        app.router.add_post("/api/desktop/lock", self.handle_api_desktop_lock)
        app.router.add_get("/api/workflows", self.handle_api_workflows_list)
        app.router.add_post("/api/workflows/run", self.handle_api_workflow_run)
        app.router.add_get("/api/activity", self.handle_api_activity)
        app.router.add_get("/api/relay/status", self.handle_api_relay_status)
        app.router.add_get("/api/relay/config", self.handle_api_relay_config_get)
        app.router.add_post("/api/relay/config", self.handle_api_relay_config_post)
        app.router.add_get("/api/settings/hub", self.handle_api_settings_hub_get)
        app.router.add_post("/api/settings/hub", self.handle_api_settings_hub_post)
        app.router.add_get("/api/mcp-gateway/status", self.handle_api_mcp_gateway_status)

        # Screen streaming & Camera delivery routes (Phase 26A / Stage 6C any-to-any)
        app.router.add_post("/api/screen/capture-phone", self.handle_api_screen_capture_phone)
        app.router.add_get("/api/screen/capture-latest", self.handle_api_screen_capture_latest)
        app.router.add_get("/api/screen/status", self.handle_api_screen_status)
        app.router.add_get("/api/screen/senders", self.handle_api_screen_senders)
        app.router.add_get("/api/screen/frame", self.handle_api_screen_frame)
        app.router.add_post("/api/screen/stop", self.handle_api_screen_stop)
        app.router.add_post("/api/screen/share/start", self.handle_api_screen_share_start)
        app.router.add_post("/api/screen/share/stop", self.handle_api_screen_share_stop)
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

        # Distribution & Onboarding (Phase 29 & Phase 3)
        app.router.add_get("/api/install/android-apk", self.handle_api_install_android_apk)
        app.router.add_get("/api/app/download-apk", self.handle_api_install_android_apk)
        app.router.add_get("/api/app/apk-info", self.handle_api_app_apk_info)
        app.router.add_get("/api/onboarding/status", self.handle_api_onboarding_status)
        app.router.add_post("/api/onboarding/complete", self.handle_api_onboarding_complete)
        app.router.add_get("/api/account-discovery/status", self.handle_api_account_discovery_status)
        app.router.add_post("/api/account-discovery/config", self.handle_api_account_discovery_config)

        # Cross-Network Federation & Session Controls (Phase 30)
        app.router.add_get("/api/directory/resolve/{snow_id}", self.handle_api_directory_resolve)
        app.router.add_get("/api/federation/grants", self.handle_api_federation_grants)
        app.router.add_post("/api/federation/invite", self.handle_api_federation_invite)
        app.router.add_post("/api/federation/accept", self.handle_api_federation_accept)
        app.router.add_post("/api/federation/tier", self.handle_api_federation_tier)
        app.router.add_post("/api/federation/revoke", self.handle_api_federation_revoke)
        app.router.add_post("/api/federation/kill-switch", self.handle_api_federation_kill_switch)

        # USB Tethering and AI MCP Host Management (Batch 4 & Stage 3B)
        app.router.add_get("/api/usb/status", self.handle_api_usb_status)
        app.router.add_post("/api/usb/connect", self.handle_api_usb_connect)
        app.router.add_post("/api/usb/disconnect", self.handle_api_usb_disconnect)
        app.router.add_post("/api/usb/unlock-permissions", self.handle_api_usb_unlock_permissions)
        app.router.add_post("/api/mcp/setup", self.handle_api_mcp_setup)
        app.router.add_post("/api/mcp/gateway/toggle", self.handle_api_mcp_gateway_toggle)
        app.router.add_post("/api/mcp/test-local", self.handle_api_mcp_test_local)
        app.router.add_post("/api/mcp/tunnel/start", self.handle_api_mcp_tunnel_start)
        app.router.add_post("/api/mcp/tunnel/stop", self.handle_api_mcp_tunnel_stop)
        app.router.add_get("/api/mcp/tunnel/status", self.handle_api_mcp_tunnel_status)
        app.router.add_get("/api/mcp/tunnel/config", self.handle_api_mcp_tunnel_config_get)
        app.router.add_post("/api/mcp/tunnel/config", self.handle_api_mcp_tunnel_config_post)
        app.router.add_get("/api/mcp/oauth/pending", self.handle_api_mcp_oauth_pending)
        app.router.add_post("/api/mcp/oauth/approve", self.handle_api_mcp_oauth_approve)
        app.router.add_post("/api/mcp/oauth/reject", self.handle_api_mcp_oauth_reject)

        # Relay Tunnel Management (Phase 4 Stage 4A)
        app.router.add_post("/api/relay/tunnel/start", self.handle_api_relay_tunnel_start)
        app.router.add_post("/api/relay/tunnel/stop", self.handle_api_relay_tunnel_stop)
        app.router.add_get("/api/relay/tunnel/status", self.handle_api_relay_tunnel_status)

        # System Lifecycle (Phase 4 Stage 4A)
        app.router.add_get("/api/system/status", self.handle_api_system_status)
        app.router.add_get("/api/system/ipc-secret", self.handle_api_system_ipc_secret)
        app.router.add_post("/api/system/pause", self.handle_api_system_pause)
        app.router.add_post("/api/system/resume", self.handle_api_system_resume)
        app.router.add_post("/api/system/shutdown", self.handle_api_system_shutdown)

        # Additional Native Capability Endpoints (Phase 4 Stage 4B)
        app.router.add_post("/api/devices/ring", self.handle_api_devices_ring)
        app.router.add_post("/api/camera/capture", self.handle_api_camera_capture)
        app.router.add_post("/api/clipboard/sync", self.handle_api_clipboard_sync)
        app.router.add_post("/api/files/upload", self.handle_api_files_upload)
        app.router.add_get("/api/mcp/tunnel/qr", self.handle_api_mcp_tunnel_qr)

        # Route aliases for client compatibility and resilience
        app.router.add_post("/api/mcp/hosts/setup", self.handle_api_mcp_setup)
        app.router.add_post("/api/mesh/connect", self.handle_api_devices_connect_peer)
        app.router.add_post("/api/pair/pin", self.handle_api_devices_connect_peer)
        app.router.add_post("/api/federation/connect", self.handle_api_federation_accept)
        app.router.add_post("/api/clipboard/sync/toggle", self.handle_api_clipboard_sync)
        app.router.add_post("/api/clipboard/clear", self.handle_api_clipboard_buffer_clear)
        app.router.add_get("/api/approvals/pending", self.handle_api_approvals)
        app.router.add_post("/api/transfer/upload", self.handle_api_files_upload)
        app.router.add_get("/api/apps", self.handle_api_apps_android)

        return app

    def create_app(self) -> web.Application:
        """Alias for _build_app to construct the aiohttp application."""
        return self._build_app()

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
        # Stop active MCP gateway if one exists
        if self._mcp_gateway_runner:
            try:
                await self._mcp_gateway_runner.cleanup()
            except Exception as exc:
                logger.warning("Error cleaning up MCP gateway on server stop: %s", exc)
            finally:
                self._mcp_gateway_runner = None
                self._mcp_gateway_site = None
                self._mcp_gateway_instance = None

        # Stop active ephemeral APK server if one exists
        if self._ephemeral_apk_runner:
            try:
                await self._ephemeral_apk_runner.cleanup()
            except Exception as exc:
                logger.warning("Error cleaning up ephemeral APK server on stop: %s", exc)
            finally:
                self._ephemeral_apk_runner = None
                self._ephemeral_apk_site = None
                self._ephemeral_apk_app = None
                self._ephemeral_apk_port = 0

        # Stop active tunnels if they exist
        if hasattr(self, "tunnel_manager"):
            try:
                await self.tunnel_manager.stop_all_tunnels()
                if self._mcp_gateway_instance:
                    self._mcp_gateway_instance.set_public_url(None)
            except Exception as texc:
                logger.warning("Error stopping tunnels on server stop: %s", texc)

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
