"""Tunnel and Remote Expose Manager for SNOW Remote MCP Gateway and Device Relay.

Provides lifecycle management for public tunnel providers (Cloudflared, Tailscale, Custom)
to expose:
1. The authenticated Remote MCP Streamable HTTP Gateway (port 8771).
2. The authenticated Remote Device Relay listener (port 8770).

Security Guarantees:
1. Port Restriction: ONLY port 8771 (MCP Gateway) and port 8770 (Device Relay) may be tunneled.
   Tunneling of Web Dashboard (:8769) or Core IPC (:8767) is strictly forbidden.
2. Isolated Process Lifecycle: Tracks spawned tunnel subprocesses by PID; guarantees
   clean termination without orphaned background daemons or pipe buffer deadlocks.
3. Provider Discovery: Detects available binaries preferring bundled packages, system PATH,
   and standard Windows install locations.
"""

from __future__ import annotations

import asyncio
from collections import deque
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

ALLOWED_TUNNEL_PORT: int = 8771
ALLOWED_RELAY_TUNNEL_PORT: int = 8770
ALLOWED_TUNNEL_PORTS: frozenset[int] = frozenset({ALLOWED_TUNNEL_PORT, ALLOWED_RELAY_TUNNEL_PORT})

CLOUDFLARED_URL_REGEX = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
TAILSCALE_URL_REGEX = re.compile(r"https://[a-zA-Z0-9.-]+\.ts\.net(?::\d+)?")


def find_cloudflared_binary() -> Optional[str]:
    """Locate cloudflared executable preferring bundled binaries before searching system PATH.

    Lookup Precedence:
    1. PyInstaller bundled temporary extraction root (_MEIPASS/bin/cloudflared.exe, _MEIPASS/cloudflared.exe)
    2. Frozen/installed application binary directory (Path(sys.executable).parent/bin/cloudflared.exe)
    3. Frozen/installed root directory (Path(sys.executable).parent/cloudflared.exe)
    4. Development packaging directory (packaging/bin/cloudflared.exe)
    5. Standard Windows installation locations (Program Files, LocalAppData, Chocolatey, Scoop)
    6. System PATH as final fallback
    """
    candidates: list[Path] = []

    # 1. PyInstaller bundled extraction directory (one-file mode)
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "bin" / "cloudflared.exe")
        candidates.append(Path(meipass) / "cloudflared.exe")

    # 2 & 3. Executable parent directory (one-dir installation)
    exe_dir = Path(sys.executable).parent
    candidates.append(exe_dir / "bin" / "cloudflared.exe")
    candidates.append(exe_dir / "cloudflared.exe")

    # 4. Development repository path
    try:
        repo_root = Path(__file__).resolve().parents[3]
        candidates.append(repo_root / "packaging" / "bin" / "cloudflared.exe")
        candidates.append(repo_root / "bin" / "cloudflared.exe")
    except Exception:
        pass

    for c in candidates:
        if c.is_file():
            return str(c)

    # 5. Windows standard install locations
    win_candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "cloudflared" / "cloudflared.exe",
        Path(os.environ.get("LOCALAPPDATA", r"C:\Users\AppData\Local")) / "cloudflared" / "cloudflared.exe",
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "chocolatey" / "bin" / "cloudflared.exe",
        Path.home() / "scoop" / "shims" / "cloudflared.exe",
    ]
    for c in win_candidates:
        if c.is_file():
            return str(c)

    # 6. System PATH as final fallback
    found = shutil.which("cloudflared.exe") or shutil.which("cloudflared")
    if found:
        return found

    return None


def find_tailscale_binary() -> Optional[str]:
    """Locate tailscale executable in PATH or standard system directories."""
    found = shutil.which("tailscale.exe") or shutil.which("tailscale")
    if found:
        return found

    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Tailscale" / "tailscale.exe",
        Path(os.environ.get("LOCALAPPDATA", r"C:\Users\AppData\Local")) / "Tailscale" / "tailscale.exe",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
    return None


class _TunnelInstance:
    """Manages an isolated public tunnel process lifecycle for a specific target port."""

    def __init__(self, target_port: int, purpose: str = "mcp") -> None:
        self.target_port = target_port
        self.purpose = purpose
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._reader_task: Optional[asyncio.Task[None]] = None
        self._provider: Optional[str] = None
        self._public_url: Optional[str] = None
        self._started_at: float = 0.0
        self._log_buffer: deque[str] = deque(maxlen=50)
        self._lock = asyncio.Lock()

    async def _drain_stderr(
        self,
        proc: asyncio.subprocess.Process,
        provider: str,
        url_future: asyncio.Future[str],
    ) -> None:
        """Continuously drain stderr, match public URL, and retain bounded output lines."""
        pattern = CLOUDFLARED_URL_REGEX if provider == "cloudflared" else TAILSCALE_URL_REGEX
        try:
            while proc.stderr and not proc.stderr.at_eof():
                line_bytes = await proc.stderr.readline()
                if not line_bytes:
                    break
                line = line_bytes.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                self._log_buffer.append(line)
                if not url_future.done():
                    m = pattern.search(line)
                    if m:
                        url_future.set_result(m.group(0))
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.debug("[%s tunnel] Reader encountered error: %s", self.purpose, exc)
        finally:
            if not url_future.done():
                url_future.cancel()

    async def _stop_tunnel_unlocked(self) -> dict[str, Any]:
        """Internal teardown helper called while self._lock is already held."""
        # 1. Cancel and await background reader task
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
        self._reader_task = None

        # 2. Terminate subprocess if active
        pid = None
        if self._proc:
            proc = self._proc
            pid = proc.pid
            try:
                if proc.returncode is None:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=2.5)
                    except (asyncio.TimeoutError, Exception):
                        proc.kill()
                        try:
                            await asyncio.wait_for(proc.wait(), timeout=1.0)
                        except Exception:
                            pass
            except Exception as exc:
                logger.warning("[%s tunnel] Error stopping tunnel subprocess %s: %s", self.purpose, pid, exc)
            finally:
                self._proc = None

        self._provider = None
        self._public_url = None
        self._started_at = 0.0
        self._log_buffer.clear()

        if pid:
            logger.info("[%s tunnel] Stopped tunnel subprocess [pid=%d]", self.purpose, pid)
            return {"success": True, "status": "STOPPED", "message": f"{self.purpose.upper()} tunnel process {pid} stopped."}
        return {"success": True, "status": "STOPPED", "message": f"No active {self.purpose} tunnel process."}

    async def stop(self) -> dict[str, Any]:
        """Safely terminate any active tunnel subprocess under synchronization."""
        async with self._lock:
            return await self._stop_tunnel_unlocked()

    async def start(
        self,
        provider: str = "cloudflared",
        port: Optional[int] = None,
        custom_url: Optional[str] = None,
        timeout: float = 12.0,
    ) -> dict[str, Any]:
        """Start a public tunnel exposing this instance's verified port."""
        target_port = port if port is not None else self.target_port
        async with self._lock:
            # 1. Enforce strict port boundary
            if target_port not in ALLOWED_TUNNEL_PORTS:
                err = (
                    f"Security Error: Public tunnels may only expose Remote MCP Gateway ({ALLOWED_TUNNEL_PORT}) "
                    f"or Remote Device Relay ({ALLOWED_RELAY_TUNNEL_PORT}). Port {target_port} is strictly restricted."
                )
                logger.error(err)
                return {"success": False, "status": "PORT_RESTRICTED", "error": err}

            # Enforce dedicated port per instance purpose
            if self.purpose == "mcp" and target_port != ALLOWED_TUNNEL_PORT:
                err = f"Security Error: MCP tunnel instance cannot target port {target_port}."
                logger.error(err)
                return {"success": False, "status": "PORT_RESTRICTED", "error": err}
            elif self.purpose == "relay" and target_port != ALLOWED_RELAY_TUNNEL_PORT:
                err = f"Security Error: Relay tunnel instance cannot target port {target_port}."
                logger.error(err)
                return {"success": False, "status": "PORT_RESTRICTED", "error": err}

            # 2. Stop any existing tunnel on this instance safely without re-locking
            await self._stop_tunnel_unlocked()

            provider_lower = provider.strip().lower()

            # Case A: Custom URL provider
            if provider_lower == "custom":
                if not custom_url or not custom_url.startswith(("http://", "https://", "ws://", "wss://")):
                    return {
                        "success": False,
                        "status": "INVALID_URL",
                        "error": "A valid public URL is required for custom tunnel provider.",
                    }
                self._provider = "custom"
                self._public_url = custom_url.rstrip("/")
                self._started_at = time.time()
                logger.info("Configured custom [%s] public URL: %s", self.purpose, self._public_url)
                res: dict[str, Any] = {
                    "success": True,
                    "status": "STARTED",
                    "purpose": self.purpose,
                    "provider": "custom",
                    "public_url": self._public_url,
                }
                if self.purpose == "mcp":
                    res["mcp_endpoint"] = f"{self._public_url}/mcp"
                return res

            # Case B: Cloudflared Tunnel
            elif provider_lower == "cloudflared":
                cf_bin = find_cloudflared_binary()
                if not cf_bin:
                    return {
                        "success": False,
                        "status": "BINARY_NOT_FOUND",
                        "error": (
                            "cloudflared binary was not found on your system. "
                            "Download it from: https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
                        ),
                    }

                # Construct tunnel command (both MCP Gateway and Relay listeners use HTTP/WebSocket)
                target_scheme = "http"
                target_url = f"{target_scheme}://127.0.0.1:{target_port}"
                cmd = [
                    cf_bin,
                    "tunnel",
                    "--url",
                    target_url,
                    "--no-autoupdate",
                ]

                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags |= subprocess.CREATE_NO_WINDOW

                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.PIPE,
                        creationflags=creation_flags,
                    )
                except Exception as exc:
                    return {
                        "success": False,
                        "status": "SPAWN_FAILED",
                        "error": f"Failed launching cloudflared for {self.purpose}: {exc}",
                    }

                self._proc = proc
                self._provider = "cloudflared"
                self._started_at = time.time()

                url_future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
                self._reader_task = asyncio.create_task(
                    self._drain_stderr(proc, "cloudflared", url_future)
                )

                try:
                    public_url = await asyncio.wait_for(url_future, timeout=timeout)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    await self._stop_tunnel_unlocked()
                    return {
                        "success": False,
                        "status": "TUNNEL_URL_TIMEOUT",
                        "error": f"cloudflared started but did not produce a trycloudflare.com URL within {timeout}s.",
                    }

                self._public_url = public_url
                logger.info("[%s tunnel] cloudflared established: %s -> :%d", self.purpose, public_url, target_port)
                res = {
                    "success": True,
                    "status": "STARTED",
                    "purpose": self.purpose,
                    "provider": "cloudflared",
                    "public_url": public_url,
                    "pid": proc.pid,
                }
                if self.purpose == "mcp":
                    res["mcp_endpoint"] = f"{public_url}/mcp"
                elif self.purpose == "relay":
                    clean_host = public_url.replace("https://", "").replace("http://", "").rstrip("/")
                    res["relay_endpoint"] = f"wss://{clean_host}/v1/tunnel"
                return res

            # Case C: Tailscale Funnel
            elif provider_lower == "tailscale":
                ts_bin = find_tailscale_binary()
                if not ts_bin:
                    return {
                        "success": False,
                        "status": "BINARY_NOT_FOUND",
                        "error": "tailscale binary was not found on your system. Install Tailscale: https://tailscale.com",
                    }

                cmd = [ts_bin, "funnel", str(target_port)]
                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags |= subprocess.CREATE_NO_WINDOW

                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.PIPE,
                        creationflags=creation_flags,
                    )
                except Exception as exc:
                    return {
                        "success": False,
                        "status": "SPAWN_FAILED",
                        "error": f"Failed launching tailscale funnel for {self.purpose}: {exc}",
                    }

                self._proc = proc
                self._provider = "tailscale"
                self._started_at = time.time()

                url_future = asyncio.get_running_loop().create_future()
                self._reader_task = asyncio.create_task(
                    self._drain_stderr(proc, "tailscale", url_future)
                )

                try:
                    public_url = await asyncio.wait_for(url_future, timeout=timeout)
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    await self._stop_tunnel_unlocked()
                    return {
                        "success": False,
                        "status": "FUNNEL_UNAVAILABLE",
                        "error": (
                            "Tailscale Funnel failed to produce a valid *.ts.net HTTPS URL within timeout. "
                            "Ensure Funnel is enabled on your tailnet: https://tailscale.com/kb/1223/funnel"
                        ),
                    }

                self._public_url = public_url
                logger.info("[%s tunnel] Tailscale funnel established: %s -> :%d", self.purpose, public_url, target_port)
                res = {
                    "success": True,
                    "status": "STARTED",
                    "purpose": self.purpose,
                    "provider": "tailscale",
                    "public_url": public_url,
                    "pid": proc.pid,
                }
                if self.purpose == "mcp":
                    res["mcp_endpoint"] = f"{public_url}/mcp"
                elif self.purpose == "relay":
                    clean_host = public_url.replace("https://", "").replace("http://", "").rstrip("/")
                    res["relay_endpoint"] = f"wss://{clean_host}/v1/tunnel"
                return res

            else:
                return {
                    "success": False,
                    "status": "UNSUPPORTED_PROVIDER",
                    "error": f"Unsupported tunnel provider '{provider}'. Supported: cloudflared, tailscale, custom.",
                }

    def get_status(self) -> dict[str, Any]:
        """Query current tunnel state, active provider, and public endpoints for this instance."""
        is_active = False
        pid = None
        if self._provider == "custom" and self._public_url:
            is_active = True
        elif self._proc:
            if self._proc.returncode is None:
                is_active = True
                pid = self._proc.pid
            else:
                self._proc = None
                self._provider = None
                self._public_url = None

        mcp_ep = f"{self._public_url.rstrip('/')}/mcp" if (self.purpose == "mcp" and self._public_url) else None

        return {
            "active": is_active,
            "purpose": self.purpose,
            "provider": self._provider if is_active else None,
            "public_url": self._public_url if is_active else None,
            "mcp_endpoint": mcp_ep,
            "target_port": self.target_port,
            "pid": pid,
        }


class TunnelManager:
    """Coordinates isolated public tunnel lifecycles for both Remote MCP Gateway and Device Relay."""

    def __init__(self, target_port: int = ALLOWED_TUNNEL_PORT) -> None:
        self.target_port = target_port
        self._mcp_tunnel = _TunnelInstance(target_port=ALLOWED_TUNNEL_PORT, purpose="mcp")
        self._relay_tunnel = _TunnelInstance(target_port=ALLOWED_RELAY_TUNNEL_PORT, purpose="relay")

    @property
    def mcp_tunnel(self) -> _TunnelInstance:
        """Isolated tunnel instance for Remote AI MCP Gateway."""
        return self._mcp_tunnel

    @property
    def relay_tunnel(self) -> _TunnelInstance:
        """Isolated tunnel instance for Remote Device Relay."""
        return self._relay_tunnel

    @property
    def _lock(self) -> asyncio.Lock:
        """Backward compatibility access to the primary MCP tunnel instance lock."""
        return self._mcp_tunnel._lock

    def get_available_providers(self) -> list[str]:
        """Detect which tunnel provider binaries are currently installed and usable."""
        providers = ["custom"]
        if find_cloudflared_binary():
            providers.append("cloudflared")
        if find_tailscale_binary():
            providers.append("tailscale")
        return providers

    async def start_tunnel(
        self,
        provider: str = "cloudflared",
        port: int = ALLOWED_TUNNEL_PORT,
        custom_url: Optional[str] = None,
        timeout: float = 12.0,
    ) -> dict[str, Any]:
        """Start a public tunnel exposing Remote MCP Gateway (port 8771).

        Security Boundary: Strictly restricts exposure to Remote MCP Gateway (8771).
        Attempts to expose port 8770 (Relay), 8769 (Dashboard), or 8767 (Core IPC) are rejected.
        """
        if port != ALLOWED_TUNNEL_PORT:
            err = (
                f"Security Error: Remote MCP Gateway tunnel may only expose port {ALLOWED_TUNNEL_PORT}. "
                f"Port {port} is strictly restricted."
            )
            logger.error(err)
            return {"success": False, "status": "PORT_RESTRICTED", "error": err}

        return await self._mcp_tunnel.start(provider=provider, port=port, custom_url=custom_url, timeout=timeout)

    async def start_relay_tunnel(
        self,
        provider: str = "cloudflared",
        port: int = ALLOWED_RELAY_TUNNEL_PORT,
        custom_url: Optional[str] = None,
        timeout: float = 12.0,
    ) -> dict[str, Any]:
        """Start a public tunnel exposing Remote Device Relay (port 8770).

        Security Boundary: Strictly restricts exposure to Remote Device Relay (8770).
        Attempts to expose port 8771 (MCP), 8769 (Dashboard), or 8767 (Core IPC) are rejected.
        """
        if port != ALLOWED_RELAY_TUNNEL_PORT:
            err = (
                f"Security Error: Remote Device Relay tunnel may only expose port {ALLOWED_RELAY_TUNNEL_PORT}. "
                f"Port {port} is strictly restricted."
            )
            logger.error(err)
            return {"success": False, "status": "PORT_RESTRICTED", "error": err}

        return await self._relay_tunnel.start(provider=provider, port=port, custom_url=custom_url, timeout=timeout)

    async def stop_tunnel(self, port: Optional[int] = None) -> dict[str, Any]:
        """Safely terminate an active tunnel subprocess by port (defaults to MCP gateway port)."""
        target = port or self.target_port
        if target == ALLOWED_TUNNEL_PORT:
            return await self._mcp_tunnel.stop()
        elif target == ALLOWED_RELAY_TUNNEL_PORT:
            return await self._relay_tunnel.stop()
        else:
            return {"success": False, "status": "PORT_RESTRICTED", "error": f"Invalid port {target}"}

    async def stop_all_tunnels(self) -> dict[str, Any]:
        """Cleanly terminate both MCP and Relay tunnel instances."""
        res_mcp = await self._mcp_tunnel.stop()
        res_relay = await self._relay_tunnel.stop()
        return {
            "success": True,
            "status": "ALL_STOPPED",
            "mcp": res_mcp,
            "relay": res_relay,
        }

    def get_status(self, port: int = ALLOWED_TUNNEL_PORT) -> dict[str, Any]:
        """Query tunnel state for a specific port (defaults to Remote MCP Gateway)."""
        if port == ALLOWED_RELAY_TUNNEL_PORT:
            status = self._relay_tunnel.get_status()
        else:
            status = self._mcp_tunnel.get_status()
        status["available_providers"] = self.get_available_providers()
        return status

    def get_relay_tunnel_status(self) -> dict[str, Any]:
        """Convenience query for the Remote Device Relay tunnel state."""
        return self.get_status(port=ALLOWED_RELAY_TUNNEL_PORT)

    def get_mcp_tunnel_status(self) -> dict[str, Any]:
        """Convenience query for the Remote MCP Gateway tunnel state."""
        return self.get_status(port=ALLOWED_TUNNEL_PORT)

    def get_all_status(self) -> dict[str, Any]:
        """Query current status of both isolated tunnel instances."""
        return {
            "mcp": self._mcp_tunnel.get_status(),
            "relay": self._relay_tunnel.get_status(),
            "available_providers": self.get_available_providers(),
        }
