"""Tunnel and Remote Expose Manager for SNOW Remote MCP Gateway.

Provides lifecycle management for public tunnel providers (Cloudflared, Tailscale, Custom)
to expose the authenticated Remote MCP Streamable HTTP Gateway (port 8771) without exposing
the loopback Web Dashboard (port 8769) or Desktop Core IPC (port 8767).

Security Guarantees:
1. Port Restriction: ONLY the Remote MCP Gateway (port 8771) may be tunneled.
   Tunneling of Web Dashboard (:8769) or Core IPC (:8767) is strictly forbidden.
2. Isolated Process Lifecycle: Tracks spawned tunnel subprocesses by PID; guarantees
   clean termination without orphaned background daemons or pipe buffer deadlocks.
3. Provider Discovery: Detects available binaries in system PATH and standard directories.
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
CLOUDFLARED_URL_REGEX = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
TAILSCALE_URL_REGEX = re.compile(r"https://[a-zA-Z0-9.-]+\.ts\.net(?::\d+)?")


def find_cloudflared_binary() -> Optional[str]:
    """Locate cloudflared executable in PATH or standard system directories."""
    # 1. System PATH
    found = shutil.which("cloudflared.exe") or shutil.which("cloudflared")
    if found:
        return found

    # 2. Windows standard install locations
    candidates = [
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "cloudflared" / "cloudflared.exe",
        Path(os.environ.get("LOCALAPPDATA", r"C:\Users\AppData\Local")) / "cloudflared" / "cloudflared.exe",
        Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "chocolatey" / "bin" / "cloudflared.exe",
        Path.home() / "scoop" / "shims" / "cloudflared.exe",
    ]
    for c in candidates:
        if c.is_file():
            return str(c)
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


class TunnelManager:
    """Manages public tunnel lifecycles for the SNOW Remote MCP Gateway."""

    def __init__(self, target_port: int = ALLOWED_TUNNEL_PORT) -> None:
        self.target_port = target_port
        self._proc: Optional[asyncio.subprocess.Process] = None
        self._reader_task: Optional[asyncio.Task[None]] = None
        self._provider: Optional[str] = None
        self._public_url: Optional[str] = None
        self._started_at: float = 0.0
        self._log_buffer: deque[str] = deque(maxlen=50)
        self._lock = asyncio.Lock()

    def get_available_providers(self) -> list[str]:
        """Detect which tunnel provider binaries are currently installed and usable."""
        providers = ["custom"]
        if find_cloudflared_binary():
            providers.append("cloudflared")
        if find_tailscale_binary():
            providers.append("tailscale")
        return providers

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
            logger.debug("Tunnel reader encountered error: %s", exc)
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
                logger.warning("Error stopping tunnel subprocess %s: %s", pid, exc)
            finally:
                self._proc = None

        self._provider = None
        self._public_url = None
        self._started_at = 0.0
        self._log_buffer.clear()

        if pid:
            logger.info("Stopped tunnel subprocess [pid=%d]", pid)
            return {"success": True, "status": "STOPPED", "message": f"Tunnel process {pid} stopped."}
        return {"success": True, "status": "STOPPED", "message": "No active tunnel process."}

    async def stop_tunnel(self) -> dict[str, Any]:
        """Safely terminate any active tunnel subprocess under synchronization."""
        async with self._lock:
            return await self._stop_tunnel_unlocked()

    async def start_tunnel(
        self,
        provider: str = "cloudflared",
        port: int = ALLOWED_TUNNEL_PORT,
        custom_url: Optional[str] = None,
        timeout: float = 12.0,
    ) -> dict[str, Any]:
        """Start a public tunnel exposing the Remote MCP Gateway under lock synchronization."""
        async with self._lock:
            # 1. Enforce strict port boundary
            if port != ALLOWED_TUNNEL_PORT:
                err = (
                    f"Security Error: Public tunnels may only expose the authenticated Remote MCP "
                    f"Gateway (port {ALLOWED_TUNNEL_PORT}). Port {port} is strictly restricted."
                )
                logger.error(err)
                return {"success": False, "status": "PORT_RESTRICTED", "error": err}

            # 2. Stop any existing tunnel safely without re-locking
            await self._stop_tunnel_unlocked()

            provider_lower = provider.strip().lower()

            # Case A: Custom URL provider
            if provider_lower == "custom":
                if not custom_url or not custom_url.startswith(("http://", "https://")):
                    return {
                        "success": False,
                        "status": "INVALID_URL",
                        "error": "A valid http:// or https:// public URL is required for custom tunnel provider.",
                    }
                self._provider = "custom"
                self._public_url = custom_url.rstrip("/")
                self._started_at = time.time()
                logger.info("Configured custom Remote MCP public URL: %s", self._public_url)
                return {
                    "success": True,
                    "status": "STARTED",
                    "provider": "custom",
                    "public_url": self._public_url,
                    "mcp_endpoint": f"{self._public_url}/mcp",
                }

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

                cmd = [
                    cf_bin,
                    "tunnel",
                    "--url",
                    f"http://127.0.0.1:{port}",
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
                        "error": f"Failed launching cloudflared: {exc}",
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
                logger.info("cloudflared tunnel established: %s -> :%d", public_url, port)
                return {
                    "success": True,
                    "status": "STARTED",
                    "provider": "cloudflared",
                    "public_url": public_url,
                    "mcp_endpoint": f"{public_url}/mcp",
                    "pid": proc.pid,
                }

            # Case C: Tailscale Funnel
            elif provider_lower == "tailscale":
                ts_bin = find_tailscale_binary()
                if not ts_bin:
                    return {
                        "success": False,
                        "status": "BINARY_NOT_FOUND",
                        "error": "tailscale binary was not found on your system. Install Tailscale: https://tailscale.com",
                    }

                cmd = [ts_bin, "funnel", str(port)]
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
                        "error": f"Failed launching tailscale funnel: {exc}",
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
                logger.info("Tailscale funnel established: %s -> :%d", public_url, port)
                return {
                    "success": True,
                    "status": "STARTED",
                    "provider": "tailscale",
                    "public_url": public_url,
                    "mcp_endpoint": f"{public_url}/mcp",
                    "pid": proc.pid,
                }

            else:
                return {
                    "success": False,
                    "status": "UNSUPPORTED_PROVIDER",
                    "error": f"Unsupported tunnel provider '{provider}'. Supported: cloudflared, tailscale, custom.",
                }

    def get_status(self) -> dict[str, Any]:
        """Query current tunnel state, active provider, and public endpoints."""
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

        mcp_ep = f"{self._public_url.rstrip('/')}/mcp" if self._public_url else None

        return {
            "active": is_active,
            "provider": self._provider if is_active else None,
            "public_url": self._public_url if is_active else None,
            "mcp_endpoint": mcp_ep if is_active else None,
            "target_port": self.target_port,
            "pid": pid,
            "available_providers": self.get_available_providers(),
        }
