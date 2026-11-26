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
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from typing import Any, Optional
import uuid

from snow.core.config import resolve_default_hub_url, validate_hub_url

logger = logging.getLogger(__name__)

ALLOWED_TUNNEL_PORT: int = 8771
ALLOWED_RELAY_TUNNEL_PORT: int = 8770
ALLOWED_TUNNEL_PORTS: frozenset[int] = frozenset({ALLOWED_TUNNEL_PORT, ALLOWED_RELAY_TUNNEL_PORT})

CLOUDFLARED_URL_REGEX = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")
TAILSCALE_URL_REGEX = re.compile(r"https://[a-zA-Z0-9.-]+\.ts\.net(?::\d+)?")


def get_default_tunnel_config_path() -> Path:
    """Resolve the default configuration path for persistent tunnel settings (~/.snow/tunnel_config.json)."""
    env_dir = os.getenv("SNOW_DATA_DIR")
    target_dir = Path(env_dir.strip()) if env_dir and env_dir.strip() else (Path.home() / ".snow")
    return target_dir / "tunnel_config.json"


def load_tunnel_config(config_path: Optional[Path] = None) -> dict[str, Any]:
    """Load persistent tunnel configuration, returning empty dict if missing or unreadable."""
    path = config_path or get_default_tunnel_config_path()
    if path.is_file():
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
        except Exception as exc:
            logger.warning("Failed to load tunnel configuration from %s: %s", path, exc)
    return {}


def save_tunnel_config(config: dict[str, Any], config_path: Optional[Path] = None) -> None:
    """Safely persist tunnel configuration to disk using atomic temp file replacement."""
    path = config_path or get_default_tunnel_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.parent / f".{path.name}.tmp_{uuid.uuid4().hex[:8]}"
    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        temp_path.replace(path)
    except Exception as exc:
        logger.error("Failed to save tunnel configuration to %s: %s", path, exc)
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass
        raise


def redact_tunnel_config(config: dict[str, Any]) -> dict[str, Any]:
    """Recursively scrub tokens, secrets, and credentials before returning in status or logs."""
    redacted: dict[str, Any] = {}
    for k, v in config.items():
        k_lower = str(k).lower()
        if any(sec in k_lower for sec in ("token", "secret", "key", "password", "credential", "ticket")):
            if isinstance(v, str) and len(v) > 8:
                redacted[k] = f"{v[:4]}***{v[-2:]}"
            else:
                redacted[k] = "[REDACTED]"
        elif isinstance(v, dict):
            redacted[k] = redact_tunnel_config(v)
        else:
            redacted[k] = v
    return redacted


def is_remote_ai_link_enabled(
    config: Optional[dict[str, Any]] = None,
    config_path: Optional[Path] = None,
) -> bool:
    """Return True when Remote AI Link should auto-start (default True unless manually stopped)."""
    cfg = config if config is not None else load_tunnel_config(config_path=config_path)
    raw = cfg.get("remote_ai_link_enabled", True)
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        return raw.strip().lower() not in ("0", "false", "no", "off", "disabled")
    return bool(raw)


def set_remote_ai_link_enabled(
    enabled: bool,
    config_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Persist explicit Remote AI Link user preference without dropping other tunnel config."""
    cfg = load_tunnel_config(config_path=config_path)
    cfg["remote_ai_link_enabled"] = bool(enabled)
    save_tunnel_config(cfg, config_path=config_path)
    return cfg


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
        self._background_active: bool = False
        self._mcp_forwarder: Optional[Any] = None

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

        # 1b. Close active Render/relay reverse tunnel forwarder if running
        if self._mcp_forwarder is not None:
            try:
                await self._mcp_forwarder.stop()
            except Exception as exc:
                logger.warning("[%s tunnel] Error stopping reverse tunnel forwarder: %s", self.purpose, exc)
            self._mcp_forwarder = None

        # 1c. Disable background Tailscale Funnel if active
        if self._provider == "tailscale" and self._background_active:
            ts_bin = find_tailscale_binary()
            if ts_bin:
                creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                try:
                    stop_proc = await asyncio.create_subprocess_exec(
                        ts_bin,
                        "funnel",
                        f"--https=443",
                        "off",
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.DEVNULL,
                        stderr=asyncio.subprocess.DEVNULL,
                        creationflags=creation_flags,
                    )
                    await asyncio.wait_for(stop_proc.wait(), timeout=3.0)
                except Exception as exc:
                    logger.debug("[%s tunnel] Best-effort Tailscale funnel off returned: %s", self.purpose, exc)
            self._background_active = False

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
        token: Optional[str] = None,
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

            provider_lower = provider.strip().lower()
            existing_status = self.get_status()
            if (
                existing_status.get("active")
                and self._provider == provider_lower
                and not custom_url
            ):
                res: dict[str, Any] = {
                    "success": True,
                    "status": "ALREADY_RUNNING",
                    "purpose": self.purpose,
                    "provider": self._provider,
                    "public_url": self._public_url,
                }
                if existing_status.get("mcp_endpoint"):
                    res["mcp_endpoint"] = existing_status["mcp_endpoint"]
                return res

            # 2. Stop any existing tunnel on this instance safely without re-locking
            await self._stop_tunnel_unlocked()

            tunnel_cfg = load_tunnel_config()
            if self.purpose == "mcp":
                resolved_token = (
                    token
                    or tunnel_cfg.get("mcp_cloudflare_token")
                    or tunnel_cfg.get("cloudflare_token")
                    or tunnel_cfg.get("token")
                )
                cfg_url = (
                    tunnel_cfg.get("mcp_public_url")
                    or tunnel_cfg.get("public_url")
                    or tunnel_cfg.get("custom_url")
                )
            elif self.purpose == "relay":
                # For relay, support relay_cloudflare_token. Do not accidentally use MCP token for relay tunnel.
                resolved_token = token or tunnel_cfg.get("relay_cloudflare_token")
                cfg_url = tunnel_cfg.get("relay_public_url")
            else:
                resolved_token = token or tunnel_cfg.get("cloudflare_token") or tunnel_cfg.get("token")
                cfg_url = tunnel_cfg.get("public_url") or tunnel_cfg.get("custom_url")

            resolved_custom_url = custom_url or cfg_url

            # Case A: Custom URL provider
            if provider_lower == "custom":
                if not resolved_custom_url or not resolved_custom_url.startswith(("http://", "https://", "ws://", "wss://")):
                    return {
                        "success": False,
                        "status": "INVALID_URL",
                        "error": "A valid public URL is required for custom tunnel provider.",
                    }
                self._provider = "custom"
                self._public_url = resolved_custom_url.rstrip("/")
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

            # Case B: Cloudflared Tunnel (Named or Quick Tunnel)
            elif provider_lower == "cloudflared":
                cf_bin = find_cloudflared_binary()
                if not cf_bin:
                    return {
                        "success": False,
                        "status": "BINARY_NOT_FOUND",
                        "error": (
                            "cloudflared is optional and not installed yet. Install via "
                            "'winget install Cloudflare.cloudflared' (or https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/), "
                            "or switch Tunnel Provider to Tailscale Funnel / SNOW Render Relay."
                        ),
                    }

                creation_flags = 0
                if sys.platform == "win32":
                    creation_flags |= subprocess.CREATE_NO_WINDOW

                # Subcase B1: Named Tunnel with explicit or configured token
                if resolved_token:
                    # Validate public URL: require a valid https:// public URL
                    if not resolved_custom_url or not resolved_custom_url.strip().lower().startswith("https://"):
                        return {
                            "success": False,
                            "status": "INVALID_URL",
                            "error": f"A valid public https:// URL is required for named {self.purpose} tunnel.",
                        }
                    public_url = resolved_custom_url.strip().rstrip("/")
                    if ".snow.internal" in public_url.lower():
                        return {
                            "success": False,
                            "status": "INVALID_URL",
                            "error": "Fabricated internal domains (*.snow.internal) cannot be used as public tunnel URLs.",
                        }

                    cmd = [
                        cf_bin,
                        "tunnel",
                        "--no-autoupdate",
                        "run",
                        "--token",
                        str(resolved_token).strip(),
                    ]
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
                            "error": f"Failed launching cloudflared named tunnel for {self.purpose}: {exc}",
                        }

                    self._proc = proc
                    self._provider = "cloudflared"
                    self._started_at = time.time()

                    # Check for early failure
                    await asyncio.sleep(0.3)
                    if proc.returncode is not None:
                        err_out = ""
                        if proc.stderr:
                            try:
                                err_bytes = await asyncio.wait_for(proc.stderr.read(512), timeout=0.5)
                                err_out = err_bytes.decode("utf-8", errors="replace").strip()
                            except Exception:
                                pass
                        await self._stop_tunnel_unlocked()
                        return {
                            "success": False,
                            "status": "TUNNEL_EXITED",
                            "error": f"cloudflared named tunnel exited immediately (code={proc.returncode}): {err_out}",
                        }

                    self._public_url = public_url
                    url_future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
                    self._reader_task = asyncio.create_task(
                        self._drain_stderr(proc, "cloudflared", url_future)
                    )
                    logger.info("[%s tunnel] cloudflared named tunnel running: %s (pid=%s)", self.purpose, public_url, proc.pid)
                    res = {
                        "success": True,
                        "status": "STARTED",
                        "purpose": self.purpose,
                        "provider": "cloudflared",
                        "mode": "named",
                        "public_url": public_url,
                        "pid": proc.pid,
                    }
                    if self.purpose == "mcp":
                        res["mcp_endpoint"] = f"{public_url}/mcp"
                    elif self.purpose == "relay":
                        clean_host = public_url.replace("https://", "").replace("http://", "").rstrip("/")
                        res["relay_endpoint"] = f"wss://{clean_host}/v1/tunnel"
                    return res

                # Subcase B2: Quick Tunnel fallback
                target_scheme = "http"
                target_url = f"{target_scheme}://127.0.0.1:{target_port}"
                cmd = [
                    cf_bin,
                    "tunnel",
                    "--url",
                    target_url,
                    "--no-autoupdate",
                ]

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

                url_future = asyncio.get_running_loop().create_future()
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
                    "mode": "quick",
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

                creation_flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
                combined_output = ""
                cmd = [ts_bin, "funnel", "--bg", str(target_port)]

                try:
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        creationflags=creation_flags,
                    )
                    out_bytes, err_bytes = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                    out_str = out_bytes.decode("utf-8", errors="replace").strip()
                    err_str = err_bytes.decode("utf-8", errors="replace").strip()
                    combined_output = "\n".join(part for part in (out_str, err_str) if part)
                    if combined_output:
                        for line in combined_output.splitlines()[-10:]:
                            self._log_buffer.append(line)
                    if proc.returncode != 0:
                        return {
                            "success": False,
                            "status": "FUNNEL_UNAVAILABLE",
                            "error": (
                                f"Tailscale Funnel command failed (code={proc.returncode}): "
                                f"{combined_output or 'Ensure Tailscale is signed in and Funnel is enabled on your tailnet.'}"
                            ),
                        }
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    return {
                        "success": False,
                        "status": "FUNNEL_UNAVAILABLE",
                        "error": (
                            "Tailscale Funnel did not complete within timeout. "
                            "Ensure Tailscale is signed in and Funnel is enabled: https://tailscale.com/kb/1223/funnel"
                        ),
                    }
                except Exception as exc:
                    return {
                        "success": False,
                        "status": "SPAWN_FAILED",
                        "error": f"Failed launching tailscale funnel for {self.purpose}: {exc}",
                    }

                public_url: Optional[str] = None
                try:
                    status_proc = await asyncio.create_subprocess_exec(
                        ts_bin,
                        "status",
                        "--json",
                        stdin=asyncio.subprocess.DEVNULL,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        creationflags=creation_flags,
                    )
                    st_out, _ = await asyncio.wait_for(status_proc.communicate(), timeout=min(timeout, 6.0))
                    if status_proc.returncode == 0 and st_out:
                        st_json = json.loads(st_out.decode("utf-8", errors="replace"))
                        dns_name = str((st_json.get("Self") or {}).get("DNSName") or "").strip().rstrip(".")
                        if dns_name:
                            public_url = f"https://{dns_name}"
                except Exception as exc:
                    logger.debug("[%s tunnel] tailscale status --json lookup failed: %s", self.purpose, exc)

                if not public_url and combined_output:
                    match = TAILSCALE_URL_REGEX.search(combined_output)
                    if match:
                        public_url = match.group(0).rstrip("/")

                if not public_url:
                    return {
                        "success": False,
                        "status": "FUNNEL_UNAVAILABLE",
                        "error": (
                            "Tailscale Funnel enabled but MagicDNS *.ts.net hostname could not be determined "
                            "from 'tailscale status --json'. Enable MagicDNS & HTTPS in Tailscale admin."
                        ),
                    }

                self._provider = "tailscale"
                self._background_active = True
                self._public_url = public_url
                self._started_at = time.time()
                logger.info("[%s tunnel] Tailscale funnel established: %s -> :%d", self.purpose, public_url, target_port)
                res = {
                    "success": True,
                    "status": "STARTED",
                    "purpose": self.purpose,
                    "provider": "tailscale",
                    "mode": "background",
                    "public_url": public_url,
                }
                if self.purpose == "mcp":
                    res["mcp_endpoint"] = f"{public_url}/mcp"
                elif self.purpose == "relay":
                    clean_host = public_url.replace("https://", "").replace("http://", "").rstrip("/")
                    res["relay_endpoint"] = f"wss://{clean_host}/v1/tunnel"
                return res

            # Case D: SNOW Render Relay reverse tunnel (permanent /u/{network_id}/mcp URL)
            elif provider_lower == "render":
                if self.purpose != "mcp":
                    return {
                        "success": False,
                        "status": "UNSUPPORTED_PROVIDER",
                        "error": "Render reverse MCP tunnel is only supported on the MCP gateway port (8771).",
                    }
                hub_candidate = (
                    resolved_custom_url
                    or tunnel_cfg.get("default_hub_url")
                    or resolve_default_hub_url()
                    or ""
                ).strip()
                if not hub_candidate:
                    return {
                        "success": False,
                        "status": "INVALID_URL",
                        "error": "Configure Default Hub URL (SNOW_DEFAULT_HUB_URL) or enter your Render Relay HTTPS URL first.",
                    }
                try:
                    base_url = validate_hub_url(hub_candidate)
                except ValueError as url_exc:
                    return {
                        "success": False,
                        "status": "INVALID_URL",
                        "error": str(url_exc),
                    }
                from snow.security.identity import (
                    load_or_create_device_identity,
                    load_or_create_network_key_identity,
                )
                dev_ident = load_or_create_device_identity()
                snow_id = str(tunnel_cfg.get("snow_id") or dev_ident.snow_id).strip().upper()
                ticket = token or tunnel_cfg.get("relay_ticket") or ""
                ws_scheme = "wss://" if base_url.startswith("https://") else "ws://"
                clean_host = base_url.split("://", 1)[1]
                relay_ws_url = f"{ws_scheme}{clean_host}/v1/tunnel"
                from snow.relay.mcp_forwarder import RelayMcpForwarder

                if ticket:
                    forwarder = RelayMcpForwarder(
                        relay_ws_url=relay_ws_url,
                        snow_id=snow_id,
                        ticket=ticket,
                        local_gateway_url=f"http://127.0.0.1:{target_port}",
                        device_id=dev_ident.device_id,
                        device_name=dev_ident.device_name,
                    )
                    route_id = snow_id
                else:
                    net_ident = load_or_create_network_key_identity()
                    forwarder = RelayMcpForwarder(
                        relay_ws_url=relay_ws_url,
                        snow_id=snow_id,
                        local_gateway_url=f"http://127.0.0.1:{target_port}",
                        network_key_identity=net_ident,
                        hub_http_url=base_url,
                        device_id=dev_ident.device_id,
                        device_name=dev_ident.device_name,
                    )
                    route_id = net_ident.network_id

                ok, err = await forwarder.start(timeout=timeout)
                if not ok:
                    return {
                        "success": False,
                        "status": "RELAY_CONNECT_FAILED",
                        "error": err or "Failed connecting Render reverse MCP tunnel.",
                    }
                self._mcp_forwarder = forwarder
                self._provider = "render"
                self._background_active = True
                self._public_url = f"{base_url}/u/{route_id}"
                self._started_at = time.time()
                return {
                    "success": True,
                    "status": "STARTED",
                    "purpose": self.purpose,
                    "provider": "render",
                    "snow_id": snow_id,
                    "network_id": getattr(forwarder, "network_id", "") or route_id,
                    "public_url": self._public_url,
                    "mcp_endpoint": f"{self._public_url}/mcp",
                }

            else:
                return {
                    "success": False,
                    "status": "UNSUPPORTED_PROVIDER",
                    "error": f"Unsupported tunnel provider '{provider}'. Supported: cloudflared, tailscale, render, custom.",
                }

    def get_status(self) -> dict[str, Any]:
        """Query current tunnel state, active provider, and public endpoints for this instance."""
        is_active = False
        pid = None
        if self._provider == "custom" and self._public_url:
            is_active = True
        elif self._provider == "tailscale" and self._background_active and self._public_url:
            is_active = True
        elif self._provider == "render" and self._mcp_forwarder is not None and getattr(self._mcp_forwarder, "is_connected", False) and self._public_url:
            is_active = True
        elif self._proc:
            if self._proc.returncode is None:
                is_active = True
                pid = self._proc.pid
            else:
                self._proc = None
                self._provider = None
                self._public_url = None
                self._background_active = False

        if self.purpose == "mcp" and self._public_url:
            clean_pub = self._public_url.rstrip("/")
            mcp_ep = clean_pub if clean_pub.endswith("/mcp") else f"{clean_pub}/mcp"
        else:
            mcp_ep = None

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
        token: Optional[str] = None,
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

        return await self._mcp_tunnel.start(provider=provider, port=port, custom_url=custom_url, timeout=timeout, token=token)

    async def start_relay_tunnel(
        self,
        provider: str = "cloudflared",
        port: int = ALLOWED_RELAY_TUNNEL_PORT,
        custom_url: Optional[str] = None,
        timeout: float = 12.0,
        token: Optional[str] = None,
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

        return await self._relay_tunnel.start(provider=provider, port=port, custom_url=custom_url, timeout=timeout, token=token)

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
        """Query current status of both isolated tunnel instances and persistent config."""
        return {
            "mcp": self._mcp_tunnel.get_status(),
            "relay": self._relay_tunnel.get_status(),
            "available_providers": self.get_available_providers(),
            "config": redact_tunnel_config(load_tunnel_config()),
        }
