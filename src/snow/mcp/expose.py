"""Zero-port-forwarding public exposure tool for SNOW Remote MCP Gateway.

Securely exposes the local Remote MCP Streamable HTTP Gateway (default 127.0.0.1:8771)
over public HTTPS tunnels using Cloudflare Quick Tunnels (cloudflared) or Tailscale Funnel.
Enforces OAuth 2.1, PKCE S256, and AI_MCP execution principal boundaries.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import time
from typing import Optional
import urllib.request

from snow.core.subprocess_util import get_no_window_subprocess_kwargs

logger = logging.getLogger(__name__)

DEFAULT_GATEWAY_PORT: int = 8771
CLOUDFLARE_URL_PATTERN = re.compile(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com")


class ExposeManager:
    """Manages secure zero-port-forwarding public tunnel exposure and gateway lifecycle."""

    def __init__(
        self,
        port: int = DEFAULT_GATEWAY_PORT,
        provider: str = "cloudflared",
        public_url: Optional[str] = None,
        external_gateway: bool = False,
        trusted_proxies: Optional[str] = None,
    ) -> None:
        self.port = port
        self.provider = provider.lower().strip()
        self.public_url = public_url.rstrip("/") if public_url else None
        self.external_gateway = external_gateway
        self.trusted_proxies = trusted_proxies
        self._tunnel_process: Optional[subprocess.Popen] = None
        self._gateway_process: Optional[subprocess.Popen] = None

    def check_gateway_health(self, timeout: float = 2.0) -> bool:
        """Check if the local SNOW Remote MCP Gateway is running and healthy."""
        url = f"http://127.0.0.1:{self.port}/health"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SNOW-Expose/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if resp.status == 200:
                    data = resp.read().decode("utf-8")
                    return "healthy" in data
        except Exception:
            return False
        return False

    @staticmethod
    def detect_provider(provider: str) -> tuple[bool, Optional[str], str]:
        """Verify binary availability and return setup instructions if missing."""
        prov = provider.lower().strip()
        if prov == "cloudflared":
            binary = shutil.which("cloudflared")
            if binary:
                return True, binary, ""
            instructions = (
                "Cloudflare Tunnel client (cloudflared) was not found in PATH.\n"
                "To install cloudflared:\n"
                "  - Windows (winget):  winget install --id Cloudflare.cloudflared\n"
                "  - Windows (scoop):   scoop install cloudflared\n"
                "  - macOS (Homebrew):  brew install cloudflared\n"
                "  - Direct download:   https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
            )
            return False, None, instructions

        elif prov == "tailscale":
            binary = shutil.which("tailscale")
            if binary:
                return True, binary, ""
            instructions = (
                "Tailscale CLI was not found in PATH.\n"
                "To install Tailscale with Funnel support:\n"
                "  - Windows / macOS / Linux: https://tailscale.com/download\n"
                "  - Enable Funnel in admin console: https://login.tailscale.com/admin/features/funnel"
            )
            return False, None, instructions

        else:
            return False, None, f"Unsupported tunnel provider: '{provider}'. Supported: cloudflared, tailscale."

    def start_tunnel(self) -> int:
        """Synchronous entry point for starting tunnel and managing gateway lifecycle."""
        # 1. Gateway preflight checks
        if self.external_gateway:
            if not self.check_gateway_health():
                print(
                    f"[!] Error: External Remote MCP Gateway is not running or healthy on port {self.port}.\n"
                    f"    Please start the gateway first:\n"
                    f"      snow mcp-gateway --port {self.port} --public-url <tunnel-url> --trusted-proxies 127.0.0.1,::1\n"
                    f"    Or run without --external-gateway to let 'snow expose' manage the gateway automatically.",
                    file=sys.stderr,
                )
                return 1
            print(f"[*] External gateway mode: Connecting to existing gateway on 127.0.0.1:{self.port}...", file=sys.stderr)
        else:
            if self.check_gateway_health():
                print(
                    f"[!] Warning: An existing gateway is already responding on 127.0.0.1:{self.port}.\n"
                    f"    In managed mode, 'snow expose' requires port {self.port} to be free to launch a dedicated gateway\n"
                    f"    configured with the detected public tunnel URL.\n"
                    f"    Use '--external-gateway' to expose your existing gateway, or select an unused port via '--port <port>'.",
                    file=sys.stderr,
                )
                return 1

        # 2. Check tunnel provider binary
        available, binary_path, instructions = self.detect_provider(self.provider)
        if not available or not binary_path:
            print(f"[!] Error: {instructions}", file=sys.stderr)
            return 1

        print(f"[*] Starting {self.provider} tunnel pointing to 127.0.0.1:{self.port}...", file=sys.stderr)
        detected_public_url = self.public_url

        try:
            # 3. Launch tunnel provider subprocess
            if self.provider == "cloudflared":
                cmd = [binary_path, "tunnel", "--url", f"http://127.0.0.1:{self.port}"]
                self._tunnel_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    **get_no_window_subprocess_kwargs(),
                )

                assert self._tunnel_process.stdout is not None
                start_time = time.time()
                while not detected_public_url and (time.time() - start_time < 30.0):
                    line = self._tunnel_process.stdout.readline()
                    if not line and self._tunnel_process.poll() is not None:
                        break
                    match = CLOUDFLARE_URL_PATTERN.search(line)
                    if match:
                        detected_public_url = match.group(0)
                        break

            elif self.provider == "tailscale":
                cmd = [binary_path, "funnel", f"{self.port}"]
                self._tunnel_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    **get_no_window_subprocess_kwargs(),
                )

                assert self._tunnel_process.stdout is not None
                start_time = time.time()
                while not detected_public_url and (time.time() - start_time < 15.0):
                    line = self._tunnel_process.stdout.readline()
                    if not line and self._tunnel_process.poll() is not None:
                        break
                    if "https://" in line:
                        for word in line.split():
                            if word.startswith("https://"):
                                detected_public_url = word.strip().rstrip("/")
                                break

            if not detected_public_url:
                print(
                    f"[!] Failed detecting public HTTPS URL from {self.provider} within timeout.",
                    file=sys.stderr,
                )
                self.stop()
                return 1

            # 4. In default managed mode, spawn the managed RemoteMcpGateway subprocess with detected public URL
            if not self.external_gateway:
                print(f"[*] Spawning managed RemoteMcpGateway with public URL: {detected_public_url}...", file=sys.stderr)
                if getattr(sys, "frozen", False):
                    exe_path = Path(sys.executable).resolve()
                    sibling_snow = exe_path.with_name("snow.exe")
                    core_exe = str(sibling_snow) if sibling_snow.is_file() else str(exe_path)
                    gw_cmd = [
                        core_exe,
                        "mcp-gateway",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(self.port),
                        "--public-url",
                        detected_public_url,
                        "--trusted-proxies",
                        self.trusted_proxies or "127.0.0.1,::1",
                    ]
                else:
                    gw_cmd = [
                        sys.executable,
                        "-m",
                        "snow.mcp.remote_gateway",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        str(self.port),
                        "--public-url",
                        detected_public_url,
                        "--trusted-proxies",
                        self.trusted_proxies or "127.0.0.1,::1",
                    ]
                self._gateway_process = subprocess.Popen(
                    gw_cmd,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                    **get_no_window_subprocess_kwargs(),
                )

                # Wait for managed gateway to be healthy
                gw_ready = False
                start_gw = time.time()
                while time.time() - start_gw < 10.0:
                    if self._gateway_process.poll() is not None:
                        err = self._gateway_process.stderr.read() if self._gateway_process.stderr else ""
                        print(f"[!] Managed RemoteMcpGateway exited prematurely: {err}", file=sys.stderr)
                        self.stop()
                        return 1
                    if self.check_gateway_health(timeout=1.0):
                        gw_ready = True
                        break
                    time.sleep(0.3)

                if not gw_ready:
                    print(f"[!] Managed gateway failed healthcheck on 127.0.0.1:{self.port} within 10s.", file=sys.stderr)
                    self.stop()
                    return 1

            # 5. Display banner
            self._print_connection_banner(detected_public_url)

            # 6. Monitor both processes
            while True:
                if self._tunnel_process and self._tunnel_process.poll() is not None:
                    print("[!] Tunnel process exited unexpectedly.", file=sys.stderr)
                    break
                if not self.external_gateway and self._gateway_process and self._gateway_process.poll() is not None:
                    print("[!] Managed RemoteMcpGateway exited unexpectedly.", file=sys.stderr)
                    break
                time.sleep(1.0)

            self.stop()
            return 0

        except KeyboardInterrupt:
            print("\n[*] Shutting down public tunnel and managed services cleanly...", file=sys.stderr)
            self.stop()
            print("[+] Public tunnel and services closed.", file=sys.stderr)
            return 0
        except Exception as exc:
            print(f"[!] Tunnel execution failed: {exc}", file=sys.stderr)
            self.stop()
            return 1

    def _print_connection_banner(self, public_origin: str) -> None:
        """Display clear, formatted copyable endpoints and setup guidance."""
        clean_origin = public_origin.rstrip("/")
        mcp_endpoint = f"{clean_origin}/mcp"
        resource_meta = f"{clean_origin}/.well-known/oauth-protected-resource"
        auth_meta = f"{clean_origin}/.well-known/oauth-authorization-server"

        mode_desc = "External Gateway" if self.external_gateway else "Managed RemoteMcpGateway"

        banner = f"""
================================================================================
SNOW Remote MCP Gateway — Public Zero-Port-Forwarding Exposure
================================================================================
  Provider:            {self.provider} ({mode_desc})
  Local Gateway:       http://127.0.0.1:{self.port}/mcp
  Public HTTPS Origin: {clean_origin}
  Public MCP Endpoint: {mcp_endpoint}
  OAuth Resource:      {resource_meta}
  OAuth Auth Server:   {auth_meta}
  Security Principal:  ExecutionPrincipal.AI_MCP (Strict least-privilege)
  Human Approval:      ApprovalPolicyEngine enforced on all sensitive capabilities
================================================================================

[AI Assistant Configuration Guide]

Claude (Desktop / Web / Custom Connector):
  1. Add Remote MCP Endpoint:
     URL: {mcp_endpoint}
  2. Protocol: Streamable HTTP (OAuth 2.1 + PKCE S256)

ChatGPT (Custom Connector / Developer Mode):
  1. Add MCP Server URL:
     {mcp_endpoint}
  2. Authorization: OAuth 2.1 Code Flow with PKCE

Gemini Antigravity / Custom MCP:
  1. Connect to URL:
     {mcp_endpoint}

================================================================================
Tunnel active. Press Ctrl+C to terminate public exposure.
================================================================================
"""
        print(banner)

    def stop(self) -> None:
        """Terminate active gateway and tunnel processes cleanly."""
        if self._gateway_process and self._gateway_process.poll() is None:
            try:
                self._gateway_process.terminate()
                self._gateway_process.wait(timeout=3.0)
            except Exception:
                try:
                    self._gateway_process.kill()
                except Exception:
                    pass
            self._gateway_process = None

        if self._tunnel_process and self._tunnel_process.poll() is None:
            try:
                self._tunnel_process.terminate()
                self._tunnel_process.wait(timeout=3.0)
            except Exception:
                try:
                    self._tunnel_process.kill()
                except Exception:
                    pass
            self._tunnel_process = None


def run_expose(
    provider: str = "cloudflared",
    port: int = DEFAULT_GATEWAY_PORT,
    public_url: Optional[str] = None,
    external_gateway: bool = False,
    trusted_proxies: Optional[str] = None,
) -> int:
    """CLI handler for 'snow expose'."""
    manager = ExposeManager(
        port=port,
        provider=provider,
        public_url=public_url,
        external_gateway=external_gateway,
        trusted_proxies=trusted_proxies,
    )
    return manager.start_tunnel()
