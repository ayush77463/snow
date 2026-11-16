"""Authenticated loopback IPC bridge connecting the SNOW MCP server to SNOW Core.

The MCP server runs as a separate subprocess and communicates with the already-running
headless SNOW Core daemon through this bridge.

SECURITY INVARIANTS:
1. Local Loopback Only: Connects exclusively to 127.0.0.1.
2. Secret Authentication: Automatically loads and presents ~/.snow/ipc.secret.
3. Fail-Safe Error Handling: Converts transport dropouts and offline core states into
   structured errors (e.g. CORE_OFFLINE) rather than raw unhandled tracebacks.
4. No Duplicate Services: Never starts secondary WSS or HTTP servers.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional
import uuid

from snow.core.ipc import (
    DEFAULT_IPC_SECRET_FILENAME,
    IPC_PROTOCOL_VERSION,
    MAX_IPC_MESSAGE_SIZE,
    get_default_secret_path,
)

logger = logging.getLogger(__name__)


class SnowMcpBridge:
    """IPC client bridge allowing MCP tool handlers to query and command SNOW Desktop Core."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8767,
        secret: Optional[str] = None,
        secret_path: Optional[Path | str] = None,
    ) -> None:
        self.host = host
        self.port = port
        self._explicit_secret = secret
        self.secret_path = Path(secret_path) if secret_path else get_default_secret_path()

    def _get_secret(self) -> Optional[str]:
        """Resolve the IPC authentication secret."""
        if self._explicit_secret:
            return self._explicit_secret

        env_secret = os.environ.get("SNOW_IPC_SECRET")
        if env_secret and env_secret.strip():
            return env_secret.strip()

        if self.secret_path.is_file():
            try:
                secret_text = self.secret_path.read_text(encoding="utf-8").strip()
                if secret_text:
                    return secret_text
            except Exception as exc:
                logger.warning("Could not read IPC secret from %s: %s", self.secret_path, exc)

        return None

    async def call(
        self, op: str, payload: Optional[dict[str, Any]] = None, timeout: float = 10.0
    ) -> dict[str, Any]:
        """Dispatch a single authenticated request to the SNOW Core IPC server.

        Opens an ephemeral TCP connection, transmits the request, receives the correlated
        response, and cleanly closes the connection. Returns structured errors on failure.
        """
        secret = self._get_secret()
        if not secret:
            return {
                "success": False,
                "status": "CORE_OFFLINE",
                "error": (
                    f"IPC secret not found at {self.secret_path}. "
                    "Ensure SNOW Desktop Core is running."
                ),
            }

        request_id = str(uuid.uuid4())
        request_obj = {
            "version": IPC_PROTOCOL_VERSION,
            "request_id": request_id,
            "op": op,
            "auth_token": secret,
            "payload": payload or {},
        }

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=min(timeout, 5.0),
            )
        except (ConnectionRefusedError, OSError) as conn_err:
            return {
                "success": False,
                "status": "CORE_OFFLINE",
                "error": f"SNOW Desktop Core is offline or unreachable at {self.host}:{self.port} ({conn_err}).",
            }
        except asyncio.TimeoutError:
            return {
                "success": False,
                "status": "CORE_OFFLINE",
                "error": f"Connection to SNOW Desktop Core at {self.host}:{self.port} timed out.",
            }

        try:
            # Transmit serialized frame
            frame = json.dumps(request_obj, separators=(",", ":")).encode("utf-8") + b"\n"
            writer.write(frame)
            await writer.drain()

            # Await response frame
            raw_response = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not raw_response:
                return {
                    "success": False,
                    "status": "CONNECTION_RESET",
                    "error": "SNOW Desktop Core closed IPC connection without replying.",
                }

            if len(raw_response) > MAX_IPC_MESSAGE_SIZE:
                return {
                    "success": False,
                    "status": "MESSAGE_TOO_LARGE",
                    "error": f"IPC response exceeded maximum frame size ({MAX_IPC_MESSAGE_SIZE} bytes).",
                }

            response_obj = json.loads(raw_response.decode("utf-8").strip())
            if not isinstance(response_obj, dict):
                return {
                    "success": False,
                    "status": "INVALID_RESPONSE",
                    "error": "Received malformed non-object IPC response.",
                }

            return response_obj

        except asyncio.TimeoutError:
            return {
                "success": False,
                "status": "REQUEST_TIMEOUT",
                "error": f"IPC operation '{op}' timed out waiting for response after {timeout:.1f}s.",
            }
        except Exception as exc:
            return {
                "success": False,
                "status": "INTERNAL_ERROR",
                "error": f"IPC error communicating with core: {exc}",
            }
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def get_device_status(self) -> dict[str, Any]:
        """Query live core server and connected device overview."""
        return await self.call("get_device_status", timeout=5.0)

    async def list_devices(self) -> dict[str, Any]:
        """Query all known paired devices and their connection states."""
        return await self.call("list_devices", timeout=5.0)

    async def send_device_request(
        self,
        device_id: str,
        action: str,
        data: Optional[dict[str, Any]] = None,
        timeout: float = 30.0,
    ) -> dict[str, Any]:
        """Route a request action to a connected, authenticated Android device."""
        payload = {
            "device_id": device_id,
            "action": action,
            "data": data,
            "timeout": timeout,
        }
        return await self.call("device_request", payload=payload, timeout=timeout + 5.0)

    async def ping(self) -> dict[str, Any]:
        """Test IPC transport reachability."""
        return await self.call("ping", timeout=3.0)
