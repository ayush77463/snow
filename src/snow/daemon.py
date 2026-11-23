"""Core daemon lifecycle manager for SNOW.

Coordinates background Core daemon startup, status inspection, and shutdown.
GUARANTEES:
1. Concurrency Safety: Uses an asyncio.Lock to serialize auto-spawn attempts
   and prevent duplicate background daemon processes.
2. Headless Detachment: On Windows, uses CREATE_NO_WINDOW (0x08000000) so no console
   window appears.
3. Strict Output Redirection: Daemon stdout and stderr are redirected to dedicated
   log files (~/.snow/logs/core.log), strictly isolated from MCP stdio.
4. Process Identity Verification: Verifies process command-line before sending
   termination signals to prevent killing recycled or unrelated PIDs.
5. Non-Blocking Async Polling: Uses bounded asynchronous sleep loops (max 5s)
   without blocking the MCP event loop.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any, Dict, Optional

import psutil

logger = logging.getLogger(__name__)

CREATE_NO_WINDOW: int = 0x08000000
DETACHED_PROCESS: int = 0x00000008
DEFAULT_SPAWN_TIMEOUT_SECONDS: float = 5.0
POLL_INTERVAL_SECONDS: float = 0.15


def get_snow_dir() -> Path:
    """Return the canonical SNOW configuration and state directory."""
    data_dir = os.environ.get("SNOW_DATA_DIR")
    if data_dir:
        return Path(data_dir).resolve()
    return (Path.home() / ".snow").resolve()


def get_pid_file_path() -> Path:
    """Return the path to the Core daemon PID tracking file."""
    return get_snow_dir() / "snow_core.pid"


def get_daemon_log_path() -> Path:
    """Return the path to the background daemon log file."""
    log_dir = get_snow_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "core.log"


class CoreDaemonManager:
    """Manages the background execution, health checks, and lifecycle of SNOW Core."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8767,
        spawn_timeout: float = DEFAULT_SPAWN_TIMEOUT_SECONDS,
    ) -> None:
        self.host = host
        self.port = port
        self.spawn_timeout = spawn_timeout
        self._spawn_lock = asyncio.Lock()

    async def is_ipc_ready(self, timeout: float = 0.5) -> bool:
        """Check whether the Core IPC TCP endpoint is actively accepting connections."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=timeout,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    def get_tracked_pid(self) -> Optional[int]:
        """Read the currently recorded daemon PID from disk, if present."""
        pid_file = get_pid_file_path()
        if not pid_file.is_file():
            return None
        try:
            content = pid_file.read_text(encoding="utf-8").strip()
            if content.isdigit():
                return int(content)
        except Exception as exc:
            logger.debug("Failed reading PID file: %s", exc)
        return None

    def _write_pid(self, pid: int) -> None:
        """Record the active daemon PID."""
        try:
            get_snow_dir().mkdir(parents=True, exist_ok=True)
            get_pid_file_path().write_text(str(pid), encoding="utf-8")
        except Exception as exc:
            logger.warning("Failed writing PID file: %s", exc)

    def _clear_pid(self) -> None:
        """Remove the PID tracking file."""
        try:
            pid_file = get_pid_file_path()
            if pid_file.exists():
                pid_file.unlink()
        except Exception as exc:
            logger.debug("Failed removing PID file: %s", exc)

    def is_process_snow_core(self, pid: int) -> bool:
        """Verify whether a given PID is alive and belongs to SNOW Core."""
        try:
            proc = psutil.Process(pid)
            if not proc.is_running():
                return False
            name = proc.name().lower()
            if name in ("snow.exe", "snow"):
                return True
            cmdline = " ".join(proc.cmdline()).lower()
            return "snow.main" in cmdline or "snow.core.server" in cmdline or "-m snow" in cmdline or "snow.exe" in cmdline
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return False
        except Exception as exc:
            logger.debug("Error checking process %d: %s", pid, exc)
            return False

    def _get_core_command(self) -> list[str]:
        """Resolve the executable command for SNOW Desktop Core."""
        if getattr(sys, "frozen", False):
            # Running as a frozen executable (e.g. snow-tray.exe or snow.exe)
            exe_path = Path(sys.executable).resolve()
            sibling_core = exe_path.with_name("snow.exe")
            if sibling_core.is_file():
                return [str(sibling_core)]
            return [str(exe_path)]
        return [sys.executable, "-m", "snow.main"]

    async def ensure_core_running(self) -> dict[str, Any]:
        """Ensure SNOW Core daemon is running and accepting IPC connections.

        If already running, returns immediately. If offline, launches a detached
        background process and awaits IPC readiness up to spawn_timeout.
        """
        # Fast path without lock
        if await self.is_ipc_ready():
            return {
                "success": True,
                "status": "ALREADY_RUNNING",
                "message": "SNOW Desktop Core is running and accepting IPC connections.",
                "pid": self.get_tracked_pid(),
            }

        # Serialized startup path
        async with self._spawn_lock:
            # Re-check under lock in case another coroutine started it
            if await self.is_ipc_ready():
                return {
                    "success": True,
                    "status": "ALREADY_RUNNING",
                    "message": "SNOW Desktop Core is running and accepting IPC connections.",
                    "pid": self.get_tracked_pid(),
                }

            logger.info("Starting background SNOW Desktop Core daemon...")
            log_path = get_daemon_log_path()

            creation_flags = 0
            if sys.platform == "win32":
                creation_flags |= CREATE_NO_WINDOW | DETACHED_PROCESS

            log_file = None
            try:
                # Open dedicated log file for daemon output
                log_file = open(log_path, "a", encoding="utf-8")
                cmd = self._get_core_command()
                proc = subprocess.Popen(
                    cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    stdin=subprocess.DEVNULL,
                    creationflags=creation_flags,
                    close_fds=True,
                )
                self._write_pid(proc.pid)
                logger.info("Spawned Core daemon [pid=%d], waiting for IPC readiness...", proc.pid)
            except Exception as exc:
                logger.error("Failed spawning Core daemon process: %s", exc)
                return {
                    "success": False,
                    "status": "SPAWN_FAILED",
                    "error": f"Failed to spawn background SNOW Core process: {exc}",
                }
            finally:
                if log_file and not log_file.closed:
                    try:
                        log_file.close()
                    except Exception:
                        pass

            # Bounded asynchronous polling
            deadline = time.monotonic() + self.spawn_timeout
            while time.monotonic() < deadline:
                if await self.is_ipc_ready():
                    logger.info("Core daemon is online and IPC is ready [pid=%d].", proc.pid)
                    return {
                        "success": True,
                        "status": "STARTED",
                        "message": f"Successfully started SNOW Desktop Core (PID {proc.pid}).",
                        "pid": proc.pid,
                    }

                # Check if process crashed immediately
                if proc.poll() is not None:
                    self._clear_pid()
                    return {
                        "success": False,
                        "status": "CRASHED_ON_STARTUP",
                        "error": (
                            f"SNOW Core process terminated prematurely with exit code {proc.returncode}. "
                            f"Check logs at {log_path}."
                        ),
                        "exit_code": proc.returncode,
                    }

                await asyncio.sleep(POLL_INTERVAL_SECONDS)

            # Timed out waiting for IPC readiness
            return {
                "success": False,
                "status": "STARTUP_TIMEOUT",
                "error": (
                    f"SNOW Core process (PID {proc.pid}) did not become ready within "
                    f"{self.spawn_timeout:.1f}s. Check logs at {log_path}."
                ),
                "pid": proc.pid,
            }

    async def stop_core(self, timeout: float = 5.0) -> dict[str, Any]:
        """Gracefully stop the background SNOW Core daemon."""
        pid = self.get_tracked_pid()
        is_ready = await self.is_ipc_ready()

        if not is_ready and not (pid and self.is_process_snow_core(pid)):
            self._clear_pid()
            return {
                "success": True,
                "status": "ALREADY_STOPPED",
                "message": "SNOW Core daemon is not running.",
            }

        target_proc = None
        if pid and self.is_process_snow_core(pid):
            try:
                target_proc = psutil.Process(pid)
            except Exception:
                pass

        # Attempt graceful termination
        if target_proc:
            try:
                target_proc.terminate()
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    if not target_proc.is_running():
                        break
                    await asyncio.sleep(0.1)

                if target_proc.is_running():
                    target_proc.kill()
                    await asyncio.sleep(0.1)
            except Exception as exc:
                logger.warning("Error stopping daemon process %d: %s", pid, exc)

        self._clear_pid()
        is_still_ready = await self.is_ipc_ready(timeout=0.3)
        if not is_still_ready:
            return {
                "success": True,
                "status": "STOPPED",
                "message": f"Successfully stopped SNOW Core daemon (PID {pid}).",
            }
        else:
            return {
                "success": False,
                "status": "STOP_FAILED",
                "error": "SNOW Core IPC endpoint is still responding after termination attempt.",
            }

    async def get_status(self) -> dict[str, Any]:
        """Inspect the current daemon and IPC status."""
        pid = self.get_tracked_pid()
        ipc_online = await self.is_ipc_ready(timeout=0.5)
        proc_running = bool(pid and self.is_process_snow_core(pid))

        return {
            "daemon_running": proc_running or ipc_online,
            "ipc_ready": ipc_online,
            "pid": pid if proc_running else None,
            "host": self.host,
            "port": self.port,
            "log_path": str(get_daemon_log_path()),
        }
