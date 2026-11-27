"""Core daemon lifecycle manager for SNOW.

Coordinates background Core daemon startup, status inspection, and shutdown.
GUARANTEES:
1. Cross-Process Serialization: Uses an OS-backed file lock paired with an
   in-process asyncio.Lock to prevent duplicate Core daemon spawns across
   concurrent processes (CLI, Web, Tray, MCP).
2. Headless Detachment: On Windows, uses CREATE_NO_WINDOW | DETACHED_PROCESS |
   CREATE_NEW_PROCESS_GROUP so no console window appears and console signals
   cannot kill the background daemon.
3. Strict Output Redirection: Daemon stdout and stderr are redirected to dedicated
   log files (~/.snow/logs/core.log), strictly isolated from MCP stdio.
4. Ownership Verification: Uses structured atomic PID metadata (pid, create_time,
   exe, port) plus authenticated SNOW IPC readiness probing to detect PID reuse
   and foreign port occupants.
5. Ownership-Safe Cleanup: Only the process matching PID and create_time can be
   stopped or have its PID metadata removed.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from typing import Any, AsyncIterator, Dict, Optional
import uuid

import psutil

if sys.platform == "win32":
    import msvcrt
else:
    import fcntl

logger = logging.getLogger(__name__)

CREATE_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
DETACHED_PROCESS: int = getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
CREATE_NEW_PROCESS_GROUP: int = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
DEFAULT_SPAWN_TIMEOUT_SECONDS: float = 5.0
DEFAULT_LOCK_TIMEOUT_SECONDS: float = 10.0
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


def get_lock_file_path() -> Path:
    """Return the path to the Core daemon cross-process startup lock file."""
    return get_snow_dir() / "snow_core.lock"


def get_daemon_log_path() -> Path:
    """Return the path to the background daemon log file."""
    log_dir = get_snow_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir / "core.log"


def _normalize_exe_path(path_str: Optional[str]) -> Optional[str]:
    if not path_str or not isinstance(path_str, str):
        return None
    clean = path_str.strip()
    if not clean:
        return None
    try:
        resolved = str(Path(clean).resolve())
    except OSError:
        resolved = os.path.abspath(clean)
    return os.path.normcase(resolved)


def _read_file_text_raw(path: Path) -> Optional[str]:
    """Read UTF-8 text using low-level OS file descriptors (immune to mocked builtins.open)."""
    if not path.is_file():
        return None
    fd = os.open(str(path), os.O_RDONLY)
    try:
        chunks: list[bytes] = []
        while True:
            buf = os.read(fd, 8192)
            if not buf:
                break
            chunks.append(buf)
        return b"".join(chunks).decode("utf-8")
    finally:
        os.close(fd)


def _atomic_write_text_raw(path: Path, text: str) -> None:
    """Atomically write UTF-8 text via temp file + fsync + os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.parent / f".tmp_{path.name}_{uuid.uuid4().hex}"
    data = text.encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(tmp_path), flags, 0o600)
    try:
        view = memoryview(data)
        total = 0
        while total < len(data):
            written = os.write(fd, view[total:])
            if written <= 0:
                raise OSError("Short write while writing Core PID metadata.")
            total += written
        try:
            os.fsync(fd)
        except OSError:
            pass
    except Exception:
        os.close(fd)
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise
    else:
        os.close(fd)
    try:
        os.replace(tmp_path, path)
    except Exception:
        try:
            if tmp_path.exists():
                tmp_path.unlink()
        except OSError:
            pass
        raise


def _try_lock_fd(fd: int) -> None:
    """Acquire non-blocking OS lock on byte 0 of open file descriptor."""
    if sys.platform == "win32":
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock_fd(fd: int) -> None:
    """Release OS lock on byte 0 of open file descriptor."""
    if sys.platform == "win32":
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


class CoreDaemonManager:
    """Manages the background execution, health checks, and lifecycle of SNOW Core."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8767,
        spawn_timeout: float = DEFAULT_SPAWN_TIMEOUT_SECONDS,
        lock_timeout: float = DEFAULT_LOCK_TIMEOUT_SECONDS,
        secret: Optional[str] = None,
        secret_path: Optional[Path | str] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.spawn_timeout = spawn_timeout
        self.lock_timeout = lock_timeout
        self._explicit_secret = secret
        self.secret_path = Path(secret_path) if secret_path else None
        self._spawn_lock = asyncio.Lock()
        self._last_pid_error: Optional[str] = None
        self._last_ipc_error: Optional[str] = None

    @asynccontextmanager
    async def _acquire_cross_process_lock(
        self, timeout: Optional[float] = None
    ) -> AsyncIterator[None]:
        """Serialize Core startup decisions across processes using a kernel file lock."""
        effective_timeout = max(0.2, float(timeout if timeout is not None else self.lock_timeout))
        lock_path = get_lock_file_path()
        lock_path.parent.mkdir(parents=True, exist_ok=True)

        fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        locked = False
        try:
            # Ensure byte 0 exists for Win32 LockFile semantics.
            if os.fstat(fd).st_size == 0:
                try:
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.write(fd, b"0")
                except OSError:
                    pass

            deadline = time.monotonic() + effective_timeout
            while True:
                try:
                    _try_lock_fd(fd)
                    locked = True
                    break
                except (OSError, BlockingIOError) as exc:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(
                            f"Timed out after {effective_timeout:.1f}s acquiring Core startup lock "
                            f"at '{lock_path}': {exc}"
                        ) from exc
                    await asyncio.sleep(0.05)

            yield
        finally:
            if locked:
                try:
                    _unlock_fd(fd)
                except OSError as exc:
                    logger.debug("Error releasing Core startup lock '%s': %s", lock_path, exc)
            try:
                os.close(fd)
            except OSError as exc:
                logger.debug("Error closing Core startup lock descriptor '%s': %s", lock_path, exc)

    def _get_ipc_secret(self) -> Optional[str]:
        """Resolve local Core IPC shared secret without mutating or generating one."""
        if self._explicit_secret and str(self._explicit_secret).strip():
            return str(self._explicit_secret).strip()

        env_secret = os.environ.get("SNOW_IPC_SECRET")
        if env_secret and env_secret.strip():
            return env_secret.strip()

        from snow.core.ipc import get_default_secret_path

        secret_path = self.secret_path or get_default_secret_path()
        try:
            raw = _read_file_text_raw(secret_path)
            if raw and raw.strip():
                return raw.strip()
        except Exception as exc:
            logger.debug("Could not read IPC secret from %s: %s", secret_path, exc)
        return None

    async def probe_ipc_identity(self, timeout: float = 0.5) -> tuple[bool, str]:
        """Verify that the IPC endpoint is an authenticated SNOW Core via IPC ping."""
        from snow.core.ipc import IPC_PROTOCOL_VERSION, MAX_IPC_MESSAGE_SIZE

        secret = self._get_ipc_secret()
        if not secret:
            self._last_ipc_error = "IPC_SECRET_MISSING"
            return False, "IPC_SECRET_MISSING"

        deadline = time.monotonic() + max(0.05, float(timeout))
        writer: Optional[asyncio.StreamWriter] = None
        try:
            rem = max(0.05, deadline - time.monotonic())
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=rem,
            )

            req_id = str(uuid.uuid4())
            frame = (
                json.dumps(
                    {
                        "version": IPC_PROTOCOL_VERSION,
                        "request_id": req_id,
                        "op": "ping",
                        "auth_token": secret,
                        "payload": {},
                    },
                    separators=(",", ":"),
                ).encode("utf-8")
                + b"\n"
            )
            writer.write(frame)
            await writer.drain()

            rem = max(0.05, deadline - time.monotonic())
            raw_line = await asyncio.wait_for(reader.readline(), timeout=rem)
            if not raw_line:
                self._last_ipc_error = "IPC_EMPTY_RESPONSE"
                return False, "IPC_EMPTY_RESPONSE"
            if len(raw_line) > MAX_IPC_MESSAGE_SIZE:
                self._last_ipc_error = "IPC_OVERSIZED_RESPONSE"
                return False, "IPC_OVERSIZED_RESPONSE"

            resp = json.loads(raw_line.decode("utf-8").strip())
            if not isinstance(resp, dict):
                self._last_ipc_error = "IPC_INVALID_RESPONSE"
                return False, "IPC_INVALID_RESPONSE"
            if resp.get("version") != IPC_PROTOCOL_VERSION:
                self._last_ipc_error = "IPC_PROTOCOL_MISMATCH"
                return False, "IPC_PROTOCOL_MISMATCH"
            if resp.get("request_id") != req_id:
                self._last_ipc_error = "IPC_CORRELATION_MISMATCH"
                return False, "IPC_CORRELATION_MISMATCH"
            if resp.get("status") == "UNAUTHORIZED":
                self._last_ipc_error = "IPC_UNAUTHORIZED"
                return False, "IPC_UNAUTHORIZED"
            data = resp.get("data")
            if (
                resp.get("success") is True
                and resp.get("status") == "SUCCESS"
                and isinstance(data, dict)
                and data.get("status") == "pong"
            ):
                self._last_ipc_error = None
                return True, "IPC_READY"

            self._last_ipc_error = "IPC_UNEXPECTED_REPLY"
            return False, "IPC_UNEXPECTED_REPLY"
        except asyncio.TimeoutError:
            self._last_ipc_error = "IPC_TIMEOUT"
            return False, "IPC_TIMEOUT"
        except (ConnectionRefusedError, OSError):
            self._last_ipc_error = "IPC_OFFLINE"
            return False, "IPC_OFFLINE"
        except (ValueError, UnicodeDecodeError):
            self._last_ipc_error = "IPC_MALFORMED_JSON"
            return False, "IPC_MALFORMED_JSON"
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    async def is_ipc_ready(self, timeout: float = 0.5) -> bool:
        """Check whether an authenticated SNOW Core IPC server is responsive."""
        ok, _ = await self.probe_ipc_identity(timeout=timeout)
        return ok

    async def _is_port_occupied(self, timeout: float = 0.25) -> bool:
        """Check whether anything is accepting TCP connections or bound on (host, port)."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port),
                timeout=timeout,
            )
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except (ConnectionRefusedError, asyncio.TimeoutError):
            pass
        except OSError:
            pass

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((self.host, self.port))
            return False
        except OSError:
            return True
        finally:
            try:
                sock.close()
            except OSError:
                pass

    @staticmethod
    def _validate_structured_pid_payload(obj: Any) -> Optional[dict[str, Any]]:
        if not isinstance(obj, dict):
            return None
        pid = obj.get("pid")
        create_time = obj.get("create_time")
        exe = obj.get("exe")
        port = obj.get("port")

        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return None
        if (
            not isinstance(create_time, (int, float))
            or isinstance(create_time, bool)
            or not math.isfinite(float(create_time))
            or float(create_time) <= 0
        ):
            return None
        if not isinstance(exe, str) or not exe.strip():
            return None
        if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
            return None

        return {
            "pid": pid,
            "create_time": float(create_time),
            "exe": exe.strip(),
            "port": port,
            "legacy": False,
        }

    def get_pid_metadata(self) -> Optional[dict[str, Any]]:
        """Read and validate Core PID metadata (structured JSON or legacy integer)."""
        pid_file = get_pid_file_path()
        try:
            raw = _read_file_text_raw(pid_file)
        except Exception as exc:
            logger.warning("Failed reading Core PID file '%s': %s", pid_file, exc)
            self._last_pid_error = "PID_READ_ERROR"
            return None

        if raw is None:
            self._last_pid_error = None
            return None

        content = raw.strip()
        if not content:
            logger.warning("Malformed empty Core PID file at '%s'.", pid_file)
            self._last_pid_error = "MALFORMED_PID_METADATA"
            return None

        if content.startswith("{"):
            try:
                parsed = json.loads(content)
            except Exception as exc:
                logger.warning("Corrupt JSON in Core PID file '%s': %s", pid_file, exc)
                self._last_pid_error = "MALFORMED_PID_METADATA"
                return None
            validated = self._validate_structured_pid_payload(parsed)
            if validated is None:
                logger.warning("Invalid Core PID metadata schema in '%s'.", pid_file)
                self._last_pid_error = "MALFORMED_PID_METADATA"
                return None
            self._last_pid_error = None
            return validated

        if content.isdigit():
            pid_val = int(content)
            if pid_val > 0:
                self._last_pid_error = None
                return {
                    "pid": pid_val,
                    "create_time": None,
                    "exe": None,
                    "port": None,
                    "legacy": True,
                }

        logger.warning("Unrecognized Core PID file format in '%s'.", pid_file)
        self._last_pid_error = "MALFORMED_PID_METADATA"
        return None

    def get_tracked_pid(self) -> Optional[int]:
        """Read the currently recorded daemon PID from disk, if valid."""
        meta = self.get_pid_metadata()
        return meta["pid"] if meta else None

    def _capture_process_metadata(self, pid: int) -> Optional[dict[str, Any]]:
        """Inspect live OS metadata for an owned Core process."""
        try:
            proc = psutil.Process(pid)
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                return None
            ct = float(proc.create_time())
            exe = proc.exe()
            if not math.isfinite(ct) or ct <= 0 or not exe:
                return None
            return {
                "pid": int(pid),
                "create_time": ct,
                "exe": str(exe),
                "port": int(self.port),
            }
        except (psutil.Error, OSError, ValueError):
            return None

    def _write_pid(
        self,
        pid: int,
        create_time: Optional[float] = None,
        exe: Optional[str] = None,
        port: Optional[int] = None,
    ) -> bool:
        """Atomically record structured daemon ownership metadata."""
        meta_exe = exe
        meta_ct = create_time
        if meta_ct is None or not meta_exe:
            captured = self._capture_process_metadata(pid)
            if captured:
                if meta_ct is None:
                    meta_ct = captured["create_time"]
                if not meta_exe:
                    meta_exe = captured["exe"]

        payload = {
            "pid": int(pid),
            "create_time": float(meta_ct) if meta_ct is not None else 0.0,
            "exe": str(meta_exe or ""),
            "port": int(port if port is not None else self.port),
        }
        validated = self._validate_structured_pid_payload(payload)
        if validated is None:
            logger.debug("Skipping atomic PID metadata write for unverifiable PID %s.", pid)
            return False

        serialized = json.dumps(
            {
                "pid": validated["pid"],
                "create_time": validated["create_time"],
                "exe": validated["exe"],
                "port": validated["port"],
            },
            separators=(",", ":"),
        )
        try:
            _atomic_write_text_raw(get_pid_file_path(), serialized)
            return True
        except Exception as exc:
            logger.warning("Failed writing Core PID metadata: %s", exc)
            return False

    def _clear_pid(
        self,
        expected_pid: Optional[int] = None,
        expected_create_time: Optional[float] = None,
    ) -> bool:
        """Remove PID tracking file only after verifying instance ownership when provided."""
        try:
            pid_file = get_pid_file_path()
            if not pid_file.exists():
                return False

            if expected_pid is not None:
                current = self.get_pid_metadata()
                if current is None or current["pid"] != expected_pid:
                    logger.debug(
                        "Skipping PID file removal: current owner %r does not match expected pid=%s.",
                        current,
                        expected_pid,
                    )
                    return False
                if expected_create_time is not None and current.get("create_time") is not None:
                    if abs(float(current["create_time"]) - float(expected_create_time)) > 1.0:
                        logger.debug(
                            "Skipping PID file removal: create_time mismatch (%s vs %s).",
                            current.get("create_time"),
                            expected_create_time,
                        )
                        return False

            pid_file.unlink()
            return True
        except Exception as exc:
            logger.debug("Failed removing PID file: %s", exc)
            return False

    def is_process_snow_core(
        self,
        pid: int,
        expected_create_time: Optional[float] = None,
        expected_exe: Optional[str] = None,
    ) -> bool:
        """Verify whether a given PID is alive and positively belongs to SNOW Core."""
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return False
        try:
            proc = psutil.Process(pid)
            if not proc.is_running() or proc.status() == psutil.STATUS_ZOMBIE:
                return False

            if expected_create_time is not None:
                actual_ct = float(proc.create_time())
                if abs(actual_ct - float(expected_create_time)) > 1.0:
                    return False

            try:
                actual_exe_raw = proc.exe()
            except (psutil.AccessDenied, psutil.Error, OSError):
                actual_exe_raw = None

            if expected_exe:
                norm_actual = _normalize_exe_path(actual_exe_raw)
                norm_expected = _normalize_exe_path(expected_exe)
                if not norm_actual or not norm_expected or norm_actual != norm_expected:
                    return False

            name = (proc.name() or "").lower()
            try:
                cmd_args = [str(part) for part in proc.cmdline()]
            except (psutil.AccessDenied, psutil.Error, OSError):
                cmd_args = []
            cmdline = " ".join(cmd_args).lower()
            lower_args = [arg.lower() for arg in cmd_args]

            # Never misidentify web/tray/mcp subcommands as SNOW Core.
            if len(lower_args) >= 2 and lower_args[1] in ("web", "tray", "mcp", "doctor", "status", "setup"):
                return False
            if "-m snow.cli web" in cmdline or "-m snow.cli tray" in cmdline or "-m snow.mcp" in cmdline:
                return False

            is_core_cmd = (
                "snow.main" in cmdline
                or "snow.core.server" in cmdline
                or "-m snow" in cmdline
            )
            if is_core_cmd:
                return True

            if name in ("snow.exe", "snow"):
                if len(lower_args) <= 1 or "core" in lower_args[1:]:
                    return True

            if "snow.exe" in cmdline and "core" in lower_args:
                return True

            return False
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return False
        except Exception as exc:
            logger.debug("Error checking process %d: %s", pid, exc)
            return False

    def _resolve_spawned_core_pid(self, spawned_pid: int) -> int:
        """Unwrap PEP 405 venv launcher stub PIDs on Windows to the live Core interpreter PID."""
        try:
            parent = psutil.Process(spawned_pid)
            parent_exe = _normalize_exe_path(parent.exe())
            children = parent.children(recursive=False)
            verified_children: list[int] = []
            for child in children:
                try:
                    child_exe = _normalize_exe_path(child.exe())
                except (psutil.Error, OSError):
                    child_exe = None
                if (
                    parent_exe
                    and child_exe
                    and parent_exe != child_exe
                    and self.is_process_snow_core(child.pid)
                ):
                    verified_children.append(child.pid)
            if len(verified_children) == 1:
                return verified_children[0]
        except Exception:
            pass
        return spawned_pid

    def _get_core_command(self) -> list[str]:
        """Resolve the executable command for SNOW Desktop Core."""
        if getattr(sys, "frozen", False):
            # Running as a frozen executable (e.g. snow-tray.exe or snow.exe)
            exe_path = Path(sys.executable).resolve()
            sibling_core = exe_path.with_name("snow.exe")
            if sibling_core.is_file():
                return [str(sibling_core), "core"]
            if exe_path.name.lower() == "snow.exe":
                return [str(exe_path), "core"]
            raise FileNotFoundError(
                f"SNOW Core executable 'snow.exe' not found alongside {exe_path}"
            )
        return [sys.executable, "-m", "snow.main"]

    async def _adopt_or_report_existing_core(self) -> dict[str, Any]:
        """Return ALREADY_RUNNING status once IPC identity is confirmed, upgrading legacy PID if owned."""
        meta = self.get_pid_metadata()
        verified_pid: Optional[int] = None
        if meta:
            pid_val = meta["pid"]
            if meta.get("legacy"):
                if self.is_process_snow_core(pid_val):
                    verified_pid = pid_val
                    self._write_pid(pid_val, port=self.port)
            else:
                if self.is_process_snow_core(
                    pid_val,
                    expected_create_time=meta.get("create_time"),
                    expected_exe=meta.get("exe"),
                ):
                    verified_pid = pid_val

        return {
            "success": True,
            "status": "ALREADY_RUNNING",
            "message": "SNOW Desktop Core is running and accepting authenticated IPC connections.",
            "pid": verified_pid,
        }

    async def ensure_core_running(self) -> dict[str, Any]:
        """Ensure SNOW Core daemon is running and accepting authenticated IPC connections.

        Uses both an in-process asyncio lock and an OS-level cross-process file lock
        to serialize startup across processes without PID races or duplicate Core spawns.
        """
        # Fast path when authenticated Core IPC is already online.
        if await self.is_ipc_ready():
            meta = self.get_pid_metadata()
            if meta is None or not meta.get("legacy"):
                return await self._adopt_or_report_existing_core()

        async with self._spawn_lock:
            try:
                async with self._acquire_cross_process_lock():
                    # Re-check under both locks in case a peer just finished startup.
                    if await self.is_ipc_ready():
                        return await self._adopt_or_report_existing_core()

                    # Fail closed if an unrelated or unresponsive listener already holds the IPC port.
                    if await self._is_port_occupied(timeout=0.25):
                        probe_err = self._last_ipc_error or "IPC_IDENTITY_FAILED"
                        return {
                            "success": False,
                            "status": "PORT_CONFLICT",
                            "error": (
                                f"IPC port {self.port} on {self.host} is already occupied by a process "
                                f"that failed SNOW Core verification ({probe_err})."
                            ),
                        }

                    # Inspect existing PID metadata carefully before spawning.
                    existing_meta = self.get_pid_metadata()
                    if existing_meta is not None:
                        existing_pid = existing_meta["pid"]
                        if not existing_meta.get("legacy") and self.is_process_snow_core(
                            existing_pid,
                            expected_create_time=existing_meta.get("create_time"),
                            expected_exe=existing_meta.get("exe"),
                        ):
                            # Core process is alive; allow brief IPC readiness settle before failing closed.
                            grace_deadline = time.monotonic() + min(1.5, float(self.spawn_timeout))
                            while time.monotonic() < grace_deadline:
                                if await self.is_ipc_ready(timeout=0.3):
                                    return await self._adopt_or_report_existing_core()
                                await asyncio.sleep(POLL_INTERVAL_SECONDS)
                            return {
                                "success": False,
                                "status": "IPC_READINESS_FAILED",
                                "error": (
                                    f"Verified SNOW Core process (PID {existing_pid}) is running, "
                                    f"but IPC readiness check on {self.host}:{self.port} failed "
                                    f"({self._last_ipc_error or 'IPC_OFFLINE'})."
                                ),
                                "pid": existing_pid,
                            }

                    logger.info("Starting background SNOW Desktop Core daemon...")
                    log_path = get_daemon_log_path()

                    creation_flags = 0
                    if sys.platform == "win32":
                        creation_flags |= CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP

                    log_file = None
                    try:
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

                    owned_meta = self._capture_process_metadata(proc.pid)
                    owned_ct = owned_meta["create_time"] if owned_meta else None
                    owned_exe = owned_meta["exe"] if owned_meta else None
                    wrote_pid = False
                    if proc.poll() is None:
                        wrote_pid = self._write_pid(
                            proc.pid,
                            create_time=owned_ct,
                            exe=owned_exe,
                            port=self.port,
                        )

                    logger.info("Spawned Core daemon [pid=%d], waiting for IPC readiness...", proc.pid)

                    deadline = time.monotonic() + self.spawn_timeout
                    while time.monotonic() < deadline:
                        if await self.is_ipc_ready():
                            effective_pid = self._resolve_spawned_core_pid(proc.pid)
                            effective_meta = self._capture_process_metadata(effective_pid)
                            if effective_meta:
                                owned_ct = effective_meta["create_time"]
                                owned_exe = effective_meta["exe"]
                            wrote_pid = self._write_pid(
                                effective_pid,
                                create_time=owned_ct,
                                exe=owned_exe,
                                port=self.port,
                            ) or wrote_pid
                            logger.info("Core daemon is online and IPC is ready [pid=%d].", effective_pid)
                            return {
                                "success": True,
                                "status": "STARTED",
                                "message": f"Successfully started SNOW Desktop Core (PID {effective_pid}).",
                                "pid": effective_pid,
                            }

                        if proc.poll() is not None:
                            if wrote_pid:
                                self._clear_pid(
                                    expected_pid=proc.pid,
                                    expected_create_time=owned_ct,
                                )
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

                    return {
                        "success": False,
                        "status": "STARTUP_TIMEOUT",
                        "error": (
                            f"SNOW Core process (PID {proc.pid}) did not become ready within "
                            f"{self.spawn_timeout:.1f}s ({self._last_ipc_error or 'IPC_TIMEOUT'}). "
                            f"Check logs at {log_path}."
                        ),
                        "pid": proc.pid,
                    }
            except TimeoutError as lock_err:
                logger.error("Core startup lock acquisition timed out: %s", lock_err)
                return {
                    "success": False,
                    "status": "LOCK_TIMEOUT",
                    "error": str(lock_err),
                }

    async def stop_core(self, timeout: float = 5.0) -> dict[str, Any]:
        """Gracefully stop the verified background SNOW Core daemon."""
        meta = self.get_pid_metadata()
        pid = meta["pid"] if meta else None
        is_ready = await self.is_ipc_ready()

        if self._last_pid_error == "MALFORMED_PID_METADATA" and not is_ready:
            return {
                "success": False,
                "status": "INVALID_PID_METADATA",
                "error": (
                    f"Core PID metadata at '{get_pid_file_path()}' is malformed and IPC is offline; "
                    "refusing to terminate an unverified process."
                ),
            }

        is_verified_proc = False
        if meta and pid is not None:
            if meta.get("legacy"):
                is_verified_proc = self.is_process_snow_core(pid) and is_ready
            else:
                is_verified_proc = self.is_process_snow_core(
                    pid,
                    expected_create_time=meta.get("create_time"),
                    expected_exe=meta.get("exe"),
                )

        if not is_ready and not is_verified_proc:
            if meta and not meta.get("legacy"):
                # Clean up stale structured PID metadata only if process is verified dead/reused.
                self._clear_pid(
                    expected_pid=meta["pid"],
                    expected_create_time=meta.get("create_time"),
                )
            return {
                "success": True,
                "status": "ALREADY_STOPPED",
                "message": "SNOW Core daemon is not running.",
            }

        if not is_verified_proc:
            return {
                "success": False,
                "status": "UNVERIFIABLE_PROCESS",
                "error": (
                    f"Refusing to terminate PID {pid}: process identity/creation time could not be "
                    "positively verified as an owned SNOW Core instance."
                ),
            }

        target_proc = None
        expected_ct = meta.get("create_time") if meta else None
        try:
            target_proc = psutil.Process(pid)
        except Exception as exc:
            return {
                "success": False,
                "status": "STOP_FAILED",
                "error": f"Failed opening verified Core process {pid}: {exc}",
            }

        # Collect verified launcher child processes (e.g. Windows venv stub -> real Python Core)
        child_targets: list[tuple[psutil.Process, Optional[float]]] = []
        try:
            for child in target_proc.children(recursive=False):
                if self.is_process_snow_core(child.pid):
                    child_targets.append((child, float(child.create_time())))
        except Exception:
            pass

        # Attempt graceful termination of the verified instance (and verified Core child if wrapped).
        try:
            for child, _ in child_targets:
                try:
                    child.terminate()
                except Exception:
                    pass
            target_proc.terminate()
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                child_alive = any(c.is_running() for c, _ in child_targets)
                if not target_proc.is_running() and not child_alive:
                    break
                await asyncio.sleep(0.1)

            for child, child_ct in child_targets:
                if child.is_running():
                    if child_ct is None or abs(float(child.create_time()) - child_ct) <= 1.0:
                        child.kill()

            if target_proc.is_running():
                # Re-verify create_time before force-kill.
                if expected_ct is None or abs(float(target_proc.create_time()) - float(expected_ct)) <= 1.0:
                    target_proc.kill()
                    await asyncio.sleep(0.1)
        except Exception as exc:
            logger.warning("Error stopping daemon process %d: %s", pid, exc)

        self._clear_pid(expected_pid=pid, expected_create_time=expected_ct)
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
        meta = self.get_pid_metadata()
        pid = meta["pid"] if meta else None
        ipc_online = await self.is_ipc_ready(timeout=0.5)
        proc_running = False
        if meta and pid is not None:
            if meta.get("legacy"):
                proc_running = bool(ipc_online and self.is_process_snow_core(pid))
            else:
                proc_running = self.is_process_snow_core(
                    pid,
                    expected_create_time=meta.get("create_time"),
                    expected_exe=meta.get("exe"),
                )

        return {
            "daemon_running": proc_running or ipc_online,
            "ipc_ready": ipc_online,
            "pid": pid if proc_running else None,
            "host": self.host,
            "port": self.port,
            "log_path": str(get_daemon_log_path()),
            "pid_metadata_valid": self._last_pid_error is None,
        }
