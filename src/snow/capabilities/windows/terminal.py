"""Windows terminal command execution capability for SNOW.

Provides controlled asynchronous shell command execution on Windows hosts.
SECURITY MODEL & LIMITATIONS:
- Blocklist Defense-in-Depth: Catastrophic operations (volume formatting, critical
  system destruction, and tampering with SNOW cryptographic identity / IPC secrets)
  are intercepted and rejected.
- Shell Inherent Risk: A blocklist alone CANNOT make arbitrary shell execution
  completely safe. Shell commands run with the permissions of the local user session.
  AI clients must not assume unrestricted safety or use arbitrary command synthesis
  without user intent.
- Strict Bounds: Bounded execution timeouts (default 30s, max 120s) and bounded output
  buffers (128 KiB per stream) prevent denial of service and memory exhaustion.
- No Silent Privilege Escalation: Does not request or attempt administrator elevation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
import os
from pathlib import Path
import re
import shlex
import time
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS: float = 30.0
MAX_TIMEOUT_SECONDS: float = 120.0
MAX_OUTPUT_BYTES: int = 128 * 1024  # 128 KiB cap per stream

# Regex patterns matching catastrophic or destructive operations
CATASTROPHIC_PATTERNS: list[re.Pattern] = [
    # Disk / volume formatting
    re.compile(r"\bformat\s+[a-zA-Z]:", re.IGNORECASE),
    re.compile(r"\bdiskpart\b", re.IGNORECASE),
    # Recursive deletion of root or Windows directories
    re.compile(r"\b(del|erase|rmdir|rd)\s+.*([a-zA-Z]:\\|\bWindows\b|\bSystem32\b)", re.IGNORECASE),
    re.compile(r"\bRemove-Item\b.*(-Recurse|-r)\b.*([a-zA-Z]:\\|\bWindows\b|\bSystem32\b)", re.IGNORECASE),
    # Tampering with SNOW secret files or authentication material
    re.compile(r"\b(del|erase|remove-item|rm|move|ren)\b.*(\.snow|ipc\.secret|server\.key|server\.crt|snow_devices\.db)", re.IGNORECASE),
    re.compile(r"\bicacls\b.*(\.snow|ipc\.secret)", re.IGNORECASE),
    # Fork bombs / infinite process spawns
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),
    re.compile(r"%\s*0\s*\|\s*%\s*0", re.IGNORECASE),
]


@dataclass
class TerminalSecurityPolicy:
    """Configurable execution policy for the Windows terminal capability."""

    allow_execution: bool = True
    block_catastrophic: bool = True
    allowed_working_directories: Optional[List[Path]] = None
    max_timeout: float = MAX_TIMEOUT_SECONDS


class WindowsTerminalExecutor:
    """Asynchronous Windows command-line executor with output limits and safety policy."""

    def __init__(self, policy: Optional[TerminalSecurityPolicy] = None) -> None:
        self.policy = policy or TerminalSecurityPolicy()

    def validate_command(self, command: str) -> Optional[str]:
        """Validate command against security policies.

        Returns an error string if rejected, or None if permitted.
        """
        if not command or not isinstance(command, str) or not command.strip():
            return "Command must be a non-empty string."

        if not self.policy.allow_execution:
            return "Terminal execution is disabled by configuration policy."

        if self.policy.block_catastrophic:
            cleaned = command.strip()
            for pattern in CATASTROPHIC_PATTERNS:
                if pattern.search(cleaned):
                    return (
                        f"Command rejected by security policy: matches forbidden "
                        f"destructive pattern ({pattern.pattern})."
                    )

        return None

    def validate_cwd(self, cwd: Optional[str | Path]) -> tuple[Optional[Path], Optional[str]]:
        """Validate and resolve requested working directory."""
        if cwd is None or cwd == "":
            return Path.cwd().resolve(), None

        try:
            resolved = Path(cwd).resolve()
        except Exception as exc:
            return None, f"Invalid working directory path: {exc}"

        if not resolved.exists():
            return None, f"Working directory does not exist: '{cwd}'"

        if not resolved.is_dir():
            return None, f"Working directory is not a directory: '{cwd}'"

        if self.policy.allowed_working_directories:
            permitted = False
            for allowed_root in self.policy.allowed_working_directories:
                try:
                    if resolved == allowed_root or resolved.is_relative_to(allowed_root):
                        permitted = True
                        break
                except Exception:
                    continue
            if not permitted:
                return None, f"Working directory '{cwd}' is not within authorized roots."

        return resolved, None

    async def execute_command(
        self,
        command: str,
        cwd: Optional[str | Path] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> dict[str, Any]:
        """Execute a shell command asynchronously with bounds on time and buffer output.

        Args:
            command: The command line string to execute.
            cwd: Working directory (defaults to current directory).
            timeout: Maximum execution time in seconds (bounded to policy max).

        Returns:
            Structured dictionary with exit code, stdout, stderr, and truncation flags.
        """
        # 1. Validate command
        validation_err = self.validate_command(command)
        if validation_err:
            return {
                "success": False,
                "status": "POLICY_DENIED",
                "error": validation_err,
                "command": command,
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "timed_out": False,
                "execution_time_ms": 0.0,
                "working_directory": str(cwd or ""),
            }

        # 2. Validate cwd
        resolved_cwd, cwd_err = self.validate_cwd(cwd)
        if cwd_err:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": cwd_err,
                "command": command,
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "timed_out": False,
                "execution_time_ms": 0.0,
                "working_directory": str(cwd or ""),
            }

        # 3. Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "error": f"Timeout must be a positive number, got {timeout!r}.",
                "command": command,
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "timed_out": False,
                "execution_time_ms": 0.0,
                "working_directory": str(resolved_cwd),
            }

        effective_timeout = min(float(timeout), self.policy.max_timeout)
        start_time = time.monotonic()

        # 4. Spawn process
        proc = None
        try:
            # On Windows, create_subprocess_shell uses cmd.exe /c
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=str(resolved_cwd),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except Exception as exc:
            elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
            return {
                "success": False,
                "status": "SPAWN_FAILED",
                "error": f"Failed to spawn subprocess: {exc}",
                "command": command,
                "exit_code": None,
                "stdout": "",
                "stderr": "",
                "stdout_truncated": False,
                "stderr_truncated": False,
                "timed_out": False,
                "execution_time_ms": elapsed_ms,
                "working_directory": str(resolved_cwd),
            }

        # 5. Read output with timeout
        stdout_raw = b""
        stderr_raw = b""
        timed_out = False

        try:
            stdout_raw, stderr_raw = await asyncio.wait_for(
                proc.communicate(),
                timeout=effective_timeout,
            )
        except asyncio.TimeoutError:
            timed_out = True
            try:
                proc.kill()
                await proc.wait()
            except Exception:
                pass
        except Exception as exc:
            logger.warning("Error communicating with subprocess: %s", exc)
            try:
                proc.kill()
            except Exception:
                pass

        elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
        exit_code = proc.returncode if proc else None

        # 6. Apply buffer truncation limits
        stdout_truncated = len(stdout_raw) > MAX_OUTPUT_BYTES
        stderr_truncated = len(stderr_raw) > MAX_OUTPUT_BYTES

        stdout_bytes = stdout_raw[:MAX_OUTPUT_BYTES]
        stderr_bytes = stderr_raw[:MAX_OUTPUT_BYTES]

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")

        if timed_out:
            return {
                "success": False,
                "status": "TIMEOUT",
                "error": f"Command timed out after {effective_timeout:.1f}s.",
                "command": command,
                "exit_code": None,
                "stdout": stdout_text,
                "stderr": stderr_text,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "timed_out": True,
                "execution_time_ms": elapsed_ms,
                "working_directory": str(resolved_cwd),
            }

        is_success = exit_code == 0
        status_code = "SUCCESS" if is_success else "COMMAND_FAILED"

        return {
            "success": is_success,
            "status": status_code,
            "error": None if is_success else f"Command exited with code {exit_code}.",
            "command": command,
            "exit_code": exit_code,
            "stdout": stdout_text,
            "stderr": stderr_text,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "timed_out": False,
            "execution_time_ms": elapsed_ms,
            "working_directory": str(resolved_cwd),
        }
