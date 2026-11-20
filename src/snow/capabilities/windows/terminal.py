"""Windows terminal command execution capability for SNOW.

Provides controlled asynchronous shell command execution on Windows hosts.
SECURITY MODEL & LIMITATIONS:
- Four Structured Security Tiers:
  * READ_ONLY: Safe inspection and diagnostic commands permitted to AI_MCP within approved roots.
  * WORKSPACE_SCOPED: AI workspace operations permitted only within approved roots.
  * OWNER_CONFIRMED: Full user-level execution across valid Windows directories for authenticated
    OWNER_MANUAL principal with explicit confirmation.
  * RESTRICTED_BLOCKED: Destructive or catastrophic operations hard-blocked regardless of principal.
- Catastrophic & Credential Tampering Protection: Operations like volume formatting, critical
  system destruction, and tampering with SNOW cryptographic identity / IPC secrets are blocked.
- Strict Bounds: Bounded execution timeouts (default 30s, max 120s) and bounded output
  buffers (128 KiB per stream) prevent denial of service and memory exhaustion.
- No Silent Privilege Escalation: Does not request or attempt administrator elevation.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import StrEnum
import logging
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Set

from snow.security.context import ExecutionContext, ExecutionPrincipal

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS: float = 30.0
MAX_TIMEOUT_SECONDS: float = 120.0
MAX_OUTPUT_BYTES: int = 128 * 1024  # 128 KiB cap per stream


class TerminalSecurityTier(StrEnum):
    """The four explicit terminal security tiers governing command execution."""

    READ_ONLY = "READ_ONLY"
    WORKSPACE_SCOPED = "WORKSPACE_SCOPED"
    OWNER_CONFIRMED = "OWNER_CONFIRMED"
    RESTRICTED_BLOCKED = "RESTRICTED_BLOCKED"


# Regex patterns matching catastrophic or destructive operations
CATASTROPHIC_PATTERNS: list[re.Pattern] = [
    # Disk / volume formatting (including switches before/after drive letter)
    re.compile(r"\bformat(\.com)?\s+.*[a-zA-Z]:", re.IGNORECASE),
    re.compile(r"\bdiskpart\b", re.IGNORECASE),
    # Recursive deletion of root or Windows directories (both backslash and forward slash)
    re.compile(r"\b(del|erase|rmdir|rd)\s+.*([a-zA-Z]:[\\/]|\bWindows\b|\bSystem32\b)", re.IGNORECASE),
    re.compile(r"\bRemove-Item\b.*(-Recurse|-r)\b.*([a-zA-Z]:[\\/]|\bWindows\b|\bSystem32\b)", re.IGNORECASE),
    # Tampering with SNOW secret files or authentication material
    re.compile(r"\b(del|erase|remove-item|rm|rmdir|rd|move|ren)\b.*(\.snow|ipc\.secret|server\.key|server\.crt|snow_devices\.db)", re.IGNORECASE),
    re.compile(r"\bicacls\b.*(\.snow|ipc\.secret)", re.IGNORECASE),
    # Fork bombs / infinite process spawns
    re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:", re.IGNORECASE),
    re.compile(r"%\s*0\s*\|\s*%\s*0", re.IGNORECASE),
]

# System administrative tools and service management prohibited from Tier B (WORKSPACE_SCOPED) for AI_MCP
SUBSHELL_AND_ADMIN_PATTERNS: list[re.Pattern] = [
    re.compile(r"\b(Get-Service|Start-Service|Stop-Service|Restart-Service|Set-Service)\b", re.IGNORECASE),
    re.compile(r"\b(net|sc|taskkill|shutdown|bcdedit|wbadmin|vssadmin)(\.exe)?\b", re.IGNORECASE),
    re.compile(r"\b(Restart-Computer|Stop-Computer)\b", re.IGNORECASE),
]

# Patterns strictly blocked for AI_MCP (evasion, registry, privilege escalation, credential access)
AI_BLOCKED_PATTERNS: list[re.Pattern] = [
    # Encoded PowerShell execution
    re.compile(r"powershell(\.exe)?\s+.*(-e|-enc|-encodedcommand|-encoded)\b", re.IGNORECASE),
    re.compile(r"pwsh(\.exe)?\s+.*(-e|-enc|-encodedcommand|-encoded)\b", re.IGNORECASE),
    # Registry tampering
    re.compile(r"\breg(\.exe)?\s+(add|delete|copy|restore|import)\b", re.IGNORECASE),
    re.compile(r"\b(Set-ItemProperty|Remove-ItemProperty|New-ItemProperty|Clear-ItemProperty)\b.*(HKLM|HKCU|Registry::)", re.IGNORECASE),
    # Privilege escalation
    re.compile(r"\brunas(\.exe)?\b", re.IGNORECASE),
    re.compile(r"Start-Process\b.*-Verb\s+RunAs", re.IGNORECASE),
    # Direct access to .snow credentials
    re.compile(r"(\.snow|ipc\.secret|server\.key|snow_devices\.db)", re.IGNORECASE),
]

# Whitelist of safe inspection commands for Tier A (READ_ONLY)
READ_ONLY_BASE_COMMANDS: set[str] = {
    "whoami",
    "hostname",
    "ipconfig",
    "systeminfo",
    "dir",
    "get-childitem",
    "gci",
    "ls",
    "type",
    "get-content",
    "cat",
    "where",
    "where.exe",
    "which",
    "echo",
    "write-output",
}

READ_ONLY_GIT_SUBCOMMANDS: set[str] = {
    "status",
    "log",
    "diff",
    "show",
    "branch",
    "tag",
    "rev-parse",
    "describe",
    "version",
    "--version",
    "-v",
}


def get_default_workspace_roots() -> list[Path]:
    """Return approved default workspace roots for AI_MCP callers."""
    roots: list[Path] = []
    try:
        home = Path.home().resolve()
        roots.append(home)
        for sub in ("Desktop", "Documents", "Downloads"):
            p = (home / sub).resolve()
            if p.exists():
                roots.append(p)
    except Exception:
        pass
    try:
        cwd = Path.cwd().resolve()
        roots.append(cwd)
    except Exception:
        pass
    return roots


def check_interactive_repl(command: str) -> Optional[str]:
    """Check if command is an interactive REPL invocation without execution arguments.

    Returns a friendly error message if it would hang waiting for interactive input,
    or None if the command includes non-interactive execution arguments.
    """
    parts = command.strip().split()
    if not parts:
        return None
    raw_exe = parts[0].lower().replace('"', '').replace("'", "")
    exe_name = Path(raw_exe).name
    if exe_name.endswith(".exe"):
        exe_name = exe_name[:-4]

    repl_names = {"python", "py", "node", "cmd", "powershell", "pwsh"}
    if exe_name not in repl_names:
        return None

    args = parts[1:]
    # Bare command: e.g. 'python', 'py', 'node', 'cmd', 'powershell'
    if not args:
        return (
            f"Interactive REPL '{exe_name}' requires arguments in non-interactive command mode. "
            f"Try '{exe_name} --version' or '{exe_name} -c \"print(1 + 1)\"'."
        )

    # For 'python' and 'py', check if flags or scripts are provided
    if exe_name in ("python", "py"):
        non_interactive_markers = {"-c", "-m", "-h", "--help", "-v", "-V", "--version", "-W", "-X", "-?", "/?"}
        has_action = False
        for a in args:
            if a in non_interactive_markers:
                has_action = True
                break
            if a.endswith(".py") or a.endswith(".pyw"):
                has_action = True
                break
            # If there's an argument that does not look like a version selector (-3, -3.13) or -i
            if not a.startswith("-"):
                has_action = True
                break
            elif a not in ("-i", "-3", "-2") and not re.match(r"^-[23](\.\d+)?$", a):
                has_action = True
                break
        if not has_action:
            return (
                f"Interactive REPL '{exe_name}' requires arguments in non-interactive command mode. "
                f"Try '{exe_name} --version' or '{exe_name} -c \"print(1 + 1)\"'."
            )

    elif exe_name in ("powershell", "pwsh"):
        non_interactive_markers = {"-command", "-c", "-file", "-f", "-help", "-?", "/?", "-version", "-v"}
        has_action = any(a.lower() in non_interactive_markers or a.endswith(".ps1") for a in args)
        if not has_action:
            return (
                f"Interactive REPL '{exe_name}' requires arguments in non-interactive command mode. "
                f"Try '{exe_name} -Command \"Get-Date\"'."
            )

    elif exe_name == "cmd":
        non_interactive_markers = {"/c", "/k", "/?"}
        has_action = any(a.lower() in non_interactive_markers for a in args)
        if not has_action:
            return (
                f"Interactive REPL '{exe_name}' requires arguments in non-interactive command mode. "
                f"Try 'cmd /c \"echo hello\"'."
            )

    elif exe_name == "node":
        non_interactive_markers = {"-e", "--eval", "-p", "--print", "-v", "--version", "-h", "--help"}
        has_action = any(
            a in non_interactive_markers or a.endswith(".js") or a.endswith(".mjs") or not a.startswith("-")
            for a in args
        )
        if not has_action:
            return (
                f"Interactive REPL '{exe_name}' requires arguments in non-interactive command mode. "
                f"Try 'node --version' or 'node -e \"console.log(1+1)\"'."
            )

    return None


@dataclass
class TerminalSecurityPolicy:
    """Configurable execution policy for the Windows terminal capability."""

    allow_execution: bool = True
    block_catastrophic: bool = True
    allowed_working_directories: Optional[List[Path]] = None
    max_timeout: float = MAX_TIMEOUT_SECONDS


class WindowsTerminalExecutor:
    """Asynchronous Windows command-line executor with output limits and 4-tier safety policy."""

    def __init__(
        self,
        policy: Optional[TerminalSecurityPolicy] = None,
        ticket_validator: Optional[Callable[[str, Optional[str], str], bool]] = None,
    ) -> None:
        self.policy = policy or TerminalSecurityPolicy()
        self.ticket_validator = ticket_validator

    def set_ticket_validator(
        self, validator: Callable[[str, Optional[str], str], bool]
    ) -> None:
        """Bind a server-side single-use confirmation ticket validation callback."""
        self.ticket_validator = validator

    def get_workspace_roots(self) -> list[Path]:
        """Return the combined list of authorized workspace roots."""
        roots = list(self.policy.allowed_working_directories or [])
        if not roots:
            roots = get_default_workspace_roots()
        return roots

    def classify_command(
        self,
        command: str,
        cwd: Optional[Path | str] = None,
        ctx: Optional[ExecutionContext] = None,
    ) -> TerminalSecurityTier:
        """Classify a command into one of the four structured security tiers.

        Tiers:
        1. RESTRICTED_BLOCKED: Catastrophic destruction, credential access, or AI evasion.
        2. READ_ONLY: Safe inspection within allowed bounds.
        3. WORKSPACE_SCOPED: Safe workspace commands in approved directories for AI_MCP.
        4. OWNER_CONFIRMED: General commands requiring owner confirmation.
        """
        ctx = ctx or ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="default")
        cmd_clean = (command or "").strip()

        # 1. Check catastrophic patterns (hard block for ALL callers, including OWNER_MANUAL)
        for pattern in CATASTROPHIC_PATTERNS:
            if pattern.search(cmd_clean):
                return TerminalSecurityTier.RESTRICTED_BLOCKED

        # Credential tampering targeting .snow private key, database, or IPC secret is blocked for ALL
        if re.search(r"\b(del|erase|remove-item|rm|rmdir|rd|move|ren)\b.*(\.snow|ipc\.secret|server\.key|server\.crt|snow_devices\.db)", cmd_clean, re.IGNORECASE):
            return TerminalSecurityTier.RESTRICTED_BLOCKED

        # 2. Check AI-specific blocked patterns (encoded commands, registry tampering, privilege escalation)
        if ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
            for pattern in AI_BLOCKED_PATTERNS:
                if pattern.search(cmd_clean):
                    return TerminalSecurityTier.RESTRICTED_BLOCKED

        # 3. Check for READ_ONLY inspection tier
        # Disallow output redirection (>, >>) in read-only
        has_redirection = bool(re.search(r"(>>|>)", cmd_clean))
        if not has_redirection:
            # Check single or chained commands
            tokens = cmd_clean.split()
            if tokens:
                first_token = tokens[0].lower().removesuffix(".exe")
                # Direct base command match
                if first_token in READ_ONLY_BASE_COMMANDS:
                    # Check for path traversal to .snow
                    if not re.search(r"(\.snow|ipc\.secret|server\.key|snow_devices\.db)", cmd_clean, re.IGNORECASE):
                        return TerminalSecurityTier.READ_ONLY
                # Git inspection subcommands
                elif first_token == "git" and len(tokens) >= 2:
                    sub = tokens[1].lower()
                    if sub in READ_ONLY_GIT_SUBCOMMANDS:
                        return TerminalSecurityTier.READ_ONLY
                # Python version checks
                elif first_token in ("python", "python3", "py") and any(
                    arg in ("--version", "-v", "-3.13") for arg in tokens[1:]
                ):
                    return TerminalSecurityTier.READ_ONLY

        # 4. Check WORKSPACE_SCOPED tier
        # Allowed for AI_MCP if working directory is inside approved workspace roots,
        # but subshell escapes and system administrative tools are strictly prohibited.
        resolved_cwd = None
        if cwd:
            try:
                resolved_cwd = Path(cwd).resolve()
            except Exception:
                pass
        else:
            try:
                resolved_cwd = Path.cwd().resolve()
            except Exception:
                pass

        if resolved_cwd:
            roots = self.get_workspace_roots()
            in_workspace = any(
                resolved_cwd == r or resolved_cwd.is_relative_to(r)
                for r in roots
            )
            # Check that command does not reference .. escaping workspace or system directories
            escapes_workspace = bool(re.search(r"(\.\.[\\/].*(\.\.[\\/]|Windows|System32))", cmd_clean, re.IGNORECASE))
            has_subshell_or_admin = any(p.search(cmd_clean) for p in SUBSHELL_AND_ADMIN_PATTERNS)
            if in_workspace and not escapes_workspace and not has_subshell_or_admin and ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
                return TerminalSecurityTier.WORKSPACE_SCOPED

        # 5. Otherwise, requires OWNER_CONFIRMED
        return TerminalSecurityTier.OWNER_CONFIRMED

    def validate_command(
        self, command: str, ctx: Optional[ExecutionContext] = None
    ) -> Optional[str]:
        """Validate command against security policies.

        Returns an error string if rejected, or None if permitted.
        Catastrophic and destructive commands are blocked for all principals.
        """
        ctx = ctx or ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="default")

        if not command or not isinstance(command, str) or not command.strip():
            return "Command must be a non-empty string."

        if not self.policy.allow_execution:
            return "Terminal execution is disabled by configuration policy."

        # Catastrophic destructive operations are blocked for ALL principals (including OWNER_MANUAL)
        if self.policy.block_catastrophic:
            cleaned = command.strip()
            for pattern in CATASTROPHIC_PATTERNS:
                if pattern.search(cleaned):
                    return (
                        f"Command rejected by security policy: matches forbidden "
                        f"destructive pattern ({pattern.pattern})."
                    )

        # AI-specific blocklist (evasion, encoded powershell, registry manipulation)
        if ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
            cleaned = command.strip()
            for pattern in AI_BLOCKED_PATTERNS:
                if pattern.search(cleaned):
                    return (
                        f"Command rejected by security policy: matches forbidden "
                        f"destructive or sensitive pattern ({pattern.pattern})."
                    )

        return None

    def validate_cwd(
        self, cwd: Optional[str | Path], ctx: Optional[ExecutionContext] = None
    ) -> tuple[Optional[Path], Optional[str]]:
        """Validate and resolve requested working directory."""
        ctx = ctx or ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="default")

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

        # OWNER_MANUAL can use any valid existing directory on the host
        if ctx.principal != ExecutionPrincipal.OWNER_MANUAL:
            roots = self.get_workspace_roots()
            permitted = any(
                resolved == r or resolved.is_relative_to(r)
                for r in roots
            )
            if not permitted:
                return None, f"Working directory '{cwd}' is not within authorized roots."

        return resolved, None

    async def execute_command(
        self,
        command: str,
        cwd: Optional[str | Path] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        ctx: Optional[ExecutionContext] = None,
        confirmed: bool = False,
        confirmation_ticket: Optional[str] = None,
    ) -> dict[str, Any]:
        """Execute a shell command asynchronously with bounds on time and buffer output.

        Enforces the four security tiers:
        - READ_ONLY: Safe inspection, permitted for AI_MCP and OWNER_MANUAL.
        - WORKSPACE_SCOPED: Permitted for AI_MCP in approved workspace directories.
        - OWNER_CONFIRMED: Permitted for OWNER_MANUAL with server-validated confirmation.
        - RESTRICTED_BLOCKED: Rejected with POLICY_DENIED.

        Returns:
            Structured dictionary with exit code, stdout, stderr, tier, and truncation flags.
        """
        ctx = ctx or ExecutionContext(principal=ExecutionPrincipal.AI_MCP, origin="default")

        # 1. Classify security tier
        tier = self.classify_command(command, cwd=cwd, ctx=ctx)

        # 2. Validate command structure & blocklist
        validation_err = self.validate_command(command, ctx=ctx)
        if validation_err or tier == TerminalSecurityTier.RESTRICTED_BLOCKED:
            err_msg = validation_err or "Command rejected by security policy: matches forbidden destructive pattern."
            return {
                "success": False,
                "status": "POLICY_DENIED",
                "tier": tier.value,
                "error": err_msg,
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

        # 3. Validate working directory
        resolved_cwd, cwd_err = self.validate_cwd(cwd, ctx=ctx)
        if cwd_err:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "tier": tier.value,
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

        # Validate server-issued confirmation ticket if provided
        is_valid_ticket = False
        if confirmation_ticket and self.ticket_validator:
            is_valid_ticket = self.ticket_validator(
                str(confirmation_ticket),
                ctx.device_id or "local_owner",
                command,
            )

        # 4. Enforce Tier permissions
        if tier == TerminalSecurityTier.OWNER_CONFIRMED:
            # AI callers are NEVER permitted to execute OWNER_CONFIRMED commands
            if not ctx.is_owner:
                return {
                    "success": False,
                    "status": "POLICY_DENIED",
                    "tier": tier.value,
                    "error": (
                        "Command requires OWNER_CONFIRMED tier; AI callers are restricted to "
                        "READ_ONLY and WORKSPACE_SCOPED tiers."
                    ),
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

            # Owner execution strictly requires explicit authorization via a valid confirmation ticket.
            # A client-supplied confirmed=True or arbitrary non-empty ticket string is never sufficient.
            if not is_valid_ticket:
                return {
                    "success": False,
                    "status": "CONFIRMATION_REQUIRED",
                    "tier": tier.value,
                    "error": "Execution requires explicit user confirmation via a valid, single-use confirmation ticket.",
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

        # 5. Validate timeout
        if not isinstance(timeout, (int, float)) or timeout <= 0:
            return {
                "success": False,
                "status": "INVALID_ARGUMENT",
                "tier": tier.value,
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

        # 6. Fast-fail guard: Reject bare/interactive REPLs that require input
        repl_err = check_interactive_repl(command)
        if repl_err:
            return {
                "success": False,
                "status": "INTERACTIVE_REPL_REJECTED",
                "tier": tier.value,
                "error": repl_err,
                "command": command,
                "exit_code": None,
                "stdout": "",
                "stderr": repl_err,
                "stdout_truncated": False,
                "stderr_truncated": False,
                "timed_out": False,
                "execution_time_ms": 0.0,
                "working_directory": str(resolved_cwd),
            }

        effective_timeout = min(float(timeout), self.policy.max_timeout)
        start_time = time.monotonic()

        # 7. Spawn process
        proc = None
        try:
            extra_kwargs: dict[str, Any] = {}
            if sys.platform == "win32":
                extra_kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

            # On Windows, create_subprocess_shell uses cmd.exe /c
            proc = await asyncio.create_subprocess_shell(
                command,
                cwd=str(resolved_cwd),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **extra_kwargs,
            )
        except (PermissionError, OSError) as exc:
            elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
            is_perm = isinstance(exc, PermissionError) or getattr(exc, "winerror", None) == 5
            status = "OS_PERMISSION_DENIED" if is_perm else "SPAWN_FAILED"
            return {
                "success": False,
                "status": status,
                "tier": tier.value,
                "error": f"OS permission denied: {exc}" if is_perm else f"Failed to spawn subprocess: {exc}",
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
        except Exception as exc:
            elapsed_ms = round((time.monotonic() - start_time) * 1000, 2)
            return {
                "success": False,
                "status": "SPAWN_FAILED",
                "tier": tier.value,
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

        # 7. Read output with timeout
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

        # 8. Apply buffer truncation limits
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
                "tier": tier.value,
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
            "tier": tier.value,
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
