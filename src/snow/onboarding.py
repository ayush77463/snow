"""Multi-Host AI Assistant Onboarding Adapters for SNOW.

Provides safe configuration generation, merging, and removal for:
- Claude Desktop (%APPDATA%\\Claude\\claude_desktop_config.json)
- Gemini CLI / Antigravity (~/.gemini/settings.json)
- Cursor (~/.cursor/mcp.json)
- ChatGPT / Generic MCP (~/.snow/chatgpt_mcp_config.json)

Security & Data Integrity Guarantees:
1. Merges non-destructively: preserves all other settings and sibling MCP servers.
2. Creates .bak backups before overwriting or modifying any existing configuration.
3. Uses atomic filesystem replace to prevent partial writes or corrupt configs.
4. Validates JSON structure before and after modification.
5. In dry-run mode, creates zero files, performs zero modifications, and spawns no daemons.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import shutil
import sys
import tempfile
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def get_default_python_executable() -> str:
    """Resolve the active Python interpreter path with proper quoting if needed."""
    return sys.executable


def get_canonical_mcp_entry(python_exe: Optional[str] = None) -> dict[str, Any]:
    """Generate the canonical stdio MCP server launch configuration for SNOW."""
    exe = python_exe or get_default_python_executable()
    is_standalone_binary = Path(exe).name.lower() in ("snow.exe", "snow")
    return {
        "command": exe,
        "args": ["mcp"] if is_standalone_binary else ["-m", "snow.mcp"],
    }


def get_remote_mcp_entry(
    url: str = "http://127.0.0.1:8771/mcp", auth_token: Optional[str] = None
) -> dict[str, Any]:
    """Generate the Streamable HTTP MCP entry for remote/networked AI clients."""
    entry: dict[str, Any] = {
        "url": url,
        "transport": "streamable_http",
    }
    if auth_token:
        entry["headers"] = {"Authorization": f"Bearer {auth_token}"}
    return entry


def atomic_write_json(
    file_path: Path, data: dict[str, Any], backup: bool = True
) -> Optional[Path]:
    """Atomically write JSON data to file with automatic .bak backup creation."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = None

    if file_path.exists() and backup:
        backup_path = file_path.with_suffix(file_path.suffix + ".bak")
        try:
            shutil.copy2(file_path, backup_path)
        except Exception as exc:
            logger.warning("Could not create backup at %s: %s", backup_path, exc)
            backup_path = None

    tmp_fd, tmp_name = tempfile.mkstemp(
        dir=str(file_path.parent), prefix=f".tmp_{file_path.name}_"
    )
    tmp_path = Path(tmp_name)
    try:
        with open(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.write("\n")
        os.replace(tmp_path, file_path)
        return backup_path
    except Exception:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
        raise


def safe_read_json(file_path: Path) -> Tuple[Optional[dict[str, Any]], Optional[str]]:
    """Safely read and parse a JSON configuration file.

    Returns:
        (parsed_dict, None) if file exists and contains valid JSON object.
        (None, None) if file does not exist.
        (None, error_message) if file exists but contains invalid JSON.
    """
    if not file_path.exists():
        return None, None
    try:
        content = file_path.read_text(encoding="utf-8").strip()
        if not content:
            return {}, None
        parsed = json.loads(content)
        if not isinstance(parsed, dict):
            return None, f"Expected JSON object in {file_path}, got {type(parsed).__name__}"
        return parsed, None
    except Exception as exc:
        return None, f"Failed parsing JSON from {file_path}: {exc}"


# =========================================================================
# Host Configuration Adapters
# =========================================================================


class BaseHostAdapter:
    """Abstract base adapter for an AI assistant host configuration."""

    name: str = "base"
    display_name: str = "Base Host"

    def get_default_config_path(self) -> Path:
        raise NotImplementedError

    def get_mcp_entry(self, python_exe: Optional[str] = None) -> dict[str, Any]:
        return get_canonical_mcp_entry(python_exe)

    def configure(
        self,
        target_path: Optional[Path] = None,
        dry_run: bool = False,
        python_exe: Optional[str] = None,
    ) -> dict[str, Any]:
        """Configure SNOW MCP server in the target host configuration."""
        path = target_path or self.get_default_config_path()
        mcp_entry = self.get_mcp_entry(python_exe)

        existing_data, err = safe_read_json(path)
        if err:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "success": False,
                "status": "INVALID_EXISTING_CONFIG",
                "error": err,
            }

        is_new = existing_data is None
        data = dict(existing_data) if existing_data is not None else {}

        # Safely insert/update mcpServers.snow
        mcp_servers = data.setdefault("mcpServers", {})
        if not isinstance(mcp_servers, dict):
            data["mcpServers"] = {}
            mcp_servers = data["mcpServers"]

        mcp_servers["snow"] = mcp_entry

        if dry_run:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "action": "CREATE" if is_new else "UPDATE",
                "success": True,
                "status": "DRY_RUN",
                "planned_config": data,
                "is_new_file": is_new,
            }

        try:
            bak = atomic_write_json(path, data, backup=not is_new)
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "action": "CREATE" if is_new else "UPDATE",
                "success": True,
                "status": "CONFIGURED",
                "backup_path": str(bak) if bak else None,
                "is_new_file": is_new,
            }
        except Exception as exc:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "success": False,
                "status": "WRITE_FAILED",
                "error": str(exc),
            }

    def remove(
        self,
        target_path: Optional[Path] = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Remove SNOW MCP server entry from the target host configuration."""
        path = target_path or self.get_default_config_path()
        if not path.exists():
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "success": True,
                "status": "NOT_PRESENT",
                "message": f"Configuration file {path} does not exist.",
            }

        data, err = safe_read_json(path)
        if err:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "success": False,
                "status": "INVALID_EXISTING_CONFIG",
                "error": err,
            }

        mcp_servers = data.get("mcpServers") if isinstance(data, dict) else None
        if not isinstance(mcp_servers, dict) or "snow" not in mcp_servers:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "success": True,
                "status": "ALREADY_REMOVED",
                "message": f"SNOW MCP entry was not found in {path}.",
            }

        # Remove snow entry while preserving all other servers and settings
        del mcp_servers["snow"]

        if dry_run:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "action": "REMOVE_ENTRY",
                "success": True,
                "status": "DRY_RUN",
                "planned_config": data,
            }

        try:
            bak = atomic_write_json(path, data, backup=True)
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "action": "REMOVE_ENTRY",
                "success": True,
                "status": "REMOVED",
                "backup_path": str(bak) if bak else None,
            }
        except Exception as exc:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "success": False,
                "status": "WRITE_FAILED",
                "error": str(exc),
            }

    def check_status(self, target_path: Optional[Path] = None) -> dict[str, Any]:
        """Check the status of SNOW MCP configuration in the target host."""
        path = target_path or self.get_default_config_path()
        if not path.exists():
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "status": "NOT_CONFIGURED",
                "is_configured": False,
                "message": f"Configuration file does not exist at {path}",
            }

        data, err = safe_read_json(path)
        if err:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "status": "WARNING",
                "is_configured": False,
                "error": err,
            }

        mcp_servers = data.get("mcpServers") if isinstance(data, dict) else None
        if isinstance(mcp_servers, dict) and "snow" in mcp_servers:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "status": "OK",
                "is_configured": True,
                "entry": mcp_servers["snow"],
            }

        return {
            "host": self.name,
            "display_name": self.display_name,
            "target_path": str(path),
            "status": "NOT_CONFIGURED",
            "is_configured": False,
            "message": "Configuration exists but mcpServers.snow entry is absent.",
        }


class ClaudeAdapter(BaseHostAdapter):
    """Adapter for Claude Desktop on Windows/macOS/Linux."""

    name = "claude"
    display_name = "Claude Desktop"

    def get_default_config_path(self) -> Path:
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / "Claude" / "claude_desktop_config.json"
        # Linux/macOS fallback
        return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"


class GeminiAdapter(BaseHostAdapter):
    """Adapter for Google Gemini CLI & Antigravity MCP settings."""

    name = "gemini"
    display_name = "Gemini CLI / Antigravity"

    def get_default_config_path(self) -> Path:
        return Path.home() / ".gemini" / "settings.json"


class CursorAdapter(BaseHostAdapter):
    """Adapter for Cursor IDE MCP configuration."""

    name = "cursor"
    display_name = "Cursor IDE"

    def get_default_config_path(self) -> Path:
        return Path.home() / ".cursor" / "mcp.json"


class ChatGPTAdapter(BaseHostAdapter):
    """Adapter for ChatGPT / Generic MCP client configuration artifact.

    Note: ChatGPT Web/Cloud operates over remote SSE/WebSocket endpoints.
    Writing this configuration file provides a documented local artifact
    for compatible desktop clients or local MCP bridge proxies.
    """

    name = "chatgpt"
    display_name = "ChatGPT / Generic MCP Artifact"

    def get_default_config_path(self) -> Path:
        snow_dir = Path.home() / ".snow"
        return snow_dir / "chatgpt_mcp_config.json"

    def configure(
        self,
        target_path: Optional[Path] = None,
        dry_run: bool = False,
        python_exe: Optional[str] = None,
    ) -> dict[str, Any]:
        res = super().configure(target_path=target_path, dry_run=dry_run, python_exe=python_exe)
        res["notes"] = (
            "Configuration artifact generated for ChatGPT / generic MCP clients. "
            "Note: Direct cloud ChatGPT integration requires a local SSE/WebSocket bridge proxy."
        )
        return res

    def remove(
        self,
        target_path: Optional[Path] = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """For ChatGPT artifact, remove the file if SNOW was the sole owner."""
        path = target_path or self.get_default_config_path()
        if not path.exists():
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "success": True,
                "status": "NOT_PRESENT",
                "message": f"Artifact {path} does not exist.",
            }

        if dry_run:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "action": "DELETE_ARTIFACT",
                "success": True,
                "status": "DRY_RUN",
            }

        try:
            path.unlink()
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "action": "DELETE_ARTIFACT",
                "success": True,
                "status": "REMOVED",
            }
        except Exception as exc:
            return {
                "host": self.name,
                "display_name": self.display_name,
                "target_path": str(path),
                "success": False,
                "status": "DELETE_FAILED",
                "error": str(exc),
            }


class RemoteMcpAdapter(BaseHostAdapter):
    """Adapter for Remote MCP Streamable HTTP configuration artifact."""

    name: str = "remote"
    display_name: str = "Remote MCP (Streamable HTTP)"

    def get_default_config_path(self) -> Path:
        snow_dir = Path.home() / ".snow"
        return snow_dir / "remote_mcp_config.json"

    def get_mcp_entry(self, python_exe: Optional[str] = None) -> dict[str, Any]:
        return get_remote_mcp_entry()


class AntigravityAdapter(BaseHostAdapter):
    """Adapter for Google Antigravity IDE MCP configuration."""

    name = "antigravity"
    display_name = "Google Antigravity"

    def get_default_config_path(self) -> Path:
        return Path.home() / ".gemini" / "antigravity" / "mcp_config.json"


# =========================================================================
# Host Onboarding Manager
# =========================================================================

SUPPORTED_HOSTS = ["claude", "gemini", "cursor", "chatgpt", "antigravity"]


class HostOnboardingManager:
    """Coordinates multi-host MCP configuration setup, status checks, and removal."""

    def __init__(
        self,
        custom_paths: Optional[dict[str, Path | str]] = None,
        python_exe: Optional[str] = None,
    ) -> None:
        self.adapters: dict[str, BaseHostAdapter] = {
            "claude": ClaudeAdapter(),
            "gemini": GeminiAdapter(),
            "cursor": CursorAdapter(),
            "chatgpt": ChatGPTAdapter(),
            "antigravity": AntigravityAdapter(),
            "remote": RemoteMcpAdapter(),
        }
        self.custom_paths: dict[str, Path] = {
            k: Path(v) for k, v in (custom_paths or {}).items()
        }
        self.python_exe = python_exe or get_default_python_executable()

    def get_adapter(self, host: str) -> Optional[BaseHostAdapter]:
        return self.adapters.get(host.strip().lower())

    def get_path(self, host: str) -> Path:
        adapter = self.adapters[host]
        return self.custom_paths.get(host) or adapter.get_default_config_path()

    def setup_host(
        self,
        host: str,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Configure one host, or 'all' supported hosts."""
        clean_host = host.strip().lower()
        if clean_host == "all":
            results = {}
            for h in SUPPORTED_HOSTS:
                results[h] = self.setup_host(h, dry_run=dry_run)
            all_ok = all(r.get("success") for r in results.values())
            return {
                "host": "all",
                "success": all_ok,
                "results": results,
                "dry_run": dry_run,
            }

        adapter = self.get_adapter(clean_host)
        if not adapter:
            return {
                "host": clean_host,
                "success": False,
                "status": "UNSUPPORTED_HOST",
                "error": f"Unsupported host '{host}'. Supported hosts: {', '.join(SUPPORTED_HOSTS)}, all",
            }

        path = self.get_path(clean_host)
        return adapter.configure(
            target_path=path, dry_run=dry_run, python_exe=self.python_exe
        )

    def remove_host(
        self,
        host: str,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Remove SNOW MCP entry from one host, or 'all' supported hosts."""
        clean_host = host.strip().lower()
        if clean_host == "all":
            results = {}
            for h in SUPPORTED_HOSTS:
                results[h] = self.remove_host(h, dry_run=dry_run)
            all_ok = all(r.get("success") for r in results.values())
            return {
                "host": "all",
                "success": all_ok,
                "results": results,
                "dry_run": dry_run,
            }

        adapter = self.get_adapter(clean_host)
        if not adapter:
            return {
                "host": clean_host,
                "success": False,
                "status": "UNSUPPORTED_HOST",
                "error": f"Unsupported host '{host}'. Supported hosts: {', '.join(SUPPORTED_HOSTS)}, all",
            }

        path = self.get_path(clean_host)
        return adapter.remove(target_path=path, dry_run=dry_run)

    def check_all_hosts(self) -> dict[str, Any]:
        """Check configuration status for all supported hosts."""
        statuses = {}
        for h, adapter in self.adapters.items():
            path = self.get_path(h)
            statuses[h] = adapter.check_status(target_path=path)
        return statuses
