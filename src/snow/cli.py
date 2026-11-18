"""Command-line interface (CLI) for SNOW.

Provides user commands for:
- snow setup: Automated and safe MCP configuration generation for Claude Desktop,
  Antigravity, Cursor, and generic MCP hosts.
- snow status: Live diagnostic overview of SNOW Core daemon, IPC endpoint, and logs.
- snow daemon start: Headless background daemon startup.
- snow daemon stop: Clean daemon termination.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Any, Dict, Optional

from snow.daemon import CoreDaemonManager, get_daemon_log_path, get_snow_dir

logger = logging.getLogger(__name__)

# Standard known MCP client configuration targets on Windows
APPDATA = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
CLAUDE_CONFIG_PATH = Path(APPDATA) / "Claude" / "claude_desktop_config.json"
ANTIGRAVITY_CONFIG_PATH = Path.home() / ".gemini" / "antigravity" / "mcp_config.json"


def get_snow_mcp_config_entry() -> dict[str, Any]:
    """Generate the canonical MCP server configuration entry for SNOW."""
    return {
        "command": sys.executable,
        "args": ["-m", "snow.mcp"],
    }


def merge_mcp_config(
    existing_content: str, server_name: str = "snow"
) -> tuple[dict[str, Any], Optional[str]]:
    """Safely merge SNOW MCP server definition into an existing JSON configuration string.

    Preserves all existing top-level keys and sibling mcpServers.
    """
    data: dict[str, Any] = {}
    warning: Optional[str] = None

    if existing_content and existing_content.strip():
        try:
            parsed = json.loads(existing_content)
            if isinstance(parsed, dict):
                data = parsed
            else:
                warning = "Existing configuration was not a JSON object; resetting to default structure."
        except json.JSONDecodeError as exc:
            warning = f"Existing configuration was invalid JSON ({exc}); backing up and recreating."

    mcp_servers = data.setdefault("mcpServers", {})
    if not isinstance(mcp_servers, dict):
        data["mcpServers"] = {}
        mcp_servers = data["mcpServers"]

    mcp_servers[server_name] = get_snow_mcp_config_entry()
    return data, warning


def atomic_write_json(file_path: Path, data: dict[str, Any], backup: bool = True) -> Optional[Path]:
    """Atomically write JSON data to file with automatic .bak creation."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    backup_path = None

    if file_path.exists() and backup:
        backup_path = file_path.with_suffix(".json.bak")
        shutil.copy2(file_path, backup_path)

    tmp_path = file_path.parent / f".tmp_{file_path.name}_{os.getpid()}"
    try:
        tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp_path, file_path)
        return backup_path
    except Exception:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except Exception:
                pass
        raise


def run_setup(dry_run: bool = False) -> int:
    """Execute the 'snow setup' command."""
    print("=" * 65)
    print("SNOW — Model Context Protocol (MCP) Setup Assistant")
    print("=" * 65)

    snow_entry = get_snow_mcp_config_entry()
    full_sample = {"mcpServers": {"snow": snow_entry}}

    print("\n[Canonical SNOW MCP Configuration]")
    print(json.dumps(full_sample, indent=2))

    if dry_run:
        print("\n[DRY RUN] No filesystem changes were made.")
        print(f"Target Claude Desktop path: {CLAUDE_CONFIG_PATH}")
        print("\nTo manually configure any MCP host, add the above snippet to its config.")
        return 0

    configured_any = False

    # Attempt Claude Desktop configuration
    target_path = CLAUDE_CONFIG_PATH
    try:
        existing_text = ""
        if target_path.exists():
            existing_text = target_path.read_text(encoding="utf-8")

        merged, warn = merge_mcp_config(existing_text, server_name="snow")
        if warn:
            print(f"\n[!] Warning for Claude Desktop config: {warn}")

        bak = atomic_write_json(target_path, merged, backup=True)
        print(f"\n[+] Successfully configured Claude Desktop at:")
        print(f"    {target_path}")
        if bak:
            print(f"    (Backup preserved at: {bak})")
        configured_any = True
    except Exception as exc:
        print(f"\n[-] Could not automatically write Claude Desktop config: {exc}")

    print("\n[Manual Setup Reference]")
    print("For Gemini CLI, Antigravity, Cursor, or other MCP clients, add:")
    print(json.dumps(full_sample, indent=2))

    return 0 if configured_any else 1


def run_status() -> int:
    """Execute the 'snow status' command."""
    manager = CoreDaemonManager()
    status_data = asyncio.run(manager.get_status())

    print("=" * 60)
    print("SNOW — System Status Overview")
    print("=" * 60)
    print(f"  Version:           0.1.0")
    print(f"  Daemon Running:    {'YES' if status_data['daemon_running'] else 'NO'}")
    print(f"  IPC Endpoint:      {'READY (online)' if status_data['ipc_ready'] else 'OFFLINE'}")
    if status_data.get("pid"):
        print(f"  Daemon PID:        {status_data['pid']}")
    print(f"  Loopback Bind:     {status_data['host']}:{status_data['port']}")
    print(f"  Daemon Log Path:   {status_data['log_path']}")
    print(f"  State Directory:   {get_snow_dir()}")

    claude_installed = CLAUDE_CONFIG_PATH.exists()
    print(f"  Claude MCP Config: {'Configured' if claude_installed else 'Not configured'}")
    print("=" * 60)
    return 0


def run_daemon_start() -> int:
    """Execute 'snow daemon start'."""
    manager = CoreDaemonManager()
    print("Starting background SNOW Desktop Core daemon...")
    res = asyncio.run(manager.ensure_core_running())

    if res.get("success"):
        pid_info = f" (PID {res['pid']})" if res.get("pid") else ""
        print(f"[+] SNOW Core is running{pid_info}.")
        print(f"    Status: {res.get('status')}")
        print(f"    Logs:   {get_daemon_log_path()}")
        return 0
    else:
        print(f"[-] Failed to start SNOW Core: {res.get('error')}")
        print(f"    Status: {res.get('status')}")
        return 1


def run_daemon_stop() -> int:
    """Execute 'snow daemon stop'."""
    manager = CoreDaemonManager()
    print("Stopping SNOW Desktop Core daemon...")
    res = asyncio.run(manager.stop_core())

    if res.get("success"):
        print(f"[+] {res.get('message', 'SNOW Core stopped.')}")
        return 0
    else:
        print(f"[-] Failed stopping SNOW Core: {res.get('error')}")
        return 1


def run_peer_trust(device_id: str, tier: str) -> int:
    """Configure trust tier for a paired device."""
    from snow.security.db import DatabaseManager
    clean_id = device_id.strip()
    clean_tier = tier.strip().lower()

    if clean_tier not in ("owner", "peer"):
        print(f"[-] Invalid tier '{tier}'. Must be 'owner' or 'peer'.")
        return 1

    db = DatabaseManager()
    device = db.get_paired_device(clean_id)
    if not device:
        print(f"[-] Device [{clean_id}] is not registered as a paired device.")
        return 1

    success = db.update_device_trust_tier(clean_id, clean_tier)
    if success:
        print(f"[+] Successfully updated device [{clean_id}] ({device.device_name}) trust tier to '{clean_tier}'.")
        return 0
    else:
        print(f"[-] Failed to update trust tier for device [{clean_id}].")
        return 1


def run_peer_list() -> int:
    """List paired peer devices and their trust tiers."""
    from snow.security.db import DatabaseManager
    db = DatabaseManager()
    devices = db.list_paired_devices()
    print("=" * 65)
    print(f"SNOW Paired Devices ({len(devices)} registered)")
    print("=" * 65)
    if not devices:
        print("  No devices paired.")
    for d in devices:
        print(f"  - [{d.device_id}] {d.device_name}")
        print(f"      Trust Tier:  {d.trust_tier.upper()}")
        print(f"      Paired At:   {d.pairing_timestamp}")
        print(f"      Last Seen:   {d.last_seen_timestamp}")
    print("=" * 65)
    return 0


def main(args: Optional[list[str]] = None) -> int:
    """CLI entry point for the 'snow' command."""
    parser = argparse.ArgumentParser(
        prog="snow",
        description="SNOW — Headless cross-device AI capability platform CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # setup
    setup_parser = subparsers.add_parser("setup", help="Configure SNOW as an MCP server")
    setup_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print configuration without making changes to disk",
    )

    # status
    subparsers.add_parser("status", help="Inspect live Core daemon and IPC status")

    # daemon
    daemon_parser = subparsers.add_parser("daemon", help="Manage background Core daemon")
    daemon_sub = daemon_parser.add_subparsers(dest="daemon_action", help="Daemon action")
    daemon_sub.add_parser("start", help="Start Core daemon in background")
    daemon_sub.add_parser("stop", help="Stop background Core daemon")

    # convenient aliases
    start_parser = subparsers.add_parser("start", help="Alias for daemon start")
    start_parser.add_argument("--daemon", action="store_true", default=True)
    subparsers.add_parser("stop", help="Alias for daemon stop")

    # peer
    peer_parser = subparsers.add_parser("peer", help="Manage paired peer devices and trust tiers")
    peer_sub = peer_parser.add_subparsers(dest="peer_action", help="Peer action")
    peer_sub.add_parser("list", help="List paired devices and their trust tiers")
    peer_trust = peer_sub.add_parser("trust", help="Configure trust tier for a paired device")
    peer_trust.add_argument("device_id", help="Device ID (UUID) of the paired device")
    peer_trust.add_argument("--tier", choices=["owner", "peer"], required=True, help="Trust tier (owner or peer)")

    parsed = parser.parse_args(args)

    if parsed.command == "setup":
        return run_setup(dry_run=parsed.dry_run)
    elif parsed.command == "status":
        return run_status()
    elif parsed.command == "daemon":
        if parsed.daemon_action == "start":
            return run_daemon_start()
        elif parsed.daemon_action == "stop":
            return run_daemon_stop()
        else:
            daemon_parser.print_help()
            return 1
    elif parsed.command == "peer":
        if parsed.peer_action == "trust":
            return run_peer_trust(parsed.device_id, parsed.tier)
        elif parsed.peer_action == "list":
            return run_peer_list()
        else:
            peer_parser.print_help()
            return 1
    elif parsed.command == "start":
        return run_daemon_start()
    elif parsed.command == "stop":
        return run_daemon_stop()
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
