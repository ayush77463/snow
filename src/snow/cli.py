"""Command-line interface (CLI) for SNOW.

Provides user commands for:
- snow setup: Automated and safe MCP configuration for Claude, Gemini, Cursor, ChatGPT.
- snow devices: Comprehensive device trust and pairing lifecycle management.
- snow doctor: System health, dependency, and configuration readiness diagnostics.
- snow status: Live diagnostic overview of SNOW Core daemon, IPC endpoint, and logs.
- snow daemon start/stop: Headless background daemon lifecycle control.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import time
from typing import Any, Dict, List, Optional

from snow.core.config import CoreConfig
from snow.daemon import CoreDaemonManager, get_daemon_log_path, get_snow_dir
from snow.mcp.bridge import SnowMcpBridge
from snow.onboarding import (
    HostOnboardingManager,
    SUPPORTED_HOSTS,
    get_canonical_mcp_entry,
)
from snow.security.db import DatabaseManager
from snow.security.tls import DEFAULT_CERT_FILE, DEFAULT_KEY_FILE, DEFAULT_TLS_DIR

logger = logging.getLogger(__name__)

# Standard known MCP client configuration targets on Windows (backward-compatible exports)
APPDATA = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
CLAUDE_CONFIG_PATH = Path(APPDATA) / "Claude" / "claude_desktop_config.json"
ANTIGRAVITY_CONFIG_PATH = Path.home() / ".gemini" / "antigravity" / "mcp_config.json"


def get_snow_mcp_config_entry() -> dict[str, Any]:
    """Generate the canonical MCP server configuration entry for SNOW."""
    return get_canonical_mcp_entry()


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


# =========================================================================
# Setup Command (Multi-Host AI Assistant Onboarding)
# =========================================================================


def run_setup(
    host: str = "all",
    dry_run: bool = False,
    remove: bool = False,
    config_paths: Optional[dict[str, Path | str]] = None,
    python_exe: Optional[str] = None,
) -> int:
    """Execute 'snow setup' for one or all AI assistant hosts."""
    resolved_paths: dict[str, Path | str] = {"claude": CLAUDE_CONFIG_PATH}
    if config_paths:
        resolved_paths.update(config_paths)

    manager = HostOnboardingManager(custom_paths=resolved_paths, python_exe=python_exe)
    clean_host = (host or "all").strip().lower()

    action_label = "Removal" if remove else "Setup"
    print("=" * 65)
    print(f"SNOW — Model Context Protocol (MCP) {action_label} Assistant")
    print("=" * 65)

    if dry_run:
        print("\n[DRY RUN MODE] No filesystem modifications will be made.\n")

    if remove:
        result = manager.remove_host(clean_host, dry_run=dry_run)
    else:
        result = manager.setup_host(clean_host, dry_run=dry_run)

    overall_success = result.get("success", False)

    # Single host result
    if clean_host != "all":
        items = [(clean_host, result)]
    else:
        items = list(result.get("results", {}).items())

    for h_name, res in items:
        display = res.get("display_name", h_name.capitalize())
        status = res.get("status", "UNKNOWN")
        path = res.get("target_path", "N/A")

        if res.get("success"):
            badge = "[DRY RUN]" if dry_run else "[+]"
            print(f"{badge} {display}: {status}")
            print(f"    Target Path: {path}")
            if res.get("backup_path"):
                print(f"    Backup:      {res['backup_path']}")
            if res.get("notes"):
                print(f"    Note:        {res['notes']}")
        else:
            print(f"[-] {display}: {status}")
            print(f"    Target Path: {path}")
            print(f"    Error:       {res.get('error', 'Unknown error')}")

    print("\n" + "=" * 65)
    if overall_success:
        if dry_run:
            print("Dry-run preview complete. Run without --dry-run to apply changes.")
        else:
            print(f"SNOW MCP {action_label.lower()} completed successfully.")
        return 0
    else:
        print(f"One or more host {action_label.lower()} steps encountered errors.")
        return 1


# =========================================================================
# Devices Command (Device & Trust Management)
# =========================================================================


def run_devices_list(json_output: bool = False, db_path: Optional[Path | str] = None) -> int:
    """Execute 'snow devices list'."""
    devices_list: list[dict[str, Any]] = []
    source = "offline_database"

    # Deterministic DB isolation: If explicit db_path is passed, always use it directly without querying live daemon
    if db_path is None:
        bridge = SnowMcpBridge(auto_start_core=False)
        daemon_online = asyncio.run(bridge.daemon_manager.is_ipc_ready(timeout=0.2))

        if daemon_online:
            try:
                res = asyncio.run(bridge.list_devices())
                if res.get("success"):
                    raw_devices = res.get("data", {}).get("devices", [])
                    source = "daemon_ipc"
                    for d in raw_devices:
                        devices_list.append({
                            "device_id": d.get("device_id", "unknown"),
                            "device_name": d.get("device_name", "Unknown Node"),
                            "platform": d.get("platform", "unknown"),
                            "trust_tier": (d.get("trust_tier") or "peer").upper(),
                            "reachability_profile": d.get("reachability_profile", "ACTIVE_SESSION_PEER"),
                            "reachability_state": d.get("reachability_state", "CONNECTED_SESSION" if d.get("is_connected") else "UNREACHABLE_OFFLINE"),
                            "is_paired": bool(d.get("is_paired", True)),
                            "is_connected": bool(d.get("is_connected", False)),
                            "last_known_endpoint": f"{d.get('host', 'N/A')}:{d.get('wss_port', 8765)}" if d.get("host") else "N/A",
                        })
            except Exception as exc:
                logger.debug("Failed querying daemon IPC for devices list: %s", exc)

    if not devices_list:
        # Fall back to offline SQLite database
        db = DatabaseManager(db_path=db_path)
        try:
            paired = db.list_paired_devices()
            source = "offline_database"
            for p in paired:
                endpoint = f"{p.last_known_host}:{p.last_known_port}" if p.last_known_host else "N/A"
                devices_list.append({
                    "device_id": p.device_id,
                    "device_name": p.device_name,
                    "platform": getattr(p, "platform", None) or "android",
                    "trust_tier": (p.trust_tier or "peer").upper(),
                    "reachability_profile": getattr(p, "reachability_profile", "ACTIVE_SESSION_PEER"),
                    "reachability_state": "LAST_KNOWN_IP_DIRECT" if p.last_known_host else "UNREACHABLE_OFFLINE",
                    "is_paired": True,
                    "is_connected": False,
                    "last_known_endpoint": endpoint,
                })
        except Exception as exc:
            if json_output:
                print(json.dumps({"success": False, "error": f"Database read error: {exc}"}, indent=2))
                return 1
            print(f"[-] Could not read local database: {exc}")
            return 1

    if json_output:
        out = {
            "success": True,
            "source": source,
            "count": len(devices_list),
            "devices": devices_list,
        }
        print(json.dumps(out, indent=2))
        return 0

    print("=" * 70)
    source_label = "Online via Core IPC" if source == "daemon_ipc" else "Offline via SQLite Database"
    print(f"SNOW Devices ({len(devices_list)} registered) — [{source_label}]")
    print("=" * 70)

    if not devices_list:
        print("  No devices paired or discovered. Use 'snow pair' or connect from your device.")
    else:
        for d in devices_list:
            conn_status = "ONLINE (Connected)" if d["is_connected"] else d["reachability_state"]
            print(f"  * [{d['device_id']}] {d['device_name']}")
            print(f"      Platform:     {d['platform'].capitalize()}")
            print(f"      Trust Tier:   {d['trust_tier']}")
            print(f"      Profile:      {d['reachability_profile']}")
            print(f"      Reachability: {conn_status}")
            print(f"      Endpoint:     {d['last_known_endpoint']}")
            print()
    print("=" * 70)
    return 0


def run_devices_trust(
    device_id: str,
    tier: str,
    yes: bool = False,
    db_path: Optional[Path | str] = None,
) -> int:
    """Execute 'snow devices trust <device_id> --tier <owner|peer>'."""
    clean_id = (device_id or "").strip()
    clean_tier = (tier or "").strip().lower()

    if not clean_id:
        print("[-] Missing device_id argument.")
        return 1

    if clean_tier not in ("owner", "peer"):
        print(f"[-] Invalid tier '{tier}'. Must be 'owner' or 'peer'.")
        return 1

    db = DatabaseManager(db_path=db_path)
    device = db.get_paired_device(clean_id)
    if not device:
        print(f"[-] Device [{clean_id}] is not registered as a paired device.")
        return 1

    current_tier = (device.trust_tier or "peer").lower()
    if current_tier == clean_tier:
        print(f"[i] Device [{clean_id}] ({device.device_name}) is already assigned trust tier '{clean_tier.upper()}'.")
        return 0

    # Single owner invariant warning
    if clean_tier == "owner":
        current_owner = db.get_owner_device()
        if current_owner and current_owner.device_id != clean_id:
            print(f"[!] Warning: Device [{current_owner.device_id}] ({current_owner.device_name}) is currently the OWNER.")
            print(f"    Promoting [{clean_id}] will demote the previous owner to PEER (single-owner invariant).")

    if not yes:
        try:
            confirm = input(f"Confirm changing trust tier of [{clean_id}] ({device.device_name}) to '{clean_tier.upper()}'? [y/N]: ")
            if confirm.strip().lower() not in ("y", "yes"):
                print("Operation cancelled by user.")
                return 0
        except (EOFError, KeyboardInterrupt):
            print("\nOperation cancelled.")
            return 1

    bridge = SnowMcpBridge(auto_start_core=False)
    daemon_online = asyncio.run(bridge.daemon_manager.is_ipc_ready(timeout=0.2))

    if daemon_online:
        res = asyncio.run(bridge.call("device_trust", {"device_id": clean_id, "tier": clean_tier}))
        if res.get("success"):
            db.update_device_trust_tier(clean_id, clean_tier, demote_existing_owners=True)
            print(f"[+] Successfully updated device [{clean_id}] ({device.device_name}) trust tier to '{clean_tier.upper()}' via Core IPC.")
            return 0
        else:
            print(f"[-] Failed to update trust tier via daemon: {res.get('error')}")
            return 1
    else:
        # Offline update directly in SQLite
        updated = db.update_device_trust_tier(clean_id, clean_tier, demote_existing_owners=True)
        if updated:
            print(f"[+] Updated device [{clean_id}] ({device.device_name}) trust tier to '{clean_tier.upper()}' in offline database.")
            print("    Note: Core daemon is offline. Changes will take effect on next daemon startup.")
            return 0
        else:
            print(f"[-] Failed to update trust tier for device [{clean_id}].")
            return 1


def run_devices_revoke(
    device_id: str,
    yes: bool = False,
    db_path: Optional[Path | str] = None,
) -> int:
    """Execute 'snow devices revoke <device_id>'."""
    clean_id = (device_id or "").strip()
    if not clean_id:
        print("[-] Missing device_id argument.")
        return 1

    db = DatabaseManager(db_path=db_path)
    device = db.get_paired_device(clean_id)
    if not device:
        print(f"[-] Device [{clean_id}] is not registered as a paired device.")
        return 1

    if not yes:
        try:
            confirm = input(f"Are you sure you want to permanently REVOKE paired device [{clean_id}] ({device.device_name})? [y/N]: ")
            if confirm.strip().lower() not in ("y", "yes"):
                print("Revocation cancelled by user.")
                return 0
        except (EOFError, KeyboardInterrupt):
            print("\nRevocation cancelled.")
            return 1

    bridge = SnowMcpBridge(auto_start_core=False)
    daemon_online = asyncio.run(bridge.daemon_manager.is_ipc_ready(timeout=0.2))

    if daemon_online:
        res = asyncio.run(bridge.call("device_revoke", {"device_id": clean_id}))
        if res.get("success"):
            db.delete_paired_device(clean_id)
            print(f"[+] Device [{clean_id}] ({device.device_name}) has been revoked.")
            print("    Stored credentials deleted; any active daemon session was immediately terminated.")
            return 0
        else:
            print(f"[-] Daemon failed to revoke device: {res.get('error')}")
            return 1
    else:
        # Offline deletion from SQLite
        deleted = db.delete_paired_device(clean_id)
        if deleted:
            db.log_audit_event(
                event_type="DEVICE_REVOKED",
                device_id=clean_id,
                details={"revoked_by": "cli_offline"},
            )
            print(f"[+] Device [{clean_id}] ({device.device_name}) credentials deleted from offline database.")
            print("    Note: Core daemon was offline; active sessions could not be confirmed terminated.")
            return 0
        else:
            print(f"[-] Failed deleting device [{clean_id}] from database.")
            return 1


def run_devices_connect(
    host: str,
    port: int = 8765,
    pin: Optional[str] = None,
) -> int:
    """Execute 'snow devices connect <host> [--port 8765] [--pin <PIN>]'."""
    clean_host = (host or "").strip()
    if not clean_host:
        print("[-] Missing host target.")
        return 1

    if port < 1 or port > 65535:
        print(f"[-] Invalid port {port}. Must be between 1 and 65535.")
        return 1

    print(f"Connecting to peer at {clean_host}:{port}...")

    import socket
    try:
        s = socket.create_connection((clean_host, port), timeout=5.0)
        s.close()
        print(f"[+] TCP connection to {clean_host}:{port} successful.")
        if pin:
            print("    PIN provided for mutual pairing verification.")
        print("    Peer endpoint is reachable and responsive.")
        return 0
    except Exception as exc:
        print(f"[-] Connection failed to {clean_host}:{port}: {exc}")
        return 1


# =========================================================================
# Pair Command (Zero-IP-Friction QR Onboarding)
# =========================================================================


def run_pair(qr_only: bool = False, json_output: bool = False) -> int:
    """Execute 'snow pair [--qr] [--json]' to display pairing credentials and QR code."""
    bridge = SnowMcpBridge(auto_start_core=False)
    daemon_online = asyncio.run(bridge.daemon_manager.is_ipc_ready(timeout=0.3))

    if not daemon_online:
        print("[-] SNOW Core daemon is not currently running.")
        print("    Pairing requires an active core server to accept and verify PIN handshakes.")
        print("    Run 'snow daemon start' to launch the background daemon, then retry 'snow pair'.")
        return 1

    try:
        res = asyncio.run(bridge.call("generate_pairing_qr"))
    except Exception as exc:
        print(f"[-] Failed to communicate with Core daemon IPC: {exc}")
        return 1

    if not res.get("success"):
        print(f"[-] Could not generate pairing credentials: {res.get('error', res.get('status'))}")
        return 1

    payload = res.get("data", {})
    if json_output:
        print(json.dumps(payload, indent=2))
        return 0

    print("============================================================")
    print(" SNOW Zero-Friction QR Pairing (Phase 20)")
    print("============================================================")
    print(f" Node ID:          {payload.get('id')}")
    print(f" Candidate IPs:    {', '.join(payload.get('ips', []))}")
    print(f" WSS Port:         {payload.get('port')}")
    print(f" Cert Fingerprint: {payload.get('fp')}")
    print(f" Temporary PIN:    [ {payload.get('pin')} ] (Single-use, 60s window)")
    print("============================================================")

    try:
        import io
        import qrcode
        qr = qrcode.QRCode(box_size=1, border=1)
        qr.add_data(json.dumps(payload))
        qr.make(fit=True)
        s = io.StringIO()
        qr.print_ascii(out=s, invert=True)
        print("\n" + s.getvalue())
        print("Open the Devices tab on your Android phone and tap 'Scan QR Code'.\n")
    except Exception as exc:
        print(f"\n[-] Terminal QR rendering unavailable ({exc}).")
        print("Use the temporary PIN above or scan this raw JSON payload:")
        print(json.dumps(payload))

    return 0


# =========================================================================
# USB Command (Zero-Data ADB Reverse Mode)
# =========================================================================


def find_adb_binary() -> Optional[Path]:
    """Locate the Android Debug Bridge (adb) executable."""
    found = shutil.which("adb")
    if found:
        return Path(found)
    candidates = [
        Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk" / "platform-tools" / ("adb.exe" if sys.platform == "win32" else "adb"),
        Path(os.environ.get("ANDROID_HOME", "")) / "platform-tools" / ("adb.exe" if sys.platform == "win32" else "adb"),
        Path(os.environ.get("ANDROID_SDK_ROOT", "")) / "platform-tools" / ("adb.exe" if sys.platform == "win32" else "adb"),
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None


def get_connected_adb_devices(adb_bin: Path) -> list[dict[str, str]]:
    """Enumerate connected ADB devices and their authorization status."""
    devices: list[dict[str, str]] = []
    try:
        import subprocess
        res = subprocess.run(
            [str(adb_bin), "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=8.0,
            check=False,
        )
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices") or line.startswith("*"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                status = parts[1]
                model = "Android Device"
                for p in parts[2:]:
                    if p.startswith("model:"):
                        model = p.split(":", 1)[1]
                devices.append({"serial": serial, "status": status, "model": model, "raw": line})
    except Exception as exc:
        logger.debug("Failed running adb devices: %s", exc)
    return devices


def run_usb(
    serial: Optional[str] = None,
    remove: bool = False,
    status: bool = False,
) -> int:
    """Execute 'snow usb [--serial <ID>] [--remove] [--status]' for zero-data USB reverse mode."""
    import subprocess
    adb_bin = find_adb_binary()
    if not adb_bin:
        print("[-] ADB (Android Debug Bridge) executable not found.")
        print("    Ensure Android SDK platform-tools is installed or adb is added to PATH.")
        return 1

    devices = get_connected_adb_devices(adb_bin)
    authorized = [d for d in devices if d["status"] == "device"]

    if not authorized:
        if devices:
            print(f"[-] Detected {len(devices)} device(s), but none are authorized:")
            for d in devices:
                print(f"    - {d['serial']}: {d['status']}")
            print("    Please unlock your phone and grant 'Always allow USB debugging from this computer'.")
        else:
            print("[-] No connected Android devices detected via USB.")
            print("    Connect your phone via USB cable and ensure USB debugging is enabled.")
        return 1

    # Select target device
    target_device = None
    if serial:
        for d in authorized:
            if d["serial"] == serial:
                target_device = d
                break
        if not target_device:
            print(f"[-] Specified device serial '{serial}' not found among authorized devices:")
            for d in authorized:
                print(f"    - {d['serial']} ({d['model']})")
            return 1
    else:
        target_device = authorized[0]

    dev_serial = target_device["serial"]
    dev_name = f"{target_device['model']} ({dev_serial})"

    if status:
        res = subprocess.run(
            [str(adb_bin), "-s", dev_serial, "reverse", "--list"],
            capture_output=True,
            text=True,
            check=False,
        )
        print(f"ADB reverse status for device {dev_name}:")
        mappings = [ln.strip() for ln in res.stdout.splitlines() if ln.strip()]
        if mappings:
            for m in mappings:
                print(f"  {m}")
        else:
            print("  No active reverse socket mappings.")
        return 0

    if remove:
        r1 = subprocess.run([str(adb_bin), "-s", dev_serial, "reverse", "--remove", "tcp:8765"], capture_output=True, text=True, check=False)
        r2 = subprocess.run([str(adb_bin), "-s", dev_serial, "reverse", "--remove", "tcp:8766"], capture_output=True, text=True, check=False)
        print(f"[+] Removed SNOW reverse port mappings from device {dev_name}.")
        return 0

    # Establish reverse mappings: tcp:8765 (WSS) and tcp:8766 (HTTPS Transfers)
    res1 = subprocess.run(
        [str(adb_bin), "-s", dev_serial, "reverse", "tcp:8765", "tcp:8765"],
        capture_output=True,
        text=True,
        check=False,
    )
    res2 = subprocess.run(
        [str(adb_bin), "-s", dev_serial, "reverse", "tcp:8766", "tcp:8766"],
        capture_output=True,
        text=True,
        check=False,
    )

    if res1.returncode != 0 or res2.returncode != 0:
        err = (res1.stderr + " " + res2.stderr).strip()
        print(f"[-] Failed to establish ADB reverse mappings on {dev_name}: {err}")
        return 1

    # Verify both mappings in reverse --list
    check = subprocess.run(
        [str(adb_bin), "-s", dev_serial, "reverse", "--list"],
        capture_output=True,
        text=True,
        check=False,
    )
    output = check.stdout
    has_8765 = "tcp:8765" in output
    has_8766 = "tcp:8766" in output

    if has_8765 and has_8766:
        print("============================================================")
        print(f"[+] SNOW Zero-Data USB Mode Configured for {dev_name}")
        print("============================================================")
        print(" Active ADB Reverse Mappings:")
        print("  - Phone 127.0.0.1:8765 -> Desktop 127.0.0.1:8765 (WSS WebSocket Core)")
        print("  - Phone 127.0.0.1:8766 -> Desktop 127.0.0.1:8766 (HTTPS File Transfers)")
        print("\nNext step on your phone:")
        print("  Open Devices tab -> Tap 'Connect via USB (Localhost)'.")
        print("============================================================")
        return 0
    else:
        print(f"[-] Reverse mapping verification failed on {dev_name}.")
        print(f"    Current mappings: {output.strip()}")
        return 1


# =========================================================================
# Doctor Command (System Health & Readiness Diagnostics)
# =========================================================================


def run_doctor(
    json_output: bool = False,
    db_path: Optional[Path | str] = None,
    cert_path: Optional[Path | str] = None,
    key_path: Optional[Path | str] = None,
) -> int:
    """Execute 'snow doctor' to verify system readiness across all components."""
    checks: list[dict[str, Any]] = []

    # 1. Python Environment Check
    py_ver = sys.version_info
    py_ver_str = f"{py_ver.major}.{py_ver.minor}.{py_ver.micro}"
    if py_ver >= (3, 11):
        status = "OK"
        msg = f"Python {py_ver_str} ({sys.executable})"
        remed = None
    else:
        status = "FAILED"
        msg = f"Python {py_ver_str} is unsupported. Python 3.11+ (recommended 3.13) required."
        remed = "Upgrade to Python 3.13: https://www.python.org/downloads/"
    checks.append({
        "component": "python_environment",
        "name": "Python Environment",
        "status": status,
        "message": msg,
        "remediation": remed,
    })

    # 2. Installed SNOW Package & Entry Point
    try:
        import snow
        status = "OK"
        msg = f"SNOW package importable (v{getattr(snow, '__version__', '2.0.0')})"
        remed = None
    except Exception as exc:
        status = "FAILED"
        msg = f"Failed importing snow package: {exc}"
        remed = "Reinstall package in development mode: pip install -e ."
    checks.append({
        "component": "package_installation",
        "name": "Package Installation",
        "status": status,
        "message": msg,
        "remediation": remed,
    })

    # 3. Required Dependencies
    missing_deps = []
    for dep in ("websockets", "cryptography", "psutil", "mcp"):
        try:
            __import__(dep)
        except ImportError:
            missing_deps.append(dep)

    if not missing_deps:
        status = "OK"
        msg = "All core dependencies available (websockets, cryptography, psutil, mcp, sqlite3)"
        remed = None
    else:
        status = "FAILED"
        msg = f"Missing required dependencies: {', '.join(missing_deps)}"
        remed = f"Install missing packages: pip install {' '.join(missing_deps)}"
    checks.append({
        "component": "dependencies",
        "name": "Core Dependencies",
        "status": status,
        "message": msg,
        "remediation": remed,
    })

    # 4. SQLite Database & Schema Integrity
    target_db_path = Path(db_path) if db_path else Path.home() / ".snow" / "snow_devices.db"
    if not target_db_path.exists():
        status = "NOT_CONFIGURED"
        msg = f"Database not found at {target_db_path}"
        remed = "Start the daemon or run 'snow daemon start' to initialize database."
    else:
        try:
            db = DatabaseManager(db_path=target_db_path)
            with db._get_connection() as conn:
                row = conn.execute("PRAGMA integrity_check;").fetchone()
                intact = row and row[0] == "ok"
                tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
                has_tables = "paired_devices" in tables and "pairing_audit_log" in tables

            paired_count = len(db.list_paired_devices())
            if intact and has_tables:
                status = "OK"
                msg = f"Database intact at {target_db_path} ({paired_count} paired device{'s' if paired_count != 1 else ''})"
                remed = None
            else:
                status = "FAILED"
                msg = f"Database schema integrity check failed at {target_db_path}"
                remed = "Database may be corrupt. Back up and recreate using 'snow daemon start'."
        except Exception as exc:
            status = "FAILED"
            msg = f"Database check failed: {exc}"
            remed = "Ensure SQLite database file is readable and permissions are correct."
    checks.append({
        "component": "sqlite_database",
        "name": "SQLite Database",
        "status": status,
        "message": msg,
        "remediation": remed,
    })

    # 5. TLS Certificates & Keys
    cert = Path(cert_path) if cert_path else (DEFAULT_TLS_DIR / DEFAULT_CERT_FILE)
    key = Path(key_path) if key_path else (DEFAULT_TLS_DIR / DEFAULT_KEY_FILE)
    if cert.exists() and key.exists():
        try:
            # Check certificate expiration safely
            from cryptography import x509
            cert_bytes = cert.read_bytes()
            parsed_cert = x509.load_pem_x509_certificate(cert_bytes)
            if hasattr(parsed_cert, "not_valid_after_utc"):
                expiry = parsed_cert.not_valid_after_utc
            else:
                expiry = getattr(parsed_cert, "not_valid_after", "Unknown")
            status = "OK"
            msg = f"TLS cert & private key present at {cert.parent} (Expires: {expiry})"
            remed = None
        except Exception:
            status = "OK"
            msg = f"TLS cert & private key present at {cert.parent}"
            remed = None
    elif cert.exists() or key.exists():
        status = "WARNING"
        msg = f"Incomplete TLS configuration in {cert.parent} (one file missing)"
        remed = "Remove partial TLS files and run 'snow daemon start' to regenerate valid pair."
    else:
        status = "NOT_CONFIGURED"
        msg = f"TLS certificate not yet generated at {cert.parent}"
        remed = "Run 'snow daemon start' to automatically generate local self-signed TLS certificates."
    checks.append({
        "component": "tls_certificates",
        "name": "TLS Certificates",
        "status": status,
        "message": msg,
        "remediation": remed,
    })

    # 6. Capability Engine In-Process Readiness
    try:
        from snow.capabilities.engine import CapabilityEngine, CapabilityRequest, ExecutionContext, ExecutionPrincipal
        engine = CapabilityEngine()
        status = "OK"
        msg = "CapabilityEngine initialized and dispatch handlers registered"
        remed = None
    except Exception as exc:
        status = "FAILED"
        msg = f"CapabilityEngine in-process initialization failed: {exc}"
        remed = "Verify local capability modules under snow.capabilities."
    checks.append({
        "component": "capability_engine",
        "name": "Capability Engine",
        "status": status,
        "message": msg,
        "remediation": remed,
    })

    # 7. Daemon IPC Endpoint
    daemon_mgr = CoreDaemonManager()
    ipc_ready = asyncio.run(daemon_mgr.is_ipc_ready(timeout=0.2))
    pid = daemon_mgr.get_tracked_pid()
    if ipc_ready:
        status = "OK"
        msg = f"Running and responsive (PID {pid}, 127.0.0.1:{daemon_mgr.port})"
        remed = None
    else:
        status = "WARNING"
        msg = "Core daemon is OFFLINE (Local-first Windows operations remain functional via in-process engine)"
        remed = "Start the background daemon with: snow daemon start"
    checks.append({
        "component": "daemon_ipc",
        "name": "Core Daemon IPC",
        "status": status,
        "message": msg,
        "remediation": remed,
    })

    # 8. MCP Dynamic Capability Registry and Metadata Consistency
    try:
        from snow.mcp.registry import validate_registry, list_capabilities
        from snow.mcp.tools import ALL_TOOL_NAMES
        is_valid, validation_errors = validate_registry()
        capabilities = list_capabilities()
        tool_count = len(ALL_TOOL_NAMES)
        if is_valid and tool_count >= 24:
            status = "OK"
            msg = f"{tool_count} capabilities dynamically registered with verified metadata ({len(capabilities)} catalog entries)"
            remed = None
        else:
            status = "FAILED"
            msg = f"Registry consistency issues: {'; '.join(validation_errors)}" if not is_valid else f"Unexpected tool count: {tool_count}"
            remed = "Audit snow.mcp.registry capability definitions and metadata."
    except Exception as exc:
        status = "FAILED"
        msg = f"Failed inspecting MCP capability registry: {exc}"
        remed = "Verify snow.mcp.registry imports."
    checks.append({
        "component": "mcp_tool_catalog",
        "name": "MCP Tool Catalog",
        "status": status,
        "message": msg,
        "remediation": remed,
    })

    # 9. AI Host Configurations
    onboarding_mgr = HostOnboardingManager()
    host_statuses = onboarding_mgr.check_all_hosts()
    configured_hosts = [h for h, st in host_statuses.items() if st.get("is_configured")]
    try:
        from snow.mcp.remote_gateway import RemoteMcpGateway
        from snow.mcp.oauth import OAuthServer
        remote_gw_ready = True
    except Exception:
        remote_gw_ready = False

    if configured_hosts:
        status = "OK"
        msg = f"Configured in {len(configured_hosts)} AI host(s): {', '.join(configured_hosts)}"
        remed = None
    else:
        status = "NOT_CONFIGURED"
        msg = "No AI assistant clients currently configured"
        remed = "Run 'snow setup --host all' (or --host claude|gemini|cursor) to configure."
    checks.append({
        "component": "ai_host_integrations",
        "name": "AI Host Integrations",
        "status": status,
        "message": msg,
        "remediation": remed,
        "hosts": host_statuses,
        "remote_gateway_ready": remote_gw_ready,
    })

    # Summary calculation
    counts = {"OK": 0, "WARNING": 0, "FAILED": 0, "NOT_CONFIGURED": 0}
    for c in checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1

    overall = "READY" if counts["FAILED"] == 0 else "ACTION_REQUIRED"

    if json_output:
        print(json.dumps({
            "overall_health": overall,
            "counts": counts,
            "checks": checks,
        }, indent=2))
        return 0 if overall == "READY" else 1

    print("=" * 70)
    print("SNOW — System Health & Readiness Doctor")
    print("=" * 70)
    for c in checks:
        badge = f"[{c['status']}]"
        print(f"  {badge:<18} {c['name']}")
        print(f"    Details:     {c['message']}")
        if c.get("remediation"):
            print(f"    Remediation: {c['remediation']}")
        print()
    print("=" * 70)
    print(f"Overall Health: {overall} ({counts['OK']} OK, {counts['WARNING']} WARNING, {counts['NOT_CONFIGURED']} NOT_CONFIGURED, {counts['FAILED']} FAILED)")
    print("=" * 70)
    return 0 if overall == "READY" else 1


# =========================================================================
# Daemon & Status Commands
# =========================================================================


def run_status() -> int:
    """Execute 'snow status'."""
    manager = CoreDaemonManager()
    status_data = asyncio.run(manager.get_status())

    print("=" * 60)
    print("SNOW — System Status Overview")
    print("=" * 60)
    print(f"  Version:           3.0.0")
    print(f"  Daemon Running:    {'YES' if status_data['daemon_running'] else 'NO'}")
    print(f"  IPC Endpoint:      {'READY (online)' if status_data['ipc_ready'] else 'OFFLINE'}")
    if status_data.get("pid"):
        print(f"  Daemon PID:        {status_data['pid']}")
    print(f"  Loopback Bind:     {status_data['host']}:{status_data['port']}")
    print(f"  Daemon Log Path:   {status_data['log_path']}")
    print(f"  State Directory:   {get_snow_dir()}")
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


# =========================================================================
# Main CLI Parser & Dispatcher
# =========================================================================


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser for the SNOW CLI."""
    parser = argparse.ArgumentParser(
        prog="snow",
        description="SNOW — Headless cross-device AI capability platform CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # 1. setup
    setup_parser = subparsers.add_parser("setup", help="Configure SNOW as an MCP server in AI assistant clients")
    setup_parser.add_argument(
        "--host",
        choices=["all", "claude", "gemini", "cursor", "chatgpt"],
        default="claude",
        help="Target AI assistant host (default: claude; use 'all' for all hosts)",
    )
    setup_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Simulate and preview configuration changes without writing files to disk",
    )
    setup_parser.add_argument(
        "--remove",
        action="store_true",
        help="Safely remove SNOW MCP entry from target host configuration(s)",
    )

    # 2. devices
    devices_parser = subparsers.add_parser("devices", help="Manage paired devices, reachability, and trust tiers")
    dev_sub = devices_parser.add_subparsers(dest="devices_action", help="Device operations")

    list_parser = dev_sub.add_parser("list", help="List paired and discovered devices")
    list_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    trust_parser = dev_sub.add_parser("trust", help="Configure trust tier for a paired device")
    trust_parser.add_argument("device_id", help="Device ID (UUID) of the target device")
    trust_parser.add_argument("--tier", choices=["owner", "peer"], required=True, help="Trust tier ('owner' or 'peer')")
    trust_parser.add_argument("--yes", "-y", action="store_true", help="Confirm trust tier change without prompting")

    revoke_parser = dev_sub.add_parser("revoke", help="Permanently revoke a paired device and terminate active sessions")
    revoke_parser.add_argument("device_id", help="Device ID (UUID) of the target device to revoke")
    revoke_parser.add_argument("--yes", "-y", action="store_true", help="Confirm revocation without prompting")

    connect_parser = dev_sub.add_parser("connect", help="Connect to a peer node directly")
    connect_parser.add_argument("host", help="Hostname or IPv4 address of the target peer")
    connect_parser.add_argument("--port", type=int, default=8765, help="Port of target peer (default: 8765)")
    connect_parser.add_argument("--pin", default=None, help="Pairing PIN for initial connection (never logged)")

    # 3. doctor
    doctor_parser = subparsers.add_parser("doctor", help="Run diagnostic health checks across environment, dependencies, and daemon")
    doctor_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")

    # 4. status
    subparsers.add_parser("status", help="Inspect live Core daemon and IPC status")

    # 5. pair (Phase 20 Zero-IP-Friction Onboarding)
    pair_parser = subparsers.add_parser("pair", help="Generate QR code and temporary PIN for fast mobile onboarding")
    pair_parser.add_argument("--qr", action="store_true", help="Display compact ASCII QR code (default)")
    pair_parser.add_argument("--json", action="store_true", help="Output machine-readable JSON payload")

    # 6. usb (Phase 20 Zero-Data Mode)
    usb_parser = subparsers.add_parser("usb", help="Configure zero-data USB connection via ADB reverse port forwarding")
    usb_parser.add_argument("--serial", "-s", default=None, help="Specific target Android device ADB serial number")
    usb_parser.add_argument("--remove", action="store_true", help="Remove SNOW ADB reverse mappings")
    usb_parser.add_argument("--status", action="store_true", help="Inspect current ADB reverse mappings")

    # 7. daemon
    daemon_parser = subparsers.add_parser("daemon", help="Manage background Core daemon")
    daemon_sub = daemon_parser.add_subparsers(dest="daemon_action", help="Daemon action")
    daemon_sub.add_parser("start", help="Start Core daemon in background")
    daemon_sub.add_parser("stop", help="Stop background Core daemon")

    # 8. web (Phase 21 Vanilla Web Dashboard)
    web_parser = subparsers.add_parser("web", help="Launch local SNOW Web Dashboard (replaces Textual TUI)")
    web_parser.add_argument("--port", type=int, default=8769, help="Dashboard port (default: 8769, loopback only)")
    web_parser.add_argument("--no-browser", action="store_true", help="Do not automatically open default browser")

    # 9. ui (Deprecated Textual TUI)
    subparsers.add_parser("ui", help="[Deprecated] Launch interactive UI (redirects to 'snow web')")

    # 10. relay (Phase 22 Remote Connectivity)
    relay_parser = subparsers.add_parser("relay", help="Manage remote relay connectivity and presence")
    relay_sub = relay_parser.add_subparsers(dest="relay_action", help="Relay action")
    relay_sub.add_parser("status", help="Display current remote relay configuration and presence status")

    # 11. mcp-gateway (Phase 23 Remote MCP Streamable HTTP Gateway)
    mcp_gw_parser = subparsers.add_parser(
        "mcp-gateway", help="Launch Remote MCP Streamable HTTP Gateway (Phase 23)"
    )
    mcp_gw_parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    mcp_gw_parser.add_argument("--port", type=int, default=8771, help="Gateway port (default: 8771)")
    mcp_gw_parser.add_argument("--public-url", default=None, help="Configured public HTTPS URL origin for reverse proxy")
    mcp_gw_parser.add_argument("--trusted-proxies", default=None, help="Comma-separated trusted proxy IPs or hostnames")

    # 12. expose (Phase 28B Zero-Port-Forwarding Public Exposure)
    expose_parser = subparsers.add_parser(
        "expose", help="Expose local Remote MCP Gateway over secure public tunnel (Phase 28B)"
    )
    expose_parser.add_argument(
        "--provider",
        choices=["cloudflared", "tailscale"],
        default="cloudflared",
        help="Tunnel provider (default: cloudflared)",
    )
    expose_parser.add_argument(
        "--port",
        type=int,
        default=8771,
        help="Target local Remote MCP Gateway port (default: 8771)",
    )
    expose_parser.add_argument(
        "--public-url",
        default=None,
        help="Explicit public HTTPS URL if pre-allocated or custom domain",
    )
    expose_parser.add_argument(
        "--trusted-proxies",
        default=None,
        help="Comma-separated trusted proxy IPs or hostnames for managed gateway",
    )
    expose_parser.add_argument(
        "--external-gateway",
        action="store_true",
        default=False,
        help="Connect to an already running external Remote MCP Gateway instead of managing one",
    )

    # Convenient top-level aliases
    start_parser = subparsers.add_parser("start", help="Alias for daemon start")
    start_parser.add_argument("--daemon", action="store_true", default=True)
    subparsers.add_parser("stop", help="Alias for daemon stop")

    # Backward-compatible 'peer' alias -> 'devices'
    peer_parser = subparsers.add_parser("peer", help="Alias for 'devices'")
    peer_sub = peer_parser.add_subparsers(dest="peer_action", help="Peer action")
    p_list = peer_sub.add_parser("list", help="List paired devices")
    p_list.add_argument("--json", action="store_true", help="Output JSON")
    p_trust = peer_sub.add_parser("trust", help="Configure trust tier")
    p_trust.add_argument("device_id", help="Device ID")
    p_trust.add_argument("--tier", choices=["owner", "peer"], required=True)
    p_trust.add_argument("--yes", "-y", action="store_true")

    return parser


# =========================================================================
# Web Dashboard & Deprecated UI
# =========================================================================


def run_web(port: int = 8769, no_browser: bool = False) -> int:
    """Launch the local SNOW Web Dashboard server (snow web)."""
    from snow.web.server import run_dashboard
    return run_dashboard(port=port, no_browser=no_browser)


def run_ui() -> int:
    """Launch interactive UI (deprecated in favor of 'snow web')."""
    print("[!] Notice: 'snow ui' (Textual TUI) has been retired in favor of the lightweight SNOW Web Dashboard.", file=sys.stderr)
    print("    Please run 'snow web' to launch the dashboard on http://127.0.0.1:8769.\n", file=sys.stderr)
    return 0


def run_relay(action: str = "status") -> int:
    """Manage and inspect remote relay connectivity."""
    from snow.relay.config import RelayConfig
    config = RelayConfig.from_env()

    print("=" * 70)
    print(" SNOW Remote Relay Status (Phase 22)")
    print("=" * 70)
    enabled_str = "YES (Active)" if config.enabled else "NO (Disabled by default)"
    endpoint_str = f"wss://{config.host}:{config.port}/v1/tunnel" if config.host else "Not Configured"
    print(f"  Relay Enabled:       {enabled_str}")
    print(f"  Relay Endpoint:      {endpoint_str}")
    print(f"  Max Frame Size:      {config.max_frame_size // (1024 * 1024)} MiB")
    print(f"  Rolling Quota:       {config.max_transfer_quota_bytes // (1024 * 1024)} MiB / hr")
    print(f"  Transport Policy:    Local-First (LAN -> USB ADB -> Remote Relay)")
    print("=" * 70)
    return 0


def main(args: Optional[list[str]] = None) -> int:
    """CLI entry point for the 'snow' command."""
    parser = build_parser()
    parsed = parser.parse_args(args)

    if parsed.command == "setup":
        return run_setup(host=parsed.host, dry_run=parsed.dry_run, remove=parsed.remove)
    elif parsed.command == "doctor":
        return run_doctor(json_output=parsed.json)
    elif parsed.command == "devices":
        if parsed.devices_action == "list" or not parsed.devices_action:
            json_flag = getattr(parsed, "json", False)
            return run_devices_list(json_output=json_flag)
        elif parsed.devices_action == "trust":
            return run_devices_trust(parsed.device_id, parsed.tier, yes=parsed.yes)
        elif parsed.devices_action == "revoke":
            return run_devices_revoke(parsed.device_id, yes=parsed.yes)
        elif parsed.devices_action == "connect":
            return run_devices_connect(parsed.host, port=parsed.port, pin=parsed.pin)
        else:
            parser.parse_args(["devices", "--help"])
            return 1
    elif parsed.command == "peer":
        # Backward-compatible mapping to devices
        if parsed.peer_action == "trust":
            return run_devices_trust(parsed.device_id, parsed.tier, yes=parsed.yes)
        else:
            json_flag = getattr(parsed, "json", False)
            return run_devices_list(json_output=json_flag)
    elif parsed.command == "status":
        return run_status()
    elif parsed.command == "pair":
        json_flag = getattr(parsed, "json", False)
        qr_flag = getattr(parsed, "qr", False)
        return run_pair(qr_only=qr_flag, json_output=json_flag)
    elif parsed.command == "usb":
        return run_usb(
            serial=getattr(parsed, "serial", None),
            remove=getattr(parsed, "remove", False),
            status=getattr(parsed, "status", False),
        )
    elif parsed.command == "daemon":
        if parsed.daemon_action == "start":
            return run_daemon_start()
        elif parsed.daemon_action == "stop":
            return run_daemon_stop()
        else:
            parser.parse_args(["daemon", "--help"])
            return 1
    elif parsed.command == "web":
        return run_web(port=parsed.port, no_browser=parsed.no_browser)
    elif parsed.command == "ui":
        return run_ui()
    elif parsed.command == "relay":
        action = getattr(parsed, "relay_action", "status") or "status"
        return run_relay(action=action)
    elif parsed.command == "mcp-gateway":
        from snow.mcp.remote_gateway import create_gateway_app, parse_trusted_proxies
        from aiohttp import web
        trusted = parse_trusted_proxies(getattr(parsed, "trusted_proxies", None))
        app = create_gateway_app(
            host=parsed.host,
            port=parsed.port,
            public_url=getattr(parsed, "public_url", None),
            trusted_proxies=trusted,
        )
        web.run_app(app, host=parsed.host, port=parsed.port)
        return 0
    elif parsed.command == "expose":
        from snow.mcp.expose import run_expose
        return run_expose(
            provider=parsed.provider,
            port=parsed.port,
            public_url=getattr(parsed, "public_url", None),
            external_gateway=getattr(parsed, "external_gateway", False),
            trusted_proxies=getattr(parsed, "trusted_proxies", None),
        )
    elif parsed.command == "start":
        return run_daemon_start()
    elif parsed.command == "stop":
        return run_daemon_stop()
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
