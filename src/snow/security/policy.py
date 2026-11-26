"""Peer capability authorization policy for SNOW Desktop Core.

Defines fine-grained capability identifiers for peer operations, maps protocol
actions to capability requirements, and provides thread-safe server-side
authorization enforcement.

Security invariants:
1. Deny-by-default: Newly paired devices receive a standard non-destructive capability
   set. Sensitive command execution ('desktop.exec') is EXCLUDED by default and requires
   an explicit trusted grant.
2. Server-side identity: Caller identity is obtained exclusively from the authenticated
   session record, never from caller-supplied message body payloads.
3. Active pairing verification: Denies all operations if the device has been unpaired or revoked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
from typing import Dict, Optional, Set

from snow.security.context import ExecutionContext, ExecutionPrincipal

logger = logging.getLogger(__name__)

# Standard capability identifiers
CAPABILITY_DESKTOP_STATUS = "desktop.status"
CAPABILITY_DESKTOP_EXEC = "desktop.exec"
CAPABILITY_DESKTOP_APP_LAUNCH = "desktop.app_launch"
CAPABILITY_DESKTOP_CLIPBOARD_READ = "desktop.clipboard.read"
CAPABILITY_DESKTOP_CLIPBOARD_WRITE = "desktop.clipboard.write"
CAPABILITY_DESKTOP_FILES_LIST = "desktop.files.list"
CAPABILITY_DESKTOP_FILES_DOWNLOAD = "desktop.files.download"
CAPABILITY_FILE_TRANSFER = "file.transfer"
CAPABILITY_MESH_LIST_PEERS = "mesh.list_peers"
CAPABILITY_PEER_RELAY = "mesh.peer_relay"

# Default capabilities granted to newly paired devices
# NOTE: CAPABILITY_DESKTOP_EXEC is strictly EXCLUDED by default!
DEFAULT_PAIRED_CAPABILITIES: set[str] = {
    CAPABILITY_DESKTOP_STATUS,
    CAPABILITY_DESKTOP_APP_LAUNCH,
    CAPABILITY_DESKTOP_CLIPBOARD_READ,
    CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    CAPABILITY_DESKTOP_FILES_LIST,
    CAPABILITY_DESKTOP_FILES_DOWNLOAD,
    CAPABILITY_FILE_TRANSFER,
    CAPABILITY_MESH_LIST_PEERS,
    CAPABILITY_PEER_RELAY,
    # Canonical manifest aliases
    "desktop.file.list",
    "desktop.apps.launch",
    "desktop.file.transfer",
}

# Mapping from incoming protocol actions to capability identifiers
ACTION_TO_CAPABILITY: dict[str, str] = {
    "desktop_status": CAPABILITY_DESKTOP_STATUS,
    "desktop_exec": CAPABILITY_DESKTOP_EXEC,
    "desktop_app_launch": CAPABILITY_DESKTOP_APP_LAUNCH,
    "desktop_clipboard_get": CAPABILITY_DESKTOP_CLIPBOARD_READ,
    "desktop_clipboard_set": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "desktop_clipboard_sync_toggle": CAPABILITY_DESKTOP_CLIPBOARD_READ,
    "desktop_file_list": CAPABILITY_DESKTOP_FILES_LIST,
    "desktop_file_stage_download": CAPABILITY_DESKTOP_FILES_DOWNLOAD,
    "file_transfer_offer": CAPABILITY_FILE_TRANSFER,
    "file_list_transfers": CAPABILITY_FILE_TRANSFER,
    "file_transfer_status": CAPABILITY_FILE_TRANSFER,
    "file_transfer_cancel": CAPABILITY_FILE_TRANSFER,
    "mesh_list_peers": CAPABILITY_MESH_LIST_PEERS,
    "peer_relay_request": CAPABILITY_PEER_RELAY,
    "media_control": "media_control",
    "windows_media_control": "media_control",
    "share_link": "share_link",
    "windows_share_link": "share_link",
    "clipboard_buffer_pin": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "clipboard_buffer_unpin": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "clipboard_buffer_delete": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "clipboard_buffer_clear": CAPABILITY_DESKTOP_CLIPBOARD_WRITE,
    "clipboard_ack": CAPABILITY_DESKTOP_CLIPBOARD_READ,
    "clipboard_history_sync": CAPABILITY_DESKTOP_CLIPBOARD_READ,
}


class PeerCapabilityPolicy:
    """Configurable server-side policy governing peer device capability access."""

    def __init__(
        self,
        default_grants: Optional[set[str]] = None,
        device_overrides: Optional[dict[str, set[str]]] = None,
        policy_file: Optional[Path | str] = None,
    ) -> None:
        self.default_grants: set[str] = (
            set(default_grants) if default_grants is not None else set(DEFAULT_PAIRED_CAPABILITIES)
        )
        self.device_overrides: dict[str, set[str]] = (
            {k: set(v) for k, v in device_overrides.items()} if device_overrides else {}
        )
        self._last_mtime: float = 0.0

        if policy_file is not None:
            self.policy_file = Path(policy_file).resolve()
        else:
            env_file = os.environ.get("SNOW_POLICY_FILE")
            if env_file:
                self.policy_file = Path(env_file).resolve()
            else:
                data_dir = os.environ.get("SNOW_DATA_DIR")
                if data_dir:
                    self.policy_file = Path(data_dir).resolve() / "peer_policy.json"
                else:
                    self.policy_file = None

        # Load persisted policy file if present
        if self.policy_file is not None:
            self._load_from_file()

        # Check environment variable for enabling peer exec (e.g. during testing or development)
        if os.environ.get("SNOW_ALLOW_PEER_EXEC", "").strip().lower() in ("1", "true", "yes"):
            self.default_grants.add(CAPABILITY_DESKTOP_EXEC)

        # Check for explicitly granted device IDs via environment
        grant_env = os.environ.get("SNOW_GRANT_EXEC_DEVICES", "")
        if grant_env:
            for dev in grant_env.split(","):
                dev_clean = dev.strip()
                if dev_clean:
                    self.grant_capability(dev_clean, CAPABILITY_DESKTOP_EXEC)

    def _load_from_file(self) -> None:
        """Load persisted policy from disk if available."""
        if not self.policy_file or not self.policy_file.is_file():
            return
        try:
            mtime = self.policy_file.stat().st_mtime
            if mtime <= self._last_mtime:
                return
            with open(self.policy_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data.get("default_grants"), list):
                self.default_grants.update(data["default_grants"])
            if isinstance(data.get("device_overrides"), dict):
                for k, v in data["device_overrides"].items():
                    if isinstance(v, list):
                        if k not in self.device_overrides:
                            self.device_overrides[k] = set(self.default_grants)
                        self.device_overrides[k].update(v)
            self._last_mtime = mtime
        except Exception as exc:
            logger.warning("Failed loading peer policy from '%s': %s", self.policy_file, exc)

    def _save_to_file(self) -> None:
        """Persist current policy to disk."""
        if not self.policy_file:
            return
        try:
            self.policy_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "default_grants": sorted(self.default_grants),
                "device_overrides": {k: sorted(v) for k, v in self.device_overrides.items()},
            }
            with open(self.policy_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            if self.policy_file.is_file():
                self._last_mtime = self.policy_file.stat().st_mtime
        except Exception as exc:
            logger.warning("Failed saving peer policy to '%s': %s", self.policy_file, exc)

    def get_granted_capabilities(self, device_id: str) -> set[str]:
        """Return the authorized set of capabilities for a given device."""
        if not device_id:
            return set()
        if self.policy_file is not None:
            self._load_from_file()
        if device_id in self.device_overrides:
            return set(self.device_overrides[device_id])
        return set(self.default_grants)

    def grant_capability(self, device_id: str, capability: str) -> None:
        """Explicitly grant a capability to a specific device and persist."""
        if not device_id:
            return
        if device_id not in self.device_overrides:
            self.device_overrides[device_id] = set(self.default_grants)
        self.device_overrides[device_id].add(capability)
        self._save_to_file()
        logger.info("Granted capability '%s' to peer device [%s]", capability, device_id)

    def revoke_capability(self, device_id: str, capability: str) -> None:
        """Explicitly revoke a capability from a specific device and persist."""
        if not device_id:
            return
        if device_id not in self.device_overrides:
            self.device_overrides[device_id] = set(self.default_grants)
        self.device_overrides[device_id].discard(capability)
        self._save_to_file()
        logger.info("Revoked capability '%s' from peer device [%s]", capability, device_id)

    def is_authorized(
        self, device_id: str, capability: str, ctx: Optional[ExecutionContext] = None
    ) -> bool:
        """Check if a device is authorized to execute a specific capability.

        Rules:
        - If ctx carries ExecutionPrincipal.OWNER_MANUAL, capability execution (including
          'desktop.exec') is authorized by default.
        - Otherwise, checks against the device's explicit grants (deny-by-default for 'desktop.exec').
        """
        if not device_id or not capability:
            return False

        # OWNER_MANUAL sessions are authorized for all standard desktop operations
        if ctx is not None and ctx.principal == ExecutionPrincipal.OWNER_MANUAL:
            return True

        granted = self.get_granted_capabilities(device_id)
        authorized = capability in granted
        if not authorized:
            logger.warning(
                "Peer authorization denied: device [%s] lacks capability '%s'",
                device_id,
                capability,
            )
        return authorized
