"""Platform-independent DeviceNode contract and CapabilityManifest for SNOW V2.

Defines the standard data model and capability advertisements for all participating
devices in the SNOW mesh (Windows desktop, Android smartphone, peer servers).

SECURITY BOUNDARY:
- Remote manifests are UNTRUSTED advertisements of claimed capabilities.
- Remote manifests NEVER establish, grant, or modify trust tiers or principal authority.
- The server/host derives authorization exclusively from its own authenticated session
  and authoritative local SQLite pairing database.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
import json
import logging
import platform
import time
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

MANIFEST_PROTOCOL_VERSION = "2.0"


class ReachabilityProfile(StrEnum):
    """Execution and availability profile of a participating device."""

    PERSISTENT_DAEMON = "PERSISTENT_DAEMON"      # Headless host daemon (Windows / Linux)
    ACTIVE_SESSION_PEER = "ACTIVE_SESSION_PEER"  # Battery/OS constrained client (Android default)
    FOREGROUND_HOST = "FOREGROUND_HOST"          # Explicitly enabled foreground server (Android host mode)


class ReachabilityState(StrEnum):
    """Dynamic network reachability state of a node."""

    CONNECTED_SESSION = "CONNECTED_SESSION"      # Active authenticated WSS connection (< 50ms)
    LAN_DISCOVERABLE = "LAN_DISCOVERABLE"        # Discovered via UDP beacon, socket not yet open
    LAST_KNOWN_IP_DIRECT = "LAST_KNOWN_IP_DIRECT"# Socket closed, last-known IP cached
    ONLINE_ROUTED = "ONLINE_ROUTED"              # Reachable through an authenticated peer relay node
    ONLINE_RELAYED = "ONLINE_RELAYED"            # Reachable through dedicated remote E2E relay tunnel
    DORMANT_RELAY = "DORMANT_RELAY"              # Known to remote relay but socket inactive
    UNREACHABLE_OFFLINE = "UNREACHABLE_OFFLINE"  # No socket and no beacon received for > 30s

    # Architectural aliases from docs/ARCHITECTURE_V2.md
    ONLINE_DIRECT = "CONNECTED_SESSION"
    DORMANT_REACHABLE = "LAN_DISCOVERABLE"
    OFFLINE = "UNREACHABLE_OFFLINE"


class CapabilityExecutionClassification(StrEnum):
    """Execution classification governing OS and UI constraints for a capability."""

    BACKGROUND_SAFE = "BACKGROUND_SAFE"
    RUNTIME_PERMISSION_REQUIRED = "RUNTIME_PERMISSION_REQUIRED"
    FOREGROUND_USER_INTERACTION_REQUIRED = "FOREGROUND_USER_INTERACTION_REQUIRED"


# Canonical capability identifiers
WINDOWS_CAPABILITIES: set[str] = {
    "desktop.status",
    "desktop.battery",
    "desktop.processes",
    "desktop.apps.launch",
    "desktop.file.read",
    "desktop.file.write",
    "desktop.file.list",
    "desktop.file.search",
    "desktop.exec",
    "desktop.clipboard.read",
    "desktop.clipboard.write",
    "desktop.file.transfer",
}

ANDROID_CAPABILITIES: set[str] = {
    "android.telemetry.get",
    "android.notifications.push",
    "android.clipboard.set",
    "android.clipboard.get",
    "android.apps.list",
    "android.apps.launch",
    "android.messaging.send_intent",
    "android.files.transfer",
    "android.ringer.ring",
}


# Capability aliases to ensure complete interoperability between protocol conventions
CAPABILITY_ALIASES: dict[str, str] = {
    "desktop.files.list": "desktop.file.list",
    "desktop.file.list": "desktop.files.list",
    "desktop.app_launch": "desktop.apps.launch",
    "desktop.apps.launch": "desktop.app_launch",
    "desktop.files.download": "desktop.file.transfer",
    "desktop.file.transfer": "desktop.files.download",
    "file.transfer": "desktop.file.transfer",
    "android.ring_phone": "android.ringer.ring",
    "android.ringer.ring": "android.ring_phone",
    "android.battery.get": "android.telemetry.get",
    "android.telemetry.get": "android.battery.get",
}


@dataclass
class CapabilityManifest:
    """Advertised capability and permission manifest for a participating device."""

    manifest_version: str = MANIFEST_PROTOCOL_VERSION
    supported_capabilities: list[str] = field(default_factory=list)
    permission_states: dict[str, str] = field(default_factory=dict)
    classifications: dict[str, str] = field(default_factory=dict)

    def supports_capability(self, capability: str) -> bool:
        """Return True if the capability (or its alias) is explicitly advertised."""
        if not capability or not isinstance(capability, str):
            return False
        clean = capability.strip()
        if clean in self.supported_capabilities:
            return True
        alias = CAPABILITY_ALIASES.get(clean)
        if alias and alias in self.supported_capabilities:
            return True
        return False

    def get_permission_state(self, capability: str) -> str:
        """Return the permission state for a capability (default: UNKNOWN)."""
        return self.permission_states.get(capability, "UNKNOWN")

    def is_background_safe(self, capability: str) -> bool:
        """Return True if capability is classified as safe for background execution."""
        return self.classifications.get(capability) == CapabilityExecutionClassification.BACKGROUND_SAFE

    def to_dict(self) -> dict[str, Any]:
        """Serialize manifest to dictionary."""
        return {
            "manifest_version": self.manifest_version,
            "supported_capabilities": list(self.supported_capabilities),
            "permission_states": dict(self.permission_states),
            "classifications": dict(self.classifications),
        }

    def to_json(self) -> str:
        """Serialize manifest to JSON string."""
        return json.dumps(self.to_dict(), separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def from_dict(cls, data: Any) -> CapabilityManifest:
        """Safely parse manifest from dictionary, rejecting malformed structures."""
        if not isinstance(data, dict):
            logger.warning("Invalid manifest data type: %s; returning empty manifest", type(data))
            return cls()

        v = str(data.get("manifest_version", MANIFEST_PROTOCOL_VERSION))
        raw_caps = data.get("supported_capabilities", [])
        caps: list[str] = []
        if isinstance(raw_caps, list):
            for c in raw_caps:
                if isinstance(c, str) and c.strip():
                    caps.append(c.strip())

        raw_perms = data.get("permission_states", {})
        perms: dict[str, str] = {}
        if isinstance(raw_perms, dict):
            for k, val in raw_perms.items():
                if isinstance(k, str) and isinstance(val, str):
                    perms[k.strip()] = val.strip()

        raw_class = data.get("classifications", {})
        classes: dict[str, str] = {}
        if isinstance(raw_class, dict):
            for k, val in raw_class.items():
                if isinstance(k, str) and isinstance(val, str):
                    classes[k.strip()] = val.strip()

        return cls(
            manifest_version=v,
            supported_capabilities=caps,
            permission_states=perms,
            classifications=classes,
        )

    @classmethod
    def from_json(cls, json_str: str) -> CapabilityManifest:
        """Parse manifest from JSON string."""
        try:
            parsed = json.loads(json_str)
            return cls.from_dict(parsed)
        except Exception as exc:
            logger.warning("Failed parsing capability manifest JSON: %s", exc)
            return cls()


def build_windows_manifest() -> CapabilityManifest:
    """Build the authoritative capability manifest for a Windows host."""
    classifications = {
        "desktop.status": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.battery": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.processes": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.apps.launch": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.file.read": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.file.write": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.file.list": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.file.search": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.exec": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.clipboard.read": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.clipboard.write": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "desktop.file.transfer": CapabilityExecutionClassification.BACKGROUND_SAFE,
    }
    permission_states = {cap: "GRANTED" for cap in WINDOWS_CAPABILITIES}
    return CapabilityManifest(
        manifest_version=MANIFEST_PROTOCOL_VERSION,
        supported_capabilities=sorted(WINDOWS_CAPABILITIES),
        permission_states=permission_states,
        classifications=classifications,
    )


def build_android_manifest() -> CapabilityManifest:
    """Build the authoritative capability manifest for an Android client."""
    classifications = {
        "android.telemetry.get": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "android.notifications.push": CapabilityExecutionClassification.RUNTIME_PERMISSION_REQUIRED,
        "android.clipboard.set": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "android.clipboard.get": CapabilityExecutionClassification.FOREGROUND_USER_INTERACTION_REQUIRED,
        "android.apps.list": CapabilityExecutionClassification.BACKGROUND_SAFE,
        "android.apps.launch": CapabilityExecutionClassification.FOREGROUND_USER_INTERACTION_REQUIRED,
        "android.messaging.send_intent": CapabilityExecutionClassification.FOREGROUND_USER_INTERACTION_REQUIRED,
        "android.files.transfer": CapabilityExecutionClassification.RUNTIME_PERMISSION_REQUIRED,
        "android.ringer.ring": CapabilityExecutionClassification.BACKGROUND_SAFE,
    }
    permission_states = {cap: "GRANTED" for cap in ANDROID_CAPABILITIES}
    return CapabilityManifest(
        manifest_version=MANIFEST_PROTOCOL_VERSION,
        supported_capabilities=sorted(ANDROID_CAPABILITIES),
        permission_states=permission_states,
        classifications=classifications,
    )


@dataclass
class DeviceNode:
    """Logical representation of a participating node in the SNOW V2 platform."""

    device_id: str
    device_name: str
    platform: str
    protocol_version: int = 1
    reachability_profile: ReachabilityProfile = ReachabilityProfile.ACTIVE_SESSION_PEER
    reachability_state: ReachabilityState = ReachabilityState.UNREACHABLE_OFFLINE
    host: Optional[str] = None
    wss_port: int = 8765
    transfer_port: int = 8766
    supported_capabilities: list[str] = field(default_factory=list)
    permission_states: dict[str, str] = field(default_factory=dict)
    last_seen_timestamp: float = 0.0
    trust_tier: Optional[str] = None
    capabilities: Optional[CapabilityManifest] = None
    is_authenticated: bool = False
    is_paired: bool = False
    transport: str = "unknown"
    connection_mode: str = "auto"
    telemetry: Optional[dict[str, Any]] = None

    def __post_init__(self) -> None:
        if self.capabilities and not self.supported_capabilities:
            self.supported_capabilities = list(self.capabilities.supported_capabilities)
        if self.capabilities and not self.permission_states:
            self.permission_states = dict(self.capabilities.permission_states)

    @property
    def is_connected(self) -> bool:
        """Return True if node is in an active authenticated connected session."""
        return self.reachability_state == ReachabilityState.CONNECTED_SESSION

    def supports_capability(self, capability: str) -> bool:
        """Check whether this node advertises support for the requested capability."""
        if self.capabilities:
            return self.capabilities.supports_capability(capability)
        clean = capability.strip()
        if clean in self.supported_capabilities:
            return True
        alias = CAPABILITY_ALIASES.get(clean)
        return bool(alias and alias in self.supported_capabilities)

    def to_dict(self, include_endpoints: bool = True) -> dict[str, Any]:
        """Convert DeviceNode to dictionary for serialization."""
        d: dict[str, Any] = {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "platform": self.platform,
            "protocol_version": self.protocol_version,
            "reachability_profile": str(self.reachability_profile),
            "reachability_state": str(self.reachability_state),
            "trust_tier": self.trust_tier,
            "is_paired": self.is_paired,
            "is_authenticated": self.is_authenticated,
            "transport": self.transport,
            "connection_mode": self.connection_mode,
            "telemetry": self.telemetry,
            "supported_capabilities": list(self.supported_capabilities),
            "permission_states": dict(self.permission_states),
            "last_seen_timestamp": self.last_seen_timestamp,
        }
        if include_endpoints:
            d["host"] = self.host
            d["wss_port"] = self.wss_port
            d["transfer_port"] = self.transfer_port
            if self.host:
                d["active_endpoints"] = [f"wss://{self.host}:{self.wss_port}"]
        if self.capabilities:
            d["capabilities"] = self.capabilities.to_dict()
        return d

    def to_summary_dict(self) -> dict[str, Any]:
        """Return a safe summary dict suitable for MCP tool responses and UI views."""
        return {
            "device_id": self.device_id,
            "device_name": self.device_name,
            "platform": self.platform,
            "trust_tier": self.trust_tier or "unpaired",
            "reachability_profile": str(self.reachability_profile),
            "reachability_state": str(self.reachability_state),
            "is_connected": self.is_connected,
            "is_paired": self.is_paired,
            "transport": self.transport,
            "connection_mode": self.connection_mode,
            "telemetry": self.telemetry,
            "supported_capabilities": list(self.supported_capabilities),
            "permission_states": dict(self.permission_states),
            "last_seen_timestamp": self.last_seen_timestamp,
            "last_seen": self.last_seen_timestamp,
            "remote_address": f"{self.host}:{self.wss_port}" if self.host else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DeviceNode:
        """Safely parse DeviceNode from dictionary with automatic timestamp unit normalization."""
        ts = data.get("last_seen_timestamp", 0.0)
        try:
            ts_float = float(ts)
            if ts_float > 1e11:  # epoch millis migration
                ts_float /= 1000.0
        except (ValueError, TypeError):
            ts_float = 0.0

        caps = None
        if "capabilities" in data and isinstance(data["capabilities"], dict):
            caps = CapabilityManifest.from_dict(data["capabilities"])

        reach_profile = data.get("reachability_profile", ReachabilityProfile.ACTIVE_SESSION_PEER)
        try:
            reach_profile = ReachabilityProfile(str(reach_profile))
        except ValueError:
            reach_profile = ReachabilityProfile.ACTIVE_SESSION_PEER

        reach_state = data.get("reachability_state", ReachabilityState.UNREACHABLE_OFFLINE)
        try:
            reach_state = ReachabilityState(str(reach_state))
        except ValueError:
            reach_state = ReachabilityState.UNREACHABLE_OFFLINE

        return cls(
            device_id=str(data.get("device_id", "")),
            device_name=str(data.get("device_name", "")),
            platform=str(data.get("platform", "generic")),
            protocol_version=int(data.get("protocol_version", 1)),
            reachability_profile=reach_profile,
            reachability_state=reach_state,
            host=data.get("host"),
            wss_port=int(data.get("wss_port", 8765)),
            transfer_port=int(data.get("transfer_port", 8766)),
            supported_capabilities=list(data.get("supported_capabilities", [])),
            permission_states=dict(data.get("permission_states", {})),
            last_seen_timestamp=ts_float,
            trust_tier=data.get("trust_tier"),
            capabilities=caps,
            is_authenticated=bool(data.get("is_authenticated", False)),
            is_paired=bool(data.get("is_paired", False)),
            transport=str(data.get("transport", "unknown")),
            connection_mode=str(data.get("connection_mode", "auto")),
            telemetry=data.get("telemetry"),
        )
