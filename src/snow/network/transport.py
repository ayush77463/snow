"""Unified transport ranking, verified route state, and active-socket route classification.

Establishes a single authoritative transport model for SNOW across desktop routing,
API status reporting, manual transport overrides, and file transfer socket attribution.

Canonical Priority:
  0. USB          (usb)
  1. Hotspot      (hotspot)
  2. Wi-Fi LAN    (wifi_lan)
  3. Remote Relay (remote_relay)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import ipaddress
import time
from typing import Any, Optional


class TransportType(StrEnum):
    """Canonical transport channels ordered strictly by priority."""

    USB = "usb"
    HOTSPOT = "hotspot"
    WIFI_LAN = "wifi_lan"
    REMOTE_RELAY = "remote_relay"


class RouteStatus(StrEnum):
    """Distinct lifecycle states separating route discovery, readiness verification, and activity."""

    DISCOVERED = "discovered"
    CANDIDATE = "candidate"
    PROBING = "probing"
    VERIFIED_AVAILABLE = "verified_available"
    ACTIVE = "active"
    UNAVAILABLE = "unavailable"
    MANUALLY_SELECTED = "manually_selected"


TRANSPORT_PRIORITY_ORDER: tuple[TransportType, ...] = (
    TransportType.USB,
    TransportType.HOTSPOT,
    TransportType.WIFI_LAN,
    TransportType.REMOTE_RELAY,
)

TRANSPORT_PRIORITY_MAP: dict[TransportType, int] = {
    TransportType.USB: 0,
    TransportType.HOTSPOT: 1,
    TransportType.WIFI_LAN: 2,
    TransportType.REMOTE_RELAY: 3,
}

TRANSPORT_BADGE_MAP: dict[TransportType, str] = {
    TransportType.USB: "USB • Zero Data",
    TransportType.HOTSPOT: "Hotspot • Zero Data",
    TransportType.WIFI_LAN: "Wi-Fi • Zero Data",
    TransportType.REMOTE_RELAY: "Remote • Uses Data",
}

VALID_TRANSPORT_MODES: tuple[str, ...] = (
    "auto",
    "usb",
    "hotspot",
    "wifi_lan",
    "remote_relay",
    "local_only",
    "remote_only",
)

MANUAL_SINGLE_TRANSPORT_MODES: frozenset[str] = frozenset(
    {
        TransportType.USB.value,
        TransportType.HOTSPOT.value,
        TransportType.WIFI_LAN.value,
        TransportType.REMOTE_RELAY.value,
    }
)

DEFAULT_ROUTE_VERIFICATION_TTL_SEC: float = 30.0
DEFAULT_PROBE_TIMEOUT_SEC: float = 2.5
DEFAULT_PROBE_COOLDOWN_SEC: float = 5.0

HOTSPOT_SUBNET_PREFIXES: tuple[str, ...] = (
    "192.168.43.",
    "192.168.49.",
    "192.168.137.",
    "172.20.10.",
)

HOTSPOT_INTERFACE_HINTS: tuple[str, ...] = (
    "ap",
    "swlan",
    "softap",
    "wifi_ap",
    "uap",
    "sap",
    "hotspot",
    "wi-fi direct",
    "local area connection*",
)


def is_loopback_host(host: Optional[str]) -> bool:
    """Return True when host refers to local loopback (127.0.0.1, localhost, ::1)."""
    clean = (host or "").strip().lower()
    if clean in ("127.0.0.1", "localhost", "::1"):
        return True
    if ":" in clean and not clean.startswith("["):
        # Strip optional host:port for IPv4 strings before parsing
        clean_ip = clean.rsplit(":", 1)[0]
    else:
        clean_ip = clean.strip("[]")
    try:
        parsed = ipaddress.ip_address(clean_ip)
        if parsed.is_loopback:
            return True
        v4_mapped = getattr(parsed, "ipv4_mapped", None)
        return bool(v4_mapped and v4_mapped.is_loopback)
    except ValueError:
        return False


def strip_host_port(host: Optional[str]) -> str:
    """Extract clean IP/hostname without scheme or trailing port."""
    raw = (host or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    if raw.startswith("[") and "]" in raw:
        return raw[1:raw.index("]")].strip().lower()
    if raw.count(":") == 1:
        return raw.split(":", 1)[0].strip().lower()
    return raw.lower()


def is_hotspot_host_or_hint(
    host: Optional[str] = None,
    *,
    transport: Optional[str] = None,
    interface_name: Optional[str] = None,
    is_hotspot: bool = False,
) -> bool:
    """Identify local mobile hotspot / Wi-Fi Direct / Windows Mobile Hotspot routes."""
    if is_hotspot:
        return True
    t = (transport or "").strip().lower()
    if "hotspot" in t or "softap" in t or "ap_direct" in t:
        return True
    iface = (interface_name or "").strip().lower()
    if iface and any(iface.startswith(h) or h in iface for h in HOTSPOT_INTERFACE_HINTS):
        return True
    clean_ip = strip_host_port(host)
    if clean_ip and any(clean_ip.startswith(prefix) for prefix in HOTSPOT_SUBNET_PREFIXES):
        return True
    return False


def normalize_transport_mode(mode: Optional[str]) -> Optional[str]:
    """Normalize supported Auto/policy/manual transport mode strings or return None."""
    raw = (mode or "").strip().lower()
    if not raw or raw == "auto":
        return "auto"
    aliases = {
        "usb_adb": "usb",
        "adb": "usb",
        "usb": "usb",
        "hotspot": "hotspot",
        "softap": "hotspot",
        "wifi": "wifi_lan",
        "wifi_lan": "wifi_lan",
        "lan": "wifi_lan",
        "remote": "remote_relay",
        "relay": "remote_relay",
        "remote_relay": "remote_relay",
        "local_only": "local_only",
        "remote_only": "remote_only",
    }
    norm = aliases.get(raw)
    return norm if norm in VALID_TRANSPORT_MODES else None


def normalize_transport_type(
    transport: Optional[str] = None,
    host: Optional[str] = None,
    connection_mode: Optional[str] = None,
    interface_name: Optional[str] = None,
    is_hotspot: bool = False,
) -> TransportType:
    """Normalize arbitrary transport/host metadata into a canonical TransportType."""
    t = (transport or "").strip().lower()
    m = (connection_mode or "").strip().lower()
    clean_host = strip_host_port(host)

    if (
        "usb" in t
        or t == "adb"
        or m == "usb"
        or (
            clean_host
            and is_loopback_host(clean_host)
            and "relay" not in t
            and "remote" not in t
            and m not in ("remote_only", "remote_relay")
        )
    ):
        return TransportType.USB

    if (
        any(k in t for k in ("relay", "remote", "hub", "federated"))
        or m in ("remote_only", "remote_relay")
        or ("relay" in clean_host or "tunnel" in clean_host or "onrender.com" in clean_host)
    ):
        return TransportType.REMOTE_RELAY

    if is_hotspot_host_or_hint(
        clean_host,
        transport=t,
        interface_name=interface_name,
        is_hotspot=is_hotspot,
    ) or m == "hotspot":
        return TransportType.HOTSPOT

    return TransportType.WIFI_LAN


def transport_badge_for(transport_type: TransportType) -> str:
    """Return user-facing transport cost/medium badge string."""
    return TRANSPORT_BADGE_MAP[transport_type]


def transport_priority_for(transport_type: TransportType) -> int:
    """Return canonical numeric priority (0 = highest)."""
    return TRANSPORT_PRIORITY_MAP[transport_type]


def classify_transfer_socket_route(
    host: Optional[str] = None,
    *,
    peer_ip: Optional[str] = None,
    usb_mapping_verified: bool = False,
    transport_hint: Optional[str] = None,
    interface_name: Optional[str] = None,
    is_hotspot: bool = False,
    is_relay: bool = False,
) -> tuple[TransportType, str]:
    """Classify the actual socket carrying a file transfer (never trusting USB cables or stale UI mode).

    Guarantees:
    - Never labels a transfer 'USB • Zero Data' unless the actual socket uses loopback AND
      the SNOW USB ADB mapping for that route is verified active.
    - Separates Hotspot from generic Wi-Fi LAN using interface/subnet truth.
    - Always labels relay traffic 'Remote • Uses Data'.
    """
    if is_relay or any(k in (transport_hint or "").strip().lower() for k in ("relay", "remote", "hub")):
        return TransportType.REMOTE_RELAY, TRANSPORT_BADGE_MAP[TransportType.REMOTE_RELAY]

    if is_hotspot or "hotspot" in (transport_hint or "").strip().lower() or is_hotspot_host_or_hint(
        None, transport=transport_hint, interface_name=interface_name, is_hotspot=is_hotspot
    ):
        return TransportType.HOTSPOT, TRANSPORT_BADGE_MAP[TransportType.HOTSPOT]

    effective_ip = strip_host_port(peer_ip) or strip_host_port(host)
    if effective_ip and is_loopback_host(effective_ip):
        if usb_mapping_verified:
            return TransportType.USB, TRANSPORT_BADGE_MAP[TransportType.USB]
        return TransportType.WIFI_LAN, TRANSPORT_BADGE_MAP[TransportType.WIFI_LAN]

    if is_hotspot_host_or_hint(
        effective_ip,
        transport=transport_hint,
        interface_name=interface_name,
        is_hotspot=is_hotspot,
    ):
        return TransportType.HOTSPOT, TRANSPORT_BADGE_MAP[TransportType.HOTSPOT]

    return TransportType.WIFI_LAN, TRANSPORT_BADGE_MAP[TransportType.WIFI_LAN]


@dataclass
class RouteCandidate:
    """Per-device candidate or verified transport entry with lifecycle metadata."""

    device_id: str
    transport: TransportType
    host: str = ""
    port: int = 8765
    transfer_port: int = 8766
    state: RouteStatus = RouteStatus.CANDIDATE
    verified: bool = False
    verified_at: float = 0.0
    expires_at: float = 0.0
    last_checked_at: float = 0.0
    cooldown_until: float = 0.0
    last_failure_reason: Optional[str] = None
    interface_name: Optional[str] = None
    is_hotspot: bool = False
    suitable_for_transfer: bool = True
    generation: int = 0
    direction: str = "unknown"  # "inbound", "outbound", "relay", "discovered"

    @property
    def priority(self) -> int:
        return TRANSPORT_PRIORITY_MAP[self.transport]

    @property
    def badge(self) -> str:
        return TRANSPORT_BADGE_MAP[self.transport]

    @property
    def is_local(self) -> bool:
        return self.transport != TransportType.REMOTE_RELAY

    def is_expired(self, now: Optional[float] = None) -> bool:
        if not self.verified or self.expires_at <= 0.0:
            return False
        cur = now if now is not None else time.monotonic()
        return cur >= self.expires_at

    def is_usable(self, now: Optional[float] = None) -> bool:
        cur = now if now is not None else time.monotonic()
        if self.state == RouteStatus.UNAVAILABLE:
            return False
        return bool(self.verified and not self.is_expired(cur))

    def to_public_dict(self, *, is_active: bool = False, is_manual: bool = False, now: Optional[float] = None) -> dict[str, Any]:
        """Serialize safe UI/API diagnostics (never includes secrets, keys, or auth tokens)."""
        cur = now if now is not None else time.monotonic()
        usable = self.is_usable(cur)
        effective_state = (
            RouteStatus.ACTIVE.value
            if is_active and usable
            else (
                RouteStatus.UNAVAILABLE.value
                if self.verified and self.is_expired(cur)
                else self.state.value
            )
        )
        return {
            "transport": self.transport.value,
            "badge": self.badge,
            "priority": self.priority,
            "state": effective_state,
            "verified": usable,
            "active": bool(is_active and usable),
            "manually_selected": bool(is_manual),
            "is_local": self.is_local,
            "suitable_for_transfer": bool(self.suitable_for_transfer and (usable or is_active)),
            "host": self.host if self.is_local else "",
            "port": self.port,
            "transfer_port": self.transfer_port,
            "last_checked_at": self.last_checked_at,
            "verified_at": self.verified_at,
            "expired": bool(self.verified and self.is_expired(cur)),
            "last_failure_reason": self.last_failure_reason,
        }


def sanitize_transport_error(raw: Any) -> str:
    """Redact potential bearer tokens, secrets, or keys from user-facing failure reasons."""
    text = str(raw or "").strip()
    if not text:
        return "Route verification failed."
    lower = text.lower()
    if any(tok in lower for tok in ("bearer ", "auth_token", "handshake_token", "bootstrap_token", "hub_token", "private key")):
        return "Authentication or certificate validation failed."
    return text[:220]
