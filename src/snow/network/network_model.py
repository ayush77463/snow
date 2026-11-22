"""Data model and network management for SNOW V4.2 Multi-Device Local SNOW Network.

Defines resilient network identity, device membership, endpoint ring-buffer history,
and principal-scoped topology views.

SECURITY INVARIANTS:
1. No Single Point of Failure: The network identity and membership persist locally
   on every node. Loss of a coordinator never erases network membership.
2. Safe Principal Views: AI_MCP is strictly prevented from inspecting raw LAN IPs,
   pairing PINs, authentication tokens, private keys, or internal database paths.
3. No Discovered Trust: Endpoint discovery alone NEVER grants pairing trust or owner authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional, Tuple
import uuid

from snow.security.context import ExecutionContext, ExecutionPrincipal
from snow.network.federation import is_capability_forbidden_for_federation

logger = logging.getLogger(__name__)

DEFAULT_NETWORK_NAME = "My SNOW Network"
MAX_ENDPOINT_HISTORY = 5

SAFE_TRANSPORT_DISPLAY: dict[str, str] = {
    "wifi_lan": "Wi-Fi LAN",
    "usb_adb": "USB ADB",
    "loopback": "Loopback",
    "peer_link": "Peer Link",
    "mesh_peer": "Peer Link",
    "local": "Local Host",
    "remote_relay": "Remote Relay",
}


def current_utc_timestamp() -> str:
    """Return strict UTC ISO-8601 formatted timestamp."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class NetworkIdentity:
    """Persistent cryptographic identity of the local SNOW Network."""

    network_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    network_name: str = DEFAULT_NETWORK_NAME
    owner_id: str = ""
    created_timestamp: str = field(default_factory=current_utc_timestamp)

    def to_dict(self) -> dict[str, Any]:
        return {
            "network_id": self.network_id,
            "network_name": self.network_name,
            "owner_id": self.owner_id,
            "created_timestamp": self.created_timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> NetworkIdentity:
        return cls(
            network_id=data.get("network_id") or str(uuid.uuid4()),
            network_name=data.get("network_name") or DEFAULT_NETWORK_NAME,
            owner_id=data.get("owner_id") or "",
            created_timestamp=data.get("created_timestamp") or current_utc_timestamp(),
        )


@dataclass
class NetworkMember:
    """Representation of a remembered device participating in the SNOW Network."""

    device_id: str
    display_name: str
    platform: str
    role: str = "member"  # "coordinator" or "member"
    trust_tier: str = "peer"  # "owner" or "peer"
    cert_fingerprint: Optional[str] = None
    is_connected: bool = False
    connection_state: str = "offline"  # "connected", "offline", "dormant"
    authoritative_transport: str = "unknown"  # "wifi_lan", "usb_adb", "loopback", "peer_link"
    remembered_endpoints: list[dict[str, Any]] = field(default_factory=list)
    last_connected_timestamp: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "device_id": self.device_id,
            "display_name": self.display_name,
            "platform": self.platform,
            "role": self.role,
            "trust_tier": self.trust_tier,
            "cert_fingerprint": self.cert_fingerprint,
            "is_connected": self.is_connected,
            "connection_state": self.connection_state,
            "authoritative_transport": self.authoritative_transport,
            "remembered_endpoints": list(self.remembered_endpoints),
            "last_connected_timestamp": self.last_connected_timestamp,
        }

    def to_safe_view(self, effective_permissions: Optional[dict[str, str]] = None) -> dict[str, Any]:
        """Generate safe, secret-redacted representation for AI_MCP callers.

        Excludes raw IP addresses, ports, private keys, auth tokens, and internal paths.
        """
        return {
            "device_id": self.device_id,
            "device_name": self.display_name,
            "platform": self.platform,
            "is_connected": self.is_connected,
            "reachability_state": self.connection_state,
            "transport": self.authoritative_transport,
            "effective_permissions": effective_permissions or {},
        }


class SnowNetworkManager:
    """Manages multi-device network identity, endpoint history, and topology synthesis."""

    def __init__(
        self,
        db_manager: Any,
        local_identity: Any = None,
        node_registry: Any = None,
    ) -> None:
        self.db_manager = db_manager
        self.local_identity = local_identity
        self.node_registry = node_registry
        self._identity: Optional[NetworkIdentity] = None
        self._init_network_identity()

    def _init_network_identity(self) -> None:
        """Load or create persistent network identity in SQLite."""
        row = self.db_manager.get_network_identity()
        if row:
            self._identity = NetworkIdentity.from_dict(row)
        else:
            # Derive stable owner fingerprint from local identity
            owner_id = ""
            if self.local_identity:
                cert_fp = getattr(self.local_identity, "cert_fingerprint", None)
                dev_id = getattr(self.local_identity, "device_id", None)
                owner_id = cert_fp or (hashlib.sha256(dev_id.encode("utf-8")).hexdigest() if dev_id else "")
            if not owner_id:
                owner_id = hashlib.sha256(uuid.uuid4().bytes).hexdigest()

            ident = NetworkIdentity(
                network_id=str(uuid.uuid4()),
                network_name=DEFAULT_NETWORK_NAME,
                owner_id=owner_id,
                created_timestamp=current_utc_timestamp(),
            )
            self.db_manager.save_network_identity(
                network_id=ident.network_id,
                network_name=ident.network_name,
                owner_id=ident.owner_id,
                created_timestamp=ident.created_timestamp,
            )
            self._identity = ident

    def get_network_identity(self) -> NetworkIdentity:
        """Return the current local SNOW Network identity."""
        if not self._identity:
            self._init_network_identity()
        return self._identity or NetworkIdentity()

    def update_network_name(self, network_name: str) -> NetworkIdentity:
        """Update network name in SQLite and in-memory state."""
        clean_name = (network_name or "").strip()
        if not clean_name:
            raise ValueError("Network name cannot be empty.")
        self.db_manager.update_network_name(clean_name)
        ident = self.get_network_identity()
        ident.network_name = clean_name
        return ident

    def record_endpoint(self, device_id: str, host: str, port: int) -> None:
        """Record a successful endpoint in the bounded ring buffer."""
        clean_host = (host or "").strip()
        if not clean_host or port <= 0 or port > 65535:
            return
        ts = current_utc_timestamp()
        try:
            self.db_manager.record_endpoint(device_id, clean_host, port, ts)
        except Exception as exc:
            logger.debug("Failed recording endpoint for device %s: %s", device_id, exc)

    def get_endpoints(self, device_id: str) -> list[tuple[str, int]]:
        """Return remembered endpoints for device with last known successful first."""
        records = self.db_manager.get_endpoints(device_id, limit=MAX_ENDPOINT_HISTORY)
        return [(r["host"], int(r["port"])) for r in records]

    def build_topology(
        self,
        principal: ExecutionPrincipal = ExecutionPrincipal.AI_MCP,
        approval_engine: Any = None,
    ) -> dict[str, Any]:
        """Build a principal-scoped view of the SNOW mesh topology.

        SECURITY BOUNDARY:
        - AI_MCP: Exposes ONLY reachable IDs, names, platforms, status, transport,
          and effective capability permissions (ALLOW, APPROVAL_REQUIRED, DENY).
          NEVER leaks IPs, ports, tokens, keys, PINs, or internal file paths.
        - OWNER_MANUAL: Receives operational metadata, network name, and role status.
        """
        ident = self.get_network_identity()

        # Representative capabilities to report effective permissions and scoping for
        relevant_capabilities = [
            "desktop.status",
            "desktop.processes",
            "desktop.apps.launch",
            "desktop.file.read",
            "desktop.file.write",
            "desktop.exec",
            "desktop.clipboard.read",
            "desktop.clipboard.write",
            "android.telemetry.get",
            "android.ringer.ring",
            "android.clipboard.set",
            "android.clipboard.get",
            "android.apps.list",
            "android.apps.launch",
            "android.camera.capture",
            "android.screen.share",
        ]

        def _compute_effective_permissions(node_platform: str) -> dict[str, str]:
            norm_plat = (node_platform or "").strip().lower()
            scoped_perms: dict[str, str] = {}
            for cap in relevant_capabilities:
                # Platform-specific capability scoping (Defect 5B)
                if norm_plat in ("windows", "desktop"):
                    if not cap.startswith("desktop."):
                        continue
                elif norm_plat == "android":
                    if not cap.startswith("android."):
                        continue

                if principal == ExecutionPrincipal.AI_MCP:
                    if cap in ("desktop.exec", "desktop.file.write"):
                        scoped_perms[cap] = "APPROVAL_REQUIRED"
                    elif cap in ("android.camera.capture", "android.screen.share", "android.ringer.ring"):
                        scoped_perms[cap] = "APPROVAL_REQUIRED"
                    else:
                        scoped_perms[cap] = "ALLOW"
                else:
                    scoped_perms[cap] = "ALLOW"
            return scoped_perms

        # Query synthesized nodes
        nodes = []
        if self.node_registry:
            nodes = list(self.node_registry.list_nodes())
        seen_ids = {getattr(n, "device_id", None) for n in nodes}

        # Include local desktop coordinator node if not present
        local_id = getattr(self.local_identity, "device_id", "desktop-core") if self.local_identity else "desktop-core"
        local_name = getattr(self.local_identity, "device_name", "Windows Desktop Host") if self.local_identity else "Windows Desktop Host"
        if local_id not in seen_ids:
            class LocalNode:
                device_id = local_id
                device_name = local_name
                platform = "windows"
                trust_tier = "owner"
                role = "coordinator"
                is_connected = True
                reachability_state = "active"
                transport = "local"
                supported_capabilities: list[str] = [c for c in relevant_capabilities if c.startswith("desktop.")]
                last_seen_timestamp = 0.0
            nodes.insert(0, LocalNode())
            seen_ids.add(local_id)

        # Include paired devices from DB if not already present
        if self.db_manager:
            try:
                paired = self.db_manager.list_paired_devices()
                for p in paired:
                    if p.device_id not in seen_ids:
                        p_plat = p.platform or "unknown"
                        class PairedNode:
                            device_id = p.device_id
                            device_name = p.device_name
                            platform = p_plat
                            trust_tier = p.trust_tier or "peer"
                            role = getattr(p, "role", "member")
                            is_connected = False
                            reachability_state = "offline"
                            transport = "none"
                            federated = False
                            supported_capabilities: list[str] = [
                                c for c in relevant_capabilities
                                if (p_plat == "android" and c.startswith("android."))
                                or (p_plat in ("windows", "desktop") and c.startswith("desktop."))
                            ]
                            last_seen_timestamp = getattr(p, "last_seen_timestamp", 0.0) or 0.0
                        nodes.append(PairedNode())
                        seen_ids.add(p.device_id)

                # Phase 30: Incorporate active federated peer nodes (Repair 4: Expiry-aware & Real Connectivity)
                if hasattr(self.db_manager, "list_federation_grants"):
                    grants = self.db_manager.list_federation_grants(active_only=True)
                    now_utc = datetime.now(timezone.utc)
                    for g in grants:
                        peer_id = g.get("peer_node_id")
                        if not peer_id or peer_id in seen_ids:
                            continue

                        # Filter out expired grants with timezone-aware UTC comparison
                        exp_str = g.get("expires_timestamp")
                        if exp_str:
                            try:
                                exp_dt = datetime.fromisoformat(exp_str)
                                if exp_dt.tzinfo is None:
                                    exp_dt = exp_dt.replace(tzinfo=timezone.utc)
                                if now_utc > exp_dt:
                                    continue  # Expired grant, skip from active topology
                            except Exception:
                                pass

                        # Genuine connectivity reflection via node_registry
                        fed_is_conn = False
                        fed_reachability = "offline"
                        if getattr(self, "node_registry", None):
                            reg_node = self.node_registry.get_node(peer_id)
                            if reg_node:
                                fed_is_conn = bool(getattr(reg_node, "is_connected", False))
                                fed_reachability = "active" if fed_is_conn else "offline"

                        raw_g_caps = json.loads(g.get("allowed_capabilities_json", "[]"))
                        g_caps = [c for c in raw_g_caps if not is_capability_forbidden_for_federation(c)]
                        class FederatedPeerNode:
                            device_id = peer_id
                            device_name = f"{g.get('peer_node_name', 'Remote Peer')} ({g.get('network_name', 'Federated Network')})"
                            platform = "federated"
                            trust_tier = "federated"
                            role = "federated_peer"
                            is_connected = fed_is_conn
                            reachability_state = fed_reachability
                            transport = "remote_relay" if fed_is_conn else "none"
                            federated = True
                            network_id = g.get("network_id", "")
                            network_name = g.get("network_name", "")
                            supported_capabilities = g_caps
                            last_seen_timestamp = g.get("last_used_timestamp") or g.get("created_timestamp") or 0.0
                            expires_timestamp = g.get("expires_timestamp")
                        nodes.append(FederatedPeerNode())
                        seen_ids.add(peer_id)
            except Exception as e:
                logger.debug("Failed listing paired or federated devices for topology: %s", e)

        device_views: list[dict[str, Any]] = []
        for n in nodes:
            is_fed = getattr(n, "federated", False)
            # Map authoritative transport safely
            raw_tr = getattr(n, "transport", "unknown")
            safe_tr = "unknown"
            if is_fed:
                safe_tr = "Federated Mesh"
            elif raw_tr == "wifi_lan":
                safe_tr = "Wi-Fi LAN"
            elif raw_tr == "usb_adb":
                safe_tr = "USB ADB"
            elif raw_tr == "loopback":
                safe_tr = "Loopback"
            elif raw_tr in ("peer_link", "mesh_peer"):
                safe_tr = "Peer Link"
            elif raw_tr == "local":
                safe_tr = "Local Host"
            elif raw_tr == "remote_relay":
                safe_tr = "Remote Relay"
            else:
                safe_tr = raw_tr

            node_platform = getattr(n, "platform", "unknown")
            if is_fed:
                node_perms = {
                    c: "ALLOW"
                    for c in getattr(n, "supported_capabilities", [])
                    if not is_capability_forbidden_for_federation(c)
                }
            else:
                node_perms = _compute_effective_permissions(node_platform)

            if principal == ExecutionPrincipal.AI_MCP:
                device_views.append({
                    "device_id": n.device_id,
                    "device_name": n.device_name,
                    "platform": n.platform,
                    "is_connected": n.is_connected,
                    "reachability_state": str(n.reachability_state),
                    "transport": safe_tr,
                    "effective_permissions": node_perms,
                    "federated": is_fed,
                })
            else:
                if is_fed:
                    raw_caps = [
                        c for c in getattr(n, "supported_capabilities", [])
                        if not is_capability_forbidden_for_federation(c)
                    ]
                else:
                    raw_caps = list(getattr(n, "supported_capabilities", []))
                    if not raw_caps:
                        if node_platform in ("windows", "desktop"):
                            raw_caps = [c for c in relevant_capabilities if c.startswith("desktop.")]
                        elif node_platform == "android":
                            raw_caps = [c for c in relevant_capabilities if c.startswith("android.")]
                    else:
                        if node_platform in ("windows", "desktop"):
                            raw_caps = [c for c in raw_caps if not c.startswith("android.")]
                        elif node_platform == "android":
                            raw_caps = [c for c in raw_caps if not c.startswith("desktop.")]

                view_entry = {
                    "device_id": n.device_id,
                    "device_name": n.device_name,
                    "platform": n.platform,
                    "trust_tier": getattr(n, "trust_tier", "peer"),
                    "role": getattr(n, "role", "member") if hasattr(n, "role") else "member",
                    "is_connected": n.is_connected,
                    "reachability_state": str(n.reachability_state),
                    "transport": safe_tr,
                    "supported_capabilities": raw_caps,
                    "effective_permissions": node_perms,
                    "last_seen": getattr(n, "last_seen_timestamp", 0.0),
                    "federated": is_fed,
                }
                if is_fed:
                    view_entry["network_id"] = getattr(n, "network_id", "")
                    view_entry["network_name"] = getattr(n, "network_name", "")
                    view_entry["expires_timestamp"] = getattr(n, "expires_timestamp", None)
                device_views.append(view_entry)

        if principal == ExecutionPrincipal.AI_MCP:
            return {
                "success": True,
                "status": "SUCCESS",
                "network_name": ident.network_name,
                "devices": device_views,
            }
        else:
            return {
                "success": True,
                "status": "SUCCESS",
                "network_id": ident.network_id,
                "network_name": ident.network_name,
                "owner_id": ident.owner_id,
                "created_timestamp": ident.created_timestamp,
                "devices": device_views,
            }
