"""Layer 3 Unified NodeRegistry for SNOW V2.

Consolidates active WebSocket sessions, SQLite paired-device records,
outbound peer connections, and UDP mesh discovery into a single thread-safe
device state and reachability registry.

SECURITY BOUNDARY:
- Clear separation between paired/authenticated nodes and unauthenticated discovery candidates.
- Discovery beacons CANNOT grant trust, override owner authority, or automatically pair.
- Target resolution enforces capability verification and prevents ambiguous routing.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict
import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from snow.network.connection_manager import ConnectionManager
from snow.network.node import (
    CapabilityManifest,
    DeviceNode,
    ReachabilityProfile,
    ReachabilityState,
    build_windows_manifest,
)
from snow.security.db import DatabaseManager, PairedDeviceRecord
from snow.security.identity import DeviceIdentity, load_or_create_device_identity

logger = logging.getLogger(__name__)


VALID_PERMISSION_PROFILES: tuple[str, ...] = (
    "full_control",
    "files_and_clipboard",
    "files_only",
    "clipboard_only",
    "not_allowed",
)


class NodeRegistry:
    """Thread-safe unified registry for all local, paired, connected, and discovered nodes."""

    def __init__(
        self,
        db_manager: Optional[DatabaseManager] = None,
        connection_manager: Optional[ConnectionManager] = None,
        discovery_service: Any = None,
        local_identity: Optional[DeviceIdentity] = None,
        local_manifest: Optional[CapabilityManifest] = None,
        port: int = 8765,
        transfer_port: int = 8766,
    ) -> None:
        self.db_manager = db_manager or DatabaseManager()
        self.connection_manager = connection_manager
        self.discovery_service = discovery_service
        self.local_identity = local_identity or load_or_create_device_identity()
        self.local_manifest = local_manifest or build_windows_manifest()
        self.port = port
        self.transfer_port = transfer_port

        self._lock = threading.RLock()
        # In-memory dynamic runtime caches
        self._active_sessions: dict[str, dict[str, Any]] = {}  # device_id -> session info
        self._discovered_candidates: dict[str, dict[str, Any]] = {}  # device_id -> candidate info
        self._manifest_cache: dict[str, CapabilityManifest] = {}  # device_id -> manifest
        self._registered_nodes: dict[str, DeviceNode] = {}  # device_id -> explicit DeviceNode
        self._permission_profiles: dict[str, str] = {}  # device_id -> profile preset

        # Hydrate persisted permission profiles from database
        try:
            for p in self.db_manager.list_paired_devices():
                saved_prof = self.db_manager.get_setting(f"device_profile:{p.device_id}")
                if isinstance(saved_prof, str):
                    if saved_prof in VALID_PERMISSION_PROFILES:
                        self._permission_profiles[p.device_id] = saved_prof
                    else:
                        self._permission_profiles[p.device_id] = "not_allowed"
        except Exception as exc:
            logger.debug("Failed hydrating permission profiles: %s", exc)

        # Register local node
        self.local_node = DeviceNode(
            device_id=self.local_identity.device_id,
            device_name=self.local_identity.device_name,
            platform="windows",
            protocol_version=1,
            reachability_profile=ReachabilityProfile.PERSISTENT_DAEMON,
            reachability_state=ReachabilityState.CONNECTED_SESSION,
            host="127.0.0.1",
            wss_port=self.port,
            transfer_port=self.transfer_port,
            supported_capabilities=list(self.local_manifest.supported_capabilities),
            permission_states=dict(self.local_manifest.permission_states),
            last_seen_timestamp=time.time(),
            trust_tier="owner",
            capabilities=self.local_manifest,
            is_authenticated=True,
            is_paired=True,
            transport="local",
        )

    # =========================================================================
    # Session & Handshake Lifecycle Hooks
    # =========================================================================

    def on_session_authenticated(
        self,
        device_id: str,
        connection_id: str,
        host: str,
        port: int = 8765,
        manifest_data: Optional[dict[str, Any] | CapabilityManifest] = None,
        transport: str = "unknown",
    ) -> DeviceNode:
        """Record an active authenticated WebSocket session for a paired device."""
        with self._lock:
            # 1. Parse and validate capability manifest
            manifest: Optional[CapabilityManifest] = None
            if isinstance(manifest_data, CapabilityManifest):
                manifest = manifest_data
            elif isinstance(manifest_data, dict):
                manifest = CapabilityManifest.from_dict(manifest_data)
            elif isinstance(manifest_data, str):
                manifest = CapabilityManifest.from_json(manifest_data)

            if manifest:
                self._manifest_cache[device_id] = manifest
                try:
                    self.db_manager.update_device_manifest(device_id, manifest.to_json())
                except Exception as exc:
                    logger.debug("Failed caching manifest to DB for device [%s]: %s", device_id, exc)

            # 2. Persist last-known endpoint
            if host:
                try:
                    self.db_manager.update_device_endpoint(device_id, host, port)
                except Exception as exc:
                    logger.debug("Failed saving endpoint for device [%s]: %s", device_id, exc)

            # 3. Update runtime session tracking
            now = time.time()
            self._active_sessions[device_id] = {
                "connection_id": connection_id,
                "host": host,
                "port": port,
                "authenticated_at": now,
                "last_seen": now,
                "transport": transport,
            }

            # Return resolved DeviceNode view
            node = self.get_node(device_id)
            if not node:
                # Fallback node if not in DB
                node = DeviceNode(
                    device_id=device_id,
                    device_name="Connected Peer",
                    platform="unknown",
                    reachability_profile=ReachabilityProfile.ACTIVE_SESSION_PEER,
                    reachability_state=ReachabilityState.CONNECTED_SESSION,
                    host=host,
                    wss_port=port,
                    last_seen_timestamp=now,
                    is_authenticated=True,
                    is_paired=True,
                    transport=transport,
                    capabilities=manifest,
                )
            return node

    def on_manifest_updated(
        self,
        device_id: str,
        manifest_data: Any,
    ) -> Optional[DeviceNode]:
        """Update live capability manifest for a connected node without altering trust boundaries."""
        with self._lock:
            # 1. Parse and validate capability manifest
            manifest: Optional[CapabilityManifest] = None
            if isinstance(manifest_data, CapabilityManifest):
                manifest = manifest_data
            elif isinstance(manifest_data, dict):
                manifest = CapabilityManifest.from_dict(manifest_data)
            elif isinstance(manifest_data, str):
                manifest = CapabilityManifest.from_json(manifest_data)

            if not manifest:
                logger.warning("Empty or invalid manifest update received for device [%s]", device_id)
                return self.get_node(device_id)

            self._manifest_cache[device_id] = manifest
            try:
                self.db_manager.update_device_manifest(device_id, manifest.to_json())
            except Exception as exc:
                logger.debug("Failed caching updated manifest to DB for device [%s]: %s", device_id, exc)

            if device_id in self._active_sessions:
                self._active_sessions[device_id]["last_seen"] = time.time()

            logger.info("Updated capability manifest for device [%s] (capabilities: %d)",
                        device_id, len(manifest.supported_capabilities))
            return self.get_node(device_id)

    def on_session_disconnected(
        self, device_id: str, connection_id: Optional[str] = None
    ) -> None:
        """Update runtime reachability when an active session terminates."""
        with self._lock:
            active = self._active_sessions.get(device_id)
            if active and connection_id and active.get("connection_id") != connection_id:
                logger.debug(
                    "Ignoring stale disconnect for device [%s] (active conn: %s, disconnecting conn: %s)",
                    device_id,
                    active.get("connection_id"),
                    connection_id,
                )
                return
            self._active_sessions.pop(device_id, None)
            logger.debug("Active session disconnected for device [%s]", device_id)

    def on_discovery_beacon(
        self,
        device_id: str,
        device_name: str,
        device_type: str,
        ip_address: str,
        port: int,
        transfer_port: int,
        cert_fingerprint: str = "",
    ) -> None:
        """Record an unauthenticated LAN discovery candidate from a UDP beacon.

        CRITICAL TRUST BOUNDARY:
        - Discovery beacons CANNOT modify SQLite paired-device records.
        - Discovery beacons CANNOT assign owner or peer trust.
        - Discovery candidates are stored strictly in an unauthenticated cache.
        """
        with self._lock:
            if device_id == self.local_identity.device_id:
                return  # Ignore self-beacon

            now = time.time()
            self._discovered_candidates[device_id] = {
                "device_id": device_id,
                "device_name": device_name,
                "platform": device_type,
                "host": ip_address,
                "port": port,
                "transfer_port": transfer_port,
                "cert_fingerprint": cert_fingerprint,
                "last_seen": now,
            }

    # =========================================================================
    # Node Queries & Reachability Synthesis
    # =========================================================================

    def register_node(self, node: DeviceNode) -> None:
        """Explicitly register or update a node in the registry."""
        with self._lock:
            self._registered_nodes[node.device_id] = node
            if node.capabilities:
                self._manifest_cache[node.device_id] = node.capabilities

    def remove_node(self, device_id: str) -> None:
        """Remove a node from runtime caches upon device revocation."""
        with self._lock:
            self._active_sessions.pop(device_id, None)
            self._discovered_candidates.pop(device_id, None)
            self._manifest_cache.pop(device_id, None)
            self._registered_nodes.pop(device_id, None)
            self._permission_profiles.pop(device_id, None)
            try:
                self.db_manager.delete_setting(f"device_profile:{device_id}")
            except Exception:
                pass

    def set_permission_profile(self, device_id: str, profile: str) -> None:
        """Set and persist the active permission profile for a device.

        Rejects unknown/invalid tier strings with ValueError instead of elevating defaults.
        """
        clean = (profile or "").strip().lower()
        if clean not in VALID_PERMISSION_PROFILES:
            raise ValueError(
                f"Invalid permission tier '{profile}'. Must be one of: {', '.join(VALID_PERMISSION_PROFILES)}."
            )
        with self._lock:
            self._permission_profiles[device_id] = clean
            try:
                self.db_manager.set_setting(f"device_profile:{device_id}", clean)
            except Exception as exc:
                logger.warning("Failed persisting device profile for [%s]: %s", device_id, exc)

    def get_permission_profile(self, device_id: str) -> str:
        """Get the active permission profile for a device (fails closed on corrupt stored tier)."""
        with self._lock:
            if device_id in self._permission_profiles:
                return self._permission_profiles[device_id]
            try:
                saved = self.db_manager.get_setting(f"device_profile:{device_id}")
                if isinstance(saved, str):
                    clean = saved.strip().lower()
                    if clean in VALID_PERMISSION_PROFILES:
                        self._permission_profiles[device_id] = clean
                        return clean
                    self._permission_profiles[device_id] = "not_allowed"
                    return "not_allowed"
            except Exception:
                pass
            return "full_control"

    def get_node(self, device_id: str) -> Optional[DeviceNode]:
        """Synthesize and return the current state of a node by device_id."""
        with self._lock:
            # 1. Local node
            if device_id == self.local_identity.device_id:
                self.local_node.transport = "local"
                return self.local_node

            # 2. Check explicitly registered nodes
            if device_id in self._registered_nodes:
                return self._registered_nodes[device_id]

            # 3. Check SQLite paired records (authoritative pairing and trust source)
            paired_record = self.db_manager.get_paired_device(device_id)

            # 4. Check active session
            active_session = self._active_sessions.get(device_id)

            # 5. Check discovery candidate
            discovery = self._discovered_candidates.get(device_id)
            if not discovery and self.discovery_service:
                # Check underlying discovery service if available
                peer_record = getattr(self.discovery_service, "get_peer", lambda x: None)(device_id)
                if peer_record:
                    discovery = {
                        "device_id": peer_record.device_id,
                        "device_name": peer_record.device_name,
                        "platform": peer_record.device_type,
                        "host": peer_record.ip_address,
                        "port": peer_record.port,
                        "transfer_port": peer_record.transfer_port,
                        "cert_fingerprint": peer_record.cert_fingerprint,
                        "last_seen": peer_record.last_seen_timestamp,
                    }

            if not paired_record and not active_session and not discovery:
                return None

            # Resolve capabilities
            manifest = self._manifest_cache.get(device_id)
            if not manifest and paired_record and paired_record.capabilities_json:
                manifest = CapabilityManifest.from_json(paired_record.capabilities_json)
                self._manifest_cache[device_id] = manifest

            # Determine reachability state
            reachability_state: ReachabilityState
            host: Optional[str] = None
            port: int = 8765
            transfer_port: int = 8766
            now = time.time()
            last_seen = now

            if active_session:
                reachability_state = ReachabilityState.CONNECTED_SESSION
                host = active_session["host"]
                port = active_session["port"]
                last_seen = active_session["last_seen"]
            elif discovery and (now - discovery["last_seen"]) <= 30.0:
                reachability_state = ReachabilityState.LAN_DISCOVERABLE
                host = discovery["host"]
                port = discovery["port"]
                transfer_port = discovery["transfer_port"]
                last_seen = discovery["last_seen"]
            elif paired_record and paired_record.last_known_host:
                reachability_state = ReachabilityState.LAST_KNOWN_IP_DIRECT
                host = paired_record.last_known_host
                port = paired_record.last_known_port or 8765
                last_seen = now  # Fallback
            else:
                reachability_state = ReachabilityState.UNREACHABLE_OFFLINE

            # Build platform and profile
            platform_str = "unknown"
            profile = ReachabilityProfile.ACTIVE_SESSION_PEER
            device_name = "Unknown Node"
            trust_tier = None
            is_paired = False
            is_authed = bool(active_session)

            if paired_record:
                device_name = paired_record.device_name
                platform_str = paired_record.platform or "android"
                profile_val = paired_record.reachability_profile or "ACTIVE_SESSION_PEER"
                try:
                    profile = ReachabilityProfile(profile_val)
                except ValueError:
                    profile = ReachabilityProfile.ACTIVE_SESSION_PEER
                trust_tier = paired_record.trust_tier
                is_paired = True
            elif discovery:
                device_name = discovery["device_name"]
                platform_str = discovery["platform"]

            caps_list = manifest.supported_capabilities if manifest else []
            perms_dict = manifest.permission_states if manifest else {}

            return DeviceNode(
                device_id=device_id,
                device_name=device_name,
                platform=platform_str,
                protocol_version=1,
                reachability_profile=profile,
                reachability_state=reachability_state,
                host=host,
                wss_port=port,
                transfer_port=transfer_port,
                supported_capabilities=caps_list,
                permission_states=perms_dict,
                last_seen_timestamp=last_seen,
                trust_tier=trust_tier,
                capabilities=manifest,
                is_authenticated=is_authed,
                is_paired=is_paired,
                transport=active_session.get("transport", "unknown") if active_session else "offline",
                connection_mode=getattr(paired_record, "connection_mode", "auto") if paired_record else "auto",
                permission_profile=self._permission_profiles.get(device_id, "full_control"),
            )

    def list_nodes(
        self, filter_paired: bool = False, filter_connected: bool = False
    ) -> list[DeviceNode]:
        """List all synthesized nodes known to the registry."""
        with self._lock:
            known_ids: set[str] = set()

            # 1. Local node
            known_ids.add(self.local_identity.device_id)

            # 2. Paired devices
            try:
                for p in self.db_manager.list_paired_devices():
                    known_ids.add(p.device_id)
            except Exception as exc:
                logger.debug("Failed listing paired devices: %s", exc)

            # 3. Active sessions
            for dev_id in self._active_sessions.keys():
                known_ids.add(dev_id)

            # 4. Discovered candidates
            for dev_id in self._discovered_candidates.keys():
                known_ids.add(dev_id)

            # 5. Explicitly registered nodes
            for dev_id in self._registered_nodes.keys():
                known_ids.add(dev_id)

            nodes: list[DeviceNode] = []
            for dev_id in known_ids:
                node = self.get_node(dev_id)
                if not node:
                    continue
                if filter_paired and not node.is_paired:
                    continue
                if filter_connected and not node.is_connected:
                    continue
                nodes.append(node)

            return nodes

    # =========================================================================
    # Target Resolution API
    # =========================================================================

    def resolve_target(
        self,
        target_query: str = "",
        required_capability: Optional[str] = None,
    ) -> tuple[Optional[DeviceNode], Optional[str]]:
        """Resolve a device query and verify capability support.

        Args:
            target_query: Empty string for default resolution, or UUID/name/prefix.
            required_capability: Optional capability string that the target must advertise.

        Returns:
            Tuple of (DeviceNode, None) on success, or (None, ErrorCode) on failure.
            Possible error codes:
            - NO_DEVICES_PAIRED: Empty query and zero paired peers exist.
            - DEVICE_REQUIRED: Empty query but multiple paired/connected peers exist.
            - DEVICE_NOT_FOUND: Query matched 0 devices.
            - AMBIGUOUS_DEVICE: Query matched > 1 devices.
            - CAPABILITY_NOT_SUPPORTED: Resolved node does not support required_capability.
        """
        with self._lock:
            # Fast-path: exact in-memory registered node lookup
            if target_query:
                clean_q = target_query.strip()
                fast_node = self._registered_nodes.get(clean_q)
                if fast_node and fast_node.device_id != self.local_identity.device_id:
                    if required_capability and not fast_node.supports_capability(required_capability):
                        return None, "CAPABILITY_NOT_SUPPORTED"
                    return fast_node, None

            # Candidate pool excludes the local node for remote operations
            all_nodes = [
                n for n in self.list_nodes()
                if n.device_id != self.local_identity.device_id
            ]

            # Case A: Default resolution (empty query)
            if not target_query or not target_query.strip():
                # Prefer active connected sessions
                connected_peers = [n for n in all_nodes if n.is_connected and n.is_paired]
                if len(connected_peers) == 1:
                    resolved = connected_peers[0]
                elif len(connected_peers) > 1:
                    return None, "DEVICE_REQUIRED"
                else:
                    # Fall back to paired devices
                    paired_peers = [n for n in all_nodes if n.is_paired]
                    if len(paired_peers) == 0:
                        return None, "NO_DEVICES_PAIRED"
                    elif len(paired_peers) == 1:
                        resolved = paired_peers[0]
                    else:
                        return None, "DEVICE_REQUIRED"

                # Check required capability
                if required_capability:
                    if not resolved.supports_capability(required_capability):
                        return None, "CAPABILITY_NOT_SUPPORTED"
                return resolved, None

            # Case B: Query-based resolution
            query = target_query.strip().lower()

            # Generic mobile alias fast-path if query is a generic alias
            if query in ("phone", "android", "mobile"):
                connected_peers = [n for n in all_nodes if n.is_connected and n.is_paired]
                if len(connected_peers) == 1:
                    resolved = connected_peers[0]
                    if required_capability and not resolved.supports_capability(required_capability):
                        return None, "CAPABILITY_NOT_SUPPORTED"
                    return resolved, None
                elif len(connected_peers) > 1:
                    return None, "DEVICE_REQUIRED"
                else:
                    paired_peers = [n for n in all_nodes if n.is_paired]
                    if len(paired_peers) == 1:
                        resolved = paired_peers[0]
                        if required_capability and not resolved.supports_capability(required_capability):
                            return None, "CAPABILITY_NOT_SUPPORTED"
                        return resolved, None
                    elif len(paired_peers) > 1:
                        return None, "DEVICE_REQUIRED"

            # 1. Exact UUID match
            for node in all_nodes:
                if node.device_id.lower() == query:
                    if required_capability and not node.supports_capability(required_capability):
                        return None, "CAPABILITY_NOT_SUPPORTED"
                    return node, None

            # 2. Exact device name match (case-insensitive)
            exact_name_matches = [
                n for n in all_nodes
                if n.device_name.lower() == query
            ]
            if len(exact_name_matches) == 1:
                resolved = exact_name_matches[0]
                if required_capability and not resolved.supports_capability(required_capability):
                    return None, "CAPABILITY_NOT_SUPPORTED"
                return resolved, None
            elif len(exact_name_matches) > 1:
                return None, "AMBIGUOUS_DEVICE"

            # 3. Unambiguous prefix or substring match
            partial_matches: list[DeviceNode] = []
            for node in all_nodes:
                if query in node.device_id.lower() or query in node.device_name.lower():
                    partial_matches.append(node)

            if len(partial_matches) == 1:
                resolved = partial_matches[0]
                if required_capability and not resolved.supports_capability(required_capability):
                    return None, "CAPABILITY_NOT_SUPPORTED"
                return resolved, None
            elif len(partial_matches) > 1:
                return None, "AMBIGUOUS_DEVICE"

            # 4. Semantic platform / device type match (e.g. query is "android" or "phone")
            if query in ("android", "phone"):
                android_matches = [
                    n for n in all_nodes
                    if (getattr(n, "platform", "") or "").lower() == "android"
                    or (getattr(n, "device_type", "") or "").lower() in ("android", "phone")
                ]
                connected_android = [n for n in android_matches if n.is_connected]
                if len(connected_android) == 1:
                    resolved = connected_android[0]
                    if required_capability and not resolved.supports_capability(required_capability):
                        return None, "CAPABILITY_NOT_SUPPORTED"
                    return resolved, None
                elif len(android_matches) == 1:
                    resolved = android_matches[0]
                    if required_capability and not resolved.supports_capability(required_capability):
                        return None, "CAPABILITY_NOT_SUPPORTED"
                    return resolved, None
                elif len(android_matches) > 1:
                    return None, "AMBIGUOUS_DEVICE"

            return None, "DEVICE_NOT_FOUND"
