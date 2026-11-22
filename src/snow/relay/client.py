"""Alias re-export for RelayTunnelClient and deterministic TLS role negotiation."""

from snow.network.relay_client import (
    RelayTunnelClient,
    TUNNEL_INIT_SIGNAL,
    is_tls_server_role,
)

__all__ = [
    "RelayTunnelClient",
    "TUNNEL_INIT_SIGNAL",
    "is_tls_server_role",
]
