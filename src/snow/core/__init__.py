"""SNOW Core modules."""

from snow.core.config import CoreConfig
from snow.core.network import NetworkInterfaceInfo, detect_usable_ipv4_addresses

__all__ = [
    "CoreConfig",
    "NetworkInterfaceInfo",
    "SnowCoreServer",
    "detect_usable_ipv4_addresses",
]


def __getattr__(name: str):
    if name == "SnowCoreServer":
        from snow.core.server import SnowCoreServer
        return SnowCoreServer
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
