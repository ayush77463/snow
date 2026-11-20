"""Network interface detection and usable IPv4 enumeration for SNOW.

Detection Approach:
-------------------
On Windows, network interfaces include physical adapters (Wi-Fi, Ethernet), virtual
adapters (WSL, Hyper-V, VPNs), and loopback interfaces. Inactive adapters often carry
autoconfigured link-local addresses (169.254.x.x) that cannot be used for cross-device
communication.

This module uses `psutil` as its primary detection mechanism because it provides:
1. Interface names (e.g. 'Wi-Fi', 'Ethernet')
2. Interface operational status (isup = True/False)
3. IP address family filtering (AF_INET for IPv4)

A fallback mechanism using standard library `socket` is also provided in case `psutil`
is unavailable or raises unexpected system exceptions.

Limitations & Real-World Reality:
---------------------------------
Discovering a local IPv4 address on an interface indicates only that the laptop possesses
an assigned IP on that network. It DOES NOT prove or guarantee that an external Android
device can route packets to it. Factors such as:
- Access Point (AP) Client Isolation on public/campus Wi-Fi
- Windows Defender Firewall rules
- Virtual adapter priority
can block inbound traffic. Empirical physical-device testing is performed in Phase 1.4.
"""

from dataclasses import dataclass
import ipaddress
import logging
import socket
from typing import List

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NetworkInterfaceInfo:
    """Structured information for an enumerated network interface."""

    interface_name: str
    ip_address: str
    netmask: str | None = None
    is_up: bool = True


def is_usable_ipv4(ip_str: str) -> bool:
    """Validate whether an IPv4 address string is usable for local device communication.

    Excludes:
    - Loopback addresses (127.0.0.0/8)
    - Link-local autoconfiguration addresses (169.254.0.0/16)
    - Unspecified address (0.0.0.0)
    - Multicast addresses (224.0.0.0/4)
    - Broadcast and reserved addresses
    """
    try:
        ip = ipaddress.IPv4Address(ip_str)
    except (ipaddress.AddressValueError, ValueError):
        return False

    if ip.is_loopback:
        return False
    if ip.is_link_local:
        return False
    if ip.is_unspecified:
        return False
    if ip.is_multicast:
        return False
    if ip.is_reserved:
        return False

    return True


def detect_usable_ipv4_addresses() -> List[NetworkInterfaceInfo]:
    """Detect and return usable IPv4 addresses across network interfaces.

    Primary path: Uses `psutil.net_if_addrs()` and `psutil.net_if_stats()` to inspect
    all adapters and their operational status (`isup`).
    
    Fallback path: Uses standard library `socket.gethostbyname_ex()` if `psutil` is
    unavailable.

    Returns:
        List of `NetworkInterfaceInfo` objects, sorted so that active (`is_up=True`)
        interfaces appear first. Returns an empty list if no usable addresses are found.
    """
    interfaces: List[NetworkInterfaceInfo] = []

    try:
        import psutil

        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for iface_name, addr_list in addrs.items():
            iface_stats = stats.get(iface_name)
            is_up = iface_stats.isup if iface_stats else False

            for addr in addr_list:
                # AF_INET corresponds to IPv4
                if addr.family == socket.AF_INET:
                    ip_str = addr.address
                    if is_usable_ipv4(ip_str):
                        interfaces.append(
                            NetworkInterfaceInfo(
                                interface_name=iface_name,
                                ip_address=ip_str,
                                netmask=addr.netmask,
                                is_up=is_up,
                            )
                        )

    except ImportError:
        logger.debug("psutil not installed; falling back to standard library socket detection.")
        interfaces = _detect_via_socket_fallback()
    except Exception as exc:
        logger.warning("Error during psutil network detection (%s); falling back to socket.", exc)
        interfaces = _detect_via_socket_fallback()

    # Prioritize active interfaces (is_up=True first)
    interfaces.sort(key=lambda iface: (not iface.is_up, iface.interface_name))
    return interfaces


def _detect_via_socket_fallback() -> List[NetworkInterfaceInfo]:
    """Fallback IPv4 detection using standard library socket functions."""
    interfaces: List[NetworkInterfaceInfo] = []
    seen_ips = set()

    try:
        hostname = socket.gethostname()
        _, _, ip_list = socket.gethostbyname_ex(hostname)
        for ip_str in ip_list:
            if ip_str not in seen_ips and is_usable_ipv4(ip_str):
                seen_ips.add(ip_str)
                interfaces.append(
                    NetworkInterfaceInfo(
                        interface_name="default",
                        ip_address=ip_str,
                        netmask=None,
                        is_up=True,
                    )
                )
    except Exception as exc:
        logger.debug("Socket fallback IPv4 enumeration failed: %s", exc)

    return interfaces


def get_active_ip_addresses() -> List[str]:
    """Return a deduplicated list of active, usable local IPv4 addresses.

    Filters out loopback, link-local, unspecified, and down interfaces.
    """
    interfaces = detect_usable_ipv4_addresses()
    seen = set()
    active_ips: List[str] = []
    for iface in interfaces:
        if iface.is_up and iface.ip_address not in seen:
            seen.add(iface.ip_address)
            active_ips.append(iface.ip_address)
    # If no up interfaces found, fall back to any usable interface
    if not active_ips:
        for iface in interfaces:
            if iface.ip_address not in seen:
                seen.add(iface.ip_address)
                active_ips.append(iface.ip_address)
    return active_ips


def detect_usb_tethering_interfaces() -> List[NetworkInterfaceInfo]:
    """Detect network interfaces established via physical USB tethering.

    USB tethering presents an actual virtual/physical network adapter to the OS
    (e.g., 'Remote NDIS', 'Apple Mobile Device Ethernet', 'USB Ethernet', or adapter
    names/descriptions indicating RNDIS/USB tethering).

    IMPORTANT DISTINCTION:
    - USB Tethering: Creates a full network interface on Windows with its own subnet
      and assigned IPv4 address.
    - ADB Reverse Mode: Does not create an OS network interface; it tunnels loopback
      ports over the Android Debug Bridge USB transport.
    """
    all_ifaces = detect_usable_ipv4_addresses()
    usb_keywords = (
        "remote ndis",
        "rndis",
        "usb ethernet",
        "apple mobile device ethernet",
        "usb tethering",
        "usb",
    )
    tethering_ifaces: List[NetworkInterfaceInfo] = []
    for iface in all_ifaces:
        name_lower = iface.interface_name.lower()
        if any(kw in name_lower for kw in usb_keywords):
            tethering_ifaces.append(iface)

    return tethering_ifaces
