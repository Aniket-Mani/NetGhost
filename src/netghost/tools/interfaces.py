import socket

import psutil

from netghost.utils.platform import get_default_route


def get_network_interfaces() -> dict:
    """
    Retrieve network interfaces and their configuration.
    Includes IP addresses, MAC addresses, interface
    status, speed and network I/O counters.
    """

    try:
        addresses = psutil.net_if_addrs()
        statistics = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True) or {}
    except (OSError, psutil.Error) as exc:
        return {
            "status": "error",
            "interfaces": {},
            "default_gateway": None,
            "default_interface": None,
            "error": f"Unable to inspect network interfaces: {exc}",
        }

    interfaces = {}

    for interface_name, address_list in addresses.items():

        interface_stats = statistics.get(interface_name)
        interface_io = io_counters.get(interface_name)

        ipv4_addresses = []
        ipv6_addresses = []
        mac_address = None

        for address in address_list:
            if address.family == socket.AF_INET:
                ipv4_addresses.append(address.address)

            elif address.family == socket.AF_INET6:
                ipv6_addresses.append(address.address)

            elif address.family == psutil.AF_LINK:
                mac_address = address.address

        interfaces[interface_name] = {
            "ipv4": ipv4_addresses,
            "ipv6": ipv6_addresses,
            "mac_address": mac_address,
            "is_up": (
                interface_stats.isup
                if interface_stats else None
            ),
            "speed_mbps": (
                interface_stats.speed
                if interface_stats else None
            ),
            "mtu": (
                interface_stats.mtu
                if interface_stats else None
            ),
            "bytes_sent": (
                interface_io.bytes_sent
                if interface_io else None
            ),
            "bytes_received": (
                interface_io.bytes_recv
                if interface_io else None
            ),
        }

    default_route = get_default_route()

    return {
        "status": "success",
        "interfaces": interfaces,
        "default_gateway": default_route["gateway"],
        "default_interface": default_route["interface"],
        "gateway_error": default_route["error"],
    }


def register_tools(mcp) -> None:
    """
    Register network interface diagnostic tools.
    """

    @mcp.tool
    def netghost_network_interfaces() -> dict:
        """
        Inspect local network interfaces.

        Returns interface names, IP addresses, MAC addresses,
        operational status, speed, MTU, traffic counters,
        and default gateway information.
        """
        return get_network_interfaces()
