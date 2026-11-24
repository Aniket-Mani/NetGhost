
import ipaddress
import socket

import psutil

VALID_PROTOCOLS = {"all", "tcp", "udp"}

VALID_STATUSES = {
    "ESTABLISHED",
    "SYN_SENT",
    "SYN_RECV",
    "FIN_WAIT1",
    "FIN_WAIT2",
    "TIME_WAIT",
    "CLOSE",
    "CLOSE_WAIT",
    "LAST_ACK",
    "LISTEN",
    "CLOSING",
    "NONE",
}


def get_address_details(address) -> dict | None:
    """Convert a psutil socket address into a consistent dictionary."""

    if not address:
        return None

    return {
        "ip": address.ip,
        "port": address.port,
    }


def get_process_details(pid: int | None) -> dict:
    """Retrieve process information without failing on permission errors."""

    if pid is None:
        return {
            "pid": None,
            "name": None,
            "lookup_status": "unavailable",
        }

    try:
        process = psutil.Process(pid)

        return {
            "pid": pid,
            "name": process.name(),
            "lookup_status": "success",
        }

    except psutil.ZombieProcess:
        status = "zombie_process"
    except psutil.NoSuchProcess:
        status = "process_terminated"
    except psutil.AccessDenied:
        status = "access_denied"

    return {
        "pid": pid,
        "name": None,
        "lookup_status": status,
    }


def get_connection_protocol(connection) -> str:
    """Determine whether a socket is TCP or UDP."""

    if connection.type == socket.SOCK_STREAM:
        return "tcp"

    if connection.type == socket.SOCK_DGRAM:
        return "udp"

    return "unknown"


def get_active_connections(
    protocol: str = "all",
    status: str | None = None,
    process_name: str | None = None,
    remote_ip: str | None = None,
) -> dict:
    """
    Inspect active IPv4 and IPv6 network connections.

    Supports optional filtering by protocol, connection state,
    process name, and remote IP address.
    """

    if not isinstance(protocol, str):
        return {"status": "invalid_input", "error": "Protocol must be one of: all, tcp, udp", "connections": []}
    protocol = protocol.lower().strip()

    if protocol not in VALID_PROTOCOLS:
        return {
            "status": "invalid_input",
            "error": "Protocol must be one of: all, tcp, udp",
            "connections": [],
        }

    if status is not None:
        if not isinstance(status, str):
            return {"status": "invalid_input", "error": "Unsupported connection status", "connections": []}
        status = status.upper().strip()

        if status not in VALID_STATUSES:
            return {
                "status": "invalid_input",
                "error": "Unsupported connection status",
                "connections": [],
            }

    if process_name is not None:
        if not isinstance(process_name, str) or not process_name.strip():
            return {"status": "invalid_input", "error": "process_name must be a non-empty string", "connections": []}
        process_name = process_name.lower().strip()

    if remote_ip is not None:
        if not isinstance(remote_ip, str):
            return {"status": "invalid_input", "error": "remote_ip must be an IPv4 or IPv6 address", "connections": []}
        try:
            remote_ip = str(ipaddress.ip_address(remote_ip.strip()))
        except ValueError:
            return {"status": "invalid_input", "error": "remote_ip must be an IPv4 or IPv6 address", "connections": []}

    try:
        raw_connections = psutil.net_connections(
            kind="inet" if protocol == "all" else protocol
        )

    except psutil.AccessDenied:
        return {
            "status": "error",
            "error": "Permission denied while inspecting network connections",
            "connections": [],
        }

    except OSError as exc:
        return {
            "status": "error",
            "error": str(exc),
            "connections": [],
        }

    connections = []
    process_cache = {}

    for connection in raw_connections:
        connection_protocol = get_connection_protocol(connection)

        if connection_protocol == "unknown":
            continue

        if protocol != "all" and connection_protocol != protocol:
            continue

        connection_status = connection.status.upper()

        if status is not None and connection_status != status:
            continue

        local_address = get_address_details(connection.laddr)
        remote_address = get_address_details(connection.raddr)

        if remote_ip is not None and (
            not remote_address or remote_address["ip"] != remote_ip
        ):
            continue

        pid = connection.pid

        if pid not in process_cache:
            process_cache[pid] = get_process_details(pid)

        process = process_cache[pid]

        if process_name is not None:
            name = process["name"]

            if not name or process_name not in name.lower():
                continue

        connections.append({
            "protocol": connection_protocol,
            "status": connection_status,
            "local_address": local_address,
            "remote_address": remote_address,
            "process": process.copy(),
            "family": (
                "IPv6"
                if connection.family == socket.AF_INET6
                else "IPv4"
            ),
        })

    tcp_count = sum(
        item["protocol"] == "tcp"
        for item in connections
    )

    udp_count = sum(
        item["protocol"] == "udp"
        for item in connections
    )

    state_counts = {}

    for item in connections:
        connection_status = item["status"]
        state_counts[connection_status] = (
            state_counts.get(connection_status, 0) + 1
        )

    return {
        "status": "success",
        "summary": {
            "total_connections": len(connections),
            "tcp_connections": tcp_count,
            "udp_connections": udp_count,
            "states": state_counts,
        },
        "filters": {
            "protocol": protocol,
            "status": status,
            "process_name": process_name,
            "remote_ip": remote_ip,
        },
        "connections": connections,
    }


def register_tools(mcp) -> None:
    """Register connection inspection as an MCP tool."""

    @mcp.tool
    def netghost_active_connections(
        protocol: str = "all",
        status: str | None = None,
        process_name: str | None = None,
        remote_ip: str | None = None,
    ) -> dict:
        """
        Inspect active TCP and UDP connections on this machine.

        Optionally filter by protocol, state, process name,
        or remote IP address.
        """

        return get_active_connections(
            protocol=protocol,
            status=status,
            process_name=process_name,
            remote_ip=remote_ip,
        )
