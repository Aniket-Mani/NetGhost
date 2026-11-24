
import ipaddress
import platform
import re
import shutil
import subprocess

from netghost.tools.latency import validate_target

RTT_PATTERN = re.compile(r"(\d+(?:\.\d+)?)\s*ms", re.IGNORECASE)

DESTINATION_PATTERN = re.compile(
    r"traceroute\s+to\s+.+?\s+\(([^)]+)\)",
    re.IGNORECASE,
)


def extract_destination_ip(output: str) -> str | None:
    """
    Extract the destination IP selected by traceroute.

    Example:
    traceroute to google.com (142.250.134.113), ...
    """

    match = DESTINATION_PATTERN.search(output)

    if not match:
        return None

    candidate = match.group(1).strip()

    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def parse_traceroute_output(
    output: str,
    probes_per_hop: int,
) -> list[dict]:
    """
    Parse numeric traceroute output into structured hop data.
    """

    hops = []

    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.*)$", line)

        if not match:
            continue

        hop_number = int(match.group(1))
        content = match.group(2)

        address = None

        for token in content.split():
            candidate = token.strip("(),")

            try:
                address = str(ipaddress.ip_address(candidate))
                break
            except ValueError:
                continue

        latencies = [
            float(value)
            for value in RTT_PATTERN.findall(content)
        ]

        received = len(latencies)
        lost = max(0, probes_per_hop - received)

        hops.append({
            "hop": hop_number,
            "address": address,
            "status": "responded" if received else "timeout",
            "probes_sent": probes_per_hop,
            "probes_received": received,
            "probes_lost": lost,
            "latencies_ms": latencies,
            "min_ms": round(min(latencies), 3) if latencies else None,
            "avg_ms": round(
                sum(latencies) / len(latencies), 3
            ) if latencies else None,
            "max_ms": round(max(latencies), 3) if latencies else None,
        })

    return hops


def trace_route(
    target: str,
    max_hops: int = 10,
    probes_per_hop: int = 2,
    timeout: float = 1.0,
    protocol: str = "udp",
) -> dict:
    """
    Trace the network route to a destination.

    Uses the native traceroute utility on macOS/Linux.

    Args:
        target: IP address or hostname.
        max_hops: Maximum TTL / route hops.
        probes_per_hop: Number of probes per hop.
        timeout: Maximum wait per probe in seconds.
        protocol: Probe protocol, either "udp" or "icmp".
    """

    target = target.strip() if isinstance(target, str) else ""

    if not validate_target(target):
        return {
            "execution_status": "invalid_input",
            "target": target,
            "error": "Invalid target",
        }

    if not isinstance(max_hops, int) or isinstance(max_hops, bool) or not 1 <= max_hops <= 30:
        return {
            "execution_status": "invalid_input",
            "target": target,
            "error": "max_hops must be an integer between 1 and 30",
        }

    if (
        not isinstance(probes_per_hop, int)
        or isinstance(probes_per_hop, bool)
        or not 1 <= probes_per_hop <= 5
    ):
        return {
            "execution_status": "invalid_input",
            "target": target,
            "error": "probes_per_hop must be an integer between 1 and 5",
        }

    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not 0.5 <= timeout <= 5
    ):
        return {
            "execution_status": "invalid_input",
            "target": target,
            "error": "timeout must be between 0.5 and 5 seconds",
        }

    if not isinstance(protocol, str) or protocol not in {"udp", "icmp"}:
        return {
            "execution_status": "invalid_input",
            "target": target,
            "error": "protocol must be either 'udp' or 'icmp'",
        }

    system = platform.system()

    if system not in {"Darwin", "Linux"}:
        return {
            "execution_status": "unsupported_platform",
            "target": target,
            "error": f"Unsupported platform: {system}",
        }

    executable = shutil.which("traceroute")

    if executable is None:
        return {
            "execution_status": "dependency_missing",
            "target": target,
            "error": "traceroute executable was not found",
        }

    # macOS BSD traceroute expects an integer wait time.
    effective_timeout = (
        max(1, int(timeout))
        if system == "Darwin"
        else float(timeout)
    )

    command = [executable, "-n"]

    if protocol == "icmp":
        if system == "Darwin":
            command.extend(["-P", "icmp"])
        else:
            command.append("-I")

    command.extend([
        "-m", str(max_hops),
        "-q", str(probes_per_hop),
        "-w", str(effective_timeout),
        target,
    ])

    # Keep execution within a bounded MCP request duration.
    calculated_timeout = (
        max_hops * probes_per_hop * effective_timeout + 5
    )
    total_timeout = min(calculated_timeout, 45)

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=total_timeout,
            check=False,
        )

        output = result.stdout + "\n" + result.stderr

        hops = parse_traceroute_output(
            output,
            probes_per_hop,
        )

        if not hops:
            return {
                "execution_status": "failed",
                "route_status": "inconclusive",
                "destination_reached": None,
                "target": target,
                "protocol": protocol,
                "error": output.strip() or "No traceroute hops returned",
            }

        destination_ip = extract_destination_ip(output)

        responding = [
            hop for hop in hops
            if hop["status"] == "responded"
        ]

        non_responding = [
            hop for hop in hops
            if hop["status"] == "timeout"
        ]

        destination_reached = None

        if destination_ip is not None:
            destination_reached = any(
                hop["address"] == destination_ip
                for hop in responding
            )

        if destination_reached is True:
            route_status = "complete"
        elif destination_reached is False and responding:
            route_status = "partial"
        elif destination_reached is False:
            route_status = "inconclusive"
        else:
            route_status = "unknown"

        return {
            "execution_status": "completed",
            "route_status": route_status,
            "destination_reached": destination_reached,
            "target": target,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "platform": system,
            "max_hops": max_hops,
            "probes_per_hop": probes_per_hop,
            "total_hops": len(hops),
            "responding_hops": len(responding),
            "non_responding_hops": len(non_responding),
            "hops": hops,
        }

    except subprocess.TimeoutExpired:
        return {
            "execution_status": "timeout",
            "route_status": "inconclusive",
            "destination_reached": None,
            "target": target,
            "protocol": protocol,
            "error": "Traceroute exceeded its execution time limit",
        }

    except OSError as exc:
        return {
            "execution_status": "failed",
            "route_status": "inconclusive",
            "destination_reached": None,
            "target": target,
            "protocol": protocol,
            "error": str(exc),
        }


def register_tools(mcp) -> None:
    """
    Register routing diagnostic tools with FastMCP.
    """

    @mcp.tool
    def netghost_traceroute(
        target: str,
        max_hops: int = 10,
        probes_per_hop: int = 2,
        timeout: float = 1.0,
        protocol: str = "udp",
    ) -> dict:
        """
        Trace the network path to a destination.

        Supports UDP and ICMP probing.
        Returns intermediate hops, IP addresses,
        per-hop latency, and destination reachability.
        """

        return trace_route(
            target=target,
            max_hops=max_hops,
            probes_per_hop=probes_per_hop,
            timeout=timeout,
            protocol=protocol,
        )
