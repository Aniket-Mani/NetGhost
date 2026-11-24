
from netghost.tools.latency import measure_latency


def measure_packet_loss(
    target: str,
    count: int = 20,
    interval: float = 0.5,
    timeout: float = 2.0,
) -> dict:
    """
    Measure packet loss through repeated ICMP probes.

    Reuses the existing latency measurement engine.

    Args:
        target: IP address or hostname.
        count: Number of probes (1-20).
        interval: Delay between probes.
        timeout: Maximum wait per probe.
    """

    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 20:
        return {
            "status": "invalid_input",
            "target": target,
            "error": "Count must be between 1 and 20",
        }

    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or not 0 <= interval <= 2:
        return {"status": "invalid_input", "target": target, "error": "Interval must be between 0 and 2 seconds"}
    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0.2 <= timeout <= 10:
        return {"status": "invalid_input", "target": target, "error": "Timeout must be between 0.2 and 10 seconds"}

    result = measure_latency(
        target=target,
        count=count,
        interval=interval,
        timeout=timeout,
    )

    if result["status"] in {
        "invalid_input",
        "unsupported_platform",
        "error",
    }:
        return result

    statistics = result["statistics"]

    return {
        "status": result["status"],
        "target": result["target"],
        "packet_loss_percent": statistics["packet_loss_percent"],
        "packets_sent": statistics["sent"],
        "packets_received": statistics["received"],
        "packets_lost": statistics["lost"],
        "probes": result["probes"],
    }


def register_tools(mcp) -> None:
    """
    Register packet-loss diagnostic tools.
    """

    @mcp.tool
    def netghost_measure_packet_loss(
        target: str,
        count: int = 20,
        interval: float = 0.5,
        timeout: float = 2.0,
    ) -> dict:
        """
        Measure packet loss to a network destination.

        Returns packets sent, received, lost and
        packet loss percentage.
        """

        return measure_packet_loss(
            target=target,
            count=count,
            interval=interval,
            timeout=timeout,
        )
