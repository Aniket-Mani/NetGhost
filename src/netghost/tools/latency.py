
import ipaddress
import platform
import re
import subprocess
import time
from statistics import mean

SUPPORTED_SYSTEMS = {"Darwin", "Linux"}

RTT_PATTERN = re.compile(
    r"time[=<]\s*([\d.]+)\s*ms",
    re.IGNORECASE,
)


def validate_target(target: str) -> bool:
    """
    Validate an IPv4, IPv6 or hostname target.
    """

    if not isinstance(target, str):
        return False

    target = target.strip()

    if not target or len(target) > 253:
        return False

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    hostname = target.rstrip(".")

    labels = hostname.split(".")

    return all(
        label
        and len(label) <= 63
        and re.fullmatch(
            r"[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?",
            label,
        )
        for label in labels
    )


def calculate_statistics(
    latencies: list[float],
    total_probes: int,
) -> dict:
    """
    Calculate latency statistics from successful probes.

    Jitter is the mean absolute difference between
    consecutive successful RTT measurements.
    """

    successful = len(latencies)
    failed = total_probes - successful

    if successful:
        minimum = min(latencies)
        maximum = max(latencies)
        average = mean(latencies)

        jitter = (
            mean([
                abs(latencies[i] - latencies[i - 1])
                for i in range(1, successful)
            ])
            if successful > 1
            else 0.0
        )

    else:
        minimum = None
        maximum = None
        average = None
        jitter = None

    return {
        "sent": total_probes,
        "received": successful,
        "lost": failed,
        "packet_loss_percent": round(
            (failed / total_probes) * 100,
            2,
        ),
        "min_ms": round(minimum, 3) if minimum is not None else None,
        "max_ms": round(maximum, 3) if maximum is not None else None,
        "avg_ms": round(average, 3) if average is not None else None,
        "jitter_ms": round(jitter, 3) if jitter is not None else None,
    }


def measure_latency(
    target: str,
    count: int = 5,
    interval: float = 0.5,
    timeout: float = 2.0,
) -> dict:
    """
    Measure network latency using repeated ICMP probes.

    Each probe runs as an independent ping process.

    Args:
        target: IP address or hostname.
        count: Number of probes.
        interval: Delay between probes.
        timeout: Maximum wait for each probe.

    Returns:
        Structured latency measurement results.
    """

    target = target.strip() if isinstance(target, str) else ""

    if not validate_target(target):
        return {
            "status": "invalid_input",
            "target": target,
            "error": "Invalid target",
        }

    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 20:
        return {
            "status": "invalid_input",
            "target": target,
            "error": "Count must be between 1 and 20",
        }

    if not isinstance(interval, (int, float)) or isinstance(interval, bool) or not 0 <= interval <= 2:
        return {
            "status": "invalid_input",
            "target": target,
            "error": "Interval must be between 0 and 2 seconds",
        }

    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0.2 <= timeout <= 10:
        return {
            "status": "invalid_input",
            "target": target,
            "error": "Timeout must be between 0.2 and 10 seconds",
        }

    system = platform.system()

    if system not in SUPPORTED_SYSTEMS:
        return {
            "status": "unsupported_platform",
            "target": target,
            "error": f"Unsupported platform: {system}",
        }

    latencies = []
    probe_results = []

    for sequence in range(count):

        command = [
            "ping",
            "-n",
            "-c",
            "1",
            target,
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )

            output = result.stdout + result.stderr

            match = RTT_PATTERN.search(output)

            if match:
                latency = float(match.group(1))

                latencies.append(latency)

                probe_results.append({
                    "sequence": sequence + 1,
                    "status": "success",
                    "latency_ms": latency,
                })

            else:
                probe_results.append({
                    "sequence": sequence + 1,
                    "status": "timeout" if "timeout" in output.lower()
                    else "failed",
                    "latency_ms": None,
                })

        except subprocess.TimeoutExpired:
            probe_results.append({
                "sequence": sequence + 1,
                "status": "timeout",
                "latency_ms": None,
            })

        except OSError as exc:
            return {
                "status": "error",
                "target": target,
                "error": str(exc),
                "probes": probe_results,
            }

        if sequence < count - 1 and interval > 0:
            time.sleep(interval)

    statistics = calculate_statistics(latencies, count)

    return {
        "status": "success" if latencies else "unreachable",
        "target": target,
        "platform": system,
        "statistics": statistics,
        "probes": probe_results,
    }


def register_tools(mcp) -> None:
    """
    Register latency diagnostic tools with FastMCP.
    """

    @mcp.tool
    def netghost_measure_latency(
        target: str,
        count: int = 5,
        interval: float = 0.5,
        timeout: float = 2.0,
    ) -> dict:
        """
        Measure network latency to an IP or hostname.

        Returns minimum, maximum, average latency,
        jitter, packet loss and individual probe results.
        """

        return measure_latency(
            target=target,
            count=count,
            interval=interval,
            timeout=timeout,
        )
