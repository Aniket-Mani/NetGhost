
import ipaddress

from netghost.tools.latency import validate_target

SYMPTOM_ALIASES = {
    "slow": "slow",
    "slow internet": "slow",
    "high latency": "slow",
    "lag": "slow",
    "dns": "dns",
    "dns failure": "dns",
    "dns not working": "dns",
    "website not resolving": "dns",
    "packet loss": "packet_loss",
    "packet_loss": "packet_loss",
    "connection drops": "packet_loss",
    "unreachable": "unreachable",
    "cannot connect": "unreachable",
    "no connectivity": "unreachable",
    "general": "general",
    "network issue": "general",
    "network activity": "network_activity",
    "network connections": "network_activity",
    "active connections": "network_activity",
    "suspicious connections": "network_activity",
    "connection activity": "network_activity",
}


def is_ip_address(target: str) -> bool:
    """Return whether a target is an IPv4 or IPv6 address."""

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def create_step(
    tool: str,
    arguments: dict,
    purpose: str,
    run_when: str = "always",
) -> dict:
    """Create a standardized diagnostic plan step."""

    return {
        "tool": tool,
        "arguments": arguments,
        "purpose": purpose,
        "run_when": run_when,
    }


def create_investigation_plan(
    symptom: str,
    target: str | None = None,
    domain: str | None = None,
) -> dict:
    """
    Create a diagnostic plan based on a reported network symptom.

    This function does not execute any diagnostic tools.
    It only determines which tools should be used.
    """

    if not isinstance(symptom, str) or not symptom.strip():
        return {
            "status": "invalid_input",
            "error": "A network symptom must be provided",
            "steps": [],
        }

    normalized_symptom = " ".join(symptom.lower().strip().split())
    category = SYMPTOM_ALIASES.get(normalized_symptom)

    if category is None:
        return {
            "status": "unsupported_symptom",
            "symptom": symptom,
            "error": "Unsupported symptom",
            "supported_symptoms": [
                "slow",
                "dns",
                "packet_loss",
                "unreachable",
                "general",
                "network_activity"
            ],
            "steps": [],
        }

    if target is not None:
        target = target.strip()

        if not validate_target(target):
            return {
                "status": "invalid_input",
                "symptom": symptom,
                "error": "Invalid target",
                "steps": [],
            }

    if domain is not None:
        domain = domain.strip().rstrip(".")

        if not validate_target(domain) or is_ip_address(domain):
            return {
                "status": "invalid_input",
                "symptom": symptom,
                "error": "Invalid domain name",
                "steps": [],
            }

    steps = []
    required_input = None

    if category == "slow":
        if not target:
            required_input = "target"
        else:
            steps = [
                create_step(
                    "netghost_network_interfaces",
                    {},
                    "Inspect network interfaces and default gateway",
                ),
                create_step(
                    "netghost_measure_latency",
                    {
                        "target": target,
                        "count": 5,
                        "interval": 0.5,
                        "timeout": 2.0,
                    },
                    "Establish a baseline for network latency",
                ),
                create_step(
                    "netghost_measure_packet_loss",
                    {
                        "target": target,
                        "count": 10,
                        "interval": 0.5,
                        "timeout": 2.0,
                    },
                    "Check for packet loss if latency measurements show an anomaly",
                    "if_latency_anomaly",
                ),
                create_step(
                    "netghost_traceroute",
                    {
                        "target": target,
                        "protocol": "icmp",
                        "max_hops": 10,
                        "probes_per_hop": 2,
                        "timeout": 1.0,
                    },
                    "Inspect the route if latency or packet loss is abnormal",
                    "if_latency_anomaly",
                ),
            ]

    elif category == "dns":
        if not domain:
            required_input = "domain"
        else:
            steps = [
                create_step(
                    "netghost_dns_configuration",
                    {},
                    "Inspect configured DNS nameservers",
                ),
                create_step(
                    "netghost_dns_lookup",
                    {
                        "domain": domain,
                        "record_type": "A",
                        "timeout": 2.0,
                        "lifetime": 4.0,
                    },
                    "Resolve the domain using the configured DNS resolver",
                ),
            ]

    elif category == "packet_loss":
        if not target:
            required_input = "target"
        else:
            steps = [
                create_step(
                    "netghost_network_interfaces",
                    {},
                    "Inspect network interfaces and default gateway",
                ),
                create_step(
                    "netghost_measure_latency",
                    {
                        "target": target,
                        "count": 5,
                        "interval": 0.5,
                        "timeout": 2.0,
                    },
                    "Establish a latency baseline",
                ),
                create_step(
                    "netghost_measure_packet_loss",
                    {
                        "target": target,
                        "count": 20,
                        "interval": 0.5,
                        "timeout": 2.0,
                    },
                    "Measure packet loss over a larger probe sample",
                ),
                create_step(
                    "netghost_traceroute",
                    {
                        "target": target,
                        "protocol": "icmp",
                        "max_hops": 10,
                        "probes_per_hop": 2,
                        "timeout": 1.0,
                    },
                    "Inspect the route if packet loss is detected",
                    "if_packet_loss_detected",
                ),
            ]

    elif category == "unreachable":
        if not target:
            required_input = "target"
        else:
            if not is_ip_address(target):
                steps.append(
                    create_step(
                        "netghost_dns_lookup",
                        {
                            "domain": target,
                            "record_type": "A",
                            "timeout": 2.0,
                            "lifetime": 4.0,
                        },
                        "Check whether the hostname resolves",
                    )
                )

            steps.extend([
                create_step(
                    "netghost_network_interfaces",
                    {},
                    "Inspect local network interfaces and default gateway",
                ),
                create_step(
                    "netghost_measure_latency",
                    {
                        "target": target,
                        "count": 5,
                        "interval": 0.5,
                        "timeout": 2.0,
                    },
                    "Test basic reachability using ICMP",
                ),
                create_step(
                    "netghost_traceroute",
                    {
                        "target": target,
                        "protocol": "icmp",
                        "max_hops": 10,
                        "probes_per_hop": 2,
                        "timeout": 1.0,
                    },
                    "Inspect the route to identify where responses stop",
                    "if_target_unreachable",
                ),
            ])
    elif category == "network_activity":
        steps = [
            create_step(
                "netghost_active_connections",
                {},
                "Inspect active TCP and UDP connections, remote endpoints, "
                "connection states, and associated processes",
            ),
        ]
    elif category == "general":
        steps = [
            create_step(
                "netghost_network_interfaces",
                {},
                "Inspect network interfaces and default gateway",
            ),
            create_step(
                "netghost_dns_configuration",
                {},
                "Inspect configured DNS nameservers",
            ),
        ]

    return {
        "status": "needs_input" if required_input else "ready",
        "symptom": symptom,
        "category": category,
        "required_input": required_input,
        "steps": steps,
    }
