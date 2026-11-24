


# Initial investigation heuristics, not universal network standards.
HIGH_GATEWAY_LATENCY_MS = 30.0
HIGH_EXTERNAL_LATENCY_MS = 150.0
EXTERNAL_GATEWAY_GAP_MS = 80.0


def get_tool_results(investigation: dict, tool: str) -> list[dict]:
    """Return evidence entries produced by a particular diagnostic tool."""

    return [
        item
        for item in investigation.get("evidence", [])
        if item.get("tool") == tool
    ]


def get_result(
    investigation: dict,
    tool: str,
    role: str | None = None,
) -> dict | None:
    """Find the latest result for a tool, optionally matching its role."""

    for item in reversed(get_tool_results(investigation, tool)):
        if item.get("role") == role:
            return item.get("result")

    return None


def get_statistics(result: dict | None) -> dict:
    """Extract latency statistics safely."""

    if not isinstance(result, dict):
        return {}

    return result.get("statistics", {})


def add_hypothesis(
    hypotheses: list[dict],
    cause: str,
    explanation: str,
    confidence: str,
    evidence: list[str],
    alternatives: list[str] | None = None,
) -> None:
    """Append a structured root-cause hypothesis."""

    hypotheses.append({
        "cause": cause,
        "explanation": explanation,
        "confidence": confidence,
        "supporting_evidence": evidence,
        "alternatives": alternatives or [],
    })


def diagnose_slow_internet(investigation: dict) -> dict:
    """Correlate gateway and external latency measurements."""

    hypotheses = []
    findings = []

    gateway = get_result(
        investigation,
        "netghost_measure_latency",
        role="gateway_latency",
    )

    external = get_result(
        investigation,
        "netghost_measure_latency",
    )

    gateway_stats = get_statistics(gateway)
    external_stats = get_statistics(external)

    gateway_avg = gateway_stats.get("avg_ms")
    external_avg = external_stats.get("avg_ms")

    gateway_loss = gateway_stats.get("packet_loss_percent")
    external_loss = external_stats.get("packet_loss_percent")

    gateway_available = isinstance(gateway_avg, (int, float))
    external_available = isinstance(external_avg, (int, float))

    if gateway_available:
        findings.append({
            "observation": "Gateway latency measured",
            "value": f"{gateway_avg} ms average",
            "evidence": "gateway_latency",
        })

    if external_available:
        findings.append({
            "observation": "External latency measured",
            "value": f"{external_avg} ms average",
            "evidence": "external_latency",
        })

    if gateway_loss is not None:
        findings.append({
            "observation": "Gateway packet loss",
            "value": f"{gateway_loss}%",
            "evidence": "gateway_latency",
        })

    if external_loss is not None:
        findings.append({
            "observation": "External packet loss",
            "value": f"{external_loss}%",
            "evidence": "external_latency",
        })

    if not gateway_available or not external_available:
        add_hypothesis(
            hypotheses,
            "insufficient_latency_evidence",
            "Both gateway and external latency measurements are needed "
            "to compare local and upstream network behavior.",
            "low",
            [],
            ["Repeat the measurements", "Check whether the gateway is reachable"],
        )

    else:
        gateway_anomaly = (
            gateway_avg > HIGH_GATEWAY_LATENCY_MS
            or (gateway_loss is not None and gateway_loss > 0)
        )

        external_anomaly = (
            external_avg > HIGH_EXTERNAL_LATENCY_MS
            or (external_loss is not None and external_loss > 0)
        )

        if gateway_anomaly:
            add_hypothesis(
                hypotheses,
                "local_network_or_gateway_issue",
                "The gateway measurement shows elevated latency or packet "
                "loss. The issue may be on the local network or gateway path.",
                "medium",
                ["gateway_latency"],
                [
                    "Wi-Fi interference or weak signal",
                    "Router overload",
                    "Local network congestion",
                    "Gateway ICMP rate limiting",
                ],
            )

        if external_anomaly and not gateway_anomaly:
            add_hypothesis(
                hypotheses,
                "upstream_or_destination_path_issue",
                "The external destination shows elevated latency or packet "
                "loss while the gateway measurement does not show the same "
                "anomaly.",
                "medium",
                ["gateway_latency", "external_latency"],
                [
                    "ISP routing or congestion",
                    "Destination-side congestion",
                    "Intermediate network filtering",
                    "Different routing behavior for the destination",
                ],
            )

        if not gateway_anomaly and not external_anomaly:
            add_hypothesis(
                hypotheses,
                "no_obvious_latency_anomaly",
                "The available gateway and external measurements do not "
                "cross the configured investigation thresholds.",
                "medium",
                ["gateway_latency", "external_latency"],
                [
                    "Intermittent congestion outside the sample window",
                    "Application or server-side slowness",
                    "DNS lookup delays",
                    "Throughput limitations not measured by ICMP",
                ],
            )

        if gateway_available and external_available:
            gap = round(external_avg - gateway_avg, 3)

            findings.append({
                "observation": "External-to-gateway latency difference",
                "value": f"{gap} ms",
                "evidence": [
                    "gateway_latency",
                    "external_latency",
                ],
            })

    return {
        "findings": findings,
        "hypotheses": hypotheses,
    }


def diagnose_dns(investigation: dict) -> dict:
    """Interpret DNS lookup outcomes and resolver configuration."""

    findings = []
    hypotheses = []

    configuration = get_result(
        investigation,
        "netghost_dns_configuration",
    )

    lookup = get_result(
        investigation,
        "netghost_dns_lookup",
    )

    if configuration:
        nameservers = configuration.get("nameservers", [])

        findings.append({
            "observation": "Configured DNS nameservers",
            "value": nameservers,
            "evidence": "dns_configuration",
        })

        if not nameservers:
            add_hypothesis(
                hypotheses,
                "dns_configuration_missing",
                "No DNS nameservers were reported by the system resolver.",
                "medium",
                ["dns_configuration"],
                ["Resolver configuration may be unavailable to the process"],
            )

    if lookup:
        status = lookup.get("status")

        findings.append({
            "observation": "DNS lookup outcome",
            "value": status,
            "evidence": "dns_lookup",
        })

        if status == "success":
            add_hypothesis(
                hypotheses,
                "dns_resolution_working",
                "The requested DNS record was resolved successfully.",
                "high",
                ["dns_lookup"],
                ["Other domains or record types may still fail"],
            )

        elif status == "nxdomain":
            add_hypothesis(
                hypotheses,
                "domain_not_found",
                "The DNS resolver returned NXDOMAIN for the requested name.",
                "high",
                ["dns_lookup"],
                [
                    "Misspelled hostname",
                    "Domain does not exist",
                    "Domain or record recently changed",
                ],
            )

        elif status in {"timeout", "no_nameservers", "dns_error"}:
            add_hypothesis(
                hypotheses,
                "dns_resolver_or_path_problem",
                "The DNS query did not complete successfully. The resolver, "
                "network path, or DNS service may be responsible.",
                "medium",
                ["dns_lookup", "dns_configuration"],
                [
                    "DNS server unavailable",
                    "Network filtering",
                    "Temporary resolver failure",
                    "Domain-specific DNS behavior",
                ],
            )

        elif status == "no_answer":
            add_hypothesis(
                hypotheses,
                "requested_record_missing",
                "The lookup completed, but the requested record type "
                "was not returned.",
                "medium",
                ["dns_lookup"],
                ["The domain may use a different record type"],
            )

    if not hypotheses:
        add_hypothesis(
            hypotheses,
            "insufficient_dns_evidence",
            "The investigation did not collect enough DNS evidence "
            "to identify a likely cause.",
            "low",
            [],
        )

    return {
        "findings": findings,
        "hypotheses": hypotheses,
    }


def diagnose_packet_loss(investigation: dict) -> dict:
    """Interpret packet-loss measurements."""

    findings = []
    hypotheses = []

    loss_result = get_result(
        investigation,
        "netghost_measure_packet_loss",
    )

    if not loss_result:
        add_hypothesis(
            hypotheses,
            "insufficient_packet_loss_evidence",
            "No packet-loss measurement was collected.",
            "low",
            [],
        )

        return {
            "findings": findings,
            "hypotheses": hypotheses,
        }

    loss = loss_result.get("packet_loss_percent")

    findings.append({
        "observation": "Measured packet loss",
        "value": f"{loss}%" if loss is not None else "Unavailable",
        "evidence": "packet_loss",
    })

    if isinstance(loss, (int, float)) and loss > 0:
        add_hypothesis(
            hypotheses,
            "packet_loss_observed",
            "ICMP probes to the target experienced packet loss. "
            "The measurement alone does not identify where packets "
            "were lost.",
            "medium",
            ["packet_loss"],
            [
                "Local wireless interference",
                "Network congestion",
                "Intermediate router behavior",
                "Destination ICMP rate limiting",
            ],
        )

    elif loss == 0:
        add_hypothesis(
            hypotheses,
            "no_packet_loss_observed",
            "No packet loss was observed during this measurement window.",
            "medium",
            ["packet_loss"],
            ["Intermittent packet loss outside the sample window"],
        )

    else:
        add_hypothesis(
            hypotheses,
            "packet_loss_measurement_inconclusive",
            "The packet-loss result did not contain a usable percentage.",
            "low",
            ["packet_loss"],
        )

    return {
        "findings": findings,
        "hypotheses": hypotheses,
    }


def diagnose_unreachable(investigation: dict) -> dict:
    """Correlate DNS, latency and route evidence for unreachable targets."""

    findings = []
    hypotheses = []

    dns = get_result(investigation, "netghost_dns_lookup")
    latency = get_result(investigation, "netghost_measure_latency")
    route = get_result(investigation, "netghost_traceroute")

    if dns:
        findings.append({
            "observation": "DNS resolution outcome",
            "value": dns.get("status"),
            "evidence": "dns_lookup",
        })

        if dns.get("status") == "nxdomain":
            add_hypothesis(
                hypotheses,
                "hostname_does_not_resolve",
                "The requested hostname returned NXDOMAIN.",
                "high",
                ["dns_lookup"],
            )

    if latency:
        findings.append({
            "observation": "Target reachability",
            "value": latency.get("status"),
            "evidence": "target_latency",
        })

    if route:
        findings.append({
            "observation": "Traceroute outcome",
            "value": {
                "route_status": route.get("route_status"),
                "destination_reached": route.get("destination_reached"),
            },
            "evidence": "traceroute",
        })

    if latency and latency.get("status") == "unreachable":
        if route and route.get("destination_reached") is False:
            add_hypothesis(
                hypotheses,
                "target_not_reached_by_probes",
                "The target did not respond to latency probes, and "
                "traceroute did not observe the destination. This does "
                "not prove that the destination is offline.",
                "medium",
                ["target_latency", "traceroute"],
                [
                    "ICMP filtering",
                    "Destination firewall",
                    "Intermediate network filtering",
                    "Routing issue",
                    "Destination outage",
                ],
            )

        elif not route:
            add_hypothesis(
                hypotheses,
                "target_not_responding",
                "The target did not respond to latency probes. "
                "A route investigation was not available.",
                "low",
                ["target_latency"],
                [
                    "ICMP filtering",
                    "Destination firewall",
                    "Destination outage",
                ],
            )

    if not hypotheses:
        add_hypothesis(
            hypotheses,
            "insufficient_reachability_evidence",
            "The collected evidence does not establish why the target "
            "was reported as unreachable.",
            "low",
            [],
        )

    return {
        "findings": findings,
        "hypotheses": hypotheses,
    }


def diagnose_general(investigation: dict) -> dict:
    """Summarize basic interface and DNS configuration evidence."""

    findings = []
    hypotheses = []

    interfaces = get_result(
        investigation,
        "netghost_network_interfaces",
    )

    dns = get_result(
        investigation,
        "netghost_dns_configuration",
    )

    if interfaces:
        gateway = interfaces.get("default_gateway")
        interface = interfaces.get("default_interface")

        findings.append({
            "observation": "Default network route",
            "value": {
                "gateway": gateway,
                "interface": interface,
            },
            "evidence": "network_interfaces",
        })

        if not gateway:
            add_hypothesis(
                hypotheses,
                "default_gateway_missing",
                "No default gateway was reported by the interface diagnostic.",
                "medium",
                ["network_interfaces"],
                ["Host may use a non-standard routing configuration"],
            )

    if dns:
        findings.append({
            "observation": "DNS configuration status",
            "value": dns.get("status"),
            "evidence": "dns_configuration",
        })

    if not hypotheses:
        add_hypothesis(
            hypotheses,
            "no_specific_fault_identified",
            "Basic network configuration was inspected, but the collected "
            "evidence is insufficient to identify a specific fault.",
            "low",
            ["network_interfaces", "dns_configuration"],
        )

    return {
        "findings": findings,
        "hypotheses": hypotheses,
    }

def diagnose_network_activity(investigation: dict) -> dict:
    """Summarize active connections without treating them as proof of threats."""

    findings = []
    hypotheses = []

    result = get_result(
        investigation,
        "netghost_active_connections",
    )

    if not result:
        add_hypothesis(
            hypotheses,
            "insufficient_connection_evidence",
            "No active connection inventory was collected.",
            "low",
            [],
        )

        return {
            "findings": findings,
            "hypotheses": hypotheses,
        }

    if result.get("status") in {
        "error",
        "invalid_input",
        "unsupported_platform",
    }:
        add_hypothesis(
            hypotheses,
            "connection_inspection_failed",
            "The active connection inventory could not be collected.",
            "low",
            ["active_connections"],
            [
                "Insufficient permissions",
                "Platform limitations",
                "Temporary operating-system error",
            ],
        )

        return {
            "findings": findings,
            "hypotheses": hypotheses,
        }

    connections = result.get("connections", [])
    summary = result.get("summary", {})

    if not isinstance(connections, list):
        connections = []

    total = summary.get("total_connections", 0)

    findings.append({
        "observation": "Active connection inventory",
        "value": total,
        "evidence": "active_connections",
    })
    correlations = investigation.get("correlations", {})

    if correlations.get("status") == "completed":
        correlation_summary = correlations.get("summary", {})

        findings.append({
            "observation": "Cross-evidence correlation summary",
            "value": {
                "relationships_found": correlation_summary.get(
                    "relationships_found", 0
                ),
                "processes_attributed": correlation_summary.get(
                    "processes_attributed", 0
                ),
                "unmatched_endpoints": correlation_summary.get(
                    "unmatched_endpoints", 0
                ),
                "unmatched_dns_records": correlation_summary.get(
                    "unmatched_dns_records", 0
                ),
            },
            "evidence": "correlations",
        })

        relationship_types = {}

        for relationship in correlations.get("relationships", []):
            relationship_type = relationship.get("type")

            if relationship_type:
                relationship_types[relationship_type] = (
                    relationship_types.get(relationship_type, 0) + 1
                )

        if relationship_types:
            findings.append({
                "observation": "Observed relationship types",
                "value": relationship_types,
                "evidence": "correlations",
            })

    findings.append({
        "observation": "Connection protocol distribution",
        "value": {
            "tcp": summary.get("tcp_connections", 0),
            "udp": summary.get("udp_connections", 0),
        },
        "evidence": "active_connections",
    })

    states = summary.get("states", {})

    if states:
        findings.append({
            "observation": "Connection states",
            "value": states,
            "evidence": "active_connections",
        })

    process_names = set()
    unattributed = 0
    remote_endpoints = set()

    for connection in connections:
        process = connection.get("process")

        if isinstance(process, dict):
            process_name = process.get("name")

            if process_name:
                process_names.add(process_name)
            else:
                unattributed += 1
        else:
            unattributed += 1

        remote = connection.get("remote_address")

        if isinstance(remote, dict) and remote.get("ip"):
            remote_endpoints.add(
                (remote["ip"], remote.get("port"))
            )

    findings.append({
        "observation": "Processes associated with connections",
        "value": sorted(process_names),
        "evidence": "active_connections",
    })

    findings.append({
        "observation": "Distinct remote endpoints",
        "value": len(remote_endpoints),
        "evidence": "active_connections",
    })

    if unattributed:
        add_hypothesis(
            hypotheses,
            "incomplete_process_attribution",
            f"Process attribution was unavailable for {unattributed} "
            "connection entries. This limits the ability to associate "
            "network activity with local applications.",
            "low",
            ["active_connections"],
            [
                "Operating-system permission restrictions",
                "Process terminated during inspection",
                "Process information unavailable",
            ],
        )

    add_hypothesis(
        hypotheses,
        "connection_inventory_collected",
        "Active network connections were inventoried. Further endpoint "
        "and process investigation is required to determine whether "
        "any activity is unusual or potentially malicious.",
        "medium",
        ["active_connections"],
        [
            "A legitimate application may maintain unfamiliar connections",
            "A connection inventory alone cannot establish malicious activity",
        ],
    )

    return {
        "findings": findings,
        "hypotheses": hypotheses,
    }

DIAGNOSERS = {
    "slow": diagnose_slow_internet,
    "dns": diagnose_dns,
    "packet_loss": diagnose_packet_loss,
    "unreachable": diagnose_unreachable,
    "general": diagnose_general,
    "network_activity": diagnose_network_activity,
}


def diagnose_investigation(investigation: dict) -> dict:
    """Generate an evidence-backed assessment from an investigation."""

    if not isinstance(investigation, dict):
        return {
            "status": "invalid_input",
            "error": "Investigation must be a dictionary",
        }

    if investigation.get("status") not in {"completed", "partial"}:
        return {
            "status": "insufficient_data",
            "summary": "The investigation did not complete successfully.",
            "findings": [],
            "hypotheses": [],
        }

    category = investigation.get("category")
    diagnoser = DIAGNOSERS.get(category)

    if diagnoser is None:
        return {
            "status": "unsupported_category",
            "summary": "No diagnosis rules exist for this symptom category.",
            "findings": [],
            "hypotheses": [],
        }

    assessment = diagnoser(investigation)

    hypotheses = assessment["hypotheses"]

    confidence_order = {
        "high": 3,
        "medium": 2,
        "low": 1,
    }

    hypotheses.sort(
        key=lambda item: confidence_order.get(item["confidence"], 0),
        reverse=True,
    )

    if not hypotheses:
        summary = "No root-cause hypothesis could be generated."
    else:
        summary = hypotheses[0]["explanation"]

    return {
        "status": "completed",
        "category": category,
        "summary": summary,
        "findings": assessment["findings"],
        "hypotheses": hypotheses,
        "limitations": [
            (
                "Confidence labels are qualitative rule-based assessments, "
                "not statistical probabilities."
            ),
            "ICMP measurements may be filtered or rate-limited.",
            "A short measurement window cannot rule out intermittent faults.",
            "The evidence may identify a symptom without locating its cause.",
            "Matching IP addresses across DNS, connection, and route evidence establishes an observed association, not proof of a shared session or malicious activity.",
        ],
    }
