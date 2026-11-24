
import ipaddress

CONNECTIONS_TOOL = "netghost_active_connections"
DNS_TOOL = "netghost_dns_lookup"
ROUTE_TOOL = "netghost_traceroute"


def normalize_ip(value: str | None) -> str | None:
    """Return a canonical IP address or None for invalid input."""

    if not isinstance(value, str) or not value.strip():
        return None

    address = value.strip().split("%", 1)[0]

    try:
        return str(ipaddress.ip_address(address))
    except ValueError:
        return None


def get_successful_results(
    evidence: list[dict],
    tool_name: str,
) -> list[tuple[int, dict]]:
    """Return successful results with their original evidence indexes."""

    results = []

    for index, item in enumerate(evidence):
        if item.get("tool") != tool_name:
            continue

        result = item.get("result")

        if not isinstance(result, dict):
            continue

        if tool_name == ROUTE_TOOL:
            successful = result.get("execution_status") == "completed"
        else:
            successful = result.get("status") == "success"

        if successful:
            results.append((index, result))

    return results


def collect_dns_records(evidence: list[dict]) -> dict:
    """Index successful A and AAAA DNS records by their resolved IP."""

    records_by_ip = {}

    for evidence_index, result in get_successful_results(
        evidence,
        DNS_TOOL,
    ):
        record_type = result.get("record_type")

        if record_type not in {"A", "AAAA"}:
            continue

        domain = result.get("domain")
        records = result.get("records", [])

        if not isinstance(domain, str) or not isinstance(records, list):
            continue

        for record_index, record in enumerate(records):
            ip_address = normalize_ip(record)

            if ip_address is None:
                continue

            records_by_ip.setdefault(ip_address, []).append({
                "domain": domain,
                "record_type": record_type,
                "evidence_index": evidence_index,
                "record_index": record_index,
            })

    return records_by_ip


def collect_route_addresses(evidence: list[dict]) -> dict:
    """Index destination and intermediate hop addresses from traceroutes."""

    addresses = {}

    for evidence_index, result in get_successful_results(
        evidence,
        ROUTE_TOOL,
    ):
        destination_ip = normalize_ip(result.get("destination_ip"))

        if destination_ip:
            addresses.setdefault(destination_ip, []).append({
                "evidence_index": evidence_index,
                "target": result.get("target"),
                "location": "destination",
                "hop": None,
            })

        hops = result.get("hops", [])

        if not isinstance(hops, list):
            continue

        for hop in hops:
            if not isinstance(hop, dict):
                continue

            hop_ip = normalize_ip(hop.get("address"))

            if hop_ip is None:
                continue

            addresses.setdefault(hop_ip, []).append({
                "evidence_index": evidence_index,
                "target": result.get("target"),
                "location": "intermediate_hop",
                "hop": hop.get("hop"),
            })

    return addresses


def correlate_investigation(investigation: dict) -> dict:
    """
    Correlate process, connection, DNS and route observations.

    Relationships are based only on matching identifiers observed
    in the collected evidence. They do not establish malicious intent.
    """

    if not isinstance(investigation, dict):
        return {
            "status": "invalid_input",
            "error": "Investigation must be a dictionary",
            "relationships": [],
        }

    evidence = investigation.get("evidence", [])

    if not isinstance(evidence, list):
        return {
            "status": "invalid_input",
            "error": "Investigation evidence must be a list",
            "relationships": [],
        }

    relationships = []
    unmatched_endpoints = []
    unmatched_dns_records = []
    connections_without_remote_endpoint = []

    dns_by_ip = collect_dns_records(evidence)
    routes_by_ip = collect_route_addresses(evidence)

    matched_dns = set()
    matched_routes = set()
    observed_endpoints = set()

    connection_count = 0
    process_count = 0

    connection_results = get_successful_results(
        evidence,
        CONNECTIONS_TOOL,
    )

    for evidence_index, result in connection_results:
        connections = result.get("connections", [])

        if not isinstance(connections, list):
            continue

        for connection_index, connection in enumerate(connections):
            if not isinstance(connection, dict):
                continue

            connection_count += 1

            connection_ref = {
                "evidence_index": evidence_index,
                "connection_index": connection_index,
            }

            process = connection.get("process")

            if isinstance(process, dict):
                pid = process.get("pid")
                name = process.get("name")

                if pid is not None or name:
                    process_count += 1

                    relationships.append({
                        "type": "process_owns_connection",
                        "source": {
                            "type": "process",
                            "pid": pid,
                            "name": name,
                        },
                        "target": {
                            "type": "connection",
                            **connection_ref,
                        },
                        "supporting_evidence": [evidence_index],
                    })

            remote_address = connection.get("remote_address")

            remote_ip = (
                normalize_ip(remote_address.get("ip"))
                if isinstance(remote_address, dict)
                else None
            )

            if remote_ip is None:
                connections_without_remote_endpoint.append(
                    connection_ref
                )
                continue

            remote_port = remote_address.get("port")

            endpoint = {
                "type": "endpoint",
                "ip": remote_ip,
                "port": remote_port,
            }

            relationships.append({
                "type": "connection_to_endpoint",
                "source": {
                    "type": "connection",
                    **connection_ref,
                },
                "target": endpoint,
                "supporting_evidence": [evidence_index],
            })

            observed_endpoints.add(remote_ip)

            matched_endpoint = False

            # Match the endpoint against observed DNS records.
            for dns_record in dns_by_ip.get(remote_ip, []):
                dns_evidence_index = dns_record["evidence_index"]
                matched_dns.add(
                    (dns_evidence_index, dns_record["record_index"])
                )
                matched_endpoint = True

                relationships.append({
                    "type": "endpoint_resolves_to_domain",
                    "source": endpoint,
                    "target": {
                        "type": "domain",
                        "name": dns_record["domain"],
                    },
                    "supporting_evidence": [
                        evidence_index,
                        dns_evidence_index,
                    ],
                    "record_type": dns_record["record_type"],
                })

            # Match the endpoint against observed traceroute addresses.
            for route in routes_by_ip.get(remote_ip, []):
                matched_routes.add(
                    (route["evidence_index"], remote_ip)
                )
                matched_endpoint = True

                relationships.append({
                    "type": "endpoint_observed_in_route",
                    "source": endpoint,
                    "target": {
                        "type": "route",
                        "evidence_index": route["evidence_index"],
                        "target": route["target"],
                        "location": route["location"],
                        "hop": route["hop"],
                    },
                    "supporting_evidence": [
                        evidence_index,
                        route["evidence_index"],
                    ],
                })

            if not matched_endpoint:
                unmatched_endpoints.append({
                    **endpoint,
                    "connection": connection_ref,
                    "reason": "No matching DNS or traceroute evidence",
                })

    # Preserve DNS observations that did not match a connection endpoint.
    for ip_address, records in dns_by_ip.items():
        for record in records:
            record_ref = (
                record["evidence_index"],
                record["record_index"],
            )

            if record_ref not in matched_dns:
                unmatched_dns_records.append({
                    "ip": ip_address,
                    **record,
                })

    return {
        "status": "completed",
        "summary": {
            "connections_inspected": connection_count,
            "processes_attributed": process_count,
            "distinct_remote_endpoints": len(observed_endpoints),
            "relationships_found": len(relationships),
            "unmatched_endpoints": len(unmatched_endpoints),
            "unmatched_dns_records": len(unmatched_dns_records),
            "connections_without_remote_endpoint": len(
                connections_without_remote_endpoint
            ),
        },
        "relationships": relationships,
        "unmatched_endpoints": unmatched_endpoints,
        "unmatched_dns_records": unmatched_dns_records,
        "connections_without_remote_endpoint": (
            connections_without_remote_endpoint
        ),
    }
