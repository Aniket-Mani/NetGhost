
from netghost.engine.correlation import (
    collect_dns_records,
    collect_route_addresses,
    correlate_investigation,
    normalize_ip,
)


def test_normalize_ip():
    assert normalize_ip("8.8.8.8") == "8.8.8.8"
    assert normalize_ip("2001:4860:4860::8888") == (
        "2001:4860:4860::8888"
    )
    assert normalize_ip("invalid") is None
    assert normalize_ip(None) is None


def test_collect_dns_records():
    evidence = [
        {
            "tool": "netghost_dns_lookup",
            "result": {
                "status": "success",
                "domain": "example.com",
                "record_type": "A",
                "records": ["93.184.216.34"],
            },
        },
    ]

    records = collect_dns_records(evidence)

    assert "93.184.216.34" in records
    assert records["93.184.216.34"][0]["domain"] == "example.com"


def test_collect_route_addresses():
    evidence = [
        {
            "tool": "netghost_traceroute",
            "result": {
                "execution_status": "completed",
                "target": "example.com",
                "destination_ip": "93.184.216.34",
                "hops": [
                    {
                        "hop": 1,
                        "address": "192.168.1.1",
                    },
                ],
            },
        },
    ]

    addresses = collect_route_addresses(evidence)

    assert "93.184.216.34" in addresses
    assert "192.168.1.1" in addresses
    assert addresses["192.168.1.1"][0]["location"] == (
        "intermediate_hop"
    )


def test_correlate_process_connection_and_dns():
    investigation = {
        "evidence": [
            {
                "tool": "netghost_active_connections",
                "result": {
                    "status": "success",
                    "connections": [
                        {
                            "protocol": "tcp",
                            "status": "ESTABLISHED",
                            "local_address": {
                                "ip": "192.168.1.10",
                                "port": 50000,
                            },
                            "remote_address": {
                                "ip": "93.184.216.34",
                                "port": 443,
                            },
                            "process": {
                                "pid": 1234,
                                "name": "browser",
                            },
                        },
                    ],
                },
            },
            {
                "tool": "netghost_dns_lookup",
                "result": {
                    "status": "success",
                    "domain": "example.com",
                    "record_type": "A",
                    "records": ["93.184.216.34"],
                },
            },
        ],
    }

    result = correlate_investigation(investigation)

    relationship_types = {
        item["type"] for item in result["relationships"]
    }

    assert "process_owns_connection" in relationship_types
    assert "connection_to_endpoint" in relationship_types
    assert "endpoint_resolves_to_domain" in relationship_types

    assert result["summary"]["connections_inspected"] == 1
    assert result["summary"]["processes_attributed"] == 1
    assert result["summary"]["unmatched_endpoints"] == 0


def test_correlate_connection_with_route():
    investigation = {
        "evidence": [
            {
                "tool": "netghost_active_connections",
                "result": {
                    "status": "success",
                    "connections": [
                        {
                            "remote_address": {
                                "ip": "192.168.1.1",
                                "port": 443,
                            },
                            "process": {
                                "pid": 1234,
                                "name": "browser",
                            },
                        },
                    ],
                },
            },
            {
                "tool": "netghost_traceroute",
                "result": {
                    "execution_status": "completed",
                    "target": "example.com",
                    "destination_ip": "93.184.216.34",
                    "hops": [
                        {
                            "hop": 1,
                            "address": "192.168.1.1",
                        },
                    ],
                },
            },
        ],
    }

    result = correlate_investigation(investigation)

    assert any(
        item["type"] == "endpoint_observed_in_route"
        for item in result["relationships"]
    )


def test_unmatched_endpoint_is_preserved():
    investigation = {
        "evidence": [
            {
                "tool": "netghost_active_connections",
                "result": {
                    "status": "success",
                    "connections": [
                        {
                            "remote_address": {
                                "ip": "203.0.113.10",
                                "port": 443,
                            },
                            "process": None,
                        },
                    ],
                },
            },
        ],
    }

    result = correlate_investigation(investigation)

    assert result["summary"]["unmatched_endpoints"] == 1
    assert (
        result["unmatched_endpoints"][0]["ip"]
        == "203.0.113.10"
    )


def test_invalid_investigation():
    result = correlate_investigation(None)

    assert result["status"] == "invalid_input"
