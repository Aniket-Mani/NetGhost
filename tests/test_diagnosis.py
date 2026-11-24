
from netghost.engine.diagnosis import diagnose_investigation


def make_evidence(tool, result, role=None):
    item = {
        "tool": tool,
        "result": result,
        "successful": True,
    }

    if role:
        item["role"] = role

    return item


def make_latency(target, avg, loss=0.0):
    return {
        "status": "success",
        "target": target,
        "statistics": {
            "avg_ms": avg,
            "packet_loss_percent": loss,
        },
    }


def test_slow_internet_with_healthy_gateway_and_external_path():
    investigation = {
        "status": "completed",
        "category": "slow",
        "evidence": [
            make_evidence(
                "netghost_measure_latency",
                make_latency("192.168.1.1", 4.0),
                "gateway_latency",
            ),
            make_evidence(
                "netghost_measure_latency",
                make_latency("google.com", 57.0),
            ),
        ],
    }

    result = diagnose_investigation(investigation)

    assert result["status"] == "completed"
    assert result["hypotheses"][0]["cause"] == "no_obvious_latency_anomaly"


def test_slow_internet_with_high_external_latency():
    investigation = {
        "status": "completed",
        "category": "slow",
        "evidence": [
            make_evidence(
                "netghost_measure_latency",
                make_latency("192.168.1.1", 4.0),
                "gateway_latency",
            ),
            make_evidence(
                "netghost_measure_latency",
                make_latency("google.com", 220.0),
            ),
        ],
    }

    result = diagnose_investigation(investigation)

    causes = [item["cause"] for item in result["hypotheses"]]

    assert "upstream_or_destination_path_issue" in causes


def test_slow_internet_with_high_gateway_latency():
    investigation = {
        "status": "completed",
        "category": "slow",
        "evidence": [
            make_evidence(
                "netghost_measure_latency",
                make_latency("192.168.1.1", 80.0),
                "gateway_latency",
            ),
            make_evidence(
                "netghost_measure_latency",
                make_latency("google.com", 220.0),
            ),
        ],
    }

    result = diagnose_investigation(investigation)

    causes = [item["cause"] for item in result["hypotheses"]]

    assert "local_network_or_gateway_issue" in causes


def test_dns_nxdomain_identifies_missing_domain():
    investigation = {
        "status": "completed",
        "category": "dns",
        "evidence": [
            make_evidence(
                "netghost_dns_lookup",
                {
                    "status": "nxdomain",
                    "domain": "missing.example",
                },
            ),
        ],
    }

    result = diagnose_investigation(investigation)

    assert result["hypotheses"][0]["cause"] == "domain_not_found"
    assert result["hypotheses"][0]["confidence"] == "high"


def test_dns_timeout_suggests_resolver_or_path_problem():
    investigation = {
        "status": "completed",
        "category": "dns",
        "evidence": [
            make_evidence(
                "netghost_dns_configuration",
                {
                    "status": "success",
                    "nameservers": ["192.168.1.1"],
                },
            ),
            make_evidence(
                "netghost_dns_lookup",
                {
                    "status": "timeout",
                    "domain": "google.com",
                },
            ),
        ],
    }

    result = diagnose_investigation(investigation)

    assert (
        result["hypotheses"][0]["cause"]
        == "dns_resolver_or_path_problem"
    )


def test_packet_loss_is_reported():
    investigation = {
        "status": "completed",
        "category": "packet_loss",
        "evidence": [
            make_evidence(
                "netghost_measure_packet_loss",
                {
                    "status": "success",
                    "target": "google.com",
                    "packet_loss_percent": 20.0,
                },
            ),
        ],
    }

    result = diagnose_investigation(investigation)

    assert result["hypotheses"][0]["cause"] == "packet_loss_observed"


def test_incomplete_traceroute_is_not_claimed_as_destination_failure():
    investigation = {
        "status": "completed",
        "category": "unreachable",
        "evidence": [
            make_evidence(
                "netghost_measure_latency",
                {
                    "status": "unreachable",
                    "target": "192.0.2.10",
                },
            ),
            make_evidence(
                "netghost_traceroute",
                {
                    "execution_status": "completed",
                    "route_status": "partial",
                    "destination_reached": False,
                },
            ),
        ],
    }

    result = diagnose_investigation(investigation)

    assert (
        result["hypotheses"][0]["cause"]
        == "target_not_reached_by_probes"
    )

    assert "does not prove" in result["hypotheses"][0]["explanation"]


def test_failed_investigation_does_not_produce_root_cause():
    investigation = {
        "status": "failed",
        "category": "slow",
        "evidence": [],
    }

    result = diagnose_investigation(investigation)

    assert result["status"] == "insufficient_data"
    assert result["hypotheses"] == []


def test_missing_latency_evidence_is_reported():
    investigation = {
        "status": "partial",
        "category": "slow",
        "evidence": [],
    }

    result = diagnose_investigation(investigation)

    assert (
        result["hypotheses"][0]["cause"]
        == "insufficient_latency_evidence"
    )
