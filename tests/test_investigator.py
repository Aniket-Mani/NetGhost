

from netghost.engine import investigator


def successful_latency(target, avg_ms=20.0, loss=0.0):
    return {
        "status": "success",
        "target": target,
        "statistics": {
            "sent": 5,
            "received": 5,
            "lost": 0,
            "packet_loss_percent": loss,
            "avg_ms": avg_ms,
            "min_ms": avg_ms - 1,
            "max_ms": avg_ms + 1,
            "jitter_ms": 1.0,
        },
    }


def interface_result(gateway="192.168.1.1"):
    return {
        "interfaces": {"en0": {"is_up": True}},
        "default_gateway": gateway,
        "default_interface": "en0",
        "gateway_error": None,
    }


def install_tool_mocks(monkeypatch, **overrides):
    """Replace registered diagnostic functions with test doubles."""

    defaults = {
        "netghost_network_interfaces": lambda: interface_result(),
        "netghost_dns_configuration": lambda: {
            "status": "success",
            "nameservers": ["192.168.1.1"],
            "search_domains": [],
        },
        "netghost_dns_lookup": lambda **kwargs: {
            "status": "success",
            "domain": kwargs["domain"],
            "records": ["93.184.216.34"],
        },
        "netghost_measure_latency": lambda **kwargs: successful_latency(
            kwargs["target"]
        ),
        "netghost_measure_packet_loss": lambda **kwargs: {
            "status": "success",
            "target": kwargs["target"],
            "packet_loss_percent": 0.0,
        },
        "netghost_traceroute": lambda **kwargs: {
            "execution_status": "completed",
            "route_status": "complete",
            "destination_reached": True,
            "target": kwargs["target"],
            "hops": [],
        },
    }

    defaults.update(overrides)
    monkeypatch.setattr(investigator, "TOOL_REGISTRY", defaults)


def test_slow_investigation_executes_gateway_and_target_latency(monkeypatch):
    install_tool_mocks(monkeypatch)

    monkeypatch.setattr(
        investigator,
        "execute_gateway_latency",
        lambda result: successful_latency(
            result["default_gateway"],
            avg_ms=4.0,
        ),
    )

    result = investigator.investigate_network(
        symptom="slow",
        target="google.com",
    )

    assert result["status"] == "completed"
    assert result["execution"]["steps_executed"] == 3

    roles = [
        item.get("role")
        for item in result["evidence"]
    ]

    assert "gateway_latency" in roles
    assert any(
        item["tool"] == "netghost_measure_latency"
        and item.get("role") is None
        and item["result"]["target"] == "google.com"
        for item in result["evidence"]
    )


def test_normal_latency_skips_deeper_diagnostics(monkeypatch):
    install_tool_mocks(monkeypatch)

    monkeypatch.setattr(
        investigator,
        "execute_gateway_latency",
        lambda result: successful_latency(
            result["default_gateway"],
            avg_ms=4.0,
        ),
    )

    result = investigator.investigate_network(
        symptom="slow",
        target="google.com",
    )

    skipped_tools = {
        item["tool"]
        for item in result["trace"]
        if item["status"] == "skipped"
    }

    assert "netghost_measure_packet_loss" in skipped_tools
    assert "netghost_traceroute" in skipped_tools


def test_high_latency_triggers_deeper_diagnostics(monkeypatch):
    install_tool_mocks(
        monkeypatch,
        netghost_measure_latency=lambda **kwargs: successful_latency(
            kwargs["target"],
            avg_ms=220.0,
        ),
    )

    monkeypatch.setattr(
        investigator,
        "execute_gateway_latency",
        lambda result: successful_latency(
            result["default_gateway"],
            avg_ms=4.0,
        ),
    )

    result = investigator.investigate_network(
        symptom="slow",
        target="google.com",
    )

    executed_tools = [
        item["tool"]
        for item in result["evidence"]
    ]

    assert "netghost_measure_packet_loss" in executed_tools
    assert "netghost_traceroute" in executed_tools


def test_failed_diagnostic_does_not_stop_investigation(monkeypatch):
    def failing_interfaces():
        raise RuntimeError("Interface inspection failed")

    install_tool_mocks(
        monkeypatch,
        netghost_network_interfaces=failing_interfaces,
    )

    result = investigator.investigate_network(
        symptom="general",
    )

    assert result["status"] == "partial"
    assert result["evidence"][0]["successful"] is False
    assert result["evidence"][1]["tool"] == "netghost_dns_configuration"
    assert result["evidence"][1]["successful"] is True


def test_missing_gateway_does_not_crash_investigation(monkeypatch):
    install_tool_mocks(
        monkeypatch,
        netghost_network_interfaces=lambda: interface_result(
            gateway=None
        ),
    )

    result = investigator.investigate_network(
        symptom="slow",
        target="google.com",
    )

    assert result["status"] == "completed"

    assert not any(
        item.get("role") == "gateway_latency"
        for item in result["evidence"]
    )


def test_max_steps_is_respected(monkeypatch):
    install_tool_mocks(monkeypatch)

    gateway_calls = []

    def gateway_latency(result):
        gateway_calls.append(result)
        return successful_latency("192.168.1.1", avg_ms=4.0)

    monkeypatch.setattr(
        investigator,
        "execute_gateway_latency",
        gateway_latency,
    )

    result = investigator.investigate_network(
        symptom="slow",
        target="google.com",
        max_steps=1,
    )

    assert result["execution"]["steps_executed"] == 1
    assert len(result["evidence"]) == 1
    assert gateway_calls == []

    assert any(
        item["status"] == "skipped"
        and item["reason"] == "Execution budget exhausted"
        for item in result["trace"]
    )


def test_nxdomain_is_a_successful_diagnostic_execution(monkeypatch):
    install_tool_mocks(
        monkeypatch,
        netghost_dns_lookup=lambda **kwargs: {
            "status": "nxdomain",
            "domain": kwargs["domain"],
            "records": [],
            "error": "Domain does not exist",
        },
    )

    result = investigator.investigate_network(
        symptom="dns",
        domain="nonexistent.example",
    )

    dns_evidence = next(
        item
        for item in result["evidence"]
        if item["tool"] == "netghost_dns_lookup"
    )

    assert dns_evidence["successful"] is True
    assert dns_evidence["result"]["status"] == "nxdomain"
    assert result["status"] == "completed"


def test_incomplete_route_is_not_a_failed_tool_execution(monkeypatch):
    install_tool_mocks(
        monkeypatch,
        netghost_measure_latency=lambda **kwargs: {
            "status": "unreachable",
            "target": kwargs["target"],
            "statistics": {
                "sent": 5,
                "received": 0,
                "lost": 5,
                "packet_loss_percent": 100.0,
                "avg_ms": None,
            },
        },
        netghost_traceroute=lambda **kwargs: {
            "execution_status": "completed",
            "route_status": "partial",
            "destination_reached": False,
            "target": kwargs["target"],
            "hops": [],
        },
    )

    result = investigator.investigate_network(
        symptom="unreachable",
        target="192.0.2.10",
    )

    route_evidence = next(
        item
        for item in result["evidence"]
        if item["tool"] == "netghost_traceroute"
    )

    assert route_evidence["successful"] is True
    assert route_evidence["result"]["destination_reached"] is False
