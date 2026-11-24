
from netghost.engine.planner import create_investigation_plan


def test_slow_internet_plan():
    plan = create_investigation_plan(
        symptom="slow internet",
        target="google.com",
    )

    assert plan["status"] == "ready"
    assert plan["category"] == "slow"

    tools = [step["tool"] for step in plan["steps"]]

    assert tools == [
        "netghost_network_interfaces",
        "netghost_measure_latency",
        "netghost_measure_packet_loss",
        "netghost_traceroute",
    ]

    assert plan["steps"][0]["run_when"] == "always"
    assert plan["steps"][2]["run_when"] == "if_latency_anomaly"


def test_dns_plan():
    plan = create_investigation_plan(
        symptom="dns failure",
        domain="google.com",
    )

    assert plan["status"] == "ready"
    assert plan["category"] == "dns"

    tools = [step["tool"] for step in plan["steps"]]

    assert tools == [
        "netghost_dns_configuration",
        "netghost_dns_lookup",
    ]

    assert plan["steps"][1]["arguments"]["domain"] == "google.com"


def test_packet_loss_plan():
    plan = create_investigation_plan(
        symptom="packet loss",
        target="1.1.1.1",
    )

    assert plan["status"] == "ready"
    assert plan["category"] == "packet_loss"

    packet_loss_step = plan["steps"][2]

    assert packet_loss_step["tool"] == "netghost_measure_packet_loss"
    assert packet_loss_step["arguments"]["count"] == 20


def test_unreachable_hostname_plan():
    plan = create_investigation_plan(
        symptom="unreachable",
        target="google.com",
    )

    tools = [step["tool"] for step in plan["steps"]]

    assert tools[0] == "netghost_dns_lookup"
    assert "netghost_measure_latency" in tools
    assert "netghost_traceroute" in tools


def test_unreachable_ip_plan():
    plan = create_investigation_plan(
        symptom="unreachable",
        target="1.1.1.1",
    )

    tools = [step["tool"] for step in plan["steps"]]

    assert "netghost_dns_lookup" not in tools
    assert "netghost_measure_latency" in tools
    assert "netghost_traceroute" in tools


def test_general_network_plan():
    plan = create_investigation_plan("general")

    assert plan["status"] == "ready"
    assert plan["category"] == "general"

    assert len(plan["steps"]) == 2


def test_missing_target():
    plan = create_investigation_plan("slow")

    assert plan["status"] == "needs_input"
    assert plan["required_input"] == "target"
    assert plan["steps"] == []


def test_missing_domain():
    plan = create_investigation_plan("dns")

    assert plan["status"] == "needs_input"
    assert plan["required_input"] == "domain"
    assert plan["steps"] == []


def test_invalid_target():
    plan = create_investigation_plan(
        symptom="slow",
        target="invalid target",
    )

    assert plan["status"] == "invalid_input"
    assert plan["steps"] == []


def test_invalid_domain():
    plan = create_investigation_plan(
        symptom="dns",
        domain="not a valid domain",
    )

    assert plan["status"] == "invalid_input"
    assert plan["steps"] == []


def test_unsupported_symptom():
    plan = create_investigation_plan("my laptop is overheating")

    assert plan["status"] == "unsupported_symptom"
    assert plan["steps"] == []


def test_empty_symptom():
    plan = create_investigation_plan("")

    assert plan["status"] == "invalid_input"
    assert plan["steps"] == []


def test_symptom_normalization():
    plan = create_investigation_plan(
        symptom="  SLOW INTERNET  ",
        target="google.com",
    )

    assert plan["category"] == "slow"
    assert plan["status"] == "ready"
