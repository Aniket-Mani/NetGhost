
import subprocess

from netghost.tools import routing
from netghost.tools.routing import (
    extract_destination_ip,
    parse_traceroute_output,
)


def test_parse_traceroute_output():

    output = """
        traceroute to google.com (142.250.0.1), 20 hops max

        1  192.168.1.1  2.123 ms  2.456 ms  3.123 ms
        2  10.0.0.1  10.234 ms  11.456 ms  12.123 ms
        3  * * *
        4  142.250.0.1  50.123 ms  51.456 ms  52.123 ms
        """

    hops = routing.parse_traceroute_output(output, 3)

    assert len(hops) == 4

    assert hops[0]["address"] == "192.168.1.1"
    assert hops[0]["status"] == "responded"
    assert hops[0]["avg_ms"] == 2.567

    assert hops[2]["address"] is None
    assert hops[2]["status"] == "timeout"
    assert hops[2]["probes_lost"] == 3

    assert hops[3]["address"] == "142.250.0.1"


def test_empty_traceroute_output():

    hops = routing.parse_traceroute_output("", 3)

    assert hops == []


def test_invalid_target():

    result = routing.trace_route("invalid target")

    assert result["execution_status"] == "invalid_input"


def test_invalid_max_hops():
    result = routing.trace_route(
        "google.com",
        max_hops=100,
    )

    assert result["execution_status"] == "invalid_input"


def test_invalid_probe_count():
    result = routing.trace_route(
        "google.com",
        probes_per_hop=10,
    )

    assert result["execution_status"] == "invalid_input"


def test_malformed_route_parameters_return_structured_error():
    assert routing.trace_route("example.com", max_hops=True)["execution_status"] == "invalid_input"
    assert routing.trace_route("example.com", protocol=[])["execution_status"] == "invalid_input"


def test_missing_traceroute(monkeypatch):

    monkeypatch.setattr(
        routing.platform,
        "system",
        lambda: "Darwin",
    )

    monkeypatch.setattr(
        routing.shutil,
        "which",
        lambda executable: None,
    )

    result = routing.trace_route("google.com")

    assert result["execution_status"] == "dependency_missing"


def test_successful_traceroute(monkeypatch):

    monkeypatch.setattr(
        routing.platform,
        "system",
        lambda: "Darwin",
    )

    monkeypatch.setattr(
        routing.shutil,
        "which",
        lambda executable: "/usr/sbin/traceroute",
    )

    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout="""
                traceroute to google.com (142.250.134.113), 10 hops max
                1  192.168.1.1  2.123 ms  2.456 ms  3.123 ms
                2  142.250.134.113  10.234 ms  11.456 ms  12.123 ms
                """,
            stderr="",
        )

    monkeypatch.setattr(
        routing.subprocess,
        "run",
        mock_run,
    )

    result = routing.trace_route(
        "google.com",
        max_hops=10,
        probes_per_hop=3,
    )

    assert result["execution_status"] == "completed"
    assert result["route_status"] == "complete"
    assert result["destination_reached"] is True
    assert result["destination_ip"] == "142.250.134.113"
    assert result["responding_hops"] == 2
    assert result["non_responding_hops"] == 0


def test_macos_traceroute_uses_integer_wait_time(monkeypatch):

    monkeypatch.setattr(
        routing.platform,
        "system",
        lambda: "Darwin",
    )

    monkeypatch.setattr(
        routing.shutil,
        "which",
        lambda executable: "/usr/sbin/traceroute",
    )

    captured = {}

    def mock_run(*args, **kwargs):
        captured["command"] = args[0]

        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=" 1  192.168.1.1  2.1 ms\n",
            stderr="",
        )

    monkeypatch.setattr(
        routing.subprocess,
        "run",
        mock_run,
    )

    routing.trace_route(
        target="google.com",
        timeout=2.0,
    )

    command = captured["command"]

    wait_index = command.index("-w")

    assert command[wait_index + 1] == "2"


def test_macos_icmp_uses_bsd_protocol_option(monkeypatch):
    monkeypatch.setattr(routing.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(routing.shutil, "which", lambda executable: "/usr/sbin/traceroute")
    captured = {}

    def mock_run(*args, **kwargs):
        captured["command"] = args[0]
        return subprocess.CompletedProcess(args=args[0], returncode=0, stdout="1  *\n", stderr="")

    monkeypatch.setattr(routing.subprocess, "run", mock_run)
    routing.trace_route("example.com", protocol="icmp")
    assert captured["command"][2:4] == ["-P", "icmp"]

def test_extract_destination_ip():
    output = """
    traceroute to google.com (142.250.134.113), 10 hops max
    """

    assert extract_destination_ip(output) == "142.250.134.113"

def test_extract_destination_ip_missing():
    assert extract_destination_ip("some unrelated output") is None

def test_parse_partial_route():
    output = """
    traceroute to google.com (142.250.134.113), 5 hops max
    1  104.28.0.0  56.105 ms  54.910 ms
    2  *
    3  142.250.166.162  91.753 ms  78.405 ms
    """

    hops = parse_traceroute_output(output, 2)

    assert len(hops) == 3
    assert hops[0]["status"] == "responded"
    assert hops[1]["status"] == "timeout"
    assert hops[2]["status"] == "responded"


def test_destination_reached_at_first_hop():
    output = """
    traceroute to 1.1.1.1 (1.1.1.1), 10 hops max
    1  1.1.1.1  61.825 ms  53.971 ms
    """

    destination = extract_destination_ip(output)
    hops = parse_traceroute_output(output, 2)

    assert destination == "1.1.1.1"
    assert any(hop["address"] == destination for hop in hops)


def test_destination_not_reached():
    output = """
    traceroute to google.com (142.250.134.113), 5 hops max
    1  104.28.0.0  56.105 ms
    2  *
    3  172.70.217.1  54.115 ms
    """

    destination = extract_destination_ip(output)
    hops = parse_traceroute_output(output, 1)

    assert destination == "142.250.134.113"
    assert not any(hop["address"] == destination for hop in hops)
