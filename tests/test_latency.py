
import subprocess

from netghost.tools import latency


def test_target_validation():
    assert latency.validate_target("google.com")
    assert latency.validate_target("192.168.1.1")
    assert latency.validate_target("2001:4860:4860::8888")

    assert not latency.validate_target("")
    assert not latency.validate_target("invalid target")
    assert not latency.validate_target("google.com;whoami")


def test_latency_statistics():

    result = latency.calculate_statistics(
        [10.0, 20.0, 30.0, 40.0],
        5,
    )

    assert result["sent"] == 5
    assert result["received"] == 4
    assert result["lost"] == 1
    assert result["packet_loss_percent"] == 20.0

    assert result["min_ms"] == 10.0
    assert result["max_ms"] == 40.0
    assert result["avg_ms"] == 25.0
    assert result["jitter_ms"] == 10.0


def test_no_successful_probes():

    result = latency.calculate_statistics([], 5)

    assert result["sent"] == 5
    assert result["received"] == 0
    assert result["lost"] == 5
    assert result["packet_loss_percent"] == 100.0
    assert result["avg_ms"] is None
    assert result["jitter_ms"] is None


def test_successful_latency_measurement(monkeypatch):

    monkeypatch.setattr(
        latency.platform,
        "system",
        lambda: "Darwin",
    )

    responses = [
        "64 bytes from 142.250.0.1: icmp_seq=0 ttl=117 time=10.0 ms",
        "64 bytes from 142.250.0.1: icmp_seq=0 ttl=117 time=20.0 ms",
        "64 bytes from 142.250.0.1: icmp_seq=0 ttl=117 time=30.0 ms",
    ]

    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=responses.pop(0),
            stderr="",
        )

    monkeypatch.setattr(
        latency.subprocess,
        "run",
        mock_run,
    )

    result = latency.measure_latency(
        target="google.com",
        count=3,
        interval=0,
    )

    assert result["status"] == "success"
    assert result["statistics"]["received"] == 3
    assert result["statistics"]["avg_ms"] == 20.0
    assert result["statistics"]["min_ms"] == 10.0
    assert result["statistics"]["max_ms"] == 30.0


def test_invalid_probe_count():

    result = latency.measure_latency(
        target="google.com",
        count=100,
    )

    assert result["status"] == "invalid_input"


def test_malformed_probe_parameters_return_structured_error():
    assert latency.measure_latency("example.com", count="5")["status"] == "invalid_input"
    assert latency.measure_latency("example.com", interval="fast")["status"] == "invalid_input"
    assert latency.measure_latency("example.com", timeout=float("nan"))["status"] == "invalid_input"


def test_timeout_probe(monkeypatch):

    monkeypatch.setattr(
        latency.platform,
        "system",
        lambda: "Darwin",
    )

    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=args[0],
            timeout=kwargs["timeout"],
        )

    monkeypatch.setattr(
        latency.subprocess,
        "run",
        mock_run,
    )

    result = latency.measure_latency(
        target="google.com",
        count=1,
        interval=0,
    )

    assert result["status"] == "unreachable"
    assert result["statistics"]["packet_loss_percent"] == 100.0
    assert result["probes"][0]["status"] == "timeout"
