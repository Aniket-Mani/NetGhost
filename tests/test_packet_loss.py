
from netghost.tools import packet_loss


def test_successful_packet_loss_measurement(monkeypatch):

    def mock_measure_latency(**kwargs):
        return {
            "status": "success",
            "target": "google.com",
            "statistics": {
                "sent": 20,
                "received": 18,
                "lost": 2,
                "packet_loss_percent": 10.0,
            },
            "probes": [],
        }

    monkeypatch.setattr(
        packet_loss,
        "measure_latency",
        mock_measure_latency,
    )

    result = packet_loss.measure_packet_loss(
        target="google.com",
        count=20,
    )

    assert result["status"] == "success"
    assert result["packets_sent"] == 20
    assert result["packets_received"] == 18
    assert result["packets_lost"] == 2
    assert result["packet_loss_percent"] == 10.0


def test_zero_packet_loss(monkeypatch):

    def mock_measure_latency(**kwargs):
        return {
            "status": "success",
            "target": "google.com",
            "statistics": {
                "sent": 20,
                "received": 20,
                "lost": 0,
                "packet_loss_percent": 0.0,
            },
            "probes": [],
        }

    monkeypatch.setattr(
        packet_loss,
        "measure_latency",
        mock_measure_latency,
    )

    result = packet_loss.measure_packet_loss("google.com")

    assert result["packet_loss_percent"] == 0.0
    assert result["packets_lost"] == 0


def test_invalid_probe_count():

    result = packet_loss.measure_packet_loss(
        target="google.com",
        count=100,
    )

    assert result["status"] == "invalid_input"


def test_unreachable_destination(monkeypatch):

    def mock_measure_latency(**kwargs):
        return {
            "status": "unreachable",
            "target": "192.0.2.1",
            "statistics": {
                "sent": 5,
                "received": 0,
                "lost": 5,
                "packet_loss_percent": 100.0,
            },
            "probes": [],
        }

    monkeypatch.setattr(
        packet_loss,
        "measure_latency",
        mock_measure_latency,
    )

    result = packet_loss.measure_packet_loss(
        target="192.0.2.1",
        count=5,
    )

    assert result["status"] == "unreachable"
    assert result["packet_loss_percent"] == 100.0
