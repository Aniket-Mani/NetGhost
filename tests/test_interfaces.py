import socket
from types import SimpleNamespace

import psutil

from netghost.tools.interfaces import get_network_interfaces


def test_network_interfaces(monkeypatch):

    mock_addresses = {
        "en0": [
            SimpleNamespace(
                family=socket.AF_INET,
                address="192.168.1.10",
            ),
            SimpleNamespace(
                family=socket.AF_INET6,
                address="fe80::1234",
            ),
            SimpleNamespace(
                family=psutil.AF_LINK,
                address="aa:bb:cc:dd:ee:ff",
            ),
        ]
    }

    mock_stats = {
        "en0": SimpleNamespace(
            isup=True, speed=1000, mtu=1500,
        )
    }
    mock_io = {
        "en0": SimpleNamespace(
            bytes_sent=10000, bytes_recv=20000,
        )
    }
    monkeypatch.setattr(
        psutil, "net_if_addrs", lambda: mock_addresses
    )

    monkeypatch.setattr(
        psutil, "net_if_stats", lambda: mock_stats
    )

    monkeypatch.setattr(
        psutil, "net_io_counters",
        lambda pernic=True: mock_io
    )

    monkeypatch.setattr(
        "netghost.tools.interfaces.get_default_route",
        lambda: {
            "gateway": "192.168.1.1",
            "interface": "en0",
            "error": None,
        },
    )

    result = get_network_interfaces()

    interface = result["interfaces"]["en0"]

    assert interface["ipv4"] == ["192.168.1.10"]
    assert interface["ipv6"] == ["fe80::1234"]
    assert interface["mac_address"] == "aa:bb:cc:dd:ee:ff"
    assert interface["is_up"] is True
    assert interface["speed_mbps"] == 1000
    assert interface["mtu"] == 1500

    assert interface["bytes_sent"] == 10000
    assert interface["bytes_received"] == 20000

    assert result["default_gateway"] == "192.168.1.1"
    assert result["default_interface"] == "en0"