
import socket
from types import SimpleNamespace

import psutil

from netghost.tools import connections


def make_connection(
    pid=123,
    protocol="tcp",
    status="ESTABLISHED",
    remote_ip="93.184.216.34",
):
    return SimpleNamespace(
        pid=pid,
        type=(
            socket.SOCK_STREAM
            if protocol == "tcp"
            else socket.SOCK_DGRAM
        ),
        family=socket.AF_INET,
        status=status,
        laddr=SimpleNamespace(ip="192.168.1.10", port=50000),
        raddr=(
            SimpleNamespace(ip=remote_ip, port=443)
            if remote_ip
            else ()
        ),
    )


def mock_process(monkeypatch, name="python"):
    class FakeProcess:
        def __init__(self, pid):
            self.pid = pid

        def name(self):
            return name

    monkeypatch.setattr(
        connections.psutil,
        "Process",
        FakeProcess,
    )


def test_get_active_connections_returns_connection_details(monkeypatch):
    mock_process(monkeypatch)

    monkeypatch.setattr(
        connections.psutil,
        "net_connections",
        lambda kind: [make_connection()],
    )

    result = connections.get_active_connections()

    assert result["status"] == "success"
    assert result["summary"]["total_connections"] == 1
    assert result["summary"]["tcp_connections"] == 1
    assert result["connections"][0]["process"]["name"] == "python"
    assert result["connections"][0]["remote_address"]["port"] == 443


def test_protocol_filter_returns_only_tcp(monkeypatch):
    mock_process(monkeypatch)

    monkeypatch.setattr(
        connections.psutil,
        "net_connections",
        lambda kind: [
            make_connection(protocol="tcp"),
            make_connection(protocol="udp"),
        ],
    )

    result = connections.get_active_connections(protocol="tcp")

    assert result["summary"]["total_connections"] == 1
    assert result["connections"][0]["protocol"] == "tcp"


def test_status_filter(monkeypatch):
    mock_process(monkeypatch)

    monkeypatch.setattr(
        connections.psutil,
        "net_connections",
        lambda kind: [
            make_connection(status="ESTABLISHED"),
            make_connection(status="LISTEN"),
        ],
    )

    result = connections.get_active_connections(status="LISTEN")

    assert result["summary"]["total_connections"] == 1
    assert result["connections"][0]["status"] == "LISTEN"


def test_process_name_filter(monkeypatch):
    mock_process(monkeypatch, name="Google Chrome")

    monkeypatch.setattr(
        connections.psutil,
        "net_connections",
        lambda kind: [make_connection()],
    )

    result = connections.get_active_connections(
        process_name="chrome"
    )

    assert result["summary"]["total_connections"] == 1


def test_remote_ip_filter(monkeypatch):
    mock_process(monkeypatch)

    monkeypatch.setattr(
        connections.psutil,
        "net_connections",
        lambda kind: [
            make_connection(remote_ip="93.184.216.34"),
            make_connection(remote_ip="1.1.1.1"),
        ],
    )

    result = connections.get_active_connections(
        remote_ip="1.1.1.1"
    )

    assert result["summary"]["total_connections"] == 1
    assert (
        result["connections"][0]["remote_address"]["ip"]
        == "1.1.1.1"
    )


def test_invalid_protocol_returns_invalid_input():
    result = connections.get_active_connections(protocol="icmp")

    assert result["status"] == "invalid_input"
    assert result["connections"] == []


def test_malformed_filters_return_invalid_input():
    assert connections.get_active_connections(protocol=[])["status"] == "invalid_input"
    assert connections.get_active_connections(remote_ip="not-an-ip")["status"] == "invalid_input"


def test_access_denied_is_handled(monkeypatch):
    def raise_access_denied(kind):
        raise psutil.AccessDenied(pid=None)

    monkeypatch.setattr(
        connections.psutil,
        "net_connections",
        raise_access_denied,
    )

    result = connections.get_active_connections()

    assert result["status"] == "error"
    assert result["connections"] == []


def test_process_access_denied_does_not_crash(monkeypatch):
    class RestrictedProcess:
        def __init__(self, pid):
            raise psutil.AccessDenied(pid=pid)

    monkeypatch.setattr(
        connections.psutil,
        "Process",
        RestrictedProcess,
    )

    monkeypatch.setattr(
        connections.psutil,
        "net_connections",
        lambda kind: [make_connection()],
    )

    result = connections.get_active_connections()

    assert result["status"] == "success"
    assert (
        result["connections"][0]["process"]["lookup_status"]
        == "access_denied"
    )
