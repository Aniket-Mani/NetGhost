
import subprocess

from netghost.utils import platform as platform_utils


def test_macos_default_route(monkeypatch):
    monkeypatch.setattr(
        platform_utils.platform,
        "system",
        lambda: "Darwin",
    )

    def mock_run(command, **kwargs):
        assert command == ["route", "-n", "get", "default"]
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="""
                route to: default
                gateway: 192.168.1.1
                interface: en0
            """,
            stderr="",
        )

    monkeypatch.setattr(
        platform_utils.subprocess,
        "run",
        mock_run,
    )

    result = platform_utils.get_default_route()

    assert result == {
        "gateway": "192.168.1.1",
        "interface": "en0",
        "error": None,
    }


def test_linux_default_route(monkeypatch):
    monkeypatch.setattr(
        platform_utils.platform,
        "system",
        lambda: "Linux",
    )

    def mock_run(command, **kwargs):
        assert command == ["ip", "route", "show", "default"]
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="default via 192.168.1.1 dev eth0 proto dhcp",
            stderr="",
        )

    monkeypatch.setattr(
        platform_utils.subprocess,
        "run",
        mock_run,
    )

    result = platform_utils.get_default_route()

    assert result == {
        "gateway": "192.168.1.1",
        "interface": "eth0",
        "error": None,
    }


def test_unsupported_platform(monkeypatch):
    monkeypatch.setattr(
        platform_utils.platform,
        "system",
        lambda: "Windows",
    )

    result = platform_utils.get_default_route()

    assert result["gateway"] is None
    assert result["interface"] is None
    assert result["error"] == "Unsupported platform: Windows"


def test_route_command_failure(monkeypatch):
    monkeypatch.setattr(
        platform_utils.platform,
        "system",
        lambda: "Darwin",
    )

    def mock_run(command, **kwargs):
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr="Permission denied",
        )

    monkeypatch.setattr(
        platform_utils.subprocess,
        "run",
        mock_run,
    )

    result = platform_utils.get_default_route()

    assert result["gateway"] is None
    assert result["interface"] is None
    assert result["error"] == "Permission denied"


def test_route_command_failure_without_stderr(monkeypatch):
    monkeypatch.setattr(
        platform_utils.platform,
        "system",
        lambda: "Darwin",
    )

    def mock_run(command, **kwargs):
        return subprocess.CompletedProcess(
            args=command,
            returncode=1,
            stdout="",
            stderr="",
        )

    monkeypatch.setattr(
        platform_utils.subprocess,
        "run",
        mock_run,
    )

    result = platform_utils.get_default_route()

    assert result["error"] == "Route command failed"


def test_route_command_timeout(monkeypatch):
    monkeypatch.setattr(
        platform_utils.platform,
        "system",
        lambda: "Darwin",
    )

    def mock_run(command, **kwargs):
        raise subprocess.TimeoutExpired(
            cmd=command,
            timeout=3,
        )

    monkeypatch.setattr(
        platform_utils.subprocess,
        "run",
        mock_run,
    )

    result = platform_utils.get_default_route()

    assert result["gateway"] is None
    assert result["interface"] is None
    assert result["error"] == "Default route lookup timed out"


def test_route_command_os_error(monkeypatch):
    monkeypatch.setattr(
        platform_utils.platform,
        "system",
        lambda: "Darwin",
    )

    def mock_run(command, **kwargs):
        raise FileNotFoundError("route command not found")

    monkeypatch.setattr(
        platform_utils.subprocess,
        "run",
        mock_run,
    )

    result = platform_utils.get_default_route()

    assert result["gateway"] is None
    assert result["interface"] is None
    assert result["error"] == "route command not found"


def test_linux_route_without_gateway(monkeypatch):
    monkeypatch.setattr(
        platform_utils.platform,
        "system",
        lambda: "Linux",
    )

    def mock_run(command, **kwargs):
        return subprocess.CompletedProcess(
            args=command,
            returncode=0,
            stdout="default dev eth0 proto dhcp",
            stderr="",
        )

    monkeypatch.setattr(
        platform_utils.subprocess,
        "run",
        mock_run,
    )

    result = platform_utils.get_default_route()

    assert result["gateway"] is None
    assert result["interface"] == "eth0"
    assert result["error"] is None
