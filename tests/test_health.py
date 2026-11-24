from netghost.tools.health import get_server_status


def test_server_status():
    result = get_server_status()

    assert result["status"] == "healthy"
    assert result["server"] == "NetGhost"
    assert result["version"] == "0.1.0"

def test_server_status_contains_runtime_information():
    result = get_server_status()

    assert "python_version" in result
    assert "platform" in result
    assert "checked_at" in result