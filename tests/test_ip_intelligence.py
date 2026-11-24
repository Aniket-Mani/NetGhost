from netghost.tools.ip_intelligence import lookup_ip_intelligence


def test_rejects_invalid_and_non_public_addresses():
    assert lookup_ip_intelligence("nope")["status"] == "invalid_input"
    assert lookup_ip_intelligence("192.168.1.1")["status"] == "not_public"


def test_rdap_lookup(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def read(self, size):
            return b'{"name":"Example Net","handle":"AS64496","country":"US","startAddress":"8.8.8.0","endAddress":"8.8.8.255","ipVersion":"v4","entities":[]}'
        def geturl(self): return "https://rdap.example/ip/8.8.8.8"
    monkeypatch.setattr("urllib.request.urlopen", lambda *args, **kwargs: Response())
    result = lookup_ip_intelligence("8.8.8.8")
    assert result["status"] == "success"
    assert result["name"] == "Example Net"
    assert result["country"] == "US"
