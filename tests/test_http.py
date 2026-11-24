from netghost.tools.http import inspect_http


def test_http_input_validation():
    assert inspect_http("file:///etc/passwd")["status"] == "invalid_input"
    assert inspect_http("https://user:pass@example.com")["status"] == "invalid_input"
    assert inspect_http("https://[invalid")["status"] == "invalid_input"
    assert inspect_http("https://example.com", max_redirects=True)["status"] == "invalid_input"


def test_inspects_and_follows_redirect(monkeypatch):
    class Headers(dict):
        def items(self): return super().items()
        def get(self, key, default=None): return super().get(key, default)
    class Response:
        def __init__(self, status, headers): self.status, self.headers = status, Headers(headers)
        def close(self): pass
    class Opener:
        def __init__(self): self.calls = 0
        def open(self, request, timeout):
            self.calls += 1
            return Response(302, {"Location": "/done"}) if self.calls == 1 else Response(200, {"Content-Type": "text/plain", "Set-Cookie": "session=secret"})
    opener = Opener()
    monkeypatch.setattr("urllib.request.build_opener", lambda *handlers: opener)
    result = inspect_http("https://example.com/start")
    assert result["status"] == "success"
    assert result["http_status"] == 200
    assert result["final_url"] == "https://example.com/done"
    assert len(result["redirects"]) == 1
    assert result["headers"]["Set-Cookie"] == "[redacted]"
