from netghost.tools.tls import inspect_tls


def test_tls_input_validation():
    assert inspect_tls("https://example.com")["status"] == "invalid_input"
    assert inspect_tls("example.com", port=70000)["status"] == "invalid_input"
    assert inspect_tls("bad host")["status"] == "invalid_input"
    assert inspect_tls("example.com", timeout=float("nan"))["status"] == "invalid_input"


def test_reports_certificate_details(monkeypatch):
    cert = {"subject": ((('commonName', 'example.com'),),), "issuer": ((('organizationName', 'Example CA'),),), "subjectAltName": (("DNS", "example.com"),), "notBefore": "Jan  1 00:00:00 2025 GMT", "notAfter": "Jan  1 00:00:00 2030 GMT"}
    class SecureSocket:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def getpeercert(self): return cert
        def version(self): return "TLSv1.3"
        def cipher(self): return ("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128)
    class RawSocket:
        def __enter__(self): return self
        def __exit__(self, *args): pass
    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: RawSocket())
    monkeypatch.setattr("ssl.create_default_context", lambda: type("Context", (), {"wrap_socket": lambda self, raw, server_hostname: SecureSocket()})())
    result = inspect_tls("example.com")
    assert result["status"] == "success"
    assert result["subject_alternative_names"] == ["example.com"]
    assert result["tls_version"] == "TLSv1.3"
