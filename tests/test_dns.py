
from types import SimpleNamespace

import netghost.tools.dns as dns_tools


def test_successful_dns_lookup(monkeypatch):

    class MockResolver:
        def __init__(self, configure=True):
            self.nameservers = ["192.168.1.1"]

        def resolve(self, domain, record_type, **kwargs):
            return SimpleNamespace(
                __iter__=None,
                rrset=SimpleNamespace(ttl=300),
            )

    class MockAnswer:
        rrset = SimpleNamespace(ttl=300)

        def __iter__(self):
            return iter([
                SimpleNamespace(to_text=lambda: "93.184.216.34")
            ])

    monkeypatch.setattr(
        dns_tools.dns.resolver,
        "Resolver",
        MockResolver,
    )


    MockResolver.resolve = lambda self, domain, record_type, **kwargs: MockAnswer()

    result = dns_tools.resolve_domain("example.com")

    assert result["status"] == "success"
    assert result["domain"] == "example.com"
    assert result["record_type"] == "A"
    assert result["records"] == ["93.184.216.34"]
    assert result["ttl"] == 300
    assert result["response_time_ms"] >= 0


def test_invalid_record_type():

    result = dns_tools.resolve_domain(
        "example.com",
        record_type="INVALID",
    )

    assert result["status"] == "invalid_input"


def test_invalid_nameserver():

    result = dns_tools.resolve_domain(
        "example.com",
        nameserver="not-an-ip",
    )

    assert result["status"] == "invalid_input"


def test_invalid_timeout():

    result = dns_tools.resolve_domain(
        "example.com",
        timeout=0,
    )

    assert result["status"] == "invalid_input"


def test_invalid_domain():

    result = dns_tools.resolve_domain("")

    assert result["status"] == "invalid_input"


def test_invalid_hostname_and_malformed_timeout():
    assert dns_tools.resolve_domain("bad..example")["status"] == "invalid_input"
    assert dns_tools.resolve_domain("example.com", timeout="slow")["status"] == "invalid_input"


def test_ptr_lookup_uses_reverse_pointer(monkeypatch):
    observed = {}

    class Answer:
        rrset = SimpleNamespace(ttl=60)
        def __iter__(self):
            return iter([SimpleNamespace(to_text=lambda: "dns.google.")])

    class Resolver:
        def __init__(self, configure=True):
            self.nameservers = ["192.0.2.53"]
        def resolve(self, domain, record_type, **kwargs):
            observed.update(domain=domain, record_type=record_type)
            return Answer()

    monkeypatch.setattr(dns_tools.dns.resolver, "Resolver", Resolver)
    result = dns_tools.resolve_domain("8.8.8.8", record_type="PTR")
    assert result["status"] == "success"
    assert observed == {"domain": "8.8.8.8.in-addr.arpa", "record_type": "PTR"}
