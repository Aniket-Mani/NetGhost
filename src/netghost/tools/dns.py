
import ipaddress
import math
import re
import time

import dns.exception
import dns.resolver
from dns.resolver import (
    NXDOMAIN,
    LifetimeTimeout,
    NoAnswer,
    NoNameservers,
)

SUPPORTED_RECORD_TYPES = {
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME",
    "PTR",
}


def get_dns_configuration() -> dict:
    """
    Retrieve DNS nameservers configured on the system.
    """

    try:
        resolver = dns.resolver.Resolver(configure=True)

        return {
            "nameservers": [str(server) for server in resolver.nameservers],
            "search_domains": [str(domain) for domain in resolver.search],
            "status": "success",
        }

    except (dns.exception.DNSException, OSError, ValueError) as exc:
        return {
            "nameservers": [],
            "search_domains": [],
            "status": "error",
            "error": str(exc),
        }


def resolve_domain(domain: str, record_type: str = "A", nameserver: str | None = None, timeout: float = 2.0, lifetime: float = 4.0) -> dict:
    """
    Resolve a domain and measure DNS query latency.

    Args:
        domain: Domain name to resolve.
        record_type: DNS record type.
        nameserver: Optional custom DNS server IP.
        timeout: Per-query timeout in seconds.
        lifetime: Maximum total resolution time.

    Returns:
        Structured DNS diagnostic results.
    """

    domain = domain.strip().rstrip(".") if isinstance(domain, str) else ""
    record_type = record_type.upper().strip() if isinstance(record_type, str) else ""

    if not domain or len(domain) > 253:
        return {
            "status": "invalid_input",
            "domain": domain,
            "error": "Invalid domain name",
        }

    if record_type not in SUPPORTED_RECORD_TYPES:
        return {
            "status": "invalid_input",
            "domain": domain,
            "error": f"Unsupported record type: {record_type}",
        }

    if record_type == "PTR":
        try:
            domain = ipaddress.ip_address(domain).reverse_pointer
        except ValueError:
            return {"status": "invalid_input", "domain": domain, "record_type": record_type, "error": "PTR lookup requires an IPv4 or IPv6 address"}
    elif not all(
        label and len(label) <= 63 and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in domain.split(".")
    ):
        return {"status": "invalid_input", "domain": domain, "record_type": record_type, "error": "Invalid domain name"}

    if (
        not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
        or not isinstance(lifetime, (int, float)) or isinstance(lifetime, bool)
        or not math.isfinite(timeout) or not math.isfinite(lifetime)
        or not (0 < timeout <= 10 and 0 < lifetime <= 30)
    ):
        return {
            "status": "invalid_input",
            "domain": domain,
            "error": "Timeout values are outside allowed limits",
        }

    if nameserver is not None:
        if not isinstance(nameserver, str):
            return {
                "status": "invalid_input",
                "domain": domain,
                "error": "Invalid nameserver IP address",
            }
        try:
            ipaddress.ip_address(nameserver)
        except ValueError:
            return {
                "status": "invalid_input",
                "domain": domain,
                "error": "Invalid nameserver IP address",
            }

    start_time = time.perf_counter()

    try:
        resolver = dns.resolver.Resolver(configure=True)
        resolver.timeout = timeout
        if nameserver:
            resolver.nameservers = [nameserver]
        configured_nameservers = resolver.nameservers
        answer = resolver.resolve(
            domain,
            record_type,
            lifetime=lifetime,
            raise_on_no_answer=True,
        )

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        records = [record.to_text() for record in answer]

        return {
            "status": "success",
            "domain": domain,
            "record_type": record_type,
            "records": records,
            "record_count": len(records),
            "ttl": answer.rrset.ttl,
            "response_time_ms": round(elapsed_ms, 3),
            "nameservers": configured_nameservers,
        }

    except NXDOMAIN:
        status = "nxdomain"
        error = "Domain does not exist"

    except NoAnswer:
        status = "no_answer"
        error = f"No {record_type} records found"

    except LifetimeTimeout:
        status = "timeout"
        error = "DNS query timed out"

    except NoNameservers:
        status = "no_nameservers"
        error = "No DNS server could complete the query"

    except (dns.exception.DNSException, OSError, ValueError) as exc:
        status = "dns_error"
        error = str(exc)

    elapsed_ms = (time.perf_counter() - start_time) * 1000

    return {
        "status": status,
        "domain": domain,
        "record_type": record_type,
        "records": [],
        "response_time_ms": round(elapsed_ms, 3),
        "nameservers": locals().get("configured_nameservers", []),
        "error": error,
    }


def register_tools(mcp) -> None:
    """
    Register DNS diagnostic tools with FastMCP.
    """

    @mcp.tool
    def netghost_dns_lookup(
        domain: str,
        record_type: str = "A",
        nameserver: str | None = None,
        timeout: float = 2.0,
        lifetime: float = 4.0,
    ) -> dict:
        """
        Resolve a domain and measure DNS response time.

        Supports A, AAAA, MX, NS, TXT, CNAME and PTR records.

        An optional custom nameserver can be supplied
        to compare DNS resolution across providers.
        """

        return resolve_domain(
            domain=domain,
            record_type=record_type,
            nameserver=nameserver,
            timeout=timeout,
            lifetime=lifetime,
        )

    @mcp.tool
    def netghost_dns_configuration() -> dict:
        """
        Retrieve DNS nameservers configured on the system.
        """

        return get_dns_configuration()
