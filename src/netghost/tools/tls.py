"""TLS certificate inspection with independent hostname and validity checks."""

import ipaddress
import math
import re
import socket
import ssl
import tempfile
from datetime import UTC, datetime


def _normalize_hostname(hostname: str) -> str | None:
    try:
        ipaddress.ip_address(hostname)
        return hostname
    except ValueError:
        pass
    try:
        ascii_name = hostname.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(ascii_name) > 253:
        return None
    labels = ascii_name.split(".")
    if not all(
        label and len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    ):
        return None
    return ascii_name


def _decode_certificate(der: bytes) -> dict:
    """Decode a peer certificate after a validation error for reporting only."""
    if not der:
        return {}
    decoder = getattr(ssl._ssl, "_test_decode_cert", None)
    if decoder is None:
        return {}
    pem = ssl.DER_cert_to_PEM_cert(der)
    with tempfile.NamedTemporaryFile(mode="w", encoding="ascii") as certificate_file:
        certificate_file.write(pem)
        certificate_file.flush()
        return decoder(certificate_file.name)


def _parse_certificate_date(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except ValueError:
        return None


def inspect_tls(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Retrieve a TLS peer certificate and report trust and hostname validation."""
    hostname = hostname.strip() if isinstance(hostname, str) else ""
    server_name = _normalize_hostname(hostname)
    if server_name is None:
        return {"status": "invalid_input", "hostname": hostname, "error": "Provide a valid hostname or IP address"}
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        return {"status": "invalid_input", "hostname": hostname, "error": "Port must be between 1 and 65535"}
    if (
        not isinstance(timeout, (int, float)) or isinstance(timeout, bool)
        or not math.isfinite(timeout) or not 0.2 <= timeout <= 20
    ):
        return {"status": "invalid_input", "hostname": hostname, "error": "Timeout must be between 0.2 and 20 seconds"}

    validation_error = None
    verification_code = None
    try:
        context = ssl.create_default_context()
        with (
            socket.create_connection((server_name, port), timeout=timeout) as raw,
            context.wrap_socket(raw, server_hostname=server_name) as secured,
        ):
            cert = secured.getpeercert()
            protocol = secured.version()
            cipher = secured.cipher()
        certificate_valid = True
    except ssl.SSLCertVerificationError as exc:
        certificate_valid = False
        validation_error = str(exc)
        verification_code = exc.verify_code
        try:
            with (
                socket.create_connection((server_name, port), timeout=timeout) as raw,
                ssl._create_unverified_context().wrap_socket(raw, server_hostname=server_name) as secured,
            ):
                cert = _decode_certificate(secured.getpeercert(binary_form=True))
                protocol = secured.version()
                cipher = secured.cipher()
        except (OSError, ssl.SSLError, TimeoutError, ValueError) as retry_exc:
            return {
                "status": "certificate_invalid", "hostname": hostname, "port": port,
                "hostname_valid": False if verification_code == 62 else None,
                "certificate_valid": False, "validation_error": validation_error,
                "certificate_error": str(retry_exc),
            }
    except (OSError, ssl.SSLError, TimeoutError, ValueError) as exc:
        return {"status": "error", "hostname": hostname, "error": str(exc)}

    not_before = _parse_certificate_date(cert.get("notBefore"))
    not_after = _parse_certificate_date(cert.get("notAfter"))
    now = datetime.now(UTC)
    sans = [value for kind, value in cert.get("subjectAltName", []) if kind in {"DNS", "IP Address"}]
    return {
        "status": "success" if certificate_valid else "certificate_invalid",
        "hostname": hostname,
        "port": port,
        "hostname_valid": True if certificate_valid else (False if verification_code == 62 else None),
        "certificate_valid": certificate_valid,
        "validation_error": validation_error,
        "subject": dict(item[0] for item in cert.get("subject", [])),
        "issuer": dict(item[0] for item in cert.get("issuer", [])),
        "subject_alternative_names": sans,
        "not_before": not_before.isoformat() if not_before else None,
        "not_after": not_after.isoformat() if not_after else None,
        "days_until_expiry": (not_after - now).days if not_after else None,
        "tls_version": protocol,
        "cipher": cipher[0] if cipher else None,
    }


def register_tools(mcp) -> None:
    @mcp.tool
    def netghost_tls_inspect(
        hostname: str,
        port: int = 443,
        timeout: float = 5.0,
    ) -> dict:
        """Inspect a server TLS certificate, subject, issuer, SANs, validity dates and hostname validation."""
        return inspect_tls(hostname, port, timeout)
