"""IP address registration and network allocation lookup via RDAP."""

import ipaddress
import json
import re
import urllib.error
import urllib.request

RDAP_TIMEOUT = 8.0


def _entity_details(entities: list) -> list[dict]:
    details = []
    for entity in entities:
        if not isinstance(entity, dict):
            continue
        name = None
        vcard = entity.get("vcardArray")
        properties = vcard[1] if isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list) else []
        for item in properties:
            if not isinstance(item, list):
                continue
            if len(item) > 3 and item[0] == "fn" and item[3]:
                name = str(item[3])
                break
        details.append({"handle": entity.get("handle"), "name": name, "roles": entity.get("roles", [])})
    return details


def lookup_ip_intelligence(address: str, timeout: float = RDAP_TIMEOUT) -> dict:
    """Look up public registration metadata for an IPv4 or IPv6 address."""
    address = address.strip() if isinstance(address, str) else ""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return {"status": "invalid_input", "ip": address, "error": "A valid IPv4 or IPv6 address is required"}
    if not isinstance(timeout, (int, float)) or not 0.2 <= timeout <= 15:
        return {"status": "invalid_input", "ip": str(ip), "error": "Timeout must be between 0.2 and 15 seconds"}
    if not ip.is_global:
        return {"status": "not_public", "ip": str(ip), "error": "RDAP registration lookup is only available for globally routable IP addresses"}
    request = urllib.request.Request(f"https://rdap.org/ip/{ip}", headers={"Accept": "application/rdap+json", "User-Agent": "NetGhost/0.1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = json.loads(response.read(2_000_000))
        handle = data.get("handle")
        asn_match = re.fullmatch(r"AS(\d+)", str(handle or ""), re.IGNORECASE)
        entities = _entity_details(data.get("entities", []))
        origin_asns = data.get("arin_originas0_originautnums", [])
        if not isinstance(origin_asns, list):
            origin_asns = []
        asns = []
        if asn_match:
            asns.append(f"AS{asn_match.group(1)}")
        for origin in origin_asns:
            value = origin.get("originautnum") if isinstance(origin, dict) else None
            if isinstance(value, str) and re.fullmatch(r"AS\d+", value, re.IGNORECASE):
                normalized = value.upper()
                if normalized not in asns:
                    asns.append(normalized)
        return {
            "status": "success", "ip": str(ip),
            "name": data.get("name"), "handle": handle,
            "asn": asns[0] if asns else None, "asns": asns,
            "organization": next((entity["name"] for entity in entities if entity["name"]), None),
            "country": data.get("country"), "start_address": data.get("startAddress"),
            "end_address": data.get("endAddress"), "ip_version": data.get("ipVersion"),
            "type": data.get("type"), "entities": entities,
            "rdap_url": data.get("rdapConformance") and response.geturl(),
        }
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, TypeError, AttributeError) as exc:
        return {"status": "error", "ip": str(ip), "error": f"RDAP lookup failed: {exc}"}


def register_tools(mcp) -> None:
    @mcp.tool
    def netghost_ip_intelligence(address: str, timeout: float = RDAP_TIMEOUT) -> dict:
        """Look up public IP ownership, ASN/organization, country and allocation data through RDAP."""
        return lookup_ip_intelligence(address, timeout)
