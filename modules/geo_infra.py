"""Infrastructure context from local DNS and reverse-DNS signals."""

import socket
from typing import Any


def run_geo_infra(target: str, dns_data: dict[str, Any], web_data: dict[str, Any]) -> dict[str, Any]:
    addresses = dns_data.get("records", {}).get("A", [])
    reverse = socket.getfqdn(addresses[0]) if addresses else None
    text = str(web_data).lower()
    cdn = next((name for name in ("cloudflare", "fastly", "akamai") if name in text), None)
    return {
        "target": target, "addresses": addresses, "reverse_dns": reverse,
        "asn": "not available without external registry", "isp": reverse or "unknown",
        "region": "unknown", "cdn": cdn or "not detected", "waf": "heuristic only",
    }
