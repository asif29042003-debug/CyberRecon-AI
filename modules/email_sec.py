"""Email security posture checks from DNS and SMTP observations."""

from typing import Any


def run_email_security(target: str, dns_data: dict[str, Any]) -> dict[str, Any]:
    records = dns_data.get("records", {})
    return {
        "target": target,
        "mx": records.get("MX", []),
        "spf": {"status": "not available via stdlib resolver", "strict": False},
        "dmarc": {"status": "not available via stdlib resolver", "policy": "unknown"},
        "dkim": {"selectors_checked": [], "status": "not checked"},
        "mta_sts": {"status": "not checked"},
        "banner": None,
    }
