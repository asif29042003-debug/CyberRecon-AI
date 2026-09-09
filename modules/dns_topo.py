"""DNS topology checks using the local resolver and standard library."""

import socket
from typing import Any


def run_dns_topology(target: str) -> dict[str, Any]:
    records: dict[str, list[str]] = {}
    for family, name in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
        try:
            records[name] = sorted({item[4][0] for item in socket.getaddrinfo(target, None, family, socket.SOCK_STREAM)})
        except (socket.gaierror, OSError):
            records[name] = []
    try:
        records["PTR"] = [socket.getfqdn(records["A"][0])] if records["A"] else []
    except OSError:
        records["PTR"] = []
    return {
        "target": target,
        "records": records,
        "checks": {
            "cname_chain": [],
            "SOA": "not available via stdlib resolver",
            "NS": "not available via stdlib resolver",
            "TXT": "not available via stdlib resolver",
            "CAA": "not available via stdlib resolver",
            "wildcard": "not tested",
            "AXFR": "not attempted",
        },
    }
