"""WHOIS and domain-registration intelligence."""

from datetime import datetime, timezone
import ipaddress
import socket
from typing import Any

WHOIS_SERVERS = ("whois.iana.org", "whois.verisign-grs.com", "whois.registry.in")


def _first(fields: dict[str, list[str]], *names: str) -> str | None:
    return next((value for name in names for value in fields.get(name, []) if value), None)


def _parse(raw: str, server: str | None) -> dict[str, Any]:
    fields: dict[str, list[str]] = {}
    for line in raw.splitlines():
        if ":" in line and not line.startswith("%"):
            key, value = line.split(":", 1)
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    created = _first(fields, "creation date", "created", "domain registration date")
    expires = _first(fields, "registry expiry date", "expiration date", "expiry date")
    days = None
    if expires:
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d", "%d-%b-%Y"):
            try:
                days = (datetime.strptime(expires[:len(fmt)], fmt).replace(tzinfo=timezone.utc) -
                        datetime.now(timezone.utc)).days
                break
            except ValueError:
                continue
    return {
        "status": "ok" if raw.strip() else "unavailable", "server": server,
        "registrar": _first(fields, "registrar"),
        "iana_id": _first(fields, "registrar iana id"),
        "created": created, "expires": expires, "days_remaining": days,
        "domain_age_years": None,
        "registrant": {
            "organization": _first(fields, "registrant organization"),
            "name": _first(fields, "registrant name"),
            "country": _first(fields, "registrant country"),
            "state": _first(fields, "registrant state"),
            "email": _first(fields, "registrant email"),
        },
        "privacy_shield": any(
            token in value.lower() for values in fields.values() for value in values
            for token in ("privacy", "redact", "proxy")
        ),
        "epp_status": fields.get("domain status", []),
        "name_servers": fields.get("name server", []) + fields.get("nameserver", []),
        "dnssec": _first(fields, "dnssec") or "unknown",
        "raw": raw[:20000],
    }


def run_domain_intel(target: str, timeout: float = 5.0) -> dict[str, Any]:
    """Query WHOIS port 43 with fail-soft registry fallback."""
    try:
        ipaddress.ip_address(target)
        return {"status": "skipped", "error": "WHOIS domain required", "fields": {}}
    except ValueError:
        pass
    for server in WHOIS_SERVERS:
        try:
            with socket.create_connection((server, 43), timeout=timeout) as sock:
                sock.sendall((target + "\r\n").encode())
                chunks = []
                while chunk := sock.recv(4096):
                    chunks.append(chunk)
            return _parse(b"".join(chunks).decode("utf-8", errors="replace"), server)
        except (socket.timeout, socket.gaierror, OSError):
            continue
    return {"status": "unavailable", "error": "WHOIS registries unreachable", "fields": {}}
