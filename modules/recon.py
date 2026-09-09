"""Deep standard-library domain and infrastructure reconnaissance."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import ipaddress
import random
import socket
import ssl
import struct
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


PORTS = (21, 22, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8080, 8443, 27017)
SERVICES = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt", 27017: "MongoDB",
}
HEADERS = {
    "strict-transport-security": "HSTS", "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options", "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy", "permissions-policy": "Permissions-Policy",
    "access-control-allow-origin": "CORS",
}
WHOIS_SERVERS = ("whois.iana.org", "whois.verisign-grs.com", "whois.registry.in")
USER_AGENT = "CyberRecon-AI/4.0 (authorized defensive assessment)"


def normalize_target(target: str) -> str:
    parsed = urlparse(target.strip() if "://" in target else f"//{target.strip()}")
    if not parsed.hostname:
        raise ValueError("Target must be a domain or IP address.")
    try:
        return ipaddress.ip_address(parsed.hostname).compressed
    except ValueError:
        return parsed.hostname.rstrip(".").lower()


def _probe(hostname: str, port: int, timeout: float) -> dict[str, Any]:
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            banner = None
            if port in (21, 22, 25):
                sock.settimeout(timeout)
                try:
                    banner = sock.recv(512).decode("utf-8", errors="replace").strip()
                except (socket.timeout, OSError):
                    pass
            return {"port": port, "service": SERVICES.get(port, "unknown"), "state": "open", "banner": banner}
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return {"port": port, "service": SERVICES.get(port, "unknown"), "state": "closed_or_filtered", "error": str(exc)}


def _web(hostname: str, timeout: float) -> dict[str, Any]:
    attempts = []
    for scheme in ("https", "http"):
        request = Request(f"{scheme}://{hostname}/", headers={"User-Agent": USER_AGENT})
        try:
            with urlopen(request, timeout=timeout) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                attempts.append({
                    "url": response.geturl(), "status": response.status,
                    "headers": dict(response.headers.items()),
                    "server": response.headers.get("Server", "Unknown"),
                    "powered_by": response.headers.get("X-Powered-By", "Unknown"),
                    "missing_headers": [label for key, label in HEADERS.items() if key not in headers],
                    "error": None,
                })
        except (HTTPError, URLError, TimeoutError, OSError) as exc:
            attempts.append({"url": f"{scheme}://{hostname}/", "missing_headers": [], "error": str(exc)})
    return {
        "attempts": attempts,
        "missing_headers": sorted({h for item in attempts for h in item.get("missing_headers", [])}),
        "server": next((item["server"] for item in attempts if item.get("server") not in (None, "Unknown")), "Unknown"),
    }


def _tls(hostname: str, timeout: float) -> dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=None if _is_ip(hostname) else hostname) as sock:
                cert = sock.getpeercert()
                raw_expiry = cert.get("notAfter")
                expiry = datetime.strptime(raw_expiry, "%b %d %H:%M:%S %Y %Z") if raw_expiry else None
                expiry = expiry.replace(tzinfo=timezone.utc) if expiry else None
                issuer = dict(part[0] for part in cert.get("issuer", ()))
                days = (expiry - datetime.now(timezone.utc)).days if expiry else None
                return {
                    "status": "ok", "tls_version": sock.version(),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "expires_at": expiry.isoformat() if expiry else None,
                    "days_remaining": days, "weak_or_expiring": bool(days is not None and days <= 30),
                }
    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, ValueError) as exc:
        return {"status": "unavailable", "error": str(exc)}


def _dns_name(name: str) -> bytes:
    return b"".join(bytes([len(label)]) + label.encode() for label in name.rstrip(".").split(".")) + b"\0"


def _dns_query(name: str, record_type: int, timeout: float) -> list[str]:
    """Resolve A, MX, and TXT records using a small DNS UDP client."""
    resolver = next((line.split()[1] for line in open("/etc/resolv.conf", encoding="utf-8")
                     if line.startswith("nameserver ")), "8.8.8.8")
    query_id = random.randint(0, 65535)
    packet = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0) + _dns_name(name) + struct.pack("!HH", record_type, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (resolver, 53))
        data, _ = sock.recvfrom(4096)
    if len(data) < 12 or struct.unpack("!H", data[:2])[0] != query_id:
        return []
    offset = 12
    while offset < len(data) and data[offset] != 0:
        offset += data[offset] + 1
    offset += 5
    answers = []
    ancount = struct.unpack("!H", data[6:8])[0]
    for _ in range(ancount):
        if offset + 12 > len(data):
            break
        offset += 2
        _, rtype, _, _, rdlength = struct.unpack("!HHHIH", data[offset:offset + 12])
        offset += 12
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rtype == 1 and rdlength == 4:
            answers.append(socket.inet_ntoa(rdata))
        elif rtype == 15 and rdlength >= 3:
            answers.append(str(struct.unpack("!H", rdata[:2])[0]) + " " + _decode_dns_pointer(data, offset - rdlength + 2))
        elif rtype == 16:
            parts = []
            cursor = 0
            while cursor < len(rdata):
                length = rdata[cursor]
                cursor += 1
                parts.append(rdata[cursor:cursor + length].decode(errors="replace"))
                cursor += length
            answers.append("".join(parts))
    return answers


def _decode_dns_pointer(data: bytes, offset: int) -> str:
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            return ".".join(labels + [_decode_dns_pointer(data, pointer)])
        offset += 1
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length
    return ".".join(labels)


def _dns_records(hostname: str, timeout: float) -> dict[str, Any]:
    records = {}
    for label, record_type in (("A", 1), ("MX", 15), ("TXT", 16)):
        try:
            records[label] = _dns_query(hostname, record_type, timeout)
        except (OSError, struct.error, ValueError, IndexError):
            records[label] = []
    return records


def _whois(hostname: str, timeout: float) -> dict[str, Any]:
    if _is_ip(hostname):
        return {"status": "skipped", "server": None, "raw": "", "fields": {}}
    raw = ""
    for server in WHOIS_SERVERS:
        try:
            with socket.create_connection((server, 43), timeout=timeout) as sock:
                sock.sendall((hostname + "\r\n").encode())
                chunks = []
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    chunks.append(chunk)
                raw = b"".join(chunks).decode("utf-8", errors="replace")
            if raw.strip():
                break
        except (socket.timeout, socket.gaierror, OSError):
            continue
    fields: dict[str, list[str]] = {}
    for line in raw.splitlines():
        if ":" in line and not line.startswith("%"):
            key, value = line.split(":", 1)
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    def first(*keys: str) -> str | None:
        return next((value for key in keys for value in fields.get(key, []) if value), None)
    created = first("creation date", "created", "domain registration date")
    expires = first("registry expiry date", "expiration date", "expiry date")
    return {
        "status": "ok" if raw.strip() else "unavailable", "server": server if raw.strip() else None,
        "registrar": first("registrar"), "iana_id": first("registrar iana id"),
        "created": created, "expires": expires,
        "registrant": {
            "name": first("registrant name"), "organization": first("registrant organization"),
            "country": first("registrant country"), "state": first("registrant state"),
            "email": first("registrant email"),
        },
        "privacy_shield": any("privacy" in value.lower() or "redact" in value.lower()
                              for values in fields.values() for value in values),
        "name_servers": fields.get("name server", []) + fields.get("nameserver", []),
        "raw": raw[:20000],
    }


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def run_recon(target: str, timeout: float = 5.0) -> dict[str, Any]:
    hostname = normalize_target(target)
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)})
        dns_error = None
    except (socket.gaierror, OSError) as exc:
        addresses, dns_error = [], str(exc)
    with ThreadPoolExecutor(max_workers=6) as executor:
        jobs = {
            "ports": executor.submit(lambda: sorted([_probe(hostname, port, timeout) for port in PORTS], key=lambda item: item["port"])),
            "web": executor.submit(_web, hostname, timeout),
            "tls": executor.submit(_tls, hostname, timeout),
            "dns_records": executor.submit(_dns_records, hostname, timeout),
            "whois": executor.submit(_whois, hostname, timeout),
        }
        results: dict[str, Any] = {}
        for name, job in jobs.items():
            try:
                results[name] = job.result()
            except Exception as exc:
                results[name] = {"status": "unavailable", "error": str(exc)}
    results["target"] = hostname
    results["dns"] = {"addresses": addresses, "error": dns_error, "reverse_dns": socket.getfqdn(addresses[0]) if addresses else None}
    results["scan_started_at"] = datetime.now(timezone.utc).isoformat()
    return results
