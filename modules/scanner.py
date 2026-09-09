"""Standard-library reconnaissance engine for CyberRecon-AI."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import ipaddress
import json
import socket
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


COMMON_PORTS = (
    21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    3306, 3389, 5432, 6379, 8080, 8443, 27017,
)
HTTP_TIMEOUT = 6
SOCKET_TIMEOUT = 1.5
USER_AGENT = "CyberRecon-AI/3.0 (authorized defensive assessment)"
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "access-control-allow-origin": "CORS",
}
SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP submission", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP alternate", 8443: "HTTPS alternate",
    27017: "MongoDB",
}


def normalize_target(target: str) -> str:
    """Return a hostname or IP address without a scheme or path."""
    candidate = target.strip()
    if not candidate:
        raise ValueError("Target cannot be empty.")
    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Target must be a valid hostname or IP address.")
    try:
        return ipaddress.ip_address(hostname).compressed
    except ValueError:
        normalized = hostname.rstrip(".").lower()
        if not normalized or any(len(label) > 63 for label in normalized.split(".")):
            raise ValueError("Target contains an invalid hostname.")
        return normalized


def resolve_target(target: str) -> dict[str, Any]:
    """Resolve IPv4/IPv6 addresses without failing the complete scan."""
    hostname = normalize_target(target)
    try:
        addresses = sorted({
            item[4][0]
            for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        })
        return {"hostname": hostname, "addresses": addresses, "error": None}
    except (socket.gaierror, OSError) as exc:
        return {"hostname": hostname, "addresses": [], "error": str(exc)}


def _read_banner(hostname: str, port: int) -> str | None:
    """Read a short service greeting from FTP/SSH/SMTP-like services."""
    try:
        with socket.create_connection((hostname, port), timeout=SOCKET_TIMEOUT) as sock:
            sock.settimeout(1.0)
            if port in (21, 22, 25, 110, 143, 465, 587, 993, 995):
                data = sock.recv(512)
                return data.decode("utf-8", errors="replace").strip() or None
    except (socket.timeout, socket.gaierror, OSError):
        return None
    return None


def _scan_port(hostname: str, port: int) -> dict[str, Any]:
    """Probe a TCP port and optionally capture its greeting."""
    try:
        with socket.create_connection((hostname, port), timeout=SOCKET_TIMEOUT):
            state = "open"
        banner = _read_banner(hostname, port)
        return {
            "port": port,
            "service": SERVICE_NAMES.get(port, "unknown"),
            "state": state,
            "banner": banner,
            "error": None,
        }
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as exc:
        return {
            "port": port,
            "service": SERVICE_NAMES.get(port, "unknown"),
            "state": "closed_or_filtered",
            "banner": None,
            "error": str(exc),
        }


def scan_ports(hostname: str) -> list[dict[str, Any]]:
    """Scan all common ports concurrently."""
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=12) as executor:
        jobs = [executor.submit(_scan_port, hostname, port) for port in COMMON_PORTS]
        for job in as_completed(jobs):
            try:
                results.append(job.result())
            except Exception as exc:
                results.append({"port": None, "state": "error", "error": str(exc)})
    return sorted(results, key=lambda item: item.get("port") or 0)


def _inspect_url(url: str) -> dict[str, Any]:
    """Fetch headers and a bounded HTML sample using urllib."""
    request = Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT) as response:
            raw_body = response.read(256_000)
            body = raw_body.decode("utf-8", errors="replace")
            headers = {key.lower(): value for key, value in response.headers.items()}
            technologies: set[str] = set()
            for value in (headers.get("server", ""), headers.get("x-powered-by", "")):
                lowered = value.lower()
                for marker, name in (
                    ("nginx", "Nginx"), ("apache", "Apache"), ("cloudflare", "Cloudflare"),
                    ("iis", "IIS"), ("gunicorn", "Gunicorn"), ("express", "Express"),
                ):
                    if marker in lowered:
                        technologies.add(name)
            lowered_body = body.lower()
            for marker, name in (
                ("wp-content", "WordPress"), ("__next_data__", "Next.js"),
                ("django", "Django"), ("laravel", "Laravel"),
            ):
                if marker in lowered_body:
                    technologies.add(name)
            missing = [
                label for header, label in SECURITY_HEADERS.items()
                if header not in headers
            ]
            return {
                "url": url,
                "final_url": response.geturl(),
                "status_code": response.status,
                "headers": dict(response.headers.items()),
                "server": response.headers.get("Server", "not disclosed"),
                "powered_by": response.headers.get("X-Powered-By", "not disclosed"),
                "missing_security_headers": missing,
                "technologies": sorted(technologies),
                "error": None,
            }
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        return {"url": url, "missing_security_headers": [], "error": str(exc)}


def inspect_web(hostname: str) -> dict[str, Any]:
    """Inspect HTTP and HTTPS concurrently and expose normalized summary fields."""
    attempts: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        jobs = [executor.submit(_inspect_url, f"{scheme}://{hostname}/")
                for scheme in ("https", "http")]
        for job in as_completed(jobs):
            try:
                attempts.append(job.result())
            except Exception as exc:
                attempts.append({"missing_security_headers": [], "error": str(exc)})
    missing = sorted({
        header for attempt in attempts
        for header in attempt.get("missing_security_headers", [])
    })
    server = next(
        (
            attempt.get("server") for attempt in attempts
            if attempt.get("server") and attempt.get("server") != "not disclosed"
        ),
        "Unknown",
    )
    return {
        "attempts": sorted(attempts, key=lambda item: item.get("url", "")),
        "missing_headers": missing,
        "server": server,
    }


def inspect_tls(hostname: str) -> dict[str, Any]:
    """Collect TLS version, cipher, issuer, SANs, and expiry safely."""
    server_name = None if _is_ip_address(hostname) else hostname
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=HTTP_TIMEOUT) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as tls_socket:
                certificate = tls_socket.getpeercert()
                expires = certificate.get("notAfter")
                expiry = (
                    datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z")
                    if expires else None
                )
                expiry_utc = expiry.replace(tzinfo=timezone.utc) if expiry else None
                days = (
                    (expiry_utc - datetime.now(timezone.utc)).days
                    if expiry_utc else None
                )
                issuer = dict(item[0] for item in certificate.get("issuer", ()))
                sans = [
                    value for kind, value in certificate.get("subjectAltName", ())
                    if kind == "DNS"
                ]
                return {
                    "status": "ok",
                    "tls_version": tls_socket.version(),
                    "cipher": tls_socket.cipher()[0] if tls_socket.cipher() else None,
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "expires_at": expiry_utc.isoformat() if expiry_utc else None,
                    "days_remaining": days,
                    "sans": sans,
                    "weak_or_expiring": bool(days is not None and days <= 30),
                    "error": None,
                }
    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, ValueError) as exc:
        return {"status": "unavailable", "error": str(exc)}


def enumerate_subdomains(hostname: str) -> dict[str, Any]:
    """Use public CT data when requested; failures become structured findings."""
    if _is_ip_address(hostname) or "." not in hostname:
        return {"status": "skipped", "subdomains": [], "error": "DNS domain required"}
    query = urlencode({"q": f"%.{hostname}", "output": "json"})
    request = Request(f"https://crt.sh/?{query}", headers={"User-Agent": USER_AGENT})
    try:
        with urlopen(request, timeout=HTTP_TIMEOUT) as response:
            payload = json.loads(response.read(2_000_000).decode("utf-8"))
        names = {
            name.strip().lower().lstrip("*.")
            for record in payload if isinstance(record, dict)
            for name in str(record.get("name_value", "")).splitlines()
            if name.strip().lower().lstrip("*.") == hostname
            or name.strip().lower().lstrip("*.").endswith(f".{hostname}")
        }
        return {"status": "ok", "subdomains": sorted(names), "error": None}
    except (HTTPError, URLError, TimeoutError, OSError, ValueError, TypeError) as exc:
        return {"status": "unavailable", "subdomains": [], "error": str(exc)}


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def run_recon(target: str, quick: bool = False) -> dict[str, Any]:
    """Run local reconnaissance with isolated failure handling per subsystem."""
    resolution = resolve_target(target)
    hostname = resolution["hostname"]
    findings: dict[str, Any] = {
        "target": hostname,
        "scan_started_at": datetime.now(timezone.utc).isoformat(),
        "dns": resolution,
        "ports": scan_ports(hostname),
        "web": inspect_web(hostname),
        "tls": inspect_tls(hostname),
    }
    findings["subdomains"] = (
        {"status": "skipped", "subdomains": [], "error": "quick scan"}
        if quick else enumerate_subdomains(hostname)
    )
    return findings
