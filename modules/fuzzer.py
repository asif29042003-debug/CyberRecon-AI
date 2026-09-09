"""Safe, bounded sensitive-endpoint discovery using urllib and threads."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


PATHS = (
    "/admin", "/login", "/wp-admin", "/cpanel", "/dashboard",
    "/.env", "/.git/HEAD", "/config.json",
)
USER_AGENT = "CyberRecon-AI/4.0 (authorized defensive assessment)"


def _host(target: str) -> str:
    value = target.strip()
    parsed = urlparse(value if "://" in value else f"//{value}")
    if not parsed.hostname:
        raise ValueError("Target must be a domain or IP address.")
    return parsed.hostname


def _probe(base: str, path: str, timeout: float) -> dict[str, Any]:
    for scheme in ("https", "http"):
        url = f"{scheme}://{base}{path}"
        request = Request(url, headers={"User-Agent": USER_AGENT})
        try:
            with urlopen(request, timeout=timeout) as response:
                status = response.status
                classification = "[CRITICAL 200 OK]" if status == 200 else "[REVIEW]"
                return {"path": path, "url": url, "status": status, "classification": classification}
        except HTTPError as exc:
            classification = {403: "[RESTRICTED 403]", 404: "[SAFE 404]"}.get(exc.code, "[REVIEW]")
            return {"path": path, "url": url, "status": exc.code, "classification": classification}
        except (URLError, TimeoutError, OSError):
            continue
    return {"path": path, "url": f"https://{base}{path}", "status": None, "classification": "[UNREACHABLE]"}


def fuzz_target(target: str, timeout: float = 5.0) -> dict[str, Any]:
    """Probe a fixed low-impact endpoint list concurrently."""
    hostname = _host(target)
    with ThreadPoolExecutor(max_workers=8) as executor:
        jobs = [executor.submit(_probe, hostname, path, timeout) for path in PATHS]
        results = [job.result() for job in as_completed(jobs)]
    return {"target": hostname, "paths": list(PATHS), "results": sorted(results, key=lambda item: item["path"])}
