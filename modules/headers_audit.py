"""HTTP security-header audit adapter."""

from typing import Any


def run_headers_audit(web_data: dict[str, Any]) -> dict[str, Any]:
    missing = sorted(set(web_data.get("missing_headers", [])))
    return {"missing": missing, "present": [], "cors_permissive": "unknown"}
