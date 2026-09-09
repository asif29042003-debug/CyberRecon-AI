"""Port-scan domain adapter."""

from typing import Any
from .recon import run_recon


def run_port_scan(target: str, timeout: float = 5.0) -> dict[str, Any]:
    data = run_recon(target, timeout)
    return {"target": target, "ports": data.get("ports", [])}
