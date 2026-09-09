"""Aggregate 150-point framework risk and report helpers."""

from typing import Any
from .autofix import generate_fixes
from .vulnscan import analyze_vulnerabilities


def run_risk_engine(data: dict[str, Any]) -> dict[str, Any]:
    risk = analyze_vulnerabilities(data)
    return {**risk, "controls": ["OWASP ASVS 4.0", "CIS Controls v8"]}


def generate_remediation(data: dict[str, Any], output_dir: str | None = None) -> dict[str, Any]:
    return generate_fixes(data, output_dir=output_dir)
