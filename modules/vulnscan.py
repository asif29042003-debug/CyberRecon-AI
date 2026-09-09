"""Deterministic offline risk correlation for reconnaissance findings."""

from typing import Any


def analyze_vulnerabilities(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Return risk findings, score, and a human-readable report."""
    score = 0
    findings: list[dict[str, Any]] = []
    open_ports = {
        item.get("port") for item in scan_data.get("ports", [])
        if item.get("state") == "open"
    }
    for port in sorted(open_ports):
        if port in {3306, 5432, 6379, 27017}:
            score += 40
            findings.append({"severity": "CRITICAL", "port": port, "message": "Database/service exposure."})
        elif port == 21:
            score += 25
            findings.append({"severity": "HIGH", "port": port, "message": "FTP may expose cleartext credentials."})
        elif port == 80 and 443 not in open_ports:
            score += 20
            findings.append({"severity": "HIGH", "port": port, "message": "HTTP is exposed without observed HTTPS."})
    missing = scan_data.get("web", {}).get("missing_headers", [])
    score += min(len(missing) * 5, 25)
    findings.extend({"severity": "MEDIUM", "header": header, "message": "Missing browser defense header."} for header in missing)
    server = scan_data.get("web", {}).get("server", "Unknown")
    if server != "Unknown":
        findings.append({"severity": "INFO", "message": f"Server banner disclosed: {server}."})
    score = min(score, 100)
    level = "CRITICAL" if score >= 70 else "HIGH" if score >= 40 else "MEDIUM" if score >= 15 else "LOW"
    whois = scan_data.get("whois", {})
    if whois.get("privacy_shield"):
        findings.append({"severity": "INFO", "message": "WHOIS privacy shielding detected."})
    lines = [f"## Offline Risk Assessment: {scan_data.get('target', 'Unknown')}",
             f"Overall risk score: **{score}/100 ({level})**"]
    lines.extend(f"- **[{item['severity']}]** {item['message']}" for item in findings)
    if not findings:
        lines.append("- No rule matches were observed; this is not proof of absence.")
    return {"score": score, "level": level, "findings": findings, "report": "\n".join(lines)}
