"""CyberRecon-AI 150-point defensive reconnaissance CLI."""

import argparse
from datetime import datetime, timezone
import json
import os
import shutil
import sys
from typing import Any

try:
    from importlib import import_module
    Console = import_module("rich.console").Console
    Panel = import_module("rich.panel").Panel
    Table = import_module("rich.table").Table
except ImportError:
    Console = Panel = Table = None

from modules.domain_intel import run_domain_intel
from modules.dns_topo import run_dns_topology
from modules.email_sec import run_email_security
from modules.geo_infra import run_geo_infra
from modules.recon import run_recon
from modules.tech_stack import run_tech_stack
from modules.headers_audit import run_headers_audit
from modules.endpoints import run_endpoints
from modules.session_sec import run_session_security
from modules.risk_engine import run_risk_engine, generate_remediation


VERSION = "v1.0"
AUTHOR = "MR ASIF"
TOOL = "CyberRecon-AI v2.0"
BANNER = """  ██████╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗███╗   ██╗
 ██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝████╗  ██║
 ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██║     ██╔██╗ ██║
 ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║     ██║╚██╗██║
 ╚██████╗   ██║   ██████╔╝███████╗██║  ██║╚██████╗██║ ╚████║
  ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═══╝"""
MANUAL = "\n".join([
    "CyberRecon-AI 150-Point Defensive Reconnaissance Framework",
    "Prepared for MR ASIF | 11 domains / 150 checks",
    "1-15 Domain intelligence | 16-30 DNS topology | 31-40 email security",
    "41-50 geo/infrastructure | 51-65 TLS | 66-85 ports",
    "86-100 technology stack | 101-112 headers | 113-132 endpoints",
    "133-140 sessions | 141-150 risk, controls, remediation and reporting.",
    "Use only against authorized targets.",
])


class PlainConsole:
    def print(self, value: Any = "") -> None:
        print(value)


console = Console() if Console else PlainConsole()


def print_banner() -> None:
    width = max(20, min(58, shutil.get_terminal_size(fallback=(58, 20)).columns))
    encoding = (getattr(sys.stdout, "encoding", "") or "").lower()
    if Console and "utf" in encoding:
        console.print(BANNER, soft_wrap=True, crop=True, width=width)
        console.print("─" * min(width, 58), soft_wrap=True)
        console.print("  ⚡ CyberRecon-AI // 150-Point Autonomous Security Suite", soft_wrap=True)
        console.print(f"  👤 Developed & Maintained by: {AUTHOR}", soft_wrap=True)
        console.print("─" * min(width, 58), soft_wrap=True)
    else:
        console.print("+" + "-" * min(56, width - 2) + "+")
        console.print("| CyberRecon-AI // 150-Point Security Suite")
        console.print(f"| Developed & Maintained by: {AUTHOR}")
        console.print("+" + "-" * min(56, width - 2) + "+")


def reports_dir() -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
    os.makedirs(path, exist_ok=True)
    return path


def safe_target(target: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in target)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description="150-point standalone defensive audit suite.")
    root.add_argument("--version", action="version", version=f"CyberRecon-AI framework {VERSION} - Prepared for {AUTHOR}")
    root.add_argument("--manual", action="store_true", help="print the complete framework reference")
    sub = root.add_subparsers(dest="command")
    commands = ("recon", "mail", "geo", "ports", "stack", "headers", "endpoints",
                "session", "score", "full", "diff", "report")
    for command in commands:
        item = sub.add_parser(command)
        item.add_argument("target")
        item.add_argument("--format", choices=("md", "json"), default="json")
    wordlist = sub.add_parser("wordlist")
    wordlist.add_argument("--add", help="word or path to append to the local wordlist")
    sub.add_parser("config-show")
    return root


def collect(target: str, command: str) -> dict[str, Any]:
    recon = run_recon(target)
    data: dict[str, Any] = {
        "target": target,
        "framework": VERSION,
        "author": AUTHOR,
        "tool": TOOL,
    }
    if command in ("recon", "full"):
        data.update({"domain_intel": run_domain_intel(target), "dns_topology": run_dns_topology(target),
                     "recon": recon})
    if command in ("mail", "full"):
        dns = data.get("dns_topology") or run_dns_topology(target)
        data["email_security"] = run_email_security(target, dns)
    if command in ("geo", "full"):
        data["geo_infra"] = run_geo_infra(target, data.get("dns_topology", {}), recon.get("web", {}))
    if command in ("ports", "full"):
        data["ports"] = recon.get("ports", [])
    if command in ("stack", "full"):
        data["tech_stack"] = run_tech_stack(recon.get("web", {}))
    if command in ("headers", "full"):
        data["headers"] = run_headers_audit(recon.get("web", {}))
    if command in ("endpoints", "full"):
        data["endpoints"] = run_endpoints(target)
    if command in ("session", "full"):
        data["session"] = run_session_security(recon.get("web", {}))
    if command in ("score", "full"):
        data["risk"] = run_risk_engine(recon)
    if command == "full":
        data["remediation"] = generate_remediation(
            recon, output_dir=os.path.join(reports_dir(), "remediation")
        )
    return data


def show(data: dict[str, Any]) -> None:
    for key, value in data.items():
        if key in ("target", "framework", "author"):
            continue
        if Table and isinstance(value, dict):
            table = Table(title=key.replace("_", " ").title())
            table.add_column("Field")
            table.add_column("Value")
            for field, item in list(value.items())[:25]:
                table.add_row(str(field), json.dumps(item, default=str)[:500])
            console.print(table)
        else:
            console.print(f"\n{key.upper()}\n{json.dumps(value, indent=2, default=str)}")


def export_data(target: str, data: dict[str, Any], fmt: str = "json") -> str:
    stamp = safe_target(target)
    payload = {**data, "generated_at": datetime.now(timezone.utc).isoformat()}
    if fmt == "md":
        path = os.path.join(reports_dir(), f"{stamp}_full_audit.md")
        content = f"# CyberRecon-AI 150-Point Audit: {target}\n\n> **Generated by:** CyberRecon-AI Security Engine | **Developer:** {AUTHOR}\n\n```json\n{json.dumps(payload, indent=2, default=str)}\n```\n"
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
    else:
        path = os.path.join(reports_dir(), f"{stamp}_full_audit.json")
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, indent=2, default=str)
            handle.write("\n")
    return path


def _flatten(value: Any, prefix: str = "") -> dict[str, str]:
    """Create stable scalar paths for readable field-level comparisons."""
    if isinstance(value, dict):
        result: dict[str, str] = {}
        for key, item in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            result.update(_flatten(item, path))
        return result
    if isinstance(value, list):
        return {prefix: json.dumps(value, sort_keys=True, default=str)}
    return {prefix: json.dumps(value, sort_keys=True, default=str)}


def diff_scan(target: str) -> dict[str, Any]:
    """Compare a fresh full audit with the previously stored JSON report."""
    path = os.path.join(reports_dir(), f"{safe_target(target)}_full_audit.json")
    if not os.path.isfile(path):
        return {"status": "baseline_missing", "path": path, "changes": []}
    with open(path, encoding="utf-8") as handle:
        previous = json.load(handle)
    current = collect(target, "full")
    old_values = _flatten(previous)
    new_values = _flatten(current)
    changes = []
    for field in sorted(set(old_values) | set(new_values)):
        if field not in old_values:
            changes.append({"field": field, "change": "added", "current": new_values[field]})
        elif field not in new_values:
            changes.append({"field": field, "change": "removed", "previous": old_values[field]})
        elif old_values[field] != new_values[field]:
            changes.append({
                "field": field,
                "change": "modified",
                "previous": old_values[field],
                "current": new_values[field],
            })
    return {"status": "compared", "path": path, "changes": changes}


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.manual:
        print(MANUAL)
        return 0
    print_banner()
    if args.command == "config-show":
        console.print(json.dumps({"timeout": 5.0, "threads": 12, "resolvers": "system resolver"}, indent=2))
        return 0
    if args.command == "wordlist":
        path = os.path.join(reports_dir(), "custom_wordlist.txt")
        if args.add:
            with open(path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(args.add.strip() + "\n")
        console.print(f"Wordlist: {path}")
        return 0
    if not args.command:
        parser().print_help()
        return 2
    try:
        if args.command == "diff":
            result = diff_scan(args.target)
            if result["status"] == "baseline_missing":
                console.print(f"No stored baseline found: {result['path']}")
            else:
                console.print(json.dumps(result, indent=2, default=str))
            return 0
        data = collect(args.target, args.command)
        if args.command == "report":
            path = export_data(args.target, data, args.format)
        else:
            show(data)
            path = export_data(args.target, data)
        console.print(f"Exported: {path}")
        return 0
    except (OSError, ValueError) as exc:
        console.print(f"Audit error: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
