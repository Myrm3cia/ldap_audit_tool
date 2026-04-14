"""
Report generator.

Writes audit findings to JSON and/or plain-text files.
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from checks.anonymous_bind import Finding
from config.settings import Severity, SEVERITY_ORDER
from core.enumerator import DirectoryInfo


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def write_report(
    findings: list[Finding],
    dir_info: DirectoryInfo,
    host: str,
    port: int,
    bind_dn: Optional[str],
    fmt: str,                    # "json" | "txt" | "both"
    output_path: Optional[str],  # path without extension; None → stdout
) -> None:
    """
    Write the audit report in the requested format.

    Args:
        findings:     Sorted list of Finding objects from the analyzer.
        dir_info:     Collected directory info (used for domain_info section).
        host:         Target LDAP server hostname.
        port:         Target LDAP server port.
        bind_dn:      Bind DN used (or None for anonymous).
        fmt:          Output format: "json", "txt", or "both".
        output_path:  Base file path (without extension). None → stdout.
    """
    report = _build_report(findings, dir_info, host, port, bind_dn)

    if fmt in ("json", "all"):
        _write_json(report, output_path)

    if fmt in ("txt", "all"):
        _write_txt(report, findings, output_path)

    if fmt in ("html", "all"):
        from output.html_reporter import write_html
        write_html(findings, dir_info, host, port, bind_dn, output_path)


# ---------------------------------------------------------------------------
# Report structure builder
# ---------------------------------------------------------------------------

def _build_report(
    findings: list[Finding],
    dir_info: DirectoryInfo,
    host: str,
    port: int,
    bind_dn: Optional[str],
) -> dict:
    by_sev = Counter(f.severity for f in findings)

    return {
        "metadata": {
            "tool":      "ldap-audit",
            "version":   "1.0.0",
            "target":    f"{host}:{port}",
            "base_dn":   dir_info.base_dn,
            "bind_dn":   bind_dn or "(anonymous)",
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        },
        "domain_info": {
            "naming_contexts":  dir_info.naming_contexts,
            "server_info":      dir_info.server_info,
            "ou_count":         dir_info.ou_count,
            "user_count":       dir_info.user_count,
            "group_count":      dir_info.group_count,
        },
        "findings": [_finding_to_dict(f) for f in findings],
        "summary": {
            "total_findings": len(findings),
            "by_severity": {
                sev.value: by_sev.get(sev, 0)
                for sev in [
                    Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                    Severity.LOW, Severity.INFO,
                ]
            },
        },
    }


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id":             f.id,
        "title":          f.title,
        "severity":       f.severity.value,
        "description":    f.description,
        "evidence":       f.evidence,
        "recommendation": f.recommendation,
    }


# ---------------------------------------------------------------------------
# JSON writer
# ---------------------------------------------------------------------------

def _write_json(report: dict, output_path: Optional[str]) -> None:
    content = json.dumps(report, indent=2, default=str)

    if output_path is None:
        print(content)
        return

    path = Path(output_path).with_suffix(".json")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"[+] JSON report written to: {path}")


# ---------------------------------------------------------------------------
# Plain-text writer
# ---------------------------------------------------------------------------

_SEP_MAJOR = "=" * 72
_SEP_MINOR = "-" * 72


def _write_txt(report: dict, findings: list[Finding], output_path: Optional[str]) -> None:
    lines: list[str] = []

    meta = report["metadata"]
    dom  = report["domain_info"]
    summ = report["summary"]

    # --- Header ---
    lines += [
        _SEP_MAJOR,
        "  LDAP SECURITY AUDIT REPORT",
        _SEP_MAJOR,
        f"  Target    : {meta['target']}",
        f"  Base DN   : {meta['base_dn']}",
        f"  Bind DN   : {meta['bind_dn']}",
        f"  Timestamp : {meta['timestamp']}",
        _SEP_MAJOR,
        "",
    ]

    # --- Domain info ---
    lines += [
        "DIRECTORY OVERVIEW",
        _SEP_MINOR,
        f"  OUs found    : {dom['ou_count']}",
        f"  Users found  : {dom['user_count']}",
        f"  Groups found : {dom['group_count']}",
        f"  Naming contexts:",
    ]
    for nc in dom["naming_contexts"]:
        lines.append(f"    - {nc}")
    if dom["server_info"].get("vendor_name"):
        lines.append(f"  Server vendor : {dom['server_info']['vendor_name']}")
    if dom["server_info"].get("vendor_version"):
        lines.append(f"  Server version: {dom['server_info']['vendor_version']}")
    lines += ["", ""]

    # --- Summary ---
    lines += [
        "SUMMARY",
        _SEP_MINOR,
        f"  Total findings: {summ['total_findings']}",
    ]
    for sev, count in summ["by_severity"].items():
        marker = "  !!!" if sev in ("CRITICAL", "HIGH") and count > 0 else "     "
        lines.append(f"{marker} {sev:10}: {count}")
    lines += ["", ""]

    # --- Findings ---
    lines += [
        "FINDINGS",
        _SEP_MINOR,
    ]

    if not findings:
        lines.append("  No issues found.")
    else:
        for i, f in enumerate(findings, start=1):
            lines += [
                "",
                f"  [{i}] [{f.severity.value}] {f.id} — {f.title}",
                "",
                "  Description:",
                _wrap("    ", f.description),
                "",
                "  Evidence:",
            ]
            for k, v in f.evidence.items():
                lines.append(f"    {k}: {json.dumps(v, default=str)}")
            lines += [
                "",
                "  Recommendation:",
                _wrap("    ", f.recommendation),
                "",
                _SEP_MINOR,
            ]

    lines += ["", _SEP_MAJOR, "  End of report", _SEP_MAJOR, ""]

    content = "\n".join(lines)

    if output_path is None:
        print(content)
        return

    path = Path(output_path).with_suffix(".txt")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    print(f"[+] TXT  report written to: {path}")


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _wrap(indent: str, text: str, width: int = 72) -> str:
    """Simple word-wrap that respects an indent prefix."""
    import textwrap
    return textwrap.fill(text, width=width, initial_indent=indent, subsequent_indent=indent)
