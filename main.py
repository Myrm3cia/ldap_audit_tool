#!/usr/bin/env python3
"""
ldap-audit — LDAP Security Posture Auditing Tool
-------------------------------------------------
Connects to an LDAP server (authenticated or anonymous) and performs
read-only security checks. No exploit, brute-force, or bypass techniques.

Usage examples:
  python main.py --host ldap.example.com --bind-dn "cn=admin,dc=example,dc=com" --bind-password secret
  python main.py --host ldap.example.com --anon
  python main.py --host ldap.example.com --port 636 --use-ssl --bind-dn "..." --bind-password "..." --output report
"""

from __future__ import annotations

import argparse
import getpass
import logging
import sys
from pathlib import Path

from config.settings import DEFAULT_LDAP_PORT, DEFAULT_LDAPS_PORT, SEVERITY_COLORS, COLOR_RESET, Severity
from core.connector import LDAPConnectionConfig, LDAPConnector
from core.enumerator import LDAPEnumerator
from core.analyzer import run_checks
from output.reporter import write_report


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        format="%(levelname)s [%(name)s] %(message)s",
        level=level,
        stream=sys.stderr,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ldap-audit",
        description="Read-only LDAP security posture auditing tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Authenticated bind, auto-detect base DN
  python main.py --host ldap.example.com \\
                 --bind-dn "cn=admin,dc=example,dc=com" \\
                 --bind-password secret

  # Prompt for password (safer than passing on CLI)
  python main.py --host ldap.example.com \\
                 --bind-dn "cn=admin,dc=example,dc=com" \\
                 --ask-password

  # Test anonymous bind only
  python main.py --host ldap.example.com --anon

  # LDAPS, specific base DN, JSON + TXT report
  python main.py --host ldap.example.com --port 636 --use-ssl \\
                 --bind-dn "cn=admin,dc=example,dc=com" --ask-password \\
                 --base-dn "dc=example,dc=com" \\
                 --format both --output ./reports/audit
""",
    )

    # --- Connection ---
    conn = parser.add_argument_group("Connection")
    conn.add_argument("--host", required=True, metavar="HOST",
                      help="LDAP server hostname or IP.")
    conn.add_argument("--port", type=int, default=None, metavar="PORT",
                      help=f"TCP port (default: {DEFAULT_LDAP_PORT} plain, {DEFAULT_LDAPS_PORT} SSL).")
    conn.add_argument("--use-ssl", action="store_true",
                      help="Use LDAPS (TLS from the start, typically port 636).")
    conn.add_argument("--use-tls", action="store_true",
                      help="Use StartTLS on a plain LDAP connection.")
    conn.add_argument("--no-verify-cert", action="store_true",
                      help="Skip TLS certificate verification (useful for self-signed certs in test environments).")
    conn.add_argument("--timeout", type=int, default=10, metavar="SEC",
                      help="Connection / receive timeout in seconds (default: 10).")

    # --- Authentication ---
    auth = parser.add_argument_group("Authentication")
    auth_ex = auth.add_mutually_exclusive_group()
    auth_ex.add_argument("--anon", action="store_true",
                         help="Force anonymous bind (no credentials).")
    auth_ex.add_argument("--bind-dn", metavar="DN",
                         help="Bind DN for authenticated access.")
    auth.add_argument("--bind-password", metavar="PASSWORD",
                      help="Bind password (avoid: prefer --ask-password).")
    auth.add_argument("--ask-password", action="store_true",
                      help="Prompt for bind password interactively (safer than --bind-password).")

    # --- Directory ---
    directory = parser.add_argument_group("Directory")
    directory.add_argument("--base-dn", metavar="DN",
                           help="Base DN for searches. Auto-detected from rootDSE if omitted.")

    # --- Checks ---
    checks = parser.add_argument_group("Checks")
    checks.add_argument(
        "--checks",
        metavar="CHECK[,CHECK...]",
        default="all",
        help=(
            "Comma-separated list of checks to run. "
            "Available: anon, pwpol, privs, attrs, rootdse. "
            "Use 'all' to run all checks (default)."
        ),
    )

    # --- Output ---
    out = parser.add_argument_group("Output")
    out.add_argument("--format", choices=["json", "txt", "html", "all"], default="json",
                     help="Report format: json, txt, html, all (json+txt+html) (default: json).")
    out.add_argument("--output", metavar="PATH",
                     help="Output file path without extension (e.g. ./report). "
                          "If omitted, report is printed to stdout.")
    out.add_argument("--verbose", "-v", action="store_true",
                     help="Enable debug-level logging.")

    return parser


def _resolve_port(args: argparse.Namespace) -> int:
    if args.port:
        return args.port
    return DEFAULT_LDAPS_PORT if args.use_ssl else DEFAULT_LDAP_PORT


def _resolve_password(args: argparse.Namespace) -> str | None:
    if args.anon:
        return None
    if args.ask_password:
        return getpass.getpass("Bind password: ")
    return args.bind_password


def _resolve_checks(raw: str) -> set[str]:
    all_checks = {"anon", "pwpol", "privs", "attrs", "rootdse"}
    if raw.strip().lower() == "all":
        return all_checks
    selected = {c.strip().lower() for c in raw.split(",")}
    unknown = selected - all_checks
    if unknown:
        print(f"[!] Unknown checks ignored: {', '.join(sorted(unknown))}", file=sys.stderr)
    return selected & all_checks


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    _setup_logging(args.verbose)

    # Validate: if bind-dn is set, a password must be supplied somehow
    if args.bind_dn and not args.bind_password and not args.ask_password:
        print(
            "[!] --bind-dn requires either --bind-password or --ask-password.",
            file=sys.stderr,
        )
        return 1

    password = _resolve_password(args)
    port     = _resolve_port(args)
    checks   = _resolve_checks(args.checks)

    config = LDAPConnectionConfig(
        host=args.host,
        port=port,
        use_ssl=args.use_ssl,
        use_tls=args.use_tls,
        bind_dn=None if args.anon else args.bind_dn,
        bind_password=password,
        base_dn=args.base_dn,
        timeout=args.timeout,
        validate_cert=not args.no_verify_cert,
    )

    print(f"[*] Connecting to {args.host}:{port} ...", flush=True)

    connector = LDAPConnector(config)
    result = connector.connect()

    if not result.success:
        print(f"[!] Connection failed: {result.error}", file=sys.stderr)
        return 1

    bind_type = "anonymous" if result.anonymous else f"as {args.bind_dn}"
    print(f"[+] Connected ({bind_type})")
    if result.base_dn:
        print(f"[+] Base DN: {result.base_dn}")
    if result.naming_contexts:
        print(f"[+] Naming contexts: {', '.join(result.naming_contexts)}")

    # --- Enumerate directory ---
    print("[*] Enumerating directory...")
    enumerator = LDAPEnumerator(connector, result)
    dir_info = enumerator.enumerate()

    print(f"[+] OUs found:    {dir_info.ou_count}")
    print(f"[+] Users found:  {dir_info.user_count}")
    print(f"[+] Groups found: {dir_info.group_count}")
    if dir_info.errors:
        for err in dir_info.errors:
            print(f"[!] {err}", file=sys.stderr)

    # --- Run checks ---
    print(f"[*] Running checks: {', '.join(sorted(checks))}")
    findings = run_checks(connector, result, dir_info, checks)

    connector.disconnect()

    # --- Print findings to terminal ---
    print()
    if not findings:
        print("[+] No issues found.")
    else:
        print(f"[!] {len(findings)} finding(s):\n")
        for f in findings:
            color = SEVERITY_COLORS.get(f.severity, "")
            print(f"  {color}[{f.severity.value}]{COLOR_RESET} {f.id} — {f.title}")
            print(f"           {f.description}")
            print()

    # Summary
    from collections import Counter
    by_sev = Counter(f.severity for f in findings)
    print("Summary:", " | ".join(
        f"{sev.value}: {by_sev.get(sev, 0)}"
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    ))

    # --- Write report file (if requested) ---
    if args.output or args.format in ("json", "txt", "html", "all"):
        write_report(
            findings=findings,
            dir_info=dir_info,
            host=args.host,
            port=port,
            bind_dn=args.bind_dn,
            fmt=args.format,
            output_path=args.output,
        )

    # Exit code: 1 if any HIGH or CRITICAL findings
    critical_or_high = any(
        f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings
    )
    return 1 if critical_or_high else 0


if __name__ == "__main__":
    sys.exit(main())
