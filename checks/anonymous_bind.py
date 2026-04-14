"""
LDAP-001 — Anonymous bind check.

Attempts an unauthenticated bind to the target server and, if successful,
measures how much of the directory is readable without credentials.

This is purely a read-only probe: no data is written, no credentials are
guessed.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ldap3 import Connection, Server, SYNC, ANONYMOUS, SUBTREE, BASE
from ldap3.core.exceptions import LDAPException, LDAPBindError

from config.settings import CheckID, Severity

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Finding dataclass (shared shape used by all checks)
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    description: str
    evidence: dict   = field(default_factory=dict)
    recommendation: str = ""


# ---------------------------------------------------------------------------
# Check
# ---------------------------------------------------------------------------

def run(host: str, port: int, base_dn: str, use_ssl: bool = False, timeout: int = 10) -> list[Finding]:
    """
    Try an anonymous bind to *host*:*port*.

    Returns a list of Finding objects (0 or 1 entries).
    Does NOT use the existing authenticated connection — a fresh connection
    is opened with no credentials to accurately test the server's policy.

    Args:
        host:     LDAP server hostname or IP.
        port:     TCP port.
        base_dn:  Base DN to probe read access after a successful anon bind.
        use_ssl:  Whether to use LDAPS.
        timeout:  Connection timeout in seconds.
    """
    findings: list[Finding] = []

    logger.debug("LDAP-001: testing anonymous bind to %s:%d", host, port)

    try:
        server = Server(host, port=port, use_ssl=use_ssl, connect_timeout=timeout)
        conn   = Connection(
            server,
            authentication=ANONYMOUS,
            client_strategy=SYNC,
            receive_timeout=timeout,
            raise_exceptions=False,   # handle errors manually here
            read_only=True,
        )
        bound = conn.bind()
    except LDAPException as exc:
        logger.debug("LDAP-001: anonymous bind raised exception: %s", exc)
        return findings   # cannot connect at all — not a finding

    if not bound or not conn.bound:
        logger.debug("LDAP-001: anonymous bind rejected (good)")
        conn.unbind()
        return findings

    # --- Bind succeeded: measure exposure ---
    logger.debug("LDAP-001: anonymous bind accepted — probing read access")

    readable_base  = _can_read_base(conn, base_dn)
    entry_count    = _count_entries(conn, base_dn) if readable_base else 0
    rootdse_attrs  = _read_rootdse(conn)

    conn.unbind()

    evidence = {
        "anonymous_bind_accepted": True,
        "base_dn_readable":        readable_base,
        "visible_entry_count":     entry_count,
        "rootdse_attributes_exposed": sorted(rootdse_attrs),
    }

    # Severity scales with exposure
    if readable_base and entry_count > 0:
        severity    = Severity.HIGH
        description = (
            f"The server accepts unauthenticated (anonymous) LDAP binds and "
            f"exposes at least {entry_count} directory entries under '{base_dn}' "
            f"without any credentials."
        )
    else:
        severity    = Severity.MEDIUM
        description = (
            "The server accepts unauthenticated (anonymous) LDAP binds. "
            "Directory entries are not directly readable, but server metadata "
            "may still be exposed (rootDSE, naming contexts, supported controls)."
        )

    findings.append(Finding(
        id=CheckID.ANONYMOUS_BIND,
        title="Anonymous bind accepted",
        severity=severity,
        description=description,
        evidence=evidence,
        recommendation=(
            "Disable anonymous bind in the LDAP server configuration. "
            "For OpenLDAP set 'disallow bind_anon'. "
            "For Active Directory this is controlled via the "
            "'dsHeuristics' attribute on the Directory Service object."
        ),
    ))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _can_read_base(conn: Connection, base_dn: str) -> bool:
    """Check whether the base DN is readable anonymously (BASE scope)."""
    try:
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=["objectClass"],
        )
        return bool(conn.entries)
    except LDAPException:
        return False


def _count_entries(conn: Connection, base_dn: str, limit: int = 50) -> int:
    """Count entries visible under base_dn (SUBTREE), capped at *limit*."""
    try:
        conn.search(
            search_base=base_dn,
            search_filter="(objectClass=*)",
            search_scope=SUBTREE,
            attributes=["objectClass"],
            size_limit=limit,
        )
        return len(conn.entries)
    except LDAPException:
        return 0


def _read_rootdse(conn: Connection) -> list[str]:
    """Return a list of attribute names readable from rootDSE anonymously."""
    try:
        conn.search(
            search_base="",
            search_filter="(objectClass=*)",
            search_scope=BASE,
            attributes=['*'],
        )
        if conn.entries:
            return list(conn.entries[0].entry_attributes)
    except LDAPException:
        pass
    return []
