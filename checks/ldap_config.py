"""
LDAP configuration security checks.

LDAP-006 — LDAP signing not enforced (detected via successful unsigned bind)
LDAP-007 — LDAPS not available or not enforced on port 636
"""

from __future__ import annotations

import logging
import socket
import ssl

from ldap3 import Connection, Server, SYNC, ANONYMOUS, SIMPLE, Tls
from ldap3.core.exceptions import LDAPException

from checks.anonymous_bind import Finding
from config.settings import CheckID, Severity, DEFAULT_LDAPS_PORT
from core.connector import LDAPConnector, LDAPConnectionConfig

logger = logging.getLogger(__name__)


def run(
    connector: LDAPConnector,
    host: str,
    port: int,
    bind_dn: str | None,
    bind_password: str | None,
    timeout: int = 10,
) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_ldap006(connector))
    findings.extend(_ldap007(host, port, timeout))
    return findings


# ---------------------------------------------------------------------------
# LDAP-006 — LDAP signing not enforced
# ---------------------------------------------------------------------------

def _ldap006(connector: LDAPConnector) -> list[Finding]:
    """
    If we successfully performed a simple bind without signing, the server
    does not require LDAP signing (ldapServerIntegrity < 2).
    This allows LDAP traffic to be intercepted and modified via MITM attacks.
    """
    # Our connector always uses simple bind without signing.
    # A successful bind is proof that signing is not required.
    if not connector.connection or not connector.connection.bound:
        return []

    # Additional check: try to read the DS policy object to get the actual setting
    integrity_value = _read_ldap_integrity(connector)

    description = (
        "The LDAP server accepted a simple bind without message signing. "
        "LDAP signing is not enforced (ldapServerIntegrity < 2). "
        "Without signing, LDAP traffic can be intercepted and modified "
        "by a man-in-the-middle attacker (LDAP relay attacks)."
    )
    evidence: dict = {"unsigned_bind_accepted": True}
    if integrity_value is not None:
        evidence["ldapServerIntegrity"] = integrity_value
        evidence["interpretation"] = {
            0: "None — no signing required",
            1: "Negotiate — signing negotiated but not required",
            2: "Require — signing required (secure)",
        }.get(integrity_value, f"Unknown value: {integrity_value}")

    return [Finding(
        id=CheckID.LDAP_SIGNING,
        title="LDAP signing not enforced",
        severity=Severity.HIGH,
        description=description,
        evidence=evidence,
        recommendation=(
            "Enforce LDAP signing on the domain controller: "
            "set 'Domain controller: LDAP server signing requirements' to 'Require signing' "
            "via GPO (Computer Configuration > Windows Settings > Security Settings > "
            "Local Policies > Security Options). "
            "Also enforce LDAP client signing via 'Network security: LDAP client signing requirements'."
        ),
    )]


def _read_ldap_integrity(connector: LDAPConnector) -> int | None:
    """
    Try to read ldapServerIntegrity from the DS policy object.
    Returns the integer value or None if not readable.
    """
    base_dn = connector.config.base_dn or ""
    if not base_dn:
        return None

    # Path to the Default Query Policy object
    policy_dn = (
        f"CN=Default Query Policy,CN=Query-Policies,"
        f"CN=Directory Service,CN=Windows NT,"
        f"CN=Services,CN=Configuration,{base_dn}"
    )
    try:
        entries = connector.search(
            search_base=policy_dn,
            search_filter="(objectClass=*)",
            attributes=["lDAPAdminLimits"],
            search_scope="BASE",
        )
        if entries:
            limits = entries[0].entry_attributes_as_dict.get("lDAPAdminLimits", [])
            for item in (limits if isinstance(limits, list) else [limits]):
                s = str(item)
                if s.startswith("LDAPSigningPolicy="):
                    return int(s.split("=")[1])
    except Exception as exc:
        logger.debug("LDAP-006: could not read DS policy: %s", exc)
    return None


# ---------------------------------------------------------------------------
# LDAP-007 — LDAPS not available
# ---------------------------------------------------------------------------

def _ldap007(host: str, port: int, timeout: int) -> list[Finding]:
    """
    Probe port 636 to check if LDAPS is available.
    If LDAPS is not configured, all LDAP traffic (including binds) flows
    in cleartext on port 389.
    """
    ldaps_available = _probe_ldaps(host, DEFAULT_LDAPS_PORT, timeout)

    if ldaps_available:
        # LDAPS is up. Check if plain LDAP on 389 is also still open.
        plain_open = _probe_tcp(host, 389, timeout)
        if plain_open and port == 389:
            return [Finding(
                id=CheckID.LDAPS_MISSING,
                title="LDAPS available but plain LDAP (port 389) is also open",
                severity=Severity.MEDIUM,
                description=(
                    "LDAPS is configured on port 636, but plain LDAP on port 389 is also "
                    "accepting connections. Clients may fall back to unencrypted LDAP. "
                    "If LDAPS is intended to be the only LDAP channel, port 389 should be blocked."
                ),
                evidence={
                    "ldaps_port_636": True,
                    "plain_ldap_port_389": True,
                },
                recommendation=(
                    "Block inbound port 389 on domain controllers via Windows Firewall "
                    "or network ACLs once all clients have been migrated to LDAPS. "
                    "Alternatively, enforce channel binding and LDAP signing as a compensating control."
                ),
            )]
        return []   # LDAPS available and plain LDAP is not exposed — good

    # LDAPS not available
    return [Finding(
        id=CheckID.LDAPS_MISSING,
        title="LDAPS (port 636) not available",
        severity=Severity.HIGH,
        description=(
            "LDAPS is not configured or not reachable on port 636. "
            "All LDAP communication including bind credentials and directory data "
            "travels in cleartext on the network."
        ),
        evidence={
            "ldaps_port_636": False,
            "plain_ldap_port_389": _probe_tcp(host, 389, timeout),
        },
        recommendation=(
            "Install a valid TLS certificate on all domain controllers and enable LDAPS. "
            "Use Active Directory Certificate Services (AD CS) or a public CA. "
            "After enablement, enforce LDAPS by blocking port 389."
        ),
    )]


def _probe_ldaps(host: str, port: int, timeout: int) -> bool:
    """Return True if an SSL handshake succeeds on host:port."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host):
                return True
    except Exception as exc:
        logger.debug("LDAP-007: LDAPS probe failed on %s:%d — %s", host, port, exc)
        return False


def _probe_tcp(host: str, port: int, timeout: int) -> bool:
    """Return True if a TCP connection can be established to host:port."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False
