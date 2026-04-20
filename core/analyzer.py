"""
Check orchestrator.

Runs the selected check modules and aggregates their findings.
"""

from __future__ import annotations

import logging

from checks.anonymous_bind import Finding
from config.settings import Severity, SEVERITY_ORDER
from core.connector import LDAPConnector, LDAPConnectionResult
from core.enumerator import DirectoryInfo

logger = logging.getLogger(__name__)


def run_checks(
    connector: LDAPConnector,
    conn_result: LDAPConnectionResult,
    dir_info: DirectoryInfo,
    checks: set[str],
) -> list[Finding]:
    """
    Execute the requested checks and return a sorted list of findings.

    Args:
        connector:   Connected LDAPConnector (for checks that need live queries).
        conn_result: Result from the initial connection / bind.
        dir_info:    Pre-collected directory information.
        checks:      Set of check identifiers to run
                     (subset of: anon, pwpol, privs, attrs, rootdse).

    Returns:
        All findings sorted by severity (highest first).
    """
    findings: list[Finding] = []
    base_dn = dir_info.base_dn

    if "anon" in checks:
        logger.debug("Running check: anon (LDAP-001)")
        from checks import anonymous_bind
        findings.extend(anonymous_bind.run(
            host=connector.config.host,
            port=connector.config.port,
            base_dn=base_dn,
            use_ssl=connector.config.use_ssl,
            timeout=connector.config.timeout,
        ))

    if "pwpol" in checks:
        logger.debug("Running check: pwpol (LDAP-002)")
        from checks import password_policy
        findings.extend(password_policy.run(connector, base_dn))

    if "privs" in checks:
        logger.debug("Running check: privs (LDAP-003)")
        from checks import privileged_accounts
        findings.extend(privileged_accounts.run(connector, dir_info))

    if "attrs" in checks:
        logger.debug("Running check: attrs (LDAP-004)")
        from checks import missing_attributes
        findings.extend(missing_attributes.run(dir_info))

    if "rootdse" in checks:
        logger.debug("Running check: rootdse (LDAP-005)")
        findings.extend(_check_rootdse(dir_info))

    if "ldapcfg" in checks:
        logger.debug("Running check: ldapcfg (LDAP-006, LDAP-007)")
        from checks import ldap_config
        findings.extend(ldap_config.run(
            connector=connector,
            host=connector.config.host,
            port=connector.config.port,
            bind_dn=connector.config.bind_dn,
            bind_password=connector.config.bind_password,
            timeout=connector.config.timeout,
        ))

    if "kerb" in checks:
        logger.debug("Running check: kerb (KERB-001 to KERB-004)")
        from checks import kerberos
        findings.extend(kerberos.run(dir_info))

    if "acc" in checks:
        logger.debug("Running check: acc (ACC-001)")
        from checks import account
        findings.extend(account.run(dir_info))

    if "priv" in checks:
        logger.debug("Running check: priv (PRIV-001, PRIV-002)")
        from checks import privilege
        findings.extend(privilege.run(connector, dir_info))

    if "comp" in checks:
        logger.debug("Running check: comp (COMP-001, COMP-002, COMP-003)")
        from checks import computers
        findings.extend(computers.run(connector, dir_info))

    if "pol" in checks:
        logger.debug("Running check: pol (POL-001)")
        from checks import policy
        findings.extend(policy.run(connector, dir_info))

    # Sort: highest severity first, then by check ID
    findings.sort(
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), f.id),
    )

    logger.info("Checks complete — %d finding(s) total", len(findings))
    return findings


def _check_rootdse(dir_info: DirectoryInfo) -> list[Finding]:
    """
    LDAP-005 — Report if the rootDSE is readable and what it exposes.
    This is always INFO severity: server metadata exposure is expected
    but worth documenting.
    """
    from config.settings import CheckID

    if not dir_info.root_dse:
        return []

    exposed_attrs = sorted(dir_info.root_dse.keys())
    sensitive = [a for a in exposed_attrs if any(
        kw in a.lower() for kw in ("version", "vendor", "supported", "naming", "schema")
    )]

    return [Finding(
        id=CheckID.ROOTDSE_EXPOSURE,
        title="Server metadata readable via rootDSE",
        severity=Severity.INFO,
        description=(
            f"The rootDSE is readable and exposes {len(exposed_attrs)} attributes "
            "including server version, supported controls, and naming contexts. "
            "While normal for LDAP, this information assists directory reconnaissance."
        ),
        evidence={
            "total_attributes": len(exposed_attrs),
            "sensitive_attributes": sensitive,
            "naming_contexts": dir_info.naming_contexts,
            "server_info": dir_info.server_info,
        },
        recommendation=(
            "Restrict rootDSE readability to authenticated users if the server "
            "supports it, or ensure the exposed information does not include "
            "sensitive internal details."
        ),
    )]
