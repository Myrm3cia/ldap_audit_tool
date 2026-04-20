"""
Privilege escalation path checks.

PRIV-001 — Nested group membership: users with indirect privileged access
PRIV-002 — AdminSDHolder: accounts protected by SDProp (adminCount=1)
"""

from __future__ import annotations

import logging

from ldap3 import SUBTREE
from ldap3.core.exceptions import LDAPException

from checks.anonymous_bind import Finding
from config.settings import CheckID, Severity
from core.connector import LDAPConnector
from core.enumerator import DirectoryInfo, UserEntry

logger = logging.getLogger(__name__)

# AD OID for recursive (transitive) group membership lookup
MATCHING_RULE_IN_CHAIN = "1.2.840.113556.1.4.1941"

PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators",
    "Server Operators",
    "Print Operators",
    "Group Policy Creator Owners",
]

UAC_DISABLED = 0x00000002


def run(connector: LDAPConnector, dir_info: DirectoryInfo) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_priv001(connector, dir_info))
    findings.extend(_priv002(connector, dir_info))
    return findings


# ---------------------------------------------------------------------------
# PRIV-001 — Nested group membership
# ---------------------------------------------------------------------------

def _priv001(connector: LDAPConnector, dir_info: DirectoryInfo) -> list[Finding]:
    """
    Use AD's LDAP_MATCHING_RULE_IN_CHAIN OID to find all users with
    transitive membership in privileged groups, then subtract direct members
    to identify those with INDIRECT (nested) access only.
    """
    base_dn = dir_info.base_dn
    if not base_dn:
        return []

    # Build a map of group CN → group DN for privileged groups
    priv_group_dns: dict[str, str] = {}
    for group in dir_info.groups:
        if group.cn in PRIVILEGED_GROUPS:
            priv_group_dns[group.cn] = group.dn

    if not priv_group_dns:
        logger.debug("PRIV-001: no privileged groups found to check")
        return []

    nested_map: dict[str, list[str]] = {}  # user_dn → [group_cn, ...]

    for group_cn, group_dn in priv_group_dns.items():
        # Transitive members (all levels)
        transitive_dns = _transitive_members(connector, base_dn, group_dn)
        # Direct members only
        direct_dns     = _direct_members(connector, base_dn, group_dn)

        indirect = transitive_dns - direct_dns
        for dn in indirect:
            nested_map.setdefault(dn, []).append(group_cn)

    if not nested_map:
        return []

    # Enrich with user info where available
    user_by_dn = {u.dn.lower(): u for u in dir_info.users}
    accounts = []
    for dn, groups in nested_map.items():
        u = user_by_dn.get(dn.lower())
        accounts.append({
            "dn":             dn,
            "sAMAccountName": _first(u, "sAMAccountName") if u else "",
            "indirectGroups": groups,
        })

    return [Finding(
        id=CheckID.NESTED_GROUPS,
        title="Users with indirect privileged group membership",
        severity=Severity.HIGH,
        description=(
            f"{len(accounts)} account(s) have indirect (nested) membership in one or more "
            "privileged groups. These accounts inherit elevated privileges through group nesting "
            "which may not be immediately visible in standard group management tools."
        ),
        evidence={
            "count": len(accounts),
            "accounts": accounts[:30],
            "truncated": len(accounts) > 30,
        },
        recommendation=(
            "Audit group nesting in privileged groups. Flatten group structures where possible "
            "and apply the principle of least privilege. Use 'AD Administrative Center' or "
            "PowerShell Get-ADGroupMember -Recursive to review transitive membership."
        ),
    )]


def _transitive_members(connector: LDAPConnector, base_dn: str, group_dn: str) -> set[str]:
    """Return DNs of all objects with transitive membership in group_dn."""
    try:
        entries = connector.search(
            search_base=base_dn,
            search_filter=f"(memberOf:{MATCHING_RULE_IN_CHAIN}:={group_dn})",
            attributes=["distinguishedName"],
            search_scope=SUBTREE,
            size_limit=1000,
        )
        return {e.entry_dn for e in entries}
    except Exception as exc:
        logger.debug("PRIV-001: transitive member search failed for %s: %s", group_dn, exc)
        return set()


def _direct_members(connector: LDAPConnector, base_dn: str, group_dn: str) -> set[str]:
    """Return DNs of direct members of group_dn."""
    try:
        entries = connector.search(
            search_base=base_dn,
            search_filter=f"(memberOf={group_dn})",
            attributes=["distinguishedName"],
            search_scope=SUBTREE,
            size_limit=1000,
        )
        return {e.entry_dn for e in entries}
    except Exception as exc:
        logger.debug("PRIV-001: direct member search failed for %s: %s", group_dn, exc)
        return set()


# ---------------------------------------------------------------------------
# PRIV-002 — AdminSDHolder
# ---------------------------------------------------------------------------

def _priv002(connector: LDAPConnector, dir_info: DirectoryInfo) -> list[Finding]:
    """
    Find all objects with adminCount=1. These are protected by the
    AdminSDHolder / SDProp process. Accounts that are no longer in any
    privileged group but retain adminCount=1 are 'orphaned' — their ACLs
    are still managed by SDProp (locked down) but they may be overlooked.
    """
    base_dn = dir_info.base_dn
    if not base_dn:
        return []

    entries = connector.search(
        search_base=base_dn,
        search_filter="(adminCount=1)",
        attributes=['*'],
        search_scope=SUBTREE,
        size_limit=500,
    )

    if not entries:
        return []

    # Determine which privileged group DNs exist
    priv_group_dns = {g.dn.lower() for g in dir_info.groups if g.cn in PRIVILEGED_GROUPS}

    protected   = []
    orphaned    = []

    for e in entries:
        dn     = e.entry_dn
        sam    = _attr_first(e, "sAMAccountName")
        member_of = []
        try:
            raw = e["memberOf"].value
            if raw is None:
                member_of = []
            elif isinstance(raw, list):
                member_of = [str(v) for v in raw]
            else:
                member_of = [str(raw)]
        except Exception:
            member_of = []

        in_priv_group = any(g.lower() in priv_group_dns for g in member_of)
        entry_info    = {"dn": dn, "sAMAccountName": sam, "memberOf": member_of[:5]}

        if in_priv_group:
            protected.append(entry_info)
        else:
            orphaned.append(entry_info)

    findings = []

    if protected:
        findings.append(Finding(
            id=CheckID.ADMINSDHOLDER,
            title="Accounts protected by AdminSDHolder (adminCount=1)",
            severity=Severity.INFO,
            description=(
                f"{len(protected)} account(s) are in privileged groups and have adminCount=1. "
                "Their ACLs are managed by SDProp every 60 minutes. "
                "This is expected for privileged accounts but increases the attack surface."
            ),
            evidence={
                "count": len(protected),
                "accounts": protected[:20],
                "truncated": len(protected) > 20,
            },
            recommendation=(
                "Regularly review the list of adminCount=1 accounts. "
                "Ensure only necessary accounts are in privileged groups."
            ),
        ))

    if orphaned:
        findings.append(Finding(
            id=CheckID.ADMINSDHOLDER,
            title="Orphaned AdminSDHolder accounts (adminCount=1, not in privileged groups)",
            severity=Severity.MEDIUM,
            description=(
                f"{len(orphaned)} account(s) have adminCount=1 but are NOT currently members "
                "of any known privileged group. These are 'SDProp orphans' — their ACLs are "
                "still locked by SDProp, making them harder to manage, and they may have "
                "retained elevated permissions from a previous privileged role."
            ),
            evidence={
                "count": len(orphaned),
                "accounts": orphaned[:20],
                "truncated": len(orphaned) > 20,
            },
            recommendation=(
                "For each orphaned account: if no longer privileged, set adminCount=0 and "
                "restore default ACL inheritance. Use 'dsacls' or AD administrative tools "
                "to reset permissions. Verify these accounts do not retain sensitive access."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _first(u: UserEntry | None, attr: str) -> str:
    if u is None:
        return ""
    val = u.attributes.get(attr, [])
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val) if val else ""


def _attr_first(entry, attr: str) -> str:
    try:
        val = entry[attr].value
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val is not None else ""
    except Exception:
        return ""
