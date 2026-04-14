"""
LDAP-003 — Privileged account check.

Identifies accounts with elevated privileges by:
- Matching DN/CN patterns against known admin names
- Checking group membership in privileged groups
- Detecting stale or anomalous admin accounts

All operations are read-only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from checks.anonymous_bind import Finding
from config.settings import CheckID, Severity, PRIVILEGED_DN_PATTERNS
from core.connector import LDAPConnector
from core.enumerator import DirectoryInfo, UserEntry, GroupEntry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Well-known privileged group names (case-insensitive match)
# ---------------------------------------------------------------------------

PRIVILEGED_GROUP_NAMES = {
    "domain admins",
    "enterprise admins",
    "schema admins",
    "group policy creator owners",
    "account operators",
    "backup operators",
    "print operators",
    "server operators",
    "administrators",
    "domain controllers",
    "read-only domain controllers",
    # Generic / OpenLDAP / 389-DS
    "admins",
    "sudo",
    "sudoers",
    "wheel",
    "root",
}

# AD userAccountControl flags
UAC_ACCOUNT_DISABLED    = 0x0002
UAC_DONT_EXPIRE_PASSWD  = 0x10000
UAC_PASSWORD_NOT_REQD   = 0x0020


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(connector: LDAPConnector, dir_info: DirectoryInfo) -> list[Finding]:
    """
    Analyse users and groups for privilege-related security issues.

    Returns a list of Finding objects.
    """
    findings: list[Finding] = []

    priv_groups   = _find_privileged_groups(dir_info.groups)
    priv_users_by_group = _users_in_privileged_groups(dir_info.users, priv_groups)
    priv_users_by_dn    = _users_with_privileged_dn(dir_info.users)

    all_priv_dns = set(priv_users_by_group) | set(priv_users_by_dn)

    # --- Finding: privileged groups found ---
    if priv_groups:
        findings.append(Finding(
            id=CheckID.PRIVILEGED_ACCOUNTS,
            title="Privileged groups identified",
            severity=Severity.INFO,
            description=(
                f"Found {len(priv_groups)} group(s) with elevated privileges. "
                "Review membership to ensure the principle of least privilege is applied."
            ),
            evidence={
                "privileged_groups": [
                    {"dn": g.dn, "cn": g.cn, "member_count": len(g.members)}
                    for g in priv_groups
                ]
            },
            recommendation="Periodically review privileged group membership and remove unnecessary members.",
        ))

    # --- Finding: users in privileged groups ---
    if priv_users_by_group:
        findings.append(Finding(
            id=CheckID.PRIVILEGED_ACCOUNTS,
            title="Users with privileged group membership",
            severity=Severity.MEDIUM,
            description=(
                f"{len(priv_users_by_group)} user account(s) are members of "
                "one or more privileged groups."
            ),
            evidence={
                "users": [
                    {"dn": dn, "groups": groups}
                    for dn, groups in priv_users_by_group.items()
                ]
            },
            recommendation=(
                "Ensure all privileged accounts are justified, have strong passwords, "
                "and are used only for administrative tasks (separate from daily-use accounts)."
            ),
        ))

    # --- Finding: AD-specific anomalies on privileged accounts ---
    ad_findings = _check_ad_account_flags(dir_info.users, all_priv_dns)
    findings.extend(ad_findings)

    # --- Finding: enabled privileged accounts with non-expiring passwords ---
    noexpiry = _privileged_no_password_expiry(dir_info.users, all_priv_dns)
    if noexpiry:
        findings.append(Finding(
            id=CheckID.PRIVILEGED_ACCOUNTS,
            title="Privileged accounts with non-expiring passwords",
            severity=Severity.MEDIUM,
            description=(
                f"{len(noexpiry)} privileged account(s) have the "
                "'Password never expires' flag set."
            ),
            evidence={"accounts": [{"dn": u.dn, "cn": u.cn} for u in noexpiry]},
            recommendation=(
                "Remove the 'Password never expires' flag from privileged accounts "
                "and enforce regular password rotation."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_privileged_groups(groups: list[GroupEntry]) -> list[GroupEntry]:
    """Return groups whose CN matches a known privileged group name."""
    result = []
    for g in groups:
        cn_lower = g.cn.lower()
        if cn_lower in PRIVILEGED_GROUP_NAMES:
            result.append(g)
            logger.debug("LDAP-003: privileged group found: %s", g.dn)
        else:
            # Also match partial PRIVILEGED_DN_PATTERNS
            dn_lower = g.dn.lower()
            for pattern in PRIVILEGED_DN_PATTERNS:
                if pattern in dn_lower:
                    result.append(g)
                    logger.debug("LDAP-003: privileged group by DN pattern: %s", g.dn)
                    break
    return result


def _users_in_privileged_groups(
    users: list[UserEntry],
    priv_groups: list[GroupEntry],
) -> dict[str, list[str]]:
    """
    Build a mapping {user_dn: [group_cn, ...]} for users who are members
    of any privileged group.

    Checks both the 'member' attribute on groups and the 'memberOf' on users.
    """
    priv_group_dns  = {g.dn.lower() for g in priv_groups}
    priv_group_by_dn = {g.dn.lower(): g.cn for g in priv_groups}

    result: dict[str, list[str]] = {}

    for user in users:
        member_of = user.attributes.get("memberOf", [])
        matched_groups = []
        for group_dn in member_of:
            if group_dn.lower() in priv_group_dns:
                matched_groups.append(priv_group_by_dn[group_dn.lower()])
        if matched_groups:
            result[user.dn] = matched_groups

    # Also scan group 'member' attributes (covers cases where memberOf is not replicated)
    for group in priv_groups:
        for member_dn in group.members:
            member_lower = member_dn.lower()
            # Check if member DN corresponds to a user
            for user in users:
                if user.dn.lower() == member_lower:
                    entry = result.setdefault(user.dn, [])
                    if group.cn not in entry:
                        entry.append(group.cn)

    return result


def _users_with_privileged_dn(users: list[UserEntry]) -> dict[str, list[str]]:
    """Return users whose DN matches a privileged pattern."""
    result: dict[str, list[str]] = {}
    for user in users:
        dn_lower = user.dn.lower()
        matched = [p for p in PRIVILEGED_DN_PATTERNS if p in dn_lower]
        if matched:
            result[user.dn] = matched
    return result


def _check_ad_account_flags(
    users: list[UserEntry],
    privileged_dns: set[str],
) -> list[Finding]:
    """
    For AD environments: check userAccountControl flags on privileged accounts.
    Flags checked: PASSWORD_NOT_REQD.
    """
    findings: list[Finding] = []
    no_pwd_required = []

    for user in users:
        if user.dn not in privileged_dns:
            continue
        uac = _uac_value(user)
        if uac is None:
            continue
        if uac & UAC_PASSWORD_NOT_REQD:
            no_pwd_required.append(user)

    if no_pwd_required:
        findings.append(Finding(
            id=CheckID.PRIVILEGED_ACCOUNTS,
            title="Privileged accounts with 'Password not required' flag",
            severity=Severity.HIGH,
            description=(
                f"{len(no_pwd_required)} privileged account(s) have the "
                "UAC_PASSWORD_NOT_REQD flag set, meaning they may authenticate "
                "with an empty password."
            ),
            evidence={"accounts": [{"dn": u.dn, "cn": u.cn} for u in no_pwd_required]},
            recommendation=(
                "Clear the UAC_PASSWORD_NOT_REQD flag on all privileged accounts "
                "and ensure a strong password is set."
            ),
        ))

    return findings


def _privileged_no_password_expiry(
    users: list[UserEntry],
    privileged_dns: set[str],
) -> list[UserEntry]:
    """Return privileged, enabled users with non-expiring passwords."""
    result = []
    for user in users:
        if user.dn not in privileged_dns:
            continue
        uac = _uac_value(user)
        if uac is None:
            continue
        disabled = bool(uac & UAC_ACCOUNT_DISABLED)
        no_expiry = bool(uac & UAC_DONT_EXPIRE_PASSWD)
        if no_expiry and not disabled:
            result.append(user)
    return result


def _uac_value(user: UserEntry) -> int | None:
    """Extract integer userAccountControl value from a UserEntry."""
    raw = user.attributes.get("userAccountControl", [])
    if not raw:
        return None
    try:
        return int(raw[0] if isinstance(raw, list) else raw)
    except (ValueError, TypeError):
        return None
