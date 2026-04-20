"""
Account security checks.

ACC-001 — Password age: accounts with very old or never-changed passwords
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from checks.anonymous_bind import Finding
from config.settings import CheckID, Severity
from core.enumerator import DirectoryInfo, UserEntry

logger = logging.getLogger(__name__)

AD_EPOCH_DELTA_SECONDS = 11_644_473_600
UAC_DISABLED           = 0x00000002

PASSWORD_AGE_HIGH_DAYS   = 365   # > 1 year → HIGH
PASSWORD_AGE_MEDIUM_DAYS = 180   # > 6 months → MEDIUM


def run(dir_info: DirectoryInfo) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_acc001(dir_info))
    return findings


def _acc001(dir_info: DirectoryInfo) -> list[Finding]:
    """
    Flag enabled accounts whose password has not been changed in a long time.
    Distinguishes never-changed (pwdLastSet=0) from very-old passwords.
    """
    now = datetime.now(tz=timezone.utc)
    never_changed: list[UserEntry] = []
    old_high: list[tuple[UserEntry, int]] = []    # > PASSWORD_AGE_HIGH_DAYS
    old_medium: list[tuple[UserEntry, int]] = []  # > PASSWORD_AGE_MEDIUM_DAYS

    for u in dir_info.users:
        if _is_disabled(u):
            continue
        raw = u.attributes.get("pwdLastSet", [])
        if not raw:
            continue
        val = raw[0] if isinstance(raw, list) else raw
        try:
            ts = int(val)
        except (ValueError, TypeError):
            continue

        if ts == 0:
            never_changed.append(u)
            continue

        unix_ts = (ts / 10_000_000) - AD_EPOCH_DELTA_SECONDS
        if unix_ts <= 0:
            never_changed.append(u)
            continue

        age_days = (now - datetime.fromtimestamp(unix_ts, tz=timezone.utc)).days
        if age_days > PASSWORD_AGE_HIGH_DAYS:
            old_high.append((u, age_days))
        elif age_days > PASSWORD_AGE_MEDIUM_DAYS:
            old_medium.append((u, age_days))

    result = []

    if never_changed:
        result.append(Finding(
            id=CheckID.PASSWORD_AGE,
            title="Enabled accounts with password never changed",
            severity=Severity.HIGH,
            description=(
                f"{len(never_changed)} enabled account(s) have never had their password "
                "changed since account creation (pwdLastSet = 0). These may be using "
                "a default or provisioning password."
            ),
            evidence={
                "count": len(never_changed),
                "accounts": [{"dn": u.dn, "sAMAccountName": _first(u, "sAMAccountName")}
                              for u in never_changed[:20]],
                "truncated": len(never_changed) > 20,
            },
            recommendation=(
                "Force a password reset on all accounts where pwdLastSet = 0. "
                "Enable 'User must change password at next logon' and verify "
                "these are legitimate active accounts."
            ),
        ))

    if old_high:
        old_high.sort(key=lambda x: x[1], reverse=True)
        result.append(Finding(
            id=CheckID.PASSWORD_AGE,
            title=f"Accounts with passwords older than {PASSWORD_AGE_HIGH_DAYS} days",
            severity=Severity.HIGH,
            description=(
                f"{len(old_high)} enabled account(s) have not changed their password "
                f"in over {PASSWORD_AGE_HIGH_DAYS} days."
            ),
            evidence={
                "count": len(old_high),
                "threshold_days": PASSWORD_AGE_HIGH_DAYS,
                "accounts": [{"dn": u.dn, "sAMAccountName": _first(u, "sAMAccountName"),
                               "password_age_days": days}
                              for u, days in old_high[:20]],
                "truncated": len(old_high) > 20,
            },
            recommendation=(
                f"Enforce a maximum password age of {PASSWORD_AGE_HIGH_DAYS} days "
                "in the Default Domain Policy. Force immediate password reset "
                "on the accounts listed."
            ),
        ))

    if old_medium:
        old_medium.sort(key=lambda x: x[1], reverse=True)
        result.append(Finding(
            id=CheckID.PASSWORD_AGE,
            title=f"Accounts with passwords older than {PASSWORD_AGE_MEDIUM_DAYS} days",
            severity=Severity.MEDIUM,
            description=(
                f"{len(old_medium)} enabled account(s) have not changed their password "
                f"in over {PASSWORD_AGE_MEDIUM_DAYS} days."
            ),
            evidence={
                "count": len(old_medium),
                "threshold_days": PASSWORD_AGE_MEDIUM_DAYS,
                "accounts": [{"dn": u.dn, "sAMAccountName": _first(u, "sAMAccountName"),
                               "password_age_days": days}
                              for u, days in old_medium[:20]],
                "truncated": len(old_medium) > 20,
            },
            recommendation=(
                f"Enforce a maximum password age policy. "
                "Consider notifying users with passwords older than "
                f"{PASSWORD_AGE_MEDIUM_DAYS} days to change them."
            ),
        ))

    return result


def _is_disabled(u: UserEntry) -> bool:
    raw = u.attributes.get("userAccountControl", [])
    if not raw:
        return False
    try:
        return bool(int(raw[0] if isinstance(raw, list) else raw) & UAC_DISABLED)
    except (ValueError, TypeError):
        return False


def _first(u: UserEntry, attr: str) -> str:
    val = u.attributes.get(attr, [])
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val) if val else ""
