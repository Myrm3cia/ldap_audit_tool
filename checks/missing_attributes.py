"""
LDAP-004 — Missing security attributes check.

Identifies user accounts that are missing attributes considered important
for security posture:
- No password policy assigned (pwdPolicySubentry / msDS-PSOApplied)
- Password never set (pwdLastSet = 0 in AD)
- Account with no email address (optional, INFO only)
- Stale accounts: last logon very old or never logged in (AD)

All operations are read-only.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from checks.anonymous_bind import Finding
from config.settings import CheckID, Severity
from core.enumerator import DirectoryInfo, UserEntry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Thresholds
# ---------------------------------------------------------------------------

STALE_LOGON_DAYS = 180   # accounts not logged in for this many days are flagged

# AD epoch starts 1601-01-01; Python datetime epoch is 1970-01-01
AD_EPOCH_DELTA_SECONDS = 11_644_473_600


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(dir_info: DirectoryInfo) -> list[Finding]:
    """
    Scan collected user entries for missing or anomalous security attributes.

    Returns a list of Finding objects.
    """
    findings: list[Finding] = []

    no_pwd_policy      = []
    pwd_never_set      = []
    stale_accounts     = []
    never_logged_in    = []

    for user in dir_info.users:
        uac = _uac(user)
        # Skip disabled accounts — they may legitimately lack some attributes
        if uac is not None and (uac & 0x0002):
            continue

        if _missing_password_policy(user):
            no_pwd_policy.append(user)

        if _password_never_set(user):
            pwd_never_set.append(user)

        stale = _stale_logon(user)
        if stale == "never":
            never_logged_in.append(user)
        elif stale == "stale":
            stale_accounts.append(user)

    # --- Emit findings ---
    if no_pwd_policy:
        findings.append(Finding(
            id=CheckID.MISSING_ATTRIBUTES,
            title="Accounts without an explicit password policy",
            severity=Severity.LOW,
            description=(
                f"{len(no_pwd_policy)} enabled account(s) have no explicit password "
                "policy assigned (no pwdPolicySubentry or msDS-PSOApplied). "
                "They fall back to the default domain policy, which may be weaker."
            ),
            evidence={
                "count": len(no_pwd_policy),
                "accounts": [{"dn": u.dn, "cn": u.cn} for u in no_pwd_policy[:20]],
                "truncated": len(no_pwd_policy) > 20,
            },
            recommendation=(
                "Assign an explicit Fine-Grained Password Policy (PSO) to privileged "
                "accounts, or verify the default domain policy meets your requirements."
            ),
        ))

    if pwd_never_set:
        findings.append(Finding(
            id=CheckID.MISSING_ATTRIBUTES,
            title="Accounts where password was never set",
            severity=Severity.HIGH,
            description=(
                f"{len(pwd_never_set)} enabled account(s) have never had a password set "
                "(pwdLastSet = 0). These accounts may be accessible with an empty or "
                "default password."
            ),
            evidence={
                "count": len(pwd_never_set),
                "accounts": [{"dn": u.dn, "cn": u.cn} for u in pwd_never_set[:20]],
                "truncated": len(pwd_never_set) > 20,
            },
            recommendation=(
                "Immediately set a strong password for these accounts or disable them "
                "if they are not needed."
            ),
        ))

    if never_logged_in:
        findings.append(Finding(
            id=CheckID.MISSING_ATTRIBUTES,
            title="Enabled accounts that have never logged in",
            severity=Severity.MEDIUM,
            description=(
                f"{len(never_logged_in)} enabled account(s) show no recorded logon "
                "activity. These may be orphaned or pre-provisioned accounts that "
                "represent an unnecessary attack surface."
            ),
            evidence={
                "count": len(never_logged_in),
                "accounts": [{"dn": u.dn, "cn": u.cn} for u in never_logged_in[:20]],
                "truncated": len(never_logged_in) > 20,
            },
            recommendation=(
                "Review and disable accounts that have never been used. "
                "Remove them after confirming they are not needed."
            ),
        ))

    if stale_accounts:
        findings.append(Finding(
            id=CheckID.MISSING_ATTRIBUTES,
            title=f"Stale accounts (no logon in {STALE_LOGON_DAYS}+ days)",
            severity=Severity.MEDIUM,
            description=(
                f"{len(stale_accounts)} enabled account(s) have not logged in for "
                f"more than {STALE_LOGON_DAYS} days. Stale accounts represent an "
                "unnecessary attack surface."
            ),
            evidence={
                "count": len(stale_accounts),
                "stale_threshold_days": STALE_LOGON_DAYS,
                "accounts": [
                    {"dn": u.dn, "cn": u.cn, "last_logon": _last_logon_str(u)}
                    for u in stale_accounts[:20]
                ],
                "truncated": len(stale_accounts) > 20,
            },
            recommendation=(
                "Disable and review accounts inactive for more than "
                f"{STALE_LOGON_DAYS} days. Implement an automated stale account "
                "management process."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Per-user checks
# ---------------------------------------------------------------------------

def _missing_password_policy(user: UserEntry) -> bool:
    """True if the user has no explicit password policy attribute."""
    has_pwd_policy = any(
        user.attributes.get(attr)
        for attr in ("pwdPolicySubentry", "msDS-PSOApplied")
    )
    return not has_pwd_policy


def _password_never_set(user: UserEntry) -> bool:
    """
    True if pwdLastSet == 0 (AD: password was never set).
    Returns False if the attribute is absent (non-AD or not readable).
    """
    raw = user.attributes.get("pwdLastSet") or user.attributes.get("passwordExpirationTime")
    if not raw:
        return False
    val = raw[0] if isinstance(raw, list) else raw
    try:
        return int(val) == 0
    except (ValueError, TypeError):
        return False


def _stale_logon(user: UserEntry) -> str | None:
    """
    Returns 'never' if the account has never logged in,
    'stale' if last logon was more than STALE_LOGON_DAYS ago,
    None otherwise.
    Checks both 'lastLogonTimestamp' and 'lastLogon' (AD).
    """
    for attr in ("lastLogonTimestamp", "lastLogon"):
        raw = user.attributes.get(attr)
        if not raw:
            continue
        val = raw[0] if isinstance(raw, list) else raw
        try:
            ts = int(val)
        except (ValueError, TypeError):
            continue
        if ts == 0:
            return "never"
        # Convert AD timestamp to Unix timestamp
        unix_ts = (ts / 10_000_000) - AD_EPOCH_DELTA_SECONDS
        if unix_ts <= 0:
            return "never"
        last_logon = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
        delta = datetime.now(tz=timezone.utc) - last_logon
        if delta.days > STALE_LOGON_DAYS:
            return "stale"
        return None   # recent logon
    return None   # attribute not present — cannot determine


def _last_logon_str(user: UserEntry) -> str:
    """Return a human-readable last logon date for evidence output."""
    for attr in ("lastLogonTimestamp", "lastLogon"):
        raw = user.attributes.get(attr)
        if not raw:
            continue
        val = raw[0] if isinstance(raw, list) else raw
        try:
            ts = int(val)
            if ts == 0:
                return "never"
            unix_ts = (ts / 10_000_000) - AD_EPOCH_DELTA_SECONDS
            dt = datetime.fromtimestamp(unix_ts, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d")
        except (ValueError, TypeError, OSError):
            continue
    return "unknown"


def _uac(user: UserEntry) -> int | None:
    raw = user.attributes.get("userAccountControl", [])
    if not raw:
        return None
    try:
        return int(raw[0] if isinstance(raw, list) else raw)
    except (ValueError, TypeError):
        return None
