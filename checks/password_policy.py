"""
LDAP-002 — Password policy check.

Reads and analyses password policy objects from the directory.
Supports:
- Active Directory (Default Domain Policy via msDS-* attributes + Fine-Grained PSOs)
- OpenLDAP / 389-DS (pwdPolicy objectClass, RFC 3112)

All operations are read-only.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from ldap3 import SUBTREE, BASE
from ldap3.core.exceptions import LDAPException

from checks.anonymous_bind import Finding
from config.settings import CheckID, Severity
from core.connector import LDAPConnector

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Thresholds (tunable)
# ---------------------------------------------------------------------------

MIN_PASSWORD_LENGTH   = 8
MAX_PASSWORD_AGE_DAYS = 365   # policy considered "no expiry" above this
MIN_LOCKOUT_THRESHOLD = 10    # failed attempts before lockout; 0 = no lockout


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(connector: LDAPConnector, base_dn: str) -> list[Finding]:
    """
    Analyse password policies found in the directory.

    Returns a list of Finding objects, one per policy issue detected.
    """
    findings: list[Finding] = []

    # --- Active Directory ---
    ad_findings = _check_ad_policy(connector, base_dn)
    findings.extend(ad_findings)

    # --- OpenLDAP / RFC 3112 ---
    oid_findings = _check_pwdpolicy_objects(connector, base_dn)
    findings.extend(oid_findings)

    if not findings:
        logger.debug("LDAP-002: no password policy issues found (or policy not readable)")

    return findings


# ---------------------------------------------------------------------------
# Active Directory
# ---------------------------------------------------------------------------

def _check_ad_policy(connector: LDAPConnector, base_dn: str) -> list[Finding]:
    """Read the AD Default Domain Policy and any Fine-Grained PSOs."""
    findings: list[Finding] = []

    # Default Domain Policy lives on the domain object itself
    domain_entries = connector.search(
        search_base=base_dn,
        search_filter="(objectClass=domainDNS)",
        attributes=['*'],
        search_scope=BASE,
    )

    if domain_entries:
        entry = domain_entries[0]
        attrs = entry.entry_attributes_as_dict
        issues = _analyse_ad_domain_policy(attrs)
        for issue in issues:
            findings.append(Finding(
                id=CheckID.PASSWORD_POLICY,
                title=f"Weak AD password policy: {issue['title']}",
                severity=issue["severity"],
                description=issue["description"],
                evidence={"source": "Default Domain Policy", "dn": entry.entry_dn, **issue["evidence"]},
                recommendation=issue["recommendation"],
            ))

    # Fine-Grained Password Policies (PSOs) — AD 2008+
    pso_entries = connector.search(
        search_base=f"CN=Password Settings Container,CN=System,{base_dn}",
        search_filter="(objectClass=msDS-PasswordSettings)",
        attributes=['*'],
        search_scope=SUBTREE,
    )

    for pso in pso_entries:
        attrs = pso.entry_attributes_as_dict
        issues = _analyse_pso(attrs, pso.entry_dn)
        for issue in issues:
            findings.append(Finding(
                id=CheckID.PASSWORD_POLICY,
                title=f"Weak PSO policy: {issue['title']}",
                severity=issue["severity"],
                description=issue["description"],
                evidence={"source": "Fine-Grained PSO", "dn": pso.entry_dn, **issue["evidence"]},
                recommendation=issue["recommendation"],
            ))

    return findings


def _analyse_ad_domain_policy(attrs: dict) -> list[dict]:
    """Check relevant AD password policy attributes on the domain object."""
    issues = []

    # minPwdLength
    min_len = _int_attr(attrs, "minPwdLength")
    if min_len is not None and min_len < MIN_PASSWORD_LENGTH:
        issues.append({
            "title": "Minimum password length too short",
            "severity": Severity.MEDIUM,
            "description": (
                f"The domain minimum password length is {min_len} characters "
                f"(recommended minimum: {MIN_PASSWORD_LENGTH})."
            ),
            "evidence": {"minPwdLength": min_len},
            "recommendation": f"Set minPwdLength to at least {MIN_PASSWORD_LENGTH} in the Default Domain Policy.",
        })

    # maxPwdAge (stored as negative 100-nanosecond intervals)
    max_age_raw = _int_attr(attrs, "maxPwdAge")
    if max_age_raw is not None:
        max_age_days = _ad_interval_to_days(max_age_raw)
        if max_age_days == 0:
            issues.append({
                "title": "Passwords never expire",
                "severity": Severity.MEDIUM,
                "description": "The domain policy does not enforce password expiration (maxPwdAge = 0).",
                "evidence": {"maxPwdAge_days": 0},
                "recommendation": "Set a password expiration policy (e.g. 90 days) in the Default Domain Policy.",
            })
        elif max_age_days > MAX_PASSWORD_AGE_DAYS:
            issues.append({
                "title": "Password expiration too long",
                "severity": Severity.LOW,
                "description": (
                    f"Passwords expire after {max_age_days} days "
                    f"(recommended maximum: {MAX_PASSWORD_AGE_DAYS} days)."
                ),
                "evidence": {"maxPwdAge_days": max_age_days},
                "recommendation": f"Reduce maxPwdAge to {MAX_PASSWORD_AGE_DAYS} days or less.",
            })

    # lockoutThreshold
    lockout = _int_attr(attrs, "lockoutThreshold")
    if lockout is not None and lockout == 0:
        issues.append({
            "title": "Account lockout disabled",
            "severity": Severity.HIGH,
            "description": (
                "The lockout threshold is 0, meaning accounts are never locked "
                "after repeated failed authentication attempts. This facilitates "
                "online password guessing attacks."
            ),
            "evidence": {"lockoutThreshold": 0},
            "recommendation": "Set lockoutThreshold to 5–10 failed attempts in the Default Domain Policy.",
        })

    # pwdProperties: bit 0 = complexity required
    pwd_props = _int_attr(attrs, "pwdProperties")
    if pwd_props is not None and not (pwd_props & 1):
        issues.append({
            "title": "Password complexity not required",
            "severity": Severity.MEDIUM,
            "description": (
                "The 'Password must meet complexity requirements' flag is disabled "
                "(pwdProperties bit 0 = 0)."
            ),
            "evidence": {"pwdProperties": pwd_props},
            "recommendation": "Enable password complexity requirements in the Default Domain Policy.",
        })

    return issues


def _analyse_pso(attrs: dict, dn: str) -> list[dict]:
    """Check a Fine-Grained PSO for weak settings."""
    issues = []

    min_len = _int_attr(attrs, "msDS-MinimumPasswordLength")
    if min_len is not None and min_len < MIN_PASSWORD_LENGTH:
        issues.append({
            "title": "Minimum password length too short",
            "severity": Severity.MEDIUM,
            "description": f"PSO '{dn}' sets minimum password length to {min_len}.",
            "evidence": {"msDS-MinimumPasswordLength": min_len},
            "recommendation": f"Increase msDS-MinimumPasswordLength to at least {MIN_PASSWORD_LENGTH}.",
        })

    lockout = _int_attr(attrs, "msDS-LockoutThreshold")
    if lockout is not None and lockout == 0:
        issues.append({
            "title": "Account lockout disabled in PSO",
            "severity": Severity.HIGH,
            "description": f"PSO '{dn}' sets lockout threshold to 0 (no lockout).",
            "evidence": {"msDS-LockoutThreshold": 0},
            "recommendation": "Set msDS-LockoutThreshold to 5–10 in this PSO.",
        })

    complexity = _bool_attr(attrs, "msDS-PasswordComplexityEnabled")
    if complexity is False:
        issues.append({
            "title": "Password complexity disabled in PSO",
            "severity": Severity.MEDIUM,
            "description": f"PSO '{dn}' disables password complexity requirements.",
            "evidence": {"msDS-PasswordComplexityEnabled": False},
            "recommendation": "Enable msDS-PasswordComplexityEnabled in this PSO.",
        })

    return issues


# ---------------------------------------------------------------------------
# OpenLDAP / RFC 3112 pwdPolicy
# ---------------------------------------------------------------------------

def _check_pwdpolicy_objects(connector: LDAPConnector, base_dn: str) -> list[Finding]:
    """Search for RFC 3112 pwdPolicy objects and analyse their settings."""
    findings: list[Finding] = []

    entries = connector.search(
        search_base=base_dn,
        search_filter="(objectClass=pwdPolicy)",
        attributes=['*'],
        search_scope=SUBTREE,
    )

    for entry in entries:
        attrs = entry.entry_attributes_as_dict

        # pwdMinLength
        min_len = _int_attr(attrs, "pwdMinLength")
        if min_len is not None and min_len < MIN_PASSWORD_LENGTH:
            findings.append(Finding(
                id=CheckID.PASSWORD_POLICY,
                title="Weak pwdPolicy: minimum length too short",
                severity=Severity.MEDIUM,
                description=f"pwdPolicy '{entry.entry_dn}' sets pwdMinLength to {min_len}.",
                evidence={"dn": entry.entry_dn, "pwdMinLength": min_len},
                recommendation=f"Set pwdMinLength to at least {MIN_PASSWORD_LENGTH}.",
            ))

        # pwdLockout / pwdMaxFailure
        lockout_enabled = _bool_attr(attrs, "pwdLockout")
        max_failure     = _int_attr(attrs, "pwdMaxFailure")

        if lockout_enabled is False:
            findings.append(Finding(
                id=CheckID.PASSWORD_POLICY,
                title="Weak pwdPolicy: account lockout disabled",
                severity=Severity.HIGH,
                description=f"pwdPolicy '{entry.entry_dn}' has pwdLockout set to FALSE.",
                evidence={"dn": entry.entry_dn, "pwdLockout": False},
                recommendation="Set pwdLockout to TRUE and pwdMaxFailure to 5–10.",
            ))
        elif max_failure is not None and max_failure >= MIN_LOCKOUT_THRESHOLD:
            findings.append(Finding(
                id=CheckID.PASSWORD_POLICY,
                title="Weak pwdPolicy: lockout threshold too high",
                severity=Severity.LOW,
                description=(
                    f"pwdPolicy '{entry.entry_dn}' allows {max_failure} failed attempts "
                    f"before lockout (recommended: less than {MIN_LOCKOUT_THRESHOLD})."
                ),
                evidence={"dn": entry.entry_dn, "pwdMaxFailure": max_failure},
                recommendation=f"Reduce pwdMaxFailure below {MIN_LOCKOUT_THRESHOLD}.",
            ))

        # pwdMaxAge (in seconds, 0 = no expiry)
        max_age_secs = _int_attr(attrs, "pwdMaxAge")
        if max_age_secs is not None:
            max_age_days = max_age_secs // 86400
            if max_age_days == 0:
                findings.append(Finding(
                    id=CheckID.PASSWORD_POLICY,
                    title="Weak pwdPolicy: passwords never expire",
                    severity=Severity.MEDIUM,
                    description=f"pwdPolicy '{entry.entry_dn}' sets pwdMaxAge to 0 (no expiration).",
                    evidence={"dn": entry.entry_dn, "pwdMaxAge": 0},
                    recommendation="Set pwdMaxAge to enforce password rotation.",
                ))

    return findings


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _int_attr(attrs: dict, key: str) -> int | None:
    val = attrs.get(key)
    if not val:
        return None
    v = val[0] if isinstance(val, list) else val
    try:
        return int(v)
    except (ValueError, TypeError):
        return None


def _bool_attr(attrs: dict, key: str) -> bool | None:
    val = attrs.get(key)
    if not val:
        return None
    v = str(val[0] if isinstance(val, list) else val).upper()
    if v in ("TRUE", "1", "YES"):
        return True
    if v in ("FALSE", "0", "NO"):
        return False
    return None


def _ad_interval_to_days(interval: int) -> int:
    """
    Convert an AD time interval (negative 100-nanosecond units) to days.
    A value of 0 means 'never'.
    """
    if interval == 0:
        return 0
    # interval is stored as a large negative integer
    positive = abs(interval)
    seconds  = positive / 10_000_000
    return int(seconds / 86400)
