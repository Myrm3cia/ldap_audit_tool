"""
Kerberos security checks.

KERB-001 — AS-REP Roasting: accounts with Kerberos pre-authentication disabled
KERB-002 — Kerberoasting: user accounts with SPNs (service tickets crackable offline)
KERB-003 — Weak Kerberos encryption (DES / RC4)
KERB-004 — Delegation misconfigurations (unconstrained / constrained / protocol transition)
"""

from __future__ import annotations

import logging

from checks.anonymous_bind import Finding
from config.settings import CheckID, Severity
from core.enumerator import DirectoryInfo, UserEntry

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# UAC flags
# ---------------------------------------------------------------------------
UAC_DISABLED               = 0x00000002
UAC_DONT_REQ_PREAUTH       = 0x00400000
UAC_TRUSTED_FOR_DELEGATION = 0x00080000   # unconstrained
UAC_TRUSTED_TO_AUTH        = 0x01000000   # protocol transition (S4U2Self)
UAC_NOT_DELEGATED          = 0x00100000

# ---------------------------------------------------------------------------
# msDS-SupportedEncryptionTypes bit flags
# ---------------------------------------------------------------------------
ENC_DES_CBC_CRC = 0x01
ENC_DES_CBC_MD5 = 0x02
ENC_RC4_HMAC    = 0x04
ENC_AES128      = 0x08
ENC_AES256      = 0x10


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run(dir_info: DirectoryInfo) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_kerb001(dir_info))
    findings.extend(_kerb002(dir_info))
    findings.extend(_kerb003(dir_info))
    findings.extend(_kerb004(dir_info))
    return findings


# ---------------------------------------------------------------------------
# KERB-001 — AS-REP Roasting
# ---------------------------------------------------------------------------

def _kerb001(dir_info: DirectoryInfo) -> list[Finding]:
    """
    Find enabled user accounts with DONT_REQ_PREAUTH set.
    These accounts can have AS-REP tickets requested by anyone without
    supplying a password, and the response is encrypted with the account's
    password hash (crackable offline).
    """
    at_risk = [
        u for u in dir_info.users
        if not _is_disabled(u)
        and _uac(u) is not None
        and bool(_uac(u) & UAC_DONT_REQ_PREAUTH)
    ]

    if not at_risk:
        return []

    return [Finding(
        id=CheckID.ASREP_ROASTING,
        title="AS-REP Roastable accounts detected",
        severity=Severity.HIGH,
        description=(
            f"{len(at_risk)} enabled account(s) have Kerberos pre-authentication "
            "disabled (DONT_REQ_PREAUTH). An attacker can request an AS-REP ticket "
            "for these accounts without credentials and attempt offline password cracking."
        ),
        evidence={
            "count": len(at_risk),
            "accounts": [{"dn": u.dn, "cn": u.cn, "sAMAccountName": _first(u, "sAMAccountName")}
                         for u in at_risk],
        },
        recommendation=(
            "Enable Kerberos pre-authentication on all accounts "
            "(remove DONT_REQ_PREAUTH from userAccountControl). "
            "If legacy systems require it, enforce strong passwords and monitor AS-REP requests."
        ),
    )]


# ---------------------------------------------------------------------------
# KERB-002 — Kerberoasting
# ---------------------------------------------------------------------------

def _kerb002(dir_info: DirectoryInfo) -> list[Finding]:
    """
    Find enabled user accounts (not computers, not krbtgt) with SPNs.
    Service tickets for these accounts are encrypted with the account's
    password hash and can be cracked offline (Kerberoasting).
    """
    at_risk = []
    for u in dir_info.users:
        if _is_disabled(u):
            continue
        sam = _first(u, "sAMAccountName").lower()
        if sam in ("krbtgt",):
            continue
        spns = u.attributes.get("servicePrincipalName", [])
        if spns:
            at_risk.append((u, spns if isinstance(spns, list) else [spns]))

    if not at_risk:
        return []

    # Elevate severity if any of these accounts are also in privileged groups
    priv_keywords = {"domain admins", "enterprise admins", "schema admins", "administrators"}
    has_privileged = any(
        any(kw in str(g).lower() for kw in priv_keywords for g in u.attributes.get("memberOf", []))
        for u, _ in at_risk
    )

    return [Finding(
        id=CheckID.KERBEROASTING,
        title="Kerberoastable service accounts detected",
        severity=Severity.HIGH if has_privileged else Severity.MEDIUM,
        description=(
            f"{len(at_risk)} enabled user account(s) have a servicePrincipalName (SPN) set. "
            "Any authenticated domain user can request a service ticket for these accounts "
            "and attempt offline password cracking."
            + (" One or more of these accounts have privileged group membership." if has_privileged else "")
        ),
        evidence={
            "count": len(at_risk),
            "accounts": [
                {
                    "dn": u.dn,
                    "sAMAccountName": _first(u, "sAMAccountName"),
                    "spns": spns[:5],
                    "memberOf": [str(g) for g in u.attributes.get("memberOf", [])][:5],
                }
                for u, spns in at_risk
            ],
        },
        recommendation=(
            "Use managed service accounts (gMSA) where possible — they have "
            "auto-rotating 120-character passwords. For legacy SPNs, ensure accounts "
            "have strong passwords (>25 chars) and are regularly rotated. "
            "Audit SPN assignments and remove unnecessary ones."
        ),
    )]


# ---------------------------------------------------------------------------
# KERB-003 — Weak Kerberos encryption
# ---------------------------------------------------------------------------

def _kerb003(dir_info: DirectoryInfo) -> list[Finding]:
    """
    Identify accounts explicitly configured to use DES or RC4 encryption.
    If msDS-SupportedEncryptionTypes is 0 or absent, AD defaults to RC4.
    """
    findings: list[Finding] = []

    des_accounts  = []
    rc4_only      = []
    default_rc4   = []   # value=0 → AD negotiates, often RC4

    for u in dir_info.users:
        if _is_disabled(u):
            continue
        enc_raw = u.attributes.get("msDS-SupportedEncryptionTypes", [])
        if not enc_raw:
            default_rc4.append(u)
            continue
        enc = int(enc_raw[0] if isinstance(enc_raw, list) else enc_raw)
        if enc == 0:
            default_rc4.append(u)
            continue
        has_des = bool(enc & (ENC_DES_CBC_CRC | ENC_DES_CBC_MD5))
        has_aes = bool(enc & (ENC_AES128 | ENC_AES256))
        has_rc4 = bool(enc & ENC_RC4_HMAC)

        if has_des:
            des_accounts.append((u, enc))
        elif has_rc4 and not has_aes:
            rc4_only.append((u, enc))

    if des_accounts:
        findings.append(Finding(
            id=CheckID.WEAK_KERBEROS_CRYPTO,
            title="Accounts with DES Kerberos encryption enabled",
            severity=Severity.CRITICAL,
            description=(
                f"{len(des_accounts)} account(s) explicitly support DES Kerberos encryption. "
                "DES is cryptographically broken and trivially crackable."
            ),
            evidence={
                "count": len(des_accounts),
                "accounts": [{"dn": u.dn, "sAMAccountName": _first(u, "sAMAccountName"),
                               "encTypes": hex(enc)} for u, enc in des_accounts],
            },
            recommendation=(
                "Remove DES encryption types from msDS-SupportedEncryptionTypes. "
                "Set the value to 0x18 (AES128 + AES256 only) and disable DES in the "
                "Default Domain Policy (Kerberos > Encryption types)."
            ),
        ))

    if rc4_only:
        findings.append(Finding(
            id=CheckID.WEAK_KERBEROS_CRYPTO,
            title="Accounts restricted to RC4 Kerberos encryption",
            severity=Severity.HIGH,
            description=(
                f"{len(rc4_only)} account(s) are configured to use RC4-HMAC only "
                "(no AES support). RC4 is susceptible to pass-the-hash and "
                "faster offline cracking."
            ),
            evidence={
                "count": len(rc4_only),
                "accounts": [{"dn": u.dn, "sAMAccountName": _first(u, "sAMAccountName"),
                               "encTypes": hex(enc)} for u, enc in rc4_only],
            },
            recommendation=(
                "Enable AES128 and AES256 encryption types "
                "(msDS-SupportedEncryptionTypes = 0x18). "
                "Ensure clients and services support AES before disabling RC4."
            ),
        ))

    if default_rc4:
        findings.append(Finding(
            id=CheckID.WEAK_KERBEROS_CRYPTO,
            title="Accounts with no explicit encryption type (RC4 default)",
            severity=Severity.MEDIUM,
            description=(
                f"{len(default_rc4)} enabled account(s) have no "
                "msDS-SupportedEncryptionTypes set (value=0 or absent). "
                "Active Directory defaults to offering RC4 for these accounts."
            ),
            evidence={
                "count": len(default_rc4),
                "sample": [{"dn": u.dn, "sAMAccountName": _first(u, "sAMAccountName")}
                            for u in default_rc4[:20]],
                "truncated": len(default_rc4) > 20,
            },
            recommendation=(
                "Explicitly set msDS-SupportedEncryptionTypes to 0x18 (AES128+AES256) "
                "on all accounts, or enable it domain-wide via GPO: "
                "Computer Configuration > Kerberos > Encryption types."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# KERB-004 — Delegation misconfigurations
# ---------------------------------------------------------------------------

def _kerb004(dir_info: DirectoryInfo) -> list[Finding]:
    """
    Detect dangerous Kerberos delegation settings on user accounts.
    Computer accounts with delegation are checked separately in COMP-002.
    """
    findings: list[Finding] = []

    unconstrained     = []   # TRUSTED_FOR_DELEGATION (any service, any user)
    protocol_trans    = []   # TRUSTED_TO_AUTH_FOR_DELEGATION (S4U2Self)
    constrained       = []   # msDS-AllowedToDelegateTo set

    for u in dir_info.users:
        if _is_disabled(u):
            continue
        uac = _uac(u)
        spns = u.attributes.get("msDS-AllowedToDelegateTo", [])

        if uac is not None:
            if uac & UAC_TRUSTED_FOR_DELEGATION:
                unconstrained.append(u)
            elif uac & UAC_TRUSTED_TO_AUTH:
                protocol_trans.append(u)

        if spns:
            constrained.append((u, spns if isinstance(spns, list) else [spns]))

    if unconstrained:
        findings.append(Finding(
            id=CheckID.DELEGATION,
            title="User accounts with unconstrained Kerberos delegation",
            severity=Severity.CRITICAL,
            description=(
                f"{len(unconstrained)} user account(s) have unconstrained delegation enabled "
                "(TRUSTED_FOR_DELEGATION). Any service running under these accounts can "
                "impersonate any user to any service in the domain — including Domain Admins."
            ),
            evidence={
                "count": len(unconstrained),
                "accounts": [{"dn": u.dn, "sAMAccountName": _first(u, "sAMAccountName")}
                              for u in unconstrained],
            },
            recommendation=(
                "Remove TRUSTED_FOR_DELEGATION from user accounts. "
                "Use constrained delegation or resource-based constrained delegation (RBCD) instead. "
                "If legacy systems require it, enforce Kerberos armoring and monitor for TGT theft."
            ),
        ))

    if protocol_trans:
        findings.append(Finding(
            id=CheckID.DELEGATION,
            title="User accounts with protocol transition delegation (S4U2Self)",
            severity=Severity.HIGH,
            description=(
                f"{len(protocol_trans)} user account(s) have protocol transition "
                "(TRUSTED_TO_AUTH_FOR_DELEGATION) enabled. These accounts can obtain "
                "service tickets on behalf of any user without requiring their credentials."
            ),
            evidence={
                "count": len(protocol_trans),
                "accounts": [{"dn": u.dn, "sAMAccountName": _first(u, "sAMAccountName"),
                               "delegateTo": u.attributes.get("msDS-AllowedToDelegateTo", [])}
                              for u in protocol_trans],
            },
            recommendation=(
                "Review the need for protocol transition on these accounts. "
                "Prefer resource-based constrained delegation where possible. "
                "At minimum, restrict via msDS-AllowedToDelegateTo to specific services."
            ),
        ))

    if constrained:
        findings.append(Finding(
            id=CheckID.DELEGATION,
            title="User accounts with constrained delegation configured",
            severity=Severity.MEDIUM,
            description=(
                f"{len(constrained)} user account(s) have constrained Kerberos delegation "
                "configured (msDS-AllowedToDelegateTo). These can impersonate users to "
                "the listed services. Verify these are intentional and minimal."
            ),
            evidence={
                "count": len(constrained),
                "accounts": [
                    {"dn": u.dn, "sAMAccountName": _first(u, "sAMAccountName"),
                     "delegatesTo": spns[:10]}
                    for u, spns in constrained
                ],
            },
            recommendation=(
                "Audit msDS-AllowedToDelegateTo on all accounts. "
                "Remove entries that are no longer needed. "
                "Consider migrating to resource-based constrained delegation (RBCD)."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uac(user: UserEntry) -> int | None:
    raw = user.attributes.get("userAccountControl", [])
    if not raw:
        return None
    try:
        return int(raw[0] if isinstance(raw, list) else raw)
    except (ValueError, TypeError):
        return None


def _is_disabled(user: UserEntry) -> bool:
    uac = _uac(user)
    return uac is not None and bool(uac & UAC_DISABLED)


def _first(user: UserEntry, attr: str) -> str:
    val = user.attributes.get(attr, [])
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val) if val else ""
