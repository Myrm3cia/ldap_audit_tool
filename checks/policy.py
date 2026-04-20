"""
Policy checks.

POL-001 — Kerberos policy: encryption types and krbtgt account health
"""

from __future__ import annotations

import logging

from ldap3 import BASE

from checks.anonymous_bind import Finding
from config.settings import CheckID, Severity
from core.connector import LDAPConnector
from core.enumerator import DirectoryInfo

logger = logging.getLogger(__name__)

ENC_DES_CBC_CRC = 0x01
ENC_DES_CBC_MD5 = 0x02
ENC_RC4_HMAC    = 0x04
ENC_AES128      = 0x08
ENC_AES256      = 0x10


def run(connector: LDAPConnector, dir_info: DirectoryInfo) -> list[Finding]:
    return _pol001(connector, dir_info)


def _pol001(connector: LDAPConnector, dir_info: DirectoryInfo) -> list[Finding]:
    """
    Assess Kerberos policy health by inspecting:
    1. The krbtgt account encryption types (controls TGT encryption)
    2. Domain-level maxPwdAge / lockout already checked in LDAP-002,
       so here we focus on what is Kerberos-specific.

    Note: ticket lifetime (TGT age, service ticket age) is stored in the
    Default Domain Policy GPO in SYSVOL, which is not accessible via LDAP.
    This check provides what CAN be determined via LDAP and flags the gap.
    """
    base_dn = dir_info.base_dn
    if not base_dn:
        return []

    findings: list[Finding] = []

    # --- krbtgt account ---
    krbtgt_dn = f"CN=krbtgt,CN=Users,{base_dn}"
    entries = connector.search(
        search_base=krbtgt_dn,
        search_filter="(objectClass=user)",
        attributes=['*'],
        search_scope=BASE,
    )

    if entries:
        krbtgt = entries[0]
        attrs  = krbtgt.entry_attributes_as_dict

        enc_raw = attrs.get("msDS-SupportedEncryptionTypes", [])
        enc_val = None
        if enc_raw:
            try:
                enc_val = int(enc_raw[0] if isinstance(enc_raw, list) else enc_raw)
            except (ValueError, TypeError):
                pass

        pwd_last_set = _dict_int(attrs, "pwdLastSet") or 0

        # Check krbtgt encryption types
        if enc_val is None or enc_val == 0:
            findings.append(Finding(
                id=CheckID.KERBEROS_POLICY,
                title="krbtgt account uses default RC4 encryption (no explicit AES)",
                severity=Severity.HIGH,
                description=(
                    "The krbtgt account has no explicit msDS-SupportedEncryptionTypes set "
                    "(value = 0 or absent). Active Directory defaults to offering RC4-HMAC "
                    "for Ticket Granting Tickets (TGTs). RC4-based TGTs are susceptible to "
                    "offline cracking (Golden Ticket attacks are faster with RC4)."
                ),
                evidence={
                    "krbtgt_dn": krbtgt_dn,
                    "msDS-SupportedEncryptionTypes": enc_val,
                },
                recommendation=(
                    "Set msDS-SupportedEncryptionTypes on the krbtgt account to 0x18 "
                    "(AES128 + AES256). After changing, reset the krbtgt password twice "
                    "(with a replication delay between resets) to invalidate existing tickets."
                ),
            ))
        elif enc_val & (ENC_DES_CBC_CRC | ENC_DES_CBC_MD5):
            findings.append(Finding(
                id=CheckID.KERBEROS_POLICY,
                title="krbtgt account supports DES encryption",
                severity=Severity.CRITICAL,
                description=(
                    "The krbtgt account is configured to support DES Kerberos encryption "
                    f"(msDS-SupportedEncryptionTypes = {hex(enc_val)}). "
                    "DES is cryptographically broken and enables trivial Golden Ticket forgery."
                ),
                evidence={
                    "krbtgt_dn": krbtgt_dn,
                    "msDS-SupportedEncryptionTypes": hex(enc_val),
                },
                recommendation=(
                    "Immediately disable DES on the krbtgt account and set "
                    "msDS-SupportedEncryptionTypes to 0x18 (AES only). "
                    "Reset the krbtgt password twice to invalidate existing tickets."
                ),
            ))

        # Check krbtgt password age (Golden Ticket invalidation)
        if pwd_last_set:
            from datetime import datetime, timezone
            AD_EPOCH = 11_644_473_600
            unix_ts  = (pwd_last_set / 10_000_000) - AD_EPOCH
            if unix_ts > 0:
                age_days = (datetime.now(tz=timezone.utc) -
                            datetime.fromtimestamp(unix_ts, tz=timezone.utc)).days
                if age_days > 180:
                    findings.append(Finding(
                        id=CheckID.KERBEROS_POLICY,
                        title=f"krbtgt password not rotated in {age_days} days",
                        severity=Severity.MEDIUM,
                        description=(
                            f"The krbtgt account password was last changed {age_days} days ago. "
                            "The krbtgt secret is the root of all Kerberos trust in the domain. "
                            "If a Golden Ticket was created with the old key, it remains valid "
                            "until the password is rotated twice."
                        ),
                        evidence={
                            "krbtgt_dn":         krbtgt_dn,
                            "password_age_days": age_days,
                        },
                        recommendation=(
                            "Rotate the krbtgt password every 180 days or immediately after "
                            "a suspected compromise. Reset it twice (wait for AD replication "
                            "between resets) to fully invalidate old Golden Tickets. "
                            "Use Microsoft's 'New-KrbtgtKeys.ps1' script for safe rotation."
                        ),
                    ))

    # --- Note about ticket lifetime (not readable via LDAP) ---
    findings.append(Finding(
        id=CheckID.KERBEROS_POLICY,
        title="Kerberos ticket lifetime requires GPO inspection",
        severity=Severity.INFO,
        description=(
            "Kerberos ticket lifetime settings (TGT lifetime, service ticket lifetime, "
            "renewal lifetime) are stored in the Default Domain Policy GPO in SYSVOL "
            "and cannot be read via LDAP. Manual verification is required."
        ),
        evidence={
            "defaults_if_not_configured": {
                "maximum_tgt_lifetime_hours":     10,
                "maximum_service_ticket_minutes": 600,
                "maximum_renewal_days":           7,
                "maximum_clock_skew_minutes":     5,
            },
            "recommended": {
                "maximum_tgt_lifetime_hours":     "8–10 (default is acceptable)",
                "maximum_service_ticket_minutes": "≤ 600",
                "maximum_renewal_days":           "≤ 7",
            },
        },
        recommendation=(
            "Verify Kerberos policy via: Group Policy Management > Default Domain Policy > "
            "Computer Configuration > Windows Settings > Security Settings > "
            "Account Policies > Kerberos Policy. "
            "The AD default values are generally acceptable; reduce if your policy requires it."
        ),
    ))

    return findings


def _dict_int(d: dict, key: str) -> int | None:
    val = d.get(key, [])
    v   = val[0] if isinstance(val, list) else val
    try:
        return int(v)
    except (ValueError, TypeError):
        return None
