"""
Computer account security checks.

COMP-001 — Stale computer accounts (inactive machine accounts)
COMP-002 — Computer accounts with delegation enabled
COMP-003 — Domain trust relationships
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from ldap3 import SUBTREE, BASE

from checks.anonymous_bind import Finding
from config.settings import CheckID, Severity
from core.connector import LDAPConnector
from core.enumerator import DirectoryInfo, ComputerEntry

logger = logging.getLogger(__name__)

AD_EPOCH_DELTA_SECONDS = 11_644_473_600
UAC_DISABLED               = 0x00000002
UAC_TRUSTED_FOR_DELEGATION = 0x00080000
UAC_TRUSTED_TO_AUTH        = 0x01000000
UAC_WORKSTATION_TRUST      = 0x00001000
UAC_SERVER_TRUST           = 0x00002000   # Domain Controller

STALE_COMPUTER_DAYS = 90

# trustAttributes flags
TRUST_ATTR_NON_TRANSITIVE   = 0x001
TRUST_ATTR_QUARANTINED      = 0x004   # SID filtering enabled (external trusts)
TRUST_ATTR_FOREST_TRANSITIVE = 0x008
TRUST_ATTR_CROSS_ORGANIZATION = 0x010

# trustDirection
TRUST_DIR_INBOUND     = 1
TRUST_DIR_OUTBOUND    = 2
TRUST_DIR_BIDIRECTIONAL = 3

# trustType
TRUST_TYPE_DOWNLEVEL  = 1   # NT4
TRUST_TYPE_UPLEVEL    = 2   # AD Kerberos
TRUST_TYPE_MIT        = 3   # MIT Kerberos


def run(connector: LDAPConnector, dir_info: DirectoryInfo) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_comp001(dir_info))
    findings.extend(_comp002(dir_info))
    findings.extend(_comp003(connector, dir_info))
    return findings


# ---------------------------------------------------------------------------
# COMP-001 — Stale computer accounts
# ---------------------------------------------------------------------------

def _comp001(dir_info: DirectoryInfo) -> list[Finding]:
    """
    Find enabled computer accounts that have not authenticated in more than
    STALE_COMPUTER_DAYS days. Stale machine accounts may indicate decommissioned
    systems that still have valid credentials in the domain.
    """
    now   = datetime.now(tz=timezone.utc)
    stale = []
    never = []

    for c in dir_info.computers:
        if _is_disabled(c):
            continue
        if _is_dc(c):
            continue   # DCs are managed differently

        logon_result = _last_logon(c, now)
        if logon_result == "never":
            never.append(c)
        elif isinstance(logon_result, int) and logon_result > STALE_COMPUTER_DAYS:
            stale.append((c, logon_result))

    findings = []

    if never:
        findings.append(Finding(
            id=CheckID.STALE_COMPUTERS,
            title="Enabled computer accounts that have never authenticated",
            severity=Severity.MEDIUM,
            description=(
                f"{len(never)} enabled computer account(s) show no recorded logon activity. "
                "These may be pre-staged, decommissioned, or orphaned machine accounts."
            ),
            evidence={
                "count": len(never),
                "computers": [{"dn": c.dn, "cn": c.cn, "os": _first(c, "operatingSystem")}
                               for c in never[:20]],
                "truncated": len(never) > 20,
            },
            recommendation=(
                "Verify whether these machines are still active. "
                "Disable and delete computer accounts for decommissioned systems."
            ),
        ))

    if stale:
        stale.sort(key=lambda x: x[1], reverse=True)
        findings.append(Finding(
            id=CheckID.STALE_COMPUTERS,
            title=f"Stale computer accounts (no logon in {STALE_COMPUTER_DAYS}+ days)",
            severity=Severity.MEDIUM,
            description=(
                f"{len(stale)} enabled computer account(s) have not authenticated "
                f"in over {STALE_COMPUTER_DAYS} days. "
                "Stale machine accounts represent unnecessary attack surface."
            ),
            evidence={
                "count": len(stale),
                "threshold_days": STALE_COMPUTER_DAYS,
                "computers": [{"dn": c.dn, "cn": c.cn, "days_inactive": days,
                                "os": _first(c, "operatingSystem")}
                               for c, days in stale[:20]],
                "truncated": len(stale) > 20,
            },
            recommendation=(
                f"Disable computer accounts inactive for more than {STALE_COMPUTER_DAYS} days "
                "after verifying they are no longer in use. Implement an automated stale account "
                "cleanup process."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# COMP-002 — Computer accounts with delegation
# ---------------------------------------------------------------------------

def _comp002(dir_info: DirectoryInfo) -> list[Finding]:
    """
    Find non-DC computer accounts with Kerberos delegation enabled.
    Unconstrained delegation on a workstation or server allows an attacker
    who compromises that machine to capture and relay TGTs.
    """
    unconstrained = []
    constrained   = []

    for c in dir_info.computers:
        if _is_disabled(c) or _is_dc(c):
            continue
        uac  = _uac(c)
        spns = c.attributes.get("msDS-AllowedToDelegateTo", [])

        if uac is not None:
            if uac & UAC_TRUSTED_FOR_DELEGATION:
                unconstrained.append(c)
                continue
            if uac & UAC_TRUSTED_TO_AUTH:
                constrained.append((c, spns if isinstance(spns, list) else [spns]))
                continue

        if spns:
            constrained.append((c, spns if isinstance(spns, list) else [spns]))

    findings = []

    if unconstrained:
        findings.append(Finding(
            id=CheckID.COMPUTER_DELEGATION,
            title="Non-DC computer accounts with unconstrained delegation",
            severity=Severity.CRITICAL,
            description=(
                f"{len(unconstrained)} non-domain-controller computer account(s) have "
                "unconstrained Kerberos delegation enabled. Compromising any of these "
                "machines allows an attacker to capture TGTs and impersonate any domain user, "
                "including Domain Admins (PrinterBug / Coerce attacks)."
            ),
            evidence={
                "count": len(unconstrained),
                "computers": [{"dn": c.dn, "cn": c.cn,
                                "os": _first(c, "operatingSystem"),
                                "dnsHostName": _first(c, "dNSHostName")}
                               for c in unconstrained],
            },
            recommendation=(
                "Remove TRUSTED_FOR_DELEGATION from all non-DC computer accounts. "
                "Migrate to constrained or resource-based constrained delegation. "
                "Enable 'Account is sensitive and cannot be delegated' on privileged accounts "
                "to protect them from delegation abuse."
            ),
        ))

    if constrained:
        findings.append(Finding(
            id=CheckID.COMPUTER_DELEGATION,
            title="Computer accounts with constrained delegation configured",
            severity=Severity.MEDIUM,
            description=(
                f"{len(constrained)} computer account(s) have constrained delegation "
                "configured (msDS-AllowedToDelegateTo). Review whether these are necessary."
            ),
            evidence={
                "count": len(constrained),
                "computers": [{"dn": c.dn, "cn": c.cn, "delegatesTo": spns[:5]}
                               for c, spns in constrained],
            },
            recommendation=(
                "Audit msDS-AllowedToDelegateTo on all computer accounts. "
                "Remove entries that are no longer needed."
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# COMP-003 — Domain trust relationships
# ---------------------------------------------------------------------------

def _comp003(connector: LDAPConnector, dir_info: DirectoryInfo) -> list[Finding]:
    """
    Enumerate trustedDomain objects under CN=System and flag risky configurations:
    - SID filtering disabled on external trusts (allows SID history abuse)
    - Bidirectional transitive trusts with external domains
    - Downlevel (NT4-style) trusts
    """
    base_dn = dir_info.base_dn
    if not base_dn:
        return []

    system_dn = f"CN=System,{base_dn}"
    entries = connector.search(
        search_base=system_dn,
        search_filter="(objectClass=trustedDomain)",
        attributes=['*'],
        search_scope=SUBTREE,
        size_limit=100,
    )

    if not entries:
        logger.debug("COMP-003: no trusted domain objects found")
        return []

    trusts = []
    for e in entries:
        attrs    = e.entry_attributes_as_dict
        name     = _dict_first(attrs, "name") or _dict_first(attrs, "cn")
        t_dir    = _dict_int(attrs, "trustDirection")
        t_type   = _dict_int(attrs, "trustType")
        t_attrs  = _dict_int(attrs, "trustAttributes") or 0

        sid_filtering = bool(t_attrs & TRUST_ATTR_QUARANTINED)
        transitive    = not bool(t_attrs & TRUST_ATTR_NON_TRANSITIVE)
        forest_trust  = bool(t_attrs & TRUST_ATTR_FOREST_TRANSITIVE)
        direction_str = {1: "Inbound", 2: "Outbound", 3: "Bidirectional"}.get(t_dir or 0, "Unknown")
        type_str      = {1: "Downlevel (NT4)", 2: "Uplevel (AD)", 3: "MIT Kerberos"}.get(t_type or 0, "Unknown")

        trusts.append({
            "name":          name,
            "dn":            e.entry_dn,
            "direction":     direction_str,
            "type":          type_str,
            "transitive":    transitive,
            "forest_trust":  forest_trust,
            "sid_filtering": sid_filtering,
            "trustAttributes": hex(t_attrs),
            "_raw_dir":  t_dir,
            "_raw_type": t_type,
        })

    findings = []

    # SID filtering disabled on external (non-forest) trusts
    sid_filter_off = [t for t in trusts if not t["sid_filtering"] and not t["forest_trust"]]
    if sid_filter_off:
        findings.append(Finding(
            id=CheckID.DOMAIN_TRUSTS,
            title="Domain trusts with SID filtering disabled",
            severity=Severity.HIGH,
            description=(
                f"{len(sid_filter_off)} external domain trust(s) have SID filtering "
                "disabled. An attacker who compromises the trusted domain can inject "
                "arbitrary SIDs (including Enterprise Admins) via SID history to "
                "escalate privileges in this domain."
            ),
            evidence={"trusts": sid_filter_off},
            recommendation=(
                "Enable SID filtering (quarantine) on all external trusts: "
                "netdom trust <TrustingDomain> /domain:<TrustedDomain> /quarantine:yes"
            ),
        ))

    # Bidirectional transitive trusts with non-forest domains
    bidir_transitive = [
        t for t in trusts
        if t.get("_raw_dir") == TRUST_DIR_BIDIRECTIONAL
        and t["transitive"]
        and not t["forest_trust"]
    ]
    if bidir_transitive:
        findings.append(Finding(
            id=CheckID.DOMAIN_TRUSTS,
            title="Bidirectional transitive external trusts",
            severity=Severity.MEDIUM,
            description=(
                f"{len(bidir_transitive)} bidirectional transitive trust(s) exist with "
                "external (non-forest) domains. These extend the attack surface: "
                "a compromise in the trusted domain can be leveraged laterally."
            ),
            evidence={"trusts": bidir_transitive},
            recommendation=(
                "Review whether bidirectional trust is necessary. "
                "Prefer one-directional trusts where possible. "
                "Ensure SID filtering is enabled and audit trust usage regularly."
            ),
        ))

    # Downlevel (NT4) trusts
    downlevel = [t for t in trusts if t.get("_raw_type") == TRUST_TYPE_DOWNLEVEL]
    if downlevel:
        findings.append(Finding(
            id=CheckID.DOMAIN_TRUSTS,
            title="Legacy downlevel (NT4-style) domain trusts",
            severity=Severity.MEDIUM,
            description=(
                f"{len(downlevel)} NT4-style downlevel trust(s) found. "
                "These use older, weaker authentication mechanisms and represent "
                "a legacy attack surface."
            ),
            evidence={"trusts": downlevel},
            recommendation=(
                "Migrate to Kerberos-based (uplevel) trusts. "
                "If NT4 systems are decommissioned, remove these trust relationships."
            ),
        ))

    # All trusts as INFO if no issues found
    if trusts and not findings:
        findings.append(Finding(
            id=CheckID.DOMAIN_TRUSTS,
            title="Domain trust relationships",
            severity=Severity.INFO,
            description=f"Found {len(trusts)} domain trust relationship(s). No obvious misconfigurations detected.",
            evidence={"trusts": [{k: v for k, v in t.items() if not k.startswith("_")} for t in trusts]},
            recommendation="Periodically review trust relationships and remove any that are no longer needed.",
        ))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uac(c: ComputerEntry) -> int | None:
    raw = c.attributes.get("userAccountControl", [])
    if not raw:
        return None
    try:
        return int(raw[0] if isinstance(raw, list) else raw)
    except (ValueError, TypeError):
        return None


def _is_disabled(c: ComputerEntry) -> bool:
    uac = _uac(c)
    return uac is not None and bool(uac & UAC_DISABLED)


def _is_dc(c: ComputerEntry) -> bool:
    uac = _uac(c)
    return uac is not None and bool(uac & UAC_SERVER_TRUST)


def _last_logon(c: ComputerEntry, now: datetime) -> str | int:
    for attr in ("lastLogonTimestamp", "lastLogon"):
        raw = c.attributes.get(attr, [])
        if not raw:
            continue
        val = raw[0] if isinstance(raw, list) else raw
        try:
            ts = int(val)
        except (ValueError, TypeError):
            continue
        if ts == 0:
            return "never"
        unix_ts = (ts / 10_000_000) - AD_EPOCH_DELTA_SECONDS
        if unix_ts <= 0:
            return "never"
        days = (now - datetime.fromtimestamp(unix_ts, tz=timezone.utc)).days
        return days
    return "never"


def _first(c: ComputerEntry, attr: str) -> str:
    val = c.attributes.get(attr, [])
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val) if val else ""


def _dict_first(d: dict, key: str) -> str:
    val = d.get(key, [])
    if isinstance(val, list):
        return str(val[0]) if val else ""
    return str(val) if val else ""


def _dict_int(d: dict, key: str) -> int | None:
    val = d.get(key, [])
    v   = val[0] if isinstance(val, list) else val
    try:
        return int(v)
    except (ValueError, TypeError):
        return None
