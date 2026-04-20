# ldap-audit-tool

Read-only LDAP security posture auditing tool.

Connects to an LDAP server (authenticated or anonymous) and performs security checks on directory configuration, Kerberos settings, account hygiene, and trust relationships. No exploits, no brute-force, no bypass techniques — analysis and reporting only.

## Requirements

- Python 3.10+
- `ldap3` library

## Installation

```bash
git clone https://github.com/Myrm3cia/ldap_audit_tool.git
cd ldap_audit_tool

python3 -m venv .venv
source .venv/bin/activate       # Linux / macOS
# .venv\Scripts\activate        # Windows (PowerShell)
# source .venv/Scripts/activate # Windows (Git Bash)

pip install -r requirements.txt
```

> The virtual environment must be active whenever you run the tool.
> To deactivate: `deactivate`

## Quick start

```bash
# Authenticated bind (password prompt)
python main.py --host ldap.example.com \
               --bind-dn "DOMAIN\administrator" \
               --ask-password

# Anonymous bind test only
python main.py --host ldap.example.com --anon

# LDAPS, specific base DN, all report formats
python main.py --host ldap.example.com --port 636 --use-ssl \
               --bind-dn "cn=admin,dc=example,dc=com" --ask-password \
               --base-dn "dc=example,dc=com" \
               --format all --output ./reports/audit

# Run only specific check groups
python main.py --host ldap.example.com --ask-password \
               --bind-dn "DOMAIN\administrator" \
               --checks kerb,priv,comp
```

## Options

### Connection
| Flag | Description |
|---|---|
| `--host` | LDAP server hostname or IP (required) |
| `--port` | TCP port (default: 389, 636 for LDAPS) |
| `--use-ssl` | LDAPS — TLS from the start |
| `--use-tls` | StartTLS on plain port |
| `--no-verify-cert` | Skip TLS certificate verification |
| `--timeout` | Connection timeout in seconds (default: 10) |

### Authentication
| Flag | Description |
|---|---|
| `--bind-dn` | Bind DN for authenticated access |
| `--bind-password` | Bind password (use `--ask-password` instead) |
| `--ask-password` | Prompt for password interactively (safer) |
| `--anon` | Force anonymous bind |

### Checks
| Flag | Description |
|---|---|
| `--checks` | Comma-separated check groups to run, or `all` (default: `all`) |

Available check groups:

| Key | Check IDs | Description |
|---|---|---|
| `anon` | LDAP-001 | Anonymous bind — tests whether the server allows unauthenticated access |
| `pwpol` | LDAP-002 | Password policy — AD Default Domain Policy, Fine-Grained PSOs, lockout settings |
| `privs` | LDAP-003 | Privileged accounts — group membership, UAC flags, non-expiring passwords |
| `attrs` | LDAP-004 | Missing attributes — no policy assigned, password never set, stale accounts |
| `rootdse` | LDAP-005 | rootDSE exposure — server metadata readable without authentication |
| `ldapcfg` | LDAP-006, LDAP-007 | LDAP configuration — signing enforcement, LDAPS availability |
| `kerb` | KERB-001 – KERB-004 | Kerberos — AS-REP roasting, Kerberoastable SPNs, weak encryption, delegation |
| `acc` | ACC-001 | Account hygiene — stale passwords, accounts with password never changed |
| `priv` | PRIV-001, PRIV-002 | Privilege — indirect DA/EA membership, orphaned adminCount accounts |
| `comp` | COMP-001 – COMP-003 | Computers — stale machine accounts, delegation on workstations, domain trusts |
| `pol` | POL-001 | Policy — krbtgt encryption types, krbtgt password age |

### Output
| Flag | Description |
|---|---|
| `--format` | `json` \| `txt` \| `html` \| `all` (default: `json`) |
| `--output` | Base path without extension (e.g. `./report`). Omit to print to stdout. |
| `--verbose` | Enable debug-level logging |

## Output formats

| Format | File | Description |
|---|---|---|
| `json` | `report.json` | Machine-readable, structured findings |
| `txt` | `report.txt` | Plain text, suitable for email/tickets |
| `html` | `report.html` | Self-contained interactive report (Nessus-style) |
| `all` | all three | Generates all formats at once |

## Checks reference

### LDAP-001 — Anonymous bind
Tests whether the server allows unauthenticated access by opening a separate anonymous connection. Flags the ability to read directory data without credentials.

### LDAP-002 — Password policy
Reads the Default Domain Policy and any Fine-Grained Password Policies (PSOs). Flags absent lockout settings, weak minimum length, no complexity requirements, and long maximum password age.

### LDAP-003 — Privileged accounts
Enumerates members of Domain Admins, Enterprise Admins, Schema Admins, Account Operators, and Backup Operators. Flags accounts with `DONT_EXPIRE_PASSWORD`, disabled MFA indicators, and built-in Administrator accounts in use.

### LDAP-004 — Missing attributes
Finds enabled user accounts with no assigned password policy, password never set (`pwdLastSet=0`), and accounts that have never logged in.

### LDAP-005 — rootDSE exposure
Documents the server attributes exposed via rootDSE (server version, supported controls, naming contexts). Always INFO severity.

### LDAP-006 — LDAP signing
Detects whether the server requires message signing. A successful simple bind without signing proves `ldapServerIntegrity < 2`, allowing LDAP relay attacks.

### LDAP-007 — LDAPS availability
Probes port 636 for SSL. Flags absence of LDAPS (cleartext credentials) or LDAPS coexisting with open port 389 (fallback risk).

### KERB-001 — AS-REP roasting
Finds enabled user accounts with `DONT_REQ_PREAUTH` set (`UF_DONT_REQUIRE_PREAUTH = 0x00400000`). These accounts expose their password hash to offline cracking without needing domain credentials.

### KERB-002 — Kerberoasting
Finds enabled non-computer accounts with Service Principal Names (SPNs) registered. Their TGS tickets can be requested by any authenticated user and cracked offline.

### KERB-003 — Weak Kerberos encryption
Checks `msDS-SupportedEncryptionTypes` on user accounts. Flags DES (broken), RC4-only, and missing AES configuration.

### KERB-004 — Kerberos delegation
Finds non-DC accounts with unconstrained delegation (`TRUSTED_FOR_DELEGATION`), protocol transition (`TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION`), or constrained delegation (`msDS-AllowedToDelegateTo`).

### ACC-001 — Stale passwords
Finds enabled accounts where the password has never been changed (`pwdLastSet=0`), or has not changed in over 180 / 365 days.

### PRIV-001 — Indirect privileged group membership
Uses the `LDAP_MATCHING_RULE_IN_CHAIN` OID for recursive group membership lookup. Flags accounts that reach Domain Admins or Enterprise Admins through nested groups.

### PRIV-002 — Orphaned adminCount accounts
Finds accounts with `adminCount=1` that are no longer members of any protected group. These accounts retain hardened ACLs from SDProp and may be overlooked.

### COMP-001 — Stale computer accounts
Enabled non-DC computer accounts that have not authenticated in more than 90 days, or have never authenticated. Stale machine accounts represent unnecessary attack surface.

### COMP-002 — Computer delegation
Non-DC computer accounts with Kerberos delegation enabled. Unconstrained delegation allows TGT capture and impersonation of any domain user.

### COMP-003 — Domain trusts
Enumerates `trustedDomain` objects under `CN=System`. Flags SID filtering disabled on external trusts (SID history abuse), bidirectional transitive trusts, and legacy NT4-style trusts.

### POL-001 — Kerberos policy
Inspects the krbtgt account encryption types and password age. DES on krbtgt is CRITICAL; RC4 default or password not rotated in 180+ days are flagged. Notes that ticket lifetime settings require GPO inspection.

## Project structure

```
ldap_audit_tool/
├── main.py                      # CLI entry point
├── requirements.txt
├── config/
│   └── settings.py              # Constants, severity levels, check IDs
├── core/
│   ├── connector.py             # LDAP connection management
│   ├── enumerator.py            # Directory enumeration (OUs, users, groups, computers)
│   └── analyzer.py              # Check orchestrator
├── checks/
│   ├── anonymous_bind.py        # LDAP-001 + Finding dataclass
│   ├── password_policy.py       # LDAP-002
│   ├── privileged_accounts.py   # LDAP-003
│   ├── missing_attributes.py    # LDAP-004
│   ├── ldap_config.py           # LDAP-006, LDAP-007
│   ├── kerberos.py              # KERB-001 – KERB-004
│   ├── account.py               # ACC-001
│   ├── privilege.py             # PRIV-001, PRIV-002
│   ├── computers.py             # COMP-001 – COMP-003
│   └── policy.py                # POL-001
└── output/
    ├── reporter.py              # JSON / TXT dispatcher
    └── html_reporter.py         # Self-contained Nessus-style HTML report
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No HIGH or CRITICAL findings |
| `1` | At least one HIGH or CRITICAL finding detected |

Useful for scripting:
```bash
python main.py --host ldap.example.com --ask-password \
               --bind-dn "DOMAIN\administrator" || echo "Critical issues found"
```

## Notes

- All LDAP operations are **read-only** (`read_only=True` on the connection)
- The anonymous bind check (LDAP-001) opens a **separate** unauthenticated connection — it does not reuse the authenticated session
- Attribute requests use `['*']` (all user attributes) to avoid sending schema-specific names to servers that reject them (AD rejects OpenLDAP-only attribute names)
- The `LDAP_MATCHING_RULE_IN_CHAIN` OID (`1.2.840.113556.1.4.1941`) is used for recursive group membership queries — Active Directory only
- Tested against Active Directory (Windows Server 2019/2022)
