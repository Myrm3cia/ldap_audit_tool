# ldap-audit

Read-only LDAP security posture auditing tool.

Connects to an LDAP server (authenticated or anonymous) and performs security checks on directory configuration. No exploits, no brute-force, no bypass techniques — analysis and reporting only.

## Requirements

- Python 3.10+
- `ldap3` library

## Installation

```bash
git clone <repo>
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

# Anonymous bind test
python main.py --host ldap.example.com --anon

# LDAPS, specific base DN, all reports
python main.py --host ldap.example.com --port 636 --use-ssl \
               --bind-dn "cn=admin,dc=example,dc=com" --ask-password \
               --base-dn "dc=example,dc=com" \
               --format all --output ./reports/audit
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
| `--checks` | Comma-separated checks to run, or `all` (default: `all`) |

Available checks:

| ID | Key | Description |
|---|---|---|
| LDAP-001 | `anon` | Anonymous bind — opens a separate unauthenticated connection to test server policy |
| LDAP-002 | `pwpol` | Password policy — AD Default Domain Policy, Fine-Grained PSOs, OpenLDAP pwdPolicy |
| LDAP-003 | `privs` | Privileged accounts — groups, UAC flags, non-expiring passwords |
| LDAP-004 | `attrs` | Missing attributes — no policy assigned, password never set, stale/never-logged-in accounts |
| LDAP-005 | `rootdse` | rootDSE exposure — server metadata readable without authentication |

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

## Project structure

```
ldap_audit_tool/
├── main.py                    # CLI entry point
├── config/
│   └── settings.py            # Constants, severity levels, DN patterns
├── core/
│   ├── connector.py           # LDAP connection management
│   ├── enumerator.py          # Directory enumeration (OUs, users, groups)
│   └── analyzer.py            # Check orchestrator
├── checks/
│   ├── anonymous_bind.py      # LDAP-001
│   ├── password_policy.py     # LDAP-002
│   ├── privileged_accounts.py # LDAP-003
│   └── missing_attributes.py  # LDAP-004
└── output/
    ├── reporter.py            # JSON / TXT writer
    └── html_reporter.py       # HTML report (self-contained)
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No HIGH or CRITICAL findings |
| `1` | At least one HIGH or CRITICAL finding detected |

Useful for scripting:
```bash
python main.py --host ldap.example.com --ask-password || echo "Critical issues found"
```

## Notes

- All LDAP operations are **read-only** (`read_only=True` on the connection)
- The anonymous bind check opens a **separate** connection — it does not reuse the authenticated session
- Attribute requests use `['*']` (all user attributes) to avoid sending schema-specific names to servers that would reject them (e.g. AD rejects OpenLDAP-only attribute names)
- Tested against Active Directory (Windows Server) and compatible with OpenLDAP / 389-DS
