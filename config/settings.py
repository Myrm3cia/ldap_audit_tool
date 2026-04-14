"""
Global constants, severity levels, and default values for ldap-audit.
"""

from enum import Enum


# --- Severity ---

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH:     4,
    Severity.MEDIUM:   3,
    Severity.LOW:      2,
    Severity.INFO:     1,
}

# Terminal colors (ANSI)
SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[1;31m",   # bold red
    Severity.HIGH:     "\033[31m",     # red
    Severity.MEDIUM:   "\033[33m",     # yellow
    Severity.LOW:      "\033[36m",     # cyan
    Severity.INFO:     "\033[37m",     # white
}
COLOR_RESET = "\033[0m"


# --- Default ports ---

DEFAULT_LDAP_PORT  = 389
DEFAULT_LDAPS_PORT = 636


# --- Connection defaults ---

DEFAULT_TIMEOUT        = 10   # seconds
DEFAULT_RECEIVE_TIMEOUT = 10


# --- Privileged patterns ---
# DN fragments or CN values that suggest elevated privileges.

PRIVILEGED_DN_PATTERNS = [
    "cn=admin",
    "cn=administrator",
    "cn=root",
    "cn=manager",
    "cn=directory manager",
    "cn=domain admins",
    "cn=schema admins",
    "cn=enterprise admins",
    "cn=group policy creator owners",
    "cn=account operators",
    "cn=backup operators",
    "ou=admins",
]

# Group object classes to recognise
GROUP_OBJECT_CLASSES = [
    "groupOfNames",
    "groupOfUniqueNames",
    "posixGroup",
    "group",
    "organizationalRole",
]

# User object classes to recognise
USER_OBJECT_CLASSES = [
    "inetOrgPerson",
    "person",
    "organizationalPerson",
    "posixAccount",
    "shadowAccount",
    "user",
]


# --- Password policy attributes ---

PWD_POLICY_ATTRIBUTES = [
    "pwdPolicySubentry",    # RFC 3112
    "pwdMaxAge",
    "pwdMinLength",
    "pwdMaxFailure",
    "pwdLockout",
    "pwdLockoutDuration",
    "pwdMustChange",
    "pwdAllowUserChange",
    "pwdExpireWarning",
    "passwordExpirationTime",    # Netscape/389-DS
    "passwordMinAge",
    "passwordMaxAge",
    "passwordInHistory",
    "passwordLockout",
    "passwordMinLength",
    "msDS-PasswordSettings",     # Active Directory
    "msDS-MinimumPasswordLength",
    "msDS-PasswordComplexityEnabled",
    "msDS-LockoutThreshold",
    "msDS-LockoutDuration",
]

# Attribute that marks an account as locked / disabled
ACCOUNT_DISABLED_ATTRIBUTES = [
    "pwdAccountLockedTime",
    "nsAccountLock",
    "userAccountControl",   # AD: bit 2 = ACCOUNTDISABLE
]


# --- Security-relevant user attributes to collect ---

USER_ATTRIBUTES = [
    "cn",
    "uid",
    "sAMAccountName",
    "userPrincipalName",
    "mail",
    "memberOf",
    "pwdPolicySubentry",
    "pwdAccountLockedTime",
    "nsAccountLock",
    "userAccountControl",
    "shadowExpire",
    "shadowLastChange",
    "shadowMax",
    "passwordExpirationTime",
    "passwordExpWarning",
    "createTimestamp",
    "modifyTimestamp",
]


# --- Check IDs ---

class CheckID:
    ANONYMOUS_BIND      = "LDAP-001"
    PASSWORD_POLICY     = "LDAP-002"
    PRIVILEGED_ACCOUNTS = "LDAP-003"
    MISSING_ATTRIBUTES  = "LDAP-004"
    ROOTDSE_EXPOSURE    = "LDAP-005"
