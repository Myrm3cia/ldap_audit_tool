"""
Directory enumerator.

Collects structural information from the LDAP directory:
- Domain info (naming contexts, server metadata)
- Organisational units (OU tree)
- Users (with security-relevant attributes)
- Groups (with membership)

All operations are read-only. Enumeration depth is limited to what the
authenticated (or anonymous) session is allowed to read.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import ldap3
from ldap3 import SUBTREE, LEVEL, BASE, ALL_OPERATIONAL_ATTRIBUTES

from config.settings import (
    USER_OBJECT_CLASSES,
    GROUP_OBJECT_CLASSES,
    USER_ATTRIBUTES,
)
from core.connector import LDAPConnector, LDAPConnectionResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class UserEntry:
    dn: str
    attributes: dict = field(default_factory=dict)

    @property
    def cn(self) -> str:
        return self._first("cn")

    @property
    def uid(self) -> str:
        return self._first("uid") or self._first("sAMAccountName")

    def _first(self, attr: str) -> str:
        val = self.attributes.get(attr)
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val else ""

    def __repr__(self) -> str:
        return f"UserEntry(dn={self.dn!r})"


@dataclass
class GroupEntry:
    dn: str
    attributes: dict = field(default_factory=dict)

    @property
    def cn(self) -> str:
        val = self.attributes.get("cn")
        if isinstance(val, list):
            return str(val[0]) if val else ""
        return str(val) if val else ""

    @property
    def members(self) -> list[str]:
        for attr in ("member", "uniqueMember", "memberUid"):
            val = self.attributes.get(attr, [])
            if val:
                return [str(m) for m in (val if isinstance(val, list) else [val])]
        return []

    def __repr__(self) -> str:
        return f"GroupEntry(dn={self.dn!r})"


@dataclass
class OUEntry:
    dn: str
    name: str


@dataclass
class DirectoryInfo:
    """All information collected about the directory."""
    base_dn: str
    naming_contexts: list[str]          = field(default_factory=list)
    server_info: dict                   = field(default_factory=dict)
    root_dse: dict                      = field(default_factory=dict)
    organisational_units: list[OUEntry] = field(default_factory=list)
    users: list[UserEntry]              = field(default_factory=list)
    groups: list[GroupEntry]            = field(default_factory=list)
    errors: list[str]                   = field(default_factory=list)

    @property
    def user_count(self) -> int:
        return len(self.users)

    @property
    def group_count(self) -> int:
        return len(self.groups)

    @property
    def ou_count(self) -> int:
        return len(self.organisational_units)


# ---------------------------------------------------------------------------
# Enumerator
# ---------------------------------------------------------------------------

class LDAPEnumerator:
    """
    Collects directory information via read-only LDAP searches.

    Args:
        connector:   An LDAPConnector that is already connected and bound.
        conn_result: The LDAPConnectionResult from connector.connect().
        size_limit:  Max entries per search (0 = server default).
    """

    def __init__(
        self,
        connector: LDAPConnector,
        conn_result: LDAPConnectionResult,
        size_limit: int = 500,
    ) -> None:
        self._conn    = connector
        self._result  = conn_result
        self._size    = size_limit

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def enumerate(self) -> DirectoryInfo:
        """
        Run full directory enumeration and return a DirectoryInfo.
        Each sub-method is independent; errors are collected, not raised.
        """
        base_dn = self._result.base_dn or ""
        info = DirectoryInfo(
            base_dn=base_dn,
            naming_contexts=self._result.naming_contexts,
            server_info=self._result.server_info,
        )

        if not base_dn:
            info.errors.append("No base DN available — skipping enumeration.")
            logger.warning("No base DN; skipping enumeration.")
            return info

        info.root_dse           = self._get_root_dse()
        info.organisational_units = self._get_ous(base_dn)
        info.users              = self._get_users(base_dn)
        info.groups             = self._get_groups(base_dn)

        logger.info(
            "Enumeration complete — OUs: %d, users: %d, groups: %d",
            info.ou_count, info.user_count, info.group_count,
        )
        return info

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_root_dse(self) -> dict:
        dse = self._conn.get_root_dse()
        if dse:
            logger.debug("rootDSE read successfully (%d attributes)", len(dse))
        else:
            logger.debug("rootDSE not readable or empty")
        return dse

    def _get_ous(self, base_dn: str) -> list[OUEntry]:
        entries = self._conn.search(
            search_base=base_dn,
            search_filter="(objectClass=organizationalUnit)",
            attributes=['*'],
            search_scope=SUBTREE,
            size_limit=self._size,
        )
        ous = []
        for e in entries:
            name = self._attr_str(e, "ou")
            ous.append(OUEntry(dn=e.entry_dn, name=name))
        logger.debug("Found %d OUs", len(ous))
        return ous

    def _get_users(self, base_dn: str) -> list[UserEntry]:
        search_filter = self._or_filter("objectClass", USER_OBJECT_CLASSES)
        # Request all available attributes (*) — filtering is done client-side.
        # This avoids sending attribute names unknown to the server (e.g. AD
        # rejects OpenLDAP-only names like pwdPolicySubentry).
        entries = self._conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            attributes=['*'],
            search_scope=SUBTREE,
            size_limit=self._size,
        )
        users = []
        for e in entries:
            attrs = self._entry_to_dict(e, USER_ATTRIBUTES)
            users.append(UserEntry(dn=e.entry_dn, attributes=attrs))
        logger.debug("Found %d user entries", len(users))
        return users

    def _get_groups(self, base_dn: str) -> list[GroupEntry]:
        search_filter = self._or_filter("objectClass", GROUP_OBJECT_CLASSES)
        group_attrs = ["cn", "description", "member", "uniqueMember", "memberUid", "objectClass"]
        # Same strategy: request all, filter client-side.
        entries = self._conn.search(
            search_base=base_dn,
            search_filter=search_filter,
            attributes=['*'],
            search_scope=SUBTREE,
            size_limit=self._size,
        )
        groups = []
        for e in entries:
            attrs = self._entry_to_dict(e, group_attrs)
            groups.append(GroupEntry(dn=e.entry_dn, attributes=attrs))
        logger.debug("Found %d group entries", len(groups))
        return groups

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    @staticmethod
    def _or_filter(attribute: str, values: list[str]) -> str:
        """Build an LDAP OR filter: (|(attr=val1)(attr=val2)...)"""
        parts = "".join(f"({attribute}={v})" for v in values)
        return f"(|{parts})"

    @staticmethod
    def _attr_str(entry: ldap3.Entry, attr: str) -> str:
        try:
            val = entry[attr].value
            if isinstance(val, list):
                return str(val[0]) if val else ""
            return str(val) if val is not None else ""
        except (ldap3.core.exceptions.LDAPAttributeError, KeyError):
            return ""

    @staticmethod
    def _entry_to_dict(entry: ldap3.Entry, attributes: list[str]) -> dict:
        """Convert an ldap3 Entry to a plain dict, handling list/single values."""
        result = {}
        for attr in attributes:
            if attr == "dn":
                result["dn"] = entry.entry_dn
                continue
            try:
                val = entry[attr].value
                # Normalise to list of strings for consistency
                if val is None:
                    result[attr] = []
                elif isinstance(val, list):
                    result[attr] = [str(v) for v in val]
                else:
                    result[attr] = [str(val)]
            except (ldap3.core.exceptions.LDAPAttributeError, KeyError):
                result[attr] = []
        return result
