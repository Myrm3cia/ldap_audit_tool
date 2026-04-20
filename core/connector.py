"""
LDAP connection management.

Handles:
- Authenticated bind (simple)
- Anonymous bind
- TLS / LDAPS
- Safe disconnection
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Optional

import ldap3
from ldap3 import (
    Connection,
    Server,
    SYNC,
    ANONYMOUS,
    SIMPLE,
    Tls,
    ALL_OPERATIONAL_ATTRIBUTES,
    SUBTREE,
    BASE,
)
from ldap3.core.exceptions import (
    LDAPException,
    LDAPBindError,
    LDAPSocketOpenError,
    LDAPStartTLSError,
)

from config.settings import DEFAULT_LDAP_PORT, DEFAULT_LDAPS_PORT, DEFAULT_TIMEOUT

logger = logging.getLogger(__name__)


@dataclass
class LDAPConnectionConfig:
    """All parameters needed to open an LDAP connection."""
    host: str
    port: int                       = DEFAULT_LDAP_PORT
    use_ssl: bool                   = False     # LDAPS (port 636)
    use_tls: bool                   = False     # StartTLS on plain port
    bind_dn: Optional[str]          = None      # None → anonymous
    bind_password: Optional[str]    = None
    base_dn: Optional[str]          = None      # auto-detected if None
    timeout: int                    = DEFAULT_TIMEOUT
    validate_cert: bool             = False     # set True in prod


@dataclass
class LDAPConnectionResult:
    """Outcome of a connection attempt."""
    success: bool
    anonymous: bool                 = False
    error: Optional[str]            = None
    server_info: dict               = field(default_factory=dict)
    naming_contexts: list[str]      = field(default_factory=list)
    base_dn: Optional[str]          = None


class LDAPConnector:
    """
    Opens and manages a single LDAP connection.

    Usage:
        connector = LDAPConnector(config)
        result = connector.connect()
        if result.success:
            entries = connector.search(...)
        connector.disconnect()

    Or as context manager:
        with LDAPConnector(config) as conn:
            ...
    """

    def __init__(self, config: LDAPConnectionConfig) -> None:
        self.config = config
        self._server: Optional[Server] = None
        self._conn: Optional[Connection] = None
        self.auth_denied_count: int = 0  # searches blocked due to incomplete bind

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self) -> LDAPConnectionResult:
        """
        Establish the LDAP connection.
        Returns an LDAPConnectionResult describing what happened.
        """
        try:
            self._server = self._build_server()
            self._conn   = self._build_connection()
            self._conn.bind()
        except LDAPBindError as exc:
            return LDAPConnectionResult(success=False, error=f"Bind failed: {exc}")
        except LDAPSocketOpenError as exc:
            return LDAPConnectionResult(success=False, error=f"Cannot reach server: {exc}")
        except LDAPStartTLSError as exc:
            return LDAPConnectionResult(success=False, error=f"StartTLS failed: {exc}")
        except LDAPException as exc:
            return LDAPConnectionResult(success=False, error=f"LDAP error: {exc}")

        if not self._conn.bound:
            return LDAPConnectionResult(
                success=False,
                error=f"Bind returned no error but connection is not bound. "
                      f"Result: {self._conn.result}",
            )

        result = self._collect_server_info()
        logger.info(
            "Connected to %s:%d — anonymous=%s, base_dn=%s",
            self.config.host, self.config.port, result.anonymous, result.base_dn,
        )
        return result

    def disconnect(self) -> None:
        if self._conn and self._conn.bound:
            try:
                self._conn.unbind()
            except LDAPException:
                pass
        self._conn = None
        self._server = None

    @property
    def connection(self) -> Optional[Connection]:
        return self._conn

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str] | str = None,
        search_scope: str = SUBTREE,
        size_limit: int = 0,
    ) -> list[ldap3.Entry]:
        """
        Perform an LDAP search and return a list of ldap3 Entry objects.
        Returns [] on error (error is logged).

        Args:
            search_base:    Base DN for the search.
            search_filter:  LDAP filter string, e.g. '(objectClass=person)'.
            attributes:     List of attribute names, or ldap3.ALL / ldap3.ALL_OPERATIONAL_ATTRIBUTES.
            search_scope:   SUBTREE | ONELEVEL | BASE.
            size_limit:     Max entries (0 = server default).
        """
        if not self._conn or not self._conn.bound:
            logger.error("search() called on unbound connection")
            return []

        # Default to '*' (all user attributes) — avoids sending unknown
        # attribute names to servers that would reject them (e.g. AD).
        if attributes is None:
            attributes = ['*']

        try:
            self._conn.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=search_scope,
                attributes=attributes,
                size_limit=size_limit,
            )
        except LDAPException as exc:
            exc_str = str(exc)
            # Schema errors (unknown class/attribute) are expected when probing
            # servers that don't support a given schema (e.g. AD vs OpenLDAP).
            # Log at DEBUG to avoid noise; everything else is a real WARNING.
            if "invalid class" in exc_str or "invalid attribute type" in exc_str:
                logger.debug("Search skipped (%s): %s", search_filter, exc)
            elif "000004DC" in exc_str or "must be completed" in exc_str:
                self.auth_denied_count += 1
                logger.debug("Search blocked (auth required) (%s): %s", search_filter, exc)
            else:
                logger.warning("Search failed (%s): %s", search_filter, exc)
            return []

        entries = list(self._conn.entries)
        response_count = len([
            r for r in (self._conn.response or [])
            if r.get('type') == 'searchResEntry'
        ])
        logger.debug(
            "Search (%s) → entries=%d, raw_response_entries=%d, result=%s",
            search_filter, len(entries), response_count,
            self._conn.result.get('description', '?') if self._conn.result else '?',
        )
        return entries

    def get_root_dse(self) -> dict:
        """
        Read the rootDSE (server metadata) as a plain dict.
        Returns {} if not readable.
        """
        if not self._conn:
            return {}
        try:
            self._conn.search(
                search_base="",
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=ALL_OPERATIONAL_ATTRIBUTES,
            )
            if self._conn.entries:
                return self._conn.entries[0].entry_attributes_as_dict
        except LDAPException as exc:
            logger.debug("rootDSE not readable: %s", exc)
        return {}

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "LDAPConnector":
        self.connect()
        return self

    def __exit__(self, *_) -> None:
        self.disconnect()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_server(self) -> Server:
        tls = None
        if self.config.use_tls or self.config.use_ssl:
            import ssl
            tls = Tls(
                validate=ssl.CERT_REQUIRED if self.config.validate_cert else ssl.CERT_NONE,
            )

        port = self.config.port
        if self.config.use_ssl and port == DEFAULT_LDAP_PORT:
            port = DEFAULT_LDAPS_PORT

        return Server(
            host=self.config.host,
            port=port,
            use_ssl=self.config.use_ssl,
            tls=tls,
            connect_timeout=self.config.timeout,
            get_info=ldap3.DSA,
        )

    def _build_connection(self) -> Connection:
        anonymous = not self.config.bind_dn

        conn = Connection(
            server=self._server,
            user=self.config.bind_dn,
            password=self.config.bind_password,
            authentication=ANONYMOUS if anonymous else SIMPLE,
            client_strategy=SYNC,
            receive_timeout=self.config.timeout,
            raise_exceptions=True,
            read_only=True,   # never write to the directory
        )

        if self.config.use_tls and not self.config.use_ssl:
            conn.start_tls()

        return conn

    def _collect_server_info(self) -> LDAPConnectionResult:
        """Build LDAPConnectionResult after a successful bind."""
        anonymous = not self.config.bind_dn
        naming_contexts: list[str] = []
        server_info: dict = {}

        if self._server and self._server.info:
            info = self._server.info
            naming_contexts = [str(nc) for nc in (info.naming_contexts or [])]
            server_info = {
                "vendor_name":    str(info.vendor_name or ""),
                "vendor_version": str(info.vendor_version or ""),
                "supported_ldap_versions": [str(v) for v in (info.supported_ldap_versions or [])],
                "supported_sasl_mechanisms": [str(m) for m in (info.supported_sasl_mechanisms or [])],
                "supported_controls": [str(c) for c in (info.supported_controls or [])],
            }

        # Determine effective base DN
        base_dn = self.config.base_dn
        if not base_dn and naming_contexts:
            base_dn = naming_contexts[0]
            logger.info("Auto-detected base DN: %s", base_dn)

        return LDAPConnectionResult(
            success=True,
            anonymous=anonymous,
            server_info=server_info,
            naming_contexts=naming_contexts,
            base_dn=base_dn,
        )
