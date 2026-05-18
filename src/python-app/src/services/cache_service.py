"""Service for caching existing firewall records and group membership."""

import ipaddress
from dataclasses import dataclass, field

from src.domain.entities import NetworkRecord, RecordType
from src.infrastructure.firewall_client import FirewallClient


@dataclass
class GroupMembershipCache:
    """
    Cache for group membership.

    Tracks which hosts are already members of target groups
    to enable efficient update operations.
    """

    _fqdn_group_members: set[str] = field(default_factory=set)
    _ip_group_members: set[str] = field(default_factory=set)
    _loaded: bool = False

    def load(
        self,
        client: FirewallClient,
        fqdn_group_name: str,
        ip_group_name: str,
    ) -> bool:
        """
        Load group membership from the firewall.

        Args:
            client: Firewall client
            fqdn_group_name: Name of the FQDN host group
            ip_group_name: Name of the IP host group

        Returns:
            True if successful, False otherwise
        """
        try:
            self._fqdn_group_members = client.get_fqdn_group_members(fqdn_group_name)
            self._ip_group_members = client.get_ip_group_members(ip_group_name)
            self._loaded = True
            return True
        except Exception:
            self._loaded = False
            return False

    def is_member(self, record: NetworkRecord) -> bool:
        """
        Check if a record is already a member of its target group.

        Args:
            record: Network record to check

        Returns:
            True if already a member, False otherwise.
            Returns False if cache not loaded.
        """
        if not self._loaded:
            return False

        # Host names in Sophos are the record values
        host_name = record.value

        if record.record_type == RecordType.FQDN:
            return host_name in self._fqdn_group_members

        if record.record_type in (RecordType.IP_ADDRESS, RecordType.NETWORK_CIDR):
            return host_name in self._ip_group_members

        return False

    @property
    def is_loaded(self) -> bool:
        """Check if cache was loaded."""
        return self._loaded

    @property
    def stats(self) -> dict[str, int]:
        """Get cache statistics."""
        return {
            "fqdn_members": len(self._fqdn_group_members),
            "ip_members": len(self._ip_group_members),
        }


@dataclass
class ExistingRecordsCache:
    """
    Cache for existing firewall records.

    Fetches existing records from the firewall once and provides
    fast O(1) lookups to determine if a record already exists.
    """

    _fqdns: set[str] = field(default_factory=set)
    _ip_hosts: set[str] = field(default_factory=set)
    _networks: set[str] = field(default_factory=set)
    _loaded: bool = False
    _fetch_failed: bool = False

    def load(self, client: FirewallClient) -> bool:
        """
        Load existing records from the firewall.

        Args:
            client: Firewall client to fetch records from

        Returns:
            True if fetch succeeded, False if it failed (will use fallback mode)
        """
        try:
            self._fqdns = client.get_existing_fqdns()
            self._ip_hosts = client.get_existing_ip_hosts()
            self._networks = client.get_existing_networks()
            self._loaded = True
            self._fetch_failed = False
            return True
        except Exception:
            self._fetch_failed = True
            self._loaded = False
            return False

    def exists(self, record: NetworkRecord) -> bool:
        """
        Check if a record already exists on the firewall.

        Args:
            record: Network record to check

        Returns:
            True if record exists, False otherwise.
            Always returns False if cache wasn't loaded (fallback mode).
        """
        if not self._loaded or self._fetch_failed:
            # Fallback: assume record doesn't exist, let API handle it
            return False

        if record.record_type == RecordType.FQDN:
            return record.value.lower() in self._fqdns

        if record.record_type == RecordType.IP_ADDRESS:
            return record.value in self._ip_hosts

        if record.record_type == RecordType.NETWORK_CIDR:
            # Normalize the CIDR for comparison
            try:
                normalized = str(ipaddress.ip_network(record.value, strict=False))
                return normalized in self._networks
            except ValueError:
                return False

        return False

    @property
    def is_loaded(self) -> bool:
        """Check if cache was successfully loaded."""
        return self._loaded

    @property
    def fetch_failed(self) -> bool:
        """Check if fetch failed (using fallback mode)."""
        return self._fetch_failed

    @property
    def stats(self) -> dict[str, int]:
        """Get cache statistics."""
        return {
            "fqdns": len(self._fqdns),
            "ip_hosts": len(self._ip_hosts),
            "networks": len(self._networks),
            "total": len(self._fqdns) + len(self._ip_hosts) + len(self._networks),
        }
