"""Infrastructure layer for Sophos Firewall API interactions."""

import ast
import ipaddress
from typing import Callable, Final, Protocol

from pydantic import BaseModel, Field
from sophosfirewall_python.firewallapi import SophosFirewall, SophosFirewallAPIError

from src.domain.entities import NetworkRecord, OperationResult, OperationStatus
from src.domain.exceptions import (
    FirewallAuthenticationException,
    FirewallConnectionException,
    FirewallIPRestrictionException,
    FirewallOperationException,
    ResourceAlreadyExistsException,
)

# Status code constants
STATUS_SUCCESS: Final[str] = "200"
STATUS_ALREADY_EXISTS: Final[str] = "501"
STATUS_OPERATION_FAILED: Final[str] = "502"
STATUS_INVALID_VALUE: Final[str] = "503"
STATUS_MISSING_PARAM: Final[str] = "504"
STATUS_AUTH_FAILED: Final[str] = "534"
STATUS_UNKNOWN: Final[str] = "unknown"

# Status code to message mapping
_STATUS_MESSAGES: Final[dict[str, str]] = {
    STATUS_SUCCESS: "Created successfully",
    STATUS_ALREADY_EXISTS: "Already exists",
    STATUS_OPERATION_FAILED: "Operation failed",
    STATUS_INVALID_VALUE: "Invalid value",
    STATUS_MISSING_PARAM: "Missing parameter",
    STATUS_AUTH_FAILED: "Authentication failed",
    STATUS_UNKNOWN: "Unknown response format",
}

# Status code to OperationStatus mapping
_STATUS_MAPPING: Final[dict[str, OperationStatus]] = {
    STATUS_SUCCESS: OperationStatus.SUCCESS,
    STATUS_ALREADY_EXISTS: OperationStatus.ALREADY_EXISTS,
}


class APIResponse(BaseModel):
    """Sophos Firewall API response structure."""
    
    transaction_id: str | None = Field(None, alias="@transactionid")
    status_code: str = Field(..., alias="Status")
    status_message: str = Field(..., alias="Status")
    
    class Config:
        populate_by_name = True


class FirewallClient(Protocol):
    """Protocol defining firewall client interface."""

    def create_fqdn_group(self, name: str) -> OperationResult:
        """Create FQDN host group."""
        ...

    def create_ip_group(self, name: str) -> OperationResult:
        """Create IP host group."""
        ...

    def create_fqdn_host(self, record: NetworkRecord, group: str) -> OperationResult:
        """Create FQDN host entry."""
        ...

    def create_ip_host(self, record: NetworkRecord, group: str) -> OperationResult:
        """Create IP host entry."""
        ...

    def create_network(self, record: NetworkRecord, group: str) -> OperationResult:
        """Create network entry."""
        ...

    def get_existing_fqdns(self) -> set[str]:
        """Get all existing FQDN host values."""
        ...

    def get_existing_ip_hosts(self) -> set[str]:
        """Get all existing IP host values."""
        ...

    def get_existing_networks(self) -> set[str]:
        """Get all existing network CIDR values."""
        ...

    def get_fqdn_group_members(self, group_name: str) -> set[str]:
        """Get FQDN host names in a group."""
        ...

    def get_ip_group_members(self, group_name: str) -> set[str]:
        """Get IP host names in a group."""
        ...

    def add_to_fqdn_group(self, group_name: str, host_names: list[str]) -> bool:
        """Add FQDN hosts to a group. Returns True if successful."""
        ...

    def add_to_ip_group(self, group_name: str, host_names: list[str]) -> bool:
        """Add IP hosts to a group. Returns True if successful."""
        ...


class SophosFirewallClient:
    """
    Adapter for Sophos Firewall API.

    Wraps the sophosfirewall_python library and translates between
    the domain layer and the external API.
    """

    def __init__(
        self,
        hostname: str,
        username: str,
        password: str,
        port: int = 4444,
        verify_ssl: bool = False
    ):
        """
        Initialize firewall client.
        
        Args:
            hostname: Firewall hostname or IP
            username: API username
            password: API password
            port: API port (default: 4444)
            verify_ssl: Whether to verify SSL certificates
            
        Raises:
            FirewallConnectionException: If connection fails
            FirewallAuthenticationException: If authentication fails
        """
        try:
            self._client = SophosFirewall(
                hostname=hostname,
                username=username,
                password=password,
                port=port,
                verify=verify_ssl,
            )
        except SophosFirewallAPIError as e:
            error_msg = str(e.args[0]) if e.args else str(e)
            
            if "authentication" in error_msg.lower():
                raise FirewallAuthenticationException(error_msg)
            
            raise FirewallConnectionException(error_msg)
    
    @staticmethod
    def _contains_already_exists(text: str) -> bool:
        """Check if text indicates resource already exists."""
        text_lower = text.lower()
        return "already exists" in text_lower or "same name" in text_lower

    @staticmethod
    def _extract_status_from_response(response: dict) -> dict:
        """
        Extract status detail from various response structures.

        Sophos API returns status in different locations:
        - response["Response"]["Status"] (direct)
        - response["Response"]["IPHost"]["Status"] (for IP hosts/networks)
        - response["Response"]["FQDNHost"]["Status"] (for FQDN hosts)
        """
        api_response = response.get("Response", response)

        # Try direct Status first
        if "Status" in api_response and "@code" in api_response.get("Status", {}):
            return api_response["Status"]

        # Try resource-specific keys (IPHost, FQDNHost, IPNetwork, etc.)
        for key in ("IPHost", "FQDNHost", "IPNetwork", "FQDNHostGroup", "IPHostGroup"):
            if key in api_response:
                resource = api_response[key]
                if isinstance(resource, dict) and "Status" in resource:
                    return resource["Status"]

        return {}

    def _parse_response(
        self,
        response: dict,
        record: NetworkRecord,
    ) -> OperationResult:
        """
        Parse API response into OperationResult.

        Args:
            response: Raw API response
            record: Network record being processed

        Returns:
            OperationResult with parsed status
        """
        status_detail = self._extract_status_from_response(response)

        # Extract code and message with fallbacks
        code = (
            status_detail.get("@code")
            or status_detail.get("code")
            or STATUS_UNKNOWN
        )
        message = (
            status_detail.get("#text")
            or status_detail.get("text")
            or status_detail.get("message")
            or ""
        )

        # Handle 502 "already exists" edge case
        if code == STATUS_OPERATION_FAILED and self._contains_already_exists(str(response)):
            code = STATUS_ALREADY_EXISTS
            message = "Already exists"

        # Provide default message if empty
        if not message or message == "No message":
            message = _STATUS_MESSAGES.get(code, f"Operation completed with status {code}")

        # Map status code to operation status
        status = _STATUS_MAPPING.get(code, OperationStatus.FAILED)

        return OperationResult(
            record=record,
            status=status,
            status_code=code,
            message=message,
        )
    
    def _try_parse_error_response(
        self,
        error: SophosFirewallAPIError,
        record: NetworkRecord,
    ) -> OperationResult | None:
        """Attempt to parse error as a response dict."""
        if not error.args:
            return None

        first_arg = error.args[0]

        # Direct dict response
        if isinstance(first_arg, dict):
            return self._parse_response(first_arg, record)

        # String that might be a dict representation
        if isinstance(first_arg, str):
            try:
                error_dict = ast.literal_eval(first_arg)
                if isinstance(error_dict, dict):
                    return self._parse_response(error_dict, record)
            except (ValueError, SyntaxError, MemoryError):
                pass

        return None

    def _execute_operation(
        self,
        operation_func: Callable,
        record: NetworkRecord,
        *args,
        **kwargs,
    ) -> OperationResult:
        """
        Execute a firewall operation with error handling.

        Args:
            operation_func: API operation to execute
            record: Network record being processed
            args, kwargs: Arguments for the operation

        Returns:
            OperationResult with operation outcome

        Raises:
            FirewallIPRestrictionException: If IP not allowed
        """
        try:
            response = operation_func(*args, **kwargs)
            return self._parse_response(response, record)
        except SophosFirewallAPIError as e:
            error_msg = str(e.args[0]) if e.args else str(e)

            # IP restriction should stop execution
            if "not allowed from the requester IP" in error_msg:
                raise FirewallIPRestrictionException(error_msg)

            # Try to parse error as response dict
            parsed = self._try_parse_error_response(e, record)
            if parsed:
                return parsed

            # Check for "already exists" pattern
            if self._contains_already_exists(error_msg):
                return OperationResult(
                    record=record,
                    status=OperationStatus.ALREADY_EXISTS,
                    status_code=STATUS_ALREADY_EXISTS,
                    message="Already exists",
                )

            # Return as failed operation
            return OperationResult(
                record=record,
                status=OperationStatus.FAILED,
                status_code=STATUS_OPERATION_FAILED,
                message=error_msg or "Operation failed",
            )
    
    def _create_group(
        self,
        create_func: Callable,
        name: str,
        **kwargs,
    ) -> None:
        """
        Create host group with standardized error handling.

        Args:
            create_func: API function to call
            name: Group name
            kwargs: Additional arguments for create_func

        Raises:
            ResourceAlreadyExistsException: If group already exists
            FirewallOperationException: On other operation failures
        """
        try:
            create_func(name, **kwargs)
        except SophosFirewallAPIError as e:
            error_msg = str(e.args[0]) if e.args else str(e)

            # Check dict response for "already exists"
            if isinstance(e.args[0], dict):
                status = e.args[0].get("Status", {})
                code = status.get("@code", "")
                text = status.get("#text", "")
                if code == STATUS_OPERATION_FAILED and self._contains_already_exists(text):
                    raise ResourceAlreadyExistsException(f"Group '{name}' already exists")

            if self._contains_already_exists(error_msg):
                raise ResourceAlreadyExistsException(f"Group '{name}' already exists")

            raise FirewallOperationException(error_msg)

    def create_fqdn_group(self, name: str) -> None:
        """Create FQDN host group."""
        self._create_group(self._client.create_fqdn_hostgroup, name)

    def create_ip_group(self, name: str) -> None:
        """Create IP host group."""
        self._create_group(self._client.create_ip_hostgroup, name, host_list=[])
    
    def create_fqdn_host(
        self,
        record: NetworkRecord,
        group: str
    ) -> OperationResult:
        """
        Create FQDN host entry.
        
        Args:
            record: FQDN record
            group: Group to add host to
            
        Returns:
            Operation result
        """
        return self._execute_operation(
            self._client.create_fqdn_host,
            record,
            name=record.value,
            fqdn=record.value,
            fqdn_group_list=[group],
        )
    
    def create_ip_host(
        self,
        record: NetworkRecord,
        group: str
    ) -> OperationResult:
        """
        Create IP host entry (single IP as /32 network).
        
        Args:
            record: IP address record
            group: Group to add host to
            
        Returns:
            Operation result
        """
        return self._execute_operation(
            self._client.create_ip_host,
            record,
            name=record.value,
            ip_address=record.value,
            host_group_list=[group],
        )
    
    def create_network(
        self,
        record: NetworkRecord,
        group: str
    ) -> OperationResult:
        """
        Create network entry from CIDR.

        Args:
            record: Network CIDR record
            group: Group to add network to

        Returns:
            Operation result
        """
        ip_net = ipaddress.ip_network(record.value, strict=False)

        return self._execute_operation(
            self._client.create_ip_network,
            record,
            name=record.value,
            ip_network=str(ip_net.network_address),
            mask=str(ip_net.netmask),
        )

    def get_existing_fqdns(self) -> set[str]:
        """
        Fetch all existing FQDN host values from the firewall.

        Returns:
            Set of FQDN values (lowercase normalized)
        """
        try:
            response = self._client.get_fqdn_host()
            return self._extract_fqdn_values(response)
        except SophosFirewallAPIError:
            return set()

    def get_existing_ip_hosts(self) -> set[str]:
        """
        Fetch all existing IP host values from the firewall.

        Returns:
            Set of IP address values
        """
        try:
            response = self._client.get_ip_host()
            return self._extract_ip_values(response)
        except SophosFirewallAPIError:
            return set()

    def get_existing_networks(self) -> set[str]:
        """
        Fetch all existing network CIDR values from the firewall.

        Returns:
            Set of network CIDR values (normalized)
        """
        try:
            response = self._client.get_ip_host()
            return self._extract_network_values(response)
        except SophosFirewallAPIError:
            return set()

    @staticmethod
    def _extract_fqdn_values(response: dict) -> set[str]:
        """Extract FQDN values from API response."""
        result = set()
        api_response = response.get("Response", response)
        fqdn_hosts = api_response.get("FQDNHost", [])

        # Handle single item (dict) or multiple items (list)
        if isinstance(fqdn_hosts, dict):
            fqdn_hosts = [fqdn_hosts]

        for host in fqdn_hosts:
            if isinstance(host, dict):
                fqdn = host.get("FQDN", "")
                if fqdn:
                    result.add(fqdn.lower())
        return result

    @staticmethod
    def _extract_ip_values(response: dict) -> set[str]:
        """Extract single IP address values from API response."""
        result = set()
        api_response = response.get("Response", response)
        ip_hosts = api_response.get("IPHost", [])

        if isinstance(ip_hosts, dict):
            ip_hosts = [ip_hosts]

        for host in ip_hosts:
            if isinstance(host, dict):
                host_type = host.get("HostType", "")
                # Only include single IP addresses, not networks or ranges
                if host_type == "IP":
                    ip_addr = host.get("IPAddress", "")
                    if ip_addr:
                        result.add(ip_addr)
        return result

    @staticmethod
    def _extract_network_values(response: dict) -> set[str]:
        """Extract network CIDR values from API response."""
        result = set()
        api_response = response.get("Response", response)
        ip_hosts = api_response.get("IPHost", [])

        if isinstance(ip_hosts, dict):
            ip_hosts = [ip_hosts]

        for host in ip_hosts:
            if isinstance(host, dict):
                host_type = host.get("HostType", "")
                if host_type == "Network":
                    ip_addr = host.get("IPAddress", "")
                    subnet = host.get("Subnet", "")
                    if ip_addr and subnet:
                        # Normalize to CIDR notation
                        try:
                            network = ipaddress.ip_network(f"{ip_addr}/{subnet}", strict=False)
                            result.add(str(network))
                        except ValueError:
                            pass
        return result

    def get_fqdn_group_members(self, group_name: str) -> set[str]:
        """
        Get FQDN host names that are members of a group.

        Args:
            group_name: Name of the FQDN host group

        Returns:
            Set of FQDN host names in the group
        """
        try:
            response = self._client.get_fqdn_hostgroup(name=group_name)
            return self._extract_group_members(response, "FQDNHostGroup", "FQDNHostList")
        except SophosFirewallAPIError:
            return set()

    def get_ip_group_members(self, group_name: str) -> set[str]:
        """
        Get IP host names that are members of a group.

        Args:
            group_name: Name of the IP host group

        Returns:
            Set of IP host names in the group
        """
        try:
            response = self._client.get_ip_hostgroup(name=group_name)
            return self._extract_group_members(response, "IPHostGroup", "HostList")
        except SophosFirewallAPIError:
            return set()

    @staticmethod
    def _extract_group_members(response: dict, group_key: str, list_key: str) -> set[str]:
        """Extract member names from a host group response."""
        result = set()
        api_response = response.get("Response", response)
        group = api_response.get(group_key, {})

        if isinstance(group, dict):
            host_list = group.get(list_key, {})
            # Handle nested Host list structure
            if isinstance(host_list, dict):
                hosts = host_list.get("Host", [])
                if isinstance(hosts, str):
                    result.add(hosts)
                elif isinstance(hosts, list):
                    result.update(hosts)
            elif isinstance(host_list, list):
                result.update(host_list)

        return result

    def add_to_fqdn_group(self, group_name: str, host_names: list[str]) -> bool:
        """
        Add FQDN hosts to a group.

        Args:
            group_name: Name of the FQDN host group
            host_names: List of FQDN host names to add

        Returns:
            True if successful, False otherwise
        """
        if not host_names:
            return True

        try:
            self._client.update_fqdn_hostgroup(
                name=group_name,
                fqdn_host_list=host_names,
                action="add",
            )
            return True
        except SophosFirewallAPIError:
            return False

    def add_to_ip_group(self, group_name: str, host_names: list[str]) -> bool:
        """
        Add IP hosts to a group.

        Args:
            group_name: Name of the IP host group
            host_names: List of IP host names to add

        Returns:
            True if successful, False otherwise
        """
        if not host_names:
            return True

        try:
            self._client.update_ip_hostgroup(
                name=group_name,
                host_list=host_names,
                action="add",
            )
            return True
        except SophosFirewallAPIError:
            return False