"""Infrastructure layer for Sophos Firewall API interactions."""

import ipaddress
from typing import Protocol

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


class SophosFirewallClient:
    """
    Adapter for Sophos Firewall API.
    
    Wraps the sophosfirewall_python library and translates between
    the domain layer and the external API.
    """
    
    # Status code mappings
    STATUS_SUCCESS = "200"
    STATUS_ALREADY_EXISTS = "501"
    STATUS_AUTH_FAILED = "534"
    
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
        # Handle different response structures
        if "Response" in response:
            api_response = response.get("Response", {})
        else:
            api_response = response
        
        # Get status detail
        status_detail = api_response.get("Status", {})
        
        # Extract code and message with multiple fallbacks
        code = status_detail.get("@code") or status_detail.get("code") or "unknown"
        message = status_detail.get("#text") or status_detail.get("text") or status_detail.get("message") or ""
        
        # Debug: Print raw response if code is unknown
        if code == "unknown":
            print(f"[yellow]Debug - Raw response for {record.value}: {response}[/yellow]")
        
        # Provide default messages if empty
        if not message or message == "No message":
            if code == "200":
                message = "Created successfully"
            elif code == "501":
                message = "Already exists"
            elif code == "502":
                # Check the full response for context
                full_response_str = str(response).lower()
                if "already exists" in full_response_str or "same name" in full_response_str:
                    message = "Already exists"
                else:
                    message = "Operation failed"
            elif code == "503":
                message = "Invalid value"
            elif code == "504":
                message = "Missing parameter"
            elif code == "534":
                message = "Authentication failed"
            elif code == "unknown":
                message = "Unknown response format - check debug output"
            else:
                message = f"Operation completed with status {code}"
        
        # Map status code to operation status
        if code == "200":
            status = OperationStatus.SUCCESS
        elif code == "501":
            status = OperationStatus.ALREADY_EXISTS
        elif code == "502":
            # Check if it's really "already exists"
            if "already exists" in message.lower() or "same name" in message.lower():
                status = OperationStatus.ALREADY_EXISTS
                message = "Already exists"
            else:
                status = OperationStatus.FAILED
        elif code == "unknown":
            status = OperationStatus.FAILED
        else:
            status = OperationStatus.FAILED
        
        return OperationResult(
            record=record,
            status=status,
            status_code=code,
            message=message,
        )
    
    def _execute_operation(
        self,
        operation_func,
        record: NetworkRecord,
        *args,
        **kwargs
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
            
            # Handle IP restriction specifically - this should stop execution
            if "not allowed from the requester IP" in error_msg:
                raise FirewallIPRestrictionException(error_msg)
            
            # Try to parse error as response (it might be a dict)
            try:
                if isinstance(e.args[0], dict):
                    return self._parse_response(e.args[0], record)
                elif isinstance(e.args[0], str):
                    # Try to parse as dict if it's a string representation
                    import ast
                    try:
                        error_dict = ast.literal_eval(error_msg)
                        if isinstance(error_dict, dict):
                            return self._parse_response(error_dict, record)
                    except:
                        pass
            except Exception:
                pass
            
            # If we can't parse it, check for common error patterns
            if "already exists" in error_msg.lower() or "same name" in error_msg.lower():
                return OperationResult(
                    record=record,
                    status=OperationStatus.ALREADY_EXISTS,
                    status_code="501",
                    message="Already exists",
                )
            
            # For any other error, return as failed operation (don't raise)
            return OperationResult(
                record=record,
                status=OperationStatus.FAILED,
                status_code="500",
                message=error_msg if error_msg else "Operation failed",
            )
    
    def create_fqdn_group(self, name: str) -> None:
        """
        Create FQDN host group.
        
        Args:
            name: Group name
            
        Raises:
            FirewallOperationException: On operation failure (with details)
        """
        try:
            self._client.create_fqdn_hostgroup(name)
        except SophosFirewallAPIError as e:
            error_msg = str(e.args[0]) if e.args else str(e)
            
            # Check if it's a dict response with status code 502 (already exists)
            if isinstance(e.args[0], dict):
                status = e.args[0].get("Status", {})
                code = status.get("@code", "")
                text = status.get("#text", "")
                if code == "502" and "already exists" in text.lower():
                    raise ResourceAlreadyExistsException(f"Group '{name}' already exists")
            
            if "already exists" in error_msg.lower():
                raise ResourceAlreadyExistsException(f"Group '{name}' already exists")
            
            raise FirewallOperationException(error_msg)
    
    def create_ip_group(self, name: str) -> None:
        """
        Create IP host group.
        
        Args:
            name: Group name
            
        Raises:
            FirewallOperationException: On operation failure (with details)
        """
        try:
            self._client.create_ip_hostgroup(name, host_list=[])
        except SophosFirewallAPIError as e:
            error_msg = str(e.args[0]) if e.args else str(e)
            
            # Check if it's a dict response with status code 502 (already exists)
            if isinstance(e.args[0], dict):
                status = e.args[0].get("Status", {})
                code = status.get("@code", "")
                text = status.get("#text", "")
                if code == "502" and "already exists" in text.lower():
                    raise ResourceAlreadyExistsException(f"Group '{name}' already exists")
            
            if "already exists" in error_msg.lower():
                raise ResourceAlreadyExistsException(f"Group '{name}' already exists")
            
            raise FirewallOperationException(error_msg)
    
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