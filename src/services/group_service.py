"""Service for managing host groups."""

from dataclasses import dataclass

from src.domain.entities import RecordType
from src.domain.exceptions import FirewallOperationException, ResourceAlreadyExistsException
from src.infrastructure.firewall_client import FirewallClient


@dataclass
class GroupConfiguration:
    """Configuration for host groups."""
    
    base_name: str
    
    @property
    def fqdn_group_name(self) -> str:
        """Get FQDN group name."""
        return f"{self.base_name}_FQDNHostGroup"
    
    @property
    def ip_group_name(self) -> str:
        """Get IP group name."""
        return f"{self.base_name}_IPHostGroup"


class HostGroupService:
    """
    Service for host group operations.
    
    Handles creation and management of FQDN and IP host groups.
    """
    
    def __init__(self, firewall_client: FirewallClient, config: GroupConfiguration):
        """
        Initialize service.
        
        Args:
            firewall_client: Client for firewall operations
            config: Group configuration
        """
        self._client = firewall_client
        self._config = config
    
    @property
    def fqdn_group(self) -> str:
        """Get FQDN group name."""
        return self._config.fqdn_group_name
    
    @property
    def ip_group(self) -> str:
        """Get IP group name."""
        return self._config.ip_group_name
    
    def create_groups(self) -> dict[str, bool]:
        """
        Create both FQDN and IP host groups.
        
        Returns:
            Dictionary with group names and creation status
        """
        results = {}
        
        # Create FQDN group
        try:
            self._client.create_fqdn_group(self.fqdn_group)
            results[self.fqdn_group] = True
        except ResourceAlreadyExistsException:
            results[self.fqdn_group] = False
        except FirewallOperationException as e:
            # Check if it's an "already exists" error from the error message
            error_msg = str(e).lower()
            if "already exists" in error_msg or "same name" in error_msg:
                results[self.fqdn_group] = False
            else:
                raise  # Re-raise if it's a different error
        
        # Create IP group
        try:
            self._client.create_ip_group(self.ip_group)
            results[self.ip_group] = True
        except ResourceAlreadyExistsException:
            results[self.ip_group] = False
        except FirewallOperationException as e:
            # Check if it's an "already exists" error from the error message
            error_msg = str(e).lower()
            if "already exists" in error_msg or "same name" in error_msg:
                results[self.ip_group] = False
            else:
                raise  # Re-raise if it's a different error
        
        return results
    
    def get_group_for_record_type(self, record_type: RecordType) -> str:
        """
        Get appropriate group name for a record type.
        
        Args:
            record_type: Type of network record
            
        Returns:
            Group name
            
        Raises:
            ValueError: If record type doesn't map to a group
        """
        if record_type == RecordType.FQDN:
            return self.fqdn_group
        
        if record_type in (RecordType.IP_ADDRESS, RecordType.NETWORK_CIDR):
            return self.ip_group
        
        raise ValueError(f"No group mapping for record type: {record_type}")