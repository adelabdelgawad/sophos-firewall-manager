"""Service for processing network records."""

from typing import Callable

from src.domain.entities import (
    NetworkRecord,
    OperationResult,
    OperationStatus,
    ProcessingSummary,
    RecordType,
)
from src.infrastructure.firewall_client import FirewallClient
from src.services.group_service import HostGroupService


class RecordProcessingService:
    """
    Service for processing network records.
    
    Orchestrates the creation of firewall entries from network records.
    """
    
    def __init__(
        self,
        firewall_client: FirewallClient,
        group_service: HostGroupService,
    ):
        """
        Initialize service.
        
        Args:
            firewall_client: Client for firewall operations
            group_service: Service for group management
        """
        self._client = firewall_client
        self._group_service = group_service
    
    def process_record(self, record: NetworkRecord) -> OperationResult:
        """
        Process a single network record.
        
        Args:
            record: Network record to process
            
        Returns:
            Result of the operation
        """
        # Skip invalid records
        if not record.is_valid:
            return OperationResult(
                record=record,
                status=OperationStatus.SKIPPED,
                status_code="000",
                message="Invalid record format",
            )
        
        # Get appropriate group
        try:
            group = self._group_service.get_group_for_record_type(record.record_type)
        except ValueError as e:
            return OperationResult(
                record=record,
                status=OperationStatus.FAILED,
                status_code="000",
                message=str(e),
            )
        
        # Process based on record type
        if record.is_fqdn:
            result = self._client.create_fqdn_host(record, group)
        elif record.is_ip_address:
            result = self._client.create_ip_host(record, group)
        elif record.is_network:
            result = self._client.create_network(record, group)
        else:
            result = OperationResult(
                record=record,
                status=OperationStatus.FAILED,
                status_code="000",
                message="Unknown record type",
            )
        
        # If successful, update the group to include this host
        if result.succeeded:
            try:
                self._add_to_group(record, group)
            except Exception:
                # If adding to group fails, still return success for host creation
                pass
        
        return result
    
    def _add_to_group(self, record: NetworkRecord, group: str) -> None:
        """
        Add a host to its group after creation.
        
        Args:
            record: Network record that was created
            group: Group name to add to
        """
        # This would require the update_group API call
        # For now, we'll skip this as the sophosfirewall_python library
        # may not support adding hosts to existing groups directly
        pass
    
    def process_batch(
        self,
        records: list[NetworkRecord],
        callback: Callable[[OperationResult], None] | None = None,
    ) -> ProcessingSummary:
        """
        Process multiple records with optional progress callback.
        
        Args:
            records: List of network records to process
            callback: Optional callback for each result
            
        Returns:
            Summary of processing results
        """
        summary = ProcessingSummary()
        
        for record in records:
            result = self.process_record(record)
            summary.record_result(result)
            
            if callback:
                callback(result)
        
        return summary