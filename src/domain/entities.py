"""Core domain entities representing business concepts."""

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class RecordType(Enum):
    """Types of network records that can be processed."""
    
    FQDN = "fqdn"
    IP_ADDRESS = "ip_address"
    NETWORK_CIDR = "network_cidr"
    INVALID = "invalid"


class OperationStatus(Enum):
    """Status of firewall operations."""
    
    SUCCESS = "success"
    ALREADY_EXISTS = "already_exists"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class NetworkRecord:
    """
    Represents a single network record from input.
    
    Immutable value object that encapsulates a network record
    and its validated type.
    """
    
    value: str
    record_type: RecordType
    
    @property
    def is_valid(self) -> bool:
        """Check if the record is valid."""
        return self.record_type != RecordType.INVALID
    
    @property
    def is_fqdn(self) -> bool:
        """Check if record is an FQDN."""
        return self.record_type == RecordType.FQDN
    
    @property
    def is_ip_address(self) -> bool:
        """Check if record is an IP address."""
        return self.record_type == RecordType.IP_ADDRESS
    
    @property
    def is_network(self) -> bool:
        """Check if record is a network in CIDR notation."""
        return self.record_type == RecordType.NETWORK_CIDR


@dataclass
class HostGroup:
    """Represents a firewall host group."""
    
    name: str
    group_type: RecordType  # FQDN or IP
    
    def __post_init__(self):
        """Validate group type."""
        if self.group_type not in (RecordType.FQDN, RecordType.IP_ADDRESS):
            raise ValueError(f"Invalid group type: {self.group_type}")


@dataclass
class OperationResult:
    """
    Result of a firewall operation.
    
    Contains all information about the operation outcome.
    """
    
    record: NetworkRecord
    status: OperationStatus
    status_code: str
    message: str
    
    @property
    def succeeded(self) -> bool:
        """Check if operation succeeded."""
        return self.status == OperationStatus.SUCCESS
    
    @property
    def failed(self) -> bool:
        """Check if operation failed."""
        return self.status == OperationStatus.FAILED


@dataclass
class ProcessingSummary:
    """
    Summary of batch record processing.
    
    Tracks statistics for the entire processing operation.
    """
    
    total: int = 0
    successful: int = 0
    already_exists: int = 0
    failed: int = 0
    skipped: int = 0
    
    def record_result(self, result: OperationResult) -> None:
        """Update summary with an operation result."""
        self.total += 1
        
        if result.status == OperationStatus.SUCCESS:
            self.successful += 1
        elif result.status == OperationStatus.ALREADY_EXISTS:
            self.already_exists += 1
        elif result.status == OperationStatus.FAILED:
            self.failed += 1
        elif result.status == OperationStatus.SKIPPED:
            self.skipped += 1
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total == 0:
            return 0.0
        return (self.successful / self.total) * 100