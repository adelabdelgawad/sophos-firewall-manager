"""Unit tests for domain entities."""

import pytest

from src.domain.entities import (
    NetworkRecord,
    OperationResult,
    OperationStatus,
    ProcessingSummary,
    RecordType,
)


class TestNetworkRecord:
    """Tests for NetworkRecord entity."""
    
    def test_fqdn_record(self):
        """Test FQDN record creation."""
        record = NetworkRecord(value="example.com", record_type=RecordType.FQDN)
        
        assert record.value == "example.com"
        assert record.record_type == RecordType.FQDN
        assert record.is_valid is True
        assert record.is_fqdn is True
        assert record.is_ip_address is False
        assert record.is_network is False
    
    def test_ip_record(self):
        """Test IP address record creation."""
        record = NetworkRecord(value="192.168.1.1", record_type=RecordType.IP_ADDRESS)
        
        assert record.is_valid is True
        assert record.is_ip_address is True
        assert record.is_fqdn is False
    
    def test_network_record(self):
        """Test network CIDR record creation."""
        record = NetworkRecord(value="10.0.0.0/8", record_type=RecordType.NETWORK_CIDR)
        
        assert record.is_valid is True
        assert record.is_network is True
        assert record.is_ip_address is False
    
    def test_invalid_record(self):
        """Test invalid record."""
        record = NetworkRecord(value="invalid", record_type=RecordType.INVALID)
        
        assert record.is_valid is False
        assert record.is_fqdn is False
        assert record.is_ip_address is False
        assert record.is_network is False
    
    def test_immutability(self):
        """Test that NetworkRecord is immutable."""
        record = NetworkRecord(value="example.com", record_type=RecordType.FQDN)
        
        with pytest.raises(AttributeError):
            record.value = "new.com"  # type: ignore


class TestOperationResult:
    """Tests for OperationResult entity."""
    
    def test_successful_result(self):
        """Test successful operation result."""
        record = NetworkRecord(value="example.com", record_type=RecordType.FQDN)
        result = OperationResult(
            record=record,
            status=OperationStatus.SUCCESS,
            status_code="200",
            message="Created successfully"
        )
        
        assert result.succeeded is True
        assert result.failed is False
        assert result.status == OperationStatus.SUCCESS
    
    def test_failed_result(self):
        """Test failed operation result."""
        record = NetworkRecord(value="example.com", record_type=RecordType.FQDN)
        result = OperationResult(
            record=record,
            status=OperationStatus.FAILED,
            status_code="500",
            message="Operation failed"
        )
        
        assert result.succeeded is False
        assert result.failed is True
        assert result.status == OperationStatus.FAILED


class TestProcessingSummary:
    """Tests for ProcessingSummary entity."""
    
    def test_initial_summary(self):
        """Test initial summary state."""
        summary = ProcessingSummary()
        
        assert summary.total == 0
        assert summary.successful == 0
        assert summary.already_exists == 0
        assert summary.failed == 0
        assert summary.skipped == 0
        assert summary.success_rate == 0.0
    
    def test_record_success(self):
        """Test recording successful operation."""
        summary = ProcessingSummary()
        record = NetworkRecord(value="example.com", record_type=RecordType.FQDN)
        result = OperationResult(
            record=record,
            status=OperationStatus.SUCCESS,
            status_code="200",
            message="Created"
        )
        
        summary.record_result(result)
        
        assert summary.total == 1
        assert summary.successful == 1
        assert summary.success_rate == 100.0
    
    def test_record_already_exists(self):
        """Test recording already exists status."""
        summary = ProcessingSummary()
        record = NetworkRecord(value="example.com", record_type=RecordType.FQDN)
        result = OperationResult(
            record=record,
            status=OperationStatus.ALREADY_EXISTS,
            status_code="501",
            message="Already exists"
        )
        
        summary.record_result(result)
        
        assert summary.total == 1
        assert summary.already_exists == 1
        assert summary.success_rate == 0.0
    
    def test_record_failed(self):
        """Test recording failed operation."""
        summary = ProcessingSummary()
        record = NetworkRecord(value="example.com", record_type=RecordType.FQDN)
        result = OperationResult(
            record=record,
            status=OperationStatus.FAILED,
            status_code="500",
            message="Failed"
        )
        
        summary.record_result(result)
        
        assert summary.total == 1
        assert summary.failed == 1
        assert summary.success_rate == 0.0
    
    def test_record_skipped(self):
        """Test recording skipped operation."""
        summary = ProcessingSummary()
        record = NetworkRecord(value="invalid", record_type=RecordType.INVALID)
        result = OperationResult(
            record=record,
            status=OperationStatus.SKIPPED,
            status_code="000",
            message="Skipped"
        )
        
        summary.record_result(result)
        
        assert summary.total == 1
        assert summary.skipped == 1
        assert summary.success_rate == 0.0
    
    def test_mixed_results(self):
        """Test recording multiple operations."""
        summary = ProcessingSummary()
        record = NetworkRecord(value="example.com", record_type=RecordType.FQDN)
        
        # 3 successful
        for _ in range(3):
            result = OperationResult(
                record=record,
                status=OperationStatus.SUCCESS,
                status_code="200",
                message="Created"
            )
            summary.record_result(result)
        
        # 1 failed
        result = OperationResult(
            record=record,
            status=OperationStatus.FAILED,
            status_code="500",
            message="Failed"
        )
        summary.record_result(result)
        
        # 1 skipped
        result = OperationResult(
            record=record,
            status=OperationStatus.SKIPPED,
            status_code="000",
            message="Skipped"
        )
        summary.record_result(result)
        
        assert summary.total == 5
        assert summary.successful == 3
        assert summary.failed == 1
        assert summary.skipped == 1
        assert summary.success_rate == 60.0