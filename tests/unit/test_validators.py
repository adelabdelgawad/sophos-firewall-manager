"""Unit tests for validators."""

import pytest

from src.domain.entities import RecordType
from src.domain.validators import (
    FQDNValidator,
    IPAddressValidator,
    NetworkCIDRValidator,
    RecordClassifier,
)


class TestFQDNValidator:
    """Tests for FQDN validation."""
    
    @pytest.mark.parametrize("fqdn", [
        "example.com",
        "subdomain.example.com",
        "deep.subdomain.example.com",
        "*.example.com",  # Wildcard
        "example.com.",  # Absolute
        "test-domain.com",
        "123.example.com",
    ])
    def test_valid_fqdns(self, fqdn):
        """Test valid FQDNs."""
        assert FQDNValidator.is_valid(fqdn) is True
    
    @pytest.mark.parametrize("fqdn", [
        "example",  # Single label
        "-example.com",  # Leading hyphen
        "example-.com",  # Trailing hyphen
        "exam ple.com",  # Space
        "",  # Empty
        "a" * 64 + ".com",  # Label too long
        "a" * 254,  # Domain too long
        "example..com",  # Empty label
    ])
    def test_invalid_fqdns(self, fqdn):
        """Test invalid FQDNs."""
        assert FQDNValidator.is_valid(fqdn) is False


class TestIPAddressValidator:
    """Tests for IP address validation."""
    
    @pytest.mark.parametrize("ip", [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "255.255.255.255",
        "0.0.0.0",
        # IPv6
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::1",
        "::1",
        "fe80::1",
    ])
    def test_valid_ip_addresses(self, ip):
        """Test valid IP addresses."""
        assert IPAddressValidator.is_valid(ip) is True
    
    @pytest.mark.parametrize("ip", [
        "256.1.1.1",  # Out of range
        "192.168.1",  # Incomplete
        "192.168.1.1.1",  # Too many octets
        "abc.def.ghi.jkl",  # Non-numeric
        "",  # Empty
        "192.168.1.1/24",  # CIDR notation
    ])
    def test_invalid_ip_addresses(self, ip):
        """Test invalid IP addresses."""
        assert IPAddressValidator.is_valid(ip) is False


class TestNetworkCIDRValidator:
    """Tests for network CIDR validation."""
    
    @pytest.mark.parametrize("network", [
        "192.168.1.0/24",
        "10.0.0.0/8",
        "172.16.0.0/16",
        "192.168.1.128/25",
        "0.0.0.0/0",
        # IPv6
        "2001:db8::/32",
        "fe80::/10",
        "::1/128",
    ])
    def test_valid_networks(self, network):
        """Test valid network CIDRs."""
        assert NetworkCIDRValidator.is_valid(network) is True
    
    @pytest.mark.parametrize("network", [
        "192.168.1.0",  # No CIDR
        "192.168.1.0/",  # Missing prefix
        "192.168.1.0/33",  # Invalid prefix
        "256.1.1.0/24",  # Invalid IP
        "",  # Empty
        "192.168.1.0/abc",  # Non-numeric prefix
    ])
    def test_invalid_networks(self, network):
        """Test invalid network CIDRs."""
        assert NetworkCIDRValidator.is_valid(network) is False


class TestRecordClassifier:
    """Tests for record classification."""
    
    def test_classify_fqdn(self):
        """Test FQDN classification."""
        classifier = RecordClassifier()
        record = classifier.classify("example.com")
        
        assert record.value == "example.com"
        assert record.record_type == RecordType.FQDN
        assert record.is_valid is True
        assert record.is_fqdn is True
    
    def test_classify_ip_address(self):
        """Test IP address classification."""
        classifier = RecordClassifier()
        record = classifier.classify("192.168.1.1")
        
        assert record.value == "192.168.1.1"
        assert record.record_type == RecordType.IP_ADDRESS
        assert record.is_valid is True
        assert record.is_ip_address is True
    
    def test_classify_network(self):
        """Test network CIDR classification."""
        classifier = RecordClassifier()
        record = classifier.classify("192.168.1.0/24")
        
        assert record.value == "192.168.1.0/24"
        assert record.record_type == RecordType.NETWORK_CIDR
        assert record.is_valid is True
        assert record.is_network is True
    
    def test_classify_invalid(self):
        """Test invalid record classification."""
        classifier = RecordClassifier()
        record = classifier.classify("invalid-record")
        
        assert record.value == "invalid-record"
        assert record.record_type == RecordType.INVALID
        assert record.is_valid is False
    
    def test_classify_batch(self):
        """Test batch classification."""
        classifier = RecordClassifier()
        records = classifier.classify_batch([
            "example.com",
            "192.168.1.1",
            "10.0.0.0/8",
            "invalid",
        ])
        
        assert len(records) == 4
        assert records[0].record_type == RecordType.FQDN
        assert records[1].record_type == RecordType.IP_ADDRESS
        assert records[2].record_type == RecordType.NETWORK_CIDR
        assert records[3].record_type == RecordType.INVALID
    
    def test_priority_order(self):
        """Test that CIDR is checked before IP address."""
        classifier = RecordClassifier()
        
        # This should be classified as CIDR, not IP
        record = classifier.classify("192.168.1.0/32")
        assert record.record_type == RecordType.NETWORK_CIDR