"""Domain validation logic for network records."""

import re
from functools import lru_cache
from typing import Final, Protocol

from pydantic import BaseModel, IPvAnyAddress, IPvAnyNetwork, ValidationError

from .entities import NetworkRecord, RecordType


class Validator(Protocol):
    """Protocol for validators."""
    
    def is_valid(self, value: str) -> bool:
        """Check if value is valid."""
        ...


class FQDNValidator:
    """
    Validates Fully Qualified Domain Names per RFC 1035 and RFC 3696.
    
    Uses caching for improved performance on repeated validations.
    """
    
    MAX_LENGTH: Final[int] = 253
    MIN_LABELS: Final[int] = 2
    
    _PATTERN: Final[re.Pattern] = re.compile(
        r"^((?![-])[-A-Z\d]{1,63}(?<!-)[.])*(?!-)[-A-Z\d]{1,63}(?<!-)[.]?$",
        re.IGNORECASE
    )
    
    @classmethod
    @lru_cache(maxsize=1024)
    def is_valid(cls, fqdn: str) -> bool:
        """
        Validate FQDN with caching.
        
        Args:
            fqdn: Domain name to validate
            
        Returns:
            True if valid FQDN
        """
        if not isinstance(fqdn, str) or not fqdn:
            return False
        
        # Handle wildcard domains
        normalized = fqdn.removeprefix("*.").lower()
        
        # Check length
        if len(normalized.rstrip(".")) > cls.MAX_LENGTH:
            return False
        
        # Check pattern
        if not cls._PATTERN.match(normalized):
            return False
        
        # Check minimum labels
        label_count = normalized.rstrip(".").count(".") + 1
        return label_count >= cls.MIN_LABELS


class IPAddressValidator:
    """Validates IPv4 and IPv6 addresses using Pydantic."""
    
    @staticmethod
    @lru_cache(maxsize=1024)
    def is_valid(ip: str) -> bool:
        """
        Validate IP address with caching.
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid IPv4 or IPv6
        """
        if not isinstance(ip, str) or not ip:
            return False
        
        class _IPModel(BaseModel):
            address: IPvAnyAddress
        
        try:
            _IPModel(address=ip)
            return True
        except ValidationError:
            return False


class NetworkCIDRValidator:
    """Validates network addresses in CIDR notation."""
    
    @staticmethod
    @lru_cache(maxsize=1024)
    def is_valid(network: str) -> bool:
        """
        Validate network CIDR with caching.
        
        Args:
            network: Network in CIDR notation
            
        Returns:
            True if valid CIDR
        """
        if not isinstance(network, str) or "/" not in network:
            return False
        
        class _NetworkModel(BaseModel):
            network: IPvAnyNetwork
        
        try:
            _NetworkModel(network=network)
            return True
        except ValidationError:
            return False


class RecordClassifier:
    """
    Classifies network records into their appropriate types.
    
    Uses the strategy pattern with multiple validators.
    """
    
    def __init__(self):
        """Initialize classifier with validators."""
        self._validators = [
            (NetworkCIDRValidator, RecordType.NETWORK_CIDR),
            (IPAddressValidator, RecordType.IP_ADDRESS),
            (FQDNValidator, RecordType.FQDN),
        ]
    
    def classify(self, value: str) -> NetworkRecord:
        """
        Classify a network record string.
        
        Args:
            value: Raw network record string
            
        Returns:
            NetworkRecord with determined type
        """
        value = value.strip()
        
        for validator, record_type in self._validators:
            if validator.is_valid(value):
                return NetworkRecord(value=value, record_type=record_type)
        
        return NetworkRecord(value=value, record_type=RecordType.INVALID)
    
    def classify_batch(self, values: list[str]) -> list[NetworkRecord]:
        """
        Classify multiple records.
        
        Args:
            values: List of raw record strings
            
        Returns:
            List of classified NetworkRecords
        """
        return [self.classify(value) for value in values]


# Convenience functions for backward compatibility
def is_valid_fqdn(fqdn: str) -> bool:
    """Check if string is a valid FQDN."""
    return FQDNValidator.is_valid(fqdn)


def is_valid_ip_address(ip: str) -> bool:
    """Check if string is a valid IP address."""
    return IPAddressValidator.is_valid(ip)


def is_valid_network_cidr(network: str) -> bool:
    """Check if string is valid network CIDR."""
    return NetworkCIDRValidator.is_valid(network)