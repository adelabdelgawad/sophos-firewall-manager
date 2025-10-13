"""Custom exceptions for the domain layer."""


class DomainException(Exception):
    """Base exception for domain layer."""
    pass


class ValidationException(DomainException):
    """Raised when validation fails."""
    pass


class FirewallException(DomainException):
    """Base exception for firewall operations."""
    pass


class FirewallConnectionException(FirewallException):
    """Raised when cannot connect to firewall."""
    pass


class FirewallAuthenticationException(FirewallException):
    """Raised when authentication fails."""
    pass


class FirewallIPRestrictionException(FirewallException):
    """Raised when IP is not allowed to access API."""
    pass


class FirewallOperationException(FirewallException):
    """Raised when a firewall operation fails."""
    
    def __init__(self, message: str, status_code: str = None):
        super().__init__(message)
        self.status_code = status_code


class ResourceAlreadyExistsException(FirewallException):
    """Raised when trying to create a resource that already exists."""
    pass


class FileOperationException(DomainException):
    """Raised when file operations fail."""
    pass


class ConfigurationException(DomainException):
    """Raised when configuration is invalid."""
    pass