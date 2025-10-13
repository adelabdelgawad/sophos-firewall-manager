"""Configuration management using Pydantic settings."""

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class FirewallSettings(BaseSettings):
    """Sophos Firewall connection settings."""
    
    model_config = SettingsConfigDict(
        env_prefix="FIREWALL_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # Ignore extra fields
    )
    
    hostname: str = Field(..., description="Firewall hostname or IP address")
    username: str = Field(..., description="API username")
    password: str = Field(..., description="API password")
    port: int = Field(default=4444, description="API port")
    verify_ssl: bool = Field(default=False, description="Verify SSL certificates")


class ApplicationSettings(BaseSettings):
    """Application-level settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Ignore extra fields
    )
    
    # Application settings
    file_encoding: str = Field(default="utf-8", description="Input file encoding")
    progress_enabled: bool = Field(default=True, description="Show progress bar")
    verbose: bool = Field(default=False, description="Verbose output")


@lru_cache
def get_settings() -> tuple[ApplicationSettings, FirewallSettings]:
    """
    Get application and firewall settings.
    
    Returns:
        Tuple of (ApplicationSettings, FirewallSettings)
    """
    return ApplicationSettings(), FirewallSettings()