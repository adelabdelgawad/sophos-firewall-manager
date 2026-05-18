//! Configuration loading. Ports `config/settings.py`.
//!
//! Settings come from environment variables (and an optional `.env` file).
//! Firewall settings use the `FIREWALL_` prefix.

use crate::domain::errors::{AppError, Result};

/// Sophos Firewall connection settings.
pub struct FirewallSettings {
    pub hostname: String,
    pub username: String,
    pub password: String,
    pub port: u16,
    pub verify_ssl: bool,
}

/// Application-level settings.
pub struct AppSettings {
    pub file_encoding: String,
    pub progress_enabled: bool,
    pub verbose: bool,
}

/// Load application and firewall settings, reading `.env` if present.
pub fn load_settings() -> Result<(AppSettings, FirewallSettings)> {
    // Load `.env` into the process environment if the file exists.
    let _ = dotenvy::dotenv();

    let firewall = FirewallSettings {
        hostname: required("FIREWALL_HOSTNAME")?,
        username: required("FIREWALL_USERNAME")?,
        password: required("FIREWALL_PASSWORD")?,
        port: parse_port("FIREWALL_PORT", 4444)?,
        verify_ssl: parse_bool("FIREWALL_VERIFY_SSL", false),
    };

    let app = AppSettings {
        file_encoding: optional("FILE_ENCODING").unwrap_or_else(|| "utf-8".to_string()),
        progress_enabled: parse_bool("PROGRESS_ENABLED", true),
        verbose: parse_bool("VERBOSE", false),
    };

    Ok((app, firewall))
}

/// A required setting, or a configuration error if missing/empty.
fn required(key: &str) -> Result<String> {
    match std::env::var(key) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(AppError::Configuration(format!(
            "Failed to load settings: {key} is required"
        ))),
    }
}

/// An optional non-empty setting.
fn optional(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Parse a port number, falling back to `default` when unset.
fn parse_port(key: &str, default: u16) -> Result<u16> {
    match optional(key) {
        None => Ok(default),
        Some(value) => value.parse().map_err(|_| {
            AppError::Configuration(format!(
                "Failed to load settings: {key} must be a valid port number"
            ))
        }),
    }
}

/// Parse a boolean setting leniently, falling back to `default`.
fn parse_bool(key: &str, default: bool) -> bool {
    match optional(key) {
        None => default,
        Some(value) => match value.trim().to_lowercase().as_str() {
            "true" | "1" | "yes" | "on" | "t" | "y" => true,
            "false" | "0" | "no" | "off" | "f" | "n" => false,
            _ => default,
        },
    }
}
