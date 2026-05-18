//! Domain error types. Ports `src/domain/exceptions.py`.
//!
//! The Python code uses an exception hierarchy; the CLI maps specific
//! exception types to exit codes. This enum keeps the same distinctions.

use std::fmt;

/// All errors that can surface to the CLI.
#[derive(Debug, Clone)]
pub enum AppError {
    /// Domain validation failure (`ValidationException`).
    Validation(String),
    /// Could not connect to the firewall (`FirewallConnectionException`).
    FirewallConnection(String),
    /// Authentication to the firewall failed (`FirewallAuthenticationException`).
    FirewallAuthentication(String),
    /// Requester IP is not allowed (`FirewallIPRestrictionException`).
    FirewallIpRestriction(String),
    /// A firewall operation failed (`FirewallOperationException`).
    FirewallOperation {
        message: String,
        status_code: Option<String>,
    },
    /// A resource already exists (`ResourceAlreadyExistsException`).
    ResourceAlreadyExists(String),
    /// File read/validation failure (`FileOperationException`).
    File(String),
    /// Invalid configuration (`ConfigurationException`).
    Configuration(String),
}

impl AppError {
    /// Process exit code, matching the `Application.run()` handlers.
    pub fn exit_code(&self) -> i32 {
        match self {
            AppError::File(_) => 1,
            AppError::FirewallIpRestriction(_) => 2,
            AppError::FirewallConnection(_)
            | AppError::FirewallAuthentication(_)
            | AppError::FirewallOperation { .. }
            | AppError::ResourceAlreadyExists(_) => 3,
            AppError::Configuration(_) => 4,
            AppError::Validation(_) => 1,
        }
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::Validation(m)
            | AppError::FirewallConnection(m)
            | AppError::FirewallAuthentication(m)
            | AppError::FirewallIpRestriction(m)
            | AppError::ResourceAlreadyExists(m)
            | AppError::File(m)
            | AppError::Configuration(m) => write!(f, "{m}"),
            AppError::FirewallOperation { message, .. } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for AppError {}

/// Convenient result alias used across the crate.
pub type Result<T> = std::result::Result<T, AppError>;
