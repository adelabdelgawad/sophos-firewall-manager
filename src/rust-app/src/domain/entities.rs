//! Core domain entities. Ports `src/domain/entities.py`.

/// Types of network records that can be processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    Fqdn,
    IpAddress,
    NetworkCidr,
    Invalid,
}

impl RecordType {
    /// The lowercase string used by the Python `RecordType` enum values.
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::Fqdn => "fqdn",
            RecordType::IpAddress => "ip_address",
            RecordType::NetworkCidr => "network_cidr",
            RecordType::Invalid => "invalid",
        }
    }
}

/// Status of firewall operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    Success,
    AlreadyExists,
    Updated,
    Failed,
    Skipped,
}

impl OperationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            OperationStatus::Success => "success",
            OperationStatus::AlreadyExists => "already_exists",
            OperationStatus::Updated => "updated",
            OperationStatus::Failed => "failed",
            OperationStatus::Skipped => "skipped",
        }
    }
}

/// A single network record from input. Immutable value object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkRecord {
    pub value: String,
    pub record_type: RecordType,
}

impl NetworkRecord {
    pub fn new(value: impl Into<String>, record_type: RecordType) -> Self {
        Self {
            value: value.into(),
            record_type,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.record_type != RecordType::Invalid
    }

    pub fn is_fqdn(&self) -> bool {
        self.record_type == RecordType::Fqdn
    }

    pub fn is_ip_address(&self) -> bool {
        self.record_type == RecordType::IpAddress
    }

    pub fn is_network(&self) -> bool {
        self.record_type == RecordType::NetworkCidr
    }
}

/// Result of a firewall operation.
#[derive(Debug, Clone)]
pub struct OperationResult {
    pub record: NetworkRecord,
    pub status: OperationStatus,
    pub status_code: String,
    pub message: String,
}

impl OperationResult {
    pub fn new(
        record: NetworkRecord,
        status: OperationStatus,
        status_code: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            record,
            status,
            status_code: status_code.into(),
            message: message.into(),
        }
    }

    pub fn succeeded(&self) -> bool {
        self.status == OperationStatus::Success
    }
}

/// Summary of batch record processing.
#[derive(Debug, Clone, Default)]
pub struct ProcessingSummary {
    pub total: u64,
    pub successful: u64,
    pub updated: u64,
    pub already_exists: u64,
    pub failed: u64,
    pub skipped: u64,
}

impl ProcessingSummary {
    pub fn new() -> Self {
        Self::default()
    }

    /// Update summary with an operation result.
    pub fn record_result(&mut self, result: &OperationResult) {
        self.total += 1;
        match result.status {
            OperationStatus::Success => self.successful += 1,
            OperationStatus::Updated => self.updated += 1,
            OperationStatus::AlreadyExists => self.already_exists += 1,
            OperationStatus::Failed => self.failed += 1,
            OperationStatus::Skipped => self.skipped += 1,
        }
    }

    /// Success rate percentage. Created and updated both count as successful.
    pub fn success_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        ((self.successful + self.updated) as f64 / self.total as f64) * 100.0
    }
}
