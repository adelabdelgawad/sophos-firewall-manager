//! Application workflow, shared by the CLI and the Tauri UI.
//!
//! `run_workflow` performs the same steps as the Python `Application.run()`,
//! but instead of printing it emits `WorkflowEvent`s through a callback. Each
//! front-end translates those events to its own output (terminal or UI).

use crate::domain::entities::{OperationResult, ProcessingSummary};
use crate::domain::errors::Result;
use crate::domain::validators;
use crate::infra::firewall_client::SophosFirewallClient;
use crate::services::cache_service::{ExistingRecordsCache, GroupMembershipCache};
use crate::services::group_service::{GroupConfiguration, HostGroupService};
use crate::services::record_service::RecordProcessingService;

/// Connection and run parameters supplied by a front-end.
pub struct WorkflowConfig {
    pub hostname: String,
    pub username: String,
    pub password: String,
    pub port: u16,
    pub verify_ssl: bool,
    pub base_name: String,
    pub update_mode: bool,
}

/// Severity of a status message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Info,
    Success,
    Warning,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Info => "info",
            LogLevel::Success => "success",
            LogLevel::Warning => "warning",
        }
    }
}

/// An observable step in the workflow.
pub enum WorkflowEvent {
    /// A human-readable status line.
    Log { level: LogLevel, message: String },
    /// The outcome of processing one record.
    Record(OperationResult),
    /// The final processing summary.
    Summary(ProcessingSummary),
}

/// Run the full host-group workflow against the firewall.
///
/// `lines` are the raw records (already read from a file or text box).
/// `on_event` receives every status update, per-record result, and the summary.
pub fn run_workflow(
    config: &WorkflowConfig,
    lines: Vec<String>,
    on_event: &mut dyn FnMut(WorkflowEvent),
) -> Result<()> {
    let client = SophosFirewallClient::new(
        &config.hostname,
        &config.username,
        &config.password,
        config.port,
        config.verify_ssl,
    )?;
    let group_service =
        HostGroupService::new(&client, GroupConfiguration::new(config.base_name.clone()));
    let record_service = RecordProcessingService::new(&client, &group_service);

    // Step 1: classify records.
    on_event(WorkflowEvent::Log {
        level: LogLevel::Info,
        message: "Classifying records...".to_string(),
    });
    let records = validators::classify_batch(&lines);
    let valid_count = records.iter().filter(|r| r.is_valid()).count();
    let invalid_count = records.len() - valid_count;
    on_event(WorkflowEvent::Log {
        level: LogLevel::Success,
        message: format!("Valid: {valid_count}, Invalid: {invalid_count}"),
    });

    // Step 2: create host groups.
    on_event(WorkflowEvent::Log {
        level: LogLevel::Info,
        message: "Creating host groups...".to_string(),
    });
    for (group_name, created) in group_service.create_groups()? {
        let (level, message) = if created {
            (LogLevel::Success, format!("Created group: {group_name}"))
        } else {
            (
                LogLevel::Warning,
                format!("Group already exists: {group_name}"),
            )
        };
        on_event(WorkflowEvent::Log { level, message });
    }

    // Step 3: fetch existing records for de-duplication.
    on_event(WorkflowEvent::Log {
        level: LogLevel::Info,
        message: "Checking existing records...".to_string(),
    });
    let mut existing_cache = ExistingRecordsCache::new();
    existing_cache.load(&client);
    let (fqdns, ip_hosts, networks, total) = existing_cache.stats();
    on_event(WorkflowEvent::Log {
        level: LogLevel::Success,
        message: format!(
            "Found {total} existing records (FQDNs: {fqdns}, IPs: {ip_hosts}, Networks: {networks})"
        ),
    });

    let mut existing_records = Vec::new();
    let mut new_records = Vec::new();
    for record in &records {
        if record.is_valid() && existing_cache.exists(record) {
            existing_records.push(record.clone());
        } else {
            new_records.push(record.clone());
        }
    }

    let mut records_to_update = Vec::new();
    let mut skipped_existing: u64 = 0;

    if config.update_mode && !existing_records.is_empty() {
        on_event(WorkflowEvent::Log {
            level: LogLevel::Info,
            message: "Loading group membership...".to_string(),
        });
        let mut membership = GroupMembershipCache::new();
        membership.load(&client, group_service.fqdn_group(), group_service.ip_group());
        let (fqdn_members, ip_members) = membership.stats();
        on_event(WorkflowEvent::Log {
            level: LogLevel::Success,
            message: format!("Group has {fqdn_members} FQDNs, {ip_members} IPs"),
        });

        records_to_update = existing_records
            .iter()
            .filter(|r| !membership.is_member(r))
            .cloned()
            .collect();
        let already_in_group = existing_records.len() - records_to_update.len();
        if already_in_group > 0 {
            on_event(WorkflowEvent::Log {
                level: LogLevel::Warning,
                message: format!("Skipping {already_in_group} records already in group"),
            });
        }
        if !records_to_update.is_empty() {
            on_event(WorkflowEvent::Log {
                level: LogLevel::Info,
                message: format!(
                    "Will update {} existing records to add to group",
                    records_to_update.len()
                ),
            });
        }
    } else {
        skipped_existing = existing_records.len() as u64;
        if skipped_existing > 0 {
            on_event(WorkflowEvent::Log {
                level: LogLevel::Warning,
                message: format!("Skipping {skipped_existing} records that already exist"),
            });
        }
    }

    // Step 4: process records.
    if new_records.len() + records_to_update.len() == 0 {
        let mut message = String::from("All records already exist");
        if config.update_mode {
            message.push_str(" and are in the target groups");
        }
        message.push_str(" - nothing to do!");
        on_event(WorkflowEvent::Log {
            level: LogLevel::Success,
            message,
        });
        on_event(WorkflowEvent::Summary(ProcessingSummary::new()));
        return Ok(());
    }

    let mut summary = ProcessingSummary::new();

    if !new_records.is_empty() {
        let valid_new = new_records.iter().filter(|r| r.is_valid()).count();
        on_event(WorkflowEvent::Log {
            level: LogLevel::Info,
            message: format!("Creating {valid_new} new records..."),
        });
        let batch = record_service.process_batch(&new_records, |result| {
            on_event(WorkflowEvent::Record(result.clone()));
        })?;
        summary.total += batch.total;
        summary.successful += batch.successful;
        summary.updated += batch.updated;
        summary.already_exists += batch.already_exists;
        summary.failed += batch.failed;
        summary.skipped += batch.skipped;
    }

    if !records_to_update.is_empty() {
        on_event(WorkflowEvent::Log {
            level: LogLevel::Info,
            message: format!("Updating {} existing records...", records_to_update.len()),
        });
        for record in &records_to_update {
            let result = record_service.update_existing_record(record);
            summary.record_result(&result);
            on_event(WorkflowEvent::Record(result));
        }
    }

    summary.already_exists += skipped_existing;
    summary.total += skipped_existing;

    on_event(WorkflowEvent::Summary(summary));
    Ok(())
}
