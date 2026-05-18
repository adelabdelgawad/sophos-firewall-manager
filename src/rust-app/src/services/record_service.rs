//! Record processing service. Ports `src/services/record_service.py`.

use crate::domain::entities::{
    NetworkRecord, OperationResult, OperationStatus, ProcessingSummary, RecordType,
};
use crate::domain::errors::Result;
use crate::infra::firewall_client::FirewallApi;

use super::group_service::HostGroupService;

/// Orchestrates creation of firewall entries from network records.
pub struct RecordProcessingService<'a> {
    client: &'a dyn FirewallApi,
    group_service: &'a HostGroupService<'a>,
}

impl<'a> RecordProcessingService<'a> {
    pub fn new(client: &'a dyn FirewallApi, group_service: &'a HostGroupService<'a>) -> Self {
        Self {
            client,
            group_service,
        }
    }

    /// Add an already-existing record to its target group.
    pub fn update_existing_record(&self, record: &NetworkRecord) -> OperationResult {
        if !record.is_valid() {
            return OperationResult::new(
                record.clone(),
                OperationStatus::Skipped,
                "000",
                "Invalid record format",
            );
        }

        let group = match self.group_service.group_for_record_type(record.record_type) {
            Ok(group) => group.to_string(),
            Err(e) => {
                return OperationResult::new(
                    record.clone(),
                    OperationStatus::Failed,
                    "000",
                    e.to_string(),
                )
            }
        };

        if self.add_to_group(record, &group) {
            OperationResult::new(
                record.clone(),
                OperationStatus::Updated,
                "200",
                format!("Added to group {group}"),
            )
        } else {
            OperationResult::new(
                record.clone(),
                OperationStatus::Failed,
                "500",
                format!("Failed to add to group {group}"),
            )
        }
    }

    /// Process a single record: create the firewall entry, then add it to its
    /// group. Returns `Err` only for a fatal IP access restriction.
    pub fn process_record(&self, record: &NetworkRecord) -> Result<OperationResult> {
        if !record.is_valid() {
            return Ok(OperationResult::new(
                record.clone(),
                OperationStatus::Skipped,
                "000",
                "Invalid record format",
            ));
        }

        let group = match self.group_service.group_for_record_type(record.record_type) {
            Ok(group) => group.to_string(),
            Err(e) => {
                return Ok(OperationResult::new(
                    record.clone(),
                    OperationStatus::Failed,
                    "000",
                    e.to_string(),
                ))
            }
        };

        let result = match record.record_type {
            RecordType::Fqdn => self.client.create_fqdn_host(record, &group)?,
            RecordType::IpAddress => self.client.create_ip_host(record, &group)?,
            RecordType::NetworkCidr => self.client.create_network(record, &group)?,
            RecordType::Invalid => OperationResult::new(
                record.clone(),
                OperationStatus::Failed,
                "000",
                "Unknown record type",
            ),
        };

        // On success, also register the host in its group (failures ignored).
        if result.succeeded() {
            self.add_to_group(record, &group);
        }

        Ok(result)
    }

    /// Add a record's host name to its group.
    fn add_to_group(&self, record: &NetworkRecord, group: &str) -> bool {
        let host = vec![record.value.clone()];
        match record.record_type {
            RecordType::Fqdn => self.client.add_to_fqdn_group(group, &host),
            RecordType::IpAddress | RecordType::NetworkCidr => {
                self.client.add_to_ip_group(group, &host)
            }
            RecordType::Invalid => false,
        }
    }

    /// Process many records, invoking `callback` after each result.
    pub fn process_batch(
        &self,
        records: &[NetworkRecord],
        mut callback: impl FnMut(&OperationResult),
    ) -> Result<ProcessingSummary> {
        let mut summary = ProcessingSummary::new();
        for record in records {
            let result = self.process_record(record)?;
            summary.record_result(&result);
            callback(&result);
        }
        Ok(summary)
    }
}
