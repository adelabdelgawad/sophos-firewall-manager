//! Host group management service. Ports `src/services/group_service.py`.

use crate::domain::entities::RecordType;
use crate::domain::errors::{AppError, Result};
use crate::infra::firewall_client::FirewallApi;

/// Configuration for host group names.
pub struct GroupConfiguration {
    pub base_name: String,
}

impl GroupConfiguration {
    pub fn new(base_name: impl Into<String>) -> Self {
        Self {
            base_name: base_name.into(),
        }
    }

    pub fn fqdn_group_name(&self) -> String {
        format!("{}_FQDNHostGroup", self.base_name)
    }

    pub fn ip_group_name(&self) -> String {
        format!("{}_IPHostGroup", self.base_name)
    }
}

/// Service for creating and resolving FQDN and IP host groups.
pub struct HostGroupService<'a> {
    client: &'a dyn FirewallApi,
    fqdn_group: String,
    ip_group: String,
}

impl<'a> HostGroupService<'a> {
    pub fn new(client: &'a dyn FirewallApi, config: GroupConfiguration) -> Self {
        Self {
            client,
            fqdn_group: config.fqdn_group_name(),
            ip_group: config.ip_group_name(),
        }
    }

    pub fn fqdn_group(&self) -> &str {
        &self.fqdn_group
    }

    pub fn ip_group(&self) -> &str {
        &self.ip_group
    }

    /// Create both host groups. Returns `(group_name, created)` pairs in
    /// creation order (`created = false` means the group already existed).
    pub fn create_groups(&self) -> Result<Vec<(String, bool)>> {
        let fqdn =
            self.create_one(self.client.create_fqdn_group(&self.fqdn_group), &self.fqdn_group)?;
        let ip = self.create_one(self.client.create_ip_group(&self.ip_group), &self.ip_group)?;
        Ok(vec![fqdn, ip])
    }

    /// Interpret a single group creation outcome, treating "already exists"
    /// errors as `created = false` and propagating anything else.
    fn create_one(&self, outcome: Result<()>, name: &str) -> Result<(String, bool)> {
        match outcome {
            Ok(()) => Ok((name.to_string(), true)),
            Err(AppError::ResourceAlreadyExists(_)) => Ok((name.to_string(), false)),
            Err(AppError::FirewallOperation {
                message,
                status_code,
            }) => {
                let lower = message.to_lowercase();
                if lower.contains("already exists") || lower.contains("same name") {
                    Ok((name.to_string(), false))
                } else {
                    Err(AppError::FirewallOperation {
                        message,
                        status_code,
                    })
                }
            }
            Err(other) => Err(other),
        }
    }

    /// Group name for a record type. FQDN → FQDN group; IP/CIDR → IP group.
    pub fn group_for_record_type(&self, record_type: RecordType) -> Result<&str> {
        match record_type {
            RecordType::Fqdn => Ok(&self.fqdn_group),
            RecordType::IpAddress | RecordType::NetworkCidr => Ok(&self.ip_group),
            RecordType::Invalid => Err(AppError::Validation(format!(
                "No group mapping for record type: {}",
                record_type.as_str()
            ))),
        }
    }
}
