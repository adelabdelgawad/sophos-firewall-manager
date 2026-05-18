//! Caches for existing firewall records and group membership.
//! Ports `src/services/cache_service.py`.

use std::collections::HashSet;

use crate::domain::entities::{NetworkRecord, RecordType};
use crate::domain::validators;
use crate::infra::firewall_client::FirewallApi;

/// Tracks which hosts are already members of the target groups.
#[derive(Default)]
pub struct GroupMembershipCache {
    fqdn_members: HashSet<String>,
    ip_members: HashSet<String>,
    loaded: bool,
}

impl GroupMembershipCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load group membership from the firewall.
    pub fn load(&mut self, client: &dyn FirewallApi, fqdn_group: &str, ip_group: &str) -> bool {
        self.fqdn_members = client.get_fqdn_group_members(fqdn_group).into_iter().collect();
        self.ip_members = client.get_ip_group_members(ip_group).into_iter().collect();
        self.loaded = true;
        true
    }

    /// Whether a record is already a member of its target group.
    pub fn is_member(&self, record: &NetworkRecord) -> bool {
        if !self.loaded {
            return false;
        }
        match record.record_type {
            RecordType::Fqdn => self.fqdn_members.contains(&record.value),
            RecordType::IpAddress | RecordType::NetworkCidr => {
                self.ip_members.contains(&record.value)
            }
            RecordType::Invalid => false,
        }
    }

    /// `(fqdn_members, ip_members)` counts.
    pub fn stats(&self) -> (usize, usize) {
        (self.fqdn_members.len(), self.ip_members.len())
    }
}

/// Caches existing firewall records for fast existence checks.
#[derive(Default)]
pub struct ExistingRecordsCache {
    fqdns: HashSet<String>,
    ip_hosts: HashSet<String>,
    networks: HashSet<String>,
    loaded: bool,
}

impl ExistingRecordsCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Load existing records from the firewall. The underlying client swallows
    /// fetch errors (returning empty sets), so this always succeeds.
    pub fn load(&mut self, client: &dyn FirewallApi) -> bool {
        self.fqdns = client.get_existing_fqdns().into_iter().collect();
        self.ip_hosts = client.get_existing_ip_hosts().into_iter().collect();
        self.networks = client.get_existing_networks().into_iter().collect();
        self.loaded = true;
        true
    }

    /// Whether a record already exists on the firewall.
    pub fn exists(&self, record: &NetworkRecord) -> bool {
        if !self.loaded {
            return false;
        }
        match record.record_type {
            RecordType::Fqdn => self.fqdns.contains(&record.value.to_lowercase()),
            RecordType::IpAddress => self.ip_hosts.contains(&record.value),
            RecordType::NetworkCidr => match validators::normalize_cidr(&record.value) {
                Some(normalized) => self.networks.contains(&normalized),
                None => false,
            },
            RecordType::Invalid => false,
        }
    }

    /// `(fqdns, ip_hosts, networks, total)` counts.
    pub fn stats(&self) -> (usize, usize, usize, usize) {
        let total = self.fqdns.len() + self.ip_hosts.len() + self.networks.len();
        (
            self.fqdns.len(),
            self.ip_hosts.len(),
            self.networks.len(),
            total,
        )
    }
}
