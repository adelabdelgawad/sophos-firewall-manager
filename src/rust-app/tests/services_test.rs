//! Service-layer tests using an in-memory mock firewall.
//!
//! The equivalence harness covers all pure logic; this test covers the
//! service orchestration (`HostGroupService`, `RecordProcessingService`),
//! which depends on the firewall trait and so cannot be diffed against Python.

use sfm::domain::entities::{NetworkRecord, OperationResult, OperationStatus, RecordType};
use sfm::domain::errors::Result;
use sfm::infra::firewall_client::FirewallApi;
use sfm::services::group_service::{GroupConfiguration, HostGroupService};
use sfm::services::record_service::RecordProcessingService;

/// A firewall double that returns canned successes.
#[derive(Default)]
struct MockFirewall;

impl FirewallApi for MockFirewall {
    fn create_fqdn_group(&self, _name: &str) -> Result<()> {
        Ok(())
    }
    fn create_ip_group(&self, _name: &str) -> Result<()> {
        Ok(())
    }
    fn create_fqdn_host(&self, record: &NetworkRecord, _group: &str) -> Result<OperationResult> {
        Ok(OperationResult::new(
            record.clone(),
            OperationStatus::Success,
            "200",
            "Created successfully",
        ))
    }
    fn create_ip_host(&self, record: &NetworkRecord, _group: &str) -> Result<OperationResult> {
        Ok(OperationResult::new(
            record.clone(),
            OperationStatus::Success,
            "200",
            "Created successfully",
        ))
    }
    fn create_network(&self, record: &NetworkRecord, _group: &str) -> Result<OperationResult> {
        Ok(OperationResult::new(
            record.clone(),
            OperationStatus::Success,
            "200",
            "Created successfully",
        ))
    }
    fn get_existing_fqdns(&self) -> Vec<String> {
        Vec::new()
    }
    fn get_existing_ip_hosts(&self) -> Vec<String> {
        Vec::new()
    }
    fn get_existing_networks(&self) -> Vec<String> {
        Vec::new()
    }
    fn get_fqdn_group_members(&self, _group: &str) -> Vec<String> {
        Vec::new()
    }
    fn get_ip_group_members(&self, _group: &str) -> Vec<String> {
        Vec::new()
    }
    fn add_to_fqdn_group(&self, _group: &str, _hosts: &[String]) -> bool {
        true
    }
    fn add_to_ip_group(&self, _group: &str, _hosts: &[String]) -> bool {
        true
    }
}

#[test]
fn create_groups_returns_both_groups_in_order() {
    let mock = MockFirewall;
    let service = HostGroupService::new(&mock, GroupConfiguration::new("Prod"));

    let results = service.create_groups().expect("groups created");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0], ("Prod_FQDNHostGroup".to_string(), true));
    assert_eq!(results[1], ("Prod_IPHostGroup".to_string(), true));
}

#[test]
fn group_for_record_type_maps_each_type() {
    let mock = MockFirewall;
    let service = HostGroupService::new(&mock, GroupConfiguration::new("Prod"));

    assert_eq!(
        service.group_for_record_type(RecordType::Fqdn).unwrap(),
        "Prod_FQDNHostGroup"
    );
    assert_eq!(
        service.group_for_record_type(RecordType::IpAddress).unwrap(),
        "Prod_IPHostGroup"
    );
    assert_eq!(
        service
            .group_for_record_type(RecordType::NetworkCidr)
            .unwrap(),
        "Prod_IPHostGroup"
    );
    assert!(service.group_for_record_type(RecordType::Invalid).is_err());
}

#[test]
fn process_record_creates_a_valid_record() {
    let mock = MockFirewall;
    let group_service = HostGroupService::new(&mock, GroupConfiguration::new("Prod"));
    let record_service = RecordProcessingService::new(&mock, &group_service);

    let record = NetworkRecord::new("example.com", RecordType::Fqdn);
    let result = record_service.process_record(&record).expect("processed");

    assert_eq!(result.status, OperationStatus::Success);
    assert!(result.succeeded());
}

#[test]
fn process_record_skips_an_invalid_record() {
    let mock = MockFirewall;
    let group_service = HostGroupService::new(&mock, GroupConfiguration::new("Prod"));
    let record_service = RecordProcessingService::new(&mock, &group_service);

    let record = NetworkRecord::new("not-valid", RecordType::Invalid);
    let result = record_service.process_record(&record).expect("processed");

    assert_eq!(result.status, OperationStatus::Skipped);
}

#[test]
fn update_existing_record_adds_to_group() {
    let mock = MockFirewall;
    let group_service = HostGroupService::new(&mock, GroupConfiguration::new("Prod"));
    let record_service = RecordProcessingService::new(&mock, &group_service);

    let record = NetworkRecord::new("10.0.0.0/8", RecordType::NetworkCidr);
    let result = record_service.update_existing_record(&record);

    assert_eq!(result.status, OperationStatus::Updated);
    assert_eq!(result.message, "Added to group Prod_IPHostGroup");
}
