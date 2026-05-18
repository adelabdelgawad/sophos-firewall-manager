//! Sophos Firewall XML API client. Ports `src/infrastructure/firewall_client.py`.
//!
//! The Python code wraps the `sophosfirewall-python` library. That library
//! posts Jinja2-rendered XML to `https://<host>:<port>/webconsole/APIController`
//! as a `reqxml` form field. This module builds the same XML directly.

use std::time::Duration;

use reqwest::blocking::Client;

use crate::domain::entities::{NetworkRecord, OperationResult, OperationStatus, RecordType};
use crate::domain::errors::{AppError, Result};
use crate::domain::validators;

use super::response;
use super::xml;

/// Abstraction over firewall operations, mirroring the Python `FirewallClient`
/// protocol so services can be exercised against a test double.
pub trait FirewallApi {
    fn create_fqdn_group(&self, name: &str) -> Result<()>;
    fn create_ip_group(&self, name: &str) -> Result<()>;
    fn create_fqdn_host(&self, record: &NetworkRecord, group: &str) -> Result<OperationResult>;
    fn create_ip_host(&self, record: &NetworkRecord, group: &str) -> Result<OperationResult>;
    fn create_network(&self, record: &NetworkRecord, group: &str) -> Result<OperationResult>;
    fn get_existing_fqdns(&self) -> Vec<String>;
    fn get_existing_ip_hosts(&self) -> Vec<String>;
    fn get_existing_networks(&self) -> Vec<String>;
    fn get_fqdn_group_members(&self, group: &str) -> Vec<String>;
    fn get_ip_group_members(&self, group: &str) -> Vec<String>;
    fn add_to_fqdn_group(&self, group: &str, host_names: &[String]) -> bool;
    fn add_to_ip_group(&self, group: &str, host_names: &[String]) -> bool;
}

/// Escape a value for inclusion in XML text, matching markupsafe / Jinja2
/// autoescaping used by the Python library's templates.
fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&#39;"),
            '"' => out.push_str("&#34;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Adapter for the Sophos Firewall XML API.
pub struct SophosFirewallClient {
    http: Client,
    url: String,
    username: String,
    password: String,
}

impl SophosFirewallClient {
    /// Build a client. `verify_ssl = false` disables certificate verification,
    /// matching the Python `verify` flag.
    pub fn new(
        hostname: &str,
        username: &str,
        password: &str,
        port: u16,
        verify_ssl: bool,
    ) -> Result<Self> {
        let http = Client::builder()
            .danger_accept_invalid_certs(!verify_ssl)
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| AppError::FirewallConnection(e.to_string()))?;

        Ok(Self {
            http,
            url: format!("https://{hostname}:{port}/webconsole/APIController"),
            username: username.to_string(),
            password: password.to_string(),
        })
    }

    fn login_block(&self) -> String {
        format!(
            "<Login><Username>{}</Username><Password>{}</Password></Login>",
            xml_escape(&self.username),
            xml_escape(&self.password),
        )
    }

    /// POST a `reqxml` payload and return the response body text.
    fn post(&self, request_xml: &str) -> Result<String> {
        let response = self
            .http
            .post(&self.url)
            .header("Accept", "application/xml")
            .form(&[("reqxml", request_xml)])
            .send()
            .map_err(|e| AppError::FirewallConnection(e.to_string()))?;

        let body = response
            .text()
            .map_err(|e| AppError::FirewallConnection(e.to_string()))?;

        // The IP access restriction must stop execution (CLI exit code 2).
        if body.contains("not allowed from the requester IP") {
            return Err(AppError::FirewallIpRestriction(
                "not allowed from the requester IP".to_string(),
            ));
        }
        Ok(body)
    }

    /// Run a create operation and parse the response, matching `_execute_operation`.
    fn execute(&self, request_xml: &str, record: &NetworkRecord) -> Result<OperationResult> {
        match self.post(request_xml) {
            Ok(body) => Ok(response::parse_response(&body, record)),
            Err(AppError::FirewallIpRestriction(m)) => Err(AppError::FirewallIpRestriction(m)),
            // A transport failure is reported as a failed operation, not a crash.
            Err(other) => Ok(OperationResult::new(
                record.clone(),
                OperationStatus::Failed,
                response::STATUS_OPERATION_FAILED,
                other.to_string(),
            )),
        }
    }

    /// Create a host group, matching `_create_group`.
    fn create_group(&self, request_xml: &str, name: &str) -> Result<()> {
        let body = self.post(request_xml)?;
        if response::contains_already_exists(&body) {
            return Err(AppError::ResourceAlreadyExists(format!(
                "Group '{name}' already exists"
            )));
        }
        // Treat any non-2xx status as an operation failure.
        let result =
            response::parse_response(&body, &NetworkRecord::new(name, RecordType::Invalid));
        match result.status {
            OperationStatus::Success | OperationStatus::AlreadyExists => Ok(()),
            _ => Err(AppError::FirewallOperation {
                message: result.message,
                status_code: Some(result.status_code),
            }),
        }
    }

    /// Build a `<Get>` request for a tag.
    fn get_tag_xml(&self, tag: &str) -> String {
        format!(
            "<Request>{}<Get><{tag}></{tag}></Get></Request>",
            self.login_block(),
        )
    }

    /// Build a `<Get>` request for a tag filtered by `Name`.
    fn get_filtered_xml(&self, tag: &str, name: &str) -> String {
        format!(
            "<Request>{}<Get><{tag}><Filter><key name=\"Name\" criteria=\"=\">{}</key></Filter></{tag}></Get></Request>",
            self.login_block(),
            xml_escape(name),
        )
    }

    /// GET a tag, returning the response body or `None` on any failure.
    fn get(&self, tag: &str) -> Option<String> {
        self.post(&self.get_tag_xml(tag)).ok()
    }
}

impl FirewallApi for SophosFirewallClient {
    fn create_fqdn_group(&self, name: &str) -> Result<()> {
        let request = format!(
            "<Request>{}<Set operation=\"add\"><FQDNHostGroup transactionid=\"\">\
             <Name>{}</Name><Description></Description></FQDNHostGroup></Set></Request>",
            self.login_block(),
            xml_escape(name),
        );
        self.create_group(&request, name)
    }

    fn create_ip_group(&self, name: &str) -> Result<()> {
        let request = format!(
            "<Request>{}<Set operation=\"add\"><IPHostGroup transactionid=\"\">\
             <Name>{}</Name><IPFamily>IPv4</IPFamily><Description></Description>\
             <HostList></HostList></IPHostGroup></Set></Request>",
            self.login_block(),
            xml_escape(name),
        );
        self.create_group(&request, name)
    }

    fn create_fqdn_host(&self, record: &NetworkRecord, group: &str) -> Result<OperationResult> {
        let request = format!(
            "<Request>{login}<Set operation=\"add\"><FQDNHost transactionid=\"\">\
             <Name>{name}</Name><Description></Description><FQDN>{name}</FQDN>\
             <FQDNHostGroupList><FQDNHostGroup>{group}</FQDNHostGroup></FQDNHostGroupList>\
             </FQDNHost></Set></Request>",
            login = self.login_block(),
            name = xml_escape(&record.value),
            group = xml_escape(group),
        );
        self.execute(&request, record)
    }

    fn create_ip_host(&self, record: &NetworkRecord, _group: &str) -> Result<OperationResult> {
        // The Sophos `createiphost` template has no host-group field; group
        // membership is applied separately via `add_to_ip_group`.
        let request = format!(
            "<Request>{login}<Set operation=\"add\"><IPHost transactionid=\"\">\
             <Name>{name}</Name><IPFamily>IPv4</IPFamily><HostType>IP</HostType>\
             <IPAddress>{name}</IPAddress></IPHost></Set></Request>",
            login = self.login_block(),
            name = xml_escape(&record.value),
        );
        self.execute(&request, record)
    }

    fn create_network(&self, record: &NetworkRecord, _group: &str) -> Result<OperationResult> {
        let (network_address, mask) = match validators::network_parts(&record.value) {
            Some(parts) => parts,
            None => {
                return Ok(OperationResult::new(
                    record.clone(),
                    OperationStatus::Failed,
                    "000",
                    "Invalid network value",
                ))
            }
        };
        let request = format!(
            "<Request>{login}<Set operation=\"add\"><IPHost transactionid=\"\">\
             <Name>{name}</Name><IPFamily>IPv4</IPFamily><HostType>Network</HostType>\
             <IPAddress>{addr}</IPAddress><Subnet>{mask}</Subnet></IPHost></Set></Request>",
            login = self.login_block(),
            name = xml_escape(&record.value),
            addr = xml_escape(&network_address),
            mask = xml_escape(&mask),
        );
        self.execute(&request, record)
    }

    fn get_existing_fqdns(&self) -> Vec<String> {
        self.get("FQDNHost")
            .map(|body| response::extract_fqdn_values(&body))
            .unwrap_or_default()
    }

    fn get_existing_ip_hosts(&self) -> Vec<String> {
        self.get("IPHost")
            .map(|body| response::extract_ip_values(&body))
            .unwrap_or_default()
    }

    fn get_existing_networks(&self) -> Vec<String> {
        self.get("IPHost")
            .map(|body| response::extract_network_values(&body))
            .unwrap_or_default()
    }

    fn get_fqdn_group_members(&self, group: &str) -> Vec<String> {
        self.post(&self.get_filtered_xml("FQDNHostGroup", group))
            .ok()
            .map(|body| response::extract_group_members(&body, "FQDNHostGroup", "FQDNHostList"))
            .unwrap_or_default()
    }

    fn get_ip_group_members(&self, group: &str) -> Vec<String> {
        self.post(&self.get_filtered_xml("IPHostGroup", group))
            .ok()
            .map(|body| response::extract_group_members(&body, "IPHostGroup", "HostList"))
            .unwrap_or_default()
    }

    fn add_to_fqdn_group(&self, group: &str, host_names: &[String]) -> bool {
        if host_names.is_empty() {
            return true;
        }
        let body = match self.post(&self.get_filtered_xml("FQDNHostGroup", group)) {
            Ok(body) => body,
            Err(_) => return false,
        };
        let mut members = read_group_members(&body, "FQDNHostGroup", "FQDNHostList", "FQDNHost");
        for host in host_names {
            if !members.contains(host) {
                members.push(host.clone());
            }
        }
        let entries: String = members
            .iter()
            .map(|h| format!("<FQDNHost>{}</FQDNHost>", xml_escape(h)))
            .collect();
        let request = format!(
            "<Request>{}<Set operation=\"update\"><FQDNHostGroup transactionid=\"\">\
             <Name>{}</Name><Description></Description><FQDNHostList>{}</FQDNHostList>\
             </FQDNHostGroup></Set></Request>",
            self.login_block(),
            xml_escape(group),
            entries,
        );
        self.post(&request).is_ok()
    }

    fn add_to_ip_group(&self, group: &str, host_names: &[String]) -> bool {
        if host_names.is_empty() {
            return true;
        }
        let body = match self.post(&self.get_filtered_xml("IPHostGroup", group)) {
            Ok(body) => body,
            Err(_) => return false,
        };
        let mut members = read_group_members(&body, "IPHostGroup", "HostList", "Host");
        for host in host_names {
            if !members.contains(host) {
                members.push(host.clone());
            }
        }
        let entries: String = members
            .iter()
            .map(|h| format!("<Host>{}</Host>", xml_escape(h)))
            .collect();
        let request = format!(
            "<Request>{}<Set operation=\"update\"><IPHostGroup transactionid=\"\">\
             <Name>{}</Name><Description></Description><HostList>{}</HostList>\
             <IPFamily>IPv4</IPFamily></IPHostGroup></Set></Request>",
            self.login_block(),
            xml_escape(group),
            entries,
        );
        self.post(&request).is_ok()
    }
}

/// Read the current member host names of a group, the way the Sophos library's
/// own update path does (using the correct member element name).
fn read_group_members(body: &str, group_tag: &str, list_tag: &str, member_tag: &str) -> Vec<String> {
    let doc = xml::parse(body);
    let api = doc.child("Response").unwrap_or(&doc);
    let mut result = Vec::new();
    if let Some(group) = api.child(group_tag) {
        if let Some(list) = group.child(list_tag) {
            for member in list.children_named(member_tag) {
                if !member.text.is_empty() {
                    result.push(member.text.clone());
                }
            }
        }
    }
    result
}
