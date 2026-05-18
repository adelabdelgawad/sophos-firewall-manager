//! Pure parsing of Sophos Firewall API responses.
//!
//! Ports the response-handling static methods of `SophosFirewallClient`
//! (`_extract_status_from_response`, `_parse_response`, `_extract_*_values`,
//! `_extract_group_members`, `_contains_already_exists`). This module performs
//! no I/O, so it is fully covered by the equivalence harness.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

use crate::domain::entities::{NetworkRecord, OperationResult, OperationStatus};

use super::xml::{self, Element};

// Status code constants (mirrors firewall_client.py).
pub const STATUS_ALREADY_EXISTS: &str = "501";
pub const STATUS_OPERATION_FAILED: &str = "502";
pub const STATUS_UNKNOWN: &str = "unknown";

/// Status code to human message, matching `_STATUS_MESSAGES`.
fn status_message(code: &str) -> String {
    match code {
        "200" => "Created successfully".to_string(),
        "501" => "Already exists".to_string(),
        "502" => "Operation failed".to_string(),
        "503" => "Invalid value".to_string(),
        "504" => "Missing parameter".to_string(),
        "534" => "Authentication failed".to_string(),
        "unknown" => "Unknown response format".to_string(),
        other => format!("Operation completed with status {other}"),
    }
}

/// Status code to `OperationStatus`, matching `_STATUS_MAPPING` (default Failed).
fn map_status(code: &str) -> OperationStatus {
    match code {
        "200" => OperationStatus::Success,
        "501" => OperationStatus::AlreadyExists,
        _ => OperationStatus::Failed,
    }
}

/// True if the text indicates a resource already exists.
pub fn contains_already_exists(text: &str) -> bool {
    let lower = text.to_lowercase();
    lower.contains("already exists") || lower.contains("same name")
}

/// The element treated as the API response body: the `<Response>` element if
/// present, otherwise the whole document. Mirrors `response.get("Response", response)`.
fn api_response(doc: &Element) -> &Element {
    doc.child("Response").unwrap_or(doc)
}

/// Find the `Status` element, matching `_extract_status_from_response`.
fn extract_status(api: &Element) -> Option<&Element> {
    // A direct `<Status>` with a `code` attribute wins.
    if let Some(status) = api.child("Status") {
        if status.attr("code").is_some() {
            return Some(status);
        }
    }
    // Otherwise look inside known resource elements (only when exactly one).
    for key in ["IPHost", "FQDNHost", "IPNetwork", "FQDNHostGroup", "IPHostGroup"] {
        let mut matches = api.children_named(key);
        if let Some(first) = matches.next() {
            if matches.next().is_none() {
                if let Some(status) = first.child("Status") {
                    return Some(status);
                }
            }
        }
    }
    None
}

fn first_nonempty(values: &[Option<&str>]) -> Option<String> {
    values
        .iter()
        .flatten()
        .find(|v| !v.is_empty())
        .map(|v| v.to_string())
}

/// Parse a raw API response into an `OperationResult`, matching `_parse_response`.
pub fn parse_response(xml_text: &str, record: &NetworkRecord) -> OperationResult {
    let doc = xml::parse(xml_text);
    let api = api_response(&doc);
    let status = extract_status(api);

    let code_child = status.and_then(|s| s.child("code")).map(|c| c.text.as_str());
    let text_child = status.and_then(|s| s.child("text")).map(|c| c.text.as_str());
    let msg_child = status.and_then(|s| s.child("message")).map(|c| c.text.as_str());

    let mut code = first_nonempty(&[status.and_then(|s| s.attr("code")), code_child])
        .unwrap_or_else(|| STATUS_UNKNOWN.to_string());

    let mut message =
        first_nonempty(&[status.map(|s| s.text.as_str()), text_child, msg_child])
            .unwrap_or_default();

    // 502 + "already exists" is normalized to a 501.
    if code == STATUS_OPERATION_FAILED && contains_already_exists(xml_text) {
        code = STATUS_ALREADY_EXISTS.to_string();
        message = "Already exists".to_string();
    }

    if message.is_empty() || message == "No message" {
        message = status_message(&code);
    }

    OperationResult::new(record.clone(), map_status(&code), code, message)
}

/// Extract all FQDN host values (lower-cased), matching `_extract_fqdn_values`.
pub fn extract_fqdn_values(xml_text: &str) -> Vec<String> {
    let doc = xml::parse(xml_text);
    let api = api_response(&doc);
    let mut result = Vec::new();
    for host in api.children_named("FQDNHost") {
        if let Some(fqdn) = host.child("FQDN") {
            if !fqdn.text.is_empty() {
                result.push(fqdn.text.to_lowercase());
            }
        }
    }
    result
}

/// Extract single IP host values, matching `_extract_ip_values`.
pub fn extract_ip_values(xml_text: &str) -> Vec<String> {
    let doc = xml::parse(xml_text);
    let api = api_response(&doc);
    let mut result = Vec::new();
    for host in api.children_named("IPHost") {
        if host.child("HostType").map(|t| t.text.as_str()) == Some("IP") {
            if let Some(addr) = host.child("IPAddress") {
                if !addr.text.is_empty() {
                    result.push(addr.text.clone());
                }
            }
        }
    }
    result
}

/// Extract network CIDR values (normalized), matching `_extract_network_values`.
pub fn extract_network_values(xml_text: &str) -> Vec<String> {
    let doc = xml::parse(xml_text);
    let api = api_response(&doc);
    let mut result = Vec::new();
    for host in api.children_named("IPHost") {
        if host.child("HostType").map(|t| t.text.as_str()) != Some("Network") {
            continue;
        }
        let ip = host.child("IPAddress").map(|e| e.text.as_str()).unwrap_or("");
        let subnet = host.child("Subnet").map(|e| e.text.as_str()).unwrap_or("");
        if ip.is_empty() || subnet.is_empty() {
            continue;
        }
        if let Some(cidr) = normalize_network_from_mask(ip, subnet) {
            result.push(cidr);
        }
    }
    result
}

/// Extract member host names from a host group, matching `_extract_group_members`.
///
/// Note: the Python code always looks for a `<Host>` element inside the list
/// container. For FQDN groups the real element is `<FQDNHost>`, so FQDN group
/// membership comes back empty — that behavior is preserved here.
pub fn extract_group_members(xml_text: &str, group_key: &str, list_key: &str) -> Vec<String> {
    let doc = xml::parse(xml_text);
    let api = api_response(&doc);
    let mut result = Vec::new();
    if let Some(group) = api.child(group_key) {
        if let Some(host_list) = group.child(list_key) {
            for host in host_list.children_named("Host") {
                if !host.text.is_empty() {
                    result.push(host.text.clone());
                }
            }
        }
    }
    result
}

/// Normalize `ip_address` + dotted `subnet` mask into canonical CIDR, matching
/// Python `str(ip_network(f"{ip}/{subnet}", strict=False))`.
fn normalize_network_from_mask(ip: &str, subnet: &str) -> Option<String> {
    if let Ok(addr) = ip.parse::<Ipv4Addr>() {
        let mask: u32 = subnet.parse::<Ipv4Addr>().ok()?.into();
        let prefix = contiguous_prefix_u32(mask)?;
        let net = Ipv4Net::new(addr, prefix).ok()?;
        return Some(net.trunc().to_string());
    }
    if let Ok(addr) = ip.parse::<Ipv6Addr>() {
        let mask: u128 = subnet.parse::<Ipv6Addr>().ok()?.into();
        let prefix = contiguous_prefix_u128(mask)?;
        let net = Ipv6Net::new(addr, prefix).ok()?;
        return Some(net.trunc().to_string());
    }
    None
}

/// Prefix length of a contiguous 32-bit mask, or `None` if not contiguous.
fn contiguous_prefix_u32(mask: u32) -> Option<u8> {
    let ones = mask.leading_ones();
    if ones + mask.trailing_zeros() == 32 {
        Some(ones as u8)
    } else {
        None
    }
}

/// Prefix length of a contiguous 128-bit mask, or `None` if not contiguous.
fn contiguous_prefix_u128(mask: u128) -> Option<u8> {
    let ones = mask.leading_ones();
    if ones + mask.trailing_zeros() == 128 {
        Some(ones as u8)
    } else {
        None
    }
}
