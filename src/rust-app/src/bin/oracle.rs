//! Equivalence oracle: computes outputs for the shared test cases using the
//! Rust implementation, so they can be diffed against the Python results.
//!
//! Usage: `oracle <cases.json>` — writes a JSON results object to stdout.

use std::collections::BTreeSet;

use serde_json::{json, Map, Value};

use sfm::domain::entities::{
    NetworkRecord, OperationResult, OperationStatus, ProcessingSummary, RecordType,
};
use sfm::domain::validators;
use sfm::infra::file_reader::TextFileReader;
use sfm::infra::response;
use sfm::presentation::formatters as fmt;
use sfm::services::group_service::GroupConfiguration;

fn record_type_from_str(s: &str) -> RecordType {
    match s {
        "fqdn" => RecordType::Fqdn,
        "ip_address" => RecordType::IpAddress,
        "network_cidr" => RecordType::NetworkCidr,
        _ => RecordType::Invalid,
    }
}

fn status_from_str(s: &str) -> OperationStatus {
    match s {
        "success" => OperationStatus::Success,
        "already_exists" => OperationStatus::AlreadyExists,
        "updated" => OperationStatus::Updated,
        "skipped" => OperationStatus::Skipped,
        _ => OperationStatus::Failed,
    }
}

/// Extract a category as a list of strings.
fn strings(cases: &Value, key: &str) -> Vec<String> {
    cases
        .get(key)
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Extract a category as a list of JSON objects.
fn objects(cases: &Value, key: &str) -> Vec<Value> {
    cases
        .get(key)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Sort and deduplicate, mirroring Python `sorted(set(...))`.
fn sorted_set(values: Vec<String>) -> Vec<String> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn field_u64(obj: &Value, key: &str) -> u64 {
    obj.get(key).and_then(Value::as_u64).unwrap_or(0)
}

fn field_str<'a>(obj: &'a Value, key: &str) -> &'a str {
    obj.get(key).and_then(Value::as_str).unwrap_or("")
}

fn run_summary(statuses: &[String]) -> Value {
    let mut summary = ProcessingSummary::new();
    let dummy = NetworkRecord::new("x", RecordType::Fqdn);
    for status in statuses {
        let result = OperationResult::new(dummy.clone(), status_from_str(status), "000", "");
        summary.record_result(&result);
    }
    json!({
        "total": summary.total,
        "successful": summary.successful,
        "updated": summary.updated,
        "already_exists": summary.already_exists,
        "failed": summary.failed,
        "skipped": summary.skipped,
        "success_rate": format!("{:.6}", summary.success_rate()),
    })
}

fn summary_from_object(obj: &Value) -> ProcessingSummary {
    ProcessingSummary {
        total: field_u64(obj, "total"),
        successful: field_u64(obj, "successful"),
        updated: field_u64(obj, "updated"),
        already_exists: field_u64(obj, "already_exists"),
        failed: field_u64(obj, "failed"),
        skipped: field_u64(obj, "skipped"),
    }
}

fn run_file_read(content: &str) -> Value {
    let path = std::env::temp_dir().join(format!("sfm_oracle_{}.txt", fastish_id(content)));
    if std::fs::write(&path, content).is_err() {
        return json!({ "err": true });
    }
    let reader = TextFileReader::new("utf-8");
    let result = match reader.read_lines(&path.to_string_lossy()) {
        Ok(lines) => json!({ "ok": lines }),
        Err(_) => json!({ "err": true }),
    };
    let _ = std::fs::remove_file(&path);
    result
}

/// A cheap content-derived id so temp files for different cases do not collide.
fn fastish_id(content: &str) -> u64 {
    let mut hash: u64 = 1469598103934665603;
    for byte in content.bytes() {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(1099511628211);
    }
    hash
}

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "../equivalence/cases.json".to_string());
    let raw = std::fs::read_to_string(&path).expect("failed to read cases.json");
    let cases: Value = serde_json::from_str(&raw).expect("failed to parse cases.json");

    let mut out = Map::new();

    out.insert(
        "fqdn".into(),
        json!(strings(&cases, "fqdn")
            .iter()
            .map(|s| validators::fqdn_is_valid(s))
            .collect::<Vec<_>>()),
    );

    out.insert(
        "ip".into(),
        json!(strings(&cases, "ip")
            .iter()
            .map(|s| validators::ip_is_valid(s))
            .collect::<Vec<_>>()),
    );

    out.insert(
        "cidr".into(),
        json!(strings(&cases, "cidr")
            .iter()
            .map(|s| validators::cidr_is_valid(s))
            .collect::<Vec<_>>()),
    );

    out.insert(
        "classify".into(),
        json!(strings(&cases, "classify")
            .iter()
            .map(|s| validators::classify(s).record_type.as_str())
            .collect::<Vec<_>>()),
    );

    out.insert(
        "cidr_normalize".into(),
        json!(strings(&cases, "cidr_normalize")
            .iter()
            .map(|s| validators::normalize_cidr(s))
            .collect::<Vec<_>>()),
    );

    out.insert(
        "network_parts".into(),
        json!(strings(&cases, "network_parts")
            .iter()
            .map(|s| validators::network_parts(s).map(|(a, m)| vec![a, m]))
            .collect::<Vec<_>>()),
    );

    out.insert(
        "summary".into(),
        json!(objects(&cases, "summary")
            .iter()
            .map(|case| {
                let statuses: Vec<String> = case
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default();
                run_summary(&statuses)
            })
            .collect::<Vec<_>>()),
    );

    out.insert(
        "group_naming".into(),
        json!(strings(&cases, "group_naming")
            .iter()
            .map(|base| {
                let config = GroupConfiguration::new(base.clone());
                json!({
                    "fqdn": config.fqdn_group_name(),
                    "ip": config.ip_group_name(),
                })
            })
            .collect::<Vec<_>>()),
    );

    out.insert(
        "format_result".into(),
        json!(objects(&cases, "format_result")
            .iter()
            .map(|obj| {
                let record = NetworkRecord::new(
                    field_str(obj, "value"),
                    record_type_from_str(field_str(obj, "record_type")),
                );
                let result = OperationResult::new(
                    record,
                    status_from_str(field_str(obj, "status")),
                    field_str(obj, "status_code"),
                    field_str(obj, "message"),
                );
                fmt::format_result(&result)
            })
            .collect::<Vec<_>>()),
    );

    out.insert(
        "format_summary".into(),
        json!(objects(&cases, "format_summary")
            .iter()
            .map(|obj| fmt::format_summary(&summary_from_object(obj)))
            .collect::<Vec<_>>()),
    );

    out.insert(
        "format_group".into(),
        json!(objects(&cases, "format_group")
            .iter()
            .map(|obj| {
                let created = obj.get("created").and_then(Value::as_bool).unwrap_or(false);
                fmt::format_group(field_str(obj, "name"), created)
            })
            .collect::<Vec<_>>()),
    );

    out.insert(
        "format_color".into(),
        json!(objects(&cases, "format_color")
            .iter()
            .map(|obj| {
                let message = field_str(obj, "message");
                match field_str(obj, "kind") {
                    "success" => fmt::success(message),
                    "error" => fmt::error(message),
                    "warning" => fmt::warning(message),
                    _ => fmt::info(message),
                }
            })
            .collect::<Vec<_>>()),
    );

    out.insert(
        "contains_already_exists".into(),
        json!(strings(&cases, "contains_already_exists")
            .iter()
            .map(|s| response::contains_already_exists(s))
            .collect::<Vec<_>>()),
    );

    out.insert(
        "parse_response".into(),
        json!(objects(&cases, "parse_response")
            .iter()
            .map(|obj| {
                let record = NetworkRecord::new(
                    field_str(obj, "value"),
                    record_type_from_str(field_str(obj, "record_type")),
                );
                let result = response::parse_response(field_str(obj, "xml"), &record);
                json!({
                    "status": result.status.as_str(),
                    "status_code": result.status_code,
                    "message": result.message,
                })
            })
            .collect::<Vec<_>>()),
    );

    out.insert(
        "extract_fqdns".into(),
        json!(strings(&cases, "extract_fqdns")
            .iter()
            .map(|xml| sorted_set(response::extract_fqdn_values(xml)))
            .collect::<Vec<_>>()),
    );

    out.insert(
        "extract_ips".into(),
        json!(strings(&cases, "extract_ips")
            .iter()
            .map(|xml| sorted_set(response::extract_ip_values(xml)))
            .collect::<Vec<_>>()),
    );

    out.insert(
        "extract_networks".into(),
        json!(strings(&cases, "extract_networks")
            .iter()
            .map(|xml| sorted_set(response::extract_network_values(xml)))
            .collect::<Vec<_>>()),
    );

    out.insert(
        "extract_group_members".into(),
        json!(objects(&cases, "extract_group_members")
            .iter()
            .map(|obj| {
                sorted_set(response::extract_group_members(
                    field_str(obj, "xml"),
                    field_str(obj, "group_key"),
                    field_str(obj, "list_key"),
                ))
            })
            .collect::<Vec<_>>()),
    );

    out.insert(
        "file_read".into(),
        json!(strings(&cases, "file_read")
            .iter()
            .map(|content| run_file_read(content))
            .collect::<Vec<_>>()),
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&Value::Object(out)).unwrap()
    );
}
