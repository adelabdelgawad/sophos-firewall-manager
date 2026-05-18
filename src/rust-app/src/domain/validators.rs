//! Domain validation logic for network records. Ports `src/domain/validators.py`.
//!
//! The Python validators delegate to pydantic (`IPvAnyAddress`/`IPvAnyNetwork`)
//! and a regex. Those semantics are reproduced here without a regex engine:
//!
//! * IPv4/IPv6 parsing uses `std::net`, which matches Python `ipaddress`:
//!   leading-zero octets are rejected, surrounding whitespace is rejected.
//!   Python additionally accepts an IPv6 `%zone` scope id, so that suffix is
//!   stripped before parsing an address.
//! * Networks are validated *strictly* (host bits must be zero), matching
//!   pydantic `IPvAnyNetwork`. The prefix must be all decimal digits.
//! * FQDNs are validated label-by-label, matching the Python regex.

use std::net::{Ipv4Addr, Ipv6Addr};

use ipnet::{IpNet, Ipv4Net, Ipv6Net};

use super::entities::{NetworkRecord, RecordType};

const FQDN_MAX_LENGTH: usize = 253;
const FQDN_MIN_LABELS: usize = 2;

// --- FQDN -------------------------------------------------------------------

/// Validate a Fully Qualified Domain Name (RFC 1035 / 3696).
pub fn fqdn_is_valid(fqdn: &str) -> bool {
    if fqdn.is_empty() {
        return false;
    }

    // Handle wildcard domains: Python `removeprefix("*.")` strips one prefix.
    let normalized = match fqdn.strip_prefix("*.") {
        Some(rest) => rest.to_lowercase(),
        None => fqdn.to_lowercase(),
    };

    // Length check uses the value with all trailing dots removed.
    let trimmed = normalized.trim_end_matches('.');
    if trimmed.chars().count() > FQDN_MAX_LENGTH {
        return false;
    }

    if !fqdn_pattern_matches(&normalized) {
        return false;
    }

    // Minimum label count.
    let label_count = trimmed.matches('.').count() + 1;
    label_count >= FQDN_MIN_LABELS
}

/// Reproduces the Python FQDN regex: zero or more `label.` groups followed by
/// a final `label` and an optional single trailing dot.
fn fqdn_pattern_matches(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // The regex permits exactly one optional trailing dot.
    let core = s.strip_suffix('.').unwrap_or(s);
    if core.is_empty() {
        return false;
    }
    core.split('.').all(label_ok)
}

/// A single DNS label: 1-63 ASCII alphanumerics/hyphens, no leading/trailing hyphen.
fn label_ok(label: &str) -> bool {
    if label.is_empty() {
        return false;
    }
    if !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return false;
    }
    // All bytes are ASCII here, so byte length equals character length.
    if label.len() > 63 {
        return false;
    }
    !label.starts_with('-') && !label.ends_with('-')
}

// --- IP address -------------------------------------------------------------

/// Validate an IPv4 or IPv6 address.
pub fn ip_is_valid(ip: &str) -> bool {
    if ip.is_empty() {
        return false;
    }
    ip.parse::<Ipv4Addr>().is_ok() || ipv6_is_valid(ip)
}

/// IPv6 parsing that, like Python `ipaddress`, accepts an optional `%zone`.
fn ipv6_is_valid(ip: &str) -> bool {
    let base = match ip.split_once('%') {
        Some((_, zone)) if zone.is_empty() => return false,
        Some((addr, _)) => addr,
        None => ip,
    };
    base.parse::<Ipv6Addr>().is_ok()
}

// --- Network CIDR -----------------------------------------------------------

/// Validate a network in CIDR notation (strict: host bits must be zero).
pub fn cidr_is_valid(network: &str) -> bool {
    if !network.contains('/') {
        return false;
    }
    match parse_network_lax(network) {
        Some(net) => net.trunc() == net,
        None => false,
    }
}

/// Parse `addr/prefix` permissively (host bits allowed). Returns `None` for any
/// malformed address or prefix. The prefix must be all decimal digits, matching
/// Python `ipaddress` (which rejects `+`, signs and surrounding whitespace but
/// tolerates leading zeros).
fn parse_network_lax(network: &str) -> Option<IpNet> {
    let (addr_s, prefix_s) = network.split_once('/')?;
    if prefix_s.is_empty() || !prefix_s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let prefix: u32 = prefix_s.parse().ok()?;

    if let Ok(addr) = addr_s.parse::<Ipv4Addr>() {
        if prefix > 32 {
            return None;
        }
        return Some(IpNet::V4(Ipv4Net::new(addr, prefix as u8).ok()?));
    }
    if let Ok(addr) = addr_s.parse::<Ipv6Addr>() {
        if prefix > 128 {
            return None;
        }
        return Some(IpNet::V6(Ipv6Net::new(addr, prefix as u8).ok()?));
    }
    None
}

/// Normalize a CIDR string the way Python `str(ip_network(x, strict=False))`
/// does: host bits masked off, IPv6 lower-cased and compressed.
pub fn normalize_cidr(network: &str) -> Option<String> {
    parse_network_lax(network).map(|net| net.trunc().to_string())
}

/// Network address and dotted/compressed netmask for a CIDR string, matching
/// Python `ip_network(...).network_address` and `.netmask`.
pub fn network_parts(network: &str) -> Option<(String, String)> {
    let net = parse_network_lax(network)?;
    Some((net.network().to_string(), net.netmask().to_string()))
}

// --- Classification ---------------------------------------------------------

/// Classify a raw record string into a `NetworkRecord`.
///
/// Validators run in priority order: CIDR, then IP address, then FQDN.
pub fn classify(value: &str) -> NetworkRecord {
    let value = value.trim();
    if cidr_is_valid(value) {
        NetworkRecord::new(value, RecordType::NetworkCidr)
    } else if ip_is_valid(value) {
        NetworkRecord::new(value, RecordType::IpAddress)
    } else if fqdn_is_valid(value) {
        NetworkRecord::new(value, RecordType::Fqdn)
    } else {
        NetworkRecord::new(value, RecordType::Invalid)
    }
}

/// Classify many records.
pub fn classify_batch<I, S>(values: I) -> Vec<NetworkRecord>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    values.into_iter().map(|v| classify(v.as_ref())).collect()
}
