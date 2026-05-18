# Rust ↔ Python Equivalence

The Rust port in [`src/rust-app/`](src/rust-app/) reimplements the Python
application in [`src/python-app/`](src/python-app/). Their behavior is verified
by a differential harness in [`equivalence/`](equivalence/).

## Running the harness

```bash
src/python-app/.venv/Scripts/python.exe equivalence/compare.py
```

The harness:

1. Generates a shared `equivalence/cases.json` of synthetic inputs.
2. Runs `equivalence/py_oracle.py` — computes outputs with the **actual Python
   application code**.
3. Runs the Rust `oracle` binary — computes outputs with the **Rust library**.
4. Diffs the two, category by category.

Exit code `0` means every category is byte-identical between the two
implementations.

**Current status: 233 / 233 cases identical across 19 categories.**

## What is verified

Every deterministic, pure-logic surface of the application:

| Category | Surface under test |
|---|---|
| `fqdn`, `ip`, `cidr` | Domain validators (`validators.py` ↔ `domain/validators.rs`) |
| `classify` | `RecordClassifier` priority order |
| `cidr_normalize` | `str(ip_network(x, strict=False))` ↔ `normalize_cidr` |
| `network_parts` | `network_address` / `netmask` extraction for `create_network` |
| `summary` | `ProcessingSummary.record_result` and `success_rate` |
| `group_naming` | `GroupConfiguration` group-name suffixes |
| `format_result`, `format_summary`, `format_group`, `format_color` | All presentation formatters (Rich-markup output) |
| `contains_already_exists` | "already exists" / "same name" detection |
| `parse_response` | API response -> `OperationResult` mapping |
| `extract_fqdns`, `extract_ips`, `extract_networks` | Existing-record extraction from API XML |
| `extract_group_members` | Group membership extraction from API XML |
| `file_read` | `TextFileReader` line cleaning, blank handling, BOM/CRLF |

The 64 original Python `pytest` cases are included in the harness inputs as
ground truth.

## What is NOT verified

The **live network layer** cannot be differentially tested without a real
Sophos Firewall:

- HTTP transport (`reqwest` vs `requests`).
- `create_groups` / `create_*_host` / `add_to_*_group` round-trips against a
  live device.
- `_post` error surfacing for live `534` / IP-restriction responses.

These paths are ported faithfully from the `sophosfirewall-python` library's
Jinja2 templates (`createfqdnhost.j2`, `createiphost.j2`, etc.), but their
correctness rests on code review, not the harness. The *response parsing* that
those paths feed into **is** fully covered (`parse_response`, `extract_*`).

## Deliberate divergences

A few Python behaviors are bugs that the Rust port handles correctly instead of
reproducing crash-for-crash:

1. **`create_ip_host` group argument** — the Python app passes
   `host_group_list=[group]` to the library's `create_ip_host`, which has no
   such parameter (a `TypeError` at runtime). The Sophos `createiphost`
   template has no host-group field anyway. The Rust port creates the IP host
   and then registers group membership through `add_to_ip_group`, which is the
   working form of the same intent.

2. **`get_fqdn_group_members`** — the Python `_extract_group_members` always
   looks for a `<Host>` element, but FQDN groups use `<FQDNHost>`. FQDN group
   membership therefore always comes back empty. This is preserved: the Rust
   `extract_group_members` is verified to return the same (empty) result.

3. **`parse_response` robustness** — Python's `_parse_response` raises
   `AttributeError` if a resource's `<Status>` is plain text with no `code`
   attribute. The Rust port handles this gracefully. Real Sophos responses
   always include the `code` attribute, so only well-formed responses are
   exercised in the harness.

## Notes on cross-language parity

- FQDN validation is reimplemented label-by-label (no regex engine) because the
  Python regex uses lookaround, which the Rust `regex` crate does not support.
  The label rules are exactly equivalent and verified by 39 `fqdn` cases.
- IP/CIDR validation uses `std::net` + `ipnet`, which matches Python
  `ipaddress` / pydantic semantics (leading-zero rejection, strict networks).
  An IPv6 `%zone` scope id is stripped before parsing, matching Python.
- The `file_read` category covers UTF-8 BOM and CRLF handling. A lone `\r`
  (classic Mac line ending) is the one untested newline form.
