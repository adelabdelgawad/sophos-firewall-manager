"""Equivalence harness.

Generates the shared `cases.json`, runs both the Python oracle and the Rust
`oracle` binary against it, and diffs the results category by category.

Exit code 0 means every category is identical between the two implementations.
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CASES_PATH = os.path.join(ROOT, "equivalence", "cases.json")
PY_ORACLE = os.path.join(ROOT, "equivalence", "py_oracle.py")
VENV_PYTHON = os.path.join(ROOT, ".venv", "Scripts", "python.exe")
RUST_MANIFEST = os.path.join(ROOT, "src", "rust-app", "Cargo.toml")
RUST_ORACLE = os.path.join(ROOT, "src", "rust-app", "target", "debug", "oracle.exe")


def build_cases():
    """Build the shared test-case set covering every pure-logic surface."""
    long_label = "a" * 64          # one label over the 63-char limit
    max_label = "a" * 63           # one label at the limit
    over_253 = ".".join(["a" * 60] * 4) + ".aaaaaaaaaaaaaaaaaaaa"  # 264 chars
    exactly_ok = ".".join(["a" * 49] * 5)  # 5 labels, 249 chars

    fqdn = [
        "example.com", "subdomain.example.com", "deep.subdomain.example.com",
        "*.example.com", "example.com.", "test-domain.com", "123.example.com",
        "a-b.c-d.com", "xn--d1acpjx3f.xn--p1ai", "EXAMPLE.COM", "a.b", "1.2",
        "999.example.com", max_label + ".com", exactly_ok,
        "example", "-example.com", "example-.com", "exam ple.com", "",
        long_label + ".com", "a" * 254, "example..com", "*.*.example.com",
        "_dmarc.example.com", "host_name.example.com", "example.com..",
        ".example.com", "*.", "a..b", " example.com", "example.com ",
        "ex@mple.com", "café.com", "exam\tple.com", over_253,
        "MixedCase.Example.COM", "x-.example.com", "-.example.com",
    ]

    ip = [
        "192.168.1.1", "10.0.0.1", "172.16.0.1", "8.8.8.8", "255.255.255.255",
        "0.0.0.0", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", "2001:db8::1",
        "::1", "fe80::1", "::", "fe80::1%eth0", "::ffff:192.168.1.1", "FE80::1",
        "256.1.1.1", "192.168.1", "192.168.1.1.1", "abc.def.ghi.jkl", "",
        "192.168.1.1/24", "192.168.001.001", "192.168.1.1 ", " 1.2.3.4",
        "1.2.3.04", "0x7f.0.0.1", "1::2::3", "12345::", "gggg::1",
        "2001:db8:::1", "1.2.3.4.5", "...", "::ffff:0:0",
    ]

    cidr = [
        "192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/16", "192.168.1.128/25",
        "0.0.0.0/0", "2001:db8::/32", "fe80::/10", "::1/128", "10.0.0.0/008",
        "192.168.1.0/032",
        "192.168.1.0", "192.168.1.0/", "192.168.1.0/33", "256.1.1.0/24", "",
        "192.168.1.0/abc", "192.168.1.5/24", "10.0.0.5/8", "2001:db8::1/32",
        "192.168.1.0/+24", "192.168.1.0/ 24", "fe80::1%eth0/64",
        "192.168.1.00/24", "10/8", "192.168.1.0/24/5", "2001:db8::/129",
        "1.2.3.4", "2001:db8::/-1", "192.168.1.0/99999999999999999999",
    ]

    classify = [
        "example.com", "192.168.1.1", "10.0.0.0/8", "invalid", "192.168.1.0/32",
        "2001:db8::1", "2001:db8::/32", " example.com ", "  10.0.0.0/8  ",
        "-bad", "256.256.256.256", "192.168.1.5/24", "*.example.com", "",
        "192.168.1.0/24", "fe80::1", "host.name.local",
    ]

    cidr_normalize = [
        "10.0.0.0/8", "192.168.1.0/24", "2001:db8::/32", "192.168.1.5/24",
        "10.0.0.255/24", "2001:DB8::1/32", "::1/128", "0.0.0.0/0",
        "10.0.0.0/008", "999.0.0.0/8", "not-a-cidr", "fe80::/10",
        "2001:db8:0:0::/64", "172.16.5.4/16", "192.168.1.0/032",
    ]

    network_parts = [
        "10.0.0.0/8", "192.168.1.5/24", "2001:db8::/32", "::1/128", "0.0.0.0/0",
        "172.16.0.0/16", "bad", "2001:db8::/64", "192.168.1.0/24",
        "255.255.255.255/32",
    ]

    summary = [
        [],
        ["success"],
        ["failed"],
        ["success", "success", "failed", "skipped", "skipped"],
        ["updated", "updated"],
        ["success", "updated", "already_exists", "failed", "skipped"],
        ["already_exists", "already_exists"],
        ["success"] * 7,
        ["skipped"] * 3,
        ["success", "failed", "failed"],
    ]

    group_naming = [
        "Production", "Dev_Network", "", "a b", "X&Y", "O'Brien", "group<1>",
        "名前", "Office2024",
    ]

    format_result = [
        {"value": "example.com", "record_type": "fqdn", "status": "success",
         "status_code": "200", "message": "Created successfully"},
        {"value": "1.2.3.4", "record_type": "ip_address", "status": "updated",
         "status_code": "200", "message": "Added to group X_IPHostGroup"},
        {"value": "api.example.com", "record_type": "fqdn",
         "status": "already_exists", "status_code": "501",
         "message": "Already exists"},
        {"value": "bad-record", "record_type": "invalid", "status": "skipped",
         "status_code": "000", "message": "Invalid record format"},
        {"value": "10.0.0.0/8", "record_type": "network_cidr",
         "status": "failed", "status_code": "502", "message": "Operation failed"},
        {"value": "a&b<c>.com", "record_type": "fqdn", "status": "success",
         "status_code": "200", "message": "ok"},
    ]

    format_summary = [
        {"total": 0},
        {"total": 1, "successful": 1},
        {"total": 3, "successful": 2, "failed": 1},
        {"total": 16, "successful": 1, "failed": 15},
        {"total": 8, "successful": 1, "failed": 7},
        {"total": 5, "successful": 2, "updated": 1, "already_exists": 1,
         "failed": 1},
        {"total": 7, "failed": 7},
        {"total": 100, "successful": 33, "failed": 67},
        {"total": 6, "successful": 1, "updated": 1, "failed": 4},
    ]

    format_group = [
        {"name": "Production_FQDNHostGroup", "created": True},
        {"name": "Production_IPHostGroup", "created": False},
        {"name": "X&Y_FQDNHostGroup", "created": True},
        {"name": "", "created": False},
    ]

    format_color = [
        {"kind": "success", "message": "Loaded 10 records"},
        {"kind": "error", "message": "File error: not found"},
        {"kind": "warning", "message": "Skipping 2 records"},
        {"kind": "info", "message": "Classifying records..."},
        {"kind": "success", "message": ""},
    ]

    contains_already_exists = [
        "Object already exists", "ALREADY EXISTS now",
        "host with same name found", "SAME NAME", "nothing here", "",
        "exists already", "alreadyexists", "Configuration already Exists.",
    ]

    parse_response = [
        {"xml": "<Response><Status code=\"200\">Configuration applied "
                "successfully.</Status></Response>"},
        {"xml": "<Response><Status code=\"200\"></Status></Response>"},
        {"xml": "<Response><Status code=\"501\">Record already exists."
                "</Status></Response>"},
        {"xml": "<Response><Status code=\"502\">Operation failed.</Status>"
                "</Response>"},
        {"xml": "<Response><Status code=\"502\">The configuration already "
                "exists on the device.</Status></Response>"},
        {"xml": "<Response><FQDNHost transactionid=\"abc\"><Status code=\"200\">"
                "Configuration applied successfully.</Status></FQDNHost>"
                "</Response>"},
        {"xml": "<Response><IPHost><Status code=\"503\">Invalid value for "
                "IPAddress.</Status></IPHost></Response>"},
        {"xml": "<Response><IPNetwork><Status code=\"504\">Mandatory parameter "
                "missing.</Status></IPNetwork></Response>"},
        {"xml": "<Response><Status code=\"534\">API access not allowed from "
                "this IP.</Status></Response>"},
        {"xml": "<Response><Status code=\"200\">No message</Status></Response>"},
        {"xml": "<Response><Login><status>Authentication Failure</status>"
                "</Login></Response>"},
    ]
    for case in parse_response:
        case["value"] = "x"
        case["record_type"] = "fqdn"

    extract_fqdns = [
        "<Response><FQDNHost><Name>n1</Name><FQDN>Example.COM</FQDN></FQDNHost>"
        "<FQDNHost><Name>n2</Name><FQDN>api.example.com</FQDN></FQDNHost>"
        "</Response>",
        "<Response><FQDNHost><Name>n</Name><FQDN>solo.example.com</FQDN>"
        "</FQDNHost></Response>",
        "<Response><Login><status>OK</status></Login></Response>",
        "<Response><FQDNHost><Name>n</Name></FQDNHost></Response>",
        "<Response><FQDNHost><Name>n</Name><FQDN></FQDN></FQDNHost></Response>",
    ]

    extract_ips = [
        "<Response><IPHost><Name>a</Name><HostType>IP</HostType><IPAddress>"
        "1.2.3.4</IPAddress></IPHost><IPHost><Name>b</Name><HostType>Network"
        "</HostType><IPAddress>10.0.0.0</IPAddress><Subnet>255.0.0.0</Subnet>"
        "</IPHost></Response>",
        "<Response><IPHost><Name>a</Name><HostType>IP</HostType><IPAddress>"
        "8.8.8.8</IPAddress></IPHost></Response>",
        "<Response><Login><status>OK</status></Login></Response>",
        "<Response><IPHost><HostType>IPRange</HostType><StartIPAddress>"
        "1.1.1.1</StartIPAddress></IPHost></Response>",
    ]

    extract_networks = [
        "<Response><IPHost><Name>a</Name><HostType>IP</HostType><IPAddress>"
        "1.2.3.4</IPAddress></IPHost><IPHost><Name>b</Name><HostType>Network"
        "</HostType><IPAddress>10.0.0.0</IPAddress><Subnet>255.0.0.0</Subnet>"
        "</IPHost></Response>",
        "<Response><IPHost><Name>n</Name><HostType>Network</HostType>"
        "<IPAddress>192.168.1.0</IPAddress><Subnet>255.255.255.0</Subnet>"
        "</IPHost><IPHost><Name>m</Name><HostType>Network</HostType><IPAddress>"
        "172.16.0.0</IPAddress><Subnet>255.255.0.0</Subnet></IPHost></Response>",
        "<Response><IPHost><HostType>Network</HostType><IPAddress>10.0.0.0"
        "</IPAddress><Subnet>255.255.255.255</Subnet></IPHost></Response>",
        "<Response><Login><status>OK</status></Login></Response>",
        "<Response><IPHost><HostType>Network</HostType><IPAddress>10.0.0.0"
        "</IPAddress><Subnet>255.0.255.0</Subnet></IPHost></Response>",
    ]

    extract_group_members = [
        {"xml": "<Response><IPHostGroup><Name>G</Name><HostList><Host>h1</Host>"
                "<Host>h2</Host></HostList></IPHostGroup></Response>",
         "group_key": "IPHostGroup", "list_key": "HostList"},
        {"xml": "<Response><IPHostGroup><Name>G</Name><HostList><Host>only"
                "</Host></HostList></IPHostGroup></Response>",
         "group_key": "IPHostGroup", "list_key": "HostList"},
        {"xml": "<Response><FQDNHostGroup><Name>G</Name><FQDNHostList>"
                "<FQDNHost>f1</FQDNHost><FQDNHost>f2</FQDNHost></FQDNHostList>"
                "</FQDNHostGroup></Response>",
         "group_key": "FQDNHostGroup", "list_key": "FQDNHostList"},
        {"xml": "<Response><Login><status>OK</status></Login></Response>",
         "group_key": "IPHostGroup", "list_key": "HostList"},
        {"xml": "<Response><IPHostGroup><Name>G</Name></IPHostGroup></Response>",
         "group_key": "IPHostGroup", "list_key": "HostList"},
    ]

    file_read = [
        "a\nb\nc\n",
        "  x  \n\n  y  \n",
        "",
        "   \n  \n",
        "single line no newline",
        "host.com\r\n1.2.3.4\r\n",
        "﻿example.com\nnext\n",
        "line1\n\n\nline2\n",
        "\t tab.com \t\n",
    ]

    return {
        "fqdn": fqdn,
        "ip": ip,
        "cidr": cidr,
        "classify": classify,
        "cidr_normalize": cidr_normalize,
        "network_parts": network_parts,
        "summary": summary,
        "group_naming": group_naming,
        "format_result": format_result,
        "format_summary": format_summary,
        "format_group": format_group,
        "format_color": format_color,
        "contains_already_exists": contains_already_exists,
        "parse_response": parse_response,
        "extract_fqdns": extract_fqdns,
        "extract_ips": extract_ips,
        "extract_networks": extract_networks,
        "extract_group_members": extract_group_members,
        "file_read": file_read,
    }


def run(cmd, **kwargs):
    """Run a command and return its UTF-8 stdout; raise on failure.

    Subprocess output is decoded as UTF-8 explicitly rather than relying on the
    console code page, which would otherwise mangle the Rust oracle's output.
    """
    result = subprocess.run(cmd, capture_output=True, **kwargs)
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")
        sys.stderr.write(f"command failed: {cmd}\n{stderr}\n")
        sys.exit(1)
    return result.stdout.decode("utf-8")


def main():
    cases = build_cases()
    with open(CASES_PATH, "w", encoding="utf-8") as handle:
        json.dump(cases, handle, indent=2, ensure_ascii=False)

    # Build the Rust oracle, then run it.
    run(["cargo", "build", "--quiet", "--manifest-path", RUST_MANIFEST,
         "--bin", "oracle"])
    rust_out = json.loads(run([RUST_ORACLE, CASES_PATH]))

    # Run the Python oracle.
    py_out = json.loads(run([VENV_PYTHON, PY_ORACLE, CASES_PATH]))

    # Compare category by category.
    categories = sorted(set(py_out) | set(rust_out))
    total_cases = 0
    total_mismatch = 0
    failed_categories = []

    print("=" * 64)
    print(f"{'CATEGORY':<26}{'CASES':>8}{'MATCH':>10}{'RESULT':>12}")
    print("=" * 64)

    for category in categories:
        py_values = py_out.get(category, [])
        rust_values = rust_out.get(category, [])
        inputs = cases.get(category, [])
        count = max(len(py_values), len(rust_values))
        total_cases += count

        mismatches = []
        for index in range(count):
            py_value = py_values[index] if index < len(py_values) else "<missing>"
            rust_value = (
                rust_values[index] if index < len(rust_values) else "<missing>"
            )
            if py_value != rust_value:
                case_input = inputs[index] if index < len(inputs) else "<?>"
                mismatches.append((index, case_input, py_value, rust_value))

        total_mismatch += len(mismatches)
        status = "OK" if not mismatches else "FAIL"
        if mismatches:
            failed_categories.append(category)
        print(f"{category:<26}{count:>8}{count - len(mismatches):>10}{status:>12}")

        for index, case_input, py_value, rust_value in mismatches[:8]:
            # `ascii()` keeps output printable on any console encoding and
            # makes invisible characters (e.g. a BOM) visible as escapes.
            print(f"    [#{index}] input={ascii(case_input)}")
            print(f"          python = {ascii(py_value)}")
            print(f"          rust   = {ascii(rust_value)}")

    print("=" * 64)
    print(f"Total cases: {total_cases}  |  Mismatches: {total_mismatch}")

    if total_mismatch == 0:
        print("RESULT: PASS - Rust and Python outputs are identical.")
        return 0
    print(f"RESULT: FAIL - mismatched categories: {', '.join(failed_categories)}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
