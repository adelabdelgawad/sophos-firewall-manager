"""Python equivalence oracle.

Reads the shared `cases.json`, computes outputs using the *actual* Python
application code, and writes a JSON results object to stdout. The Rust `oracle`
binary produces the same structure; `compare.py` diffs the two.
"""

import json
import os
import sys
import tempfile

# Make the python-app's `src` and `config` packages importable.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_PYTHON_APP = os.path.join(_PROJECT_ROOT, "src", "python-app")
sys.path.insert(0, _PYTHON_APP)

import ipaddress  # noqa: E402

import xmltodict  # noqa: E402

from src.domain.entities import (  # noqa: E402
    NetworkRecord,
    OperationResult,
    OperationStatus,
    ProcessingSummary,
    RecordType,
)
from src.domain.exceptions import FileOperationException  # noqa: E402
from src.domain.validators import (  # noqa: E402
    FQDNValidator,
    IPAddressValidator,
    NetworkCIDRValidator,
    RecordClassifier,
)
from src.infrastructure.file_reader import TextFileReader  # noqa: E402
from src.infrastructure.firewall_client import SophosFirewallClient  # noqa: E402
from src.presentation.formatters import (  # noqa: E402
    ColorFormatter,
    GroupCreationFormatter,
    OperationResultFormatter,
    SummaryFormatter,
)
from src.services.group_service import GroupConfiguration  # noqa: E402

_RECORD_TYPES = {
    "fqdn": RecordType.FQDN,
    "ip_address": RecordType.IP_ADDRESS,
    "network_cidr": RecordType.NETWORK_CIDR,
    "invalid": RecordType.INVALID,
}
_STATUSES = {
    "success": OperationStatus.SUCCESS,
    "already_exists": OperationStatus.ALREADY_EXISTS,
    "updated": OperationStatus.UPDATED,
    "skipped": OperationStatus.SKIPPED,
    "failed": OperationStatus.FAILED,
}

# A firewall client built with dummy credentials. The constructor performs no
# network calls, so the pure parsing helpers can be exercised directly.
_CLIENT = SophosFirewallClient(hostname="h", username="u", password="p")
_CLASSIFIER = RecordClassifier()


def normalize_cidr(value):
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except (ValueError, TypeError):
        return None


def network_parts(value):
    try:
        net = ipaddress.ip_network(value, strict=False)
        return [str(net.network_address), str(net.netmask)]
    except (ValueError, TypeError):
        return None


def run_summary(statuses):
    summary = ProcessingSummary()
    record = NetworkRecord(value="x", record_type=RecordType.FQDN)
    for status in statuses:
        result = OperationResult(
            record=record,
            status=_STATUSES.get(status, OperationStatus.FAILED),
            status_code="000",
            message="",
        )
        summary.record_result(result)
    return {
        "total": summary.total,
        "successful": summary.successful,
        "updated": summary.updated,
        "already_exists": summary.already_exists,
        "failed": summary.failed,
        "skipped": summary.skipped,
        "success_rate": f"{summary.success_rate:.6f}",
    }


def summary_from_object(obj):
    return ProcessingSummary(
        total=obj.get("total", 0),
        successful=obj.get("successful", 0),
        updated=obj.get("updated", 0),
        already_exists=obj.get("already_exists", 0),
        failed=obj.get("failed", 0),
        skipped=obj.get("skipped", 0),
    )


def run_format_result(obj):
    record = NetworkRecord(
        value=obj.get("value", ""),
        record_type=_RECORD_TYPES.get(obj.get("record_type", ""), RecordType.INVALID),
    )
    result = OperationResult(
        record=record,
        status=_STATUSES.get(obj.get("status", ""), OperationStatus.FAILED),
        status_code=obj.get("status_code", ""),
        message=obj.get("message", ""),
    )
    return OperationResultFormatter.format(result)


def run_format_color(obj):
    kind = obj.get("kind", "info")
    message = obj.get("message", "")
    return {
        "success": ColorFormatter.success,
        "error": ColorFormatter.error,
        "warning": ColorFormatter.warning,
        "info": ColorFormatter.info,
    }.get(kind, ColorFormatter.info)(message)


def run_parse_response(obj):
    record = NetworkRecord(
        value=obj.get("value", "x"),
        record_type=_RECORD_TYPES.get(obj.get("record_type", "fqdn"), RecordType.FQDN),
    )
    parsed = xmltodict.parse(obj.get("xml", ""))
    result = _CLIENT._parse_response(parsed, record)
    return {
        "status": result.status.value,
        "status_code": result.status_code,
        "message": result.message,
    }


def run_file_read(content):
    fd, path = tempfile.mkstemp(suffix=".txt")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content.encode("utf-8"))
        try:
            lines = TextFileReader(encoding="utf-8").read_lines(path)
            return {"ok": lines}
        except FileOperationException:
            return {"err": True}
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def main():
    cases_path = sys.argv[1] if len(sys.argv) > 1 else "equivalence/cases.json"
    with open(cases_path, "r", encoding="utf-8") as handle:
        cases = json.load(handle)

    out = {}

    out["fqdn"] = [FQDNValidator.is_valid(v) for v in cases.get("fqdn", [])]
    out["ip"] = [IPAddressValidator.is_valid(v) for v in cases.get("ip", [])]
    out["cidr"] = [NetworkCIDRValidator.is_valid(v) for v in cases.get("cidr", [])]
    out["classify"] = [
        _CLASSIFIER.classify(v).record_type.value for v in cases.get("classify", [])
    ]
    out["cidr_normalize"] = [normalize_cidr(v) for v in cases.get("cidr_normalize", [])]
    out["network_parts"] = [network_parts(v) for v in cases.get("network_parts", [])]
    out["summary"] = [run_summary(c) for c in cases.get("summary", [])]
    out["group_naming"] = [
        {
            "fqdn": GroupConfiguration(base_name=b).fqdn_group_name,
            "ip": GroupConfiguration(base_name=b).ip_group_name,
        }
        for b in cases.get("group_naming", [])
    ]
    out["format_result"] = [run_format_result(c) for c in cases.get("format_result", [])]
    out["format_summary"] = [
        SummaryFormatter.format(summary_from_object(c))
        for c in cases.get("format_summary", [])
    ]
    out["format_group"] = [
        GroupCreationFormatter.format(c.get("name", ""), c.get("created", False))
        for c in cases.get("format_group", [])
    ]
    out["format_color"] = [run_format_color(c) for c in cases.get("format_color", [])]
    out["contains_already_exists"] = [
        SophosFirewallClient._contains_already_exists(s)
        for s in cases.get("contains_already_exists", [])
    ]
    out["parse_response"] = [run_parse_response(c) for c in cases.get("parse_response", [])]
    out["extract_fqdns"] = [
        sorted(SophosFirewallClient._extract_fqdn_values(xmltodict.parse(x)))
        for x in cases.get("extract_fqdns", [])
    ]
    out["extract_ips"] = [
        sorted(SophosFirewallClient._extract_ip_values(xmltodict.parse(x)))
        for x in cases.get("extract_ips", [])
    ]
    out["extract_networks"] = [
        sorted(SophosFirewallClient._extract_network_values(xmltodict.parse(x)))
        for x in cases.get("extract_networks", [])
    ]
    out["extract_group_members"] = [
        sorted(
            SophosFirewallClient._extract_group_members(
                xmltodict.parse(c.get("xml", "")),
                c.get("group_key", ""),
                c.get("list_key", ""),
            )
        )
        for c in cases.get("extract_group_members", [])
    ]
    out["file_read"] = [run_file_read(c) for c in cases.get("file_read", [])]

    json.dump(out, sys.stdout, indent=2)


if __name__ == "__main__":
    main()
