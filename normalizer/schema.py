"""SOC canonical event schema shared by all ingestors, engine, and storage."""
from __future__ import annotations
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Mapping

REQUIRED_FIELDS = (
    "timestamp_utc", "source_type", "src_ip", "dst_ip",
    "username", "hostname", "action", "severity",
)
OPTIONAL_FIELDS = (
    "dst_port", "process_name", "command_line", "signature", "raw",
)
SEVERITIES = {"info", "low", "medium", "high", "critical"}
SOURCES = {"suricata", "sysmon", "auth_log"}

class EventValidationError(ValueError):
    """Raised when an event violates the shared data contract."""


def _utc_iso(value: str | datetime) -> str:
    try:
        dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise EventValidationError("timestamp_utc must be ISO 8601") from exc
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise EventValidationError("timestamp_utc must contain a timezone")
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _ip_or_none(value: Any, field: str) -> str | None:
    if value is None or value == "":
        return None
    try:
        return str(ip_address(str(value)))
    except ValueError as exc:
        raise EventValidationError(f"{field} is not a valid IPv4/IPv6 address") from exc


def normalize_event(record: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and normalize a canonical event. All eight keys must exist.

    src_ip/dst_ip/username/hostname can be None when the original log lacks them.
    Parsers should map their own raw formats into this schema before calling.
    """
    missing = [name for name in REQUIRED_FIELDS if name not in record]
    if missing:
        raise EventValidationError(f"Missing required keys: {', '.join(missing)}")
    source = str(record["source_type"]).strip().lower()
    if source not in SOURCES:
        raise EventValidationError(f"source_type must be one of: {', '.join(sorted(SOURCES))}")
    severity = str(record["severity"]).strip().lower()
    if severity not in SEVERITIES:
        raise EventValidationError(f"Unknown severity: {severity}")
    action = str(record["action"] or "").strip()
    if not action:
        raise EventValidationError("action must not be empty")
    dst_port = record.get("dst_port")
    if dst_port is not None and dst_port != "":
        if isinstance(dst_port, bool):
            raise EventValidationError("dst_port must be an integer between 0 and 65535")
        try:
            dst_port = int(dst_port)
        except (TypeError, ValueError) as exc:
            raise EventValidationError("dst_port must be an integer") from exc
        if not 0 <= dst_port <= 65535:
            raise EventValidationError("dst_port out of range")
    else:
        dst_port = None
    result = {
        "timestamp_utc": _utc_iso(record["timestamp_utc"]),
        "source_type": source,
        "src_ip": _ip_or_none(record["src_ip"], "src_ip"),
        "dst_ip": _ip_or_none(record["dst_ip"], "dst_ip"),
        "username": None if record["username"] in (None, "") else str(record["username"]),
        "hostname": None if record["hostname"] in (None, "") else str(record["hostname"]),
        "action": action,
        "severity": severity,
        "dst_port": dst_port,
        "process_name": record.get("process_name"),
        "command_line": record.get("command_line"),
        "signature": record.get("signature"),
        "raw": record.get("raw", dict(record)),
    }
    return result
