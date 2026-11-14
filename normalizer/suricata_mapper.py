"""Suricata EVE record -> canonical event.

Supported ``event_type`` values: alert, flow, dns (queries only) and http.
Everything else (stats, tls, fileinfo...) is not used by the toolkit.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from normalizer.schema import EventValidationError, normalize_event

# Suricata calls it "severity" but it is a priority: 1 is the most serious.
SEVERITY_BY_PRIORITY = {1: "high", 2: "medium", 3: "low"}
_TIME_FORMATS = ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z")



def parse_eve_time(text: Any) -> datetime:
    """Parse Suricata timestamp and require timezone."""
    for layout in _TIME_FORMATS:
        try:
            dt = datetime.strptime(str(text), layout)

            # Khong chap nhan timestamp thieu timezone
            if dt.tzinfo is None or dt.utcoffset() is None:
                continue

            return dt

        except ValueError:
            continue

    raise EventValidationError(
        f"unreadable or zone-less timestamp: {text!r}"
    )



def _alert_severity(alert: Mapping[str, Any]) -> str:
    try:
        priority = int(alert.get("severity"))
    except (TypeError, ValueError):
        return "medium"                      # an alert that does not say how serious it is
    return SEVERITY_BY_PRIORITY.get(priority, "info")


def map_eve(record: Mapping[str, Any]) -> dict[str, Any] | None:
    """Canonical event, or None for record types the toolkit does not use.

    Raises EventValidationError when a supported record is broken.
    """
    kind = record.get("event_type")
    if "timestamp" not in record:
        raise EventValidationError("record has no timestamp")
    moment = parse_eve_time(record["timestamp"])
    severity, signature = "info", None
    if kind == "alert":
        alert = record.get("alert")
        if not isinstance(alert, Mapping):
            raise EventValidationError("alert record without alert details")
        action, severity, signature = "alert", _alert_severity(alert), alert.get("signature")
    elif kind == "flow":
        action = "flow"
        flow = record.get("flow")
        # A flow record is written when the flow ends or times out, often a
        # minute late. What matters for correlation is when it started.
        if isinstance(flow, Mapping) and flow.get("start"):
            moment = parse_eve_time(flow["start"])
    elif kind == "dns":
        dns = record.get("dns")
        if not isinstance(dns, Mapping) or dns.get("type") not in ("query", "request"):
            return None                      # answers would duplicate the query
        action = "dns_query"
    elif kind == "http":
        action = "http_request"
    else:
        return None
    return normalize_event({
        "timestamp_utc": moment,
        "source_type": "suricata",
        "src_ip": record.get("src_ip"),
        "dst_ip": record.get("dest_ip"),
        "username": None,
        "hostname": record.get("host"),      # name of the sensor, when configured
        "action": action,
        "severity": severity,
        "dst_port": record.get("dest_port"),
        "signature": signature,
        "raw": dict(record),
    })
