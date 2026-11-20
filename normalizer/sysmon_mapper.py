"""Sysmon event -> canonical event.

Only two event types are used:

* Event ID 1 (process creation)  -> action ``process_create``
* Event ID 3 (network connection) -> action ``network_connection``

``ingestors/sysmon.py`` first brings the different export layouts to one
shape; this module only knows that shape: an event id, the EventData fields,
the computer name and (as a fallback) the system time of the record.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Mapping

from normalizer.schema import EventValidationError, normalize_event

EVENT_PROCESS_CREATE = 1
EVENT_NETWORK_CONNECTION = 3
_POWERSHELL_DATE = re.compile(r"^/Date\((?P<millis>-?\d+)\)/$")


def parse_sysmon_time(utc_time: Any, system_time: Any = None) -> datetime:
    """Event time as an aware UTC datetime.

    Sysmon's own ``UtcTime`` looks like ``2026-11-12 01:20:03.512``: no zone
    marker, but it is always UTC. When it is missing, the record's system
    time is used: an ISO string, or PowerShell's ``/Date(1762910403512)/``.
    """
    if utc_time:
        try:
            moment = datetime.fromisoformat(str(utc_time).strip().replace(" ", "T"))
        except ValueError:
            raise EventValidationError(f"unreadable UtcTime: {utc_time!r}") from None
        return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment
    if system_time:
        text = str(system_time).strip()
        found = _POWERSHELL_DATE.match(text)
        if found:
            return datetime.fromtimestamp(int(found["millis"]) / 1000, tz=timezone.utc)
        try:
            # Windows writes seven decimals (100 ns ticks); Python reads at most six.
            moment = datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", text).replace("Z", "+00:00"))
        except ValueError:
            raise EventValidationError(f"unreadable system time: {system_time!r}") from None
        if moment.tzinfo is None:
            raise EventValidationError("system time without a time zone")
        return moment
    raise EventValidationError("event has no UtcTime and no system time")


def map_sysmon(event_id: Any, data: Mapping[str, Any], computer: str | None,
               system_time: Any = None) -> dict[str, Any] | None:
    """Canonical event, or None for the Sysmon event types the toolkit does not use.

    Raises EventValidationError when an Event ID 1 or 3 record is broken.
    """
    try:
        event_id = int(event_id)
    except (TypeError, ValueError):
        raise EventValidationError(f"event id is not a number: {event_id!r}") from None
    if event_id not in (EVENT_PROCESS_CREATE, EVENT_NETWORK_CONNECTION):
        return None
    event = {
        "timestamp_utc": parse_sysmon_time(data.get("UtcTime"), system_time),
        "source_type": "sysmon",
        "src_ip": None, "dst_ip": None,
        "username": data.get("User"),
        "hostname": computer,
        "severity": "info",
        "process_name": data.get("Image"),          # full path: rule 3 needs the folder
        "raw": dict(data),
    }
    if event_id == EVENT_PROCESS_CREATE:
        if not data.get("Image"):
            raise EventValidationError("process event without Image")
        event.update(action="process_create", command_line=data.get("CommandLine"))
    else:
        if not data.get("SourceIp") or not data.get("DestinationIp"):
            raise EventValidationError("network event without addresses")
        event.update(action="network_connection", src_ip=data["SourceIp"], dst_ip=data["DestinationIp"],
                     dst_port=data.get("DestinationPort"))
    return normalize_event(event)
