"""Windows Sysmon reader for events exported to JSON.

Accepted files: one JSON object per line, or one JSON array (what
PowerShell's ``ConvertTo-Json`` writes). Accepted record layouts:

* flat          ``{"EventID": 1, "Computer": "...", "UtcTime": "...", "Image": ...}``
* evtx_dump     ``{"Event": {"System": {...}, "EventData": {...}}}``
* winlogbeat    ``{"@timestamp": "...", "winlog": {"event_id": 1, "event_data": {...}}}``
* Get-WinEvent  ``{"Id": 1, "MachineName": "...", "Message": "Process Create:\\r\\nUtcTime: ..."}``

Reading ``.evtx`` files directly is not supported: export them to JSON first.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from ingestors.base import skip, start_stats, text_encoding
from normalizer.schema import EventValidationError
from normalizer.sysmon_mapper import map_sysmon


def _message_fields(message: str) -> dict[str, str]:
    """``Key: Value`` lines of a rendered event message (first line is the title)."""
    fields = {}
    for line in str(message).splitlines()[1:]:
        key, separator, value = line.partition(":")
        if separator:
            fields[key.strip()] = value.strip()
    return fields


def flatten(record: Mapping[str, Any]) -> tuple[Any, Mapping[str, Any], str | None, Any]:
    """Any supported layout -> (event id, EventData fields, computer, system time)."""
    event = record.get("Event")
    if isinstance(event, Mapping):                                        # evtx_dump
        system = event.get("System") or {}
        event_id = system.get("EventID")
        if isinstance(event_id, Mapping):                                 # {"#text": 1, "#attributes": {...}}
            event_id = event_id.get("#text")
        created = system.get("TimeCreated") or {}
        system_time = (created.get("#attributes") or {}).get("SystemTime") if isinstance(created, Mapping) else created
        return event_id, event.get("EventData") or {}, system.get("Computer"), system_time
    winlog = record.get("winlog")
    if isinstance(winlog, Mapping):                                       # winlogbeat
        return (winlog.get("event_id"), winlog.get("event_data") or {},
                winlog.get("computer_name"), record.get("@timestamp"))
    if "Id" in record and "Message" in record:                            # PowerShell Get-WinEvent
        return (record["Id"], _message_fields(record["Message"]),
                record.get("MachineName"), record.get("TimeCreated"))
    computer = record.get("Computer") or record.get("Hostname") or record.get("ComputerName")
    system_time = record.get("TimeCreated") or record.get("@timestamp")
    return record.get("EventID", record.get("EventId")), record, computer, system_time


def parse_records(records: Iterable[Any], stats: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    """Canonical events from already decoded JSON records."""
    stats = start_stats(stats)
    for record in records:
        stats["lines"] += 1
        if not isinstance(record, Mapping):
            skip(stats, "invalid", "not a JSON object")
            continue
        try:
            event_id, data, computer, system_time = flatten(record)
            if not isinstance(data, Mapping):
                raise EventValidationError("event data is not a JSON object")
            event = map_sysmon(event_id, data, computer, system_time)
        except EventValidationError as exc:
            skip(stats, "invalid", str(exc))
            continue
        if event is None:
            skip(stats, "ignored", f"Sysmon event id {event_id}")
            continue
        stats["events"] += 1
        yield event


def _decode_lines(lines: Iterable[str], stats: dict[str, Any]) -> Iterator[Any]:
    """JSON Lines -> records; a broken line is counted and skipped."""
    for raw_line in lines:
        text = raw_line.strip()
        if not text:
            continue
        try:
            yield json.loads(text)
        except json.JSONDecodeError:
            stats["lines"] += 1
            skip(stats, "invalid", "not valid JSON")


def parse_text(text: str, stats: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    """Canonical events from the content of an exported file."""
    stats = start_stats(stats)
    try:
        whole = json.loads(text)
    except json.JSONDecodeError:
        records: Iterable[Any] = _decode_lines(text.splitlines(), stats)   # one object per line
    else:
        records = whole if isinstance(whole, list) else [whole]            # an array, or a single event
    yield from parse_records(records, stats)


def parse_file(path: Path, stats: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    """Agreed ingestor interface: ``parse_file(path)`` yields canonical events."""
    path = Path(path)
    yield from parse_text(path.read_text(encoding=text_encoding(path), errors="replace"), stats)
