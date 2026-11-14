"""Suricata EVE JSON reader (one JSON object per line).

Broken lines never stop the import: they are counted in ``stats["invalid"]``
and the reader moves on. Record types the toolkit does not use are counted in
``stats["ignored"]``.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Iterator

from ingestors.base import read_lines, skip, start_stats
from normalizer.schema import EventValidationError
from normalizer.suricata_mapper import map_eve


def parse_lines(lines: Iterable[str], stats: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    stats = start_stats(stats)
    for raw_line in lines:
        text = raw_line.strip()
        if not text:
            continue
        stats["lines"] += 1
        try:
            record = json.loads(text)
        except json.JSONDecodeError:
            skip(stats, "invalid", "not valid JSON")
            continue
        if not isinstance(record, dict):
            skip(stats, "invalid", "not a JSON object")
            continue
        try:
            event = map_eve(record)
        except EventValidationError as exc:
            skip(stats, "invalid", str(exc))
            continue
        if event is None:
            skip(stats, "ignored", f"event_type {record.get('event_type')}")
            continue
        stats["events"] += 1
        yield event


def parse_file(path: Path, stats: dict[str, Any] | None = None) -> Iterator[dict[str, Any]]:
    """Agreed ingestor interface: ``parse_file(path)`` yields canonical events."""
    yield from parse_lines(read_lines(Path(path)), stats)
