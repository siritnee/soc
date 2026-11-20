"""Reading a data set folder (manifest, log files, ground truth).

A data set is what ``python -m datagen.benchmark`` writes: log files plus
``manifest.json`` (which file belongs to which source, and the year / time
zone convention of auth.log) and ``ground_truth.json`` (the scenarios).
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Iterator

from ingestors import auth_log, suricata, sysmon
from storage.models import insert_events

SOURCES = ("auth_log", "suricata", "sysmon")


def parse_source(source: str, path: Path, stats: dict[str, Any] | None = None, *,
                 year: int | None = None, tz: str | None = None) -> Iterator[dict[str, Any]]:
    """Canonical events of one log file. ``year`` and ``tz`` only matter for auth.log."""
    if source == "auth_log":
        return auth_log.parse_file(path, stats, year=year, tz=tz)
    if source == "suricata":
        return suricata.parse_file(path, stats)
    if source == "sysmon":
        return sysmon.parse_file(path, stats)
    raise ValueError(f"unknown source {source!r}; expected one of {', '.join(SOURCES)}")


def load_manifest(dataset_dir: Path) -> dict[str, Any]:
    path = Path(dataset_dir) / "manifest.json"
    if not path.is_file():
        raise ValueError(f"{dataset_dir} is not a data set folder: manifest.json is missing")
    return json.loads(path.read_text(encoding="utf-8"))


def load_ground_truth(dataset_dir: Path) -> list[dict[str, Any]]:
    manifest = load_manifest(dataset_dir)
    path = Path(dataset_dir) / manifest.get("ground_truth", "ground_truth.json")
    return json.loads(path.read_text(encoding="utf-8"))["scenarios"]


def ingest_dataset(conn: sqlite3.Connection, dataset_dir: Path) -> dict[str, dict[str, Any]]:
    """Parse every log file of the data set into the database.

    Returns the parser statistics per source (lines, events, ignored, invalid, reasons).
    """
    dataset_dir = Path(dataset_dir)
    result = {}
    for entry in load_manifest(dataset_dir)["sources"]:
        stats: dict[str, Any] = {}
        events = parse_source(entry["source"], dataset_dir / entry["file"], stats,
                              year=entry.get("year"), tz=entry.get("tz"))
        stats["stored"] = insert_events(conn, events)
        result[entry["source"]] = stats
    return result
