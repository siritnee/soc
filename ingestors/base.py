"""Helpers shared by the ingestors: line statistics and safe file reading.

Statistics contract (all ingestors): ``parse_file(path, stats)`` fills the
caller's dict with

* ``lines``   - non-empty lines (or records) read,
* ``events``  - canonical events produced,
* ``ignored`` - well-formed lines the toolkit has no use for (cron, stats...),
* ``invalid`` - broken lines (bad JSON, no timestamp, impossible date...),
* ``reasons`` - why lines were skipped: reason text -> number of lines.

Counters add up when the same dict is passed again, so one dict can total
several files.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator


def start_stats(stats: dict[str, Any] | None) -> dict[str, Any]:
    """Return ``stats`` (or a throwaway dict) with every counter present."""
    stats = {} if stats is None else stats
    for counter in ("lines", "events", "ignored", "invalid"):
        stats.setdefault(counter, 0)
    stats.setdefault("reasons", {})
    return stats


def skip(stats: dict[str, Any], kind: str, reason: str) -> None:
    """Count one skipped line; ``kind`` is "ignored" or "invalid"."""
    stats[kind] += 1
    label = f"{kind}: {reason}"
    stats["reasons"][label] = stats["reasons"].get(label, 0) + 1


def text_encoding(path: Path) -> str:
    """Encoding of a log file, from its byte-order mark.

    Files written by Windows PowerShell 5 (``> file.json``) are UTF-16; other
    tools write UTF-8, sometimes with a BOM. ``utf-8-sig`` reads both UTF-8
    variants.
    """
    with Path(path).open("rb") as handle:
        head = handle.read(2)
    return "utf-16" if head in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"


def read_lines(path: Path) -> Iterator[str]:
    """Lines of a text file; undecodable bytes become U+FFFD instead of crashing."""
    with Path(path).open(encoding=text_encoding(path), errors="replace") as handle:
        yield from handle
