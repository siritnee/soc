"""Everything the dashboard reads from or writes to the database.

Kept apart from ``dashboard.py`` so it can be tested without Streamlit.
All functions take an open SQLite connection (``storage.models.connect``).
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any, Sequence

from engine.correlation import detect_incidents, mitre_for_rule
from engine.incident import export_summary_from_db, load_incident, save_new_incidents
from engine.net import is_internal
from eval.dataset import parse_source
from storage.models import insert_events, list_events, set_incident_status
from datetime import date

STATUSES = ("New", "In Progress", "Closed")
OPEN_STATUSES = ("New", "In Progress")
SEVERITIES = ("critical", "high", "medium", "low", "info")
_FILTER_COLUMNS = ("source_type", "action", "severity")


def _rows(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def _marks(values: Sequence[Any]) -> str:
    return ",".join("?" for _ in values)


# ---- overview -------------------------------------------------------------------

def overview(conn: sqlite3.Connection) -> dict[str, Any]:
    """The headline numbers of the dashboard."""
    def grouped(sql: str) -> dict[str, int]:
        return {row[0]: row[1] for row in conn.execute(sql).fetchall()}

    by_status = grouped("SELECT status, COUNT(*) FROM incidents GROUP BY status")
    first, last = conn.execute("SELECT MIN(timestamp_utc), MAX(timestamp_utc) FROM events").fetchone()
    return {
        "events": conn.execute("SELECT COUNT(*) FROM events").fetchone()[0],
        "incidents": sum(by_status.values()),
        "open_incidents": sum(by_status.get(status, 0) for status in OPEN_STATUSES),
        "open_serious": conn.execute(
            "SELECT COUNT(*) FROM incidents WHERE status IN ('New', 'In Progress') "
            "AND severity IN ('critical', 'high')").fetchone()[0],
        "by_status": by_status,
        "by_source": grouped("SELECT source_type, COUNT(*) FROM events GROUP BY source_type ORDER BY source_type"),
        "first_event_utc": first,
        "last_event_utc": last,
    }


def attacked_asset(event: dict[str, Any]) -> str | None:
    """Which machine of ours an incident event is about.

    The internal destination when there is one (scan target, exploited host);
    otherwise the host that wrote the log (the server in auth.log, the
    workstation in Sysmon); otherwise an internal source (an infected machine
    calling out). The Suricata sensor's own name is never an asset.
    """
    if is_internal(event.get("dst_ip")):
        return event["dst_ip"]
    if event.get("hostname") and event.get("source_type") != "suricata":
        return event["hostname"]
    if is_internal(event.get("src_ip")):
        return event["src_ip"]
    return None


def top_assets(conn: sqlite3.Connection, limit: int = 5) -> list[dict[str, Any]]:
    """Most attacked assets: by number of incidents, then by number of incident events."""
    rows = _rows(conn.execute(
        """SELECT ie.incident_id, e.src_ip, e.dst_ip, e.hostname, e.source_type
           FROM incident_events ie JOIN events e ON e.id = ie.event_id"""))
    incidents: dict[str, set[int]] = {}
    events: dict[str, int] = {}
    for row in rows:
        asset = attacked_asset(row)
        if asset:
            incidents.setdefault(asset, set()).add(row["incident_id"])
            events[asset] = events.get(asset, 0) + 1
    ranked = sorted(incidents, key=lambda asset: (-len(incidents[asset]), -events[asset], asset))
    return [{"asset": asset, "incidents": len(incidents[asset]), "events": events[asset]} for asset in ranked[:limit]]


# ---- incidents ---------------------------------------------------------------------

def list_incidents(conn: sqlite3.Connection, statuses: Sequence[str] = (), severities: Sequence[str] = (),
                   rule_ids: Sequence[str] = ()) -> list[dict[str, Any]]:
    """Incidents, oldest first, with their event count and MITRE technique. Empty filters mean "all"."""
    where, values = [], []
    for column, wanted in (("status", statuses), ("severity", severities), ("rule_id", rule_ids)):
        if wanted:
            where.append(f"i.{column} IN ({_marks(wanted)})")
            values.extend(wanted)
    rows = _rows(conn.execute(
        f"""SELECT i.*, (SELECT COUNT(*) FROM incident_events ie WHERE ie.incident_id = i.incident_id) AS event_count
            FROM incidents i {'WHERE ' + ' AND '.join(where) if where else ''}
            ORDER BY i.first_seen_utc, i.incident_id""", values))
    for row in rows:
        row["mitre"] = mitre_for_rule(row["rule_id"])
    return rows


def incidents_on_day(
    incidents: Sequence[dict[str, Any]],
    day: date,
) -> list[dict[str, Any]]:
    """Return incidents active at any time during a UTC date."""
    selected = day.isoformat()

    return [
        item for item in incidents
        if item["first_seen_utc"][:10]
        <= selected
        <= item["last_seen_utc"][:10]
    ]


def incident_details(conn: sqlite3.Connection, incident_id: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """One incident and its events, oldest first."""
    return load_incident(conn, incident_id)


def update_incident(conn: sqlite3.Connection, incident_id: int, status: str, analyst: str | None) -> None:
    """Change status and assigned analyst (an empty name clears the assignment)."""
    set_incident_status(conn, incident_id, status, (analyst or "").strip() or None)


def investigation_summary(conn: sqlite3.Connection, incident_id: int) -> str:
    return export_summary_from_db(conn, incident_id)


# ---- log search ----------------------------------------------------------------------

def filter_choices(conn: sqlite3.Connection, column: str) -> list[str]:
    """Distinct values of a filterable column, for the filter widgets."""
    if column not in _FILTER_COLUMNS:
        raise ValueError(f"not a filter column: {column}")
    return [row[0] for row in conn.execute(f"SELECT DISTINCT {column} FROM events ORDER BY {column}")]


def search_events(conn: sqlite3.Connection, *, ip: str = "", start_utc: str | None = None,
                  end_utc: str | None = None, severities: Sequence[str] = (), sources: Sequence[str] = (),
                  actions: Sequence[str] = (), text: str = "", limit: int = 200,
                  offset: int = 0) -> tuple[list[dict[str, Any]], int]:
    """Events that pass every given filter, oldest first, plus the total number of matches.

    ``ip`` matches source or destination; ending it with a dot ("10.0.2.")
    matches a whole range. ``start_utc`` / ``end_utc`` are canonical
    timestamps and are inclusive. ``text`` is looked for in the user name,
    host name, signature, command line and the raw record.
    """
    where, values = [], []
    ip = ip.strip()
    if ip:
        if ip.endswith(".") or ip.endswith(":"):
            where.append("(src_ip LIKE ? OR dst_ip LIKE ?)")
            values += [ip + "%"] * 2
        else:
            where.append("(src_ip = ? OR dst_ip = ?)")
            values += [ip] * 2
    if start_utc:
        where.append("timestamp_utc >= ?")
        values.append(start_utc)
    if end_utc:
        where.append("timestamp_utc <= ?")
        values.append(end_utc)
    for column, wanted in (("severity", severities), ("source_type", sources), ("action", actions)):
        if wanted:
            where.append(f"{column} IN ({_marks(wanted)})")
            values.extend(wanted)
    text = text.strip()
    if text:
        columns = ("username", "hostname", "signature", "command_line", "process_name", "raw_json")
        where.append("(" + " OR ".join(f"{column} LIKE ? ESCAPE '\\'" for column in columns) + ")")
        pattern = "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        values += [pattern] * len(columns)
    clause = "WHERE " + " AND ".join(where) if where else ""
    total = conn.execute(f"SELECT COUNT(*) FROM events {clause}", values).fetchone()[0]
    rows = _rows(conn.execute(
        f"""SELECT id, timestamp_utc, source_type, severity, action, src_ip, dst_ip, dst_port,
                   username, hostname, process_name, command_line, signature
            FROM events {clause} ORDER BY timestamp_utc, id LIMIT ? OFFSET ?""", values + [limit, offset]))
    return rows, total


# ---- analysing an uploaded log ----------------------------------------------------------


def file_digest(
    source: str,
    data: bytes,
    *,
    year: int | None = None,
    tz: str | None = None,
) -> str:
    """Fingerprint a file together with its parsing configuration."""
    options = {
        "source": source,
        "year": year if source == "auth_log" else None,
        "tz": tz if source == "auth_log" else None,
    }

    import json

    metadata = json.dumps(
        options, sort_keys=True
    ).encode("utf-8")

    return hashlib.sha256(
        metadata + b"\0" + data
    ).hexdigest()


def analyze_log(conn: sqlite3.Connection, source: str, data: bytes, *, year: int | None = None,
                tz: str | None = None) -> dict[str, Any]:
    """Parse an uploaded log, store its events, run the rules, save new incidents.

    Returns the parser statistics, how many events were stored and the ids of
    the incidents that are new.
    """

    digest = file_digest(source, data, year=year, tz=tz)

    already_imported = conn.execute(
        "SELECT 1 FROM ingested_files WHERE digest = ?",
        (digest,),
    ).fetchone()

    if already_imported:
        return {
            "stats": {},
            "stored": 0,
            "new_incident_ids": [],
            "duplicate": True,
        }

    before = {
        row[0]
        for row in conn.execute(
            "SELECT incident_id FROM incidents"
        )
    }

    handle, name = tempfile.mkstemp(suffix=".log")

    try:
        with os.fdopen(handle, "wb") as temp:
            temp.write(data)

        stats = {}

        stored = insert_events(
            conn,
            parse_source(
                source,
                Path(name),
                stats,
                year=year,
                tz=tz,
            ),
        )

    finally:
        os.unlink(name)

    save_new_incidents(
        conn,
        detect_incidents(list_events(conn)),
    )

    after = [
        row[0]
        for row in conn.execute(
            """
            SELECT incident_id
            FROM incidents
            ORDER BY incident_id
            """
        )
    ]

    with conn:
        conn.execute(
            """
            INSERT INTO ingested_files
                (digest, source, stored_events)
            VALUES (?, ?, ?)
            """,
            (digest, source, stored),
        )

    return {
        "stats": stats,
        "stored": stored,
        "new_incident_ids": [
            incident_id
            for incident_id in after
            if incident_id not in before
        ],
        "duplicate": False,
    }
