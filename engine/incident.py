"""Incident helpers: save without duplicates, export an investigation summary."""
from __future__ import annotations

import sqlite3
from collections import Counter
from typing import Any, Iterable, Mapping, Sequence

from engine.correlation import rule_by_id
from storage.models import insert_incident, transaction

_CHUNK = 500  # stay well below SQLite's bound-parameter limit



_SEVERITY_RANK = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _find_existing_incident_id(conn, rule_id, event_ids):
    """Find the stored incident sharing the most events with this result."""
    overlap = {}

    ids = list(dict.fromkeys(int(x) for x in event_ids))

    for start in range(0, len(ids), _CHUNK):
        chunk = ids[start:start + _CHUNK]
        if not chunk:
            continue

        marks = ",".join("?" for _ in chunk)

        rows = conn.execute(
            f"""
            SELECT ie.incident_id, COUNT(*) AS shared_events
            FROM incident_events ie
            JOIN incidents i
              ON i.incident_id = ie.incident_id
            WHERE i.rule_id = ?
              AND ie.event_id IN ({marks})
            GROUP BY ie.incident_id
            """,
            [rule_id, *chunk],
        ).fetchall()

        for incident_id, shared in rows:
            overlap[incident_id] = overlap.get(incident_id, 0) + shared

    if not overlap:
        return None

    # Prefer the incident with the largest event overlap.
    # Use the smaller ID as a deterministic tie-breaker.
    return max(overlap, key=lambda i: (overlap[i], -i))


def _update_existing_incident(conn, incident_id, incident):
    """Extend an existing incident without resetting its triage status."""
    stored = conn.execute(
        """
        SELECT severity, title, summary,
               first_seen_utc, last_seen_utc
        FROM incidents
        WHERE incident_id = ?
        """,
        (incident_id,),
    ).fetchone()

    if stored is None:
        raise ValueError(f"Incident {incident_id} not found")

    current_rank = _SEVERITY_RANK[stored["severity"]]
    incoming_rank = _SEVERITY_RANK[incident["severity"]]

    # Keep the more serious assessment.
    if incoming_rank >= current_rank:
        severity = incident["severity"]
        title = incident["title"]
        summary = incident.get("summary") or stored["summary"]
    else:
        severity = stored["severity"]
        title = stored["title"]
        summary = stored["summary"]

    first_seen = min(
        stored["first_seen_utc"],
        incident["first_seen_utc"],
    )
    last_seen = max(
        stored["last_seen_utc"],
        incident["last_seen_utc"],
    )

    event_ids = list(dict.fromkeys(
        int(x) for x in incident["event_ids"]
    ))

    with transaction(conn):
        conn.executemany(
            """
            INSERT OR IGNORE INTO incident_events
                (incident_id, event_id)
            VALUES (?, ?)
            """,
            [(incident_id, event_id) for event_id in event_ids],
        )

        conn.execute(
            """
            UPDATE incidents
            SET severity = ?,
                title = ?,
                summary = ?,
                first_seen_utc = ?,
                last_seen_utc = ?
            WHERE incident_id = ?
            """,
            (
                severity,
                title,
                summary,
                first_seen,
                last_seen,
                incident_id,
            ),
        )


def save_new_incidents(conn, incidents):
    """Save new incidents and extend previously stored incidents.

    Returns the number of newly created incidents.
    Updating an existing incident does not increase this count.
    """
    # Resolve existing matches before inserting anything.
    # This preserves the case where two genuinely new incidents
    # share an event within the same detection batch.
    planned = [
        (
            incident,
            _find_existing_incident_id(
                conn,
                incident["rule_id"],
                incident["event_ids"],
            ),
        )
        for incident in incidents
    ]

    inserted = 0

    for incident, existing_id in planned:
        if existing_id is None:
            insert_incident(conn, incident)
            inserted += 1
        else:
            _update_existing_incident(conn, existing_id, incident)

    return inserted


def _rows(cursor: sqlite3.Cursor) -> list[dict[str, Any]]:
    names = [column[0] for column in cursor.description]
    return [dict(zip(names, row)) for row in cursor.fetchall()]


def load_incident(conn: sqlite3.Connection, incident_id: int) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Read one stored incident (with ``event_ids``) and its events, oldest first."""
    found = _rows(conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)))
    if not found:
        raise ValueError(f"Incident {incident_id} not found")
    events = _rows(conn.execute(
        """SELECT e.* FROM events e
           JOIN incident_events ie ON ie.event_id = e.id
           WHERE ie.incident_id = ? ORDER BY e.timestamp_utc, e.id""", (incident_id,)))
    incident = found[0]
    incident["event_ids"] = [event["id"] for event in events]
    return incident, events


def export_summary_from_db(conn: sqlite3.Connection, incident_id: int, max_timeline: int = 20) -> str:
    """Summary of a stored incident; this is what the dashboard button needs."""
    incident, events = load_incident(conn, incident_id)
    return export_summary(incident, events, max_timeline)


def export_summary(incident: Mapping[str, Any], events: Iterable[Mapping[str, Any]],
                   max_timeline: int = 20) -> str:
    """Markdown investigation summary for one incident.

    ``events`` may be all events or only the incident's; rows are matched
    through ``incident["event_ids"]``. A long timeline shows its beginning and
    its end, because the end usually holds the decisive event.
    """
    wanted = set(incident.get("event_ids", []))
    related = sorted((e for e in events if e.get("id") in wanted),
                     key=lambda e: (e["timestamp_utc"], e["id"]))

    def distinct(field: str) -> str:
        values = sorted({str(e[field]) for e in related if e.get(field)})
        return ", ".join(values) if values else "-"

    def timeline_row(e: Mapping[str, Any]) -> str:
        port = f":{e['dst_port']}" if e.get("dst_port") is not None else ""
        user = f" user={e['username']}" if e.get("username") else ""
        return (f"- {e['timestamp_utc']} [{e['source_type']}] {e['action']} "
                f"{e.get('src_ip') or '-'} -> {e.get('dst_ip') or '-'}{port}{user}")

    incident_id = incident.get("incident_id")
    rule = rule_by_id(incident["rule_id"])
    lines = [
        f"# Incident {'#' + str(incident_id) if incident_id is not None else '(not saved)'}: {incident['title']}",
        "",
        f"- Rule: {incident['rule_id']}",
        f"- MITRE ATT&CK: {incident.get('mitre') or (rule.mitre if rule else None) or '-'}",
        f"- Severity: {incident['severity']}",
        f"- Status: {incident.get('status') or 'New'}",
        f"- Assigned analyst: {incident.get('assigned_analyst') or '-'}",
        f"- First seen (UTC): {incident['first_seen_utc']}",
        f"- Last seen (UTC): {incident['last_seen_utc']}",
        f"- Related events: {len(related)}",
        "",
        "## What happened",
        incident.get("summary") or "-",
        "",
        "## Entities",
        f"- Source IPs: {distinct('src_ip')}",
        f"- Destination IPs: {distinct('dst_ip')}",
        f"- Usernames: {distinct('username')}",
        f"- Hosts: {distinct('hostname')}",
        "",
        "## Events by action",
    ]
    for action, count in sorted(Counter(e["action"] for e in related).items()):
        lines.append(f"- {action}: {count}")
    lines += ["", "## Timeline"]
    if len(related) <= max_timeline:
        lines += [timeline_row(e) for e in related]
    else:
        tail = max(1, max_timeline // 2)
        head = max(1, max_timeline - tail)
        lines += [timeline_row(e) for e in related[:head]]
        lines.append(f"- ... {len(related) - head - tail} more event(s) ...")
        lines += [timeline_row(e) for e in related[len(related) - tail:]]
    if rule and rule.recommendations:
        lines += ["", "## Suggested next steps"]
        lines += [f"{number}. {step}" for number, step in enumerate(rule.recommendations, start=1)]
    return "\n".join(lines) + "\n"
