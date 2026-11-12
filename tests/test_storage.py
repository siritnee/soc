import sqlite3
import pytest
from storage.models import connect, init_db, insert_events, list_events, insert_incident, counts, set_incident_status

BASE = dict(timestamp_utc="2026-11-12T02:00:00.000000Z", source_type="auth_log",src_ip="192.0.2.10",
            dst_ip=None,username="student",hostname="lab",action="ssh_failed",severity="medium")

def test_init_tables_indices(tmp_path):
    with connect(tmp_path / "soc.db") as db:
        init_db(db)
        tables = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        indexes = {x[0] for x in db.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert {"events","incidents","incident_events"} <= tables
    assert {"idx_events_timestamp_utc","idx_events_src_ip"} <= indexes

def test_batch_insert_and_incident_link(tmp_path):
    with connect(tmp_path / "soc.db") as db:
        init_db(db)
        assert insert_events(db, [BASE, {**BASE,"action":"ssh_success"}], batch_size=1) == 2
        items = list_events(db)
        assert len(items) == 2
        incident_id = insert_incident(db, dict(rule_id="R-SSH",title="SSH brute-force",severity="high",
            first_seen_utc=items[0]["timestamp_utc"],last_seen_utc=items[1]["timestamp_utc"],
            event_ids=[items[0]["id"],items[1]["id"]]))
        assert counts(db) == (2,1)
        assert db.execute("SELECT count(*) FROM incident_events WHERE incident_id=?",(incident_id,)).fetchone()[0] == 2
        set_incident_status(db, incident_id, "In Progress", "analyst1")
        assert db.execute("SELECT status FROM incidents WHERE incident_id=?",(incident_id,)).fetchone()[0] == "In Progress"
