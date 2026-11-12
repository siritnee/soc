"""Contract test uses a fake engine; NOT a validation of member 4's final rules."""
import json
import sys
import types
from pathlib import Path
from pipeline.__main__ import main
from storage.models import connect, counts

BASE = dict(timestamp_utc="2026-11-12T09:00:00+07:00",source_type="auth_log",
            src_ip="192.0.2.10",dst_ip=None,username=None,hostname=None,
            action="ssh_failed",severity="medium")

def test_pipeline_ingest_detect_with_stubbed_engine(monkeypatch, tmp_path):
    data = tmp_path / "input.jsonl"
    data.write_text(json.dumps(BASE) + "\n", encoding="utf-8")
    db_path = str(tmp_path / "demo.db")
    fake = types.ModuleType("engine.correlation")
    def detect_incidents(events):
        assert len(events) == 1
        return [dict(rule_id="TEST",title="Synthetic incident",severity="medium",
            first_seen_utc=events[0]["timestamp_utc"],
            last_seen_utc=events[0]["timestamp_utc"],event_ids=[events[0]["id"]])]
    fake.detect_incidents = detect_incidents
    monkeypatch.setitem(sys.modules,"engine.correlation",fake)
    assert main(["--db",db_path,"init-db"]) == 0
    assert main(["--db",db_path,"ingest","--source","normalized","--file",str(data)]) == 0
    assert main(["--db",db_path,"detect"]) == 0
    with connect(db_path) as db:
        assert counts(db) == (1,1)
