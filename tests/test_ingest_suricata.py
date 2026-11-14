"""Suricata EVE ingestor: record types, timestamps, broken lines, statistics."""
import json
from pathlib import Path

import pytest

from ingestors import suricata
from ingestors.suricata import parse_lines
from normalizer.schema import REQUIRED_FIELDS, EventValidationError
from normalizer.suricata_mapper import map_eve, parse_eve_time
from storage.models import connect, init_db, insert_events, list_events

SAMPLE = Path(__file__).parent / "data" / "eve_sample.json"


def alert(severity=1, **changes):
    record = {
        "timestamp": "2026-11-12T08:15:02.123456+0700", "flow_id": 1, "event_type": "alert",
        "src_ip": "203.0.113.77", "src_port": 44321, "dest_ip": "10.0.2.24", "dest_port": 445, "proto": "TCP",
        "alert": {"action": "allowed", "gid": 1, "signature_id": 1000001, "rev": 1,
                  "signature": "LAB EXPLOIT test", "category": "test", "severity": severity},
        "host": "sensor-01",
    }
    record.update(changes)
    return record


# ---- the sample file --------------------------------------------------------

def test_sample_file_counts_and_actions():
    stats = {}
    found = list(suricata.parse_file(SAMPLE, stats))
    assert [e["action"] for e in found] == ["alert", "alert", "alert", "flow", "dns_query", "http_request"]
    assert [e["severity"] for e in found] == ["high", "medium", "low", "info", "info", "info"]
    assert (stats["lines"], stats["events"], stats["ignored"], stats["invalid"]) == (12, 6, 2, 4)
    assert stats["reasons"]["ignored: event_type stats"] == 1
    assert stats["reasons"]["invalid: not valid JSON"] == 1
    for event in found:
        assert set(REQUIRED_FIELDS) <= set(event)
        assert event["source_type"] == "suricata" and event["timestamp_utc"].endswith("Z")


def test_sample_file_goes_into_storage(tmp_path):
    with connect(tmp_path / "soc.db") as db:
        init_db(db)
        assert insert_events(db, suricata.parse_file(SAMPLE)) == 6
        stored = list_events(db)
    # storage orders by event time: the flow started at 08:30 although it was logged at 08:31
    assert [e["action"] for e in stored][-1] == "flow"
    assert stored[0]["raw"]["alert"]["signature_id"] == 1000001


# ---- mapping ----------------------------------------------------------------

def test_alert_fields_and_zone_conversion():
    event = map_eve(alert())
    assert event["timestamp_utc"] == "2026-11-12T01:15:02.123456Z"       # +0700 -> UTC
    assert (event["src_ip"], event["dst_ip"], event["dst_port"]) == ("203.0.113.77", "10.0.2.24", 445)
    assert (event["action"], event["severity"], event["signature"]) == ("alert", "high", "LAB EXPLOIT test")
    assert event["hostname"] == "sensor-01" and event["username"] is None
    assert event["raw"]["alert"]["category"] == "test"


@pytest.mark.parametrize("priority, expected", [(1, "high"), (2, "medium"), (3, "low"), (4, "info"),
                                                 (255, "info"), ("2", "medium"), (None, "medium"), ("?", "medium")])
def test_alert_priority_becomes_severity(priority, expected):
    assert map_eve(alert(priority))["severity"] == expected


@pytest.mark.parametrize("text, expected", [
    ("2026-11-12T08:15:02.123456+0700", "2026-11-12T01:15:02.123456Z"),
    ("2026-11-12T08:15:02.123456+07:00", "2026-11-12T01:15:02.123456Z"),
    ("2026-11-12T08:15:02+0700", "2026-11-12T01:15:02.000000Z"),
    ("2026-11-12T01:15:02.5Z", "2026-11-12T01:15:02.500000Z"),
    ("2026-11-11T20:15:02.000000-0500", "2026-11-12T01:15:02.000000Z"),
])
def test_timestamp_spellings(text, expected):
    assert map_eve(alert(timestamp=text))["timestamp_utc"] == expected


@pytest.mark.parametrize("text", ["2026-11-12T08:15:02", "2026-11-12 08:15:02+0700", "yesterday", "", None, 1731374102])
def test_unusable_timestamps_are_rejected(text):
    with pytest.raises(EventValidationError):
        parse_eve_time(text)


def test_flow_uses_its_start_time_not_the_time_it_was_logged():
    record = {"timestamp": "2026-11-12T08:31:01.500000+0700", "event_type": "flow",
              "src_ip": "10.0.2.99", "dest_ip": "10.0.1.10", "dest_port": 23, "proto": "TCP",
              "flow": {"start": "2026-11-12T08:30:00.100000+0700", "end": "2026-11-12T08:30:00.100000+0700"}}
    assert map_eve(record)["timestamp_utc"] == "2026-11-12T01:30:00.100000Z"
    del record["flow"]["start"]
    assert map_eve(record)["timestamp_utc"] == "2026-11-12T01:31:01.500000Z"
    assert map_eve(record)["action"] == "flow" and map_eve(record)["severity"] == "info"


def test_flow_without_ports_is_still_an_event():
    record = {"timestamp": "2026-11-12T08:31:01.500000+0700", "event_type": "flow",
              "src_ip": "10.0.2.21", "dest_ip": "10.0.1.2", "proto": "ICMP"}
    assert map_eve(record)["dst_port"] is None


def test_dns_queries_are_kept_and_answers_dropped():
    record = {"timestamp": "2026-11-12T08:20:00.000000+0700", "event_type": "dns", "src_ip": "10.0.2.21",
              "dest_ip": "10.0.1.2", "dest_port": 53, "proto": "UDP",
              "dns": {"type": "query", "rrname": "www.example.com", "rrtype": "A"}}
    assert map_eve(record)["action"] == "dns_query"
    record["dns"]["type"] = "answer"
    assert map_eve(record) is None


def test_unused_record_types_return_none():
    for kind in ("stats", "tls", "fileinfo", "anomaly", None):
        assert map_eve({"timestamp": "2026-11-12T08:20:08.000000+0700", "event_type": kind}) is None


@pytest.mark.parametrize("change", [
    {"src_ip": "not-an-ip"}, {"dest_port": 70000}, {"dest_port": "http"}, {"alert": "oops"}, {"alert": None},
])
def test_broken_alert_records_are_rejected(change):
    with pytest.raises(EventValidationError):
        map_eve(alert(**change))


def test_record_without_timestamp_is_rejected():
    record = alert()
    del record["timestamp"]
    with pytest.raises(EventValidationError):
        map_eve(record)


# ---- broken lines and statistics ---------------------------------------------

def test_broken_lines_are_counted_and_the_reader_goes_on():
    stats = {}
    lines = [
        "\n",
        "{broken json\n",
        '"just a string"\n',
        "[1, 2]\n",
        json.dumps(alert(src_ip="not-an-ip")) + "\n",
        json.dumps({"timestamp": "2026-11-12T08:20:08.000000+0700", "event_type": "stats"}) + "\r\n",
        json.dumps(alert()) + "\r\n",
        json.dumps(alert(2)),
    ]
    found = list(parse_lines(lines, stats))
    assert [e["severity"] for e in found] == ["high", "medium"]
    assert (stats["lines"], stats["events"], stats["ignored"], stats["invalid"]) == (7, 2, 1, 4)


def test_statistics_add_up_when_the_same_dict_is_reused():
    stats = {}
    for _ in range(3):
        list(parse_lines([json.dumps(alert()), "oops"], stats))
    assert (stats["lines"], stats["events"], stats["invalid"]) == (6, 3, 3)


def test_file_written_by_windows_tools_is_read(tmp_path):
    for name, encoding in (("bom.json", "utf-8-sig"), ("utf16.json", "utf-16")):
        path = tmp_path / name
        path.write_text(json.dumps(alert()) + "\n", encoding=encoding)
        (event,) = suricata.parse_file(path)
        assert event["action"] == "alert"


def test_file_with_damaged_bytes_does_not_crash(tmp_path):
    path = tmp_path / "damaged.json"
    path.write_bytes(json.dumps(alert()).encode() + b"\n\xff\xfe\xfa broken \x80\n" + json.dumps(alert(3)).encode() + b"\n")
    stats = {}
    assert [e["severity"] for e in suricata.parse_file(path, stats)] == ["high", "low"]
    assert stats["invalid"] == 1
