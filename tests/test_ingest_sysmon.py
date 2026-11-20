"""Sysmon ingestor: export layouts, time handling, broken records, statistics."""
import json
from pathlib import Path

import pytest

from ingestors import sysmon
from ingestors.sysmon import flatten, parse_records, parse_text
from normalizer.schema import REQUIRED_FIELDS, EventValidationError
from normalizer.sysmon_mapper import map_sysmon, parse_sysmon_time
from storage.models import connect, init_db, insert_events, list_events

SAMPLE = Path(__file__).parent / "data" / "sysmon_sample.json"

PROCESS = {"EventID": 1, "Computer": "WS-01.lab.example", "UtcTime": "2026-11-12 01:20:03.512",
           "Image": "C:\\Users\\alice\\AppData\\Local\\Temp\\invoice_viewer.exe",
           "CommandLine": "\"C:\\Users\\alice\\AppData\\Local\\Temp\\invoice_viewer.exe\" /quiet",
           "User": "LAB\\alice", "ParentImage": "C:\\Windows\\explorer.exe"}
NETWORK = {"EventID": 3, "Computer": "WS-04.lab.example", "UtcTime": "2026-11-12 01:45:10.100",
           "Image": "System", "User": "NT AUTHORITY\\SYSTEM", "Protocol": "tcp", "Initiated": True,
           "SourceIp": "10.0.2.24", "SourcePort": 49812, "DestinationIp": "10.0.1.20", "DestinationPort": 445}


def one(record):
    (event,) = parse_records([record])
    return event


# ---- the sample file --------------------------------------------------------

def test_sample_file_counts_and_actions():
    stats = {}
    found = list(sysmon.parse_file(SAMPLE, stats))
    assert [e["action"] for e in found] == [
        "process_create", "network_connection", "process_create", "network_connection", "network_connection"]
    assert (stats["lines"], stats["events"], stats["ignored"], stats["invalid"]) == (11, 5, 2, 4)
    assert stats["reasons"]["ignored: Sysmon event id 5"] == 1
    assert stats["reasons"]["invalid: not valid JSON"] == 1
    for event in found:
        assert set(REQUIRED_FIELDS) <= set(event)
        assert event["source_type"] == "sysmon" and event["severity"] == "info"


def test_sample_file_goes_into_storage(tmp_path):
    with connect(tmp_path / "soc.db") as db:
        init_db(db)
        assert insert_events(db, sysmon.parse_file(SAMPLE)) == 5
        stored = list_events(db)
    assert [e["timestamp_utc"][11:19] for e in stored] == ["01:20:03", "01:30:00", "01:45:10", "01:46:00", "01:47:00"]
    assert stored[0]["raw"]["ParentImage"] == "C:\\Windows\\explorer.exe"


# ---- the two event types ------------------------------------------------------

def test_process_creation_fields():
    event = one(PROCESS)
    assert event["action"] == "process_create"
    assert event["timestamp_utc"] == "2026-11-12T01:20:03.512000Z"         # UtcTime is UTC already
    assert event["hostname"] == "WS-01.lab.example" and event["username"] == "LAB\\alice"
    assert event["process_name"] == "C:\\Users\\alice\\AppData\\Local\\Temp\\invoice_viewer.exe"
    assert event["command_line"].endswith("invoice_viewer.exe\" /quiet")
    assert event["src_ip"] is None and event["dst_ip"] is None and event["dst_port"] is None


def test_network_connection_fields():
    event = one(NETWORK)
    assert event["action"] == "network_connection"
    assert (event["src_ip"], event["dst_ip"], event["dst_port"]) == ("10.0.2.24", "10.0.1.20", 445)
    assert event["process_name"] == "System" and event["command_line"] is None
    assert event["raw"]["Initiated"] is True


def test_numbers_written_as_text_are_accepted():
    event = one({**NETWORK, "EventID": "3", "DestinationPort": "3389"})
    assert event["dst_port"] == 3389


def test_other_event_ids_are_ignored_and_counted():
    stats = {}
    records = [{**PROCESS, "EventID": other} for other in (5, 11, 22, 13)]
    assert list(parse_records(records, stats)) == []
    assert stats["ignored"] == 4 and stats["invalid"] == 0


@pytest.mark.parametrize("record, reason", [
    ({**PROCESS, "EventID": "one"}, "event id is not a number"),
    ({**PROCESS, "EventID": None}, "event id is not a number"),
    ({k: v for k, v in PROCESS.items() if k != "Image"}, "process event without Image"),
    ({k: v for k, v in NETWORK.items() if k != "SourceIp"}, "network event without addresses"),
    ({**NETWORK, "DestinationIp": "not-an-ip"}, "dst_ip is not a valid"),
    ({**NETWORK, "DestinationPort": 70000}, "dst_port out of range"),
    ({**PROCESS, "UtcTime": "not a time"}, "unreadable UtcTime"),
    ({k: v for k, v in PROCESS.items() if k != "UtcTime"}, "no UtcTime and no system time"),
    ("just text", "not a JSON object"),
    ([1, 2], "not a JSON object"),
])
def test_broken_records_are_counted_with_a_reason(record, reason):
    stats = {}
    assert list(parse_records([record], stats)) == []
    assert stats["invalid"] == 1 and stats["events"] == 0
    assert any(reason in text for text in stats["reasons"])


# ---- time ----------------------------------------------------------------------

@pytest.mark.parametrize("utc_time, system_time, expected", [
    ("2026-11-12 01:20:03.512", None, "2026-11-12T01:20:03.512000+00:00"),
    ("2026-11-12 01:20:03", None, "2026-11-12T01:20:03+00:00"),
    ("2026-11-12 01:20:03.512", "2020-01-01T00:00:00Z", "2026-11-12T01:20:03.512000+00:00"),   # UtcTime wins
    (None, "2026-11-12T01:46:00.1234567Z", "2026-11-12T01:46:00.123456+00:00"),                # 7 decimals
    (None, "2026-11-12T08:46:00.500000+07:00", "2026-11-12T08:46:00.500000+07:00"),
    (None, "/Date(1794447960000)/", "2026-11-12T01:46:00+00:00"),                              # PowerShell 5
    ("", "2026-11-12T01:46:00Z", "2026-11-12T01:46:00+00:00"),
])
def test_time_sources(utc_time, system_time, expected):
    assert parse_sysmon_time(utc_time, system_time).isoformat() == expected


@pytest.mark.parametrize("utc_time, system_time", [
    (None, None), ("", ""), ("12/11/2026 01:20", None), (None, "2026-11-12T01:46:00"), (None, "soon")])
def test_unusable_times_are_rejected(utc_time, system_time):
    with pytest.raises(EventValidationError):
        parse_sysmon_time(utc_time, system_time)


# ---- export layouts ------------------------------------------------------------

def test_evtx_dump_layout():
    data = {k: v for k, v in NETWORK.items() if k not in ("EventID", "Computer")}
    record = {"Event": {"System": {"EventID": {"#text": 3, "#attributes": {"Qualifiers": 0}},
                                   "TimeCreated": {"#attributes": {"SystemTime": "2026-11-12T01:45:10.1001234Z"}},
                                   "Computer": "WS-04.lab.example"},
                        "EventData": data}}
    assert flatten(record)[0] == 3
    event = one(record)
    assert (event["action"], event["hostname"], event["dst_port"]) == ("network_connection", "WS-04.lab.example", 445)
    assert event["timestamp_utc"] == "2026-11-12T01:45:10.100000Z"


def test_winlogbeat_layout_uses_the_record_timestamp_when_utctime_is_missing():
    data = {k: v for k, v in PROCESS.items() if k not in ("EventID", "Computer", "UtcTime")}
    record = {"@timestamp": "2026-11-12T01:20:04.000Z",
              "winlog": {"event_id": "1", "computer_name": "WS-01.lab.example", "event_data": data}}
    event = one(record)
    assert (event["action"], event["hostname"]) == ("process_create", "WS-01.lab.example")
    assert event["timestamp_utc"] == "2026-11-12T01:20:04.000000Z"


def test_powershell_get_winevent_layout_reads_the_message_text():
    message = ("Network connection detected:\r\nRuleName: -\r\nUtcTime: 2026-11-12 01:45:10.100\r\n"
               "ProcessGuid: {0a1b2c3d-0001-0002-0003-00000000a002}\r\nProcessId: 4\r\nImage: C:\\Windows\\System32\\mstsc.exe\r\n"
               "User: LAB\\dave\r\nProtocol: tcp\r\nInitiated: true\r\nSourceIp: 10.0.2.24\r\nSourcePort: 49812\r\n"
               "DestinationIp: 10.0.2.21\r\nDestinationPort: 3389")
    record = {"Id": 3, "MachineName": "WS-04.lab.example", "TimeCreated": "/Date(1794447910100)/", "Message": message}
    event = one(record)
    assert (event["src_ip"], event["dst_ip"], event["dst_port"]) == ("10.0.2.24", "10.0.2.21", 3389)
    assert event["process_name"] == "C:\\Windows\\System32\\mstsc.exe" and event["username"] == "LAB\\dave"
    assert event["timestamp_utc"] == "2026-11-12T01:45:10.100000Z"


def test_map_sysmon_can_be_called_directly():
    assert map_sysmon(1, PROCESS, "WS-01.lab.example")["action"] == "process_create"
    assert map_sysmon(7, PROCESS, "WS-01.lab.example") is None


# ---- file formats --------------------------------------------------------------

def test_json_array_as_written_by_convertto_json(tmp_path):
    path = tmp_path / "export.json"
    path.write_text(json.dumps([PROCESS, NETWORK, {**PROCESS, "EventID": 5}], indent=4), encoding="utf-8")
    stats = {}
    assert [e["action"] for e in sysmon.parse_file(path, stats)] == ["process_create", "network_connection"]
    assert (stats["lines"], stats["events"], stats["ignored"]) == (3, 2, 1)


def test_single_object_file_and_empty_file(tmp_path):
    path = tmp_path / "one.json"
    path.write_text(json.dumps(PROCESS, indent=2), encoding="utf-8")
    assert [e["action"] for e in sysmon.parse_file(path)] == ["process_create"]
    path.write_text("", encoding="utf-8")
    stats = {}
    assert list(sysmon.parse_file(path, stats)) == [] and stats["lines"] == 0


def test_json_lines_with_a_broken_line_and_windows_line_endings():
    text = json.dumps(PROCESS) + "\r\n" + '{"EventID": 1, "Image": "C:\\\\Win' + "\r\n\r\n" + json.dumps(NETWORK) + "\r\n"
    stats = {}
    assert [e["action"] for e in parse_text(text, stats)] == ["process_create", "network_connection"]
    assert (stats["lines"], stats["events"], stats["invalid"]) == (3, 2, 1)


def test_utf16_file_from_windows_powershell(tmp_path):
    path = tmp_path / "utf16.json"
    path.write_text(json.dumps([PROCESS]), encoding="utf-16")
    assert [e["action"] for e in sysmon.parse_file(path)] == ["process_create"]


def test_statistics_add_up_when_the_same_dict_is_reused():
    stats = {}
    for _ in range(2):
        list(parse_records([PROCESS, {**PROCESS, "EventID": 5}, "oops"], stats))
    assert (stats["lines"], stats["events"], stats["ignored"], stats["invalid"]) == (6, 2, 2, 2)
