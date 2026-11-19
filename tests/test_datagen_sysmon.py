"""Synthetic Sysmon generator and the cross-source pivot scenario."""
import base64
import json
import re
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network

import pytest

from datagen import suricata as gen_eve
from datagen import sysmon as gen_sysmon
from datagen.common import LAB_TZ, Rng, utc_iso
from engine.correlation import detect_incidents
from ingestors import suricata, sysmon

START = datetime(2026, 11, 12, 8, 0, tzinfo=LAB_TZ)
ALLOWED = [ip_network(n) for n in ("10.0.0.0/8", "192.168.0.0/16", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def parse(bundle):
    """Events of both sources, numbered like rows read from storage."""
    events = list(sysmon.parse_text(gen_sysmon.render(bundle.sysmon)))
    events += list(suricata.parse_lines(gen_eve.render(bundle.eve).splitlines(True)))
    for number, event in enumerate(events, start=1):
        event["id"] = number
    return events


def test_time_and_encoding_helpers():
    assert gen_sysmon.sysmon_time(datetime(2026, 11, 12, 8, 20, 3, 512999, tzinfo=LAB_TZ)) == "2026-11-12 01:20:03.512"
    assert gen_sysmon.computer("WS-01") == "WS-01.lab.example"
    payload = gen_sysmon.encoded_command("Write-Output 'SOC lab synthetic test'")
    assert base64.b64decode(payload).decode("utf-16-le") == "Write-Output 'SOC lab synthetic test'"


def test_records_look_like_sysmon_and_are_parseable():
    rng = Rng(1)
    _, process = gen_sysmon.process_entry(rng, START, "WS-01", "alice", "C:\\Windows\\System32\\notepad.exe", "a.txt")
    _, network = gen_sysmon.network_entry(rng, START, "WS-01", "alice", "System", "10.0.2.21", "10.0.1.20", 445)
    assert process["EventID"] == 1 and process["Computer"] == "WS-01.lab.example" and process["User"] == "LAB\\alice"
    assert process["CommandLine"] == "\"C:\\Windows\\System32\\notepad.exe\" a.txt"
    assert re.fullmatch(r"\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}", process["ProcessGuid"])
    assert re.fullmatch(r"SHA256=[0-9A-F]{64}", process["Hashes"])
    assert network["EventID"] == 3 and network["DestinationPort"] == 445 and network["Initiated"] is True
    events = list(sysmon.parse_records([process, network]))
    assert [e["action"] for e in events] == ["process_create", "network_connection"]
    assert events[0]["timestamp_utc"] == "2026-11-12T01:00:00.000000Z"


def test_benign_activity_raises_no_incident():
    bundle = gen_sysmon.benign_activity(Rng(2), START, 180)
    stats = {}
    events = list(sysmon.parse_text(gen_sysmon.render(bundle.sysmon), stats))
    assert bundle.labels == [] and stats["invalid"] == 0 and stats["ignored"] > 10      # event ids 5, 11, 22
    images = {e["process_name"] for e in events if e["action"] == "process_create"}
    assert any("\\AppData\\Local\\Microsoft\\OneDrive\\" in image for image in images)   # look-alike is present
    assert any(e["command_line"] and "-ExecutionPolicy Bypass" in e["command_line"] for e in events)
    assert detect_incidents(parse(bundle)) == []


@pytest.mark.parametrize("variant, severity, events_in_scenario", [("temp", "medium", 3), ("encoded", "high", 1)])
def test_suspicious_process_scenarios(variant, severity, events_in_scenario):
    bundle = gen_sysmon.suspicious_process(Rng(3), START, "WS-01", variant, "sp")
    assert len(bundle.sysmon) == events_in_scenario
    (label,) = bundle.labels
    assert label.expected_rule == "SUSPICIOUS_PROCESS" and label.match == {"hostname": ["WS-01.lab.example"]}
    (incident,) = detect_incidents(parse(bundle))
    assert (incident["rule_id"], incident["severity"]) == ("SUSPICIOUS_PROCESS", severity)
    assert incident["detected_at_utc"] == utc_iso(label.start)
    with pytest.raises(ValueError):
        gen_sysmon.suspicious_process(Rng(3), START, "WS-01", "other", "sp")


def test_port_scan_seen_by_sysmon():
    bundle = gen_sysmon.port_scan(Rng(4), START, "WS-03", "10.0.1.20", list(range(20, 80)), 10, "scan")
    (incident,) = detect_incidents(parse(bundle))
    assert incident["rule_id"] == "INTERNAL_PORT_SCAN" and len(incident["event_ids"]) == 60
    assert incident["dedup_key"] == "INTERNAL_PORT_SCAN|10.0.2.23->10.0.1.20"
    assert bundle.labels[0].sources == ["sysmon"]


def test_pivot_scenario_spans_two_log_sources():
    targets = [("10.0.1.20", 445), ("10.0.1.2", 445), ("10.0.2.21", 3389)]
    bundle = gen_sysmon.pivot(Rng(5), START, "203.0.113.77", "WS-04", targets, "pivot")
    assert len(bundle.sysmon) == 3 and len(bundle.eve) == 2                  # the alert and its flow
    (label,) = bundle.labels
    assert label.sources == ["suricata", "sysmon"] and label.expected_rule == "NETWORK_TO_HOST_PIVOT"
    assert label.match == {"src_ip": ["203.0.113.77", "10.0.2.24"]}
    events = parse(bundle)
    (incident,) = detect_incidents(events)
    assert (incident["rule_id"], incident["severity"]) == ("NETWORK_TO_HOST_PIVOT", "critical")
    assert incident["first_seen_utc"] == utc_iso(label.start) and incident["last_seen_utc"] == utc_iso(label.end)
    assert incident["detected_at_utc"] == utc_iso(label.start + timedelta(seconds=45))
    sources = {event["source_type"] for event in events if event["id"] in incident["event_ids"]}
    assert sources == {"suricata", "sysmon"}


def everything(seed):
    rng = Rng(seed)
    bundle = gen_sysmon.benign_activity(rng.fork("benign"), START, 120)
    bundle.merge(gen_sysmon.suspicious_process(rng.fork("temp"), START + timedelta(minutes=20), "WS-01", "temp", "temp"))
    bundle.merge(gen_sysmon.suspicious_process(rng.fork("enc"), START + timedelta(minutes=50), "WS-02", "encoded", "enc"))
    bundle.merge(gen_sysmon.port_scan(rng.fork("scan"), START + timedelta(minutes=70), "WS-03", "10.0.1.20",
                                      list(range(20, 80)), 10, "scan"))
    bundle.merge(gen_sysmon.pivot(rng.fork("pivot"), START + timedelta(minutes=90), "203.0.113.77", "WS-04",
                                  [("10.0.1.20", 445), ("10.0.1.2", 445), ("10.0.2.21", 3389)], "pivot"))
    return bundle


def test_scenarios_inside_normal_activity_are_all_found_and_nothing_else():
    incidents = detect_incidents(parse(everything(2026)))
    assert sorted((i["rule_id"], i["dedup_key"].split("|")[1]) for i in incidents) == [
        ("INTERNAL_PORT_SCAN", "10.0.2.23->10.0.1.20"),
        ("NETWORK_TO_HOST_PIVOT", "10.0.2.24"),
        ("SUSPICIOUS_PROCESS", "WS-01.lab.example"),
        ("SUSPICIOUS_PROCESS", "WS-02.lab.example"),
    ]


def test_same_seed_same_file_and_only_lab_addresses():
    first, again, other = everything(2026), everything(2026), everything(2027)
    text = gen_sysmon.render(first.sysmon)
    assert text == gen_sysmon.render(again.sysmon) and text != gen_sysmon.render(other.sysmon)
    assert gen_eve.render(first.eve) == gen_eve.render(again.eve)
    addresses = {ip_address(found) for found in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
                                                           text + gen_eve.render(first.eve))}
    assert len(addresses) >= 10
    assert sorted(str(a) for a in addresses if not any(a in network for network in ALLOWED)) == []


def test_demo_command_writes_a_parseable_file(tmp_path, capsys):
    assert gen_sysmon.main(["--out", str(tmp_path / "sysmon.json"), "--seed", "3", "--minutes", "30"]) == 0
    labels = json.loads(capsys.readouterr().out)
    assert [item["scenario_id"] for item in labels] == ["demo-temp-process", "demo-encoded-powershell"]
    stats = {}
    events = list(sysmon.parse_file(tmp_path / "sysmon.json", stats))
    assert stats["invalid"] == 0 and len(events) > 20
    for number, event in enumerate(events, start=1):
        event["id"] = number
    assert [i["rule_id"] for i in detect_incidents(events)] == ["SUSPICIOUS_PROCESS", "SUSPICIOUS_PROCESS"]
