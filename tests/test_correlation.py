"""Unit tests for the correlation engine, rule 1, rule 2 and incident helpers."""
from datetime import datetime, timedelta, timezone

import pytest

from engine.correlation import (
    CorrelationEngine, SlidingWindow, default_rules, detect_incidents,
    detect_with_stats, format_ts,
)
from engine.incident import export_summary, export_summary_from_db, load_incident, save_new_incidents
from engine.net import is_internal
from engine.rules.beaconing import BeaconingRule
from engine.rules.port_scan import PortScanRule
from engine.rules.ssh_brute_force import SSHBruteForceRule
from storage.models import (
    connect, counts, init_db, insert_events, insert_incident, list_events, set_incident_status,
)

T0 = datetime(2026, 11, 12, 2, 0, 0, tzinfo=timezone.utc)
ATTACKER = "192.0.2.10"
TARGET = "10.0.0.5"


class Log:
    """Builds events with increasing ids, like rows read back from storage."""

    def __init__(self):
        self.events = []

    def add(self, offset, action, src_ip=ATTACKER, dst_port=None, source_type="auth_log"):
        self.events.append({
            "id": len(self.events) + 1,
            "timestamp_utc": format_ts(T0 + timedelta(seconds=offset)),
            "source_type": source_type, "src_ip": src_ip, "dst_ip": TARGET,
            "username": "root", "hostname": "lab-host", "action": action,
            "severity": "info", "dst_port": dst_port,
        })
        return self

    def fails(self, offsets, src_ip=ATTACKER):
        for offset in offsets:
            self.add(offset, "ssh_failed", src_ip)
        return self

    def scan(self, ports, step=1.0, start=0.0):
        for i, port in enumerate(ports):
            self.add(start + i * step, "network_connection", dst_port=port, source_type="sysmon")
        return self


    def alerts(self, offsets, signature="LAB MALWARE CnC Beacon", severity="high",
               src_ip="10.0.2.40", dst_ip="203.0.113.200"):
        for offset in offsets:
            self.add(offset, "alert", src_ip=src_ip, dst_port=443, source_type="suricata")
            self.events[-1].update(dst_ip=dst_ip, signature=signature, severity=severity)
        return self


def ssh(events, **kwargs):
    return CorrelationEngine([SSHBruteForceRule()], **kwargs).run(events)


def scan(events, **kwargs):
    return CorrelationEngine([PortScanRule()], **kwargs).run(events)


def beacon(events, **kwargs):
    return CorrelationEngine([BeaconingRule()], **kwargs).run(events)


# ---- sliding window ---------------------------------------------------------

def test_window_keeps_item_exactly_on_the_boundary():
    w = SlidingWindow(60)
    w.add(T0, "a")
    w.add(T0 + timedelta(seconds=60), "b")
    assert w.items() == ["a", "b"]
    w.add(T0 + timedelta(seconds=60, microseconds=1), "c")
    assert w.items() == ["b", "c"]


def test_window_rejects_time_going_backwards():
    w = SlidingWindow(60)
    w.add(T0, "a")
    with pytest.raises(ValueError):
        w.add(T0 - timedelta(seconds=1), "b")


# ---- rule 1: SSH brute force ------------------------------------------------

def test_five_failures_in_exactly_60s_then_success():
    log = Log().fails([0, 15, 30, 45, 60]).add(61, "ssh_success")
    (incident,) = ssh(log.events)
    assert incident.rule_id == "SSH_BRUTE_FORCE"
    assert incident.severity == "critical"
    assert incident.mitre == "T1110"
    assert incident.event_ids == [1, 2, 3, 4, 5, 6]
    assert incident.to_dict()["first_seen_utc"] == "2026-11-12T02:00:00.000000Z"
    assert incident.to_dict()["last_seen_utc"] == "2026-11-12T02:01:01.000000Z"


def test_five_failures_within_59s_detected_but_61s_not():
    assert len(ssh(Log().fails([0, 10, 20, 30, 59]).add(60, "ssh_success").events)) == 1
    assert ssh(Log().fails([0, 10, 20, 30, 61]).add(62, "ssh_success").events) == []


def test_four_failures_are_not_enough():
    assert ssh(Log().fails([0, 1, 2, 3]).add(4, "ssh_success").events) == []


def test_failures_without_success_or_lockout_give_no_incident():
    assert ssh(Log().fails(range(10)).events) == []


def test_lockout_gives_high_severity():
    (incident,) = ssh(Log().fails(range(5)).add(5, "ssh_lockout").events)
    assert incident.severity == "high"


def test_success_from_another_ip_does_not_count():
    log = Log().fails(range(5)).add(5, "ssh_success", src_ip="192.0.2.99")
    assert ssh(log.events) == []


def test_failures_split_over_two_ips_do_not_add_up():
    log = Log().fails([0, 1, 2]).fails([3, 4, 5], src_ip="192.0.2.11").add(6, "ssh_success")
    assert ssh(log.events) == []


def test_success_before_the_failures_does_not_count():
    assert ssh(Log().add(0, "ssh_success").fails(range(1, 6)).events) == []


def test_success_too_long_after_last_failure_does_not_count():
    assert len(ssh(Log().fails(range(5)).add(64, "ssh_success").events)) == 1   # 60s after t=4
    assert ssh(Log().fails(range(5)).add(65, "ssh_success").events) == []       # 61s after t=4


def test_success_resets_the_failure_count_of_a_normal_user():
    # 3 typos, login, 2 typos, login: five failures in 60s but never five in a row
    log = Log().fails([0, 1, 2]).add(3, "ssh_success").fails([4, 5]).add(6, "ssh_success")
    assert ssh(log.events) == []


def test_only_the_first_follow_up_after_a_burst_alerts():
    engine = CorrelationEngine([SSHBruteForceRule()])
    engine.run(Log().fails(range(5)).add(5, "ssh_success").add(6, "ssh_success").events)
    assert engine.stats.raw_alerts == 1


def test_events_in_the_same_second_keep_their_id_order():
    # auth.log only has one-second resolution
    log = Log().fails([0, 0, 0, 0, 0]).add(0, "ssh_success")
    assert len(ssh(log.events)) == 1


def test_out_of_order_events_are_sorted_by_event_time():
    log = Log().add(10, "ssh_success").fails([4, 2, 0, 3, 1])   # arrival order is scrambled
    (incident,) = ssh(log.events)
    assert sorted(incident.event_ids) == [1, 2, 3, 4, 5, 6]
    assert incident.first_seen == T0


def test_event_time_is_used_even_for_logs_from_years_ago():
    log = Log().fails(range(5)).add(5, "ssh_success")
    for event in log.events:
        event["timestamp_utc"] = event["timestamp_utc"].replace("2026", "2019")
    assert len(ssh(log.events)) == 1


# ---- rule 2: port scan ------------------------------------------------------

def test_fifteen_ports_in_30s_detected_fourteen_not():
    (incident,) = scan(Log().scan(range(1, 16), step=2).events)   # t = 0 .. 28
    assert incident.rule_id == "INTERNAL_PORT_SCAN"
    assert incident.mitre == "T1046"
    assert len(incident.event_ids) == 15
    assert scan(Log().scan(range(1, 15)).events) == []


def test_port_scan_window_boundary_30s_vs_31s():
    in_30 = Log().scan(range(1, 15)).add(30, "network_connection", dst_port=99)
    in_31 = Log().scan(range(1, 15)).add(31, "network_connection", dst_port=99)
    assert len(scan(in_30.events)) == 1
    assert scan(in_31.events) == []


def test_same_port_repeated_is_not_a_scan():
    assert scan(Log().scan([443] * 40, step=0.5).events) == []


def test_ports_spread_over_several_targets_are_not_one_scan():
    log = Log().scan(range(1, 16))
    for i, event in enumerate(log.events):
        event["dst_ip"] = f"10.0.0.{i % 2 + 1}"
    assert scan(log.events) == []


def test_events_without_port_or_with_other_action_are_ignored():
    log = Log()
    for port in range(1, 16):
        log.add(port, "alert", dst_port=port, source_type="suricata")
    assert scan(log.events) == []


def test_scan_that_pauses_and_resumes_stays_one_incident_without_duplicate_ids():
    log = Log().scan(range(1, 21), step=1).scan(range(100, 120), step=1, start=100)
    engine = CorrelationEngine([PortScanRule()])
    (incident,) = engine.run(log.events)
    assert sorted(incident.event_ids) == list(range(1, 41))
    assert engine.stats.raw_alerts == 12          # ports 15-20 of each half


def test_scan_stopped_alerting_once_old_ports_leave_the_window():
    # 15 ports at t=0..14, then one new port per 10s: never 15 distinct in 30s again
    log = Log().scan(range(1, 16))
    for i in range(5):
        log.add(60 + i * 10, "network_connection", dst_port=200 + i, source_type="sysmon")
    engine = CorrelationEngine([PortScanRule()])
    (incident,) = engine.run(log.events)
    assert engine.stats.raw_alerts == 1
    assert len(incident.event_ids) == 15


def test_large_scan_is_handled_in_linear_time():
    engine = CorrelationEngine([PortScanRule()])
    (incident,) = engine.run(Log().scan(range(1, 20001), step=0.001).events)
    assert len(incident.event_ids) == 20000
    assert engine.stats.raw_alerts == 20000 - 14


def test_internal_only_option_ignores_scans_that_touch_the_internet():
    events = Log().scan(range(1, 16)).events
    for event in events:
        event["src_ip"] = "203.0.113.9"                    # documentation range = "Internet"
    assert len(CorrelationEngine([PortScanRule()]).run(events)) == 1
    assert CorrelationEngine([PortScanRule(internal_only=True)]).run(events) == []
    for event in events:
        event["src_ip"] = "10.0.2.99"
    assert len(CorrelationEngine([PortScanRule(internal_only=True)]).run(events)) == 1


def test_is_internal_knows_documentation_ranges_are_not_internal():
    assert is_internal("10.0.1.10") and is_internal("192.168.1.5") and is_internal("172.16.0.1")
    assert not is_internal("192.0.2.10") and not is_internal("203.0.113.50")
    assert not is_internal("198.51.100.23")
    assert not is_internal(None) and not is_internal("") and not is_internal("not-an-ip")


# ---- rule 5: beaconing -------------------------------------------------------

def test_six_alerts_one_minute_apart_are_a_beacon_five_are_not():
    (incident,) = beacon(Log().alerts([0, 60, 120, 180, 240, 300]).events)
    assert incident.rule_id == "MALWARE_BEACONING"
    assert incident.severity == "high" and incident.mitre == "T1071"
    assert incident.event_ids == [1, 2, 3, 4, 5, 6]
    assert incident.detected_at == T0 + timedelta(seconds=300)
    assert beacon(Log().alerts([0, 60, 120, 180, 240]).events) == []


def test_beacon_tolerates_30_percent_jitter_but_not_more():
    assert len(beacon(Log().alerts([0, 60, 120, 180, 240, 318]).events)) == 1   # last gap 78 = +30 %
    assert beacon(Log().alerts([0, 60, 120, 180, 240, 319]).events) == []       # last gap 79 > +30 %
    assert len(beacon(Log().alerts([0, 60, 120, 180, 240, 282]).events)) == 1   # last gap 42 = -30 %
    assert beacon(Log().alerts([0, 60, 120, 180, 240, 281]).events) == []       # last gap 41 < -30 %


def test_burst_of_alerts_and_irregular_alerts_are_not_a_beacon():
    assert beacon(Log().alerts([0, 1, 2, 3, 4, 5, 6, 7]).events) == []            # gaps under 5 s
    assert beacon(Log().alerts([0, 20, 200, 230, 600, 610, 900]).events) == []    # no rhythm


def test_low_severity_alerts_and_other_signatures_do_not_count():
    assert beacon(Log().alerts(range(0, 600, 60), severity="low").events) == []
    mixed = Log().alerts([0, 120, 240], signature="A").alerts([60, 180, 300], signature="B")
    assert beacon(mixed.events) == []


def test_beacon_needs_the_same_source_and_destination():
    split = (Log().alerts([0, 120, 240], dst_ip="203.0.113.200")
             .alerts([60, 180, 300], dst_ip="203.0.113.201"))
    assert beacon(split.events) == []


def test_long_beacon_is_one_incident_even_when_slower_than_the_default_cooldown():
    engine = CorrelationEngine([BeaconingRule()])              # engine cooldown is 300 s
    (incident,) = engine.run(Log().alerts(range(0, 600 * 12, 600)).events)   # one every 10 min
    assert len(incident.event_ids) == 12
    assert engine.stats.raw_alerts == 7 and engine.stats.incidents == 1


def test_beacon_window_boundary_3600s_vs_3601s():
    assert len(beacon(Log().alerts(range(0, 3601, 720)).events)) == 1         # six alerts span 3600 s
    assert beacon(Log().alerts([0, 720, 1440, 2160, 2880, 3601]).events) == []


def test_missed_beacon_only_delays_detection():
    # the beacon at t=180 is lost; the pattern is steady again from t=240
    (incident,) = beacon(Log().alerts([0, 60, 120, 240, 300, 360, 420, 480, 540]).events)
    assert incident.detected_at == T0 + timedelta(seconds=540)


# ---- dedup / cooldown / stats ----------------------------------------------

def test_long_scan_is_one_incident_and_savings_are_counted():
    engine = CorrelationEngine([PortScanRule()])
    (incident,) = engine.run(Log().scan(range(1, 101), step=0.1).events)
    assert engine.stats.raw_alerts == 86          # every hit from the 15th port on
    assert engine.stats.incidents == 1
    assert incident.raw_alert_count == 86
    assert len(incident.event_ids) == 100
    assert engine.stats.dedup_savings == pytest.approx(1 - 1 / 86)


def test_detected_at_is_the_first_alert_and_does_not_move_when_merging():
    (incident,) = scan(Log().scan(range(1, 41), step=0.5).events)
    found = incident.to_dict()
    assert found["first_seen_utc"] == "2026-11-12T02:00:00.000000Z"
    assert found["detected_at_utc"] == "2026-11-12T02:00:07.000000Z"   # 15th port
    assert found["last_seen_utc"] == "2026-11-12T02:00:19.500000Z"


def test_cooldown_boundary_300s_merges_301s_opens_new_incident():
    def two_attacks(gap):
        return (Log().fails(range(5)).add(5, "ssh_lockout")
                .fails([5 + gap - 5 + i for i in range(5)]).add(5 + gap, "ssh_lockout").events)
    assert len(ssh(two_attacks(300))) == 1
    assert len(ssh(two_attacks(301))) == 2


def test_merged_incident_takes_the_highest_severity():
    log = Log().fails(range(5)).add(5, "ssh_lockout").fails(range(10, 15)).add(15, "ssh_success")
    (incident,) = ssh(log.events)
    assert incident.severity == "critical"
    assert incident.raw_alert_count == 2
    assert len(incident.event_ids) == 12


def test_merged_incident_keeps_title_and_summary_of_the_most_severe_alert():
    log = Log().fails(range(5)).add(5, "ssh_success").fails(range(10, 15)).add(15, "ssh_lockout")
    (incident,) = ssh(log.events)
    assert incident.severity == "critical"
    assert "login succeeded" in incident.title
    assert "successful login" in incident.summary


def test_event_without_id_is_rejected_with_a_clear_error():
    events = Log().fails(range(5)).events
    del events[0]["id"]
    with pytest.raises(ValueError, match="id"):
        ssh(events)


def test_different_attackers_are_separate_incidents():
    log = (Log().fails(range(5)).add(5, "ssh_success")
           .fails(range(5), src_ip="192.0.2.11").add(5, "ssh_success", src_ip="192.0.2.11"))
    assert len(ssh(log.events)) == 2


def test_engine_skips_events_with_bad_timestamp():
    log = Log().fails(range(5)).add(5, "ssh_success")
    log.events.append({"id": 99, "timestamp_utc": "not-a-date", "action": "ssh_failed"})
    engine = CorrelationEngine([SSHBruteForceRule()])
    assert len(engine.run(log.events)) == 1
    assert engine.stats.skipped_events == 1


# ---- contract, storage, summary --------------------------------------------

def test_detect_incidents_returns_contract_shaped_dicts():
    events = Log().fails(range(5)).add(5, "ssh_success").scan(range(1, 16), start=100).events
    incidents = detect_incidents(events)
    assert [i["rule_id"] for i in incidents] == ["SSH_BRUTE_FORCE", "INTERNAL_PORT_SCAN"]
    for incident in incidents:
        assert {"rule_id", "title", "severity", "status", "assigned_analyst", "first_seen_utc",
                "last_seen_utc", "summary", "event_ids"} <= set(incident)
        assert incident["status"] == "New" and incident["assigned_analyst"] is None
    _, stats = detect_with_stats(events)
    assert stats["raw_alerts"] == 2 and stats["incidents"] == 2


def test_default_rules_contain_rules_1_2_and_5():
    ids = {rule.rule_id for rule in default_rules()}
    assert {"SSH_BRUTE_FORCE", "INTERNAL_PORT_SCAN", "MALWARE_BEACONING"} <= ids


def test_stats_are_also_counted_per_rule():
    events = (Log().fails(range(5)).add(5, "ssh_success").scan(range(1, 21), start=100)
              .alerts(range(1000, 1700, 100)).events)
    _, stats = detect_with_stats(events)
    assert stats["by_rule"] == {
        "INTERNAL_PORT_SCAN": {"raw_alerts": 6, "incidents": 1},
        "MALWARE_BEACONING": {"raw_alerts": 2, "incidents": 1},
        "SSH_BRUTE_FORCE": {"raw_alerts": 1, "incidents": 1},
    }
    assert stats["raw_alerts"] == 9 and stats["incidents"] == 3


def test_rerun_on_same_database_creates_no_duplicates(tmp_path):
    raw = Log().fails(range(5)).add(5, "ssh_success").events
    with connect(tmp_path / "soc.db") as db:
        init_db(db)
        insert_events(db, [{k: v for k, v in e.items() if k != "id"} for e in raw])
        assert save_new_incidents(db, detect_incidents(list_events(db))) == 1
        set_incident_status(db, 1, "In Progress", "analyst1")
        assert save_new_incidents(db, detect_incidents(list_events(db))) == 0
        assert counts(db) == (6, 1)
        assert db.execute("SELECT status FROM incidents").fetchone()[0] == "In Progress"


def test_export_summary_mentions_the_key_facts():
    events = Log().fails(range(5)).add(5, "ssh_success").events
    (incident,) = detect_incidents(events)
    text = export_summary({**incident, "incident_id": 7}, events)
    assert "# Incident #7: SSH brute-force detected" in text
    assert "T1110" in text and ATTACKER in text
    assert "- ssh_failed: 5" in text and "- ssh_success: 1" in text
    assert "Severity: critical" in text
    assert "## Suggested next steps" in text and "1. If a login succeeded" in text


def test_two_new_incidents_sharing_an_event_are_both_saved(tmp_path):
    raw = Log().fails(range(3)).events
    with connect(tmp_path / "soc.db") as db:
        init_db(db)
        insert_events(db, [{k: v for k, v in e.items() if k != "id"} for e in raw])
        base = dict(rule_id="R", title="t", severity="low",
                    first_seen_utc=raw[0]["timestamp_utc"], last_seen_utc=raw[2]["timestamp_utc"])
        found = [{**base, "event_ids": [1, 2]}, {**base, "event_ids": [2, 3]}]
        assert save_new_incidents(db, found) == 2
        assert save_new_incidents(db, found) == 0
        assert save_new_incidents(db, [{**base, "rule_id": "OTHER", "event_ids": [1]}]) == 1


def test_summary_of_a_stored_incident(tmp_path):
    raw = Log().fails(range(30)).add(30, "ssh_success").events
    with connect(tmp_path / "soc.db") as db:
        init_db(db)
        insert_events(db, [{k: v for k, v in e.items() if k != "id"} for e in raw])
        (found,) = detect_incidents(list_events(db))
        incident_id = insert_incident(db, found)
        set_incident_status(db, incident_id, "In Progress", "analyst1")
        incident, events = load_incident(db, incident_id)
        assert incident["event_ids"] == list(range(1, 32)) and len(events) == 31
        text = export_summary_from_db(db, incident_id)
        with pytest.raises(ValueError):
            load_incident(db, 999)
    assert f"# Incident #{incident_id}:" in text
    assert "MITRE ATT&CK: T1110" in text          # looked up from the rule, not stored in the DB
    assert "Status: In Progress" in text and "Assigned analyst: analyst1" in text
    assert "- ... 11 more event(s) ..." in text
    timeline = text.split("## Timeline\n")[1].split("\n\n")[0].splitlines()
    assert len(timeline) == 21                       # 10 first + "... more ..." + 10 last
    assert timeline[-1].endswith("ssh_success 192.0.2.10 -> 10.0.0.5 user=root")
