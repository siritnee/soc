"""Synthetic auth.log and Suricata generators: reproducible, lab-only addresses,
and scenarios that really contain what their label says."""
import random
import re
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network

import pytest

from datagen import auth_log as gen_auth
from datagen import suricata as gen_eve
from datagen.common import LAB_TZ, Label, LogBundle, Rng, in_file_order, utc_iso
from ingestors import auth_log, suricata

START = datetime(2026, 11, 12, 8, 0, tzinfo=LAB_TZ)
ALLOWED = [ip_network(n) for n in ("10.0.0.0/8", "192.168.0.0/16", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def parse_auth(bundle):
    return list(auth_log.parse_lines(gen_auth.render(bundle.auth).splitlines(True), year=2026))


def parse_eve(bundle):
    return list(suricata.parse_lines(gen_eve.render(bundle.eve).splitlines(True)))


def with_ids(events):
    for number, event in enumerate(events, start=1):
        event["id"] = number
    return events


def seconds(event):
    return datetime.fromisoformat(event["timestamp_utc"].replace("Z", "+00:00")).timestamp()


# ---- shared helpers ----------------------------------------------------------

def test_rng_is_reproducible_and_built_on_random_random():
    assert [Rng(5).random() for _ in range(3)] != [Rng(6).random() for _ in range(3)]
    first, second, plain = Rng(5), Rng(5), random.Random(5)
    assert [first.random() for _ in range(5)] == [second.random() for _ in range(5)] == [plain.random() for _ in range(5)]
    rng = Rng(5)
    assert all(3 <= rng.randint(3, 6) <= 6 for _ in range(200))
    assert {rng.randint(3, 6) for _ in range(200)} == {3, 4, 5, 6}
    assert sorted(rng.shuffled(range(10))) == list(range(10))
    assert re.fullmatch(r"[0-9a-f]{12}", rng.token(12))


def test_fork_gives_independent_streams():
    parent = Rng(5)
    before = parent.fork("auth").random()
    parent.random()                                   # using the parent must not disturb the fork
    assert parent.fork("auth").random() == before
    assert parent.fork("auth").random() != parent.fork("eve").random()


def test_label_and_file_order_helpers():
    label = Label("s1", "port_scan", True, "INTERNAL_PORT_SCAN", START, START + timedelta(seconds=5),
                  {"src_ip": ["10.0.2.99"]}, ["suricata"], "demo")
    assert label.to_dict()["start_utc"] == "2026-11-12T01:00:00.000000Z" == utc_iso(START)
    assert label.to_dict()["expected_rule"] == "INTERNAL_PORT_SCAN"
    entries = [(START + timedelta(seconds=2), "c"), (START, "a"), (START, "b")]
    assert [text for _, text in in_file_order(entries)] == ["a", "b", "c"]
    merged = LogBundle(auth=[(START, "x")]).merge(LogBundle(auth=[(START, "y")], labels=[label]))
    assert len(merged.auth) == 2 and merged.labels == [label]


def test_syslog_stamp_has_no_year_and_pads_the_day():
    assert gen_auth.stamp(datetime(2026, 11, 2, 1, 40, 3, tzinfo=LAB_TZ)) == "Nov  2 01:40:03"
    assert gen_auth.stamp(datetime(2026, 11, 12, 1, 40, 3, 999999, tzinfo=LAB_TZ)) == "Nov 12 01:40:03"
    assert gen_eve.eve_time(datetime(2026, 11, 12, 8, 15, 2, 123456, tzinfo=LAB_TZ)) == "2026-11-12T08:15:02.123456+0700"


# ---- auth.log scenarios --------------------------------------------------------

def test_brute_force_that_ends_in_a_login():
    bundle = gen_auth.brute_force(Rng(1), START, "203.0.113.50", "bastion-01", ["admin", "root", "deploy"],
                                  12, "success", "bf")
    events = [e for e in parse_auth(bundle) if e["src_ip"] == "203.0.113.50"]
    assert [e["action"] for e in events].count("ssh_failed") == 12
    assert [e["action"] for e in events].count("ssh_invalid_user") == 4        # "admin" does not exist
    assert events[-1]["action"] == "ssh_success" and events[-1]["username"] == "deploy"
    assert {e["hostname"] for e in events} == {"bastion-01"}
    (label,) = bundle.labels
    assert label.malicious and label.expected_rule == "SSH_BRUTE_FORCE" and label.kind == "ssh_brute_force"
    assert utc_iso(label.start) == events[0]["timestamp_utc"] == "2026-11-12T01:00:00.000000Z"
    assert utc_iso(label.end) == events[-1]["timestamp_utc"]
    assert label.match == {"src_ip": ["203.0.113.50"]}


def test_brute_force_that_ends_in_a_lockout_keeps_the_attacker_ip():
    bundle = gen_auth.brute_force(Rng(2), START, "198.51.100.23", "web-01", ["alice"], 8, "lockout", "lock")
    events = parse_auth(bundle)
    locks = [e for e in events if e["action"] == "ssh_lockout"]
    assert len(locks) == 3                                                    # first lock + 2 later tries
    assert {e["src_ip"] for e in locks} == {"198.51.100.23"} and {e["username"] for e in locks} == {"alice"}
    assert [e["action"] for e in events].count("ssh_failed") == 10
    assert utc_iso(bundle.labels[0].end) == locks[-1]["timestamp_utc"]


def test_brute_force_without_outcome_expects_no_incident():
    bundle = gen_auth.brute_force(Rng(3), START, "203.0.113.51", "db-01", ["root"], 9, "none", "quit")
    assert bundle.labels[0].expected_rule is None and bundle.labels[0].malicious
    assert {e["action"] for e in parse_auth(bundle)} == {"ssh_failed"}
    with pytest.raises(ValueError):
        gen_auth.brute_force(Rng(3), START, "203.0.113.51", "db-01", ["root"], 9, "maybe", "bad")


def test_typo_login_is_labelled_harmless():
    bundle = gen_auth.typo_login(Rng(4), START, "web-01", "alice", "10.0.2.21", 3, "typo")
    actions = [e["action"] for e in parse_auth(bundle)]
    assert actions[:4] == ["ssh_failed", "ssh_failed", "ssh_failed", "ssh_success"]
    (label,) = bundle.labels
    assert not label.malicious and label.expected_rule is None and label.kind == "decoy"


def test_benign_activity_never_looks_like_brute_force():
    bundle = gen_auth.benign_activity(Rng(5), START, 180)
    stats = {}
    events = list(auth_log.parse_lines(gen_auth.render(bundle.auth).splitlines(True), stats, year=2026))
    assert bundle.labels == [] and len(events) > 30
    assert {"ssh_success", "sudo_command"} <= {e["action"] for e in events}
    assert stats["ignored"] > 20 and stats["invalid"] == 0                    # cron and session lines
    failures = {}
    for event in events:
        if event["action"] == "ssh_failed":
            failures.setdefault(event["src_ip"], []).append(seconds(event))
    for times in failures.values():
        assert all(later - earlier > 60 for earlier, later in zip(times, times[4:]))


# ---- Suricata scenarios --------------------------------------------------------

def test_port_scan_scenario():
    ports = list(range(1, 201))
    bundle = gen_eve.port_scan(Rng(6), START, "10.0.2.99", "10.0.1.10", ports, 20, "scan")
    events = parse_eve(bundle)
    assert {e["action"] for e in events} == {"flow"} and len(events) == 200
    assert sorted(e["dst_port"] for e in events) == ports
    assert {(e["src_ip"], e["dst_ip"]) for e in events} == {("10.0.2.99", "10.0.1.10")}
    times = sorted(seconds(e) for e in events)
    assert times[-1] - times[0] <= 20.1
    (label,) = bundle.labels
    assert label.expected_rule == "INTERNAL_PORT_SCAN" and label.malicious
    assert utc_iso(label.start) == min(e["timestamp_utc"] for e in events)
    assert utc_iso(label.end) == max(e["timestamp_utc"] for e in events)
    # Suricata logs a flow about a minute after it started, so the file is not in event order.
    logged = [record["timestamp"] for _, record in in_file_order(bundle.eve)]
    started = [record["flow"]["start"] for _, record in in_file_order(bundle.eve)]
    assert logged == sorted(logged) and all(a < b for a, b in zip(started, logged))


def test_harmless_port_look_alike_is_labelled_as_such():
    bundle = gen_eve.port_scan(Rng(6), START, "10.0.2.10", "10.0.1.11", list(range(5000, 5010)), 20, "inventory",
                               malicious=False)
    (label,) = bundle.labels
    assert not label.malicious and label.expected_rule is None and label.kind == "decoy"


def test_beaconing_scenario_is_regular():
    bundle = gen_eve.beaconing(Rng(7), START, "10.0.2.40", "203.0.113.200", 443, 60, 30, "beacon")
    alerts = [e for e in parse_eve(bundle) if e["action"] == "alert"]
    assert len(alerts) == 30 and {e["severity"] for e in alerts} == {"high"}
    assert {e["signature"] for e in alerts} == {"LAB MALWARE Generic CnC beacon over HTTPS"}
    times = sorted(seconds(e) for e in alerts)
    gaps = [later - earlier for earlier, later in zip(times, times[1:])]
    assert all(54 <= gap <= 66 for gap in gaps)                               # 60 s +- 10 %
    assert len({round(gap, 3) for gap in gaps}) > 20                          # jittered, not a metronome
    assert bundle.labels[0].expected_rule == "MALWARE_BEACONING"


def test_repeated_alert_look_alike():
    gaps = [20, 180, 35, 400, 60, 15, 240]
    bundle = gen_eve.repeated_alerts(Rng(8), START, "10.0.2.22", "192.0.2.80", gaps, gen_eve.SIG_CLEARTEXT, "noise")
    alerts = parse_eve(bundle)
    assert len(alerts) == 8 and {e["severity"] for e in alerts} == {"medium"}
    assert not bundle.labels[0].malicious


def test_benign_traffic_has_the_record_types_the_parser_must_cope_with():
    bundle = gen_eve.benign_traffic(Rng(9), START, 60)
    stats = {}
    events = list(suricata.parse_lines(gen_eve.render(bundle.eve).splitlines(True), stats))
    assert {"flow", "dns_query", "http_request", "alert"} <= {e["action"] for e in events}
    assert stats["ignored"] == 3 and stats["invalid"] == 0                    # three "stats" records
    assert {e["severity"] for e in events if e["action"] == "alert"} == {"low"}
    ports = {}
    for event in events:
        if event["action"] == "flow":
            ports.setdefault((event["src_ip"], event["dst_ip"]), set()).add(event["dst_port"])
    assert max(len(found) for found in ports.values()) < 15                   # nothing scan-like


# ---- rules of the project ------------------------------------------------------

def everything(seed):
    rng = Rng(seed)
    bundle = gen_auth.benign_activity(rng.fork("auth"), START, 120)
    bundle.merge(gen_auth.brute_force(rng.fork("bf"), START + timedelta(minutes=40), "203.0.113.50", "bastion-01",
                                      ["admin", "root", "deploy"], 12, "success", "bf"))
    bundle.merge(gen_auth.typo_login(rng.fork("typo"), START + timedelta(minutes=70), "web-01", "alice", "10.0.2.21", 3, "typo"))
    bundle.merge(gen_eve.benign_traffic(rng.fork("eve"), START, 120))
    bundle.merge(gen_eve.port_scan(rng.fork("scan"), START + timedelta(minutes=30), "10.0.2.99", "10.0.1.10",
                                   list(range(1, 201)), 20, "scan"))
    bundle.merge(gen_eve.beaconing(rng.fork("beacon"), START + timedelta(minutes=10), "10.0.2.40", "203.0.113.200",
                                   443, 60, 30, "beacon"))
    return bundle


def test_same_seed_same_files_different_seed_different_files():
    first, again, other = everything(2026), everything(2026), everything(2027)
    assert gen_auth.render(first.auth) == gen_auth.render(again.auth)
    assert gen_eve.render(first.eve) == gen_eve.render(again.eve)
    assert gen_auth.render(first.auth) != gen_auth.render(other.auth)
    assert gen_eve.render(first.eve) != gen_eve.render(other.eve)


def test_only_private_and_documentation_addresses_are_used():
    bundle = everything(2026)
    text = gen_auth.render(bundle.auth) + gen_eve.render(bundle.eve)
    addresses = {ip_address(found) for found in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text)}
    assert len(addresses) > 10
    outside = sorted(str(a) for a in addresses if not any(a in network for network in ALLOWED))
    assert outside == []


def test_engine_finds_the_attacks_and_nothing_else():
    """Cross-module check; runs once the correlation engine is in the repo."""
    correlation = pytest.importorskip("engine.correlation")
    bundle = everything(2026)
    events = with_ids(parse_auth(bundle) + parse_eve(bundle))
    incidents = correlation.detect_incidents(events)
    assert sorted(i["rule_id"] for i in incidents) == ["INTERNAL_PORT_SCAN", "MALWARE_BEACONING", "SSH_BRUTE_FORCE"]
    by_rule = {i["rule_id"]: i for i in incidents}
    assert by_rule["SSH_BRUTE_FORCE"]["dedup_key"].endswith("203.0.113.50")
    assert by_rule["INTERNAL_PORT_SCAN"]["dedup_key"].endswith("10.0.2.99->10.0.1.10")
    assert by_rule["MALWARE_BEACONING"]["dedup_key"].endswith("10.0.2.40->203.0.113.200")


def test_demo_commands_write_parseable_files(tmp_path, capsys):
    import json

    assert gen_auth.main(["--out", str(tmp_path / "auth.log"), "--seed", "3", "--minutes", "30"]) == 0
    (label,) = json.loads(capsys.readouterr().out)
    assert label["expected_rule"] == "SSH_BRUTE_FORCE" and label["start_utc"] == "2026-11-12T01:15:00.000000Z"
    stats = {}
    events = list(auth_log.parse_file(tmp_path / "auth.log", stats, year=2026))
    assert [e["action"] for e in events if e["src_ip"] == "203.0.113.50"].count("ssh_failed") == 12
    assert stats["invalid"] == 0

    assert gen_eve.main(["--out", str(tmp_path / "eve.json"), "--seed", "3", "--minutes", "30"]) == 0
    labels = json.loads(capsys.readouterr().out)
    assert [item["expected_rule"] for item in labels] == ["INTERNAL_PORT_SCAN", "MALWARE_BEACONING"]
    stats = {}
    events = list(suricata.parse_file(tmp_path / "eve.json", stats))
    assert len([e for e in events if e["src_ip"] == "10.0.2.99"]) == 100 and stats["invalid"] == 0
