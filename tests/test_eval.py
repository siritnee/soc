"""Evaluation: scoring formulas, data set loading, the benchmark itself."""
import json
import re
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

from datagen import benchmark
from eval import dataset as eval_dataset
from eval import run as eval_run
from eval.metrics import event_belongs, reduction, score
from storage.models import connect, counts, init_db, list_events

ROOT = Path(__file__).resolve().parent.parent
BENCHMARK = ROOT / "data" / "benchmark"
HOLDOUT = ROOT / "data" / "holdout"
ALLOWED = [ip_network(n) for n in ("10.0.0.0/8", "192.168.0.0/16", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def at(seconds):
    return f"2026-11-12T01:{seconds // 60:02d}:{seconds % 60:02d}.000000Z"


def scenario(scenario_id, start, end, src_ip, *, malicious=True, rule="R1", **more):
    return {"scenario_id": scenario_id, "kind": "test", "malicious": malicious, "expected_rule": rule,
            "start_utc": at(start), "end_utc": at(end), "match": {"src_ip": [src_ip], **more},
            "sources": ["auth_log"], "description": scenario_id}


def incident(rule_id, event_ids, detected, first=None, last=None):
    return {"rule_id": rule_id, "title": rule_id, "severity": "high", "dedup_key": f"{rule_id}|x",
            "first_seen_utc": at(first if first is not None else detected), "detected_at_utc": at(detected),
            "last_seen_utc": at(last if last is not None else detected),
            "event_ids": event_ids, "raw_alert_count": len(event_ids)}


def event(event_id, seconds, src_ip, **more):
    return {"id": event_id, "timestamp_utc": at(seconds), "src_ip": src_ip, "dst_ip": None, "hostname": None, **more}


# ---- formulas -----------------------------------------------------------------

def test_event_belongs_checks_time_and_every_match_field():
    attack = scenario("a", 10, 20, "203.0.113.50", hostname=["web-01"])
    assert event_belongs(event(1, 10, "203.0.113.50", hostname="web-01"), attack)      # first second
    assert event_belongs(event(1, 20, "203.0.113.50", hostname="web-01"), attack)      # last second
    assert not event_belongs(event(1, 9, "203.0.113.50", hostname="web-01"), attack)
    assert not event_belongs(event(1, 21, "203.0.113.50", hostname="web-01"), attack)
    assert not event_belongs(event(1, 15, "203.0.113.51", hostname="web-01"), attack)
    assert not event_belongs(event(1, 15, "203.0.113.50", hostname="db-01"), attack)


def test_reduction_formula():
    assert reduction(500, 8) == pytest.approx(0.984)
    assert reduction(8, 8) == 0 and reduction(0, 0) is None


def test_score_counts_true_and_false_positives():
    scenarios = [
        scenario("found", 0, 60, "203.0.113.50"),
        scenario("missed-wrong-rule", 100, 160, "203.0.113.51", rule="R2"),
        scenario("harmless", 200, 260, "10.0.2.21", malicious=False, rule=None),
        scenario("no-rule-for-it", 300, 360, "203.0.113.52", rule=None),
        scenario("never-seen", 400, 460, "203.0.113.53"),
    ]
    events = [event(1, 0, "203.0.113.50"), event(2, 40, "203.0.113.50"), event(3, 120, "203.0.113.51"),
              event(4, 210, "10.0.2.21"), event(5, 500, "10.0.2.99"), event(6, 330, "203.0.113.52")]
    incidents = [
        incident("R1", [1, 2], detected=40, first=0),   # true positive
        incident("R1", [3], detected=120),              # right place, wrong rule -> false positive
        incident("R1", [4], detected=210),              # on the harmless scenario -> false positive
        incident("R1", [5], detected=500),              # matches nothing -> false positive
        incident("R9", [6], detected=330),              # an attack nobody expected a rule for -> true positive
    ]
    result = score(incidents, events, scenarios, {"raw_alerts": 50, "by_rule": {"R1": {"raw_alerts": 49, "incidents": 4}}})
    detection = result["detection"]
    assert [row["verdict"] for row in result["incidents"]] == [
        "true_positive", "false_positive", "false_positive", "false_positive", "true_positive"]
    assert (detection["true_positives"], detection["false_positives"]) == (2, 3)
    assert detection["precision"] == pytest.approx(2 / 5)
    assert (detection["attacks_with_a_rule"], detection["attacks_found"], detection["attacks_missed"]) == (3, 1, 2)
    assert detection["recall"] == pytest.approx(1 / 3)
    assert detection["f1"] == pytest.approx(2 * 0.4 * (1 / 3) / (0.4 + 1 / 3))
    assert (detection["all_attacks"], detection["all_attacks_found"]) == (4, 2)
    assert (detection["harmless_scenarios"], detection["harmless_scenarios_flagged"]) == (1, 1)
    by_id = {row["scenario_id"]: row for row in result["scenarios"]}
    assert by_id["found"]["detected"] and by_id["found"]["latency_seconds"] == 40.0
    assert not by_id["missed-wrong-rule"]["detected"] and by_id["missed-wrong-rule"]["incident_rules"] == ["R1"]
    assert by_id["harmless"]["incident_rules"] == ["R1"] and not by_id["never-seen"]["detected"]
    assert result["latency_seconds"] == {"count": 1, "mean": 40.0, "median": 40.0, "min": 40.0, "max": 40.0}
    assert result["alert_reduction"]["reduction"] == pytest.approx(0.9)
    assert result["alert_reduction"]["by_rule"]["R1"]["reduction"] == pytest.approx(1 - 4 / 49)
    assert result["incidents"][1]["scenarios"] == ["missed-wrong-rule"]


def test_score_without_incidents_or_without_attacks():
    result = score([], [], [scenario("a", 0, 60, "203.0.113.50")], {"raw_alerts": 0})
    assert result["detection"]["precision"] is None and result["detection"]["recall"] == 0
    assert result["detection"]["f1"] is None and result["latency_seconds"]["mean"] is None
    result = score([], [], [], {"raw_alerts": 0})
    assert result["detection"]["recall"] is None and result["alert_reduction"]["reduction"] is None


def test_latency_uses_the_earliest_incident_that_found_the_scenario():
    scenarios = [scenario("a", 0, 600, "203.0.113.50")]
    events = [event(1, 100, "203.0.113.50"), event(2, 500, "203.0.113.50")]
    result = score([incident("R1", [2], detected=500), incident("R1", [1], detected=100)], events, scenarios, {})
    assert result["scenarios"][0]["latency_seconds"] == 100.0 and result["detection"]["true_positives"] == 2


# ---- data set loading -----------------------------------------------------------

def test_parse_source_rejects_unknown_sources_and_folders_without_manifest(tmp_path):
    with pytest.raises(ValueError, match="unknown source"):
        eval_dataset.parse_source("firewall", tmp_path / "x.log")
    with pytest.raises(ValueError, match="manifest.json is missing"):
        eval_dataset.load_manifest(tmp_path)


def test_ingest_dataset_reports_parser_statistics(tmp_path):
    with connect(tmp_path / "soc.db") as db:
        init_db(db)
        stats = eval_dataset.ingest_dataset(db, BENCHMARK)
        total_events, _ = counts(db)
    assert set(stats) == {"auth_log", "suricata", "sysmon"}
    assert [stats[source]["invalid"] for source in ("auth_log", "suricata", "sysmon")] == [2, 2, 2]
    assert sum(item["stored"] for item in stats.values()) == total_events == 1138
    manifest = eval_dataset.load_manifest(BENCHMARK)
    assert [entry["broken_lines"] for entry in manifest["sources"]] == [2, 2, 2]
    assert [stats[entry["source"]]["lines"] for entry in manifest["sources"]] == [entry["lines"] for entry in manifest["sources"]]


# ---- the benchmark ----------------------------------------------------------------

@pytest.fixture(scope="module")
def benchmark_result():
    return eval_run.evaluate_dataset(BENCHMARK)


def test_benchmark_finds_every_attack_that_has_a_rule(benchmark_result):
    detection = benchmark_result["detection"]
    assert (detection["attacks_with_a_rule"], detection["attacks_found"], detection["recall"]) == (8, 8, 1.0)
    found = {row["scenario_id"]: row for row in benchmark_result["scenarios"] if row["malicious"]}
    assert found["ssh-bruteforce-gave-up"]["detected"] is False            # no login, no lockout: outside rule 1
    assert (detection["all_attacks"], detection["all_attacks_found"]) == (9, 8)
    assert {row["expected_rule"] for row in found.values() if row["expected_rule"]} == {
        "SSH_BRUTE_FORCE", "INTERNAL_PORT_SCAN", "MALWARE_BEACONING", "SUSPICIOUS_PROCESS", "NETWORK_TO_HOST_PIVOT"}


def test_benchmark_has_exactly_the_one_known_false_positive(benchmark_result):
    detection = benchmark_result["detection"]
    assert (detection["incidents"], detection["true_positives"], detection["false_positives"]) == (9, 8, 1)
    assert detection["precision"] == pytest.approx(8 / 9)
    (wrong,) = [row for row in benchmark_result["incidents"] if row["verdict"] == "false_positive"]
    assert wrong["rule_id"] == "SUSPICIOUS_PROCESS" and wrong["scenarios"] == ["decoy-appdata-program"]
    flagged = [row["scenario_id"] for row in benchmark_result["scenarios"] if not row["malicious"] and row["incident_rules"]]
    assert flagged == ["decoy-appdata-program"] and detection["harmless_scenarios"] == 7


def test_benchmark_alert_reduction_and_latency(benchmark_result):
    reduction_part = benchmark_result["alert_reduction"]
    assert (reduction_part["raw_alerts"], reduction_part["incidents"]) == (278, 9)
    assert reduction_part["reduction"] == pytest.approx(1 - 9 / 278)
    assert reduction_part["by_rule"]["INTERNAL_PORT_SCAN"] == {"raw_alerts": 232, "incidents": 2,
                                                               "reduction": pytest.approx(1 - 2 / 232)}
    latency = {row["scenario_id"]: row["latency_seconds"] for row in benchmark_result["scenarios"]}
    assert latency["ssh-bruteforce-login"] == 44.0 and latency["ssh-bruteforce-lockout"] == 31.0
    assert latency["process-temp"] == 0.0 and latency["pivot"] == 45.0
    assert 0 < latency["portscan-network"] < 3 and 0 < latency["portscan-host"] < 5
    assert 240 <= latency["beaconing"] <= 360                              # sixth beacon, one a minute
    assert benchmark_result["latency_seconds"]["count"] == 8


def test_every_scenario_of_the_ground_truth_exists_in_the_logs():
    with connect(":memory:") as db:
        init_db(db)
        eval_dataset.ingest_dataset(db, BENCHMARK)
        events = list_events(db)
    for item in eval_dataset.load_ground_truth(BENCHMARK):
        assert any(event_belongs(e, item) for e in events), item["scenario_id"]
        assert item["start_utc"] <= item["end_utc"]


def test_report_and_metrics_files(tmp_path, capsys):
    assert eval_run.main(["--dataset", str(BENCHMARK), "--out", str(tmp_path)]) == 0
    printed = capsys.readouterr().out
    assert "raw_alerts=278 incidents=9" in printed and "precision=0.889 recall=1.000" in printed
    report = (tmp_path / "soc-benchmark-v1.md").read_text(encoding="utf-8")
    assert "**278 cảnh báo thô** được gom thành **9 incident**: giảm **96.8%**" in report
    assert "Precision: **88.9%** (8 incident đúng / 9 incident)" in report
    assert "BÁO NHẦM (`decoy-appdata-program`)" in report and "| `pivot` |" in report
    metrics = json.loads((tmp_path / "soc-benchmark-v1.json").read_text(encoding="utf-8"))
    assert metrics["detection"]["recall"] == 1.0 and metrics["events"] == 1138
    assert eval_run.main(["--dataset", str(tmp_path / "nothing"), "--out", str(tmp_path)]) == 2


def test_committed_report_matches_a_fresh_run(tmp_path):
    """The numbers in the repository must be the numbers the program produces."""
    committed = ROOT / "eval" / "results" / "soc-benchmark-v1.json"
    assert json.loads(committed.read_text(encoding="utf-8")) == json.loads(
        json.dumps(eval_run.evaluate_dataset(BENCHMARK)))


# ---- the data files ----------------------------------------------------------------

def test_benchmark_and_holdout_can_be_rebuilt_exactly(tmp_path):
    benchmark.write_benchmark(tmp_path / "benchmark")
    benchmark.write_holdout(tmp_path / "holdout")
    for committed, rebuilt in ((BENCHMARK, tmp_path / "benchmark"), (HOLDOUT, tmp_path / "holdout")):
        names = sorted(path.name for path in committed.iterdir())
        assert names == sorted(path.name for path in rebuilt.iterdir())
        for name in names:      # read_text ignores the CRLF that Git may write on Windows
            assert (committed / name).read_text(encoding="utf-8") == (rebuilt / name).read_text(encoding="utf-8"), name


def test_data_files_only_contain_lab_addresses():
    addresses = set()
    for folder in (BENCHMARK, HOLDOUT):
        for path in folder.iterdir():
            text = path.read_text(encoding="utf-8")
            addresses |= {ip_address(found) for found in re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", text)}
    assert len(addresses) > 20
    assert sorted(str(a) for a in addresses if not any(a in network for network in ALLOWED)) == []


def test_holdout_is_described_but_not_scored_here():
    """The hold-out log is for practising the defence; tests must not turn it
    into something rules get tuned against. Only its shape is checked."""
    manifest = eval_dataset.load_manifest(HOLDOUT)
    assert [entry["source"] for entry in manifest["sources"]] == ["auth_log"]
    kinds = [(item["scenario_id"], item["malicious"]) for item in eval_dataset.load_ground_truth(HOLDOUT)]
    assert kinds == [("holdout-typo-login", False), ("holdout-bruteforce-login", True),
                     ("holdout-slow-bruteforce", True), ("holdout-bruteforce-lockout", True)]
