"""Scoring incidents against the ground truth.

Definitions used in the report:

* An event *belongs* to a scenario when its time lies inside the scenario
  and every field listed in the scenario's ``match`` has one of the listed
  values (for example ``src_ip`` is the attacker).
* An incident *matches* a scenario when at least one of its events belongs to it.
* An incident is a **true positive** when it matches an attack whose expected
  rule is the incident's rule (or an attack with no expected rule at all).
  Every other incident is a **false positive**.
* **Precision** = true positives / all incidents.
* **Recall** = attacks found / attacks that a rule is expected to find.
* **Detection latency** = time the rule first fired minus the start of the
  attack, both taken from the event timestamps.
* **Alert reduction** = 1 - incidents / raw alerts, a raw alert being one
  rule match before merging.
"""
from __future__ import annotations

from statistics import mean, median
from typing import Any, Iterable, Mapping, Sequence

from engine.correlation import parse_ts


def event_belongs(event: Mapping[str, Any], scenario: Mapping[str, Any]) -> bool:
    moment = parse_ts(event["timestamp_utc"])
    if not parse_ts(scenario["start_utc"]) <= moment <= parse_ts(scenario["end_utc"]):
        return False
    return all(event.get(name) in values for name, values in scenario["match"].items())


def _is_hit(incident: Mapping[str, Any], scenario: Mapping[str, Any]) -> bool:
    """Does this incident count as finding this scenario?"""
    return scenario["malicious"] and scenario["expected_rule"] in (None, incident["rule_id"])


def reduction(raw_alerts: int, incidents: int) -> float | None:
    return None if raw_alerts == 0 else 1 - incidents / raw_alerts


def score(incidents: Sequence[Mapping[str, Any]], events: Iterable[Mapping[str, Any]],
          scenarios: Sequence[Mapping[str, Any]], engine_stats: Mapping[str, Any]) -> dict[str, Any]:
    """Compare what the engine reported with what the data set contains."""
    by_id = {event["id"]: event for event in events}
    incident_rows = []
    found_by: dict[str, list[Mapping[str, Any]]] = {scenario["scenario_id"]: [] for scenario in scenarios}
    touched: dict[str, list[str]] = {scenario["scenario_id"]: [] for scenario in scenarios}
    for incident in incidents:
        own_events = [by_id[event_id] for event_id in incident["event_ids"] if event_id in by_id]
        matched = [s for s in scenarios if any(event_belongs(event, s) for event in own_events)]
        hits = [s for s in matched if _is_hit(incident, s)]
        for scenario in matched:
            touched[scenario["scenario_id"]].append(incident["rule_id"])
        for scenario in hits:
            found_by[scenario["scenario_id"]].append(incident)
        incident_rows.append({
            "rule_id": incident["rule_id"], "severity": incident["severity"], "title": incident["title"],
            "dedup_key": incident.get("dedup_key"), "first_seen_utc": incident["first_seen_utc"],
            "detected_at_utc": incident.get("detected_at_utc"), "last_seen_utc": incident["last_seen_utc"],
            "events": len(incident["event_ids"]), "raw_alerts": incident.get("raw_alert_count"),
            "verdict": "true_positive" if hits else "false_positive",
            "scenarios": [s["scenario_id"] for s in (hits or matched)],
        })

    scenario_rows, latencies = [], []
    for scenario in scenarios:
        finders = found_by[scenario["scenario_id"]]
        latency = None
        detections = [parse_ts(i["detected_at_utc"]) for i in finders if i.get("detected_at_utc")]
        if detections:
            latency = round((min(detections) - parse_ts(scenario["start_utc"])).total_seconds(), 3)
        in_scope = scenario["malicious"] and scenario["expected_rule"] is not None
        if in_scope and latency is not None:
            latencies.append(latency)
        scenario_rows.append({
            "scenario_id": scenario["scenario_id"], "kind": scenario["kind"], "malicious": scenario["malicious"],
            "expected_rule": scenario["expected_rule"], "description": scenario["description"],
            "start_utc": scenario["start_utc"], "sources": scenario["sources"],
            "detected": bool(finders), "incident_rules": touched[scenario["scenario_id"]],
            "latency_seconds": latency,
        })

    in_scope = [row for row in scenario_rows if row["malicious"] and row["expected_rule"]]
    attacks = [row for row in scenario_rows if row["malicious"]]
    decoys = [row for row in scenario_rows if not row["malicious"]]
    true_positives = sum(row["verdict"] == "true_positive" for row in incident_rows)
    found = sum(row["detected"] for row in in_scope)
    precision = true_positives / len(incident_rows) if incident_rows else None
    recall = found / len(in_scope) if in_scope else None
    f1 = None
    if precision is not None and recall is not None:
        f1 = 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)
    raw_alerts = engine_stats.get("raw_alerts", 0)
    return {
        "alert_reduction": {
            "raw_alerts": raw_alerts, "incidents": len(incident_rows),
            "reduction": reduction(raw_alerts, len(incident_rows)),
            "by_rule": {rule_id: {**counts, "reduction": reduction(counts["raw_alerts"], counts["incidents"])}
                        for rule_id, counts in engine_stats.get("by_rule", {}).items()},
        },
        "detection": {
            "incidents": len(incident_rows), "true_positives": true_positives,
            "false_positives": len(incident_rows) - true_positives,
            "attacks_with_a_rule": len(in_scope), "attacks_found": found, "attacks_missed": len(in_scope) - found,
            "precision": precision, "recall": recall, "f1": f1,
            "all_attacks": len(attacks), "all_attacks_found": sum(row["detected"] for row in attacks),
            "harmless_scenarios": len(decoys),
            "harmless_scenarios_flagged": sum(bool(row["incident_rules"]) for row in decoys),
        },
        "latency_seconds": {
            "count": len(latencies),
            "mean": round(mean(latencies), 3) if latencies else None,
            "median": round(median(latencies), 3) if latencies else None,
            "min": min(latencies) if latencies else None,
            "max": max(latencies) if latencies else None,
        },
        "scenarios": scenario_rows,
        "incidents": incident_rows,
    }
