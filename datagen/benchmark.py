"""Builds the benchmark data set and the hold-out brute-force log.

    python -m datagen.benchmark --out data/benchmark --holdout data/holdout

The data set is put together from the generators of members 2 and 3: two
hours of normal activity in three log sources, eight labelled attacks, one
attack the rules are not meant to catch, and seven harmless look-alikes.
Everything is derived from a seed, so the same command always writes the
same files.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Sequence

from datagen import auth_log, suricata, sysmon
from datagen.common import LAB_TZ, LogBundle, Rng, utc_iso

BENCHMARK_SEED = 2026
BENCHMARK_START = datetime(2026, 11, 12, 8, 0, tzinfo=LAB_TZ)     # 08:00 in the lab = 01:00 UTC
BENCHMARK_MINUTES = 120
HOLDOUT_SEED = 7771
HOLDOUT_START = datetime(2026, 11, 20, 14, 0, tzinfo=LAB_TZ)
HOLDOUT_MINUTES = 45
TZ_TEXT = "+07:00"

# Damaged lines, as left behind by a full disk or a cut-off copy. They are
# inserted at fixed places so the parsers' "invalid" counters have work to do.
_BROKEN = {
    "auth_log": {40: "Nov 12 08:4", 150: "###### log rotated ######"},
    "suricata": {120: '{"timestamp":"2026-11-12T08:31:07.000000+0700","event_type":"flow","src_ip":"10.0.2.2', 600: "{}"},
    "sysmon": {90: '{"EventID": 1, "Computer": "WS-02.lab.example", "UtcTime": "2026-11-12 01:3',
               200: '{"EventID": 3, "Computer": "WS-03.lab.example", "UtcTime": "unknown", "SourceIp": "10.0.2.23", '
                    '"DestinationIp": "10.0.1.20", "DestinationPort": 445}'},
}


def _at(start: datetime, minutes: float) -> datetime:
    return start + timedelta(minutes=minutes)


def build_benchmark(seed: int = BENCHMARK_SEED) -> LogBundle:
    """Normal activity, attacks and look-alikes of the benchmark, unsorted."""
    rng, start = Rng(seed), BENCHMARK_START
    bundle = auth_log.benign_activity(rng.fork("benign-auth"), start, BENCHMARK_MINUTES)
    bundle.merge(suricata.benign_traffic(rng.fork("benign-network"), start, BENCHMARK_MINUTES))
    bundle.merge(sysmon.benign_activity(rng.fork("benign-windows"), start, BENCHMARK_MINUTES))

    # --- attacks the rules must find ---------------------------------------
    bundle.merge(suricata.beaconing(rng.fork("a1"), _at(start, 10), "10.0.2.40", "203.0.113.200", 443,
                                    interval=60, count=40, scenario_id="beaconing"))
    bundle.merge(auth_log.brute_force(rng.fork("a2"), _at(start, 25), "203.0.113.50", "bastion-01",
                                      ["admin", "root", "deploy"], 12, "success", "ssh-bruteforce-login"))
    bundle.merge(suricata.port_scan(rng.fork("a3"), _at(start, 40), "10.0.2.99", "10.0.1.10",
                                    list(range(1, 201)), 20, "portscan-network"))
    bundle.merge(sysmon.suspicious_process(rng.fork("a4"), _at(start, 55), "WS-01", "temp", "process-temp"))
    bundle.merge(sysmon.suspicious_process(rng.fork("a5"), _at(start, 65), "WS-02", "encoded", "process-encoded"))
    bundle.merge(auth_log.brute_force(rng.fork("a6"), _at(start, 80), "198.51.100.23", "web-01",
                                      ["alice"], 8, "lockout", "ssh-bruteforce-lockout"))
    bundle.merge(sysmon.port_scan(rng.fork("a7"), _at(start, 95), "WS-03", "10.0.1.20",
                                  list(range(20, 80)), 10, "portscan-host"))
    bundle.merge(sysmon.pivot(rng.fork("a8"), _at(start, 105), "203.0.113.77", "WS-04",
                              [("10.0.1.20", 445), ("10.0.1.2", 445), ("10.0.2.21", 3389), ("10.0.2.22", 3389)],
                              "pivot"))

    # --- an attack outside what rule 1 is defined to catch -----------------
    bundle.merge(auth_log.brute_force(rng.fork("o1"), _at(start, 50), "203.0.113.51", "db-01",
                                      ["root", "postgres"], 9, "none", "ssh-bruteforce-gave-up"))

    # --- harmless look-alikes ----------------------------------------------
    bundle.merge(auth_log.typo_login(rng.fork("d1"), _at(start, 15), "web-01", "alice", "10.0.2.21", 3,
                                     "decoy-typo-login"))
    bundle.merge(auth_log.typo_login(rng.fork("d2"), _at(start, 30), "db-01", "bob", "10.0.2.22", 6,
                                     "decoy-slow-failures", gap=(70.0, 110.0)))
    bundle.merge(suricata.port_scan(rng.fork("d3"), _at(start, 60), "10.0.2.10", "10.0.1.11",
                                    list(range(5430, 5440)), 20, "decoy-few-ports", malicious=False))
    bundle.merge(suricata.port_scan(rng.fork("d4"), _at(start, 70), "10.0.2.10", "10.0.1.10",
                                    list(range(8000, 8020)), 570, "decoy-slow-sweep", malicious=False))
    bundle.merge(suricata.repeated_alerts(rng.fork("d5"), _at(start, 20), "10.0.2.22", "192.0.2.80",
                                          [20, 180, 35, 400, 60, 15, 240], suricata.SIG_CLEARTEXT,
                                          "decoy-irregular-alerts"))
    bundle.merge(suricata.repeated_alerts(rng.fork("d6"), _at(start, 35), "10.0.1.10", "192.0.2.81",
                                          [300] * 6, suricata.SIG_UPDATE, "decoy-periodic-low-alerts", port=443))
    # Kept on purpose: rule 3 reports this one, so the report shows a real false positive.
    bundle.merge(sysmon.unlisted_appdata_program(rng.fork("d7"), _at(start, 45), "WS-04", "decoy-appdata-program"))
    return bundle


def build_holdout(seed: int = HOLDOUT_SEED) -> LogBundle:
    """A separate SSH log for practising the defence. It must not be used
    while rules are being tuned."""
    rng, start = Rng(seed), HOLDOUT_START
    bundle = auth_log.benign_activity(rng.fork("benign"), start, HOLDOUT_MINUTES)
    bundle.merge(auth_log.typo_login(rng.fork("typo"), _at(start, 4), "bastion-01", "carol", "10.0.2.23", 4,
                                     "holdout-typo-login"))
    bundle.merge(auth_log.brute_force(rng.fork("login"), _at(start, 9), "203.0.113.9", "db-01",
                                      ["oracle", "postgres", "backup"], 9, "success", "holdout-bruteforce-login",
                                      gap=(1.0, 2.5)))
    bundle.merge(auth_log.brute_force(rng.fork("slow"), _at(start, 18), "198.51.100.88", "web-01",
                                      ["root", "www-data", "deploy"], 10, "success", "holdout-slow-bruteforce",
                                      gap=(18.0, 22.0)))
    bundle.labels[-1].expected_rule = None
    bundle.labels[-1].description += " One try every 20 seconds: never five failures inside one minute."
    bundle.merge(auth_log.brute_force(rng.fork("lock"), _at(start, 31), "198.51.100.77", "bastion-01",
                                      ["dave"], 7, "lockout", "holdout-bruteforce-lockout"))
    return bundle


def _with_broken_lines(text: str, broken: dict[int, str]) -> str:
    lines = text.splitlines()
    for index in sorted(broken):
        lines.insert(min(index, len(lines)), broken[index])
    return "\n".join(lines) + "\n"


def _readme(name: str, description: str, seed: int, command: str, labels: Sequence[dict]) -> str:
    rows = "\n".join(
        f"| `{label['scenario_id']}` | {'attack' if label['malicious'] else 'harmless'} | "
        f"{label['expected_rule'] or '-'} | {label['start_utc'][11:19]} | {', '.join(label['sources'])} | "
        f"{label['description']} |" for label in labels)
    return (f"# {name}\n\n{description}\n\n"
            f"Synthetic data only: private (10.x) and documentation IP ranges, made-up users and hosts.\n"
            f"Do not edit by hand. Rebuild with:\n\n    {command}\n\n(seed {seed}; the same seed always "
            f"gives the same files).\n\n"
            "| Scenario | Kind | Rule that must fire | Start (UTC) | Log sources | What happens |\n"
            "|---|---|---|---|---|---|\n" + rows + "\n")


def write_dataset(bundle: LogBundle, out_dir: Path, *, name: str, description: str, seed: int,
                  start: datetime, minutes: int, command: str, broken: dict[str, dict[int, str]] | None = None) -> dict:
    """Write the log files, ground_truth.json, manifest.json and README.md; return the manifest."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    broken = broken or {}
    texts = {
        "auth_log": ("auth.log", auth_log.render(bundle.auth)),
        "suricata": ("eve.json", suricata.render(bundle.eve)),
        "sysmon": ("sysmon.json", sysmon.render(bundle.sysmon)),
    }
    sources = []
    for source, (file_name, text) in texts.items():
        if not text:
            continue
        text = _with_broken_lines(text, broken.get(source, {}))
        with open(out_dir / file_name, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        entry = {"source": source, "file": file_name, "lines": len(text.splitlines()),
                 "broken_lines": len(broken.get(source, {}))}
        if source == "auth_log":
            entry.update(year=start.year, tz=TZ_TEXT)
        sources.append(entry)
    labels = [label.to_dict() for label in sorted(bundle.labels, key=lambda item: (item.start, item.scenario_id))]
    manifest = {
        "name": name, "description": description, "seed": seed, "built_with": command,
        "start_utc": utc_iso(start), "end_utc": utc_iso(start + timedelta(minutes=minutes)),
        "sources": sources, "ground_truth": "ground_truth.json",
    }
    for file_name, content in (("ground_truth.json", {"dataset": name, "scenarios": labels}),
                               ("manifest.json", manifest)):
        with open(out_dir / file_name, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(content, indent=2, ensure_ascii=False) + "\n")
    with open(out_dir / "README.md", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(_readme(name, description, seed, command, labels))
    return manifest


def write_benchmark(out_dir: Path, seed: int = BENCHMARK_SEED) -> dict:
    return write_dataset(
        build_benchmark(seed), out_dir, name="soc-benchmark-v1", seed=seed,
        description="Two hours of lab activity in three log sources with labelled attacks and harmless look-alikes.",
        start=BENCHMARK_START, minutes=BENCHMARK_MINUTES, broken=_BROKEN,
        command="python -m datagen.benchmark --out data/benchmark --holdout data/holdout")


def write_holdout(out_dir: Path, seed: int = HOLDOUT_SEED) -> dict:
    return write_dataset(
        build_holdout(seed), out_dir, name="soc-holdout-bruteforce", seed=seed,
        description="SSH log kept aside for practising the defence. Not used when rules are tuned.",
        start=HOLDOUT_START, minutes=HOLDOUT_MINUTES,
        command="python -m datagen.benchmark --out data/benchmark --holdout data/holdout")


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m datagen.benchmark", description=__doc__.splitlines()[0])
    parser.add_argument("--out", default="data/benchmark", help="folder for the benchmark")
    parser.add_argument("--holdout", default=None, help="also write the hold-out log to this folder")
    args = parser.parse_args(argv)
    todo = [(args.out, write_benchmark)] + ([(args.holdout, write_holdout)] if args.holdout else [])
    for folder, write in todo:
        manifest = write(Path(folder))
        sizes = ", ".join(f"{entry['file']} {entry['lines']} lines" for entry in manifest["sources"])
        print(f"{manifest['name']} -> {folder}: {sizes}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
