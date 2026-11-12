"""CLI entry point: python -m pipeline <command>."""
from __future__ import annotations
import argparse
import importlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Iterator
from normalizer.schema import normalize_event
from storage.models import connect, init_db, insert_events, list_events, insert_incident, counts


def read_normalized_jsonl(path: Path) -> Iterator[dict]:
    with path.open(encoding="utf-8") as fh:
        for no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                obj = json.loads(line)
                yield normalize_event(obj)
            except (json.JSONDecodeError, ValueError) as exc:
                raise ValueError(f"{path}:{no}: {exc}") from exc


def load_source(source: str, path: Path):
    if source == "normalized":
        return read_normalized_jsonl(path)
    modules = {
        "suricata": "ingestors.suricata",
        "sysmon": "ingestors.sysmon",
        "auth_log": "ingestors.auth_log",
    }
    try:
        parser = importlib.import_module(modules[source])
        return parser.parse_file(path)  # Agreed interface for teammate 2 / 3
    except (ImportError, AttributeError) as exc:
        raise RuntimeError(f"Parser for {source} has not been integrated yet: {exc}") from exc


def do_ingest(db_path: str, source: str, file_path: str) -> int:
    with connect(db_path) as conn:
        init_db(conn)
        return insert_events(conn, load_source(source, Path(file_path)))


def do_detect(db_path: str) -> int:
    try:
        from engine.correlation import detect_incidents
    except ImportError as exc:
        raise RuntimeError(
            "Engine pending: member 4 must implement engine.correlation.detect_incidents(events)"
        ) from exc
    with connect(db_path) as conn:
        init_db(conn)
        incidents = detect_incidents(list_events(conn))
        inserted = 0
        for inc in incidents:
            insert_incident(conn, inc)
            inserted += 1
        return inserted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m pipeline")
    parser.add_argument("--db", default=os.environ.get("SOC_DB_PATH", "data/soc.db"),
                        help="SQLite db path; specify this before the command")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    ingest = sub.add_parser("ingest")
    ingest.add_argument("--source", choices=["normalized", "suricata", "sysmon", "auth_log"], required=True)
    ingest.add_argument("--file", required=True)
    sub.add_parser("detect")
    sub.add_parser("dashboard")
    replay = sub.add_parser("replay")
    replay.add_argument("--dataset", default="data/examples/normalized.jsonl")
    args = parser.parse_args(argv)
    try:
        if args.command == "init-db":
            with connect(args.db) as conn:
                init_db(conn)
            print(f"Created DB: {args.db}")
        elif args.command == "ingest":
            count = do_ingest(args.db, args.source, args.file)
            print(f"Ingested {count} event(s) into {args.db}")
        elif args.command == "detect":
            count = do_detect(args.db)
            print(f"Detected and saved {count} incident(s)")
        elif args.command == "dashboard":
            ui_file = Path("ui/dashboard.py")
            if not ui_file.exists():
                raise RuntimeError("Dashboard pending: member 5 must implement ui/dashboard.py")
            env = {**os.environ, "SOC_DB_PATH":args.db}
            return subprocess.run([sys.executable, "-m", "streamlit", "run", str(ui_file)],env=env,check=False).returncode
        elif args.command == "replay":
            # Isolated temporary DB avoids contaminating the regular SOC database.
            with tempfile.TemporaryDirectory() as temp:
                replay_db = str(Path(temp) / "replay.sqlite3")
                count = do_ingest(replay_db, "normalized", args.dataset)
                print(f"Replayed {count} normalized event(s)")
                new_incidents = do_detect(replay_db)
                with connect(replay_db) as conn:
                    events, incidents = counts(conn)
                print(f"events={events}, incidents={incidents}, newly_created={new_incidents}")
                print("Note: evaluate precision/recall against ground truth in eval/ (member 5)")
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 0

if __name__ == "__main__":
    sys.exit(main())
