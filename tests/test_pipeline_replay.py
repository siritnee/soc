
"""Regression tests for the replay CLI."""

from pathlib import Path
from pipeline.__main__ import main

ROOT = Path(__file__).resolve().parents[1]


def test_replay_benchmark_directory(capsys):
    result = main([
        "replay", "--dataset",
        str(ROOT / "data" / "benchmark")
    ])

    captured = capsys.readouterr()

    assert result == 0
    assert "auth_log: 82 event(s) stored" in captured.out
    assert "suricata: 780 event(s) stored" in captured.out
    assert "sysmon: 276 event(s) stored" in captured.out
    assert "events=1138, incidents=9, newly_created=9" in captured.out
    assert "WinError" not in captured.err


def test_replay_normalized_jsonl(capsys):
    result = main([
        "replay", "--dataset",
        str(ROOT / "data" / "examples" / "normalized.jsonl")
    ])

    captured = capsys.readouterr()

    assert result == 0
    assert "normalized event(s)" in captured.out


def test_replay_missing_dataset(tmp_path, capsys):
    result = main([
        "replay", "--dataset",
        str(tmp_path / "not_found")
    ])

    captured = capsys.readouterr()

    assert result == 2
    assert "Dataset not found" in captured.err
