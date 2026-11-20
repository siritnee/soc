
"""End-to-end test: raw logs -> SQLite -> detection -> incidents."""

from pathlib import Path

from pipeline.__main__ import main
from storage.models import (
    connect,
    counts,
    set_incident_status,
)

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "data" / "benchmark"


def test_pipeline_end_to_end(tmp_path, monkeypatch, capsys):
    # Cấu hình thời gian cho auth.log
    monkeypatch.setenv("SOC_AUTH_LOG_YEAR", "2026")
    monkeypatch.setenv("SOC_AUTH_LOG_TZ", "+07:00")

    # Database tạm do pytest tự tạo
    db = str(tmp_path / "soc_e2e.db")

    def run(*args):
        return main(["--db", db, *args])

    # 1. Tạo database
    assert run("init-db") == 0

    # 2. Nhập đủ 3 nguồn log thật của benchmark
    for source, filename in [
        ("auth_log", "auth.log"),
        ("suricata", "eve.json"),
        ("sysmon", "sysmon.json"),
    ]:
        assert run(
            "ingest",
            "--source", source,
            "--file", str(BENCHMARK / filename),
        ) == 0

    # 3. Kiểm tra tổng số event
    with connect(db) as conn:
        assert counts(conn) == (1138, 0)

    # 4. Phát hiện lần đầu
    assert run("detect") == 0
    assert "Detected and saved 9 incident(s)" in capsys.readouterr().out

    with connect(db) as conn:
        assert counts(conn) == (1138, 9)

        # Kiểm tra cả 5 loại luật
        rule_ids = {
            row[0]
            for row in conn.execute(
                "SELECT DISTINCT rule_id FROM incidents"
            )
        }

        assert rule_ids == {
            "SSH_BRUTE_FORCE",
            "INTERNAL_PORT_SCAN",
            "SUSPICIOUS_PROCESS",
            "NETWORK_TO_HOST_PIVOT",
            "MALWARE_BEACONING",
        }

        # Đổi trạng thái 1 incident
        set_incident_status(
            conn, 1, "In Progress", "analyst01"
        )

    # 5. Chạy detect lần hai
    assert run("detect") == 0
    assert "Detected and saved 0 incident(s)" in capsys.readouterr().out

    # 6. Kiểm tra không trùng và không mất trạng thái
    with connect(db) as conn:
        assert counts(conn) == (1138, 9)

        incident = conn.execute(
            """
            SELECT status, assigned_analyst
            FROM incidents
            WHERE incident_id = 1
            """
        ).fetchone()

        assert incident["status"] == "In Progress"
        assert incident["assigned_analyst"] == "analyst01"
