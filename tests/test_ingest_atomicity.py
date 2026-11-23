"""Regression tests: persistent CLI dedup and all-or-nothing uploads."""
import json
from pathlib import Path

import pytest

from pipeline.__main__ import main
from storage.models import connect, init_db, counts, file_digest_path, file_digest
from ui import data as ui_data


AUTH_SAMPLE = ("Nov 12 08:00:01 lab sshd[100]: Failed password for root from 203.0.113.50 port 12345 ssh2\n"
               "Nov 12 08:00:02 lab sshd[100]: Failed password for root from 203.0.113.50 port 12346 ssh2\n"
               "Nov 12 08:00:03 lab sshd[100]: Failed password for root from 203.0.113.50 port 12347 ssh2\n"
               "Nov 12 08:00:04 lab sshd[100]: Accepted password for root from 203.0.113.50 port 12348 ssh2\n")


@pytest.fixture
def cli_sample(tmp_path, monkeypatch):
    monkeypatch.setenv('SOC_AUTH_LOG_YEAR', '2026')
    monkeypatch.setenv('SOC_AUTH_LOG_TZ', '+07:00')
    sample = tmp_path / 'auth.log'
    sample.write_text(AUTH_SAMPLE, encoding='utf-8')
    return sample


def test_cli_same_file_twice_does_not_create_false_bruteforce(tmp_path, cli_sample, capsys):
    db = str(tmp_path / 'soc.db')
    args = ['--db', db, 'ingest', '--source', 'auth_log', '--file', str(cli_sample)]
    assert main(args) == 0
    assert main(['--db', db, 'detect']) == 0
    with connect(db) as conn:
        assert counts(conn) == (4, 0)
    assert main(args) == 0
    assert 'Ingested 0 event(s)' in capsys.readouterr().out
    assert main(['--db', db, 'detect']) == 0
    with connect(db) as conn:
        assert counts(conn) == (4, 0)
        assert conn.execute('SELECT COUNT(*) FROM ingested_files').fetchone()[0] == 1


def test_cli_different_auth_parsing_configuration_is_not_silently_skipped(tmp_path, cli_sample, monkeypatch):
    db = str(tmp_path / 'soc.db')
    args = ['--db', db, 'ingest', '--source', 'auth_log', '--file', str(cli_sample)]
    assert main(args) == 0
    monkeypatch.setenv('SOC_AUTH_LOG_TZ', '+00:00')
    assert main(args) == 0
    with connect(db) as conn:
        assert counts(conn) == (8, 0)
        assert conn.execute('SELECT COUNT(*) FROM ingested_files').fetchone()[0] == 2


def test_dashboard_upload_after_cli_uses_same_fingerprint(tmp_path, cli_sample):
    db = str(tmp_path / 'soc.db')
    args = ['--db', db, 'ingest', '--source', 'auth_log', '--file', str(cli_sample)]
    assert main(args) == 0
    with connect(db) as conn:
        response = ui_data.analyze_log(conn, 'auth_log', cli_sample.read_bytes(), year=2026, tz='+07:00')
        assert response['duplicate'] is True
        assert counts(conn) == (4, 0)


def test_cli_ingest_after_dashboard_upload_uses_same_fingerprint(tmp_path, cli_sample):
    db = str(tmp_path / 'soc.db')
    with connect(db) as conn:
        init_db(conn)
        response = ui_data.analyze_log(conn, 'auth_log', cli_sample.read_bytes(), year=2026, tz='+07:00')
        assert response['duplicate'] is False
        assert counts(conn) == (4, 0)
    assert main(['--db', db, 'ingest', '--source', 'auth_log', '--file', str(cli_sample)]) == 0
    with connect(db) as conn:
        assert counts(conn) == (4, 0)
        assert conn.execute('SELECT COUNT(*) FROM ingested_files').fetchone()[0] == 1


def test_dashboard_failure_during_correlation_rolls_back_events_and_digest(tmp_path, cli_sample, monkeypatch):
    db = tmp_path / 'soc.db'
    with connect(db) as conn:
        init_db(conn)
        real = ui_data.save_new_incidents
        monkeypatch.setattr(ui_data, 'save_new_incidents', lambda *_: (_ for _ in ()).throw(RuntimeError('simulated failure')))
        with pytest.raises(RuntimeError, match='simulated failure'):
            ui_data.analyze_log(conn, 'auth_log', cli_sample.read_bytes(), year=2026, tz='+07:00')
        assert counts(conn) == (0, 0)
        assert conn.execute('SELECT COUNT(*) FROM ingested_files').fetchone()[0] == 0
        monkeypatch.setattr(ui_data, 'save_new_incidents', real)
        assert ui_data.analyze_log(conn, 'auth_log', cli_sample.read_bytes(), year=2026, tz='+07:00')['stored'] == 4
        assert counts(conn) == (4, 0)


def test_dashboard_failure_after_saving_incident_rolls_back_everything(tmp_path, cli_sample, monkeypatch):
    db = tmp_path / 'soc.db'
    with connect(db) as conn:
        init_db(conn)
        real = ui_data.save_new_incidents
        def save_then_crash(conn, incidents):
            real(conn, incidents)
            # Write evidence of rollback even when no incident matched the sample.
            conn.execute('INSERT INTO incidents (rule_id, title, severity, first_seen_utc, last_seen_utc) VALUES (?,?,?,?,?)',
                         ('FAKE', 'partial write', 'high', '2026-11-12T00:00:00Z','2026-11-12T00:00:00Z'))
            raise RuntimeError('crashed after incident write')
        monkeypatch.setattr(ui_data, 'save_new_incidents', save_then_crash)
        with pytest.raises(RuntimeError, match='crashed after incident write'):
            ui_data.analyze_log(conn, 'auth_log', cli_sample.read_bytes(), year=2026, tz='+07:00')
        assert counts(conn) == (0, 0)
        assert conn.execute('SELECT COUNT(*) FROM ingested_files').fetchone()[0] == 0


def test_cli_bad_json_after_valid_line_rolls_back(tmp_path):
    from tests.test_storage import BASE
    db = str(tmp_path / 'soc.db')
    badfile = tmp_path / 'mixed.jsonl'
    badfile.write_text(json.dumps(BASE) + '\n{broken json\n', encoding='utf-8')
    assert main(['--db', db, 'ingest', '--source', 'normalized', '--file', str(badfile)]) == 2
    with connect(db) as conn:
        assert counts(conn) == (0, 0)
        assert conn.execute('SELECT COUNT(*) FROM ingested_files').fetchone()[0] == 0
    badfile.write_text(json.dumps(BASE) + '\n', encoding='utf-8')
    assert main(['--db', db, 'ingest', '--source', 'normalized', '--file', str(badfile)]) == 0
    with connect(db) as conn:
        assert counts(conn) == (1, 0)


def test_file_and_memory_digests_equal_for_every_source(tmp_path):
    data = b'raw bytes\n'
    path = tmp_path / 'log'
    path.write_bytes(data)
    for source in ('auth_log', 'suricata', 'sysmon', 'normalized'):
        assert file_digest(source, data, year=2026, tz='+07:00') == file_digest_path(source, path, year=2026, tz='+07:00')


def test_dashboard_rolls_back_real_incident_created_before_failure(tmp_path, monkeypatch):
    """An exception after creating a genuine incident must leave the DB empty."""
    from pathlib import Path
    holdout = Path(__file__).resolve().parents[1] / 'data' / 'holdout' / 'auth.log'
    db_path = tmp_path / 'real_incident_rollback.db'
    original = ui_data.save_new_incidents
    with connect(db_path) as conn:
        init_db(conn)
        def save_then_fail(conn, incidents):
            created = original(conn, incidents)
            assert created >= 1  # must actually create incident evidence first
            raise RuntimeError('failure after real incident')
        monkeypatch.setattr(ui_data, 'save_new_incidents', save_then_fail)
        with pytest.raises(RuntimeError, match='failure after real incident'):
            ui_data.analyze_log(conn, 'auth_log', holdout.read_bytes(), year=2026, tz='+07:00')
        assert counts(conn) == (0, 0)
        assert conn.execute('SELECT COUNT(*) FROM incident_events').fetchone()[0] == 0
        assert conn.execute('SELECT COUNT(*) FROM ingested_files').fetchone()[0] == 0
