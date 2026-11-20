"""Dashboard: database queries (ui/data.py) and the Streamlit page itself."""
from contextlib import closing
from pathlib import Path

import pytest

from engine.correlation import detect_incidents
from engine.incident import save_new_incidents
from eval.dataset import ingest_dataset
from storage.models import connect, counts, init_db, list_events
from ui import data

ROOT = Path(__file__).resolve().parent.parent
BENCHMARK = ROOT / "data" / "benchmark"
HOLDOUT_LOG = ROOT / "data" / "holdout" / "auth.log"


@pytest.fixture(scope="module")
def template_db(tmp_path_factory):
    """A database filled from the benchmark, with detection already run."""
    path = tmp_path_factory.mktemp("dashboard") / "template.db"
    with closing(connect(path)) as conn:
        init_db(conn)
        ingest_dataset(conn, BENCHMARK)
        save_new_incidents(conn, detect_incidents(list_events(conn)))
    return path


@pytest.fixture
def db_path(template_db, tmp_path):
    path = tmp_path / "soc.db"
    path.write_bytes(template_db.read_bytes())
    return path


@pytest.fixture
def db(db_path):
    with closing(connect(db_path)) as conn:
        yield conn


# ---- reading the SQLite database ---------------------------------------------------

def test_overview_numbers(db):
    numbers = data.overview(db)
    assert (numbers["events"], numbers["incidents"], numbers["open_incidents"]) == (1138, 9, 9)
    assert numbers["open_serious"] == 5 and numbers["by_status"] == {"New": 9}
    assert numbers["by_source"] == {"auth_log": 82, "suricata": 780, "sysmon": 276}
    assert numbers["first_event_utc"] < numbers["last_event_utc"]


def test_overview_of_an_empty_database(tmp_path):
    with closing(connect(tmp_path / "empty.db")) as conn:
        init_db(conn)
        numbers = data.overview(conn)
        assert (numbers["events"], numbers["incidents"], numbers["open_incidents"]) == (0, 0, 0)
        assert data.top_assets(conn) == [] and data.list_incidents(conn) == []
        assert data.search_events(conn) == ([], 0)


def test_top_assets_are_our_own_machines(db):
    assets = data.top_assets(db, limit=8)
    assert assets[0] == {"asset": "10.0.1.20", "incidents": 2, "events": 62}      # file server: scan + pivot
    names = [row["asset"] for row in assets]
    assert "bastion-01" in names and "10.0.2.40" in names                         # brute-forced server, infected host
    assert "203.0.113.200" not in names and "sensor-01" not in names              # not the C2 server, not the sensor
    assert len(data.top_assets(db, limit=3)) == 3


def test_attacked_asset_choices():
    assert data.attacked_asset({"dst_ip": "10.0.1.10", "src_ip": "10.0.2.99", "hostname": "sensor-01", "source_type": "suricata"}) == "10.0.1.10"
    assert data.attacked_asset({"dst_ip": None, "src_ip": "203.0.113.50", "hostname": "bastion-01", "source_type": "auth_log"}) == "bastion-01"
    assert data.attacked_asset({"dst_ip": "203.0.113.200", "src_ip": "10.0.2.40", "hostname": "sensor-01", "source_type": "suricata"}) == "10.0.2.40"
    assert data.attacked_asset({"dst_ip": "192.0.2.80", "src_ip": "203.0.113.5", "hostname": "sensor-01", "source_type": "suricata"}) is None


def test_incident_list_and_filters(db):
    incidents = data.list_incidents(db)
    assert len(incidents) == 9 and incidents[0]["mitre"] == "T1071" and incidents[0]["event_count"] == 40
    assert [i["first_seen_utc"] for i in incidents] == sorted(i["first_seen_utc"] for i in incidents)
    assert len(data.list_incidents(db, severities=["critical"])) == 2
    assert {i["rule_id"] for i in data.list_incidents(db, rule_ids=["SSH_BRUTE_FORCE"])} == {"SSH_BRUTE_FORCE"}
    assert data.list_incidents(db, statuses=["Closed"]) == []
    assert len(data.list_incidents(db, statuses=["New"], severities=["high", "critical"])) == 5


# ---- filters of the log search ---------------------------------------------------------

def test_search_by_ip_exact_and_by_range(db):
    rows, total = data.search_events(db, ip="203.0.113.50")
    assert total == len(rows) == 17 and {r["src_ip"] for r in rows} == {"203.0.113.50"}
    _, as_destination = data.search_events(db, ip="10.0.1.20")
    assert as_destination > 60                                                    # matches the destination too
    _, whole_range = data.search_events(db, ip="203.0.113.")
    assert whole_range > total
    assert data.search_events(db, ip="203.0.113.5")[1] == 0                       # exact means exact


def test_search_by_time_severity_source_action_and_text(db):
    _, total = data.search_events(db, start_utc="2026-11-12T01:25:00.000000Z", end_utc="2026-11-12T01:25:44.000000Z",
                                  sources=["auth_log"])
    assert total == 17                                                            # the first brute-force attack
    rows, total = data.search_events(db, severities=["high"], actions=["alert"])
    assert total == 41 and {r["severity"] for r in rows} == {"high"}
    rows, total = data.search_events(db, text="invoice_viewer")
    assert total == 3 and rows[0]["process_name"].endswith("invoice_viewer.exe")
    assert data.search_events(db, text="100%_no_such_text")[1] == 0               # % and _ are plain characters
    assert data.search_events(db, sources=["sysmon"], severities=["critical"])[1] == 0


def test_search_pages_do_not_overlap(db):
    first, total = data.search_events(db, sources=["suricata"], limit=50, offset=0)
    second, _ = data.search_events(db, sources=["suricata"], limit=50, offset=50)
    assert total == 780 and len(first) == len(second) == 50
    assert not {r["id"] for r in first} & {r["id"] for r in second}
    assert first[-1]["timestamp_utc"] <= second[0]["timestamp_utc"]


def test_filter_choices_only_for_known_columns(db):
    assert data.filter_choices(db, "source_type") == ["auth_log", "suricata", "sysmon"]
    assert "ssh_failed" in data.filter_choices(db, "action")
    with pytest.raises(ValueError):
        data.filter_choices(db, "raw_json; DROP TABLE events")


# ---- changing an incident, exporting the summary -----------------------------------------

def test_update_incident_status_and_analyst(db):
    data.update_incident(db, 2, "In Progress", "  analyst1 ")
    incident, events = data.incident_details(db, 2)
    assert (incident["status"], incident["assigned_analyst"]) == ("In Progress", "analyst1") and len(events) == 13
    data.update_incident(db, 2, "Closed", "analyst1")
    assert data.overview(db)["open_incidents"] == 8 and data.overview(db)["open_serious"] == 4
    data.update_incident(db, 2, "Closed", "")
    assert data.incident_details(db, 2)[0]["assigned_analyst"] is None
    with pytest.raises(ValueError):
        data.update_incident(db, 2, "Done", "analyst1")


def test_investigation_summary_export(db):
    text = data.investigation_summary(db, 2)
    assert text.startswith("# Incident #2: SSH brute-force detected (login succeeded)")
    assert "203.0.113.50" in text and "MITRE ATT&CK: T1110" in text and "## Suggested next steps" in text


# ---- analysing an uploaded log ---------------------------------------------------------------

def test_uploaded_log_is_stored_and_correlated(db):
    content = HOLDOUT_LOG.read_bytes()
    result = data.analyze_log(db, "auth_log", content, year=2026, tz="+07:00")
    assert result["stored"] == result["stats"]["events"] > 30 and result["stats"]["invalid"] == 0
    assert len(result["new_incident_ids"]) >= 1
    new = [data.incident_details(db, incident_id)[0] for incident_id in result["new_incident_ids"]]
    assert {incident["rule_id"] for incident in new} == {"SSH_BRUTE_FORCE"}
    assert counts(db)[1] == 9 + len(new)
    assert data.file_digest("auth_log", content) != data.file_digest("suricata", content)
    with pytest.raises(ValueError):
        data.analyze_log(db, "firewall", b"x")


def test_uploaded_garbage_is_counted_not_fatal(db):
    result = data.analyze_log(db, "suricata", b"this is not json\n{broken\n")
    assert result["stored"] == 0 and result["stats"]["invalid"] == 2 and result["new_incident_ids"] == []


# ---- the Streamlit page ---------------------------------------------------------------------

def run_page(db_path, monkeypatch):
    testing = pytest.importorskip("streamlit.testing.v1")
    monkeypatch.setenv("SOC_DB_PATH", str(db_path))
    page = testing.AppTest.from_file(str(ROOT / "ui" / "dashboard.py"), default_timeout=60).run()
    assert not page.exception, [item.value for item in page.exception]
    return page


def test_page_shows_the_database(db_path, monkeypatch):
    page = run_page(db_path, monkeypatch)
    assert [(m.label, m.value) for m in page.metric] == [
        ("Tổng sự kiện", "1,138"), ("Incident đang mở", "9"), ("Đang mở, mức high/critical", "5"), ("Tổng incident", "9")]
    assert [tab.label for tab in page.tabs] == ["Tổng quan", "Incident", "Tìm kiếm log", "Phân tích log mới"]
    assert any("1,138 sự kiện khớp" in caption.value for caption in page.caption)


def test_page_on_an_empty_database(tmp_path, monkeypatch):
    page = run_page(tmp_path / "new.db", monkeypatch)
    assert page.metric[0].value == "0" and any("Chưa có dữ liệu" in info.value for info in page.info)


def test_page_changes_an_incident(db_path, monkeypatch):
    page = run_page(db_path, monkeypatch)
    page.selectbox(key="incident_pick").select(2).run()
    page.selectbox(key="status_2").select("In Progress")
    page.text_input(key="analyst_2").input("analyst1")
    next(button for button in page.button if button.label == "Lưu thay đổi").click().run()
    assert not page.exception
    assert any("Đã cập nhật incident #2" in message.value for message in page.success)
    with closing(connect(db_path)) as conn:
        row = conn.execute("SELECT status, assigned_analyst FROM incidents WHERE incident_id = 2").fetchone()
    assert tuple(row) == ("In Progress", "analyst1")


def test_page_filters_the_log_search(db_path, monkeypatch):
    page = run_page(db_path, monkeypatch)
    page.text_input(key="search_ip").input("203.0.113.50").run()
    assert any(caption.value.startswith("17 sự kiện khớp") for caption in page.caption)
    page.multiselect(key="search_severity").select("info").run()
    assert any(caption.value.startswith("1 sự kiện khớp") for caption in page.caption)   # the successful login
