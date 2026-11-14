"""auth.log ingestor: time conventions, message types, broken lines, statistics."""
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ingestors import auth_log
from ingestors.auth_log import parse_lines, parse_tz
from normalizer.schema import REQUIRED_FIELDS
from storage.models import connect, init_db, insert_events, list_events

SAMPLE = Path(__file__).parent / "data" / "auth_sample.log"
FAILED = "sshd[3001]: Failed password for root from 203.0.113.50 port 40118 ssh2"


def events(text, **options):
    options.setdefault("year", 2026)
    return list(parse_lines(text.splitlines(True), **options))


def one(text, **options):
    (event,) = events(text, **options)
    return event


# ---- the sample file --------------------------------------------------------

def test_sample_file_counts_and_actions():
    stats = {}
    found = list(auth_log.parse_file(SAMPLE, stats, year=2026))
    assert [e["action"] for e in found] == [
        "ssh_success", "sudo_command", "sudo_failed", "sudo_denied",
        "ssh_invalid_user", "ssh_failed", "ssh_failed", "ssh_failed", "ssh_failed",
        "ssh_max_auth_exceeded", "ssh_failed", "ssh_success",
        "ssh_failed", "ssh_lockout", "ssh_failed", "ssh_failed",
    ]
    assert (stats["lines"], stats["events"], stats["ignored"], stats["invalid"]) == (22, 16, 5, 2)
    assert stats["reasons"]["invalid: no syslog timestamp"] == 1
    assert stats["reasons"]["invalid: impossible date"] == 1
    for event in found:
        assert set(REQUIRED_FIELDS) <= set(event)
        assert event["source_type"] == "auth_log" and event["timestamp_utc"].endswith("Z")


def test_sample_file_goes_into_storage(tmp_path):
    with connect(tmp_path / "soc.db") as db:
        init_db(db)
        assert insert_events(db, auth_log.parse_file(SAMPLE, year=2026)) == 16
        stored = list_events(db)
    assert stored[0]["raw"]["line"].startswith("Nov 12 08:00:12 bastion-01 sshd[2101]: Accepted publickey")


# ---- time zone and year -----------------------------------------------------

def test_default_zone_is_utc_plus_7_and_time_becomes_utc():
    event = one(f"Nov 12 08:40:03 bastion-01 {FAILED}\n")
    assert event["timestamp_utc"] == "2026-11-12T01:40:03.000000Z"


def test_zone_can_be_given_as_argument_or_environment(monkeypatch):
    line = f"Nov 12 08:40:03 bastion-01 {FAILED}\n"
    assert one(line, tz="-05:00")["timestamp_utc"] == "2026-11-12T13:40:03.000000Z"
    assert one(line, tz="UTC")["timestamp_utc"] == "2026-11-12T08:40:03.000000Z"
    monkeypatch.setenv("SOC_AUTH_LOG_TZ", "+0900")
    assert one(line)["timestamp_utc"] == "2026-11-11T23:40:03.000000Z"
    assert one(line, tz="+07:00")["timestamp_utc"] == "2026-11-12T01:40:03.000000Z"   # argument wins


def test_parse_tz_accepts_common_spellings_and_rejects_nonsense():
    assert parse_tz("+07:00") == parse_tz("+0700") == parse_tz("+07") == timezone(timedelta(hours=7))
    assert parse_tz("-05:30") == timezone(-timedelta(hours=5, minutes=30))
    assert parse_tz("Z") == parse_tz("utc") == timezone.utc
    for bad in ("Asia/Ho_Chi_Minh", "7", "+25:00", ""):
        with pytest.raises(ValueError):
            parse_tz(bad)


def test_year_from_argument_then_environment(monkeypatch):
    line = f"Nov 12 08:40:03 bastion-01 {FAILED}\n"
    assert one(line, year=2024)["timestamp_utc"].startswith("2024-11-12")
    monkeypatch.setenv("SOC_AUTH_LOG_YEAR", "2023")
    assert one(line, year=None)["timestamp_utc"].startswith("2023-11-12")
    assert one(line, year=2024)["timestamp_utc"].startswith("2024-11-12")            # argument wins


def test_year_is_guessed_from_today_when_nothing_is_configured(monkeypatch):
    monkeypatch.delenv("SOC_AUTH_LOG_YEAR", raising=False)
    zone = timezone(timedelta(hours=7))
    line = f"Dec 31 23:59:00 bastion-01 {FAILED}\n"
    # Read on 2 January 2027: "Dec 31" of 2027 would lie in the future, so it is 2026.
    assert one(line, year=None, now=datetime(2027, 1, 2, tzinfo=zone))["timestamp_utc"].startswith("2026-12-31")
    # Read later the same evening: this year.
    assert one(line, year=None, now=datetime(2026, 12, 31, 23, 59, 30, tzinfo=zone))["timestamp_utc"].startswith("2026-12-31")
    # A log line a few hours "ahead" (clock skew) still belongs to this year.
    line = f"Nov 12 20:00:00 bastion-01 {FAILED}\n"
    assert one(line, year=None, now=datetime(2026, 11, 12, 8, tzinfo=zone))["timestamp_utc"].startswith("2026-11-12")


def test_file_that_crosses_new_year_moves_to_the_next_year():
    text = (f"Dec 31 23:59:58 bastion-01 {FAILED}\n"
            f"Jan  1 00:00:01 bastion-01 {FAILED}\n"
            f"Dec 31 23:59:59 bastion-01 {FAILED}\n"      # late line, still last year
            f"Jan  1 00:00:02 bastion-01 {FAILED}\n")
    assert [e["timestamp_utc"] for e in events(text, year=2026, tz="UTC")] == [
        "2026-12-31T23:59:58.000000Z", "2027-01-01T00:00:01.000000Z",
        "2026-12-31T23:59:59.000000Z", "2027-01-01T00:00:02.000000Z",
    ]


def test_29_february_exists_only_in_leap_years():
    line = f"Feb 29 10:00:00 bastion-01 {FAILED}\n"
    assert one(line, year=2028)["timestamp_utc"].startswith("2028-02-29")
    stats = {}
    assert list(parse_lines([line], stats, year=2027)) == []
    assert stats["invalid"] == 1


def test_single_digit_day_is_padded_with_a_space():
    assert one(f"Nov  2 08:40:03 bastion-01 {FAILED}\n")["timestamp_utc"] == "2026-11-02T01:40:03.000000Z"


def test_iso_timestamp_lines_keep_their_own_zone():
    event = one(f"2025-03-01T10:00:00.250000-05:00 bastion-01 {FAILED}\n", year=2026, tz="+07:00")
    assert event["timestamp_utc"] == "2025-03-01T15:00:00.250000Z"
    event = one(f"2025-03-01T10:00:00Z bastion-01 {FAILED}\n")
    assert event["timestamp_utc"] == "2025-03-01T10:00:00.000000Z"


# ---- message types ----------------------------------------------------------

def test_failed_password_fields():
    event = one(f"Nov 12 08:40:03 bastion-01 {FAILED}\n")
    assert (event["action"], event["severity"]) == ("ssh_failed", "medium")
    assert (event["src_ip"], event["username"], event["hostname"]) == ("203.0.113.50", "root", "bastion-01")
    assert event["dst_ip"] is None and event["dst_port"] is None
    assert event["raw"]["src_port"] == 40118 and event["raw"]["invalid_user"] is False


def test_invalid_user_gives_one_failure_not_two():
    found = events("Nov 12 08:40:01 bastion-01 sshd[3001]: Invalid user admin from 203.0.113.50 port 40112\n"
                   "Nov 12 08:40:03 bastion-01 sshd[3001]: Failed password for invalid user admin from 203.0.113.50 port 40112 ssh2\n")
    assert [e["action"] for e in found] == ["ssh_invalid_user", "ssh_failed"]
    assert found[1]["username"] == "admin" and found[1]["raw"]["invalid_user"] is True


def test_accepted_password_and_publickey_are_both_a_success():
    found = events("Nov 12 08:00:12 bastion-01 sshd[2101]: Accepted publickey for alice from 10.0.2.21 port 50122 ssh2: ED25519 SHA256:SYNTHETICx0001\n"
                   "Nov 12 08:00:15 bastion-01 sshd[2102]: Accepted password for bob from 10.0.2.22 port 50123 ssh2\n")
    assert [(e["action"], e["username"], e["src_ip"], e["raw"]["method"]) for e in found] == [
        ("ssh_success", "alice", "10.0.2.21", "publickey"), ("ssh_success", "bob", "10.0.2.22", "password")]


def test_failed_publickey_is_not_a_password_failure():
    stats = {}
    line = "Nov 12 08:00:12 bastion-01 sshd[2101]: Failed publickey for alice from 10.0.2.21 port 50122 ssh2\n"
    assert list(parse_lines([line], stats, year=2026)) == []
    assert stats["ignored"] == 1


def test_repeated_message_is_expanded():
    found = events("Nov 12 08:40:09 bastion-01 sshd[3002]: message repeated 3 times: "
                   "[ Failed password for root from 203.0.113.50 port 40118 ssh2]\n")
    assert [e["action"] for e in found] == ["ssh_failed"] * 3
    assert {e["timestamp_utc"] for e in found} == {"2026-11-12T01:40:09.000000Z"}


def test_lockout_takes_the_ip_from_the_same_sshd_process():
    found = events("Nov 12 09:10:22 web-01 sshd[4100]: Failed password for alice from 198.51.100.23 port 51000 ssh2\n"
                   "Nov 12 09:10:23 web-01 sshd[4999]: Failed password for alice from 10.0.2.21 port 51900 ssh2\n"
                   "Nov 12 09:10:25 web-01 sshd[4100]: pam_faillock(sshd:auth): Consecutive login failures for user alice account temporarily locked\n")
    lock = found[-1]
    assert (lock["action"], lock["severity"], lock["username"]) == ("ssh_lockout", "high", "alice")
    assert lock["src_ip"] == "198.51.100.23"          # pid 4100, not the newer line of pid 4999


def test_lockout_falls_back_to_the_last_ip_seen_for_that_user():
    found = events("Nov 12 09:10:20 web-01 sshd[4100]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.23  user=alice\n"
                   "Nov 12 09:10:25 web-01 sshd[4200]: pam_tally2(sshd:auth): user alice (1001) tally 6, deny 5\n")
    assert [(e["action"], e["src_ip"]) for e in found] == [("ssh_lockout", "198.51.100.23")]


def test_lockout_without_any_earlier_line_has_no_ip():
    lock = one("Nov 12 09:10:25 web-01 sshd[4100]: pam_faillock(sshd:auth): Consecutive login failures for user alice account temporarily locked\n")
    assert lock["action"] == "ssh_lockout" and lock["src_ip"] is None
    assert lock["raw"]["src_ip_from"] == "unknown"


def test_lockout_on_another_host_does_not_borrow_the_ip():
    found = events("Nov 12 09:10:22 web-01 sshd[4100]: Failed password for alice from 198.51.100.23 port 51000 ssh2\n"
                   "Nov 12 09:10:25 db-01 sshd[4100]: pam_faillock(sshd:auth): Consecutive login failures for user alice account temporarily locked\n")
    assert found[-1]["src_ip"] is None


def test_sudo_lines():
    found = events("Nov 12 08:05:44 bastion-01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update ; echo done\n"
                   "Nov 12 08:06:10 bastion-01 sudo:      bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/su -\n"
                   "Nov 12 08:07:30 bastion-01 sudo:  mallory : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/mallory ; USER=root ; COMMAND=/bin/bash\n")
    assert [(e["action"], e["severity"], e["username"]) for e in found] == [
        ("sudo_command", "info", "alice"), ("sudo_failed", "medium", "bob"), ("sudo_denied", "medium", "mallory")]
    assert found[0]["command_line"] == "/usr/bin/apt update ; echo done"
    assert found[0]["process_name"] == "sudo" and found[0]["src_ip"] is None
    assert found[0]["raw"]["run_as"] == "root" and found[0]["raw"]["cwd"] == "/home/alice"


def test_host_name_instead_of_ip_is_kept_but_not_used_as_address():
    event = one("Nov 12 09:13:00 web-01 sshd[4103]: Failed password for dave from client.lab.example port 51003 ssh2\n")
    assert event["src_ip"] is None and event["raw"]["client"] == "client.lab.example"


# ---- broken input and statistics ---------------------------------------------

def test_broken_and_uninteresting_lines_are_counted_not_fatal():
    stats = {}
    text = ("\n"
            "   \n"
            "complete garbage\n"
            "Nov 12 08:40:03 bastion-01\n"
            "Xyz 12 08:40:03 bastion-01 sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2\n"
            "Nov 12 25:00:00 bastion-01 sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2\n"
            "2026-13-45T00:00:00+07:00 bastion-01 sshd[1]: Failed password for root from 203.0.113.50 port 1 ssh2\n"
            "Nov 12 08:17:01 bastion-01 CRON[2300]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)\n"
            f"Nov 12 08:40:03 bastion-01 {FAILED}\n")
    found = list(parse_lines(text.splitlines(True), stats, year=2026))
    assert len(found) == 1
    assert (stats["lines"], stats["events"], stats["ignored"], stats["invalid"]) == (7, 1, 1, 5)


def test_windows_line_endings_and_missing_final_newline():
    found = events(f"Nov 12 08:40:03 bastion-01 {FAILED}\r\nNov 12 08:40:04 bastion-01 {FAILED}")
    assert [e["timestamp_utc"][11:19] for e in found] == ["01:40:03", "01:40:04"]
    assert found[0]["raw"]["line"].endswith("ssh2")


def test_statistics_add_up_when_the_same_dict_is_reused():
    stats = {}
    for _ in range(2):
        list(parse_lines([f"Nov 12 08:40:03 bastion-01 {FAILED}\n", "garbage\n"], stats, year=2026))
    assert (stats["lines"], stats["events"], stats["invalid"]) == (4, 2, 2)
    assert stats["reasons"] == {"invalid: no syslog timestamp": 2}


def test_file_with_utf8_bom_and_utf16_are_read(tmp_path):
    line = f"Nov 12 08:40:03 bastion-01 {FAILED}\n"
    for name, encoding in (("bom.log", "utf-8-sig"), ("utf16.log", "utf-16")):
        path = tmp_path / name
        path.write_text(line, encoding=encoding)
        (event,) = auth_log.parse_file(path, year=2026)
        assert event["action"] == "ssh_failed"


def test_generated_brute_force_is_detected_by_the_engine():
    """Cross-module check; runs once the correlation engine is in the repo."""
    correlation = pytest.importorskip("engine.correlation")
    found = list(auth_log.parse_file(SAMPLE, year=2026))
    for number, event in enumerate(found, start=1):
        event["id"] = number
    incidents = correlation.detect_incidents(found)
    assert [(i["rule_id"], i["severity"]) for i in incidents] == [("SSH_BRUTE_FORCE", "critical")]
    assert "203.0.113.50" in incidents[0]["summary"]

# ---- regressions: lockout IP hints must be fresh and attributable -----------

def test_regression_lockout_does_not_borrow_stale_ip_hours_later():
    found = events(
        "Nov 12 08:00:00 web-01 sshd[4100]: Failed password for alice from 203.0.113.1 port 51000 ssh2\n"
        "Nov 12 20:30:00 web-01 sshd[4100]: pam_faillock(sshd:auth): "
        "Consecutive login failures for user alice account temporarily locked\n"
    )
    lock = found[-1]
    assert lock["action"] == "ssh_lockout"
    assert lock["src_ip"] is None
    assert lock["raw"]["src_ip_from"] == "unknown"


def test_regression_lockout_ip_within_five_minutes_is_accepted_inclusive():
    found = events(
        "Nov 12 09:00:00 web-01 sshd[4100]: Failed password for alice from 203.0.113.1 port 51000 ssh2\n"
        "Nov 12 09:05:00 web-01 sshd[4100]: pam_faillock(sshd:auth): "
        "Consecutive login failures for user alice account temporarily locked\n"
    )
    assert found[-1]["src_ip"] == "203.0.113.1"
    assert found[-1]["raw"]["src_ip_from"] == "recent sshd process"


def test_regression_lockout_at_five_minutes_and_one_second_has_no_ip():
    found = events(
        "Nov 12 09:00:00 web-01 sshd[4100]: Failed password for alice from 203.0.113.1 port 51000 ssh2\n"
        "Nov 12 09:05:01 web-01 sshd[4100]: pam_faillock(sshd:auth): "
        "Consecutive login failures for user alice account temporarily locked\n"
    )
    assert found[-1]["src_ip"] is None


def test_regression_lockout_mismatched_pid_user_does_not_misattribute_ip():
    found = events(
        "Nov 12 09:00:00 web-01 sshd[4100]: Failed password for bob from 203.0.113.2 port 51000 ssh2\n"
        "Nov 12 09:00:01 web-01 sshd[4100]: pam_faillock(sshd:auth): "
        "Consecutive login failures for user alice account temporarily locked\n"
    )
    assert found[-1]["src_ip"] is None


def test_regression_pid_missing_does_not_mix_different_users():
    found = events(
        "Nov 12 09:00:00 web-01 sshd: Failed password for bob from 203.0.113.2 port 51000 ssh2\n"
        "Nov 12 09:00:01 web-01 sshd: pam_faillock(sshd:auth): "
        "Consecutive login failures for user alice account temporarily locked\n"
    )
    assert found[-1]["src_ip"] is None


def test_regression_future_ip_observation_is_not_used_for_earlier_lockout():
    found = events(
        "Nov 12 09:00:05 web-01 sshd[4100]: Failed password for alice from 203.0.113.2 port 51000 ssh2\n"
        "Nov 12 09:00:00 web-01 sshd[4100]: pam_faillock(sshd:auth): "
        "Consecutive login failures for user alice account temporarily locked\n"
    )
    assert found[-1]["src_ip"] is None


def test_regression_late_old_line_does_not_override_latest_client():
    found = events(
        "Nov 12 09:00:04 web-01 sshd[4100]: Failed password for alice from 203.0.113.2 port 51000 ssh2\n"
        "Nov 12 09:00:00 web-01 sshd[4100]: Failed password for alice from 203.0.113.1 port 51000 ssh2\n"
        "Nov 12 09:00:05 web-01 sshd[4100]: pam_faillock(sshd:auth): "
        "Consecutive login failures for user alice account temporarily locked\n"
    )
    assert found[-1]["src_ip"] == "203.0.113.2"


# ---- regressions: classic syslog must follow ISO year/time anchors ---------

def test_regression_iso_timestamp_reanchors_classic_new_year():
    found = events(
        "2025-12-31T23:59:58+07:00 web-01 sshd[3001]: Failed password for alice from 203.0.113.2 port 51000 ssh2\n"
        "Jan  1 00:00:02 web-01 sshd[3001]: Failed password for alice from 203.0.113.2 port 51000 ssh2\n",
        year=2025, tz="+07:00"
    )
    assert [e["timestamp_utc"] for e in found] == [
        "2025-12-31T16:59:58.000000Z",
        "2025-12-31T17:00:02.000000Z",
    ]


def test_regression_iso_timestamp_other_zone_anchors_local_syslog():
    found = events(
        "2025-12-31T23:58:00Z web-01 sshd[3001]: Failed password for alice from 203.0.113.2 port 51000 ssh2\n"
        "Jan  1 07:59:00 web-01 sshd[3001]: Failed password for alice from 203.0.113.2 port 51000 ssh2\n",
        year=2025, tz="+07:00"
    )
    assert [e["timestamp_utc"] for e in found] == [
        "2025-12-31T23:58:00.000000Z",
        "2026-01-01T00:59:00.000000Z",
    ]


def test_regression_invalid_iso_tag_does_not_reanchor_clock():
    stats = {}
    found = list(parse_lines([
        "Dec 31 23:58:00 web-01 sshd[3001]: Failed password for alice from 203.0.113.2 port 51000 ssh2\n",
        "2030-01-01T00:00:00+07:00 bad-tag-without-program\n",
        "Jan  1 00:00:01 web-01 sshd[3001]: Failed password for alice from 203.0.113.2 port 51000 ssh2\n",
    ], stats, year=2025, tz="+07:00"))
    assert [e["timestamp_utc"][:10] for e in found] == ["2025-12-31", "2025-12-31"]
    assert stats["invalid"] == 1


# ---- regressions: invalid time zone components -----------------------------

@pytest.mark.parametrize("bad", ["+00:60", "-05:60", "+12:99", "+13:60", "+14:01", "-14:01"])
def test_regression_parse_tz_rejects_invalid_minute_components(bad):
    with pytest.raises(ValueError):
        parse_tz(bad)


# ---- regressions: sudo failure/denial without COMMAND= ---------------------

def test_regression_sudo_denied_without_command_is_an_event():
    event = one(
        "Nov 12 08:07:30 bastion-01 sudo: mallory : user NOT in sudoers ; TTY=pts/2 ; PWD=/home/mallory ; USER=root\n"
    )
    assert (event["action"], event["severity"], event["username"]) == ("sudo_denied", "medium", "mallory")
    assert event["command_line"] is None and event["raw"]["run_as"] == "root"


def test_regression_sudo_failed_without_command_is_an_event():
    event = one(
        "Nov 12 08:06:10 bastion-01 sudo: bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; USER=root\n"
    )
    assert (event["action"], event["severity"], event["username"]) == ("sudo_failed", "medium", "bob")
    assert event["command_line"] is None


def test_regression_sudo_pam_auth_failure_without_command_is_an_event():
    event = one(
        "Nov 12 08:06:10 bastion-01 sudo[1234]: pam_unix(sudo:auth): authentication failure; "
        "logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost= user=alice\n"
    )
    assert (event["action"], event["severity"], event["username"]) == ("sudo_failed", "medium", "alice")
    assert event["command_line"] is None


def test_regression_sudo_unrelated_pam_session_remains_ignored():
    stats = {}
    found = list(parse_lines([
        "Nov 12 08:06:10 bastion-01 sudo[1234]: pam_unix(sudo:session): session opened for user root(uid=0) by alice(uid=1000)\n",
    ], stats, year=2026))
    assert found == [] and stats["ignored"] == 1


def test_regression_sudo_denied_with_case_insensitive_not_allowed():
    event = one(
        "Nov 12 08:07:30 bastion-01 sudo: mallory : user NOT ALLOWED to execute sudo ; TTY=pts/2\n"
    )
    assert event["action"] == "sudo_denied"
    assert event["username"] == "mallory"


def test_regression_sudo_extended_actions_are_compatible_with_storage(tmp_path):
    raw = (
        "Nov 12 08:06:10 bastion-01 sudo[1234]: pam_unix(sudo:auth): authentication failure; user=alice\n"
        "Nov 12 08:07:30 bastion-01 sudo: mallory : user NOT in sudoers ; TTY=pts/2\n"
    )
    with connect(tmp_path / "extended.db") as db:
        init_db(db)
        assert insert_events(db, parse_lines(raw.splitlines(True), year=2026)) == 2
        assert {e["action"] for e in list_events(db)} == {"sudo_failed", "sudo_denied"}
