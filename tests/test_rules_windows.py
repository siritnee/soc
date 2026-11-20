"""Rule 3 (Suspicious Process Execution) and rule 4 (Network-to-Host Pivot)."""
from datetime import datetime, timedelta, timezone

import pytest

from engine.correlation import CorrelationEngine, default_rules, format_ts
from engine.rules.windows import (
    RULES, NetworkToHostPivotRule, SuspiciousProcessRule, is_encoded_flag, uses_encoded_powershell,
)

T0 = datetime(2026, 11, 12, 1, 0, 0, tzinfo=timezone.utc)
ATTACKER = "203.0.113.77"          # documentation range = the Internet in the lab
VICTIM = "10.0.2.24"               # Windows workstation with Sysmon
FILE_SERVER = "10.0.1.20"
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
TEMP_EXE = "C:\\Users\\alice\\AppData\\Local\\Temp\\invoice_viewer.exe"


class Log:
    """Builds canonical events with increasing ids, like rows read from storage."""

    def __init__(self):
        self.events = []

    def _add(self, offset, source_type, action, **fields):
        event = {"id": len(self.events) + 1, "timestamp_utc": format_ts(T0 + timedelta(seconds=offset)),
                 "source_type": source_type, "action": action, "severity": "info",
                 "src_ip": None, "dst_ip": None, "dst_port": None, "username": None, "hostname": None,
                 "process_name": None, "command_line": None, "signature": None}
        event.update(fields)
        self.events.append(event)
        return self

    def process(self, offset, image, command_line=None, host="WS-01.lab.example", user="LAB\\alice"):
        return self._add(offset, "sysmon", "process_create", process_name=image,
                         command_line=command_line if command_line is not None else f"\"{image}\"",
                         hostname=host, username=user)

    def alert(self, offset, src_ip=ATTACKER, dst_ip=VICTIM, severity="high", source_type="suricata"):
        return self._add(offset, source_type, "alert", src_ip=src_ip, dst_ip=dst_ip, dst_port=445,
                         severity=severity, signature="LAB EXPLOIT test", hostname="sensor-01")

    def connection(self, offset, src_ip=VICTIM, dst_ip=FILE_SERVER, port=445, source_type="sysmon",
                   action="network_connection"):
        return self._add(offset, source_type, action, src_ip=src_ip, dst_ip=dst_ip, dst_port=port,
                         hostname="WS-04.lab.example", process_name="System")


def suspicious(events, **options):
    return CorrelationEngine([SuspiciousProcessRule(**options)]).run(events)


def pivot(events, **options):
    return CorrelationEngine([NetworkToHostPivotRule(**options)]).run(events)


# ---- rule 3: where the program runs from ---------------------------------------

@pytest.mark.parametrize("image", [
    TEMP_EXE,
    "C:\\Windows\\Temp\\update.exe",
    "C:\\Temp\\tool.exe",
    "C:\\Users\\bob\\AppData\\Roaming\\helper.exe",
    "c:\\users\\bob\\appdata\\local\\temp\\LOWER.EXE",            # case does not matter
    "C:/Users/bob/AppData/Local/Temp/slashes.exe",                # nor do forward slashes
])
def test_program_in_appdata_or_temp_is_reported(image):
    (incident,) = suspicious(Log().process(0, image).events)
    assert incident.rule_id == "SUSPICIOUS_PROCESS" and incident.severity == "medium"
    assert incident.mitre == "T1059.001" and incident.event_ids == [1]
    assert "user-writable folder" in incident.summary and "LAB\\alice" in incident.summary


@pytest.mark.parametrize("image", [
    "C:\\Windows\\System32\\notepad.exe",
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Users\\bob\\Documents\\Templates\\report.exe",           # "Templates" is not "Temp"
    "C:\\Users\\bob\\Desktop\\temp.exe",                          # a file named temp, not the folder
    "C:\\Tools\\MyAppData\\tool.exe",
])
def test_ordinary_locations_are_not_reported(image):
    assert suspicious(Log().process(0, image).events) == []


def test_allow_listed_programs_under_appdata_are_not_reported():
    log = (Log().process(0, "C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "/background")
           .process(1, "C:\\Users\\bob\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe"))
    assert suspicious(log.events) == []
    assert len(suspicious(log.events, allowlist=())) == 1              # without the list both are reported
    extra = Log().process(0, "C:\\Users\\bob\\AppData\\Local\\Programs\\Zoom\\Zoom.exe")
    assert len(suspicious(extra.events)) == 1
    assert suspicious(extra.events, allowlist=["\\AppData\\Local\\Programs\\Zoom\\"]) == []


# ---- rule 3: PowerShell with an encoded command ----------------------------------

@pytest.mark.parametrize("flag", ["-enc", "-EncodedCommand", "-e", "-ec", "-eNc", "-encod", "/enc", "\u2013enc"])
def test_every_spelling_of_the_encoded_flag_is_reported(flag):
    log = Log().process(0, POWERSHELL, f"powershell.exe -NoP -W Hidden {flag} VwByAGkAdABlAA==")
    (incident,) = suspicious(log.events)
    assert incident.severity == "high" and "encoded command" in incident.summary


@pytest.mark.parametrize("command_line", [
    "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1",
    "powershell.exe -ep bypass -ex unrestricted",
    "powershell.exe -Command \"Get-Process -Name explorer\"",
    "powershell.exe",
    "",
])
def test_plain_powershell_is_not_reported(command_line):
    assert suspicious(Log().process(0, POWERSHELL, command_line).events) == []


def test_flag_helpers():
    assert all(is_encoded_flag(flag) for flag in ("-e", "-en", "-enc", "-encodedcommand", "-EC", "/E"))
    assert not any(is_encoded_flag(text) for text in ("-ex", "-ep", "-f", "enc", "-", "", "-encx", "-encodedcommands"))
    assert uses_encoded_powershell("C:\\Program Files\\PowerShell\\7\\pwsh.exe", "\"C:\\Program Files\\PowerShell\\7\\pwsh.exe\" -enc AAAA")
    assert uses_encoded_powershell("C:\\Windows\\System32\\cmd.exe", "cmd.exe /c powershell -w hidden -enc AAAA")
    assert not uses_encoded_powershell("C:\\Tools\\grep.exe", "grep.exe -e pattern file.txt")
    assert not uses_encoded_powershell("C:\\Windows\\System32\\cmd.exe", "cmd.exe /e:on /c powershell -File a.ps1")


def test_encoded_powershell_started_from_temp_gives_both_reasons():
    log = Log().process(0, "C:\\Users\\alice\\AppData\\Local\\Temp\\powershell.exe", "powershell.exe -enc AAAA")
    (incident,) = suspicious(log.events)
    assert incident.severity == "high"
    assert "user-writable folder" in incident.summary and "encoded command" in incident.summary


def test_rule_3_ignores_other_events_and_missing_fields():
    log = Log().connection(0).alert(1)
    log._add(2, "sysmon", "process_create")                           # no image, no command line
    assert suspicious(log.events) == []


def test_processes_on_one_computer_become_one_incident_other_computers_their_own():
    log = (Log().process(0, TEMP_EXE).process(30, POWERSHELL, "powershell -enc AAAA")
           .process(60, TEMP_EXE, host="WS-02.lab.example", user="LAB\\bob"))
    engine = CorrelationEngine([SuspiciousProcessRule()])
    first, second = engine.run(log.events)
    assert first.dedup_key == "SUSPICIOUS_PROCESS|WS-01.lab.example"
    assert first.event_ids == [1, 2] and first.severity == "high" and first.raw_alert_count == 2
    assert second.dedup_key == "SUSPICIOUS_PROCESS|WS-02.lab.example" and second.severity == "medium"
    assert engine.stats.raw_alerts == 3 and engine.stats.incidents == 2


# ---- rule 4: network alert, then internal connection ------------------------------

def test_victim_of_a_high_alert_that_then_connects_inside_is_a_pivot():
    log = Log().alert(0).connection(45)
    (incident,) = pivot(log.events)
    assert incident.rule_id == "NETWORK_TO_HOST_PIVOT" and incident.severity == "critical"
    assert incident.mitre == "T1021" and incident.dedup_key == f"NETWORK_TO_HOST_PIVOT|{VICTIM}"
    assert incident.event_ids == [1, 2]                                # the Suricata alert and the Sysmon event
    assert incident.first_seen == T0 and incident.detected_at == T0 + timedelta(seconds=45)
    assert "45s later" in incident.summary and f"{FILE_SERVER}:445" in incident.summary


def test_source_of_the_alert_can_be_the_one_that_pivots():
    log = Log().alert(0, src_ip=VICTIM, dst_ip="203.0.113.200").connection(30)
    assert len(pivot(log.events)) == 1


def test_attacker_seen_by_sysmon_connecting_to_an_internal_host_also_counts():
    log = Log().alert(0).connection(20, src_ip=ATTACKER, dst_ip=VICTIM, port=3389)
    (incident,) = pivot(log.events)
    assert incident.dedup_key == f"NETWORK_TO_HOST_PIVOT|{ATTACKER}"


def test_time_window_600s_inclusive_601s_not_and_never_before_the_alert():
    assert len(pivot(Log().alert(0).connection(600).events)) == 1
    assert pivot(Log().alert(0).connection(601).events) == []
    assert pivot(Log().connection(0).alert(10).events) == []
    assert len(pivot(Log().alert(0).connection(120).events, window_seconds=120)) == 1
    assert pivot(Log().alert(0).connection(121).events, window_seconds=120) == []


@pytest.mark.parametrize("severity, expected", [("info", 0), ("low", 0), ("medium", 0), ("high", 1), ("critical", 1)])
def test_only_serious_alerts_arm_the_rule(severity, expected):
    assert len(pivot(Log().alert(0, severity=severity).connection(30).events)) == expected


def test_minimum_severity_is_a_parameter():
    assert len(pivot(Log().alert(0, severity="medium").connection(30).events, min_severity="medium")) == 1


def test_connection_must_go_to_another_internal_machine():
    assert pivot(Log().alert(0).connection(30, dst_ip="192.0.2.80").events) == []       # the Internet
    assert pivot(Log().alert(0).connection(30, dst_ip="203.0.113.5").events) == []
    assert pivot(Log().alert(0).connection(30, dst_ip=VICTIM).events) == []             # itself
    assert len(pivot(Log().alert(0).connection(30, dst_ip="192.168.1.5").events)) == 1


def test_connection_from_an_ip_that_was_not_in_the_alert_is_ignored():
    assert pivot(Log().alert(0).connection(30, src_ip="10.0.2.21").events) == []


def test_both_log_sources_are_required():
    # a Suricata flow from the victim is not "recorded by Sysmon"
    assert pivot(Log().alert(0).connection(30, source_type="suricata", action="flow").events) == []
    assert pivot(Log().alert(0).connection(30, source_type="suricata").events) == []
    # an "alert" that does not come from Suricata does not arm the rule
    assert pivot(Log().alert(0, source_type="sysmon").connection(30).events) == []


def test_many_connections_after_one_alert_are_one_incident():
    log = Log().alert(0).connection(45).connection(80, dst_ip="10.0.1.2").connection(130, dst_ip="10.0.2.21", port=3389)
    engine = CorrelationEngine([NetworkToHostPivotRule()])
    (incident,) = engine.run(log.events)
    assert incident.event_ids == [1, 2, 3, 4] and incident.raw_alert_count == 3
    assert "Internal connections since the alert: 3, to 3 machine(s)." in incident.summary
    assert f"connecting to {FILE_SERVER}:445" in incident.summary        # the first one stays in the text
    assert engine.stats.to_dict()["by_rule"] == {"NETWORK_TO_HOST_PIVOT": {"raw_alerts": 3, "incidents": 1}}


def test_connections_400s_apart_stay_one_incident():
    # the engine's default cooldown is 300 s; the rule asks for its own window instead
    (incident,) = pivot(Log().alert(0).connection(100).connection(500).events)
    assert incident.raw_alert_count == 2


def test_a_new_alert_restarts_the_window():
    assert pivot(Log().alert(0).connection(700).events) == []
    (incident,) = pivot(Log().alert(0).alert(500).connection(700).events)
    assert incident.event_ids == [2, 3] and incident.first_seen == T0 + timedelta(seconds=500)


def test_two_compromised_machines_are_two_incidents():
    log = (Log().alert(0).connection(30)
           .alert(60, dst_ip="10.0.2.23").connection(90, src_ip="10.0.2.23"))
    assert sorted(i.dedup_key for i in pivot(log.events)) == [
        "NETWORK_TO_HOST_PIVOT|10.0.2.23", f"NETWORK_TO_HOST_PIVOT|{VICTIM}"]


def test_sources_ingested_in_the_wrong_order_still_correlate():
    log = Log().connection(45).alert(0)            # Sysmon file loaded first: lower ids, later time
    (incident,) = pivot(log.events)
    assert sorted(incident.event_ids) == [1, 2] and incident.detected_at == T0 + timedelta(seconds=45)


# ---- integration with the engine ---------------------------------------------------

def test_engine_loads_the_windows_rules():
    assert [rule.__name__ for rule in RULES] == ["SuspiciousProcessRule", "NetworkToHostPivotRule"]
    ids = [rule.rule_id for rule in default_rules()]
    assert ids == ["SSH_BRUTE_FORCE", "INTERNAL_PORT_SCAN", "MALWARE_BEACONING",
                   "SUSPICIOUS_PROCESS", "NETWORK_TO_HOST_PIVOT"]
    assert all(rule.recommendations for rule in default_rules())


def test_rules_keep_no_state_between_runs():
    engine = CorrelationEngine([NetworkToHostPivotRule()])
    assert engine.run(Log().alert(0).events) == []
    assert engine.run(Log().connection(30).events) == []      # the alert of the first run is forgotten
