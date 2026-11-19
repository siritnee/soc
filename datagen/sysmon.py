"""Synthetic Sysmon events: everyday Windows activity plus labelled scenarios.

Records are flat JSON objects, one per line: ``EventID``, ``Computer``,
``UtcTime`` and the usual Sysmon fields. Hashes are random hex strings and
the "malware" is only a file name: nothing here comes from a real machine.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from typing import Sequence

from datagen import suricata as eve
from datagen.common import (
    DOMAIN, INTERNET_SITES, WINDOWS_HOSTS, WORKSTATION_USERS, Label, LogBundle, Rng, in_file_order,
)

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
_PROGRAMS = (
    ("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "--type=renderer"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "/n C:\\Users\\{user}\\Documents\\report.docx"),
    ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "C:\\Users\\{user}\\Documents\\budget.xlsx"),
    ("C:\\Windows\\System32\\notepad.exe", "C:\\Users\\{user}\\Desktop\\notes.txt"),
    ("C:\\Windows\\System32\\svchost.exe", "-k netsvcs -p"),
    # Harmless look-alikes for rule 3: allow-listed AppData programs and plain PowerShell.
    ("C:\\Users\\{user}\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe", "/background"),
    ("C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe", "--type=gpu-process"),
    (POWERSHELL, "-NoProfile -ExecutionPolicy Bypass -File C:\\Scripts\\backup.ps1"),
)


def sysmon_time(moment: datetime) -> str:
    """Sysmon's ``UtcTime``: UTC, millisecond precision, no zone marker."""
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _whole_ms(moment: datetime) -> datetime:
    """Sysmon only records milliseconds."""
    return moment.replace(microsecond=moment.microsecond // 1000 * 1000)


def render(entries: Sequence[tuple[datetime, dict]]) -> str:
    return "".join(json.dumps(record, ensure_ascii=False) + "\n" for _, record in in_file_order(entries))


def computer(host: str) -> str:
    return f"{host}.{DOMAIN}"


def _header(rng: Rng, moment: datetime, host: str, event_id: int) -> dict:
    return {"EventID": event_id, "Channel": CHANNEL, "Computer": computer(host), "UtcTime": sysmon_time(moment),
            "ProcessGuid": "{" + "-".join(rng.token(size) for size in (8, 4, 4, 4, 12)) + "}",
            "ProcessId": rng.randint(600, 9000)}


def process_entry(rng: Rng, moment: datetime, host: str, user: str, image: str, arguments: str = "",
                  parent: str = "C:\\Windows\\explorer.exe") -> tuple[datetime, dict]:
    """Event ID 1: a process was created."""
    moment = _whole_ms(moment)
    record = _header(rng, moment, host, 1)
    record.update({
        "Image": image, "CommandLine": f"\"{image}\" {arguments}".strip(),
        "CurrentDirectory": f"C:\\Users\\{user}\\", "User": f"LAB\\{user}", "IntegrityLevel": "Medium",
        "Hashes": "SHA256=" + rng.token(64).upper(), "ParentProcessId": rng.randint(600, 9000),
        "ParentImage": parent, "ParentCommandLine": parent,
    })
    return moment, record


def network_entry(rng: Rng, moment: datetime, host: str, user: str, image: str, src_ip: str,
                  dst_ip: str, dst_port: int, initiated: bool = True) -> tuple[datetime, dict]:
    """Event ID 3: a network connection was made (or accepted)."""
    moment = _whole_ms(moment)
    record = _header(rng, moment, host, 3)
    record.update({
        "Image": image, "User": f"LAB\\{user}", "Protocol": "tcp", "Initiated": initiated,
        "SourceIsIpv6": False, "SourceIp": src_ip, "SourcePort": rng.randint(49152, 65535),
        "DestinationIsIpv6": False, "DestinationIp": dst_ip, "DestinationPort": dst_port,
    })
    return moment, record


def other_entry(rng: Rng, moment: datetime, host: str, event_id: int) -> tuple[datetime, dict]:
    """Event types the toolkit ignores (5 process ended, 11 file created, 22 DNS query)."""
    moment = _whole_ms(moment)
    record = _header(rng, moment, host, event_id)
    record["Image"] = "C:\\Windows\\System32\\svchost.exe"
    return moment, record


def benign_activity(rng: Rng, start: datetime, minutes: int,
                    hosts: Sequence[str] = tuple(WORKSTATION_USERS)) -> LogBundle:
    """Office work on the workstations: programs start, files are opened,
    the file server and the domain controller are contacted, sites are visited."""
    bundle = LogBundle()
    services = [(WINDOWS_HOSTS["FS-01"], 445), (WINDOWS_HOSTS["DC-01"], 88), (WINDOWS_HOSTS["DC-01"], 389)]
    sites = sorted(INTERNET_SITES.values())
    for host in hosts:
        user, address = WORKSTATION_USERS[host], WINDOWS_HOSTS[host]
        elapsed = rng.uniform(0.5, 3)
        while elapsed < minutes:
            moment = start + timedelta(minutes=elapsed)
            image, arguments = rng.choice(_PROGRAMS)
            image, arguments = image.replace("{user}", user), arguments.replace("{user}", user)
            bundle.sysmon.append(process_entry(rng, moment, host, user, image, arguments))
            later = moment + timedelta(seconds=rng.uniform(1, 20))
            if rng.chance(0.5):
                server, port = rng.choice(services)
                bundle.sysmon.append(network_entry(rng, later, host, user, "System", address, server, port))
            else:
                bundle.sysmon.append(network_entry(rng, later, host, user, image, address, rng.choice(sites), 443))
            if rng.chance(0.4):
                bundle.sysmon.append(other_entry(rng, later + timedelta(seconds=2), host, rng.choice((5, 11, 22))))
            elapsed += rng.uniform(2, 7)
    return bundle


def encoded_command(script: str) -> str:
    """What ``powershell -enc`` expects: base64 of the UTF-16LE text."""
    return base64.b64encode(script.encode("utf-16-le")).decode("ascii")


def suspicious_process(rng: Rng, start: datetime, host: str, variant: str, scenario_id: str) -> LogBundle:
    """A dropped program run from Temp (``variant="temp"``) or PowerShell
    with an encoded command (``variant="encoded"``)."""
    bundle = LogBundle()
    user, address = WORKSTATION_USERS[host], WINDOWS_HOSTS[host]
    if variant == "temp":
        image = f"C:\\Users\\{user}\\AppData\\Local\\Temp\\invoice_viewer.exe"
        bundle.sysmon.append(process_entry(rng, start, host, user, image))
        bundle.sysmon.append(process_entry(rng, start + timedelta(seconds=3), host, user,
                                           "C:\\Windows\\System32\\cmd.exe", "/c whoami", parent=image))
        bundle.sysmon.append(network_entry(rng, start + timedelta(seconds=6), host, user, image, address,
                                           "203.0.113.90", 443))
        what = f"{user} runs invoice_viewer.exe from the Temp folder on {host}"
    elif variant == "encoded":
        payload = encoded_command("Write-Output 'SOC lab synthetic test'")
        bundle.sysmon.append(process_entry(rng, start, host, user, POWERSHELL, f"-NoP -W Hidden -enc {payload}",
                                           parent="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"))
        what = f"Word starts PowerShell with an encoded command on {host}"
    else:
        raise ValueError("variant must be temp or encoded")
    bundle.labels.append(Label(
        scenario_id=scenario_id, kind="suspicious_process", malicious=True, expected_rule="SUSPICIOUS_PROCESS",
        start=bundle.sysmon[0][0], end=bundle.sysmon[-1][0], match={"hostname": [computer(host)]}, sources=["sysmon"],
        description=what + ".",
    ))
    return bundle


def unlisted_appdata_program(rng: Rng, start: datetime, host: str, scenario_id: str) -> LogBundle:
    """A harmless program that a user installed under AppData and that is not
    on rule 3's allow-list ("LabChat" is a made-up product). Rule 3, as the
    assignment defines it, reports this: a realistic false positive."""
    bundle = LogBundle()
    user, address = WORKSTATION_USERS[host], WINDOWS_HOSTS[host]
    image = f"C:\\Users\\{user}\\AppData\\Local\\Programs\\LabChat\\LabChat.exe"
    bundle.sysmon.append(process_entry(rng, start, host, user, image, "--startup"))
    bundle.sysmon.append(network_entry(rng, start + timedelta(seconds=4), host, user, image, address,
                                       INTERNET_SITES["www.example.com"], 443))
    bundle.labels.append(Label(
        scenario_id=scenario_id, kind="decoy", malicious=False, expected_rule=None,
        start=bundle.sysmon[0][0], end=bundle.sysmon[-1][0], match={"hostname": [computer(host)]},
        sources=["sysmon"],
        description=f"{user} starts LabChat, a legitimate program installed under AppData, on {host}. Not an attack.",
    ))
    return bundle


def port_scan(rng: Rng, start: datetime, host: str, target_ip: str, ports: Sequence[int],
              seconds: float, scenario_id: str) -> LogBundle:
    """A workstation probing many ports of one server, seen by Sysmon on the workstation."""
    bundle = LogBundle()
    user, address = WORKSTATION_USERS[host], WINDOWS_HOSTS[host]
    step = seconds / max(len(ports) - 1, 1)
    for index, port in enumerate(ports):
        moment = start + timedelta(seconds=index * step + rng.uniform(0, step * 0.3))
        bundle.sysmon.append(network_entry(rng, moment, host, user, POWERSHELL, address, target_ip, port))
    bundle.labels.append(Label(
        scenario_id=scenario_id, kind="port_scan", malicious=True, expected_rule="INTERNAL_PORT_SCAN",
        start=bundle.sysmon[0][0], end=bundle.sysmon[-1][0],
        match={"src_ip": [address], "dst_ip": [target_ip]}, sources=["sysmon"],
        description=f"{host} ({address}) connects to {len(ports)} different ports on {target_ip} "
                    f"in about {seconds:g} seconds.",
    ))
    return bundle


def pivot(rng: Rng, start: datetime, attacker_ip: str, host: str,
          targets: Sequence[tuple[str, int]], scenario_id: str, *, delay: float = 45.0) -> LogBundle:
    """Cross-source scenario for rule 4.

    Suricata alerts on an exploit against ``host``; ``delay`` seconds later
    Sysmon on that host records it connecting to other internal machines.
    """
    bundle = LogBundle()
    user, victim_ip = WORKSTATION_USERS[host], WINDOWS_HOSTS[host]
    bundle.eve.append(eve.alert_entry(rng, start, attacker_ip, victim_ip, 445, eve.SIG_EXPLOIT))
    bundle.eve.append(eve.flow_entry(rng, start, attacker_ip, victim_ip, 445, seconds=2.0))
    moment = start + timedelta(seconds=delay)
    for target_ip, port in targets:
        image = "C:\\Windows\\System32\\mstsc.exe" if port == 3389 else "System"
        bundle.sysmon.append(network_entry(rng, moment, host, user, image, victim_ip, target_ip, port))
        moment += timedelta(seconds=rng.uniform(15, 50))
    bundle.labels.append(Label(
        scenario_id=scenario_id, kind="pivot", malicious=True, expected_rule="NETWORK_TO_HOST_PIVOT",
        start=start, end=bundle.sysmon[-1][0], match={"src_ip": [attacker_ip, victim_ip]},
        sources=["suricata", "sysmon"],
        description=(f"Suricata alerts on an exploit from {attacker_ip} against {host} ({victim_ip}); "
                     f"then {host} connects to {len(targets)} internal machines."),
    ))
    return bundle


def main(argv: Sequence[str] | None = None) -> int:
    """Demo: ``python -m datagen.sysmon --out sysmon.json`` writes normal activity
    plus two suspicious processes and prints their labels. The pivot scenario
    needs a Suricata file too: use ``pivot()`` from Python or the benchmark builder."""
    import argparse

    parser = argparse.ArgumentParser(prog="python -m datagen.sysmon", description=main.__doc__)
    parser.add_argument("--out", required=True, help="file to write")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--minutes", type=int, default=60, help="length of the normal activity")
    parser.add_argument("--start", default="2026-11-12T08:00:00+07:00", help="ISO time of the first minute")
    args = parser.parse_args(argv)
    rng, start = Rng(args.seed), datetime.fromisoformat(args.start)
    bundle = benign_activity(rng.fork("benign"), start, args.minutes)
    bundle.merge(suspicious_process(rng.fork("temp"), start + timedelta(minutes=args.minutes / 3), "WS-01",
                                    "temp", "demo-temp-process"))
    bundle.merge(suspicious_process(rng.fork("encoded"), start + timedelta(minutes=args.minutes / 2), "WS-02",
                                    "encoded", "demo-encoded-powershell"))
    with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render(bundle.sysmon))
    print(json.dumps([label.to_dict() for label in bundle.labels], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
