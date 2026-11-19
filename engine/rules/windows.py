"""The Windows-side rules.

Rule 3 - Suspicious Process Execution (MITRE ATT&CK T1059.001)
Rule 4 - Network-to-Host Pivot (MITRE ATT&CK T1021)

``RULES`` at the bottom is what the correlation engine loads.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence

from engine.correlation import SEVERITY_ORDER, Alert, Rule
from engine.net import is_internal

# ---- rule 3 -----------------------------------------------------------------

# Folders any user can write to, so malware likes to start from them.
_USER_WRITABLE = re.compile(r"\\(appdata|temp)\\", re.IGNORECASE)
# Well-known programs that legitimately live under AppData (lower case, part of the path).
DEFAULT_ALLOWLIST = (
    "\\appdata\\local\\microsoft\\onedrive\\",
    "\\appdata\\local\\microsoft\\teams\\",
)
_POWERSHELL = ("powershell", "powershell.exe", "pwsh", "pwsh.exe")
_DASHES = "-/–—―"          # PowerShell also accepts "/" and typographic dashes


def is_encoded_flag(token: str) -> bool:
    """True for ``-enc`` and every other spelling PowerShell accepts for
    ``-EncodedCommand``: any prefix of that word (-e, -en, -enc, ...) or -ec."""
    if len(token) < 2 or token[0] not in _DASHES:
        return False
    name = token[1:].lower()
    return name == "ec" or "encodedcommand".startswith(name)


def uses_encoded_powershell(image: str, command_line: str) -> bool:
    """PowerShell started with an encoded command, either as the process
    itself or inside the command line of another program (cmd /c powershell -enc ...)."""
    in_powershell = image.lower().replace("/", "\\").rsplit("\\", 1)[-1] in _POWERSHELL
    for token in command_line.split():
        name = token.strip("\"'").lower().replace("/", "\\").rsplit("\\", 1)[-1]
        if name in _POWERSHELL:
            in_powershell = True
        elif in_powershell and is_encoded_flag(token):
            return True
    return False


class SuspiciousProcessRule(Rule):
    """A process that starts from AppData or Temp, or PowerShell with ``-enc``.

    Each match is one alert; alerts on the same computer inside the cooldown
    become one incident.
    """

    rule_id = "SUSPICIOUS_PROCESS"
    title = "Suspicious process execution"
    mitre = "T1059.001"
    recommendations = (
        "Decode the PowerShell command (base64, UTF-16LE) or collect the file and its hash.",
        "Look at the parent process and at what the process did next: child processes, network connections.",
        "If it is not approved software: isolate the computer and reset the user's credentials.",
    )

    def __init__(self, allowlist: Sequence[str] = DEFAULT_ALLOWLIST) -> None:
        self.allowlist = tuple(entry.lower() for entry in allowlist)

    def process(self, event: Mapping[str, Any], ts: datetime) -> list[Alert]:
        if event.get("action") != "process_create":
            return []
        image = event.get("process_name") or ""
        path = image.lower().replace("/", "\\")
        reasons = []
        if _USER_WRITABLE.search(path) and not any(entry in path for entry in self.allowlist):
            reasons.append("it runs from a user-writable folder (AppData or Temp)")
        encoded = uses_encoded_powershell(image, event.get("command_line") or "")
        if encoded:
            reasons.append("PowerShell was given an encoded command")
        if not reasons:
            return []
        host = event.get("hostname") or "unknown host"
        user = event.get("username") or "unknown user"
        return [Alert(
            rule_id=self.rule_id,
            key=host,
            title=self.title,
            severity="high" if encoded else "medium",
            first_seen=ts,
            last_seen=ts,
            event_ids=[event["id"]],
            summary=f"{image} started by {user} on {host}: {' and '.join(reasons)}.",
            mitre=self.mitre,
        )]


# ---- rule 4 -----------------------------------------------------------------

@dataclass
class _Flag:
    """What is remembered about an IP after a serious network alert."""
    alert_time: datetime
    alert_id: int
    signature: str
    first_target: str = ""                   # first internal connection after the alert
    first_delay: float = 0.0
    connections: int = 0
    targets: set = field(default_factory=set)


class NetworkToHostPivotRule(Rule):
    """A serious network alert, then the same IP opens an internal connection.

    1. Suricata raises an alert of at least ``min_severity``. Both addresses of
       the alert are remembered together with the time of the alert.
    2. Within ``window_seconds`` Sysmon (Event ID 3) records a connection whose
       source is one of those addresses and whose destination is another
       internal machine.

    The network sensor and the Windows host each saw half of the story; the
    IP address is what ties the two log sources together.
    """

    rule_id = "NETWORK_TO_HOST_PIVOT"
    title = "Network alert followed by internal connections (possible pivot)"
    mitre = "T1021"
    recommendations = (
        "Treat the source machine as compromised: isolate it and collect its Sysmon log.",
        "Check every machine it connected to after the alert for new logins and new processes.",
        "Find out how the first alert happened (exploit, phishing, stolen password) and close that door.",
    )

    def __init__(self, window_seconds: float = 600, min_severity: str = "high") -> None:
        self.window = timedelta(seconds=window_seconds)
        self.min_rank = SEVERITY_ORDER.index(min_severity)
        self.cooldown_seconds = window_seconds       # one incident per IP for the whole window
        self.reset()

    def reset(self) -> None:
        self._flagged: dict[str, _Flag] = {}      # ip -> its latest serious alert

    def process(self, event: Mapping[str, Any], ts: datetime) -> list[Alert]:
        source, action = event.get("source_type"), event.get("action")
        if source == "suricata" and action == "alert":
            if SEVERITY_ORDER.index(event.get("severity", "info")) >= self.min_rank:
                for ip in {event.get("src_ip"), event.get("dst_ip")} - {None}:
                    self._flagged[ip] = _Flag(ts, event["id"], event.get("signature") or "unknown signature")
            return []
        if source != "sysmon" or action != "network_connection":
            return []
        src_ip, dst_ip = event.get("src_ip"), event.get("dst_ip")
        flagged = self._flagged.get(src_ip)
        if flagged is None or not is_internal(dst_ip) or dst_ip == src_ip:
            return []
        if ts - flagged.alert_time > self.window:      # too late to blame the alert
            del self._flagged[src_ip]
            return []
        if not flagged.connections:
            port = f":{event['dst_port']}" if event.get("dst_port") is not None else ""
            flagged.first_target = f"{dst_ip}{port}"
            flagged.first_delay = (ts - flagged.alert_time).total_seconds()
        flagged.connections += 1
        flagged.targets.add(dst_ip)
        return [Alert(
            rule_id=self.rule_id,
            key=src_ip,
            title=self.title,
            severity="critical",
            first_seen=flagged.alert_time,
            last_seen=ts,
            event_ids=[flagged.alert_id, event["id"]],
            summary=(f"{src_ip} appeared in the Suricata alert \"{flagged.signature}\" and "
                     f"{flagged.first_delay:.0f}s later Sysmon recorded it connecting to {flagged.first_target}. "
                     f"Internal connections since the alert: {flagged.connections}, "
                     f"to {len(flagged.targets)} machine(s)."),
            mitre=self.mitre,
        )]


RULES = [SuspiciousProcessRule, NetworkToHostPivotRule]
