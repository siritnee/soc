"""Rule 2 - Internal Port Scan (MITRE ATT&CK T1046)."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from engine.correlation import Alert, Rule, SlidingWindow
from engine.net import is_internal

# Actions that represent "a connection attempt to a port":
# Sysmon Event ID 3 (network_connection) and Suricata flow records (flow).
CONNECTION_ACTIONS = frozenset({"network_connection", "flow"})


@dataclass
class _Target:
    """State kept for one (source IP, destination IP) pair."""
    window: SlidingWindow
    ports: Counter = field(default_factory=Counter)   # port -> hits inside the window
    scanning: bool = False                            # previous event already alerted


class PortScanRule(Rule):
    """One source touching >= ``threshold`` distinct ports of one target
    inside ``window_seconds``.

    The alert that first crosses the threshold lists every event in the window.
    While the scan goes on, each further event raises one more alert that lists
    only that new event, so the engine can merge it cheaply into the incident.
    With ``internal_only=True`` both addresses must be internal (RFC 1918).
    """

    rule_id = "INTERNAL_PORT_SCAN"
    title = "Internal port scan detected"
    mitre = "T1046"
    recommendations = (
        "Identify the scanning host and its owner; an unknown device is a finding in itself.",
        "Check what the scanner did next: logins, SMB/RDP sessions, new processes on the target.",
        "Confirm whether this is an approved vulnerability scan before closing.",
    )

    def __init__(self, threshold: int = 15, window_seconds: float = 30,
                 actions: frozenset[str] = CONNECTION_ACTIONS,
                 internal_only: bool = False) -> None:
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.actions = actions
        self.internal_only = internal_only
        self.reset()

    def reset(self) -> None:
        self._targets: dict[tuple[str, str], _Target] = {}

    def process(self, event: Mapping[str, Any], ts: datetime) -> list[Alert]:
        src_ip, dst_ip, port = event.get("src_ip"), event.get("dst_ip"), event.get("dst_port")
        if event.get("action") not in self.actions or not src_ip or not dst_ip or port is None:
            return []
        if self.internal_only and not (is_internal(src_ip) and is_internal(dst_ip)):
            return []
        target = self._targets.get((src_ip, dst_ip))
        if target is None:
            target = self._targets[(src_ip, dst_ip)] = _Target(SlidingWindow(self.window_seconds))
        target.ports[port] += 1
        for old_port, _ in target.window.add(ts, (port, event["id"])):
            target.ports[old_port] -= 1
            if target.ports[old_port] == 0:
                del target.ports[old_port]
        if len(target.ports) < self.threshold:
            target.scanning = False
            return []
        if target.scanning:
            event_ids = [event["id"]]
        else:
            event_ids = [event_id for _, event_id in target.window.items()]
        target.scanning = True
        return [Alert(
            rule_id=self.rule_id,
            key=f"{src_ip}->{dst_ip}",
            title=self.title,
            severity="medium",
            first_seen=target.window.first_ts(),
            last_seen=ts,
            event_ids=event_ids,
            summary=(f"{src_ip} probed {len(target.ports)} distinct ports on {dst_ip} "
                     f"within {self.window_seconds:g}s."),
            mitre=self.mitre,
        )]
