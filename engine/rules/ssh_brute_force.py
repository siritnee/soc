"""Rule 1 - SSH Brute Force (MITRE ATT&CK T1110)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from engine.correlation import Alert, Rule, SlidingWindow

FAILED_ACTIONS = frozenset({"ssh_failed"})
SUCCESS_ACTIONS = frozenset({"ssh_success"})
LOCKOUT_ACTIONS = frozenset({"ssh_lockout"})


@dataclass
class _Burst:
    """A run of failures that already reached the threshold."""
    event_ids: list[int]
    first_seen: datetime
    last_seen: datetime


class SSHBruteForceRule(Rule):
    """>= ``threshold`` failed logins from one source IP inside ``window_seconds``,
    followed by a success or a lockout from the same IP.

    The follow-up must arrive at most ``follow_seconds`` after the last failure
    of the burst; a login an hour later is not treated as part of the attack.
    A successful login also clears the failures counted so far for that IP, so
    "3 typos, login, 2 typos, login" by a normal user is not reported.
    """

    rule_id = "SSH_BRUTE_FORCE"
    title = "SSH brute-force detected"
    mitre = "T1110"
    recommendations = (
        "If a login succeeded: lock or reset that account and review its session (commands, sudo).",
        "Block the source IP and check whether it tried other hosts.",
        "Check that the targeted accounts use strong passwords or key-only SSH.",
    )

    def __init__(self, threshold: int = 5, window_seconds: float = 60,
                 follow_seconds: float = 60) -> None:
        if threshold < 1:
            raise ValueError("threshold must be >= 1")
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.follow = timedelta(seconds=follow_seconds)
        self.reset()

    def reset(self) -> None:
        self._failures: dict[str, SlidingWindow] = {}
        self._bursts: dict[str, _Burst] = {}

    def process(self, event: Mapping[str, Any], ts: datetime) -> list[Alert]:
        src_ip = event.get("src_ip")
        action = event.get("action")
        if not src_ip:
            return []
        if action in FAILED_ACTIONS:
            self._on_failure(src_ip, event, ts)
            return []
        if action in SUCCESS_ACTIONS or action in LOCKOUT_ACTIONS:
            return self._on_follow_up(src_ip, event, ts, action in SUCCESS_ACTIONS)
        return []

    def _on_failure(self, src_ip: str, event: Mapping[str, Any], ts: datetime) -> None:
        window = self._failures.setdefault(src_ip, SlidingWindow(self.window_seconds))
        window.add(ts, event["id"])
        burst = self._bursts.get(src_ip)
        if burst is not None and ts - burst.last_seen > self.follow:
            burst = None
            self._bursts.pop(src_ip)
        if burst is not None:
            burst.event_ids.append(event["id"])
            burst.last_seen = ts
        elif len(window) >= self.threshold:
            self._bursts[src_ip] = _Burst(window.items(), window.first_ts(), ts)

    def _on_follow_up(self, src_ip: str, event: Mapping[str, Any], ts: datetime,
                      success: bool) -> list[Alert]:
        burst = self._bursts.pop(src_ip, None)
        if success or burst is not None:
            self._failures.pop(src_ip, None)
        if burst is None or ts - burst.last_seen > self.follow:
            return []
        failures = len(burst.event_ids)
        outcome = "a successful login" if success else "an account lockout"
        user = event.get("username") or "unknown user"
        host = event.get("hostname") or event.get("dst_ip") or "unknown host"
        return [Alert(
            rule_id=self.rule_id,
            key=src_ip,
            title=self.title + (" (login succeeded)" if success else " (account locked)"),
            severity="critical" if success else "high",
            first_seen=burst.first_seen,
            last_seen=ts,
            event_ids=burst.event_ids + [event["id"]],
            summary=(f"{failures} failed SSH logins from {src_ip} "
                     f"(at least {self.threshold} within {self.window_seconds:g}s), "
                     f"followed by {outcome} ({user} on {host})."),
            mitre=self.mitre,
        )]
