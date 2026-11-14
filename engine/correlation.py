"""Correlation engine: Rule interface, event-time sliding window, dedup, incidents.

Everything here is driven by the timestamp carried by each event
(``timestamp_utc``). The machine clock is never read, so replaying an old
log file gives exactly the same result as watching it live.
"""
from __future__ import annotations

import importlib
from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator, Mapping, Sequence

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
DEFAULT_COOLDOWN_SECONDS = 300


def parse_ts(value: str | datetime) -> datetime:
    """Turn a canonical ``timestamp_utc`` into an aware UTC datetime."""
    dt = value if isinstance(value, datetime) else datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp_utc must contain a timezone")
    return dt.astimezone(timezone.utc)


def format_ts(dt: datetime) -> str:
    """Same text format as normalizer.schema, e.g. 2026-11-12T02:00:00.000000Z."""
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def max_severity(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


class SlidingWindow:
    """Items whose event time lies within ``seconds`` of the newest item.

    Boundary rule (inclusive): an item stays while ``newest - item <= seconds``.
    With a 60 s window, items at t=0 and t=60 are together; t=0 and t=61 are not.
    Callers must add items in non-decreasing time order (the engine sorts first).
    """

    def __init__(self, seconds: float) -> None:
        if seconds <= 0:
            raise ValueError("window size must be > 0")
        self.size = timedelta(seconds=seconds)
        self._items: deque[tuple[datetime, Any]] = deque()

    def add(self, ts: datetime, item: Any) -> list[Any]:
        """Add an item and return the items that just fell out of the window."""
        if self._items and ts < self._items[-1][0]:
            raise ValueError("SlidingWindow needs items in time order")
        self._items.append((ts, item))
        evicted = []
        while ts - self._items[0][0] > self.size:
            evicted.append(self._items.popleft()[1])
        return evicted

    def items(self) -> list[Any]:
        return [item for _, item in self._items]

    def last(self, count: int) -> list[tuple[datetime, Any]]:
        """The newest ``count`` entries as (time, item), oldest first."""
        newest = [self._items[-i] for i in range(1, min(count, len(self._items)) + 1)]
        return newest[::-1]

    def first_ts(self) -> datetime | None:
        return self._items[0][0] if self._items else None

    def clear(self) -> None:
        self._items.clear()

    def __len__(self) -> int:
        return len(self._items)


@dataclass
class Alert:
    """One raw rule match. Several alerts may be merged into one incident."""
    rule_id: str
    key: str                 # entity the alert is about, e.g. the source IP
    title: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    event_ids: list[int]
    summary: str = ""
    mitre: str | None = None


class Rule(ABC):
    """Interface every correlation rule implements.

    The engine calls ``process`` once per event, in event-time order, and
    ``reset`` before each run. A rule keeps whatever state it needs between
    calls and returns zero or more Alert objects. Events are the dicts returned
    by ``storage.models.list_events`` (canonical schema plus ``id``).
    """

    rule_id: str = ""
    title: str = ""
    mitre: str | None = None
    # Dedup cooldown for this rule; None means "use the engine default".
    cooldown_seconds: float | None = None
    # What the analyst should check first; printed in the investigation summary.
    recommendations: tuple[str, ...] = ()

    @abstractmethod
    def process(self, event: Mapping[str, Any], ts: datetime) -> list[Alert]:
        """Consume one event (``ts`` is its parsed timestamp_utc)."""

    def reset(self) -> None:
        """Forget all state. Override when the rule keeps state."""


@dataclass
class Incident:
    """A group of related alerts shown to the analyst as one case.

    ``incident_id`` stays None until storage assigns it (AUTOINCREMENT).
    """
    rule_id: str
    title: str
    severity: str
    first_seen: datetime
    last_seen: datetime
    event_ids: list[int]
    summary: str = ""
    dedup_key: str = ""
    mitre: str | None = None
    raw_alert_count: int = 1
    status: str = "New"
    assigned_analyst: str | None = None
    incident_id: int | None = None
    detected_at: datetime | None = None   # event time at which the rule first fired

    def __post_init__(self) -> None:
        if self.detected_at is None:
            self.detected_at = self.last_seen
        self.event_ids = list(dict.fromkeys(self.event_ids))
        self._seen = set(self.event_ids)

    def merge(self, alert: Alert) -> None:
        """Fold a repeated alert into this incident instead of opening a new one.

        Title and summary follow the most severe alert (the latest one on a tie),
        so they always describe the same thing.
        """
        for event_id in alert.event_ids:
            if event_id not in self._seen:
                self._seen.add(event_id)
                self.event_ids.append(event_id)
        self.first_seen = min(self.first_seen, alert.first_seen)
        self.last_seen = max(self.last_seen, alert.last_seen)
        if max_severity(alert.severity, self.severity) == alert.severity:
            self.severity = alert.severity
            self.title = alert.title
            self.summary = alert.summary or self.summary
        self.raw_alert_count += 1

    def to_dict(self) -> dict[str, Any]:
        """Shape agreed in docs/INTEGRATION_CONTRACT.md, plus a few extra keys."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "assigned_analyst": self.assigned_analyst,
            "first_seen_utc": format_ts(self.first_seen),
            "last_seen_utc": format_ts(self.last_seen),
            "detected_at_utc": format_ts(self.detected_at),
            "summary": self.summary,
            "event_ids": sorted(self.event_ids),
            "dedup_key": self.dedup_key,
            "mitre": self.mitre,
            "raw_alert_count": self.raw_alert_count,
        }


@dataclass
class EngineStats:
    events: int = 0
    skipped_events: int = 0      # events without a usable timestamp
    raw_alerts: int = 0
    incidents: int = 0
    by_rule: dict[str, dict[str, int]] = field(default_factory=dict)

    def count(self, rule_id: str, what: str) -> None:
        setattr(self, what, getattr(self, what) + 1)
        per_rule = self.by_rule.setdefault(rule_id, {"raw_alerts": 0, "incidents": 0})
        per_rule[what] += 1

    @property
    def dedup_savings(self) -> float:
        """Share of raw alerts the analyst no longer has to open (0.0 - 1.0)."""
        return 0.0 if self.raw_alerts == 0 else 1 - self.incidents / self.raw_alerts

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "skipped_events": self.skipped_events,
            "raw_alerts": self.raw_alerts,
            "incidents": self.incidents,
            "dedup_savings": round(self.dedup_savings, 4),
            "by_rule": {rule_id: dict(counts) for rule_id, counts in sorted(self.by_rule.items())},
        }


class CorrelationEngine:
    """Runs rules over events and merges repeated alerts into incidents.

    Dedup: alerts with the same (rule_id, key) join the open incident as long
    as the new alert is at most ``cooldown_seconds`` (event time) after that
    incident's last_seen. A later alert opens a new incident. A rule may set
    its own ``cooldown_seconds``; otherwise the engine value is used.
    """

    def __init__(self, rules: Sequence[Rule] | None = None,
                 cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS) -> None:
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must be >= 0")
        self.rules = list(rules) if rules is not None else default_rules()
        self.cooldown = timedelta(seconds=cooldown_seconds)
        self.stats = EngineStats()

    def run(self, events: Iterable[Mapping[str, Any]]) -> list[Incident]:
        self.stats = EngineStats()
        for rule in self.rules:
            rule.reset()
        incidents: list[Incident] = []
        latest: dict[tuple[str, str], Incident] = {}
        for ts, event in self._in_time_order(events):
            for rule in self.rules:
                for alert in rule.process(event, ts):
                    self.stats.count(alert.rule_id, "raw_alerts")
                    slot = (alert.rule_id, alert.key)
                    current = latest.get(slot)
                    cooldown = (self.cooldown if rule.cooldown_seconds is None
                                else timedelta(seconds=rule.cooldown_seconds))
                    if current is not None and alert.last_seen - current.last_seen <= cooldown:
                        current.merge(alert)
                        continue
                    incident = Incident(
                        rule_id=alert.rule_id, title=alert.title, severity=alert.severity,
                        first_seen=alert.first_seen, last_seen=alert.last_seen,
                        event_ids=list(alert.event_ids), summary=alert.summary,
                        dedup_key=f"{alert.rule_id}|{alert.key}", mitre=alert.mitre or rule.mitre,
                    )
                    latest[slot] = incident
                    incidents.append(incident)
                    self.stats.count(alert.rule_id, "incidents")
        return incidents

    def _in_time_order(self, events: Iterable[Mapping[str, Any]]) -> Iterator[tuple[datetime, Mapping[str, Any]]]:
        """Sort by event time so logs that arrived out of order are still correct."""
        timed = []
        for position, event in enumerate(events):
            self.stats.events += 1
            try:
                ts = parse_ts(event["timestamp_utc"])
            except (KeyError, TypeError, ValueError):
                self.stats.skipped_events += 1
                continue
            if event.get("id") is None:
                raise ValueError("every event needs an 'id' (use storage.models.list_events)")
            timed.append((ts, event["id"], position, event))
        timed.sort(key=lambda row: row[:3])
        for ts, _, _, event in timed:
            yield ts, event


def default_rules() -> list[Rule]:
    """Rules 1, 2 and 5, plus member 3's Windows rules once that module exists.

    ``engine/rules/windows.py`` is expected to expose ``RULES``: a list of
    Rule subclasses (or instances).
    """
    from engine.rules.beaconing import BeaconingRule
    from engine.rules.port_scan import PortScanRule
    from engine.rules.ssh_brute_force import SSHBruteForceRule

    rules: list[Rule] = [SSHBruteForceRule(), PortScanRule(), BeaconingRule()]
    try:
        windows = importlib.import_module("engine.rules.windows")
    except ModuleNotFoundError as exc:
        if exc.name != "engine.rules.windows":
            raise
    else:
        for item in getattr(windows, "RULES", []):
            rules.append(item() if isinstance(item, type) else item)
    return rules


def rule_by_id(rule_id: str) -> Rule | None:
    """The default rule with this id, to read its MITRE code or recommendations."""
    for rule in default_rules():
        if rule.rule_id == rule_id:
            return rule
    return None


def mitre_for_rule(rule_id: str) -> str | None:
    """MITRE technique of a rule; the incidents table has no column for it."""
    rule = rule_by_id(rule_id)
    return rule.mitre if rule else None


def detect_incidents(events: list[dict]) -> list[dict]:
    """Entry point used by ``python -m pipeline detect`` (see the contract)."""
    return [incident.to_dict() for incident in CorrelationEngine().run(events)]


def detect_with_stats(events: Iterable[Mapping[str, Any]],
                      cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS) -> tuple[list[dict], dict]:
    """Incidents plus raw-alert / incident counts for the evaluation report."""
    engine = CorrelationEngine(cooldown_seconds=cooldown_seconds)
    incidents = [incident.to_dict() for incident in engine.run(events)]
    return incidents, engine.stats.to_dict()
