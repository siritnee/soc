"""Rule 5 - Malware Beaconing (MITRE ATT&CK T1071).

Not one of the four rules required by the assignment: it exists because the
benchmark must contain a "malware beaconing" scenario and something has to
detect it.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from engine.correlation import SEVERITY_ORDER, Alert, Rule, SlidingWindow


class BeaconingRule(Rule):
    """The same IDS alert between the same two hosts, repeating at a steady pace.

    Malware that "phones home" contacts its server every N seconds, so the
    gaps between the alerts are almost equal. The rule looks at the newest
    ``threshold`` alerts of one (source, destination, signature):

    * all of them lie inside ``window_seconds``;
    * the median gap is at least ``min_interval_seconds`` (a burst is not a beacon);
    * every gap is within ``tolerance`` (30 %) of the median gap.

    Alerts below ``min_severity`` are ignored.
    """

    rule_id = "MALWARE_BEACONING"
    title = "Periodic IDS alert (possible malware beaconing)"
    mitre = "T1071"
    recommendations = (
        "Isolate the source host and find the process that makes the connection.",
        "Block the destination IP/domain and search other hosts for the same destination.",
        "Check what the host did before the first beacon: downloads, new processes, logins.",
    )

    def __init__(self, threshold: int = 6, window_seconds: float = 3600,
                 tolerance: float = 0.3, min_interval_seconds: float = 5,
                 min_severity: str = "medium") -> None:
        if threshold < 3:
            raise ValueError("threshold must be >= 3 (at least two gaps to compare)")
        self.threshold = threshold
        self.window_seconds = window_seconds
        self.tolerance = tolerance
        self.min_interval_seconds = min_interval_seconds
        self.min_rank = SEVERITY_ORDER.index(min_severity)
        # A slow beacon (one alert every 10 minutes) must stay one incident.
        self.cooldown_seconds = window_seconds
        self.reset()

    def reset(self) -> None:
        self._windows: dict[tuple[str, str, str], SlidingWindow] = {}
        self._beaconing: set[tuple[str, str, str]] = set()

    def process(self, event: Mapping[str, Any], ts: datetime) -> list[Alert]:
        src_ip, dst_ip = event.get("src_ip"), event.get("dst_ip")
        if event.get("action") != "alert" or not src_ip or not dst_ip:
            return []
        if SEVERITY_ORDER.index(event.get("severity", "info")) < self.min_rank:
            return []
        signature = event.get("signature") or "unknown signature"
        key = (src_ip, dst_ip, signature)
        window = self._windows.setdefault(key, SlidingWindow(self.window_seconds))
        window.add(ts, event["id"])
        newest = window.last(self.threshold)
        median_gap = self._steady_gap([when for when, _ in newest])
        if median_gap is None:
            self._beaconing.discard(key)
            return []
        # First alert of a beacon lists the events that prove it; later ones add one event.
        event_ids = [event["id"]] if key in self._beaconing else [event_id for _, event_id in newest]
        self._beaconing.add(key)
        port = f":{event['dst_port']}" if event.get("dst_port") is not None else ""
        return [Alert(
            rule_id=self.rule_id,
            key=f"{src_ip}->{dst_ip}",
            title=self.title,
            severity="high",
            first_seen=newest[0][0],
            last_seen=ts,
            event_ids=event_ids,
            summary=(f"{len(window)} alerts \"{signature}\" from {src_ip} to {dst_ip}{port} "
                     f"in the last {self.window_seconds:g}s, about one every {median_gap:.0f}s."),
            mitre=self.mitre,
        )]

    def _steady_gap(self, times: list[datetime]) -> float | None:
        """Median gap in seconds when ``times`` look like a beacon, else None."""
        if len(times) < self.threshold:
            return None
        gaps = sorted((later - earlier).total_seconds() for earlier, later in zip(times, times[1:]))
        median = gaps[len(gaps) // 2]
        if median < self.min_interval_seconds:
            return None
        if any(abs(gap - median) > self.tolerance * median for gap in gaps):
            return None
        return median
