"""Shared pieces of the synthetic log generators.

Everything produced by ``datagen`` is fake. IP addresses are private (10.x)
or come from the documentation ranges 192.0.2.0/24, 198.51.100.0/24 and
203.0.113.0/24, which play the role of the Internet. Host names end in the
reserved names ``.example``, ``example.com``, ``example.net``, ``example.org``.
"""
from __future__ import annotations

import random
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

# The lab machines write their logs in local time (UTC+7).
LAB_TZ = timezone(timedelta(hours=7))

# ---- lab inventory ---------------------------------------------------------
DOMAIN = "lab.example"
LINUX_SERVERS = {"bastion-01": "10.0.1.5", "web-01": "10.0.1.10", "db-01": "10.0.1.11"}
WINDOWS_HOSTS = {
    "DC-01": "10.0.1.2", "FS-01": "10.0.1.20",
    "WS-01": "10.0.2.21", "WS-02": "10.0.2.22", "WS-03": "10.0.2.23", "WS-04": "10.0.2.24",
}
WORKSTATION_USERS = {"WS-01": "alice", "WS-02": "bob", "WS-03": "carol", "WS-04": "dave"}
DNS_SERVER = WINDOWS_HOSTS["DC-01"]
INTERNET_SITES = {
    "www.example.com": "192.0.2.80", "updates.example.net": "192.0.2.81",
    "mail.example.org": "192.0.2.82", "cdn.example.com": "192.0.2.83",
}


class Rng:
    """Seeded random helper.

    It only calls ``random.Random.random()``, the one method Python promises
    to keep identical across versions, so a seed gives the same log files on
    every machine.
    """

    def __init__(self, seed: int) -> None:
        self.seed = seed
        self._random = random.Random(seed)

    def random(self) -> float:
        return self._random.random()

    def uniform(self, low: float, high: float) -> float:
        return low + (high - low) * self.random()

    def randint(self, low: int, high: int) -> int:
        """Whole number between ``low`` and ``high``, both included."""
        return low + int(self.random() * (high - low + 1))

    def choice(self, items: Sequence[Any]) -> Any:
        return items[int(self.random() * len(items))]

    def chance(self, probability: float) -> bool:
        return self.random() < probability

    def shuffled(self, items: Sequence[Any]) -> list[Any]:
        result = list(items)
        for index in range(len(result) - 1, 0, -1):
            other = self.randint(0, index)
            result[index], result[other] = result[other], result[index]
        return result

    def token(self, length: int, alphabet: str = "0123456789abcdef") -> str:
        return "".join(self.choice(alphabet) for _ in range(length))

    def fork(self, name: str) -> "Rng":
        """Independent stream for one generator, so editing a scenario does
        not change the random numbers of the others."""
        return Rng(zlib.crc32(f"{self.seed}:{name}".encode("utf-8")))


def utc_iso(moment: datetime) -> str:
    """Same text format as ``timestamp_utc`` in the shared schema."""
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass
class Label:
    """Ground truth for one scenario (an attack, or a harmless look-alike)."""
    scenario_id: str
    kind: str                       # ssh_brute_force, port_scan, beaconing, suspicious_process, pivot, decoy
    malicious: bool
    expected_rule: str | None       # rule_id that must raise an incident; None for decoys
    start: datetime                 # first event of the scenario
    end: datetime                   # last event of the scenario
    match: dict[str, list[str]]     # which events belong to it: field -> accepted values
    sources: list[str]              # log sources that contain it
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "kind": self.kind,
            "malicious": self.malicious,
            "expected_rule": self.expected_rule,
            "start_utc": utc_iso(self.start),
            "end_utc": utc_iso(self.end),
            "match": self.match,
            "sources": self.sources,
            "description": self.description,
        }


@dataclass
class LogBundle:
    """Log entries of the three sources plus the labels that describe them.

    Each entry is ``(time, payload)``. The time is only used to put the
    entries in file order; the payload is what gets written.
    """
    auth: list[tuple[datetime, str]] = field(default_factory=list)       # "host program[pid]: message"
    eve: list[tuple[datetime, dict]] = field(default_factory=list)       # Suricata EVE records
    sysmon: list[tuple[datetime, dict]] = field(default_factory=list)    # Sysmon records
    labels: list[Label] = field(default_factory=list)

    def merge(self, other: "LogBundle") -> "LogBundle":
        self.auth.extend(other.auth)
        self.eve.extend(other.eve)
        self.sysmon.extend(other.sysmon)
        self.labels.extend(other.labels)
        return self


def in_file_order(entries: Sequence[tuple[datetime, Any]]) -> list[tuple[datetime, Any]]:
    """Entries sorted by time; equal times keep the order they were created in."""
    return [entry for _, entry in sorted(enumerate(entries), key=lambda pair: (pair[1][0], pair[0]))]
