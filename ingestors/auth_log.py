"""Linux auth.log reader.

Classic syslog lines look like ``Nov 12 08:40:03 web-01 sshd[3001]: ...``:
no year and no time zone. The conventions of this toolkit are:

* Time zone: the ``tz`` argument, else the environment variable
  ``SOC_AUTH_LOG_TZ``, else ``+07:00`` (the lab machines run on Vietnam time).
* Year of the first line: the ``year`` argument, else ``SOC_AUTH_LOG_YEAR``,
  else the current year - or the year before, when the current year would
  put that line more than one day in the future.
* Every following line gets the year that puts it closest to the line before
  it, so a file that runs from December into January stays correct.
* Lines that start with a full ISO timestamp (rsyslog's newer format) already
  say everything and are used as they are.

Every timestamp is converted to UTC by the shared schema.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from ingestors.base import read_lines, skip, start_stats
from normalizer.auth_log_mapper import AuthLogMapper
from normalizer.schema import EventValidationError

DEFAULT_TZ = "+07:00"
MAX_REPEAT = 1000        # upper bound for "message repeated N times"

_MONTHS = {name: number for number, name in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}
_CLASSIC = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"\s+(?P<rest>.+)$")
_ISO = re.compile(r"^(?P<stamp>\d{4}-\d{2}-\d{2}T\S+)\s+(?P<rest>.+)$")
_TAG = re.compile(r"^(?P<host>\S+)\s+(?P<program>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$")
_REPEATED = re.compile(r"^message repeated (?P<count>\d+) times?: \[\s*(?P<message>.*?)\s*\]$")
_TZ = re.compile(r"^(?P<sign>[+-])(?P<hours>\d{2}):?(?P<minutes>\d{2})?$")


def parse_tz(text: str) -> timezone:
    """``+07:00``, ``+0700``, ``-05``, ``Z`` or ``UTC`` -> a fixed-offset time zone."""
    value = str(text).strip()
    if value.upper() in ("Z", "UTC"):
        return timezone.utc
    found = _TZ.match(value)
    if not found:
        raise ValueError(f"time zone must look like +07:00, got {text!r}")
    hours = int(found["hours"])
    minutes = int(found["minutes"] or 0)
    if minutes >= 60:
        raise ValueError(f"time zone minutes out of range: {text!r}")
    offset = timedelta(hours=hours, minutes=minutes)
    if offset > timedelta(hours=14):
        raise ValueError(f"time zone offset out of range: {text!r}")
    return timezone(offset if found["sign"] == "+" else -offset)


class _Clock:
    """Gives classic syslog timestamps their missing year and time zone."""

    def __init__(self, year: int | None, zone: timezone, now: datetime | None) -> None:
        self.year = year
        self.zone = zone
        self.now = now
        self.previous: datetime | None = None

    def observe_iso(self, moment: datetime) -> None:
        """Anchor subsequent classic timestamps to the local date of an ISO line."""
        local = moment.astimezone(self.zone)
        self.previous = local
        self.year = local.year

    def resolve(self, month: int, day: int, hour: int, minute: int, second: int) -> datetime:
        def build(year: int) -> datetime | None:
            try:
                return datetime(year, month, day, hour, minute, second, tzinfo=self.zone)
            except ValueError:               # 30 February, or 29 February outside a leap year
                return None

        if self.previous is None:
            if self.year is None:
                now = self.now or datetime.now(self.zone)
                guess = build(now.year)
                self.year = now.year - 1 if guess and guess > now + timedelta(days=1) else now.year
            moment = build(self.year)
        else:
            around = [m for m in (build(self.previous.year + step) for step in (-1, 0, 1)) if m]
            moment = min(around, key=lambda m: abs(m - self.previous)) if around else None
        if moment is None:
            raise ValueError("impossible date")
        self.previous = moment
        return moment


def _split(line: str, clock: _Clock) -> tuple[datetime, str, str, int | None, str]:
    """One line -> (time, host, program, pid, message). Raises ValueError."""
    found = _ISO.match(line)
    is_iso = found is not None
    if found:
        try:
            moment = datetime.fromisoformat(found["stamp"].replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("unreadable ISO timestamp") from None
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=clock.zone)
    else:
        found = _CLASSIC.match(line)
        if not found or found["month"] not in _MONTHS:
            raise ValueError("no syslog timestamp")
        moment = clock.resolve(_MONTHS[found["month"]], int(found["day"]), int(found["hour"]),
                               int(found["minute"]), int(found["second"]))
    tag = _TAG.match(found["rest"])
    if not tag:
        raise ValueError("no 'host program: message' part")
    pid = int(tag["pid"]) if tag["pid"] else None
    if is_iso:
        # A mixed-format file must use this ISO line as the year/time anchor.
        # Keep the original timezone in the event; only the clock uses local time.
        clock.observe_iso(moment)
    return moment, tag["host"], tag["program"], pid, tag["message"]


def parse_lines(lines: Iterable[str], stats: dict[str, Any] | None = None, *,
                year: int | None = None, tz: str | None = None,
                now: datetime | None = None) -> Iterator[dict[str, Any]]:
    """Canonical events from auth.log lines. ``now`` exists for tests only."""
    stats = start_stats(stats)
    zone = parse_tz(tz or os.environ.get("SOC_AUTH_LOG_TZ") or DEFAULT_TZ)
    if year is None and os.environ.get("SOC_AUTH_LOG_YEAR"):
        year = int(os.environ["SOC_AUTH_LOG_YEAR"])
    clock = _Clock(year, zone, now)
    mapper = AuthLogMapper()
    for raw_line in lines:
        line = raw_line.rstrip("\r\n")
        if not line.strip():
            continue
        stats["lines"] += 1
        try:
            moment, host, program, pid, message = _split(line, clock)
        except ValueError as exc:
            skip(stats, "invalid", str(exc))
            continue
        # rsyslog folds identical lines into "message repeated 3 times: [ ... ]".
        repeated = _REPEATED.match(message)
        copies = 1
        if repeated:
            copies, message = min(int(repeated["count"]), MAX_REPEAT), repeated["message"]
        try:
            event = mapper.map(moment, host, program, pid, message, line)
        except EventValidationError as exc:
            skip(stats, "invalid", str(exc))
            continue
        if event is None:
            skip(stats, "ignored", f"{program} line with no login, sudo or lockout information")
            continue
        for _ in range(copies):
            stats["events"] += 1
            yield dict(event)


def parse_file(path: Path, stats: dict[str, Any] | None = None, *,
               year: int | None = None, tz: str | None = None,
               now: datetime | None = None) -> Iterator[dict[str, Any]]:
    """Agreed ingestor interface: ``parse_file(path)`` yields canonical events."""
    yield from parse_lines(read_lines(Path(path)), stats, year=year, tz=tz, now=now)
