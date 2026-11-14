"""Meaning of auth.log messages: one syslog message -> one canonical event.

``ingestors/auth_log.py`` splits a line into time, host, program, pid and
message; this module decides what the message means.

Actions produced: ssh_failed, ssh_success, ssh_invalid_user, ssh_lockout,
ssh_max_auth_exceeded, sudo_command, sudo_failed, sudo_denied.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
from typing import Any

from normalizer.schema import normalize_event

_FAILED = re.compile(
    r"^Failed (?P<method>password|keyboard-interactive/pam) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
_INVALID_USER = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
_MAX_AUTH = re.compile(
    r"maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)")
# PAM line that precedes "Failed password"; only used to remember the client IP.
_PAM_FAILURE = re.compile(
    r"pam_unix\(sshd:auth\): authentication failure;.*\brhost=(?P<ip>\S+)(?:\s+user=(?P<user>\S+))?")
# Account lockouts. None of these lines contains the client IP.
_LOCK_FAILLOCK = re.compile(
    r"Consecutive login failures for user (?P<user>\S+) account temporarily locked")
_LOCK_TALLY = re.compile(r"pam_tally2?\([^)]*\): user (?P<user>\S+) \(\d+\) tally \d+, deny \d+")
_LOCK_GENERIC = re.compile(r"account (?:temporarily )?locked", re.IGNORECASE)
_USER_WORD = re.compile(r"\buser (?P<user>[^\s,;:()]+)")
_SUDO = re.compile(r"^\s*(?P<user>\S+) : (?P<rest>.+)$")
_SUDO_AUTH_FAILURE = re.compile(r"\bpam_unix\(sudo:auth\): authentication failure\b", re.IGNORECASE)
_SUDO_AUTH_USER = re.compile(r"\buser=(?P<user>[^\s;]+)")
_LOCKOUT_IP_MAX_AGE = timedelta(minutes=5)  # Correlation hint only; not proof of the attacker.


@dataclass(frozen=True)
class _RecentIP:
    address: str
    seen_at: datetime
    username: str | None


def _ip_or_none(text: str | None) -> str | None:
    """sshd prints a host name instead of an address when UseDNS is on."""
    try:
        return str(ip_address(text)) if text else None
    except ValueError:
        return None


class AuthLogMapper:
    """Keeps the little state needed to give lockout lines a source IP.

    A lockout line names the user but not always the attacker. An earlier
    client's IP is only a hint when it matches the same host, a compatible
    sshd process/user and was observed in the last five event-time minutes.
    Unknown or stale hints stay ``None`` to avoid false correlations.
    """

    def __init__(self) -> None:
        self._ip_by_pid: dict[tuple[str, int], _RecentIP] = {}
        self._ip_by_user: dict[tuple[str, str], _RecentIP] = {}

    def map(self, ts: datetime, host: str, program: str, pid: int | None,
            message: str, line: str) -> dict[str, Any] | None:
        """Canonical event for one message, or None when the line is not of interest."""
        if program == "sshd":
            return self._map_sshd(ts, host, pid, message, line)
        if program == "sudo":
            return self._map_sudo(ts, host, message, line)
        return None

    # ---- sshd --------------------------------------------------------------
    def _map_sshd(self, ts, host, pid, message, line):
        found = _FAILED.search(message)
        if found:
            ip = self._remember(ts, host, pid, found["user"], found["ip"])
            return self._event(ts, host, "ssh_failed", "medium", line, src_ip=ip, username=found["user"],
                               extra={"method": found["method"], "src_port": int(found["port"]),
                                      "invalid_user": bool(found["invalid"]), "client": found["ip"]})
        found = _ACCEPTED.search(message)
        if found:
            return self._event(ts, host, "ssh_success", "info", line, src_ip=_ip_or_none(found["ip"]),
                               username=found["user"],
                               extra={"method": found["method"], "src_port": int(found["port"]),
                                      "client": found["ip"]})
        found = _INVALID_USER.search(message)
        if found:
            ip = self._remember(ts, host, pid, found["user"], found["ip"])
            return self._event(ts, host, "ssh_invalid_user", "low", line, src_ip=ip,
                               username=found["user"] or None, extra={"client": found["ip"]})
        found = _MAX_AUTH.search(message)
        if found:
            ip = self._remember(ts, host, pid, found["user"], found["ip"])
            return self._event(ts, host, "ssh_max_auth_exceeded", "medium", line, src_ip=ip,
                               username=found["user"], extra={"client": found["ip"]})
        found = _PAM_FAILURE.search(message)
        if found:
            self._remember(ts, host, pid, found["user"], found["ip"])
            return None                       # the "Failed password" line is the event
        found = _LOCK_FAILLOCK.search(message) or _LOCK_TALLY.search(message)
        if found or _LOCK_GENERIC.search(message):
            user_match = found or _USER_WORD.search(message)
            user = user_match["user"] if user_match else None
            ip, origin = self._recent_lockout_ip(ts, host, pid, user)
            return self._event(ts, host, "ssh_lockout", "high", line, src_ip=ip, username=user,
                               extra={"src_ip_from": origin})
        return None

    @staticmethod
    def _fresh(record: _RecentIP | None, ts: datetime) -> bool:
        if record is None:
            return False
        age = ts - record.seen_at
        return timedelta(0) <= age <= _LOCKOUT_IP_MAX_AGE

    def _recent_lockout_ip(self, ts: datetime, host: str, pid: int | None,
                           user: str | None) -> tuple[str | None, str]:
        if pid is not None:
            by_pid = self._ip_by_pid.get((host, pid))
            # An sshd PID can be reused. Never bind an explicitly different user.
            if (self._fresh(by_pid, ts) and by_pid is not None
                    and (user is None or by_pid.username is None or by_pid.username == user)):
                return by_pid.address, "recent sshd process"
        if user:
            by_user = self._ip_by_user.get((host, user))
            if self._fresh(by_user, ts) and by_user is not None:
                return by_user.address, "recent same-user sshd event"
        return None, "unknown"

    def _remember(self, ts: datetime, host: str, pid: int | None,
                  user: str | None, client: str) -> str | None:
        ip = _ip_or_none(client)
        if ip:
            record = _RecentIP(ip, ts, user)
            # None is not a reliable process identifier; never use it as one.
            if pid is not None:
                old = self._ip_by_pid.get((host, pid))
                if old is None or ts >= old.seen_at:
                    self._ip_by_pid[(host, pid)] = record
            if user:
                old = self._ip_by_user.get((host, user))
                if old is None or ts >= old.seen_at:
                    self._ip_by_user[(host, user)] = record
        return ip

    # ---- sudo --------------------------------------------------------------
    def _map_sudo(self, ts, host, message, line):
        found = _SUDO.match(message)
        if found:
            user, rest = found["user"], found["rest"]
        else:
            # PAM sudo authentication errors have no leading "username :" prefix.
            if not _SUDO_AUTH_FAILURE.search(message):
                return None
            match = _SUDO_AUTH_USER.search(message)
            user = match["user"] if match else None
            rest = message

        lowered = rest.lower()
        if (_SUDO_AUTH_FAILURE.search(rest) or
                "incorrect password attempt" in lowered or
                "authentication failure" in lowered):
            action, severity = "sudo_failed", "medium"
        elif ("not in sudoers" in lowered or "not allowed" in lowered or
              "not permitted" in lowered):
            action, severity = "sudo_denied", "medium"
        elif "COMMAND=" in rest:
            action, severity = "sudo_command", "info"
        else:
            return None  # Ignore unrelated PAM/session messages.

        if "COMMAND=" in rest:
            details, command = rest.split("COMMAND=", 1)
            command = command.strip()
        else:
            details, command = rest, None
        fields = dict(part.split("=", 1) for part in details.split(" ; ") if "=" in part)
        return self._event(ts, host, action, severity, line, username=user,
                           command_line=command, process_name="sudo",
                           extra={"run_as": fields.get("USER", "").strip() or None,
                                  "tty": fields.get("TTY", "").strip() or None,
                                  "cwd": fields.get("PWD", "").strip() or None})

    # ---- shared --------------------------------------------------------------
    @staticmethod
    def _event(ts, host, action, severity, line, *, src_ip=None, username=None,
               command_line=None, process_name="sshd", extra=None) -> dict[str, Any]:
        raw = {"line": line}
        raw.update(extra or {})
        return normalize_event({
            "timestamp_utc": ts, "source_type": "auth_log",
            "src_ip": src_ip, "dst_ip": None,
            "username": username, "hostname": host,
            "action": action, "severity": severity,
            "process_name": process_name, "command_line": command_line,
            "raw": raw,
        })
