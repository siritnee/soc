"""Synthetic auth.log: everyday logins plus labelled SSH attacks.

Each function returns a LogBundle; ``render`` turns its auth entries into
file text. Times inside the bundle are real datetimes, the file shows them
the way syslog does: local time, no year, no zone.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Sequence

from datagen.common import (
    LAB_TZ, LINUX_SERVERS, WINDOWS_HOSTS, WORKSTATION_USERS, Label, LogBundle, Rng, in_file_order,
)

_MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
_SUDO_COMMANDS = (
    "/usr/bin/systemctl status nginx", "/usr/bin/apt update", "/usr/bin/journalctl -u ssh -n 50",
    "/usr/bin/tail -n 100 /var/log/syslog", "/usr/bin/systemctl restart app.service",
)
# Looks like a key fingerprint, is not one.
_FAKE_FINGERPRINT = "SHA256:SYNTHETICxFINGERPRINTxFORxLABxUSExONLYx0001"


def stamp(moment: datetime, tz=LAB_TZ) -> str:
    """``Nov  2 08:40:03`` - month names are spelled out here so the result
    does not depend on the language settings of the machine."""
    local = moment.astimezone(tz)
    return f"{_MONTHS[local.month - 1]} {local.day:>2} {local:%H:%M:%S}"


def _whole(moment: datetime) -> datetime:
    """auth.log only records whole seconds."""
    return moment.replace(microsecond=0)


def render(entries: Sequence[tuple[datetime, str]], tz=LAB_TZ) -> str:
    return "".join(f"{stamp(moment, tz)} {text}\n" for moment, text in in_file_order(entries))


class _Host:
    """Writes lines for one server and hands out process ids."""

    def __init__(self, bundle: LogBundle, name: str, first_pid: int) -> None:
        self.bundle, self.name, self.pid = bundle, name, first_pid

    def next_pid(self) -> int:
        self.pid += 1
        return self.pid

    def line(self, moment: datetime, tag: str, message: str) -> None:
        self.bundle.auth.append((_whole(moment), f"{self.name} {tag}: {message}"))

    def sshd(self, moment: datetime, pid: int, message: str) -> None:
        self.line(moment, f"sshd[{pid}]", message)

    def failed(self, moment: datetime, pid: int, user: str, ip: str, port: int, known: bool) -> datetime:
        """One wrong password: sshd first notes the attempt, a second later it
        reports the failure. Returns the time of the "Failed password" line."""
        failure = moment + timedelta(seconds=1)
        if known:
            self.sshd(moment, pid, "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 "
                                   f"tty=ssh ruser= rhost={ip}  user={user}")
            self.sshd(failure, pid, f"Failed password for {user} from {ip} port {port} ssh2")
        else:
            self.sshd(moment, pid, f"Invalid user {user} from {ip} port {port}")
            self.sshd(failure, pid, f"Failed password for invalid user {user} from {ip} port {port} ssh2")
        return failure

    def session(self, rng: Rng, moment: datetime, user: str, ip: str, method: str = "publickey",
                minutes: float = 10.0) -> None:
        """A normal login: accepted, a few sudo commands, logout."""
        pid, port = self.next_pid(), rng.randint(49152, 65000)
        suffix = f": ED25519 {_FAKE_FINGERPRINT}" if method == "publickey" else ""
        self.sshd(moment, pid, f"Accepted {method} for {user} from {ip} port {port} ssh2{suffix}")
        self.sshd(moment, pid, f"pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)")
        self.line(moment, "systemd-logind[612]", f"New session {rng.randint(10, 999)} of user {user}.")
        for _ in range(rng.randint(0, 2)):
            when = moment + timedelta(seconds=rng.uniform(20, minutes * 50))
            self.line(when, "sudo", f"   {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; "
                                    f"COMMAND={rng.choice(_SUDO_COMMANDS)}")
            self.line(when, "sudo", f"pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid=1001)")
        self.sshd(moment + timedelta(minutes=minutes), pid,
                  f"pam_unix(sshd:session): session closed for user {user}")


def benign_activity(rng: Rng, start: datetime, minutes: int,
                    servers: Sequence[str] = tuple(LINUX_SERVERS)) -> LogBundle:
    """Cron jobs, admin logins from the workstations, and the odd typo."""
    bundle = LogBundle()
    clients = [(WORKSTATION_USERS[name], WINDOWS_HOSTS[name]) for name in WORKSTATION_USERS]
    for index, server in enumerate(servers):
        host = _Host(bundle, server, 2000 + 1000 * index)
        for minute in range(5 + index, minutes, 15):                      # cron every 15 minutes
            when = start + timedelta(minutes=minute, seconds=1)
            pid = host.next_pid()
            host.line(when, f"CRON[{pid}]", "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
            host.line(when + timedelta(seconds=1), f"CRON[{pid}]", "pam_unix(cron:session): session closed for user root")
        elapsed = rng.uniform(2, 12)
        while elapsed < minutes - 12:
            user, ip = rng.choice(clients)
            when = start + timedelta(minutes=elapsed)
            if rng.chance(0.2):                                            # one wrong password, then right
                pid, port = host.next_pid(), rng.randint(49152, 65000)
                when = host.failed(when, pid, user, ip, port, known=True) + timedelta(seconds=rng.uniform(4, 9))
                host.session(rng, when, user, ip, method="password", minutes=rng.uniform(3, 10))
            else:
                host.session(rng, when, user, ip, minutes=rng.uniform(3, 10))
            elapsed += rng.uniform(14, 32)
    return bundle


def brute_force(rng: Rng, start: datetime, attacker_ip: str, server: str, usernames: Sequence[str],
                failures: int, outcome: str, scenario_id: str, *, valid_users: Sequence[str] = ("root",),
                gap: tuple[float, float] = (1.5, 4.0), after_lock: int = 2) -> LogBundle:
    """Password guessing from one IP that ends in a login or an account lockout.

    ``outcome`` is "success" (the last user in ``usernames`` logs in),
    "lockout" (pam_faillock locks that user) or "none" (the attacker gives up).
    """
    if outcome not in ("success", "lockout", "none"):
        raise ValueError("outcome must be success, lockout or none")
    bundle = LogBundle()
    host = _Host(bundle, server, 3000 + rng.randint(0, 500))
    victim = usernames[-1]
    known = set(valid_users) | {victim}
    moment, pid = start, host.next_pid()
    for attempt in range(failures):
        if attempt and attempt % 3 == 0:                                   # sshd drops the client after 3 tries
            pid = host.next_pid()
        user = victim if outcome == "lockout" else usernames[attempt % len(usernames)]
        end = host.failed(moment, pid, user, attacker_ip, rng.randint(32768, 60999), known=user in known)
        moment = end + timedelta(seconds=rng.uniform(*gap))
    if outcome == "success":
        pid, end = host.next_pid(), moment
        host.sshd(moment, pid, f"Accepted password for {victim} from {attacker_ip} port {rng.randint(32768, 60999)} ssh2")
        host.sshd(moment, pid, f"pam_unix(sshd:session): session opened for user {victim}(uid=1002) by (uid=0)")
    elif outcome == "lockout":
        locked = f"pam_faillock(sshd:auth): Consecutive login failures for user {victim} account temporarily locked"
        end += timedelta(seconds=1)
        host.sshd(end, pid, locked)                                        # same sshd process as the last failure
        for _ in range(after_lock):                                        # the attacker keeps trying for a while
            pid = host.next_pid()
            moment = end + timedelta(seconds=rng.uniform(*gap))
            end = host.failed(moment, pid, victim, attacker_ip, rng.randint(32768, 60999), known=True)
            end += timedelta(seconds=1)
            host.sshd(end, pid, locked)
    ending = {"success": f"then logs in as {victim}", "lockout": f"until {victim} is locked out",
              "none": "and gives up"}[outcome]
    bundle.labels.append(Label(
        scenario_id=scenario_id, kind="ssh_brute_force", malicious=True,
        expected_rule=None if outcome == "none" else "SSH_BRUTE_FORCE",
        start=_whole(start), end=_whole(end), match={"src_ip": [attacker_ip]}, sources=["auth_log"],
        description=f"{attacker_ip} tries {failures} SSH passwords on {server} {ending}.",
    ))
    return bundle


def typo_login(rng: Rng, start: datetime, server: str, user: str, client_ip: str,
               failures: int, scenario_id: str, gap: tuple[float, float] = (4.0, 9.0)) -> LogBundle:
    """A real user mistypes the password a few times, then gets it right.

    With a wide ``gap`` this is also the "slow" look-alike: many failures,
    but never five inside one minute.
    """
    bundle = LogBundle()
    host = _Host(bundle, server, 5000 + rng.randint(0, 500))
    moment, pid = start, host.next_pid()
    for _ in range(failures):
        moment = host.failed(moment, pid, user, client_ip, rng.randint(49152, 65000), known=True)
        moment += timedelta(seconds=rng.uniform(*gap))
    host.session(rng, moment, user, client_ip, method="password", minutes=5)
    bundle.labels.append(Label(
        scenario_id=scenario_id, kind="decoy", malicious=False, expected_rule=None,
        start=_whole(start), end=_whole(moment), match={"src_ip": [client_ip], "hostname": [server]},
        sources=["auth_log"],
        description=f"{user} mistypes the password {failures} times on {server}, then logs in. Not an attack.",
    ))
    return bundle


def main(argv: Sequence[str] | None = None) -> int:
    """Demo: ``python -m datagen.auth_log --out auth.log`` writes normal activity
    plus one brute-force attack and prints the label of the attack."""
    import argparse
    import json

    parser = argparse.ArgumentParser(prog="python -m datagen.auth_log", description=main.__doc__)
    parser.add_argument("--out", required=True, help="file to write")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--minutes", type=int, default=60, help="length of the normal activity")
    parser.add_argument("--start", default="2026-11-12T08:00:00+07:00", help="ISO time of the first minute")
    args = parser.parse_args(argv)
    rng, start = Rng(args.seed), datetime.fromisoformat(args.start)
    bundle = benign_activity(rng.fork("benign"), start, args.minutes)
    bundle.merge(brute_force(rng.fork("attack"), start + timedelta(minutes=args.minutes / 2), "203.0.113.50",
                             "bastion-01", ["admin", "root", "deploy"], 12, "success", "demo-brute-force"))
    with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render(bundle.auth, start.tzinfo or LAB_TZ))
    print(json.dumps([label.to_dict() for label in bundle.labels], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
