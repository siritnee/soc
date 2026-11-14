"""Synthetic Suricata EVE records: normal traffic plus labelled network attacks.

Signature names start with "LAB" and use local rule ids (1000000-1999999);
they are made up for this project, not copied from a public rule set.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Sequence

from datagen.common import (
    DNS_SERVER, INTERNET_SITES, LAB_TZ, LINUX_SERVERS, WINDOWS_HOSTS, WORKSTATION_USERS,
    Label, LogBundle, Rng, in_file_order,
)

SENSOR = "sensor-01"
# Suricata writes a flow record when the flow times out, not when it starts.
FLOW_LOG_DELAY = {"TCP": 60.0, "UDP": 30.0}

SIG_EXPLOIT = (1000001, "LAB EXPLOIT Possible SMB remote code execution attempt",
               "Attempted Administrator Privilege Gain", 1)
SIG_BEACON = (1000002, "LAB MALWARE Generic CnC beacon over HTTPS",
              "Malware Command and Control Activity Detected", 1)
SIG_UPDATE = (1000010, "LAB INFO Software update check", "Not Suspicious Traffic", 3)
SIG_CLEARTEXT = (1000011, "LAB POLICY Cleartext HTTP to external site",
                 "Potential Corporate Privacy Violation", 2)


def eve_time(moment: datetime, tz=LAB_TZ) -> str:
    """Suricata's layout: local time with a zone offset that has no colon."""
    return moment.astimezone(tz).strftime("%Y-%m-%dT%H:%M:%S.%f%z")


def render(entries: Sequence[tuple[datetime, dict]]) -> str:
    """One JSON object per line, in the order Suricata would have logged them."""
    return "".join(json.dumps(record, ensure_ascii=False) + "\n" for _, record in in_file_order(entries))


def _base(rng: Rng, moment: datetime, kind: str, src_ip: str, dst_ip: str, dst_port: int,
          proto: str, src_port: int | None = None) -> dict:
    return {
        "timestamp": eve_time(moment), "flow_id": rng.randint(10**14, 10**15 - 1), "in_iface": "eth0",
        "event_type": kind, "src_ip": src_ip, "src_port": src_port or rng.randint(49152, 65535),
        "dest_ip": dst_ip, "dest_port": dst_port, "proto": proto, "host": SENSOR,
    }


def alert_entry(rng: Rng, moment: datetime, src_ip: str, dst_ip: str, dst_port: int,
                signature: tuple[int, str, str, int], proto: str = "TCP") -> tuple[datetime, dict]:
    sid, name, category, severity = signature
    record = _base(rng, moment, "alert", src_ip, dst_ip, dst_port, proto)
    record["alert"] = {"action": "allowed", "gid": 1, "signature_id": sid, "rev": 1,
                       "signature": name, "category": category, "severity": severity}
    return moment, record


def flow_entry(rng: Rng, start: datetime, src_ip: str, dst_ip: str, dst_port: int,
               proto: str = "TCP", seconds: float = 0.0, answered: bool = True) -> tuple[datetime, dict]:
    """A finished flow. The record's own timestamp is when Suricata wrote it."""
    end = start + timedelta(seconds=seconds)
    logged = end + timedelta(seconds=FLOW_LOG_DELAY[proto] + rng.uniform(0, 3))
    record = _base(rng, logged, "flow", src_ip, dst_ip, dst_port, proto)
    packets = rng.randint(4, 40) if answered else 1
    record["flow"] = {
        "pkts_toserver": packets, "pkts_toclient": packets - 1 if answered else 0,
        "bytes_toserver": packets * rng.randint(60, 600), "bytes_toclient": packets * rng.randint(60, 900) if answered else 0,
        "start": eve_time(start), "end": eve_time(end), "age": int(seconds),
        "state": "closed" if answered else "new", "reason": "timeout", "alerted": False,
    }
    return logged, record


def dns_entry(rng: Rng, moment: datetime, src_ip: str, name: str) -> tuple[datetime, dict]:
    record = _base(rng, moment, "dns", src_ip, DNS_SERVER, 53, "UDP")
    record["dns"] = {"type": "query", "id": rng.randint(1, 65535), "rrname": name, "rrtype": "A", "tx_id": 0}
    return moment, record


def http_entry(rng: Rng, moment: datetime, src_ip: str, dst_ip: str, site: str, url: str) -> tuple[datetime, dict]:
    record = _base(rng, moment, "http", src_ip, dst_ip, 80, "TCP")
    record["http"] = {"hostname": site, "url": url, "http_user_agent": "LabBrowser/1.0",
                      "http_method": "GET", "protocol": "HTTP/1.1", "status": 200, "length": rng.randint(200, 9000)}
    return moment, record


def stats_entry(moment: datetime) -> tuple[datetime, dict]:
    """Suricata's periodic counters: a record type the toolkit ignores."""
    return moment, {"timestamp": eve_time(moment), "event_type": "stats",
                    "stats": {"uptime": 3600, "decoder": {"pkts": 123456}}}


def benign_traffic(rng: Rng, start: datetime, minutes: int) -> LogBundle:
    """Web browsing, name lookups, file-server and domain traffic, update checks."""
    bundle = LogBundle()
    sites = sorted(INTERNET_SITES.items())
    internal = [(WINDOWS_HOSTS["FS-01"], 445), (WINDOWS_HOSTS["DC-01"], 88), (WINDOWS_HOSTS["DC-01"], 389)]
    clients = [WINDOWS_HOSTS[name] for name in WORKSTATION_USERS] + sorted(LINUX_SERVERS.values())
    for client in clients:
        elapsed = rng.uniform(0.5, 4)
        while elapsed < minutes:
            moment = start + timedelta(minutes=elapsed)
            if rng.chance(0.3):                                            # internal service
                server, port = rng.choice(internal)
                bundle.eve.append(flow_entry(rng, moment, client, server, port, seconds=rng.uniform(0.2, 30)))
            else:                                                          # look up a site, then visit it
                site, address = rng.choice(sites)
                bundle.eve.append(dns_entry(rng, moment, client, site))
                bundle.eve.append(flow_entry(rng, moment, client, DNS_SERVER, 53, proto="UDP", seconds=0.05))
                visit = moment + timedelta(seconds=0.2)
                if rng.chance(0.25):
                    bundle.eve.append(http_entry(rng, visit, client, address, site, "/index.html"))
                    bundle.eve.append(flow_entry(rng, visit, client, address, 80, seconds=rng.uniform(0.5, 20)))
                else:
                    bundle.eve.append(flow_entry(rng, visit, client, address, 443, seconds=rng.uniform(0.5, 90)))
                if site.startswith("updates.") and rng.chance(0.5):
                    bundle.eve.append(alert_entry(rng, visit, client, address, 443, SIG_UPDATE))
            elapsed += rng.uniform(2.5, 8)
    for minute in range(0, minutes, 20):
        bundle.eve.append(stats_entry(start + timedelta(minutes=minute, seconds=8)))
    return bundle


def port_scan(rng: Rng, start: datetime, scanner_ip: str, target_ip: str, ports: Sequence[int],
              seconds: float, scenario_id: str, *, malicious: bool = True,
              open_ports: Sequence[int] = (22, 80, 443)) -> LogBundle:
    """One host probing many ports of another. With ``malicious=False`` it is
    the harmless look-alike (too few ports, or far too slow)."""
    bundle = LogBundle()
    step = seconds / max(len(ports) - 1, 1)
    probes = []
    for index, port in enumerate(ports):
        probes.append(start + timedelta(seconds=index * step + rng.uniform(0, step * 0.3)))
        bundle.eve.append(flow_entry(rng, probes[-1], scanner_ip, target_ip, port, answered=port in open_ports))
    bundle.labels.append(Label(
        scenario_id=scenario_id, kind="port_scan" if malicious else "decoy", malicious=malicious,
        expected_rule="INTERNAL_PORT_SCAN" if malicious else None,
        start=probes[0], end=probes[-1], match={"src_ip": [scanner_ip], "dst_ip": [target_ip]}, sources=["suricata"],
        description=(f"{scanner_ip} connects to {len(ports)} different ports on {target_ip} "
                     f"in about {seconds:g} seconds." + ("" if malicious else " Not an attack.")),
    ))
    return bundle


def beaconing(rng: Rng, start: datetime, src_ip: str, c2_ip: str, port: int, interval: float,
              count: int, scenario_id: str, *, jitter: float = 0.1) -> LogBundle:
    """Malware calling its control server every ``interval`` seconds (+- ``jitter``)."""
    bundle = LogBundle()
    moment = start
    for beat in range(count):
        if beat:
            moment += timedelta(seconds=interval * (1 + rng.uniform(-jitter, jitter)))
        bundle.eve.append(alert_entry(rng, moment, src_ip, c2_ip, port, SIG_BEACON))
        bundle.eve.append(flow_entry(rng, moment, src_ip, c2_ip, port, seconds=rng.uniform(0.2, 0.8)))
    bundle.labels.append(Label(
        scenario_id=scenario_id, kind="beaconing", malicious=True, expected_rule="MALWARE_BEACONING",
        start=start, end=moment, match={"src_ip": [src_ip], "dst_ip": [c2_ip]}, sources=["suricata"],
        description=f"{src_ip} contacts {c2_ip}:{port} {count} times, about every {interval:g} seconds.",
    ))
    return bundle


def repeated_alerts(rng: Rng, start: datetime, src_ip: str, dst_ip: str, gaps: Sequence[float],
                    signature: tuple[int, str, str, int], scenario_id: str, port: int = 80) -> LogBundle:
    """The same alert several times with the given gaps (seconds): a harmless
    look-alike of beaconing, either irregular or of low severity."""
    bundle = LogBundle()
    moment = start
    bundle.eve.append(alert_entry(rng, moment, src_ip, dst_ip, port, signature))
    for gap in gaps:
        moment += timedelta(seconds=gap)
        bundle.eve.append(alert_entry(rng, moment, src_ip, dst_ip, port, signature))
    bundle.labels.append(Label(
        scenario_id=scenario_id, kind="decoy", malicious=False, expected_rule=None,
        start=start, end=moment, match={"src_ip": [src_ip], "dst_ip": [dst_ip]}, sources=["suricata"],
        description=f"{len(gaps) + 1} alerts \"{signature[1]}\" from {src_ip} to {dst_ip}. Not an attack.",
    ))
    return bundle


def main(argv: Sequence[str] | None = None) -> int:
    """Demo: ``python -m datagen.suricata --out eve.json`` writes normal traffic
    plus a port scan and a beacon, and prints their labels."""
    import argparse

    parser = argparse.ArgumentParser(prog="python -m datagen.suricata", description=main.__doc__)
    parser.add_argument("--out", required=True, help="file to write")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--minutes", type=int, default=60, help="length of the normal traffic")
    parser.add_argument("--start", default="2026-11-12T08:00:00+07:00", help="ISO time of the first minute")
    args = parser.parse_args(argv)
    rng, start = Rng(args.seed), datetime.fromisoformat(args.start)
    bundle = benign_traffic(rng.fork("benign"), start, args.minutes)
    bundle.merge(port_scan(rng.fork("scan"), start + timedelta(minutes=args.minutes / 2), "10.0.2.99",
                           "10.0.1.10", list(range(1, 101)), 20, "demo-port-scan"))
    bundle.merge(beaconing(rng.fork("beacon"), start + timedelta(minutes=5), "10.0.2.40", "203.0.113.200",
                           443, 60, 20, "demo-beaconing"))
    with open(args.out, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render(bundle.eve))
    print(json.dumps([label.to_dict() for label in bundle.labels], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
