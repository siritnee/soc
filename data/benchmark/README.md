# soc-benchmark-v1

Two hours of lab activity in three log sources with labelled attacks and harmless look-alikes.

Synthetic data only: private (10.x) and documentation IP ranges, made-up users and hosts.
Do not edit by hand. Rebuild with:

    python -m datagen.benchmark --out data/benchmark --holdout data/holdout

(seed 2026; the same seed always gives the same files).

| Scenario | Kind | Rule that must fire | Start (UTC) | Log sources | What happens |
|---|---|---|---|---|---|
| `beaconing` | attack | MALWARE_BEACONING | 01:10:00 | suricata | 10.0.2.40 contacts 203.0.113.200:443 40 times, about every 60 seconds. |
| `decoy-typo-login` | harmless | - | 01:15:00 | auth_log | alice mistypes the password 3 times on web-01, then logs in. Not an attack. |
| `decoy-irregular-alerts` | harmless | - | 01:20:00 | suricata | 8 alerts "LAB POLICY Cleartext HTTP to external site" from 10.0.2.22 to 192.0.2.80. Not an attack. |
| `ssh-bruteforce-login` | attack | SSH_BRUTE_FORCE | 01:25:00 | auth_log | 203.0.113.50 tries 12 SSH passwords on bastion-01 then logs in as deploy. |
| `decoy-slow-failures` | harmless | - | 01:30:00 | auth_log | bob mistypes the password 6 times on db-01, then logs in. Not an attack. |
| `decoy-periodic-low-alerts` | harmless | - | 01:35:00 | suricata | 7 alerts "LAB INFO Software update check" from 10.0.1.10 to 192.0.2.81. Not an attack. |
| `portscan-network` | attack | INTERNAL_PORT_SCAN | 01:40:00 | suricata | 10.0.2.99 connects to 200 different ports on 10.0.1.10 in about 20 seconds. |
| `decoy-appdata-program` | harmless | - | 01:45:00 | sysmon | dave starts LabChat, a legitimate program installed under AppData, on WS-04. Not an attack. |
| `ssh-bruteforce-gave-up` | attack | - | 01:50:00 | auth_log | 203.0.113.51 tries 9 SSH passwords on db-01 and gives up. |
| `process-temp` | attack | SUSPICIOUS_PROCESS | 01:55:00 | sysmon | alice runs invoice_viewer.exe from the Temp folder on WS-01. |
| `decoy-few-ports` | harmless | - | 02:00:00 | suricata | 10.0.2.10 connects to 10 different ports on 10.0.1.11 in about 20 seconds. Not an attack. |
| `process-encoded` | attack | SUSPICIOUS_PROCESS | 02:05:00 | sysmon | Word starts PowerShell with an encoded command on WS-02. |
| `decoy-slow-sweep` | harmless | - | 02:10:08 | suricata | 10.0.2.10 connects to 20 different ports on 10.0.1.10 in about 570 seconds. Not an attack. |
| `ssh-bruteforce-lockout` | attack | SSH_BRUTE_FORCE | 02:20:00 | auth_log | 198.51.100.23 tries 8 SSH passwords on web-01 until alice is locked out. |
| `portscan-host` | attack | INTERNAL_PORT_SCAN | 02:35:00 | sysmon | WS-03 (10.0.2.23) connects to 60 different ports on 10.0.1.20 in about 10 seconds. |
| `pivot` | attack | NETWORK_TO_HOST_PIVOT | 02:45:00 | suricata, sysmon | Suricata alerts on an exploit from 203.0.113.77 against WS-04 (10.0.2.24); then WS-04 connects to 4 internal machines. |
