# soc-holdout-bruteforce

SSH log kept aside for practising the defence. Not used when rules are tuned.

Synthetic data only: private (10.x) and documentation IP ranges, made-up users and hosts.
Do not edit by hand. Rebuild with:

    python -m datagen.benchmark --out data/benchmark --holdout data/holdout

(seed 7771; the same seed always gives the same files).

| Scenario | Kind | Rule that must fire | Start (UTC) | Log sources | What happens |
|---|---|---|---|---|---|
| `holdout-typo-login` | harmless | - | 07:04:00 | auth_log | carol mistypes the password 4 times on bastion-01, then logs in. Not an attack. |
| `holdout-bruteforce-login` | attack | SSH_BRUTE_FORCE | 07:09:00 | auth_log | 203.0.113.9 tries 9 SSH passwords on db-01 then logs in as backup. |
| `holdout-slow-bruteforce` | attack | - | 07:18:00 | auth_log | 198.51.100.88 tries 10 SSH passwords on web-01 then logs in as deploy. One try every 20 seconds: never five failures inside one minute. |
| `holdout-bruteforce-lockout` | attack | SSH_BRUTE_FORCE | 07:31:00 | auth_log | 198.51.100.77 tries 7 SSH passwords on bastion-01 until dave is locked out. |
