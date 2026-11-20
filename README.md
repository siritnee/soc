
# Multi-Source SOC Analyst Toolkit

A multi-source Security Operations Center (SOC) analyst toolkit for
offline security log analysis, incident detection, investigation,
and visualization.

GitHub: https://github.com/siritnee/soc

## 1. Project Overview

The toolkit processes three security log sources:

- Suricata EVE JSON: network security events
- Windows Sysmon JSON: Windows host activity
- Linux auth.log: SSH authentication events

Processing pipeline:

Raw Logs
  -> Ingestors
  -> Normalized Events
  -> SQLite Database
  -> Correlation Engine
  -> Security Incidents
  -> Streamlit Dashboard

The application supports incident triage, status management,
analyst assignment, incident timelines, log searching, and
investigation report export.

## 2. Technologies

- Python 3.11+
- SQLite
- Streamlit
- Pytest
- Suricata EVE JSON
- Windows Sysmon
- Linux auth.log

## 3. Project Structure

```text
soc/
├── ingestors/        # Raw security log parsers
├── normalizer/       # Shared canonical event schema
├── storage/          # SQLite database operations
├── engine/           # Correlation engine and detection rules
│   └── rules/
├── pipeline/         # Command-line interface
├── ui/               # Streamlit dashboard
├── datagen/          # Synthetic log generators
├── data/
│   ├── benchmark/    # Three-source benchmark dataset
│   ├── holdout/      # Separate SSH test dataset
│   └── examples/     # Normalized sample events
├── eval/             # Evaluation and reporting
├── tests/            # Automated tests
├── docs/             # Technical documentation
├── requirements.txt
└── README.md
```

## 4. Installation (Windows PowerShell)

Clone the repository:

```powershell
git clone https://github.com/siritnee/soc.git
cd soc
```

Create a Python virtual environment:

```powershell
py -m venv .venv
```

Install dependencies:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Commands below assume the current directory is the repository root.

PowerShell script activation is not required. Use the Python
executable inside `.venv` directly.

## 5. Running the SOC Pipeline

### 5.1 Initialize SQLite

```powershell
.\.venv\Scripts\python.exe -m pipeline --db data/demo.db init-db
```

### 5.2 Configure Linux Authentication Log Time

```powershell
$env:SOC_AUTH_LOG_YEAR = "2026"
$env:SOC_AUTH_LOG_TZ = "+07:00"
```

### 5.3 Ingest Linux auth.log

```powershell
.\.venv\Scripts\python.exe -m pipeline --db data/demo.db ingest --source auth_log --file data/benchmark/auth.log
```

### 5.4 Ingest Suricata EVE JSON

```powershell
.\.venv\Scripts\python.exe -m pipeline --db data/demo.db ingest --source suricata --file data/benchmark/eve.json
```

### 5.5 Ingest Windows Sysmon JSON

```powershell
.\.venv\Scripts\python.exe -m pipeline --db data/demo.db ingest --source sysmon --file data/benchmark/sysmon.json
```

Expected event counts from the benchmark:

| Source | Events |
|---|---:|
| Linux auth.log | 82 |
| Suricata | 780 |
| Sysmon | 276 |
| **Total** | **1,138** |

### 5.6 Detect Security Incidents

```powershell
.\.venv\Scripts\python.exe -m pipeline --db data/demo.db detect
```

Expected result for a fresh benchmark database:

```text
Detected and saved 9 incident(s)
```

Running the same detection again should produce:

```text
Detected and saved 0 incident(s)
```

The pipeline uses incident deduplication to prevent saving
duplicate incidents from unchanged events.

### 5.7 Launch Dashboard

```powershell
.\.venv\Scripts\python.exe -m pipeline --db data/demo.db dashboard
```

Open:

http://localhost:8501

Keep the Streamlit terminal running while using the dashboard.

## 6. Detection Rules

The correlation engine implements five rules:

| Rule ID | Description |
|---|---|
| SSH_BRUTE_FORCE | Repeated SSH failures followed by successful login or account lockout |
| INTERNAL_PORT_SCAN | Multiple destination ports scanned within a short interval |
| SUSPICIOUS_PROCESS | Suspicious Windows process execution or encoded PowerShell |
| NETWORK_TO_HOST_PIVOT | Correlation between a Suricata alert and subsequent Sysmon host activity |
| MALWARE_BEACONING | Repeated periodic network communications |

Rules generate security incidents that can be reviewed
and managed in the Dashboard.

## 7. Streamlit Dashboard

The Dashboard contains four main tabs:

1. Overview
   - Event and incident statistics
   - Incident timeline
   - Frequently targeted hosts

2. Incidents
   - Incident details and related events
   - Status management: New, In Progress, Closed
   - Analyst assignment
   - Markdown investigation summary export

3. Log Search
   - Search security events
   - Filter by source, IP, time, action, and severity

4. New Log Analysis
   - Upload a new security log
   - Parse and normalize events
   - Save events to SQLite
   - Detect new incidents

## 8. Benchmark Evaluation

Run the three-source benchmark:

```powershell
.\.venv\Scripts\python.exe -m eval.run --dataset data/benchmark --out eval/demo_results
```

Results reproduced on the benchmark dataset:

| Metric | Value |
|---|---:|
| Normalized events | 1,138 |
| Raw alerts | 278 |
| Correlated incidents | 9 |
| Alert reduction | 96.8% |
| Precision | 88.9% |
| Recall (in-scope attacks) | 100% |
| False-positive incidents | 1 |
| Mean event-time detection latency | 51.755 seconds |

Evaluation compares incidents with `ground_truth.json`.

Precision measures the proportion of reported incidents
classified as true positives.

Recall measures detected attack scenarios that have a
corresponding implemented detection rule.

Mean detection latency is based on log event timestamps,
not actual wall-clock processing time.

All benchmark data is synthetic. These results demonstrate
behavior on the supplied scenarios, not guaranteed detection
performance in production environments.

## 9. Holdout Demonstration

A separate dataset is available in:

```text
data/holdout/auth.log
```

For a live demonstration:

1. Open the Dashboard.
2. Select the New Log Analysis tab.
3. Upload `data/holdout/auth.log`.
4. Select the Linux auth.log source.
5. Use year 2026 and time zone +07:00.
6. Start analysis.
7. Inspect newly detected SSH incidents.
8. Open an incident and assign an analyst.
9. Change its status to In Progress.
10. Export the incident investigation summary.

The holdout dataset is intended for demonstrating
detection on separately prepared events.

## 10. Replay Mode

The CLI also supports replay of normalized JSONL events:

```powershell
.\.venv\Scripts\python.exe -m pipeline replay --dataset data/examples/normalized.jsonl
```

Replay creates a temporary isolated SQLite database,
ingests normalized events, runs detection, and prints counts.

Replay does not use the three raw benchmark log files
directly and does not modify the regular Dashboard database.

Use `eval.run` for complete three-source benchmark evaluation.

## 11. Automated Testing

Run all tests:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

Verified local result on November 20, 2026:

```text
289 passed
```

Run only the end-to-end integration test:

```powershell
.\.venv\Scripts\python.exe -m pytest tests/test_pipeline_e2e.py -v
```

The end-to-end test validates:

- Ingestion from all three benchmark log sources
- SQLite event persistence
- Correlation and incident creation
- Incident deduplication across repeated detection runs
- Preservation of incident status and analyst assignment

## 12. Team Responsibilities

- Member 1: Shared schema, database, CLI pipeline,
  end-to-end integration, documentation, and coordination
- Member 2: Suricata and Linux auth.log ingestion
- Member 3: Sysmon ingestion and Windows detection rules
- Member 4: Correlation engine and incident management
- Member 5: Dashboard, benchmark dataset, and evaluation

## 13. Known Limitations

- The benchmark uses synthetic security logs.
- Some legitimate behavior may trigger false positives.
- Recall is reported for attacks covered by implemented rules.
- Uploading the same raw file repeatedly may duplicate events.
- Replay supports normalized JSONL rather than the raw
  three-source benchmark directory.
- Detection and correlation operate offline, not as a
  production real-time SOC monitoring service.

## 14. References

- Suricata EVE JSON:
  https://docs.suricata.io/en/latest/output/eve/eve-json-format.html

- Microsoft Sysmon:
  https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

- MITRE ATT&CK:
  https://attack.mitre.org/
