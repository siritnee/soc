# GitHub Issues – copy từng mục vào tab Issues của repo soc

> Assignee: thay bằng GitHub username thực tế. Mỗi issue có acceptance criteria.

## Issue 1 [Leader] Khởi tạo cấu trúc, schema, DB
- Owner: Thành viên 1
- Branch: feature/leader-foundation
- Deliverables: folders, normalizer/schema.py, storage/models.py, pytest, PR template, CI workflow
- Done khi: tests pass, có 3 bảng, index timestamp_utc/src_ip, 8 keys schema; PR review rồi merge.

## Issue 2 [Ingest] Suricata + auth.log
- Owner: Thành viên 2
- Branch: feature/ingestors-linux-suricata
- Deliverables: ingestors/suricata.py, ingestors/auth_log.py; parse_file(Path) -> iterable canonical dict
- Done khi: parse alert / failed-success-lockout; lỗi timestamp/timezone được xử lý; parser unit tests pass.

## Issue 3 [Windows] Sysmon + 2 rule Windows
- Owner: Thành viên 3
- Branch: feature/sysmon-windows-rules
- Deliverables: ingestors/sysmon.py, engine/rules/windows.py; Event ID 1/3; suspicious process + pivot
- Done khi: 2 rule có test, mốc thời gian và cross-source IP match rõ ràng.

## Issue 4 [Engine] Correlation + Incident
- Owner: Thành viên 4
- Branch: feature/correlation-engine
- Deliverables: engine/correlation.py; Rule interface; SSH brute-force / port scan; dedup cooldown; incident summary
- Done khi: test 5 failures/60s+success; port scan 15 ports/30s; out-of-order logs; no duplicate incidents on rerun.

## Issue 5 [Dashboard/Evaluation] UI + benchmark
- Owner: Thành viên 5
- Branch: feature/ui-evaluation
- Deliverables: ui/dashboard.py, dataset with ground truth, eval scripts
- Done khi: timeline, filters, state changes, incident export, upload unseen log; actual metrics produced by scripts.

## Issue 6 [Leader] Tích hợp E2E và README
- Owner: Thành viên 1
- Branch: feature/pipeline-integration
- Deliverables: pipeline/CLI ingest, detect, dashboard, replay; E2E with real parsers and rules; README details
- Done khi: Suricata/Sysmon/auth.log ingest -> SQLite -> 4 rules -> incidents -> UI; screenshot/test logs and 1 demo script.
