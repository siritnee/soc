# SOC – contract chung của nhóm

## 1. Schema `normalizer/schema.py`
- Mỗi ingestor phải tạo dict với **đủ tám KEY**: `timestamp_utc`, `source_type`, `src_ip`, `dst_ip`, `username`, `hostname`, `action`, `severity`.
- Nguồn: `suricata`, `sysmon`, `auth_log`.
- `timestamp_utc`: ISO 8601 có timezone; ví dụ `2026-11-12T02:00:00.000000Z`.
- `src_ip`, `dst_ip`, `username`, `hostname` được phép `null` nếu nguồn không có dữ liệu.
- `severity`: `info`, `low`, `medium`, `high`, `critical`.
- `action`: chuỗi có nghĩa, nhóm phải thống nhất tên (ví dụ `ssh_failed`, `ssh_success`, `ssh_lockout`, `alert`, `process_create`, `network_connection`).
- Trường phụ: `dst_port`, `process_name`, `command_line`, `signature`, `raw`.
- Gọi `normalize_event(mapped_raw)` để kiểm tra và trả về dict chuẩn.

## 2. Thành viên 2–3: các ingestor
Tạo:
- `ingestors/suricata.py`: `parse_file(path: pathlib.Path) -> Iterable[dict]`
- `ingestors/auth_log.py`: `parse_file(path: pathlib.Path) -> Iterable[dict]`
- `ingestors/sysmon.py`: `parse_file(path: pathlib.Path) -> Iterable[dict]`

Mỗi dict trả về **phải tuân thủ schema ở trên**. Parser nên thống kê dòng lỗi và định nghĩa quy tắc bỏ qua dòng không hợp lệ; giao diện bổ sung phải thống nhất trước khi merge.

## 3. Thành viên 4: correlation engine
`engine/correlation.py` cần export:
```python
def detect_incidents(events: list[dict]) -> list[dict]:
    # events đã sắp xếp tăng theo timestamp_utc, có khóa id
    # return các incident dictionary
    ...
```
Ví dụ một incident:
```python
{
  "rule_id": "SSH_BRUTE_FORCE",
  "title": "SSH brute-force detected",
  "severity": "high",
  "status": "New",
  "assigned_analyst": None,
  "first_seen_utc": "2026-11-12T02:00:00.000000Z",
  "last_seen_utc": "2026-11-12T02:00:59.000000Z",
  "summary": "Synthetic scenario",
  "event_ids": [1,2,3,4,5,6]
}
```
- Đảm bảo engine kiểm tra 4 luật của đề bài (không thay thế bằng 1 luật demo).
- Cần thống nhất chính sách chống tạo incident trùng khi chạy lại `detect`.

## 4. Thành viên 5: UI / evaluation
- `ui/dashboard.py` đọc db từ `os.environ.get("SOC_DB_PATH", "data/soc.db")`.
- Bảng: `events`, `incidents`, `incident_events` từ `storage/models.py`.
- Evaluation nhận benchmark có nhãn; không tự gán precision/recall từ dữ liệu demo.
- Dashboard dùng API storage hoặc SQLite connection có foreign keys enabled.

## 5. Lệnh chạy của trưởng nhóm
```powershell
python -m pipeline --db data/soc.db init-db
python -m pipeline --db data/soc.db ingest --source normalized --file data/examples/normalized.jsonl
python -m pipeline --db data/soc.db ingest --source suricata --file data/suricata/eve.json
python -m pipeline --db data/soc.db detect
python -m pipeline --db data/soc.db dashboard
python -m pipeline replay --dataset data/examples/normalized.jsonl
```
`detect` và `replay` sẽ thông báo **engine chưa tích hợp** cho tới khi Thành viên 4 merge code thật.

## 6. Git / PR
- Mỗi người tạo branch `feature/*` hoặc `fix/*`.
- Không push thẳng `main`.
- Mỗi PR: mô tả issue, ảnh/test output, review chéo, rồi mới merge.
