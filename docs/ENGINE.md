# Correlation engine và incident (Thành viên 4)

## File
| File | Nội dung |
|---|---|
| `engine/correlation.py` | `SlidingWindow`, interface `Rule`, `Alert`, `Incident`, `CorrelationEngine`, `detect_incidents()`, `detect_with_stats()` |
| `engine/net.py` | `is_internal(ip)`: IP có thuộc mạng nội bộ không |
| `engine/rules/ssh_brute_force.py` | Luật 1 |
| `engine/rules/port_scan.py` | Luật 2 |
| `engine/rules/beaconing.py` | Luật 5 (bổ sung) |
| `engine/incident.py` | Lưu không trùng, đọc incident, xuất tóm tắt điều tra |

## Engine chạy thế nào
1. Sắp xếp sự kiện theo `timestamp_utc` (trùng thời gian thì theo `id`), nên log đến sai thứ tự vẫn đúng.
2. Đưa từng sự kiện qua từng luật; luật trả về các `Alert` (cảnh báo thô).
3. Alert cùng `(rule_id, key)` và cách `last_seen` của incident đang mở không quá cooldown thì gộp vào;
   xa hơn thì mở incident mới. Cooldown mặc định 300 giây; luật có thể đặt `cooldown_seconds` riêng.
4. Mọi phép so thời gian dùng thời gian trong sự kiện, không dùng đồng hồ máy.

## Cửa sổ trượt
`SlidingWindow(N)` giữ các mục cách mục mới nhất không quá N giây, tính cả biên: mục bị loại khi
`mới nhất - nó > N`. Với N = 60: giây 0 và giây 60 cùng cửa sổ; giây 0 và giây 61 thì không.

## Các luật trong file này
| Luật | Điều kiện | Gộp theo | Severity | Tham số |
|---|---|---|---|---|
| `SSH_BRUTE_FORCE` | ≥ 5 `ssh_failed` trong 60 giây, rồi `ssh_success` hoặc `ssh_lockout`, cùng `src_ip` | `src_ip` | thành công: critical; khóa: high | `threshold`, `window_seconds`, `follow_seconds` |
| `INTERNAL_PORT_SCAN` | ≥ 15 `dst_port` khác nhau, cùng `src_ip` và `dst_ip`, trong 30 giây | cặp IP | medium | `threshold`, `window_seconds`, `actions`, `internal_only` |
| `MALWARE_BEACONING` | 6 alert gần nhất cùng nguồn, đích, signature cách nhau đều (lệch ≤ 30% so với trung vị, trung vị ≥ 5 giây), trong 1 giờ | cặp IP | high | `threshold`, `window_seconds`, `tolerance`, `min_severity` |

Ghi chú:
- Luật 1: lần thành công hoặc khóa phải đến trong 60 giây sau lần thất bại cuối. Đăng nhập thành công xóa bộ đếm
  thất bại của IP đó (người gõ sai 3 lần, vào được, sai 2 lần nữa không bị báo). Brute force không có thành công
  hay khóa thì không tạo incident: đúng định nghĩa của đề bài.
- Luật 2 đếm sự kiện `network_connection` (Sysmon) và `flow` (Suricata).
- Luật 5 không nằm trong 4 luật bắt buộc; có vì benchmark phải có kịch bản beaconing.

## Thêm luật mới
```python
from engine.correlation import Alert, Rule

class MyRule(Rule):
    rule_id = "MY_RULE"; title = "..."; mitre = "T...."
    def reset(self): ...                       # xóa trạng thái trước mỗi lần chạy
    def process(self, event, ts):              # gọi cho từng sự kiện, theo thứ tự thời gian
        return [Alert(rule_id=self.rule_id, key="...", title=self.title, severity="high",
                      first_seen=ts, last_seen=ts, event_ids=[event["id"]], summary="...")]
```
Luật phía Windows khai báo trong `RULES` của `engine/rules/windows.py`; engine tự nạp.

## Incident
- `detect_incidents(events)` trả dict theo contract, thêm `detected_at_utc` (lúc luật báo lần đầu), `dedup_key`,
  `mitre`, `raw_alert_count`.
- `detect_with_stats(events)` trả thêm `raw_alerts`, `incidents`, `dedup_savings = 1 - incidents/raw_alerts`, `by_rule`.
- `save_new_incidents(conn, incidents)`: bỏ qua incident cùng luật đã lưu mà có chung sự kiện; chạy lại không tạo trùng,
  không ghi đè trạng thái. Hạn chế: incident đã lưu không được bổ sung sự kiện mới.
- `export_summary_from_db(conn, incident_id)`: tóm tắt điều tra dạng Markdown (luật, MITRE, thời gian, IP/user/host,
  số sự kiện theo loại, timeline đầu và cuối, gợi ý bước tiếp theo).

## Chạy test
```powershell
python -m pytest -q tests/test_correlation.py
```
