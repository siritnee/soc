# Ingestor auth.log và Suricata, generator log giả (Thành viên 2)

## File
| File | Nội dung |
|---|---|
| `ingestors/base.py` | Bộ đếm thống kê dùng chung, đọc file an toàn (BOM, UTF-16) |
| `ingestors/auth_log.py` | Tách dòng syslog, quy ước năm và múi giờ, dòng lặp |
| `normalizer/auth_log_mapper.py` | Ý nghĩa từng thông điệp sshd/sudo → sự kiện chuẩn |
| `ingestors/suricata.py` | Đọc EVE JSON từng dòng |
| `normalizer/suricata_mapper.py` | Bản ghi EVE → sự kiện chuẩn |
| `datagen/common.py` | `Rng` có seed, sơ đồ mạng lab, `Label`, `LogBundle` |
| `datagen/auth_log.py`, `datagen/suricata.py` | Sinh log nền và kịch bản tấn công có nhãn |

## Giao diện
```python
stats = {}
events = list(parse_file(path, stats))            # auth.log: thêm year=2026, tz="+07:00"
# stats = {"lines": 233, "events": 82, "ignored": 149, "invalid": 2, "reasons": {...}}
```
`lines` dòng đọc được; `events` sự kiện tạo ra; `ignored` dòng hợp lệ nhưng không dùng (cron, session...);
`invalid` dòng hỏng; `reasons` lý do và số dòng. Dòng hỏng không làm dừng việc đọc.

## Quy ước thời gian của auth.log
Dòng syslog kiểu `Nov 12 08:40:03 web-01 sshd[3001]: ...` không có năm và múi giờ.
- Múi giờ: tham số `tz`, rồi biến môi trường `SOC_AUTH_LOG_TZ`, mặc định `+07:00`.
- Năm của dòng đầu: tham số `year`, rồi `SOC_AUTH_LOG_YEAR`, nếu không có thì lấy năm hiện tại (lùi một năm nếu
  kết quả nằm ở tương lai quá một ngày).
- Các dòng sau được gán năm sao cho gần dòng trước nhất, nên file chạy qua giao thừa vẫn đúng.
- Dòng có timestamp ISO đầy đủ (định dạng mới của rsyslog) giữ múi giờ gốc khi chuẩn hóa,
  **đồng thời cập nhật năm/mốc thời gian tham chiếu theo múi giờ cấu hình** để dòng syslog cổ điển đi sau
  không bị gán sai năm khi trộn hai định dạng.
- Offset giờ cố định hỗ trợ `UTC`, `Z`, `+07`, `+0700`, `+07:00`; giá trị phút từ 60 trở lên bị từ chối.
- Mọi thời gian được đổi sang UTC khi qua `normalize_event`.

## Các bẫy đã xử lý
| Bẫy | Cách xử lý |
|---|---|
| "Invalid user" và "Failed password for invalid user" là hai dòng của một lần thử | Chỉ dòng sau là `ssh_failed` |
| `message repeated 3 times: [ ... ]` | Tách thành 3 sự kiện |
| Dòng khóa tài khoản (pam_faillock, pam_tally2) không có IP | Chỉ mượn IP nguồn của **cùng host / cùng PID với user tương thích**, hoặc **cùng host / cùng username** trong **5 phút trước đó theo timestamp sự kiện**, kể cả đúng mốc 5 phút; quá hạn/không đủ căn cứ thì `src_ip=None` |
| "Failed publickey" | Không tính là sai mật khẩu |
| sudo thất bại, sudo bị từ chối nhưng không có `COMMAND=` | Xuất `sudo_failed`/`sudo_denied` với `command_line=None`; bao gồm PAM `pam_unix(sudo:auth): authentication failure` |
| sshd in tên máy thay cho IP | Giữ sự kiện, `src_ip` để trống |
| Timestamp Suricata dạng `+0700` | Đọc được cả `+0700`, `+07:00`, `Z` |
| Flow của Suricata ghi ra file muộn khoảng một phút | Dùng `flow.start` làm thời gian sự kiện |
| File có BOM hoặc UTF-16 (xuất từ Windows), byte hỏng | Tự nhận mã hóa; byte hỏng không làm dừng |

## Bảng `action`
| Nguồn | `action` (severity) |
|---|---|
| auth_log | `ssh_failed` (medium), `ssh_success` (info), `ssh_invalid_user` (low), `ssh_lockout` (high), `ssh_max_auth_exceeded` (medium), `sudo_command` (info), `sudo_failed` (medium), `sudo_denied` (medium) |
| suricata | `alert` (ưu tiên 1→high, 2→medium, 3→low, khác→info), `flow`, `dns_query`, `http_request` (info) |

## Generator
```powershell
python -m datagen.auth_log --out auth.log --seed 1 --minutes 60
python -m datagen.suricata --out eve.json --seed 1 --minutes 60
```
Cùng seed cho cùng file trên mọi máy (chỉ dùng `random.Random.random()`). Mỗi kịch bản trả về một `Label`:
thời gian bắt đầu, kết thúc, trường `match`, luật mong đợi. Chỉ dùng IP 10.x và các dải tài liệu.

## Chạy test
```powershell
python -m pytest -q tests/test_ingest_auth_log.py tests/test_ingest_suricata.py tests/test_datagen_auth_suricata.py
```

## Kiểm thử hồi quy (bản sửa 4 vấn đề)
- `tests/test_ingest_auth_log.py` có thêm test bảo vệ 4 thay đổi: IP lockout cũ/khác user/thiếu PID/đến lệch thứ tự; ISO + syslog qua năm; múi giờ có phút sai; sudo không có COMMAND.
- `python -m pytest -q` trên bản ghép với repo nền tảng 12/11/2026: **108 passed, 2 skipped** (2 test cần `engine.correlation` của Thành viên 4).
- Với generator `--seed 1 --minutes 10`, ingest qua CLI nền tảng: **17 auth events + 178 Suricata events = 195 events**. Đó là dữ liệu giả lập, không phải kết quả phát hiện incident hay benchmark precision/recall.

### Lưu ý tích hợp
- `ssh_lockout` thiếu IP hợp lệ sẽ có `src_ip=None` để tránh dựng nhầm chuỗi brute-force. Quy tắc 5 phút là **quy ước an toàn cho dữ liệu mô phỏng** cần xác nhận với Thành viên 4; không phải bằng chứng duy nhất xác định nguồn tấn công.
- Action `flow` của Suricata phải được Thành viên 4 dùng nhất quán cho luật `INTERNAL_PORT_SCAN`. Nếu muốn đổi tên thành `network_connection`, cần thống nhất và cập nhật test của cả nhóm trước.
- Nhãn `MALWARE_BEACONING` xuất hiện trong dữ liệu của generator nhưng không thuộc bốn luật bắt buộc của đề; Thành viên 5 phải thống nhất cách tính benchmark để không tính sai recall.
