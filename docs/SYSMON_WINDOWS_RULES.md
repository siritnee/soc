# Ingestor Sysmon và luật phía Windows (Thành viên 3)

## File
| File | Nội dung |
|---|---|
| `ingestors/sysmon.py` | Đọc file JSON đã export, đưa các kiểu bản ghi về một dạng |
| `normalizer/sysmon_mapper.py` | Event ID 1 và 3 → sự kiện chuẩn |
| `engine/rules/windows.py` | Luật 3 và luật 4, danh sách `RULES` |
| `datagen/sysmon.py` | Sinh log Sysmon nền, process đáng ngờ, port scan, kịch bản pivot |

## Ingestor
- File: mỗi dòng một object JSON, hoặc một mảng JSON (kiểu `ConvertTo-Json`). Chưa đọc trực tiếp `.evtx`.
- Kiểu bản ghi nhận được: phẳng (`EventID`, `Computer`, `UtcTime`...), `evtx_dump` (`Event.System`, `Event.EventData`),
  winlogbeat (`winlog.event_data`), và `Get-WinEvent` của PowerShell (đọc các dòng `Key: Value` trong `Message`).
- Event ID 1 → `process_create` (`process_name` là đường dẫn đầy đủ của `Image`, `command_line`, `username`, `hostname`).
- Event ID 3 → `network_connection` (`src_ip`, `dst_ip`, `dst_port`).
- Event ID khác: bỏ qua và đếm trong `ignored`.
- Thời gian: `UtcTime` của Sysmon không ghi múi giờ nhưng luôn là UTC. Thiếu `UtcTime` thì dùng thời gian hệ thống
  của bản ghi (ISO, kể cả 7 chữ số thập phân, hoặc `/Date(...)/` của PowerShell 5).

## Luật 3 – Suspicious Process Execution (`SUSPICIOUS_PROCESS`, T1059.001)
Báo khi một sự kiện `process_create` thỏa một trong hai điều kiện:
- Đường dẫn chương trình có thư mục `\AppData\` hoặc `\Temp\` (không phân biệt hoa thường), trừ các chương trình
  trong allowlist (mặc định: OneDrive, Teams). Severity medium.
- PowerShell được gọi với cờ lệnh mã hóa: `-enc`, `-EncodedCommand`, `-e`, `-ec` và mọi cách viết tắt hợp lệ,
  kể cả khi nằm trong dòng lệnh của chương trình khác (`cmd /c powershell -enc ...`). Severity high.

Gộp theo máy (`hostname`). Phần mềm hợp lệ cài dưới AppData mà chưa có trong allowlist sẽ bị báo; benchmark giữ
một trường hợp như vậy để thấy giới hạn này.

## Luật 4 – Network-to-Host Pivot (`NETWORK_TO_HOST_PIVOT`, T1021)
1. Suricata có alert mức `high` trở lên: ghi nhớ cả IP nguồn và IP đích của alert cùng thời điểm alert.
2. Trong 600 giây sau đó, Sysmon (Event ID 3) ghi một kết nối có IP nguồn là một trong các IP đã nhớ và IP đích là
   máy nội bộ khác → alert mức critical.

Mốc thời gian: kết nối trước alert không tính; đúng 600 giây vẫn tính, 601 giây thì không; alert mới của cùng IP
làm cửa sổ tính lại từ đầu. Khóa nối hai nguồn log là địa chỉ IP. Mạng nội bộ là 10/8, 172.16/12, 192.168/16
(các dải IP tài liệu đóng vai Internet).

## Generator
```powershell
python -m datagen.sysmon --out sysmon.json --seed 1 --minutes 60
```
`pivot()` sinh kịch bản xuyên hai nguồn: một alert Suricata và các kết nối Sysmon sau đó.

## Chạy test
```powershell
python -m pytest -q tests/test_ingest_sysmon.py tests/test_rules_windows.py tests/test_datagen_sysmon.py
```
