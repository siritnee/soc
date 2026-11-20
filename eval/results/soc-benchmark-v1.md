# Báo cáo đánh giá: soc-benchmark-v1

File này do lệnh `python -m eval.run --dataset data/benchmark --out eval/results` sinh ra. Không sửa tay: muốn có số mới thì chạy lại lệnh.

## 1. Dữ liệu đầu vào

- Khoảng thời gian (UTC): 2026-11-12T01:00:00.000000Z đến 2026-11-12T03:00:00.000000Z
- Seed của bộ sinh dữ liệu: 2026
- Tổng số sự kiện sau chuẩn hóa: **1138**

| Nguồn | Dòng đọc | Sự kiện | Dòng không liên quan | Dòng lỗi |
|---|---:|---:|---:|---:|
| auth_log | 233 | 82 | 149 | 2 |
| suricata | 788 | 780 | 6 | 2 |
| sysmon | 324 | 276 | 46 | 2 |

## 2. Giảm cảnh báo

**278 cảnh báo thô** được gom thành **9 incident**: giảm **96.8%**.

| Luật | Cảnh báo thô | Incident | Tỉ lệ giảm |
|---|---:|---:|---:|
| INTERNAL_PORT_SCAN | 232 | 2 | 99.1% |
| MALWARE_BEACONING | 35 | 1 | 97.1% |
| NETWORK_TO_HOST_PIVOT | 6 | 1 | 83.3% |
| SSH_BRUTE_FORCE | 2 | 2 | 0.0% |
| SUSPICIOUS_PROCESS | 3 | 3 | 0.0% |

Cảnh báo thô là một lần luật thỏa điều kiện, trước khi gộp. Tỉ lệ giảm = 1 - số incident / số cảnh báo thô.

## 3. So với ground truth

- Precision: **88.9%** (8 incident đúng / 9 incident)
- Recall: **100.0%** (8 / 8 kịch bản tấn công có luật tương ứng)
- F1: **94.1%**
- Incident báo nhầm (false positive): **1**
- Kịch bản vô hại bị báo: **1** / 7
- Tính trên mọi kịch bản tấn công, kể cả loại không luật nào được thiết kế để bắt: 8 / 9

### Kịch bản tấn công

| Kịch bản | Bắt đầu (UTC) | Nguồn log | Luật mong đợi | Phát hiện | Độ trễ (giây) |
|---|---|---|---|---|---:|
| `beaconing` | 01:10:00 | suricata | MALWARE_BEACONING | có | 290.2 |
| `ssh-bruteforce-login` | 01:25:00 | auth_log | SSH_BRUTE_FORCE | có | 44.0 |
| `portscan-network` | 01:40:00 | suricata | INTERNAL_PORT_SCAN | có | 1.4 |
| `ssh-bruteforce-gave-up` | 01:50:00 | auth_log | không có (ngoài phạm vi luật) | không | - |
| `process-temp` | 01:55:00 | sysmon | SUSPICIOUS_PROCESS | có | 0.0 |
| `process-encoded` | 02:05:00 | sysmon | SUSPICIOUS_PROCESS | có | 0.0 |
| `ssh-bruteforce-lockout` | 02:20:00 | auth_log | SSH_BRUTE_FORCE | có | 31.0 |
| `portscan-host` | 02:35:00 | sysmon | INTERNAL_PORT_SCAN | có | 2.4 |
| `pivot` | 02:45:00 | suricata, sysmon | NETWORK_TO_HOST_PIVOT | có | 45.0 |

### Kịch bản vô hại (trông giống tấn công)

| Kịch bản | Mô tả | Bị báo? |
|---|---|---|
| `decoy-typo-login` | alice mistypes the password 3 times on web-01, then logs in. Not an attack. | không |
| `decoy-irregular-alerts` | 8 alerts "LAB POLICY Cleartext HTTP to external site" from 10.0.2.22 to 192.0.2.80. Not an attack. | không |
| `decoy-slow-failures` | bob mistypes the password 6 times on db-01, then logs in. Not an attack. | không |
| `decoy-periodic-low-alerts` | 7 alerts "LAB INFO Software update check" from 10.0.1.10 to 192.0.2.81. Not an attack. | không |
| `decoy-appdata-program` | dave starts LabChat, a legitimate program installed under AppData, on WS-04. Not an attack. | SUSPICIOUS_PROCESS |
| `decoy-few-ports` | 10.0.2.10 connects to 10 different ports on 10.0.1.11 in about 20 seconds. Not an attack. | không |
| `decoy-slow-sweep` | 10.0.2.10 connects to 20 different ports on 10.0.1.10 in about 570 seconds. Not an attack. | không |

## 4. Độ trễ phát hiện

Tính trên 8 kịch bản được phát hiện: trung bình **51.8 giây**, trung vị **16.7 giây**, nhỏ nhất 0.0 giây, lớn nhất 290.2 giây.

Độ trễ = thời điểm luật báo lần đầu trừ thời điểm bắt đầu kịch bản, cả hai lấy từ timestamp của sự kiện (không phải giờ máy chạy phân tích).

## 5. Danh sách incident

| # | Luật | Mức | Đối tượng | Bắt đầu | Phát hiện | Kết thúc | Sự kiện | Cảnh báo thô | Kết luận |
|---:|---|---|---|---|---|---|---:|---:|---|
| 1 | MALWARE_BEACONING | high | 10.0.2.40->203.0.113.200 | 01:10:00 | 01:14:50 | 01:49:08 | 40 | 35 | đúng (`beaconing`) |
| 2 | SSH_BRUTE_FORCE | critical | 203.0.113.50 | 01:25:01 | 01:25:44 | 01:25:44 | 13 | 1 | đúng (`ssh-bruteforce-login`) |
| 3 | INTERNAL_PORT_SCAN | medium | 10.0.2.99->10.0.1.10 | 01:40:00 | 01:40:01 | 01:40:20 | 200 | 186 | đúng (`portscan-network`) |
| 4 | SUSPICIOUS_PROCESS | medium | WS-04.lab.example | 01:45:00 | 01:45:00 | 01:45:00 | 1 | 1 | BÁO NHẦM (`decoy-appdata-program`) |
| 5 | SUSPICIOUS_PROCESS | medium | WS-01.lab.example | 01:55:00 | 01:55:00 | 01:55:00 | 1 | 1 | đúng (`process-temp`) |
| 6 | SUSPICIOUS_PROCESS | high | WS-02.lab.example | 02:05:00 | 02:05:00 | 02:05:00 | 1 | 1 | đúng (`process-encoded`) |
| 7 | SSH_BRUTE_FORCE | high | 198.51.100.23 | 02:20:01 | 02:20:31 | 02:20:31 | 9 | 1 | đúng (`ssh-bruteforce-lockout`) |
| 8 | INTERNAL_PORT_SCAN | medium | 10.0.2.23->10.0.1.20 | 02:35:00 | 02:35:02 | 02:35:10 | 60 | 46 | đúng (`portscan-host`) |
| 9 | NETWORK_TO_HOST_PIVOT | critical | 10.0.2.24 | 02:45:00 | 02:45:45 | 02:53:15 | 7 | 6 | đúng (`pivot`) |

## 6. Cách đối chiếu

- Một sự kiện thuộc một kịch bản khi thời gian của nó nằm trong kịch bản và các trường trong `match` của ground truth khớp (ví dụ `src_ip` là IP kẻ tấn công).
- Một incident khớp một kịch bản khi có ít nhất một sự kiện của nó thuộc kịch bản đó.
- Incident đúng (true positive): khớp một kịch bản tấn công và đúng luật mong đợi. Mọi incident khác là báo nhầm.

## 7. Lưu ý khi đọc số liệu

- Đây là dữ liệu giả do chính nhóm sinh ra; người viết luật biết trước các kịch bản. Số liệu cho biết công cụ chạy đúng thiết kế, không cho biết nó sẽ tốt đến đâu trên log thật.
- Kịch bản tấn công ngoài phạm vi luật và kịch bản vô hại bị báo nhầm (nếu có) được giữ lại có chủ ý để thấy giới hạn của bộ luật.
- Flow của Suricata được ghi ra file chậm khoảng một phút so với lúc kết nối bắt đầu; độ trễ ở mục 4 tính theo thời điểm kết nối bắt đầu.
