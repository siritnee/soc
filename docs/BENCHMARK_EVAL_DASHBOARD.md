# Benchmark, đánh giá và dashboard (Thành viên 5)

## File
| File | Nội dung |
|---|---|
| `datagen/benchmark.py` | Lắp benchmark và log để dành từ các generator |
| `data/benchmark/` | `auth.log`, `eve.json`, `sysmon.json`, `ground_truth.json`, `manifest.json`, `README.md` |
| `data/holdout/` | Log brute-force để tập bảo vệ; không dùng khi chỉnh luật |
| `eval/dataset.py` | Đọc thư mục dữ liệu, gọi đúng ingestor |
| `eval/metrics.py` | Công thức precision, recall, độ trễ, tỉ lệ giảm cảnh báo |
| `eval/run.py` | Chạy toàn bộ và sinh báo cáo |
| `eval/results/` | Báo cáo và số liệu do chương trình sinh ra |
| `ui/data.py`, `ui/dashboard.py` | Truy vấn database và giao diện Streamlit |

## Benchmark
```powershell
python -m datagen.benchmark --out data/benchmark --holdout data/holdout
```
Hai giờ hoạt động (08:00–10:00 giờ lab, tức 01:00–03:00 UTC) gồm log nền, 8 kịch bản tấn công có luật tương ứng,
1 kịch bản tấn công ngoài phạm vi luật (brute force bỏ cuộc), 7 kịch bản vô hại trông giống tấn công, và 6 dòng hỏng
cố ý. Cùng seed luôn cho cùng file; test sẽ báo nếu file trong repo khác file sinh lại.

`ground_truth.json`: mỗi kịch bản có `start_utc`, `end_utc`, `match` (trường → giá trị, ví dụ `src_ip` là IP tấn công),
`expected_rule`, `malicious`.

## Đánh giá
```powershell
python -m eval.run --dataset data/benchmark --out eval/results
```
- Incident đúng: có sự kiện thuộc một kịch bản tấn công và đúng luật mong đợi. Còn lại là báo nhầm.
- Precision = incident đúng / tổng incident. Recall = kịch bản tìm thấy / kịch bản tấn công có luật tương ứng.
- Độ trễ = lúc luật báo lần đầu − lúc kịch bản bắt đầu (theo thời gian sự kiện).
- Tỉ lệ giảm = 1 − số incident / số cảnh báo thô.

Số liệu chỉ lấy từ file do lệnh trên sinh ra. Log để dành chạy bằng
`python -m eval.run --dataset data/holdout --out eval/results` khi tập bảo vệ.

## Dashboard
```powershell
python -m pipeline --db data/demo.db dashboard
```
| Tab | Chức năng |
|---|---|
| Tổng quan | Tổng sự kiện, incident đang mở, timeline incident, thiết bị bị tấn công nhiều nhất |
| Incident | Lọc, xem chi tiết, đổi trạng thái và analyst, tải tóm tắt điều tra |
| Tìm kiếm log | Lọc theo IP (gõ `10.0.2.` để tìm cả dải), thời gian, mức độ, nguồn, hành động, từ khóa |
| Phân tích log mới | Tải file log lên, lưu vào database, chạy luật, hiện incident mới |

"Thiết bị bị tấn công" là máy nội bộ: IP đích nội bộ; nếu không có thì máy ghi log; nếu không thì IP nguồn nội bộ.
Thời gian hiển thị theo UTC. Nạp cùng một file hai lần sẽ nhân đôi sự kiện; dashboard cảnh báo trong cùng phiên.

## Chạy test
```powershell
python -m pytest -q tests/test_eval.py tests/test_dashboard.py
```
