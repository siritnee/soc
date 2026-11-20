"""Run the whole toolkit on a data set and write the evaluation report.

    python -m eval.run --dataset data/benchmark --out eval/results

Every number in the report comes from this run: the log files are parsed by
the real ingestors, stored in SQLite, correlated by the real engine and then
compared with ground_truth.json.
"""
from __future__ import annotations

import json
from contextlib import closing
from pathlib import Path
from typing import Any, Sequence

from engine.correlation import detect_with_stats
from eval.dataset import ingest_dataset, load_ground_truth, load_manifest
from eval.metrics import score
from storage.models import connect, init_db, list_events


def evaluate_dataset(dataset_dir: Path) -> dict[str, Any]:
    """Ingest, detect and score one data set. Nothing is written to disk."""
    dataset_dir = Path(dataset_dir)
    manifest = load_manifest(dataset_dir)
    with closing(connect(":memory:")) as conn:
        init_db(conn)
        ingest = ingest_dataset(conn, dataset_dir)
        events = list_events(conn)
    incidents, engine_stats = detect_with_stats(events)
    result = score(incidents, events, load_ground_truth(dataset_dir), engine_stats)
    result = {
        "dataset": manifest["name"], "seed": manifest.get("seed"),
        "start_utc": manifest.get("start_utc"), "end_utc": manifest.get("end_utc"),
        "events": len(events),
        "ingest": {source: {key: stats[key] for key in ("lines", "events", "ignored", "invalid")}
                   for source, stats in ingest.items()},
        **result,
    }
    return result


# ---- report -------------------------------------------------------------------

def _percent(value: float | None) -> str:
    return "không tính được" if value is None else f"{value * 100:.1f}%"


def _seconds(value: float | None) -> str:
    return "-" if value is None else f"{value:.1f}"


def _clock(text: str | None) -> str:
    return text[11:19] if text else "-"


def render_report(result: dict[str, Any], command: str) -> str:
    """The evaluation report as Markdown (Vietnamese)."""
    reduction, detection, latency = result["alert_reduction"], result["detection"], result["latency_seconds"]
    lines = [
        f"# Báo cáo đánh giá: {result['dataset']}",
        "",
        f"File này do lệnh `{command}` sinh ra. Không sửa tay: muốn có số mới thì chạy lại lệnh.",
        "",
        "## 1. Dữ liệu đầu vào",
        "",
        f"- Khoảng thời gian (UTC): {result['start_utc']} đến {result['end_utc']}",
        f"- Seed của bộ sinh dữ liệu: {result['seed']}",
        f"- Tổng số sự kiện sau chuẩn hóa: **{result['events']}**",
        "",
        "| Nguồn | Dòng đọc | Sự kiện | Dòng không liên quan | Dòng lỗi |",
        "|---|---:|---:|---:|---:|",
    ]
    for source, stats in result["ingest"].items():
        lines.append(f"| {source} | {stats['lines']} | {stats['events']} | {stats['ignored']} | {stats['invalid']} |")
    lines += [
        "",
        "## 2. Giảm cảnh báo",
        "",
        f"**{reduction['raw_alerts']} cảnh báo thô** được gom thành **{reduction['incidents']} incident**: "
        f"giảm **{_percent(reduction['reduction'])}**.",
        "",
        "| Luật | Cảnh báo thô | Incident | Tỉ lệ giảm |",
        "|---|---:|---:|---:|",
    ]
    for rule_id, counts in reduction["by_rule"].items():
        lines.append(f"| {rule_id} | {counts['raw_alerts']} | {counts['incidents']} | {_percent(counts['reduction'])} |")
    lines += [
        "",
        "Cảnh báo thô là một lần luật thỏa điều kiện, trước khi gộp. Tỉ lệ giảm = 1 - số incident / số cảnh báo thô.",
        "",
        "## 3. So với ground truth",
        "",
        f"- Precision: **{_percent(detection['precision'])}** "
        f"({detection['true_positives']} incident đúng / {detection['incidents']} incident)",
        f"- Recall: **{_percent(detection['recall'])}** "
        f"({detection['attacks_found']} / {detection['attacks_with_a_rule']} kịch bản tấn công có luật tương ứng)",
        f"- F1: **{_percent(detection['f1'])}**",
        f"- Incident báo nhầm (false positive): **{detection['false_positives']}**",
        f"- Kịch bản vô hại bị báo: **{detection['harmless_scenarios_flagged']}** / {detection['harmless_scenarios']}",
        f"- Tính trên mọi kịch bản tấn công, kể cả loại không luật nào được thiết kế để bắt: "
        f"{detection['all_attacks_found']} / {detection['all_attacks']}",
        "",
        "### Kịch bản tấn công",
        "",
        "| Kịch bản | Bắt đầu (UTC) | Nguồn log | Luật mong đợi | Phát hiện | Độ trễ (giây) |",
        "|---|---|---|---|---|---:|",
    ]
    for row in result["scenarios"]:
        if row["malicious"]:
            expected = row["expected_rule"] or "không có (ngoài phạm vi luật)"
            lines.append(f"| `{row['scenario_id']}` | {_clock(row['start_utc'])} | {', '.join(row['sources'])} | "
                         f"{expected} | {'có' if row['detected'] else 'không'} | {_seconds(row['latency_seconds'])} |")
    lines += ["", "### Kịch bản vô hại (trông giống tấn công)", "",
              "| Kịch bản | Mô tả | Bị báo? |", "|---|---|---|"]
    for row in result["scenarios"]:
        if not row["malicious"]:
            flagged = ", ".join(row["incident_rules"]) if row["incident_rules"] else "không"
            lines.append(f"| `{row['scenario_id']}` | {row['description']} | {flagged} |")
    lines += [
        "",
        "## 4. Độ trễ phát hiện",
        "",
        f"Tính trên {latency['count']} kịch bản được phát hiện: trung bình **{_seconds(latency['mean'])} giây**, "
        f"trung vị **{_seconds(latency['median'])} giây**, nhỏ nhất {_seconds(latency['min'])} giây, "
        f"lớn nhất {_seconds(latency['max'])} giây.",
        "",
        "Độ trễ = thời điểm luật báo lần đầu trừ thời điểm bắt đầu kịch bản, cả hai lấy từ timestamp của sự kiện "
        "(không phải giờ máy chạy phân tích).",
        "",
        "## 5. Danh sách incident",
        "",
        "| # | Luật | Mức | Đối tượng | Bắt đầu | Phát hiện | Kết thúc | Sự kiện | Cảnh báo thô | Kết luận |",
        "|---:|---|---|---|---|---|---|---:|---:|---|",
    ]
    for number, row in enumerate(result["incidents"], start=1):
        subject = (row["dedup_key"] or "").split("|", 1)[-1]
        verdict = "đúng" if row["verdict"] == "true_positive" else "BÁO NHẦM"
        scenario = f" (`{row['scenarios'][0]}`)" if row["scenarios"] else ""
        lines.append(f"| {number} | {row['rule_id']} | {row['severity']} | {subject} | {_clock(row['first_seen_utc'])} | "
                     f"{_clock(row['detected_at_utc'])} | {_clock(row['last_seen_utc'])} | {row['events']} | "
                     f"{row['raw_alerts']} | {verdict}{scenario} |")
    lines += [
        "",
        "## 6. Cách đối chiếu",
        "",
        "- Một sự kiện thuộc một kịch bản khi thời gian của nó nằm trong kịch bản và các trường trong `match` "
        "của ground truth khớp (ví dụ `src_ip` là IP kẻ tấn công).",
        "- Một incident khớp một kịch bản khi có ít nhất một sự kiện của nó thuộc kịch bản đó.",
        "- Incident đúng (true positive): khớp một kịch bản tấn công và đúng luật mong đợi. Mọi incident khác là báo nhầm.",
        "",
        "## 7. Lưu ý khi đọc số liệu",
        "",
        "- Đây là dữ liệu giả do chính nhóm sinh ra; người viết luật biết trước các kịch bản. Số liệu cho biết "
        "công cụ chạy đúng thiết kế, không cho biết nó sẽ tốt đến đâu trên log thật.",
        "- Kịch bản tấn công ngoài phạm vi luật và kịch bản vô hại bị báo nhầm (nếu có) được giữ lại có chủ ý "
        "để thấy giới hạn của bộ luật.",
        "- Flow của Suricata được ghi ra file chậm khoảng một phút so với lúc kết nối bắt đầu; độ trễ ở mục 4 "
        "tính theo thời điểm kết nối bắt đầu.",
        "",
    ]
    return "\n".join(lines)


def summary_line(result: dict[str, Any]) -> str:
    """One ASCII line for the terminal."""
    reduction, detection, latency = result["alert_reduction"], result["detection"], result["latency_seconds"]

    def number(value: float | None) -> str:
        return "n/a" if value is None else f"{value:.3f}"

    return (f"{result['dataset']}: events={result['events']} raw_alerts={reduction['raw_alerts']} "
            f"incidents={reduction['incidents']} reduction={number(reduction['reduction'])} "
            f"precision={number(detection['precision'])} recall={number(detection['recall'])} "
            f"false_positives={detection['false_positives']} mean_latency_s={number(latency['mean'])}")


def main(argv: Sequence[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="python -m eval.run", description=__doc__.splitlines()[0])
    parser.add_argument("--dataset", default="data/benchmark", help="data set folder (with manifest.json)")
    parser.add_argument("--out", default="eval/results", help="folder for the report and the metrics file")
    args = parser.parse_args(argv)
    try:
        result = evaluate_dataset(Path(args.dataset))
    except (OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}")
        return 2
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    command = f"python -m eval.run --dataset {Path(args.dataset).as_posix()} --out {out_dir.as_posix()}"
    with open(out_dir / f"{result['dataset']}.md", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(render_report(result, command))
    with open(out_dir / f"{result['dataset']}.json", "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(summary_line(result))
    print(f"report: {(out_dir / (result['dataset'] + '.md')).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
