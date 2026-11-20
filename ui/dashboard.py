"""SOC dashboard (Streamlit).

    python -m pipeline --db data/soc.db dashboard
    # or: streamlit run ui/dashboard.py   (database path from SOC_DB_PATH)

Tabs: overview, incidents (status change, summary export), log search,
and analysis of an uploaded log. All database work is in ``ui/data.py``.
"""
from __future__ import annotations

import inspect
import os
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:               # "streamlit run" only puts ui/ on the path
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

from storage.models import connect, init_db  # noqa: E402
from ui import data  # noqa: E402

DB_PATH = os.environ.get("SOC_DB_PATH", "data/soc.db")
SOURCE_NAMES = {"auth_log": "Linux auth.log", "suricata": "Suricata EVE JSON", "sysmon": "Windows Sysmon (JSON)"}
# Severity is a state, so it uses the reserved status colours; low and info stay neutral.
SEVERITY_COLOURS = {"critical": "#d03b3b", "high": "#ec835a", "medium": "#fab219", "low": "#898781", "info": "#c3c2b7"}
SERIES_BLUE = "#2a78d6"
PAGE_SIZE = 200
# Newer Streamlit wants width="stretch"; older versions only know use_container_width.
_NEW_WIDTH = "stretch" in str(inspect.signature(st.dataframe).parameters.get("width"))
WIDE = {"width": "stretch"} if _NEW_WIDTH else {"use_container_width": True}


def parse_utc(text: str) -> datetime:
    return datetime.fromisoformat(text.replace("Z", "+00:00"))


def canonical(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def short(text: str | None) -> str:
    """2026-11-12T01:25:44.000000Z -> 2026-11-12 01:25:44"""
    return text[:19].replace("T", " ") if text else "-"


def timeline_spec() -> dict:
    """Vega-Lite: one row per rule, a bar from first to last event, a dot where it starts."""
    colour = {"field": "severity", "type": "nominal", "title": "Mức độ",
              "scale": {"domain": list(SEVERITY_COLOURS), "range": list(SEVERITY_COLOURS.values())}}
    tooltip = [{"field": "incident", "title": "Incident"}, {"field": "severity", "title": "Mức độ"},
               {"field": "status", "title": "Trạng thái"}, {"field": "start", "type": "temporal", "title": "Bắt đầu (UTC)",
                                                           "timeUnit": "utcyearmonthdatehoursminutesseconds"},
               {"field": "events", "title": "Số sự kiện"}]
    x = {"field": "start", "type": "temporal", "title": "Thời gian (UTC)", "scale": {"type": "utc"},
         "axis": {"format": "%H:%M", "grid": True}}
    y = {"field": "rule", "type": "nominal", "title": None, "axis": {"labelLimit": 240}}
    return {
        "height": {"step": 34},
        "layer": [
            {"mark": {"type": "bar", "height": 8, "cornerRadius": 4},
             "encoding": {"x": x, "x2": {"field": "end"}, "y": y, "color": colour, "tooltip": tooltip}},
            {"mark": {"type": "point", "filled": True, "size": 110, "stroke": "#fcfcfb", "strokeWidth": 2},
             "encoding": {"x": x, "y": y, "color": colour, "tooltip": tooltip}},
        ],
    }


def assets_spec() -> dict:
    """Vega-Lite: horizontal bars, one series, value written at the bar end."""
    y = {"field": "asset", "type": "nominal", "sort": None, "title": None, "axis": {"labelLimit": 220}}
    x = {"field": "incidents", "type": "quantitative", "title": "Số incident", "axis": {"tickMinStep": 1}}
    tooltip = [{"field": "asset", "title": "Thiết bị"}, {"field": "incidents", "title": "Số incident"},
               {"field": "events", "title": "Sự kiện liên quan"}]
    return {
        "height": {"step": 30},
        "layer": [
            {"mark": {"type": "bar", "color": SERIES_BLUE, "cornerRadiusEnd": 4, "height": 16},
             "encoding": {"x": x, "y": y, "tooltip": tooltip}},
            {"mark": {"type": "text", "align": "left", "dx": 6},
             "encoding": {"x": x, "y": y, "text": {"field": "incidents"}}},
        ],
    }


def show_overview(conn) -> None:
    numbers = data.overview(conn)
    first, second, third, fourth = st.columns(4)
    first.metric("Tổng sự kiện", f"{numbers['events']:,}")
    second.metric("Incident đang mở", numbers["open_incidents"])
    third.metric("Đang mở, mức high/critical", numbers["open_serious"])
    fourth.metric("Tổng incident", numbers["incidents"])
    if not numbers["events"]:
        st.info("Chưa có dữ liệu. Nạp log bằng `python -m pipeline ingest ...` hoặc ở tab **Phân tích log mới**.")
        return
    st.caption(f"Dữ liệu từ {short(numbers['first_event_utc'])} đến {short(numbers['last_event_utc'])} (UTC). "
               + " · ".join(f"{SOURCE_NAMES.get(source, source)}: {count:,}" for source, count in numbers["by_source"].items()))

    st.subheader("Timeline incident")
    incidents = data.list_incidents(conn)
    if incidents:
        rows = [{"incident": f"#{item['incident_id']} {item['title']}", "rule": item["rule_id"],
                 "severity": item["severity"], "status": item["status"], "events": item["event_count"],
                 "start": item["first_seen_utc"], "end": item["last_seen_utc"]} for item in incidents]
        st.vega_lite_chart(rows, timeline_spec(), **WIDE)
        with st.expander("Xem dạng bảng"):
            st.dataframe([{"Incident": row["incident"], "Mức độ": row["severity"], "Trạng thái": row["status"],
                           "Bắt đầu (UTC)": short(row["start"]), "Kết thúc (UTC)": short(row["end"]),
                           "Số sự kiện": row["events"]} for row in rows], **WIDE, hide_index=True)
    else:
        st.info("Chưa có incident. Chạy `python -m pipeline detect` sau khi nạp log.")

    st.subheader("Thiết bị bị tấn công nhiều nhất")
    assets = data.top_assets(conn, limit=8)
    if assets:
        st.vega_lite_chart(assets, assets_spec(), **WIDE)
        with st.expander("Xem dạng bảng"):
            st.dataframe([{"Thiết bị": row["asset"], "Số incident": row["incidents"], "Sự kiện liên quan": row["events"]}
                          for row in assets], **WIDE, hide_index=True)
    else:
        st.caption("Chưa có incident nào gắn với thiết bị nội bộ.")


def show_incidents(conn) -> None:
    left, middle, right = st.columns(3)
    statuses = left.multiselect("Trạng thái", data.STATUSES, key="incident_status_filter")
    severities = middle.multiselect("Mức độ", data.SEVERITIES, key="incident_severity_filter")
    rules = right.multiselect("Luật", sorted({item["rule_id"] for item in data.list_incidents(conn)}),
                              key="incident_rule_filter")
    incidents = data.list_incidents(conn, statuses, severities, rules)
    st.caption(f"{len(incidents)} incident")
    if not incidents:
        st.info("Không có incident nào khớp bộ lọc.")
        return
    st.dataframe([{"ID": item["incident_id"], "Mức độ": item["severity"], "Trạng thái": item["status"],
                   "Analyst": item["assigned_analyst"] or "-", "Luật": item["rule_id"], "MITRE": item["mitre"] or "-",
                   "Bắt đầu (UTC)": short(item["first_seen_utc"]), "Kết thúc (UTC)": short(item["last_seen_utc"]),
                   "Sự kiện": item["event_count"], "Tiêu đề": item["title"]} for item in incidents],
                 **WIDE, hide_index=True)

    labels = {item["incident_id"]: f"#{item['incident_id']} · {item['severity']} · {item['title']}" for item in incidents}
    chosen = st.selectbox("Chọn incident để xem chi tiết", list(labels), format_func=labels.get, key="incident_pick")
    incident, events = data.incident_details(conn, chosen)
    st.markdown(f"**{incident['title']}**  \n{incident['summary'] or ''}")

    with st.form("incident_update"):
        status_column, analyst_column = st.columns(2)
        status = status_column.selectbox("Trạng thái", data.STATUSES, index=data.STATUSES.index(incident["status"]),
                                         key=f"status_{chosen}")
        analyst = analyst_column.text_input("Analyst phụ trách", incident["assigned_analyst"] or "", key=f"analyst_{chosen}")
        if st.form_submit_button("Lưu thay đổi"):
            data.update_incident(conn, chosen, status, analyst)
            st.session_state["notice"] = f"Đã cập nhật incident #{chosen}: {status}."
            st.rerun()

    summary = data.investigation_summary(conn, chosen)
    st.download_button("Tải tóm tắt điều tra (.md)", summary, file_name=f"incident_{chosen}_summary.md",
                       mime="text/markdown", key="summary_download")
    with st.expander("Xem tóm tắt điều tra"):
        st.markdown(summary)
    with st.expander(f"Sự kiện liên quan ({len(events)})"):
        st.dataframe([{"Thời gian (UTC)": short(e["timestamp_utc"]), "Nguồn": e["source_type"], "Hành động": e["action"],
                       "IP nguồn": e["src_ip"], "IP đích": e["dst_ip"], "Cổng": e["dst_port"], "User": e["username"],
                       "Host": e["hostname"]} for e in events], **WIDE, hide_index=True)


def show_search(conn) -> None:
    numbers = data.overview(conn)
    if not numbers["events"]:
        st.info("Chưa có sự kiện nào trong database.")
        return
    first, last = parse_utc(numbers["first_event_utc"]), parse_utc(numbers["last_event_utc"])
    ip_column, text_column = st.columns(2)
    ip = ip_column.text_input("Địa chỉ IP (nguồn hoặc đích)", key="search_ip",
                              help="Gõ đủ địa chỉ, hoặc kết thúc bằng dấu chấm để tìm cả dải, ví dụ 10.0.2.")
    text = text_column.text_input("Từ khóa (user, host, signature, lệnh, nội dung gốc)", key="search_text")
    severity_column, source_column, action_column = st.columns(3)
    severities = severity_column.multiselect("Mức độ", data.filter_choices(conn, "severity"), key="search_severity")
    sources = source_column.multiselect("Nguồn log", data.filter_choices(conn, "source_type"), key="search_source",
                                        format_func=lambda name: SOURCE_NAMES.get(name, name))
    actions = action_column.multiselect("Hành động", data.filter_choices(conn, "action"), key="search_action")
    low, high = first.replace(tzinfo=None, microsecond=0), last.replace(tzinfo=None, microsecond=0) + timedelta(seconds=1)
    if low < high - timedelta(seconds=1):
        start, end = st.slider("Khoảng thời gian (UTC)", min_value=low, max_value=high, value=(low, high),
                               format="YYYY-MM-DD HH:mm:ss", step=timedelta(seconds=1), key="search_time")
    else:
        start, end = low, high
    start_utc = canonical(start.replace(tzinfo=timezone.utc))
    end_utc = canonical(end.replace(tzinfo=timezone.utc))
    page = st.number_input("Trang", min_value=1, value=1, step=1, key="search_page")
    rows, total = data.search_events(conn, ip=ip, start_utc=start_utc, end_utc=end_utc, severities=severities,
                                     sources=sources, actions=actions, text=text, limit=PAGE_SIZE,
                                     offset=(page - 1) * PAGE_SIZE)
    pages = max(1, -(-total // PAGE_SIZE))
    st.caption(f"{total:,} sự kiện khớp · trang {min(page, pages)}/{pages} ({PAGE_SIZE} dòng mỗi trang)")
    st.dataframe([{"ID": r["id"], "Thời gian (UTC)": short(r["timestamp_utc"]), "Nguồn": r["source_type"],
                   "Mức độ": r["severity"], "Hành động": r["action"], "IP nguồn": r["src_ip"], "IP đích": r["dst_ip"],
                   "Cổng": r["dst_port"], "User": r["username"], "Host": r["hostname"],
                   "Chi tiết": r["signature"] or r["command_line"] or r["process_name"]} for r in rows],
                 **WIDE, hide_index=True)


def show_upload(conn) -> None:
    st.write("Tải một file log lên để chuẩn hóa, lưu vào database và chạy các luật tương quan ngay. "
             "Incident mới sẽ hiện ở tab **Incident** và trên timeline.")
    with st.form("upload_form"):
        uploaded = st.file_uploader("File log", key="upload_file")
        source = st.selectbox("Loại log", list(SOURCE_NAMES), format_func=SOURCE_NAMES.get, key="upload_source")
        year_column, zone_column = st.columns(2)
        year = year_column.number_input("Năm của log (chỉ dùng cho auth.log)", min_value=2000, max_value=2100,
                                        value=datetime.now().year, step=1, key="upload_year")
        zone = zone_column.text_input("Múi giờ của log (chỉ dùng cho auth.log)", "+07:00", key="upload_tz")
        again = st.checkbox("Nạp lại dù file này đã được nạp trong phiên này", key="upload_again")
        submitted = st.form_submit_button("Phân tích")
    if not submitted:
        return
    if uploaded is None:
        st.warning("Hãy chọn một file trước.")
        return
    content = uploaded.getvalue()
    digest = data.file_digest(source, content)
    seen = st.session_state.setdefault("uploaded_digests", set())
    if digest in seen and not again:
        st.warning("File này đã được nạp trong phiên này. Nạp lần nữa sẽ nhân đôi sự kiện; "
                   "tích vào ô ở trên nếu bạn vẫn muốn.")
        return
    try:
        result = data.analyze_log(conn, source, content, year=int(year), tz=zone)
    except ValueError as exc:
        st.error(f"Không phân tích được: {exc}")
        return
    seen.add(digest)
    stats = result["stats"]
    one, two, three, four = st.columns(4)
    one.metric("Dòng đọc", stats["lines"])
    two.metric("Sự kiện lưu", result["stored"])
    three.metric("Dòng không liên quan", stats["ignored"])
    four.metric("Dòng lỗi", stats["invalid"])
    if stats["reasons"]:
        with st.expander("Lý do bỏ qua dòng"):
            st.dataframe([{"Lý do": reason, "Số dòng": count} for reason, count in sorted(stats["reasons"].items())],
                         **WIDE, hide_index=True)
    if result["new_incident_ids"]:
        st.success(f"Phát hiện {len(result['new_incident_ids'])} incident mới.")
        for incident_id in result["new_incident_ids"]:
            incident, _ = data.incident_details(conn, incident_id)
            st.markdown(f"- **#{incident_id} · {incident['severity']} · {incident['title']}**: {incident['summary']}")
    else:
        st.info("Không có incident mới từ file này.")


def main() -> None:
    st.set_page_config(page_title="SOC Analyst Toolkit", layout="wide")
    st.title("SOC Analyst Toolkit")
    st.caption(f"Database: `{DB_PATH}` · mọi thời gian hiển thị theo UTC")
    if st.session_state.get("notice"):
        st.success(st.session_state.pop("notice"))
    with closing(connect(DB_PATH)) as conn:
        init_db(conn)
        overview_tab, incident_tab, search_tab, upload_tab = st.tabs(
            ["Tổng quan", "Incident", "Tìm kiếm log", "Phân tích log mới"])
        with overview_tab:
            show_overview(conn)
        with incident_tab:
            show_incidents(conn)
        with search_tab:
            show_search(conn)
        with upload_tab:
            show_upload(conn)


main()
