from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

from core.log_parser import parse_logs
from core.detector import detect_events
from core.storage import (
    init_db,
    save_investigation,
    list_investigations,
    get_investigation,
)
from core.reporting import build_html_report


# ------------------------------------------------------------------
# Page setup and database initialization
# ------------------------------------------------------------------
st.set_page_config(
    page_title="CyberShield | Security Log Analyzer",
    page_icon="🛡️",
    layout="wide",
)

init_db()

st.title("🛡️ CyberShield")
st.caption("Local security log analysis and suspicious-activity detection")
st.info(
    "This tool analyzes logs you provide. Findings are indicators for "
    "investigation, not proof of malicious activity."
)


# ------------------------------------------------------------------
# Sidebar detection settings
# ------------------------------------------------------------------
st.sidebar.title("🛡️ CyberShield")
st.sidebar.subheader("Detection settings")

failed_threshold = st.sidebar.slider(
    "Failed-request threshold",
    min_value=2,
    max_value=20,
    value=5,
    help="Flag an IP when its HTTP 401/403 response count reaches this number.",
)

burst_threshold = st.sidebar.slider(
    "Requests per rolling minute",
    min_value=5,
    max_value=100,
    value=30,
    help="Flag requests in a rolling one-minute window when the IP reaches this count.",
)

st.sidebar.caption(
    "Detection scores prioritize investigation; they are not attack probabilities."
)


# ------------------------------------------------------------------
# Input
# ------------------------------------------------------------------
uploaded_file = st.file_uploader(
    "Upload an Apache/Nginx access log",
    type=["log", "txt"],
    help="Maximum file size: 10 MB. Expected format: common Apache/Nginx access logs.",
)
use_sample = st.checkbox("Use the built-in sample log")

if not uploaded_file and not use_sample:
    st.markdown(
        """
        ### Getting started
        1. Upload an Apache/Nginx access log, or select the sample log option.
        2. Review request statistics and suspicious activity.
        3. Adjust detection thresholds in the sidebar.
        4. Investigate events and export filtered findings.
        """
    )
    st.stop()


# ------------------------------------------------------------------
# Read and parse logs
# ------------------------------------------------------------------
try:
    if uploaded_file:
        raw_bytes = uploaded_file.getvalue()

        if len(raw_bytes) > 10 * 1024 * 1024:
            st.error("File is larger than the 10 MB limit.")
            st.stop()

        log_text = raw_bytes.decode("utf-8", errors="replace")
        source_name = uploaded_file.name
    else:
        sample_path = Path(__file__).parent / "data" / "sample_access.log"
        log_text = sample_path.read_text(encoding="utf-8")
        source_name = "sample_access.log"

    logs, skipped = parse_logs(log_text)

    if logs.empty:
        st.error("No valid access-log entries were found.")
        st.caption("This version expects standard Apache/Nginx access-log entries.")
        st.stop()

    events = detect_events(
        logs,
        failed_threshold=failed_threshold,
        burst_threshold=burst_threshold,
    )

except (OSError, UnicodeError, ValueError) as exc:
    st.error(f"Could not read or analyze the log: {exc}")
    st.stop()
except Exception as exc:
    st.error(f"Unexpected log-analysis error: {exc}")
    st.stop()


st.success(f"Analyzed: {source_name}")
if skipped:
    st.warning(f"{skipped} non-empty line(s) could not be parsed.")


# ------------------------------------------------------------------
# Day 4: Save investigation and generate report
# ------------------------------------------------------------------
st.divider()
st.subheader("Save investigation & generate report")

save_col, report_col = st.columns(2)

with save_col:
    if st.button("Save investigation to history", type="primary"):
        try:
            saved_id = save_investigation(
                source_name=source_name,
                logs=logs,
                events=events,
            )
            st.session_state["last_saved_investigation_id"] = saved_id
            st.success(f"Investigation #{saved_id} saved successfully.")
        except (OSError, ValueError, TypeError) as exc:
            st.error(f"Could not save investigation: {exc}")
        except Exception as exc:
            st.error(f"Unexpected database error: {exc}")

with report_col:
    try:
        html_report = build_html_report(
            source_name=source_name,
            logs=logs,
            events=events,
        )
        st.download_button(
            "Download HTML security report",
            data=html_report.encode("utf-8"),
            file_name="cybershield_security_report.html",
            mime="text/html",
        )
    except Exception as exc:
        st.error(f"Could not generate report: {exc}")


# ------------------------------------------------------------------
# Overall metrics
# ------------------------------------------------------------------
high_count = int((events["severity"] == "High").sum()) if not events.empty else 0
medium_count = int((events["severity"] == "Medium").sum()) if not events.empty else 0

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total requests", f"{len(logs):,}")
col2.metric("Unique IPs", f"{logs['ip'].nunique():,}")
col3.metric("Flagged events", f"{len(events):,}")
col4.metric("High-severity events", f"{high_count:,}")


# ------------------------------------------------------------------
# Request overview charts
# ------------------------------------------------------------------
st.divider()
st.subheader("Request overview")
chart_left, chart_right = st.columns(2)

with chart_left:
    status_counts = (
        logs["status"].value_counts().sort_index()
        .rename_axis("HTTP status").reset_index(name="Requests")
    )
    fig = px.bar(
        status_counts,
        x="HTTP status",
        y="Requests",
        title="HTTP status distribution",
    )
    st.plotly_chart(fig, use_container_width=True)

with chart_right:
    ip_request_counts = (
        logs["ip"].value_counts().head(10)
        .rename_axis("IP address").reset_index(name="Requests")
    )
    fig = px.bar(
        ip_request_counts,
        x="Requests",
        y="IP address",
        orientation="h",
        title="Top 10 IP addresses by request count",
    )
    st.plotly_chart(fig, use_container_width=True)


# ------------------------------------------------------------------
# Security investigation center
# ------------------------------------------------------------------
st.divider()
st.subheader("Security Investigation Center")

if events.empty:
    st.success("No events matched the current detection rules.")
    st.caption("Try lowering the thresholds in the sidebar if appropriate for your logs.")
else:
    event_data = events.copy()
    event_data["timestamp"] = pd.to_datetime(
        event_data["timestamp"], utc=True, errors="coerce"
    )
    event_data = event_data.dropna(subset=["timestamp"])

    st.markdown("### Investigation filters")
    filter_col1, filter_col2 = st.columns(2)

    with filter_col1:
        selected_severities = st.multiselect(
            "Severity",
            options=["High", "Medium", "Low"],
            default=["High", "Medium", "Low"],
        )
        available_ips = sorted(event_data["ip"].astype(str).unique().tolist())
        selected_ips = st.multiselect(
            "Source IP address",
            options=available_ips,
            default=available_ips,
        )

    with filter_col2:
        available_statuses = sorted(event_data["status"].unique().tolist())
        selected_statuses = st.multiselect(
            "HTTP status code",
            options=available_statuses,
            default=available_statuses,
        )
        search_text = st.text_input(
            "Search path or detection reason",
            placeholder="e.g. /login or sensitive path",
        )

    min_date = event_data["timestamp"].min().date()
    max_date = event_data["timestamp"].max().date()
    date_range = st.date_input(
        "Date range (UTC)",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date,
    )

    filtered = event_data[
        event_data["severity"].isin(selected_severities)
        & event_data["ip"].astype(str).isin(selected_ips)
        & event_data["status"].isin(selected_statuses)
    ].copy()

    if search_text.strip():
        query = search_text.strip()
        text_match = (
            filtered["path"].astype(str).str.contains(query, case=False, regex=False)
            | filtered["reason"].astype(str).str.contains(query, case=False, regex=False)
        )
        filtered = filtered[text_match]

    if isinstance(date_range, (tuple, list)) and len(date_range) == 2:
        start_date, end_date = date_range
        filtered = filtered[
            (filtered["timestamp"].dt.date >= start_date)
            & (filtered["timestamp"].dt.date <= end_date)
        ]

    st.divider()
    st.markdown("### Filtered event summary")
    high_filtered = int((filtered["severity"] == "High").sum())
    medium_filtered = int((filtered["severity"] == "Medium").sum())
    low_filtered = int((filtered["severity"] == "Low").sum())

    metric1, metric2, metric3, metric4 = st.columns(4)
    metric1.metric("Matching events", len(filtered))
    metric2.metric("High severity", high_filtered)
    metric3.metric("Medium severity", medium_filtered)
    metric4.metric("Low severity", low_filtered)

    chart_col1, chart_col2 = st.columns(2)
    with chart_col1:
        if not filtered.empty:
            severity_counts = (
                filtered["severity"].value_counts()
                .reindex(["High", "Medium", "Low"], fill_value=0)
                .rename_axis("Severity").reset_index(name="Events")
            )
            fig = px.bar(
                severity_counts,
                x="Severity",
                y="Events",
                title="Events by severity",
            )
            st.plotly_chart(fig, use_container_width=True)

    with chart_col2:
        if not filtered.empty:
            flagged_ip_counts = (
                filtered["ip"].value_counts().head(10)
                .rename_axis("IP address").reset_index(name="Events")
            )
            fig = px.bar(
                flagged_ip_counts,
                x="Events",
                y="IP address",
                orientation="h",
                title="Top IPs in filtered events",
            )
            st.plotly_chart(fig, use_container_width=True)

    st.markdown("### Matching security events")
    display_columns = [
        "timestamp", "ip", "method", "path", "status", "severity", "reason"
    ]
    if "risk_score" in filtered.columns:
        display_columns.insert(6, "risk_score")
    display_columns = [
        column for column in display_columns if column in filtered.columns
    ]

    if filtered.empty:
        st.info("No events match the selected filters.")
    else:
        st.dataframe(
            filtered[display_columns],
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("### Investigate an individual event")
        reset_filtered = filtered.reset_index(drop=True)
        event_labels = []

        for _, row in reset_filtered.iterrows():
            score_text = (
                f" | Score {row['risk_score']}"
                if "risk_score" in reset_filtered.columns else ""
            )
            event_labels.append(
                f"{row['severity']}{score_text} | {row['ip']} | "
                f"{row['method']} {row['path']} | "
                f"{row['timestamp'].strftime('%Y-%m-%d %H:%M:%S UTC')}"
            )

        selected_event_label = st.selectbox(
            "Choose an event",
            options=event_labels,
        )
        selected_event = reset_filtered.iloc[
            event_labels.index(selected_event_label)
        ]

        detail_left, detail_right = st.columns(2)
        with detail_left:
            st.write("**Source IP:**", selected_event["ip"])
            st.write("**Timestamp (UTC):**", str(selected_event["timestamp"]))
            st.write("**HTTP method:**", selected_event["method"])
            st.write("**Request path:**", selected_event["path"])

        with detail_right:
            st.write("**HTTP status:**", selected_event["status"])
            st.write("**Severity:**", selected_event["severity"])
            if "risk_score" in selected_event.index:
                st.write(
                    "**Heuristic risk score:**",
                    selected_event["risk_score"],
                    "/ 100",
                )
            st.write("**Detection reason:**", selected_event["reason"])
            if "size" in selected_event.index:
                st.write("**Response size:**", selected_event["size"], "bytes")

        st.warning(
            "A detection is a signal for investigation, not confirmation of an attack. "
            "Review surrounding logs and application context. Risk scores are heuristic, not probabilities."
        )

        csv_bytes = filtered[display_columns].to_csv(index=False).encode("utf-8")
        st.download_button(
            "Download filtered findings as CSV",
            data=csv_bytes,
            file_name="cybershield_filtered_findings.csv",
            mime="text/csv",
        )


with st.expander("View parsed log entries"):
    st.dataframe(logs, use_container_width=True, hide_index=True)


# ------------------------------------------------------------------
# Day 4: Investigation history
# ------------------------------------------------------------------
st.divider()
st.subheader("Investigation History")

try:
    history = list_investigations(limit=100)

    if history.empty:
        st.info(
            "No saved investigations yet. Analyze a log and click "
            "'Save investigation to history'."
        )
    else:
        st.dataframe(
            history,
            use_container_width=True,
            hide_index=True,
        )

        history_ids = history["id"].astype(int).tolist()
        history_labels = {
            int(row["id"]): (
                f"#{int(row['id'])} — {row['source_name']} — "
                f"{row['created_at']}"
            )
            for _, row in history.iterrows()
        }

        selected_id = st.selectbox(
            "Choose a saved investigation",
            options=history_ids,
            format_func=lambda value: history_labels[value],
        )

        if st.button("Load saved findings"):
            st.session_state["loaded_investigation_id"] = int(selected_id)

        loaded_id = st.session_state.get("loaded_investigation_id")

        if loaded_id in history_ids:
            saved = get_investigation(loaded_id)

            if saved:
                st.markdown(f"### Saved investigation #{saved['id']}")
                st.write("**Source:**", saved["source_name"])
                st.write("**Saved at (UTC):**", saved["created_at"])

                saved_col1, saved_col2, saved_col3, saved_col4 = st.columns(4)
                saved_col1.metric("Requests", saved["total_requests"])
                saved_col2.metric("Unique IPs", saved["unique_ips"])
                saved_col3.metric("Flagged events", saved["flagged_events"])
                saved_col4.metric("High severity", saved["high_events"])

                saved_events = saved["events"]
                if saved_events.empty:
                    st.info("This investigation contains no flagged events.")
                else:
                    st.dataframe(
                        saved_events,
                        use_container_width=True,
                        hide_index=True,
                    )
                    saved_csv = saved_events.to_csv(index=False).encode("utf-8")
                    st.download_button(
                        "Download saved findings as CSV",
                        data=saved_csv,
                        file_name=f"cybershield_investigation_{loaded_id}.csv",
                        mime="text/csv",
                        key=f"saved_csv_{loaded_id}",
                    )

except Exception as exc:
    st.error(f"Could not load investigation history: {exc}")
