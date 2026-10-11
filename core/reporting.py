
from datetime import datetime, timezone
from html import escape

import pandas as pd


def build_html_report(
    source_name: str,
    logs: pd.DataFrame,
    events: pd.DataFrame,
) -> str:
    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    total_requests = len(logs)
    unique_ips = logs["ip"].nunique() if not logs.empty else 0
    high_events = (
        int((events["severity"] == "High").sum())
        if not events.empty else 0
    )

    safe_source = escape(str(source_name))
    safe_generated = escape(generated_at)

    if events.empty:
        events_html = "<p>No events matched the configured rules.</p>"
    else:
        display_columns = [
            column for column in [
                "timestamp", "ip", "method", "path", "status",
                "severity", "risk_score", "reason",
            ]
            if column in events.columns
        ]

        safe_events = events[display_columns].copy()

        # Escape every cell before converting the table to HTML.
        safe_events = safe_events.map(
            lambda value: escape(str(value))
        )

        events_html = safe_events.to_html(
            index=False,
            border=0,
            classes="events",
            escape=False,
        )

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberShield Security Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; color: #17202a; }}
h1 {{ color: #087f5b; }}
.metrics {{ display: flex; flex-wrap: wrap; gap: 12px; }}
.metric {{ border: 1px solid #d5d8dc; border-radius: 8px;
           padding: 14px; min-width: 150px; }}
.events {{ border-collapse: collapse; width: 100%; font-size: 12px; }}
.events th, .events td {{ border: 1px solid #ddd; padding: 8px;
                          text-align: left; overflow-wrap: anywhere; }}
.events th {{ background: #e8f5e9; }}
.note {{ background: #fff8db; padding: 12px; border-radius: 6px; }}
</style>
</head>
<body>
<h1>CyberShield — Security Analysis Report</h1>
<p><strong>Source:</strong> {safe_source}</p>
<p><strong>Generated:</strong> {safe_generated}</p>
<div class="metrics">
<div class="metric"><strong>Total requests</strong><h2>{total_requests}</h2></div>
<div class="metric"><strong>Unique IPs</strong><h2>{unique_ips}</h2></div>
<div class="metric"><strong>Flagged events</strong><h2>{len(events)}</h2></div>
<div class="metric"><strong>High severity</strong><h2>{high_events}</h2></div>
</div>
<h2>Detected events</h2>
{events_html}
<p class="note">Detections are indicators for investigation, not proof
of malicious activity. Validate findings against surrounding logs.</p>
</body>
</html>"""
