
from datetime import datetime, timedelta, timezone

import pandas as pd

from core.detector import detect_events


def make_logs(statuses, paths=None):
    start = datetime(2026, 10, 10, 8, 30, tzinfo=timezone.utc)

    if paths is None:
        paths = ["/login"] * len(statuses)

    return pd.DataFrame([
        {
            "timestamp": start + timedelta(seconds=i),
            "ip": "192.0.2.10",
            "method": "POST",
            "path": path,
            "status": status,
            "size": 512,
        }
        for i, (status, path) in enumerate(zip(statuses, paths))
    ])


# Test 1: repeated authentication failures
logs = make_logs([401] * 5)
events = detect_events(logs, failed_threshold=5, burst_threshold=30)

assert len(events) == 5
assert events["reason"].str.contains(
    "authentication/authorization failures"
).all()
print("PASS: repeated failure detection")


# Test 2: sensitive path
logs = make_logs([404], ["/.env"])
events = detect_events(logs)

assert len(events) == 1
assert events.iloc[0]["risk_score"] == 25
print("PASS: sensitive path detection")


# Test 3: request burst
logs = make_logs([200] * 30)
events = detect_events(logs, burst_threshold=30)

assert len(events) == 30
assert events["reason"].str.contains("rolling minute").all()
print("PASS: request burst detection")


# Test 4: normal traffic should not trigger a rule
logs = make_logs([200, 200, 200])
events = detect_events(logs)

assert events.empty
print("PASS: normal traffic")


print("All detector tests passed.")
