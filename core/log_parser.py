
import re
from datetime import datetime

import pandas as pd


# Common Apache/Nginx combined or common access-log format.
LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+[^"]*)?"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\d+|-)'
)


def parse_logs(text: str) -> tuple[pd.DataFrame, int]:
    """Parse access logs. Return parsed rows and the number of skipped lines."""
    rows = []
    skipped = 0

    for line in text.splitlines():
        line = line.strip()

        if not line:
            continue

        match = LOG_PATTERN.search(line)

        if not match:
            skipped += 1
            continue

        item = match.groupdict()

        try:
            timestamp = datetime.strptime(
                item["timestamp"],
                "%d/%b/%Y:%H:%M:%S %z",
            )
        except ValueError:
            skipped += 1
            continue

        rows.append({
            "timestamp": timestamp,
            "ip": item["ip"],
            "method": item["method"],
            "path": item["path"],
            "status": int(item["status"]),
            "size": (
                int(item["size"])
                if item["size"] != "-"
                else 0
            ),
        })

    columns = ["timestamp", "ip", "method", "path", "status", "size"]
    return pd.DataFrame(rows, columns=columns), skipped
