
import json
import sqlite3
from pathlib import Path

import pandas as pd


DB_PATH = Path(__file__).resolve().parent.parent / "data" / "cybershield.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS investigations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_name TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                total_requests INTEGER NOT NULL,
                unique_ips INTEGER NOT NULL,
                flagged_events INTEGER NOT NULL,
                high_events INTEGER NOT NULL,
                events_json TEXT NOT NULL
            )
        """)


def save_investigation(source_name, logs, events):
    """Persist one completed investigation and its findings."""
    event_records = json.loads(
        events.to_json(orient="records", date_format="iso")
    )

    with get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO investigations (
                source_name, total_requests, unique_ips,
                flagged_events, high_events, events_json
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                source_name,
                int(len(logs)),
                int(logs["ip"].nunique()),
                int(len(events)),
                int(
                    (events["severity"] == "High").sum()
                ) if not events.empty else 0,
                json.dumps(event_records),
            ),
        )
        return cursor.lastrowid


def list_investigations(limit=100):
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, source_name, created_at, total_requests,
                   unique_ips, flagged_events, high_events
            FROM investigations
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, min(int(limit), 500)),),
        ).fetchall()

    return pd.DataFrame([dict(row) for row in rows])


def get_investigation(investigation_id):
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT *
            FROM investigations
            WHERE id = ?
            """,
            (int(investigation_id),),
        ).fetchone()

    if row is None:
        return None

    result = dict(row)
    result["events"] = pd.DataFrame(
        json.loads(result.pop("events_json"))
    )
    return result
