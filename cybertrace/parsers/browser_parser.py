"""
Chromium SQLite Artifact Parser (Non-Destructive Forensics)
Safely extracts browsing history and file download records from Chrome/Edge/Brave
SQLite database artifacts without modifying filesystem metadata or access times.
"""

import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from typing import Optional
import pandas as pd


def webkit_timestamp_to_utc(webkit_microseconds: Optional[int]) -> str:
    """
    Converts a Chromium WebKit epoch timestamp (microseconds since January 1, 1601 UTC)
    to a standardized human-readable ISO 8601 UTC string: YYYY-MM-DD HH:MM:SS UTC.

    Formula: unix_epoch_seconds = (webkit_microseconds / 1,000,000) - 11,644,473,600
    """
    if webkit_microseconds is None or webkit_microseconds <= 0:
        return "Unknown / Not Recorded"

    try:
        unix_seconds = (webkit_microseconds / 1_000_000.0) - 11_644_473_600.0
        # Sanity check: between 1990 and 2050
        if 631152000 <= unix_seconds <= 2524608000:
            dt = datetime.fromtimestamp(unix_seconds, tz=timezone.utc)
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        else:
            return "Invalid WebKit Timestamp"
    except (OSError, OverflowError, ValueError):
        return "Invalid WebKit Timestamp"


def parse_chromium_history(file_bytes: bytes) -> pd.DataFrame:
    """
    Parses the 'urls' and 'visits' tables from raw Chromium 'History' SQLite database bytes.

    Non-destructive design: writes bytes to a temporary read-only file handle
    which is unlinked immediately after querying.

    Returns:
        pd.DataFrame with columns: ['timestamp', 'url', 'title', 'visit_count', 'source']
    """
    expected_cols = ["timestamp", "url", "title", "visit_count", "source"]

    if not file_bytes:
        return pd.DataFrame(columns=expected_cols)

    tmp_path = None
    try:
        # Write to temporary file for SQLite connection
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp_file:
            tmp_file.write(file_bytes)
            tmp_path = tmp_file.name

        # Connect in read-only mode using SQLite URI
        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        # Check if 'urls' table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='urls'")
        if not cursor.fetchone():
            conn.close()
            return pd.DataFrame(columns=expected_cols)

        # Query URLs and last visit time
        query = """
            SELECT url, title, visit_count, last_visit_time
            FROM urls
            ORDER BY last_visit_time ASC
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()

        records = []
        for url, title, visit_count, last_visit_time in rows:
            ts_utc = webkit_timestamp_to_utc(last_visit_time)
            records.append({
                "timestamp": ts_utc,
                "url": url or "(no url)",
                "title": title or "(no title)",
                "visit_count": visit_count or 1,
                "source": "Chromium History",
            })

        if not records:
            return pd.DataFrame(columns=expected_cols)

        return pd.DataFrame(records)

    except Exception as e:
        # Graceful fallback for malformed or non-SQLite database
        return pd.DataFrame(columns=expected_cols)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def parse_chromium_downloads(file_bytes: bytes) -> pd.DataFrame:
    """
    Parses Chromium 'downloads' table from raw SQLite database bytes.

    Returns:
        pd.DataFrame with columns: ['timestamp', 'target_path', 'received_bytes', 'total_bytes', 'state', 'source']
    """
    expected_cols = ["timestamp", "target_path", "received_bytes", "total_bytes", "state", "source"]

    if not file_bytes:
        return pd.DataFrame(columns=expected_cols)

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as tmp_file:
            tmp_file.write(file_bytes)
            tmp_path = tmp_file.name

        conn = sqlite3.connect(f"file:{tmp_path}?mode=ro", uri=True)
        cursor = conn.cursor()

        # Verify 'downloads' table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads'")
        if not cursor.fetchone():
            conn.close()
            return pd.DataFrame(columns=expected_cols)

        # Introspect available columns in downloads table
        cursor.execute("PRAGMA table_info(downloads)")
        columns = [row[1] for row in cursor.fetchall()]

        path_col = "current_path" if "current_path" in columns else ("target_path" if "target_path" in columns else "id")
        time_col = "start_time" if "start_time" in columns else "id"
        rec_col = "received_bytes" if "received_bytes" in columns else "0"
        tot_col = "total_bytes" if "total_bytes" in columns else "0"
        state_col = "state" if "state" in columns else "'Complete'"

        query = f"SELECT {path_col}, {time_col}, {rec_col}, {tot_col}, {state_col} FROM downloads"
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()

        records = []
        for path_val, time_val, rec_val, tot_val, state_val in rows:
            ts_utc = webkit_timestamp_to_utc(time_val) if isinstance(time_val, int) else "Unknown"
            records.append({
                "timestamp": ts_utc,
                "target_path": str(path_val),
                "received_bytes": rec_val or 0,
                "total_bytes": tot_val or 0,
                "state": "Complete" if state_val in (1, "Complete") else f"State {state_val}",
                "source": "Chromium Downloads",
            })

        if not records:
            return pd.DataFrame(columns=expected_cols)

        return pd.DataFrame(records)

    except Exception:
        return pd.DataFrame(columns=expected_cols)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
