#!/usr/bin/env python3
"""
Smoke module: scheduler

Verifies the scheduler background loop is alive by asserting its heartbeat
timestamp in the dashboard.db kv table is fresh. The scheduler writes this
timestamp each iteration of its 3600 s loop; this check uses a 2× threshold
(7200 s) to account for startup delay and transient slowness.

Requirements:
  - direct read access to SMOKE_DB (default DASHBOARD_DB_PATH, or
    /var/lib/patched-dashboard/dashboard.db)

Exit codes:
  0 = heartbeat present and fresh
  1 = heartbeat missing or stale
"""
import os
import sys
import sqlite3
from datetime import datetime, timezone


DB_PATH = os.getenv(
    "SMOKE_DB",
    os.getenv("DASHBOARD_DB_PATH", "/var/lib/patched-dashboard/dashboard.db"),
)
HEARTBEAT_MAX_AGE_S = 3600 * 2  # 2× the scheduler sleep interval


def step(msg: str) -> None:
    print(f"\n→ {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"  ✓ {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"  ✗ {msg}", flush=True)
    sys.exit(1)


def main():
    print("scheduler smoke starting")
    print(f"  db: {DB_PATH}")

    step("Read scheduler_heartbeat from kv table")
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT value FROM kv WHERE key='scheduler_heartbeat'").fetchone()
        conn.close()
    except Exception as e:
        fail(f"could not read dashboard.db: {e}")

    if not row:
        fail(
            "scheduler_heartbeat not found in kv table — "
            "scheduler may not have completed its first iteration yet "
            "(wait up to 3600 s after service start)"
        )

    ts_str = row["value"]
    try:
        ts = datetime.fromisoformat(ts_str)
    except ValueError:
        fail(f"scheduler_heartbeat has invalid timestamp: {ts_str!r}")

    now = datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    age_s = (now - ts).total_seconds()

    if age_s > HEARTBEAT_MAX_AGE_S:
        fail(
            f"scheduler heartbeat is {age_s:.0f}s old "
            f"(threshold {HEARTBEAT_MAX_AGE_S}s) — scheduler loop may be stuck"
        )
    ok(f"heartbeat is {age_s:.0f}s old (threshold {HEARTBEAT_MAX_AGE_S}s) — scheduler ok")

    print("\nscheduler PASSED")


if __name__ == "__main__":
    main()
