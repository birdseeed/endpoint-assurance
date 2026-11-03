"""
Test for PAT-901: dashboard SQLite connections must open with WAL journal
mode and a busy_timeout so concurrent writers (hourly scheduler_loop tick
functions, per-request audit rows, scan/retention threads) wait instead of
immediately raising "database is locked" past SQLite's default 5s window.

Drives the actual connection helper (shared._open_db_connection), the one
both shared.get_db() and main.py's shadowed get_db() route through, and
confirms a freshly opened connection reports the expected PRAGMA values.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import shared  # noqa: E402


def test_open_db_connection_sets_wal_and_busy_timeout(tmp_path):
    db_path = tmp_path / "pat901-test.db"

    conn = shared._open_db_connection(db_path)
    try:
        journal_mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        busy_timeout = conn.execute("PRAGMA busy_timeout").fetchone()[0]
    finally:
        conn.close()

    assert journal_mode.lower() == "wal"
    assert busy_timeout == 10000


def test_get_db_context_manager_sets_wal_and_busy_timeout(tmp_path, monkeypatch):
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "pat901-getdb-test.db")

    with shared.get_db() as db:
        journal_mode = db.execute("PRAGMA journal_mode").fetchone()[0]
        busy_timeout = db.execute("PRAGMA busy_timeout").fetchone()[0]

    assert journal_mode.lower() == "wal"
    assert busy_timeout == 10000
