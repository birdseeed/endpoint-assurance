"""Additional source-boundary cases, independent of the frozen acceptance set."""
import json
import sqlite3
from datetime import datetime, timezone

import pytest

import service_exceptions as evidence
from tests.pat1966_support import feed


@pytest.mark.parametrize("value", ["2026-02-30T00:00:00Z", "2026-10-03T00:00:00", "2026-10-03T00:00:00+01:00", {}, 0])
def test_non_calendar_or_non_utc_source_times_are_quarantined(value):
    data = feed()
    data["exceptions"][0]["evidence_at"] = value
    result, invalid = evidence.project(data, datetime.now(timezone.utc))
    assert invalid == {"scheduled_jobs"}
    assert [v["check_id"] for v in result["exceptions"]] == ["device_reports"]


def test_bad_observation_quarantines_its_category_only():
    data = feed()
    data["checks"][1]["observations"][0]["result"] = ["ok"]
    result, invalid = evidence.project(data, datetime.now(timezone.utc))
    assert invalid == {"scheduled_jobs"}
    assert result["checks"][1]["result"] == "unknown"
    assert result["exceptions"][0]["check_id"] == "device_reports"


def test_private_observation_fields_are_not_forwarded():
    data = feed()
    data["checks"][1]["observations"][0]["output"] = "PRIVATE"
    result, _ = evidence.project(data, datetime.now(timezone.utc))
    assert "PRIVATE" not in json.dumps(result)


def test_readonly_context_denies_writes_and_does_not_create_missing_db(tmp_path):
    from shared import _open_db_connection, readonly_db_connections
    path = tmp_path / "existing.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE sample(value TEXT)")
    with readonly_db_connections():
        conn = _open_db_connection(path)
        try:
            assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                conn.execute("INSERT INTO sample VALUES ('forbidden')")
        finally:
            conn.close()
        with pytest.raises(sqlite3.OperationalError):
            _open_db_connection(tmp_path / "missing.db")
    assert not (tmp_path / "missing.db").exists()
    # The scoped option cannot alter normal writer behaviour after the read.
    conn = _open_db_connection(path)
    try:
        conn.execute("INSERT INTO sample VALUES ('allowed')")
        conn.commit()
    finally:
        conn.close()


def test_failed_report_query_does_not_clear_supported_job_exception():
    data, invalid = evidence.project(feed(), datetime.now(timezone.utc))
    def unavailable():
        raise sqlite3.OperationalError("PRIVATE error")
    result = evidence.join_local(data, invalid, unavailable, lambda *args: (None, True), datetime.now(timezone.utc))
    assert "PRIVATE" not in json.dumps(result)
    assert any(e["check_id"] == "scheduled_jobs" for e in result["exceptions"])
    assert next(c for c in result["checks"] if c["id"] == "reports")["result"] == "unknown"
