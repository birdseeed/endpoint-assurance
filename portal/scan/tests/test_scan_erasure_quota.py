"""Synthetic rolling-window accounting after personal scan data is erased."""
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import shared

from test_scan_erasure import seed


@pytest.mark.parametrize("pending", [False, True])
@pytest.mark.parametrize("identity", ["email", "ip"])
def test_erasure_preserves_each_quota(db_conn, monkeypatch, pending, identity):
    monkeypatch.setattr(shared, "PUBLIC_RL_PER_EMAIL_24H", 2)
    monkeypatch.setattr(shared, "PUBLIC_RL_PER_IP_24H", 2)
    erased, _, report = seed(db_conn)
    seed(db_conn, "b" * 32)
    email = "fixture@example.invalid" if identity == "email" else "other@example.invalid"
    ip = "192.0.2.1" if identity == "ip" else "192.0.2.2"
    assert shared._check_rate_limits(email, ip)
    unlink = Path.unlink
    def fail_report(path, *args, **kwargs):
        if pending and path == report:
            raise PermissionError("synthetic failure")
        return unlink(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", fail_report)
        assert shared._erase_public_scan(erased) == ("pending" if pending else "deleted")
        assert shared._check_rate_limits(email, ip)
        if pending:
            assert shared._erase_public_scan(erased) == "pending"
            assert db_conn.execute("SELECT COUNT(*) FROM public_scan_erasure_limits").fetchone()[0] == 1
    # One identified request plus one erased request counts exactly twice.
    monkeypatch.setattr(shared, "PUBLIC_RL_PER_EMAIL_24H", 3)
    monkeypatch.setattr(shared, "PUBLIC_RL_PER_IP_24H", 3)
    assert shared._check_rate_limits(email, ip) is None
    if pending:
        assert shared._erase_public_scan(erased) == "deleted"
        assert db_conn.execute("SELECT COUNT(*) FROM public_scan_erasure_limits").fetchone()[0] == 1


def test_ledger_is_pseudonymous_and_keeps_original_window(db_conn, monkeypatch):
    scan_id, _, _ = seed(db_conn)
    created = (datetime.now(UTC) - timedelta(hours=23)).isoformat()
    db_conn.execute("UPDATE public_scans SET created_at=? WHERE id=?", (created, scan_id))
    db_conn.commit()
    assert shared._erase_public_scan(scan_id) == "deleted"
    row = dict(db_conn.execute("SELECT * FROM public_scan_erasure_limits").fetchone())
    assert set(row) == {"scan_hash", "created_at", "mac_key", "email_mac", "ip_mac"}
    assert row["created_at"] == created
    assert len(row["mac_key"]) == 32
    assert len(row["email_mac"]) == len(row["ip_mac"]) == 32
    serialized = repr(row)
    for raw in (scan_id, "fixture@example.invalid", "192.0.2.1", "Synthetic Company",
                "123456", "download-", "delete-"):
        assert raw not in serialized
    monkeypatch.setattr(shared, "PUBLIC_RL_PER_EMAIL_24H", 1)
    assert shared._check_rate_limits("fixture@example.invalid", "other")
    class Later(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime.now(UTC) + timedelta(hours=2)
    monkeypatch.setattr(shared, "datetime", Later)
    assert shared._check_rate_limits("fixture@example.invalid", "192.0.2.1") is None
    assert db_conn.execute("SELECT COUNT(*) FROM public_scan_erasure_limits").fetchone()[0] == 0


def test_sweep_purges_expired_accounting(db_conn):
    scan_id, _, _ = seed(db_conn)
    assert shared._erase_public_scan(scan_id) == "deleted"
    db_conn.execute("UPDATE public_scan_erasure_limits SET created_at=?",
                    ((datetime.now(UTC) - timedelta(hours=25)).isoformat(),))
    db_conn.commit()
    shared._public_retention_sweep()
    assert db_conn.execute("SELECT COUNT(*) FROM public_scan_erasure_limits").fetchone()[0] == 0


@pytest.mark.parametrize("already_erased", [False, True])
def test_legacy_or_expired_erasure_cannot_create_fresh_window(db_conn, already_erased):
    scan_id, _, _ = seed(db_conn, old=not already_erased, status="deleted")
    if already_erased:
        db_conn.execute("UPDATE public_scans SET email='', ip=NULL WHERE id=?", (scan_id,))
        db_conn.commit()
    assert shared._erase_public_scan(scan_id) == "deleted"
    assert db_conn.execute("SELECT COUNT(*) FROM public_scan_erasure_limits").fetchone()[0] == 0
