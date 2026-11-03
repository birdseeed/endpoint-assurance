"""Synthetic-only deletion and retention regressions; no service lifecycle/network."""
from datetime import UTC, datetime, timedelta
from pathlib import Path
import socket
import subprocess
import sys
import threading

import pytest
import requests
import shared


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError("Network forbidden in erasure tests")
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(requests.sessions.Session, "request", blocked)


def seed(db, scan_id="a" * 32, *, old=False, status="complete", deleted=False):
    now = datetime.now(UTC)
    created = (now - timedelta(days=40) if old else now).isoformat()
    upload = shared.PUBLIC_DIR / scan_id / "devices.csv"
    upload.parent.mkdir(parents=True, exist_ok=True)
    upload.write_text("synthetic inventory")
    report = shared.PUBLIC_REPORTS_DIR / f"Patched_CVE_Synthetic_{scan_id}.docx"
    report.write_text("synthetic report")
    db.execute(
        "INSERT INTO public_scans (id,email,company,ip,status,otp_code,otp_expires_at,"
        "devices_path,report_path,download_token,delete_token,error,job_id,created_at,deleted_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (scan_id, "fixture@example.invalid", "Synthetic Company", "192.0.2.1", status,
         "123456", (now - timedelta(hours=1)).isoformat(), str(upload), str(report),
         "download-" + scan_id, "delete-" + scan_id, "sensitive fixture error", "job-fixture",
         created, created if deleted else None),
    )
    db.commit()
    return scan_id, upload, report


def test_explicit_delete_erases_row_and_capabilities(client, db_conn):
    scan_id, upload, report = seed(db_conn)
    response = client.post(f"/public/scan/d/delete-{scan_id}")
    assert response.status_code == 200
    assert db_conn.execute("SELECT * FROM public_scans WHERE id=?", (scan_id,)).fetchone() is None
    assert not upload.exists() and not report.exists()
    for path in (f"/public/scan/r/download-{scan_id}", f"/public/scan/d/delete-{scan_id}",
                 f"/public/scan/status/{scan_id}", f"/public/scan/verify/{scan_id}"):
        assert client.get(path).status_code == 404
    assert client.post(f"/public/scan/d/delete-{scan_id}").status_code == 404
    assert client.post(f"/public/scan/verify/{scan_id}", data={"otp": "123456"}).status_code == 404


def test_sweep_cleans_old_and_legacy_deleted_but_keeps_fresh_and_waitlist(db_conn):
    old = seed(db_conn, "b" * 32, old=True)
    legacy = seed(db_conn, "c" * 32, status="deleted", deleted=True)
    fresh = seed(db_conn, "d" * 32)
    now = datetime.now(UTC).isoformat()
    db_conn.execute("INSERT INTO waitlist_signups (id,email,name,created_at) VALUES (?,?,?,?)",
                    ("waitlist", "waiting@example.invalid", "Synthetic", now))
    db_conn.commit()
    shared._public_retention_sweep()
    assert [r[0] for r in db_conn.execute("SELECT id FROM public_scans")] == [fresh[0]]
    for _, upload, report in (old, legacy):
        assert not upload.exists() and not report.exists()
    assert fresh[1].exists() and fresh[2].exists()
    assert db_conn.execute("SELECT COUNT(*) FROM waitlist_signups").fetchone()[0] == 1


def test_failed_unlink_scrubs_personal_fields_and_retries(client, db_conn, monkeypatch):
    scan_id, upload, report = seed(db_conn)
    unlink = Path.unlink
    def fail_report(path, *args, **kwargs):
        if path == report:
            raise PermissionError("synthetic failure")
        return unlink(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", fail_report)
        response = client.post(f"/public/scan/d/delete-{scan_id}")
        assert response.status_code == 503
        assert "removed" not in response.text.lower()
        row = db_conn.execute("SELECT * FROM public_scans WHERE id=?", (scan_id,)).fetchone()
        for field in ("email", "company", "ip", "otp_code", "otp_expires_at", "download_token", "job_id", "error"):
            assert not row[field]
        assert row["report_path"] == str(report)
        assert row["devices_path"] is None
        assert client.get(f"/public/scan/r/download-{scan_id}").status_code == 404
        assert "retry" in client.get(f"/public/scan/d/delete-{scan_id}").text.lower()
    shared._public_retention_sweep()
    assert db_conn.execute("SELECT * FROM public_scans WHERE id=?", (scan_id,)).fetchone() is None
    assert not report.exists()


def test_missing_files_are_success(client, db_conn):
    scan_id, upload, report = seed(db_conn)
    upload.unlink()
    report.unlink()
    assert client.post(f"/public/scan/d/delete-{scan_id}").status_code == 200
    assert db_conn.execute("SELECT * FROM public_scans WHERE id=?", (scan_id,)).fetchone() is None


@pytest.mark.parametrize("status", ["verified", "scanning"])
def test_active_worker_must_finish_before_erasure(client, db_conn, status):
    scan_id, upload, report = seed(db_conn, old=True, status=status)
    with shared._public_scan_lock(scan_id):
        assert client.post(f"/public/scan/d/delete-{scan_id}").status_code == 409
        shared._public_retention_sweep()
        assert upload.exists() and report.exists()
        assert db_conn.execute("SELECT status FROM public_scans WHERE id=?", (scan_id,)).fetchone()[0] == status
    # A stale status without a running worker is no obstacle to erasure.
    shared._public_retention_sweep()
    assert db_conn.execute("SELECT * FROM public_scans WHERE id=?", (scan_id,)).fetchone() is None


def test_deletion_never_unlinks_paths_outside_scan_ownership(client, db_conn, tmp_path):
    scan_id, _, _ = seed(db_conn)
    unrelated = tmp_path / "unrelated.txt"
    unrelated.write_text("must remain")
    db_conn.execute("UPDATE public_scans SET report_path=? WHERE id=?", (str(unrelated), scan_id))
    db_conn.commit()
    assert client.post(f"/public/scan/d/delete-{scan_id}").status_code == 503
    assert unrelated.read_text() == "must remain"


def test_expired_verification_then_erasure(client, db_conn):
    scan_id, _, _ = seed(db_conn, status="pending_verify")
    assert client.post(f"/public/scan/verify/{scan_id}", data={"otp": "123456"}).status_code == 410
    assert client.post(f"/public/scan/d/delete-{scan_id}").status_code == 200
    assert client.post(f"/public/scan/verify/{scan_id}", data={"otp": "123456"}).status_code == 404


def test_erased_scan_cannot_start_worker_or_send_mail(db_conn, monkeypatch):
    scan_id, _, _ = seed(db_conn, status="verified")
    assert shared._erase_public_scan(scan_id) == "deleted"
    def forbidden(*args, **kwargs):
        pytest.fail("Erased scan started work or attempted email")
    monkeypatch.setattr(shared, "run_report_job", forbidden)
    monkeypatch.setattr(shared, "_send_email", forbidden)
    shared._run_public_scan(scan_id)
    assert db_conn.execute("SELECT COUNT(*) FROM public_scans").fetchone()[0] == 0


def test_worker_keeps_failed_upload_unlink_for_erasure_retry(db_conn, monkeypatch):
    scan_id, upload, _ = seed(db_conn, status="verified")
    monkeypatch.setattr(shared, "run_report_job", lambda *a, **kw: shared.ReportJobOutcome(status="timeout"))
    monkeypatch.setattr(shared, "_send_email", lambda *a, **kw: True)
    unlink = Path.unlink
    def fail_upload(path, *args, **kwargs):
        if path == upload:
            raise PermissionError("synthetic failure")
        return unlink(path, *args, **kwargs)
    with monkeypatch.context() as patch:
        patch.setattr(Path, "unlink", fail_upload)
        shared._run_public_scan(scan_id)
    assert db_conn.execute("SELECT devices_path FROM public_scans WHERE id=?", (scan_id,)).fetchone()[0] == str(upload)
    assert shared._erase_public_scan(scan_id) == "deleted"
    assert not upload.exists()


def test_worker_and_erasure_exclude_each_other(client, db_conn, monkeypatch):
    scan_id, _, old_report = seed(db_conn, status="verified")
    old_report.unlink()
    entered = threading.Event()
    release = threading.Event()
    emails = []
    def generate(target, args, timeout, output, **kwargs):
        entered.set()
        assert release.wait(5)
        Path(output).write_text("synthetic generated report")
        return shared.ReportJobOutcome(status="done")
    monkeypatch.setattr(shared, "run_report_job", generate)
    monkeypatch.setattr(shared, "_send_email", lambda *a, **kw: emails.append(a) or True)
    worker = threading.Thread(target=shared._run_public_scan, args=(scan_id,))
    worker.start()
    try:
        assert entered.wait(5)
        assert client.post(f"/public/scan/d/delete-{scan_id}").status_code == 409
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
    assert len(emails) == 1
    report = db_conn.execute("SELECT report_path FROM public_scans WHERE id=?", (scan_id,)).fetchone()[0]
    assert client.post(f"/public/scan/d/delete-{scan_id}").status_code == 200
    assert not Path(report).exists()
    shared._run_public_scan(scan_id)
    assert len(emails) == 1


def test_lock_exclusion_across_processes(db_conn):
    scan_id, _, _ = seed(db_conn)
    script = "import sys; sys.path.insert(0, sys.argv[1]); import shared; print(shared._erase_public_scan(sys.argv[2]))"
    def erase_in_child():
        return subprocess.run(
            [sys.executable, "-c", script, str(shared.BASE), scan_id],
            capture_output=True, text=True, check=True, timeout=15,
        ).stdout.strip()
    with shared._public_scan_lock(scan_id):
        assert erase_in_child() == "busy"
    assert erase_in_child() == "deleted"
    assert db_conn.execute("SELECT COUNT(*) FROM public_scans").fetchone()[0] == 0


def test_orphan_writer_retains_erasure_guard_until_actual_child_exit(db_conn, tmp_path):
    import os
    import time

    scan_id, _, report = seed(db_conn, status="scanning")
    report.unlink()
    started = tmp_path / "orphan-started"
    release = tmp_path / "orphan-release"
    script = """
import sys
sys.path[:0] = [sys.argv[1], sys.argv[2]]
import shared
from _hardkill_targets import wait_for_release_then_write
with shared._public_scan_lock(sys.argv[3]) as guard:
    shared.run_report_job(wait_for_release_then_write,
                         tuple(sys.argv[4:7]), 15, sys.argv[4], guard_fd=guard.fileno())
"""
    parent = subprocess.Popen(
        [sys.executable, "-c", script, str(shared.BASE), str(Path(__file__).parent),
         scan_id, str(report), str(started), str(release)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    child_pid = None
    try:
        deadline = time.monotonic() + 5
        while not started.exists() and parent.poll() is None and time.monotonic() < deadline:
            time.sleep(0.02)
        assert started.exists(), f"synthetic supervisor exited: {parent.poll()}"
        child_pid = int(started.read_text())
        parent.kill()  # SIGKILL: no Python cleanup and no daemon-child shutdown.
        parent.wait(timeout=5)
        assert shared._erase_public_scan(scan_id) == "busy"
        assert db_conn.execute("SELECT id FROM public_scans WHERE id=?", (scan_id,)).fetchone()
        release.write_text("release synthetic child")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = shared._erase_public_scan(scan_id)
            if result == "deleted":
                break
            assert result == "busy"
            time.sleep(0.02)
        assert result == "deleted"
        child_pid = None  # The guarded writer has finished; do not signal a re-used PID.
        assert not report.exists()
        # An inherited lock must be released only after the child can no
        # longer write, not merely after the supervisor process is gone.
        time.sleep(0.1)
        assert not report.exists()
    finally:
        release.write_text("ensure synthetic child finishes")
        if parent.poll() is None:
            parent.kill()
            parent.wait(timeout=5)
        if child_pid is not None:
            try:
                os.kill(child_pid, 9)
            except ProcessLookupError:
                pass


@pytest.mark.parametrize("outcome", ["done", "error", "timeout"])
def test_guarded_job_outcomes_release_only_child_reference(db_conn, tmp_path, outcome):
    from _hardkill_targets import (
        raise_synthetic_failure, sleep_then_touch_sentinel, wait_for_release_then_write,
    )

    scan_id, _, report = seed(db_conn)
    report.unlink()
    if outcome == "done":
        release = tmp_path / "release"
        release.touch()
        target = wait_for_release_then_write
        args = (str(report), str(tmp_path / "started"), str(release))
        timeout = 5
    elif outcome == "error":
        target = raise_synthetic_failure
        args = ([], str(report), None)
        timeout = 5
    else:
        target = sleep_then_touch_sentinel
        args = ([], str(report), None, 1)
        timeout = 0.02
    with shared._public_scan_lock(scan_id) as guard:
        result = shared.run_report_job(target, args, timeout, str(report), guard_fd=guard.fileno())
        assert result.status == outcome
        # Child exit must not issue LOCK_UN against the parent's lock.
        assert shared._erase_public_scan(scan_id) == "busy"
    assert shared._erase_public_scan(scan_id) == "deleted"
    assert not report.exists()
    assert not Path(str(report) + ".sentinel").exists()


def test_guard_transfer_failure_cannot_start_writer_or_leak_lock(db_conn, monkeypatch):
    from _hardkill_targets import sleep_then_touch_sentinel

    scan_id, _, report = seed(db_conn)
    report.unlink()
    def transfer_failure(fd):
        raise RuntimeError("synthetic guard transfer failure")
    with monkeypatch.context() as patch:
        patch.setattr(shared._mp_reduction, "DupFd", transfer_failure)
        with pytest.raises(RuntimeError, match="synthetic guard transfer failure"):
            with shared._public_scan_lock(scan_id) as guard:
                shared.run_report_job(sleep_then_touch_sentinel, ([], str(report), None, 0),
                                      5, str(report), guard_fd=guard.fileno())
    assert not report.exists()
    assert not Path(str(report) + ".sentinel").exists()
    assert shared._erase_public_scan(scan_id) == "deleted"
