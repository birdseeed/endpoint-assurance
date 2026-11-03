"""
PAT-670 — trial expiry scheduler + upgrade email.

Covers:
  * check_trial_expiry_emails skips trials where upgrade_email_sent_at is set
    (duplicate prevention).
  * check_trial_expiry_emails only emails trials not yet expired and not yet notified
    (expiry / filter logic).
  * Empty trial list results in no email sends (idempotency).
  * Graceful degradation when the platform API is unreachable.

Run with: pytest tests/test_trial_expiry.py -v
"""

import os
import sys
from unittest.mock import MagicMock, patch, call

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard


@pytest.fixture(autouse=True)
def _tmp_db(tmp_path, monkeypatch):
    """PAT-817: check_trial_expiry_emails now reads/writes the local
    trial_expiry_notifications idempotency table, so every test needs a real
    (temp) SQLite DB with the schema initialised."""
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()


# ── Helpers ──────────────────────────────────────────────────────────────────

def _make_trial(**kwargs):
    """Return a minimal trial dict; keyword args override defaults."""
    base = {
        "tenant_id": "tenant-uuid-001",
        "name": "Acme Corp",
        "trial_email": "admin@acme.example",
        "trial_expires_at": "2099-01-01T00:00:00Z",
        "upgrade_email_sent_at": None,
        "device_count": 3,
        "failing_eval_count": 7,
        "state": "expiring_soon",
    }
    base.update(kwargs)
    return base


def _ok_trials_response(trials):
    """Return a mock requests.Response carrying a trials payload."""
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"trials": trials}
    r.content = b"..."
    return r


def _error_response(status=500):
    r = MagicMock()
    r.status_code = status
    r.content = b"error"
    return r


def _notify_ok():
    r = MagicMock()
    r.status_code = 200
    r.content = b"{}"
    r.json.return_value = {}
    return r


# ── Test: empty trial list — no email sends ───────────────────────────────────

def test_empty_trial_list_sends_no_emails():
    """If the platform returns an empty trials list, _send_email is never called."""
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email") as mock_send:
        mock_http.get.return_value = _ok_trials_response([])
        dashboard.check_trial_expiry_emails()
        mock_send.assert_not_called()


# ── Test: duplicate prevention — upgrade_email_sent_at already set ───────────

def test_skips_trial_with_upgrade_email_already_sent():
    """Trials where upgrade_email_sent_at is set must be skipped."""
    already_sent = _make_trial(upgrade_email_sent_at="2026-07-01T08:00:00Z")
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email") as mock_send:
        mock_http.get.return_value = _ok_trials_response([already_sent])
        dashboard.check_trial_expiry_emails()
        mock_send.assert_not_called()


def test_sends_email_when_upgrade_email_not_yet_sent():
    """Trials with upgrade_email_sent_at=None and not expired must get an email."""
    trial = _make_trial()
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email", return_value=True) as mock_send:
        mock_http.get.return_value = _ok_trials_response([trial])
        mock_http.post.return_value = _notify_ok()
        dashboard.check_trial_expiry_emails()
        mock_send.assert_called_once()
        _, call_kwargs = mock_send.call_args[0], mock_send.call_args
        # First positional arg is to_email
        assert mock_send.call_args[0][0] == "admin@acme.example"


# ── Test: expiry filter — expired trials skipped ─────────────────────────────

def test_skips_expired_trials():
    """Trials with state=expired must be logged but not emailed."""
    expired = _make_trial(state="expired")
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email") as mock_send:
        mock_http.get.return_value = _ok_trials_response([expired])
        dashboard.check_trial_expiry_emails()
        mock_send.assert_not_called()


def test_mixed_trials_only_emails_eligible():
    """With one eligible and one already-notified trial, only one email is sent."""
    eligible = _make_trial(tenant_id="t1", trial_email="a@example.com")
    notified = _make_trial(tenant_id="t2", trial_email="b@example.com",
                           upgrade_email_sent_at="2026-07-01T08:00:00Z")
    expired = _make_trial(tenant_id="t3", trial_email="c@example.com", state="expired")

    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email", return_value=True) as mock_send:
        mock_http.get.return_value = _ok_trials_response([eligible, notified, expired])
        mock_http.post.return_value = _notify_ok()
        dashboard.check_trial_expiry_emails()
        assert mock_send.call_count == 1
        assert mock_send.call_args[0][0] == "a@example.com"


# ── Test: trial-notify POST called after successful email ────────────────────

def test_trial_notify_called_after_email_success():
    """After a successful email send, the platform trial-notify endpoint is called."""
    trial = _make_trial()
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email", return_value=True):
        mock_http.get.return_value = _ok_trials_response([trial])
        mock_http.post.return_value = _notify_ok()
        dashboard.check_trial_expiry_emails()
        # http.post must be called with the trial-notify URL
        post_call = mock_http.post.call_args
        assert post_call is not None
        assert "trial-notify" in post_call[0][0]
        assert trial["tenant_id"] in post_call[0][0]


def test_trial_notify_not_called_when_email_fails():
    """If email delivery fails, trial-notify must NOT be called."""
    trial = _make_trial()
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email", return_value=False):
        mock_http.get.return_value = _ok_trials_response([trial])
        dashboard.check_trial_expiry_emails()
        mock_http.post.assert_not_called()


# ── Test: graceful degradation when platform API unreachable ─────────────────

def test_degrades_gracefully_on_non_200_response():
    """A non-200 from the platform must not raise and must skip processing."""
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email") as mock_send:
        mock_http.get.return_value = _error_response(503)
        dashboard.check_trial_expiry_emails()
        mock_send.assert_not_called()


def test_degrades_gracefully_on_network_exception():
    """A network error fetching trials must not raise."""
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email") as mock_send:
        mock_http.get.side_effect = ConnectionError("unreachable")
        dashboard.check_trial_expiry_emails()
        mock_send.assert_not_called()


# ── Test: trial missing trial_email — skipped gracefully ────────────────────

def test_skips_trial_with_no_email_address():
    """A trial with no trial_email must be skipped without error."""
    no_email = _make_trial(trial_email=None)
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email") as mock_send:
        mock_http.get.return_value = _ok_trials_response([no_email])
        dashboard.check_trial_expiry_emails()
        mock_send.assert_not_called()


# ── Test: email subject and content ─────────────────────────────────────────

def test_email_subject_and_content():
    """The upgrade email must carry the correct subject and mention pricing URL."""
    trial = _make_trial(
        name="Widgets Ltd",
        trial_email="owner@widgets.example",
        trial_expires_at="2099-06-15T00:00:00Z",
        device_count=5,
        failing_eval_count=12,
    )
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email", return_value=True) as mock_send:
        mock_http.get.return_value = _ok_trials_response([trial])
        mock_http.post.return_value = _notify_ok()
        dashboard.check_trial_expiry_emails()

        assert mock_send.called
        to_email, subject, html, text = mock_send.call_args[0][:4]
        assert to_email == "owner@widgets.example"
        assert subject == "Your Patched trial expires in 2 days"
        assert "patched.im/pricing" in html
        assert "patched.im/pricing" in text
        assert "Widgets Ltd" in html
        assert "5 devices" in html
        assert "12 CVE findings" in html


# ── PAT-817: local idempotency ledger survives a trial-notify POST failure ────

def test_local_ledger_recorded_even_when_trial_notify_fails():
    """If the email sends successfully but the platform trial-notify POST fails,
    the local trial_expiry_notifications row must still be written — otherwise
    tomorrow's tick would see upgrade_email_sent_at still None and resend."""
    trial = _make_trial()
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email", return_value=True) as mock_send:
        mock_http.get.return_value = _ok_trials_response([trial])
        mock_http.post.return_value = _error_response(500)  # trial-notify fails
        dashboard.check_trial_expiry_emails()
        mock_send.assert_called_once()

    with dashboard.get_db() as db:
        row = db.execute(
            "SELECT 1 FROM trial_expiry_notifications WHERE tenant_id=? AND milestone=?",
            (trial["tenant_id"], "expires_2d"),
        ).fetchone()
    assert row is not None, "local ledger must record the send regardless of trial-notify outcome"


def test_local_ledger_recorded_when_trial_notify_throws():
    """A trial-notify POST that raises must not prevent the local ledger write."""
    trial = _make_trial()
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email", return_value=True):
        mock_http.get.return_value = _ok_trials_response([trial])
        mock_http.post.side_effect = ConnectionError("platform unreachable")
        dashboard.check_trial_expiry_emails()  # must not raise

    with dashboard.get_db() as db:
        row = db.execute(
            "SELECT 1 FROM trial_expiry_notifications WHERE tenant_id=? AND milestone=?",
            (trial["tenant_id"], "expires_2d"),
        ).fetchone()
    assert row is not None


def test_second_tick_skips_when_local_ledger_already_set_even_if_platform_flag_missing():
    """Simulates the PAT-817 failure scenario end-to-end: tick 1 sends the email
    and trial-notify fails, so the platform's upgrade_email_sent_at stays None.
    Tick 2 (next day) must NOT resend, because the local ledger already has the
    row — even though the platform-side flag never got set."""
    trial = _make_trial()  # upgrade_email_sent_at stays None throughout
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email", return_value=True) as mock_send:
        mock_http.get.return_value = _ok_trials_response([trial])
        mock_http.post.return_value = _error_response(500)
        dashboard.check_trial_expiry_emails()
        assert mock_send.call_count == 1

        # Tick 2: platform still reports upgrade_email_sent_at=None (trial-notify
        # never succeeded), but the local ledger must block a resend.
        dashboard.check_trial_expiry_emails()
        assert mock_send.call_count == 1, "must not double-send once the local ledger has the row"


def test_trial_with_no_tenant_id_is_skipped_without_crashing():
    """A malformed platform entry with no tenant_id must not blow up the local
    ledger INSERT (tenant_id is a NOT NULL PK column) and must not abort the
    loop before processing the remaining, well-formed trials."""
    no_tid = _make_trial(tenant_id=None, trial_email="orphan@example.com")
    good = _make_trial(tenant_id="t-good", trial_email="good@example.com")
    with patch.object(dashboard, "http") as mock_http, \
         patch.object(dashboard, "_send_email", return_value=True) as mock_send:
        mock_http.get.return_value = _ok_trials_response([no_tid, good])
        mock_http.post.return_value = _notify_ok()
        dashboard.check_trial_expiry_emails()  # must not raise
        assert mock_send.call_count == 1
        assert mock_send.call_args[0][0] == "good@example.com"
