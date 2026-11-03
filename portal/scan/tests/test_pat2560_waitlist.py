"""PAT-2560: the Mac app waitlist has a route, a stored list and a page of its own.

The waitlist count decides whether the app is built (300 sign ups within two
weeks of the first public post), so these tests hold the properties the count
depends on:

* one row per person, however many times they submit;
* a repeat submission is indistinguishable from a first one;
* a bot that fills the honeypot leaves no trace;
* the list survives the retention sweep, and its rate-limit ledger does not;
* a mailer that has died does not hide sign ups, and does not look healthy.
"""

import csv
import importlib.util
import io
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

SCAN_DIR = Path(__file__).resolve().parent.parent


# ── helpers ──────────────────────────────────────────────────────────────────
def _submit(client, **overrides):
    data = {
        "name": "Sam",
        "email": "sam@example.test",
        "devices": "2",
        "tool": "MacUpdater, until it closed",
        "website": "",  # honeypot, empty for a genuine submission
    }
    data.update(overrides)
    return client.post("/public/waitlist", data=data)


def _rows(db_conn, table="waitlist_signups"):
    return db_conn.execute(f"SELECT * FROM {table} ORDER BY created_at").fetchall()


@pytest.fixture
def mail(monkeypatch):
    """Record what the route asks the mailer to send. `mail.ok = False` makes
    every send fail the way _send_email does: it returns False."""
    import router

    class Mail:
        ok = True
        sent: list

    box = Mail()
    box.sent = []

    def _send(to_email, subject, html, text, attachment_path=None,
              attachment_name=None, bcc=None):
        box.sent.append({"to": to_email, "subject": subject, "html": html, "text": text})
        return box.ok

    monkeypatch.setattr(router, "_send_email", _send)

    # The waitlist must never reach for the enquiry form's Graph-only call: on
    # a box that sends through SendGrid that call fails every time.
    def _never(*_a, **_k):
        raise AssertionError("the waitlist route called _graph_send_mail directly")

    monkeypatch.setattr(router, "_graph_send_mail", _never)
    return box


def _load_cli():
    spec = importlib.util.spec_from_file_location("waitlist_cli", SCAN_DIR / "bin" / "waitlist.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ── a real sign up ───────────────────────────────────────────────────────────
def test_a_sign_up_is_stored_announced_and_thanked(client, db_conn, mail):
    resp = _submit(client)
    assert resp.status_code == 200

    rows = _rows(db_conn)
    assert len(rows) == 1
    row = rows[0]
    assert (row["email"], row["name"], row["devices"], row["tool"]) == (
        "sam@example.test", "Sam", "2", "MacUpdater, until it closed")
    assert row["notified_at"], "a delivered notification is recorded on the row"

    assert len(mail.sent) == 1
    assert mail.sent[0]["to"] == "hello@patched.im"
    assert mail.sent[0]["subject"] == "Waitlist sign up 1: Sam"
    assert "sam@example.test" in mail.sent[0]["text"]
    assert "MacUpdater, until it closed" in mail.sent[0]["text"]


def test_the_subject_carries_the_running_total(client, mail):
    for n, address in enumerate(("a@example.test", "b@example.test", "c@example.test"), 1):
        _submit(client, email=address, name=f"Person{n}")
    assert [m["subject"] for m in mail.sent] == [
        "Waitlist sign up 1: Person1",
        "Waitlist sign up 2: Person2",
        "Waitlist sign up 3: Person3",
    ]


def test_the_page_is_about_the_mac_app_and_nothing_else(client, mail):
    text = _submit(client).text
    assert "Thanks, Sam. You are on the list." in text
    assert "Patched is still being built." in text
    assert "you will be taken off the list" in text
    lowered = text.lower()
    # It is not an enquiry, there is nothing to buy or try, and the service
    # that used to live at this address is not mentioned.
    for stale in ("enquiry", "pricing", "trial", "estate", "endpoint", "download",
                  "customer login", "docs.patched.im", "status.patched.im"):
        assert stale not in lowered, stale
    assert "—" not in text and "–" not in text
    assert 'href="https://patched.im/#waitlist">Join the waitlist</a>' in text
    assert '<meta name="robots" content="noindex,nofollow">' in text


def test_the_name_is_escaped_on_the_page_and_in_the_email(client, mail):
    resp = _submit(client, name="<script>alert(1)</script>")
    assert resp.status_code == 200
    assert "<script>alert(1)</script>" not in resp.text
    assert "&lt;script&gt;" in resp.text
    assert "<script>" not in mail.sent[0]["html"]


# ── one row per person ───────────────────────────────────────────────────────
def test_a_repeat_sign_up_stores_nothing_new_and_looks_identical(client, db_conn, mail):
    first = _submit(client)
    second = _submit(client, devices="9", tool="Something else")

    assert second.status_code == first.status_code == 200
    assert second.text == first.text, "a repeat must not be distinguishable from a first sign up"

    rows = _rows(db_conn)
    assert len(rows) == 1
    assert rows[0]["devices"] == "2", "the first answers stand; a repeat does not overwrite them"
    assert len(mail.sent) == 1, "a repeat is not announced and does not move the total"


def test_the_same_address_in_another_case_is_the_same_person(client, db_conn, mail):
    _submit(client, email="Sam@Example.Test")
    _submit(client, email="  sam@example.test  ")
    rows = _rows(db_conn)
    assert [r["email"] for r in rows] == ["sam@example.test"]
    assert len(mail.sent) == 1


# ── the honeypot ─────────────────────────────────────────────────────────────
def test_a_filled_honeypot_leaves_no_trace(client, db_conn, mail):
    real = _submit(client, email="real@example.test")
    bot = _submit(client, email="bot@example.test", website="https://spam.example")

    assert bot.status_code == 200
    assert "You are on the list." in bot.text
    assert bot.text == real.text.replace("real@example.test", "bot@example.test")
    assert [r["email"] for r in _rows(db_conn)] == ["real@example.test"]
    assert [r["email"] for r in _rows(db_conn, "waitlist_attempts")] == ["real@example.test"]
    assert len(mail.sent) == 1


# ── refusals say why, and store nothing ──────────────────────────────────────
@pytest.mark.parametrize("fields, reason", [
    ({"name": ""}, "Please give a first name."),
    ({"name": "   "}, "Please give a first name."),
    ({"name": "x" * 101}, "That name is too long."),
    ({"email": ""}, "Please give a valid email address."),
    ({"email": "not-an-email"}, "Please give a valid email address."),
    ({"email": "a" * 250 + "@example.test"}, "Please give a valid email address."),
])
def test_a_bad_submission_is_refused_with_a_reason(client, db_conn, mail, fields, reason):
    resp = _submit(client, **fields)
    assert resp.status_code == 400
    assert "That did not go through" in resp.text
    assert reason in resp.text
    assert "You are on the list." not in resp.text
    assert _rows(db_conn) == []
    assert _rows(db_conn, "waitlist_attempts") == []
    assert mail.sent == []


def test_missing_fields_are_a_page_not_a_json_error(client, db_conn, mail):
    resp = client.post("/public/waitlist", data={})
    assert resp.status_code == 400
    assert "That did not go through" in resp.text
    assert resp.headers["content-type"].startswith("text/html")


def test_long_optional_answers_are_cut_not_refused(client, db_conn, mail):
    resp = _submit(client, devices="d" * 500, tool="t" * 500)
    assert resp.status_code == 200
    row = _rows(db_conn)[0]
    assert len(row["devices"]) == 200 and len(row["tool"]) == 200


def test_newlines_cannot_reach_the_subject_line(client, db_conn, mail):
    _submit(client, name="Sam\r\nBcc: someone@example.test")
    assert "\n" not in mail.sent[0]["subject"] and "\r" not in mail.sent[0]["subject"]
    assert _rows(db_conn)[0]["name"] == "Sam Bcc: someone@example.test"


# ── rate limits ──────────────────────────────────────────────────────────────
def test_the_email_limit_is_visible_and_counts_repeats(client, db_conn, mail):
    for _ in range(3):
        assert _submit(client).status_code == 200
    resp = _submit(client)
    assert resp.status_code == 429
    assert "too many tries from this email address" in resp.text
    assert "That did not go through" in resp.text
    assert len(_rows(db_conn)) == 1
    assert len(_rows(db_conn, "waitlist_attempts")) == 3


def test_the_network_limit_is_visible(client, db_conn, mail):
    for n in range(10):
        assert _submit(client, email=f"p{n}@example.test").status_code == 200
    resp = _submit(client, email="p10@example.test")
    assert resp.status_code == 429
    assert "too many tries from this network" in resp.text
    assert len(_rows(db_conn)) == 10


def test_the_limit_answers_a_stranger_and_a_member_alike(client, db_conn, mail):
    """Three tries from an address already on the list, and three from one that
    never got on it (the honeypot aside, every counted try is a sign up), are
    refused with the same words: the refusal says nothing about membership."""
    for _ in range(3):
        _submit(client, email="member@example.test")
    member = _submit(client, email="member@example.test")

    # Empty the list but keep the ledger: this address is now a stranger with
    # the same three counted tries.
    db_conn.execute("DELETE FROM waitlist_signups")
    db_conn.commit()
    stranger = _submit(client, email="member@example.test")

    assert member.status_code == stranger.status_code == 429
    assert member.text == stranger.text


# ── what is kept, and for how long ───────────────────────────────────────────
def test_the_list_holds_no_ip_address(db_conn):
    columns = {r[1] for r in db_conn.execute("PRAGMA table_info(waitlist_signups)")}
    assert columns == {"id", "email", "name", "devices", "tool", "created_at", "notified_at"}


def test_the_email_address_is_unique_in_the_schema(db_conn):
    db_conn.execute(
        "INSERT INTO waitlist_signups (id, email, name, created_at) "
        "VALUES ('1','x@example.test','X','t')")
    with pytest.raises(sqlite3.IntegrityError):
        db_conn.execute(
            "INSERT INTO waitlist_signups (id, email, name, created_at) "
            "VALUES ('2','x@example.test','X','t')")


def test_the_retention_sweep_keeps_the_list_and_purges_the_ledger(client, db_conn, mail):
    import shared

    _submit(client, email="old@example.test")
    _submit(client, email="new@example.test")
    long_ago = (datetime.now(UTC) - timedelta(days=shared.PUBLIC_RETENTION_DAYS + 400)).isoformat()
    db_conn.execute("UPDATE waitlist_signups SET created_at=? WHERE email='old@example.test'",
                    (long_ago,))
    db_conn.execute("UPDATE waitlist_attempts SET created_at=? WHERE email='old@example.test'",
                    (long_ago,))
    db_conn.commit()

    shared._public_retention_sweep()

    assert sorted(r["email"] for r in _rows(db_conn)) == ["new@example.test", "old@example.test"]
    assert [r["email"] for r in _rows(db_conn, "waitlist_attempts")] == ["new@example.test"]


# ── a dead mailer ────────────────────────────────────────────────────────────
def test_a_failed_notification_does_not_lose_or_hide_the_sign_up(client, db_conn, mail, capsys):
    mail.ok = False
    resp = _submit(client)

    assert resp.status_code == 200
    assert "You are on the list." in resp.text, "the person is on the list, so they are told so"
    rows = _rows(db_conn)
    assert len(rows) == 1 and rows[0]["notified_at"] is None
    assert "notification email was not sent" in capsys.readouterr().out
    assert client.get("/healthz").json()["waitlist_unnotified"] == 1

    # The next sign up, with mail working again, carries the true total.
    mail.ok = True
    _submit(client, email="next@example.test", name="Next")
    assert mail.sent[-1]["subject"] == "Waitlist sign up 2: Next"
    assert client.get("/healthz").json()["waitlist_unnotified"] == 1


def test_healthz_reports_zero_when_mail_works_and_never_the_list_size(client, mail):
    for n in range(4):
        _submit(client, email=f"h{n}@example.test")
    body = client.get("/healthz").json()
    assert body["waitlist_unnotified"] == 0
    assert 4 not in [v for k, v in body.items() if k.startswith("waitlist")]
    assert [k for k in body if k.startswith("waitlist")] == ["waitlist_unnotified"]


def test_healthz_says_minus_one_when_the_list_cannot_be_read(client, db_conn):
    db_conn.execute("DROP TABLE waitlist_signups")
    db_conn.commit()
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json()["waitlist_unnotified"] == -1


# ── the route itself ─────────────────────────────────────────────────────────
def test_a_get_goes_back_to_the_form(client):
    resp = client.get("/public/waitlist", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "https://patched.im/#waitlist"


def test_the_old_enquiry_route_is_untouched(client, db_conn, monkeypatch):
    import router

    monkeypatch.setattr(router, "_graph_send_mail", lambda *a, **k: True)
    resp = client.post("/public/pricing-enquiry", data={
        "name": "Jo", "email": "jo@example.test", "organisation": "Mac app waitlist"})
    assert resp.status_code == 200
    assert _rows(db_conn) == [], "the enquiry route never writes to the waitlist"
    assert len(_rows(db_conn, "public_pricing_enquiries")) == 1


# ── the operator's tool ──────────────────────────────────────────────────────
def test_cli_count_and_remove(client, db_conn, mail, capsys):
    import shared

    cli = _load_cli()
    for n in range(3):
        _submit(client, email=f"c{n}@example.test")
    db = str(shared.DB_PATH)

    assert cli.main(["--db", db, "count"]) == 0
    assert "on the list: 3" in capsys.readouterr().out

    assert cli.main(["--db", db, "remove", " C1@Example.Test "]) == 0
    out = capsys.readouterr().out
    assert "removed c1@example.test" in out and "On the list: 2" in out
    assert sorted(r["email"] for r in _rows(db_conn)) == ["c0@example.test", "c2@example.test"]
    assert "c1@example.test" not in [r["email"] for r in _rows(db_conn, "waitlist_attempts")]

    # Removing someone who is not there is said plainly and exits non-zero.
    assert cli.main(["--db", db, "remove", "nobody@example.test"]) == 1
    assert "was not on the list" in capsys.readouterr().out


def test_cli_count_since_reads_the_test_window(client, db_conn, mail, capsys):
    import shared

    cli = _load_cli()
    _submit(client, email="before@example.test")
    _submit(client, email="after@example.test")
    db_conn.execute("UPDATE waitlist_signups SET created_at='2026-10-01T09:00:00+00:00' "
                    "WHERE email='before@example.test'")
    db_conn.execute("UPDATE waitlist_signups SET created_at='2026-10-21T09:00:00+00:00' "
                    "WHERE email='after@example.test'")
    db_conn.commit()

    assert cli.main(["--db", str(shared.DB_PATH), "count",
                     "--since", "2026-10-20T00:00:00+00:00"]) == 0
    out = capsys.readouterr().out
    assert "on the list: 2" in out
    assert "since 2026-10-20T00:00:00+00:00: 1" in out


def test_cli_export_neutralises_spreadsheet_formulas(client, db_conn, mail, capsys):
    import shared

    cli = _load_cli()
    _submit(client, name="=HYPERLINK(1)", tool="@SUM(1)", devices="-1")
    assert cli.main(["--db", str(shared.DB_PATH), "export"]) == 0
    rows = list(csv.reader(io.StringIO(capsys.readouterr().out)))
    assert rows[0] == ["created_at", "name", "email", "devices", "tool", "notified_at"]
    record = dict(zip(rows[0], rows[1], strict=True))
    assert record["name"] == "'=HYPERLINK(1)"
    assert record["tool"] == "'@SUM(1)"
    assert record["devices"] == "'-1"
    assert record["email"] == "sam@example.test"


def test_cli_refuses_a_database_that_is_not_there(tmp_path):
    cli = _load_cli()
    with pytest.raises(SystemExit) as exc:
        cli.main(["--db", str(tmp_path / "nope.db"), "count"])
    assert "no database" in str(exc.value)
