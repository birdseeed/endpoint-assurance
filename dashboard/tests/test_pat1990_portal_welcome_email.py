"""
PAT-1990 — Customer Access: verified welcome email after Cloudflare Access
(One-time PIN) is confirmed.

Extends PAT-128's Customer Access tab with a "Send welcome" action that emails
a design partner their portal sign-in instructions — but only after the exact
address has been confirmed live against the app.patched.im Cloudflare Access
Allow policy, because One-time PIN is the only login method enabled there and
identity is therefore the exact email string in the policy.

Covers the ticket's acceptance criteria one test class each:
  * refuses when the email is not in the Cloudflare Allow policy, and says why
  * refuses role/shared addresses ("Named individuals only")
  * a confirmation step repeats tenant + recipient before anything is sent
  * welcomed_at/welcomed_by are written ONLY after a confirmed successful send
    (the PAT-815 shape: a failed send must not be recorded as a success)
  * EMAIL_DRY_RUN is respected and surfaced
  * every attempt and outcome lands in the access audit trail
  * Reply-To is andy@patched.im and the sender stays noreply@patched.im

Run with: pytest tests/test_pat1990_portal_welcome_email.py -v
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
import shared as dashboard_shared  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

_AUTH = {"Authorization": "Bearer test-key"}
_TENANT = "a5effb0c-c4c3-5d57-af50-5c7fd102599e"
_EMAIL = "jane@client.com"
_BASE = f"/admin/tenants/{_TENANT}/portal-users/{_EMAIL}"
_CONFIRM = {"X-Confirm-Resource": _EMAIL}


def _mock_upstream(payload, status=200):
    m = MagicMock()
    m.status_code = status
    m.content = json.dumps(payload).encode() if payload is not None else b""
    m.json.return_value = payload
    m.text = json.dumps(payload) if payload is not None else ""
    return m


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    # The Cloudflare read credential the portal_auth monitor (PAT-1712/837)
    # already uses. No new credential is introduced by this feature.
    monkeypatch.setattr(dashboard, "CLOUDFLARE_API_TOKEN", "cf-token")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCOUNT_ID", "cf-account")
    monkeypatch.setattr(dashboard, "CLOUDFLARE_ACCESS_APP_ID", "cf-app")
    # Andy's manual pre-flight value. Set here so the tests exercise the
    # normal path; TestCloudflareSenderPlaceholder covers it being unset.
    monkeypatch.setattr(dashboard, "PORTAL_WELCOME_CLOUDFLARE_SENDER", "noreply@notify.cloudflare.com")
    # Delivery live by default; TestDryRun flips it.
    monkeypatch.setattr(dashboard_shared, "EMAIL_DRY_RUN", False)
    monkeypatch.setattr(dashboard_shared, "GRAPH_MAIL_TENANT_ID", "t")
    monkeypatch.setattr(dashboard_shared, "GRAPH_MAIL_CLIENT_ID", "c")
    monkeypatch.setattr(dashboard_shared, "GRAPH_MAIL_CLIENT_SECRET", "s")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _seed_client(tenant_id=_TENANT, company="Acme Ltd"):
    with dashboard.get_db() as db:
        db.execute(
            "INSERT INTO clients (id, company, tenant_id, created_at) VALUES (?,?,?,?)",
            ("id-1", company, tenant_id, datetime.now(timezone.utc).isoformat()),
        )


def _welcome_audit(cols="*"):
    with dashboard.get_db() as db:
        return [dict(r) for r in db.execute(f"SELECT {cols} FROM portal_welcome_audit_log").fetchall()]


def _welcome_state(tenant_id=_TENANT, email=_EMAIL):
    with dashboard.get_db() as db:
        rows = db.execute(
            "SELECT * FROM portal_user_welcomes WHERE tenant_id=? AND email=?",
            (tenant_id, email.lower()),
        ).fetchall()
    return [dict(r) for r in rows]


def _admin_audit(cols="*"):
    with dashboard.get_db() as db:
        return [dict(r) for r in db.execute(f"SELECT {cols} FROM admin_audit_log").fetchall()]


# ── Upstream / Cloudflare fakes ───────────────────────────────────────────────

_PORTAL_USER_LIST = {
    "users": [{"email": _EMAIL, "tenant_id": _TENANT,
               "created_at": "2026-09-01T00:00:00Z", "disabled_at": None}],
    "total": 1,
}


def _cf_policies(include_emails, decision="allow", exclude_emails=(), require=None, name="Patched staff and customers"):
    policy = {
        "id": "pol-1",
        "name": name,
        "decision": decision,
        "include": [{"email": {"email": e}} for e in include_emails],
        "exclude": [{"email": {"email": e}} for e in exclude_emails],
    }
    if require:
        policy["require"] = require
    return {"success": True, "result": [policy]}


def _fake_get(portal_users=None, cf_payload=None, cf_status=200, portal_status=200):
    """One requests.get stand-in that routes by URL: the go-service portal-users
    list vs. the Cloudflare Access policies endpoint."""
    portal_users = portal_users if portal_users is not None else _PORTAL_USER_LIST
    cf_payload = cf_payload if cf_payload is not None else _cf_policies([_EMAIL])

    def get(url, **kwargs):
        if "api.cloudflare.com" in url:
            return _mock_upstream(cf_payload, status=cf_status)
        return _mock_upstream(portal_users, status=portal_status)
    return get


def _post_welcome(client, body=None, headers=None, email=_EMAIL):
    base = f"/admin/tenants/{_TENANT}/portal-users/{email}"
    return client.post(
        base + "/welcome",
        json=body if body is not None else {"first_name": "Jane"},
        headers={**_AUTH, "X-Confirm-Resource": email, **(headers or {})},
    )


# ══════════════════════════════════════════════════════════════════════════════
# Acceptance: refuses when the email is not in the Cloudflare Allow policy
# ══════════════════════════════════════════════════════════════════════════════

class TestCloudflarePrecondition:
    def test_refuses_when_email_absent_from_allow_policy(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(cf_payload=_cf_policies(["someone.else@client.com"]))), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 412
        assert "not in any Include rule" in r.json()["error"]
        send.assert_not_called()
        assert _welcome_state() == []

    def test_refusal_says_why(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(cf_payload=_cf_policies([]))), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            r = _post_welcome(client)
        body = r.json()["error"]
        assert _EMAIL in body
        assert "Add the exact address in Cloudflare first" in body
        assert body == _welcome_audit("detail")[0]["detail"]

    def test_domain_rule_is_not_evidence_for_an_individual(self, client):
        # An email_domain include authorises "anyone at this domain", which is
        # not the claim this gate makes. Must not count.
        _seed_client()
        cf = _cf_policies([])
        cf["result"][0]["include"] = [{"email_domain": {"domain": "client.com"}}]
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get(cf_payload=cf)), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 412
        send.assert_not_called()

    def test_everyone_rule_is_not_evidence_for_an_individual(self, client):
        _seed_client()
        cf = _cf_policies([])
        cf["result"][0]["include"] = [{"everyone": {}}]
        with patch.object(dashboard.http, "get", side_effect=_fake_get(cf_payload=cf)), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            r = _post_welcome(client)
        assert r.status_code == 412

    def test_match_is_case_insensitive(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(cf_payload=_cf_policies(["JANE@Client.COM"]))), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 200, r.text
        send.assert_called_once()

    def test_non_allow_policy_does_not_count(self, client):
        # The address sits in a Bypass/Deny policy's include. Not an Allow.
        _seed_client()
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(cf_payload=_cf_policies([_EMAIL], decision="deny"))), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            r = _post_welcome(client)
        assert r.status_code == 502
        assert "no Allow policy" in r.json()["error"]

    def test_explicit_exclude_overrides_include(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(
                              cf_payload=_cf_policies([_EMAIL], exclude_emails=[_EMAIL]))), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 412
        assert "explicitly excluded" in r.json()["error"]
        send.assert_not_called()

    def test_cloudflare_unreachable_fails_closed(self, client):
        _seed_client()
        send = MagicMock(return_value=True)

        def get(url, **kwargs):
            if "api.cloudflare.com" in url:
                raise RuntimeError("connection reset")
            return _mock_upstream(_PORTAL_USER_LIST)

        with patch.object(dashboard.http, "get", side_effect=get), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 502
        send.assert_not_called()
        assert _welcome_audit("outcome")[0]["outcome"] == "failed"

    def test_missing_cloudflare_credential_fails_closed(self, client, monkeypatch):
        _seed_client()
        monkeypatch.setattr(dashboard, "CLOUDFLARE_API_TOKEN", "")
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 502
        assert "CLOUDFLARE_API_TOKEN" in r.json()["error"]
        send.assert_not_called()

    def test_cloudflare_non_200_fails_closed(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get(cf_status=403)), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 502
        send.assert_not_called()

    def test_helper_reports_require_block_without_overclaiming(self, client):
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(
                              cf_payload=_cf_policies([_EMAIL], require=[{"geo": {"country_code": "GB"}}]))):
            ok, detail = dashboard._cf_access_email_authorised(_EMAIL)
        assert ok is True
        assert "Require block" in detail
        assert "does not evaluate" in detail


# ══════════════════════════════════════════════════════════════════════════════
# Acceptance: refuses shared or role addresses
# ══════════════════════════════════════════════════════════════════════════════

class TestNamedIndividualsOnly:
    @pytest.mark.parametrize("local", [
        "it", "admin", "support", "info", "helpdesk",
        "security", "office", "accounts", "team", "all",
    ])
    def test_every_denylisted_local_part_is_refused(self, client, local):
        _seed_client()
        addr = f"{local}@client.com"
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(cf_payload=_cf_policies([addr]))), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client, email=addr)
        assert r.status_code == 422
        assert "Named individuals only" in r.json()["error"]
        send.assert_not_called()

    def test_denylist_is_case_insensitive(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            r = _post_welcome(client, email="IT@Client.com")
        assert r.status_code == 422

    def test_plus_addressed_role_mailbox_is_refused(self, client):
        # support+acme@ reaches the same shared mailbox as support@.
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            r = _post_welcome(client, email="support+acme@client.com")
        assert r.status_code == 422

    def test_named_individual_is_not_refused(self, client):
        assert dashboard._portal_welcome_role_address("jane@client.com") is None
        # A local part that merely contains a denylisted word is a real person.
        assert dashboard._portal_welcome_role_address("info.smith@client.com") is None
        assert dashboard._portal_welcome_role_address("adminah@client.com") is None

    def test_denylist_refusal_precedes_any_upstream_call(self, client):
        # Local, definitive and permanent: no reason to spend a Cloudflare or
        # go-service call on an address that can never be welcomed.
        _seed_client()
        get_mock = MagicMock()
        with patch.object(dashboard.http, "get", get_mock), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            r = _post_welcome(client, email="admin@client.com")
        assert r.status_code == 422
        get_mock.assert_not_called()

    def test_console_surfaces_named_individuals_only_in_the_add_form(self, client):
        html = client.get("/console").text
        assert "Named individuals only" in html
        for local in ("it@", "admin@", "support@", "helpdesk@", "accounts@"):
            assert local in html


# ══════════════════════════════════════════════════════════════════════════════
# Acceptance: a confirmation step shows tenant and recipient before sending
# ══════════════════════════════════════════════════════════════════════════════

class TestConfirmationStep:
    def test_send_is_confirm_gated_server_side(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", send):
            r = client.post(_BASE + "/welcome", json={"first_name": "Jane"}, headers=_AUTH)
        assert r.status_code == 428
        assert "Confirmation required" in r.json()["error"]
        send.assert_not_called()

    def test_wrong_confirm_value_is_rejected(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client, headers={"X-Confirm-Resource": "someone.else@client.com"})
        assert r.status_code == 409
        send.assert_not_called()

    def test_confirm_rule_and_destructive_classification_are_registered(self):
        path = f"/admin/tenants/{_TENANT}/portal-users/{_EMAIL}/welcome"
        assert dashboard._is_destructive("POST", path)
        assert dashboard._confirm_rule("POST", path) == ("portal_recipient", _EMAIL)
        # Owner-only, matching PAT-128's grant/revoke bar.
        assert not dashboard._consultant_write_allowed("POST", path)

    def test_confirm_resource_accepts_percent_encoded_ident(self):
        vals = dashboard._resolve_confirm_resource("portal_recipient", "jane%40client.com")
        assert _EMAIL in vals

    def test_preflight_context_repeats_tenant_recipient_and_purpose(self, client):
        _seed_client(company="Acme Ltd")
        with patch.object(dashboard.http, "get", side_effect=_fake_get()):
            r = client.get(_BASE + "/welcome-context", headers=_AUTH)
        ctx = r.json()
        assert r.status_code == 200
        assert ctx["can_send"] is True
        assert ctx["tenant_name"] == "Acme Ltd"
        assert ctx["recipient"] == _EMAIL
        assert ctx["subject"] == "Your Patched portal access"
        assert ctx["reply_to"] == "andy@patched.im"
        assert ctx["sender"] == "noreply@patched.im"
        assert ctx["cloudflare_verified"] is True

    def test_preflight_refuses_and_explains_without_sending(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(cf_payload=_cf_policies([]))), \
             patch.object(dashboard, "_send_email", send):
            r = client.get(_BASE + "/welcome-context", headers=_AUTH)
        ctx = r.json()
        assert ctx["can_send"] is False
        assert "not in any Include rule" in ctx["reason"]
        send.assert_not_called()
        # A preflight read changes nothing and writes no send-attempt row.
        assert _welcome_audit() == []

    def test_console_confirm_modal_repeats_tenant_recipient_and_effect(self, client):
        html = client.get("/console").text
        assert "function _caSendWelcome(" in html
        assert "/welcome-context" in html
        assert "This sends portal access instructions to" in html
        assert "'X-Confirm-Resource': typedEmail" in html
        assert "confirmWord: ctx.recipient" in html

    def test_console_offers_send_and_resend_actions(self, client):
        html = client.get("/console").text
        assert "_caSendWelcome(this.dataset.email)" in html
        assert "'Resend welcome' : 'Send welcome'" in html
        assert ">Welcome sent<" in html


# ══════════════════════════════════════════════════════════════════════════════
# Acceptance: state only on success (the PAT-815 shape)
# ══════════════════════════════════════════════════════════════════════════════

class TestStateOnlyOnSuccess:
    def test_successful_send_records_welcomed_at_and_by(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            r = _post_welcome(client)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["ok"] is True and body["state_recorded"] is True
        rows = _welcome_state()
        assert len(rows) == 1
        assert rows[0]["welcomed_at"] == body["welcomed_at"]
        assert rows[0]["welcomed_by"] == "bearer-token"

    def test_failed_send_leaves_state_unchanged_and_shows_the_error(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=False)):
            r = _post_welcome(client)
        assert r.status_code == 502
        assert "Email delivery failed" in r.json()["error"]
        assert "still unwelcomed" in r.json()["error"]
        assert _welcome_state() == []

    def test_mail_provider_exception_leaves_state_unchanged(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(side_effect=RuntimeError("graph 500"))):
            r = _post_welcome(client)
        assert r.status_code == 502
        assert "graph 500" in r.json()["error"]
        assert _welcome_state() == []

    def test_failed_send_after_a_success_does_not_clear_or_advance_state(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            first = _post_welcome(client)
        assert first.status_code == 200
        original = _welcome_state()[0]

        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=False)):
            second = _post_welcome(client)
        assert second.status_code == 502
        assert _welcome_state()[0] == original

    def test_resend_repeats_the_cloudflare_check(self, client):
        # Membership can be removed between the first send and the second, so
        # a resend that skipped the check would assert something stale.
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            assert _post_welcome(client).status_code == 200

        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(cf_payload=_cf_policies([]))), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 412
        send.assert_not_called()

    def test_successful_resend_advances_the_timestamp(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            first = _post_welcome(client)
            time.sleep(0.01)
            second = _post_welcome(client)
        assert first.status_code == 200 and second.status_code == 200
        assert len(_welcome_state()) == 1
        assert _welcome_state()[0]["welcomed_at"] == second.json()["welcomed_at"]
        assert second.json()["welcomed_at"] > first.json()["welcomed_at"]

    def test_non_member_of_this_tenant_is_refused(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(portal_users={"users": [], "total": 0})), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 404
        send.assert_not_called()

    def test_disabled_portal_user_is_refused(self, client):
        _seed_client()
        disabled = {"users": [{"email": _EMAIL, "tenant_id": _TENANT,
                               "created_at": "2026-09-01T00:00:00Z",
                               "disabled_at": "2026-09-10T00:00:00Z"}], "total": 1}
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get(portal_users=disabled)), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 409
        send.assert_not_called()

    def test_upstream_membership_error_fails_closed_as_502(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get(portal_status=500)), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 502
        send.assert_not_called()

    def test_first_name_is_required(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client, body={})
        assert r.status_code == 400
        send.assert_not_called()

    def test_welcome_state_is_listed_for_the_console(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            assert _post_welcome(client).status_code == 200
        r = client.get(f"/admin/tenants/{_TENANT}/portal-welcomes", headers=_AUTH)
        assert r.status_code == 200
        welcomes = r.json()["welcomes"]
        assert [w["email"] for w in welcomes] == [_EMAIL]


# ══════════════════════════════════════════════════════════════════════════════
# Acceptance: EMAIL_DRY_RUN respected and shown
# ══════════════════════════════════════════════════════════════════════════════

class TestDryRun:
    def test_dry_run_refuses_and_records_nothing(self, client, monkeypatch):
        # _send_email() returns True under EMAIL_DRY_RUN (PAT-1010), so
        # recording welcomed_at off that return would mark a customer welcomed
        # who was never written to. Refuse instead.
        _seed_client()
        monkeypatch.setattr(dashboard_shared, "EMAIL_DRY_RUN", True)
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 503
        assert r.json()["dry_run"] is True
        assert "EMAIL_DRY_RUN" in r.json()["error"]
        send.assert_not_called()
        assert _welcome_state() == []

    def test_dry_run_is_audited_as_its_own_outcome(self, client, monkeypatch):
        _seed_client()
        monkeypatch.setattr(dashboard_shared, "EMAIL_DRY_RUN", True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            _post_welcome(client)
        rows = _welcome_audit()
        assert [r["outcome"] for r in rows] == ["dry_run"]

    def test_dry_run_is_surfaced_in_the_preflight_context(self, client, monkeypatch):
        _seed_client()
        monkeypatch.setattr(dashboard_shared, "EMAIL_DRY_RUN", True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()):
            ctx = client.get(_BASE + "/welcome-context", headers=_AUTH).json()
        assert ctx["can_send"] is False
        assert ctx["dry_run"] is True
        assert ctx["email_delivery"] == "dry_run"

    def test_dry_run_parsing_itself_is_untouched(self):
        # PAT-1346/PAT-1010: the variable's own parsing and its smoke-test
        # coupling are deliberately load-bearing. This ticket only consumes it.
        assert dashboard_shared._parse_email_dry_run("0") is False
        assert dashboard_shared._parse_email_dry_run("") is False
        assert dashboard_shared._parse_email_dry_run("1") is True
        assert dashboard_shared._parse_email_dry_run("banana") is True


# ══════════════════════════════════════════════════════════════════════════════
# Acceptance: every attempt and outcome is in the access audit trail
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditTrail:
    def test_successful_send_is_audited(self, client):
        _seed_client(company="Acme Ltd")
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            _post_welcome(client)
        rows = _welcome_audit()
        assert len(rows) == 1
        assert rows[0]["outcome"] == "sent"
        assert rows[0]["recipient"] == _EMAIL
        assert rows[0]["tenant_id"] == _TENANT
        assert rows[0]["tenant_name"] == "Acme Ltd"
        assert rows[0]["actor_email"] == "bearer-token"

    def test_refusal_is_audited_with_its_reason(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            _post_welcome(client, email="admin@client.com")
        rows = _welcome_audit()
        assert [r["outcome"] for r in rows] == ["refused"]
        assert "Named individuals only" in rows[0]["detail"]

    def test_failure_is_audited(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=False)):
            _post_welcome(client)
        rows = _welcome_audit()
        assert [r["outcome"] for r in rows] == ["failed"]

    def test_every_attempt_leaves_exactly_one_row(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            _post_welcome(client)
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(cf_payload=_cf_policies([]))), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            _post_welcome(client)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=False)):
            _post_welcome(client)
        assert [r["outcome"] for r in _welcome_audit()] == ["sent", "refused", "failed"]

    def test_central_admin_audit_row_is_written_too(self, client):
        # Route-local trail PLUS the central destructive-write trail, the same
        # pairing the other high-risk actions in main.py use.
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            _post_welcome(client)
        rows = [r for r in _admin_audit("path, method, outcome")
                if r["path"].endswith("/welcome")]
        assert len(rows) == 1
        assert rows[0]["method"] == "POST"
        assert rows[0]["outcome"] == "allowed"

    def test_central_audit_records_a_rejected_send(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get",
                          side_effect=_fake_get(cf_payload=_cf_policies([]))), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            _post_welcome(client)
        rows = [r for r in _admin_audit("path, outcome") if r["path"].endswith("/welcome")]
        assert rows[0]["outcome"] == "rejected_412"

    def test_confirm_missing_is_audited_centrally(self, client):
        _seed_client()
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            client.post(_BASE + "/welcome", json={"first_name": "Jane"}, headers=_AUTH)
        rows = [r for r in _admin_audit("path, outcome") if r["path"].endswith("/welcome")]
        assert rows[0]["outcome"] == "confirm_missing"

    def test_preflight_read_is_not_classified_destructive(self):
        assert not dashboard._is_destructive(
            "GET", f"/admin/tenants/{_TENANT}/portal-users/{_EMAIL}/welcome-context")


# ══════════════════════════════════════════════════════════════════════════════
# Acceptance: Reply-To andy@patched.im, sender noreply@patched.im, copy
# ══════════════════════════════════════════════════════════════════════════════

class TestMessage:
    def test_reply_to_and_subject_on_the_send(self, client):
        _seed_client()
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", send):
            _post_welcome(client)
        args, kwargs = send.call_args
        assert args[0] == _EMAIL
        assert args[1] == "Your Patched portal access"
        assert kwargs["reply_to"] == "andy@patched.im"

    def test_sender_stays_the_configured_noreply_mailbox(self):
        assert dashboard.MAIL_SENDER == "noreply@patched.im"

    def test_graph_message_carries_the_reply_to_header(self):
        captured = {}

        def fake_post(url, **kwargs):
            captured.update(kwargs.get("json") or {})
            m = MagicMock()
            m.status_code = 202
            return m

        with patch.object(dashboard_shared, "_graph_mail_token", return_value="tok"), \
             patch.object(dashboard_shared.http, "post", side_effect=fake_post):
            ok = dashboard_shared._graph_send_mail(
                _EMAIL, "s", "<p>h</p>", "h", reply_to="andy@patched.im")
        assert ok is True
        assert captured["message"]["replyTo"] == [
            {"emailAddress": {"address": "andy@patched.im"}}
        ]

    def test_graph_message_omits_reply_to_when_not_asked_for(self):
        captured = {}

        def fake_post(url, **kwargs):
            captured.update(kwargs.get("json") or {})
            m = MagicMock()
            m.status_code = 202
            return m

        with patch.object(dashboard_shared, "_graph_mail_token", return_value="tok"), \
             patch.object(dashboard_shared.http, "post", side_effect=fake_post):
            dashboard_shared._graph_send_mail(_EMAIL, "s", "<p>h</p>", "h")
        assert "replyTo" not in captured["message"]

    def test_body_matches_the_approved_copy(self):
        _subject, html, text = dashboard._render_portal_welcome_email(
            "Jane", "Acme Ltd", _EMAIL)
        assert text.startswith("Hi Jane,")
        assert "Your Patched portal for Acme Ltd is ready." in text
        assert "what's on your estate" in text
        assert "https://app.patched.im" in text
        assert f"Enter {_EMAIL}." in text
        assert "one-time code" in text
        assert "Andy Bridson\nPatched" in text
        assert "support@patched.im" in text
        # House copy rules: "estate" not "fleet", no em dashes.
        assert "fleet" not in text.lower()
        assert "—" not in text
        # HTML is derived from the text, so it carries the same wording.
        assert "Hi Jane," in html
        assert 'href="https://app.patched.im"' in html

    def test_cloudflare_sender_is_substituted_when_configured(self, monkeypatch):
        monkeypatch.setattr(dashboard, "PORTAL_WELCOME_CLOUDFLARE_SENDER",
                            "noreply@notify.cloudflare.com")
        _s, _h, text = dashboard._render_portal_welcome_email("Jane", "Acme Ltd", _EMAIL)
        assert "it will arrive from noreply@notify.cloudflare.com." in text
        assert "{cloudflare_sender}" not in text


# Andy-approved replacement paragraphs, PAT-1990 comment
# 57943c65-4fd7-4374-9fc7-d9b8877c5274. The rest of the body is unchanged.
_APPROVED_HELP = (
    "Questions about the portal or your findings? Reply to this email or write "
    "to support@patched.im."
)
_APPROVED_NAMED_ACCESS = (
    "Access is personal to you. Each colleague who needs the portal gets their "
    "own named access. Reply with their name and email and it will be set up."
)
_APPROVED_RENDERED_BODY = """Hi Jane,

Your Patched portal for Acme Ltd is ready. It's where you'll see what's on your estate, what has changed, what's vulnerable and whether your controls are working.

Signing in

1. Go to https://app.patched.im
2. Enter jane@client.com. It has to be exactly this address, because your access is tied to it.
3. You'll be emailed a one-time code. Enter it and you're in.

The code comes from Cloudflare, who secure the portal, not from Patched, so it will arrive from noreply@notify.cloudflare.com. If it hasn't turned up within a minute, check your junk or quarantine folder. If your IT team holds external mail, ask them to allow that address.

Codes only last a few minutes, and when your session ends you'll be asked for a new one. That's deliberate.

Your first look

If your devices haven't reported in yet, the portal will look fairly empty. The Install page in the portal has the agent and instructions, and devices appear shortly after they're installed.

Getting help

Questions about the portal or your findings? Reply to this email or write to support@patched.im.

Access is personal to you. Each colleague who needs the portal gets their own named access. Reply with their name and email and it will be set up.

Andy Bridson
Patched"""


@pytest.fixture
def rendered_self_service_welcome(monkeypatch):
    """Exercise the actual renderer without starting the app or sending mail."""
    monkeypatch.setattr(dashboard, "PORTAL_WELCOME_CLOUDFLARE_SENDER",
                        "noreply@notify.cloudflare.com")
    guards = [MagicMock(side_effect=AssertionError("copy check must not send mail"))
              for _ in range(3)]
    provider = MagicMock(side_effect=AssertionError("copy check must not call provider HTTP"))
    monkeypatch.setattr(dashboard, "_send_email", guards[0])
    monkeypatch.setattr(dashboard_shared, "_send_email", guards[1])
    monkeypatch.setattr(dashboard_shared, "_graph_send_mail", guards[2])
    monkeypatch.setattr(dashboard_shared.http, "post", provider)
    try:
        yield dashboard._render_portal_welcome_email("Jane", "Acme Ltd", _EMAIL)
    finally:
        for guard in [*guards, provider]:
            guard.assert_not_called()


class TestApprovedSelfServiceCopy:
    def test_render_preserves_all_other_approved_content(self, rendered_self_service_welcome):
        subject, _html, text = rendered_self_service_welcome
        assert subject == "Your Patched portal access"
        assert text == _APPROVED_RENDERED_BODY

    @pytest.mark.parametrize("body_index", [1, 2], ids=["html", "text"])
    @pytest.mark.parametrize("paragraph", [_APPROVED_HELP, _APPROVED_NAMED_ACCESS],
                             ids=["help", "named-access"])
    def test_render_contains_both_approved_paragraphs(
            self, rendered_self_service_welcome, body_index, paragraph):
        assert paragraph in rendered_self_service_welcome[body_index]

    @pytest.mark.parametrize("body_index", [1, 2], ids=["html", "text"])
    @pytest.mark.parametrize("forbidden", ["specialist", "I'll", "we will"])
    def test_render_has_no_personal_service_promises(
            self, rendered_self_service_welcome, body_index, forbidden):
        # HTML escapes apostrophes; decode entities before checking its wording.
        from html import unescape
        body = unescape(rendered_self_service_welcome[body_index]).lower()
        assert forbidden.lower() not in body


# ══════════════════════════════════════════════════════════════════════════════
# Auth boundary — this route mails a customer their sign-in instructions
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthBoundary:
    def test_send_requires_authentication(self, client):
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", send):
            r = client.post(_BASE + "/welcome", json={"first_name": "Jane"},
                            headers=_CONFIRM)
        assert r.status_code == 401
        send.assert_not_called()

    def test_preflight_and_state_reads_require_authentication(self, client):
        assert client.get(_BASE + "/welcome-context").status_code == 401
        assert client.get(f"/admin/tenants/{_TENANT}/portal-welcomes").status_code == 401

    def test_consultant_cannot_send(self, client, monkeypatch):
        # Owner-only, matching PAT-128's grant/revoke bar. A consultant write
        # is refused by the RBAC layer before the handler runs, and the denial
        # itself is audited because the route is destructive-classified.
        _seed_client()
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", {"owner@patched.im"})
        cookie = dashboard._session_encode("consultant@patched.im", int(time.time()) + 3600)
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", send):
            r = client.post(
                _BASE + "/welcome", json={"first_name": "Jane"},
                headers={**_CONFIRM, "Cookie": f"{dashboard.SESSION_COOKIE}={cookie}"})
        assert r.status_code == 403
        send.assert_not_called()
        assert _welcome_state() == []
        rows = [x for x in _admin_audit("path, outcome") if x["path"].endswith("/welcome")]
        assert rows[0]["outcome"] == "denied_rbac"

    def test_session_identity_is_recorded_as_the_sender(self, client, monkeypatch):
        # welcomed_by has to name a person, not "unknown" — it is the record of
        # who told this customer how to sign in.
        _seed_client()
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", {"owner@patched.im"})
        cookie = dashboard._session_encode("owner@patched.im", int(time.time()) + 3600)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", MagicMock(return_value=True)):
            r = client.post(
                _BASE + "/welcome", json={"first_name": "Jane"},
                headers={**_CONFIRM, "Cookie": f"{dashboard.SESSION_COOKIE}={cookie}"})
        assert r.status_code == 200, r.text
        assert _welcome_state()[0]["welcomed_by"] == "owner@patched.im"
        assert _welcome_audit("actor_email")[0]["actor_email"] == "owner@patched.im"


class TestCloudflareSenderPlaceholder:
    """The one thing this ticket cannot finish: the real Cloudflare One-time
    PIN sender address, which needs a live test sign-in to read. The template
    keeps the literal placeholder, and the send route refuses while it is
    unfilled so a customer can never receive the unsubstituted text."""

    def test_template_keeps_the_literal_placeholder_when_unset(self, monkeypatch):
        monkeypatch.setattr(dashboard, "PORTAL_WELCOME_CLOUDFLARE_SENDER", "")
        _s, _h, text = dashboard._render_portal_welcome_email("Jane", "Acme Ltd", _EMAIL)
        assert "it will arrive from {cloudflare_sender}." in text

    def test_send_refuses_while_the_placeholder_is_unfilled(self, client, monkeypatch):
        _seed_client()
        monkeypatch.setattr(dashboard, "PORTAL_WELCOME_CLOUDFLARE_SENDER", "")
        send = MagicMock(return_value=True)
        with patch.object(dashboard.http, "get", side_effect=_fake_get()), \
             patch.object(dashboard, "_send_email", send):
            r = _post_welcome(client)
        assert r.status_code == 503
        assert r.json()["cloudflare_sender_missing"] is True
        assert "PORTAL_WELCOME_CLOUDFLARE_SENDER" in r.json()["error"]
        send.assert_not_called()
        assert _welcome_state() == []

    def test_preflight_surfaces_the_unfilled_placeholder(self, client, monkeypatch):
        _seed_client()
        monkeypatch.setattr(dashboard, "PORTAL_WELCOME_CLOUDFLARE_SENDER", "")
        with patch.object(dashboard.http, "get", side_effect=_fake_get()):
            ctx = client.get(_BASE + "/welcome-context", headers=_AUTH).json()
        assert ctx["can_send"] is False
        assert ctx["cloudflare_sender_missing"] is True
