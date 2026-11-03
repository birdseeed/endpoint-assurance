import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard
import shared


@pytest.fixture
def client(tmp_path, monkeypatch):
    # These owner-workflow fixtures name their privileged identities explicitly.
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im", "specialist@patched.im"}))
    monkeypatch.setattr(shared, "DB_PATH", tmp_path / "test.db")
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def session(email="owner@patched.im"):
    token = dashboard._session_encode(email, int(time.time()) + 3600)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={token}"}


def response(status=200, payload=None, content=b"", headers=None, text=""):
    r = MagicMock(status_code=status, content=content, headers=headers or {}, text=text)
    r.json.return_value = payload if payload is not None else {}
    return r


class TestStaffArtifactWorkflow:
    @pytest.mark.parametrize("path", [
        "/admin/tenants/not-a-uuid/assessment-artifacts/approve",
        "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/not-a-uuid/download-tokens",
    ])
    def test_invalid_path_identifiers_never_reach_platform(self, client, path):
        with patch.object(dashboard.http, "post") as post:
            r = client.post(path, headers=session(), content=b"{}")
        assert r.status_code == 400
        post.assert_not_called()

    def test_approval_requires_named_session_not_shared_bearer(self, client):
        r = client.post(
            "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/approve",
            headers={"Authorization": "Bearer test-key"},
            files={"document": ("report.pdf", b"%PDF-1.7", "application/pdf")},
            data={"engagement_reference": "EA-1", "document_version": "v1", "generated_at": "2026-08-15T10:00:00Z"},
        )
        assert r.status_code == 403

    def test_approval_forwards_bytes_and_server_resolved_actor(self, client):
        upstream = response(201, {"id": "artifact-1", "sha256": "ab" * 32})
        with patch.object(dashboard.http, "post", return_value=upstream) as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/approve",
                headers=session("specialist@patched.im"),
                files={"document": ("report.pdf", b"%PDF-1.7\nexact", "application/pdf")},
                data={"engagement_reference": "EA-1", "document_version": "v1", "generated_at": "2026-08-15T10:00:00Z"},
            )
        assert r.status_code == 201
        assert post.call_args.kwargs["headers"]["X-Patched-Actor-Email"] == "specialist@patched.im"
        assert b"%PDF-1.7\nexact" in post.call_args.kwargs["data"]

    def test_wrong_tenant_or_artifact_is_preserved_from_platform(self, client):
        upstream = response(404, {"error": "artifact not found"})
        with patch.object(dashboard.http, "post", return_value=upstream):
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/22222222-2222-4222-8222-222222222222/download-tokens",
                headers=session(), json={"recipient": "customer@example.com"},
            )
        assert r.status_code == 404

    def test_cross_tenant_artifact_lookup_is_indistinguishable_from_nonexistent(self, client):
        """P2 (round 3 review): the round-1/2 version of this test only asserted a
        hard-coded mock 404 was relayed, entirely delegating actual cross-tenant
        scoping to unverified platform behavior. This test instead mocks the
        platform's REAL error contract for that exact scenario: the sibling Go
        worktree's IssueAssessmentDownloadTokenHandler (assessment_artifacts.go)
        scopes its lookup as `WHERE id=$1::uuid AND tenant_id=$2::uuid` and, on
        no match, calls `http.Error(w, "artifact not found", 404)` — stdlib
        `net/http`'s plain-text responder (`Content-Type: text/plain;
        charset=utf-8`, body `"artifact not found\n"`), NOT a JSON body. Critically,
        that query is written so a real artifact that exists under a DIFFERENT
        tenant produces the exact same 404 the platform would return for an
        artifact_id that never existed at all — the two cases are byte-identical
        at the Go layer by construction. This test proves the dashboard preserves
        that indistinguishability end to end rather than accidentally introducing
        a side channel (e.g. a different message, header, or status for one case
        vs. the other) while relaying it."""
        def platform_not_found():
            r = response(404, content=b"artifact not found\n", text="artifact not found\n",
                         headers={"Content-Type": "text/plain; charset=utf-8"})
            r.json.side_effect = ValueError("no JSON object could be decoded")
            return r

        # Scenario A: artifact_id genuinely belongs to a different tenant.
        with patch.object(dashboard.http, "post", return_value=platform_not_found()):
            r_wrong_tenant = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/"
                "22222222-2222-4222-8222-222222222222/download-tokens",
                headers=session(), json={"recipient": "customer@example.com"},
            )
        # Scenario B: artifact_id never existed under any tenant. Same platform
        # response shape, by construction of the SQL above.
        with patch.object(dashboard.http, "post", return_value=platform_not_found()):
            r_never_existed = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/"
                "33333333-3333-4333-8333-333333333333/download-tokens",
                headers=session(), json={"recipient": "customer@example.com"},
            )
        assert r_wrong_tenant.status_code == 404
        assert r_never_existed.status_code == 404
        # Relayed bodies must be identical — no distinguishing detail leaked
        # about the artifact existing (under another tenant) in one case but
        # not the other.
        assert r_wrong_tenant.json() == r_never_existed.json()
        assert r_wrong_tenant.json()["body"].strip() == "artifact not found"

    def test_token_response_adds_existing_public_recipient_path(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "PUBLIC_BASE_URL", "https://dashboard.patched.im")
        token = "33333333-3333-4333-8333-333333333333"
        upstream = response(200, {"token": token, "expires_at": "2026-08-22T10:00:00Z"})
        with patch.object(dashboard.http, "post", return_value=upstream):
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/22222222-2222-4222-8222-222222222222/download-tokens",
                headers=session(), json={"recipient": "customer@example.com"},
            )
        assert r.status_code == 200
        assert r.json()["download_url"] == f"https://dashboard.patched.im/reports/download/{token}"

    def test_invalid_success_contract_fails_closed(self, client):
        upstream = response(200, payload=None, content=b"not-json", text="not-json")
        upstream.json.side_effect = ValueError("invalid JSON")
        with patch.object(dashboard.http, "post", return_value=upstream):
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/22222222-2222-4222-8222-222222222222/download-tokens",
                headers=session(), json={"recipient": "customer@example.com"},
            )
        assert r.status_code == 502

    def test_transport_details_are_not_reflected(self, client):
        secret_detail = "internal-hostname:8443 refused"
        with patch.object(dashboard.http, "post", side_effect=RuntimeError(secret_detail)):
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/22222222-2222-4222-8222-222222222222/download-tokens",
                headers=session(), json={"recipient": "customer@example.com"},
            )
        assert r.status_code == 502
        assert secret_detail not in r.text

    def test_token_response_is_projected_not_relayed_verbatim(self, client, monkeypatch):
        """P3 (main.py:10487 pre-fix): the platform payload must be projected onto a
        fixed allowlist rather than relayed verbatim, so an unexpected extra field
        (e.g. something filesystem-shaped) the platform might one day include is
        structurally dropped rather than merely absent by upstream convention."""
        monkeypatch.setattr(dashboard, "PUBLIC_BASE_URL", "https://dashboard.patched.im")
        token = "33333333-3333-4333-8333-333333333333"
        upstream = response(200, {
            "token": token, "expires_at": "2026-08-22T10:00:00Z",
            "recipient": "customer@example.com", "artifact_id": "22222222-2222-4222-8222-222222222222",
            "storage_path": "/var/patched/assessments/should-never-leave-the-platform",
        })
        with patch.object(dashboard.http, "post", return_value=upstream):
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/22222222-2222-4222-8222-222222222222/download-tokens",
                headers=session(), json={"recipient": "customer@example.com"},
            )
        assert r.status_code == 200
        body = r.json()
        assert set(body) == {"token", "download_url", "expires_at", "recipient", "artifact_id"}
        assert "storage_path" not in body

    def test_download_token_issue_requires_json_content_type(self, client):
        """P2 (main.py:10468 pre-fix, CSRF): a cross-site <form enctype="text/plain">
        POST whose body happens to parse as JSON must not be relayed to the platform
        as a genuine application/json request. SameSite=Lax already stops the session
        cookie riding along on a cross-site POST in compliant browsers (see the route's
        comment) — this is the route-local defense-in-depth on top of that."""
        with patch.object(dashboard.http, "post") as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/22222222-2222-4222-8222-222222222222/download-tokens",
                headers={**session(), "Content-Type": "text/plain"},
                content=b'{"recipient": "customer@example.com"}',
            )
        assert r.status_code == 400
        post.assert_not_called()

    def test_approve_rejects_non_multipart_content_type(self, client):
        with patch.object(dashboard.http, "post") as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/approve",
                headers={**session(), "Content-Type": "application/json"},
                content=b'{"document": "not-a-file"}',
            )
        assert r.status_code == 400
        post.assert_not_called()

    def test_approve_accepts_boundary_less_multipart_content_type_header(self, client):
        """P3 (main.py:10429 pre-fix): the old literal `.startswith("multipart/form-data;")`
        match rejected a legitimate boundary-less `Content-Type: multipart/form-data`
        header with the generic 400 instead of letting it through to real handling."""
        upstream = response(201, {"id": "artifact-1"})
        with patch.object(dashboard.http, "post", return_value=upstream) as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/approve",
                headers={**session(), "Content-Type": "multipart/form-data"},
                content=b"irrelevant-body-platform-will-reject-independently",
            )
        assert r.status_code != 400
        post.assert_called_once()

    def test_approve_rejects_oversized_body_before_forwarding(self, client):
        oversized = b"x" * (dashboard._ASSESSMENT_APPROVE_BODY_MAX_BYTES + 1)
        with patch.object(dashboard.http, "post") as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/approve",
                headers={**session(), "Content-Type": "multipart/form-data; boundary=x"},
                content=oversized,
            )
        assert r.status_code == 413
        post.assert_not_called()

    def test_download_token_issue_rejects_oversized_body(self, client):
        oversized = b"x" * ((1 << 14) + 1)
        with patch.object(dashboard.http, "post") as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/22222222-2222-4222-8222-222222222222/download-tokens",
                headers={**session(), "Content-Type": "application/json"},
                content=oversized,
            )
        assert r.status_code == 413
        post.assert_not_called()

    def test_approve_accepts_document_at_platform_max_size(self, client):
        """P2 (main.py:10548 pre-fix, size-limit drift): a document at the platform's
        own hard per-document ceiling (assessment_artifacts.go: maxAssessmentArtifactBytes
        = 25 << 20) must actually be accepted by the dashboard's own pre-flight gate —
        proving the approve-side and download-side limits agree, so nothing legitimately
        approved can be undeliverable. See test_download_accepts_content_at_platform_max_size
        below for the download-side half of the same round trip."""
        big_doc = b"%PDF-1.7" + b"\x00" * (dashboard._ASSESSMENT_DOCUMENT_MAX_BYTES - 8)
        upstream = response(201, {"id": "artifact-1", "sha256": "ab" * 32})
        with patch.object(dashboard.http, "post", return_value=upstream) as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/approve",
                headers=session(),
                files={"document": ("report.pdf", big_doc, "application/pdf")},
                data={"engagement_reference": "EA-1", "document_version": "v1", "generated_at": "2026-08-15T10:00:00Z"},
            )
        assert r.status_code == 201
        post.assert_called_once()

    def test_download_tokens_route_403s_for_non_owner_consultant_session(self, client, monkeypatch):
        """P2 (owner-only enforcement not actually driven end-to-end pre-fix): a real
        request with a real non-owner staff session, not a direct call to the internal
        rule-table helpers."""
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        with patch.object(dashboard.http, "post") as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/22222222-2222-4222-8222-222222222222/download-tokens",
                headers=session("consultant@patched.im"), json={"recipient": "customer@example.com"},
            )
        assert r.status_code == 403
        post.assert_not_called()

    def test_approve_route_403s_for_non_owner_consultant_session(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
        with patch.object(dashboard.http, "post") as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/approve",
                headers=session("consultant@patched.im"),
                files={"document": ("report.pdf", b"%PDF-1.7", "application/pdf")},
                data={"engagement_reference": "EA-1", "document_version": "v1", "generated_at": "2026-08-15T10:00:00Z"},
            )
        assert r.status_code == 403
        post.assert_not_called()

    def test_client_supplied_actor_header_is_ignored_on_token_issue(self, client):
        """A client-supplied X-Patched-Actor-Email must never override the
        session-derived actor forwarded to the platform as the issuing actor."""
        upstream = response(200, {"token": "33333333-3333-4333-8333-333333333333"})
        with patch.object(dashboard.http, "post", return_value=upstream) as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/22222222-2222-4222-8222-222222222222/download-tokens",
                headers={**session("specialist@patched.im"), "X-Patched-Actor-Email": "attacker@evil.example"},
                json={"recipient": "customer@example.com"},
            )
        assert r.status_code == 200
        assert post.call_args.kwargs["headers"]["X-Patched-Actor-Email"] == "specialist@patched.im"

    def test_client_supplied_actor_header_is_ignored_on_approve(self, client):
        upstream = response(201, {"id": "artifact-1"})
        with patch.object(dashboard.http, "post", return_value=upstream) as post:
            r = client.post(
                "/admin/tenants/11111111-1111-4111-8111-111111111111/assessment-artifacts/approve",
                headers={**session("specialist@patched.im"), "X-Patched-Actor-Email": "attacker@evil.example"},
                files={"document": ("report.pdf", b"%PDF-1.7", "application/pdf")},
                data={"engagement_reference": "EA-1", "document_version": "v1", "generated_at": "2026-08-15T10:00:00Z"},
            )
        assert r.status_code == 201
        assert post.call_args.kwargs["headers"]["X-Patched-Actor-Email"] == "specialist@patched.im"


class TestPublicAssessmentDownload:
    def test_returns_byte_identical_pdf_with_safe_headers(self, client):
        token = "33333333-3333-4333-8333-333333333333"
        expected = b"%PDF-1.7\x00exact approved bytes"
        upstream = response(200, content=expected, headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="endpoint-assurance-EA-1-v1.pdf"',
        })
        with patch.object(dashboard.http, "post", return_value=upstream):
            r = client.get(f"/reports/download/{token}")
        assert r.status_code == 200
        assert r.content == expected
        assert r.headers["content-type"] == "application/pdf"
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["referrer-policy"] == "no-referrer"

    def test_invalid_token_never_reaches_platform(self, client):
        with patch.object(dashboard.http, "post") as post:
            r = client.get("/reports/download/not-a-token")
        assert r.status_code == 404
        post.assert_not_called()

    @pytest.mark.parametrize("content", [b"", b"x" * (dashboard._ASSESSMENT_DOCUMENT_MAX_BYTES + 1)])
    def test_fails_closed_on_empty_or_oversized_platform_bytes(self, client, content):
        upstream = response(200, content=content, headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="report.pdf"',
        })
        with patch.object(dashboard.http, "post", return_value=upstream):
            r = client.get("/reports/download/33333333-3333-4333-8333-333333333333")
        assert r.status_code == 502

    @pytest.mark.parametrize("content_type,disposition", [
        ("text/html", 'attachment; filename="report.pdf"'),
        ("application/pdf", 'inline; filename="report.pdf"'),
        ("application/pdf", 'attachment; filename="../../escape.pdf"'),
    ])
    def test_fails_closed_on_unsafe_upstream_contract(self, client, content_type, disposition):
        upstream = response(200, content=b"payload", headers={
            "Content-Type": content_type, "Content-Disposition": disposition,
        })
        with patch.object(dashboard.http, "post", return_value=upstream):
            r = client.get("/reports/download/33333333-3333-4333-8333-333333333333")
        assert r.status_code == 502

    @pytest.mark.parametrize("status", [404, 409, 410])
    def test_preserves_platform_token_and_integrity_failures(self, client, status):
        with patch.object(dashboard.http, "post", return_value=response(status, text="denied")):
            r = client.get("/reports/download/33333333-3333-4333-8333-333333333333")
        assert r.status_code == status

    def test_download_accepts_content_at_platform_max_size(self, client):
        """P2 (main.py:10548 pre-fix, size-limit drift): content at exactly the
        platform's own per-document ceiling must be delivered, not 502'd — the
        download-side half of the round trip proven from the approve side by
        test_approve_accepts_document_at_platform_max_size above. Both checks are
        pinned to the same dashboard._ASSESSMENT_DOCUMENT_MAX_BYTES constant."""
        content = b"x" * dashboard._ASSESSMENT_DOCUMENT_MAX_BYTES
        upstream = response(200, content=content, headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": 'attachment; filename="report.pdf"',
        })
        with patch.object(dashboard.http, "post", return_value=upstream):
            r = client.get("/reports/download/33333333-3333-4333-8333-333333333333")
        assert r.status_code == 200
        assert r.content == content

    def test_platform_redeem_call_is_a_single_irreversible_post(self, client):
        """P2 (main.py:10524 pre-fix, token-burn-on-failure): the platform's redeem
        handler (assessment_artifacts.go: RedeemAssessmentDownloadTokenHandler) marks
        the token used in the same DB transaction that hash-verifies the artifact,
        committed BEFORE any response is returned — so by the time this dashboard
        code sees a malformed/unsafe response and fails closed with 502, the token is
        already durably consumed server-side with no un-redeem endpoint to call. This
        test documents and pins that current, accepted behavior: the redeem POST is
        made exactly once, with no dashboard-side retry or compensating action — a
        full fix (returning the token to a usable state) is not achievable from this
        worktree alone; see the comment in public_report_download (main.py)."""
        upstream = response(200, content=b"payload", headers={
            "Content-Type": "text/html",  # not an allowed type -> dashboard fails closed
            "Content-Disposition": 'attachment; filename="report.pdf"',
        })
        with patch.object(dashboard.http, "post", return_value=upstream) as post:
            r = client.get("/reports/download/33333333-3333-4333-8333-333333333333")
        assert r.status_code == 502
        post.assert_called_once()
        assert post.call_args.args[0].endswith(
            "/admin/assessment-download-tokens/33333333-3333-4333-8333-333333333333/redeem"
        )

    def test_legacy_non_uuid_local_token_still_resolves(self, client):
        """P2 (main.py:10503 pre-fix, strict UUID gate): PAT-370's local
        report_ext_tokens.token has always been minted as str(uuid.uuid4()) (verified
        against git history), but the redeem route must not assume every outstanding
        token is UUID-shaped — a non-UUID value already present in the local table
        must still resolve via the legacy PAT-370 lookup path rather than 404ing
        ahead of the DB query."""
        legacy_token = "legacy-tok-not-a-uuid-8f2c91a4"
        with dashboard.get_db() as db:
            db.execute(
                "INSERT INTO report_ext_tokens (token, tenant_id, record_id, email, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (legacy_token, "tenant-1", "record-1", "customer@example.com", "2099-01-01T00:00:00+00:00"),
            )
        xlsx_bytes = b"PK\x03\x04legacy-xlsx-bytes"
        upstream_get = response(200, content=xlsx_bytes)
        with patch.object(dashboard.http, "get", return_value=upstream_get) as get, \
             patch.object(dashboard.http, "post") as post:
            r = client.get(f"/reports/download/{legacy_token}")
        assert r.status_code == 200
        assert r.content == xlsx_bytes
        get.assert_called_once()
        post.assert_not_called()

    def test_non_uuid_unknown_token_still_404s_without_reaching_platform(self, client):
        with patch.object(dashboard.http, "post") as post:
            r = client.get("/reports/download/definitely-not-a-known-legacy-token")
        assert r.status_code == 404
        post.assert_not_called()


def test_routes_are_owner_only_and_audited():
    approval = "/admin/tenants/t/assessment-artifacts/approve"
    issue = "/admin/tenants/t/assessment-artifacts/a/download-tokens"
    assert not dashboard._consultant_write_allowed("POST", approval)
    assert not dashboard._consultant_write_allowed("POST", issue)
    assert dashboard._is_destructive("POST", approval)
    assert dashboard._is_destructive("POST", issue)
