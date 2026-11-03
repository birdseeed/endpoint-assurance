"""
PAT-779 — per-tenant operator runbook / notes.

Covers:
  * CRUD lifecycle (create, list, edit, soft-delete) via
    /admin/tenants/{tid}/runbook-notes[/{id}].
  * Notes are scoped by tenant_id — a note created for one tenant never
    appears in another tenant's list.
  * Deleted notes drop out of the list (soft delete — deleted_at set,
    not a hard DELETE).
  * created_by/updated_by/created_at/updated_at are recorded from the
    session identity, and updated_by/updated_at change on edit.
  * Invalid category is rejected; missing title is rejected.
  * Consultants cannot create/edit/delete (owner-only writes, matching the
    codebase default); GET still works for consultants.
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def client(tmp_path, monkeypatch):
    # These owner-workflow fixtures name their privileged identities explicitly.
    monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({"owner@patched.im"}))
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _cookie(email, ttl=3600):
    tok = dashboard._session_encode(email, int(time.time()) + ttl)
    return {"Cookie": f"{dashboard.SESSION_COOKIE}={tok}"}


OWNER = "owner@patched.im"


class TestRunbookNotesCrud:
    def test_create_then_list(self, client):
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes",
            headers=_cookie(OWNER),
            json={"title": "VPN caveat", "body": "Needs split-tunnel off.", "category": "technical"},
        )
        assert r.status_code == 200
        note_id = r.json()["id"]

        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie(OWNER))
        assert r.status_code == 200
        notes = r.json()["notes"]
        assert len(notes) == 1
        assert notes[0]["id"] == note_id
        assert notes[0]["title"] == "VPN caveat"
        assert notes[0]["category"] == "technical"
        assert notes[0]["created_by"] == OWNER
        assert notes[0]["updated_by"] == OWNER
        assert notes[0]["created_at"]
        assert notes[0]["updated_at"]

    def test_scoped_by_tenant(self, client):
        client.post("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie(OWNER), json={"title": "A"})
        client.post("/admin/tenants/b27fb783-0526-5455-85dc-ffc0082795e1/runbook-notes", headers=_cookie(OWNER), json={"title": "B"})

        r1 = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie(OWNER))
        r2 = client.get("/admin/tenants/b27fb783-0526-5455-85dc-ffc0082795e1/runbook-notes", headers=_cookie(OWNER))
        assert [n["title"] for n in r1.json()["notes"]] == ["A"]
        assert [n["title"] for n in r2.json()["notes"]] == ["B"]

    def test_edit_updates_actor_and_fields(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS",
                            frozenset({"alice@patched.im", "bob@patched.im"}))
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes",
            headers=_cookie("alice@patched.im"),
            json={"title": "Original", "body": "v1", "category": "other"},
        )
        note_id = r.json()["id"]

        r = client.put(
            f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes/{note_id}",
            headers=_cookie("bob@patched.im"),
            json={"title": "Updated", "body": "v2", "category": "support", "pinned": True},
        )
        assert r.status_code == 200

        notes = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie(OWNER)).json()["notes"]
        assert len(notes) == 1
        n = notes[0]
        assert n["title"] == "Updated"
        assert n["body"] == "v2"
        assert n["category"] == "support"
        assert n["pinned"] == 1
        assert n["created_by"] == "alice@patched.im"
        assert n["updated_by"] == "bob@patched.im"

    def test_delete_is_soft_and_removes_from_list(self, client):
        r = client.post("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie(OWNER), json={"title": "Temp"})
        note_id = r.json()["id"]

        r = client.delete(f"/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes/{note_id}", headers=_cookie(OWNER))
        assert r.status_code == 200

        notes = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie(OWNER)).json()["notes"]
        assert notes == []

        with dashboard.get_db() as db:
            row = db.execute(
                "SELECT deleted_at FROM tenant_runbook_notes WHERE id=?", (note_id,)
            ).fetchone()
        assert row is not None
        assert row["deleted_at"] is not None

    def test_pinned_sorts_first(self, client):
        client.post("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie(OWNER), json={"title": "Unpinned"})
        client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes",
            headers=_cookie(OWNER),
            json={"title": "Pinned", "pinned": True},
        )
        notes = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie(OWNER)).json()["notes"]
        assert notes[0]["title"] == "Pinned"

    def test_missing_title_rejected(self, client):
        r = client.post("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie(OWNER), json={"body": "no title"})
        assert r.status_code == 400

    def test_invalid_category_rejected(self, client):
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes",
            headers=_cookie(OWNER),
            json={"title": "X", "category": "not-a-real-category"},
        )
        assert r.status_code == 400

    def test_edit_unknown_note_404s(self, client):
        r = client.put(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes/does-not-exist",
            headers=_cookie(OWNER),
            json={"title": "X"},
        )
        assert r.status_code == 404


class TestRunbookNotesRbac:
    def test_consultant_can_list(self, client, monkeypatch):
        client.post("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie(OWNER), json={"title": "A"})
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({OWNER}))
        r = client.get("/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes", headers=_cookie("consultant@example.com"))
        assert r.status_code == 200

    def test_consultant_cannot_create(self, client, monkeypatch):
        monkeypatch.setattr(dashboard, "DASHBOARD_OPERATORS", frozenset({OWNER}))
        r = client.post(
            "/admin/tenants/0a4c2c91-7412-575c-b544-dea3a596dd31/runbook-notes",
            headers=_cookie("consultant@example.com"),
            json={"title": "Nope"},
        )
        assert r.status_code == 403
