"""
PAT-780 — global GitHub-backed Docs section.

Covers:
  * /api/docs/tree groups docs by top-level folder (category) and pulls the
    title from the first `# ` heading, falling back to a humanized filename.
  * /api/docs/content renders Markdown to HTML (code blocks + tables) and
    rejects path-traversal / non-.md paths.
  * /api/docs/search matches on title and body content.
  * All three routes are guarded by the standard /api/* session-or-Bearer
    middleware (401 with no credentials).
  * Console nav/section wiring: a "Docs" link + section exist.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def docs_root(tmp_path, monkeypatch):
    root = tmp_path / "docs"
    root.mkdir()
    (root / "architecture.md").write_text(
        "# System Architecture\n\nHow the pieces fit together.\n\n"
        "```python\nprint('hello')\n```\n\n"
        "| A | B |\n|---|---|\n| 1 | 2 |\n"
    )
    (root / "onboarding-checklist.md").write_text("No heading here, just prose about setup.")
    ops_dir = root / "operations"
    ops_dir.mkdir()
    (ops_dir / "runbook.md").write_text("# Incident Runbook\n\nEscalate to on-call via PagerDuty.")
    monkeypatch.setattr(dashboard, "_DOCS_ROOT", root)
    return root


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


AUTH = {"Authorization": "Bearer test-key"}


class TestDocsTree:
    def test_groups_by_top_level_folder(self, client, docs_root):
        r = client.get("/api/docs/tree", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 3
        cats = {c["category"]: c["docs"] for c in data["categories"]}
        assert "General" in cats
        assert "operations" in cats
        general_paths = {d["path"] for d in cats["General"]}
        assert general_paths == {"architecture.md", "onboarding-checklist.md"}
        assert {d["path"] for d in cats["operations"]} == {"operations/runbook.md"}

    def test_title_from_first_heading(self, client, docs_root):
        data = client.get("/api/docs/tree", headers=AUTH).json()
        by_path = {d["path"]: d["title"] for c in data["categories"] for d in c["docs"]}
        assert by_path["architecture.md"] == "System Architecture"
        assert by_path["operations/runbook.md"] == "Incident Runbook"

    def test_title_falls_back_to_humanized_filename(self, client, docs_root):
        data = client.get("/api/docs/tree", headers=AUTH).json()
        by_path = {d["path"]: d["title"] for c in data["categories"] for d in c["docs"]}
        assert by_path["onboarding-checklist.md"] == "Onboarding Checklist"

    def test_empty_docs_dir(self, client, tmp_path, monkeypatch):
        empty = tmp_path / "empty-docs"
        empty.mkdir()
        monkeypatch.setattr(dashboard, "_DOCS_ROOT", empty)
        r = client.get("/api/docs/tree", headers=AUTH)
        assert r.status_code == 200
        assert r.json() == {"categories": [], "count": 0}

    def test_missing_docs_dir_does_not_500(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(dashboard, "_DOCS_ROOT", tmp_path / "does-not-exist")
        r = client.get("/api/docs/tree", headers=AUTH)
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_requires_auth(self, client, docs_root):
        r = client.get("/api/docs/tree")
        assert r.status_code == 401


class TestDocsContent:
    def test_renders_markdown_with_code_and_tables(self, client, docs_root):
        r = client.get("/api/docs/content", params={"path": "architecture.md"}, headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        assert data["title"] == "System Architecture"
        assert "<table>" in data["html"]
        assert "<code" in data["html"] or "<pre>" in data["html"]
        assert data["github_url"].endswith("/blob/main/docs/architecture.md")

    def test_nested_path(self, client, docs_root):
        r = client.get("/api/docs/content", params={"path": "operations/runbook.md"}, headers=AUTH)
        assert r.status_code == 200
        assert r.json()["title"] == "Incident Runbook"

    def test_not_found(self, client, docs_root):
        r = client.get("/api/docs/content", params={"path": "nope.md"}, headers=AUTH)
        assert r.status_code == 404

    def test_rejects_path_traversal(self, client, docs_root, tmp_path):
        secret = tmp_path / "secret.md"
        secret.write_text("# Secret\nshould never be reachable")
        r = client.get("/api/docs/content", params={"path": "../secret.md"}, headers=AUTH)
        assert r.status_code == 400

    def test_rejects_non_markdown_suffix(self, client, docs_root):
        (docs_root / "notes.txt").write_text("not markdown")
        r = client.get("/api/docs/content", params={"path": "notes.txt"}, headers=AUTH)
        assert r.status_code == 400

    def test_requires_auth(self, client, docs_root):
        r = client.get("/api/docs/content", params={"path": "architecture.md"})
        assert r.status_code == 401


class TestDocsSearch:
    def test_matches_title(self, client, docs_root):
        r = client.get("/api/docs/search", params={"q": "runbook"}, headers=AUTH)
        assert r.status_code == 200
        paths = {res["path"] for res in r.json()["results"]}
        assert "operations/runbook.md" in paths

    def test_matches_body_content(self, client, docs_root):
        r = client.get("/api/docs/search", params={"q": "pagerduty"}, headers=AUTH)
        results = r.json()["results"]
        assert any(res["path"] == "operations/runbook.md" for res in results)
        assert results[0]["snippet"]

    def test_no_query_returns_empty(self, client, docs_root):
        r = client.get("/api/docs/search", params={"q": ""}, headers=AUTH)
        assert r.json() == {"results": []}

    def test_no_match_returns_empty_list(self, client, docs_root):
        r = client.get("/api/docs/search", params={"q": "nonexistent-term-xyz"}, headers=AUTH)
        assert r.json()["results"] == []

    def test_requires_auth(self, client, docs_root):
        r = client.get("/api/docs/search", params={"q": "runbook"})
        assert r.status_code == 401


class TestConsoleWiring:
    def test_docs_nav_link_present(self, client):
        r = client.get("/console")
        html = r.text if r.status_code == 200 else ""
        # /console redirects to /console/{CONSOLE_BUILD_ID}; follow it.
        if r.status_code in (301, 302, 307, 308):
            r = client.get(r.headers["location"])
            html = r.text
        assert 'id="nav-docs"' in html
        assert 'id="section-docs"' in html
        assert "_docsLoad" in html
