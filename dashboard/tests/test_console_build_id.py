"""Console cache-bust build-id coupling.

Regression cover for the console redirect loop that has now shipped twice
(PAT-966, and again on 2026-07-25). Failure mode: `static/js/theme.js` held
its own hardcoded copy of CONSOLE_BUILD_ID. When main.py's value was bumped
and theme.js's was not, the server redirected /console to the new build id
while theme.js redirected back to the stale one — an infinite loop that
presents as a flashing page, worst on mobile.

theme.js now derives the build id from its own ?v= query string, so main.py
is the single source of truth. These tests fail if a second source is ever
reintroduced.
"""
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "console-test.db")
    with TestClient(dashboard.app) as value:
        yield value


def test_theme_js_has_no_hardcoded_build_id():
    """theme.js must not carry a second copy of the build id.

    A hardcoded value here silently drifts from main.py on every bump and
    reintroduces the redirect loop. Comments referencing past incidents are
    fine; an actual assignment is not.
    """
    source = (REPO / "static" / "js" / "theme.js").read_text()
    code = "\n".join(
        line for line in source.splitlines()
        if not line.lstrip().startswith(("//", "*", "/*"))
    )
    assert not re.search(r"CONSOLE_BUILD_ID\s*=\s*['\"]", code), (
        "theme.js assigns a literal CONSOLE_BUILD_ID. It must derive the build "
        "id from its own ?v= query instead — see this module's docstring."
    )


def test_console_page_stamps_every_asset_with_the_current_build_id(client, verified_access_headers):
    """The served console must reference the live build id, not a stale literal."""
    response = client.get("/console", headers=verified_access_headers("owner@patched.im"), follow_redirects=True)
    assert response.status_code == 200
    build_id = dashboard.CONSOLE_BUILD_ID
    for asset in ("/static/js/theme.js", "/static/css/theme.css", "/static/css/console.css"):
        assert f"{asset}?v={build_id}" in response.text, (
            f"{asset} is not cache-busted with the current build id "
            f"({build_id}) — a hardcoded version here goes stale silently."
        )


def test_console_redirects_to_the_current_build_id(client, verified_access_headers):
    """/console must land on /console/<current build id>, in one hop."""
    response = client.get("/console", headers=verified_access_headers("owner@patched.im"), follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == f"/console/{dashboard.CONSOLE_BUILD_ID}"


def test_stale_build_id_redirects_forward_not_in_a_loop(client, verified_access_headers):
    """A stale /console/<old> URL must redirect forward to the current build."""
    response = client.get("/console/2026-07-24i", headers=verified_access_headers("owner@patched.im"), follow_redirects=False)
    assert response.status_code == 302
    assert response.headers["location"] == f"/console/{dashboard.CONSOLE_BUILD_ID}"
