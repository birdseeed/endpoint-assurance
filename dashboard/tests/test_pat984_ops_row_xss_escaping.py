"""PAT-984: stored XSS in the Ops tab — `_opsRow` (dashboard/templates/
console.html, ~:16200) built its `<div>` by raw string concatenation of
`label`/`val` straight into a string that is later assigned to `.innerHTML`,
with no escaping. Same class as PAT-854 (see test_pat854_xss_onclick_
escaping.py), but a plain innerHTML-injection sink rather than the
onclick-JS-string-context variant: here `_escHtml` (an HTML-attribute/text
escaper) IS the correct tool, it just wasn't being called.

Anyone who can write a `*.json` file into `/srv/backup/health` on
patched-api-01 controls `label`/`val`/`b.detail` (and friends) verbatim, and
those fields render directly into the authenticated staff console's DOM via
`.innerHTML =`.

Fix, mirroring the reference-safe pattern already used by `healthRow` in the
Home health strip (~:5759, unmodified by this ticket):
  1. `_opsRow(label, val, warn, dot)` now escapes `label` and `val` with
     `_escHtml` itself, so every call site is fixed at once.
  2. `warn` (bool, style-only) and the new `dot` (tri-state true/false/
     undefined, style-only) are never escaped — they never carry attacker
     data. `dot` replaces the old pattern of callers concatenating
     `_opsDot(...)`'s trusted HTML directly into `val`, which would have
     been mangled into visible escaped text once `val` itself is escaped.
  3. The backups tile's `b.detail` is escaped before concatenation.
  4. The certs tile's error row no longer hand-builds a raw `<span>` around
     `c.error` (that raw HTML was passed whole as `val`, defeating `_opsRow`'s
     escaping); it now flows through `_opsRow`'s own escaping like everything
     else, with `warn` supplying the visual emphasis instead.
  5. `_opsFwApply`'s live-run result panel escapes `d.exit_code`/`d.journal`
     (returned from `/api/ops/firewall-apply`) before concatenating into
     `.innerHTML`.

This file proves the fix two ways, consistent with test_pat854_xss_onclick_
escaping.py's approach (static extraction of the real shipped source, plus a
faithful reference-port of the render logic run against a real payload —
no JS runtime dependency in the pytest-only suite):

  1. `TestReferenceRenderIsInert` ports `_escHtml`/`_opsDot`/`_opsRow` to
     Python and renders a real `<img src=x onerror=...>` payload through it,
     proving the output contains the escaped entity form and never a live
     `<img` tag — i.e. the payload is inert markup, not executable.

  2. `TestFixedSourceMatchesRealFile` extracts the ACTUAL current `_opsRow`
     source (and the backups/certs/firewall-apply call sites) from a
     live-rendered console.html and asserts the escaping calls are present.

  3. `TestNoRemainingVulnerablePattern` greps the whole template for the
     specific anti-patterns this ticket fixed, so a regression anywhere
     (not just the originally-named sites) fails this suite.
"""

import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

XSS_PAYLOAD = "<img src=x onerror=alert(document.cookie)>"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


@pytest.fixture
def console_html(client):
    r = client.get("/console")
    assert r.status_code == 200
    return r.text


def _extract_fn(text, name):
    start = text.index("function " + name + "(")
    i = text.index("{", start)
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[start:j + 1]
    raise AssertionError("unbalanced braces for " + name)


def _esc_html_reference(s):
    """Faithful port of the single `_escHtml` in console.html."""
    if s is None:
        return ""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _ops_dot_reference(ok):
    """Port of `_opsDot` — always safe: `ok` is a boolean, never attacker
    data, so its returned HTML is trusted."""
    if ok is True:
        color = "var(--success)"
    elif ok is False:
        color = "var(--danger)"
    else:
        color = "var(--text-muted)"
    return (
        '<span style="display:inline-block;width:8px;height:8px;'
        "border-radius:50%;background:" + color + ';margin-right:6px;'
        'vertical-align:middle;"></span>'
    )


def _ops_row_reference(label, val, warn=False, dot=None):
    """Faithful port of the FIXED `_opsRow(label, val, warn, dot)`."""
    dot_html = _ops_dot_reference(dot) if dot in (True, False) else ""
    return (
        '<div style="display:flex;justify-content:space-between;padding:5px 0;'
        'border-bottom:1px solid var(--card-border);font-size:var(--fs-sm);">'
        + '<span style="color:var(--text-muted);">' + _esc_html_reference(label) + "</span>"
        + '<span style="' + ("color:var(--warning);font-weight:600;" if warn else "") + '">'
        + dot_html + _esc_html_reference(val) + "</span>"
        + "</div>"
    )


class TestReferenceRenderIsInert:
    """Proves a malicious payload arriving as ops data renders inert
    (HTML-entity-escaped text), not as live markup, once run through the
    fixed `_opsRow` logic."""

    def test_malicious_label_renders_inert(self):
        rendered = _ops_row_reference(XSS_PAYLOAD, "yes", warn=False)
        assert "<img" not in rendered
        assert "onerror=alert(document.cookie)" in rendered  # present, but as inert text
        assert "&lt;img src=x onerror=alert(document.cookie)&gt;" in rendered

    def test_malicious_val_renders_inert(self):
        rendered = _ops_row_reference("Stalest tenant", XSS_PAYLOAD, warn=True)
        assert "<img" not in rendered
        assert "&lt;img src=x onerror=alert(document.cookie)&gt;" in rendered

    def test_malicious_label_and_val_both_render_inert(self):
        rendered = _ops_row_reference(XSS_PAYLOAD, XSS_PAYLOAD, warn=False)
        assert rendered.count("<img") == 0
        assert rendered.count("&lt;img") == 2

    def test_trusted_dot_markup_survives_unescaped_alongside_escaped_val(self):
        # The `dot` param is boolean-only (never attacker data), so its
        # generated <span> must still render as live markup even though the
        # adjacent `val` text is escaped — proves the fix didn't collaterally
        # break the status-dot indicator by escaping trusted, code-generated
        # HTML along with it.
        rendered = _ops_row_reference("DB reachable", "NO", warn=True, dot=False)
        assert '<span style="display:inline-block' in rendered
        assert "background:var(--danger)" in rendered

    def test_warn_boolean_is_not_escaped_or_treated_as_data(self):
        # warn=True should only ever select the style branch, never appear
        # literally in the output.
        rendered = _ops_row_reference("x", "y", warn=True)
        assert "True" not in rendered
        assert "color:var(--warning);font-weight:600;" in rendered


class TestFixedSourceMatchesRealFile:
    """Extracts the ACTUAL shipped render logic and proves the escaping
    calls are really there — not just true of the reference port above."""

    def test_opsRow_escapes_label_and_val(self, console_html):
        fn = _extract_fn(console_html, "_opsRow")
        assert "_escHtml(label)" in fn
        assert "_escHtml(val)" in fn
        # The old vulnerable pattern (bare concatenation, no escaper) must
        # not reappear.
        assert re.search(r"[\"']\s*\+\s*label\s*\+\s*[\"']", fn) is None
        assert re.search(r"[\"']\s*\+\s*val\s*\+\s*[\"']", fn) is None

    def test_opsRow_does_not_escape_warn_or_dot(self, console_html):
        fn = _extract_fn(console_html, "_opsRow")
        assert "_escHtml(warn)" not in fn
        assert "_escHtml(dot)" not in fn

    def test_backups_detail_is_escaped(self, console_html):
        fn = _extract_fn(console_html, "_opsRender")
        assert "_escHtml(b.detail)" in fn
        assert re.search(r"[\"']\s*\+\s*b\.detail\s*\+\s*[\"']", fn) is None

    def test_certs_error_row_no_longer_hand_builds_raw_html(self, console_html):
        fn = _extract_fn(console_html, "_opsRender")
        # The old vulnerable pattern wrapped raw HTML around c.error and
        # passed the whole thing as `val` (which defeated _opsRow's
        # escaping entirely, since it escapes the fragment as a whole).
        assert 'color:var(--danger);">ERR: \' + c.error' not in fn
        assert "'<span style=\"color:var(--danger);\">ERR: '" not in fn

    def test_fw_apply_result_escapes_exit_code_and_journal(self, console_html):
        fn = _extract_fn(console_html, "_opsFwApply")
        assert "_escHtml(d.exit_code)" in fn
        assert "_escHtml(d.journal)" in fn
        assert re.search(r"[\"']\s*\+\s*d\.exit_code\s*\+\s*[\"']", fn) is None
        assert re.search(r"pre\s*\+\s*d\.journal\s*\+", fn) is None


class TestNoRemainingVulnerablePattern:
    """Whole-template regression guard: a new call site that reintroduces
    any of these anti-patterns anywhere in the file fails this suite, not
    just the originally reported sites."""

    def test_no_ops_dot_concatenated_directly_into_opsRow_val_argument(self, console_html):
        # Before the fix, callers built `val` themselves as
        # `_opsDot(x) + someText` and passed the whole HTML blob as the
        # second argument to _opsRow. That pattern must not come back — the
        # dot now goes through _opsRow's own `dot` parameter.
        # Exclude the `_opsRow` function *definition* itself, which
        # legitimately builds `dotHtml` from `_opsDot(dot)` internally —
        # this guards against a *call site* like `_opsRow(x, _opsDot(y) +
        # ..., ...)` reappearing.
        assert re.search(r"(?<!function )_opsRow\([^;]*?_opsDot\(", console_html) is None

    def test_no_raw_span_wrapped_error_passed_as_opsRow_val(self, console_html):
        assert 'var(--danger);">ERR: \' + c.error + \'</span>' not in console_html
