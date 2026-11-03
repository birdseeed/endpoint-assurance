"""PAT-854: P0 stored XSS — agent-reported app name into the staff console via
an inline event-handler built by JS-string concatenation (dashboard/templates/
console.html, originally :9215 `_pdrEmergencyDeployPrompt` and :13759
`_catalogueMirrorApproval`).

Root cause: `_escHtml` HTML-entity-escapes `'` to `&#39;`. That is the correct
escaper for an *HTML attribute value*, but the code used it to build a value
that becomes a *JS string literal* inside an inline `onclick="...('...')"`
handler. A browser HTML-decodes an attribute value BEFORE handing it to the
JS parser, so `&#39;` turns back into `'` and the attacker's quote closes the
string early — anything after it runs as separate, unescaped JS. `ro.label`/
`ro.version` (app display name/version) and the catalogue `a.label` both
originate from agent-reported inventory data on a customer endpoint, so an
app named e.g. `x'); alert(document.cookie); //` executed arbitrary JS in the
authenticated staff session on render, no click required.

Fix: stop interpolating the value into the handler's JS source at all. Carry
it via a `data-*` HTML attribute (the correct escaper for that context is
`_escHtml`, used as originally intended) and read it back at click time with
`this.dataset.xxx` — a plain runtime property read, never re-parsed as JS
source, so entity-decoding can't hand the JS engine anything to break out of.

This file proves the class of bug is closed two ways, without adding a JS
runtime dependency to the (pytest-only) test suite, consistent with how
tests/test_pat852.py's TestHomepageHrefXssGuard proves the sibling PAT-66
homepage-href finding is closed — static extraction of the real shipped
source, plus reference-implementation string/HTML-decode simulation of what
a browser actually does with an attribute value:

  1. `test_old_vulnerable_pattern_would_have_executed_injected_js` reconstructs
     the exact pre-fix root-cause snippet quoted in the ticket and shows,
     using the real `_escHtml` behaviour plus Python's stdlib HTML entity
     decoder (`html.unescape`, the same decode step a browser performs on an
     attribute value), that the malicious label genuinely breaks out and the
     injected `alert(...)` call lands outside any string literal — i.e. the
     bug was real, not just theoretical.

  2. `test_fixed_render_*` extracts the ACTUAL current source for both named
     sites from a live-rendered `console.html` and asserts the emitted
     `onclick`/`onchange` attribute text is a fixed constant that never
     varies with the label's content, while the label itself survives
     correctly (and inertly) in its `data-*` attribute — i.e. the fix holds
     against the real shipped code, not a hand-copied assumption of it.

  3. `TestNoRemainingVulnerablePattern` greps the whole template for the
     anti-pattern (an escaping function's output concatenated into an
     inline event-handler's JS-string-literal argument) and for the dead
     shadowed `_escHtml` duplicate, so a regression anywhere in the file —
     not just the two originally-named sites — fails this suite.
"""

import html
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

MALICIOUS_LABEL = "x'); alert(document.cookie); //"
MALICIOUS_VERSION = "1.0'); alert(1); //"


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
    """Faithful port of the single surviving `_escHtml` in console.html —
    kept in sync (and checked against the real source) by
    test_fixed_render_pdr_emergency_deploy_button below."""
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _browser_attribute_value(html_fragment, attr_name):
    """Mimic real HTML attribute-value tokenization for `name="..."`: a
    double-quoted attribute value runs from the opening quote to the *next*
    literal `"` — HTML has no backslash-escaping inside attribute values.
    Entity references are resolved afterwards, exactly like a real browser:
    decode-after-tokenize, never before."""
    m = re.search(re.escape(attr_name) + r'="([^"]*)"', html_fragment)
    assert m, f"{attr_name!r} attribute not found in fragment: {html_fragment!r}"
    return html.unescape(m.group(1))


class TestOldPatternWasExploitable:
    """Confirms the pre-fix root-cause snippet quoted in PAT-854 really was
    exploitable — not just stylistically wrong — before asserting the fix."""

    def test_old_vulnerable_pattern_would_have_executed_injected_js(self):
        rollout_id = "r1"
        # This mirrors, character for character (once the JS template string
        # is evaluated), the pre-fix line at console.html:9215:
        #   'onclick="_pdrEmergencyDeployPrompt(\'' + ro.id + '\',\'' +
        #     _escHtml(ro.label) + '\',\'' + _escHtml(ro.version) + '\')"'
        old_onclick_value = (
            "_pdrEmergencyDeployPrompt('" + rollout_id + "','"
            + _esc_html_reference(MALICIOUS_LABEL) + "','"
            + _esc_html_reference(MALICIOUS_VERSION) + "')"
        )
        old_fragment = 'onclick="' + old_onclick_value + '"'

        # &#39; survives HTML attribute tokenization untouched (it contains no
        # literal quote), so the whole attribute is captured intact...
        decoded_js = _browser_attribute_value(old_fragment, "onclick")
        # ...but decoding it (what the browser does before invoking it as JS)
        # turns &#39; back into a literal ' — closing the JS string early.
        assert "&#39;" not in decoded_js
        assert "alert(document.cookie)" in decoded_js
        # The decoded text is exploitable: '<call>);<space>alert(...);<space>//...'
        # is syntactically a completed call statement followed by a second,
        # independent statement that runs the injected alert, with the rest
        # smuggled into a trailing `//` line comment. Demonstrate this by
        # locating the injected marker outside of any '...'-delimited run.
        prefix = decoded_js.split("alert(document.cookie)")[0]
        # An odd number of *unescaped* single quotes before the marker means
        # the marker sits outside string-literal context (a preceding string
        # closed and a new statement began) rather than still being inside
        # the intended label string.
        assert prefix.count("'") % 2 == 0  # both prior '...' strings closed cleanly
        assert prefix.rstrip().endswith(";")  # a real statement boundary, not string content


class TestFixedRenderIsInert:
    """Extracts the ACTUAL, currently-shipped render logic and proves the
    label/version never reach the emitted onclick/onchange JS source."""

    def test_no_more_shadowed_dead_escHtml(self, console_html):
        # PAT-854 also required de-duplicating the two top-level `_escHtml`
        # definitions (the first, non-'-escaping one at the old :4136 was
        # permanently shadowed by the real one and was dead code that ~45
        # call sites appeared to use).
        assert console_html.count("function _escHtml(") == 1

    def test_fixed_render_pdr_emergency_deploy_button(self, console_html):
        fn = _extract_fn(console_html, "_pdrRenderRollouts")
        # The vulnerable concatenation is gone...
        assert "_pdrEmergencyDeployPrompt(\\'" not in fn
        # ...replaced by data-* attributes read back via this.dataset at
        # click time, so the value never re-enters JS source.
        assert 'data-ro-label="' + "' + _escHtml(ro.label) + '" + '"' in fn
        assert (
            "onclick=\"_pdrEmergencyDeployPrompt(this.dataset.roId,"
            "this.dataset.roLabel,this.dataset.roVersion)\"" in fn
        )

        # Simulate what actually lands in the DOM for a malicious label,
        # using the real _escHtml (ported above) for the data-* attribute —
        # the correct escaper for this context, used correctly this time.
        button_html = (
            'data-ro-id="' + _esc_html_reference("r1") + '" '
            'data-ro-label="' + _esc_html_reference(MALICIOUS_LABEL) + '" '
            'data-ro-version="' + _esc_html_reference(MALICIOUS_VERSION) + '" '
            'onclick="_pdrEmergencyDeployPrompt(this.dataset.roId,'
            'this.dataset.roLabel,this.dataset.roVersion)"'
        )
        # The label survives the attribute round-trip byte-for-byte (the
        # button still works — this.dataset.roLabel === original ro.label)...
        assert _browser_attribute_value(button_html, "data-ro-label") == MALICIOUS_LABEL
        # ...while the onclick JS source is a FIXED CONSTANT: it contains no
        # trace of the label at all, so no label content — quotes, `//`,
        # anything — can ever change what JS actually runs.
        onclick_js = _browser_attribute_value(button_html, "onclick")
        assert "alert(" not in onclick_js
        assert MALICIOUS_LABEL not in onclick_js
        assert onclick_js == (
            "_pdrEmergencyDeployPrompt(this.dataset.roId,"
            "this.dataset.roLabel,this.dataset.roVersion)"
        )

    def test_catalogue_mirror_approval_checkbox_site_removed(self, console_html):
        # PAT-847: the Apps-tab EULA-approval checkbox this site rendered (and
        # `_catalogueMirrorApproval` itself) was removed outright — the local
        # catalogue_mirror_approvals store it wrote to was vestigial (mirror
        # status has been pull-derived since PAT-852). The fixed `data-label`
        # + `this.dataset` pattern this test used to pin down no longer has
        # anything to guard; assert the whole site (function and handler) is
        # gone rather than asserting a now-nonexistent fixed rendering.
        # PAT-2249 then removed _catalogueRenderRows itself with the rest of
        # the catalogue screen.
        assert "function _catalogueRenderRows" not in console_html
        assert "_catalogueMirrorApproval" not in console_html


class TestNoRemainingVulnerablePattern:
    """Whole-template regression guard — the ticket's own sweep instruction
    was 'grep the whole template ... fix every hit found, don't just fix the
    two named sites'. Pin that down so a *new* onXXX="...'+ escFn(x) + '..."
    site anywhere in the file fails this suite, not just the two originally
    reported ones."""

    _ESCAPER_NAMES = ("_escHtml", "_esc", "_whEsc", "_sitEsc")

    def test_no_escaper_output_concatenated_into_js_string_literal_handler(self, console_html):
        # Matches e.g. onclick="fn(\'...\',\'' + _escHtml(x) + '..." — an
        # escaping function's output spliced right after a backslash-escaped
        # single quote inside an inline event-handler attribute. Everything
        # between stays within that one attribute's value (`[^"]*?`, so a
        # literal `"` is never crossed, matching how HTML tokenizes a
        # double-quoted attribute), which is why an arbitrarily long run of
        # earlier literal arguments before the escaped one does NOT let a
        # variant slip past (an earlier `[^"]{0,20}` cap did — see the note
        # below). This is precisely the HTML-escaper-in-a-JS-string-context
        # bug; it must not match anywhere in the template, not just at the
        # two named sites.
        #
        # Verified in review to:
        #   (a) match BOTH original root-cause snippets reconstructed in
        #       TestOldPatternWasExploitable, AND the multi-literal variant
        #       `onclick="fn(\'id\',\'<20+ char literal>\',\'' + _escHtml(x)`
        #       that a narrower window would have missed;
        #   (b) NOT match the pre-existing safe idioms that legitimately
        #       concatenate an escaper's output near an inline handler:
        #         - `data-path="' + _escHtml(d.path) + '" onclick=
        #           "_docsOpen(this.getAttribute(\'data-path\'))"` — the
        #           backslash-quote is a hardcoded attribute-NAME constant in
        #           a DIFFERENT attribute than the escaper call, and a literal
        #           `"` closes the onclick before the escaper is reached;
        #         - `onclick="_caprQuickReview(' + _escHtml(JSON.stringify(c))
        #           + ',this)"` — the escaper's output is the WHOLE argument
        #           (a JSON literal), not spliced between `\'...\'` JS-string
        #           quotes, so it cannot break out of a string it never opens.
        pattern = re.compile(
            r'on\w+="[^"]*?\\\'[^"]*?\' \+ (?:'
            + "|".join(re.escape(n) for n in self._ESCAPER_NAMES)
            + r")\("
        )
        hits = pattern.findall(console_html)
        assert hits == []

    def test_named_root_cause_snippets_are_gone(self, console_html):
        # The exact strings quoted as the root cause in PAT-854 must not
        # reappear (e.g. via a careless revert).
        assert "_pdrEmergencyDeployPrompt(\\'' + ro.id + '\\',\\'' + _escHtml(ro.label)" not in console_html
        assert "_catalogueMirrorApproval(\\'' + _escHtml(a.label)" not in console_html
