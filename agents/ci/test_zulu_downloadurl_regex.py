"""PAT-1430 regression: Azul Zulu JDK downloadURL extraction must not admit
markup into the resolved artifact URL.

Background (see PAT-1430 for the full investigation): the zulujdk11/13/15/
17/18 stanzas scraped https://cdn.azul.com/zulu/bin/ with a `grep -Eio` that
deliberately over-captures everything after the filename (`(.*)`, needed so
the same match also carries the size/date columns downstream) and then
tried to strip the markup back off with `sed 's/<\\/a>//'`. That only
stripped the `</a>` tag itself, leaving the immediately-following `</td>`
attached to the URL -- every resolved download 404s.

Two independent bugs were found, not one:

1. Markup leak: `sed 's/<\\/a>//'` does not remove `</td>`, so the
   resolved downloadURL always carried a trailing `</td>`.
2. A vestigial `awk '{print $2 $1}' | sort | cut -c11-` pipeline stage --
   apparently written for an older page layout that put a size field
   before the filename on the same matched line, which the real page no
   longer does -- silently truncated a fixed 10 leading characters off the
   real filename (e.g. "zulu11.90." on the zulujdk11 arm64 build), even
   after the `</td>` leak above is fixed. Both bugs had to be fixed for
   the five affected labels to resolve to a real (HTTP 200) artifact.

Critically, the vendor markup itself is IDENTICAL between the five broken
labels and the five that already worked -- `...dmg</a></td>` on every row,
regardless of JDK version. The "not affected" labels (zulujdk8/21/23,
zulujdkfx17) worked only because their sed had already been special-cased
to strip `</a></td>` (an ad hoc fix for the one fragment observed at the
time) and they never accumulated the `cut -c11-` bug. That ad hoc
`</a></td>` strip is itself exactly the fragile pattern PAT-1430 replaced:
special-casing one observed markup shape rather than making the capture
structurally incapable of carrying `<`, `>` or whitespace at all. This
test proves the fix that replaced both patterns -- `sed -E
's/[<[:space:]].*//'` -- generalizes beyond the one fragment ever actually
observed (`</td>`), by also exercising a markup tail that was never seen
in production.

A follow-up review pass (same day) found the fix had landed as THREE
distinct pipeline shapes across the 18 stanza lines rather than one: the
five originally-broken labels got the full structural rewrite, but
zulujdk21/23/8 kept a vestigial `sed 's/…M//' | awk '{print $2 $1}'` stage
(a no-op today -- exactly the species of dead pipeline stage that the
`cut -c11-` bug turned out to be, just not yet fatal), and zulujdkfx17 kept
plain `sort` instead of `sort -V`. Plain `sort` on `zulu17.9.11-...` vs
`zulu17.100.4-...` orders "100" before "9" lexicographically and would
silently resolve an OLDER JDK as "latest" the moment Azul publishes a
minor >= 100 or a single-digit minor after a double-digit one -- the same
"looks healthy, quietly returns the wrong artifact" failure class as the
bug this ticket started from. All 18 lines were made byte-identical
(`sed -E 's/[<[:space:]].*//' | sort -V | tail -1`); a version-ordering
test for zulujdkfx17 below pins that.

This test executes the REAL, committed shell one-liners lifted verbatim out
of engine/Installomator.sh (not a re-implementation of the regex), with
`curl` stubbed to serve a committed HTML fixture instead of the network, so
the pin tracks the shipped code rather than a copy of it that could drift.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "engine" / "Installomator.sh"
FIXTURE = ROOT / "ci" / "fixtures" / "azul-zulu-bin-index-fragment.html"

# A markup tail that has never actually been observed on Azul's page --
# deliberately NOT `</td>`, the one fragment the original bug report was
# scoped to. If the fix special-cased `</td>` instead of truncating at the
# first `<` or whitespace generically, this row would still leak markup.
SYNTHETIC_TAIL_ROW = (
    '\t\t<tr>\n'
    '\t\t\t<td><a href="/zulu/bin/zulu17.99.1-ca-jdk17.0.99-macosx_aarch64.dmg">'
    'zulu17.99.1-ca-jdk17.0.99-macosx_aarch64.dmg</a> <!-- new CDN annotation --></td>\n'
    '\t\t\t<td>2026-08-19 00:00</td>\n'
    '\t\t</tr>\n'
)

# Three more synthetic, never-actually-observed shapes, each proving the
# structural sed does not depend on the ONE fragment (`</td>`, no attrs, no
# wrapper) that PAT-1430's original bug report happened to be scoped to.

# 1. Extra attributes on the <a> tag itself (e.g. a `rel` the vendor adds).
#    These sit BEFORE the `">` that anchors the grep match against the link
#    TEXT (not the href), so they should not perturb extraction at all --
#    this pins that the pattern keys off the closing `">` immediately
#    preceding the visible filename, not off `<a href=` specifically.
EXTRA_ATTRIBUTE_ROW = (
    '\t\t<tr>\n'
    '\t\t\t<td><a href="/zulu/bin/zulu17.70.1-ca-jdk17.0.21-macosx_aarch64.dmg" '
    'rel="nofollow" data-cdn="mirror-3">'
    'zulu17.70.1-ca-jdk17.0.21-macosx_aarch64.dmg</a></td>\n'
    '\t\t\t<td>2026-08-19 00:00</td>\n'
    '\t\t</tr>\n'
)

# 2. Whitespace between `</a>` and `</td>` on the SAME line (rather than the
#    real page's `</a></td>` with nothing between them). The structural sed
#    truncates at the first `<` OR whitespace, so the space itself is the
#    cut point here, not the `<`.
WHITESPACE_BEFORE_TD_ROW = (
    '\t\t<tr>\n'
    '\t\t\t<td><a href="/zulu/bin/zulu17.71.1-ca-jdk17.0.22-macosx_aarch64.dmg">'
    'zulu17.71.1-ca-jdk17.0.22-macosx_aarch64.dmg</a>   </td>\n'
    '\t\t\t<td>2026-08-19 00:00</td>\n'
    '\t\t</tr>\n'
)

# 3. A wrapper element after `</a>` instead of the real page's bare `</td>`
#    (e.g. a "NEW" badge some future CDN redesign wraps the cell in).
SPAN_WRAPPER_ROW = (
    '\t\t<tr>\n'
    '\t\t\t<td><a href="/zulu/bin/zulu17.72.1-ca-jdk17.0.23-macosx_aarch64.dmg">'
    'zulu17.72.1-ca-jdk17.0.23-macosx_aarch64.dmg</a><span class="new-badge">NEW</span></td>\n'
    '\t\t\t<td>2026-08-19 00:00</td>\n'
    '\t\t</tr>\n'
)

# zulujdkfx17 regression fixture (PAT-1430 follow-up review): the exact
# scenario the review named -- a minor version >= 100 alongside a
# single-digit minor. Plain `sort` orders "100" before "9" lexicographically
# and would pick zulu17.9.11 (the OLDER jdk17.0.21 build) as "latest";
# `sort -V` correctly picks zulu17.100.4 (jdk17.0.22).
FX17_VERSION_ORDER_ROWS = (
    '\t\t<tr>\n'
    '\t\t\t<td><a href="/zulu/bin/zulu17.68.17-ca-fx-jdk17.0.20-macosx_aarch64.dmg">'
    'zulu17.68.17-ca-fx-jdk17.0.20-macosx_aarch64.dmg</a></td>\n'
    '\t\t\t<td>2026-07-01 00:00</td>\n'
    '\t\t</tr>\n'
    '\t\t<tr>\n'
    '\t\t\t<td><a href="/zulu/bin/zulu17.9.11-ca-fx-jdk17.0.21-macosx_aarch64.dmg">'
    'zulu17.9.11-ca-fx-jdk17.0.21-macosx_aarch64.dmg</a></td>\n'
    '\t\t\t<td>2026-10-01 00:00</td>\n'
    '\t\t</tr>\n'
    '\t\t<tr>\n'
    '\t\t\t<td><a href="/zulu/bin/zulu17.100.4-ca-fx-jdk17.0.22-macosx_aarch64.dmg">'
    'zulu17.100.4-ca-fx-jdk17.0.22-macosx_aarch64.dmg</a></td>\n'
    '\t\t\t<td>2026-08-01 00:00</td>\n'
    '\t\t</tr>\n'
)

MARKUP_OR_WHITESPACE_RE = re.compile(r"[<> \t\n\r]")


class ZuluDownloadURLRegexTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine_text = ENGINE.read_text(encoding="utf-8")
        assert FIXTURE.is_file(), f"missing fixture: {FIXTURE}"

    def _stanza(self, label: str) -> str:
        """Extract the real `<label>) ... ;;` case-arm body verbatim from
        the committed engine. Zulu stanzas contain only if/elif/fi (no
        nested case block), so the first `\\n    ;;\\n` after the header
        reliably closes the arm."""
        match = re.search(
            rf"^{re.escape(label)}\)\n(.*?)\n    ;;\n",
            self.engine_text,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(match, f"could not locate stanza for label {label!r}")
        return match.group(1)

    def _resolve(self, label: str, *, arch: str, fixture_path: Path) -> subprocess.CompletedProcess:
        """Run the label's real downloadURL-resolution logic under zsh,
        with `arch` and `curl` stubbed -- the same "stub only the side
        effect, execute the real production logic" convention used by
        ci/test_installomator_execution_contract.py and
        ci/test-pkgindmg-runtime.zsh."""
        stanza = self._stanza(label)
        script = f'''
arch() {{ print -r -- "{arch}"; }}
curl() {{ cat "{fixture_path}"; }}
printlog() {{ :; }}
{stanza}
print -r -- "DOWNLOADURL:$downloadURL"
'''
        return subprocess.run(
            ["zsh", "-f", "-c", script],
            text=True,
            capture_output=True,
            check=False,
        )

    def _downloadurl(self, result: subprocess.CompletedProcess) -> str:
        self.assertEqual(0, result.returncode, result.stderr)
        match = re.search(r"^DOWNLOADURL:(.*)$", result.stdout, re.MULTILINE)
        self.assertIsNotNone(match, result.stdout)
        return match.group(1)

    # -- the five labels PAT-1430 fixed --------------------------------

    def test_zulujdk17_arm64_resolves_clean_url_against_real_markup_shape(self):
        """zulujdk17 (one of the five affected labels) against the real,
        vendor-captured fixture: no `<`, `>`, or whitespace anywhere in the
        resolved URL, and it selects the newer of the two fixture rows."""
        result = self._resolve("zulujdk17", arch="arm64", fixture_path=FIXTURE)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu17.68.203-ca-jdk17.0.20.1-macosx_aarch64.dmg",
            url,
        )

    def test_zulujdk17_x64_resolves_clean_url_against_real_markup_shape(self):
        result = self._resolve("zulujdk17", arch="i386", fixture_path=FIXTURE)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu17.68.203-ca-jdk17.0.20.1-macosx_x64.dmg",
            url,
        )

    def test_zulujdk17_does_not_special_case_the_observed_td_fragment(self):
        """The fix must be structural (truncate at the first `<` or
        whitespace), not a special case for `</td>`. Exercise a markup
        tail that was never actually observed on Azul's page and prove it
        is still stripped cleanly."""
        fixture = Path(self._write_tmp_fixture(SYNTHETIC_TAIL_ROW))
        result = self._resolve("zulujdk17", arch="arm64", fixture_path=fixture)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu17.99.1-ca-jdk17.0.99-macosx_aarch64.dmg",
            url,
        )

    def test_zulujdk17_survives_extra_attributes_on_the_anchor_tag(self):
        """A `rel`/`data-*` attribute on the `<a>` tag itself must not
        perturb extraction -- the match keys off the closing `">`
        immediately before the visible filename, not off `<a href=`."""
        fixture = Path(self._write_tmp_fixture(EXTRA_ATTRIBUTE_ROW))
        result = self._resolve("zulujdk17", arch="arm64", fixture_path=fixture)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu17.70.1-ca-jdk17.0.21-macosx_aarch64.dmg",
            url,
        )

    def test_zulujdk17_survives_whitespace_between_anchor_close_and_td(self):
        """Whitespace (not markup) between `</a>` and `</td>` on the same
        line must also be cut -- the fix truncates at the first `<` OR
        whitespace, not just the first `<`."""
        fixture = Path(self._write_tmp_fixture(WHITESPACE_BEFORE_TD_ROW))
        result = self._resolve("zulujdk17", arch="arm64", fixture_path=fixture)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu17.71.1-ca-jdk17.0.22-macosx_aarch64.dmg",
            url,
        )

    def test_zulujdk17_survives_span_wrapper_after_anchor(self):
        """A non-`</td>` wrapper element (e.g. a "NEW" badge span) right
        after `</a>` must be cut just as cleanly as `</td>` is."""
        fixture = Path(self._write_tmp_fixture(SPAN_WRAPPER_ROW))
        result = self._resolve("zulujdk17", arch="arm64", fixture_path=fixture)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu17.72.1-ca-jdk17.0.23-macosx_aarch64.dmg",
            url,
        )

    def test_zulujdk11_arm64_resolves_clean_url_against_real_markup_shape(self):
        """zulujdk11 is the specific label whose real-world breakage (the
        `...macosx_aarch64.dmg</td>` example quoted in the ticket, itself
        missing the "zulu11.90." prefix too -- see module docstring) started
        this investigation. Prove it against the real fixture directly,
        not just via its sibling zulujdk17."""
        result = self._resolve("zulujdk11", arch="arm64", fixture_path=FIXTURE)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu11.90.205-ca-jdk11.0.32.1-macosx_aarch64.dmg",
            url,
        )

    def test_zulujdk11_x64_resolves_clean_url_against_real_markup_shape(self):
        result = self._resolve("zulujdk11", arch="i386", fixture_path=FIXTURE)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu11.90.205-ca-jdk11.0.32.1-macosx_x64.dmg",
            url,
        )

    # -- the pipeline-uniformity follow-up (same-day review) ------------

    def test_zulujdkfx17_uses_version_sort_not_lexicographic_sort(self):
        """zulujdkfx17 kept plain `sort` (not `sort -V`) even after the
        main fix landed. Against three candidates spanning a double-digit
        minor followed by a single-digit minor followed by a minor >= 100
        (zulu17.68 / zulu17.9 / zulu17.100 -- the exact shape the review
        flagged), plain `sort` would pick zulu17.9.11 (an OLDER jdk17.0.21
        build, since "9" > "100" and "68" lexicographically) as "latest".
        `sort -V` must pick zulu17.100.4 (jdk17.0.22), the real latest."""
        fixture = Path(self._write_tmp_fixture(FX17_VERSION_ORDER_ROWS))
        result = self._resolve("zulujdkfx17", arch="arm64", fixture_path=fixture)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu17.100.4-ca-fx-jdk17.0.22-macosx_aarch64.dmg",
            url,
        )

    def test_all_eighteen_zulu_downloadurl_lines_share_one_pipeline_shape(self):
        """The point of the structural fix is ONE extraction shape, not
        several independently-maintained variants that can drift apart
        (as zulujdk21/23/8's vestigial `awk`/`M`-strip stage and
        zulujdkfx17's plain `sort` did in the first cut of this fix).
        Pin that all 18 `downloadURL=https://cdn.azul.com/zulu/bin/...`
        lines (9 labels x 2 archs; zulujdk25 uses a JSON API, not this
        HTML-scrape shape, and is out of scope) end with the exact same
        tail."""
        expected_tail = "sed -E 's/[<[:space:]].*//' | sort -V | tail -1)"
        lines = [
            line
            for line in self.engine_text.splitlines()
            if "downloadURL=https://cdn.azul.com/zulu/bin/$(curl" in line
        ]
        self.assertEqual(18, len(lines), f"expected 18 zulu scrape lines, found {len(lines)}")
        for line in lines:
            self.assertTrue(
                line.rstrip().endswith(expected_tail),
                f"pipeline shape drifted from the shared structural extraction: {line.strip()!r}",
            )

    def _write_tmp_fixture(self, row_html: str) -> str:
        import tempfile

        handle = tempfile.NamedTemporaryFile(
            mode="w", suffix=".html", delete=False, encoding="utf-8"
        )
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        handle.write(row_html)
        handle.close()
        return handle.name

    # -- the labels that already worked: must not regress ---------------

    def test_zulujdk8_arm64_still_resolves_clean_url(self):
        """zulujdk8 already stripped `</a></td>` before this fix. Prove the
        replacement (structural, not `</td>`-specific) still resolves it
        correctly against the same real markup shape."""
        result = self._resolve("zulujdk8", arch="arm64", fixture_path=FIXTURE)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu8.96.0.205-ca-jdk8.0.504-macosx_aarch64.dmg",
            url,
        )

    def test_zulujdk8_x64_still_resolves_clean_url(self):
        result = self._resolve("zulujdk8", arch="i386", fixture_path=FIXTURE)
        url = self._downloadurl(result)
        self.assertNotRegex(url, MARKUP_OR_WHITESPACE_RE, f"markup/whitespace leaked into URL: {url!r}")
        self.assertEqual(
            "https://cdn.azul.com/zulu/bin/zulu8.96.0.205-ca-jdk8.0.504-macosx_x64.dmg",
            url,
        )


if __name__ == "__main__":
    unittest.main()
