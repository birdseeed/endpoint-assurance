"""
PAT-902, staff console docs viewer stored/reflected XSS via raw HTML in
docs/*.md.

Root cause: /api/docs/content rendered doc source with `_markdown.markdown(
text, extensions=["fenced_code", "tables", "sane_lists"])`. python-markdown
passes raw HTML embedded in the source straight through unescaped, and
templates/console.html:_docsOpen does
`'<div class="docs-viewer-body">' + d.html + '</div>'` into innerHTML with no
client-side escaping. Any docs/*.md file (or anyone with write access to one,
e.g. via a PR) containing a `<script>` tag or an `onerror=`/`onclick=`
handler executed live in the authenticated staff console.

Fix: sanitise server-side, in api_docs_content, via `_docs_sanitize_html` -
a strict allowlist HTML rebuilder (main.py, `_DocsHtmlSanitizer`) built on
`html.parser.HTMLParser` (stdlib only, no new dependency). It keeps only the
tag/attribute surface _DOCS_MD_EXTENSIONS legitimately emits and drops
everything else: disallowed tags are unwrapped (text kept, escaped), on*
attributes are never in the allowlist so they are always dropped regardless
of tag, `<script>`/`<style>` are dropped tag-and-content, and `href` values
go through a scheme allowlist (http/https/mailto, or scheme-less
relative/fragment links) that also strips the TAB/LF/CR browsers ignore when
parsing a URL scheme (the classic "java\\tscript:" filter-bypass trick).

Covers:
  * <script>...</script> is stripped entirely (tag and content).
  * <img src=x onerror=...>, the on* handler never survives; img itself is
    not in the allowlist (docs/*.md do not currently use images) so the
    whole tag is dropped too.
  * A markdown link to a javascript: URL renders with the href stripped.
  * A raw on* attribute on an otherwise-allowed tag (e.g. <a onclick=...>)
    is dropped while the tag and its safe attributes/content survive.
  * Legitimate markdown (headings, fenced code, tables, links) still renders
    with its real content intact.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

AUTH = {"Authorization": "Bearer test-key"}


@pytest.fixture
def docs_root(tmp_path, monkeypatch):
    root = tmp_path / "docs"
    root.mkdir()
    monkeypatch.setattr(dashboard, "_DOCS_ROOT", root)
    return root


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "test.db")
    dashboard.init_db()
    with TestClient(dashboard.app) as c:
        yield c


def _write_doc(root, name, text):
    p = root / name
    p.write_text(text)
    return p


class TestScriptTagStripped:
    def test_script_tag_and_content_removed(self, client, docs_root):
        _write_doc(
            docs_root, "evil.md",
            "# Evil\n\n<script>alert(1)</script>\n\nSafe paragraph.\n",
        )
        r = client.get("/api/docs/content", params={"path": "evil.md"}, headers=AUTH)
        assert r.status_code == 200
        html = r.json()["html"]
        assert "<script" not in html
        assert "alert(1)" not in html
        assert "Safe paragraph." in html

    def test_script_survives_inside_fenced_code_as_inert_text(self, client, docs_root):
        # A <script> tag typed inside a fenced code block is example text
        # (e.g. documenting a vulnerable pattern), not live markup, markdown
        # itself escapes it to &lt;script&gt; before our sanitiser ever runs,
        # so it must render as visible text, never as a real element.
        _write_doc(
            docs_root, "example.md",
            "# Example\n\n```html\n<script>alert(1)</script>\n```\n",
        )
        r = client.get("/api/docs/content", params={"path": "example.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "<script>" not in html
        assert "&lt;script&gt;" in html


class TestImgOnerrorStripped:
    def test_img_with_onerror_fully_removed(self, client, docs_root):
        _write_doc(
            docs_root, "img.md",
            '# Img\n\n<img src=x onerror=alert(1)>\n\nAfter.\n',
        )
        r = client.get("/api/docs/content", params={"path": "img.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "<img" not in html
        assert "onerror" not in html
        assert "alert(1)" not in html
        assert "After." in html


class TestJavascriptHrefStripped:
    def test_markdown_link_javascript_href_dropped(self, client, docs_root):
        _write_doc(
            docs_root, "link.md",
            "# Link\n\n[click me](javascript:alert(1))\n",
        )
        r = client.get("/api/docs/content", params={"path": "link.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "javascript:" not in html
        assert "<a>click me</a>" in html or "<a >click me</a>" in html

    def test_raw_anchor_javascript_href_dropped(self, client, docs_root):
        _write_doc(
            docs_root, "rawlink.md",
            '# Link\n\n<a href="javascript:alert(1)">go</a>\n',
        )
        r = client.get("/api/docs/content", params={"path": "rawlink.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "javascript:" not in html

    def test_tab_obfuscated_javascript_href_dropped(self, client, docs_root):
        # Browsers strip TAB/LF/CR from anywhere in a URL before parsing its
        # scheme, so "java\tscript:" resolves to "javascript:" at click time
        # even though a naive substring/prefix check on the raw attribute
        # value would miss it.
        _write_doc(
            docs_root, "obf.md",
            '# Link\n\n<a href="java&#9;script:alert(1)">go</a>\n',
        )
        r = client.get("/api/docs/content", params={"path": "obf.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "script:alert" not in html
        assert "href" not in html

    def test_https_href_survives(self, client, docs_root):
        _write_doc(docs_root, "good.md", "[docs](https://example.com/page)\n")
        r = client.get("/api/docs/content", params={"path": "good.md"}, headers=AUTH)
        html = r.json()["html"]
        assert 'href="https://example.com/page"' in html

    def test_relative_href_survives(self, client, docs_root):
        _write_doc(docs_root, "rel.md", "[other doc](SCHEMA.md)\n")
        r = client.get("/api/docs/content", params={"path": "rel.md"}, headers=AUTH)
        html = r.json()["html"]
        assert 'href="SCHEMA.md"' in html

    def test_protocol_relative_href_dropped(self, client, docs_root):
        # "//evil.example.com/x" has no "scheme:" prefix, so a naive check
        # would bucket it with genuinely relative links like "SCHEMA.md" --
        # but browsers resolve it to an absolute link to an arbitrary host
        # under the page's current scheme. Found in code review; regression
        # guard for main.py's _docs_safe_href.
        _write_doc(docs_root, "protorel.md", '<a href="//evil.example.com/phish">go</a>\n')
        r = client.get("/api/docs/content", params={"path": "protorel.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "evil.example.com" not in html
        assert "<a>go</a>" in html

    def test_backslash_normalised_protocol_relative_href_dropped(self, client, docs_root):
        # Browsers treat backslash as a path separator in URLs, so
        # "\\evil.example.com" and "/\evil.example.com" both normalise to a
        # protocol-relative link to another host, same as "//evil...".
        _write_doc(docs_root, "backslash.md", '<a href="/\\\\evil.example.com/x">go</a>\n')
        r = client.get("/api/docs/content", params={"path": "backslash.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "evil.example.com" not in html

    def test_single_leading_slash_absolute_path_href_survives(self, client, docs_root):
        # A single leading slash is a same-origin absolute path (not a
        # different host) and must stay allowed.
        _write_doc(docs_root, "abspath.md", '<a href="/docs/other.md">go</a>\n')
        r = client.get("/api/docs/content", params={"path": "abspath.md"}, headers=AUTH)
        html = r.json()["html"]
        assert 'href="/docs/other.md"' in html


class TestSelfClosedScriptStyleDropsContent:
    def test_self_closed_script_does_not_leak_following_text(self, client, docs_root):
        # HTMLParser still fires a later handle_endtag() for a self-closed
        # <script/> (the "/" is meaningless on a non-void HTML element; a
        # real browser keeps it open and treats everything up to the next
        # literal </script> as raw content). Found in code review; regression
        # guard that this content is dropped, not leaked as visible text.
        _write_doc(
            docs_root, "selfclosed.md",
            "# Doc\n\n<script/>alert(1)</script>\n\nAfter.\n",
        )
        r = client.get("/api/docs/content", params={"path": "selfclosed.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "alert(1)" not in html
        assert "After." in html

    def test_self_closed_style_does_not_leak_following_text(self, client, docs_root):
        _write_doc(
            docs_root, "selfclosedstyle.md",
            "# Doc\n\n<style/>body{color:red}</style>\n\nAfter.\n",
        )
        r = client.get("/api/docs/content", params={"path": "selfclosedstyle.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "color:red" not in html
        assert "After." in html


class TestOnAttributeStripped:
    def test_onclick_on_allowed_tag_dropped_but_tag_survives(self, client, docs_root):
        _write_doc(
            docs_root, "onclick.md",
            '# Click\n\n<a href="https://example.com" onclick="alert(1)">go</a>\n',
        )
        r = client.get("/api/docs/content", params={"path": "onclick.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "onclick" not in html
        assert "alert(1)" not in html
        assert 'href="https://example.com"' in html
        assert ">go</a>" in html

    def test_onclick_on_disallowed_tag_dropped_with_tag_unwrapped(self, client, docs_root):
        _write_doc(
            docs_root, "div.md",
            '# Div\n\n<div onclick="alert(1)">payload</div>\n',
        )
        r = client.get("/api/docs/content", params={"path": "div.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "<div" not in html
        assert "onclick" not in html
        assert "alert(1)" not in html
        assert "payload" in html


class TestLegitimateMarkdownStillRenders:
    def test_headings_lists_code_tables_links(self, client, docs_root):
        _write_doc(
            docs_root, "legit.md",
            "# System Architecture\n\n"
            "Some *emphasis* and **strong** text.\n\n"
            "- item one\n- item two\n\n"
            "```python\nprint('hello')\n```\n\n"
            "| A | B |\n|---|---|\n| 1 | 2 |\n\n"
            "[GitHub](https://github.com/Patched-LTD/dashboard)\n",
        )
        r = client.get("/api/docs/content", params={"path": "legit.md"}, headers=AUTH)
        assert r.status_code == 200
        html = r.json()["html"]
        assert "<h1>System Architecture</h1>" in html
        assert "<em>emphasis</em>" in html
        assert "<strong>strong</strong>" in html
        assert "<li>item one</li>" in html
        assert "<pre><code" in html
        assert "print('hello')" in html
        assert "<table>" in html and "<th>A</th>" in html
        assert 'href="https://github.com/Patched-LTD/dashboard"' in html

    def test_table_alignment_style_survives(self, client, docs_root):
        _write_doc(docs_root, "aligned.md", "| A | B |\n|:--|--:|\n| 1 | 2 |\n")
        r = client.get("/api/docs/content", params={"path": "aligned.md"}, headers=AUTH)
        html = r.json()["html"]
        assert 'style="text-align: left;"' in html
        assert 'style="text-align: right;"' in html

    def test_details_summary_collapsible_block_survives(self, client, docs_root):
        # docs/architecture.md uses raw <details>/<summary> for collapsible
        # previous-snapshot sections, real content, not an attack. Confirms
        # the allowlist keeps this specific pattern working end to end.
        _write_doc(
            docs_root, "collapsible.md",
            "# Architecture\n\n"
            "<details>\n<summary>Previous snapshot</summary>\n\n"
            "Some archived detail text.\n\n</details>\n",
        )
        r = client.get("/api/docs/content", params={"path": "collapsible.md"}, headers=AUTH)
        html = r.json()["html"]
        assert "<details>" in html
        assert "<summary>Previous snapshot</summary>" in html
        assert "Some archived detail text." in html
        assert "</details>" in html
