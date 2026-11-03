"""PAT-1997: the Approval column needs a dedicated width and nowrap
controls, or they wrap mid-word against the table-scroll edge - see
portal.css for the full story.

PAT-2070 and PAT-2092 widened it to 210px for the longest mailto link,
"Ask us to confirm first ->".

PAT-2008: the mailto links are gone. Round 1 held at most two stacked
approval buttons and a History link, each a short nowrap word, or a locked
row's reason, which wraps at spaces - 130px fit "Unapprove" with margin.

PAT-2120: every row now uses PAT-2008 round 2's richer select + Apply
pattern (a state select, Apply, the bulk checkbox, a state pill and
History), not the old button list - 130px overflowed the merged table's
card at 1440px+, so this reuses the old inventory table's own measured
195px (PAT-2119)."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_software_actions_column_has_dedicated_width_and_nowrap():
    source = (ROOT / "templates" / "software.html").read_text()
    css = (ROOT / "static" / "css" / "portal.css").read_text()

    assert '<col class="software-col-actions">' in source
    assert ".software-col-actions { width: 195px; }" in css
    button_rule = css[css.index(".approval__btn {"):]
    button_rule = button_rule[:button_rule.index("}")]
    assert "white-space: nowrap;" in button_rule
