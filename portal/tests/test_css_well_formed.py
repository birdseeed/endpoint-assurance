"""portal.css must parse as a whole: balanced braces, terminated comments.

A single unclosed @media block silently swallows every rule after it -
browsers drop the rest rather than erroring. That happened on 25 Sept 2026
when a rebase joined two appended blocks and lost the shared closing brace,
leaving the /software bulk bar permanently visible; PAT-2092 was the same
class of silent drop (a stray comment terminator). Catch it in the unit
suite, before a browser ever sees it.
"""

import re
from pathlib import Path

CSS = Path(__file__).resolve().parent.parent / "static" / "css" / "portal.css"


def _strip_comments(text: str) -> str:
    return re.sub(r"/\*.*?\*/", lambda m: re.sub(r"[^\n]", "", m.group(0)), text, flags=re.S)


def test_comments_are_terminated():
    text = CSS.read_text()
    assert text.count("/*") == text.count("*/"), "an unterminated /* comment swallows the rest"


def test_braces_balance_and_never_go_negative():
    depth = 0
    for lineno, line in enumerate(_strip_comments(CSS.read_text()).split("\n"), 1):
        depth += line.count("{") - line.count("}")
        assert depth >= 0, f"portal.css:{lineno} closes a block that was never opened"
    assert depth == 0, (
        f"portal.css ends {depth} block(s) deep: an unclosed block drops every rule after it"
    )
