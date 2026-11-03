"""
PAT-1635: unify the dashboard's five Slack senders behind one shared block
builder (_build_alert_blocks) and its helpers.

Covers the specific defects the ticket names:
  * A datetime.timedelta must never reach rendered Slack text in its raw
    repr form (e.g. "8:35:16.811440") -- _format_alert_value rounds it to
    whole minutes/hours.
  * Long text is truncated on a word boundary, never mid-token
    (_truncate_alert_text).
  * check_statuses rows that report a byte-identical body collapse to one
    digest line noting how many other checks reported the same thing
    (_dedupe_check_lines) -- the maintenance_prod01 /
    tick_maintenance_prod01_fast / tick_maintenance_drift_check triple.
  * None of the five Slack senders' own string literals (outside their
    docstrings) contain an em dash.
  * severity/resolved drive a consistent icon via _build_alert_blocks.

Run with: pytest tests/test_pat1635_alert_blocks.py -v
"""

import ast
import inspect
import os
import sys
import textwrap
from datetime import timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ.setdefault("DASHBOARD_API_KEY", "test-key")

import main as dashboard  # noqa: E402


# ── _format_alert_value: timedelta must never reach rendered output raw ────


def test_timedelta_never_reaches_rendered_output_unformatted():
    # The exact historical leak this ticket names: str(timedelta(...)) is
    # "8:35:16.811440" -- microseconds and a bare colon-separated repr, not
    # human text. _format_alert_value must never produce that shape.
    raw = timedelta(hours=8, minutes=35, seconds=16, microseconds=811440)
    rendered = dashboard._format_alert_value(raw)
    assert "811440" not in rendered  # no microseconds
    assert "." not in rendered  # no fractional-second remnant at all
    assert rendered == "8h 35m"


def test_timedelta_under_an_hour_renders_in_minutes():
    assert dashboard._format_alert_value(timedelta(minutes=42, seconds=59)) == "43m"


def test_build_alert_blocks_formats_timedelta_fields():
    """Integration check: a timedelta handed to _build_alert_blocks via
    `fields` must come out formatted in the actual blocks payload, not as
    a raw repr -- this is the shape _run_automation_alerts_tick's staleness
    section relies on."""
    blocks = dashboard._build_alert_blocks(
        "warning",
        "Automation lagging: nightly_export",
        fields=[("Time since", timedelta(hours=8, minutes=35, seconds=16, microseconds=811440))],
    )
    rendered = str(blocks)
    assert "811440" not in rendered
    assert "8:35:16" not in rendered
    assert "8h 35m" in rendered


# ── _truncate_alert_text: truncate on a boundary, never mid-token ──────────


def test_truncate_alert_text_short_string_unchanged():
    assert dashboard._truncate_alert_text("short", limit=500) == "short"


def test_truncate_alert_text_breaks_on_word_boundary():
    text = "word " * 40 + "trailingtoken extra words after the cut point"
    truncated = dashboard._truncate_alert_text(text, limit=50)
    assert truncated.endswith("…")
    body = truncated[:-1].rstrip()
    # Every token in the truncated body must be a complete token from the
    # original string -- none may be a partial prefix of a longer word.
    original_tokens = set(text.split())
    for token in body.split():
        assert token in original_tokens, f"{token!r} was cut mid-word"


def test_truncate_alert_text_does_not_cut_a_single_long_word_falsely_clean():
    # A string with no whitespace before the limit has no boundary to back
    # off to -- must still terminate (no crash, no runaway growth) rather
    # than silently emit an unbounded string.
    text = "x" * 40 + " " + "y" * 40
    truncated = dashboard._truncate_alert_text(text, limit=10)
    assert len(truncated) <= 11  # 10 chars + the ellipsis marker


# ── _dedupe_check_lines: collapse identical bodies in the digest ───────────


def test_dedupe_check_lines_collapses_identical_bodies():
    checks = [
        {"name": "maintenance_prod01", "state": "degraded", "reason": "stray config backup found"},
        {"name": "tick_maintenance_prod01_fast", "state": "degraded", "reason": "stray config backup found"},
        {"name": "tick_maintenance_drift_check", "state": "degraded", "reason": "stray config backup found"},
    ]
    lines = dashboard._dedupe_check_lines(checks)
    assert len(lines) == 1
    assert "maintenance_prod01" in lines[0]
    assert "also reported by 2 other checks" in lines[0]
    # The two collapsed names must not each print their own full body line.
    assert "tick_maintenance_prod01_fast`" not in lines[0]


def test_dedupe_check_lines_keeps_distinct_bodies_separate():
    checks = [
        {"name": "deploy_drift", "state": "degraded", "reason": "checkout HEAD does not match"},
        {"name": "portal_auth", "state": "degraded", "reason": "AUD mismatch"},
    ]
    lines = dashboard._dedupe_check_lines(checks)
    assert len(lines) == 2
    assert "also reported by" not in lines[0]
    assert "also reported by" not in lines[1]


def test_dedupe_check_lines_singular_suffix():
    checks = [
        {"name": "maintenance_prod01", "state": "degraded", "reason": "same body"},
        {"name": "tick_maintenance_drift_check", "state": "degraded", "reason": "same body"},
    ]
    lines = dashboard._dedupe_check_lines(checks)
    assert len(lines) == 1
    assert "also reported by 1 other check)" in lines[0]


# ── severity/resolved -> icon ───────────────────────────────────────────────


def test_critical_severity_uses_red_circle():
    blocks = dashboard._build_alert_blocks("critical", "Something broke")
    assert ":red_circle:" in str(blocks)


def test_warning_severity_uses_warning_icon():
    blocks = dashboard._build_alert_blocks("warning", "Something is lagging")
    assert ":warning:" in str(blocks)


def test_resolved_overrides_severity_icon():
    # A resolved event always renders the checkmark, regardless of the
    # severity of whatever it is recovering from.
    blocks = dashboard._build_alert_blocks("critical", "Back to normal", resolved=True)
    text = str(blocks)
    assert ":white_check_mark:" in text
    assert ":red_circle:" not in text


# ── No em dash in any of the five senders' own outbound string literals ────


_FIVE_SENDERS = [
    "_send_check_status_alert",
    "_run_automation_alerts_tick",
    "_run_automation_digest_tick",
    "_send_health_alert",
    "_send_portal_auth_alert",
]


def _string_literals(fn) -> list:
    """Every string constant literal in the function's body, excluding its
    own docstring -- this file's docstrings and inline `#` comments are
    allowed to use an em dash (established codebase style, see AGENTS.md's
    "no em dashes in shippable copy" scoped to outbound copy, not internal
    prose); what must never carry one is a literal that ends up in the
    Slack payload itself."""
    src = textwrap.dedent(inspect.getsource(fn))
    tree = ast.parse(src)
    func_node = tree.body[0]
    body = list(func_node.body)
    if body:
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(getattr(first, "value", None), ast.Constant)
            and isinstance(first.value.value, str)
        ):
            body = body[1:]  # drop the docstring statement itself

    literals = []

    class _StrCollector(ast.NodeVisitor):
        def visit_Constant(self, node):
            if isinstance(node.value, str):
                literals.append(node.value)

    collector = _StrCollector()
    for stmt in body:
        collector.visit(stmt)
    return literals


@pytest.mark.parametrize("name", _FIVE_SENDERS)
def test_no_em_dash_in_sender_outbound_literals(name):
    fn = getattr(dashboard, name)
    offenders = [s for s in _string_literals(fn) if "—" in s]
    assert offenders == [], f"{name} has an em dash in outbound string literal(s): {offenders!r}"


def test_shared_builder_itself_has_no_em_dash_in_string_literals():
    offenders = [s for s in _string_literals(dashboard._build_alert_blocks) if "—" in s]
    assert offenders == []
