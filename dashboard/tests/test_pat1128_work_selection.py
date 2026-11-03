"""PAT-1128: Work selection and calm service-health presentation."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text(encoding="utf-8")
CSS = (ROOT / "static" / "css" / "console.css").read_text(encoding="utf-8")
WORK_JS = (ROOT / "static" / "js" / "console-work.js").read_text(encoding="utf-8")


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


def _home_region():
    start = HTML.index('<div id="section-home"')
    end = HTML.index("<!-- ═══ SECTION: REPORTS", start)
    return HTML[start:end]


def test_work_rows_select_in_place_and_default_to_highest_visible_priority():
    fn = _extract_fn(HTML, "_renderHomeAttention")

    # The row is the single selection target: customer-name navigation would
    # bypass the inspector and change tenant context unexpectedly.
    assert "_homeSelectTenant(row.getAttribute('data-tenant-id'))" in fn
    assert "_triageDrill" not in fn
    assert "ranked.some" in fn
    assert "ranked[0].tenant.id" in fn


def test_work_rows_expose_selection_state_and_keyboard_instructions():
    fn = _extract_fn(HTML, "_renderHomeAttention")
    keyboard = _extract_fn(HTML, "_bindSelectableRows")
    home = _home_region()

    assert 'aria-selected="false"' in fn
    assert 'aria-label="' in fn
    assert 'aria-describedby="home-attention-selection-help"' in fn
    # Legacy row helpers retain their keyboard contract, but Home no longer mounts them.
    assert 'id="home-attention-selection-help"' not in home
    assert 'id="home-service-exceptions" aria-busy="true"' in home
    assert "e.key === 'Enter'" in keyboard
    assert "e.key === ' '" in keyboard
    assert "e.key !== 'ArrowDown' && e.key !== 'ArrowUp'" in keyboard


def test_inspector_retains_explicit_customer_and_signal_destinations():
    fn = _extract_fn(HTML, "_renderHomeInspector")

    assert "Open customer" in fn
    for destination in ("'cve-findings'", "'compliance-status'", "'device-health'", "'software-catalogue'"):
        assert destination in fn


def test_work_uses_accurate_estate_posture_label_and_infrastructure_link():
    home = _home_region()

    assert "<h2>Estate posture</h2>" in home
    assert "<h2>Recent activity</h2>" not in home
    assert "View Infrastructure" in home
    assert "consoleNav('ops')" in home


def test_service_health_summarises_only_green_checks():
    fn = _extract_fn(HTML, "_renderHomeHealth")

    assert "PatchedConsoleWork.renderServiceHealth" in fn
    assert "var attentionRows = [];" in WORK_JS
    assert "var healthyLabels = [];" in WORK_JS
    assert "dotClass === 'dot-green'" in WORK_JS
    assert "attentionRows.join('') + healthySummary" in WORK_JS
    assert ".home-health-summary" in CSS


def test_work_table_keeps_essential_columns_inside_a_narrow_phone_panel():
    # Work's customer rows are inspector controls, not a horizontally-scrolled
    # report. At phone widths retain the customer, device and patching columns;
    # the row label/inspector still carry the hidden posture and priority.
    assert "@media (max-width: 520px)" in CSS
    assert "#home-attention-content table { table-layout: fixed; }" in CSS
    assert "#home-attention-content th:nth-child(2)," in CSS
    assert "#home-attention-content td:nth-child(2)," in CSS
    assert "#home-attention-content th:nth-child(5)," in CSS
    assert "#home-attention-content td:nth-child(5) { display: none; }" in CSS
