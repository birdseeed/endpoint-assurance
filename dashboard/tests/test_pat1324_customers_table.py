"""PAT-1324: Customers follows the standard full-width table pattern."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates/console.html").read_text()
CSS = (ROOT / "static/css/console.css").read_text()


def _customers_markup() -> str:
    start = HTML.index('id="section-customers-list"')
    end = HTML.index('id="section-tenant-workspace"')
    return HTML[start:end]


def test_customers_has_one_standard_command_bar():
    customers = _customers_markup()
    assert 'class="command-bar cl-command-bar"' in customers
    assert 'aria-label="Customer table controls"' in customers
    assert customers.index('id="cl-search"') < customers.index('class="spacer"')
    assert customers.index('onclick="_ctOpen()"') > customers.index('class="spacer"')
    assert 'id="cl-freshness"' in customers


def test_customers_no_longer_reserves_an_empty_inspector():
    customers = _customers_markup()
    assert 'id="cl-content" class="cl-content"' in customers
    assert 'id="cl-list-detail"' not in customers
    assert 'id="cl-inspector"' not in customers
    assert 'Select a customer to preview' not in customers
    assert "function _clSelectTenant" not in HTML
    assert "function _clRenderInspector" not in HTML


def test_customer_table_is_full_width_and_keeps_explicit_actions():
    assert ".cl-table-shell { width: 100%; }" in CSS
    table_rule = CSS.split(".cl-table {", 1)[1].split("}", 1)[0]
    assert "width: 100%;" in table_rule
    assert "table-layout: fixed;" in table_rule
    assert 'class="cl-customer-link"' in HTML
    assert "enterTenant(_findTenant(this.dataset.tenantId))" in HTML
    assert 'disabled title="A read-only support session is not available">Support unavailable</button>' in HTML
    assert "/impersonation/start" not in HTML.split("function _renderClientTable", 1)[1].split("\nfunction ", 1)[0]
    assert '<th class="col-actions">Actions</th>' in HTML


def test_agent_drift_uses_compact_table_context_strip():
    assert "cl-drift-title" in HTML
    assert "cl-drift-chips" in HTML
    assert "cl-drift-summary" in HTML
    assert "#cl-agent-drift {" in CSS
    assert "display: flex;" in CSS.split("#cl-agent-drift {", 1)[1].split("}", 1)[0]

