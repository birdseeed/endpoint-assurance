"""PAT-1356: compact, separated Account workspace contract."""

from pathlib import Path

from lxml import html


ROOT = Path(__file__).resolve().parents[1]
CONSOLE = (ROOT / "templates" / "console.html").read_text()


def test_account_has_keyboard_accessible_compact_views_and_summary():
    assert 'class="acct-summary"' in CONSOLE
    summary = CONSOLE[CONSOLE.index('class="acct-summary"'):CONSOLE.index('class="acct-view-tabs"')]
    for field in ("tier", "state", "renewal", "contacts"):
        assert f'id="acct-summary-{field}"' in summary
    assert 'acct-summary-app-control' not in summary
    assert 'role="tablist" aria-label="Account workspace views"' in CONSOLE
    for view in ("profile", "commercial", "notifications", "lifecycle"):
        assert f'data-account-view-button="{view}"' in CONSOLE
    assert 'data-account-view-button="service"' not in CONSOLE
    assert "_acctViewKeydown" in CONSOLE
    assert "function _acctArrangePanels()" in CONSOLE
    for view in ("profile", "commercial", "notifications", "lifecycle"):
        assert f'id="acct-{view}-sections"' in CONSOLE
        assert f'aria-labelledby="acct-view-{view}"' in CONSOLE


def test_account_separates_routine_save_from_confirmed_tier_change():
    account_save = CONSOLE[CONSOLE.index("function _acctDoSave"):CONSOLE.index("function _acctSave")]
    assert "/subscription-tier" not in account_save
    assert "Promise.all([accountSave" not in account_save
    tier_update = CONSOLE[CONSOLE.index("function _acctUpdateTier"):CONSOLE.index("// ── PAT-444")]
    assert "dangerConfirm" in tier_update
    assert "/subscription-tier" in tier_update
    assert "_auditHeaders" in tier_update
    assert 'id="acct-commercial-save-btn"' in CONSOLE
    assert 'id="acct-commercial-save-msg"' in CONSOLE
    assert "Commercial settings saved." in CONSOLE
    assert "Profile saved." in CONSOLE


def test_plan_actions_are_owner_only_and_preserve_the_internal_capability_state():
    plan = CONSOLE[CONSOLE.index('class="acct-section owner-only" id="acct-commercial-plan"'):CONSOLE.index('id="acct-profile-lifecycle"')]
    assert 'class="acct-section owner-only" id="acct-commercial-plan"' in plan
    assert 'id="acct-tier-save-btn"' in plan
    tier_update = CONSOLE[CONSOLE.index("function _acctUpdateTier"):CONSOLE.index("// ── PAT-444")]
    assert "canonicalAppControl(" in tier_update
    assert "response, !!_acctAccountSnapshot.app_control_enabled" in tier_update
    assert "acct-app-control" not in tier_update
    assert "_acctAccountSnapshot.app_control_enabled = canonicalAppControl" in tier_update
    assert "_consoleState.tenantData.app_control_enabled = canonicalAppControl" in tier_update
    assert "ctxnav-cust-tier" in tier_update
    assert "function _acctPayload(view)" in CONSOLE
    summary_populate = CONSOLE[CONSOLE.index("function _acctSummaryPopulate"):CONSOLE.index("function _acctCurrentFields")]
    assert "acct-summary-app-control" not in summary_populate


def test_charge_form_is_closed_until_explicitly_opened_and_lifecycle_does_not_duplicate_devices():
    assert 'id="charge-form" onsubmit="_chargeCreate(event)" hidden' in CONSOLE
    assert "function _chargeFormToggle(open)" in CONSOLE
    assert "dc-device-tbody" not in CONSOLE
    assert "View devices" in CONSOLE


def test_account_panels_keep_account_and_charge_submit_boundaries_separate():
    assert 'id="acct-profile-sections" class="acct-view-panel"' in CONSOLE
    assert 'id="acct-commercial-sections" class="acct-view-panel"' in CONSOLE
    assert 'id="acct-commercial-form" onsubmit="_acctSave(event, \'commercial\')"' in CONSOLE
    assert 'id="acct-commercial-charges-mount"' in CONSOLE
    assert 'id="charge-form" onsubmit="_chargeCreate(event)"' in CONSOLE
    charge_editor = CONSOLE[CONSOLE.index('id="charge-form"'):CONSOLE.index('function _chargeCreate(event)')]
    assert 'form="acct-form"' not in charge_editor
    assert 'form="acct-commercial-form"' not in charge_editor


def test_account_markup_has_no_nested_forms_and_charge_editor_is_independent():
    tree = html.fromstring(CONSOLE)
    forms = {form.get("id"): form for form in tree.xpath("//form[@id]")}
    assert {"acct-form", "acct-commercial-form", "charge-form", "stale-form"}.issubset(forms)
    assert not forms["acct-form"].xpath(".//form")
    assert not forms["acct-commercial-form"].xpath(".//form")
    assert not forms["charge-form"].xpath("ancestor::form")
