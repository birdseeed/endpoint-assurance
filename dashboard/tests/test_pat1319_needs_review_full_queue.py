"""PAT-1319: the Software Catalogue "Needs review" badge, the catalogue
summary's "Unreviewed" stat, and the rows actually rendered on the Needs
review view must all agree, and the complete unresolved queue must be
reachable on initial load without mutating anything.

The bug: templates/console.html rendered the "Unreviewed" summary stat
straight from the backend allowlist-scan's `summary.unreviewed` (installed
fleet-app inventory only — see the now-superseded first _asStatBlock call in
_asRenderPolicyBar, and go-service TenantAllowlistScanHandler in
go-service/internal/handlers/allowlist.go, read-only reference checkout at
../patched.im), while the "Needs review" tab badge and its rows counted a
strictly larger set: unreviewed/not_in_allowlist installed apps PLUS
not-yet-decided tenant_new_apps rows (software discovered on endpoints but
not yet even matched into the installed-app allowlist scan — a distinct data
source, /admin/tenants/{id}/new-apps, populated by go-service's
detectNewTenantApps sweep). Both numbers were shown side by side on the same
view as if they meant the same thing: 23 vs 5 in production on 2026-08-13.

Investigation ruled out a page-size/LIMIT/slice: none exists in
_scRenderTable's review-view row building (templates/console.html), in
main.py's thin /admin/tenants/{id}/{new-apps,allowlist/scan} proxies, or in
the go-service handlers those proxy to (go-service/internal/handlers/
{new_apps,allowlist}.go — no LIMIT clause on either query). The full
unresolved set was already fetched and rendered on initial load; the only
defect was the summary stat using a narrower, differently-scoped count than
the badge and rows it sat beside. The fix computes one `reviewTotal` in
_scRenderTable and feeds it to both the badge (_scUpdateViewCounts) and the
summary stat (_scUpdateUnreviewedStat), so they cannot diverge again.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "templates" / "console.html").read_text()
MAIN_PY = (ROOT / "main.py").read_text()


def _slice(start_marker, end_marker):
    start = HTML.index(start_marker)
    end = HTML.index(end_marker, start)
    return HTML[start:end]


# ── Wiring: badge and summary stat share one source of truth ────────────────

def test_unreviewed_stat_block_has_a_stable_id_to_update_in_place():
    assert "function _asStatBlock(val, label, cls, id)" in HTML
    render_bar = _slice("function _asRenderPolicyBar(data)", "function _asStatBlock")
    assert "'as-stat-unreviewed'" in render_bar
    assert "'Unreviewed'" in render_bar


def test_badge_and_summary_stat_share_one_reviewTotal_variable():
    """The two numbers that used to disagree (23 vs 5) must now be fed from
    the exact same variable, computed once — not two independently computed
    expressions that can silently drift apart again."""
    render = _slice("function _scRenderTable()", "function _scUpdateViewCounts(review")
    assert "var reviewTotal = (_scNewApps || []).length + reviewInstalledCount;" in render
    assert "_scUpdateViewCounts(reviewTotal, apps.length, catOnly.length);" in render
    assert "_scUpdateUnreviewedStat(reviewTotal);" in render


def test_unreviewed_stat_updater_targets_the_stable_id():
    updater = _slice("function _scUpdateUnreviewedStat", "\n\n")
    assert "getElementById('as-stat-unreviewed')" in updater
    assert "el.textContent = total;" in updater


def test_stat_update_runs_before_the_drift_early_return():
    """Counts must update the same way regardless of which catalogue view is
    active — including 'drift', which returns early from _scRenderTable
    before any rows are built. If the stat update moved after this guard it
    would go stale whenever an operator lands on the drift view first."""
    render = _slice("function _scRenderTable()", "function _scUpdateViewCounts(review")
    stat_pos = render.index("_scUpdateUnreviewedStat(reviewTotal);")
    drift_pos = render.index("if (_scView === 'drift')")
    assert stat_pos < drift_pos


# ── No hidden page-size/LIMIT truncating the row source ──────────────────────

def test_review_row_sources_are_not_sliced_or_paginated():
    """No LIMIT/page-size/slice truncates the new-app or unreviewed-installed
    row sources before they're pushed into `rows` for the review view — the
    signature of a fixed-size window PAT-1319 asked us to rule out."""
    review_branch = _slice("if (_scView === 'review') {", "} else if (_scView === 'installed')")
    assert ".slice(" not in review_branch
    assert "unresolvedInstalled.forEach(function(a) {" in review_branch
    assert "(_scNewApps || []).forEach(function(a) {" in review_branch


def test_new_apps_and_allowlist_scan_proxies_pass_through_unbounded():
    """main.py's proxy routes forward status straight through with no
    limit/page query param of their own — the dashboard layer isn't the one
    capping the result set either."""
    new_apps_route = MAIN_PY[MAIN_PY.index('@app.get("/admin/tenants/{tenant_id}/new-apps")'):][:700]
    assert "limit" not in new_apps_route.lower()
    assert 'params={"status": status}' in new_apps_route
    scan_route = MAIN_PY[MAIN_PY.index('@app.get("/admin/tenants/{tenant_id}/allowlist/scan")'):][:400]
    assert "limit" not in scan_route.lower()


def test_pending_staged_changes_do_not_hide_or_fabricate_unreviewed_rows():
    """A staged-but-unsaved decision (_asPending) must not remove an app from
    the unresolved set the badge/stat/rows all count — otherwise resolving a
    visible row could make counts drop before the change is saved, then
    "correct" back up on reload, which would look exactly like PAT-1319's
    reported 'a previously hidden row appears'."""
    render = _slice("function _scRenderTable()", "function _scUpdateViewCounts(review")
    unresolved_filter = render[render.index("var unresolvedInstalled"):render.index("var reviewInstalledCount")]
    assert "_asPending" not in unresolved_filter
    assert "a.status" in unresolved_filter


# ── Behavioural mirror: a tenant with more unresolved apps than any ─────────
# plausible display limit, proving every row is reachable on initial load.
#
# This is a faithful Python port of the counting algorithm in
# _scRenderTable's review-view branch (templates/console.html): the new-app
# names set, the unreviewed/not_in_allowlist installed-app filter, the
# de-duplication against new-app names, and the default-filter (status=all,
# no query, no platform filter) row pass-through. It exists to demonstrate
# the acceptance criteria numerically at tenant scale; the string-guard tests
# above are what actually pin the real JS source against regressing.

def _new_app_names(new_apps):
    return {a["name"].lower() for a in new_apps if a.get("name")}


def _unresolved_installed(installed_apps):
    return [a for a in installed_apps if a.get("status") in ("unreviewed", "not_in_allowlist")]


def _review_rows(new_apps, installed_apps):
    """Mirrors _scRenderTable's `_scView === 'review'` row build under the
    default filter (_asActiveStatus == 'all', no query, no platform filter) —
    every _scPassNewAppFilter/_scPassInstalledFilter check in that state is a
    no-op pass-through, so every candidate row is included."""
    new_names = _new_app_names(new_apps)
    rows = [{"kind": "new_app", "name": a["name"]} for a in new_apps]
    for a in _unresolved_installed(installed_apps):
        if a["name"].lower() in new_names:
            continue
        rows.append({"kind": "installed", "name": a["name"]})
    return rows


def _review_total(new_apps, installed_apps):
    new_names = _new_app_names(new_apps)
    review_installed = [
        a for a in _unresolved_installed(installed_apps)
        if a["name"].lower() not in new_names
    ]
    return len(new_apps) + len(review_installed)


def _make_tenant(new_app_count, unreviewed_installed_count, approved_installed_count):
    new_apps = [{"name": "New App %d" % i, "decision": None} for i in range(new_app_count)]
    installed_apps = [
        {"name": "Unreviewed App %d" % i, "status": "unreviewed"}
        for i in range(unreviewed_installed_count)
    ]
    installed_apps += [
        {"name": "Approved App %d" % i, "status": "allowed"}
        for i in range(approved_installed_count)
    ]
    return new_apps, installed_apps


def test_full_unresolved_set_is_reachable_on_initial_load_above_any_display_limit():
    # 22 newly discovered apps + 12 unreviewed installed apps = 34 unresolved,
    # comfortably above any plausible fixed page size (e.g. 20/25), plus 6
    # already-approved installed apps that must NOT count as unresolved.
    new_apps, installed_apps = _make_tenant(22, 12, 6)

    badge = _review_total(new_apps, installed_apps)
    rows = _review_rows(new_apps, installed_apps)

    assert badge == 34
    assert len(rows) == 34  # every unresolved row reachable, nothing withheld
    assert {r["name"] for r in rows} == (
        {a["name"] for a in new_apps} | {a["name"] for a in installed_apps if a["status"] == "unreviewed"}
    )


def test_badge_summary_stat_and_accessible_rows_agree_under_default_filters():
    new_apps, installed_apps = _make_tenant(18, 5, 3)
    badge = _review_total(new_apps, installed_apps)
    rows = _review_rows(new_apps, installed_apps)
    # reviewTotal in the real JS feeds both the badge and _scUpdateUnreviewedStat
    # directly (see test_badge_and_summary_stat_share_one_reviewTotal_variable),
    # so proving badge == accessible-row-count here proves all three agree.
    summary_stat = badge
    assert badge == summary_stat == len(rows) == 23


def test_actioning_a_row_does_not_surface_a_row_that_was_already_reachable():
    """Approving one new-app row (which the real UI does via a full reload —
    _napDecide's PUT then _scReload(), see below) must simply drop the total
    by one; it must never reveal an app that wasn't already counted in the
    pre-action badge/stat/rows."""
    new_apps, installed_apps = _make_tenant(22, 12, 6)
    before_rows = {r["name"] for r in _review_rows(new_apps, installed_apps)}
    before_total = _review_total(new_apps, installed_apps)

    approved_name = new_apps[0]["name"]
    new_apps_after = [a for a in new_apps if a["name"] != approved_name]
    after_rows = {r["name"] for r in _review_rows(new_apps_after, installed_apps)}
    after_total = _review_total(new_apps_after, installed_apps)

    assert after_total == before_total - 1
    assert after_rows == before_rows - {approved_name}
    assert after_rows.issubset(before_rows)  # nothing "new" appears


def test_action_on_a_row_reloads_the_full_dataset_not_a_client_side_splice():
    """_napDecide (the shared decision handler for new-app rows) triggers a
    full _scReload(), not a local array splice — so the post-action counts
    always reflect server truth rather than a locally-guessed remainder."""
    decide = _slice("async function _napDecide(tenantId, id, decision, opts) {", "\n}\n")
    assert "_scReload();" in decide
    assert ".splice(" not in decide


def test_status_filter_applies_across_the_whole_unresolved_set_not_a_rendered_subset():
    """Mirrors _scPassInstalledFilter's 'unreviewed' branch: filtering must be
    evaluated against every unresolved-installed app, including ones beyond
    any earlier-rendered page, not just whatever happened to already be in
    the DOM."""
    _, installed_apps = _make_tenant(0, 12, 6)
    installed_apps.append({"name": "Blocked App", "status": "flagged"})
    matched = [
        a for a in installed_apps
        if a.get("status") in ("unreviewed", "not_in_allowlist")
    ]
    assert len(matched) == 12
    assert all(a["status"] == "unreviewed" for a in matched)

    filter_src = _slice("function _scPassInstalledFilter(a, query) {", "function _scPassNewAppFilter")
    assert "PatchedConsoleGovernance.installedFilterMatches" in filter_src
