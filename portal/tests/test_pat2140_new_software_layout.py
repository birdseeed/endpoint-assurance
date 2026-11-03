"""PAT-2140: the Overview's New software card colour-codes its urgency
counters and pills using the portal's existing severity tones, Platform
reads macOS/Windows through the existing platform_display filter, and
First seen splits into a date line and a time line so it reads on at most
two lines instead of wrapping one word per line.

Browser-rendered wrap/overflow/colour-contrast coverage lives in
e2e/test_pat2140_new_software_layout.py; this file is the fast,
template-and-filter-level check.
"""

import main
from tests.conftest import OVERVIEW, STUB_STATE


def _get(client, token, path="/"):
    STUB_STATE["expected_jwt"] = token
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _product(name, urgency, **fields):
    base = {
        "name": name, "platform": "macos", "identifier": f"com.example.{name.lower()}",
        "team_id": "ABCDE12345", "product_key": f"application:macos:com.example.{name.lower()}",
        "approval_state": "unreviewed", "first_seen_at": "2026-09-24T20:51:00Z",
        "device_count": 1, "urgency": urgency, "reasons": [],
    }
    base.update(fields)
    return base


def _new_software(**fields):
    base = {
        "since": "2026-09-10T12:00:00Z", "since_basis": "default_window",
        "until": "2026-09-24T12:00:00Z", "window_days": 14, "last_review_at": None,
        "total": 0, "counts": {"critical": 0, "high": 0, "not_assessed": 0, "medium": 0, "low": 0},
        "excluded": {"approved": 0, "ignored": 0, "patched_agent": 0},
        "truncated": False, "limit": 50, "products": [],
    }
    base.update(fields)
    return base


# ── Urgency pill classes ────────────────────────────────────────────────

def test_not_assessed_pill_is_its_own_class_distinct_from_muted_and_low():
    """Red on current main: not_assessed used to map to pill-muted, the
    exact same class the Low tone already used - the two were visually
    indistinguishable."""
    assert main.NEW_SOFTWARE_URGENCY_PILL_CLASS["not_assessed"] == "pill-info"
    assert main.NEW_SOFTWARE_URGENCY_PILL_CLASS["not_assessed"] != (
        main.NEW_SOFTWARE_URGENCY_PILL_CLASS["low"])
    assert main.NEW_SOFTWARE_URGENCY_PILL_CLASS["not_assessed"] != "pill-muted"


def test_every_urgency_level_keeps_a_distinct_pill_class():
    classes = list(main.NEW_SOFTWARE_URGENCY_PILL_CLASS.values())
    assert len(classes) == len(set(classes))


# ── KPI counter tones ────────────────────────────────────────────────────

def test_kpi_counters_colour_code_every_level_and_zero_is_muted(client, make_token):
    products = [_product("CritOne", "critical")]
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": _new_software(
        total=1, counts={"critical": 1, "high": 0, "not_assessed": 0, "medium": 0, "low": 0},
        products=products,
    )}
    token = make_token()
    body = _get(client, token).text
    card_start = body.index("New software")
    card = body[card_start:body.index("</section>", card_start)]

    def value_class(label):
        label_start = card.index(f'>{label}<')
        item_start = card.rindex('class="kpi__item"', 0, label_start)
        item = card[item_start:card.index("</div>", card.index("kpi__value", item_start))]
        value_start = item.index('class="kpi__value')
        return item[value_start:item.index('"', value_start + len('class="'))]

    # Non-zero Critical: alert tone.
    assert "bad-text" in value_class("Critical")
    # Zero High/Not assessed/Medium: muted, not plain/uncoloured.
    assert "mute-text" in value_class("High")
    assert "mute-text" in value_class("Not assessed")
    assert "mute-text" in value_class("Medium")
    # Low is always the muted tone, whatever the count.
    assert "mute-text" in value_class("Low")
    # not_assessed and medium must never share a class (the reported bug:
    # both used to render "warn-text").
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": _new_software(
        total=2, counts={"critical": 0, "high": 0, "not_assessed": 1, "medium": 1, "low": 0},
        products=[_product("NA", "not_assessed"), _product("Med", "medium")],
    )}
    body = _get(client, token).text
    card_start = body.index("New software")
    card = body[card_start:body.index("</section>", card_start)]

    def value_class2(label):
        label_start = card.index(f'>{label}<')
        item_start = card.rindex('class="kpi__item"', 0, label_start)
        item = card[item_start:card.index("</div>", card.index("kpi__value", item_start))]
        value_start = item.index('class="kpi__value')
        return item[value_start:item.index('"', value_start + len('class="'))]

    na_class = value_class2("Not assessed")
    medium_class = value_class2("Medium")
    assert "graphite-text" in na_class
    assert "warn-text" in medium_class
    assert na_class != medium_class


# ── Platform display ─────────────────────────────────────────────────────

def test_platform_renders_display_label_not_raw_key(client, make_token):
    products = [
        _product("MacApp", "critical", platform="macos"),
        _product("WinApp", "high", platform="windows"),
    ]
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": _new_software(
        total=2, counts={"critical": 1, "high": 1, "not_assessed": 0, "medium": 0, "low": 0},
        products=products,
    )}
    token = make_token()
    body = _get(client, token).text

    def platform_cell(row_marker):
        # PAT-2177: scope to the New software table; the High-risk
        # software card above also names critical/high products.
        row_start = body.index(row_marker, body.index('id="new-software-heading"'))
        row = body[row_start:body.index("</tr>", row_start)]
        product_cell_end = row.index("</td>") + len("</td>")
        rest = row[product_cell_end:]
        return rest[:rest.index("</td>")]

    mac_cell = platform_cell("MacApp")
    win_cell = platform_cell("WinApp")
    assert "macOS" in mac_cell
    assert "Windows" in win_cell
    # The raw internal key still legitimately rides along in the row's
    # hidden approval-item JSON payload (machine data, not customer-facing
    # display text) - only the visible Platform cell must never show it.
    assert "macos" not in mac_cell
    assert "windows" not in win_cell


# ── First seen: date and time on their own lines ─────────────────────────

def test_first_seen_splits_date_and_time_into_separate_spans(client, make_token):
    products = [_product("DateTool", "critical", first_seen_at="2026-09-24T20:51:00Z")]
    STUB_STATE["overview_data"] = {**OVERVIEW, "new_software": _new_software(
        total=1, counts={"critical": 1, "high": 0, "not_assessed": 0, "medium": 0, "low": 0},
        products=products,
    )}
    token = make_token()
    body = _get(client, token).text
    row_start = body.index("DateTool", body.index('id="new-software-heading"'))
    row = body[row_start:body.index("</tr>", row_start)]
    assert '<span class="cell-evidence__main nowrap">24 Sep 2026</span>' in row
    assert '<span class="cell-subtle">20:51 UTC</span>' in row
    # Never the old single-string "24 Sep 2026 20:51 UTC" run together.
    assert "24 Sep 2026 20:51" not in row


def test_humantime_filter_matches_humandate_with_time():
    value = "2026-09-24T20:51:00Z"
    assert main.humantime(value) == "20:51"
    assert main.humandate(value, True) == "24 Sep 2026 20:51"
    assert main.humandate(value, True).endswith(main.humantime(value))


def test_humantime_empty_and_unparseable():
    assert main.humantime("") == "-"
    assert main.humantime(None) == "-"
    assert main.humantime("not-a-date") == "not-a-date"


# ── CSS cache-bust ─────────────────────────────────────────────────────

def test_css_cache_bust_moved_past_pat_2137(client, make_token):
    # PAT-2140 changed portal.css, so the cache-bust must have moved past
    # the pre-2140 value; later tickets bump it again without breaking this.
    token = make_token()
    body = _get(client, token).text
    assert "/static/css/portal.css?v=" in body
    assert "/static/css/portal.css?v=2026-09-25-pat-2137" not in body
