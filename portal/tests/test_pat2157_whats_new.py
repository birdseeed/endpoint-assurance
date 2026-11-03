"""PAT-2157: the customer-facing "What's new" changelog.

`GET /whats-new` renders `data/changelog.json`'s entries newest first,
grouped by month, behind the same auth as every other signed-in page.
`validate_changelog_entry` is exercised directly against red-proof
fixtures (a bad tag, a missing date, a PAT- reference, an em dash,
"fleet" and a link to a route that does not exist), each asserted to
raise ValueError, plus a passing case to prove the validator is not
just rejecting everything.
"""

import copy

import pytest

import main

GOOD_ENTRY = {
    "date": "2026-09-25",
    "tag": "New",
    "title": "A perfectly good entry",
    "body": "This entry passes validation and links to a real route.",
    "link": "/software",
}


def _get(client, token, path="/whats-new"):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


# ── Page rendering ──────────────────────────────────────────────────────
def test_whats_new_requires_auth(client):
    resp = client.get("/whats-new")
    assert resp.status_code == 401


def test_whats_new_renders_seeded_entries(client, make_token):
    resp = _get(client, make_token())
    assert resp.status_code == 200
    assert "What's new" in resp.text
    # A representative slice of the seeded copy - not the full list, so this
    # test does not have to change every time a new entry is added.
    assert "Decide on software yourself" in resp.text
    assert "Clearer CVE assessment" in resp.text


def test_entries_render_newest_first(client, make_token):
    body = _get(client, make_token()).text
    first_pos = body.index("Device identity and hardware")
    last_pos = body.index("Clearer CVE assessment")
    assert first_pos < last_pos, "the 25 Sept entry must render before the 23 Sept one"


def test_entries_are_grouped_by_month(client, make_token):
    body = _get(client, make_token()).text
    assert "September 2026" in body
    # Every seeded entry falls in one month, so the heading appears once.
    assert body.count("September 2026") == 1


def test_each_entry_shows_a_tag_and_links_to_a_real_route(client, make_token):
    body = _get(client, make_token()).text
    for tag in ("New", "Improved", "Fixed"):
        assert f">{tag}<" in body
    assert 'href="/software"' in body
    assert 'href="/software/alerts"' in body


def test_seeded_copy_has_no_banned_words_or_ticket_references():
    # Checked against the entries' own title/body text, not the rendered
    # page - the page's own asset URLs legitimately contain "pat-" (the
    # portal.css cache-bust) and would make a whole-page substring check
    # a false positive.
    text = " ".join(f"{e['title']} {e['body']}" for e in main.CHANGELOG_ENTRIES)
    lowered = text.lower()
    assert "fleet" not in lowered
    assert "—" not in text
    assert "pat-" not in lowered
    assert "specialist" not in lowered


# ── Validation (red-proofed) ──────────────────────────────────────────────
KNOWN_ROUTES = {"/", "/software", "/software/alerts", "/devices", "/whats-new"}


def test_valid_entry_passes():
    main.validate_changelog_entry(GOOD_ENTRY, KNOWN_ROUTES)  # must not raise


def test_rejects_pat_reference():
    bad = copy.deepcopy(GOOD_ENTRY)
    bad["body"] = "This change shipped for PAT-2157 and works great."
    with pytest.raises(ValueError, match="PAT-"):
        main.validate_changelog_entry(bad, KNOWN_ROUTES)


def test_rejects_em_dash():
    bad = copy.deepcopy(GOOD_ENTRY)
    bad["body"] = "This changed — for the better."
    with pytest.raises(ValueError, match="em dash"):
        main.validate_changelog_entry(bad, KNOWN_ROUTES)


def test_rejects_fleet():
    bad = copy.deepcopy(GOOD_ENTRY)
    bad["body"] = "See every device across your fleet in one place."
    with pytest.raises(ValueError, match="fleet"):
        main.validate_changelog_entry(bad, KNOWN_ROUTES)


def test_rejects_bad_tag():
    bad = copy.deepcopy(GOOD_ENTRY)
    bad["tag"] = "Announcement"
    with pytest.raises(ValueError, match="tag"):
        main.validate_changelog_entry(bad, KNOWN_ROUTES)


def test_rejects_missing_date():
    bad = copy.deepcopy(GOOD_ENTRY)
    del bad["date"]
    with pytest.raises(ValueError, match="date"):
        main.validate_changelog_entry(bad, KNOWN_ROUTES)


def test_rejects_unparseable_date():
    bad = copy.deepcopy(GOOD_ENTRY)
    bad["date"] = "25 September 2026"
    with pytest.raises(ValueError, match="date"):
        main.validate_changelog_entry(bad, KNOWN_ROUTES)


def test_rejects_nonexistent_route():
    bad = copy.deepcopy(GOOD_ENTRY)
    bad["link"] = "/this-page-does-not-exist"
    with pytest.raises(ValueError, match="route"):
        main.validate_changelog_entry(bad, KNOWN_ROUTES)


def test_rejects_dynamic_route_link():
    # /devices/{device_id} is a real route template, but no single URL
    # exists for it - an entry must link to a static page instead.
    bad = copy.deepcopy(GOOD_ENTRY)
    bad["link"] = "/devices/{device_id}"
    with pytest.raises(ValueError, match="route"):
        main.validate_changelog_entry(bad, KNOWN_ROUTES)


# ── Route-drift guard on the real data file ────────────────────────────────
def test_every_real_entry_link_matches_a_live_route():
    known_routes = main._changelog_known_routes()
    for entry in main.CHANGELOG_ENTRIES:
        assert entry["link"] in known_routes, (
            f"{entry['title']!r} links to {entry['link']!r}, which is not a live route"
        )


def test_changelog_entries_loaded_and_sorted_newest_first():
    dates = [e["date"] for e in main.CHANGELOG_ENTRIES]
    assert dates == sorted(dates, reverse=True)
    assert len(main.CHANGELOG_ENTRIES) >= 1


# ── Nav: pinned above Support, outside the alphabetical rail__nav list ────
def test_nav_link_present_pinned_above_support(client, make_token):
    body = _get(client, make_token(), "/").text
    nav_end = body.index("</nav>")
    pinned_pos = body.index('id="rail-whats-new"')
    specialist_pos = body.index('class="rail__specialist"')
    assert pinned_pos > nav_end, "What's new must sit outside rail__nav"
    assert pinned_pos < specialist_pos, "What's new must sit above the Support block"
    assert 'href="/whats-new"' in body


def test_nav_link_active_on_whats_new_page(client, make_token):
    body = _get(client, make_token()).text
    assert 'id="rail-whats-new"' in body
    idx = body.index('id="rail-whats-new"')
    snippet = body[idx : idx + 200]
    assert "active" in snippet


def test_nav_link_carries_newest_date_for_unread_dot(client, make_token):
    body = _get(client, make_token(), "/").text
    assert "data-whats-new-newest=" in body
    assert main.CHANGELOG_NEWEST_DATE in body


# ── CSS cache-bust ──────────────────────────────────────────────────────
def test_portal_css_version_bumped_past_pat_2141():
    # PAT-2237: the cache-bust is now derived from portal.css's own content
    # hash (static_url()) rather than a hand-bumped literal, so a change to
    # portal.css always moves the served URL with nothing to assert here
    # beyond "the template still resolves the version through static_url()".
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    base = (root / "templates" / "base.html").read_text()
    assert "{{ static_url('css/portal.css') }}" in base

    css = (root / "static" / "css" / "portal.css").read_text()
    assert "PAT-2157" in css
    assert ".rail__unread-dot" in css
