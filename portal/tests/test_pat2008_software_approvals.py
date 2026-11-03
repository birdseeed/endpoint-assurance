"""PAT-2008: customer admins mark software Approved, Unapproved or Ignored
from /software, inline and in bulk, against PAT-2007's
PUT /v1/portal/software-approvals.

This is the portal's first customer write that changes governance state, so
most of these tests are about what must NOT reach the platform: a viewer, a
missing or wrong CSRF token, a cross-origin request, a body that tries to
name a tenant or actor, an over-cap bulk request. Each of those asserts the
stub recorded no write call at all.
"""

import copy
import json
import re
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest

import main
from tests.conftest import APPLICATIONS, SOFTWARE_INVENTORY, STUB_STATE

# PAT-2008 review fix: _same_origin now requires https for every host except
# a genuinely local one (localhost/127.0.0.1) - the TestClient's default
# "testserver" host is not exempt, so every test below sends an explicit
# https Origin/Referer, the same as real traffic through nginx would.
ORIGIN = "https://testserver"


def _headers(token, **extra):
    return {"Cf-Access-Jwt-Assertion": token, **extra}


def _get(client, token, path="/software"):
    return client.get(path, headers=_headers(token))


def _item(name="MysteryApp", **fields):
    base = {"type": "application", "platform": "macos",
            "identifier": "com.example.mysteryapp", "name": name}
    base.update(fields)
    return json.dumps(base)


def _ext_item(name="MysteryHelper", browser="firefox", extension_id="mysteryhelper-ext-id"):
    return json.dumps({"type": "browser_extension", "browser": browser,
                       "extension_id": extension_id, "name": name})


def _post(client, token, fields, origin=ORIGIN, csrf=True, follow=False, extra_headers=None):
    body = list(fields)
    if csrf is True:
        body.append(("csrf_token", main._csrf_token(token)))
    elif isinstance(csrf, str):
        body.append(("csrf_token", csrf))
    headers = _headers(token, **{"Content-Type": "application/x-www-form-urlencoded"})
    if origin is not None:
        headers["Origin"] = origin
    headers.update(extra_headers or {})
    return client.post("/software/approvals", content=urlencode(body), headers=headers,
                       follow_redirects=follow)


def _row(html, name, group="waiting"):
    """The <tr>...</tr> for the product `name` inside the merged table's
    `group` bucket (waiting/not_wanted/approved/ignored/unrecognised - the
    same data-filter-decision value main.py stamps on every row). PAT-2120
    replaced the five separate decision-group tables with one table, so a
    row is now disambiguated by that attribute instead of by scanning past
    a group's old <h2> heading."""
    marker = f'data-filter-decision="{group}"'
    pos = 0
    while True:
        tr_start = html.index("<tr ", pos)
        tr_end = html.index("</tr>", tr_start)
        row = html[tr_start:tr_end]
        if marker in row and name in row:
            return row
        pos = tr_end + len("</tr>")


def _row_item(row):
    """The approval_item_json a rendered row-form's hidden `item` field
    actually carries (PAT-2120: one field shared by every state option,
    not a per-action value), decoded from the row's own HTML - not
    hand-built - so a test using it proves what _app_approval/
    _inventory_approval actually rendered."""
    import html as html_module
    match = re.search(r'<input type="hidden" name="item" value="([^"]*)">', row)
    assert match, "no item field found in row"
    return json.loads(html_module.unescape(match.group(1)))


def _flash(client, token, response):
    """Follow a write's 303 back to /software and return that page."""
    assert response.status_code == 303, response.text[:400]
    location = response.headers["location"]
    return client.get(location, headers=_headers(token))


# ── Rendering: who sees controls ─────────────────────────────────────────

def test_admin_sees_inline_and_bulk_controls(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token)
    assert resp.status_code == 200
    html = resp.text
    assert 'id="approval-form"' in html
    assert f'name="csrf_token" value="{main._csrf_token(token)}"' in html
    row = _row(html, "MysteryApp")
    for label in ("Approve", "Unapprove", "Ignore"):
        assert f'>{label}</option>' in row
    assert 'class="approval-select"' in row
    # PAT-2255: history opens from the product name (the product detail).
    assert 'class="product-name" href="/software/history?' in row
    # An already approved extension offers only the two other states.
    approved = _row(html, "TeamChat", "approved")
    assert ">Approve</option>" not in approved
    assert ">Unapprove</option>" in approved and ">Ignore</option>" in approved
    # The bulk bar and filters. PAT-2163 (orchestrator follow-up): "Unreviewed
    # only" is gone (Approval = Waiting on a decision is the identical set);
    # "Select all shown" moved into the table's own select column.
    for text in ("Select all shown", "data-filter-publisher",
                 "data-filter-min-devices", 'value="approved" data-bulk-submit'):
        assert text in html
    assert STUB_STATE["me_requests"] == 1


def test_viewer_sees_state_and_history_but_no_controls(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _get(client, token)
    assert resp.status_code == 200
    html = resp.text
    assert 'id="approval-form"' not in html
    assert "approval__btn" not in html
    assert 'class="approval-select"' not in html
    assert "csrf_token" not in html
    assert "Select all shown" not in html
    assert "An administrator on your account can change them." in html
    row = _row(html, "MysteryApp")
    assert 'class="product-name" href="/software/history?' in row
    # PAT-2255: one approval state per row, in the Approval column.
    assert ">Unreviewed</span>" in row
    # Header and body cell counts still match without the select column.
    table = html[html.index("waiting"):]
    table = table[:table.index("</table>")]
    head = table[table.index("<thead>"):table.index("</thead>")]
    header_cells = len(re.findall(r"<th[\s>]", head))
    body_row = table[table.index("<tbody>"):]
    body_row = body_row[:body_row.index("</tr>")]
    assert header_cells == body_row.count("<td")


def test_unknown_role_is_read_only(client, make_token):
    STUB_STATE["portal_role"] = "owner"
    resp = _get(client, make_token())
    assert resp.status_code == 200
    assert "approval__btn" not in resp.text


def test_role_lookup_failure_hides_controls_but_keeps_the_page(client, make_token):
    STUB_STATE["me_status"] = 500
    resp = _get(client, make_token())
    assert resp.status_code == 200
    assert "approval__btn" not in resp.text
    assert "your account role could not be checked" in resp.text
    assert "MysteryApp" in resp.text


def test_name_only_and_unaddressable_rows_explain_and_show_no_controls(client, make_token):
    token = make_token()
    html = _get(client, token).text
    guess = _row(html, "GuessWho")
    assert "Known by its name only, so it has no confirmed identity and cannot be marked." in guess
    assert "approval__btn" not in guess
    assert "approval-select" not in guess
    assert "History</a>" not in guess
    corp = _row(html, "CorpVPN", "approved")
    assert "Set as mandatory in your Patched policy" in corp
    assert "approval__btn" not in corp
    slack = _row(html, "Slack", "approved")
    assert "without a product identifier the portal can send" in slack
    assert "approval__btn" not in slack
    ghost = _row(html, "GhostApp", "not_wanted")
    assert "No device evidence confirms this product&#39;s identity" in ghost


def test_specialist_and_mailto_approval_wording_is_gone(client, make_token):
    html = _get(client, make_token()).text
    for phrase in ("Approve it", "Remove it", "Ask us to confirm first",
                   "Your specialist records the decision", "your specialist"):
        assert phrase not in html, phrase
    # No visible text on the page mentions a specialist (the rail's support
    # block keeps its old CSS class name, which is not copy).
    assert not re.search(r">[^<]*specialist[^<]*<", html, re.IGNORECASE)
    mailtos = re.findall(r'href="(mailto:[^"]*)"', html)
    # Only the support contact in the rail and footer remain.
    assert mailtos and all(m == "mailto:hello@patched.im" for m in mailtos), mailtos
    assert "software_action_mailto" not in main.templates.env.globals


def test_unmanaged_application_policy_groups_as_ignored(client, make_token):
    apps = copy.deepcopy(APPLICATIONS)
    apps["applications"][-1]["policy_state"] = "unmanaged"
    STUB_STATE["applications_data"] = apps
    html = _get(client, make_token()).text
    row = _row(html, "OddPolicy", "ignored")
    assert row
    # The decision-state tab names the state either way (PAT-2120: it is
    # always offered as a filter); what must not happen is a row actually
    # landing in it.
    assert 'data-filter-decision="unrecognised"' not in html


# PAT-2104: GET /v1/portal/applications now carries `identifier` and
# `policy_team_id` on a decided (policy) row whenever the platform can
# round-trip that exact row through PUT /v1/portal/software-approvals.
# Before this, `identifier` was always "" on a decided row and every one of
# them locked, so a customer could never unapprove something they had
# approved. This is the platform's own contract example (contracts/
# portal-api.md GET /v1/portal/applications), reused verbatim.
def test_decided_application_row_with_identity_gets_working_controls(client, make_token):
    # team_id (device signing evidence) and policy_team_id (the policy's
    # own stored Team ID) are deliberately different values here - exactly
    # as contracts/portal-api.md warns they can genuinely diverge - so this
    # only passes if the item is built from policy_team_id, not team_id.
    _extend(
        [_application_row(
            "SlackApproved", "com.tinyspeck.slackmacgap", "approved",
            team_id="OBSVD12345", policy_team_id="7QQ2SVXP7X",
            product_key="application:macos:com.tinyspeck.slackmacgap:7QQ2SVXP7X",
        )],
        [],
    )
    html = _get(client, make_token()).text
    row = _row(html, "SlackApproved", "approved")
    # Already approved: only the other two states are offered.
    assert ">Approve</option>" not in row
    assert ">Unapprove</option>" in row and ">Ignore</option>" in row
    assert "cannot be marked" not in row
    assert "cannot be changed here" not in row
    unapprove_item = _row_item(row)
    assert unapprove_item["identifier"] == "com.tinyspeck.slackmacgap"
    assert unapprove_item["team_id"] == "7QQ2SVXP7X"


def test_decided_application_row_without_identity_stays_locked(client, make_token):
    _extend(
        [_application_row("StillUnaddressable", "", "approved", platform="any")],
        [],
    )
    html = _get(client, make_token()).text
    row = _row(html, "StillUnaddressable", "approved")
    assert "without a product identifier the portal can send" in row
    assert "approval__btn" not in row


def test_decided_macos_application_row_without_a_valid_team_id_is_locked(client, make_token):
    _extend(
        [_application_row(
            "NoPolicyTeamId", "com.acme.nopolicyteam", "unapproved",
            policy_team_id=None, product_key=None,
        )],
        [],
    )
    html = _get(client, make_token()).text
    row = _row(html, "NoPolicyTeamId", "not_wanted")
    assert "Its macOS signing Team ID is not known, so it cannot be changed here." in row
    assert "approval__btn" not in row


def test_decided_mandatory_row_with_identity_still_locks_as_mandatory(client, make_token):
    _extend(
        [_application_row(
            "MandatoryWithIdentity", "com.acme.mandatoryid", "mandatory",
            team_id="MAND123456", policy_team_id="MAND123456",
            product_key="application:macos:com.acme.mandatoryid:MAND123456",
        )],
        [],
    )
    html = _get(client, make_token()).text
    row = _row(html, "MandatoryWithIdentity", "approved")
    assert "Set as mandatory in your Patched policy, so it cannot be changed here." in row
    assert "approval__btn" not in row


def test_inventory_row_merges_into_its_governance_row_by_identity(client, make_token):
    # PAT-2104: /v1/portal/software now carries its own team_id/product_key/
    # policy_state on every row. PAT-2120: when that identity (platform +
    # identifier) matches a GET /v1/portal/applications row exactly, the two
    # merge into one row rather than rendering twice - the ticket's core
    # join rule (see main.py's _software_identity_key docstring). The
    # applications row below still exists (its signing evidence still
    # drives the Publisher filter dropdown) but is no longer where the
    # merged row's own identity comes from.
    apps = copy.deepcopy(APPLICATIONS)
    apps["applications"].append({
        "type": "application", "name": "ArchiveTool", "identifier": "com.acme.archive",
        "platform": "macos", "policy_state": "undecided", "enforcement_tier": "",
        "device_count": 2, "evidence_basis": "identifier_match", "removal_state": "not_available",
        "decided_by": None, "decided_at": None, "justification": None, "version_count": 1,
        "team_id": "ACME123456", "signed_by": "Developer ID Application: Acme Ltd (ACME123456)",
        "notarized": True,
    })
    STUB_STATE["applications_data"] = apps
    inventory = copy.deepcopy(SOFTWARE_INVENTORY)
    for product in inventory["products"]:
        if product["identifier"] == "com.acme.archive":
            product["team_id"] = "ACME123456"
            product["product_key"] = _product_key("macos", "com.acme.archive", "ACME123456")
            product["policy_state"] = None
    STUB_STATE["software_inventory_data"] = inventory
    token = make_token()
    html = _get(client, token).text
    # Exactly one ArchiveTool row, not two - proof it merged rather than
    # rendering the same product from each source independently.
    assert len(re.findall(r'class="product-name"[^>]*>ArchiveTool<', html)) == 1
    archive = _row(html, "ArchiveTool", "waiting")
    assert "Unreviewed" in archive
    assert "&#34;team_id&#34;:&#34;ACME123456&#34;" in archive
    # Round 2: one compact form (state select + Apply), no per-row sentence.
    assert 'data-approval-row-form' in archive
    assert '<option value="unapproved">Unapprove</option>' in archive
    # Round 3: the default is an empty placeholder, never a state.
    assert '<option value="" selected>Set state…</option>' in archive
    assert archive.index('value="" selected') < archive.index('<option value="approved">')
    assert ">Apply</button>" in archive
    assert f'name="csrf_token" value="{main._csrf_token(token)}"' in archive
    # An unknown platform cannot be marked - a separate, unmatched
    # inventory-only row (no application shares its identity).
    unknown = _row(html, "UnknownEvidence", "waiting")
    assert "Its platform is not known, so it cannot be marked." in unknown
    assert "approval__btn" not in unknown
    # Publisher comes from the signing identity, prefix and Team ID removed.
    assert '<option value="Acme Ltd"' in html


def _extend(apps_extra, inventory_extra):
    """Append rows to fresh copies of the standard fixtures and install
    them as this test's stub state."""
    apps = copy.deepcopy(APPLICATIONS)
    apps["applications"].extend(apps_extra)
    STUB_STATE["applications_data"] = apps
    inventory = copy.deepcopy(SOFTWARE_INVENTORY)
    inventory["products"].extend(inventory_extra)
    STUB_STATE["software_inventory_data"] = inventory


def _product_key(platform, identifier, team_id=None):
    """PUT /v1/portal/software-approvals' own key shape
    (application:<platform>:<lowercased identifier>[:<team_id>]), used to
    build a realistic PAT-2104 `product_key` for test fixtures."""
    key = f"application:{platform}:{identifier.lower()}"
    if platform == "macos" and team_id:
        key += f":{team_id}"
    return key


def _inventory_product(name, identifier, platform="macos", team_id=None,
                       product_key=None, policy_state=None):
    return {
        "name": name, "names": [name], "identifier": identifier, "platform": platform,
        "versions": ["1.0"], "unknown_version_installation_count": 0,
        "device_count": 1, "installation_count": 1, "evidence_at": "2026-09-20T11:00:00Z",
        "last_used_at": None, "metered_installation_count": 1, "unmetered_installation_count": 0,
        "stale_installation_count": 0, "unused_installation_count": 0, "usage_state": "used",
        "removal_candidate": False, "canonical_key": None, "canonical_name": None,
        "cve_assessment": {"state": "not_assessed", "last_matched_at": None, "finding_count": None},
        # PAT-2104: this row's own governance/identity fields - absent by
        # default, matching an older platform build (falls back to locked).
        "team_id": team_id, "product_key": product_key, "policy_state": policy_state,
    }


def _application_row(name, identifier, policy_state, evidence_basis="identifier_match",
                     team_id=None, platform="macos", policy_team_id=None, product_key=None):
    tier = "report" if policy_state != "undecided" else ""
    return {
        "type": "application", "name": name, "identifier": identifier, "platform": platform,
        "policy_state": policy_state, "enforcement_tier": tier,
        "device_count": 3, "evidence_basis": evidence_basis,
        "identifier_matched_devices": 0, "name_matched_devices": 0,
        "removal_state": "not_available",
        "decided_by": None,
        "decided_at": None if policy_state == "undecided" else "2026-07-01T09:00:00Z",
        "justification": None if policy_state == "undecided" else "Decided for this test.",
        "version_count": 1, "team_id": team_id,
        "signed_by": "Acme Ltd" if team_id else None, "notarized": True if team_id else None,
        # PAT-2104: the policy row's own identity fields (decided rows
        # only) - absent by default, matching an older platform build.
        "policy_team_id": policy_team_id, "product_key": product_key,
    }


# PAT-2120: DecidedButNameOnly appears in both fixtures with the same
# (platform, identifier) - GET /v1/portal/software's inventory data merges
# into the one governance row rather than rendering separately, so this row
# with no product_key of its own locks with the "no device evidence" reason
# - the same message an unmatched row got before PAT-2104 - regardless of
# what the paired applications row's own evidence_basis says. Its own
# policy_state still shows (both fixtures agree it is "approved" here).
def test_merged_row_without_its_own_product_key_stays_locked(client, make_token):
    _extend(
        [_application_row("DecidedButNameOnly", "com.acme.decided", "approved",
                          evidence_basis="name_match_only")],
        [_inventory_product("DecidedButNameOnly", "com.acme.decided", policy_state="approved")],
    )
    html = _get(client, make_token()).text
    assert len(re.findall(r'class="product-name"[^>]*>DecidedButNameOnly<', html)) == 1
    row = _row(html, "DecidedButNameOnly", "approved")
    assert "Approved" in row
    assert "No device evidence confirms this product&#39;s identity, so it cannot be marked." in row
    assert "data-approval-row-form" not in row
    assert "approval-select" not in row


def test_mandatory_inventory_only_row_is_locked(client, make_token):
    _extend(
        [],
        [_inventory_product(
            "AlwaysOnAgent", "com.acme.always", team_id="AGNT123456",
            product_key=_product_key("macos", "com.acme.always", "AGNT123456"),
            policy_state="mandatory",
        )],
    )
    html = _get(client, make_token()).text
    # mandatory folds into the Approved bucket (PAT-1742 ruling, carried
    # into _inventory_group the same way _app_group already does).
    row = _row(html, "AlwaysOnAgent", "approved")
    # PAT-2255: one of the four approval states; mandatory reads Approved
    # (PAT-1742) and its lock line says why it cannot be changed.
    assert ">Approved</span>" in row
    assert "Set as mandatory in your Patched policy, so it cannot be changed here." in row
    assert "data-approval-row-form" not in row
    assert "approval-select" not in row


def test_macos_inventory_only_row_without_a_team_id_is_locked(client, make_token):
    _extend(
        [],
        [_inventory_product(
            "NoTeamIdApp", "com.acme.noteam", team_id=None,
            # A malformed/missing team_id would normally mean the platform
            # never sets product_key either (PAT-2104) - set here anyway to
            # exercise the portal's own defensive check independently.
            product_key="application:macos:com.acme.noteam",
        )],
    )
    html = _get(client, make_token()).text
    # No policy_state on this fixture row -> the "waiting" default (the same
    # fallback _inventory_approval already gives its own state pill).
    row = _row(html, "NoTeamIdApp", "waiting")
    assert "Unreviewed" in row
    assert "Its macOS signing Team ID is not known, so it cannot be changed here." in row
    assert "data-approval-row-form" not in row
    assert "approval-select" not in row


def test_merged_row_uses_its_inventory_policy_state_not_a_borrowed_one(client, make_token):
    # The paired applications row is deliberately "unapproved" - if this
    # still borrowed identity/state (pre-PAT-2104 behaviour), the row below
    # would show Unapproved and no team_id. It must show its own Approved
    # state and its own team_id instead, and (PAT-2120) the row must live in
    # the Approved bucket to match that pill, not stay in Not wanted where
    # the applications side alone would have placed it.
    _extend(
        [_application_row("FullIdentityApp", "com.acme.fullid", "unapproved",
                          team_id="OTHR123456")],
        [_inventory_product(
            "FullIdentityApp", "com.acme.fullid", team_id="FULL123456",
            product_key=_product_key("macos", "com.acme.fullid", "FULL123456"),
            policy_state="approved",
        )],
    )
    html = _get(client, make_token()).text
    assert len(re.findall(r'class="product-name"[^>]*>FullIdentityApp<', html)) == 1
    row = _row(html, "FullIdentityApp", "approved")
    assert "Approved" in row
    assert "Unapproved" not in row
    assert "data-approval-row-form" in row
    assert "&#34;team_id&#34;:&#34;FULL123456&#34;" in row
    # The write item carries the policy's own FULL123456 team_id, never the
    # applications side's device-observed OTHR123456 - but OTHR123456 can
    # legitimately still appear elsewhere in the row, in the Signing
    # badge's tooltip (that is genuine, separate device-signing evidence,
    # not the write identity), so the write item is checked directly
    # rather than searching the whole row.
    assert _row_item(row)["team_id"] == "FULL123456"
    assert "approval-select" in row
    assert "cannot be marked" not in row
    assert "cannot be changed here" not in row


# PAT-2104: an inventory-only row with no policy_state/team_id/product_key at
# all (an older platform build) falls back to locked exactly as every row
# was before PAT-2104.
def test_inventory_only_row_with_missing_pat2104_fields_falls_back_to_locked(client, make_token):
    _extend([], [_inventory_product("BareIdentityApp", "com.acme.bare")])
    html = _get(client, make_token()).text
    row = _row(html, "BareIdentityApp", "waiting")
    assert "No device evidence confirms this product&#39;s identity, so it cannot be marked." in row
    assert "data-approval-row-form" not in row
    assert "approval-select" not in row


# PAT-2008 review fix (P3): the identifier-length lock, shared by
# _app_approval and _inventory_approval - the platform silently truncates a
# stored identifier at 128 characters, so a write at or past that length
# would save a value that no longer matches the real product. PAT-2120: the
# two fixtures share (platform, identifier) here too, so this is one merged
# row, and it must lock the same way regardless of which side's lock reason
# would have fired first.
def test_identifier_at_the_platforms_128_char_limit_is_locked_on_the_merged_row(
    client, make_token,
):
    long_id = "com.acme." + "a" * 125
    assert len(long_id) >= 128
    _extend(
        [_application_row("LongIdentifierApp", long_id, "undecided", team_id="LONG123456")],
        [_inventory_product(
            "LongIdentifierApp", long_id, team_id="LONG123456",
            product_key=_product_key("macos", long_id, "LONG123456"),
        )],
    )
    too_long = "Its identifier is too long for Patched to store, so it cannot be changed here."
    html = _get(client, make_token()).text
    assert len(re.findall(r'class="product-name"[^>]*>LongIdentifierApp<', html)) == 1
    row = _row(html, "LongIdentifierApp", "waiting")
    assert too_long in row
    assert "approval__btn" not in row
    assert "data-approval-row-form" not in row


# PAT-2008 review fix (P3): the row's compact form carries data-protected,
# the same signal portal.js already reads off application rows, so the
# "protected product" confirm actually fires for it too. This CorpVPN has
# its own distinct (macos, com.acme.corpvpn) identity, so it does not merge
# with the default fixture's unrelated CorpVPN application row (platform
# "any", no identifier) - it renders as its own inventory-only row.
def test_protected_inventory_only_row_carries_the_confirm_attribute(client, make_token):
    _extend(
        [],
        [_inventory_product(
            "CorpVPN", "com.acme.corpvpn", team_id="VPNN123456",
            product_key=_product_key("macos", "com.acme.corpvpn", "VPNN123456"),
        )],
    )
    html = _get(client, make_token()).text
    assert len(re.findall(r'class="product-name"[^>]*>CorpVPN<', html)) == 2
    row = _row(html, "CorpVPN", "waiting")
    assert 'data-approval-row-form' in row
    assert 'data-protected="1"' in row


# PAT-2120 non-author review fix (P2): a merged row's protected/
# protected_category/protected_label must come from exactly one source.
# _merge_inventory_evidence used to let _inventory_approval independently
# recompute `protected` from the INVENTORY product's own name while
# protected_category/protected_label stayed whatever the governance
# (applications) row's own name had already matched - two separate
# lookups that can disagree since the two sides can genuinely report
# different names for the same product (device-observed vs policy name).
# These two tests exercise both mismatch directions; both are red on the
# commit before this fix (3674191): the first rendered "Protected by your
# None" (protected=True from the inventory name, but protected_category/
# protected_label stayed None from the unmatched governance name), the
# second rendered no badge at all (protected overwritten to False by the
# unmatched inventory name, even though the governance name matched).
def test_merged_row_prefers_governance_protected_match_over_inventory(client, make_token):
    """Governance name matches the protected list, inventory name does
    not - the badge must show the governance side's match, never "None"."""
    _extend(
        [_application_row("GuardianEDR", "com.acme.mergeprotect1", "undecided",
                          team_id="MRGA123456")],
        [_inventory_product(
            "NotOnTheProtectedList", "com.acme.mergeprotect1", team_id="MRGA123456",
            product_key=_product_key("macos", "com.acme.mergeprotect1", "MRGA123456"),
        )],
    )
    html = _get(client, make_token()).text
    assert len(re.findall(r'class="product-name"[^>]*>GuardianEDR<', html)) == 1
    row = _row(html, "GuardianEDR", "waiting")
    assert 'title="Protected by your EDR"' in row
    assert "Protected by your None" not in row


def test_merged_row_falls_back_to_inventory_protected_match(client, make_token):
    """Governance name does not match the protected list, inventory name
    does - the badge must still show (from the inventory side's match),
    not silently vanish because the governance side found nothing."""
    _extend(
        [_application_row("NotOnTheProtectedListApp", "com.acme.mergeprotect2", "undecided",
                          team_id="MRGB123456")],
        [_inventory_product(
            "GuardianEDR", "com.acme.mergeprotect2", team_id="MRGB123456",
            product_key=_product_key("macos", "com.acme.mergeprotect2", "MRGB123456"),
        )],
    )
    html = _get(client, make_token()).text
    assert len(re.findall(r'class="product-name"[^>]*>NotOnTheProtectedListApp<', html)) == 1
    row = _row(html, "NotOnTheProtectedListApp", "waiting")
    assert 'title="Protected by your EDR"' in row


# ── Writes: the guards ───────────────────────────────────────────────────

def test_admin_single_mark_writes_and_redirects_back_with_a_result(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    action = json.dumps({"state": "approved", "item": json.loads(_item())})
    resp = _post(client, token, [("row_action", action), ("reason", "Needed by finance"),
                                 ("return_to", "/software?type=application&publisher=Acme")])
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith("/software?type=application&publisher=Acme&approval_result=")
    assert location.endswith("#approval-result")
    assert len(STUB_STATE["approval_puts"]) == 1
    put = STUB_STATE["approval_puts"][0]
    assert put["jwt"] == token
    assert put["body"] == {
        "state": "approved", "reason": "Needed by finance",
        "items": [{"type": "application", "platform": "macos",
                   "identifier": "com.example.mysteryapp"}],
    }
    page = client.get(location, headers=_headers(token)).text
    assert "1 of 1 product changed to Approved." in page
    # The stub reads the write back as a policy row: it left Waiting.
    waiting = page[page.index("waiting"):page.index("not_wanted")]
    assert "MysteryApp" not in waiting
    assert "MysteryApp" in page[page.index("approved"):]


# PAT-2104: unapproving something already approved was impossible before
# this - a decided row's identifier was always "" so it always locked. The
# posted item's team_id comes from the policy row's own policy_team_id, not
# the unrelated device-signing-evidence team_id field (deliberately
# different here - OTHR123456 vs 7QQ2SVXP7X - to prove it wasn't confused).
def test_unapproving_a_decided_row_posts_its_policy_team_id_as_team_id(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    _extend(
        [_application_row(
            "SlackApproved", "com.tinyspeck.slackmacgap", "approved",
            team_id="OTHR123456", policy_team_id="7QQ2SVXP7X",
            product_key="application:macos:com.tinyspeck.slackmacgap:7QQ2SVXP7X",
        )],
        [],
    )
    html = _get(client, token).text
    row = _row(html, "SlackApproved", "approved")
    # Posts exactly what the rendered row-form carries - the real
    # select-and-Apply path, not a hand-built body.
    assert ">Unapprove</option>" in row
    item = json.dumps(_row_item(row))
    resp = _post(client, token, [("state", "unapproved"), ("item", item)])
    assert resp.status_code == 303
    put = STUB_STATE["approval_puts"][0]
    assert put["body"]["items"] == [{
        "type": "application", "platform": "macos",
        "identifier": "com.tinyspeck.slackmacgap", "team_id": "7QQ2SVXP7X",
    }]


def test_viewer_post_is_refused_before_any_platform_write(client, make_token):
    STUB_STATE["portal_role"] = "viewer"
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item())])
    assert resp.status_code == 403
    assert "Only an administrator on your account can change approval state" in resp.text
    assert STUB_STATE["approval_puts"] == []


def test_missing_csrf_token_is_refused(client, make_token):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item())], csrf=False)
    assert resp.status_code == 403
    assert "This page has expired" in resp.text
    assert STUB_STATE["approval_puts"] == []
    assert STUB_STATE["me_requests"] == 0


@pytest.mark.parametrize("bad", ["0" * 64, "", "not-a-token"])
def test_invalid_csrf_token_is_refused(client, make_token, bad):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item())], csrf=bad)
    assert resp.status_code == 403
    assert STUB_STATE["approval_puts"] == []


def test_csrf_token_from_another_session_is_refused(client, make_token):
    token = make_token()
    other = make_token(email="bob@tenant-a.example", exp_delta=900)
    assert other != token
    resp = _post(client, token, [("state", "approved"), ("item", _item())],
                 csrf=main._csrf_token(other))
    assert resp.status_code == 403
    assert STUB_STATE["approval_puts"] == []


def test_duplicate_csrf_fields_are_refused(client, make_token):
    token = make_token()
    good = main._csrf_token(token)
    resp = _post(client, token, [("state", "approved"), ("item", _item()),
                                 ("csrf_token", good), ("csrf_token", good)], csrf=False)
    assert resp.status_code == 403
    assert STUB_STATE["approval_puts"] == []


@pytest.mark.parametrize("origin", [
    "https://evil.example", "null", "http://testserver.evil.example",
    "https://app.patched.im.evil.example",
])
def test_cross_origin_post_is_refused(client, make_token, origin):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item())], origin=origin)
    assert resp.status_code == 403
    assert "did not come from the portal page itself" in resp.text
    assert STUB_STATE["approval_puts"] == []


def test_post_with_neither_origin_nor_referer_is_refused(client, make_token):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item())], origin=None)
    assert resp.status_code == 403
    assert STUB_STATE["approval_puts"] == []


def test_same_origin_referer_is_accepted_when_origin_is_absent(client, make_token):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item())], origin=None,
                 extra_headers={"Referer": "https://testserver/software?type=application"})
    assert resp.status_code == 303
    assert len(STUB_STATE["approval_puts"]) == 1


def test_cross_site_referer_is_refused(client, make_token):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item())], origin=None,
                 extra_headers={"Referer": "https://evil.example/software"})
    assert resp.status_code == 403


# PAT-2008 review fix: nginx terminates TLS in front of the portal and
# forwards plain http, so request.url.scheme is not a trustworthy signal -
# _same_origin used to accept an Origin whose scheme merely matched the
# request's own (always http behind that proxy), which let a same-host
# http Origin pass on a host that is never actually served over http.
def test_http_origin_on_a_non_local_host_is_refused(client, make_token):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item())],
                 origin="http://testserver")
    assert resp.status_code == 403
    assert "did not come from the portal page itself" in resp.text
    assert STUB_STATE["approval_puts"] == []


def test_https_origin_on_a_non_local_host_is_accepted(client, make_token):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item())],
                 origin="https://testserver")
    assert resp.status_code == 303
    assert len(STUB_STATE["approval_puts"]) == 1


def test_tenant_and_actor_come_from_the_session_never_the_body(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    # Stray top-level fields naming a tenant or actor are not forwarded.
    resp = _post(client, token, [
        ("state", "approved"), ("item", _item()),
        ("tenant_id", "99999999-0000-0000-0000-000000000000"),
        ("actor_email", "someone@else.example"),
    ])
    assert resp.status_code == 303
    body = STUB_STATE["approval_puts"][0]["body"]
    assert set(body) == {"state", "items"}
    assert "99999999" not in json.dumps(body)
    assert STUB_STATE["approval_puts"][0]["jwt"] == token
    # A tenant key inside an item is refused outright.
    resp = _post(client, token, [
        ("state", "approved"),
        ("item", _item(tenant_id="99999999-0000-0000-0000-000000000000")),
    ])
    assert resp.status_code == 400
    assert len(STUB_STATE["approval_puts"]) == 1


@pytest.mark.parametrize("state", ["mandatory", "APPROVED", ""])
def test_unrecognised_states_are_rejected(client, make_token, state):
    token = make_token()
    resp = _post(client, token, [("state", state), ("item", _item())])
    assert resp.status_code == 400
    assert STUB_STATE["approval_puts"] == []


def test_unreviewed_is_accepted_by_the_shared_route_but_not_offered_by_software(
    client, make_token,
):
    """PAT-2058: the write route now accepts "unreviewed" too (the
    Homebrew tab's Reset to unreviewed action posts it, through this same
    route) - main.APPROVAL_ALL_WRITE_STATES, not the narrower
    main.APPROVAL_WRITE_STATES /software's own bulk bar and per-row select
    still render. This is the negative half of that: /software's UI never
    renders the option (see test_admin_sees_inline_and_bulk_controls-style
    assertions elsewhere in this file), but a request naming it directly
    is not refused as malformed."""
    token = make_token()
    resp = _post(client, token, [("state", "unreviewed"), ("item", _item())])
    assert resp.status_code == 303
    assert STUB_STATE["approval_puts"][0]["body"]["state"] == "unreviewed"


@pytest.mark.parametrize("item", [
    json.dumps({"type": "application", "platform": "any", "identifier": "x"}),
    json.dumps({"type": "application", "platform": "macos", "identifier": ""}),
    json.dumps({"type": "application", "platform": "windows", "identifier": "x",
                "team_id": "ABCDE12345"}),
    json.dumps({"type": "application", "platform": "macos", "identifier": "x",
                "team_id": "bad"}),
    json.dumps({"type": "browser_extension", "browser": "opera", "extension_id": "abc"}),
    json.dumps({"type": "browser_extension", "browser": "chrome", "extension_id": "a b"}),
    json.dumps({"type": "package", "identifier": "x"}),
    json.dumps(["not", "an", "object"]),
    "{not json",
])
def test_malformed_items_are_refused(client, make_token, item):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", item)])
    assert resp.status_code == 400
    assert STUB_STATE["approval_puts"] == []


def test_bulk_cap_is_enforced_by_the_portal(client, make_token):
    token = make_token()
    items = [("item", _item(name=f"App {n}", identifier=f"com.example.app{n}"))
             for n in range(main.APPROVAL_MAX_ITEMS + 1)]
    resp = _post(client, token, [("state", "ignored"), *items])
    page = _flash(client, token, resp).text
    assert "Select at most 500 products at a time. Nothing was changed." in page
    assert STUB_STATE["approval_puts"] == []


def test_bulk_at_the_cap_is_sent_as_one_write(client, make_token):
    token = make_token()
    items = [("item", _item(name=f"App {n}", identifier=f"com.example.app{n}"))
             for n in range(main.APPROVAL_MAX_ITEMS)]
    resp = _post(client, token, [("state", "ignored"), ("reason", "Legacy kit"), *items])
    assert resp.status_code == 303
    assert len(STUB_STATE["approval_puts"]) == 1
    assert len(STUB_STATE["approval_puts"][0]["body"]["items"]) == 500


def test_bulk_mixed_kinds_and_duplicates_are_deduplicated(client, make_token):
    token = make_token()
    resp = _post(client, token, [("state", "unapproved"), ("item", _item()),
                                 ("item", _item()), ("item", _ext_item())])
    assert resp.status_code == 303
    items = STUB_STATE["approval_puts"][0]["body"]["items"]
    assert items == [
        {"type": "application", "platform": "macos", "identifier": "com.example.mysteryapp"},
        {"type": "browser_extension", "browser": "firefox",
         "extension_id": "mysteryhelper-ext-id"},
    ]


def test_bulk_with_nothing_selected_writes_nothing(client, make_token):
    token = make_token()
    resp = _post(client, token, [("state", "approved")])
    assert "Select at least one product first." in _flash(client, token, resp).text
    assert STUB_STATE["approval_puts"] == []


def test_reason_over_the_limit_writes_nothing(client, make_token):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item()),
                                 ("reason", "x" * 1001)])
    assert "The reason can be at most 1000 characters." in _flash(client, token, resp).text
    assert STUB_STATE["approval_puts"] == []


def test_oversized_body_is_refused(client, make_token):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item()),
                                 ("reason", "x" * (main.APPROVAL_MAX_BODY_BYTES + 1))])
    assert resp.status_code == 413
    assert STUB_STATE["approval_puts"] == []


def test_return_to_cannot_leave_the_software_page(client, make_token):
    token = make_token()
    for target in ("https://evil.example/", "//evil.example/software", "/devices",
                   "/software/../devices", "\\\\evil.example"):
        resp = _post(client, token, [("state", "approved"), ("item", _item()),
                                     ("return_to", target)])
        assert resp.status_code == 303
        assert urlsplit(resp.headers["location"]).path == "/software", target
        assert not urlsplit(resp.headers["location"]).netloc


# ── Results and errors ───────────────────────────────────────────────────

def test_platform_refusal_surfaces_to_the_user_with_product_names(client, make_token):
    token = make_token()
    STUB_STATE["approval_put_error"] = (422, {
        "error": "unconfirmed_identity",
        "message": "some products have no confirmed identity",
        "items": [{"index": 1, "code": "unconfirmed_identity",
                   "message": "this product has no confirmed identity"}],
    })
    resp = _post(client, token, [("state", "approved"), ("item", _ext_item()),
                                 ("item", _item())])
    page = _flash(client, token, resp).text
    assert "Some products do not have a confirmed identity yet" in page
    assert "MysteryApp: this product has no confirmed identity" in page
    assert "changed to" not in page


def test_platform_admin_refusal_is_shown_as_a_message_not_an_unlinked_account(
    client, make_token,
):
    token = make_token()
    STUB_STATE["approval_put_error"] = (403, {"error": "admin_role_required",
                                              "message": "admin only"})
    resp = _post(client, token, [("state", "approved"), ("item", _item())])
    page = _flash(client, token, resp).text
    assert "Only an administrator on your account can change approval state." in page


def test_platform_outage_says_the_change_may_not_have_saved(client, make_token):
    token = make_token()
    STUB_STATE["approval_put_error"] = (502, {"error": "bad gateway"})
    resp = _post(client, token, [("state", "approved"), ("item", _item())])
    page = _flash(client, token, resp).text
    assert "could not be reached, so this change may not have been saved" in page


def test_platform_session_rejection_goes_to_session_expired(client, make_token):
    token = make_token()
    STUB_STATE["approval_put_error"] = (401, {"error": "identity rejected"})
    resp = _post(client, token, [("state", "approved"), ("item", _item())])
    assert resp.status_code == 401


def test_protected_warning_is_shown_after_the_write(client, make_token):
    token = make_token()
    STUB_STATE["protected_identifiers"] = {"com.example.mysteryapp"}
    resp = _post(client, token, [("state", "unapproved"), ("item", _item())])
    page = _flash(client, token, resp).text
    assert "Protected product marked Unapproved." in page
    assert "MysteryApp (EDR)" in page


def test_resolved_alerts_are_reported_when_present_and_tolerated_when_absent(
    client, make_token,
):
    token = make_token()
    resp = _post(client, token, [("state", "approved"), ("item", _item())])
    assert "alert" not in _flash(client, token, resp).text.split("approval-result")[1][:600]
    STUB_STATE["approval_put_extra"] = {"resolved_alerts": 2}
    resp = _post(client, token, [("state", "ignored"), ("item", _ext_item())])
    assert "2 open Unapproved alerts resolved." in _flash(client, token, resp).text


def test_a_forged_result_notice_is_not_rendered(client, make_token):
    token = make_token()
    forged = main._sign_flash(make_token(email="mallory@tenant-a.example", exp_delta=700),
                              {"error": "Call 555 0100 to restore access"})
    html = _get(client, token, "/software?approval_result=" + forged).text
    assert "555 0100" not in html
    signed = main._sign_flash(token, {"error": "ok"})
    # Always change the last hex digit. Overwriting the tail with a fixed
    # "00" was a no-op whenever the real signature already ended "00"
    # (1 run in 256), which made this test fail at random.
    tampered = signed[:-1] + ("1" if signed[-1] == "0" else "0")
    assert 'id="approval-result"' not in _get(
        client, token, "/software?approval_result=" + tampered).text


def test_reasons_and_names_are_escaped(client, make_token):
    token = make_token()
    hostile = '<script>alert(1)</script>"><img src=x onerror=alert(2)>'
    resp = _post(client, token, [("state", "unapproved"), ("reason", hostile),
                                 ("item", _item(name=hostile))])
    assert resp.status_code == 303
    history = client.get("/software/history?" + urlencode({"item": _item(name=hostile)}),
                         headers=_headers(token)).text
    assert "<script>alert(1)</script>" not in history
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in history
    assert "<img src=x" not in history
    STUB_STATE["approval_put_error"] = (422, {
        "error": "unconfirmed_identity", "message": "x",
        "items": [{"index": 0, "code": "unconfirmed_identity", "message": hostile}]})
    resp = _post(client, token, [("state", "approved"), ("item", _item(name=hostile))])
    page = _flash(client, token, resp).text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


# ── History ──────────────────────────────────────────────────────────────

def test_history_shows_who_when_before_after_and_why(client, make_token):
    token = make_token()
    _post(client, token, [("state", "approved"), ("reason", "Finance tool"), ("item", _item())])
    _post(client, token, [("state", "unapproved"), ("reason", "Replaced"), ("item", _item())])
    STUB_STATE["portal_role"] = "viewer"  # viewers read history too
    resp = client.get("/software/history?" + urlencode({"item": _item()}),
                      headers=_headers(token))
    assert resp.status_code == 200
    html = resp.text
    assert "alice@tenant-a.example" in html
    assert "24 Sep 2026 10:00 UTC" in html
    assert html.index("Replaced") < html.index("Finance tool")  # newest first
    assert "Unreviewed" in html and "Approved" in html and "Unapproved" in html
    request = STUB_STATE["approval_history_requests"][-1]
    assert request == {"type": "application", "platform": "macos",
                       "identifier": "com.example.mysteryapp", "limit": "100"}
    partial = client.get("/software/history?" + urlencode({"item": _item(), "partial": "1"}),
                         headers=_headers(token)).text
    assert "<html" not in partial and "Finance tool" in partial


def test_history_rejects_a_malformed_item_and_survives_a_platform_failure(client, make_token):
    token = make_token()
    assert client.get("/software/history?item=%7Bbad", headers=_headers(token)).status_code == 400
    STUB_STATE["approval_history_status"] = 500
    resp = client.get("/software/history?" + urlencode({"item": _ext_item(), "partial": "1"}),
                      headers=_headers(token))
    assert resp.status_code == 200
    assert "History could not be loaded just now." in resp.text


def test_history_requires_access_like_every_other_route(client):
    resp = client.get("/software/history?" + urlencode({"item": _item()}))
    assert resp.status_code == 401


def test_approval_write_requires_access_like_every_other_route(client):
    resp = client.post("/software/approvals", content="state=approved",
                       headers={"Origin": ORIGIN,
                                "Content-Type": "application/x-www-form-urlencoded"})
    assert resp.status_code == 401
    assert STUB_STATE["approval_puts"] == []


def test_filter_query_values_seed_the_controls(client, make_token):
    html = _get(client, make_token(),
                "/software?publisher=Slack%20Technologies%2C%20Inc.&min_devices=3&unreviewed=1").text
    assert '<option value="Slack Technologies, Inc." selected>' in html
    assert 'value="3" placeholder="0" data-filter-min-devices' in html
    # PAT-2163 (orchestrator follow-up): the "Unreviewed only" checkbox is
    # gone - the legacy ?unreviewed=1 alias now seeds the Approval
    # dropdown's "waiting" checkbox instead (main.py's
    # _software_approval_filter: Approval = Waiting on a decision is the
    # identical row set).
    assert '<input type="checkbox" name="approval" value="waiting" checked>' in html
    return_to = re.search(r'name="return_to" value="([^"]*)"', html).group(1)
    assert parse_qs(urlsplit(return_to.replace("&amp;", "&")).query)["min_devices"] == ["3"]


def test_inventory_row_form_writes_one_item(client, make_token):
    """The inventory's compact form posts state + item, the bulk shape."""
    token = make_token()
    item = _item(name="ArchiveTool", identifier="com.acme.archive")
    resp = _post(client, token, [("state", "unapproved"), ("item", item)])
    assert resp.status_code == 303
    assert STUB_STATE["approval_puts"][0]["body"]["items"] == [
        {"type": "application", "platform": "macos", "identifier": "com.acme.archive"}]


def test_decision_state_tabs_carry_estate_totals(client, make_token):
    """PAT-2120: the five decision group cards (and the JS that live-
    recounted their pill/KPI totals as other filters narrowed what was
    shown) are gone, replaced by the decision-state segmented control -
    its tab labels carry the same estate-wide totals, now server-rendered
    once rather than recomputed client-side. The waiting bucket includes
    the six SOFTWARE_INVENTORY products with no matching governance row
    (3 undecided/unreviewed applications+extensions, plus 6 unmatched
    inventory products - see test_software.py's module docstring)."""
    html = _get(client, make_token()).text
    # PAT-2255: the options use the one approval vocabulary a row shows.
    for label, total in (
        ("Unreviewed", 9), ("Unapproved", 4),
        ("Approved", 3), ("Ignored", 1), ("State not recognised", 1),
    ):
        assert f'>{label} ({total})<' in html


def test_inventory_row_form_with_the_placeholder_state_is_refused(client, make_token):
    """Round 3: submitting the "Set state…" placeholder (state "") writes
    nothing, even without JavaScript to disable Apply."""
    token = make_token()
    item = _item(name="ArchiveTool", identifier="com.acme.archive")
    resp = _post(client, token, [("state", ""), ("item", item)])
    assert resp.status_code == 400
    assert "Choose Approve, Unapprove, Ignore or Reset to unreviewed." in resp.text
    assert STUB_STATE["approval_puts"] == []
