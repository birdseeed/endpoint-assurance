"""PAT-1440: drift guard for the /healthz projection allowlist in main.py.

Context: stray_config_backups (PAT-1431/1433) and systemd_hardening
(PAT-1237) were added to all three patched-maintenance-facts.sh emitters in
one change each, and reached prod-01/api-01's dashboard rows immediately -
but never reached portal-01's, because _maintenance_info() in this repo's
main.py builds an explicit allowlist dict and anything not named there is
silently dropped. Nothing failed; nothing logged; the field just never
appeared. That is exactly the "absence reads as clean" shape PAT-912/837/960
already caught this estate doing elsewhere (see root AGENTS.md), just one
layer further out - at a transport boundary between emitter and dashboard
rather than inside a single check.

The parity block convention (test_pat1433_stray_config_backups_parity.py,
test_pat1237_systemd_hardening_parity.py) keeps the three *emitters*
identical. Nothing kept the three *transports* in step - portal's was a
silent allowlist with no test watching it. This test is that watch: it
parses deploy/patched-maintenance-facts.sh's own `facts = {...}` dict
literal (the actual JSON keys the emitter writes) and asserts every one of
those keys has a recorded decision in main.py's MAINTENANCE_HEALTHZ_PROJECTION
map - carried through, reduced to counts, or deliberately withheld with a
stated reason. A field with no entry fails this test loudly instead of
vanishing at /healthz the way these two just did.

Deliberately NOT clever reflection over _maintenance_info's source (walking
its AST, or diffing its returned keys against the raw facts) - a regex over
a known dict-literal shape, checked against a plain hand-maintained mapping,
is the whole mechanism. Simple and readable beats generality here: the
emitter's `facts = {...}` block has been byte-stable in shape (one
"key": value per line) since PAT-989, and a person choosing the projection
decision for a new field is exactly the discipline this ticket exists to
force - reflection would let a new field's decision be silently defaulted
instead of chosen.
"""

import re
from pathlib import Path

import main as portal_main

REPO = Path(__file__).resolve().parent.parent
EMITTER_SCRIPT = REPO / "deploy" / "patched-maintenance-facts.sh"

# Matches a top-level `"key": ...,` line inside the emitter's `facts = {...}`
# python3-heredoc dict literal, e.g. `    "generated_at": datetime.now(...),`
# or `    "systemd_hardening": systemd_hardening,`. Anchored to leading
# whitespace + a quoted key + a colon, which is exactly this block's house
# style (see the emitter script itself) and nothing else in the file uses.
_FACTS_KEY_RE = re.compile(r'^\s{4}"([a-z0-9_]+)":', re.MULTILINE)


def _emitter_facts_keys() -> list[str]:
    text = EMITTER_SCRIPT.read_text()
    start = text.index("\nfacts = {")
    end = text.index("\n}\n", start)
    block = text[start:end]
    keys = _FACTS_KEY_RE.findall(block)
    assert keys, (
        f"{EMITTER_SCRIPT}: found the facts = {{...}} block but extracted no "
        "keys from it -- the regex or the block's shape has drifted, fix "
        "the extraction before trusting this test's other assertions"
    )
    return keys


def test_emitter_facts_block_is_still_shaped_as_expected():
    # A basic sanity check on the extraction itself, independent of the
    # projection-parity assertion below -- if this fails, the regex broke,
    # not the projection.
    keys = _emitter_facts_keys()
    assert "generated_at" in keys
    assert "stray_config_backups" in keys
    assert "systemd_hardening" in keys


def test_every_emitter_field_has_a_recorded_healthz_projection_decision():
    """The guard itself: every key the emitter's facts dict produces must
    have an entry in MAINTENANCE_HEALTHZ_PROJECTION. A field with no
    decision must fail here, not vanish silently at /healthz."""
    emitter_keys = set(_emitter_facts_keys())
    decided_keys = set(portal_main.MAINTENANCE_HEALTHZ_PROJECTION)

    undecided = emitter_keys - decided_keys
    assert not undecided, (
        f"deploy/patched-maintenance-facts.sh produces {sorted(undecided)} "
        "with no recorded /healthz projection decision in main.py's "
        "MAINTENANCE_HEALTHZ_PROJECTION. Add an entry there: 'carried', "
        "'reduced', or 'withheld: <reason>' -- see that map's own comment. "
        "This is the exact silent-drop PAT-1440 fixed for "
        "stray_config_backups/systemd_hardening; don't let a future field "
        "repeat it."
    )

    # Keep the map honest in the other direction too: an entry for a field
    # the emitter no longer produces is a stale decision nobody is
    # exercising, and stale entries make the map progressively less
    # trustworthy as a record of what's actually true today.
    stale = decided_keys - emitter_keys
    assert not stale, (
        f"MAINTENANCE_HEALTHZ_PROJECTION has entries for {sorted(stale)}, "
        "which deploy/patched-maintenance-facts.sh no longer produces -- "
        "remove the stale entry/entries."
    )


def test_every_decision_is_one_of_the_three_recognised_shapes():
    for field, decision in portal_main.MAINTENANCE_HEALTHZ_PROJECTION.items():
        assert decision in ("carried", "reduced") or decision.startswith("withheld: "), (
            f"{field!r}: {decision!r} is not a recognised projection decision "
            "-- use 'carried', 'reduced', or 'withheld: <reason>'"
        )
        if decision.startswith("withheld: "):
            assert len(decision) > len("withheld: "), (
                f"{field!r}: a withheld decision must state a reason, not be empty"
            )


def test_reduced_fields_actually_produce_reduced_keys_at_healthz(tmp_path, monkeypatch):
    """A 'reduced' decision that isn't backed by real code would be just as
    silent a failure as no decision at all. Cross-check the two fields this
    ticket adds against the live reduction: their raw keys must never appear
    in _maintenance_info()'s output, and their *_count/*_available keys must.
    See test_pages.py's own maintenance-summary tests for the full behaviour
    matrix (absence vs. zero, available:false, leakage) - this is just the
    smoke-level tie between the projection map and the real function."""
    import json as _json
    from datetime import UTC as _UTC
    from datetime import datetime as _datetime

    facts = {
        "generated_at": _datetime.now(_UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reboot_required": False,
        "security_updates": 0,
        "esm_updates": 0,
        "pro_attached": True,
        "automatic_reboot_configured": True,
        "third_party_pending": [],
        "timers": [],
        "stray_config_backups": [
            {
                "path": "/etc/patched-portal/portal.env.bak-pat1",
                "mode": "0644",
                "owner": "root",
                "group": "root",
                "group_readable": True,
                "world_readable": False,
                "mode_unknown": False,
            }
        ],
        "systemd_hardening": {
            "available": True,
            "units": [
                {
                    "unit": "patched-portal.service",
                    "score": 7.2,
                    "rating": "EXPOSED",
                    "class": "network-facing",
                    "ceiling": 6.0,
                    "over_ceiling": True,
                }
            ],
        },
    }
    facts_file = tmp_path / "maintenance.json"
    facts_file.write_text(_json.dumps(facts))
    monkeypatch.setattr(portal_main, "MAINTENANCE_FACTS_FILE", facts_file)

    info = portal_main._maintenance_info()
    assert info is not None
    assert "stray_config_backups" not in info
    assert "systemd_hardening" not in info
    assert info["stray_config_backups_count"] == 1
    assert info["systemd_hardening_available"] is True
    assert info["systemd_hardening_over_ceiling_count"] == 1
