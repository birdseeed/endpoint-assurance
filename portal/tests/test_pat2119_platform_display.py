"""PAT-2119: /software's Current software inventory table showed the raw
platform key ("macos", "windows", "linux") in its Platform cell instead of
the customer-facing spelling. main.platform_display is the Jinja filter
that fixes it; these tests cover the pure function and its use in the
rendered page. No Jinja filter or macro for this already existed (checked
main.py and templates/_macros.html before adding one) - the closest thing,
device_table's `{{ d.platform }}` in _macros.html, has the same raw-value
bug but is out of this ticket's scope (the live report was specific to
/software's inventory table)."""

import pytest

import main
from tests.conftest import SOFTWARE_INVENTORY, STUB_STATE


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("macos", "macOS"),
        ("windows", "Windows"),
        ("linux", "Linux"),
        # Anything not in the map passes through unchanged - an older
        # platform's "unknown", or a future platform key nobody has taught
        # this list yet. Absence requires authority (root AGENTS.md): a
        # display filter must not guess at a label for a value it doesn't
        # recognise.
        ("unknown", "unknown"),
        ("solaris", "solaris"),
        ("", ""),
        (None, None),
    ],
)
def test_platform_display(value, expected):
    assert main.platform_display(value) == expected


def test_software_inventory_platform_cell_uses_display_labels(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = client.get("/software", headers={"Cf-Access-Jwt-Assertion": token})
    assert resp.status_code == 200
    html = resp.text

    # SOFTWARE_INVENTORY (tests/conftest.py) carries macos, windows, macos,
    # macos and unknown across its five products - every mapped value must
    # render as its display label, and the raw keys must not appear
    # anywhere in the inventory table's Platform column.
    assert ">macOS<" in html
    assert ">Windows<" in html
    # unknown has no mapping and must pass through unchanged, never blank
    # and never a guessed label.
    assert ">unknown<" in html

    platforms = {p["platform"] for p in SOFTWARE_INVENTORY["products"]}
    assert platforms == {"macos", "windows", "unknown"}
    assert ">macos<" not in html
    assert ">windows<" not in html
