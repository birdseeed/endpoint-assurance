"""PAT-2141 polish (Andy, 25 Sept 2026: "alignment issues", "poor layout"):
small volumes read in MB, not "0.0 GB", and macOS APFS system sub-volumes
collapse into their own disclosure instead of burying the volumes a customer
cares about."""

import main


def test_humanbytes_reads_small_values_in_mb_not_zero_gb():
    assert main.humanbytes(20_971_520) == "21 MB"
    assert main.humanbytes(500_000) == "<1 MB"
    assert main.humanbytes(0) == "0 MB"
    assert main.humanbytes(3_500_000_000) == "3.5 GB"
    assert main.humanbytes(480_000_000_000) == "480 GB"
    assert main.humanbytes(None) is None


def test_system_volumes_split_out_and_nothing_dropped():
    block = {"rows": [
        {"mount": "/"}, {"mount": "/System/Volumes/Data"},
        {"mount": "/System/Volumes/VM"}, {"mount": "/Volumes/DEV_BACKUP"},
    ]}
    out = main._split_system_volumes(block)
    assert [r["mount"] for r in out["rows"]] == ["/", "/Volumes/DEV_BACKUP"]
    assert [r["mount"] for r in out["system_rows"]] == [
        "/System/Volumes/Data", "/System/Volumes/VM"]


def test_device_page_collapses_system_volumes(client, make_token):
    # PAT-2164: Storage volumes moved to the Hardware tab.
    body = client.get(
        "/devices/dev-mac-001/hardware", cookies={"CF_Authorization": make_token()}).text
    assert "macOS system volumes (4)" in body
    assert '<details class="hardware-system-volumes">' in body
    assert "/Volumes/DEV_BACKUP" in body
    assert "0.0 GB" not in body
