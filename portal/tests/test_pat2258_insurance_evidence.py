"""PAT-2258: the cyber insurance evidence pack page.

Consumes GET /v1/portal/insurance-evidence verbatim (contracts/portal-api.md).
The platform owns every figure, status, source and freshness; the portal
renders them, links each answer to the portal page its evidence comes from,
always shows the "Not evidenced by Patched" group, proxies the platform's own
PDF and CSV, and never states or implies a verdict about cover.
"""

import copy
import re

from tests.conftest import (
    INSURANCE_EVIDENCE,
    INSURANCE_EVIDENCE_CSV,
    INSURANCE_EVIDENCE_PDF,
    STUB_STATE,
)

PAGE = "/reports/insurance-evidence"

# Customer copy rules plus the pack's own: no verdict, nothing about
# insurability or premiums, "estate" not "fleet", no em dash, no ticket ids.
_BANNED = re.compile(
    r"\b(compliant|certified|insurable|premiums?|fleet)\b|—|PAT-\d", re.IGNORECASE)


def _get(client, token, path):
    return client.get(path, headers={"Cf-Access-Jwt-Assertion": token})


def _main(body: str) -> str:
    """The page's own content, without the shared shell (rail, footer)."""
    start = body.index('<main class="page')
    return body[start:body.index("</main>", start)]


def _ok(client, make_token, path=PAGE):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = _get(client, token, path)
    assert resp.status_code == 200, resp.text[:500]
    return resp, token


def test_renders_every_question_in_both_groups(client, make_token):
    resp, _ = _ok(client, make_token)
    main = _main(resp.text)
    assert "Cyber insurance evidence" in main
    for q in INSURANCE_EVIDENCE["questions"]:
        assert q["title"] in main, q["title"]
        assert q["question"] in main, q["question"]
    evidenced_at = main.index("Answers from Patched evidence")
    not_evidenced_at = main.index('id="ie-not-evidenced-heading"')
    assert evidenced_at < main.index("EDR and anti-malware") < not_evidenced_at
    for title in ("Multi-factor authentication", "Email security", "Backups",
                  "Incident response plan", "Security awareness training"):
        assert not_evidenced_at < main.index(title), title


def test_answers_show_unknown_devices_freshness_and_answer_text(client, make_token):
    resp, _ = _ok(client, make_token)
    main = _main(resp.text)
    edr = next(q for q in INSURANCE_EVIDENCE["questions"] if q["id"] == "edr_coverage")
    block = main[main.index('id="q-edr_coverage"'):main.index('id="q-disk_encryption"')]
    assert "1 of 4 devices (25.0%)" in block
    assert "Unknown devices" in block and ">3<" in block
    assert "As of" in block and "UTC" in block
    assert edr["answer_text"].split(".")[0] in block
    assert "How this is worked out" in block


def test_each_answer_links_to_its_source_view(client, make_token):
    resp, _ = _ok(client, make_token)
    main = _main(resp.text)
    for q in INSURANCE_EVIDENCE["questions"]:
        if q["source"]:
            assert f'href="{q["source"]["path"]}"' in main, q["id"]


def test_status_counts_carry_their_denominator(client, make_token):
    resp, _ = _ok(client, make_token)
    main = _main(resp.text)
    assert "7 of 12" in main   # partly evidenced
    assert "5 of 12" in main   # not evidenced by Patched
    assert "0 of 12" in main


def test_evidenced_status_never_takes_the_ok_tone(client, make_token):
    data = copy.deepcopy(INSURANCE_EVIDENCE)
    data["questions"][0]["status"] = "evidenced"
    STUB_STATE["insurance_evidence_data"] = data
    resp, _ = _ok(client, make_token)
    main = _main(resp.text)
    block = main[main.index('id="q-edr_coverage"'):main.index('id="q-disk_encryption"')]
    assert ">Evidenced<" in block
    assert "pill-ok" not in main


def test_unrecognised_status_renders_unknown_never_evidenced(client, make_token):
    data = copy.deepcopy(INSURANCE_EVIDENCE)
    data["questions"][0]["status"] = "definitely_fine"
    STUB_STATE["insurance_evidence_data"] = data
    resp, _ = _ok(client, make_token)
    block = _main(resp.text)
    block = block[block.index('id="q-edr_coverage"'):block.index('id="q-disk_encryption"')]
    assert ">Unknown<" in block
    assert "Evidenced" not in block.replace("Partly evidenced", "")


def test_only_plain_portal_paths_are_linked(client, make_token):
    data = copy.deepcopy(INSURANCE_EVIDENCE)
    data["questions"][0]["source"] = {"label": "Elsewhere", "path": "https://evil.example/x"}
    data["questions"][1]["source"] = {"label": "Protocol-relative", "path": "//evil.example"}
    data["questions"][2]["source"] = {"label": "Script", "path": "javascript:alert(1)"}
    STUB_STATE["insurance_evidence_data"] = data
    resp, _ = _ok(client, make_token)
    main = _main(resp.text)
    assert "evil.example" not in main
    assert "javascript:" not in main
    assert "Elsewhere" in main  # the label still shows, unlinked


def test_page_copy_never_states_a_verdict(client, make_token):
    resp, _ = _ok(client, make_token)
    match = _BANNED.search(_main(resp.text))
    assert not match, f"banned copy {match.group(0)!r}"


def test_download_buttons_point_at_pdf_and_csv(client, make_token):
    resp, _ = _ok(client, make_token)
    main = _main(resp.text)
    assert 'href="/reports/insurance-evidence.pdf"' in main
    assert 'href="/reports/insurance-evidence.csv"' in main


def test_csv_proxies_platform_bytes_verbatim(client, make_token):
    resp, token = _ok(client, make_token, PAGE + ".csv")
    assert resp.headers["content-type"].startswith("text/csv")
    assert resp.content == INSURANCE_EVIDENCE_CSV.encode()
    assert "attachment" in resp.headers["content-disposition"]
    req = STUB_STATE["insurance_evidence_requests"][-1]
    assert req == {"format": "csv", "jwt": token}


def test_pdf_proxies_platform_bytes_verbatim(client, make_token):
    resp, token = _ok(client, make_token, PAGE + ".pdf")
    assert resp.headers["content-type"].startswith("application/pdf")
    assert resp.content == INSURANCE_EVIDENCE_PDF
    assert resp.headers["content-disposition"].endswith('.pdf"')
    req = STUB_STATE["insurance_evidence_requests"][-1]
    assert req == {"format": "pdf", "jwt": token}


def test_page_request_sends_no_tenant_or_extra_params(client, make_token):
    _, token = _ok(client, make_token)
    assert STUB_STATE["insurance_evidence_requests"] == [{"format": "json", "jwt": token}]


def test_upstream_failure_is_an_honest_error(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["insurance_evidence_status"] = 500
    for path in (PAGE, PAGE + ".csv", PAGE + ".pdf"):
        resp = _get(client, token, path)
        assert resp.status_code == 502, path
        assert "text/csv" not in resp.headers.get("content-type", "")
        assert "application/pdf" not in resp.headers.get("content-type", "")


def test_malformed_payload_is_an_error_not_a_blank_pack(client, make_token):
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    STUB_STATE["insurance_evidence_data"] = ["not", "an", "object"]
    resp = _get(client, token, PAGE)
    assert resp.status_code >= 500
    assert "Answers from Patched evidence" not in resp.text


def test_reports_page_lists_the_pack_under_assurance(client, make_token):
    resp, _ = _ok(client, make_token, "/reports")
    main = _main(resp.text)
    assurance = main.index("Endpoint assurance")
    assert assurance < main.index('href="/reports/insurance-evidence"')
