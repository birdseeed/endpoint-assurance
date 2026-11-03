"""Additional upload boundary and evidence regressions; all transport is local."""

import asyncio
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

import pytest
from starlette.requests import Request

import certificates
import main
from tests.test_pat2389_certificates import (
    AGENT,
    API,
    CERT_ID,
    ORIGIN,
    ROUTES,
    UPLOADED,
    get_page,
    headers,
    mutate,
    writes,
)
from tests.test_pat2389_certificates import platform as platform
from tests.test_pat2389_certificates import public_certificates as public_certificates


@pytest.mark.parametrize("status,text", [(401, "session"), (403, "not linked"),
                                       (503, "not yet enabled")])
def test_list_preserves_existing_account_and_session_failures(
    client, make_token, platform, status, text
):
    platform["status"][("GET", API)] = status
    response = get_page(client, make_token())
    assert response.status_code == status
    assert text in response.text.lower()
    assert "INTERNAL_PROVIDER_SECRET" not in response.text


@pytest.mark.parametrize("suffix", [b"trailing", b"\x00", b"\n"])
def test_der_trailing_bytes_are_refused(public_certificates, suffix):
    with pytest.raises(ValueError):
        certificates.validate_public_certificate(public_certificates["der"] + suffix)


@pytest.mark.parametrize("change", ["chain", "prefix", "suffix", "headers"])
def test_pem_must_be_exactly_one_plain_certificate(public_certificates, change):
    pem = public_certificates["pem"]
    raw = {"chain": pem + pem, "prefix": b"unexpected\n" + pem,
           "suffix": pem + b"unexpected\n", "headers": pem.replace(
               b"-----BEGIN CERTIFICATE-----\n", b"-----BEGIN CERTIFICATE-----\nProc-Type: 4\n"
           )}[change]
    with pytest.raises(ValueError):
        certificates.validate_public_certificate(raw)


def test_surrounding_pem_whitespace_is_accepted(public_certificates):
    certificates.validate_public_certificate(b" \r\n" + public_certificates["pem"] + b" \n")


@pytest.mark.parametrize("label", ["\tName", "Name\n", "Bad\x00name", "Bad\x85name"])
def test_control_characters_in_labels_are_refused(
    client, make_token, platform, public_certificates, label
):
    response = mutate(client, make_token(), ROUTES[0], label=label,
                      certificate=public_certificates["pem"])
    assert response.status_code == 400
    assert not writes(platform)


def test_empty_browser_file_input_updates_label_only(client, make_token, platform):
    token = make_token()
    response = client.post(ROUTES[1],
        data={"label": "Renamed", "csrf_token": main._csrf_token(token)},
        files={"certificate": ("", b"", "application/octet-stream")},
        headers=headers(token, Origin=ORIGIN), follow_redirects=False)
    assert response.status_code == 303
    assert writes(platform)[0][2]["json"] == {"label": "Renamed"}


def test_incomplete_replacement_cannot_become_label_only(client, make_token, platform):
    token = make_token()
    raw = (
        '--testboundary\r\nContent-Disposition: form-data; name="label"\r\n\r\n'
        'Changed label\r\n'
        '--testboundary\r\nContent-Disposition: form-data; name="csrf_token"\r\n\r\n'
        f'{main._csrf_token(token)}\r\n'
        '--testboundary\r\nContent-Disposition: form-data; name="certificate"; '
        'filename="bad.pem"\r\nContent-Type: application/octet-stream\r\n\r\n'
        'invalid replacement'
    ).encode()
    response = client.post(ROUTES[1], content=raw, headers=headers(token, Origin=ORIGIN,
        **{"Content-Type": "multipart/form-data; boundary=testboundary"}),
        follow_redirects=False)
    assert response.status_code == 400
    assert not writes(platform)


@pytest.mark.parametrize("field,values", [
    ("csrf_token", ["\N{SNOWMAN}"]), ("csrf_token", ["valid", "valid"]),
    ("label", ["One", "Two"]),
])
def test_ambiguous_fields_and_non_ascii_csrf_fail_closed(
    client, make_token, platform, field, values
):
    token = make_token()
    fields = {"label": ["Name"], "csrf_token": [main._csrf_token(token)]}
    fields[field] = [main._csrf_token(token) if v == "valid" else v for v in values]
    response = client.post(ROUTES[1], content=urlencode(fields, doseq=True),
        headers=headers(token, Origin=ORIGIN,
                        **{"Content-Type": "application/x-www-form-urlencoded"}))
    assert response.status_code in (400, 403)
    assert not writes(platform)


@pytest.mark.parametrize("device_id", ["//evil.example", "../other", CERT_ID + '?x="bad'])
def test_agent_device_links_require_a_uuid(client, make_token, platform, device_id):
    platform["rows"] = [{**AGENT, "device_id": device_id}]
    response = get_page(client, make_token())
    assert response.status_code == 200
    assert 'href="/devices/' not in response.text


def test_forged_uploaded_device_provenance_is_ignored(client, make_token, platform):
    platform["rows"] = [{**UPLOADED, "device_id": CERT_ID}]
    assert 'href="/devices/' not in get_page(client, make_token()).text


@pytest.mark.parametrize("days,status", [(-1, "expired"), (0, "critical"), (7, "critical"),
                                        (8, "warning"), (30, "warning"), (31, "healthy")])
def test_current_utc_day_thresholds_override_stale_healthy_metadata(days, status):
    now = datetime(2026, 10, 3, 22, tzinfo=UTC)
    row = certificates.row_view({**UPLOADED, "not_after": (
        now + timedelta(days=days, minutes=1)).isoformat(), "days_until_expiry": 999}, now)
    assert row["days"] == days
    assert row["status"] == status


@pytest.mark.parametrize("expiry", ["2099-01-01", "2099-01-01T00:00:00",
                                   "2099-02-30T00:00:00Z", True, 100])
def test_incomplete_or_impossible_dates_are_unknown(expiry):
    row = certificates.row_view({**UPLOADED, "not_after": expiry}, datetime.now(UTC))
    assert row["status"] == "unknown"
    assert row["days"] is None


@pytest.mark.parametrize("declared", [None, b"1"])
def test_actual_stream_size_is_bounded_independently_of_content_length(monkeypatch, declared):
    async def exercise():
        chunks = iter([b"x" * (48 * 1024), b"x" * (48 * 1024), b"x"])

        async def receive():
            return {"type": "http.request", "body": next(chunks), "more_body": True}

        request_headers = [(b"host", b"testserver"), (b"origin", ORIGIN.encode()),
                           (b"content-type", b"multipart/form-data; boundary=test")]
        if declared is not None:
            request_headers.append((b"content-length", declared))
        request = Request({"type": "http", "method": "POST", "path": ROUTES[0],
                           "headers": request_headers}, receive)
        form, response = await main._guarded_certificate_form(request)
        assert form is None
        assert response == 413
        assert not hasattr(request, "_body")

    # Inspect the guard directly so HTTP client framing cannot normalise the
    # deliberately incorrect Content-Length before the app sees it.
    monkeypatch.setattr(main, "_certificate_refusal", lambda request, status, message: status)
    asyncio.run(exercise())
