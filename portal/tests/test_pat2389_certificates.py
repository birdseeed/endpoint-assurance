"""PAT-2389: public certificate tracking is a guarded stateless proxy.

The local transport below refuses unrecognised platform paths. No test can
send certificate bytes, assertions or mutations to a real platform.
"""

import base64
import json
import re
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode, urlsplit

import pytest
import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import main

CERT_ID = "6d75459e-1111-4111-8111-111111111111"
API = "/v1/portal/certificates"
ORIGIN = "https://testserver"
ROUTES = ["/certificates/upload", f"/certificates/{CERT_ID}/update",
          f"/certificates/{CERT_ID}/delete"]
UPLOADED = {
    "id": CERT_ID, "source": "uploaded", "label": "Public VPN certificate",
    "subject_cn": "vpn.example.test", "issuer_cn": "Public test issuer",
    "fingerprint_sha256": "a" * 64, "sha1": "b" * 40,
    "not_before": "2026-07-01T00:00:00Z", "not_after": "2099-07-01T00:00:00Z",
    "ext_key_usage": [], "basic_constraints_ca": False, "is_self_signed": False,
    "days_until_expiry": 26000, "status": "healthy",
}
AGENT = {
    "source": "agent", "device_id": "6d75459e-2222-4222-8222-222222222222",
    "subject_cn": "Endpoint certificate",
    "issuer_cn": "Endpoint issuer", "sha1": "c" * 40,
    "not_after": "2099-01-01T00:00:00Z", "collected_at": "2026-10-01T00:00:00Z",
    "days_until_expiry_at_collection": 26000, "days_until_expiry": 26000,
    "status": "healthy", "ext_key_usage": [], "basic_constraints_ca": False,
    "is_self_signed": False,
}


@pytest.fixture(scope="module")
def public_certificates():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vpn.example.test")])
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=90)).sign(key, hashes.SHA256()))
    return {"pem": cert.public_bytes(serialization.Encoding.PEM),
            "der": cert.public_bytes(serialization.Encoding.DER)}


@pytest.fixture
def platform(client, monkeypatch):
    state = {"role": "admin", "rows": [dict(UPLOADED), dict(AGENT)],
             "calls": [], "status": {}, "envelope": True}

    def request(method, url, **kwargs):
        path = urlsplit(url).path
        state["calls"].append((method, path, kwargs))
        if path == "/v1/portal/me" and method == "GET":
            body = {"role": state["role"]}
        elif path == API and method == "GET":
            body = {"certificates": state["rows"]} if state["envelope"] else state["rows"]
        elif path == API and method == "POST":
            body = dict(UPLOADED)
        elif path == f"{API}/{CERT_ID}" and method in ("PATCH", "DELETE"):
            body = dict(UPLOADED)
        # These optional base-template discoveries must remain local too.
        elif path == "/v1/portal/feedback" and method == "GET":
            body = {"enabled": False}
        elif path == "/v1/portal/entitlement" and method == "GET":
            body = {}
        else:
            raise AssertionError(f"Unexpected upstream call: {method} {path}")
        response = requests.Response()
        response.status_code = state["status"].get((method, path),
            404 if path == "/v1/portal/feedback" else
            201 if method == "POST" else 204 if method == "DELETE" else 200)
        if response.status_code >= 400:
            body = {"error": "certificate_test_error", "message": "INTERNAL_PROVIDER_SECRET"}
        response._content = (b"" if response.status_code == 204
                             else json.dumps(body).encode())
        response.headers["Content-Type"] = "application/json"
        return response

    monkeypatch.setattr(main.upstream._session, "request", request)
    return state


def headers(token, **extra):
    return {"Cf-Access-Jwt-Assertion": token, **extra}


def get_page(client, token):
    return client.get("/certificates", headers=headers(token))


def mutate(client, token, path, *, certificate=None, label="Public VPN certificate",
           csrf=True, origin=ORIGIN, fields=None):
    data = {"label": label, **(fields or {})}
    if csrf is True:
        data["csrf_token"] = main._csrf_token(token)
    elif isinstance(csrf, str):
        data["csrf_token"] = csrf
    request_headers = headers(token)
    if origin is not None:
        request_headers["Origin"] = origin
    if certificate is not None:
        return client.post(path, data=data, files={"certificate": (
            "public.cer", certificate, "application/octet-stream")},
            headers=request_headers, follow_redirects=False)
    request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    return client.post(path, content=urlencode(data), headers=request_headers,
                       follow_redirects=False)


def writes(platform):
    return [call for call in platform["calls"] if call[0] != "GET"]


@pytest.mark.parametrize("envelope", [True, False])
@pytest.mark.parametrize("role", ["admin", "viewer"])
def test_every_viewer_has_certificate_navigation_and_distinct_sources(
    client, make_token, platform, envelope, role
):
    platform.update(role=role, envelope=envelope)
    token = make_token()
    response = get_page(client, token)
    assert response.status_code == 200
    nav = re.search(r'<nav class="rail__nav"[^>]*>(.*?)</nav>', response.text, re.S).group(1)
    assert 'href="/certificates"' in nav
    assert "Public VPN certificate" in response.text
    assert "Uploaded" in response.text
    assert "Agent" in response.text
    assert "Endpoint certificate" in response.text
    assert AGENT["device_id"] in response.text
    if role == "viewer":
        assert not re.search(r'<form[^>]*action="/certificates', response.text)
    else:
        assert "Public certificate only" in response.text
        assert "Private keys are not accepted" in response.text
        assert f'/certificates/{CERT_ID}/update' in response.text
        assert f'/certificates/{CERT_ID}/delete' in response.text
    assert not writes(platform)
    certificate_reads = [call for call in platform["calls"] if call[1] == API]
    assert len(certificate_reads) == 1
    assert certificate_reads[0][2]["headers"][main.upstream.JWT_HEADER] == token
    assert certificate_reads[0][2].get("params") in (None, {})


def test_certificate_page_requires_authentication(client, platform):
    assert client.get("/certificates").status_code in (401, 403)
    assert platform["calls"] == []


@pytest.mark.parametrize("missing_date", [None, "", "not-a-date", "absent"])
def test_missing_or_invalid_expiry_never_renders_healthy(
    client, make_token, platform, missing_date
):
    platform["rows"] = [{**UPLOADED, "not_after": missing_date,
                         "status": "healthy", "days_until_expiry": 26000}]
    if missing_date == "absent":
        platform["rows"][0].pop("not_after")
    response = get_page(client, make_token())
    assert response.status_code == 200
    assert "unknown" in response.text.lower()
    assert not re.search(r">\s*Healthy\s*<", response.text, re.I)


@pytest.mark.parametrize("status,days", [("expired", -1), ("critical", 7),
                                        ("warning", 25), ("healthy", 90)])
def test_expiry_status_and_days_are_visible(client, make_token, platform, status, days):
    # Give the integer-day calculation room for request elapsed time.
    offset = timedelta(days=days, hours=1 if days >= 0 else -1)
    expiry = (datetime.now(UTC) + offset).isoformat()
    platform["rows"] = [{**UPLOADED, "status": status, "days_until_expiry": days,
                         "not_after": expiry}]
    response = get_page(client, make_token())
    assert response.status_code == 200
    assert status in response.text.lower()
    assert str(days) in response.text


def test_failed_list_is_unavailable_not_empty(client, make_token, platform):
    platform["status"][("GET", API)] = 500
    response = get_page(client, make_token())
    assert response.status_code in (200, 502, 503)
    assert "unavailable" in response.text.lower()
    assert "no certificates" not in response.text.lower()
    assert "INTERNAL_PROVIDER_SECRET" not in response.text


@pytest.mark.parametrize("path", ROUTES)
def test_role_is_refreshed_after_admin_page_before_mutation(
    client, make_token, platform, public_certificates, path
):
    token = make_token()
    assert get_page(client, token).status_code == 200
    platform["role"] = "viewer"
    response = mutate(client, token, path, certificate=(
        public_certificates["pem"] if path.endswith("upload") else None))
    assert response.status_code == 403
    assert not writes(platform)
    assert sum(call[1] == "/v1/portal/me" for call in platform["calls"]) >= 2


@pytest.mark.parametrize("path", ROUTES)
@pytest.mark.parametrize("csrf,origin", [(False, ORIGIN), ("wrong", ORIGIN),
                                        (True, "https://evil.example"), (True, None)])
def test_all_mutations_guard_origin_and_csrf_before_upstream(
    client, make_token, platform, public_certificates, path, csrf, origin
):
    response = mutate(client, make_token(), path, csrf=csrf, origin=origin,
                      certificate=public_certificates["pem"] if path.endswith("upload") else None)
    assert response.status_code == 403
    assert not writes(platform)


@pytest.mark.parametrize("encoding", ["pem", "der"])
@pytest.mark.parametrize("platform_status", [201, 200])
def test_public_upload_forwards_exact_bytes_and_jwt_without_client_identity(
    client, make_token, platform, public_certificates, encoding, platform_status
):
    token = make_token()
    platform["status"][("POST", API)] = platform_status
    response = mutate(client, token, ROUTES[0], certificate=public_certificates[encoding],
                      fields={"tenant_id": "foreign-tenant", "actor_email": "forged@example.test"})
    assert response.status_code == 303
    assert response.headers["location"].split("?")[0] == "/certificates"
    assert len(writes(platform)) == 1
    method, path, kwargs = writes(platform)[0]
    assert (method, path) == ("POST", API)
    assert kwargs["headers"][main.upstream.JWT_HEADER] == token
    assert kwargs["json"] == {"label": "Public VPN certificate",
                              "certificate": base64.b64encode(
                                  public_certificates[encoding]).decode("ascii")}
    assert kwargs.get("params") in (None, {})


@pytest.mark.parametrize("content", [
    b"-----BEGIN PRIVATE KEY-----\nPRIVATE_TEST_SENTINEL\n-----END PRIVATE KEY-----",
    b"-----BEGIN RSA PRIVATE KEY-----\nPRIVATE_TEST_SENTINEL\n-----END RSA PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----\nPRIVATE_TEST_SENTINEL\n"
    b"-----END ENCRYPTED PRIVATE KEY-----",
    b"not an X.509 certificate", b"x" * (64 * 1024 + 1),
])
def test_invalid_key_and_oversized_uploads_never_reach_platform_or_logs(
    client, make_token, platform, caplog, content
):
    response = mutate(client, make_token(), ROUTES[0], certificate=content)
    assert response.status_code in (400, 413, 422)
    assert not writes(platform)
    assert "PRIVATE_TEST_SENTINEL" not in response.text + caplog.text


@pytest.mark.parametrize("label", ["", " ", "x" * 201])
def test_invalid_labels_are_refused_before_mutation(
    client, make_token, platform, public_certificates, label
):
    response = mutate(client, make_token(), ROUTES[0], certificate=public_certificates["pem"],
                      label=label)
    assert response.status_code in (400, 422)
    assert not writes(platform)


def test_public_certificate_with_appended_private_key_is_refused(
    client, make_token, platform, public_certificates, caplog
):
    content = public_certificates["pem"] + (
        b"-----BEGIN PRIVATE KEY-----\nPRIVATE_TEST_SENTINEL\n-----END PRIVATE KEY-----")
    response = mutate(client, make_token(), ROUTES[0], certificate=content)
    assert response.status_code in (400, 422)
    assert not writes(platform)
    assert "PRIVATE_TEST_SENTINEL" not in response.text + caplog.text


@pytest.mark.parametrize("path", ROUTES)
def test_unknown_role_cannot_mutate(client, make_token, platform, public_certificates, path):
    platform["role"] = "owner"
    response = mutate(client, make_token(), path, certificate=(
        public_certificates["pem"] if path.endswith("upload") else None))
    assert response.status_code == 403
    assert not writes(platform)


@pytest.mark.parametrize("path", ROUTES)
def test_malformed_urlencoded_body_cannot_mutate(client, make_token, platform, path):
    response = client.post(path, content=b"\xff\xfe", headers=headers(make_token(),
        Origin=ORIGIN, **{"Content-Type": "application/x-www-form-urlencoded"}),
        follow_redirects=False)
    assert response.status_code in (400, 403, 422)
    assert not writes(platform)


def test_total_multipart_request_is_bounded(client, make_token, platform, public_certificates):
    response = mutate(client, make_token(), ROUTES[0], certificate=public_certificates["pem"],
                      fields={"padding": "x" * (96 * 1024)})
    assert response.status_code == 413
    assert not writes(platform)


def test_malformed_multipart_is_refused_without_mutation(client, make_token, platform):
    response = client.post(ROUTES[0], content=b"not multipart", headers=headers(make_token(),
        Origin=ORIGIN, **{"Content-Type": "multipart/form-data; boundary=missing"}),
        follow_redirects=False)
    assert response.status_code in (400, 403, 422)
    assert not writes(platform)


@pytest.mark.parametrize("replacement", [False, True])
def test_update_uses_patch_with_label_and_optional_replacement_only(
    client, make_token, platform, public_certificates, replacement
):
    token = make_token()
    response = mutate(client, token, ROUTES[1], label="Renewed public VPN",
                      certificate=public_certificates["der"] if replacement else None)
    assert response.status_code == 303
    assert response.headers["location"].split("?")[0] == "/certificates"
    method, path, kwargs = writes(platform)[0]
    assert (method, path) == ("PATCH", f"{API}/{CERT_ID}")
    expected = {"label": "Renewed public VPN"}
    if replacement:
        expected["certificate"] = base64.b64encode(public_certificates["der"]).decode("ascii")
    assert kwargs["json"] == expected
    assert kwargs["headers"][main.upstream.JWT_HEADER] == token


def test_delete_proxies_no_body_and_redirects(client, make_token, platform):
    token = make_token()
    response = mutate(client, token, ROUTES[2], fields={"tenant_id": "foreign"})
    assert response.status_code == 303
    assert response.headers["location"].split("?")[0] == "/certificates"
    method, path, kwargs = writes(platform)[0]
    assert (method, path) == ("DELETE", f"{API}/{CERT_ID}")
    assert kwargs.get("json") is None
    assert kwargs.get("params") in (None, {})
    assert kwargs["headers"][main.upstream.JWT_HEADER] == token


@pytest.mark.parametrize("operation,method", [("upload", "POST"), ("update", "PATCH"),
                                            ("delete", "DELETE")])
@pytest.mark.parametrize("status", [400, 403, 404, 429, 500])
def test_provider_operation_errors_are_safe_and_leave_retry_navigation(
    client, make_token, platform, public_certificates, operation, method, status
):
    path = ROUTES[["upload", "update", "delete"].index(operation)]
    platform["status"][(method, API if operation == "upload" else f"{API}/{CERT_ID}")] = status
    response = mutate(client, make_token(), path, certificate=(
        public_certificates["pem"] if operation == "upload" else None))
    assert response.status_code in (200, 400, 403, 404, 429, 502, 503)
    assert "INTERNAL_PROVIDER_SECRET" not in response.text
    assert "certificate_test_error" not in response.text
    assert 'href="/certificates"' in response.text
    assert len(writes(platform)) == 1


def test_agent_records_offer_no_edit_or_delete_form(client, make_token, platform):
    platform["rows"] = [dict(AGENT)]
    response = get_page(client, make_token())
    assert response.status_code == 200
    assert "Endpoint certificate" in response.text
    assert not re.search(r'<form[^>]*action="/certificates/[^"/]+/(update|delete)"', response.text)
    assert f'{AGENT["device_id"]}/update' not in response.text
    assert f'{AGENT["device_id"]}/delete' not in response.text


def test_uploaded_records_do_not_invent_device_provenance(client, make_token, platform):
    platform["rows"] = [dict(UPLOADED)]
    response = get_page(client, make_token())
    assert response.status_code == 200
    assert "Public VPN certificate" in response.text
    assert "Uploaded" in response.text
    assert not re.search(r'href="/devices/[^"?]+"', response.text)


def test_private_key_replacement_is_refused_without_patch(client, make_token, platform, caplog):
    response = mutate(client, make_token(), ROUTES[1], certificate=(
        b"-----BEGIN PRIVATE KEY-----\nPRIVATE_TEST_SENTINEL\n-----END PRIVATE KEY-----"))
    assert response.status_code in (400, 422)
    assert not writes(platform)
    assert "PRIVATE_TEST_SENTINEL" not in response.text + caplog.text
