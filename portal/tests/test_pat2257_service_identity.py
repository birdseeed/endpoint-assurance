"""PAT-2257: the read-only service identity for the authenticated prod walk.

A Cloudflare Access service token's JWT carries `common_name` (the token's
client id) and no `email`. The portal accepts one ONLY when:

  * it passes exactly the same signature / audience / issuer / expiry
    checks as a person's token (auth.verify_token, unchanged), and
  * its common_name equals PORTAL_SERVICE_TOKEN_COMMON_NAME (unset by
    default, so the feature is off unless the box configures it).

The identity it maps to is read-only: the auth middleware refuses every
non-GET/HEAD request from it before any route runs, so no write route - the
ones that exist today, enumerated below from app.routes, or one added
later - can be reached by it. The platform owns the tenant (tenant zero,
from its own config); the portal never sends or infers one.
"""

import logging
import time
from urllib.parse import urlencode

import jwt as pyjwt
import pytest

import auth
import main
from tests.conftest import AUD, GOOD_KID, STUB_STATE, TEAM_DOMAIN

# Low-entropy placeholder, not the real client id.
SERVICE_CN = "walker-test.access"
ORIGIN = "https://testserver"
SAFE = {"GET", "HEAD"}


@pytest.fixture
def make_service_token(keypairs):
    def _make(common_name=SERVICE_CN, *, key="good", kid=GOOD_KID, aud=AUD,
              iss=f"https://{TEAM_DOMAIN}", exp_delta=600, email=None, alg="RS256"):
        now = int(time.time())
        claims = {
            "aud": [aud], "iss": iss, "iat": now - 30, "nbf": now - 30,
            "exp": now + exp_delta, "sub": "", "type": "app",
            "common_name": common_name, "identity_nonce": "n0nce",
        }
        if email is not None:
            claims["email"] = email
        if alg == "none":
            return pyjwt.encode(claims, None, algorithm="none", headers={"kid": kid})
        return pyjwt.encode(claims, keypairs[key], algorithm="RS256", headers={"kid": kid})
    return _make


@pytest.fixture
def service_on(monkeypatch):
    monkeypatch.setenv("PORTAL_SERVICE_TOKEN_COMMON_NAME", SERVICE_CN)


@pytest.fixture
def writes(monkeypatch):
    """Record every upstream write call; a refused request must make none."""
    calls = []
    for name in ("post_json", "put_json", "delete_json", "post_multipart"):
        def _rec(*args, _name=name, **kwargs):
            calls.append((_name, args[0] if args else None))
            raise AssertionError(f"upstream.{_name} reached for the service identity")
        monkeypatch.setattr(main.upstream, name, _rec)
    return calls


def _h(token):
    return {"Cf-Access-Jwt-Assertion": token}


# ── auth.verify_token ────────────────────────────────────────────────────

def test_allowlisted_service_token_verifies(service_on, make_service_token):
    claims = auth.verify_token(make_service_token())
    assert auth.service_common_name(claims) == SERVICE_CN


def test_service_token_refused_when_feature_unset(monkeypatch, make_service_token):
    monkeypatch.delenv("PORTAL_SERVICE_TOKEN_COMMON_NAME", raising=False)
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_service_token())


def test_service_token_refused_when_config_blank(monkeypatch, make_service_token):
    monkeypatch.setenv("PORTAL_SERVICE_TOKEN_COMMON_NAME", "   ")
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_service_token(common_name=""))
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_service_token())


@pytest.mark.parametrize("cn", ["other-token.access", "", SERVICE_CN + "x",
                                SERVICE_CN.upper(), " " + SERVICE_CN])
def test_non_allowlisted_common_name_refused(service_on, make_service_token, cn):
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_service_token(common_name=cn))


@pytest.mark.parametrize("kwargs", [
    {"key": "rogue"},                          # forged signature, known kid
    {"kid": "no-such-kid"},                    # unknown key
    {"aud": "some-other-app"},                 # wrong audience
    {"iss": "https://evil.cloudflareaccess.com"},
    {"exp_delta": -60},                        # expired
    {"alg": "none"},                           # unsigned
])
def test_forged_or_invalid_service_token_refused(service_on, make_service_token, kwargs):
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_service_token(**kwargs))


def test_person_token_is_never_a_service_identity(service_on, make_token):
    claims = auth.verify_token(make_token())
    assert auth.service_common_name(claims) is None


def test_email_claim_wins_over_common_name(service_on, make_service_token):
    """A token with an email is a person's token; the common_name path is only
    ever taken for an email-less token."""
    claims = auth.verify_token(make_service_token(email="alice@tenant-a.example"))
    assert auth.service_common_name(claims) is None


# ── Reads work, as a read-only identity ──────────────────────────────────

def test_service_identity_reads_the_overview(client, service_on, make_service_token):
    token = make_service_token()
    STUB_STATE["expected_jwt"] = token  # forwarded verbatim upstream
    resp = client.get("/", headers=_h(token))
    assert resp.status_code == 200, resp.text[:300]
    # The page never shows the common name (it is the token's client id).
    assert SERVICE_CN not in resp.text
    assert "Read-only service" in resp.text


@pytest.mark.parametrize("path", ["/devices", "/software", "/reports", "/support"])
def test_service_identity_reads_other_pages(client, service_on, make_service_token, path):
    token = make_service_token()
    resp = client.get(path, headers=_h(token))
    assert resp.status_code == 200, f"{path}: {resp.status_code} {resp.text[:200]}"
    assert SERVICE_CN not in resp.text


def test_service_identity_is_never_offered_write_controls(
        client, service_on, make_service_token):
    """Even if the platform said admin, the portal's own view of this identity
    is read-only, so no approve form renders for it."""
    STUB_STATE["portal_role"] = "admin"
    resp = client.get("/software", headers=_h(make_service_token()))
    assert resp.status_code == 200
    assert 'action="/software/approvals"' not in resp.text


def test_non_allowlisted_service_token_gets_401(client, service_on, make_service_token):
    resp = client.get("/", headers=_h(make_service_token(common_name="stranger.access")))
    assert resp.status_code == 401


def test_service_token_gets_401_when_feature_off(client, monkeypatch, make_service_token):
    monkeypatch.delenv("PORTAL_SERVICE_TOKEN_COMMON_NAME", raising=False)
    resp = client.get("/", headers=_h(make_service_token()))
    assert resp.status_code == 401


def test_forged_service_token_gets_401(client, service_on, make_service_token):
    resp = client.get("/", headers=_h(make_service_token(key="rogue")))
    assert resp.status_code == 401


def test_service_identity_sends_no_tenant_upstream(
        client, service_on, make_service_token, monkeypatch):
    """Tenant isolation, portal half: the portal forwards the JWT and nothing
    else identifying. A tenant in the query string reaches no platform call;
    the platform maps this identity to its configured tenant only."""
    seen = []
    real = main.upstream.get_json

    def spy(path, jwt_token, params=None):
        seen.append((path, jwt_token, dict(params or {})))
        return real(path, jwt_token, params=params)

    monkeypatch.setattr(main.upstream, "get_json", spy)
    token = make_service_token()
    resp = client.get("/?tenant_id=5c048e12-0000-4000-8000-000000000000&tenant=x",
                      headers={**_h(token), "X-Tenant-ID": "5c048e12"})
    assert resp.status_code == 200
    assert seen
    for _path, jwt_token, params in seen:
        assert jwt_token == token
        assert not {"tenant_id", "tenant"} & set(params)


# ── Every write is refused, centrally ────────────────────────────────────

def _unsafe_routes():
    out = []
    for route in main.app.routes:
        for method in sorted(set(getattr(route, "methods", None) or ()) - SAFE - {"OPTIONS"}):
            out.append((method, route.path))
    return out


def test_write_route_enumeration_is_not_empty():
    routes = set(_unsafe_routes())
    assert len(routes) >= 17, routes
    assert {("POST", "/software/approvals"), ("POST", "/devices/retirement"),
            ("POST", "/devices/device-list"), ("POST", "/feedback"),
            ("POST", "/ai-tooling/notifications"), ("POST", "/install/enrolment-keys"),
            ("POST", "/reports/schedule"), ("POST", "/devices/jamf/setup")} <= routes


@pytest.mark.parametrize("method,path", _unsafe_routes())
def test_every_write_route_refuses_the_service_identity(
        client, service_on, make_service_token, writes, method, path):
    """Same-origin, with a valid CSRF token for the session: everything a
    genuine write needs except a writable identity. Refused 403, and no
    platform write was attempted."""
    token = make_service_token()
    body = urlencode([("csrf_token", main._csrf_token(token)), ("state", "approved")])
    resp = client.request(
        method, path.replace("{", "").replace("}", ""), content=body,
        headers={**_h(token), "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False)
    assert resp.status_code == 403, f"{method} {path} answered {resp.status_code}"
    assert "read-only" in resp.text.lower()
    assert writes == []


def test_approve_post_is_refused_for_the_service_identity(
        client, service_on, make_service_token, writes, caplog):
    token = make_service_token()
    STUB_STATE["portal_role"] = "admin"
    fields = [("csrf_token", main._csrf_token(token)), ("state", "approved"),
              ("item", '{"type": "application", "platform": "macos", '
                       '"identifier": "com.example.mysteryapp", "name": "MysteryApp"}')]
    with caplog.at_level(logging.WARNING):
        resp = client.post(
            "/software/approvals", content=urlencode(fields),
            headers={**_h(token), "Origin": ORIGIN,
                     "Content-Type": "application/x-www-form-urlencoded"},
            follow_redirects=False)
    assert resp.status_code == 403
    assert writes == []
    lines = [r.getMessage() for r in caplog.records if "service_identity" in r.getMessage()]
    assert lines, "the refusal is logged against the service identity"
    assert all(f"common_name={SERVICE_CN}" in line for line in lines)
    assert all("@" not in line for line in lines)


def test_person_writes_are_unaffected(client, make_token, service_on):
    """The central guard only ever applies to the service identity: a person's
    same-origin, tokened write still reaches its route (the stub accepts it)."""
    token = make_token()
    STUB_STATE["expected_jwt"] = token
    resp = client.post(
        "/reports/generate",
        content=urlencode([("csrf_token", main._csrf_token(token)),
                           ("report_type", "patch-status")]),
        headers={**_h(token), "Origin": ORIGIN,
                 "Content-Type": "application/x-www-form-urlencoded"},
        follow_redirects=False)
    assert resp.status_code == 303
    assert STUB_STATE["generate_calls"] == 1


def test_head_is_allowed_for_the_service_identity(client, service_on, make_service_token):
    resp = client.head("/healthz")
    assert resp.status_code in (200, 405)
    resp = client.request("HEAD", "/", headers=_h(make_service_token()))
    assert resp.status_code != 403
