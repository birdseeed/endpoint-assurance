"""Unit tests for CF Access JWT verification (auth.py). Fail closed."""

import base64

import pytest

import auth
from tests.conftest import ROGUE_KID, TEAM_DOMAIN


def test_valid_token_returns_claims(make_token):
    claims = auth.verify_token(make_token())
    assert claims["email"] == "alice@tenant-a.example"


def test_empty_token_rejected():
    with pytest.raises(auth.AuthError):
        auth.verify_token("")


def test_garbage_token_rejected():
    with pytest.raises(auth.AuthError):
        auth.verify_token("not-a-jwt-at-all")


def test_wrong_audience_rejected(make_token):
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_token(aud="some-other-application-aud"))


def test_wrong_issuer_rejected(make_token):
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_token(iss="https://evil.cloudflareaccess.com"))


def test_expired_token_rejected(make_token):
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_token(exp_delta=-120))


def test_token_signed_by_unknown_key_rejected(make_token):
    # Right claims, wrong private key and kid not in the team JWKS.
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_token(key="rogue", kid=ROGUE_KID))


def test_forged_signature_with_known_kid_rejected(make_token):
    # kid matches a real JWKS entry but the signature comes from another key.
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_token(key="rogue"))


def test_token_without_email_rejected(make_token):
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_token(drop_email=True))


def test_missing_team_domain_is_config_error(monkeypatch, make_token):
    token = make_token()
    monkeypatch.delenv("PORTAL_ACCESS_TEAM_DOMAIN")
    with pytest.raises(auth.ConfigError):
        auth.verify_token(token)


def test_missing_aud_is_config_error(monkeypatch, make_token):
    token = make_token()
    monkeypatch.delenv("PORTAL_ACCESS_AUD")
    with pytest.raises(auth.ConfigError):
        auth.verify_token(token)


def test_team_domain_scheme_is_normalised(monkeypatch):
    monkeypatch.setenv("PORTAL_ACCESS_TEAM_DOMAIN", f"https://{TEAM_DOMAIN}/")
    assert auth.issuer() == f"https://{TEAM_DOMAIN}"
    assert auth.certs_url() == f"https://{TEAM_DOMAIN}/cdn-cgi/access/certs"


def test_jwks_fetch_failure_fails_closed(monkeypatch, make_token):
    def boom():
        raise RuntimeError("network down")

    monkeypatch.setattr(auth, "_fetch_jwks", boom)
    auth.reset_jwks_cache()
    with pytest.raises(auth.AuthError):
        auth.verify_token(make_token())


# ── fetch_login_method (PAT-127, display-only best-effort) ────────────────
#
# This is never on the auth-decision path - failures must degrade to None,
# never raise, so a get-identity outage can never take the portal down.


class _FakeResponse:
    def __init__(self, payload=None, status=200, raise_exc=None):
        self._payload = payload or {}
        self.status_code = status
        self._raise_exc = raise_exc

    def raise_for_status(self):
        if self._raise_exc:
            raise self._raise_exc
        if self.status_code >= 400:
            raise RuntimeError(f"status {self.status_code}")

    def json(self):
        return self._payload


def test_fetch_login_method_empty_token_returns_none():
    assert auth.fetch_login_method("") is None


def test_fetch_login_method_known_idp_maps_to_display_name(monkeypatch):
    monkeypatch.setattr(
        auth.requests, "get",
        lambda *a, **k: _FakeResponse({"idp": {"type": "azureAD", "id": "abc"}}),
    )
    assert auth.fetch_login_method("some-token") == "Microsoft"


def test_fetch_login_method_unknown_idp_returns_raw_type(monkeypatch):
    monkeypatch.setattr(
        auth.requests, "get",
        lambda *a, **k: _FakeResponse({"idp": {"type": "okta-saml"}}),
    )
    assert auth.fetch_login_method("some-token") == "okta-saml"


def test_fetch_login_method_missing_idp_returns_none(monkeypatch):
    monkeypatch.setattr(auth.requests, "get", lambda *a, **k: _FakeResponse({}))
    assert auth.fetch_login_method("some-token") is None


class _RawJSONResponse(_FakeResponse):
    """Like _FakeResponse, but .json() returns exactly what's given - including
    non-dict shapes (list/string/None) - unlike _FakeResponse's `payload or {}`,
    which would mask an empty-but-wrong-shape body."""

    def __init__(self, raw):
        super().__init__()
        self._raw = raw

    def json(self):
        return self._raw


def test_fetch_login_method_non_dict_json_body_returns_none(monkeypatch):
    # A non-object JSON response (list, string, or bare null) must degrade to
    # None, not raise - get-identity is not guaranteed to be a JSON object on
    # every error path a proxy/edge in front of it might introduce.
    for bad_body in (["unexpected", "shape"], "oops", None):
        monkeypatch.setattr(
            auth.requests, "get",
            lambda *a, body=bad_body, **k: _RawJSONResponse(body),
        )
        assert auth.fetch_login_method("some-token") is None


def test_fetch_login_method_non_string_idp_type_returns_none(monkeypatch):
    monkeypatch.setattr(
        auth.requests, "get",
        lambda *a, **k: _FakeResponse({"idp": {"type": 123}}),
    )
    assert auth.fetch_login_method("some-token") is None


def test_fetch_login_method_network_error_returns_none(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("network down")

    monkeypatch.setattr(auth.requests, "get", boom)
    assert auth.fetch_login_method("some-token") is None


def test_fetch_login_method_http_error_returns_none(monkeypatch):
    monkeypatch.setattr(
        auth.requests, "get", lambda *a, **k: _FakeResponse(status=500)
    )
    assert auth.fetch_login_method("some-token") is None


def test_fetch_login_method_malformed_json_returns_none(monkeypatch):
    class _BadJSON(_FakeResponse):
        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr(auth.requests, "get", lambda *a, **k: _BadJSON())
    assert auth.fetch_login_method("some-token") is None


@pytest.mark.parametrize("length", [auth.MAX_TOKEN_BYTES + 1, auth.MAX_TOKEN_BYTES * 2])
def test_oversized_token_rejected_before_parsing(monkeypatch, length):
    def must_not_parse(*args, **kwargs):
        pytest.fail("oversized token reached JWT parser")
    monkeypatch.setattr(auth.pyjwt, "get_unverified_header", must_not_parse)
    with pytest.raises(auth.AuthError, match="oversized"):
        auth.verify_token("a" * length)


def test_deep_header_rejected_without_key_fetch(monkeypatch):
    header = (b'{"alg":"RS256","kid":"portal-test-key-1","nested":'
              + b'[' * 1200 + b'0' + b']' * 1199 + b'}')
    token = base64.urlsafe_b64encode(header).rstrip(b'=').decode() + '.e30.AA'
    assert len(token) < auth.MAX_TOKEN_BYTES
    monkeypatch.setattr(
        auth, "_load_keys", lambda *a, **k: pytest.fail("malformed token fetched keys")
    )
    with pytest.raises(auth.AuthError, match="malformed"):
        auth.verify_token(token)


def test_recursive_header_parser_error_is_auth_error(monkeypatch):
    def recursive(*args, **kwargs):
        raise RecursionError("nested JSON")
    monkeypatch.setattr(auth.pyjwt, "get_unverified_header", recursive)
    with pytest.raises(auth.AuthError, match="malformed"):
        auth.verify_token('e30.e30.AA')


def test_unsigned_token_cannot_bypass_signature(make_token):
    token = make_token()
    with pytest.raises(auth.AuthError):
        auth.verify_token('.'.join(token.split('.')[:2]) + '.')


@pytest.mark.parametrize("kid", [[], {}, 123])
def test_non_string_key_id_is_auth_error(monkeypatch, kid):
    monkeypatch.setattr(auth.pyjwt, "get_unverified_header", lambda _: {"kid": kid})
    with pytest.raises(auth.AuthError, match="kid"):
        auth.verify_token('e30.e30.AA')


@pytest.mark.parametrize("token", ["é.e30.AA", "\ud800.e30.AA", b'e30.e30.AA'])
def test_non_ascii_or_non_string_token_is_auth_error(token):
    with pytest.raises(auth.AuthError):
        auth.verify_token(token)


@pytest.mark.parametrize("header", ['null', '[]', '"scalar"', '42'])
def test_non_object_header_is_auth_error(header):
    encoded = base64.urlsafe_b64encode(header.encode()).rstrip(b'=').decode()
    with pytest.raises(auth.AuthError):
        auth.verify_token(encoded + '.e30.AA')
