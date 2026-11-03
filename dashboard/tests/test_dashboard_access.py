"""Origin authentication regressions; all Access keys and responses are local fixtures."""
import base64
import hashlib
import hmac
import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ.setdefault('DASHBOARD_API_KEY', 'test-key')
import main as dashboard


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard, "DB_PATH", tmp_path / "access-test.db")
    monkeypatch.setattr(dashboard, '_DEV_ENV', False)
    monkeypatch.setattr(dashboard, 'DASHBOARD_API_KEY', 'test-key')
    with TestClient(dashboard.app) as value:
        yield value


@pytest.mark.parametrize('path', ['/', '/console', '/console/stale', f'/console/{dashboard.CONSOLE_BUILD_ID}'])
def test_raw_email_cannot_mint_session(client, path):
    response = client.get(path, headers={'Cf-Access-Authenticated-User-Email': 'owner@patched.im'})
    assert response.status_code == 200
    assert dashboard.SESSION_COOKIE not in response.headers.get('set-cookie', '')


def test_legacy_session_cookie_rejected():
    b = base64.urlsafe_b64encode(f'owner@patched.im|{int(time.time()) + 600}'.encode()).decode().rstrip('=')
    mac = hmac.new(b'test-key', b.encode(), hashlib.sha256).hexdigest()
    assert dashboard._session_decode(f'{b}.{mac}') is None


@pytest.mark.parametrize('path', ['/admin/tenants/example/impersonation/start', '/admin/impersonation/end'])
def test_navigation_requires_auth_before_effects(client, monkeypatch, path):
    def forbidden(*args, **kwargs):
        pytest.fail('unauthenticated navigation reached database/audit')
    monkeypatch.setattr(dashboard, 'get_db', forbidden)
    monkeypatch.setattr(dashboard, '_imp_log', forbidden)
    response = client.get(path, headers={'Cf-Access-Authenticated-User-Email': 'owner@patched.im'}, follow_redirects=False)
    assert response.status_code == 401
    assert 'set-cookie' not in response.headers


@pytest.fixture
def access(monkeypatch):
    import json
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    import dashboard_access
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk['kid'] = 'local-key'
    monkeypatch.setenv('DASHBOARD_ACCESS_TEAM_DOMAIN', 'test-team.cloudflareaccess.com')
    monkeypatch.setenv('DASHBOARD_ACCESS_AUD', 'dashboard-audience')
    calls = []
    def fetch(issuer):
        calls.append(issuer)
        return {'keys': [jwk]}
    monkeypatch.setattr(dashboard_access, '_fetch_jwks', fetch)
    dashboard_access.reset_jwks_cache()
    def token(**changes):
        claims = {'email': 'verified@example.invalid', 'sub': 'human-id',
                  'iss': 'https://test-team.cloudflareaccess.com',
                  'aud': 'dashboard-audience', 'iat': int(time.time()) - 1,
                  'exp': int(time.time()) + 600}
        claims.update(changes)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key, algorithm='RS256', headers={'kid': 'local-key'})
    yield token, calls
    dashboard_access.reset_jwks_cache()


@pytest.mark.parametrize('change', [
    {'iss': 'https://other.cloudflareaccess.com'}, {'aud': 'portal-audience'},
    {'exp': 1}, {'exp': None}, {'iat': None}, {'sub': None}, {'email': None},
    {'email': ['owner@example.invalid']}, {'email': ' bad@example.invalid'},
    {'email': 'owner@example.invalid|123'}, {'iat': '1'}, {'exp': '9999999999'},
    {'sub': ['human']}, {'iat': True}, {'email': {'email': 'owner@example.invalid'}},
])
def test_invalid_claims_rejected(access, change):
    import dashboard_access
    token, _ = access
    with pytest.raises(dashboard_access.AuthError):
        dashboard_access.verify_token(token(**change))


@pytest.mark.parametrize('setting,value', [
    ('DASHBOARD_ACCESS_AUD', ''), ('DASHBOARD_ACCESS_TEAM_DOMAIN', ''),
    ('DASHBOARD_ACCESS_TEAM_DOMAIN', 'http://test-team.cloudflareaccess.com'),
    ('DASHBOARD_ACCESS_TEAM_DOMAIN', 'https://evil.invalid'),
    ('DASHBOARD_ACCESS_TEAM_DOMAIN', 'https://test-team.cloudflareaccess.com@evil.invalid'),
    ('DASHBOARD_ACCESS_TEAM_DOMAIN', 'https://test-team.cloudflareaccess.com/path'),
    ('DASHBOARD_ACCESS_TEAM_DOMAIN', 'https://test-team.cloudflareaccess.com:443'),
])
def test_configuration_fails_closed_before_network(access, monkeypatch, setting, value):
    import dashboard_access
    token, calls = access
    monkeypatch.setenv(setting, value)
    with pytest.raises(dashboard_access.AuthError):
        dashboard_access.verify_token(token())
    assert not calls


@pytest.mark.parametrize('path', ['/', '/console', '/console/stale', f'/console/{dashboard.CONSOLE_BUILD_ID}'])
@pytest.mark.parametrize('transport', ['header', 'cookie'])
def test_verified_identity_mints_cookie_and_ignores_raw_email(client, access, path, transport):
    token, calls = access
    headers = {'Cf-Access-Authenticated-User-Email': 'forged@example.invalid'}
    if transport == 'header':
        headers['Cf-Access-Jwt-Assertion'] = token()
    else:
        client.cookies.set('CF_Authorization', token())
    response = client.get(path, headers=headers)
    assert response.status_code == 200
    cookie = response.cookies[dashboard.SESSION_COOKIE]
    assert dashboard._session_decode(cookie) == 'verified@example.invalid'
    assert len(calls) == 1


def test_forged_signature_rejected(access):
    import jwt
    import dashboard_access
    from cryptography.hazmat.primitives.asymmetric import rsa
    token, _ = access
    claims = jwt.decode(token(), options={'verify_signature': False})
    forged = jwt.encode(claims, rsa.generate_private_key(public_exponent=65537, key_size=2048),
                        algorithm='RS256', headers={'kid': 'local-key'})
    with pytest.raises(dashboard_access.AuthError):
        dashboard_access.verify_token(forged)


def test_duplicate_claims_rejected_before_jwks_fetch(access):
    import jwt
    import dashboard_access
    # Duplicate keys are rejected before consulting JWKS; no signature matters.
    token, calls = access
    parts = token().split('.')
    payload = b'{"email":"one@example.invalid","email":"two@example.invalid"}'
    parts[1] = base64.urlsafe_b64encode(payload).decode().rstrip('=')
    with pytest.raises(dashboard_access.AuthError):
        dashboard_access.verify_token('.'.join(parts))
    assert calls == []


def test_unknown_key_and_fetch_failure_cooldown(access, monkeypatch):
    import jwt
    import dashboard_access
    token, calls = access
    valid = token()
    dashboard_access.verify_token(valid)
    parts = valid.split('.')
    parts[0] = base64.urlsafe_b64encode(b'{"alg":"RS256","kid":"unknown"}').decode().rstrip('=')
    for _ in range(5):
        with pytest.raises(dashboard_access.AuthError):
            dashboard_access.verify_token('.'.join(parts))
    assert len(calls) == 1
    dashboard_access.reset_jwks_cache()
    def fail(issuer):
        calls.append(issuer)
        raise RuntimeError('offline')
    monkeypatch.setattr(dashboard_access, '_fetch_jwks', fail)
    for _ in range(5):
        with pytest.raises(dashboard_access.AuthError):
            dashboard_access.verify_token(valid)
    assert len(calls) == 2


def test_identity_resolved_once_per_request(access, monkeypatch):
    from starlette.requests import Request
    import dashboard_access
    token, _ = access
    request = Request({'type': 'http', 'headers': [(b'cf-access-jwt-assertion', token().encode())]})
    original = dashboard_access.verify_token
    count = []
    def verify(value):
        count.append(value)
        return original(value)
    monkeypatch.setattr(dashboard_access, 'verify_token', verify)
    assert dashboard._cf_email(request) == dashboard._cf_email(request) == 'verified@example.invalid'
    assert len(count) == 1


@pytest.mark.parametrize('path', ['/api/scan/example/download',
    '/admin/tenants/56a0c11e-f3a4-5828-bd81-8a0701466473/report-records/example/download', '/certs'])
@pytest.mark.parametrize('auth', ['raw', 'jwt', 'bearer'])
def test_protected_downloads_and_certs_stay_session_only(client, access, path, auth):
    token, _ = access
    headers = {'raw': {'Cf-Access-Authenticated-User-Email': 'owner@example.invalid'},
               'jwt': {'Cf-Access-Jwt-Assertion': token()},
               'bearer': {'Authorization': 'Bearer test-key'}}[auth]
    response = client.get(path, headers=headers)
    assert response.status_code == 401


@pytest.mark.parametrize('auth', ['session', 'jwt', 'bearer'])
def test_authenticated_navigation_allowed(client, access, auth):
    token, _ = access
    headers = {'session': {'Cookie': f'{dashboard.SESSION_COOKIE}={dashboard._session_encode("valid@example.invalid", int(time.time())+600)}'},
               'jwt': {'Cf-Access-Jwt-Assertion': token()},
               'bearer': {'Authorization': 'Bearer test-key'}}[auth]
    response = client.get('/admin/impersonation/end', headers=headers, follow_redirects=False)
    assert response.status_code == 302


def test_actor_prefers_authenticated_state_over_raw_headers(access):
    from starlette.requests import Request
    request = Request({'type': 'http', 'headers': [(b'cf-access-authenticated-user-email', b'forged@example.invalid')]})
    request.state.actor_email = 'bearer-token'
    assert dashboard._mirror_actor_email(request) == 'bearer-token'


@pytest.mark.parametrize('bad', ['not-a-token', 'missing-exp', 'wrong-aud', 'wrong-issuer'])
def test_rejected_token_never_mints_cookie(client, access, bad):
    token, _ = access
    value = {'not-a-token': 'garbage', 'missing-exp': token(exp=None),
             'wrong-aud': token(aud='wrong'), 'wrong-issuer': token(iss='https://evil.invalid')}[bad]
    response = client.get('/console', headers={'Cf-Access-Jwt-Assertion': value,
                          'Cf-Access-Authenticated-User-Email': 'owner@example.invalid'})
    assert dashboard.SESSION_COOKIE not in response.headers.get('set-cookie', '')


def test_cache_expiry_does_not_use_stale_keys(access, monkeypatch):
    import dashboard_access
    token, calls = access
    value = token()
    dashboard_access.verify_token(value)
    monkeypatch.setattr(dashboard_access.time, 'monotonic', lambda: dashboard_access._fetched_at + 3601)
    def fail(issuer):
        raise RuntimeError('offline')
    monkeypatch.setattr(dashboard_access, '_fetch_jwks', fail)
    with pytest.raises(dashboard_access.AuthError):
        dashboard_access.verify_token(value)


@pytest.mark.parametrize('headers', [[(b'cf-access-jwt-assertion', b'one'), (b'cf-access-jwt-assertion', b'two')],
                                  [(b'cf-access-jwt-assertion', b'')]])
def test_ambiguous_or_empty_assertion_cannot_fall_back_to_cookie(access, headers):
    from starlette.requests import Request
    token, _ = access
    headers = headers + [(b'cookie', ('CF_Authorization=' + token()).encode())]
    assert dashboard._cf_email(Request({'type': 'http', 'headers': headers})) is None


@pytest.mark.parametrize('auth', ['session', 'jwt', 'bearer'])
def test_impersonation_start_uses_authenticated_actor(client, access, monkeypatch, auth):
    from contextlib import contextmanager
    token, _ = access
    @contextmanager
    def database():
        class DB:
            def execute(self, *args):
                return self
            def fetchone(self):
                return {'billing_tier': 'full', 'support_access_opt_out': False, 'company': 'Fixture'}
        yield DB()
    logged = []
    monkeypatch.setattr(dashboard, 'get_db', database)
    monkeypatch.setattr(dashboard, '_imp_log', lambda *args: logged.append(args))
    expected = {'session': 'valid@example.invalid', 'jwt': 'verified@example.invalid', 'bearer': 'bearer-token'}[auth]
    headers = {'session': {'Cookie': f'{dashboard.SESSION_COOKIE}={dashboard._session_encode(expected, int(time.time())+600)}'},
               'jwt': {'Cf-Access-Jwt-Assertion': token()},
               'bearer': {'Authorization': 'Bearer test-key'}}[auth]
    headers['Cf-Access-Authenticated-User-Email'] = 'forged@example.invalid'
    response = client.get('/admin/tenants/56a0c11e-f3a4-5828-bd81-8a0701466473/impersonation/start',
                          headers=headers, follow_redirects=False)
    assert response.status_code == 302
    assert logged[0][2] == expected
    assert dashboard.IMP_COOKIE in response.cookies
