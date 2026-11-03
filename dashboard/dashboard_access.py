"""Verify dashboard human identities against its own Cloudflare Access app.

DASHBOARD_ACCESS_TEAM_DOMAIN is a Cloudflare team hostname (optional https://).
DASHBOARD_ACCESS_AUD is this dashboard Access application's audience. Neither
setting is inferred from a request. No portal tenant or service-token policy is
shared here. Missing configuration and unavailable signing keys fail closed.
"""
import base64
import json
import math
import os
import re
import threading
import time
from urllib.parse import urlsplit

import jwt
import requests

JWKS_TTL_SECONDS = 3600
JWKS_REFRESH_COOLDOWN_SECONDS = 60
MAX_TOKEN_BYTES = 16384
MAX_JWKS_BYTES = 262144
_lock = threading.Lock()
_keys = {}
_source = None
_fetched_at = 0.0
_attempted_at = None


class AuthError(Exception):
    """Missing or unverifiable dashboard Access identity."""


def _configuration():
    raw = os.environ.get('DASHBOARD_ACCESS_TEAM_DOMAIN', '').strip()
    aud = os.environ.get('DASHBOARD_ACCESS_AUD', '').strip()
    try:
        url = urlsplit(raw if '://' in raw else 'https://' + raw)
    except ValueError as exc:
        raise AuthError('dashboard Access configuration invalid') from exc
    # Limit requests to an explicitly configured Cloudflare Access team over
    # HTTPS. Reject credentials, ports, paths, query strings and fragments.
    host = url.hostname or ''
    if (url.scheme != 'https' or url.netloc != host or url.path not in ('', '/')
            or url.query or url.fragment or not re.fullmatch(
                r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com', host)
            or not aud):
        raise AuthError('dashboard Access configuration missing or invalid')
    return 'https://' + host, aud


def _fetch_jwks(issuer):
    # Stream and bound the body; do not follow a redirect to another origin.
    with requests.get(issuer + '/cdn-cgi/access/certs', timeout=10,
                      stream=True, allow_redirects=False) as response:
        if response.status_code != 200:
            raise AuthError('Access signing keys unavailable')
        chunks, size = [], 0
        for chunk in response.iter_content(8192):
            size += len(chunk)
            if size > MAX_JWKS_BYTES:
                raise AuthError('Access signing keys too large')
            chunks.append(chunk)
        return json.loads(b''.join(chunks))


def reset_jwks_cache():
    global _keys, _source, _fetched_at, _attempted_at
    with _lock:
        _keys, _source, _fetched_at, _attempted_at = {}, None, 0.0, None


def _key(issuer, kid):
    global _keys, _source, _fetched_at, _attempted_at
    with _lock:
        now = time.monotonic()
        if _source != issuer:
            _keys, _source, _fetched_at, _attempted_at = {}, issuer, 0.0, None
        fresh = bool(_keys) and now - _fetched_at < JWKS_TTL_SECONDS
        if fresh and kid in _keys:
            return _keys[kid]
        # Covers unknown-key floods AND failed/empty initial fetches. Expired
        # keys are never served beyond the TTL when a refresh fails.
        if _attempted_at is None or now - _attempted_at >= JWKS_REFRESH_COOLDOWN_SECONDS:
            _attempted_at = now
            try:
                data = _fetch_jwks(issuer)
                entries = data.get('keys') if isinstance(data, dict) else None
                if not isinstance(entries, list) or not 0 < len(entries) <= 64:
                    raise ValueError('invalid key set')
                keys = {}
                for entry in entries:
                    if not isinstance(entry, dict) or entry.get('kty') != 'RSA':
                        continue
                    entry_kid = entry.get('kid')
                    if not isinstance(entry_kid, str) or not 0 < len(entry_kid) <= 256:
                        continue
                    if entry_kid in keys:
                        raise ValueError('ambiguous key id')
                    if entry.get('alg', 'RS256') != 'RS256' or entry.get('use', 'sig') != 'sig':
                        continue
                    keys[entry_kid] = jwt.algorithms.RSAAlgorithm.from_jwk(entry)
                if not keys:
                    raise ValueError('no RSA signing keys')
                _keys, _fetched_at = keys, now
                fresh = True
            except Exception as exc:
                raise AuthError('Access signing keys unavailable') from exc
        if not fresh or kid not in _keys:
            raise AuthError('Access signing key unknown or expired')
        return _keys[kid]


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JWT claim')
        result[key] = value
    return result


def verify_token(token):
    issuer, audience = _configuration()
    if not isinstance(token, str) or not token or len(token) > MAX_TOKEN_BYTES:
        raise AuthError('missing or oversized Access token')
    try:
        parts = token.split('.')
        if len(parts) != 3:
            raise ValueError('malformed JWT')
        # PyJWT's default JSON parser accepts duplicate keys. Reject ambiguous
        # headers and claims before signature verification, without trusting them.
        for part in parts[:2]:
            value = json.loads(base64.urlsafe_b64decode(part + '=' * (-len(part) % 4)),
                               object_pairs_hook=_unique_object)
            if not isinstance(value, dict):
                raise ValueError('JWT object required')
        header = jwt.get_unverified_header(token)
        kid = header.get('kid')
        if header.get('alg') != 'RS256' or not isinstance(kid, str) or not 0 < len(kid) <= 256:
            raise ValueError('unsupported JWT header')
        claims = jwt.decode(token, key=_key(issuer, kid), algorithms=['RS256'],
                            issuer=issuer, audience=audience,
                            options={'require': ['exp', 'iat', 'iss', 'aud', 'email', 'sub']})
        email = claims['email']
        aud = claims['aud']
        if (not isinstance(email, str) or len(email) > 254
                or not re.fullmatch(r'[^\s@|]+@[^\s@|]+\.[^\s@|]+', email)
                or not isinstance(claims['sub'], str) or not claims['sub'].strip()
                or not isinstance(claims['iss'], str)
                or any(type(claims[name]) not in (int, float) or not math.isfinite(claims[name])
                       for name in ('exp', 'iat'))
                or not (isinstance(aud, str) and aud or isinstance(aud, list) and aud
                        and all(isinstance(a, str) and a for a in aud) and len(set(aud)) == len(aud))):
            raise ValueError('invalid identity claims')
        return claims
    except AuthError:
        raise
    except Exception as exc:
        raise AuthError('Access token rejected') from exc


def resolve_email(request):
    """Resolve once per request; a raw email header is never an identity."""
    if not hasattr(request.state, 'dashboard_access_email'):
        request.state.dashboard_access_email = None
        assertions = request.headers.getlist('cf-access-jwt-assertion')
        token = assertions[0] if len(assertions) == 1 else None
        if not assertions:
            token = request.cookies.get('CF_Authorization')
        try:
            request.state.dashboard_access_email = verify_token(token)['email']
        except AuthError:
            pass
    return request.state.dashboard_access_email
