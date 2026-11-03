"""Cloudflare Access JWT verification for the Patched customer portal.

Every request to the portal must carry a valid CF Access JWT in the
Cf-Access-Jwt-Assertion header (CF also mirrors it in the CF_Authorization
cookie). We verify it server-side against the team's JWKS - we never trust
the Cf-Access-Authenticated-User-Email header on its own, because anything
that reaches the origin around Cloudflare could forge it.

Fail closed: any verification failure raises AuthError and the caller
returns 401.

Env:
  PORTAL_ACCESS_TEAM_DOMAIN  e.g. "example-team.cloudflareaccess.com"
                             (scheme optional; stripped if present)
  PORTAL_ACCESS_AUD          the Access application AUD tag
  PORTAL_SERVICE_TOKEN_COMMON_NAME
                             optional (PAT-2257). The one Cloudflare Access
                             service token client id whose JWT is accepted
                             as the read-only service identity. Unset or
                             blank = no service token is ever accepted.
"""

import hmac
import os
import threading
import time

import jwt as pyjwt
import requests

JWKS_TTL_SECONDS = 3600
# Minimum interval between forced JWKS refreshes (unknown kid), so a flood of
# garbage tokens cannot turn us into a JWKS-fetch amplifier.
JWKS_REFRESH_COOLDOWN_SECONDS = 60

ALGORITHMS = ["RS256"]
MAX_TOKEN_BYTES = 16 * 1024


class AuthError(Exception):
    """Raised on any JWT verification failure. Message is safe to log."""


class MissingTokenError(AuthError):
    """No Access token was presented at all: a visitor who has never signed
    in, not a session that lapsed. Subclasses AuthError so every existing
    `except AuthError` handler still fails closed."""


class ConfigError(Exception):
    """Raised when required auth env vars are missing."""


def team_domain() -> str:
    raw = os.environ.get("PORTAL_ACCESS_TEAM_DOMAIN", "").strip()
    if not raw:
        raise ConfigError("PORTAL_ACCESS_TEAM_DOMAIN is not set")
    return raw.removeprefix("https://").removeprefix("http://").rstrip("/")


def expected_audience() -> str:
    aud = os.environ.get("PORTAL_ACCESS_AUD", "").strip()
    if not aud:
        raise ConfigError("PORTAL_ACCESS_AUD is not set")
    return aud


def issuer() -> str:
    return f"https://{team_domain()}"


def certs_url() -> str:
    return f"{issuer()}/cdn-cgi/access/certs"


# ── JWKS cache ────────────────────────────────────────────────────────────
_jwks_lock = threading.Lock()
_jwks_keys: dict = {}  # kid -> public key object
_jwks_fetched_at: float = 0.0
_jwks_last_forced: float = 0.0


def _fetch_jwks() -> dict:
    """Fetch the team JWKS. Separated out so tests can monkeypatch it."""
    resp = requests.get(certs_url(), timeout=10)
    resp.raise_for_status()
    return resp.json()


def _load_keys(force: bool = False) -> dict:
    global _jwks_keys, _jwks_fetched_at, _jwks_last_forced
    with _jwks_lock:
        now = time.monotonic()
        fresh = _jwks_keys and (now - _jwks_fetched_at) < JWKS_TTL_SECONDS
        if fresh and not force:
            return _jwks_keys
        if force and _jwks_keys and (now - _jwks_last_forced) < JWKS_REFRESH_COOLDOWN_SECONDS:
            return _jwks_keys
        try:
            data = _fetch_jwks()
        except Exception as exc:
            if _jwks_keys:
                # Keep serving the stale key set rather than locking every
                # customer out because one JWKS fetch failed.
                return _jwks_keys
            raise AuthError(f"could not fetch Access signing keys: {exc}") from exc
        keys = {}
        for entry in data.get("keys", []):
            kid = entry.get("kid")
            if not kid:
                continue
            try:
                keys[kid] = pyjwt.algorithms.RSAAlgorithm.from_jwk(entry)
            except Exception:
                continue
        if not keys:
            raise AuthError("Access JWKS contained no usable RSA keys")
        _jwks_keys = keys
        _jwks_fetched_at = now
        if force:
            _jwks_last_forced = now
        return _jwks_keys


def reset_jwks_cache() -> None:
    """Test helper: drop the cached key set."""
    global _jwks_keys, _jwks_fetched_at, _jwks_last_forced
    with _jwks_lock:
        _jwks_keys = {}
        _jwks_fetched_at = 0.0
        _jwks_last_forced = 0.0


# ── Verification ──────────────────────────────────────────────────────────
def verify_token(token: str) -> dict:
    """Verify a CF Access JWT. Returns the claims dict or raises AuthError.

    Checks: RS256 signature against the team JWKS, audience (AUD tag),
    issuer (team domain), expiry and not-before. Requires an email claim -
    the platform derives the tenant from it, so a token without one is
    useless and rejected here.

    PAT-2257: the one exception is a service-token JWT (no email, a
    `common_name` claim holding the token's client id) whose common_name
    equals PORTAL_SERVICE_TOKEN_COMMON_NAME. It has already passed every
    check above; it maps to the read-only service identity (see
    service_common_name) and never to a person.
    """
    if not token:
        raise MissingTokenError("no Access token presented")
    # JWTs are ASCII. Bound input before parsing any attacker-controlled JSON.
    if not isinstance(token, str) or len(token) > MAX_TOKEN_BYTES or not token.isascii():
        raise AuthError("invalid or oversized Access token")
    try:
        header = pyjwt.get_unverified_header(token)
    except (pyjwt.exceptions.PyJWTError, RecursionError) as exc:
        raise AuthError(f"malformed token: {exc}") from exc
    kid = header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise AuthError("token header has no valid kid")

    keys = _load_keys()
    key = keys.get(kid)
    if key is None:
        # Key rotation: refresh once (rate-limited) and retry.
        keys = _load_keys(force=True)
        key = keys.get(kid)
    if key is None:
        raise AuthError("token signed by unknown key")

    try:
        claims = pyjwt.decode(
            token,
            key=key,
            algorithms=ALGORITHMS,
            audience=expected_audience(),
            issuer=issuer(),
            options={"require": ["exp", "iat", "aud", "iss"]},
        )
    except (pyjwt.exceptions.PyJWTError, RecursionError) as exc:
        raise AuthError(f"token rejected: {exc}") from exc

    email = claims.get("email")
    if email:
        return claims
    if service_common_name(claims) is not None:
        return claims
    raise AuthError("token has no email claim")


# ── Read-only service identity (PAT-2257) ────────────────────────────────
SERVICE_IDENTITY_LABEL = "Read-only service account"


def allowed_service_common_name() -> str | None:
    """The configured service token client id, or None when the feature is
    off (unset or blank)."""
    value = os.environ.get("PORTAL_SERVICE_TOKEN_COMMON_NAME", "").strip()
    return value or None


def service_common_name(claims: dict) -> str | None:
    """The allowlisted common_name when `claims` (already verified by
    verify_token) are the service identity's, else None.

    Only an email-less token qualifies: a token with an email is a person's
    and always stays one. The comparison is exact (no case folding or
    trimming of the claim) and constant-time."""
    if not isinstance(claims, dict) or claims.get("email"):
        return None
    allowed = allowed_service_common_name()
    cn = claims.get("common_name")
    if not allowed or not isinstance(cn, str) or not cn:
        return None
    if not hmac.compare_digest(cn.encode("utf-8"), allowed.encode("utf-8")):
        return None
    return cn


# ── Which IdP authenticated this session (PAT-127, display only) ──────────
#
# The Cf-Access-Jwt-Assertion JWT itself never carries which identity
# provider was used (Microsoft/Google SSO vs the email one-time-PIN
# fallback) - only Cloudflare's /cdn-cgi/access/get-identity endpoint
# exposes that. This is used ONLY for a "Signed in via Microsoft"-style
# display hint, NEVER for any authorization decision (tenant resolution is
# entirely the verified email claim, handled upstream by the platform) - so
# every failure mode here degrades to None rather than raising.
#
# Not wired into the per-request auth middleware: calling an extra
# Cloudflare endpoint on every single request would add latency and a new
# failure surface to the hot path for a cosmetic feature. Call this
# explicitly (e.g. once per page render, or once per session with the
# result cached) once Microsoft/Google are actually live as CF Access IdPs -
# see docs/ANDY-TODO-sso-cf-access-setup.md.
IDP_DISPLAY_NAMES = {
    "onetimepin": "email one-time PIN",
    "azureAD": "Microsoft",
    "google-apps": "Google",
}


def get_identity_url() -> str:
    return f"{issuer()}/cdn-cgi/access/get-identity"


def fetch_login_method(token: str) -> str | None:
    """Best-effort display string for which IdP authenticated this session.

    Returns a human-readable name from IDP_DISPLAY_NAMES, the raw CF `idp`
    type string if we don't recognise it (better an unfamiliar-but-honest
    label than silently dropping it), or None if the lookup fails or the
    response doesn't have the expected shape. Never raises.
    """
    if not token:
        return None
    try:
        resp = requests.get(
            get_identity_url(),
            cookies={"CF_Authorization": token},
            timeout=5,
        )
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, dict):
            return None
        idp = data.get("idp")
        if not isinstance(idp, dict):
            return None
        idp_type = idp.get("type")
    except Exception:
        return None
    if not isinstance(idp_type, str) or not idp_type:
        return None
    return IDP_DISPLAY_NAMES.get(idp_type, idp_type)
