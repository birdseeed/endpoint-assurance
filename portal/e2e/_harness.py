# TEST HARNESS ONLY, NEVER DEPLOYED.
"""Boots the real portal app (main.py) with Cloudflare Access verification
replaced by a stub, so a headless browser can load pages without a real CF
Access edge in front of it (PAT-1021).

This module is launched as a `uvicorn e2e._harness:app` subprocess by
e2e/conftest.py, with PORTAL_E2E_HARNESS=1 in its environment. It is never
imported by the app itself, by tests/, or by anything that ships to
patched-portal-01:

  - deploy/install.sh's rsync into the live app dir excludes this whole
    e2e/ directory (see the comment next to its --exclude list), so this
    module is not even present on the box.
  - The PORTAL_E2E_HARNESS guard below is a second, independent line of
    defence: importing this module anywhere the guard is not set - a stray
    import, a typo in a deploy exclude list, a future refactor - fails
    loudly at import time instead of silently serving unauthenticated
    pages.

Auth is not simply switched off. HARNESS_VALID_TOKEN below still gates
verify_token: any other token still gets the real fail-closed 401/session-
expired behaviour (see e2e/test_portal_ui.py's negative test). A stub that
accepted anything would prove nothing about whether the auth wall is still
wired up - it would just move the hole from main.py to here.
"""

import os

if os.environ.get("PORTAL_E2E_HARNESS") != "1":
    raise RuntimeError(
        "e2e/_harness.py refuses to start without PORTAL_E2E_HARNESS=1 set "
        "in the environment. This module stubs Cloudflare Access "
        "verification and must never run outside the e2e suite's own "
        "subprocess - see the module docstring."
    )

import auth  # noqa: E402

# Sentinel the stub accepts as a valid session. Must match e2e/conftest.py's
# HARNESS_VALID_TOKEN - kept as a plain duplicated literal rather than a
# shared import so this file stays importable (and its guard above
# enforceable) without pulling in pytest or any e2e/conftest.py fixture
# machinery. Real CF Access JWTs are opaque signed tokens the portal never
# generates itself, so this plain string cannot collide with a real one.
HARNESS_VALID_TOKEN = "e2e-harness-token-do-not-use-in-prod"
HARNESS_CLAIMS = {
    "email": "e2e-harness@example.com",
    "sub": "e2e-harness-sub",
    "aud": ["e2e-harness-aud"],
    "iss": "https://e2e-harness.invalid",
}


def _stub_verify_token(token: str) -> dict:
    """Replaces auth.verify_token for the lifetime of this process. Returns
    fixed claims for the one harness sentinel token; anything else -
    missing, empty, or simply wrong - is rejected exactly like a real
    expired/forged CF Access JWT would be, so main.py's fail-closed
    middleware still fails closed."""
    if token != HARNESS_VALID_TOKEN:
        raise auth.AuthError("e2e harness: token did not match the harness sentinel")
    return dict(HARNESS_CLAIMS)


auth.verify_token = _stub_verify_token

import main  # noqa: E402

app = main.app
