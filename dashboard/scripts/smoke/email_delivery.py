#!/usr/bin/env python3
"""
Smoke module: email_delivery

Named email_delivery, not email (PAT-937): run_all.py invokes each module as
a direct file (`python3 <script>.py`), which puts the script's own directory
on sys.path[0] — a sibling file named email.py shadowed Python's own stdlib
`email` package for every module in this directory (dashboard_core and
public_scan both `import requests`, which transitively needs stdlib
`email.errors`), breaking 3 of 4 smoke modules with
`ModuleNotFoundError: No module named 'email.errors'`. Any future rename must
keep clear of stdlib module names for the same reason.

Verifies that the running dashboard service can actually deliver outbound
email, and fails the deploy if it cannot.

PAT-1346 (2026-09-03): this module used to assert the opposite. From PAT-228
until now, EMAIL_DRY_RUN=1 was structurally required in production and this
check FAILED THE DEPLOY if it was ever unset, so that flipping dry-run off by
accident could not go unnoticed. That was the right gate while outbound email
was deliberately suppressed.

It is now inverted, deliberately and as a single change alongside the env var,
because suppression has been lifted: Microsoft Graph delivery was verified end
to end from prod-01 to both an external and an internal recipient, and the
send backlog was empty (no report subscriptions, no leads, no configured
digest recipients), so enabling real sending could not release stale mail.

The gate asserts email_delivery == "live" rather than merely
email_dry_run == false. Those are not the same claim. With the flag off and no
provider configured, every send would fail while a naive "not dry-run" check
still passed — precisely the silent-success shape (PAT-912, PAT-837, PAT-960)
this suite exists to catch. "live" means suppression is off AND a provider is
configured.

Note the honest limit of "live": email_delivery_status() checks configuration
presence, not working credentials. Invalid or expired credentials read
identically to good ones, so this gate proves the service intends to send and
has somewhere to send through. It does not prove the last send succeeded. The
hourly email_delivery check_statuses row (PAT-1010) is the runtime signal for
that; this is the deploy-time one.

If outbound email is ever deliberately suppressed again, invert this module in
the SAME commit as the env change, exactly as this one was, and update
truth_manifest.yaml's prod01-email-delivery entry. A deploy gate that
contradicts the intended state is worse than none.

Requirements:
  - dashboard running at SMOKE_BASE_URL (default http://127.0.0.1:8000)
  - DASHBOARD_API_KEY set in environment
  - EMAIL_DRY_RUN absent from the dashboard's EnvironmentFile
  - Microsoft Graph mail configured (GRAPH_MAIL_*)

Exit codes:
  0 = delivery live, safe to deploy
  1 = delivery suppressed or unconfigured, or endpoint unreachable
"""
import os
import sys

import requests


BASE_URL = os.getenv("SMOKE_BASE_URL", "http://127.0.0.1:8000")
API_KEY = os.getenv("DASHBOARD_API_KEY", "")


def step(msg: str) -> None:
    print(f"\n→ {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"  ✓ {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"  ✗ {msg}", flush=True)
    sys.exit(1)


def main():
    print("email_delivery smoke starting")
    print(f"  base url: {BASE_URL}")

    step("GET /api/smoke/health (email delivery state)")
    if not API_KEY:
        fail("DASHBOARD_API_KEY not set — cannot authenticate /api/smoke/health")
    try:
        r = requests.get(
            f"{BASE_URL}/api/smoke/health",
            headers={"Authorization": f"Bearer {API_KEY}"},
            timeout=10,
        )
    except Exception as e:
        fail(f"/api/smoke/health request failed: {e}")

    if r.status_code != 200:
        fail(f"/api/smoke/health returned {r.status_code}, expected 200")

    try:
        data = r.json()
    except Exception:
        fail(f"/api/smoke/health returned non-JSON: {r.text[:200]}")

    # Absent (rather than false) means the running service predates the
    # PAT-1346 probe change. Treat that as a failure: an old build silently
    # skipping this assertion is the failure mode being guarded against.
    delivery = data.get("email_delivery")
    if delivery is None:
        fail(
            "/api/smoke/health did not report email_delivery.\n"
            "  The running service predates PAT-1346. Deploy the current build\n"
            "  before relying on this gate."
        )

    if delivery == "dry_run":
        fail(
            "outbound email is suppressed on the running service.\n"
            "  EMAIL_DRY_RUN is set in /etc/patched-dashboard/dashboard.env.\n"
            "  If that is deliberate, invert this module in the same commit\n"
            "  and update truth_manifest.yaml's prod01-email-delivery entry."
        )

    if delivery == "unconfigured":
        fail(
            "Microsoft Graph mail is not configured on the running service.\n"
            "  Set GRAPH_MAIL_TENANT_ID / GRAPH_MAIL_CLIENT_ID /\n"
            "  GRAPH_MAIL_CLIENT_SECRET in the EnvironmentFile and restart.\n"
            "  Every send would currently fail."
        )

    if delivery != "live":
        fail(f"unexpected email_delivery value {delivery!r}, expected 'live'")

    ok("email delivery is live — suppression off and a provider is configured")

    print("\nemail_delivery PASSED")


if __name__ == "__main__":
    main()
