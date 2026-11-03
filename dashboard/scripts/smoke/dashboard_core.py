#!/usr/bin/env python3
"""
Smoke module: dashboard_core

First waits, bounded, for the service to come back up and answer on
SMOKE_BASE_URL (127.0.0.1:8000 in production) — a restart that systemd
reports as "active" doesn't guarantee Uvicorn has finished binding the port
yet, so this retries GET / instead of trusting the caller's own sleep.

Then verifies the single-page-app route serves HTTP 200 (GET / redirects to
/console/{build_id}; requests follows it), and that a representative
/api/* route authenticates correctly via the Bearer token. Runs against
http://127.0.0.1:8000 (below Cloudflare Access).

Note: there is no standalone GET /admin page any more (retired in the
console rebuild — /admin/* is a JSON proxy prefix only, not a page). Don't
add it back to the page-route check below.

Requirements:
  - dashboard running at SMOKE_BASE_URL (default http://127.0.0.1:8000)
  - DASHBOARD_API_KEY set in environment

Exit codes:
  0 = all checks passed
  1 = a check failed
"""
import os
import sys
import time

import requests


BASE_URL = os.getenv("SMOKE_BASE_URL", "http://127.0.0.1:8000")
API_KEY = os.getenv("DASHBOARD_API_KEY", "")
READY_TIMEOUT_S = float(os.getenv("SMOKE_READY_TIMEOUT", "30"))
READY_POLL_INTERVAL_S = float(os.getenv("SMOKE_READY_POLL_INTERVAL", "1"))


def step(msg: str) -> None:
    print(f"\n→ {msg}", flush=True)


def ok(msg: str) -> None:
    print(f"  ✓ {msg}", flush=True)


def fail(msg: str) -> None:
    print(f"  ✗ {msg}", flush=True)
    sys.exit(1)


def wait_until_ready() -> None:
    """Bounded wait for the service to answer on BASE_URL after a restart.

    A restart failing this check is a hard smoke failure — not a crash-loop
    that self-resolves — so it's worth waiting past a plain connection
    refused/reset for a few seconds before giving up, rather than failing on
    the first attempt.
    """
    step(f"Wait for {BASE_URL} to answer (bounded, {READY_TIMEOUT_S:.0f}s)")
    deadline = time.monotonic() + READY_TIMEOUT_S
    last_err = None
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        try:
            r = requests.get(f"{BASE_URL}/", timeout=5)
            if r.status_code == 200:
                ok(f"answered 200 after {attempts} attempt(s)")
                return
            last_err = f"got HTTP {r.status_code}"
        except Exception as e:
            last_err = str(e)
        time.sleep(READY_POLL_INTERVAL_S)
    fail(
        f"{BASE_URL} did not answer 200 within {READY_TIMEOUT_S:.0f}s "
        f"({attempts} attempt(s)); last error: {last_err}"
    )


def main():
    print("dashboard_core smoke starting")
    print(f"  base url: {BASE_URL}")

    wait_until_ready()

    # ── Page routes (no auth — served below CF Access) ──
    # GET / redirects (302) to /console/{CONSOLE_BUILD_ID}; requests follows
    # it, so a 200 here also proves the console template renders.
    for path in ["/"]:
        step(f"GET {path}")
        try:
            r = requests.get(f"{BASE_URL}{path}", timeout=10)
        except Exception as e:
            fail(f"{path} request failed: {e}")
        if r.status_code != 200:
            fail(f"{path} returned {r.status_code}, expected 200")
        ok(f"{path} → 200")

    # ── /api/* route with Bearer auth ──
    # PAT-572: GET /api/clients was removed with the Microsoft Graph scan
    # pipeline. /api/metrics is a simple, state-independent /api/* route
    # (aggregate scan stats, 200 even against an empty DB) that still
    # exercises the same Bearer-auth path.
    step("GET /api/metrics with Bearer token")
    if not API_KEY:
        fail("DASHBOARD_API_KEY not set — cannot test /api/* Bearer auth")
    try:
        r = requests.get(
            f"{BASE_URL}/api/metrics",
            headers={"Authorization": f"Bearer {API_KEY}"},
            timeout=10,
        )
    except Exception as e:
        fail(f"/api/metrics request failed: {e}")
    if r.status_code != 200:
        fail(f"/api/metrics returned {r.status_code} with Bearer, expected 200")
    ok("/api/metrics → 200 (Bearer auth ok)")

    print("\ndashboard_core PASSED")


if __name__ == "__main__":
    main()
