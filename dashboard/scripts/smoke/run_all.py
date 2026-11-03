#!/usr/bin/env python3
"""
Smoke test suite runner — dashboard.patched.im

Runs all smoke modules in order and exits non-zero if any fail. Each module
runs as a subprocess so failures are isolated; a failing module does not
prevent the remaining modules from running.

Modules (in order):
  dashboard_core  — page routes 200, /api/* Bearer auth
  scheduler       — heartbeat present and fresh in dashboard.db
  email_dry_run   — EMAIL_DRY_RUN active (no real sends during smoke).
                    Named email_dry_run, not email (PAT-937) — a sibling
                    module named email.py shadowed Python's own stdlib
                    `email` package for every module run from this
                    directory, breaking any module that imports `requests`.

PAT-866 removed the public_scan module: the public CVE-scan funnel it
smoke-tested (public_router.py, /public/scan) was removed from this repo
and now lives at scan.patched.im (portal repo), which has its own deploy
and its own smoke coverage there. Keeping this module here would fail
every deploy of this repo post-PAT-866 (the route it hits no longer
exists) and trigger scripts/deploy.sh's auto-rollback.

Usage:
  python3 run_all.py
  python3 run_all.py --base-url http://127.0.0.1:8000 --db /var/lib/patched-dashboard/dashboard.db

Exit codes:
  0 = all modules passed
  1 = one or more modules failed
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path


SMOKE_DIR = Path(__file__).parent

MODULES = [
    "dashboard_core",
    "scheduler",
    "email_delivery",
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--base-url", default="http://127.0.0.1:8000")
    p.add_argument(
        "--db",
        default=os.getenv(
            "DASHBOARD_DB_PATH", "/var/lib/patched-dashboard/dashboard.db"
        ),
    )
    args = p.parse_args()

    python = sys.executable
    env = os.environ.copy()
    env["SMOKE_BASE_URL"] = args.base_url
    env["SMOKE_DB"] = args.db

    results: dict[str, bool] = {}

    for module in MODULES:
        script = SMOKE_DIR / f"{module}.py"
        print(f"\n{'=' * 60}", flush=True)
        print(f"SMOKE MODULE: {module}", flush=True)
        print(f"{'=' * 60}", flush=True)

        cmd = [python, str(script)]

        result = subprocess.run(cmd, env=env)
        results[module] = result.returncode == 0

    print(f"\n{'=' * 60}", flush=True)
    print("SMOKE SUITE RESULTS:", flush=True)
    failed = []
    for module, passed in results.items():
        status = "PASS" if passed else "FAIL"
        print(f"  {status}  {module}", flush=True)
        if not passed:
            failed.append(module)

    if failed:
        print(f"\nFAILED: {', '.join(failed)}", flush=True)
        sys.exit(1)

    print(f"\nAll {len(results)} modules passed.", flush=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
