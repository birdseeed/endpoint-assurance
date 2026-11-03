"""Recorder, route helpers and snapshots shared by the boundary checks."""
import hashlib
import hmac
import json
import re
import time
from pathlib import Path

ZERO = "00000000-0000-4000-8000-000000000000"
PARAM = re.compile(r"\{([^}]+)\}")
VOLATILE = {"generated_at", "last_seen", "received_at", "next_run_at", "updated_at", "last_matched_at", "observed_at",
            "as_of", "now", "evaluated_at", "freshness", "cve_assessment", "last_run_at", "expires_at", "created_at", "until"}


class Recorder:
    def __init__(self):
        self.rows = []
        self.covered = {}

    def add(self, cid, boundary, route, method, principal, expected, observed, ok, note=""):
        self.rows.append({"id": cid, "boundary": boundary, "route": route, "method": method, "principal": principal,
                          "expected": expected, "observed": observed, "result": "PASS" if ok else "FAIL", "note": note})
        return ok

    def obs(self, cid, boundary, route, method, principal, expected, observed, note=""):
        """A recorded behaviour that is a design dependency, not a pass or a fail."""
        self.rows.append({"id": cid, "boundary": boundary, "route": route, "method": method, "principal": principal,
                          "expected": expected, "observed": observed, "result": "OBSERVATION", "note": note})

    def cover(self, inventory, method, path):
        self.covered.setdefault(inventory, set()).add((method, path))

    def summary(self):
        out = {}
        for r in self.rows:
            b = out.setdefault(r["boundary"], {"checks": 0, "pass": 0, "fail": 0, "observation": 0})
            b["checks"] += 1
            b[{"PASS": "pass", "FAIL": "fail"}.get(r["result"], "observation")] += 1
        return out


def fill(template, values=None):
    values = values or {}
    return PARAM.sub(lambda m: str(values.get(m.group(1), ZERO)), template)


def params_of(template):
    return PARAM.findall(template)


def csrf_for(jwt_token):
    # Mirrors the portal's documented construction (main.py `_csrf_token`): HMAC-SHA256 keyed by the assertion.
    return hmac.new(jwt_token.encode(), b"patched-portal-csrf-v1", hashlib.sha256).hexdigest()


def norm(obj):
    """Drop volatile keys so before/after snapshots compare equal when nothing changed."""
    if isinstance(obj, dict):
        return {k: norm(v) for k, v in obj.items() if k not in VOLATILE}
    if isinstance(obj, list):
        return [norm(v) for v in obj]
    return obj


def digest(obj):
    return hashlib.sha256(json.dumps(norm(obj), sort_keys=True, default=str).encode()).hexdigest()[:16]
