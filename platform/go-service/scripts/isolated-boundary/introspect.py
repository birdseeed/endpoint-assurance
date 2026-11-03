"""Dump the route table of a FastAPI app (and, for the staff console, its RBAC rule patterns).

Run with the target app's own interpreter and working directory:
  python introspect.py <out.json>
Imports `main` read-only from the pinned copy. No requests are made.
"""
import json
import sys

import os
sys.path.insert(0, os.getcwd())
import main  # noqa: E402

app = main.app
routes = []
for r in app.routes:
    methods = sorted(m for m in (getattr(r, "methods", None) or []) if m not in ("HEAD", "OPTIONS"))
    path = getattr(r, "path", None)
    if path is None:
        continue
    routes.append({"path": path, "methods": methods, "name": getattr(r, "name", "")})
out = {"routes": routes}


def pats(name):
    v = getattr(main, name, None)
    if v is None:
        return None
    res = []
    for item in v:
        if isinstance(item, tuple) and len(item) >= 2:
            rx = item[1]
            res.append([item[0], getattr(rx, "pattern", str(rx))] + ([item[2]] if len(item) > 2 else []))
    return res


for name in ("_CONSULTANT_WRITE_ALLOW", "_DESTRUCTIVE_RULES", "_CONFIRM_RULES", "_OWNER_ONLY_GET",
             "_LEGACY_EXECUTION_QUARANTINE_RULES"):
    out[name] = pats(name)
out["_ADMIN_NAV_EXEMPT_SUFFIXES"] = list(getattr(main, "_ADMIN_NAV_EXEMPT_SUFFIXES", []))
out["CONSOLE_BUILD_ID"] = getattr(main, "CONSOLE_BUILD_ID", None)
json.dump(out, open(sys.argv[1], "w"), indent=1)
print(len(routes), "routes")
