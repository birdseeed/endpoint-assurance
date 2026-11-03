"""Boundary F: the staff console (dashboard) at its pinned commit, with real owner and consultant sessions.

Staff identities are supplied the way the console expects them behind Cloudflare Access: the
CF-Access-Authenticated-User-Email header on GET /console/{rev}, from which the console mints its
patched_session cookie. The console's auth code is not altered. A recording proxy between the
console and the platform's internal API (tap.py) shows exactly what the console sends upstream.
"""
import json
import posixpath
import re
import sqlite3
import time
from pathlib import Path
from urllib.parse import quote

from common import ZERO, fill, params_of
import matrix
from ibclient import OWNER_STAFF, CONSULTANT_STAFF

HDR = "CF-Access-Authenticated-User-Email"


def login(e, dash, email, rev):
    r = e.http.request("GET", dash + f"/console/{rev}", headers={HDR: email})
    return r.cookies.get("patched_session"), r


def tap_entries(scratch, since=0):
    p = Path(scratch) / "logs/tap.jsonl"
    if not p.exists():
        return []
    data = p.read_bytes()[since:].decode("utf-8", "replace").splitlines()
    return [json.loads(x) for x in data if x.strip()]


def audit_rows(scratch):
    db = sqlite3.connect(str(Path(scratch) / "dashboard.db"))
    db.row_factory = sqlite3.Row
    return [dict(r) for r in db.execute("SELECT * FROM admin_audit_log ORDER BY ts")]


def run(ctx):
    rec, e, scratch = ctx.rec, ctx.e, ctx.scratch
    dash = matrix.introspect("dashboard", scratch, ctx.st)
    rev = dash["CONSOLE_BUILD_ID"]
    routes = [(m, r["path"]) for r in dash["routes"] for m in (r["methods"] or [])]
    exempt_suffix = tuple(dash["_ADMIN_NAV_EXEMPT_SUFFIXES"])
    comp = lambda rules: [(m, re.compile(p)) for m, p, *_ in rules]
    consultant_allow = comp(dash["_CONSULTANT_WRITE_ALLOW"])
    destructive = comp(dash["_DESTRUCTIVE_RULES"])
    owner_only_get = comp(dash["_OWNER_ONLY_GET"])
    confirm = [(m, re.compile(p), k) for m, p, k in dash["_CONFIRM_RULES"]]
    quarantine = comp(dash["_LEGACY_EXECUTION_QUARANTINE_RULES"])
    match = lambda rules, m, p: any(mm == m and rx.match(p) for mm, rx in rules)
    guarded = lambda m, p: (p.startswith("/api/") or p.startswith("/admin/")) and not (m == "GET" and p.endswith("/download"))
    inv = {"dashboard_methods_enumerated": len(routes), "dashboard_guarded": sum(1 for m, p in routes if guarded(m, p))}
    ctx.inventory_extra = {"dashboard": {"enumerated": len(routes), "covered": 0}}
    owner, r_o = login(e, e.dash, OWNER_STAFF, rev)
    consultant, r_c = login(e, e.dash, CONSULTANT_STAFF, rev)
    rec.add("F-LOGIN-owner-session-minted", "F", f"/console/{rev}", "GET", "staff.owner via CF header", "session cookie minted", bool(owner), bool(owner))
    rec.add("F-LOGIN-consultant-session-minted", "F", f"/console/{rev}", "GET", "staff.consultant via CF header", "session cookie minted", bool(consultant), bool(consultant))
    tap_start = (scratch / "logs/tap.jsonl").stat().st_size if (scratch / "logs/tap.jsonl").exists() else 0
    cover = set()

    def req(m, p, cookie=None, headers=None, body=None):
        h = dict(headers or {})
        cookies = {"patched_session": cookie} if cookie else None
        return e.http.request(m, e.dash + p, headers=h, cookies=cookies, data=body if body is not None else (b"{}" if m in matrix.WRITE else None))

    fp = lambda p: fill(p, {k: (ctx.e.tenants["A"]["id"] if "tenant" in k.lower() else ZERO) for k in params_of(p)})

    # --- F-NOID: every route without any staff identity
    for m, p in routes:
        cover.add((m, p))
        path = fp(p)
        r = req(m, path)
        if guarded(m, p):
            exempt = m == "GET" and p.endswith(exempt_suffix)
            if exempt:
                ok = r.status_code in (200, 302, 303, 400, 401, 403, 404, 405, 422) and "CANARY" not in r.text
                exp = "documented navigation exemption (GET .../impersonation/start|end): no data in body"
            else:
                ok, exp = r.status_code == 401, 401
            rec.add(f"F-NOID-{m}-{p}", "F", p, m, "no identity", exp, r.status_code, ok)
        else:
            # not behind the /api and /admin middleware: record what an anonymous caller gets and require no tenant data
            ok = r.status_code < 500 and "CANARY" not in r.text and ctx.e.tenants["A"]["id"] not in r.text
            leakage = p in ("/docs", "/redoc", "/openapi.json") and r.status_code == 200
            rec.add(f"F-NOID-open-{m}-{p}", "F", p, m, "no identity", "no tenant data; API documentation not served anonymously",
                    r.status_code, ok and not leakage, "anonymous route listing" if leakage else "")
        # forged and partial credentials
        if guarded(m, p):
            forged = "c3RhZmYub3duZXJAcGF0Y2hlZC5leGFtcGxlfDQ3MDAwMDAwMDA.0000000000000000000000000000000000000000000000000000000000000000"
            for name, kw in (("cf_header_only", dict(headers={HDR: OWNER_STAFF})),
                             ("forged_session_mac", dict(cookie=forged)),
                             ("wrong_bearer", dict(headers={"Authorization": "Bearer ib-wrong"})),
                             ("bearer_prefix_only", dict(headers={"Authorization": "Bearer "}))):
                if m == "GET" and p.endswith(exempt_suffix):
                    continue
                r = req(m, path, **kw)
                rec.add(f"F-CRED-{name}-{m}-{p}", "F", p, m, name, 401, r.status_code, r.status_code == 401)
    # tampered cookie: owner email grafted onto the consultant's MAC
    try:
        mac = consultant.rsplit(".", 1)[1]
        import base64
        payload = base64.urlsafe_b64encode(f"{OWNER_STAFF}|4700000000".encode()).decode().rstrip("=")
        r = req("GET", "/admin/logs", cookie=f"{payload}.{mac}")
        rec.add("F-CRED-session-email-swapped-keeping-mac", "F", "/admin/logs", "GET", "consultant MAC with owner email", 401, r.status_code, r.status_code == 401)
    except Exception as ex:
        rec.add("F-CRED-session-email-swapped-keeping-mac", "F", "/admin/logs", "GET", "tamper", 401, str(ex), False)
    # consultant cookie plus an owner CF header must not raise the role
    r = req("GET", "/admin/logs", cookie=consultant, headers={HDR: OWNER_STAFF})
    rec.add("F-RBAC-consultant-cookie-with-owner-header", "F", "/admin/logs", "GET", "consultant session + owner CF header", 403, r.status_code, r.status_code == 403)

    # --- F-CONSULTANT: every state-changing route and every owner-only read
    audit_before = len(audit_rows(scratch))
    not_exercised = []
    for m, p in routes:
        if not guarded(m, p):
            continue
        path = fp(p)
        is_write = m in matrix.WRITE
        is_owner_get = m == "GET" and match(owner_only_get, m, path)
        if not (is_write or is_owner_get):
            continue
        if is_write and match(consultant_allow, m, path):
            not_exercised.append((m, p))
            rec.add(f"F-RBAC-consultant-{m}-{p}", "F", p, m, "consultant", "allowed by design (write allow-list); not exercised because it would write", "not exercised", True,
                    "in _CONSULTANT_WRITE_ALLOW")
            continue
        r = req(m, path, cookie=consultant, headers={"X-Confirm-Resource": "x"})
        tag = "destructive" if match(destructive, m, path) else "quarantined" if match(quarantine, m, path) else "write"
        rec.add(f"F-RBAC-consultant-{m}-{p}", "F", p, m, "consultant", 403, r.status_code, r.status_code == 403, f"rule class: {tag}")
    # every destructive rule must have at least one concrete route to exercise
    for rule in dash["_DESTRUCTIVE_RULES"]:
        rx = re.compile(rule[1])
        hits = [p for m, p in routes if m == rule[0] and rx.match(fp(p))]
        if hits:
            rec.add(f"F-RBAC-destructive-rule-has-route-{rule[0]}-{rule[1]}", "F", rule[1], rule[0], "rule table", "matches at least one mounted route", len(hits), True)
        else:
            rec.obs(f"F-RBAC-destructive-rule-has-route-{rule[0]}-{rule[1]}", "F", rule[1], rule[0], "rule table", "matches at least one mounted route", 0,
                    "rule for a route that is not mounted (installomator_sync is a quarantined legacy automation name); the rule is inert, nothing to exercise")
    # owner positive control: owner is not refused by RBAC (confirmation required on the confirm-gated ones)
    r = req("DELETE", fp("/admin/tenants/{tenant_id}/purge"), cookie=owner)
    rec.add("F-RBAC-owner-positive-control-confirmation-required", "F", "/admin/tenants/{id}/purge", "DELETE", "owner without X-Confirm-Resource",
            "428 (RBAC passes, typed confirmation missing); nothing purged", r.status_code, r.status_code == 428)
    r = req("DELETE", fp("/admin/tenants/{tenant_id}/purge"), cookie=owner, headers={"X-Confirm-Resource": "wrong-name"})
    rec.add("F-RBAC-owner-wrong-confirmation", "F", "/admin/tenants/{id}/purge", "DELETE", "owner with wrong X-Confirm-Resource", 409, r.status_code, r.status_code == 409)
    still = e.admin("GET", "/admin/tenants").text
    rec.add("F-RBAC-tenants-intact-after-confirmation-probes", "F", "/admin/tenants", "GET", "admin API", "both tenants still present",
            "present" if all(ctx.e.tenants[L]["id"] in still for L in "AB") else "missing", all(ctx.e.tenants[L]["id"] in still for L in "AB"))

    # --- F-PASSTHROUGH: tenant id in the path is forwarded exactly as given; hostile ids stay inside one path segment
    safe_gets = [p for m, p in routes if m == "GET" and re.fullmatch(r"/admin/tenants/\{tenant_id\}/[a-z-]+", p)][:12]
    for p in safe_gets:
        for L in "AB":
            tid = e.tenants[L]["id"]
            mark = (scratch / "logs/tap.jsonl").stat().st_size
            r = req("GET", fill(p, {"tenant_id": tid}), cookie=owner)
            ent = [x for x in tap_entries(scratch, mark) if x["path"].split("?")[0] == fill(p, {"tenant_id": tid})]
            rec.add(f"F-PASS-{L}-{p}", "F", p, "GET", f"owner, tenant {L} id in path", "forwarded upstream with the same tenant id, admin bearer attached",
                    {"status": r.status_code, "forwarded": len(ent), "auth": ent[0]["auth"] if ent else None},
                    (bool(ent) and ent[0]["auth"] == "admin") or (not ent and p.endswith(("/impersonation-log", "/support-access"))),
                    "" if ent else "handled inside the console (local SQLite); not a proxy route, so there is no upstream call to record")
    hostile = {"dotdot": "..", "enc_dotdot": "%2e%2e", "enc_slash": "a%2fb", "enc_question": "a%3Fx%3D1", "crlf": "x%0d%0aInjected:%201",
               "slash_traverse": f"{e.tenants['A']['id']}%2f..%2f{e.tenants['B']['id']}", "unicode_slash": "a%e2%88%95b", "backslash": "a%5cb"}
    for name, tid in hostile.items():
        mark = (scratch / "logs/tap.jsonl").stat().st_size
        r = e.http.request("GET", e.dash + f"/admin/tenants/{tid}/agent-health", cookies={"patched_session": owner})
        ent = tap_entries(scratch, mark)
        fwd = [x["path"] for x in ent]
        # acceptable: not forwarded, or forwarded as /admin/tenants/<one segment>/agent-health
        def fine(path):
            parts = path.split("?")[0].split("/")
            return len(parts) == 5 and parts[1] == "admin" and parts[2] == "tenants" and parts[4] == "agent-health"
        ok = all(fine(x) for x in fwd) and not any("\r" in x or "\n" in x for x in fwd) and (e.tenants["B"]["id"] not in r.text or name != "slash_traverse")
        rec.add(f"F-PASS-hostile-tenant-id-{name}", "F", "/admin/tenants/{tenant_id}/agent-health", "GET", "owner", "stays inside one path segment, or not forwarded",
                {"request_line": f"GET /admin/tenants/{tid}/agent-health", "console_status": r.status_code,
                 "forwarded": [(x["path"], x.get("status")) for x in ent]}, ok,
                "" if ok else "forwarded path differs from the route the caller named; upstream status recorded; no route reachable this way, see document")
    # inbound headers are not relayed to the platform; the console's own bearer is
    mark = (scratch / "logs/tap.jsonl").stat().st_size
    r = req("GET", fp("/admin/tenants/{tenant_id}/agent-health"), cookie=owner,
            headers={"X-Evil-Probe": "1", "X-Forwarded-For": "203.0.113.9", "Cf-Access-Jwt-Assertion": ctx.tok("A.admin"), "X-Admin-Actor": "evil@spoof.example"})
    ent = tap_entries(scratch, mark)
    names = set(ent[0]["header_names"]) if ent else set()
    rec.add("F-PASS-inbound-headers-not-relayed", "F", "/admin/tenants/{id}/agent-health", "GET", "owner with extra headers", "no inbound custom header reaches the platform; auth is the console's own admin bearer",
            sorted(names), bool(ent) and ent[0]["auth"] == "admin" and not (names & {"x-evil-probe", "x-forwarded-for", "cf-access-jwt-assertion", "x-admin-actor"}))
    mark = (scratch / "logs/tap.jsonl").stat().st_size
    r = req("GET", fp("/admin/tenants/{tenant_id}/agent-health"), cookie=owner, headers={"Authorization": "Bearer attacker-supplied"})
    ent = tap_entries(scratch, mark)
    rec.add("F-PASS-inbound-authorization-not-relayed", "F", "/admin/tenants/{id}/agent-health", "GET", "owner session plus attacker Authorization header",
            "request upstream carries the console's admin bearer, never the client's", [x["auth"] for x in ent], bool(ent) and all(x["auth"] == "admin" for x in ent) and r.status_code in (200, 401))

    # --- F-ACTOR: staff attribution is the server-resolved email, not anything the client supplies
    probe_email = "staff.probe@tenant-a.example"
    spoof = {"X-Actor": "evil@spoof.example", "X-Audit-Actor": "evil@spoof.example", HDR: "evil@spoof.example", "X-Forwarded-User": "evil@spoof.example",
             "X-Audit-Reason": "attribution probe", "Content-Type": "application/json"}
    before = len(audit_rows(scratch))
    r = req("POST", fp("/admin/tenants/{tenant_id}/portal-users"), cookie=owner, headers=spoof, body=json.dumps({"email": probe_email, "role": "viewer", "actor": "evil@spoof.example", "actor_email": "evil@spoof.example"}))
    rows = audit_rows(scratch)[before:]
    mine = [x for x in rows if x["path"].endswith("/portal-users") and x["method"] == "POST"]
    rec.add("F-ACTOR-owner-write-audit-row", "F", "POST /admin/tenants/{id}/portal-users", "POST", "owner with spoofed headers and body fields",
            "console audit row names the session email", [(x["actor_email"], x["role"], x["outcome"]) for x in mine],
            bool(mine) and all(x["actor_email"] == OWNER_STAFF and x["role"] == "owner" for x in mine) and r.status_code < 500, f"status {r.status_code}")
    users = e.admin("GET", f"/admin/portal-users?tenant_id={e.tenants['A']['id']}").text
    rec.add("F-ACTOR-platform-saw-write-with-tenant-from-path", "F", "/admin/portal-users", "GET", "admin API", "probe user exists under tenant A only", probe_email in users, probe_email in users)
    before = len(audit_rows(scratch))
    r = req("POST", fp("/admin/tenants/{tenant_id}/portal-users"), cookie=consultant, headers=spoof, body=json.dumps({"email": "staff.probe2@tenant-a.example"}))
    rows = [x for x in audit_rows(scratch)[before:] if x["path"].endswith("/portal-users")]
    rec.add("F-ACTOR-consultant-denial-audited", "F", "POST /admin/tenants/{id}/portal-users", "POST", "consultant with spoofed headers", "403 and a denied_rbac audit row naming the consultant",
            {"status": r.status_code, "rows": [(x["actor_email"], x["outcome"]) for x in rows]},
            r.status_code == 403 and bool(rows) and all(x["actor_email"] == CONSULTANT_STAFF and x["outcome"] == "denied_rbac" for x in rows))
    # bearer path: shared key, no person
    before = len(audit_rows(scratch))
    r = e.http.request("POST", e.dash + fp("/admin/tenants/{tenant_id}/portal-users"), headers={"Authorization": f"Bearer {ctx.st['dash_api_key']}", "Content-Type": "application/json", **{"X-Audit-Reason": "bearer probe"}},
                       data=json.dumps({"email": "staff.probe3@tenant-a.example", "role": "viewer"}))
    rows = [x for x in audit_rows(scratch)[before:] if x["path"].endswith("/portal-users")]
    rec.add("F-ACTOR-bearer-path-attribution", "F", "POST /admin/tenants/{id}/portal-users", "POST", "shared DASHBOARD_API_KEY bearer", "actor is a generic label, role owner (no person attributable)",
            [(x["actor_email"], x["role"]) for x in rows], bool(rows) and rows[0]["actor_email"] == "bearer-token" and rows[0]["role"] == "owner",
            "informational: the shared bearer is the rollback/script path and always owner")
    # clean up the probe users through the platform's own admin API
    for em in (probe_email, "staff.probe3@tenant-a.example"):
        e.admin("DELETE", "/admin/portal-users/" + em)

    # --- F-EDGE: the console mints an owner session from the CF header; only the edge makes that header trustworthy
    probe, rr = login(e, e.dash, "attacker@evil.example", rev)
    r = req("GET", "/admin/tenants", cookie=probe)
    rec.obs("F-EDGE-header-mints-session-for-anyone", "F", f"/console/{rev}", "GET", "client sending CF-Access-Authenticated-User-Email",
            "console must only be reachable through Cloudflare Access", {"cookie_minted": bool(probe), "then /admin/tenants": r.status_code},
            "design dependency on network placement, not a finding against the code; unproven locally")

    # --- F-BEARER: nothing the console sent upstream lacked the admin bearer
    ent = tap_entries(scratch, tap_start)
    bad = [x for x in ent if x["auth"] != "admin"]
    rec.add("F-BEARER-every-upstream-call-carries-admin-bearer", "F", "console -> platform internal API (tap log)", "*", "console process",
            "0 upstream calls without the admin bearer", {"calls": len(ent), "without_bearer": len(bad)}, bool(ent) and not bad,
            "; ".join(f"{x['method']} {x['path']} auth={x['auth']}" for x in bad[:5]))
    # the platform refuses the console's calls if the bearer were missing: direct control through the tap-free path
    r = e.http.request("GET", e.internal + f"/admin/tenants/{e.tenants['A']['id']}/agent-health")
    rec.add("F-BEARER-platform-refuses-without-bearer", "F", "/admin/tenants/{id}/agent-health (internal)", "GET", "no bearer", 401, r.status_code, r.status_code == 401)
    ctx.inventory_extra["dashboard"]["covered"] = len(cover)
    ctx.inventory_extra["dashboard"]["consultant_allowlisted_not_exercised"] = len(not_exercised)
