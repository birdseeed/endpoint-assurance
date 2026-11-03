"""Tenant-boundary and role matrix against the isolated stack (boundaries A to D and G).
Boundaries E (browser) and F (staff console) live in browser.py and staff.py.
"""
import base64
import csv
import hashlib
import hmac
import io
import json
import re
import shutil
import subprocess
import sys
import time
import zlib
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID  # noqa: F401

import ibclient
from ibclient import PRINCIPALS, NOBODY, SERVICE_CN
from common import Recorder, ZERO, fill, params_of, csrf_for, norm, digest
import idp

WRITE = ("POST", "PUT", "PATCH", "DELETE")
# Non-GET platform portal routes that change no state, so a viewer may call them. Everything else in WRITE is admin only.
# /exports/table-pdf (PAT-2405) renders the table in its body as a PDF and stores nothing; it is a POST only because the
# rows travel in the body. Its one admin-only export key is checked separately in section C.
STATELESS_WRITES = {"/exports/table-pdf"}
# Ruled 2026-10-05 (PAT-2406, PAT-2408): "Viewers can generate reports but only admins change schedules; the Local
# Admin report is admin-only." POST /reports is therefore the one stored write open to every role, and the report
# history is the one part of the tenant snapshot a viewer is allowed to add to. The admin-only report is checked
# separately in sections C and D.
VIEWER_GENERATES = "/reports"
VIEWER_MAY_ADD_TO = {"/reports"}
ADMIN_ONLY_REPORT = "local-admin"
# PAT-1883: self-service sign-up and access management, behind SELF_SERVICE_SIGNUP_ENABLED (default off, and off in
# this harness: `ib` does not set it). While it is off every one of these routes answers 404 to any verified caller.
# The expectations below hold in either state, so the matrix does not have to be edited when the flag is turned on.
#   /signup/*  the pre-membership group: it needs no tenant mapping, so a verified person with no membership is not
#              refused 403 there as on every other /v1/portal route. Its only identity is the verified email.
#   /access*   ordinary tenant routes; the writes are owner only, so an admin is refused as well as a viewer.
SIGNUP_PREFIX = "/signup/"
ACCESS_PREFIX = "/access"


def is_signup(tmpl):
    return tmpl.startswith(SIGNUP_PREFIX)


def is_access(tmpl):
    return tmpl == ACCESS_PREFIX or tmpl.startswith(ACCESS_PREFIX + "/")


class Ctx:
    def __init__(self, st, scratch):
        self.st, self.scratch = st, Path(scratch)
        self.e = ibclient.Env(st, scratch)
        self.rec = Recorder()
        self.objs = st["objects"]
        self._tok = {}
        self.plat_routes = json.loads((self.scratch / "results/platform-routes.json").read_text())
        self.portal_routes = introspect("portal", self.scratch, st)
        self.pr = [(r["method"], r["path"]) for r in self.plat_routes
                   if r["surface"] == "public" and r["path"].startswith("/v1/portal")]
        self.internal = [(r["method"], r["path"]) for r in self.plat_routes if r["surface"] == "internal"]
        self.public_all = [(r["method"], r["path"]) for r in self.plat_routes if r["surface"] == "public"]
        for L in "AB":
            o = self.objs[L]
            dl = o.get("device_list_raw") or {}
            entries = (dl.get("on_list_never_seen") or []) + (dl.get("matched") or [])
            o["entry_id"] = str(entries[0]["entry_id"]) if entries else "0"

    def who_email(self, who):
        L, role = who.split(".")
        if role == "service":
            return None
        return PRINCIPALS[L][role]

    def tok(self, who):
        if who not in self._tok:
            if who.endswith(".service"):
                self._tok[who] = self.e.minter.mint(common_name=SERVICE_CN, ttl=7200)
            else:
                self._tok[who] = self.e.minter.mint(email=self.who_email(who), ttl=7200)
        return self._tok[who]

    def markers(self, Y):
        o = self.objs[Y]
        m = [f"CANARY-{Y}-", self.e.tenants[Y]["id"], o["device_id"], o["device_id_2"], o["win_device_id"], o["cert_id"],
             o["decl_id"], o["report_id"], o["enrol_key_id"]]
        if o.get("jamf_token_marker"):
            m.append(o["jamf_token_marker"])
        m.append(self.e.tenants[Y]["bearer"])
        m.append(self.e.tenants[Y]["hmac_b64"])
        return m

    def leaks(self, text, Y, ignore=()):
        """Foreign markers present in text. Values the attacker itself supplied (an id in the path, a tenant
        id in the query) are removed first: a not-found page echoing the requested id is reflection, not leakage."""
        from urllib.parse import quote
        for v in ignore:
            v = str(v)
            for form in {v, quote(v, safe=""), v.replace("-", "&#45;")}:
                text = text.replace(form, "")
        return [m for m in self.markers(Y) if m and m in text]

    def papi(self, who, method, path, **kw):
        return self.e.papi(method, path, self.tok(who) if who else None, **kw)

    def portal(self, who, method, path, headers=None, data=None, token=None, **kw):
        h = {"Cf-Access-Jwt-Assertion": token if token is not None else self.tok(who)}
        if headers:
            h.update(headers)
        return self.e.http.request(method, self.e.portal + path, headers=h, data=data, **kw)

    def snap(self, Y):
        o = self.objs[Y]
        paths = ["/certificates", "/device-list", "/software-declarations", "/enrolment-keys", "/software-notifications",
                 "/reports", "/reports/schedules", "/devices", f"/devices/{o['device_id_2']}/retirement/history",
                 "/software-approvals/history", "/mdm/jamf/setup", "/software-alerts", "/agent-releases", "/overview"]
        out = {}
        for p in paths:
            r = self.papi(f"{Y}.admin", "GET", p)
            try:
                out[p] = r.json()
            except Exception:
                out[p] = r.text
        return out


def introspect(name, scratch, st):
    out = Path(scratch) / f"results/{name}-routes.json"
    src = Path(scratch) / "src" / name
    here = Path(__file__).resolve().parent
    if name == "portal":
        py = ibclient_portal_python()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch / "home"), "PLATFORM_BASE_URL": "http://127.0.0.1:1",
               "PORTAL_ACCESS_TEAM_DOMAIN": "127.0.0.1:1", "PORTAL_ACCESS_AUD": "x"}
    else:
        py = str(Path(scratch) / "venv-dash/bin/python")
        (Path(scratch) / "dash-state-introspect").mkdir(exist_ok=True)
        env = {"PATH": "/usr/bin:/bin", "HOME": str(scratch / "home"), "DASHBOARD_DB_PATH": str(scratch / "dash-introspect.db"),
               "DASHBOARD_STATE_DIR": str(scratch / "dash-state-introspect"), "PATCHED_API_INTERNAL": "http://127.0.0.1:1",
               "DASHBOARD_API_KEY": "x", "ADMIN_API_TOKEN": "x"}
    r = subprocess.run([py, str(here / "introspect.py"), str(out)], cwd=src, env=env, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f"introspection of {name} failed: {r.stderr[-800:]}")
    return json.loads(out.read_text())


def ibclient_portal_python():
    import os
    return os.environ.get("IB_PORTAL_PYTHON", sys.executable)


# ---------------------------------------------------------------------------------------------------------------
# Token variants (boundary A)
# ---------------------------------------------------------------------------------------------------------------
def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def jwt_variants(ctx):
    m, now = ctx.e.minter, int(time.time())
    viewer = PRINCIPALS["A"]["viewer"]
    good = ctx.tok("A.viewer")
    head, payload, sig = good.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["email"] = PRINCIPALS["A"]["admin"]
    tampered = ".".join([head, b64u(json.dumps(claims).encode()), sig])
    pub_pem = serialization.load_pem_private_key(m.signing, None).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    hs_head = b64u(json.dumps({"alg": "HS256", "typ": "JWT", "kid": idp.KID}).encode())
    hs_pay = b64u(json.dumps({"iss": m.issuer, "aud": [m.audience], "email": viewer, "exp": now + 600}).encode())
    hs_sig = b64u(hmac.new(pub_pem, f"{hs_head}.{hs_pay}".encode(), hashlib.sha256).digest())
    return [
        # name, token (None = header absent), expected status
        ("no_header", None, 401), ("empty_header", "", 401), ("malformed", "not-a-jwt", 401), ("two_part", "aaaa.bbbb", 401),
        ("expired", m.mint(email=viewer, exp=now - 3600), 401),
        ("not_yet_valid", m.mint(email=viewer, nbf=now + 3600), 401),
        ("wrong_issuer", m.mint(email=viewer, iss="https://evil.example"), 401),
        ("wrong_audience", m.mint(email=viewer, aud="some-other-aud"), 401),
        ("rogue_key_right_kid", m.mint(email=viewer, key="rogue"), 401),
        ("rogue_key_unknown_kid", m.mint(email=viewer, key="rogue", kid="attacker-kid"), 401),
        ("alg_none", m.mint_unsigned_for_denial_tests(email=viewer), 401),
        ("alg_hs256_public_key_secret", f"{hs_head}.{hs_pay}.{hs_sig}", 401),
        ("payload_tampered_email", tampered, 401),
        ("no_email_no_common_name", m.mint(), 401),
        ("empty_email", m.mint(email=""), 401),
        ("service_wrong_common_name", m.mint(common_name="not-the-allowlisted-token"), 401),
        ("valid_no_membership", m.mint(email=NOBODY), 403),
        ("valid_disabled_membership_A", m.mint(email=PRINCIPALS["A"]["disabled"]), 403),
        ("valid_disabled_membership_B", m.mint(email=PRINCIPALS["B"]["disabled"]), 403),
    ]


def section_a(ctx):
    rec, e = ctx.rec, ctx.e
    variants = jwt_variants(ctx)
    # Platform portal API, every route
    for (method, path) in ctx.pr:
        rec.cover("platform_portal", method, path)
        url_path = path[len("/v1/portal"):]
        for name, token, want in variants:
            body = {} if method in WRITE else None
            r = e.papi(method, fill(url_path), token, body=body)
            ok = r.status_code == want
            if is_signup(url_path) and want == 403:
                # A verified person with no (or a disabled) membership is who this group is for: 404 while the feature
                # is off; with it on, their own state (200), a refused body (400), a missing invitation (404) or
                # "already belongs somewhere" for the disabled member (409). Never another tenant's data.
                want, ok = "404 (feature off), or 200/400/404/409 from the sign-up handler", r.status_code in (200, 400, 404, 409)
            rec.add(f"A-PLAT-{method}-{path}-{name}", "A", f"/v1/portal{url_path}", method, f"token:{name}", want, r.status_code,
                    ok and not any(ctx.leaks(r.text, L) for L in "AB"))
        # valid bearer header instead of the Access header
        r = e.http.request(method, e.public + fill(path), headers={"Authorization": "Bearer " + ctx.tok("A.admin")},
                           data=b"{}" if method in WRITE else None)
        rec.add(f"A-PLAT-{method}-{path}-authorization_header_instead", "A", path, method, "valid JWT in Authorization header", 401,
                r.status_code, r.status_code == 401)
        # token in query string and cookie must not authenticate
        r = e.http.request(method, e.public + fill(path), params={"Cf-Access-Jwt-Assertion": ctx.tok("A.admin")},
                           cookies={"CF_Authorization": ctx.tok("A.admin")}, data=b"{}" if method in WRITE else None)
        rec.add(f"A-PLAT-{method}-{path}-query_and_cookie_only", "A", path, method, "valid JWT in query/cookie only", 401,
                r.status_code, r.status_code == 401)
        # service identity on every non-GET route
        if method not in ("GET", "HEAD"):
            r = ctx.papi("A.service", method, fill(url_path), body={})
            rec.add(f"A-PLAT-{method}-{path}-service_write", "A", path, method, "service identity", "403 read-only",
                    r.status_code, r.status_code == 403 and "read-only" in r.text.lower(), r.text[:80])
    # Portal itself, every route
    routes = [(m, r["path"]) for r in ctx.portal_routes["routes"] for m in (r["methods"] or [])
              if r["path"] not in ("/healthz",) and not r["path"].startswith("/static")]
    for method, path in routes:
        rec.cover("portal", method, path)
        for name, token, want in variants:
            h = {"Origin": e.portal}
            if token is not None:
                h["Cf-Access-Jwt-Assertion"] = token
            r = e.http.request(method, e.portal + fill(path), headers=h, data={} if method in WRITE else None)
            if want == 403:
                ok = r.status_code == 403 or (r.status_code == 200 and "CANARY" not in r.text and method == "GET")
                exp = "403 (or 200 with no tenant data where the page never calls the platform)"
            else:
                ok = r.status_code == 401
                exp = 401
            ok = ok and not any(ctx.leaks(r.text, L) for L in "AB")
            rec.add(f"A-PORTAL-{method}-{path}-{name}", "A", path, method, f"token:{name}", exp, r.status_code, ok)
        if method not in ("GET", "HEAD"):
            r = ctx.portal("A.service", method, fill(path), headers={"Origin": e.portal}, data={})
            rec.add(f"A-PORTAL-{method}-{path}-service_write", "A", path, method, "service identity", 403, r.status_code,
                    r.status_code == 403 and "read-only" in r.text.lower())
    # exempt paths
    for p in ("/healthz",):
        r = e.http.request("GET", e.portal + p)
        rec.add(f"A-PORTAL-exempt{p}", "A", p, "GET", "none", 200, r.status_code, r.status_code == 200)
    r = e.http.request("GET", e.portal + "/static/does-not-exist.css")
    rec.add("A-PORTAL-static-miss", "A", "/static/*", "GET", "none", "404 (no data)", r.status_code, r.status_code in (200, 404) and "CANARY" not in r.text)
    # cookie transport on the portal; header precedence
    r = e.http.request("GET", e.portal + "/devices", cookies={"CF_Authorization": ctx.tok("A.viewer")})
    rec.add("A-PORTAL-cookie-valid", "A", "/devices", "GET", "A.viewer via CF_Authorization cookie", 200, r.status_code, r.status_code == 200)
    r = e.http.request("GET", e.portal + "/devices", cookies={"CF_Authorization": "garbage"})
    rec.add("A-PORTAL-cookie-garbage", "A", "/devices", "GET", "garbage cookie", 401, r.status_code, r.status_code == 401)
    r = e.http.request("GET", e.portal + "/devices", headers={"Cf-Access-Jwt-Assertion": "garbage"},
                       cookies={"CF_Authorization": ctx.tok("A.viewer")})
    rec.add("A-PORTAL-bad-header-good-cookie", "A", "/devices", "GET", "bad header, good cookie", "401 (header wins) or refused", r.status_code,
            r.status_code == 401, "header takes precedence over cookie")
    # forged identity headers are never a credential
    r = e.http.request("GET", e.portal + "/devices", headers={"Cf-Access-Authenticated-User-Email": PRINCIPALS["A"]["admin"]})
    rec.add("A-PORTAL-forged-email-header-only", "A", "/devices", "GET", "Cf-Access-Authenticated-User-Email only", 401, r.status_code, r.status_code == 401)
    r = e.http.request("GET", e.public + "/v1/portal/me", headers={"Cf-Access-Authenticated-User-Email": PRINCIPALS["A"]["admin"]})
    rec.add("A-PLAT-forged-email-header-only", "A", "/v1/portal/me", "GET", "Cf-Access-Authenticated-User-Email only", 401, r.status_code, r.status_code == 401)
    # service identity: GET allowed, scoped to tenant A, role is service_readonly
    r = ctx.papi("A.service", "GET", "/me")
    rec.add("A-PLAT-service-me", "A", "/v1/portal/me", "GET", "A.service", "200 tenant A, not admin", r.status_code,
            r.status_code == 200 and ctx.e.tenants["A"]["id"] in r.text and '"admin"' not in r.text, r.text[:120])
    # a token carrying BOTH an email and the service common name is a person's, never the service identity
    both = e.minter.mint(email=PRINCIPALS["A"]["viewer"], common_name=SERVICE_CN)
    r = e.papi("GET", "/me", both)
    rec.add("A-PLAT-email-plus-service-cn-is-person", "A", "/v1/portal/me", "GET", "email A.viewer plus service common_name",
            "200, role viewer, not service_readonly", r.status_code, r.status_code == 200 and '"viewer"' in r.text and "service" not in r.text, r.text[:100])
    r = e.papi("POST", "/software-declarations", both, body={"name": "x", "publisher": "p", "platform": "macos", "justification": "j"})
    rec.add("A-PLAT-email-plus-service-cn-write-follows-person-role", "A", "/v1/portal/software-declarations", "POST", "email A.viewer plus service common_name",
            "403 admin_role_required (person's viewer role), not the service read-only refusal", r.status_code,
            r.status_code == 403 and "read-only" not in r.text.lower(), r.text[:100])
    r = e.papi("GET", "/me", e.minter.mint(email=NOBODY, common_name=SERVICE_CN))
    rec.add("A-PLAT-email-plus-service-cn-unmapped-email", "A", "/v1/portal/me", "GET", "unmapped email plus service common_name",
            "403 (judged as the email, not as the service)", r.status_code, r.status_code == 403)
    r = ctx.portal(None, "GET", "/", token=both)
    rec.add("A-PORTAL-email-plus-service-cn-is-person", "A", "/", "GET", "email A.viewer plus service common_name",
            "200 as a person, never shown as the read-only service account", r.status_code,
            r.status_code == 200 and "Read-only service account" not in r.text)
    r = ctx.portal(None, "POST", "/software/add", headers={"Origin": e.portal, "Content-Type": "application/x-www-form-urlencoded"},
                   data={"csrf_token": csrf_for(both)}, token=both)
    rec.add("A-PORTAL-email-plus-service-cn-write-not-service-refusal", "A", "/software/add", "POST", "email A.viewer plus service common_name",
            "judged as a viewer, not refused as the read-only service account", r.status_code, "read-only" not in r.text.lower())
    r = ctx.portal(None, "GET", "/", token=e.minter.mint(email=NOBODY, common_name=SERVICE_CN))
    rec.add("A-PORTAL-email-plus-service-cn-unmapped-email", "A", "/", "GET", "unmapped email plus service common_name", 403, r.status_code, r.status_code == 403)
    # email case and whitespace variants resolve to the same membership, never to another
    for name, em in (("upper_case", PRINCIPALS["A"]["viewer"].upper()), ("trailing_space", PRINCIPALS["A"]["viewer"] + " "),
                     ("plus_tag", PRINCIPALS["A"]["viewer"].replace("@", "+x@"))):
        r = ctx.e.papi("GET", "/me", ctx.e.minter.mint(email=em))
        txt = r.text
        ok = (r.status_code == 200 and ctx.e.tenants["A"]["id"] in txt and '"viewer"' in txt) if name != "plus_tag" else r.status_code in (200, 403) and not ctx.leaks(txt, "B")
        rec.add(f"A-PLAT-email-variant-{name}", "A", "/v1/portal/me", "GET", f"email {name}", "same member or refused, never another tenant", r.status_code, ok, txt[:100])


# ---------------------------------------------------------------------------------------------------------------
# Bodies
# ---------------------------------------------------------------------------------------------------------------
def b64cert(cn):
    import seed
    return base64.b64encode(seed.make_cert(cn)).decode()


def write_body(ctx, method, tmpl, attacker_label, victim=None):
    o = ctx.objs[victim or attacker_label]
    key = (method, tmpl)
    bodies = {
        ("PUT", "/agent-releases"): {"action": "device_channels", "device_ids": [o["device_id"]], "channel": "beta"},
        ("POST", "/certificates"): {"label": f"CANARY-{attacker_label}-HACK", "certificate": b64cert(f"CANARY-{attacker_label}-HACKCERT")},
        ("PATCH", "/certificates/{id}"): {"label": f"CANARY-{attacker_label}-HACKLABEL"},
        ("PUT", "/device-list"): {"filename": f"CANARY-{attacker_label}-hack.csv", "entries": [{"hostname": f"CANARY-{attacker_label}-HACKLISTED"}]},
        ("PUT", "/devices/{deviceID}/retirement"): {"retired": True, "reason": f"CANARY-{attacker_label}-HACK"},
        ("POST", "/enrolment"): {},
        ("POST", "/exports/table-pdf"): {"export": "devices", "columns": ["Hostname"], "rows": [[f"CANARY-{attacker_label}-HACKROW"]]},
        ("POST", "/enrolment-keys"): {"label": f"CANARY-{attacker_label}-HACKKEY", "max_devices": 2, "expires_in_days": 1},
        ("POST", "/feedback"): {"type": "feature", "title": f"CANARY-{attacker_label}-HACK title", "description": "hack hack hack hack"},
        ("DELETE", "/mdm/jamf/devices"): {"device_ids": [o["device_id"]]},
        ("PUT", "/mdm/jamf/setup"): {"check_in_enabled": True},
        ("POST", "/mdm/jamf/token"): {},
        ("POST", "/reports"): {"report_type": "executive-summary"},
        ("PUT", "/reports/schedule"): {"cadence": "weekly", "weekday": 1, "hour_utc": 3 if attacker_label == "A" else 5, "enabled": False},
        ("PUT", "/reports/schedules/{reportType}"): {"cadence": "weekly", "weekday": 1, "hour_utc": 3 if attacker_label == "A" else 5, "enabled": False},
        ("POST", "/software-alerts/{id}/acknowledge"): {"note": f"CANARY-{attacker_label}-HACKNOTE"},
        ("PUT", "/software-approvals"): {"items": [{"type": "application", "platform": "macos",
                                                    "identifier": f"com.canary{(victim or attacker_label).lower()}.app1",
                                                    "team_id": f"CNRY{victim or attacker_label}00001"}],
                                         "state": "approved", "reason": f"CANARY-{attacker_label}-HACK"},
        ("POST", "/software-declarations"): {"name": f"CANARY-{attacker_label}-HACKDECL", "publisher": "p", "platform": "macos", "justification": "j"},
        ("POST", "/software-declarations/{declarationID}/resolve"): {"alias_id": ZERO, "justification": f"CANARY-{attacker_label}-HACK"},
        ("PUT", "/software-notifications"): {"unapproved_alerts_enabled": False, "new_software_enabled": True},
        # PAT-1883. Well-formed bodies, so that with the feature on the answer is the membership or role decision and
        # not a 400. These routes decode strictly: a body carrying a tenant id or an identity is refused 400 (platform
        # tests cover that), which would hide the decision this matrix is here to check. Accept, revoke, disable and
        # enable take no body and get {} from the default below.
        ("POST", "/signup/organisation"): {"name": f"CANARY-{attacker_label}-HACKORG"},
        ("POST", "/access/invitations"): {"email": f"canary-{attacker_label.lower()}-hack@invited.example", "role": "admin"},
        ("PUT", "/access/members/{memberEmail}/role"): {"role": "admin"},
    }
    return bodies.get(key, {} if method in WRITE else None)


def obj_values(ctx, tmpl, Y):
    o = ctx.objs[Y]
    names = params_of(tmpl)
    if not names:
        return [{}]
    vals = []
    for p in names:
        pl = p.lower()
        if pl in ("deviceid", "device_id"):
            c = [o["device_id"], o["device_id_2"], o["win_device_id"]]
        elif pl in ("declarationid", "declaration_id"):
            c = [o["decl_id"]]
        elif pl in ("keyid", "key_id"):
            c = [o["enrol_key_id"]]
        elif pl in ("entryid", "entry_id"):
            c = [o["entry_id"]]
        elif pl == "reporttype":
            c = ["executive-summary"]
        elif pl == "record_id":
            c = [o["cert_id"]]
        elif pl == "report_id":
            c = [o["report_id"]]
        elif pl == "alert_id":
            c = [str(a) for a in o["alert_ids"]] or ["0"]
        elif pl == "id":
            c = [o["cert_id"]] if "certificates" in tmpl else [o["report_id"]] if "reports" in tmpl else \
                [str(a) for a in o["alert_ids"]] or ["0"]
        elif pl == "memberemail":
            # PAT-1883: the victim tenant's real member addresses. From another tenant each must answer 404.
            c = [PRINCIPALS[Y]["viewer"], PRINCIPALS[Y]["admin"]]
        else:
            c = [ZERO]
        vals.append((p, c))
    out = [{}]
    for p, c in vals:
        out = [dict(d, **{p: x}) for d in out for x in c]
    return out


def wait_for(cond, what, timeout=45):
    """Bounded poll; fail the run clearly if the condition never holds."""
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return
        time.sleep(0.5)
    raise SystemExit(f"timed out after {timeout}s waiting for: {what}")


def own_values_ok(ctx, tmpl, attacker, r):
    """Type-scoped routes (reportType) return the caller's own tenant configuration."""
    if "reportType" in tmpl and r.status_code == 200:
        want = 3 if attacker == "A" else 5
        try:
            return r.json().get("hour_utc") == want
        except Exception:
            return False
    return None


# ---------------------------------------------------------------------------------------------------------------
# B: cross tenant
# ---------------------------------------------------------------------------------------------------------------
ATTACKERS = {"A": ["A.admin", "A.viewer", "A.domain", "A.service"], "B": ["B.admin", "B.viewer", "B.domain"]}
TENANT_PARAMS = ["tenant_id", "tenantId", "tenant", "tenantID", "org_id"]
TENANT_HEADERS = ["X-Tenant-ID", "X-Patched-Tenant", "X-Tenant", "Tenant-Id"]


def section_b(ctx):
    rec, e = ctx.rec, ctx.e
    ctx.b_diffs = {}
    for X, Y in (("A", "B"), ("B", "A")):
        before_y = ctx.snap(Y)
        for who in ATTACKERS[X]:
            # --- platform portal API
            for method, path in ctx.pr:
                tmpl = path[len("/v1/portal"):]
                is_write = method in WRITE
                for vals in obj_values(ctx, tmpl, Y):
                    p = fill(tmpl, vals)
                    if who.endswith(".service") and is_write:
                        continue  # covered in A
                    body = write_body(ctx, method, tmpl, X, victim=Y) if is_write else None
                    r = ctx.papi(who, method, p, body=body)
                    own = own_values_ok(ctx, tmpl, X, r) if method == "GET" else None
                    leak = ctx.leaks(r.text, Y, ignore=vals.values())
                    if "reportType" in tmpl and is_write:
                        ok, exp = not leak and r.status_code < 500, "own-tenant type-scoped write; no foreign data"
                    elif params_of(tmpl) and own is None:
                        ok = r.status_code in (400, 403, 404, 405, 409, 422) and not leak
                        exp = "403/404 and no foreign data"
                    elif own is not None:
                        ok, exp = own and not leak, "own tenant configuration only"
                    elif is_write:
                        ok, exp = not leak, "no foreign data (state diff checked after)"
                    else:
                        ok, exp = r.status_code < 500 and not leak, "no foreign data"
                    rec.add(f"B-PLAT-{who}-{method}-{path}-{'/'.join(map(str, vals.values())) or 'noid'}", "B", f"/v1/portal{p}", method,
                            f"{who} -> {Y}", exp, r.status_code, ok, ("LEAK " + str(leak)) if leak else "")
                if not is_write:
                    # tenant-naming query parameters and headers must be ignored or refused
                    if not params_of(tmpl):
                        base = ctx.papi(who, method, tmpl)
                        for qp in TENANT_PARAMS:
                            r = ctx.papi(who, method, tmpl, params={qp: e.tenants[Y]["id"]})
                            leak = ctx.leaks(r.text, Y, ignore=[e.tenants[Y]["id"]])
                            rec.add(f"B-PLAT-{who}-{method}-{path}-q-{qp}", "B", f"/v1/portal{tmpl}?{qp}=<victim>", method, f"{who} -> {Y}",
                                    f"{base.status_code} like baseline, or 4xx; no foreign data", r.status_code,
                                    not leak and r.status_code in (base.status_code, 400, 403, 404, 422))
                        r = ctx.papi(who, method, tmpl, headers={h: e.tenants[Y]["id"] for h in TENANT_HEADERS})
                        leak = ctx.leaks(r.text, Y, ignore=[e.tenants[Y]["id"]])
                        rec.add(f"B-PLAT-{who}-{method}-{path}-hdr", "B", f"/v1/portal{tmpl} + tenant headers", method, f"{who} -> {Y}",
                                "no foreign data", r.status_code, not leak and r.status_code in (base.status_code, 400, 403, 404, 422))
            # --- the portal's own routes (GET reads)
            # The service identity is exercised on every portal GET read here (refused on non-GET routes: boundary A and the POST block below).
            for rt in ctx.portal_routes["routes"]:
                for method in rt["methods"]:
                    path = rt["path"]
                    if path in ("/healthz",) or path.startswith("/static"):
                        continue
                    if method != "GET":
                        continue
                    for vals in obj_values(ctx, path, Y):
                        p = fill(path, vals)
                        r = ctx.portal(who, "GET", p)
                        leak = ctx.leaks(r.text, Y, ignore=vals.values()) + ctx.leaks(r.headers.get("Location", ""), Y, ignore=vals.values())
                        if params_of(path):
                            ok = r.status_code in (400, 403, 404, 422) and not leak
                            exp = "403/404 and no foreign data"
                        else:
                            ok, exp = r.status_code < 500 and not leak, "no foreign data"
                        rec.add(f"B-PORTAL-{who}-GET-{path}-{'/'.join(map(str, vals.values())) or 'noid'}", "B", p, "GET", f"{who} -> {Y}",
                                exp, r.status_code, ok, ("LEAK " + str(leak)) if leak else "")
                        if not params_of(path):
                            r2 = ctx.portal(who, "GET", p + ("&" if "?" in p else "?") + "tenant_id=" + e.tenants[Y]["id"])
                            leak2 = ctx.leaks(r2.text, Y, ignore=[e.tenants[Y]["id"]])
                            rec.add(f"B-PORTAL-{who}-GET-{path}-q-tenant_id", "B", p + "?tenant_id=<victim>", "GET", f"{who} -> {Y}",
                                    "no foreign data", r2.status_code, not leak2 and r2.status_code < 500)
            # portal POST routes: Origin and CSRF correct, victim object ids, tenant fields in the form
            if not who.endswith(".service"):
                tokv = ctx.tok(who)
                for rt in ctx.portal_routes["routes"]:
                    for method in rt["methods"]:
                        if method != "POST":
                            continue
                        path = rt["path"]
                        for vals in obj_values(ctx, path, Y):
                            form = {"csrf_token": csrf_for(tokv), "tenant_id": e.tenants[Y]["id"], "tenant": e.tenants[Y]["id"],
                                    "device_id": ctx.objs[Y]["device_id_2"], "retired": "true", "reason": f"CANARY-{X}-HACK",
                                    "alias_id": ZERO, "justification": f"CANARY-{X}-HACK", "note": "x", "label": f"CANARY-{X}-HACKLABEL",
                                    "cadence": "weekly", "weekday": "1", "hour_utc": "3" if X == "A" else "5", "report_type": "executive-summary"}
                            r = ctx.portal(who, "POST", fill(path, vals), headers={"Origin": e.portal,
                                           "Content-Type": "application/x-www-form-urlencoded"}, data=form)
                            leak = ctx.leaks(r.text, Y, ignore=list(vals.values()) + [e.tenants[Y]["id"], ctx.objs[Y]["device_id_2"]]) + ctx.leaks(r.headers.get("Location", ""), Y, ignore=list(vals.values()) + [e.tenants[Y]["id"], ctx.objs[Y]["device_id_2"]])
                            rec.add(f"B-PORTAL-{who}-POST-{path}-{'/'.join(map(str, vals.values())) or 'noid'}", "B", fill(path, vals),
                                    "POST", f"{who} -> {Y}", "refused or no-op; no foreign data; victim state unchanged (diff below)",
                                    r.status_code, not leak and r.status_code < 500, ("LEAK " + str(leak)) if leak else "")
        after_y = ctx.snap(Y)
        moved = [k for k in before_y if digest(before_y[k]) != digest(after_y[k])]
        rec.add(f"B-STATE-victim-{Y}-unchanged-after-{X}-attacks", "B", f"snapshot of tenant {Y} (14 portal reads)", "GET", f"{Y}.admin",
                f"no object of tenant {Y} changed by any request made as tenant {X}", ", ".join(moved) or "no diff", not moved,
                "; ".join(f"{k}: {json.dumps(norm(before_y[k]))[:200]} -> {json.dumps(norm(after_y[k]))[:200]}" for k in moved)[:1200])
        ctx.b_diffs[Y] = moved
    ingest_cross(ctx)
    positive_controls(ctx)


def positive_controls(ctx):
    """Prove the detector can see data: every tenant's own admin must retrieve its own markers and own object ids."""
    rec = ctx.rec
    rec.add("B-CONTROL-detector", "B", "harness", "n/a", "n/a", "leak detector flags a foreign marker", "flagged" if ctx.leaks("x CANARY-B-HOST-1 y", "B") else "missed",
            bool(ctx.leaks("x CANARY-B-HOST-1 y", "B")))
    for L in "AB":
        hits_plat = hits_portal = obj_ok = obj_total = 0
        for method, path in ctx.pr:
            tmpl = path[len("/v1/portal"):]
            if method != "GET":
                continue
            if params_of(tmpl):
                for vals in obj_values(ctx, tmpl, L):
                    r = ctx.papi(f"{L}.admin", "GET", fill(tmpl, vals))
                    if "reportType" in tmpl:
                        continue
                    obj_total += 1
                    obj_ok += r.status_code == 200
            else:
                r = ctx.papi(f"{L}.admin", "GET", tmpl)
                hits_plat += any(m in r.text for m in ctx.markers(L))
        for rt in ctx.portal_routes["routes"]:
            for method in rt["methods"]:
                if method != "GET" or rt["path"] in ("/healthz",) or rt["path"].startswith("/static") or params_of(rt["path"]):
                    continue
                r = ctx.portal(f"{L}.admin", "GET", rt["path"])
                hits_portal += any(m in r.text for m in ctx.markers(L))
        rec.add(f"B-CONTROL-own-data-visible-{L}", "B", "platform GET routes without ids", "GET", f"{L}.admin",
                "own markers appear in at least 8 platform and 8 portal responses", {"platform": hits_plat, "portal": hits_portal},
                hits_plat >= 8 and hits_portal >= 8)
        rec.add(f"B-CONTROL-own-objects-readable-{L}", "B", "platform GET routes with ids (own ids)", "GET", f"{L}.admin",
                "own object ids resolve (200) on most routes, so the foreign 404s are meaningful", {"ok": obj_ok, "total": obj_total},
                obj_total > 0 and obj_ok >= obj_total // 2)


def ingest_cross(ctx):
    rec, e = ctx.rec, ctx.e
    a, b = e.tenants["A"], e.tenants["B"]

    def signed(label_bearer, label_secret, body, ts=None, nonce=None):
        raw = json.dumps(body).encode()
        sig = hmac.new(base64.b64decode(e.tenants[label_secret]["hmac_b64"]), raw, hashlib.sha256).hexdigest()
        h = {"Content-Type": "application/json", "Authorization": f"Bearer {e.tenants[label_bearer]['bearer']}",
             "X-Patched-Signature": sig, "X-Patched-Timestamp": str(ts or int(time.time())),
             "X-Patched-Nonce": nonce or hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:32]}
        return e.http.request("POST", e.public + "/v1/inventory", data=raw, headers=h), h, raw

    import seed
    seed.ibclient_tenant.update({"A": a["id"], "B": b["id"]})
    p = seed.mac_payload("A", 7)
    p["device"].update(serial="SER-A-INJECT-1", hw_uuid="AAAAAAAA-7777-4777-8777-777777777777", hostname="CANARY-A-INJECTED")
    r, _, _ = signed("A", "B", p)
    rec.add("B-INGEST-bearerA-with-hmacB", "B", "/v1/inventory", "POST", "A bearer, B HMAC secret", 401, r.status_code, r.status_code == 401)
    r, _, _ = signed("B", "A", p)
    rec.add("B-INGEST-bearerB-with-hmacA", "B", "/v1/inventory", "POST", "B bearer, A HMAC secret", 401, r.status_code, r.status_code == 401)
    r, h, raw = signed("A", "A", p, ts=int(time.time()) - 7200)
    rec.add("B-INGEST-stale-timestamp", "B", "/v1/inventory", "POST", "A", "refused", r.status_code, r.status_code in (400, 401, 403))
    p2 = json.loads(json.dumps(p))
    p2["tenant_id"] = b["id"]  # body names tenant B while authenticating as A
    p2["device"].update(serial="SER-A-INJECT-2", hw_uuid="AAAAAAAA-7777-4777-8777-777777777778", hostname="CANARY-A-INJECTED-BODYTENANT")
    r, h, raw = signed("A", "A", p2)
    if r.status_code == 200:
        wait_for(lambda: "CANARY-A-INJECTED-BODYTENANT" in ctx.papi("A.admin", "GET", "/devices").text,
                 "extractor to materialise the injected device under tenant A")
    b_devs = ctx.papi("B.admin", "GET", "/devices").text
    a_devs = ctx.papi("A.admin", "GET", "/devices").text
    rec.add("B-INGEST-body-tenant-id-names-B", "B", "/v1/inventory", "POST", "A creds, payload tenant_id=B", "refused, or stored under A only",
            r.status_code, "CANARY-A-INJECTED-BODYTENANT" not in b_devs and "CANARY-A-" not in b_devs,
            f"status {r.status_code}; appears under A: {'CANARY-A-INJECTED-BODYTENANT' in a_devs}")
    nonce = "replaynonce" + hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:20]
    p3 = json.loads(json.dumps(p))
    p3["device"].update(serial="SER-A-INJECT-3", hw_uuid="AAAAAAAA-7777-4777-8777-777777777779", hostname="CANARY-A-REPLAY")
    r1, h, raw = signed("A", "A", p3, nonce=nonce)
    r2 = e.http.request("POST", e.public + "/v1/inventory", data=raw, headers=h)
    rec.add("B-INGEST-replay-same-nonce", "B", "/v1/inventory", "POST", "A", "second use refused", [r1.status_code, r2.status_code],
            r1.status_code == 200 and r2.status_code in (400, 401, 403, 409))
    for method, path in (("GET", "/v1/devices/{deviceID}/removal-tasks/pending"), ("POST", "/v1/devices/{deviceID}/removal-tasks/report")):
        vid = ctx.objs["B"]["device_id"]
        raw = b"{}" if method == "POST" else b""
        sig = hmac.new(base64.b64decode(a["hmac_b64"]), raw, hashlib.sha256).hexdigest()
        h = {"Authorization": f"Bearer {a['bearer']}", "X-Patched-Signature": sig, "X-Patched-Timestamp": str(int(time.time())),
             "X-Patched-Nonce": hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:32]}
        r = e.http.request(method, e.public + path.replace("{deviceID}", vid), headers=h, data=raw or None)
        rec.add(f"B-INGEST-{method}-removal-tasks-foreign-device", "B", path, method, "A creds, B device id",
                "403/404 or empty, no foreign data", r.status_code, r.status_code in (200, 400, 401, 403, 404, 405, 410, 422) and not ctx.leaks(r.text, "B"), r.text[:80])
    for method, path in (("GET", "/v1/agent-config"), ("GET", "/v1/posture")):
        sig = hmac.new(base64.b64decode(a["hmac_b64"]), b"", hashlib.sha256).hexdigest()
        h = {"Authorization": f"Bearer {a['bearer']}", "X-Patched-Signature": sig, "X-Patched-Timestamp": str(int(time.time())),
             "X-Patched-Nonce": hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:32]}
        r = e.http.request(method, e.public + path, headers=h, params={"tenant_id": b["id"], "device_id": ctx.objs["B"]["device_id"]})
        rec.add(f"B-INGEST-{path}-tenant-param", "B", path, method, "A creds + tenant_id=B", "no foreign data", r.status_code,
                not ctx.leaks(r.text, "B") and r.status_code < 500)
    # PAT-2424: GET /v1/device/identity takes strict v3 signatures only and returns a device for a device-scoped
    # credential only. The harness credentials are tenant-level, so the correctly signed call must be refused with
    # the distinct 409, the legacy-signed one with 401, and neither may echo anything of B's that the query names.
    path = "/v1/device/identity"
    for label, v3 in (("v3", True), ("legacy-signature", False)):
        ts, nonce = str(int(time.time())), hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:32]
        msg = f"patched-hmac-v3\nGET\ndevice_identity\n{ts}\n{nonce}\n".encode() if v3 else b""
        sig = hmac.new(base64.b64decode(a["hmac_b64"]), msg, hashlib.sha256).hexdigest()
        h = {"Authorization": f"Bearer {a['bearer']}", "X-Patched-Signature": sig, "X-Patched-Timestamp": ts, "X-Patched-Nonce": nonce}
        r = e.http.request("GET", e.public + path, headers=h, params={"tenant_id": b["id"], "device_id": ctx.objs["B"]["device_id"]})
        want = 409 if v3 else 401
        rec.add(f"B-INGEST-{path}-tenant-credential-{label}", "B", path, "GET", "A tenant-level creds + tenant_id=B, device_id=B",
                f"{want}, no identity", r.status_code,
                r.status_code == want and not ctx.leaks(r.text, "B") and not ctx.leaks(r.text, "A") and "device_id" not in r.text, r.text[:80])


# ---------------------------------------------------------------------------------------------------------------
# D: reports and exports
# ---------------------------------------------------------------------------------------------------------------
def pdf_text(raw):
    """Concatenate raw bytes, every FlateDecode stream, and `pdftotext` output when available."""
    chunks = [raw]
    for m in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", raw, re.S):
        try:
            chunks.append(zlib.decompress(m.group(1)))
        except Exception:
            pass
    text = b"\n".join(chunks).decode("latin-1", "replace").replace("\x00", "")  # fpdf2 writes UTF-16BE text runs
    exe = shutil.which("pdftotext")
    if exe:
        try:
            r = subprocess.run([exe, "-", "-"], input=raw, capture_output=True, timeout=30)
            text += "\n" + r.stdout.decode("utf-8", "replace")
        except Exception:
            pass
    return text


DANGEROUS = ("=", "+", "-", "@", "\t", "\r")


def csv_dangerous_cells(text):
    bad = []
    for row in csv.reader(io.StringIO(text)):
        for cell in row:
            if cell and cell[0] in DANGEROUS and not re.fullmatch(r"-?\d+(\.\d+)?", cell):
                bad.append(cell[:60])
    return bad


def section_d(ctx):
    rec, e = ctx.rec, ctx.e
    cat = ctx.papi("A.admin", "GET", "/reports/catalogue").json()["reports"]
    rec.add("D-catalogue", "D", "/v1/portal/reports/catalogue", "GET", "A.admin", "200 with report types", len(cat), len(cat) > 0)
    generated = {"A": [], "B": []}
    for L in "AB":
        for t in cat:
            r = ctx.papi(f"{L}.admin", "POST", "/reports", body={"report_type": t["type"]})
            if r.status_code == 201:
                generated[L].append((t["type"], r.json()["id"]))
            if t.get("subject_scope") == "tenant":
                rec.add(f"D-generate-{L}-{t['type']}", "D", "/v1/portal/reports", "POST", f"{L}.admin", "201 (tenant-scoped type)",
                        r.status_code, r.status_code == 201, r.text[:100] if r.status_code != 201 else "")
            else:
                rec.add(f"D-generate-{L}-{t['type']}", "D", "/v1/portal/reports", "POST", f"{L}.admin",
                        "400 or 422 (subject-scoped type needs a subject)", r.status_code, r.status_code in (400, 422), r.text[:100])
    ctx.generated = generated
    admin_only = {t["type"] for t in cat if t.get("admin_only")}
    rec.add("D-catalogue-admin-only", "D", "/v1/portal/reports/catalogue", "GET", "A.admin", f"admin_only marks {ADMIN_ONLY_REPORT} only",
            sorted(admin_only), admin_only == {ADMIN_ONLY_REPORT})

    def refused(who, typ):
        """PAT-2406: an admin-only report is refused to every identity that is not an admin of the tenant."""
        return typ in admin_only and not who.endswith(".admin")
    own_hits = {"A": 0, "B": 0}
    for X, Y in (("A", "B"), ("B", "A")):
        for who in ATTACKERS[X]:
            for typ, rid in generated[X]:
                r = ctx.papi(who, "GET", f"/reports/{rid}")
                txt = pdf_text(r.content) if r.content[:4] == b"%PDF" else r.text
                leak = ctx.leaks(txt, Y)
                if f"CANARY-{X}-" in txt:
                    own_hits[X] += 1
                if refused(who, typ):
                    served = r.content[:4] == b"%PDF" or bool(r.headers.get("Content-Disposition"))
                    rec.add(f"D-PLAT-download-{who}-{typ}", "D", f"/v1/portal/reports/{{id}} ({typ})", "GET", who, "403 and no file (admin-only report)",
                            r.status_code, r.status_code == 403 and not served and not leak, "FILE SERVED" if served else "")
                    continue
                rec.add(f"D-PLAT-download-{who}-{typ}", "D", f"/v1/portal/reports/{{id}} ({typ})", "GET", who, "own report, no foreign marker",
                        r.status_code, r.status_code in (200, 404) and not leak, ("LEAK " + str(leak)) if leak else f"{len(r.content)} bytes")
            for typ, rid in generated[Y]:
                r = ctx.papi(who, "GET", f"/reports/{rid}")
                txt = pdf_text(r.content) if r.content[:4] == b"%PDF" else r.text
                rec.add(f"D-PLAT-download-foreign-{who}-{typ}", "D", "/v1/portal/reports/{id} (foreign)", "GET", f"{who} -> {Y}", "403/404",
                        r.status_code, r.status_code in (403, 404) and not ctx.leaks(txt, Y))
                r = ctx.portal(who, "GET", f"/reports/{rid}/download")
                rec.add(f"D-PORTAL-download-foreign-{who}-{typ}", "D", "/reports/{id}/download (foreign)", "GET", f"{who} -> {Y}", "403/404",
                        r.status_code, r.status_code in (403, 404) and not ctx.leaks(r.text, Y) and not ctx.leaks(pdf_text(r.content), Y))
            for typ, rid in generated[X]:
                r = ctx.portal(who, "GET", f"/reports/{rid}/download")
                txt = pdf_text(r.content) if r.content[:4] == b"%PDF" else r.text
                if refused(who, typ):
                    served = r.content[:4] == b"%PDF" or "attachment" in r.headers.get("Content-Disposition", "")
                    rec.add(f"D-PORTAL-download-{who}-{typ}", "D", "/reports/{id}/download", "GET", who, "403 or 404 page and no file (admin-only report)",
                            r.status_code, r.status_code in (403, 404) and not served and not ctx.leaks(txt, Y), "FILE SERVED" if served else "")
                    continue
                rec.add(f"D-PORTAL-download-{who}-{typ}", "D", "/reports/{id}/download", "GET", who, "own report, no foreign marker",
                        r.status_code, r.status_code in (200, 404) and not ctx.leaks(txt, Y))
    rec.add("D-positive-control-reports", "D", "generated report text", "GET", "A.admin/B.admin",
            "at least one generated report of each tenant contains its own marker (so absence of foreign markers is meaningful)", own_hits,
            own_hits["A"] > 0 and own_hits["B"] > 0, "if this fails the PDFs are not text-searchable here; see the document")
    # every portal CSV/PDF/download route
    exports = [(m, r["path"]) for r in ctx.portal_routes["routes"] for m in r["methods"] if m == "GET" and
               (r["path"].endswith((".csv", ".pdf", "/download")) or "export" in r["path"])]
    csv_markers = {"A": 0, "B": 0}
    for X, Y in (("A", "B"), ("B", "A")):
        for who in ATTACKERS[X]:
            for method, path in exports:
                if "{" in path:
                    continue
                r = ctx.portal(who, "GET", path)
                body = pdf_text(r.content) if r.content[:4] == b"%PDF" else r.text
                leak = ctx.leaks(body, Y)
                bad = csv_dangerous_cells(r.text) if path.endswith(".csv") and r.status_code == 200 else []
                if path.endswith(".csv") and f"CANARY-{X}-" in r.text:
                    csv_markers[X] += 1
                rec.add(f"D-PORTAL-export-{who}-{path}", "D", path, "GET", who, "no foreign marker; no formula-leading cells",
                        r.status_code, r.status_code < 500 and not leak and not bad,
                        (("LEAK " + str(leak)) if leak else "") + (("FORMULA " + str(bad[:3])) if bad else ""))
                rec.cover("portal_exports", method, path)
    rec.add("D-positive-control-csv", "D", "portal CSV exports", "GET", "A/B admin", "own canary rows present in CSV exports", csv_markers,
            csv_markers["A"] > 0 and csv_markers["B"] > 0)
    # Formula neutralisation, using every portal CSV route (the software, findings, devices, approved, homebrew, local-admins and
    # duplicate-tools exports are all in `exports` above, so they get the foreign-marker and formula checks in the D-PORTAL-export rows too).
    for L in "AB":
        found, inert = 0, 0
        for method, path in exports:
            if not path.endswith(".csv") or "{" in path:
                continue
            r = ctx.portal(f"{L}.admin", "GET", path)
            for row in csv.reader(io.StringIO(r.text)):
                for cell in row:
                    if re.search(rf"CANARY-{L}-(FORMULA|PLUS|AT|MINUS|WINFORMULA|EXTFORMULA)", cell):
                        found += 1
                        if not cell or cell[0] not in DANGEROUS:
                            inert += 1
        rec.add(f"D-formula-values-neutralised-{L}", "D", "portal CSV exports", "GET", f"{L}.admin",
                "seeded formula-leading values appear and none starts with = + - @ tab or CR", {"seen": found, "inert": inert},
                found > 0 and found == inert, "found=0 means no export carried the seeded names; see document")
    # platform JSON export route
    for who in ATTACKERS["A"]:
        r = ctx.papi(who, "GET", "/software-approvals/history/export")
        rec.add(f"D-PLAT-approval-export-{who}", "D", "/v1/portal/software-approvals/history/export", "GET", who, "no foreign marker",
                r.status_code, r.status_code < 500 and not ctx.leaks(r.text, "B"))


# ---------------------------------------------------------------------------------------------------------------
# G: internal router isolation
# ---------------------------------------------------------------------------------------------------------------
def section_g(ctx):
    rec, e = ctx.rec, ctx.e
    public = set(ctx.public_all)
    public_paths = {p for _, p in public}
    for method, path in ctx.internal:
        rec.cover("platform_internal", method, path)
        p = fill(path)
        r = e.http.request(method, e.public + p, headers={"Authorization": f"Bearer {e.admin_token}"}, data=b"{}" if method in WRITE else None)
        also_public = (method, path) in public or path in public_paths
        if also_public:
            rec.add(f"G-PUBLIC-{method}-{path}", "G", path, method, "admin bearer on public listener",
                    "route is deliberately also public (health or token redemption)", r.status_code, r.status_code != 500, "mounted on both listeners by design")
        else:
            rec.add(f"G-PUBLIC-{method}-{path}", "G", path, method, "admin bearer on public listener", "404", r.status_code, r.status_code == 404)
        for name, hdr, want in (("no_bearer", {}, 401), ("wrong_bearer", {"Authorization": "Bearer ib-wrong-token"}, 401),
                                ("tenant_bearer_a", {"Authorization": f"Bearer {e.tenants['A']['bearer']}"}, 401),
                                ("empty_bearer", {"Authorization": "Bearer "}, 401), ("basic_scheme", {"Authorization": f"Basic {e.admin_token}"}, 401),
                                ("portal_jwt", {"Cf-Access-Jwt-Assertion": ctx.tok("A.admin")}, 401)):
            r = e.http.request(method, e.internal + p, headers=hdr, data=b"{}" if method in WRITE else None)
            if path in ("/health", "/metrics"):
                rec.add(f"G-INTERNAL-{method}-{path}-{name}", "G", path, method, name, "200 (open by design: liveness and scrape)", r.status_code, r.status_code == 200)
            else:
                rec.add(f"G-INTERNAL-{method}-{path}-{name}", "G", path, method, name, want, r.status_code, r.status_code == want)
    # PAT-2408: the Bearer scheme is required; the admin token on its own, with no scheme, must be refused like any other bad shape
    r = e.http.request("GET", e.internal + "/admin/tenants", headers={"Authorization": e.admin_token})
    r0 = e.http.request("GET", e.internal + "/admin/tenants", headers={"Authorization": "ib-wrong-bare-token"})
    rec.add("G-INTERNAL-wrong-bare-token", "G", "/admin/tenants", "GET", "wrong token without Bearer prefix", 401, r0.status_code, r0.status_code == 401,
            "the secret itself is still required")
    rec.add("G-INTERNAL-raw-token-no-scheme", "G", "/admin/tenants", "GET", "admin token without Bearer prefix", 401,
            r.status_code, r.status_code == 401, "the internal listener accepted the admin token without the Bearer scheme (PAT-2408 regression)" if r.status_code != 401 else "")
    # positive control
    r = e.http.request("GET", e.internal + "/admin/tenants", headers={"Authorization": f"Bearer {e.admin_token}"})
    rec.add("G-INTERNAL-positive-control", "G", "/admin/tenants", "GET", "admin bearer on internal listener", 200, r.status_code, r.status_code == 200)
    # public listener non-portal routes must not honour the admin token as a credential
    r = e.http.request("GET", e.public + "/v1/portal/me", headers={"Authorization": f"Bearer {e.admin_token}"})
    rec.add("G-PUBLIC-portal-with-admin-bearer", "G", "/v1/portal/me", "GET", "admin bearer", 401, r.status_code, r.status_code == 401)


# ---------------------------------------------------------------------------------------------------------------
# C: roles and actor attribution
# ---------------------------------------------------------------------------------------------------------------
def section_c(ctx):
    rec, e = ctx.rec, ctx.e
    writes = [(m, p) for m, p in ctx.pr if m in WRITE]
    before = ctx.snap("A")
    for who in ("A.viewer", "A.domain"):
        for method, path in writes:
            tmpl = path[len("/v1/portal"):]
            vals = obj_values(ctx, tmpl, "A")[0]
            r = ctx.papi(who, method, fill(tmpl, vals), body=write_body(ctx, method, tmpl, "A"))
            if tmpl in STATELESS_WRITES:
                want, ok = "200 (stateless render, open to every role)", r.status_code == 200
            elif tmpl == VIEWER_GENERATES:
                want, ok = "201 (every role may generate a report that is not admin-only)", r.status_code == 201
            elif is_signup(tmpl):
                # Not decided by role: a member is refused as a member (409, already belongs to an organisation) and a
                # missing invitation is 404. Never 200/201: a member cannot create a second organisation or join one.
                want, ok = "404 (feature off or no such invitation) or 409 (already a member); never created", r.status_code in (404, 409)
            elif is_access(tmpl):
                want = "403 owner_role_required (404 acceptable only where the feature is disabled)"
                ok = (r.status_code == 403 and "owner_role_required" in r.text) or r.status_code == 404
            else:
                want = "403 (404/503 acceptable only where the feature is disabled)" if tmpl == "/feedback" else 403
                ok = r.status_code == 403 or (tmpl == "/feedback" and r.status_code in (404, 503))
            rec.add(f"C-PLAT-{who}-{method}-{path}", "C", path, method, who, want, r.status_code, ok, r.text[:80] if not ok else "")
        # the one admin-only export key: the local administrators roster (account names)
        roster = dict(write_body(ctx, "POST", "/exports/table-pdf", "A"), export="local-admins")
        r = ctx.papi(who, "POST", "/exports/table-pdf", body=roster)
        rec.add(f"C-PLAT-{who}-table-pdf-local-admins", "C", "/v1/portal/exports/table-pdf (local-admins)", "POST", who, 403, r.status_code,
                r.status_code == 403, r.text[:80] if r.status_code != 403 else "")
        # the one admin-only report type: the same roster as a generated report (PAT-2406)
        r = ctx.papi(who, "POST", "/reports", body={"report_type": ADMIN_ONLY_REPORT})
        rec.add(f"C-PLAT-{who}-report-generate-{ADMIN_ONLY_REPORT}", "C", f"/v1/portal/reports ({ADMIN_ONLY_REPORT})", "POST", who, 403, r.status_code,
                r.status_code == 403, r.text[:80] if r.status_code != 403 else "")
    after = ctx.snap("A")
    moved = [k for k in before if digest(before[k]) != digest(after[k]) and k not in VIEWER_MAY_ADD_TO]
    rec.add("C-PLAT-viewer-writes-changed-nothing", "C", "tenant A snapshot", "GET", "A.admin",
            "no state change from viewer/domain writes, other than the reports they are allowed to generate",
            ", ".join(moved) or "no diff", not moved)
    # admin allowed (own tenant, own objects)
    for method, path in writes:
        tmpl = path[len("/v1/portal"):]
        if method == "DELETE" and tmpl in ("/device-list", "/mdm/jamf/token", "/mdm/jamf/devices", "/certificates/{id}", "/device-list/entries/{entryID}"):
            continue  # destructive on seeded evidence; exercised via fresh objects below
        vals = obj_values(ctx, tmpl, "A")[0]
        r = ctx.papi("A.admin", method, fill(tmpl, vals), body=write_body(ctx, method, tmpl, "A"))
        if is_access(tmpl):
            # PAT-1883: managing access is owner only, so an admin is refused here too (404 while the feature is off).
            rec.add(f"C-PLAT-A.admin-{method}-{path}", "C", path, method, "A.admin",
                    "403 owner_role_required (404 acceptable only where the feature is disabled)", r.status_code,
                    (r.status_code == 403 and "owner_role_required" in r.text) or r.status_code == 404, r.text[:100])
            continue
        rec.add(f"C-PLAT-A.admin-{method}-{path}", "C", path, method, "A.admin", "allowed (not 401/403); no 5xx", r.status_code,
                r.status_code not in (401, 403) and r.status_code < 500, r.text[:100] if r.status_code >= 400 else "")
    # fresh-object destructive admin writes
    c = ctx.papi("A.admin", "POST", "/certificates", body={"label": "CANARY-A-FRESH", "certificate": b64cert("CANARY-A-FRESHCERT")})
    cid = c.json().get("id") if c.status_code in (200, 201) else None
    rec.add("C-PLAT-A.admin-certificate-lifecycle-create", "C", "/v1/portal/certificates", "POST", "A.admin", 201, c.status_code, c.status_code == 201)
    if cid:
        r = ctx.papi("A.admin", "PATCH", f"/certificates/{cid}", body={"label": "CANARY-A-RELABEL"})
        rec.add("C-PLAT-A.admin-certificate-lifecycle-patch", "C", "/v1/portal/certificates/{id}", "PATCH", "A.admin", 200, r.status_code, r.status_code == 200)
        r = ctx.papi("A.admin", "DELETE", f"/certificates/{cid}")
        rec.add("C-PLAT-A.admin-certificate-lifecycle-delete", "C", "/v1/portal/certificates/{id}", "DELETE", "A.admin", "200 or 204", r.status_code, r.status_code in (200, 204))
    viewer_impact(ctx)
    # portal POST routes as viewer and domain principal
    before = ctx.snap("A")
    for who in ("A.viewer", "A.domain"):
        tokv = ctx.tok(who)
        for rt in ctx.portal_routes["routes"]:
            for method in rt["methods"]:
                if method != "POST":
                    continue
                path = rt["path"]
                vals = obj_values(ctx, path, "A")[0]
                form = {"csrf_token": csrf_for(tokv), "device_id": ctx.objs["A"]["device_id_2"], "retired": "false", "reason": "CANARY-A-VIEWERHACK",
                        "alias_id": ZERO, "justification": "x", "note": "x", "label": "CANARY-A-VIEWERHACK", "cadence": "daily", "hour_utc": "1",
                        "report_type": "executive-summary", "state": "approved", "item": json.dumps({"type": "application"}),
                        "name": "CANARY-A-VIEWERHACK", "publisher": "p", "platform": "macos"}
                r = ctx.portal(who, "POST", fill(path, vals), headers={"Origin": e.portal, "Content-Type": "application/x-www-form-urlencoded"}, data=form)
                rec.add(f"C-PORTAL-{who}-POST-{path}", "C", path, "POST", who, "refused or no-op (state diff below)", r.status_code, r.status_code < 500)
    after = ctx.snap("A")
    moved = [k for k in before if digest(before[k]) != digest(after[k]) and k not in VIEWER_MAY_ADD_TO]
    rec.add("C-PORTAL-viewer-posts-changed-nothing", "C", "tenant A snapshot", "GET", "A.admin",
            "no state change from viewer/domain posts through the portal, other than the reports they are allowed to generate",
            ", ".join(moved) or "no diff", not moved, "; ".join(f"{k}: {json.dumps(norm(before[k]))[:160]} -> {json.dumps(norm(after[k]))[:160]}" for k in moved)[:900])
    actor_attribution(ctx)


def viewer_impact(ctx):
    """What the viewer-permitted writes can cause, measured locally on tenant A."""
    rec, e = ctx.rec, ctx.e
    r = ctx.papi("A.viewer", "POST", "/enrolment", body={})
    tok = r.json().get("enrollment_token") if r.status_code == 201 else None
    if tok:
        dev = "aaaaaaaa-5555-4555-8555-" + hashlib.sha256(tok.encode()).hexdigest()[:12]
        er = e.http.request("POST", e.public + "/v1/enrol", headers={"Content-Type": "application/json"},
                            data=json.dumps({"enrollment_token": tok, "device_id": dev}))
        enrolled = er.status_code == 200 and "bearer_token" in er.text
        landed = None
        if enrolled:
            j = er.json()
            p = json.loads((Path(__file__).resolve().parents[2] / "testdata/payload-fixtures/valid/minimal.json").read_text())
            p["tenant_id"] = j["tenant_id"]
            p["device"].update(serial="SER-A-VIEWERENROL", hw_uuid="AAAAAAAA-5555-4555-8555-555555555555", hostname="CANARY-A-VIEWERENROL")
            body = json.dumps(p).encode()
            sig = hmac.new(base64.b64decode(j["hmac_secret"]), body, hashlib.sha256).hexdigest()
            ir = e.http.request("POST", e.public + "/v1/inventory", data=body, headers={
                "Content-Type": "application/json", "Authorization": "Bearer " + j["bearer_token"], "X-Patched-Signature": sig,
                "X-Patched-Timestamp": str(int(time.time())), "X-Patched-Nonce": hashlib.sha256(str(time.time_ns()).encode()).hexdigest()[:32]})
            if ir.status_code == 200:
                wait_for(lambda: "CANARY-A-VIEWERENROL" in ctx.papi("A.admin", "GET", "/devices").text,
                         "extractor to materialise the viewer-enrolled device")
            landed = ir.status_code == 200
        rec.add("C-IMPACT-viewer-enrolment-token-redeems", "C", "POST /v1/portal/enrolment then POST /v1/enrol", "POST", "A.viewer",
                "a read-only role cannot mint a credential that enrols a device",
                {"minted": True, "redeemed": enrolled, "device_landed_in_tenant_A": landed}, not enrolled,
                "token minted by a viewer redeemed, device credentials issued, and inventory from it appeared in tenant A" if enrolled else "")
    else:
        rec.add("C-IMPACT-viewer-enrolment-token-redeems", "C", "POST /v1/portal/enrolment", "POST", "A.viewer", "refused", r.status_code, r.status_code == 403)
    # Ruled 2026-10-05: a viewer generates reports (one row added to the tenant's history) but not the Local Admin report.
    def admin_total():
        return ctx.papi("A.admin", "GET", "/reports", params={"limit": 1}).json()["total"]
    before = admin_total()
    ok_gen = ctx.papi("A.viewer", "POST", "/reports", body={"report_type": "executive-summary"})
    mid = admin_total()
    refused_gen = ctx.papi("A.viewer", "POST", "/reports", body={"report_type": ADMIN_ONLY_REPORT})
    after = admin_total()
    rec.add("C-IMPACT-viewer-report-generate", "C", "POST /v1/portal/reports", "POST", "A.viewer",
            f"201 and one record added for an ordinary report; 403 and no record for {ADMIN_ONLY_REPORT}",
            {"ordinary": ok_gen.status_code, "added": mid - before, ADMIN_ONLY_REPORT: refused_gen.status_code, "added_admin_only": after - mid},
            ok_gen.status_code == 201 and mid == before + 1 and refused_gen.status_code == 403 and after == mid)
    # Ruled 2026-10-05: only an admin changes a schedule. Both PUT routes, and the stored schedule must not move.
    s0 = ctx.papi("A.admin", "GET", "/reports/schedules/executive-summary").json()
    change = {"cadence": "weekly", "weekday": 1, "hour_utc": 9, "enabled": False}
    put_typed = ctx.papi("A.viewer", "PUT", "/reports/schedules/executive-summary", body=change)
    put_alias = ctx.papi("A.viewer", "PUT", "/reports/schedule", body=change)
    s1 = ctx.papi("A.admin", "GET", "/reports/schedules/executive-summary").json()
    read = ctx.papi("A.viewer", "GET", "/reports/schedules/executive-summary")
    if s0.get("hour_utc") != s1.get("hour_utc"):  # leave the tenant as seeded if the refusal ever regresses
        ctx.papi("A.admin", "PUT", "/reports/schedules/executive-summary", body={"cadence": "weekly", "weekday": 1, "hour_utc": 3, "enabled": False})
    rec.add("C-IMPACT-viewer-schedule-change", "C", "PUT /v1/portal/reports/schedules/{type} and /reports/schedule", "PUT", "A.viewer",
            "403 on both routes, stored schedule unchanged, and the viewer can still read it (200)",
            {"typed": put_typed.status_code, "alias": put_alias.status_code, "hour_before": s0.get("hour_utc"), "hour_after": s1.get("hour_utc"),
             "viewer_read": read.status_code},
            put_typed.status_code == 403 and put_alias.status_code == 403 and s0.get("hour_utc") == s1.get("hour_utc") and read.status_code == 200,
            "a viewer changed the tenant's report schedule (PAT-2408 regression)" if s0.get("hour_utc") != s1.get("hour_utc") else "")
    viewer_admin_only_report(ctx)


def viewer_admin_only_report(ctx):
    """PAT-2406: the Local Admin report carries the roster's account names, so only an admin may obtain it, by any route."""
    rec = ctx.rec
    made = ctx.papi("A.admin", "POST", "/reports", body={"report_type": ADMIN_ONLY_REPORT})
    rid = made.json().get("id") if made.status_code == 201 else None
    rec.add(f"C-ROLE-admin-generates-{ADMIN_ONLY_REPORT}", "C", f"/v1/portal/reports ({ADMIN_ONLY_REPORT})", "POST", "A.admin", 201, made.status_code, made.status_code == 201)
    if not rid:
        return
    for fmt in ("pdf", "csv"):
        r = ctx.papi("A.admin", "GET", f"/reports/{rid}", params={"format": fmt})
        rec.add(f"C-ROLE-A.admin-download-{ADMIN_ONLY_REPORT}-{fmt}", "C", f"/v1/portal/reports/{{id}}?format={fmt} ({ADMIN_ONLY_REPORT})", "GET", "A.admin",
                "200 (control: the file exists)", r.status_code, r.status_code == 200 and len(r.content) > 0)
    for who in ("A.viewer", "A.domain", "A.service"):
        for fmt in ("pdf", "csv"):
            r = ctx.papi(who, "GET", f"/reports/{rid}", params={"format": fmt})
            served = r.content[:4] == b"%PDF" or "admin_names" in r.text or bool(r.headers.get("Content-Disposition"))
            rec.add(f"C-ROLE-{who}-download-{ADMIN_ONLY_REPORT}-{fmt}", "C", f"/v1/portal/reports/{{id}}?format={fmt} ({ADMIN_ONLY_REPORT})", "GET", who,
                    "403 and no file content", r.status_code, r.status_code == 403 and not served, "FILE CONTENT SERVED" if served else "")
        lst = ctx.papi(who, "GET", "/reports", params={"limit": 200})
        listed = lst.status_code != 200 or any(x.get("id") == rid or x.get("report_type") == ADMIN_ONLY_REPORT for x in lst.json().get("reports", []))
        rec.add(f"C-ROLE-{who}-list-omits-{ADMIN_ONLY_REPORT}", "C", "/v1/portal/reports", "GET", who, f"200 and no {ADMIN_ONLY_REPORT} record listed",
                lst.status_code, not listed)
        cat = ctx.papi(who, "GET", "/reports/catalogue")
        offered = cat.status_code != 200 or any(x.get("type") == ADMIN_ONLY_REPORT or x.get("admin_only") for x in cat.json().get("reports", []))
        rec.add(f"C-ROLE-{who}-catalogue-omits-{ADMIN_ONLY_REPORT}", "C", "/v1/portal/reports/catalogue", "GET", who,
                f"200 and {ADMIN_ONLY_REPORT} not offered", cat.status_code, not offered)
    cat = ctx.papi("A.admin", "GET", "/reports/catalogue").json().get("reports", [])
    flagged = sorted(x.get("type") for x in cat if x.get("admin_only"))
    rec.add("C-ROLE-A.admin-catalogue-flags-admin-only", "C", "/v1/portal/reports/catalogue", "GET", "A.admin",
            f"admin_only set on {ADMIN_ONLY_REPORT} only", flagged, flagged == [ADMIN_ONLY_REPORT])


def actor_attribution(ctx):
    rec, e = ctx.rec, ctx.e
    mixed = "Alice.Admin@Tenant-A.example"
    tok = e.minter.mint(email=mixed, ttl=3600)
    spoof = {"Cf-Access-Authenticated-User-Email": "evil@spoof.example", "X-Actor": "evil@spoof.example",
             "X-Forwarded-User": "evil@spoof.example", "X-Authenticated-User": "evil@spoof.example", "X-Forwarded-Email": "evil@spoof.example"}
    A = ctx.objs["A"]
    good = {mixed, mixed.lower()}

    def verdict(cid, route, method, observed, note=""):
        ok = observed in good and "evil" not in str(observed)
        rec.add(cid, "C", route, method, "A.admin (token email, mixed case)", "recorded actor is the token email, not client-supplied",
                observed, ok, note)

    # 1 retirement (+ rejected body field)
    r = e.papi("PUT", f"/devices/{A['win_device_id']}/retirement", tok, body={"retired": True, "reason": "x", "actor_email": "evil@spoof.example", "retired_by": "evil@spoof.example"}, headers=spoof)
    rec.add("C-ACTOR-retirement-extra-body-fields", "C", "/v1/portal/devices/{id}/retirement", "PUT", "A.admin", "refused (strict) or ignored", r.status_code, r.status_code in (200, 400, 422))
    e.papi("PUT", f"/devices/{A['win_device_id']}/retirement", tok, body={"retired": False, "reason": "attribution probe"}, headers=spoof)
    e.papi("PUT", f"/devices/{A['win_device_id']}/retirement", tok, body={"retired": True, "reason": "attribution probe 2"}, headers=spoof)
    h = e.papi("GET", f"/devices/{A['win_device_id']}/retirement/history", tok).json()
    actors = {d["actor_email"] for d in h.get("decisions", [])}
    verdict("C-ACTOR-1-retirement-history", "/v1/portal/devices/{id}/retirement/history", "PUT", ",".join(sorted(actors)) if len(actors) > 1 else next(iter(actors), ""))
    if len(actors) > 1:
        rec.rows[-1]["result"] = "PASS" if all(a in good for a in actors) else "FAIL"
    # 2 device list
    r = e.papi("PUT", "/device-list", tok, body={"filename": "attribution.csv", "entries": [{"hostname": "CANARY-A-ATTRIB"}], "uploaded_by": "evil@spoof.example"}, headers=spoof)
    rec.add("C-ACTOR-device-list-extra-body-field", "C", "/v1/portal/device-list", "PUT", "A.admin", "refused or ignored", r.status_code, r.status_code in (200, 400, 422))
    r = e.papi("PUT", "/device-list", tok, body={"filename": "attribution.csv", "entries": [{"hostname": "CANARY-A-ATTRIB"}]}, headers=spoof)
    g = e.papi("GET", "/device-list", tok).json()
    verdict("C-ACTOR-2-device-list-uploaded-by", "/v1/portal/device-list", "PUT", (g.get("list") or {}).get("uploaded_by"))
    # 3 enrolment key create then revoke
    r = e.papi("POST", "/enrolment-keys", tok, body={"label": "CANARY-A-ATTRIB", "max_devices": 1, "expires_in_days": 1, "created_by": "evil@spoof.example"}, headers=spoof)
    rec.add("C-ACTOR-enrolment-key-extra-body-field", "C", "/v1/portal/enrolment-keys", "POST", "A.admin", "refused or ignored", r.status_code, r.status_code in (201, 400, 422))
    r = e.papi("POST", "/enrolment-keys", tok, body={"label": "CANARY-A-ATTRIB2", "max_devices": 1, "expires_in_days": 1}, headers=spoof)
    kid = r.json().get("key_id")
    verdict("C-ACTOR-3-enrolment-key-created-by", "/v1/portal/enrolment-keys", "POST", r.json().get("created_by"))
    rv = e.papi("POST", f"/enrolment-keys/{kid}/revoke", tok, body={}, headers=spoof)
    keys = {k["key_id"]: k for k in e.papi("GET", "/enrolment-keys", tok).json()["keys"]}
    verdict("C-ACTOR-4-enrolment-key-revoked-by", "/v1/portal/enrolment-keys/{id}/revoke", "POST", (keys.get(kid) or {}).get("revoked_by"), f"revoke status {rv.status_code}")
    # 5 declaration
    r = e.papi("POST", "/software-declarations", tok, body={"name": "CANARY-A-ATTRIBDECL", "publisher": "p", "platform": "macos", "justification": "j"}, headers=spoof)
    verdict("C-ACTOR-5-declaration-created-by", "/v1/portal/software-declarations", "POST", r.json().get("created_by") if r.status_code == 201 else r.status_code)
    # 6 notifications
    r = e.papi("PUT", "/software-notifications", tok, body={"unapproved_alerts_enabled": True, "new_software_enabled": False}, headers=spoof)
    verdict("C-ACTOR-6-notifications-updated-by", "/v1/portal/software-notifications", "PUT", r.json().get("updated_by") if r.status_code == 200 else r.status_code)
    # 7 approvals history
    ap = e.papi("PUT", "/software-approvals", tok, body={"items": [{"type": "application", "platform": "macos", "identifier": "com.canarya.app2", "team_id": "CNRYA00002"}], "state": "unapproved", "reason": "attribution"}, headers=spoof)
    hist = e.papi("GET", "/software-approvals/history", tok).json()
    acts = {d.get("actor_email") for d in hist.get("decisions", [])}
    ok = bool(acts) and all(a in good for a in acts if a)
    rec.add("C-ACTOR-7-approval-history", "C", "/v1/portal/software-approvals/history", "GET", "A.admin", "all recorded actors are token emails",
            sorted(a for a in acts if a), ok and "evil" not in str(acts), f"PUT status {ap.status_code}")
    # 8 through the portal: retirement form with spoofed headers
    form = {"csrf_token": csrf_for(tok), "device_id": A["win_device_id"], "retired": "false", "reason": "portal attribution"}
    pr = e.http.request("POST", e.portal + "/devices/retirement", headers={"Cf-Access-Jwt-Assertion": tok, "Origin": e.portal, **spoof,
                        "Content-Type": "application/x-www-form-urlencoded"}, data=form)
    h = e.papi("GET", f"/devices/{A['win_device_id']}/retirement/history", tok).json()
    latest = (h.get("decisions") or [{}])[0].get("actor_email")
    rec.add("C-ACTOR-8-portal-retirement", "C", "/devices/retirement (portal)", "POST", "A.admin via portal", "platform records the token email",
            latest, latest in good and "evil" not in str(latest), f"portal status {pr.status_code}")
    # service identity attribution is not exposed by any read route
    rec.add("C-ACTOR-service-attribution-not-readable", "C", "portal_access_log", "n/a", "A.service", "not exercised: no read route exposes portal_access_log",
            "not exercised", True, "the service identity is read-only; its audit name is service:<common_name> per code reading only")


# ---------------------------------------------------------------------------------------------------------------
# run
# ---------------------------------------------------------------------------------------------------------------
def run(st, scratch, args):
    scratch = Path(scratch)
    if not st.get("seeded"):
        raise SystemExit("environment is not seeded; run `ib seed` first")
    ctx = Ctx(st, scratch)
    only = set((args.only or "ABCDEFG").replace(",", "").upper()) if args else set("ABCDEFG")
    t0 = time.time()
    tap_mark = (scratch / "logs/tap.jsonl").stat().st_size if (scratch / "logs/tap.jsonl").exists() else 0
    order = [("A", section_a), ("B", section_b), ("D", section_d), ("G", section_g)]
    for name, fn in order:
        if name in only:
            n0 = len(ctx.rec.rows)
            fn(ctx)
            print(f"section {name}: {len(ctx.rec.rows) - n0} checks", flush=True)
    if "E" in only:
        import browser
        n0 = len(ctx.rec.rows)
        browser.run(ctx)
        print(f"section E: {len(ctx.rec.rows) - n0} checks", flush=True)
    if "F" in only:
        import staff
        n0 = len(ctx.rec.rows)
        staff.run(ctx)
        print(f"section F: {len(ctx.rec.rows) - n0} checks", flush=True)
    if "C" in only:
        n0 = len(ctx.rec.rows)
        section_c(ctx)
        print(f"section C: {len(ctx.rec.rows) - n0} checks", flush=True)
    summary = ctx.rec.summary()
    inventory = {
        "platform_portal": {"enumerated": len(ctx.pr), "covered": len(ctx.rec.covered.get("platform_portal", ()))},
        "platform_internal": {"enumerated": len(ctx.internal), "covered": len(ctx.rec.covered.get("platform_internal", ()))},
        "platform_public_all": {"enumerated": len(ctx.public_all)},
        "portal": {"enumerated": sum(len(r["methods"]) for r in ctx.portal_routes["routes"]),
                   "covered": len(ctx.rec.covered.get("portal", ()))},
    }
    inventory.update(getattr(ctx, "inventory_extra", {}))
    out = {"meta": {"platform_commit": st["platform_sha"], "portal_commit": st["portal_sha"], "dashboard_commit": st["dashboard_sha"],
                    "platform_worktree_dirty_outside_harness": st.get("platform_dirty"),
                    "started": st.get("started"), "run_seconds": round(time.time() - t0, 1), "sections": sorted(only)},
           "summary": summary, "inventory": inventory, "checks": ctx.rec.rows}
    path = scratch / "results" / f"matrix-results-{time.strftime('%Y%m%dT%H%M%S')}.json"
    path.write_text(json.dumps(out, indent=1))
    digest_ = hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps({"results_file": str(path), "sha256": digest_, "summary": summary, "inventory": inventory}, indent=1))
    fails = [r for r in ctx.rec.rows if r["result"] == "FAIL"]
    print(f"{len(ctx.rec.rows)} checks, {len(fails)} failed")
    for r in fails[:60]:
        print("FAIL", r["id"], r["observed"], r["note"][:120])
    return 0
