"""Boundary E: portal Origin/CSRF on every POST route, stored-script rendering, and a real cross-origin
form post in Chromium (Playwright). Runs against the real portal at its pinned commit."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from common import ZERO, fill, params_of, csrf_for
from ibclient import PRINCIPALS

ORIGIN_MSG = "did not come from the portal page itself"
CSRF_MSG = "This page has expired"


def post_routes(ctx):
    return [r["path"] for r in ctx.portal_routes["routes"] if "POST" in (r["methods"] or [])]


MULTIPART = {"/devices/device-list", "/feedback", "/support", "/certificates/upload", "/certificates/{record_id}/update",
             "/certificates/{record_id}/delete"}
GUARD_WORDS = (ORIGIN_MSG, CSRF_MSG, "has expired", "not come from the portal")


def send(ctx, path, p, tok, headers, form, multipart, pad=0):
    e = ctx.e
    h = {"Cf-Access-Jwt-Assertion": tok, **headers}
    if multipart:
        keep = {"/devices/device-list": ["csrf_token"], "/feedback": ["csrf_token"], "/support": ["csrf_token"],
                "/certificates/upload": ["csrf_token", "label"], "/certificates/{record_id}/update": ["csrf_token", "label"],
                "/certificates/{record_id}/delete": ["csrf_token"]}[path]
        files = {k: (None, form[k]) for k in keep if k in form}
        if path == "/devices/device-list":
            files["device_list_file"] = ("list.csv", b"hostname\nCANARY-A-CSRFPROBE\n", "text/csv")
        if path == "/feedback":
            files.update(type=(None, "feature"), description=(None, "csrf probe description text"))
        if path == "/support":
            files.update(category=(None, "not_working"), description=(None, "csrf probe description text"))
        if path == "/certificates/upload":
            files["certificate"] = ("c.der", b"not a certificate", "application/octet-stream")
        if pad:
            files["pad"] = ("pad.bin", b"a" * pad, "application/octet-stream")
        if not files:
            files["x"] = (None, "1")
        import requests
        req = requests.Request("POST", e.portal + p, headers=h, files=files).prepare()
        return e.http.request("POST", e.portal + p, headers={**h, "Content-Type": req.headers["Content-Type"]}, data=req.body)
    h["Content-Type"] = "application/x-www-form-urlencoded"
    return e.http.request("POST", e.portal + p, headers=h, data=form)


def guard_checks(ctx):
    rec, e = ctx.rec, ctx.e
    tok = ctx.tok("A.admin")
    other = ctx.tok("B.admin")
    base_form = lambda: {"csrf_token": csrf_for(tok), "device_id": ctx.objs["A"]["device_id_2"], "retired": "false",
                         "reason": "csrf probe", "cadence": "weekly", "weekday": "1", "hour_utc": "3", "report_type": "executive-summary",
                         "note": "x", "alias_id": ZERO, "justification": "x", "label": "csrf probe"}
    cases = [
        ("missing_csrf", lambda f: {k: v for k, v in f.items() if k != "csrf_token"}, {"Origin": e.portal}, CSRF_MSG),
        ("wrong_csrf", lambda f: dict(f, csrf_token="0" * 64), {"Origin": e.portal}, CSRF_MSG),
        ("csrf_of_other_session", lambda f: dict(f, csrf_token=csrf_for(other)), {"Origin": e.portal}, CSRF_MSG),
        ("duplicate_csrf_fields", None, {"Origin": e.portal}, CSRF_MSG),
        ("origin_cross_site", lambda f: f, {"Origin": "https://evil.example"}, ORIGIN_MSG),
        ("origin_null", lambda f: f, {"Origin": "null"}, ORIGIN_MSG),
        ("origin_other_port_same_host", lambda f: f, {"Origin": "http://127.0.0.1:1"}, ORIGIN_MSG),
        ("origin_other_scheme_same_host_prod_style", lambda f: f, {"Origin": "https://app.patched.im"}, ORIGIN_MSG),
        ("no_origin_no_referer", lambda f: f, {}, ORIGIN_MSG),
        ("referer_cross_site_only", lambda f: f, {"Referer": "https://evil.example/page"}, ORIGIN_MSG),
    ]
    for path in post_routes(ctx):
        p = fill(path, {k: ("0" if k in ("alert_id", "entry_id") else ZERO) for k in params_of(path)})
        mp = path in MULTIPART
        for name, mut, hdrs, want in cases:
            if name == "duplicate_csrf_fields":
                if mp:
                    continue
                body = f"csrf_token={csrf_for(tok)}&csrf_token={csrf_for(tok)}&device_id={ZERO}"
                r = e.http.request("POST", e.portal + p, headers={"Cf-Access-Jwt-Assertion": tok, "Origin": e.portal,
                                   "Content-Type": "application/x-www-form-urlencoded"}, data=body)
            else:
                r = send(ctx, path, p, tok, hdrs, mut(base_form()), mp)
            msg_ok = (want in r.text) if not mp else any(w in r.text for w in GUARD_WORDS) or "expired" in r.text.lower()
            rec.add(f"E-GUARD-{path}-{name}", "E", path, "POST", "A.admin session" + (" (multipart)" if mp else ""),
                    f"403 and guard message '{want[:25]}...'", r.status_code,
                    r.status_code == 403 and msg_ok and not ctx.leaks(r.text, "B"), r.text[:80].replace("\n", " ") if r.status_code != 403 else "")
        # oversized body
        if mp:
            r = send(ctx, path, p, tok, {"Origin": e.portal}, base_form(), True, pad=6 * 1024 * 1024)
        else:
            r = e.http.request("POST", e.portal + p, headers={"Cf-Access-Jwt-Assertion": tok, "Origin": e.portal,
                               "Content-Type": "application/x-www-form-urlencoded"}, data="csrf_token=" + csrf_for(tok) + "&x=" + "a" * 40000)
        rec.add(f"E-GUARD-{path}-oversized", "E", path, "POST", "A.admin session", "413 or other refusal, never success", r.status_code,
                r.status_code in (400, 403, 411, 413, 422))
        # GET on a POST-only path never changes state
        r = e.http.request("GET", e.portal + p, headers={"Cf-Access-Jwt-Assertion": tok})
        get_routes = {x["path"] for x in ctx.portal_routes["routes"] if "GET" in (x["methods"] or [])}
        if path not in get_routes:
            rec.add(f"E-GUARD-{path}-get-refused", "E", path, "GET", "A.admin session", "405", r.status_code, r.status_code in (404, 405))
        # positive control: correct Origin and CSRF are accepted by the guard (the request reaches the route)
        r = send(ctx, path, p, tok, {"Origin": e.portal}, base_form(), mp)
        rec.add(f"E-GUARD-{path}-positive-control", "E", path, "POST", "A.admin session", "guard passes (no origin/csrf refusal text)",
                r.status_code, ORIGIN_MSG not in r.text and CSRF_MSG not in r.text and r.status_code < 500, r.text[:80].replace("\n", " "))
        rec.cover("portal_post_guard", "POST", path)
    # the harness's CSRF construction equals what the page embeds
    r = e.http.request("GET", e.portal + "/devices", headers={"Cf-Access-Jwt-Assertion": tok})
    rec.add("E-GUARD-csrf-matches-page-token", "E", "/devices", "GET", "A.admin", "page embeds the HMAC-derived token", r.status_code,
            csrf_for(tok) in r.text, "harness derivation validated against the rendered token")


class Evil(BaseHTTPRequestHandler):
    portal = ""
    device = ""

    def do_GET(self):
        if self.path.startswith("/form"):
            html = (f'<html><body><form id=f method=post action="{self.portal}/devices/retirement">'
                    f'<input name=device_id value="{self.device}"><input name=retired value=true>'
                    f'<input name=reason value="cross-site"></form><script>document.getElementById("f").submit()</script></body></html>')
        elif self.path.startswith("/fetch"):
            html = (f'<html><body><script>fetch("{self.portal}/devices/retirement",{{method:"POST",credentials:"include",mode:"no-cors",'
                    f'headers:{{"Content-Type":"application/x-www-form-urlencoded"}},body:"device_id={self.device}&retired=true&reason=x"}})'
                    f'.then(()=>document.title="sent").catch(e=>document.title="blocked")</script></body></html>')
        else:
            html = "<html></html>"
        b = html.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):
        pass


def browser_checks(ctx):
    from playwright.sync_api import sync_playwright
    rec, e = ctx.rec, ctx.e
    shots = ctx.scratch / "shots"
    shots.mkdir(exist_ok=True)
    tok = ctx.tok("A.admin")
    A = ctx.objs["A"]
    pages = [r["path"] for r in ctx.portal_routes["routes"] if "GET" in (r["methods"] or []) and r["path"] not in ("/healthz",)
             and not r["path"].startswith("/static") and not r["path"].endswith((".csv", ".pdf")) and not params_of(r["path"])]
    param_pages = [(r["path"], fill(r["path"], {k: (A["device_id"] if "device" in k else A["decl_id"] if "decl" in k else
                                                    str(A["alert_ids"][0]) if "alert" in k else A["report_id"]) for k in params_of(r["path"])}))
                   for r in ctx.portal_routes["routes"] if "GET" in (r["methods"] or []) and params_of(r["path"])
                   and not r["path"].endswith((".csv", ".pdf", "/download"))]
    targets = [(p, p) for p in pages] + param_pages
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            ctx_b = browser.new_context(extra_http_headers={"Cf-Access-Jwt-Assertion": tok})
            page = ctx_b.new_page()
            dialogs = []
            page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
            seen_text = 0
            for tmpl, url in targets:
                dialogs.clear()
                resp = page.goto(e.portal + url, wait_until="load")
                page.wait_for_timeout(150)
                html = page.content()
                xss = page.evaluate("() => ({a: typeof window.__xss_A, b: typeof window.__xss_B})")
                script_inj = page.evaluate("() => Array.from(document.scripts).some(s => s.textContent.includes('__xss_'))")
                img_inj = page.evaluate("() => !!document.querySelector('img[onerror]')")
                hit_text = "CANARY-A-XSS" in (page.inner_text("body") if page.query_selector("body") else "")
                seen_text += hit_text
                ok = (resp.status < 500 and not dialogs and xss["a"] == "undefined" and not script_inj and not img_inj
                      and "<script>window.__xss_A" not in html and "<img src=x onerror" not in html)
                rec.add(f"E-XSS-render-{tmpl}", "E", url, "GET", "A.admin in Chromium", "stored script/img payload inert: no dialog, no injected element, no global set",
                        {"status": resp.status, "dialogs": list(dialogs), "window_xss": xss["a"], "script": script_inj, "img_onerror": img_inj,
                         "payload_shown_as_text": hit_text}, ok)
            rec.add("E-XSS-positive-control-payload-displayed-as-text", "E", "portal pages", "GET", "A.admin in Chromium",
                    "payload text is displayed as text on at least 3 pages (so the pages that carry it were exercised)", seen_text, seen_text >= 3)
            for name, url in (("software", "/software"), ("devices", "/devices"), ("device-detail", f"/devices/{A['device_id']}"),
                              ("extensions", "/extensions"), ("findings", "/findings")):
                page.goto(e.portal + url, wait_until="load")
                page.screenshot(path=str(shots / f"portal-A-admin-{name}.png"), full_page=True)
            # Real cross-origin form post and fetch from another origin on the same host (cookie is sent: same site)
            Evil.portal, Evil.device = e.portal, A["win_device_id"]
            srv = ThreadingHTTPServer(("127.0.0.1", 0), Evil)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            evil = f"http://127.0.0.1:{srv.server_address[1]}"
            before = ctx.papi("A.admin", "GET", f"/devices/{A['win_device_id']}/retirement/history").json()
            ck = browser.new_context()
            ck.add_cookies([{"name": "CF_Authorization", "value": tok, "url": e.portal, "httpOnly": True, "sameSite": "Lax"}])
            p2 = ck.new_page()
            seen = []
            p2.on("response", lambda r: seen.append((r.url, r.status)) if r.url.startswith(e.portal) else None)
            p2.goto(evil + "/form", wait_until="load")
            p2.wait_for_timeout(500)
            body = p2.inner_text("body")
            posted = [s for u, s in seen if u.endswith("/devices/retirement")]
            p2.screenshot(path=str(shots / "portal-cross-origin-form-refused.png"))
            rec.add("E-BROWSER-cross-origin-form-post", "E", "/devices/retirement", "POST", "A.admin cookie, form on another origin",
                    "403 origin refusal page, no state change", posted, bool(posted) and posted[0] == 403 and ORIGIN_MSG in body)
            p3 = ck.new_page()
            seen.clear()
            p3.goto(evil + "/fetch", wait_until="load")
            p3.wait_for_timeout(500)
            posted = [s for u, s in seen if u.endswith("/devices/retirement")]
            rec.add("E-BROWSER-cross-origin-fetch-no-cors", "E", "/devices/retirement", "POST", "A.admin cookie, fetch from another origin",
                    "request, if sent, answered 403", posted or "no response observed", all(s == 403 for s in posted))
            after = ctx.papi("A.admin", "GET", f"/devices/{A['win_device_id']}/retirement/history").json()
            rec.add("E-BROWSER-cross-origin-no-state-change", "E", "/v1/portal/devices/{id}/retirement/history", "GET", "A.admin",
                    "retirement history unchanged by the cross-origin attempts", len(after.get("decisions", [])),
                    len(after.get("decisions", [])) == len(before.get("decisions", [])))
            # in-browser positive control: the page's own form with its own token is accepted by the guard
            page.goto(e.portal + f"/devices/{A['win_device_id']}", wait_until="load")
            token_in_page = page.evaluate("() => { const i = document.querySelector('input[name=csrf_token]'); return i ? i.value : '' }")
            r = page.request.post(e.portal + "/devices/retirement", form={"csrf_token": token_in_page, "device_id": A["win_device_id"],
                                  "retired": "false", "reason": "same-origin control"}, headers={"Origin": e.portal})
            rec.add("E-BROWSER-same-origin-positive-control", "E", "/devices/retirement", "POST", "A.admin in Chromium",
                    "the page's own token and origin pass the guard", r.status, bool(token_in_page) and r.status < 400 and ORIGIN_MSG not in r.text())
            srv.shutdown()
        finally:
            browser.close()


def run(ctx):
    guard_checks(ctx)
    browser_checks(ctx)
