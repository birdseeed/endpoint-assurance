"""Shared client helpers: loopback-only HTTP, principals, signed ingestion."""
import hashlib
import hmac
import json
import secrets
import time
from pathlib import Path
from urllib.parse import urlparse

import requests

import idp

AUD = "ib-synthetic-aud-tag-0001"
SERVICE_CN = "ib-synthetic-service-token"
OWNER_STAFF = "staff.owner@patched.example"
CONSULTANT_STAFF = "staff.consultant@patched.example"

# Synthetic principals. The harness seeds the two roles an operator hands out, admin and viewer. Since PAT-1883 the
# product also has an owner role; the harness has no owner principal, so on the owner-only /v1/portal/access writes the
# matrix checks the refusals (viewer, admin, non-member, service identity) and the platform's own tests cover the owner.
PRINCIPALS = {
    "A": {"admin": "alice.admin@tenant-a.example", "viewer": "vera.viewer@tenant-a.example",
          "disabled": "dave.disabled@tenant-a.example", "domain": "dom.user@dom-a.example", "domain_name": "dom-a.example"},
    "B": {"admin": "bob.admin@tenant-b.example", "viewer": "wendy.viewer@tenant-b.example",
          "disabled": "dora.disabled@tenant-b.example", "domain": "dom.user@dom-b.example", "domain_name": "dom-b.example"},
}
NOBODY = "nobody@nowhere.example"


def loopback_only(url):
    host = urlparse(url).hostname
    if host not in ("127.0.0.1", "localhost"):
        raise RuntimeError(f"refusing non-loopback request to {host}")


class Http:
    """requests wrapper that refuses any non-loopback URL and ignores proxy/env settings."""

    def __init__(self):
        self.s = requests.Session()
        self.s.trust_env = False

    def request(self, method, url, **kw):
        loopback_only(url)
        kw.setdefault("timeout", 30)
        kw.setdefault("allow_redirects", False)
        return self.s.request(method, url, **kw)


class Env:
    def __init__(self, st, scratch):
        self.st, self.scratch = st, Path(scratch)
        self.public = f"http://127.0.0.1:{st['public_port']}"
        self.internal = f"http://127.0.0.1:{st['internal_port']}"
        self.portal = f"http://127.0.0.1:{st['portal_port']}"
        self.dash = f"http://127.0.0.1:{st['dash_port']}"
        self.admin_token = st["admin_token"]
        self.tenants = st["tenants"]
        self.minter = idp.Minter(scratch, st["idp_port"], AUD)
        self.http = Http()

    def tok(self, email=None, **kw):
        return self.minter.mint(email=email, **kw)

    def admin(self, method, path, body=None, token="__admin__"):
        h = {"Content-Type": "application/json"}
        if token == "__admin__":
            h["Authorization"] = f"Bearer {self.admin_token}"
        elif token:
            h["Authorization"] = f"Bearer {token}"
        return self.http.request(method, self.internal + path, data=json.dumps(body) if body is not None else None, headers=h)

    def papi(self, method, path, token, body=None, params=None, headers=None, raw=None):
        h = {"Cf-Access-Jwt-Assertion": token} if token is not None else {}
        if body is not None:
            h["Content-Type"] = "application/json"
        if headers:
            h.update(headers)
        return self.http.request(method, self.public + "/v1/portal" + path, headers=h, params=params,
                                 data=raw if raw is not None else (json.dumps(body) if body is not None else None))

    def ingest(self, label, payload):
        t = self.tenants[label]
        body = json.dumps(payload).encode()
        import base64
        sig = hmac.new(base64.b64decode(t["hmac_b64"]), body, hashlib.sha256).hexdigest()
        h = {"Content-Type": "application/json", "Authorization": f"Bearer {t['bearer']}",
             "X-Patched-Signature": sig, "X-Patched-Timestamp": str(int(time.time())), "X-Patched-Nonce": secrets.token_hex(16)}
        return self.http.request("POST", self.public + "/v1/inventory", data=body, headers=h)
