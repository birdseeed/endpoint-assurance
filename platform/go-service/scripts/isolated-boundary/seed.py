"""Create synthetic principals and tenant-specific data through the platform's own routes.

Admin API (internal listener, throwaway bearer): tenants (done in `up`), portal users, domain claims.
Signed inventory ingestion (public listener, tenant bearer + HMAC): devices, apps, extensions.
Portal API as each tenant's admin: certificate, software declaration, retirement, device list,
report, schedule, enrolment key, notifications, Jamf token.
SQL is not used anywhere.
"""
import base64
import copy
import datetime
import json
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import ibclient
from ibclient import PRINCIPALS

FX = Path(__file__).resolve().parents[2] / "testdata/payload-fixtures/valid"


def need(r, *ok):
    if r.status_code not in (ok or (200, 201)):
        raise SystemExit(f"seed step failed: {r.request.method} {r.url} -> {r.status_code} {r.text[:300]}")
    return r


def make_cert(cn):
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now)
         .not_valid_after(now + datetime.timedelta(days=90)).sign(k, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.DER)


def mac_payload(L, n, hosts_extra=True):
    p = json.loads((FX / "full.json").read_text())
    ext = json.loads((FX / "with-browser-extensions.json").read_text())["browser_extensions"]
    p["tenant_id"] = ibclient_tenant[L]
    p["device"].update(serial=f"SER-{L}-MAC-{n}", hw_uuid=f"{L * 8}-0000-4000-8000-00000000000{n}",
                       hostname=f"CANARY-{L}-HOST-{n}", computer_name=f"CANARY-{L} Mac {n}")
    base = p["apps"][1]
    team = f"CNRY{L}0000{n}"
    p["apps"] = [
        {**base, "name": f"CANARY-{L}-APP-{n}", "bundle_id": f"com.canary{L.lower()}.app{n}", "team_id": team,
         "path": f"/Applications/Canary{L}{n}.app", "signed_by": f"CANARY-{L}-SIGNER"},
        {**base, "name": f"<script>window.__xss_{L}=1</script>CANARY-{L}-XSS", "bundle_id": f"com.canary{L.lower()}.xss{n}",
         "team_id": team, "path": f"/Applications/Xss{L}{n}.app"},
        {**base, "name": f"<img src=x onerror=alert('{L}')>CANARY-{L}-IMG", "bundle_id": f"com.canary{L.lower()}.img{n}",
         "team_id": team, "path": f"/Applications/Img{L}{n}.app"},
        {**base, "name": f"=HYPERLINK(\"http://127.0.0.1/\",\"x\")CANARY-{L}-FORMULA", "bundle_id": f"com.canary{L.lower()}.f1{n}",
         "team_id": team, "path": f"/Applications/F1{L}{n}.app"},
        {**base, "name": f"+SUM(1)CANARY-{L}-PLUS", "bundle_id": f"com.canary{L.lower()}.f2{n}", "team_id": team,
         "path": f"/Applications/F2{L}{n}.app"},
        {**base, "name": f"@SUM(1)CANARY-{L}-AT", "bundle_id": f"com.canary{L.lower()}.f3{n}", "team_id": team,
         "path": f"/Applications/F3{L}{n}.app"},
        {**base, "name": f"-2+3CANARY-{L}-MINUS", "bundle_id": f"com.canary{L.lower()}.f4{n}", "team_id": team,
         "path": f"/Applications/F4{L}{n}.app"},
    ]
    p["browser_extensions"] = [dict(x, name=f"CANARY-{L}-EXT-{i}" if i != 2 else f"=1+1CANARY-{L}-EXTFORMULA",
                                    extension_id=x["extension_id"] + f"{L.lower()}{n}"[:0]) for i, x in enumerate(ext)]
    for c in p.get("certificates", []):
        c["subject_cn"] = f"CANARY-{L}-CERTCN"
    return p


def win_payload(L):
    p = json.loads((FX / "full-v3-windows.json").read_text())
    p["tenant_id"] = ibclient_tenant[L]
    p["device"].update(serial=f"SER-{L}-WIN-1", hw_uuid=f"{L * 8}-1111-4111-8111-111111111111", hostname=f"CANARY-{L}-WINHOST")
    p["apps"][0]["name"] = f"CANARY-{L}-WINAPP"
    p["apps"][1]["name"] = f"=CMD|' /C calc'!A0 CANARY-{L}-WINFORMULA"
    return p


ibclient_tenant = {}


def run(st, scratch):
    e = ibclient.Env(st, scratch)
    objs = st.setdefault("objects", {})
    for L in "AB":
        ibclient_tenant[L] = e.tenants[L]["id"]
    for L in "AB":
        tid, pr = e.tenants[L]["id"], PRINCIPALS[L]
        need(e.admin("POST", "/admin/portal-users", {"email": pr["admin"], "tenant_id": tid, "role": "admin"}))
        need(e.admin("POST", "/admin/portal-users", {"email": pr["viewer"], "tenant_id": tid, "role": "viewer"}))
        need(e.admin("POST", "/admin/portal-users", {"email": pr["disabled"], "tenant_id": tid, "role": "admin"}))
        need(e.admin("DELETE", "/admin/portal-users/" + pr["disabled"]), 200)
        need(e.admin("POST", "/admin/tenant-email-domains", {"domain": pr["domain_name"], "tenant_id": tid}))
    for L in "AB":
        o = objs.setdefault(L, {})
        for n in (1, 2):
            need(e.ingest(L, mac_payload(L, n)))
        need(e.ingest(L, win_payload(L)))
    deadline = time.time() + 40
    while time.time() < deadline:
        counts = {L: e.papi("GET", "/devices", e.tok(PRINCIPALS[L]["admin"])).json().get("total") for L in "AB"}
        if all(v == 3 for v in counts.values()):
            break
        time.sleep(1)
    else:
        raise SystemExit(f"extractor did not materialise devices: {counts}")
    for L in "AB":
        adm = e.tok(PRINCIPALS[L]["admin"])
        o = objs[L]
        devs = e.papi("GET", "/devices", adm).json()["devices"]
        o["devices"] = {d["hostname"]: d["device_id"] for d in devs}
        o["device_id"] = o["devices"][f"CANARY-{L}-HOST-1"]
        o["device_id_2"] = o["devices"][f"CANARY-{L}-HOST-2"]
        o["win_device_id"] = o["devices"][f"CANARY-{L}-WINHOST"]
        cert = need(e.papi("POST", "/certificates", adm, {"label": f"CANARY-{L}-CERTLABEL",
                                                           "certificate": base64.b64encode(make_cert(f"CANARY-{L}-UPCERT")).decode()})).json()
        o["cert_id"] = cert["id"]
        decl = need(e.papi("POST", "/software-declarations", adm, {"name": f"CANARY-{L}-DECL", "publisher": f"CANARY-{L}-PUB",
                                                                    "platform": "macos", "justification": f"CANARY-{L}-JUST"})).json()
        o["decl_id"] = decl["id"]
        need(e.papi("PUT", f"/devices/{o['device_id_2']}/retirement", adm, {"retired": True, "reason": f"CANARY-{L}-RETIRE"}))
        need(e.papi("PUT", "/device-list", adm, {"filename": f"CANARY-{L}-list.csv", "entries": [{"hostname": f"CANARY-{L}-LISTED"}]}))
        dl = e.papi("GET", "/device-list", adm).json()
        o["device_list_raw"] = dl
        rep = need(e.papi("POST", "/reports", adm, {"report_type": "executive-summary"})).json()
        o["report_id"] = rep["id"]
        need(e.papi("PUT", "/reports/schedules/executive-summary", adm,
                    {"cadence": "weekly", "weekday": 1, "hour_utc": 3 if L == "A" else 5, "enabled": False}))
        key = need(e.papi("POST", "/enrolment-keys", adm, {"label": f"CANARY-{L}-KEY", "max_devices": 5, "expires_in_days": 7})).json()
        o["enrol_key_id"] = key["key_id"]
        need(e.papi("PUT", "/software-notifications", adm, {"unapproved_alerts_enabled": True, "new_software_enabled": False}))
        # approvals: a confirmed identity (bundle id plus team id) is required
        r = e.papi("PUT", "/software-approvals", adm, {"items": [{"type": "application", "platform": "macos",
                    "identifier": f"com.canary{L.lower()}.app1", "team_id": f"CNRY{L}00001"}], "state": "unapproved",
                    "reason": f"CANARY-{L}-REASON"})
        o["approval_status"] = r.status_code
        end = time.time() + 30
        al = {}
        while time.time() < end:
            al = e.papi("GET", "/software-alerts", adm).json()
            if al.get("alerts") or r.status_code != 200:
                break
            time.sleep(0.5)
        else:
            raise SystemExit("timed out waiting for the software alert raised by the approval write")
        o["alert_ids"] = [a.get("id") for a in al.get("alerts", [])]
        j = e.papi("POST", "/mdm/jamf/token", adm, {})
        o["jamf_token_status"] = j.status_code
        o["jamf_token_marker"] = (j.json().get("token") or j.json().get("plaintext") or "") if j.status_code in (200, 201) else ""
    st["seeded"] = True
    (Path(scratch) / "state.json").write_text(json.dumps(st, indent=1))
    print(json.dumps({L: {k: v for k, v in objs[L].items() if k != "device_list_raw"} for L in "AB"}, indent=1)[:3000])
