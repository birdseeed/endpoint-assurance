#!/usr/bin/env python3
"""Isolated tenant-boundary environment for Patched (PAT-2367).

Subcommands:
  up      build and start Postgres, local identity issuer, platform, portal, staff console
  seed    create the two disposable tenants' principals and synthetic data
  run     run the boundary matrix (A-G); writes JSON results
  down    stop everything, confirm nothing is left listening
  all     up, seed, run, down (down always runs)

Everything binds 127.0.0.1. Nothing here talks to any *.patched.im host, any
Tailscale host or Cloudflare. All keys, passwords and tokens are generated at
run time into the scratch directory (IB_SCRATCH) and are never committed.
"""
import base64
import json
import os
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
GO_SERVICE = HERE.parents[1]
REPO_PARENT = Path(os.environ.get("IB_REPOS", "/Users/andybridson/Development/Patched.im"))
SCRATCH = Path(os.environ.get(
    "IB_SCRATCH", "/private/tmp/claude-501/-Users-andybridson/4c68e7e2-21de-4eca-b811-d38552ae5b1d/scratchpad/pat-2367"))
PG_BIN = Path(os.environ.get("IB_PG_BIN", "/opt/homebrew/opt/postgresql@16/bin"))
PORTAL_REPO = Path(os.environ.get("IB_PORTAL_REPO", REPO_PARENT / "portal"))
DASH_REPO = Path(os.environ.get("IB_DASHBOARD_REPO", REPO_PARENT / "dashboard"))
PORTAL_PY = Path(os.environ.get("IB_PORTAL_PYTHON", PORTAL_REPO / ".venv/bin/python"))
STATE = SCRATCH / "state.json"
AUD = "ib-synthetic-aud-tag-0001"
SERVICE_CN = "ib-synthetic-service-token"
OWNER_STAFF = "staff.owner@patched.example"
CONSULTANT_STAFF = "staff.consultant@patched.example"
GO_ENV = {"DEVELOPER_DIR": "/Library/Developer/CommandLineTools"}


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def load_state():
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def save_state(st):
    STATE.write_text(json.dumps(st, indent=1))
    STATE.chmod(0o600)


def sh(argv, env=None, cwd=None, check=True, quiet=False):
    r = subprocess.run(argv, env=env, cwd=cwd, capture_output=True, text=True)
    if check and r.returncode:
        raise SystemExit(f"command failed ({r.returncode}): {' '.join(map(str, argv))}\n{r.stdout[-1500:]}\n{r.stderr[-1500:]}")
    return r


def sandbox_env(extra):
    """Minimal environment. Any outbound request to a non-loopback host is sent to a dead local
    proxy and fails closed (loopback is never proxied)."""
    env = {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": str(SCRATCH / "home"),
           "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
           "http_proxy": "http://127.0.0.1:9", "https_proxy": "http://127.0.0.1:9",
           "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost", "LANG": "en_GB.UTF-8"}
    env.update(extra)
    return env


def spawn(name, argv, env, cwd, st):
    log = open(SCRATCH / "logs" / f"{name}.log", "ab")
    p = subprocess.Popen(argv, env=env, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    st.setdefault("pids", {})[name] = p.pid
    save_state(st)
    return p


def wait_http(url, timeout=40, ok=lambda c: c < 500, ctx=None):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=2, context=ctx) as r:
                if ok(r.status):
                    return True
        except urllib.error.HTTPError as e:
            if ok(e.code):
                return True
            last = e
        except Exception as e:
            last = e
        time.sleep(0.3)
    raise SystemExit(f"timeout waiting for {url}: {last}")


def pin_sources(st):
    """Pinned copies of origin/main for the portal and the staff console, never the live checkouts."""
    for name, repo in (("portal", PORTAL_REPO), ("dashboard", DASH_REPO)):
        sh(["git", "-C", str(repo), "fetch", "origin"], check=False)
        sha = sh(["git", "-C", str(repo), "rev-parse", "origin/main"]).stdout.strip()
        dest = SCRATCH / "src" / name
        if st.get(f"{name}_sha") != sha or not dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
            dest.mkdir(parents=True)
            arc = subprocess.Popen(["git", "-C", str(repo), "archive", sha], stdout=subprocess.PIPE)
            subprocess.run(["tar", "-x", "-C", str(dest)], stdin=arc.stdout, check=True)
            arc.wait()
        st[f"{name}_sha"] = sha
    st["platform_sha"] = sh(["git", "-C", str(GO_SERVICE), "rev-parse", "HEAD"]).stdout.strip()
    st["platform_dirty"] = bool(sh(["git", "-C", str(GO_SERVICE), "status", "--porcelain", "--", ".",
                                    ":(exclude)scripts/isolated-boundary", ":(exclude)docs/security"]).stdout.strip())


def ensure_dash_venv():
    venv = SCRATCH / "venv-dash"
    if not (venv / "bin/python").exists():
        sh([sys.executable, "-m", "venv", str(venv)])
    req = SCRATCH / "src/dashboard/requirements.txt"
    marker = venv / ".req-installed"
    if not marker.exists():
        sh([str(venv / "bin/pip"), "install", "-q", "-r", str(req)])
        marker.write_text("ok")
    return venv / "bin/python"


def start_postgres(st):
    pg = SCRATCH / "pg"
    shutil.rmtree(pg, ignore_errors=True)
    pg.mkdir(parents=True)
    port = free_port()
    admin_pw, app_pw = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    pwfile = pg / "pw"
    pwfile.write_text(admin_pw + "\n")
    pwfile.chmod(0o600)
    sh([PG_BIN / "initdb", "-D", pg / "data", "-U", "ibadmin", "--auth=scram-sha-256", "--pwfile", pwfile,
        "--no-locale", "--encoding=UTF8"], quiet=True)
    pwfile.unlink()
    # The scratch path is longer than the 103-byte unix socket limit, so Postgres listens on loopback TCP only.
    sh([PG_BIN / "pg_ctl", "-D", pg / "data", "-l", SCRATCH / "logs/postgres.log", "-w", "-o",
        f"-c listen_addresses=127.0.0.1 -p {port} -c unix_socket_directories=''", "start"])
    st.update(pg_port=port, pg_admin_pw=admin_pw, pg_app_pw=app_pw)
    save_state(st)
    penv = {"PGPASSWORD": admin_pw, "PATH": "/usr/bin:/bin"}
    psql = lambda db, *a: sh([PG_BIN / "psql", "-h", "127.0.0.1", "-p", str(port), "-U", "ibadmin", "-d", db,
                              "-v", "ON_ERROR_STOP=1", "-q", *a], env=penv)
    psql("postgres", "-c", f"CREATE ROLE patched LOGIN NOSUPERUSER PASSWORD '{app_pw}'")
    psql("postgres", "-c", "CREATE DATABASE patched_ib OWNER ibadmin")
    mig = sorted(p for p in (GO_SERVICE / "migrations").glob("*.sql") if not p.name.endswith("_rollback.sql"))
    for f in mig:
        text = f.read_text()
        if text.startswith("-- migrate:statement-by-statement"):
            stmt = []
            for line in text.split("\n"):
                t = line.strip()
                if not t or t.startswith("--"):
                    continue
                stmt.append(line)
                if t.endswith(";"):
                    psql("patched_ib", "-c", "\n".join(stmt))
                    stmt = []
            if stmt:
                psql("patched_ib", "-c", "\n".join(stmt))
        else:
            psql("patched_ib", "-f", str(f))
    st["migrations_applied"] = len(mig)
    save_state(st)


def platform_env(st, with_service):
    e = {
        "DATABASE_URL": f"postgresql://patched:{st['pg_app_pw']}@127.0.0.1:{st['pg_port']}/patched_ib?sslmode=disable",
        "LISTEN_PUBLIC": f"127.0.0.1:{st['public_port']}", "LISTEN_INTERNAL": f"127.0.0.1:{st['internal_port']}",
        "ADMIN_API_TOKEN": st["admin_token"],
        "PORTAL_ACCESS_TEAM_DOMAIN": f"127.0.0.1:{st['idp_port']}", "PORTAL_ACCESS_AUD": AUD,
        "AGENT_CONFIG_SIGNING_KEY": st["signing_seed_b64"], "PATCHED_KEK": st["kek_b64"],
        "PATCHED_ARTIFACT_DIR": str(SCRATCH / "artifacts"), "PATCHED_BACKUP_HEALTH_DIR": str(SCRATCH / "health"),
        "REPORT_STORAGE_ROOT": str(SCRATCH / "reports"), "PATCHED_MAINTENANCE_FACTS_PATH": str(SCRATCH / "maint.json"),
        "RATE_LIMIT_RPM": "600000", "RATE_LIMIT_BURST": "100000",
        "PORTAL_RATE_LIMIT_RPM": "600000", "PORTAL_RATE_LIMIT_BURST": "100000",
        "PORTAL_ENROL_MINTS_PER_HOUR": "1000",
        "JAMF_WEBHOOK_PUBLIC_BASE_URL": "http://127.0.0.1",
        "IB_EXTRA_CA_FILE": str(SCRATCH / "keys/ca.pem"),
    }
    if with_service:
        e["PORTAL_SERVICE_TOKEN_COMMON_NAME"] = SERVICE_CN
        e["PORTAL_SERVICE_TOKEN_TENANT_ID"] = st["tenants"]["A"]["id"]
    return sandbox_env(e)


def start_platform(st, with_service):
    p = spawn("platform", [str(SCRATCH / "bin/patched-api")], platform_env(st, with_service), GO_SERVICE, st)
    wait_http(f"http://127.0.0.1:{st['public_port']}/health")
    wait_http(f"http://127.0.0.1:{st['internal_port']}/health")
    return p


def stop_pid(name, st, sig=signal.SIGTERM):
    pid = st.get("pids", {}).pop(name, None)
    if not pid:
        return
    try:
        os.killpg(pid, sig)
    except (ProcessLookupError, PermissionError):
        return
    for _ in range(50):
        try:
            os.waitpid(pid, os.WNOHANG)  # reap if it is our child
        except ChildProcessError:
            pass
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        try:
            os.killpg(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    save_state(st)


def admin(st, method, path, body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{st['internal_port']}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {st['admin_token']}", "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read() or b"null")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def cmd_up(args):
    for d in ("src", "bin", "logs", "keys", "results", "shots", "artifacts", "health", "reports", "home", "dash-state"):
        (SCRATCH / d).mkdir(parents=True, exist_ok=True)
    if load_state().get("pids"):
        raise SystemExit("environment already recorded as up; run `ib.py down` first")
    st = {"pids": {}, "started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    pin_sources(st)
    save_state(st)
    sys.path.insert(0, str(HERE))
    import idp
    idp.generate_keys(SCRATCH)
    st.update(public_port=free_port())
    st.update(internal_port=free_port(), idp_port=free_port(), portal_port=free_port(), dash_port=free_port(),
              tap_port=free_port(), extractor_port=free_port())
    st.update(admin_token="ib-synthetic-admin-" + secrets.token_urlsafe(24),
              dash_api_key="ib-synthetic-dash-key-" + secrets.token_urlsafe(24),
              signing_seed_b64=base64.b64encode(os.urandom(32)).decode(), kek_b64=base64.b64encode(os.urandom(32)).decode())
    (SCRATCH / "keys/admin.token").write_text(st["admin_token"])
    (SCRATCH / "keys/admin.token").chmod(0o600)
    save_state(st)
    try:
        # 1. platform binary (overlay adds only the test-CA trust init; no product file changes)
        overlay = {"Replace": {
            str(GO_SERVICE / "cmd/patched-api/zz_ib_trust.go"): str(HERE / "testdata/overlay/zz_ib_trust.go"),
            str(GO_SERVICE / "cmd/patched-api/zz_ib_routes_test.go"): str(HERE / "testdata/overlay/zz_ib_routes_test.go")}}
        (SCRATCH / "overlay.json").write_text(json.dumps(overlay))
        genv = {**os.environ, **GO_ENV}
        sh(["go", "build", "-overlay", SCRATCH / "overlay.json", "-o", SCRATCH / "bin/patched-api", "./cmd/patched-api"],
           env=genv, cwd=GO_SERVICE)
        sh(["go", "build", "-o", SCRATCH / "bin/patched-extractor", "./cmd/patched-extractor"], env=genv, cwd=GO_SERVICE)
        r = sh(["go", "test", "-overlay", SCRATCH / "overlay.json", "-count=1", "-run", "TestIBRouteInventory", "./cmd/patched-api"],
               env={**genv, "IB_ROUTES_OUT": str(SCRATCH / "results/platform-routes.json")}, cwd=GO_SERVICE)
        # 2. database
        start_postgres(st)
        # 3. identity issuer (HTTPS JWKS on loopback)
        spawn("idp", [str(PORTAL_PY), str(HERE / "idp.py"), "serve", str(SCRATCH), str(st["idp_port"])],
              sandbox_env({}), HERE, st)
        import ssl
        ctx = ssl.create_default_context(cafile=str(SCRATCH / "keys/ca.pem"))
        wait_http(f"https://127.0.0.1:{st['idp_port']}/cdn-cgi/access/certs", ctx=ctx)
        # 4. platform, create the two tenants through the admin API, then restart with the service identity bound to A
        start_platform(st, with_service=False)
        st["tenants"] = {}
        for label in ("A", "B"):
            code, out = admin(st, "POST", "/admin/tenants", {"name": f"IB Tenant {label} CANARY-{label}-TENANT"})
            if code != 201:
                raise SystemExit(f"tenant create failed {code} {out}")
            st["tenants"][label] = {"id": out["tenant_id"], "bearer": out["bearer_token"], "hmac_b64": out["hmac_secret_b64"]}
        save_state(st)
        stop_pid("platform", st)
        start_platform(st, with_service=True)
        spawn("extractor", [str(SCRATCH / "bin/patched-extractor")], sandbox_env({
            "DATABASE_URL": platform_env(st, False)["DATABASE_URL"], "LISTEN_METRICS": f"127.0.0.1:{st['extractor_port']}",
            "EXTRACTOR_POLL_EVERY": "1s", "PATCHED_KEK": st["kek_b64"]}), GO_SERVICE, st)
        wait_http(f"http://127.0.0.1:{st['extractor_port']}/metrics")
        # 5. tap between console and platform internal API, then portal and console from pinned copies
        spawn("tap", [str(PORTAL_PY), str(HERE / "tap.py"), str(st["tap_port"]), str(st["internal_port"]),
                      str(SCRATCH / "logs/tap.jsonl"), str(SCRATCH / "keys/admin.token")], sandbox_env({}), HERE, st)
        penv = sandbox_env({
            "PLATFORM_BASE_URL": f"http://127.0.0.1:{st['public_port']}",
            "PORTAL_ACCESS_TEAM_DOMAIN": f"127.0.0.1:{st['idp_port']}", "PORTAL_ACCESS_AUD": AUD,
            "PORTAL_SERVICE_TOKEN_COMMON_NAME": SERVICE_CN,
            "REQUESTS_CA_BUNDLE": str(SCRATCH / "keys/ca.pem"), "SSL_CERT_FILE": str(SCRATCH / "keys/ca.pem"),
            "DEPLOYED_SHA_FILE": str(SCRATCH / "home/DEPLOYED_SHA")})
        spawn("portal", [str(PORTAL_PY), "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(st["portal_port"])],
              penv, SCRATCH / "src/portal", st)
        wait_http(f"http://127.0.0.1:{st['portal_port']}/healthz")
        dpy = ensure_dash_venv()
        denv = sandbox_env({
            "PATCHED_API_INTERNAL": f"http://127.0.0.1:{st['tap_port']}", "ADMIN_API_TOKEN": st["admin_token"],
            "DASHBOARD_API_KEY": st["dash_api_key"], "DASHBOARD_OPERATORS": OWNER_STAFF,
            "DASHBOARD_DB_PATH": str(SCRATCH / "dashboard.db"), "DASHBOARD_STATE_DIR": str(SCRATCH / "dash-state"),
            "PORTAL_ACCESS_AUD": AUD})
        spawn("dashboard", [str(dpy), "-m", "uvicorn", "main:app", "--host", "127.0.0.1", "--port", str(st["dash_port"])],
              denv, SCRATCH / "src/dashboard", st)
        wait_http(f"http://127.0.0.1:{st['dash_port']}/console", timeout=90)
        st["up"] = True
        save_state(st)
    except BaseException:
        print("bring-up failed; tearing down", file=sys.stderr)
        cmd_down(None)
        raise
    print(json.dumps({k: st[k] for k in ("platform_sha", "portal_sha", "dashboard_sha", "public_port", "internal_port",
                                         "idp_port", "portal_port", "dash_port", "pg_port")}, indent=1))


def cmd_down(args):
    st = load_state()
    for name in ("dashboard", "portal", "tap", "extractor", "platform", "idp"):
        stop_pid(name, st)
    if "pg_port" in st and (SCRATCH / "pg/data/postmaster.pid").exists():
        sh([PG_BIN / "pg_ctl", "-D", SCRATCH / "pg/data", "-m", "fast", "-w", "stop"], check=False)
    st.pop("up", None)
    save_state(st)
    # confirm nothing is left listening on the recorded ports
    left = []
    for key in ("pg_port", "public_port", "internal_port", "idp_port", "portal_port", "dash_port", "tap_port", "extractor_port"):
        port = st.get(key)
        if port:
            with socket.socket() as s:
                s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    left.append((key, port))
    print("TEARDOWN", "still listening: %s" % left if left else "nothing listening on any harness port")
    if left:
        sys.exit(1)


def cmd_seed(args):
    import seed
    seed.run(load_state(), SCRATCH)


def cmd_run(args):
    import matrix
    sys.exit(matrix.run(load_state(), SCRATCH, args))


def main():
    sys.path.insert(0, str(HERE))
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for n in ("up", "seed", "down", "all"):
        sub.add_parser(n)
    r = sub.add_parser("run")
    r.add_argument("--only", help="comma separated check id prefixes, e.g. A,B or B-READ")
    args = ap.parse_args()
    if args.cmd == "all":
        try:
            cmd_up(args)
            cmd_seed(args)
            args.only = None
            cmd_run(args)
        finally:
            cmd_down(args)
    else:
        {"up": cmd_up, "seed": cmd_seed, "run": cmd_run, "down": cmd_down}[args.cmd](args)


if __name__ == "__main__":
    main()
