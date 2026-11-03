#!/usr/bin/env python3
"""Run synthetic tenant-boundary checks on an owned private PostgreSQL.

No existing DATABASE_URL is used. Requires local initdb, pg_ctl, createdb and Go.
The original denial reproducer also runs in ordinary integration coverage.
"""
import argparse
import os
from pathlib import Path
import shutil
import secrets
import socket
import subprocess
import sys
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reproduce-disable", action="store_true")
    parser.add_argument("--full", action="store_true", help="run full integration and DB-backed Go package suites")
    parser.add_argument("--pg-bin", type=Path, help="directory of complete PostgreSQL server binaries")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    commands = {}
    pg_bin = args.pg_bin
    if pg_bin is None:
        for candidate in (Path("/opt/homebrew/opt/postgresql@16/bin"), Path(shutil.which("initdb") or "/missing").resolve().parent):
            if (candidate / "postgres").is_file():
                pg_bin = candidate
                break
    if pg_bin is None or not (pg_bin / "postgres").is_file():
        parser.error("complete PostgreSQL server binaries required, set --pg-bin")
    for name in ("initdb", "pg_ctl", "createdb", "createuser", "go"):
        commands[name] = shutil.which(name) if name == "go" else str(pg_bin / name)
        commands[name] = commands[name] or "/missing"
        if not Path(commands[name]).is_file():
            parser.error(f"missing prerequisite {name}")
    env = os.environ.copy()
    for key in tuple(env):
        if key.startswith("PG") or key in ("DATABASE_URL", "TEST_DATABASE_URL"):
            env.pop(key, None)
    env["DEVELOPER_DIR"] = "/Library/Developer/CommandLineTools"
    port = 5432
    password = secrets.token_urlsafe(32) if args.full else None
    if args.full:
        # Select a loopback ephemeral port; a bind race fails startup safely.
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
    work = tempfile.mkdtemp(prefix="pat2379-")
    data = str(Path(work) / "data")
    started = False
    def dsn(database):
        if args.full:
            return f"postgresql://readiness:{password}@127.0.0.1:{port}/{database}?sslmode=disable"
        return f"postgresql://readiness@/{database}?host={work}&sslmode=disable"
    failures = []
    def run(argv, collect=False):
        print("RUN", " ".join(argv), flush=True)
        result = subprocess.run(argv, cwd=root, env=env)
        print("EXIT", result.returncode, flush=True)
        if result.returncode:
            if not collect:
                raise subprocess.CalledProcessError(result.returncode, argv)
            failures.append(subprocess.CalledProcessError(result.returncode, argv))
    try:
        init = [commands["initdb"], "-D", data, "-U", "readiness", "--auth-local=trust",
                "--auth-host=scram-sha-256" if args.full else "--auth-host=reject", "--no-locale", "--encoding=UTF8"]
        if args.full:
            pwfile = Path(work) / "init-password"
            pwfile.touch(mode=0o600)
            pwfile.write_text(password + "\n")
            init += ["--pwfile", str(pwfile)]
        run(init)
        if args.full:
            pwfile.unlink()
        host = "127.0.0.1" if args.full else "''"
        run([commands["pg_ctl"], "-D", data, "-l", str(Path(work) / "postgres.log"), "-o", f"-k {work} -h {host} -p {port}", "-w", "start"])
        started = True
        run([commands["createuser"], "-h", work, "-p", str(port), "-U", "readiness", "patched"])
        run([commands["createdb"], "-h", work, "-p", str(port), "-U", "readiness", "readiness_test"])
        env["TEST_DATABASE_URL"] = dsn("readiness_test")
        positive = "Test(PortalCrossTenantIsolationMatrix|PortalAuthFailureModes|PortalApprovalWriteRequiresAdmin|PortalApprovalCrossTenantIsolation|PortalScheduleLifecycleAndIsolation|PortalTypedScheduleIsolation|PortalScheduleSweeperSameSlotPerTypeIsolation|PortalServiceIdentityIsReadOnlyAndTenantScoped|PortalSoftwareDeviceIDCrossTenantIs404WithNoRowData|PortalExtensionsDeviceIDCrossTenantIs404WithNoRowData|TenantExport|MandatoryInstallStatusPublicRouteStrictV3AndReplay)$"
        positive = positive[:-2] + "|PortalEmailDomainAutoBinding|PortalRevokedExplicitTenantCannotRebindThroughDomain|PortalDBLookupPrecedenceAndFailures|PAT2367DisabledUserCannotRebindThroughDomain)$"
        integration = [commands["go"], "test", "-count=1", "-v", "-timeout=300s", "-tags=integration", "./integration"]
        run(integration if args.full else integration + ["-run", positive], collect=args.full)
        if args.full:
            env["PATCHED_DB_TESTS_REQUIRED"] = "1"
            # Serial packages avoid shared-fixture interference; integration
            # already applied migrations, so these reuse its database.
            run([commands["go"], "test", "-p=1", "-count=1", "-v", "-timeout=180s", "./..."], collect=True)
            run([commands["createdb"], "-h", work, "-p", str(port), "-U", "readiness", "kek_test"])
            env["TEST_DATABASE_URL"] = dsn("kek_test")
            run([commands["go"], "test", "-count=1", "-v", "-timeout=120s", "-tags=integration", "./cmd/patched-kek-backfill/..."], collect=True)
        else:
            run([commands["go"], "test", "-count=1", "-v", "./cmd/patched-api", "./internal/auth", "./internal/portalauth"])
            run([commands["go"], "test", "-count=1", "-v", "./internal/handlers", "-run", "Test(EnrolmentKey.*|EnrolHandler_ConcurrentSingleUse|EnrolHandler_RollbackLeavesTokenUnconsumed|PortalEnrolmentGenerateHandler_.*|AssessmentDownload_DB_ExpiryReplayTenantAndHash)$"])
        if args.reproduce_disable:
            # TestMain reapplies forward migrations: use another fresh DB.
            run([commands["createdb"], "-h", work, "-p", str(port), "-U", "readiness", "repro_test"])
            env["TEST_DATABASE_URL"] = dsn("repro_test")
            run([commands["go"], "test", "-count=1", "-v", "-tags=integration,adversarial", "./integration", "-run", "TestPAT2367DisabledUserCannotRebindThroughDomain$"])
        if failures:
            raise failures[0]
    finally:
        if started or (Path(data) / "postmaster.pid").exists():
            stop = subprocess.run([commands["pg_ctl"], "-D", data, "-m", "immediate", "-w", "stop"], env=env)
            if stop.returncode or (Path(data) / "postmaster.pid").exists():
                print(f"STOP FAILED: retained owned cluster {work}", file=sys.stderr)
                raise subprocess.CalledProcessError(stop.returncode or 1, stop.args)
        shutil.rmtree(work)
        print("CLEANUP removed owned cluster", flush=True)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(f"FAILED: command exited {exc.returncode}", file=sys.stderr)
        sys.exit(exc.returncode)
