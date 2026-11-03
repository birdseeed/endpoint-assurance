#!/usr/bin/env python3
"""Schema drift detection for patched-api-01 (PAT-2053).

Prod's schema can silently differ from what the migrations produce: early
tables were hand-applied from pre-merge drafts, and deploy.sh never re-runs
anything below version 0056. CI and every test database are built from the
migrations, so nothing noticed until a migration failed on deploy (PAT-2051).

This tool closes that gap in two halves.

``build-journal`` (CI, on a throwaway PostgreSQL of the same major as prod)
    Applies every forward migration to an empty database in lexical order, the
    way deploy.sh and the integration harness do, and records the normalised
    fingerprint (schema_fingerprint.sql) after each conventioned migration
    (version >= 0056). The output is a compact journal: one full base
    fingerprint plus the added and removed lines per migration. Any release's
    expected schema can be rebuilt from it.

``check`` (the box, READ-ONLY, before migrations)
    Fingerprints the live database inside a read-only transaction, finds the
    newest conventioned migration the live database records, rebuilds the
    fingerprint the migrations produce at exactly that version, and compares.
    Differences listed in the allowlist are accepted. Anything else is printed
    as a diff and the exit status is non-zero, so the deploy stops before it
    applies anything.

Exit codes for ``check``: 0 clean (possibly with accepted differences),
1 unexplained drift, 2 the comparison could not be made (unknown head, major
version mismatch, bad journal, database unreachable). 2 is a refusal too.

Never prints the database URL. The URL is passed to psql as an argument, the
same exposure deploy.sh already has.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
FINGERPRINT_SQL = HERE / "schema_fingerprint.sql"
JOURNAL_MAGIC = "# patched schema fingerprint journal v1"
MIGRATION_FLOOR = 56
FORWARD_RE = re.compile(r"^([0-9]{4})_[a-z0-9_]+\.sql$")
VERSION_RE = re.compile(r"^([0-9]{4})_[a-z0-9_]+$")

EXIT_CLEAN = 0
EXIT_DRIFT = 1
EXIT_REFUSED = 2


class DriftError(Exception):
    """A comparison that cannot be made. Always a refusal, never a pass."""


# ---------------------------------------------------------------------------
# psql plumbing


def _psql(dsn: str, *args: str, read_only: bool = False, input_sql: str | None = None) -> str:
    env = dict(os.environ)
    if read_only:
        # Every transaction in this session is read-only: a write, if one were
        # ever added to the fingerprint query, fails instead of landing.
        env["PGOPTIONS"] = (env.get("PGOPTIONS", "") + " -c default_transaction_read_only=on").strip()
    cmd = ["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", dsn, *args]
    proc = subprocess.run(cmd, input=input_sql, capture_output=True, text=True, env=env, check=False)
    if proc.returncode != 0:
        # psql error text can include the host and database name but never the
        # password; still, keep only the first lines to avoid echoing SQL.
        err = "\n".join(proc.stderr.strip().splitlines()[:5])
        raise DriftError(f"psql failed (exit {proc.returncode}): {err}")
    return proc.stdout


def fingerprint(dsn: str, read_only: bool = True) -> list[str]:
    out = _psql(dsn, "-tA", "-f", str(FINGERPRINT_SQL), read_only=read_only)
    return [line for line in out.splitlines() if line]


def live_versions(dsn: str) -> list[str]:
    out = _psql(dsn, "-tA", "-c", "SELECT version FROM schema_migrations", read_only=True)
    return [v.strip() for v in out.splitlines() if v.strip()]


def conventioned(versions) -> list[str]:
    return sorted(v for v in versions if VERSION_RE.match(v) and int(v[:4]) >= MIGRATION_FLOOR)


def head_from_versions(versions: list[str]) -> str:
    recorded = conventioned(versions)
    if not recorded:
        raise DriftError("schema_migrations records no conventioned (>= 0056) migration")
    return recorded[-1]


_TABLE_KINDS = {"relation", "column", "constraint", "index", "trigger", "partition_key", "view", "sequence"}


def object_scope(line: str) -> str | None:
    """The object a fingerprint line belongs to: its table, function, type or extension."""
    parts = line.split("|")
    if len(parts) < 2 or parts[0] == "server_major":
        return None
    kind = "rel" if parts[0] in _TABLE_KINDS else parts[0]
    return f"{kind}:{parts[1]}"


# ---------------------------------------------------------------------------
# Journal


@dataclass
class Journal:
    base_version: str
    base: list[str]
    steps: list[tuple[str, list[str], list[str]]] = field(default_factory=list)  # (version, added, removed)

    def versions(self) -> list[str]:
        return [self.base_version] + [v for v, _, _ in self.steps]

    def expected_at(self, version: str) -> list[str]:
        """Expected fingerprint with every journal version up to ``version`` applied."""
        known = self.versions()
        if version not in known:
            raise DriftError(
                f"version {version} is not in the journal (journal covers "
                f"{self.base_version}..{known[-1]})"
            )
        return self.expected_for([v for v in known if v <= version])[0]

    def expected_for(self, recorded: list[str]) -> tuple[list[str], list[str]]:
        """Expected fingerprint for a database that records exactly ``recorded``.

        Migrations can merge and deploy out of number order, so a box may have
        applied 0175 while 0174 is still pending. The expected schema is the
        base plus the journal steps the box actually records, up to its head.
        Steps it lacks are skipped, and returned so the caller can say so.

        Skipping is only sound when the missing step's objects are independent
        of the later steps that were applied. When a skipped step touches the
        same table, function, type or extension as a later applied step, the
        reconstruction would be a guess, so this refuses and names the gap.
        """
        rec = set(conventioned(recorded))
        if not rec:
            raise DriftError("schema_migrations records no conventioned (>= 0056) migration")
        known = self.versions()
        unknown = sorted(rec - set(known))
        if unknown:
            raise DriftError(
                "the box records migration(s) this release's journal does not contain: "
                + ", ".join(unknown)
                + f" (journal covers {self.base_version}..{known[-1]}); no expected schema "
                "exists to compare against"
            )
        head = max(rec)
        if self.base_version not in rec:
            raise DriftError(
                f"gap: the box does not record the journal base {self.base_version}, "
                "so its expected schema cannot be rebuilt"
            )
        steps = [(v, a, r) for v, a, r in self.steps if v <= head]
        skipped = [v for v, _, _ in steps if v not in rec]
        if skipped:
            later_scopes: dict[str, set[str]] = {}
            for v, added, removed in steps:
                later_scopes[v] = {sc for sc in map(object_scope, added + removed) if sc}
            conflicts = []
            for sv in skipped:
                mine = later_scopes[sv]
                for v, _, _ in steps:
                    if v > sv and v in rec and mine & later_scopes[v]:
                        conflicts.append(f"{sv} (shares {', '.join(sorted(mine & later_scopes[v]))} with applied {v})")
                        break
            if conflicts:
                raise DriftError(
                    "gap: the box has not applied " + "; ".join(conflicts)
                    + ". A later migration it has applied touches the same objects, so the "
                    "expected schema cannot be rebuilt without it. Apply the missing "
                    "migration(s) by hand as the patched role, then re-run the check."
                )
        current = set(self.base)
        for v, added, removed in steps:
            if v not in rec:
                continue
            current.difference_update(removed)
            current.update(added)
        return sorted(current), skipped

    def dump(self) -> str:
        out = [JOURNAL_MAGIC, f"base {self.base_version}"]
        out += [f"= {line}" for line in self.base]
        for v, added, removed in self.steps:
            out.append(f"@ {v}")
            out += [f"- {line}" for line in removed]
            out += [f"+ {line}" for line in added]
        return "\n".join(out) + "\n"

    @classmethod
    def parse(cls, text: str) -> "Journal":
        lines = text.splitlines()
        if not lines or lines[0] != JOURNAL_MAGIC:
            raise DriftError("not a schema fingerprint journal (bad header)")
        if len(lines) < 2 or not lines[1].startswith("base "):
            raise DriftError("journal has no base line")
        journal = cls(base_version=lines[1][5:], base=[])
        step: tuple[str, list[str], list[str]] | None = None
        for n, line in enumerate(lines[2:], start=3):
            tag, _, rest = line.partition(" ")
            if tag == "=" and step is None:
                journal.base.append(rest)
            elif tag == "@":
                step = (rest, [], [])
                journal.steps.append(step)
            elif tag == "+" and step is not None:
                step[1].append(rest)
            elif tag == "-" and step is not None:
                step[2].append(rest)
            else:
                raise DriftError(f"journal line {n} is malformed")
        return journal


_SCRATCH_DSN_RE = re.compile(
    r"^postgres(?:ql)?://[^/@]*@?(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?/patched_test_[A-Za-z0-9_]+(?:\?.*)?$"
)


def _refuse_non_scratch(dsn: str) -> None:
    """build-journal replays every migration from 0001, so it must never be
    pointed at a real database. Accept only a local patched_test_* database;
    the DSN itself is never echoed."""
    if not _SCRATCH_DSN_RE.match(dsn):
        raise DriftError(
            "refusing to build a journal: the build DSN must name a local "
            "patched_test_* database (localhost or 127.0.0.1)"
        )


def build_journal(admin_dsn_db: str, migrations_dir: Path) -> Journal:
    """Apply forward migrations to an EMPTY database and journal fingerprints.

    ``admin_dsn_db`` must point at a freshly created, empty database. The
    caller owns creating and dropping it.
    """
    _refuse_non_scratch(admin_dsn_db)
    files = sorted(
        p for p in migrations_dir.iterdir()
        if p.is_file() and FORWARD_RE.match(p.name) and not p.name.endswith("_rollback.sql")
    )
    if not files:
        raise DriftError(f"no forward migrations in {migrations_dir}")
    journal: Journal | None = None
    previous: set[str] = set()
    for f in files:
        _psql(admin_dsn_db, "-f", str(f))
        number = int(f.name[:4])
        version = f.name[:-4]
        if number < MIGRATION_FLOOR:
            continue
        current = set(fingerprint(admin_dsn_db, read_only=False))
        if journal is None:
            journal = Journal(base_version=version, base=sorted(current))
        else:
            journal.steps.append((version, sorted(current - previous), sorted(previous - current)))
        previous = current
    if journal is None:
        raise DriftError("no conventioned (>= 0056) migration found to journal")
    return journal


# ---------------------------------------------------------------------------
# Allowlist and comparison


@dataclass
class AllowEntry:
    side: str  # "+" extra on live, "-" missing from live
    pattern: str
    lineno: int


def allow_matches(pattern: str, line: str) -> bool:
    """Exact match, except that a pattern ending in ``|*`` matches every line
    starting with the text before the ``*`` (for example every column of one
    table). No other character is special: ``[]``, ``?`` and a ``*`` anywhere
    else are literal, because fingerprint lines contain types such as
    ``text[]``."""
    if pattern.endswith("|*"):
        return line.startswith(pattern[:-1])
    return line == pattern


def parse_allowlist(text: str) -> list[AllowEntry]:
    entries = []
    for n, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        side, _, pattern = line.partition(" ")
        if side not in {"+", "-"} or not pattern.strip():
            raise DriftError(f"allowlist line {n} must be '+ <pattern>' or '- <pattern>'")
        entries.append(AllowEntry(side, pattern.strip(), n))
    return entries


@dataclass
class Comparison:
    extra: list[str]      # on live, not expected
    missing: list[str]    # expected, not on live
    accepted: list[str]   # "+ line" / "- line" matched by the allowlist
    unused: list[AllowEntry]

    @property
    def clean(self) -> bool:
        return not self.extra and not self.missing


def compare(expected: list[str], live: list[str], allow: list[AllowEntry]) -> Comparison:
    exp_major = [line for line in expected if line.startswith("server_major|")]
    live_major = [line for line in live if line.startswith("server_major|")]
    if exp_major != live_major:
        raise DriftError(
            f"PostgreSQL major differs (expected {exp_major or '?'}, live {live_major or '?'}); "
            "build the journal on the same major as the target"
        )
    exp, liv = set(expected), set(live)
    used: set[int] = set()
    extra, missing, accepted = [], [], []

    def allowed(side: str, line: str) -> bool:
        for e in allow:
            if e.side == side and allow_matches(e.pattern, line):
                used.add(e.lineno)
                return True
        return False

    for line in sorted(liv - exp):
        (accepted.append(f"+ {line}") if allowed("+", line) else extra.append(line))
    for line in sorted(exp - liv):
        (accepted.append(f"- {line}") if allowed("-", line) else missing.append(line))
    unused = [e for e in allow if e.lineno not in used]
    return Comparison(extra, missing, accepted, unused)


def report(cmp: Comparison, head: str, out=sys.stdout) -> None:
    print(f"schema drift check against the migrations at {head}", file=out)
    if cmp.accepted:
        print(f"accepted by allowlist: {len(cmp.accepted)} difference(s)", file=out)
    for e in cmp.unused:
        print(f"note: allowlist line {e.lineno} matched nothing ({e.side} {e.pattern}); remove it once confirmed", file=out)
    if cmp.clean:
        print("OK: live schema matches the migrations", file=out)
        return
    print("DRIFT: the live schema differs from what the migrations produce.", file=out)
    print("  '+' is on the live database but not in the migrations;", file=out)
    print("  '-' is in the migrations but missing from the live database.", file=out)
    for line in cmp.extra:
        print(f"+ {line}", file=out)
    for line in cmp.missing:
        print(f"- {line}", file=out)
    print(
        "Reconcile with an additive migration, or, if the difference is deliberate, "
        "record it in schema-drift-allowlist.txt with the reason.",
        file=out,
    )


def run_check(journal_path: Path, allowlist_path: Path, dsn: str | None,
              live_fingerprint: Path | None, head: str | None, out=sys.stdout,
              recorded: list[str] | None = None) -> int:
    """Compare a live schema with the journal.

    ``recorded`` is the box's schema_migrations versions. It is read from the
    database unless given; ``head`` alone means "every journal version up to
    head is applied" (audits of a fingerprint file with no bookkeeping).
    """
    try:
        journal = Journal.parse(journal_path.read_text())
        allow = parse_allowlist(allowlist_path.read_text())
        if live_fingerprint is not None:
            live = [line for line in live_fingerprint.read_text().splitlines() if line]
        else:
            if not dsn:
                raise DriftError("DATABASE_URL is not set")
            live = fingerprint(dsn, read_only=True)
        if recorded is None:
            if head is not None:
                recorded = [v for v in journal.versions() if v <= head]
                if head not in journal.versions():
                    recorded.append(head)
            elif dsn and live_fingerprint is None:
                recorded = live_versions(dsn)
            else:
                raise DriftError("--head is required with --live-fingerprint")
        head = head_from_versions(recorded)
        expected, skipped = journal.expected_for(recorded)
        cmp = compare(expected, live, allow)
    except (DriftError, OSError) as exc:
        print(f"REFUSED: schema drift check could not run: {exc}", file=out)
        return EXIT_REFUSED
    except Exception as exc:  # noqa: BLE001 - a crash must never read as drift (exit 1)
        print(f"REFUSED: schema drift check could not run: unexpected {type(exc).__name__}: {exc}", file=out)
        return EXIT_REFUSED
    for v in skipped:
        print(f"note: the box has not applied {v}; it is pending and is left out of the expected schema", file=out)
    report(cmp, head, out=out)
    return EXIT_CLEAN if cmp.clean else EXIT_DRIFT


# ---------------------------------------------------------------------------
# CLI


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build-journal", help="CI: apply migrations to an empty DB and write the journal")
    b.add_argument("--migrations", type=Path, required=True)
    b.add_argument("--out", type=Path, required=True)
    b.add_argument("--dsn-env", default="SCHEMA_DRIFT_BUILD_DSN",
                   help="env var holding the URL of an EMPTY scratch database")

    e = sub.add_parser("expected", help="print the expected fingerprint at a version")
    e.add_argument("--journal", type=Path, required=True)
    e.add_argument("--version", required=True)

    c = sub.add_parser("check", help="box: READ-ONLY compare of the live DB with the journal")
    c.add_argument("--journal", type=Path, required=True)
    c.add_argument("--allowlist", type=Path, required=True)
    c.add_argument("--dsn-env", default="DATABASE_URL")
    c.add_argument("--live-fingerprint", type=Path,
                   help="compare a fingerprint file instead of connecting (tests and audits)")
    c.add_argument("--head", help="override the live head version (defaults to schema_migrations)")

    args = ap.parse_args(argv)
    if args.cmd == "build-journal":
        dsn = os.environ.get(args.dsn_env)
        if not dsn:
            print(f"{args.dsn_env} is not set", file=sys.stderr)
            return EXIT_REFUSED
        try:
            journal = build_journal(dsn, args.migrations)
        except DriftError as exc:
            print(f"build-journal failed: {exc}", file=sys.stderr)
            return EXIT_REFUSED
        with tempfile.NamedTemporaryFile("w", dir=args.out.parent or ".", delete=False) as tmp:
            tmp.write(journal.dump())
        os.replace(tmp.name, args.out)
        print(f"journal written: {args.out} ({journal.base_version}..{journal.versions()[-1]}, "
              f"{len(journal.versions())} versions)")
        return EXIT_CLEAN
    if args.cmd == "expected":
        try:
            lines = Journal.parse(args.journal.read_text()).expected_at(args.version)
        except DriftError as exc:
            print(str(exc), file=sys.stderr)
            return EXIT_REFUSED
        print("\n".join(lines))
        return EXIT_CLEAN
    return run_check(args.journal, args.allowlist, os.environ.get(args.dsn_env),
                     args.live_fingerprint, args.head)


if __name__ == "__main__":
    # Python's own exit status for an uncaught exception is 1, which callers
    # read as drift. Anything that escapes main is a refusal instead.
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"REFUSED: schema drift check could not run: unexpected {type(exc).__name__}: {exc}")
        sys.exit(EXIT_REFUSED)
