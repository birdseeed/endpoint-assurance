"""Tests for the PAT-2053 schema drift check (schema_drift.py, schema-drift-check.sh).

Pure-logic tests always run. Database tests need SCHEMA_DRIFT_TEST_DSN, a URL
to a PostgreSQL maintenance database whose role may CREATE DATABASE. They skip
without it, except when SCHEMA_DRIFT_DB_TESTS_REQUIRED=1 (set only by the
schema-drift workflow, which provides a database), where a missing DSN is a
wiring bug and fails.
"""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import schema_drift as sd  # noqa: E402

TEST_DSN = os.environ.get("SCHEMA_DRIFT_TEST_DSN", "")
DB_REQUIRED = os.environ.get("SCHEMA_DRIFT_DB_TESTS_REQUIRED") == "1"


def fp(*lines: str) -> list[str]:
    return sorted(["server_major|16", *lines])


class JournalTests(unittest.TestCase):
    def test_round_trip_and_reconstruction(self):
        j = sd.Journal(base_version="0056_a", base=fp("relation|t|r", "column|t|id|bigint|not null|"))
        j.steps.append(("0057_b", ["column|t|name|text|null|"], []))
        j.steps.append(("0058_c", ["index|t|t_name|CREATE INDEX t_name ON public.t USING btree (name)"],
                        ["column|t|name|text|null|"]))
        parsed = sd.Journal.parse(j.dump())
        self.assertEqual(parsed.versions(), ["0056_a", "0057_b", "0058_c"])
        self.assertEqual(parsed.expected_at("0056_a"), j.base)
        self.assertIn("column|t|name|text|null|", parsed.expected_at("0057_b"))
        at_c = parsed.expected_at("0058_c")
        self.assertNotIn("column|t|name|text|null|", at_c)
        self.assertIn("index|t|t_name|CREATE INDEX t_name ON public.t USING btree (name)", at_c)

    def test_unknown_version_refused(self):
        j = sd.Journal(base_version="0056_a", base=fp())
        with self.assertRaises(sd.DriftError):
            j.expected_at("0099_future")

    def test_malformed_journal_refused(self):
        for text in ["", "not a journal\n", f"{sd.JOURNAL_MAGIC}\n", f"{sd.JOURNAL_MAGIC}\nbase 0056_a\n+ orphan\n",
                     f"{sd.JOURNAL_MAGIC}\nbase 0056_a\n?? what\n"]:
            with self.subTest(text=text), self.assertRaises(sd.DriftError):
                sd.Journal.parse(text)

    def _ooo_journal(self):
        j = sd.Journal(base_version="0056_a", base=fp("relation|t|r", "column|t|id|bigint|not null|"))
        j.steps.append(("0057_b", ["relation|u|r", "column|u|id|bigint|not null|"], []))
        j.steps.append(("0058_c", ["column|t|name|text|null|"], []))
        j.steps.append(("0059_d", ["column|u|label|text|null|"], []))
        return j

    def test_out_of_order_independent_gap_is_skipped(self):
        # 0058 deployed before 0057; they touch different tables.
        expected, skipped = self._ooo_journal().expected_for(["0001_initial", "0056_a", "0058_c"])
        self.assertEqual(skipped, ["0057_b"])
        self.assertIn("column|t|name|text|null|", expected)
        self.assertNotIn("relation|u|r", expected)

    def test_out_of_order_dependent_gap_is_refused_by_name(self):
        # 0059 touches table u, which only the missing 0057 creates.
        with self.assertRaises(sd.DriftError) as ctx:
            self._ooo_journal().expected_for(["0056_a", "0058_c", "0059_d"])
        self.assertIn("gap", str(ctx.exception))
        self.assertIn("0057_b", str(ctx.exception))
        self.assertIn("0059_d", str(ctx.exception))

    def test_pending_versions_above_head_are_ignored(self):
        expected, skipped = self._ooo_journal().expected_for(["0056_a", "0057_b"])
        self.assertEqual(skipped, [])
        self.assertNotIn("column|t|name|text|null|", expected)

    def test_unrecorded_base_or_unknown_version_refused(self):
        with self.assertRaises(sd.DriftError):
            self._ooo_journal().expected_for(["0057_b"])
        with self.assertRaises(sd.DriftError) as ctx:
            self._ooo_journal().expected_for(["0056_a", "0060_unknown"])
        self.assertIn("0060_unknown", str(ctx.exception))

    def test_head_ignores_grandfathered_and_odd_versions(self):
        self.assertEqual(sd.head_from_versions(["0016", "0055_x", "0057_b", "0056_a", "0999"]), "0057_b")
        with self.assertRaises(sd.DriftError):
            sd.head_from_versions(["0001_initial", "0037", "0055_tenant_webhooks"])


class ScratchGuardTests(unittest.TestCase):
    def test_build_journal_refuses_a_non_scratch_database(self):
        for dsn in (
            "postgres://u:x@db.internal:5432/patched?sslmode=require",
            "postgres://u:x@localhost:5432/patched",
            "postgres://u:x@10.0.0.5/patched_test_x",
            "postgres://u:x@localhost/patched_testx",
        ):
            with self.assertRaises(sd.DriftError, msg=dsn):
                sd.build_journal(dsn, Path("/nonexistent"))

    def test_scratch_guard_accepts_local_patched_test_databases(self):
        for dsn in (
            "postgres://patched:pw@localhost:5432/patched_test_drift_journal?sslmode=disable",
            "postgresql://127.0.0.1/patched_test_a1",
        ):
            sd._refuse_non_scratch(dsn)


class CompareTests(unittest.TestCase):
    def test_clean(self):
        c = sd.compare(fp("relation|t|r"), fp("relation|t|r"), [])
        self.assertTrue(c.clean)

    def test_extra_and_missing_reported(self):
        c = sd.compare(fp("relation|t|r", "index|t|i|x"), fp("relation|t|r", "column|t|planted|text|null|"), [])
        self.assertEqual(c.extra, ["column|t|planted|text|null|"])
        self.assertEqual(c.missing, ["index|t|i|x"])
        self.assertFalse(c.clean)

    def test_allowlist_accepts_by_side_and_pattern(self):
        allow = sd.parse_allowlist("# why\n+ column|t|*\n- index|t|i|x\n+ relation|gone|r\n")
        c = sd.compare(fp("index|t|i|x"), fp("column|t|a|text|null|", "column|t|b|text|null|"), allow)
        self.assertTrue(c.clean)
        self.assertEqual(len(c.accepted), 3)
        self.assertEqual([e.pattern for e in c.unused], ["relation|gone|r"])

    def test_allowlist_side_matters(self):
        allow = sd.parse_allowlist("- column|t|*\n")
        c = sd.compare(fp(), fp("column|t|a|text|null|"), allow)
        self.assertEqual(c.extra, ["column|t|a|text|null|"])

    def test_allowlist_is_exact_so_brackets_are_literal(self):
        line = "column|t|tags|text[]|not null|'{}'::text[]"
        allow = sd.parse_allowlist(f"+ {line}\n")
        c = sd.compare(fp(), fp(line), allow)
        self.assertTrue(c.clean, "a literal text[] line must match itself")
        # fnmatch would read [] as a class; exact matching must not treat it as one.
        allow = sd.parse_allowlist("+ column|t|tags|text[x]|not null|'{}'::text[]\n")
        self.assertFalse(sd.compare(fp(), fp("column|t|tags|textx|not null|'{}'::text[]"), allow).clean)

    def test_only_trailing_pipe_star_is_a_wildcard(self):
        self.assertTrue(sd.allow_matches("column|t|*", "column|t|a|text|null|"))
        self.assertFalse(sd.allow_matches("column|t|*", "column|tt|a|text|null|"))
        self.assertFalse(sd.allow_matches("column|*|a|text|null|", "column|t|a|text|null|"))
        self.assertFalse(sd.allow_matches("column|t|a*", "column|t|ab|text|null|"))

    def test_bad_allowlist_refused(self):
        with self.assertRaises(sd.DriftError):
            sd.parse_allowlist("column|t|a\n")

    def test_major_mismatch_refused(self):
        with self.assertRaises(sd.DriftError):
            sd.compare(["server_major|16"], ["server_major|17"], [])

    def test_shipped_allowlist_parses(self):
        entries = sd.parse_allowlist((HERE / "schema-drift-allowlist.txt").read_text())
        self.assertTrue(all(e.side == "+" for e in entries), "shipped allowlist only accepts prod-only extras")
        self.assertLessEqual(len(entries), 5, "keep the allowlist minimal; reconcile instead")

    def test_run_check_on_fingerprint_files(self):
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            j = sd.Journal(base_version="0056_a", base=fp("relation|t|r"))
            (dp / "journal").write_text(j.dump())
            (dp / "allow").write_text("")
            (dp / "live").write_text("\n".join(fp("relation|t|r", "column|t|planted|text|null|")) + "\n")
            out = io.StringIO()
            rc = sd.run_check(dp / "journal", dp / "allow", None, dp / "live", "0056_a", out=out)
            self.assertEqual(rc, sd.EXIT_DRIFT)
            self.assertIn("+ column|t|planted|text|null|", out.getvalue())
            out = io.StringIO()
            rc = sd.run_check(dp / "journal", dp / "allow", None, None, None, out=out)
            self.assertEqual(rc, sd.EXIT_REFUSED)


class CrashIsRefusalTests(unittest.TestCase):
    """PAT-2062: an unexpected exception must exit 2 (refused), never 1 (drift)."""

    def _files(self, d: Path) -> tuple[Path, Path]:
        (d / "journal").write_text(sd.Journal(base_version="0056_a", base=fp()).dump())
        (d / "allow").write_text("")
        return d / "journal", d / "allow"

    def test_run_check_turns_an_unexpected_exception_into_a_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            journal, allow = self._files(Path(d))
            original = sd.fingerprint
            sd.fingerprint = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
            try:
                out = io.StringIO()
                rc = sd.run_check(journal, allow, "postgres://x/y", None, None, out=out)
            finally:
                sd.fingerprint = original
            self.assertEqual(rc, sd.EXIT_REFUSED)
            self.assertIn("could not run: unexpected RuntimeError", out.getvalue())

    def test_undecodable_psql_output_exits_2_from_the_cli(self):
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            journal, allow = self._files(dp)
            fake = dp / "bin"
            fake.mkdir()
            (fake / "psql").write_text("#!/bin/sh\nprintf '\\377\\376 not utf-8\\n'\n")
            (fake / "psql").chmod(0o755)
            env = dict(os.environ, PATH=f"{fake}:{os.environ['PATH']}", DATABASE_URL="postgres://u@127.0.0.1:1/db",
                       LC_ALL="C.UTF-8", PYTHONUTF8="1")
            proc = subprocess.run(
                [sys.executable, str(HERE / "schema_drift.py"), "check", "--journal", str(journal),
                 "--allowlist", str(allow)],
                capture_output=True, text=True, env=env, timeout=60, check=False)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("could not run: unexpected UnicodeDecodeError", proc.stdout)


class FingerprintQueryTests(unittest.TestCase):
    def test_fingerprint_query_is_select_only(self):
        sql = (HERE / "schema_fingerprint.sql").read_text()
        body = "\n".join(line.split("--", 1)[0] for line in sql.splitlines()).upper()
        for word in ("INSERT", "UPDATE", "DELETE", "ALTER", "CREATE", "DROP", "TRUNCATE", "GRANT", "COPY"):
            self.assertNotRegex(body, rf"\b{word}\b", f"fingerprint query must stay read-only ({word})")


class WrapperTests(unittest.TestCase):
    def test_env_file_url_never_printed(self):
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            secret = "placeholderpw"
            (dp / "env").write_text(f'OTHER=1\nDATABASE_URL="postgres://u:{secret}@127.0.0.1:1/db"\n')
            j = sd.Journal(base_version="0056_a", base=fp())
            (dp / "journal").write_text(j.dump())
            env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
            env["PGCONNECT_TIMEOUT"] = "2"
            proc = subprocess.run(
                ["bash", str(HERE / "schema-drift-check.sh"), "--journal", str(dp / "journal"),
                 "--env-file", str(dp / "env")],
                capture_output=True, text=True, env=env, timeout=60, check=False)
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("REFUSED", proc.stdout)
            self.assertNotIn(secret, proc.stdout + proc.stderr)

    def test_duplicate_url_lines_refused(self):
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            (dp / "env").write_text("DATABASE_URL=postgres://a/b\nDATABASE_URL=postgres://c/d\n")
            (dp / "journal").write_text(sd.Journal(base_version="0056_a", base=fp()).dump())
            env = {k: v for k, v in os.environ.items() if k != "DATABASE_URL"}
            proc = subprocess.run(
                ["bash", str(HERE / "schema-drift-check.sh"), "--journal", str(dp / "journal"),
                 "--env-file", str(dp / "env")],
                capture_output=True, text=True, env=env, timeout=30, check=False)
            self.assertEqual(proc.returncode, 2)


def _db_url(base: str, dbname: str) -> str:
    parts = urlsplit(base)
    return urlunsplit((parts.scheme, parts.netloc, "/" + dbname, parts.query, parts.fragment))


MIGRATIONS = {
    "0001_initial.sql": """
        CREATE TABLE schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
        CREATE TABLE widgets (id bigserial PRIMARY KEY, name text NOT NULL DEFAULT '');
        INSERT INTO schema_migrations (version) VALUES ('0001_initial');
    """,
    "0056_widget_colour.sql": """
        BEGIN;
        ALTER TABLE widgets ADD COLUMN colour text;
        INSERT INTO schema_migrations (version) VALUES ('0056_widget_colour');
        COMMIT;
    """,
    "0056_widget_colour_rollback.sql": "SELECT 1;",
    "0057_widget_index.sql": """
        BEGIN;
        CREATE INDEX widgets_colour_idx ON widgets (colour);
        CREATE FUNCTION widget_touch() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$;
        CREATE TRIGGER widgets_touch BEFORE UPDATE ON widgets FOR EACH ROW EXECUTE FUNCTION widget_touch();
        INSERT INTO schema_migrations (version) VALUES ('0057_widget_index');
        COMMIT;
    """,
    "0058_gadgets.sql": """
        BEGIN;
        CREATE TABLE gadgets (id bigserial PRIMARY KEY, tags text[] NOT NULL DEFAULT '{}');
        INSERT INTO schema_migrations (version) VALUES ('0058_gadgets');
        COMMIT;
    """,
    "0059_widget_size.sql": """
        BEGIN;
        CREATE INDEX widgets_name_idx ON widgets (name);
        INSERT INTO schema_migrations (version) VALUES ('0059_widget_size');
        COMMIT;
    """,
}


@unittest.skipUnless(TEST_DSN or DB_REQUIRED, "SCHEMA_DRIFT_TEST_DSN not set")
class DatabaseTests(unittest.TestCase):
    """Build a journal from a tiny migrations set, then check real targets."""

    @classmethod
    def setUpClass(cls):
        if not TEST_DSN:
            raise AssertionError("SCHEMA_DRIFT_DB_TESTS_REQUIRED=1 but SCHEMA_DRIFT_TEST_DSN is unset")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        mig = cls.dir / "migrations"
        mig.mkdir()
        for name, body in MIGRATIONS.items():
            (mig / name).write_text(body)
        cls.mig = mig
        cls.dbs: list[str] = []
        build = cls._new_db()
        cls.journal = sd.build_journal(build, mig)
        (cls.dir / "journal").write_text(cls.journal.dump())
        (cls.dir / "allow").write_text("")

    @classmethod
    def tearDownClass(cls):
        for name in cls.dbs:
            subprocess.run(["psql", "-X", "-q", "-d", TEST_DSN, "-c", f'DROP DATABASE IF EXISTS "{name}"'],
                           capture_output=True, check=False)
        cls.tmp.cleanup()

    @classmethod
    def _new_db(cls) -> str:
        name = f"patched_test_drift_{uuid.uuid4().hex[:10]}"
        subprocess.run(["psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-d", TEST_DSN, "-c", f'CREATE DATABASE "{name}"'],
                       check=True, capture_output=True)
        cls.dbs.append(name)
        return _db_url(TEST_DSN, name)

    def _migrated_target(self, upto: str | None = None, skip: tuple[str, ...] = ()) -> str:
        url = self._new_db()
        for f in sorted(self.mig.iterdir()):
            if f.name.endswith("_rollback.sql") or f.name.startswith(skip):
                continue
            sd._psql(url, "-f", str(f))
            if upto and f.name.startswith(upto):
                break
        return url

    def _check(self, url: str, allow: str = "") -> tuple[int, str]:
        (self.dir / "allow").write_text(allow)
        out = io.StringIO()
        rc = sd.run_check(self.dir / "journal", self.dir / "allow", url, None, None, out=out)
        return rc, out.getvalue()

    def test_journal_covers_conventioned_versions(self):
        self.assertEqual(self.journal.versions(),
                         ["0056_widget_colour", "0057_widget_index", "0058_gadgets", "0059_widget_size"])

    def test_clean_target_is_green(self):
        rc, out = self._check(self._migrated_target())
        self.assertEqual(rc, sd.EXIT_CLEAN, out)

    def test_target_at_previous_release_is_green(self):
        rc, out = self._check(self._migrated_target(upto="0056"))
        self.assertEqual(rc, sd.EXIT_CLEAN, out)
        self.assertIn("0056_widget_colour", out)

    def test_planted_column_is_red(self):
        url = self._migrated_target()
        sd._psql(url, "-c", "ALTER TABLE widgets ADD COLUMN planted integer")
        rc, out = self._check(url)
        self.assertEqual(rc, sd.EXIT_DRIFT, out)
        self.assertIn("+ column|widgets|planted|integer|null|", out)

    def test_changed_nullability_and_missing_index_are_red(self):
        url = self._migrated_target()
        sd._psql(url, "-c", "ALTER TABLE widgets ALTER COLUMN name DROP NOT NULL; DROP INDEX widgets_colour_idx")
        rc, out = self._check(url)
        self.assertEqual(rc, sd.EXIT_DRIFT, out)
        self.assertIn("+ column|widgets|name|text|null|''::text", out)
        self.assertIn("- index|widgets|widgets_colour_idx|", out)

    def test_out_of_order_independent_gap_is_green_with_note(self):
        # 0058 (new table) deployed while 0057 (widgets) is still pending.
        url = self._migrated_target(upto="0058", skip=("0057",))
        rc, out = self._check(url)
        self.assertEqual(rc, sd.EXIT_CLEAN, out)
        self.assertIn("has not applied 0057_widget_index", out)

    def test_out_of_order_dependent_gap_is_refused(self):
        # 0059 touches widgets like the missing 0057, so the shape is a guess.
        url = self._migrated_target(skip=("0057",))
        rc, out = self._check(url)
        self.assertEqual(rc, sd.EXIT_REFUSED, out)
        self.assertIn("0057_widget_index", out)
        self.assertIn("0059_widget_size", out)

    def test_invalid_index_is_red(self):
        url = self._migrated_target()
        sd._psql(url, "-c", "UPDATE pg_index SET indisvalid = false WHERE indexrelid = 'widgets_colour_idx'::regclass")
        rc, out = self._check(url)
        self.assertEqual(rc, sd.EXIT_DRIFT, out)
        self.assertIn("widgets_colour_idx", out)
        self.assertIn("|INVALID", out)

    def test_disabled_trigger_is_red(self):
        url = self._migrated_target()
        sd._psql(url, "-c", "ALTER TABLE widgets DISABLE TRIGGER widgets_touch")
        rc, out = self._check(url)
        self.assertEqual(rc, sd.EXIT_DRIFT, out)
        self.assertIn("|enabled:D", out)

    def test_changed_collation_is_red(self):
        url = self._migrated_target()
        sd._psql(url, "-c", 'ALTER TABLE widgets ALTER COLUMN name TYPE text COLLATE "C"')
        rc, out = self._check(url)
        self.assertEqual(rc, sd.EXIT_DRIFT, out)
        self.assertIn("|collate:C", out)

    def test_allowlisted_array_column_is_green(self):
        url = self._migrated_target()
        sd._psql(url, "-c", "ALTER TABLE gadgets ADD COLUMN extra text[]")
        rc, out = self._check(url, allow="+ column|gadgets|extra|text[]|null|\n")
        self.assertEqual(rc, sd.EXIT_CLEAN, out)

    def test_allowlisted_difference_is_green(self):
        url = self._migrated_target()
        sd._psql(url, "-c", "ALTER TABLE widgets ADD COLUMN planted integer")
        rc, out = self._check(url, allow="# test\n+ column|widgets|planted|*\n")
        self.assertEqual(rc, sd.EXIT_CLEAN, out)

    def test_unknown_head_is_refused(self):
        url = self._migrated_target()
        sd._psql(url, "-c", "INSERT INTO schema_migrations (version) VALUES ('0099_from_the_future')")
        rc, out = self._check(url)
        self.assertEqual(rc, sd.EXIT_REFUSED, out)

    def test_check_session_cannot_write(self):
        url = self._migrated_target()
        with self.assertRaises(sd.DriftError):
            sd._psql(url, "-c", "INSERT INTO widgets (name) VALUES ('x')", read_only=True)

    def test_check_leaves_target_unchanged(self):
        url = self._migrated_target()
        before = sd.fingerprint(url), sd._psql(url, "-tAc", "SELECT count(*) FROM schema_migrations")
        self._check(url)
        after = sd.fingerprint(url), sd._psql(url, "-tAc", "SELECT count(*) FROM schema_migrations")
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
