#!/usr/bin/env python3
"""waitlist.py — read and maintain the Mac app waitlist (PAT-2560).

Operator tool, NOT called from any request. The list lives in the scan
service's own SQLite database (table waitlist_signups); this is the only
supported way to count it, read it, export it or take someone off it.

Usage (on patched-portal-01, as the scan user):

    W="sudo -u scan /opt/patched-scan/venv/bin/python /opt/patched-scan/bin/waitlist.py"
    $W count
    $W list
    $W export > waitlist.csv
    $W remove someone@example.com

`count` prints the number of people on the list and how many sign ups since a
given time (`--since 2026-10-20T09:00:00+00:00`), which is what the waitlist
test is read from. `remove` deletes one person by email address, from the list
and from the rate-limit ledger, and is what the privacy notice's "we will
delete your details" means in practice.

The database defaults to /var/lib/patched-scan/db/scan.db. Point it elsewhere
with --db or SCAN_DB_PATH. Standard library only, so it runs under any Python 3
without the service's dependencies.
"""

import argparse
import csv
import os
import sqlite3
import sys

DEFAULT_DB = "/var/lib/patched-scan/db/scan.db"
COLUMNS = ("created_at", "name", "email", "devices", "tool", "notified_at")
# A spreadsheet treats a cell that starts with one of these as a formula. Every
# value here was typed by a stranger, so the export neutralises them the same
# way the service's other CSVs do: a leading single quote.
_FORMULA_LEADS = ("=", "+", "-", "@", "\t", "\r", "\n")


def _csv_safe(value) -> str:
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_LEADS) or text.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + text
    return text


def _connect(path: str) -> sqlite3.Connection:
    if not os.path.exists(path):
        raise SystemExit(f"waitlist: no database at {path}")
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def cmd_count(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    total = conn.execute("SELECT COUNT(*) FROM waitlist_signups").fetchone()[0]
    unnotified = conn.execute(
        "SELECT COUNT(*) FROM waitlist_signups WHERE notified_at IS NULL"
    ).fetchone()[0]
    print(f"on the list: {total}")
    if args.since:
        since = conn.execute(
            "SELECT COUNT(*) FROM waitlist_signups WHERE created_at >= ?", (args.since,)
        ).fetchone()[0]
        print(f"since {args.since}: {since}")
    print(f"notification email not sent: {unnotified}")
    return 0


def cmd_list(conn: sqlite3.Connection, _args: argparse.Namespace) -> int:
    rows = conn.execute(
        f"SELECT {', '.join(COLUMNS)} FROM waitlist_signups ORDER BY created_at"
    ).fetchall()
    for row in rows:
        print("\t".join("" if row[c] is None else str(row[c]) for c in COLUMNS))
    print(f"{len(rows)} on the list", file=sys.stderr)
    return 0


def cmd_export(conn: sqlite3.Connection, _args: argparse.Namespace) -> int:
    rows = conn.execute(
        f"SELECT {', '.join(COLUMNS)} FROM waitlist_signups ORDER BY created_at"
    ).fetchall()
    writer = csv.writer(sys.stdout, lineterminator="\n")
    writer.writerow(COLUMNS)
    for row in rows:
        writer.writerow([_csv_safe(row[c]) for c in COLUMNS])
    return 0


def cmd_remove(conn: sqlite3.Connection, args: argparse.Namespace) -> int:
    email = args.email.strip().lower()
    removed = conn.execute("DELETE FROM waitlist_signups WHERE email = ?", (email,)).rowcount
    attempts = conn.execute("DELETE FROM waitlist_attempts WHERE email = ?", (email,)).rowcount
    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM waitlist_signups").fetchone()[0]
    if not removed:
        # Not an error to shout about, but never a silent success either: the
        # operator must know nothing was on the list under that address.
        print(f"waitlist: {email} was not on the list "
              f"({attempts} rate-limit record(s) deleted). On the list: {total}")
        return 1
    print(f"waitlist: removed {email} ({attempts} rate-limit record(s) deleted). "
          f"On the list: {total}")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="waitlist.py", description=__doc__.splitlines()[0])
    parser.add_argument("--db", default=os.getenv("SCAN_DB_PATH", DEFAULT_DB),
                        help=f"path to scan.db (default {DEFAULT_DB})")
    sub = parser.add_subparsers(dest="command", required=True)
    p_count = sub.add_parser("count", help="how many people are on the list")
    p_count.add_argument("--since", help="also count sign ups at or after this ISO 8601 UTC time")
    p_count.set_defaults(func=cmd_count)
    sub.add_parser("list", help="print the list, tab separated").set_defaults(func=cmd_list)
    sub.add_parser("export", help="write the list as CSV to stdout").set_defaults(func=cmd_export)
    p_remove = sub.add_parser("remove", help="delete one person by email address")
    p_remove.add_argument("email")
    p_remove.set_defaults(func=cmd_remove)
    args = parser.parse_args(argv)

    conn = _connect(args.db)
    try:
        return args.func(conn, args)
    finally:
        conn.close()


if __name__ == "__main__":
    raise SystemExit(main())
