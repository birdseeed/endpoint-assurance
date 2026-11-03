#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Prune old generated reports for patched-prod-01 (PAT-87)
# ─────────────────────────────────────────────────────────────────────────────
# Designed to live on the box at /opt/patched-dashboard/deploy/ and run on a
# schedule via systemd timer (patched-dashboard-prune-reports.timer). Also fine
# to invoke ad-hoc by hand.
#
# The dashboard writes one .docx per CVE scan into reports/ and never cleans up,
# which is the most likely cause of the disk slowly filling on patched-prod-01
# (see docs/OPERATIONS.md "Disk filling up"). download_report() already 404s
# gracefully for missing files, so deleting old reports is safe — the link just
# stops working once a report ages out.
#
# Only *.docx in the top level of reports/ are touched. The reports/public/
# subdirectory (public scan assets) is left alone, as is dashboard.db.
#
# PAT-2307: the dashboard writes reports to its state directory,
# /var/lib/patched-dashboard/reports, not to the code tree, which root owns.
# Reports written before that move stay in /opt/patched-dashboard/reports
# (copied, never moved or deleted, by deploy/code-tree-guard.sh); this job
# no longer prunes them, and the service user could not delete them there
# anyway. See deploy/RUNBOOK.md for their cleanup.
#
# Usage:
#   prune-reports.sh [RETENTION_DAYS]
#   RETENTION_DAYS defaults to 90. Override via the env var RETENTION_DAYS or arg.
set -euo pipefail

REPORTS_DIR="${REPORTS_DIR:-/var/lib/patched-dashboard/reports}"
RETENTION_DAYS="${1:-${RETENTION_DAYS:-90}}"

if [[ ! -d "$REPORTS_DIR" ]]; then
  echo "prune-reports: reports dir $REPORTS_DIR does not exist, nothing to do"
  exit 0
fi

# Only top-level *.docx older than the retention window. reports/public/ and
# dashboard.db are never touched (-maxdepth 1, -name '*.docx').
count=0
while IFS= read -r -d '' f; do
  echo "prune-reports: removing $(basename "$f")"
  rm -f -- "$f"
  count=$((count + 1))
done < <(find "$REPORTS_DIR" -maxdepth 1 -type f -name '*.docx' -mtime "+${RETENTION_DAYS}" -print0)

echo "prune-reports: removed ${count} report(s) older than ${RETENTION_DAYS} days from $REPORTS_DIR"
