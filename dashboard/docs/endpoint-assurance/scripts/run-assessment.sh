#!/usr/bin/env bash
# One-command wrapper for the PAT-1502 report-drafting run: fetch evidence,
# then invoke the drafting prompt against it with Claude Code.
#
# Usage:
#   ADMIN_API_TOKEN=<token> ./run-assessment.sh <tenant-id>
#
# What it does, in order:
#   1. Runs fetch-evidence.sh for <tenant-id>, writing a timestamped
#      evidence bundle under docs/endpoint-assurance/runs/.
#   2. Runs the drafting prompt (draft-report-prompt.md) against that
#      bundle and the report template, via
#      `claude --dangerously-skip-permissions -p ...`, writing a
#      timestamped draft report alongside the bundle.
#
# Nothing here is a dashboard feature - no route, no UI, no scheduled job.
# It is a specialist's operator tool, run manually per engagement per the
# ticket's own "no scheduled job" constraint.
#
# Re-run this with the same tenant id at any point in the engagement (e.g.
# for a retainer's periodic review) - it always fetches fresh evidence and
# writes a new, separately timestamped draft; it never edits a prior draft
# or requires one to exist.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TENANT_ID="${1:-}"

if [[ -z "$TENANT_ID" ]]; then
  echo "Usage: ADMIN_API_TOKEN=<token> $0 <tenant-id>" >&2
  exit 1
fi

command -v claude >/dev/null || {
  echo "error: 'claude' CLI not found on PATH - install Claude Code first" >&2
  exit 1
}

echo "== Step 1: fetch evidence ==" >&2
EVIDENCE_BUNDLE_PATH="$("$SCRIPT_DIR/fetch-evidence.sh" "$TENANT_ID")"
echo "Evidence bundle: $EVIDENCE_BUNDLE_PATH" >&2

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUTPUT_DRAFT_PATH="$SCRIPT_DIR/../runs/draft-report-${TENANT_ID}-${TIMESTAMP}.md"
REPORT_TEMPLATE_PATH="$SCRIPT_DIR/../report-template.md"

echo "== Step 2: draft report ==" >&2
echo "Output will be written to: $OUTPUT_DRAFT_PATH" >&2

EVIDENCE_BUNDLE_PATH="$EVIDENCE_BUNDLE_PATH" \
REPORT_TEMPLATE_PATH="$REPORT_TEMPLATE_PATH" \
OUTPUT_DRAFT_PATH="$OUTPUT_DRAFT_PATH" \
claude --dangerously-skip-permissions -p "$(cat "$SCRIPT_DIR/draft-report-prompt.md")"

echo "== Done ==" >&2
echo "Evidence bundle: $EVIDENCE_BUNDLE_PATH" >&2
echo "Draft report:    $OUTPUT_DRAFT_PATH" >&2
