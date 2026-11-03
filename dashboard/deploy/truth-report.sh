#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# Push local systemd evidence to dashboard.patched.im's operational truth page
# (PAT-1303)
# ─────────────────────────────────────────────────────────────────────────────
# Designed to live at /opt/patched-*/deploy/truth-report.sh (or wherever this
# box keeps its deploy scripts) and run on a schedule via systemd timer.
# Follows the same "generic script, own systemd timer" pattern as
# deploy/hetzner-firewall-apply.{sh,service,timer} in this repo.
#
# Why this exists: prod-01 runs the dashboard app itself, so it can read
# systemd/file evidence for its own jobs directly (see truth.py's
# collect_systemd_observation). api-01 and portal-01 cannot be read that way
# without opening a new inbound path to them, so instead they PUSH their own
# local systemd evidence here, over the outbound HTTPS path that already
# exists to dashboard.patched.im, authenticated with the same Bearer token
# every other script/integration on these boxes already uses (see
# api_bearer_auth in dashboard's main.py) — no new credential, no new
# inbound port.
#
# NOT YET INSTALLED anywhere as of PAT-1303. Until it is installed and its
# timer enabled on api-01/portal-01, the manifest entries it would cover
# render amber ("no observation collected") on the truth page — that is the
# correct, honest state, not a bug.
#
# IMPORTANT: the ENTRY_ID -> unit mapping below must stay in sync with
# truth_manifest.yaml's api-01/portal-01 systemd-kind entries by hand. There
# is no shared source of truth between this script and that YAML file today
# — if you add/rename/remove a systemd-kind entry in the manifest for
# api-01 or portal-01, update the matching case block here in the same
# change, or the new entry will report amber forever with no way to tell
# that from "reporter isn't running yet".
#
# Usage:
#   truth-report.sh
#   (no arguments; determines which box's entries to report by `hostname`)
#
# Config (env file, NOT provisioned by this ticket — see PAT-1303 report):
#   /etc/patched-truth-report/report.env, containing at minimum:
#     DASHBOARD_API_KEY=<the shared bearer token>
#   Optionally:
#     TRUTH_REPORT_URL=https://dashboard.patched.im/admin/truth/report
#
# Exit codes:
#   0  success (all reportable entries POSTed, or nothing to report)
#   1  preflight failure (missing tool, no config, unrecognised host)
#   2  network failure POSTing to the dashboard
# ─────────────────────────────────────────────────────────────────────────────

set -uo pipefail
# Deliberately NOT `set -e` — `systemctl show` on a unit that has never run
# leaves several properties empty, which is an expected, handled case here,
# not a script error (same reasoning as patched-maintenance-facts.sh).

ENV_FILE="${TRUTH_REPORT_ENV_FILE:-/etc/patched-truth-report/report.env}"
REPORT_URL="${TRUTH_REPORT_URL:-https://dashboard.patched.im/admin/truth/report}"

for tool in curl jq systemctl; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERR: $tool not installed." >&2
        exit 1
    fi
done

# PAT-1303 non-author review finding: sourcing executes whatever the file
# contains, as root. A symlink planted at this path, or a file another account
# can rewrite, would be arbitrary root code execution rather than a config read.
# So refuse anything that is not a plain regular file owned by root and not
# writable by group or other.
if [ -h "$ENV_FILE" ]; then
    echo "ERR: $ENV_FILE is a symlink. Refusing to source it." >&2
    exit 1
fi
if [ -e "$ENV_FILE" ]; then
    if [ ! -f "$ENV_FILE" ]; then
        echo "ERR: $ENV_FILE is not a regular file. Refusing to source it." >&2
        exit 1
    fi
    env_owner=$(stat -c '%u' "$ENV_FILE")
    env_perm=$(stat -c '%a' "$ENV_FILE")
    if [ "$env_owner" != "0" ]; then
        echo "ERR: $ENV_FILE is owned by uid $env_owner, not root. Refusing to source it." >&2
        exit 1
    fi
    case "$env_perm" in
        ??[2367]|?[2367]?)
            echo "ERR: $ENV_FILE is group- or world-writable (mode $env_perm). Refusing to source it." >&2
            exit 1
            ;;
    esac
    # shellcheck disable=SC1090
    source "$ENV_FILE"
fi
if [ -z "${DASHBOARD_API_KEY:-}" ]; then
    echo "ERR: DASHBOARD_API_KEY not set (expected in $ENV_FILE). Not installed/provisioned yet — see PAT-1303." >&2
    exit 1
fi

# ── Determine scope + this box's entry_id -> unit mapping ──────────────────
HOST_SHORT="$(hostname -s 2>/dev/null || hostname)"
declare -A ENTRY_UNITS=()
case "$HOST_SHORT" in
    patched-api-01)
        SCOPE="api-01"
        ENTRY_UNITS=(
            [api01-cve-sync]="patched-cve-sync.service"
            [api01-backup]="patched-backup.service"
            [api01-partitions]="patched-partitions.service"
            [api01-alert-metrics]="patched-alert-metrics.service"
        )
        ;;
    patched-portal-01)
        SCOPE="portal-01"
        ENTRY_UNITS=(
            [portal01-backup]="patched-portal-backup.service"
            [portal01-scan-nvd-refresh]="patched-scan-nvd-refresh.service"
        )
        ;;
    *)
        echo "ERR: unrecognised host '$HOST_SHORT' — this script only knows patched-api-01 and patched-portal-01." >&2
        exit 1
        ;;
esac

# ── Collect evidence for each mapped unit, forcing UTC so timestamps parse
#    deterministically on the receiving end (truth.py expects exactly this
#    "Thu 2026-08-13 23:30:34 UTC" shape). ──
OBSERVATIONS="[]"
for entry_id in "${!ENTRY_UNITS[@]}"; do
    unit="${ENTRY_UNITS[$entry_id]}"
    props=$(TZ=UTC systemctl show "$unit" \
        --property=ActiveState,LoadState,Result,ExecMainStatus,ExecMainStartTimestamp,ExecMainExitTimestamp 2>/dev/null)

    # PAT-1411 / PAT-1426: mirrors truth.py's _UNIT_DEFINITION_GONE_LOAD_STATES
    # guard (see the comment there for the full incident writeup) — keep this
    # list byte-for-byte in sync with that frozenset, checked by
    # tests/test_pat1426_truth_report_loadstate.py. systemd can keep reporting
    # ActiveState=inactive/Result=success from the LAST real run even after a
    # unit's definition is gone (e.g. a .timer outlives its paired .service),
    # so the ActiveState check below is not enough on its own — a vanished
    # unit must never render as a fresh success. Only LoadState=loaded means
    # there is a live definition to trust ActiveState/Result against.
    load_state=$(echo "$props" | sed -n 's/^LoadState=//p')
    case "$load_state" in
        not-found|masked|bad-setting|error)
            echo "  $entry_id ($unit): unit definition is gone (LoadState=$load_state), skipping — absence renders amber, which is the honest state"
            continue
            ;;
    esac

    active_state=$(echo "$props" | sed -n 's/^ActiveState=//p')
    if [ -z "$active_state" ]; then
        echo "  $entry_id ($unit): unit not found on this box, skipping"
        continue
    fi

    result=$(echo "$props" | sed -n 's/^Result=//p')
    exit_status=$(echo "$props" | sed -n 's/^ExecMainStatus=//p')
    start_ts=$(echo "$props" | sed -n 's/^ExecMainStartTimestamp=//p')
    exit_ts=$(echo "$props" | sed -n 's/^ExecMainExitTimestamp=//p')
    # PAT-1303 non-author review finding: this used to fall back to the START
    # timestamp when the exit timestamp was empty. That is exactly the failure
    # this page exists to catch: a unit that started and then hung has no exit
    # timestamp, so it would have reported a fresh observation carrying the
    # PREVIOUS run's Result=success, and rendered green while stuck. Only a
    # completed run is evidence, so report the exit timestamp or nothing.
    #
    # Every unit mapped here is a timer-driven oneshot, which is why "no exit
    # timestamp" is unambiguously "has not completed". A long-running service
    # would need different handling, since it legitimately never exits while
    # healthy: do not add one to ENTRY_UNITS without revisiting this.
    raw_ts="$exit_ts"

    if [ -z "$raw_ts" ]; then
        echo "  $entry_id ($unit): no completed run (never ran, or still running), skipping — absence renders amber, which is the honest state"
        continue
    fi

    observed_at=$(date -u -d "$raw_ts" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)
    if [ -z "$observed_at" ]; then
        echo "  $entry_id ($unit): could not parse timestamp '$raw_ts', skipping"
        continue
    fi

    if [ "$result" = "success" ]; then
        success="true"
    else
        success="false"
    fi
    detail="Result=${result:-unknown}$( [ -n "$exit_status" ] && echo ", ExecMainStatus=$exit_status" )"

    OBSERVATIONS=$(echo "$OBSERVATIONS" | jq \
        --arg entry_id "$entry_id" \
        --argjson success "$success" \
        --arg detail "$detail" \
        --arg observed_at "$observed_at" \
        '. + [{"entry_id": $entry_id, "success": $success, "detail": $detail, "observed_at": $observed_at}]')
    echo "  $entry_id ($unit): success=$success observed_at=$observed_at"
done

COUNT=$(echo "$OBSERVATIONS" | jq 'length')
if [ "$COUNT" -eq 0 ]; then
    echo "Nothing to report for $HOST_SHORT (no mapped unit has completed a run yet)."
    exit 0
fi

PAYLOAD=$(jq -n --arg scope "$SCOPE" --argjson observations "$OBSERVATIONS" '{"scope": $scope, "observations": $observations}')

echo "→ Reporting $COUNT observation(s) for scope=$SCOPE to $REPORT_URL"

# PAT-1303 non-author review finding: a fixed /tmp path is predictable, so any
# local account can pre-plant a symlink there and have this root-run curl write
# through it, or read back a response it substituted. mktemp gives an
# unpredictable name created with a private mode, and the trap removes it on
# every exit path including the error branches below.
RESPONSE_FILE=$(mktemp /tmp/truth-report-response.XXXXXXXXXX) || {
    echo "ERR: could not create a temporary file for the response." >&2
    exit 2
}
trap 'rm -f "$RESPONSE_FILE"' EXIT

HTTP_CODE=$(curl -fsS -o "$RESPONSE_FILE" -w '%{http_code}' \
    --max-time 15 \
    -H "Authorization: Bearer $DASHBOARD_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "$REPORT_URL") || {
    echo "ERR: POST to $REPORT_URL failed." >&2
    exit 2
}
if [ "$HTTP_CODE" != "200" ]; then
    echo "ERR: $REPORT_URL returned HTTP $HTTP_CODE: $(cat "$RESPONSE_FILE" 2>/dev/null)" >&2
    exit 2
fi

echo "✓ Reported. Response: $(cat "$RESPONSE_FILE" 2>/dev/null)"
