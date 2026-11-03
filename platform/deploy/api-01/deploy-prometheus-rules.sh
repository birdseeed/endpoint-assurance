#!/usr/bin/env bash
# deploy-prometheus-rules.sh — installs api-vps-artefacts/alerting/prometheus-rules-patched.yml
# as /etc/prometheus/rules/patched.yml on api-01. PAT-1423.
#
# Before this ticket, nothing deployed this file at all: it only reached the
# box when a person remembered to `scp` it (see api-vps-artefacts/alerting/
# README.md's superseded manual "Deploy" section). That gap is what let
# PAT-1377's fix to two dead-on-arrival alert rules merge to main and then
# sit unshipped for days — patched-api-01 kept evaluating the broken
# expressions the whole time, and only PAT-1389's selector-liveness checker
# caught it, on its first contact with production. This script + the
# workflow step that runs it close that gap: every push to main that touches
# the rules file ships it, gated on `promtool check rules`, with a backup
# kept and a sidecar hash recorded so drift is detectable afterwards
# (PAT-1423 item 3 — see api-vps-artefacts/patched-maintenance-facts.sh).
#
# Run ON api-01 as root, invoked by .github/workflows/deploy-api-01.yml over
# SSH, after the same rsync step stages this script + the rules file into
# /opt/patched-prometheus-staging/ -- deliberately NOT the Go binaries'
# /opt/patched-deploy-staging/, which deploy.sh deletes as its last action.
# Deliberately NOT
# folded into deploy.sh: that script's binary-swap/migration/timer-quiesce
# machinery exists to make a three-binary + migration deploy safely
# reversible mid-flight; a single static config file doesn't need any of
# that. It needs a validation gate, a backup a human can restore by hand,
# and a loud failure if anything didn't take — that's what this script does.
#
# The HTTP /-/reload endpoint is DISABLED on this box (Prometheus runs
# without --web.enable-lifecycle, so POST localhost:9090/-/reload returns
# 403). Do not "fix" that by adding --web.enable-lifecycle — the supported
# reload path here is `systemctl reload prometheus` (SIGHUP), which is what
# this script uses, and it verifies afterwards that the reload actually took
# rather than trusting systemctl's exit code (SIGHUP delivery succeeding is
# not the same as Prometheus accepting the new config — see the reload
# section below).
set -Eeuo pipefail

if [[ "$EUID" -eq 0 ]]; then
  # Workflow/manual production entrypoints clear the environment before Bash
  # starts. Re-establish the same contract here before any external command
  # (same pattern as deploy.sh/emergency-api-only.sh in this directory).
  PATH=/usr/sbin:/usr/bin:/sbin:/bin
  export PATH
  unset BASH_ENV ENV CDPATH
  if printenv PATCHED_PROM_TEST_MODE >/dev/null 2>&1; then
    echo "PATCHED_PROM_TEST_MODE is forbidden for root production invocation" >&2
    exit 1
  fi
  UNSAFE_OVERRIDE_NAMES=(
    PATCHED_PROM_STAGED_RULES PATCHED_PROM_STAGED_RULE_TESTS PATCHED_PROM_RULES_DEST PATCHED_PROM_SIDECAR
    PATCHED_PROM_BACKUP_DIR PATCHED_PROM_SYSTEMCTL_BIN PATCHED_PROM_PROMTOOL_BIN
    PATCHED_PROM_CURL_BIN PATCHED_PROM_URL PATCHED_PROM_OWNER PATCHED_PROM_JQ_BIN
  )
  for override_name in "${UNSAFE_OVERRIDE_NAMES[@]}"; do
    if printenv "$override_name" >/dev/null 2>&1; then
      echo "$override_name is forbidden for root production invocation" >&2
      exit 1
    fi
  done
  STAGED_RULES="/opt/patched-prometheus-staging/prometheus-rules-patched.yml"
  STAGED_RULE_TESTS="/opt/patched-prometheus-staging/prometheus-rules-patched.test.yml"
  RULES_DEST="/etc/prometheus/rules/patched.yml"
  SIDECAR="${RULES_DEST}.sha256"
  BACKUP_DIR="/root/patched-deploy-backups"
  SYSTEMCTL="systemctl"
  PROMTOOL="promtool"
  CURL="curl"
  JQ="jq"
  PROM_URL="http://localhost:9090"
  RULES_OWNER="prometheus:prometheus"
  PROMTOOL_EXPECTED_VERSION="2.45.3"
else
  [[ "${PATCHED_PROM_TEST_MODE:-}" == "1" ]] || { echo "deploy-prometheus-rules.sh must run as root" >&2; exit 1; }
  STAGED_RULES="${PATCHED_PROM_STAGED_RULES:?test staged rules path required}"
  STAGED_RULE_TESTS="${PATCHED_PROM_STAGED_RULE_TESTS:?test staged rules test path required}"
  RULES_DEST="${PATCHED_PROM_RULES_DEST:?test rules destination required}"
  SIDECAR="${PATCHED_PROM_SIDECAR:-${RULES_DEST}.sha256}"
  BACKUP_DIR="${PATCHED_PROM_BACKUP_DIR:?test backup dir required}"
  SYSTEMCTL="${PATCHED_PROM_SYSTEMCTL_BIN:-systemctl}"
  PROMTOOL="${PATCHED_PROM_PROMTOOL_BIN:-promtool}"
  CURL="${PATCHED_PROM_CURL_BIN:-curl}"
  JQ="${PATCHED_PROM_JQ_BIN:-jq}"
  PROM_URL="${PATCHED_PROM_URL:-http://localhost:9090}"
  RULES_OWNER="${PATCHED_PROM_OWNER:-}"
fi

: "${STAGED_RULE_TESTS:?staged rules test path required}"

# Optional: the commit this rules file came from, purely for provenance in
# the sidecar. Not required — a bare install still works — but the workflow
# always passes $GITHUB_SHA, so production always records one.
SOURCE_COMMIT="${1:-}"
if [[ -n "$SOURCE_COMMIT" && ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
  echo "source commit argument, if given, must be 40 lowercase hex characters" >&2
  exit 1
fi

log() { printf '\n== %s ==\n' "$*"; }

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

[[ -f "$STAGED_RULES" ]] || { echo "missing staged rules file: $STAGED_RULES" >&2; exit 1; }
[[ -s "$STAGED_RULES" ]] || { echo "staged rules file is empty: $STAGED_RULES" >&2; exit 1; }
[[ -f "$STAGED_RULE_TESTS" ]] || { echo "missing staged rules test file: $STAGED_RULE_TESTS" >&2; exit 1; }
[[ -s "$STAGED_RULE_TESTS" ]] || { echo "staged rules test file is empty: $STAGED_RULE_TESTS" >&2; exit 1; }

# ─── Gate: never install a file that fails validation ───────────────────────
log "promtool check rules"
command -v "$PROMTOOL" >/dev/null 2>&1 || {
  echo "$PROMTOOL not found — refusing to install unvalidated rules" >&2
  exit 1
}
if [[ "$EUID" -eq 0 ]]; then
  "$PROMTOOL" --version | grep -F "$PROMTOOL_EXPECTED_VERSION" >/dev/null || {
    echo "$PROMTOOL must be Prometheus $PROMTOOL_EXPECTED_VERSION for the deployed rule-test contract" >&2
    exit 1
  }
fi
PROMTOOL_OUTPUT="$("$PROMTOOL" check rules "$STAGED_RULES")"
printf '%s\n' "$PROMTOOL_OUTPUT"
log "promtool test rules"
"$PROMTOOL" test rules "$STAGED_RULE_TESTS"
# promtool exits non-zero on a check failure, which set -e already turns
# into a hard stop above — this is just capturing stdout too so the rule
# count below can double-check the live reload against the same file.
EXPECTED_RULE_COUNT="$(printf '%s\n' "$PROMTOOL_OUTPUT" | sed -n 's/.*SUCCESS: \([0-9][0-9]*\) rules found.*/\1/p')"
if [[ -z "$EXPECTED_RULE_COUNT" ]]; then
  # Non-author review, PAT-1423: this used to be an `if [[ -n
  # "$EXPECTED_RULE_COUNT" ]]` guard around the independent post-reload
  # rule-count confirmation further down — meaning a promtool output format
  # change would silently SKIP that confirmation while the deploy still
  # reported success, having verified strictly less than it claims to.
  # That is exactly the "a check that stops running looks identical to one
  # that is running" shape this ticket exists to close, so it cannot ship
  # inside the fix for it. Fail loudly and refuse to proceed instead —
  # nothing has been installed yet at this point.
  echo "could not determine the validated rule count from promtool's output — the independent post-reload rule-count confirmation could not run, so refusing to proceed rather than installing with less verification than this script claims to provide. promtool output was:" >&2
  printf '%s\n' "$PROMTOOL_OUTPUT" >&2
  exit 1
fi

# ─── Backup the live file before touching it ─────────────────────────────────
install -d -m 0755 "$BACKUP_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP=""
if [[ -f "$RULES_DEST" ]]; then
  BACKUP="$BACKUP_DIR/patched.yml.bak-${TS}"
  cp -a "$RULES_DEST" "$BACKUP"
  log "Backed up previous rules to $BACKUP"
else
  log "No existing $RULES_DEST — first install, nothing to back up"
fi

# ─── Install atomically ──────────────────────────────────────────────────────
log "Installing $RULES_DEST"
cp "$STAGED_RULES" "${RULES_DEST}.new"
if [[ -n "$RULES_OWNER" ]]; then
  chown "$RULES_OWNER" "${RULES_DEST}.new"
fi
chmod 0644 "${RULES_DEST}.new"
mv -f "${RULES_DEST}.new" "$RULES_DEST"

INSTALLED_SHA256="$(sha256_file "$RULES_DEST")"
EXPECTED_SHA256="$(sha256_file "$STAGED_RULES")"
if [[ "$INSTALLED_SHA256" != "$EXPECTED_SHA256" ]]; then
  echo "installed rules hash does not match staged file — refusing to reload. Backup: ${BACKUP:-none taken}" >&2
  exit 1
fi

# ─── Sidecar: record what this deploy installed (PAT-1423 item 3) ───────────
# api-vps-artefacts/patched-maintenance-facts.sh reads this back and reports
# both the live file's current hash and this recorded hash, so a hand-scp or
# hand-edit made after this deploy shows up as drift instead of going
# unnoticed — same shape the estate already uses for the application
# checkout (DEPLOYED_SHA, PAT-992/PAT-1378), applied here to this file.
{
  printf 'INSTALLED_SHA256=%s\n' "$INSTALLED_SHA256"
  printf 'INSTALLED_AT=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'SOURCE_COMMIT=%s\n' "${SOURCE_COMMIT:-unknown}"
} > "${SIDECAR}.new"
if [[ -n "$RULES_OWNER" ]]; then
  chown "$RULES_OWNER" "${SIDECAR}.new"
fi
chmod 0644 "${SIDECAR}.new"
mv -f "${SIDECAR}.new" "$SIDECAR"

# ─── Reload: SIGHUP via systemctl, NOT the HTTP endpoint (disabled — 403) ────
log "Reloading prometheus"
# Non-author review, PAT-1423: this used to swallow a pre-reload fetch
# failure into RELOAD_BEFORE="" with no signal, which silently degrades the
# post-reload "did the timestamp actually advance" check into "is
# RELOAD_AFTER merely non-empty" — the same silently-weakened-verification
# shape as the rule-count fix above, just smaller blast radius. This script
# runs ON api-01 querying its own localhost Prometheus, so a failure here
# means Prometheus (or the metric it's supposed to self-report) is already
# broken before this script has touched anything reload-related — not a
# cross-network blip worth tolerating — so fail closed rather than degrade
# quietly. Nothing has been reloaded yet at this point; only install has
# happened, and the backup remains available for recovery.
if ! BEFORE_METRICS="$("$CURL" -fsS --max-time 5 "${PROM_URL}/metrics")"; then
  echo "could not reach ${PROM_URL}/metrics before reloading — refusing to proceed: the post-reload check that confirms the reload actually advanced Prometheus's own last-reload timestamp depends on knowing that timestamp beforehand, and silently skipping it would weaken the same guarantee this script exists to provide. $RULES_DEST was installed but not yet reloaded. Backup: ${BACKUP:-none taken}" >&2
  exit 1
fi
RELOAD_BEFORE="$(printf '%s\n' "$BEFORE_METRICS" | awk '/^prometheus_config_last_reload_success_timestamp_seconds /{print $2}')"
if [[ -z "$RELOAD_BEFORE" ]]; then
  echo "${PROM_URL}/metrics did not report prometheus_config_last_reload_success_timestamp_seconds before reloading — cannot confirm the reload advances it afterwards. $RULES_DEST was installed but not yet reloaded. Backup: ${BACKUP:-none taken}" >&2
  exit 1
fi

if ! "$SYSTEMCTL" reload prometheus; then
  echo "systemctl reload prometheus failed — rules file installed at $RULES_DEST but NOT reloaded. Backup: ${BACKUP:-none taken}" >&2
  exit 1
fi

# Verify the reload actually took, rather than trusting systemctl's exit
# code: SIGHUP delivery succeeding is not the same as Prometheus accepting
# the new config. On a bad reload, Prometheus logs the error and keeps
# running on its last-good config — systemctl reload can return 0 while
# nothing changed. prometheus_config_last_reload_successful and its
# ...timestamp_seconds sibling are Prometheus's own self-reported signal for
# exactly this; the rule-count check against promtool's own count below is a
# second, independent confirmation that THIS file is what loaded.
#
# Non-author review, PAT-1423 round 2: this used to be a single fixed sleep
# then one metrics read. On a loaded box Prometheus may not have processed
# the SIGHUP within that window yet, which would read as a false deploy
# failure — expensive given this path can't be exercised until Actions comes
# back (PAT-1425), so its first real run is unattended. Poll instead, up to
# a bounded overall timeout, stopping as soon as a DEFINITIVE signal
# arrives either way: the timestamp has advanced past RELOAD_BEFORE
# (accepted), or prometheus_config_last_reload_successful has read "0"
# (rejected — Prometheus sets this the moment it finishes processing a bad
# reload, so seeing it is never an ambiguous "hasn't processed the SIGHUP
# yet" reading, the way a stale "1" mixed with an unmoved timestamp is). A
# genuine rejection therefore still fails fast, not after the full timeout;
# only the ambiguous "no answer yet" case waits.
POLL_INTERVAL="${PATCHED_PROM_RELOAD_WAIT:-2}"
POLL_TIMEOUT="${PATCHED_PROM_RELOAD_TIMEOUT:-30}"
POLL_DEADLINE=$(( $(date +%s) + POLL_TIMEOUT ))
METRICS=""
RELOAD_SUCCESSFUL=""
RELOAD_AFTER=""
while true; do
  sleep "$POLL_INTERVAL"
  if METRICS="$("$CURL" -fsS --max-time 5 "${PROM_URL}/metrics")"; then
    RELOAD_SUCCESSFUL="$(printf '%s\n' "$METRICS" | awk '/^prometheus_config_last_reload_successful /{print $2}')"
    RELOAD_AFTER="$(printf '%s\n' "$METRICS" | awk '/^prometheus_config_last_reload_success_timestamp_seconds /{print $2}')"
    if [[ "$RELOAD_SUCCESSFUL" == "0" ]] || { [[ -n "$RELOAD_AFTER" ]] && [[ "$RELOAD_AFTER" != "$RELOAD_BEFORE" ]]; }; then
      break
    fi
  else
    METRICS=""
  fi
  [[ "$(date +%s)" -lt "$POLL_DEADLINE" ]] || break
done

if [[ -z "$METRICS" ]]; then
  echo "could not reach ${PROM_URL}/metrics after reload (polled for up to ${POLL_TIMEOUT}s) — cannot confirm Prometheus took the file. Backup: ${BACKUP:-none taken}" >&2
  exit 1
fi
if [[ "$RELOAD_SUCCESSFUL" != "1" ]]; then
  echo "Prometheus reload REJECTED (prometheus_config_last_reload_successful=${RELOAD_SUCCESSFUL:-unknown}) — the box is still running its previous config even though $RULES_DEST was installed. Backup: ${BACKUP:-none taken}" >&2
  exit 1
fi
if [[ -z "$RELOAD_AFTER" || "$RELOAD_AFTER" == "$RELOAD_BEFORE" ]]; then
  echo "Prometheus reload did not advance its last-reload timestamp after polling for up to ${POLL_TIMEOUT}s (before=${RELOAD_BEFORE:-none} after=${RELOAD_AFTER:-none}) — cannot confirm the reload was actually applied. Backup: ${BACKUP:-none taken}" >&2
  exit 1
fi

# EXPECTED_RULE_COUNT is guaranteed non-empty here — the script already
# exited above (right after the promtool gate) if it couldn't be parsed, so
# this confirmation always runs rather than silently not running.
#
# Non-author review, PAT-1423 round 4: /api/v1/rules returns rule groups
# from EVERY loaded rule file on the box, not just ours. Comparing
# promtool's per-file count against that global total is only correct while
# patched.yml happens to be the only rule file Prometheus loads — the
# moment a second one is added, every deploy starts failing on a spurious
# mismatch, and the failure message ("the reload did not take the new
# file") sends whoever hits it to debug the wrong thing entirely. Filter by
# each group's own `file` field (Prometheus reports the exact path it
# loaded the group from) so this means "our file's rules loaded", not "the
# global total happens to match".
command -v "$JQ" >/dev/null 2>&1 || { echo "$JQ not found — cannot confirm the installed rule count" >&2; exit 1; }
# shellcheck disable=SC2016 # $rules_dest is a jq variable bound by --arg
# just before it, not a shell expansion — shellcheck's usual --arg heuristic
# only recognises a literal `jq` command name, not the "$JQ" variable this
# script uses for testability, so it can't tell that here.
if ! LIVE_RULE_COUNT="$("$CURL" -fsS --max-time 5 "${PROM_URL}/api/v1/rules" | "$JQ" --arg rules_dest "$RULES_DEST" '[.data.groups[] | select(.file == $rules_dest) | .rules[]] | length')"; then
  echo "could not query ${PROM_URL}/api/v1/rules to confirm the installed rule count" >&2
  exit 1
fi
if [[ "$LIVE_RULE_COUNT" != "$EXPECTED_RULE_COUNT" ]]; then
  echo "live Prometheus reports ${LIVE_RULE_COUNT} rules loaded from $RULES_DEST but the staged file has ${EXPECTED_RULE_COUNT} — the reload did not take the new file. Backup: ${BACKUP:-none taken}" >&2
  exit 1
fi

log "Prometheus reloaded and confirmed serving $RULES_DEST ($INSTALLED_SHA256)"

# ─── Prune old backups, keep the last 5 (same convention as deploy.sh) ──────
# Non-author review, PAT-1423 round 2: the fixed-width YYYYMMDDTHHMMSSZ
# names already sort chronologically under plain ASCII/lexicographic order,
# and bash glob expansion is itself sorted, so this was not producing a
# wrong prune order today. This is hardening, not a bug fix: don't rely on
# glob order at all — collect matches (order irrelevant at this point), then
# explicitly re-sort with `sort` pinned to the C locale, so pruning can never
# start depending on an ambient LC_COLLATE this script doesn't control. This
# is the rollback safety net; a wrong prune here loses the exact thing an
# incident would reach for.
MAX_BACKUPS=5
backups=()
for backup in "$BACKUP_DIR"/patched.yml.bak-*; do
  [[ -f "$backup" ]] || continue
  backups+=("$backup")
done
if [[ "${backups[0]+set}" == set ]]; then
  mapfile -t backups < <(printf '%s\n' "${backups[@]}" | LC_ALL=C sort)
  for ((i = 0; i < ${#backups[@]} - MAX_BACKUPS; i++)); do
    rm -f "${backups[$i]}"
  done
fi
