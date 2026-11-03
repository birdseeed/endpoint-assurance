#!/usr/bin/env bash
# Fail a deploy if any named Patched unit cannot be scored against the
# ceilings in patched.im/docs/systemd-hardening-floor.md.
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  echo "usage: $0 <patched-unit.service> [...]" >&2
  exit 2
fi

for required_command in systemctl systemd-analyze awk; do
  command -v "$required_command" >/dev/null 2>&1 || {
    echo "hardening floor: required command missing: $required_command" >&2
    exit 1
  }
done

# PARITY-BLOCK-BEGIN: deploy-hardening-ceilings-policy (PAT-1237)
unit_class() {
  case "$1" in
    patched-backup.service|patched-prod-backup.service|patched-portal-backup.service|patched-prod-restore-test.service)
      printf '%s\n' credential-handling ;;
    patched-api.service|patched-dashboard.service|patched-portal.service|patched-extractor.service|patched-scan.service)
      printf '%s\n' application ;;
    patched-cve-sync.service|patched-tooling-cve-refresh.service|patched-partitions.service|patched-alert-metrics.service|patched-dashboard-prune-reports.service|patched-prod-alerts.service|patched-maintenance-facts.service|patched-scan-nvd-refresh.service)
      printf '%s\n' scheduled-maintenance ;;
    *) return 1 ;;
  esac
}

ceiling_for_class() {
  case "$1" in
    credential-handling) printf '%s\n' 6.7 ;;
    application|scheduled-maintenance) printf '%s\n' 6.0 ;;
    *) return 1 ;;
  esac
}
# PARITY-BLOCK-END: deploy-hardening-ceilings-policy (PAT-1237)

failed=0
for unit in "$@"; do
  if ! class="$(unit_class "$unit")"; then
    echo "hardening floor: $unit is not classified in docs/systemd-hardening-floor.md" >&2
    failed=1
    continue
  fi
  ceiling="$(ceiling_for_class "$class")"
  if [[ "$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)" != "loaded" ]]; then
    echo "hardening floor: $unit is not loaded after deploy" >&2
    failed=1
    continue
  fi
  analysis="$(LC_ALL=C SYSTEMD_COLORS=0 SYSTEMD_EMOJI=0 systemd-analyze --no-pager security "$unit")" || {
    echo "hardening floor: systemd-analyze failed for $unit" >&2
    failed=1
    continue
  }
  score=""
  while IFS= read -r line; do
    # systemd has used both ASCII and Unicode arrows/smileys around this
    # stable sentence. Parse only the sentence, exact unit, and numeric
    # score; presentation glyphs and the descriptive suffix are irrelevant.
    if [[ "$line" =~ Overall[[:space:]]+exposure[[:space:]]+level[[:space:]]+for[[:space:]]+([^:[:space:]]+):[[:space:]]+([0-9]+([.][0-9]+)?)([[:space:]]|$) ]] && [[ "${BASH_REMATCH[1]}" == "$unit" ]]; then
      score="${BASH_REMATCH[2]}"
      break
    fi
  done <<< "$analysis"
  if [[ -z "$score" ]]; then
    echo "hardening floor: no parseable exposure score for $unit" >&2
    failed=1
    continue
  fi
  if ! LC_ALL=C awk -v score="$score" -v ceiling="$ceiling" 'BEGIN { exit !(score <= ceiling) }'; then
    echo "hardening floor: $unit scored $score, above $class ceiling $ceiling" >&2
    failed=1
    continue
  fi
  echo "hardening floor: $unit scored $score, within $class ceiling $ceiling"
done

[[ "$failed" -eq 0 ]]
