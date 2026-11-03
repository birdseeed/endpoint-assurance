#!/bin/zsh
##############################################################################
# test-os-update-state.zsh — PAT-2133, the os_update state computation.
#
# endpoint/patched-update.sh section 3b (PAT-273) computes the os_update block
# from the installed version, the SOFA feed and the optional policy plist.
# It used to fall back to the installed version as target_os when SOFA gave no
# latest version, so ver_ge(installed, target) was always true and a Mac whose
# latest version was unknown reported up_to_date. Absence requires authority:
# with no policy target and no known latest version the state is unknown and
# target_os is omitted, never "None", never "", never the installed version.
#
# This extracts the exact Python heredoc the daemon runs (anchored on its
# "$PYTHON3" - "$OS_UPDATE_TMP" line) and runs it against fixture SOFA caches
# and policy plists. A test-only prelude fakes /usr/bin/sw_vers and makes the
# network unreachable. No root, no daemon, no network.
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
UPDATE_SH="$SCRIPT_DIR/patched-update.sh"
PYTHON3="${PATCHED_TEST_PYTHON3:-$(command -v python3)}"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/.os-update-state-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

BLOCK="$WORK/block.py"
awk '/^"\$PYTHON3" - "\$OS_UPDATE_TMP" <<'"'"'PYEOF'"'"'$/{f=1;next} f&&/^PYEOF$/{exit} f' \
    "$UPDATE_SH" > "$BLOCK"
if [[ ! -s "$BLOCK" ]] || ! grep -q "sofa_cache" "$BLOCK"; then
    echo "FATAL: could not extract the os_update heredoc from $UPDATE_SH"
    exit 1
fi

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc"; fi
}

# run_case <installed_os> <sofa-json|-> <policy-target|-> <output>
#   sofa-json "-" means no cache and no network. policy-target "-" means no
#   policy file; any other value (including "") is written as target_os.
run_case() {
    local installed="$1" sofa="$2" policy_target="$3" out="$4"
    local state="$WORK/state.$RANDOM"
    mkdir -p "$state/triggers"
    [[ "$sofa" != "-" ]] && print -r -- "$sofa" > "$state/sofa-cache.json"
    if [[ "$policy_target" != "-" ]]; then
        "$PYTHON3" -c 'import plistlib,sys; plistlib.dump({"target_os": sys.argv[2]}, open(sys.argv[1], "wb"))' \
            "$state/os-update-policy.plist" "$policy_target"
    fi
    {
        print -r -- 'import subprocess as _sp, urllib.request as _ur'
        print -r -- '_real = _sp.check_output'
        print -r -- 'def _fake(args, *a, **k):'
        print -r -- '    if args and args[0] == "/usr/bin/sw_vers":'
        print -r -- "        return '''$installed''' + '\\n'"
        print -r -- '    return _real(args, *a, **k)'
        print -r -- '_sp.check_output = _fake'
        print -r -- 'def _nonet(*a, **k): raise OSError("network disabled in test")'
        print -r -- '_ur.urlopen = _nonet'
        cat "$BLOCK"
    } > "$state/run.py"
    PATCHED_STATE_DIR="$state" \
    PATCHED_TRIGGER_DIR="$state/triggers" \
    PATCHED_SOFA_CACHE="$state/sofa-cache.json" \
    PATCHED_OS_POLICY_FILE="$state/os-update-policy.plist" \
        "$PYTHON3" "$state/run.py" "$out"
}

field() {
    "$PYTHON3" -c 'import json,sys; o=json.load(open(sys.argv[1])); print(repr(o.get(sys.argv[2], "<absent>")) if sys.argv[2] in o else "<absent>")' \
        "$1" "$2" 2>/dev/null
}

sofa_for() { # sofa_for <version> <release-days-ago>
    local rd
    rd=$("$PYTHON3" -c 'import datetime,sys; print((datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(days=int(sys.argv[1]))).strftime("%Y-%m-%dT00:00:00Z"))' "$2")
    print -r -- "{\"OSVersions\":[{\"Latest\":{\"ProductVersion\":\"$1\",\"ReleaseDate\":\"$rd\",\"CVEs\":{},\"ActivelyExploitedCVEs\":[]}}]}"
}

no_none_text() { ! grep -q '"None"' "$1" && ! grep -q '"target_os": ""' "$1"; }

OUT="$WORK/out.json"

echo "--- latest unknown (SOFA has no entry for this major), no policy target"
run_case "26.0" "$(sofa_for 15.7 20)" "-" "$OUT"
chk "state is unknown, not up_to_date" "$([[ "$(field "$OUT" state)" == "'unknown'" ]] && echo 1 || echo 0)"
chk "target_os is absent" "$([[ "$(field "$OUT" target_os)" == "<absent>" ]] && echo 1 || echo 0)"
chk "latest_os is null" "$([[ "$(field "$OUT" latest_os)" == "None" ]] && echo 1 || echo 0)"
chk "no \"None\" or empty target text in the JSON" "$(no_none_text "$OUT" && echo 1 || echo 0)"

echo "--- latest unknown (no SOFA cache and network unreachable), no policy target"
run_case "26.0" "-" "-" "$OUT"
chk "state is unknown" "$([[ "$(field "$OUT" state)" == "'unknown'" ]] && echo 1 || echo 0)"
chk "target_os is absent" "$([[ "$(field "$OUT" target_os)" == "<absent>" ]] && echo 1 || echo 0)"

echo "--- latest unknown, empty policy target is no target"
run_case "26.0" "$(sofa_for 15.7 20)" "" "$OUT"
chk "state is unknown" "$([[ "$(field "$OUT" state)" == "'unknown'" ]] && echo 1 || echo 0)"
chk "target_os is absent, not \"\"" "$([[ "$(field "$OUT" target_os)" == "<absent>" ]] && echo 1 || echo 0)"

echo "--- latest known and newer"
run_case "26.0" "$(sofa_for 26.1 10)" "-" "$OUT"
chk "state is update_required or update_recommended" "$([[ "$(field "$OUT" state)" == "'update_required'" || "$(field "$OUT" state)" == "'update_recommended'" ]] && echo 1 || echo 0)"
chk "target_os is the SOFA latest" "$([[ "$(field "$OUT" target_os)" == "'26.1'" ]] && echo 1 || echo 0)"

echo "--- latest known and newer, released within the minimum age"
run_case "26.0" "$(sofa_for 26.1 2)" "-" "$OUT"
chk "state is update_recommended" "$([[ "$(field "$OUT" state)" == "'update_recommended'" ]] && echo 1 || echo 0)"

echo "--- latest known and equal"
run_case "26.1" "$(sofa_for 26.1 10)" "-" "$OUT"
chk "state is up_to_date" "$([[ "$(field "$OUT" state)" == "'up_to_date'" ]] && echo 1 || echo 0)"
chk "target_os is the SOFA latest" "$([[ "$(field "$OUT" target_os)" == "'26.1'" ]] && echo 1 || echo 0)"

echo "--- policy target set: unchanged"
run_case "26.1" "$(sofa_for 26.1 10)" "26.2" "$OUT"
chk "policy target above installed wins over SOFA latest" "$([[ "$(field "$OUT" target_os)" == "'26.2'" ]] && echo 1 || echo 0)"
chk "policy target above installed is not up_to_date" "$([[ "$(field "$OUT" state)" != "'up_to_date'" ]] && echo 1 || echo 0)"
run_case "26.1" "$(sofa_for 15.7 20)" "26.0" "$OUT"
chk "policy target met with latest unknown is up_to_date" "$([[ "$(field "$OUT" state)" == "'up_to_date'" ]] && echo 1 || echo 0)"
chk "policy target is reported" "$([[ "$(field "$OUT" target_os)" == "'26.0'" ]] && echo 1 || echo 0)"
run_case "26.0" "$(sofa_for 15.7 20)" "26.3" "$OUT"
chk "policy target unmet with latest unknown is unknown" "$([[ "$(field "$OUT" state)" == "'unknown'" ]] && echo 1 || echo 0)"
chk "policy target is still reported" "$([[ "$(field "$OUT" target_os)" == "'26.3'" ]] && echo 1 || echo 0)"

echo "--- installed version unreadable"
run_case "" "$(sofa_for 26.1 10)" "-" "$OUT"
chk "state is unknown" "$([[ "$(field "$OUT" state)" == "'unknown'" ]] && echo 1 || echo 0)"
chk "target_os is absent, not \"\"" "$([[ "$(field "$OUT" target_os)" == "<absent>" ]] && echo 1 || echo 0)"

echo
echo "Results: $pass passed, $fail failed"
(( fail == 0 ))
