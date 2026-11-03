#!/bin/zsh
##############################################################################
# test-build-bundle-agent-version.zsh — PAT-1227 release provenance gate.
#
# Builds an unmodified copy of the real collector and every real lib module,
# then inspects the generated single-file collector. The negative cases alter
# only scratch copies to prove the bundler fails closed if the release-time
# JSON field is absent, duplicated, or no longer the expected placeholder.
#
# Run: zsh macos/test-build-bundle-agent-version.zsh
##############################################################################

set -u

SCRIPT_DIR="${0:A:h}"
SENTINEL_VERSION="97.41.3.2"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/patched-bundle-version-test.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
chk() {
    local desc="$1" ok="$2"
    if (( ok )); then
        (( pass++ ))
        echo "  PASS: $desc"
    else
        (( fail++ ))
        echo "  FAIL: $desc"
    fi
}

scratch_macos() {
    local name copy_dir
    name="$1"
    copy_dir="$WORK/$name"
    cp -R "$SCRIPT_DIR" "$copy_dir"
    rm -rf "$copy_dir/dist"
    print -r -- "$copy_dir"
}

agent_version_line_count() {
    local collector="$1"
    grep -cE '^[[:space:]]*"agent_version"[[:space:]]*:[[:space:]]*"[^"]*",[[:space:]]*$' "$collector" || true
}

agent_version_value_count() {
    local collector="$1" expected="$2"
    awk -v expected="$expected" '
        /^[[:space:]]*"agent_version"[[:space:]]*:[[:space:]]*"[^"]*",[[:space:]]*$/ {
            value = $0
            sub(/^[[:space:]]*"agent_version"[[:space:]]*:[[:space:]]*"/, "", value)
            sub(/",[[:space:]]*$/, "", value)
            if (value == expected) count++
        }
        END { print count + 0 }
    ' "$collector"
}

mutate_scratch_collector() {
    local mode="$1" collector="$2" tmp
    tmp=$(mktemp "$collector.XXXXXX") || return 1

    case "$mode" in
        missing)
            awk '!/^[[:space:]]*"agent_version":[[:space:]]*"__PATCHED_AGENT_VERSION__",[[:space:]]*$/' \
                "$collector" > "$tmp"
            ;;
        duplicate)
            awk '
                /^[[:space:]]*"agent_version":[[:space:]]*"__PATCHED_AGENT_VERSION__",[[:space:]]*$/ {
                    print
                }
                { print }
            ' "$collector" > "$tmp"
            ;;
        mismatch)
            awk '
                /^[[:space:]]*"agent_version":[[:space:]]*"__PATCHED_AGENT_VERSION__",[[:space:]]*$/ {
                    marker = "\"__PATCHED_AGENT_VERSION__\""
                    marker_pos = index($0, marker)
                    $0 = substr($0, 1, marker_pos - 1) "\"stale-source-version\"" substr($0, marker_pos + length(marker))
                }
                { print }
            ' "$collector" > "$tmp"
            ;;
        whitespace)
            awk '
                /^[[:space:]]*"agent_version":[[:space:]]*"__PATCHED_AGENT_VERSION__",[[:space:]]*$/ {
                    print "\t\"agent_version\"\t:\t\"__PATCHED_AGENT_VERSION__\","
                    next
                }
                { print }
            ' "$collector" > "$tmp"
            ;;
        *)
            rm -f "$tmp"
            return 1
            ;;
    esac
    mv -f "$tmp" "$collector"
}

expect_failure() {
    local desc="$1" expected="$2"
    shift 2
    local output="$WORK/failure-$RANDOM.log"

    if "$@" > "$output" 2>&1; then
        chk "$desc exits non-zero" 0
        return
    fi
    chk "$desc exits non-zero" 1
    chk "$desc reports the rejected version field" "$(grep -qF "$expected" "$output" && echo 1 || echo 0)"
}

echo "[1] real collector bundle receives the resolved release version"
positive=$(scratch_macos positive)
if bash "$positive/build-bundle.sh" --agent-version "$SENTINEL_VERSION" > "$WORK/positive.log" 2>&1; then
    chk "build succeeds for numeric release version" 1
else
    chk "build succeeds for numeric release version" 0
    cat "$WORK/positive.log"
fi

collector="$positive/dist/patched-collect.sh"
chk "built collector exists" "$(test -s "$collector" && echo 1 || echo 0)"
chk "built collector has exactly one agent_version JSON field" \
    "$([[ "$(agent_version_line_count "$collector")" == "1" ]] && echo 1 || echo 0)"
chk "built collector agent_version equals sentinel release version" \
    "$(grep -qE '^[[:space:]]*"agent_version":[[:space:]]*"97\.41\.3\.2",[[:space:]]*$' "$collector" && echo 1 || echo 0)"
chk "built collector contains no release placeholder" \
    "$(grep -qF '__PATCHED_AGENT_VERSION__' "$collector" && echo 0 || echo 1)"

echo "[2] valid JSON whitespace around the colon is accepted"
whitespace_field=$(scratch_macos whitespace-field)
mutate_scratch_collector whitespace "$whitespace_field/patched-collect.sh" || exit 1
if bash "$whitespace_field/build-bundle.sh" --agent-version "$SENTINEL_VERSION" > "$WORK/whitespace.log" 2>&1; then
    chk "build accepts whitespace around agent_version colon" 1
else
    chk "build accepts whitespace around agent_version colon" 0
    cat "$WORK/whitespace.log"
fi
whitespace_collector="$whitespace_field/dist/patched-collect.sh"
chk "whitespace-variant collector has exactly one agent_version JSON field" \
    "$([[ "$(agent_version_line_count "$whitespace_collector")" == "1" ]] && echo 1 || echo 0)"
chk "whitespace-variant collector stamps the sentinel release version" \
    "$([[ "$(agent_version_value_count "$whitespace_collector" "$SENTINEL_VERSION")" == "1" ]] && echo 1 || echo 0)"

echo "[3] an explicit valid version is mandatory"
missing_arg=$(scratch_macos missing-arg)
expect_failure "missing --agent-version" "Usage:" bash "$missing_arg/build-bundle.sh"

invalid_version=$(scratch_macos invalid-version)
expect_failure "invalid version" "invalid agent version" \
    bash "$invalid_version/build-bundle.sh" --agent-version 01.2.3

zero_revision=$(scratch_macos zero-revision)
expect_failure "zero beta revision" "invalid agent version" \
    bash "$zero_revision/build-bundle.sh" --agent-version 1.2.3.0

large_revision=$(scratch_macos large-revision)
expect_failure "beta revision over 99" "invalid agent version" \
    bash "$large_revision/build-bundle.sh" --agent-version 1.2.3.100

echo "[4] malformed collector version fields fail closed"
missing_field=$(scratch_macos missing-field)
mutate_scratch_collector missing "$missing_field/patched-collect.sh" || exit 1
expect_failure "missing agent_version field" "exactly one JSON agent_version field" \
    bash "$missing_field/build-bundle.sh" --agent-version "$SENTINEL_VERSION"

duplicate_field=$(scratch_macos duplicate-field)
mutate_scratch_collector duplicate "$duplicate_field/patched-collect.sh" || exit 1
expect_failure "duplicated agent_version field" "exactly one JSON agent_version field" \
    bash "$duplicate_field/build-bundle.sh" --agent-version "$SENTINEL_VERSION"

mismatched_field=$(scratch_macos mismatched-field)
mutate_scratch_collector mismatch "$mismatched_field/patched-collect.sh" || exit 1
expect_failure "mismatched agent_version field" "missing, duplicated, or mismatched source field" \
    bash "$mismatched_field/build-bundle.sh" --agent-version "$SENTINEL_VERSION"

echo ""
echo "==== $pass passed, $fail failed ===="
[[ $fail -eq 0 ]] && exit 0 || exit 1
