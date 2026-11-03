#!/bin/zsh --no-rcs
# Engine hardening gate (security review H5).
#
# The committed engine/Installomator.sh is the CANONICAL, hardened engine.
# engine/assemble.sh (a symlink to engine/utils/assemble.sh) reassembles the
# engine from engine/fragments/*, which are stale upstream Installomator and
# contain NONE of the Patched fail-closed verification controls and default to
# DEBUG=1. Running assemble.sh --script would silently overwrite the hardened
# engine with an unverified one.
#
# This gate asserts two invariants on every PR/push that touches the engine:
#   1. The committed engine keeps DEBUG=0 and every Patched verification marker
#      (exit 60..64, assert_https_url, PINNED_SHA256, PATCHED_VERIFICATION_FAILED).
#   2. assemble.sh refuses to run (fails closed) unless the explicit
#      PATCHED_ALLOW_UNHARDENED_ASSEMBLE=1 escape hatch is set — so it cannot be
#      used, in CI or by a contributor, to regenerate an unhardened engine.
#
# Usage: zsh ci/test-engine-hardening.zsh
# Exit 0 if all invariants hold; non-zero otherwise.

set -u

HERE="${0:a:h}"
ENGINE="$HERE/../engine/Installomator.sh"
ASSEMBLE="$HERE/../engine/assemble.sh"

FAIL=0
pass() { print "  PASS  $1"; }
fail() { print "  FAIL  $1"; FAIL=1; }

if [[ ! -f "$ENGINE" ]]; then
    print "ERROR: engine not found at $ENGINE" >&2
    exit 1
fi

print "== 1. Committed engine retains hardening =="

# DEBUG must default to 0.
if grep -Eq '^DEBUG=0[[:space:]]*(#.*)?$' "$ENGINE"; then
    pass "DEBUG=0 default present"
else
    fail "DEBUG=0 default NOT present (engine may run in debug mode / skip root check)"
fi

# Each Patched verification exit code must be present.
for code in 60 61 62 63 64; do
    if grep -Eq "cleanupAndExit ${code}\b|exit ${code}\b" "$ENGINE"; then
        pass "verification exit ${code} present"
    else
        fail "verification exit ${code} MISSING"
    fi
done

# Named guards / markers.
for marker in "assert_https_url" "PINNED_SHA256" "PATCHED_VERIFICATION_FAILED"; do
    if grep -q "$marker" "$ENGINE"; then
        pass "marker '$marker' present"
    else
        fail "marker '$marker' MISSING"
    fi
done

print "== 2. assemble.sh fails closed without the escape hatch =="

# Snapshot the engine so we can prove assemble.sh did not overwrite it.
BEFORE_SHA=$(shasum -a 256 "$ENGINE" | awk '{print $1}')

# Run assemble.sh with --script (the flag that would overwrite Installomator.sh),
# WITHOUT the escape hatch. It must exit non-zero and touch nothing.
if [[ -e "$ASSEMBLE" ]]; then
    unset PATCHED_ALLOW_UNHARDENED_ASSEMBLE
    out=$(zsh "$ASSEMBLE" --script 2>&1)
    rc=$?
    if [[ $rc -ne 0 ]]; then
        pass "assemble.sh --script refused (exit $rc)"
    else
        fail "assemble.sh --script ran without the escape hatch (exit 0) — could strip hardening"
    fi

    AFTER_SHA=$(shasum -a 256 "$ENGINE" | awk '{print $1}')
    if [[ "$BEFORE_SHA" == "$AFTER_SHA" ]]; then
        pass "committed engine unchanged by assemble.sh"
    else
        fail "assemble.sh MODIFIED engine/Installomator.sh"
    fi
else
    fail "assemble.sh not found at $ASSEMBLE"
fi

print "== 3. Download curls refuse an https-to-http redirect (PAT-885 / T6) =="

# assert_https_url only validates the pre-resolved downloadURL string; curl's
# -L flag will happily follow a redirect to a different protocol unless the
# fetch itself is also pinned. Every curl invocation that writes the
# downloaded artifact to $archiveName must carry both --proto and
# --proto-redir restricted to https, so an https-to-http redirect fails
# closed instead of being fetched and mounted before spctl/TeamID runs.
#
# The restriction flags must also come AFTER ${curlOptions} on the command
# line, not before: curl uses the last occurrence of a repeated single-value
# option, so if a label's curlOptions ever carried its own --proto-redir, a
# fixed restriction placed BEFORE curlOptions would be silently overridden
# while this grep still found the flags present. Asserting on relative
# position (not just presence) catches that regression.
DOWNLOAD_LINES=$(grep -n -- '-o "\$archiveName"' "$ENGINE")

if [[ -z "$DOWNLOAD_LINES" ]]; then
    fail "no curl invocation writing to \$archiveName found (expected at least 2: pipe branch and plain branch)"
else
    DOWNLOAD_LINE_COUNT=$(print -r -- "$DOWNLOAD_LINES" | wc -l | tr -d ' ')
    pass "found $DOWNLOAD_LINE_COUNT download-curl call site(s) writing \$archiveName"

    while IFS= read -r hit; do
        lineno="${hit%%:*}"
        linetext="${hit#*:}"
        if [[ "$linetext" != *'--proto '*'=https'* || "$linetext" != *'--proto-redir '*'=https'* ]]; then
            fail "line $lineno: missing --proto/--proto-redir https restriction, redirect to http would be followed: $linetext"
        elif [[ "$linetext" == *'curlOptions'*'--proto '*'=https'*'--proto-redir '*'=https'* ]]; then
            pass "line $lineno: --proto/--proto-redir pinned to https, placed after \${curlOptions} (non-overridable)"
        else
            fail "line $lineno: --proto/--proto-redir present but not placed AFTER \${curlOptions}, a label's curlOptions could override the restriction: $linetext"
        fi
    done <<< "$DOWNLOAD_LINES"
fi

print ""
if [[ $FAIL -eq 0 ]]; then
    print "engine hardening gate: OK"
    exit 0
else
    print "engine hardening gate: FAILED"
    exit 1
fi
