#!/bin/bash
##############################################################################
# build-bundle.sh
#
# Produces single-file deployable bundles for the macOS agent's two
# entrypoints — the collector and the uploader — inlining each sourced
# lib/*.sh module with its actual file contents so no lib/ directory is
# needed at runtime. This is what makes "no lib/ needed at runtime" true for
# a release install: install.sh ships these bundles instead of the raw
# entrypoints plus a lib/ directory.
#
# Two lib-reference idioms are handled:
#
#   1. Unconditional (patched-collect.sh):
#        source "${LIB_DIR}/foo.sh"
#      Replaced in place with the contents of lib/foo.sh.
#
#   2. Guarded (patched-upload.sh) — the enforcement modules are optional at
#      the source level (a dev checkout without lib/ should still run) but
#      must be unconditional in the bundle, or the bundled script would take
#      the else branch every time (no lib/ ships in the tarball) and silently
#      skip enforcement forever:
#        if [[ -f ".../lib/foo.sh" ]]; then
#            source ".../lib/foo.sh"
#            foo_call || true
#        else
#            echo "... not found — skipping ..."
#        fi
#      The whole if/else/fi is collapsed: the source line is replaced with
#      lib/foo.sh's contents, the other then-branch lines (the enforcement
#      calls) are kept, and the else branch (the skip message) is dropped.
#      The guard itself is untouched in the unbundled source file, so a
#      source-tree checkout with lib/ present, or without it, still behaves
#      as written.
#
# Usage:
#   cd macos && bash build-bundle.sh --agent-version X.Y.Z.N
#
# Output:
#   dist/patched-collect.sh   (chmod +x, ready to deploy)
#   dist/patched-upload.sh    (chmod +x, ready to deploy)
##############################################################################
set -euo pipefail

usage() {
    echo "Usage: $0 --agent-version X.Y.Z or X.Y.Z.N" >&2
    exit 64
}

if [[ "$#" -ne 2 || "$1" != "--agent-version" ]]; then
    usage
fi

AGENT_VERSION="$2"

# Wire versions are numeric X.Y.Z for stable releases and X.Y.Z.N for beta
# candidates. Channel remains separate registration metadata; the beta
# revision is numeric so both installed-version comparators can order updates.
if ! [[ "$AGENT_VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(\.([1-9][0-9]?))?$ ]]; then
    echo "build-bundle: ERROR: invalid agent version '$AGENT_VERSION': expected numeric X.Y.Z[.N]" >&2
    exit 65
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB_DIR="$SCRIPT_DIR/lib"
DIST="$SCRIPT_DIR/dist"
AGENT_VERSION_PLACEHOLDER="__PATCHED_AGENT_VERSION__"

mkdir -p "$DIST"

bundle_one() {
    local src="$1" out="$2"

    # A library named in a `source` directive that is missing, unreadable,
    # or empty is a build error, not an empty inline: inline_lib() reads it
    # itself (rather than leaving that to the getline-in-a-loop condition,
    # which treats "could not open" and "normal end of file" the same way)
    # and calls awk's exit on either failure so the bad read surfaces as a
    # non-zero awk exit status, which `set -euo pipefail` then turns into a
    # non-zero build. srcfile is passed in only to name the referencing file
    # in the error.
    awk -v lib_dir="$LIB_DIR" -v srcfile="$src" '
    BEGIN { state = "normal" }
    {
        line = $0
    }

    function inline_lib(name,    rc, count, src_line, path) {
        path = lib_dir "/" name
        count = 0
        while (1) {
            rc = (getline src_line < path)
            if (rc <= 0) break
            print src_line
            count++
        }
        close(path)
        if (rc < 0) {
            printf "build-bundle: ERROR: cannot read library %s (referenced by %s)\n", path, srcfile > "/dev/stderr"
            exit 1
        }
        if (count == 0) {
            printf "build-bundle: ERROR: library %s is empty (referenced by %s)\n", path, srcfile > "/dev/stderr"
            exit 1
        }
    }

    # --- idiom 1: unconditional `source "${LIB_DIR}/foo.sh"` -------------
    state == "normal" && line ~ /source[ \t]+"\$\{LIB_DIR\}\// {
        name = line
        sub(/.*\//, "", name)
        sub(/".*/, "", name)
        print "# --- inlined: " name " ---"
        inline_lib(name)
        next
    }

    # --- idiom 2: guarded `if [[ -f ".../lib/foo.sh" ]]; then` -----------
    state == "normal" && line ~ /^[ \t]*if \[\[ -f "[^"]*\/lib\/[A-Za-z0-9_]+\.sh"[ \t]*\]\];[ \t]*then[ \t]*$/ {
        name = line
        sub(/.*\/lib\//, "", name)
        sub(/".*/, "", name)
        pending_lib = name
        state = "guarded_then"
        next
    }

    state == "normal" { print line; next }

    # Inside the then-branch: replace the matching source line with the
    # inlined library contents; pass every other line (the enforcement
    # calls) through unchanged; an `else` ends the then-branch.
    state == "guarded_then" && line ~ ("source[ \t]+\"[^\"]*/lib/" pending_lib "\"") {
        print "# --- inlined: " pending_lib " ---"
        inline_lib(pending_lib)
        next
    }
    state == "guarded_then" && line ~ /^[ \t]*else[ \t]*$/ {
        state = "guarded_else"
        next
    }
    state == "guarded_then" { print line; next }

    # Inside the else-branch (the "not found — skipping" fallback): drop
    # every line until the closing `fi`, which ends the block.
    state == "guarded_else" && line ~ /^[ \t]*fi[ \t]*$/ {
        state = "normal"
        next
    }
    state == "guarded_else" { next }
    ' "$src" > "$out"

    chmod +x "$out"
}

# Belt-and-suspenders check that runs after a bundle_one that did not itself
# fail: confirm the bundle actually contains what the source file promised.
# This catches a different failure shape than inline_lib()'s read errors —
# a `source` directive whose line no longer matches either awk idiom (a
# formatting change, say) passes through bundle_one untouched and unnoticed,
# leaving a bundle that still points at a lib/ file that will not exist at
# runtime. The expected library set is derived from the source file's own
# `source` directives (both idioms), not hardcoded, so a library added later
# is covered automatically.
verify_bundle() {
    local src="$1" out="$2"
    local expected lib incomplete=0

    expected=$(grep -oE '(\$\{LIB_DIR\}|/lib)/[A-Za-z0-9_]+\.sh' "$src" | sed -E 's#.*/##' | sort -u)

    while IFS= read -r lib; do
        [[ -z "$lib" ]] && continue
        if ! grep -qF "# --- inlined: $lib ---" "$out"; then
            echo "build-bundle: ERROR: $out has no inlined copy of $lib, but $src sources it" >&2
            incomplete=1
        fi
    done <<< "$expected"

    if grep -q "not found — skipping" "$out"; then
        echo "build-bundle: ERROR: $out still contains a 'not found — skipping' fallback — a guarded library block was not collapsed" >&2
        incomplete=1
    fi

    if [[ "$incomplete" -ne 0 ]]; then
        exit 1
    fi
}

# The collector source deliberately contains one release-time placeholder, not
# a hand-maintained version. Stamp the generated collector only after all
# library inlining checks have passed, then prove that the artifact has one and
# only one agent_version field containing the requested release version. A
# missing, duplicated, or changed source marker is a hard failure: releasing a
# misleading collector version breaks inventory provenance.
count_exact_agent_version_field() {
    local expected_value="$1" out="$2"

    # Keep expected_value out of an awk regular expression. The release
    # version is validated above, but the placeholder is deliberately a build
    # detail that could change independently in future.
    awk -v expected_value="$expected_value" '
        /^[[:space:]]*"agent_version"[[:space:]]*:[[:space:]]*"[^"]*",[[:space:]]*$/ {
            value = $0
            sub(/^[[:space:]]*"agent_version"[[:space:]]*:[[:space:]]*"/, "", value)
            sub(/",[[:space:]]*$/, "", value)
            if (value == expected_value) {
                count++
            }
        }
        END { print count + 0 }
    ' "$out"
}

stamp_collector_version() {
    local out="$1" field_count placeholder_count stamped_count stamp_tmp

    field_count=$(grep -cE '^[[:space:]]*"agent_version"[[:space:]]*:[[:space:]]*"[^"]*",[[:space:]]*$' "$out" || true)
    if [[ "$field_count" -ne 1 ]]; then
        echo "build-bundle: ERROR: $out must contain exactly one JSON agent_version field; found $field_count" >&2
        rm -f "$out"
        exit 1
    fi

    placeholder_count=$(count_exact_agent_version_field "$AGENT_VERSION_PLACEHOLDER" "$out")
    if [[ "$placeholder_count" -ne 1 ]]; then
        echo "build-bundle: ERROR: $out must contain exactly one $AGENT_VERSION_PLACEHOLDER marker; found $placeholder_count (missing, duplicated, or mismatched source field)" >&2
        rm -f "$out"
        exit 1
    fi

    stamp_tmp=$(mktemp "$DIST/.patched-collect.sh.XXXXXX")
    awk -v version="$AGENT_VERSION" -v placeholder="$AGENT_VERSION_PLACEHOLDER" '
        /^[[:space:]]*"agent_version"[[:space:]]*:[[:space:]]*"[^"]*",[[:space:]]*$/ {
            marker = "\"" placeholder "\""
            marker_pos = index($0, marker)
            if (marker_pos > 0) {
                $0 = substr($0, 1, marker_pos - 1) "\"" version "\"" substr($0, marker_pos + length(marker))
            }
        }
        { print }
    ' "$out" > "$stamp_tmp"
    chmod +x "$stamp_tmp"
    mv -f "$stamp_tmp" "$out"

    stamped_count=$(count_exact_agent_version_field "$AGENT_VERSION" "$out")
    if [[ "$stamped_count" -ne 1 ]] || grep -qF "$AGENT_VERSION_PLACEHOLDER" "$out"; then
        echo "build-bundle: ERROR: $out agent_version stamp did not exactly match requested version $AGENT_VERSION" >&2
        rm -f "$out"
        exit 1
    fi
}

bundle_one "$SCRIPT_DIR/patched-collect.sh" "$DIST/patched-collect.sh"
verify_bundle "$SCRIPT_DIR/patched-collect.sh" "$DIST/patched-collect.sh"
stamp_collector_version "$DIST/patched-collect.sh"
bundle_one "$SCRIPT_DIR/patched-upload.sh"  "$DIST/patched-upload.sh"
verify_bundle "$SCRIPT_DIR/patched-upload.sh"  "$DIST/patched-upload.sh"

echo "Bundle written to: $DIST/patched-collect.sh"
wc -l < "$DIST/patched-collect.sh" | xargs -I{} echo "Lines: {}"
echo "Bundle written to: $DIST/patched-upload.sh"
wc -l < "$DIST/patched-upload.sh" | xargs -I{} echo "Lines: {}"
