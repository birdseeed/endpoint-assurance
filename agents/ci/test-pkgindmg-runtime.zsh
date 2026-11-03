#!/bin/zsh
set -euo pipefail

repo_root="${0:A:h:h}"
source "$repo_root/engine/fragments/functions.sh"

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
dmgmount="$fixture/mount"
mkdir -p "$dmgmount"

fail() {
    print -u2 -- "FAIL: $1"
    exit 1
}

# Exercise the actual production dispatcher while replacing only mount and
# installation side effects. This catches branch ordering/reachability drift
# that a direct resolver test cannot see.
mountDMG() { : }
printlog() { : }
installFromPKG() { installed_archive="$archiveName" }
cleanupAndExit() { fail "$2" }

expect_install() {
    local selected="$1"
    installed_archive=""
    archiveName="$dmgmount/source.dmg"
    installPkgInDmg
    [[ "$installed_archive" == "$selected" ]] || \
        fail "installPkgInDmg selected $installed_archive, expected $selected"
}

expect_install_failure_names_dmg() {
    local selector_kind="$1" selector="$2"
    local output rc
    if output=$(
        (
            cleanupAndExit() { print -r -- "$2"; exit "$1" }
            dmgmount="$fixture/empty"
            mkdir -p "$dmgmount"
            archiveName="$fixture/Original Payload.dmg"
            pkgName=""
            pkgPathPattern=""
            if [[ "$selector_kind" == "pkgPathPattern" ]]; then
                pkgPathPattern="$selector"
            else
                pkgName="$selector"
            fi
            installPkgInDmg
        ) 2>&1
    ); then
        fail "expected installPkgInDmg refusal for $selector_kind"
    else
        rc=$?
    fi
    [[ "$rc" -eq 20 ]] || fail "$selector_kind refusal exited $rc, expected 20"
    [[ "$output" == *"$selector"* ]] || fail "$selector_kind refusal omitted pattern"
    [[ "$output" == *"$fixture/Original Payload.dmg"* ]] || \
        fail "$selector_kind refusal lost original DMG archive name: $output"
}

# pkgPathPattern must dispatch before the empty-pkgName root default. JRE is
# nested, so the historical reversed ordering cannot accidentally pass.
mkdir -p "$fixture/e2e-jre/Java 8 Update 451.app/Contents/Resources"
touch "$fixture/e2e-jre/Java 8 Update 451.app/Contents/Resources/JavaAppletPlugin.pkg"
dmgmount="$fixture/e2e-jre"
pkgName=""
pkgPathPattern="Java 8 Update 451.app/Contents/Resources/JavaAppletPlugin.pkg"
expect_install "$dmgmount/Java 8 Update 451.app/Contents/Resources/JavaAppletPlugin.pkg"
expect_install_failure_names_dmg pkgPathPattern \
    "Java 8 Update 450.app/Contents/Resources/JavaAppletPlugin.pkg"

# The typed default remains exactly one root-level regular package.
mkdir -p "$fixture/e2e-root/Nested"
touch "$fixture/e2e-root/Root.pkg" "$fixture/e2e-root/Nested/Ignored.pkg"
dmgmount="$fixture/e2e-root"
pkgName=""
pkgPathPattern=""
expect_install "$dmgmount/Root.pkg"

# A literal pkgName preserves the direct-root preference before recursive
# fallback, even when an identically named nested package exists.
mkdir -p "$fixture/e2e-basename/Nested"
touch "$fixture/e2e-basename/Installer.pkg" \
      "$fixture/e2e-basename/Nested/Installer.pkg"
dmgmount="$fixture/e2e-basename"
pkgName="Installer.pkg"
pkgPathPattern=""
expect_install "$dmgmount/Installer.pkg"

expect_install_failure_names_dmg pkgPathPattern "Missing/Nested.pkg"
expect_install_failure_names_dmg pkgName "Missing.pkg"

# PAT-1428: lcadvancedvpnclient's real DMG ships two root .pkg files -- the
# actual installer and a hazardous "Uninstall.pkg". The typed root-unique-
# pkg default (empty pkgName, this label's pre-fix shell stanza shape) must
# refuse rather than arbitrarily pick either one, and the label's explicit
# pkgName (added to the Installomator shell stanza by this fix) must select
# the real installer, never the uninstaller, even though both sit at the
# DMG root.
mkdir -p "$fixture/e2e-lcadvancedvpnclient"
touch "$fixture/e2e-lcadvancedvpnclient/LANCOM Advanced VPN Client.pkg" \
      "$fixture/e2e-lcadvancedvpnclient/Uninstall.pkg"
if (
    cleanupAndExit() { print -r -- "$2"; exit "$1" }
    dmgmount="$fixture/e2e-lcadvancedvpnclient"
    archiveName="$fixture/Original Payload.dmg"
    pkgName=""
    pkgPathPattern=""
    installPkgInDmg
) 2>/dev/null; then
    fail "expected root-unique-pkg default to refuse with two root pkgs present"
fi
dmgmount="$fixture/e2e-lcadvancedvpnclient"
pkgName="LANCOM Advanced VPN Client.pkg"
pkgPathPattern=""
expect_install "$dmgmount/LANCOM Advanced VPN Client.pkg"

dmgmount="$fixture/mount"

expect_match() {
    local pattern="$1" expected="$2" actual
    actual=$(resolvePkgPathPattern "$pattern") || fail "expected match for $pattern"
    [[ "$actual" == "$expected" ]] || fail "$pattern resolved to $actual, expected $expected"
}

expect_no_match() {
    local pattern="$1"
    if resolvePkgPathPattern "$pattern" >/dev/null; then
        fail "expected refusal for $pattern"
    fi
}

# One machine-readable corpus binds the endpoint's real zsh resolver to the
# Python validator and verifier implementations.
corpus="$repo_root/ci/fixtures/pkgindmg-locator-cases.json"
corpus_mount="$fixture/corpus"
mkdir -p "$corpus_mount"
while IFS= read -r relative; do
    mkdir -p "$corpus_mount/${relative:h}"
    touch "$corpus_mount/$relative"
done < <(python3 -c \
    'import json,sys; print("\n".join(json.load(open(sys.argv[1], encoding="utf-8"))["files"]))' \
    "$corpus")
dmgmount="$corpus_mount"
while IFS=$'\t' read -r case_id valid pattern64 match64; do
    pattern=$(python3 -c \
        'import base64,sys; print(base64.b64decode(sys.argv[1]).decode("utf-8") + "__END__", end="")' \
        "$pattern64")
    pattern="${pattern%__END__}"
    if [[ "$valid" == "false" ]]; then
        expect_no_match "$pattern"
    elif [[ "$match64" == "-" ]]; then
        expect_no_match "$pattern"
    else
        expected=$(python3 -c \
            'import base64,sys; print(base64.b64decode(sys.argv[1]).decode("utf-8"), end="")' \
            "$match64")
        expect_match "$pattern" "$dmgmount/$expected"
    fi
done < <(python3 -c '
import base64,json,sys
doc=json.load(open(sys.argv[1], encoding="utf-8"))
enc=lambda value: base64.b64encode(value.encode("utf-8")).decode("ascii")
for case in doc["cases"]:
    match="-" if case["match"] is None else enc(case["match"])
    print(case["id"], str(case["valid"]).lower(), enc(case["pattern"]), match, sep="\t")
' "$corpus")

dmgmount="$fixture/mount"

# JRE's real multi-component pattern executes segment-by-segment.
mkdir -p "$dmgmount/Java 8 Update 451.app/Contents/Resources"
touch "$dmgmount/Java 8 Update 451.app/Contents/Resources/JavaAppletPlugin.pkg"
expect_match \
    "Java 8 Update *.app/Contents/Resources/JavaAppletPlugin.pkg" \
    "$dmgmount/Java 8 Update 451.app/Contents/Resources/JavaAppletPlugin.pkg"

# Matching is deliberately case-insensitive, preserving Installomator's
# historical find -iname behaviour on every mounted-volume filesystem.
expect_match \
    "java 8 update *.APP/contents/resources/javaappletplugin.PKG" \
    "$dmgmount/Java 8 Update 451.app/Contents/Resources/JavaAppletPlugin.pkg"

# OpenVPN's architecture-specific basename character class is executable.
touch "$dmgmount/OpenVPN_Connect_3_6_0_arm64_Installer_signed.pkg"
expect_match \
    "OpenVPN_Connect_[0-9_()]*_arm64_Installer_signed.pkg" \
    "$dmgmount/OpenVPN_Connect_3_6_0_arm64_Installer_signed.pkg"

# Bare parentheses are rejected consistently because zsh treats them as glob
# syntax. Parentheses remain valid as literals inside a character class.
touch "$dmgmount/Product (Intel).pkg"
expect_no_match "Product (Intel).pkg"

# A path-segment star cannot cross a directory boundary.
mkdir -p "$dmgmount/Segment/Nested"
touch "$dmgmount/Segment/Nested/Installer.pkg"
expect_no_match "Segment/*.pkg"

# Repeated component names do not confuse final-segment detection.
mkdir -p "$dmgmount/Repeat/Repeat"
touch "$dmgmount/Repeat/Repeat/Repeated.pkg"
expect_match "Repeat/Repeat/Repeated.pkg" "$dmgmount/Repeat/Repeat/Repeated.pkg"

# Symlinked files and directories never become payloads or traversal roots.
mkdir -p "$fixture/outside"
touch "$fixture/outside/Escape.pkg"
ln -s "$fixture/outside" "$dmgmount/Linked"
ln -s "$fixture/outside/Escape.pkg" "$dmgmount/Symlink.pkg"
expect_no_match "Linked/Escape.pkg"
expect_no_match "Symlink.pkg"

# Do not descend into an existing package bundle.
mkdir -p "$dmgmount/Outer.pkg/Contents"
touch "$dmgmount/Outer.pkg/Contents/Inner.pkg"
expect_no_match "Inner.pkg"

# Preserve safe root-basename preference even when a nested duplicate exists.
touch "$dmgmount/Installer.pkg"
mkdir -p "$dmgmount/Nested"
touch "$dmgmount/Nested/Installer.pkg"
expect_match "Installer.pkg" "$dmgmount/Installer.pkg"

# Without a root candidate, recursive basename ambiguity fails closed.
rm "$dmgmount/Installer.pkg"
mkdir -p "$dmgmount/Other"
touch "$dmgmount/Other/Installer.pkg"
expect_no_match "Installer.pkg"

expect_no_match "../Escape.pkg"
expect_no_match "/Escape.pkg"
expect_no_match $'Safe.pkg\nOther.pkg'
expect_no_match $'Safe.pkg\rOther.pkg'

# PAT-1385 P2 fix (round 8): this used to be named/framed as "the UTF-8
# locale test" and read `LC_ALL=en_US.UTF-8 expect_no_match "Installér.pkg"`
# -- but resolvePkgPathPattern()'s own vocabulary check pins its grep to
# `LC_ALL=C` INTERNALLY (functions.sh: `print -r -- "$pattern" | LC_ALL=C
# grep -Eq '^[][A-Za-z0-9 ._+()@/*?-]+$'`), regardless of whatever locale
# the CALLER runs under. That means the caller-side `LC_ALL=en_US.UTF-8`
# prefix had ZERO effect on the comparison actually being exercised: the
# exact same "no match" result would occur under any caller locale
# (including no LC_ALL override at all), so the old test didn't prove what
# its shape implied ("this resolver is UTF-8-locale-aware and correctly
# rejects it anyway") -- it proved nothing about locale sensitivity at all.
#
# A non-author review (2026-08-15) confirmed there is no reachable
# caller-locale-sensitive behaviour left in resolvePkgPathPattern() to test
# instead: the vocabulary gate is ASCII-only and pinned to C, so no
# multibyte byte sequence ever reaches any later, non-pinned comparison
# (the `no_case_glob`/`:l` case-folding further down never sees non-ASCII
# input, because the pinned gate above already refused it). Locale-
# independent byte comparison is the CORRECT, deliberate design for a
# security-relevant path-matching function that selects the exact bytes an
# endpoint installs -- behaviour must not vary by which macOS
# Language & Region setting happens to be active on a given customer Mac.
#
# This is now an explicit, honestly-named proof of THAT property: the same
# input, run under three different caller locales (the previous
# en_US.UTF-8, the C locale the resolver itself pins to internally, and a
# third, unrelated locale), must all refuse identically. If the internal
# LC_ALL=C pin were ever accidentally removed or narrowed, this is the test
# that would catch the resulting locale-dependent behaviour drift.
for caller_locale in en_US.UTF-8 C de_DE.UTF-8; do
    LC_ALL="$caller_locale" expect_no_match "Installér.pkg"
done

print -- "pkgindmg runtime dispatch and resolver: OK"
