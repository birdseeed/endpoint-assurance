#!/bin/bash
# tools/build-bundle.sh — assemble the Patched Updater endpoint bundle.
#
# PAT-1505: this builds an ASSURANCE-ONLY bundle. It is the only bundle this
# script produces and the only one that is distributed.
#
# What that means, and why it is a build-time decision rather than a runtime
# one. The vNext product boundary (26 August 2026) quarantines packaging, the
# signed deployment catalogue, Self Service, mandatory rollout and direct
# remediation: Patched is Endpoint Assurance and Software Governance, not a
# packaging or deployment product. The daemon's AGENT_TIER gate (default
# assurance, fail-safe on missing config or hash mismatch) is real and
# stays, but it only decides what RUNS. It does not decide what is on disk.
# This bundle installs as root on prospect machines during a pre-sale
# assessment, and a security reviewer — or the PAT-140 pentest firm, whose
# scope was rescoped to exclude the executor — reads what is installed, not
# what a runtime flag currently gates off. So the deployment engine is not
# copied into the bundle at all.
#
# NOT SHIPPED (deliberately; the sources REMAIN in the repo, untouched, so
# PAT-1481 can bring a narrow, separately-scoped, separately-pentested macOS
# executor back as an opt-in add-on later — this is a shipping decision, not a
# deletion):
#     engine/Installomator.sh          the hard-forked installer engine
#     endpoint/patched-install.sh      Tier-2 pending-installs engine (PAT-661)
#     endpoint/patched-uninstall.sh    scheduled-removals engine (PAT-376)
#     endpoint/labels-allowlist.txt    derived package-authorisation allowlist
#     engine/LICENSE + the NOTICE      Installomator's Apache 2.0 attribution.
#                                      Apache 2.0 §4(a)/§4(d) require these to
#                                      travel with the covered work; with
#                                      Installomator.sh no longer distributed
#                                      there is no covered work in this bundle,
#                                      and the NOTICE's "This bundle includes
#                                      Installomator" would be false.
#     com.patched.install-check.plist    root LaunchDaemon -> patched-install.sh
#     com.patched.uninstall-check.plist  root LaunchDaemon -> patched-uninstall.sh
#
# RETIRED (PAT-2245; deleted from the repository, not merely unshipped): the
# signed deployment-catalogue poller, its verifier and its 4-hourly root
# LaunchDaemon. install.sh and tools/pkg-scripts/postinstall still boot out
# and delete any copy an older bundle left on a Mac.
#
# Outputs:
#   dist/patched-updater/          bundle (copy to /usr/local/patched-updater/)
#     patched-update.sh            daemon; NOT in the manifest (carries its pin)
#     patched-fetch-config.sh      signed agent-config channel
#     patched-fetch-posture.sh     signed posture channel
#     patched-enroll.sh            enrolment
#     patched-log-upload.sh        log upload
#     patched-decommission.sh      decommission / expiry orchestrator
#     verify-agent-config.py verify-posture.py validate-posture.py
#     agent_config_floor.py        anti-rollback floor parser (PAT-1763)
#     agent_config_tenant.py       cached-config tenant check (PAT-1773)
#     agent_update_channel.py      verified self-update channel (PAT-2005)
#     patched-proxy-resolve.py
#     endpoint-uninstall.sh macos-uninstall.sh   staged by the decommissioner
#     com.patched.*.plist          LaunchDaemon plists (all under integrity scope)
#     manifest.sha256              SHA-256 of every file above
#   dist/install.sh                EXPECTED_MANIFEST_HASH stamped in
#   dist/uninstall.sh
#
# Usage:
#   bash tools/build-bundle.sh [--repo-root DIR]
#
# Requires: shasum.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Allow override for CI/testing.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo-root) REPO_ROOT="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

DIST="$REPO_ROOT/dist"
DIST_BUNDLE="$DIST/patched-updater"

echo "=== Patched Updater endpoint bundle build ==="
echo "Repo root: $REPO_ROOT"

# --- Clean + create ---
rm -rf "$DIST_BUNDLE"
mkdir -p "$DIST_BUNDLE"

# PAT-1505: the derived package allowlist is no longer emitted into the bundle.
# Its only consumer was the deployment engine, which this bundle no longer
# ships, so emitting it would leave an unread package-authorisation list sitting
# in a bundle a prospect's security reviewer will read. The label manifest and
# its integrity gate are untouched: ci/validate-labels.py still runs in
# .github/workflows/validate-labels.yml, and endpoint/labels-allowlist.txt is
# still kept in sync with the manifest by that workflow's own diff check.

# --- Copy bundle files ---
cp "$REPO_ROOT/endpoint/patched-update.sh" "$DIST_BUNDLE/patched-update.sh"
chmod 755 "$DIST_BUNDLE/patched-update.sh"

cp "$REPO_ROOT/endpoint/patched-fetch-config.sh" "$DIST_BUNDLE/patched-fetch-config.sh"
chmod 755 "$DIST_BUNDLE/patched-fetch-config.sh"

cp "$REPO_ROOT/endpoint/patched-enroll.sh" "$DIST_BUNDLE/patched-enroll.sh"
chmod 755 "$DIST_BUNDLE/patched-enroll.sh"

cp "$REPO_ROOT/endpoint/patched-log-upload.sh" "$DIST_BUNDLE/patched-log-upload.sh"
chmod 755 "$DIST_BUNDLE/patched-log-upload.sh"

cp "$REPO_ROOT/endpoint/verify-agent-config.py" "$DIST_BUNDLE/verify-agent-config.py"
chmod 755 "$DIST_BUNDLE/verify-agent-config.py"
cp "$REPO_ROOT/endpoint/agent_update_channel.py" "$DIST_BUNDLE/agent_update_channel.py"
chmod 755 "$DIST_BUNDLE/agent_update_channel.py"

# PAT-1763: the one agent-config anti-rollback floor parser. The verifier,
# patched-fetch-config.sh and patched-enroll.sh all load it from this
# directory, so its bytes sit under the same manifest as theirs.
cp "$REPO_ROOT/endpoint/agent_config_floor.py" "$DIST_BUNDLE/agent_config_floor.py"
chmod 755 "$DIST_BUNDLE/agent_config_floor.py"

# PAT-1773: the one check that the cached agent-config belongs to the enrolled
# tenant. The legacy execution gate loads it in-process and the daemon's config
# readers run it, so its bytes sit under the same manifest as theirs.
cp "$REPO_ROOT/endpoint/agent_config_tenant.py" "$DIST_BUNDLE/agent_config_tenant.py"
chmod 755 "$DIST_BUNDLE/agent_config_tenant.py"

# PAT-1481: patched-update.sh retains dormant legacy execution call sites and
# therefore retains their fail-closed authority evaluator. Its bytes must be
# inside the same signed manifest trust anchor as every root caller. The
# assurance-only bundle still ships no engine, allowlist or actuation daemon.
cp "$REPO_ROOT/endpoint/patched-legacy-app-execution-gate.py" "$DIST_BUNDLE/patched-legacy-app-execution-gate.py"
chmod 755 "$DIST_BUNDLE/patched-legacy-app-execution-gate.py"

# PAT-1116: the sole posture-cache writer verifies the signed envelope before
# committing the decoded body consumed by desktop and root-side readers.
cp "$REPO_ROOT/endpoint/patched-fetch-posture.sh" "$DIST_BUNDLE/patched-fetch-posture.sh"
chmod 755 "$DIST_BUNDLE/patched-fetch-posture.sh"

cp "$REPO_ROOT/endpoint/verify-posture.py" "$DIST_BUNDLE/verify-posture.py"
chmod 755 "$DIST_BUNDLE/verify-posture.py"

cp "$REPO_ROOT/endpoint/validate-posture.py" "$DIST_BUNDLE/validate-posture.py"
chmod 755 "$DIST_BUNDLE/validate-posture.py"

cp "$REPO_ROOT/endpoint/patched-proxy-resolve.py" "$DIST_BUNDLE/patched-proxy-resolve.py"
chmod 755 "$DIST_BUNDLE/patched-proxy-resolve.py"

# PAT-1505: Installomator.sh, labels-allowlist.txt, LICENSE and NOTICE are NOT
# copied. See the header for the reasoning, including why dropping Apache 2.0's
# LICENSE/NOTICE is correct once the covered work is no longer distributed.

# --- LaunchDaemon plists (under integrity scope so both install.sh and
#     the daemon's verify_bundle cover them at install and runtime) ---
cp "$REPO_ROOT/endpoint/com.patched.update.plist" "$DIST_BUNDLE/com.patched.update.plist"
chmod 644 "$DIST_BUNDLE/com.patched.update.plist"

cp "$REPO_ROOT/endpoint/com.patched.config-poll.plist" "$DIST_BUNDLE/com.patched.config-poll.plist"
chmod 644 "$DIST_BUNDLE/com.patched.config-poll.plist"

# PAT-1505: the actuation LaunchDaemons are NOT copied, and each is
# excluded together with the engine script it targets — a plist without its
# target is a daemon that bootstraps to a missing path, which is a broken
# install, not a narrower one:
#   com.patched.uninstall-check.plist -> patched-uninstall.sh    (was PAT-376)
#   com.patched.install-check.plist   -> patched-install.sh      (was PAT-661)
# endpoint/install.sh's LAUNCHDAEMONS array drops them, and its PAT-1505 purge
# step boots out and removes any copy left behind by a bundle installed before
# this change, together with the retired PAT-2245 catalogue poller.

cp "$REPO_ROOT/endpoint/com.patched.posture-poll.plist" "$DIST_BUNDLE/com.patched.posture-poll.plist"
chmod 644 "$DIST_BUNDLE/com.patched.posture-poll.plist"

# PAT-1109: agent-decommission orchestrator + its (dormant — never in
# install.sh's LAUNCHDAEMONS array) LaunchDaemon template, plus
# byte-identical, flat-renamed copies of BOTH uninstall.sh scripts. Reused
# (not reinvented) by patched-decommission.sh: it stages these two copies
# into DECOMM_DIR before running them, so the detached removal survives
# either uninstall.sh deleting its own source bundle directory mid-run.
# Renamed to avoid a same-directory filename collision (both source files
# are called uninstall.sh).
cp "$REPO_ROOT/endpoint/patched-decommission.sh" "$DIST_BUNDLE/patched-decommission.sh"
chmod 755 "$DIST_BUNDLE/patched-decommission.sh"

cp "$REPO_ROOT/endpoint/com.patched.decommission.plist" "$DIST_BUNDLE/com.patched.decommission.plist"
chmod 644 "$DIST_BUNDLE/com.patched.decommission.plist"

cp "$REPO_ROOT/endpoint/uninstall.sh" "$DIST_BUNDLE/endpoint-uninstall.sh"
chmod 755 "$DIST_BUNDLE/endpoint-uninstall.sh"

cp "$REPO_ROOT/macos/uninstall.sh" "$DIST_BUNDLE/macos-uninstall.sh"
chmod 755 "$DIST_BUNDLE/macos-uninstall.sh"

# --- Generate manifest.sha256 ---
# Deterministic order; relative filenames; single-space separator so that
# patched-update.sh's parser (want="${line%% *}" rel="${line##* }") works cleanly.
#
# NOTE (PAT-687): patched-update.sh is deliberately NOT listed here. The daemon
# carries the pinned hash of THIS manifest (EXPECTED_MANIFEST_HASH), so it cannot
# also hash itself without a circular dependency. install.sh instead verifies the
# daemon separately against EXPECTED_DAEMON_HASH before copying it into place.
echo ""
echo "--- Generating manifest.sha256 ---"
(
    cd "$DIST_BUNDLE"
    shasum -a 256 \
        patched-fetch-config.sh \
        patched-fetch-posture.sh \
        patched-proxy-resolve.py \
        patched-enroll.sh \
        patched-log-upload.sh \
        verify-agent-config.py \
        agent_update_channel.py \
        agent_config_floor.py \
        agent_config_tenant.py \
        patched-legacy-app-execution-gate.py \
        verify-posture.py \
        validate-posture.py \
        com.patched.update.plist \
        com.patched.config-poll.plist \
        com.patched.posture-poll.plist \
        patched-decommission.sh \
        com.patched.decommission.plist \
        endpoint-uninstall.sh \
        macos-uninstall.sh \
        | sed 's/  / /' > manifest.sha256
)
echo "manifest.sha256:"
sed 's/^/  /' "$DIST_BUNDLE/manifest.sha256"

# --- Manifest completeness gate (PAT-1505) ---
# The manifest above is a hand-maintained list, and both trust anchors are
# derived from it: install.sh gates the whole install on sha256(manifest), and
# the daemon's verify_bundle() only ever checks the files the manifest names. So
# a file that ships without a manifest entry is the worst failure mode available
# here, because it does not fail closed. Nothing would ever notice it being
# swapped: it rides along in the release tarball unverified by either anchor,
# and while install.sh's copy loop is manifest-driven and would not place it in
# /usr/local/patched-updater, "not in the manifest" is precisely the state that
# makes an extra file invisible to every check in the chain.
#
# Removing entries from the list above (which is what PAT-1505 did) is exactly
# the edit that can leave the two out of step, in either direction:
#   - a manifest entry with no file  -> shasum fails, build breaks loudly (fine)
#   - a file with no manifest entry  -> silent, and unverified forever (not fine)
# So assert the bundle directory and the manifest describe each other exactly.
# The only two legitimate extras are manifest.sha256 itself and patched-update.sh
# (the daemon carries the manifest pin, so it cannot hash itself — install.sh
# anchors it separately against EXPECTED_DAEMON_HASH).
(
    cd "$DIST_BUNDLE"
    listed=$(awk '{print $NF}' manifest.sha256 | sort)
    present=$(ls -A | grep -v -x -e manifest.sha256 -e patched-update.sh | sort)
    if [[ "$listed" != "$present" ]]; then
        echo "ERROR: manifest.sha256 does not describe the bundle exactly." >&2
        echo "  Only in manifest (ghost entries):" >&2
        comm -23 <(printf '%s\n' "$listed") <(printf '%s\n' "$present") | sed 's/^/    /' >&2
        echo "  Only in bundle (shipped but unverified):" >&2
        comm -13 <(printf '%s\n' "$listed") <(printf '%s\n' "$present") | sed 's/^/    /' >&2
        exit 1
    fi
    echo "manifest covers every shipped file (plus manifest.sha256 + the separately-anchored daemon)."
)

# --- Compute pins and stamp them in ---
# MANIFEST_HASH is the v1 trust anchor (install.sh) AND the runtime pin baked
# into the daemon (patched-update.sh). DAEMON_HASH anchors the daemon itself,
# which is not in the manifest.
MANIFEST_HASH=$(shasum -a 256 "$DIST_BUNDLE/manifest.sha256" | awk '{print $1}')
echo ""
echo "manifest.sha256 hash (v1 trust anchor + daemon pin): $MANIFEST_HASH"

# Pin the manifest hash INTO the runtime daemon, then hash the stamped daemon.
# Anchor to the assignment line ONLY: the daemon also contains the literal
# "__MANIFEST_HASH__" in its dev-build skip check, which must stay intact so the
# pin check is skipped only in unstamped source checkouts, never in a release.
sed -i.bak "s|^EXPECTED_MANIFEST_HASH=\"__MANIFEST_HASH__\"|EXPECTED_MANIFEST_HASH=\"$MANIFEST_HASH\"|" "$DIST_BUNDLE/patched-update.sh"
rm -f "$DIST_BUNDLE/patched-update.sh.bak"
chmod 755 "$DIST_BUNDLE/patched-update.sh"

DAEMON_HASH=$(shasum -a 256 "$DIST_BUNDLE/patched-update.sh" | awk '{print $1}')
echo "patched-update.sh hash (daemon trust anchor):        $DAEMON_HASH"

# Stamp both anchors into install.sh.
sed -e "s/__MANIFEST_HASH__/$MANIFEST_HASH/" \
    -e "s/__DAEMON_HASH__/$DAEMON_HASH/" \
    "$REPO_ROOT/endpoint/install.sh" > "$DIST/install.sh"
chmod 755 "$DIST/install.sh"

cp "$REPO_ROOT/endpoint/uninstall.sh" "$DIST/uninstall.sh"
chmod 755 "$DIST/uninstall.sh"

# --- enrollment.json stamp-point (PAT-546) ---
# Ships alongside install.sh (NOT inside the bundle, NOT in manifest.sha256).
# The patched.im download service substitutes the null token value at download
# time for the email-link delivery path; install.sh auto-detects it.
# Excluding it from the manifest means stamping does not invalidate bundle
# integrity — only the bundle scripts are under the hash manifest.
cat > "$DIST/enrollment.json" <<'ENROLL_EOF'
{"enrollment_token": null}
ENROLL_EOF
chmod 644 "$DIST/enrollment.json"

echo ""
echo "=== Build complete ==="
echo "  Bundle:          $DIST_BUNDLE/"
echo "  install.sh:      $DIST/install.sh  (manifest hash stamped)"
echo "  uninstall.sh:    $DIST/uninstall.sh"
echo "  enrollment.json: $DIST/enrollment.json  (stamp-point placeholder)"
