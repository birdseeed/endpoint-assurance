#!/bin/zsh
##############################################################################
# test-enroll-credential-write.zsh — focused test for patched-enroll.sh's
# credential-write failure path (PAT-1026, PAT-1781).
#
# endpoint/ has no general enrol test harness — patched-enroll.sh has no
# existing test-*.zsh counterpart, and this file deliberately does not try to
# become one. It does not exercise the full happy path: landing all four
# credential files requires actually chowning them to root:wheel, which is
# not achievable in an unprivileged test sandbox. Instead it forces exactly
# one write-block failure and asserts the script leaves an honest suspended
# state rather than a false "Enrolled" or a retry with a token HTTP 200 already
# consumed. It also proves a failure before any 200 retains the token.
#
# The forcing mechanism is not synthetic: run unprivileged (as any CI/dev
# user, never as root), `chown root:wheel` on the .tmp credential files
# always fails with EPERM. That is exactly the class of mid-block failure
# the fix guards against, so this test needs no fault injection beyond
# "don't run as root" — which is how this test always runs.
#
# PAT-1756 adds the agent-config anti-rollback floor to both paths. A failed
# credential write must leave the floor untouched. A successful enrolment must
# remove it; that path runs against a scratch copy of patched-enroll.sh whose
# PATH prelude puts a stub `chown` first (the only step an unprivileged user
# cannot perform), the same technique test-device-id-header-wordsplit.zsh
# uses. Nothing else in the copy is changed. PAT-1763: every run points
# PATCHED_BUNDLE_DIR at this directory, so the floor is classified by the
# agent_config_floor.py under test rather than an installed bundle's copy.
##############################################################################

set -u
export PATCHED_API_URL="http://127.0.0.1:1"

SCRIPT_DIR="${0:A:h}"
TARGET="$SCRIPT_DIR/patched-enroll.sh"
PYTHON3="/usr/bin/python3"

pass=0; fail=0

chk_eq() {
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then
        (( pass++ )); echo "  PASS: $desc -> $got"
    else
        (( fail++ )); echo "  FAIL: $desc"
        echo "        expected: $exp"
        echo "        got:      $got"
    fi
}

chk_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc"
        echo "        needle:   $needle"
        echo "        haystack: ${haystack:0:400}"
    fi
}

chk_not_contains() {
    local desc="$1" needle="$2" haystack="$3"
    if [[ "$haystack" != *"$needle"* ]]; then
        (( pass++ )); echo "  PASS: $desc"
    else
        (( fail++ )); echo "  FAIL: $desc — should NOT contain: $needle"
        echo "        haystack: ${haystack:0:400}"
    fi
}

if [[ "$(id -u)" == "0" ]]; then
    echo "SKIP: this test relies on 'chown root:wheel' failing with EPERM for an"
    echo "      unprivileged user; running as root would make the write succeed"
    echo "      and defeat the point of the test. Skipping."
    echo "RESULT: pass=0 fail=0"
    exit 0
fi

CREDS_DIR=$(mktemp -d /tmp/.test-enroll-creds.XXXXXX)
STATE_DIR=$(mktemp -d /tmp/.test-enroll-state.XXXXXX)
STUB_WORK=$(mktemp -d /tmp/.test-enroll-stub.XXXXXX)
server_pid=""
cleanup() {
    [[ -n "$server_pid" ]] && kill "$server_pid" 2>/dev/null
    rm -rf "$CREDS_DIR" "$STATE_DIR" "$STUB_WORK"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Minimal local HTTP server standing in for POST /v1/enrol. Picks its own
# ephemeral port and reports it back via a temp file so the test can point
# PATCHED_API_URL at it. Serves a bounded number of requests, then exits —
# no orphan process left behind even if the test aborts before the trap runs.
# ---------------------------------------------------------------------------
port_file=$(mktemp /tmp/.test-enroll-port.XXXXXX)
"$PYTHON3" - "$port_file" <<'PYEOF' &
import http.server, json, sys

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass  # keep test output clean

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        self.rfile.read(length)
        body = json.dumps({
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "bearer_token": "test-bearer-token-value",
            "hmac_secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "device_id": "c2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[1], "w") as f:
    f.write(str(srv.server_port))
srv.timeout = 30
for _ in range(40):
    srv.handle_request()
PYEOF
server_pid=$!

# Bounded poll for the server to publish its port — no fixed sleep.
port=""
for _ in $(seq 1 50); do
    if [[ -s "$port_file" ]]; then
        port=$(cat "$port_file")
        break
    fi
    sleep 0.1
done
rm -f "$port_file"

if [[ -z "$port" ]]; then
    echo "FAIL: local /v1/enrol stub server did not start"
    (( fail++ ))
    echo "RESULT: pass=${pass} fail=${fail}"
    exit 1
fi

API_URL="http://127.0.0.1:${port}"

# ============================================================================
# Pre-200 network failure — no server accepted the token, so it remains live.
# ============================================================================
echo "\n--- Pre-200 network failure retains the enrollment token ---"

printf 'test-enrollment-token\n' > "$CREDS_DIR/enrollment-token"
rm -f "$CREDS_DIR/enrollment-token.rejected" "$CREDS_DIR/suspended"
out=$(PATCHED_BUNDLE_DIR="$SCRIPT_DIR" PATCHED_CREDS_DIR="$CREDS_DIR" PATCHED_STATE_DIR="$STATE_DIR" PATCHED_API_URL="http://127.0.0.1:1" zsh "$TARGET" 2>&1)
rc=$?

chk_eq "pre-200 network failure exits 0 for retry" "0" "$rc"
chk_contains "pre-200 network failure is reported as transient" "transient error (HTTP 000)" "$out"
chk_eq "pre-200 network failure retains the canonical token" "1" "$([ -f "$CREDS_DIR/enrollment-token" ] && echo 1 || echo 0)"
chk_eq "pre-200 network failure does not create a spent-token file" "0" "$([ -f "$CREDS_DIR/enrollment-token.rejected" ] && echo 1 || echo 0)"
chk_eq "pre-200 network failure does not suspend" "0" "$([ -f "$CREDS_DIR/suspended" ] && echo 1 || echo 0)"

# ============================================================================
# Forced credential-write failure — chown root:wheel on the .tmp files fails
# (EPERM, unprivileged test user) partway through the write block.
# ============================================================================
echo "\n--- Post-200 credential-write failure retires the spent token ---"

printf 'test-enrollment-token\n' > "$CREDS_DIR/enrollment-token"
FLOOR_FIXTURE='{"tenant_id":"previous-tenant","config_version":12}'
printf '%s' "$FLOOR_FIXTURE" > "$STATE_DIR/agent-config.version"

out=$(PATCHED_BUNDLE_DIR="$SCRIPT_DIR" PATCHED_CREDS_DIR="$CREDS_DIR" PATCHED_STATE_DIR="$STATE_DIR" PATCHED_API_URL="$API_URL" zsh "$TARGET" 2>&1)
rc=$?

chk_eq "exit code is 1 (HTTP 200 consumed the token)" "1" "$rc"
chk_contains "reports the persist failure" "failed to persist" "$out"
chk_contains "reports that the consumed token cannot be retried" "consumed enrollment token cannot be retried" "$out"
chk_not_contains "never claims Enrolled on a partial write" "Enrolled: tenant" "$out"

chk_eq "canonical enrollment-token retired" "0" "$([ -f "$CREDS_DIR/enrollment-token" ] && echo 1 || echo 0)"
chk_eq "consumed enrollment-token moved to the spent-token path" "1" "$([ -f "$CREDS_DIR/enrollment-token.rejected" ] && echo 1 || echo 0)"
chk_eq "post-200 write failure enters suspended state" "1" "$([ -f "$CREDS_DIR/suspended" ] && echo 1 || echo 0)"
chk_eq "tenant-id NOT created (chown failed before any mv)"    "0" "$([ -f "$CREDS_DIR/tenant-id" ]    && echo 1 || echo 0)"
chk_eq "bearer-token NOT created"                                "0" "$([ -f "$CREDS_DIR/bearer-token" ] && echo 1 || echo 0)"
chk_eq "hmac-secret NOT created"                                 "0" "$([ -f "$CREDS_DIR/hmac-secret" ]  && echo 1 || echo 0)"
chk_eq "device-id NOT created"                                   "0" "$([ -f "$CREDS_DIR/device-id" ]    && echo 1 || echo 0)"
chk_eq "no leftover tenant-id.tmp"    "0" "$([ -f "$CREDS_DIR/tenant-id.tmp" ]    && echo 1 || echo 0)"
chk_eq "no leftover bearer-token.tmp" "0" "$([ -f "$CREDS_DIR/bearer-token.tmp" ] && echo 1 || echo 0)"
chk_eq "no leftover hmac-secret.tmp"  "0" "$([ -f "$CREDS_DIR/hmac-secret.tmp" ]  && echo 1 || echo 0)"
chk_eq "no leftover device-id.tmp"    "0" "$([ -f "$CREDS_DIR/device-id.tmp" ]    && echo 1 || echo 0)"
chk_eq "PAT-1756: anti-rollback floor untouched when the credential write fails" \
    "$FLOOR_FIXTURE" "$(cat "$STATE_DIR/agent-config.version" 2>/dev/null)"
chk_not_contains "PAT-1756: no floor reset is claimed on a failed write" "floor reset" "$out"

# ============================================================================
# PAT-1756: successful enrolment resets the agent-config anti-rollback floor.
# The WIN-STAGING shape on macOS: a legacy bare integer left by the previous
# tenant, then enrolment into a new tenant.
# ============================================================================
echo "\n--- Successful enrolment removes the anti-rollback floor ---"

STUB_BIN="$STUB_WORK/bin"
mkdir -p "$STUB_BIN"
printf '#!/bin/sh\nexit 0\n' > "$STUB_BIN/chown"
chmod +x "$STUB_BIN/chown"
COPY="$STUB_WORK/patched-enroll.sh"
/usr/bin/python3 "$SCRIPT_DIR/../ci/privileged_script_fixture.py" "$TARGET" "$COPY" "$STUB_BIN" || exit 1

rm -f "$CREDS_DIR"/tenant-id "$CREDS_DIR"/bearer-token "$CREDS_DIR"/hmac-secret "$CREDS_DIR"/device-id \
    "$CREDS_DIR"/enrollment-token.rejected "$CREDS_DIR"/suspended
printf 'test-enrollment-token\n' > "$CREDS_DIR/enrollment-token"
printf '12' > "$STATE_DIR/agent-config.version"

out=$(PATCHED_BUNDLE_DIR="$SCRIPT_DIR" PATCHED_CREDS_DIR="$CREDS_DIR" PATCHED_STATE_DIR="$STATE_DIR" PATCHED_API_URL="$API_URL" zsh "$COPY" 2>&1)
rc=$?

chk_eq "exit code is 0" "0" "$rc"
chk_contains "reports enrolment" "Enrolled: tenant 00000000-0000-0000-0000-000000000001" "$out"
chk_eq "credentials landed (bearer-token present)" "1" "$([ -f "$CREDS_DIR/bearer-token" ] && echo 1 || echo 0)"
chk_eq "enrollment-token consumed" "0" "$([ -f "$CREDS_DIR/enrollment-token" ] && echo 1 || echo 0)"
chk_eq "PAT-1756: anti-rollback floor removed after a successful enrolment" \
    "0" "$([ -e "$STATE_DIR/agent-config.version" ] && echo 1 || echo 0)"
chk_contains "PAT-1756: the removal is logged with the kind and the enrolled tenant" \
    "anti-rollback floor removed (legacy) for enrolled tenant 00000000-0000-0000-0000-000000000001" "$out"

# enrol_with_floor <floor-content|MISSING>: fresh enrolment against the stub
# server (tenant 00000000-0000-0000-0000-000000000001) with the given floor.
ENROLLED_TENANT="00000000-0000-0000-0000-000000000001"
enrol_with_floor() {
    rm -f "$CREDS_DIR"/tenant-id "$CREDS_DIR"/bearer-token "$CREDS_DIR"/hmac-secret "$CREDS_DIR"/device-id
    printf 'test-enrollment-token\n' > "$CREDS_DIR/enrollment-token"
    rm -f "$STATE_DIR/agent-config.version"
    [[ "$1" == MISSING ]] || printf '%s' "$1" > "$STATE_DIR/agent-config.version"
    out=$(PATCHED_BUNDLE_DIR="$SCRIPT_DIR" PATCHED_CREDS_DIR="$CREDS_DIR" PATCHED_STATE_DIR="$STATE_DIR" PATCHED_API_URL="$API_URL" zsh "$COPY" 2>&1)
    rc=$?
}

echo "\n--- Same-tenant re-enrolment keeps the keyed floor ---"
SAME_FLOOR='{"tenant_id":"'"$ENROLLED_TENANT"'","config_version":12}'
enrol_with_floor "$SAME_FLOOR"
chk_eq "exit code is 0" "0" "$rc"
chk_contains "enrolled" "Enrolled: tenant $ENROLLED_TENANT" "$out"
chk_eq "PAT-1756: a floor keyed to the enrolled tenant is kept byte for byte" \
    "$SAME_FLOOR" "$(cat "$STATE_DIR/agent-config.version" 2>/dev/null)"
chk_contains "PAT-1756: keeping the floor is logged" "floor kept; it already belongs to enrolled tenant $ENROLLED_TENANT" "$out"
same_verify=$("$PYTHON3" -c '
import importlib.util, sys
spec = importlib.util.spec_from_file_location("vac", sys.argv[1])
vac = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vac)
print(vac._rollback_floor_for_tenant(vac._read_rollback_floor(sys.argv[2]), sys.argv[3])[0])
' "$SCRIPT_DIR/verify-agent-config.py" "$STATE_DIR/agent-config.version" "$ENROLLED_TENANT")
chk_eq "PAT-1756: the verifier still reads floor 12 for the enrolled tenant, so anything lower is rejected" "12" "$same_verify"

echo "\n--- Other-tenant, corrupt and legacy floors are removed ---"
removable_floors=(
    '{"tenant_id":"previous-tenant","config_version":12}'
    'not a floor'
    '{"tenant_id":"'"$ENROLLED_TENANT"'","config_version":"12"}'
    '7'
    '{"tenant_id":"previous-tenant","tenant_id":"'"$ENROLLED_TENANT"'","config_version":12}'
    '{"tenant_id":"'"$ENROLLED_TENANT"'","config_version":12,"config_version":1}'
    '{"Tenant_ID":"x","tenant_id":"'"$ENROLLED_TENANT"'","config_version":12}'
    '{"tenant_id":"'"$ENROLLED_TENANT"'","config_version":12.0}'
    '{"tenant_id":"'"$ENROLLED_TENANT"'","config_version":true}'
    '{"tenant_id":["'"$ENROLLED_TENANT"'"],"config_version":12}'
    '{"tenant_id":7,"config_version":12}'
)
removable_kinds=(other_tenant corrupt corrupt legacy corrupt corrupt corrupt corrupt corrupt corrupt corrupt)
for i in {1..${#removable_floors}}; do
    removable="${removable_floors[$i]}"
    enrol_with_floor "$removable"
    chk_eq "exit code is 0 for floor '$removable'" "0" "$rc"
    chk_eq "PAT-1756: floor '$removable' removed" "0" "$([ -e "$STATE_DIR/agent-config.version" ] && echo 1 || echo 0)"
    chk_contains "PAT-1756: floor '$removable' classified as ${removable_kinds[$i]}" "floor removed (${removable_kinds[$i]})" "$out"
done

echo "\n--- A floor reader that crashes or answers unexpectedly keeps the floor ---"
for reader_mode in crash garbage; do
    reader_stub="$STUB_BIN/python3-floor-$reader_mode"
    if [[ "$reader_mode" == crash ]]; then
        printf '#!/bin/zsh\ncase "$1:$2" in *agent_config_floor.py:enrol-state) exit 70 ;; esac\nexec /usr/bin/python3 "$@"\n' > "$reader_stub"
    else
        printf '#!/bin/zsh\ncase "$1:$2" in *agent_config_floor.py:enrol-state) print "applies 9"; exit 0 ;; esac\nexec /usr/bin/python3 "$@"\n' > "$reader_stub"
    fi
    chmod +x "$reader_stub"
    READER_COPY="$STUB_WORK/patched-enroll-$reader_mode.sh"
    sed -e 's#^PYTHON3="/usr/bin/python3"$#PYTHON3="'"$reader_stub"'"#' "$COPY" > "$READER_COPY"
    if ! grep -q '^PYTHON3="'"$reader_stub"'"$' "$READER_COPY"; then
        echo "FATAL: PYTHON3 rewrite did not match in $TARGET"
        exit 1
    fi
    rm -f "$CREDS_DIR"/tenant-id "$CREDS_DIR"/bearer-token "$CREDS_DIR"/hmac-secret "$CREDS_DIR"/device-id
    printf 'test-enrollment-token\n' > "$CREDS_DIR/enrollment-token"
    printf '7' > "$STATE_DIR/agent-config.version"   # removable if it were classified
    out=$(PATCHED_BUNDLE_DIR="$SCRIPT_DIR" PATCHED_CREDS_DIR="$CREDS_DIR" PATCHED_STATE_DIR="$STATE_DIR" PATCHED_API_URL="$API_URL" zsh "$READER_COPY" 2>&1)
    rc=$?
    chk_contains "reader $reader_mode: enrolment still completes" "Enrolled: tenant $ENROLLED_TENANT" "$out"
    chk_eq "PAT-1756: reader $reader_mode: floor kept" "7" "$(cat "$STATE_DIR/agent-config.version" 2>/dev/null)"
    if [[ "$reader_mode" == crash ]]; then
        chk_contains "PAT-1756: reader crash logged with its exit code" "the floor reader failed (exit 70), so it is not removed" "$out"
    else
        chk_contains "PAT-1756: unexpected reader output logged" "the floor reader returned an unexpected result (applies 9), so it is not removed" "$out"
    fi
done
rm -f "$STATE_DIR/agent-config.version"

echo "\n--- A floor that cannot be read is kept ---"
rm -f "$CREDS_DIR"/tenant-id "$CREDS_DIR"/bearer-token "$CREDS_DIR"/hmac-secret "$CREDS_DIR"/device-id
printf 'test-enrollment-token\n' > "$CREDS_DIR/enrollment-token"
mkdir -p "$STATE_DIR/agent-config.version"   # opening a directory as a file fails: unreadable
out=$(PATCHED_BUNDLE_DIR="$SCRIPT_DIR" PATCHED_CREDS_DIR="$CREDS_DIR" PATCHED_STATE_DIR="$STATE_DIR" PATCHED_API_URL="$API_URL" zsh "$COPY" 2>&1)
rc=$?
chk_eq "exit code is 0" "0" "$rc"
chk_eq "PAT-1756: an unreadable floor is not removed" "1" "$([ -e "$STATE_DIR/agent-config.version" ] && echo 1 || echo 0)"
chk_contains "PAT-1756: keeping the unreadable floor is logged as an error" "it could not be read (IsADirectoryError), so it is not removed" "$out"
rmdir "$STATE_DIR/agent-config.version"

echo "\n--- No floor on disk ---"
enrol_with_floor MISSING
chk_eq "exit code is 0" "0" "$rc"
chk_contains "PAT-1756: absence is logged" "no agent-config anti-rollback floor on disk" "$out"

echo "\n--- PAT-1763: enrolment never clears the execution-denial marker ---"
MARKER='{"tenant_id":"previous-tenant","config_version":50,"legacy_app_execution_revoked_at":50}'
printf '%s' "$MARKER" > "$STATE_DIR/agent-config.execution-denied"
enrol_with_floor '{"tenant_id":"previous-tenant","config_version":50}'
chk_contains "enrolled into the new tenant" "Enrolled: tenant $ENROLLED_TENANT" "$out"
chk_eq "PAT-1763: the other tenant's execution-denial marker is left for the first verified commit" \
    "$MARKER" "$(cat "$STATE_DIR/agent-config.execution-denied" 2>/dev/null)"
rm -f "$STATE_DIR/agent-config.execution-denied"

echo "\n--- PAT-1763: a missing floor parser keeps the floor ---"
rm -f "$CREDS_DIR"/tenant-id "$CREDS_DIR"/bearer-token "$CREDS_DIR"/hmac-secret "$CREDS_DIR"/device-id
printf 'test-enrollment-token\n' > "$CREDS_DIR/enrollment-token"
printf '7' > "$STATE_DIR/agent-config.version"
out=$(PATCHED_BUNDLE_DIR="$STUB_WORK/no-such-bundle" PATCHED_CREDS_DIR="$CREDS_DIR" PATCHED_STATE_DIR="$STATE_DIR" PATCHED_API_URL="$API_URL" zsh "$COPY" 2>&1)
rc=$?
chk_eq "exit code is 0" "0" "$rc"
chk_contains "enrolment still completes" "Enrolled: tenant $ENROLLED_TENANT" "$out"
chk_eq "PAT-1763: floor kept when agent_config_floor.py is missing" "7" "$(cat "$STATE_DIR/agent-config.version" 2>/dev/null)"
chk_contains "PAT-1763: the missing reader is logged as a reader failure" "the floor reader failed (exit" "$out"
rm -f "$STATE_DIR/agent-config.version"

# ============================================================================
# Summary
# ============================================================================
echo ""
echo "RESULT: pass=${pass} fail=${fail}"
[[ $fail -eq 0 ]]
