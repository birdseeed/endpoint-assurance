#!/bin/zsh
##############################################################################
# test-certs.zsh — unit tests for the System keychain certificate collector
# (collect_certs) in certs.sh (PAT-1696, PAT-1709, PAT-1732, PAT-1735,
# PAT-1740).
#
# Sources the live function out of certs.sh (no top-level side effects at
# source time) so the tests exercise the real code, not a copy. Boundaries:
#
#   /usr/bin/security  shadowed with a zsh function of the same name. zsh
#                      resolves a function before an external command even
#                      when the command word is an absolute path, so
#                      `security find-certificate -a -p ...` hits the fixture
#                      instead of the runner's real System keychain.
#   date               shadowed for `date -u +%s` only (pins "now" to
#                      2030-01-01T00:00:00Z so days_until_expiry is stable);
#                      every other date call goes to the real binary.
#   /usr/bin/openssl   NOT shadowed by default: the stock binary parses the
#   /usr/bin/od        fixture PEMs and od hex-dumps the DER, because that is
#                      what the collector depends on. Section 6 logs every
#                      openssl call, then shadows od, replaying the real hex
#                      with bytes removed, added or wrapped, or failing. The
#                      walk reads DER bytes, not any openssl text rendering, so
#                      there is no LibreSSL / OpenSSL output shape to replay.
#
# The fixture certificates below are public, self-signed, keyless test certs
# generated for this file only (private keys discarded at generation time).
# The PAT-1735 fixtures were made with OpenSSL 3.6.3 `req -x509` and one
# config-driven extension each; "Duplicate BC" had a 2.5.29.99 extension OID
# byte-patched to 2.5.29.19 and was re-signed, so its signature still verifies.
#
# KNOWN-GAP checks record current behaviour that breaks the "absent evidence
# is never a pass" rule. They pass today and FAIL LOUDLY if the behaviour
# changes, so a fix must update the assertion in the same change. Run:
#   zsh macos/lib/test-certs.zsh
# CERTS_SH_UNDER_TEST=<path> runs the same tests against another certs.sh.
# COLLECT_SH_UNDER_TEST=<path> reads the payload heredoc from another
# patched-collect.sh.
##############################################################################

set -u
SCRIPT_DIR="${0:A:h}"
PYTHON3="/usr/bin/python3"

source "$SCRIPT_DIR/common.sh"
source "${CERTS_SH_UNDER_TEST:-$SCRIPT_DIR/certs.sh}"
# PAT-1974: the shared payload heredoc this file evaluates via COLLECT_SH now
# calls local_admins_payload() too. Without this, $(local_admins_payload)
# resolves to nothing (command not found on stderr, empty stdout), leaving
# `"local_admins": ,` in the heredoc output -- invalid JSON that fails every
# downstream field assertion in this file with JSON_ERROR, including ones
# about certificates that have nothing to do with local admins.
source "$SCRIPT_DIR/auth.sh"

pass=0; fail=0; gaps=0
chk_eq() {  # chk_eq <desc> <expected> <actual>
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); echo "  PASS: $desc"
    else (( fail++ )); echo "  FAIL: $desc -> got=$got want=$exp"; fi
}
# chk_known_gap <desc> <current-behaviour> <actual>
chk_known_gap() {
    local desc="$1" exp="$2" got="$3"
    if [[ "$got" == "$exp" ]]; then (( pass++ )); (( gaps++ )); echo "  KNOWN-GAP: $desc"
    else (( fail++ )); echo "  FAIL: KNOWN-GAP behaviour changed, update this assertion: $desc -> got=$got was=$exp"; fi
}

# json_eval <json-file> <python-expr over d> -> printed result
json_eval() {
    "$PYTHON3" -c "
import json, sys
d = json.load(open(sys.argv[1]))
print($2)
" "$1" 2>/dev/null || echo "JSON_ERROR"
}

# payload_eval <python-expr over d>: renders the tail of the REAL payload
# heredoc in patched-collect.sh (from "apps" to "browser_extensions", which
# holds the certificates and collection_status members) with the collector's
# current state, closes the object and evaluates the expression over it. A
# comma or quoting mistake in either member makes every payload check read
# JSON_ERROR. The sections around the certificate members are stubbed.
COLLECT_SH="${COLLECT_SH_UNDER_TEST:-$SCRIPT_DIR/../patched-collect.sh}"
PAYLOAD_TAIL=$(sed -n '/^  "apps": \$(apps_payload_array),$/,/^  "browser_extensions": /p' "$COLLECT_SH" 2>/dev/null)
if [[ "$PAYLOAD_TAIL" != *'$(certs_payload_member)'* \
      || "$PAYLOAD_TAIL" != *'"collection_status": {"certificates": $(json_escape "$(certs_collection_status)"), "apps": $(json_escape "$(apps_collection_status)"), "apps_users": $(apps_users_collection_status), "safari_extensions": $(json_escape "$(safari_extensions_collection_status)")},'* \
      || "$PAYLOAD_TAIL" != *'"browser_extensions": '* ]]; then
    echo "FAIL: could not find the certificate members of the payload heredoc in $COLLECT_SH"
    exit 1
fi
payload_eval() {
    local obj="$PATCHED_TMPDIR/payload.json"
    local APPS_JSON_FILE="$PATCHED_TMPDIR/apps-stub.json"
    local HARDWARE_HEALTH_JSON_TMP="$PATCHED_TMPDIR/hw-stub.json"
    local BROWSER_EXTENSIONS_JSON_FILE="$PATCHED_TMPDIR/be-stub.json"
    # PAT-2065 added browser_extensions_status just above browser_extensions.
    browser_extensions_status_payload() { printf '{"collection_status":"failed"}'; }
    # PAT-2066: apps and collection_status.apps come from apps.sh, covered by
    # test-apps.zsh; stubbed here as an unfinished apps collection.
    apps_payload_array() { printf '[]'; }
    apps_collection_status() { printf 'unavailable'; }
    # PAT-2075: collection_status.apps_users also comes from apps.sh; no
    # user scope was read by an unfinished apps collection.
    apps_users_collection_status() { printf '[]'; }
    # PAT-2067: collection_status.safari_extensions comes from
    # browser_extensions.sh, covered by test-browser-extensions.zsh.
    safari_extensions_collection_status() { printf 'unavailable'; }
    local PENDING_UPDATES_JSON="[]" PATCHES_JSON="[]"
    print -r -- '[]' > "$APPS_JSON_FILE"
    print -r -- '{}' > "$HARDWARE_HEALTH_JSON_TMP"
    print -r -- '[]' > "$BROWSER_EXTENSIONS_JSON_FILE"
    {
        print -r -- "{"
        eval "cat <<PAYLOAD_EOF
$PAYLOAD_TAIL
PAYLOAD_EOF"
        print -r -- "}"
    } > "$obj" 2>/dev/null
    json_eval "$obj" "$1"
}
# payload_status: collection_status.certificates in the assembled payload.
payload_status() { payload_eval 'd["collection_status"]["certificates"]'; }

# stdout_bytes: bytes the collector wrote to stdout in the last run_case.
stdout_bytes() { wc -c < "$PATCHED_TMPDIR/collector-stdout.log" | tr -d ' '; }
# warning_line: the PATCHED_COLLECTION_WARNING line from the last run_case.
warning_line() { grep "^PATCHED_COLLECTION_WARNING" "$PATCHED_TMPDIR/collector-stderr.log" 2>/dev/null || true; }

# ── Boundary doubles ───────────────────────────────────────────────────────
FIXED_NOW_EPOCH=1893456000   # 2030-01-01T00:00:00Z
date() {
    if [[ "$*" == "-u +%s" ]]; then print -r -- "$FIXED_NOW_EPOCH"
    else command date "$@"; fi
}

# MOCK_SECURITY_MODE:
#   pem         find-certificate prints $MOCK_PEM_FILE
#   empty       openable keychain holding no certificates (exit 0, no output)
#   fail        find-certificate exits non-zero
#   garbage     find-certificate prints non-PEM text, exit 0
#   unopenable  what real `security` does for a missing, unreadable or corrupt
#               keychain (verified on macOS 26): find-certificate exits 0 with
#               no output, show-keychain-info fails
MOCK_SECURITY_MODE="empty"
MOCK_PEM_FILE=""
SECURITY_ARGS_LOG=$(mktemp)
/usr/bin/security() {
    print -r -- "$*" >> "$SECURITY_ARGS_LOG"
    if [[ "${1:-}" == "show-keychain-info" ]]; then
        case "$MOCK_SECURITY_MODE" in
            unopenable) print -u2 "security: SecKeychainCopySettings $2: The specified keychain could not be found."; return 50 ;;
            *) return 0 ;;
        esac
    fi
    case "$MOCK_SECURITY_MODE" in
        pem)        cat "$MOCK_PEM_FILE" ;;
        empty)      return 0 ;;
        fail)       print -u2 "security: SecKeychainSearchCopyNext: The specified keychain could not be found."; return 50 ;;
        garbage)    print -r -- "this is not a certificate store"; return 0 ;;
        unopenable) return 0 ;;
    esac
}

run_case() {  # run_case <mode> [<pem-file>]
    MOCK_SECURITY_MODE="$1"
    MOCK_PEM_FILE="${2:-}"
    PATCHED_TMPDIR=$(mktemp -d)
    unset CERTS_COLLECTION_STATUS
    collect_certs > "$PATCHED_TMPDIR/collector-stdout.log" 2> "$PATCHED_TMPDIR/collector-stderr.log"
}

# ── Fixture certificates ───────────────────────────────────────────────────
FIX=$(mktemp -d)

# CN "Patched Test Valid", notAfter 2099-12-31T23:59:59Z, basicConstraints
# critical CA:TRUE, no extendedKeyUsage
cat > "$FIX/valid.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBwDCCAWWgAwIBAgIUHkFhVdRjNF5HjbiEW3lSe5LQ3bgwCgYIKoZIzj0EAwIw
NDEVMBMGA1UECgwMUGF0Y2hlZCBUZXN0MRswGQYDVQQDDBJQYXRjaGVkIFRlc3Qg
VmFsaWQwIBcNMjAwMTAxMDAwMDAwWhgPMjA5OTEyMzEyMzU5NTlaMDQxFTATBgNV
BAoMDFBhdGNoZWQgVGVzdDEbMBkGA1UEAwwSUGF0Y2hlZCBUZXN0IFZhbGlkMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE4p5ORthLV6i0BhZEbAiDH9mG+sLv7SG/
n/oasXregU4kqan1wCsHJKdTFKrzxRKAePFnWJuCNvQOLZPor3pEy6NTMFEwHQYD
VR0OBBYEFMTsJyXqZW8pI1M8a+EstkrT3U6MMB8GA1UdIwQYMBaAFMTsJyXqZW8p
I1M8a+EstkrT3U6MMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIh
AIrRnYBtOb6q09qiIMbKP9e5b8kWXzXzhct8PRTViwJtAiEA41jZdrawBT7avUPH
aKroUzRBW37q40fCf63y4KfkbnA=
-----END CERTIFICATE-----
PEM

# CN "Patched Test Expired", notAfter 2001-01-01T00:00:00Z
cat > "$FIX/expired.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBwDCCAWegAwIBAgIUSEtf+tDqlKe0GG0BTeLUVvQ7RCkwCgYIKoZIzj0EAwIw
NjEVMBMGA1UECgwMUGF0Y2hlZCBUZXN0MR0wGwYDVQQDDBRQYXRjaGVkIFRlc3Qg
RXhwaXJlZDAeFw0wMDAxMDEwMDAwMDBaFw0wMTAxMDEwMDAwMDBaMDYxFTATBgNV
BAoMDFBhdGNoZWQgVGVzdDEdMBsGA1UEAwwUUGF0Y2hlZCBUZXN0IEV4cGlyZWQw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQi76Ze1hGq5gm2P5fCf+2hiN6ArOig
rShbhdRJ82zJO5qi9jMAmbASPBjITK5srlMpvbkJM1U6RS2B52yKkskUo1MwUTAd
BgNVHQ4EFgQUf4/Eix7Zz3XR71b6/bmYPYfN0oowHwYDVR0jBBgwFoAUf4/Eix7Z
z3XR71b6/bmYPYfN0oowDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAgNHADBE
AiB0wxOzMjoXTJjZo7aPIT50kGj74AiCD+YuuwwAXG4qiAIgZsmZKIquBN1ZHeby
E8q9M/9odfuifwDWl1WOrHbjbmE=
-----END CERTIFICATE-----
PEM

# CN "Patched Test Expiring", notAfter 2030-01-15T00:00:00Z (14 days after
# the pinned "now")
cat > "$FIX/expiring.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBwzCCAWmgAwIBAgIUL+NXrsxoZHnRaCTlJCeauVrHf44wCgYIKoZIzj0EAwIw
NzEVMBMGA1UECgwMUGF0Y2hlZCBUZXN0MR4wHAYDVQQDDBVQYXRjaGVkIFRlc3Qg
RXhwaXJpbmcwHhcNMjkxMjAxMDAwMDAwWhcNMzAwMTE1MDAwMDAwWjA3MRUwEwYD
VQQKDAxQYXRjaGVkIFRlc3QxHjAcBgNVBAMMFVBhdGNoZWQgVGVzdCBFeHBpcmlu
ZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMsVjgevoSpVXIxkAPXCvcHttW3d
OjHzqhJbFbZYIXuM9qMnyI/TLifpmgiNUqef8asp7kfS3UZUhFJYZcDkn9SjUzBR
MB0GA1UdDgQWBBQFnvP+3S3WNwIpppDjdHl81uoAhzAfBgNVHSMEGDAWgBQFnvP+
3S3WNwIpppDjdHl81uoAhzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gA
MEUCICKc7hC2HKRcZxPPvhdf7fhyCvXRU78RKROj2i2eiW0pAiEAzAupqiHvm2v1
iNwPgAuqKYNswkupx1Utx99ZNMZFMIw=
-----END CERTIFICATE-----
PEM

# CN "Patched Test CA", notAfter 2099-12-31T23:59:59Z, basicConstraints
# critical CA:TRUE, extendedKeyUsage serverAuth,clientAuth
cat > "$FIX/ca.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIB2DCCAX6gAwIBAgIUFh2yi5hSTDsZtPJzTNTwAlvdowUwCgYIKoZIzj0EAwIw
MTEVMBMGA1UECgwMUGF0Y2hlZCBUZXN0MRgwFgYDVQQDDA9QYXRjaGVkIFRlc3Qg
Q0EwIBcNMjAwMTAxMDAwMDAwWhgPMjA5OTEyMzEyMzU5NTlaMDExFTATBgNVBAoM
DFBhdGNoZWQgVGVzdDEYMBYGA1UEAwwPUGF0Y2hlZCBUZXN0IENBMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEVUhhsGYgC2thIv6+4tSNYCEdgivLDJx8BHrsDwnr
NlXPu1KtWpCNcAKuWFD1sT8+AWOAITFQzL7jL0TRm/Q5ZqNyMHAwHQYDVR0OBBYE
FDN6zhxsW3Ubz4Q1YAh2dOI73MQxMB8GA1UdIwQYMBaAFDN6zhxsW3Ubz4Q1YAh2
dOI73MQxMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG
AQUFBwMCMAoGCCqGSM49BAMCA0gAMEUCIClOVWJZyc48M6cPBdM58mU6KRb7ixRE
wtBfjizlvS78AiEAjET0/kachyxZszTa6GAR2UMC+rk+W2pk4MHPSL/6h3c=
-----END CERTIFICATE-----
PEM

# CN "Patched Test Leaf", basicConstraints CA:FALSE (not critical),
# extendedKeyUsage serverAuth, clientAuth, codeSigning
cat > "$FIX/leaf.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBvzCCAWWgAwIBAgIUdNqGg9+NtMgpoqjx9aPmSSgo69kwCgYIKoZIzj0EAwIw
MzEVMBMGA1UECgwMUGF0Y2hlZCBUZXN0MRowGAYDVQQDDBFQYXRjaGVkIFRlc3Qg
TGVhZjAgFw0yMDAxMDEwMDAwMDBaGA8yMDk5MTIzMTIzNTk1OVowMzEVMBMGA1UE
CgwMUGF0Y2hlZCBUZXN0MRowGAYDVQQDDBFQYXRjaGVkIFRlc3QgTGVhZjBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABDOu52c2gZEQtTcyupApessRHIYarVbI6bpV
XCqb1OR+yn82zNeOamNoQV17z0JscBDBmwx7rEox1gylkRZ/bPyjVTBTMAkGA1Ud
EwQCMAAwJwYDVR0lBCAwHgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAzAd
BgNVHQ4EFgQUa47btG5LsKJKk1MNbH9n/SMg2bAwCgYIKoZIzj0EAwIDSAAwRQIg
AUXslO3BTbzbw5w1THLYnxuo59UY/HxVvbrHoV2ZFqACIQCvRABNYqsL988KpXuC
uNo+7jxHeyQ7QDur7DPaDyYhqQ==
-----END CERTIFICATE-----
PEM

# CN "Patched Test Intermediate CA", basicConstraints critical CA:TRUE,
# pathlen:0, extendedKeyUsage carrying every OID whose display name differs
# between LibreSSL 3.3 and OpenSSL 3 (or that only one of them names), plus
# an Apple OID neither names
cat > "$FIX/intermediate.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIICljCCAj2gAwIBAgIUPoiK5UoM2JnvK0oFnjgSU9LUjpgwCgYIKoZIzj0EAwIw
PjEVMBMGA1UECgwMUGF0Y2hlZCBUZXN0MSUwIwYDVQQDDBxQYXRjaGVkIFRlc3Qg
SW50ZXJtZWRpYXRlIENBMCAXDTIwMDEwMTAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5
WjA+MRUwEwYDVQQKDAxQYXRjaGVkIFRlc3QxJTAjBgNVBAMMHFBhdGNoZWQgVGVz
dCBJbnRlcm1lZGlhdGUgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARI76yj
rAiuXbjreKfuxUFAQXn7hMVMibgmEv3R35f4aowNulvEYZyKbo9+Mb2UnKIoe+kw
+LWerzpOPV+/z87mo4IBFTCCAREwEgYDVR0TAQH/BAgwBgEB/wIBADCB2wYDVR0l
BIHTMIHQBgRVHSUABggrBgEFBQcDBQYIKwYBBQUHAwYGCCsGAQUFBwMHBgorBgEE
AYI3FAICBgorBgEEAYI3CgMEBgorBgEEAYI3CgMDBgorBgEEAYI3AgEVBgorBgEE
AYI3AgEWBglghkgBhvhCBAEGCCsGAQUFBwMEBggrBgEFBQcDCAYIKwYBBQUHAwkG
CCsGAQUFBwMRBggrBgEFBQcDFQYIKwYBBQUHAxYGBysGAQUCAwQGBysGAQUCAwUG
CisGAQQBgjcKAwEGCSqGSIb3Y2QEATAdBgNVHQ4EFgQU/Pbge+/q3g2taJ8mRiZU
eNkQzZQwCgYIKoZIzj0EAwIDRwAwRAIgWARUHgWQKS71vWv7/hYNDZhX6sy9t1B9
Fe66875uBkUCIBh+xDdBMyeYnlpIGjTw/xVjwhWgqP2Xac5eMdYcvbzU
-----END CERTIFICATE-----
PEM

# CN "Patched Test No Basic Constraints": no basicConstraints extension,
# extendedKeyUsage codeSigning
cat > "$FIX/nobc.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBwDCCAWagAwIBAgIUKon/HDh3mWvyyQnLWXlwyesWtBIwCgYIKoZIzj0EAwIw
QzEVMBMGA1UECgwMUGF0Y2hlZCBUZXN0MSowKAYDVQQDDCFQYXRjaGVkIFRlc3Qg
Tm8gQmFzaWMgQ29uc3RyYWludHMwIBcNMjAwMTAxMDAwMDAwWhgPMjA5OTEyMzEy
MzU5NTlaMEMxFTATBgNVBAoMDFBhdGNoZWQgVGVzdDEqMCgGA1UEAwwhUGF0Y2hl
ZCBUZXN0IE5vIEJhc2ljIENvbnN0cmFpbnRzMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAES3IXqXEvCAmggxwv22cMVeo35YsXGgtYflXhT4GJAflfnFbO/tvRT2TC
sssSmUFKrZ0Gk/YDojL+u4MXDiucRqM2MDQwEwYDVR0lBAwwCgYIKwYBBQUHAwMw
HQYDVR0OBBYEFH+WRVVx3rpa0upibf/b77ZmuXOhMAoGCCqGSM49BAMCA0gAMEUC
IQCdAtUR/gPT8iRe98tYOB2zoitzBatUSnI6OBD2zs8zTgIgB09n6SDDY4KPIfIW
LXiYjwWfw633sYI7GNeZp2Pv+jY=
-----END CERTIFICATE-----
PEM

# CN "Patched Test Hidden CA": a Netscape Comment extension whose IA5String
# contains newlines and a forged "X509v3 Basic Constraints: CA:FALSE" block,
# followed by the real basicConstraints critical CA:TRUE. `openssl x509 -text`
# prints the comment verbatim, so the text holds two Basic Constraints headers
# and first-match parsing would report this CA as CA:FALSE.
cat > "$FIX/hidden-ca.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIB+jCCAaCgAwIBAgIUSAxq8Ynz0+j9cv8IH3p96/R+rxgwCgYIKoZIzj0EAwIw
ODEVMBMGA1UECgwMUGF0Y2hlZCBUZXN0MR8wHQYDVQQDDBZQYXRjaGVkIFRlc3Qg
SGlkZGVuIENBMCAXDTIwMDEwMTAwMDAwMFoYDzIwOTkxMjMxMjM1OTU5WjA4MRUw
EwYDVQQKDAxQYXRjaGVkIFRlc3QxHzAdBgNVBAMMFlBhdGNoZWQgVGVzdCBIaWRk
ZW4gQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQKwSFGg0IlFPrK/DY8byl5
jh5viZ/fXkcssno4Gq26x7eRsw8VUOEGwCcJzHwNQo9umtOKJL/uhwykkQbESd7x
o4GFMIGCMFAGCWCGSAGG+EIBDQRDFkF4CiAgICAgICAgICAgIFg1MDl2MyBCYXNp
YyBDb25zdHJhaW50czogCiAgICAgICAgICAgICAgICBDQTpGQUxTRTAPBgNVHRMB
Af8EBTADAQH/MB0GA1UdDgQWBBTvhD5MVs6AKuCfc/CsqzB+LQ24IzAKBggqhkjO
PQQDAgNIADBFAiEArGWLtEmhM0KJ0AucrLAfDDL8exPw1TFK30cS2A1GKC0CIEHH
PY3Wkmfc1RuFdZ9YN2ErEFLTxkhC8JYWJYelkHuu
-----END CERTIFICATE-----
PEM

# CN "Patched Test Forged Text": no basicConstraints and no
# extendedKeyUsage extension, only a Netscape Comment whose text forges
# "Basic Constraints: critical CA:TRUE" and "Extended Key Usage: Code Signing".
cat > "$FIX/forged.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIICPDCCAeKgAwIBAgIUPXGU33XYLe0yva4h3CXhShbG3PwwCgYIKoZIzj0EAwIw
OjEVMBMGA1UECgwMUGF0Y2hlZCBUZXN0MSEwHwYDVQQDDBhQYXRjaGVkIFRlc3Qg
Rm9yZ2VkIFRleHQwIBcNMjAwMTAxMDAwMDAwWhgPMjA5OTEyMzEyMzU5NTlaMDox
FTATBgNVBAoMDFBhdGNoZWQgVGVzdDEhMB8GA1UEAwwYUGF0Y2hlZCBUZXN0IEZv
cmdlZCBUZXh0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKeWLrb3qIfYxvVzQ
KGqMbXZWlpt7PbkpX+Ki2DWAPtu5q+PoPXvs0A6UU0YKuOvKUybobkebfiOhOCkT
F2qqsKOBwzCBwDCBngYJYIZIAYb4QgENBIGQFoGNeAogICAgICAgICAgICBYNTA5
djMgQmFzaWMgQ29uc3RyYWludHM6IGNyaXRpY2FsCiAgICAgICAgICAgICAgICBD
QTpUUlVFCiAgICAgICAgICAgIFg1MDl2MyBFeHRlbmRlZCBLZXkgVXNhZ2U6IAog
ICAgICAgICAgICAgICAgQ29kZSBTaWduaW5nMB0GA1UdDgQWBBStIsZ2AhQaYqa3
ywypyT/jLVVZQzAKBggqhkjOPQQDAgNIADBFAiEAryJtt4R8+y72j/EncZTbIfyl
9MV+0C7lQ+dSLA7acHkCIHSMwrh6rVVF9kyzDF1WvnTrfN3ywQV1eHn4o/t08J1H
-----END CERTIFICATE-----
PEM

# A PEM block whose body is not a certificate (corrupt store entry).
cat > "$FIX/corrupt.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
Tm90IGEgcmVhbCBjZXJ0aWZpY2F0ZSwganVzdCBiYXNlNjQgdGV4dA==
-----END CERTIFICATE-----
PEM

# CN "CA:TRUE X509v3 Basic Constraints 2.5.29.19", plus subject attributes
# whose types are the basicConstraints (2.5.29.19 = "CA:TRUE") and
# extKeyUsage (2.5.29.37 = "1.3.6.1.5.5.7.3.3") OIDs. No extensions other than
# subjectKeyIdentifier: the extension OIDs and text appear only in the subject.
cat > "$FIX/forged-subject.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIICDjCCAbOgAwIBAgIIXwQB30UvduowCgYIKoZIzj0EAwIwejEVMBMGA1UECgwM
UGF0Y2hlZCBUZXN0MTMwMQYDVQQDDCpDQTpUUlVFIFg1MDl2MyBCYXNpYyBDb25z
dHJhaW50cyAyLjUuMjkuMTkxEDAOBgNVHRMMB0NBOlRSVUUxGjAYBgNVHSUMETEu
My42LjEuNS41LjcuMy4zMCAXDTI2MDkxNDAwNTAwOFoYDzIxMjYwODIxMDA1MDA4
WjB6MRUwEwYDVQQKDAxQYXRjaGVkIFRlc3QxMzAxBgNVBAMMKkNBOlRSVUUgWDUw
OXYzIEJhc2ljIENvbnN0cmFpbnRzIDIuNS4yOS4xOTEQMA4GA1UdEwwHQ0E6VFJV
RTEaMBgGA1UdJQwRMS4zLjYuMS41LjUuNy4zLjMwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAQ644qiKO7E97pcj35ZWlGh2nQEkaApLHCHVwGRONgGca3/KBn73XKi
cRfU6YoEgvwofJyeFr0uS8dnI7PZ6LQ7oyEwHzAdBgNVHQ4EFgQUozwhfG7No1wh
HnWQPe9SUX7LSsMwCgYIKoZIzj0EAwIDSQAwRgIhALFYQ51BnpttW+H7geL9PuSh
Ue1lfsX7yRshc2/+ejDpAiEAmdMeMPMVQ6AaN3QPXQ7nP8t3oPWKi66WNZoA5T6d
lZI=
-----END CERTIFICATE-----
PEM

# CN "Patched Test Injected Lines": a private extension (1.3.6.1.4.1.55555.1)
# whose value is printable text. asn1parse prints printable OCTET STRINGs raw,
# so the text puts three structure-shaped lines into its output, at the offset
# where the next real line starts, forging a basicConstraints CA:TRUE
# extension. There is no real basicConstraints. A valid certificate: the
# asn1parse line walk (PAT-1735) had to skip it, the DER walk classifies it
# (PAT-1740).
cat > "$FIX/injected.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIICZTCCAgugAwIBAgIIXfOmc9ck6KEwCgYIKoZIzj0EAwIwPTEVMBMGA1UECgwM
UGF0Y2hlZCBUZXN0MSQwIgYDVQQDDBtQYXRjaGVkIFRlc3QgSW5qZWN0ZWQgTGlu
ZXMwIBcNMjYwOTE0MDA1MDU5WhgPMjEyNjA4MjEwMDUwNTlaMD0xFTATBgNVBAoM
DFBhdGNoZWQgVGVzdDEkMCIGA1UEAwwbUGF0Y2hlZCBUZXN0IEluamVjdGVkIExp
bmVzMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOuOKoijuxPe6XI9+WVpRodp0
BJGgKSxwh1cBkTjYBnGt/ygZ+91yonEX1OmKBIL8KHycnha9LkvHZyOz2ei0O6OB
8jCB7zCBzQYJKwYBBAGDsgMBBIG/eAogIDUwMDpkPTQgIGhsPTIgbD0gIDEyIGNv
bnM6IFNFUVVFTkNFICAgICAgICAgIAogIDUwMjpkPTUgIGhsPTIgbD0gICAzIHBy
aW06IE9CSkVDVCAgICAgICAgICAgIDpYNTA5djMgQmFzaWMgQ29uc3RyYWludHMK
ICA1MDc6ZD01ICBobD0yIGw9ICAgNSBwcmltOiBPQ1RFVCBTVFJJTkcgICAgICBb
SEVYIERVTVBdOjMwMDMwMTAxRkYwHQYDVR0OBBYEFKM8IXxuzaNcIR51kD3vUlF+
y0rDMAoGCCqGSM49BAMCA0gAMEUCIQCYR3DRm9Frc+EyBGUAnkWUtNYGhhkEbcA0
FF5tGsMfRQIgUmHBwl0NpBuYIQadTg00emDIu9dxgfvF6Ef+RkbKcl8=
-----END CERTIFICATE-----
PEM

# CN "Patched Test Netscape Comment": a CA:FALSE leaf, extendedKeyUsage
# serverAuth, clientAuth. Its Netscape Comment (2.16.840.1.113730.1.13)
# IA5String and a subject/issuer description UTF8String both hold newlines
# and text copying asn1parse structure lines at the offsets where the next
# real lines start, forging a critical basicConstraints CA:TRUE. asn1parse
# prints the description raw, so the PAT-1735 line walk skipped this valid
# certificate. Made with OpenSSL 3.6.3 `req -x509`; the signature verifies.
cat > "$FIX/nscomment.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIDrDCCA1KgAwIBAgIIXhwKS30vOhkwCgYIKoZIzj0EAwIwgcgxFTATBgNVBAoM
DFBhdGNoZWQgVGVzdDGBhjCBgwYDVQQNDHxPcHMKICAxOTg6ZD0zICBobD0yIGw9
ICAxNSBjb25zOiBTRVQgICAgICAgICAgICAgICAKICAyMDA6ZD00ICBobD0yIGw9
ICAgMyBwcmltOiBPQkpFQ1QgICAgICAgICAgICA6WDUwOXYzIEJhc2ljIENvbnN0
cmFpbnRzMSYwJAYDVQQDDB1QYXRjaGVkIFRlc3QgTmV0c2NhcGUgQ29tbWVudDAg
Fw0yNjA5MTQwMDAwMDBaGA8yMTI2MDgyMTAwMDAwMFowgcgxFTATBgNVBAoMDFBh
dGNoZWQgVGVzdDGBhjCBgwYDVQQNDHxPcHMKICAxOTg6ZD0zICBobD0yIGw9ICAx
NSBjb25zOiBTRVQgICAgICAgICAgICAgICAKICAyMDA6ZD00ICBobD0yIGw9ICAg
MyBwcmltOiBPQkpFQ1QgICAgICAgICAgICA6WDUwOXYzIEJhc2ljIENvbnN0cmFp
bnRzMSYwJAYDVQQDDB1QYXRjaGVkIFRlc3QgTmV0c2NhcGUgQ29tbWVudDBZMBMG
ByqGSM49AgEGCCqGSM49AwEHA0IABH+Pb7PVRQAcbXIzEAN5F5hF77R1J4iVmqk3
U2zwtVGmC6a9+TBWH79IWQNgqc3CeNvIyGsyy/4lh08Kvm61G2OjggEgMIIBHDCB
0AYJYIZIAYb4QgENBIHCFoG/WAogIDc4NTpkPTQgIGhsPTIgbD0gIDE1IGNvbnM6
IFNFUVVFTkNFICAgICAgICAgIAogIDc4NzpkPTUgIGhsPTIgbD0gICAzIHByaW06
IE9CSkVDVCAgICAgICAgICAgIDpYNTA5djMgQmFzaWMgQ29uc3RyYWludHMKICA3
OTI6ZD01ICBobD0yIGw9ICAgNSBwcmltOiBPQ1RFVCBTVFJJTkcgICAgICBbSEVY
IERVTVBdOjMwMDMwMTAxRkYwCQYDVR0TBAIwADAdBgNVHSUEFjAUBggrBgEFBQcD
AQYIKwYBBQUHAwIwHQYDVR0OBBYEFFHyMrP9yyIffGhJA0G2Ec7wN2n3MAoGCCqG
SM49BAMCA0gAMEUCIQDXqlqdsjuwc1xnoE5DacX/OhDhcCz3lRkFncCEX6bUlwIg
GSsUecGCpiJalocVVdu7xhctmVEBpcOm/tQzYd1iolo=
-----END CERTIFICATE-----
PEM

# CN "Patched Test Duplicate BC": basicConstraints CA:FALSE followed by a
# second, critical basicConstraints CA:TRUE.
cat > "$FIX/dup-bc.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBrDCCAVGgAwIBAgIIfqPMgNTO2KQwCgYIKoZIzj0EAwIwOzEVMBMGA1UECgwM
UGF0Y2hlZCBUZXN0MSIwIAYDVQQDDBlQYXRjaGVkIFRlc3QgRHVwbGljYXRlIEJD
MCAXDTI2MDkxNDAwNTEwMFoYDzIxMjYwODIxMDA1MTAwWjA7MRUwEwYDVQQKDAxQ
YXRjaGVkIFRlc3QxIjAgBgNVBAMMGVBhdGNoZWQgVGVzdCBEdXBsaWNhdGUgQkMw
WTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ644qiKO7E97pcj35ZWlGh2nQEkaAp
LHCHVwGRONgGca3/KBn73XKicRfU6YoEgvwofJyeFr0uS8dnI7PZ6LQ7oz0wOzAJ
BgNVHRMEAjAAMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFKM8IXxuzaNcIR51
kD3vUlF+y0rDMAoGCCqGSM49BAMCA0kAMEYCIQDNrHqSTg3f9c8XvfzPBO8JIXq8
nXl/iKivfCO/gFvsawIhAOoojx+VCsL5wmW+MCCaM+FLQnXbSDKJk6etaekOPYrn
-----END CERTIFICATE-----
PEM

# CN "Patched Test BER Boolean": critical basicConstraints whose cA BOOLEAN is
# 0x01 (BER true, not the DER 0xFF).
cat > "$FIX/ber-bool.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBnjCCAUSgAwIBAgIIMrMZPNyXQaMwCgYIKoZIzj0EAwIwOjEVMBMGA1UECgwM
UGF0Y2hlZCBUZXN0MSEwHwYDVQQDDBhQYXRjaGVkIFRlc3QgQkVSIEJvb2xlYW4w
IBcNMjYwOTE0MDA1MDA4WhgPMjEyNjA4MjEwMDUwMDhaMDoxFTATBgNVBAoMDFBh
dGNoZWQgVGVzdDEhMB8GA1UEAwwYUGF0Y2hlZCBUZXN0IEJFUiBCb29sZWFuMFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOuOKoijuxPe6XI9+WVpRodp0BJGgKSxw
h1cBkTjYBnGt/ygZ+91yonEX1OmKBIL8KHycnha9LkvHZyOz2ei0O6MyMDAwDwYD
VR0TAQH/BAUwAwEBATAdBgNVHQ4EFgQUozwhfG7No1whHnWQPe9SUX7LSsMwCgYI
KoZIzj0EAwIDSAAwRQIgTT2lH0LCh7QRqmPADem88lA0YpUDzBe97TMAQYtttAcC
IQDe0F4TJ8nKLDljQW7s+OaubmncmeEFnHxMArKG2BeEMw==
-----END CERTIFICATE-----
PEM

# CN "Patched Test Empty EKU": basicConstraints CA:FALSE and an
# extendedKeyUsage that is an empty SEQUENCE (X.509 requires at least one).
cat > "$FIX/empty-eku.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIBoDCCAUagAwIBAgIJAIjj4/o3XR65MAoGCCqGSM49BAMCMDgxFTATBgNVBAoM
DFBhdGNoZWQgVGVzdDEfMB0GA1UEAwwWUGF0Y2hlZCBUZXN0IEVtcHR5IEVLVTAg
Fw0yNjA5MTQwMDUwMDhaGA8yMTI2MDgyMTAwNTAwOFowODEVMBMGA1UECgwMUGF0
Y2hlZCBUZXN0MR8wHQYDVQQDDBZQYXRjaGVkIFRlc3QgRW1wdHkgRUtVMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEOuOKoijuxPe6XI9+WVpRodp0BJGgKSxwh1cB
kTjYBnGt/ygZ+91yonEX1OmKBIL8KHycnha9LkvHZyOz2ei0O6M3MDUwCQYDVR0T
BAIwADAJBgNVHSUEAjAAMB0GA1UdDgQWBBSjPCF8bs2jXCEedZA971JRfstKwzAK
BggqhkjOPQQDAgNIADBFAiEA+Ev5U5E96hWDkza2rdGmuJF6zDvdnvkjO+A3lrH+
cfYCIE4uc05oZ5dkv5o5vEmVLkpP909vQIe7qCW38CBszhmJ
-----END CERTIFICATE-----
PEM

# CN "Patched Test Leaf Unknown EKU": basicConstraints CA:FALSE,
# extendedKeyUsage serverAuth, clientAuth, a private OID and a UUID OID whose
# last arc does not fit in a double.
cat > "$FIX/leaf-unknown-eku.pem" <<'PEM'
-----BEGIN CERTIFICATE-----
MIIB5TCCAYqgAwIBAgIJAK95o8dIPTFuMAoGCCqGSM49BAMCMD8xFTATBgNVBAoM
DFBhdGNoZWQgVGVzdDEmMCQGA1UEAwwdUGF0Y2hlZCBUZXN0IExlYWYgVW5rbm93
biBFS1UwIBcNMjYwOTE0MDA1MDA4WhgPMjEyNjA4MjEwMDUwMDhaMD8xFTATBgNV
BAoMDFBhdGNoZWQgVGVzdDEmMCQGA1UEAwwdUGF0Y2hlZCBUZXN0IExlYWYgVW5r
bm93biBFS1UwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQ644qiKO7E97pcj35Z
WlGh2nQEkaApLHCHVwGRONgGca3/KBn73XKicRfU6YoEgvwofJyeFr0uS8dnI7PZ
6LQ7o20wazAJBgNVHRMEAjAAMD8GA1UdJQQ4MDYGCCsGAQUFBwMBBggrBgEFBQcD
AgYKKwYBBAGDsgMHAQYUaYPwnafrz97gx6GnssCUjMj513YwHQYDVR0OBBYEFKM8
IXxuzaNcIR51kD3vUlF+y0rDMAoGCCqGSM49BAMCA0kAMEYCIQDUj/4gfS1ScXaV
23bg16bdCrjQ1q9HpuYJtb/1bbAc1AIhALiUnfgmo3W6HjVZG4ozboLQwbxRHtzk
rT8OuaHlIr0a
-----END CERTIFICATE-----
PEM

INTERMEDIATE_EKU="2.5.29.37.0,1.3.6.1.5.5.7.3.5,1.3.6.1.5.5.7.3.6,1.3.6.1.5.5.7.3.7,1.3.6.1.4.1.311.20.2.2,1.3.6.1.4.1.311.10.3.4,1.3.6.1.4.1.311.10.3.3,1.3.6.1.4.1.311.2.1.21,1.3.6.1.4.1.311.2.1.22,2.16.840.1.113730.4.1,1.3.6.1.5.5.7.3.4,1.3.6.1.5.5.7.3.8,1.3.6.1.5.5.7.3.9,1.3.6.1.5.5.7.3.17,1.3.6.1.5.5.7.3.21,1.3.6.1.5.5.7.3.22,1.3.6.1.5.2.3.4,1.3.6.1.5.2.3.5,1.3.6.1.4.1.311.10.3.1,1.2.840.113635.100.4.1"

##############################################################################
# 1. Valid certificate in the System keychain: identity fields, a positive
#    days_until_expiry, and the collector asked the right store.
##############################################################################
echo "--- 1. Valid certificate"

: > "$SECURITY_ARGS_LOG"
run_case pem "$FIX/valid.pem"

chk_eq "output is valid JSON array" "list" "$(json_eval "$CERTS_JSON_TMP" 'type(d).__name__')"
chk_eq "one certificate reported" "1" "$(json_eval "$CERTS_JSON_TMP" 'len(d)')"
chk_eq "subject_cn" "Patched Test Valid" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["subject_cn"]')"
chk_eq "issuer_cn" "Patched Test Valid" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["issuer_cn"]')"
chk_eq "not_after ISO-8601 UTC" "2099-12-31T23:59:59Z" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["not_after"]')"
chk_eq "days_until_expiry positive" "25566" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["days_until_expiry"]')"
chk_eq "sha1 lowercase, no colons" "5461c9b43941880e8d5a0d74e46b685d084b54c9" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["sha1"]')"
chk_eq "is_self_signed true" "True" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["is_self_signed"]')"
chk_eq "store tagged System" "System" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["store"]')"
chk_eq "reads System.keychain" "find-certificate -a -p /Library/Keychains/System.keychain" "$(head -1 "$SECURITY_ARGS_LOG")"
chk_eq "collection status complete" "complete" "${CERTS_COLLECTION_STATUS:-unset}"
chk_eq "payload carries the certificates key" "1" "$(payload_eval 'len(d["certificates"])')"
chk_eq "payload collection_status.certificates complete" "complete" "$(payload_status)"
# PAT-2066 added collection_status.apps beside certificates; PAT-2075 apps_users.
chk_eq "collection_status is a top-level object with certificates, apps, apps_users (PAT-2075) and safari_extensions (PAT-2067)" "apps,apps_users,certificates,safari_extensions" "$(payload_eval '",".join(sorted(d["collection_status"].keys()))')"
chk_eq "no collection warning" "" "$(warning_line)"

##############################################################################
# 2. Expired certificate: negative days_until_expiry (floor, not truncation).
##############################################################################
echo "--- 2. Expired certificate"

run_case pem "$FIX/expired.pem"

chk_eq "one certificate reported" "1" "$(json_eval "$CERTS_JSON_TMP" 'len(d)')"
chk_eq "subject_cn" "Patched Test Expired" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["subject_cn"]')"
chk_eq "not_after" "2001-01-01T00:00:00Z" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["not_after"]')"
chk_eq "days_until_expiry negative" "-10592" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["days_until_expiry"]')"

##############################################################################
# 3. Expiring inside a warning window (14 days out). The collector has no
#    warning-window field: it reports days_until_expiry and the threshold is
#    applied server-side. Pin the per-cert key set so a new field is a
#    deliberate contract change, not a silent one.
##############################################################################
echo "--- 3. Certificate expiring inside the warning window"

run_case pem "$FIX/expiring.pem"

chk_eq "days_until_expiry is 14" "14" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["days_until_expiry"]')"
chk_eq "per-cert key set unchanged" \
    "basic_constraints_ca,days_until_expiry,ext_key_usage,is_self_signed,issuer_cn,not_after,sha1,store,subject_cn" \
    "$(json_eval "$CERTS_JSON_TMP" '",".join(sorted(d[0].keys()))')"

##############################################################################
# 4. Several certificates in one store: all reported, store order kept, and
#    nothing written to stdout. zsh prints `name=value` when `local name`
#    re-runs on an existing local, so a declaration inside the per-cert loop
#    echoed earlier certs' fields into patched-collect.log (PAT-1709).
##############################################################################
echo "--- 4. Mixed store (valid, expired, expiring)"

cat "$FIX/valid.pem" "$FIX/expired.pem" "$FIX/expiring.pem" > "$FIX/mixed.pem"
run_case pem "$FIX/mixed.pem"

chk_eq "three certificates reported" "3" "$(json_eval "$CERTS_JSON_TMP" 'len(d)')"
chk_eq "store order kept" "Patched Test Valid|Patched Test Expired|Patched Test Expiring" \
    "$(json_eval "$CERTS_JSON_TMP" '"|".join(c["subject_cn"] for c in d)')"
chk_eq "nothing written to stdout across 3 certs" "0" "$(stdout_bytes)"

##############################################################################
# 5. Extension fields through the runner's real /usr/bin/openssl. Stock macOS
#    ships LibreSSL, which has no `x509 -ext`; the collector walks the DER with
#    `asn1parse` instead, which prints the same on LibreSSL and OpenSSL 3.
##############################################################################
echo "--- 5. Extension fields, real openssl ($(/usr/bin/openssl version 2>/dev/null))"

cat "$FIX/ca.pem" "$FIX/leaf.pem" "$FIX/nobc.pem" "$FIX/valid.pem" "$FIX/intermediate.pem" > "$FIX/extensions.pem"
run_case pem "$FIX/extensions.pem"

chk_eq "five certificates reported" "5" "$(json_eval "$CERTS_JSON_TMP" 'len(d)')"
chk_eq "CA cert: basic_constraints_ca true" "True" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["basic_constraints_ca"]')"
chk_eq "CA cert: EKU serverAuth, clientAuth" "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2" "$(json_eval "$CERTS_JSON_TMP" '",".join(d[0]["ext_key_usage"])')"
chk_eq "leaf: basic_constraints_ca false (CA:FALSE)" "False" "$(json_eval "$CERTS_JSON_TMP" 'd[1]["basic_constraints_ca"]')"
chk_eq "leaf: EKU serverAuth, clientAuth, codeSigning" "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.3" "$(json_eval "$CERTS_JSON_TMP" '",".join(d[1]["ext_key_usage"])')"
chk_eq "no basicConstraints: basic_constraints_ca false" "False" "$(json_eval "$CERTS_JSON_TMP" 'd[2]["basic_constraints_ca"]')"
chk_eq "no basicConstraints: EKU codeSigning" "1.3.6.1.5.5.7.3.3" "$(json_eval "$CERTS_JSON_TMP" '",".join(d[2]["ext_key_usage"])')"
chk_eq "no EKU extension: ext_key_usage []" "0" "$(json_eval "$CERTS_JSON_TMP" 'len(d[3]["ext_key_usage"])')"
chk_eq "no EKU extension: CA:TRUE still read" "True" "$(json_eval "$CERTS_JSON_TMP" 'd[3]["basic_constraints_ca"]')"
chk_eq "CA:TRUE, pathlen:0 reads as CA" "True" "$(json_eval "$CERTS_JSON_TMP" 'd[4]["basic_constraints_ca"]')"
chk_eq "every EKU OID decoded, known and unknown" "$INTERMEDIATE_EKU" "$(json_eval "$CERTS_JSON_TMP" '",".join(d[4]["ext_key_usage"])')"
chk_eq "ext_key_usage is a JSON array of strings" "True" "$(json_eval "$CERTS_JSON_TMP" 'all(isinstance(o, str) for c in d for o in c["ext_key_usage"])')"
chk_eq "collection status complete" "complete" "${CERTS_COLLECTION_STATUS:-unset}"
chk_eq "nothing written to stdout across 5 certs" "0" "$(stdout_bytes)"

run_case pem "$FIX/leaf-unknown-eku.pem"
chk_eq "leaf, unknown EKU OIDs: basic_constraints_ca false" "False" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["basic_constraints_ca"]')"
chk_eq "leaf, unknown EKU OIDs: dotted, arcs of any size" \
    "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2,1.3.6.1.4.1.55555.7.1,2.25.329800735698586629295641978511506172918" \
    "$(json_eval "$CERTS_JSON_TMP" '",".join(d[0]["ext_key_usage"])')"
chk_eq "ext_key_usage wire format unchanged" '"ext_key_usage": ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.4.1.55555.7.1", "2.25.329800735698586629295641978511506172918"], "basic_constraints_ca": false' \
    "$(grep -o '"ext_key_usage": \[[^]]*\], "basic_constraints_ca": [a-z]*' "$CERTS_JSON_TMP")"
chk_eq "leaf, unknown EKU OIDs: collection status complete" "complete" "${CERTS_COLLECTION_STATUS:-unset}"

##############################################################################
# 6. The DER walk. Every openssl call is logged: two per certificate, and
#    asn1parse (whose string values print raw) is never run. Then the stub od
#    replays the real hex for the certificate with one change (a byte run
#    removed, a forged extension inserted, trailing or wrapping bytes, a token
#    od never prints, or a failing exit) and every other call goes to the real
#    binary. Each change must skip the certificate, never classify it.
##############################################################################
echo "--- 6. DER that does not walk cleanly"

OPENSSL_CALLS_LOG=$(mktemp)
/usr/bin/openssl() {
    print -r -- "$*" >> "$OPENSSL_CALLS_LOG"
    if [[ "${OPENSSL_MUTATION:-}" == "x509-fail" && "$*" == "x509 -outform DER" ]]; then
        command /usr/bin/openssl "$@"; return 1
    fi
    command /usr/bin/openssl "$@"
}
: > "$OPENSSL_CALLS_LOG"
run_case pem "$FIX/extensions.pem"
chk_eq "five certificates cost ten openssl calls" "10" "$(wc -l < "$OPENSSL_CALLS_LOG" | tr -d ' ')"
chk_eq "asn1parse is never run" "0" "$(grep -c asn1parse "$OPENSSL_CALLS_LOG")"

OD_MUTATION=""
/usr/bin/od() {
    if [[ -z "$OD_MUTATION" ]]; then
        command /usr/bin/od "$@"; return $?
    fi
    local hex
    hex=$(command /usr/bin/od "$@")
    hex=${(j: :)${=hex}}
    case "$OD_MUTATION" in
        od-fail)
            print -r -- "$hex"; return 1 ;;
        drop-last)
            print -r -- "${hex% *}" ;;
        drop-bc-value)
            # basicConstraints extnValue content removed, lengths left alone.
            print -r -- "${hex/04 05 30 03 01 01 ff/04 05}" ;;
        append-bc)
            # A forged critical basicConstraints CA:TRUE extension inserted
            # after the last real extension, lengths left alone.
            print -r -- "${hex/ 30 0a 06 08 2a 86 48 ce 3d 04 03 02 03 / 30 0f 06 03 55 1d 13 01 01 ff 04 05 30 03 01 01 ff 30 0a 06 08 2a 86 48 ce 3d 04 03 02 03 }" ;;
        trailing)
            print -r -- "$hex 00" ;;
        wrap)
            # The whole certificate inside one more SEQUENCE, lengths correct.
            print -r -- "30 82 01 c4 $hex" ;;
        suppressed)
            # od without -v prints "*" for repeated lines.
            print -r -- "$hex *" ;;
    esac
}

for mutation in x509-fail od-fail drop-last drop-bc-value append-bc trailing wrap suppressed; do
    if [[ "$mutation" == "x509-fail" ]]; then OPENSSL_MUTATION="x509-fail"; OD_MUTATION=""
    else OPENSSL_MUTATION=""; OD_MUTATION="$mutation"; fi
    run_case pem "$FIX/valid.pem"
    chk_eq "[$mutation] certificate skipped, collection partial" "partial" "${CERTS_COLLECTION_STATUS:-unset}"
    chk_eq "[$mutation] certificates key omitted" "False" "$(payload_eval '"certificates" in d')"
    chk_eq "[$mutation] warning names the reason" \
        "PATCHED_COLLECTION_WARNING section=certificates status=partial reason=der_unparseable skipped=1" "$(warning_line)"
done
OPENSSL_MUTATION=""
OD_MUTATION="append-bc"
run_case pem "$FIX/nobc.pem"
chk_eq "[append-bc] no-basicConstraints cert with a forged one inserted is skipped" "partial" "${CERTS_COLLECTION_STATUS:-unset}"
OD_MUTATION=""
run_case pem "$FIX/valid.pem"
chk_eq "stub passthrough: unmodified output still classifies" "True|complete" \
    "$(json_eval "$CERTS_JSON_TMP" 'd[0]["basic_constraints_ca"]')|${CERTS_COLLECTION_STATUS:-unset}"
unfunction /usr/bin/od /usr/bin/openssl

##############################################################################
# 7. Forged extension text and malformed extensions. Extensions are read from
#    the DER structure by position, so text in a subject or a string
#    extension cannot create, hide or duplicate one. A basicConstraints or
#    extKeyUsage that really is repeated or malformed skips the certificate
#    (partial: the server upserts the rest and prunes nothing) rather than
#    guessing a classification.
##############################################################################
echo "--- 7. Forged extension text and malformed extensions"

# The Netscape Comment forges "X509v3 Basic Constraints: CA:FALSE" in -text
# ahead of the real critical CA:TRUE. The DER has one basicConstraints.
cat "$FIX/valid.pem" "$FIX/hidden-ca.pem" > "$FIX/hidden-plus-valid.pem"
run_case pem "$FIX/hidden-plus-valid.pem"
chk_eq "comment forging a second Basic Constraints: both certs sent" "Patched Test Valid|Patched Test Hidden CA" "$(payload_eval '"|".join(c["subject_cn"] for c in d["certificates"])')"
chk_eq "comment forging CA:FALSE: the real CA:TRUE is read" "True" "$(json_eval "$CERTS_JSON_TMP" 'd[1]["basic_constraints_ca"]')"
chk_eq "comment forging CA:FALSE: collection complete" "complete" "${CERTS_COLLECTION_STATUS:-unset}"
chk_eq "comment forging CA:FALSE: no warning" "" "$(warning_line)"

run_case pem "$FIX/forged.pem"
chk_eq "comment forging CA:TRUE with no real extension: basic_constraints_ca false" \
    "False" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["basic_constraints_ca"]')"
chk_eq "comment forging EKU Code Signing with no real extension: ext_key_usage []" \
    "0" "$(json_eval "$CERTS_JSON_TMP" 'len(d[0]["ext_key_usage"])')"
chk_eq "comment forging extensions: collection complete" "complete" "${CERTS_COLLECTION_STATUS:-unset}"

run_case pem "$FIX/forged-subject.pem"
chk_eq "subject forging CA:TRUE and the extension OIDs: subject_cn as written" \
    "CA:TRUE X509v3 Basic Constraints 2.5.29.19" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["subject_cn"]')"
chk_eq "subject forging CA:TRUE: basic_constraints_ca false" "False" "$(json_eval "$CERTS_JSON_TMP" 'd[0]["basic_constraints_ca"]')"
chk_eq "subject forging extKeyUsage: ext_key_usage []" "0" "$(json_eval "$CERTS_JSON_TMP" 'len(d[0]["ext_key_usage"])')"
chk_eq "subject forging extensions: collection complete" "complete" "${CERTS_COLLECTION_STATUS:-unset}"

# String values that asn1parse prints as structure-shaped lines are data in
# the DER walk. The PAT-1735 line walk skipped both of these valid
# certificates; they are classified from their real extensions.
cat "$FIX/valid.pem" "$FIX/injected.pem" "$FIX/nscomment.pem" > "$FIX/printed-lines.pem"
run_case pem "$FIX/printed-lines.pem"
chk_eq "values printing forged asn1parse lines: every cert sent" \
    "Patched Test Valid|Patched Test Injected Lines|Patched Test Netscape Comment" \
    "$(payload_eval '"|".join(c["subject_cn"] for c in d["certificates"])')"
chk_eq "private extension forging CA:TRUE, no real basicConstraints: basic_constraints_ca false" \
    "False" "$(json_eval "$CERTS_JSON_TMP" 'd[1]["basic_constraints_ca"]')"
chk_eq "private extension forging CA:TRUE: ext_key_usage []" "0" "$(json_eval "$CERTS_JSON_TMP" 'len(d[1]["ext_key_usage"])')"
chk_eq "Netscape Comment and description forging CA:TRUE on a CA:FALSE leaf: basic_constraints_ca false" \
    "False" "$(json_eval "$CERTS_JSON_TMP" 'd[2]["basic_constraints_ca"]')"
chk_eq "Netscape Comment leaf: EKU serverAuth, clientAuth" "1.3.6.1.5.5.7.3.1,1.3.6.1.5.5.7.3.2" \
    "$(json_eval "$CERTS_JSON_TMP" '",".join(d[2]["ext_key_usage"])')"
chk_eq "Netscape Comment leaf: is_self_signed true" "True" "$(json_eval "$CERTS_JSON_TMP" 'd[2]["is_self_signed"]')"
chk_eq "values printing forged asn1parse lines: collection complete" "complete" "${CERTS_COLLECTION_STATUS:-unset}"
chk_eq "values printing forged asn1parse lines: no warning" "" "$(warning_line)"
chk_eq "values printing forged asn1parse lines: nothing written to stdout" "0" "$(stdout_bytes)"

skip_case() {  # skip_case <label> <pem> <reason>
    cat "$FIX/valid.pem" "$2" > "$FIX/skip-case.pem"
    run_case pem "$FIX/skip-case.pem"
    chk_eq "$1: collection partial" "partial" "${CERTS_COLLECTION_STATUS:-unset}"
    chk_eq "$1: only the other certificate is sent" "Patched Test Valid" "$(payload_eval '"|".join(c["subject_cn"] for c in d["certificates"])')"
    chk_eq "$1: warning names the reason" \
        "PATCHED_COLLECTION_WARNING section=certificates status=partial reason=$3 skipped=1" "$(warning_line)"
    chk_eq "$1: nothing written to stdout" "0" "$(stdout_bytes)"
}
skip_case "basicConstraints repeated" "$FIX/dup-bc.pem" "extensions_ambiguous"
skip_case "basicConstraints cA BOOLEAN not DER" "$FIX/ber-bool.pem" "der_unparseable"
skip_case "extKeyUsage empty" "$FIX/empty-eku.pem" "der_unparseable"

##############################################################################
# 8. No certificates: an openable, empty store is a real observation, sent as
#    an empty array (the server prunes stored rows for it).
##############################################################################
echo "--- 8. No certificates present"

run_case empty
chk_eq "empty store -> []" "0" "$(json_eval "$CERTS_JSON_TMP" 'len(d)')"
chk_eq "empty store is a complete reading" "complete" "${CERTS_COLLECTION_STATUS:-unset}"
chk_eq "payload carries certificates: []" "[]" "$(payload_eval 'json.dumps(d["certificates"])')"
chk_eq "payload collection_status.certificates complete" "complete" "$(payload_status)"
chk_eq "keychain openability checked" "show-keychain-info /Library/Keychains/System.keychain" "$(tail -1 "$SECURITY_ARGS_LOG")"

##############################################################################
# 9. Missing, unreadable or malformed store output is unavailable, never "no
#    certificates": the payload omits the key, says unavailable, so the server
#    keeps its rows, and one warning line names the reason.
##############################################################################
echo "--- 9. Unreadable or malformed store"

unavailable_case() {  # unavailable_case <label> <reason>
    chk_eq "$1: collection unavailable" "unavailable" "${CERTS_COLLECTION_STATUS:-unset}"
    chk_eq "$1: certificates key omitted from payload" "False" "$(payload_eval '"certificates" in d')"
    chk_eq "$1: payload collection_status.certificates unavailable" "unavailable" "$(payload_status)"
    chk_eq "$1: payload still valid JSON" "True" "$(payload_eval '"apps" in d and "hardware_health" in d')"
    chk_eq "$1: warning names the reason" \
        "PATCHED_COLLECTION_WARNING section=certificates status=unavailable reason=$2" "$(warning_line)"
    chk_eq "$1: nothing written to stdout" "0" "$(stdout_bytes)"
}

run_case fail
unavailable_case "security exits non-zero" "security_exit_50"

run_case unopenable
unavailable_case "keychain unopenable, security silent" "keychain_unopenable"

run_case garbage
unavailable_case "non-PEM store output" "non_certificate_output"

head -5 "$FIX/valid.pem" > "$FIX/truncated.pem"
run_case pem "$FIX/truncated.pem"
unavailable_case "PEM block with no END line" "truncated_certificate"

{ cat "$FIX/valid.pem"; print -r -- "security: trailing diagnostic"; } > "$FIX/valid-plus-text.pem"
run_case pem "$FIX/valid-plus-text.pem"
unavailable_case "valid cert followed by non-PEM text" "non_certificate_output"

# A store-level failure outranks a skipped certificate: the output read so
# far cannot be trusted to be the whole store.
{ cat "$FIX/corrupt.pem" "$FIX/valid.pem"; print -r -- "security: trailing diagnostic"; } > "$FIX/corrupt-valid-text.pem"
run_case pem "$FIX/corrupt-valid-text.pem"
unavailable_case "skipped cert then non-PEM text" "non_certificate_output"

##############################################################################
# 10. A certificate that cannot be parsed in a store that was read is left
#     out and the collection is partial: the certificates that parsed are
#     sent (the server upserts them and prunes nothing). When nothing parsed
#     the key is omitted, so an older server that ignores collection_status
#     cannot read [] as "prune every row".
##############################################################################
echo "--- 10. Partial collection"

partial_case() {  # partial_case <label> <sent subject_cns or "-" for key omitted> <reason> <skipped>
    chk_eq "$1: collection partial" "partial" "${CERTS_COLLECTION_STATUS:-unset}"
    if [[ "$2" == "-" ]]; then
        chk_eq "$1: certificates key omitted from payload" "False" "$(payload_eval '"certificates" in d')"
    else
        chk_eq "$1: parsed certificates sent" "$2" "$(payload_eval '"|".join(c["subject_cn"] for c in d["certificates"])')"
    fi
    chk_eq "$1: payload collection_status.certificates partial" "partial" "$(payload_status)"
    chk_eq "$1: payload still valid JSON" "True" "$(payload_eval '"apps" in d and "hardware_health" in d')"
    chk_eq "$1: warning names the reason and count" \
        "PATCHED_COLLECTION_WARNING section=certificates status=partial reason=$3 skipped=$4" "$(warning_line)"
    chk_eq "$1: nothing written to stdout" "0" "$(stdout_bytes)"
}

cat "$FIX/corrupt.pem" "$FIX/valid.pem" > "$FIX/corrupt-plus-valid.pem"
run_case pem "$FIX/corrupt-plus-valid.pem"
partial_case "corrupt PEM block before a valid cert" "Patched Test Valid" "certificate_unparseable" "1"

cat "$FIX/valid.pem" "$FIX/corrupt.pem" "$FIX/expired.pem" > "$FIX/valid-corrupt-expired.pem"
run_case pem "$FIX/valid-corrupt-expired.pem"
partial_case "corrupt PEM block between two valid certs" "Patched Test Valid|Patched Test Expired" "certificate_unparseable" "1"

cat "$FIX/corrupt.pem" "$FIX/dup-bc.pem" "$FIX/valid.pem" > "$FIX/two-skips.pem"
run_case pem "$FIX/two-skips.pem"
partial_case "two unparseable certs, first reason kept" "Patched Test Valid" "certificate_unparseable" "2"

cat "$FIX/corrupt.pem" "$FIX/corrupt.pem" > "$FIX/all-corrupt.pem"
run_case pem "$FIX/all-corrupt.pem"
partial_case "nothing parsed" "-" "certificate_unparseable" "2"

##############################################################################
# 11. The payload never reports a state collect_certs did not set. Before the
#     collector runs (the patched-collect.sh stub) or with an unknown value,
#     the key is omitted and collection_status says unavailable.
##############################################################################
echo "--- 11. Status before collection or unknown"

PATCHED_TMPDIR=$(mktemp -d)
CERTS_JSON_TMP="$PATCHED_TMPDIR/certs-stub.json"
print -r -- '[]' > "$CERTS_JSON_TMP"
for CERTS_COLLECTION_STATUS in "unavailable" "undetermined" "" "COMPLETE"; do
    CERTS_COLLECTED_COUNT=0
    chk_eq "status '$CERTS_COLLECTION_STATUS': certificates key omitted" "False" "$(payload_eval '"certificates" in d')"
    chk_eq "status '$CERTS_COLLECTION_STATUS': collection_status unavailable" "unavailable" "$(payload_status)"
done
unset CERTS_COLLECTION_STATUS
chk_eq "status unset: certificates key omitted" "False" "$(payload_eval '"certificates" in d')"
chk_eq "status unset: collection_status unavailable" "unavailable" "$(payload_status)"

echo
echo "RESULT: pass=$pass fail=$fail known_gaps=$gaps"
[[ $fail -eq 0 ]]
