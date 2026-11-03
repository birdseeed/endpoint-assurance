# certs.sh — system keychain certificate inventory with expiry visibility.
# Sets CERTS_JSON_TMP (path to the temp JSON array file),
# CERTS_COLLECTION_STATUS ("complete" | "partial" | "unavailable") and
# CERTS_COLLECTED_COUNT (certificates written to CERTS_JSON_TMP).
# The temp file is consumed by the main script's JSON assembly (through
# certs_payload_member and certs_collection_status) and cleaned up after the
# heredoc runs.
# Sourced by patched-collect.sh; not executable directly.
#
# ABSENCE REQUIRES AUTHORITY (PAT-1709, PAT-1732). The payload contract gives
# the top-level `certificates` key these meanings (payload.schema.json,
# upsertCertificates in the platform repo):
#   key absent        -> no opinion, the server leaves stored rows alone
#   []                -> the agent read the store and it is empty, prune all
#   non-empty array   -> upsert these, prune every stored cert not listed
# and the top-level `collection_status.certificates` value qualifies it:
#   complete          -> the rules above apply
#   partial           -> upsert the certificates sent, prune nothing
#   unavailable       -> write nothing
#
# complete: the whole System keychain was read and every certificate in it
#   parsed. The array is sent, [] included.
# partial: the store itself was read, but one or more PEM blocks in it could
#   not be classified (openssl or date cannot parse it, its DER structure does
#   not walk cleanly, or its basicConstraints or extKeyUsage is repeated or
#   malformed). Those certificates are left out and the
#   rest are sent. When nothing parsed the key is omitted, because an empty
#   partial array carries no information and an older server that ignores
#   collection_status would read [] as "prune every row".
# unavailable: the store could not be read as a whole (tools missing,
#   keychain unopenable, `security` failing, printing something that is not
#   PEM, or ending mid-certificate). The key is omitted.
# Anything other than complete logs one PATCHED_COLLECTION_WARNING line to
# stderr naming the reason.

CERTS_KEYCHAIN="/Library/Keychains/System.keychain"

# Extract the CN component from an openssl subject/issuer output line.
# Handles both LibreSSL legacy format (/CN=value slash-delimited) and modern
# OpenSSL format (CN = value comma-delimited). Uses PYTHON3 (set by main
# script) for reliable regex — same dependency as json_escape.
_certs_extract_cn() {
    local line="$1"
    printf '%s' "$line" | "$PYTHON3" -c '
import re, sys
s = sys.stdin.read()
# Matches /CN=value (legacy) or ,CN = value or leading CN = value (modern)
m = re.search(r"(?:^|[/,\s])CN\s*=\s*([^/,]+)", s)
if m:
    print(m.group(1).strip(), end="")
' 2>/dev/null
}

# _certs_parse_extensions
#   stdin:  ONE PEM certificate block.
#   stdout: "<ext_key_usage JSON array><TAB><true|false>" on success.
#   exit:   0 ok, 2 `openssl x509 -outform DER | od` failed or printed nothing
#           usable, 3 ambiguous (basicConstraints or extKeyUsage appears
#           twice), 4 the DER structure, or a basicConstraints / extKeyUsage
#           value in it, is not in the shape X.509 requires.
#
# Classified from the certificate's DER bytes, never from a text rendering
# (PAT-1735, PAT-1740). `openssl x509 -text` prints subject strings and string
# extensions verbatim, so a certificate with no basicConstraints extension
# could print "CA:TRUE" and be reported as a CA. Stock macOS /usr/bin/openssl
# is LibreSSL, which has no `x509 -ext` (PAT-1709). `openssl asn1parse` is no
# better: it prints UTF8String, IA5String, PrintableString, T61String,
# VisibleString, NumericString, UTCTime, GeneralizedTime and any printable
# OCTET STRING raw, newlines included, and `-dump` does not change that on
# LibreSSL 3.3.6 (it only hex-dumps types asn1parse has no printer for). A
# walk over asn1parse lines therefore had to reject every certificate whose
# printed values contain line-shaped text (a subject attribute, or a private
# extension whose value is printable, holding newlines), which dropped valid
# certificates from the evidence.
#
# So no certificate byte is ever rendered as text here. `openssl x509 -outform
# DER` re-encodes the certificate openssl parsed, `od` prints every byte as two
# hex digits, and awk walks the DER itself: each TLV header is decoded from the
# bytes (definite lengths only), every element must fit exactly inside its
# parent, constructed elements are descended into and primitives are stepped
# over by their length, and the outer SEQUENCE must end at the last byte.
# There are no lines to forge: attacker-controlled content only ever reaches
# awk as hex digits inside a primitive the walk has already measured. Any bad
# byte, token or length skips the certificate.
#
# The walk also holds the certificate to the X.509 outline, so a length that
# reframes the bytes after it cannot yield another accepted structure: the
# Certificate SEQUENCE holds exactly TBSCertificate SEQUENCE,
# signatureAlgorithm and signature BIT STRING; TBSCertificate holds its fields
# in order ([0] version, serial INTEGER, signature, issuer, validity, subject,
# subjectPublicKeyInfo, optional [1], [2], [3]); an AlgorithmIdentifier is an
# OBJECT and at most one parameters value; a Name is non-empty SETs of
# SEQUENCE { OBJECT, value }; validity is two times; subjectPublicKeyInfo is
# an AlgorithmIdentifier and a BIT STRING.
#
# Extensions are found by position, not by searching: the [3] container that
# is a direct child of TBSCertificate (nothing may follow it) holds one
# SEQUENCE, and each Extension SEQUENCE in it is an OBJECT naming it (matched
# on its content bytes, 55 1D 13 or 55 1D 25), an optional critical BOOLEAN,
# then the extnValue OCTET STRING. basicConstraints is SEQUENCE { cA BOOLEAN OPTIONAL,
# pathLen INTEGER OPTIONAL } and is CA only when cA is present and TRUE (0xFF;
# an explicit 0x00 reads as false and any other byte skips the certificate);
# extKeyUsage is a non-empty SEQUENCE OF OBJECT IDENTIFIER, emitted as dotted
# OIDs (arbitrary-size arcs). An absent extension is [] / false, which is a
# real observation here because the whole structure parsed.
_certs_parse_extensions() {
    setopt localoptions pipefail
    local _certs_hex=""
    _certs_hex=$(/usr/bin/openssl x509 -outform DER 2>/dev/null | /usr/bin/od -An -v -tx1 2>/dev/null) || return 2
    [[ -n "${_certs_hex//[[:space:]]/}" ]] || return 2
    print -r -- "$_certs_hex" | LC_ALL=C /usr/bin/awk '
function fail(code) { if (!rc) rc = code; exit rc }

# Decimal-string arithmetic, so an OID arc of any size stays exact.
function muladd(s, m, a,    i, d, r, c) {
    c = a; r = ""
    for (i = length(s); i >= 1; i--) {
        d = substr(s, i, 1) * m + c
        r = (d % 10) r
        c = int(d / 10)
    }
    while (c > 0) { r = (c % 10) r; c = int(c / 10) }
    sub(/^0+/, "", r)
    return r == "" ? "0" : r
}
function subsmall(s, k,    i, d, r, b) {
    r = ""; b = 0
    for (i = length(s); i >= 1; i--) {
        d = substr(s, i, 1) - (k % 10) - b
        k = int(k / 10)
        if (d < 0) { d += 10; b = 1 } else b = 0
        r = d r
    }
    sub(/^0+/, "", r)
    return r == "" ? "0" : r
}

# One TLV header at B[p], which must fit before lim. Sets CLS (0 universal,
# 64 application, 128 context, 192 private), CONS (1 constructed), TAG,
# CSTART and CEND (content bounds). 0 on a truncated header, an indefinite
# length or content running past lim.
function tlv(p, lim,    b, n, i) {
    if (p >= lim) return 0
    b = B[p++]
    CLS = b - b % 64; CONS = int(b / 32) % 2; TAG = b % 32
    if (TAG == 31) {
        TAG = 0
        for (i = 0; ; i++) {
            if (p >= lim || i == 4) return 0
            b = B[p++]
            TAG = TAG * 128 + b % 128
            if (b < 128) break
        }
    }
    if (p >= lim) return 0
    b = B[p++]
    if (b < 128) n = b
    else {
        if (b == 128 || b > 132) return 0
        i = b - 128; n = 0
        while (i-- > 0) { if (p >= lim) return 0; n = n * 256 + B[p++] }
    }
    if (p + n > lim) return 0
    CSTART = p; CEND = p + n
    return 1
}

# DER length at B[p], before lim; sets LEN and HDRLEN (length octets).
function derlen(p, lim,    n, i) {
    if (p >= lim) return 0
    if (B[p] < 128) { LEN = B[p]; HDRLEN = 1; return 1 }
    n = B[p] - 128
    if (n < 1 || n > 3 || p + n >= lim) return 0
    LEN = 0
    for (i = 1; i <= n; i++) LEN = LEN * 256 + B[p + i]
    HDRLEN = 1 + n
    return 1
}

# basicConstraints extnValue in B[s..e-1].
function parse_bc(s, e,    p, end_) {
    if (e - s < 2 || B[s] != 48 || !derlen(s + 1, e)) fail(4)
    p = s + 1 + HDRLEN; end_ = p + LEN
    if (end_ != e) fail(4)
    ca = "false"
    if (p < end_ && B[p] == 1) {
        if (p + 2 >= end_ || B[p + 1] != 1) fail(4)
        if (B[p + 2] == 255) ca = "true"
        else if (B[p + 2] != 0) fail(4)
        p += 3
    }
    if (p < end_ && B[p] == 2) {
        if (!derlen(p + 1, end_) || LEN < 1) fail(4)
        p += 1 + HDRLEN + LEN
    }
    if (p != end_) fail(4)
}

# extKeyUsage extnValue in B[s..e-1].
function parse_eku(s, e,    p, end_, q, qend, v, first, oid, count) {
    if (e - s < 2 || B[s] != 48 || !derlen(s + 1, e)) fail(4)
    p = s + 1 + HDRLEN; end_ = p + LEN
    if (end_ != e) fail(4)
    eku = ""; count = 0
    while (p < end_) {
        if (B[p] != 6 || !derlen(p + 1, end_) || LEN < 1) fail(4)
        q = p + 1 + HDRLEN; qend = q + LEN
        if (qend > end_ || B[qend - 1] >= 128) fail(4)
        oid = ""; first = 1
        while (q < qend) {
            if (B[q] == 128) fail(4)
            v = "0"
            while (B[q] >= 128) { v = muladd(v, 128, B[q] - 128); q++ }
            v = muladd(v, 128, B[q]); q++
            if (first) {
                if (length(v) < 3 && v + 0 < 40) oid = "0." v
                else if (length(v) < 3 && v + 0 < 80) oid = "1." (v - 40)
                else oid = "2." subsmall(v, 80)
                first = 0
            } else oid = oid "." v
        }
        eku = eku (count ? ", " : "") "\"" oid "\""
        count++
        p = qend
    }
    if (count == 0) fail(4)
}

# A container closed: check what its role requires.
function close_top(    r, c) {
    r = ROLE[top]; c = CHILD[top]
    if (r == "cert" && c != 3) fail(4)
    if (r == "tbs" && TBS_AT < 7) fail(4)
    if ((r == "alg" || r == "rdn" || r == "version") && c < 1) fail(4)
    if ((r == "atv" || r == "validity" || r == "spki") && c != 2) fail(4)
    if (r == "ext") {
        if (!ext_have_oid || !ext_have_value) fail(4)
        if (ext_kind == "bc") parse_bc(ext_vs, ext_ve)
        else if (ext_kind == "eku") parse_eku(ext_vs, ext_ve)
    }
    top--
}

function walk(    p, parent, role, seq, slot) {
    p = 0; top = 0
    while (p < nb) {
        while (top > 0 && END_AT[top] == p) close_top()
        if (top == 0 && p > 0) fail(4)
        if (!tlv(p, top > 0 ? END_AT[top] : nb)) fail(4)
        seq = (CLS == 0 && CONS && TAG == 16)
        parent = (top > 0) ? ROLE[top] : "top"
        if (top > 0) CHILD[top]++
        role = ""

        if (parent == "top") {
            if (!seq) fail(4)
            role = "cert"
        } else if (parent == "cert") {
            if (CHILD[top] == 1) { if (!seq) fail(4); role = "tbs"; TBS_AT = 0 }
            else if (CHILD[top] == 2) { if (!seq) fail(4); role = "alg" }
            else if (CHILD[top] == 3) { if (CLS != 0 || CONS || TAG != 3) fail(4) }
            else fail(4)
        } else if (parent == "tbs") {
            # TBSCertificate fields, in order: [0] version (optional), serial
            # INTEGER, signature, issuer, validity, subject and
            # subjectPublicKeyInfo SEQUENCEs, then [1] and [2] unique IDs and
            # [3] extensions, each optional. Nothing may follow [3].
            if (CLS == 128 && CONS && TAG == 0) slot = 1
            else if (CLS == 0 && !CONS && TAG == 2) slot = 2
            else if (seq && TBS_AT >= 2 && TBS_AT <= 6) slot = TBS_AT + 1
            else if (CLS == 128 && !CONS && TAG == 1) slot = 8
            else if (CLS == 128 && !CONS && TAG == 2) slot = 9
            else if (CLS == 128 && CONS && TAG == 3) slot = 10
            else fail(4)
            if (slot <= TBS_AT) fail(4)
            if (slot >= 3 && slot <= 7 && slot != TBS_AT + 1) fail(4)
            if (slot == 2 && TBS_AT > 1) fail(4)
            if (slot >= 8 && TBS_AT < 7) fail(4)
            TBS_AT = slot
            if (slot == 1) role = "version"
            else if (slot == 3) role = "alg"
            else if (slot == 4 || slot == 6) role = "name"
            else if (slot == 5) role = "validity"
            else if (slot == 7) role = "spki"
            else if (slot == 10) role = "extwrap"
        } else if (parent == "version") {
            if (CHILD[top] != 1 || CLS != 0 || CONS || TAG != 2) fail(4)
        } else if (parent == "alg") {
            # AlgorithmIdentifier: OBJECT, then at most one parameters value.
            if (CHILD[top] == 1) { if (CLS != 0 || CONS || TAG != 6) fail(4) }
            else if (CHILD[top] > 2) fail(4)
        } else if (parent == "name") {
            if (CLS != 0 || !CONS || TAG != 17) fail(4)
            role = "rdn"
        } else if (parent == "rdn") {
            if (!seq) fail(4)
            role = "atv"
        } else if (parent == "atv") {
            # AttributeTypeAndValue: OBJECT, then one value of any type.
            if (CHILD[top] == 1) { if (CLS != 0 || CONS || TAG != 6) fail(4) }
            else if (CHILD[top] > 2) fail(4)
        } else if (parent == "validity") {
            # notBefore and notAfter: UTCTime or GeneralizedTime.
            if (CHILD[top] > 2 || CLS != 0 || CONS || (TAG != 23 && TAG != 24)) fail(4)
        } else if (parent == "spki") {
            if (CHILD[top] == 1) { if (!seq) fail(4); role = "alg" }
            else if (CHILD[top] != 2 || CLS != 0 || CONS || TAG != 3) fail(4)
        } else if (parent == "extwrap") {
            if (CHILD[top] != 1 || !seq || CEND != END_AT[top]) fail(4)
            role = "exts"
        } else if (parent == "exts") {
            if (!seq) fail(4)
            role = "ext"
            ext_have_oid = 0; ext_have_value = 0; ext_kind = ""
        } else if (parent == "ext") {
            if (CONS || CLS != 0 || ext_have_value) fail(4)
            if (CHILD[top] == 1) {
                if (TAG != 6) fail(4)
                ext_have_oid = 1
                if (CEND - CSTART == 3 && B[CSTART] == 85 && B[CSTART + 1] == 29) {
                    if (B[CSTART + 2] == 19) {
                        if (seen_bc) fail(3)
                        seen_bc = 1; ext_kind = "bc"
                    } else if (B[CSTART + 2] == 37) {
                        if (seen_eku) fail(3)
                        seen_eku = 1; ext_kind = "eku"
                    }
                }
            } else if (CHILD[top] == 2 && TAG == 1) {
                # critical flag: not reported
            } else if (TAG == 4) {
                ext_have_value = 1; ext_vs = CSTART; ext_ve = CEND
            } else fail(4)
        }

        if (CONS) {
            if (top == 128) fail(4)
            top++; ROLE[top] = role; END_AT[top] = CEND; CHILD[top] = 0
            p = CSTART
        } else p = CEND
    }
    while (top > 0 && END_AT[top] == p) close_top()
    if (top != 0) fail(4)
}

BEGIN {
    HEX = "0123456789abcdef"
    rc = 0; nb = 0
    seen_bc = 0; seen_eku = 0
    ca = "false"; eku = ""
}

{
    for (i = 1; i <= NF; i++) {
        if ($i !~ /^[0-9a-f][0-9a-f]$/) fail(2)
        B[nb++] = (index(HEX, substr($i, 1, 1)) - 1) * 16 + index(HEX, substr($i, 2, 1)) - 1
    }
}

END {
    if (rc) exit rc
    if (nb == 0) exit 2
    walk()
    printf "[%s]\t%s\n", eku, ca
}
' 2>/dev/null
}

# certs_payload_member
#   Prints the `"certificates": [...],` payload member (trailing comma
#   included) when collection is complete, or partial with at least one
#   certificate read, and nothing otherwise, so the payload heredoc omits the
#   key and the server keeps its stored rows.
certs_payload_member() {
    case "$(certs_collection_status)" in
        complete) ;;
        partial) (( ${CERTS_COLLECTED_COUNT:-0} > 0 )) || return 0 ;;
        *) return 0 ;;
    esac
    [[ -n "${CERTS_JSON_TMP:-}" && -s "$CERTS_JSON_TMP" ]] || return 0
    printf '"certificates": %s,' "$(cat "$CERTS_JSON_TMP")"
}

# certs_collection_status
#   Prints the wire value for collection_status.certificates: complete,
#   partial or unavailable. Anything else (unset, a stub, a typo) is
#   unavailable, so the server never treats an unknown state as a reading.
certs_collection_status() {
    case "${CERTS_COLLECTION_STATUS:-}" in
        complete|partial) print -r -- "$CERTS_COLLECTION_STATUS" ;;
        *) print -r -- "unavailable" ;;
    esac
}

collect_certs() {
    CERTS_JSON_TMP=$(mktemp "$PATCHED_TMPDIR/certs.XXXXXX")  # H11: root-owned 0700 dir, not /tmp
    CERTS_COLLECTION_STATUS="unavailable"
    CERTS_COLLECTED_COUNT=0

    # Every local is declared once, here. zsh prints `name=value` to stdout
    # when `local name` re-runs on a name that is already local, so a
    # declaration inside the per-cert loop leaked earlier certs' fields into
    # the collector's stdout (PAT-1709).
    local certs_first=true fail_reason="" pem_data="" security_rc=0 now_epoch=""
    local skip_reason="" skipped_count=0
    local line="" pem_block="" in_block=false ext_rc=0 ext_out=""
    local cert_info="" subject_line="" issuer_line="" enddate_line="" fingerprint_line=""
    local enddate_str="" not_after="" not_after_epoch="" diff=0 days_until_expiry=0
    local subject_cn="" issuer_cn="" sha1="" eku_json="" bc_ca="" subj_dn="" issuer_dn="" is_self_signed=""

    echo "[" > "$CERTS_JSON_TMP"

    if [[ ! -x "/usr/bin/security" ]] || [[ ! -x "/usr/bin/openssl" ]] || [[ ! -x "/usr/bin/awk" ]] || [[ ! -x "/usr/bin/od" ]]; then
        fail_reason="tools_missing"
    fi

    if [[ -z "$fail_reason" ]]; then
        pem_data=$(/usr/bin/security find-certificate -a -p "$CERTS_KEYCHAIN" 2>/dev/null)
        security_rc=$?
        if (( security_rc != 0 )); then
            fail_reason="security_exit_${security_rc}"
        elif [[ -z "$pem_data" ]]; then
            # `security find-certificate` exits 0 with no output for a missing,
            # unreadable or corrupt keychain as well as for an empty one
            # (verified on macOS 26). Only an openable keychain makes empty
            # output a real observation.
            if ! /usr/bin/security show-keychain-info "$CERTS_KEYCHAIN" >/dev/null 2>&1; then
                fail_reason="keychain_unopenable"
            fi
        fi
    fi

    if [[ -z "$fail_reason" && -n "$pem_data" ]]; then
        now_epoch=$(date -u +%s)

        # Accumulate lines into pem_block. Each complete PEM block costs two
        # openssl calls: `x509` for the identity and expiry fields, then
        # `x509 -outform DER` (hex-dumped by od) for the extensions.
        while IFS= read -r line || [[ -n "$line" ]]; do
            if [[ "$in_block" == "false" ]]; then
                [[ -z "${line//[[:space:]]/}" ]] && continue
                if [[ "$line" != "-----BEGIN CERTIFICATE-----" ]]; then
                    fail_reason="non_certificate_output"
                    break
                fi
                in_block=true
                pem_block=""
            fi
            pem_block+="${line}"$'\n'
            [[ "$line" != "-----END CERTIFICATE-----" ]] && continue
            in_block=false

            cert_info=$(printf '%s' "$pem_block" | /usr/bin/openssl x509 -noout -subject -issuer -enddate -fingerprint -sha1 2>/dev/null) || cert_info=""
            ext_out=""
            ext_rc=2
            if [[ -n "$cert_info" ]]; then
                ext_out=$(printf '%s' "$pem_block" | _certs_parse_extensions)
                ext_rc=$?
            fi
            pem_block=""

            # From here on a failure belongs to this one certificate, not to
            # the store: record it, skip the certificate and keep reading.
            if [[ -z "$cert_info" ]]; then
                (( skipped_count += 1 ))
                [[ -n "$skip_reason" ]] || skip_reason="certificate_unparseable"
                continue
            fi

            subject_line=$(printf '%s\n' "$cert_info" | grep "^subject=")
            issuer_line=$(printf '%s\n'  "$cert_info" | grep "^issuer=")
            enddate_line=$(printf '%s\n' "$cert_info" | grep "^notAfter=")
            fingerprint_line=$(printf '%s\n' "$cert_info" | grep "^SHA1 Fingerprint=")

            # Parse expiry. openssl prints: "notAfter=Jun  5 12:00:00 2027 GMT"
            # BSD date %e is space-padded day — matches openssl's " 5" for single-digit days.
            enddate_str="${enddate_line#notAfter=}"
            not_after=$(date -ju -f "%b %e %T %Y %Z" "$enddate_str" "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || not_after=""
            not_after_epoch=$(date -ju -f "%b %e %T %Y %Z" "$enddate_str" "+%s" 2>/dev/null) || not_after_epoch=""

            if [[ -z "$not_after" ]] || [[ -z "$not_after_epoch" ]]; then
                (( skipped_count += 1 ))
                [[ -n "$skip_reason" ]] || skip_reason="expiry_unparseable"
                continue
            fi

            # floor((not_after - now) / 86400): shell integer division truncates toward
            # zero, so we adjust the numerator for negative values to get true floor.
            diff=$(( not_after_epoch - now_epoch ))
            if (( diff >= 0 )); then
                days_until_expiry=$(( diff / 86400 ))
            else
                days_until_expiry=$(( (diff - 86399) / 86400 ))
            fi

            subject_cn=$(_certs_extract_cn "$subject_line")
            issuer_cn=$(_certs_extract_cn "$issuer_line")
            # Strip label, remove colon separators between hex pairs, lowercase.
            sha1=$(printf '%s' "${fingerprint_line#SHA1 Fingerprint=}" | tr -d ':' | tr '[:upper:]' '[:lower:]')

            # ext_key_usage (OID array) and basic_constraints_ca, from the DER
            # structure (_certs_parse_extensions). Absent extension -> [] /
            # false; that is a real observation here because the whole
            # structure parsed. Anything else skips this certificate.
            if (( ext_rc != 0 )) || [[ "$ext_out" != *$'\t'* ]]; then
                (( skipped_count += 1 ))
                if [[ -z "$skip_reason" ]]; then
                    case "$ext_rc" in
                        3) skip_reason="extensions_ambiguous" ;;
                        *) skip_reason="der_unparseable" ;;
                    esac
                fi
                continue
            fi
            eku_json="${ext_out%%$'\t'*}"
            bc_ca="${ext_out#*$'\t'}"

            # is_self_signed: true iff subject DN equals issuer DN (full string, not just CN).
            subj_dn="${subject_line#subject=}"
            subj_dn="${subj_dn#" "}"
            issuer_dn="${issuer_line#issuer=}"
            issuer_dn="${issuer_dn#" "}"
            if [[ -n "$subj_dn" ]] && [[ "$subj_dn" == "$issuer_dn" ]]; then
                is_self_signed="true"
            else
                is_self_signed="false"
            fi

            if [[ "$certs_first" == "false" ]]; then
                echo "," >> "$CERTS_JSON_TMP"
            fi
            certs_first=false
            (( CERTS_COLLECTED_COUNT += 1 ))
            cat >> "$CERTS_JSON_TMP" <<EOF
{"subject_cn": $(json_escape "$subject_cn"), "issuer_cn": $(json_escape "$issuer_cn"), "sha1": $(json_escape "$sha1"), "not_after": $(json_escape "$not_after"), "days_until_expiry": $days_until_expiry, "ext_key_usage": $eku_json, "basic_constraints_ca": $bc_ca, "is_self_signed": $is_self_signed, "store": "System"}
EOF
        done <<< "$pem_data"

        if [[ -z "$fail_reason" && "$in_block" == "true" ]]; then
            fail_reason="truncated_certificate"
        fi
    fi

    echo "]" >> "$CERTS_JSON_TMP"

    # A store-level failure outranks skipped certificates: the output that was
    # read cannot be trusted to be the whole store, so nothing is sent.
    if [[ -n "$fail_reason" ]]; then
        CERTS_COLLECTION_STATUS="unavailable"
        echo "PATCHED_COLLECTION_WARNING section=certificates status=unavailable reason=${fail_reason}" >&2
    elif (( skipped_count > 0 )); then
        CERTS_COLLECTION_STATUS="partial"
        echo "PATCHED_COLLECTION_WARNING section=certificates status=partial reason=${skip_reason} skipped=${skipped_count}" >&2
    else
        CERTS_COLLECTION_STATUS="complete"
    fi
    return 0
}
