package platformroot

import (
	"context"
	"crypto/sha1" //nolint:gosec // fingerprint algorithm, not a security primitive — must match device_certificates.sha1 (agent-computed X509 SHA-1 thumbprint)
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// AppleRootListURL is the CCADB report for Apple's Trusted Root Program, TLS
// Server Authentication trust bit. Confirmed live and fetchable while
// researching PAT-1738:
//
//	curl -s "https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=AppleTLSServerAuthenticationCSV"
//
// Columns (as observed): "CA Owner","Certificate Name","SHA-256
// Fingerprint","SPKI SHA256","Valid From (GMT)","Valid To (GMT)","Full CRL
// Issued By This CA","JSON Array of Partitioned CRLs","X.509 Certificate
// (PEM)","Apple Status","Apple Applied Constraints". 122 rows observed, all
// "Apple Status"=Included (this report is pre-filtered to the TLS Server
// Authentication trust bit; Apple roots trusted only for S/MIME or code
// signing are out of scope for this v1 — see the package doc note below).
//
// Apple's CCADB report gives only a SHA-256 fingerprint, never SHA-1 — but
// device_certificates.sha1 (and the Windows/macOS agents' own collected
// fingerprint) is SHA-1. Rather than change the join key or require the
// agents to also collect SHA-256, this report's embedded PEM certificate
// ("X.509 Certificate (PEM)") is parsed and its SHA-1 fingerprint computed
// server-side with the same definition both agents use (SHA-1 over the DER
// bytes) — an authoritative recomputation, not a guess.
//
// KNOWN LIMITATION: this covers Apple's TLS Server Authentication trust bit
// only, the trust bit relevant to HTTPS interception (the primary rogue-root
// risk this ticket targets). An Apple root trusted only for S/MIME,
// timestamping or code signing is not in this list. Widening to
// AppleSMIMECSV / AppleTimestampingCSV etc. is a follow-up if that gap
// matters in practice, not done here to keep this fetch bounded.
const AppleRootListURL = "https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=AppleTLSServerAuthenticationCSV"

const appleStatusIncluded = "Included"

// ParseAppleCSV parses the CCADB Apple TLS Server Authentication report CSV
// into RootCert records, computing each row's SHA-1 thumbprint from its
// embedded PEM certificate. Keeps only rows whose Apple Status is Included.
func ParseAppleCSV(data []byte, sourceURL string, fetchedAt time.Time) ([]RootCert, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read apple csv header: %w", err)
	}
	col := indexHeader(header)
	nameIdx, ok := col["Certificate Name"]
	if !ok {
		return nil, fmt.Errorf("apple csv: missing %q column", "Certificate Name")
	}
	pemIdx, ok := col["X.509 Certificate (PEM)"]
	if !ok {
		return nil, fmt.Errorf("apple csv: missing %q column", "X.509 Certificate (PEM)")
	}
	statusIdx, ok := col["Apple Status"]
	if !ok {
		return nil, fmt.Errorf("apple csv: missing %q column", "Apple Status")
	}

	var out []RootCert
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read apple csv row: %w", err)
		}
		if statusIdx >= len(row) || pemIdx >= len(row) {
			continue
		}
		if row[statusIdx] != appleStatusIncluded {
			continue
		}
		block, _ := pem.Decode([]byte(row[pemIdx]))
		if block == nil {
			// Row parses as CSV but the PEM cell isn't PEM (or is truncated,
			// or the column moved) — a CCADB format change wouldn't fail
			// loudly otherwise, so this is a real Included root going
			// missing from platform_root_certificates. Log rather than lose
			// the signal (PAT-1738 review).
			slog.Warn("platformroot: apple csv row skipped, PEM decode failed", "name", nameFor(row, nameIdx))
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Warn("platformroot: apple csv row skipped, certificate parse failed", "name", nameFor(row, nameIdx), "err", err)
			continue
		}
		sum := sha1.Sum(cert.Raw)
		cn := cert.Subject.CommonName
		if cn == "" && nameIdx < len(row) {
			cn = row[nameIdx]
		}
		out = append(out, RootCert{
			ThumbprintSHA1: hex.EncodeToString(sum[:]),
			Platform:       PlatformMacOS,
			Source:         SourceAppleCCADBTLSServer,
			SourceURL:      sourceURL,
			SubjectCN:      cn,
			FetchedAt:      fetchedAt,
		})
	}
	return out, nil
}

// FetchAppleRoots downloads and parses the live Apple CCADB report. url
// defaults to AppleRootListURL when empty.
func FetchAppleRoots(ctx context.Context, url string) ([]RootCert, error) {
	if url == "" {
		url = AppleRootListURL
	}
	body, err := fetch(ctx, url, SourceAppleCCADBTLSServer)
	if err != nil {
		return nil, fmt.Errorf("fetch apple root list: %w", err)
	}
	return ParseAppleCSV(body, url, time.Now().UTC())
}

// nameFor returns row[idx] for a log field, or "" if idx is out of bounds —
// never panics on a malformed row.
func nameFor(row []string, idx int) string {
	if idx < 0 || idx >= len(row) {
		return ""
	}
	return row[idx]
}
