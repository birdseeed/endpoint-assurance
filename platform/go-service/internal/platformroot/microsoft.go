package platformroot

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

// MicrosoftRootListURL is the CCADB "Included CA Certificate Report" for the
// Microsoft Trusted Root Program — the CA list Windows' Root/CA stores are
// ultimately sourced from (distributed via authroot.stl / Windows Update).
// CCADB is the industry-standard clearinghouse Microsoft, Apple, Mozilla and
// Chrome jointly publish root-program membership through; this specific
// report was confirmed live and fetchable (CSV, ~530 rows including
// historical Disabled/Removed entries) while researching PAT-1738:
//
//	curl -s https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV
//
// Columns (as observed): "Microsoft Status","CA Owner","CA Common Name or
// Certificate Name","Subject","SHA-1 Fingerprint","SHA-256
// Fingerprint","Microsoft EKUs","Valid From [GMT]","Valid To
// [GMT]","Public Key Algorithm","Signature Hash Algorithm". SHA-1 is given
// directly, so no PEM parsing or re-hashing is needed for this platform.
const MicrosoftRootListURL = "https://ccadb.my.salesforce-sites.com/microsoft/IncludedCACertificateReportForMSFTCSV"

// microsoftStatusIncluded is the "Microsoft Status" value for a CA currently
// trusted by the Microsoft Trusted Root Program. The report also lists
// "Disabled" and other historical statuses for CAs that used to be included
// — those are deliberately excluded (a Disabled root should not classify a
// device certificate as a legitimate platform root).
const microsoftStatusIncluded = "Included"

// ParseMicrosoftCSV parses the CCADB Microsoft Included CA Certificate
// Report CSV into RootCert records, keeping only currently-Included rows.
func ParseMicrosoftCSV(data []byte, sourceURL string, fetchedAt time.Time) ([]RootCert, error) {
	r := csv.NewReader(strings.NewReader(string(data)))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	header, err := r.Read()
	if err != nil {
		return nil, fmt.Errorf("read microsoft csv header: %w", err)
	}
	col := indexHeader(header)
	statusIdx, ok := col["Microsoft Status"]
	if !ok {
		return nil, fmt.Errorf("microsoft csv: missing %q column", "Microsoft Status")
	}
	cnIdx, ok := col["CA Common Name or Certificate Name"]
	if !ok {
		return nil, fmt.Errorf("microsoft csv: missing %q column", "CA Common Name or Certificate Name")
	}
	sha1Idx, ok := col["SHA-1 Fingerprint"]
	if !ok {
		return nil, fmt.Errorf("microsoft csv: missing %q column", "SHA-1 Fingerprint")
	}

	var out []RootCert
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read microsoft csv row: %w", err)
		}
		if statusIdx >= len(row) || sha1Idx >= len(row) {
			// A short row (fewer columns than the header promised) is a real
			// CCADB format change, not routine — log rather than lose the
			// signal (PAT-1738 review).
			slog.Warn("platformroot: microsoft csv row skipped, short row", "columns", len(row))
			continue
		}
		if row[statusIdx] != microsoftStatusIncluded {
			continue
		}
		sha1 := strings.ToLower(strings.TrimSpace(row[sha1Idx]))
		if sha1 == "" {
			slog.Warn("platformroot: microsoft csv row skipped, empty SHA-1 fingerprint", "name", nameFor(row, cnIdx))
			continue
		}
		cn := ""
		if cnIdx < len(row) {
			cn = row[cnIdx]
		}
		out = append(out, RootCert{
			ThumbprintSHA1: sha1,
			Platform:       PlatformWindows,
			Source:         SourceMicrosoftCCADB,
			SourceURL:      sourceURL,
			SubjectCN:      cn,
			FetchedAt:      fetchedAt,
		})
	}
	return out, nil
}

// FetchMicrosoftRoots downloads and parses the live Microsoft CCADB report.
// url defaults to MicrosoftRootListURL when empty.
func FetchMicrosoftRoots(ctx context.Context, url string) ([]RootCert, error) {
	if url == "" {
		url = MicrosoftRootListURL
	}
	body, err := fetch(ctx, url, SourceMicrosoftCCADB)
	if err != nil {
		return nil, fmt.Errorf("fetch microsoft root list: %w", err)
	}
	return ParseMicrosoftCSV(body, url, time.Now().UTC())
}

// indexHeader maps each CSV header column name to its index.
func indexHeader(header []string) map[string]int {
	idx := make(map[string]int, len(header))
	for i, h := range header {
		idx[strings.TrimSpace(h)] = i
	}
	return idx
}
