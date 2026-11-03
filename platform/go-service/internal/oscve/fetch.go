package oscve

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AdvisoryDocument struct {
	Source     Source
	ID         string
	URL        string
	Revision   string
	Advisories []Advisory
}

// httpClient is the shared client for vendor feed fetches. The fetchers are the
// live seam — they are deliberately thin so the parsers (ParseApple / ParseMSRC)
// can be unit-tested against committed fixtures without network access.
var httpClient = &http.Client{Timeout: 30 * time.Second}

// maxVendorResponseBytes bounds how much of a single vendor response body
// fetchOnce reads into memory (PAT-2041). Measured 2026-09-23 with a
// read-only curl against the live vendor endpoints: the MSRC updates
// catalogue was ~48KB, MSRC CVRF month documents ranged up to the largest
// observed, September 2026, at 17,698,349 bytes (~16.9 MiB — Patch Tuesday
// months run largest; July 2026 was the next biggest at ~12.4MB), Apple GDMF
// was ~70KB, the Apple security-releases page was ~315KB, and the CISA KEV
// catalogue was ~1.7MB. Set to at least 4x the largest measured body
// (~67.5MB), rounded up to a power-of-two MiB.
const maxVendorResponseBytes = 128 << 20 // 128 MiB

// vendorBodyLimit is the cap fetchOnce actually enforces. It is a package
// var only so tests can shrink it to exercise the overflow path without
// allocating a multi-hundred-MB body; production code must never change it
// and tests must restore it via t.Cleanup.
var vendorBodyLimit int64 = maxVendorResponseBytes

// FetchApple downloads the Apple security-releases payload and parses it into
// Advisory records. The agent build environment may have no outbound internet;
// callers running offline should parse a saved payload with ParseApple instead.
//
// NOTE: the canonical Apple page (AppleSecurityReleasesURL) is HTML; a production
// deployment fronts it with an extraction step that emits the AppleReleasesFeed
// JSON ParseApple consumes. This fetcher expects that JSON endpoint to be passed
// as url (e.g. an internal mirror), so the parsing contract stays stable.
func FetchApple(ctx context.Context, url string) ([]Advisory, error) {
	if url == "" {
		url = AppleSecurityReleasesURL
	}
	body, err := fetch(ctx, url, "apple", "security-releases")
	if err != nil {
		return nil, fmt.Errorf("fetch apple: %w", err)
	}
	return ParseApple(body)
}

// FetchMSRC downloads one explicitly named MSRC CVRF v3.0 document (identified
// by docID, e.g. "2024-Jun") for deterministic replay and operator recovery.
// The normal live path is FetchMSRCOfficial, which follows the updates catalogue.
func FetchMSRC(ctx context.Context, docID string) ([]Advisory, error) {
	url := MSRCBaseURL + "/document/" + docID
	body, err := fetch(ctx, url, "msrc", docID)
	if err != nil {
		return nil, fmt.Errorf("fetch msrc %s: %w", docID, err)
	}
	return ParseMSRC(body)
}

func FetchAppleOfficial(ctx context.Context, indexURL, gdmfURL string) ([]AdvisoryDocument, error) {
	if indexURL == "" {
		indexURL = AppleSecurityReleasesURL
	}
	if gdmfURL == "" {
		gdmfURL = AppleGDMFURL
	}
	indexBody, err := fetchAccept(ctx, indexURL, "text/html", "apple", "security-index")
	if err != nil {
		return nil, fmt.Errorf("fetch apple security index: %w", err)
	}
	releases, err := ParseAppleSecurityIndex(indexBody, indexURL)
	if err != nil {
		return nil, err
	}
	gdmfBody, err := fetchGDMF(ctx, gdmfURL)
	if err != nil {
		return nil, fmt.Errorf("fetch apple gdmf: %w", err)
	}
	builds, err := ParseAppleGDMF(gdmfBody)
	if err != nil {
		return nil, err
	}
	supportedMajors := map[string]bool{}
	for version := range builds {
		if parts, ok := numericVersion(version); ok && len(parts) > 0 {
			supportedMajors[fmt.Sprint(parts[0])] = true
		}
	}
	documents := make([]AdvisoryDocument, 0, len(releases))
	for _, release := range releases {
		if release.NoPublishedCVEs {
			continue
		}
		parts, comparable := numericVersion(release.Version)
		if !comparable || len(parts) == 0 || !supportedMajors[fmt.Sprint(parts[0])] {
			continue
		}
		body, fetchErr := fetchAccept(ctx, release.AdvisoryURL, "text/html", "apple", release.DocumentID)
		if fetchErr != nil {
			return nil, fmt.Errorf("fetch apple advisory %s: %w", release.DocumentID, fetchErr)
		}
		advisories, parseErr := ParseAppleAdvisoryHTML(body, release, builds[release.Version])
		if parseErr != nil {
			return nil, parseErr
		}
		documents = append(documents, AdvisoryDocument{Source: SourceApple, ID: release.DocumentID, URL: release.AdvisoryURL, Advisories: advisories})
	}
	if len(documents) == 0 {
		return nil, fmt.Errorf("apple official sources produced no advisory documents")
	}
	return documents, nil
}

func FetchMSRCOfficial(ctx context.Context, updatesURL string) ([]AdvisoryDocument, error) {
	if updatesURL == "" {
		updatesURL = MSRCUpdatesURL
	}
	body, err := fetchAccept(ctx, updatesURL, "application/json", "msrc", "updates-catalogue")
	if err != nil {
		return nil, fmt.Errorf("fetch msrc updates: %w", err)
	}
	updates, err := ParseMSRCUpdates(body)
	if err != nil {
		return nil, err
	}
	documents := make([]AdvisoryDocument, 0, len(updates))
	for _, update := range updates {
		year, yearErr := strconv.Atoi(strings.SplitN(update.ID, "-", 2)[0])
		if yearErr != nil || year < 2015 {
			continue
		} // Windows 10/11 endpoint scope.
		docBody, fetchErr := fetchAccept(ctx, update.CvrfURL, "application/json", "msrc", update.ID)
		if fetchErr != nil {
			return nil, fmt.Errorf("fetch msrc document %s: %w", update.ID, fetchErr)
		}
		advisories, parseErr := ParseMSRC(docBody)
		if parseErr != nil {
			return nil, fmt.Errorf("parse msrc document %s: %w", update.ID, parseErr)
		}
		for i := range advisories {
			advisories[i].SourceDocumentID = update.ID
		}
		// Documents without client Windows advisories are valid catalogue
		// members and are recorded with a zero count.
		documents = append(documents, AdvisoryDocument{Source: SourceMSRC, ID: update.ID, URL: update.CvrfURL, Revision: update.CurrentReleaseDate, Advisories: advisories})
	}
	if len(documents) == 0 {
		return nil, fmt.Errorf("msrc official sources produced no documents")
	}
	return documents, nil
}

func fetch(ctx context.Context, url, source, document string) ([]byte, error) {
	return fetchAccept(ctx, url, "application/json", source, document)
}

// fetchAccept fetches url with an explicit Accept header, retrying on a
// transient vendor error (PAT-2039). source/document identify the call for
// the retry WARN log only, e.g. "msrc"/"2015-Aug".
func fetchAccept(ctx context.Context, url, accept, source, document string) ([]byte, error) {
	return fetchAcceptWithClient(ctx, httpClient, url, accept, source, document)
}

func fetchGDMF(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	// The additional Apple root is deliberately scoped to the canonical GDMF
	// host. HTTP/HTTPS fixture and replay overrides keep using the configured
	// shared client and its normal trust policy.
	if !strings.EqualFold(parsed.Scheme, "https") || !strings.EqualFold(parsed.Hostname(), "gdmf.apple.com") {
		return fetchAccept(ctx, rawURL, "application/json", "apple", "gdmf")
	}
	client, err := newGDMFHTTPClient(httpClient)
	if err != nil {
		return nil, err
	}
	return fetchAcceptWithClient(ctx, client, rawURL, "application/json", "apple", "gdmf")
}

// fetchAcceptWithClient is the shared low-level fetch entrypoint. It retries
// transient vendor errors (5xx, 429, network timeouts/resets) with bounded
// backoff via fetchWithRetry — see retry.go — so a lone transient vendor
// blip (the MSRC 503 that failed the 2026-09-23 os-sync preflight) doesn't
// fail the whole run. A persistent failure, a fatal 4xx, or a decode error
// still returns an error exactly as before.
func fetchAcceptWithClient(ctx context.Context, client *http.Client, url, accept, source, document string) ([]byte, error) {
	return fetchWithRetry(ctx, client, url, accept, source, document)
}

// fetchOnce performs a single HTTP GET attempt with no retry. Errors are
// typed (vendorHTTPError / vendorTransportError) so fetchWithRetry can
// classify retryable-vs-fatal without matching a formatted message.
func fetchOnce(ctx context.Context, client *http.Client, url, accept string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	resp, err := client.Do(req)
	if err != nil {
		return nil, &vendorTransportError{err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &vendorHTTPError{
			StatusCode: resp.StatusCode,
			RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}
	// Read one byte past the limit so an exactly-at-limit body doesn't get
	// silently truncated and mistaken for the whole document: if the read
	// comes back longer than the limit, we know there was more to read.
	body, err := io.ReadAll(io.LimitReader(resp.Body, vendorBodyLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > vendorBodyLimit {
		return nil, &vendorBodyTooLargeError{Limit: vendorBodyLimit}
	}
	return body, nil
}

func ReplaceAdvisoryDocument(ctx context.Context, pool *pgxpool.Pool, document AdvisoryDocument) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin advisory document replacement: %w", err)
	}
	defer tx.Rollback(ctx) // no-op after Commit
	if _, err := tx.Exec(ctx, `DELETE FROM os_cve_advisories WHERE source=$1 AND source_document_id=$2`, string(document.Source), document.ID); err != nil {
		return fmt.Errorf("delete stale advisory document %s/%s: %w", document.Source, document.ID, err)
	}
	batch := &pgx.Batch{}
	for _, a := range document.Advisories {
		batch.Queue(`
			INSERT INTO os_cve_advisories
				(os_platform, os_version, os_build, cve_id, cvss_v3_score,
				 severity, fixed_in_build, source, vendor_title, advisory_url, published_at,
				 synced_at, source_document_id, vendor_reference)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,NOW(),$12,$13)
			ON CONFLICT (os_platform, os_version, os_build, cve_id, source) DO UPDATE SET
				cvss_v3_score=EXCLUDED.cvss_v3_score, severity=EXCLUDED.severity,
				fixed_in_build=EXCLUDED.fixed_in_build, advisory_url=EXCLUDED.advisory_url,
				vendor_title=EXCLUDED.vendor_title,
				published_at=EXCLUDED.published_at, synced_at=NOW(),
				source_document_id=EXCLUDED.source_document_id,
				vendor_reference=EXCLUDED.vendor_reference
		`, a.Platform, a.OSVersion, a.OSBuild, a.CVEID, a.Score, a.Severity,
			a.FixedInBuild, string(a.Source), a.VendorTitle, a.AdvisoryURL,
			a.PublishedAt, document.ID, a.VendorReference)
	}
	if batch.Len() > 0 {
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return fmt.Errorf("insert advisory document %s at %d: %w", document.ID, i, err)
			}
		}
		if err := br.Close(); err != nil {
			return fmt.Errorf("close advisory document batch %s: %w", document.ID, err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO os_cve_source_documents
			(source, document_id, document_url, source_revision, fetched_at, advisory_count)
		VALUES ($1,$2,$3,$4,NOW(),$5)
		ON CONFLICT (source, document_id) DO UPDATE SET
			document_url=EXCLUDED.document_url, source_revision=EXCLUDED.source_revision,
			fetched_at=NOW(), advisory_count=EXCLUDED.advisory_count
	`, string(document.Source), document.ID, document.URL, document.Revision, len(document.Advisories)); err != nil {
		return fmt.Errorf("record advisory document %s: %w", document.ID, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit advisory document %s: %w", document.ID, err)
	}
	return nil
}

func PruneSourceDocuments(ctx context.Context, pool *pgxpool.Pool, source Source, keep []string) (int64, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `DELETE FROM os_cve_advisories WHERE source=$1 AND NOT (source_document_id = ANY($2))`, string(source), keep)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM os_cve_source_documents WHERE source=$1 AND NOT (document_id = ANY($2))`, string(source), keep); err != nil {
		return 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// UpsertAdvisories writes Advisory records to os_cve_advisories, idempotent on the
// (os_platform, os_version, os_build, cve_id, source) unique key. Mirrors the
// batched upsert pattern of cmd/patched-cve-sync.upsertCVEs.
func UpsertAdvisories(ctx context.Context, pool *pgxpool.Pool, advisories []Advisory) (int, error) {
	const batchSize = 500
	total := 0
	for i := 0; i < len(advisories); i += batchSize {
		end := i + batchSize
		if end > len(advisories) {
			end = len(advisories)
		}
		batch := &pgx.Batch{}
		for _, a := range advisories[i:end] {
			batch.Queue(`
				INSERT INTO os_cve_advisories
					(os_platform, os_version, os_build, cve_id, cvss_v3_score,
					 severity, fixed_in_build, source, vendor_title, advisory_url, synced_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
				ON CONFLICT (os_platform, os_version, os_build, cve_id, source) DO UPDATE SET
					cvss_v3_score  = EXCLUDED.cvss_v3_score,
					severity       = EXCLUDED.severity,
					fixed_in_build = EXCLUDED.fixed_in_build,
					vendor_title   = EXCLUDED.vendor_title,
					advisory_url   = EXCLUDED.advisory_url,
					synced_at      = NOW()
			`, a.Platform, a.OSVersion, a.OSBuild, a.CVEID, a.Score,
				a.Severity, a.FixedInBuild, string(a.Source), a.VendorTitle, a.AdvisoryURL)
		}
		br := pool.SendBatch(ctx, batch)
		for j := 0; j < batch.Len(); j++ {
			if _, err := br.Exec(); err != nil {
				br.Close()
				return total, fmt.Errorf("upsert os advisory at offset %d: %w", i+j, err)
			}
		}
		if err := br.Close(); err != nil {
			return total, fmt.Errorf("batch close at offset %d: %w", i, err)
		}
		total += batch.Len()
	}
	return total, nil
}

// LoadAdvisories reads vendor OS advisories for one platform from the DB. The
// matcher (MatchOS) is pure, so this is the only DB read it needs.
func LoadAdvisories(ctx context.Context, pool *pgxpool.Pool, platform string) ([]Advisory, error) {
	rows, err := pool.Query(ctx, `
		SELECT os_platform, os_version, os_build, cve_id, cvss_v3_score,
		       COALESCE(severity,''), fixed_in_build, source, vendor_title, advisory_url
		FROM os_cve_advisories
		WHERE os_platform = $1
	`, platform)
	if err != nil {
		return nil, fmt.Errorf("query os advisories: %w", err)
	}
	defer rows.Close()
	var out []Advisory
	for rows.Next() {
		var a Advisory
		var src string
		if err := rows.Scan(&a.Platform, &a.OSVersion, &a.OSBuild, &a.CVEID,
			&a.Score, &a.Severity, &a.FixedInBuild, &src, &a.VendorTitle, &a.AdvisoryURL); err != nil {
			return nil, fmt.Errorf("scan os advisory: %w", err)
		}
		a.Source = Source(src)
		out = append(out, a)
	}
	return out, rows.Err()
}

// kevCatalog is a minimal placeholder for CISA KEV (known-exploited) flagging.
// STUB (PAT-409 optional scope): the KEV catalogue JSON is fetched from
// KEVCatalogURL and indexed by CVE so both app and OS findings can be flagged
// known-exploited. The fetch/index is implemented; wiring the flag through the
// report is a TODO.
const KEVCatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

type kevFeed struct {
	Vulnerabilities []struct {
		CVEID string `json:"cveID"`
	} `json:"vulnerabilities"`
}

// FetchKEV returns the set of known-exploited CVE IDs from the CISA KEV catalogue.
// Callers (app + OS finding paths) can flag findings whose CVE is in this set.
func FetchKEV(ctx context.Context, url string) (map[string]bool, error) {
	if url == "" {
		url = KEVCatalogURL
	}
	body, err := fetch(ctx, url, "cisa-kev", "kev-catalog")
	if err != nil {
		return nil, fmt.Errorf("fetch kev: %w", err)
	}
	return ParseKEV(body)
}

// ParseKEV indexes the CISA KEV catalogue payload into a set of CVE IDs.
func ParseKEV(data []byte) (map[string]bool, error) {
	var f kevFeed
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse kev: %w", err)
	}
	set := make(map[string]bool, len(f.Vulnerabilities))
	for _, v := range f.Vulnerabilities {
		if v.CVEID != "" {
			set[v.CVEID] = true
		}
	}
	return set, nil
}
