package cpepropose

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"patched.im/api/internal/httpretry"
)

// DefaultNVDCPEURL is NVD's CPE dictionary API.
const DefaultNVDCPEURL = "https://services.nvd.nist.gov/rest/json/cpes/2.0"

const (
	// MaxCandidates bounds the candidate list one proposal carries (and so
	// the prompt, the admin view and the enum in the model's schema).
	MaxCandidates = 20
	// nvdCPEPageSize is the one page read per keyword search. The result is
	// deduplicated to vendor:product pairs, so one page of CPE versions is
	// plenty for ranking and keeps a search to exactly one request.
	nvdCPEPageSize = 500
	// maxTitleRunes bounds an NVD title carried into a candidate.
	maxTitleRunes = 200
	// maxCPEResponseBytes bounds a dictionary response body read into memory.
	maxCPEResponseBytes = 16 << 20
)

// Candidate is one NVD application CPE (vendor:product) a proposal may be
// mapped to. Vendor and Product keep NVD's formatted-string escaping,
// lowercased: the same form cve_feed_entries.cpe_patterns and
// app_cpe_mappings store.
type Candidate struct {
	ID         string `json:"id"` // "C1".."C20": the only thing the model may answer with
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	Title      string `json:"title"`
	Deprecated bool   `json:"deprecated"`
	// Entries is how many CPE entries (versions) NVD lists for the pair on
	// the page read; a rough popularity signal for ranking only.
	Entries int `json:"entries"`
	// CVECount is the number of CVEs in the local feed filed under the pair
	// (set by the worker). Zero is not a reason to reject a candidate.
	CVECount int `json:"cve_count"`
}

// Key is the candidate's "vendor:product".
func (c Candidate) Key() string { return c.Vendor + ":" + c.Product }

// CandidateSource searches the CPE dictionary.
type CandidateSource interface {
	Search(ctx context.Context, keyword string) ([]Candidate, error)
}

// Dictionary is the NVD CPE dictionary client: cached, rate-limited and
// retried the way patched-cve-sync treats the CVE API (a 5xx, 429 or
// transport error is retried with backoff; a load-shed 200 that reports
// results but carries none is retried too; any other 4xx or a decode error is
// fatal). It never logs a URL, the keyword or a response body.
type Dictionary struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
	Cache   DB            // nil disables the cache
	TTL     time.Duration // cache lifetime
	// Pacer spaces every request, retries included (nil: no pacing, tests).
	// Production uses the database-wide NVDBudget so every proposer process
	// shares one budget.
	Pacer  Pacer
	Logger *slog.Logger
	// Sleep overrides the retry backoff wait (tests).
	Sleep func(context.Context, time.Duration) error
}

// NVD request budget for the proposer (PAT-2138 security review, P2). NVD
// allows 50 requests per rolling 30 s with an API key and 5 without, per
// key, shared with patched-cve-sync's CVE feed walk (which paces itself at
// the full limit, 600 ms / 6 s between requests, and whose page fetches take
// seconds each, so its real rate sits below it). The proposer takes a tenth
// of the limit, counted across every proposer process through one database
// row (NVDBudget), retries included:
//
//	with a key     one request per 6 s  (5 per 30 s, 10% of 50)
//	without a key  one request per 60 s (0.5 per 30 s, 10% of 5)
const (
	nvdProposerIntervalKeyed   = 6 * time.Second
	nvdProposerIntervalUnkeyed = 60 * time.Second
)

// NewDictionary returns a Dictionary paced by the shared database budget.
func NewDictionary(apiKey string, db DB, logger *slog.Logger) *Dictionary {
	every := nvdProposerIntervalUnkeyed
	if apiKey != "" {
		every = nvdProposerIntervalKeyed
	}
	if logger == nil {
		logger = slog.Default()
	}
	d := &Dictionary{
		BaseURL: DefaultNVDCPEURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
		Cache:   db,
		TTL:     30 * 24 * time.Hour,
		Logger:  logger,
	}
	if db != nil {
		d.Pacer = &NVDBudget{DB: db, Interval: every}
	}
	return d
}

// Pacer waits until one more request may be sent.
type Pacer interface {
	Wait(ctx context.Context) error
}

// NVDBudget is a Pacer shared by every process through the single
// cpe_nvd_budget row: a request may go when the last one any proposer sent
// is at least Interval ago. Taking a slot is one atomic UPDATE (the row lock
// is held only for that statement), so two processes can never both take
// the same slot, and no transaction is held open while waiting.
type NVDBudget struct {
	DB       DB
	Interval time.Duration
	// Sleep overrides the wait (tests).
	Sleep func(context.Context, time.Duration) error
}

// Wait implements Pacer.
func (b *NVDBudget) Wait(ctx context.Context) error {
	for {
		var took bool
		var wait float64
		err := b.DB.QueryRow(ctx, `
			WITH take AS (
				UPDATE cpe_nvd_budget SET last_request_at = clock_timestamp()
				WHERE id = 1 AND last_request_at <= clock_timestamp() - make_interval(secs => $1)
				RETURNING true AS took
			)
			SELECT COALESCE((SELECT took FROM take), false),
			       COALESCE((SELECT CASE WHEN isfinite(last_request_at)
			                        THEN GREATEST(0, EXTRACT(EPOCH FROM (last_request_at + make_interval(secs => $1) - clock_timestamp())))::float8
			                        ELSE 0 END
			                 FROM cpe_nvd_budget WHERE id = 1), $1)
		`, b.Interval.Seconds()).Scan(&took, &wait)
		if err != nil {
			return fmt.Errorf("nvd request budget: %w", err)
		}
		if took {
			return nil
		}
		d := time.Duration(wait*float64(time.Second)) + 50*time.Millisecond
		if d > b.Interval {
			d = b.Interval
		}
		sleep := b.Sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		if err := sleep(ctx, d); err != nil {
			return err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// errDegradedPage is NVD's load-shedding shape: HTTP 200, totalResults > 0,
// no products. Retryable, like a 5xx.
var errDegradedPage = errors.New("nvd cpe dictionary returned an empty page for a non-empty result (load shedding)")

type nvdCPEResponse struct {
	TotalResults int `json:"totalResults"`
	Products     []struct {
		CPE struct {
			CPEName    string `json:"cpeName"`
			Deprecated bool   `json:"deprecated"`
			Titles     []struct {
				Title string `json:"title"`
				Lang  string `json:"lang"`
			} `json:"titles"`
		} `json:"cpe"`
	} `json:"products"`
}

type cachedSearch struct {
	Candidates []Candidate `json:"candidates"`
}

// Search returns up to MaxCandidates application CPEs for keyword, ranked
// (current before deprecated, then by how many entries NVD lists, then by
// key). An empty keyword returns nothing and makes no request.
func (d *Dictionary) Search(ctx context.Context, keyword string) ([]Candidate, error) {
	keyword = strings.TrimSpace(keyword)
	if keyword == "" {
		return nil, nil
	}
	cacheKey := strings.ToLower(keyword)
	if got, ok := d.cached(ctx, cacheKey); ok {
		return got, nil
	}
	body, err := httpretry.Do(ctx, httpretry.Options{
		MaxAttempts: 4,
		OverallCap:  3 * time.Minute,
		Backoff:     []time.Duration{5 * time.Second, 20 * time.Second, 60 * time.Second},
		IsRetryable: func(err error) bool {
			return errors.Is(err, errDegradedPage) || httpretry.IsRetryable(err)
		},
		RetryAfter: func(err error) time.Duration {
			var he *httpretry.HTTPError
			if errors.As(err, &he) {
				return he.RetryAfter
			}
			return 0
		},
		Status: func(err error) int {
			var he *httpretry.HTTPError
			if errors.As(err, &he) {
				return he.StatusCode
			}
			return 0
		},
		Logger:    d.logger(),
		LogAction: "nvd cpe dictionary search",
		Source:    "nvd",
		Document:  "cpes",
		Sleep:     d.Sleep,
	}, func(ctx context.Context) ([]byte, error) {
		if d.Pacer != nil {
			if err := d.Pacer.Wait(ctx); err != nil {
				return nil, fmt.Errorf("nvd cpe rate limit wait: %w", err)
			}
		}
		return d.fetch(ctx, keyword)
	})
	if err != nil {
		return nil, err
	}
	var resp nvdCPEResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("nvd cpe decode: %w", err)
	}
	type agg struct {
		c          Candidate
		current    bool
		titleFound bool
	}
	byKey := map[string]*agg{}
	for _, p := range resp.Products {
		part, vendor, product, ok := parseCPE23Name(p.CPE.CPEName)
		if !ok || part != "a" {
			continue
		}
		key := vendor + ":" + product
		a := byKey[key]
		if a == nil {
			a = &agg{c: Candidate{Vendor: vendor, Product: product}}
			byKey[key] = a
		}
		a.c.Entries++
		if !p.CPE.Deprecated {
			a.current = true
		}
		if !a.titleFound {
			for _, t := range p.CPE.Titles {
				if t.Lang == "en" && strings.TrimSpace(t.Title) != "" {
					a.c.Title = capRunes(strings.Join(strings.Fields(t.Title), " "), maxTitleRunes)
					a.titleFound = true
					break
				}
			}
		}
	}
	out := make([]Candidate, 0, len(byKey))
	for _, a := range byKey {
		a.c.Deprecated = !a.current
		out = append(out, a.c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Deprecated != out[j].Deprecated {
			return !out[i].Deprecated
		}
		if out[i].Entries != out[j].Entries {
			return out[i].Entries > out[j].Entries
		}
		return out[i].Key() < out[j].Key()
	})
	if len(out) > MaxCandidates {
		out = out[:MaxCandidates]
	}
	d.store(ctx, cacheKey, resp.TotalResults, out)
	return out, nil
}

func (d *Dictionary) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

func (d *Dictionary) fetch(ctx context.Context, keyword string) ([]byte, error) {
	u, err := url.Parse(d.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("nvd cpe base url: %w", err)
	}
	q := u.Query()
	q.Set("keywordSearch", keyword)
	q.Set("resultsPerPage", strconv.Itoa(nvdCPEPageSize))
	q.Set("startIndex", "0")
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("nvd cpe request: %w", err)
	}
	if d.APIKey != "" {
		req.Header.Set("apiKey", d.APIKey)
	}
	client := d.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, &httpretry.TransportError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return nil, &httpretry.HTTPError{StatusCode: resp.StatusCode,
			RetryAfter: httpretry.ParseRetryAfter(resp.Header.Get("Retry-After"), 60*time.Second)}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCPEResponseBytes+1))
	if err != nil {
		return nil, &httpretry.TransportError{Err: err}
	}
	if len(body) > maxCPEResponseBytes {
		return nil, fmt.Errorf("nvd cpe response exceeds %d bytes", maxCPEResponseBytes)
	}
	var probe nvdCPEResponse
	if err := json.Unmarshal(body, &probe); err != nil {
		return nil, fmt.Errorf("nvd cpe decode: %w", err)
	}
	if probe.TotalResults > 0 && len(probe.Products) == 0 {
		return nil, errDegradedPage
	}
	return body, nil
}

func (d *Dictionary) cached(ctx context.Context, key string) ([]Candidate, bool) {
	if d.Cache == nil {
		return nil, false
	}
	var raw []byte
	err := d.Cache.QueryRow(ctx, `
		SELECT results FROM cpe_dictionary_cache
		WHERE query = $1 AND fetched_at > now() - make_interval(secs => $2)
	`, key, d.TTL.Seconds()).Scan(&raw)
	if err != nil {
		return nil, false
	}
	var out []Candidate
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false
	}
	return out, true
}

func (d *Dictionary) store(ctx context.Context, key string, total int, cands []Candidate) {
	if d.Cache == nil || utf8.RuneCountInString(key) > maxNameRunes {
		return
	}
	if cands == nil {
		cands = []Candidate{}
	}
	raw, err := json.Marshal(cands)
	if err != nil {
		return
	}
	if _, err := d.Cache.Exec(ctx, `
		INSERT INTO cpe_dictionary_cache (query, results, total_results, fetched_at)
		VALUES ($1, $2::jsonb, $3, now())
		ON CONFLICT (query) DO UPDATE SET results = EXCLUDED.results,
			total_results = EXCLUDED.total_results, fetched_at = EXCLUDED.fetched_at
	`, key, raw, total); err != nil {
		d.logger().Warn("cpe dictionary cache write failed", "err", err)
	}
}

// parseCPE23Name splits a CPE 2.3 formatted string into part, vendor and
// product, honouring backslash escapes ("\:" does not split). Vendor and
// product keep their escapes and are lowercased, the form every CPE key in
// this codebase is stored in.
func parseCPE23Name(s string) (part, vendor, product string, ok bool) {
	if !strings.HasPrefix(s, "cpe:2.3:") {
		return "", "", "", false
	}
	var fields []string
	var cur strings.Builder
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\':
			cur.WriteRune(r)
			escaped = true
		case r == ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
		if len(fields) > 5 {
			break
		}
	}
	fields = append(fields, cur.String())
	if len(fields) < 5 {
		return "", "", "", false
	}
	part, vendor, product = fields[2], strings.ToLower(fields[3]), strings.ToLower(fields[4])
	if vendor == "" || product == "" || vendor == "*" || product == "*" || vendor == "-" || product == "-" {
		return "", "", "", false
	}
	return part, vendor, product, true
}

var (
	// keywordNoise drops parenthesised qualifiers ("(x64)", "(Preview)") and
	// anything that looks like a version number from a display name before it
	// becomes an NVD keyword: NVD keyword search ANDs every word, so a version
	// or an architecture tag in the keyword only loses matches.
	parenthesised = regexp.MustCompile(`\([^)]*\)|\[[^\]]*\]`)
	versionish    = regexp.MustCompile(`^v?\d+([._-]\d+)*[a-z]?$`)
)

// maxKeywordWords bounds a keyword; long display names are almost always a
// product name followed by edition, architecture or locale noise.
const maxKeywordWords = 5

// Keywords returns the NVD keyword searches for a display name, most specific
// first, at most two: the cleaned name, then (when it has more than two
// words) its first two words. Deterministic and pure.
func Keywords(displayName string) []string {
	cleaned := parenthesised.ReplaceAllString(displayName, " ")
	var words []string
	for _, raw := range strings.Fields(cleaned) {
		// Keep a word's inner punctuation ("7-Zip", "Notepad++"); drop what
		// surrounds it (".NET" -> "NET", "Code," -> "Code").
		w := strings.TrimFunc(raw, func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '+'
		})
		w = strings.TrimLeft(w, "+")
		if strings.IndexFunc(w, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) < 0 {
			continue
		}
		lw := strings.ToLower(w)
		if lw == "" || versionish.MatchString(lw) {
			continue
		}
		switch lw {
		case "x64", "x86", "arm64", "amd64", "64", "32", "bit", "the":
			continue
		}
		words = append(words, w)
		if len(words) == maxKeywordWords {
			break
		}
	}
	if len(words) == 0 {
		return nil
	}
	out := []string{capRunes(strings.Join(words, " "), 100)}
	if len(words) > 2 {
		out = append(out, strings.Join(words[:2], " "))
	}
	return out
}

func capRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n])
}
