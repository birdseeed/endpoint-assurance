package lifecycle

// The endoflife.date fetcher (PAT-2147).
//
// Observed API shape (GET https://endoflife.date/api/v1/products/<slug>/,
// checked live on 2026-09-25, schema_version "1.2.1"):
//
//	{"schema_version":"1.2.1","generated_at":"…","last_modified":"…",
//	 "result":{"name":"macos","label":"Apple macOS","links":{"html":"https://endoflife.date/macos",…},
//	           "releases":[{"name":"14","label":"macOS 14 (Sonoma)","releaseDate":"2023-09-26",
//	                        "isLts":false,"isEol":true,"eolFrom":"2026-09-14",
//	                        "isEoas":…,"eoasFrom":…,"isEoes":…,"eoesFrom":…,
//	                        "isMaintained":false,"latest":{"name":"14.8.9",…}},…]}}
//
// eolFrom is the first date without (security) support, or null when none is
// announced; isEol is the source's own flag at generation time. eoasFrom
// (end of active support) and eoesFrom (end of paid extended support, e.g.
// Windows ESU) appear only on some products. latest may be null (Chrome).
// An unknown slug is a 404 HTML page; an alias slug (google-chrome) is a
// same-host 301 to the canonical one (chrome).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/httpretry"
)

// DefaultBaseURL is the endoflife.date v1 products endpoint.
const DefaultBaseURL = "https://endoflife.date/api/v1/products/"

const (
	// DefaultMaxBodyBytes caps one product response. The largest product
	// the seed uses (chrome, ~150 cycles) is about 40 KiB.
	DefaultMaxBodyBytes = 2 << 20
	// DefaultRequestTimeout bounds one HTTP attempt.
	DefaultRequestTimeout = 20 * time.Second
	// DefaultSlugBudget bounds one slug's attempts plus backoff.
	DefaultSlugBudget = 60 * time.Second
	// maxReleases bounds how many cycles one product may carry.
	maxReleases = 2000
	// refreshLockKey is the advisory lock that keeps two refreshes (the
	// scheduled job and an admin trigger) from running at once.
	refreshLockKey int64 = 0x2147_1ec1
	userAgent            = "patched-lifecycle-sync/1 (+https://patched.im)"
)

// ErrRefreshInProgress: another refresh holds the lock.
var ErrRefreshInProgress = errors.New("a lifecycle refresh is already running")

// Fetcher fetches endoflife.date products.
type Fetcher struct {
	BaseURL        string
	Client         *http.Client
	MaxBodyBytes   int64
	RequestTimeout time.Duration
	SlugBudget     time.Duration
	Logger         *slog.Logger
	// Sleep overrides the retry backoff wait (tests).
	Sleep func(context.Context, time.Duration) error
	// Now overrides the clock (tests).
	Now func() time.Time
}

// NewFetcher returns a Fetcher with the production defaults. The client
// follows at most three redirects and only within the base URL's host.
func NewFetcher(logger *slog.Logger) *Fetcher {
	if logger == nil {
		logger = slog.Default()
	}
	return &Fetcher{BaseURL: DefaultBaseURL, Logger: logger}
}

func (f *Fetcher) base() (*url.URL, error) {
	b := f.BaseURL
	if b == "" {
		b = DefaultBaseURL
	}
	if !strings.HasSuffix(b, "/") {
		b += "/"
	}
	return url.Parse(b)
}

func (f *Fetcher) client(base *url.URL) *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return &http.Client{
		Timeout: f.requestTimeout(),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Host != base.Host || req.URL.Scheme != base.Scheme {
				return fmt.Errorf("redirect to another host refused")
			}
			return nil
		},
	}
}

func (f *Fetcher) requestTimeout() time.Duration {
	if f.RequestTimeout > 0 {
		return f.RequestTimeout
	}
	return DefaultRequestTimeout
}

func (f *Fetcher) maxBody() int64 {
	if f.MaxBodyBytes > 0 {
		return f.MaxBodyBytes
	}
	return DefaultMaxBodyBytes
}

func (f *Fetcher) now() time.Time {
	if f.Now != nil {
		return f.Now()
	}
	return time.Now()
}

type apiDate struct{ t *time.Time }

func (d *apiDate) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		d.t = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("date: %w", err)
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return fmt.Errorf("date %q: %w", s, err)
	}
	d.t = &t
	return nil
}

type apiRelease struct {
	Name        string  `json:"name"`
	Label       string  `json:"label"`
	ReleaseDate apiDate `json:"releaseDate"`
	IsLTS       *bool   `json:"isLts"`
	IsEOL       *bool   `json:"isEol"`
	EOLFrom     apiDate `json:"eolFrom"`
	EOASFrom    apiDate `json:"eoasFrom"`
	EOESFrom    apiDate `json:"eoesFrom"`
	Latest      *struct {
		Name string `json:"name"`
	} `json:"latest"`
}

type apiProduct struct {
	SchemaVersion string `json:"schema_version"`
	LastModified  string `json:"last_modified"`
	Result        struct {
		Name  string `json:"name"`
		Label string `json:"label"`
		Links struct {
			HTML string `json:"html"`
		} `json:"links"`
		Releases []apiRelease `json:"releases"`
	} `json:"result"`
}

// FetchedProduct is a parsed, validated product ready to store.
type FetchedProduct struct {
	Slug          string
	Label         string
	APIURL        string
	HTMLURL       string
	SchemaVersion string
	LastModified  string
	Cycles        []Cycle
}

func clip(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ParseProduct validates one product response. It fails closed: a response
// with an unexpected schema major, no releases, an unparsable date, or a
// duplicate or oversized cycle name is refused as a whole, and the stored
// data (if any) is kept.
func ParseProduct(slug, apiURL string, body []byte) (FetchedProduct, error) {
	var p apiProduct
	if err := json.Unmarshal(body, &p); err != nil {
		return FetchedProduct{}, fmt.Errorf("decode %s: %w", slug, err)
	}
	if !strings.HasPrefix(p.SchemaVersion, "1.") {
		return FetchedProduct{}, fmt.Errorf("%s: unsupported schema_version %q", slug, clip(p.SchemaVersion, 20))
	}
	n := len(p.Result.Releases)
	if n == 0 || n > maxReleases {
		return FetchedProduct{}, fmt.Errorf("%s: %d releases, want 1 to %d", slug, n, maxReleases)
	}
	out := FetchedProduct{
		Slug: slug, Label: clip(p.Result.Label, 200), APIURL: apiURL,
		SchemaVersion: p.SchemaVersion, LastModified: clip(p.LastModified, 40),
		HTMLURL: "https://endoflife.date/" + slug,
	}
	if h := p.Result.Links.HTML; strings.HasPrefix(h, "https://endoflife.date/") && len(h) <= 200 {
		out.HTMLURL = h
	}
	seen := map[string]bool{}
	for _, r := range p.Result.Releases {
		name := strings.ToLower(strings.TrimSpace(r.Name))
		if name == "" || len(name) > 100 {
			return FetchedProduct{}, fmt.Errorf("%s: release with an empty or oversized name", slug)
		}
		if seen[name] {
			return FetchedProduct{}, fmt.Errorf("%s: duplicate release %q", slug, name)
		}
		seen[name] = true
		c := Cycle{
			Name: name, Label: clip(r.Label, 200), ReleaseDate: r.ReleaseDate.t,
			EOLDate: r.EOLFrom.t, IsEOL: r.IsEOL, SupportDate: r.EOASFrom.t, ExtendedSupportDate: r.EOESFrom.t,
		}
		if r.IsLTS != nil {
			c.IsLTS = *r.IsLTS
		}
		if r.Latest != nil {
			c.LatestVersion = clip(strings.TrimSpace(r.Latest.Name), 100)
		}
		out.Cycles = append(out.Cycles, c)
	}
	return out, nil
}

// fetchOnce is one HTTP attempt. It sends nothing but the slug in the path
// and a fixed User-Agent: no tenant data ever reaches the source.
func (f *Fetcher) fetchOnce(ctx context.Context, base *url.URL, slug string) ([]byte, error) {
	u := base.ResolveReference(&url.URL{Path: url.PathEscape(slug) + "/"})
	ctx, cancel := context.WithTimeout(ctx, f.requestTimeout())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	resp, err := f.client(base).Do(req)
	if err != nil {
		return nil, &httpretry.TransportError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, &httpretry.HTTPError{StatusCode: resp.StatusCode,
			RetryAfter: httpretry.ParseRetryAfter(resp.Header.Get("Retry-After"), httpretry.DefaultRetryAfterCap)}
	}
	limit := f.maxBody()
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("response of %d bytes exceeds the %d byte cap", resp.ContentLength, limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, &httpretry.TransportError{Err: err}
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeds the %d byte cap", limit)
	}
	return body, nil
}

// Fetch retrieves and parses one slug with bounded retries (5xx, 429 and
// transport errors retry; any other status, an oversized body or an invalid
// document does not).
func (f *Fetcher) Fetch(ctx context.Context, slug string) (FetchedProduct, error) {
	if !ValidSlug(slug) {
		return FetchedProduct{}, fmt.Errorf("invalid slug %q", clip(slug, 100))
	}
	base, err := f.base()
	if err != nil {
		return FetchedProduct{}, err
	}
	budget := f.SlugBudget
	if budget <= 0 {
		budget = DefaultSlugBudget
	}
	body, err := httpretry.Do(ctx, httpretry.Options{
		MaxAttempts: httpretry.DefaultMaxAttempts,
		OverallCap:  budget,
		Backoff:     httpretry.DefaultBackoff,
		IsRetryable: httpretry.IsRetryable,
		RetryAfter: func(err error) time.Duration {
			var h *httpretry.HTTPError
			if errors.As(err, &h) {
				return h.RetryAfter
			}
			return 0
		},
		Status: func(err error) int {
			var h *httpretry.HTTPError
			if errors.As(err, &h) {
				return h.StatusCode
			}
			return 0
		},
		Logger:    f.Logger,
		LogAction: "lifecycle fetch",
		Source:    SourceName,
		Document:  slug,
		Sleep:     f.Sleep,
	}, func(ctx context.Context) ([]byte, error) { return f.fetchOnce(ctx, base, slug) })
	if err != nil {
		return FetchedProduct{}, err
	}
	apiURL := base.ResolveReference(&url.URL{Path: url.PathEscape(slug) + "/"}).String()
	return ParseProduct(slug, apiURL, body)
}

// SlugOutcome is one slug's refresh result.
type SlugOutcome struct {
	Slug   string `json:"slug"`
	OK     bool   `json:"ok"`
	Cycles int    `json:"cycles"`
	Error  string `json:"error,omitempty"`
}

// RefreshResult summarises a refresh.
type RefreshResult struct {
	Slugs     []SlugOutcome `json:"slugs"`
	Succeeded int           `json:"succeeded"`
	Failed    int           `json:"failed"`
}

// ActiveSlugs lists the slugs of every proposed or published mapping: the
// only products the fetcher refreshes.
func ActiveSlugs(ctx context.Context, db DB) ([]string, error) {
	rows, err := db.Query(ctx, `
		SELECT DISTINCT eol_slug FROM lifecycle_mappings
		WHERE status IN ('proposed', 'published') ORDER BY eol_slug`)
	if err != nil {
		return nil, fmt.Errorf("list lifecycle slugs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Lock takes the refresh advisory lock on a dedicated connection. The
// caller must call the returned release function.
func Lock(ctx context.Context, pool *pgxpool.Pool) (func(), error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	var ok bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, refreshLockKey).Scan(&ok); err != nil {
		conn.Release()
		return nil, err
	}
	if !ok {
		conn.Release()
		return nil, ErrRefreshInProgress
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, refreshLockKey)
		conn.Release()
	}, nil
}

// Refresh fetches the given slugs (every active slug when slugs is empty)
// and stores each success. The caller holds the lock (see Lock). One slug's
// failure is recorded against that slug and does not stop the others; the
// error return is only for a database failure.
func (f *Fetcher) Refresh(ctx context.Context, pool *pgxpool.Pool, slugs []string) (RefreshResult, error) {
	if len(slugs) == 0 {
		var err error
		slugs, err = ActiveSlugs(ctx, pool)
		if err != nil {
			return RefreshResult{}, err
		}
	}
	res := RefreshResult{Slugs: []SlugOutcome{}}
	base, err := f.base()
	if err != nil {
		return res, err
	}
	for _, slug := range slugs {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		p, ferr := f.Fetch(ctx, slug)
		if ferr != nil {
			msg := clip(ferr.Error(), 500)
			f.Logger.Warn("lifecycle fetch failed; keeping previous data", "slug", slug, "err", msg)
			apiURL := base.ResolveReference(&url.URL{Path: url.PathEscape(slug) + "/"}).String()
			if ValidSlug(slug) {
				if _, err := pool.Exec(ctx, `
					INSERT INTO lifecycle_products (slug, api_url, last_attempt_at, last_error)
					VALUES ($1, $2, $3, $4)
					ON CONFLICT (slug) DO UPDATE SET last_attempt_at = EXCLUDED.last_attempt_at, last_error = EXCLUDED.last_error`,
					slug, apiURL, f.now(), msg); err != nil {
					return res, fmt.Errorf("record lifecycle fetch failure for %s: %w", slug, err)
				}
			}
			res.Slugs = append(res.Slugs, SlugOutcome{Slug: slug, Error: msg})
			res.Failed++
			continue
		}
		if err := Store(ctx, pool, p, f.now()); err != nil {
			return res, err
		}
		res.Slugs = append(res.Slugs, SlugOutcome{Slug: slug, OK: true, Cycles: len(p.Cycles)})
		res.Succeeded++
	}
	return res, nil
}

// Store replaces one product's cycles in a single transaction.
func Store(ctx context.Context, pool *pgxpool.Pool, p FetchedProduct, fetchedAt time.Time) error {
	return pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO lifecycle_products
				(slug, label, api_url, html_url, schema_version, api_last_modified, fetched_at, last_attempt_at, last_error, cycle_count)
			VALUES ($1, NULLIF($2, ''), $3, $4, $5, NULLIF($6, ''), $7, $7, NULL, $8)
			ON CONFLICT (slug) DO UPDATE SET
				label = EXCLUDED.label, api_url = EXCLUDED.api_url, html_url = EXCLUDED.html_url,
				schema_version = EXCLUDED.schema_version, api_last_modified = EXCLUDED.api_last_modified,
				fetched_at = EXCLUDED.fetched_at, last_attempt_at = EXCLUDED.last_attempt_at,
				last_error = NULL, cycle_count = EXCLUDED.cycle_count`,
			p.Slug, p.Label, p.APIURL, p.HTMLURL, p.SchemaVersion, p.LastModified, fetchedAt, len(p.Cycles)); err != nil {
			return fmt.Errorf("store lifecycle product %s: %w", p.Slug, err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM lifecycle_cycles WHERE slug = $1`, p.Slug); err != nil {
			return fmt.Errorf("clear lifecycle cycles %s: %w", p.Slug, err)
		}
		batch := &pgx.Batch{}
		for _, c := range p.Cycles {
			batch.Queue(`
				INSERT INTO lifecycle_cycles
					(slug, cycle, label, release_date, eol_date, is_eol, support_date, extended_support_date,
					 latest_version, is_lts, fetched_at, source_url)
				VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11, $12)`,
				p.Slug, c.Name, c.Label, c.ReleaseDate, c.EOLDate, c.IsEOL, c.SupportDate, c.ExtendedSupportDate,
				c.LatestVersion, c.IsLTS, fetchedAt, p.APIURL)
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return fmt.Errorf("store lifecycle cycles %s: %w", p.Slug, err)
		}
		return nil
	})
}
