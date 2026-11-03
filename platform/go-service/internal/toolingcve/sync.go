// Package toolingcve owns PAT-2109's exact AI-tooling vulnerability seam.
// Network access is deliberately confined to Sync, called by
// patched-cve-sync. Extractor request processing only enqueues local work.
package toolingcve

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"patched.im/api/internal/cvematch"
)

const (
	defaultOSVBaseURL  = "https://api.osv.dev"
	queryBatchSize     = 1000
	queueSnapshotLimit = 10000
	syncTimeout        = 10 * time.Minute
	osvUserAgent       = "patched-cve-sync/tooling-advisories"
	// AdvisoryLockID serialises nightly/full and prompt tooling refreshes even
	// when their independent systemd timers overlap. The hex value encodes the
	// PAT2109 feature namespace, matching cvepipeline's named-lock convention.
	AdvisoryLockID int64 = 0x50415432313039
)

// Client is the bounded official OSV API client used by the scheduled sync.
type Client struct {
	BaseURL   string
	HTTP      *http.Client
	configErr error
}

func NewClient(baseURL string) *Client {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = defaultOSVBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	client := &Client{BaseURL: baseURL, HTTP: &http.Client{Timeout: 20 * time.Second}}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		client.configErr = fmt.Errorf("invalid OSV base URL %q: http or https endpoint required", baseURL)
		return client
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			client.configErr = fmt.Errorf("invalid OSV base URL %q: plain HTTP is allowed only for loopback test hosts", baseURL)
		}
	}
	return client
}

type observation struct {
	Block, Unit, Kind, EntryKey string
}

type input struct {
	TenantID, DeviceID                         string
	Kind, Ecosystem, Package, Identity, Source string
	Version                                    string
	ObservedAt                                 time.Time
	Observations                               []observation
	UnsupportedReason                          string
	CanAssess                                  bool
}

func (in input) key() string {
	return strings.Join([]string{in.DeviceID, in.Kind, in.Identity, in.Source, in.Version}, "\x1f")
}

type currentRow struct {
	TenantID, DeviceID, Block, Unit, EntryKind, EntryKey string
	IdentityKind, Identity, Companion, Version           string
	ObservedAt                                           time.Time
	Attributes                                           []byte
	CanAssess                                            bool
}

// loadInputs reads only the authority-aware current projection. failed units
// are excluded, while partial rows remain because PAT-2021 deliberately keeps
// their last known current entries until an authoritative report removes them.
func loadInputs(ctx context.Context, pool *pgxpool.Pool, deviceIDs []string) ([]input, error) {
	rows, err := pool.Query(ctx, `
		SELECT c.tenant_id::text, c.device_id::text, c.block, c.unit, c.entry_kind, c.entry_key,
		       so.identity_kind, so.identity_value_normalized,
		       so.companion_value_normalized, COALESCE(d.attributes->>'version',si.current_version,''),
		       c.observed_at, d.attributes,
		       (s.collection_status IN ('complete','partial','not_present')
		        AND COALESCE(s.unit_statuses->>c.unit,s.collection_status) IN ('complete','partial','not_present'))
		FROM tooling_current_entries c
		JOIN tooling_device_state s ON s.device_id=c.device_id AND s.tenant_id=c.tenant_id AND s.block=c.block
		JOIN software_observations so ON so.id=c.observation_id AND so.tenant_id=c.tenant_id
		JOIN tooling_observation_details d ON d.observation_id=c.observation_id AND d.tenant_id=c.tenant_id
		LEFT JOIN software_installations si ON si.device_id=c.device_id
		 AND si.identity_fingerprint=so.identity_fingerprint AND si.tenant_id=c.tenant_id AND si.removed_at IS NULL
		WHERE s.reported_at > '-infinity'::timestamptz
		  AND ($1::uuid[] IS NULL OR c.device_id=ANY($1::uuid[]))
		  AND c.observed_at >= COALESCE((s.authority->>c.unit)::timestamptz,'-infinity'::timestamptz)
		ORDER BY c.device_id, c.block, c.unit, c.entry_key`, deviceIDs)
	if err != nil {
		return nil, fmt.Errorf("load tooling vulnerability inputs: %w", err)
	}
	defer rows.Close()
	var raw []currentRow
	for rows.Next() {
		var r currentRow
		if err := rows.Scan(&r.TenantID, &r.DeviceID, &r.Block, &r.Unit, &r.EntryKind, &r.EntryKey,
			&r.IdentityKind, &r.Identity, &r.Companion, &r.Version, &r.ObservedAt, &r.Attributes, &r.CanAssess); err != nil {
			return nil, err
		}
		raw = append(raw, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Direct exact package versions are the only version authority an MCP
	// package reference may inherit.
	direct := map[string][]string{}
	directAssessable := map[string]bool{}
	for _, r := range raw {
		eco := ecosystemForIdentity(r.IdentityKind)
		if eco != "" && r.Version != "" {
			k := r.DeviceID + "\x1f" + eco + "\x1f" + r.Identity
			seen := false
			for _, v := range direct[k] {
				seen = seen || v == r.Version
			}
			if !seen {
				direct[k] = append(direct[k], r.Version)
			}
			if r.CanAssess {
				directAssessable[k+"\x1f"+r.Version] = true
			}
		}
	}

	byKey := map[string]*input{}
	add := func(in input, o observation) {
		k := in.key()
		if old := byKey[k]; old != nil {
			old.Observations = appendObservation(old.Observations, o)
			old.CanAssess = old.CanAssess || in.CanAssess
			if in.ObservedAt.After(old.ObservedAt) {
				old.ObservedAt = in.ObservedAt
			}
			return
		}
		in.Observations = []observation{o}
		byKey[k] = &in
	}
	for _, r := range raw {
		o := observation{Block: r.Block, Unit: r.Unit, Kind: r.EntryKind, EntryKey: r.EntryKey}
		switch r.IdentityKind {
		case "npm_package", "pip_package":
			eco := ecosystemForIdentity(r.IdentityKind)
			version, reason := r.Version, ""
			if version == "" {
				version, reason = "unknown", "version_missing"
			}
			add(input{TenantID: r.TenantID, DeviceID: r.DeviceID, Kind: "package", Ecosystem: eco,
				Package: r.Identity, Identity: r.Identity, Source: eco, Version: version,
				ObservedAt: r.ObservedAt, UnsupportedReason: reason, CanAssess: r.CanAssess}, o)
		case "mcp_server":
			var a struct {
				Runner, Package *string
				PackageStatus   string `json:"package_status"`
			}
			if json.Unmarshal(r.Attributes, &a) != nil || a.PackageStatus != "extracted" || a.Package == nil {
				add(input{TenantID: r.TenantID, DeviceID: r.DeviceID, Kind: "mcp_server", Identity: r.Identity,
					Source: "mcp", Version: "unknown", ObservedAt: r.ObservedAt, UnsupportedReason: "mcp_package_unresolved", CanAssess: r.CanAssess}, o)
				continue
			}
			eco := ecosystemForRunner(a.Runner)
			pkg := normalisePackage(eco, *a.Package)
			versions := direct[r.DeviceID+"\x1f"+eco+"\x1f"+pkg]
			inheritsDirectVersion := len(versions) > 0
			reason := mcpResolutionReason(eco, pkg, len(versions) > 0)
			if len(versions) == 0 {
				versions = []string{"unknown"}
			}
			sort.Strings(versions)
			for _, version := range versions {
				kind := "package"
				storedEco, storedPackage := eco, pkg
				if eco == "" || pkg == "" {
					kind = "mcp_server"
					storedEco, storedPackage = "", ""
				}
				canAssess := r.CanAssess
				if inheritsDirectVersion {
					canAssess = canAssess && directAssessable[r.DeviceID+"\x1f"+eco+"\x1f"+pkg+"\x1f"+version]
				}
				add(input{TenantID: r.TenantID, DeviceID: r.DeviceID, Kind: kind, Ecosystem: storedEco,
					Package: storedPackage, Identity: firstNonEmpty(pkg, r.Identity), Source: firstNonEmpty(eco, "mcp"),
					Version: version, ObservedAt: r.ObservedAt, UnsupportedReason: reason, CanAssess: canAssess}, o)
			}
		case "ide_extension":
			version, reason := r.Version, ""
			if version == "" {
				version, reason = "unknown", "version_missing"
			}
			add(input{TenantID: r.TenantID, DeviceID: r.DeviceID, Kind: "ide_extension",
				Identity: r.Identity, Source: r.Companion, Version: version, ObservedAt: r.ObservedAt,
				UnsupportedReason: reason, CanAssess: r.CanAssess}, o)
		case "local_model_runtime":
			version, reason := r.Version, ""
			if version == "" {
				version, reason = "unknown", "version_missing"
			}
			if r.Identity == "llama_cpp" && !safeLlamaVersion(version) {
				reason = "version_not_comparable"
			}
			add(input{TenantID: r.TenantID, DeviceID: r.DeviceID, Kind: "local_runtime",
				Identity: r.Identity, Source: r.Companion, Version: version, ObservedAt: r.ObservedAt,
				UnsupportedReason: reason, CanAssess: r.CanAssess}, o)
			// local_model and every unidentified kind are intentionally excluded.
		}
	}
	out := make([]input, 0, len(byKey))
	for _, in := range byKey {
		out = append(out, *in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	return out, nil
}

func mcpResolutionReason(ecosystem, pkg string, hasExactVersion bool) string {
	if ecosystem == "" || pkg == "" {
		return "mcp_ecosystem_unsupported"
	}
	if !hasExactVersion {
		return "mcp_exact_version_unavailable"
	}
	return ""
}

func ecosystemForIdentity(k string) string {
	if k == "npm_package" {
		return "npm"
	}
	if k == "pip_package" {
		return "PyPI"
	}
	return ""
}

func ecosystemForRunner(r *string) string {
	if r == nil {
		return ""
	}
	switch *r {
	case "npx", "npm", "bunx", "pnpx", "pnpm", "yarn":
		return "npm"
	case "uvx", "uv", "pipx":
		return "PyPI"
	}
	return ""
}

func normalisePackage(ecosystem, s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if ecosystem == "PyPI" {
		r := strings.NewReplacer("_", "-", ".", "-")
		s = r.Replace(s)
		for strings.Contains(s, "--") {
			s = strings.ReplaceAll(s, "--", "-")
		}
	}
	return s
}

func safeLlamaVersion(v string) bool {
	if v == "" || v == "unknown" || strings.ContainsAny(v, "/+_") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(v, "v"), ".")
	if len(parts) < 2 || len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func appendObservation(a []observation, o observation) []observation {
	for _, old := range a {
		if old == o {
			return a
		}
	}
	return append(a, o)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

type osvQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}
type osvBatchRequest struct {
	Queries []osvQuery `json:"queries"`
}
type osvBatchResult struct {
	Vulns []struct {
		ID string `json:"id"`
	} `json:"vulns"`
	NextPageToken string `json:"next_page_token"`
}
type osvBatchResponse struct {
	Results []osvBatchResult `json:"results"`
}

type osvRecord struct {
	ID        string             `json:"id"`
	Aliases   []string           `json:"aliases"`
	Summary   string             `json:"summary"`
	Details   string             `json:"details"`
	Published *time.Time         `json:"published"`
	Modified  *time.Time         `json:"modified"`
	Withdrawn *time.Time         `json:"withdrawn"`
	Severity  []osvSeverityEntry `json:"severity"`
	Affected  []osvAffected      `json:"affected"`
	Database  json.RawMessage    `json:"database_specific"`
	Raw       json.RawMessage    `json:"-"`
}
type osvSeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}
type osvAffected struct {
	Package           struct{ Ecosystem, Name string } `json:"package"`
	Ranges            json.RawMessage                  `json:"ranges"`
	Versions          []string                         `json:"versions"`
	EcosystemSpecific json.RawMessage                  `json:"ecosystem_specific"`
	DatabaseSpecific  json.RawMessage                  `json:"database_specific"`
}

func (c *Client) postJSON(ctx context.Context, path string, request, response any) error {
	if c.configErr != nil {
		return c.configErr
	}
	b, err := json.Marshal(request)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", osvUserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		limited, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("OSV %s: HTTP %d: %s", path, resp.StatusCode, strings.TrimSpace(string(limited)))
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 10<<20)).Decode(response)
}

func (c *Client) queryBatch(ctx context.Context, inputs []input) ([][]string, error) {
	out := make([][]string, len(inputs))
	for start := 0; start < len(inputs); start += queryBatchSize {
		end := start + queryBatchSize
		if end > len(inputs) {
			end = len(inputs)
		}
		req := osvBatchRequest{Queries: make([]osvQuery, end-start)}
		for i, in := range inputs[start:end] {
			req.Queries[i].Package.Name, req.Queries[i].Package.Ecosystem = in.Package, in.Ecosystem
			req.Queries[i].Version = in.Version
		}
		var resp osvBatchResponse
		if err := c.postJSON(ctx, "/v1/querybatch", req, &resp); err != nil {
			return nil, err
		}
		if len(resp.Results) != end-start {
			return nil, fmt.Errorf("OSV querybatch returned %d results for %d queries", len(resp.Results), end-start)
		}
		var pending []int
		for i, r := range resp.Results {
			for _, v := range r.Vulns {
				if v.ID != "" {
					out[start+i] = append(out[start+i], v.ID)
				}
			}
			if r.NextPageToken != "" {
				req.Queries[i].PageToken = r.NextPageToken
				pending = append(pending, i)
			}
		}
		for page := 0; len(pending) > 0; page++ {
			if page >= 100 {
				return nil, errors.New("OSV querybatch pagination exceeded 100 pages")
			}
			nextReq := osvBatchRequest{Queries: make([]osvQuery, len(pending))}
			for i, original := range pending {
				nextReq.Queries[i] = req.Queries[original]
			}
			var nextResp osvBatchResponse
			if err := c.postJSON(ctx, "/v1/querybatch", nextReq, &nextResp); err != nil {
				return nil, err
			}
			if len(nextResp.Results) != len(pending) {
				return nil, fmt.Errorf("OSV paginated querybatch returned %d results for %d queries", len(nextResp.Results), len(pending))
			}
			var again []int
			for i, result := range nextResp.Results {
				original := pending[i]
				for _, v := range result.Vulns {
					if v.ID != "" {
						out[start+original] = append(out[start+original], v.ID)
					}
				}
				if result.NextPageToken != "" {
					req.Queries[original].PageToken = result.NextPageToken
					again = append(again, original)
				}
			}
			pending = again
		}
	}
	return out, nil
}

func (c *Client) vulnerability(ctx context.Context, id string) (osvRecord, error) {
	var out osvRecord
	if c.configErr != nil {
		return out, c.configErr
	}
	u := c.BaseURL + "/v1/vulns/" + url.PathEscape(id)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return out, err
	}
	req.Header.Set("User-Agent", osvUserAgent)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return out, fmt.Errorf("OSV vuln %s: HTTP %d", id, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return out, err
	}
	if out.ID == "" {
		return out, errors.New("OSV vulnerability missing id")
	}
	out.Raw = b
	return out, nil
}

type finding struct {
	Source, ID, CVE, Severity string
	Score                     *float64
}

type queueItem struct {
	DeviceID    string
	RequestedAt time.Time
}

// Sync refreshes every active estate input. Scheduled/full refreshes use this
// path. A failed OSV request leaves each affected exact version pending with
// null counts; it never converts failure into assessed-zero.
func Sync(ctx context.Context, pool *pgxpool.Pool, client *Client, logger *slog.Logger) error {
	return syncScope(ctx, pool, client, logger, false)
}

// SyncQueued refreshes only the device IDs present in the local invalidation
// queue. It is the prompt timer path and performs no OSV request when empty.
func SyncQueued(ctx context.Context, pool *pgxpool.Pool, client *Client, logger *slog.Logger) error {
	return syncScope(ctx, pool, client, logger, true)
}

func syncScope(ctx context.Context, pool *pgxpool.Pool, client *Client, logger *slog.Logger, queuedOnly bool) error {
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()
	lockConn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer lockConn.Release()
	var locked bool
	if err := lockConn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, AdvisoryLockID).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		logger.Info("tooling vulnerability sync already running; leaving queue for retry")
		return nil
	}
	defer func() {
		unlockCtx, unlockCancel := context.WithTimeout(context.Background(), 5*time.Second)
		var unlocked bool
		unlockErr := lockConn.QueryRow(unlockCtx, `SELECT pg_advisory_unlock($1)`, AdvisoryLockID).Scan(&unlocked)
		unlockCancel()
		if unlockErr == nil && unlocked {
			return
		}

		logger.Error("tooling vulnerability advisory unlock failed; closing connection", "error", unlockErr, "unlocked", unlocked)
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if closeErr := lockConn.Conn().Close(closeCtx); closeErr != nil {
			logger.Error("tooling vulnerability advisory-lock connection close failed", "error", closeErr)
		}
		closeCancel()
	}()

	queued, err := loadQueueSnapshot(ctx, pool)
	if err != nil {
		return err
	}
	if len(queued) == queueSnapshotLimit {
		logger.Warn("tooling vulnerability refresh queue snapshot reached cap", "limit", queueSnapshotLimit)
	}
	var deviceIDs []string
	if queuedOnly {
		if len(queued) == 0 {
			return nil
		}
		for _, q := range queued {
			deviceIDs = append(deviceIDs, q.DeviceID)
		}
	}
	inputs, err := loadInputs(ctx, pool, deviceIDs)
	if err != nil {
		return err
	}
	if err := deactivateAuthoritativelyRemoved(ctx, pool, inputs, deviceIDs); err != nil {
		return err
	}

	var packages []input
	for _, in := range inputs {
		if !in.CanAssess {
			if err := storeAssessment(ctx, pool, in, "pending", "inventory_unavailable", nil, ""); err != nil {
				return err
			}
			continue
		}
		if in.UnsupportedReason != "" {
			if err := storeAssessment(ctx, pool, in, "not_assessed", in.UnsupportedReason, nil, ""); err != nil {
				return err
			}
			continue
		}
		if in.Kind == "package" {
			packages = append(packages, in)
			continue
		}
		fs, reason, err := matchCPE(ctx, pool, in)
		if err != nil {
			if e := storeAssessment(ctx, pool, in, "pending", "refresh_failed", nil, err.Error()); e != nil {
				return e
			}
			return err
		}
		if reason != "" {
			if err := storeAssessment(ctx, pool, in, "not_assessed", reason, nil, ""); err != nil {
				return err
			}
			continue
		}
		if err := storeAssessment(ctx, pool, in, "assessed", "", fs, ""); err != nil {
			return err
		}
	}
	if len(packages) == 0 {
		return clearQueueSnapshot(ctx, pool, queued)
	}

	results, err := client.queryBatch(ctx, packages)
	if err != nil {
		cause := fmt.Errorf("OSV exact package query: %w", err)
		return markPackageAssessmentsPending(packages, cause, func(in input) error {
			return storeAssessment(ctx, pool, in, "pending", "osv_refresh_failed", nil, err.Error())
		})
	}
	records := map[string]osvRecord{}
	for _, ids := range results {
		for _, id := range ids {
			if _, ok := records[id]; ok {
				continue
			}
			r, err := client.vulnerability(ctx, id)
			if err != nil {
				cause := fmt.Errorf("fetch OSV advisory %s: %w", id, err)
				return markPackageAssessmentsPending(packages, cause, func(in input) error {
					return storeAssessment(ctx, pool, in, "pending", "osv_refresh_failed", nil, err.Error())
				})
			}
			records[id] = r
			if err := storeOSVRecord(ctx, pool, r); err != nil {
				return err
			}
		}
	}
	for i, in := range packages {
		var fs []finding
		for _, id := range results[i] {
			r := records[id]
			sev, score := osvSeverityAndScore(r)
			fs = append(fs, finding{Source: "osv", ID: id, CVE: canonicalCVE(r.Aliases), Severity: sev, Score: score})
		}
		if err := storeAssessment(ctx, pool, in, "assessed", "", fs, ""); err != nil {
			return err
		}
	}
	logger.Info("tooling vulnerability sync complete", "inputs", len(inputs), "package_queries", len(packages), "advisories", len(records))
	return clearQueueSnapshot(ctx, pool, queued)
}

func markPackageAssessmentsPending(packages []input, cause error, store func(input) error) error {
	errs := []error{cause}
	for _, in := range packages {
		if err := store(in); err != nil {
			errs = append(errs, fmt.Errorf("persist pending OSV assessment for %s %s: %w", in.Ecosystem, in.Identity, err))
		}
	}
	return errors.Join(errs...)
}

func deactivateAuthoritativelyRemoved(ctx context.Context, pool *pgxpool.Pool, current []input, deviceIDs []string) error {
	keys := make([]string, 0, len(current))
	for _, in := range current {
		keys = append(keys, in.key())
	}
	// A failed or partial report retains tooling_current_entries, so a subject
	// remains in current and is not closed here. A complete/not_present unit
	// prunes its entries first; only then can this derived assessment go inactive.
	_, err := pool.Exec(ctx, `
		UPDATE tooling_vulnerability_assessments a SET active=false, updated_at=now()
		WHERE a.active AND ($2::uuid[] IS NULL OR a.device_id=ANY($2::uuid[])) AND NOT EXISTS (
		 SELECT 1 FROM unnest($1::text[]) k
		 WHERE k = concat_ws(E'\x1f',a.device_id::text,a.subject_kind,a.identity_value,a.companion,a.version))`, keys, deviceIDs)
	return err
}

func loadQueueSnapshot(ctx context.Context, pool *pgxpool.Pool) ([]queueItem, error) {
	rows, err := pool.Query(ctx, `SELECT device_id::text,requested_at FROM tooling_vulnerability_refresh_queue ORDER BY requested_at,device_id LIMIT $1`, queueSnapshotLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []queueItem
	for rows.Next() {
		var item queueItem
		if err := rows.Scan(&item.DeviceID, &item.RequestedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func clearQueueSnapshot(ctx context.Context, pool *pgxpool.Pool, snapshot []queueItem) error {
	if len(snapshot) == 0 {
		return nil
	}
	ids := make([]string, len(snapshot))
	times := make([]time.Time, len(snapshot))
	for i, item := range snapshot {
		ids[i], times[i] = item.DeviceID, item.RequestedAt
	}
	_, err := pool.Exec(ctx, `DELETE FROM tooling_vulnerability_refresh_queue q USING
		unnest($1::uuid[],$2::timestamptz[]) AS snap(device_id,requested_at)
		WHERE q.device_id=snap.device_id AND q.requested_at <= snap.requested_at`, ids, times)
	return err
}

func matchCPE(ctx context.Context, pool *pgxpool.Pool, in input) ([]finding, string, error) {
	rows, err := pool.Query(ctx, `SELECT cpe_vendor,cpe_product FROM tooling_vulnerability_mappings
		WHERE identity_kind=$1 AND identity_value=$2 AND companion=$3 AND review_state='published' ORDER BY id`,
		mapKind(in.Kind), in.Identity, in.Source)
	if err != nil {
		return nil, "", err
	}
	var mappings []cvematch.CPEMapping
	var keys []string
	for rows.Next() {
		var vendor, product string
		if err := rows.Scan(&vendor, &product); err != nil {
			rows.Close()
			return nil, "", err
		}
		mappings = append(mappings, cvematch.CPEMapping{MatchName: in.Identity, CPEVendor: vendor, CPEProduct: product})
		keys = append(keys, vendor+":"+product)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	if len(mappings) == 0 {
		return nil, "no_curated_mapping", nil
	}
	frows, err := pool.Query(ctx, `SELECT cve_id,COALESCE(description,''),cvss_v3_score::float8,COALESCE(severity,''),cpe_patterns,cpe_ranges,published_at
		FROM cve_feed_entries WHERE cpe_patterns && $1::text[]`, keys)
	if err != nil {
		return nil, "", err
	}
	var feed []cvematch.CVEEntry
	for frows.Next() {
		var e cvematch.CVEEntry
		var ranges []byte
		var published *time.Time
		if err := frows.Scan(&e.CVEID, &e.Description, &e.Score, &e.Severity, &e.Patterns, &ranges, &published); err != nil {
			frows.Close()
			return nil, "", err
		}
		if published != nil {
			e.PublishedAt = *published
		}
		if err := json.Unmarshal(ranges, &e.Ranges); err != nil {
			frows.Close()
			return nil, "", err
		}
		feed = append(feed, e)
	}
	frows.Close()
	if err := frows.Err(); err != nil {
		return nil, "", err
	}
	matched := cvematch.Match([]cvematch.ScannedApp{{Name: in.Identity, Version: in.Version}}, mappings, feed, "")
	fs := make([]finding, 0, len(matched))
	seen := map[string]bool{}
	for _, f := range matched {
		if seen[f.CVEID] {
			continue
		}
		seen[f.CVEID] = true
		fs = append(fs, finding{Source: "nvd", ID: f.CVEID, CVE: f.CVEID, Severity: normaliseSeverity(f.Severity), Score: f.Score})
	}
	return fs, "", nil
}

func mapKind(k string) string {
	if k == "local_runtime" {
		return "local_model_runtime"
	}
	return k
}

func storeOSVRecord(ctx context.Context, pool *pgxpool.Pool, r osvRecord) error {
	sev, score := osvSeverityAndScore(r)
	aliases := r.Aliases
	if aliases == nil {
		aliases = []string{}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO tooling_advisories
		(source,advisory_id,canonical_cve_id,aliases,summary,details,severity,score,published_at,modified_at,withdrawn_at,raw_document,synced_at)
		VALUES ('osv',$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,now())
		ON CONFLICT(source,advisory_id) DO UPDATE SET canonical_cve_id=EXCLUDED.canonical_cve_id,
		aliases=EXCLUDED.aliases,summary=EXCLUDED.summary,details=EXCLUDED.details,severity=EXCLUDED.severity,
		score=EXCLUDED.score,published_at=EXCLUDED.published_at,modified_at=EXCLUDED.modified_at,withdrawn_at=EXCLUDED.withdrawn_at,
		raw_document=EXCLUDED.raw_document,synced_at=now()`, r.ID, nullString(canonicalCVE(r.Aliases)), aliases,
		r.Summary, r.Details, nullString(sev), score, r.Published, r.Modified, r.Withdrawn, []byte(r.Raw))
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `DELETE FROM tooling_advisory_packages WHERE source='osv' AND advisory_id=$1`, r.ID); err != nil {
		return err
	}
	for _, a := range r.Affected {
		if a.Package.Ecosystem != "npm" && a.Package.Ecosystem != "PyPI" {
			continue
		}
		ranges := a.Ranges
		if len(ranges) == 0 || string(ranges) == "null" {
			ranges = json.RawMessage(`[]`)
		}
		versions := a.Versions
		if versions == nil {
			versions = []string{}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO tooling_advisory_packages(source,advisory_id,ecosystem,package_name,affected_ranges,affected_versions)
			VALUES('osv',$1,$2,$3,$4,$5)`, r.ID, a.Package.Ecosystem, normalisePackage(a.Package.Ecosystem, a.Package.Name), ranges, versions); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func storeAssessment(ctx context.Context, pool *pgxpool.Pool, in input, state, reason string, findings []finding, lastError string) error {
	obs, err := json.Marshal(in.Observations)
	if err != nil {
		return fmt.Errorf("marshal tooling vulnerability observations for %s %s: %w", in.Kind, in.Identity, err)
	}
	entryKeys := make([]string, 0, len(in.Observations))
	for _, o := range in.Observations {
		if o.EntryKey != "" {
			entryKeys = append(entryKeys, o.EntryKey)
		}
	}
	sort.Strings(entryKeys)
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var id int64
	var count any
	var assessed any
	if state == "assessed" {
		count = len(findings)
		assessed = time.Now().UTC()
	}
	high := highest(findings)
	err = tx.QueryRow(ctx, `INSERT INTO tooling_vulnerability_assessments
		(tenant_id,device_id,subject_kind,ecosystem,package_name,identity_value,companion,version,state,reason,
		 finding_count,highest_severity,observations,current_entry_keys,input_observed_at,assessed_at,active,last_error,updated_at)
		VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,true,$17,now())
		ON CONFLICT(device_id,subject_kind,identity_value,companion,version) DO UPDATE SET
		tenant_id=EXCLUDED.tenant_id,ecosystem=EXCLUDED.ecosystem,package_name=EXCLUDED.package_name,state=EXCLUDED.state,
		reason=EXCLUDED.reason,finding_count=EXCLUDED.finding_count,highest_severity=EXCLUDED.highest_severity,
		observations=EXCLUDED.observations,current_entry_keys=EXCLUDED.current_entry_keys,
		input_observed_at=EXCLUDED.input_observed_at,assessed_at=EXCLUDED.assessed_at,
		active=true,last_error=EXCLUDED.last_error,updated_at=now() RETURNING id`, in.TenantID, in.DeviceID, in.Kind,
		nullString(in.Ecosystem), nullString(in.Package), in.Identity, in.Source, in.Version, state, nullString(reason), count,
		nullString(high), obs, entryKeys, in.ObservedAt, assessed, nullString(lastError)).Scan(&id)
	if err != nil {
		return err
	}
	if state != "assessed" {
		if _, err = tx.Exec(ctx, `DELETE FROM tooling_vulnerability_findings WHERE assessment_id=$1`, id); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	if _, err = tx.Exec(ctx, `DELETE FROM tooling_vulnerability_findings WHERE assessment_id=$1`, id); err != nil {
		return err
	}
	for _, f := range findings {
		if f.Source == "nvd" {
			raw, _ := json.Marshal(map[string]string{"source": "cve_feed_entries", "cve_id": f.ID})
			if _, err = tx.Exec(ctx, `INSERT INTO tooling_advisories(source,advisory_id,canonical_cve_id,aliases,severity,score,raw_document)
				VALUES('nvd',$1,$1,ARRAY[$1],$2,$3,$4) ON CONFLICT(source,advisory_id) DO UPDATE SET
				severity=EXCLUDED.severity,score=EXCLUDED.score,raw_document=EXCLUDED.raw_document,synced_at=now()`, f.ID, nullString(f.Severity), f.Score, raw); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(ctx, `INSERT INTO tooling_vulnerability_findings(assessment_id,source,advisory_id,canonical_cve_id,severity,score)
			VALUES($1,$2,$3,$4,$5,$6)`, id, f.Source, f.ID, nullString(f.CVE), nullString(f.Severity), f.Score); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

func osvSeverityAndScore(r osvRecord) (string, *float64) {
	// Prefer the strongest authoritative label found in OSV database/ecosystem
	// metadata or a supported top-level CVSS vector. The score is retained from
	// the strongest supported vector even when metadata supplies the label.
	var d struct {
		Severity string `json:"severity"`
	}
	best := "UNKNOWN"
	if json.Unmarshal(r.Database, &d) == nil && d.Severity != "" {
		best = normaliseSeverity(d.Severity)
	}
	for _, a := range r.Affected {
		for _, raw := range []json.RawMessage{a.EcosystemSpecific, a.DatabaseSpecific} {
			d = struct {
				Severity string `json:"severity"`
			}{}
			if json.Unmarshal(raw, &d) == nil && severityRank(normaliseSeverity(d.Severity)) > severityRank(best) {
				best = normaliseSeverity(d.Severity)
			}
		}
	}
	var bestScore *float64
	for _, entry := range r.Severity {
		score, ok := cvssBaseScore(entry.Score)
		if !ok {
			continue
		}
		if bestScore == nil || score > *bestScore {
			s := score
			bestScore = &s
		}
	}
	if bestScore != nil {
		fromScore := severityForScore(*bestScore)
		if severityRank(fromScore) > severityRank(best) {
			best = fromScore
		}
	}
	return best, bestScore
}

func osvSeverity(r osvRecord) string {
	severity, _ := osvSeverityAndScore(r)
	return severity
}

func cvssBaseScore(vector string) (float64, bool) {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		parsed, err := gocvss30.ParseVector(vector)
		if err == nil {
			return parsed.BaseScore(), true
		}
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		parsed, err := gocvss31.ParseVector(vector)
		if err == nil {
			return parsed.BaseScore(), true
		}
	case strings.HasPrefix(vector, "CVSS:4.0/"):
		parsed, err := gocvss40.ParseVector(vector)
		if err == nil {
			return parsed.Score(), true
		}
	}
	return 0, false
}

func severityForScore(score float64) string {
	switch {
	case score == 0:
		return "NONE"
	case score < 4:
		return "LOW"
	case score < 7:
		return "MEDIUM"
	case score < 9:
		return "HIGH"
	default:
		return "CRITICAL"
	}
}
func normaliseSeverity(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	switch s {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE":
		return s
	}
	return "UNKNOWN"
}
func canonicalCVE(aliases []string) string {
	for _, a := range aliases {
		u := strings.ToUpper(a)
		if strings.HasPrefix(u, "CVE-") {
			return u
		}
	}
	return ""
}
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func highest(fs []finding) string {
	h := ""
	for _, f := range fs {
		if severityRank(f.Severity) > severityRank(h) {
			h = f.Severity
		}
	}
	return h
}

func severityRank(s string) int {
	if s == "" {
		return 0
	}
	return map[string]int{"UNKNOWN": 1, "NONE": 2, "LOW": 3, "MEDIUM": 4, "HIGH": 5, "CRITICAL": 6}[normaliseSeverity(s)]
}
