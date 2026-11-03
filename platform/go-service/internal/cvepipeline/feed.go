package cvepipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"sort"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvelifecycle"
	"patched.im/api/internal/cvematch"
)

// FeedMatchState is the part of a cve_feed_entries row that can change a
// match result. Description, vector and timestamps are deliberately absent:
// a change to those alone re-matches nothing.
type FeedMatchState struct {
	Patterns []string
	Ranges   []cvematch.CPERange
	Score    *float64
	Severity string
}

// LoadFeedMatchStates reads the current match-relevant state of the given
// CVE IDs, before a sync page overwrites them. Missing IDs are new entries.
func LoadFeedMatchStates(ctx context.Context, q DB, cveIDs []string) (map[string]FeedMatchState, error) {
	out := map[string]FeedMatchState{}
	if len(cveIDs) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `
		SELECT cve_id, cpe_patterns, cpe_ranges, cvss_v3_score::float8, COALESCE(severity, '')
		FROM cve_feed_entries WHERE cve_id = ANY($1::text[])
	`, cveIDs)
	if err != nil {
		return nil, fmt.Errorf("load prior feed state: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var st FeedMatchState
		var rangesRaw []byte
		if err := rows.Scan(&id, &st.Patterns, &rangesRaw, &st.Score, &st.Severity); err != nil {
			return nil, fmt.Errorf("scan prior feed state: %w", err)
		}
		if len(rangesRaw) > 0 && string(rangesRaw) != "null" {
			if err := json.Unmarshal(rangesRaw, &st.Ranges); err != nil {
				return nil, fmt.Errorf("unmarshal prior cpe_ranges for %s: %w", id, err)
			}
		}
		out[id] = st
	}
	return out, rows.Err()
}

// FeedDeltaKeys returns the CPE keys whose matches may have changed between
// prior (state before the sync, keyed by CVE ID) and next (state written by
// the sync). A new CVE contributes its keys; a changed CVE contributes the
// union of its old and new keys, so a product dropped from a CVE's
// configuration has its now-stale findings re-matched away. An unchanged CVE
// contributes nothing. Pure; unit-tested.
func FeedDeltaKeys(prior, next map[string]FeedMatchState) []string {
	keys := map[string]bool{}
	for id, n := range next {
		p, existed := prior[id]
		if existed && sameMatchState(p, n) {
			continue
		}
		for _, k := range n.Patterns {
			keys[k] = true
		}
		if existed {
			for _, k := range p.Patterns {
				keys[k] = true
			}
		}
	}
	delete(keys, "")
	return sortedKeys(keys)
}

func sameMatchState(a, b FeedMatchState) bool {
	if a.Severity != b.Severity || !equalStrings(uniqueSorted(a.Patterns), uniqueSorted(b.Patterns)) {
		return false
	}
	if (a.Score == nil) != (b.Score == nil) || (a.Score != nil && *a.Score != *b.Score) {
		return false
	}
	if len(a.Ranges) == 0 && len(b.Ranges) == 0 {
		return true
	}
	return reflect.DeepEqual(a.Ranges, b.Ranges)
}

// RecordFeedDelta durably records CPE keys a sync touched. It is written per
// page as the sync proceeds, so a crash part-way through keeps what was
// already ingested marked for re-matching.
func RecordFeedDelta(ctx context.Context, q DB, keys []string) error {
	keys = uniqueSorted(keys)
	if len(keys) == 0 {
		return nil
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO cve_feed_delta (cpe_key, recorded_at)
		SELECT k, now() FROM unnest($1::text[]) AS k WHERE btrim(k) <> ''
		ON CONFLICT (cpe_key) DO UPDATE SET recorded_at = EXCLUDED.recorded_at
	`, keys); err != nil {
		return fmt.Errorf("record feed delta: %w", err)
	}
	return nil
}

// ClearFeedDeltaBefore drops delta keys recorded before cutoff. The nightly
// full match calls it with the time it started loading the feed: every key
// recorded before then is covered by the full match.
func ClearFeedDeltaBefore(ctx context.Context, q DB, cutoff time.Time) error {
	if _, err := q.Exec(ctx, `DELETE FROM cve_feed_delta WHERE recorded_at < $1`, cutoff); err != nil {
		return fmt.Errorf("clear feed delta: %w", err)
	}
	return nil
}

// FeedDeltaResult reports what one MatchFeedDelta run did.
type FeedDeltaResult struct {
	Keys         int // CPE keys pending in cve_feed_delta at the start
	Mappings     int // mappings resolving to one of those keys
	Observations int // (device, product) observations re-matched
	Findings     int
	NewFindings  int
	// SkippedForFullMatch: a full match held the match lock; the delta is
	// left in place (the full match clears what it covers).
	SkippedForFullMatch bool
}

// MatchFeedDelta re-matches only the observations whose CPE mapping resolves
// to a key recorded in cve_feed_delta, against the local CVE store, then
// clears the keys it covered. Observations are application products and,
// since PAT-2045, current Homebrew formulae and casks with a curated mapping
// on one of those keys. An observation of an unaffected product is not
// touched. A failure leaves the delta in place for the next run.
func MatchFeedDelta(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) (FeedDeltaResult, error) {
	var res FeedDeltaResult
	if logger == nil {
		logger = slog.Default()
	}
	release, ok, err := tryTargetedMatchLock(ctx, pool)
	if err != nil {
		return res, err
	}
	if !ok {
		res.SkippedForFullMatch = true
		logger.Info("feed delta match skipped: a full match is running and covers it")
		return res, nil
	}
	defer release()
	rows, err := pool.Query(ctx, `SELECT cpe_key, recorded_at FROM cve_feed_delta ORDER BY cpe_key`)
	if err != nil {
		if isUndefinedTable(err) {
			return res, fmt.Errorf("cve_feed_delta table not found: apply migration 0161 before using the delta modes: %w", err)
		}
		return res, fmt.Errorf("load feed delta: %w", err)
	}
	var keys []string
	var recordedAt []time.Time
	keySet := map[string]bool{}
	for rows.Next() {
		var k string
		var at time.Time
		if err := rows.Scan(&k, &at); err != nil {
			rows.Close()
			return res, fmt.Errorf("scan feed delta: %w", err)
		}
		keys = append(keys, k)
		recordedAt = append(recordedAt, at)
		keySet[k] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("iterate feed delta: %w", err)
	}
	res.Keys = len(keys)
	if res.Keys == 0 {
		logger.Info("feed delta match: no CPE keys pending, nothing to re-match (run --mode=delta-sync to fetch and record a delta)")
	}

	mappings, err := LoadMappings(ctx, pool)
	if err != nil {
		return res, err
	}
	var affectedNames []string
	for _, m := range mappings {
		if keySet[m.CPEKey()] {
			res.Mappings++
			affectedNames = append(affectedNames, m.MatchName)
		}
	}
	jobs, err := activeObservationsMatching(ctx, pool, uniqueSorted(affectedNames))
	if err != nil {
		return res, err
	}
	// PAT-2045: Homebrew packages whose curated mapping resolves to a touched
	// key are re-matched too, through the Homebrew matcher (matchDevice
	// routes their display names to matchDeviceHomebrew). A mapping that is
	// not curated never matches, so a delta on its key changes nothing.
	brewMappings, err := LoadHomebrewMappings(ctx, pool)
	if err != nil {
		return res, err
	}
	var brewKeys []homebrewKey
	for _, m := range brewMappings {
		if m.ReviewState != cvematch.MappingCurated || !keySet[m.CPEKey()] {
			continue
		}
		if k, ok := homebrewKeyForSource(m.SourceType, m.Name); ok {
			res.Mappings++
			brewKeys = append(brewKeys, k)
		}
	}
	brewJobs, err := activeHomebrewObservations(ctx, pool, brewKeys)
	if err != nil {
		return res, err
	}
	jobs = append(jobs, brewJobs...)
	byDevice := map[string][]string{}
	var devices []string
	for _, j := range jobs {
		if byDevice[j.DeviceID] == nil {
			devices = append(devices, j.DeviceID)
		}
		byDevice[j.DeviceID] = append(byDevice[j.DeviceID], j.AppName)
	}
	sort.Strings(devices)

	ix := newMappingIndex(mappings)
	feed := newFeedCache()
	var total matchOutcome
	var errs []error
	for _, deviceID := range devices {
		outcome, err := matchDeviceTx(ctx, pool, ix, feed, deviceID, byDevice[deviceID], SourceFeedSync)
		if err != nil {
			errs = append(errs, fmt.Errorf("device %s: %w", deviceID, err))
			continue
		}
		total.add(outcome)
	}
	res.Observations = total.Observations
	res.Findings = total.Findings
	res.NewFindings = len(total.New)

	if err := cvelifecycle.ReconcileIdentities(ctx, pool, total.Identities, logger); err != nil {
		errs = append(errs, fmt.Errorf("reconcile CVE lifecycle after feed delta: %w", err))
	}
	fireNewFindingWebhooks(pool, total.New)
	if len(errs) > 0 {
		return res, errors.Join(errs...)
	}
	// Clear exactly the keys this run covered, and only if no later sync
	// re-recorded them meanwhile.
	if len(keys) > 0 {
		if _, err := pool.Exec(ctx, `
			DELETE FROM cve_feed_delta d
			USING unnest($1::text[], $2::timestamptz[]) AS done(cpe_key, recorded_at)
			WHERE d.cpe_key = done.cpe_key AND d.recorded_at <= done.recorded_at
		`, keys, recordedAt); err != nil {
			return res, fmt.Errorf("clear covered feed delta: %w", err)
		}
	}
	if err := RecordRun(ctx, pool, "delta_match", time.Now().UTC()); err != nil {
		return res, err
	}
	logger.Info("feed delta matched", "cpe_keys", res.Keys, "mappings", res.Mappings,
		"observations", res.Observations, "findings", res.Findings, "new_findings", res.NewFindings)
	return res, nil
}

func matchDeviceTx(ctx context.Context, pool *pgxpool.Pool, ix *mappingIndex, feed *feedCache,
	deviceID string, names []string, source string) (matchOutcome, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return matchOutcome{}, fmt.Errorf("begin device match: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	outcome, err := matchDevice(ctx, tx, ix, feed, deviceID, names, source)
	if err != nil {
		return matchOutcome{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return matchOutcome{}, fmt.Errorf("commit device match: %w", err)
	}
	return outcome, nil
}
