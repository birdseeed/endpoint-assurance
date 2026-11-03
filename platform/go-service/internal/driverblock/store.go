package driverblock

import (
	"context"
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

// SourceFreshFor allows one missed nightly refresh before a list is reported
// stale. A stale list is still matched (a hash that was listed stays a
// finding), but every finding and the list summary say how old it is.
const SourceFreshFor = 48 * time.Hour

// MinRetainedFraction guards against a truncated or wrong document that still
// parses: a refresh whose entry count falls below this fraction of the last
// good list's is refused and recorded as a failure, keeping the last good
// list. Genuine list shrinkage of that size would need a human to look.
const MinRetainedFraction = 0.5

// ErrImplausibleShrink is returned when a refresh would replace a list with
// one less than MinRetainedFraction of its size.
var ErrImplausibleShrink = errors.New("refresh would shrink the list implausibly; last good list kept")

// SourceState is the stored state of one source.
type SourceState struct {
	Source         string
	SourceURL      string
	Status         string // succeeded | failed (the latest attempt)
	AttemptedAt    time.Time
	FetchedAt      *time.Time // the last successful fetch
	SourceRevision string
	EntryCount     int
	LastError      string
}

// Stale reports whether findings from this source rest on an old list.
func (s SourceState) Stale(now time.Time) bool {
	return s.FetchedAt == nil || s.Status != "succeeded" || now.Sub(s.FetchedAt.UTC()) > SourceFreshFor
}

// Fetch downloads and parses one source. authorityURL is fixed in the
// returned provenance even when fetchURL points at a controlled mirror.
// Redirects (aka.ms to download.microsoft.com) are followed only to HTTPS.
// Transient failures are retried with the shared bounded backoff
// (internal/httpretry); a 4xx or a parse failure is not.
func Fetch(ctx context.Context, client *http.Client, source, fetchURL string, fetchedAt time.Time) (Snapshot, error) {
	if client == nil {
		client = &http.Client{
			Timeout: 120 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				if req.URL.Scheme != "https" {
					return errors.New("refusing a non-HTTPS redirect")
				}
				return nil
			},
		}
	}
	if fetchURL == "" {
		var err error
		if fetchURL, err = AuthorityURL(source); err != nil {
			return Snapshot{}, err
		}
	}
	parsed, err := url.ParseRequestURI(fetchURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return Snapshot{}, fmt.Errorf("driver blocklist source URL must be an absolute HTTPS URL")
	}
	limit := int64(maxMicrosoftDocumentBytes)
	if source == SourceLOLDrivers {
		limit = maxLOLDriversBytes
	}
	body, err := httpretry.Do(ctx, httpretry.Options{
		MaxAttempts: httpretry.DefaultMaxAttempts,
		OverallCap:  httpretry.DefaultOverallCap,
		Backoff:     httpretry.DefaultBackoff,
		IsRetryable: httpretry.IsRetryable,
		RetryAfter: func(err error) time.Duration {
			var httpErr *httpretry.HTTPError
			if errors.As(err, &httpErr) {
				return httpErr.RetryAfter
			}
			return 0
		},
		Status: func(err error) int {
			var httpErr *httpretry.HTTPError
			if errors.As(err, &httpErr) {
				return httpErr.StatusCode
			}
			return 0
		},
		Logger:    slog.Default(),
		LogAction: "driver blocklist fetch",
		Source:    source,
		Document:  source,
		Sleep:     httpretry.SleepCtx,
	}, func(ctx context.Context) ([]byte, error) {
		return fetchOnce(ctx, client, fetchURL, limit)
	})
	if err != nil {
		return Snapshot{}, err
	}
	return Parse(source, body, fetchedAt)
}

func fetchOnce(ctx context.Context, client *http.Client, rawURL string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "patched-cve-sync (+https://patched.im)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, &httpretry.TransportError{Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, &httpretry.HTTPError{
			StatusCode: resp.StatusCode,
			RetryAfter: httpretry.ParseRetryAfter(resp.Header.Get("Retry-After"), httpretry.DefaultRetryAfterCap),
		}
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("source document exceeds %d bytes", limit)
	}
	return body, nil
}

// ReplaceSnapshot atomically replaces one source's entries and marks it
// succeeded. It refuses (and stores nothing) when the snapshot's provenance
// is inconsistent, or when it would shrink the stored list below
// MinRetainedFraction; the caller then records the failure.
func ReplaceSnapshot(ctx context.Context, pool *pgxpool.Pool, snapshot Snapshot, attemptedAt time.Time) error {
	authority, err := AuthorityURL(snapshot.Source)
	if err != nil {
		return err
	}
	if snapshot.SourceURL != authority {
		return fmt.Errorf("store driver blocklist: source %q authority URL mismatch", snapshot.Source)
	}
	if snapshot.FetchedAt.IsZero() || len(snapshot.Entries) == 0 {
		return errors.New("store driver blocklist: a snapshot needs a fetched time and entries")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin driver blocklist snapshot: %w", err)
	}
	defer tx.Rollback(ctx)

	var previous int
	var previousStatus string
	err = tx.QueryRow(ctx, `SELECT entry_count, status FROM driver_blocklist_source_state
		WHERE source = $1 FOR UPDATE`, snapshot.Source).Scan(&previous, &previousStatus)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("read driver blocklist state: %w", err)
	}
	if previous > 0 && float64(len(snapshot.Entries)) < float64(previous)*MinRetainedFraction {
		return fmt.Errorf("%s: %d entries against %d: %w", snapshot.Source, len(snapshot.Entries), previous, ErrImplausibleShrink)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO driver_blocklist_source_state
			(source, source_url, status, attempted_at, fetched_at, source_revision, entry_count, last_error)
		VALUES ($1, $2, 'succeeded', $3, $4, $5, $6, NULL)
		ON CONFLICT (source) DO UPDATE SET
			source_url = EXCLUDED.source_url, status = 'succeeded', attempted_at = EXCLUDED.attempted_at,
			fetched_at = EXCLUDED.fetched_at, source_revision = EXCLUDED.source_revision,
			entry_count = EXCLUDED.entry_count, last_error = NULL`,
		snapshot.Source, snapshot.SourceURL, attemptedAt.UTC(), snapshot.FetchedAt.UTC(),
		boundRunes(snapshot.SourceRevision, maxRevisionRunes), len(snapshot.Entries)); err != nil {
		return fmt.Errorf("upsert driver blocklist state: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM driver_blocklist_entries WHERE source = $1`, snapshot.Source); err != nil {
		return fmt.Errorf("clear driver blocklist entries: %w", err)
	}
	rows := make([][]any, 0, len(snapshot.Entries))
	for _, e := range snapshot.Entries {
		rows = append(rows, []any{snapshot.Source, e.HashKind, e.Hash, e.EntryID, e.EntryName, e.Category,
			snapshot.FetchedAt.UTC(), snapshot.SourceRevision})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"driver_blocklist_entries"},
		[]string{"source", "hash_kind", "hash", "entry_id", "entry_name", "category", "fetched_at", "source_revision"},
		pgx.CopyFromRows(rows)); err != nil {
		return fmt.Errorf("insert driver blocklist entries: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit driver blocklist snapshot: %w", err)
	}
	return nil
}

// RecordFailure marks the latest attempt failed without touching the entries
// or the last successful fetch time: the last good list stays, and its age
// shows it is stale. reason is a fixed category kept for operators
// (fetch_or_parse_failed, store_failed, implausible_shrink); it is bounded
// and must never carry response content or a URL.
func RecordFailure(ctx context.Context, pool *pgxpool.Pool, source string, attemptedAt time.Time, reason string) error {
	authority, err := AuthorityURL(source)
	if err != nil {
		return err
	}
	reason = boundRunes(strings.TrimSpace(reason), 512)
	_, err = pool.Exec(ctx, `
		INSERT INTO driver_blocklist_source_state
			(source, source_url, status, attempted_at, fetched_at, source_revision, entry_count, last_error)
		VALUES ($1, $2, 'failed', $3, NULL, '', 0, $4)
		ON CONFLICT (source) DO UPDATE SET
			status = 'failed', attempted_at = EXCLUDED.attempted_at, last_error = EXCLUDED.last_error`,
		source, authority, attemptedAt.UTC(), reason)
	if err != nil {
		return fmt.Errorf("record driver blocklist failure: %w", err)
	}
	return nil
}

// LoadSourceStates reads every source's stored state.
func LoadSourceStates(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (map[string]SourceState, error) {
	rows, err := q.Query(ctx, `SELECT source, source_url, status, attempted_at, fetched_at,
			source_revision, entry_count, COALESCE(last_error, '')
		FROM driver_blocklist_source_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]SourceState{}
	for rows.Next() {
		var s SourceState
		if err := rows.Scan(&s.Source, &s.SourceURL, &s.Status, &s.AttemptedAt, &s.FetchedAt,
			&s.SourceRevision, &s.EntryCount, &s.LastError); err != nil {
			return nil, err
		}
		out[s.Source] = s
	}
	return out, rows.Err()
}
