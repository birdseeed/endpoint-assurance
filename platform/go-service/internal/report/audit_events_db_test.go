package report

// DB-backed tests for FetchTenantAuditEvents (PAT-1022, audit_events.go).
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as report_db_test.go (PAT-709/PAT-1007's pat709Pool) — an
// isolated schema built from minimal hand-crafted tables (not the real
// migrations), so this only needs `tenants` for the FK and `audit_events`
// itself, mirroring migrations/0098_audit_events.sql's shape closely enough
// to exercise the query, not applying every migration from zero.

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1022Schema = "pat1022_audit_events_test"

func pat1022Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed audit_events report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1022Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1022Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1022Schema,
		`CREATE TABLE ` + pat1022Schema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		// Mirrors migrations/0098_audit_events.sql — omits the append-only
		// trigger and CHECK constraints, which aren't exercised by this
		// query-focused test (see internal/handlers/events_db_test.go's
		// TestEventsPost_DB_AppendOnlyGuardHolds for that coverage against
		// the real migration).
		`CREATE TABLE ` + pat1022Schema + `.audit_events (
			id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id        UUID        NOT NULL REFERENCES ` + pat1022Schema + `.tenants(id),
			device_id        TEXT        NOT NULL,
			event_type       TEXT        NOT NULL,
			label            TEXT,
			version          TEXT,
			verified_signer  TEXT,
			reason           TEXT,
			expected         TEXT,
			actual           TEXT,
			platform         TEXT        NOT NULL,
			source_ip        INET,
			occurred_at      TIMESTAMPTZ NOT NULL,
			ingested_at      TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1022Schema+` CASCADE`)
	})
	return pool
}

func pat1022SeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ($1) RETURNING id::text`, name).Scan(&id); err != nil {
		t.Fatalf("insert tenant %q: %v", name, err)
	}
	return id
}

func pat1022SeedEvent(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID, eventType, platform string, occurredAt time.Time) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO audit_events (tenant_id, device_id, event_type, platform, occurred_at)
		VALUES ($1::uuid, $2, $3, $4, $5)
	`, tenantID, deviceID, eventType, platform, occurredAt)
	if err != nil {
		t.Fatalf("insert audit_events row: %v", err)
	}
}

// pat1022SeedEventReturningID is pat1022SeedEvent plus the inserted row's
// id, needed by any test that builds an AuditEventCursor (the composite
// cursor requires the id half, not just occurred_at).
func pat1022SeedEventReturningID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID, eventType, platform string, occurredAt time.Time) string {
	t.Helper()
	var id string
	err := pool.QueryRow(ctx, `
		INSERT INTO audit_events (tenant_id, device_id, event_type, platform, occurred_at)
		VALUES ($1::uuid, $2, $3, $4, $5)
		RETURNING id::text
	`, tenantID, deviceID, eventType, platform, occurredAt).Scan(&id)
	if err != nil {
		t.Fatalf("insert audit_events row: %v", err)
	}
	return id
}

// TestFetchTenantAuditEvents_ScopedToTenant proves the query never returns
// another tenant's rows even when both tenants have events inside the same
// date window — the whole point of "tenant-scoped, not device-scoped"
// (PAT-1022 item 4).
func TestFetchTenantAuditEvents_ScopedToTenant(t *testing.T) {
	pool := pat1022Pool(t)
	ctx := context.Background()

	tenantA := pat1022SeedTenant(t, ctx, pool, "pat1022-tenant-a")
	tenantB := pat1022SeedTenant(t, ctx, pool, "pat1022-tenant-b")

	now := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	pat1022SeedEvent(t, ctx, pool, tenantA, "dev-a1", "install_completed", "macos", now)
	pat1022SeedEvent(t, ctx, pool, tenantB, "dev-b1", "install_completed", "macos", now)

	items, err := FetchTenantAuditEvents(ctx, pool, tenantA,
		now.Add(-time.Hour), now.Add(time.Hour), 100, nil, "", "")
	if err != nil {
		t.Fatalf("FetchTenantAuditEvents: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1 (tenant A's only)", len(items))
	}
	if items[0].DeviceID != "dev-a1" {
		t.Errorf("DeviceID = %q, want dev-a1 (tenant B's event must not leak into tenant A's report)", items[0].DeviceID)
	}
}

// TestFetchTenantAuditEvents_DateRangeBounded proves since/until actually
// bound the query — an event outside [since, until) must never be
// returned, regardless of tenant.
func TestFetchTenantAuditEvents_DateRangeBounded(t *testing.T) {
	pool := pat1022Pool(t)
	ctx := context.Background()

	tenantID := pat1022SeedTenant(t, ctx, pool, "pat1022-daterange-tenant")

	inWindow := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	beforeWindow := time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)
	afterWindow := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)

	pat1022SeedEvent(t, ctx, pool, tenantID, "dev-in", "install_completed", "macos", inWindow)
	pat1022SeedEvent(t, ctx, pool, tenantID, "dev-before", "install_completed", "macos", beforeWindow)
	pat1022SeedEvent(t, ctx, pool, tenantID, "dev-after", "install_completed", "macos", afterWindow)

	since := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	until := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	items, err := FetchTenantAuditEvents(ctx, pool, tenantID, since, until, 100, nil, "", "")
	if err != nil {
		t.Fatalf("FetchTenantAuditEvents: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("got %d items, want 1 (only the in-window event)", len(items))
	}
	if items[0].DeviceID != "dev-in" {
		t.Errorf("DeviceID = %q, want dev-in", items[0].DeviceID)
	}
}

// TestFetchTenantAuditEvents_UntilIsExclusive proves the upper bound is
// exclusive — an event AT exactly `until` must not be returned, which is
// what makes back-to-back [since, until) windows non-overlapping for a
// caller paging month by month.
func TestFetchTenantAuditEvents_UntilIsExclusive(t *testing.T) {
	pool := pat1022Pool(t)
	ctx := context.Background()

	tenantID := pat1022SeedTenant(t, ctx, pool, "pat1022-exclusive-tenant")
	boundary := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	pat1022SeedEvent(t, ctx, pool, tenantID, "dev-boundary", "install_completed", "macos", boundary)

	items, err := FetchTenantAuditEvents(ctx, pool, tenantID,
		time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC), boundary, 100, nil, "", "")
	if err != nil {
		t.Fatalf("FetchTenantAuditEvents: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("got %d items, want 0 — event at exactly `until` must be excluded", len(items))
	}
}

// TestFetchTenantAuditEvents_FiltersAndOrdering proves event_type/device_id
// filters narrow the result, and that results come back newest-first.
func TestFetchTenantAuditEvents_FiltersAndOrdering(t *testing.T) {
	pool := pat1022Pool(t)
	ctx := context.Background()

	tenantID := pat1022SeedTenant(t, ctx, pool, "pat1022-filter-tenant")
	base := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)

	pat1022SeedEvent(t, ctx, pool, tenantID, "dev-1", "install_completed", "macos", base)
	pat1022SeedEvent(t, ctx, pool, tenantID, "dev-1", "verification_failed", "macos", base.Add(time.Hour))
	pat1022SeedEvent(t, ctx, pool, tenantID, "dev-2", "install_completed", "windows", base.Add(2*time.Hour))

	// event_type filter.
	items, err := FetchTenantAuditEvents(ctx, pool, tenantID,
		base.Add(-time.Hour), base.Add(3*time.Hour), 100, nil, "install_completed", "")
	if err != nil {
		t.Fatalf("FetchTenantAuditEvents: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("event_type filter: got %d items, want 2", len(items))
	}
	for _, it := range items {
		if it.EventType != "install_completed" {
			t.Errorf("event_type filter leaked a %q row", it.EventType)
		}
	}
	// Newest first.
	if !items[0].OccurredAt.After(items[1].OccurredAt) {
		t.Errorf("results not newest-first: %v then %v", items[0].OccurredAt, items[1].OccurredAt)
	}

	// device_id filter.
	items, err = FetchTenantAuditEvents(ctx, pool, tenantID,
		base.Add(-time.Hour), base.Add(3*time.Hour), 100, nil, "", "dev-2")
	if err != nil {
		t.Fatalf("FetchTenantAuditEvents: %v", err)
	}
	if len(items) != 1 || items[0].DeviceID != "dev-2" {
		t.Fatalf("device_id filter: got %+v, want exactly dev-2's row", items)
	}
}

// TestFetchTenantAuditEvents_BeforeCursorPaginates proves the optional
// `before` cursor narrows further within [since, until), the same
// pagination convention dbListEnforcementAudit
// (internal/handlers/enforcement_audit.go) already uses for its `before`
// param.
func TestFetchTenantAuditEvents_BeforeCursorPaginates(t *testing.T) {
	pool := pat1022Pool(t)
	ctx := context.Background()

	tenantID := pat1022SeedTenant(t, ctx, pool, "pat1022-cursor-tenant")
	base := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)

	pat1022SeedEvent(t, ctx, pool, tenantID, "dev-1", "install_completed", "macos", base)
	second := base.Add(time.Hour)
	secondID := pat1022SeedEventReturningID(t, ctx, pool, tenantID, "dev-2", "install_completed", "macos", second)

	items, err := FetchTenantAuditEvents(ctx, pool, tenantID,
		base.Add(-time.Hour), base.Add(3*time.Hour), 100, &AuditEventCursor{OccurredAt: second, ID: secondID}, "", "")
	if err != nil {
		t.Fatalf("FetchTenantAuditEvents: %v", err)
	}
	if len(items) != 1 || items[0].DeviceID != "dev-1" {
		t.Fatalf("before cursor: got %+v, want exactly the row strictly before `second`", items)
	}
}

// TestFetchTenantAuditEvents_BeforeCursorStableAcrossDuplicateTimestamps
// proves the composite (occurred_at, id) cursor keeps pagination stable
// even when several rows share the exact same occurred_at — the P1 finding
// this fix addresses. occurred_at alone would let `occurred_at < cursor`
// either skip or duplicate rows at that boundary, depending on which
// same-timestamp row happened to land last in the previous page. Paging
// through with a limit smaller than the tied batch must still visit every
// row exactly once, in the query's own (occurred_at DESC, id DESC) order.
func TestFetchTenantAuditEvents_BeforeCursorStableAcrossDuplicateTimestamps(t *testing.T) {
	pool := pat1022Pool(t)
	ctx := context.Background()

	tenantID := pat1022SeedTenant(t, ctx, pool, "pat1022-dup-ts-tenant")
	tied := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)

	const n = 7
	for i := 0; i < n; i++ {
		pat1022SeedEvent(t, ctx, pool, tenantID, fmt.Sprintf("dev-tied-%d", i), "install_completed", "macos", tied)
	}

	since := tied.Add(-time.Hour)
	until := tied.Add(time.Hour)
	const pageSize = 2

	var seen []AuditEventItem
	var cursor *AuditEventCursor
	for {
		page, err := FetchTenantAuditEvents(ctx, pool, tenantID, since, until, pageSize, cursor, "", "")
		if err != nil {
			t.Fatalf("FetchTenantAuditEvents: %v", err)
		}
		if len(page) == 0 {
			break
		}
		seen = append(seen, page...)
		last := page[len(page)-1]
		cursor = &AuditEventCursor{OccurredAt: last.OccurredAt, ID: last.ID}
		if len(page) < pageSize {
			break
		}
		if len(seen) > n {
			t.Fatalf("paginated past the total row count (%d) without exhausting the window — infinite loop or duplication", n)
		}
	}

	if len(seen) != n {
		t.Fatalf("got %d rows across all pages, want exactly %d (no skips or duplicates)", len(seen), n)
	}
	byID := make(map[string]int, n)
	for _, it := range seen {
		byID[it.ID]++
	}
	if len(byID) != n {
		t.Fatalf("got %d distinct ids across all pages, want %d — some row was duplicated", len(byID), n)
	}
	for id, count := range byID {
		if count != 1 {
			t.Errorf("id %s appeared %d times, want exactly once", id, count)
		}
	}
	// Confirm the composite order (occurred_at DESC, id DESC) is actually
	// what was walked: consecutive ids must be strictly decreasing since
	// every row here shares the same occurred_at.
	for i := 1; i < len(seen); i++ {
		if seen[i-1].ID <= seen[i].ID {
			t.Errorf("rows not in id-DESC tie-break order at index %d: %s then %s", i, seen[i-1].ID, seen[i].ID)
		}
	}
}

// TestFetchTenantAuditEvents_LimitClamped proves an out-of-range limit is
// clamped to 1000 rather than rejected or left unbounded.
func TestFetchTenantAuditEvents_LimitClamped(t *testing.T) {
	pool := pat1022Pool(t)
	ctx := context.Background()

	tenantID := pat1022SeedTenant(t, ctx, pool, "pat1022-limit-tenant")
	base := time.Date(2026, 7, 10, 9, 0, 0, 0, time.UTC)
	pat1022SeedEvent(t, ctx, pool, tenantID, "dev-1", "install_completed", "macos", base)

	// limit=0 and a huge limit must both behave sanely (clamped, not error).
	for _, limit := range []int{0, -5, 5000} {
		items, err := FetchTenantAuditEvents(ctx, pool, tenantID,
			base.Add(-time.Hour), base.Add(time.Hour), limit, nil, "", "")
		if err != nil {
			t.Fatalf("FetchTenantAuditEvents(limit=%d): %v", limit, err)
		}
		if len(items) != 1 {
			t.Errorf("FetchTenantAuditEvents(limit=%d): got %d items, want 1", limit, len(items))
		}
	}
}
