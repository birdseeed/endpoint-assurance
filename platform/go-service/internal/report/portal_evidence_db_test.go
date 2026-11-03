package report

// DB-backed regression coverage for the evidence lookup's ordering and page
// boundary. Skipped unless TEST_DATABASE_URL points at a scratch Postgres.

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1867Schema = "pat1867_test"

func pat1867Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed portal evidence test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1867Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("new pool: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, stmt := range []string{
		`DROP SCHEMA IF EXISTS ` + pat1867Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1867Schema,
		`CREATE TABLE ` + pat1867Schema + `.devices (
			id UUID PRIMARY KEY,
			tenant_id UUID NOT NULL
		)`,
		`CREATE TABLE ` + pat1867Schema + `.raw_payloads (
			id BIGSERIAL PRIMARY KEY,
			tenant_id UUID NOT NULL,
			device_id UUID,
			received_at TIMESTAMPTZ NOT NULL,
			body JSONB NOT NULL
		)`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			pool.Close()
			t.Fatalf("schema setup: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1867Schema+` CASCADE`)
	})
	return pool
}

func insertPAT1867Payload(t *testing.T, pool *pgxpool.Pool, tenantID, deviceID string, received time.Time, payload map[string]any) int64 {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var id int64
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO raw_payloads (tenant_id, device_id, received_at, body)
		VALUES ($1::uuid, $2::uuid, $3, $4::jsonb)
		RETURNING id
	`, tenantID, deviceID, received, body).Scan(&id); err != nil {
		t.Fatalf("insert payload: %v", err)
	}
	return id
}

func TestFetchPortalDeviceEvidenceNewestRowAndPageScope(t *testing.T) {
	pool := pat1867Pool(t)
	ctx := context.Background()
	now := time.Date(2026, time.September, 19, 12, 0, 0, 0, time.UTC)
	tenantID := "11111111-1111-4111-8111-111111111111"
	deviceNewest := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1"
	deviceTie := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2"
	deviceMalformed := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3"
	deviceOffPage := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4"

	for _, deviceID := range []string{deviceNewest, deviceTie, deviceMalformed, deviceOffPage} {
		if _, err := pool.Exec(ctx, `INSERT INTO devices (id, tenant_id) VALUES ($1::uuid, $2::uuid)`, deviceID, tenantID); err != nil {
			t.Fatalf("insert device %s: %v", deviceID, err)
		}
	}

	oldReceived := now.Add(-2 * time.Hour)
	newReceived := now.Add(-time.Hour)
	oldObserved := now.Add(-3 * time.Hour)
	newObserved := now.Add(-90 * time.Minute)
	insertPAT1867Payload(t, pool, tenantID, deviceNewest, oldReceived, map[string]any{
		"collected_at":      oldObserved.Format(time.RFC3339),
		"collection_status": map[string]any{"certificates": "complete"},
	})
	insertPAT1867Payload(t, pool, tenantID, deviceNewest, newReceived, map[string]any{
		"collected_at":      newObserved.Format(time.RFC3339),
		"collection_status": map[string]any{"certificates": "partial"},
	})

	tieReceived := now.Add(-45 * time.Minute)
	firstID := insertPAT1867Payload(t, pool, tenantID, deviceTie, tieReceived, map[string]any{
		"collected_at":      now.Add(-50 * time.Minute).Format(time.RFC3339),
		"collection_status": map[string]any{"certificates": "partial"},
	})
	secondID := insertPAT1867Payload(t, pool, tenantID, deviceTie, tieReceived, map[string]any{
		"collected_at":      now.Add(-40 * time.Minute).Format(time.RFC3339),
		"collection_status": map[string]any{"certificates": "complete"},
	})
	if secondID <= firstID {
		t.Fatalf("test setup ids = %d then %d, want increasing", firstID, secondID)
	}

	insertPAT1867Payload(t, pool, tenantID, deviceMalformed, oldReceived, map[string]any{
		"collected_at":      oldObserved.Format(time.RFC3339),
		"collection_status": map[string]any{"certificates": "complete"},
	})
	malformedObserved := now.Add(-20 * time.Minute)
	malformedReceived := now.Add(-10 * time.Minute)
	insertPAT1867Payload(t, pool, tenantID, deviceMalformed, malformedReceived, map[string]any{
		"collected_at":      malformedObserved.Format(time.RFC3339),
		"collection_status": map[string]any{"certificates": 42},
	})

	insertPAT1867Payload(t, pool, tenantID, deviceOffPage, now.Add(-5*time.Minute), map[string]any{
		"collected_at":      now.Add(-6 * time.Minute).Format(time.RFC3339),
		"collection_status": map[string]any{"certificates": "complete"},
	})

	page := []TenantDeviceRow{{ID: deviceNewest}, {ID: deviceTie}, {ID: deviceMalformed}}
	got, err := fetchPortalDeviceEvidence(ctx, pool, tenantID, page, now)
	if err != nil {
		t.Fatalf("fetch evidence: %v", err)
	}
	if len(got) != len(page) {
		t.Fatalf("evidence rows = %d, want page size %d", len(got), len(page))
	}
	if _, ok := got[deviceOffPage]; ok {
		t.Fatal("off-page device evidence was fetched")
	}

	newest := got[deviceNewest]
	if newest.ObservedAt == nil || !newest.ObservedAt.Equal(newObserved) || newest.ReceivedAt == nil || !newest.ReceivedAt.Equal(newReceived) ||
		sectionValue(newest.Sections.Certificates) != EvidenceSectionPartial || newest.Authority != EvidenceAuthorityPresenceOnly {
		t.Fatalf("newest evidence = %+v, want timestamps and status from same newest receipt", newest)
	}

	tie := got[deviceTie]
	if tie.ObservedAt == nil || !tie.ObservedAt.Equal(now.Add(-40*time.Minute)) ||
		sectionValue(tie.Sections.Certificates) != EvidenceSectionComplete || tie.Authority != EvidenceAuthoritySectionScoped {
		t.Fatalf("tie evidence = %+v, want higher raw_payload id", tie)
	}

	malformed := got[deviceMalformed]
	if malformed.ReceivedAt == nil || !malformed.ReceivedAt.Equal(malformedReceived) ||
		malformed.ObservedAt == nil || !malformed.ObservedAt.Equal(malformedObserved) ||
		len(malformed.Sections.statuses()) != 0 || malformed.Authority != EvidenceAuthorityUnknown {
		t.Fatalf("malformed newest evidence = %+v, want newest timestamps but no fallback authority", malformed)
	}
}
