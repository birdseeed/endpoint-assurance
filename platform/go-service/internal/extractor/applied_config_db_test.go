package extractor

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/appliedconfig"
)

// DB-backed round trip for PAT-1668: the extractor's insert path and
// appliedconfig.PostgresStore's read path, against a schema mirroring
// migrations/0127_applied_config_snapshots.sql. Gated behind
// TEST_DATABASE_URL — same convention as internal/intune's
// postgres_store_test.go — and pinned to an isolated schema that is dropped
// on cleanup, so no real data is touched.
//
// Both halves live in one test file because they share one schema
// definition: a column name typo would otherwise only be caught in
// production, which is precisely the failure mode the ticket's honesty rules
// are about.

const appliedConfigTestSchema = "pat1668_test"

func appliedConfigPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed applied-configuration test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = appliedConfigTestSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + appliedConfigTestSchema + ` CASCADE`,
		`CREATE SCHEMA ` + appliedConfigTestSchema,
		`CREATE TABLE ` + appliedConfigTestSchema + `.tenants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid()
		)`,
		`CREATE TABLE ` + appliedConfigTestSchema + `.devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + appliedConfigTestSchema + `.tenants(id) ON DELETE CASCADE
		)`,
		// Mirrors migrations/0127_applied_config_snapshots.sql.
		`CREATE TABLE ` + appliedConfigTestSchema + `.applied_config_snapshots (
			id                      BIGSERIAL   PRIMARY KEY,
			tenant_id               UUID        NOT NULL REFERENCES ` + appliedConfigTestSchema + `.tenants(id) ON DELETE CASCADE,
			device_id               UUID        NOT NULL REFERENCES ` + appliedConfigTestSchema + `.devices(id) ON DELETE CASCADE,
			raw_payload_id          BIGINT      NOT NULL,
			raw_payload_received_at TIMESTAMPTZ NOT NULL,
			observed_at             TIMESTAMPTZ NOT NULL,
			collection_status       TEXT        NOT NULL CHECK (collection_status IN ('ok', 'rate_limited', 'unavailable')),
			profiles_count          INTEGER     NOT NULL DEFAULT 0,
			profiles_truncated      BOOLEAN     NOT NULL DEFAULT false,
			mdm_server_url          TEXT,
			mdm_supervised          TEXT        NOT NULL DEFAULT 'Unknown' CHECK (mdm_supervised IN ('Yes', 'No', 'Unknown')),
			created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
			UNIQUE (device_id, raw_payload_id)
		)`,
		`CREATE TABLE ` + appliedConfigTestSchema + `.applied_config_profiles (
			id                 BIGSERIAL   PRIMARY KEY,
			snapshot_id        BIGINT      NOT NULL REFERENCES ` + appliedConfigTestSchema + `.applied_config_snapshots(id) ON DELETE CASCADE,
			ordinal            INTEGER     NOT NULL,
			profile_identifier TEXT        NOT NULL DEFAULT '',
			display_name       TEXT        NOT NULL DEFAULT '',
			organization       TEXT        NOT NULL DEFAULT '',
			payload            TEXT,
			payload_capped     BOOLEAN     NOT NULL DEFAULT false,
			decode_error       BOOLEAN     NOT NULL DEFAULT false,
			created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("schema setup failed on %q: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+appliedConfigTestSchema+` CASCADE`)
	})
	return pool
}

func seedTenantAndDevices(t *testing.T, pool *pgxpool.Pool, n int) (string, []string) {
	t.Helper()
	ctx := context.Background()
	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	devices := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO devices (tenant_id) VALUES ($1::uuid) RETURNING id::text`, tenantID).Scan(&id); err != nil {
			t.Fatalf("insert device: %v", err)
		}
		devices = append(devices, id)
	}
	return tenantID, devices
}

// ingest runs the real extractor insert path inside a transaction, exactly
// as processRow does.
func ingest(t *testing.T, pool *pgxpool.Pool, tenantID, deviceID string, rawID int64, observedAt time.Time, wire string) int {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	part := parseAppliedConfiguration(json.RawMessage(wire), nil)
	n, err := insertAppliedConfigSnapshot(ctx, tx, tenantID, deviceID, rawID, observedAt.Add(time.Minute), observedAt, part, nil)
	if err != nil {
		t.Fatalf("insertAppliedConfigSnapshot: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return n
}

// wire assembles one applied_configuration object. profiles is spliced in as
// raw JSON so profile payload strings stay exactly as written.
func wire(status string, truncated bool, count int, mdmURL string, profiles string) string {
	doc := map[string]any{
		"profiles":           json.RawMessage(profiles),
		"profiles_count":     count,
		"profiles_truncated": truncated,
		"collection_status":  status,
		"mdm_supervised":     "Yes",
		"mdm_server_url":     nil,
	}
	if mdmURL != "" {
		doc["mdm_server_url"] = mdmURL
	}
	b, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	return string(b)
}

const fwProfilesJSON = `[{"identifier":"org.example.firewall","display_name":"Firewall","organization":"Example Ltd","payload":"[{\"EnableFirewall\":true}]","payload_capped":false}]`
const fwProfilesChangedJSON = `[{"identifier":"org.example.firewall","display_name":"Firewall","organization":"Example Ltd","payload":"[{\"EnableFirewall\":false}]","payload_capped":false}]`

func TestAppliedConfigDB_IngestThenDiffRoundTrips(t *testing.T) {
	pool := appliedConfigPool(t)
	tenantID, devices := seedTenantAndDevices(t, pool, 1)
	device := devices[0]

	base := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)
	if n := ingest(t, pool, tenantID, device, 1, base, wire("ok", false, 1, "https://jamf.example.org/mdm", fwProfilesJSON)); n != 1 {
		t.Fatalf("first ingest wrote %d profile rows, want 1", n)
	}
	if n := ingest(t, pool, tenantID, device, 2, base.Add(24*time.Hour), wire("ok", false, 1, "https://jamf.example.org/mdm", fwProfilesChangedJSON)); n != 1 {
		t.Fatalf("second ingest wrote %d profile rows, want 1", n)
	}

	store := appliedconfig.NewPostgresStore(pool)
	report, err := appliedconfig.TenantEstateChanges(context.Background(), store, tenantID, time.Time{})
	if err != nil {
		t.Fatalf("TenantEstateChanges: %v", err)
	}
	if report.DevicesCompared != 1 {
		t.Fatalf("DevicesCompared = %d, want 1", report.DevicesCompared)
	}
	if len(report.Groups) != 1 {
		t.Fatalf("groups = %+v, want one payload-changed finding", report.Groups)
	}
	g := report.Groups[0]
	if g.Kind != appliedconfig.ProfilePayloadChanged || g.ProfileIdentifier != "org.example.firewall" {
		t.Errorf("group = (%s, %s)", g.ProfileIdentifier, g.Kind)
	}
	if g.AffectedDeviceCount != 1 || g.AffectedDevices[0].DeviceID != device {
		t.Errorf("affected devices = %+v, want just %s", g.AffectedDevices, device)
	}
	if g.ObservationKind != appliedconfig.ObservationKind {
		t.Errorf("group is not labelled as applied configuration: %q", g.ObservationKind)
	}
	if len(g.MDMServerURLs) != 1 || g.MDMServerURLs[0] != "https://jamf.example.org/mdm" {
		t.Errorf("MDMServerURLs = %v, want the enrolled server", g.MDMServerURLs)
	}
	// The window is two observation times, never a single event time.
	if !g.EarliestObservedStart.Equal(base) || !g.LatestObservedEnd.Equal(base.Add(24*time.Hour)) {
		t.Errorf("window = (%s, %s), want (%s, %s)",
			g.EarliestObservedStart, g.LatestObservedEnd, base, base.Add(24*time.Hour))
	}
}

// TestAppliedConfigDB_ReExtractionIsIdempotent: the table is append-only, so
// re-extracting an already-extracted raw payload must add nothing rather
// than duplicate the observation.
func TestAppliedConfigDB_ReExtractionIsIdempotent(t *testing.T) {
	pool := appliedConfigPool(t)
	tenantID, devices := seedTenantAndDevices(t, pool, 1)
	device := devices[0]
	base := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)

	ingest(t, pool, tenantID, device, 7, base, wire("ok", false, 1, "", fwProfilesJSON))
	if n := ingest(t, pool, tenantID, device, 7, base, wire("ok", false, 1, "", fwProfilesJSON)); n != 0 {
		t.Errorf("re-extraction wrote %d profile rows, want 0", n)
	}

	ctx := context.Background()
	var snapshots, profiles int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM applied_config_snapshots`).Scan(&snapshots); err != nil {
		t.Fatalf("count snapshots: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM applied_config_profiles`).Scan(&profiles); err != nil {
		t.Fatalf("count profiles: %v", err)
	}
	if snapshots != 1 || profiles != 1 {
		t.Errorf("after re-extraction: %d snapshots / %d profile rows, want 1 / 1", snapshots, profiles)
	}
}

// TestAppliedConfigDB_FailedCollectionNeverBecomesABaseline is the storage
// half of the rule Diff enforces in memory: a rate-limited run is stored and
// visible, but the query that feeds the diff must skip straight past it to
// the last genuinely ok observation.
func TestAppliedConfigDB_FailedCollectionNeverBecomesABaseline(t *testing.T) {
	pool := appliedConfigPool(t)
	tenantID, devices := seedTenantAndDevices(t, pool, 1)
	device := devices[0]
	base := time.Date(2026, 9, 8, 9, 0, 0, 0, time.UTC)

	ingest(t, pool, tenantID, device, 1, base, wire("ok", false, 1, "", fwProfilesJSON))
	// Two failed runs in between. The agent serves its cache, so the
	// profile list looks healthy; only collection_status says otherwise.
	ingest(t, pool, tenantID, device, 2, base.Add(24*time.Hour), wire("rate_limited", false, 1, "", fwProfilesJSON))
	ingest(t, pool, tenantID, device, 3, base.Add(48*time.Hour), wire("unavailable", false, 0, "", `[]`))
	ingest(t, pool, tenantID, device, 4, base.Add(72*time.Hour), wire("ok", false, 1, "", fwProfilesChangedJSON))

	ctx := context.Background()
	var stored int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM applied_config_snapshots`).Scan(&stored); err != nil {
		t.Fatalf("count: %v", err)
	}
	if stored != 4 {
		t.Errorf("stored %d snapshots, want all 4 — a failed run is evidence and must be kept", stored)
	}

	store := appliedconfig.NewPostgresStore(pool)
	pairs, err := store.ComparablePairs(ctx, tenantID, time.Time{})
	if err != nil {
		t.Fatalf("ComparablePairs: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("got %d pairs, want 1", len(pairs))
	}
	if !pairs[0].Prior.ObservedAt.Equal(base) {
		t.Errorf("baseline = %s, want the last ok observation %s — a failed run displaced it",
			pairs[0].Prior.ObservedAt, base)
	}
	if !pairs[0].Current.ObservedAt.Equal(base.Add(72 * time.Hour)) {
		t.Errorf("current = %s, want %s", pairs[0].Current.ObservedAt, base.Add(72*time.Hour))
	}

	// And the resulting finding is the single real change, not a mass
	// removal invented by the empty 'unavailable' run.
	report, err := appliedconfig.TenantEstateChanges(ctx, store, tenantID, time.Time{})
	if err != nil {
		t.Fatalf("TenantEstateChanges: %v", err)
	}
	if len(report.Groups) != 1 || report.Groups[0].Kind != appliedconfig.ProfilePayloadChanged {
		t.Errorf("groups = %+v, want exactly one payload change", report.Groups)
	}
}

// TestAppliedConfigDB_DeviceThatStoppedReportingIsNotCompared: the `since`
// cutoff is what keeps a silent Mac from producing entries.
func TestAppliedConfigDB_DeviceThatStoppedReportingIsNotCompared(t *testing.T) {
	pool := appliedConfigPool(t)
	tenantID, devices := seedTenantAndDevices(t, pool, 2)
	live, silent := devices[0], devices[1]
	base := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)

	ingest(t, pool, tenantID, live, 1, base, wire("ok", false, 1, "", fwProfilesJSON))
	ingest(t, pool, tenantID, live, 2, base.Add(24*time.Hour), wire("ok", false, 1, "", fwProfilesChangedJSON))

	// The silent Mac reported twice, a month ago, and has said nothing
	// since. It must contribute nothing at all.
	ingest(t, pool, tenantID, silent, 3, base.Add(-30*24*time.Hour), wire("ok", false, 1, "", fwProfilesJSON))
	ingest(t, pool, tenantID, silent, 4, base.Add(-29*24*time.Hour), wire("ok", false, 1, "", fwProfilesJSON))

	ctx := context.Background()
	store := appliedconfig.NewPostgresStore(pool)
	pairs, err := store.ComparablePairs(ctx, tenantID, base)
	if err != nil {
		t.Fatalf("ComparablePairs: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("got %d pairs, want 1: %+v", len(pairs), pairs)
	}
	if pairs[0].Current.DeviceID != live {
		t.Errorf("compared device %s, want the live one %s", pairs[0].Current.DeviceID, live)
	}

	report, err := appliedconfig.TenantEstateChanges(ctx, store, tenantID, base)
	if err != nil {
		t.Fatalf("TenantEstateChanges: %v", err)
	}
	for _, g := range report.Groups {
		for _, d := range g.AffectedDevices {
			if d.DeviceID == silent {
				t.Errorf("the silent device produced a change entry in group %s/%s", g.ProfileIdentifier, g.Kind)
			}
		}
	}
}

// TestAppliedConfigDB_CappedPayloadSurvivesStorageVerbatim: a head-capped
// payload is not valid JSON, which is exactly why the column is TEXT. It
// must come back byte for byte.
func TestAppliedConfigDB_CappedPayloadSurvivesStorageVerbatim(t *testing.T) {
	pool := appliedConfigPool(t)
	tenantID, devices := seedTenantAndDevices(t, pool, 1)
	device := devices[0]
	base := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)

	const fragment = `[{"PayloadType": "com.apple.secu`
	capped := `[{"identifier":"org.example.big","display_name":"Big","organization":"","payload":` +
		mustJSONString(fragment) + `,"payload_capped":true}]`

	ingest(t, pool, tenantID, device, 1, base, wire("ok", false, 1, "", capped))
	ingest(t, pool, tenantID, device, 2, base.Add(24*time.Hour), wire("ok", false, 1, "", capped))

	ctx := context.Background()
	store := appliedconfig.NewPostgresStore(pool)
	pairs, err := store.ComparablePairs(ctx, tenantID, time.Time{})
	if err != nil {
		t.Fatalf("ComparablePairs: %v", err)
	}
	if len(pairs) != 1 || len(pairs[0].Current.Profiles) != 1 {
		t.Fatalf("pairs = %+v", pairs)
	}
	got := pairs[0].Current.Profiles[0]
	if got.Payload != fragment {
		t.Errorf("payload = %q, want the verbatim fragment %q", got.Payload, fragment)
	}
	if !got.PayloadCapped {
		t.Error("payload_capped did not survive the round trip")
	}

	set, err := appliedconfig.Diff(pairs[0].Prior, pairs[0].Current)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(set.Changes) != 0 {
		t.Errorf("identical capped payloads produced %d changes", len(set.Changes))
	}
	if len(set.Notes.CapLimitedIdentifiers) != 1 {
		t.Errorf("CapLimitedIdentifiers = %v, want the cap caveat recorded", set.Notes.CapLimitedIdentifiers)
	}
}

// TestAppliedConfigDB_UnknownCollectionStatusStoredAsUnavailable: an agent
// sending a status this server does not know must not be recorded as a
// successful collection.
func TestAppliedConfigDB_UnknownCollectionStatusStoredAsUnavailable(t *testing.T) {
	pool := appliedConfigPool(t)
	tenantID, devices := seedTenantAndDevices(t, pool, 1)
	device := devices[0]
	base := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)

	ingest(t, pool, tenantID, device, 1, base, wire("some_future_status", false, 1, "", fwProfilesJSON))

	var status string
	if err := pool.QueryRow(context.Background(),
		`SELECT collection_status FROM applied_config_snapshots WHERE device_id = $1::uuid`, device).Scan(&status); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != string(appliedconfig.CollectionUnavailable) {
		t.Errorf("collection_status = %q, want %q", status, appliedconfig.CollectionUnavailable)
	}
}

// TestAppliedConfigDB_ReportedCountAboveStoredRowsForcesTruncated: if the
// agent says it saw more profiles than it sent, the list is bounded whatever
// the truncated flag claimed — believing the flag over the arithmetic is how
// a short list turns into a false mass-removal signal.
func TestAppliedConfigDB_ReportedCountAboveStoredRowsForcesTruncated(t *testing.T) {
	pool := appliedConfigPool(t)
	tenantID, devices := seedTenantAndDevices(t, pool, 1)
	device := devices[0]
	base := time.Date(2026, 9, 11, 9, 0, 0, 0, time.UTC)

	// One profile row, but the agent claims 900 and says truncated: false.
	ingest(t, pool, tenantID, device, 1, base, wire("ok", false, 900, "", fwProfilesJSON))

	var truncated bool
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT profiles_truncated, profiles_count FROM applied_config_snapshots WHERE device_id = $1::uuid`,
		device).Scan(&truncated, &count); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !truncated {
		t.Error("profiles_truncated = false although the reported count exceeds the stored rows")
	}
	if count != 900 {
		t.Errorf("profiles_count = %d, want the agent's own 900 preserved", count)
	}
}

func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
