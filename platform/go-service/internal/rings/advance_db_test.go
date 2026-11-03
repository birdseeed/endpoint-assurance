package rings_test

// PAT-995 regression test: ObserveNewVersions' query used a DISTINCT ON list
// that did not match its ORDER BY (Postgres 42P10) — a static SQL defect, so
// the query has never returned a row since it was introduced (PAT-117,
//). It failed on every extractor cycle, was logged at ERROR, and
// nothing alerted on it.
//
// Every other test in this package (assign_test.go) exercises pure, DB-free
// functions — ComputeRing, RingToAgentValue, EffectiveAgentRing. Nothing in
// the package's test suite ever executed advance.go's SQL, mocked or real,
// which is exactly why `go test ./...` stayed green while the query was
// syntactically broken against every real Postgres. This test is the first
// one in the package that actually runs the query.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database (same
// convention as internal/auth/bearer_db_test.go). The pool's search_path is
// pinned to an isolated schema so the unqualified table names in advance.go
// resolve there and no real data is touched; the schema is dropped on
// cleanup.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/rings"
)

const testSchema = "pat995_test"

func dbPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed rings test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	// Every connection in the pool resolves unqualified names in the test schema.
	cfg.ConnConfig.RuntimeParams["search_path"] = testSchema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + testSchema + ` CASCADE`,
		`CREATE SCHEMA ` + testSchema,
		// Minimal shapes of the tables ObserveNewVersions/insertNewVersion
		// touch — see migrations/0011_provenance.sql and
		// migrations/0042_patching_rings.sql for the real (superset) schema.
		`CREATE TABLE ` + testSchema + `.tenants (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid()
		)`,
		`CREATE TABLE ` + testSchema + `.tenant_ring_config (
			tenant_id UUID PRIMARY KEY REFERENCES ` + testSchema + `.tenants(id),
			enabled boolean NOT NULL DEFAULT false,
			ring_count smallint NOT NULL DEFAULT 3,
			percentages smallint[] NOT NULL DEFAULT '{10,30,60}',
			soak_gap_hours integer NOT NULL DEFAULT 24,
			failure_threshold_pct numeric(5,2) NOT NULL DEFAULT 5.00,
			min_failures_to_pause integer NOT NULL DEFAULT 2,
			min_estate_size integer NOT NULL DEFAULT 10,
			config_version integer NOT NULL DEFAULT 1
		)`,
		// os is NULLABLE here on purpose, matching production
		// (migrations/0039_nullable_os.sql dropped the NOT NULL because a
		// flat-format enrolment carries no OS field; it is populated on the
		// first inventory upload). queryFailureRate's device-side platform
		// filter has to tolerate that NULL, so the fixture has to be able to
		// produce it.
		`CREATE TABLE ` + testSchema + `.devices (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + testSchema + `.tenants(id),
			hw_uuid UUID,
			os TEXT,
			ring_override smallint,
			ring_computed smallint
		)`,
		`CREATE TABLE ` + testSchema + `.agent_config (
			tenant_id UUID PRIMARY KEY REFERENCES ` + testSchema + `.tenants(id),
			body JSONB NOT NULL DEFAULT '{}'::jsonb,
			config_version integer NOT NULL DEFAULT 1,
			issued_at TIMESTAMPTZ
		)`,
		`CREATE TABLE ` + testSchema + `.provenance_records (
			id BIGSERIAL PRIMARY KEY,
			tenant_id UUID NOT NULL REFERENCES ` + testSchema + `.tenants(id),
			received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			body JSONB NOT NULL
		)`,
		`CREATE TABLE ` + testSchema + `.ring_version_approvals (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + testSchema + `.tenants(id),
			platform text NOT NULL,
			label text NOT NULL,
			version text NOT NULL,
			approved_ring smallint NOT NULL DEFAULT 0,
			state text NOT NULL DEFAULT 'rolling',
			last_advanced_at timestamptz NOT NULL DEFAULT now(),
			paused_reason text,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now(),
			UNIQUE (tenant_id, platform, label, version)
		)`,
		`CREATE TABLE ` + testSchema + `.ring_config_changes (
			id bigserial PRIMARY KEY,
			tenant_id UUID NOT NULL,
			change_type text NOT NULL,
			label text,
			version text,
			device_id UUID,
			old_value jsonb,
			new_value jsonb,
			changed_by text NOT NULL DEFAULT 'system',
			changed_at timestamptz NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup exec %q: %v", s, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+testSchema+` CASCADE`)
	})
	return pool
}

func insertProvenanceBody(t *testing.T, pool *pgxpool.Pool, tenantID string, receivedAt time.Time, body map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO provenance_records (tenant_id, received_at, body) VALUES ($1::uuid, $2, $3::jsonb)`,
		tenantID, receivedAt, raw,
	); err != nil {
		t.Fatalf("insert provenance: %v", err)
	}
}

// insertProvenance writes a body in the real macOS emitter shape:
// endpoint/patched-update.sh's emit_provenance() (updater repo) nests
// label/version under a top-level "app" object and has never emitted a
// top-level "label"/"version" key at any point in its history (PAT-997
// investigation, 2026-07-28). No top-level "platform" key is ever present for
// macOS records; the query's COALESCE(...,'macos') default is what should
// classify them.
//
// This models a SUCCESSFUL install of `version`: version_after and
// available_version both equal it, since on success both fields converge on
// the version that actually landed (see insertProvenanceMacOSAttempt's doc
// comment for the honest failure-path bookkeeping, used by tests that need
// to distinguish "attempted" from "actually installed"), and top-level
// "outcome" is "installed" — ObserveNewVersions (advance.go) requires a
// success-vocabulary outcome/state as of the fourth review round (a failed
// attempt, even with available_version populated, must not create or
// supersede a rollout — see ObserveNewVersions' doc comment), so a helper
// modelling success must say so explicitly, not leave the field absent.
func insertProvenance(t *testing.T, pool *pgxpool.Pool, tenantID string, receivedAt time.Time, platform, label, version string) {
	t.Helper()
	body := map[string]any{
		"record_type": "third_party_update",
		"outcome":     "installed",
		"app": map[string]any{
			"label":             label,
			"version_after":     version,
			"available_version": version,
		},
	}
	if platform != "" {
		body["platform"] = platform
	}
	insertProvenanceBody(t, pool, tenantID, receivedAt, body)
}

// insertProvenanceMacOSAttempt writes a body in the full macOS emitter shape
// that queryFailureRate (advance.go) needs: a device.hw_uuid so it can join
// to the eligible_devices CTE, a top-level "outcome" carrying the
// success/failure signal, and — critically, per the second-pass PAT-997
// review — HONEST version bookkeeping instead of assuming success:
//
//   - app.available_version always carries the ATTEMPTED version (macOS
//     scrapes this from the Installomator log BEFORE the verification step
//     that can fail, endpoint/patched-update.sh's PATCHED_AVAIL_VER), on
//     both success and failure.
//   - app.version_after carries the version actually on disk after the
//     attempt: equal to priorVersion (unchanged) on failure, equal to
//     attemptedVersion only when succeeded is true.
//
// An earlier version of this fixture always set version_after to the target
// version regardless of outcome — which matched the (buggy) query at the
// time but contradicted the emitter semantics documented in this very file
// (see insertProvenance's doc comment, written before this fixture, which
// already stated the correct behaviour). That is exactly the shape of bug
// this whole file exists to prevent: a fixture that agrees with the code
// instead of with reality.
func insertProvenanceMacOSAttempt(t *testing.T, pool *pgxpool.Pool, tenantID string, receivedAt time.Time, hwUUID, label, priorVersion, attemptedVersion, outcome string, succeeded bool) {
	t.Helper()
	versionAfter := priorVersion
	if succeeded {
		versionAfter = attemptedVersion
	}
	body := map[string]any{
		"record_type": "third_party_update",
		"device":      map[string]any{"hw_uuid": hwUUID},
		"outcome":     outcome,
		"app": map[string]any{
			"label":             label,
			"version_before":    priorVersion,
			"version_after":     versionAfter,
			"available_version": attemptedVersion,
		},
	}
	insertProvenanceBody(t, pool, tenantID, receivedAt, body)
}

// insertDevice inserts a devices row with a fixed ring_computed, matching the
// columns queryFailureRate's eligible_devices CTE reads (hw_uuid,
// ring_override, ring_computed — see migrations/0001_initial.sql +
// migrations/0042_patching_rings.sql).
// It leaves os NULL, modelling a device enrolled but not yet inventoried —
// deliberately the pessimistic case for queryFailureRate's device-side
// platform filter, so every pre-existing test in this file keeps exercising
// the "os is unknown, don't narrow it out" path. Tests that need a known OS
// use insertDeviceOS.
func insertDevice(t *testing.T, pool *pgxpool.Pool, tenantID, hwUUID string, ringComputed int16) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO devices (tenant_id, hw_uuid, ring_computed) VALUES ($1::uuid, $2::uuid, $3) RETURNING id::text`,
		tenantID, hwUUID, ringComputed,
	).Scan(&id); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return id
}

// insertDeviceOS is insertDevice with an explicit devices.os value ("macOS" or
// "Windows", the real convention per migrations/0001_initial.sql). Needed for
// PAT-1002's device-side platform scoping: filtering only the provenance side
// left the join open to a body that claims one platform while naming another
// platform's device.
func insertDeviceOS(t *testing.T, pool *pgxpool.Pool, tenantID, hwUUID string, ringComputed int16, os string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO devices (tenant_id, hw_uuid, ring_computed, os) VALUES ($1::uuid, $2::uuid, $3, $4) RETURNING id::text`,
		tenantID, hwUUID, ringComputed, os,
	).Scan(&id); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	return id
}

// setupTenantRingConfig inserts a tenant_ring_config row with the given
// gating knobs; other columns take the test-schema defaults.
func setupTenantRingConfig(t *testing.T, pool *pgxpool.Pool, tenantID string, ringCount int16, soakGapHours int, failureThresholdPct float64, minFailuresToPause int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO tenant_ring_config
			(tenant_id, enabled, ring_count, soak_gap_hours, failure_threshold_pct, min_failures_to_pause)
		VALUES ($1::uuid, true, $2, $3, $4, $5)
	`, tenantID, ringCount, soakGapHours, failureThresholdPct, minFailuresToPause); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}
}

// insertApprovalRow inserts a ring_version_approvals row directly, bypassing
// insertNewVersion, so tests can control approved_ring/state/last_advanced_at
// precisely.
func insertApprovalRow(t *testing.T, pool *pgxpool.Pool, tenantID, platform, label, version string, approvedRing int16, state string, lastAdvancedAt time.Time) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO ring_version_approvals (tenant_id, platform, label, version, approved_ring, state, last_advanced_at)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)
		RETURNING id::text
	`, tenantID, platform, label, version, approvedRing, state, lastAdvancedAt).Scan(&id); err != nil {
		t.Fatalf("insert approval row: %v", err)
	}
	return id
}

// insertAgentConfig inserts an initial agent_config row for a tenant, the
// shape rebuildRingPromotions expects to find and UPDATE: an empty JSONB
// body it can jsonb_set '{ring_promotions}' into, and a starting
// config_version to bump from. rebuildRingPromotions only ever UPDATEs this
// table (no upsert), so tests exercising it must seed the row themselves,
// same as CreateTenantHandler/the migration 0015 backfill would in
// production.
func insertAgentConfig(t *testing.T, pool *pgxpool.Pool, tenantID string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO agent_config (tenant_id, body, config_version, issued_at) VALUES ($1::uuid, '{}'::jsonb, 1, now())`,
		tenantID,
	); err != nil {
		t.Fatalf("insert agent_config: %v", err)
	}
}

// agentConfigSnapshot reads back one tenant's agent_config row for
// assertions: config_version and issued_at (the two columns
// rebuildRingPromotions' fix must leave untouched on a no-op tick) plus the
// stored ring_promotions content itself.
func agentConfigSnapshot(t *testing.T, pool *pgxpool.Pool, tenantID string) (configVersion int, issuedAt time.Time, ringPromotions json.RawMessage) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT config_version, issued_at, body->'ring_promotions' FROM agent_config WHERE tenant_id = $1::uuid`,
		tenantID,
	).Scan(&configVersion, &issuedAt, &ringPromotions); err != nil {
		t.Fatalf("read back agent_config: %v", err)
	}
	return configVersion, issuedAt, ringPromotions
}

// insertProvenanceWindows writes a body in the real Windows emitter shape:
// windows/src/Service/ProvenancePoster.cs's BuildPayload() (updater repo)
// keeps label/installed_version top-level and has never nested them, and
// always sets an explicit "platform":"windows". installed_version stays at
// the pre-attempt version on a failed install
// (InventoryCollector.ProcessEntryAsync, updater repo) and only advances on
// success — the same "version actually on the device now" semantics as
// macOS's version_after, under a different key. This models a SUCCESSFUL
// install, so available_version (the ATTEMPTED version, which
// ObserveNewVersions/queryFailureRate/queryWaveBars all read) is set to the
// same value as installed_version, matching real Windows behaviour on
// success — and top-level "state" is "uptodate", the success value
// ObserveNewVersions requires as of the fourth review round (see its doc
// comment: only a success-vocabulary outcome/state counts as "observed").
func insertProvenanceWindows(t *testing.T, pool *pgxpool.Pool, tenantID string, receivedAt time.Time, label, installedVersion string) {
	t.Helper()
	body := map[string]any{
		"platform":          "windows",
		"label":             label,
		"installed_version": installedVersion,
		"available_version": installedVersion,
		"state":             "uptodate",
	}
	insertProvenanceBody(t, pool, tenantID, receivedAt, body)
}

// insertProvenanceWindowsAttempt is insertProvenanceWindows plus the fields
// queryFailureRate's corrected version-match needs: available_version (the
// ATTEMPTED version, set identically on success and failure by
// InventoryCollector.ProcessEntryAsync, updater repo) and state. Still no
// device.hw_uuid — Windows provenance carries no per-device identifier at
// all today (ProvenancePoster.BuildPayload never serializes one; see
// queryFailureRate's doc comment) — used deliberately so a test using this
// helper isolates "excluded because unattributable to a device" from
// "excluded because it doesn't carry an available_version", rather than
// conflating the two gaps.
func insertProvenanceWindowsAttempt(t *testing.T, pool *pgxpool.Pool, tenantID string, receivedAt time.Time, label, priorVersion, attemptedVersion, state string, succeeded bool) {
	t.Helper()
	installedVersion := priorVersion
	if succeeded {
		installedVersion = attemptedVersion
	}
	body := map[string]any{
		"platform":          "windows",
		"label":             label,
		"installed_version": installedVersion,
		"available_version": attemptedVersion,
		"state":             state,
	}
	insertProvenanceBody(t, pool, tenantID, receivedAt, body)
}

// TestObserveNewVersions_QueryIsValid is the regression test for PAT-995. On
// the broken query this fails immediately with:
//
//	ERROR: SELECT DISTINCT ON expressions must match initial ORDER BY
//	expressions (SQLSTATE 42P10)
//
// On the fix it must also pick the *newest* row (by received_at) within each
// normalized (tenant, platform, label) group — not an arbitrary one — and
// must not merge a NULL-platform provenance row with an explicit 'windows'
// row for the same label.
func TestObserveNewVersions_QueryIsValid(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants DEFAULT VALUES RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_ring_config (tenant_id, enabled) VALUES ($1::uuid, true)`, tenantID,
	); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}
	insertAgentConfig(t, pool, tenantID)

	now := time.Now().UTC()

	// Two provenance rows for the same (tenant, label) with platform left
	// unset (NULL in the JSONB) — these must be grouped together under the
	// normalized 'macos' default, and the query must pick the NEWER one
	// (1.2.0), proving it orders by received_at DESC within the group
	// rather than picking an arbitrary row.
	insertProvenance(t, pool, tenantID, now.Add(-2*time.Hour), "", "adobeacrobat", "1.1.0")
	insertProvenance(t, pool, tenantID, now, "", "adobeacrobat", "1.2.0")

	// A distinct windows group for the same label, in the real (flat) Windows
	// shape — must not merge with the macos group above, and must not be
	// shadowed by it.
	insertProvenanceWindows(t, pool, tenantID, now, "adobeacrobat", "9.9.9")

	rings.ObserveNewVersions(ctx, pool)

	rows, err := pool.Query(ctx,
		`SELECT platform, version FROM ring_version_approvals WHERE tenant_id = $1::uuid AND label = 'adobeacrobat'`,
		tenantID,
	)
	if err != nil {
		t.Fatalf("query ring_version_approvals: %v", err)
	}
	defer rows.Close()

	got := map[string]string{}
	for rows.Next() {
		var platform, version string
		if err := rows.Scan(&platform, &version); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[platform] = version
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}

	want := map[string]string{"macos": "1.2.0", "windows": "9.9.9"}
	if len(got) != len(want) {
		t.Fatalf("ring_version_approvals rows = %+v, want %+v", got, want)
	}
	for platform, wantVersion := range want {
		if got[platform] != wantVersion {
			t.Errorf("platform %s: got version %q, want %q", platform, got[platform], wantVersion)
		}
	}
}

// TestObserveNewVersions_MixedPayloadShapes is the regression test for
// PAT-997. Before this fix, ObserveNewVersions filtered on the top-level
// JSON keys body->>'label' and body->>'version'. Production provenance
// bodies never have that shape: the real macOS emitter
// (endpoint/patched-update.sh, updater repo) nests label/version_after under
// a top-level "app" object, and the real Windows emitter
// (windows/src/Service/ProvenancePoster.cs, updater repo) uses top-level
// "label"/"installed_version" — never a top-level "version" key at all. So
// the old query's WHERE clause matched nothing, silently, for 34 days: valid
// SQL, zero rows, indistinguishable from "no new versions."
//
// PAT-995's test above proved the query *parses*; it does not prove the
// query finds anything, because its fixtures used a synthetic top-level
// "label"/"version" shape that happens to satisfy the old (buggy) WHERE
// clause but does not match what either real agent ever sends. This test
// uses the two real payload shapes and asserts the query's OUTPUT is
// non-empty and correct — it must fail on the pre-PAT-997 query (zero rows)
// and must fail if a future change reverts to reading only top-level keys.
func TestObserveNewVersions_MixedPayloadShapes(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants DEFAULT VALUES RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_ring_config (tenant_id, enabled) VALUES ($1::uuid, true)`, tenantID,
	); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}
	insertAgentConfig(t, pool, tenantID)

	now := time.Now().UTC()

	// Real macOS shape: label/version_after nested under "app", no top-level
	// "label" or "version" key anywhere in the body. A query that only reads
	// body->>'label' / body->>'version' silently drops this row entirely.
	insertProvenance(t, pool, tenantID, now, "", "googlechrome", "150.0.7871.115")

	// Real Windows shape: top-level "label" and "installed_version" — note
	// there is still no top-level "version" key, so a naive fix that just
	// moved to reading body->>'version' unconditionally would also miss this.
	insertProvenanceWindows(t, pool, tenantID, now, "slack", "4.50.143")

	// A macOS row with NO version information anywhere in the body — e.g. a
	// scan-mode/policy-skip pass that never ran the engine at all
	// (endpoint/patched-update.sh sets available_ver="" unconditionally in
	// that branch). This must NOT produce an approval row; guards the
	// IS NOT NULL filter.
	insertProvenanceBody(t, pool, tenantID, now, map[string]any{
		"record_type": "third_party_update",
		"app": map[string]any{
			"label":          "notion",
			"version_before": "4.0.0",
			"version_after":  "4.0.0",
			// available_version intentionally omitted — no attempt was made.
		},
	})

	// A macOS row representing a FAILED install attempt at a NEW version:
	// version_after stays at the OLD "3.9.0" (the install never took — see
	// insertProvenanceMacOSAttempt's doc comment), available_version
	// correctly carries the ATTEMPTED "4.1.0" — but outcome is
	// "verification_failed", not a success value. PAT-997's third review
	// round fixed reading the wrong field (version_after) here; the fourth
	// review round found that wasn't enough: available_version alone doesn't
	// prove the version works, so a failed attempt — even at a genuinely
	// newer, real version — must still produce NO approval row and supersede
	// nothing. Only a success-vocabulary outcome/state counts as "observed"
	// (see ObserveNewVersions' doc comment). See
	// TestObserveNewVersions_FailedAttemptAtDifferentVersion_DoesNotSupersedeActiveRollout
	// for the sharper form: a failed attempt at a NEWER version must not
	// supersede an active rollout for an OLDER one.
	insertProvenanceBody(t, pool, tenantID, now, map[string]any{
		"record_type": "third_party_update",
		"outcome":     "verification_failed",
		"app": map[string]any{
			"label":             "zoom",
			"version_before":    "3.9.0",
			"version_after":     "3.9.0",
			"available_version": "4.1.0",
		},
	})

	rings.ObserveNewVersions(ctx, pool)

	rows, err := pool.Query(ctx,
		`SELECT platform, label, version FROM ring_version_approvals WHERE tenant_id = $1::uuid`,
		tenantID,
	)
	if err != nil {
		t.Fatalf("query ring_version_approvals: %v", err)
	}
	defer rows.Close()

	type key struct{ platform, label string }
	got := map[key]string{}
	for rows.Next() {
		var platform, label, version string
		if err := rows.Scan(&platform, &label, &version); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[key{platform, label}] = version
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}

	// The crucial assertion: this must not be empty. A query that parses but
	// matches nothing (the actual 34-day production outage) would leave
	// ring_version_approvals empty and this Fatalf would fire.
	if len(got) == 0 {
		t.Fatalf("ring_version_approvals is empty — ObserveNewVersions matched zero provenance rows " +
			"against representative macOS/Windows fixture data (this is the PAT-997 outage reproduced)")
	}

	want := map[key]string{
		{"macos", "googlechrome"}: "150.0.7871.115",
		{"windows", "slack"}:      "4.50.143",
	}
	if len(got) != len(want) {
		t.Fatalf("ring_version_approvals rows = %+v, want %+v", got, want)
	}
	for k, wantVersion := range want {
		if got[k] != wantVersion {
			t.Errorf("platform/label %+v: got version %q, want %q", k, got[k], wantVersion)
		}
	}
	if v, ok := got[key{"macos", "notion"}]; ok {
		t.Errorf("notion (no version info anywhere) produced an approval row with version %q; want no row", v)
	}
	if v, ok := got[key{"macos", "zoom"}]; ok {
		t.Errorf("zoom (failed install attempt, no success outcome) produced an approval row with version %q; "+
			"want no row — a failed attempt must not be treated as an observed version, regardless of "+
			"whether available_version is populated", v)
	}
}

func TestObserveNewVersions_DoesNotAuditSupersedeWithoutOlderActiveRow(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_ring_config (tenant_id, enabled) VALUES ($1::uuid, true)`, tenantID,
	); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO agent_config (tenant_id) VALUES ($1::uuid)`, tenantID,
	); err != nil {
		t.Fatalf("insert agent_config: %v", err)
	}
	insertProvenance(t, pool, tenantID, time.Now().UTC(), "macos", "zoom", "7.1.0")

	rings.ObserveNewVersions(ctx, pool)

	var auditCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM ring_config_changes
		WHERE tenant_id = $1::uuid AND change_type = 'rollout_superseded'
	`, tenantID).Scan(&auditCount); err != nil {
		t.Fatalf("query supersede audit: %v", err)
	}
	if auditCount != 0 {
		t.Fatalf("rollout_superseded audit rows = %d, want 0 when no older active row existed", auditCount)
	}
}

func TestObserveNewVersions_AuditsActualSupersedeOnce(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_ring_config (tenant_id, enabled) VALUES ($1::uuid, true)`, tenantID,
	); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO agent_config (tenant_id) VALUES ($1::uuid)`, tenantID,
	); err != nil {
		t.Fatalf("insert agent_config: %v", err)
	}
	oldID := insertApprovalRow(t, pool, tenantID, "macos", "zoom", "7.0.0",
		1, "rolling", time.Now().UTC().Add(-24*time.Hour))
	insertProvenance(t, pool, tenantID, time.Now().UTC(), "macos", "zoom", "7.1.0")

	rings.ObserveNewVersions(ctx, pool)

	_, oldState, _ := approvalSnapshot(t, pool, oldID)
	if oldState != "superseded" {
		t.Fatalf("older rollout state = %q, want superseded", oldState)
	}
	var auditCount int
	var supersededCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*), COALESCE(max((new_value->>'superseded_count')::int), 0)
		FROM ring_config_changes
		WHERE tenant_id = $1::uuid AND change_type = 'rollout_superseded'
	`, tenantID).Scan(&auditCount, &supersededCount); err != nil {
		t.Fatalf("query supersede audit: %v", err)
	}
	if auditCount != 1 || supersededCount != 1 {
		t.Fatalf("supersede audit = {rows:%d count:%d}, want {rows:1 count:1}", auditCount, supersededCount)
	}
}

func TestObserveNewVersions_DelayedOlderSuccessCannotSupersedeNewerRollout(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_ring_config (tenant_id, enabled) VALUES ($1::uuid, true)`, tenantID,
	); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO agent_config (tenant_id) VALUES ($1::uuid)`, tenantID,
	); err != nil {
		t.Fatalf("insert agent_config: %v", err)
	}

	newerID := insertApprovalRow(t, pool, tenantID, "macos", "zoom", "3.0.0",
		1, "rolling", time.Now().UTC().Add(-time.Hour))
	// This success is received later, but reports an older version because it
	// was queued/offline. received_at must never be treated as version order.
	insertProvenance(t, pool, tenantID, time.Now().UTC(), "macos", "zoom", "2.0.0")

	rings.ObserveNewVersions(ctx, pool)

	_, newerState, _ := approvalSnapshot(t, pool, newerID)
	if newerState != "rolling" {
		t.Fatalf("newer rollout state = %q, want rolling", newerState)
	}
	var olderCount, supersedeAudits int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM ring_version_approvals
		WHERE tenant_id = $1::uuid AND platform = 'macos' AND label = 'zoom'
		  AND version = '2.0.0'
	`, tenantID).Scan(&olderCount); err != nil {
		t.Fatalf("query rollout history: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM ring_config_changes
		WHERE tenant_id = $1::uuid AND change_type = 'rollout_superseded'
	`, tenantID).Scan(&supersedeAudits); err != nil {
		t.Fatalf("query supersede audits: %v", err)
	}
	if olderCount != 0 || supersedeAudits != 0 {
		t.Fatalf("delayed older success created rows/audit = {%d,%d}, want {0,0}", olderCount, supersedeAudits)
	}
}

// TestObserveNewVersions_FailedAttemptDoesNotSupersedeActiveRollout is the
// SAME-VERSION form of the third-review-round ObserveNewVersions regression:
// not just "reports the wrong version" but "actively destroys a real one".
// See TestObserveNewVersions_FailedAttemptAtDifferentVersion_DoesNotSupersedeActiveRollout
// below for the DIFFERENT-version form the fourth review round found this
// test didn't cover.
//
// Scenario: a "2.0" rollout is already active (state "rolling") for
// adobeacrobat. A device still on "1.0" attempts to install "2.0", and the
// attempt FAILS — so version_after stays "1.0" (the install never took), but
// available_version correctly carries the attempted "2.0", with a failure
// outcome.
//
// Before the third-round fix, ObserveNewVersions read version_after, so it
// would surface "1.0" as "the latest observed version" — a version that
// isn't new at all — find no existing "1.0" approval row, and call
// insertNewVersion for "1.0". insertNewVersion's own supersede step
// ("... AND version <> $4", advance.go) would then supersede every other
// rolling/paused row for this label whose version differs from "1.0" —
// which includes the genuinely active "2.0" rollout. A single failed install
// attempt would silently kill a real in-flight rollout.
//
// After the third-round fix, available_version ("2.0") matches the
// ALREADY-tracked "2.0" row, so the LEFT JOIN in ObserveNewVersions finds it
// and insertNewVersion is never called — nothing to supersede. After the
// fourth-round fix (success-vocabulary outcome required), this holds for an
// independent reason too: a failed attempt is now excluded from "observed"
// entirely, regardless of which version it names.
func TestObserveNewVersions_FailedAttemptDoesNotSupersedeActiveRollout(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_ring_config (tenant_id, enabled) VALUES ($1::uuid, true)`, tenantID,
	); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}

	activeID := insertApprovalRow(t, pool, tenantID, "macos", "adobeacrobat", "2.0",
		1, "rolling", time.Now().UTC().Add(-2*time.Hour))

	now := time.Now().UTC()
	// A device on "1.0" attempts "2.0" and fails: version_after stays "1.0",
	// available_version carries the attempted "2.0", outcome is a failure.
	insertProvenanceBody(t, pool, tenantID, now, map[string]any{
		"record_type": "third_party_update",
		"outcome":     "verification_failed",
		"app": map[string]any{
			"label":             "adobeacrobat",
			"version_before":    "1.0",
			"version_after":     "1.0",
			"available_version": "2.0",
		},
	})

	rings.ObserveNewVersions(ctx, pool)

	gotRing, gotState, _ := approvalSnapshot(t, pool, activeID)
	if gotState != "rolling" || gotRing != 1 {
		t.Fatalf("active 2.0 approval = {ring:%d state:%q}, want {ring:1 state:\"rolling\"} — "+
			"a failed install attempt at the SAME version must not supersede the active rollout for it", gotRing, gotState)
	}

	var spuriousCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM ring_version_approvals WHERE tenant_id = $1::uuid AND platform = 'macos' AND label = 'adobeacrobat' AND version = '1.0'`,
		tenantID,
	).Scan(&spuriousCount); err != nil {
		t.Fatalf("query for spurious 1.0 row: %v", err)
	}
	if spuriousCount != 0 {
		t.Errorf("found %d approval row(s) for version \"1.0\" — a failed 2.0 attempt must not be misreported "+
			"as a new \"1.0\" observation", spuriousCount)
	}
}

// TestObserveNewVersions_FailedAttemptAtDifferentVersion_DoesNotSupersedeActiveRollout
// is the DIFFERENT-VERSION form of the ObserveNewVersions supersede
// regression — the one the fourth review round found the same-version test
// above didn't cover. The third-round fix (reading available_version instead
// of version_after) correctly stops a failed attempt from being misreported
// as the WRONG version, but does nothing to stop a failed attempt from being
// correctly reported as a DIFFERENT, genuinely newer version — and
// insertNewVersion's supersede step doesn't care why it was called, only
// that the version differs from what's already active.
//
// Scenario: a "2.0" rollout is active and healthy (state "rolling") for
// adobeacrobat. A device attempts "3.0" — a real, newer version — and the
// attempt FAILS: version_after stays at "2.0" (already installed, unchanged
// by the failed attempt), available_version correctly carries the attempted
// "3.0", outcome is a failure.
//
// Before the fourth-round fix, available_version="3.0" would not match the
// existing "2.0" row, so insertNewVersion("3.0") would be called, and its
// supersede step ("... AND version <> $4") would supersede the healthy "2.0"
// rollout — a single failed download of an unrelated, newer version killing
// an in-flight rollout that was working fine. After the fix, the failure
// outcome excludes this record from "observed" entirely (see
// ObserveNewVersions' doc comment): insertNewVersion is never called for
// "3.0" at all, so there's nothing to supersede with.
func TestObserveNewVersions_FailedAttemptAtDifferentVersion_DoesNotSupersedeActiveRollout(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_ring_config (tenant_id, enabled) VALUES ($1::uuid, true)`, tenantID,
	); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}

	activeID := insertApprovalRow(t, pool, tenantID, "macos", "adobeacrobat", "2.0",
		1, "rolling", time.Now().UTC().Add(-2*time.Hour))

	now := time.Now().UTC()
	// A device already on "2.0" attempts "3.0" and fails: version_after
	// stays "2.0" (unchanged), available_version carries the attempted
	// "3.0" — a genuinely different, newer version — with a failure outcome.
	insertProvenanceBody(t, pool, tenantID, now, map[string]any{
		"record_type": "third_party_update",
		"outcome":     "verification_failed",
		"app": map[string]any{
			"label":             "adobeacrobat",
			"version_before":    "2.0",
			"version_after":     "2.0",
			"available_version": "3.0",
		},
	})

	rings.ObserveNewVersions(ctx, pool)

	gotRing, gotState, _ := approvalSnapshot(t, pool, activeID)
	if gotState != "rolling" || gotRing != 1 {
		t.Fatalf("active 2.0 approval = {ring:%d state:%q}, want {ring:1 state:\"rolling\"} — "+
			"a failed install attempt at a DIFFERENT (newer) version must not supersede the active "+
			"rollout for a version that is actually working", gotRing, gotState)
	}

	var spuriousCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM ring_version_approvals WHERE tenant_id = $1::uuid AND platform = 'macos' AND label = 'adobeacrobat' AND version = '3.0'`,
		tenantID,
	).Scan(&spuriousCount); err != nil {
		t.Fatalf("query for spurious 3.0 row: %v", err)
	}
	if spuriousCount != 0 {
		t.Errorf("found %d approval row(s) for version \"3.0\" — a failed attempt must not create a row "+
			"for the version it attempted, only a successful one should", spuriousCount)
	}
}

// TestObserveNewVersions_RecordTypeAllowlist_RejectsForgedType is the test
// for the record_type ALLOWLIST fix (fourth review round). Unlike
// queryFailureRate and queryWaveBars, ObserveNewVersions had NO record_type
// check at all before this round — any record with a label, a success
// outcome/state, and an available_version would be treated as "observed",
// regardless of record_type. provenance is client-supplied JSON archived
// verbatim under a shared tenant secret, so a forged record_type like
// "inventory" carrying otherwise update-shaped, successful-looking fields
// could create a rollout row and supersede an active one — the same
// decision-signal-injection concern already fixed in the other two queries.
//
// A device reports a forged "inventory" record with a successful outcome
// for a version genuinely different from an already-active rollout. Must
// produce NO new row and must NOT supersede the active one.
func TestObserveNewVersions_RecordTypeAllowlist_RejectsForgedType(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_ring_config (tenant_id, enabled) VALUES ($1::uuid, true)`, tenantID,
	); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}

	activeID := insertApprovalRow(t, pool, tenantID, "macos", "adobeacrobat", "2.0",
		1, "rolling", time.Now().UTC().Add(-2*time.Hour))

	now := time.Now().UTC()
	// A forged record: real-looking success fields for "3.0", but
	// record_type is neither absent nor "third_party_update".
	insertProvenanceBody(t, pool, tenantID, now, map[string]any{
		"record_type": "inventory",
		"outcome":     "installed",
		"app": map[string]any{
			"label":             "adobeacrobat",
			"version_before":    "2.0",
			"version_after":     "3.0",
			"available_version": "3.0",
		},
	})

	rings.ObserveNewVersions(ctx, pool)

	gotRing, gotState, _ := approvalSnapshot(t, pool, activeID)
	if gotState != "rolling" || gotRing != 1 {
		t.Fatalf("active 2.0 approval = {ring:%d state:%q}, want {ring:1 state:\"rolling\"} — "+
			"a forged record_type:\"inventory\" row must not supersede the active rollout", gotRing, gotState)
	}

	var spuriousCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM ring_version_approvals WHERE tenant_id = $1::uuid AND platform = 'macos' AND label = 'adobeacrobat' AND version = '3.0'`,
		tenantID,
	).Scan(&spuriousCount); err != nil {
		t.Fatalf("query for spurious 3.0 row: %v", err)
	}
	if spuriousCount != 0 {
		t.Errorf("found %d approval row(s) for version \"3.0\" — a forged record_type must not create a row", spuriousCount)
	}
}

// captureLogs redirects the package-level slog default logger to an
// in-memory JSON buffer for the duration of the test and returns a function
// that parses and returns everything captured so far as decoded records.
//
// PAT-997 third review round disabled processApproval's mutations entirely
// (see its doc comment in advance.go), which meant DB state alone could not
// prove what the decision logic concluded for a "rolling" row: the row was
// always unchanged then, regardless of whether queryFailureRate's field
// paths, ring scope, platform scope, or dedup were correct or badly broken.
// The structured decision log line processApproval emits on every pass was
// the only observable signal available for tests that needed to prove
// decision-logic correctness independent of the disablement itself.
//
// PAT-1118 re-enabled mutation, so DB state is now a valid assertion again
// for most of these tests (and several below assert both: the resulting row
// state AND the log line, since the log line remains the audit trail of
// which decision fired and why — see processApproval's doc comment). The
// zero-sample branches (eligibleDevices==0, noObservations) still never
// mutate by design, so captureLogs stays the only way to distinguish those
// two structurally different causes of an unchanged row. Level is forced to
// Debug so the "soak not yet elapsed" branch — the only one logged below
// Info — is never silently dropped by a default handler level filter.
func captureLogs(t *testing.T) func() []map[string]any {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return func() []map[string]any {
		var records []map[string]any
		dec := json.NewDecoder(bytes.NewReader(buf.Bytes()))
		for {
			var m map[string]any
			if err := dec.Decode(&m); err != nil {
				break
			}
			records = append(records, m)
		}
		return records
	}
}

// findLogForApproval returns the first captured log record whose "id" field
// matches approvalID and whose "msg" contains msgSubstr, or nil if none
// matches.
func findLogForApproval(records []map[string]any, approvalID, msgSubstr string) map[string]any {
	for _, r := range records {
		id, _ := r["id"].(string)
		msg, _ := r["msg"].(string)
		if id == approvalID && strings.Contains(msg, msgSubstr) {
			return r
		}
	}
	return nil
}

// approvalSnapshot reads back one ring_version_approvals row's mutable state
// for assertions.
func approvalSnapshot(t *testing.T, pool *pgxpool.Pool, id string) (approvedRing int16, state string, pausedReason *string) {
	t.Helper()
	if err := pool.QueryRow(context.Background(),
		`SELECT approved_ring, state, paused_reason FROM ring_version_approvals WHERE id = $1::uuid`, id,
	).Scan(&approvedRing, &state, &pausedReason); err != nil {
		t.Fatalf("read back approval row: %v", err)
	}
	return approvedRing, state, pausedReason
}

// TestProcessApproval_ZeroObservations_DoesNotAdvance is the crucial PAT-997
// gating regression test. Before the second review round's fix,
// queryFailureRate returning (0, 0) on zero matching provenance rows was
// indistinguishable from (0, 0) on genuinely healthy zero-failure data: both
// read as "0% failure rate", and processApproval's only advance-blocking
// checks were state/soak/threshold — none of which a 0% rate ever trips.
//
// This scenario has zero evidence either way, so it's the one case where
// automatic mutation being live (PAT-1118) or not produces the same DB
// outcome: the row must stay at ring 0/"rolling" regardless. What
// discriminates correct decision logic from broken is the LOGGED decision:
// this asserts the specific "no install observations yet" record appears
// (not, say, "advanced"), via captureLogs.
func TestProcessApproval_ZeroObservations_DoesNotAdvance(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	// soak_gap_hours=0 so soakElapsed is true unconditionally; a generous
	// failure_threshold_pct so nothing about the threshold could plausibly
	// block advancement — the ONLY thing standing between this row and
	// advancing must be the zero-observation check.
	setupTenantRingConfig(t, pool, tenantID, 4 /* ring_count */, 0 /* soak_gap_hours */, 50.0 /* threshold */, 2 /* min_failures */)

	// An eligible ring-0 device exists — but it has never reported any
	// provenance for this label/version. Zero observations, not zero failures.
	insertDevice(t, pool, tenantID, "11111111-1111-1111-1111-111111111111", 0)

	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "adobeacrobat", "1.0.0",
		0 /* approved_ring */, "rolling", time.Now().UTC().Add(-48*time.Hour))

	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)

	gotRing, gotState, _ := approvalSnapshot(t, pool, approvalID)
	if gotRing != 0 || gotState != "rolling" {
		t.Fatalf("approval row = {ring:%d state:%q}, want {ring:0 state:\"rolling\"} — "+
			"a rollout with zero install observations must not advance", gotRing, gotState)
	}

	logs := getLogs()
	rec := findLogForApproval(logs, approvalID, "no install observations yet")
	if rec == nil {
		t.Fatalf("no log record found reporting zero observations for approval %s", approvalID)
	}
	if oc, _ := rec["observed_count"].(float64); oc != 0 {
		t.Errorf("logged observed_count = %v, want 0", rec["observed_count"])
	}
	// Devices DO exist in this ring — this is the transient "not reported yet"
	// case, not the structural "nobody is in this ring" one, and the two must
	// not be conflated.
	if ed, _ := rec["eligible_devices"].(float64); ed != 1 {
		t.Errorf("logged eligible_devices = %v, want 1", rec["eligible_devices"])
	}

	// PAT-1002 defect 11, the part the assertion above does not cover: zero
	// observations must be BOTH not-a-pass and not-a-failure. The old code
	// only avoided auto-pausing here by accident — 0.0 > threshold and
	// 0 >= min_failures_to_pause both happen to be false for the configured
	// ranges — so assert the absence of each verdict explicitly rather than
	// trusting arithmetic on an empty sample to keep landing the right way.
	if rec := findLogForApproval(logs, approvalID, "rings: advanced"); rec != nil {
		t.Errorf("zero observations were treated as a pass: %+v", rec)
	}
	if rec := findLogForApproval(logs, approvalID, "rings: completed"); rec != nil {
		t.Errorf("zero observations were treated as a pass (completion): %+v", rec)
	}
	if rec := findLogForApproval(logs, approvalID, "rings: auto-paused"); rec != nil {
		t.Errorf("zero observations were treated as a failure: %+v", rec)
	}
}

// TestProcessApproval_NoEligibleDevicesInRing covers the other zero-sample
// cause PAT-1002 defect 11 asks to be explicit about: not "the devices in this
// ring have not reported yet" but "there are no devices in this ring at all".
//
// Both block advancement and neither is a failure, so an earlier version
// reported them with one message. They are not the same situation: the first
// resolves by waiting, the second never does. A rollout parked on a ring with
// no devices can never gather evidence, so it sits there permanently, and
// under the old "no observations yet" wording that permanent stall was
// indistinguishable from a rollout that started five minutes ago.
//
// The scenario here is the exact one defect 8's numeric increment produced: a
// ring_count=3 tenant assigns devices to agent rings 0, 1 and 3 only, and the
// rollout is sitting on 2.
func TestProcessApproval_NoEligibleDevicesInRing(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 3 /* rings 0,1,3 */, 0, 50.0, 2)

	// Devices exist, on the rings this config actually assigns. None on 2.
	insertDevice(t, pool, tenantID, "4b4b4b4b-4b4b-4b4b-4b4b-4b4b4b4b4b40", 0)
	insertDevice(t, pool, tenantID, "4b4b4b4b-4b4b-4b4b-4b4b-4b4b4b4b4b41", 1)
	insertDevice(t, pool, tenantID, "4b4b4b4b-4b4b-4b4b-4b4b-4b4b4b4b4b43", 3)

	now := time.Now().UTC()
	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "firefox", "130.0",
		2 /* the phantom ring a pre-PAT-1002 advance would have left it on */, "rolling", now.Add(-48*time.Hour))

	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)

	gotRing, gotState, _ := approvalSnapshot(t, pool, approvalID)
	if gotRing != 2 || gotState != "rolling" {
		t.Fatalf("approval = {ring:%d state:%q}, want {ring:2 state:\"rolling\"} UNCHANGED", gotRing, gotState)
	}

	logs := getLogs()
	rec := findLogForApproval(logs, approvalID, "no devices are assigned")
	if rec == nil {
		t.Fatalf("no \"no devices are assigned\" log record for approval %s — a rollout on a ring containing "+
			"no devices can never gather evidence there, and must say so rather than reporting the transient "+
			"\"not reported yet\" message forever", approvalID)
	}
	if ed, _ := rec["eligible_devices"].(float64); ed != 0 {
		t.Errorf("logged eligible_devices = %v, want 0", rec["eligible_devices"])
	}
	// Same as above: neither a pass nor a failure.
	if rec := findLogForApproval(logs, approvalID, "rings: advanced"); rec != nil {
		t.Errorf("an empty ring was treated as a pass: %+v", rec)
	}
	if rec := findLogForApproval(logs, approvalID, "rings: auto-paused"); rec != nil {
		t.Errorf("an empty ring was treated as a failure: %+v", rec)
	}
}

// TestProcessApproval_NonContiguousRings_AdvancesToNextConfiguredRing is the
// PAT-1002 defect-8 regression test, end to end through AdvanceAll.
//
// approved_ring used to move by +1 (clamped at 3). That is only correct for
// ring_count=4. For every other ring_count, RingToAgentValue pins the last
// band to 3 and leaves holes below it, so the increment landed the rollout on
// a ring no device is assigned to: evidence could never arrive, observedCount
// stayed 0 forever, and the rollout deadlocked one step short of GA. Worse, it
// deadlocked while still reporting "rolling", so nothing distinguished it from
// a rollout that was progressing.
//
// Each case here gives the rollout healthy, eligible evidence from a device on
// its CURRENT ring, so the only question left is which ring it actually moves
// to. PAT-1118 turned this from a logged hypothetical into a real mutation,
// so this now asserts the DB row's approved_ring after the pass, not just the
// logged decision.
func TestProcessApproval_NonContiguousRings_AdvancesToNextConfiguredRing(t *testing.T) {
	cases := []struct {
		name         string
		ringCount    int16
		currentRing  int16
		wantNextRing int16
	}{
		// ring_count 2 assigns 0 and 3. The old code would have said 1.
		{"ring_count 2: ring 0 advances straight to GA", 2, 0, 3},
		// ring_count 3 assigns 0, 1 and 3. The old code would have said 2,
		// which is the deadlock: no device is ever assigned agent ring 2 under
		// this config.
		{"ring_count 3: ring 1 advances straight to GA", 3, 1, 3},
		{"ring_count 3: ring 0 advances to 1", 3, 0, 1},
		// ring_count 4 is contiguous — unchanged behaviour, kept so a future
		// change can't fix the holes by breaking the common case.
		{"ring_count 4: ring 1 advances to 2", 4, 1, 2},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pool := dbPool(t)
			ctx := context.Background()

			var tenantID string
			if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
				t.Fatalf("insert tenant: %v", err)
			}
			setupTenantRingConfig(t, pool, tenantID, tc.ringCount, 0, 50.0, 2)
			insertAgentConfig(t, pool, tenantID)

			hw := "6c6c6c6c-6c6c-6c6c-6c6c-6c6c6c6c6c6c"
			insertDeviceOS(t, pool, tenantID, hw, tc.currentRing, "macOS")

			now := time.Now().UTC()
			insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hw),
				"firefox", "129.0", "130.0", "installed", true)

			approvalID := insertApprovalRow(t, pool, tenantID, "macos", "firefox", "130.0",
				tc.currentRing, "rolling", now.Add(-48*time.Hour))

			getLogs := captureLogs(t)
			rings.AdvanceAll(ctx, pool, nil)

			gotRing, gotState, _ := approvalSnapshot(t, pool, approvalID)
			if gotRing != tc.wantNextRing || gotState != "rolling" {
				t.Fatalf("approval = {ring:%d state:%q}, want {ring:%d state:\"rolling\"} — "+
					"the next ring must come from the tenant's configured ring list, not approved_ring+1, or "+
					"the rollout lands on a ring with no devices in it and can never move again",
					gotRing, gotState, tc.wantNextRing)
			}

			rec := findLogForApproval(getLogs(), approvalID, "rings: advanced")
			if rec == nil {
				t.Fatalf("no \"rings: advanced\" log record for approval %s", approvalID)
			}
			if got, _ := rec["advanced_to_ring"].(float64); int16(got) != tc.wantNextRing {
				t.Errorf("logged advanced_to_ring = %v, want %v", rec["advanced_to_ring"], tc.wantNextRing)
			}
		})
	}
}

// TestProcessApproval_RealMacOSFailures_AutoPauses proves queryFailureRate
// reads real macOS provenance shapes correctly end to end: two ring-0
// devices, two matching FAILED-install records using honest emitter
// semantics (available_version carries the attempted target "8.10.0";
// version_after stays at the prior "8.9.0" because the install never took —
// see insertProvenanceMacOSAttempt) — a 100% failure rate that must be
// recognized as auto-pause-worthy. The first version of this test asserted
// this via a fixture that set version_after to the target version on
// failure, which contradicts real emitter behaviour and — more importantly —
// happened to match the query's original (buggy) version_after-keyed WHERE
// clause, so it could not have caught that bug. This version, matching on
// available_version, catches it.
//
// PAT-1118 turned this from a logged hypothetical into a real mutation: the
// row must actually transition to "paused" with a paused_reason recording the
// failure rate, not just log that it would have.
func TestProcessApproval_RealMacOSFailures_AutoPauses(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4, 0 /* soak_gap_hours */, 10.0 /* threshold pct */, 1 /* min_failures */)
	insertAgentConfig(t, pool, tenantID)

	hw1 := "22222222-2222-2222-2222-222222222221"
	hw2 := "22222222-2222-2222-2222-222222222222"
	insertDevice(t, pool, tenantID, hw1, 0)
	insertDevice(t, pool, tenantID, hw2, 0)

	// Provenance carries the hw_uuid in the real macOS convention
	// (IOPlatformUUID, uppercase) while devices.hw_uuid — a Postgres uuid
	// column — normalizes to lowercase on ::text cast. A prior version of
	// this fix compared them as raw text and silently matched nothing on
	// live production data; using uppercase here (unlike the lowercase
	// literals used elsewhere in this file where the join isn't under test)
	// pins that case-normalization behaviour against regression.
	now := time.Now().UTC()
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hw1), "1password", "8.9.0", "8.10.0", "verification_failed", false)
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hw2), "1password", "8.9.0", "8.10.0", "verification_failed", false)

	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "1password", "8.10.0",
		0, "rolling", now.Add(-48*time.Hour))

	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)

	gotRing, gotState, pausedReason := approvalSnapshot(t, pool, approvalID)
	if gotState != "paused" || gotRing != 0 || pausedReason == nil {
		t.Fatalf("approval row = {ring:%d state:%q reason:%v}, want {ring:0 state:\"paused\" reason:non-nil} — "+
			"a 100%% failure rate from real macOS payload shapes must auto-pause the rollout", gotRing, gotState, pausedReason)
	}
	if !strings.Contains(*pausedReason, "100") {
		t.Errorf("paused_reason = %q, want it to mention the 100%% failure rate", *pausedReason)
	}

	rec := findLogForApproval(getLogs(), approvalID, "rings: auto-paused")
	if rec == nil {
		t.Fatalf("no \"rings: auto-paused\" log record found for approval %s — "+
			"100%% failure rate from real macOS payload shapes should have been recognized and acted on", approvalID)
	}
	if rate, _ := rec["failure_rate"].(float64); rate != 100 {
		t.Errorf("logged failure_rate = %v, want 100", rec["failure_rate"])
	}
}

// TestProcessApproval_Windows_SkipsAutomaticGating is the PAT-1002 defect-9
// regression test, and it replaces an earlier test
// (TestProcessApproval_WindowsOnlyObservations_FailClosed) that asserted the
// symptom rather than the decision.
//
// The underlying gap is unchanged and is structural: the Windows provenance
// emitter (windows/src/Service/ProvenancePoster.cs BuildPayload, updater repo)
// serializes tenant_id, label, installed_version, available_version, state,
// platform and computer_name, and no per-device identifier of any kind. Every
// gate in this package is per-device, so no quantity of Windows evidence can
// ever satisfy one.
//
// What changed is how that is reported. Letting the gate run and come up empty
// logged "no install observations yet" forever — the same line a macOS rollout
// emits while its devices are still working through a soak, so an impossible
// state was indistinguishable from a transient one. Windows approvals are now
// short-circuited BEFORE the evidence query with an explicit manual-only
// decision.
//
// Five successful Windows installs are seeded here precisely because they
// would look like advance-worthy evidence to a gate that trusted them: if a
// future change removes the Windows branch and loosens the device join so
// unattributed rows count, this test fails on the missing skip record rather
// than passing quietly because "no observations" happens to still be true.
func TestProcessApproval_Windows_SkipsAutomaticGating(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4, 0, 50.0, 2)

	insertDeviceOS(t, pool, tenantID, "33333333-3333-3333-3333-333333333333", 0, "Windows")

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		insertProvenanceWindowsAttempt(t, pool, tenantID, now, "slack", "4.49.0", "4.50.143", "uptodate", true)
	}

	approvalID := insertApprovalRow(t, pool, tenantID, "windows", "slack", "4.50.143",
		0, "rolling", now.Add(-48*time.Hour))

	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)

	gotRing, gotState, _ := approvalSnapshot(t, pool, approvalID)
	if gotRing != 0 || gotState != "rolling" {
		t.Fatalf("approval row = {ring:%d state:%q}, want {ring:0 state:\"rolling\"} — "+
			"Windows rollouts are manual-only, even now that automatic advancement is live (PAT-1118); "+
			"this row must never mutate through the automatic path regardless", gotRing, gotState)
	}

	logs := getLogs()
	if rec := findLogForApproval(logs, approvalID, "automatic gating skipped"); rec == nil {
		t.Fatalf("no \"automatic gating skipped\" log record for Windows approval %s — a Windows rollout "+
			"must be excluded from the automatic gate explicitly, not run through a gate it can never satisfy", approvalID)
	}
	// The point of the explicit branch is that the impossible case no longer
	// masquerades as the transient one, so the transient line must NOT appear.
	if rec := findLogForApproval(logs, approvalID, "no install observations yet"); rec != nil {
		t.Errorf("Windows approval logged the transient \"no install observations yet\" decision: %+v — "+
			"that is the macOS 'devices have not reported yet' message and reads as something that will "+
			"resolve on its own, which for Windows it never will", rec)
	}
	if rec := findLogForApproval(logs, approvalID, "rings: advanced"); rec != nil {
		t.Errorf("Windows approval was judged advance-worthy and mutated: %+v — unattributed Windows records "+
			"must never count as per-device evidence", rec)
	}
}

// TestProcessApproval_Windows_ManualSkipReachesCompleted is the other half of
// defect 9: with automatic gating skipped for Windows, manual skip is the ONLY
// way a Windows rollout ever moves, so it has to be able to finish the job.
//
// Before this fix it could not. RingRolloutSkipHandler clamped approved_ring
// at 3 and left state 'rolling', and the only transitions to 'completed' were
// completeApproval (on the disabled automatic path) and emergency-deploy
// (which requires a reason and means "bypass the gates", not "this finished").
// A Windows rollout driven to GA by hand therefore stayed on the dashboard's
// active list forever.
//
// This exercises the state machine directly rather than through the HTTP
// handler, which lives in another package: the assertion is that a rollout
// sitting at its final configured ring has somewhere to go, and that the
// approvals table accepts and reports the terminal state. The handler's own
// path is covered by TestRingRolloutSkip_* in internal/handlers.
func TestProcessApproval_Windows_ManualSkipReachesCompleted(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 3 /* rings 0,1,3 */, 0, 50.0, 2)

	now := time.Now().UTC()
	approvalID := insertApprovalRow(t, pool, tenantID, "windows", "slack", "4.50.143",
		0, "rolling", now.Add(-48*time.Hour))

	// Walk the configured ring list the way manual skip now does.
	ring := 0
	for {
		next, ok := rings.NextConfiguredRing(ring, 3)
		if !ok {
			break
		}
		ring = next
		if _, err := pool.Exec(ctx,
			`UPDATE ring_version_approvals SET approved_ring = $1 WHERE id = $2::uuid`, ring, approvalID,
		); err != nil {
			t.Fatalf("manual skip to ring %d: %v", ring, err)
		}
	}
	if ring != 3 {
		t.Fatalf("manual skipping ended at ring %d, want 3 (GA) — a Windows rollout must be able to reach "+
			"GA by hand in a bounded number of skips, without stopping on a ring no device is in", ring)
	}

	// At GA there is no next configured ring, so the next skip completes it.
	if _, ok := rings.NextConfiguredRing(ring, 3); ok {
		t.Fatalf("NextConfiguredRing(3, 3) reports another ring after GA — completion would never be reachable")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE ring_version_approvals SET state = 'completed' WHERE id = $1::uuid`, approvalID,
	); err != nil {
		t.Fatalf("complete: %v", err)
	}

	gotRing, gotState, _ := approvalSnapshot(t, pool, approvalID)
	if gotRing != 3 || gotState != "completed" {
		t.Fatalf("approval = {ring:%d state:%q}, want {ring:3 state:\"completed\"}", gotRing, gotState)
	}

	// A completed rollout must drop out of the automatic pass entirely: it is
	// no longer in AdvanceAll's ('rolling','paused') selection, so a later tick
	// cannot resurrect or re-evaluate it.
	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)
	if rec := findLogForApproval(getLogs(), approvalID, ""); rec != nil {
		t.Errorf("completed approval was still evaluated by AdvanceAll: %+v", rec)
	}
	gotRing, gotState, _ = approvalSnapshot(t, pool, approvalID)
	if gotRing != 3 || gotState != "completed" {
		t.Errorf("approval = {ring:%d state:%q} after a later pass, want {ring:3 state:\"completed\"} unchanged", gotRing, gotState)
	}
}

// TestProcessApproval_AdvancesOnRealEvidence_NotCrossPlatform is doing double
// duty:
//
//  1. It is THE verification that automatic advancement, now live (PAT-1118),
//     actually moves a rollout under perfect healthy evidence, soak elapsed,
//     everything eligible for the macOS approval row: approved_ring must move
//     from 0 to 1 and the row must stay "rolling" (not the final ring for
//     ring_count=4).
//  2. It is the P0 cross-platform-contamination regression test: the same
//     macOS evidence must not advance (or even register as evidence for) a
//     Windows approval row for the identical tenant/label/version —
//     a.Platform was never passed into queryFailureRate's query before this
//     fix, so in a mixed estate macOS installs could satisfy a Windows row's
//     gate and vice versa, quietly defeating the Windows fail-closed
//     behaviour asserted elsewhere in this file.
//
// The Windows approval row here is inserted directly via insertApprovalRow
// rather than through ObserveNewVersions, so this test controls the row's
// starting ring and state exactly and stays independent of the separate
// question of what state a newly observed Windows version starts in (covered
// by TestInsertNewVersion_WindowsStartsRolling below).
func TestProcessApproval_AdvancesOnRealEvidence_NotCrossPlatform(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	// ring_count=4 -> agent values 0,1,2,3 map 1:1 to ring indices, so a
	// would-be advance from ring 0 would go to 1, not straight to complete.
	setupTenantRingConfig(t, pool, tenantID, 4, 0 /* soak_gap_hours */, 50.0 /* generous threshold */, 2)
	insertAgentConfig(t, pool, tenantID)

	hw := "66666666-6666-6666-6666-666666666666"
	insertDevice(t, pool, tenantID, hw, 0)

	now := time.Now().UTC()
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hw), "adobeacrobat", "24.0", "24.1", "installed", true)

	macApprovalID := insertApprovalRow(t, pool, tenantID, "macos", "adobeacrobat", "24.1",
		0, "rolling", now.Add(-48*time.Hour))
	winApprovalID := insertApprovalRow(t, pool, tenantID, "windows", "adobeacrobat", "24.1",
		0, "rolling", now.Add(-48*time.Hour))

	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)
	logs := getLogs()

	// --- (1) Perfect healthy evidence actually advances the macOS row. ---
	macRing, macState, _ := approvalSnapshot(t, pool, macApprovalID)
	if macRing != 1 || macState != "rolling" {
		t.Fatalf("macos approval = {ring:%d state:%q}, want {ring:1 state:\"rolling\"} — "+
			"real successful macOS evidence for this exact label/version should have advanced this ring", macRing, macState)
	}
	macRec := findLogForApproval(logs, macApprovalID, "rings: advanced")
	if macRec == nil {
		t.Fatalf("no \"rings: advanced\" log record for approval %s", macApprovalID)
	}
	if want, got := float64(1), macRec["advanced_to_ring"]; got != want {
		t.Errorf("logged advanced_to_ring = %v, want %v", got, want)
	}

	// --- (2) That evidence must not leak into the Windows row's gate. ---
	//
	// As of PAT-1002 the Windows row is short-circuited before the evidence
	// query runs at all (see TestProcessApproval_Windows_SkipsAutomaticGating),
	// which is a stronger guarantee than the platform filter alone: no
	// evidence of any platform reaches a Windows approval's gate. The
	// macOS-side platform filter — the one that still has to work, since
	// macOS approvals DO run the gate — is covered by
	// TestProcessApproval_PlatformScoped_ForgedPlatformDoesNotCount below.
	winRing, winState, _ := approvalSnapshot(t, pool, winApprovalID)
	if winRing != 0 || winState != "rolling" {
		t.Errorf("windows approval = {ring:%d state:%q}, want {ring:0 state:\"rolling\"}", winRing, winState)
	}
	if rec := findLogForApproval(logs, winApprovalID, "automatic gating skipped"); rec == nil {
		t.Fatalf("no \"automatic gating skipped\" log record for windows approval %s", winApprovalID)
	}
	if rec := findLogForApproval(logs, winApprovalID, "rings: advanced"); rec != nil {
		t.Errorf("windows approval was judged advance-worthy on macOS evidence and mutated: %+v — macOS "+
			"evidence for the SAME label/version must never register as evidence for a Windows row", rec)
	}
}

// TestProcessApproval_PlatformScoped_ForgedPlatformDoesNotCount is the
// surviving direct test of queryFailureRate's platform scoping, in the
// direction that still runs the gate (macOS). It covers BOTH sides of the
// scope, which the pre-PAT-1002 code only half-had:
//
//   - Provenance side: a record claiming "platform":"windows" must not count
//     towards a macOS approval, even when it carries the device.hw_uuid of a
//     genuinely eligible macOS device. Before the platform filter was passed
//     into the query at all, it did.
//   - Device side: a device whose devices.os is "Windows" must not be an
//     eligible device for a macOS approval, even when a macOS-shaped record
//     names its hw_uuid. Filtering only the provenance side left this open:
//     provenance body is client-supplied JSON, so the platform claimed in the
//     body and the device the body names are independently chosen, and a body
//     could claim macOS while naming a Windows device.
//
// Only the one legitimately macOS record (macOS-shaped body, macOS device)
// may count, so observed_count must be 1.
func TestProcessApproval_PlatformScoped_ForgedPlatformDoesNotCount(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4, 0, 50.0, 2)
	insertAgentConfig(t, pool, tenantID)

	hwMac := "5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a51"
	hwWin := "5a5a5a5a-5a5a-5a5a-5a5a-5a5a5a5a5a52"
	insertDeviceOS(t, pool, tenantID, hwMac, 0, "macOS")
	insertDeviceOS(t, pool, tenantID, hwWin, 0, "Windows")

	now := time.Now().UTC()

	// Legitimate: macOS body, macOS device. Counts.
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hwMac), "adobeacrobat", "24.0", "24.1", "installed", true)

	// Wrong-platform body naming an eligible macOS device. Must not count for
	// a macOS approval.
	insertProvenanceBody(t, pool, tenantID, now.Add(time.Minute), map[string]any{
		"record_type": "third_party_update",
		"platform":    "windows",
		"device":      map[string]any{"hw_uuid": strings.ToUpper(hwMac)},
		"outcome":     "installed",
		"app": map[string]any{
			"label":             "adobeacrobat",
			"version_before":    "24.0",
			"version_after":     "24.1",
			"available_version": "24.1",
		},
	})

	// macOS-shaped body naming a WINDOWS device. Must not count either: the
	// device is not eligible for a macOS rollout.
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hwWin), "adobeacrobat", "24.0", "24.1", "installed", true)

	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "adobeacrobat", "24.1",
		0, "rolling", now.Add(-48*time.Hour))

	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)

	rec := findLogForApproval(getLogs(), approvalID, "rings: advanced")
	if rec == nil {
		t.Fatalf("no \"rings: advanced\" log record for approval %s — the one legitimate macOS "+
			"observation should still count and advance the rollout", approvalID)
	}
	if oc, _ := rec["observed_count"].(float64); oc != 1 {
		t.Errorf("logged observed_count = %v, want 1 — only the macOS-body/macOS-device record may count; "+
			"a forged \"platform\":\"windows\" body and a Windows device must both be excluded", rec["observed_count"])
	}
	if ed, _ := rec["eligible_devices"].(float64); ed != 1 {
		t.Errorf("logged eligible_devices = %v, want 1 — a device whose os is \"Windows\" is not an "+
			"eligible device for a macOS rollout", rec["eligible_devices"])
	}

	gotRing, gotState, _ := approvalSnapshot(t, pool, approvalID)
	if gotRing != 1 || gotState != "rolling" {
		t.Errorf("approval = {ring:%d state:%q}, want {ring:1 state:\"rolling\"} — the legitimate macOS "+
			"observation should have advanced the rollout for real", gotRing, gotState)
	}
}

// TestProcessApproval_CurrentRingOnly is the P0 regression test for "earlier
// ring evidence advances later rings": eligible_devices used to select every
// device with effective ring <= approved_ring, so once a rollout advanced
// from ring 0 to ring 1, a ring-0 device's evidence (e.g. a periodic
// "already_current" re-report, unrelated to the newly-opened ring 1) kept
// satisfying observedCount forever, letting ring 1 advance to ring 2 (and so
// on to GA) with zero ring-1 devices ever having reported anything.
//
// Phase 1: approved_ring is already 1 (simulating a rollout that already
// advanced past ring 0 once). Fresh evidence (received after last_advanced_at)
// exists ONLY from a ring-0 device. Must NOT advance — ring 0 already spent
// its evidence justifying the 0->1 move; it doesn't get to also justify 1->2.
//
// Phase 2: add fresh evidence from an actual ring-1 device and re-run. Its
// evidence-worthiness must now be recognized and, since PAT-1118, actually
// acted on — proving the fix isn't simply "nothing ever counts again" but
// specifically "count only evidence from the ring being exposed".
func TestProcessApproval_CurrentRingOnly(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4, 0, 50.0, 2)
	insertAgentConfig(t, pool, tenantID)

	hwRing0 := "77777777-7777-7777-7777-777777777770"
	hwRing1 := "77777777-7777-7777-7777-777777777771"
	insertDevice(t, pool, tenantID, hwRing0, 0)
	insertDevice(t, pool, tenantID, hwRing1, 1)

	now := time.Now().UTC()
	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "firefox", "130.0",
		1 /* approved_ring: already advanced once */, "rolling", now.Add(-48*time.Hour))

	// Phase 1: only stale ring-0 evidence, received after last_advanced_at.
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hwRing0), "firefox", "129.0", "130.0", "installed", true)

	getLogs1 := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)

	gotRing, gotState, _ := approvalSnapshot(t, pool, approvalID)
	if gotRing != 1 || gotState != "rolling" {
		t.Fatalf("phase 1: approval = {ring:%d state:%q}, want {ring:1 state:\"rolling\"} UNCHANGED", gotRing, gotState)
	}
	if rec := findLogForApproval(getLogs1(), approvalID, "no install observations yet"); rec == nil {
		t.Fatalf("phase 1: no \"no install observations yet\" log record — " +
			"a ring-0 device's evidence must not count as observed for a rollout already exposing ring 1")
	}

	// Phase 2: fresh ring-1 evidence arrives. Now it should be recognized as
	// advance-worthy and actually advanced.
	insertProvenanceMacOSAttempt(t, pool, tenantID, now.Add(time.Minute), strings.ToUpper(hwRing1), "firefox", "129.0", "130.0", "installed", true)

	getLogs2 := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)

	gotRing, gotState, _ = approvalSnapshot(t, pool, approvalID)
	if gotRing != 2 || gotState != "rolling" {
		t.Fatalf("phase 2: approval = {ring:%d state:%q}, want {ring:2 state:\"rolling\"} — "+
			"once the ring actually being exposed (ring 1) reports real evidence, the rollout should advance", gotRing, gotState)
	}
	rec := findLogForApproval(getLogs2(), approvalID, "rings: advanced")
	if rec == nil {
		t.Fatalf("phase 2: no \"rings: advanced\" log record — once the ring actually being exposed " +
			"(ring 1) reports real evidence, it should be recognized as advance-worthy and acted on")
	}
	if want, got := float64(2), rec["advanced_to_ring"]; got != want {
		t.Errorf("phase 2: logged advanced_to_ring = %v, want %v", got, want)
	}
}

// TestProcessApproval_RepeatedRowsFromOneDevice_DoNotInflateEvidence is the
// P1 regression test: without a latest-per-device pick, a single device
// retrying (or simply re-polling) could inflate observedCount arbitrarily,
// and — more dangerously — could single-handedly satisfy
// min_failures_to_pause by itself. Codex's framing: provenance is
// client-supplied JSON archived verbatim under a shared tenant secret, so
// this is decision-signal injection, not SQL injection, but the defence is
// the same instinct — one client-controlled event stream should not be able
// to out-vote reality.
//
// One device reports "verification_failed" five times. min_failures_to_pause
// is 2. Deduped to one observation per device, failureCount is 1 — below
// threshold — so this must NOT auto-pause. (It also must not advance: with
// only one real observation the failure rate is 100%, over the configured
// failure_threshold_pct, so it correctly stays put rather than progressing.)
// Without the dedup fix, failureCount would be 5, satisfying
// min_failures_to_pause=2 on a single device's say-so.
func TestProcessApproval_RepeatedRowsFromOneDevice_DoNotInflateEvidence(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4, 0, 10.0 /* threshold pct */, 2 /* min_failures_to_pause */)

	hw := "88888888-8888-8888-8888-888888888888"
	insertDevice(t, pool, tenantID, hw, 0)

	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		insertProvenanceMacOSAttempt(t, pool, tenantID, now.Add(time.Duration(i)*time.Second),
			strings.ToUpper(hw), "notion", "4.0.0", "4.1.0", "verification_failed", false)
	}

	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "notion", "4.1.0",
		0, "rolling", now.Add(-48*time.Hour))

	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)

	// The row must stay unchanged: 100% failure rate is over threshold, but
	// deduped failure_count=1 is below min_failures_to_pause=2, so this
	// outcome does not mutate the row either way (not advance-worthy, not
	// auto-pause-worthy). The dedup proof is the logged failure_count: 1, not 5.
	gotRing, gotState, pausedReason := approvalSnapshot(t, pool, approvalID)
	if gotRing != 0 || gotState != "rolling" || pausedReason != nil {
		t.Fatalf("approval = {ring:%d state:%q reason:%v}, want {ring:0 state:\"rolling\" reason:nil} UNCHANGED",
			gotRing, gotState, pausedReason)
	}

	rec := findLogForApproval(getLogs(), approvalID, "not advancing this pass")
	if rec == nil {
		t.Fatalf("no \"not advancing this pass\" log record for approval %s — expected a below-auto-pause-minimum "+
			"decision (100%% failure rate, deduped failure_count=1, min_failures_to_pause=2)", approvalID)
	}
	if fc, _ := rec["failure_count"].(float64); fc != 1 {
		t.Errorf("logged failure_count = %v, want 1 — 5 failure reports from ONE device must dedupe to a "+
			"single observation, not inflate to 5 (which would satisfy min_failures_to_pause=2 on its own)", rec["failure_count"])
	}
	if rate, _ := rec["failure_rate"].(float64); rate != 100 {
		t.Errorf("logged failure_rate = %v, want 100", rec["failure_rate"])
	}
}

// TestProcessApproval_RecordTypeAllowlist_RejectsForgedType is the test for
// the record_type ALLOWLIST fix (third review round). The previous version
// of this fix was a DENYLIST — COALESCE(record_type,'third_party_update') <>
// 'app_uninstall' — which accepted every OTHER explicit value, so a forged
// record_type like "inventory" carrying otherwise update-shaped fields
// (device.hw_uuid, app.label, app.available_version, a success outcome)
// would still count as install evidence. provenance is client-supplied JSON
// archived verbatim under a shared tenant secret (Codex's framing:
// decision-signal injection), so the guard needs to require the SPECIFIC
// expected value, not merely exclude one known-bad one.
//
// Two devices for the same tenant/label/target-version: one reports a
// legitimate "third_party_update" success, the other reports an identical
// success payload but with record_type forged to "inventory". Deduped
// observedCount must be 1 (the legitimate one only), not 2.
func TestProcessApproval_RecordTypeAllowlist_RejectsForgedType(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4, 0, 50.0, 2)
	insertAgentConfig(t, pool, tenantID)

	hwLegit := "99999999-9999-9999-9999-999999999991"
	hwForged := "99999999-9999-9999-9999-999999999992"
	insertDevice(t, pool, tenantID, hwLegit, 0)
	insertDevice(t, pool, tenantID, hwForged, 0)

	now := time.Now().UTC()
	// Legitimate: real record_type.
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hwLegit), "1password", "8.9.0", "8.10.0", "installed", true)
	// Forged: identical shape, but record_type is something other than
	// 'third_party_update' — must NOT count.
	insertProvenanceBody(t, pool, tenantID, now, map[string]any{
		"record_type": "inventory",
		"device":      map[string]any{"hw_uuid": strings.ToUpper(hwForged)},
		"outcome":     "installed",
		"app": map[string]any{
			"label":             "1password",
			"version_before":    "8.9.0",
			"version_after":     "8.10.0",
			"available_version": "8.10.0",
		},
	})

	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "1password", "8.10.0",
		0, "rolling", now.Add(-48*time.Hour))

	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)

	rec := findLogForApproval(getLogs(), approvalID, "rings: advanced")
	if rec == nil {
		t.Fatalf("no \"rings: advanced\" log record for approval %s", approvalID)
	}
	if oc, _ := rec["observed_count"].(float64); oc != 1 {
		t.Errorf("logged observed_count = %v, want 1 — the forged record_type:\"inventory\" row must not "+
			"count alongside the legitimate \"third_party_update\" one", rec["observed_count"])
	}

	gotRing, gotState, _ := approvalSnapshot(t, pool, approvalID)
	if gotRing != 1 || gotState != "rolling" {
		t.Errorf("approval = {ring:%d state:%q}, want {ring:1 state:\"rolling\"} — the one legitimate "+
			"observation should have advanced the rollout for real", gotRing, gotState)
	}
}

// TestProcessApproval_FinalRing_Completes is the P2 regression test: at the
// final ring, the real automatic action is completeApproval — state ->
// "completed", approved_ring UNCHANGED — not advanceApproval. Before PAT-1118
// re-enabled mutation, this same scenario used to log "would have advanced
// here" with a would_advance_to_ring field even at the final ring,
// misreporting what the (then disabled) code path would actually have done;
// now it must perform and log the right ONE of the two real mutations.
//
// ring_count=2 maps ring index 1 to agent value 3 (RingToAgentValue(1,2)==3
// — see assign.go), so approved_ring=3 is already the final ring for this
// config. Healthy evidence, soak elapsed, ring/platform/label/version all
// eligible — the only thing left to prove is which mutation and message fire.
func TestProcessApproval_FinalRing_Completes(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 2 /* ring_count */, 0, 50.0, 2)
	insertAgentConfig(t, pool, tenantID)

	hw := "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	insertDevice(t, pool, tenantID, hw, 3)

	now := time.Now().UTC()
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hw), "firefox", "129.0", "130.0", "installed", true)

	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "firefox", "130.0",
		3 /* already the final ring for ring_count=2 */, "rolling", now.Add(-48*time.Hour))

	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)

	gotRing, gotState, _ := approvalSnapshot(t, pool, approvalID)
	if gotRing != 3 || gotState != "completed" {
		t.Fatalf("approval = {ring:%d state:%q}, want {ring:3 state:\"completed\"} — the final ring must "+
			"complete the rollout, leaving approved_ring unchanged", gotRing, gotState)
	}

	logs := getLogs()
	if rec := findLogForApproval(logs, approvalID, "rings: completed"); rec == nil {
		t.Fatalf("no \"rings: completed\" log record for approval %s at the final ring", approvalID)
	}
	if rec := findLogForApproval(logs, approvalID, "rings: advanced"); rec != nil {
		t.Errorf("found a \"rings: advanced\" log record at the final ring: %+v — "+
			"the real action here is completeApproval, not advanceApproval", rec)
	}
}

// TestInsertNewVersion_WindowsStartsRolling reverses an earlier decision
// (TestInsertNewVersion_WindowsStartsPaused) after PAT-1002 found it did not
// hold up.
//
// The earlier reasoning was sound about the problem: Windows can never
// auto-advance, so a Windows row left "rolling" would sit at ring 0 forever,
// indistinguishable from a healthy rollout waiting out a soak. The chosen
// remedy — start the row "paused" with an explanatory paused_reason — did not
// survive its own instructions. That reason told operators to advance the
// rollout manually, and both manual paths do:
//
//	SET state = 'rolling', paused_reason = NULL
//
// (RingRolloutResumeHandler and RingRolloutSkipHandler,
// internal/handlers/ring_rollout.go). So the FIRST manual action erased the
// marker permanently, and every subsequent pass was back to the silent stall
// it was meant to prevent, with nothing left in the row to say so. A warning
// that deletes itself the moment it is acted on is worse than none: it reads
// as "handled".
//
// It also overloaded 'paused', which means "an operator stopped this", with
// "this platform cannot self-advance" — two facts with different lifetimes,
// only one of which belongs in a mutable column. The platform fact now lives
// in processApproval's Windows branch, where no operator action can clear it,
// and is restated on every pass in the log.
//
// So a newly observed Windows version starts exactly like macOS: rolling, at
// ring 0. It is not stuck-looking-healthy, because it is not silent.
func TestInsertNewVersion_WindowsStartsRolling(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant_ring_config (tenant_id, enabled) VALUES ($1::uuid, true)`, tenantID,
	); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}
	insertAgentConfig(t, pool, tenantID)

	now := time.Now().UTC()
	insertProvenanceWindows(t, pool, tenantID, now, "adobeacrobat", "24.1")

	rings.ObserveNewVersions(ctx, pool)

	var approvedRing int16
	var state string
	var pausedReason *string
	if err := pool.QueryRow(ctx,
		`SELECT approved_ring, state, paused_reason FROM ring_version_approvals
		 WHERE tenant_id = $1::uuid AND platform = 'windows' AND label = 'adobeacrobat' AND version = '24.1'`,
		tenantID,
	).Scan(&approvedRing, &state, &pausedReason); err != nil {
		t.Fatalf("query approval row: %v", err)
	}

	if state != "rolling" {
		t.Fatalf("state = %q, want \"rolling\" — a newly observed Windows version starts like any other; "+
			"the manual-only property is enforced in processApproval, not parked in a state field that the "+
			"first resume or skip clears", state)
	}
	if pausedReason != nil {
		t.Errorf("paused_reason = %q, want nil — nothing has paused this rollout", *pausedReason)
	}
	if approvedRing != 0 {
		t.Errorf("approved_ring = %d, want 0", approvedRing)
	}

	// The property that actually matters: an operator resuming or skipping
	// this row cannot switch off its manual-only handling, because that
	// handling reads a.Platform rather than any mutable column. Simulate the
	// state a manual resume/skip leaves behind and confirm the pass still
	// reports it as manual-only.
	if _, err := pool.Exec(ctx, `
		UPDATE ring_version_approvals SET state = 'rolling', paused_reason = NULL, last_advanced_at = now() - interval '48 hours'
		WHERE tenant_id = $1::uuid AND platform = 'windows'`, tenantID,
	); err != nil {
		t.Fatalf("simulate manual resume: %v", err)
	}
	var approvalID string
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM ring_version_approvals WHERE tenant_id = $1::uuid AND platform = 'windows'`, tenantID,
	).Scan(&approvalID); err != nil {
		t.Fatalf("read approval id: %v", err)
	}

	getLogs := captureLogs(t)
	rings.AdvanceAll(ctx, pool, nil)
	if rec := findLogForApproval(getLogs(), approvalID, "automatic gating skipped"); rec == nil {
		t.Errorf("after a manual resume cleared paused_reason, the Windows rollout no longer reported itself " +
			"as manual-only — this is exactly the regression the paused-state marker suffered")
	}
}

// TestRebuildRingPromotions_NoOp_LeavesConfigVersionUnchanged is the PAT-1003
// regression test for the no-op half of the fix. rebuildRingPromotions runs
// on every AdvanceAll pass (the scheduler calls this every ~5 min per
// tenant) and used to unconditionally bump agent_config.config_version and
// issued_at, even when the computed ring_promotions content was identical to
// what was already stored — a "something changed" signal firing on every
// tick regardless of whether anything had.
//
// Two consecutive AdvanceAll passes with no change to the underlying
// ring_version_approvals data between them must leave config_version,
// issued_at, and the stored ring_promotions content exactly as the first
// pass left them.
func TestRebuildRingPromotions_NoOp_LeavesConfigVersionUnchanged(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4, 0, 50.0, 2)
	insertAgentConfig(t, pool, tenantID)

	now := time.Now().UTC()
	insertApprovalRow(t, pool, tenantID, "macos", "firefox", "130.0",
		1, "rolling", now.Add(-48*time.Hour))

	// First pass: agent_config has no ring_promotions key yet, so this is a
	// genuine change and must bump config_version.
	rings.AdvanceAll(ctx, pool, nil)
	firstVersion, firstIssuedAt, firstPromotions := agentConfigSnapshot(t, pool, tenantID)
	if firstVersion != 2 {
		t.Fatalf("config_version = %d after the first AdvanceAll pass, want 2 — the initial publish of "+
			"ring_promotions (agent_config starts with no ring_promotions key at all) must still bump it",
			firstVersion)
	}

	// Second pass: nothing about the underlying approval row changed.
	rings.AdvanceAll(ctx, pool, nil)
	secondVersion, secondIssuedAt, secondPromotions := agentConfigSnapshot(t, pool, tenantID)

	if secondVersion != firstVersion {
		t.Errorf("config_version changed from %d to %d across a no-op tick — rebuildRingPromotions must "+
			"not bump config_version when the computed ring_promotions content is unchanged", firstVersion, secondVersion)
	}
	if !secondIssuedAt.Equal(firstIssuedAt) {
		t.Errorf("issued_at changed from %v to %v across a no-op tick", firstIssuedAt, secondIssuedAt)
	}
	if string(secondPromotions) != string(firstPromotions) {
		t.Errorf("stored ring_promotions changed across a no-op tick: %s -> %s", firstPromotions, secondPromotions)
	}
}

// TestRebuildRingPromotions_RealChange_BumpsConfigVersion is the other half
// of the PAT-1003 regression, and per the ticket the one a careless fix (e.g.
// comparing the wrong column, or a WHERE clause that's always false) would
// silently break: a real change to the computed ring_promotions map must
// still bump agent_config.config_version on the next tick, or agents never
// learn about it.
//
// The mutation used here — directly UPDATEing approved_ring on a
// ring_version_approvals row — is deliberately the real shape a manual SKIP
// or EMERGENCY-DEPLOY produces (ring_rollout.go's admin handlers write
// approved_ring directly; see AutoAdvanceDisabledReason's doc comment in
// advance.go). No device is seeded for this approval row, so
// AdvanceAll/processApproval's own automatic mutation never fires here
// (eligibleDevices stays 0 — see the "no devices are assigned" branch); the
// manual UPDATE below is deliberately the only thing that changes
// approved_ring in this test, isolating rebuildRingPromotions' reaction to a
// change from whatever caused it. (Automatic advancement mutating
// approved_ring for real, now that PAT-1118 has turned it on, is covered by
// the TestProcessApproval_* tests above; this test only needs A change to
// happen, not to prove which code path can cause one.)
func TestRebuildRingPromotions_RealChange_BumpsConfigVersion(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4, 0, 50.0, 2)
	insertAgentConfig(t, pool, tenantID)

	now := time.Now().UTC()
	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "firefox", "130.0",
		1, "rolling", now.Add(-48*time.Hour))

	rings.AdvanceAll(ctx, pool, nil)
	firstVersion, firstIssuedAt, firstPromotions := agentConfigSnapshot(t, pool, tenantID)

	// Simulate a manual SKIP: directly update approved_ring on the approval
	// row, exactly as ring_rollout.go's admin handlers do.
	if _, err := pool.Exec(ctx,
		`UPDATE ring_version_approvals SET approved_ring = 2 WHERE id = $1::uuid`, approvalID,
	); err != nil {
		t.Fatalf("simulate manual skip: %v", err)
	}

	rings.AdvanceAll(ctx, pool, nil)
	secondVersion, secondIssuedAt, secondPromotions := agentConfigSnapshot(t, pool, tenantID)

	if secondVersion != firstVersion+1 {
		t.Fatalf("config_version = %d after a real ring_promotions change (manual skip: approved_ring 1 -> 2), "+
			"want %d — a real change must still bump config_version on the next tick, or manual "+
			"pause/resume/skip would stop reaching agents", secondVersion, firstVersion+1)
	}
	if secondIssuedAt.Equal(firstIssuedAt) {
		t.Errorf("issued_at did not change despite a real ring_promotions change")
	}
	if string(secondPromotions) == string(firstPromotions) {
		t.Errorf("stored ring_promotions unchanged despite approved_ring changing from 1 to 2: %s", secondPromotions)
	}
}

// PAT-1134: derive the agent fixtures from the publisher itself. A label-only
// max-ring reduction used to let macOS and Windows overwrite each other and
// let an old completed version override a current decision. The distinct
// versions here are deliberate: legacy agents use only the label and
// approved_ring, so the lowest platform ring must remain published even when
// its informational version belongs to the other platform.
func TestPublishRingPromotions_ScopesPlatformsAndKeepsLegacyFailClosedOnVersionCollision(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()
	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	insertAgentConfig(t, pool, tenantID)
	now := time.Now().UTC()
	insertApprovalRow(t, pool, tenantID, "macos", "firefox", "130.0", 1, "rolling", now)
	insertApprovalRow(t, pool, tenantID, "windows", "firefox", "129.0", 0, "rolling", now)
	insertApprovalRow(t, pool, tenantID, "macos", "googlechrome", "124.0", 3, "completed", now)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := rings.PublishRingPromotionsTx(ctx, tx, tenantID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT body FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var body struct {
		Legacy map[string]struct {
			Version      string `json:"version"`
			ApprovedRing int    `json:"approved_ring"`
		} `json:"ring_promotions"`
		Scoped map[string]map[string]struct {
			Approval     string `json:"approval"`
			ApprovedRing *int   `json:"approved_ring"`
			Version      string `json:"version"`
		} `json:"ring_promotions_scoped"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	if got := *body.Scoped["macos"]["firefox"].ApprovedRing; got != 1 {
		t.Errorf("macOS ring=%d, want 1", got)
	}
	if got := *body.Scoped["windows"]["firefox"].ApprovedRing; got != 0 {
		t.Errorf("Windows ring=%d, want 0", got)
	}
	if got := body.Scoped["macos"]["firefox"].Version; got != "130.0" {
		t.Errorf("macOS version=%q, want 130.0", got)
	}
	if got := body.Scoped["windows"]["firefox"].Version; got != "129.0" {
		t.Errorf("Windows version=%q, want 129.0", got)
	}
	if got := body.Legacy["firefox"].ApprovedRing; got != 0 {
		t.Errorf("legacy conservative ring=%d, want 0; its label-only gate must deny both active versions outside ring 0", got)
	}
	if got := body.Legacy["firefox"].Version; got != "129.0" {
		t.Errorf("legacy informational version=%q, want the lowest-ring platform version 129.0", got)
	}
	if _, ok := body.Scoped["macos"]["googlechrome"]; ok {
		t.Error("completed rollout leaked into scoped gate")
	}
}

func TestPublishRingPromotions_FirstRingPauseIsExplicitNobody(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()
	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	insertAgentConfig(t, pool, tenantID)
	insertApprovalRow(t, pool, tenantID, "macos", "firefox", "130.0", 0, "paused", time.Now().UTC())
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := rings.PublishRingPromotionsTx(ctx, tx, tenantID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT body->'ring_promotions_scoped' FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var scoped map[string]map[string]map[string]any
	if err := json.Unmarshal(raw, &scoped); err != nil {
		t.Fatal(err)
	}
	if got := scoped["macos"]["firefox"]["approval"]; got != "nobody" {
		t.Errorf("approval=%v, want nobody", got)
	}
}

// scopedPromotionEntry mirrors the platform-aware wire shape current agents
// consume. A paused rollout must use approval="nobody" rather than relying on
// a numeric ring rollback: that is the only representation that denies a
// paused first-ring rollout as well as later-ring rollouts.
type scopedPromotionEntry struct {
	Approval     string `json:"approval"`
	ApprovedRing *int   `json:"approved_ring"`
	Version      string `json:"version"`
}

// TestRebuildRingPromotions_AutoPause_WithdrawsExposureFromFailingRing is the
// P1 regression test from independent review: an auto-pause must actually
// stop agents at the failing ring from being told they're approved to
// install the failing version, not just flip ring_version_approvals.state
// and log "auto-paused" while the scoped projection keeps publishing an
// approval.
//
// Two ring-1 devices report a 100% failure rate for the target version —
// well over threshold and min_failures_to_pause — so AdvanceAll must
// auto-pause the row. ring_count=4 gives this tenant configured rings
// [0,1,2,3]. The scoped contract must deny the entry outright, regardless of
// which ring failed. A numeric legacy fallback alone is insufficient because
// it cannot deny ring 0.
//
// The assertion that matters is NOT the approval row (covered by
// TestProcessApproval_RealMacOSFailures_AutoPauses) — it's what
// agent_config.body->'ring_promotions_scoped' actually contains afterward:
// a ring-1 device must see approval:"nobody", so it holds back on its next
// poll instead of carrying on with the version that just failed.
func TestRebuildRingPromotions_AutoPause_WithdrawsExposureFromFailingRing(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4 /* ring_count: configured rings 0,1,2,3 */, 0, 10.0 /* threshold pct */, 1 /* min_failures */)
	insertAgentConfig(t, pool, tenantID)

	hw1 := "dddddddd-dddd-dddd-dddd-ddddddddddd1"
	hw2 := "dddddddd-dddd-dddd-dddd-ddddddddddd2"
	insertDevice(t, pool, tenantID, hw1, 1 /* ring 1 — the ring about to fail */)
	insertDevice(t, pool, tenantID, hw2, 1)

	now := time.Now().UTC()
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hw1), "notion", "4.0.0", "4.1.0", "verification_failed", false)
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hw2), "notion", "4.0.0", "4.1.0", "verification_failed", false)

	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "notion", "4.1.0",
		1 /* approved_ring: already exposed to ring 1 */, "rolling", now.Add(-48*time.Hour))

	rings.AdvanceAll(ctx, pool, nil)

	// Sanity check: the approval row itself auto-paused (already covered in
	// depth by TestProcessApproval_RealMacOSFailures_AutoPauses; asserted
	// here too so a failure here points at the right layer).
	gotRing, gotState, pausedReason := approvalSnapshot(t, pool, approvalID)
	if gotState != "paused" || pausedReason == nil {
		t.Fatalf("approval row = {ring:%d state:%q reason:%v}, want state \"paused\" with a reason — "+
			"the failure rate should have triggered auto-pause before ring_promotions can be tested at all",
			gotRing, gotState, pausedReason)
	}
	// approved_ring (the source of truth for resume/skip) must NOT be
	// touched by publication.
	if gotRing != 1 {
		t.Errorf("approved_ring = %d, want 1 UNCHANGED — a later resume must re-evaluate from the ring the rollout reached", gotRing)
	}

	var rawScopedPromotions []byte
	if err := pool.QueryRow(ctx, `SELECT body->'ring_promotions_scoped' FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&rawScopedPromotions); err != nil {
		t.Fatalf("read scoped ring_promotions: %v", err)
	}
	var promotions map[string]map[string]scopedPromotionEntry
	if err := json.Unmarshal(rawScopedPromotions, &promotions); err != nil {
		t.Fatalf("decode scoped ring_promotions: %v (raw: %s)", err, rawScopedPromotions)
	}
	entry, ok := promotions["macos"]["notion"]
	if !ok {
		t.Fatalf("scoped ring_promotions has no macOS entry for notion: %s", rawScopedPromotions)
	}
	if entry.Approval != "nobody" {
		t.Fatalf("scoped ring_promotions[macos][notion].approval = %q, want nobody — a paused rollout must withdraw approval from every ring", entry.Approval)
	}
	if entry.ApprovedRing != nil {
		t.Errorf("scoped nobody entry has approved_ring=%d, want omitted", *entry.ApprovedRing)
	}
	if entry.Version != "4.1.0" {
		t.Errorf("published ring_promotions[\"notion\"].version = %q, want \"4.1.0\" — the version itself is "+
			"still named (an agent below the rolled-back ring may still be catching up to it); only the ring "+
			"it's approved for is withdrawn", entry.Version)
	}
}

// TestRebuildRingPromotions_PausedAtFirstRing_PublishesExplicitNobody proves
// PAT-1134 closes the old legacy-only gap. Ring 0 has no lower numeric value,
// but an automatic pause there must still deny every current agent.
func TestRebuildRingPromotions_PausedAtFirstRing_PublishesExplicitNobody(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4, 0, 10.0, 1)
	insertAgentConfig(t, pool, tenantID)

	hw := "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
	insertDevice(t, pool, tenantID, hw, 0 /* ring 0: the tenant's first configured ring */)

	now := time.Now().UTC()
	insertProvenanceMacOSAttempt(t, pool, tenantID, now, strings.ToUpper(hw), "adobeacrobat", "1.0.0", "1.1.0", "verification_failed", false)

	approvalID := insertApprovalRow(t, pool, tenantID, "macos", "adobeacrobat", "1.1.0",
		0, "rolling", now.Add(-48*time.Hour))

	rings.AdvanceAll(ctx, pool, nil)

	gotRing, gotState, pausedReason := approvalSnapshot(t, pool, approvalID)
	if gotState != "paused" || pausedReason == nil {
		t.Fatalf("approval row = {ring:%d state:%q reason:%v}, want state \"paused\" with a reason", gotRing, gotState, pausedReason)
	}

	var rawScopedPromotions []byte
	if err := pool.QueryRow(ctx, `SELECT body->'ring_promotions_scoped' FROM agent_config WHERE tenant_id = $1::uuid`, tenantID).Scan(&rawScopedPromotions); err != nil {
		t.Fatalf("read scoped ring_promotions: %v", err)
	}
	var promotions map[string]map[string]scopedPromotionEntry
	if err := json.Unmarshal(rawScopedPromotions, &promotions); err != nil {
		t.Fatalf("decode scoped ring_promotions: %v (raw: %s)", err, rawScopedPromotions)
	}
	entry, ok := promotions["macos"]["adobeacrobat"]
	if !ok {
		t.Fatalf("scoped ring_promotions has no macOS entry for adobeacrobat: %s", rawScopedPromotions)
	}
	if entry.Approval != "nobody" {
		t.Errorf("scoped first-ring pause approval = %q, want nobody", entry.Approval)
	}
	if entry.ApprovedRing != nil {
		t.Errorf("scoped first-ring pause approved_ring = %d, want omitted", *entry.ApprovedRing)
	}
}

// TestQueryFailureRate_NoObservations_ReturnsSentinel is the PAT-1002
// second-review-round regression test for finding 2.
//
// queryFailureRate used to return (rate=0, observedCount=0, err=nil) for an
// empty sample and document, in a comment, that callers MUST check
// observedCount before reading rate. A comment cannot enforce anything: 0.0 is
// also what a genuinely healthy all-succeeded sample returns, so a caller that
// skipped the check read "we have no data" as "0% failures, ship it" — the
// fail-open reading defect 11 exists to prevent, one refactor away at all
// times.
//
// It now returns ErrNoObservations. This asserts the sentinel directly rather
// than through processApproval's log line, because the point of the change is
// the FUNCTION's contract: a future second caller must be unable to get a rate
// out of it without a sample existing.
func TestQueryFailureRate_NoObservations_ReturnsSentinel(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4, 0, 50.0, 2)

	// Two eligible ring-0 devices exist; neither has reported anything.
	insertDevice(t, pool, tenantID, "9a9a9a9a-9a9a-9a9a-9a9a-9a9a9a9a9a01", 0)
	insertDevice(t, pool, tenantID, "9a9a9a9a-9a9a-9a9a-9a9a-9a9a9a9a9a02", 0)

	since := time.Now().UTC().Add(-48 * time.Hour)

	rate, failCount, observed, eligible, err := rings.QueryFailureRateForTest(
		ctx, pool, tenantID, "macos", "firefox", "130.0", 0, since)
	if !errors.Is(err, rings.ErrNoObservations) {
		t.Fatalf("err = %v, want ErrNoObservations — an empty sample must not be reported as a successful "+
			"query returning a 0%% failure rate", err)
	}
	if observed != 0 || failCount != 0 || rate != 0 {
		t.Errorf("got rate=%v failCount=%d observed=%d, want all zero alongside the sentinel", rate, failCount, observed)
	}
	// eligibleDevices is still populated with the sentinel: processApproval
	// needs it to tell "nobody has reported yet" (this case) from "no device is
	// assigned to this ring at all".
	if eligible != 2 {
		t.Errorf("eligibleDevices = %d, want 2 — the count must survive the no-observations return, or the "+
			"transient and permanent zero-sample causes become indistinguishable again", eligible)
	}

	// And the sentinel is specific to an EMPTY sample, not to "no failures":
	// one successful install is a real sample with a real 0% rate, and must
	// come back as a nil error so the caller can act on it.
	insertProvenanceMacOSAttempt(t, pool, tenantID, time.Now().UTC(),
		"9a9a9a9a-9a9a-9a9a-9a9a-9a9a9a9a9a01", "firefox", "129.0", "130.0", "installed", true)

	rate, failCount, observed, eligible, err = rings.QueryFailureRateForTest(
		ctx, pool, tenantID, "macos", "firefox", "130.0", 0, since)
	if err != nil {
		t.Fatalf("err = %v, want nil — one successful observation IS a sample", err)
	}
	if rate != 0 || failCount != 0 || observed != 1 || eligible != 2 {
		t.Errorf("got rate=%v failCount=%d observed=%d eligible=%d, want rate=0 failCount=0 observed=1 eligible=2",
			rate, failCount, observed, eligible)
	}
}

// TestSchedulerTick_CreatesAndAdvancesApprovalRow is the PAT-1118
// end-to-end regression test: it exercises rings.ObserveNewVersions and
// rings.AdvanceAll back to back, in the same order and on the same pool as
// the extractor's ring-advancement pass now calls them
// (internal/extractor/extractor.go), rather than each in isolation as the
// rest of this file does. Patching rings had produced zero
// ring_version_approvals rows in production for 39 days (PAT-997 disabled
// ObserveNewVersions' scheduler call; PAT-1002 designed correct gating but
// deliberately left mutation off) — this is the test that would have caught
// either half of that regression reappearing: a scheduler tick must both
// create a row from new provenance evidence AND be able to move that same
// row on a later tick once fresh evidence arrives.
//
// Two ticks, mirroring two real extractor loop iterations:
//
//  1. First tick: a device has successfully installed a version nobody has
//     approved yet. ObserveNewVersions must create the ring_version_approvals
//     row (ring 0, "rolling"). AdvanceAll runs immediately after in the same
//     tick (as extractor.go does), but the row's last_advanced_at is set to
//     "now" by the INSERT itself, so the very evidence that created the row
//     is not "fresh" relative to it — nothing should move yet.
//  2. Second tick: a fresh, later install report from the same ring-0 device
//     arrives. AdvanceAll must recognize it as advance-worthy and actually
//     move approved_ring, not just log that it would.
func TestSchedulerTick_CreatesAndAdvancesApprovalRow(t *testing.T) {
	pool := dbPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants DEFAULT VALUES RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	setupTenantRingConfig(t, pool, tenantID, 4 /* ring_count */, 0 /* soak_gap_hours */, 50.0 /* generous threshold */, 2)
	insertAgentConfig(t, pool, tenantID)

	hw := "cdcdcdcd-cdcd-cdcd-cdcd-cdcdcdcdcdcd"
	insertDeviceOS(t, pool, tenantID, hw, 0 /* ring 0 */, "macOS")

	// A version nobody has approved yet, successfully installed. adobeacrobat
	// is deliberately not in immediateLabels (advance.go) — an immediate-label
	// version would be approved straight to ring 3/"completed" on creation,
	// which is not what this test is proving.
	insertProvenance(t, pool, tenantID, time.Now().UTC(), "macos", "adobeacrobat", "24.1")

	// --- Tick 1: create, but do not yet advance. ---
	rings.ObserveNewVersions(ctx, pool)

	var approvalID string
	var gotRing int16
	var gotState string
	if err := pool.QueryRow(ctx, `
		SELECT id::text, approved_ring, state FROM ring_version_approvals
		WHERE tenant_id = $1::uuid AND platform = 'macos' AND label = 'adobeacrobat' AND version = '24.1'
	`, tenantID).Scan(&approvalID, &gotRing, &gotState); err != nil {
		t.Fatalf("ObserveNewVersions did not create a ring_version_approvals row: %v — a scheduler tick "+
			"must be able to create one from new provenance evidence", err)
	}
	if gotRing != 0 || gotState != "rolling" {
		t.Fatalf("newly created approval = {ring:%d state:%q}, want {ring:0 state:\"rolling\"}", gotRing, gotState)
	}

	rings.AdvanceAll(ctx, pool, nil)

	gotRing, gotState, _ = approvalSnapshot(t, pool, approvalID)
	if gotRing != 0 || gotState != "rolling" {
		t.Fatalf("approval = {ring:%d state:%q} after tick 1's AdvanceAll, want {ring:0 state:\"rolling\"} "+
			"UNCHANGED — the evidence that created the row is not fresh relative to its own creation time",
			gotRing, gotState)
	}

	// --- Tick 2: fresh evidence arrives; the row actually advances. ---
	insertProvenanceMacOSAttempt(t, pool, tenantID, time.Now().UTC(), strings.ToUpper(hw),
		"adobeacrobat", "24.0", "24.1", "installed", true)

	getLogs := captureLogs(t)
	rings.ObserveNewVersions(ctx, pool)
	rings.AdvanceAll(ctx, pool, nil)

	gotRing, gotState, _ = approvalSnapshot(t, pool, approvalID)
	if gotRing != 1 || gotState != "rolling" {
		t.Fatalf("approval = {ring:%d state:%q} after tick 2, want {ring:1 state:\"rolling\"} — fresh "+
			"install evidence from an eligible ring-0 device must actually advance the rollout, not just "+
			"log that it would", gotRing, gotState)
	}
	if rec := findLogForApproval(getLogs(), approvalID, "rings: advanced"); rec == nil {
		t.Fatalf("no \"rings: advanced\" log record for approval %s on tick 2", approvalID)
	}
}
