package report

// PAT-709 regression: devices enrolled via POST /v1/enrol carry os = NULL
// until their first inventory payload is extracted (migration 0039 made
// devices.os nullable). Fetch's device SELECT must tolerate that NULL —
// before the COALESCE fix every posture poll in the enrol-to-first-inventory
// window failed with "cannot scan NULL into *string" and surfaced as a 500.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as internal/auth/bearer_db_test.go. The pool's search_path is
// pinned to an isolated schema so no real data is touched.
//
// PAT-1007 extended this harness with provenance_records (see
// migrations/0011_provenance.sql) rather than standing up a second one —
// fetchProvenancePatchHistory's query needs nothing beyond what's already
// here (tenants for the FK, devices for hw_uuid).

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const pat709Schema = "pat709_test"

func pat709Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed report test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat709Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat709Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat709Schema,
		`CREATE TABLE ` + pat709Schema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		// Only the columns Fetch's device SELECT reads; os is nullable as of
		// migration 0039.
		`CREATE TABLE ` + pat709Schema + `.devices (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id          UUID NOT NULL REFERENCES ` + pat709Schema + `.tenants(id),
			serial             TEXT,
			hw_uuid            UUID,
			hostname           TEXT,
			computer_name      TEXT,
			hw_model           TEXT,
			arch               TEXT,
			os                 TEXT,
			os_version         TEXT,
			os_build           TEXT,
			agent_version      TEXT,
			first_seen         TIMESTAMPTZ NOT NULL DEFAULT now(),
			last_seen          TIMESTAMPTZ NOT NULL DEFAULT now(),
			pending_updates    JSONB,
			hardware           JSONB,
			security_inventory JSONB,
			backup_status      JSONB,
			device_class       TEXT NOT NULL DEFAULT 'unknown'
			                   CHECK (device_class IN ('workstation','server','domain_controller','unknown'))
		)`,
		`CREATE TABLE ` + pat709Schema + `.compliance_rules (
			id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key                  TEXT NOT NULL,
			title                     TEXT NOT NULL,
			description               TEXT,
			benchmark                 TEXT NOT NULL DEFAULT '',
			benchmark_version         TEXT NOT NULL DEFAULT '',
			severity                  TEXT NOT NULL DEFAULT 'low',
			nist_mappings             TEXT[],
			iso_mappings              TEXT[],
			cyber_essentials_mappings TEXT[],
			platform                  TEXT NOT NULL DEFAULT 'macos',
			enabled                   BOOLEAN NOT NULL DEFAULT true,
			device_class              TEXT[]
		)`,
		`CREATE TABLE ` + pat709Schema + `.compliance_evaluations (
			device_id      UUID NOT NULL,
			rule_id        UUID NOT NULL,
			status         TEXT NOT NULL,
			observed_value TEXT,
			severity       TEXT NOT NULL DEFAULT 'low',
			evaluated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat709Schema + `.patches (
			device_id    UUID NOT NULL,
			title        TEXT,
			identifier   TEXT,
			installed_at TIMESTAMPTZ,
			observed_at  TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		`CREATE TABLE ` + pat709Schema + `.device_apps (
			device_id    UUID NOT NULL,
			name         TEXT,
			version      TEXT,
			identifier   TEXT NOT NULL,
			identifier_kind TEXT,
			signer       TEXT,
			team_id      TEXT,
			architecture TEXT,
			notarized    BOOLEAN,
			last_seen    TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
		// PAT-1007: matches migrations/0011_provenance.sql. No FK to devices —
		// fetchProvenancePatchHistory matches on body->'device'->>'hw_uuid'
		// text, the same way advance.go's queryFailureRate does.
		`CREATE TABLE ` + pat709Schema + `.provenance_records (
			id          BIGSERIAL PRIMARY KEY,
			tenant_id   UUID NOT NULL REFERENCES ` + pat709Schema + `.tenants(id),
			received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
			body        JSONB NOT NULL
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat709Schema+` CASCADE`)
	})
	return pool
}

// TestFetchNullOSDevice covers the enrol-to-first-inventory window: a device
// row exists (enrolment created it) but no inventory has populated os yet.
func TestFetchNullOSDevice(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-709 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, os, os_version)
		VALUES ($1::uuid, 'PAT709SERIAL', NULL, NULL)
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch on NULL-os device: %v", err)
	}
	if rep.Device.OS != "" {
		t.Errorf("Device.OS = %q, want empty string for NULL os", rep.Device.OS)
	}
	if rep.Device.Serial != "PAT709SERIAL" {
		t.Errorf("Device.Serial = %q, want PAT709SERIAL", rep.Device.Serial)
	}
	if rep.Tenant != "PAT-709 Test Tenant" {
		t.Errorf("Tenant = %q, want PAT-709 Test Tenant", rep.Tenant)
	}
}

func TestFetchPropagatesAppIdentifierKind(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `INSERT INTO tenants (name) VALUES ('PAT-1481 Identifier Kind Tenant') RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	var deviceID string
	if err := pool.QueryRow(ctx, `INSERT INTO devices (tenant_id, serial) VALUES ($1::uuid, 'PAT1481IDENTIFIERKIND') RETURNING id::text`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, version, identifier, identifier_kind)
		VALUES ($1::uuid, 'Example Package', '1.0', 'Example.Package', 'winget')
	`, deviceID); err != nil {
		t.Fatalf("insert device app: %v", err)
	}

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(rep.Apps) != 1 {
		t.Fatalf("Apps: want 1, got %+v", rep.Apps)
	}
	if rep.Apps[0].IdentifierKind != "winget" {
		t.Errorf("Apps[0].IdentifierKind = %q, want winget", rep.Apps[0].IdentifierKind)
	}
}

// TestFetchUsesEffectiveSeverityFromEvaluation is a PAT-744 regression test.
// compliance_evaluations.severity is written at evaluation time as
// COALESCE(tr.override_severity, cr.severity) — the EFFECTIVE, tenant-aware
// severity — while compliance_rules.severity is always the GLOBAL severity.
// Fetch's evaluation query must surface the former (matching what the
// findings endpoint returns), not silently fall back to the latter via its
// join to compliance_rules.
func TestFetchUsesEffectiveSeverityFromEvaluation(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-744 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, os, os_version)
		VALUES ($1::uuid, 'PAT744SERIAL', 'macOS', '15.0')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	// The rule's GLOBAL severity is "low"...
	var ruleID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, severity)
		VALUES ('pat744_test_rule', 'PAT-744 Test Rule', 'low')
		RETURNING id::text
	`).Scan(&ruleID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	// ...but this tenant has an override_severity of "critical" on that rule.
	// The evaluator writes the EFFECTIVE severity onto the evaluation row —
	// simulated directly here since this schema doesn't model tenant_rules.
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, severity)
		VALUES ($1::uuid, $2::uuid, 'fail', 'critical')
	`, deviceID, ruleID); err != nil {
		t.Fatalf("insert evaluation: %v", err)
	}

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(rep.Evaluations) != 1 {
		t.Fatalf("len(Evaluations) = %d, want 1", len(rep.Evaluations))
	}
	if got, want := rep.Evaluations[0].Severity, "critical"; got != want {
		t.Errorf("Evaluations[0].Severity = %q, want %q (the effective/override severity from compliance_evaluations, not the rule's global severity %q)", got, want, "low")
	}
	if rep.Evaluations[0].RuleKey != "pat744_test_rule" {
		t.Errorf("Evaluations[0].RuleKey = %q, want pat744_test_rule", rep.Evaluations[0].RuleKey)
	}
}

// insertPat1007Provenance writes a provenance_records row in the real macOS
// emitter shape: label/available_version nested under a top-level "app"
// object, device.hw_uuid for the device join, and a top-level "outcome" —
// mirroring insertProvenanceMacOSAttempt in internal/rings/advance_db_test.go.
func insertPat1007Provenance(t *testing.T, pool *pgxpool.Pool, tenantID string, receivedAt time.Time, body map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal provenance body: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO provenance_records (tenant_id, received_at, body) VALUES ($1::uuid, $2, $3::jsonb)`,
		tenantID, receivedAt, raw,
	); err != nil {
		t.Fatalf("insert provenance: %v", err)
	}
}

// TestFetch_ProvenanceOutcomeAndFailureReason is the core PAT-1007
// acceptance criterion: a provenance row for this device with a failure
// outcome and a failure_reason must surface as a PatchHistoryItem carrying
// both fields — a failed patch stops being invisible. It must land on
// rep.ProvenancePatchHistory, NOT rep.PatchHistory: the latter feeds the
// PDF's OS-update-only "macOS Update History" section (see
// Report.ProvenancePatchHistory's doc comment), so a failed third-party
// install must never appear there.
func TestFetch_ProvenanceOutcomeAndFailureReason(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-1007 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	hwUUID := "9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A"
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, os, os_version)
		VALUES ($1::uuid, 'PAT1007SERIAL', $2::uuid, 'macOS', '15.5')
		RETURNING id::text
	`, tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	insertPat1007Provenance(t, pool, tenantID, time.Now().UTC(), map[string]any{
		"record_type":    "third_party_update",
		"device":         map[string]any{"hw_uuid": hwUUID},
		"outcome":        "verification_failed",
		"failure_reason": "checksum mismatch",
		"app": map[string]any{
			"label":             "1password",
			"available_version": "8.10.0",
		},
	})

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(rep.PatchHistory) != 0 {
		t.Errorf("PatchHistory = %+v, want empty — no OS patches were inserted, and a provenance row "+
			"must never land here (it would leak into the PDF's OS-update section)", rep.PatchHistory)
	}
	if len(rep.ProvenancePatchHistory) != 1 {
		t.Fatalf("len(ProvenancePatchHistory) = %d, want 1: %+v", len(rep.ProvenancePatchHistory), rep.ProvenancePatchHistory)
	}
	got := rep.ProvenancePatchHistory[0]
	if got.Title != "1password" {
		t.Errorf("Title = %q, want %q", got.Title, "1password")
	}
	if got.Identifier != "1password|8.10.0" {
		t.Errorf("Identifier = %q, want %q", got.Identifier, "1password|8.10.0")
	}
	if got.Outcome != "verification_failed" {
		t.Errorf("Outcome = %q, want %q", got.Outcome, "verification_failed")
	}
	if got.FailureReason != "checksum mismatch" {
		t.Errorf("FailureReason = %q, want %q", got.FailureReason, "checksum mismatch")
	}
}

// TestFetch_ProvenanceFieldsTruncatedAtFiveHundredChars is the P1 fix for
// unbounded response size: LIMIT 200 in fetchProvenancePatchHistory's query
// bounds row COUNT, not row SIZE. label/available_version/outcome/
// failure_reason are ALL client-supplied text straight from
// provenance_records.body (JSON POSTed under a shared tenant secret,
// accepted up to POST /v1/provenance's maxBodyBytes cap) — an oversized
// value in any of the four must be TRUNCATED at the SQL layer, not merely
// tolerated, or 200 rows of megabyte-scale text could blow up a single
// device-detail response. outcome/state is exactly as client-controlled as
// the other three (read from the same untrusted JSONB, not a DB-enforced
// enum), so this covers it too — a second-round review finding after the
// first round only capped label/available_version/failure_reason.
func TestFetch_ProvenanceFieldsTruncatedAtFiveHundredChars(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-1007 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	hwUUID := "9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A"
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, os, os_version)
		VALUES ($1::uuid, 'PAT1007SERIAL5', $2::uuid, 'macOS', '15.5')
		RETURNING id::text
	`, tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	oversizedReason := strings.Repeat("x", 10000)
	oversizedLabel := strings.Repeat("y", 10000)
	oversizedVersion := strings.Repeat("9", 10000)
	oversizedOutcome := strings.Repeat("z", 10000)
	insertPat1007Provenance(t, pool, tenantID, time.Now().UTC(), map[string]any{
		"record_type":    "third_party_update",
		"device":         map[string]any{"hw_uuid": hwUUID},
		"outcome":        oversizedOutcome,
		"failure_reason": oversizedReason,
		"app": map[string]any{
			"label":             oversizedLabel,
			"available_version": oversizedVersion,
		},
	})

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(rep.ProvenancePatchHistory) != 1 {
		t.Fatalf("len(ProvenancePatchHistory) = %d, want 1", len(rep.ProvenancePatchHistory))
	}
	got := rep.ProvenancePatchHistory[0]

	// Title is the truncated label; Identifier is "<truncated label>|<truncated version>".
	if len(got.Title) != 500 {
		t.Errorf("Title length = %d, want 500 (truncated, not merely present)", len(got.Title))
	}
	if len(got.Outcome) != 500 {
		t.Errorf("Outcome length = %d, want 500 (truncated, not merely present)", len(got.Outcome))
	}
	if len(got.FailureReason) != 500 {
		t.Errorf("FailureReason length = %d, want 500 (truncated, not merely present)", len(got.FailureReason))
	}
	// Identifier = label + "|" + version, so it should be exactly 500+1+500.
	if len(got.Identifier) != 1001 {
		t.Errorf("Identifier length = %d, want 1001 (500-char label + '|' + 500-char version)", len(got.Identifier))
	}
}

// TestFetch_ProvenanceSortsByEventTimeNotReceiptTime is the fix for a
// real ordering bug: the updater agent can queue events locally and post
// them in a batch later (offline device, retry/backoff), so a stale queued
// event can land in provenance_records with a LATER received_at than a
// genuinely more recent event that was posted immediately. Sorting by
// received_at would then surface the OLD event as "current" — e.g. a stale
// queued FAILURE outranking a newer SUCCESS, showing a device that's
// actually fine as "currently failing".
//
// This seeds two provenance rows whose received_at order is the OPPOSITE of
// their own event-time order (recorded_at) and asserts the result sorts by
// the EVENT time, not receipt time: a newer event (by recorded_at) that was
// received EARLIER must still come first.
func TestFetch_ProvenanceSortsByEventTimeNotReceiptTime(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-1007 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	hwUUID := "9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A"
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, os, os_version)
		VALUES ($1::uuid, 'PAT1007SERIAL6', $2::uuid, 'macOS', '15.5')
		RETURNING id::text
	`, tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	now := time.Now().UTC()

	// The STALE failure: its own event time (recorded_at) is OLDER, but it
	// was queued on the agent and posted late, so its received_at is NEWER
	// than the success below. If ordering used received_at, this would sort
	// FIRST (wrongly appearing as the current state).
	insertPat1007Provenance(t, pool, tenantID, now, map[string]any{ // received_at = now (newest receipt)
		"record_type": "third_party_update",
		"device":      map[string]any{"hw_uuid": hwUUID},
		"outcome":     "verification_failed",
		"recorded_at": now.Add(-24 * time.Hour).Format("2006-01-02T15:04:05Z"), // event time = 24h ago (oldest event)
		"app": map[string]any{
			"label":             "1password",
			"available_version": "8.9.0",
		},
	})
	// The GENUINE latest state: a success that actually happened more
	// recently (by event time) but reached the server first (received
	// earlier) — the opposite ordering from the row above.
	insertPat1007Provenance(t, pool, tenantID, now.Add(-1*time.Hour), map[string]any{ // received_at = 1h ago
		"record_type": "third_party_update",
		"device":      map[string]any{"hw_uuid": hwUUID},
		"outcome":     "installed",
		"recorded_at": now.Format("2006-01-02T15:04:05Z"), // event time = now (newest event)
		"app": map[string]any{
			"label":             "1password",
			"available_version": "8.10.0",
		},
	})

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(rep.ProvenancePatchHistory) != 2 {
		t.Fatalf("len(ProvenancePatchHistory) = %d, want 2: %+v", len(rep.ProvenancePatchHistory), rep.ProvenancePatchHistory)
	}

	// Must sort by event time (recorded_at): the "installed" 8.10.0 row
	// (event time = now) must come BEFORE the "verification_failed" 8.9.0
	// row (event time = 24h ago), even though the failed row was RECEIVED
	// more recently.
	first, second := rep.ProvenancePatchHistory[0], rep.ProvenancePatchHistory[1]
	if first.Outcome != "installed" || first.Identifier != "1password|8.10.0" {
		t.Errorf("patch_history[0] = %+v, want the \"installed\" 8.10.0 row (newest by EVENT time) — "+
			"got the stale queued failure instead, meaning ordering fell back to received_at", first)
	}
	if second.Outcome != "verification_failed" || second.Identifier != "1password|8.9.0" {
		t.Errorf("patch_history[1] = %+v, want the stale \"verification_failed\" 8.9.0 row (oldest by EVENT time)", second)
	}
	// InstalledAt on the surfaced item should reflect the EVENT time, not
	// the receipt time (now, the failed row's received_at) — a 20+ hour
	// gap distinguishes the two clearly.
	if first.InstalledAt == nil || now.Sub(*first.InstalledAt) > time.Minute {
		t.Errorf("patch_history[0].InstalledAt = %v, want ~now (its recorded_at), not its received_at", first.InstalledAt)
	}
}

// TestFetch_ProvenanceMalformedEventTimestampFallsBackToReceivedAt proves a
// provenance row with a garbage (non-ISO-8601) recorded_at value does not
// break the query — a naive unconditional ::timestamptz cast on untrusted
// client text would raise a hard Postgres error and fail the WHOLE
// device-detail response, not just this one field. It must instead fall
// back to the row's received_at, exactly like a row with recorded_at absent
// entirely.
func TestFetch_ProvenanceMalformedEventTimestampFallsBackToReceivedAt(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-1007 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	hwUUID := "9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A"
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, os, os_version)
		VALUES ($1::uuid, 'PAT1007SERIAL7', $2::uuid, 'macOS', '15.5')
		RETURNING id::text
	`, tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	receivedAt := time.Now().UTC()
	insertPat1007Provenance(t, pool, tenantID, receivedAt, map[string]any{
		"record_type": "third_party_update",
		"device":      map[string]any{"hw_uuid": hwUUID},
		"outcome":     "installed",
		"recorded_at": "definitely-not-a-timestamp",
		"app": map[string]any{
			"label":             "slack",
			"available_version": "4.50.0",
		},
	})

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v — a malformed recorded_at value must not error the query", err)
	}
	if len(rep.ProvenancePatchHistory) != 1 {
		t.Fatalf("len(ProvenancePatchHistory) = %d, want 1: %+v", len(rep.ProvenancePatchHistory), rep.ProvenancePatchHistory)
	}
	got := rep.ProvenancePatchHistory[0]
	if got.InstalledAt == nil || got.InstalledAt.Sub(receivedAt) > time.Minute || receivedAt.Sub(*got.InstalledAt) > time.Minute {
		t.Errorf("InstalledAt = %v, want ~%v (fell back to received_at)", got.InstalledAt, receivedAt)
	}
}

// TestFetch_ProvenanceOutOfRangeEventTimestampFallsBackToReceivedAt is the
// actual gap the shape-only regex guard (this query's first-round fix)
// missed: "2026-99-99T99:99:99" has exactly the right digit POSITIONS to
// pass a `~ '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}'` check, but month 99 and
// day 99 aren't valid, so the ::timestamptz cast on it still throws — a
// regex guard alone would let this value straight through to a hard
// Postgres error, 500ing the whole device-detail response. The prior test
// above (TestFetch_ProvenanceMalformedEventTimestampFallsBackToReceivedAt)
// only proves a value that FAILS the shape check falls back safely; it
// can't catch this because "definitely-not-a-timestamp" never had the right
// shape to reach the cast in the first place. pg_input_is_valid must reject
// this by actually validating against timestamptz's real input function,
// not just checking digit positions.
func TestFetch_ProvenanceOutOfRangeEventTimestampFallsBackToReceivedAt(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-1007 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	hwUUID := "9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A"
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, os, os_version)
		VALUES ($1::uuid, 'PAT1007SERIAL8', $2::uuid, 'macOS', '15.5')
		RETURNING id::text
	`, tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	receivedAt := time.Now().UTC()
	insertPat1007Provenance(t, pool, tenantID, receivedAt, map[string]any{
		"record_type": "third_party_update",
		"device":      map[string]any{"hw_uuid": hwUUID},
		"outcome":     "installed",
		"recorded_at": "2026-99-99T99:99:99", // right shape, invalid month/day/hour/minute/second
		"app": map[string]any{
			"label":             "slack",
			"available_version": "4.50.0",
		},
	})

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v — a shape-valid but range-invalid recorded_at value must not error the query "+
			"(this is the actual gap a shape-only regex guard leaves open)", err)
	}
	if len(rep.ProvenancePatchHistory) != 1 {
		t.Fatalf("len(ProvenancePatchHistory) = %d, want 1: %+v", len(rep.ProvenancePatchHistory), rep.ProvenancePatchHistory)
	}
	got := rep.ProvenancePatchHistory[0]
	if got.InstalledAt == nil || got.InstalledAt.Sub(receivedAt) > time.Minute || receivedAt.Sub(*got.InstalledAt) > time.Minute {
		t.Errorf("InstalledAt = %v, want ~%v (fell back to received_at)", got.InstalledAt, receivedAt)
	}
}

// TestFetch_ProvenanceInfiniteEventTimestampFallsBackToReceivedAt is the gap
// pg_input_is_valid alone leaves open: timestamptz's real input function
// genuinely accepts the special values "infinity"/"-infinity", so
// pg_input_is_valid('infinity', 'timestamptz') is true and the cast succeeds
// at the SQL layer — but pgx cannot scan an infinite timestamptz into a Go
// time.Time, so Fetch would error on every future request for this device
// once such a row exists, not just a transient one. The query's explicit
// NOT IN ('infinity', '-infinity') guard must reject these before the
// validity check even runs.
func TestFetch_ProvenanceInfiniteEventTimestampFallsBackToReceivedAt(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-1007 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	hwUUID := "1A2B3C4D-5E6F-7A8B-9C0D-1E2F3A4B5C6D"
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, os, os_version)
		VALUES ($1::uuid, 'PAT1007SERIAL9', $2::uuid, 'macOS', '15.5')
		RETURNING id::text
	`, tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	receivedAt := time.Now().UTC()
	insertPat1007Provenance(t, pool, tenantID, receivedAt, map[string]any{
		"record_type": "third_party_update",
		"device":      map[string]any{"hw_uuid": hwUUID},
		"outcome":     "installed",
		"recorded_at": "infinity", // valid per pg_input_is_valid, unscannable into time.Time
		"app": map[string]any{
			"label":             "slack",
			"available_version": "4.50.0",
		},
	})

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v — recorded_at=\"infinity\" must not error the query or persistently "+
			"break this device's patch history", err)
	}
	if len(rep.ProvenancePatchHistory) != 1 {
		t.Fatalf("len(ProvenancePatchHistory) = %d, want 1: %+v", len(rep.ProvenancePatchHistory), rep.ProvenancePatchHistory)
	}
	got := rep.ProvenancePatchHistory[0]
	if got.InstalledAt == nil || got.InstalledAt.Sub(receivedAt) > time.Minute || receivedAt.Sub(*got.InstalledAt) > time.Minute {
		t.Errorf("InstalledAt = %v, want ~%v (fell back to received_at)", got.InstalledAt, receivedAt)
	}
}

// TestFetch_ProvenanceExcludesOtherDevice proves a provenance row belonging
// to a DIFFERENT device (different hw_uuid, even under the same tenant) is
// never attributed to this device's patch history.
func TestFetch_ProvenanceExcludesOtherDevice(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-1007 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, os, os_version)
		VALUES ($1::uuid, 'PAT1007SERIAL2', 'BBBBBBBB-1111-1111-1111-111111111111'::uuid, 'macOS', '15.5')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	// Provenance for a different hw_uuid entirely — must not leak here.
	insertPat1007Provenance(t, pool, tenantID, time.Now().UTC(), map[string]any{
		"record_type": "third_party_update",
		"device":      map[string]any{"hw_uuid": "CCCCCCCC-2222-2222-2222-222222222222"},
		"outcome":     "installed",
		"app": map[string]any{
			"label":             "slack",
			"available_version": "4.50.0",
		},
	})

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(rep.ProvenancePatchHistory) != 0 {
		t.Errorf("ProvenancePatchHistory = %+v, want empty — provenance for another device's hw_uuid must not match", rep.ProvenancePatchHistory)
	}
}

// TestFetch_ProvenanceExcludesWindowsShape documents and locks in the known,
// deliberate gap called out in the PAT-1007 ticket: the Windows provenance
// emitter (windows/src/Service/ProvenancePoster.cs, updater repo) never
// serializes a device.hw_uuid at all — see internal/rings/advance.go's
// queryFailureRate doc comment for the identical gap in the ring-gating
// query. A Windows-shaped row (flat label/state, no "device" object) must not
// error the query and must not spuriously attribute to any device.
func TestFetch_ProvenanceExcludesWindowsShape(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-1007 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	hwUUID := "9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A"
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, os, os_version)
		VALUES ($1::uuid, 'PAT1007SERIAL3', $2::uuid, 'Windows', '11')
		RETURNING id::text
	`, tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	// Real Windows emitter shape: flat label/installed_version/state, no
	// "device" key anywhere in the body.
	insertPat1007Provenance(t, pool, tenantID, time.Now().UTC(), map[string]any{
		"platform":          "windows",
		"label":             "slack",
		"installed_version": "4.50.0",
		"available_version": "4.50.0",
		"state":             "uptodate",
	})

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if len(rep.ProvenancePatchHistory) != 0 {
		t.Errorf("ProvenancePatchHistory = %+v, want empty — Windows provenance carries no per-device identifier "+
			"today, so it must not be attributed to any device (known limitation, not a bug to fix here)", rep.ProvenancePatchHistory)
	}
}

// TestFetch_PatchHistoryStaysSeparateAndMergesOnDemand is the P1 fix
// regression: report.Fetch must keep rep.PatchHistory OS-patches-only (so
// the PDF renderer, which reads that field directly, is completely
// unaffected by this ticket) while rep.ProvenancePatchHistory carries the
// provenance-sourced rows on its own newest-first field. It then proves the
// exported MergePatchHistory — the thing a consumer like the JSON
// device-detail handler calls explicitly — correctly interleaves real,
// DB-fetched data from both sources into one newest-first list (not just a
// concatenation), the same property internal/report/report_test.go's pure
// unit tests already prove with synthetic data.
func TestFetch_PatchHistoryStaysSeparateAndMergesOnDemand(t *testing.T) {
	pool := pat709Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('PAT-1007 Test Tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	hwUUID := "9C8B7A6F-5E4D-3C2B-1A09-8F7E6D5C4B3A"
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, os, os_version)
		VALUES ($1::uuid, 'PAT1007SERIAL4', $2::uuid, 'macOS', '15.5')
		RETURNING id::text
	`, tenantID, hwUUID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}

	now := time.Now().UTC()

	// OS-patch rows: 1 hour ago and 3 hours ago.
	if _, err := pool.Exec(ctx, `
		INSERT INTO patches (device_id, title, identifier, installed_at)
		VALUES
			($1::uuid, 'macOS 15.5', 'macOS 15.5|15.5', $2),
			($1::uuid, 'Safari', 'Safari|18.5', $3)
	`, deviceID, now.Add(-1*time.Hour), now.Add(-3*time.Hour)); err != nil {
		t.Fatalf("insert patches: %v", err)
	}

	// Provenance rows: right now (most recent overall) and 2 hours ago
	// (between the two OS-patch rows).
	insertPat1007Provenance(t, pool, tenantID, now, map[string]any{
		"record_type": "third_party_update",
		"device":      map[string]any{"hw_uuid": hwUUID},
		"outcome":     "installed",
		"app": map[string]any{
			"label":             "slack",
			"available_version": "4.50.0",
		},
	})
	insertPat1007Provenance(t, pool, tenantID, now.Add(-2*time.Hour), map[string]any{
		"record_type":    "third_party_update",
		"device":         map[string]any{"hw_uuid": hwUUID},
		"outcome":        "verification_failed",
		"failure_reason": "checksum mismatch",
		"app": map[string]any{
			"label":             "1password",
			"available_version": "8.10.0",
		},
	})

	rep, err := Fetch(ctx, pool, deviceID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// rep.PatchHistory must stay OS-patches-only — exactly what the patches
	// table query alone returns, untouched by provenance data.
	if len(rep.PatchHistory) != 2 {
		t.Fatalf("len(PatchHistory) = %d, want 2 (OS-patch rows only): %+v", len(rep.PatchHistory), rep.PatchHistory)
	}
	wantOSOrder := []string{"macOS 15.5|15.5", "Safari|18.5"}
	for i, id := range wantOSOrder {
		if rep.PatchHistory[i].Identifier != id {
			t.Errorf("PatchHistory position %d: got identifier %q, want %q", i, rep.PatchHistory[i].Identifier, id)
		}
		if rep.PatchHistory[i].Outcome != "" || rep.PatchHistory[i].FailureReason != "" {
			t.Errorf("PatchHistory[%d] (%q) unexpectedly has outcome/failure_reason: %+v",
				i, rep.PatchHistory[i].Identifier, rep.PatchHistory[i])
		}
	}

	// rep.ProvenancePatchHistory must carry the provenance rows, separately,
	// also newest-first.
	if len(rep.ProvenancePatchHistory) != 2 {
		t.Fatalf("len(ProvenancePatchHistory) = %d, want 2: %+v", len(rep.ProvenancePatchHistory), rep.ProvenancePatchHistory)
	}
	wantProvOrder := []string{"slack|4.50.0", "1password|8.10.0"}
	for i, id := range wantProvOrder {
		if rep.ProvenancePatchHistory[i].Identifier != id {
			t.Errorf("ProvenancePatchHistory position %d: got identifier %q, want %q",
				i, rep.ProvenancePatchHistory[i].Identifier, id)
		}
	}

	// The exported merge — what the JSON device-detail handler calls — must
	// interleave both DB-fetched slices into one newest-first list.
	merged := MergePatchHistory(rep.PatchHistory, rep.ProvenancePatchHistory)
	wantMergedOrder := []string{"slack|4.50.0", "macOS 15.5|15.5", "1password|8.10.0", "Safari|18.5"}
	if len(merged) != 4 {
		t.Fatalf("len(merged) = %d, want 4: %+v", len(merged), merged)
	}
	for i, id := range wantMergedOrder {
		if merged[i].Identifier != id {
			t.Errorf("merged position %d: got identifier %q, want %q (full order: %+v)",
				i, merged[i].Identifier, id, merged)
		}
	}
}
