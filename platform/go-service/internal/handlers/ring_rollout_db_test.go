package handlers

// DB-backed tests for queryWaveBars (PAT-997 follow-up review). Before this
// change queryWaveBars had no test coverage at all — Codex's second-pass
// review flagged that explicitly — and shared three defects with
// queryFailureRate (internal/rings/advance.go): it matched "installed"/
// "failed" on version_after/installed_version (the POST-attempt version,
// which a failure never advances — so a genuine failure could never show up
// as "failed"), it never scoped by platform (so macOS and Windows evidence
// for the same label+version could bleed into each other's wave bars), and
// it had no record_type guard against a client-forged non-update record.
//
// These tests use TEST_DATABASE_URL against a fully-migrated schema (same
// convention as allowlist_agent_known_path_test.go / catalogue_signed_db_test.go
// in this package) rather than the rings package's isolated-bespoke-schema
// convention, since this package doesn't hand-roll its own minimal schema and
// the real devices/provenance_records/tenants/ring_version_approvals tables
// are what queryWaveBars actually reads.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// rrInsertDevice inserts a devices row with a fixed ring_computed.
func rrInsertDevice(t *testing.T, pool *pgxpool.Pool, tenantID, hwUUID string, ringComputed int16) string {
	t.Helper()
	return rrInsertDeviceOS(t, pool, tenantID, hwUUID, ringComputed, "macOS")
}

// rrInsertDeviceOS is rrInsertDevice with an explicit os column value
// ("macOS" or "Windows", matching devices.os's real convention — see
// migrations/0001_initial.sql). Needed to test queryWaveBars' platform-scoped
// denominator (PAT-997 fifth review round): device_rings must only count
// devices of the platform being queried, not every device in the tenant.
func rrInsertDeviceOS(t *testing.T, pool *pgxpool.Pool, tenantID, hwUUID string, ringComputed int16, os string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, hw_uuid, ring_computed, os)
		VALUES ($1::uuid, $2::uuid, $3, $4)
		RETURNING id::text
	`, tenantID, hwUUID, ringComputed, os).Scan(&id); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1::uuid`, id) })
	return id
}

// rrInsertProvenance writes an arbitrary body to provenance_records.
func rrInsertProvenance(t *testing.T, pool *pgxpool.Pool, tenantID string, receivedAt time.Time, body map[string]any) {
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

// rrMacOSAttempt builds a body in the real macOS emitter shape
// (endpoint/patched-update.sh emit_provenance, updater repo): device.hw_uuid,
// top-level outcome, app.label/app.available_version (the ATTEMPTED
// version — populated on both success and failure) and app.version_after
// (the version actually on disk after the attempt — unchanged from
// version_before on failure, per InventoryCollector.ProcessEntryAsync parity
// on the Windows side and the rc-based case statement in patched-update.sh on
// the macOS side). priorVersion/attemptedVersion/succeeded together produce
// version_after honestly instead of assuming success like an earlier version
// of this fix's fixtures did.
func rrMacOSAttempt(t *testing.T, pool *pgxpool.Pool, tenantID string, receivedAt time.Time, hwUUID, label, priorVersion, attemptedVersion, outcome string, succeeded bool) {
	t.Helper()
	versionAfter := priorVersion
	if succeeded {
		versionAfter = attemptedVersion
	}
	rrInsertProvenance(t, pool, tenantID, receivedAt, map[string]any{
		"record_type": "third_party_update",
		"device":      map[string]any{"hw_uuid": hwUUID},
		"outcome":     outcome,
		"app": map[string]any{
			"label":             label,
			"version_before":    priorVersion,
			"version_after":     versionAfter,
			"available_version": attemptedVersion,
		},
	})
}

// rrMacOSRingGated builds a body matching patched-update.sh's ring_skip
// branch: the engine never runs, so available_version is unconditionally
// empty (patched-update.sh: `available_ver=""` in the
// mode==scan||policy_skip||ring_skip||bpp_failclosed branch) — there is no
// field anywhere in this record that names the withheld target version. This
// is deliberately version-less, mirroring real emitter behaviour, to prove
// queryWaveBars' "gated" bucket doesn't require (and can't require) a
// version match.
func rrMacOSRingGated(t *testing.T, pool *pgxpool.Pool, tenantID string, receivedAt time.Time, hwUUID, label, installedVersion string) {
	t.Helper()
	rrInsertProvenance(t, pool, tenantID, receivedAt, map[string]any{
		"record_type": "third_party_update",
		"device":      map[string]any{"hw_uuid": hwUUID},
		"outcome":     "ring_gated",
		"app": map[string]any{
			"label":         label,
			"version_after": installedVersion, // unchanged: engine never ran
			// available_version intentionally absent.
		},
	})
}

// TestQueryWaveBars_RealShapesAttributeCorrectly proves queryWaveBars reads
// real macOS payload shapes correctly across all four buckets using four
// distinct devices in the same ring, and specifically that:
//   - "installed" and "failed" are matched on available_version (the
//     ATTEMPTED version), so a genuine failure of the target version — whose
//     version_after/version_before never move — is counted as failed, not
//     silently dropped the way a version_after-keyed match would drop it.
//   - "gated" counts a ring_gated record with NO version field at all (real
//     emitter behaviour — see rrMacOSRingGated), proving the version filter
//     was correctly NOT applied to the gated bucket.
//   - "total" counts every device in the ring regardless of whether it has
//     any matching provenance (D4 has none).
func TestQueryWaveBars_RealShapesAttributeCorrectly(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat997-wavebars-tenant", "pat997-wavebars-token", "pat997-wavebars-hmac-secret-32b!")

	const label = "1password"
	const target = "8.10.0"

	hw1 := "44444444-4444-4444-4444-444444444441"
	hw2 := "44444444-4444-4444-4444-444444444442"
	hw3 := "44444444-4444-4444-4444-444444444443"
	hw4 := "44444444-4444-4444-4444-444444444444"
	rrInsertDevice(t, pool, tenantID, hw1, 1)
	rrInsertDevice(t, pool, tenantID, hw2, 1)
	rrInsertDevice(t, pool, tenantID, hw3, 1)
	rrInsertDevice(t, pool, tenantID, hw4, 1)

	now := time.Now().UTC()
	// D1: successful install of the target version.
	rrMacOSAttempt(t, pool, tenantID, now, hw1, label, "8.9.0", target, "installed", true)
	// D2: FAILED attempt at the target version — version_after stays "8.9.0"
	// (the prior version), available_version carries the attempted target.
	// A version_after-keyed match would silently exclude this row entirely.
	rrMacOSAttempt(t, pool, tenantID, now, hw2, label, "8.9.0", target, "verification_failed", false)
	// D3: ring-gated skip — no version field anywhere in the body.
	rrMacOSRingGated(t, pool, tenantID, now, hw3, label, "8.9.0")
	// D4: no provenance at all for this label.

	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	bars := queryWaveBars(ctx, pool, tenantID, "macos", label, target, logger)

	var got *ringWaveBar
	for i := range bars {
		if bars[i].Ring == 1 {
			got = &bars[i]
		}
	}
	if got == nil {
		t.Fatalf("no ring=1 bucket in %+v", bars)
	}
	want := ringWaveBar{Ring: 1, Installed: 1, Gated: 1, Failed: 1, Total: 4}
	if *got != want {
		t.Fatalf("ring 1 wave bar = %+v, want %+v", *got, want)
	}
}

// TestQueryWaveBars_PlatformScoped proves macOS evidence cannot leak into a
// Windows-platform wave-bar query (PAT-997 P0: a.Platform/e.Platform was
// never passed to this query at all) AND that the DENOMINATOR is
// platform-scoped too (fifth review round P1): device_rings used to select
// every device in the tenant regardless of platform, so a macOS device
// diluted (or, as the prior version of this test asserted, was REQUIRED to
// appear in) a Windows rollout's Total. This test now seeds one macOS device
// and one Windows device and proves each platform's query sees only its own
// device — Total included, not just Installed.
//
// The macOS record used is macOS-shaped — which DOES carry a joinable
// device.hw_uuid — so the Installed assertions isolate the provenance
// platform filter specifically, rather than being trivially satisfied by the
// separate, unrelated fact that Windows provenance carries no device
// identifier at all today (see queryFailureRate's doc comment in advance.go).
func TestQueryWaveBars_PlatformScoped(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat997-wavebars-platform-tenant", "pat997-wavebars-platform-token", "pat997-wavebars-platform-hmac-32b!")

	const label = "slack"
	const target = "4.50.143"
	hwMac := "55555555-5555-5555-5555-555555555555"
	hwWin := "55555555-5555-5555-5555-555555555556"
	rrInsertDeviceOS(t, pool, tenantID, hwMac, 0, "macOS")
	rrInsertDeviceOS(t, pool, tenantID, hwWin, 0, "Windows")

	now := time.Now().UTC()
	// A real macOS-shaped success record — no top-level "platform" key, so
	// the query's own COALESCE(...,'macos') default is what should classify
	// it, exactly as ObserveNewVersions/queryFailureRate do.
	rrMacOSAttempt(t, pool, tenantID, now, hwMac, label, "4.49.0", target, "installed", true)
	// The Windows device reports nothing for this label/version — its
	// wave bar should show Total=1 (it exists), Installed=0 (no evidence).

	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))

	macBars := queryWaveBars(ctx, pool, tenantID, "macos", label, target, logger)
	winBars := queryWaveBars(ctx, pool, tenantID, "windows", label, target, logger)

	var macRing0, winRing0 *ringWaveBar
	for i := range macBars {
		if macBars[i].Ring == 0 {
			macRing0 = &macBars[i]
		}
	}
	for i := range winBars {
		if winBars[i].Ring == 0 {
			winRing0 = &winBars[i]
		}
	}
	if macRing0 == nil || macRing0.Installed != 1 || macRing0.Total != 1 {
		t.Fatalf("macos-platform query ring 0 = %+v, want {Installed:1 Total:1} — "+
			"only the macOS device should be in this query's denominator", macRing0)
	}
	if winRing0 == nil || winRing0.Installed != 0 {
		t.Fatalf("windows-platform query ring 0 = %+v, want Installed=0 — "+
			"a macOS-shaped success record must not count as Windows evidence", winRing0)
	}
	if winRing0.Total != 1 {
		t.Errorf("windows-platform query ring 0 Total = %d, want 1 — the WINDOWS device (not the macOS one) "+
			"should be the sole denominator for a Windows-platform query. A macOS device diluting this "+
			"total is exactly the P1 defect this test now guards against", winRing0.Total)
	}
}

// TestQueryWaveBars_RecordTypeAllowlist_RejectsForgedType is the test for the
// record_type ALLOWLIST fix (third PAT-997 review round). The prior fix was
// a DENYLIST — COALESCE(record_type,'third_party_update') <> 'app_uninstall'
// — which let any OTHER forged record_type (e.g. "inventory") through with
// otherwise update-shaped fields. provenance is client-supplied JSON
// archived verbatim under a shared tenant secret, so the guard needs an
// explicit allowlist, not merely one excluded known-bad value. Mirrors
// TestProcessApproval_RecordTypeAllowlist_RejectsForgedType in
// internal/rings/advance_db_test.go, which covers the identical defect in
// queryFailureRate.
func TestQueryWaveBars_RecordTypeAllowlist_RejectsForgedType(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat997-wavebars-recordtype-tenant", "pat997-wavebars-recordtype-token", "pat997-wavebars-recordtype-hmac-32b!")

	const label = "1password"
	const target = "8.10.0"
	hw := "77777777-7777-7777-7777-777777777777"
	rrInsertDevice(t, pool, tenantID, hw, 0)

	now := time.Now().UTC()
	// A forged record: update-shaped fields, but record_type is neither
	// absent nor "third_party_update".
	rrInsertProvenance(t, pool, tenantID, now, map[string]any{
		"record_type": "inventory",
		"device":      map[string]any{"hw_uuid": hw},
		"outcome":     "installed",
		"app": map[string]any{
			"label":             label,
			"version_before":    "8.9.0",
			"version_after":     target,
			"available_version": target,
		},
	})

	logger := slog.New(slog.NewTextHandler(discardWriter{}, nil))
	bars := queryWaveBars(ctx, pool, tenantID, "macos", label, target, logger)

	var got *ringWaveBar
	for i := range bars {
		if bars[i].Ring == 0 {
			got = &bars[i]
		}
	}
	if got == nil {
		t.Fatalf("no ring=0 bucket in %+v", bars)
	}
	if got.Installed != 0 {
		t.Errorf("ring 0 Installed = %d, want 0 — a forged record_type:\"inventory\" row must not count", got.Installed)
	}
	if got.Total != 1 {
		t.Errorf("ring 0 Total = %d, want 1 (the device still exists in that ring)", got.Total)
	}
}

// TestRingRolloutStatusHandler_ReportsPermanentQuarantine keeps the dashboard
// contract aligned with the production invariant.
func TestRingRolloutStatusHandler_ReportsPermanentQuarantine(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat997-autoadvance-note-tenant", "pat997-autoadvance-note-token", "pat997-autoadvance-note-hmac-32b!")

	handler := RingRolloutStatusHandler(pool)
	req := httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/ring-rollouts", nil)
	req = withChiParam(req, "tenantID", tenantID)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("got %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var resp ringRolloutsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.AutoAdvanceEnabled {
		t.Errorf("auto_advance_enabled = true, want false")
	}
	// PAT-997 (fifth review round): a non-empty check passes for ANY string,
	// including an inaccurate one — which is exactly what shipped when this
	// constant briefly claimed "pause/resume reaches agents" (false; see
	// rings.AutoAdvanceDisabledReason's doc comment). Assert equality with
	// the single source of truth so a future overstatement here fails loudly
	// instead of silently passing a "non-empty" check.
	if resp.AutoAdvanceNote != "legacy rollout advancement is permanently quarantined" {
		t.Errorf("auto_advance_note = %q, want permanent-quarantine explanation", resp.AutoAdvanceNote)
	}
}

// discardWriter is an io.Writer that discards everything, used to keep the
// slog.Logger these tests must pass to queryWaveBars quiet.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

// rrSeedRingConfig inserts a tenant_ring_config row with the given ring_count.
// percentages must have exactly ring_count elements (DB CHECK,
// migrations/0042_patching_rings.sql).
func rrSeedRingConfig(t *testing.T, pool *pgxpool.Pool, tenantID string, ringCount int, percentages []int16) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO tenant_ring_config (tenant_id, enabled, ring_count, percentages)
		VALUES ($1::uuid, true, $2, $3)
		ON CONFLICT (tenant_id) DO UPDATE SET ring_count = EXCLUDED.ring_count, percentages = EXCLUDED.percentages
	`, tenantID, ringCount, percentages); err != nil {
		t.Fatalf("insert tenant_ring_config: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenant_ring_config WHERE tenant_id = $1::uuid`, tenantID)
	})
}

// rrSeedApproval inserts a ring_version_approvals row and returns its id.
func rrSeedApproval(t *testing.T, pool *pgxpool.Pool, tenantID, platform, label, version string, approvedRing int16, state string) string {
	t.Helper()
	// Manual rollout actions publish into agent_config in their own transaction.
	// Direct DB test tenants bypass CreateTenantHandler, so seed the production
	// invariant here rather than letting an unrelated missing row turn an action
	// regression into a misleading 500.
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO agent_config (tenant_id, body, config_version, issued_at)
		VALUES ($1::uuid, '{}'::jsonb, 1, now())
		ON CONFLICT (tenant_id) DO NOTHING
	`, tenantID); err != nil {
		t.Fatalf("insert agent_config: %v", err)
	}
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO ring_version_approvals (tenant_id, platform, label, version, approved_ring, state)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)
		RETURNING id::text
	`, tenantID, platform, label, version, approvedRing, state).Scan(&id); err != nil {
		t.Fatalf("insert ring_version_approvals: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ring_version_approvals WHERE id = $1::uuid`, id)
	})
	return id
}

// rrCallSkip invokes RingRolloutSkipHandler once and returns the decoded
// {approved_ring, state} it reports.
func rrCallSkip(t *testing.T, pool *pgxpool.Pool, tenantID, rolloutID string) (int, string) {
	t.Helper()
	handler := RingRolloutSkipHandlerForLegacyExecutionCompatibility(pool)
	req := httptest.NewRequest(http.MethodPost,
		"/admin/tenants/"+tenantID+"/ring-rollouts/"+rolloutID+"/skip",
		strings.NewReader(`{"changed_by":"test"}`))
	req = withChiParam(req, "tenantID", tenantID)
	// withChiParam builds a fresh route context each call, so add the second
	// param to the context the first one produced rather than replacing it.
	rctx := chi.RouteContext(req.Context())
	rctx.URLParams.Add("id", rolloutID)

	rr := httptest.NewRecorder()
	handler(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("skip returned %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		ApprovedRing int    `json:"approved_ring"`
		State        string `json:"state"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode skip response: %v", err)
	}
	return resp.ApprovedRing, resp.State
}

// TestRingRolloutSkip_WalksConfiguredRingsAndCompletes is the PAT-1002
// defect-8/9 regression test for the manual path.
//
// Manual skip used to compute approved_ring+1 clamped at 3, and never set
// state to 'completed'. Both matter more than they used to: with automatic
// gating skipped for Windows entirely (see rings.processApproval), manual skip
// is the ONLY way a Windows rollout ever moves, so it has to be able to walk
// the rollout to GA and then close it out.
//
// This tenant is on ring_count=3, which assigns devices to agent rings 0, 1
// and 3 — never 2. The old behaviour spent a skip moving the rollout to ring
// 2, exposing the update to nobody, and then clamped at 3 in state 'rolling'
// forever: the rollout could be driven to GA but never finished, so it stayed
// on the dashboard's active list indefinitely.
func TestRingRolloutSkip_WalksConfiguredRingsAndCompletes(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1002-skip-tenant", "pat1002-skip-token", "pat1002-skip-hmac-secret-32b!!")
	rrSeedRingConfig(t, pool, tenantID, 3, []int16{10, 30, 60})

	rolloutID := rrSeedApproval(t, pool, tenantID, "windows", "slack", "4.50.143", 0, "rolling")

	// 0 -> 1: the next CONFIGURED ring, which here is also +1.
	if ring, state := rrCallSkip(t, pool, tenantID, rolloutID); ring != 1 || state != "rolling" {
		t.Fatalf("first skip = {ring:%d state:%q}, want {ring:1 state:\"rolling\"}", ring, state)
	}

	// 1 -> 3, jumping the hole. The old code went to 2, a ring this tenant
	// assigns no device to, so the skip exposed the update to nobody.
	if ring, state := rrCallSkip(t, pool, tenantID, rolloutID); ring != 3 || state != "rolling" {
		t.Fatalf("second skip = {ring:%d state:%q}, want {ring:3 state:\"rolling\"} — ring 2 is not a "+
			"configured ring for ring_count=3, so skipping onto it wastes a step and exposes the update "+
			"to no devices", ring, state)
	}

	// At GA there is no next ring, so this skip completes the rollout rather
	// than clamping to 3 and staying 'rolling' forever.
	if ring, state := rrCallSkip(t, pool, tenantID, rolloutID); ring != 3 || state != "completed" {
		t.Fatalf("third skip = {ring:%d state:%q}, want {ring:3 state:\"completed\"} — a rollout manually "+
			"driven to GA must be able to finish; completeApproval is on the disabled automatic path and "+
			"emergency-deploy means something else", ring, state)
	}

	// And the DB agrees, so the rollout drops off the dashboard's active list
	// (RingRolloutStatusHandler selects only 'rolling' and 'paused').
	var gotRing int
	var gotState string
	if err := pool.QueryRow(ctx,
		`SELECT approved_ring, state FROM ring_version_approvals WHERE id = $1::uuid`, rolloutID,
	).Scan(&gotRing, &gotState); err != nil {
		t.Fatalf("read back approval: %v", err)
	}
	if gotRing != 3 || gotState != "completed" {
		t.Errorf("stored approval = {ring:%d state:%q}, want {ring:3 state:\"completed\"}", gotRing, gotState)
	}
}

// TestRingRolloutSkip_NoRingConfigDefaultsToContiguous covers the fallback the
// ring_count lookup needs: a tenant with no tenant_ring_config row at all.
// Defaulting to ring_count=4 preserves the 0-1-2-3 walk this handler assumed
// before PAT-1002, so adding the lookup can't change behaviour for a tenant
// that never configured rings.
func TestRingRolloutSkip_NoRingConfigDefaultsToContiguous(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1002-skip-noconfig-tenant", "pat1002-skip-noconfig-token", "pat1002-skip-noconfig-hmac32!!")
	// Deliberately NO rrSeedRingConfig call.

	rolloutID := rrSeedApproval(t, pool, tenantID, "macos", "firefox", "130.0", 1, "rolling")

	if ring, state := rrCallSkip(t, pool, tenantID, rolloutID); ring != 2 || state != "rolling" {
		t.Fatalf("skip with no ring config = {ring:%d state:%q}, want {ring:2 state:\"rolling\"}", ring, state)
	}
}

// rrCallSkipRaw invokes RingRolloutSkipHandler once and returns the raw status
// code and body, without asserting 200 the way rrCallSkip does. Needed for the
// conflict paths, where a non-200 IS the expected result.
func rrCallSkipRaw(t *testing.T, pool *pgxpool.Pool, tenantID, rolloutID string) (int, string) {
	t.Helper()
	handler := RingRolloutSkipHandlerForLegacyExecutionCompatibility(pool)
	req := httptest.NewRequest(http.MethodPost,
		"/admin/tenants/"+tenantID+"/ring-rollouts/"+rolloutID+"/skip",
		strings.NewReader(`{"changed_by":"test"}`))
	req = withChiParam(req, "tenantID", tenantID)
	rctx := chi.RouteContext(req.Context())
	rctx.URLParams.Add("id", rolloutID)

	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr.Code, rr.Body.String()
}

func rrCallActionRaw(t *testing.T, handler http.HandlerFunc, tenantID, rolloutID, action, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost,
		"/admin/tenants/"+tenantID+"/ring-rollouts/"+rolloutID+"/"+action,
		strings.NewReader(body))
	req = withChiParam(req, "tenantID", tenantID)
	chi.RouteContext(req.Context()).URLParams.Add("id", rolloutID)
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr.Code, rr.Body.String()
}

// rrSkipAuditRings returns the new_value->>'ring' of every 'rollout_skipped'
// audit row for a tenant, oldest first. The audit log is the only record of who
// advanced a rollout and when, so it is the thing a double-apply corrupts.
func rrSkipAuditRings(t *testing.T, pool *pgxpool.Pool, tenantID string) []int {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT (new_value->>'ring')::int
		FROM ring_config_changes
		WHERE tenant_id = $1::uuid AND change_type = 'rollout_skipped'
		ORDER BY id
	`, tenantID)
	if err != nil {
		t.Fatalf("query audit rows: %v", err)
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("scan audit row: %v", err)
		}
		out = append(out, v)
	}
	return out
}

// TestRingRolloutSkip_TerminalStateIsConflict covers the deterministic half of
// PAT-1002 finding 5's guard: the skip UPDATE is now predicated on the rollout
// still being in a state a skip can apply from.
//
// 'completed' and 'superseded' are terminal (migrations/0042_patching_rings.sql
// pins state to those four values). Before this change the handler read the row
// and updated it unconditionally, so skipping a completed rollout resurrected
// it to 'rolling' and wrote an audit row saying an operator had advanced
// something the state machine had already closed.
func TestRingRolloutSkip_TerminalStateIsConflict(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1002-skip-terminal-tenant", "pat1002-skip-terminal-token", "pat1002-skip-terminal-hmac32!")
	rrSeedRingConfig(t, pool, tenantID, 4, []int16{10, 20, 30, 40})
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM ring_config_changes WHERE tenant_id = $1::uuid`, tenantID)
	})

	for _, state := range []string{"completed", "superseded"} {
		rolloutID := rrSeedApproval(t, pool, tenantID, "macos", "firefox-"+state, "130.0", 3, state)

		code, body := rrCallSkipRaw(t, pool, tenantID, rolloutID)
		if code != http.StatusConflict {
			t.Errorf("skip on a %q rollout returned %d (%s), want 409 — a terminal rollout must not be "+
				"resurrected by an advance", state, code, strings.TrimSpace(body))
		}

		var gotRing int
		var gotState string
		if err := pool.QueryRow(ctx,
			`SELECT approved_ring, state FROM ring_version_approvals WHERE id = $1::uuid`, rolloutID,
		).Scan(&gotRing, &gotState); err != nil {
			t.Fatalf("read back approval: %v", err)
		}
		if gotState != state || gotRing != 3 {
			t.Errorf("rollout in state %q after refused skip = {ring:%d state:%q}, want it untouched", state, gotRing, gotState)
		}
	}

	if got := rrSkipAuditRings(t, pool, tenantID); len(got) != 0 {
		t.Errorf("refused skips wrote %d audit rows (%v), want none — the audit log must not record an "+
			"advance that did not happen", len(got), got)
	}
}

// TestRingRolloutSkip_ConcurrentSkipsDoNotDoubleApply is the PAT-1002
// finding-5 regression test.
//
// pgx runs at Read Committed. Two skips arriving together on the same rollout
// both pass the handler's initial SELECT without seeing each other's
// uncommitted write, both compute the same next ring from the same stale
// approved_ring, and — before this fix — both UPDATE and both INSERT a
// 'rollout_skipped' audit row. The rollout moved ONE ring while two 200s and
// two audit entries claimed it moved two: the audit log, the only record of who
// advanced what, silently disagreed with the rollout itself.
//
// The interleaving is forced rather than raced. Two goroutines released
// together do NOT reliably overlap — an earlier version of this test did
// exactly that and passed against the unguarded handler on every run, because
// the first request finished its whole transaction before the second began, so
// it proved nothing. Here the losing request is the handler itself and the
// winner is a transaction this test holds open:
//
//  1. T1 (this test) updates approved_ring 0 -> 1 and does NOT commit.
//  2. The handler runs. Its SELECT sees the pre-T1 row (ring 0, Read
//     Committed), so it computes exactly the same next ring T1 already took.
//  3. Its UPDATE blocks on T1's row lock — waited for explicitly, not slept on.
//  4. T1 commits. The handler re-evaluates its WHERE against the new row.
//
// Step 4 is the entire fix: approved_ring is no longer the 0 it read, so the
// UPDATE matches nothing, the handler returns 409, and the audit INSERT never
// runs. Without the guard the UPDATE applies, writing ring 1 over ring 1 and
// recording a second advance that never happened.
func TestRingRolloutSkip_ConcurrentSkipsDoNotDoubleApply(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	tenantID := parSeedTenant(t, ctx, pool, "pat1002-skip-race-tenant", "pat1002-skip-race-token", "pat1002-skip-race-hmac-32b!!")
	// ring_count 4: agent rings 0,1,2,3, a contiguous walk, so "next ring" is
	// unambiguously 1 for both writers.
	rrSeedRingConfig(t, pool, tenantID, 4, []int16{10, 20, 30, 40})
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM ring_config_changes WHERE tenant_id = $1::uuid`, tenantID)
	})

	rolloutID := rrSeedApproval(t, pool, tenantID, "windows", "slack", "4.50.143", 0, "rolling")

	// 1. The winning skip, held open.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin competing tx: %v", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `
		UPDATE ring_version_approvals
		SET approved_ring = 1, state = 'rolling', paused_reason = NULL,
		    last_advanced_at = now(), updated_at = now()
		WHERE id = $1::uuid
	`, rolloutID); err != nil {
		t.Fatalf("competing update: %v", err)
	}

	// 2 + 3. The handler reads the pre-update row, then blocks on the row lock.
	done := make(chan int, 1)
	go func() {
		code, _ := rrCallSkipRaw(t, pool, tenantID, rolloutID)
		done <- code
	}()
	rrWaitForRowLockWaiter(t, pool)

	// 4. Release it.
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit competing tx: %v", err)
	}
	committed = true

	var code int
	select {
	case code = <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("skip handler did not return after the competing transaction committed")
	}

	if code != http.StatusConflict {
		t.Errorf("skip that lost the race returned %d, want 409 — its UPDATE must match no row once the "+
			"winner has moved approved_ring off the value it read", code)
	}

	var gotRing int
	var gotState string
	if err := pool.QueryRow(ctx,
		`SELECT approved_ring, state FROM ring_version_approvals WHERE id = $1::uuid`, rolloutID,
	).Scan(&gotRing, &gotState); err != nil {
		t.Fatalf("read back approval: %v", err)
	}
	if gotRing != 1 || gotState != "rolling" {
		t.Errorf("rollout = {ring:%d state:%q}, want {ring:1 state:\"rolling\"} — exactly one advance happened",
			gotRing, gotState)
	}

	// The audit log is what the double-apply actually corrupts: the row write
	// is idempotent (ring 1 over ring 1), the second audit entry is not.
	if audit := rrSkipAuditRings(t, pool, tenantID); len(audit) != 0 {
		t.Errorf("the refused skip wrote %d audit row(s) (%v), want none — an advance that did not happen must "+
			"not appear in the only record of who advanced what", len(audit), audit)
	}

	// And a skip arriving cleanly AFTER the winner committed is unaffected: it
	// reads ring 1 and legitimately advances to 2.
	if ring, state := rrCallSkip(t, pool, tenantID, rolloutID); ring != 2 || state != "rolling" {
		t.Errorf("subsequent non-racing skip = {ring:%d state:%q}, want {ring:2 state:\"rolling\"} — the guard "+
			"must reject only stale writes, not serialised ones", ring, state)
	}
}

// PAT-1134: every manual action must leave terminal rows untouched. Emergency
// deploy used to be the exception: it read a completed row and then updated it
// without a state predicate, creating an audit entry for a closed rollout.
func TestRingRolloutManualActions_TerminalRowsAreConflict(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool, "pat1134-terminal-actions", "pat1134-terminal-actions-token", "pat1134-terminal-actions-hmac-secret")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM ring_config_changes WHERE tenant_id = $1::uuid`, tenantID) })

	cases := []struct {
		action  string
		handler http.HandlerFunc
		body    string
	}{
		{"pause", RingRolloutPauseHandler(pool), `{"changed_by":"test"}`},
		{"resume", RingRolloutResumeHandlerForLegacyExecutionCompatibility(pool), `{"changed_by":"test"}`},
		{"emergency", RingRolloutEmergencyHandlerForLegacyExecutionCompatibility(pool), `{"changed_by":"test","reason":"zero day"}`},
	}
	for _, tc := range cases {
		t.Run(tc.action, func(t *testing.T) {
			rolloutID := rrSeedApproval(t, pool, tenantID, "macos", "terminal-"+tc.action, "130.0", 3, "completed")
			code, body := rrCallActionRaw(t, tc.handler, tenantID, rolloutID, tc.action, tc.body)
			if code != http.StatusConflict {
				t.Fatalf("%s on completed rollout returned %d (%s), want 409", tc.action, code, strings.TrimSpace(body))
			}
			var state string
			var ring int
			if err := pool.QueryRow(ctx, `SELECT state, approved_ring FROM ring_version_approvals WHERE id = $1::uuid`, rolloutID).Scan(&state, &ring); err != nil {
				t.Fatal(err)
			}
			if state != "completed" || ring != 3 {
				t.Errorf("terminal rollout changed to {state:%q ring:%d}", state, ring)
			}
		})
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM ring_config_changes WHERE tenant_id = $1::uuid`, tenantID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 0 {
		t.Errorf("terminal actions wrote %d audit rows, want 0", audits)
	}
}

// The emergency path needs the same compare-and-set guard as skip. Force a
// stale read, then change the ring before its UPDATE obtains the row lock.
func TestRingRolloutEmergency_ConcurrentStaleWriteIsConflict(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool, "pat1134-emergency-race", "pat1134-emergency-race-token", "pat1134-emergency-race-hmac-secret")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM ring_config_changes WHERE tenant_id = $1::uuid`, tenantID) })
	rolloutID := rrSeedApproval(t, pool, tenantID, "macos", "firefox", "130.0", 0, "rolling")

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()
	if _, err := tx.Exec(ctx, `UPDATE ring_version_approvals SET approved_ring = 1 WHERE id = $1::uuid`, rolloutID); err != nil {
		t.Fatal(err)
	}

	done := make(chan int, 1)
	go func() {
		code, _ := rrCallActionRaw(t, RingRolloutEmergencyHandlerForLegacyExecutionCompatibility(pool), tenantID, rolloutID, "emergency", `{"changed_by":"test","reason":"zero day"}`)
		done <- code
	}()
	rrWaitForRowLockWaiter(t, pool)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	committed = true

	select {
	case code := <-done:
		if code != http.StatusConflict {
			t.Errorf("stale emergency returned %d, want 409", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("emergency handler did not return after competing transaction committed")
	}
	var ring int
	var state string
	if err := pool.QueryRow(ctx, `SELECT approved_ring, state FROM ring_version_approvals WHERE id = $1::uuid`, rolloutID).Scan(&ring, &state); err != nil {
		t.Fatal(err)
	}
	if ring != 1 || state != "rolling" {
		t.Errorf("rollout = {ring:%d state:%q}, want {ring:1 state:rolling}", ring, state)
	}
	var audits int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM ring_config_changes WHERE tenant_id = $1::uuid`, tenantID).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 0 {
		t.Errorf("stale emergency wrote %d audit rows, want 0", audits)
	}
}

// rrWaitForRowLockWaiter blocks until some backend is waiting on a lock while
// running a statement against ring_version_approvals, i.e. until the handler
// under test has reached its UPDATE and been blocked by the transaction the
// test is holding open. Polling pg_stat_activity is what makes the interleave
// deterministic instead of a sleep that is either flaky or slow.
func rrWaitForRowLockWaiter(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var n int
		if err := pool.QueryRow(context.Background(), `
			SELECT count(*)
			FROM pg_stat_activity
			WHERE wait_event_type = 'Lock'
			  AND query ILIKE '%ring_version_approvals%'
			  AND pid <> pg_backend_pid()
		`).Scan(&n); err != nil {
			t.Fatalf("poll pg_stat_activity: %v", err)
		}
		if n > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for the skip handler to block on the rollout row lock")
}
