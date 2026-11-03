package handlers

// PAT-1690 regression: TenantRulesListHandler's evaluated_devices field must
// reflect only devices actually evaluated against a rule, not the tenant's
// raw device total. A platform-scoped rule (e.g. Windows-only) is never
// evaluated on macOS devices at all, so those devices must not count toward
// its denominator — the client-side bug this field exists to fix combined
// the tenant's whole device count with a platform-filtered fail list.
//
// Skipped unless TEST_DATABASE_URL points at a scratch database, same
// convention as platform_switch_aggregation_db_test.go (pat862Pool) and
// enforcement_audit_credential_db_test.go — pool's search_path is pinned to
// an isolated schema so no real data is touched.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const pat1690Schema = "pat1690_test"

func pat1690Pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping DB-backed handler test")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = pat1690Schema + ",public"
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgxpool.NewWithConfig: %v", err)
	}
	t.Cleanup(pool.Close)

	ctx := context.Background()
	for _, s := range []string{
		`CREATE EXTENSION IF NOT EXISTS "pgcrypto"`,
		`DROP SCHEMA IF EXISTS ` + pat1690Schema + ` CASCADE`,
		`CREATE SCHEMA ` + pat1690Schema,
		`CREATE TABLE ` + pat1690Schema + `.tenants (
			id   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			name TEXT NOT NULL
		)`,
		`CREATE TABLE ` + pat1690Schema + `.devices (
			id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id UUID NOT NULL REFERENCES ` + pat1690Schema + `.tenants(id),
			hostname  TEXT
		)`,
		`CREATE TABLE ` + pat1690Schema + `.compliance_rules (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			rule_key           TEXT NOT NULL,
			benchmark          TEXT NOT NULL DEFAULT 'CIS Test',
			benchmark_version  TEXT NOT NULL DEFAULT 'v1',
			control_identifier TEXT,
			title              TEXT NOT NULL,
			severity           TEXT NOT NULL DEFAULT 'low',
			platform           TEXT NOT NULL DEFAULT 'macos',
			collection_tier    TEXT NOT NULL DEFAULT 'T1',
			enabled            BOOLEAN NOT NULL DEFAULT true,
			UNIQUE (benchmark, benchmark_version, rule_key)
		)`,
		`CREATE TABLE ` + pat1690Schema + `.tenant_rules (
			id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id          UUID NOT NULL REFERENCES ` + pat1690Schema + `.tenants(id),
			rule_id            UUID NOT NULL REFERENCES ` + pat1690Schema + `.compliance_rules(id),
			enabled            BOOLEAN NOT NULL DEFAULT true,
			override_severity  TEXT,
			suppression_reason TEXT,
			suppressed_until   TIMESTAMPTZ
		)`,
		`CREATE TABLE ` + pat1690Schema + `.compliance_evaluations (
			device_id    UUID NOT NULL,
			rule_id      UUID NOT NULL,
			status       TEXT NOT NULL,
			evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now()
		)`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("setup %q: %v", s[:40], err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+pat1690Schema+` CASCADE`)
	})
	return pool
}

// TestTenantRulesListHandler_VersionedControlIdentifiers proves that control
// identifiers are versioned data, not values inferred from rule_key. The same
// stable key can have a different identifier under two benchmark revisions,
// while an unmapped Patched check serialises an explicit JSON null.
func TestTenantRulesListHandler_VersionedControlIdentifiers(t *testing.T) {
	pool := pat1690Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1858 Test Tenant') RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	for _, row := range []struct {
		benchmark        string
		benchmarkVersion string
		identifier       *string
		title            string
	}{
		{benchmark: "CIS Test Benchmark", benchmarkVersion: "v1.0", identifier: pat1858StringPointer("1.2"), title: "Synthetic rule v1"},
		{benchmark: "CIS Test Benchmark", benchmarkVersion: "v2.0", identifier: pat1858StringPointer("4.5"), title: "Synthetic rule v2"},
		{benchmark: "patched.im baseline", benchmarkVersion: "v1", identifier: nil, title: "Patched own check"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO compliance_rules
				(rule_key, benchmark, benchmark_version, control_identifier, title)
			VALUES ('stable_filevault_rule', $1, $2, $3, $4)
		`, row.benchmark, row.benchmarkVersion, row.identifier, row.title); err != nil {
			t.Fatalf("insert %s %s rule: %v", row.benchmark, row.benchmarkVersion, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenant-rules/"+tenantID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	TenantRulesListHandler(pool)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Rules []json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	got := make(map[string]tenantRuleEntry)
	for _, raw := range resp.Rules {
		var entry tenantRuleEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			t.Fatalf("decode entry: %v", err)
		}
		got[entry.Benchmark+"|"+entry.BenchmarkVersion] = entry

		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			t.Fatalf("decode entry fields: %v", err)
		}
		if _, present := fields["control_identifier"]; !present {
			t.Fatalf("control_identifier omitted for %s %s", entry.Benchmark, entry.BenchmarkVersion)
		}
		if entry.Benchmark == "patched.im baseline" && string(fields["control_identifier"]) != "null" {
			t.Errorf("Patched own check control_identifier = %s, want explicit null", fields["control_identifier"])
		}
	}

	for key, want := range map[string]string{
		"CIS Test Benchmark|v1.0": "1.2",
		"CIS Test Benchmark|v2.0": "4.5",
	} {
		entry, ok := got[key]
		if !ok {
			t.Fatalf("missing versioned entry %s", key)
		}
		if entry.ControlIdentifier == nil || *entry.ControlIdentifier != want {
			t.Errorf("%s control_identifier = %v, want %q", key, entry.ControlIdentifier, want)
		}
	}
	entry, ok := got["patched.im baseline|v1"]
	if !ok {
		t.Fatal("missing Patched own-check entry")
	}
	if entry.ControlIdentifier != nil {
		t.Errorf("Patched own check control_identifier = %q, want nil", *entry.ControlIdentifier)
	}
}

func pat1858StringPointer(value string) *string { return &value }

// TestTenantRulesListHandler_EvaluatedDevices seeds a tenant with two macOS
// devices and one Windows device, plus a Windows-only rule evaluated on the
// Windows device only (pass) and a cross-platform T1 rule evaluated on all
// three. It asserts evaluated_devices is 1 for the platform-scoped rule
// (never 3, the tenant's raw device total) and 3 for the T1 rule.
func TestTenantRulesListHandler_EvaluatedDevices(t *testing.T) {
	pool := pat1690Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name) VALUES ('PAT-1690 Test Tenant') RETURNING id::text
	`).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	deviceIDs := make([]string, 3)
	for i, hostname := range []string{"mac-01", "mac-02", "win-01"} {
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname) VALUES ($1::uuid, $2) RETURNING id::text
		`, tenantID, hostname).Scan(&deviceIDs[i]); err != nil {
			t.Fatalf("insert device %s: %v", hostname, err)
		}
	}
	macDevice1, macDevice2, winDevice := deviceIDs[0], deviceIDs[1], deviceIDs[2]

	var winRuleID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, severity, platform, collection_tier)
		VALUES ('pat1690_windows_only', 'PAT-1690 Windows-Only Rule', 'high', 'windows', 'T1')
		RETURNING id::text
	`).Scan(&winRuleID); err != nil {
		t.Fatalf("insert windows rule: %v", err)
	}

	var allPlatformRuleID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO compliance_rules (rule_key, title, severity, platform, collection_tier)
		VALUES ('pat1690_all_platform', 'PAT-1690 All-Platform Rule', 'low', 'macos', 'T1')
		RETURNING id::text
	`).Scan(&allPlatformRuleID); err != nil {
		t.Fatalf("insert all-platform rule: %v", err)
	}

	// Windows-only rule: evaluated (pass) on the Windows device only. The two
	// macOS devices were never evaluated against it at all.
	if _, err := pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status)
		VALUES ($1::uuid, $2::uuid, 'pass')
	`, winDevice, winRuleID); err != nil {
		t.Fatalf("insert windows rule evaluation: %v", err)
	}

	// All-platform rule: evaluated on all three devices (two pass, one fail).
	for i, dev := range []string{macDevice1, macDevice2, winDevice} {
		status := "pass"
		if i == 1 {
			status = "fail"
		}
		if _, err := pool.Exec(ctx, `
			INSERT INTO compliance_evaluations (device_id, rule_id, status)
			VALUES ($1::uuid, $2::uuid, $3)
		`, dev, allPlatformRuleID, status); err != nil {
			t.Fatalf("insert all-platform evaluation for %s: %v", dev, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/tenant-rules/"+tenantID, nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("tenantID", tenantID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	rec := httptest.NewRecorder()
	TenantRulesListHandler(pool)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp tenantRulesListResp
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	byKey := make(map[string]tenantRuleEntry)
	for _, e := range resp.Rules {
		byKey[e.RuleKey] = e
	}

	winEntry, ok := byKey["pat1690_windows_only"]
	if !ok {
		t.Fatalf("windows-only rule missing from response")
	}
	if winEntry.EvaluatedDevices != 1 {
		t.Errorf("windows-only rule: expected evaluated_devices=1 (the one Windows device), got %d — "+
			"if this is 3, the tenant's raw device total leaked back in as the denominator", winEntry.EvaluatedDevices)
	}

	allEntry, ok := byKey["pat1690_all_platform"]
	if !ok {
		t.Fatalf("all-platform rule missing from response")
	}
	if allEntry.EvaluatedDevices != 3 {
		t.Errorf("all-platform rule: expected evaluated_devices=3, got %d", allEntry.EvaluatedDevices)
	}
}
