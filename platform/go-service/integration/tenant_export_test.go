//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// exportBundleShape mirrors the JSON produced by handlers.TenantExportHandler.
// Declared locally so the test asserts on the wire contract, not internal types.
type exportBundleShape struct {
	ExportedAt time.Time `json:"exported_at"`
	TenantID   string    `json:"tenant_id"`
	Scope      string    `json:"scope"`
	UserFilter string    `json:"user_filter"`
	Tenant     struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"tenant"`
	Devices []struct {
		ID                 string `json:"id"`
		PrimaryUserAccount string `json:"primary_user_account"`
		Apps               []struct {
			Name       string `json:"name"`
			Identifier string `json:"identifier"`
		} `json:"apps"`
		ComplianceSignals []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"compliance_signals"`
		ComplianceEvaluations []struct {
			RuleKey string `json:"rule_key"`
			Status  string `json:"status"`
		} `json:"compliance_evaluations"`
	} `json:"devices"`
	Reports  []json.RawMessage `json:"reports"`
	AuditLog []json.RawMessage `json:"audit_log"`
}

func seedExportDevice(t *testing.T, ctx context.Context, hwUUID, serial, hostname, user string) string {
	t.Helper()
	var id string
	err := env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, primary_user_account, primary_user_display)
		VALUES ($1::uuid, $2, $3::uuid, $4, 'macOS', '15.0', $5, $5)
		RETURNING id::text`,
		env.tenantID, serial, hwUUID, hostname, user).Scan(&id)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return id
}

func TestTenantExport(t *testing.T) {
	ctx := context.Background()

	// Distinctive user emails so scoped assertions can't collide with devices
	// created by other integration tests sharing this tenant.
	const userA = "export-alice@pat136.example"
	const userB = "export-bob@pat136.example"

	devA := seedExportDevice(t, ctx, "e1000000-0000-0000-0000-000000000001", "PAT136-A", "alice-mac", userA)
	devB := seedExportDevice(t, ctx, "e1000000-0000-0000-0000-000000000002", "PAT136-B", "bob-mac", userB)

	// Children for device A.
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, version, identifier)
		VALUES ($1::uuid, 'Firefox', '120.0', 'org.mozilla.firefox'),
		       ($1::uuid, 'Slack', '4.0', 'com.tinyspeck.slackmacgap')`, devA); err != nil {
		t.Fatalf("seed apps: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO compliance_signals (device_id, key, value, severity)
		VALUES ($1::uuid, 'filevault', 'On', 'ok')`, devA); err != nil {
		t.Fatalf("seed signal: %v", err)
	}
	var ruleID string
	if err := env.pool.QueryRow(ctx, `SELECT id::text FROM compliance_rules LIMIT 1`).Scan(&ruleID); err != nil {
		t.Fatalf("pick rule: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, benchmark_version)
		VALUES ($1::uuid, $2::uuid, 'pass', 'On', 'medium', 'v1.0.0')`, devA, ruleID); err != nil {
		t.Fatalf("seed evaluation: %v", err)
	}

	getBundle := func(t *testing.T, url string) exportBundleShape {
		t.Helper()
		resp, err := http.Get(url)
		if err != nil {
			t.Fatalf("GET %s: %v", url, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d", url, resp.StatusCode)
		}
		var b exportBundleShape
		if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
			t.Fatalf("decode bundle: %v", err)
		}
		return b
	}

	findDevice := func(b exportBundleShape, id string) (int, bool) {
		for i, d := range b.Devices {
			if d.ID == id {
				return i, true
			}
		}
		return -1, false
	}

	t.Run("full tenant export attaches children", func(t *testing.T) {
		b := getBundle(t, env.internalSrv.URL+"/admin/tenants/"+env.tenantID+"/export")
		if b.Scope != "tenant" {
			t.Errorf("scope = %q, want tenant", b.Scope)
		}
		if b.UserFilter != "" {
			t.Errorf("user_filter = %q, want empty", b.UserFilter)
		}
		if b.Reports == nil || b.AuditLog == nil {
			t.Errorf("reports/audit_log must be present arrays, got reports=%v audit=%v", b.Reports, b.AuditLog)
		}
		i, ok := findDevice(b, devA)
		if !ok {
			t.Fatalf("device A not found in export")
		}
		if len(b.Devices[i].Apps) != 2 {
			t.Errorf("device A apps = %d, want 2", len(b.Devices[i].Apps))
		}
		if len(b.Devices[i].ComplianceSignals) != 1 {
			t.Errorf("device A signals = %d, want 1", len(b.Devices[i].ComplianceSignals))
		}
		if len(b.Devices[i].ComplianceEvaluations) != 1 {
			t.Errorf("device A evaluations = %d, want 1", len(b.Devices[i].ComplianceEvaluations))
		}
		if _, ok := findDevice(b, devB); !ok {
			t.Errorf("device B not found in full export")
		}
	})

	t.Run("user-scoped export returns only that user", func(t *testing.T) {
		b := getBundle(t, env.internalSrv.URL+"/admin/tenants/"+env.tenantID+"/export?user="+userA)
		if b.Scope != "user" {
			t.Errorf("scope = %q, want user", b.Scope)
		}
		if b.UserFilter != userA {
			t.Errorf("user_filter = %q, want %q", b.UserFilter, userA)
		}
		if len(b.Devices) != 1 {
			t.Fatalf("user-scoped devices = %d, want 1", len(b.Devices))
		}
		if b.Devices[0].ID != devA {
			t.Errorf("user-scoped device = %s, want %s (device A)", b.Devices[0].ID, devA)
		}
		// Tenant-wide records must be excluded from a DSR user export.
		if len(b.Reports) != 0 || len(b.AuditLog) != 0 {
			t.Errorf("user scope must omit tenant records: reports=%d audit=%d", len(b.Reports), len(b.AuditLog))
		}
	})

	t.Run("user filter is case-insensitive", func(t *testing.T) {
		b := getBundle(t, env.internalSrv.URL+"/admin/tenants/"+env.tenantID+"/export?user=EXPORT-ALICE@PAT136.EXAMPLE")
		if len(b.Devices) != 1 || b.Devices[0].ID != devA {
			t.Errorf("case-insensitive filter failed: got %d devices", len(b.Devices))
		}
	})

	t.Run("export is scoped to the tenant only", func(t *testing.T) {
		// A device in a different tenant sharing the same primary-user email
		// must never appear in this tenant's export — the core privacy invariant.
		otherTenant, _, _, err := createTestTenant(env.internalSrv.URL, "pat136-other-tenant")
		if err != nil {
			t.Fatalf("create other tenant: %v", err)
		}
		if _, err := env.pool.Exec(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, primary_user_account, primary_user_display)
			VALUES ($1::uuid, 'PAT136-OTHER', 'e1000000-0000-0000-0000-0000000000ff'::uuid, 'other-mac', 'macOS', '15.0', $2, $2)`,
			otherTenant, userA); err != nil {
			t.Fatalf("seed other-tenant device: %v", err)
		}

		b := getBundle(t, env.internalSrv.URL+"/admin/tenants/"+env.tenantID+"/export?user="+userA)
		if len(b.Devices) != 1 || b.Devices[0].ID != devA {
			t.Errorf("cross-tenant leak: got %d devices, want only device A", len(b.Devices))
		}
	})

	t.Run("unknown tenant is 404", func(t *testing.T) {
		resp, err := http.Get(env.internalSrv.URL + "/admin/tenants/00000000-0000-0000-0000-0000000000ff/export")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("unknown tenant status = %d, want 404", resp.StatusCode)
		}
	})
}
