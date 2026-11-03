package report

// PAT-2496: FetchEncryptionStates against a database (the isolated schema
// pat1762Pool builds). It covers what the pure classifier test cannot: that the
// query reads the latest evaluation over the FileVault and BitLocker rules for
// both platforms alike, ignores every other rule, honours the tenant boundary,
// and answers for one device, a list, or the whole tenant from one function.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func pat2496Device(t *testing.T, pool *pgxpool.Pool, tenantID, hostname, osName string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO devices (tenant_id, hostname, os, os_version)
		VALUES ($1::uuid, $2, $3, '15.0') RETURNING id::text`, tenantID, hostname, osName).Scan(&id); err != nil {
		t.Fatalf("insert device %s: %v", hostname, err)
	}
	return id
}

func pat2496Eval(t *testing.T, pool *pgxpool.Pool, deviceID, ruleID, status string, observed *string, at time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, evaluated_at)
		VALUES ($1::uuid, $2::uuid, $3, $4, 'critical', $5)`, deviceID, ruleID, status, observed, at); err != nil {
		t.Fatalf("insert evaluation: %v", err)
	}
}

func TestFetchEncryptionStates(t *testing.T) {
	pool := pat1762Pool(t)
	ctx := context.Background()
	tenant := insertPAT1762Tenant(t, pool)
	other := insertPAT1762Tenant(t, pool)
	fileVault := insertPAT1762Rule(t, pool, encryptionRuleKeys[0], "Enable FileVault", "critical")
	bitLocker := insertPAT1762Rule(t, pool, encryptionRuleKeys[1], "Enable BitLocker", "critical")
	unrelated := insertPAT1762Rule(t, pool, "cis_macos_2_3_firewall", "Firewall", "high")
	now := time.Now().UTC()

	macOn := pat2496Device(t, pool, tenant, "mac-on", "macOS")
	pat2496Eval(t, pool, macOn, fileVault, "pass", strPtr("On"), now)

	winOff := pat2496Device(t, pool, tenant, "win-off", "Windows")
	pat2496Eval(t, pool, winOff, bitLocker, "fail", strPtr("Off"), now)

	winOn := pat2496Device(t, pool, tenant, "win-on", "Windows")
	pat2496Eval(t, pool, winOn, bitLocker, "pass", strPtr("On"), now)

	winUnreadable := pat2496Device(t, pool, tenant, "win-unreadable", "Windows")
	pat2496Eval(t, pool, winUnreadable, bitLocker, "fail", nil, now)

	macNotApplicable := pat2496Device(t, pool, tenant, "mac-na", "macOS")
	pat2496Eval(t, pool, macNotApplicable, fileVault, "not_applicable", nil, now)

	macErrorObserved := pat2496Device(t, pool, tenant, "mac-error", "macOS")
	pat2496Eval(t, pool, macErrorObserved, fileVault, "error", strPtr("garbled"), now)

	noEvaluation := pat2496Device(t, pool, tenant, "no-eval", "macOS")

	// Only the latest evaluation counts: an old pass superseded by a newer
	// observed off is not encrypted, and the reverse is encrypted.
	nowOff := pat2496Device(t, pool, tenant, "now-off", "Windows")
	pat2496Eval(t, pool, nowOff, bitLocker, "pass", strPtr("On"), now.Add(-48*time.Hour))
	pat2496Eval(t, pool, nowOff, bitLocker, "fail", strPtr("Off"), now)
	nowOn := pat2496Device(t, pool, tenant, "now-on", "Windows")
	pat2496Eval(t, pool, nowOn, bitLocker, "fail", strPtr("Off"), now.Add(-48*time.Hour))
	pat2496Eval(t, pool, nowOn, bitLocker, "pass", strPtr("On"), now)

	// An evaluation of any other rule, however recent, is not encryption.
	otherRuleOnly := pat2496Device(t, pool, tenant, "other-rule", "macOS")
	pat2496Eval(t, pool, otherRuleOnly, unrelated, "fail", strPtr("Off"), now)
	// A newer unrelated evaluation does not displace the encryption one.
	shadowed := pat2496Device(t, pool, tenant, "shadowed", "macOS")
	pat2496Eval(t, pool, shadowed, fileVault, "pass", strPtr("On"), now.Add(-time.Hour))
	pat2496Eval(t, pool, shadowed, unrelated, "fail", strPtr("Off"), now)

	foreign := pat2496Device(t, pool, other, "foreign", "Windows")
	pat2496Eval(t, pool, foreign, bitLocker, "fail", strPtr("Off"), now)

	want := map[string]string{
		macOn: EncryptionStateEncrypted, winOn: EncryptionStateEncrypted, nowOn: EncryptionStateEncrypted, shadowed: EncryptionStateEncrypted,
		winOff: EncryptionStateNotEncrypted, macErrorObserved: EncryptionStateNotEncrypted, nowOff: EncryptionStateNotEncrypted,
		winUnreadable: EncryptionStateUnknown, macNotApplicable: EncryptionStateUnknown, noEvaluation: EncryptionStateUnknown,
		otherRuleOnly: EncryptionStateUnknown,
	}

	// Every device of the tenant, from one call, and none from another tenant.
	got, err := FetchEncryptionStates(ctx, pool, tenant, nil)
	if err != nil {
		t.Fatalf("all devices: %v", err)
	}
	if len(got) != len(want) {
		t.Errorf("returned %d devices, want %d: %v", len(got), len(want), got)
	}
	for id, w := range want {
		if got[id] != w {
			t.Errorf("device %s = %q, want %q", id, got[id], w)
		}
	}
	if _, ok := got[foreign]; ok {
		t.Errorf("another tenant's device leaked into the result")
	}

	// One device, from the same function.
	one, err := FetchEncryptionStates(ctx, pool, tenant, []string{winOff})
	if err != nil {
		t.Fatalf("one device: %v", err)
	}
	if len(one) != 1 || one[winOff] != EncryptionStateNotEncrypted {
		t.Errorf("one device = %v, want only %s not_encrypted", one, winOff)
	}

	// A list narrows to the list. A device of another tenant named in the
	// list is absent, exactly as if it did not exist.
	some, err := FetchEncryptionStates(ctx, pool, tenant, []string{macOn, noEvaluation, foreign})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(some) != 2 || some[macOn] != EncryptionStateEncrypted || some[noEvaluation] != EncryptionStateUnknown {
		t.Errorf("list = %v, want mac-on encrypted and no-eval unknown only", some)
	}
	if _, ok := some[foreign]; ok {
		t.Errorf("a device outside the tenant was answered for")
	}

	// An empty, non-nil list asks for no device and answers for none (it is
	// not "all devices").
	none, err := FetchEncryptionStates(ctx, pool, tenant, []string{})
	if err != nil || len(none) != 0 {
		t.Errorf("empty list = %v, %v; want no devices", none, err)
	}

	// The roster's flag is read off the same states.
	flags, err := fetchPortalDeviceFlags(ctx, pool, tenant, []string{macOn, winOff, winUnreadable}, now)
	if err != nil {
		t.Fatalf("roster flags: %v", err)
	}
	if f := flags[macOn].encryptionOK; f == nil || !*f {
		t.Errorf("roster mac-on = %v, want true", boolPtrStr(f))
	}
	if f := flags[winOff].encryptionOK; f == nil || *f {
		t.Errorf("roster win-off = %v, want false", boolPtrStr(f))
	}
	if f := flags[winUnreadable].encryptionOK; f != nil {
		t.Errorf("roster win-unreadable = %v, want nil", boolPtrStr(f))
	}
}
