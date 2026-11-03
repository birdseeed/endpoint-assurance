package report

// PAT-1992: the built-in RID-500 Administrator rule. A disabled built-in is
// excluded from the assessed admin count, an enabled one is a finding, and
// "unknown" or an absent state is neither. macOS is explicitly not-applicable
// and its verdict is unchanged.

import (
	"context"
	"strings"
	"testing"
)

func sp(s string) *string { return &s }

// u is a user-principal built-in entry.
func u(sid, state *string) builtinAdminEntry {
	return builtinAdminEntry{Sid: sid, PrincipalType: "user", AccountState: state}
}

func TestAssessBuiltinAdminWindows(t *testing.T) {
	sid := sp("S-1-5-21-1-2-3-500")
	cases := []struct {
		name         string
		builtins     []builtinAdminEntry
		reported     int
		wantVerdict  string
		wantAssessed int
	}{
		{"disabled is excluded", []builtinAdminEntry{u(sid, sp("disabled"))}, 3, BuiltinAdminDisabled, 2},
		{"enabled stays and is flagged", []builtinAdminEntry{u(sid, sp("enabled"))}, 3, BuiltinAdminEnabled, 3},
		{"unknown is not disabled", []builtinAdminEntry{u(sid, sp("unknown"))}, 3, BuiltinAdminUnknown, 3},
		{"absent is not disabled", []builtinAdminEntry{u(sid, nil)}, 3, BuiltinAdminUnknown, 3},
		{"no built-in entry", nil, 3, BuiltinAdminNone, 3},
		{"no count signal: nothing excluded", []builtinAdminEntry{u(sid, sp("disabled"))}, -1, BuiltinAdminDisabled, -1},
		{"never below zero", []builtinAdminEntry{u(sid, sp("disabled"))}, 0, BuiltinAdminDisabled, 0},
		{"builtin flag without a RID-500 SID is ignored", []builtinAdminEntry{u(nil, sp("disabled")), u(sp("S-1-5-21-1-2-3-1500"), sp("disabled"))}, 3, BuiltinAdminNone, 3},
		{"domain-joined: local disabled, domain unknown", []builtinAdminEntry{u(sid, sp("disabled")), u(sp("S-1-5-21-9-9-9-500"), sp("unknown"))}, 4, BuiltinAdminUnknown, 3},
		{"disabled group principal is not excluded (never counted)", []builtinAdminEntry{{Sid: sid, PrincipalType: "group", AccountState: sp("disabled")}}, 3, BuiltinAdminDisabled, 3},
		{"domain-joined: enabled wins the verdict", []builtinAdminEntry{u(sid, sp("disabled")), u(sp("S-1-5-21-9-9-9-500"), sp("enabled"))}, 4, BuiltinAdminEnabled, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, n, note := assessBuiltinAdmin("Windows", tc.builtins, tc.reported)
			if v != tc.wantVerdict || n != tc.wantAssessed {
				t.Errorf("got (%s, %d), want (%s, %d)", v, n, tc.wantVerdict, tc.wantAssessed)
			}
			if v != BuiltinAdminNone && note == "" {
				t.Error("a built-in verdict must carry an explanatory note")
			}
		})
	}
}

func TestAssessBuiltinAdminMacOSIsExplicitlyNotApplicable(t *testing.T) {
	// Even a (malformed) builtin entry with a disabled state must not adjust a
	// macOS count: the check is Windows-only.
	v, n, note := assessBuiltinAdmin("macOS", []builtinAdminEntry{u(sp("S-1-5-21-1-2-3-500"), sp("disabled"))}, 3)
	if v != BuiltinAdminNotApplicable || n != 3 {
		t.Errorf("macOS: got (%s, %d), want (%s, 3)", v, n, BuiltinAdminNotApplicable)
	}
	if !strings.Contains(note, "macOS") || !strings.Contains(note, "root") || !strings.Contains(note, "as reported") {
		t.Errorf("macOS note must say no built-in check ran and the verdict is on the roster as reported; got %q", note)
	}
}

// TestFetchLocalAdminReportBuiltinAdminVerdicts: end to end through the real
// query. Every Windows device reports local_admin_count 3 (the built-in plus
// two others), which is "at-risk" unless a disabled built-in is excluded.
func TestFetchLocalAdminReportBuiltinAdminVerdicts(t *testing.T) {
	pool := pat1974Pool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenants (name) VALUES ('pat1992-tenant') RETURNING id::text`,
	).Scan(&tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	type dev struct {
		host, os string
		count    string
		state    *string // built-in entry's account_state; builtin entry omitted when hasBuiltin is false
		builtin  bool
	}
	devs := []dev{
		{"WIN-DISABLED", "Windows", "3", sp("disabled"), true},
		{"WIN-ENABLED", "Windows", "3", sp("enabled"), true},
		{"WIN-UNKNOWN", "Windows", "3", sp("unknown"), true},
		{"WIN-ABSENT", "Windows", "3", nil, true},
		{"MAC-1", "macOS", "3", nil, false},
		// Only admin is the enabled built-in: count 1 would be compliant,
		// but an enabled built-in is never compliant.
		{"WIN-ENABLED-ONLY", "Windows", "1", sp("enabled"), true},
	}
	for _, d := range devs {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO devices (tenant_id, hostname, os) VALUES ($1::uuid, $2, $3) RETURNING id::text`,
			tenantID, d.host, d.os,
		).Scan(&id); err != nil {
			t.Fatalf("insert device %s: %v", d.host, err)
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO compliance_signals (device_id, key, value) VALUES ($1::uuid, 'local_admin_count', $2)`,
			id, d.count,
		); err != nil {
			t.Fatalf("insert signal %s: %v", d.host, err)
		}
		if d.builtin {
			if _, err := pool.Exec(ctx,
				`INSERT INTO local_admin_accounts (device_id, name, principal_type, builtin, sid, account_state)
				 VALUES ($1::uuid, $2, 'user', true, 'S-1-5-21-1-2-3-500', $3)`,
				id, d.host+`\Administrator`, d.state,
			); err != nil {
				t.Fatalf("insert built-in %s: %v", d.host, err)
			}
		}
		others := []string{"alice", "bob"}
		if d.host == "WIN-ENABLED-ONLY" {
			others = nil
		}
		for _, n := range others {
			if _, err := pool.Exec(ctx,
				`INSERT INTO local_admin_accounts (device_id, name, principal_type, builtin) VALUES ($1::uuid, $2, 'user', false)`,
				id, n,
			); err != nil {
				t.Fatalf("insert %s/%s: %v", d.host, n, err)
			}
		}
		if !d.builtin {
			if _, err := pool.Exec(ctx,
				`INSERT INTO local_admin_accounts (device_id, name, principal_type, builtin) VALUES ($1::uuid, 'carol', 'user', false)`,
				id,
			); err != nil {
				t.Fatalf("insert %s/carol: %v", d.host, err)
			}
		}
	}

	r, err := FetchLocalAdminReport(ctx, pool, tenantID)
	if err != nil {
		t.Fatalf("FetchLocalAdminReport: %v", err)
	}
	got := map[string]LocalAdminDevice{}
	for _, d := range r.Devices {
		got[d.Hostname] = d
	}

	want := map[string]struct {
		verdict  string
		assessed int
		risk     string
	}{
		"WIN-DISABLED": {BuiltinAdminDisabled, 2, "compliant"},
		"WIN-ENABLED":  {BuiltinAdminEnabled, 3, "at-risk"},
		"WIN-UNKNOWN":  {BuiltinAdminUnknown, 3, "at-risk"},
		"WIN-ABSENT":   {BuiltinAdminUnknown, 3, "at-risk"},
		// macOS verdict is unchanged: count 3 is at-risk, as before PAT-1992.
		"MAC-1": {BuiltinAdminNotApplicable, 3, "at-risk"},
	}
	wantReported := map[string]int{"WIN-ENABLED-ONLY": 1}
	for host, w := range want {
		d, ok := got[host]
		if !ok {
			t.Fatalf("device %s missing from report", host)
		}
		if d.BuiltinAdmin != w.verdict || d.AdminCount != w.assessed || d.Risk != w.risk {
			t.Errorf("%s: got (verdict %s, count %d, risk %s), want (%s, %d, %s)",
				host, d.BuiltinAdmin, d.AdminCount, d.Risk, w.verdict, w.assessed, w.risk)
		}
		wr := 3
		if v, ok := wantReported[host]; ok {
			wr = v
		}
		if d.ReportedAdminCount != wr {
			t.Errorf("%s: ReportedAdminCount = %d, want %d (the signal as reported)", host, d.ReportedAdminCount, wr)
		}
	}

	// An enabled built-in as the only admin is never compliant.
	if d := got["WIN-ENABLED-ONLY"]; d.BuiltinAdmin != BuiltinAdminEnabled || d.AdminCount != 1 || d.Risk != "at-risk" {
		t.Errorf("WIN-ENABLED-ONLY: got (verdict %s, count %d, risk %s), want (enabled, 1, at-risk)", d.BuiltinAdmin, d.AdminCount, d.Risk)
	}
	// Only WIN-DISABLED is compliant; the enabled-only device is not counted there.
	if r.CompliantCount != 1 {
		t.Errorf("CompliantCount = %d, want 1 (WIN-DISABLED only)", r.CompliantCount)
	}
	if r.AtRiskCount != 5 {
		t.Errorf("AtRiskCount = %d, want 5", r.AtRiskCount)
	}
	if !strings.Contains(got["MAC-1"].BuiltinAdminNote, "macOS") {
		t.Errorf("MAC-1 note must state the macOS position explicitly, got %q", got["MAC-1"].BuiltinAdminNote)
	}
	if r.BuiltinEnabledCount != 2 {
		t.Errorf("BuiltinEnabledCount = %d, want 2", r.BuiltinEnabledCount)
	}
	if r.BuiltinDisabledExcludedCount != 1 {
		t.Errorf("BuiltinDisabledExcludedCount = %d, want 1", r.BuiltinDisabledExcludedCount)
	}

	recs := strings.Join(localAdminRecommendations(r), "\n")
	if !strings.Contains(recs, "built-in Administrator account enabled") {
		t.Errorf("recommendations must flag the enabled built-in Administrator; got:\n%s", recs)
	}
	line := builtinExcludedSummary(r)
	if !strings.HasPrefix(line, "1 Windows device(s) have a disabled built-in Administrator") {
		t.Errorf("excluded summary line: got %q", line)
	}
	if strings.ContainsRune(line+builtinAdminMethodNote, '\u2014') {
		t.Error("rendered built-in copy must not contain an em dash")
	}
	if builtinExcludedSummary(LocalAdminReport{}) != "" {
		t.Error("excluded summary must be empty when nothing was excluded")
	}
	if _, err := RenderLocalAdminPDF(r); err != nil {
		t.Errorf("RenderLocalAdminPDF: %v", err)
	}
}
