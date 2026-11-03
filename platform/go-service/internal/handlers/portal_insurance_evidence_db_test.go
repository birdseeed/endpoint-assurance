package handlers

// PAT-2258 contract tests for GET /v1/portal/insurance-evidence, the cyber
// insurance evidence pack, against a migrated Postgres:
//
//   - every answer agrees with the read model it names, for a seeded tenant
//     (computed here from the source read model's own output, and pinned to
//     hand-counted figures so an agreement between two wrong numbers still
//     fails);
//   - a device that has not reported within 14 days, and a retired device,
//     never count towards a positive figure even when their last evidence
//     was positive;
//   - the not-evidenced questions are always present;
//   - the tenant comes only from the portalauth identity, and one tenant's
//     devices never reach another's pack;
//   - ?format=csv is one row per question, with its basis; ?format=pdf is
//     the customer PDF.
//
// Skipped without TEST_DATABASE_URL unless PATCHED_DB_TESTS_REQUIRED is set.

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/lifecycle"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/remoteaccess"
	"patched.im/api/internal/report"
)

const iePath = "/v1/portal/insurance-evidence"

func ieDo(t *testing.T, pool *pgxpool.Pool, tenantID, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if tenantID != "" {
		req = req.WithContext(portalauth.WithIdentity(req.Context(),
			portalauth.Identity{Email: "viewer@pat2258.example", TenantID: tenantID}))
	}
	rec := httptest.NewRecorder()
	PortalInsuranceEvidenceHandler(pool).ServeHTTP(rec, req)
	return rec
}

func ieGet(t *testing.T, pool *pgxpool.Pool, tenantID string) report.InsuranceEvidence {
	t.Helper()
	rec := ieDo(t, pool, tenantID, iePath)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d (%s)", iePath, rec.Code, rec.Body.String())
	}
	var out report.InsuranceEvidence
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func ieFind(t *testing.T, p report.InsuranceEvidence, id string) report.InsuranceAnswer {
	t.Helper()
	for _, q := range p.Questions {
		if q.ID == id {
			return q
		}
	}
	t.Fatalf("question %s missing", id)
	return report.InsuranceAnswer{}
}

func ieWant(t *testing.T, a report.InsuranceAnswer, want map[string]int) {
	t.Helper()
	for k, v := range want {
		if got, ok := a.Answer.Counts[k]; !ok || got != v {
			t.Errorf("%s: counts[%s] = %d (present %v), want %d; all %v", a.ID, k, got, ok, v, a.Answer.Counts)
		}
	}
}

func ieSignal(t *testing.T, pool *pgxpool.Pool, deviceID, key, value string) {
	t.Helper()
	pocExec(t, pool, "seed signal "+key, `INSERT INTO compliance_signals (device_id, key, value) VALUES ($1::uuid, $2, $3)`,
		deviceID, key, value)
}

// ieEncryption seeds a device's disk-encryption evidence the way an agent's
// payload leaves it after the extractor has run (PAT-2496): the compliance
// signal under the key the agent really sends (filevault on macOS,
// bitlocker_os_drive on Windows, never "bitlocker") and the evaluation of the
// CIS disk-encryption rule over that signal. observed is the signal value; nil
// seeds the unreadable shape (no signal, a failed evaluation with no observed
// value).
func ieEncryption(t *testing.T, pool *pgxpool.Pool, deviceID, signalKey, ruleKey, status string, observed *string) {
	t.Helper()
	if observed != nil {
		ieSignal(t, pool, deviceID, signalKey, *observed)
	}
	pocExec(t, pool, "seed encryption evaluation "+ruleKey, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, benchmark_version)
		SELECT $1::uuid, r.id, $3, $4, r.severity, r.benchmark_version
		FROM compliance_rules r WHERE r.rule_key = $2`, deviceID, ruleKey, status, observed)
}

func ieTools(t *testing.T, pool *pgxpool.Pool, deviceID, toolsJSON string) {
	t.Helper()
	pocExec(t, pool, "seed security tools", `UPDATE devices SET security_inventory = $2::jsonb WHERE id = $1::uuid`,
		deviceID, `{"security_tools":`+toolsJSON+`}`)
}

const ieSophos = `[{"id":"sophos","name":"Sophos Intercept X"}]`

// ieSeed builds tenant A's estate:
//
//	mac-active   active    Sophos, FileVault on,  2 admins, critical CVE 40 days, macOS 13 (unsupported), AnyDesk
//	win-stale    3 days    unrecognised tool,     BitLocker off, 4 admins
//	mac-silent   30 days   Sophos, FileVault on,  1 admin    (positive but never counted)
//	mac-bare     active    no evidence at all
//	mac-retired  active    Sophos, FileVault on,  1 admin, retired (never counted)
//
// Disk encryption is seeded as agents deliver it (PAT-2496): FileVault under
// the signal key "filevault" and BitLocker under "bitlocker_os_drive", each
// with the evaluation of its CIS rule.
type ieEstate struct {
	tenant, active, stale, silent, bare, retired string
}

func ieSeed(t *testing.T, pool *pgxpool.Pool, label string) ieEstate {
	t.Helper()
	e := ieEstate{tenant: cerTenant(t, pool, "pat2258-"+label)}
	mk := func(host, osName, version, lastSeen string) string {
		var id string
		if err := pool.QueryRow(context.Background(), `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, arch, last_seen)
			VALUES ($1::uuid, $2, gen_random_uuid(), $3, $4, $5, 'arm64', `+lastSeen+`)
			RETURNING id::text`, e.tenant, "pat2258-"+pocSuffix(t), host+"-"+label, osName, version).Scan(&id); err != nil {
			t.Fatalf("seed device %s: %v", host, err)
		}
		return id
	}
	e.active = mk("mac-active", "macOS", "13.6.1", "now() - interval '1 hour'")
	e.stale = mk("win-stale", "Windows", "10.0.26100", "now() - interval '3 days'")
	e.silent = mk("mac-silent", "macOS", "26.0.1", "now() - interval '30 days'")
	e.bare = mk("mac-bare", "macOS", "26.0.1", "now() - interval '2 hours'")
	e.retired = mk("mac-retired", "macOS", "26.0.1", "now() - interval '1 hour'")
	pocRetire(t, pool, e.tenant, e.retired)

	on, off := "On", "Off"
	for _, id := range []string{e.active, e.silent, e.retired} {
		ieTools(t, pool, id, ieSophos)
		ieEncryption(t, pool, id, "filevault", "cis_macos_2_5_1_1_filevault", "pass", &on)
	}
	ieTools(t, pool, e.stale, `[{"id":"homegrown-av","name":"Homegrown AV"}]`)
	ieEncryption(t, pool, e.stale, "bitlocker_os_drive", "cis_win_18_10_11_bitlocker_os_drive", "fail", &off)
	ieSignal(t, pool, e.active, "local_admin_count", "2")
	ieSignal(t, pool, e.stale, "local_admin_count", "4")
	ieSignal(t, pool, e.silent, "local_admin_count", "1")
	ieSignal(t, pool, e.retired, "local_admin_count", "1")

	cerCVE(t, pool, e.active, "CRITICAL", "now() - interval '40 days'", "OldApp", "1.0", "2.0")

	raFP := func(deviceID, bundle, name string) {
		pocExec(t, pool, "seed installation "+bundle, `
			INSERT INTO software_installations
				(tenant_id, device_id, platform, identity_kind, identity_value_normalized, companion_value_normalized,
				 identity_fingerprint, current_name, current_version, first_seen_at, last_seen_at, provenance)
			VALUES ($1::uuid, $2::uuid, 'macos', 'macos_bundle', $3, '', encode(sha256(($2 || $3)::bytea), 'hex'),
			        $4, '1.0', now(), now(), 'inventory_payload')`, e.tenant, deviceID, bundle, name)
	}
	raFP(e.active, "com.philandro.anydesk", "AnyDesk")
	pocExec(t, pool, "seed app policy", `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy) VALUES ($1::uuid, 'com.philandro.anydesk', 'macos', 'unapproved')`, e.tenant)
	return e
}

// ieStoreMacOSLifecycle makes macOS 13 past end of support and 26 supported,
// through the migration's published macOS OS mapping.
func ieStoreMacOSLifecycle(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	now := time.Now().UTC()
	d := func(off time.Duration) *time.Time {
		x := now.Add(off)
		x = time.Date(x.Year(), x.Month(), x.Day(), 0, 0, 0, 0, time.UTC)
		return &x
	}
	yes, no := true, false
	if err := lifecycle.Store(context.Background(), pool, lifecycle.FetchedProduct{
		Slug: "macos", Label: "macOS", APIURL: "https://endoflife.date/api/v1/products/macos/",
		HTMLURL: "https://endoflife.date/macos", SchemaVersion: "1.2.1",
		Cycles: []lifecycle.Cycle{
			{Name: "26", IsEOL: &no, LatestVersion: "26.1"},
			{Name: "13", EOLDate: d(-100 * 24 * time.Hour), IsEOL: &yes, LatestVersion: "13.7.8"},
		},
	}, now.Add(-time.Hour)); err != nil {
		t.Fatalf("store macos lifecycle: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM lifecycle_products WHERE slug = 'macos'`)
	})
}

func TestPortalInsuranceEvidence_AgreesWithSourceReadModels(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	ieStoreMacOSLifecycle(t, pool)
	e := ieSeed(t, pool, "agree")
	ctx := context.Background()

	p := ieGet(t, pool, e.tenant)
	ce, err := report.FetchPortalCEReadiness(ctx, pool, e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	reporting := map[string]bool{}
	for _, d := range ce.Devices {
		reporting[d.DeviceID] = d.Reporting.Bucket == "active" || d.Reporting.Bucket == "stale"
	}
	if len(ce.Devices) != 4 || p.DevicesInScope != 4 || p.RetiredExcluded != 1 {
		t.Fatalf("scope: ce %d devices, pack %d in scope / %d retired; want 4 / 4 / 1", len(ce.Devices), p.DevicesInScope, p.RetiredExcluded)
	}

	// EDR: the EDR coverage report's own state, over in-scope reporting devices.
	edr, err := report.FetchEDRCoverageReport(ctx, pool, e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	covered := 0
	for _, d := range edr.Devices {
		if d.State == report.EDRStateCovered && reporting[d.DeviceID] {
			covered++
		}
	}
	if edr.Covered != 3 {
		t.Fatalf("seed check: EDR report covered = %d, want 3 (active, silent, retired)", edr.Covered)
	}
	a := ieFind(t, p, "edr_coverage")
	if covered != 1 || a.Answer.Value == nil || *a.Answer.Value != covered {
		t.Errorf("edr covered: pack %s, source-derived %d, want 1 (silent and retired never count)", ieInt(a.Answer.Value), covered)
	}
	ieWant(t, a, map[string]int{"devices_in_scope": 4, "covered": 1, "unrecognised_tool": 1, "no_evidence": 1, "not_reporting": 1})
	if a.UnknownDevices == nil || *a.UnknownDevices != 3 || a.Status != report.InsurancePartial {
		t.Errorf("edr unknown %s status %s, want 3 / partial", ieInt(a.UnknownDevices), a.Status)
	}
	if a.Answer.Percentage == nil || *a.Answer.Percentage != 25.0 {
		t.Errorf("edr percentage %v, want 25.0", ieFloat(a.Answer.Percentage))
	}

	// Encryption: the state the encryption report carries per device, which
	// comes from report.FetchEncryptionStates (PAT-2496). The pinned counts
	// below are hand-counted from the seed, so two wrong numbers agreeing
	// still fails.
	enc, err := report.FetchEncryptionPostureReport(ctx, pool, e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	encOn := 0
	for _, d := range enc.Devices {
		if d.State == report.EncryptionStateEncrypted && reporting[d.DeviceID] {
			encOn++
		}
	}
	a = ieFind(t, p, "disk_encryption")
	if encOn != 1 || a.Answer.Value == nil || *a.Answer.Value != encOn {
		t.Errorf("encrypted: pack %s, source-derived %d, want 1", ieInt(a.Answer.Value), encOn)
	}
	ieWant(t, a, map[string]int{"encrypted": 1, "not_encrypted": 1, "no_evidence": 1, "not_reporting": 1})
	// The one device observed off is named, by hostname; the silent device,
	// the retired device and the one with no evidence are not.
	if want := "Encryption is turned off on: win-stale-agree."; !strings.Contains(a.AnswerText, want) {
		t.Errorf("disk_encryption answer %q does not say %q", a.AnswerText, want)
	}
	for _, h := range []string{"mac-active-agree", "mac-silent-agree", "mac-bare-agree", "mac-retired-agree"} {
		if strings.Contains(a.AnswerText, h) {
			t.Errorf("disk_encryption answer names %s: %q", h, a.AnswerText)
		}
	}

	// Local admin: the local admin report's assessed count.
	adm, err := report.FetchLocalAdminReport(ctx, pool, e.tenant)
	if err != nil {
		t.Fatal(err)
	}
	accounts := 0
	for _, d := range adm.Devices {
		if d.AdminCount >= 0 && reporting[d.DeviceID] {
			accounts += d.AdminCount
		}
	}
	a = ieFind(t, p, "local_admin_rights")
	if accounts != 6 || a.Answer.Value == nil || *a.Answer.Value != accounts {
		t.Errorf("admin accounts: pack %s, source-derived %d, want 6", ieInt(a.Answer.Value), accounts)
	}
	ieWant(t, a, map[string]int{"devices_with_count": 2, "devices_2_or_fewer": 1, "devices_3_to_4": 1, "no_evidence": 1, "not_reporting": 1})

	// Patching: the CE readiness items.
	items := 0
	for _, d := range ce.Devices {
		items += len(d.Items)
	}
	a = ieFind(t, p, "patching_speed")
	if items != 1 || a.Answer.Value == nil || *a.Answer.Value != items {
		t.Errorf("updates over 14 days: pack %s, CE items %d, want 1", ieInt(a.Answer.Value), items)
	}
	ieWant(t, a, map[string]int{"updates_over_14_days": 1, "updates_over_30_days": 1, "critical_over_14_days": 1,
		"devices_over_14_days": 1, "devices_none_outstanding": 1, "devices_unknown": 2})

	// Unsupported: the lifecycle report's rows.
	life, err := lifecycle.Build(ctx, pool, e.tenant, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	unsupportedOS := 0
	for _, r := range life.Rows {
		if r.Kind == lifecycle.KindOperatingSystem && r.State == lifecycle.StateUnsupported {
			unsupportedOS++
		}
	}
	a = ieFind(t, p, "unsupported_software")
	ieWant(t, a, map[string]int{"devices_assessed": life.Basis.DevicesAssessed, "devices_unsupported_os": unsupportedOS})
	if unsupportedOS != 1 {
		t.Errorf("seed check: lifecycle unsupported OS = %d, want 1 (mac-active on macOS 13)", unsupportedOS)
	}

	// Remote access: the remote access report's summary.
	ra, err := remoteaccess.Build(ctx, pool, e.tenant, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	a = ieFind(t, p, "remote_access_tools")
	ieWant(t, a, map[string]int{"tools_found": ra.Summary.RemoteAccessToolCount,
		"unapproved_tools": ra.Summary.RemoteAccess[remoteaccess.StateUnapproved].Tools})
	if ra.Summary.RemoteAccessToolCount != 1 || a.Status == report.InsuranceEvidenced {
		t.Errorf("remote access: source tools %d, pack status %s; want 1 and never evidenced", ra.Summary.RemoteAccessToolCount, a.Status)
	}

	// Asset inventory: CE readiness buckets.
	a = ieFind(t, p, "asset_inventory")
	ieWant(t, a, map[string]int{"devices_in_scope": 4, "reported_24_hours": 2, "reported_14_days": 3, "not_reporting": 1, "retired_excluded": 1})

	// Every evidenced answer names its source path and freshness.
	for _, q := range p.Questions {
		if q.Group == report.InsuranceGroupEvidenced && (q.Source == nil || q.AsOf == nil || q.AnswerText == "" || q.Basis == "") {
			t.Errorf("%s: missing source/as_of/text/basis: %+v", q.ID, q)
		}
	}
	for _, id := range []string{"mfa", "email_security", "backups", "incident_response", "security_training"} {
		if q := ieFind(t, p, id); q.Status != report.InsuranceNotEvidenced {
			t.Errorf("%s: status %s, want not_evidenced_by_patched", id, q.Status)
		}
	}
}

func TestPortalInsuranceEvidence_TenantIsolation(t *testing.T) {
	pool := pocPool(t)
	a := ieSeed(t, pool, "iso-a")
	b := cerTenant(t, pool, "pat2258-iso-b")
	bDev := pocDevice(t, pool, b, "b-only", "macOS", "now() - interval '1 hour'", "")
	ieTools(t, pool, bDev, ieSophos)

	pa, pb := ieGet(t, pool, a.tenant), ieGet(t, pool, b)
	if pa.DevicesInScope != 4 || pb.DevicesInScope != 1 {
		t.Fatalf("in scope: A %d, B %d; want 4 / 1", pa.DevicesInScope, pb.DevicesInScope)
	}
	if v := ieFind(t, pb, "edr_coverage").Answer.Value; v == nil || *v != 1 {
		t.Errorf("B edr covered %s, want 1", ieInt(v))
	}
	if v := ieFind(t, pb, "local_admin_rights").Answer.Value; v == nil || *v != 0 {
		t.Errorf("B admin accounts %s, want 0 (A's accounts must not leak)", ieInt(v))
	}
	// A tenant hint in the query is refused, never honoured.
	if rec := ieDo(t, pool, b, iePath+"?tenant_id="+a.tenant); rec.Code != http.StatusBadRequest {
		t.Errorf("tenant hint: %d, want 400", rec.Code)
	}
	if rec := ieDo(t, pool, "", iePath); rec.Code != http.StatusUnauthorized {
		t.Errorf("no identity: %d, want 401", rec.Code)
	}
	if rec := ieDo(t, pool, b, iePath+"?format=xlsx"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad format: %d, want 400", rec.Code)
	}
}

func TestPortalInsuranceEvidence_CSVAndPDF(t *testing.T) {
	pool := pocPool(t)
	e := ieSeed(t, pool, "csv")
	p := ieGet(t, pool, e.tenant)

	rec := ieDo(t, pool, e.tenant, iePath+"?format=csv")
	if rec.Code != http.StatusOK || !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/csv") {
		t.Fatalf("csv: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	rows, err := csv.NewReader(bytes.NewReader(rec.Body.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("parse csv: %v", err)
	}
	if len(rows) != 1+len(p.Questions) || len(p.Questions) != len(report.InsuranceQuestionIDs()) {
		t.Fatalf("csv rows = %d, want header + %d questions", len(rows), len(p.Questions))
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[h] = i
	}
	for _, h := range []string{"question_id", "status", "answer_text", "counts", "unknown_devices", "as_of", "source_path", "basis"} {
		if _, ok := col[h]; !ok {
			t.Fatalf("csv header missing %q: %v", h, rows[0])
		}
	}
	for i, id := range report.InsuranceQuestionIDs() {
		r := rows[i+1]
		if r[col["question_id"]] != id || r[col["basis"]] == "" || r[col["answer_text"]] == "" {
			t.Errorf("csv row %d: id %q basis %q", i+1, r[col["question_id"]], r[col["basis"]])
		}
	}
	if got := rec.Header().Get("X-Patched-Export-Rows"); got != "12" {
		t.Errorf("X-Patched-Export-Rows = %q, want 12", got)
	}

	rec = ieDo(t, pool, e.tenant, iePath+"?format=pdf")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/pdf" ||
		!bytes.HasPrefix(rec.Body.Bytes(), []byte("%PDF")) {
		t.Fatalf("pdf: %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !bytes.Contains(rec.Body.Bytes(), []byte("/Width 512")) || bytes.Contains(rec.Body.Bytes(), []byte("/Width 1000")) {
		t.Errorf("portal PDF must carry the customer header, never the staff mark")
	}

	// The catalogue generation path renders the same pack.
	pdf, snap, err := renderPortalReport(context.Background(), pool, e.tenant, "insurance-evidence", nil)
	if err != nil || !bytes.HasPrefix(pdf, []byte("%PDF")) || snap["devices_in_scope"] != 4 {
		t.Errorf("renderPortalReport: err %v, snapshot %v", err, snap)
	}
}

func ieInt(p *int) string {
	if p == nil {
		return "null"
	}
	return strconv.Itoa(*p)
}

func ieFloat(p *float64) any {
	if p == nil {
		return "null"
	}
	return *p
}
