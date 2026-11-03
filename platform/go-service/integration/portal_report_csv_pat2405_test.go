//go:build integration

package integration

// PAT-2405 (platform half): every customer catalogue report is downloadable as
// PDF or CSV. These tests are written ahead of the implementation and go only
// through HTTP routes and SQL, so they compile today and fail on assertions.
//
// Proposed contract the tests pin (see the Phase A report for the rationale):
//   - GET /v1/portal/reports/{id}?format=pdf|csv, default pdf, anything else 400.
//   - csv: 200, "text/csv; charset=utf-8", attachment filename
//     "<sanitised name>.csv", first row a header, rectangular, every cell
//     passed through csvSafe.
//   - a record with no CSV: 404 with JSON {"error":"csv_not_available"} while the
//     PDF still downloads.
//   - history entries carry "formats": ["pdf","csv"] (or ["pdf"]).
//   - report_records.csv_path is stored as <tenant>/<record>/report.csv beside
//     report.pdf.

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"

	"patched.im/api/internal/handlers"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/reportsched"
)

const pat2405CSVContentType = "text/csv; charset=utf-8"

var pat2405UnsafeFilenameRune = regexp.MustCompile(`[^A-Za-z0-9._-]`)

// pat2405Filename mirrors handlers.sanitiseFilename (reports.go): every rune
// outside [A-Za-z0-9._-] becomes '_'.
func pat2405Filename(name string) string {
	return pat2405UnsafeFilenameRune.ReplaceAllString(name, "_")
}

type pat2405Download struct {
	status      int
	contentType string
	disposition string
	body        []byte
}

func pat2405Get(t *testing.T, token, id, query string) pat2405Download {
	t.Helper()
	path := "/v1/portal/reports/" + id
	if query != "" {
		path += "?" + query
	}
	resp := portalDo(t, http.MethodGet, path, token, nil)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return pat2405Download{
		status:      resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		disposition: resp.Header.Get("Content-Disposition"),
		body:        body,
	}
}

func (d pat2405Download) filename(t *testing.T) string {
	t.Helper()
	_, params, err := mime.ParseMediaType(d.disposition)
	if err != nil {
		t.Fatalf("Content-Disposition %q: %v", d.disposition, err)
	}
	return params["filename"]
}

func (d pat2405Download) isPDF() bool { return bytes.HasPrefix(d.body, []byte("%PDF-")) }

// pat2405Generate POSTs a report and returns its id.
func pat2405Generate(t *testing.T, token, reportType, name string) string {
	t.Helper()
	body := fmt.Sprintf(`{"report_type":%q,"name":%q}`, reportType, name)
	resp := portalDo(t, http.MethodPost, "/v1/portal/reports", token, strings.NewReader(body))
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("POST %s = %d: %s", reportType, resp.StatusCode, raw)
	}
	var out struct {
		ID string `json:"id"`
	}
	decodeJSON(t, resp, &out)
	if out.ID == "" {
		t.Fatalf("POST %s returned no id", reportType)
	}
	return out.ID
}

// pat2405CSV downloads ?format=csv, asserts the transport contract and
// returns the parsed table (header first). Rows must all be the header's
// width: a CSV here is one flat table.
func pat2405CSV(t *testing.T, token, id, wantStem string) (header []string, rows [][]string) {
	t.Helper()
	d := pat2405Get(t, token, id, "format=csv")
	if d.status != http.StatusOK {
		t.Fatalf("GET ?format=csv = %d, want 200 (body %.120q)", d.status, d.body)
	}
	if d.contentType != pat2405CSVContentType {
		t.Fatalf("csv Content-Type = %q, want %q", d.contentType, pat2405CSVContentType)
	}
	if want := pat2405Filename(wantStem) + ".csv"; d.filename(t) != want {
		t.Fatalf("csv filename = %q, want %q", d.filename(t), want)
	}
	if d.isPDF() {
		t.Fatalf("csv download body is a PDF")
	}
	table := pat2405ParseCSV(t, d.body)
	if len(table) == 0 {
		t.Fatalf("csv has no header row (empty body)")
	}
	pat2405AssertHeader(t, table[0])
	return table[0], table[1:]
}

func pat2405ParseCSV(t *testing.T, body []byte) [][]string {
	t.Helper()
	body = bytes.TrimPrefix(body, []byte("\xef\xbb\xbf")) // tolerate an Excel BOM
	r := csv.NewReader(bytes.NewReader(body))
	// FieldsPerRecord left at 0: every record must be as wide as the header.
	table, err := r.ReadAll()
	if err != nil {
		t.Fatalf("csv does not parse as a rectangular table: %v\n%.300s", err, body)
	}
	return table
}

func pat2405AssertHeader(t *testing.T, header []string) {
	t.Helper()
	if len(header) == 0 {
		t.Fatal("empty header row")
	}
	seen := map[string]bool{}
	for _, h := range header {
		if strings.TrimSpace(h) == "" {
			t.Fatalf("header has an empty column name: %q", header)
		}
		if seen[h] {
			t.Fatalf("header repeats column %q: %q", h, header)
		}
		seen[h] = true
	}
}

func pat2405Col(t *testing.T, header []string, name string) int {
	t.Helper()
	for i, h := range header {
		if h == name {
			return i
		}
	}
	t.Fatalf("header %q has no column %q", header, name)
	return -1
}

// pat2405Rows returns the rows whose column col equals val.
func pat2405Rows(rows [][]string, col int, val string) [][]string {
	var out [][]string
	for _, r := range rows {
		if r[col] == val {
			out = append(out, r)
		}
	}
	return out
}

func pat2405HistoryFormats(t *testing.T, token, id string) []string {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/reports?limit=200", token, nil)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET /v1/portal/reports = %d", resp.StatusCode)
	}
	var hist struct {
		Reports []struct {
			ID      string   `json:"id"`
			Formats []string `json:"formats"`
		} `json:"reports"`
	}
	decodeJSON(t, resp, &hist)
	for _, r := range hist.Reports {
		if r.ID == id {
			if r.Formats == nil {
				t.Fatalf("history entry %s has no formats array", id)
			}
			return r.Formats
		}
	}
	t.Fatalf("report %s missing from history", id)
	return nil
}

func pat2405ReportRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("REPORT_STORAGE_ROOT")
	if root == "" {
		t.Fatal("REPORT_STORAGE_ROOT not set by TestMain")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatalf("resolve REPORT_STORAGE_ROOT: %v", err)
	}
	return resolved
}

// pat2405CSVPath reads report_records.csv_path (NULL -> "").
func pat2405CSVPath(t *testing.T, id string) (path string, present bool) {
	t.Helper()
	var p *string
	if err := env.pool.QueryRow(t.Context(),
		`SELECT csv_path FROM report_records WHERE id = $1::uuid`, id).Scan(&p); err != nil {
		t.Fatalf("read report_records.csv_path for %s (column missing?): %v", id, err)
	}
	if p == nil {
		return "", false
	}
	return *p, true
}

func pat2405PortalCatalogueTypes(t *testing.T, token string) []string {
	t.Helper()
	resp := portalDo(t, http.MethodGet, "/v1/portal/reports/catalogue", token, nil)
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		t.Fatalf("GET catalogue = %d", resp.StatusCode)
	}
	var cat struct {
		Reports []struct {
			Type string `json:"type"`
		} `json:"reports"`
	}
	decodeJSON(t, resp, &cat)
	var types []string
	for _, r := range cat.Reports {
		types = append(types, r.Type)
	}
	if len(types) == 0 {
		t.Fatal("empty portal catalogue")
	}
	return types
}

// pat2405Seed gives a governance tenant (admin + viewer) a populated estate:
// two macOS devices and one Windows device, one CVE finding, and one
// approved-software policy.
type pat2405Estate struct {
	*govTenant
	macHosts []string
	winHost  string
	cveID    string
}

func pat2405SeedEstate(t *testing.T, label string) *pat2405Estate {
	t.Helper()
	g := newGovTenant(t, "csv-"+label, "")
	suffix := randomHex(3)
	e := &pat2405Estate{govTenant: g, cveID: "CVE-2099-24" + suffix[:4]}
	now := time.Now().UTC()
	var firstMac string
	for i := 0; i < 2; i++ {
		host := fmt.Sprintf("mac-%s-%d", suffix, i)
		id := govDevice(t, g.id, host, "macOS", now)
		if i == 0 {
			firstMac = id
		}
		e.macHosts = append(e.macHosts, host)
	}
	e.winHost = "win-" + suffix
	govDevice(t, g.id, e.winHost, "Windows", now)

	ctx := context.Background()
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity)
		VALUES ($1, 'pat2405 seeded vulnerability', 'nvd', 9.8, 'CRITICAL')
		ON CONFLICT (cve_id) DO NOTHING`, e.cveID); err != nil {
		t.Fatalf("seed cve: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, cvss_v3_score, severity)
		VALUES ($1::uuid, $2, 'VulnApp', '1.0.0', 9.8, 'CRITICAL')`, firstMac, e.cveID); err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, $2, 'macos', 'approved', 'report')`, g.id, "ApprovedThing-"+suffix); err != nil {
		t.Fatalf("seed approved policy: %v", err)
	}
	return e
}

func (e *pat2405Estate) approvedName() string {
	// the policy name seeded by pat2405SeedEstate
	var n string
	_ = env.pool.QueryRow(context.Background(),
		`SELECT name FROM tenant_app_policies WHERE tenant_id = $1::uuid AND policy = 'approved' AND name LIKE 'ApprovedThing-%'`, e.id).Scan(&n)
	return n
}

// ---------------------------------------------------------------------------
// (a) guard: every customer catalogue type has a CSV renderer
// ---------------------------------------------------------------------------

// TestPAT2405GuardEveryCatalogueTypeStoresACSV is the behavioural twin of
// TestPortalReportRenderersMatchCustomerCatalogue (a unit test that cannot be
// written until the CSV renderer map exists; see the Phase A report). It reads
// the catalogue from the API rather than a hard-coded list, so a fifteenth
// customer type with no CSV renderer fails here.
func TestPAT2405GuardEveryCatalogueTypeStoresACSV(t *testing.T) {
	e := pat2405SeedEstate(t, "guard")
	for _, reportType := range pat2405PortalCatalogueTypes(t, e.adminToken) {
		t.Run(reportType, func(t *testing.T) {
			id := pat2405Generate(t, e.adminToken, reportType, "guard "+reportType)
			path, present := pat2405CSVPath(t, id)
			if !present || path == "" {
				t.Fatalf("%s: report_records.csv_path is NULL, no CSV renderer ran", reportType)
			}
			if got := pat2405HistoryFormats(t, e.adminToken, id); !reflect.DeepEqual(got, []string{"pdf", "csv"}) {
				t.Fatalf("%s: history formats = %v, want [pdf csv]", reportType, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// (b) representative types: real rows and figures
// ---------------------------------------------------------------------------

func TestPAT2405CSVDeviceTableEncryptionPosture(t *testing.T) {
	e := pat2405SeedEstate(t, "devtable")
	id := pat2405Generate(t, e.adminToken, "encryption-posture", "Enc posture")
	header, rows := pat2405CSV(t, e.adminToken, id, "Enc posture")

	host, osCol := pat2405Col(t, header, "hostname"), pat2405Col(t, header, "os")
	var want int
	if err := env.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM devices WHERE tenant_id = $1::uuid`, e.id).Scan(&want); err != nil {
		t.Fatal(err)
	}
	if len(rows) != want {
		t.Fatalf("csv rows = %d, want one per device (%d)", len(rows), want)
	}
	for _, h := range e.macHosts {
		got := pat2405Rows(rows, host, h)
		if len(got) != 1 || got[0][osCol] != "macOS" {
			t.Fatalf("host %s rows = %v, want one macOS row", h, got)
		}
	}
	if got := pat2405Rows(rows, host, e.winHost); len(got) != 1 || got[0][osCol] != "Windows" {
		t.Fatalf("windows host rows = %v", got)
	}
}

func TestPAT2405CSVFindingsTableCVEReport(t *testing.T) {
	e := pat2405SeedEstate(t, "findings")
	id := pat2405Generate(t, e.adminToken, "cve-report", "CVE exposure")
	header, rows := pat2405CSV(t, e.adminToken, id, "CVE exposure")

	cve := pat2405Col(t, header, "cve_id")
	sev := pat2405Col(t, header, "severity")
	app := pat2405Col(t, header, "app_name")
	ver := pat2405Col(t, header, "app_version")
	host := pat2405Col(t, header, "hostname")
	got := pat2405Rows(rows, cve, e.cveID)
	if len(got) != 1 {
		t.Fatalf("rows for %s = %v, want exactly one (one device carries it)", e.cveID, got)
	}
	r := got[0]
	if !strings.EqualFold(r[sev], "critical") || r[app] != "VulnApp" || r[ver] != "1.0.0" || r[host] != e.macHosts[0] {
		t.Fatalf("finding row = %v, want critical VulnApp 1.0.0 on %s", r, e.macHosts[0])
	}
	if cvss := pat2405Col(t, header, "cvss"); !strings.Contains(r[cvss], "9.8") {
		t.Fatalf("cvss cell = %q, want 9.8", r[cvss])
	}
	if len(rows) != 1 {
		t.Fatalf("csv has %d data rows, want 1 (only one finding exists)", len(rows))
	}
}

func TestPAT2405CSVExecutiveSummaryIsMetricValue(t *testing.T) {
	e := pat2405SeedEstate(t, "exec")
	id := pat2405Generate(t, e.adminToken, "executive-summary", "Exec summary")
	header, rows := pat2405CSV(t, e.adminToken, id, "Exec summary")
	if !reflect.DeepEqual(header, []string{"metric", "value"}) {
		t.Fatalf("executive header = %q, want [metric value]", header)
	}
	value := func(contains ...string) string {
		t.Helper()
		for _, r := range rows {
			m := strings.ToLower(r[0])
			ok := true
			for _, c := range contains {
				ok = ok && strings.Contains(m, c)
			}
			if ok {
				return r[1]
			}
		}
		t.Fatalf("no metric containing %v in %v", contains, rows)
		return ""
	}
	if v := value("total", "devices"); v != "3" {
		t.Errorf("total devices = %q, want 3 (what the PDF's EstateStats held)", v)
	}
	if v := value("macos", "devices"); v != "2" {
		t.Errorf("macOS devices = %q, want 2", v)
	}
	if v := value("windows", "devices"); v != "1" {
		t.Errorf("Windows devices = %q, want 1", v)
	}
}

func TestPAT2405CSVSoftwareListApprovedSoftware(t *testing.T) {
	e := pat2405SeedEstate(t, "software")
	id := pat2405Generate(t, e.adminToken, "approved-software", "Approved list")
	header, rows := pat2405CSV(t, e.adminToken, id, "Approved list")
	name := pat2405Col(t, header, "name")
	platform := pat2405Col(t, header, "platform")
	got := pat2405Rows(rows, name, e.approvedName())
	if len(got) != 1 || got[0][platform] != "macos" {
		t.Fatalf("approved rows = %v, want one macos row named %q", got, e.approvedName())
	}
	// Every new tenant also carries the auto-approved Patched Agent policies
	// (PAT-1318), which the PDF lists too. Nothing else may appear.
	for _, r := range rows {
		if r[name] != e.approvedName() && !strings.Contains(strings.ToLower(r[name]), "patched") {
			t.Fatalf("unexpected approved row %v: want only %q and the Patched Agent entries", r, e.approvedName())
		}
	}
}

// ---------------------------------------------------------------------------
// (c) all 14 types, with data and with none
// ---------------------------------------------------------------------------

func TestPAT2405CSVEveryCatalogueTypeDownloads(t *testing.T) {
	e := pat2405SeedEstate(t, "all14")
	types := pat2405PortalCatalogueTypes(t, e.adminToken)
	if len(types) != 14 {
		t.Fatalf("catalogue has %d types, this test was written for 14", len(types))
	}
	for _, reportType := range types {
		t.Run(reportType, func(t *testing.T) {
			name := "All " + reportType
			id := pat2405Generate(t, e.adminToken, reportType, name)
			header, _ := pat2405CSV(t, e.adminToken, id, name)
			if len(header) < 2 {
				t.Fatalf("%s header has %d column(s): %q", reportType, len(header), header)
			}
		})
	}
}

func TestPAT2405CSVEmptyEstateKeepsHeaderRow(t *testing.T) {
	g := newGovTenant(t, "csv-empty", "") // no devices, no findings, no approvals
	e := &pat2405Estate{govTenant: g}
	for _, reportType := range pat2405PortalCatalogueTypes(t, e.adminToken) {
		t.Run(reportType, func(t *testing.T) {
			name := "Empty " + reportType
			id := pat2405Generate(t, e.adminToken, reportType, name)
			header, rows := pat2405CSV(t, e.adminToken, id, name)
			if reportType != "executive-summary" && reportType != "insurance-evidence" && len(rows) != 0 {
				// An estate with no data has no natural rows. The two summary
				// shaped reports legitimately carry metric/question rows.
				t.Logf("%s: %d data rows for an empty estate (header %q)", reportType, len(rows), header)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// (d) controls: default and ?format=pdf are the PDF, exactly as today
// ---------------------------------------------------------------------------

func TestPAT2405DefaultAndExplicitPDFAreUnchanged(t *testing.T) {
	e := pat2405SeedEstate(t, "pdf")
	id := pat2405Generate(t, e.adminToken, "patch-status", "Patch evidence")

	def := pat2405Get(t, e.adminToken, id, "")
	exp := pat2405Get(t, e.adminToken, id, "format=pdf")
	for label, d := range map[string]pat2405Download{"default": def, "format=pdf": exp} {
		if d.status != http.StatusOK || d.contentType != "application/pdf" || !d.isPDF() {
			t.Fatalf("%s: status %d type %q pdf=%v", label, d.status, d.contentType, d.isPDF())
		}
		if got := d.filename(t); got != "Patch_evidence.pdf" {
			t.Fatalf("%s: filename %q, want Patch_evidence.pdf", label, got)
		}
	}
	if !bytes.Equal(def.body, exp.body) {
		t.Fatal("default and ?format=pdf return different bytes")
	}
}

// ---------------------------------------------------------------------------
// (e) unknown formats are 400; the admin xlsx route is untouched
// ---------------------------------------------------------------------------

func TestPAT2405UnknownFormatIs400(t *testing.T) {
	e := pat2405SeedEstate(t, "badfmt")
	id := pat2405Generate(t, e.adminToken, "patch-status", "Bad format")
	for _, q := range []string{"format=xlsx", "format=anything-else", "format=CSV%20", "format=csv&format=xlsx"} {
		d := pat2405Get(t, e.adminToken, id, q)
		if d.status != http.StatusBadRequest {
			t.Errorf("?%s = %d (type %q), want 400", q, d.status, d.contentType)
		}
	}
}

func TestPAT2405AdminDownloadRouteIsUnaffected(t *testing.T) {
	e := pat2405SeedEstate(t, "adminxlsx")
	root := pat2405ReportRoot(t)

	var recID string
	if err := env.pool.QueryRow(context.Background(), `SELECT gen_random_uuid()::text`).Scan(&recID); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, e.id, recID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	xlsx := []byte("PK\x03\x04 pat2405 control workbook")
	pdf := []byte("%PDF-1.4 pat2405 control")
	for name, b := range map[string][]byte{"report.xlsx": xlsx, "report.pdf": pdf} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO report_records (id, tenant_id, name, recipient_summary, source, report_type, pdf_path, xlsx_path, issued_at)
		VALUES ($1::uuid, $2::uuid, 'Admin control', '[]', 'admin', 'executive-summary', $3, $4, now())`,
		recID, e.id, filepath.Join(e.id, recID, "report.pdf"), filepath.Join(e.id, recID, "report.xlsx")); err != nil {
		t.Fatalf("seed admin record: %v", err)
	}

	r := chi.NewRouter()
	r.Get("/admin/tenants/{tenantID}/report-records/{id}/download", handlers.DownloadReportHandler(env.pool))
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	get := func(q string) (int, string, []byte) {
		resp, err := http.Get(srv.URL + "/admin/tenants/" + e.id + "/report-records/" + recID + "/download?" + q)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("Content-Type"), b
	}
	code, ct, body := get("format=xlsx")
	if code != http.StatusOK || ct != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" || !bytes.Equal(body, xlsx) {
		t.Fatalf("admin xlsx = %d %q %q", code, ct, body)
	}
	code, ct, body = get("format=pdf")
	if code != http.StatusOK || ct != "application/pdf" || !bytes.Equal(body, pdf) {
		t.Fatalf("admin pdf = %d %q %q", code, ct, body)
	}
}

// ---------------------------------------------------------------------------
// (f) tenant scoping, roles, service identity
// ---------------------------------------------------------------------------

func TestPAT2405TenantScopingAndRoles(t *testing.T) {
	a := pat2405SeedEstate(t, "scopeA")
	b := pat2405SeedEstate(t, "scopeB")
	idA := pat2405Generate(t, a.adminToken, "encryption-posture", "Scope A")
	idB := pat2405Generate(t, b.adminToken, "encryption-posture", "Scope B")

	// Another tenant's id is not found, in either format, for any role.
	for _, who := range []struct{ label, token string }{{"admin B", b.adminToken}, {"viewer B", b.viewerToken}} {
		for _, q := range []string{"", "format=pdf", "format=csv"} {
			if d := pat2405Get(t, who.token, idA, q); d.status != http.StatusNotFound {
				t.Errorf("%s GET tenant A report ?%s = %d, want 404", who.label, q, d.status)
			}
		}
	}
	for _, q := range []string{"format=pdf", "format=csv"} {
		if d := pat2405Get(t, a.adminToken, idB, q); d.status != http.StatusNotFound {
			t.Errorf("admin A GET tenant B report ?%s = %d, want 404", q, d.status)
		}
	}
	for _, id := range []string{"00000000-0000-4000-8000-000000000000", "not-a-uuid"} {
		if d := pat2405Get(t, a.adminToken, id, "format=csv"); d.status != http.StatusNotFound {
			t.Errorf("csv for %q = %d, want 404", id, d.status)
		}
	}

	// Any role may download their own tenant's report, both formats.
	for _, who := range []struct{ label, token string }{{"admin", a.adminToken}, {"viewer", a.viewerToken}} {
		if d := pat2405Get(t, who.token, idA, "format=pdf"); d.status != http.StatusOK || !d.isPDF() {
			t.Errorf("%s pdf = %d pdf=%v, want 200 PDF", who.label, d.status, d.isPDF())
		}
		header, _ := pat2405CSV(t, who.token, idA, "Scope A")
		_ = header
	}
}

// TestPAT2405ServiceIdentityDownloads: today the read-only service identity
// (GET and HEAD only, one tenant) can download a tenant's report PDF because
// the download is a plain GET. The CSV is the same route and the same method,
// so it must be exactly as reachable, and no more: not another tenant's.
func TestPAT2405ServiceIdentityDownloads(t *testing.T) {
	a := pat2405SeedEstate(t, "svcA")
	b := pat2405SeedEstate(t, "svcB")
	idA := pat2405Generate(t, a.adminToken, "encryption-posture", "Service A")
	idB := pat2405Generate(t, b.adminToken, "encryption-posture", "Service B")

	const cn = "walker-pat2405.access" // placeholder
	v := portalauth.New(env.idp.issuer, env.idp.audience, env.idp.srv.URL).
		WithService(&portalauth.ServiceIdentity{CommonName: cn, TenantID: a.id})
	r := chi.NewRouter()
	r.Route("/v1/portal", func(pr chi.Router) {
		pr.Use(portalauth.Middleware(v, portalauth.DBLookup(env.pool), nil, portalauth.DBAudit(env.pool),
			portalauth.WithServiceTenantCheck(portalauth.DBTenantLive(env.pool))))
		pr.Get("/reports", handlers.PortalReportsListHandler(env.pool))
		pr.Get("/reports/{id}", handlers.PortalReportDownloadHandler(env.pool))
	})
	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	token := env.idp.tokenWith(t, jwt.MapClaims{
		"iss": env.idp.issuer, "aud": env.idp.audience, "common_name": cn,
		"sub": "", "type": "app",
		"iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(10 * time.Minute).Unix(),
	})
	get := func(id, q string) pat2405Download {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/portal/reports/"+id+"?"+q, nil)
		req.Header.Set(portalauth.Header, token)
		req.Header.Set("X-Tenant-ID", b.id) // must be ignored
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return pat2405Download{resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Content-Disposition"), body}
	}

	if d := get(idA, "format=pdf"); d.status != http.StatusOK || !d.isPDF() {
		t.Fatalf("service pdf = %d pdf=%v, want 200 PDF (current behaviour)", d.status, d.isPDF())
	}
	d := get(idA, "format=csv")
	if d.status != http.StatusOK || d.contentType != pat2405CSVContentType || d.isPDF() {
		t.Fatalf("service csv = %d %q pdf=%v, want 200 text/csv", d.status, d.contentType, d.isPDF())
	}
	for _, q := range []string{"format=pdf", "format=csv"} {
		if d := get(idB, q); d.status != http.StatusNotFound {
			t.Errorf("service identity GET other tenant ?%s = %d, want 404", q, d.status)
		}
	}
}

// ---------------------------------------------------------------------------
// (g) a record with no CSV
// ---------------------------------------------------------------------------

// pat2405LegacyRecord inserts an issued portal record that has a PDF and no
// csv_path, the shape of every report generated before this change. It names
// no csv_path column so it runs before and after the migration.
func pat2405LegacyRecord(t *testing.T, e *pat2405Estate) string {
	t.Helper()
	src := pat2405Generate(t, e.adminToken, "patch-status", "Legacy source")
	pdf := pat2405Get(t, e.adminToken, src, "format=pdf")
	if !pdf.isPDF() {
		t.Fatal("could not obtain a PDF to seed the legacy record")
	}
	var id string
	if err := env.pool.QueryRow(context.Background(), `SELECT gen_random_uuid()::text`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(pat2405ReportRoot(t), e.id, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "report.pdf"), pdf.body, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(context.Background(), `
		INSERT INTO report_records (id, tenant_id, name, recipient_summary, source, report_type, pdf_path, issued_at)
		VALUES ($1::uuid, $2::uuid, 'Legacy report', '[]', 'portal', 'patch-status', $3, now())`,
		id, e.id, filepath.Join(e.id, id, "report.pdf")); err != nil {
		t.Fatalf("seed legacy record: %v", err)
	}
	return id
}

func TestPAT2405RecordWithoutCSVAnswers404ButPDFStillDownloads(t *testing.T) {
	e := pat2405SeedEstate(t, "legacy")
	id := pat2405LegacyRecord(t, e)

	d := pat2405Get(t, e.adminToken, id, "format=csv")
	if d.status != http.StatusNotFound {
		t.Fatalf("csv for a record with no csv_path = %d (type %q), want 404", d.status, d.contentType)
	}
	if !strings.HasPrefix(d.contentType, "application/json") {
		t.Fatalf("404 Content-Type = %q, want application/json", d.contentType)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(d.body, &body); err != nil || body.Error != "csv_not_available" {
		t.Fatalf("404 body = %q, want JSON error code csv_not_available (err %v)", d.body, err)
	}

	for _, q := range []string{"", "format=pdf"} {
		if p := pat2405Get(t, e.adminToken, id, q); p.status != http.StatusOK || !p.isPDF() {
			t.Fatalf("legacy pdf ?%s = %d pdf=%v, want 200 PDF", q, p.status, p.isPDF())
		}
	}
	if got := pat2405HistoryFormats(t, e.adminToken, id); !reflect.DeepEqual(got, []string{"pdf"}) {
		t.Fatalf("legacy history formats = %v, want [pdf]", got)
	}
}

// ---------------------------------------------------------------------------
// (h) history formats for a new record
// ---------------------------------------------------------------------------

func TestPAT2405HistoryListsBothFormatsForNewRecord(t *testing.T) {
	e := pat2405SeedEstate(t, "history")
	id := pat2405Generate(t, e.adminToken, "stale-endpoints", "History formats")
	if got := pat2405HistoryFormats(t, e.adminToken, id); !reflect.DeepEqual(got, []string{"pdf", "csv"}) {
		t.Fatalf("history formats = %v, want [pdf csv]", got)
	}
}

// ---------------------------------------------------------------------------
// (i) scheduled generation produces both files
// ---------------------------------------------------------------------------

func TestPAT2405ScheduledRunProducesBothFiles(t *testing.T) {
	ctx := context.Background()
	e := pat2405SeedEstate(t, "sched")
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO portal_report_schedules (tenant_id, cadence, weekday, hour_utc, enabled, next_run_at)
		VALUES ($1::uuid, 'weekly', 1, 7, true, $2)`, e.id, time.Now().UTC().Add(-time.Hour)); err != nil {
		t.Fatalf("seed schedule: %v", err)
	}
	reportsched.New(env.pool, handlers.PortalReportGenerator(env.pool)).Sweep(ctx)

	var id, name, pdfPath string
	if err := env.pool.QueryRow(ctx, `
		SELECT id::text, name, pdf_path FROM report_records
		WHERE tenant_id = $1::uuid AND source = 'portal' AND schedule_slot IS NOT NULL`, e.id).Scan(&id, &name, &pdfPath); err != nil {
		t.Fatalf("no scheduled record: %v", err)
	}
	csvPath, present := pat2405CSVPath(t, id)
	if !present {
		t.Fatal("scheduled record has no csv_path")
	}
	if filepath.Dir(csvPath) != filepath.Dir(pdfPath) {
		t.Fatalf("scheduled csv %q not beside pdf %q", csvPath, pdfPath)
	}
	if _, err := os.Stat(filepath.Join(pat2405ReportRoot(t), csvPath)); err != nil {
		t.Fatalf("scheduled csv file missing: %v", err)
	}
	if got := pat2405HistoryFormats(t, e.adminToken, id); !reflect.DeepEqual(got, []string{"pdf", "csv"}) {
		t.Fatalf("scheduled history formats = %v", got)
	}
	pat2405CSV(t, e.adminToken, id, name)
}

// ---------------------------------------------------------------------------
// (j) formula neutralisation
// ---------------------------------------------------------------------------

func TestPAT2405CSVNeutralisesFormulaCells(t *testing.T) {
	g := newGovTenant(t, "csv-formula", "")
	ctx := context.Background()
	suffix := randomHex(3)
	payloads := []string{"=1+1", "+cmd|calc", "-2+3", "@SUM(A1)"}

	var firstDevice string
	for i, p := range payloads {
		id := govDevice(t, g.id, fmt.Sprintf("%s-host%d-%s", p, i, suffix), "macOS", time.Now().UTC())
		if i == 0 {
			firstDevice = id
		}
	}
	cve := "CVE-2099-25" + suffix[:4]
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity)
		VALUES ($1, 'formula test', 'nvd', 7.5, 'HIGH') ON CONFLICT (cve_id) DO NOTHING`, cve); err != nil {
		t.Fatal(err)
	}
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, cvss_v3_score, severity)
		VALUES ($1::uuid, $2, '=HYPERLINK("http://x")', '1.0', 7.5, 'HIGH')`, firstDevice, cve); err != nil {
		t.Fatal(err)
	}
	approved := "@approved-" + suffix
	if _, err := env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, $2, 'macos', 'approved', 'report')`, g.id, approved); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		reportType string
		col        string
		wants      []string // original cell values, each must appear as "'"+value
	}{
		{"encryption-posture", "hostname", func() []string {
			var w []string
			for i, p := range payloads {
				w = append(w, fmt.Sprintf("%s-host%d-%s", p, i, suffix))
			}
			return w
		}()},
		{"cve-report", "app_name", []string{`=HYPERLINK("http://x")`}},
		{"approved-software", "name", []string{approved}},
	} {
		t.Run(tc.reportType, func(t *testing.T) {
			name := "Formula " + tc.reportType
			id := pat2405Generate(t, g.adminToken, tc.reportType, name)
			header, rows := pat2405CSV(t, g.adminToken, id, name)
			col := pat2405Col(t, header, tc.col)
			for _, want := range tc.wants {
				// The hostnames above start with the payload, so they are the
				// dangerous leading character cases; the stored cell must be
				// the csvSafe form: a single quote, then the original text.
				if got := pat2405Rows(rows, col, "'"+want); len(got) != 1 {
					t.Errorf("%s: no neutralised cell %q in column %s; cells: %v", tc.reportType, "'"+want, tc.col, pat2405ColumnValues(rows, col))
				}
				if got := pat2405Rows(rows, col, want); len(got) != 0 {
					t.Errorf("%s: raw formula cell %q present", tc.reportType, want)
				}
			}
			for _, r := range rows {
				for _, cell := range r {
					if cell != "" && strings.ContainsRune("=+-@\t\r", rune(cell[0])) {
						t.Errorf("%s: cell %q starts with a formula character", tc.reportType, cell)
					}
				}
			}
		})
	}
}

func pat2405ColumnValues(rows [][]string, col int) []string {
	var out []string
	for _, r := range rows {
		out = append(out, r[col])
	}
	return out
}

// ---------------------------------------------------------------------------
// (k) storage layout: beside the PDF, nowhere else, never from user input
// ---------------------------------------------------------------------------

func TestPAT2405CSVIsStoredBesideThePDFAndNowhereElse(t *testing.T) {
	e := pat2405SeedEstate(t, "storage")
	hostile := "../../../etc/cron.d/x\\..\\y;report"
	id := pat2405Generate(t, e.adminToken, "encryption-posture", hostile)

	var pdfPath string
	if err := env.pool.QueryRow(context.Background(),
		`SELECT pdf_path FROM report_records WHERE id = $1::uuid`, id).Scan(&pdfPath); err != nil {
		t.Fatal(err)
	}
	csvPath, present := pat2405CSVPath(t, id)
	if !present {
		t.Fatal("csv_path is NULL")
	}
	if want := filepath.Join(e.id, id, "report.csv"); csvPath != want {
		t.Fatalf("csv_path = %q, want exactly %q (tenant/record/report.csv, nothing from the report name)", csvPath, want)
	}
	if filepath.Dir(csvPath) != filepath.Dir(pdfPath) {
		t.Fatalf("csv %q is not beside pdf %q", csvPath, pdfPath)
	}

	root := pat2405ReportRoot(t)
	if b, err := os.ReadFile(filepath.Join(root, csvPath)); err != nil || len(b) == 0 {
		t.Fatalf("csv file not on disk at %s: %v", csvPath, err)
	}

	// Nothing named report.csv anywhere under the root belongs to this record
	// except the one file, and nothing about this record exists outside the
	// tenant/record directory.
	var found []string
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.Contains(p, id) {
			rel, _ := filepath.Rel(root, p)
			found = append(found, rel)
		}
		return nil
	})
	wantFiles := map[string]bool{
		filepath.Join(e.id, id, "report.pdf"): true,
		filepath.Join(e.id, id, "report.csv"): true,
	}
	if len(found) != len(wantFiles) {
		t.Fatalf("files for record: %v, want exactly %v", found, wantFiles)
	}
	for _, f := range found {
		if !wantFiles[f] {
			t.Fatalf("unexpected file %q for record; want %v", f, wantFiles)
		}
	}

	// The hostile name only ever reaches the Content-Disposition, sanitised.
	d := pat2405Get(t, e.adminToken, id, "format=csv")
	if d.status != http.StatusOK {
		t.Fatalf("csv = %d", d.status)
	}
	got := d.filename(t)
	if got != pat2405Filename(hostile)+".csv" {
		t.Fatalf("filename = %q", got)
	}
	if strings.ContainsAny(got, `/\;`) {
		t.Fatalf("filename %q carries path or header-breaking characters", got)
	}
}

// ---------------------------------------------------------------------------
// audit: a CSV download is audited exactly like the PDF's
// ---------------------------------------------------------------------------

func TestPAT2405CSVDownloadIsAuditedLikeThePDF(t *testing.T) {
	e := pat2405SeedEstate(t, "audit")
	id := pat2405Generate(t, e.adminToken, "encryption-posture", "Audit csv")

	count := func() int {
		var n int
		if err := env.pool.QueryRow(context.Background(), `
			SELECT count(*) FROM portal_access_log
			WHERE email = $1 AND tenant_id = $2::uuid AND method = 'GET' AND status = 200
			  AND route LIKE '%/reports/%' AND route NOT LIKE '%catalogue%' AND route NOT LIKE '%schedule%'`,
			e.adminEmail, e.id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	waitFor := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for count() < want {
			if time.Now().After(deadline) {
				t.Fatalf("audit rows = %d, want >= %d", count(), want)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	base := count()
	if d := pat2405Get(t, e.adminToken, id, "format=pdf"); d.status != http.StatusOK {
		t.Fatalf("pdf = %d", d.status)
	}
	waitFor(base + 1)
	pat2405CSV(t, e.adminToken, id, "Audit csv") // asserts a real CSV came back
	waitFor(base + 2)
}
