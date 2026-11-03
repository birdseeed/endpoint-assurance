package handlers

// PAT-2405: POST /v1/portal/exports/table-pdf. No database needed: the
// handler's two lookups (the caller's role and the tenant's display name)
// are injected, so these tests fake them and drive the real decode,
// validation and renderer.

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"patched.im/api/internal/portalauth"
)

const (
	tablePDFTenantA = "00000000-0000-4000-8000-0000000000aa"
	tablePDFTenantB = "00000000-0000-4000-8000-0000000000bb"
)

// tablePDFTestRouter mounts the handler the way cmd/patched-api does (POST
// only, under /v1/portal), with fake lookups: roles by email, tenant names by
// tenant id.
func tablePDFTestRouter(roles map[string]string) http.Handler {
	deps := portalTablePDFDeps{
		role: func(_ context.Context, id portalauth.Identity) (string, error) {
			if r, ok := roles[id.Email]; ok {
				return r, nil
			}
			return portalauth.RoleViewer, nil
		},
		tenantName: func(_ context.Context, tenantID string) (string, error) {
			return map[string]string{tablePDFTenantA: "Acme Tenant Alpha", tablePDFTenantB: "Bravo Tenant Beta"}[tenantID], nil
		},
		now: func() time.Time { return time.Date(2026, 10, 4, 21, 5, 0, 0, time.UTC) },
	}
	r := chi.NewRouter()
	r.Route("/v1/portal", func(pr chi.Router) {
		pr.Post("/exports/table-pdf", portalTablePDFHandler(deps))
	})
	return r
}

func tablePDFRequest(t *testing.T, h http.Handler, method string, id *portalauth.Identity, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/v1/portal/exports/table-pdf", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if id != nil {
		req = req.WithContext(portalauth.WithIdentity(req.Context(), *id))
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func tablePDFBody(t *testing.T, v map[string]any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func tablePDFValid(export string) map[string]any {
	return map[string]any{
		"export":  export,
		"filters": []map[string]string{{"label": "Platform", "value": "macOS"}},
		"columns": []string{"Hostname", "Platform"},
		"rows":    [][]string{{"mac-01", "macOS"}, {"mac-02", "macOS"}},
	}
}

var reTablePDFStream = regexp.MustCompile(`(?s)stream\r?\n(.*?)\r?\nendstream`)

// tablePDFHasText reports whether needle is drawn as text in a PDF from this
// repo's renderers. They write text through an embedded UTF-8 font, so a
// string appears in a (deflated) content stream as its UTF-16BE bytes. Good
// for plain ASCII needles with no parentheses or backslashes, which is all
// these tests look for.
func tablePDFHasText(t *testing.T, pdf []byte, needle string) bool {
	t.Helper()
	var want []byte
	for _, c := range []byte(needle) {
		want = append(want, 0, c)
	}
	for _, m := range reTablePDFStream.FindAllSubmatch(pdf, -1) {
		zr, err := zlib.NewReader(bytes.NewReader(m[1]))
		if err != nil {
			continue
		}
		raw, _ := io.ReadAll(zr)
		zr.Close()
		if bytes.Contains(raw, want) {
			return true
		}
	}
	return false
}

func assertTablePDFError(t *testing.T, rr *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if rr.Code != status {
		t.Fatalf("status = %d, want %d; body %q", rr.Code, status, rr.Body.String())
	}
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil || e.Error != code {
		t.Fatalf("error body = %q, want code %q", rr.Body.String(), code)
	}
}

var (
	tablePDFViewer = portalauth.Identity{Email: "viewer@acme.example", TenantID: tablePDFTenantA}
	tablePDFAdmin  = portalauth.Identity{Email: "admin@acme.example", TenantID: tablePDFTenantA}
	tablePDFRoles  = map[string]string{"admin@acme.example": portalauth.RoleAdmin}
)

// The portal contract names exactly these sixteen exports and the title each
// prints with. A key added, dropped or renamed here must be a deliberate
// change to both services.
func TestPortalTableExports_AllowListIsExactlyTheContract(t *testing.T) {
	want := map[string]string{
		"devices":                        "Devices",
		"devices-stale":                  "Stale devices",
		"jamf-coverage":                  "Jamf coverage",
		"findings":                       "Findings",
		"homebrew":                       "Homebrew packages",
		"local-admins":                   "Local administrators",
		"ai-tooling":                     "AI tooling",
		"ai-tooling-device":              "AI tooling on one device",
		"software-unsupported":           "Unsupported software",
		"software-unsupported-devices":   "Unsupported software: installations",
		"software-remote-access":         "Remote access software",
		"software-remote-access-devices": "Remote access software: installations",
		"software-version-sprawl":        "Software version sprawl",
		"software-duplicate-tools":       "Duplicate tools",
		"software-publishers":            "Software publishers",
		"software-publishers-devices":    "Software publishers: installations",
	}
	if len(portalTableExports) != 16 || len(want) != 16 {
		t.Fatalf("allow-list has %d keys, contract has %d, want 16", len(portalTableExports), len(want))
	}
	for key, title := range want {
		got, ok := portalTableExports[key]
		if !ok {
			t.Errorf("allow-list is missing %q", key)
			continue
		}
		if got.title != title {
			t.Errorf("%q title = %q, want %q", key, got.title, title)
		}
		if got.adminOnly != (key == "local-admins") {
			t.Errorf("%q adminOnly = %v", key, got.adminOnly)
		}
	}
}

func TestPortalTablePDF_EveryAllowListedKeyRenders(t *testing.T) {
	h := tablePDFTestRouter(tablePDFRoles)
	keys := make([]string, 0, len(portalTableExports))
	for k := range portalTableExports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		t.Fatal("allow-list is empty")
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			rr := tablePDFRequest(t, h, http.MethodPost, &tablePDFAdmin, tablePDFBody(t, tablePDFValid(key)))
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, body %q", rr.Code, rr.Body.String())
			}
			if ct := rr.Header().Get("Content-Type"); ct != "application/pdf" {
				t.Errorf("Content-Type = %q", ct)
			}
			if cd := rr.Header().Get("Content-Disposition"); cd != `attachment; filename="`+key+`.pdf"` {
				t.Errorf("Content-Disposition = %q", cd)
			}
			if cc := rr.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
			pdf := rr.Body.Bytes()
			if !bytes.HasPrefix(pdf, []byte("%PDF-")) {
				t.Fatalf("body is not a PDF: %q", pdf[:min(len(pdf), 16)])
			}
			for _, needle := range []string{portalTableExports[key].title, "Acme Tenant Alpha", "mac-02", "Hostname", "Platform: macOS"} {
				if !tablePDFHasText(t, pdf, needle) {
					t.Errorf("PDF does not show %q", needle)
				}
			}
		})
	}
}

func TestPortalTablePDF_RefusesBadRequests(t *testing.T) {
	h := tablePDFTestRouter(tablePDFRoles)
	with := func(mut func(m map[string]any)) string {
		m := tablePDFValid("devices")
		mut(m)
		return tablePDFBody(t, m)
	}
	cols := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "c"
		}
		return out
	}
	manyRows := func(n int) [][]string {
		out := make([][]string, n)
		for i := range out {
			out[i] = []string{"a", "b"}
		}
		return out
	}
	manyFilters := func(n int) []map[string]string {
		out := make([]map[string]string, n)
		for i := range out {
			out[i] = map[string]string{"label": "l", "value": "v"}
		}
		return out
	}
	cases := map[string]string{
		"unknown export key":       with(func(m map[string]any) { m["export"] = "invoices" }),
		"missing export key":       with(func(m map[string]any) { delete(m, "export") }),
		"key differing in case":    with(func(m map[string]any) { m["export"] = "Devices" }),
		"unknown top-level field":  with(func(m map[string]any) { m["title"] = "Mine" }),
		"tenant hint in the body":  with(func(m map[string]any) { m["tenant_id"] = tablePDFTenantB }),
		"missing columns":          with(func(m map[string]any) { delete(m, "columns"); m["rows"] = [][]string{} }),
		"empty columns":            with(func(m map[string]any) { m["columns"] = []string{}; m["rows"] = [][]string{} }),
		"blank column name":        with(func(m map[string]any) { m["columns"] = []string{"Hostname", "  "} }),
		"121-character column":     with(func(m map[string]any) { m["columns"] = []string{"Hostname", strings.Repeat("n", 121)} }),
		"41 columns":               with(func(m map[string]any) { m["columns"] = cols(41); m["rows"] = [][]string{} }),
		"ragged row (short)":       with(func(m map[string]any) { m["rows"] = [][]string{{"a", "b"}, {"a"}} }),
		"ragged row (long)":        with(func(m map[string]any) { m["rows"] = [][]string{{"a", "b", "c"}} }),
		"null row":                 with(func(m map[string]any) { m["rows"] = []any{nil} }),
		"non-string cell":          with(func(m map[string]any) { m["rows"] = []any{[]any{"a", 1}} }),
		"missing rows":             with(func(m map[string]any) { delete(m, "rows") }),
		"10001 rows":               with(func(m map[string]any) { m["rows"] = manyRows(10001) }),
		"21 filters":               with(func(m map[string]any) { m["filters"] = manyFilters(21) }),
		"unknown field in filter":  with(func(m map[string]any) { m["filters"] = []map[string]string{{"label": "l", "value": "v", "x": "y"}} }),
		"negative total_rows":      with(func(m map[string]any) { m["total_rows"] = -1 }),
		"malformed JSON":           `{"export":"devices","columns":["a"],"rows":[["x"]`,
		"empty body":               ``,
		"not an object":            `[]`,
		"trailing second document": tablePDFBody(t, tablePDFValid("devices")) + `{"export":"devices"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			assertTablePDFError(t, tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, body), http.StatusBadRequest, "invalid_request")
		})
	}
}

func TestPortalTablePDF_LimitsAreInclusive(t *testing.T) {
	h := tablePDFTestRouter(tablePDFRoles)
	cols := make([]string, 40)
	row := make([]string, 40)
	for i := range cols {
		cols[i], row[i] = "c", "v"
	}
	filters := make([]map[string]string, 20)
	for i := range filters {
		filters[i] = map[string]string{"label": "l", "value": "v"}
	}
	rr := tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, tablePDFBody(t, map[string]any{
		"export": "findings", "columns": cols, "rows": [][]string{row}, "filters": filters, "total_rows": 5}))
	if rr.Code != http.StatusOK {
		t.Fatalf("40 columns and 20 filters = %d, want 200; body %q", rr.Code, rr.Body.String())
	}
	if !tablePDFHasText(t, rr.Body.Bytes(), "first 1 of 5 rows") {
		t.Errorf("total_rows above the rows sent must print the first N of M notice")
	}
	// Zero rows is a valid export.
	rr = tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, tablePDFBody(t, map[string]any{
		"export": "findings", "columns": []string{"CVE"}, "rows": [][]string{}}))
	if rr.Code != http.StatusOK || !tablePDFHasText(t, rr.Body.Bytes(), "No rows for this selection") {
		t.Fatalf("zero rows = %d, want a 200 PDF saying there are no rows", rr.Code)
	}
}

func TestPortalTablePDF_TenThousandRowsAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("renders a 10,000-row PDF")
	}
	h := tablePDFTestRouter(tablePDFRoles)
	rows := make([][]string, 10000)
	for i := range rows {
		rows[i] = []string{"host", "macOS"}
	}
	m := tablePDFValid("devices")
	m["rows"] = rows
	rr := tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, tablePDFBody(t, m))
	if rr.Code != http.StatusOK {
		t.Fatalf("10000 rows = %d, want 200; body %q", rr.Code, rr.Body.String())
	}
}

func TestPortalTablePDF_BodyOverSixteenMiBIs413(t *testing.T) {
	h := tablePDFTestRouter(tablePDFRoles)
	body := `{"export":"devices","columns":["a"],"rows":[["` + strings.Repeat("x", 16<<20) + `"]]}`
	rr := tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, body)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body = %d, want 413; body %q", rr.Code, rr.Body.String())
	}
}

func TestPortalTablePDF_LocalAdminsIsAdminOnly(t *testing.T) {
	h := tablePDFTestRouter(tablePDFRoles)
	body := tablePDFBody(t, tablePDFValid("local-admins"))

	assertTablePDFError(t, tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, body), http.StatusForbidden, "admin_role_required")

	// The service identity has no email and is never more than a viewer.
	svc := portalauth.Identity{TenantID: tablePDFTenantA, Service: "svc"}
	assertTablePDFError(t, tablePDFRequest(t, h, http.MethodPost, &svc, body), http.StatusForbidden, "admin_role_required")

	rr := tablePDFRequest(t, h, http.MethodPost, &tablePDFAdmin, body)
	if rr.Code != http.StatusOK || !bytes.HasPrefix(rr.Body.Bytes(), []byte("%PDF-")) {
		t.Fatalf("admin local-admins = %d, want a 200 PDF; body %q", rr.Code, rr.Body.String())
	}

	// Every other key is open to a viewer, as the page data is.
	rr = tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, tablePDFBody(t, tablePDFValid("devices")))
	if rr.Code != http.StatusOK {
		t.Fatalf("viewer devices = %d, want 200; body %q", rr.Code, rr.Body.String())
	}
}

// A failed role lookup must never fall through to rendering the roster.
func TestPortalTablePDF_RoleLookupFailureIs500NotAPDF(t *testing.T) {
	deps := portalTablePDFDeps{
		role:       func(context.Context, portalauth.Identity) (string, error) { return "", io.ErrUnexpectedEOF },
		tenantName: func(context.Context, string) (string, error) { return "Acme", nil },
		now:        time.Now,
	}
	rr := tablePDFRequest(t, portalTablePDFHandler(deps), http.MethodPost, &tablePDFAdmin, tablePDFBody(t, tablePDFValid("local-admins")))
	if rr.Code != http.StatusInternalServerError || bytes.Contains(rr.Body.Bytes(), []byte("%PDF-")) {
		t.Fatalf("role lookup failure = %d %q, want 500 and no PDF", rr.Code, rr.Body.String())
	}
}

func TestPortalTablePDF_TenantNameComesFromTheIdentityOnly(t *testing.T) {
	h := tablePDFTestRouter(tablePDFRoles)
	body := tablePDFBody(t, tablePDFValid("devices"))

	rrA := tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, body)
	idB := portalauth.Identity{Email: "viewer@bravo.example", TenantID: tablePDFTenantB}
	rrB := tablePDFRequest(t, h, http.MethodPost, &idB, body)
	if rrA.Code != http.StatusOK || rrB.Code != http.StatusOK {
		t.Fatalf("status A=%d B=%d", rrA.Code, rrB.Code)
	}
	if !tablePDFHasText(t, rrA.Body.Bytes(), "Acme Tenant Alpha") || tablePDFHasText(t, rrA.Body.Bytes(), "Bravo Tenant Beta") {
		t.Errorf("tenant A's PDF does not carry exactly tenant A's name")
	}
	if !tablePDFHasText(t, rrB.Body.Bytes(), "Bravo Tenant Beta") || tablePDFHasText(t, rrB.Body.Bytes(), "Acme Tenant Alpha") {
		t.Errorf("tenant B's PDF does not carry exactly tenant B's name")
	}

	// Every way a body or request might try to name another tenant is refused
	// or ignored; none of them changes whose name is printed.
	for _, field := range []string{"tenant", "tenant_id", "tenant_name", "title"} {
		m := tablePDFValid("devices")
		m[field] = "Bravo Tenant Beta"
		assertTablePDFError(t, tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, tablePDFBody(t, m)), http.StatusBadRequest, "invalid_request")
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/portal/exports/table-pdf?tenant_id="+tablePDFTenantB, strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", tablePDFTenantB)
	req = req.WithContext(portalauth.WithIdentity(req.Context(), tablePDFViewer))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code == http.StatusOK && tablePDFHasText(t, rr.Body.Bytes(), "Bravo Tenant Beta") {
		t.Errorf("a tenant hint in the query or headers changed the tenant printed")
	}
}

func TestPortalTablePDF_NoIdentityFailsClosed(t *testing.T) {
	h := tablePDFTestRouter(tablePDFRoles)
	rr := tablePDFRequest(t, h, http.MethodPost, nil, tablePDFBody(t, tablePDFValid("devices")))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("no identity = %d, want 401", rr.Code)
	}
}

func TestPortalTablePDF_WrongMethodIs405(t *testing.T) {
	h := tablePDFTestRouter(tablePDFRoles)
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		rr := tablePDFRequest(t, h, method, &tablePDFViewer, tablePDFBody(t, tablePDFValid("devices")))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s = %d, want 405", method, rr.Code)
		}
	}
}

func TestPortalTablePDF_RejectsLayoutResourceBudgets(t *testing.T) {
	h := tablePDFTestRouter(tablePDFRoles)
	for name, value := range map[string]string{"large cell": strings.Repeat("x", (32<<10)+1), "line breaks": strings.Repeat("\n", 2048), "alternate breaks": strings.Repeat("\u2028", 2048), "CR breaks": strings.Repeat("\r", 2048)} {
		t.Run(name, func(t *testing.T) {
			m := tablePDFValid("devices")
			m["rows"] = [][]string{{value, "macOS"}}
			rr := tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, tablePDFBody(t, m))
			assertTablePDFError(t, rr, http.StatusBadRequest, "invalid_request")
			if strings.Contains(rr.Header().Get("Content-Type"), "pdf") {
				t.Fatal("rejection returned a PDF")
			}
		})
	}
	m := tablePDFValid("devices")
	m["filters"] = []map[string]string{{"label": "Selection", "value": strings.Repeat("x", (32<<10)+1)}}
	assertTablePDFError(t, tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, tablePDFBody(t, m)), http.StatusBadRequest, "invalid_request")
	// Page exhaustion is a client error too, with no partial PDF response.
	rows := make([][]string, 30)
	for i := range rows {
		rows[i] = []string{strings.Repeat("\n", 1000), ""}
	}
	m = tablePDFValid("devices")
	m["rows"] = rows
	assertTablePDFError(t, tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, tablePDFBody(t, m)), http.StatusBadRequest, "invalid_request")
}

func TestPortalTablePDF_BudgetRejectedBeforeLookupAndCanceledRequest(t *testing.T) {
	lookups := 0
	h := portalTablePDFHandler(portalTablePDFDeps{tenantName: func(context.Context, string) (string, error) { lookups++; return "Acme", nil }, now: time.Now})
	m := tablePDFValid("devices")
	m["rows"] = [][]string{{strings.Repeat("x", (32<<10)+1), "macOS"}}
	rr := tablePDFRequest(t, h, http.MethodPost, &tablePDFViewer, tablePDFBody(t, m))
	assertTablePDFError(t, rr, http.StatusBadRequest, "invalid_request")
	if lookups != 0 {
		t.Fatal("over-budget request reached tenant lookup")
	}
	ctx, cancel := context.WithCancel(portalauth.WithIdentity(context.Background(), tablePDFViewer))
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/portal/exports/table-pdf", strings.NewReader(tablePDFBody(t, tablePDFValid("devices")))).WithContext(ctx)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Body.Len() != 0 || strings.Contains(rr.Header().Get("Content-Type"), "pdf") {
		t.Fatal("canceled request returned content")
	}
}
