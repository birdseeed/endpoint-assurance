package handlers

// PAT-2364: compiling regressions against the existing JSON/CSV-only handler.
import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/json"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"os"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
)

// Decode visible fpdf identity-font Tj operands, never PDF metadata. The
// report package separately tests the font round trip. Newline boundaries
// are retained so callers can check full values across physical wraps.
func cerPDFVisibleText(t *testing.T, data []byte) string {
	t.Helper()
	objects := regexp.MustCompile(`(?s)\d+ 0 obj\s*(<<.*?>>)\s*stream\r?\n`)
	operands := regexp.MustCompile(`(?s)\(((?:\\.|[^\\()])*)\)\s*Tj`)
	var text strings.Builder
	for _, loc := range objects.FindAllSubmatchIndex(data, -1) {
		// Binary zlib data can itself end with CR/LF bytes. Respect the PDF
		// stream length rather than trimming bytes from its checksum.
		length := regexp.MustCompile(`/Length\s+([0-9]+)\b`).FindSubmatch(data[loc[2]:loc[3]])
		if length == nil {
			t.Fatal("fpdf stream has no direct length")
		}
		n, err := strconv.Atoi(string(length[1]))
		if err != nil || n > len(data)-loc[1] {
			t.Fatal("invalid PDF stream length")
		}
		stream := data[loc[1] : loc[1]+n]
		if bytes.Contains(data[loc[2]:loc[3]], []byte("FlateDecode")) {
			z, err := zlib.NewReader(bytes.NewReader(stream))
			if err != nil {
				t.Fatal(err)
			}
			stream, err = io.ReadAll(z)
			z.Close()
			if err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Contains(stream, []byte("BT")) {
			continue
		}
		for _, m := range operands.FindAllSubmatch(stream, -1) {
			s := m[1]
			raw := make([]byte, 0, len(s))
			for i := 0; i < len(s); i++ {
				if s[i] != '\\' {
					raw = append(raw, s[i])
					continue
				}
				i++
				if i == len(s) {
					break
				}
				switch s[i] {
				case 'n':
					raw = append(raw, '\n')
				case 'r':
					raw = append(raw, '\r')
				case 't':
					raw = append(raw, '\t')
				case 'b':
					raw = append(raw, '\b')
				case 'f':
					raw = append(raw, '\f')
				case '\r', '\n':
				default:
					if s[i] >= '0' && s[i] <= '7' {
						j := i
						for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
							j++
						}
						n, _ := strconv.ParseUint(string(s[i:j]), 8, 8)
						raw = append(raw, byte(n))
						i = j - 1
					} else {
						raw = append(raw, s[i])
					}
				}
			}
			if bytes.Contains(raw, []byte{0}) {
				units := make([]uint16, 0, len(raw)/2)
				for i := 0; i+1 < len(raw); i += 2 {
					units = append(units, uint16(raw[i])<<8|uint16(raw[i+1]))
				}
				text.WriteString(string(utf16.Decode(units)))
			} else {
				text.Write(raw)
			}
			text.WriteByte('\n')
		}
	}
	return text.String()
}
func cerPDFRequire(t *testing.T, text, value string) {
	t.Helper()
	// A wrapped value may cross a page footer. Keep testing every footer
	// separately, but remove its standalone line when matching evidence.
	if !strings.HasPrefix(value, "Page ") {
		text = regexp.MustCompile(`(?m)^Page [0-9]+ / [0-9]+\n`).ReplaceAllString(text, "")
	}
	if !strings.Contains(strings.Join(strings.Fields(text), ""), strings.Join(strings.Fields(value), "")) {
		t.Errorf("PDF omitted visible value %q", value)
	}
}
func cerReadOnlyPool(t *testing.T, pool *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	cfg := pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	ro, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(ro.Close)
	var mode string
	if err := ro.QueryRow(context.Background(), "SHOW transaction_read_only").Scan(&mode); err != nil || mode != "on" {
		t.Fatalf("read-only pool: %s, %v", mode, err)
	}
	return ro
}
func TestPortalCEReadiness_PDFTenantIsolationAndReadOnly(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	a, b := cerTenant(t, pool, "pdf-a"), cerTenant(t, pool, "pdf-b")
	aDev := cerDeviceHost(t, pool, a, "Tenant A endpoint", "macOS", "now() - interval '1 hour'")
	bDev := cerDeviceHost(t, pool, b, "Tenant B private endpoint", "Windows", "now() - interval '1 hour'")
	bCVE := cerCVE(t, pool, bDev, "critical", "now() - interval '40 days'", "B private product", "1.0", "")
	ro := cerReadOnlyPool(t, pool)
	for _, role := range []string{portalauth.RoleAdmin, portalauth.RoleViewer, portalauth.RoleServiceReadOnly} {
		t.Run(role, func(t *testing.T) {
			rec := cerDo(t, ro, a, cerPath+"?format=pdf", func(r *http.Request) {
				email := role + "-" + pocSuffix(t) + "@example.invalid"
				service := ""
				if role != portalauth.RoleServiceReadOnly {
					pocExec(t, pool, "seed portal role", `INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, $3)`, email, a, role)
				}
				if role == portalauth.RoleServiceReadOnly {
					email = ""
					service = "fixture-service"
				}
				*r = *r.WithContext(portalauth.WithIdentity(r.Context(), portalauth.Identity{Email: email, TenantID: a, Service: service}))
				r.Header.Set("X-Tenant-ID", b)
			})
			if rec.Code != 200 {
				t.Fatalf("PDF = %d, want 200: %s", rec.Code, rec.Body.String())
			}
			if rec.Header().Get("Content-Type") != "application/pdf" || !bytes.HasPrefix(rec.Body.Bytes(), []byte("%PDF-")) {
				t.Fatal("not a PDF response")
			}
			if !regexp.MustCompile(`^attachment; filename="ce-readiness-\d{4}-\d{2}-\d{2}\.pdf"$`).MatchString(rec.Header().Get("Content-Disposition")) {
				t.Errorf("unsafe or undated filename: %q", rec.Header().Get("Content-Disposition"))
			}
			if !bytes.Contains(rec.Body.Bytes(), []byte("/Width 512")) || bytes.Contains(rec.Body.Bytes(), []byte("/Width 1000")) {
				t.Error("customer header required")
			}
			text := cerPDFVisibleText(t, rec.Body.Bytes())
			cerPDFRequire(t, text, aDev)
			cerPDFRequire(t, text, "Tenant A endpoint")
			for _, secret := range []string{bDev, bCVE, "Tenant B private endpoint", "B private product"} {
				if strings.Contains(text, secret) {
					t.Errorf("cross-tenant leak: %q", secret)
				}
			}
		})
	}
}
func TestPortalCEReadiness_PDFRejectsQueryAndMissingIdentity(t *testing.T) {
	// Repeated pdf is rejected too: a PDF request has one unambiguous format.
	for _, query := range []string{"format=xlsx", "format=PDF", "format=pdf&tenant_id=other", "format=pdf&tenant=other", "format=pdf&limit=1", "format=pdf&format=csv", "format=pdf&format=pdf"} {
		t.Run(query, func(t *testing.T) {
			rec := cerDo(t, nil, "00000000-0000-0000-0000-000000000001", cerPath+"?"+query, nil)
			if rec.Code != 400 {
				t.Errorf("status %d, want 400", rec.Code)
			}
		})
	}
	if rec := cerDo(t, nil, "", cerPath+"?format=pdf", nil); rec.Code != 401 {
		t.Errorf("no identity status %d", rec.Code)
	}
}
func TestPortalCEReadiness_PDFCompleteMultipageEvidence(t *testing.T) {
	pool := pocPool(t)
	pocEnsureFullMatchRun(t, pool)
	tenant := cerTenant(t, pool, "pdf-complete")
	longProduct := "LongProduct(" + strings.Repeat("Unbroken0123456789", 100) + ")\\ é <script>https://example.invalid/not-a-link</script> ENDPRODUCT"
	active := cerDeviceHost(t, pool, tenant, "München (audit) \\ "+strings.Repeat("LongHostname", 50), "macOS", "now() - interval '1 hour'")
	cerEval(t, pool, active, "cis_macos_2_5_2_1_gatekeeper", "fail")
	for i := 0; i < 16; i++ {
		cerCVE(t, pool, active, "critical", "now() - interval '40 days'", fmt.Sprintf("item-%02d %s", i, longProduct), "installed-version-1.2.3", "")
	}
	cerDeviceHost(t, pool, tenant, "stale-device", "Windows", "now() - interval '3 days'")
	cerDeviceHost(t, pool, tenant, "silent-device", "macOS", "now() - interval '30 days'")
	for i := 0; i < 8; i++ {
		cerDeviceHost(t, pool, tenant, fmt.Sprintf("last-device-%02d", i), "macOS", "now() - interval '1 hour'")
	}
	modelRec := cerDo(t, pool, tenant, cerPath, nil)
	var model report.PortalCEReadiness
	if modelRec.Code != 200 {
		t.Fatalf("JSON = %d: %s", modelRec.Code, modelRec.Body.String())
	}
	if err := json.Unmarshal(modelRec.Body.Bytes(), &model); err != nil {
		t.Fatal(err)
	}
	rec := cerDo(t, cerReadOnlyPool(t, pool), tenant, cerPath+"?format=pdf", nil)
	if rec.Code != 200 {
		t.Fatalf("PDF = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	data := rec.Body.Bytes()
	text := cerPDFVisibleText(t, data)
	pages := strings.Count(string(data), "/Type /Page") - strings.Count(string(data), "/Type /Pages")
	if pages < 5 {
		t.Errorf("expected many pages, got %d", pages)
	}
	for i := 1; i <= pages; i++ {
		cerPDFRequire(t, text, fmt.Sprintf("Page %d / %d", i, pages))
	}
	for _, v := range []string{"Cyber Essentials readiness evidence pack", "conservative proxy", "advisory publication", "14 days", "fix-release date", "not recorded", "not_evidenced", "device_stale", "device_silent", longProduct, model.Estate.Source, model.CVEMatching.Source, model.CVEMatching.State} {
		cerPDFRequire(t, text, v)
	}
	checkTime := func(tm *time.Time) {
		if tm != nil {
			cerPDFRequire(t, text, tm.UTC().Format("2006-01-02 15:04:05 UTC"))
		}
	}
	checkPtr := func(s *string) {
		if s != nil {
			cerPDFRequire(t, text, *s)
		}
	}
	checkEvidence := func(e report.CEEvidence) {
		cerPDFRequire(t, text, e.State)
		cerPDFRequire(t, text, e.Source)
		checkPtr(e.Reason)
		checkTime(e.ObservedAt)
	}
	checkTime(model.Estate.Freshness.ObservedAt)
	checkEvidence(model.CVEMatching)
	for _, d := range model.Devices {
		for _, v := range []string{d.DeviceID, d.Hostname, d.Platform, d.State, d.Reporting.Bucket, d.Reporting.Source} {
			cerPDFRequire(t, text, v)
		}
		for _, v := range d.StateReasons {
			cerPDFRequire(t, text, v)
		}
		checkTime(d.Reporting.ObservedAt)
		checkEvidence(d.CVEEvidence)
		checkEvidence(d.OSUpdateEvidence)
		for _, c := range d.Controls {
			for _, v := range []string{c.Control, c.Category, c.State, c.Source} {
				cerPDFRequire(t, text, v)
			}
			checkPtr(c.Reason)
			checkPtr(c.RuleKey)
			checkTime(c.ObservedAt)
		}
		for _, it := range d.Items {
			for _, v := range []string{it.Kind, it.CVEID, it.Severity, it.Product, it.InstalledVersion, it.Source, it.DueBasis, it.KEV.State, it.KEV.Source} {
				cerPDFRequire(t, text, v)
			}
			checkPtr(it.FixedVersion)
			checkPtr(it.KEV.Reason)
			checkTime(it.ObservedAt)
			checkTime(&it.PublishedAt)
			checkTime(&it.DueAt)
			checkTime(it.KEV.FetchedAt)
			cerPDFRequire(t, text, fmt.Sprintf("Age: %d days", it.AgeDays))
			cerPDFRequire(t, text, fmt.Sprintf("Overdue: %d days", it.DaysOverdue))
		}
	}
	for _, activePDF := range []string{"/URI", "/JavaScript", "/OpenAction", "/Subtype /Link"} {
		if bytes.Contains(data, []byte(activePDF)) {
			t.Errorf("endpoint text became active PDF content: %s", activePDF)
		}
	}
	if out := os.Getenv("CE_READINESS_PDF_SAMPLE"); out != "" {
		if err := os.WriteFile(out, data, 0600); err != nil {
			t.Fatal(err)
		}
		t.Logf("synthetic sample: %s (%d pages)", out, pages)
	}
}
