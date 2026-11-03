//go:build integration

// Portal read API integration tests (PAT-693).
//
// This file is the DB-backed half of the cross-tenant isolation proof (the
// unit-level half — identity resolution never influenced by client input —
// lives in internal/portalauth/middleware_test.go). It runs the real router,
// real portalauth.Middleware, real portal_users lookups, and real tenant-
// scoped queries against a live Postgres, and asserts the locked PAT-330
// invariant: a tenant A identity can NEVER read tenant B devices, findings,
// or reports.
package integration

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/report"
)

// ---------------------------------------------------------------------------
// Fake Cloudflare Access IdP
// ---------------------------------------------------------------------------

type portalIdP struct {
	key      *rsa.PrivateKey
	kid      string
	issuer   string
	audience string
	srv      *httptest.Server
}

// startPortalIdP generates an RSA key and serves it as a CF-style JWKS.
// Called from TestMain (no *testing.T), so it returns errors.
func startPortalIdP() (*portalIdP, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}
	idp := &portalIdP{
		key:      key,
		kid:      "integration-key-1",
		issuer:   "https://integrationteam.cloudflareaccess.com",
		audience: "integration-aud-tag",
	}
	idp.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kid": idp.kid,
				"kty": "RSA",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}},
		})
	}))
	return idp, nil
}

// token signs a valid CF-Access-style JWT asserting the given email.
func (p *portalIdP) token(t *testing.T, email string) string {
	t.Helper()
	return p.tokenWith(t, jwt.MapClaims{
		"iss":   p.issuer,
		"aud":   p.audience,
		"email": email,
		"iat":   time.Now().Add(-time.Minute).Unix(),
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
}

func (p *portalIdP) tokenWith(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = p.kid
	signed, err := tok.SignedString(p.key)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return signed
}

// ---------------------------------------------------------------------------
// HTTP + seeding helpers
// ---------------------------------------------------------------------------

// portalDo sends a request to the public server with the given portal JWT
// (empty token = no header) and returns the response.
func portalDo(t *testing.T, method, path, token string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, env.publicSrv.URL+path, body)
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, path, err)
	}
	if token != "" {
		req.Header.Set(portalauth.Header, token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return resp
}

// decodeJSON decodes the response body into out and closes it.
func decodeJSON(t *testing.T, resp *http.Response, out any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
}

// mapPortalUser creates/updates an email → tenant mapping via the internal
// admin CRUD and asserts the expected status.
func mapPortalUser(t *testing.T, email, tenantID string, wantStatus int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"email": email, "tenant_id": tenantID})
	resp, err := http.Post(env.internalSrv.URL+"/admin/portal-users", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /admin/portal-users: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /admin/portal-users(%s) = %d, want %d: %s", email, resp.StatusCode, wantStatus, b)
	}
}

// disablePortalUser soft-disables a mapping via the internal admin CRUD.
func disablePortalUser(t *testing.T, email string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, env.internalSrv.URL+"/admin/portal-users/"+email, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /admin/portal-users/%s: %v", email, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("DELETE /admin/portal-users/%s = %d: %s", email, resp.StatusCode, b)
	}
}

// mapEmailDomain registers (or re-enables) a domain -> tenant auto-binding
// via the internal admin CRUD (PAT-127) and asserts the expected status.
func mapEmailDomain(t *testing.T, domain, tenantID string, wantStatus int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"domain": domain, "tenant_id": tenantID})
	resp, err := http.Post(env.internalSrv.URL+"/admin/tenant-email-domains", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /admin/tenant-email-domains: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /admin/tenant-email-domains(%s) = %d, want %d: %s", domain, resp.StatusCode, wantStatus, b)
	}
}

// disableEmailDomain soft-disables a domain auto-binding via the internal
// admin CRUD.
func disableEmailDomain(t *testing.T, domain string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, env.internalSrv.URL+"/admin/tenant-email-domains/"+domain, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /admin/tenant-email-domains/%s: %v", domain, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("DELETE /admin/tenant-email-domains/%s = %d: %s", domain, resp.StatusCode, b)
	}
}

// portalTenant is one fully-seeded tenant in the isolation matrix.
type portalTenant struct {
	name          string
	tenantID      string
	deviceID      string
	email         string
	token         string
	cveID         string // seeded CVE finding on this tenant's device
	reportID      string // filled during the reports leg
	unapprovedApp string // seeded tenant_app_policies(policy='unapproved') app name
	extensionID   string // seeded device_browser_extensions.extension_id, policy='unapproved'
}

// seedPortalTenant creates a tenant, one device with compliance evaluations
// and a CVE finding, and a portal_users mapping for email.
func seedPortalTenant(t *testing.T, name, email, cveID string) *portalTenant {
	t.Helper()
	ctx := t.Context()

	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, name)
	if err != nil {
		t.Fatalf("create tenant %s: %v", name, err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID, "SER-"+name, "host-"+name).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device for %s: %v", name, err)
	}

	// One pass + one fail evaluation from the seeded CIS rule pack, so the
	// device has a compliance summary and the tenant a non-trivial overview.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, severity, benchmark_version)
		SELECT $1::uuid, id,
		       CASE WHEN rule_key = 'cis_macos_2_5_1_1_filevault' THEN 'pass' ELSE 'fail' END,
		       severity, benchmark_version
		FROM compliance_rules
		WHERE rule_key IN ('cis_macos_2_5_1_1_filevault', 'cis_macos_2_5_2_2_firewall')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed evaluations for %s: %v", name, err)
	}

	_, err = env.pool.Exec(ctx, `
		INSERT INTO cve_feed_entries (cve_id, description, description_source, cvss_v3_score, severity)
		VALUES ($1, 'integration test vulnerability', 'nvd', 9.8, 'CRITICAL')
		ON CONFLICT (cve_id) DO NOTHING
	`, cveID)
	if err != nil {
		t.Fatalf("seed cve entry %s: %v", cveID, err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_cve_findings (device_id, cve_id, app_name, app_version, cvss_v3_score, severity)
		VALUES ($1::uuid, $2, 'VulnApp', '1.0.0', 9.8, 'CRITICAL')
	`, deviceID, cveID)
	if err != nil {
		t.Fatalf("seed cve finding for %s: %v", name, err)
	}

	// PAT-729: an unapproved-policy app installed on this tenant's device, so
	// the isolation matrix has a per-tenant unapproved-apps target too.
	unapprovedApp := "ShadyApp-" + name
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, $2, 'any', 'unapproved', 'report')
	`, tenantID, unapprovedApp)
	if err != nil {
		t.Fatalf("seed unapproved app policy for %s: %v", name, err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, $2, $3, '1.0.0')
	`, deviceID, unapprovedApp, "com.example."+unapprovedApp)
	if err != nil {
		t.Fatalf("seed unapproved device app for %s: %v", name, err)
	}

	// PAT-826/PAT-933: a browser extension installed on this tenant's device,
	// tagged unapproved, so the isolation matrix has a per-tenant extensions
	// target too.
	extensionID := "ext-" + name
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		VALUES ($1::uuid, 'chrome', 'testuser', 'Default', $2, $3, '1.0', 'elevated')
	`, deviceID, extensionID, "ShadyExtension-"+name)
	if err != nil {
		t.Fatalf("seed browser extension for %s: %v", name, err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'any', $2, $3, 'unapproved')
	`, tenantID, extensionID, "ShadyExtension-"+name)
	if err != nil {
		t.Fatalf("seed extension policy for %s: %v", name, err)
	}

	mapPortalUser(t, email, tenantID, http.StatusCreated)

	return &portalTenant{
		name:          name,
		tenantID:      tenantID,
		deviceID:      deviceID,
		email:         email,
		token:         env.idp.token(t, email),
		cveID:         cveID,
		unapprovedApp: unapprovedApp,
		extensionID:   extensionID,
	}
}

// ---------------------------------------------------------------------------
// Cross-tenant isolation matrix
// ---------------------------------------------------------------------------

// TestPortalCrossTenantIsolationMatrix seeds two tenants (A, B), each with a
// device, compliance evaluations, a distinct CVE finding, and a portal
// identity, then walks every portal endpoint from BOTH identities asserting
// that each sees exactly its own tenant's data and gets 404 (never data,
// never 403) on the other tenant's resources.
func TestPortalCrossTenantIsolationMatrix(t *testing.T) {
	a := seedPortalTenant(t, "portal-iso-a", "alice@isolation-a.example", "CVE-2099-1001")
	b := seedPortalTenant(t, "portal-iso-b", "bob@isolation-b.example", "CVE-2099-1002")
	// Give only tenant A one additional latest unreadable evaluation. The
	// control-coverage route must expose it only to A, proving its aggregate
	// cannot drift into a cross-tenant rule/evaluation query.
	if _, err := env.pool.Exec(t.Context(), `
		INSERT INTO compliance_evaluations (device_id, rule_id, status, observed_value, severity, benchmark_version)
		SELECT $1::uuid, id, 'fail', NULL, severity, benchmark_version
		FROM compliance_rules
		WHERE rule_key = 'cis_macos_2_5_1_1_filevault'
	`, a.deviceID); err != nil {
		t.Fatalf("seed tenant-A undetermined evaluation: %v", err)
	}

	// Generate one portal report per tenant up front so the reports leg of
	// the matrix has cross-tenant targets.
	for _, pt := range []*portalTenant{a, b} {
		body := strings.NewReader(`{"name":"Isolation matrix report"}`)
		resp := portalDo(t, http.MethodPost, "/v1/portal/reports", pt.token, body)
		if resp.StatusCode != http.StatusCreated {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("POST /v1/portal/reports as %s = %d: %s", pt.email, resp.StatusCode, raw)
		}
		var rec struct {
			ID string `json:"id"`
		}
		decodeJSON(t, resp, &rec)
		if rec.ID == "" {
			t.Fatalf("POST /v1/portal/reports as %s returned empty id", pt.email)
		}
		pt.reportID = rec.ID
	}

	matrix := []struct {
		who   *portalTenant
		other *portalTenant
	}{
		{who: a, other: b},
		{who: b, other: a},
	}

	for _, m := range matrix {
		m := m
		t.Run(m.who.name, func(t *testing.T) {
			t.Run("control coverage is own tenant only", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/control-coverage", m.who.token, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("control coverage = %d", resp.StatusCode)
				}
				var out struct {
					Platforms []string `json:"platforms"`
					Controls  struct {
						Total                   int `json:"total"`
						UndeterminedEvaluations int `json:"undetermined_evaluations"`
					} `json:"controls"`
					Measurements struct {
						Pass          int `json:"pass"`
						Fail          int `json:"fail"`
						Undetermined  int `json:"undetermined"`
						NotApplicable int `json:"not_applicable"`
					} `json:"measurements"`
					Identifiers struct {
						CISMapped   int `json:"cis_mapped"`
						CISUnmapped int `json:"cis_unmapped"`
						NonCIS      int `json:"non_cis"`
					} `json:"identifiers"`
					Benchmarks []struct {
						Benchmark        string `json:"benchmark"`
						BenchmarkVersion string `json:"benchmark_version"`
						Controls         struct {
							Total int `json:"total"`
						} `json:"controls"`
						Measurements struct {
							Pass          int `json:"pass"`
							Fail          int `json:"fail"`
							Undetermined  int `json:"undetermined"`
							NotApplicable int `json:"not_applicable"`
						} `json:"measurements"`
						Identifiers struct {
							CISMapped   int `json:"cis_mapped"`
							CISUnmapped int `json:"cis_unmapped"`
							NonCIS      int `json:"non_cis"`
						} `json:"identifiers"`
					} `json:"benchmarks"`
					TotalZero bool `json:"total_zero"`
				}
				decodeJSON(t, resp, &out)
				if out.TotalZero || out.Controls.Total == 0 {
					t.Fatalf("coverage empty=%t total=%d, want the seeded live rule pack", out.TotalZero, out.Controls.Total)
				}
				if !reflect.DeepEqual(out.Platforms, []string{"macos", "windows"}) {
					t.Errorf("platforms = %#v, want [macos windows] (the tenant's enabled mix)", out.Platforms)
				}
				if len(out.Benchmarks) == 0 {
					t.Fatal("benchmarks empty, want active benchmark/version pairs")
				}
				var benchmarkPass, benchmarkFail, benchmarkUndetermined, benchmarkNA int
				var benchmarkMapped, benchmarkUnmapped, benchmarkNonCIS int
				for _, benchmark := range out.Benchmarks {
					if benchmark.Benchmark == "" || benchmark.BenchmarkVersion == "" {
						t.Errorf("benchmark pair = %#v, want non-empty benchmark and version", benchmark)
					}
					if benchmark.Identifiers.CISMapped+benchmark.Identifiers.CISUnmapped+benchmark.Identifiers.NonCIS != benchmark.Controls.Total {
						t.Errorf("benchmark identifier buckets = %+v, want definition counts totaling %d", benchmark.Identifiers, benchmark.Controls.Total)
					}
					benchmarkPass += benchmark.Measurements.Pass
					benchmarkFail += benchmark.Measurements.Fail
					benchmarkUndetermined += benchmark.Measurements.Undetermined
					benchmarkNA += benchmark.Measurements.NotApplicable
					benchmarkMapped += benchmark.Identifiers.CISMapped
					benchmarkUnmapped += benchmark.Identifiers.CISUnmapped
					benchmarkNonCIS += benchmark.Identifiers.NonCIS
				}
				if benchmarkPass != out.Measurements.Pass || benchmarkFail != out.Measurements.Fail || benchmarkUndetermined != out.Measurements.Undetermined || benchmarkNA != out.Measurements.NotApplicable {
					t.Errorf("benchmark measurements = pass:%d fail:%d undetermined:%d not_applicable:%d, want top-level %+v", benchmarkPass, benchmarkFail, benchmarkUndetermined, benchmarkNA, out.Measurements)
				}
				if benchmarkMapped != out.Identifiers.CISMapped || benchmarkUnmapped != out.Identifiers.CISUnmapped || benchmarkNonCIS != out.Identifiers.NonCIS {
					t.Errorf("benchmark identifiers = mapped:%d unmapped:%d non_cis:%d, want top-level %+v", benchmarkMapped, benchmarkUnmapped, benchmarkNonCIS, out.Identifiers)
				}
				wantUndetermined := 1
				if m.who == a {
					wantUndetermined = 2
				}
				if out.Controls.UndeterminedEvaluations != wantUndetermined {
					t.Errorf("undetermined_evaluations = %d, want %d for %s only", out.Controls.UndeterminedEvaluations, wantUndetermined, m.who.name)
				}
				if out.Measurements.Undetermined != wantUndetermined || out.Measurements.Fail != 0 || out.Measurements.NotApplicable != 0 {
					t.Errorf("measurements = %+v, want only %d undetermined evaluations for %s", out.Measurements, wantUndetermined, m.who.name)
				}
				wantPass := 1
				if m.who == a {
					wantPass = 0
				}
				if out.Measurements.Pass != wantPass {
					t.Errorf("measurements.pass = %d, want %d for %s", out.Measurements.Pass, wantPass, m.who.name)
				}
				if out.Identifiers.CISMapped == 0 || out.Identifiers.CISMapped+out.Identifiers.CISUnmapped+out.Identifiers.NonCIS != out.Controls.Total {
					t.Errorf("identifier buckets = %+v, want explicit definition counts totaling %d", out.Identifiers, out.Controls.Total)
				}
			})

			t.Run("overview is own tenant only", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/overview", m.who.token, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("overview = %d", resp.StatusCode)
				}
				var ov struct {
					TenantName   string `json:"tenant_name"`
					DevicesTotal int    `json:"devices_total"`
				}
				decodeJSON(t, resp, &ov)
				if ov.TenantName != m.who.name {
					t.Errorf("tenant_name = %q, want %q", ov.TenantName, m.who.name)
				}
				if ov.DevicesTotal != 1 {
					t.Errorf("devices_total = %d, want 1 (own device only)", ov.DevicesTotal)
				}
			})

			t.Run("device roster contains only own devices", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/devices", m.who.token, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("devices = %d", resp.StatusCode)
				}
				var out struct {
					Total   int `json:"total"`
					Devices []struct {
						DeviceID string `json:"device_id"`
					} `json:"devices"`
				}
				decodeJSON(t, resp, &out)
				if out.Total != 1 || len(out.Devices) != 1 {
					t.Fatalf("total=%d len=%d, want exactly the one own device", out.Total, len(out.Devices))
				}
				if out.Devices[0].DeviceID != m.who.deviceID {
					t.Errorf("roster device = %s, want %s", out.Devices[0].DeviceID, m.who.deviceID)
				}
				for _, d := range out.Devices {
					if d.DeviceID == m.other.deviceID {
						t.Fatalf("CROSS-TENANT LEAK: %s's roster contains %s's device", m.who.name, m.other.name)
					}
				}
			})

			t.Run("own device detail is readable", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/devices/"+m.who.deviceID, m.who.token, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("own device detail = %d, want 200", resp.StatusCode)
				}
				var out struct {
					Device struct {
						DeviceID string `json:"device_id"`
					} `json:"device"`
					ComplianceSignals []struct {
						RuleID string `json:"rule_id"`
					} `json:"compliance_signals"`
				}
				decodeJSON(t, resp, &out)
				if out.Device.DeviceID != m.who.deviceID {
					t.Errorf("device_id = %s, want %s", out.Device.DeviceID, m.who.deviceID)
				}
				if len(out.ComplianceSignals) == 0 {
					t.Errorf("expected seeded compliance signals, got none")
				}
			})

			t.Run("other tenant's device detail is 404", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/devices/"+m.other.deviceID, m.who.token, nil)
				resp.Body.Close()
				if resp.StatusCode != http.StatusNotFound {
					t.Fatalf("cross-tenant device detail = %d, want 404 (never 200, never 403)", resp.StatusCode)
				}
			})

			t.Run("findings contain only own tenant's CVEs", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/findings", m.who.token, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("findings = %d", resp.StatusCode)
				}
				var out struct {
					Findings []struct {
						CVEID string `json:"cve_id"`
					} `json:"findings"`
				}
				decodeJSON(t, resp, &out)
				sawOwn := false
				for _, f := range out.Findings {
					if f.CVEID == m.other.cveID {
						t.Fatalf("CROSS-TENANT LEAK: %s sees %s's finding %s", m.who.name, m.other.name, f.CVEID)
					}
					if f.CVEID == m.who.cveID {
						sawOwn = true
					}
				}
				if !sawOwn {
					t.Errorf("own finding %s missing from /v1/portal/findings", m.who.cveID)
				}
			})

			t.Run("unapproved apps contain only own tenant's data", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", m.who.token, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("unapproved-apps = %d", resp.StatusCode)
				}
				var out struct {
					Total int `json:"total"`
					Apps  []struct {
						AppName         string `json:"app_name"`
						DevicesAffected int    `json:"devices_affected"`
					} `json:"apps"`
				}
				decodeJSON(t, resp, &out)
				sawOwn := false
				for _, a := range out.Apps {
					if a.AppName == m.other.unapprovedApp {
						t.Fatalf("CROSS-TENANT LEAK: %s sees %s's unapproved app %s", m.who.name, m.other.name, a.AppName)
					}
					if a.AppName == m.who.unapprovedApp {
						sawOwn = true
						if a.DevicesAffected != 1 {
							t.Errorf("own unapproved app device count = %d, want 1", a.DevicesAffected)
						}
					}
				}
				if !sawOwn {
					t.Errorf("own unapproved app %s missing from /v1/portal/unapproved-apps", m.who.unapprovedApp)
				}
			})

			t.Run("extensions contain only own tenant's data", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", m.who.token, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("extensions = %d", resp.StatusCode)
				}
				var out struct {
					Total      int `json:"total"`
					Extensions []struct {
						ExtensionID   string `json:"extension_id"`
						DeviceCount   int    `json:"device_count"`
						ApprovalState string `json:"approval_state"`
						Devices       []struct {
							DeviceID string `json:"device_id"`
						} `json:"devices"`
					} `json:"extensions"`
				}
				decodeJSON(t, resp, &out)
				sawOwn := false
				for _, e := range out.Extensions {
					if e.ExtensionID == m.other.extensionID {
						t.Fatalf("CROSS-TENANT LEAK: %s sees %s's extension %s", m.who.name, m.other.name, e.ExtensionID)
					}
					for _, d := range e.Devices {
						if d.DeviceID == m.other.deviceID {
							t.Fatalf("CROSS-TENANT LEAK: %s's extension %s lists %s's device", m.who.name, e.ExtensionID, m.other.name)
						}
					}
					if e.ExtensionID == m.who.extensionID {
						sawOwn = true
						if e.DeviceCount != 1 {
							t.Errorf("own extension device count = %d, want 1", e.DeviceCount)
						}
						if e.ApprovalState != "unapproved" {
							t.Errorf("own extension approval_state = %q, want unapproved", e.ApprovalState)
						}
					}
				}
				if !sawOwn {
					t.Errorf("own extension %s missing from /v1/portal/extensions", m.who.extensionID)
				}
			})

			t.Run("report history lists only own reports", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/reports", m.who.token, nil)
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("reports = %d", resp.StatusCode)
				}
				var out struct {
					Reports []struct {
						ID string `json:"id"`
					} `json:"reports"`
				}
				decodeJSON(t, resp, &out)
				sawOwn := false
				for _, rec := range out.Reports {
					if rec.ID == m.other.reportID {
						t.Fatalf("CROSS-TENANT LEAK: %s's report history lists %s's report", m.who.name, m.other.name)
					}
					if rec.ID == m.who.reportID {
						sawOwn = true
					}
				}
				if !sawOwn {
					t.Errorf("own report %s missing from history", m.who.reportID)
				}
			})

			t.Run("own report downloads as PDF", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/reports/"+m.who.reportID, m.who.token, nil)
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("own report download = %d, want 200", resp.StatusCode)
				}
				if ct := resp.Header.Get("Content-Type"); ct != "application/pdf" {
					t.Errorf("Content-Type = %q, want application/pdf", ct)
				}
				head := make([]byte, 5)
				if _, err := io.ReadFull(resp.Body, head); err != nil || string(head) != "%PDF-" {
					t.Errorf("body does not start with %%PDF- (err=%v, head=%q)", err, head)
				}
			})

			t.Run("other tenant's report download is 404", func(t *testing.T) {
				resp := portalDo(t, http.MethodGet, "/v1/portal/reports/"+m.other.reportID, m.who.token, nil)
				resp.Body.Close()
				if resp.StatusCode != http.StatusNotFound {
					t.Fatalf("cross-tenant report download = %d, want 404", resp.StatusCode)
				}
			})
		})
	}
}

func TestPortalControlCoverageExplicitZeroState(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-coverage-zero")
	if err != nil {
		t.Fatalf("create zero-coverage tenant: %v", err)
	}
	if _, err := env.pool.Exec(t.Context(), `
		UPDATE tenants
		SET macos_enabled = false, windows_enabled = false
		WHERE id = $1::uuid
	`, tenantID); err != nil {
		t.Fatalf("disable tenant platforms: %v", err)
	}

	email := "zero-coverage@example.test"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	resp := portalDo(t, http.MethodGet, "/v1/portal/control-coverage", env.idp.token(t, email), nil)
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("control coverage = %d: %s", resp.StatusCode, raw)
	}
	var out struct {
		Platforms []string `json:"platforms"`
		Controls  struct {
			Total                   int `json:"total"`
			Evaluated               int `json:"evaluated"`
			OutOfScope              int `json:"out_of_scope"`
			UndeterminedEvaluations int `json:"undetermined_evaluations"`
		} `json:"controls"`
		Measurements struct {
			Pass          int `json:"pass"`
			Fail          int `json:"fail"`
			Undetermined  int `json:"undetermined"`
			NotApplicable int `json:"not_applicable"`
		} `json:"measurements"`
		Identifiers struct {
			CISMapped   int `json:"cis_mapped"`
			CISUnmapped int `json:"cis_unmapped"`
			NonCIS      int `json:"non_cis"`
		} `json:"identifiers"`
		Benchmarks []struct{} `json:"benchmarks"`
		TotalZero  bool       `json:"total_zero"`
	}
	decodeJSON(t, resp, &out)
	if !out.TotalZero {
		t.Fatal("total_zero = false, want true")
	}
	if len(out.Platforms) != 0 || len(out.Benchmarks) != 0 {
		t.Fatalf("platforms=%v benchmarks=%v, want explicit empty arrays", out.Platforms, out.Benchmarks)
	}
	if out.Controls.Total != 0 || out.Controls.Evaluated != 0 || out.Controls.OutOfScope != 0 || out.Controls.UndeterminedEvaluations != 0 {
		t.Fatalf("controls = %+v, want explicit zero counts", out.Controls)
	}
	if out.Measurements.Pass != 0 || out.Measurements.Fail != 0 || out.Measurements.Undetermined != 0 || out.Measurements.NotApplicable != 0 {
		t.Fatalf("measurements = %+v, want explicit zero counts", out.Measurements)
	}
	if out.Identifiers.CISMapped != 0 || out.Identifiers.CISUnmapped != 0 || out.Identifiers.NonCIS != 0 {
		t.Fatalf("identifiers = %+v, want explicit zero counts", out.Identifiers)
	}
}

// ---------------------------------------------------------------------------
// GET /v1/portal/unapproved-apps — aggregation + empty state (PAT-729)
// ---------------------------------------------------------------------------

// TestPortalUnapprovedAppsAggregation seeds two devices on one tenant, both
// running the same unapproved-policy app, and asserts the endpoint reports
// exactly one row with devices_affected = 2 — proving the device count is a
// real aggregation across the fleet, not per-device duplication.
func TestPortalUnapprovedAppsAggregation(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-unapproved-agg")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceIDs [2]string
	for i := range deviceIDs {
		err = env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
			VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.5', '24F74', 'arm64', now())
			RETURNING id::text
		`, tenantID, fmt.Sprintf("SER-agg-%d", i), fmt.Sprintf("host-agg-%d", i)).Scan(&deviceIDs[i])
		if err != nil {
			t.Fatalf("seed device %d: %v", i, err)
		}
	}

	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'BitTorrentClient', 'any', 'unapproved', 'app_management')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed unapproved policy: %v", err)
	}

	for i, devID := range deviceIDs {
		_, err = env.pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, identifier, version)
			VALUES ($1::uuid, 'BitTorrentClient', $2, '3.0.0')
		`, devID, fmt.Sprintf("com.example.bittorrent.%d", i))
		if err != nil {
			t.Fatalf("seed device_apps %d: %v", i, err)
		}
	}

	email := "agg@unapproved-agg.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unapproved-apps = %d", resp.StatusCode)
	}
	var out struct {
		Total int `json:"total"`
		Apps  []struct {
			AppName         string `json:"app_name"`
			EnforcementTier string `json:"enforcement_tier"`
			DevicesAffected int    `json:"devices_affected"`
		} `json:"apps"`
	}
	decodeJSON(t, resp, &out)

	if out.Total != 1 || len(out.Apps) != 1 {
		t.Fatalf("total=%d len=%d, want exactly 1 aggregated app row", out.Total, len(out.Apps))
	}
	app := out.Apps[0]
	if app.AppName != "BitTorrentClient" {
		t.Errorf("app_name = %q, want BitTorrentClient", app.AppName)
	}
	if app.EnforcementTier != "app_management" {
		t.Errorf("enforcement_tier = %q, want app_management", app.EnforcementTier)
	}
	if app.DevicesAffected != 2 {
		t.Errorf("devices_affected = %d, want 2 (aggregated across both devices)", app.DevicesAffected)
	}
}

// TestPortalUnapprovedAppsCrossTenantSameAppName is a targeted regression
// test for a cross-tenant leak found in FetchAppPolicyDriftReport's SQL
// (PAT-729 review): the device_apps join previously matched by app identity
// across ALL tenants' devices with no tenant scoping, then joined devices
// only as an unused decoration — so tenant A tagging an app unapproved could
// pick up tenant B's device count for a same-named app, even though tenant A
// has zero devices of its own running it. Two tenants both run "CommonApp";
// only tenant A tags it unapproved. Tenant A must see 0 devices affected
// (it has none itself) — tenant B's device must never be counted.
func TestPortalUnapprovedAppsCrossTenantSameAppName(t *testing.T) {
	ctx := t.Context()
	tenantA, _, _, err := createTestTenant(env.internalSrv.URL, "portal-unapproved-leak-a")
	if err != nil {
		t.Fatalf("create tenant A: %v", err)
	}
	tenantB, _, _, err := createTestTenant(env.internalSrv.URL, "portal-unapproved-leak-b")
	if err != nil {
		t.Fatalf("create tenant B: %v", err)
	}

	// Tenant B has a device running "CommonApp" — tenant B does NOT tag it
	// unapproved, so this device must never be counted for tenant A either.
	var deviceB string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-leak-b', gen_random_uuid(), 'host-leak-b', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantB).Scan(&deviceB)
	if err != nil {
		t.Fatalf("seed tenant B device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'CommonApp', 'com.example.commonapp', '1.0.0')
	`, deviceB)
	if err != nil {
		t.Fatalf("seed tenant B device_apps: %v", err)
	}

	// Tenant A tags "CommonApp" unapproved but has NO devices of its own.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'CommonApp', 'any', 'unapproved', 'report')
	`, tenantA)
	if err != nil {
		t.Fatalf("seed tenant A policy: %v", err)
	}

	email := "leak-a@unapproved-leak.example"
	mapPortalUser(t, email, tenantA, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unapproved-apps = %d", resp.StatusCode)
	}
	var out struct {
		Apps []struct {
			AppName         string `json:"app_name"`
			DevicesAffected int    `json:"devices_affected"`
		} `json:"apps"`
	}
	decodeJSON(t, resp, &out)
	if len(out.Apps) != 1 || out.Apps[0].AppName != "CommonApp" {
		t.Fatalf("apps = %+v, want exactly one CommonApp row", out.Apps)
	}
	if out.Apps[0].DevicesAffected != 0 {
		t.Fatalf("CROSS-TENANT LEAK: devices_affected = %d, want 0 (tenant A has no devices of its own; the count came from tenant B's device)", out.Apps[0].DevicesAffected)
	}
}

// TestPortalUnapprovedAppsPlatformScoped is a targeted regression test
// (PAT-729 review) for a same-tenant platform-scoping gap in
// FetchAppPolicyDriftReport: a policy row's platform (macos|windows|any) was
// never checked against the matched device's OS, so a windows-only policy
// could pick up devices_affected from an unrelated macOS device that merely
// shares the app's name. One tenant, one macOS device running "WinOnlyApp",
// and a tenant_app_policies row scoping "WinOnlyApp" to windows only — the
// macOS device must NOT be counted.
func TestPortalUnapprovedAppsPlatformScoped(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-unapproved-platform")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-platform-mac', gen_random_uuid(), 'host-platform-mac', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'WinOnlyApp', 'com.example.winonlyapp', '1.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'WinOnlyApp', 'windows', 'unapproved', 'report')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}

	email := "platform@unapproved-platform.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unapproved-apps = %d", resp.StatusCode)
	}
	var out struct {
		Apps []struct {
			AppName         string `json:"app_name"`
			DevicesAffected int    `json:"devices_affected"`
		} `json:"apps"`
	}
	decodeJSON(t, resp, &out)
	if len(out.Apps) != 1 || out.Apps[0].AppName != "WinOnlyApp" {
		t.Fatalf("apps = %+v, want exactly one WinOnlyApp row", out.Apps)
	}
	if out.Apps[0].DevicesAffected != 0 {
		t.Fatalf("devices_affected = %d, want 0 (windows-only policy must not match a macOS device)", out.Apps[0].DevicesAffected)
	}
}

// TestPortalUnapprovedAppsEmptyState asserts a tenant with no
// tenant_app_policies(policy='unapproved') rows gets a 200 with an empty
// (never null) apps array, not an error.
func TestPortalUnapprovedAppsEmptyState(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-unapproved-empty")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	email := "empty@unapproved-empty.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unapproved-apps = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Total int   `json:"total"`
		Apps  []any `json:"apps"`
	}
	decodeJSON(t, resp, &out)
	if out.Total != 0 {
		t.Errorf("total = %d, want 0", out.Total)
	}
	if out.Apps == nil {
		t.Errorf("apps = nil, want empty (never null) array")
	}
	if len(out.Apps) != 0 {
		t.Errorf("apps = %+v, want empty", out.Apps)
	}
}

// unapprovedAppsEvidenceOut is the shared response shape for the PAT-1725
// evidence_basis assertions below.
type unapprovedAppsEvidenceOut struct {
	Apps []struct {
		AppName                string `json:"app_name"`
		DevicesAffected        int    `json:"devices_affected"`
		EvidenceBasis          string `json:"evidence_basis"`
		IdentifierMatchedCount int    `json:"identifier_matched_devices"`
		NameMatchedCount       int    `json:"name_matched_devices"`
	} `json:"apps"`
}

// TestPortalUnapprovedAppsEvidenceBasisIdentifierMatch (PAT-1725): a policy
// row keyed on bundle_id, matched on two devices both via a real
// device_apps.identifier, must report evidence_basis "identifier_match" with
// every matched device counted as identifier-matched and none as name-only —
// the claim comes from the platform's own identifier match, never a display
// name comparison.
func TestPortalUnapprovedAppsEvidenceBasisIdentifierMatch(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-unapproved-ev-idmatch")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceIDs [2]string
	for i := range deviceIDs {
		err = env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
			VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.5', '24F74', 'arm64', now())
			RETURNING id::text
		`, tenantID, fmt.Sprintf("SER-ev-idmatch-%d", i), fmt.Sprintf("host-ev-idmatch-%d", i)).Scan(&deviceIDs[i])
		if err != nil {
			t.Fatalf("seed device %d: %v", i, err)
		}
		_, err = env.pool.Exec(ctx, `
			INSERT INTO device_apps (device_id, name, identifier, version)
			VALUES ($1::uuid, 'Totally Different Display Name', 'com.example.idmatch', '2.0.0')
		`, deviceIDs[i])
		if err != nil {
			t.Fatalf("seed device_apps %d: %v", i, err)
		}
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.example.idmatch', 'any', 'unapproved', 'app_management')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed unapproved policy: %v", err)
	}

	email := "idmatch@unapproved-ev.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unapproved-apps = %d: %s", resp.StatusCode, b)
	}
	var out unapprovedAppsEvidenceOut
	decodeJSON(t, resp, &out)
	if len(out.Apps) != 1 {
		t.Fatalf("apps = %+v, want exactly one row", out.Apps)
	}
	app := out.Apps[0]
	if app.EvidenceBasis != "identifier_match" {
		t.Errorf("evidence_basis = %q, want identifier_match (both devices matched by bundle_id, never by the differing display name)", app.EvidenceBasis)
	}
	if app.DevicesAffected != 2 || app.IdentifierMatchedCount != 2 || app.NameMatchedCount != 0 {
		t.Errorf("counts = devices_affected=%d identifier_matched=%d name_matched=%d, want 2/2/0",
			app.DevicesAffected, app.IdentifierMatchedCount, app.NameMatchedCount)
	}
}

// TestPortalUnapprovedAppsEvidenceBasisTeamIDMatch (PAT-1725): a policy row
// keyed on team_id (signing identity) alone, matched via
// device_apps.team_id rather than any bundle_id, must also report
// "identifier_match" — team_id is a real identifier per
// deriveObservedSoftwareIdentity's own identifier-vs-name distinction
// (internal/extractor/software_inventory.go), not a name comparison.
func TestPortalUnapprovedAppsEvidenceBasisTeamIDMatch(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-unapproved-ev-teamid")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-ev-teamid', gen_random_uuid(), 'host-ev-teamid', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	// bundle_id deliberately differs from the policy's bundle_id (NULL, in
	// fact — the policy only sets team_id), and the display name differs
	// from anything the policy would match on, so team_id is the ONLY
	// condition that can fire.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, team_id, version)
		VALUES ($1::uuid, 'Some Signed App', 'com.example.signedapp', 'TEAM-EXAMPLE123', '4.5.6')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed device_apps: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, team_id, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'TEAM-EXAMPLE123', 'any', 'unapproved', 'app_management')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed unapproved policy: %v", err)
	}

	email := "teamid@unapproved-ev.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unapproved-apps = %d: %s", resp.StatusCode, b)
	}
	var out unapprovedAppsEvidenceOut
	decodeJSON(t, resp, &out)
	if len(out.Apps) != 1 {
		t.Fatalf("apps = %+v, want exactly one row", out.Apps)
	}
	app := out.Apps[0]
	if app.EvidenceBasis != "identifier_match" {
		t.Errorf("evidence_basis = %q, want identifier_match (matched via team_id, a real signing identity)", app.EvidenceBasis)
	}
	if app.DevicesAffected != 1 || app.IdentifierMatchedCount != 1 || app.NameMatchedCount != 0 {
		t.Errorf("counts = devices_affected=%d identifier_matched=%d name_matched=%d, want 1/1/0",
			app.DevicesAffected, app.IdentifierMatchedCount, app.NameMatchedCount)
	}
}

// TestPortalUnapprovedAppsEvidenceBasisMixedIsNameMatchOnly (PAT-1725): one
// device ties to the policy through a real identifier (bundle_id) and a
// second device only shares the display name with a different identifier —
// the row is only as strong as its weakest instance, so the whole row must
// report "name_match_only", never "identifier_match".
func TestPortalUnapprovedAppsEvidenceBasisMixedIsNameMatchOnly(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-unapproved-ev-mixed")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var idDeviceID, nameOnlyDeviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-ev-mixed-id', gen_random_uuid(), 'host-ev-mixed-id', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&idDeviceID)
	if err != nil {
		t.Fatalf("seed identifier-matched device: %v", err)
	}
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-ev-mixed-name', gen_random_uuid(), 'host-ev-mixed-name', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&nameOnlyDeviceID)
	if err != nil {
		t.Fatalf("seed name-only device: %v", err)
	}

	// Matches the policy's bundle_id — a real identifier.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'MixedApp', 'com.example.mixed', '1.0.0')
	`, idDeviceID)
	if err != nil {
		t.Fatalf("seed identifier-matched device_apps: %v", err)
	}
	// Same display name, but a different identifier — only the name
	// condition fires for this device.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'MixedApp', 'com.example.mixed.repackaged', '9.9.9')
	`, nameOnlyDeviceID)
	if err != nil {
		t.Fatalf("seed name-only device_apps: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.example.mixed', 'MixedApp', 'any', 'unapproved', 'app_management')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed unapproved policy: %v", err)
	}

	email := "mixed@unapproved-ev.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unapproved-apps = %d: %s", resp.StatusCode, b)
	}
	var out unapprovedAppsEvidenceOut
	decodeJSON(t, resp, &out)
	if len(out.Apps) != 1 {
		t.Fatalf("apps = %+v, want exactly one row", out.Apps)
	}
	app := out.Apps[0]
	if app.EvidenceBasis != "name_match_only" {
		t.Errorf("evidence_basis = %q, want name_match_only (one of two matched devices tied only by display name)", app.EvidenceBasis)
	}
	if app.DevicesAffected != 2 || app.IdentifierMatchedCount != 1 || app.NameMatchedCount != 1 {
		t.Errorf("counts = devices_affected=%d identifier_matched=%d name_matched=%d, want 2/1/1",
			app.DevicesAffected, app.IdentifierMatchedCount, app.NameMatchedCount)
	}
}

// TestPortalUnapprovedAppsEvidenceBasisSingleDeviceTwoRowsNotDoubleCounted
// (PAT-1725 review fix): a single device with TWO device_apps rows — one
// tied to the policy only by bundle_id, the other tied only by display
// name — must count as exactly ONE identifier-matched device and ZERO
// name-matched devices, never both. An earlier version derived
// name_matched_devices with a per-ROW "matched by name AND NOT matched by
// identifier" SQL FILTER, which double-counted this exact device: the
// identifier FILTER passed via the bundle_id row, and the name FILTER also
// passed via the OTHER row (which itself has no identifier match), so the
// same device_id landed in both COUNT(DISTINCT ...) buckets. The fix
// derives name_matched_devices in Go as devices_with_app -
// identifier_matched, which is correct per-device by construction.
func TestPortalUnapprovedAppsEvidenceBasisSingleDeviceTwoRowsNotDoubleCounted(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-unapproved-ev-tworows")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-ev-tworows', gen_random_uuid(), 'host-ev-tworows', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// Row 1: matches the policy's bundle_id — a real identifier.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'TwoRowsApp', 'com.example.tworows', '1.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed identifier-matched row: %v", err)
	}
	// Row 2: same device, a SECOND installed app that only matches the
	// policy by display name (different identifier entirely).
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, identifier, version)
		VALUES ($1::uuid, 'TwoRowsApp', 'com.example.tworows.unrelated-copy', '2.0.0')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed name-only row on same device: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_app_policies (tenant_id, bundle_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'com.example.tworows', 'TwoRowsApp', 'any', 'unapproved', 'app_management')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed unapproved policy: %v", err)
	}

	email := "tworows@unapproved-ev.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unapproved-apps = %d: %s", resp.StatusCode, b)
	}
	var out unapprovedAppsEvidenceOut
	decodeJSON(t, resp, &out)
	if len(out.Apps) != 1 {
		t.Fatalf("apps = %+v, want exactly one row", out.Apps)
	}
	app := out.Apps[0]
	if app.DevicesAffected != 1 {
		t.Fatalf("devices_affected = %d, want 1 (one device, two device_apps rows)", app.DevicesAffected)
	}
	if app.IdentifierMatchedCount != 1 || app.NameMatchedCount != 0 {
		t.Errorf("counts = identifier_matched=%d name_matched=%d, want 1/0 (the device has an identifier-matched row, so it must not ALSO land in name_matched)",
			app.IdentifierMatchedCount, app.NameMatchedCount)
	}
	if app.EvidenceBasis != "identifier_match" {
		t.Errorf("evidence_basis = %q, want identifier_match", app.EvidenceBasis)
	}
}

// TestPortalUnapprovedAppsEvidenceBasisNoMatchIsUnknown (PAT-1725): a policy
// row with zero matched devices has no evidence to grade at all — it must
// report "unknown", never default to "identifier_match".
func TestPortalUnapprovedAppsEvidenceBasisNoMatchIsUnknown(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-unapproved-ev-unknown")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	_, err = env.pool.Exec(t.Context(), `
		INSERT INTO tenant_app_policies (tenant_id, name, platform, policy, enforcement_tier)
		VALUES ($1::uuid, 'NeverInstalledApp', 'any', 'unapproved', 'report')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed unapproved policy with no matching device: %v", err)
	}

	email := "unknown@unapproved-ev.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/unapproved-apps", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("unapproved-apps = %d: %s", resp.StatusCode, b)
	}
	var out unapprovedAppsEvidenceOut
	decodeJSON(t, resp, &out)
	if len(out.Apps) != 1 {
		t.Fatalf("apps = %+v, want exactly one row", out.Apps)
	}
	app := out.Apps[0]
	if app.EvidenceBasis != "unknown" {
		t.Errorf("evidence_basis = %q, want unknown (zero matched devices; never default to identifier_match)", app.EvidenceBasis)
	}
	if app.DevicesAffected != 0 || app.IdentifierMatchedCount != 0 || app.NameMatchedCount != 0 {
		t.Errorf("counts = devices_affected=%d identifier_matched=%d name_matched=%d, want 0/0/0",
			app.DevicesAffected, app.IdentifierMatchedCount, app.NameMatchedCount)
	}
}

// ---------------------------------------------------------------------------
// GET /v1/portal/extensions — aggregation, approval-state derivation, empty
// state (PAT-933)
// ---------------------------------------------------------------------------

// TestPortalExtensionsAggregation seeds two devices on one tenant, both
// running the same browser extension at different versions, and asserts the
// endpoint reports exactly one row with device_count = 2, both versions
// listed, and both hostnames present for drill-down — proving the
// aggregation is real, not per-device duplication.
func TestPortalExtensionsAggregation(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-agg")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceIDs [2]string
	hostnames := [2]string{"agg-host-0", "agg-host-1"}
	versions := [2]string{"1.0.0", "1.1.0"}
	for i := range deviceIDs {
		err = env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
			VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.5', '24F74', 'arm64', now())
			RETURNING id::text
		`, tenantID, fmt.Sprintf("SER-ext-agg-%d", i), hostnames[i]).Scan(&deviceIDs[i])
		if err != nil {
			t.Fatalf("seed device %d: %v", i, err)
		}
		_, err = env.pool.Exec(ctx, `
			INSERT INTO device_browser_extensions
				(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
			VALUES ($1::uuid, 'chrome', 'user', 'Default', 'ext-agg-shared', 'SharedExtension', $2, 'normal')
		`, deviceIDs[i], versions[i])
		if err != nil {
			t.Fatalf("seed extension on device %d: %v", i, err)
		}
	}

	email := "agg@ext-agg.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Total      int `json:"total"`
		Extensions []struct {
			ExtensionID   string   `json:"extension_id"`
			Name          string   `json:"name"`
			Browser       string   `json:"browser"`
			Versions      []string `json:"versions"`
			DeviceCount   int      `json:"device_count"`
			ApprovalState string   `json:"approval_state"`
			Devices       []struct {
				DeviceID string `json:"device_id"`
				Hostname string `json:"hostname"`
			} `json:"devices"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)

	if out.Total != 1 || len(out.Extensions) != 1 {
		t.Fatalf("total=%d len=%d, want exactly 1 aggregated extension row", out.Total, len(out.Extensions))
	}
	ext := out.Extensions[0]
	if ext.ExtensionID != "ext-agg-shared" {
		t.Errorf("extension_id = %q, want ext-agg-shared", ext.ExtensionID)
	}
	if ext.Name != "SharedExtension" {
		t.Errorf("name = %q, want SharedExtension", ext.Name)
	}
	if ext.Browser != "chrome" {
		t.Errorf("browser = %q, want chrome", ext.Browser)
	}
	if ext.DeviceCount != 2 {
		t.Errorf("device_count = %d, want 2 (aggregated across both devices)", ext.DeviceCount)
	}
	if len(ext.Devices) != 2 {
		t.Fatalf("devices = %+v, want 2 entries for drill-down", ext.Devices)
	}
	gotHostnames := map[string]bool{}
	for _, d := range ext.Devices {
		gotHostnames[d.Hostname] = true
	}
	for _, h := range hostnames {
		if !gotHostnames[h] {
			t.Errorf("devices missing hostname %q for drill-down: %+v", h, ext.Devices)
		}
	}
	if len(ext.Versions) != 2 {
		t.Fatalf("versions = %+v, want both 1.0.0 and 1.1.0", ext.Versions)
	}
	gotVersions := map[string]bool{}
	for _, v := range ext.Versions {
		gotVersions[v] = true
	}
	for _, v := range versions {
		if !gotVersions[v] {
			t.Errorf("versions missing %q: %+v", v, ext.Versions)
		}
	}
	if ext.ApprovalState != "unreviewed" {
		t.Errorf("approval_state = %q, want unreviewed (no policy row seeded)", ext.ApprovalState)
	}
}

// TestPortalExtensionsEvidenceBasisIsAlwaysIdentifierMatch (PAT-1725):
// extensions are grouped and matched by extension_id, the browser store's
// own identifier — never by display name — so evidence_basis must always
// read "identifier_match", even when two devices report different names for
// the same extension_id (a renamed or localized extension listing).
func TestPortalExtensionsEvidenceBasisIsAlwaysIdentifierMatch(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-ev-idmatch")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceIDs [2]string
	names := [2]string{"AdBlock Plus", "Adblock Plus (renamed)"}
	for i := range deviceIDs {
		err = env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
			VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.5', '24F74', 'arm64', now())
			RETURNING id::text
		`, tenantID, fmt.Sprintf("SER-ext-ev-idmatch-%d", i), fmt.Sprintf("host-ext-ev-idmatch-%d", i)).Scan(&deviceIDs[i])
		if err != nil {
			t.Fatalf("seed device %d: %v", i, err)
		}
		_, err = env.pool.Exec(ctx, `
			INSERT INTO device_browser_extensions
				(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
			VALUES ($1::uuid, 'chrome', 'user', 'Default', 'ext-ev-idmatch', $2, '1.0', 'normal')
		`, deviceIDs[i], names[i])
		if err != nil {
			t.Fatalf("seed extension on device %d: %v", i, err)
		}
	}

	email := "idmatch@ext-ev.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Extensions []struct {
			ExtensionID   string `json:"extension_id"`
			EvidenceBasis string `json:"evidence_basis"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)
	if len(out.Extensions) != 1 {
		t.Fatalf("extensions = %+v, want exactly one aggregated row", out.Extensions)
	}
	if out.Extensions[0].EvidenceBasis != "identifier_match" {
		t.Errorf("evidence_basis = %q, want identifier_match (grouped by extension_id, a real identifier, despite differing display names)",
			out.Extensions[0].EvidenceBasis)
	}
}

// TestPortalExtensionsApprovalStateDerivation seeds one tenant with four
// extensions covering all four approval states the PAT-826 policy store
// distinguishes: a persisted "approved" row, a persisted "unapproved" row, a
// persisted "ignored" row, and an extension with NO policy row at all
// (implicit "unreviewed" — the state PAT-933 must expose distinctly from an
// explicit "approved" decision, since an operator has not actually reviewed
// it). It also proves a browser-specific policy row wins over a
// browser-agnostic 'any' row for the same extension_id.
func TestPortalExtensionsApprovalStateDerivation(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-states")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-ext-states', gen_random_uuid(), 'host-ext-states', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	type seed struct {
		extID, name, want string
	}
	plain := []seed{
		{"ext-approved", "ApprovedExt", "approved"},
		{"ext-unapproved", "UnapprovedExt", "unapproved"},
		{"ext-ignored", "IgnoredExt", "ignored"},
		{"ext-unreviewed", "UnreviewedExt", "unreviewed"},
	}
	for _, s := range plain {
		_, err = env.pool.Exec(ctx, `
			INSERT INTO device_browser_extensions
				(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
			VALUES ($1::uuid, 'chrome', 'user', 'Default', $2, $3, '1.0', 'normal')
		`, deviceID, s.extID, s.name)
		if err != nil {
			t.Fatalf("seed extension %s: %v", s.extID, err)
		}
		if s.want == "unreviewed" {
			continue // no policy row — the implicit fourth state
		}
		_, err = env.pool.Exec(ctx, `
			INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
			VALUES ($1::uuid, 'any', $2, $3, $4)
		`, tenantID, s.extID, s.name, s.want)
		if err != nil {
			t.Fatalf("seed policy for %s: %v", s.extID, err)
		}
	}

	// Browser-specific override: an 'any' row says approved, but a
	// chrome-specific row says unapproved for the same extension_id — the
	// chrome-specific row must win for a chrome observation.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		VALUES ($1::uuid, 'chrome', 'user', 'Default', 'ext-override', 'OverrideExt', '1.0', 'normal')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed override extension: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'any', 'ext-override', 'OverrideExt', 'approved')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed 'any' policy for override: %v", err)
	}
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'chrome', 'ext-override', 'OverrideExt', 'unapproved')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed chrome-specific policy for override: %v", err)
	}

	email := "states@ext-states.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Extensions []struct {
			ExtensionID   string `json:"extension_id"`
			ApprovalState string `json:"approval_state"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)

	got := map[string]string{}
	for _, e := range out.Extensions {
		got[e.ExtensionID] = e.ApprovalState
	}
	for _, s := range plain {
		if got[s.extID] != s.want {
			t.Errorf("approval_state[%s] = %q, want %q", s.extID, got[s.extID], s.want)
		}
	}
	if got["ext-override"] != "unapproved" {
		t.Errorf("approval_state[ext-override] = %q, want unapproved (browser-specific row must win over 'any')", got["ext-override"])
	}
}

// TestPortalExtensionsDecisionProvenance (PAT-1800) asserts decided_by/
// decided_at/justification are sourced from the matched
// tenant_extension_policies row (approved_by/updated_at/notes) when one
// exists, and are all null for an "unreviewed" row with no policy row at
// all — never fabricated. Also asserts an empty-string approved_by/notes
// (the table's NOT NULL DEFAULT ”) reads as null, not as a real decision.
func TestPortalExtensionsDecisionProvenance(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-provenance")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-ext-prov', gen_random_uuid(), 'host-ext-prov', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		VALUES
			($1::uuid, 'chrome', 'user', 'Default', 'ext-decided', 'DecidedExt', '1.0', 'normal'),
			($1::uuid, 'chrome', 'user', 'Default', 'ext-blank', 'BlankExt', '1.0', 'normal'),
			($1::uuid, 'chrome', 'user', 'Default', 'ext-unreviewed', 'UnreviewedExt', '1.0', 'normal')
	`, deviceID)
	if err != nil {
		t.Fatalf("seed extensions: %v", err)
	}

	// A real decision: approved_by and notes both set.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy, approved_by, notes)
		VALUES ($1::uuid, 'any', 'ext-decided', 'DecidedExt', 'approved', 'admin@example.com', 'Vetted by security team')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed decided policy: %v", err)
	}

	// A policy row with the table's default blank approved_by/notes — must
	// read as null, not as an empty-string "decision".
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'any', 'ext-blank', 'BlankExt', 'unapproved')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed blank policy: %v", err)
	}

	// ext-unreviewed has no policy row at all.

	email := "provenance@ext-provenance.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Extensions []struct {
			ExtensionID   string     `json:"extension_id"`
			ApprovalState string     `json:"approval_state"`
			DecidedBy     *string    `json:"decided_by"`
			DecidedAt     *time.Time `json:"decided_at"`
			Justification *string    `json:"justification"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)

	byID := map[string]struct {
		ApprovalState string
		DecidedBy     *string
		DecidedAt     *time.Time
		Justification *string
	}{}
	for _, e := range out.Extensions {
		byID[e.ExtensionID] = struct {
			ApprovalState string
			DecidedBy     *string
			DecidedAt     *time.Time
			Justification *string
		}{e.ApprovalState, e.DecidedBy, e.DecidedAt, e.Justification}
	}

	decided, ok := byID["ext-decided"]
	if !ok {
		t.Fatalf("ext-decided missing from response")
	}
	if decided.DecidedBy == nil || *decided.DecidedBy != "admin@example.com" {
		t.Errorf("ext-decided decided_by = %v, want admin@example.com", decided.DecidedBy)
	}
	if decided.DecidedAt == nil {
		t.Errorf("ext-decided decided_at = nil, want a real timestamp")
	}
	if decided.Justification == nil || *decided.Justification != "Vetted by security team" {
		t.Errorf("ext-decided justification = %v, want %q", decided.Justification, "Vetted by security team")
	}

	blank, ok := byID["ext-blank"]
	if !ok {
		t.Fatalf("ext-blank missing from response")
	}
	if blank.DecidedBy != nil {
		t.Errorf("ext-blank decided_by = %v, want nil (empty approved_by must not read as a real decision)", *blank.DecidedBy)
	}
	if blank.Justification != nil {
		t.Errorf("ext-blank justification = %v, want nil (empty notes must not read as a real decision)", *blank.Justification)
	}
	if blank.DecidedAt == nil {
		t.Errorf("ext-blank decided_at = nil, want a real timestamp (the policy row itself was still created/decided)")
	}

	unreviewed, ok := byID["ext-unreviewed"]
	if !ok {
		t.Fatalf("ext-unreviewed missing from response")
	}
	if unreviewed.ApprovalState != "unreviewed" {
		t.Fatalf("ext-unreviewed approval_state = %q, want unreviewed", unreviewed.ApprovalState)
	}
	if unreviewed.DecidedBy != nil || unreviewed.DecidedAt != nil || unreviewed.Justification != nil {
		t.Errorf("ext-unreviewed provenance = decided_by=%v decided_at=%v justification=%v, want all nil (no policy row exists)",
			unreviewed.DecidedBy, unreviewed.DecidedAt, unreviewed.Justification)
	}
}

// TestPortalExtensionsEmptyState asserts a tenant with no browser extension
// telemetry gets a 200 with an empty (never null) extensions array, not an
// error. Also asserts estate_too_large is false here (PAT-933 gate round
// 5): this ordinary empty-tenant response and the fail-closed
// source-row-cap response (TestPortalExtensionsSourceRowCap) are otherwise
// identical (total 0, extensions empty), so estate_too_large is the only
// field that tells them apart — this test proves it reads false for the
// case it must NOT fire for.
func TestPortalExtensionsEmptyState(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-empty")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	email := "empty@ext-empty.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Total          int   `json:"total"`
		EstateTooLarge bool  `json:"estate_too_large"`
		Extensions     []any `json:"extensions"`
	}
	decodeJSON(t, resp, &out)
	if out.Total != 0 {
		t.Errorf("total = %d, want 0", out.Total)
	}
	if out.EstateTooLarge {
		t.Errorf("estate_too_large = true, want false (tenant has no telemetry, not an oversized estate)")
	}
	if out.Extensions == nil {
		t.Errorf("extensions = nil, want empty (never null) array")
	}
	if len(out.Extensions) != 0 {
		t.Errorf("extensions = %+v, want empty", out.Extensions)
	}
}

// TestPortalExtensionsDeviceDrilldownCap seeds one extension on 55 devices
// (over the 50-device drill-down cap) and asserts the GitHub-Non-Author-Review abuse-resistance
// behaviour: device_count stays the exact total, the devices list is capped
// at 50 entries ordered by hostname (so the first 50 alphabetically survive),
// and devices_truncated is set.
func TestPortalExtensionsDeviceDrilldownCap(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-devcap")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	const seeded = 55
	for i := 0; i < seeded; i++ {
		var deviceID string
		hostname := fmt.Sprintf("devcap-host-%03d", i) // zero-padded => hostname order == numeric order
		err = env.pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
			VALUES ($1::uuid, $2, gen_random_uuid(), $3, 'macOS', '15.5', '24F74', 'arm64', now())
			RETURNING id::text
		`, tenantID, fmt.Sprintf("SER-devcap-%03d", i), hostname).Scan(&deviceID)
		if err != nil {
			t.Fatalf("seed device %d: %v", i, err)
		}
		_, err = env.pool.Exec(ctx, `
			INSERT INTO device_browser_extensions
				(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
			VALUES ($1::uuid, 'chrome', 'user', 'Default', 'ext-devcap', 'DevCapExt', '1.0', 'normal')
		`, deviceID)
		if err != nil {
			t.Fatalf("seed extension on device %d: %v", i, err)
		}
	}

	email := "devcap@ext-devcap.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Total      int  `json:"total"`
		Truncated  bool `json:"truncated"`
		Extensions []struct {
			ExtensionID  string `json:"extension_id"`
			DeviceCount  int    `json:"device_count"`
			DevicesTrunc bool   `json:"devices_truncated"`
			Devices      []struct {
				Hostname string `json:"hostname"`
			} `json:"devices"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)

	if out.Total != 1 || len(out.Extensions) != 1 {
		t.Fatalf("total=%d len=%d, want exactly 1 extension row", out.Total, len(out.Extensions))
	}
	if out.Truncated {
		t.Errorf("truncated = true, want false (only 1 extension row)")
	}
	ext := out.Extensions[0]
	if ext.DeviceCount != seeded {
		t.Errorf("device_count = %d, want %d (exact, never capped)", ext.DeviceCount, seeded)
	}
	if len(ext.Devices) != 50 {
		t.Fatalf("devices = %d entries, want exactly 50 (the drill-down cap)", len(ext.Devices))
	}
	if !ext.DevicesTrunc {
		t.Errorf("devices_truncated = false, want true (%d devices > cap)", seeded)
	}
	// The cap keeps the FIRST 50 by hostname: 000..049 present, 050+ cut.
	if got := ext.Devices[0].Hostname; got != "devcap-host-000" {
		t.Errorf("first device = %q, want devcap-host-000", got)
	}
	if got := ext.Devices[49].Hostname; got != "devcap-host-049" {
		t.Errorf("last device = %q, want devcap-host-049", got)
	}
	for _, d := range ext.Devices {
		if d.Hostname >= "devcap-host-050" {
			t.Errorf("over-cap device %q leaked into the drill-down", d.Hostname)
		}
	}
}

// TestPortalExtensionsVersionsCap seeds one extension reporting 25 distinct
// versions across profiles on one device and asserts the version list is
// capped at 20 (lowest-sorting first) with versions_truncated set, while
// device_count stays exact.
func TestPortalExtensionsVersionsCap(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-vercap")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-vercap', gen_random_uuid(), 'host-vercap', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// 25 distinct versions via 25 distinct profiles (unique index includes
	// profile, so one device can carry them all).
	const seededVersions = 25
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		SELECT $1::uuid, 'chrome', 'user', 'Profile-' || LPAD(i::text, 2, '0'),
		       'ext-vercap', 'VerCapExt', '1.0.' || LPAD(i::text, 2, '0'), 'normal'
		FROM generate_series(0, $2::int - 1) AS i
	`, deviceID, seededVersions)
	if err != nil {
		t.Fatalf("seed versions: %v", err)
	}

	email := "vercap@ext-vercap.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Extensions []struct {
			ExtensionID   string   `json:"extension_id"`
			Versions      []string `json:"versions"`
			VersionsTrunc bool     `json:"versions_truncated"`
			DeviceCount   int      `json:"device_count"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)

	if len(out.Extensions) != 1 {
		t.Fatalf("extensions = %d rows, want 1", len(out.Extensions))
	}
	ext := out.Extensions[0]
	if len(ext.Versions) != 20 {
		t.Fatalf("versions = %d entries, want exactly 20 (the version cap): %v", len(ext.Versions), ext.Versions)
	}
	if !ext.VersionsTrunc {
		t.Errorf("versions_truncated = false, want true (%d versions > cap)", seededVersions)
	}
	if ext.Versions[0] != "1.0.00" || ext.Versions[19] != "1.0.19" {
		t.Errorf("versions cap must keep the 20 lowest-sorting: first=%q last=%q", ext.Versions[0], ext.Versions[19])
	}
	if ext.DeviceCount != 1 {
		t.Errorf("device_count = %d, want 1", ext.DeviceCount)
	}
}

// TestPortalExtensionsVersionCountExactPreCap (PAT-1799) reuses the same
// 25-version seed as TestPortalExtensionsVersionsCap and asserts
// version_count reports the exact pre-cap distinct-version count (25), not
// len(versions) (20, after the display cap) — the field exists so the portal
// can show "N devices on M versions" without under-reporting M once the
// versions list itself has been truncated.
func TestPortalExtensionsVersionCountExactPreCap(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-vercount")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-vercount', gen_random_uuid(), 'host-vercount', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	const seededVersions = 25
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		SELECT $1::uuid, 'chrome', 'user', 'Profile-' || LPAD(i::text, 2, '0'),
		       'ext-vercount', 'VerCountExt', '1.0.' || LPAD(i::text, 2, '0'), 'normal'
		FROM generate_series(0, $2::int - 1) AS i
	`, deviceID, seededVersions)
	if err != nil {
		t.Fatalf("seed versions: %v", err)
	}

	email := "vercount@ext-vercount.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Extensions []struct {
			ExtensionID   string   `json:"extension_id"`
			Versions      []string `json:"versions"`
			VersionsTrunc bool     `json:"versions_truncated"`
			VersionCount  int      `json:"version_count"`
			DeviceCount   int      `json:"device_count"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)

	if len(out.Extensions) != 1 {
		t.Fatalf("extensions = %d rows, want 1", len(out.Extensions))
	}
	ext := out.Extensions[0]
	if ext.VersionCount != seededVersions {
		t.Errorf("version_count = %d, want %d (exact pre-cap count, independent of the %d-entry display cap)",
			ext.VersionCount, seededVersions, len(ext.Versions))
	}
	if len(ext.Versions) != 20 {
		t.Fatalf("versions = %d entries, want exactly 20 (the display cap)", len(ext.Versions))
	}
}

// TestPortalExtensionsRowCap seeds 505 distinct extensions on one device
// (over the 500-row cap), tagging exactly one of the LAST-alphabetically
// extensions unapproved, and asserts: the response carries exactly 500 rows,
// total stays the exact 505, truncated is set, and the unapproved extension
// survives the cut because unapproved rows order first — the cap bites the
// unreviewed tail, never the page's point.
func TestPortalExtensionsRowCap(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-rowcap")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-rowcap', gen_random_uuid(), 'host-rowcap', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// 505 extensions in one INSERT; names zzz-ext-000..zzz-ext-504 so the
	// unapproved one below sorts alphabetically LAST among its state peers.
	const seeded = 505
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		SELECT $1::uuid, 'chrome', 'user', 'Default',
		       'ext-rowcap-' || LPAD(i::text, 3, '0'),
		       'zzz-ext-' || LPAD(i::text, 3, '0'),
		       '1.0', 'normal'
		FROM generate_series(0, $2::int - 1) AS i
	`, deviceID, seeded)
	if err != nil {
		t.Fatalf("seed extensions: %v", err)
	}

	// Tag the alphabetically-last extension unapproved. Without state-first
	// ordering it would be cut by the 500-row cap; with it, it must be row 1.
	_, err = env.pool.Exec(ctx, `
		INSERT INTO tenant_extension_policies (tenant_id, browser, extension_id, name, policy)
		VALUES ($1::uuid, 'any', 'ext-rowcap-504', 'zzz-ext-504', 'unapproved')
	`, tenantID)
	if err != nil {
		t.Fatalf("seed unapproved policy: %v", err)
	}

	email := "rowcap@ext-rowcap.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Total      int  `json:"total"`
		Truncated  bool `json:"truncated"`
		Extensions []struct {
			ExtensionID   string `json:"extension_id"`
			ApprovalState string `json:"approval_state"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)

	if out.Total != seeded {
		t.Errorf("total = %d, want %d (exact pre-cap count)", out.Total, seeded)
	}
	if len(out.Extensions) != 500 {
		t.Fatalf("extensions = %d rows, want exactly 500 (the row cap)", len(out.Extensions))
	}
	if !out.Truncated {
		t.Errorf("truncated = false, want true (%d > 500)", seeded)
	}
	if out.Extensions[0].ExtensionID != "ext-rowcap-504" || out.Extensions[0].ApprovalState != "unapproved" {
		t.Errorf("first row = %s (%s), want ext-rowcap-504 (unapproved) — unapproved rows must survive the cap",
			out.Extensions[0].ExtensionID, out.Extensions[0].ApprovalState)
	}
	for i, e := range out.Extensions[1:] {
		if e.ApprovalState != "unreviewed" {
			t.Errorf("row %d approval_state = %q, want unreviewed", i+1, e.ApprovalState)
		}
	}
}

// TestPortalExtensionsTextFieldTruncation seeds two extensions on one device
// whose (via the device) hostname is oversized, plus extension_id/name/
// browser/version sitting AT their documented caps (GitHub-Non-Author-Review gate round 3:
// count caps alone don't bound response size when the underlying `text`
// columns are tenant-controlled). It asserts the hostname comes back
// truncated to its documented cap, the at-cap fields pass through unchanged
// (proving the boundary is inclusive, not an off-by-one truncation), and
// device_count/version_count and the truncated flags — which come from
// separate untruncated aggregates — remain exact.
//
// PAT-933 gate round 7 / migration 0085 added CHECK constraints on
// device_browser_extensions.{browser,extension_id,name,version} equal to
// this file's own display caps (portalExtensionsMaxBrowserLen/MaxIDLen/
// MaxNameLen/MaxVersionLen), so — unlike before round 7 — this test can no
// longer seed those four columns OVER their caps even via direct SQL: the
// INSERT itself is now rejected before an oversized row can exist. That is
// the intended effect of 0085, not a gap in this test; see
// TestPortalExtensionsFieldLengthChecksRejectOversizedRows below for the
// regression coverage proving the CHECK constraints actually hold.
// devices.hostname carries no such constraint (0085 only touches
// device_browser_extensions), so it remains the one field here that can
// still be seeded oversized and is still expected to come back truncated by
// this query's output-projection LEFT() — see part (c) of this file's... er,
// portal_extensions.go's doc comment.
//
// The two extensions share a long common prefix in extension_id (under
// portalExtensionsMaxIDLen, so the INSERT succeeds) but differ after that.
// Asserting exactly two distinct rows come back, each correctly aggregated,
// still proves the ident CTE's GROUP BY and the LATERAL join predicates
// (dbe.extension_id = p.extension_id) key off the full value and don't
// collapse similar-prefixed identities into one aggregated row.
func TestPortalExtensionsTextFieldTruncation(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-trunc")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	longHostname := "trunc-host-" + strings.Repeat("h", 300)
	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-trunc', gen_random_uuid(), $2, 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID, longHostname).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// Shared prefix well under portalExtensionsMaxIDLen (128) so both
	// INSERTs succeed under the 0085 CHECK constraint; the two full values
	// still differ and must remain distinct aggregated rows.
	sharedIDPrefix := strings.Repeat("x", 90)
	extIDFirst := sharedIDPrefix + "-first-tail-stays-distinct"
	extIDSecond := sharedIDPrefix + "-second-tail-stays-distinct"
	// name below its 256 cap (no truncation expected); browser and version
	// sit EXACTLY at their caps (32 / 64) to prove the boundary is
	// inclusive — LEFT(x, cap) on a cap-length string must be a no-op.
	name := "TruncExt-" + strings.Repeat("n", 200)
	browser := "chrome-" + strings.Repeat("b", 25) // 7 + 25 = 32
	version := "1.0.0-" + strings.Repeat("v", 58)  // 6 + 58 = 64

	for _, extID := range []string{extIDFirst, extIDSecond} {
		_, err = env.pool.Exec(ctx, `
			INSERT INTO device_browser_extensions
				(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
			VALUES ($1::uuid, $2, 'user', 'Default', $3, $4, $5, 'normal')
		`, deviceID, browser, extID, name, version)
		if err != nil {
			t.Fatalf("seed extension %s: %v", extID, err)
		}
	}

	email := "trunc@ext-trunc.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Total      int  `json:"total"`
		Truncated  bool `json:"truncated"`
		Extensions []struct {
			ExtensionID   string   `json:"extension_id"`
			Name          string   `json:"name"`
			Browser       string   `json:"browser"`
			Versions      []string `json:"versions"`
			VersionsTrunc bool     `json:"versions_truncated"`
			DeviceCount   int      `json:"device_count"`
			DevicesTrunc  bool     `json:"devices_truncated"`
			Devices       []struct {
				Hostname string `json:"hostname"`
			} `json:"devices"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)

	// Two distinct extension_ids must survive as two distinct rows — proof
	// the shared prefix never causes the GROUP BY / join keys to collapse
	// similar identities.
	if out.Total != 2 || len(out.Extensions) != 2 {
		t.Fatalf("total=%d len=%d, want exactly 2 aggregated extension rows (must not collapse on shared prefix)",
			out.Total, len(out.Extensions))
	}
	if out.Truncated {
		t.Errorf("truncated = true, want false (only 2 rows, well under the row cap)")
	}

	wantExtIDs := map[string]bool{extIDFirst: true, extIDSecond: true}
	seenIDs := map[string]bool{}
	for _, ext := range out.Extensions {
		seenIDs[ext.ExtensionID] = true

		// extension_id is well under its 128 cap and must pass through
		// byte-for-byte unmodified.
		if !wantExtIDs[ext.ExtensionID] {
			t.Errorf("extension_id = %q, want one of %v (unmodified, under cap)", ext.ExtensionID, wantExtIDs)
		}
		// name is under its 256 cap and must pass through unmodified.
		if ext.Name != name {
			t.Errorf("name = %q, want unmodified %q (under portalExtensionsMaxNameLen)", ext.Name, name)
		}
		// browser sits EXACTLY at its 32 cap — LEFT(x, 32) on a 32-char
		// string must be a no-op, not an off-by-one truncation.
		if got, want := len(ext.Browser), 32; got != want {
			t.Errorf("browser length = %d, want %d (portalExtensionsMaxBrowserLen, at-cap boundary): %q", got, want, ext.Browser)
		}
		if ext.Browser != browser {
			t.Errorf("browser = %q, want unmodified %q (exactly at cap)", ext.Browser, browser)
		}

		if len(ext.Versions) != 1 {
			t.Fatalf("versions = %d entries, want exactly 1", len(ext.Versions))
		}
		// version sits EXACTLY at its 64 cap — same inclusive-boundary check.
		if got, want := len(ext.Versions[0]), 64; got != want {
			t.Errorf("version length = %d, want %d (portalExtensionsMaxVersionLen, at-cap boundary): %q", got, want, ext.Versions[0])
		}
		if ext.Versions[0] != version {
			t.Errorf("version = %q, want unmodified %q (exactly at cap)", ext.Versions[0], version)
		}
		if ext.VersionsTrunc {
			t.Errorf("versions_truncated = true, want false (only 1 version, text truncation must not set the count flag)")
		}

		// device_count/devices_truncated are separate untruncated
		// aggregates — text truncation on the displayed hostname must not
		// perturb them.
		if ext.DeviceCount != 1 {
			t.Errorf("device_count = %d, want 1 (exact, unaffected by text truncation)", ext.DeviceCount)
		}
		if ext.DevicesTrunc {
			t.Errorf("devices_truncated = true, want false (only 1 device)")
		}
		if len(ext.Devices) != 1 {
			t.Fatalf("devices = %d entries, want exactly 1", len(ext.Devices))
		}
		// hostname (devices.hostname) carries no CHECK constraint — it is
		// the one field here still genuinely oversized and still expected
		// to come back truncated by this query's output-projection LEFT().
		if got, want := len(ext.Devices[0].Hostname), 256; got != want {
			t.Errorf("hostname length = %d, want %d (portalExtensionsMaxHostnameLen): %q", got, want, ext.Devices[0].Hostname)
		}
		if ext.Devices[0].Hostname != longHostname[:256] {
			t.Errorf("hostname = %q, want truncated prefix %q", ext.Devices[0].Hostname, longHostname[:256])
		}
	}
	if len(seenIDs) != 2 {
		t.Fatalf("expected 2 distinct extension_ids in the response, got %d distinct: %v", len(seenIDs), seenIDs)
	}
}

// TestPortalExtensionsFieldLengthChecksRejectOversizedRows proves the 0085
// migration's defense-in-depth CHECK constraints actually hold at the
// database level — not just that upsertBrowserExtensions happens to
// truncate before writing (internal/extractor/upsert.go), but that ANY
// write path, including one that bypasses Go entirely, is rejected outright
// for browser/extension_id/name/version values over their documented caps
// (32/128/256/64 — matching this file's own portalExtensionsMaxBrowserLen/
// MaxIDLen/MaxNameLen/MaxVersionLen). This is the regression guard for the
// PAT-933 gate round-7 finding: prior to migration 0085, a row inserted
// directly via SQL (or any future ingestion path) could carry unbounded
// text in these columns; after 0085, the schema itself refuses it.
func TestPortalExtensionsFieldLengthChecksRejectOversizedRows(t *testing.T) {
	ctx := t.Context()
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-checklen")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-checklen', gen_random_uuid(), 'checklen-host', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	const insertStmt = `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, 'normal')
	`

	cases := []struct {
		name           string
		browser        string
		userAccount    string
		profile        string
		extensionID    string
		extName        string
		version        string
		wantConstraint string
	}{
		{
			name:           "browser over 32",
			browser:        strings.Repeat("b", 33),
			userAccount:    "user",
			profile:        "Default",
			extensionID:    "ext-a",
			extName:        "name-a",
			version:        "v1",
			wantConstraint: "device_browser_extensions_browser_len",
		},
		{
			name:           "extension_id over 128",
			browser:        "chrome",
			userAccount:    "user",
			profile:        "Default",
			extensionID:    strings.Repeat("e", 129),
			extName:        "name-b",
			version:        "v1",
			wantConstraint: "device_browser_extensions_extension_id_len",
		},
		{
			name:           "name over 256",
			browser:        "chrome",
			userAccount:    "user",
			profile:        "Default",
			extensionID:    "ext-c",
			extName:        strings.Repeat("n", 257),
			version:        "v1",
			wantConstraint: "device_browser_extensions_name_len",
		},
		{
			name:           "version over 64",
			browser:        "chrome",
			userAccount:    "user",
			profile:        "Default",
			extensionID:    "ext-d",
			extName:        "name-d",
			version:        strings.Repeat("v", 65),
			wantConstraint: "device_browser_extensions_version_len",
		},
		{
			name:           "user_account over 128",
			browser:        "chrome",
			userAccount:    strings.Repeat("u", 129),
			profile:        "Default",
			extensionID:    "ext-e",
			extName:        "name-e",
			version:        "v1",
			wantConstraint: "device_browser_extensions_user_account_len",
		},
		{
			name:           "profile over 128",
			browser:        "chrome",
			userAccount:    "user",
			profile:        strings.Repeat("p", 129),
			extensionID:    "ext-f",
			extName:        "name-f",
			version:        "v1",
			wantConstraint: "device_browser_extensions_profile_len",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := env.pool.Exec(ctx, insertStmt, deviceID, tc.browser, tc.userAccount, tc.profile, tc.extensionID, tc.extName, tc.version)
			if err == nil {
				t.Fatalf("insert with %s succeeded, want a CHECK constraint violation (%s)", tc.name, tc.wantConstraint)
			}
			if !strings.Contains(err.Error(), tc.wantConstraint) {
				t.Errorf("insert error = %q, want it to reference constraint %q", err.Error(), tc.wantConstraint)
			}
		})
	}
}

// TestPortalExtensionsSourceRowCap exercises the GitHub-Non-Author-Review gate round-4
// fail-closed guard: portalExtensionsMaxSourceRows caps the tenant's RAW
// (ungrouped) device_browser_extensions row count that FetchPortalExtensions
// will agree to GROUP BY/sort at all, independent of and prior to
// portalExtensionsMaxRows (the displayed-row cap). Without this guard, the
// ident CTE's GROUP BY and total_count's GROUP BY would both scan and group
// every row a tenant has ever accumulated — device_browser_extensions rows
// are upserted (upsertBrowserExtensions, internal/extractor/upsert.go) but
// never deleted, so that count is not bounded by any per-upload or
// per-device cap and grows for the tenant's entire lifetime.
//
// The test lowers portalExtensionsMaxSourceRows to 10 (restored via defer)
// and seeds 15 raw rows — over the lowered threshold but far below
// portalExtensionsMaxRows (500), so a passing "displayed-row cap" test alone
// would not catch a regression here. It asserts the endpoint still answers
// 200 (never 500 — same "degrade gracefully" convention as the missing-table
// case), with an empty extensions list, truncated=true, and (PAT-933 gate
// round 5) estate_too_large=true — the field that distinguishes this
// fail-closed branch from an ordinary empty-tenant response
// (TestPortalExtensionsEmptyState asserts estate_too_large is false there),
// since both otherwise produce byte-for-byte identical total/extensions.
func TestPortalExtensionsSourceRowCap(t *testing.T) {
	ctx := t.Context()
	restore := report.SetPortalExtensionsMaxSourceRowsForTest(10)
	defer restore()

	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-srccap")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-srccap', gen_random_uuid(), 'host-srccap', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// 15 distinct raw rows: over the lowered threshold (10), nowhere near
	// portalExtensionsMaxRows (500).
	const seeded = 15
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		SELECT $1::uuid, 'chrome', 'user', 'Default',
		       'ext-srccap-' || LPAD(i::text, 3, '0'),
		       'srccap-ext-' || LPAD(i::text, 3, '0'),
		       '1.0', 'normal'
		FROM generate_series(0, $2::int - 1) AS i
	`, deviceID, seeded)
	if err != nil {
		t.Fatalf("seed extensions: %v", err)
	}

	email := "srccap@ext-srccap.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d, want 200 (fail closed, not 500): %s", resp.StatusCode, b)
	}
	var out struct {
		Total          int  `json:"total"`
		Truncated      bool `json:"truncated"`
		EstateTooLarge bool `json:"estate_too_large"`
		Extensions     []struct {
			ExtensionID string `json:"extension_id"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)

	if len(out.Extensions) != 0 {
		t.Errorf("extensions = %d entries, want 0 (fail-closed branch never queries the ident CTE)", len(out.Extensions))
	}
	if !out.Truncated {
		t.Errorf("truncated = false, want true (source rows %d > lowered cap 10)", seeded)
	}
	if !out.EstateTooLarge {
		t.Errorf("estate_too_large = false, want true (fail-closed branch fired; this is what distinguishes it from an ordinary empty tenant)")
	}
}

// TestPortalExtensionsSourceRowCapUnderThreshold asserts the new
// portalExtensionsMaxSourceRows guard does not perturb the normal path: with
// the threshold lowered to 10 and only 3 rows seeded (under it), the
// endpoint returns the extensions exactly as it would have before this
// guard existed.
func TestPortalExtensionsSourceRowCapUnderThreshold(t *testing.T) {
	ctx := t.Context()
	restore := report.SetPortalExtensionsMaxSourceRowsForTest(10)
	defer restore()

	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-srccap-ok")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-srccap-ok', gen_random_uuid(), 'host-srccap-ok', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	const seeded = 3
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		SELECT $1::uuid, 'chrome', 'user', 'Default',
		       'ext-srccap-ok-' || LPAD(i::text, 3, '0'),
		       'srccap-ok-ext-' || LPAD(i::text, 3, '0'),
		       '1.0', 'normal'
		FROM generate_series(0, $2::int - 1) AS i
	`, deviceID, seeded)
	if err != nil {
		t.Fatalf("seed extensions: %v", err)
	}

	email := "srccap-ok@ext-srccap-ok.example"
	mapPortalUser(t, email, tenantID, http.StatusCreated)
	token := env.idp.token(t, email)

	resp := portalDo(t, http.MethodGet, "/v1/portal/extensions", token, nil)
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("extensions = %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Total          int  `json:"total"`
		Truncated      bool `json:"truncated"`
		EstateTooLarge bool `json:"estate_too_large"`
		Extensions     []struct {
			ExtensionID string `json:"extension_id"`
		} `json:"extensions"`
	}
	decodeJSON(t, resp, &out)

	if out.Total != seeded {
		t.Errorf("total = %d, want %d (under the source-row cap, unaffected)", out.Total, seeded)
	}
	if len(out.Extensions) != seeded {
		t.Errorf("extensions = %d entries, want %d", len(out.Extensions), seeded)
	}
	if out.Truncated {
		t.Errorf("truncated = true, want false (%d rows is under both caps)", seeded)
	}
	if out.EstateTooLarge {
		t.Errorf("estate_too_large = true, want false (%d rows is under the source-row cap; fail-closed branch must not fire)", seeded)
	}
}

// TestPortalExtensionsSourceRowProbeIsBounded proves the PAT-933 gate
// round-6 fix directly: the fail-closed pre-check in
// report.FetchPortalExtensions is a bounded existence probe (LIMIT
// threshold+1), not a plain COUNT(*) that would have to visit every row a
// tenant has ever accumulated. TestPortalExtensionsSourceRowCap already
// proves the HTTP-visible *behaviour* (200, empty, estate_too_large=true)
// above the threshold, but that response is identical whether the pre-check
// scanned 15 rows or 15 million — it cannot distinguish "bounded" from
// "merely correct". This test seeds a row count far above the lowered
// threshold and calls report.FetchPortalExtensions directly (bypassing
// HTTP) to assert SourceRowCount reads exactly threshold+1, never the true
// seeded count: that is only possible if the probe's LIMIT actually stopped
// the scan early rather than counting every row.
func TestPortalExtensionsSourceRowProbeIsBounded(t *testing.T) {
	ctx := t.Context()
	const threshold = 10
	restore := report.SetPortalExtensionsMaxSourceRowsForTest(threshold)
	defer restore()

	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-ext-probebound")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	var deviceID string
	err = env.pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-probebound', gen_random_uuid(), 'host-probebound', 'macOS', '15.5', '24F74', 'arm64', now())
		RETURNING id::text
	`, tenantID).Scan(&deviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}

	// Seed far more rows than the lowered threshold (10) — if the pre-check
	// were still a plain COUNT(*), SourceRowCount would read exactly 200
	// here; a bounded probe must report exactly threshold+1 (11) instead.
	const seeded = 200
	_, err = env.pool.Exec(ctx, `
		INSERT INTO device_browser_extensions
			(device_id, browser, user_account, profile, extension_id, name, version, risk_level)
		SELECT $1::uuid, 'chrome', 'user', 'Default',
		       'ext-probebound-' || LPAD(i::text, 3, '0'),
		       'probebound-ext-' || LPAD(i::text, 3, '0'),
		       '1.0', 'normal'
		FROM generate_series(0, $2::int - 1) AS i
	`, deviceID, seeded)
	if err != nil {
		t.Fatalf("seed extensions: %v", err)
	}

	res, err := report.FetchPortalExtensions(ctx, env.pool, tenantID)
	if err != nil {
		t.Fatalf("FetchPortalExtensions: %v", err)
	}
	if !res.EstateTooLarge {
		t.Fatalf("estate_too_large = false, want true (%d seeded rows > threshold %d)", seeded, threshold)
	}
	if want := int64(threshold + 1); res.SourceRowCount != want {
		t.Errorf("SourceRowCount = %d, want exactly %d (threshold+1) — a value of %d (the true seeded count) "+
			"would mean the pre-check is scanning every row again, not stopping at LIMIT threshold+1",
			res.SourceRowCount, want, seeded)
	}
}

// ---------------------------------------------------------------------------
// Auth failure modes against the live router
// ---------------------------------------------------------------------------

// TestPortalAuthFailureModes exercises the deny paths end-to-end: no token,
// garbage token, wrong audience, valid token with no portal_users mapping,
// and a disabled mapping (plus re-enable via idempotent re-POST).
func TestPortalAuthFailureModes(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-auth-modes")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	t.Run("missing token is 401", func(t *testing.T) {
		resp := portalDo(t, http.MethodGet, "/v1/portal/overview", "", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("garbage token is 401", func(t *testing.T) {
		resp := portalDo(t, http.MethodGet, "/v1/portal/overview", "not.a.jwt", nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("wrong audience is 401", func(t *testing.T) {
		tok := env.idp.tokenWith(t, jwt.MapClaims{
			"iss":   env.idp.issuer,
			"aud":   "some-other-application",
			"email": "audience@wrong.example",
			"exp":   time.Now().Add(10 * time.Minute).Unix(),
		})
		resp := portalDo(t, http.MethodGet, "/v1/portal/overview", tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("expired token is 401", func(t *testing.T) {
		tok := env.idp.tokenWith(t, jwt.MapClaims{
			"iss":   env.idp.issuer,
			"aud":   env.idp.audience,
			"email": "expired@auth.example",
			"exp":   time.Now().Add(-time.Hour).Unix(),
		})
		resp := portalDo(t, http.MethodGet, "/v1/portal/overview", tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", resp.StatusCode)
		}
	})

	t.Run("verified but unmapped email is 403", func(t *testing.T) {
		resp := portalDo(t, http.MethodGet, "/v1/portal/overview",
			env.idp.token(t, "stranger@nowhere.example"), nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want 403", resp.StatusCode)
		}
	})

	t.Run("disabled mapping is 403 until re-enabled", func(t *testing.T) {
		email := "carol@auth-modes.example"
		mapPortalUser(t, email, tenantID, http.StatusCreated)
		tok := env.idp.token(t, email)

		resp := portalDo(t, http.MethodGet, "/v1/portal/overview", tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("mapped identity = %d, want 200", resp.StatusCode)
		}

		disablePortalUser(t, email)
		resp = portalDo(t, http.MethodGet, "/v1/portal/overview", tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("disabled identity = %d, want 403", resp.StatusCode)
		}

		// Re-POST re-enables (idempotent onboarding).
		mapPortalUser(t, email, tenantID, http.StatusCreated)
		resp = portalDo(t, http.MethodGet, "/v1/portal/overview", tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("re-enabled identity = %d, want 200", resp.StatusCode)
		}
	})
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

// TestPortalReadsAreAuditLogged asserts every authenticated portal read lands
// in portal_access_log with the resolved tenant, and that a denied (unmapped)
// identity is logged too.
func TestPortalReadsAreAuditLogged(t *testing.T) {
	pt := seedPortalTenant(t, "portal-audit", "dave@audit.example", "CVE-2099-2001")

	resp := portalDo(t, http.MethodGet, "/v1/portal/devices", pt.token, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("devices = %d", resp.StatusCode)
	}

	deniedEmail := "mallory@audit-denied.example"
	resp = portalDo(t, http.MethodGet, "/v1/portal/devices", env.idp.token(t, deniedEmail), nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unmapped identity = %d, want 403", resp.StatusCode)
	}

	// The audit insert runs after the response is written; poll briefly.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var okCount, deniedCount int
		err := env.pool.QueryRow(t.Context(), `
			SELECT
				COUNT(*) FILTER (WHERE email = $1 AND tenant_id = $2::uuid AND status = 200),
				COUNT(*) FILTER (WHERE email = $3 AND tenant_id IS NULL AND status = 403)
			FROM portal_access_log
		`, pt.email, pt.tenantID, deniedEmail).Scan(&okCount, &deniedCount)
		if err != nil {
			t.Fatalf("query portal_access_log: %v", err)
		}
		if okCount >= 1 && deniedCount >= 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("audit rows missing: ok=%d denied=%d", okCount, deniedCount)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// ---------------------------------------------------------------------------
// Email-domain auto-binding (PAT-127)
// ---------------------------------------------------------------------------

// TestPortalEmailDomainAutoBinding covers the SSO user-to-tenant binding
// added in PAT-127: a tenant registers its email domain, and any verified
// identity at that domain resolves to it with NO portal_users row required.
// It also proves the resolution order the ticket calls for — the manual
// portal_users override always wins over a domain match — and that a
// domain, once disabled, stops auto-resolving.
func TestPortalEmailDomainAutoBinding(t *testing.T) {
	tenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-domain-auto")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	otherTenantID, _, _, err := createTestTenant(env.internalSrv.URL, "portal-domain-other")
	if err != nil {
		t.Fatalf("create other tenant: %v", err)
	}

	domain := "domain-auto.example"
	mapEmailDomain(t, domain, tenantID, http.StatusCreated)

	// Seed one device on the DOMAIN-registered tenant only. Both tenants are
	// otherwise identical (bare, no devices) — without this, the override
	// test below couldn't actually tell the two resolution paths apart: an
	// empty device list would look the same whether the override worked or
	// was silently ignored in favour of the domain match.
	var domainTenantDeviceHostname = "host-domain-tenant-only"
	_, err = env.pool.Exec(t.Context(), `
		INSERT INTO devices (tenant_id, serial, hw_uuid, hostname, os, os_version, os_build, arch, last_seen)
		VALUES ($1::uuid, 'SER-domain-tenant', gen_random_uuid(), $2, 'macOS', '15.5', '24F74', 'arm64', now())
	`, tenantID, domainTenantDeviceHostname)
	if err != nil {
		t.Fatalf("seed device on domain tenant: %v", err)
	}

	t.Run("unmapped user at a registered domain auto-resolves", func(t *testing.T) {
		tok := env.idp.token(t, "newuser@"+domain)
		resp := portalDo(t, http.MethodGet, "/v1/portal/overview", tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (domain auto-bind)", resp.StatusCode)
		}
	})

	t.Run("manual portal_users override wins over domain match", func(t *testing.T) {
		// A consultant on the same domain, but explicitly pinned elsewhere —
		// e.g. an agency address that happens to share a domain with a
		// customer but must resolve to a different tenant.
		email := "consultant@" + domain
		mapPortalUser(t, email, otherTenantID, http.StatusCreated)
		tok := env.idp.token(t, email)

		resp := portalDo(t, http.MethodGet, "/v1/portal/devices", tok, nil)
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
		var got struct {
			Devices []map[string]any `json:"devices"`
		}
		decodeJSON(t, resp, &got)
		// otherTenantID (the override target) has no seeded devices; the
		// domain-registered tenant has exactly one. Asserting an EMPTY
		// roster here is the discriminating check — a non-empty roster (or
		// the seeded device's hostname) would mean the override was ignored
		// and the domain match won instead.
		if len(got.Devices) != 0 {
			t.Errorf("devices = %d, want 0 (should resolve to override tenant, not domain tenant)", len(got.Devices))
		}
	})

	t.Run("disabled domain stops auto-resolving", func(t *testing.T) {
		email := "another-newuser@" + domain
		tok := env.idp.token(t, email)

		resp := portalDo(t, http.MethodGet, "/v1/portal/overview", tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("pre-disable status = %d, want 200", resp.StatusCode)
		}

		disableEmailDomain(t, domain)

		resp = portalDo(t, http.MethodGet, "/v1/portal/overview", tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("post-disable status = %d, want 403", resp.StatusCode)
		}

		// Re-registering brings it back (onboarding re-run idempotency, same
		// convention as portal_users).
		mapEmailDomain(t, domain, tenantID, http.StatusCreated)
		resp = portalDo(t, http.MethodGet, "/v1/portal/overview", tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("re-enabled status = %d, want 200", resp.StatusCode)
		}
	})

	t.Run("registering an already-actively-claimed domain to another tenant is rejected", func(t *testing.T) {
		mapEmailDomain(t, domain, otherTenantID, http.StatusConflict)
		// Original binding must be unaffected by the rejected attempt.
		tok := env.idp.token(t, "still-bound@"+domain)
		resp := portalDo(t, http.MethodGet, "/v1/portal/overview", tok, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200 (original binding preserved)", resp.StatusCode)
		}
	})
}
