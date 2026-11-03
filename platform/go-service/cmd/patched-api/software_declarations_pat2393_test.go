package main

// PAT-2393 acceptance through the production router. Run after the normal
// integration migration check, against a disposable TEST_DATABASE_URL only.
// No handler stub, test-only route table, production tenant or network IdP.
import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"patched.im/api/internal/extractor"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/ratelimit"
)

const declarationPath = "/v1/portal/software-declarations"

type declarationFixture struct {
	pool                                                    *pgxpool.Pool
	router                                                  http.Handler
	sign                                                    func(string) string
	tenant, other, email, admin, viewer, otherAdmin, bearer string
	secret                                                  []byte
}

func pat2393Owner(t *testing.T) {
	t.Helper()
	p, n := os.Getenv("QUEUE_RUN_TEST_OWNER_PATH"), os.Getenv("QUEUE_RUN_TEST_OWNER_NONCE")
	if p == "" && n == "" {
		return
	}
	if p == "" || n == "" {
		t.Fatal("fixture owner path and nonce must both be configured")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Nonce string `json:"owner_nonce"`
	}
	if json.Unmarshal(b, &record) != nil || record.Nonce != n {
		t.Fatal("fixture ownership changed")
	}
}

func pat2393Fixture(t *testing.T) *declarationFixture {
	t.Helper()
	pat2393Owner(t)
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires migrated disposable TEST_DATABASE_URL; see acceptance command")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	// Portable CI accepts its usual test database. Never connect to a non-test
	// named database or a remote host for these synthetic acceptance mutations.
	if !strings.Contains(strings.ToLower(cfg.ConnConfig.Database), "test") || !(cfg.ConnConfig.Host == "localhost" || cfg.ConnConfig.Host == "127.0.0.1" || strings.HasPrefix(cfg.ConnConfig.Host, "/")) {
		t.Fatal("requires local test database")
	}
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	f := &declarationFixture{pool: pool, secret: []byte("synthetic-pat2393-hmac-secret"), bearer: "synthetic-pat2393-" + pat2393Random()}
	f.tenant = f.seedTenant(t)
	bearerHash := sha256.Sum256([]byte(f.bearer))
	f.exec(t, `INSERT INTO tenant_credentials(tenant_id,bearer_token_hash,hmac_secret) VALUES($1::uuid,$2,$3)`, f.tenant, bearerHash[:], f.secret)
	f.other = f.seedTenant(t)
	otherHash := sha256.Sum256([]byte("other-synthetic-" + pat2393Random()))
	f.exec(t, `UPDATE tenants SET bearer_token_hash=$2 WHERE id=$1::uuid`, f.other, otherHash[:])
	f.email = "admin-" + f.tenant + "@pat2393.invalid"
	viewerEmail, otherEmail := "viewer-"+f.tenant+"@pat2393.invalid", "admin-"+f.other+"@pat2393.invalid"
	for _, u := range [][3]string{{f.email, f.tenant, "admin"}, {viewerEmail, f.tenant, "viewer"}, {otherEmail, f.other, "admin"}} {
		f.exec(t, `INSERT INTO portal_users(email,tenant_id,role) VALUES($1,$2::uuid,$3)`, u[0], u[1], u[2])
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kid": "pat2393-test", "kty": "RSA", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())}}})
	}))
	t.Cleanup(jwks.Close)
	f.sign = func(email string) string {
		claims := jwt.MapClaims{"iss": svcTestIssuer, "aud": svcTestAud, "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix()}
		if email == "service" {
			claims["common_name"] = "pat2393-service.access"
			claims["type"] = "app"
			claims["sub"] = ""
		} else {
			claims["email"] = email
			claims["sub"] = email
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = "pat2393-test"
		s, e := tok.SignedString(key)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	verifier := portalauth.New(svcTestIssuer, svcTestAud, jwks.URL).WithService(&portalauth.ServiceIdentity{CommonName: "pat2393-service.access", TenantID: f.tenant})
	limiter := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})
	f.router = newPublicRouter(pool, nil, limiter, 5*time.Minute, verifier, limiter, limiter, "", "", nil, nil, "", nil, "", nil)
	f.admin, f.viewer, f.otherAdmin = f.sign(f.email), f.sign(viewerEmail), f.sign(otherEmail)
	return f
}
func pat2393Random() string { b := make([]byte, 12); _, _ = rand.Read(b); return hex.EncodeToString(b) }
func (f *declarationFixture) exec(t *testing.T, q string, args ...any) {
	t.Helper()
	pat2393Owner(t)
	if _, e := f.pool.Exec(t.Context(), q, args...); e != nil {
		t.Fatal(e)
	}
}
func (f *declarationFixture) seedTenant(t *testing.T) string {
	t.Helper()
	var id string
	sum := sha256.Sum256([]byte(f.bearer))
	if e := f.pool.QueryRow(t.Context(), `INSERT INTO tenants(name,bearer_token_hash,hmac_secret) VALUES($1,$2,$3) RETURNING id::text`, "PAT2393 synthetic "+pat2393Random(), sum[:], f.secret).Scan(&id); e != nil {
		t.Fatal(e)
	}
	return id
}
func (f *declarationFixture) request(t *testing.T, method, path, token string, body any, want int) *httptest.ResponseRecorder {
	t.Helper()
	pat2393Owner(t)
	var b []byte
	if body != nil {
		var e error
		b, e = json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	r.Header.Set(portalauth.Header, token)
	r.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, r)
	if rr.Code != want {
		t.Fatalf("%s %s = %d, want %d: %s", method, path, rr.Code, want, rr.Body.String())
	}
	return rr
}
func pat2393JSON(t *testing.T, r *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if e := json.Unmarshal(r.Body.Bytes(), &out); e != nil {
		t.Fatal(e)
	}
	return out
}
func pat2393Equal(t *testing.T, row map[string]any, key string, want any) {
	t.Helper()
	if fmt.Sprint(row[key]) != fmt.Sprint(want) {
		t.Errorf("%s = %#v, want %#v; row=%v", key, row[key], want, row)
	}
}
func (f *declarationFixture) create(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	return pat2393JSON(t, f.request(t, "POST", declarationPath, f.admin, body, 201))
}
func pat2393Body(platform string) map[string]any {
	return map[string]any{"name": "Synthetic Editor", "publisher": "Synthetic Publisher", "platform": platform, "justification": "Approved for the synthetic acceptance estate", "min_version": "2.0", "review_date": "2099-12-31"}
}
func (f *declarationFixture) alias(t *testing.T, platform, kind, companion string) (string, string) {
	t.Helper()
	pat2393Owner(t)
	var product, alias string
	identifier := "com.pat2393." + pat2393Random()
	if platform == "windows" {
		identifier = "pat2393.editor." + pat2393Random()
	}
	if e := f.pool.QueryRow(t.Context(), `INSERT INTO software_products(canonical_key,canonical_name,vendor_name,lifecycle_state) VALUES($1,'Synthetic Editor','Synthetic Publisher','active') RETURNING id::text`, identifier).Scan(&product); e != nil {
		t.Fatal(e)
	}
	if e := f.pool.QueryRow(t.Context(), `INSERT INTO software_product_aliases(product_id,platform,identity_kind,identity_value_normalized,companion_value_normalized,match_confidence,provenance) VALUES($1::uuid,$2,$3,$4,$5,'exact','reviewed') RETURNING id::text`, product, platform, kind, identifier, companion).Scan(&alias); e != nil {
		t.Fatal(e)
	}
	return alias, identifier
}
func (f *declarationFixture) row(t *testing.T, id string) map[string]any {
	t.Helper()
	return pat2393JSON(t, f.request(t, "GET", declarationPath+"/"+id, f.viewer, nil, 200))
}
func (f *declarationFixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if e := f.pool.QueryRow(t.Context(), q, args...).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func pat2393ID(t *testing.T, row map[string]any) string {
	t.Helper()
	id, ok := row["id"].(string)
	if !ok || id == "" {
		t.Fatalf("missing declaration id: %v", row)
	}
	return id
}

func TestPAT2393ZeroInstallUnresolvedAndAudit(t *testing.T) {
	f := pat2393Fixture(t)
	body := pat2393Body("macos")
	row := f.create(t, body)
	id := pat2393ID(t, row)
	for key, want := range map[string]any{"name": body["name"], "publisher": body["publisher"], "approval_state": "approved", "identity_state": "unmatched", "observation_state": "not_observed", "observed_installation_count": 0, "source": "portal", "min_version": "2.0", "review_date": "2099-12-31"} {
		pat2393Equal(t, row, key, want)
		pat2393Equal(t, f.row(t, id), key, want)
	}
	if f.count(t, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid`, f.tenant) != 0 {
		t.Fatal("unresolved declaration created an effective/name policy")
	}
	if f.count(t, `SELECT count(*) FROM devices WHERE tenant_id=$1::uuid`, f.tenant) != 0 {
		t.Fatal("creation invented an endpoint")
	}
	history := pat2393JSON(t, f.request(t, "GET", declarationPath+"/"+id+"/history", f.viewer, nil, 200))
	events, ok := history["decisions"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("creation history: %v", history)
	}
	event := events[0].(map[string]any)
	pat2393Equal(t, event, "actor_email", f.email)
	pat2393Equal(t, event, "action", "created")
	pat2393Equal(t, event, "justification", body["justification"])
	if event["decided_at"] == nil {
		t.Fatal("missing audit timestamp")
	}
}
func TestPAT2393KnownSelectionDeduplicatesAndSharesStore(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	body := pat2393Body("macos")
	body["alias_id"] = alias
	row := f.create(t, body)
	id := pat2393ID(t, row)
	pat2393Equal(t, row, "identity_state", "matched")
	pat2393Equal(t, row, "observed_installation_count", 0)
	f.request(t, "POST", declarationPath, f.admin, body, 409)
	if f.count(t, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid AND bundle_id=$2 AND team_id='SYNTHETIC1' AND source='portal' AND policy='approved' AND min_version='2.0'`, f.tenant, identifier) != 1 {
		t.Fatal("known declaration did not use the single existing policy store")
	}
	// The retained operator editor sees and modifies that exact policy. A later
	// declaration read must reflect the authoritative policy, not shadow it.
	f.exec(t, `UPDATE tenant_app_policies SET policy='unapproved' WHERE tenant_id=$1::uuid AND bundle_id=$2`, f.tenant, identifier)
	pat2393Equal(t, f.row(t, id), "approval_state", "unapproved")
}
func TestPAT2393RBACJWTAndTenantIsolation(t *testing.T) {
	f := pat2393Fixture(t)
	body := pat2393Body("windows")
	for _, tok := range []string{f.viewer, f.sign("service")} {
		f.request(t, "POST", declarationPath, tok, body, 403)
	}
	for _, tok := range []string{"", "unsigned.invalid.jwt", f.admin + "tampered"} {
		f.request(t, "POST", declarationPath, tok, body, 401)
	}
	row := f.create(t, body)
	id := pat2393ID(t, row)
	f.request(t, "GET", declarationPath+"/"+id, f.otherAdmin, nil, 404)
	f.request(t, "GET", declarationPath+"/"+id+"/history", f.otherAdmin, nil, 404)
	alias, _ := f.alias(t, "windows", "windows_native_publisher", "cn=synthetic publisher")
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.otherAdmin, map[string]any{"alias_id": alias, "justification": "cross tenant"}, 404)
	other := pat2393JSON(t, f.request(t, "GET", declarationPath, f.otherAdmin, nil, 200))
	pat2393Equal(t, other, "total", 0)
	// A still-valid JWT cannot retain its former admin role or tenant mapping.
	f.exec(t, `UPDATE portal_users SET role='viewer' WHERE email=$1`, f.email)
	f.request(t, "POST", declarationPath, f.admin, body, 403)
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "stale admin"}, 403)
	f.exec(t, `UPDATE portal_users SET role='admin',tenant_id=$2::uuid WHERE email=$1`, f.email, f.other)
	f.request(t, "GET", declarationPath+"/"+id, f.admin, nil, 404)
}
func TestPAT2393InputCannotAssertIdentityOrActor(t *testing.T) {
	f := pat2393Fixture(t)
	for _, key := range []string{"tenant_id", "actor_email", "publisher_key", "team_id", "observed_installation_count", "identity_state", "source"} {
		t.Run(key, func(t *testing.T) {
			body := pat2393Body("windows")
			body[key] = "forged"
			f.request(t, "POST", declarationPath, f.admin, body, 400)
		})
	}
	for _, tc := range []struct{ key, value string }{{"platform", "any"}, {"review_date", "2099-02-30"}, {"min_version", ">=2.0 || *"}, {"name", ""}, {"publisher", ""}} {
		t.Run(tc.key+tc.value, func(t *testing.T) {
			body := pat2393Body("macos")
			body[tc.key] = tc.value
			f.request(t, "POST", declarationPath, f.admin, body, 400)
		})
	}
	f.request(t, "GET", declarationPath+"?tenant_id="+f.other, f.admin, nil, 400)
}
func TestPAT2393CuratedSearchAndUnsafeAliasRefusal(t *testing.T) {
	f := pat2393Fixture(t)
	good, _ := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	nameOnly, _ := f.alias(t, "macos", "display_name", "")
	wrongPlatform, _ := f.alias(t, "windows", "windows_winget", "")
	rr := f.request(t, "GET", "/v1/portal/software-products?query=Synthetic&platform=macos", f.admin, nil, 200)
	if !strings.Contains(rr.Body.String(), good) || strings.Contains(rr.Body.String(), nameOnly) || strings.Contains(rr.Body.String(), wrongPlatform) {
		t.Fatalf("search did not filter safe platform identities: %s", rr.Body.String())
	}
	for _, alias := range []string{nameOnly, wrongPlatform, "00000000-0000-4000-8000-000000000099"} {
		body := pat2393Body("macos")
		body["alias_id"] = alias
		f.request(t, "POST", declarationPath, f.admin, body, 422)
	}
	f.exec(t, `UPDATE software_products SET lifecycle_state='replaced' WHERE id=(SELECT product_id FROM software_product_aliases WHERE id=$1::uuid)`, good)
	body := pat2393Body("macos")
	body["alias_id"] = good
	f.request(t, "POST", declarationPath, f.admin, body, 422)
}
func TestPAT2393ExplicitResolutionPreservesDeclaration(t *testing.T) {
	f := pat2393Fixture(t)
	original := pat2393Body("macos")
	row := f.create(t, original)
	id := pat2393ID(t, row)
	alias, _ := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "Verified curated tuple"}, 200)
	resolved := f.row(t, id)
	pat2393Equal(t, resolved, "identity_state", "matched")
	pat2393Equal(t, resolved, "id", id)
	pat2393Equal(t, resolved, "name", original["name"])
	pat2393Equal(t, resolved, "publisher", original["publisher"])
	history := pat2393JSON(t, f.request(t, "GET", declarationPath+"/"+id+"/history", f.admin, nil, 200))
	events := history["decisions"].([]any)
	if len(events) != 2 {
		t.Fatalf("expected retained creation and resolution events: %v", history)
	}
	actions := map[string]bool{}
	for _, e := range events {
		v := e.(map[string]any)
		actions[fmt.Sprint(v["action"])] = true
		pat2393Equal(t, v, "actor_email", f.email)
	}
	if !actions["created"] || !actions["resolved"] {
		t.Fatalf("missing resolution history: %v", history)
	}
	// Resolving two declarations to the same effective identity is a conflict,
	// not a silent merge that destroys the second declaration's audit.
	second := pat2393Body("macos")
	second["name"] = "Alternative supplied name"
	otherID := pat2393ID(t, f.create(t, second))
	f.request(t, "POST", declarationPath+"/"+otherID+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "duplicate"}, 409)
	pat2393Equal(t, f.row(t, otherID), "identity_state", "unmatched")
}

// Report authenticated synthetic inventory through the production ingest
// route and extractor. No direct SQL inventions of device/observation state.
func (f *declarationFixture) observe(t *testing.T, hw string, apps []map[string]any, collected time.Time) {
	f.observeFixture(t, "full.json", hw, apps, collected)
}
func (f *declarationFixture) observeFixture(t *testing.T, fixture, hw string, apps []map[string]any, collected time.Time) {
	t.Helper()
	pat2393Owner(t)
	raw, e := os.ReadFile(filepath.Join("..", "..", "testdata", "payload-fixtures", "valid", fixture))
	if e != nil {
		t.Fatal(e)
	}
	var payload map[string]any
	if e = json.Unmarshal(raw, &payload); e != nil {
		t.Fatal(e)
	}
	payload["tenant_id"] = f.tenant
	payload["schema_version"] = 3
	if fixture == "full.json" {
		payload["platform"] = "macos"
	}
	payload["collection_status"] = map[string]any{"apps": "complete"}
	payload["collected_at"] = collected.UTC().Format(time.RFC3339)
	dev := payload["device"].(map[string]any)
	dev["hw_uuid"] = hw
	dev["serial"] = "PAT2393-" + hw
	dev["hostname"] = "pat2393-synthetic"
	payload["apps"] = apps
	raw, e = json.Marshal(payload)
	if e != nil {
		t.Fatal(e)
	}
	mac := hmac.New(sha256.New, f.secret)
	_, _ = mac.Write(raw)
	r := httptest.NewRequest("POST", "/v1/inventory", bytes.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.bearer)
	r.Header.Set("X-Patched-Signature", hex.EncodeToString(mac.Sum(nil)))
	r.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	r.Header.Set("X-Patched-Nonce", pat2393Random())
	rr := httptest.NewRecorder()
	f.router.ServeHTTP(rr, r)
	if rr.Code != 200 {
		t.Fatalf("inventory fixture: %d %s", rr.Code, rr.Body.String())
	}
	if e = extractor.ProcessOnce(context.Background(), f.pool); e != nil {
		t.Fatal(e)
	}
	if n := f.count(t, `SELECT count(*) FROM raw_payloads WHERE tenant_id=$1::uuid AND (extracted_at IS NULL OR extraction_error IS NOT NULL)`, f.tenant); n != 0 {
		t.Fatalf("fixture extraction left %d failed/pending rows", n)
	}
}
func pat2393App(identifier, team, version string) map[string]any {
	return map[string]any{"name": "Synthetic Editor", "bundle_id": identifier, "identifier": identifier, "team_id": team, "version": version, "path": "/Applications/Synthetic Editor.app", "signed_by": "Synthetic Publisher", "notarized": true}
}
func TestPAT2393FixtureGuard(t *testing.T) {
	f := pat2393Fixture(t)
	f.request(t, "GET", "/v1/portal/me", f.admin, nil, 200)
	now := time.Now().Add(-time.Minute)
	f.observe(t, "12392393-0000-4000-8000-000000000001", []map[string]any{pat2393App("com.pat2393.fixture", "SYNTHETIC1", "2.1")}, now)
	if f.count(t, `SELECT count(*) FROM device_apps da JOIN devices d ON d.id=da.device_id WHERE d.tenant_id=$1::uuid AND identifier='com.pat2393.fixture'`, f.tenant) != 1 {
		t.Fatal("fixture failed to ingest exactly one app")
	}
	f.observe(t, "12392393-0000-4000-8000-000000000001", []map[string]any{}, now.Add(time.Second))
	if f.count(t, `SELECT count(*) FROM software_installations WHERE tenant_id=$1::uuid AND removed_at IS NULL`, f.tenant) != 0 {
		t.Fatal("fixture authoritative disappearance did not close installation")
	}
}
func TestPAT2393ObservationIdentityConstraintsAndDisappearance(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	body := pat2393Body("macos")
	body["alias_id"] = alias
	id := pat2393ID(t, f.create(t, body))
	hw := "12392393-0000-4000-8000-000000000002"
	now := time.Now().Add(-time.Minute)
	// Same display name, wrong bundle and wrong Team ID must never count.
	f.observe(t, hw, []map[string]any{pat2393App("com.pat2393.spoof", "SYNTHETIC1", "2.1"), pat2393App(identifier, "IMPOSTOR01", "2.1")}, now)
	pat2393Equal(t, f.row(t, id), "observed_installation_count", 0)
	f.observe(t, hw, []map[string]any{pat2393App(identifier, "SYNTHETIC1", "1.9")}, now.Add(time.Second))
	row := f.row(t, id)
	pat2393Equal(t, row, "observed_installation_count", 1)
	pat2393Equal(t, row, "observation_state", "observed")
	pat2393Equal(t, row, "outside_constraint_count", 1)
	pat2393Equal(t, row, "approval_state", "approved")
	pat2393Equal(t, row, "review_date", "2099-12-31")
	f.observe(t, hw, []map[string]any{pat2393App(identifier, "SYNTHETIC1", "2.1")}, now.Add(2*time.Second))
	pat2393Equal(t, f.row(t, id), "outside_constraint_count", 0)
	f.observe(t, hw, []map[string]any{pat2393App(identifier, "SYNTHETIC1", "")}, now.Add(3*time.Second))
	pat2393Equal(t, f.row(t, id), "unknown_version_count", 1)
	f.observe(t, hw, []map[string]any{}, now.Add(4*time.Second))
	row = f.row(t, id)
	pat2393Equal(t, row, "observed_installation_count", 0)
	pat2393Equal(t, row, "observation_state", "not_observed")
	pat2393Equal(t, row, "approval_state", "approved")
	history := pat2393JSON(t, f.request(t, "GET", declarationPath+"/"+id+"/history", f.admin, nil, 200))
	if len(history["decisions"].([]any)) != 1 {
		t.Fatal("inventory rewrote governance history")
	}
}
func TestPAT2393UnresolvedNamesNeverAutoMatch(t *testing.T) {
	f := pat2393Fixture(t)
	id := pat2393ID(t, f.create(t, pat2393Body("macos")))
	_, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	_, otherIdentifier := f.alias(t, "macos", "macos_bundle_team", "OTHERTEAM1")
	f.observe(t, "12392393-0000-4000-8000-000000000003", []map[string]any{pat2393App(identifier, "SYNTHETIC1", "2.1"), pat2393App(otherIdentifier, "OTHERTEAM1", "2.1")}, time.Now().Add(-time.Minute))
	row := f.row(t, id)
	pat2393Equal(t, row, "identity_state", "unmatched")
	pat2393Equal(t, row, "observed_installation_count", 0)
	if f.count(t, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid AND source='portal'`, f.tenant) != 0 {
		t.Fatal("name-only declaration conferred effective approval")
	}
}
func TestPAT2393WindowsWithoutPublisherRemainsUnmatched(t *testing.T) {
	f := pat2393Fixture(t)
	alias, _ := f.alias(t, "windows", "windows_winget", "")
	body := pat2393Body("windows")
	body["alias_id"] = alias
	row := f.create(t, body)
	pat2393Equal(t, row, "identity_state", "unmatched")
	if f.count(t, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid AND source='portal'`, f.tenant) != 0 {
		t.Fatal("unvouched publisher inherited approval")
	}
}
func TestPAT2393ApprovedListAndExportIncludeZeroInstallState(t *testing.T) {
	f := pat2393Fixture(t)
	body := pat2393Body("windows")
	body["name"] = "=Synthetic Editor"
	id := pat2393ID(t, f.create(t, body))
	list := pat2393JSON(t, f.request(t, "GET", "/v1/portal/software/approved", f.viewer, nil, 200))
	rows := list["products"].([]any)
	found := false
	for _, v := range rows {
		r := v.(map[string]any)
		if r["declaration_id"] == id {
			found = true
			for key, want := range map[string]any{"source": "portal", "identity_state": "unmatched", "observation_state": "not_observed", "observed_installation_count": 0} {
				pat2393Equal(t, r, key, want)
			}
		}
	}
	if !found {
		t.Fatalf("declaration missing from approved list: %v", list)
	}
	rr := f.request(t, "GET", "/v1/portal/software/approved?format=csv", f.viewer, nil, 200)
	csvBody := rr.Body.String()
	records, e := csv.NewReader(strings.NewReader(csvBody)).ReadAll()
	if e != nil {
		t.Fatal(e)
	}
	headers := map[string]int{}
	for i, h := range records[0] {
		headers[h] = i
	}
	for _, h := range []string{"declaration_id", "source", "identity_state", "observation_state", "observed_installation_count"} {
		if _, ok := headers[h]; !ok {
			t.Fatalf("export missing %s", h)
		}
	}
	foundCSV := false
	for _, cells := range records[1:] {
		if cells[headers["declaration_id"]] == id {
			foundCSV = true
			for key, want := range map[string]string{"source": "portal", "identity_state": "unmatched", "observation_state": "not_observed", "observed_installation_count": "0"} {
				if cells[headers[key]] != want {
					t.Errorf("CSV %s=%s, want %s", key, cells[headers[key]], want)
				}
			}
		}
	}
	if !foundCSV {
		t.Fatal("CSV missing declaration row")
	}
	if !strings.Contains(csvBody, "'=Synthetic Editor") {
		t.Fatal("declared name missing or CSV formula prefix not neutralised")
	}
	f.request(t, "GET", "/v1/portal/software/approved?tenant_id="+url.QueryEscape(f.other), f.viewer, nil, 400)
}

func pat2393WindowsApp(identifier, signer, state string) map[string]any {
	evidence := map[string]any{"collection_status": "complete", "collected_at": time.Now().UTC().Format(time.RFC3339), "source": "windows_authenticode_offline", "signature_state": state, "errors": []string{}, "executable_resolution": "display_icon"}
	if state == "valid" {
		evidence["signer"] = signer
		evidence["signer_thumbprint"] = strings.Repeat("1", 64)
		evidence["issuer"] = "CN=Synthetic Issuer"
		evidence["root_thumbprint"] = strings.Repeat("c", 64)
		evidence["root_kind"] = "microsoft"
	}
	return map[string]any{"name": "Synthetic Editor", "identifier": identifier, "version": "2.1", "publisher": "Synthetic Publisher", "architecture": "x86_64", "installation_evidence": evidence}
}
func (f *declarationFixture) seedCVE(t *testing.T) string {
	t.Helper()
	n, _ := strconv.ParseUint(pat2393Random()[:8], 16, 32)
	cve := "CVE-2099-" + strconv.FormatUint(n+10000, 10)
	f.exec(t, `INSERT INTO cve_feed_entries(cve_id,description,description_source,severity,cvss_v3_score) VALUES($1,'Synthetic acceptance finding','nvd','HIGH',8.0)`, cve)
	f.exec(t, `INSERT INTO device_cve_findings(device_id,cve_id,app_name,app_version,severity,match_confidence) SELECT id,$2,'Synthetic Editor','2.1','HIGH','confirmed' FROM devices WHERE tenant_id=$1::uuid`, f.tenant, cve)
	return cve
}
func TestPAT2393WindowsFixtureGuard(t *testing.T) {
	f := pat2393Fixture(t)
	f.observeFixture(t, "full-v3-windows.json", "12392393-0000-4000-8000-000000000004", []map[string]any{pat2393WindowsApp("pat2393.editor", "CN=Synthetic Publisher", "valid")}, time.Now().Add(-time.Minute))
	if f.count(t, `SELECT count(*) FROM software_installations WHERE tenant_id=$1::uuid AND platform='windows' AND identity_kind='windows_native_publisher'`, f.tenant) != 1 {
		t.Fatal("Windows fixture did not create a real observation")
	}
	cve := f.seedCVE(t)
	rr := f.request(t, "GET", "/v1/portal/findings", f.viewer, nil, 200)
	if !strings.Contains(rr.Body.String(), cve) {
		t.Fatalf("synthetic CVE not visible before feature action: %s", rr.Body.String())
	}
}
func TestPAT2393WindowsPublisherEvidenceAndSpoofing(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "windows", "windows_native_publisher", "synthetic publisher")
	body := pat2393Body("windows")
	body["alias_id"] = alias
	id := pat2393ID(t, f.create(t, body))
	pat2393Equal(t, f.row(t, id), "identity_state", "unmatched")
	path := declarationPath + "/" + id + "/resolve"
	resolve := map[string]any{"alias_id": alias, "justification": "Confirmed exact observed publisher"}
	now := time.Now().Add(-time.Minute)
	hw := "12392393-0000-4000-8000-000000000005"
	f.observeFixture(t, "full-v3-windows.json", hw, []map[string]any{pat2393WindowsApp(identifier, "", "unsigned")}, now)
	f.request(t, "POST", path, f.admin, resolve, 422)
	f.observeFixture(t, "full-v3-windows.json", hw, []map[string]any{pat2393WindowsApp(identifier, "CN=Synthetic Publisher", "valid")}, now.Add(time.Second))
	f.request(t, "POST", path, f.admin, resolve, 200)
	pat2393Equal(t, f.row(t, id), "observed_installation_count", 1)
	// Identical registry name, product id and publisher string are insufficient
	// when independently collected Authenticode says a different signer.
	f.observeFixture(t, "full-v3-windows.json", hw, []map[string]any{pat2393WindowsApp(identifier, "CN=Impostor Publisher", "valid")}, now.Add(2*time.Second))
	pat2393Equal(t, f.row(t, id), "observed_installation_count", 0)
	rr := f.request(t, "GET", "/v1/portal/software?search="+url.QueryEscape(identifier), f.admin, nil, 200)
	var result struct {
		Products []struct {
			PolicyState *string `json:"policy_state"`
		} `json:"products"`
	}
	if e := json.Unmarshal(rr.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if len(result.Products) == 0 {
		t.Fatal("spoofed observation vanished rather than remaining unapproved")
	}
	for _, p := range result.Products {
		if p.PolicyState != nil && *p.PolicyState == "approved" {
			t.Fatal("spoofed signer inherited approval")
		}
	}
}
func TestPAT2393ApprovalKeepsVulnerabilityFindings(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	f.observe(t, "12392393-0000-4000-8000-000000000006", []map[string]any{pat2393App(identifier, "SYNTHETIC1", "2.1")}, time.Now().Add(-time.Minute))
	cve := f.seedCVE(t)
	before := f.request(t, "GET", "/v1/portal/findings", f.viewer, nil, 200)
	if !strings.Contains(before.Body.String(), cve) {
		t.Fatal("CVE fixture not visible before approval")
	}
	body := pat2393Body("macos")
	body["alias_id"] = alias
	f.create(t, body)
	after := f.request(t, "GET", "/v1/portal/findings", f.viewer, nil, 200)
	if !strings.Contains(after.Body.String(), cve) {
		t.Fatal("approval hid vulnerability finding")
	}
	if f.count(t, `SELECT count(*) FROM device_cve_findings cf JOIN devices d ON d.id=cf.device_id WHERE d.tenant_id=$1::uuid AND cf.cve_id=$2`, f.tenant, cve) != 1 {
		t.Fatal("approval cleared vulnerability evidence")
	}
}

func TestPAT2393AmbiguousWindowsPublishersRefuseResolution(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "windows", "windows_native_publisher", "synthetic publisher")
	body := pat2393Body("windows")
	body["alias_id"] = alias
	id := pat2393ID(t, f.create(t, body))
	now := time.Now().Add(-time.Minute)
	for i, signer := range []string{"CN=Synthetic Publisher", "CN=Conflicting Publisher"} {
		f.observeFixture(t, "full-v3-windows.json", fmt.Sprintf("12392393-0000-4000-8000-%012d", 10+i), []map[string]any{pat2393WindowsApp(identifier, signer, "valid")}, now)
	}
	f.request(t, "POST", declarationPath+"/"+id+"/resolve", f.admin, map[string]any{"alias_id": alias, "justification": "Ambiguous evidence must be refused"}, 422)
	row := f.row(t, id)
	pat2393Equal(t, row, "identity_state", "unmatched")
	pat2393Equal(t, row, "observed_installation_count", 0)
	if f.count(t, `SELECT count(*) FROM tenant_app_policies WHERE tenant_id=$1::uuid AND source='portal'`, f.tenant) != 0 {
		t.Fatal("ambiguous publisher evidence created effective approval")
	}
}

func TestPAT2393PlatformIdentityCannotCrossMatch(t *testing.T) {
	f := pat2393Fixture(t)
	alias, identifier := f.alias(t, "macos", "macos_bundle_team", "SYNTHETIC1")
	body := pat2393Body("macos")
	body["alias_id"] = alias
	id := pat2393ID(t, f.create(t, body))
	f.observeFixture(t, "full-v3-windows.json", "12392393-0000-4000-8000-000000000020", []map[string]any{pat2393WindowsApp(identifier, "CN=Synthetic Publisher", "valid")}, time.Now().Add(-time.Minute))
	pat2393Equal(t, f.row(t, id), "observed_installation_count", 0)
	rr := f.request(t, "GET", "/v1/portal/software?search="+url.QueryEscape(identifier), f.viewer, nil, 200)
	var result struct {
		Products []struct {
			PolicyState *string `json:"policy_state"`
		} `json:"products"`
	}
	if e := json.Unmarshal(rr.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	if len(result.Products) == 0 {
		t.Fatal("Windows evidence absent")
	}
	for _, p := range result.Products {
		if p.PolicyState != nil && *p.PolicyState == "approved" {
			t.Fatal("macOS policy approved a Windows observation")
		}
	}
}
