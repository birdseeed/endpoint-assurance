package handlers

// PAT-2287: revoke an unused enrolment (bootstrap) token through the admin
// API, list the live ones, and make /v1/enrol refuse a revoked token with the
// same response as an expired one.
//
// The DB round-trip tests are skipped when TEST_DATABASE_URL is unset, and
// fail instead when PATCHED_DB_TESTS_REQUIRED promises a database (the
// go-integration-test "internal/handlers DB-gated tests" step), so the
// coverage cannot silently evaporate.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/ratelimit"
)

// ---------------------------------------------------------------------------
// Input validation, no DB required (nil pool: a DB touch would panic)
// ---------------------------------------------------------------------------

func TestRevokeBootstrapTokenHandler_BadTenantIDIs400(t *testing.T) {
	rr := httptest.NewRecorder()
	bootstrapTokenAdminRouter(nil).ServeHTTP(rr, httptest.NewRequest(http.MethodPost,
		"/admin/tenants/not-a-uuid/bootstrap-tokens/00000000-0000-4000-8000-000000000001/revoke", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("revoke with bad tenantID = %d, want 400: %s", rr.Code, rr.Body.String())
	}
}

func TestRevokeBootstrapTokenHandler_BadTokenIDIs404(t *testing.T) {
	rr := httptest.NewRecorder()
	bootstrapTokenAdminRouter(nil).ServeHTTP(rr, httptest.NewRequest(http.MethodPost,
		"/admin/tenants/00000000-0000-4000-8000-000000000001/bootstrap-tokens/not-a-uuid/revoke", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("revoke with bad token id = %d, want 404: %s", rr.Code, rr.Body.String())
	}
	if got := strings.TrimSpace(rr.Body.String()); got != "bootstrap token not found" {
		t.Fatalf("revoke with bad token id body = %q, want the same not-found body as an unknown id", got)
	}
}

func TestListBootstrapTokensHandler_BadTenantIDIs400(t *testing.T) {
	rr := httptest.NewRecorder()
	bootstrapTokenAdminRouter(nil).ServeHTTP(rr, httptest.NewRequest(http.MethodGet,
		"/admin/tenants/not-a-uuid/bootstrap-tokens", nil))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("list with bad tenantID = %d, want 400: %s", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// DB round-trip tests
// ---------------------------------------------------------------------------

// bootstrapTokenAdminRouter mounts the three bootstrap-token admin routes on
// the same paths cmd/patched-api/main.go uses, so chi URL params resolve
// exactly as they do in production.
func bootstrapTokenAdminRouter(pool *pgxpool.Pool) http.Handler {
	r := chi.NewRouter()
	r.Post("/admin/tenants/{tenantID}/bootstrap-tokens", MintBootstrapTokenHandler(pool))
	r.Get("/admin/tenants/{tenantID}/bootstrap-tokens", ListBootstrapTokensHandler(pool))
	r.Post("/admin/tenants/{tenantID}/bootstrap-tokens/{tokenID}/revoke", RevokeBootstrapTokenHandler(pool))
	return r
}

func bootstrapRevokeTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" {
			t.Fatal("PATCHED_DB_TESTS_REQUIRED is set but TEST_DATABASE_URL is not; PAT-2287 bootstrap-token revoke DB coverage would silently evaporate")
		}
		t.Skip("TEST_DATABASE_URL not set; skipping PAT-2287 bootstrap-token revoke DB test")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// adminMint mints through the real admin handler and returns the response.
func adminMint(t *testing.T, h http.Handler, tenantID, path string) mintBootstrapTokenResp {
	t.Helper()
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost,
		"/admin/tenants/"+tenantID+"/bootstrap-tokens?path="+path, nil))
	if rr.Code != http.StatusCreated {
		t.Fatalf("mint = %d, want 201: %s", rr.Code, rr.Body.String())
	}
	var out mintBootstrapTokenResp
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode mint response: %v", err)
	}
	return out
}

func adminRevoke(h http.Handler, tenantID, tokenID string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodPost,
		"/admin/tenants/"+tenantID+"/bootstrap-tokens/"+tokenID+"/revoke", nil))
	return rr
}

type revokeResp struct {
	TokenID   string     `json:"token_id"`
	RevokedAt *time.Time `json:"revoked_at"`
	Changed   bool       `json:"changed"`
}

func decodeRevoke(t *testing.T, rr *httptest.ResponseRecorder) revokeResp {
	t.Helper()
	var out revokeResp
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode revoke response %q: %v", rr.Body.String(), err)
	}
	return out
}

func tokenRevokedAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tokenID string) *time.Time {
	t.Helper()
	var at *time.Time
	if err := pool.QueryRow(ctx, `SELECT revoked_at FROM bootstrap_tokens WHERE id = $1::uuid`, tokenID).Scan(&at); err != nil {
		t.Fatalf("read revoked_at for %s: %v", tokenID, err)
	}
	return at
}

func revokeAuditCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tokenID string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM enrollment_token_audit WHERE token_id = $1::uuid AND action = 'revoke'
	`, tokenID).Scan(&n); err != nil {
		t.Fatalf("count revoke audit rows for %s: %v", tokenID, err)
	}
	return n
}

func expireToken(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tokenID string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `UPDATE bootstrap_tokens SET expires_at = now() - interval '1 minute' WHERE id = $1::uuid`, tokenID); err != nil {
		t.Fatalf("expire token %s: %v", tokenID, err)
	}
}

// assertSameRefusal fails unless two /v1/enrol refusals are byte-identical in
// status, content type and body.
func assertSameRefusal(t *testing.T, revoked, expired *httptest.ResponseRecorder) {
	t.Helper()
	if expired.Code != http.StatusGone {
		t.Fatalf("expired token enrol = %d, want 410: %s", expired.Code, expired.Body.String())
	}
	if revoked.Code != expired.Code {
		t.Fatalf("revoked token enrol status = %d, expired = %d: the reason leaks through the status (body %q)", revoked.Code, expired.Code, revoked.Body.String())
	}
	if revoked.Body.String() != expired.Body.String() {
		t.Fatalf("revoked token enrol body = %q, expired = %q: the reason leaks through the body", revoked.Body.String(), expired.Body.String())
	}
	if rc, ec := revoked.Header().Get("Content-Type"), expired.Header().Get("Content-Type"); rc != ec {
		t.Fatalf("revoked token Content-Type = %q, expired = %q", rc, ec)
	}
}

// TestBootstrapTokenRevoke_EnrolRefusedWithExpiredResponse is the ticket's
// first "done when": mint, revoke, and enrolment with that token fails, with
// the same response an expired token gets.
func TestBootstrapTokenRevoke_EnrolRefusedWithExpiredResponse(t *testing.T) {
	pool := bootstrapRevokeTestPool(t)
	ctx := context.Background()
	h := bootstrapTokenAdminRouter(pool)
	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2287-revoke-then-enrol")

	revoked := adminMint(t, h, tenantID, "mdm")
	expired := adminMint(t, h, tenantID, "mdm")
	expireToken(t, ctx, pool, expired.TokenID)

	rr := adminRevoke(h, tenantID, revoked.TokenID)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	got := decodeRevoke(t, rr)
	if got.TokenID != revoked.TokenID || got.RevokedAt == nil || !got.Changed {
		t.Fatalf("revoke response = %+v, want token_id %s, revoked_at set, changed true", got, revoked.TokenID)
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("revoke Cache-Control = %q, want no-store", rr.Header().Get("Cache-Control"))
	}

	enrol := EnrolHandler(pool, ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000}))
	revokedRR := doEnrolRequest(t, enrol, revoked.EnrollmentToken, deviceUUID(22870))
	expiredRR := doEnrolRequest(t, enrol, expired.EnrollmentToken, deviceUUID(22871))
	assertSameRefusal(t, revokedRR, expiredRR)

	var consumedAt *time.Time
	if err := pool.QueryRow(ctx, `SELECT consumed_at FROM bootstrap_tokens WHERE id = $1::uuid`, revoked.TokenID).Scan(&consumedAt); err != nil {
		t.Fatalf("read consumed_at: %v", err)
	}
	if consumedAt != nil {
		t.Fatalf("revoked token consumed_at = %v, want NULL: a refused enrol must not burn it", *consumedAt)
	}
	var creds int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_credentials WHERE tenant_id = $1::uuid`, tenantID).Scan(&creds); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if creds != 0 {
		t.Fatalf("tenant_credentials rows = %d after refused enrols, want 0", creds)
	}
}

// TestEnrolHandler_RevokedTokenRefusedLikeExpired isolates the /v1/enrol
// change from the revoke handler: a row with revoked_at set, and nothing else
// wrong with it, is refused exactly as an expired row is.
func TestEnrolHandler_RevokedTokenRefusedLikeExpired(t *testing.T) {
	pool := bootstrapRevokeTestPool(t)
	ctx := context.Background()
	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2287-enrol-revoked-row")

	revoked, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "mdm", "")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	expired, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "mdm", "")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE bootstrap_tokens SET revoked_at = now() WHERE id = $1::uuid`, revoked.TokenID); err != nil {
		t.Fatalf("set revoked_at: %v", err)
	}
	expireToken(t, ctx, pool, expired.TokenID)

	enrol := EnrolHandler(pool, ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000}))
	assertSameRefusal(t,
		doEnrolRequest(t, enrol, revoked.PlaintextToken, deviceUUID(22872)),
		doEnrolRequest(t, enrol, expired.PlaintextToken, deviceUUID(22873)))
}

// Revocation keeps the expired response even if an email-link remint also
// supersedes the token, whichever operation happens first.
func TestBootstrapTokenRevoke_SupersededTokenRefusedLikeExpired(t *testing.T) {
	for _, revokeFirst := range []bool{true, false} {
		name := "supersede_then_revoke"
		if revokeFirst {
			name = "revoke_then_supersede"
		}
		t.Run(name, func(t *testing.T) {
			pool := bootstrapRevokeTestPool(t)
			ctx := context.Background()
			h := bootstrapTokenAdminRouter(pool)
			tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2287-revoked-superseded")
			tok := adminMint(t, h, tenantID, "email-link")
			revoke := func() {
				if rr := adminRevoke(h, tenantID, tok.TokenID); rr.Code != http.StatusOK {
					t.Fatalf("revoke = %d, want 200: %s", rr.Code, rr.Body.String())
				}
			}
			if revokeFirst {
				revoke()
			}
			adminMint(t, h, tenantID, "email-link")
			if !revokeFirst {
				revoke()
			}
			expired := adminMint(t, h, tenantID, "mdm")
			expireToken(t, ctx, pool, expired.TokenID)
			enrol := EnrolHandler(pool, ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000}))
			assertSameRefusal(t,
				doEnrolRequest(t, enrol, tok.EnrollmentToken, deviceUUID(22877)),
				doEnrolRequest(t, enrol, expired.EnrollmentToken, deviceUUID(22878)))
		})
	}
}

// TestBootstrapTokenRevoke_CrossTenantIs404AndTokenStillWorks is the
// ticket's second "done when": another tenant's token cannot be revoked, and
// the refusal is indistinguishable from an id that does not exist.
func TestBootstrapTokenRevoke_CrossTenantIs404AndTokenStillWorks(t *testing.T) {
	pool := bootstrapRevokeTestPool(t)
	ctx := context.Background()
	h := bootstrapTokenAdminRouter(pool)
	attacker := mkSupersedeTestTenant(t, ctx, pool, "pat2287-cross-tenant-caller")
	victim := mkSupersedeTestTenant(t, ctx, pool, "pat2287-cross-tenant-owner")

	victimTok := adminMint(t, h, victim, "mdm")

	cross := adminRevoke(h, attacker, victimTok.TokenID)
	missing := adminRevoke(h, attacker, "00000000-0000-4000-8000-00000000fe11")
	if cross.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant revoke = %d, want 404: %s", cross.Code, cross.Body.String())
	}
	if missing.Code != cross.Code || missing.Body.String() != cross.Body.String() {
		t.Fatalf("cross-tenant revoke (%d %q) differs from unknown-id revoke (%d %q): existence oracle",
			cross.Code, cross.Body.String(), missing.Code, missing.Body.String())
	}

	if at := tokenRevokedAt(t, ctx, pool, victimTok.TokenID); at != nil {
		t.Fatalf("victim token revoked_at = %v after cross-tenant revoke, want NULL", *at)
	}
	if n := revokeAuditCount(t, ctx, pool, victimTok.TokenID); n != 0 {
		t.Fatalf("revoke audit rows for victim token = %d, want 0", n)
	}

	enrol := EnrolHandler(pool, ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000}))
	if rr := doEnrolRequest(t, enrol, victimTok.EnrollmentToken, deviceUUID(22874)); rr.Code != http.StatusOK {
		t.Fatalf("victim token enrol after cross-tenant revoke = %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

// TestBootstrapTokenRevoke_IdempotentSecondRevoke: a second revoke succeeds,
// reports changed=false, keeps the original revoked_at and writes no second
// audit row.
func TestBootstrapTokenRevoke_IdempotentSecondRevoke(t *testing.T) {
	pool := bootstrapRevokeTestPool(t)
	ctx := context.Background()
	h := bootstrapTokenAdminRouter(pool)
	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2287-idempotent")

	tok := adminMint(t, h, tenantID, "mdm")

	first := adminRevoke(h, tenantID, tok.TokenID)
	if first.Code != http.StatusOK {
		t.Fatalf("first revoke = %d, want 200: %s", first.Code, first.Body.String())
	}
	stored := tokenRevokedAt(t, ctx, pool, tok.TokenID)
	if stored == nil {
		t.Fatal("revoked_at is NULL after first revoke")
	}

	second := adminRevoke(h, tenantID, tok.TokenID)
	if second.Code != http.StatusOK {
		t.Fatalf("second revoke = %d, want 200: %s", second.Code, second.Body.String())
	}
	got := decodeRevoke(t, second)
	if got.Changed {
		t.Fatal("second revoke reported changed=true, want false")
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(*stored) {
		t.Fatalf("second revoke revoked_at = %v, want the original %v", got.RevokedAt, *stored)
	}
	if after := tokenRevokedAt(t, ctx, pool, tok.TokenID); after == nil || !after.Equal(*stored) {
		t.Fatalf("stored revoked_at moved from %v to %v on a repeat revoke", *stored, after)
	}
	if n := revokeAuditCount(t, ctx, pool, tok.TokenID); n != 1 {
		t.Fatalf("revoke audit rows = %d after two revokes, want 1", n)
	}
}

// TestBootstrapTokenRevoke_ConsumedTokenIs409 refuses to revoke a token a
// device has already enrolled with, and changes nothing.
func TestBootstrapTokenRevoke_ConsumedTokenIs409(t *testing.T) {
	pool := bootstrapRevokeTestPool(t)
	ctx := context.Background()
	h := bootstrapTokenAdminRouter(pool)
	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2287-consumed")

	tok := adminMint(t, h, tenantID, "mdm")
	enrol := EnrolHandler(pool, ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000}))
	if rr := doEnrolRequest(t, enrol, tok.EnrollmentToken, deviceUUID(22875)); rr.Code != http.StatusOK {
		t.Fatalf("enrol = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	rr := adminRevoke(h, tenantID, tok.TokenID)
	if rr.Code != http.StatusConflict {
		t.Fatalf("revoke of consumed token = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "consumed") {
		t.Fatalf("409 body = %q, want it to say the token was consumed", rr.Body.String())
	}
	if at := tokenRevokedAt(t, ctx, pool, tok.TokenID); at != nil {
		t.Fatalf("consumed token revoked_at = %v, want NULL", *at)
	}
	if n := revokeAuditCount(t, ctx, pool, tok.TokenID); n != 0 {
		t.Fatalf("revoke audit rows for consumed token = %d, want 0", n)
	}
}

// TestBootstrapTokenRevoke_WritesAuditRowWithActor: the revoke is recorded in
// enrollment_token_audit as its own action, attributed to the one principal
// the admin auth can vouch for (PAT-1135), with the token's own delivery path
// and expiry.
func TestBootstrapTokenRevoke_WritesAuditRowWithActor(t *testing.T) {
	pool := bootstrapRevokeTestPool(t)
	ctx := context.Background()
	h := bootstrapTokenAdminRouter(pool)
	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2287-audit")

	tok := adminMint(t, h, tenantID, "email-link")
	before := time.Now().Add(-time.Minute)
	if rr := adminRevoke(h, tenantID, tok.TokenID); rr.Code != http.StatusOK {
		t.Fatalf("revoke = %d, want 200: %s", rr.Code, rr.Body.String())
	}

	var (
		auditTenant, deliveryPath string
		actor, actorEmail         *string
		auditExpires, generatedAt time.Time
		tokenExpires              time.Time
	)
	if err := pool.QueryRow(ctx, `
		SELECT a.tenant_id::text, a.delivery_path, a.actor, a.actor_email, a.expires_at, a.generated_at, t.expires_at
		FROM enrollment_token_audit a JOIN bootstrap_tokens t ON t.id = a.token_id
		WHERE a.token_id = $1::uuid AND a.action = 'revoke'
	`, tok.TokenID).Scan(&auditTenant, &deliveryPath, &actor, &actorEmail, &auditExpires, &generatedAt, &tokenExpires); err != nil {
		t.Fatalf("read revoke audit row: %v", err)
	}
	if auditTenant != tenantID {
		t.Errorf("audit tenant_id = %s, want %s", auditTenant, tenantID)
	}
	if deliveryPath != "email-link" {
		t.Errorf("audit delivery_path = %q, want the token's own %q", deliveryPath, "email-link")
	}
	if actor == nil || *actor != adminSharedTokenActor {
		t.Errorf("audit actor = %v, want %q", actor, adminSharedTokenActor)
	}
	if actorEmail != nil {
		t.Errorf("audit actor_email = %q, want NULL on the admin path", *actorEmail)
	}
	if !auditExpires.Equal(tokenExpires) {
		t.Errorf("audit expires_at = %v, want the token's %v", auditExpires, tokenExpires)
	}
	if generatedAt.Before(before) {
		t.Errorf("audit generated_at = %v, want the revoke time (after %v)", generatedAt, before)
	}

	var mintRows int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM enrollment_token_audit WHERE token_id = $1::uuid AND action = 'mint'
	`, tok.TokenID).Scan(&mintRows); err != nil {
		t.Fatalf("count mint audit rows: %v", err)
	}
	if mintRows != 1 {
		t.Errorf("mint audit rows = %d, want 1 (the mint row keeps action='mint')", mintRows)
	}
}

// TestListBootstrapTokens_OnlyLiveTokensAndNoHash lists exactly the tokens
// that could still enrol a device, with id, created, expires and delivery
// path, and never the hash.
func TestListBootstrapTokens_OnlyLiveTokensAndNoHash(t *testing.T) {
	pool := bootstrapRevokeTestPool(t)
	ctx := context.Background()
	h := bootstrapTokenAdminRouter(pool)
	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat2287-list")
	other := mkSupersedeTestTenant(t, ctx, pool, "pat2287-list-other")

	live1 := adminMint(t, h, tenantID, "mdm")
	live2 := adminMint(t, h, tenantID, "mdm")
	revoked := adminMint(t, h, tenantID, "mdm")
	consumed := adminMint(t, h, tenantID, "mdm")
	expired := adminMint(t, h, tenantID, "mdm")
	superseded := adminMint(t, h, tenantID, "email-link")
	live3 := adminMint(t, h, tenantID, "email-link") // supersedes the one above
	otherTok := adminMint(t, h, other, "mdm")

	if rr := adminRevoke(h, tenantID, revoked.TokenID); rr.Code != http.StatusOK {
		t.Fatalf("revoke = %d: %s", rr.Code, rr.Body.String())
	}
	enrol := EnrolHandler(pool, ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000}))
	if rr := doEnrolRequest(t, enrol, consumed.EnrollmentToken, deviceUUID(22876)); rr.Code != http.StatusOK {
		t.Fatalf("enrol = %d: %s", rr.Code, rr.Body.String())
	}
	expireToken(t, ctx, pool, expired.TokenID)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/tenants/"+tenantID+"/bootstrap-tokens", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("list = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("list Cache-Control = %q, want no-store", rr.Header().Get("Cache-Control"))
	}
	body := rr.Body.String()
	if strings.Contains(strings.ToLower(body), "hash") {
		t.Fatalf("list body mentions a hash: %s", body)
	}
	for _, tok := range []mintBootstrapTokenResp{live1, live2, live3, revoked, consumed, expired, superseded, otherTok} {
		if strings.Contains(body, tok.EnrollmentToken) {
			t.Fatalf("list body contains a plaintext token: %s", body)
		}
	}

	var out struct {
		Tokens []map[string]any `json:"tokens"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	wantKeys := []string{"created_at", "delivery_path", "expires_at", "token_id"}
	var gotIDs []string
	paths := map[string]string{}
	for _, row := range out.Tokens {
		var keys []string
		for k := range row {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if strings.Join(keys, ",") != strings.Join(wantKeys, ",") {
			t.Fatalf("list row keys = %v, want exactly %v", keys, wantKeys)
		}
		id, _ := row["token_id"].(string)
		gotIDs = append(gotIDs, id)
		paths[id], _ = row["delivery_path"].(string)
	}
	wantIDs := []string{live1.TokenID, live2.TokenID, live3.TokenID}
	sort.Strings(gotIDs)
	sort.Strings(wantIDs)
	if strings.Join(gotIDs, ",") != strings.Join(wantIDs, ",") {
		t.Fatalf("listed token ids = %v, want only the live ones %v (revoked %s, consumed %s, expired %s, superseded %s, other tenant %s must be absent)",
			gotIDs, wantIDs, revoked.TokenID, consumed.TokenID, expired.TokenID, superseded.TokenID, otherTok.TokenID)
	}
	if paths[live3.TokenID] != "email-link" || paths[live1.TokenID] != "mdm" {
		t.Fatalf("listed delivery paths = %v, want live3 email-link and live1 mdm", paths)
	}

	unknown := httptest.NewRecorder()
	h.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/admin/tenants/00000000-0000-4000-8000-00000000fe12/bootstrap-tokens", nil))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("list for unknown tenant = %d, want 404: %s", unknown.Code, unknown.Body.String())
	}
}
