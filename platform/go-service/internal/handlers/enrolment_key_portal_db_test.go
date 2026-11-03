package handlers

// PAT-2250: portal create / list / revoke for tenant enrolment keys, plus the
// lock-order check against bootstrap tokens and CheckTrialDeviceCap.
// DB-backed; skipped without TEST_DATABASE_URL.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/portalauth"
)

func seedPortalUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, role string) string {
	t.Helper()
	email := "pat2250-" + role + "-" + tenantID[:8] + "@keys.example"
	if _, err := pool.Exec(ctx, `INSERT INTO portal_users (email, tenant_id, role) VALUES ($1, $2::uuid, $3)`, email, tenantID, role); err != nil {
		t.Fatalf("seed portal user: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM portal_users WHERE email = $1`, email) })
	return email
}

// keyPortalRouter mounts the three key routes as main.go does.
func keyPortalRouter(pool *pgxpool.Pool) http.Handler {
	r := chi.NewRouter()
	r.Post("/v1/portal/enrolment-keys", PortalEnrolmentKeyCreateHandler(pool, nil))
	r.Get("/v1/portal/enrolment-keys", PortalEnrolmentKeysListHandler(pool))
	r.Post("/v1/portal/enrolment-keys/{keyID}/revoke", PortalEnrolmentKeyRevokeHandler(pool))
	return r
}

func keyPortalDo(h http.Handler, method, path, body, email, tenantID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req = req.WithContext(portalauth.WithIdentity(req.Context(), portalauth.Identity{Email: email, TenantID: tenantID}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Create returns the plaintext once; the database holds only its SHA-256 and
// a four-character hint; no log line from create, enrol, refusal, list or
// revoke carries the plaintext or its secret part; list never returns it.
func TestEnrolmentKeyPortal_LifecyclePlaintextNeverStoredOrLogged(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2250-portal-lifecycle")
	admin := seedPortalUser(t, ctx, pool, tenantID, "admin")

	logs := &syncBuffer{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	h := keyPortalRouter(pool)
	rr := keyPortalDo(h, http.MethodPost, "/v1/portal/enrolment-keys",
		`{"label":"Intune rollout","max_devices":1,"expires_in_days":14}`, admin, tenantID)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: status %d body %q", rr.Code, rr.Body.String())
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("create Cache-Control = %q, want no-store", cc)
	}
	var created struct {
		KeyID         string    `json:"key_id"`
		EnrollmentKey string    `json:"enrollment_key"`
		KeyHint       string    `json:"key_hint"`
		MaxDevices    int       `json:"max_devices"`
		ExpiresAt     time.Time `json:"expires_at"`
		CreatedBy     string    `json:"created_by"`
		Status        string    `json:"status"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	plaintext := created.EnrollmentKey
	if !strings.HasPrefix(plaintext, "pek_") || len(plaintext) != len("pek_")+43 {
		t.Fatalf("key %q is not pek_ + 43 base64url chars", plaintext)
	}
	secret := strings.TrimPrefix(plaintext, "pek_")
	if created.KeyHint != "pek_"+secret[:4] || created.MaxDevices != 1 || created.CreatedBy != admin || created.Status != "active" {
		t.Fatalf("unexpected create response %+v", created)
	}
	if d := time.Until(created.ExpiresAt); d < 13*24*time.Hour || d > 15*24*time.Hour {
		t.Fatalf("expires_at %v is not ~14 days out", created.ExpiresAt)
	}

	// Stored: hash only.
	var storedHash []byte
	var rowJSON string
	if err := pool.QueryRow(ctx, `SELECT key_hash, row_to_json(k)::text FROM tenant_enrolment_keys k WHERE id = $1::uuid`, created.KeyID).Scan(&storedHash, &rowJSON); err != nil {
		t.Fatalf("read key row: %v", err)
	}
	want := sha256.Sum256([]byte(plaintext))
	if !bytes.Equal(storedHash, want[:]) {
		t.Fatal("key_hash is not SHA-256 of the plaintext")
	}
	if strings.Contains(rowJSON, secret[4:]) {
		t.Fatal("key row contains the plaintext secret")
	}

	// Enrol within the cap, then past it (the refusal path logs too).
	eh := keyTestEnrolHandler(pool)
	if rr := enrolWithToken(eh, plaintext, deviceUUID(800)); rr.Code != http.StatusOK {
		t.Fatalf("enrol: status %d body %q", rr.Code, rr.Body.String())
	}
	if rr := enrolWithToken(eh, plaintext, deviceUUID(801)); rr.Code != http.StatusGone || strings.Contains(rr.Body.String(), secret) {
		t.Fatalf("past cap: status %d body %q, want 410 without the key", rr.Code, rr.Body.String())
	}

	// List: every role, no plaintext, usage and status.
	viewer := seedPortalUser(t, ctx, pool, tenantID, "viewer")
	rr = keyPortalDo(h, http.MethodGet, "/v1/portal/enrolment-keys", "", viewer, tenantID)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: status %d body %q", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), secret) || strings.Contains(rr.Body.String(), "enrollment_key\"") {
		t.Fatalf("list leaks key material: %q", rr.Body.String())
	}
	var list struct {
		Keys []struct {
			KeyID           string `json:"key_id"`
			DevicesEnrolled int    `json:"devices_enrolled"`
			Status          string `json:"status"`
		} `json:"keys"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &list)
	if len(list.Keys) != 1 || list.Keys[0].KeyID != created.KeyID || list.Keys[0].DevicesEnrolled != 1 || list.Keys[0].Status != "exhausted" {
		t.Fatalf("unexpected list %+v", list)
	}

	// Revoke, then enrolment is refused; revoke again is a no-op.
	rr = keyPortalDo(h, http.MethodPost, "/v1/portal/enrolment-keys/"+created.KeyID+"/revoke", "", admin, tenantID)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"changed":true`) {
		t.Fatalf("revoke: status %d body %q", rr.Code, rr.Body.String())
	}
	if rr := enrolWithToken(eh, plaintext, deviceUUID(800)); rr.Code != http.StatusGone {
		t.Fatalf("enrol after revoke: status %d, want 410", rr.Code)
	}
	rr = keyPortalDo(h, http.MethodPost, "/v1/portal/enrolment-keys/"+created.KeyID+"/revoke", "{}", admin, tenantID)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"changed":false`) {
		t.Fatalf("second revoke: status %d body %q", rr.Code, rr.Body.String())
	}
	var revokedBy string
	if err := pool.QueryRow(ctx, `SELECT revoked_by FROM tenant_enrolment_keys WHERE id = $1::uuid`, created.KeyID).Scan(&revokedBy); err != nil || revokedBy != admin {
		t.Fatalf("revoked_by = %q (%v), want %q", revokedBy, err, admin)
	}

	out := logs.String()
	if !strings.Contains(out, "enrolment key created") || !strings.Contains(out, "enrolment_key_id="+created.KeyID) {
		t.Fatalf("log capture did not see the key lifecycle; captured:\n%s", out)
	}
	if strings.Contains(out, secret) || strings.Contains(out, secret[4:20]) {
		t.Fatalf("logs contain the plaintext key:\n%s", out)
	}
}

// Only a portal admin creates or revokes; a viewer is refused with 403 and
// nothing is written.
func TestEnrolmentKeyPortal_ViewerCannotCreateOrRevoke(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2250-portal-viewer")
	viewer := seedPortalUser(t, ctx, pool, tenantID, "viewer")
	h := keyPortalRouter(pool)

	rr := keyPortalDo(h, http.MethodPost, "/v1/portal/enrolment-keys", `{"label":"x","max_devices":5}`, viewer, tenantID)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer create: status %d body %q, want 403", rr.Code, rr.Body.String())
	}
	keyID, _ := seedEnrolmentKey(t, ctx, pool, tenantID, 5, time.Now().Add(time.Hour))
	rr = keyPortalDo(h, http.MethodPost, "/v1/portal/enrolment-keys/"+keyID+"/revoke", "", viewer, tenantID)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("viewer revoke: status %d body %q, want 403", rr.Code, rr.Body.String())
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_enrolment_keys WHERE tenant_id = $1::uuid AND revoked_at IS NULL`, tenantID).Scan(&n); err != nil || n != 1 {
		t.Fatalf("live keys = %d (%v), want only the seeded one", n, err)
	}
}

// Tenant A's admin can neither see nor revoke tenant B's key, and a request
// body cannot name a tenant.
func TestEnrolmentKeyPortal_TenantIsolation(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantA := catSeedTenant(t, ctx, pool, "pat2250-portal-a")
	tenantB := catSeedTenant(t, ctx, pool, "pat2250-portal-b")
	adminA := seedPortalUser(t, ctx, pool, tenantA, "admin")
	keyB, _ := seedEnrolmentKey(t, ctx, pool, tenantB, 5, time.Now().Add(time.Hour))
	h := keyPortalRouter(pool)

	rr := keyPortalDo(h, http.MethodPost, "/v1/portal/enrolment-keys/"+keyB+"/revoke", "", adminA, tenantA)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant revoke: status %d body %q, want 404", rr.Code, rr.Body.String())
	}
	var revoked bool
	if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM tenant_enrolment_keys WHERE id = $1::uuid`, keyB).Scan(&revoked); err != nil || revoked {
		t.Fatalf("tenant B key revoked=%v (%v), want untouched", revoked, err)
	}
	rr = keyPortalDo(h, http.MethodGet, "/v1/portal/enrolment-keys", "", adminA, tenantA)
	if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), keyB) {
		t.Fatalf("tenant A list: status %d body %q, must not show tenant B's key", rr.Code, rr.Body.String())
	}
	rr = keyPortalDo(h, http.MethodPost, "/v1/portal/enrolment-keys",
		`{"label":"x","max_devices":5,"tenant_id":"`+tenantB+`"}`, adminA, tenantA)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("create with tenant_id in body: status %d, want 400", rr.Code)
	}
}

func TestEnrolmentKeyPortal_CreateValidation(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2250-portal-validation")
	admin := seedPortalUser(t, ctx, pool, tenantID, "admin")
	h := keyPortalRouter(pool)
	for _, body := range []string{
		``,
		`{"max_devices":5}`,
		`{"label":"   ","max_devices":5}`,
		`{"label":"x","max_devices":0}`,
		`{"label":"x","max_devices":100001}`,
		`{"label":"x","max_devices":5,"expires_in_days":0}`,
		`{"label":"x","max_devices":5,"expires_in_days":366}`,
		`{"label":"` + strings.Repeat("a", 101) + `","max_devices":5}`,
		`{"label":"a\u0007b","max_devices":5}`,
		`{"Label":"x","max_devices":5}`,
	} {
		if rr := keyPortalDo(h, http.MethodPost, "/v1/portal/enrolment-keys", body, admin, tenantID); rr.Code != http.StatusBadRequest {
			t.Errorf("body %q: status %d, want 400", body, rr.Code)
		}
	}
	// Decommissioned tenant: 409, like the single-use mint.
	if _, err := pool.Exec(ctx, `INSERT INTO tenant_decommission (tenant_id, mode) VALUES ($1::uuid, 'immediate')`, tenantID); err != nil {
		t.Fatalf("set directive: %v", err)
	}
	if rr := keyPortalDo(h, http.MethodPost, "/v1/portal/enrolment-keys", `{"label":"x","max_devices":5}`, admin, tenantID); rr.Code != http.StatusConflict {
		t.Fatalf("decommissioned tenant: status %d body %q, want 409", rr.Code, rr.Body.String())
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_enrolment_keys WHERE tenant_id = $1::uuid`, tenantID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("keys written = %d (%v), want 0", n, err)
	}
}

// Key enrolments and single-use token enrolments race on one trial tenant.
// Both paths lock their credential row, then the tenants row
// (CheckTrialDeviceCap). With one order there is no deadlock: every request
// ends 200, 402 (trial cap) or 410, none 500, and the trial cap holds.
func TestEnrolmentKey_ConcurrentWithBootstrapTokensOnTrialTenantNoDeadlock(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2250-trial-mixed")
	if _, err := pool.Exec(ctx, `UPDATE tenants SET is_trial = true, trial_expires_at = now() + interval '7 days', trial_device_cap = 3 WHERE id = $1::uuid`, tenantID); err != nil {
		t.Fatalf("make trial: %v", err)
	}
	_, key := seedEnrolmentKey(t, ctx, pool, tenantID, 50, time.Now().Add(time.Hour))
	var tokens []string
	for i := 0; i < 4; i++ {
		tok := "tok-" + deviceUUID(900+i)
		hash := sha256.Sum256([]byte(tok))
		if _, err := pool.Exec(ctx, `INSERT INTO bootstrap_tokens (tenant_id, token_hash, expires_at) VALUES ($1::uuid, $2, now() + interval '1 hour')`, tenantID, hash[:]); err != nil {
			t.Fatalf("mint token: %v", err)
		}
		tokens = append(tokens, tok)
	}
	h := keyTestEnrolHandler(pool)

	ctxTimeout, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	const nKey = 8
	codes := make([]int, nKey+len(tokens))
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < len(codes); i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			cred := key
			if i >= nKey {
				cred = tokens[i-nKey]
			}
			body, _ := json.Marshal(map[string]any{"enrollment_token": cred, "device_id": deviceUUID(950 + i)})
			req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytesReader(body)).WithContext(ctxTimeout)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			codes[i] = rr.Code
		}(i)
	}
	close(start)
	wg.Wait()

	ok := 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusPaymentRequired, http.StatusGone:
		default:
			t.Fatalf("unexpected status %d in %v (a deadlock or lock error surfaces as 500)", c, codes)
		}
	}
	if ok != 3 {
		t.Fatalf("admitted %d devices on a trial capped at 3 (codes %v)", ok, codes)
	}
}
