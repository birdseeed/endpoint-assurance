package handlers

// PAT-2250: reusable per-tenant enrolment keys redeemed at POST /v1/enrol.
// DB-backed; skipped without TEST_DATABASE_URL.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/ratelimit"
)

// seedEnrolmentKey inserts a key row directly (bypassing the portal create
// handler) and returns its id and plaintext.
func seedEnrolmentKey(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID string, maxDevices int, expiresAt time.Time) (string, string) {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	secret := base64.RawURLEncoding.EncodeToString(raw)
	plaintext := "pek_" + secret
	hash := sha256.Sum256([]byte(plaintext))
	var keyID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant_enrolment_keys (tenant_id, key_hash, key_hint, label, max_devices, expires_at, created_at, created_by)
		VALUES ($1::uuid, $2, $3, 'test key', $4, $5::timestamptz, LEAST(now(), $5::timestamptz - interval '1 hour'), 'seed@example.test')
		RETURNING id::text`, tenantID, hash[:], secret[:4], maxDevices, expiresAt).Scan(&keyID); err != nil {
		t.Fatalf("seed enrolment key: %v", err)
	}
	return keyID, plaintext
}

func enrolWithToken(h http.Handler, token, hwUUID string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]any{"enrollment_token": token, "device_id": hwUUID})
	req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytesReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func keyTestEnrolHandler(pool *pgxpool.Pool) http.Handler {
	return EnrolHandler(pool, ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000}))
}

func keyUseCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, keyID string) (rows, distinct int) {
	t.Helper()
	if err := pool.QueryRow(ctx, `
		SELECT count(*), count(DISTINCT hw_uuid) FROM tenant_enrolment_key_uses WHERE key_id = $1::uuid`,
		keyID).Scan(&rows, &distinct); err != nil {
		t.Fatalf("count key uses: %v", err)
	}
	return rows, distinct
}

func TestEnrolmentKey_EnrolWithinCap(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2250-within-cap")
	keyID, key := seedEnrolmentKey(t, ctx, pool, tenantID, 2, time.Now().Add(24*time.Hour))
	h := keyTestEnrolHandler(pool)

	for i := 0; i < 2; i++ {
		rr := enrolWithToken(h, key, deviceUUID(100+i))
		if rr.Code != http.StatusOK {
			t.Fatalf("enrol %d: status %d body %q", i, rr.Code, rr.Body.String())
		}
		var resp enrolResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if resp.TenantID != tenantID || resp.BearerToken == "" || resp.HMACSecret == "" {
			t.Fatalf("enrol %d: unexpected response %+v", i, resp)
		}
	}
	// The same key keeps working: it is not single-use.
	rows, distinct := keyUseCount(t, ctx, pool, keyID)
	if rows != 2 || distinct != 2 {
		t.Fatalf("key uses rows=%d distinct=%d, want 2/2", rows, distinct)
	}
	var creds int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant_credentials WHERE tenant_id = $1::uuid AND device_id IS NOT NULL`, tenantID).Scan(&creds); err != nil {
		t.Fatalf("count creds: %v", err)
	}
	if creds != 2 {
		t.Fatalf("credentials = %d, want 2", creds)
	}
}

func TestEnrolmentKey_PastCapRefused(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2250-past-cap")
	keyID, key := seedEnrolmentKey(t, ctx, pool, tenantID, 1, time.Now().Add(24*time.Hour))
	h := keyTestEnrolHandler(pool)

	if rr := enrolWithToken(h, key, deviceUUID(200)); rr.Code != http.StatusOK {
		t.Fatalf("first enrol: status %d body %q", rr.Code, rr.Body.String())
	}
	rr := enrolWithToken(h, key, deviceUUID(201))
	if rr.Code != http.StatusGone {
		t.Fatalf("enrol past cap: status %d body %q, want 410", rr.Code, rr.Body.String())
	}
	// Re-enrolling the device that already holds the slot (wipe and
	// reinstall) does not consume a second slot, so it is still admitted.
	if rr := enrolWithToken(h, key, deviceUUID(200)); rr.Code != http.StatusOK {
		t.Fatalf("re-enrol of counted device: status %d body %q, want 200", rr.Code, rr.Body.String())
	}
	rows, distinct := keyUseCount(t, ctx, pool, keyID)
	if rows != 2 || distinct != 1 {
		t.Fatalf("key uses rows=%d distinct=%d, want 2/1", rows, distinct)
	}
	var devices int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id = $1::uuid`, tenantID).Scan(&devices); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if devices != 1 {
		t.Fatalf("devices = %d, want 1 (refused enrolment must not create a device)", devices)
	}
}

// Concurrent enrolments against a key at max_devices-1: exactly one new
// device is admitted, every other request gets 410, none errors.
func TestEnrolmentKey_ConcurrentAtCapMinusOneAdmitsExactlyOne(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2250-concurrent")
	const maxDevices = 4
	keyID, key := seedEnrolmentKey(t, ctx, pool, tenantID, maxDevices, time.Now().Add(24*time.Hour))
	h := keyTestEnrolHandler(pool)

	for i := 0; i < maxDevices-1; i++ {
		if rr := enrolWithToken(h, key, deviceUUID(300+i)); rr.Code != http.StatusOK {
			t.Fatalf("pre-enrol %d: status %d body %q", i, rr.Code, rr.Body.String())
		}
	}

	// Hold every enrolment between its cap COUNT and its use INSERT so the
	// requests genuinely overlap there. With the key row lock they queue
	// behind each other; without it several read "under cap" and all admit.
	enrolmentKeyAfterCapCount = func() { time.Sleep(40 * time.Millisecond) }
	t.Cleanup(func() { enrolmentKeyAfterCapCount = nil })

	const n = 12
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = enrolWithToken(h, key, deviceUUID(400+i)).Code
		}(i)
	}
	close(start)
	wg.Wait()

	ok, gone, other := 0, 0, 0
	for _, c := range codes {
		switch c {
		case http.StatusOK:
			ok++
		case http.StatusGone:
			gone++
		default:
			other++
		}
	}
	if ok != 1 || gone != n-1 || other != 0 {
		t.Fatalf("concurrent at cap-1: ok=%d gone=%d other=%d (codes %v), want 1/%d/0", ok, gone, other, codes, n-1)
	}
	if _, distinct := keyUseCount(t, ctx, pool, keyID); distinct != maxDevices {
		t.Fatalf("distinct devices on key = %d, want %d", distinct, maxDevices)
	}
	var devices int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id = $1::uuid`, tenantID).Scan(&devices); err != nil {
		t.Fatalf("count devices: %v", err)
	}
	if devices != maxDevices {
		t.Fatalf("devices = %d, want %d", devices, maxDevices)
	}
}

func TestEnrolmentKey_RevokedAndExpiredRefused(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2250-revoked-expired")
	h := keyTestEnrolHandler(pool)

	// Revoked after one enrolment: new enrolments refused, the enrolled
	// device's credential is untouched.
	revokedID, revoked := seedEnrolmentKey(t, ctx, pool, tenantID, 10, time.Now().Add(24*time.Hour))
	if rr := enrolWithToken(h, revoked, deviceUUID(500)); rr.Code != http.StatusOK {
		t.Fatalf("enrol before revoke: status %d body %q", rr.Code, rr.Body.String())
	}
	if _, err := pool.Exec(ctx, `UPDATE tenant_enrolment_keys SET revoked_at = now(), revoked_by = 'x@example.test' WHERE id = $1::uuid`, revokedID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if rr := enrolWithToken(h, revoked, deviceUUID(501)); rr.Code != http.StatusGone {
		t.Fatalf("revoked key: status %d body %q, want 410", rr.Code, rr.Body.String())
	}
	if rr := enrolWithToken(h, revoked, deviceUUID(500)); rr.Code != http.StatusGone {
		t.Fatalf("revoked key, re-enrol of counted device: status %d body %q, want 410", rr.Code, rr.Body.String())
	}
	var live int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM tenant_credentials tc JOIN devices d ON d.id = tc.device_id
		WHERE d.tenant_id = $1::uuid AND d.hw_uuid = $2::uuid AND tc.revoked_at IS NULL`,
		tenantID, deviceUUID(500)).Scan(&live); err != nil {
		t.Fatalf("count creds: %v", err)
	}
	if live != 1 {
		t.Fatalf("live credentials for the enrolled device = %d, want 1 (revocation must not unenrol)", live)
	}

	// Expired.
	_, expired := seedEnrolmentKey(t, ctx, pool, tenantID, 10, time.Now().Add(-time.Minute))
	if rr := enrolWithToken(h, expired, deviceUUID(502)); rr.Code != http.StatusGone {
		t.Fatalf("expired key: status %d body %q, want 410", rr.Code, rr.Body.String())
	}
}

// A key is bound to the tenant that owns it: /v1/enrol takes the tenant
// from the key, never from the request, so tenant A's key always lands the
// device in tenant A and never in tenant B.
func TestEnrolmentKey_TenantBound(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantA := catSeedTenant(t, ctx, pool, "pat2250-tenant-a")
	tenantB := catSeedTenant(t, ctx, pool, "pat2250-tenant-b")
	keyAID, keyA := seedEnrolmentKey(t, ctx, pool, tenantA, 5, time.Now().Add(24*time.Hour))
	h := keyTestEnrolHandler(pool)

	// A client that tries to steer the tenant gets tenant A regardless.
	body, _ := json.Marshal(map[string]any{"enrollment_token": keyA, "device_id": deviceUUID(600), "tenant_id": tenantB})
	req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytesReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("enrol: status %d body %q", rr.Code, rr.Body.String())
	}
	var resp enrolResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.TenantID != tenantA {
		t.Fatalf("enrolled into tenant %s, want key owner %s", resp.TenantID, tenantA)
	}
	var inB int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM devices WHERE tenant_id = $1::uuid`, tenantB).Scan(&inB); err != nil {
		t.Fatalf("count B devices: %v", err)
	}
	if inB != 0 {
		t.Fatalf("tenant B has %d devices, want 0", inB)
	}
	var useTenant string
	if err := pool.QueryRow(ctx, `SELECT d.tenant_id::text FROM tenant_enrolment_key_uses u JOIN devices d ON d.id = u.device_id WHERE u.key_id = $1::uuid AND u.tenant_id = d.tenant_id`, keyAID).Scan(&useTenant); err != nil {
		t.Fatalf("read key use: %v", err)
	}
	if useTenant != tenantA {
		t.Fatalf("key use recorded for tenant %s, want %s", useTenant, tenantA)
	}
}

// A single-use bootstrap token whose random base64url text happens to start
// with "pek_" must still redeem through the bootstrap path: the prefix
// routes the lookup, it never makes an existing token unusable.
func TestEnrolmentKey_BootstrapTokenWithKeyPrefixStillRedeems(t *testing.T) {
	pool := catConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := catSeedTenant(t, ctx, pool, "pat2250-prefix-collision")
	token := "pek_" + base64.RawURLEncoding.EncodeToString(make([]byte, 30))
	hash := sha256.Sum256([]byte(token))
	if _, err := pool.Exec(ctx, `INSERT INTO bootstrap_tokens (tenant_id, token_hash, expires_at) VALUES ($1::uuid, $2, now() + interval '1 hour')`, tenantID, hash[:]); err != nil {
		t.Fatalf("mint token: %v", err)
	}
	h := keyTestEnrolHandler(pool)
	if rr := enrolWithToken(h, token, deviceUUID(700)); rr.Code != http.StatusOK {
		t.Fatalf("enrol: status %d body %q", rr.Code, rr.Body.String())
	}
	if rr := enrolWithToken(h, token, deviceUUID(701)); rr.Code != http.StatusGone {
		t.Fatalf("second use of single-use token: status %d, want 410", rr.Code)
	}
}
