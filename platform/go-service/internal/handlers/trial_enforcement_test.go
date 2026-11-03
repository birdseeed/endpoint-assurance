package handlers

// PAT-867: proves the trial guard is actually wired up and firing, not just
// defined. Before this ticket, TrialGuardMiddleware/CheckTrialDeviceCap were
// never called from anywhere reachable by a real request (see trial.go's
// package doc comment) — an expired trial ingested forever and a
// device-capped trial enrolled without limit. These tests exercise the real
// handlers end to end against a live Postgres, gated by TEST_DATABASE_URL like
// TestTrialProvisionHandlerDB above.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/envelope"
	"patched.im/api/internal/ratelimit"
)

// testTenantOpts configures testTenant's insert.
type testTenantOpts struct {
	isTrial        bool
	trialExpiresAt *time.Time // nil => not a trial deadline
	trialDeviceCap int        // only meaningful when isTrial
	trialEmail     string     // must be unique per trial row (partial unique index)
}

// testTenant inserts a tenant row directly (bypassing the HTTP provisioning
// path so trial_expires_at can be set to an already-past value) and returns
// its ID, a usable plaintext bearer token, and the RAW HMAC secret (needed to
// sign a valid /v1/inventory request). Cleans itself up via t.Cleanup.
func testTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, opts testTenantOpts) (tenantID, bearerToken string, hmacSecretRaw []byte) {
	t.Helper()

	bearerBytes := make([]byte, 32)
	if _, err := rand.Read(bearerBytes); err != nil {
		t.Fatalf("rand bearer: %v", err)
	}
	bearerToken = base64.RawURLEncoding.EncodeToString(bearerBytes)
	bearerHash := sha256.Sum256([]byte(bearerToken))

	hmacSecret := make([]byte, 32)
	if _, err := rand.Read(hmacSecret); err != nil {
		t.Fatalf("rand hmac: %v", err)
	}
	encHMAC, err := envelope.Default().EncryptBytes(hmacSecret)
	if err != nil {
		t.Fatalf("encrypt hmac: %v", err)
	}

	var trialEmailArg any
	if opts.trialEmail != "" {
		trialEmailArg = opts.trialEmail
	}

	err = pool.QueryRow(ctx, `
		INSERT INTO tenants (
			name, bearer_token_hash, hmac_secret,
			is_trial, trial_expires_at, trial_device_cap, trial_email
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id::text
	`, "pat-867-test-tenant", bearerHash[:], encHMAC,
		opts.isTrial, opts.trialExpiresAt, opts.trialDeviceCap, trialEmailArg).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id = $1::uuid`, tenantID)
	})

	encCredHMAC, err := envelope.Default().EncryptBytes(hmacSecret)
	if err != nil {
		t.Fatalf("encrypt cred hmac: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2, $3)
	`, tenantID, bearerHash[:], encCredHMAC); err != nil {
		t.Fatalf("insert tenant_credentials: %v", err)
	}

	return tenantID, bearerToken, hmacSecret
}

// signedInventoryReq builds a fully-authenticated POST /v1/inventory request
// for the given tenant credentials, with a v3 signature binding the operation,
// body and fresh replay headers. The trial-expiry check runs only after this
// whole gate passes, so the request must be genuinely valid to reach it.
func signedInventoryReq(t *testing.T, bearerToken string, hmacSecretRaw, body []byte) *http.Request {
	t.Helper()

	nonceB := make([]byte, 16)
	_, _ = rand.Read(nonceB)

	req := httptest.NewRequest(http.MethodPost, "/v1/inventory", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Patched-Nonce", hex.EncodeToString(nonceB))
	req.Header.Set("X-Patched-Signature", agentV3TestSignature(hmacSecretRaw, req.Method, "inventory", req.Header.Get("X-Patched-Timestamp"), req.Header.Get("X-Patched-Nonce"), body))
	return req
}

// testBootstrapToken mints a valid, unconsumed bootstrap token for tenantID
// and returns its plaintext.
func testBootstrapToken(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID string) string {
	t.Helper()
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		t.Fatalf("rand token: %v", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(plaintext))
	if _, err := pool.Exec(ctx, `
		INSERT INTO bootstrap_tokens (tenant_id, token_hash, expires_at)
		VALUES ($1::uuid, $2, now() + interval '1 hour')
	`, tenantID, hash[:]); err != nil {
		t.Fatalf("insert bootstrap_token: %v", err)
	}
	return plaintext
}

// testEnrolledDevice inserts a device + a non-revoked per-device credential
// row for tenantID, so it counts towards CheckTrialDeviceCap's device count.
func testEnrolledDevice(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID string) {
	t.Helper()
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hw_uuid, os)
		VALUES ($1::uuid, gen_random_uuid(), 'macOS')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	bearerBytes := make([]byte, 16)
	_, _ = rand.Read(bearerBytes)
	hash := sha256.Sum256(bearerBytes)
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2::uuid, $3, $4)
	`, tenantID, deviceID, hash[:], []byte("unused")); err != nil {
		t.Fatalf("insert device credential: %v", err)
	}
}

func trialDBPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping trial enforcement DB tests")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// ---------------------------------------------------------------------------
// (a) InventoryHandler: expired trial tenant gets 402, not silent accept.
// ---------------------------------------------------------------------------

func TestInventoryHandler_ExpiredTrial_Returns402(t *testing.T) {
	pool := trialDBPool(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-24 * time.Hour) // expired yesterday
	tenantID, bearerToken, hmacSecret := testTenant(t, ctx, pool, testTenantOpts{
		isTrial:        true,
		trialExpiresAt: &past,
		trialDeviceCap: 3,
		trialEmail:     "pat867-expired@example.test",
	})

	rl := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})
	h := InventoryHandler(pool, rl, 5*time.Minute)

	// The trial-expiry check runs only AFTER the full auth + replay gate
	// (bearer, HMAC, timestamp, nonce), so the request must be genuinely and
	// fully authenticated to reach it. Body is `{}` — it would fail schema
	// validation, but the 402 is returned before that step, which is what we
	// are asserting. (An UNSIGNED request would 401 here, not 402 — that is
	// the point of the ordering; see TestInventoryHandler_ExpiredTrial_UnsignedIs401.)
	req := signedInventoryReq(t, bearerToken, hmacSecret, []byte(`{}`))
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("tenant_id=%s: want 402 for expired trial, got %d: %s", tenantID, w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "trial_expired" {
		t.Errorf(`want {"error":"trial_expired"}, got %v`, resp)
	}
}

// TestInventoryHandler_ExpiredTrial_UnsignedIs401 pins the security ordering
// from the PAT-867 non-author review: an expired trial tenant presenting a
// valid bearer but NO HMAC signature must get the uniform 401, never a 402.
// The 402 is a state signal for an authenticated tenant and must not precede
// the second auth factor (else a bearer-only holder gets a trial-status
// oracle). This test fails if the trial check is ever moved back ahead of the
// HMAC/timestamp/nonce gate.
func TestInventoryHandler_ExpiredTrial_UnsignedIs401(t *testing.T) {
	pool := trialDBPool(t)
	ctx := context.Background()

	past := time.Now().UTC().Add(-24 * time.Hour)
	tenantID, bearerToken, _ := testTenant(t, ctx, pool, testTenantOpts{
		isTrial:        true,
		trialExpiresAt: &past,
		trialDeviceCap: 3,
		trialEmail:     "pat867-expired-unsigned@example.test",
	})

	rl := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})
	h := InventoryHandler(pool, rl, 5*time.Minute)

	// Valid bearer, but no X-Patched-Signature — must fail at HMAC (401).
	req := httptest.NewRequest(http.MethodPost, "/v1/inventory", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("tenant_id=%s: bearer-only request for an expired trial must be 401 (uniform auth failure), got %d: %s",
			tenantID, w.Code, w.Body.String())
	}
}

// TestTrialChecks_FailClosedOnDBError proves both checks SURFACE a DB error
// (return err != nil) rather than swallowing it, which is what lets the
// handlers fail closed — a paid-tier gate must never be bypassed by a lookup
// failure. A closed pool is a deterministic stand-in for an infra fault: its
// QueryRow returns an error via Scan. The handlers turn that non-nil error
// into a 500 (see inventory.go / enrolment.go), so an expired/capped trial can
// never slip through on a DB hiccup.
func TestTrialChecks_FailClosedOnDBError(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping trial fail-closed DB test")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	pool.Close() // force every subsequent query to error
	ctx := context.Background()
	const someTenant = "00000000-0000-0000-0000-000000000001"

	if _, err := CheckTrialExpired(ctx, pool, someTenant); err == nil {
		t.Error("CheckTrialExpired must surface a DB error (return non-nil) so the caller fails closed")
	}
	if _, err := CheckTrialDeviceCap(ctx, pool, someTenant); err == nil {
		t.Error("CheckTrialDeviceCap must surface a DB error (return non-nil) so the caller fails closed")
	}
}

// TestInventoryHandler_NonTrialTenant_Unaffected proves the same code path
// does not reject a non-trial tenant — the 402 must not become a blanket
// regression for paying/full tenants.
func TestInventoryHandler_NonTrialTenant_Unaffected(t *testing.T) {
	pool := trialDBPool(t)
	ctx := context.Background()

	tenantID, bearerToken, _ := testTenant(t, ctx, pool, testTenantOpts{isTrial: false})

	rl := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})
	h := InventoryHandler(pool, rl, 5*time.Minute)

	req := httptest.NewRequest(http.MethodPost, "/v1/inventory", bytes.NewBufferString(`{}`))
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	w := httptest.NewRecorder()
	h(w, req)

	// Not a trial tenant, so CheckTrialExpired must not fire — the request
	// should fail later, at HMAC verification (401), never at 402.
	if w.Code == http.StatusPaymentRequired {
		t.Fatalf("tenant_id=%s: non-trial tenant got 402 — trial guard false positive: %s", tenantID, w.Body.String())
	}
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("tenant_id=%s: want 401 (missing HMAC signature), got %d: %s", tenantID, w.Code, w.Body.String())
	}
}

// ---------------------------------------------------------------------------
// (b) EnrolHandler: trial tenant at its device cap gets 402, not a new device.
// ---------------------------------------------------------------------------

func TestEnrolHandler_TrialDeviceCapReached_Returns402(t *testing.T) {
	pool := trialDBPool(t)
	ctx := context.Background()

	future := time.Now().UTC().Add(14 * 24 * time.Hour)
	tenantID, _, _ := testTenant(t, ctx, pool, testTenantOpts{
		isTrial:        true,
		trialExpiresAt: &future,
		trialDeviceCap: 1, // cap of 1
		trialEmail:     "pat867-cap@example.test",
	})
	// Pre-populate one enrolled device so the tenant is already at its cap.
	testEnrolledDevice(t, ctx, pool, tenantID)

	token := testBootstrapToken(t, ctx, pool, tenantID)

	rl := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})
	h := EnrolHandler(pool, rl)

	body, _ := json.Marshal(map[string]any{
		"enrollment_token": token,
		"device_id":        "00000000-0000-0000-0000-0000000000aa",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("tenant_id=%s: want 402 at device cap, got %d: %s", tenantID, w.Code, w.Body.String())
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["error"] != "trial_device_cap_reached" {
		t.Errorf(`want {"error":"trial_device_cap_reached"}, got %v`, resp)
	}

	// The token must not have been burned — rejecting the enrolment rolls the
	// tx back (see EnrolHandler's deferred Rollback), so a later successful
	// enrolment (e.g. after an admin raises the cap) can still use it.
	var consumedAt *time.Time
	hash := sha256.Sum256([]byte(token))
	if err := pool.QueryRow(ctx, `
		SELECT consumed_at FROM bootstrap_tokens WHERE token_hash = $1
	`, hash[:]).Scan(&consumedAt); err != nil {
		t.Fatalf("query token: %v", err)
	}
	if consumedAt != nil {
		t.Error("want bootstrap token NOT consumed after a 402 device-cap rejection")
	}
}

// TestCheckTrialDeviceCap_SerializesConcurrentEnrol proves the cap check is
// atomic against a concurrent same-tenant enrolment (PAT-867 non-author-review
// finding: the COUNT-then-INSERT was a TOCTOU race). It drives two real
// transactions with a deterministic interleaving rather than relying on
// goroutine-scheduling luck — an HTTP-level race test is unreliable because a
// cold pool tends to serialise the requests and hide the defect.
//
// Setup: trial tenant, cap=1, zero devices. tx1 runs the cap check (observes
// "under cap"), then inserts its device but does NOT commit. tx2 then runs the
// same check. With the FOR UPDATE tenant-row lock, tx2 MUST block on tx1 until
// tx1 commits, and then observe the cap as reached. Without the lock, tx2's
// COUNT reads its own snapshot (tx1's device still uncommitted), returns
// "under cap", and both enrolments would proceed — the exact overshoot the
// reviewer flagged; that path makes this test fail on the "completed without
// blocking" branch.
func TestCheckTrialDeviceCap_SerializesConcurrentEnrol(t *testing.T) {
	pool := trialDBPool(t)
	ctx := context.Background()

	future := time.Now().UTC().Add(14 * 24 * time.Hour)
	tenantID, _, _ := testTenant(t, ctx, pool, testTenantOpts{
		isTrial:        true,
		trialExpiresAt: &future,
		trialDeviceCap: 1,
		trialEmail:     "pat867-cap-serialize@example.test",
	})

	// tx1: run the cap check (takes the FOR UPDATE lock and sees 0 < 1), then
	// insert a device + credential representing the first enrolment, uncommitted.
	tx1, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	defer func() { _ = tx1.Rollback(ctx) }()

	reached1, err := CheckTrialDeviceCap(ctx, tx1, tenantID)
	if err != nil {
		t.Fatalf("tx1 cap check: %v", err)
	}
	if reached1 {
		t.Fatalf("tx1 cap check: want under-cap (false) at 0 devices, got true")
	}
	insertDeviceCredInTx(t, ctx, tx1, tenantID)

	// tx2: the concurrent enrolment. With FOR UPDATE it must block on tx1's
	// tenant-row lock. Run it in a goroutine and assert it does NOT complete
	// while tx1 is still open.
	tx2, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin tx2: %v", err)
	}
	defer func() { _ = tx2.Rollback(ctx) }()

	type capRes struct {
		reached bool
		err     error
	}
	done := make(chan capRes, 1)
	go func() {
		r, e := CheckTrialDeviceCap(ctx, tx2, tenantID)
		done <- capRes{r, e}
	}()

	select {
	case res := <-done:
		t.Fatalf("tx2 cap check returned (reached=%v, err=%v) while tx1 held the lock — "+
			"FOR UPDATE is not serialising same-tenant enrolments; the cap-overshoot race is open",
			res.reached, res.err)
	case <-time.After(2 * time.Second):
		// Expected: tx2 is blocked on tx1's tenant-row lock.
	}

	// Commit tx1 (its device becomes visible). tx2 unblocks and must now see
	// the cap as reached.
	if err := tx1.Commit(ctx); err != nil {
		t.Fatalf("commit tx1: %v", err)
	}
	res := <-done
	if res.err != nil {
		t.Fatalf("tx2 cap check after tx1 commit: %v", res.err)
	}
	if !res.reached {
		t.Error("after tx1 committed its device, tx2 must observe the cap as reached (true)")
	}
}

// insertDeviceCredInTx inserts a device + a non-revoked device-scoped
// credential for tenantID on tx (mirrors testEnrolledDevice but on an open
// transaction so the row is visible only within that tx until commit).
func insertDeviceCredInTx(t *testing.T, ctx context.Context, tx pgx.Tx, tenantID string) {
	t.Helper()
	var deviceID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hw_uuid, os)
		VALUES ($1::uuid, gen_random_uuid(), 'macOS')
		RETURNING id::text
	`, tenantID).Scan(&deviceID); err != nil {
		t.Fatalf("insert device in tx: %v", err)
	}
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	h := sha256.Sum256(b)
	if _, err := tx.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, device_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2::uuid, $3, $4)
	`, tenantID, deviceID, h[:], []byte("unused")); err != nil {
		t.Fatalf("insert device credential in tx: %v", err)
	}
}

// TestEnrolHandler_NonTrialTenant_Unaffected proves a non-trial tenant can
// still enrol past what would be a trial device cap — the guard must only
// ever apply to is_trial=true tenants.
func TestEnrolHandler_NonTrialTenant_Unaffected(t *testing.T) {
	pool := trialDBPool(t)
	ctx := context.Background()

	tenantID, _, _ := testTenant(t, ctx, pool, testTenantOpts{isTrial: false})
	// Enrol several devices — well past what a trial's default cap (3) would
	// allow — to prove no cap applies to a non-trial tenant.
	for i := 0; i < 5; i++ {
		testEnrolledDevice(t, ctx, pool, tenantID)
	}

	token := testBootstrapToken(t, ctx, pool, tenantID)

	rl := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})
	h := EnrolHandler(pool, rl)

	body, _ := json.Marshal(map[string]any{
		"enrollment_token": token,
		"device_id":        "00000000-0000-0000-0000-0000000000bb",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("tenant_id=%s: want 200 (non-trial tenant unaffected by device cap), got %d: %s",
			tenantID, w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), tenantID) {
		t.Errorf("want response body to contain tenant_id %s, got: %s", tenantID, w.Body.String())
	}
}
