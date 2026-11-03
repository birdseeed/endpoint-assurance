package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"

	"patched.im/api/internal/db"
	"patched.im/api/internal/ratelimit"
)

// ---------------------------------------------------------------------------
// H3 regression: enrolment-token consume must be atomic + transactional.
// DB round-trip tests — skipped when TEST_DATABASE_URL is not set.
// ---------------------------------------------------------------------------

func deviceUUID(i int) string {
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", i+1)
}

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

func TestEnrolHandler_ConcurrentSingleUse(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping enrolment concurrency DB test")
	}

	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	// Create a tenant.
	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('enrol-concurrency-test',
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM tenant_credentials WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM devices WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM bootstrap_tokens WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID)
	})

	// Mint one bootstrap token.
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	tokenPlain := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(tokenPlain))
	if _, err := pool.Exec(ctx, `
		INSERT INTO bootstrap_tokens (tenant_id, token_hash, expires_at)
		VALUES ($1::uuid, $2, now() + interval '1 hour')`, tenantID, hash[:]); err != nil {
		t.Fatalf("mint token: %v", err)
	}

	// Generous limiter so rate-limiting never masks the token gate.
	rl := ratelimit.New(ratelimit.Config{RPM: 600000, Burst: 10000})
	h := EnrolHandler(pool, rl)

	const n = 10
	type result struct{ code int }
	results := make([]result, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Distinct device_id per goroutine so device upsert conflicts don't
			// mask the token gate we're actually testing.
			devID := deviceUUID(i)
			body, _ := json.Marshal(map[string]any{
				"enrollment_token": tokenPlain,
				"device_id":        devID,
			})
			req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytesReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			<-start
			h.ServeHTTP(rr, req)
			results[i] = result{code: rr.Code}
		}(i)
	}
	close(start)
	wg.Wait()

	success, gone, other := 0, 0, 0
	for _, r := range results {
		switch r.code {
		case http.StatusOK:
			success++
		case http.StatusGone:
			gone++
		default:
			other++
		}
	}
	if success != 1 {
		t.Errorf("expected exactly 1 success, got %d (gone=%d other=%d)", success, gone, other)
	}
	if other != 0 {
		t.Errorf("expected 0 non-200/410 responses, got %d", other)
	}

	// Exactly one credential row should have been issued.
	var credCount int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM tenant_credentials WHERE tenant_id = $1::uuid`, tenantID).Scan(&credCount); err != nil {
		t.Fatalf("count creds: %v", err)
	}
	if credCount != 1 {
		t.Errorf("expected exactly 1 credential row, got %d", credCount)
	}

	// Token must be marked consumed.
	var consumed *string
	if err := pool.QueryRow(ctx,
		`SELECT consumed_at::text FROM bootstrap_tokens WHERE token_hash = $1`, hash[:]).Scan(&consumed); err != nil {
		t.Fatalf("check consumed: %v", err)
	}
	if consumed == nil {
		t.Error("token should be marked consumed after a successful enrolment")
	}
}

// TestEnrolHandler_RollbackLeavesTokenUnconsumed confirms that when a downstream
// step aborts the enrolment (here: rate limiting, which returns 429 after the
// atomic consume), the transaction rolls back and the token remains usable.
func TestEnrolHandler_RollbackLeavesTokenUnconsumed(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping enrolment rollback DB test")
	}

	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ('enrol-rollback-test',
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		        '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text`).Scan(&tenantID); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM tenant_credentials WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM devices WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM bootstrap_tokens WHERE tenant_id = $1::uuid`, tenantID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID)
	})

	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	tokenPlain := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(tokenPlain))
	if _, err := pool.Exec(ctx, `
		INSERT INTO bootstrap_tokens (tenant_id, token_hash, expires_at)
		VALUES ($1::uuid, $2, now() + interval '1 hour')`, tenantID, hash[:]); err != nil {
		t.Fatalf("mint token: %v", err)
	}

	// Burst 0 → the limiter denies every request, forcing a 429 after the
	// atomic consume statement has already run inside the tx.
	rl := ratelimit.New(ratelimit.Config{RPM: 0, Burst: 0})
	h := EnrolHandler(pool, rl)

	body, _ := json.Marshal(map[string]any{
		"enrollment_token": tokenPlain,
		"device_id":        deviceUUID(1),
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/enrol", bytesReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d (body %s)", rr.Code, rr.Body.String())
	}

	// The consume must have rolled back — token is still usable.
	var consumed *string
	if err := pool.QueryRow(ctx,
		`SELECT consumed_at::text FROM bootstrap_tokens WHERE token_hash = $1`, hash[:]).Scan(&consumed); err != nil {
		t.Fatalf("check consumed: %v", err)
	}
	if consumed != nil {
		t.Errorf("token must remain unconsumed after a rolled-back enrolment, got consumed_at=%v", *consumed)
	}
}

// TestMintTenantEnrolmentToken_ConcurrentEmailLinkMintsSerialize is the
// PAT-836 analogue of TestEnrolHandler_ConcurrentSingleUse: N truly
// concurrent email-link mints for the SAME tenant must still end up with
// exactly one live (non-superseded) token, never two-or-more. Without the
// pg_advisory_xact_lock in mintTenantEnrolmentToken's email-link branch, two
// mints that both begin before either commits could each run their
// supersede UPDATE seeing zero prior rows (under READ COMMITTED, neither
// sees the other's uncommitted INSERT) and both insert — leaving two
// simultaneously-valid tokens. The lock serializes them so each subsequent
// mint's supersede UPDATE always sees every previously-committed one.
func TestMintTenantEnrolmentToken_ConcurrentEmailLinkMintsSerialize(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PAT-836 concurrent email-link mint DB test")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { pool.Close() })

	tenantID := mkSupersedeTestTenant(t, ctx, pool, "pat836-concurrent-email-link")

	const n = 10
	tokenIDs := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			res, err := mintTenantEnrolmentToken(ctx, pool, tenantID, "email-link", "")
			tokenIDs[i] = res.TokenID
			errs[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
	}

	live := 0
	for i, tokenID := range tokenIDs {
		if tokenID == "" {
			t.Fatalf("mint %d: empty token ID", i)
		}
		if got := supersededAtFor(t, ctx, pool, tokenID); got == nil {
			live++
		}
	}
	if live != 1 {
		t.Errorf("expected exactly 1 live (non-superseded) email-link token after %d concurrent mints, got %d", n, live)
	}
}
