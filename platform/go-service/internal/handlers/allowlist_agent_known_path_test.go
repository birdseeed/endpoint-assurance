package handlers

// Tests for the known_path field on GET /v1/allowlist/pending-removals
// (PAT-806): the response now carries each queued entry's known_app_bundles
// path when one is on record, scoped strictly by (name, platform) so a
// macOS-platform known_app_bundles row can never populate known_path for a
// Windows-platform queue entry (and vice versa).
//
// DB-backed: require TEST_DATABASE_URL and are skipped otherwise, matching the
// pattern used by internal/handlers/device_removals_test.go. Drives the real
// handler end-to-end (bearer + HMAC + timestamp + nonce), since the handler
// has no dependency-injection seam for auth.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/ratelimit"
)

// parConnectOrSkip mirrors drConnectOrSkip (device_removals_test.go) — kept as
// its own helper name to avoid any cross-file naming collisions in this package.
func parConnectOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping pending-removals known_path DB tests")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

// parSeedTenant creates a tenant at subscription_tier='managed' (the
// queue's required minimum, PAT-650; PAT-1599 migration 0138 collapsed the
// old three-rung vocabulary to assurance/managed, and 'patch' no longer
// satisfies any tenants.subscription_tier check constraint or tier gate) with
// a known bearer token + HMAC secret, and registers cleanup. Returns the
// tenant ID.
func parSeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name, bearerToken, hmacSecret string) string {
	t.Helper()
	tokenHash := sha256.Sum256([]byte(bearerToken))

	var tenantID string
	err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret, subscription_tier)
		VALUES ($1, $2, $3, 'managed')
		RETURNING id::text
	`, name, tokenHash[:], []byte(hmacSecret)).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })

	// tenant_credentials is the table LookupTenantByBearer actually queries;
	// the tenants columns above are legacy/deprecated but still populated for
	// compatibility (see migration 0017 comment).
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_credentials (tenant_id, bearer_token_hash, hmac_secret)
		VALUES ($1::uuid, $2, $3)
	`, tenantID, tokenHash[:], []byte(hmacSecret)); err != nil {
		t.Fatalf("insert tenant_credentials: %v", err)
	}

	return tenantID
}

// parSeedAllowlistEntry queues one marked_for_uninstall tenant_allowlists row
// whose queued_at is safely past the 24h hold, via a backdated
// tenant_allowlist_changes audit row (mirrors the handler's own queued_at
// derivation).
func parSeedAllowlistEntry(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, platform, name string) int64 {
	t.Helper()
	var entryID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO tenant_allowlists (tenant_id, platform, name, match_mode, enforcement)
		VALUES ($1::uuid, $2, $3, 'exact_name', 'marked_for_uninstall')
		RETURNING id
	`, tenantID, platform, name).Scan(&entryID)
	if err != nil {
		t.Fatalf("insert tenant_allowlists: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_allowlist_changes (tenant_id, entry_id, action, detail, changed_at)
		VALUES ($1::uuid, $2, 'enforcement_changed', '{"to":"marked_for_uninstall"}'::jsonb, now() - INTERVAL '48 hours')
	`, tenantID, entryID); err != nil {
		t.Fatalf("insert tenant_allowlist_changes: %v", err)
	}
	return entryID
}

func parSeedKnownAppBundle(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name, platform, path string) {
	t.Helper()
	if _, err := pool.Exec(ctx, `
		INSERT INTO known_app_bundles (name, platform, app_path) VALUES ($1, $2, $3)
	`, name, platform, path); err != nil {
		t.Fatalf("insert known_app_bundles: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM known_app_bundles WHERE name = $1 AND platform = $2`, name, platform)
	})
}

// parSignedRequest builds a GET /v1/allowlist/pending-removals request with a
// valid bearer token and v3 signature binding the operation, empty body,
// current timestamp and a unique nonce.
func parSignedRequest(t *testing.T, bearerToken, hmacSecret string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/v1/allowlist/pending-removals", nil)
	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-Patched-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	req.Header.Set("X-Patched-Nonce", fmt.Sprintf("pat806-test-nonce-%d", time.Now().UnixNano()))
	req.Header.Set("X-Patched-Signature", agentV3TestSignature([]byte(hmacSecret), req.Method, "pending_removals", req.Header.Get("X-Patched-Timestamp"), req.Header.Get("X-Patched-Nonce"), nil))
	return req
}

// TestPendingRemovals_KnownPathScopedByPlatform is the core PAT-806
// correctness check: the same app NAME queued once as a macos entry and once
// as a windows entry must each surface ONLY its own platform's known_path —
// never the other platform's bundle path, even though both rows share the
// same name.
func TestPendingRemovals_KnownPathScopedByPlatform(t *testing.T) {
	pool := parConnectOrSkip(t)
	// t.Cleanup (not a plain defer): a bare `defer pool.Close()` runs at
	// function-return time, which is BEFORE the testing package invokes
	// t.Cleanup callbacks -- so the seed helpers' DELETE-on-cleanup below
	// would silently fail against an already-closed pool (found in PAT-806
	// review; this exact ordering bug also exists in device_removals_test.go's
	// `defer pool.Close()` -- left alone there as pre-existing/out of scope).
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat806-test-token-scoped"
	hmacSecret := "pat806-test-hmac-secret-32-bytes!"
	appName := "PAT806App"

	tenantID := parSeedTenant(t, ctx, pool, "pat806-scoped-tenant", bearerToken, hmacSecret)
	parSeedAllowlistEntry(t, ctx, pool, tenantID, "macos", appName)
	parSeedAllowlistEntry(t, ctx, pool, tenantID, "windows", appName)

	parSeedKnownAppBundle(t, ctx, pool, appName, "macos", "/Applications/PAT806App.app")
	parSeedKnownAppBundle(t, ctx, pool, appName, "windows", `C:\Program Files\PAT806App\app.exe`)

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := PendingRemovalsHandlerForLegacyExecutionCompatibility(pool, rl, 5*time.Minute)

	req := parSignedRequest(t, bearerToken, hmacSecret)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp pendingRemovalsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(resp.Items) != 2 {
		t.Fatalf("want 2 items (macos + windows), got %d: %+v", len(resp.Items), resp.Items)
	}

	var gotMacos, gotWindows bool
	for _, item := range resp.Items {
		if item.Name != appName {
			t.Errorf("unexpected item name %q in response", item.Name)
			continue
		}
		switch item.Platform {
		case "macos":
			gotMacos = true
			if item.KnownPath == nil || *item.KnownPath != "/Applications/PAT806App.app" {
				t.Errorf("macos entry known_path = %v, want /Applications/PAT806App.app", item.KnownPath)
			}
		case "windows":
			gotWindows = true
			if item.KnownPath == nil || *item.KnownPath != `C:\Program Files\PAT806App\app.exe` {
				t.Errorf(`windows entry known_path = %v, want C:\Program Files\PAT806App\app.exe`, item.KnownPath)
			}
		default:
			t.Errorf("unexpected platform %q", item.Platform)
		}
	}
	if !gotMacos || !gotWindows {
		t.Fatalf("expected both a macos and a windows item; gotMacos=%v gotWindows=%v", gotMacos, gotWindows)
	}
}

// TestPendingRemovals_KnownPathAbsentWhenNoMatch covers the null/absent case:
// a queued entry with no matching known_app_bundles row gets known_path=null,
// not an error and not a false match.
func TestPendingRemovals_KnownPathAbsentWhenNoMatch(t *testing.T) {
	pool := parConnectOrSkip(t)
	// t.Cleanup (not a plain defer): a bare `defer pool.Close()` runs at
	// function-return time, which is BEFORE the testing package invokes
	// t.Cleanup callbacks -- so the seed helpers' DELETE-on-cleanup below
	// would silently fail against an already-closed pool (found in PAT-806
	// review; this exact ordering bug also exists in device_removals_test.go's
	// `defer pool.Close()` -- left alone there as pre-existing/out of scope).
	t.Cleanup(func() { pool.Close() })
	ctx := context.Background()

	bearerToken := "pat806-test-token-nomatch"
	hmacSecret := "pat806-test-hmac-secret-nomatch!"
	appName := "PAT806NoBundleApp"

	tenantID := parSeedTenant(t, ctx, pool, "pat806-nomatch-tenant", bearerToken, hmacSecret)
	parSeedAllowlistEntry(t, ctx, pool, tenantID, "macos", appName)
	// Deliberately no known_app_bundles row for this app.

	rl := ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
	handler := PendingRemovalsHandlerForLegacyExecutionCompatibility(pool, rl, 5*time.Minute)

	req := parSignedRequest(t, bearerToken, hmacSecret)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp pendingRemovalsResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(resp.Items) != 1 {
		t.Fatalf("want 1 item, got %d: %+v", len(resp.Items), resp.Items)
	}
	if resp.Items[0].KnownPath != nil {
		t.Errorf("known_path = %v, want nil (no known_app_bundles row for this app)", *resp.Items[0].KnownPath)
	}
}
