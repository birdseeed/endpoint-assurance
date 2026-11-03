package extractor

// new_apps_notify_test.go — tests for the Slack/email alert on new-app
// detection (PAT-819): a genuinely new tenant_new_apps row alerts exactly
// once; duplicate ingests, deferred items, and resolved items never re-alert;
// a failing Slack webhook is logged but never fails the sweep.
//
// DB-backed; require TEST_DATABASE_URL and are skipped otherwise, matching the
// convention in handlers/catalogue_test.go and handlers/notify_alerts_test.go.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/notify"
)

// naConnectOrSkip opens a pool using TEST_DATABASE_URL or skips the test.
func naConnectOrSkip(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping new-app notify DB tests")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return pool
}

// naSeedTenant inserts a throwaway tenant and registers cleanup.
func naSeedTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) string {
	t.Helper()
	var tenantID string
	err := pool.QueryRow(ctx, `
		INSERT INTO tenants (name, bearer_token_hash, hmac_secret)
		VALUES ($1, '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea,
		            '\x0000000000000000000000000000000000000000000000000000000000000000'::bytea)
		RETURNING id::text
	`, name).Scan(&tenantID)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1::uuid`, tenantID) })
	return tenantID
}

// naSeedDeviceWithApp inserts one macOS device with a single installed app
// that has no matching tenant_app_policies row, so detectNewTenantApps's
// candidate query treats it as a new-app candidate. Thin wrapper over
// naSeedDeviceWithAppOS with the macOS default this helper has always had —
// existing callers are unaffected.
func naSeedDeviceWithApp(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, appName, teamID, identifier string) {
	t.Helper()
	naSeedDeviceWithAppOS(t, ctx, pool, tenantID, appName, teamID, identifier, "macOS")
}

// naSeedDeviceWithAppOS is naSeedDeviceWithApp with an explicit devices.os
// value (e.g. "Windows"), for tests that need a genuinely
// platform-attributed candidate rather than the macOS default — PAT-1318
// finding B: candidatesSQL derives platform from devices.os
// (new_apps.go: LOWER(td.os) = 'windows' → 'windows', else 'macos'), so a
// test claiming to exercise "the Windows case" must actually set os =
// 'Windows' here, not merely use a Windows-shaped app name/identifier on a
// macOS-tagged device.
func naSeedDeviceWithAppOS(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, appName, teamID, identifier, os string) {
	t.Helper()
	var deviceID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO devices (tenant_id, hw_uuid, hostname, os)
		VALUES ($1::uuid, gen_random_uuid(), 'test-host', $2)
		RETURNING id::text
	`, tenantID, os).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device_apps (device_id, name, version, identifier, team_id)
		VALUES ($1::uuid, $2, '1.0', $3, $4)
	`, deviceID, appName, identifier, teamID); err != nil {
		t.Fatalf("insert device_app: %v", err)
	}
}

// naSlackCounter starts a test Slack webhook server that counts deliveries
// (always 200 OK) and points NOTIFY_SLACK_WEBHOOK_URL at it for the test.
func naSlackCounter(t *testing.T) *int32 {
	t.Helper()
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("NOTIFY_SLACK_WEBHOOK_URL", srv.URL)
	return &count
}

// naFailingSlack starts a test Slack webhook server that always 500s, to
// exercise the delivery-failure path.
func naFailingSlack(t *testing.T) *int32 {
	t.Helper()
	var count int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&count, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("NOTIFY_SLACK_WEBHOOK_URL", srv.URL)
	return &count
}

func naWaitForCount(t *testing.T, counter *int32, want int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(counter) == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for slack call count = %d, got %d", want, atomic.LoadInt32(counter))
}

// naAssertStableCount asserts *counter stays at want for the given window —
// used to prove a duplicate/deferred/resolved item did NOT trigger an alert.
func naAssertStableCount(t *testing.T, counter *int32, want int32, window time.Duration) {
	t.Helper()
	time.Sleep(window)
	if got := atomic.LoadInt32(counter); got != want {
		t.Fatalf("expected slack call count to stay at %d, got %d", want, got)
	}
}

// ---------------------------------------------------------------------------
// New record — exactly one alert
// ---------------------------------------------------------------------------

func TestDetectNewTenantAppsNewRecordSendsOneSlackAlert(t *testing.T) {
	pool := naConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := naSeedTenant(t, ctx, pool, "pat819-new-record")
	naSeedDeviceWithApp(t, ctx, pool, tenantID, "Totally New App", "TEAMID819", "com.example.new819")

	counter := naSlackCounter(t)
	notifier := notify.New()

	if err := doDetectNewTenantApps(ctx, pool, tenantID, notifier); err != nil {
		t.Fatalf("doDetectNewTenantApps: %v", err)
	}
	naWaitForCount(t, counter, 1, 2*time.Second)
}

// ---------------------------------------------------------------------------
// Duplicate ingest of an existing pending record — no additional alert
// ---------------------------------------------------------------------------

func TestDetectNewTenantAppsDuplicateIngestDoesNotSpamSlack(t *testing.T) {
	pool := naConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := naSeedTenant(t, ctx, pool, "pat819-dup-record")
	naSeedDeviceWithApp(t, ctx, pool, tenantID, "Duplicate App", "TEAMDUP819", "com.example.dup819")

	counter := naSlackCounter(t)
	notifier := notify.New()

	if err := doDetectNewTenantApps(ctx, pool, tenantID, notifier); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	naWaitForCount(t, counter, 1, 2*time.Second)

	// A second device running the same still-undecided app simulates a
	// duplicate inventory ingest: the upsert bumps host_count in place but
	// must not fire a second alert.
	naSeedDeviceWithApp(t, ctx, pool, tenantID, "Duplicate App", "TEAMDUP819", "com.example.dup819")
	if err := doDetectNewTenantApps(ctx, pool, tenantID, notifier); err != nil {
		t.Fatalf("second sweep: %v", err)
	}
	naAssertStableCount(t, counter, 1, 300*time.Millisecond)
}

// ---------------------------------------------------------------------------
// Deferred existing record — no alert
// ---------------------------------------------------------------------------

func TestDetectNewTenantAppsDeferredExistingRecordDoesNotAlert(t *testing.T) {
	pool := naConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := naSeedTenant(t, ctx, pool, "pat819-deferred")
	teamID := "TEAMDEFER819"
	naSeedDeviceWithApp(t, ctx, pool, tenantID, "Deferred App", teamID, "com.example.defer819")

	// Pre-seed the tenant_new_apps row as already deferred by an operator —
	// app_identity mirrors the "team:" + lower(team_id) rule in candidatesSQL.
	identity := "team:" + strings.ToLower(teamID)
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_new_apps (tenant_id, app_identity, name, publisher_signature, platform, host_count, decision, defer_until)
		VALUES ($1::uuid, $2, 'Deferred App', $3, 'macos', 1, 'defer', now() + interval '90 days')
	`, tenantID, identity, teamID); err != nil {
		t.Fatalf("seed deferred new_app row: %v", err)
	}

	counter := naSlackCounter(t)
	notifier := notify.New()

	if err := doDetectNewTenantApps(ctx, pool, tenantID, notifier); err != nil {
		t.Fatalf("doDetectNewTenantApps: %v", err)
	}
	naAssertStableCount(t, counter, 0, 300*time.Millisecond)
}

// ---------------------------------------------------------------------------
// Resolved existing record — no alert
// ---------------------------------------------------------------------------

func TestDetectNewTenantAppsResolvedExistingRecordDoesNotAlert(t *testing.T) {
	pool := naConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := naSeedTenant(t, ctx, pool, "pat819-resolved")
	teamID := "TEAMRESOLVED819"
	naSeedDeviceWithApp(t, ctx, pool, tenantID, "Resolved App", teamID, "com.example.resolved819")

	// Pre-seed the tenant_new_apps row as already approved by an operator.
	identity := "team:" + strings.ToLower(teamID)
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_new_apps (tenant_id, app_identity, name, publisher_signature, platform, host_count, decision, decided_by, decided_at)
		VALUES ($1::uuid, $2, 'Resolved App', $3, 'macos', 1, 'approve', 'admin', now())
	`, tenantID, identity, teamID); err != nil {
		t.Fatalf("seed resolved new_app row: %v", err)
	}

	counter := naSlackCounter(t)
	notifier := notify.New()

	if err := doDetectNewTenantApps(ctx, pool, tenantID, notifier); err != nil {
		t.Fatalf("doDetectNewTenantApps: %v", err)
	}
	naAssertStableCount(t, counter, 0, 300*time.Millisecond)
}

// ---------------------------------------------------------------------------
// Slack delivery failure — logged, sweep still succeeds
// ---------------------------------------------------------------------------

func TestDetectNewTenantAppsSlackFailureDoesNotFailSweep(t *testing.T) {
	pool := naConnectOrSkip(t)
	defer pool.Close()
	ctx := context.Background()

	tenantID := naSeedTenant(t, ctx, pool, "pat819-slack-fail")
	naSeedDeviceWithApp(t, ctx, pool, tenantID, "Fails To Alert App", "TEAMFAIL819", "com.example.fail819")

	counter := naFailingSlack(t)
	notifier := notify.New()

	if err := doDetectNewTenantApps(ctx, pool, tenantID, notifier); err != nil {
		t.Fatalf("doDetectNewTenantApps must not fail when Slack delivery fails: %v", err)
	}
	naWaitForCount(t, counter, 1, 2*time.Second) // delivery was attempted despite the 500

	var count int
	if err := pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenant_new_apps WHERE tenant_id = $1::uuid`, tenantID).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected the tenant_new_apps row to persist despite Slack failure, got %d rows", count)
	}
}
