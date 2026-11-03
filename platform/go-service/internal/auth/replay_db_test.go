package auth_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"patched.im/api/internal/auth"
)

func replayPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping nonce retention DB test")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnConfig.Host != "127.0.0.1" || !strings.Contains(cfg.ConnConfig.Database, "test") {
		t.Fatal("nonce retention test requires loopback test database")
	}
	const schema = "nonce_retention_test"
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	for _, sql := range []string{"DROP SCHEMA IF EXISTS " + schema + " CASCADE", "CREATE SCHEMA " + schema, "CREATE TABLE seen_nonces (tenant_id uuid NOT NULL, nonce text NOT NULL, seen_at timestamptz NOT NULL, PRIMARY KEY (tenant_id, nonce))"} {
		if _, err := pool.Exec(context.Background(), sql); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	return pool
}

func TestCheckAndStoreNonce_RetainsClockAheadSignedRequest(t *testing.T) {
	pool := replayPool(t)
	ctx := context.Background()
	const tenant = "11111111-1111-1111-1111-111111111111"
	const otherTenant = "22222222-2222-2222-2222-222222222222"
	const skew = 5 * time.Minute
	for _, form := range []string{"v3", "v2"} {
		t.Run(form, func(t *testing.T) {
			nonce := "captured-" + form
			// Simulate receipt 400 seconds ago with the signed clock 200 seconds
			// ahead. The unchanged timestamp is still inside the 300-second window.
			ts := fmt.Sprint(time.Now().Add(-200 * time.Second).Unix())
			secret, body := []byte("retention-test-secret"), []byte(`{"inventory":true}`)
			input := "patched-hmac-v3\nPOST\ninventory\n" + ts + "\n" + nonce + "\n"
			if form == "v2" {
				input = "patched-hmac-v2\n" + ts + "\n" + nonce + "\n"
			}
			mac := hmac.New(sha256.New, secret)
			mac.Write([]byte(input))
			mac.Write(body)
			signature := hex.EncodeToString(mac.Sum(nil))
			if err := auth.ValidateTimestamp(ts, skew); err != nil {
				t.Fatal(err)
			}
			if err := auth.VerifyHMACSigned(secret, "POST", auth.EndpointInventory, ts, nonce, body, signature); err != nil {
				t.Fatal(err)
			}
			if err := auth.CheckAndStoreNonce(ctx, pool, tenant, nonce, skew); err != nil {
				t.Fatal(err)
			}
			if _, err := pool.Exec(ctx, "UPDATE seen_nonces SET seen_at = now() - interval '400 seconds' WHERE tenant_id=$1::uuid AND nonce=$2", tenant, nonce); err != nil {
				t.Fatal(err)
			}
			// A different request must run pruning first: PostgreSQL data-modifying
			// CTEs share a snapshot, so replaying directly could mask early deletion.
			if err := auth.CheckAndStoreNonce(ctx, pool, otherTenant, "prune-"+form, skew); err != nil {
				t.Fatal(err)
			}
			if err := auth.CheckAndStoreNonce(ctx, pool, tenant, nonce, skew); !errors.Is(err, auth.ErrNonceReplay) {
				t.Fatalf("still-valid captured request nonce = %v, want ErrNonceReplay", err)
			}
			// Identical nonce values remain independent between tenants.
			if err := auth.CheckAndStoreNonce(ctx, pool, otherTenant, nonce, skew); err != nil {
				t.Fatal(err)
			}
			if err := auth.CheckAndStoreNonce(ctx, pool, otherTenant, nonce, skew); !errors.Is(err, auth.ErrNonceReplay) {
				t.Fatalf("normal duplicate = %v", err)
			}
			if _, err := pool.Exec(ctx, "UPDATE seen_nonces SET seen_at = now() - interval '601 seconds' WHERE tenant_id=$1::uuid AND nonce=$2", tenant, nonce); err != nil {
				t.Fatal(err)
			}
			if err := auth.CheckAndStoreNonce(ctx, pool, tenant, "expire-"+form, skew); err != nil {
				t.Fatal(err)
			}
			var count int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM seen_nonces WHERE tenant_id=$1::uuid AND nonce=$2", tenant, nonce).Scan(&count); err != nil || count != 0 {
				t.Fatalf("expired nonce count=%d err=%v", count, err)
			}
		})
	}
}

func TestCheckAndStoreNonce_RoundsRetentionUp(t *testing.T) {
	pool := replayPool(t)
	ctx := context.Background()
	const tenant = "11111111-1111-1111-1111-111111111111"
	const skew = 1100 * time.Millisecond
	if err := auth.CheckAndStoreNonce(ctx, pool, tenant, "fractional", skew); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE seen_nonces SET seen_at=now()-interval '2.5 seconds'"); err != nil {
		t.Fatal(err)
	}
	if err := auth.CheckAndStoreNonce(ctx, pool, tenant, "prune-fractional", skew); err != nil {
		t.Fatal(err)
	}
	if err := auth.CheckAndStoreNonce(ctx, pool, tenant, "fractional", skew); !errors.Is(err, auth.ErrNonceReplay) {
		t.Fatalf("rounded retention = %v, want ErrNonceReplay", err)
	}
}

func TestCheckAndStoreNonce_NonpositiveWindowFailsBeforeDB(t *testing.T) {
	for _, skew := range []time.Duration{0, -time.Second} {
		if err := auth.CheckAndStoreNonce(context.Background(), nil, "", "nonce", skew); !errors.Is(err, auth.ErrInvalidReplaySkew) {
			t.Fatalf("skew %v = %v", skew, err)
		}
	}
}
