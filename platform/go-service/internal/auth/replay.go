package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrMissingTimestamp  = errors.New("missing X-Patched-Timestamp header")
	ErrBadTimestamp      = errors.New("X-Patched-Timestamp is not a valid Unix timestamp")
	ErrTimestampSkew     = errors.New("timestamp outside allowed skew window")
	ErrInvalidReplaySkew = errors.New("replay skew must be positive")
	ErrMissingNonce      = errors.New("missing X-Patched-Nonce header")
	ErrNonceReplay       = errors.New("nonce already seen — replay detected")
)

// ValidateTimestamp checks that the Unix-seconds value in tsHeader is within
// ±skew of the current time. Returns one of the Err* sentinel errors on failure.
func ValidateTimestamp(tsHeader string, skew time.Duration) error {
	if tsHeader == "" {
		return ErrMissingTimestamp
	}
	secs, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return ErrBadTimestamp
	}
	diff := time.Since(time.Unix(secs, 0))
	if diff < 0 {
		diff = -diff
	}
	if diff > skew {
		return fmt.Errorf("%w (diff=%v, allowed=±%v)", ErrTimestampSkew, diff.Round(time.Second), skew)
	}
	return nil
}

// CheckAndStoreNonce records the nonce for the given tenant in seen_nonces and
// returns ErrNonceReplay if it has been seen before. Nonces are retained for
// at least twice skew: a clock-ahead request accepted at the future edge of
// the timestamp window can remain valid for another full window after receipt.
//
// The caller must have already called ValidateTimestamp. All callers sharing
// seen_nonces must use the same configured skew, as the production router does,
// because pruning spans tenants. Nonpositive windows fail before any DB work.
func CheckAndStoreNonce(ctx context.Context, pool *pgxpool.Pool, tenantID, nonce string, skew time.Duration) error {
	if nonce == "" {
		return ErrMissingNonce
	}

	if skew <= 0 {
		return ErrInvalidReplaySkew
	}
	// Round upward without doubling the duration (which could overflow).
	retentionSecs := int64(skew/time.Second)*2 + int64((2*(skew%time.Second)+time.Second-1)/time.Second)

	// Prune expired nonces across all tenants, then insert ours.
	// ON CONFLICT DO NOTHING means a replay returns no row → pgx.ErrNoRows.
	var inserted int
	err := pool.QueryRow(ctx, `
		WITH pruned AS (
			DELETE FROM seen_nonces
			WHERE seen_at < now() - make_interval(secs => $3)
		)
		INSERT INTO seen_nonces (tenant_id, nonce, seen_at)
		VALUES ($1::uuid, $2, now())
		ON CONFLICT (tenant_id, nonce) DO NOTHING
		RETURNING 1
	`, tenantID, nonce, retentionSecs).Scan(&inserted)

	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNonceReplay
	}
	if err != nil {
		return fmt.Errorf("nonce store: %w", err)
	}
	return nil
}
