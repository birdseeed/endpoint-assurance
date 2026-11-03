// Package main is a one-shot, idempotent backfill that envelope-encrypts any
// currently-PLAINTEXT (unmarked) secret values in the columns covered by the
// PAT-687 envelope scheme:
//
//	tenant_credentials.hmac_secret  (BYTEA — active auth secret)
//	tenants.hmac_secret             (BYTEA — legacy auth secret)
//	tenant_ca.ca_key_pem            (TEXT  — per-tenant CA private key)
//	tenant_webhooks.secret          (TEXT  — webhook signing secret)
//
// It requires PATCHED_KEK (so writes are actually encrypted) and DATABASE_URL.
// Values that already carry the envelope Marker are never rewritten, so running
// it twice is a no-op; each such value is instead verify-decrypted with the
// loaded KEK, using the same codec its column's production read path uses. A
// marked value that carries the marker but is not valid ciphertext (corrupt, or
// encrypted under a different KEK) is reported by table, column and row id and
// left byte-identical — never re-encrypted, rewritten or nulled. Verify
// failures do not stop the backfill: unmarked plaintext rows in the same column
// (and every other column) still get backfilled as normal, and the tool exits
// non-zero only at the end, once every column has been processed, naming every
// failing row. Each column's updates run in their own transaction, and
// per-column counts (including verify failures) are reported. Safe to run
// after deploying the KEK-aware binary: existing plaintext rows keep
// authenticating via the read-path fallback until they are backfilled here.
//
// Usage:
//
//	PATCHED_KEK=... DATABASE_URL=... patched-kek-backfill
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/db"
	"patched.im/api/internal/envelope"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if err := run(context.Background(), logger); err != nil {
		logger.Error("backfill failed", "err", err)
		os.Exit(1)
	}
}

// column describes one envelope-covered secret column. bytea reports whether the
// column is BYTEA (vs TEXT); pkCast is the SQL type the primary key is cast to in
// the UPDATE predicate (the PK is always read as text for a uniform scan).
type column struct {
	table  string
	col    string
	pk     string
	pkCast string // "bigint" or "uuid"
	bytea  bool
}

func run(ctx context.Context, logger *slog.Logger) error {
	// The envelope must be ENABLED — a backfill with no KEK would "encrypt" to
	// plaintext, which is pointless and would silently do nothing useful.
	env, err := envelope.FromEnv()
	if err != nil {
		return fmt.Errorf("load %s: %w", envelope.EnvVar, err)
	}
	if !env.Enabled() {
		return fmt.Errorf("%s must be set to a valid KEK to run the backfill", envelope.EnvVar)
	}

	url := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if url == "" {
		return errors.New("DATABASE_URL is empty")
	}
	pool, err := db.Connect(ctx, url)
	if err != nil {
		return fmt.Errorf("db connect: %w", err)
	}
	defer pool.Close()

	columns := []column{
		{table: "tenant_credentials", col: "hmac_secret", pk: "id", pkCast: "bigint", bytea: true},
		{table: "tenants", col: "hmac_secret", pk: "id", pkCast: "uuid", bytea: true},
		{table: "tenant_ca", col: "ca_key_pem", pk: "tenant_id", pkCast: "uuid", bytea: false},
		{table: "tenant_webhooks", col: "secret", pk: "id", pkCast: "uuid", bytea: false},
	}

	var verifyFailed []string
	for _, c := range columns {
		scanned, updated, err := backfillColumn(ctx, pool, env, c)
		var ve *verifyError
		switch {
		case err != nil && errors.As(err, &ve):
			// A verify failure never aborts the run: the column's own writes
			// already committed (see backfillColumn), and the other columns
			// still need scanning. Collected and reported once, at the end.
			verifyFailed = append(verifyFailed, ve.rows...)
		case err != nil:
			return fmt.Errorf("%s.%s: %w", c.table, c.col, err)
		}
		nFailed := 0
		if ve != nil {
			nFailed = len(ve.rows)
		}
		logger.Info("column backfilled",
			"table", c.table, "column", c.col,
			"scanned", scanned, "encrypted", updated, "already_encrypted", scanned-updated,
			"verify_failed", nFailed)
	}

	if len(verifyFailed) > 0 {
		for _, row := range verifyFailed {
			logger.Error("marked value failed verify: not valid ciphertext under the loaded KEK, left untouched", "row", row)
		}
		return fmt.Errorf("verify failed for %d marked row(s), left untouched (see logged rows above): %s",
			len(verifyFailed), strings.Join(verifyFailed, "; "))
	}

	logger.Info("backfill complete")
	return nil
}

// verifyError reports one or more marked values in a column that do not
// actually decrypt under the loaded KEK. It is returned only after that
// column's own writes (backfilling the unmarked/plaintext rows) have already
// committed successfully — a verify failure never blocks, rolls back or
// rewrites anything; it is report-only. Distinguished from other error types
// so run() can keep scanning subsequent columns instead of aborting the
// whole tool on the first bad row.
type verifyError struct {
	rows []string // "table.column id=<pk>", never the value itself
}

func (e *verifyError) Error() string {
	return fmt.Sprintf("%d marked row(s) failed verify: %s", len(e.rows), strings.Join(e.rows, "; "))
}

// verifyMarked attempts to decrypt an already-marked value with the same
// codec its column's production read path uses (internal/auth/bearer.go for
// the two BYTEA hmac_secret columns; internal/handlers/enrolment.go and
// internal/webhook/{store,dispatcher}.go for the TEXT columns), so a value
// verify accepts is exactly one production code would also accept. The
// envelope scheme carries no per-row AAD/context (no tenant id or column name
// bound into the ciphertext — see internal/envelope/envelope.go), so no extra
// context needs to be supplied here to match those call sites.
func verifyMarked(env *envelope.Envelope, c column, val []byte) error {
	if c.bytea {
		_, err := env.DecryptBytes(val)
		return err
	}
	_, err := env.DecryptString(string(val))
	return err
}

// backfillColumn re-encrypts every unmarked value in one column and verifies
// every already-marked value decrypts under the loaded KEK. Returns
// (rowsScanned, rowsEncrypted). The whole column's writes run in a single
// transaction so a mid-run write failure leaves the column untouched; verify
// never participates in that transaction's write path — a marked value is
// never added to the rewrite job list regardless of whether it verifies, so a
// verify failure cannot itself cause (or block) a rewrite. The primary key is
// read as text and cast back in the UPDATE predicate so int and UUID PKs are
// handled alike. A non-nil *verifyError return means the column's writes
// already committed; any other non-nil err means the transaction rolled back.
func backfillColumn(ctx context.Context, pool *pgxpool.Pool, env *envelope.Envelope, c column) (scanned, updated int, err error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	type job struct {
		id  string
		val []byte // raw column bytes (BYTEA bytes, or UTF-8 bytes of TEXT)
	}
	var jobs []job
	var verifyFailed []string

	//nolint:gosec // table/column/pk are hardcoded identifiers, not user input.
	q := fmt.Sprintf(`SELECT %s::text, %s FROM %s`, c.pk, c.col, c.table)
	rows, err := tx.Query(ctx, q)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var id string
		var val []byte
		if err := rows.Scan(&id, &val); err != nil {
			rows.Close()
			return 0, 0, err
		}
		scanned++
		if isEncrypted(val) {
			// Already carries the penc1: marker — never rewritten, only
			// verified. A value that fails verify is reported, not guessed
			// at: it is left exactly as read.
			if verr := verifyMarked(env, c, val); verr != nil {
				verifyFailed = append(verifyFailed, fmt.Sprintf("%s.%s id=%s", c.table, c.col, id))
			}
			continue
		}
		jobs = append(jobs, job{id: id, val: val})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	//nolint:gosec // hardcoded identifiers.
	upd := fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE %s = $2::%s`, c.table, c.col, c.pk, c.pkCast)
	for _, j := range jobs {
		enc, err := encryptForColumn(env, c, j.val)
		if err != nil {
			return 0, 0, fmt.Errorf("encrypt id=%s: %w", j.id, err)
		}
		if _, err := tx.Exec(ctx, upd, enc, j.id); err != nil {
			return 0, 0, fmt.Errorf("update id=%s: %w", j.id, err)
		}
		updated++
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, err
	}
	if len(verifyFailed) > 0 {
		return scanned, updated, &verifyError{rows: verifyFailed}
	}
	return scanned, updated, nil
}

// isEncrypted reports whether a stored value already carries the envelope Marker
// (the ASCII bytes of "penc1:"). Uses the envelope package's Marker constant
// rather than hardcoding the string.
func isEncrypted(val []byte) bool {
	return len(val) >= len(envelope.Marker) && string(val[:len(envelope.Marker)]) == envelope.Marker
}

// encryptForColumn envelope-encrypts one raw column value using the codec that
// matches the column's SQL type: EncryptBytes for BYTEA columns (c.bytea),
// EncryptString for TEXT columns. The returned value is bound directly as the
// SQL parameter in the UPDATE — []byte for BYTEA, string for TEXT — so a
// caller (or test) can distinguish which path ran from the returned type
// alone, not just from c.bytea.
func encryptForColumn(env *envelope.Envelope, c column, val []byte) (any, error) {
	if c.bytea {
		return env.EncryptBytes(val)
	}
	return env.EncryptString(string(val))
}
