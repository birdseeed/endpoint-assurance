package handlers

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

// dbQuerier is satisfied by both *pgxpool.Pool and pgx.Tx, so a read helper
// can run inside a transaction or against the pool.
//
// PAT-2249: moved here, and renamed from catalogueQuerier, when
// catalogue_review.go was retired with the catalogue review pipeline. Its
// remaining callers are the agent-config reads in agent_config.go.
type dbQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// nilIfEmpty trims s and returns nil for an empty result, so an absent
// optional text value is stored as SQL NULL rather than "".
//
// PAT-2249: moved here unchanged from the retired catalogue_review.go.
func nilIfEmpty(s string) *string {
	if s = strings.TrimSpace(s); s != "" {
		return &s
	}
	return nil
}
