// Package protectedsoftware implements PAT-1801's server-side enforcement:
// a governance disposition action (marking an application "unapproved",
// queuing/targeting a removal, adding an item to a removal campaign's
// scope) must never be able to target security tooling — EDR, MDM agents,
// backup agents, or Patched's own collector.
//
// This package only answers "is this product protected for this tenant".
// It never decides what to do about a match — the caller (each enforcement
// write path) owns rejecting the write and shaping the error response. It
// also never touches CVE correlation or any finding pipeline: protection is
// about disposition, not visibility, and this package has no knowledge of
// device_cve_findings / cve_feed_entries at all.
package protectedsoftware

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Querier is satisfied by both *pgxpool.Pool and pgx.Tx, so Check can run
// inside an existing transaction (matching the FOR UPDATE / lock pattern
// tenant_app_policies' write path already uses) or standalone.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Identity is what a caller knows about the product it is about to act on.
// Not every field needs a value — a row only needs enough to match on.
type Identity struct {
	// TeamID is the macOS Developer Team ID OR the Windows Authenticode
	// signer — tenant_app_policies.team_id already carries both meanings
	// under one column (0032), and this mirrors that.
	TeamID *string
	// BundleID is the macOS CFBundleIdentifier.
	BundleID *string
	// WinPublisher + WinProductCode identify a Windows product by its
	// installed-program Publisher and MSI ProductCode. Both must be set
	// together; either alone is not treated as a strong identifier.
	WinPublisher   *string
	WinProductCode *string
	// ProcessName is the weakest identifier: a process/executable or plain
	// display name, matched case-insensitively against protected_software's
	// process_name and product_name columns (per the ticket, these two are
	// the same fallback tier, not two independent match bases).
	ProcessName *string
	// ProductName is an observed display name, never an executable name. It
	// matches only product_name when no strong identifier is available.
	ProductName *string
}

// hasStrongIdentifier reports whether id carries any of the identifiers that
// must be checked before ever falling back to name matching.
func (id Identity) hasStrongIdentifier() bool {
	return nonEmpty(id.TeamID) || nonEmpty(id.BundleID) ||
		(nonEmpty(id.WinPublisher) && nonEmpty(id.WinProductCode))
}

func nonEmpty(s *string) bool {
	return s != nil && strings.TrimSpace(*s) != ""
}

// Match describes the protected_software row a product matched.
type Match struct {
	ID          int64
	Category    string
	Vendor      string
	ProductName string
	IsBaseline  bool
}

// Check looks up whether id matches a protected_software row for tenantID —
// either the shared baseline (minus any override for this tenant) or the
// tenant's own additions. It returns (nil, nil) when nothing matches: a
// product that fails to match is NOT protected. Fail-closed here means
// "never guess a match", not "assume protection by default" — those are
// opposite failure modes and this package only implements the first.
//
// Matching precedence: team_id/signer, bundle_id, and win_publisher+
// win_product_code are checked first (in one query, any one of them
// matching is sufficient). Only when id carries NONE of those does Check
// fall back to a second query matching ProcessName against process_name OR
// product_name. A strong identifier that fails to match never triggers the
// name fallback — a non-matching bundle_id, for example, is itself evidence
// this is a different product, and falling back to a loose name match at
// that point would risk matching the wrong thing under the same display
// name.
func Check(ctx context.Context, q Querier, tenantID string, id Identity) (*Match, error) {
	if id.hasStrongIdentifier() {
		return checkStrong(ctx, q, tenantID, id)
	}
	if nonEmpty(id.ProcessName) {
		return checkProcessName(ctx, q, tenantID, *id.ProcessName)
	}
	if nonEmpty(id.ProductName) {
		return checkProductName(ctx, q, tenantID, *id.ProductName)
	}
	return nil, nil
}

func checkProductName(ctx context.Context, q Querier, tenantID, name string) (*Match, error) {
	return scanMatch(q.QueryRow(ctx, `
		SELECT ps.id, ps.category, ps.vendor, ps.product_name, (ps.tenant_id IS NULL)
		FROM protected_software ps
		WHERE `+scopeClause+`
		AND lower(ps.product_name) = lower($2::text)
		LIMIT 1
	`, tenantID, name))
}

const scopeClause = `
	(
		(ps.tenant_id IS NULL AND NOT EXISTS (
			SELECT 1 FROM protected_software_overrides o
			WHERE o.baseline_id = ps.id AND o.tenant_id = $1::uuid
		))
		OR ps.tenant_id = $1::uuid
	)
`

func checkStrong(ctx context.Context, q Querier, tenantID string, id Identity) (*Match, error) {
	row := q.QueryRow(ctx, `
		SELECT ps.id, ps.category, ps.vendor, ps.product_name, (ps.tenant_id IS NULL)
		FROM protected_software ps
		WHERE `+scopeClause+`
		AND (
			($2::text IS NOT NULL AND (lower(ps.team_id) = lower($2::text) OR lower(ps.signer) = lower($2::text)))
			OR ($3::text IS NOT NULL AND lower(ps.bundle_id) = lower($3::text))
			OR ($4::text IS NOT NULL AND $5::text IS NOT NULL
			    AND lower(ps.win_publisher) = lower($4::text) AND lower(ps.win_product_code) = lower($5::text))
		)
		LIMIT 1
	`, tenantID, id.TeamID, id.BundleID, id.WinPublisher, id.WinProductCode)
	return scanMatch(row)
}

func checkProcessName(ctx context.Context, q Querier, tenantID, processName string) (*Match, error) {
	row := q.QueryRow(ctx, `
		SELECT ps.id, ps.category, ps.vendor, ps.product_name, (ps.tenant_id IS NULL)
		FROM protected_software ps
		WHERE `+scopeClause+`
		AND (lower(ps.process_name) = lower($2::text) OR lower(ps.product_name) = lower($2::text))
		LIMIT 1
	`, tenantID, processName)
	return scanMatch(row)
}

func scanMatch(row pgx.Row) (*Match, error) {
	var m Match
	if err := row.Scan(&m.ID, &m.Category, &m.Vendor, &m.ProductName, &m.IsBaseline); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return &m, nil
}
