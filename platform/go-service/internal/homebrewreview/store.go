// Package homebrewreview owns the PAT-2046 staff curation model for the
// PAT-2023 Homebrew CPE review queue (homebrew_cpe_review_queue): the global,
// tenant-free backlog of unmapped official-tap formulae and casks that
// internal/cvepipeline's nightly run (recordHomebrewReview) populates.
//
// This is the one path by which a Homebrew curated mapping gets created.
// map and accept-suggestion both insert a curated row into app_cpe_mappings
// (source_type homebrew_formula or homebrew_cask, review_state curated) and
// mark the queue row mapped; dismiss marks it dismissed. Every action is
// audited in homebrew_review_audit with who, when, before and after
// (PAT-1135 actor split: the server-established actor, the caller's
// untrusted claim, the source address).
//
// A curated app_cpe_mappings insert here is picked up automatically by the
// PAT-2045 event path: internal/cvepipeline.SyncMappingSnapshot diffs
// app_cpe_mappings against cve_mapping_snapshot on every drain cycle
// (internal/extractor's drainCVEQueue, run every ingest poll), so the diff
// does not care who or what wrote the row -- a migration, the nightly run's
// own seed, or this admin API. Once a curated Homebrew mapping appears as a
// new row in that diff it is queued as a 'mapping' job, expanded to every
// active device whose current Homebrew list carries the formula or cask
// (activeHomebrewObservations), and matched, all with no new payload and no
// full match required. See internal/cvepipeline/homebrew.go's package
// comment for the full path list.
//
// accept-suggestion refuses a row with metadata_conflict set unless the
// caller passes confirm_conflict: true, matching the caution
// recordHomebrewReview already applies when writing that suggestion: the
// suggestion is endpoint-reported metadata, never itself a mapping, and a
// conflicting report means two devices' receipts disagreed about the
// package's homepage or source URL.
//
// Second trust gate on accept-suggestion (P2, adversarial review of the
// first cut): metadata_conflict only fires when two reports disagree, so a
// single malicious tenant that is the first and only reporter of a rare
// formula can plant a plausible suggested_cpe_key with no conflict ever
// recorded, and staff would accept it estate-wide on one click. Before
// accepting a suggestion, accept-suggestion therefore also counts the
// distinct tenants currently reporting the package (live, from
// homebrew_current_entries, never stored) and refuses with ErrConflict when
// fewer than two report it, unless the caller passes
// confirm_single_reporter: true. This is a second, independently named
// confirmation from confirm_conflict: a row can have zero metadata conflict
// and still rest on one tenant's word alone, and the two audit differently
// distinct risks in the same audit row.
package homebrewreview

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"patched.im/api/internal/cvematch"
)

// Review queue statuses (homebrew_cpe_review_queue.status).
const (
	StatusPending   = "pending"
	StatusMapped    = "mapped"
	StatusDismissed = "dismissed"
)

var (
	// ErrNotFound: no review row with that id.
	ErrNotFound = errors.New("not found")
	// ErrConflict: the row is not in a state the requested action allows, or
	// a live curated mapping already covers this CPE key.
	ErrConflict = errors.New("conflict")
	// ErrInvalidRequest: the request body itself is invalid (missing
	// cpe_vendor/cpe_product, no suggestion on the row, malformed key).
	ErrInvalidRequest = errors.New("invalid request")
	// ErrUnknownCPEKey: the vendor:product key does not exist in the local
	// NVD store (cve_feed_entries.cpe_patterns), so it cannot be curated.
	ErrUnknownCPEKey = errors.New("unknown cpe key")
)

// Actor is the audit attribution for one admin write (PAT-1135 split: the
// server-established actor, the caller's untrusted claim, the source addr).
type Actor struct {
	Actor      string
	Claimed    *string
	SourceAddr *string
}

// DB is the subset of pgx shared by a pool and a transaction.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ReviewRow is one homebrew_cpe_review_queue row, plus its estate prevalence
// (the count of devices, across every tenant, whose current Homebrew list
// carries this formula or cask). No tenant or device identifier is ever
// part of this type: the queue is global, and the prevalence figure is an
// aggregate count, not evidence tied to any one estate.
type ReviewRow struct {
	ID                    int64      `json:"id"`
	PackageKind           string     `json:"package_kind"`
	Name                  string     `json:"name"`
	Homepage              *string    `json:"homepage"`
	SourceURL             *string    `json:"source_url"`
	Status                string     `json:"status"`
	SuggestedCPEKey       *string    `json:"suggested_cpe_key"`
	MetadataConflict      bool       `json:"metadata_conflict"`
	MetadataConflictCount int        `json:"metadata_conflict_count"`
	FirstSeenAt           time.Time  `json:"first_seen_at"`
	LastSeenAt            time.Time  `json:"last_seen_at"`
	ResolvedAt            *time.Time `json:"resolved_at"`
	EstatePrevalence      int        `json:"estate_prevalence"`
	// ReportingTenantCount is the count of distinct tenants, live at query
	// time, currently reporting this formula or cask. Only List populates
	// it (zero otherwise), same as EstatePrevalence. Never a tenant
	// identifier itself, only a count.
	ReportingTenantCount int `json:"reporting_tenant_count"`
}

// mapOutcome is the after-snapshot audited for map and accept_suggestion: the
// updated queue row, the curated mapping it created, and which explicit
// confirmations (if any) the caller supplied to get past a trust gate.
type mapOutcome struct {
	Review                  ReviewRow `json:"review"`
	MappingID               int64     `json:"mapping_id"`
	CPEVendor               string    `json:"cpe_vendor"`
	CPEProduct              string    `json:"cpe_product"`
	SourceType              string    `json:"source_type"`
	ConfirmedConflict       bool      `json:"confirmed_conflict"`
	ConfirmedSingleReporter bool      `json:"confirmed_single_reporter"`
}

const reviewColumns = `id, package_kind, name, homepage, source_url, status, suggested_cpe_key,
	metadata_conflict, metadata_conflict_count, first_seen_at, last_seen_at, resolved_at`

// reviewColumnsQualified is reviewColumns with the r. prefix List's query
// needs: its LEFT JOIN subquery also projects package_kind and name, so the
// unqualified names in reviewColumns are ambiguous there.
const reviewColumnsQualified = `r.id, r.package_kind, r.name, r.homepage, r.source_url, r.status, r.suggested_cpe_key,
	r.metadata_conflict, r.metadata_conflict_count, r.first_seen_at, r.last_seen_at, r.resolved_at`

func scanReviewRow(row pgx.Row) (ReviewRow, error) {
	var r ReviewRow
	err := row.Scan(&r.ID, &r.PackageKind, &r.Name, &r.Homepage, &r.SourceURL, &r.Status,
		&r.SuggestedCPEKey, &r.MetadataConflict, &r.MetadataConflictCount,
		&r.FirstSeenAt, &r.LastSeenAt, &r.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReviewRow{}, ErrNotFound
	}
	return r, err
}

// ListFilter narrows and orders List.
type ListFilter struct {
	// Status: "", "pending", "mapped" or "dismissed". Empty means every
	// status.
	Status string
	// Kind: "", "formula" or "cask". Empty means both.
	Kind string
	// Sort: "prevalence" (highest estate prevalence first) or "" / "recent"
	// (most recently seen first, the default).
	Sort string
}

// List returns the review queue, each row carrying its estate prevalence
// (the count of devices, across every tenant, whose current Homebrew list
// carries that formula or cask today) and its reporting tenant count (the
// count of distinct tenants behind those devices). Both are computed live
// from homebrew_current_entries on every call, never stored on the queue
// row. Never returns a tenant or device identifier.
func List(ctx context.Context, db DB, filter ListFilter) ([]ReviewRow, error) {
	rows, err := db.Query(ctx, `
		SELECT `+reviewColumnsQualified+`, COALESCE(p.prevalence, 0) AS estate_prevalence,
		       COALESCE(p.reporting_tenants, 0) AS reporting_tenant_count
		FROM homebrew_cpe_review_queue r
		LEFT JOIN (
			SELECT package_kind, lower(btrim(name)) AS name,
			       count(DISTINCT device_id) AS prevalence,
			       count(DISTINCT tenant_id) AS reporting_tenants
			FROM homebrew_current_entries
			WHERE package_kind IN ('formula', 'cask')
			GROUP BY package_kind, lower(btrim(name))
		) p ON p.package_kind = r.package_kind AND p.name = lower(btrim(r.name))
		WHERE ($1 = '' OR r.status = $1) AND ($2 = '' OR r.package_kind = $2)
		ORDER BY
			(CASE WHEN $3 = 'prevalence' THEN COALESCE(p.prevalence, 0) END) DESC NULLS LAST,
			(CASE WHEN $3 = 'prevalence' THEN NULL ELSE r.last_seen_at END) DESC NULLS LAST,
			r.id DESC
	`, filter.Status, filter.Kind, filter.Sort)
	if err != nil {
		return nil, fmt.Errorf("list homebrew review queue: %w", err)
	}
	defer rows.Close()
	out := []ReviewRow{}
	for rows.Next() {
		var r ReviewRow
		if err := rows.Scan(&r.ID, &r.PackageKind, &r.Name, &r.Homepage, &r.SourceURL, &r.Status,
			&r.SuggestedCPEKey, &r.MetadataConflict, &r.MetadataConflictCount,
			&r.FirstSeenAt, &r.LastSeenAt, &r.ResolvedAt, &r.EstatePrevalence, &r.ReportingTenantCount); err != nil {
			return nil, fmt.Errorf("scan homebrew review row: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// reportingTenantCount counts the distinct tenants, live at query time,
// whose current Homebrew list carries this formula or cask. Same source and
// join key as List's own reporting_tenant_count column; kept as a single-row
// query here because AcceptSuggestion needs it inside its write transaction,
// gated on one specific row, not the whole listing.
func reportingTenantCount(ctx context.Context, db DB, packageKind, name string) (int, error) {
	var n int
	if err := db.QueryRow(ctx, `
		SELECT count(DISTINCT tenant_id) FROM homebrew_current_entries
		WHERE package_kind = $1 AND lower(btrim(name)) = lower(btrim($2))
	`, packageKind, name).Scan(&n); err != nil {
		return 0, fmt.Errorf("count reporting tenants for %s %s: %w", packageKind, name, err)
	}
	return n, nil
}

func lockReview(ctx context.Context, tx pgx.Tx, id int64) (ReviewRow, error) {
	return scanReviewRow(tx.QueryRow(ctx, `SELECT `+reviewColumns+` FROM homebrew_cpe_review_queue WHERE id = $1 FOR UPDATE`, id))
}

func mapWriteErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: a curated mapping for this package and CPE key already exists", ErrConflict)
	}
	return err
}

func writeAudit(ctx context.Context, tx pgx.Tx, reviewID int64, action string, actor Actor, before, after any) error {
	var beforeJSON []byte
	if before != nil {
		b, err := json.Marshal(before)
		if err != nil {
			return err
		}
		beforeJSON = b
	}
	afterJSON, err := json.Marshal(after)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO homebrew_review_audit
			(review_id, action, actor, claimed_actor, source_addr, before, after)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb)
	`, reviewID, action, actor.Actor, actor.Claimed, actor.SourceAddr, nullJSON(beforeJSON), string(afterJSON)); err != nil {
		return fmt.Errorf("write homebrew review audit: %w", err)
	}
	return nil
}

func nullJSON(b []byte) any {
	if b == nil {
		return nil
	}
	return string(b)
}

// sourceTypeFor returns the app_cpe_mappings.source_type for a review row's
// package kind.
func sourceTypeFor(packageKind string) string {
	if packageKind == "cask" {
		return cvematch.HomebrewCaskSource
	}
	return cvematch.HomebrewFormulaSource
}

// cpeKeyKnown reports whether vendor:product exists in the local NVD store,
// the same existence check internal/cvepipeline's recordHomebrewReview uses
// to decide whether a candidate key is safe to surface as a suggestion.
func cpeKeyKnown(ctx context.Context, db DB, vendor, product string) (bool, error) {
	key := vendor + ":" + product
	var known bool
	if err := db.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM cve_feed_entries WHERE cpe_patterns @> ARRAY[$1::text])
	`, key).Scan(&known); err != nil {
		return false, fmt.Errorf("check cpe key %s: %w", key, err)
	}
	return known, nil
}

// minReportingTenants is the floor accept-suggestion enforces before
// treating a suggestion as safe to accept without explicit confirmation
// (P2): below this, the suggestion could rest on a single tenant's
// self-reported metadata alone.
const minReportingTenants = 2

// validCPEComponent reports whether s is non-empty and free of ':' and
// whitespace, the same shape HomebrewSuggestionCandidates already requires
// of a candidate vendor or product before it is ever offered as a
// suggestion (P3): a colon would be parsed back as a field separator, and
// whitespace has no place in an NVD CPE vendor or product token.
func validCPEComponent(s string) bool {
	if s == "" {
		return false
	}
	return !strings.ContainsAny(s, ": \t\n\r\f\v")
}

// applyMapping validates vendor/product against the local CVE store, inserts
// the curated app_cpe_mappings row, marks the queue row mapped and audits
// the whole thing in one transaction. Shared by Map and AcceptSuggestion;
// confirmedConflict/confirmedSingleReporter are recorded in the audit row
// exactly as the caller supplied them (both false from Map, which has no
// such gates of its own).
func applyMapping(ctx context.Context, tx pgx.Tx, before ReviewRow, vendor, product string, actor Actor, action string, confirmedConflict, confirmedSingleReporter bool) (ReviewRow, error) {
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	product = strings.ToLower(strings.TrimSpace(product))
	if !validCPEComponent(vendor) || !validCPEComponent(product) {
		return ReviewRow{}, fmt.Errorf("%w: cpe_vendor and cpe_product must be non-empty and contain no ':' or whitespace", ErrInvalidRequest)
	}
	known, err := cpeKeyKnown(ctx, tx, vendor, product)
	if err != nil {
		return ReviewRow{}, err
	}
	if !known {
		return ReviewRow{}, fmt.Errorf("%w: %s:%s is not a known CPE key in the CVE store", ErrUnknownCPEKey, vendor, product)
	}
	sourceType := sourceTypeFor(before.PackageKind)
	var mappingID int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO app_cpe_mappings (platform, match_name, cpe_vendor, cpe_product, notes, source_type, review_state)
		VALUES ('macos', $1, $2, $3, $4, $5, 'curated')
		RETURNING id
	`, before.Name, vendor, product, "PAT-2046 review queue: "+action, sourceType).Scan(&mappingID); err != nil {
		return ReviewRow{}, mapWriteErr(err)
	}
	after, err := scanReviewRow(tx.QueryRow(ctx, `
		UPDATE homebrew_cpe_review_queue SET status = 'mapped', resolved_at = now()
		WHERE id = $1 RETURNING `+reviewColumns, before.ID))
	if err != nil {
		return ReviewRow{}, err
	}
	if err := writeAudit(ctx, tx, before.ID, action, actor, before,
		mapOutcome{Review: after, MappingID: mappingID, CPEVendor: vendor, CPEProduct: product, SourceType: sourceType,
			ConfirmedConflict: confirmedConflict, ConfirmedSingleReporter: confirmedSingleReporter}); err != nil {
		return ReviewRow{}, err
	}
	return after, nil
}

// Map curates cpe_vendor/cpe_product directly onto a pending review row: it
// inserts the curated app_cpe_mappings row and marks the queue row mapped.
// The only path by which a Homebrew mapping gets created. 409 if the row is
// not pending; 400 if the key is missing, contains ':' or whitespace, or is
// otherwise malformed; 400 (ErrUnknownCPEKey) if the key has no presence in
// the local NVD store. Map is a human directly typing both halves of the
// key, so it carries neither of accept-suggestion's confirmation gates.
func Map(ctx context.Context, tx pgx.Tx, id int64, cpeVendor, cpeProduct string, actor Actor) (ReviewRow, error) {
	row, err := lockReview(ctx, tx, id)
	if err != nil {
		return ReviewRow{}, err
	}
	if row.Status != StatusPending {
		return ReviewRow{}, fmt.Errorf("%w: review row is %s, not pending", ErrConflict, row.Status)
	}
	return applyMapping(ctx, tx, row, cpeVendor, cpeProduct, actor, "map", false, false)
}

// AcceptSuggestion curates the row's own suggested_cpe_key. Two independent
// trust gates, both refusing with ErrConflict unless explicitly overridden:
//
//   - confirmConflict, when the row has metadata_conflict set: at least one
//     other report disagreed with the first-seen homepage or source URL the
//     suggestion rests on.
//   - confirmSingleReporter, when fewer than minReportingTenants distinct
//     tenants currently report the package (counted live, P2): with no
//     conflict ever recorded, a single tenant could still be the only voice
//     behind the suggestion, whether or not it is acting in good faith.
//
// Both confirmations are independent of each other and are recorded in the
// audit row as given. ErrInvalidRequest when there is no suggestion to
// accept, or it is malformed.
func AcceptSuggestion(ctx context.Context, tx pgx.Tx, id int64, confirmConflict, confirmSingleReporter bool, actor Actor) (ReviewRow, error) {
	row, err := lockReview(ctx, tx, id)
	if err != nil {
		return ReviewRow{}, err
	}
	if row.Status != StatusPending {
		return ReviewRow{}, fmt.Errorf("%w: review row is %s, not pending", ErrConflict, row.Status)
	}
	if row.SuggestedCPEKey == nil || strings.TrimSpace(*row.SuggestedCPEKey) == "" {
		return ReviewRow{}, fmt.Errorf("%w: this row has no suggested CPE key", ErrInvalidRequest)
	}
	if row.MetadataConflict && !confirmConflict {
		return ReviewRow{}, fmt.Errorf("%w: this row's metadata is contested; resend with confirm_conflict true to accept the suggestion anyway", ErrConflict)
	}
	tenants, err := reportingTenantCount(ctx, tx, row.PackageKind, row.Name)
	if err != nil {
		return ReviewRow{}, err
	}
	if tenants < minReportingTenants && !confirmSingleReporter {
		return ReviewRow{}, fmt.Errorf("%w: only %d tenant(s) currently report this package; resend with confirm_single_reporter true to accept the suggestion anyway", ErrConflict, tenants)
	}
	vendor, product, ok := strings.Cut(*row.SuggestedCPEKey, ":")
	if !ok || strings.TrimSpace(vendor) == "" || strings.TrimSpace(product) == "" {
		return ReviewRow{}, fmt.Errorf("%w: malformed suggested CPE key %q", ErrInvalidRequest, *row.SuggestedCPEKey)
	}
	return applyMapping(ctx, tx, row, vendor, product, actor, "accept_suggestion", confirmConflict, confirmSingleReporter)
}

// Dismiss marks a pending row dismissed and audits it. 409 if the row is not
// pending.
func Dismiss(ctx context.Context, tx pgx.Tx, id int64, actor Actor) (ReviewRow, error) {
	before, err := lockReview(ctx, tx, id)
	if err != nil {
		return ReviewRow{}, err
	}
	if before.Status != StatusPending {
		return ReviewRow{}, fmt.Errorf("%w: review row is %s, not pending", ErrConflict, before.Status)
	}
	after, err := scanReviewRow(tx.QueryRow(ctx, `
		UPDATE homebrew_cpe_review_queue SET status = 'dismissed', resolved_at = now()
		WHERE id = $1 RETURNING `+reviewColumns, id))
	if err != nil {
		return ReviewRow{}, err
	}
	if err := writeAudit(ctx, tx, id, "dismiss", actor, before, after); err != nil {
		return ReviewRow{}, err
	}
	return after, nil
}

// RetryDeadlock runs fn and, if it fails with a PostgreSQL deadlock
// (SQLSTATE 40P01), runs it once more. Every write here is safe to repeat:
// map/accept-suggestion fail as a conflict on a second attempt against an
// already-mapped row, and dismiss is likewise idempotent-by-conflict.
func RetryDeadlock(fn func() error) error {
	err := fn()
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "40P01" {
		return fn()
	}
	return err
}
