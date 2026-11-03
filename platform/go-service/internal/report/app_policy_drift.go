package report

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AppPolicyRow holds one app policy and its device match count.
//
// EvidenceBasis (PAT-1725) says how the aggregated device_apps matches for
// this row were tied to the policy, using the vocabulary documented in
// contracts/portal-api.md:
//   - "identifier_match" — every matched device tied through bundle_id or
//     team_id (a real identifier), never through name alone.
//   - "name_match_only" — at least one matched device was tied only by
//     lower(name) = lower(tap.name). A row is only as strong as its weakest
//     instance: one name-only match downgrades the whole row.
//   - "unknown" — no device matched at all (DevicesWithApp == 0); there is
//     no evidence to grade.
//
// This is identity evidence, not version evidence — do not read
// "identifier_match" as "the installed version was confirmed".
type AppPolicyRow struct {
	AppName string
	Policy  string
	// Platform (PAT-1727) is the tenant_app_policies.platform value this row
	// was configured with: "macos", "windows" or "any". Added to the
	// GROUP BY below alongside the other identity columns so two policies
	// differing only by platform (same name/bundle_id/team_id/policy/tier,
	// one scoped macos, one windows) are never collapsed into a single row —
	// they are distinct configured policies with independent device counts.
	Platform        string
	EnforcementTier string
	DevicesWithApp  int
	EvidenceBasis   string
	// IdentifierMatchedCount is the distinct-device count where at least
	// one matching device_apps row tied to this policy via bundle_id or
	// team_id (a real identifier).
	IdentifierMatchedCount int
	// NameMatchedCount is derived, not independently queried:
	// DevicesWithApp - IdentifierMatchedCount. Every device counted in
	// DevicesWithApp matched at least one of the OR conditions in the join
	// below, and IdentifierMatchedCount already counts a device if ANY of
	// its rows matched by identifier — so the remainder is exactly the
	// devices whose every matching row was name-only. See the query
	// comment above FetchAppPolicyDriftReport's SELECT for why this can't
	// be a second per-row SQL FILTER without double-counting a device that
	// has both an identifier-matched row and a separate name-only row.
	NameMatchedCount int
	// VersionCount (PAT-1799) is the exact distinct-version count across
	// every matched device_apps row for this policy — "N devices on M
	// versions" for the portal. 0 when DevicesWithApp is 0.
	VersionCount int
	// TeamID / SignedBy / Notarized (PAT-1799) are the macOS codesign
	// signing state observed on matched devices — nil means "unknown", not
	// "unsigned"/"not notarized". Deliberately computed from macOS-matched
	// devices only: device_apps.team_id/signer/notarized are macOS
	// codesign concepts, and the current Windows collector never populates
	// them (device_apps.notarized in particular defaults to a literal
	// `false` when a Windows payload omits the field — see
	// internal/extractor/upsert.go — which would misread as a real
	// "not notarized" verdict if surfaced here). Restricting the
	// aggregation to matched non-Windows devices avoids ever reporting a
	// false negative for a platform that never signs the same way; a
	// windows-only or windows-matched-only policy always reads nil/unknown
	// for all three fields.
	TeamID    *string
	SignedBy  *string
	Notarized *bool
	// PolicyUpdatedAt (PAT-1800) is tenant_app_policies.updated_at for this
	// row: NOT NULL, DEFAULT now() at insert, so every policy row carries a
	// real timestamp for when its policy state was last set (creation counts
	// as "last set" for a row nobody has edited since). Used as the portal's
	// decided_at for policy rows.
	PolicyUpdatedAt time.Time
	// PolicyNotes (PAT-1800) is tenant_app_policies.notes verbatim: NOT NULL
	// DEFAULT ''. Empty string means no justification was recorded, not "a
	// blank justification" — callers must treat "" as absent (nil), never
	// display it as a real value. There is deliberately no PolicyDecidedBy
	// field: tenant_app_policies (0032) has no actor column at all, unlike
	// tenant_extension_policies (0071, approved_by) — nobody is recorded as
	// having made this decision, so the portal's decided_by is always nil
	// for a policy row. See contracts/portal-api.md's PAT-1800 scope note.
	PolicyNotes string
	// IdentityBundleID / IdentityTeamID / IdentityWingetID / IdentityHasName
	// (PAT-2104) are this row's RAW tenant_app_policies identity columns,
	// not the aggregated observed-signing evidence TeamID/SignedBy above.
	// portal_applications.go uses them, together with Platform, to derive
	// PortalApplication's Identifier/PolicyTeamID/ProductKey: the exact
	// values PUT /v1/portal/software-approvals' currentAppDecision needs to
	// find this same row again. Never confuse these with TeamID/SignedBy
	// above: a bundle-only policy (IdentityTeamID nil) can still show a
	// non-nil observed TeamID, because TeamID is signing evidence seen on
	// matched devices, not this row's own team_id column.
	IdentityBundleID *string
	IdentityTeamID   *string
	IdentityWingetID *string
	IdentityHasName  bool
}

// AppPolicyDriftReport contains the app policy drift data for a tenant.
type AppPolicyDriftReport struct {
	GeneratedAt time.Time
	Tenant      string
	Policies    []AppPolicyRow
}

// FetchAppPolicyDriftReport fetches app policy drift data for a tenant.
// If the tenant_app_policies table does not exist, returns empty data without error.
func FetchAppPolicyDriftReport(ctx context.Context, pool *pgxpool.Pool, tenantID string) (AppPolicyDriftReport, error) {
	var r AppPolicyDriftReport
	r.GeneratedAt = time.Now().UTC()

	err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id = $1`, tenantID).Scan(&r.Tenant)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrTenantNotFound
		}
		return r, fmt.Errorf("fetch tenant: %w", err)
	}

	// PAT-729 review found two correctness bugs in this query, both fixed
	// here:
	//
	//  1. Cross-tenant leak: device_apps is now joined AFTER devices is
	//     scoped to this tenant (dv), matched to da.device_id — NOT the
	//     other way around. The previous form joined device_apps directly
	//     on name/bundle_id/team_id with no tenant scoping at all, then
	//     joined devices only as an unused decoration (its columns were
	//     never selected or filtered on), so any device belonging to ANY
	//     tenant with a same-named/bundle_id/team_id app silently inflated
	//     (or fabricated) devices_with_app for this tenant — invisible
	//     until this became a customer-facing count instead of a
	//     staff-only one.
	//  2. Missing platform scoping: a policy row's platform (macos|
	//     windows|any) was never checked against the matched device's OS,
	//     unlike the equivalent per-device drift handler
	//     (TenantAppPolicyDriftHandler's policyPlatformMatches), so a
	//     windows-only policy could pick up a same-named macOS app and
	//     vice versa. Folded into the devices join below.
	// identifier_matched (PAT-1725): a device counts here if ANY of its
	// matching device_apps rows tied to this policy through bundle_id or
	// team_id — a real identifier, per software_inventory.go's own
	// identifier-vs-name distinction. This FILTER is per-row, but
	// COUNT(DISTINCT da.device_id) collapses it to "this device had at
	// least one identifier-matched row", which is exactly the semantics
	// wanted: a device is identifier-matched if ANY of its rows matched
	// that way, regardless of how many other rows it also has.
	//
	// name_matched_devices is deliberately NOT a second FILTER here. An
	// earlier version tried "matched by name AND NOT matched by
	// identifier" per row, but that condition is evaluated per ROW, not
	// per DEVICE: a device with two device_apps rows — one matched only by
	// bundle_id, one matched only by name — would satisfy the identifier
	// FILTER (via row 1) AND the per-row name-minus-identifier FILTER (via
	// row 2, which itself has no identifier match), double-counting the
	// same device in both buckets. Deriving it in Go instead
	// (devices_with_app - identifier_matched, see below the scan) is
	// correct by construction: every matched device is counted exactly
	// once in devices_with_app, and identifier_matched is already a
	// correct per-device count, so the remainder is exactly the devices
	// with zero identifier-matched rows — i.e. tied only by name.
	rows, err := pool.Query(ctx, `
		SELECT COALESCE(tap.name, tap.bundle_id, tap.team_id, '—'),
		       tap.policy, tap.enforcement_tier, tap.platform,
		       tap.updated_at, tap.notes,
		       tap.bundle_id, tap.team_id, tap.winget_id, (tap.name IS NOT NULL),
		       COUNT(DISTINCT da.device_id)::int AS devices_with_app,
		       COUNT(DISTINCT da.device_id) FILTER (
		           WHERE (tap.bundle_id IS NOT NULL AND da.identifier = tap.bundle_id)
		              OR (tap.team_id IS NOT NULL AND da.team_id = tap.team_id)
		       )::int AS identifier_matched,
		       COUNT(DISTINCT da.version) FILTER (WHERE da.version IS NOT NULL)::int AS version_count,
		       MAX(da.team_id) FILTER (WHERE NOT (dv.os ILIKE 'windows%')) AS team_id,
		       MAX(da.signer) FILTER (WHERE NOT (dv.os ILIKE 'windows%')) AS signed_by,
		       COALESCE(BOOL_OR(da.notarized) FILTER (
		           WHERE NOT (dv.os ILIKE 'windows%') AND da.notarized IS NOT NULL
		       ), false) AS notarized_true,
		       COALESCE(BOOL_OR(da.notarized IS FALSE) FILTER (
		           WHERE NOT (dv.os ILIKE 'windows%') AND da.notarized IS NOT NULL
		       ), false) AS notarized_false
		FROM effective_tenant_app_policies($1::uuid) tap
		LEFT JOIN devices dv ON dv.tenant_id = tap.tenant_id
		    AND (tap.platform = 'any' OR lower(dv.os) = tap.platform)
		LEFT JOIN device_apps da ON da.device_id = dv.id AND (
		    (tap.name IS NOT NULL AND lower(da.name) = lower(tap.name))
		    OR (tap.bundle_id IS NOT NULL AND da.identifier = tap.bundle_id)
		    OR (tap.team_id IS NOT NULL AND da.team_id = tap.team_id)
		)
		WHERE tap.tenant_id = $1
		GROUP BY tap.name, tap.bundle_id, tap.team_id, tap.winget_id, tap.policy, tap.enforcement_tier,
		         tap.platform, tap.updated_at, tap.notes
		ORDER BY tap.policy, COALESCE(tap.name, tap.bundle_id, tap.team_id)
	`, tenantID)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return r, nil
		}
		return r, fmt.Errorf("fetch app policy drift: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var row AppPolicyRow
		var notarizedTrue, notarizedFalse bool
		if err := rows.Scan(&row.AppName, &row.Policy, &row.EnforcementTier, &row.Platform,
			&row.PolicyUpdatedAt, &row.PolicyNotes,
			&row.IdentityBundleID, &row.IdentityTeamID, &row.IdentityWingetID, &row.IdentityHasName,
			&row.DevicesWithApp, &row.IdentifierMatchedCount, &row.VersionCount,
			&row.TeamID, &row.SignedBy, &notarizedTrue, &notarizedFalse); err != nil {
			return r, fmt.Errorf("scan app policy row: %w", err)
		}
		row.NameMatchedCount = row.DevicesWithApp - row.IdentifierMatchedCount
		row.EvidenceBasis = appPolicyEvidenceBasis(row.DevicesWithApp, row.IdentifierMatchedCount)
		row.Notarized = notarizedTriState(notarizedTrue, notarizedFalse)
		r.Policies = append(r.Policies, row)
	}
	return r, rows.Err()
}

// notarizedTriState derives a *bool from the two BOOL_OR aggregates the
// FetchAppPolicyDriftReport/portalApplicationsUndecidedQuery queries
// compute (see their doc comments): notarizedTrue is true when at least one
// matched non-Windows device reported notarized=true, notarizedFalse when
// at least one reported notarized=false. Both false means no matched
// non-Windows device carried a non-NULL notarized signal at all — unknown,
// not "not notarized" (root AGENTS.md: absence requires authority). "true"
// wins over "false" when a policy/group spans devices that disagree, same
// worst-case-first convention as PortalExtension.RiskLevel's BOOL_OR, but
// inverted: here the fielded evidence outranks its absence, so a single
// confirmed-notarized instance is reported rather than averaged away.
func notarizedTriState(notarizedTrue, notarizedFalse bool) *bool {
	switch {
	case notarizedTrue:
		v := true
		return &v
	case notarizedFalse:
		v := false
		return &v
	default:
		return nil
	}
}

// appPolicyEvidenceBasis implements the PAT-1725 weakest-instance rule:
// a row is only as strong as its worst-evidenced matched device.
func appPolicyEvidenceBasis(devicesWithApp, identifierMatched int) string {
	switch {
	case devicesWithApp == 0:
		return "unknown"
	case identifierMatched == devicesWithApp:
		return "identifier_match"
	default:
		return "name_match_only"
	}
}
