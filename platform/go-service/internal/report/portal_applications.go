// GET /v1/portal/applications (PAT-1727). Extends the existing
// GET /v1/portal/unapproved-apps aggregation (which is left unchanged — the
// live portal still consumes it) so the portal can also show approved and
// undecided applications, in the same single table as extensions.
package report

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/softwaregov"
)

// Abuse-resistance caps for the undecided-application half of this endpoint,
// mirroring the pattern established in portal_extensions.go: undecided rows
// are grouped directly from tenant-controlled device_apps content, so the
// same argument applies — cap before aggregation, truncate tenant-controlled
// text only in the final projection, and fail closed if the tenant's raw row
// count is too large to safely group.
//
// Policy rows (from tenant_app_policies, via FetchAppPolicyDriftReport) are
// NOT subject to these caps: they are grouped by admin-configured policy
// identity, whose cardinality is bounded by how many policies an operator
// has created, not by customer-controlled device_apps volume.
const (
	// portalApplicationsMaxUndecidedRows caps how many undecided-application
	// groups one response carries, ordered by device_count descending so the
	// cap bites the least-widespread tail.
	portalApplicationsMaxUndecidedRows = 500
	// portalApplicationsMaxNameLen / portalApplicationsMaxIdentifierLen
	// bound the emitted tenant-controlled text fields — same convention and
	// same lengths as portalExtensionsMaxNameLen / portalExtensionsMaxIDLen
	// in portal_extensions.go, applied with SQL LEFT() strictly in the final
	// output projection, never on the GROUP BY/join keys.
	portalApplicationsMaxNameLen       = 256
	portalApplicationsMaxIdentifierLen = 128
)

// portalApplicationsMaxSourceRows fails the undecided-application
// aggregation closed, before any GROUP BY, if the tenant's raw (ungrouped)
// device_apps row count exceeds this. Unlike device_browser_extensions,
// device_apps rows ARE pruned per device on every ingest (the stale-row
// DELETE in internal/extractor/upsert.go), so this table does not share the
// PAT-933 unbounded-lifetime-growth problem — but a tenant's raw row count
// still scales with device count x installed-app count, both of which a
// large legitimate estate can push high, so the same defence-in-depth guard
// applies. var, not const, so tests can lower it without seeding hundreds of
// thousands of rows — see SetPortalApplicationsMaxSourceRowsForTest.
var portalApplicationsMaxSourceRows = 100_000

// SetPortalApplicationsMaxSourceRowsForTest overrides
// portalApplicationsMaxSourceRows and returns a func that restores the
// original value. Test-only, exported for the integration test package —
// same convention as SetPortalExtensionsMaxSourceRowsForTest.
func SetPortalApplicationsMaxSourceRowsForTest(n int) (restore func()) {
	orig := portalApplicationsMaxSourceRows
	portalApplicationsMaxSourceRows = n
	return func() { portalApplicationsMaxSourceRows = orig }
}

// PortalApplicationRemovalStateNotAvailable mirrors
// PortalAppRemovalStateNotAvailable (portal.go) for every row this endpoint
// emits, policy and undecided alike: PAT-1598's authorised-removal campaign
// records carry no delivery pathway and do not feed this endpoint.
const PortalApplicationRemovalStateNotAvailable = PortalAppRemovalStateNotAvailable

// PortalApplicationUndecided is the PolicyState value for an installed
// application matching no tenant_app_policies row under the
// FetchAppPolicyDriftReport matching rules. Distinct from every persisted
// tenant_app_policies.policy value (mandatory/approved/unapproved/unmanaged)
// so the portal can never confuse "nobody has decided" with "approved".
const PortalApplicationUndecided = "undecided"

// PortalApplication is one row for GET /v1/portal/applications: either a
// tenant_app_policies-backed policy row (PolicyState is the persisted policy
// value) or an undecided installed application matching no policy row
// (PolicyState is PortalApplicationUndecided).
type PortalApplication struct {
	Name string
	// Identifier is the device_apps.identifier this row was grouped by, for
	// an undecided row grouped by identifier (EvidenceBasis
	// "identifier_match"). For a policy row (PAT-2104) it is instead
	// tenant_app_policies.bundle_id, but ONLY when this exact row can be
	// addressed again through PUT /v1/portal/software-approvals: see
	// PolicyTeamID/ProductKey below and policyRoundTripIdentity's doc
	// comment for the addressability rule. "" whenever no such identity is
	// available — a name-only row, an undecided row grouped by name only, or
	// a policy row PUT cannot address.
	Identifier string
	// PolicyTeamID (PAT-2104, policy rows only) is this row's OWN
	// tenant_app_policies.team_id, normalised the same way the write path
	// stores it (upper, trimmed), set only when Identifier is also set. This
	// is deliberately a different field from TeamID below: TeamID is signing
	// evidence OBSERVED on matched devices (may be non-nil even when this
	// policy carries no team_id at all, e.g. a bundle-only policy on
	// genuinely signed software), while PolicyTeamID is the policy's own
	// identity column — the value PUT /v1/portal/software-approvals'
	// currentAppDecision keys on. Sending TeamID back on a write would
	// target the wrong row (or fabricate a new one) whenever the two
	// diverge; PolicyTeamID never does. nil on Windows, per PAT-2007's rule
	// that Windows items carry no team_id, and nil whenever the row cannot
	// be round-tripped through the write schema.
	PolicyTeamID *string
	// ProductKey (PAT-2104, policy rows only) is exactly the key PAT-2007's
	// write path computes for this identity (softwaregov.ApplicationKey),
	// so a client already holding a product_key from a write response can
	// match it against a row read here. nil under the same conditions as
	// Identifier/PolicyTeamID.
	ProductKey *string
	// Platform is "macos", "windows" or "any". "any" only occurs on policy
	// rows (a tenant_app_policies row scoped to both platforms) — an
	// undecided row is always grouped from one real device's OS, so it is
	// always "macos" or "windows".
	Platform string
	// PolicyState is the tenant_app_policies.policy value (mandatory /
	// approved / unapproved / unmanaged) or PortalApplicationUndecided.
	PolicyState string
	// EnforcementTier is "" for undecided rows — there is no policy row to
	// carry a tier.
	EnforcementTier string
	DeviceCount     int
	// EvidenceBasis: "identifier_match" / "name_match_only" / "unknown" for
	// policy rows (AppPolicyRow.EvidenceBasis, PAT-1725); "identifier_match"
	// or "name_match_only" for undecided rows, per how the group was formed
	// (never "unknown" — an undecided row always has at least one device).
	EvidenceBasis          string
	IdentifierMatchedCount int
	NameMatchedCount       int
	// RemovalState is always PortalApplicationRemovalStateNotAvailable.
	RemovalState string
	// VersionCount (PAT-1799) is the exact distinct-version count across
	// every device_apps row backing this row's DeviceCount — "N devices on
	// M versions" for the portal. 0 when DeviceCount is 0.
	VersionCount int
	// TeamID / SignedBy / Notarized (PAT-1799): macOS codesign signing
	// state observed across matched devices. nil means "unknown", never a
	// false "unsigned"/"not notarized" verdict — see AppPolicyRow's doc
	// comment (app_policy_drift.go) for why these are deliberately derived
	// from non-Windows matched devices only.
	TeamID    *string
	SignedBy  *string
	Notarized *bool
	// LatestKnownVersion (PAT-1728) is app_catalog_entries.latest_version for
	// this product, matched via the same platform + verified_signer/name
	// identity rule needs_attention.go's catalog_out_of_date CTE uses — nil
	// when no catalog entry matches. Only ever populated for policy rows
	// whose PolicyState is "approved" or "mandatory"; nil on every other
	// row, including undecided ones — see fetchApprovedCatalogGaps' doc
	// comment for why this pass is scoped that way. Never a guessed value:
	// nil means "no trustworthy latest version", not "unknown, assume
	// current" (root AGENTS.md: absence requires authority).
	LatestKnownVersion *string
	// DevicesBehindCount (PAT-1728) is the count of this row's matched
	// devices running a version older than LatestKnownVersion, by real
	// semantic version comparison (cvematch.CompareVersions), not string
	// comparison. Same nullability as LatestKnownVersion: nil exactly when
	// LatestKnownVersion is nil, never a guessed 0 — 0 is a real, confident
	// "no device is behind" answer and must stay distinguishable from "we
	// don't know".
	DevicesBehindCount *int
	// DecidedBy / DecidedAt / Justification (PAT-1800) carry provenance for
	// this row's PolicyState: who decided it, when, and why. All three are
	// nil when there is genuinely no decision record to show — never
	// fabricated, never defaulted to a value that would read as a real
	// decision (root AGENTS.md: "absence requires authority"). Source
	// differs by row kind:
	//
	//   - Policy rows (PolicyState is a persisted tenant_app_policies
	//     value): DecidedAt is tenant_app_policies.updated_at (always
	//     present — NOT NULL, set at insert and every edit).
	//     Justification is tenant_app_policies.notes, nil when empty.
	//     DecidedBy is always nil: tenant_app_policies has no actor column
	//     at all (unlike tenant_extension_policies' approved_by) — see
	//     AppPolicyRow's doc comment and contracts/portal-api.md's PAT-1800
	//     scope note.
	//   - Undecided rows (PolicyState "undecided"): looked up against
	//     tenant_new_apps by the same team_id > identifier > name
	//     precedence tenant_app_policies matching already uses in this
	//     file (see newAppIdentityKey), only when that tenant_new_apps row
	//     has recorded a real decision (decision IS NOT NULL). This is a
	//     distinct triage action, not a promotion to policy — the row still
	//     reads "undecided" at the governance layer even when populated.
	//     Justification is always nil here: tenant_new_apps has no
	//     free-text field. DecidedBy/DecidedAt come straight from that
	//     row's decided_by/decided_at.
	DecidedBy     *string
	DecidedAt     *time.Time
	Justification *string
}

// PortalApplicationsResult carries the merged policy + undecided application
// list plus the exact pre-cap total and truncation/estate signals for the
// undecided half (see portalApplicationsMaxSourceRows doc comment).
type PortalApplicationsResult struct {
	Applications []PortalApplication
	// Total is the exact row count before the undecided cap: the number of
	// policy rows (always exact — see the const doc comment above) plus the
	// undecided pre-cap group count. When EstateTooLarge, the undecided half
	// is unknown and excluded, so Total reflects the policy rows only.
	Total     int
	Truncated bool
	// EstateTooLarge is true only when the undecided-application fail-closed
	// pre-check fired. Policy rows are still returned in this case (see the
	// const doc comment above); only the undecided section is empty.
	EstateTooLarge bool
	SourceRowCount int64
}

// FetchPortalApplications returns the tenant's applications with a policy
// state (PAT-1727): every tenant_app_policies row, each with the device
// count matched exactly as FetchAppPolicyDriftReport already computes it,
// plus every installed application matching no policy row at all
// ("undecided"). Approved/mandatory policy rows also carry the PAT-1728
// catalog "devices behind" comparison (LatestKnownVersion/DevicesBehindCount
// on PortalApplication) — see fetchApprovedCatalogGaps' doc comment. See
// contracts/portal-api.md for the full response shape.
func FetchPortalApplications(ctx context.Context, pool *pgxpool.Pool, tenantID string) (PortalApplicationsResult, error) {
	var res PortalApplicationsResult

	drift, err := FetchAppPolicyDriftReport(ctx, pool, tenantID)
	if err != nil {
		return res, fmt.Errorf("portal applications: fetch policy drift: %w", err)
	}

	// PAT-1728: catalog "devices behind" gaps for approved/mandatory policy
	// rows only — see fetchApprovedCatalogGaps' doc comment. A tenant with
	// no policies at all still pays for this query, but it's a bounded,
	// cheap no-match SELECT in that case.
	gaps, err := fetchApprovedCatalogGaps(ctx, pool, tenantID)
	if err != nil {
		return res, fmt.Errorf("portal applications: fetch approved catalog gaps: %w", err)
	}

	for _, p := range drift.Policies {
		decidedAt := p.PolicyUpdatedAt
		var justification *string
		if p.PolicyNotes != "" {
			justification = &p.PolicyNotes
		}
		app := PortalApplication{
			Name:                   p.AppName,
			Platform:               p.Platform,
			PolicyState:            p.Policy,
			EnforcementTier:        p.EnforcementTier,
			DeviceCount:            p.DevicesWithApp,
			EvidenceBasis:          p.EvidenceBasis,
			IdentifierMatchedCount: p.IdentifierMatchedCount,
			NameMatchedCount:       p.NameMatchedCount,
			RemovalState:           PortalApplicationRemovalStateNotAvailable,
			VersionCount:           p.VersionCount,
			TeamID:                 p.TeamID,
			SignedBy:               p.SignedBy,
			Notarized:              p.Notarized,
			// DecidedBy stays nil — see PortalApplication.DecidedBy's doc
			// comment: tenant_app_policies has no actor column.
			DecidedAt:     &decidedAt,
			Justification: justification,
		}
		if ident, teamID, key, ok := policyRoundTripIdentity(p); ok {
			app.Identifier = ident
			if teamID != "" {
				app.PolicyTeamID = &teamID
			}
			app.ProductKey = &key
		}
		if p.Policy == "approved" || p.Policy == "mandatory" {
			key := catalogGapKey{Name: p.AppName, Policy: p.Policy, EnforcementTier: p.EnforcementTier, Platform: p.Platform}
			if gap, ok := gaps[key]; ok {
				latest := gap.LatestVersion
				behind := gap.DevicesBehindCount
				app.LatestKnownVersion = &latest
				app.DevicesBehindCount = &behind
			}
		}
		res.Applications = append(res.Applications, app)
	}
	res.Total = len(res.Applications)

	var haveDeviceApps, havePolicies bool
	err = pool.QueryRow(ctx, `
		SELECT to_regclass('device_apps') IS NOT NULL,
		       to_regclass('tenant_app_policies') IS NOT NULL
	`).Scan(&haveDeviceApps, &havePolicies)
	if err != nil {
		return res, fmt.Errorf("portal applications: probe tables: %w", err)
	}
	if !haveDeviceApps {
		sortPortalApplications(res.Applications)
		return res, nil
	}

	// Fail-closed pre-check, same bounded-existence-probe shape as
	// FetchPortalExtensions (see portal_extensions.go part (d) of its doc
	// comment): select at most portalApplicationsMaxSourceRows+1 matching
	// device_apps rows, so the probe's own cost never scales past the
	// threshold regardless of the tenant's true row count.
	var sourceRows int64
	err = pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM (
			SELECT 1 FROM device_apps da
			JOIN devices d ON d.id = da.device_id
			WHERE d.tenant_id = $1::uuid
			LIMIT $2
		) capped
	`, tenantID, int64(portalApplicationsMaxSourceRows)+1).Scan(&sourceRows)
	if err != nil {
		return res, fmt.Errorf("portal applications: probe device_apps row count: %w", err)
	}
	if sourceRows > int64(portalApplicationsMaxSourceRows) {
		res.Truncated = true
		res.EstateTooLarge = true
		res.SourceRowCount = sourceRows
		sortPortalApplications(res.Applications)
		return res, nil
	}

	policyJoin := portalApplicationsPolicyJoin
	if !havePolicies {
		policyJoin = portalApplicationsPolicyStub
	}

	rows, err := pool.Query(ctx, fmt.Sprintf(portalApplicationsUndecidedQuery, policyJoin),
		tenantID, portalApplicationsMaxUndecidedRows,
		portalApplicationsMaxNameLen, portalApplicationsMaxIdentifierLen)
	if err != nil {
		return res, fmt.Errorf("portal applications: fetch undecided: %w", err)
	}
	defer rows.Close()

	var undecidedTotal int
	var undecided []PortalApplication
	for rows.Next() {
		var app PortalApplication
		var hasIdentifier, notarizedTrue, notarizedFalse bool
		if err := rows.Scan(&app.Name, &app.Identifier, &hasIdentifier, &app.Platform,
			&app.DeviceCount, &app.VersionCount, &app.TeamID, &app.SignedBy,
			&notarizedTrue, &notarizedFalse, &undecidedTotal); err != nil {
			return res, fmt.Errorf("portal applications: scan undecided row: %w", err)
		}
		app.PolicyState = PortalApplicationUndecided
		app.RemovalState = PortalApplicationRemovalStateNotAvailable
		if hasIdentifier {
			app.EvidenceBasis = "identifier_match"
		} else {
			app.EvidenceBasis = "name_match_only"
			app.Identifier = ""
		}
		app.Notarized = notarizedTriState(notarizedTrue, notarizedFalse)
		if app.Platform == "windows" {
			// The current Windows collector never reports codesign identity
			// (device_apps.team_id/signer/notarized are macOS concepts) —
			// force explicit unknown here rather than trust whatever MAX()
			// happened to return, since device_apps.notarized in particular
			// can hold a literal `false` for a Windows row that never
			// carried a real signal at all (see AppPolicyRow's doc comment,
			// app_policy_drift.go).
			app.TeamID, app.SignedBy, app.Notarized = nil, nil, nil
		}
		undecided = append(undecided, app)
	}
	if err := rows.Err(); err != nil {
		return res, fmt.Errorf("portal applications: iterate undecided rows: %w", err)
	}

	if len(undecided) > 0 {
		if err := attachNewAppDecisions(ctx, pool, tenantID, undecided); err != nil {
			return res, fmt.Errorf("portal applications: attach new-app decisions: %w", err)
		}
	}

	res.Applications = append(res.Applications, undecided...)
	res.Total += undecidedTotal
	res.Truncated = undecidedTotal > len(undecided)
	sortPortalApplications(res.Applications)
	return res, nil
}

// newAppIdentityKey computes the tenant_new_apps.app_identity a given
// undecided PortalApplication row would have been filed under, using the
// SAME precedence tenant_app_policies matching already uses everywhere else
// in this file and portal_extensions.go's sibling: team_id > identifier
// (bundle proxy) > lower(name). teamID follows AppPolicyRow's convention —
// nil/empty/"Unknown" all mean "no usable team_id".
//
// This is deliberately NOT byte-identical to the extractor's own mandatoryKey
// (internal/extractor/new_apps.go), which additionally prefers a typed
// Windows winget identifier ("winget:<id>") over a bare identifier when
// device_apps.identifier_kind = 'winget'. This read path has no
// identifier_kind available (portalApplicationsUndecidedQuery does not
// select it, and adding it would touch the abuse-resistance-hardened
// undecided query for a narrower win) and instead reuses the plain
// team/bundle/name precedence this file already applies for
// tenant_app_policies matching. Consequence: a Windows undecided row whose
// tenant_new_apps entry was filed under a "winget:" key finds no match here
// and reads decided_by/decided_at/justification all nil — a false negative
// (real provenance not shown), never a false positive (never attributed to
// the wrong app). Flagged as a follow-up rather than rushed into this
// change.
func newAppIdentityKey(teamID *string, identifier, name string) string {
	if teamID != nil {
		t := strings.ToLower(strings.TrimSpace(*teamID))
		if t != "" && t != "unknown" {
			return "team:" + t
		}
	}
	if identifier != "" {
		return "bundle:" + strings.ToLower(identifier)
	}
	return "name:" + strings.ToLower(name)
}

// newAppDecision is the decided_by/decided_at pair for one tenant_new_apps
// row that has recorded a real decision.
type newAppDecision struct {
	decidedBy string
	decidedAt time.Time
}

// attachNewAppDecisions (PAT-1800) looks up each undecided row against
// tenant_new_apps and, when a decision has been recorded there, sets
// DecidedBy/DecidedAt in place. This is a distinct triage decision, not a
// governance policy — PolicyState stays "undecided" regardless (see
// PortalApplication.DecidedBy's doc comment). Justification is never set
// here: tenant_new_apps has no free-text field to source it from.
//
// Degrades to a no-op if tenant_new_apps doesn't exist (platform build
// predating PAT-167/PAT-36 migration), same convention as every other
// optional-table probe in this file.
func attachNewAppDecisions(ctx context.Context, pool *pgxpool.Pool, tenantID string, undecided []PortalApplication) error {
	var haveNewApps bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('tenant_new_apps') IS NOT NULL`).Scan(&haveNewApps); err != nil {
		return fmt.Errorf("probe tenant_new_apps: %w", err)
	}
	if !haveNewApps {
		return nil
	}

	rows, err := pool.Query(ctx, `
		SELECT app_identity, decided_by, decided_at
		FROM tenant_new_apps
		WHERE tenant_id = $1::uuid
		  AND decision IS NOT NULL
		  AND decided_by IS NOT NULL
		  AND decided_at IS NOT NULL
	`, tenantID)
	if err != nil {
		return fmt.Errorf("query tenant_new_apps decisions: %w", err)
	}
	defer rows.Close()

	decisions := make(map[string]newAppDecision)
	for rows.Next() {
		var identity string
		var d newAppDecision
		if err := rows.Scan(&identity, &d.decidedBy, &d.decidedAt); err != nil {
			return fmt.Errorf("scan tenant_new_apps decision: %w", err)
		}
		decisions[identity] = d
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(decisions) == 0 {
		return nil
	}

	for i := range undecided {
		app := &undecided[i]
		key := newAppIdentityKey(app.TeamID, app.Identifier, app.Name)
		d, ok := decisions[key]
		if !ok {
			continue
		}
		decidedBy := d.decidedBy
		decidedAt := d.decidedAt
		app.DecidedBy = &decidedBy
		app.DecidedAt = &decidedAt
	}
	return nil
}

// policyRoundTripTeamIDPattern mirrors handlers.approvalTeamIDPattern (an
// unexported var in internal/handlers/portal_software_approvals.go): the
// exact shape PUT /v1/portal/software-approvals accepts for an application
// team_id. Duplicated rather than imported — internal/handlers already
// imports internal/report, so importing back would cycle — and it is a
// small, stable constant (the pattern hasn't changed since PAT-2007).
var policyRoundTripTeamIDPattern = regexp.MustCompile(`^[A-Z0-9]{10}$`)

// policyRoundTripIdentity (PAT-2104) derives the identity a policy row can
// be represented by on PUT /v1/portal/software-approvals, using the SAME
// exact-match rule that handler's currentAppDecision uses to find this row
// again: platform macos or windows (never "any" — the write schema has no
// platform=any item), winget_id unset, name unset, and a non-empty
// bundle_id. team_id is included only on macos, and only when it is
// present and already has the shape the write path requires (10 character
// Apple Team ID) — a stored team_id that does not fit that shape cannot be
// echoed back without failing the write's own 400 validation, so the whole
// row is treated as unaddressable rather than half-represented.
//
// ok is false — identifier/teamID/productKey all zero — whenever this row
// cannot be safely round-tripped: a name-only row, a winget-keyed row, an
// "any"-platform row, or a malformed team_id. Never invents an identifier
// for a row the write path cannot find (root AGENTS.md: "absence requires
// authority").
func policyRoundTripIdentity(p AppPolicyRow) (identifier, teamID, productKey string, ok bool) {
	if p.IdentityHasName || p.IdentityWingetID != nil {
		return "", "", "", false
	}
	if p.Platform != "macos" && p.Platform != "windows" {
		return "", "", "", false
	}
	if p.IdentityBundleID == nil || strings.TrimSpace(*p.IdentityBundleID) == "" {
		return "", "", "", false
	}
	identifier = strings.TrimSpace(*p.IdentityBundleID)
	if p.Platform == "macos" && p.IdentityTeamID != nil {
		t := strings.ToUpper(strings.TrimSpace(*p.IdentityTeamID))
		if t != "" {
			if !policyRoundTripTeamIDPattern.MatchString(t) {
				return "", "", "", false
			}
			teamID = t
		}
	}
	productKey = softwaregov.ApplicationKey(p.Platform, identifier, teamID)
	return identifier, teamID, productKey, true
}

// portalApplicationPolicyStateRank orders GET /v1/portal/applications rows:
// unapproved first (the page's point, same convention as
// portalExtensionsQuery's approval_state ordering), then undecided, then
// approved, then the remaining persisted policy values, then by device
// count descending and name.
var portalApplicationPolicyStateRank = map[string]int{
	"unapproved": 0,
	"undecided":  1,
	"approved":   2,
	"mandatory":  3,
	"unmanaged":  4,
}

func portalApplicationPolicyStateRankOf(state string) int {
	if r, ok := portalApplicationPolicyStateRank[state]; ok {
		return r
	}
	return len(portalApplicationPolicyStateRank)
}

func sortPortalApplications(apps []PortalApplication) {
	sort.SliceStable(apps, func(i, j int) bool {
		ri, rj := portalApplicationPolicyStateRankOf(apps[i].PolicyState), portalApplicationPolicyStateRankOf(apps[j].PolicyState)
		if ri != rj {
			return ri < rj
		}
		if apps[i].DeviceCount != apps[j].DeviceCount {
			return apps[i].DeviceCount > apps[j].DeviceCount
		}
		return strings.ToLower(apps[i].Name) < strings.ToLower(apps[j].Name)
	})
}

// portalApplicationsUndecidedQuery finds device_apps rows matching no
// tenant_app_policies row under the identical matching rule
// FetchAppPolicyDriftReport uses (name/bundle_id/team_id, platform-scoped),
// then groups them by the strongest identifier available. device_apps.
// identifier is written NOT NULL and non-empty is enforced at ingestion
// (internal/extractor/upsert.go skips any app payload row whose resolved
// identifier is empty), so in practice virtually every row groups by
// identifier; grouping falls back to lower(name) only for rows that predate
// that invariant. %s is the policy-nonexistence join — the real
// tenant_app_policies check normally, or a stub (never matches, so every
// device_apps row is "undecided") when that table hasn't been migrated yet.
const portalApplicationsUndecidedQuery = `
WITH base AS (
    SELECT
        da.device_id,
        da.identifier                    AS raw_identifier,
        NULLIF(TRIM(da.identifier), '')  AS identifier,
        da.name,
        da.team_id,
        da.signer,
        da.version,
        da.notarized,
        CASE WHEN d.os ILIKE 'windows%%' THEN 'windows' ELSE 'macos' END AS platform
    FROM device_apps da
    JOIN devices d ON d.id = da.device_id
    WHERE d.tenant_id = $1::uuid
),
candidates AS (
    SELECT b.device_id, b.identifier, b.name, b.platform, b.team_id, b.signer, b.version, b.notarized
    FROM base b
    WHERE NOT EXISTS (
        SELECT 1
        %s
    )
),
grouped AS (
    SELECT
        COALESCE(identifier, lower(name)) AS group_key,
        platform,
        (identifier IS NOT NULL)          AS has_identifier,
        MAX(name)                         AS display_name,
        MAX(identifier)                   AS display_identifier,
        COUNT(DISTINCT device_id)::int    AS device_count,
        COUNT(DISTINCT version) FILTER (WHERE version IS NOT NULL)::int AS version_count,
        MAX(team_id)                      AS display_team_id,
        MAX(signer)                       AS display_signer,
        COALESCE(BOOL_OR(notarized) FILTER (WHERE notarized IS NOT NULL), false)          AS notarized_true,
        COALESCE(BOOL_OR(notarized IS FALSE) FILTER (WHERE notarized IS NOT NULL), false) AS notarized_false
    FROM candidates
    GROUP BY 1, 2, 3
)
SELECT LEFT(display_name, $3), LEFT(COALESCE(display_identifier, ''), $4), has_identifier, platform,
       device_count,
       version_count, display_team_id, display_signer, notarized_true, notarized_false,
       COUNT(*) OVER()::int AS total_count
FROM grouped
ORDER BY device_count DESC, LOWER(display_name)
LIMIT $2
`

// portalApplicationsPolicyJoin mirrors FetchAppPolicyDriftReport's matching
// rule exactly (name/bundle_id/team_id, platform-scoped) so an app counted
// as "undecided" here can never also match a configured policy there.
const portalApplicationsPolicyJoin = `
        FROM effective_tenant_app_policies($1::uuid) tap
        WHERE tap.tenant_id = $1::uuid
          AND (tap.platform = 'any' OR b.platform = tap.platform)
          AND (
              (tap.name IS NOT NULL AND lower(b.name) = lower(tap.name))
              OR (tap.bundle_id IS NOT NULL AND b.raw_identifier = tap.bundle_id)
              OR (tap.team_id IS NOT NULL AND b.team_id = tap.team_id)
          )`

// portalApplicationsPolicyStub stands in when tenant_app_policies has not
// been migrated: NOT EXISTS over an always-empty set means every device_apps
// row is "undecided".
const portalApplicationsPolicyStub = `
        FROM (SELECT 1 WHERE false) tap`
