package softwaregov

// Tenant declarations are authored intent. Only a verified resolution links
// that intent to the existing policy store. Observations remain independent.
import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const DeclarationLimit = 1000

var MinimumVersionPattern = regexp.MustCompile(`^[0-9]{1,9}(\.[0-9]{1,9}){0,7}$`)

type Declaration struct {
	ID                        string     `json:"id"`
	Name                      string     `json:"name"`
	Publisher                 string     `json:"publisher"`
	Platform                  string     `json:"platform"`
	Justification             string     `json:"justification"`
	MinVersion                *string    `json:"min_version"`
	ReviewDate                *string    `json:"review_date"`
	SelectedAliasID           *string    `json:"selected_alias_id"`
	ResolvedAliasID           *string    `json:"resolved_alias_id"`
	PolicyID                  *int64     `json:"policy_id"`
	Identifier                string     `json:"identifier"`
	IdentityKind              string     `json:"identity_kind"`
	Companion                 string     `json:"identity_companion"`
	PublisherKey              *string    `json:"-"`
	CreatedBy                 string     `json:"created_by"`
	CreatedAt                 time.Time  `json:"created_at"`
	ResolvedAt                *time.Time `json:"resolved_at"`
	ApprovalState             string     `json:"approval_state"`
	IdentityState             string     `json:"identity_state"`
	ObservationState          string     `json:"observation_state"`
	EffectiveApprovalState    string     `json:"effective_approval_state"`
	Source                    string     `json:"source"`
	ObservedInstallationCount int        `json:"observed_installation_count"`
	OutsideConstraintCount    int        `json:"outside_constraint_count"`
	UnknownVersionCount       int        `json:"unknown_version_count"`
}

// FetchDeclarations returns every declaration the tenant has made, oldest
// first, with its identity, observation and effective approval state.
func FetchDeclarations(ctx context.Context, q Querier, tenantID string) ([]Declaration, error) {
	return fetchDeclarations(ctx, q, tenantID, "")
}

// FetchDeclaration returns one of the tenant's declarations. found is false
// when the id is not a declaration of this tenant, including when it is
// another tenant's: the two are deliberately indistinguishable.
func FetchDeclaration(ctx context.Context, q Querier, tenantID, declarationID string) (d Declaration, found bool, err error) {
	ds, err := fetchDeclarations(ctx, q, tenantID, declarationID)
	if err != nil || len(ds) == 0 {
		return Declaration{}, false, err
	}
	return ds[0], true, nil
}

// fetchDeclarations is always tenant-scoped; declarationID ("" for all) only
// narrows within the tenant. Once a declaration is linked to a policy row the
// policy is the authority for state and minimum version (an operator may have
// changed either since); the declaration's own values remain in the decision
// history.
func fetchDeclarations(ctx context.Context, q Querier, tenantID, declarationID string) ([]Declaration, error) {
	rows, err := q.Query(ctx, `
 SELECT d.id::text,d.name,d.publisher,d.platform,d.justification,
 CASE WHEN p.id IS NOT NULL THEN p.min_version ELSE d.min_version END,d.review_date::text,
 d.selected_alias_id::text,d.resolved_alias_id::text,d.policy_id,COALESCE(d.resolved_identifier,''),
 COALESCE(d.resolved_kind,''),COALESCE(d.resolved_companion,''),d.resolved_publisher_key,d.created_by,d.created_at,d.resolved_at,
 CASE WHEN p.id IS NOT NULL THEN p.policy WHEN d.resolved_at IS NOT NULL THEN 'unreviewed' ELSE 'approved' END,
 COALESCE(p.source,'portal'),
 COALESCE(a.identity_kind=d.resolved_kind AND a.identity_value_normalized=d.resolved_identifier
 AND a.companion_value_normalized=d.resolved_companion AND a.platform=d.platform
 AND a.match_confidence IN ('exact','high') AND a.provenance='reviewed' AND a.retired_at IS NULL AND sp.lifecycle_state='active',FALSE),
 EXISTS(SELECT 1 FROM effective_tenant_app_policies($1::uuid) ep WHERE ep.id=d.policy_id)
 FROM tenant_software_declarations d
 LEFT JOIN tenant_app_policies p ON p.id=d.policy_id AND p.tenant_id=d.tenant_id
 LEFT JOIN software_product_aliases a ON a.id=d.resolved_alias_id
 LEFT JOIN software_products sp ON sp.id=a.product_id
 WHERE d.tenant_id=$1::uuid AND ($3='' OR d.id::text=$3) ORDER BY d.created_at,d.id LIMIT $2`, tenantID, DeclarationLimit+1, declarationID)
	if err != nil {
		return nil, fmt.Errorf("load software declarations: %w", err)
	}
	out := []Declaration{}
	for rows.Next() {
		var d Declaration
		var valid, effective bool
		if err = rows.Scan(&d.ID, &d.Name, &d.Publisher, &d.Platform, &d.Justification, &d.MinVersion, &d.ReviewDate, &d.SelectedAliasID, &d.ResolvedAliasID, &d.PolicyID, &d.Identifier, &d.IdentityKind, &d.Companion, &d.PublisherKey, &d.CreatedBy, &d.CreatedAt, &d.ResolvedAt, &d.ApprovalState, &d.Source, &valid, &effective); err != nil {
			rows.Close()
			return nil, err
		}
		d.ApprovalState = AppPolicyState(d.ApprovalState)
		d.IdentityState = "unmatched"
		d.ObservationState = "not_observed"
		d.EffectiveApprovalState = "unmatched"
		if d.ResolvedAt != nil && valid {
			d.IdentityState = "matched"
			d.EffectiveApprovalState = "active"
			if !effective {
				d.EffectiveApprovalState = "suspended"
			}
		}
		out = append(out, d)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	if len(out) > DeclarationLimit {
		return nil, ErrEstateTooLarge
	}
	for i := range out {
		if out[i].IdentityState == "matched" {
			if err = declarationObservations(ctx, q, tenantID, &out[i]); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// CurrentInstallationSQL is the one Go-side statement of which
// software_installations rows are current. It expects the installation as si
// and its latest observation LEFT JOINed as o. macOS: not removed. Windows
// adds a device_apps row matched byte for byte on the observation's
// observed_identifier, because no application scope closes a native Windows
// installation; an installation with no observation cannot be shown removed
// and stays current. This is the rule effective_tenant_app_policies applies
// in SQL (migration 0224); the declaration read and the staff catalogue
// review both use this constant so they cannot drift from each other.
const CurrentInstallationSQL = `si.removed_at IS NULL AND (si.platform<>'windows' OR o.id IS NULL OR EXISTS (SELECT 1 FROM device_apps da
 WHERE da.device_id=si.device_id AND da.identifier=o.observed_identifier))`

// TenantsDeclaredThroughAlias lists the tenants that hold a declaration
// resolved through the alias. Retiring or reviving the alias changes what
// their policy resolver returns with no policy row and no report changing.
func TenantsDeclaredThroughAlias(ctx context.Context, q Querier, aliasID string) ([]string, error) {
	return scanStrings(q.Query(ctx, `SELECT DISTINCT tenant_id::text FROM tenant_software_declarations WHERE resolved_alias_id=$1::uuid ORDER BY 1`, aliasID))
}

// declarationObservations counts the current installations that are verifiably
// the resolved identity. A same-name, other-publisher or other-platform
// installation is never counted. Windows adds two conditions: the pinned
// Authenticode publisher, and a device_apps row, because no application scope
// closes a native Windows installation. The row is matched byte for byte on
// the latest observation's observed_identifier, never on a re-normalised
// value (see migration 0224). An installation with no observation has no
// signature evidence and is skipped by the publisher check below.
func declarationObservations(ctx context.Context, q Querier, tenantID string, d *Declaration) error {
	rows, err := q.Query(ctx, `
 SELECT si.current_version,COALESCE(o.observed_signature_state,''),COALESCE(o.observed_authenticode_root_kind,''),
 COALESCE(o.observed_authenticode_root_thumbprint,''),COALESCE(o.observed_authenticode_signer,'')
 FROM software_installations si JOIN devices dv ON dv.id=si.device_id AND dv.tenant_id=si.tenant_id
 LEFT JOIN software_observations o ON o.id=si.latest_observation_id AND o.tenant_id=si.tenant_id
 WHERE si.tenant_id=$1::uuid AND si.platform=$2 AND si.alias_id=$3::uuid AND si.identity_kind=$4
 AND si.identity_value_normalized=$5 AND si.companion_value_normalized=$6
 AND si.resolution_confidence IN ('exact','high')
 AND `+CurrentInstallationSQL, tenantID, d.Platform, d.ResolvedAliasID, d.IdentityKind, d.Identifier, d.Companion)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var version *string
		var state, kind, root, signer string
		if err = rows.Scan(&version, &state, &kind, &root, &signer); err != nil {
			return err
		}
		if d.Platform == "windows" && (d.PublisherKey == nil || state != "valid" || (kind != "microsoft" && kind != "public") || AuthenticodePublisherKey(root, signer) != *d.PublisherKey) {
			continue
		}
		d.ObservedInstallationCount++
		if d.MinVersion != nil && strings.TrimSpace(*d.MinVersion) != "" {
			// A minimum an operator later set in another format cannot be
			// compared numerically, so nothing is claimed to be inside it.
			below, known := false, false
			if version != nil {
				below, known = minimumVersionBelow(*version, *d.MinVersion)
			}
			switch {
			case !known:
				d.UnknownVersionCount++
			case below:
				d.OutsideConstraintCount++
			}
		}
	}
	if d.ObservedInstallationCount > 0 {
		d.ObservationState = "observed"
	}
	return rows.Err()
}

// minimumVersionBelow compares two numeric dotted versions; a missing trailing
// component means zero. known is false, and nothing is claimed, unless both
// are entirely numeric dotted: "1.2.3-beta", "2024a", "v2" or an empty string
// is unknown, never below the minimum and never inside it.
func minimumVersionBelow(installed, minimum string) (below, known bool) {
	if !MinimumVersionPattern.MatchString(installed) || !MinimumVersionPattern.MatchString(minimum) {
		return false, false
	}
	a, b := strings.Split(installed, "."), strings.Split(minimum, ".")
	n := len(a)
	if len(b) > n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		var x, y int64
		var err error
		if i < len(a) {
			if x, err = strconv.ParseInt(a[i], 10, 64); err != nil {
				return false, false
			}
		}
		if i < len(b) {
			if y, err = strconv.ParseInt(b[i], 10, 64); err != nil {
				return false, false
			}
		}
		if x != y {
			return x < y, true
		}
	}
	return false, true
}

// DeclaredWindowsEligibility fingerprints which of the tenant's declared
// Windows approvals are currently effective. Their eligibility follows
// installation evidence, so a report from one device can suspend or restore an
// approval for the whole tenant without any policy row changing.
func DeclaredWindowsEligibility(ctx context.Context, q Querier, tenantID string) (string, error) {
	var out string
	err := q.QueryRow(ctx, `
 SELECT COALESCE(string_agg(d.policy_id::text, ',' ORDER BY d.policy_id), '')
 FROM tenant_software_declarations d
 JOIN effective_tenant_app_policies($1::uuid) p ON p.id=d.policy_id
 WHERE d.tenant_id=$1::uuid AND d.platform='windows'`, tenantID).Scan(&out)
	if err != nil {
		return "", fmt.Errorf("declared approval eligibility: %w", err)
	}
	return out, nil
}

// MarkPolicyResolutionChanged bumps the tenant's policy version, the signal
// the Unapproved-present summary rebuilds on, for a change in what the policy
// resolver returns that no policy-table trigger can see.
func MarkPolicyResolutionChanged(ctx context.Context, q Querier, tenantID string) error {
	_, err := q.Exec(ctx, `
 INSERT INTO software_unapproved_presence_state (tenant_id, policy_version, summary_version, policy_changed_at)
 VALUES ($1::uuid, 1, 0, now())
 ON CONFLICT (tenant_id) DO UPDATE
 SET policy_version = software_unapproved_presence_state.policy_version + 1, policy_changed_at = now()`, tenantID)
	if err != nil {
		return fmt.Errorf("mark policy resolution changed: %w", err)
	}
	return nil
}
