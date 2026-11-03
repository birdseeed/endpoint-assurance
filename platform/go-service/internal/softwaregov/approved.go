package softwaregov

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ApprovedProduct is one Approved policy row with who approved it and when.
//
// ApprovedBy and ApprovedAt come from the PAT-2007 decision audit when the
// latest decision for the product key set it Approved (approved_via
// "portal"). Otherwise the row was set by the operator admin API, which
// records no actor for applications: ApprovedBy is then the extension row's
// own approved_by when there is one, else null, and ApprovedAt is the policy
// row's last update (approved_at_basis "policy_last_updated"), which may be
// later than the original approval.
type ApprovedProduct struct {
	DeclarationID             string    `json:"declaration_id,omitempty"`
	Source                    string    `json:"source"`
	IdentityState             string    `json:"identity_state,omitempty"`
	ObservationState          string    `json:"observation_state,omitempty"`
	EffectiveApprovalState    string    `json:"effective_approval_state,omitempty"`
	ObservedInstallationCount int       `json:"observed_installation_count"`
	OutsideConstraintCount    int       `json:"outside_constraint_count"`
	UnknownVersionCount       int       `json:"unknown_version_count"`
	Publisher                 string    `json:"publisher,omitempty"`
	MinVersion                *string   `json:"min_version,omitempty"`
	ReviewDate                *string   `json:"review_date,omitempty"`
	Type                      string    `json:"type"`
	PolicyID                  int64     `json:"policy_id"`
	ProductKey                *string   `json:"product_key"`
	Name                      string    `json:"name"`
	Platform                  string    `json:"platform,omitempty"`
	Identifier                string    `json:"identifier,omitempty"`
	TeamID                    string    `json:"team_id,omitempty"`
	WingetID                  string    `json:"winget_id,omitempty"`
	MatchName                 string    `json:"match_name,omitempty"`
	Browser                   string    `json:"browser,omitempty"`
	ExtensionID               string    `json:"extension_id,omitempty"`
	ObservationKind           string    `json:"observation_kind,omitempty"`
	ObservationSource         string    `json:"observation_source,omitempty"`
	ApprovedBy                *string   `json:"approved_by"`
	ApprovedVia               string    `json:"approved_via"`
	ApprovedAt                time.Time `json:"approved_at"`
	ApprovedAtBasis           string    `json:"approved_at_basis"`
	Justification             *string   `json:"justification"`
}

// ApprovedList is GET /v1/portal/software/approved.
type ApprovedList struct {
	GeneratedAt time.Time         `json:"generated_at"`
	Total       int               `json:"total"`
	Products    []ApprovedProduct `json:"products"`
}

type decision struct {
	actor    string
	at       time.Time
	newState string
}

func latestDecisions(ctx context.Context, q Querier, tenantID string) (map[string]decision, error) {
	rows, err := q.Query(ctx, `
		SELECT DISTINCT ON (product_key) product_key, actor_email, decided_at, new_state
		FROM software_approval_decisions
		WHERE tenant_id = $1::uuid
		ORDER BY product_key, decided_at DESC, id DESC
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("latest approval decisions: %w", err)
	}
	defer rows.Close()
	out := map[string]decision{}
	for rows.Next() {
		var key string
		var d decision
		if err := rows.Scan(&key, &d.actor, &d.at, &d.newState); err != nil {
			return nil, fmt.Errorf("scan approval decision: %w", err)
		}
		out[key] = d
	}
	return out, rows.Err()
}

// FetchApproved lists every Approved application and extension policy.
func FetchApproved(ctx context.Context, q Querier, tenantID string, asOf time.Time) (ApprovedList, error) {
	out := ApprovedList{GeneratedAt: asOf.UTC(), Products: []ApprovedProduct{}}
	decisions, err := latestDecisions(ctx, q, tenantID)
	if err != nil {
		return out, err
	}
	attribute := func(p *ApprovedProduct, policyUpdated time.Time, rowActor *string) {
		if p.ProductKey != nil {
			if d, ok := decisions[*p.ProductKey]; ok && d.newState == StateApproved {
				actor := d.actor
				p.ApprovedBy, p.ApprovedVia, p.ApprovedAt, p.ApprovedAtBasis = &actor, "portal", d.at.UTC(), "decision"
				return
			}
		}
		p.ApprovedVia, p.ApprovedAt, p.ApprovedAtBasis = "operator", policyUpdated.UTC(), "policy_last_updated"
		if rowActor != nil && strings.TrimSpace(*rowActor) != "" {
			a := strings.TrimSpace(*rowActor)
			p.ApprovedBy = &a
		}
	}

	rows, err := q.Query(ctx, `
		SELECT tap.id, tap.platform, tap.bundle_id, tap.team_id, tap.winget_id, tap.name,
		       tap.updated_at, NULLIF(tap.notes, ''),
		       (SELECT min(da.name) FROM device_apps da JOIN devices d ON d.id = da.device_id
		        WHERE d.tenant_id = tap.tenant_id AND tap.bundle_id IS NOT NULL
		          AND lower(btrim(da.identifier)) = lower(btrim(tap.bundle_id)))
		FROM tenant_app_policies tap
		WHERE tap.tenant_id = $1::uuid AND tap.policy = 'approved'
	`, tenantID)
	if err != nil {
		return out, fmt.Errorf("approved applications: %w", err)
	}
	for rows.Next() {
		var id int64
		var platform string
		var bundle, team, winget, name, notes, observed *string
		var updated time.Time
		if err := rows.Scan(&id, &platform, &bundle, &team, &winget, &name, &updated, &notes, &observed); err != nil {
			rows.Close()
			return out, fmt.Errorf("scan approved application: %w", err)
		}
		p := ApprovedProduct{Type: TypeApplication, PolicyID: id, Platform: platform, Justification: notes}
		if bundle != nil {
			p.Identifier = strings.TrimSpace(*bundle)
		}
		if team != nil {
			p.TeamID = strings.ToUpper(strings.TrimSpace(*team))
		}
		if winget != nil {
			p.WingetID = *winget
		}
		if name != nil {
			p.MatchName = *name
		}
		// Only a row keyed exactly like a portal item (identifier, optional
		// Team ID, one platform) has a PAT-2007 product key.
		if p.Identifier != "" && winget == nil && name == nil && (platform == "macos" || platform == "windows") {
			k := ApplicationKey(platform, p.Identifier, p.TeamID)
			p.ProductKey = &k
		}
		switch {
		case name != nil && strings.TrimSpace(*name) != "":
			p.Name = *name
		case observed != nil:
			p.Name = *observed
		case p.Identifier != "":
			p.Name = p.Identifier
		case p.WingetID != "":
			p.Name = p.WingetID
		default:
			p.Name = p.TeamID
		}
		attribute(&p, updated, nil)
		out.Products = append(out.Products, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("iterate approved applications: %w", err)
	}

	rows, err = q.Query(ctx, `
		SELECT id, browser, extension_id, name, NULLIF(approved_by, ''), updated_at, NULLIF(notes, '')
		FROM tenant_extension_policies
		WHERE tenant_id = $1::uuid AND policy = 'approved'
	`, tenantID)
	if err != nil {
		return out, fmt.Errorf("approved extensions: %w", err)
	}
	for rows.Next() {
		var id int64
		var browser, extID, name string
		var approvedBy, notes *string
		var updated time.Time
		if err := rows.Scan(&id, &browser, &extID, &name, &approvedBy, &updated, &notes); err != nil {
			rows.Close()
			return out, fmt.Errorf("scan approved extension: %w", err)
		}
		k := ExtensionKey(browser, extID)
		p := ApprovedProduct{Type: TypeBrowserExtension, PolicyID: id, ProductKey: &k, Name: name,
			Browser: browser, ExtensionID: extID, Justification: notes}
		if strings.TrimSpace(p.Name) == "" {
			p.Name = extID
		}
		attribute(&p, updated, approvedBy)
		out.Products = append(out.Products, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("iterate approved extensions: %w", err)
	}

	// PAT-2058: approved Homebrew formulae and casks, same resolver and
	// decision audit as applications and extensions above. tenant_homebrew_
	// policies has no actor column (like tenant_app_policies), so ApprovedBy
	// comes only from the portal decision audit when it applies.
	rows, err = q.Query(ctx, `
		SELECT id, kind, name, tap, updated_at, NULLIF(notes, '')
		FROM tenant_homebrew_policies
		WHERE tenant_id = $1::uuid AND policy = 'approved'
	`, tenantID)
	if err != nil {
		return out, fmt.Errorf("approved homebrew: %w", err)
	}
	for rows.Next() {
		var id int64
		var kind, name, tap string
		var notes *string
		var updated time.Time
		if err := rows.Scan(&id, &kind, &name, &tap, &updated, &notes); err != nil {
			rows.Close()
			return out, fmt.Errorf("scan approved homebrew: %w", err)
		}
		typ, key := TypeHomebrewFormula, HomebrewFormulaKey(name, tap)
		if kind == "cask" {
			typ, key = TypeHomebrewCask, HomebrewCaskKey(name, tap)
		}
		p := ApprovedProduct{Type: typ, PolicyID: id, ProductKey: &key, Name: name,
			Platform: "macos", Identifier: name, Justification: notes}
		attribute(&p, updated, nil)
		out.Products = append(out.Products, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("iterate approved homebrew: %w", err)
	}

	rows, err = q.Query(ctx, `
		SELECT id, identity_kind, name, source, updated_at, NULLIF(notes, '')
		FROM tenant_observation_policies
		WHERE tenant_id = $1::uuid AND policy = 'approved'
	`, tenantID)
	if err != nil {
		return out, fmt.Errorf("approved observations: %w", err)
	}
	for rows.Next() {
		var id int64
		var kind, name, source string
		var notes *string
		var updated time.Time
		if err := rows.Scan(&id, &kind, &name, &source, &updated, &notes); err != nil {
			rows.Close()
			return out, fmt.Errorf("scan approved observation: %w", err)
		}
		key := ObservationKey(kind, name, source)
		p := ApprovedProduct{Type: TypeObservation, PolicyID: id, ProductKey: &key, Name: name,
			Identifier: name, ObservationKind: kind, ObservationSource: source, Justification: notes}
		attribute(&p, updated, nil)
		out.Products = append(out.Products, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("iterate approved observations: %w", err)
	}

	// PAT-2393 declarations. A resolved declaration is linked to an ordinary
	// policy row, which stays the single authority: that row keeps its own
	// approver, time, justification and minimum version (an operator or a
	// later portal decision may have changed them) and only gains the
	// declaration's identity and observation metadata. An unresolved
	// declaration has no policy row, matches nothing and is listed as
	// declared intent with zero installations.
	declarations, err := FetchDeclarations(ctx, q, tenantID)
	if err != nil {
		return out, err
	}
	byPolicy := map[int64]Declaration{}
	for _, d := range declarations {
		if d.PolicyID != nil {
			byPolicy[*d.PolicyID] = d
		}
	}
	for i := range out.Products {
		p := &out.Products[i]
		p.Source = p.ApprovedVia
		if p.Type != TypeApplication {
			continue
		}
		d, ok := byPolicy[p.PolicyID]
		if !ok {
			continue
		}
		p.DeclarationID, p.Publisher, p.ReviewDate = d.ID, d.Publisher, d.ReviewDate
		p.IdentityState, p.ObservationState, p.EffectiveApprovalState = d.IdentityState, d.ObservationState, d.EffectiveApprovalState
		p.ObservedInstallationCount, p.OutsideConstraintCount, p.UnknownVersionCount = d.ObservedInstallationCount, d.OutsideConstraintCount, d.UnknownVersionCount
		p.MinVersion = d.MinVersion
		if p.Name == p.Identifier {
			// Nothing observed supplies a name yet; the declared one reads
			// better than a bare identifier.
			p.Name = d.Name
		}
	}
	for _, d := range declarations {
		if d.PolicyID != nil || d.ResolvedAt != nil {
			continue
		}
		creator, reason := d.CreatedBy, d.Justification
		out.Products = append(out.Products, ApprovedProduct{Type: TypeApplication, DeclarationID: d.ID, Name: d.Name,
			Publisher: d.Publisher, Platform: d.Platform, Source: d.Source, IdentityState: d.IdentityState,
			ObservationState: d.ObservationState, EffectiveApprovalState: d.EffectiveApprovalState,
			MinVersion: d.MinVersion, ReviewDate: d.ReviewDate, ApprovedBy: &creator, ApprovedVia: "portal",
			ApprovedAt: d.CreatedAt.UTC(), ApprovedAtBasis: "declaration", Justification: &reason})
	}
	sort.Slice(out.Products, func(i, j int) bool {
		a, b := out.Products[i], out.Products[j]
		if strings.ToLower(a.Name) != strings.ToLower(b.Name) {
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.PolicyID < b.PolicyID
	})
	out.Total = len(out.Products)
	return out, nil
}
