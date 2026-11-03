package softwaregov

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"patched.im/api/internal/agentidentity"
	"patched.im/api/internal/cvepipeline"
)

// The overview's new software block (PAT-2093): products first seen in the
// last NewSoftwareUrgencyWindow, or since the tenant's last review when that
// is more recent, each with an urgency level (urgency.go) and the evidence
// behind it.
//
// Products and first seen come from the same query as
// GET /v1/portal/software/new (fetchNewSoftware), and "last review" is that
// endpoint's notion too: the most recent approval decision any customer user
// recorded (LastReviewAt). Trust evidence is each current installation's
// latest software observation (the immutable per-report evidence the
// extractor records beside software_installations), because only it keeps
// the collector's "no signing authority" report distinct from a missing
// field, and only it carries PAT-2112's signing_status and
// notarization_status, and PAT-2113's Windows Authenticode signature_state
// and signer, with PAT-2116's root thumbprint and root kind. CVE state is cvepipeline's estate assessment, the rollup behind
// GET /v1/portal/software's cve_assessment.

// NewSoftwareUrgencyWindow is the default window, and the longest one.
const NewSoftwareUrgencyWindow = 14 * 24 * time.Hour

// NewSoftwareUrgencyLimit bounds the overview's product list.
const NewSoftwareUrgencyLimit = 50

// Window bases for NewSoftwareUrgency.SinceBasis.
const (
	SinceDefaultWindow = "default_window"
	// SinceLastReview ("last_review") is shared with /software/new.
)

// UrgencyCounts is products per level. Excluded products are not counted.
type UrgencyCounts struct {
	Critical    int `json:"critical"`
	High        int `json:"high"`
	NotAssessed int `json:"not_assessed"`
	Medium      int `json:"medium"`
	Low         int `json:"low"`
}

// UrgencyExcluded is products in the window left out of the list and counts.
type UrgencyExcluded struct {
	Approved     int `json:"approved"`
	Ignored      int `json:"ignored"`
	PatchedAgent int `json:"patched_agent"`
}

// UrgentNewProduct is one product in the overview's new software block. The
// identity fields match GET /v1/portal/software (PAT-2104): identifier,
// team_id and product_key are what PUT /v1/portal/software-approvals takes.
type UrgentNewProduct struct {
	Name     string `json:"name"`
	Platform string `json:"platform"`
	// Identifier is the normalised identifier; null for a name-only product.
	Identifier *string `json:"identifier"`
	// TeamID is the macOS Team ID every current installation agrees on; null
	// on Windows, and on macOS when there is none, when installations
	// disagree, or when it is not a valid Apple Team ID.
	TeamID *string `json:"team_id"`
	// ProductKey is PAT-2007's key; null when the product cannot be addressed
	// by the approval write (name-only, or macOS Team ID disagreement or
	// malformed Team ID).
	ProductKey    *string         `json:"product_key"`
	IdentityBasis string          `json:"identity_basis"`
	ApprovalState string          `json:"approval_state"`
	FirstSeenAt   time.Time       `json:"first_seen_at"`
	DeviceCount   int             `json:"device_count"`
	Urgency       string          `json:"urgency"`
	Reasons       []UrgencyReason `json:"reasons"`
	Trust         UrgencyTrust    `json:"trust"`
	CVE           UrgencyCVE      `json:"cve"`
}

// NewSoftwareUrgency is the overview's new_software block.
type NewSoftwareUrgency struct {
	Since        time.Time  `json:"since"`
	SinceBasis   string     `json:"since_basis"`
	Until        time.Time  `json:"until"`
	WindowDays   int        `json:"window_days"`
	LastReviewAt *time.Time `json:"last_review_at"`
	Coverage     Coverage   `json:"coverage"`
	// Total is the products classified (in the window, not excluded).
	Total    int             `json:"total"`
	Counts   UrgencyCounts   `json:"counts"`
	Excluded UrgencyExcluded `json:"excluded"`
	// Truncated is true when the window held more than
	// MaxNewSoftwareProducts products: only the newest were classified, so
	// counts are a floor.
	Truncated bool               `json:"truncated"`
	Limit     int                `json:"limit"`
	Products  []UrgentNewProduct `json:"products"`
}

// isPatchedAgent reports whether a product is one of Patched's own agent
// surfaces (agentidentity.Identities), matched on the same identity column
// the auto-approval seed uses.
func isPatchedAgent(platform, identifier, name string, nameOnly bool) bool {
	for _, id := range agentidentity.Identities {
		if id.Platform != platform {
			continue
		}
		if id.BundleID != "" && !nameOnly && strings.EqualFold(strings.TrimSpace(id.BundleID), identifier) {
			return true
		}
		if id.Name != "" && strings.EqualFold(strings.TrimSpace(id.Name), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

type productGroup struct {
	platform string
	nameOnly bool
	ident    string
}

// FetchNewSoftwareUrgency builds the overview's new software block.
func FetchNewSoftwareUrgency(ctx context.Context, q Querier, tenantID string, now time.Time) (NewSoftwareUrgency, error) {
	now = now.UTC()
	out := NewSoftwareUrgency{Until: now, WindowDays: int(NewSoftwareUrgencyWindow / (24 * time.Hour)),
		Limit: NewSoftwareUrgencyLimit, Products: []UrgentNewProduct{}}
	last, err := LastReviewAt(ctx, q, tenantID)
	if err != nil {
		return out, err
	}
	out.LastReviewAt = last
	out.Since, out.SinceBasis = now.Add(-NewSoftwareUrgencyWindow), SinceDefaultWindow
	if last != nil && last.After(out.Since) {
		out.Since, out.SinceBasis = *last, SinceLastReview
	}

	since := out.Since
	ns, err := fetchNewSoftwareWithTooling(ctx, q, tenantID, NewSoftware{GeneratedAt: now, Until: now, Since: &since,
		SinceBasis: out.SinceBasis, LastReviewAt: last, Products: []NewProduct{}}, false)
	if err != nil {
		return out, err
	}
	out.Coverage = ns.Coverage
	out.Truncated = ns.Truncated

	var candidates []NewProduct
	for _, p := range ns.Products {
		// PAT-2031 exposes named tooling in the full new-software review
		// endpoint. The overview urgency model is deliberately application
		// trust and CVE evidence only, so it must not invent a signing/CVE
		// verdict for an npm package, local model or MCP server.
		if p.Type == TypeObservation {
			continue
		}
		nameOnly := p.IdentityBasis == "name_only"
		switch {
		case isPatchedAgent(p.Platform, p.Identifier, p.Name, nameOnly):
			out.Excluded.PatchedAgent++
		case p.ApprovalState == StateApproved:
			out.Excluded.Approved++
		case p.ApprovalState == StateIgnored:
			out.Excluded.Ignored++
		default:
			candidates = append(candidates, p)
		}
	}
	if len(candidates) == 0 {
		return out, nil
	}

	groups := make([]productGroup, len(candidates))
	var cveKeys []cvepipeline.EstateProductKey
	for i, p := range candidates {
		groups[i] = productGroup{platform: p.Platform, nameOnly: p.IdentityBasis == "name_only", ident: p.Identifier}
		if !groups[i].nameOnly {
			cveKeys = append(cveKeys, cvepipeline.EstateProductKey{Identifier: p.Identifier, Platform: p.Platform})
		}
	}
	facts, err := loadTrustFacts(ctx, q, tenantID, groups)
	if err != nil {
		return out, err
	}
	cves, err := cvepipeline.AssessEstateProductsNormalized(ctx, q, tenantID, cveKeys)
	if err != nil {
		return out, fmt.Errorf("new software cve assessment: %w", err)
	}
	pol, err := loadPolicies(ctx, q, tenantID)
	if err != nil {
		return out, err
	}
	approvedKeys, err := approvedPublisherKeys(ctx, q, tenantID)
	if err != nil {
		return out, err
	}
	approved := publisherApprovals{teams: approvedTeamIDs(pol), authenticode: approvedKeys}

	rows := make([]UrgentNewProduct, 0, len(candidates))
	for i, p := range candidates {
		g := groups[i]
		f := facts[g]
		f.Platform, f.NameOnly, f.Ident = g.platform, g.nameOnly, g.ident
		cve := cvepipeline.EstateAssessment{State: cvepipeline.StateNotAssessed}
		if !g.nameOnly {
			cve = cvepipeline.EstateAssessmentOrNotAssessed(cves,
				cvepipeline.EstateProductKey{Identifier: p.Identifier, Platform: p.Platform})
		}
		level, reasons, trust := classifyUrgency(f, cve, approved)
		row := UrgentNewProduct{
			Name: p.Name, Platform: p.Platform, IdentityBasis: p.IdentityBasis,
			ApprovalState: p.ApprovalState, FirstSeenAt: p.FirstSeenAt, DeviceCount: p.DeviceCount,
			Urgency: level, Reasons: reasons, Trust: trust,
			CVE: UrgencyCVE{State: cve.State, FindingCount: cve.FindingCount},
		}
		if cve.State != cvepipeline.StateNotAssessed {
			sev := cve.Severity
			row.CVE.Severity = &sev
		}
		if !g.nameOnly {
			ident := p.Identifier
			row.Identifier = &ident
			row.TeamID, row.ProductKey = addressableIdentity(g.platform, ident, f)
		}
		rows = append(rows, row)
		switch level {
		case UrgencyCritical:
			out.Counts.Critical++
		case UrgencyHigh:
			out.Counts.High++
		case UrgencyNotAssessed:
			out.Counts.NotAssessed++
		case UrgencyMedium:
			out.Counts.Medium++
		case UrgencyLow:
			out.Counts.Low++
		}
	}
	out.Total = len(rows)
	sortUrgentProducts(rows)
	if len(rows) > NewSoftwareUrgencyLimit {
		rows = rows[:NewSoftwareUrgencyLimit]
	}
	out.Products = rows
	return out, nil
}

// sortUrgentProducts orders by urgency (most severe first), then newest
// first, then name and identity for a stable order.
func sortUrgentProducts(rows []UrgentNewProduct) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if ra, rb := urgencyRank[a.Urgency], urgencyRank[b.Urgency]; ra != rb {
			return ra > rb
		}
		if !a.FirstSeenAt.Equal(b.FirstSeenAt) {
			return a.FirstSeenAt.After(b.FirstSeenAt)
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		return deref(a.Identifier) < deref(b.Identifier)
	})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// addressableIdentity returns the team_id and product_key the approval write
// would accept, following GET /v1/portal/software's PAT-2104 rule: Windows
// carries no Team ID; on macOS a Team ID is used only when every installation
// reports the same valid one, and a product whose installations disagree or
// report a malformed Team ID gets no product_key rather than a guessed one.
func addressableIdentity(platform, ident string, f trustFacts) (*string, *string) {
	if platform != "macos" {
		key := ApplicationKey(platform, ident, "")
		return nil, &key
	}
	switch {
	case f.TeamInstallations == 0:
		key := ApplicationKey(platform, ident, "")
		return nil, &key
	case len(f.TeamIDs) == 1 && f.TeamInstallations == f.Installations:
		team := normalisedTeamID(platform, f.TeamIDs[0])
		if team == "" {
			return nil, nil
		}
		key := ApplicationKey(platform, ident, team)
		return &team, &key
	default:
		return nil, nil
	}
}

// approvedTeamIDs is the set of valid Team IDs on the tenant's approved
// application policies that can apply on macOS.
func approvedTeamIDs(pol policies) map[string]bool {
	out := map[string]bool{}
	for _, r := range pol.apps {
		p := r.policy
		if p.Policy != "approved" || p.TeamID == nil || (p.Platform != "macos" && p.Platform != "any") {
			continue
		}
		if t := normalisedTeamID("macos", *p.TeamID); t != "" {
			out[t] = true
		}
	}
	return out
}

// maxDistinctEvidence bounds each distinct-value list per product.
const maxDistinctEvidence = 10

// loadTrustFacts reads the trust evidence for the given product groups in one
// set-based query. The basis is each group's current installations, or all of
// its installations when every one has been removed. A group with no row
// comes back zero valued, which classifies as unknown, never trusted.
func loadTrustFacts(ctx context.Context, q Querier, tenantID string, groups []productGroup) (map[productGroup]trustFacts, error) {
	out := make(map[productGroup]trustFacts, len(groups))
	if len(groups) == 0 {
		return out, nil
	}
	platforms := make([]string, len(groups))
	nameOnly := make([]bool, len(groups))
	idents := make([]string, len(groups))
	for i, g := range groups {
		platforms[i], nameOnly[i], idents[i] = g.platform, g.nameOnly, g.ident
	}
	rows, err := q.Query(ctx, `
		WITH keys AS (
			SELECT * FROM unnest($2::text[], $3::bool[], $4::text[]) AS k(platform, name_only, ident)
		), inst AS (
			SELECT si.platform, si.identity_kind IN ('name_publisher', 'display_name') AS name_only,
			       si.identity_value_normalized AS ident, si.identity_kind,
			       si.companion_value_normalized AS companion, si.removed_at,
			       btrim(si.current_publisher) AS publisher,
			       btrim(o.observed_signer) AS signer,
			       o.observed_signing_status AS signing_status,
			       o.observed_notarization_status AS notarization_status,
			       o.observed_signature_state AS signature_state,
			       btrim(o.observed_authenticode_signer) AS authenticode_signer,
			       o.observed_authenticode_signer_thumbprint AS signer_thumbprint,
			       o.observed_authenticode_issuer AS issuer,
			       o.observed_authenticode_root_thumbprint AS root_thumbprint,
			       o.observed_authenticode_root_kind AS root_kind
			FROM software_installations si
			JOIN keys k ON k.platform = si.platform
			           AND k.name_only = (si.identity_kind IN ('name_publisher', 'display_name'))
			           AND k.ident = si.identity_value_normalized
			LEFT JOIN software_observations o
			       ON o.id = si.latest_observation_id AND o.tenant_id = si.tenant_id
			WHERE si.tenant_id = $1::uuid
			  AND si.identity_kind = ANY($5)
		), basis AS (
			SELECT i.*
			FROM (SELECT inst.*, bool_or(removed_at IS NULL)
			             OVER (PARTITION BY platform, name_only, ident) AS has_current
			      FROM inst) i
			WHERE i.removed_at IS NULL OR NOT i.has_current
		)
		SELECT platform, name_only, ident,
		       count(*)::int,
		       count(*) FILTER (WHERE identity_kind = 'display_name')::int,
		       count(*) FILTER (WHERE signer IS NOT NULL)::int,
		       count(*) FILTER (WHERE signer IS NOT NULL AND (signer = '' OR lower(signer) = $6)
		                        AND signing_status IS DISTINCT FROM 'unsigned'
		                        AND signing_status IS DISTINCT FROM 'adhoc'
		                        AND signing_status IS DISTINCT FROM 'untrusted'
		                        AND signing_status IS DISTINCT FROM 'invalid')::int,
		       count(*) FILTER (WHERE signing_status = 'unsigned')::int,
		       count(*) FILTER (WHERE signing_status = 'adhoc')::int,
		       count(*) FILTER (WHERE signing_status = 'untrusted')::int,
		       count(*) FILTER (WHERE signing_status = 'invalid')::int,
		       count(*) FILTER (WHERE notarization_status = 'notarized')::int,
		       COALESCE((array_agg(DISTINCT signer ORDER BY signer) FILTER (
		           WHERE signer IS NOT NULL AND signer <> '' AND lower(signer) <> $6))[1:$7::int], '{}'),
		       count(*) FILTER (WHERE identity_kind = 'macos_bundle_team')::int,
		       COALESCE((array_agg(DISTINCT companion ORDER BY companion) FILTER (
		           WHERE identity_kind = 'macos_bundle_team'))[1:$7::int], '{}'),
		       count(*) FILTER (WHERE publisher IS NOT NULL AND publisher <> '')::int,
		       COALESCE((array_agg(DISTINCT publisher ORDER BY publisher) FILTER (
		           WHERE publisher IS NOT NULL AND publisher <> ''))[1:$7::int], '{}'),
		       count(*) FILTER (WHERE signature_state = 'valid')::int,
		       count(*) FILTER (WHERE signature_state = 'invalid')::int,
		       count(*) FILTER (WHERE signature_state = 'unknown')::int,
		       count(*) FILTER (WHERE signature_state = 'valid'
		                        AND authenticode_signer IS NOT NULL AND authenticode_signer <> '')::int,
		       COALESCE((array_agg(DISTINCT authenticode_signer ORDER BY authenticode_signer) FILTER (
		           WHERE signature_state = 'valid' AND authenticode_signer IS NOT NULL
		             AND authenticode_signer <> ''))[1:$7::int], '{}'),
		       count(*) FILTER (WHERE signature_state = 'unsigned')::int,
		       count(*) FILTER (WHERE signature_state = 'valid'
		                        AND root_kind IN ('microsoft', 'public'))::int,
		       count(*) FILTER (WHERE signature_state = 'valid'
		                        AND root_kind IN ('microsoft', 'public') AND root_thumbprint IS NOT NULL)::int,
		       COALESCE((array_agg(DISTINCT root_thumbprint ORDER BY root_thumbprint) FILTER (
		           WHERE signature_state = 'valid' AND root_kind IN ('microsoft', 'public')
		             AND root_thumbprint IS NOT NULL))[1:$7::int], '{}'),
		       count(*) FILTER (WHERE signature_state = 'valid' AND root_kind = 'enterprise')::int,
		       count(*) FILTER (WHERE signature_state = 'valid' AND root_kind IS NULL
		                        AND root_thumbprint IS NULL AND signer_thumbprint IS NULL
		                        AND issuer IS NULL)::int
		FROM basis
		GROUP BY platform, name_only, ident
	`, tenantID, platforms, nameOnly, idents, applicationIdentityKinds, signerSentinel, maxDistinctEvidence)
	if err != nil {
		return nil, fmt.Errorf("new software trust evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var g productGroup
		var f trustFacts
		if err := rows.Scan(&g.platform, &g.nameOnly, &g.ident, &f.Installations, &f.DisplayNameOnly,
			&f.SignerReported, &f.SignerUnestablished, &f.ExplicitUnsigned, &f.ExplicitAdhoc,
			&f.ExplicitUntrusted, &f.ExplicitInvalid,
			&f.NotarisedTrue, &f.Signers,
			&f.TeamInstallations, &f.TeamIDs, &f.PublisherInstallations, &f.Publishers,
			&f.SignatureValid, &f.SignatureInvalid, &f.SignatureUnknown, &f.SignatureValidSigned,
			&f.AuthenticodeSigners, &f.SignatureUnsigned, &f.RootPublic, &f.RootPublicPinned,
			&f.AuthenticodeRoots, &f.RootEnterprise, &f.RootLegacy); err != nil {
			return nil, fmt.Errorf("scan new software trust evidence: %w", err)
		}
		out[g] = f
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate new software trust evidence: %w", err)
	}
	return out, nil
}
