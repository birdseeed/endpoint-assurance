package softwaregov

import (
	"context"
	"fmt"
	"sort"
	"time"

	"patched.im/api/internal/deviceretirement"
)

// New software: products first seen on the tenant within a window.
//
// "First seen on the tenant" is the earliest software_installations
// first_seen_at for the product across every device, including
// installations since removed. A product that was installed, removed and
// installed again is therefore not new. software_installations is the
// normalised installation projection (0111); only application identity kinds
// are read here, so Homebrew and developer tooling (which have their own
// views) do not appear.
//
// The window starts at an explicit date, or at the tenant's last review: the
// most recent approval decision any customer user recorded
// (software_approval_decisions, PAT-2007). PAT-2093's urgency reuses this
// query and LastReviewAt for the overview (newsoftware_urgency.go) rather than
// adding fields here.

// applicationIdentityKinds is an allowlist of the application kinds the
// extractor writes (internal/extractor/software_inventory.go).
var applicationIdentityKinds = []string{
	"macos_bundle_team", "macos_bundle",
	"windows_winget", "windows_native_publisher", "windows_native",
	"name_publisher", "display_name",
}

// MaxNewSoftwareProducts caps one response. Truncated says when it bound.
const MaxNewSoftwareProducts = 1000

// Since bases.
const (
	SinceQuery      = "query"       // the caller gave a date
	SinceLastReview = "last_review" // the tenant's most recent approval decision
	SinceNoReview   = "no_review"   // no decision ever recorded: everything is new
	SinceWindow     = "window"      // a notification window
)

// FirstDevice is the device a product was first seen on.
type FirstDevice struct {
	DeviceID    string    `json:"device_id"`
	Hostname    string    `json:"hostname"`
	FirstSeenAt time.Time `json:"first_seen_at"`
	// StillInstalled is false when that installation has since been removed.
	StillInstalled bool `json:"still_installed"`
}

// NewProduct is one product first seen in the window.
type NewProduct struct {
	Type     string `json:"type,omitempty"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	// Identifier is the normalised identifier, or the normalised name when
	// the product is known by name only.
	Identifier string `json:"identifier"`
	TeamID     string `json:"team_id,omitempty"`
	// IdentityBasis is "identifier", or "name_only" when the endpoint
	// reported no identifier. A name-only product has no ProductKey and
	// cannot be given an approval decision (PAT-2007 refuses it).
	IdentityBasis     string    `json:"identity_basis"`
	ProductKey        *string   `json:"product_key"`
	ApprovalState     string    `json:"approval_state"`
	ObservationKind   string    `json:"observation_kind,omitempty"`
	ObservationSource string    `json:"observation_source,omitempty"`
	FirstSeenAt       time.Time `json:"first_seen_at"`
	// DeviceCount is devices with the product installed now.
	DeviceCount int         `json:"device_count"`
	FirstDevice FirstDevice `json:"first_device"`
}

// NewSoftware is GET /v1/portal/software/new.
type NewSoftware struct {
	GeneratedAt  time.Time    `json:"generated_at"`
	Since        *time.Time   `json:"since"`
	SinceBasis   string       `json:"since_basis"`
	Until        time.Time    `json:"until"`
	LastReviewAt *time.Time   `json:"last_review_at"`
	Coverage     Coverage     `json:"coverage"`
	Total        int          `json:"total"`
	Truncated    bool         `json:"truncated"`
	Products     []NewProduct `json:"products"`
}

// LastReviewAt is the time of the most recent approval write by any
// customer user, or nil when there has never been one.
func LastReviewAt(ctx context.Context, q Querier, tenantID string) (*time.Time, error) {
	var t *time.Time
	if err := q.QueryRow(ctx, `
		SELECT max(decided_at) FROM software_approval_decisions WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&t); err != nil {
		return nil, fmt.Errorf("last review lookup: %w", err)
	}
	if t != nil {
		u := t.UTC()
		t = &u
	}
	return t, nil
}

// FetchNewSoftware lists products first seen after since (exclusive) and at
// or before until. since nil means from the tenant's last review.
func FetchNewSoftware(ctx context.Context, q Querier, tenantID string, since *time.Time, until time.Time) (NewSoftware, error) {
	until = until.UTC()
	out := NewSoftware{GeneratedAt: until, Until: until, Products: []NewProduct{}}
	last, err := LastReviewAt(ctx, q, tenantID)
	if err != nil {
		return out, err
	}
	out.LastReviewAt = last
	switch {
	case since != nil:
		s := since.UTC()
		out.Since, out.SinceBasis = &s, SinceQuery
	case last != nil:
		out.Since, out.SinceBasis = last, SinceLastReview
	default:
		out.SinceBasis = SinceNoReview
	}
	return fetchNewSoftwareWithTooling(ctx, q, tenantID, out, true)
}

// FetchNewSoftwareWindow is the notification form: (from, until].
func FetchNewSoftwareWindow(ctx context.Context, q Querier, tenantID string, from, until time.Time) (NewSoftware, error) {
	f, u := from.UTC(), until.UTC()
	out := NewSoftware{GeneratedAt: u, Until: u, Since: &f, SinceBasis: SinceWindow, Products: []NewProduct{}}
	return fetchNewSoftwareWithTooling(ctx, q, tenantID, out, true)
}

// FetchNewAIToolingWindow returns only named, decision-safe tooling identities.
// It has its own cap so a busy application window cannot consume the AI
// notification's rows before the independent cursor advances.
func FetchNewAIToolingWindow(ctx context.Context, q Querier, tenantID string, from, until time.Time) (NewSoftware, error) {
	f, u := from.UTC(), until.UTC()
	out := NewSoftware{GeneratedAt: u, Until: u, Since: &f, SinceBasis: SinceWindow, Products: []NewProduct{}}
	// Reuse the established coverage calculation, but discard its application
	// rows before loading tooling against its own bound.
	covered, err := fetchNewSoftwareWithTooling(ctx, q, tenantID, out, false)
	if err != nil {
		return out, err
	}
	out.Coverage = covered.Coverage
	pol, err := loadPolicies(ctx, q, tenantID)
	if err != nil {
		return out, err
	}
	if err := appendNewTooling(ctx, q, tenantID, out.Since, out.Until, pol, &out); err != nil {
		return out, err
	}
	if len(out.Products) > MaxNewSoftwareProducts {
		out.Products = out.Products[:MaxNewSoftwareProducts]
	}
	out.Truncated = out.Total > len(out.Products)
	return out, nil
}

// fetchNewSoftwareWithTooling keeps tooling in the full review endpoint, but
// lets the application-only urgency model avoid a newer tooling row consuming
// an application's capped review slot.
func fetchNewSoftwareWithTooling(ctx context.Context, q Querier, tenantID string, out NewSoftware, includeTooling bool) (NewSoftware, error) {
	coverageEstate := Estate{AsOf: out.Until}
	var oldest *time.Time
	if err := q.QueryRow(ctx, `
		SELECT count(*)::int,
		       count(*) FILTER (WHERE NOT r.retired AND d.last_seen < $2)::int,
		       count(*) FILTER (WHERE NOT r.retired AND NOT EXISTS (
		           SELECT 1 FROM software_installations si
		           WHERE si.device_id = d.id AND si.tenant_id = d.tenant_id
		             AND si.identity_kind = ANY($3)))::int,
		       min(d.last_seen) FILTER (WHERE NOT r.retired),
		       count(*) FILTER (WHERE r.retired)::int
		FROM devices d
		CROSS JOIN LATERAL (SELECT `+deviceretirement.RetiredSQL("d")+` AS retired) r
		WHERE d.tenant_id = $1::uuid
	`, tenantID, out.Until.Add(-StaleAfter), applicationIdentityKinds).Scan(
		&coverageEstate.DevicesTotal, &coverageEstate.DevicesStale, &coverageEstate.DevicesWithoutInventory, &oldest,
		&coverageEstate.DevicesRetired); err != nil {
		return out, fmt.Errorf("new software coverage: %w", err)
	}
	if oldest != nil {
		o := oldest.UTC()
		coverageEstate.OldestDeviceLastSeen = &o
	}
	out.Coverage = CoverageOf(coverageEstate)
	// A fresh application snapshot cannot establish absence for developer
	// tooling. Keep application Complete unchanged for the urgency model, but
	// expose unavailable tooling evidence so combined review/drift callers do
	// not infer that missing tooling is absent.
	if err := q.QueryRow(ctx, `
		SELECT count(*)::int
		FROM devices d
		CROSS JOIN LATERAL (SELECT `+deviceretirement.RetiredSQL("d")+` AS retired) r
		WHERE d.tenant_id = $1::uuid AND NOT r.retired
		  AND (SELECT count(*) FROM tooling_device_state s
		       WHERE s.tenant_id = d.tenant_id AND s.device_id = d.id
		         AND s.block IN ('ide_extensions', 'package_managers', 'local_models', 'mcp_servers')
		         AND s.collection_status IN ('complete', 'not_present')
		         AND COALESCE(s.truncated, FALSE) = FALSE
		         AND s.reported_at > '-infinity'::timestamptz
		         AND NOT EXISTS (
				 SELECT 1 FROM jsonb_each_text(COALESCE(s.unit_statuses, '{}'::jsonb)) u
				 WHERE u.value NOT IN ('complete', 'not_present')
			 )
		      ) <> 4
	`, tenantID).Scan(&out.Coverage.DevicesWithUnavailableTooling); err != nil {
		return out, fmt.Errorf("new software tooling coverage: %w", err)
	}
	out.Coverage.ToolingEvidenceComplete = out.Coverage.DevicesWithUnavailableTooling == 0

	pol, err := loadPolicies(ctx, q, tenantID)
	if err != nil {
		return out, err
	}

	rows, err := q.Query(ctx, `
		WITH inst AS (
			SELECT si.platform, si.identity_kind, si.identity_value_normalized AS ident,
			       si.companion_value_normalized AS companion, si.device_id, si.first_seen_at,
			       si.removed_at, si.current_name,
			       si.identity_kind IN ('name_publisher', 'display_name') AS name_only
			FROM software_installations si
			WHERE si.tenant_id = $1::uuid
			  AND si.identity_kind = ANY($2)
		), grouped AS (
			SELECT platform, name_only, ident,
			       min(first_seen_at) AS first_seen_at,
			       count(DISTINCT device_id) FILTER (WHERE removed_at IS NULL)::int AS device_count,
			       COALESCE(max(companion) FILTER (WHERE identity_kind = 'macos_bundle_team'), '') AS team_id,
			       bool_or(identity_kind = 'windows_winget') AS winget,
			       COALESCE(min(current_name) FILTER (WHERE removed_at IS NULL), min(current_name)) AS name
			FROM inst
			GROUP BY platform, name_only, ident
		), windowed AS (
			SELECT * FROM grouped
			WHERE ($3::timestamptz IS NULL OR first_seen_at > $3::timestamptz)
			  AND first_seen_at <= $4::timestamptz
		)
		SELECT w.platform, w.name_only, w.ident, w.team_id, w.winget, w.name, w.first_seen_at, w.device_count,
		       fd.device_id::text, COALESCE(fd.hostname, ''), fd.first_seen_at, fd.removed_at IS NULL,
		       count(*) OVER ()::int
		FROM windowed w
		JOIN LATERAL (
			SELECT i.device_id, d.hostname, i.first_seen_at, i.removed_at
			FROM inst i
			JOIN devices d ON d.id = i.device_id AND d.tenant_id = $1::uuid
			WHERE i.platform = w.platform AND i.name_only = w.name_only AND i.ident = w.ident
			ORDER BY i.first_seen_at, i.device_id
			LIMIT 1
		) fd ON true
		ORDER BY w.first_seen_at DESC, w.name, w.ident, w.platform
		LIMIT $5
	`, tenantID, applicationIdentityKinds, out.Since, out.Until, MaxNewSoftwareProducts)
	if err != nil {
		return out, fmt.Errorf("new software query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var p NewProduct
		var nameOnly, winget bool
		if err := rows.Scan(&p.Platform, &nameOnly, &p.Identifier, &p.TeamID, &winget, &p.Name, &p.FirstSeenAt,
			&p.DeviceCount, &p.FirstDevice.DeviceID, &p.FirstDevice.Hostname, &p.FirstDevice.FirstSeenAt,
			&p.FirstDevice.StillInstalled, &out.Total); err != nil {
			return out, fmt.Errorf("scan new software: %w", err)
		}
		p.FirstSeenAt = p.FirstSeenAt.UTC()
		p.FirstDevice.FirstSeenAt = p.FirstDevice.FirstSeenAt.UTC()
		p.TeamID = normalisedTeamID(p.Platform, p.TeamID)
		if nameOnly {
			p.IdentityBasis = "name_only"
			p.TeamID = ""
			// Only a name policy can match a product with no identifier.
			state, _ := pol.resolveApp("", "", "", p.Name, p.Platform)
			p.ApprovalState = state
		} else {
			p.IdentityBasis = "identifier"
			key := ApplicationKey(p.Platform, p.Identifier, p.TeamID)
			p.ProductKey = &key
			kind := ""
			if winget {
				kind = "winget"
			}
			state, _ := pol.resolveApp(p.TeamID, p.Identifier, kind, p.Name, p.Platform)
			p.ApprovalState = state
		}
		out.Products = append(out.Products, p)
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("iterate new software: %w", err)
	}
	if includeTooling {
		if err := appendNewTooling(ctx, q, tenantID, out.Since, out.Until, pol, &out); err != nil {
			return out, err
		}
	}
	if len(out.Products) > MaxNewSoftwareProducts {
		out.Products = out.Products[:MaxNewSoftwareProducts]
		out.Truncated = true
	}
	out.Truncated = out.Total > len(out.Products)
	return out, nil
}

// appendNewTooling adds current, named PAT-2021 identities to the same
// review window as applications. Current-entry authority is essential here:
// a failed or stale tooling block cannot make a vanished package look newly
// installed, and no unidentified identity is a decision target.
func appendNewTooling(ctx context.Context, q Querier, tenantID string, since *time.Time, until time.Time, pol policies, out *NewSoftware) error {
	rows, err := q.Query(ctx, `
		WITH current AS (
			SELECT c.device_id, so.identity_kind, so.identity_value_normalized AS name,
			       so.companion_value_normalized AS source, so.identity_fingerprint
			FROM tooling_current_entries c
			JOIN tooling_device_state s ON s.device_id = c.device_id AND s.tenant_id = c.tenant_id AND s.block = c.block
			JOIN software_observations so ON so.id = c.observation_id AND so.tenant_id = c.tenant_id
			WHERE c.tenant_id = $1::uuid
			  AND s.collection_status IN ('complete', 'partial', 'not_present')
			  AND COALESCE(s.unit_statuses ->> c.unit, s.collection_status) IN ('complete', 'partial', 'not_present')
			  AND c.observed_at >= COALESCE((s.authority ->> c.unit)::timestamptz, '-infinity'::timestamptz)
			  AND so.identity_kind IN ('ide_extension', 'npm_package', 'pip_package',
			                           'local_model', 'local_model_runtime', 'mcp_server')
		), history AS (
			SELECT identity_kind, identity_value_normalized AS name,
			       companion_value_normalized AS source, min(first_seen_at) AS first_seen_at
			FROM software_installations
			WHERE tenant_id = $1::uuid
			  AND identity_kind IN ('ide_extension', 'npm_package', 'pip_package',
			                        'local_model', 'local_model_runtime', 'mcp_server')
			GROUP BY identity_kind, identity_value_normalized, companion_value_normalized
		), grouped AS (
			SELECT c.identity_kind, c.name, c.source, min(h.first_seen_at) AS first_seen_at,
			       count(DISTINCT c.device_id)::int AS device_count,
			       min(si.current_name) AS display_name
			FROM current c
			JOIN history h ON h.identity_kind = c.identity_kind AND h.name = c.name AND h.source = c.source
			JOIN software_installations si ON si.tenant_id = $1::uuid AND si.device_id = c.device_id
			                            AND si.identity_fingerprint = c.identity_fingerprint AND si.removed_at IS NULL
			GROUP BY c.identity_kind, c.name, c.source
		), windowed AS (
			SELECT * FROM grouped WHERE ($2::timestamptz IS NULL OR first_seen_at > $2::timestamptz)
			  AND first_seen_at <= $3::timestamptz
		)
		SELECT w.identity_kind, w.name, w.source, w.display_name, w.first_seen_at, w.device_count,
		       fd.device_id::text, COALESCE(d.hostname, ''), fd.first_seen_at, fd.still_installed,
		       count(*) OVER ()::int
		FROM windowed w
		JOIN LATERAL (
			SELECT si.device_id, si.first_seen_at, si.removed_at IS NULL AS still_installed
			FROM software_installations si
			WHERE si.tenant_id = $1::uuid AND si.identity_kind = w.identity_kind
			  AND si.identity_value_normalized = w.name AND si.companion_value_normalized = w.source
			ORDER BY si.first_seen_at, si.device_id LIMIT 1
		) fd ON true
		JOIN devices d ON d.id = fd.device_id AND d.tenant_id = $1::uuid
		ORDER BY w.first_seen_at DESC, w.display_name, w.identity_kind, w.name, w.source
		LIMIT $4
	`, tenantID, since, until, MaxNewSoftwareProducts+1)
	if err != nil {
		return fmt.Errorf("new tooling query: %w", err)
	}
	defer rows.Close()
	tooling := []NewProduct{}
	toolingTotal := 0
	for rows.Next() {
		var p NewProduct
		if err := rows.Scan(&p.ObservationKind, &p.Identifier, &p.ObservationSource, &p.Name, &p.FirstSeenAt, &p.DeviceCount,
			&p.FirstDevice.DeviceID, &p.FirstDevice.Hostname, &p.FirstDevice.FirstSeenAt, &p.FirstDevice.StillInstalled, &toolingTotal); err != nil {
			return fmt.Errorf("scan new tooling: %w", err)
		}
		p.Type = TypeObservation
		p.Platform = ""
		p.IdentityBasis = "observation"
		p.FirstSeenAt = p.FirstSeenAt.UTC()
		p.FirstDevice.FirstSeenAt = p.FirstDevice.FirstSeenAt.UTC()
		key := ObservationKey(p.ObservationKind, p.Identifier, p.ObservationSource)
		p.ProductKey = &key
		p.ApprovalState, _ = pol.resolveObservation(p.ObservationKind, p.Identifier, p.ObservationSource)
		tooling = append(tooling, p)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate new tooling: %w", err)
	}
	out.Total += toolingTotal
	out.Products = append(out.Products, tooling...)
	sort.SliceStable(out.Products, func(i, j int) bool {
		if !out.Products[i].FirstSeenAt.Equal(out.Products[j].FirstSeenAt) {
			return out.Products[i].FirstSeenAt.After(out.Products[j].FirstSeenAt)
		}
		if out.Products[i].Name != out.Products[j].Name {
			return out.Products[i].Name < out.Products[j].Name
		}
		return out.Products[i].Identifier < out.Products[j].Identifier
	})
	return nil
}
