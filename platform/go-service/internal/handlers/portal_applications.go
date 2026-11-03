// GET /v1/portal/applications (PAT-1727) — the tenant's applications with a
// policy state (approved / unapproved / any other configured policy value /
// undecided), so the portal can show the full software-governance picture
// alongside GET /v1/portal/extensions in one table. Leaves
// GET /v1/portal/unapproved-apps unchanged; the live portal still consumes
// it.
package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/report"
)

type portalApplicationEntry struct {
	Type       string `json:"type"`
	Name       string `json:"name"`
	Identifier string `json:"identifier,omitempty"`
	// PolicyTeamID / ProductKey (PAT-2104, policy rows only): the identity
	// PUT /v1/portal/software-approvals needs to change this exact row
	// again. Both nil for an undecided row and for a policy row the write
	// schema cannot address (name-only, winget-keyed, "any"-platform, or a
	// malformed team_id) — see report.PortalApplication's doc comment.
	// PolicyTeamID is deliberately not the same value as TeamID below: see
	// that doc comment for why they can diverge.
	PolicyTeamID *string `json:"policy_team_id,omitempty"`
	ProductKey   *string `json:"product_key,omitempty"`
	Platform     string  `json:"platform"`
	// PolicyState is one of the tenant_app_policies.policy values
	// (mandatory / approved / unapproved / unmanaged) or "undecided" — see
	// contracts/portal-api.md.
	PolicyState string `json:"policy_state"`
	// EnforcementTier carries the retired internal tier vocabulary and is
	// never populated for an "undecided" row — see the equivalent warning on
	// GET /v1/portal/unapproved-apps in contracts/portal-api.md.
	EnforcementTier        string `json:"enforcement_tier,omitempty"`
	DeviceCount            int    `json:"device_count"`
	EvidenceBasis          string `json:"evidence_basis"`
	IdentifierMatchedCount int    `json:"identifier_matched_devices"`
	NameMatchedCount       int    `json:"name_matched_devices"`
	RemovalState           string `json:"removal_state"`
	// VersionCount (PAT-1799) is the exact distinct-version count across
	// the devices behind DeviceCount — "N devices on M versions".
	VersionCount int `json:"version_count"`
	// TeamID / SignedBy / Notarized (PAT-1799): macOS codesign signing
	// state. null means genuinely unknown (no signing evidence collected —
	// always the case for a Windows row today), never a false
	// "unsigned"/"not notarized" verdict. See report.AppPolicyRow's doc
	// comment for why.
	TeamID    *string `json:"team_id"`
	SignedBy  *string `json:"signed_by"`
	Notarized *bool   `json:"notarized"`
	// LatestKnownVersion / DevicesBehindCount (PAT-1728): the catalog
	// "devices behind" comparison, populated only for policy_state
	// "approved"/"mandatory" rows with a matching app_catalog_entries
	// product. Both null (never a guessed 0) when there is no trustworthy
	// latest version to compare against — see report.PortalApplication's
	// doc comment.
	LatestKnownVersion *string `json:"latest_known_version"`
	DevicesBehindCount *int    `json:"devices_behind_count"`
	// DecidedBy / DecidedAt / Justification (PAT-1800): who decided this
	// row's policy_state, when, and why. All three null when there is no
	// decision record to show — see report.PortalApplication's doc comment
	// for exactly which table each is sourced from per row kind, and
	// contracts/portal-api.md for the customer-facing contract.
	DecidedBy     *string    `json:"decided_by"`
	DecidedAt     *time.Time `json:"decided_at"`
	Justification *string    `json:"justification"`
}

type portalApplicationsResp struct {
	GeneratedAt time.Time `json:"generated_at"`
	Total       int       `json:"total"`
	Truncated   bool      `json:"truncated"`
	// EstateTooLarge (PAT-1727): true only when the undecided-application
	// fail-closed source-row cap fired — see
	// report.PortalApplicationsResult's doc comment. Policy rows (approved /
	// unapproved / …) are still present in this case; only undecided rows
	// are withheld.
	EstateTooLarge bool                     `json:"estate_too_large"`
	Applications   []portalApplicationEntry `json:"applications"`
}

// PortalApplicationsHandler returns the tenant's applications with a policy
// state (PAT-1727): every configured tenant_app_policies row plus every
// installed application matching none of them ("undecided"). See
// contracts/portal-api.md.
func PortalApplicationsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_applications", "tenant_id", id.TenantID)

		res, err := report.FetchPortalApplications(r.Context(), pool, id.TenantID)
		if err != nil {
			logger.Error("fetch portal applications failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if res.EstateTooLarge {
			// Same rationale as PortalExtensionsHandler's equivalent log
			// line: otherwise silent and indistinguishable in the JSON
			// response from a tenant with zero undecided applications.
			logger.Warn("portal applications fail-closed: undecided source row count at least cap",
				"source_rows_at_least", res.SourceRowCount)
		}

		apps := make([]portalApplicationEntry, 0, len(res.Applications))
		for _, a := range res.Applications {
			apps = append(apps, portalApplicationEntry{
				Type:                   "application",
				Name:                   a.Name,
				Identifier:             a.Identifier,
				PolicyTeamID:           a.PolicyTeamID,
				ProductKey:             a.ProductKey,
				Platform:               a.Platform,
				PolicyState:            a.PolicyState,
				EnforcementTier:        a.EnforcementTier,
				DeviceCount:            a.DeviceCount,
				EvidenceBasis:          a.EvidenceBasis,
				IdentifierMatchedCount: a.IdentifierMatchedCount,
				NameMatchedCount:       a.NameMatchedCount,
				RemovalState:           a.RemovalState,
				VersionCount:           a.VersionCount,
				TeamID:                 a.TeamID,
				SignedBy:               a.SignedBy,
				Notarized:              a.Notarized,
				LatestKnownVersion:     a.LatestKnownVersion,
				DevicesBehindCount:     a.DevicesBehindCount,
				DecidedBy:              a.DecidedBy,
				DecidedAt:              a.DecidedAt,
				Justification:          a.Justification,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalApplicationsResp{
			GeneratedAt:    time.Now().UTC(),
			Total:          res.Total,
			Truncated:      res.Truncated,
			EstateTooLarge: res.EstateTooLarge,
			Applications:   apps,
		})
	}
}
