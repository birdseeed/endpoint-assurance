package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvepipeline"
	"patched.im/api/internal/report"
)

type portalSoftwareCoverage struct {
	InstallationCount int `json:"installation_count"`
	MeteredCount      int `json:"metered_installation_count"`
	UnmeteredCount    int `json:"unmetered_installation_count"`
	StaleCount        int `json:"stale_installation_count"`
	UnusedCount       int `json:"unused_installation_count"`
	// NoEvidenceCount (PAT-2327) is additive: fresh, metered installations
	// with no usable last-use evidence. Not unused.
	NoEvidenceCount int `json:"no_evidence_installation_count"`
}

type portalSoftwareProduct struct {
	Name                            string     `json:"name"`
	Names                           []string   `json:"names"`
	Identifier                      string     `json:"identifier"`
	Platform                        string     `json:"platform"`
	Versions                        []string   `json:"versions"`
	UnknownVersionInstallationCount int        `json:"unknown_version_installation_count"`
	DeviceCount                     int        `json:"device_count"`
	InstallationCount               int        `json:"installation_count"`
	EvidenceAt                      time.Time  `json:"evidence_at"`
	LastUsedAt                      *time.Time `json:"last_used_at"`
	MeteredInstallationCount        int        `json:"metered_installation_count"`
	UnmeteredInstallationCount      int        `json:"unmetered_installation_count"`
	StaleInstallationCount          int        `json:"stale_installation_count"`
	UnusedInstallationCount         int        `json:"unused_installation_count"`
	NoEvidenceInstallationCount     int        `json:"no_evidence_installation_count"`
	UsageState                      string     `json:"usage_state"`
	RemovalCandidate                bool       `json:"removal_candidate"`
	CanonicalKey                    *string    `json:"canonical_key"`
	CanonicalName                   *string    `json:"canonical_name"`
	// TeamID / ProductKey / PolicyState (PAT-2104) are additive identity and
	// governance fields, matching PUT /v1/portal/software-approvals exactly:
	// TeamID is macOS only (null on Windows and whenever the group's
	// installations disagree); ProductKey is the same key that write path
	// computes for this identity; PolicyState is the resolved governance
	// state ("approved"/"unapproved"/"mandatory"/"ignored"), null when
	// undecided or unresolvable. See report.PortalSoftwareProduct's doc
	// comment.
	TeamID      *string `json:"team_id"`
	ProductKey  *string `json:"product_key"`
	PolicyState *string `json:"policy_state"`
	// CVEAssessment (PAT-2028) is additive: normally the estate-wide CVE
	// assessment state for this product, rolled up across every installation
	// in the tenant. On a ?device_id= request (PAT-2156) this is instead
	// scoped to that device's own installed versions of the product — see
	// cvepipeline.AssessEstateProductsForDevice. finding_count is null
	// unless the product has CPE mapping coverage; see docs/API.md and
	// cvepipeline.EstateAssessment.
	CVEAssessment cvepipeline.EstateAssessment `json:"cve_assessment"`
	// FirstSeenOnDevice (PAT-2156) is only present on a ?device_id= response
	// — the earliest device_apps.first_seen for this product on that
	// device. Omitted entirely (not null) on the unfiltered page, so that
	// response's JSON shape is unchanged from before PAT-2156.
	FirstSeenOnDevice *time.Time `json:"first_seen_on_device,omitempty"`
}

type portalSoftwareResp struct {
	GeneratedAt time.Time               `json:"generated_at"`
	Total       int                     `json:"total"`
	Limit       int                     `json:"limit"`
	Offset      int                     `json:"offset"`
	Coverage    portalSoftwareCoverage  `json:"coverage"`
	Products    []portalSoftwareProduct `json:"products"`
}

// PortalSoftwareHandler is the paginated tenant inventory and metering view.
// Tenant scope comes only from the verified portal identity. This endpoint is
// intentionally not based on the capped policy applications query.
//
// PAT-2156: an optional ?device_id= query param narrows the page to that
// device's own current installations. It is validated against the verified
// tenant BEFORE any inventory query runs: a malformed UUID is a 400, and an
// unknown device or one owned by another tenant is a 404 — deliberately the
// SAME 404 for both, so this endpoint can never be used as a cross-tenant
// device-existence oracle (the same rule PortalDeviceDetailHandler and
// PortalHomebrewDeviceHandler already follow for a path-form deviceID).
func PortalSoftwareHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		search := strings.TrimSpace(r.URL.Query().Get("search"))
		if len(search) > 256 {
			http.Error(w, "search must be at most 256 characters", http.StatusBadRequest)
			return
		}
		limit, offset := parsePagination(r)
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_software", "tenant_id", id.TenantID)

		deviceID := strings.TrimSpace(r.URL.Query().Get("device_id"))
		if deviceID != "" {
			if !looksLikeUUID(deviceID) {
				http.Error(w, "device_id must be a UUID", http.StatusBadRequest)
				return
			}
			owner, err := report.DeviceTenant(r.Context(), pool, deviceID)
			if err != nil || owner != id.TenantID {
				if err != nil && !errors.Is(err, report.ErrDeviceNotFound) {
					logger.Error("device ownership check failed", "err", err)
					http.Error(w, "internal error", http.StatusInternalServerError)
					return
				}
				// Not found and not-yours are deliberately indistinguishable.
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
		}

		var page report.PortalSoftwarePage
		var err error
		if deviceID != "" {
			page, err = report.FetchPortalSoftwareForDevice(r.Context(), pool, id.TenantID, deviceID, search, limit, offset)
		} else {
			page, err = report.FetchPortalSoftware(r.Context(), pool, id.TenantID, search, limit, offset)
		}
		if err != nil {
			logger.Error("fetch portal software failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		keys := make([]cvepipeline.EstateProductKey, 0, len(page.Products))
		for _, product := range page.Products {
			keys = append(keys, cvepipeline.EstateProductKey{Identifier: product.Identifier, Platform: product.Platform})
		}
		var assessments map[cvepipeline.EstateProductKey]cvepipeline.EstateAssessment
		if deviceID != "" {
			// PAT-2156: scoped to this device's own installed versions, not
			// rolled up across the whole tenant estate — see
			// cvepipeline.AssessEstateProductsForDevice's doc comment for why
			// AssessEstateProducts itself is wrong for a device-filtered row.
			assessments, err = cvepipeline.AssessEstateProductsForDevice(r.Context(), pool, id.TenantID, deviceID, keys)
		} else {
			assessments, err = cvepipeline.AssessEstateProducts(r.Context(), pool, id.TenantID, keys)
		}
		if err != nil {
			logger.Error("fetch cve assessment failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(portalSoftwareResponse(page, assessments, limit, offset)); err != nil {
			logger.Warn("encode portal software response failed", "err", err)
		}
	}
}

// portalSoftwareResponse keeps the response timestamp tied to the single
// instant used for query freshness and unused-horizon evaluation.
func portalSoftwareResponse(page report.PortalSoftwarePage, assessments map[cvepipeline.EstateProductKey]cvepipeline.EstateAssessment, limit, offset int) portalSoftwareResp {
	products := make([]portalSoftwareProduct, 0, len(page.Products))
	for _, product := range page.Products {
		key := cvepipeline.EstateProductKey{Identifier: product.Identifier, Platform: product.Platform}
		products = append(products, portalSoftwareProduct{
			Name: product.Name, Names: product.Names, Identifier: product.Identifier,
			Platform: product.Platform, Versions: product.Versions,
			UnknownVersionInstallationCount: product.UnknownVersionInstallationCount,
			DeviceCount:                     product.DeviceCount, InstallationCount: product.InstallationCount,
			EvidenceAt: product.EvidenceAt, LastUsedAt: product.LastUsedAt,
			MeteredInstallationCount:    product.MeteredInstallationCount,
			UnmeteredInstallationCount:  product.UnmeteredInstallationCount,
			StaleInstallationCount:      product.StaleInstallationCount,
			UnusedInstallationCount:     product.UnusedInstallationCount,
			NoEvidenceInstallationCount: product.NoEvidenceInstallationCount,
			UsageState:                  product.UsageState, RemovalCandidate: product.RemovalCandidate,
			FirstSeenOnDevice: product.FirstSeenOnDevice,
			CanonicalKey:      product.CanonicalKey, CanonicalName: product.CanonicalName,
			TeamID: product.TeamID, ProductKey: product.ProductKey, PolicyState: product.PolicyState,
			CVEAssessment: cvepipeline.EstateAssessmentOrNotAssessed(assessments, key),
		})
	}
	return portalSoftwareResp{
		GeneratedAt: page.GeneratedAt, Total: page.Total, Limit: limit, Offset: offset,
		Coverage: portalSoftwareCoverage{InstallationCount: page.Coverage.InstallationCount,
			MeteredCount: page.Coverage.MeteredCount, UnmeteredCount: page.Coverage.UnmeteredCount,
			StaleCount: page.Coverage.StaleCount, UnusedCount: page.Coverage.UnusedCount,
			NoEvidenceCount: page.Coverage.NoEvidenceCount},
		Products: products,
	}
}
