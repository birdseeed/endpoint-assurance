package handlers

// GET /v1/portal/tagged-products (PAT-2015): the caller's tenant's software
// carrying a live category tag (PAT-2001), grouped by product, with device
// counts, user counts where the inventory has users, first and last seen,
// and approval state read from the existing app and extension policy tables.
//
// Tenant scoping comes only from the authenticated portal identity; there is
// no tenant parameter. The global rule tables are joined for category and
// match basis only and carry no tenant data.
//
// Read-only: approval state is read from tenant_app_policies (apps) and
// tenant_extension_policies (browser extensions), never written here.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/extpresence"
	"patched.im/api/internal/extractor"
	"patched.im/api/internal/softwaregov"
)

// taggedProductsMaxSourceRows fails the endpoint closed (estate_too_large)
// rather than returning a silently partial aggregate.
const taggedProductsMaxSourceRows = 50000

const taggedProductsMaxVersions = 20
const taggedProductsMaxDevices = 100

// extensionPresenceWindowDays is the pre-PAT-2055 extension presence rule,
// kept for devices that have never sent browser_extensions_status. Extension
// rows are never deleted when an extension goes away; every ingest that
// reports it refreshes last_seen. On such a device an extension counts as
// present while its last_seen is within this many days of its device's own
// last report. A device that has stopped reporting keeps its last known
// extensions, as its installations do.
//
// A device that sends the status block gets no window at all: an extension
// is hidden only once an authoritative (complete or not_present, uncapped)
// report for its device, or its own user and browser, arrived after its
// last_seen (extpresence.PresentSQL). A partial report never hides one.
// Either way this only hides the extension here and never retires its tag.
const extensionPresenceWindowDays = 30

var portalCategoryKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

type portalTaggedProduct struct {
	Category          string        `json:"category"`
	Subtype           string        `json:"subtype"`
	ObservationKind   string        `json:"observation_kind"`
	ProductKey        string        `json:"product_key"`
	Name              string        `json:"name"`
	CanonicalName     *string       `json:"canonical_name"`
	Vendor            *string       `json:"vendor"`
	ObservedPublisher *string       `json:"observed_publisher"`
	Identifier        string        `json:"identifier"`
	Browser           *string       `json:"browser"`
	Platforms         []string      `json:"platforms"`
	Versions          []string      `json:"versions"`
	VersionCount      int           `json:"version_count"`
	DeviceCount       int           `json:"device_count"`
	Devices           []string      `json:"devices"`
	DevicesTruncated  bool          `json:"devices_truncated"`
	UserCount         *int          `json:"user_count"`
	FirstSeen         time.Time     `json:"first_seen"`
	LastSeen          time.Time     `json:"last_seen"`
	ApprovalState     string        `json:"approval_state"`
	ApprovalTarget    *approvalItem `json:"approval_target"`
	MatchBasis        []string      `json:"match_basis"`
	// Metering fields apply only to desktop applications. Every other subtype,
	// including app-backed non-desktop observations, says not_applicable:
	// they have no collected launch telemetry, rather than zero usage.
	LastUsedAt                       *time.Time `json:"last_used_at"`
	MeteredInstallationCount         int        `json:"metered_installation_count"`
	UnmeteredInstallationCount       int        `json:"unmetered_installation_count"`
	StaleMeteringInstallationCount   int        `json:"stale_metering_installation_count"`
	UnknownMeteringInstallationCount int        `json:"unknown_metering_installation_count"`
	MeteringState                    string     `json:"metering_state"`

	devices      map[string]bool
	users        map[string]bool
	versions     map[string]bool
	platforms    map[string]bool
	basis        map[string]bool
	approvals    map[string]bool
	targets      map[string]approvalItem
	targetUnsafe bool
	metering     map[string]taggedProductMetering
}

type taggedProductMetering struct {
	state    string
	lastUsed *time.Time
}

type portalTaggedProductsResp struct {
	GeneratedAt         time.Time             `json:"generated_at"`
	Category            *string               `json:"category"`
	Subtype             *string               `json:"subtype"`
	Total               int                   `json:"total"`
	Limit               int                   `json:"limit"`
	Offset              int                   `json:"offset"`
	EstateTooLarge      bool                  `json:"estate_too_large"`
	DistinctDeviceTotal int                   `json:"distinct_device_total"`
	Products            []portalTaggedProduct `json:"products"`
}

// portalTaggedAppsSQL: live tags on present installations. The tenant
// predicate on software_category_tags is the isolation boundary; every other
// join is keyed from it.
const portalTaggedAppsSQL = `
	SELECT COALESCE(r.category_key, pt.category_key), COALESCE(r.subtype_key, pt.subtype_key),
	       COALESCE(r.identifier_type, 'software_product'),
	       t.device_id::text, si.id::text, si.platform, si.identity_fingerprint, si.product_id::text,
	       sp.canonical_name, sp.vendor_name, si.current_name, si.current_version, si.current_publisher,
	       si.first_seen_at, si.last_seen_at,
	       COALESCE(so.observed_identifier, si.identity_value_normalized),
	       COALESCE(so.observed_identifier_kind, ''), COALESCE(so.observed_team_id, ''),
	       COALESCE(d.os, ''), si.identity_kind, si.identity_value_normalized,
	       si.companion_value_normalized, t.observation_kind,
	       lai.identity_kind, lai.identity_value_normalized, lai.companion_value_normalized,
	       COALESCE(lai.current_name, ''), COALESCE(ld.os, ''),
	       usage.last_used_at, usage.last_seen, usage.metering_status
	FROM software_category_tags t
	JOIN software_installations si ON si.id = t.installation_id AND si.tenant_id = t.tenant_id
	JOIN devices d ON d.id = t.device_id AND d.tenant_id = t.tenant_id
	LEFT JOIN software_observations so ON so.id = si.latest_observation_id
	LEFT JOIN software_products sp ON sp.id = si.product_id
	LEFT JOIN software_category_rules r ON r.id = t.rule_id
	LEFT JOIN software_category_product_tags pt ON pt.id = t.product_tag_id
	LEFT JOIN homebrew_cask_app_links l ON l.cask_installation_id = si.id
	LEFT JOIN software_installations lai ON lai.id = l.app_installation_id
	  AND lai.tenant_id = si.tenant_id AND lai.removed_at IS NULL
	LEFT JOIN devices ld ON ld.id = lai.device_id AND ld.tenant_id = lai.tenant_id
	-- Usage is joined only through the current installation's own immutable
	-- observation identifier and version. In particular, current_name is not
	-- a join key: matching a display name would invent cross-contract usage.
	LEFT JOIN LATERAL (
		SELECT CASE WHEN da.usage_evidence IS NULL OR da.usage_evidence = 'recorded' THEN da.last_used_at END AS last_used_at,
		       COALESCE(da.usage_evidence_at, da.last_seen) AS last_seen,
		       CASE WHEN da.usage_evidence IN ('unmapped', 'unavailable') THEN 'unavailable' ELSE d.metering_status END AS metering_status
		FROM device_apps da
		WHERE da.device_id = si.device_id
		  AND NULLIF(btrim(so.observed_identifier), '') IS NOT NULL
		  AND lower(btrim(da.identifier)) = lower(btrim(so.observed_identifier))
		  AND NULLIF(btrim(da.version), '') IS NOT DISTINCT FROM NULLIF(btrim(si.current_version), '')
		  AND da.last_seen >= si.last_seen_at
		ORDER BY da.last_seen DESC, da.id DESC
		LIMIT 1
	) usage ON true
	WHERE t.tenant_id = $1::uuid
	  AND t.retired_at IS NULL
	  AND t.installation_id IS NOT NULL
	  AND si.removed_at IS NULL
	  AND (si.identity_kind NOT IN ('ide_extension', 'npm_package', 'pip_package', 'local_model', 'local_model_runtime', 'mcp_server')
	       OR EXISTS (
		   SELECT 1 FROM tooling_current_entries tc
		   JOIN tooling_device_state ts ON ts.device_id = tc.device_id AND ts.tenant_id = tc.tenant_id AND ts.block = tc.block
		   WHERE tc.tenant_id = t.tenant_id AND tc.device_id = si.device_id
		     AND tc.observation_id = si.latest_observation_id
		     AND ts.collection_status IN ('complete', 'partial', 'not_present')
		     AND COALESCE(ts.unit_statuses ->> tc.unit, ts.collection_status) IN ('complete', 'partial', 'not_present')
		     AND tc.observed_at >= COALESCE((ts.authority ->> tc.unit)::timestamptz, '-infinity'::timestamptz)
	   ))
	  AND COALESCE(r.state, pt.state) = 'published'
	  AND ($2 = '' OR COALESCE(r.category_key, pt.category_key) = $2)
	  AND ($3 = '' OR COALESCE(r.subtype_key, pt.subtype_key) = $3)
	LIMIT $4`

var portalTaggedExtensionsSQL = `
	SELECT r.category_key, r.subtype_key, r.identifier_type,
	       t.device_id::text, dbe.browser, dbe.extension_id, dbe.name, dbe.version, dbe.user_account,
	       dbe.first_seen, dbe.last_seen,
	       COALESCE(d.os, ''),
	       (SELECT p.policy FROM tenant_extension_policies p
	         WHERE p.tenant_id = t.tenant_id AND p.extension_id = dbe.extension_id
	           AND (p.browser = dbe.browser OR p.browser = 'any')
	         ORDER BY (p.browser = dbe.browser) DESC LIMIT 1)
	FROM software_category_tags t
	JOIN device_browser_extensions dbe ON dbe.id = t.browser_extension_id AND dbe.device_id = t.device_id
	JOIN devices d ON d.id = t.device_id AND d.tenant_id = t.tenant_id
	JOIN software_category_rules r ON r.id = t.rule_id
	WHERE t.tenant_id = $1::uuid
	  AND t.retired_at IS NULL
	  AND t.observation_kind = 'browser_extension'
	  AND r.state = 'published'
	  AND ` + extpresence.PresentSQL("dbe", "dbe.last_seen >= d.last_seen - make_interval(days => $5)") + `
	  AND ($2 = '' OR r.category_key = $2)
	  AND ($3 = '' OR r.subtype_key = $3)
	LIMIT $4`

func devicePlatformLabel(os string) string {
	o := strings.ToLower(strings.TrimSpace(os))
	switch {
	case strings.HasPrefix(o, "windows"):
		return "windows"
	case strings.HasPrefix(o, "mac"), strings.HasPrefix(o, "darwin"):
		return "macos"
	}
	return "unknown"
}

func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// PortalTaggedProductsHandler serves GET /v1/portal/tagged-products.
func PortalTaggedProductsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, ok := identity(w, r)
		if !ok {
			return
		}
		logger := slog.With("req_id", middleware.GetReqID(r.Context()),
			"handler", "portal_tagged_products", "tenant_id", id.TenantID)

		q := r.URL.Query()
		category, subtype := strings.TrimSpace(q.Get("category")), strings.TrimSpace(q.Get("subtype"))
		if (category != "" && !portalCategoryKeyPattern.MatchString(category)) ||
			(subtype != "" && !portalCategoryKeyPattern.MatchString(subtype)) {
			http.Error(w, "category and subtype must be keys", http.StatusBadRequest)
			return
		}
		limit, offset := 200, 0
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 1000 {
				http.Error(w, "limit must be 1 to 1000", http.StatusBadRequest)
				return
			}
			limit = n
		}
		if v := q.Get("offset"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 {
				http.Error(w, "offset must be 0 or more", http.StatusBadRequest)
				return
			}
			offset = n
		}

		products, tooLarge, err := fetchTaggedProducts(r.Context(), pool, id.TenantID, category, subtype)
		if err != nil {
			logger.Error("fetch tagged products failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if tooLarge {
			logger.Warn("portal tagged products fail-closed: source rows at least cap",
				"max_source_rows", taggedProductsMaxSourceRows)
		}
		total := len(products)
		page := []portalTaggedProduct{}
		if offset < total {
			end := offset + limit
			if end > total {
				end = total
			}
			page = products[offset:end]
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(portalTaggedProductsResp{
			GeneratedAt: time.Now().UTC(), Category: optionalString(category), Subtype: optionalString(subtype),
			Total: total, Limit: limit, Offset: offset, EstateTooLarge: tooLarge,
			DistinctDeviceTotal: distinctTaggedDevices(products), Products: page,
		})
	}
}

func fetchTaggedProducts(ctx context.Context, pool *pgxpool.Pool, tenantID, category, subtype string) ([]portalTaggedProduct, bool, error) {
	groups := map[string]*portalTaggedProduct{}
	group := func(key, cat, sub, kind string) *portalTaggedProduct {
		k := cat + "\x1f" + sub + "\x1f" + key
		g, ok := groups[k]
		if !ok {
			g = &portalTaggedProduct{Category: cat, Subtype: sub, ObservationKind: kind, ProductKey: key,
				devices: map[string]bool{}, users: map[string]bool{}, versions: map[string]bool{},
				platforms: map[string]bool{}, basis: map[string]bool{}, approvals: map[string]bool{}, targets: map[string]approvalItem{},
				metering: map[string]taggedProductMetering{}}
			groups[k] = g
		}
		return g
	}
	seen := func(g *portalTaggedProduct, first, last time.Time) {
		if g.FirstSeen.IsZero() || first.Before(g.FirstSeen) {
			g.FirstSeen = first
		}
		if last.After(g.LastSeen) {
			g.LastSeen = last
		}
	}
	addTarget := func(g *portalTaggedProduct, target *approvalItem) {
		if target == nil {
			g.targetUnsafe = true
			return
		}
		b, _ := json.Marshal(target)
		g.targets[string(b)] = *target
	}
	rowsRead := 0

	// Apps. Approval uses the same resolver as the drift and posture surfaces.
	policyRows, err := pool.Query(ctx, `
		SELECT id, team_id, bundle_id, winget_id, name, platform, policy, enforcement_tier, min_version, source
		FROM effective_tenant_app_policies($1::uuid)
		WHERE tenant_id = $1::uuid AND policy IN ('mandatory', 'approved', 'unapproved', 'unmanaged')
	`, tenantID)
	if err != nil {
		return nil, false, err
	}
	var policies []tenantPolicy
	for policyRows.Next() {
		var p tenantPolicy
		if err := policyRows.Scan(&p.ID, &p.TeamID, &p.BundleID, &p.WingetID, &p.Name, &p.Platform,
			&p.Policy, &p.EnforcementTier, &p.MinVersion, &p.Source); err != nil {
			policyRows.Close()
			return nil, false, err
		}
		policies = append(policies, p)
	}
	policyRows.Close()
	if err := policyRows.Err(); err != nil {
		return nil, false, err
	}
	index := buildTenantPolicyIndex(policies)
	resolvedPolicies, err := softwaregov.LoadPolicies(ctx, pool, tenantID)
	if err != nil {
		return nil, false, err
	}

	rows, err := pool.Query(ctx, portalTaggedAppsSQL, tenantID, category, subtype, taggedProductsMaxSourceRows+1)
	if err != nil {
		return nil, false, err
	}
	for rows.Next() {
		rowsRead++
		var cat, sub, basis, deviceID, installationID, platform, fingerprint, name, identifier, identifierKind, teamID, deviceOS, observationIdentityKind, observationName, observationSource, kind string
		var productID, canonicalName, vendor, version, publisher, linkedKind, linkedIdentifier, linkedCompanion, linkedName, linkedOS, meteringStatus *string
		var usageLastSeen, usageLastUsed *time.Time
		var first, last time.Time
		if err := rows.Scan(&cat, &sub, &basis, &deviceID, &installationID, &platform, &fingerprint, &productID,
			&canonicalName, &vendor, &name, &version, &publisher, &first, &last,
			&identifier, &identifierKind, &teamID, &deviceOS, &observationIdentityKind, &observationName, &observationSource, &kind,
			&linkedKind, &linkedIdentifier, &linkedCompanion, &linkedName, &linkedOS,
			&usageLastUsed, &usageLastSeen, &meteringStatus); err != nil {
			rows.Close()
			return nil, false, err
		}
		// PAT-2021: IDE extensions, npm and pip packages and MCP servers are
		// installations too, grouped by kind so a package never merges with
		// an app of the same fingerprint namespace.
		key := kind + ":" + platform + ":" + fingerprint
		if productID != nil {
			key = "product:" + *productID
		}
		g := group(key, cat, sub, kind)
		if g.Name == "" {
			g.Name, g.Identifier = name, identifier
			g.CanonicalName, g.Vendor = canonicalName, vendor
		}
		if g.ObservedPublisher == nil && publisher != nil {
			g.ObservedPublisher = publisher
		}
		g.devices[deviceID] = true
		g.platforms[platform] = true
		g.basis[basis] = true
		if version != nil && *version != "" {
			g.versions[*version] = true
		}
		state := "unreviewed"
		if kind == "app" {
			if p, ok := index.resolveAppPolicy(teamID, identifier, identifierKind, name, deviceOS); ok {
				state = p.Policy
			}
		} else if softwaregov.ObservationPolicyKind(observationIdentityKind) {
			state = resolvedPolicies.ResolveObservation(observationIdentityKind, observationName, observationSource)
		} else if observationIdentityKind == "homebrew_formula" {
			state = resolvedPolicies.ResolveHomebrew("formula", observationName, observationSource)
		} else if observationIdentityKind == "homebrew_cask" {
			if linkedKind == nil {
				state = resolvedPolicies.ResolveHomebrew("cask", observationName, observationSource)
			} else {
				linkedTeam := ""
				if *linkedKind == "macos_bundle_team" {
					linkedTeam = *linkedCompanion
				}
				state = resolvedPolicies.ResolveApp(linkedTeam, *linkedIdentifier, *linkedKind, *linkedName, *linkedOS)
			}
		}
		g.approvals[state] = true
		// There is no name-based bridge from a normalised installation to
		// metering. The query supplies usage only when its latest observation's
		// exact identifier and version still match a current device_apps row.
		// Record once per installation even if several category rules attached
		// the same tagged installation.
		if _, already := g.metering[installationID]; !already {
			metering := taggedProductMetering{state: "unknown"}
			if usageLastSeen != nil && meteringStatus != nil {
				if *meteringStatus != "ok" {
					metering.state = "unmetered"
				} else if usageLastSeen.Before(time.Now().UTC().Add(-30 * 24 * time.Hour)) {
					metering.state = "stale"
				} else {
					metering.state, metering.lastUsed = "metered", usageLastUsed
				}
			}
			g.metering[installationID] = metering
		}
		var target *approvalItem
		switch {
		case kind == "app" && (platform == "macos" || platform == "windows") && strings.TrimSpace(identifier) != "":
			p, ident := platform, strings.TrimSpace(identifier)
			t := approvalItem{Type: "application", Platform: &p, Identifier: &ident}
			if platform == "macos" && strings.TrimSpace(teamID) != "" {
				team := strings.ToUpper(strings.TrimSpace(teamID))
				t.TeamID = &team
			}
			if _, ie := normalizeApprovalItem(t); ie == nil {
				target = &t
			}
		case softwaregov.ObservationPolicyKind(observationIdentityKind):
			name, source, identityKind := observationName, observationSource, observationIdentityKind
			t := approvalItem{Type: "observation", Name: &name, Source: &source, IdentityKind: &identityKind}
			if _, ie := normalizeApprovalItem(t); ie == nil {
				target = &t
			}
		}
		addTarget(g, target)
		seen(g, first, last)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	rows, err = pool.Query(ctx, portalTaggedExtensionsSQL, tenantID, category, subtype, taggedProductsMaxSourceRows+1, extensionPresenceWindowDays)
	if err != nil {
		return nil, false, err
	}
	for rows.Next() {
		rowsRead++
		var cat, sub, basis, deviceID, browser, extID, name, userAccount, deviceOS string
		var version, policy *string
		var first, last time.Time
		if err := rows.Scan(&cat, &sub, &basis, &deviceID, &browser, &extID, &name, &version,
			&userAccount, &first, &last, &deviceOS, &policy); err != nil {
			rows.Close()
			return nil, false, err
		}
		g := group("ext:"+browser+":"+strings.ToLower(extID), cat, sub, "browser_extension")
		if g.Name == "" {
			g.Name, g.Identifier = name, extID
			b := browser
			g.Browser = &b
		}
		g.devices[deviceID] = true
		// The Safari sentinel (PAT-2064) is not a real user; a Safari
		// product must never show one more distinct user than it has.
		if lu := strings.ToLower(userAccount); lu != extractor.SafariSystemSentinel {
			g.users[lu] = true
		}
		g.platforms[devicePlatformLabel(deviceOS)] = true
		g.basis[basis] = true
		if version != nil && *version != "" {
			g.versions[*version] = true
		}
		state := "unreviewed"
		if policy != nil {
			state = *policy
		}
		g.approvals[state] = true
		b, extension := browser, extID
		target := approvalItem{Type: "browser_extension", Browser: &b, ExtensionID: &extension}
		if _, ie := normalizeApprovalItem(target); ie == nil {
			addTarget(g, &target)
		} else {
			addTarget(g, nil)
		}
		seen(g, first, last)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	if rowsRead > taggedProductsMaxSourceRows {
		return []portalTaggedProduct{}, true, nil
	}

	out := make([]portalTaggedProduct, 0, len(groups))
	for _, g := range groups {
		g.DeviceCount = len(g.devices)
		g.Devices = sortedSet(g.devices)
		if len(g.Devices) > taggedProductsMaxDevices {
			g.Devices, g.DevicesTruncated = g.Devices[:taggedProductsMaxDevices], true
		}
		if g.ObservationKind == "browser_extension" {
			n := len(g.users)
			g.UserCount = &n
		}
		g.Platforms = sortedSet(g.platforms)
		g.MatchBasis = sortedSet(g.basis)
		all := sortedSet(g.versions)
		g.VersionCount = len(all)
		if len(all) > taggedProductsMaxVersions {
			all = all[:taggedProductsMaxVersions]
		}
		g.Versions = all
		if len(g.approvals) == 1 {
			for s := range g.approvals {
				g.ApprovalState = s
			}
		} else {
			g.ApprovalState = "mixed"
		}
		if !g.targetUnsafe && len(g.targets) == 1 {
			for _, target := range g.targets {
				t := target
				g.ApprovalTarget = &t
			}
		}
		g.MeteringState = "not_applicable"
		if g.ObservationKind == "app" && g.Subtype == "desktop_app" {
			for _, m := range g.metering {
				switch m.state {
				case "metered":
					g.MeteredInstallationCount++
					if m.lastUsed != nil && (g.LastUsedAt == nil || m.lastUsed.After(*g.LastUsedAt)) {
						t := m.lastUsed.UTC()
						g.LastUsedAt = &t
					}
				case "unmetered":
					g.UnmeteredInstallationCount++
				case "stale":
					g.StaleMeteringInstallationCount++
				default:
					g.UnknownMeteringInstallationCount++
				}
			}
			totalMeteringInstallations := len(g.metering)
			switch {
			case g.StaleMeteringInstallationCount > 0:
				g.MeteringState = "stale"
			case totalMeteringInstallations > 0 && g.MeteredInstallationCount == totalMeteringInstallations:
				g.MeteringState = "metered"
			case g.MeteredInstallationCount > 0:
				g.MeteringState = "partial"
			case totalMeteringInstallations > 0 && g.UnmeteredInstallationCount == totalMeteringInstallations:
				g.MeteringState = "unmetered"
			default:
				g.MeteringState = "unknown"
			}
			// A last-use timestamp from one member cannot certify the whole
			// product group while any member is partial, stale, unavailable or
			// missing. Keep those states explicitly unknown rather than letting
			// a historical value imply complete metering coverage.
			if g.MeteringState != "metered" {
				g.LastUsedAt = nil
			}
		}
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].DeviceCount != out[j].DeviceCount {
			return out[i].DeviceCount > out[j].DeviceCount
		}
		if a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name); a != b {
			return a < b
		}
		return out[i].ProductKey+out[i].Subtype < out[j].ProductKey+out[j].Subtype
	})
	return out, false, nil
}

func distinctTaggedDevices(products []portalTaggedProduct) int {
	set := map[string]bool{}
	for _, p := range products {
		for id := range p.devices {
			set[id] = true
		}
	}
	return len(set)
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
