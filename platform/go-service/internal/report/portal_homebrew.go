// GET /v1/portal/homebrew/* (PAT-2013, consumed by the PAT-1999 Homebrew
// tab). Read-only views over the Homebrew evidence stored on the software
// observation seam: software_observations rows with identity kinds
// homebrew_formula, homebrew_cask and homebrew_tap, their
// homebrew_observation_details, homebrew_device_state and
// homebrew_cask_app_links.
//
// "Current" per device is homebrew_current_entries (PAT-2032): for each
// formula keg (kind, prefix, name, version), cask or tap, the detail row of
// the newest report that listed it, at or after the device's authority_at. A
// partial report only adds or refreshes; a complete or not_present report
// drops what it did not list; a failed report changes nothing. The extractor
// maintains the projection, so no read scans a device's history. Every query is scoped to the caller's tenant in its first CTE.
package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/softwaregov"
)

// homebrewCoreTaps are the two taps the Homebrew tab does not list by
// default (PAT-1999: "every tap in use beyond homebrew/core and
// homebrew/cask").
var homebrewCoreTaps = []string{"homebrew/core", "homebrew/cask"}

// homebrewCurrentCTE: $1 = tenant id. Defines tenant_devices,
// current_entries, installations, cask_links, linked_casks and
// counted_once_casks.
//
// linked_casks is every active cask with an active app link, for display.
// counted_once_casks is the subset whose link is reported_path, the only
// basis strong enough to hide the cask from estate totals (PAT-2032): a
// default_appdir link is a name-based guess.
const homebrewCurrentCTE = `
	WITH tenant_devices AS (
		SELECT d.id, d.hostname, d.os
		FROM devices d
		WHERE d.tenant_id = $1::uuid
	), current_entries AS (
		SELECT DISTINCT ON (h.device_id, h.package_kind, h.prefix, h.name, COALESCE(h.version, ''))
		       h.observation_id, h.device_id, h.package_kind, h.prefix, h.name, h.version,
		       h.tap, h.installed_on_request, h.installed_as_dependency, h.installed_at,
		       h.runtime_dependencies, h.homepage, h.source_url, h.opt_linked,
		       h.receipt_status, h.formula_file_status, h.versions_on_disk, h.apps,
		       h.tap_directory, h.remote_url, h.config_status, h.observed_at,
		       so.identity_kind, so.identity_fingerprint,
		       so.identity_value_normalized AS name_key,
		       so.companion_value_normalized AS tap_key
		FROM homebrew_current_entries c
		JOIN tenant_devices td ON td.id = c.device_id
		JOIN homebrew_device_state s ON s.device_id = c.device_id AND s.tenant_id = $1::uuid
		JOIN homebrew_observation_details h
		  ON h.inventory_run_id = c.inventory_run_id AND h.device_id = c.device_id
		 AND h.package_kind = c.package_kind AND h.prefix = c.prefix AND h.name = c.name
		 AND (h.package_kind <> 'formula' OR h.version = c.version_key)
		 AND h.tenant_id = $1::uuid
		JOIN software_observations so ON so.id = h.observation_id AND so.tenant_id = h.tenant_id
		WHERE c.tenant_id = $1::uuid
		  -- Defence in depth beside the ingest lock: evidence older than the
		  -- device's newest complete or not_present report is never current.
		  AND (s.authority_at IS NULL OR c.observed_at >= s.authority_at)
		ORDER BY h.device_id, h.package_kind, h.prefix, h.name, COALESCE(h.version, ''),
		         h.observation_id DESC
	), installations AS (
		SELECT si.id, si.device_id, si.identity_fingerprint, si.first_seen_at
		FROM software_installations si
		WHERE si.tenant_id = $1::uuid
		  AND si.identity_kind IN ('homebrew_formula','homebrew_cask','homebrew_tap')
	), cask_links AS (
		-- An active cask installation linked to an active app installation.
		SELECT ci.device_id, ci.identity_fingerprint, l.link_basis
		FROM software_installations ci
		JOIN homebrew_cask_app_links l ON l.cask_installation_id = ci.id
		JOIN software_installations ai ON ai.id = l.app_installation_id AND ai.removed_at IS NULL
		WHERE ci.tenant_id = $1::uuid AND ci.removed_at IS NULL
		  AND ci.identity_kind = 'homebrew_cask'
	), linked_casks AS (
		SELECT DISTINCT device_id, identity_fingerprint FROM cask_links
	), counted_once_casks AS (
		SELECT DISTINCT device_id, identity_fingerprint FROM cask_links
		WHERE link_basis = 'reported_path'
	), homebrew_policies AS (
		-- PAT-2058: this tenant's own Homebrew approval decisions, keyed the
		-- same way the resolver (softwaregov.homebrewPolicyKey) and the
		-- write handler (currentHomebrewDecision) match them. tap is
		-- already the '' (default-tap-or-unrecorded) / explicit-tap form
		-- NormalizeHomebrewTap produces, since that is what the write path
		-- stores; the CASE below folds current_entries' own tap_key
		-- (identity_value_normalized-derived, so homebrew/core or
		-- homebrew/cask rather than '') to the same form before matching.
		SELECT kind, name, tap, policy FROM tenant_homebrew_policies WHERE tenant_id = $1::uuid
	)`

// homebrewApprovalTapExpr folds a current_entries tap_key column to the same
// ” (default tap or unrecorded) / explicit-tap form tenant_homebrew_policies
// stores it in (softwaregov.NormalizeHomebrewTap), for joining against
// homebrew_policies. kind is 'formula' or 'cask'.
func homebrewApprovalTapExpr(tapKeyCol, kind string) string {
	def := "homebrew/core"
	if kind == "cask" {
		def = "homebrew/cask"
	}
	return "(CASE WHEN " + tapKeyCol + " = '" + def + "' THEN '' ELSE " + tapKeyCol + " END)"
}

// homebrewApprovalState maps a possibly-absent tenant_homebrew_policies.policy
// to the portal's four-state vocabulary, reusing softwaregov's app/extension
// mapping (identical vocabulary: ” unreviewed, unmanaged ignored, otherwise
// the value itself; Homebrew never stores mandatory).
func homebrewApprovalState(policy *string) string {
	if policy == nil {
		return softwaregov.StateUnreviewed
	}
	return softwaregov.AppPolicyState(*policy)
}

// HomebrewIdentity is the stored identity of a formula, cask or tap: the
// software_observations identity kind, normalised name and normalised tap
// ("" when the receipt did not say). PAT-2023 keys CVE mappings on it.
type HomebrewIdentity struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
	Tap  string `json:"tap"`
}

type HomebrewDeviceStatusCounts struct {
	Complete    int `json:"complete"`
	Partial     int `json:"partial"`
	NotPresent  int `json:"not_present"`
	Failed      int `json:"failed"`
	NotReported int `json:"not_reported"`
}

type HomebrewSummary struct {
	GeneratedAt                     time.Time                  `json:"generated_at"`
	MacOSDeviceCount                int                        `json:"macos_device_count"`
	DevicesWithHomebrew             int                        `json:"devices_with_homebrew"`
	DeviceStatus                    HomebrewDeviceStatusCounts `json:"device_status"`
	FormulaCount                    int                        `json:"formula_count"`
	FormulaOnRequestCount           int                        `json:"formula_on_request_count"`
	FormulaInstallationCount        int                        `json:"formula_installation_count"`
	CaskCount                       int                        `json:"cask_count"`
	CaskInstallationCount           int                        `json:"cask_installation_count"`
	LinkedCaskInstallationCount     int                        `json:"linked_cask_installation_count"`
	TapCount                        int                        `json:"tap_count"`
	ThirdPartyTapCount              int                        `json:"third_party_tap_count"`
	EstateSoftwareInstallationCount int                        `json:"estate_software_installation_count"`
	// UnreviewedCount / UnapprovedCount (PAT-2058) count distinct current
	// formulae and casks together (not installations, not taps -- taps are
	// not approvable) resolved to those two states by the same policy join
	// the formulae and cask lists use.
	UnreviewedCount int `json:"unreviewed_count"`
	UnapprovedCount int `json:"unapproved_count"`
}

// FetchHomebrewSummary returns the estate summary strip. Estate totals count
// a cask once (as its app) only when the app link is reported_path;
// linked_cask_installation_count also includes default_appdir links.
func FetchHomebrewSummary(ctx context.Context, pool *pgxpool.Pool, tenantID string) (HomebrewSummary, error) {
	out := HomebrewSummary{GeneratedAt: time.Now().UTC()}
	var directUnreviewed, directUnapproved int
	err := pool.QueryRow(ctx, homebrewCurrentCTE+`
		, device_status AS (
			SELECT td.id,
			       CASE WHEN hs.collection_status IS NOT NULL THEN hs.collection_status
			            ELSE 'not_reported' END AS status,
			       td.os ILIKE '%macos%' AS is_macos
			FROM tenant_devices td
			LEFT JOIN homebrew_device_state hs ON hs.device_id = td.id AND hs.tenant_id = $1::uuid
		), product_states AS (
			-- PAT-2058: one row per distinct current formula/cask identity,
			-- joined to its approval policy (if any). Taps are excluded: they
			-- are not approvable.
			SELECT DISTINCT package_kind, name_key, tap_key
			FROM current_entries WHERE package_kind IN ('formula', 'cask')
		), product_policies AS (
			SELECT ps.package_kind, ps.name_key, ps.tap_key, hp.policy
			FROM product_states ps
			LEFT JOIN homebrew_policies hp ON hp.kind = ps.package_kind AND hp.name = ps.name_key
			                               AND hp.tap = CASE ps.package_kind
			                                   WHEN 'cask' THEN `+homebrewApprovalTapExpr("ps.tap_key", "cask")+`
			                                   ELSE `+homebrewApprovalTapExpr("ps.tap_key", "formula")+` END
		)
		SELECT
			(SELECT count(*) FROM device_status WHERE is_macos OR status <> 'not_reported')::int,
			(SELECT count(*) FROM device_status WHERE status IN ('complete','partial'))::int,
			(SELECT count(*) FROM device_status WHERE status = 'complete')::int,
			(SELECT count(*) FROM device_status WHERE status = 'partial')::int,
			(SELECT count(*) FROM device_status WHERE status = 'not_present')::int,
			(SELECT count(*) FROM device_status WHERE status = 'failed')::int,
			(SELECT count(*) FROM device_status WHERE status = 'not_reported' AND is_macos)::int,
			(SELECT count(DISTINCT (name_key, tap_key)) FROM current_entries WHERE package_kind = 'formula')::int,
			(SELECT count(DISTINCT (name_key, tap_key)) FROM current_entries
			  WHERE package_kind = 'formula' AND installed_on_request IS TRUE)::int,
			(SELECT count(*) FROM current_entries WHERE package_kind = 'formula')::int,
			(SELECT count(DISTINCT (name_key, tap_key)) FROM current_entries WHERE package_kind = 'cask')::int,
			(SELECT count(*) FROM current_entries WHERE package_kind = 'cask')::int,
			(SELECT count(*) FROM current_entries ce
			  WHERE ce.package_kind = 'cask'
			    AND EXISTS (SELECT 1 FROM linked_casks lc
			                WHERE lc.device_id = ce.device_id
			                  AND lc.identity_fingerprint = ce.identity_fingerprint))::int,
			(SELECT count(DISTINCT name_key) FROM current_entries
			  WHERE package_kind = 'tap' AND NOT (name_key = ANY($2::text[])))::int,
			(SELECT count(DISTINCT name_key) FROM current_entries
			  WHERE package_kind = 'tap' AND name_key NOT LIKE 'homebrew/%')::int,
			(SELECT count(*) FROM software_installations si
			  WHERE si.tenant_id = $1::uuid AND si.removed_at IS NULL
			    AND si.identity_kind <> 'homebrew_tap'
			    -- PAT-2021: the Homebrew tab's estate figure stays apps and
			    -- Homebrew; tooling items are counted on the AI Tooling tab.
			    AND si.identity_kind NOT IN ('ide_extension','ide_extension_unidentified',
			        'npm_package','npm_package_unidentified','pip_package','pip_package_unidentified',
			        'local_model','local_model_unidentified','local_model_runtime',
			        'mcp_server','mcp_server_unnamed')
			    AND NOT EXISTS (SELECT 1 FROM counted_once_casks lc
			                    WHERE si.identity_kind = 'homebrew_cask'
			                      AND lc.device_id = si.device_id
			                      AND lc.identity_fingerprint = si.identity_fingerprint))::int,
			(SELECT count(*) FROM product_policies WHERE policy IS NULL)::int,
			(SELECT count(*) FROM product_policies WHERE policy = 'unapproved')::int
	`, tenantID, homebrewCoreTaps).Scan(
		&out.MacOSDeviceCount, &out.DevicesWithHomebrew,
		&out.DeviceStatus.Complete, &out.DeviceStatus.Partial, &out.DeviceStatus.NotPresent,
		&out.DeviceStatus.Failed, &out.DeviceStatus.NotReported,
		&out.FormulaCount, &out.FormulaOnRequestCount, &out.FormulaInstallationCount,
		&out.CaskCount, &out.CaskInstallationCount, &out.LinkedCaskInstallationCount,
		&out.TapCount, &out.ThirdPartyTapCount, &out.EstateSoftwareInstallationCount,
		&directUnreviewed, &directUnapproved,
	)
	if err != nil {
		return out, fmt.Errorf("homebrew summary: %w", err)
	}
	// The SQL above keeps the other summary aggregates set-based. Its direct
	// policy count is replaced here because a cask's effective state can be an
	// app policy (and can be mixed across linked/standalone installations).
	_ = directUnreviewed
	_ = directUnapproved
	unreviewed, unapproved, err := homebrewEffectivePolicyCounts(ctx, pool, tenantID)
	if err != nil {
		return out, err
	}
	out.UnreviewedCount, out.UnapprovedCount = unreviewed, unapproved
	return out, nil
}

func homebrewEffectivePolicyCounts(ctx context.Context, pool *pgxpool.Pool, tenantID string) (int, int, error) {
	policies, err := softwaregov.LoadPolicies(ctx, pool, tenantID)
	if err != nil {
		return 0, 0, fmt.Errorf("load Homebrew summary policies: %w", err)
	}
	rows, err := pool.Query(ctx, homebrewCurrentCTE+`
		, products AS (
			SELECT DISTINCT package_kind, name_key, tap_key
			FROM current_entries WHERE package_kind IN ('formula', 'cask')
		), cask_installs AS (
			SELECT DISTINCT ce.name_key, ce.tap_key, ci.id
			FROM current_entries ce
			JOIN software_installations ci ON ci.tenant_id = $1::uuid AND ci.device_id = ce.device_id
				AND ci.identity_fingerprint = ce.identity_fingerprint AND ci.removed_at IS NULL
			WHERE ce.package_kind = 'cask'
		)
		SELECT p.package_kind, p.name_key, p.tap_key,
		       ai.identity_kind, ai.identity_value_normalized, ai.companion_value_normalized,
		       COALESCE(ai.current_name, ''), COALESCE(d.os, '')
		FROM products p
		LEFT JOIN cask_installs ci ON p.package_kind = 'cask' AND ci.name_key = p.name_key AND ci.tap_key = p.tap_key
		LEFT JOIN homebrew_cask_app_links l ON l.cask_installation_id = ci.id
		LEFT JOIN software_installations ai ON ai.id = l.app_installation_id AND ai.removed_at IS NULL
		LEFT JOIN devices d ON d.id = ai.device_id AND d.tenant_id = ai.tenant_id
	`, tenantID)
	if err != nil {
		return 0, 0, fmt.Errorf("homebrew summary policy identities: %w", err)
	}
	defer rows.Close()
	states := map[string]map[string]bool{}
	for rows.Next() {
		var kind, name, tap string
		var appKind, appIdentifier, appCompanion, appName, appOS *string
		if err := rows.Scan(&kind, &name, &tap, &appKind, &appIdentifier, &appCompanion, &appName, &appOS); err != nil {
			return 0, 0, fmt.Errorf("scan homebrew summary policy: %w", err)
		}
		key := kind + "\x00" + name + "\x00" + tap
		if states[key] == nil {
			states[key] = map[string]bool{}
		}
		if kind != "cask" || appKind == nil {
			states[key][policies.ResolveHomebrew(kind, name, tap)] = true
			continue
		}
		team := ""
		if *appKind == "macos_bundle_team" {
			team = *appCompanion
		}
		states[key][policies.ResolveApp(team, *appIdentifier, *appKind, *appName, *appOS)] = true
	}
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("iterate homebrew summary policies: %w", err)
	}
	unreviewed, unapproved := 0, 0
	for _, effective := range states {
		if len(effective) != 1 {
			continue
		}
		for state := range effective {
			if state == softwaregov.StateUnreviewed {
				unreviewed++
			}
			if state == softwaregov.StateUnapproved {
				unapproved++
			}
		}
	}
	return unreviewed, unapproved, nil
}

type HomebrewFormula struct {
	Identity              HomebrewIdentity `json:"identity"`
	Name                  string           `json:"name"`
	Tap                   *string          `json:"tap"`
	ThirdPartyTap         bool             `json:"third_party_tap"`
	Versions              []string         `json:"versions"`
	DeviceCount           int              `json:"device_count"`
	InstallationCount     int              `json:"installation_count"`
	OnRequestDeviceCount  int              `json:"on_request_device_count"`
	DependencyDeviceCount int              `json:"dependency_device_count"`
	Homepage              *string          `json:"homepage"`
	SourceURL             *string          `json:"source_url"`
	FirstSeenAt           *time.Time       `json:"first_seen_at"`
	EvidenceAt            time.Time        `json:"evidence_at"`
	// ApprovalState / ProductKey (PAT-2058) join the software approval
	// model: the same resolver, decision audit and write endpoint
	// (PUT /v1/portal/software-approvals) applications and extensions use.
	// ProductKey doubles as the identity a write item needs
	// ({"type":"homebrew_formula","name":...,"tap":...}); it is never null,
	// since a formula's own (name, tap) is already a confirmed identity.
	ApprovalState string `json:"approval_state"`
	ProductKey    string `json:"product_key"`
}

type HomebrewFormulaPage struct {
	GeneratedAt         time.Time         `json:"generated_at"`
	Total               int               `json:"total"`
	IncludeDependencies bool              `json:"include_dependencies"`
	Formulae            []HomebrewFormula `json:"formulae"`
}

// FetchHomebrewFormulae returns one page of estate formulae grouped by
// identity (name + tap). With includeDependencies false, an entry installed
// only as a dependency is left out; an entry whose receipt did not say how it
// was installed is kept, since hiding it would claim it is a dependency.
func FetchHomebrewFormulae(ctx context.Context, pool *pgxpool.Pool, tenantID, search string, includeDependencies bool, limit, offset int) (HomebrewFormulaPage, error) {
	page := HomebrewFormulaPage{GeneratedAt: time.Now().UTC(), IncludeDependencies: includeDependencies, Formulae: []HomebrewFormula{}}
	search = strings.TrimSpace(search)
	query := homebrewCurrentCTE + `
		, grouped AS (
			SELECT ce.name_key, ce.tap_key,
			       min(ce.name) AS name,
			       array_agg(DISTINCT ce.version ORDER BY ce.version) AS versions,
			       count(DISTINCT ce.device_id)::int AS device_count,
			       count(*)::int AS installation_count,
			       count(DISTINCT ce.device_id) FILTER (WHERE ce.installed_on_request IS TRUE)::int AS on_request_device_count,
			       count(DISTINCT ce.device_id) FILTER (WHERE ce.installed_as_dependency IS TRUE
			                                         AND ce.installed_on_request IS NOT TRUE)::int AS dependency_device_count,
			       max(ce.homepage) AS homepage,
			       max(ce.source_url) AS source_url,
			       min(i.first_seen_at) AS first_seen_at,
			       max(ce.observed_at) AS evidence_at,
			       max(hp.policy) AS policy
			FROM current_entries ce
			LEFT JOIN installations i ON i.device_id = ce.device_id
			                         AND i.identity_fingerprint = ce.identity_fingerprint
			LEFT JOIN homebrew_policies hp ON hp.kind = 'formula' AND hp.name = ce.name_key
			                               AND hp.tap = ` + homebrewApprovalTapExpr("ce.tap_key", "formula") + `
			WHERE ce.package_kind = 'formula'
			  AND ($2::boolean OR NOT (ce.installed_as_dependency IS TRUE AND ce.installed_on_request IS NOT TRUE))
			  AND ($3 = '' OR ce.name ILIKE $4 OR ce.tap_key ILIKE $4)
			GROUP BY ce.name_key, ce.tap_key
		)`
	pattern := "%" + search + "%"
	if err := pool.QueryRow(ctx, query+` SELECT count(*)::int FROM grouped`,
		tenantID, includeDependencies, search, pattern).Scan(&page.Total); err != nil {
		return page, fmt.Errorf("homebrew formulae total: %w", err)
	}
	rows, err := pool.Query(ctx, query+`
		SELECT name_key, tap_key, name, versions, device_count, installation_count,
		       on_request_device_count, dependency_device_count, homepage, source_url,
		       first_seen_at, evidence_at, policy
		FROM grouped
		ORDER BY device_count DESC, name_key ASC, tap_key ASC
		LIMIT $5 OFFSET $6`, tenantID, includeDependencies, search, pattern, limit, offset)
	if err != nil {
		return page, fmt.Errorf("homebrew formulae page: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var f HomebrewFormula
		var nameKey, tapKey string
		var policy *string
		if err := rows.Scan(&nameKey, &tapKey, &f.Name, &f.Versions, &f.DeviceCount, &f.InstallationCount,
			&f.OnRequestDeviceCount, &f.DependencyDeviceCount, &f.Homepage, &f.SourceURL,
			&f.FirstSeenAt, &f.EvidenceAt, &policy); err != nil {
			return page, fmt.Errorf("scan homebrew formula: %w", err)
		}
		f.Identity = HomebrewIdentity{Kind: "homebrew_formula", Name: nameKey, Tap: tapKey}
		f.Tap = nullableTap(tapKey)
		f.ThirdPartyTap = thirdPartyTap(tapKey)
		f.ApprovalState = homebrewApprovalState(policy)
		f.ProductKey = softwaregov.HomebrewFormulaKey(nameKey, tapKey)
		if f.Versions == nil {
			f.Versions = []string{}
		}
		page.Formulae = append(page.Formulae, f)
	}
	return page, rows.Err()
}

type HomebrewCask struct {
	Identity             HomebrewIdentity `json:"identity"`
	Token                string           `json:"token"`
	Tap                  *string          `json:"tap"`
	ThirdPartyTap        bool             `json:"third_party_tap"`
	Versions             []string         `json:"versions"`
	UnknownVersionCount  int              `json:"unknown_version_installation_count"`
	DeviceCount          int              `json:"device_count"`
	InstallationCount    int              `json:"installation_count"`
	LinkedAppDeviceCount int              `json:"linked_app_device_count"`
	AppNames             []string         `json:"app_names"`
	FirstSeenAt          *time.Time       `json:"first_seen_at"`
	EvidenceAt           time.Time        `json:"evidence_at"`
	// ApprovalState / ProductKey (PAT-2058): see HomebrewFormula's doc comment.
	ApprovalState string `json:"approval_state"`
	ProductKey    string `json:"product_key"`
}

type HomebrewCaskPage struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Total       int            `json:"total"`
	Casks       []HomebrewCask `json:"casks"`
}

// FetchHomebrewCasks returns one page of estate casks grouped by identity
// (token + tap). linked_app_device_count is how many of those devices link
// the cask to an application bundle already in inventory.
func FetchHomebrewCasks(ctx context.Context, pool *pgxpool.Pool, tenantID, search string, limit, offset int) (HomebrewCaskPage, error) {
	page := HomebrewCaskPage{GeneratedAt: time.Now().UTC(), Casks: []HomebrewCask{}}
	// A cask with a live app-bundle link is not a second product decision.
	// Resolve the linked application's policy below, rather than trusting a
	// possibly historical cask row in tenant_homebrew_policies.
	policies, err := softwaregov.LoadPolicies(ctx, pool, tenantID)
	if err != nil {
		return page, fmt.Errorf("load Homebrew approval policies: %w", err)
	}
	search = strings.TrimSpace(search)
	pattern := "%" + search + "%"
	query := homebrewCurrentCTE + `
		, casks AS (
			SELECT ce.*,
			       EXISTS (SELECT 1 FROM linked_casks lc
			               WHERE lc.device_id = ce.device_id
			                 AND lc.identity_fingerprint = ce.identity_fingerprint) AS linked
			FROM current_entries ce
			WHERE ce.package_kind = 'cask'
			  AND ($2 = '' OR ce.name ILIKE $3 OR ce.tap_key ILIKE $3)
		), grouped AS (
			SELECT c.name_key, c.tap_key, min(c.name) AS token,
			       array_agg(DISTINCT c.version ORDER BY c.version) FILTER (WHERE c.version IS NOT NULL) AS versions,
			       count(*) FILTER (WHERE c.version IS NULL)::int AS unknown_version_count,
			       count(DISTINCT c.device_id)::int AS device_count,
			       count(*)::int AS installation_count,
			       count(DISTINCT c.device_id) FILTER (WHERE c.linked)::int AS linked_app_device_count,
			       min(i.first_seen_at) AS first_seen_at,
			       max(c.observed_at) AS evidence_at,
			       max(hp.policy) AS policy
			FROM casks c
			LEFT JOIN installations i ON i.device_id = c.device_id
			                         AND i.identity_fingerprint = c.identity_fingerprint
			LEFT JOIN homebrew_policies hp ON hp.kind = 'cask' AND hp.name = c.name_key
			                               AND hp.tap = ` + homebrewApprovalTapExpr("c.tap_key", "cask") + `
			GROUP BY c.name_key, c.tap_key
		)`
	if err := pool.QueryRow(ctx, query+` SELECT count(*)::int FROM grouped`,
		tenantID, search, pattern).Scan(&page.Total); err != nil {
		return page, fmt.Errorf("homebrew casks total: %w", err)
	}
	rows, err := pool.Query(ctx, query+`
		SELECT g.name_key, g.tap_key, g.token, g.versions, g.unknown_version_count,
		       g.device_count, g.installation_count, g.linked_app_device_count,
		       COALESCE((SELECT array_agg(DISTINCT app->>'name' ORDER BY app->>'name')
		                 FROM casks c2, jsonb_array_elements(c2.apps) app
		                 WHERE c2.name_key = g.name_key AND c2.tap_key = g.tap_key), ARRAY[]::text[]),
		       g.first_seen_at, g.evidence_at, g.policy
		FROM grouped g
		ORDER BY g.device_count DESC, g.name_key ASC, g.tap_key ASC
		LIMIT $4 OFFSET $5`, tenantID, search, pattern, limit, offset)
	if err != nil {
		return page, fmt.Errorf("homebrew casks page: %w", err)
	}
	for rows.Next() {
		var c HomebrewCask
		var nameKey, tapKey string
		var policy *string
		if err := rows.Scan(&nameKey, &tapKey, &c.Token, &c.Versions, &c.UnknownVersionCount,
			&c.DeviceCount, &c.InstallationCount, &c.LinkedAppDeviceCount, &c.AppNames,
			&c.FirstSeenAt, &c.EvidenceAt, &policy); err != nil {
			rows.Close()
			return page, fmt.Errorf("scan homebrew cask: %w", err)
		}
		c.Identity = HomebrewIdentity{Kind: "homebrew_cask", Name: nameKey, Tap: tapKey}
		c.Tap = nullableTap(tapKey)
		c.ThirdPartyTap = thirdPartyTap(tapKey)
		c.ApprovalState = homebrewApprovalState(policy)
		c.ProductKey = softwaregov.HomebrewCaskKey(nameKey, tapKey)
		if c.Versions == nil {
			c.Versions = []string{}
		}
		page.Casks = append(page.Casks, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return page, err
	}
	rows.Close()
	// Do not issue follow-up policy queries while the page rows retain a pool
	// connection. This avoids a MaxConns=1 deadlock; the resolver keeps the
	// direct cask state only if a link retires in the read race.
	effective, err := pageCaskApprovalStates(ctx, pool, tenantID, policies, page.Casks)
	if err != nil {
		return page, err
	}
	for i := range page.Casks {
		if state := effective[page.Casks[i].Identity.Name+"\x00"+page.Casks[i].Identity.Tap]; state != "" {
			page.Casks[i].ApprovalState = state
		}
	}
	return page, nil
}

// pageCaskApprovalStates resolves every cask on a page with one
// authority-filtered query. It deliberately begins at homebrew_current_entries
// rather than active installations, so a stale link cannot affect a current
// Homebrew read.
func pageCaskApprovalStates(ctx context.Context, pool *pgxpool.Pool, tenantID string, policies softwaregov.Policies, casks []HomebrewCask) (map[string]string, error) {
	out := map[string]string{}
	if len(casks) == 0 {
		return out, nil
	}
	names, taps := make([]string, len(casks)), make([]string, len(casks))
	for i, c := range casks {
		names[i], taps[i] = c.Identity.Name, c.Identity.Tap
	}
	rows, err := pool.Query(ctx, homebrewCurrentCTE+`
		, requested AS (SELECT * FROM unnest($2::text[], $3::text[]) AS r(name, tap))
		SELECT r.name, r.tap, ai.identity_kind, ai.identity_value_normalized,
		       ai.companion_value_normalized, COALESCE(ai.current_name, ''), COALESCE(d.os, '')
		FROM requested r
		JOIN current_entries ce ON ce.package_kind = 'cask' AND ce.name_key = r.name AND ce.tap_key = r.tap
		JOIN installations ci ON ci.device_id = ce.device_id AND ci.identity_fingerprint = ce.identity_fingerprint
		LEFT JOIN homebrew_cask_app_links l ON l.cask_installation_id = ci.id
		LEFT JOIN software_installations ai ON ai.id = l.app_installation_id AND ai.removed_at IS NULL AND ai.tenant_id = $1::uuid
		LEFT JOIN devices d ON d.id = ai.device_id AND d.tenant_id = ai.tenant_id
	`, tenantID, names, taps)
	if err != nil {
		return out, fmt.Errorf("page cask approval states: %w", err)
	}
	defer rows.Close()
	states := map[string]map[string]bool{}
	for rows.Next() {
		var name, tap string
		var kind, ident, companion, appName, osName *string
		if err := rows.Scan(&name, &tap, &kind, &ident, &companion, &appName, &osName); err != nil {
			return out, err
		}
		key := name + "\x00" + tap
		if states[key] == nil {
			states[key] = map[string]bool{}
		}
		if kind == nil {
			states[key][policies.ResolveHomebrew("cask", name, tap)] = true
			continue
		}
		team := ""
		if *kind == "macos_bundle_team" {
			team = *companion
		}
		states[key][policies.ResolveApp(team, *ident, *kind, *appName, *osName)] = true
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	for key, ss := range states {
		if len(ss) == 1 {
			for s := range ss {
				out[key] = s
			}
		} else if len(ss) > 1 {
			out[key] = "mixed"
		}
	}
	return out, nil
}

type HomebrewTap struct {
	Identity    HomebrewIdentity `json:"identity"`
	Name        string           `json:"name"`
	ThirdParty  bool             `json:"third_party"`
	RemoteURLs  []string         `json:"remote_urls"`
	DeviceCount int              `json:"device_count"`
	FirstSeenAt *time.Time       `json:"first_seen_at"`
	EvidenceAt  time.Time        `json:"evidence_at"`
}

type HomebrewTapPage struct {
	GeneratedAt time.Time     `json:"generated_at"`
	Total       int           `json:"total"`
	IncludeCore bool          `json:"include_core"`
	Taps        []HomebrewTap `json:"taps"`
}

// FetchHomebrewTaps returns one page of taps in use. homebrew/core and
// homebrew/cask are left out unless includeCore. A tap outside the homebrew
// organisation is flagged third_party: an unvetted software source.
func FetchHomebrewTaps(ctx context.Context, pool *pgxpool.Pool, tenantID string, includeCore bool, limit, offset int) (HomebrewTapPage, error) {
	page := HomebrewTapPage{GeneratedAt: time.Now().UTC(), IncludeCore: includeCore, Taps: []HomebrewTap{}}
	query := homebrewCurrentCTE + `
		, grouped AS (
			SELECT ce.name_key, min(ce.name) AS name,
			       array_agg(DISTINCT ce.remote_url ORDER BY ce.remote_url) FILTER (WHERE ce.remote_url IS NOT NULL) AS remote_urls,
			       count(DISTINCT ce.device_id)::int AS device_count,
			       min(i.first_seen_at) AS first_seen_at,
			       max(ce.observed_at) AS evidence_at
			FROM current_entries ce
			LEFT JOIN installations i ON i.device_id = ce.device_id
			                         AND i.identity_fingerprint = ce.identity_fingerprint
			WHERE ce.package_kind = 'tap'
			  AND ($2::boolean OR NOT (ce.name_key = ANY($3::text[])))
			GROUP BY ce.name_key
		)`
	if err := pool.QueryRow(ctx, query+` SELECT count(*)::int FROM grouped`,
		tenantID, includeCore, homebrewCoreTaps).Scan(&page.Total); err != nil {
		return page, fmt.Errorf("homebrew taps total: %w", err)
	}
	rows, err := pool.Query(ctx, query+`
		SELECT name_key, name, remote_urls, device_count, first_seen_at, evidence_at
		FROM grouped
		ORDER BY (name_key NOT LIKE 'homebrew/%') DESC, device_count DESC, name_key ASC
		LIMIT $4 OFFSET $5`, tenantID, includeCore, homebrewCoreTaps, limit, offset)
	if err != nil {
		return page, fmt.Errorf("homebrew taps page: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var tp HomebrewTap
		var nameKey string
		if err := rows.Scan(&nameKey, &tp.Name, &tp.RemoteURLs, &tp.DeviceCount, &tp.FirstSeenAt, &tp.EvidenceAt); err != nil {
			return page, fmt.Errorf("scan homebrew tap: %w", err)
		}
		tp.Identity = HomebrewIdentity{Kind: "homebrew_tap", Name: nameKey}
		tp.ThirdParty = thirdPartyTap(nameKey)
		if tp.RemoteURLs == nil {
			tp.RemoteURLs = []string{}
		}
		page.Taps = append(page.Taps, tp)
	}
	return page, rows.Err()
}

// HomebrewDeviceState is one device's newest Homebrew report. Status is
// "not_reported" for a macOS device that has never sent a homebrew block
// (an agent that predates the collector, or holds it off the wire).
type HomebrewDeviceState struct {
	DeviceID         string          `json:"device_id"`
	Hostname         *string         `json:"hostname"`
	CollectionStatus string          `json:"collection_status"`
	Truncated        *bool           `json:"truncated"`
	TruncationReason *string         `json:"truncation_reason"`
	ReportedAt       *time.Time      `json:"reported_at"`
	AuthorityAt      *time.Time      `json:"authority_at"`
	Prefixes         json.RawMessage `json:"prefixes"`
	Issues           json.RawMessage `json:"issues"`
	FormulaCount     int             `json:"formula_count"`
	CaskCount        int             `json:"cask_count"`
	TapCount         int             `json:"tap_count"`
}

type HomebrewDevicePage struct {
	GeneratedAt time.Time             `json:"generated_at"`
	Total       int                   `json:"total"`
	Devices     []HomebrewDeviceState `json:"devices"`
}

const homebrewDeviceStateSelect = `
		, per_device AS (
			SELECT td.id AS device_id, td.hostname,
			       COALESCE(hs.collection_status, 'not_reported') AS collection_status,
			       hs.truncated, hs.truncation_reason, hs.reported_at, hs.authority_at,
			       COALESCE(hs.prefixes, '[]'::jsonb) AS prefixes,
			       COALESCE(hs.issues, '[]'::jsonb) AS issues,
			       (SELECT count(*) FROM current_entries ce WHERE ce.device_id = td.id AND ce.package_kind = 'formula')::int AS formula_count,
			       (SELECT count(*) FROM current_entries ce WHERE ce.device_id = td.id AND ce.package_kind = 'cask')::int AS cask_count,
			       (SELECT count(*) FROM current_entries ce WHERE ce.device_id = td.id AND ce.package_kind = 'tap')::int AS tap_count
			FROM tenant_devices td
			LEFT JOIN homebrew_device_state hs ON hs.device_id = td.id AND hs.tenant_id = $1::uuid
			WHERE hs.device_id IS NOT NULL OR td.os ILIKE '%macos%'
		)`

func scanHomebrewDeviceState(scan func(...any) error) (HomebrewDeviceState, error) {
	var d HomebrewDeviceState
	var prefixes, issues []byte
	err := scan(&d.DeviceID, &d.Hostname, &d.CollectionStatus, &d.Truncated, &d.TruncationReason,
		&d.ReportedAt, &d.AuthorityAt, &prefixes, &issues, &d.FormulaCount, &d.CaskCount, &d.TapCount)
	d.Prefixes, d.Issues = prefixes, issues
	return d, err
}

// FetchHomebrewDevices returns one page of per-device Homebrew state: every
// device that has reported a homebrew block plus every macOS device that has
// not, so "not reported" is visible rather than silently absent.
func FetchHomebrewDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string, limit, offset int) (HomebrewDevicePage, error) {
	page := HomebrewDevicePage{GeneratedAt: time.Now().UTC(), Devices: []HomebrewDeviceState{}}
	query := homebrewCurrentCTE + homebrewDeviceStateSelect
	if err := pool.QueryRow(ctx, query+` SELECT count(*)::int FROM per_device`, tenantID).Scan(&page.Total); err != nil {
		return page, fmt.Errorf("homebrew devices total: %w", err)
	}
	rows, err := pool.Query(ctx, query+`
		SELECT device_id::text, hostname, collection_status, truncated, truncation_reason,
		       reported_at, authority_at, prefixes, issues, formula_count, cask_count, tap_count
		FROM per_device
		ORDER BY hostname ASC NULLS LAST, device_id ASC
		LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	if err != nil {
		return page, fmt.Errorf("homebrew devices page: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		d, err := scanHomebrewDeviceState(rows.Scan)
		if err != nil {
			return page, fmt.Errorf("scan homebrew device: %w", err)
		}
		page.Devices = append(page.Devices, d)
	}
	return page, rows.Err()
}

type HomebrewLinkedApp struct {
	Path      string `json:"path"`
	LinkBasis string `json:"link_basis"`
	AppName   string `json:"app_name"`
}

// HomebrewDeviceEntry is one current formula, cask or tap on one device.
// Fields not meaningful for the entry's kind are null.
type HomebrewDeviceEntry struct {
	Kind                  string              `json:"kind"`
	Identity              HomebrewIdentity    `json:"identity"`
	Prefix                string              `json:"prefix"`
	Name                  string              `json:"name"`
	Version               *string             `json:"version"`
	Tap                   *string             `json:"tap"`
	ThirdPartyTap         bool                `json:"third_party_tap"`
	InstalledOnRequest    *bool               `json:"installed_on_request"`
	InstalledAsDependency *bool               `json:"installed_as_dependency"`
	InstalledAt           *time.Time          `json:"installed_at"`
	RuntimeDependencies   []string            `json:"runtime_dependencies"`
	Homepage              *string             `json:"homepage"`
	SourceURL             *string             `json:"source_url"`
	OptLinked             *bool               `json:"opt_linked"`
	ReceiptStatus         *string             `json:"receipt_status"`
	FormulaFileStatus     *string             `json:"formula_file_status"`
	VersionsOnDisk        []string            `json:"versions_on_disk"`
	Apps                  json.RawMessage     `json:"apps"`
	LinkedApps            []HomebrewLinkedApp `json:"linked_apps"`
	Directory             *string             `json:"directory"`
	RemoteURL             *string             `json:"remote_url"`
	ConfigStatus          *string             `json:"config_status"`
	FirstSeenAt           *time.Time          `json:"first_seen_at"`
	EvidenceAt            time.Time           `json:"evidence_at"`
}

type HomebrewDeviceDetail struct {
	GeneratedAt time.Time             `json:"generated_at"`
	State       HomebrewDeviceState   `json:"state"`
	Total       int                   `json:"total"`
	Kind        string                `json:"kind"`
	Entries     []HomebrewDeviceEntry `json:"entries"`
}

// FetchHomebrewDeviceDetail returns one device's Homebrew state and one page
// of its current entries (kind "" means all kinds). The caller has already
// proved the device belongs to tenantID; the queries are tenant-scoped too.
func FetchHomebrewDeviceDetail(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID, kind string, limit, offset int) (HomebrewDeviceDetail, error) {
	detail := HomebrewDeviceDetail{GeneratedAt: time.Now().UTC(), Kind: kind, Entries: []HomebrewDeviceEntry{}}
	state, err := scanHomebrewDeviceState(pool.QueryRow(ctx, homebrewCurrentCTE+homebrewDeviceStateSelect+`
		SELECT device_id::text, hostname, collection_status, truncated, truncation_reason,
		       reported_at, authority_at, prefixes, issues, formula_count, cask_count, tap_count
		FROM per_device WHERE device_id = $2::uuid`, tenantID, deviceID).Scan)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return detail, fmt.Errorf("homebrew device state: %w", err)
		}
		// A non-macOS device that never reported Homebrew has no row here.
		var hostname *string
		if qerr := pool.QueryRow(ctx, `SELECT hostname FROM devices WHERE id = $1::uuid AND tenant_id = $2::uuid`,
			deviceID, tenantID).Scan(&hostname); qerr != nil {
			return detail, fmt.Errorf("homebrew device state: %w", err)
		}
		state = HomebrewDeviceState{DeviceID: deviceID, Hostname: hostname, CollectionStatus: "not_reported",
			Prefixes: json.RawMessage("[]"), Issues: json.RawMessage("[]")}
	}
	detail.State = state

	query := homebrewCurrentCTE + `
		, entries AS (
			SELECT ce.*, i.id AS installation_id, i.first_seen_at
			FROM current_entries ce
			LEFT JOIN installations i ON i.device_id = ce.device_id
			                         AND i.identity_fingerprint = ce.identity_fingerprint
			WHERE ce.device_id = $2::uuid AND ($3 = '' OR ce.package_kind = $3)
		)`
	if err := pool.QueryRow(ctx, query+` SELECT count(*)::int FROM entries`,
		tenantID, deviceID, kind).Scan(&detail.Total); err != nil {
		return detail, fmt.Errorf("homebrew device entries total: %w", err)
	}
	rows, err := pool.Query(ctx, query+`
		SELECT e.package_kind, e.name_key, e.tap_key, e.prefix, e.name, e.version, e.tap,
		       e.installed_on_request, e.installed_as_dependency, e.installed_at,
		       e.runtime_dependencies, e.homepage, e.source_url, e.opt_linked,
		       e.receipt_status, e.formula_file_status, e.versions_on_disk, e.apps,
		       COALESCE((
		           SELECT jsonb_agg(jsonb_build_object('path', l.app_path, 'link_basis', l.link_basis,
		                                              'app_name', ai.current_name) ORDER BY l.app_path)
		           FROM homebrew_cask_app_links l
		           JOIN software_installations ai ON ai.id = l.app_installation_id AND ai.removed_at IS NULL
		           WHERE e.package_kind = 'cask' AND l.cask_installation_id = e.installation_id
		             AND l.tenant_id = $1::uuid), '[]'::jsonb),
		       e.tap_directory, e.remote_url, e.config_status, e.first_seen_at, e.observed_at
		FROM entries e
		ORDER BY CASE e.package_kind WHEN 'formula' THEN 1 WHEN 'cask' THEN 2 ELSE 3 END,
		         e.prefix, e.name, e.version NULLS FIRST
		LIMIT $4 OFFSET $5`, tenantID, deviceID, kind, limit, offset)
	if err != nil {
		return detail, fmt.Errorf("homebrew device entries page: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e HomebrewDeviceEntry
		var nameKey, tapKey string
		var apps, linked []byte
		if err := rows.Scan(&e.Kind, &nameKey, &tapKey, &e.Prefix, &e.Name, &e.Version, &e.Tap,
			&e.InstalledOnRequest, &e.InstalledAsDependency, &e.InstalledAt,
			&e.RuntimeDependencies, &e.Homepage, &e.SourceURL, &e.OptLinked,
			&e.ReceiptStatus, &e.FormulaFileStatus, &e.VersionsOnDisk, &apps, &linked,
			&e.Directory, &e.RemoteURL, &e.ConfigStatus, &e.FirstSeenAt, &e.EvidenceAt); err != nil {
			return detail, fmt.Errorf("scan homebrew device entry: %w", err)
		}
		e.Identity = HomebrewIdentity{Kind: "homebrew_" + e.Kind, Name: nameKey, Tap: tapKey}
		if e.Kind == "tap" {
			e.ThirdPartyTap = thirdPartyTap(nameKey)
		} else {
			e.ThirdPartyTap = thirdPartyTap(tapKey)
		}
		if apps != nil {
			e.Apps = apps
		}
		e.LinkedApps = []HomebrewLinkedApp{}
		if err := json.Unmarshal(linked, &e.LinkedApps); err != nil {
			return detail, fmt.Errorf("decode homebrew cask links: %w", err)
		}
		detail.Entries = append(detail.Entries, e)
	}
	return detail, rows.Err()
}

func nullableTap(tapKey string) *string {
	if tapKey == "" {
		return nil
	}
	return &tapKey
}

// thirdPartyTap: a tap outside the homebrew organisation. Unknown ("") is
// not claimed third party.
func thirdPartyTap(tapKey string) bool {
	return tapKey != "" && !strings.HasPrefix(tapKey, "homebrew/")
}
