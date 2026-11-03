package cvepipeline

// PAT-2023: Homebrew formulae and casks through both CVE match paths.
//
// Input is the device's CURRENT Homebrew list (homebrew_current_entries,
// PAT-2032), filtered by the device's authority_at exactly as the portal's
// Homebrew tab reads it. That table only loses a row on a complete or
// not_present report, so a partial or failed report can never make a
// package, and therefore its findings, disappear (absence requires
// authority). Lifecycle closure of a Homebrew finding additionally requires
// the device's newest inventory run to carry the "homebrew" authoritative
// scope (cvelifecycle required_scope).
//
// Paths:
//   - ingest: the extractor snapshots the device's Homebrew match input
//     before the Homebrew block is stored; QueueHomebrewDelta diffs it
//     afterwards and only queues changed packages that a mapping is keyed
//     by, or that left the list, as observations named by their display
//     name ("openssl@3 (Homebrew formula)"). Drain routes those names to
//     matchDeviceHomebrew;
//   - mapping publish (PAT-2045): SyncMappingSnapshot sees a published,
//     changed or removed homebrew_formula / homebrew_cask mapping and queues
//     a mapping job for its name; expandMappingJobs turns it into
//     observations on every active device whose current Homebrew list
//     includes it (activeHomebrewObservations);
//   - application mapping publish (PAT-2057): an app_name mapping job also
//     re-matches every active device's casks linked to an app it covers
//     (activeCasksLinkedToApps), because the app mapping decides whether
//     the cask or the app is the install's finding (LinkedToApp);
//   - feed delta (PAT-2045): MatchFeedDelta also re-matches the devices
//     whose curated Homebrew mappings resolve to a CPE key a sync touched;
//   - nightly: MatchHomebrewFull, called from patched-cve-sync runMatch
//     before its last_seen_at prune. It is also the only writer of the
//     review queue (recordHomebrewReview), see below.
//
// Review-queue recording (PAT-2045): unmapped official-tap packages are
// recorded for review by the nightly run only, in one sorted batch while it
// holds the exclusive match lock. They are no longer routed through
// cve_match_queue: a Mac's first report of ~200 unmapped formulae used to
// add ~200 queue rows against QueueCapacity purely to write review rows, and
// every drain re-locked popular review rows even when nothing had changed.
// The review queue is a human curation backlog that never produces a
// finding, so up to a day's latency costs nothing, and writing it only under
// the exclusive lock means no event-path transaction ever contends for a
// review row.
//
// Findings live in device_cve_findings beside application findings, with the
// optional package_source / package_name / install_reason / required_by /
// mapping_basis / confidence_tier columns set. Application findings leave
// them NULL.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/cvelifecycle"
	"patched.im/api/internal/cvematch"
	"patched.im/api/internal/webhook"
)

// homebrewCurrentPackagesSQL lists current formula kegs and casks. $1 is a
// device id array, or NULL for every device active in the nightly window.
const homebrewCurrentPackagesSQL = `
	SELECT DISTINCT ON (h.device_id, h.package_kind, h.prefix, h.name, COALESCE(h.version, ''))
	       h.device_id::text, d.tenant_id::text, h.package_kind, h.name,
	       COALESCE(h.tap, ''), COALESCE(h.version, ''),
	       h.installed_on_request, h.installed_as_dependency,
	       COALESCE(h.runtime_dependencies, '{}'::text[]),
	       COALESCE(h.homepage, ''), COALESCE(h.source_url, ''),
	       -- Application bundles this cask is linked to on this device
	       -- (PAT-2013), on either link basis, active installs only.
	       CASE WHEN h.package_kind = 'cask' THEN ARRAY(
	           SELECT DISTINCT ai.current_name
	           FROM software_installations ci
	           JOIN homebrew_cask_app_links l ON l.cask_installation_id = ci.id
	           JOIN software_installations ai
	             ON ai.id = l.app_installation_id AND ai.removed_at IS NULL
	           WHERE ci.tenant_id = h.tenant_id AND ci.device_id = h.device_id
	             AND ci.removed_at IS NULL AND ci.identity_kind = 'homebrew_cask'
	             AND ci.identity_fingerprint = so.identity_fingerprint
	             AND ai.current_name IS NOT NULL
	           ORDER BY ai.current_name
	       ) ELSE '{}'::text[] END AS linked_apps
	FROM homebrew_current_entries c
	JOIN devices d ON d.id = c.device_id AND d.tenant_id = c.tenant_id
	JOIN homebrew_device_state s ON s.device_id = c.device_id AND s.tenant_id = c.tenant_id
	JOIN homebrew_observation_details h
	  ON h.inventory_run_id = c.inventory_run_id AND h.device_id = c.device_id
	 AND h.package_kind = c.package_kind AND h.prefix = c.prefix AND h.name = c.name
	 AND (h.package_kind <> 'formula' OR h.version = c.version_key)
	 AND h.tenant_id = c.tenant_id
	JOIN software_observations so ON so.id = h.observation_id AND so.tenant_id = h.tenant_id
	WHERE c.package_kind IN ('formula', 'cask')
	  AND (s.authority_at IS NULL OR c.observed_at >= s.authority_at)
	  AND (($1::uuid[] IS NULL AND d.last_seen > NOW() - INTERVAL '` + activeDeviceWindow + `')
	       OR c.device_id = ANY($1::uuid[]))
	ORDER BY h.device_id, h.package_kind, h.prefix, h.name, COALESCE(h.version, ''),
	         h.observation_id DESC
`

// loadHomebrewPackages returns current Homebrew packages per device, and each
// device's tenant. deviceIDs nil means every active device.
//
// A cask's LinkedToApp is set when at least one application bundle it is
// linked to is covered by an application CPE mapping: that app is then
// matched on the application path, from the version actually on disk, and is
// the one finding for the install. A cask linked only to unmapped apps keeps
// its own match, so the link can never make an install lose its only
// finding.
func loadHomebrewPackages(ctx context.Context, q DB, deviceIDs []string) (map[string][]cvematch.HomebrewPackage, map[string]string, error) {
	appMappings, err := LoadMappings(ctx, q)
	if err != nil {
		return nil, nil, err
	}
	appIndex := newMappingIndex(appMappings)
	var arg any
	if deviceIDs != nil {
		arg = deviceIDs
	}
	rows, err := q.Query(ctx, homebrewCurrentPackagesSQL, arg)
	if err != nil {
		return nil, nil, fmt.Errorf("load homebrew packages: %w", err)
	}
	defer rows.Close()
	byDevice := map[string][]cvematch.HomebrewPackage{}
	tenants := map[string]string{}
	deps := map[string][][]string{} // device -> per-package runtime deps, parallel to byDevice
	for rows.Next() {
		var deviceID, tenantID string
		var p cvematch.HomebrewPackage
		var runtimeDeps []string
		if err := rows.Scan(&deviceID, &tenantID, &p.Kind, &p.Name, &p.Tap, &p.Version,
			&p.InstalledOnRequest, &p.InstalledAsDependency, &runtimeDeps,
			&p.Homepage, &p.SourceURL, &p.LinkedApps); err != nil {
			return nil, nil, fmt.Errorf("scan homebrew package: %w", err)
		}
		for _, app := range p.LinkedApps {
			if appIndex.Mapped(app) {
				p.LinkedToApp = true
				break
			}
		}
		byDevice[deviceID] = append(byDevice[deviceID], p)
		deps[deviceID] = append(deps[deviceID], runtimeDeps)
		tenants[deviceID] = tenantID
	}
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate homebrew packages: %w", err)
	}
	for deviceID, pkgs := range byDevice {
		attachRequiredBy(pkgs, deps[deviceID])
	}
	return byDevice, tenants, nil
}

// attachRequiredBy fills RequiredBy on each formula from the other formulae's
// receipts: P requires C when C is in P's runtime_dependencies. A dependency
// may be reported tap-qualified ("homebrew/core/openssl@3"); the last path
// segment is the formula name.
func attachRequiredBy(pkgs []cvematch.HomebrewPackage, runtimeDeps [][]string) {
	parents := map[string]map[string]bool{}
	for i, p := range pkgs {
		if p.Kind != "formula" {
			continue
		}
		for _, d := range runtimeDeps[i] {
			d = strings.TrimSpace(d)
			if j := strings.LastIndexByte(d, '/'); j >= 0 {
				d = d[j+1:]
			}
			if d == "" || d == p.Name {
				continue
			}
			if parents[d] == nil {
				parents[d] = map[string]bool{}
			}
			parents[d][p.Name] = true
		}
	}
	for i := range pkgs {
		if pkgs[i].Kind != "formula" || len(parents[pkgs[i].Name]) == 0 {
			continue
		}
		list := make([]string, 0, len(parents[pkgs[i].Name]))
		for name := range parents[pkgs[i].Name] {
			list = append(list, name)
		}
		sort.Strings(list)
		pkgs[i].RequiredBy = list
	}
}

// SnapshotDeviceHomebrew is the Homebrew counterpart of SnapshotDeviceApps:
// display name to a sorted list of match-relevant states (version, install
// reason, app link, dependants). The extractor takes it before the Homebrew
// block is stored and hands it to QueueHomebrewDelta afterwards.
func SnapshotDeviceHomebrew(ctx context.Context, q DB, deviceID string) (AppVersions, error) {
	byDevice, _, err := loadHomebrewPackages(ctx, q, []string{deviceID})
	if err != nil {
		return nil, err
	}
	return homebrewSnapshot(byDevice[deviceID]), nil
}

func homebrewSnapshot(pkgs []cvematch.HomebrewPackage) AppVersions {
	out := AppVersions{}
	for _, p := range pkgs {
		state := p.Version + "|" + p.InstallReason() + "|" + strconv.FormatBool(p.LinkedToApp) +
			"|" + strings.Join(p.RequiredBy, ",")
		out[p.DisplayName()] = append(out[p.DisplayName()], state)
	}
	for name, states := range out {
		out[name] = uniqueSorted(states)
	}
	return out
}

// QueueHomebrewDelta is the ingest half of Homebrew matching. Given the
// snapshot taken before the payload's Homebrew block was stored, it queues
// for the drain every changed package that some Homebrew mapping is keyed by
// (whatever its review state, tap or app link, so a change in any of those
// re-matches and prunes), and every package that left the current list (its
// findings must be pruned). Nothing else: an unmapped package has nothing to
// match, and its review-queue row is the nightly run's job (PAT-2045), so a
// first report of hundreds of unmapped formulae adds nothing to the queue.
//
// It runs inside the ingest transaction, so it writes only cve_match_queue,
// never a review or suggestion row. Removals are safe to act on: the current
// list only loses a package on a complete or not_present Homebrew report.
func QueueHomebrewDelta(ctx context.Context, q DB, tenantID, deviceID string, before AppVersions) (enqueued, dropped int, err error) {
	byDevice, _, err := loadHomebrewPackages(ctx, q, []string{deviceID})
	if err != nil {
		return 0, 0, err
	}
	pkgs := byDevice[deviceID]
	changed := ChangedProducts(before, homebrewSnapshot(pkgs), true)
	if len(changed) == 0 {
		return 0, 0, nil
	}
	mappings, err := LoadHomebrewMappings(ctx, q)
	if err != nil {
		return 0, 0, err
	}
	keyed := map[homebrewKey]bool{}
	for _, m := range mappings {
		if k, ok := homebrewKeyForSource(m.SourceType, m.Name); ok {
			keyed[k] = true
		}
	}
	wanted := map[string]bool{}
	present := map[string]bool{}
	for _, p := range pkgs {
		present[p.DisplayName()] = true
		if keyed[packageKey(p)] {
			wanted[p.DisplayName()] = true
		}
	}
	var queue []string
	for _, name := range changed {
		if !present[name] || wanted[name] {
			queue = append(queue, name)
		}
	}
	return EnqueueObservations(ctx, q, tenantID, deviceID, queue, SourceIngest)
}

// LoadHomebrewMappings reads the Homebrew-keyed CPE mappings.
func LoadHomebrewMappings(ctx context.Context, q DB) ([]cvematch.HomebrewMapping, error) {
	rows, err := q.Query(ctx, `
		SELECT source_type, match_name, cpe_vendor, cpe_product, review_state
		FROM app_cpe_mappings
		WHERE source_type IN ('homebrew_formula', 'homebrew_cask')
		ORDER BY id
	`)
	if err != nil {
		return nil, fmt.Errorf("load homebrew cpe mappings: %w", err)
	}
	defer rows.Close()
	var out []cvematch.HomebrewMapping
	for rows.Next() {
		var m cvematch.HomebrewMapping
		if err := rows.Scan(&m.SourceType, &m.Name, &m.CPEVendor, &m.CPEProduct, &m.ReviewState); err != nil {
			return nil, fmt.Errorf("scan homebrew cpe mapping: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// sourceTypeAppName is app_cpe_mappings.source_type for an application
// mapping (word-token match on the display name).
const sourceTypeAppName = "app_name"

// homebrewKey is a package kind ("formula" or "cask") and its lowercased,
// trimmed formula name or cask token: the key a Homebrew mapping and a
// review-queue row are both matched on.
type homebrewKey struct{ kind, name string }

// homebrewKeyForSource maps a Homebrew mapping's source_type and match_name
// to its package key. ok is false for any other source type.
func homebrewKeyForSource(sourceType, matchName string) (homebrewKey, bool) {
	name := strings.ToLower(strings.TrimSpace(matchName))
	if name == "" {
		return homebrewKey{}, false
	}
	switch sourceType {
	case cvematch.HomebrewFormulaSource:
		return homebrewKey{"formula", name}, true
	case cvematch.HomebrewCaskSource:
		return homebrewKey{"cask", name}, true
	}
	return homebrewKey{}, false
}

func packageKey(p cvematch.HomebrewPackage) homebrewKey {
	return homebrewKey{p.Kind, strings.ToLower(strings.TrimSpace(p.Name))}
}

// activeHomebrewObservations lists, for each key, every (tenant, device,
// Homebrew display name) on an active device whose current Homebrew list
// includes that formula or cask. "Current" is exactly what
// loadHomebrewPackages reads: homebrew_current_entries filtered by the
// device's authority_at, so a package that is only missing from a partial
// report is still listed, and one removed by an authoritative report is not.
// Sorted by device, then name.
func activeHomebrewObservations(ctx context.Context, q DB, keys []homebrewKey) ([]observationJob, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	sortHomebrewKeys(keys)
	kinds := make([]string, 0, len(keys))
	names := make([]string, 0, len(keys))
	for _, k := range keys {
		kinds, names = append(kinds, k.kind), append(names, k.name)
	}
	rows, err := q.Query(ctx, `
		SELECT DISTINCT d.tenant_id::text, c.device_id::text, c.package_kind, c.name
		FROM homebrew_current_entries c
		JOIN unnest($1::text[], $2::text[]) AS k(kind, name)
		  ON c.package_kind = k.kind AND lower(btrim(c.name)) = k.name
		JOIN devices d ON d.id = c.device_id AND d.tenant_id = c.tenant_id
		JOIN homebrew_device_state s ON s.device_id = c.device_id AND s.tenant_id = c.tenant_id
		WHERE c.package_kind IN ('formula', 'cask')
		  AND (s.authority_at IS NULL OR c.observed_at >= s.authority_at)
		  AND d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
		ORDER BY 2, 3, 4
	`, kinds, names)
	if err != nil {
		return nil, fmt.Errorf("load devices with homebrew packages: %w", err)
	}
	defer rows.Close()
	var out []observationJob
	for rows.Next() {
		var tenantID, deviceID, kind, name string
		if err := rows.Scan(&tenantID, &deviceID, &kind, &name); err != nil {
			return nil, fmt.Errorf("scan device homebrew package: %w", err)
		}
		out = append(out, observationJob{TenantID: tenantID, DeviceID: deviceID,
			AppName: cvematch.HomebrewDisplayName(kind, name)})
	}
	return out, rows.Err()
}

// activeCasksLinkedToApps lists, for application mapping names, every
// (tenant, device, cask display name) on an active device whose current cask
// is linked to an application bundle one of matchNames covers (PAT-2057).
//
// Such a cask takes its finding from the app's mapping, not its own
// (LinkedToApp, PAT-2023), so publishing or removing the app mapping can
// flip which of the two is the finding for the install. Re-matching only the
// app would leave the cask's side to the nightly run: a removed app mapping
// would leave the install with no finding until then, and a published one
// would leave a duplicate cask finding.
//
// Cost stays bounded to the devices that actually carry such a link: one
// read of the distinct linked app names on active devices (filtered in Go by
// the same word-token rule the application matcher uses), one read of the
// devices linking a covered name, then the exact Homebrew match input of
// those devices only. Only casks some Homebrew mapping is keyed by are
// returned, whatever its review state: a cask with no mapping has no finding
// of its own to add or prune. Read-only; the caller inserts. Sorted by
// device, then name.
func activeCasksLinkedToApps(ctx context.Context, q DB, matchNames []string) ([]observationJob, error) {
	if len(matchNames) == 0 {
		return nil, nil
	}
	rows, err := q.Query(ctx, `
		SELECT DISTINCT ai.current_name
		FROM homebrew_cask_app_links l
		JOIN software_installations ci
		  ON ci.id = l.cask_installation_id AND ci.removed_at IS NULL AND ci.identity_kind = 'homebrew_cask'
		JOIN software_installations ai
		  ON ai.id = l.app_installation_id AND ai.removed_at IS NULL
		JOIN devices d ON d.id = l.device_id AND d.tenant_id = l.tenant_id
		WHERE ai.current_name IS NOT NULL
		  AND d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
	`)
	if err != nil {
		return nil, fmt.Errorf("load cask-linked app names: %w", err)
	}
	covered := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan cask-linked app name: %w", err)
		}
		for _, mn := range matchNames {
			if cvematch.NameMatches(name, mn) {
				covered[name] = true
				break
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate cask-linked app names: %w", err)
	}
	if len(covered) == 0 {
		return nil, nil
	}
	coveredNames := sortedKeys(covered)
	rows, err = q.Query(ctx, `
		SELECT DISTINCT l.device_id::text
		FROM homebrew_cask_app_links l
		JOIN software_installations ci
		  ON ci.id = l.cask_installation_id AND ci.removed_at IS NULL AND ci.identity_kind = 'homebrew_cask'
		JOIN software_installations ai
		  ON ai.id = l.app_installation_id AND ai.removed_at IS NULL
		JOIN devices d ON d.id = l.device_id AND d.tenant_id = l.tenant_id
		WHERE ai.current_name = ANY($1::text[])
		  AND d.last_seen > NOW() - INTERVAL '`+activeDeviceWindow+`'
		ORDER BY 1
	`, coveredNames)
	if err != nil {
		return nil, fmt.Errorf("load devices with cask-linked apps: %w", err)
	}
	var devices []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan device with cask-linked app: %w", err)
		}
		devices = append(devices, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate devices with cask-linked apps: %w", err)
	}
	if len(devices) == 0 {
		return nil, nil
	}
	mappings, err := LoadHomebrewMappings(ctx, q)
	if err != nil {
		return nil, err
	}
	keyed := map[homebrewKey]bool{}
	for _, m := range mappings {
		if k, ok := homebrewKeyForSource(m.SourceType, m.Name); ok {
			keyed[k] = true
		}
	}
	if len(keyed) == 0 {
		return nil, nil
	}
	// The same current, authority-filtered input the Homebrew matcher reads,
	// so the queued names are exactly the ones matchDeviceHomebrew will find.
	byDevice, tenants, err := loadHomebrewPackages(ctx, q, devices)
	if err != nil {
		return nil, err
	}
	var out []observationJob
	for _, deviceID := range devices {
		names := map[string]bool{}
		for _, p := range byDevice[deviceID] {
			if p.Kind != "cask" || !keyed[packageKey(p)] {
				continue
			}
			for _, app := range p.LinkedApps {
				if covered[app] {
					names[p.DisplayName()] = true
					break
				}
			}
		}
		for _, name := range sortedKeys(names) {
			out = append(out, observationJob{TenantID: tenants[deviceID], DeviceID: deviceID, AppName: name})
		}
	}
	return out, nil
}

func sortHomebrewKeys(keys []homebrewKey) {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].name < keys[j].name
	})
}

// recordHomebrewReview maintains homebrew_cpe_review_queue for the packages
// about to be matched. It never writes app_cpe_mappings.
//
//   - An unmapped package whose receipt names homebrew/core or homebrew/cask
//     is queued. A package with no recorded tap, or from a third-party tap,
//     is never queued: the queue is global, and a local or private formula's
//     name and homepage must not leave its tenant.
//   - When the package's own homepage or source URL points at exactly one
//     "vendor:product" key present in the local NVD store, that key is stored
//     as suggested_cpe_key. It is a suggestion for a person (PAT-2046), never
//     a mapping, and produces no finding. Deviation from PAT-2023 as written
//     (which auto-accepted such matches), for security: the URLs are
//     endpoint-reported and a mapping would apply to every tenant.
//   - The first-seen homepage, source URL and suggestion are kept. A later
//     report that disagrees sets metadata_conflict and counts it, so a
//     reviewer can see the metadata is contested; it never overwrites.
//     Reports that disagree with each other inside one batch are flagged the
//     same way (PAT-2045: the nightly run is now the only caller, and
//     collapsing a batch to one entry per key must not hide a disagreement).
//     The entry kept for a new row is the first carrying a homepage in the
//     caller's order, which MatchHomebrewFull makes device-id order.
//   - A queue row whose package now has a curated mapping is marked mapped.
//   - A cask linked to its app bundle is skipped: its app is the finding.
//
// Multi-row writes go in sorted key order. The only caller is the nightly
// run, under the exclusive match lock, so no event-path transaction writes
// these rows concurrently; the order still guards against a second nightly
// process or a future curation endpoint.
func recordHomebrewReview(ctx context.Context, q DB, pkgs []cvematch.HomebrewPackage,
	mappings []cvematch.HomebrewMapping) error {
	unmapped := map[homebrewKey]cvematch.HomebrewPackage{}
	curated := map[homebrewKey]bool{}
	homepages := map[homebrewKey]map[string]bool{}
	sources := map[homebrewKey]map[string]bool{}
	note := func(seen map[homebrewKey]map[string]bool, k homebrewKey, v string) {
		if v == "" {
			return
		}
		if seen[k] == nil {
			seen[k] = map[string]bool{}
		}
		seen[k][v] = true
	}
	for _, p := range pkgs {
		if p.LinkedToApp || !p.ExplicitOfficialTap() {
			continue
		}
		k := packageKey(p)
		if len(cvematch.HomebrewMappingsFor(p, mappings)) > 0 {
			curated[k] = true
			continue
		}
		note(homepages, k, p.Homepage)
		note(sources, k, p.SourceURL)
		// Prefer an entry that carries metadata for the review row.
		if prev, ok := unmapped[k]; !ok || (prev.Homepage == "" && p.Homepage != "") {
			unmapped[k] = p
		}
	}

	if len(curated) > 0 {
		keys := make([]homebrewKey, 0, len(curated))
		for k := range curated {
			keys = append(keys, k)
		}
		sortHomebrewKeys(keys)
		var kinds, names []string
		for _, k := range keys {
			kinds, names = append(kinds, k.kind), append(names, k.name)
		}
		if _, err := q.Exec(ctx, `
			WITH locked AS (
				-- Lock in (kind, name) order before updating, so two writers
				-- can never take these row locks in opposite orders.
				SELECT r.id
				FROM homebrew_cpe_review_queue r
				JOIN unnest($1::text[], $2::text[]) AS u(kind, name)
				  ON r.package_kind = u.kind AND r.name = u.name
				WHERE r.status = 'pending'
				ORDER BY r.package_kind, r.name
				FOR UPDATE OF r
			)
			UPDATE homebrew_cpe_review_queue r
			SET status = 'mapped', resolved_at = now()
			FROM locked
			WHERE r.id = locked.id
		`, kinds, names); err != nil {
			return fmt.Errorf("mark mapped homebrew review rows: %w", err)
		}
	}
	if len(unmapped) == 0 {
		return nil
	}

	keys := make([]homebrewKey, 0, len(unmapped))
	for k := range unmapped {
		keys = append(keys, k)
	}
	sortHomebrewKeys(keys)

	// Which candidate keys exist in the local NVD store, in one query.
	var allCandidates []string
	candidates := map[homebrewKey][]string{}
	for _, k := range keys {
		c := cvematch.HomebrewSuggestionCandidates(unmapped[k])
		candidates[k] = c
		allCandidates = append(allCandidates, c...)
	}
	known := map[string]bool{}
	if len(allCandidates) > 0 {
		rows, err := q.Query(ctx, `
			SELECT k FROM unnest($1::text[]) AS k
			WHERE EXISTS (SELECT 1 FROM cve_feed_entries e WHERE e.cpe_patterns @> ARRAY[k])
		`, uniqueSorted(allCandidates))
		if err != nil {
			return fmt.Errorf("check homebrew suggestion candidates: %w", err)
		}
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return fmt.Errorf("scan homebrew suggestion candidate: %w", err)
			}
			known[k] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return fmt.Errorf("iterate homebrew suggestion candidates: %w", err)
		}
	}

	var qKinds, qNames, qHomepages, qSources, qSuggestions []string
	var qConflicts []bool
	for _, k := range keys {
		p := unmapped[k]
		var hits []string
		for _, c := range candidates[k] {
			if known[c] {
				hits = append(hits, c)
			}
		}
		suggestion := ""
		if len(hits) == 1 {
			suggestion = hits[0]
		}
		qKinds, qNames = append(qKinds, k.kind), append(qNames, k.name)
		qHomepages, qSources = append(qHomepages, p.Homepage), append(qSources, p.SourceURL)
		qSuggestions = append(qSuggestions, suggestion)
		qConflicts = append(qConflicts, len(homepages[k]) > 1 || len(sources[k]) > 1)
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO homebrew_cpe_review_queue AS r
			(package_kind, name, homepage, source_url, suggested_cpe_key,
			 metadata_conflict, metadata_conflict_count)
		SELECT u.kind, u.name, NULLIF(u.homepage, ''), NULLIF(u.source_url, ''), NULLIF(u.suggestion, ''),
		       u.conflict, CASE WHEN u.conflict THEN 1 ELSE 0 END
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[], $6::bool[]) WITH ORDINALITY
		     AS u(kind, name, homepage, source_url, suggestion, conflict, n)
		ORDER BY u.n
		ON CONFLICT (package_kind, name) DO UPDATE SET
			last_seen_at = now(),
			-- First-seen metadata is kept; a disagreeing report, or reports
			-- that disagree with each other in this batch
			-- (EXCLUDED.metadata_conflict), are flagged and counted, never
			-- written over it.
			homepage          = COALESCE(r.homepage, EXCLUDED.homepage),
			source_url        = COALESCE(r.source_url, EXCLUDED.source_url),
			suggested_cpe_key = COALESCE(r.suggested_cpe_key, EXCLUDED.suggested_cpe_key),
			metadata_conflict = r.metadata_conflict OR EXCLUDED.metadata_conflict OR (
				(r.homepage IS NOT NULL AND EXCLUDED.homepage IS NOT NULL AND r.homepage <> EXCLUDED.homepage)
				OR (r.source_url IS NOT NULL AND EXCLUDED.source_url IS NOT NULL AND r.source_url <> EXCLUDED.source_url)),
			metadata_conflict_count = r.metadata_conflict_count + CASE WHEN
				EXCLUDED.metadata_conflict
				OR (r.homepage IS NOT NULL AND EXCLUDED.homepage IS NOT NULL AND r.homepage <> EXCLUDED.homepage)
				OR (r.source_url IS NOT NULL AND EXCLUDED.source_url IS NOT NULL AND r.source_url <> EXCLUDED.source_url)
				THEN 1 ELSE 0 END,
			-- Dismissed stays dismissed. A row that was mapped but has lost
			-- its mapping is back in the queue.
			status = CASE WHEN r.status = 'mapped' THEN 'pending' ELSE r.status END,
			resolved_at = CASE WHEN r.status = 'mapped' THEN NULL ELSE r.resolved_at END
	`, qKinds, qNames, qHomepages, qSources, qSuggestions, qConflicts); err != nil {
		return fmt.Errorf("queue unmapped homebrew packages: %w", err)
	}
	return nil
}

// writeHomebrewFindings upserts one device's Homebrew findings in one
// statement and returns the ones inserted for the first time. Findings are
// unique per (cve, app_name) by construction (cvematch.MatchHomebrew).
func writeHomebrewFindings(ctx context.Context, q DB, deviceID string, findings []cvematch.HomebrewFinding) ([]cvematch.HomebrewFinding, error) {
	if len(findings) == 0 {
		return nil, nil
	}
	// Upsert in (cve_id, app_name) order, so two transactions writing the
	// same device (a drain and a feed-delta run, both on the shared match
	// lock) take these row locks in the same order.
	findings = append([]cvematch.HomebrewFinding(nil), findings...)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].CVEID != findings[j].CVEID {
			return findings[i].CVEID < findings[j].CVEID
		}
		return findings[i].AppName < findings[j].AppName
	})
	n := len(findings)
	cves, apps, versions, severities, confs, fixed := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	scores := make([]*float64, n)
	sources, pkgNames, reasons, requiredBy, bases, tiers := make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, f := range findings {
		cves[i], apps[i], versions[i], severities[i] = f.CVEID, f.AppName, f.AppVersion, f.Severity
		confs[i], fixed[i], scores[i] = f.MatchConfidence, f.FixedVersion, f.Score
		sources[i], pkgNames[i], reasons[i], bases[i], tiers[i] = f.PackageSource, f.PackageName, f.InstallReason, f.MappingBasis, f.ConfidenceTier
		rb := f.RequiredBy
		if rb == nil {
			rb = []string{}
		}
		b, err := json.Marshal(rb)
		if err != nil {
			return nil, fmt.Errorf("marshal required_by: %w", err)
		}
		requiredBy[i] = string(b)
	}
	rows, err := q.Query(ctx, `
		INSERT INTO device_cve_findings
			(device_id, cve_id, app_name, app_version, cvss_v3_score, severity,
			 match_confidence, fixed_version, last_seen_at,
			 package_source, package_name, install_reason, required_by, mapping_basis, confidence_tier)
		SELECT $1::uuid, u.cve_id, u.app_name, u.app_version, u.score, NULLIF(u.severity, ''),
		       u.confidence, u.fixed_version, NOW(),
		       u.source, u.package_name, u.reason,
		       ARRAY(SELECT jsonb_array_elements_text(u.required_by::jsonb)),
		       u.basis, u.tier
		FROM unnest($2::text[], $3::text[], $4::text[], $5::float8[], $6::text[], $7::text[], $8::text[],
		            $9::text[], $10::text[], $11::text[], $12::text[], $13::text[], $14::text[])
		     AS u(cve_id, app_name, app_version, score, severity, confidence, fixed_version,
		          source, package_name, reason, required_by, basis, tier)
		ON CONFLICT (device_id, cve_id, app_name) DO UPDATE SET
			app_version      = EXCLUDED.app_version,
			cvss_v3_score    = EXCLUDED.cvss_v3_score,
			severity         = EXCLUDED.severity,
			match_confidence = EXCLUDED.match_confidence,
			fixed_version    = EXCLUDED.fixed_version,
			package_source   = EXCLUDED.package_source,
			package_name     = EXCLUDED.package_name,
			install_reason   = EXCLUDED.install_reason,
			required_by      = EXCLUDED.required_by,
			mapping_basis    = EXCLUDED.mapping_basis,
			confidence_tier  = EXCLUDED.confidence_tier,
			last_seen_at     = NOW()
		RETURNING cve_id, app_name, (xmax = 0)
	`, deviceID, cves, apps, versions, scores, severities, confs, fixed,
		sources, pkgNames, reasons, requiredBy, bases, tiers)
	if err != nil {
		return nil, fmt.Errorf("upsert homebrew findings on %s: %w", deviceID, err)
	}
	defer rows.Close()
	type key struct{ cve, app string }
	fresh := map[key]bool{}
	for rows.Next() {
		var cve, app string
		var inserted bool
		if err := rows.Scan(&cve, &app, &inserted); err != nil {
			return nil, fmt.Errorf("scan homebrew finding upsert: %w", err)
		}
		if inserted {
			fresh[key{cve, app}] = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("upsert homebrew findings on %s: %w", deviceID, err)
	}
	var out []cvematch.HomebrewFinding
	for _, f := range findings {
		if fresh[key{f.CVEID, f.AppName}] {
			out = append(out, f)
		}
	}
	return out, nil
}

// splitHomebrewNames separates Homebrew display names from application names.
func splitHomebrewNames(names []string) (apps, brew []string) {
	for _, n := range names {
		if cvematch.IsHomebrewDisplayName(n) {
			brew = append(brew, n)
		} else {
			apps = append(apps, n)
		}
	}
	return apps, brew
}

// matchDeviceHomebrew is the Homebrew half of matchDevice: it re-matches the
// named Homebrew packages on one device inside tx and makes
// device_cve_findings agree with the result for exactly those names. The
// ingest, mapping-publish and feed-delta paths all arrive here.
//
// A withdrawn or no-longer-curated mapping re-matches to no findings, and
// they are pruned, exactly as the application path prunes on a withdrawn
// mapping. Pruning never closes anything: the lifecycle reducer closes a
// Homebrew CVE only from a report newer than the evidence it holds whose
// run carries the "homebrew" authoritative scope, and otherwise leaves it
// open (verification_unknown only when a verification was requested).
func matchDeviceHomebrew(ctx context.Context, tx pgx.Tx, feed *feedCache,
	deviceID, tenantID, hostname string, names []string) (matchOutcome, error) {
	var out matchOutcome
	byDevice, _, err := loadHomebrewPackages(ctx, tx, []string{deviceID})
	if err != nil {
		return out, err
	}
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}
	var pkgs []cvematch.HomebrewPackage
	for _, p := range byDevice[deviceID] {
		if wanted[p.DisplayName()] {
			pkgs = append(pkgs, p)
		}
	}
	mappings, err := LoadHomebrewMappings(ctx, tx)
	if err != nil {
		return out, err
	}
	// No review-queue write here (PAT-2045): the nightly run records review
	// rows, so this per-device transaction never locks a shared review row.
	var findings []cvematch.HomebrewFinding
	if keys := cvematch.HomebrewCPEKeys(pkgs, mappings); len(keys) > 0 {
		entries, err := feed.entries(ctx, tx, keys)
		if err != nil {
			return out, err
		}
		findings, _ = cvematch.MatchHomebrew(pkgs, mappings, entries)
	}
	inserted, err := writeHomebrewFindings(ctx, tx, deviceID, findings)
	if err != nil {
		return out, err
	}
	touched := map[string]bool{}
	keepCVE := make([]string, 0, len(findings))
	keepApp := make([]string, 0, len(findings))
	for _, f := range findings {
		touched[f.CVEID] = true
		keepCVE, keepApp = append(keepCVE, f.CVEID), append(keepApp, f.AppName)
	}
	for _, f := range inserted {
		out.New = append(out.New, newFinding{TenantID: tenantID, DeviceID: deviceID, Hostname: hostname,
			CVE: webhook.VulnCVE{CVEID: f.CVEID, Severity: f.Severity, Score: f.Score, AppName: f.AppName}})
	}
	// Prune what this match no longer produces for the named packages. The
	// input only loses a package on an authoritative Homebrew report, and
	// closure is still decided by the lifecycle reducer against the
	// "homebrew" scope, never here.
	pruned, err := tx.Query(ctx, `
		DELETE FROM device_cve_findings f
		WHERE f.device_id = $1::uuid
		  AND f.app_name = ANY($2::text[])
		  AND NOT EXISTS (
			  SELECT 1 FROM unnest($3::text[], $4::text[]) AS keep(cve_id, app_name)
			  WHERE keep.cve_id = f.cve_id AND keep.app_name = f.app_name
		  )
		RETURNING f.cve_id
	`, deviceID, names, keepCVE, keepApp)
	if err != nil {
		return out, fmt.Errorf("prune homebrew findings on %s: %w", deviceID, err)
	}
	for pruned.Next() {
		var cveID string
		if err := pruned.Scan(&cveID); err != nil {
			pruned.Close()
			return out, fmt.Errorf("scan pruned homebrew finding: %w", err)
		}
		touched[cveID] = true
	}
	pruned.Close()
	if err := pruned.Err(); err != nil {
		return out, fmt.Errorf("prune homebrew findings on %s: %w", deviceID, err)
	}
	out.Observations = len(names)
	out.Findings = len(findings)
	for cveID := range touched {
		out.Identities = append(out.Identities, cvelifecycle.Identity{TenantID: tenantID, CVEID: cveID})
	}
	return out, nil
}

// HomebrewFullMatchResult summarises MatchHomebrewFull.
type HomebrewFullMatchResult struct {
	Devices, Packages, Findings int
}

// MatchHomebrewFull is the nightly full match for Homebrew: every current
// formula and cask on every active device, against the whole local feed. It
// writes findings with last_seen_at = NOW(), so the caller's last_seen_at
// prune (which must run after this) removes only findings this run no
// longer produces. An error must stop the caller before that prune, or the
// prune would drop every Homebrew finding it failed to refresh.
func MatchHomebrewFull(ctx context.Context, pool *pgxpool.Pool, feed []cvematch.CVEEntry) (HomebrewFullMatchResult, error) {
	var res HomebrewFullMatchResult
	byDevice, _, err := loadHomebrewPackages(ctx, pool, nil)
	if err != nil {
		return res, err
	}
	if len(byDevice) == 0 {
		return res, nil
	}
	mappings, err := LoadHomebrewMappings(ctx, pool)
	if err != nil {
		return res, err
	}
	devices := make([]string, 0, len(byDevice))
	for deviceID := range byDevice {
		devices = append(devices, deviceID)
	}
	sort.Strings(devices)
	// Device-id order makes the review batch deterministic: which report's
	// metadata a new review row keeps no longer depends on map order.
	var all []cvematch.HomebrewPackage
	for _, deviceID := range devices {
		all = append(all, byDevice[deviceID]...)
	}
	if err := recordHomebrewReview(ctx, pool, all, mappings); err != nil {
		return res, err
	}
	index := cvematch.NewCPEIndex(feed)
	var errs []error
	for _, deviceID := range devices {
		pkgs := byDevice[deviceID]
		findings, _ := cvematch.MatchHomebrewIndexed(pkgs, mappings, index)
		if _, err := writeHomebrewFindings(ctx, pool, deviceID, findings); err != nil {
			errs = append(errs, err)
			continue
		}
		res.Devices++
		res.Packages += len(pkgs)
		res.Findings += len(findings)
	}
	return res, errors.Join(errs...)
}
