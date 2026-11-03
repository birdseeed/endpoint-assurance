package extractor

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// PAT-2013: Homebrew formulae, casks and taps are stored on the PAT-1461
// software observation seam, not in parallel tables. Each becomes an
// ordinary software_observations row in the payload's inventory run with one
// of these identity kinds, and an ordinary software_installations row.
// homebrew_observation_details carries the Homebrew-only evidence.
//
// Identity: the kind, the formula name / cask token / tap name as the value,
// and the tap as the companion. That is Homebrew's own namespace
// ("homebrew/core" + "openssl@3"), which keeps a third-party tap's
// same-named formula distinct. It is package-namespace evidence, not a
// normalised product (AGENTS.md "identity is not packaging"), so it is never
// better than medium confidence and resolves to a product only through a
// reviewed alias, the same as every other observation.
const (
	homebrewFormulaKind = "homebrew_formula"
	homebrewCaskKind    = "homebrew_cask"
	homebrewTapKind     = "homebrew_tap"

	// homebrewAbsenceAuthority is the software_inventory_runs scope a complete
	// or not_present block grants. It closes Homebrew installations only.
	homebrewAbsenceAuthority = "homebrew"

	// homebrewIdentityKindsSQL is the SQL list form of the three kinds, for
	// scope predicates. Constant text, never built from input.
	homebrewIdentityKindsSQL = "('homebrew_formula','homebrew_cask','homebrew_tap')"

	// homebrewDefaultAppDir is where Homebrew moves a cask's app unless the
	// cask or the user overrides appdir.
	homebrewDefaultAppDir = "/Applications"
)

// homebrewForPlatform returns the block only where it is meaningful:
// present, on a macOS payload. Homebrew is macOS-only; a block on any other
// platform is ignored rather than stored against the wrong evidence model.
func homebrewForPlatform(p *payload, platform string) *homebrewPart {
	if p == nil || p.Homebrew == nil || platform != "macos" {
		return nil
	}
	return p.Homebrew
}

// homebrewGrantsAuthority is true only for statuses that prove the device's
// full Homebrew state: complete (everything was read) and not_present (both
// prefixes were checked and neither has Homebrew). partial and failed never
// grant it, so they can never close an installation.
func homebrewGrantsAuthority(hb *homebrewPart) bool {
	return hb != nil && (hb.CollectionStatus == "complete" || hb.CollectionStatus == "not_present")
}

// homebrewWritesEvidence is true when the block's lists are evidence to
// store. failed writes no package rows at all.
func homebrewWritesEvidence(hb *homebrewPart) bool {
	return hb != nil && (hb.CollectionStatus == "complete" || hb.CollectionStatus == "partial")
}

func deriveHomebrewIdentity(kind, name string, tap *string) observedSoftwareIdentity {
	identity := observedSoftwareIdentity{
		Kind:         kind,
		Value:        normalizedIdentityValue(name),
		ObservedName: firstIdentityValue(name, "unknown software"),
		Confidence:   "low",
	}
	if tap != nil {
		identity.Companion = normalizedIdentityValue(*tap)
	}
	// A tap-qualified package is Homebrew's own unique name. A tap
	// observation is its own name. Neither is product identity.
	if kind == homebrewTapKind || identity.Companion != "" {
		identity.Confidence = "medium"
	}
	identity.Fingerprint = identityFingerprint("macos", identity.Kind, identity.Value, identity.Companion)
	return identity
}

func parseHomebrewTime(s *string) *time.Time {
	if s == nil {
		return nil
	}
	parsed, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		return nil
	}
	return &parsed
}

func nilIfEmptyPtr(s *string) *string {
	if s == nil || *s == "" {
		return nil
	}
	return s
}

func jsonTextPtr(v any) (*string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	s := string(b)
	return &s, nil
}

// homebrewEntry is one formula keg, cask or tap as it is stored: its
// observation identity plus every homebrew_observation_details column.
type homebrewEntry struct {
	PackageKind string // formula, cask or tap
	Identity    observedSoftwareIdentity
	Prefix      string
	Name        string
	// ObservedVersion is software_observations.observed_version and the
	// installation's current_version candidate; nil stores NULL.
	ObservedVersion *string

	Version, Tap, Homepage, SourceURL        *string
	ReceiptStatus, FormulaFileStatus         *string
	InstalledOnRequest, InstalledAsDep       *bool
	OptLinked                                *bool
	InstalledAt                              *time.Time
	RuntimeDependencies, VersionsOnDisk      *string // JSON text arrays; nil stores NULL
	Apps                                     *string // JSON; casks only
	TapDirectory, RemoteURL, TapConfigStatus *string
}

type kegDirKey struct{ prefix, name string }

// homebrewFormulaTaps returns, per formula directory (prefix + name), the one
// tap its readable receipts name. A directory whose kegs name more than one
// tap is left out: a tap-less keg there cannot be attributed.
func homebrewFormulaTaps(formulae []homebrewFormulaPart) map[kegDirKey]string {
	seen := map[kegDirKey]map[string]string{}
	for _, f := range formulae {
		if f.Tap == nil || normalizedIdentityValue(*f.Tap) == "" {
			continue
		}
		k := kegDirKey{f.Prefix, f.Name}
		if seen[k] == nil {
			seen[k] = map[string]string{}
		}
		seen[k][normalizedIdentityValue(*f.Tap)] = *f.Tap
	}
	out := make(map[kegDirKey]string, len(seen))
	for k, taps := range seen {
		if len(taps) != 1 {
			continue
		}
		for _, raw := range taps {
			out[k] = raw
		}
	}
	return out
}

// buildHomebrewEntries turns the block into stored entries, formulae then
// casks then taps, in payload order.
//
// PAT-2032 identity reconciliation: every keg of a formula lives in one
// Cellar directory (prefix + name). A keg whose receipt could not be read
// has no tap, and would otherwise become a second, tap-less installation
// beside the tapped one. When the other kegs in that same directory, in the
// same payload, name exactly one tap, the tap-less keg takes that identity at
// low confidence, since the tap is inferred rather than read. Its detail row
// keeps tap NULL, which is what the agent actually reported.
func buildHomebrewEntries(hb *homebrewPart) ([]homebrewEntry, error) {
	entries := make([]homebrewEntry, 0, len(hb.Formulae)+len(hb.Casks)+len(hb.Taps))
	formulaTaps := homebrewFormulaTaps(hb.Formulae)
	for _, f := range hb.Formulae {
		identity := deriveHomebrewIdentity(homebrewFormulaKind, f.Name, f.Tap)
		if identity.Companion == "" {
			if tap, ok := formulaTaps[kegDirKey{f.Prefix, f.Name}]; ok {
				identity = deriveHomebrewIdentity(homebrewFormulaKind, f.Name, &tap)
				identity.Confidence = "low"
			}
		}
		var deps *string
		if f.RuntimeDependencies != nil {
			var err error
			if deps, err = jsonTextPtr(f.RuntimeDependencies); err != nil {
				return nil, fmt.Errorf("marshal homebrew formula dependencies %q: %w", f.Name, err)
			}
		}
		version := f.Version
		entries = append(entries, homebrewEntry{
			PackageKind: "formula", Identity: identity, Prefix: f.Prefix, Name: f.Name,
			ObservedVersion: nilIfEmptyPtr(&version),
			Version:         &version, Tap: f.Tap, Homepage: f.Homepage, SourceURL: f.SourceURL,
			ReceiptStatus: &f.ReceiptStatus, FormulaFileStatus: &f.FormulaFileStatus,
			InstalledOnRequest: f.InstalledOnRequest, InstalledAsDep: f.InstalledAsDependency,
			OptLinked: f.OptLinked, InstalledAt: parseHomebrewTime(f.InstalledAt),
			RuntimeDependencies: deps,
		})
	}
	for _, c := range hb.Casks {
		versionsOnDisk := c.VersionsOnDisk
		if versionsOnDisk == nil {
			versionsOnDisk = []string{}
		}
		apps := c.Apps
		if apps == nil {
			apps = []homebrewCaskAppPart{}
		}
		vod, err := jsonTextPtr(versionsOnDisk)
		if err != nil {
			return nil, fmt.Errorf("marshal homebrew cask versions %q: %w", c.Token, err)
		}
		appsJSON, err := jsonTextPtr(apps)
		if err != nil {
			return nil, fmt.Errorf("marshal homebrew cask apps %q: %w", c.Token, err)
		}
		entries = append(entries, homebrewEntry{
			PackageKind: "cask", Identity: deriveHomebrewIdentity(homebrewCaskKind, c.Token, c.Tap),
			Prefix: c.Prefix, Name: c.Token, ObservedVersion: nilIfEmptyPtr(c.Version),
			Version: c.Version, Tap: c.Tap, InstalledOnRequest: c.InstalledOnRequest,
			InstalledAt: parseHomebrewTime(c.InstalledAt), ReceiptStatus: &c.ReceiptStatus,
			VersionsOnDisk: vod, Apps: appsJSON,
		})
	}
	for _, tp := range hb.Taps {
		dir := tp.Directory
		status := tp.ConfigStatus
		entries = append(entries, homebrewEntry{
			PackageKind: "tap", Identity: deriveHomebrewIdentity(homebrewTapKind, tp.Name, nil),
			Prefix: tp.Prefix, Name: tp.Name,
			TapDirectory: &dir, RemoteURL: tp.RemoteURL, TapConfigStatus: &status,
		})
	}
	return entries, nil
}

// homebrewCurrentKeg reports whether candidate should replace current as the
// entry an installation's current_version and latest_observation_id come
// from, where both share one identity. For formulae the keg opt/ links to
// is current (PAT-2032: not the string-sort maximum, which puts 1.9 above
// 1.10); without a linked keg the most recently installed one; then payload
// order. Casks and taps keep payload order: a second entry is another prefix.
func homebrewCurrentKeg(candidate, current homebrewEntry) bool {
	if candidate.PackageKind != "formula" {
		return true
	}
	cl := candidate.OptLinked != nil && *candidate.OptLinked
	ol := current.OptLinked != nil && *current.OptLinked
	if cl != ol {
		return cl
	}
	switch {
	case candidate.InstalledAt == nil && current.InstalledAt != nil:
		return false
	case candidate.InstalledAt != nil && current.InstalledAt != nil && candidate.InstalledAt.Before(*current.InstalledAt):
		return false
	}
	return true
}

// recordHomebrewObservations writes every formula, cask and tap in the
// block, starting at ordinal ordinalBase. It writes nothing unless the status
// is complete or partial.
//
// PAT-2032: the whole block is five set-based statements whatever its size
// (observations, their ids, resolutions, installations, details), not five
// per package inside the one serial ingest transaction. The rules are the
// ones recordSoftwareObservation applies to an application, with one
// deliberate omission: there is no alias lookup, because the
// software_product_aliases identity_kind CHECK admits no Homebrew kind, so
// every Homebrew observation is unresolved by construction
// (TestHomebrewAliasCheckStillExcludesHomebrewKinds guards that).
func recordHomebrewObservations(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID, runID string, ordinalBase int, hb *homebrewPart) (int, error) {
	if !homebrewWritesEvidence(hb) {
		return 0, nil
	}
	entries, err := buildHomebrewEntries(hb)
	if err != nil {
		return 0, err
	}
	n := len(entries)
	if n == 0 {
		return 0, nil
	}

	ordinals := make([]int32, n)
	names := make([]string, n)
	obsVersions := make([]*string, n)
	identifiers := make([]string, n)
	kinds := make([]string, n)
	values := make([]string, n)
	companions := make([]string, n)
	confidences := make([]string, n)
	fingerprints := make([]string, n)
	for i, e := range entries {
		ordinals[i] = int32(ordinalBase + i)
		names[i] = e.Identity.ObservedName
		obsVersions[i] = e.ObservedVersion
		identifiers[i] = e.Name
		kinds[i] = e.Identity.Kind
		values[i] = e.Identity.Value
		companions[i] = e.Identity.Companion
		confidences[i] = e.Identity.Confidence
		fingerprints[i] = e.Identity.Fingerprint
	}

	// 1. Immutable observations, idempotent on the run ordinal.
	if _, err := tx.Exec(ctx, `
		INSERT INTO software_observations (
			inventory_run_id, tenant_id, device_id, ordinal, platform,
			observed_name, observed_version, observed_identifier, observed_identifier_kind,
			identity_kind, identity_value_normalized, companion_value_normalized,
			identity_confidence, identity_fingerprint, observed_at
		)
		SELECT $1::uuid, $2::uuid, $3::uuid, u.ordinal, 'macos',
		       u.observed_name, u.observed_version, u.identifier, u.kind,
		       u.kind, u.value, u.companion, u.confidence, u.fingerprint, $4
		FROM unnest($5::int4[], $6::text[], $7::text[], $8::text[], $9::text[],
		            $10::text[], $11::text[], $12::text[], $13::text[])
		     AS u(ordinal, observed_name, observed_version, identifier, kind,
		          value, companion, confidence, fingerprint)
		ON CONFLICT (inventory_run_id, ordinal) DO NOTHING
	`, runID, row.TenantID, deviceID, row.ReceivedAt,
		ordinals, names, obsVersions, identifiers, kinds, values, companions, confidences, fingerprints); err != nil {
		return 0, fmt.Errorf("insert homebrew observations: %w", err)
	}

	// 2. Their ids. A replay must reproduce the same identity per ordinal.
	rows, err := tx.Query(ctx, `
		SELECT ordinal, id, identity_fingerprint
		FROM software_observations
		WHERE inventory_run_id = $1::uuid AND ordinal >= $2 AND ordinal < $3
	`, runID, ordinalBase, ordinalBase+n)
	if err != nil {
		return 0, fmt.Errorf("load homebrew observations: %w", err)
	}
	observationIDs := make([]int64, n)
	found := make([]bool, n)
	for rows.Next() {
		var ordinal int
		var id int64
		var fingerprint string
		if err := rows.Scan(&ordinal, &id, &fingerprint); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan homebrew observation: %w", err)
		}
		i := ordinal - ordinalBase
		if fingerprint != entries[i].Identity.Fingerprint {
			rows.Close()
			return 0, fmt.Errorf("software observation %d changed during re-extraction", ordinal)
		}
		observationIDs[i], found[i] = id, true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("load homebrew observations: %w", err)
	}
	for i, ok := range found {
		if !ok {
			return 0, fmt.Errorf("load existing software observation %d: missing", ordinalBase+i)
		}
	}

	// 3. Resolutions: always unresolved (no Homebrew alias can exist).
	if _, err := tx.Exec(ctx, `
		INSERT INTO software_observation_resolutions (
			observation_id, tenant_id, resolution_state, resolution_method
		)
		SELECT u.id, $2::uuid, 'unresolved', 'none'
		FROM unnest($1::int8[]) AS u(id)
		ON CONFLICT (observation_id) DO NOTHING
	`, observationIDs, row.TenantID); err != nil {
		return 0, fmt.Errorf("record unresolved homebrew observations: %w", err)
	}

	// 4. Installations: one row per identity. ON CONFLICT cannot touch a row
	// twice in one statement, so kegs sharing an identity are folded first,
	// keeping the current keg (homebrewCurrentKeg).
	current := map[string]int{}
	order := []string{}
	for i, e := range entries {
		fp := e.Identity.Fingerprint
		j, seen := current[fp]
		if !seen {
			order = append(order, fp)
			current[fp] = i
			continue
		}
		if homebrewCurrentKeg(e, entries[j]) {
			current[fp] = i
		}
	}
	// PAT-2032 review: a partial report that read no linked keg of a
	// formula did not read the keg Homebrew treats as current (it may be the
	// vulnerable one), so it must not move current_version to whichever keg
	// it did read. A complete report read every keg, so its fallback stands.
	var keepVersion []string
	if hb.CollectionStatus == "partial" {
		linked := map[string]bool{}
		for _, e := range entries {
			if e.PackageKind == "formula" && e.OptLinked != nil && *e.OptLinked {
				linked[e.Identity.Fingerprint] = true
			}
		}
		for _, fp := range order {
			if entries[current[fp]].PackageKind == "formula" && !linked[fp] {
				keepVersion = append(keepVersion, fp)
			}
		}
	}
	// PAT-2032b: a cask entry with no observed version (the agent reports
	// null when its receipt is unreadable but the app is still on disk) is
	// never evidence of a version change, whatever the report's collection
	// status. It must not blank a stored non-null current_version. A cask
	// seen for the first time with a null version has nothing to keep: the
	// plain INSERT branch (no conflicting row) stores NULL either way, so
	// this only guards the ON CONFLICT UPDATE path.
	for _, fp := range order {
		if e := entries[current[fp]]; e.PackageKind == "cask" && e.ObservedVersion == nil {
			keepVersion = append(keepVersion, fp)
		}
	}
	if keepVersion == nil {
		keepVersion = []string{}
	}
	m := len(order)
	iKinds := make([]string, m)
	iValues := make([]string, m)
	iCompanions := make([]string, m)
	iFingerprints := make([]string, m)
	iNames := make([]string, m)
	iVersions := make([]*string, m)
	iObservations := make([]int64, m)
	for k, fp := range order {
		i := current[fp]
		e := entries[i]
		iKinds[k], iValues[k], iCompanions[k], iFingerprints[k] = e.Identity.Kind, e.Identity.Value, e.Identity.Companion, fp
		iNames[k], iVersions[k], iObservations[k] = e.Identity.ObservedName, e.ObservedVersion, observationIDs[i]
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO software_installations (
			tenant_id, device_id, product_id, alias_id, platform,
			identity_kind, identity_value_normalized, companion_value_normalized,
			identity_fingerprint, current_name, current_version, current_publisher,
			current_path, current_architecture, resolution_confidence,
			first_seen_at, last_seen_at, latest_observation_id, provenance
		)
		SELECT $1::uuid, $2::uuid, NULL, NULL, 'macos',
		       u.kind, u.value, u.companion, u.fingerprint, u.name, u.version, NULL,
		       NULL, NULL, NULL,
		       $3, $3, u.observation_id, 'inventory_payload'
		FROM unnest($4::text[], $5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::int8[])
		     AS u(kind, value, companion, fingerprint, name, version, observation_id)
		ON CONFLICT (device_id, identity_fingerprint) DO UPDATE SET
			product_id = COALESCE(EXCLUDED.product_id, software_installations.product_id),
			alias_id = COALESCE(EXCLUDED.alias_id, software_installations.alias_id),
			resolution_confidence = COALESCE(EXCLUDED.resolution_confidence, software_installations.resolution_confidence),
			first_seen_at = LEAST(EXCLUDED.first_seen_at, software_installations.first_seen_at),
			current_name = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.current_name ELSE software_installations.current_name END,
			current_version = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at
			                        AND NOT (EXCLUDED.identity_fingerprint = ANY($11::text[]))
			                       THEN EXCLUDED.current_version ELSE software_installations.current_version END,
			current_publisher = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.current_publisher ELSE software_installations.current_publisher END,
			current_path = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.current_path ELSE software_installations.current_path END,
			current_architecture = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.current_architecture ELSE software_installations.current_architecture END,
			latest_observation_id = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.latest_observation_id ELSE software_installations.latest_observation_id END,
			provenance = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.provenance ELSE software_installations.provenance END,
			last_seen_at = GREATEST(EXCLUDED.last_seen_at, software_installations.last_seen_at),
			removed_at = CASE
				WHEN software_installations.removed_at IS NULL THEN NULL
				WHEN EXCLUDED.last_seen_at >= software_installations.removed_at THEN NULL
				ELSE software_installations.removed_at
			END,
			updated_at = now()
	`, row.TenantID, deviceID, row.ReceivedAt,
		iKinds, iValues, iCompanions, iFingerprints, iNames, iVersions, iObservations, keepVersion); err != nil {
		return 0, fmt.Errorf("upsert homebrew installations: %w", err)
	}

	// 5. Homebrew-only evidence, immutable like the observation it extends.
	dKinds := make([]string, n)
	dPrefixes := make([]string, n)
	dNames := make([]string, n)
	dVersions := make([]*string, n)
	dTaps := make([]*string, n)
	dOnRequest := make([]*bool, n)
	dAsDep := make([]*bool, n)
	dInstalledAt := make([]*time.Time, n)
	dDeps := make([]*string, n)
	dHomepages := make([]*string, n)
	dSources := make([]*string, n)
	dOptLinked := make([]*bool, n)
	dReceipts := make([]*string, n)
	dFormulaFiles := make([]*string, n)
	dVersionsOnDisk := make([]*string, n)
	dApps := make([]*string, n)
	dTapDirs := make([]*string, n)
	dRemotes := make([]*string, n)
	dConfigs := make([]*string, n)
	for i, e := range entries {
		dKinds[i], dPrefixes[i], dNames[i] = e.PackageKind, e.Prefix, e.Name
		dVersions[i], dTaps[i] = e.Version, e.Tap
		dOnRequest[i], dAsDep[i], dInstalledAt[i] = e.InstalledOnRequest, e.InstalledAsDep, e.InstalledAt
		dDeps[i], dHomepages[i], dSources[i], dOptLinked[i] = e.RuntimeDependencies, e.Homepage, e.SourceURL, e.OptLinked
		dReceipts[i], dFormulaFiles[i] = e.ReceiptStatus, e.FormulaFileStatus
		dVersionsOnDisk[i], dApps[i] = e.VersionsOnDisk, e.Apps
		dTapDirs[i], dRemotes[i], dConfigs[i] = e.TapDirectory, e.RemoteURL, e.TapConfigStatus
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO homebrew_observation_details (
			observation_id, tenant_id, device_id, inventory_run_id, package_kind,
			prefix, name, version, tap, installed_on_request, installed_as_dependency,
			installed_at, runtime_dependencies, homepage, source_url, opt_linked,
			receipt_status, formula_file_status, versions_on_disk, apps,
			tap_directory, remote_url, config_status, observed_at
		)
		SELECT u.observation_id, $1::uuid, $2::uuid, $3::uuid, u.package_kind,
		       u.prefix, u.name, u.version, u.tap, u.installed_on_request, u.installed_as_dependency,
		       u.installed_at,
		       CASE WHEN u.runtime_dependencies IS NULL THEN NULL ELSE
		            ARRAY(SELECT d.v FROM jsonb_array_elements_text(u.runtime_dependencies::jsonb)
		                  WITH ORDINALITY AS d(v, n) ORDER BY d.n) END,
		       u.homepage, u.source_url, u.opt_linked,
		       u.receipt_status, u.formula_file_status,
		       CASE WHEN u.versions_on_disk IS NULL THEN NULL ELSE
		            ARRAY(SELECT d.v FROM jsonb_array_elements_text(u.versions_on_disk::jsonb)
		                  WITH ORDINALITY AS d(v, n) ORDER BY d.n) END,
		       u.apps::jsonb,
		       u.tap_directory, u.remote_url, u.config_status, $4
		FROM unnest($5::int8[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[],
		            $11::bool[], $12::bool[], $13::timestamptz[], $14::text[], $15::text[],
		            $16::text[], $17::bool[], $18::text[], $19::text[], $20::text[],
		            $21::text[], $22::text[], $23::text[], $24::text[])
		     AS u(observation_id, package_kind, prefix, name, version, tap,
		          installed_on_request, installed_as_dependency, installed_at, runtime_dependencies, homepage,
		          source_url, opt_linked, receipt_status, formula_file_status, versions_on_disk,
		          apps, tap_directory, remote_url, config_status)
		ON CONFLICT (observation_id) DO NOTHING
	`, row.TenantID, deviceID, runID, row.ReceivedAt,
		observationIDs, dKinds, dPrefixes, dNames, dVersions, dTaps,
		dOnRequest, dAsDep, dInstalledAt, dDeps, dHomepages,
		dSources, dOptLinked, dReceipts, dFormulaFiles, dVersionsOnDisk,
		dApps, dTapDirs, dRemotes, dConfigs); err != nil {
		return 0, fmt.Errorf("insert homebrew details: %w", err)
	}
	return n, nil
}

// homebrewCaskAppLink is where one cask app entry may link, and on what
// basis. ok is false when the entry may not link at all.
func homebrewCaskAppLink(c homebrewCaskPart, app homebrewCaskAppPart) (appPath, basis string, ok bool) {
	if app.Path != nil && strings.TrimSpace(*app.Path) != "" {
		// PAT-2032: the agent reports a path only for an app, or a symlink
		// to one, inside the cask's version directory, and resolves a symlink
		// to its target. Homebrew moves app artifacts out of the Caskroom
		// rather than symlinking them from it, so a target outside this
		// cask's own Caskroom directory is a link someone placed there, not
		// evidence the cask installed that app. It does not link, and it does
		// not fall back to the default appdir either.
		token := strings.TrimSpace(c.Token)
		if token == "" || token == "." || token == ".." || strings.Contains(token, "/") {
			return "", "", false
		}
		cleaned := path.Clean(strings.TrimSpace(*app.Path))
		caskroom := path.Join(path.Clean(c.Prefix), "Caskroom", token) + "/"
		if !path.IsAbs(cleaned) || !strings.HasPrefix(cleaned, caskroom) {
			return "", "", false
		}
		return cleaned, "reported_path", true
	}
	name := strings.TrimSpace(app.Name)
	if name == "" || strings.Contains(name, "/") || name == "." || name == ".." {
		return "", "", false
	}
	// A name-based guess at Homebrew's default appdir. It ignores a cask's
	// target: rename and a custom appdir, and cannot tell a name from the
	// receipt from a name found on disk, so it is recorded for display but
	// never used to count the software once (report.homebrewCurrentCTE).
	return homebrewDefaultAppDir + "/" + name, "default_appdir", true
}

// linkHomebrewCasksToApps records which application bundle installation each
// cask installed (PAT-2013).
//
// Match rule, by path on the same device, against active application
// installations only (homebrewCaskAppLink decides the path):
//   - reported_path: an app the agent found inside the cask's own Caskroom
//     directory links at that path. Only these links make the estate count
//     the software once.
//   - default_appdir: an app reported without a path links at
//     /Applications/<name>. It is shown, but the cask is still counted: a
//     guess is not evidence enough to hide an installation.
//
// A cask whose receipt was read is authoritative about its own apps, so its
// links are replaced. Otherwise links are only added. Only the newest
// evidence for a cask installation may change its links. PAT-2032: two
// set-based statements at most, whatever the number of casks.
func linkHomebrewCasksToApps(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID string, hb *homebrewPart) error {
	if !homebrewWritesEvidence(hb) || len(hb.Casks) == 0 {
		return nil
	}
	var replace, fingerprints, paths, bases []string
	replaced := map[string]bool{}
	for _, c := range hb.Casks {
		fp := deriveHomebrewIdentity(homebrewCaskKind, c.Token, c.Tap).Fingerprint
		if c.ReceiptStatus == "read" && !replaced[fp] {
			replaced[fp] = true
			replace = append(replace, fp)
		}
		for _, app := range c.Apps {
			appPath, basis, ok := homebrewCaskAppLink(c, app)
			if !ok {
				continue
			}
			fingerprints = append(fingerprints, fp)
			paths = append(paths, appPath)
			bases = append(bases, basis)
		}
	}
	if len(replace) > 0 {
		if _, err := tx.Exec(ctx, `
			DELETE FROM homebrew_cask_app_links l
			USING software_installations ci
			WHERE l.cask_installation_id = ci.id
			  AND ci.tenant_id = $1::uuid AND ci.device_id = $2::uuid
			  AND ci.identity_fingerprint = ANY($3::text[])
			  AND ci.last_seen_at <= $4
		`, row.TenantID, deviceID, replace, row.ReceivedAt); err != nil {
			return fmt.Errorf("replace homebrew cask links: %w", err)
		}
	}
	if len(fingerprints) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO homebrew_cask_app_links (
			tenant_id, device_id, cask_installation_id, app_installation_id,
			app_path, link_basis, cask_observation_id, linked_at
		)
		SELECT DISTINCT ON (ci.id, si.id)
		       $1::uuid, $2::uuid, ci.id, si.id, u.app_path, u.link_basis, ci.latest_observation_id, $3
		FROM unnest($4::text[], $5::text[], $6::text[]) WITH ORDINALITY AS u(fingerprint, app_path, link_basis, n)
		JOIN software_installations ci
		  ON ci.tenant_id = $1::uuid AND ci.device_id = $2::uuid
		 AND ci.identity_fingerprint = u.fingerprint AND ci.last_seen_at <= $3
		JOIN software_installations si
		  ON si.tenant_id = $1::uuid AND si.device_id = $2::uuid
		 AND si.removed_at IS NULL
		 AND si.identity_kind NOT IN `+homebrewIdentityKindsSQL+`
		 AND rtrim(si.current_path, '/') = u.app_path
		ORDER BY ci.id, si.id, (u.link_basis = 'reported_path') DESC, u.n DESC
		ON CONFLICT (cask_installation_id, app_installation_id) DO UPDATE SET
			app_path = EXCLUDED.app_path,
			link_basis = EXCLUDED.link_basis,
			cask_observation_id = EXCLUDED.cask_observation_id,
			linked_at = EXCLUDED.linked_at
	`, row.TenantID, deviceID, row.ReceivedAt, fingerprints, paths, bases); err != nil {
		return fmt.Errorf("link homebrew casks to apps: %w", err)
	}
	return nil
}

// lockHomebrewDeviceState takes the per-device Homebrew lock for the rest of
// the ingest transaction (PAT-2032 review). ProcessOnce can run beside the
// worker, so without it an older partial report could read the authority
// before a newer complete one commits, and both would commit. The state row
// is created first if missing, as a placeholder that sorts before any real
// report; upsertHomebrewDeviceState overwrites it in the same transaction.
func lockHomebrewDeviceState(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID string, hb *homebrewPart) error {
	if hb == nil {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO homebrew_device_state (device_id, tenant_id, collection_status, reported_at)
		VALUES ($1::uuid, $2::uuid, $3, '-infinity'::timestamptz)
		ON CONFLICT (device_id) DO NOTHING
	`, deviceID, row.TenantID, hb.CollectionStatus); err != nil {
		return fmt.Errorf("create homebrew device state: %w", err)
	}
	var locked string
	if err := tx.QueryRow(ctx, `
		SELECT device_id::text FROM homebrew_device_state
		WHERE device_id = $1::uuid AND tenant_id = $2::uuid
		FOR UPDATE
	`, deviceID, row.TenantID).Scan(&locked); err != nil {
		return fmt.Errorf("lock homebrew device state: %w", err)
	}
	return nil
}

// upsertHomebrewCurrentEntries maintains homebrew_current_entries, the
// portal's "current" list (PAT-2032), so a read never scans a device's
// history.
//
// One row per (device, kind, prefix, name, version_key): the newest report
// that listed that formula keg, cask or tap. version_key is the keg version
// for a formula and ” for a cask or tap, whose single record is read whole.
// A partial report only adds or refreshes rows. It can list a formula
// without having read every keg of it (the formula bound cuts mid-formula,
// the time check runs per keg, an unreadable keg directory is skipped), so
// it never hides a keg. Only a complete or not_present report drops the rows
// it did not refresh. A replay older than the device's authority writes
// nothing. The caller holds lockHomebrewDeviceState.
func upsertHomebrewCurrentEntries(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID, runID string, hb *homebrewPart) error {
	if hb == nil {
		return nil
	}
	if homebrewWritesEvidence(hb) {
		var kinds, prefixes, names, versions []string
		seen := map[[4]string]bool{}
		add := func(kind, prefix, name, version string) {
			k := [4]string{kind, prefix, name, version}
			if !seen[k] {
				seen[k] = true
				kinds, prefixes = append(kinds, kind), append(prefixes, prefix)
				names, versions = append(names, name), append(versions, version)
			}
		}
		for _, f := range hb.Formulae {
			add("formula", f.Prefix, f.Name, f.Version)
		}
		for _, c := range hb.Casks {
			add("cask", c.Prefix, c.Token, "")
		}
		for _, tp := range hb.Taps {
			add("tap", tp.Prefix, tp.Name, "")
		}
		if len(kinds) > 0 {
			if _, err := tx.Exec(ctx, `
				INSERT INTO homebrew_current_entries (
					tenant_id, device_id, package_kind, prefix, name, version_key,
					observed_at, inventory_run_id
				)
				SELECT $1::uuid, $2::uuid, u.kind, u.prefix, u.name, u.version_key, $3, $4::uuid
				FROM unnest($5::text[], $6::text[], $7::text[], $8::text[]) AS u(kind, prefix, name, version_key)
				WHERE $3 >= COALESCE((SELECT s.authority_at FROM homebrew_device_state s
				                      WHERE s.device_id = $2::uuid AND s.tenant_id = $1::uuid),
				                     '-infinity'::timestamptz)
				ON CONFLICT (device_id, package_kind, prefix, name, version_key) DO UPDATE SET
					observed_at = EXCLUDED.observed_at,
					inventory_run_id = EXCLUDED.inventory_run_id
				WHERE EXCLUDED.observed_at >= homebrew_current_entries.observed_at
				  AND homebrew_current_entries.tenant_id = EXCLUDED.tenant_id
			`, row.TenantID, deviceID, row.ReceivedAt, runID, kinds, prefixes, names, versions); err != nil {
				return fmt.Errorf("upsert homebrew current entries: %w", err)
			}
		}
	}
	if homebrewGrantsAuthority(hb) {
		if _, err := tx.Exec(ctx, `
			DELETE FROM homebrew_current_entries
			WHERE tenant_id = $1::uuid AND device_id = $2::uuid AND observed_at < $3
		`, row.TenantID, deviceID, row.ReceivedAt); err != nil {
			return fmt.Errorf("prune homebrew current entries: %w", err)
		}
	}
	return nil
}

// upsertHomebrewDeviceState records the newest collection_status per device.
// It runs for every status, failed included, because "failed" and
// "not_present" must stay distinguishable to the portal. An older replay
// never overwrites a newer report, and authority_at only ever moves forward,
// only on complete or not_present.
func upsertHomebrewDeviceState(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID, runID string, hb *homebrewPart) error {
	if hb == nil {
		return nil
	}
	prefixes := hb.Prefixes
	if prefixes == nil {
		prefixes = []homebrewPrefixPart{}
	}
	issues := hb.Issues
	if issues == nil {
		issues = []homebrewIssuePart{}
	}
	prefixesJSON, err := json.Marshal(prefixes)
	if err != nil {
		return fmt.Errorf("marshal homebrew prefixes: %w", err)
	}
	issuesJSON, err := json.Marshal(issues)
	if err != nil {
		return fmt.Errorf("marshal homebrew issues: %w", err)
	}
	var authorityAt any
	if homebrewGrantsAuthority(hb) {
		authorityAt = row.ReceivedAt
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO homebrew_device_state (
			device_id, tenant_id, collection_status, truncated, truncation_reason,
			prefixes, issues, reported_at, raw_payload_id, raw_payload_received_at,
			inventory_run_id, authority_at
		) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6::jsonb, $7::jsonb, $8, $9, $8, $10::uuid, $11)
		ON CONFLICT (device_id) DO UPDATE SET
			collection_status = CASE WHEN EXCLUDED.reported_at >= homebrew_device_state.reported_at THEN EXCLUDED.collection_status ELSE homebrew_device_state.collection_status END,
			truncated = CASE WHEN EXCLUDED.reported_at >= homebrew_device_state.reported_at THEN EXCLUDED.truncated ELSE homebrew_device_state.truncated END,
			truncation_reason = CASE WHEN EXCLUDED.reported_at >= homebrew_device_state.reported_at THEN EXCLUDED.truncation_reason ELSE homebrew_device_state.truncation_reason END,
			prefixes = CASE WHEN EXCLUDED.reported_at >= homebrew_device_state.reported_at THEN EXCLUDED.prefixes ELSE homebrew_device_state.prefixes END,
			issues = CASE WHEN EXCLUDED.reported_at >= homebrew_device_state.reported_at THEN EXCLUDED.issues ELSE homebrew_device_state.issues END,
			raw_payload_id = CASE WHEN EXCLUDED.reported_at >= homebrew_device_state.reported_at THEN EXCLUDED.raw_payload_id ELSE homebrew_device_state.raw_payload_id END,
			raw_payload_received_at = CASE WHEN EXCLUDED.reported_at >= homebrew_device_state.reported_at THEN EXCLUDED.raw_payload_received_at ELSE homebrew_device_state.raw_payload_received_at END,
			inventory_run_id = CASE WHEN EXCLUDED.reported_at >= homebrew_device_state.reported_at THEN EXCLUDED.inventory_run_id ELSE homebrew_device_state.inventory_run_id END,
			reported_at = GREATEST(EXCLUDED.reported_at, homebrew_device_state.reported_at),
			authority_at = GREATEST(EXCLUDED.authority_at, homebrew_device_state.authority_at),
			updated_at = now()
		WHERE homebrew_device_state.tenant_id = EXCLUDED.tenant_id
	`, deviceID, row.TenantID, hb.CollectionStatus, hb.Truncated, hb.TruncationReason,
		string(prefixesJSON), string(issuesJSON), row.ReceivedAt, row.ID, runID, authorityAt); err != nil {
		return fmt.Errorf("upsert homebrew device state: %w", err)
	}
	return nil
}
