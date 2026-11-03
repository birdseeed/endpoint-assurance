package extractor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

type observedSoftwareIdentity struct {
	Kind         string
	Value        string
	Companion    string
	Confidence   string
	Fingerprint  string
	ObservedName string
}

type softwareResolution struct {
	ProductID  string
	AliasID    string
	Confidence string
}

func normalizedIdentityValue(value string) string {
	return strings.ToLower(strings.Join(strings.Fields(value), " "))
}

func normalizedTeamID(value string) string {
	return strings.ToUpper(strings.Join(strings.Fields(value), " "))
}

func firstIdentityValue(values ...string) string {
	for _, value := range values {
		if normalized := strings.TrimSpace(value); normalized != "" && !strings.EqualFold(normalized, "unknown") {
			return normalized
		}
	}
	return ""
}

func identityFingerprint(platform, kind, value, companion string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{platform, kind, value, companion}, "\x1f")))
	return hex.EncodeToString(sum[:])
}

// deriveObservedSoftwareIdentity describes what the endpoint actually
// reported. It does not create a software product and never treats a signer,
// publisher, or Team ID by itself as product identity.
//
// ObservedName mirrors the device_apps precedent in upsert.go (name is
// NOT NULL there too; a missing collector-reported name falls back to the
// identifier) rather than persisting app.Name verbatim: an observation with
// no name is still real evidence and must be preserved, not dropped or
// allowed to fail the insert (AGENTS.md "Absence requires authority").
func deriveObservedSoftwareIdentity(platform string, app appPart) observedSoftwareIdentity {
	identifier := firstIdentityValue(app.Identifier, app.BundleID)
	name := firstIdentityValue(app.Name, app.Path, identifier, "unknown software")
	publisher := firstIdentityValue(app.SignedBy, app.Publisher)

	identity := observedSoftwareIdentity{Confidence: "low", ObservedName: name}
	switch {
	case platform == "macos" && identifier != "" && firstIdentityValue(app.TeamID) != "":
		identity.Kind = "macos_bundle_team"
		identity.Value = normalizedIdentityValue(identifier)
		identity.Companion = normalizedTeamID(app.TeamID)
		identity.Confidence = "exact"
	case platform == "macos" && identifier != "":
		identity.Kind = "macos_bundle"
		identity.Value = normalizedIdentityValue(identifier)
		identity.Confidence = "medium"
	case platform == "windows" && app.IdentifierKind == "winget" && isCanonicalWingetInventoryID(identifier):
		identity.Kind = "windows_winget"
		identity.Value = normalizedIdentityValue(identifier)
		// The current contract does not carry the Winget source, so the
		// observation is not independently high-confidence product identity.
		identity.Confidence = "medium"
	case platform == "windows" && identifier != "" && publisher != "":
		identity.Kind = "windows_native_publisher"
		identity.Value = normalizedIdentityValue(identifier)
		identity.Companion = normalizedIdentityValue(publisher)
		identity.Confidence = "medium"
	case platform == "windows" && identifier != "":
		identity.Kind = "windows_native"
		identity.Value = normalizedIdentityValue(identifier)
	case publisher != "" || firstIdentityValue(app.TeamID) != "":
		identity.Kind = "name_publisher"
		identity.Value = normalizedIdentityValue(name)
		identity.Companion = normalizedIdentityValue(firstIdentityValue(publisher, app.TeamID))
	default:
		identity.Kind = "display_name"
		identity.Value = normalizedIdentityValue(name)
	}

	identity.Fingerprint = identityFingerprint(platform, identity.Kind, identity.Value, identity.Companion)
	return identity
}

func authoritativeSoftwareScopes(p *payload, platform string) []string {
	if p.AppsAbsenceWithheld {
		// PAT-2063: this report's apps array was not trusted to prove a
		// removal (collection_status.apps, or the no-signal safety valve), so
		// neither application scope may close an installation or a finding.
		// Homebrew and tooling carry their own authority and are unaffected.
		return nil
	}
	if platform == "macos" && p.AppsPresent {
		// apps is a required full snapshot in every supported macOS payload.
		return []string{"all_software"}
	}
	if platform != "windows" || !p.AppsPresent || p.InventoryCapabilities == nil ||
		p.InventoryCapabilities.SchemaVersion != 1 ||
		!p.InventoryCapabilities.WindowsWingetInventoryComplete {
		return nil
	}
	for _, app := range p.Apps {
		switch app.IdentifierKind {
		case "native":
			continue
		case "winget":
			if isCanonicalWingetInventoryID(firstIdentityValue(app.Identifier, app.BundleID)) {
				continue
			}
		}
		// A malformed or untyped row invalidates the whole absence claim.
		return nil
	}
	return []string{"windows_winget"}
}

// findSoftwareResolution returns the live curated alias for an observed
// identity, if any. A retired alias resolves nothing new; an installation it
// already resolved keeps that link as history (the upsert below never clears
// one).
func findSoftwareResolution(ctx context.Context, tx pgx.Tx, identity observedSoftwareIdentity, platform string) (softwareResolution, error) {
	var resolution softwareResolution
	err := tx.QueryRow(ctx, `
		SELECT id::text, product_id::text, match_confidence
		FROM software_product_aliases
		WHERE platform = $1
		  AND identity_kind = $2
		  AND identity_value_normalized = $3
		  AND companion_value_normalized = $4
		  AND retired_at IS NULL
	`, platform, identity.Kind, identity.Value, identity.Companion).Scan(
		&resolution.AliasID, &resolution.ProductID, &resolution.Confidence,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return softwareResolution{}, nil
	}
	if err != nil {
		return softwareResolution{}, fmt.Errorf("resolve software identity %s/%s: %w", platform, identity.Kind, err)
	}
	return resolution, nil
}

// upsertSoftwareInventory dual-extracts the immutable observation domain from
// the same authenticated payload as device_apps. It has no policy, package,
// deployment, or remediation side effects.
func upsertSoftwareInventory(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID string, p *payload, platform string) (int, error) {
	scopes := authoritativeSoftwareScopes(p, platform)
	if scopes == nil {
		// pgx encodes a nil slice as SQL NULL. The schema uses an empty array to
		// mean "no absence authority", so preserve that distinction explicitly.
		scopes = []string{}
	}
	wingetComplete := len(scopes) == 1 && scopes[0] == "windows_winget"
	// PAT-2013: a complete or not_present Homebrew block carries its own,
	// separate absence authority. partial and failed carry none.
	hb := homebrewForPlatform(p, platform)
	// PAT-2032 review: serialise Homebrew ingest per device before anything
	// reads or writes Homebrew state.
	if err := lockHomebrewDeviceState(ctx, tx, row, deviceID, hb); err != nil {
		return 0, err
	}
	if homebrewGrantsAuthority(hb) {
		scopes = append(scopes, homebrewAbsenceAuthority)
	}
	// PAT-2021: IDE extensions, packages, local models and MCP servers.
	// Serialise their ingest per device and block, then record the units
	// this report is authoritative for, each as its own scope.
	if err := lockToolingDeviceState(ctx, tx, row, deviceID, p); err != nil {
		return 0, err
	}
	toolingAuth := toolingAuthorities(p)
	for _, a := range toolingAuth {
		scopes = append(scopes, toolingScope(a))
	}
	toolingStatus := map[string]any{}
	blocks, statuses := toolingBlocksPresent(p)
	for i, b := range blocks {
		toolingStatus[b] = statuses[i]
	}
	coverage, err := json.Marshal(map[string]any{
		"all_software":                      platform == "macos" && !p.AppsAbsenceWithheld,
		"windows_winget_inventory_complete": wingetComplete,
		// PAT-2063: the explicit apps status as sent (nil when absent), and
		// whether this run's application absence authority was withheld.
		"apps_collection_status": func() any {
			if p.CollectionStatus == nil || p.CollectionStatus.Apps == "" {
				return nil
			}
			return p.CollectionStatus.Apps
		}(),
		"apps_absence_withheld": p.AppsAbsenceWithheld,
		// PAT-2075: machine-wide rows located in a user's home that this
		// report held because it had no authority over that home.
		"apps_legacy_user_held": len(p.AppsLegacyHeld),
		"homebrew_collection_status": func() any {
			if hb == nil {
				return nil
			}
			return hb.CollectionStatus
		}(),
		"ide_extensions_collection_status":   toolingStatus[toolingBlockIDE],
		"package_managers_collection_status": toolingStatus[toolingBlockPackages],
		"local_models_collection_status":     toolingStatus[toolingBlockModels],
		"mcp_servers_collection_status":      toolingStatus[toolingBlockMCP],
		"inventory_capability_schema": func() any {
			if p.InventoryCapabilities == nil {
				return nil
			}
			return p.InventoryCapabilities.SchemaVersion
		}(),
	})
	if err != nil {
		return 0, fmt.Errorf("marshal software inventory coverage: %w", err)
	}

	var collectedAt any
	if parsed, parseErr := time.Parse(time.RFC3339, p.CollectedAt); parseErr == nil {
		collectedAt = parsed
	}

	var runID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO software_inventory_runs (
			tenant_id, device_id, raw_payload_id, raw_payload_received_at,
			platform, agent, agent_version, collected_at, received_at,
			provenance, coverage, authoritative_scopes
		) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $4,
		          'inventory_payload', $9::jsonb, $10::text[])
		ON CONFLICT (raw_payload_id, raw_payload_received_at) DO NOTHING
		RETURNING id::text
	`, row.TenantID, deviceID, row.ID, row.ReceivedAt, platform, p.Agent, p.AgentVersion,
		collectedAt, coverage, scopes).Scan(&runID); err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("insert software inventory run: %w", err)
		}
		if err := tx.QueryRow(ctx, `
			SELECT id::text
			FROM software_inventory_runs
			WHERE raw_payload_id = $1 AND raw_payload_received_at = $2
			  AND tenant_id = $3::uuid AND device_id = $4::uuid
		`, row.ID, row.ReceivedAt, row.TenantID, deviceID).Scan(&runID); err != nil {
			return 0, fmt.Errorf("load existing software inventory run: %w", err)
		}
	}

	written := 0
	for ordinal, app := range p.Apps {
		identity := deriveObservedSoftwareIdentity(platform, app)
		authenticode := windowsSignatureEvidence(platform, app.InstallationEvidence)
		if _, err := recordSoftwareObservation(ctx, tx, row, deviceID, runID, ordinal, platform, observationRecord{
			Identity:           identity,
			Version:            app.Version,
			Identifier:         firstIdentityValue(app.Identifier, app.BundleID),
			IdentifierKind:     app.IdentifierKind,
			Publisher:          app.Publisher,
			Signer:             app.SignedBy,
			TeamID:             app.TeamID,
			Path:               app.Path,
			Architecture:       app.Architecture,
			SHA256:             nullIfPlaceholder(app.SHA256),
			Notarized:          app.Notarized,
			SigningStatus:      macOSSigningStatus(platform, app.SigningStatus),
			NotarizationStatus: macOSNotarizationStatus(platform, app.NotarizationStatus),
			Authenticode:       authenticode,
			CurrentName:        firstIdentityValue(app.Name, app.Path, identity.Value),
			CurrentPublisher:   firstIdentityValue(app.SignedBy, app.Publisher),
		}); err != nil {
			return written, err
		}
		written++
	}

	// PAT-2013: Homebrew formulae, casks and taps join the same run after the
	// applications, so their ordinals follow the apps and a replay of the
	// same raw payload reproduces them exactly.
	brewWritten, err := recordHomebrewObservations(ctx, tx, row, deviceID, runID, len(p.Apps), hb)
	written += brewWritten
	if err != nil {
		return written, err
	}

	// PAT-2021: the tooling blocks follow, in a fixed block order, so a
	// replay reproduces their ordinals too.
	toolingEntries, err := buildToolingEntries(p, platform)
	if err != nil {
		return written, err
	}
	toolingIDs, err := recordToolingObservations(ctx, tx, row, deviceID, runID, platform, len(p.Apps)+brewWritten, toolingEntries)
	if err != nil {
		return written, err
	}
	written += len(toolingEntries)

	// PAT-2075: installations of held legacy user-located rows stay open
	// under the application scopes (apps_legacy_user.go).
	heldLegacyApps, err := loadHeldLegacyApps(ctx, tx, p.AppsLegacyHeld)
	if err != nil {
		return written, err
	}
	heldLegacyValues := heldLegacyInstallationValues(heldLegacyApps)

	for _, scope := range scopes {
		// Each scope closes only its own identity kinds. all_software is the
		// macOS apps snapshot and never closes a Homebrew installation;
		// homebrew (PAT-2013) closes nothing but Homebrew installations.
		// PAT-2021: all_software closes no tooling installation either, and
		// the tooling scopes are closed together below, each by its own kinds.
		var kindPredicate string
		args := []any{row.TenantID, deviceID, row.ReceivedAt, platform, runID}
		switch scope {
		//
		// PAT-2075: the two application scopes speak for the machine-wide
		// scope and the users this report read in full. An installation a
		// per-user scope still holds (a logged-off or partially read user's
		// app, see apps_users.go) is not closed by either.
		case "all_software":
			kindPredicate = " AND si.identity_kind NOT IN " + homebrewIdentityKindsSQL +
				" AND si.identity_kind NOT IN " + toolingIdentityKindsSQL +
				heldUserScopeInstallationSQL + heldLegacyInstallationSQL
			args = append(args, heldLegacyValues)
		case "windows_winget":
			kindPredicate = " AND si.identity_kind = 'windows_winget'" + heldUserScopeInstallationSQL + heldLegacyInstallationSQL
			args = append(args, heldLegacyValues)
		case homebrewAbsenceAuthority:
			kindPredicate = " AND si.identity_kind IN " + homebrewIdentityKindsSQL
		default:
			continue
		}
		query := `
			UPDATE software_installations si
			SET removed_at = $3, updated_at = now()
			WHERE si.tenant_id = $1::uuid
			  AND si.device_id = $2::uuid
			  AND si.platform = $4
			  AND si.removed_at IS NULL
			  AND si.last_seen_at < $3` + kindPredicate + `
			  AND NOT EXISTS (
				SELECT 1 FROM software_observations so
				WHERE so.inventory_run_id = $5::uuid
				  AND so.identity_fingerprint = si.identity_fingerprint
			  )
		`
		if _, err := tx.Exec(ctx, query, args...); err != nil {
			return written, fmt.Errorf("close missing software installations for %s: %w", scope, err)
		}
	}

	if err := closeToolingInstallations(ctx, tx, row, deviceID, runID, platform, toolingAuth); err != nil {
		return written, err
	}

	if err := linkHomebrewCasksToApps(ctx, tx, row, deviceID, hb); err != nil {
		return written, err
	}
	// Before the state upsert: it reads the authority this report found.
	if err := upsertHomebrewCurrentEntries(ctx, tx, row, deviceID, runID, hb); err != nil {
		return written, err
	}
	if err := upsertHomebrewDeviceState(ctx, tx, row, deviceID, runID, hb); err != nil {
		return written, err
	}
	// Before the state upsert: it reads the unit authority this report found.
	if err := upsertToolingCurrentEntries(ctx, tx, row, deviceID, runID, toolingEntries, toolingIDs, toolingAuth); err != nil {
		return written, err
	}
	if err := upsertToolingDeviceState(ctx, tx, row, deviceID, runID, p, toolingAuth); err != nil {
		return written, err
	}

	return written, nil
}

// observationRecord is one observed item as it lands in
// software_observations and software_installations. Applications and
// Homebrew packages both go through recordSoftwareObservation, so the
// evidence, resolution and installation rules cannot drift between them.
type observationRecord struct {
	Identity       observedSoftwareIdentity
	Version        string
	Identifier     string
	IdentifierKind string
	Publisher      string
	Signer         string
	TeamID         string
	Path           string
	Architecture   string
	SHA256         any
	Notarized      *bool
	// SigningStatus and NotarizationStatus are PAT-2112's macOS evidence,
	// nil when not reported.
	SigningStatus      *string
	NotarizationStatus *string
	// Authenticode is PAT-2113/PAT-2116's Windows evidence, each member nil
	// when not reported.
	Authenticode     windowsAuthenticode
	CurrentName      string
	CurrentPublisher string
}

// macOSSigningStatus returns a macOS app's reported signing_status when it is
// one the platform knows, and nil otherwise: not reported, another platform,
// or a value outside the enum. An unknown value is dropped rather than
// refusing the whole inventory, and nil is never read as unsigned.
//
// untrusted and invalid are PAT-2117: the signature validates but its chain
// does not anchor to Apple (untrusted), or the signature does not validate
// against the code at all (invalid, tampered or broken after signing).
func macOSSigningStatus(platform, value string) *string {
	if platform != "macos" {
		return nil
	}
	switch v := strings.TrimSpace(value); v {
	case "signed", "adhoc", "unsigned", "error", "untrusted", "invalid":
		return &v
	}
	return nil
}

// windowsAuthenticode is one Windows app's normalised Authenticode evidence
// (PAT-2113, PAT-2116). Each member is nil when not reported or not
// acceptable; nil is never read as unsigned or trusted.
type windowsAuthenticode struct {
	State                *string
	Signer               *string
	SignerThumbprint     *string
	Issuer               *string
	RootThumbprint       *string
	RootKind             *string
	ExecutableResolution *string
}

// windowsSignatureEvidence normalises a Windows app's installation_evidence.
// signature_state is kept when it is one the agent defines (valid, invalid,
// unsigned, unknown). Beside valid only, it keeps the signer and issuer when
// each is 1 to 512 characters of valid UTF-8 with no control characters (the
// agent's own bound), the signer and root thumbprints when each is a SHA-256
// hex digest (lower-cased), and root_kind when it is microsoft, public or
// enterprise. executable_resolution is kept, whatever the state, when it is a
// short lower-case code. Anything else is nil (a tolerant reader: a value
// outside the enum never refuses the report), as is every member on another
// platform. The registry Publisher is never used.
func windowsSignatureEvidence(platform string, ev *appInstallationEvidencePart) windowsAuthenticode {
	var out windowsAuthenticode
	if platform != "windows" || ev == nil {
		return out
	}
	if r := strings.TrimSpace(ev.ExecutableResolution); executableResolutionPattern.MatchString(r) {
		out.ExecutableResolution = &r
	}
	state := strings.TrimSpace(ev.SignatureState)
	switch state {
	case "valid", "invalid", "unsigned", "unknown":
	default:
		return out
	}
	out.State = &state
	if state != "valid" {
		return out
	}
	out.Signer = boundedAuthenticodeName(ev.Signer)
	out.Issuer = boundedAuthenticodeName(ev.Issuer)
	out.SignerThumbprint = sha256Thumbprint(ev.SignerThumbprint)
	out.RootThumbprint = sha256Thumbprint(ev.RootThumbprint)
	switch kind := strings.TrimSpace(ev.RootKind); kind {
	case "microsoft", "public", "enterprise":
		out.RootKind = &kind
	}
	return out
}

var (
	sha256HexPattern            = regexp.MustCompile(`^[0-9a-f]{64}$`)
	executableResolutionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// boundedAuthenticodeName is a certificate DN the agent reports: 1 to 512
// characters of valid UTF-8 with no control characters, or nil.
func boundedAuthenticodeName(v string) *string {
	s := strings.TrimSpace(v)
	if n := utf8.RuneCountInString(s); n == 0 || n > 512 || !utf8.ValidString(s) ||
		strings.IndexFunc(s, unicode.IsControl) >= 0 {
		return nil
	}
	return &s
}

// sha256Thumbprint is a SHA-256 certificate thumbprint in lower-case hex, or
// nil.
func sha256Thumbprint(v string) *string {
	s := strings.ToLower(strings.TrimSpace(v))
	if !sha256HexPattern.MatchString(s) {
		return nil
	}
	return &s
}

// macOSNotarizationStatus is macOSSigningStatus for notarization_status.
func macOSNotarizationStatus(platform, value string) *string {
	if platform != "macos" {
		return nil
	}
	switch v := strings.TrimSpace(value); v {
	case "notarized", "not_notarized", "unknown":
		return &v
	}
	return nil
}

// recordSoftwareObservation inserts one immutable observation (idempotent on
// the run ordinal), records its resolution separately, and creates or
// refreshes the device installation episode. It returns the observation id.
func recordSoftwareObservation(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID, runID string, ordinal int, platform string, rec observationRecord) (int64, error) {
	identity := rec.Identity
	var observationID int64
	err := tx.QueryRow(ctx, `
		INSERT INTO software_observations (
			inventory_run_id, tenant_id, device_id, ordinal, platform,
			observed_name, observed_version, observed_identifier, observed_identifier_kind,
			observed_publisher, observed_signer, observed_team_id, observed_path,
			observed_architecture, observed_sha256, observed_notarized,
			identity_kind, identity_value_normalized, companion_value_normalized,
			identity_confidence, identity_fingerprint, observed_at,
			observed_signing_status, observed_notarization_status,
			observed_signature_state, observed_authenticode_signer,
			observed_authenticode_signer_thumbprint, observed_authenticode_issuer,
			observed_authenticode_root_thumbprint, observed_authenticode_root_kind,
			observed_executable_resolution
		) VALUES (
			$1::uuid, $2::uuid, $3::uuid, $4, $5,
			$6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
			$17, $18, $19, $20, $21, $22, $23, $24, $25, $26,
			$27, $28, $29, $30, $31
		)
		ON CONFLICT (inventory_run_id, ordinal) DO NOTHING
		RETURNING id
	`, runID, row.TenantID, deviceID, ordinal, platform,
		identity.ObservedName, nullIfEmpty(rec.Version), nullIfEmpty(rec.Identifier),
		nullIfEmpty(rec.IdentifierKind), nullIfEmpty(rec.Publisher), nullIfEmpty(rec.Signer),
		nullIfEmpty(rec.TeamID), nullIfEmpty(rec.Path), nullIfEmpty(rec.Architecture),
		rec.SHA256, rec.Notarized,
		identity.Kind, identity.Value, identity.Companion, identity.Confidence,
		identity.Fingerprint, row.ReceivedAt,
		rec.SigningStatus, rec.NotarizationStatus,
		rec.Authenticode.State, rec.Authenticode.Signer,
		rec.Authenticode.SignerThumbprint, rec.Authenticode.Issuer,
		rec.Authenticode.RootThumbprint, rec.Authenticode.RootKind,
		rec.Authenticode.ExecutableResolution,
	).Scan(&observationID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("insert software observation %d: %w", ordinal, err)
		}
		var existingFingerprint string
		if err := tx.QueryRow(ctx, `
			SELECT id, identity_fingerprint
			FROM software_observations
			WHERE inventory_run_id = $1::uuid AND ordinal = $2
		`, runID, ordinal).Scan(&observationID, &existingFingerprint); err != nil {
			return 0, fmt.Errorf("load existing software observation %d: %w", ordinal, err)
		}
		if existingFingerprint != identity.Fingerprint {
			return 0, fmt.Errorf("software observation %d changed during re-extraction", ordinal)
		}
	}

	resolution, err := findSoftwareResolution(ctx, tx, identity, platform)
	if err != nil {
		return 0, err
	}
	if resolution.ProductID == "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO software_observation_resolutions (
				observation_id, tenant_id, resolution_state, resolution_method
			) VALUES ($1, $2::uuid, 'unresolved', 'none')
			ON CONFLICT (observation_id) DO NOTHING
		`, observationID, row.TenantID); err != nil {
			return 0, fmt.Errorf("record unresolved software observation: %w", err)
		}
	} else {
		if _, err := tx.Exec(ctx, `
			INSERT INTO software_observation_resolutions (
				observation_id, tenant_id, product_id, alias_id,
				resolution_state, resolution_confidence, resolution_method, resolved_at
			) VALUES ($1, $2::uuid, $3::uuid, $4::uuid,
			          'resolved', $5, 'curated_alias', now())
			ON CONFLICT (observation_id) DO UPDATE SET
				product_id = EXCLUDED.product_id,
				alias_id = EXCLUDED.alias_id,
				resolution_state = EXCLUDED.resolution_state,
				resolution_confidence = EXCLUDED.resolution_confidence,
				resolution_method = EXCLUDED.resolution_method,
				resolved_at = EXCLUDED.resolved_at,
				updated_at = now()
		`, observationID, row.TenantID, resolution.ProductID, resolution.AliasID,
			resolution.Confidence); err != nil {
			return 0, fmt.Errorf("record resolved software observation: %w", err)
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO software_installations (
			tenant_id, device_id, product_id, alias_id, platform,
			identity_kind, identity_value_normalized, companion_value_normalized,
			identity_fingerprint, current_name, current_version, current_publisher,
			current_path, current_architecture, resolution_confidence,
			first_seen_at, last_seen_at, latest_observation_id, provenance
		) VALUES (
			$1::uuid, $2::uuid, $3::uuid, $4::uuid, $5,
			$6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
			$16, $16, $17, 'inventory_payload'
		)
		ON CONFLICT (device_id, identity_fingerprint) DO UPDATE SET
			product_id = COALESCE(EXCLUDED.product_id, software_installations.product_id),
			alias_id = COALESCE(EXCLUDED.alias_id, software_installations.alias_id),
			resolution_confidence = COALESCE(EXCLUDED.resolution_confidence, software_installations.resolution_confidence),
			first_seen_at = LEAST(EXCLUDED.first_seen_at, software_installations.first_seen_at),
			current_name = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.current_name ELSE software_installations.current_name END,
			current_version = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.current_version ELSE software_installations.current_version END,
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
	`, row.TenantID, deviceID, nullIfEmpty(resolution.ProductID), nullIfEmpty(resolution.AliasID), platform,
		identity.Kind, identity.Value, identity.Companion, identity.Fingerprint,
		rec.CurrentName, nullIfEmpty(rec.Version),
		nullIfEmpty(rec.CurrentPublisher), nullIfEmpty(rec.Path),
		nullIfEmpty(rec.Architecture), nullIfEmpty(resolution.Confidence), row.ReceivedAt, observationID); err != nil {
		return 0, fmt.Errorf("upsert software installation %s: %w", identity.Fingerprint, err)
	}
	return observationID, nil
}
