package extractor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/categorytag"
)

// PAT-2021: IDE extensions, npm and pip packages, local models and runtimes,
// and MCP servers on the PAT-1461 software observation seam, following the
// Homebrew design (PAT-2013/PAT-2032):
//
//   - every item is an ordinary software_observations row in the payload's
//     inventory run, with an ordinary software_installations row, so it
//     takes part in category tagging (PAT-2015) like any other software;
//   - the whole ingest is a fixed number of set-based statements, whatever
//     the size of the blocks;
//   - a per-device, per-block row lock on tooling_device_state serialises
//     ingest, so an older partial report can never race a newer complete one;
//   - partial only adds or refreshes; only an authoritative unit prunes
//     current entries or closes installations;
//   - current entries are keyed per item per user, so a partial report can
//     never hide an item it did not read.
//
// Identity: these are namespace identifiers (a marketplace id, a registry
// package name, a model name, an MCP server key), not normalised products
// (AGENTS.md "identity is not packaging"). software_product_aliases admits
// none of these kinds, so every observation is unresolved.

// Blocks.
const (
	toolingBlockIDE      = "ide_extensions"
	toolingBlockPackages = "package_managers"
	toolingBlockModels   = "local_models"
	toolingBlockMCP      = "mcp_servers"
)

// Identity kinds. The PAT-2015 matcher reads these (categorytag.ObservationKindFor).
const (
	kindIDEExtension             = "ide_extension"
	kindIDEExtensionUnidentified = "ide_extension_unidentified"
	kindNPMPackage               = "npm_package"
	kindNPMPackageUnidentified   = "npm_package_unidentified"
	kindPipPackage               = "pip_package"
	kindPipPackageUnidentified   = "pip_package_unidentified"
	kindLocalModel               = "local_model"
	kindLocalModelUnidentified   = "local_model_unidentified"
	kindLocalModelRuntime        = "local_model_runtime"
	kindMCPServer                = "mcp_server"
	kindMCPServerUnnamed         = "mcp_server_unnamed"
)

// toolingIdentityKindsSQL is the SQL list of every tooling identity kind, for
// scope predicates. Constant text, never built from input.
const toolingIdentityKindsSQL = "('ide_extension','ide_extension_unidentified'," +
	"'npm_package','npm_package_unidentified','pip_package','pip_package_unidentified'," +
	"'local_model','local_model_unidentified','local_model_runtime'," +
	"'mcp_server','mcp_server_unnamed')"

// ideMarketplace is the extension id namespace an editor installs from. It
// is the PAT-2015 ide_extension rule qualifier. VS Code and VS Code Insiders
// use the Visual Studio Marketplace; Cursor and Windsurf use Open VSX;
// JetBrains IDEs use the JetBrains Marketplace. The validator's family and
// editor enums make any other editor unreachable; if one ever arrived it
// gets ideMarketplaceUnknown, which no rule qualifier can equal, never "".
const ideMarketplaceUnknown = "unknown_marketplace"

func ideMarketplace(family, editor string) string {
	if family == "jetbrains" {
		return categorytag.MarketplaceJetBrains
	}
	switch editor {
	case "vscode", "vscode_insiders":
		return categorytag.MarketplaceVSCode
	case "cursor", "windsurf":
		return categorytag.MarketplaceOpenVSX
	}
	return ideMarketplaceUnknown
}

var localRuntimeNames = map[string]string{"ollama": "Ollama", "lm_studio": "LM Studio", "llama_cpp": "llama.cpp"}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return strings.TrimSpace(*s)
}

func userKey(user, userID *string) string {
	if id := deref(userID); id != "" {
		return "id:" + id
	}
	return "name:" + deref(user)
}

// toolingEntry is one reported item as it is stored.
type toolingEntry struct {
	Block, Unit, EntryKind, EntryKey string
	Identity                         observedSoftwareIdentity
	Version, Identifier              *string
	IdentifierKind                   string
	Publisher, Path                  *string
	User, UserID                     *string
	Attributes                       string
}

func toolingIdentity(platform, kind, value, companion, observedName, confidence string) observedSoftwareIdentity {
	id := observedSoftwareIdentity{
		Kind: kind, Value: value, Companion: companion,
		ObservedName: observedName, Confidence: confidence,
	}
	id.Fingerprint = identityFingerprint(platform, kind, value, companion)
	return id
}

// entryKeyer derives stable per-item keys. Two items with the same natural
// key in one report (two project-scoped MCP servers of one name, say) are
// told apart by their occurrence, which is stable because both agents sort
// their lists.
type entryKeyer map[string]int

func (k entryKeyer) key(block string, parts ...string) string {
	base := block + "\x1f" + strings.Join(parts, "\x1f")
	n := k[base]
	k[base] = n + 1
	sum := sha256.Sum256([]byte(base + "\x1f#" + strconv.Itoa(n)))
	return hex.EncodeToString(sum[:])
}

func toolingWritesEvidence(status string) bool { return status == "complete" || status == "partial" }

// toolingBlocksPresent lists the blocks this payload carries in the one
// canonical block order, which is also alphabetical: the placeholder INSERT
// and the SELECT ... ORDER BY block FOR UPDATE in lockToolingDeviceState
// therefore take row locks in the same order in every transaction, so two
// concurrent extractions for one device cannot deadlock. Every other tooling
// list (authorities, state rows, entries) follows the same order.
func toolingBlocksPresent(p *payload) (blocks, statuses []string) {
	add := func(block, status string) {
		blocks, statuses = append(blocks, block), append(statuses, status)
	}
	if p.IdeExtensions != nil {
		add(toolingBlockIDE, p.IdeExtensions.CollectionStatus)
	}
	if p.LocalModels != nil {
		add(toolingBlockModels, p.LocalModels.CollectionStatus)
	}
	if p.McpServers != nil {
		add(toolingBlockMCP, p.McpServers.CollectionStatus)
	}
	if p.PackageManagers != nil {
		add(toolingBlockPackages, p.PackageManagers.CollectionStatus)
	}
	return blocks, statuses
}

// toolingAuthority is one unit this report is authoritative for.
type toolingAuthority struct {
	Block, Unit string
}

// unitAuthority applies the unit rule: the block is not failed and not
// truncated, and the unit's own status is complete or not_present. A
// truncated block may have skipped users (the user bound does not mark a
// unit truncated), so it grants nothing.
func unitAuthority(block, status string, truncated bool, units map[string]string, order []string) []toolingAuthority {
	if status == "failed" || truncated {
		return nil
	}
	var out []toolingAuthority
	for _, unit := range order {
		if st := units[unit]; st == "complete" || st == "not_present" {
			out = append(out, toolingAuthority{block, unit})
		}
	}
	return out
}

func unitStatuses[T any](m map[string]T, status func(T) string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = status(v)
	}
	return out
}

// toolingAuthorities returns every unit the payload is authoritative for.
func toolingAuthorities(p *payload) []toolingAuthority {
	var out []toolingAuthority
	if b := p.IdeExtensions; b != nil && (b.CollectionStatus == "complete" || b.CollectionStatus == "not_present") {
		out = append(out, toolingAuthority{toolingBlockIDE, ""})
	}
	if b := p.LocalModels; b != nil {
		out = append(out, unitAuthority(toolingBlockModels, b.CollectionStatus, b.Truncated,
			unitStatuses(b.Runtimes, func(s localRuntimeSummary) string { return s.CollectionStatus }), localModelRuntimes)...)
	}
	if b := p.McpServers; b != nil {
		out = append(out, unitAuthority(toolingBlockMCP, b.CollectionStatus, b.Truncated,
			unitStatuses(b.Clients, func(s mcpClientPart) string { return s.CollectionStatus }), mcpClients)...)
	}
	if b := p.PackageManagers; b != nil {
		out = append(out, unitAuthority(toolingBlockPackages, b.CollectionStatus, b.Truncated,
			unitStatuses(b.Sources, func(s packageSourcePart) string { return s.CollectionStatus }), packageSources)...)
	}
	return out
}

// toolingScope is the software_inventory_runs.authoritative_scopes name.
func toolingScope(a toolingAuthority) string {
	switch a.Block {
	case toolingBlockIDE:
		return "ide_extensions"
	case toolingBlockPackages:
		return "packages:" + a.Unit
	}
	return a.Block + ":" + a.Unit
}

// toolingClosures turns authorities into (identity kind, companion) pairs
// whose installations this report may close; companion "*" means any.
// pip_package is fed by two sources (pip_user and pipx), so it closes only
// when both are authoritative: otherwise a package seen only through the
// unread source would be closed.
func toolingClosures(auth []toolingAuthority) (kinds, companions []string) {
	add := func(companion string, ks ...string) {
		for _, k := range ks {
			kinds, companions = append(kinds, k), append(companions, companion)
		}
	}
	have := map[toolingAuthority]bool{}
	for _, a := range auth {
		have[a] = true
	}
	for _, a := range auth {
		switch a.Block {
		case toolingBlockIDE:
			add("*", kindIDEExtension, kindIDEExtensionUnidentified)
		case toolingBlockPackages:
			if a.Unit == "npm_global" {
				add("*", kindNPMPackage, kindNPMPackageUnidentified)
			}
			if a.Unit == "pip_user" && have[toolingAuthority{toolingBlockPackages, "pipx"}] {
				add("*", kindPipPackage, kindPipPackageUnidentified)
			}
		case toolingBlockModels:
			add(a.Unit, kindLocalModel, kindLocalModelUnidentified, kindLocalModelRuntime)
		case toolingBlockMCP:
			add(a.Unit, kindMCPServer, kindMCPServerUnnamed)
		}
	}
	return kinds, companions
}

func marshalAttributes(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// buildToolingEntries turns every block that carries evidence (complete or
// partial) into stored entries, in a fixed block order and payload order.
func buildToolingEntries(p *payload, platform string) ([]toolingEntry, error) {
	var out []toolingEntry
	keys := entryKeyer{}

	if b := p.IdeExtensions; b != nil && toolingWritesEvidence(b.CollectionStatus) {
		for _, e := range b.Extensions {
			id := deref(e.ID)
			market := ideMarketplace(e.Family, e.Editor)
			var identity observedSoftwareIdentity
			keyPart := "id:" + normalizedIdentityValue(id)
			if id != "" {
				identity = toolingIdentity(platform, kindIDEExtension, normalizedIdentityValue(id), market,
					firstIdentityValue(deref(e.Name), id), "medium")
			} else {
				dir := firstIdentityValue(deref(e.Directory), "unknown")
				keyPart = "dir:" + dir
				identity = toolingIdentity(platform, kindIDEExtensionUnidentified, normalizedIdentityValue(dir), market,
					firstIdentityValue(deref(e.Name), deref(e.Directory), "unknown extension"), "low")
			}
			attrs, err := marshalAttributes(e)
			if err != nil {
				return nil, fmt.Errorf("marshal ide extension: %w", err)
			}
			user := e.User
			out = append(out, toolingEntry{
				Block: toolingBlockIDE, Unit: "", EntryKind: "extension",
				EntryKey: keys.key(toolingBlockIDE, userKey(&user, e.UserID), e.Family, e.Editor, deref(e.EditorVersion), keyPart),
				Identity: identity, Version: e.Version, Identifier: e.ID, IdentifierKind: e.Editor,
				Publisher: e.Publisher, Path: e.Directory, User: &user, UserID: e.UserID, Attributes: attrs,
			})
		}
	}

	if b := p.LocalModels; b != nil && toolingWritesEvidence(b.CollectionStatus) {
		for _, in := range b.Installations {
			name := firstIdentityValue(localRuntimeNames[in.Runtime], in.Runtime)
			attrs, err := marshalAttributes(in)
			if err != nil {
				return nil, fmt.Errorf("marshal runtime installation: %w", err)
			}
			path := in.Path
			out = append(out, toolingEntry{
				Block: toolingBlockModels, Unit: in.Runtime, EntryKind: "runtime_installation",
				EntryKey: keys.key(toolingBlockModels, "install", in.Runtime, in.Scope, userKey(in.User, in.UserID), in.Path),
				Identity: toolingIdentity(platform, kindLocalModelRuntime, in.Runtime, in.Runtime, name, "medium"),
				Version:  in.Version, Identifier: in.Identifier, IdentifierKind: in.Kind, Path: &path,
				User: in.User, UserID: in.UserID, Attributes: attrs,
			})
		}
		for _, md := range b.Models {
			name, tag := deref(md.Name), deref(md.Tag)
			display := name
			if tag != "" {
				display = firstIdentityValue(name, "unknown model") + ":" + tag
			}
			var identity observedSoftwareIdentity
			if name != "" {
				value := normalizedIdentityValue(name)
				if tag != "" {
					value += ":" + normalizedIdentityValue(tag)
				}
				identity = toolingIdentity(platform, kindLocalModel, value, md.Runtime, display, "medium")
			} else {
				identity = toolingIdentity(platform, kindLocalModelUnidentified,
					normalizedIdentityValue(firstIdentityValue(tag, "unknown")), md.Runtime,
					firstIdentityValue(display, "unknown model"), "low")
			}
			attrs, err := marshalAttributes(md)
			if err != nil {
				return nil, fmt.Errorf("marshal local model: %w", err)
			}
			storePath := md.StorePath
			out = append(out, toolingEntry{
				Block: toolingBlockModels, Unit: md.Runtime, EntryKind: "model",
				EntryKey: keys.key(toolingBlockModels, "model", md.Runtime, userKey(md.User, md.UserID), md.StorePath, name, tag),
				Identity: identity, Identifier: md.Name, IdentifierKind: md.Runtime, Path: &storePath,
				User: md.User, UserID: md.UserID, Attributes: attrs,
			})
		}
	}

	if b := p.McpServers; b != nil && toolingWritesEvidence(b.CollectionStatus) {
		for _, s := range b.Servers {
			name := deref(s.Name)
			var identity observedSoftwareIdentity
			keyPart := "name:" + name
			if name != "" {
				identity = toolingIdentity(platform, kindMCPServer, normalizedIdentityValue(name), s.Client, name, "medium")
			} else {
				fallback := firstIdentityValue(deref(s.Package), deref(s.Host), deref(s.Executable), "unnamed")
				keyPart = "unnamed:" + fallback
				identity = toolingIdentity(platform, kindMCPServerUnnamed, normalizedIdentityValue(fallback), s.Client,
					"unnamed MCP server", "low")
			}
			// The typed struct is the PAT-2020 allowlist: nothing else can
			// be marshalled into storage.
			attrs, err := marshalAttributes(s)
			if err != nil {
				return nil, fmt.Errorf("marshal mcp server: %w", err)
			}
			configPath := s.ConfigPath
			out = append(out, toolingEntry{
				Block: toolingBlockMCP, Unit: s.Client, EntryKind: "server",
				EntryKey: keys.key(toolingBlockMCP, s.Client, userKey(s.User, s.UserID), s.ConfigPath, s.Scope, keyPart),
				Identity: identity, Identifier: s.Name, IdentifierKind: s.Client, Path: &configPath,
				User: s.User, UserID: s.UserID, Attributes: attrs,
			})
		}
	}

	if b := p.PackageManagers; b != nil && toolingWritesEvidence(b.CollectionStatus) {
		for _, pk := range b.Packages {
			kind, unidentified, src := kindNPMPackage, kindNPMPackageUnidentified, categorytag.SourceNPM
			if pk.Source != "npm_global" {
				kind, unidentified, src = kindPipPackage, kindPipPackageUnidentified, categorytag.SourcePip
			}
			name := deref(pk.Name)
			var identity observedSoftwareIdentity
			keyPart := "name:" + name
			if name != "" {
				identity = toolingIdentity(platform, kind, categorytag.NormalizePackageName(src, name), "", name, "medium")
			} else {
				dir := firstIdentityValue(deref(pk.Directory), "unknown")
				keyPart = "dir:" + dir
				identity = toolingIdentity(platform, unidentified, normalizedIdentityValue(dir), "",
					firstIdentityValue(deref(pk.Directory), "unknown package"), "low")
			}
			attrs, err := marshalAttributes(pk)
			if err != nil {
				return nil, fmt.Errorf("marshal package: %w", err)
			}
			out = append(out, toolingEntry{
				Block: toolingBlockPackages, Unit: pk.Source, EntryKind: "package",
				EntryKey: keys.key(toolingBlockPackages, pk.Source, pk.Scope, userKey(pk.User, pk.UserID),
					deref(pk.Prefix), deref(pk.PipxApp), keyPart),
				Identity: identity, Version: pk.Version, Identifier: pk.Name, IdentifierKind: pk.Source,
				Path: pk.Prefix, User: pk.User, UserID: pk.UserID, Attributes: attrs,
			})
		}
	}
	return out, nil
}

// lockToolingDeviceState takes the per-device lock for every block the
// payload carries, in a fixed order, for the rest of the ingest transaction
// (the PAT-2032 review rule). Missing rows are created first as placeholders
// that sort before any real report. Two statements.
func lockToolingDeviceState(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID string, p *payload) error {
	blocks, statuses := toolingBlocksPresent(p)
	if len(blocks) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tooling_device_state (device_id, tenant_id, block, collection_status, reported_at)
		SELECT $1::uuid, $2::uuid, u.block, u.status, '-infinity'::timestamptz
		FROM unnest($3::text[], $4::text[]) AS u(block, status)
		ON CONFLICT (device_id, block) DO NOTHING
	`, deviceID, row.TenantID, blocks, statuses); err != nil {
		return fmt.Errorf("create tooling device state: %w", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT block FROM tooling_device_state
		WHERE device_id = $1::uuid AND tenant_id = $2::uuid AND block = ANY($3::text[])
		ORDER BY block
		FOR UPDATE
	`, deviceID, row.TenantID, blocks)
	if err != nil {
		return fmt.Errorf("lock tooling device state: %w", err)
	}
	n := 0
	for rows.Next() {
		n++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("lock tooling device state: %w", err)
	}
	if n != len(blocks) {
		return fmt.Errorf("lock tooling device state: locked %d of %d blocks", n, len(blocks))
	}
	return nil
}

// recordToolingObservations writes every item of every tooling block that
// carries evidence, starting at ordinal ordinalBase. Five set-based
// statements whatever the block sizes (observations, their ids,
// resolutions, installations, details), the PAT-2032 shape. It returns the
// entries with their observation ids.
func recordToolingObservations(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID, runID, platform string, ordinalBase int, entries []toolingEntry) ([]int64, error) {
	n := len(entries)
	if n == 0 {
		return nil, nil
	}
	ordinals := make([]int32, n)
	names := make([]string, n)
	versions := make([]*string, n)
	identifiers := make([]*string, n)
	identifierKinds := make([]string, n)
	publishers := make([]*string, n)
	paths := make([]*string, n)
	kinds := make([]string, n)
	values := make([]string, n)
	companions := make([]string, n)
	confidences := make([]string, n)
	fingerprints := make([]string, n)
	for i, e := range entries {
		ordinals[i] = int32(ordinalBase + i)
		names[i] = firstIdentityValue(e.Identity.ObservedName, "unknown software")
		versions[i] = nilIfEmptyPtr(e.Version)
		identifiers[i] = nilIfEmptyPtr(e.Identifier)
		identifierKinds[i] = e.IdentifierKind
		publishers[i] = nilIfEmptyPtr(e.Publisher)
		paths[i] = nilIfEmptyPtr(e.Path)
		kinds[i], values[i], companions[i] = e.Identity.Kind, e.Identity.Value, e.Identity.Companion
		confidences[i], fingerprints[i] = e.Identity.Confidence, e.Identity.Fingerprint
	}

	// 1. Immutable observations, idempotent on the run ordinal.
	if _, err := tx.Exec(ctx, `
		INSERT INTO software_observations (
			inventory_run_id, tenant_id, device_id, ordinal, platform,
			observed_name, observed_version, observed_identifier, observed_identifier_kind,
			observed_publisher, observed_path,
			identity_kind, identity_value_normalized, companion_value_normalized,
			identity_confidence, identity_fingerprint, observed_at
		)
		SELECT $1::uuid, $2::uuid, $3::uuid, u.ordinal, $4,
		       u.observed_name, u.observed_version, u.identifier, NULLIF(u.identifier_kind, ''),
		       u.publisher, u.path,
		       u.kind, u.value, u.companion, u.confidence, u.fingerprint, $5
		FROM unnest($6::int4[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[],
		            $13::text[], $14::text[], $15::text[], $16::text[], $17::text[])
		     AS u(ordinal, observed_name, observed_version, identifier, identifier_kind, publisher, path,
		          kind, value, companion, confidence, fingerprint)
		ON CONFLICT (inventory_run_id, ordinal) DO NOTHING
	`, runID, row.TenantID, deviceID, platform, row.ReceivedAt,
		ordinals, names, versions, identifiers, identifierKinds, publishers, paths,
		kinds, values, companions, confidences, fingerprints); err != nil {
		return nil, fmt.Errorf("insert tooling observations: %w", err)
	}

	// 2. Their ids. A replay must reproduce the same identity per ordinal.
	rows, err := tx.Query(ctx, `
		SELECT ordinal, id, identity_fingerprint
		FROM software_observations
		WHERE inventory_run_id = $1::uuid AND ordinal >= $2 AND ordinal < $3
	`, runID, ordinalBase, ordinalBase+n)
	if err != nil {
		return nil, fmt.Errorf("load tooling observations: %w", err)
	}
	ids := make([]int64, n)
	found := make([]bool, n)
	for rows.Next() {
		var ordinal int
		var id int64
		var fingerprint string
		if err := rows.Scan(&ordinal, &id, &fingerprint); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan tooling observation: %w", err)
		}
		i := ordinal - ordinalBase
		if fingerprint != entries[i].Identity.Fingerprint {
			rows.Close()
			return nil, fmt.Errorf("software observation %d changed during re-extraction", ordinal)
		}
		ids[i], found[i] = id, true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("load tooling observations: %w", err)
	}
	for i, ok := range found {
		if !ok {
			return nil, fmt.Errorf("load existing software observation %d: missing", ordinalBase+i)
		}
	}

	// 3. Resolutions: always unresolved (no alias kind admits these).
	if _, err := tx.Exec(ctx, `
		INSERT INTO software_observation_resolutions (observation_id, tenant_id, resolution_state, resolution_method)
		SELECT u.id, $2::uuid, 'unresolved', 'none' FROM unnest($1::int8[]) AS u(id)
		ON CONFLICT (observation_id) DO NOTHING
	`, ids, row.TenantID); err != nil {
		return nil, fmt.Errorf("record unresolved tooling observations: %w", err)
	}

	// 4. Installations, one per identity. Items sharing an identity (one
	// extension in two users' profiles) fold to the last one reported, since
	// ON CONFLICT cannot touch a row twice in one statement.
	last := map[string]int{}
	var order []string
	for i, e := range entries {
		if _, seen := last[e.Identity.Fingerprint]; !seen {
			order = append(order, e.Identity.Fingerprint)
		}
		last[e.Identity.Fingerprint] = i
	}
	m := len(order)
	iKinds, iValues, iCompanions, iFingerprints, iNames := make([]string, m), make([]string, m), make([]string, m), make([]string, m), make([]string, m)
	iVersions, iPublishers, iPaths := make([]*string, m), make([]*string, m), make([]*string, m)
	iObservations := make([]int64, m)
	for k, fp := range order {
		i := last[fp]
		e := entries[i]
		iKinds[k], iValues[k], iCompanions[k], iFingerprints[k] = e.Identity.Kind, e.Identity.Value, e.Identity.Companion, fp
		iNames[k], iVersions[k], iPublishers[k], iPaths[k] = names[i], versions[i], publishers[i], paths[i]
		iObservations[k] = ids[i]
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO software_installations (
			tenant_id, device_id, product_id, alias_id, platform,
			identity_kind, identity_value_normalized, companion_value_normalized,
			identity_fingerprint, current_name, current_version, current_publisher,
			current_path, current_architecture, resolution_confidence,
			first_seen_at, last_seen_at, latest_observation_id, provenance
		)
		SELECT $1::uuid, $2::uuid, NULL, NULL, $3,
		       u.kind, u.value, u.companion, u.fingerprint, u.name, u.version, u.publisher,
		       u.path, NULL, NULL,
		       $4, $4, u.observation_id, 'inventory_payload'
		FROM unnest($5::text[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[], $13::int8[])
		     AS u(kind, value, companion, fingerprint, name, version, publisher, path, observation_id)
		ON CONFLICT (device_id, identity_fingerprint) DO UPDATE SET
			first_seen_at = LEAST(EXCLUDED.first_seen_at, software_installations.first_seen_at),
			current_name = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.current_name ELSE software_installations.current_name END,
			current_version = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.current_version ELSE software_installations.current_version END,
			current_publisher = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.current_publisher ELSE software_installations.current_publisher END,
			current_path = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.current_path ELSE software_installations.current_path END,
			latest_observation_id = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.latest_observation_id ELSE software_installations.latest_observation_id END,
			provenance = CASE WHEN EXCLUDED.last_seen_at >= software_installations.last_seen_at THEN EXCLUDED.provenance ELSE software_installations.provenance END,
			last_seen_at = GREATEST(EXCLUDED.last_seen_at, software_installations.last_seen_at),
			removed_at = CASE
				WHEN software_installations.removed_at IS NULL THEN NULL
				WHEN EXCLUDED.last_seen_at >= software_installations.removed_at THEN NULL
				ELSE software_installations.removed_at
			END,
			updated_at = now()
		WHERE software_installations.tenant_id = EXCLUDED.tenant_id
	`, row.TenantID, deviceID, platform, row.ReceivedAt,
		iKinds, iValues, iCompanions, iFingerprints, iNames, iVersions, iPublishers, iPaths, iObservations); err != nil {
		return nil, fmt.Errorf("upsert tooling installations: %w", err)
	}

	// 5. The reported item, immutable like the observation it extends.
	blocks, units, entryKinds, entryKeys := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	users, userIDs := make([]*string, n), make([]*string, n)
	attrs := make([]string, n)
	for i, e := range entries {
		blocks[i], units[i], entryKinds[i], entryKeys[i] = e.Block, e.Unit, e.EntryKind, e.EntryKey
		users[i], userIDs[i], attrs[i] = nilIfEmptyPtr(e.User), nilIfEmptyPtr(e.UserID), e.Attributes
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tooling_observation_details (
			observation_id, tenant_id, device_id, inventory_run_id, block, unit,
			entry_kind, entry_key, user_name, user_id, attributes, observed_at
		)
		SELECT u.observation_id, $1::uuid, $2::uuid, $3::uuid, u.block, u.unit,
		       u.entry_kind, u.entry_key, u.user_name, u.user_id, u.attributes::jsonb, $4
		FROM unnest($5::int8[], $6::text[], $7::text[], $8::text[], $9::text[], $10::text[], $11::text[], $12::text[])
		     AS u(observation_id, block, unit, entry_kind, entry_key, user_name, user_id, attributes)
		ON CONFLICT (observation_id) DO NOTHING
	`, row.TenantID, deviceID, runID, row.ReceivedAt,
		ids, blocks, units, entryKinds, entryKeys, users, userIDs, attrs); err != nil {
		return nil, fmt.Errorf("insert tooling details: %w", err)
	}
	return ids, nil
}

// closeToolingInstallations closes, in one statement, every active
// installation of the authorised kinds this report did not list.
func closeToolingInstallations(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID, runID, platform string, auth []toolingAuthority) error {
	kinds, companions := toolingClosures(auth)
	if len(kinds) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE software_installations si
		SET removed_at = $3, updated_at = now()
		FROM unnest($6::text[], $7::text[]) AS a(kind, companion)
		WHERE si.tenant_id = $1::uuid
		  AND si.device_id = $2::uuid
		  AND si.platform = $4
		  AND si.removed_at IS NULL
		  AND si.last_seen_at < $3
		  AND si.identity_kind = a.kind
		  AND (a.companion = '*' OR si.companion_value_normalized = a.companion)
		  AND NOT EXISTS (
			SELECT 1 FROM software_observations so
			WHERE so.inventory_run_id = $5::uuid
			  AND so.identity_fingerprint = si.identity_fingerprint
		  )
	`, row.TenantID, deviceID, row.ReceivedAt, platform, runID, kinds, companions); err != nil {
		return fmt.Errorf("close missing tooling installations: %w", err)
	}
	return nil
}

// upsertToolingCurrentEntries maintains tooling_current_entries. Every
// listed item is added or refreshed unless the report is older than its
// unit's authority; then each authoritative unit drops the rows it did not
// refresh. Partial and failed never drop anything. Two statements at most.
// The caller holds lockToolingDeviceState.
func upsertToolingCurrentEntries(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID, runID string, entries []toolingEntry, ids []int64, auth []toolingAuthority) error {
	if len(entries) > 0 {
		n := len(entries)
		blocks, units, entryKinds, entryKeys := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		for i, e := range entries {
			blocks[i], units[i], entryKinds[i], entryKeys[i] = e.Block, e.Unit, e.EntryKind, e.EntryKey
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO tooling_current_entries (
				device_id, tenant_id, block, unit, entry_kind, entry_key,
				observation_id, observed_at, inventory_run_id
			)
			SELECT $1::uuid, $2::uuid, u.block, u.unit, u.entry_kind, u.entry_key, u.observation_id, $3, $4::uuid
			FROM unnest($5::text[], $6::text[], $7::text[], $8::text[], $9::int8[])
			     AS u(block, unit, entry_kind, entry_key, observation_id)
			LEFT JOIN tooling_device_state s
			  ON s.device_id = $1::uuid AND s.tenant_id = $2::uuid AND s.block = u.block
			WHERE $3 >= COALESCE((s.authority ->> u.unit)::timestamptz, '-infinity'::timestamptz)
			ON CONFLICT (device_id, block, entry_key) DO UPDATE SET
				observation_id = EXCLUDED.observation_id,
				observed_at = EXCLUDED.observed_at,
				inventory_run_id = EXCLUDED.inventory_run_id
			WHERE EXCLUDED.observed_at >= tooling_current_entries.observed_at
			  AND tooling_current_entries.tenant_id = EXCLUDED.tenant_id
		`, deviceID, row.TenantID, row.ReceivedAt, runID, blocks, units, entryKinds, entryKeys, ids); err != nil {
			return fmt.Errorf("upsert tooling current entries: %w", err)
		}
	}
	if len(auth) > 0 {
		blocks, units := make([]string, len(auth)), make([]string, len(auth))
		for i, a := range auth {
			blocks[i], units[i] = a.Block, a.Unit
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM tooling_current_entries c
			USING unnest($4::text[], $5::text[]) AS a(block, unit)
			WHERE c.tenant_id = $1::uuid AND c.device_id = $2::uuid
			  AND c.block = a.block AND c.unit = a.unit
			  AND c.observed_at < $3
		`, row.TenantID, deviceID, row.ReceivedAt, blocks, units); err != nil {
			return fmt.Errorf("prune tooling current entries: %w", err)
		}
	}
	return nil
}

// toolingStateRow is one block's newest state as upserted.
type toolingStateRow struct {
	Block, Status  string
	Truncated      bool
	Reason         *string
	Units, Summary any
	Issues         []toolingIssuePart
	AuthorityUnits []string
}

func toolingStateRows(p *payload, auth []toolingAuthority) []toolingStateRow {
	authBy := map[string][]string{}
	for _, a := range auth {
		authBy[a.Block] = append(authBy[a.Block], a.Unit)
	}
	var out []toolingStateRow
	if b := p.IdeExtensions; b != nil {
		out = append(out, toolingStateRow{
			Block: toolingBlockIDE, Status: b.CollectionStatus, Truncated: b.Truncated, Reason: b.TruncationReason,
			Units:   map[string]string{},
			Summary: map[string]any{"user_count": len(b.Users), "profile_count": len(b.Profiles), "reported_extension_count": len(b.Extensions)},
			Issues:  b.Issues, AuthorityUnits: authBy[toolingBlockIDE],
		})
	}
	if b := p.LocalModels; b != nil {
		var totals any
		if b.Totals != nil {
			totals = b.Totals
		}
		out = append(out, toolingStateRow{
			Block: toolingBlockModels, Status: b.CollectionStatus, Truncated: b.Truncated, Reason: b.TruncationReason,
			Units: unitStatuses(b.Runtimes, func(s localRuntimeSummary) string { return s.CollectionStatus }),
			Summary: map[string]any{"user_count": len(b.Users), "installation_count": len(b.Installations),
				"store_count": len(b.Stores), "totals": totals, "runtimes": b.Runtimes},
			Issues: b.Issues, AuthorityUnits: authBy[toolingBlockModels],
		})
	}
	if b := p.McpServers; b != nil {
		var totals any
		if b.Totals != nil {
			totals = b.Totals
		}
		out = append(out, toolingStateRow{
			Block: toolingBlockMCP, Status: b.CollectionStatus, Truncated: b.Truncated, Reason: b.TruncationReason,
			Units:   unitStatuses(b.Clients, func(s mcpClientPart) string { return s.CollectionStatus }),
			Summary: map[string]any{"user_count": len(b.Users), "totals": totals, "clients": b.Clients},
			Issues:  b.Issues, AuthorityUnits: authBy[toolingBlockMCP],
		})
	}
	if b := p.PackageManagers; b != nil {
		out = append(out, toolingStateRow{
			Block: toolingBlockPackages, Status: b.CollectionStatus, Truncated: b.Truncated, Reason: b.TruncationReason,
			Units:   unitStatuses(b.Sources, func(s packageSourcePart) string { return s.CollectionStatus }),
			Summary: map[string]any{"user_count": len(b.Users), "location_count": len(b.Locations), "sources": b.Sources},
			Issues:  b.Issues, AuthorityUnits: authBy[toolingBlockPackages],
		})
	}
	return out
}

// upsertToolingDeviceState records the newest collection_status per device
// per block, for every status (failed included, so failed and not_present
// stay distinguishable). An older replay never overwrites a newer report;
// each unit's authority only moves forward, and only for the units this
// report is authoritative for. One statement.
func upsertToolingDeviceState(ctx context.Context, tx pgx.Tx, row claimedRow, deviceID, runID string, p *payload, auth []toolingAuthority) error {
	states := toolingStateRows(p, auth)
	if len(states) == 0 {
		return nil
	}
	n := len(states)
	blocks, statuses := make([]string, n), make([]string, n)
	truncated := make([]bool, n)
	reasons := make([]*string, n)
	units, summaries, issues, authority := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
	for i, s := range states {
		blocks[i], statuses[i], truncated[i], reasons[i] = s.Block, s.Status, s.Truncated, s.Reason
		is := s.Issues
		if is == nil {
			is = []toolingIssuePart{}
		}
		a := map[string]any{}
		for _, u := range s.AuthorityUnits {
			a[u] = row.ReceivedAt
		}
		for _, f := range []struct {
			dst *string
			v   any
		}{{&units[i], s.Units}, {&summaries[i], s.Summary}, {&issues[i], is}, {&authority[i], a}} {
			b, err := json.Marshal(f.v)
			if err != nil {
				return fmt.Errorf("marshal tooling state: %w", err)
			}
			*f.dst = string(b)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO tooling_device_state (
			device_id, tenant_id, block, collection_status, truncated, truncation_reason,
			unit_statuses, summary, issues, reported_at, raw_payload_id, raw_payload_received_at,
			inventory_run_id, authority
		)
		SELECT $1::uuid, $2::uuid, u.block, u.status, u.truncated, u.reason,
		       u.units::jsonb, u.summary::jsonb, u.issues::jsonb, $3, $4, $3, $5::uuid, u.authority::jsonb
		FROM unnest($6::text[], $7::text[], $8::bool[], $9::text[], $10::text[], $11::text[], $12::text[], $13::text[])
		     AS u(block, status, truncated, reason, units, summary, issues, authority)
		ON CONFLICT (device_id, block) DO UPDATE SET
			collection_status = CASE WHEN EXCLUDED.reported_at >= tooling_device_state.reported_at THEN EXCLUDED.collection_status ELSE tooling_device_state.collection_status END,
			truncated = CASE WHEN EXCLUDED.reported_at >= tooling_device_state.reported_at THEN EXCLUDED.truncated ELSE tooling_device_state.truncated END,
			truncation_reason = CASE WHEN EXCLUDED.reported_at >= tooling_device_state.reported_at THEN EXCLUDED.truncation_reason ELSE tooling_device_state.truncation_reason END,
			unit_statuses = CASE WHEN EXCLUDED.reported_at >= tooling_device_state.reported_at THEN EXCLUDED.unit_statuses ELSE tooling_device_state.unit_statuses END,
			summary = CASE WHEN EXCLUDED.reported_at >= tooling_device_state.reported_at THEN EXCLUDED.summary ELSE tooling_device_state.summary END,
			issues = CASE WHEN EXCLUDED.reported_at >= tooling_device_state.reported_at THEN EXCLUDED.issues ELSE tooling_device_state.issues END,
			raw_payload_id = CASE WHEN EXCLUDED.reported_at >= tooling_device_state.reported_at THEN EXCLUDED.raw_payload_id ELSE tooling_device_state.raw_payload_id END,
			raw_payload_received_at = CASE WHEN EXCLUDED.reported_at >= tooling_device_state.reported_at THEN EXCLUDED.raw_payload_received_at ELSE tooling_device_state.raw_payload_received_at END,
			inventory_run_id = CASE WHEN EXCLUDED.reported_at >= tooling_device_state.reported_at THEN EXCLUDED.inventory_run_id ELSE tooling_device_state.inventory_run_id END,
			reported_at = GREATEST(EXCLUDED.reported_at, tooling_device_state.reported_at),
			authority = (
				SELECT COALESCE(jsonb_object_agg(x.unit, to_jsonb(x.at)), '{}'::jsonb)
				FROM (
					SELECT e.key AS unit, max(e.value::timestamptz) AS at
					FROM (SELECT * FROM jsonb_each_text(tooling_device_state.authority)
					      UNION ALL
					      SELECT * FROM jsonb_each_text(EXCLUDED.authority)) AS e
					GROUP BY e.key
				) AS x
			),
			updated_at = now()
		WHERE tooling_device_state.tenant_id = EXCLUDED.tenant_id
	`, deviceID, row.TenantID, row.ReceivedAt, row.ID, runID,
		blocks, statuses, truncated, reasons, units, summaries, issues, authority); err != nil {
		return fmt.Errorf("upsert tooling device state: %w", err)
	}
	return nil
}
