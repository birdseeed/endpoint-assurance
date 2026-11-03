package extractor

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PAT-2021: validators for the four tooling blocks (ide_extensions,
// package_managers, local_models, mcp_servers). Each block is optional; when
// present it is strict at every level, like homebrew.
//
// Shared status rules (absence requires authority, PAT-1710):
//   - failed: the item list (extensions, packages, models, servers) must be
//     absent, never []. Every other key is optional, because the macOS agent
//     sends a bare {"collection_status":"failed"} when its parser dies while
//     the Windows agent sends the empty rosters.
//   - complete, partial, not_present: every key is required.
//   - truncated: only partial or failed. A truncation_reason means truncated.
//   - not_present: the item list and the read rows are empty.
//   - complete: evidence of what was read. At least one read row, every read
//     row complete, and (for blocks with units) every unit complete or
//     not_present with at least one complete.
//   - a unit (package source, model runtime, MCP client) reported
//     not_present lists no items of that unit.
//
// Error messages never echo a value from the payload: a key path and the
// rule broken, nothing else. The MCP block is privacy-sensitive, so its
// errors do not echo unknown key names either.

// Bounds equal the agents' own (updater PAT-2017..2020): a conforming agent
// stops, sets truncated and reports partial first, so a block over a bound
// is a contract violation.
const (
	toolingMaxIssues      = 50
	toolingMaxUsers       = 500
	toolingMaxRows        = 10000 // profiles, locations, stores, configs, installations
	ideMaxExtensions      = 5000
	packageMaxPerSource   = 5000
	localModelMaxModels   = 5000
	mcpMaxServers         = 2000
	toolingMaxStringBytes = 4096
)

var (
	toolingStatuses    = setOf("complete", "partial", "not_present", "failed")
	toolingRowStatuses = setOf("complete", "partial", "failed")
	toolingFileStatus  = setOf("read", "missing", "unreadable", "unparseable")
	toolingScopes      = setOf("user", "system")

	ideReasons          = setOf("time_limit", "extension_limit", "user_limit")
	ideFamilies         = setOf("vscode", "jetbrains")
	ideVSCodeEditors    = setOf("vscode", "vscode_insiders", "cursor", "windsurf")
	ideProfileManifests = setOf("extensions_json", "package_json", "plugin_xml")
	ideEntryManifests   = setOf("extensions_json", "package_json", "plugin_xml_jar", "plugin_xml_unpacked", "directory_name")

	packageReasons = setOf("time_limit", "package_limit", "user_limit")
	packageSources = []string{"npm_global", "pip_user", "pipx"}

	localModelReasons        = setOf("time_limit", "model_limit", "user_limit")
	localModelRuntimes       = []string{"ollama", "lm_studio", "llama_cpp"}
	localModelVersionSources = setOf("info_plist", "homebrew_keg", "pe_version_resource", "scoop_version_dir", "none")
	localModelFormats        = setOf("gguf", "safetensors", "other")
	localModelSizeSources    = setOf("manifest", "stat")

	mcpReasons          = setOf("time_limit", "server_limit", "user_limit")
	mcpClients          = []string{"claude_desktop", "cursor", "vscode", "windsurf", "claude_code"}
	mcpServerScopes     = setOf("user", "project")
	mcpTransports       = setOf("stdio", "http", "sse", "unknown")
	mcpTransportSources = setOf("declared", "inferred")
	mcpPackageStatuses  = setOf("extracted", "unrecognised", "missing", "not_applicable")
	mcpRunners          = setOf("npx", "npm", "bunx", "pnpx", "pnpm", "yarn", "uvx", "uv", "pipx", "docker", "podman")
)

func setOf(values ...string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}

// tv carries the error-echo policy for one block.
type tv struct {
	// echoKeys lets an "additional property" error name the key. Off for
	// mcp_servers, where a key name itself could be secret-shaped.
	echoKeys bool
}

func (v tv) keys(path string, obj map[string]any, required bool, allowed ...string) error {
	ok := make(map[string]bool, len(allowed))
	for _, k := range allowed {
		ok[k] = true
	}
	var extra []string
	for k := range obj {
		if !ok[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		if v.echoKeys {
			sort.Strings(extra)
			return fmt.Errorf("%s%s: additional properties not allowed", path, extra[0])
		}
		return fmt.Errorf("%s: %d field(s) outside the allowed set (names not echoed)", strings.TrimSuffix(path, "."), len(extra))
	}
	if required {
		for _, k := range allowed {
			if _, present := obj[k]; !present {
				return fmt.Errorf("%s%s: required field is missing", path, k)
			}
		}
	}
	return nil
}

func tvObject(raw any, path string) (map[string]any, error) {
	obj, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: must be an object", path)
	}
	return obj, nil
}

func tvString(obj map[string]any, path, key string, nullable bool) error {
	raw, present := obj[key]
	if !present {
		return nil
	}
	if raw == nil {
		if nullable {
			return nil
		}
		return fmt.Errorf("%s%s: must be a string", path, key)
	}
	s, ok := raw.(string)
	if !ok {
		if nullable {
			return fmt.Errorf("%s%s: must be a string or null", path, key)
		}
		return fmt.Errorf("%s%s: must be a string", path, key)
	}
	if !nullable && strings.TrimSpace(s) == "" {
		return fmt.Errorf("%s%s: must not be empty", path, key)
	}
	if len(s) > toolingMaxStringBytes {
		return fmt.Errorf("%s%s: longer than %d bytes", path, key, toolingMaxStringBytes)
	}
	return nil
}

func tvEnum(obj map[string]any, path, key string, values map[string]bool, nullable bool) (string, error) {
	raw, present := obj[key]
	if !present {
		return "", nil
	}
	if raw == nil {
		if nullable {
			return "", nil
		}
		return "", fmt.Errorf("%s%s: must be a string", path, key)
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%s%s: must be a string", path, key)
	}
	if !values[s] {
		// The value is deliberately not echoed.
		return "", fmt.Errorf("%s%s: value not in enum %v", path, key, SortedEnum(values))
	}
	return s, nil
}

// SortedEnum lists an enum set for an error message.
func SortedEnum(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for v := range values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func tvCount(obj map[string]any, path, key string, nullable bool) error {
	raw, present := obj[key]
	if !present {
		return nil
	}
	if raw == nil {
		if nullable {
			return nil
		}
		return fmt.Errorf("%s%s: must be a non-negative integer", path, key)
	}
	f, ok := raw.(float64)
	if !ok || f != float64(int64(f)) || f < 0 {
		return fmt.Errorf("%s%s: must be a non-negative integer", path, key)
	}
	return nil
}

func tvBool(obj map[string]any, path, key string, nullable bool) error {
	raw, present := obj[key]
	if !present {
		return nil
	}
	if raw == nil && nullable {
		return nil
	}
	if _, ok := raw.(bool); !ok {
		if nullable {
			return fmt.Errorf("%s%s: must be a boolean or null", path, key)
		}
		return fmt.Errorf("%s%s: must be a boolean", path, key)
	}
	return nil
}

func tvTime(obj map[string]any, path, key string) error {
	raw := obj[key]
	if raw == nil {
		return nil
	}
	s, ok := raw.(string)
	if !ok {
		return fmt.Errorf("%s%s: must be a string or null", path, key)
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return fmt.Errorf("%s%s: must be an RFC3339 timestamp", path, key)
	}
	return nil
}

// tvItems returns the objects of an array key (nil when absent).
func tvItems(obj map[string]any, path, key string, max int) ([]map[string]any, error) {
	raw, present := obj[key]
	if !present {
		return nil, nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s%s: must be an array", path, key)
	}
	if len(arr) > max {
		return nil, fmt.Errorf("%s%s: %d entries exceeds the contract maximum of %d (the agent must truncate and report partial)", path, key, len(arr), max)
	}
	out := make([]map[string]any, len(arr))
	for i, item := range arr {
		o, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s%s[%d]: must be an object", path, key, i)
		}
		out[i] = o
	}
	return out, nil
}

// toolingHeader validates the keys every tooling block shares and the
// status, truncation and failed rules. It returns the block and its status.
func (v tv) header(m map[string]any, block, itemsKey string, keys []string, reasons map[string]bool) (map[string]any, string, bool, error) {
	obj, err := tvObject(m[block], block)
	if err != nil {
		return nil, "", false, err
	}
	path := block + "."
	if err := v.keys(path, obj, false, keys...); err != nil {
		return nil, "", false, err
	}
	status, err := tvEnum(obj, path, "collection_status", toolingStatuses, false)
	if err != nil {
		return nil, "", false, err
	}
	if status == "" {
		return nil, "", false, fmt.Errorf("%scollection_status: required field is missing", path)
	}
	if status == "failed" {
		if _, present := obj[itemsKey]; present {
			return nil, "", false, fmt.Errorf("%s%s: must be omitted when collection_status is \"failed\"", path, itemsKey)
		}
	} else if err := v.keys(path, obj, true, keys...); err != nil {
		return nil, "", false, fmt.Errorf("%w (required when collection_status is %q)", err, status)
	}
	if err := tvBool(obj, path, "truncated", false); err != nil {
		return nil, "", false, err
	}
	truncated, _ := obj["truncated"].(bool)
	if truncated && (status == "complete" || status == "not_present") {
		return nil, "", false, fmt.Errorf("%struncated: a truncated read cannot be %q", path, status)
	}
	reason, err := tvEnum(obj, path, "truncation_reason", reasons, true)
	if err != nil {
		return nil, "", false, err
	}
	if reason != "" && !truncated {
		return nil, "", false, fmt.Errorf("%struncation_reason: set on a read that is not truncated", path)
	}
	issues, err := tvItems(obj, path, "issues", toolingMaxIssues)
	if err != nil {
		return nil, "", false, err
	}
	for i, is := range issues {
		p := fmt.Sprintf("%sissues[%d].", path, i)
		if err := v.keys(p, is, true, "code", "path"); err != nil {
			return nil, "", false, err
		}
		if err := tvString(is, p, "code", false); err != nil {
			return nil, "", false, err
		}
		if err := tvString(is, p, "path", true); err != nil {
			return nil, "", false, err
		}
		if is["path"] == nil {
			return nil, "", false, fmt.Errorf("%spath: must be a string", p)
		}
	}
	return obj, status, truncated, nil
}

// users validates the users roster. unitsKey names the per-unit status map
// ("" for ide_extensions, whose rows carry a profile count instead).
func (v tv) users(obj map[string]any, path string, unitsKey string, units []string, status string) error {
	users, err := tvItems(obj, path, "users", toolingMaxUsers)
	if err != nil {
		return err
	}
	for i, u := range users {
		p := fmt.Sprintf("%susers[%d].", path, i)
		keys := []string{"user", "user_id", "collection_status", "profiles"}
		if unitsKey != "" {
			keys = []string{"user", "user_id", "collection_status", unitsKey}
		}
		if err := v.keys(p, u, true, keys...); err != nil {
			return err
		}
		if err := tvString(u, p, "user", false); err != nil {
			return err
		}
		if err := tvString(u, p, "user_id", true); err != nil {
			return err
		}
		st, err := tvEnum(u, p, "collection_status", toolingStatuses, false)
		if err != nil {
			return err
		}
		// Review P3.2: a complete block read every user in full, so each user
		// row is complete, or not_present when that user has nothing of the
		// kind; a not_present block has only not_present users.
		if err := userStatusFits(p+"collection_status", status, st); err != nil {
			return err
		}
		if unitsKey == "" {
			if err := tvCount(u, p, "profiles", false); err != nil {
				return err
			}
			continue
		}
		m, err := tvObject(u[unitsKey], p+unitsKey)
		if err != nil {
			return err
		}
		if err := v.keys(p+unitsKey+".", m, false, units...); err != nil {
			return err
		}
		for _, unit := range units {
			ust, err := tvEnum(m, p+unitsKey+".", unit, toolingStatuses, false)
			if err != nil {
				return err
			}
			if _, present := m[unit]; present {
				if err := userStatusFits(p+unitsKey+"."+unit, status, ust); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// userStatusFits applies the block status to one user (or user unit) status.
func userStatusFits(path, block, st string) error {
	switch block {
	case "complete":
		if st != "complete" && st != "not_present" {
			return fmt.Errorf("%s: must be complete or not_present when collection_status is \"complete\"", path)
		}
	case "not_present":
		if st != "not_present" {
			return fmt.Errorf("%s: must be not_present when collection_status is \"not_present\"", path)
		}
	}
	return nil
}

// unitSummaries validates the per-unit summary map (sources, runtimes,
// clients). Non-failed blocks must carry every unit. It returns unit ->
// status.
func (v tv) unitSummaries(obj map[string]any, path, key string, units []string, status string, fields func(p string, s map[string]any) error) (map[string]string, error) {
	raw, present := obj[key]
	if !present {
		return map[string]string{}, nil
	}
	m, err := tvObject(raw, path+key)
	if err != nil {
		return nil, err
	}
	if err := v.keys(path+key+".", m, status != "failed", units...); err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, unit := range units {
		sraw, ok := m[unit]
		if !ok {
			continue
		}
		p := path + key + "." + unit + "."
		s, err := tvObject(sraw, strings.TrimSuffix(p, "."))
		if err != nil {
			return nil, err
		}
		st, err := tvEnum(s, p, "collection_status", toolingStatuses, false)
		if err != nil {
			return nil, err
		}
		if st == "" {
			return nil, fmt.Errorf("%scollection_status: required field is missing", p)
		}
		if err := fields(p, s); err != nil {
			return nil, err
		}
		out[unit] = st
	}
	return out, nil
}

// unitsComplete applies the block-level unit rules: complete needs every
// unit complete or not_present with at least one complete; not_present
// needs every unit not_present.
func unitsComplete(path, key string, status string, units map[string]string) error {
	switch status {
	case "complete":
		anyComplete := false
		for unit, st := range units {
			switch st {
			case "complete":
				anyComplete = true
			case "not_present":
			default:
				return fmt.Errorf("%s%s.%s.collection_status: must be complete or not_present when collection_status is \"complete\"", path, key, unit)
			}
		}
		if !anyComplete {
			return fmt.Errorf("%s%s: a complete read needs at least one complete unit", path, key)
		}
	case "not_present":
		for unit, st := range units {
			if st != "not_present" {
				return fmt.Errorf("%s%s.%s.collection_status: must be not_present when collection_status is \"not_present\"", path, key, unit)
			}
		}
	}
	return nil
}

// rowsComplete: a complete read shows what it read, all of it complete.
func rowsComplete(path, key, status string, rows []map[string]any) error {
	switch status {
	case "complete":
		if len(rows) == 0 {
			return fmt.Errorf("%s%s: must not be empty when collection_status is \"complete\"", path, key)
		}
		for i, r := range rows {
			if r["collection_status"] != "complete" {
				return fmt.Errorf("%s%s[%d].collection_status: must be \"complete\" when collection_status is \"complete\"", path, key, i)
			}
		}
	case "not_present":
		if len(rows) > 0 {
			return fmt.Errorf("%s%s: must be empty when collection_status is \"not_present\"", path, key)
		}
	}
	return nil
}

func validateToolingBlocks(m map[string]any) error {
	if _, ok := m["ide_extensions"]; ok {
		if err := validateIdeExtensions(m); err != nil {
			return err
		}
	}
	if _, ok := m["package_managers"]; ok {
		if err := validatePackageManagers(m); err != nil {
			return err
		}
	}
	if _, ok := m["local_models"]; ok {
		if err := validateLocalModels(m); err != nil {
			return err
		}
	}
	if _, ok := m["mcp_servers"]; ok {
		if err := validateMCPServers(m); err != nil {
			return err
		}
	}
	return nil
}

// ide_extensions ----------------------------------------------------------------

func validateIdeExtensions(m map[string]any) error {
	v := tv{echoKeys: true}
	const path = "ide_extensions."
	obj, status, _, err := v.header(m, "ide_extensions", "extensions",
		[]string{"collection_status", "truncated", "truncation_reason", "users", "profiles", "issues", "extensions"}, ideReasons)
	if err != nil {
		return err
	}
	if err := v.users(obj, path, "", nil, status); err != nil {
		return err
	}
	profiles, err := tvItems(obj, path, "profiles", toolingMaxRows)
	if err != nil {
		return err
	}
	for i, p := range profiles {
		pp := fmt.Sprintf("%sprofiles[%d].", path, i)
		if err := v.keys(pp, p, true, "user", "user_id", "family", "editor", "editor_version",
			"collection_status", "manifest_source", "extension_count"); err != nil {
			return err
		}
		if err := ideEditor(p, pp); err != nil {
			return err
		}
		if err := tvString(p, pp, "user", false); err != nil {
			return err
		}
		if err := tvString(p, pp, "user_id", true); err != nil {
			return err
		}
		if _, err := tvEnum(p, pp, "collection_status", toolingRowStatuses, false); err != nil {
			return err
		}
		if _, err := tvEnum(p, pp, "manifest_source", ideProfileManifests, true); err != nil {
			return err
		}
		if err := tvCount(p, pp, "extension_count", false); err != nil {
			return err
		}
	}
	extensions, err := tvItems(obj, path, "extensions", ideMaxExtensions)
	if err != nil {
		return err
	}
	for i, e := range extensions {
		ep := fmt.Sprintf("%sextensions[%d].", path, i)
		if err := v.keys(ep, e, true, "user", "user_id", "family", "editor", "editor_version",
			"id", "name", "publisher", "publisher_display_name", "version", "installed_at",
			"source", "pre_release", "target_platform", "disabled", "directory",
			"manifest_source", "manifest_status"); err != nil {
			return err
		}
		if err := ideEditor(e, ep); err != nil {
			return err
		}
		if err := tvString(e, ep, "user", false); err != nil {
			return err
		}
		for _, k := range []string{"user_id", "id", "name", "publisher", "publisher_display_name",
			"version", "source", "target_platform", "directory"} {
			if err := tvString(e, ep, k, true); err != nil {
				return err
			}
		}
		if err := tvTime(e, ep, "installed_at"); err != nil {
			return err
		}
		for _, k := range []string{"pre_release", "disabled"} {
			if err := tvBool(e, ep, k, true); err != nil {
				return err
			}
		}
		if _, err := tvEnum(e, ep, "manifest_source", ideEntryManifests, true); err != nil {
			return err
		}
		if _, err := tvEnum(e, ep, "manifest_status", toolingFileStatus, true); err != nil {
			return err
		}
	}
	if err := rowsComplete(path, "profiles", status, profiles); err != nil {
		return err
	}
	if status == "not_present" && len(extensions) > 0 {
		return fmt.Errorf("%sextensions: must be empty when collection_status is \"not_present\"", path)
	}
	return nil
}

// ideEditor checks family and editor together: the VS Code family has four
// known editors; a JetBrains editor is the product directory prefix.
func ideEditor(obj map[string]any, path string) error {
	family, err := tvEnum(obj, path, "family", ideFamilies, false)
	if err != nil {
		return err
	}
	if err := tvString(obj, path, "editor", false); err != nil {
		return err
	}
	if err := tvString(obj, path, "editor_version", true); err != nil {
		return err
	}
	if family == "vscode" {
		if _, err := tvEnum(obj, path, "editor", ideVSCodeEditors, false); err != nil {
			return err
		}
	}
	return nil
}

// package_managers ----------------------------------------------------------------

func validatePackageManagers(m map[string]any) error {
	v := tv{echoKeys: true}
	const path = "package_managers."
	obj, status, _, err := v.header(m, "package_managers", "packages",
		[]string{"collection_status", "truncated", "truncation_reason", "sources", "users", "locations", "issues", "packages"}, packageReasons)
	if err != nil {
		return err
	}
	units, err := v.unitSummaries(obj, path, "sources", packageSources, status, func(p string, s map[string]any) error {
		if err := v.keys(p, s, true, "collection_status", "truncated", "package_count", "location_count"); err != nil {
			return err
		}
		if err := tvBool(s, p, "truncated", false); err != nil {
			return err
		}
		if t, _ := s["truncated"].(bool); t && (s["collection_status"] == "complete" || s["collection_status"] == "not_present") {
			return fmt.Errorf("%struncated: a truncated source cannot be complete or not_present", p)
		}
		for _, k := range []string{"package_count", "location_count"} {
			if err := tvCount(s, p, k, false); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if err := v.users(obj, path, "sources", packageSources, status); err != nil {
		return err
	}
	sourceSet := setOf(packageSources...)
	locations, err := tvItems(obj, path, "locations", toolingMaxRows)
	if err != nil {
		return err
	}
	for i, l := range locations {
		lp := fmt.Sprintf("%slocations[%d].", path, i)
		if err := v.keys(lp, l, true, "source", "manager", "scope", "user", "user_id", "path",
			"runtime_version", "interpreters", "collection_status", "package_count"); err != nil {
			return err
		}
		if _, err := tvEnum(l, lp, "source", sourceSet, false); err != nil {
			return err
		}
		if _, err := tvEnum(l, lp, "scope", toolingScopes, false); err != nil {
			return err
		}
		for _, k := range []string{"manager", "path"} {
			if err := tvString(l, lp, k, false); err != nil {
				return err
			}
		}
		for _, k := range []string{"user", "user_id", "runtime_version"} {
			if err := tvString(l, lp, k, true); err != nil {
				return err
			}
		}
		if err := hbStringArray(l, lp, "interpreters", false); err != nil {
			return err
		}
		if _, err := tvEnum(l, lp, "collection_status", toolingRowStatuses, false); err != nil {
			return err
		}
		if err := tvCount(l, lp, "package_count", false); err != nil {
			return err
		}
	}
	packages, err := tvItems(obj, path, "packages", packageMaxPerSource*len(packageSources))
	if err != nil {
		return err
	}
	perSource := map[string]int{}
	for i, pk := range packages {
		pp := fmt.Sprintf("%spackages[%d].", path, i)
		if err := v.keys(pp, pk, true, "source", "manager", "scope", "user", "user_id", "name",
			"version", "prefix", "runtime_version", "interpreter", "directory",
			"metadata_status", "pipx_app", "pipx_main"); err != nil {
			return err
		}
		src, err := tvEnum(pk, pp, "source", sourceSet, false)
		if err != nil {
			return err
		}
		perSource[src]++
		if _, err := tvEnum(pk, pp, "scope", toolingScopes, false); err != nil {
			return err
		}
		if err := tvString(pk, pp, "manager", false); err != nil {
			return err
		}
		for _, k := range []string{"user", "user_id", "name", "version", "prefix", "runtime_version",
			"interpreter", "directory", "pipx_app"} {
			if err := tvString(pk, pp, k, true); err != nil {
				return err
			}
		}
		if _, err := tvEnum(pk, pp, "metadata_status", toolingFileStatus, true); err != nil {
			return err
		}
		if err := tvBool(pk, pp, "pipx_main", true); err != nil {
			return err
		}
	}
	for src, n := range perSource {
		if n > packageMaxPerSource {
			return fmt.Errorf("%spackages: %d %s entries exceeds the contract maximum of %d per source", path, n, src, packageMaxPerSource)
		}
	}
	if err := unitsComplete(path, "sources", status, units); err != nil {
		return err
	}
	if err := rowsComplete(path, "locations", status, locations); err != nil {
		return err
	}
	if status == "not_present" && len(packages) > 0 {
		return fmt.Errorf("%spackages: must be empty when collection_status is \"not_present\"", path)
	}
	for src, st := range units {
		if st == "not_present" && perSource[src] > 0 {
			return fmt.Errorf("%spackages: lists a %s package although sources.%s is not_present", path, src, src)
		}
	}
	return nil
}

// local_models ----------------------------------------------------------------

func validateLocalModels(m map[string]any) error {
	v := tv{echoKeys: true}
	const path = "local_models."
	obj, status, _, err := v.header(m, "local_models", "models",
		[]string{"collection_status", "truncated", "truncation_reason", "runtimes", "totals", "users",
			"installations", "stores", "issues", "models"}, localModelReasons)
	if err != nil {
		return err
	}
	units, err := v.unitSummaries(obj, path, "runtimes", localModelRuntimes, status, func(p string, s map[string]any) error {
		if err := v.keys(p, s, true, "collection_status", "installation_count", "store_count", "model_count", "total_bytes"); err != nil {
			return err
		}
		for _, k := range []string{"installation_count", "store_count", "model_count", "total_bytes"} {
			if err := tvCount(s, p, k, false); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if raw, ok := obj["totals"]; ok {
		t, err := tvObject(raw, path+"totals")
		if err != nil {
			return err
		}
		if err := v.keys(path+"totals.", t, true, "model_count", "total_bytes"); err != nil {
			return err
		}
		for _, k := range []string{"model_count", "total_bytes"} {
			if err := tvCount(t, path+"totals.", k, false); err != nil {
				return err
			}
		}
	}
	if err := v.users(obj, path, "runtimes", localModelRuntimes, status); err != nil {
		return err
	}
	runtimeSet := setOf(localModelRuntimes...)
	installations, err := tvItems(obj, path, "installations", toolingMaxRows)
	if err != nil {
		return err
	}
	for i, in := range installations {
		ip := fmt.Sprintf("%sinstallations[%d].", path, i)
		if err := v.keys(ip, in, true, "runtime", "scope", "user", "user_id", "kind", "path",
			"version", "version_source", "identifier"); err != nil {
			return err
		}
		if _, err := tvEnum(in, ip, "runtime", runtimeSet, false); err != nil {
			return err
		}
		if _, err := tvEnum(in, ip, "scope", toolingScopes, false); err != nil {
			return err
		}
		for _, k := range []string{"kind", "path"} {
			if err := tvString(in, ip, k, false); err != nil {
				return err
			}
		}
		for _, k := range []string{"user", "user_id", "version", "identifier"} {
			if err := tvString(in, ip, k, true); err != nil {
				return err
			}
		}
		if _, err := tvEnum(in, ip, "version_source", localModelVersionSources, false); err != nil {
			return err
		}
	}
	stores, err := tvItems(obj, path, "stores", toolingMaxRows)
	if err != nil {
		return err
	}
	for i, s := range stores {
		sp := fmt.Sprintf("%sstores[%d].", path, i)
		if err := v.keys(sp, s, true, "runtime", "scope", "user", "user_id", "path",
			"collection_status", "model_count", "total_bytes"); err != nil {
			return err
		}
		if _, err := tvEnum(s, sp, "runtime", runtimeSet, false); err != nil {
			return err
		}
		if _, err := tvEnum(s, sp, "scope", toolingScopes, false); err != nil {
			return err
		}
		if err := tvString(s, sp, "path", false); err != nil {
			return err
		}
		for _, k := range []string{"user", "user_id"} {
			if err := tvString(s, sp, k, true); err != nil {
				return err
			}
		}
		if _, err := tvEnum(s, sp, "collection_status", toolingRowStatuses, false); err != nil {
			return err
		}
		for _, k := range []string{"model_count", "total_bytes"} {
			if err := tvCount(s, sp, k, false); err != nil {
				return err
			}
		}
	}
	models, err := tvItems(obj, path, "models", localModelMaxModels)
	if err != nil {
		return err
	}
	perRuntime := map[string]int{}
	for i, md := range models {
		mp := fmt.Sprintf("%smodels[%d].", path, i)
		if err := v.keys(mp, md, true, "runtime", "user", "user_id", "store_path", "name", "tag",
			"format", "size_bytes", "file_count", "size_source", "missing_blobs", "metadata_status"); err != nil {
			return err
		}
		rt, err := tvEnum(md, mp, "runtime", runtimeSet, false)
		if err != nil {
			return err
		}
		perRuntime[rt]++
		if err := tvString(md, mp, "store_path", false); err != nil {
			return err
		}
		for _, k := range []string{"user", "user_id", "name", "tag"} {
			if err := tvString(md, mp, k, true); err != nil {
				return err
			}
		}
		if _, err := tvEnum(md, mp, "format", localModelFormats, true); err != nil {
			return err
		}
		if _, err := tvEnum(md, mp, "size_source", localModelSizeSources, true); err != nil {
			return err
		}
		if _, err := tvEnum(md, mp, "metadata_status", toolingFileStatus, true); err != nil {
			return err
		}
		for _, k := range []string{"size_bytes", "file_count", "missing_blobs"} {
			if err := tvCount(md, mp, k, true); err != nil {
				return err
			}
		}
	}
	if err := unitsComplete(path, "runtimes", status, units); err != nil {
		return err
	}
	switch status {
	case "complete":
		// Evidence: something was read. Every store read must be complete.
		if len(installations)+len(stores) == 0 {
			return fmt.Errorf("%sinstallations: a complete read lists at least one installation or store", path)
		}
		for i, s := range stores {
			if s["collection_status"] != "complete" {
				return fmt.Errorf("%sstores[%d].collection_status: must be \"complete\" when collection_status is \"complete\"", path, i)
			}
		}
	case "not_present":
		if len(installations)+len(stores)+len(models) > 0 {
			return fmt.Errorf("%s: installations, stores and models must be empty when collection_status is \"not_present\"", strings.TrimSuffix(path, "."))
		}
	}
	for rt, st := range units {
		if st == "not_present" && perRuntime[rt] > 0 {
			return fmt.Errorf("%smodels: lists a %s model although runtimes.%s is not_present", path, rt, rt)
		}
	}
	return nil
}

// mcp_servers ----------------------------------------------------------------

// mcpServerAllowed is the PAT-2020 allowlist: everything Patched keeps for a
// configured MCP server. Nothing else may arrive.
var mcpServerAllowed = []string{"client", "user", "user_id", "config_path", "scope", "name",
	"transport", "transport_source", "executable", "runner", "package", "package_status", "host"}

func validateMCPServers(m map[string]any) error {
	// The privacy guard ran first (ValidatePayload), so every server entry
	// already carries only allowlisted fields with reduced values. The rest
	// is the ordinary contract, with no key or value echoed.
	v := tv{echoKeys: false}
	const path = "mcp_servers."
	obj, status, _, err := v.header(m, "mcp_servers", "servers",
		[]string{"collection_status", "truncated", "truncation_reason", "clients", "totals", "users",
			"configs", "issues", "servers"}, mcpReasons)
	if err != nil {
		return err
	}
	units, err := v.unitSummaries(obj, path, "clients", mcpClients, status, func(p string, s map[string]any) error {
		if err := v.keys(p, s, true, "collection_status", "config_count", "server_count"); err != nil {
			return err
		}
		for _, k := range []string{"config_count", "server_count"} {
			if err := tvCount(s, p, k, false); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if raw, ok := obj["totals"]; ok {
		t, err := tvObject(raw, path+"totals")
		if err != nil {
			return err
		}
		if err := v.keys(path+"totals.", t, true, "config_count", "server_count"); err != nil {
			return err
		}
		for _, k := range []string{"config_count", "server_count"} {
			if err := tvCount(t, path+"totals.", k, false); err != nil {
				return err
			}
		}
	}
	if err := v.users(obj, path, "clients", mcpClients, status); err != nil {
		return err
	}
	clientSet := setOf(mcpClients...)
	configs, err := tvItems(obj, path, "configs", toolingMaxRows)
	if err != nil {
		return err
	}
	for i, c := range configs {
		cp := fmt.Sprintf("%sconfigs[%d].", path, i)
		if err := v.keys(cp, c, true, "client", "user", "user_id", "path", "collection_status", "server_count"); err != nil {
			return err
		}
		if _, err := tvEnum(c, cp, "client", clientSet, false); err != nil {
			return err
		}
		if err := tvString(c, cp, "path", false); err != nil {
			return err
		}
		for _, k := range []string{"user", "user_id"} {
			if err := tvString(c, cp, k, true); err != nil {
				return err
			}
		}
		if _, err := tvEnum(c, cp, "collection_status", toolingRowStatuses, false); err != nil {
			return err
		}
		if err := tvCount(c, cp, "server_count", false); err != nil {
			return err
		}
	}
	servers, err := tvItems(obj, path, "servers", mcpMaxServers)
	if err != nil {
		return err
	}
	perClient := map[string]int{}
	for i, s := range servers {
		sp := fmt.Sprintf("%sservers[%d].", path, i)
		if err := v.keys(sp, s, true, mcpServerAllowed...); err != nil {
			return err
		}
		client, err := tvEnum(s, sp, "client", clientSet, false)
		if err != nil {
			return err
		}
		perClient[client]++
		if err := tvString(s, sp, "config_path", false); err != nil {
			return err
		}
		for _, k := range []string{"user", "user_id", "name", "executable", "package", "host"} {
			if err := tvString(s, sp, k, true); err != nil {
				return err
			}
		}
		for key, set := range map[string]map[string]bool{
			"scope": mcpServerScopes, "transport": mcpTransports,
			"transport_source": mcpTransportSources, "package_status": mcpPackageStatuses,
		} {
			if _, err := tvEnum(s, sp, key, set, false); err != nil {
				return err
			}
		}
		if _, err := tvEnum(s, sp, "runner", mcpRunners, true); err != nil {
			return err
		}
		if s["package"] != nil && s["package_status"] != "extracted" {
			return fmt.Errorf("%spackage: only an extracted package may be sent", sp)
		}
	}
	if err := unitsComplete(path, "clients", status, units); err != nil {
		return err
	}
	if err := rowsComplete(path, "configs", status, configs); err != nil {
		return err
	}
	if status == "not_present" && len(servers) > 0 {
		return fmt.Errorf("%sservers: must be empty when collection_status is \"not_present\"", path)
	}
	for c, st := range units {
		if st == "not_present" && perClient[c] > 0 {
			return fmt.Errorf("%sservers: lists a %s server although clients.%s is not_present", path, c, c)
		}
	}
	return nil
}

// MCP privacy guard (PAT-2021, defence in depth behind PAT-2020) ---------------

// MCPPrivacyGuardError is returned by ValidatePayload when an mcp_servers
// server entry carries a field outside the PAT-2020 allowlist, or an
// allowlisted field whose value is not in its reduced form (a host with a
// path, an executable with a directory, a secret-shaped string). The whole
// payload is rejected before anything is stored: raw_payloads is the
// immutable archive, so accepting the payload and dropping only the block
// would still persist the secret. The error names only fixed field classes,
// never a key the agent sent or any value.
type MCPPrivacyGuardError struct {
	// Entries is how many server entries broke the guard.
	Entries int
	// Classes counts violations by fixed class name.
	Classes map[string]int
}

// ErrMCPPrivacyGuard lets callers match with errors.Is.
var ErrMCPPrivacyGuard = errors.New("mcp_servers privacy guard")

func (e *MCPPrivacyGuardError) Error() string {
	return fmt.Sprintf("mcp_servers.servers: %d entr%s rejected by the privacy guard (classes: %s); no field name or value is echoed",
		e.Entries, map[bool]string{true: "y", false: "ies"}[e.Entries == 1], strings.Join(e.ClassNames(), ", "))
}

func (e *MCPPrivacyGuardError) Unwrap() error { return ErrMCPPrivacyGuard }

// ClassNames lists the violation classes, sorted.
func (e *MCPPrivacyGuardError) ClassNames() []string {
	out := make([]string, 0, len(e.Classes))
	for c := range e.Classes {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// mcpForbiddenFieldClass maps a key outside the allowlist to a fixed class.
// Anything unrecognised is "other_field"; the key itself is never reported.
func mcpForbiddenFieldClass(key string) string {
	k := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
	switch k {
	case "env", "environment", "envfile":
		return "env"
	case "args", "arguments", "argv":
		return "args"
	case "headers", "header":
		return "headers"
	case "url", "serverurl", "uri", "endpoint", "fullurl":
		return "url"
	case "command", "cmd", "commandline":
		return "command"
	case "cwd", "path", "workingdirectory", "dir":
		return "path"
	}
	if strings.Contains(k, "token") || strings.Contains(k, "secret") || strings.Contains(k, "key") ||
		strings.Contains(k, "passw") || strings.Contains(k, "auth") || strings.Contains(k, "credential") {
		return "credential"
	}
	return "other_field"
}

var (
	// The agent's own reduced forms (updater macos/lib/mcp_servers.sh and
	// McpServerScanLogic.cs); the server accepts nothing looser.
	//
	// Review round 2 (a): every server rejection must be a subset of what
	// both agents already drop, or a payload an agent legitimately sends
	// would 400 forever. mcpSecretShape is character for character the
	// agents' SECRET_SHAPE_RE / SecretShape (identical on both platforms),
	// and both apply it to exactly the emitted name, executable and
	// non-IPv6 host, and to a superstring of the emitted package (the
	// candidate; the emitted npm/PyPI name is its prefix without a version,
	// the emitted image its lower-cased public registry plus path, and no
	// public registry name matches a shape), so an emitted value matching it
	// was already dropped on the device. mcpNamePattern and
	// mcpExecutablePattern equal NAME_RE and EXECUTABLE_RE; the package
	// pattern is looser than NPM_RE, PYPI_RE and the image patterns.
	mcpNamePattern       = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9 ._@/+()\-]{0,127}$`)
	mcpExecutablePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$`)
	mcpPackagePattern    = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9._\-/]{0,254}$`)
	// Review P3.1: exactly the agents' HOST_RE and IPV6_RE (updater
	// macos/lib/mcp_servers.sh url_host, McpServerScanLogic.UrlHost). A DNS
	// host is lower-case and never secret-shaped; an IPv6 literal (the
	// inside of the brackets) is hex, colons and dots, so it can carry no
	// userinfo, port, path or query, and the agents do not secret-check it.
	mcpHostPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)*$`)
	mcpIPv6Pattern = regexp.MustCompile(`^[0-9a-f:.]{2,45}$`)
	// Review P3.3: an issue code is a fixed lower_snake token; a path is
	// never a URL.
	mcpIssueCodePattern = regexp.MustCompile(`^[a-z0-9_]{1,64}$`)
	mcpSecretShape      = regexp.MustCompile(`(?:^|[^A-Za-z0-9])(?:sk|pk|rk)[-_]|gh[pousr]_|github_pat_|glpat-|xox[abposr]-|AKIA[0-9A-Z]{12}|AIza[0-9A-Za-z_-]{8}|eyJ[A-Za-z0-9_-]{4}|ya29\.|[A-Za-z0-9]{32}`)
)

// mcpPrivacyGuard inspects every mcp_servers.servers entry before anything
// else in the payload is validated, so a guard hit is always counted, even
// on a payload that would fail for another reason too. Non-string values in
// allowlisted fields are left to the ordinary validator.
func mcpPrivacyGuard(m map[string]any) error {
	block, ok := m["mcp_servers"].(map[string]any)
	if !ok {
		return nil
	}
	servers, _ := block["servers"].([]any)
	allowed := setOf(mcpServerAllowed...)
	guard := &MCPPrivacyGuardError{Classes: map[string]int{}}
	for _, raw := range servers {
		s, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		hit := false
		flag := func(class string) {
			guard.Classes[class]++
			hit = true
		}
		for k := range s {
			if !allowed[k] {
				flag(mcpForbiddenFieldClass(k))
			}
		}
		str := func(key string) (string, bool) {
			v, ok := s[key].(string)
			return v, ok
		}
		if v, ok := str("host"); ok {
			switch {
			// An IPv6 literal always contains ':'. Without one, a hex-only
			// value (a token) must fall through to the hostname and
			// secret-shape checks rather than be waved through here.
			case strings.Contains(v, ":") && mcpIPv6Pattern.MatchString(v):
			case len(v) > 253 || !mcpHostPattern.MatchString(v):
				flag("host_not_bare")
			case mcpSecretShape.MatchString(v):
				flag("secret_shaped_value")
			}
		}
		if v, ok := str("config_path"); ok {
			if class := mcpPathClass(v); class != "" {
				flag(class)
			}
		}
		if v, ok := str("executable"); ok {
			if !mcpExecutablePattern.MatchString(v) {
				flag("executable_not_basename")
			} else if mcpSecretShape.MatchString(v) {
				flag("secret_shaped_value")
			}
		}
		if v, ok := str("package"); ok {
			if !mcpPackagePattern.MatchString(v) {
				flag("package_not_reduced")
			} else if mcpSecretShape.MatchString(v) {
				flag("secret_shaped_value")
			}
		}
		if v, ok := str("name"); ok {
			if !mcpNamePattern.MatchString(v) {
				flag("name_not_reduced")
			} else if mcpSecretShape.MatchString(v) {
				flag("secret_shaped_value")
			}
		}
		if hit {
			guard.Entries++
		}
	}
	// Review P3.3: config file paths and issues come from user-owned trees
	// and the same parser; a URL or a secret shape there is a hit too.
	var rows []map[string]any
	if configs, ok := block["configs"].([]any); ok {
		for _, raw := range configs {
			if c, ok := raw.(map[string]any); ok {
				rows = append(rows, map[string]any{"path": c["path"]})
			}
		}
	}
	if issues, ok := block["issues"].([]any); ok {
		for _, raw := range issues {
			if is, ok := raw.(map[string]any); ok {
				rows = append(rows, is)
			}
		}
	}
	for _, r := range rows {
		hit := false
		if v, ok := r["path"].(string); ok {
			if class := mcpPathClass(v); class != "" {
				guard.Classes[class]++
				hit = true
			}
		}
		if v, ok := r["code"].(string); ok && (!mcpIssueCodePattern.MatchString(v) || mcpSecretShape.MatchString(v)) {
			guard.Classes["code_not_plain"]++
			hit = true
		}
		if hit {
			guard.Entries++
		}
	}
	if guard.Entries > 0 {
		return guard
	}
	return nil
}

// mcpPathClass returns a guard class for a path that is a URL (any scheme,
// so URL userinfo too) or carries a control character.
//
// Review round 2 (a): a guard hit rejects the whole payload on every
// check-in, so on a field the agents fill from user text the server may only
// reject what the agents can never emit. Both agents build these paths by
// joining directory entries (no entry holds a "/", so "//" and "://" never
// occur) and replace any string with a control character by
// "<unprintable>". They do NOT secret-check paths, so neither does this: a
// home directory named like a key must not lock a device out. Issue codes
// are fixed agent tokens, never user text, so they get the stricter check.
func mcpPathClass(v string) string {
	if strings.Contains(v, "://") {
		return "path_not_plain"
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "path_not_plain"
		}
	}
	return ""
}
