package extractor

import (
	"fmt"
	"time"
)

// Homebrew block bounds (PAT-2013 size policy). They equal the macOS
// collector's own bounds in updater macos/lib/homebrew.sh (5,000 formulae,
// 5,000 casks, 1,000 taps, 50 issues), so a conforming agent can never hit
// them: it stops, sets truncated and reports partial first. A block over a
// bound is a contract violation and is rejected like any other. The
// prefixes bound is headroom over the agent's two fixed prefixes.
const (
	homebrewMaxFormulae = 5000
	homebrewMaxCasks    = 5000
	homebrewMaxTaps     = 1000
	homebrewMaxIssues   = 50
	homebrewMaxPrefixes = 16
)

var (
	homebrewCollectionStatuses = map[string]bool{"complete": true, "partial": true, "not_present": true, "failed": true}
	homebrewPrefixStatuses     = map[string]bool{"complete": true, "partial": true, "failed": true}
	// size_limit (PAT-2032): the agent's serialised byte budget stopped the
	// read. Like every other reason it means truncated, so partial.
	homebrewTruncationReasons = map[string]bool{"time_limit": true, "formula_limit": true, "cask_limit": true, "tap_limit": true, "size_limit": true}
	homebrewReceiptStatuses   = map[string]bool{"read": true, "missing": true, "unreadable": true, "unparseable": true}
	homebrewFormulaFileStatus = map[string]bool{"read": true, "missing": true, "unreadable": true}
	homebrewTapConfigStatuses = map[string]bool{"read": true, "missing": true, "unreadable": true, "not_a_directory": true}
)

// validateHomebrew enforces the `homebrew` block contract (PAT-2012 agent,
// PAT-2013 platform; docs/payload.schema.json). Absent is valid: an agent
// that predates the collector, or holds it off the wire. Present, it is
// strict at every level, like local_admins.
//
// Status rules, all about absence authority:
//   - failed: formulae, casks and taps must be absent. The agent omits them
//     so a failed read can never look like "no packages".
//   - complete, partial, not_present: all eight keys are required.
//   - not_present: the three lists and prefixes must be empty, and
//     truncated must not be true. A prefix row means a Homebrew layout was
//     found, and a truncated read did not finish checking.
//   - complete: truncated must be false, there must be at least one prefix
//     row, and every prefix row must be complete. A truncated read, or one with a partial or failed prefix,
//     is partial.
//
// complete and not_present grant the absence authority that closes
// installations (PAT-2032 made both rules strict for that reason).
func validateHomebrew(m map[string]any) error {
	raw, ok := m["homebrew"]
	if !ok {
		return nil
	}
	hb, ok := raw.(map[string]any)
	if !ok {
		return fmt.Errorf("homebrew: must be an object")
	}
	for k := range hb {
		switch k {
		case "collection_status", "truncated", "truncation_reason", "prefixes",
			"formulae", "casks", "taps", "issues":
		default:
			return fmt.Errorf("homebrew.%s: additional properties not allowed", k)
		}
	}
	status, err := hbEnum(hb, "homebrew.", "collection_status", homebrewCollectionStatuses, true)
	if err != nil {
		return err
	}

	if status == "failed" {
		for _, k := range []string{"formulae", "casks", "taps"} {
			if _, ok := hb[k]; ok {
				return fmt.Errorf("homebrew.%s: must be omitted when collection_status is \"failed\"", k)
			}
		}
	} else {
		if err := schemaCheckRequired(hb, "homebrew.", []string{
			"truncated", "truncation_reason", "prefixes", "formulae", "casks", "taps", "issues",
		}); err != nil {
			return fmt.Errorf("%w (required when collection_status is %q)", err, status)
		}
	}

	if v, ok := hb["truncated"]; ok {
		truncated, isBool := v.(bool)
		if !isBool {
			return fmt.Errorf("homebrew.truncated: must be a boolean")
		}
		if truncated && status == "complete" {
			return fmt.Errorf("homebrew.truncated: a truncated read cannot be \"complete\"")
		}
		if truncated && status == "not_present" {
			return fmt.Errorf("homebrew.truncated: a truncated read cannot be \"not_present\"")
		}
	}
	if v, ok := hb["truncation_reason"]; ok && v != nil {
		s, isString := v.(string)
		if !isString {
			return fmt.Errorf("homebrew.truncation_reason: must be a string or null")
		}
		if !homebrewTruncationReasons[s] {
			return fmt.Errorf("homebrew.truncation_reason: value %q not in enum [\"time_limit\", \"formula_limit\", \"cask_limit\", \"tap_limit\", \"size_limit\"]", s)
		}
	}

	if err := hbArray(hb, "prefixes", homebrewMaxPrefixes, validateHomebrewPrefix); err != nil {
		return err
	}
	if err := hbArray(hb, "formulae", homebrewMaxFormulae, validateHomebrewFormula); err != nil {
		return err
	}
	if err := hbArray(hb, "casks", homebrewMaxCasks, validateHomebrewCask); err != nil {
		return err
	}
	if err := hbArray(hb, "taps", homebrewMaxTaps, validateHomebrewTap); err != nil {
		return err
	}
	if err := hbArray(hb, "issues", homebrewMaxIssues, validateHomebrewIssue); err != nil {
		return err
	}

	if status == "complete" {
		prefixes, _ := hb["prefixes"].([]any)
		// A complete read grants absence authority, so it must show what
		// it read: at least one prefix. With no Homebrew layout the agent
		// reports not_present instead.
		if len(prefixes) == 0 {
			return fmt.Errorf("homebrew.prefixes: must not be empty when collection_status is \"complete\"")
		}
		for i, raw := range prefixes {
			if p, _ := raw.(map[string]any); p["collection_status"] != "complete" {
				return fmt.Errorf("homebrew.prefixes[%d].collection_status: must be \"complete\" when collection_status is \"complete\"", i)
			}
		}
	}
	if status == "not_present" {
		for _, k := range []string{"prefixes", "formulae", "casks", "taps"} {
			if arr, _ := hb[k].([]any); len(arr) > 0 {
				return fmt.Errorf("homebrew.%s: must be empty when collection_status is \"not_present\"", k)
			}
		}
	}
	return nil
}

func hbArray(hb map[string]any, key string, max int, item func(string, map[string]any) error) error {
	v, ok := hb[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return fmt.Errorf("homebrew.%s: must be an array", key)
	}
	if len(arr) > max {
		return fmt.Errorf("homebrew.%s: %d entries exceeds the contract maximum of %d (the agent must truncate and report partial)", key, len(arr), max)
	}
	for i, raw := range arr {
		path := fmt.Sprintf("homebrew.%s[%d].", key, i)
		obj, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("homebrew.%s[%d]: must be an object", key, i)
		}
		if err := item(path, obj); err != nil {
			return err
		}
	}
	return nil
}

func hbAllowed(path string, obj map[string]any, keys ...string) error {
	if err := schemaCheckRequired(obj, path, keys); err != nil {
		return err
	}
	allowed := make(map[string]bool, len(keys))
	for _, k := range keys {
		allowed[k] = true
	}
	for k := range obj {
		if !allowed[k] {
			return fmt.Errorf("%s%s: additional properties not allowed", path, k)
		}
	}
	return nil
}

func hbString(obj map[string]any, path, key string, nullable bool) error {
	v := obj[key]
	if v == nil {
		if nullable {
			return nil
		}
		return fmt.Errorf("%s%s: must be a string", path, key)
	}
	s, ok := v.(string)
	if !ok {
		if nullable {
			return fmt.Errorf("%s%s: must be a string or null", path, key)
		}
		return fmt.Errorf("%s%s: must be a string", path, key)
	}
	if !nullable && s == "" {
		return fmt.Errorf("%s%s: must not be empty", path, key)
	}
	return nil
}

func hbNullableBool(obj map[string]any, path, key string) error {
	if v := obj[key]; v != nil {
		if _, ok := v.(bool); !ok {
			return fmt.Errorf("%s%s: must be a boolean or null", path, key)
		}
	}
	return nil
}

func hbNullableTime(obj map[string]any, path, key string) error {
	v := obj[key]
	if v == nil {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Errorf("%s%s: must be a string or null", path, key)
	}
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return fmt.Errorf("%s%s: must be an RFC3339 timestamp", path, key)
	}
	return nil
}

func hbStringArray(obj map[string]any, path, key string, nullable bool) error {
	v := obj[key]
	if v == nil {
		if nullable {
			return nil
		}
		return fmt.Errorf("%s%s: must be an array", path, key)
	}
	arr, ok := v.([]any)
	if !ok {
		return fmt.Errorf("%s%s: must be an array", path, key)
	}
	for i, item := range arr {
		if _, ok := item.(string); !ok {
			return fmt.Errorf("%s%s[%d]: must be a string", path, key, i)
		}
	}
	return nil
}

func hbEnum(obj map[string]any, path, key string, values map[string]bool, required bool) (string, error) {
	v, ok := obj[key]
	if !ok {
		if required {
			return "", fmt.Errorf("%s%s: required field is missing", path, key)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s%s: must be a string", path, key)
	}
	if !values[s] {
		return "", fmt.Errorf("%s%s: value %q not in enum", path, key, s)
	}
	return s, nil
}

func hbCount(obj map[string]any, path, key string) error {
	f, ok := obj[key].(float64)
	if !ok || f != float64(int64(f)) || f < 0 {
		return fmt.Errorf("%s%s: must be a non-negative integer", path, key)
	}
	return nil
}

func validateHomebrewPrefix(path string, obj map[string]any) error {
	if err := hbAllowed(path, obj, "path", "owner", "owner_uid", "collection_status", "formulae", "casks", "taps"); err != nil {
		return err
	}
	if err := hbString(obj, path, "path", false); err != nil {
		return err
	}
	if err := hbString(obj, path, "owner", true); err != nil {
		return err
	}
	if v := obj["owner_uid"]; v != nil {
		if err := hbCount(obj, path, "owner_uid"); err != nil {
			return fmt.Errorf("%sowner_uid: must be a non-negative integer or null", path)
		}
	}
	if _, err := hbEnum(obj, path, "collection_status", homebrewPrefixStatuses, true); err != nil {
		return err
	}
	for _, k := range []string{"formulae", "casks", "taps"} {
		if err := hbCount(obj, path, k); err != nil {
			return err
		}
	}
	return nil
}

func validateHomebrewFormula(path string, obj map[string]any) error {
	if err := hbAllowed(path, obj, "prefix", "name", "version", "tap",
		"installed_on_request", "installed_as_dependency", "installed_at",
		"runtime_dependencies", "homepage", "source_url", "opt_linked",
		"receipt_status", "formula_file_status"); err != nil {
		return err
	}
	for _, k := range []string{"prefix", "name", "version"} {
		if err := hbString(obj, path, k, false); err != nil {
			return err
		}
	}
	for _, k := range []string{"tap", "homepage", "source_url"} {
		if err := hbString(obj, path, k, true); err != nil {
			return err
		}
	}
	for _, k := range []string{"installed_on_request", "installed_as_dependency", "opt_linked"} {
		if err := hbNullableBool(obj, path, k); err != nil {
			return err
		}
	}
	if err := hbNullableTime(obj, path, "installed_at"); err != nil {
		return err
	}
	if err := hbStringArray(obj, path, "runtime_dependencies", true); err != nil {
		return err
	}
	if _, err := hbEnum(obj, path, "receipt_status", homebrewReceiptStatuses, true); err != nil {
		return err
	}
	_, err := hbEnum(obj, path, "formula_file_status", homebrewFormulaFileStatus, true)
	return err
}

func validateHomebrewCask(path string, obj map[string]any) error {
	if err := hbAllowed(path, obj, "prefix", "token", "version", "versions_on_disk", "tap",
		"installed_on_request", "installed_at", "receipt_status", "apps"); err != nil {
		return err
	}
	for _, k := range []string{"prefix", "token"} {
		if err := hbString(obj, path, k, false); err != nil {
			return err
		}
	}
	for _, k := range []string{"version", "tap"} {
		if err := hbString(obj, path, k, true); err != nil {
			return err
		}
	}
	if err := hbStringArray(obj, path, "versions_on_disk", false); err != nil {
		return err
	}
	if err := hbNullableBool(obj, path, "installed_on_request"); err != nil {
		return err
	}
	if err := hbNullableTime(obj, path, "installed_at"); err != nil {
		return err
	}
	if _, err := hbEnum(obj, path, "receipt_status", homebrewReceiptStatuses, true); err != nil {
		return err
	}
	apps, ok := obj["apps"].([]any)
	if !ok {
		return fmt.Errorf("%sapps: must be an array", path)
	}
	for i, raw := range apps {
		appPath := fmt.Sprintf("%sapps[%d].", path, i)
		app, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("%sapps[%d]: must be an object", path, i)
		}
		if err := hbAllowed(appPath, app, "name", "path", "exists"); err != nil {
			return err
		}
		if err := hbString(app, appPath, "name", false); err != nil {
			return err
		}
		if err := hbString(app, appPath, "path", true); err != nil {
			return err
		}
		if err := hbNullableBool(app, appPath, "exists"); err != nil {
			return err
		}
	}
	return nil
}

func validateHomebrewTap(path string, obj map[string]any) error {
	if err := hbAllowed(path, obj, "prefix", "name", "directory", "remote_url", "config_status"); err != nil {
		return err
	}
	for _, k := range []string{"prefix", "name", "directory"} {
		if err := hbString(obj, path, k, false); err != nil {
			return err
		}
	}
	if err := hbString(obj, path, "remote_url", true); err != nil {
		return err
	}
	_, err := hbEnum(obj, path, "config_status", homebrewTapConfigStatuses, true)
	return err
}

func validateHomebrewIssue(path string, obj map[string]any) error {
	if err := hbAllowed(path, obj, "code", "path"); err != nil {
		return err
	}
	if err := hbString(obj, path, "code", false); err != nil {
		return err
	}
	return hbString(obj, path, "path", false)
}
