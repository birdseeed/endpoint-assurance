package extractor

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// homebrewFixture loads the real-shaped complete block fixture as a generic
// map, so each case can break exactly one thing.
func homebrewFixture(t *testing.T) map[string]any {
	t.Helper()
	data := readFixture(t, "valid", "with-homebrew-complete-macos.json")
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func validateMap(t *testing.T, m map[string]any) error {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return ValidatePayload(data)
}

func hbBlock(m map[string]any) map[string]any { return m["homebrew"].(map[string]any) }
func hbList(m map[string]any, key string) []any {
	return hbBlock(m)[key].([]any)
}
func hbItem(m map[string]any, key string, i int) map[string]any {
	return hbList(m, key)[i].(map[string]any)
}

func TestValidateHomebrewAcceptsRealShapedBlocks(t *testing.T) {
	for _, f := range []string{
		"valid/with-homebrew-complete-macos.json",
		"valid/with-homebrew-failed-macos.json",
		"edge/homebrew-partial-truncated-macos.json",
		"edge/homebrew-not-present-macos.json",
	} {
		dir, name := filepath.Split(f)
		if err := ValidatePayload(readFixture(t, strings.TrimSuffix(dir, "/"), name)); err != nil {
			t.Errorf("%s rejected: %v", f, err)
		}
	}
	// Absent is valid: an agent that predates the collector.
	m := homebrewFixture(t)
	delete(m, "homebrew")
	if err := validateMap(t, m); err != nil {
		t.Fatalf("payload without homebrew rejected: %v", err)
	}
	// The failed form the Python parser writes, with prefixes and issues.
	m = homebrewFixture(t)
	m["homebrew"] = map[string]any{
		"collection_status": "failed",
		"prefixes": []any{map[string]any{"path": "/opt/homebrew", "owner": nil, "owner_uid": nil,
			"collection_status": "failed", "formulae": 0, "casks": 0, "taps": 0}},
		"issues": []any{map[string]any{"code": "unreadable", "path": "/opt/homebrew/Cellar"}},
	}
	if err := validateMap(t, m); err != nil {
		t.Fatalf("parser failed form rejected: %v", err)
	}
}

func TestValidateHomebrewRejectsUnknownKeysAtEveryLevel(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"block":   func(m map[string]any) { hbBlock(m)["source"] = "brew" },
		"prefix":  func(m map[string]any) { hbItem(m, "prefixes", 0)["shell"] = "zsh" },
		"formula": func(m map[string]any) { hbItem(m, "formulae", 0)["cpe"] = "x" },
		"cask":    func(m map[string]any) { hbItem(m, "casks", 0)["sha256"] = "x" },
		"cask app": func(m map[string]any) {
			hbItem(m, "casks", 0)["apps"].([]any)[0].(map[string]any)["bundle_id"] = "org.mozilla.firefox"
		},
		"tap": func(m map[string]any) { hbItem(m, "taps", 0)["trusted"] = true },
		"issue": func(m map[string]any) {
			hbBlock(m)["issues"] = []any{map[string]any{"code": "unreadable", "path": "/x", "detail": "y"}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := homebrewFixture(t)
			mutate(m)
			err := validateMap(t, m)
			if err == nil || !strings.Contains(err.Error(), "additional properties not allowed") {
				t.Fatalf("unknown key accepted or wrong error: %v", err)
			}
		})
	}
}

func TestValidateHomebrewRejectsBadEnumsAndTypes(t *testing.T) {
	cases := map[string]func(m map[string]any){
		"collection_status":        func(m map[string]any) { hbBlock(m)["collection_status"] = "Complete" },
		"truncation_reason":        func(m map[string]any) { hbBlock(m)["truncation_reason"] = "byte_limit" },
		"prefix collection_status": func(m map[string]any) { hbItem(m, "prefixes", 0)["collection_status"] = "not_present" },
		"receipt_status":           func(m map[string]any) { hbItem(m, "formulae", 0)["receipt_status"] = "ok" },
		"formula_file_status":      func(m map[string]any) { hbItem(m, "formulae", 0)["formula_file_status"] = "unparseable" },
		"cask receipt_status":      func(m map[string]any) { hbItem(m, "casks", 0)["receipt_status"] = "missing_file" },
		"tap config_status":        func(m map[string]any) { hbItem(m, "taps", 0)["config_status"] = "symlink" },
		"installed_on_request":     func(m map[string]any) { hbItem(m, "formulae", 0)["installed_on_request"] = "yes" },
		"installed_at":             func(m map[string]any) { hbItem(m, "formulae", 0)["installed_at"] = "yesterday" },
		"runtime_dependencies":     func(m map[string]any) { hbItem(m, "formulae", 0)["runtime_dependencies"] = []any{1} },
		"owner_uid":                func(m map[string]any) { hbItem(m, "prefixes", 0)["owner_uid"] = -1 },
		"empty formula name":       func(m map[string]any) { hbItem(m, "formulae", 0)["name"] = "" },
		"missing formula version":  func(m map[string]any) { delete(hbItem(m, "formulae", 0), "version") },
		"truncated not bool":       func(m map[string]any) { hbBlock(m)["truncated"] = "false" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := homebrewFixture(t)
			mutate(m)
			if err := validateMap(t, m); err == nil {
				t.Fatal("invalid value accepted")
			}
		})
	}
}

func TestValidateHomebrewStatusRules(t *testing.T) {
	t.Run("failed must omit lists", func(t *testing.T) {
		m := homebrewFixture(t)
		hbBlock(m)["collection_status"] = "failed"
		if err := validateMap(t, m); err == nil {
			t.Fatal("failed block carrying lists accepted")
		}
	})
	t.Run("complete requires every list", func(t *testing.T) {
		m := homebrewFixture(t)
		delete(hbBlock(m), "casks")
		if err := validateMap(t, m); err == nil {
			t.Fatal("complete block without casks accepted")
		}
	})
	t.Run("complete cannot be truncated", func(t *testing.T) {
		m := homebrewFixture(t)
		hbBlock(m)["truncated"] = true
		hbBlock(m)["truncation_reason"] = "time_limit"
		if err := validateMap(t, m); err == nil {
			t.Fatal("truncated complete block accepted")
		}
	})
	// PAT-2032: a prefix that was not read in full, or a truncated or
	// prefix-bearing not_present block, must never be granted the absence
	// authority that complete and not_present carry.
	for _, prefixStatus := range []string{"partial", "failed"} {
		t.Run("complete with a "+prefixStatus+" prefix", func(t *testing.T) {
			m := homebrewFixture(t)
			hbItem(m, "prefixes", 0)["collection_status"] = prefixStatus
			if err := validateMap(t, m); err == nil {
				t.Fatalf("complete block with a %s prefix accepted", prefixStatus)
			}
		})
	}
	t.Run("complete needs at least one prefix row", func(t *testing.T) {
		m := homebrewFixture(t)
		hb := hbBlock(m)
		hb["prefixes"], hb["formulae"], hb["casks"], hb["taps"] = []any{}, []any{}, []any{}, []any{}
		if err := validateMap(t, m); err == nil {
			t.Fatal("complete block with no prefix rows accepted")
		}
	})
	notPresent := func(t *testing.T) map[string]any {
		m := homebrewFixture(t)
		hb := hbBlock(m)
		hb["collection_status"] = "not_present"
		hb["prefixes"], hb["formulae"], hb["casks"], hb["taps"] = []any{}, []any{}, []any{}, []any{}
		return m
	}
	t.Run("not_present baseline is valid", func(t *testing.T) {
		if err := validateMap(t, notPresent(t)); err != nil {
			t.Fatalf("empty not_present block rejected: %v", err)
		}
	})
	t.Run("not_present cannot be truncated", func(t *testing.T) {
		m := notPresent(t)
		hbBlock(m)["truncated"] = true
		hbBlock(m)["truncation_reason"] = "time_limit"
		if err := validateMap(t, m); err == nil {
			t.Fatal("truncated not_present block accepted")
		}
	})
	t.Run("not_present cannot carry prefix rows", func(t *testing.T) {
		m := notPresent(t)
		hbBlock(m)["prefixes"] = []any{map[string]any{"path": "/opt/homebrew", "owner": nil, "owner_uid": nil,
			"collection_status": "complete", "formulae": 0, "casks": 0, "taps": 0}}
		if err := validateMap(t, m); err == nil {
			t.Fatal("not_present block with a prefix row accepted")
		}
	})
	t.Run("partial may report the size_limit truncation", func(t *testing.T) {
		m := homebrewFixture(t)
		hb := hbBlock(m)
		hb["collection_status"] = "partial"
		hb["truncated"] = true
		hb["truncation_reason"] = "size_limit"
		hbItem(m, "prefixes", 0)["collection_status"] = "partial"
		if err := validateMap(t, m); err != nil {
			t.Fatalf("partial block truncated by the byte budget rejected: %v", err)
		}
	})
	t.Run("not_present lists must be empty", func(t *testing.T) {
		m := homebrewFixture(t)
		hbBlock(m)["collection_status"] = "not_present"
		if err := validateMap(t, m); err == nil {
			t.Fatal("not_present block with packages accepted")
		}
	})
}

func TestValidateHomebrewEnforcesSizeBounds(t *testing.T) {
	cases := []struct {
		key   string
		limit int
		item  func(i int) map[string]any
	}{
		{"formulae", homebrewMaxFormulae, func(i int) map[string]any {
			return map[string]any{"prefix": "/opt/homebrew", "name": fmt.Sprintf("f%d", i), "version": "1",
				"tap": nil, "installed_on_request": nil, "installed_as_dependency": nil, "installed_at": nil,
				"runtime_dependencies": nil, "homepage": nil, "source_url": nil, "opt_linked": nil,
				"receipt_status": "missing", "formula_file_status": "missing"}
		}},
		{"casks", homebrewMaxCasks, func(i int) map[string]any {
			return map[string]any{"prefix": "/opt/homebrew", "token": fmt.Sprintf("c%d", i), "version": nil,
				"versions_on_disk": []any{}, "tap": nil, "installed_on_request": nil, "installed_at": nil,
				"receipt_status": "missing", "apps": []any{}}
		}},
		{"taps", homebrewMaxTaps, func(i int) map[string]any {
			return map[string]any{"prefix": "/opt/homebrew", "name": fmt.Sprintf("u/t%d", i),
				"directory": fmt.Sprintf("u/homebrew-t%d", i), "remote_url": nil, "config_status": "missing"}
		}},
		{"issues", homebrewMaxIssues, func(i int) map[string]any {
			return map[string]any{"code": "unreadable", "path": fmt.Sprintf("/x/%d", i)}
		}},
	}
	for _, c := range cases {
		t.Run(c.key, func(t *testing.T) {
			build := func(n int) map[string]any {
				m := homebrewFixture(t)
				hbBlock(m)["collection_status"] = "partial"
				items := make([]any, n)
				for i := range items {
					items[i] = c.item(i)
				}
				hbBlock(m)[c.key] = items
				return m
			}
			if err := validateMap(t, build(c.limit)); err != nil {
				t.Fatalf("%d %s (at the bound) rejected: %v", c.limit, c.key, err)
			}
			if err := validateMap(t, build(c.limit+1)); err == nil || !strings.Contains(err.Error(), "contract maximum") {
				t.Fatalf("%d %s (over the bound) accepted or wrong error: %v", c.limit+1, c.key, err)
			}
		})
	}
}
