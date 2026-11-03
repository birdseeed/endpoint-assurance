package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestRingConfigChangesChangeTypeVocabularyMatchesMigration independently
// re-derives, by grepping real (non-test) Go source, every change_type
// value this repo's code actually writes to ring_config_changes, and
// asserts migrations/0107_ring_rollout_creation.sql's hand-copied
// ring_config_changes_change_type_check CHECK still admits every one of
// them. See that migration's own comment on the constraint for why this
// hand-copy exists and what would need to change alongside it.
func TestRingConfigChangesChangeTypeVocabularyMatchesMigration(t *testing.T) {
	migration, err := os.ReadFile("../../migrations/0110_mandatory_install_intents.sql")
	if err != nil {
		t.Fatal(err)
	}
	idx := strings.Index(string(migration), "ADD CONSTRAINT ring_config_changes_change_type_check")
	if idx < 0 {
		t.Fatal("migration no longer defines ring_config_changes_change_type_check")
	}
	block := string(migration)[idx:]
	end := strings.Index(block, "));")
	if end < 0 {
		t.Fatal("could not find end of the change_type_check CHECK block")
	}
	block = block[:end]
	re := regexp.MustCompile(`'([a-z_]+)'`)
	allowed := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(block, -1) {
		allowed[m[1]] = true
	}
	if len(allowed) == 0 {
		t.Fatal("parsed zero allowed change_type values from the migration")
	}

	written := []string{
		"config_updated", "device_override_set", "device_override_cleared",
		"rollout_paused", "rollout_resumed", "rollout_skipped",
		"rollout_advanced", "rollout_auto_paused", "rollout_completed",
		"rollout_superseded", "rollout_emergency_deploy",
		// rollout_created and mandatory_install_{evaluated,emergency,retried}
		// were retired with the signed catalogue (PAT-2246). The migration's
		// CHECK still admits them for historical rows.
	}
	goFiles, err := filepath.Glob("../../internal/*/*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(goFiles) == 0 {
		t.Fatal("found zero Go files under internal/*/*.go — path assumption broke")
	}
	for _, w := range written {
		found := false
		for _, f := range goFiles {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			// Some call sites pass the value as a Go string literal
			// ("rollout_advanced" bound as a query param); others embed it
			// directly as a SQL literal inside a raw `...` query string
			// ('config_updated'). Match either quoting style.
			if strings.Contains(string(b), `"`+w+`"`) || strings.Contains(string(b), `'`+w+`'`) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("change_type %q is no longer written anywhere in internal/*/*.go — if intentionally retired, remove it from this test's `written` list too", w)
		}
		if !allowed[w] {
			t.Errorf("change_type %q is written by Go code but NOT permitted by ring_config_changes_change_type_check in migrations/0110_mandatory_install_intents.sql — vocabulary has drifted", w)
		}
	}
}
