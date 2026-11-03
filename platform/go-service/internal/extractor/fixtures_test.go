package extractor

// TestPayloadFixtureContract is the executable contract for the POST /v1/inventory
// payload seam. It walks three fixture directories and asserts:
//
//   - valid/   — every fixture passes schema validation AND unmarshals cleanly
//     into the payload struct with a supported schema_version.
//   - edge/    — same as valid/, but for corner cases (empty arrays, Unicode, etc.)
//   - invalid/ — every fixture must fail schema validation (each violates exactly
//     one constraint so the failure is legible).
//
// Fixtures are discovered by directory walk; drop a new .json file and it is
// automatically tested. See go-service/testdata/payload-fixtures/README.md for
// the contract governance rules.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// fixturesRoot is the root of the payload fixture suite relative to the
// internal/extractor package directory (where `go test` sets the working dir).
const fixturesRoot = "../../testdata/payload-fixtures"

// TestPayloadFixtureContract exercises the full fixture suite.
func TestPayloadFixtureContract(t *testing.T) {
	// valid/ and edge/ — must pass schema validation + unmarshal cleanly.
	for _, dir := range []string{"valid", "edge"} {
		entries, err := os.ReadDir(filepath.Join(fixturesRoot, dir))
		if err != nil {
			t.Fatalf("read fixture dir %q: %v", dir, err)
		}
		found := 0
		for _, e := range entries {
			if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
				continue
			}
			found++
			name := dir + "/" + e.Name()
			t.Run(name, func(t *testing.T) {
				data := readFixture(t, dir, e.Name())

				// 1. Schema validation — delegates to ValidatePayload in validate.go.
				if err := ValidatePayload(data); err != nil {
					t.Fatalf("schema validation failed: %v", err)
				}

				// 2. Struct unmarshal — mirrors what processRow does before
				// hitting the DB.
				var p payload
				if err := json.Unmarshal(data, &p); err != nil {
					t.Fatalf("json.Unmarshal failed: %v", err)
				}

				// 3. Schema-version range check — same guard processRow applies
				// before any DB write.
				if p.SchemaVersion < minSupportedSchemaVersion || p.SchemaVersion > maxSupportedSchemaVersion {
					t.Errorf("schema_version %d is outside extractor's supported range [%d, %d]",
						p.SchemaVersion, minSupportedSchemaVersion, maxSupportedSchemaVersion)
				}
			})
		}
		if found == 0 {
			t.Errorf("no .json fixtures found in %s/", dir)
		}
	}

	// invalid/ — every fixture must fail schema validation.
	invalidDir := "invalid"
	entries, err := os.ReadDir(filepath.Join(fixturesRoot, invalidDir))
	if err != nil {
		t.Fatalf("read fixture dir %q: %v", invalidDir, err)
	}
	found := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		found++
		name := invalidDir + "/" + e.Name()
		t.Run(name, func(t *testing.T) {
			data := readFixture(t, invalidDir, e.Name())
			if err := ValidatePayload(data); err == nil {
				t.Error("expected schema validation to fail but it passed — " +
					"either the fixture is not actually invalid or the validator needs updating")
			}
		})
	}
	if found == 0 {
		t.Errorf("no .json fixtures found in %s/", invalidDir)
	}
}

// readFixture reads a fixture file under fixturesRoot/<dir>/<name>.
func readFixture(t *testing.T, dir, name string) []byte {
	t.Helper()
	path := filepath.Join(fixturesRoot, dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s/%s: %v", dir, name, err)
	}
	return data
}
