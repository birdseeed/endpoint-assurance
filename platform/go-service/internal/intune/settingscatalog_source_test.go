package intune

// Tests the msgraph-backed fetch path. Unlike settingscatalog_test.go, this
// exercises real HTTP against an httptest server standing in for Graph
// (same newTestGraphClient helper compliance_test-style code uses via
// testhelpers_test.go) — it proves GraphDefinitionSource talks to the beta
// surface correctly, not the pure resolution logic, which is covered
// without any server at all in settingscatalog_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func settingDefinitionsFixtureHandler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /deviceManagement/configurationSettings", func(w http.ResponseWriter, r *http.Request) {
		items := []map[string]any{
			{
				"id":          bitlockerDef,
				"version":     bitlockerVersion,
				"displayName": "Require device encryption",
				"description": "Requires BitLocker device encryption for OS and fixed drives.",
				"options": []map[string]any{
					{"itemId": bitlockerOptEnabled, "displayName": "Require", "description": "Encryption is required."},
					{"itemId": bitlockerDef + "_0", "displayName": "Do not require", "description": "Encryption is not required."},
				},
			},
			{
				"id":          "device_vendor_msft_policy_config_no_options_setting",
				"version":     "3",
				"displayName": "Some simple setting",
				"description": "A non-choice setting with no options.",
			},
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": items})
	})
	return mux
}

// TestGraphDefinitionSource_FetchAll_DecodesDefinitionsAndOptions proves the
// beta-scoped fetch decodes both a choice-type definition (with options)
// and a simple definition (no options) into SettingDefinition/SettingOption.
func TestGraphDefinitionSource_FetchAll_DecodesDefinitionsAndOptions(t *testing.T) {
	client := newTestGraphClient(t, settingDefinitionsFixtureHandler(t))

	src := GraphDefinitionSource{}
	defs, err := src.FetchAll(context.Background(), client, "tenant-1")
	if err != nil {
		t.Fatalf("FetchAll: %v", err)
	}
	if len(defs) != 2 {
		t.Fatalf("got %d definitions, want 2", len(defs))
	}

	var bitlocker, simple *SettingDefinition
	for i := range defs {
		switch defs[i].ID {
		case bitlockerDef:
			bitlocker = &defs[i]
		case "device_vendor_msft_policy_config_no_options_setting":
			simple = &defs[i]
		}
	}
	if bitlocker == nil {
		t.Fatalf("bitlocker definition not found in %+v", defs)
	}
	if bitlocker.Version != bitlockerVersion || bitlocker.DisplayName != "Require device encryption" {
		t.Errorf("bitlocker definition decoded wrong: %+v", bitlocker)
	}
	if len(bitlocker.Options) != 2 {
		t.Fatalf("bitlocker options = %d, want 2: %+v", len(bitlocker.Options), bitlocker.Options)
	}
	if bitlocker.Options[0].ID != bitlockerOptEnabled || bitlocker.Options[0].DisplayName != "Require" {
		t.Errorf("bitlocker option[0] decoded wrong: %+v", bitlocker.Options[0])
	}

	if simple == nil {
		t.Fatalf("simple definition not found in %+v", defs)
	}
	if len(simple.Options) != 0 {
		t.Errorf("simple.Options = %+v, want empty (non-choice setting)", simple.Options)
	}
	if simple.Version != "3" {
		t.Errorf("simple.Version = %q, want %q", simple.Version, "3")
	}
}

// fakeWriter records what PutAll was called with, so
// TestRefreshDefinitions_FetchesThenWrites can assert the fetch result was
// actually handed to the writer.
type fakeWriter struct {
	got []SettingDefinition
}

func (w *fakeWriter) PutAll(_ context.Context, defs []SettingDefinition) error {
	w.got = defs
	return nil
}

// TestRefreshDefinitions_FetchesThenWrites proves RefreshDefinitions wires
// DefinitionSource.FetchAll straight into DefinitionWriter.PutAll — the
// slow-scheduled refresh path a future caller's cron would invoke.
func TestRefreshDefinitions_FetchesThenWrites(t *testing.T) {
	client := newTestGraphClient(t, settingDefinitionsFixtureHandler(t))
	writer := &fakeWriter{}

	if err := RefreshDefinitions(context.Background(), client, "tenant-1", GraphDefinitionSource{}, writer); err != nil {
		t.Fatalf("RefreshDefinitions: %v", err)
	}
	if len(writer.got) != 2 {
		t.Fatalf("writer got %d definitions, want 2", len(writer.got))
	}
}
