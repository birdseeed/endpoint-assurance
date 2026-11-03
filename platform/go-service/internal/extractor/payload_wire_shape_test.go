package extractor

// PAT-1960 wire-shape regression: device_class, installation_type and
// os_caption are top-level payload fields, not nested under "os" — a
// property of the machine, not of the operating system, matching where
// devices.device_class lives and matching the PAT-1959 Windows agent's
// actual emission shape.
//
// This pins the shape itself, no DB required: a payload that nests these
// fields under "os" (the shape this repo mistakenly read before this fix)
// must NOT populate them — that mismatch is exactly what would have left
// devices.device_class stuck at 'unknown' forever while every test on both
// sides still passed.

import (
	"encoding/json"
	"testing"
)

func TestPayload_DeviceClassFieldsAreTopLevelNotNestedUnderOS(t *testing.T) {
	// The exact shape PAT-1959 emits (per the sample in the PAT-1960 followup).
	topLevel := []byte(`{
		"schema_version": 3,
		"platform": "windows",
		"agent": "patched-collect-win",
		"agent_version": "0.15.0",
		"tenant_id": "22222222-2222-2222-2222-222222222222",
		"collected_at": "2026-09-21T10:00:00Z",
		"device_class": "domain_controller",
		"installation_type": "Server Core",
		"os_caption": "Microsoft Windows Server 2022 Datacenter",
		"os": { "name": "Windows", "version": "10.0.20348.2582", "build": "20348" }
	}`)

	var p payload
	if err := json.Unmarshal(topLevel, &p); err != nil {
		t.Fatalf("unmarshal top-level shape: %v", err)
	}
	if p.DeviceClass != "domain_controller" {
		t.Errorf("DeviceClass = %q, want %q", p.DeviceClass, "domain_controller")
	}
	if p.InstallationType != "Server Core" {
		t.Errorf("InstallationType = %q, want %q", p.InstallationType, "Server Core")
	}
	if p.OSCaption != "Microsoft Windows Server 2022 Datacenter" {
		t.Errorf("OSCaption = %q, want %q", p.OSCaption, "Microsoft Windows Server 2022 Datacenter")
	}
	// os itself is untouched — osPart carries only name/version/build.
	if p.OS.Name != "Windows" || p.OS.Version != "10.0.20348.2582" || p.OS.Build != "20348" {
		t.Errorf("OS = %+v, want the plain name/version/build triple", p.OS)
	}

	// The wrong (pre-fix) shape: same values, nested under "os" instead of
	// top level. osPart has no device_class/installation_type/caption
	// fields any more, so json.Unmarshal silently drops them — the
	// top-level fields must stay at their zero value, never populated from
	// the nested location.
	nestedUnderOS := []byte(`{
		"schema_version": 3,
		"platform": "windows",
		"agent": "patched-collect-win",
		"agent_version": "0.15.0",
		"tenant_id": "22222222-2222-2222-2222-222222222222",
		"collected_at": "2026-09-21T10:00:00Z",
		"os": {
			"name": "Windows", "version": "10.0.20348.2582", "build": "20348",
			"device_class": "domain_controller",
			"installation_type": "Server Core",
			"caption": "Microsoft Windows Server 2022 Datacenter"
		}
	}`)

	var wrong payload
	if err := json.Unmarshal(nestedUnderOS, &wrong); err != nil {
		t.Fatalf("unmarshal os-nested shape: %v", err)
	}
	if wrong.DeviceClass != "" {
		t.Errorf("DeviceClass from os-nested payload = %q, want empty (must not be read from os.device_class)", wrong.DeviceClass)
	}
	if wrong.InstallationType != "" {
		t.Errorf("InstallationType from os-nested payload = %q, want empty", wrong.InstallationType)
	}
	if wrong.OSCaption != "" {
		t.Errorf("OSCaption from os-nested payload = %q, want empty", wrong.OSCaption)
	}

	// resolveDeviceClass must therefore resolve the os-nested payload to
	// "unknown"/not-given — the exact no-op failure mode this test exists to
	// catch, made explicit rather than left implicit in the zero-value check
	// above.
	value, given := resolveDeviceClass(&wrong)
	if value != "unknown" || given {
		t.Errorf("resolveDeviceClass(os-nested payload) = (%q, %v), want (\"unknown\", false)", value, given)
	}

	// And the top-level shape resolves for real.
	value, given = resolveDeviceClass(&p)
	if value != "domain_controller" || !given {
		t.Errorf("resolveDeviceClass(top-level payload) = (%q, %v), want (\"domain_controller\", true)", value, given)
	}
}

// TestPayload_DeviceClassLiteralUnknownIsNotGiven pins the PAT-1959
// "unknown" contract: the agent's own literal "unknown" report (source
// absent, unreadable or contradictory — never a guess) must resolve exactly
// like an absent field, not like a real classification, so it can never
// downgrade an already-known device_class on a later check-in.
func TestPayload_DeviceClassLiteralUnknownIsNotGiven(t *testing.T) {
	p := &payload{DeviceClass: "unknown"}
	value, given := resolveDeviceClass(p)
	if value != "unknown" || given {
		t.Errorf("resolveDeviceClass(DeviceClass=\"unknown\") = (%q, %v), want (\"unknown\", false)", value, given)
	}
}
