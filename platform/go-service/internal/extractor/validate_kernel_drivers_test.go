package extractor

import (
	"encoding/json"
	"strings"
	"testing"
)

// PAT-2263: kernel_drivers block validation. The accepted cases start from
// the three fixtures whose kernel_drivers block was copied verbatim from the
// Windows agent's pinned serialisation (updater
// windows/tests/Service.Tests/KernelDriverCollectorTests.cs, CompleteWire,
// PartialWire and UnavailableWire, serialised with the real
// InventoryPoster.JsonOpts), so agent and platform are held to the same bytes.

var kernelDriverFixtures = []string{
	"with-kernel-drivers-complete-windows.json",
	"with-kernel-drivers-partial-windows.json",
	"with-kernel-drivers-unavailable-windows.json",
}

func kdWith(t *testing.T, fixture string, mutate func(kd map[string]any)) []byte {
	t.Helper()
	return fixtureWith(t, fixture, func(m map[string]any) {
		mutate(m["kernel_drivers"].(map[string]any))
	})
}

func kdDriver(kd map[string]any, i int) map[string]any {
	return kd["drivers"].([]any)[i].(map[string]any)
}

func TestKernelDriversWindowsWireAccepted(t *testing.T) {
	for _, fx := range kernelDriverFixtures {
		t.Run(fx, func(t *testing.T) {
			data := readFixture(t, "valid", fx)
			if err := ValidatePayload(data); err != nil {
				t.Fatalf("rejected the Windows agent's own serialisation: %v", err)
			}
			var p payload
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatal(err)
			}
			if p.KernelDrivers == nil || p.KernelDrivers.SchemaVersion != 1 || p.KernelDrivers.Enforcement == nil {
				t.Fatalf("kernel_drivers not decoded: %+v", p.KernelDrivers)
			}
		})
	}
}

func TestKernelDriversWindowsWireDecodesFieldForField(t *testing.T) {
	var p payload
	if err := json.Unmarshal(readFixture(t, "valid", "with-kernel-drivers-complete-windows.json"), &p); err != nil {
		t.Fatal(err)
	}
	kd := p.KernelDrivers
	if kd.CollectionStatus != "complete" || len(kd.Errors) != 0 || len(kd.Drivers) != 3 {
		t.Fatalf("header = %q %v %d", kd.CollectionStatus, kd.Errors, len(kd.Drivers))
	}
	if e := kd.Enforcement; e.VulnerableDriverBlocklist != "enabled" || e.HVCI != "running" || e.SmartAppControl != "off" ||
		e.CodeIntegrityPolicy != "off" || e.BlocklistEnforced != "yes" {
		t.Fatalf("enforcement = %+v", e)
	}
	pe := kd.Drivers[2]
	if pe.Path == nil || *pe.Path != `C:\Windows\System32\drivers\pe.sys` || pe.ServiceName == nil || *pe.ServiceName != "pe" ||
		*pe.ServiceType != "kernel" || *pe.StartType != "system" || pe.Loaded == nil || !*pe.Loaded || pe.HashStatus != "hashed" ||
		*pe.SizeBytes != 712 || *pe.AuthenticodeSHA256 != "8812f0c849e0e9537b5060dd011057885eaf9047af11842840b97d8444eff841" ||
		*pe.AuthenticodeSHA1 != "49eb0bea78d9946ac607558732d912e74bb8dade" || *pe.Version != "10.0.22621.2506" ||
		strings.Join(pe.Sources, ",") != "drivers_directory,service,loaded" {
		t.Fatalf("pe = %+v", pe)
	}
	missing := kd.Drivers[0]
	if missing.HashStatus != "unhashed" || *missing.UnhashedReason != "file_missing" || missing.SHA256 != nil {
		t.Fatalf("missing = %+v", missing)
	}

	var partial payload
	if err := json.Unmarshal(readFixture(t, "valid", "with-kernel-drivers-partial-windows.json"), &partial); err != nil {
		t.Fatal(err)
	}
	remote := partial.KernelDrivers.Drivers[2]
	if remote.Path != nil || *remote.ServiceName != "remote" || *remote.UnhashedReason != "path_unsupported" || remote.Loaded != nil {
		t.Fatalf("pathless = %+v", remote)
	}
}

func TestKernelDriversAbsentAccepted(t *testing.T) {
	if err := ValidatePayload(readFixture(t, "valid", "full-v3-windows.json")); err != nil {
		t.Fatalf("a payload without the block was rejected: %v", err)
	}
}

func TestKernelDriversRejected(t *testing.T) {
	const complete = "with-kernel-drivers-complete-windows.json"
	const unavailable = "with-kernel-drivers-unavailable-windows.json"
	cases := []struct {
		name    string
		fixture string
		mutate  func(kd map[string]any)
		want    string
	}{
		{"schema version", complete, func(kd map[string]any) { kd["schema_version"] = 2.0 }, "schema_version"},
		{"status enum", complete, func(kd map[string]any) { kd["collection_status"] = "ok" }, "collection_status"},
		{"errors not codes", complete, func(kd map[string]any) { kd["errors"] = []any{"Boom!"} }, "errors[0]"},
		{"too many errors", complete, func(kd map[string]any) {
			e := make([]any, 17)
			for i := range e {
				e[i] = "x"
			}
			kd["errors"] = e
		}, "errors"},
		{"unknown key", complete, func(kd map[string]any) { kd["verdict"] = "vulnerable" }, "verdict"},
		{"enforcement missing", complete, func(kd map[string]any) { delete(kd, "enforcement") }, "enforcement"},
		{"enforcement enum", complete, func(kd map[string]any) {
			kd["enforcement"].(map[string]any)["blocklist_enforced"] = "probably"
		}, "blocklist_enforced"},
		{"enforcement field missing", complete, func(kd map[string]any) {
			delete(kd["enforcement"].(map[string]any), "hvci")
		}, "hvci"},
		{"drivers missing when complete", complete, func(kd map[string]any) { delete(kd, "drivers") }, "drivers"},
		{"drivers when unavailable", unavailable, func(kd map[string]any) { kd["drivers"] = []any{} }, "drivers"},
		{"too many drivers", complete, func(kd map[string]any) {
			row := kdDriver(kd, 1)
			rows := make([]any, 1501)
			for i := range rows {
				rows[i] = row
			}
			kd["drivers"] = rows
		}, "drivers"},
		{"uppercase hash", complete, func(kd map[string]any) {
			kdDriver(kd, 1)["sha256"] = strings.ToUpper(kdDriver(kd, 1)["sha256"].(string))
		}, "sha256"},
		{"short hash", complete, func(kd map[string]any) { kdDriver(kd, 1)["sha1"] = "abc" }, "sha1"},
		{"hashed without sha256", complete, func(kd map[string]any) { delete(kdDriver(kd, 1), "sha256") }, "sha256"},
		{"unhashed with a hash", complete, func(kd map[string]any) {
			kdDriver(kd, 0)["sha256"] = kdDriver(kd, 1)["sha256"]
		}, "sha256"},
		{"reason on a hashed row", complete, func(kd map[string]any) { kdDriver(kd, 1)["unhashed_reason"] = "read_failed" }, "unhashed_reason"},
		{"hash status enum", complete, func(kd map[string]any) { kdDriver(kd, 1)["hash_status"] = "partly" }, "hash_status"},
		{"no path or service", complete, func(kd map[string]any) { delete(kdDriver(kd, 1), "path") }, "path or a service_name"},
		{"relative path", complete, func(kd map[string]any) { kdDriver(kd, 1)["path"] = `drivers\x.sys` }, "path"},
		{"control character in path", complete, func(kd map[string]any) { kdDriver(kd, 1)["path"] = "C:\\x\u0007.sys" }, "path"},
		{"overlong path", complete, func(kd map[string]any) { kdDriver(kd, 1)["path"] = `C:\` + strings.Repeat("a", 520) }, "path"},
		{"source enum", complete, func(kd map[string]any) { kdDriver(kd, 1)["sources"] = []any{"guess"} }, "sources"},
		{"duplicate source", complete, func(kd map[string]any) {
			kdDriver(kd, 1)["sources"] = []any{"drivers_directory", "drivers_directory"}
		}, "sources"},
		{"no sources", complete, func(kd map[string]any) { kdDriver(kd, 1)["sources"] = []any{} }, "sources"},
		{"version shape", complete, func(kd map[string]any) { kdDriver(kd, 2)["version"] = "10.0" }, "version"},
		{"negative size", complete, func(kd map[string]any) { kdDriver(kd, 1)["size_bytes"] = -1.0 }, "size_bytes"},
		{"start type enum", complete, func(kd map[string]any) { kdDriver(kd, 2)["start_type"] = "sometimes" }, "start_type"},
		{"loaded not bool", complete, func(kd map[string]any) { kdDriver(kd, 2)["loaded"] = "yes" }, "loaded"},
		{"unknown driver key", complete, func(kd map[string]any) { kdDriver(kd, 1)["file_name"] = "flat.sys" }, "file_name"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidatePayload(kdWith(t, c.fixture, c.mutate))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want mention of %q", err, c.want)
			}
		})
	}
}

func TestKernelDriversAcceptsNewDiagnosticCodes(t *testing.T) {
	data := kdWith(t, "with-kernel-drivers-partial-windows.json", func(kd map[string]any) {
		kd["errors"] = append(kd["errors"].([]any), "a_future_error")
		kdDriver(kd, 0)["unhashed_reason"] = "a_future_reason"
	})
	if err := ValidatePayload(data); err != nil {
		t.Fatalf("a well-formed new code cost the device its inventory: %v", err)
	}
}

func TestKernelDriversRejectedNotEchoingValues(t *testing.T) {
	const secret = "C:\\Users\\alice\\secret-project\\x.sys\u0007"
	err := ValidatePayload(kdWith(t, "with-kernel-drivers-complete-windows.json", func(kd map[string]any) {
		kdDriver(kd, 1)["path"] = secret
	}))
	if err == nil || strings.Contains(err.Error(), "alice") {
		t.Fatalf("err = %v", err)
	}
}

func TestKernelDriversCaseVariantAndDuplicateKeysRejected(t *testing.T) {
	base := string(readFixture(t, "valid", "with-kernel-drivers-complete-windows.json"))
	variant := strings.Replace(base, `"kernel_drivers":`, `"Kernel_Drivers":`, 1)
	if err := ValidatePayload([]byte(variant)); err == nil {
		t.Fatal("a case-variant block key was accepted")
	}
	inner := strings.Replace(base, `"blocklist_enforced":"yes"`, `"Blocklist_Enforced":"yes"`, 1)
	if err := ValidatePayload([]byte(inner)); err == nil {
		t.Fatal("a case-variant enforcement key was accepted")
	}
	dup := strings.Replace(base, `"kernel_drivers": {`, `"kernel_drivers": {"schema_version":1,"collection_status":"unavailable","errors":[],"enforcement":{"vulnerable_driver_blocklist":"enabled","hvci":"running","smart_app_control":"off","code_integrity_policy":"off","blocklist_enforced":"yes"}}, "kernel_drivers": {`, 1)
	if err := ValidatePayload([]byte(dup)); err == nil {
		t.Fatal("a duplicate kernel_drivers block was accepted")
	}
}
