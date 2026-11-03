package extractor

import (
	"encoding/json"
	"strings"
	"testing"
)

// PAT-2262: firmware block validation. The accepted cases start from the
// three fixtures whose firmware block was copied verbatim from the Windows
// agent's pinned serialisation (updater
// windows/tests/Service.Tests/DeviceCollectorFirmwareTests.cs, serialised
// with the real InventoryPoster.JsonOpts), so agent and platform are held to
// the same bytes, the \u002B escape System.Text.Json writes for '+' included.

var firmwareFixtures = []string{
	"with-firmware-complete-windows.json",
	"with-firmware-partial-windows.json",
	"with-firmware-unavailable-windows.json",
}

func firmwareBlock(t *testing.T, fixture string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readFixture(t, "valid", fixture), &m); err != nil {
		t.Fatal(err)
	}
	return m["firmware"].(map[string]any)
}

// fwWith returns the complete fixture with its firmware block mutated.
func fwWith(t *testing.T, fixture string, mutate func(fw map[string]any)) []byte {
	t.Helper()
	return fixtureWith(t, fixture, func(m map[string]any) {
		mutate(m["firmware"].(map[string]any))
	})
}

func TestFirmwareWindowsWireAccepted(t *testing.T) {
	for _, fx := range firmwareFixtures {
		t.Run(fx, func(t *testing.T) {
			data := readFixture(t, "valid", fx)
			if err := ValidatePayload(data); err != nil {
				t.Fatalf("rejected the Windows agent's own serialisation: %v", err)
			}
			var p payload
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatal(err)
			}
			if p.Firmware == nil || p.Firmware.SchemaVersion != 1 {
				t.Fatalf("firmware not decoded: %+v", p.Firmware)
			}
		})
	}
}

func TestFirmwareWindowsWireDecodesFieldForField(t *testing.T) {
	var p payload
	if err := json.Unmarshal(readFixture(t, "valid", "with-firmware-complete-windows.json"), &p); err != nil {
		t.Fatal(err)
	}
	fw := p.Firmware
	if fw.CollectionStatus != "complete" || len(fw.Errors) != 0 {
		t.Fatalf("status/errors = %q %v", fw.CollectionStatus, fw.Errors)
	}
	if fw.BIOS == nil || fw.System == nil || fw.Baseboard == nil {
		t.Fatalf("sections missing: %+v", fw)
	}
	for name, got := range map[string]*string{
		"bios.manufacturer":      fw.BIOS.Manufacturer,
		"bios.version":           fw.BIOS.Version,
		"bios.smbios_version":    fw.BIOS.SMBIOSVersion,
		"bios.release_date":      fw.BIOS.ReleaseDate,
		"system.manufacturer":    fw.System.Manufacturer,
		"system.model":           fw.System.Model,
		"baseboard.manufacturer": fw.Baseboard.Manufacturer,
		"baseboard.product":      fw.Baseboard.Product,
	} {
		if got == nil || *got == "" {
			t.Errorf("%s not decoded", name)
		}
	}
	if *fw.BIOS.Version != "N3HET82W (1.54 )" || *fw.BIOS.ReleaseDate != "2023-05-12" || *fw.BIOS.SMBIOSVersion != "3.2" {
		t.Errorf("bios = %+v", fw.BIOS)
	}

	var partial payload
	if err := json.Unmarshal(readFixture(t, "valid", "with-firmware-partial-windows.json"), &partial); err != nil {
		t.Fatal(err)
	}
	b := partial.Firmware.BIOS
	if b.ReleaseDate != nil || b.ReleaseDateRaw == nil || *b.ReleaseDateRaw != "20230230000000.000000+000" {
		t.Errorf("partial bios release date = %v / %v", b.ReleaseDate, b.ReleaseDateRaw)
	}
	if partial.Firmware.Baseboard.CollectionStatus != "unavailable" || partial.Firmware.Baseboard.Product != nil {
		t.Errorf("partial baseboard = %+v", partial.Firmware.Baseboard)
	}
}

func TestFirmwareAbsentAccepted(t *testing.T) {
	data := readFixture(t, "valid", "full-v3-windows.json")
	if err := ValidatePayload(data); err != nil {
		t.Fatal(err)
	}
	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	if p.Firmware != nil {
		t.Fatal("absent block decoded as present")
	}
}

func TestFirmwareOtherAcceptedShapes(t *testing.T) {
	const complete = "with-firmware-complete-windows.json"
	for _, tc := range []struct {
		name   string
		mutate func(fw map[string]any)
	}{
		{"explicit nulls for absent values", func(fw map[string]any) {
			fw["baseboard"].(map[string]any)["product"] = nil
			fw["bios"].(map[string]any)["release_date_raw"] = nil
		}},
		{"value at the 128-character bound", func(fw map[string]any) {
			fw["system"].(map[string]any)["model"] = strings.Repeat("é", 128)
		}},
		{"an error code this platform does not know yet", func(fw map[string]any) {
			fw["collection_status"] = "partial"
			fw["errors"] = []any{"bios_some_future_code"}
		}},
		{"section with no values", func(fw map[string]any) {
			fw["baseboard"] = map[string]any{"collection_status": "complete"}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidatePayload(fwWith(t, complete, tc.mutate)); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

func TestFirmwareRejected(t *testing.T) {
	const complete = "with-firmware-complete-windows.json"
	const unavailable = "with-firmware-unavailable-windows.json"
	for _, tc := range []struct {
		name    string
		fixture string
		mutate  func(fw map[string]any)
		want    string
	}{
		{"unknown top-level key", complete, func(fw map[string]any) { fw["verdict"] = "current" }, "firmware.verdict: additional properties not allowed"},
		{"schema_version missing", complete, func(fw map[string]any) { delete(fw, "schema_version") }, "firmware.schema_version"},
		{"schema_version 2", complete, func(fw map[string]any) { fw["schema_version"] = 2 }, "firmware.schema_version"},
		{"schema_version not an integer", complete, func(fw map[string]any) { fw["schema_version"] = 1.5 }, "firmware.schema_version"},
		{"collection_status missing", complete, func(fw map[string]any) { delete(fw, "collection_status") }, "firmware.collection_status"},
		{"collection_status failed (not this block's vocabulary)", complete, func(fw map[string]any) { fw["collection_status"] = "failed" }, "firmware.collection_status"},
		{"errors missing", complete, func(fw map[string]any) { delete(fw, "errors") }, "firmware.errors"},
		{"errors not an array", complete, func(fw map[string]any) { fw["errors"] = "bios_query_failed" }, "firmware.errors"},
		{"errors over 16", complete, func(fw map[string]any) {
			var e []any
			for i := 0; i < 17; i++ {
				e = append(e, "bios_query_failed")
			}
			fw["errors"] = e
		}, "firmware.errors"},
		{"error code with free text", complete, func(fw map[string]any) {
			fw["errors"] = []any{"WMI threw: Access denied at C:\\Windows"}
		}, "firmware.errors[0]"},
		{"error code too long", complete, func(fw map[string]any) {
			fw["errors"] = []any{strings.Repeat("a", 65)}
		}, "firmware.errors[0]"},
		{"error code not a string", complete, func(fw map[string]any) { fw["errors"] = []any{7} }, "firmware.errors[0]"},
		{"complete without a section", complete, func(fw map[string]any) { delete(fw, "system") }, "firmware.system: required"},
		{"unavailable with a section", unavailable, func(fw map[string]any) {
			fw["bios"] = map[string]any{"collection_status": "complete", "version": "1.0"}
		}, "firmware.bios: not allowed when collection_status is \"unavailable\""},
		{"section not an object", complete, func(fw map[string]any) { fw["bios"] = "LENOVO" }, "firmware.bios: must be an object"},
		{"section unknown key", complete, func(fw map[string]any) {
			fw["bios"].(map[string]any)["is_outdated"] = true
		}, "firmware.bios.is_outdated: additional properties not allowed"},
		{"section status missing", complete, func(fw map[string]any) {
			delete(fw["system"].(map[string]any), "collection_status")
		}, "firmware.system.collection_status"},
		{"section status bad", complete, func(fw map[string]any) {
			fw["system"].(map[string]any)["collection_status"] = "ok"
		}, "firmware.system.collection_status"},
		{"unavailable section with values", complete, func(fw map[string]any) {
			fw["collection_status"] = "partial"
			fw["baseboard"].(map[string]any)["collection_status"] = "unavailable"
		}, "firmware.baseboard.manufacturer: not allowed when"},
		{"value over 128 characters", complete, func(fw map[string]any) {
			fw["system"].(map[string]any)["model"] = strings.Repeat("A", 129)
		}, "firmware.system.model"},
		{"value with a control character", complete, func(fw map[string]any) {
			fw["bios"].(map[string]any)["manufacturer"] = "LEN\u0000OVO"
		}, "firmware.bios.manufacturer"},
		{"value with a newline", complete, func(fw map[string]any) {
			fw["bios"].(map[string]any)["version"] = "1.0\nforged: yes"
		}, "firmware.bios.version"},
		{"value empty", complete, func(fw map[string]any) {
			fw["baseboard"].(map[string]any)["product"] = "  "
		}, "firmware.baseboard.product"},
		{"value not a string", complete, func(fw map[string]any) {
			fw["baseboard"].(map[string]any)["product"] = 42
		}, "firmware.baseboard.product"},
		{"release_date not a real date", complete, func(fw map[string]any) {
			fw["bios"].(map[string]any)["release_date"] = "2023-02-30"
		}, "firmware.bios.release_date"},
		{"release_date not ISO", complete, func(fw map[string]any) {
			fw["bios"].(map[string]any)["release_date"] = "05/12/2023"
		}, "firmware.bios.release_date"},
		{"release_date with a time", complete, func(fw map[string]any) {
			fw["bios"].(map[string]any)["release_date"] = "2023-05-12T00:00:00Z"
		}, "firmware.bios.release_date"},
		{"release_date_raw over 64", complete, func(fw map[string]any) {
			fw["bios"].(map[string]any)["release_date_raw"] = strings.Repeat("9", 65)
		}, "firmware.bios.release_date_raw"},
		{"smbios_version not dotted", complete, func(fw map[string]any) {
			fw["bios"].(map[string]any)["smbios_version"] = "three"
		}, "firmware.bios.smbios_version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidatePayload(fwWith(t, tc.fixture, tc.mutate))
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestFirmwareRejectedNotEchoingValues(t *testing.T) {
	secret := "SECRET-VALUE-" + strings.Repeat("x", 200)
	err := ValidatePayload(fwWith(t, "with-firmware-complete-windows.json", func(fw map[string]any) {
		fw["system"].(map[string]any)["model"] = secret
	}))
	if err == nil || strings.Contains(err.Error(), "SECRET-VALUE") {
		t.Fatalf("error = %v", err)
	}
}

func TestFirmwareCaseVariantAndDuplicateKeysRejected(t *testing.T) {
	complete := string(readFixture(t, "valid", "with-firmware-complete-windows.json"))
	for name, body := range map[string]string{
		"case-variant block key":   strings.Replace(complete, `"firmware":`, `"FIRMWARE":`, 1),
		"case-variant nested key":  strings.Replace(complete, `"release_date":`, `"Release_Date":`, 1),
		"case-variant section key": strings.Replace(complete, `"bios":`, `"BIOS":`, 1),
		"duplicate block": strings.Replace(complete, `"firmware":`,
			`"firmware": {"schema_version":1,"collection_status":"unavailable","errors":["bios_query_failed"]}, "firmware":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidatePayload([]byte(body)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
