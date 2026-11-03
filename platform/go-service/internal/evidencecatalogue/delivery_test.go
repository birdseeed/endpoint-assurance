package evidencecatalogue

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func deliveryTestNow() time.Time { return time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC) }

func TestWindowsEmbeddedDeliveryIsReviewedEmptyPublication(t *testing.T) {
	d, err := EmbeddedWindowsDelivery()
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Validate(deliveryTestNow()); err != nil {
		t.Fatal(err)
	}
	if d.Targets == nil || len(d.Targets) != 0 || d.ContentHash != WindowsContentHash || d.DeliveryVersion != 1 {
		t.Fatalf("unexpected publication: %+v", d)
	}
	raw, _ := json.Marshal(d)
	want := `{"catalogue_version":"2026.09.20.1","content_hash":"a3ea6bba02d8766c4f8432a04caf26154929651cb4722909b7f04df44922df5c","delivery_version":1,"expires_at":"2026-12-19T00:00:00Z","published_at":"2026-09-20T00:00:00Z","schema_version":1,"targets":[]}`
	if string(raw) != want {
		t.Fatalf("canonical delivery changed: %s", raw)
	}
}

func TestWindowsDerivationRequiresWholeCatalogueProvenanceAndExplicitPaths(t *testing.T) {
	for _, mutate := range []func(*Catalogue){
		func(c *Catalogue) { c.Entries[0].Sources = nil },
		func(c *Catalogue) { c.Entries[0].Review.Reference = "" },
		func(c *Catalogue) { c.CatalogueVersion = "changed.1" },
		func(c *Catalogue) { c.Entries = append(c.Entries, validWindowsEntry("winget_id", "Example.App")) },
	} {
		c, _ := LoadEmbedded()
		mutate(c)
		if _, err := deriveWindowsDelivery(c); err == nil {
			t.Fatal("unreviewed or unprojectable catalogue accepted")
		}
	}
}

func TestWindowsDeliveryRejectsInvalidMetadataAndTargets(t *testing.T) {
	for name, mutate := range map[string]func(*WindowsDelivery){
		"schema":    func(d *WindowsDelivery) { d.SchemaVersion++ },
		"version":   func(d *WindowsDelivery) { d.DeliveryVersion = 0 },
		"hash":      func(d *WindowsDelivery) { d.ContentHash = strings.Repeat("0", 64) },
		"nil array": func(d *WindowsDelivery) { d.Targets = nil },
		"expired":   func(d *WindowsDelivery) { d.ExpiresAt = "2026-09-21T00:00:00Z" },
		"future":    func(d *WindowsDelivery) { d.PublishedAt = "2026-09-22T00:00:00Z" },
		"unbounded": func(d *WindowsDelivery) { d.ExpiresAt = "2027-12-19T00:00:00Z" },
		"oversize":  func(d *WindowsDelivery) { d.Targets = make([]WindowsTarget, 25) },
	} {
		t.Run(name, func(t *testing.T) {
			d, _ := EmbeddedWindowsDelivery()
			mutate(d)
			if d.Validate(deliveryTestNow()) == nil {
				t.Fatal("invalid delivery accepted")
			}
		})
	}
	d, _ := EmbeddedWindowsDelivery()
	published, _ := time.Parse(time.RFC3339, d.PublishedAt)
	expires, _ := time.Parse(time.RFC3339, d.ExpiresAt)
	if d.Validate(published) != nil || d.Validate(expires.Add(-time.Second)) != nil || d.Validate(expires) == nil || d.Validate(published.Add(-time.Second)) == nil {
		t.Fatal("validity boundary mismatch")
	}
}

func validDeliveryTarget() WindowsTarget {
	return WindowsTarget{AuthenticodeSubject: "Example Corporation", IdentityKind: "windows_msi_product_code", IdentityValue: "{12345678-1234-1234-1234-123456789ABC}", InstallPath: `C:\Program Files\Example`, ExecutablePath: `C:\Program Files\Example\App.exe`}
}

func TestWindowsDeliveryProductCodeRequiresCanonicalGUID(t *testing.T) {
	for _, value := range []string{
		"12345678-1234-1234-1234-123456789ABC",
		"{12345678-1234-1234-1234-123456789abc}",
		"{12345678123412341234123456789ABC}",
		"{12345678-1234-1234-1234-123456789ABG}",
		"{12345678-1234-1234-1234-123456789AB}",
		" {12345678-1234-1234-1234-123456789ABC}",
		"{12345678-1234-1234-1234-123456789ABC}\n",
	} {
		t.Run(value, func(t *testing.T) {
			target := validDeliveryTarget()
			target.IdentityValue = value
			if target.Validate() == nil {
				t.Fatalf("noncanonical ProductCode accepted: %q", value)
			}
		})
	}
	if err := validDeliveryTarget().Validate(); err != nil {
		t.Fatalf("canonical uppercase braced ProductCode rejected: %v", err)
	}
}

func TestWindowsDeliveryRejectsAlternatePathForms(t *testing.T) {
	for _, path := range []string{
		`C:/Program Files/Example/App.exe`,
		`C:\Program Files\Example/App.exe`,
		`\\server\share\Example\App.exe`,
		`\\?\C:\Program Files\Example\App.exe`,
		`\\.\C:\Program Files\Example\App.exe`,
		`\??\C:\Program Files\Example\App.exe`,
		`C:\Program Files\Example\..\App.exe`,
		`C:\Program Files\Example\.\App.exe`,
		`C:\Program Files\Example\\App.exe`,
		`C:Program Files\Example\App.exe`,
	} {
		t.Run(path, func(t *testing.T) {
			if validPath("windows", path) || exactWindowsDeliveryPath(path) {
				t.Fatalf("alternate path form accepted: %q", path)
			}
			target := validDeliveryTarget()
			target.ExecutablePath = path
			if target.Validate() == nil {
				t.Fatalf("unsafe executable accepted: %q", path)
			}
			target = validDeliveryTarget()
			target.InstallPath = path
			if target.Validate() == nil {
				t.Fatalf("unsafe installation path accepted: %q", path)
			}
		})
	}
}

func TestWindowsTargetV1RequiresAuthoritativeIdentitySignerAndExactPaths(t *testing.T) {
	if err := validDeliveryTarget().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*WindowsTarget){
		"upgrade code":     func(v *WindowsTarget) { v.IdentityKind = "msi_upgrade_code" },
		"winget":           func(v *WindowsTarget) { v.IdentityKind = "winget_id"; v.IdentityValue = "Example.App" },
		"name":             func(v *WindowsTarget) { v.IdentityValue = "App" },
		"lowercase GUID":   func(v *WindowsTarget) { v.IdentityValue = strings.ToLower(v.IdentityValue) },
		"signer":           func(v *WindowsTarget) { v.AuthenticodeSubject = "" },
		"relative":         func(v *WindowsTarget) { v.ExecutablePath = "App.exe" },
		"outside install":  func(v *WindowsTarget) { v.ExecutablePath = `C:\Program Files\ExampleSpoof\App.exe` },
		"traversal":        func(v *WindowsTarget) { v.ExecutablePath = v.InstallPath + `\..\App.exe` },
		"wildcard":         func(v *WindowsTarget) { v.ExecutablePath = v.InstallPath + `\*.exe` },
		"alternate stream": func(v *WindowsTarget) { v.ExecutablePath = v.InstallPath + `\app:payload.exe` },
		"trailing dot":     func(v *WindowsTarget) { v.InstallPath += "." },
		"environment":      func(v *WindowsTarget) { v.InstallPath = `%ProgramFiles%\Example` },
	} {
		t.Run(name, func(t *testing.T) {
			v := validDeliveryTarget()
			mutate(&v)
			if v.Validate() == nil {
				t.Fatal("unsafe target accepted")
			}
		})
	}
	d, _ := EmbeddedWindowsDelivery()
	d.Targets = []WindowsTarget{validDeliveryTarget(), validDeliveryTarget()}
	d.ContentHash, _ = d.CanonicalContentHash()
	if d.Validate(deliveryTestNow()) == nil {
		t.Fatal("duplicate product identity accepted")
	}
}

func TestWindowsDeliveryVersionsRequireForwardPublicationIncludingRollback(t *testing.T) {
	head, _ := EmbeddedWindowsDelivery()
	if insert, err := compareWindowsDeliveryHead(head, nil, false); err != nil || !insert {
		t.Fatal("first publication rejected", err)
	}
	if insert, err := compareWindowsDeliveryHead(head, head, true); err != nil || insert {
		t.Fatal("matching publication not stable", err)
	}
	candidate := *head
	candidate.DeliveryVersion = 2
	if insert, err := compareWindowsDeliveryHead(&candidate, head, true); err != nil || !insert {
		t.Fatal("higher version reusing content hash rejected", err)
	}
	if _, err := compareWindowsDeliveryHead(head, &candidate, true); err == nil {
		t.Fatal("binary downgrade accepted")
	}
	candidate.DeliveryVersion = 3
	if _, err := compareWindowsDeliveryHead(&candidate, head, true); err == nil {
		t.Fatal("version jump accepted")
	}
	if _, err := compareWindowsDeliveryHead(&candidate, nil, false); err == nil {
		t.Fatal("non-v1 bootstrap accepted")
	}
	candidate = *head
	candidate.ExpiresAt = "2026-12-18T00:00:00Z"
	if _, err := compareWindowsDeliveryHead(&candidate, head, true); err == nil {
		t.Fatal("same-version freshness change accepted")
	}
	candidate = *head
	candidate.CatalogueVersion = "older.1"
	candidate.ContentHash, _ = candidate.CanonicalContentHash()
	candidate.DeliveryVersion = 2
	if insert, err := compareWindowsDeliveryHead(&candidate, head, true); err != nil || !insert {
		t.Fatal("intentional higher-version content rollback rejected", err)
	}
}
