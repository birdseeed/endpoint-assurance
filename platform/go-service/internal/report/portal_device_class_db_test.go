package report

// PAT-2324: FetchPortalDevices and FetchPortalDeviceSummary both carry
// device_class and os_caption, read from the same fetchTenantDevices query
// and derived by the same derivePortalDeviceClass, so the roster and the
// device page cannot disagree. Skipped unless TEST_DATABASE_URL points at a
// scratch database; reuses pat1762Pool's isolated schema.

import (
	"context"
	"testing"
)

func TestFetchPortalDevices_DeviceClassAndCaption_RosterAgreesWithSummary(t *testing.T) {
	pool := pat1762Pool(t)
	ctx := context.Background()
	tenantID := insertPAT1762Tenant(t, pool)

	type seed struct {
		hostname string
		os       string
		class    *string // nil leaves the column at its 'unknown' default
		caption  *string // nil stores SQL NULL
	}
	seeds := []seed{
		{"a-win-server", "Windows", strPtr("server"), strPtr("Microsoft Windows Server 2022 Standard")},
		{"b-win-workstation", "Windows", strPtr("workstation"), strPtr("Microsoft Windows 11 Enterprise")},
		{"c-mac-unknown", "macOS", nil, nil},
		{"d-win-unknown", "Windows", nil, nil},
		{"e-win-domain-controller", "Windows", strPtr("domain_controller"), strPtr("Microsoft Windows Server 2019 Standard")},
	}
	ids := map[string]string{}
	for _, s := range seeds {
		var id string
		if err := pool.QueryRow(ctx, `
			INSERT INTO devices (tenant_id, hostname, os, os_version, device_class, os_caption)
			VALUES ($1::uuid, $2, $3, '1.0', COALESCE($4, 'unknown'), $5)
			RETURNING id::text
		`, tenantID, s.hostname, s.os, s.class, s.caption).Scan(&id); err != nil {
			t.Fatalf("insert %s: %v", s.hostname, err)
		}
		ids[s.hostname] = id
	}

	res, err := FetchPortalDevices(ctx, pool, tenantID, 50, 0)
	if err != nil {
		t.Fatalf("FetchPortalDevices: %v", err)
	}
	if len(res.Devices) != len(seeds) {
		t.Fatalf("got %d roster rows, want %d", len(res.Devices), len(seeds))
	}
	byID := map[string]PortalDeviceRow{}
	for _, d := range res.Devices {
		byID[d.ID] = d
	}

	want := map[string]struct {
		class   string
		caption *string
	}{
		"a-win-server":            {"server", strPtr("Microsoft Windows Server 2022 Standard")},
		"b-win-workstation":       {"workstation", strPtr("Microsoft Windows 11 Enterprise")},
		"c-mac-unknown":           {"workstation", nil},
		"d-win-unknown":           {"unknown", nil},
		"e-win-domain-controller": {"server", strPtr("Microsoft Windows Server 2019 Standard")},
	}
	for host, w := range want {
		row := byID[ids[host]]
		if row.DeviceClass != w.class {
			t.Errorf("roster %s device_class = %q, want %q", host, row.DeviceClass, w.class)
		}
		if derefOrNil(row.OSCaption) != derefOrNil(w.caption) {
			t.Errorf("roster %s os_caption = %s, want %s", host, derefOrNil(row.OSCaption), derefOrNil(w.caption))
		}

		sum, err := FetchPortalDeviceSummary(ctx, pool, tenantID, ids[host])
		if err != nil {
			t.Fatalf("FetchPortalDeviceSummary %s: %v", host, err)
		}
		if sum.DeviceClass != row.DeviceClass {
			t.Errorf("%s: summary device_class = %q, roster says %q", host, sum.DeviceClass, row.DeviceClass)
		}
		if derefOrNil(sum.OSCaption) != derefOrNil(row.OSCaption) {
			t.Errorf("%s: summary os_caption = %s, roster says %s", host, derefOrNil(sum.OSCaption), derefOrNil(row.OSCaption))
		}
	}
}
