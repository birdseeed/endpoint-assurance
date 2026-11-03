package report

import "testing"

// TestHardwareIssueSummary locks the PAT-686 report-narration wording and the
// priority order (battery condition, battery capacity, storage, SMART, then
// the used_pct fallback) — must match HardwareFlag/DeviceNeedsAttention so a
// device the report calls "flagged" always gets a matching reason string.
func TestHardwareIssueSummary(t *testing.T) {
	pct := func(v int) *int { return &v }
	i64 := func(v int64) *int64 { return &v }
	str := func(v string) *string { return &v }

	tests := []struct {
		name string
		row  TenantDeviceRow
		want string
	}{
		{
			name: "no hardware data",
			row:  TenantDeviceRow{HasHardware: false},
			want: "",
		},
		{
			name: "normal device — no reason",
			row: TenantDeviceRow{
				HasHardware: true, BatteryMaxCapacityPct: pct(95), BatteryCondition: str("Normal"),
				SMARTStatus: str("Verified"), StorageFreeBytes: i64(200 << 30),
			},
			want: "",
		},
		{
			name: "battery below threshold with cycle count",
			row: TenantDeviceRow{
				HasHardware: true, BatteryMaxCapacityPct: pct(62), BatteryCycleCount: pct(412),
				SMARTStatus: str("Verified"), StorageFreeBytes: i64(200 << 30),
			},
			want: "battery 62% health (412 cycles): consider replacement",
		},
		{
			name: "battery below threshold, no cycle count",
			row: TenantDeviceRow{
				HasHardware: true, BatteryMaxCapacityPct: pct(58),
				SMARTStatus: str("Verified"), StorageFreeBytes: i64(200 << 30),
			},
			want: "battery 58% health: consider replacement",
		},
		{
			name: "bad battery condition takes priority over capacity",
			row: TenantDeviceRow{
				HasHardware: true, BatteryCondition: str("Replace Soon"), BatteryMaxCapacityPct: pct(90),
				SMARTStatus: str("Verified"), StorageFreeBytes: i64(200 << 30),
			},
			want: `battery condition "Replace Soon": consider replacement`,
		},
		{
			name: "storage below 10 GiB free — non-integer GB rounds up (never overstate free space)",
			row: TenantDeviceRow{
				HasHardware: true, BatteryMaxCapacityPct: pct(95), SMARTStatus: str("Verified"),
				StorageFreeBytes: i64(7.5 * (1 << 30)), // 7.5 GiB
			},
			want: "<8 GB free disk: storage pressure",
		},
		{
			name: "storage below 10 GiB free — exact integer GiB",
			row: TenantDeviceRow{
				HasHardware: true, BatteryMaxCapacityPct: pct(95), SMARTStatus: str("Verified"),
				StorageFreeBytes: i64(7 << 30),
			},
			want: "<7 GB free disk: storage pressure",
		},
		{
			name: "SMART warning",
			row: TenantDeviceRow{
				HasHardware: true, BatteryMaxCapacityPct: pct(95), StorageFreeBytes: i64(200 << 30),
				SMARTStatus: str("Failing"),
			},
			want: "SMART warning: potential drive failure",
		},
		{
			name: "storage used_pct fallback when free_bytes unreported",
			row: TenantDeviceRow{
				HasHardware: true, BatteryMaxCapacityPct: pct(95), SMARTStatus: str("Verified"),
				StorageUsedPct: pct(90),
			},
			want: "90% disk used: storage pressure",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.row.hardwareIssueSummary()
			if got != tc.want {
				t.Errorf("hardwareIssueSummary() = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestDeviceCompliancePct verifies the compliance-percentage formula:
// pass / (pass+fail+error) × 100, with NA excluded from the denominator.
func TestDeviceCompliancePct(t *testing.T) {
	tests := []struct {
		name     string
		pass     int
		fail     int
		errCount int
		want     float64
	}{
		{"all pass", 10, 0, 0, 100.0},
		{"all fail", 0, 10, 0, 0.0},
		{"half pass half fail", 5, 5, 0, 50.0},
		{"zero denominator", 0, 0, 0, 0.0},
		{"error counts in denominator", 8, 0, 2, 80.0},
		{"NA excluded — pass only", 3, 0, 0, 100.0}, // NA does not appear in args
		{"mixed with error", 3, 1, 1, 60.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := DeviceCompliancePct(tc.pass, tc.fail, tc.errCount)
			if got != tc.want {
				t.Errorf("DeviceCompliancePct(%d,%d,%d) = %.4f, want %.4f",
					tc.pass, tc.fail, tc.errCount, got, tc.want)
			}
		})
	}
}
