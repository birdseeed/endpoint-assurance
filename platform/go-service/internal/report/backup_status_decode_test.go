package report

import "testing"

// DecodeDeviceBackupStatus derives the served Stale flag from the same
// >= 7-day rule as BackupBucket, overriding the agent-reported flag — the
// collectors use a strict > 7, so at exactly 7 days the raw flag contradicts
// the bucket. These tests pin the boundary and the nil cases.
func TestDecodeDeviceBackupStatusDerivesStale(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		wantNil    bool
		wantStale  bool
		wantBucket string
	}{
		{name: "absent", raw: "", wantNil: true},
		{name: "json null", raw: "null", wantNil: true},
		{name: "malformed", raw: `{"has_backup":"yes"}`, wantNil: true},
		{name: "fresh 6 days", raw: `{"has_backup":true,"last_backup_days_ago":6,"stale":false,"sync_only":false}`, wantStale: false, wantBucket: "ok"},
		{
			// The boundary the agents get wrong: collector emits stale=false at
			// exactly 7 days (strict >), server rule is >= 7. Served value must
			// agree with the bucket, not the wire flag.
			name: "boundary 7 days overrides agent flag", raw: `{"has_backup":true,"last_backup_days_ago":7,"stale":false,"sync_only":false}`,
			wantStale: true, wantBucket: "stale",
		},
		{name: "old 23 days", raw: `{"has_backup":true,"last_backup_days_ago":23,"stale":true,"sync_only":false}`, wantStale: true, wantBucket: "stale"},
		{name: "no timestamp counts ok", raw: `{"has_backup":true,"stale":false,"sync_only":false}`, wantStale: false, wantBucket: "ok"},
		{
			// sync_only wins before any staleness maths; a spurious wire
			// stale=true must not survive the decode.
			name: "sync only never stale", raw: `{"has_backup":false,"last_backup_days_ago":40,"stale":true,"sync_only":true}`,
			wantStale: false, wantBucket: "sync_only",
		},
		{name: "no backup", raw: `{"has_backup":false,"stale":false,"sync_only":false}`, wantStale: false, wantBucket: "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DecodeDeviceBackupStatus([]byte(tc.raw))
			if tc.wantNil {
				if got != nil {
					t.Fatalf("want nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("want decoded value, got nil")
			}
			if got.Stale != tc.wantStale {
				t.Errorf("Stale = %v, want %v", got.Stale, tc.wantStale)
			}
			if b := BackupBucket(got.HasBackup, got.SyncOnly, got.LastBackupDaysAgo); b != tc.wantBucket {
				t.Errorf("bucket = %q, want %q", b, tc.wantBucket)
			}
			if got.Stale != (tc.wantBucket == "stale") {
				t.Errorf("served Stale %v disagrees with bucket %q", got.Stale, tc.wantBucket)
			}
		})
	}
}
