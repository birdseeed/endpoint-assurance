package report

import "testing"

func TestSoftwareUsageState(t *testing.T) {
	tests := []struct {
		name      string
		product   PortalSoftwareProduct
		state     string
		candidate bool
	}{
		{"all fresh metered used", PortalSoftwareProduct{InstallationCount: 2, MeteredInstallationCount: 2}, "used", false},
		{"all fresh metered unused", PortalSoftwareProduct{InstallationCount: 2, MeteredInstallationCount: 2, UnusedInstallationCount: 2}, "unused", true},
		{"unmetered is not unused", PortalSoftwareProduct{InstallationCount: 1, UnmeteredInstallationCount: 1}, "unmetered", false},
		{"mixed coverage is not a candidate", PortalSoftwareProduct{InstallationCount: 2, MeteredInstallationCount: 1, UnmeteredInstallationCount: 1, UnusedInstallationCount: 1}, "mixed", false},
		{"stale takes priority and is not a candidate", PortalSoftwareProduct{InstallationCount: 1, MeteredInstallationCount: 1, StaleInstallationCount: 1, UnusedInstallationCount: 1}, "stale", false},
		{"no recognised evidence is unknown", PortalSoftwareProduct{InstallationCount: 1}, "unknown", false},

		// PAT-2327: absence of a launch record is never evidence of non-use.
		// No-evidence installations (metered device, NULL last_used_at, or a
		// server) sit on the unmetered side and can never make a product unused.
		{"metered but no launch record is unmetered, not unused", PortalSoftwareProduct{InstallationCount: 2, MeteredInstallationCount: 2, NoEvidenceInstallationCount: 2}, "unmetered", false},
		{"no evidence and unmetered together stay unmetered", PortalSoftwareProduct{InstallationCount: 3, MeteredInstallationCount: 2, UnmeteredInstallationCount: 1, NoEvidenceInstallationCount: 2}, "unmetered", false},
		{"one unused install beside a no-evidence install is mixed, not a candidate", PortalSoftwareProduct{InstallationCount: 2, MeteredInstallationCount: 2, UnusedInstallationCount: 1, NoEvidenceInstallationCount: 1}, "mixed", false},
		{"one used install beside a no-evidence install is mixed", PortalSoftwareProduct{InstallationCount: 2, MeteredInstallationCount: 2, NoEvidenceInstallationCount: 1}, "mixed", false},
		{"stale takes priority over no evidence", PortalSoftwareProduct{InstallationCount: 2, MeteredInstallationCount: 2, StaleInstallationCount: 1, NoEvidenceInstallationCount: 1}, "stale", false},
		{"every install positively unused is still a candidate", PortalSoftwareProduct{InstallationCount: 3, MeteredInstallationCount: 3, UnusedInstallationCount: 3}, "unused", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, candidate := softwareUsageState(tt.product)
			if state != tt.state || candidate != tt.candidate {
				t.Errorf("softwareUsageState(%+v) = %q, %v; want %q, %v", tt.product, state, candidate, tt.state, tt.candidate)
			}
		})
	}
}
