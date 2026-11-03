package report

// PAT-2324: the portal tells servers from workstations. derivePortalDeviceClass
// is the one derivation behind device_class and os_caption on both
// GET /v1/portal/devices and GET /v1/portal/devices/{id}. These cases pin its
// contract without a database: the output vocabulary is exactly server,
// workstation or unknown; a stored domain_controller reads server; a Mac with
// no class reads workstation by OS family alone; a Windows device with no
// class stays unknown.

import "testing"

func TestDerivePortalDeviceClass(t *testing.T) {
	strp := func(s string) *string { return &s }
	cases := []struct {
		name        string
		os          string
		storedClass string
		storedCap   string
		wantClass   string
		wantCap     *string
	}{
		{"windows server keeps its caption", "Windows", "server", "Microsoft Windows Server 2022 Standard", "server", strp("Microsoft Windows Server 2022 Standard")},
		{"windows workstation", "Windows", "workstation", "Microsoft Windows 11 Enterprise", "workstation", strp("Microsoft Windows 11 Enterprise")},
		{"windows workstation without a caption", "Windows", "workstation", "", "workstation", nil},
		{"mac unknown reads workstation by OS family", "macOS", "unknown", "", "workstation", nil},
		{"mac with an empty stored class reads workstation", "macOS", "", "", "workstation", nil},
		{"mac OS family match ignores case and padding", " macos ", "unknown", "", "workstation", nil},
		{"windows unknown stays unknown", "Windows", "unknown", "", "unknown", nil},
		{"windows with an empty stored class stays unknown", "Windows", "", "", "unknown", nil},
		{"windows unknown keeps a reported caption", "Windows", "unknown", "Microsoft Windows 10 Pro", "unknown", strp("Microsoft Windows 10 Pro")},
		{"unrecognised OS with no class stays unknown", "Linux", "unknown", "", "unknown", nil},
		{"empty OS with no class stays unknown", "", "unknown", "", "unknown", nil},
		// A stored server or workstation is never overridden by the OS family.
		{"mac stored as server stays server", "macOS", "server", "", "server", nil},
		// The stored value is outside the portal vocabulary: never passed
		// through, and never upgraded to workstation, even on a Mac.
		{"unexpected stored value on windows is unknown", "Windows", "hypervisor", "", "unknown", nil},
		{"unexpected stored value on a mac is unknown", "macOS", "hypervisor", "", "unknown", nil},
		{"wrong-case stored value is not matched", "Windows", "Server", "", "unknown", nil},
		// A domain controller is a Windows Server, so it reads as server.
		{"domain_controller reads as server", "Windows", "domain_controller", "Microsoft Windows Server 2019 Standard", "server", strp("Microsoft Windows Server 2019 Standard")},
		{"domain_controller without a caption reads as server", "Windows", "domain_controller", "", "server", nil},
		{"padded stored value is trimmed", "Windows", " server ", "", "server", nil},
		// Caption handling: trimmed, null when nothing is left.
		{"caption is trimmed", "Windows", "server", "  Microsoft Windows Server 2019 Datacenter \n", "server", strp("Microsoft Windows Server 2019 Datacenter")},
		{"whitespace-only caption is null", "Windows", "server", " \t ", "server", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotClass, gotCap := derivePortalDeviceClass(TenantDeviceRow{
				OS:                tc.os,
				StoredDeviceClass: tc.storedClass,
				StoredOSCaption:   tc.storedCap,
			})
			if gotClass != tc.wantClass {
				t.Errorf("device_class = %q, want %q", gotClass, tc.wantClass)
			}
			switch {
			case gotCap == nil && tc.wantCap == nil:
			case gotCap == nil || tc.wantCap == nil:
				t.Errorf("os_caption = %v, want %v", derefOrNil(gotCap), derefOrNil(tc.wantCap))
			case *gotCap != *tc.wantCap:
				t.Errorf("os_caption = %q, want %q", *gotCap, *tc.wantCap)
			}
		})
	}
}

func derefOrNil(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}
