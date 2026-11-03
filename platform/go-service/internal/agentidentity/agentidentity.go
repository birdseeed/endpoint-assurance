// Package agentidentity is the single source of truth for the Patched Agent
// identities that must always carry an 'approved' tenant_app_policies row
// (PAT-1318). Patched Agents are trusted first-party platform components —
// the endpoint agent itself, which ships the inventory this whole system
// runs on — not customer-discovered software that needs manual review. Every
// identity listed here is auto-approved for every tenant, unconditionally,
// rather than ever surfacing in the "for review" queue
// (extractor/new_apps.go's tenant_new_apps).
//
// Each entry sets exactly one tenant_app_policies identity column (team_id /
// bundle_id / name — see 0032_tenant_app_policies.sql:38-53), matching the
// precedence extractor/new_apps.go's doDetectNewTenantApps anti-join checks
// (team_id > bundle_id > name; see candidatesSQL in that file, ~line
// 150-168). Setting more than one column on one entry would not break that
// SQL by itself — each axis is checked independently via OR — but it would
// make it ambiguous which column is the "real" identity for the entry, and
// a future edit that updates one column without the other could silently
// stop matching. One column per entry keeps this list unambiguous.
//
// There is currently no Developer ID (macOS) or Authenticode (Windows)
// signing identity to key these entries on — see docs/threat-model.md
// section 4, "Gap: agent binary itself is not currently code-signed with a
// Patched-issued certificate" (macOS PKG signing is gated on Apple Developer
// ID + incorporation; see ADR-0009). That is why this list matches on
// bundle/package identity (CFBundleIdentifier / MSI ARP display name)
// instead of a signer. When signing lands, prefer team_id (macOS Developer
// Team ID) or a stable Windows signer/UpgradeCode-derived identity, if the
// collector is ever extended to report one, and update the entries below.
//
// ACTION REQUIRED when macOS Developer ID signing lands: the two macOS
// entries below will silently start missing. Today the menu bar apps are
// unsigned, so device_apps.team_id reports 'Unknown' for them and
// extractor/new_apps.go's candidatesSQL resolves their app_identity to
// "bundle:...", which the bundle_id clause these entries carry matches.
// Once signing lands and macos/lib/apps.sh (updater repo) starts reporting
// a real Apple Developer Team ID, app_identity becomes "team:<id>" instead
// — the bundle clause no longer applies, these two entries carry no
// TeamID, and both macOS apps will reappear in every tenant's "for review"
// queue. The fix at that point is to ADD a TeamID entry for each (or
// populate TeamID on the existing entries, if the identity columns stay
// one-per-entry — see above), not to add a Name entry instead: their
// CFBundleName values are "Patched" (menu bar app) and "Patched Self
// Service" — see menubar/PatchedUpdater/Info.plist and
// menubar/PatchedUpdater/SelfService/Info.plist in the updater repo — and a
// name-only policy for the bare word "Patched" is far too broad to be safe
// (extractor/new_apps.go's widened name-match clause, PAT-1318, would then
// auto-approve any app on any tenant that simply names itself "Patched").
package agentidentity

// Platform values — mirror tenant_app_policies.platform's CHECK constraint
// (0032_tenant_app_policies.sql:42-43). Only the two concrete platforms are
// used here; "any" is not appropriate for these entries because each is a
// platform-specific binary.
const (
	PlatformMacOS   = "macos"
	PlatformWindows = "windows"
)

// Identity is one first-party Patched Agent identity to auto-approve in
// tenant_app_policies for every tenant.
type Identity struct {
	// Exactly one of TeamID, BundleID, Name is non-empty — see package doc
	// comment for why only one identity column is ever set per entry.
	TeamID   string
	BundleID string
	Name     string

	// Platform is "macos" or "windows" (PlatformMacOS / PlatformWindows).
	Platform string

	// Description documents which agent surface this identity is and where
	// its value comes from — for humans reading this list later, and echoed
	// nowhere else (tenant_app_policies.notes carries the stable seed
	// marker instead; see EnsurePatchedAgentPolicies).
	Description string
}

// Identities is the canonical list of Patched Agent identities that must be
// auto-approved for every tenant. Update here — and only here — when a new
// agent surface ships or an identity changes.
var Identities = []Identity{
	{
		// The macOS menu bar app — appears in /Applications and therefore in
		// macOS inventory, which reports bundle_id from CFBundleIdentifier
		// (updater/macos/lib/apps.sh).
		BundleID:    "im.patched.updater.menubar",
		Platform:    PlatformMacOS,
		Description: "Patched Updater menu bar app (updater/menubar/project.yml)",
	},
	{
		// The macOS Self Service app — same inventory path as the menu bar
		// app above.
		BundleID:    "im.patched.updater.selfservice",
		Platform:    PlatformMacOS,
		Description: "Patched Updater Self Service app (updater/menubar/project.yml)",
	},
	{
		// Windows inventory reports DisplayName + Publisher for an installed
		// app, with no bundle identifier
		// (updater/windows/src/Shared/Contract/InventoryPayload.cs). The
		// server-side device_apps.identifier column is instead populated
		// from the Windows registry uninstall-key name — effectively the
		// MSI ProductCode (updater/windows/src/Service/InstalledAppScanner.cs)
		// — which this installer's WiX MajorUpgrade schema
		// (updater/windows/installer/Product.wxs) regenerates on every
		// release. That makes it unusable as a stable per-tenant identity
		// the way a macOS bundle_id is, so this entry matches on the
		// display name instead.
		//
		// MSI ARP identity, for reference: Manufacturer "Patched",
		// ProductName "Patched Agent", UpgradeCode
		// {A1B2C3D4-E5F6-7890-ABCD-000000000311}
		// (updater/windows/installer/Product.wxs). UpgradeCode IS stable
		// across versions and would be the identity to switch to if the
		// Windows collector is ever extended to report it — today it only
		// sends DisplayName/DisplayVersion/Publisher/Architecture per app
		// (InstalledAppScanner.cs).
		Name:        "Patched Agent",
		Platform:    PlatformWindows,
		Description: "Patched Agent Windows MSI (updater/windows/installer/Product.wxs)",
	},
}
