package softwaregov

// PAT-2152: the SAM publisher view (PAT-2146's third saved report over
// existing evidence): every currently installed application, grouped by the
// publisher its code signing evidence proves -- the macOS Team ID or the
// Windows Authenticode subject pinned to its signing root (PAT-2121's
// AuthenticodePublisherKey) -- never the display name, registry Publisher
// string or any other installer-claimed metadata.
//
// This file gathers evidence across the WHOLE current estate (every
// installed application, not just newly seen ones) and regroups it by
// publisher identity instead of by product or by urgency. The signing
// classification itself is not reinvented: it reuses PAT-2093's pure
// classifier (urgency.go's classifyMacTrust / classifyWindowsTrust operating
// on trustFacts, gathered by newsoftware_urgency.go's loadTrustFacts) exactly
// as the overview does, so a product can never read one trust state on the
// overview and a different one here.
//
// Four groups, most attention-worthy first:
//
//   - unsigned_or_adhoc: the collector reported the installation unsigned
//     (macOS signing_status "unsigned", Windows signature_state "unsigned"),
//     or ad hoc signed (macOS only: signed with no identity at all).
//   - invalid: a signature that does not validate against the code (macOS
//     signing_status "invalid", Windows signature_state "invalid"), or one
//     that validates but whose certificate chain does not anchor to Apple
//     (macOS signing_status "untrusted", PAT-2117).
//   - unverified: no signing evidence at all (no observation, an agent too
//     old to report it, or the collector could not establish a signing
//     authority), OR a signature that validates but whose publisher cannot be
//     independently pinned: installations disagree, carry no single Team ID,
//     or (Windows) chain to an enterprise root or carry no root evidence at
//     all (an agent older than updater #668) -- PAT-2121's pinning is what
//     makes a Windows publisher identity trustworthy, so without it the
//     product is unverified, never shown under the claimed signer name.
//   - verified: every installation agrees on one Team ID (macOS) or one
//     Authenticode publisher key -- signer plus root pin (Windows), or is
//     Apple's own platform signing. trusted says whether this tenant has
//     approved a product under that exact publisher identity (PAT-2121):
//     it is this tenant's own decision, never a judgement on the vendor.
//
// Nothing here changes a device or tells an agent to act.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"patched.im/api/internal/deviceretirement"
)

// Publisher report group names, most attention-worthy first.
const (
	PublisherGroupUnsignedAdhoc = "unsigned_or_adhoc"
	PublisherGroupInvalid       = "invalid"
	PublisherGroupUnverified    = "unverified"
	PublisherGroupVerified      = "verified"
)

// publisherGroupRank orders groups for the report's row ordering: unsigned,
// invalid and unverified sort ahead of verified publishers.
var publisherGroupRank = map[string]int{
	PublisherGroupUnsignedAdhoc: 0,
	PublisherGroupInvalid:       1,
	PublisherGroupUnverified:    2,
	PublisherGroupVerified:      3,
}

// PublisherDefinition names the saved report definition (PAT-2146: each SAM
// report is a saved definition over existing read APIs).
type PublisherDefinition struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
	Title   string `json:"title"`
}

// PublisherReportDefinition is the one saved definition of this report.
var PublisherReportDefinition = PublisherDefinition{ID: "sam.software-publishers", Version: 1, Title: "Software publishers"}

// PublisherStatement is the report's standing caveat.
const PublisherStatement = "Every currently installed application, grouped by the publisher its code signing " +
	"evidence proves: the macOS Team ID, or the Windows Authenticode signer pinned to its signing root. Never the " +
	"display name, registry Publisher string or any other installer-claimed metadata. Unsigned, invalid and " +
	"unverifiable publishers are listed first. Trusted means this tenant has approved a product under that exact " +
	"publisher identity; it is this tenant's own decision, not a judgement on the vendor, and it is not an audit " +
	"or a compliance position."

// PublisherRow is one publisher (or, for the three call-out groups, one
// platform's worth of installations that could not be attributed to a
// publisher), the report's top-level listing.
type PublisherRow struct {
	// PublisherKey identifies the publisher for the /devices drill-down:
	// "team:<TEAMID>" (macOS), "apple" (macOS platform signing) or the
	// Authenticode publisher key itself (Windows, already prefixed
	// "authenticode:"). Empty for the three call-out groups, which are
	// identified by Group and Platform instead.
	PublisherKey string `json:"publisher_key"`
	Group        string `json:"group"`
	Platform     string `json:"platform"`
	// IdentityBasis is PublisherBasisTeamID, PublisherBasisAppleSignature or
	// PublisherBasisAuthenticode for a verified row, PublisherBasisNone for
	// a call-out row.
	IdentityBasis string `json:"identity_basis"`
	// Publisher is the Team ID, "Apple", or the Authenticode signer's
	// Subject DN. Nil for a call-out row: there is nothing reliable to show.
	Publisher *string `json:"publisher"`
	// Trusted is this tenant's PAT-2121 approval of the exact publisher
	// identity. Always false for a call-out row.
	Trusted      bool    `json:"trusted"`
	Signing      string  `json:"signing"`
	SignerClass  *string `json:"signer_class"`
	Notarisation string  `json:"notarisation"`
	// ProductCount is how many distinct products (by identity) fall in this
	// row: more than one product can share a publisher, and a call-out row
	// bundles every product in that group and platform.
	ProductCount      int `json:"product_count"`
	DeviceCount       int `json:"device_count"`
	StaleDeviceCount  int `json:"stale_device_count"`
	InstallationCount int `json:"installation_count"`
}

// PublisherReportRow is one installation on one device, the /devices
// drill-down.
type PublisherReportRow struct {
	DeviceID       string    `json:"device_id"`
	Hostname       string    `json:"hostname"`
	DeviceLastSeen time.Time `json:"device_last_seen"`
	DeviceStale    bool      `json:"device_stale"`
	PublisherKey   string    `json:"publisher_key"`
	Group          string    `json:"group"`
	Platform       string    `json:"platform"`
	IdentityBasis  string    `json:"identity_basis"`
	Publisher      *string   `json:"publisher"`
	Trusted        bool      `json:"trusted"`
	Signing        string    `json:"signing"`
	SignerClass    *string   `json:"signer_class"`
	Notarisation   string    `json:"notarisation"`
	ProductKey     string    `json:"product_key"`
	Name           string    `json:"name"`
	Identifier     string    `json:"identifier"`
	Version        string    `json:"version,omitempty"`
}

// PublisherReportSummary is the report's top-level totals.
type PublisherReportSummary struct {
	PublisherCount              int `json:"publisher_count"`
	TrustedPublisherCount       int `json:"trusted_publisher_count"`
	UntrustedPublisherCount     int `json:"untrusted_publisher_count"`
	UnsignedInstallationCount   int `json:"unsigned_installation_count"`
	InvalidInstallationCount    int `json:"invalid_installation_count"`
	UnverifiedInstallationCount int `json:"unverified_installation_count"`
	InstallationCount           int `json:"installation_count"`
}

// PublisherReportNotCounted is one class of evidence the report deliberately
// leaves out.
type PublisherReportNotCounted struct {
	Reason      string `json:"reason"`
	Description string `json:"description"`
	Count       int    `json:"count"`
}

// PublisherReportBasis states what the answer rests on, in the same shape
// PAT-2147/PAT-2148 use.
type PublisherReportBasis struct {
	GeneratedAt             time.Time                   `json:"generated_at"`
	EvidenceNewestAt        *time.Time                  `json:"evidence_newest_at"`
	EvidenceOldestAt        *time.Time                  `json:"evidence_oldest_at"`
	DevicesTotal            int                         `json:"devices_total"`
	DevicesAssessed         int                         `json:"devices_assessed"`
	DevicesReporting        int                         `json:"devices_reporting"`
	DevicesStale            int                         `json:"devices_stale"`
	DevicesWithoutInventory int                         `json:"devices_without_inventory"`
	StaleAfterDays          int                         `json:"stale_after_days"`
	RetiredDevicesExcluded  bool                        `json:"retired_devices_excluded"`
	DevicesRetired          int                         `json:"devices_retired"`
	NotCounted              []PublisherReportNotCounted `json:"not_counted"`
	Complete                bool                        `json:"complete"`
	Statement               string                      `json:"statement"`
	Notes                   []string                    `json:"notes"`
}

// PublisherReport is one tenant's software publisher report.
type PublisherReport struct {
	Definition  PublisherDefinition    `json:"definition"`
	GeneratedAt time.Time              `json:"generated_at"`
	Summary     PublisherReportSummary `json:"summary"`
	Basis       PublisherReportBasis   `json:"basis"`
	Publishers  []PublisherRow         `json:"-"`
	Rows        []PublisherReportRow   `json:"-"`
}

type publisherDevice struct {
	ID, Hostname, Platform string
	LastSeen               time.Time
	Stale, HasInventory    bool
}

func publisherPlatformOf(os string) string {
	switch strings.ToLower(strings.TrimSpace(os)) {
	case "macos":
		return "macos"
	case "windows":
		return "windows"
	}
	return ""
}

// publisherBucket assigns the call-out group from an installation group's
// signing state, or PublisherGroupVerified when a pinned publisher identity
// was established (verified is true only when signing is fully valid and
// pinned; see BuildPublisherReport).
func publisherBucket(signing string, verified bool) string {
	switch signing {
	case SigningUnsigned, SigningAdhoc:
		return PublisherGroupUnsignedAdhoc
	case SigningInvalid, SigningUntrusted:
		return PublisherGroupInvalid
	}
	if verified {
		return PublisherGroupVerified
	}
	return PublisherGroupUnverified
}

// publisherClassification is one product group's publisher identity and
// trust state, classified from its trustFacts.
type publisherClassification struct {
	Group, IdentityBasis, PublisherKey string
	Publisher                          *string
	Trusted                            bool
	Signing, Notarisation              string
	SignerClass                        *string
}

// classifyPublisher reuses PAT-2093's pure signing classifier
// (classifyMacTrust / classifyWindowsTrust) to establish one product group's
// publisher identity from its trust facts, then assigns the report group.
//
// A macOS product is verified whenever the classifier pins one Team ID (or
// is Apple's own platform signing): the Team ID is already a strong, hardware
// -enrolled identity, so no extra pinning is needed. A Windows product is
// verified only when windowsPublisherKey can also pin it to a root
// (PAT-2121): signed-but-unpinned evidence -- an older agent that sent no
// root, an enterprise root, or installations that disagree -- is unverified,
// never shown under the claimed signer name.
func classifyPublisher(platform string, f trustFacts, approvedTeams map[string]bool, approvedKeys map[string]map[string]bool) publisherClassification {
	trust := UrgencyTrust{Installations: f.Installations, PublisherBasis: PublisherBasisNone,
		Signing: SigningUnknown, Notarisation: NotarisationUnknown}
	noop := func(code, level, detail string) {}
	var pubKey string
	var trusted bool
	switch platform {
	case "macos":
		classifyMacTrust(f, approvedTeams, &trust, noop)
		if trust.Signing == SigningSigned {
			switch trust.PublisherBasis {
			case PublisherBasisTeamID:
				team := deref(trust.Publisher)
				pubKey = "team:" + team
				trusted = approvedTeams[team]
			case PublisherBasisAppleSignature:
				pubKey = "apple"
			}
		}
	default:
		classifyWindowsTrust(f, &trust, noop)
		if trust.Signing == SigningSigned {
			if key := windowsPublisherKey(f); key != "" {
				// Only a root-pinned signer counts (PAT-2121). Signed but
				// unpinned (an older agent, an enterprise root, or
				// installations that disagree) falls through unverified
				// below, whatever classifyWindowsTrust set Publisher to.
				pubKey = key
				trusted = len(approvedKeys[key]) > 0
			}
		}
	}
	group := publisherBucket(trust.Signing, pubKey != "")
	if group != PublisherGroupVerified {
		// Belt and braces: classifyWindowsTrust sets Publisher to the raw
		// registry Publisher string (PublisherBasisRegistryPublisher) as an
		// explicitly-unverified fallback for the overview, which reads it
		// labelled as such. This report never shows installer-claimed
		// metadata as a publisher at all, so every non-verified bucket is
		// forced clear here regardless of what either classifier set.
		trust.Publisher, trust.PublisherBasis, pubKey, trusted = nil, PublisherBasisNone, "", false
	}
	return publisherClassification{
		Group: group, IdentityBasis: trust.PublisherBasis,
		Publisher: trust.Publisher, Trusted: trusted, Signing: trust.Signing,
		Notarisation: trust.Notarisation, SignerClass: trust.SignerClass, PublisherKey: pubKey,
	}
}

// BuildPublisherReport computes the report for one tenant. tenantID must
// come from an authenticated identity; every query is scoped to it.
func BuildPublisherReport(ctx context.Context, q Querier, tenantID string, now time.Time) (PublisherReport, error) {
	now = now.UTC()
	rep := PublisherReport{Definition: PublisherReportDefinition, GeneratedAt: now}
	staleCut := now.Add(-StaleAfter)

	var total int
	if err := q.QueryRow(ctx, `
		SELECT count(*)::int FROM software_installations
		WHERE tenant_id = $1::uuid AND removed_at IS NULL`, tenantID).Scan(&total); err != nil {
		return rep, fmt.Errorf("count installations: %w", err)
	}
	if total > MaxEstateRows {
		return rep, ErrEstateTooLarge
	}

	// Devices.
	drows, err := q.Query(ctx, `
		SELECT d.id::text, COALESCE(NULLIF(d.computer_name, ''), NULLIF(d.hostname, ''), ''),
		       COALESCE(d.os, ''), d.last_seen,
		       EXISTS (SELECT 1 FROM software_installations si
		               WHERE si.device_id = d.id AND si.tenant_id = d.tenant_id AND si.removed_at IS NULL),
		       r.retired
		FROM devices d
		CROSS JOIN LATERAL (SELECT `+deviceretirement.RetiredSQL("d")+` AS retired) r
		WHERE d.tenant_id = $1::uuid
		ORDER BY d.id`, tenantID)
	if err != nil {
		return rep, fmt.Errorf("load devices: %w", err)
	}
	devices := map[string]*publisherDevice{}
	unrecognised, retired := 0, 0
	for drows.Next() {
		var d publisherDevice
		var os string
		var isRetired bool
		if err := drows.Scan(&d.ID, &d.Hostname, &os, &d.LastSeen, &d.HasInventory, &isRetired); err != nil {
			drows.Close()
			return rep, fmt.Errorf("scan device: %w", err)
		}
		d.Platform = publisherPlatformOf(os)
		d.Stale = d.LastSeen.Before(staleCut)
		rep.Basis.DevicesTotal++
		if isRetired {
			retired++
			continue
		}
		if d.Platform == "" {
			unrecognised++
			continue
		}
		dd := d
		devices[d.ID] = &dd
	}
	drows.Close()
	if err := drows.Err(); err != nil {
		return rep, err
	}

	// Every current application installation. Trust facts are read
	// separately (loadTrustFacts, below) so the estate's whole current
	// signing evidence goes through the exact same aggregation PAT-2093's
	// classifier reads, rather than a second copy of it.
	type instRow struct {
		deviceID, platform, kind, value, name, version string
	}
	irows, err := q.Query(ctx, `
		SELECT si.device_id::text, si.platform, si.identity_kind, si.identity_value_normalized,
		       si.current_name, COALESCE(si.current_version, '')
		FROM software_installations si
		WHERE si.tenant_id = $1::uuid AND si.removed_at IS NULL AND si.identity_kind = ANY($2)
		ORDER BY si.device_id, si.identity_fingerprint`, tenantID, applicationIdentityKinds)
	if err != nil {
		return rep, fmt.Errorf("load installations: %w", err)
	}
	var insts []instRow
	for irows.Next() {
		var r instRow
		if err := irows.Scan(&r.deviceID, &r.platform, &r.kind, &r.value, &r.name, &r.version); err != nil {
			irows.Close()
			return rep, fmt.Errorf("scan installation: %w", err)
		}
		if devices[r.deviceID] == nil {
			continue // a retired or unrecognised-platform device
		}
		insts = append(insts, r)
	}
	irows.Close()
	if err := irows.Err(); err != nil {
		return rep, err
	}

	// Distinct product groups present, the same key loadTrustFacts and
	// PAT-2093's classifier use.
	seen := map[productGroup]bool{}
	var groups []productGroup
	for _, r := range insts {
		g := productGroup{platform: r.platform, nameOnly: r.kind == "name_publisher" || r.kind == "display_name", ident: r.value}
		if !seen[g] {
			seen[g] = true
			groups = append(groups, g)
		}
	}
	facts, err := loadTrustFacts(ctx, q, tenantID, groups)
	if err != nil {
		return rep, err
	}

	pol, err := loadPolicies(ctx, q, tenantID)
	if err != nil {
		return rep, fmt.Errorf("load policies: %w", err)
	}
	approvedTeams := approvedTeamIDs(pol)
	approvedKeys, err := approvedPublisherKeys(ctx, q, tenantID)
	if err != nil {
		return rep, err
	}

	classifiedOf := make(map[productGroup]publisherClassification, len(groups))
	for _, g := range groups {
		classifiedOf[g] = classifyPublisher(g.platform, facts[g], approvedTeams, approvedKeys)
	}

	// Assemble the publisher rows and the drill-down.
	type agg struct {
		row      PublisherRow
		products map[productGroup]bool
		devices  map[string]bool
		stale    map[string]bool
	}
	aggs := map[string]*agg{}
	var order []string
	for _, r := range insts {
		g := productGroup{platform: r.platform, nameOnly: r.kind == "name_publisher" || r.kind == "display_name", ident: r.value}
		c := classifiedOf[g]
		rk := c.PublisherKey
		if rk == "" {
			rk = c.Group + ":" + g.platform
		}
		a := aggs[rk]
		if a == nil {
			a = &agg{
				row: PublisherRow{
					PublisherKey: c.PublisherKey, Group: c.Group, Platform: g.platform, IdentityBasis: c.IdentityBasis,
					Publisher: c.Publisher, Trusted: c.Trusted, Signing: c.Signing, SignerClass: c.SignerClass,
					Notarisation: c.Notarisation,
				},
				products: map[productGroup]bool{}, devices: map[string]bool{}, stale: map[string]bool{},
			}
			aggs[rk] = a
			order = append(order, rk)
		}
		a.products[g] = true
		a.devices[r.deviceID] = true
		a.row.InstallationCount++
		d := devices[r.deviceID]
		if d.Stale {
			a.stale[r.deviceID] = true
		}

		pk := g.platform + ":" + g.ident
		rep.Rows = append(rep.Rows, PublisherReportRow{
			DeviceID: r.deviceID, Hostname: d.Hostname, DeviceLastSeen: d.LastSeen.UTC(), DeviceStale: d.Stale,
			PublisherKey: c.PublisherKey, Group: c.Group, Platform: g.platform, IdentityBasis: c.IdentityBasis,
			Publisher: c.Publisher, Trusted: c.Trusted, Signing: c.Signing, SignerClass: c.SignerClass,
			Notarisation: c.Notarisation, ProductKey: pk, Name: r.name, Identifier: r.value, Version: r.version,
		})
	}

	sum := PublisherReportSummary{}
	for _, rk := range order {
		a := aggs[rk]
		a.row.ProductCount = len(a.products)
		a.row.DeviceCount = len(a.devices)
		a.row.StaleDeviceCount = len(a.stale)
		rep.Publishers = append(rep.Publishers, a.row)
		switch a.row.Group {
		case PublisherGroupVerified:
			sum.PublisherCount++
			if a.row.Trusted {
				sum.TrustedPublisherCount++
			} else {
				sum.UntrustedPublisherCount++
			}
		case PublisherGroupUnsignedAdhoc:
			sum.UnsignedInstallationCount += a.row.InstallationCount
		case PublisherGroupInvalid:
			sum.InvalidInstallationCount += a.row.InstallationCount
		case PublisherGroupUnverified:
			sum.UnverifiedInstallationCount += a.row.InstallationCount
		}
		sum.InstallationCount += a.row.InstallationCount
	}
	rep.Summary = sum

	sort.SliceStable(rep.Publishers, func(i, j int) bool {
		a, b := rep.Publishers[i], rep.Publishers[j]
		if ra, rb := publisherGroupRank[a.Group], publisherGroupRank[b.Group]; ra != rb {
			return ra < rb
		}
		if a.InstallationCount != b.InstallationCount {
			return a.InstallationCount > b.InstallationCount
		}
		if a.Platform != b.Platform {
			return a.Platform < b.Platform
		}
		return a.PublisherKey < b.PublisherKey
	})
	sort.SliceStable(rep.Rows, func(i, j int) bool {
		a, b := rep.Rows[i], rep.Rows[j]
		if ra, rb := publisherGroupRank[a.Group], publisherGroupRank[b.Group]; ra != rb {
			return ra < rb
		}
		if a.Hostname != b.Hostname {
			return a.Hostname < b.Hostname
		}
		if a.DeviceID != b.DeviceID {
			return a.DeviceID < b.DeviceID
		}
		return a.ProductKey < b.ProductKey
	})

	b := PublisherReportBasis{
		GeneratedAt: now, StaleAfterDays: int(StaleAfter / (24 * time.Hour)),
		DevicesTotal: rep.Basis.DevicesTotal, RetiredDevicesExcluded: true, DevicesRetired: retired,
		Statement: PublisherStatement,
		Notes: []string{
			"Devices your organisation has retired are left out of every figure and listed here as not counted. A device that has not reported for 14 days is still counted, marked stale, with the age of its evidence.",
			"Trusted is your tenant's own existing approval decision (PUT /v1/portal/software-approvals) for a product carrying this exact publisher identity, never a separate publisher allow list.",
		},
	}
	for _, d := range devices {
		b.DevicesAssessed++
		if d.Stale {
			b.DevicesStale++
		} else {
			b.DevicesReporting++
		}
		if !d.HasInventory {
			b.DevicesWithoutInventory++
		}
		t := d.LastSeen.UTC()
		if b.EvidenceNewestAt == nil || t.After(*b.EvidenceNewestAt) {
			tt := t
			b.EvidenceNewestAt = &tt
		}
		if b.EvidenceOldestAt == nil || t.Before(*b.EvidenceOldestAt) {
			tt := t
			b.EvidenceOldestAt = &tt
		}
	}
	b.NotCounted = []PublisherReportNotCounted{
		{Reason: "retired_devices", Description: "devices your organisation has retired", Count: retired},
		{Reason: "unrecognised_platform", Description: "devices reporting an operating system other than macOS or Windows", Count: unrecognised},
	}
	b.Complete = b.DevicesAssessed > 0 && b.DevicesStale == 0 && b.DevicesWithoutInventory == 0 && unrecognised == 0
	rep.Basis = b
	return rep, nil
}
