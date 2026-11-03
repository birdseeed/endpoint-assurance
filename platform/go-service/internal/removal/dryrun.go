// Package removal implements the PAT-1598 authorised-removal dry-run
// preview and the staleness rule that governs when a preview may still be
// used to authorise a removal.
//
// This package computes and grades evidence. It never actuates anything and
// has no agent-facing surface: the platform records what a removal would
// affect and who authorised it, and the customer's own management platform
// performs the removal (root AGENTS.md: evidence before actuation).
//
// Two rules from root AGENTS.md shape almost everything here:
//
//   - Absence requires authority. A device the platform has never seen
//     application inventory from is not evidence that the product is
//     absent, so it is counted and reported separately rather than quietly
//     excluded. A matched set too large to enumerate fails the preview
//     rather than truncating it, because a truncated device list presented
//     as the removal scope is a false claim about the estate.
//   - Windows and macOS parity. Matching uses the platform-neutral identity
//     columns tenant_app_policies already uses (team_id doubles as the
//     Windows Authenticode signer, bundle_id as the MSI ProductCode), and
//     nothing here branches on operating system except where the stored
//     data genuinely differs.
package removal

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"patched.im/api/internal/protectedsoftware"
)

// Querier is satisfied by both *pgxpool.Pool and pgx.Tx, so a preview can be
// computed inside the same transaction as the write it informs. It is a
// superset of protectedsoftware.Querier, so it can be handed straight to
// protectedsoftware.Check.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// MaxMatchedRows caps the raw device_apps rows one preview will consider.
// Above it the preview fails rather than truncating: see ErrTooManyMatches.
// var, not const, so tests can lower it without seeding thousands of rows —
// the same convention portal_applications.go uses for its own source cap.
var MaxMatchedRows = 5000

// SetMaxMatchedRowsForTest lowers MaxMatchedRows and returns a restore func.
func SetMaxMatchedRowsForTest(n int) (restore func()) {
	orig := MaxMatchedRows
	MaxMatchedRows = n
	return func() { MaxMatchedRows = orig }
}

// ErrTooManyMatches means the target matched more inventory rows than one
// preview can enumerate. It is deliberately an error and not a truncation
// flag: a removal scope that silently omitted devices would be read as the
// full scope by whoever authorises it.
var ErrTooManyMatches = errors.New("removal: target matches more inventory rows than one preview can enumerate")

// Evidence-basis vocabulary, identical to AppPolicyRow.EvidenceBasis
// (PAT-1725) so a removal preview grades identity evidence the same way
// every other surface in this codebase does.
const (
	EvidenceIdentifierMatch = "identifier_match"
	EvidenceNameMatchOnly   = "name_match_only"
	EvidenceUnknown         = "unknown"
)

// Artefact-basis vocabulary, matching the CHECK on
// removal_campaign_dry_runs.artefact_basis.
const (
	ArtefactBasisObserved         = "observed_paths"
	ArtefactBasisKnown            = "known_app_bundles"
	ArtefactBasisObservedAndKnown = "observed_and_known"
	ArtefactBasisNone             = "none"
)

// UnknownVersion is the bucket a device_apps row with no reported version
// falls into. It is a named bucket rather than a dropped row: "we do not
// know which version this device runs" is part of the version spread an
// authoriser needs to see.
const UnknownVersion = "unknown"

// Target is the product a campaign is aimed at, in the identity vocabulary
// tenant_app_policies (0032) established: team_id (Apple Developer Team ID
// or Windows Authenticode signer), bundle_id (CFBundleIdentifier or Windows
// MSI ProductCode), name (display-name fallback, matched
// case-insensitively), and a platform scope.
type Target struct {
	TeamID   *string
	BundleID *string
	Name     *string
	Platform string // "macos" | "windows" | "any"
}

// Identity converts a Target into the shape protectedsoftware.Check
// consumes. The mapping is one to one because this table deliberately reuses
// tenant_app_policies' identity columns; ProcessName carries the display
// name because protected_software matches that column against both
// process_name and product_name (its documented weakest tier).
func (t Target) Identity() protectedsoftware.Identity {
	return protectedsoftware.Identity{
		TeamID:      t.TeamID,
		BundleID:    t.BundleID,
		ProcessName: t.Name,
	}
}

// VersionBucket is one version and the number of matched devices running it.
type VersionBucket struct {
	Version     string `json:"version"`
	DeviceCount int    `json:"device_count"`
}

// DeviceRow is one device in the preview's scope.
type DeviceRow struct {
	DeviceID string   `json:"device_id"`
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	Versions []string `json:"versions"`
	// Paths are the on-disk locations this device actually reported for the
	// matched application. Observed, not predicted.
	Paths []string `json:"paths"`
	// EvidenceBasis is this device's own grade: identifier_match when at
	// least one of its matched rows tied through bundle_id or team_id,
	// name_match_only when every matched row tied through the display name.
	EvidenceBasis string `json:"evidence_basis"`
}

// Artefact is one path a removal would be expected to delete.
type Artefact struct {
	Path string `json:"path"`
	// Basis is "observed_paths" when at least one device reported this exact
	// path, "known_app_bundles" when it comes from the learned path table
	// and no device in scope reported it.
	Basis       string `json:"basis"`
	DeviceCount int    `json:"device_count"`
}

// ResidueItem is something a removal leaves behind. Residue is always
// reported as remaining, never as removed: the platform does not delete user
// data and must not imply that it does.
type ResidueItem struct {
	Description string `json:"description"`
	Basis       string `json:"basis"`
}

// ProtectedMatch mirrors protectedsoftware.Match for storage and transport.
type ProtectedMatch struct {
	ID          int64  `json:"id"`
	Category    string `json:"category"`
	Vendor      string `json:"vendor"`
	ProductName string `json:"product_name"`
	IsBaseline  bool   `json:"is_baseline"`
}

// Preview is one dry-run computation over current inventory.
type Preview struct {
	ComputedAt    time.Time       `json:"computed_at"`
	DeviceCount   int             `json:"device_count"`
	VersionSpread []VersionBucket `json:"version_spread"`
	Devices       []DeviceRow     `json:"devices"`
	// EvidenceBasis is the weakest-instance grade across every matched
	// device: one name-only device downgrades the whole preview.
	EvidenceBasis string `json:"evidence_basis"`
	// DevicesWithoutAppInventory counts tenant devices in the platform scope
	// that have never reported a single application row. They are neither in
	// nor out of scope. The platform has no authority to state the product
	// is absent from them, so they are surfaced rather than assumed clean.
	DevicesWithoutAppInventory  int           `json:"devices_without_app_inventory"`
	Artefacts                   []Artefact    `json:"artefacts"`
	ArtefactBasis               string        `json:"artefact_basis"`
	ArtefactEnumerationComplete bool          `json:"artefact_enumeration_complete"`
	Residue                     []ResidueItem `json:"residue"`
	// ProtectedMatch is non-nil when the target is protected for this
	// tenant. Protection is scoped to a product and a tenant, never to a
	// device, so a match excludes every candidate device at once.
	ProtectedMatch      *ProtectedMatch `json:"protected_match"`
	ExcludedDeviceCount int             `json:"excluded_device_count"`
	// InventoryWatermark is max(devices.last_seen) across the whole tenant
	// at compute time. nil means the tenant had no devices at all.
	InventoryWatermark *time.Time `json:"inventory_watermark"`
}

// residueAlwaysPresent is the fixed residue statement every preview carries.
// It is deliberately not conditional on the product: the platform has no
// per-product knowledge of what a vendor leaves behind, and inventing a
// product-specific list would be a claim without evidence. "not_enumerated"
// says exactly that.
func residueAlwaysPresent() []ResidueItem {
	return []ResidueItem{
		{
			Description: "User data under each signed-in user's home directory (application support, caches, preferences and containers) is not removed and remains on the device.",
			Basis:       "not_enumerated",
		},
		{
			Description: "Licence records, vendor account state and configuration held outside the application bundle remain on the device.",
			Basis:       "not_enumerated",
		},
		{
			Description: "System-level components a vendor installs outside the application bundle (launch daemons, kernel or system extensions, services, drivers) are not enumerated here and are not claimed to be removed.",
			Basis:       "not_enumerated",
		},
	}
}

// Compute builds a preview of what removing t from tenantID would affect,
// from inventory as it stands right now. It writes nothing.
func Compute(ctx context.Context, q Querier, tenantID string, t Target) (Preview, error) {
	p := Preview{
		ComputedAt: time.Now().UTC(),
		// Never true in anything this ticket can compute: the platform has
		// no vendor uninstall manifest, so no artefact list it produces is
		// the complete list of what a removal deletes.
		ArtefactEnumerationComplete: false,
		Residue:                     residueAlwaysPresent(),
		VersionSpread:               []VersionBucket{},
		Devices:                     []DeviceRow{},
		Artefacts:                   []Artefact{},
		EvidenceBasis:               EvidenceUnknown,
		ArtefactBasis:               ArtefactBasisNone,
	}

	platform := normalisePlatform(t.Platform)

	// Matched inventory. devices is scoped to the tenant FIRST and
	// device_apps joined to it, never the other way round: joining
	// device_apps on identity alone and decorating with devices afterwards
	// is the cross-tenant leak PAT-729 found in the drift report.
	rows, err := q.Query(ctx, `
		SELECT dv.id::text,
		       COALESCE(dv.hostname, ''),
		       COALESCE(dv.os, ''),
		       COALESCE(da.version, ''),
		       COALESCE(da.path, ''),
		       (($2::text IS NOT NULL AND da.identifier = $2::text)
		         OR ($3::text IS NOT NULL AND da.team_id = $3::text)) AS identifier_matched
		FROM devices dv
		JOIN device_apps da ON da.device_id = dv.id AND (
		    ($4::text IS NOT NULL AND lower(da.name) = lower($4::text))
		    OR ($2::text IS NOT NULL AND da.identifier = $2::text)
		    OR ($3::text IS NOT NULL AND da.team_id = $3::text)
		)
		WHERE dv.tenant_id = $1::uuid
		  AND ($5::text = 'any' OR lower(dv.os) = $5::text)
		ORDER BY dv.id, da.version
		LIMIT $6
	`, tenantID, t.BundleID, t.TeamID, t.Name, platform, MaxMatchedRows+1)
	if err != nil {
		return p, fmt.Errorf("query matched inventory: %w", err)
	}
	defer rows.Close()

	type deviceAccum struct {
		row          DeviceRow
		versions     map[string]bool
		paths        map[string]bool
		identifierOK bool
	}
	order := []string{}
	byDevice := map[string]*deviceAccum{}
	observedPathDevices := map[string]map[string]bool{}
	rowCount := 0

	for rows.Next() {
		var deviceID, hostname, os, version, path string
		var identifierMatched bool
		if err := rows.Scan(&deviceID, &hostname, &os, &version, &path, &identifierMatched); err != nil {
			return p, fmt.Errorf("scan matched inventory: %w", err)
		}
		rowCount++
		if rowCount > MaxMatchedRows {
			return p, ErrTooManyMatches
		}

		d, ok := byDevice[deviceID]
		if !ok {
			d = &deviceAccum{
				row:      DeviceRow{DeviceID: deviceID, Hostname: hostname, OS: os},
				versions: map[string]bool{},
				paths:    map[string]bool{},
			}
			byDevice[deviceID] = d
			order = append(order, deviceID)
		}
		if identifierMatched {
			d.identifierOK = true
		}
		v := strings.TrimSpace(version)
		if v == "" {
			v = UnknownVersion
		}
		d.versions[v] = true
		if appPath := strings.TrimSpace(path); appPath != "" {
			d.paths[appPath] = true
			if observedPathDevices[appPath] == nil {
				observedPathDevices[appPath] = map[string]bool{}
			}
			observedPathDevices[appPath][deviceID] = true
		}
	}
	if err := rows.Err(); err != nil {
		return p, fmt.Errorf("matched inventory rows: %w", err)
	}

	// Version spread counts DEVICES per version, not rows: a device with the
	// same version recorded twice is one device on one version.
	versionDevices := map[string]int{}
	identifierMatchedDevices := 0
	for _, id := range order {
		d := byDevice[id]
		d.row.Versions = sortedKeys(d.versions)
		d.row.Paths = sortedKeys(d.paths)
		if d.identifierOK {
			d.row.EvidenceBasis = EvidenceIdentifierMatch
			identifierMatchedDevices++
		} else {
			d.row.EvidenceBasis = EvidenceNameMatchOnly
		}
		for v := range d.versions {
			versionDevices[v]++
		}
		p.Devices = append(p.Devices, d.row)
	}
	p.DeviceCount = len(order)
	p.EvidenceBasis = weakestEvidence(p.DeviceCount, identifierMatchedDevices)

	for _, v := range sortedKeysInt(versionDevices) {
		p.VersionSpread = append(p.VersionSpread, VersionBucket{Version: v, DeviceCount: versionDevices[v]})
	}

	// Devices with no application inventory at all. Not "clean" — unknown.
	if err := q.QueryRow(ctx, `
		SELECT count(*)::int
		FROM devices dv
		WHERE dv.tenant_id = $1::uuid
		  AND ($2::text = 'any' OR lower(dv.os) = $2::text)
		  AND NOT EXISTS (SELECT 1 FROM device_apps da WHERE da.device_id = dv.id)
	`, tenantID, platform).Scan(&p.DevicesWithoutAppInventory); err != nil {
		return p, fmt.Errorf("count devices without app inventory: %w", err)
	}

	// Artefacts: paths devices actually reported, plus whatever
	// known_app_bundles (PAT-806) learned for this display name. Both are
	// best effort and neither is authoritative, which is what
	// ArtefactEnumerationComplete = false records.
	artefacts, basis, err := computeArtefacts(ctx, q, t, platform, observedPathDevices)
	if err != nil {
		return p, err
	}
	p.Artefacts = artefacts
	p.ArtefactBasis = basis

	// Protected-software check. Reuses PAT-1801's enforcement directly:
	// there is exactly one protected list and exactly one check against it.
	match, err := protectedsoftware.Check(ctx, q, tenantID, t.Identity())
	if err != nil {
		return p, fmt.Errorf("protected software check: %w", err)
	}
	if match != nil {
		p.ProtectedMatch = &ProtectedMatch{
			ID:          match.ID,
			Category:    match.Category,
			Vendor:      match.Vendor,
			ProductName: match.ProductName,
			IsBaseline:  match.IsBaseline,
		}
		// Every candidate device is excluded: protection is per product per
		// tenant, so there is no partial case to represent.
		p.ExcludedDeviceCount = p.DeviceCount
	}

	// Tenant-wide inventory watermark. See the migration comment for why
	// tenant-wide and not matched-devices-only.
	watermark, err := InventoryWatermark(ctx, q, tenantID)
	if err != nil {
		return p, err
	}
	p.InventoryWatermark = watermark.LastUpload

	return p, nil
}

func computeArtefacts(ctx context.Context, q Querier, t Target, platform string, observed map[string]map[string]bool) ([]Artefact, string, error) {
	artefacts := make([]Artefact, 0, len(observed))
	for _, path := range sortedKeysDeviceSet(observed) {
		artefacts = append(artefacts, Artefact{
			Path:        path,
			Basis:       ArtefactBasisObserved,
			DeviceCount: len(observed[path]),
		})
	}

	var known []string
	if t.Name != nil && strings.TrimSpace(*t.Name) != "" {
		rows, err := q.Query(ctx, `
			SELECT app_path FROM known_app_bundles
			WHERE lower(name) = lower($1::text)
			  AND ($2::text = 'any' OR platform = $2::text)
			ORDER BY app_path
		`, *t.Name, platform)
		if err != nil {
			return nil, "", fmt.Errorf("query known app bundles: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			var p string
			if err := rows.Scan(&p); err != nil {
				return nil, "", fmt.Errorf("scan known app bundle: %w", err)
			}
			if strings.TrimSpace(p) == "" || observed[p] != nil {
				continue
			}
			known = append(known, p)
		}
		if err := rows.Err(); err != nil {
			return nil, "", fmt.Errorf("known app bundle rows: %w", err)
		}
	}
	for _, p := range known {
		artefacts = append(artefacts, Artefact{Path: p, Basis: ArtefactBasisKnown, DeviceCount: 0})
	}

	switch {
	case len(observed) > 0 && len(known) > 0:
		return artefacts, ArtefactBasisObservedAndKnown, nil
	case len(observed) > 0:
		return artefacts, ArtefactBasisObserved, nil
	case len(known) > 0:
		return artefacts, ArtefactBasisKnown, nil
	default:
		return artefacts, ArtefactBasisNone, nil
	}
}

// Watermark is the tenant's inventory state at a point in time: the most
// recent upload from any of its devices, and how many devices it has.
type Watermark struct {
	LastUpload  *time.Time
	DeviceCount int
}

// InventoryWatermark reads the tenant's current inventory watermark.
func InventoryWatermark(ctx context.Context, q Querier, tenantID string) (Watermark, error) {
	var w Watermark
	if err := q.QueryRow(ctx, `
		SELECT max(last_seen), count(*)::int FROM devices WHERE tenant_id = $1::uuid
	`, tenantID).Scan(&w.LastUpload, &w.DeviceCount); err != nil {
		return w, fmt.Errorf("read inventory watermark: %w", err)
	}
	return w, nil
}

func normalisePlatform(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case "macos", "windows", "any":
		return p
	default:
		return "any"
	}
}

// weakestEvidence applies the PAT-1725 rule: a set is only as strong as its
// worst-evidenced member.
func weakestEvidence(deviceCount, identifierMatched int) string {
	switch {
	case deviceCount == 0:
		return EvidenceUnknown
	case identifierMatched == deviceCount:
		return EvidenceIdentifierMatch
	default:
		return EvidenceNameMatchOnly
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysInt(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysDeviceSet(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
