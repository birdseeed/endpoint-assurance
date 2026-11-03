package report

// PAT-2205's authoritative AI-tooling evidence builder. HTTP JSON, CSV and
// the generated PDF all project this type. Queries select an allowlist of
// typed fields from tooling_observation_details; the raw attributes object is
// never decoded or serialised.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/extpresence"
	"patched.im/api/internal/softwaregov"
)

const ToolingEvidenceMaxItems = 50000

var ErrToolingEvidenceTooLarge = errors.New("AI tooling evidence exceeds the bounded report size")

// ToolingApprovalTarget is exactly the item shape accepted by
// PUT /v1/portal/software-approvals for a named observation.
type ToolingApprovalTarget struct {
	Type         string  `json:"type"`
	Platform     *string `json:"platform"`
	Identifier   *string `json:"identifier"`
	TeamID       *string `json:"team_id"`
	Browser      *string `json:"browser"`
	ExtensionID  *string `json:"extension_id"`
	Name         *string `json:"name"`
	Tap          *string `json:"tap"`
	IdentityKind *string `json:"identity_kind"`
	Source       *string `json:"source"`
}

type ToolingAdvisoryReference struct {
	Source         string     `json:"source"`
	AdvisoryID     string     `json:"advisory_id"`
	CanonicalCVEID *string    `json:"canonical_cve_id"`
	Severity       *string    `json:"severity"`
	Score          *float64   `json:"score"`
	PublishedAt    *time.Time `json:"published_at"`
	ModifiedAt     *time.Time `json:"modified_at"`
	SyncedAt       time.Time  `json:"synced_at"`
}

type ToolingEvidenceProvenance struct {
	ItemID          string     `json:"item_id"`
	InputObservedAt time.Time  `json:"input_observed_at"`
	AssessedAt      *time.Time `json:"assessed_at"`
	FreshUntil      *time.Time `json:"fresh_until"`
	Fresh           bool       `json:"fresh"`
}

type ToolingItemAssessment struct {
	SubjectKind       string                     `json:"subject_kind"`
	Ecosystem         *string                    `json:"ecosystem"`
	Identity          string                     `json:"identity"`
	Source            string                     `json:"source"`
	Version           string                     `json:"version"`
	State             string                     `json:"state"`
	UnsupportedReason *string                    `json:"unsupported_reason"`
	FindingCount      *int                       `json:"finding_count"`
	HighestSeverity   *string                    `json:"highest_severity"`
	Provenance        ToolingEvidenceProvenance  `json:"evidence_provenance"`
	Advisories        []ToolingAdvisoryReference `json:"advisories"`

	id int64
}

// ToolingEvidenceItem deliberately has no attributes, paths, user identities,
// command arguments, environment, prompt/content or raw URL field.
type ToolingEvidenceItem struct {
	ItemID            string                 `json:"item_id"`
	DeviceID          string                 `json:"device_id"`
	Hostname          string                 `json:"hostname"`
	Platform          string                 `json:"platform"`
	Block             string                 `json:"block"`
	Unit              string                 `json:"unit"`
	EntryKind         string                 `json:"entry_kind"`
	CollectionStatus  string                 `json:"collection_status"`
	LowerBound        bool                   `json:"lower_bound"`
	IdentityKind      string                 `json:"identity_kind"`
	Identity          string                 `json:"identity"`
	Source            string                 `json:"source"`
	Name              string                 `json:"name"`
	Version           *string                `json:"version"`
	Publisher         *string                `json:"publisher"`
	ObservedAt        time.Time              `json:"observed_at"`
	PolicyState       string                 `json:"policy_state"`
	ApprovalTarget    *ToolingApprovalTarget `json:"approval_target"`
	Family            *string                `json:"family,omitempty"`
	Editor            *string                `json:"editor,omitempty"`
	EditorVersion     *string                `json:"editor_version,omitempty"`
	MarketplaceSource *string                `json:"marketplace_source,omitempty"`
	PackageManager    *string                `json:"package_manager,omitempty"`
	Scope             *string                `json:"scope,omitempty"`
	Runtime           *string                `json:"runtime,omitempty"`
	ModelTag          *string                `json:"model_tag,omitempty"`
	ModelFormat       *string                `json:"model_format,omitempty"`
	SizeBytes         *int64                 `json:"size_bytes,omitempty"`
	Transport         *string                `json:"transport,omitempty"`
	TransportSource   *string                `json:"transport_source,omitempty"`
	Runner            *string                `json:"runner,omitempty"`
	Package           *string                `json:"package,omitempty"`
	PackageStatus     *string                `json:"package_status,omitempty"`
	Host              *string                `json:"host,omitempty"`
	// LastUsedAt and MeteringState are present for tagged desktop-application
	// evidence. No equivalent browser-extension telemetry exists, so extension
	// rows explicitly carry not_applicable rather than an invented zero.
	LastUsedAt    *time.Time              `json:"last_used_at,omitempty"`
	MeteringState string                  `json:"metering_state,omitempty"`
	Assessments   []ToolingItemAssessment `json:"assessments"`

	entryKey string
}

type ToolingEvidenceCoverage struct {
	DevicesTotal       int `json:"devices_total"`
	DevicesWithTooling int `json:"devices_with_tooling"`
	LowerBoundDevices  int `json:"lower_bound_devices"`
	UnknownDevices     int `json:"unknown_devices"`
}

type ToolingEvidenceReport struct {
	GeneratedAt time.Time               `json:"generated_at"`
	TenantName  string                  `json:"tenant_name"`
	Coverage    ToolingEvidenceCoverage `json:"coverage"`
	Items       []ToolingEvidenceItem   `json:"items"`
}

type ToolingEvidencePage struct {
	GeneratedAt time.Time             `json:"generated_at"`
	DeviceID    string                `json:"device_id"`
	Total       int                   `json:"total"`
	Limit       int                   `json:"limit"`
	Offset      int                   `json:"offset"`
	Items       []ToolingEvidenceItem `json:"items"`
}

func portalToolingItemID(tenantID, deviceID, key string) string {
	s := sha256.Sum256([]byte("portal-tooling\x1f" + tenantID + "\x1f" + deviceID + "\x1f" + key))
	return "ati_" + hex.EncodeToString(s[:16])
}

func toolingEvidenceEntryRef(deviceID, entryKey string) string {
	return deviceID + "\x1f" + entryKey
}

func toolingApprovalTarget(kind, identity, source string) *ToolingApprovalTarget {
	if !softwaregov.ObservationPolicyKind(kind) || strings.TrimSpace(identity) == "" {
		return nil
	}
	t, name, k, src := "observation", identity, kind, source
	return &ToolingApprovalTarget{Type: t, Name: &name, IdentityKind: &k, Source: &src}
}

func toolingAppApprovalTarget(platform, identifier, teamID string) *ToolingApprovalTarget {
	identifier = strings.TrimSpace(identifier)
	if (platform != "macos" && platform != "windows") || identifier == "" || utf8.RuneCountInString(identifier) > 512 || strings.IndexFunc(identifier, unicode.IsControl) >= 0 {
		return nil
	}
	p, ident := platform, identifier
	t := &ToolingApprovalTarget{Type: softwaregov.TypeApplication, Platform: &p, Identifier: &ident}
	if platform == "macos" && strings.TrimSpace(teamID) != "" {
		team := strings.ToUpper(strings.TrimSpace(teamID))
		if !toolingApprovalTeamIDPattern.MatchString(team) {
			return nil
		}
		t.TeamID = &team
	}
	return t
}

func toolingExtensionApprovalTarget(browser, extensionID string) *ToolingApprovalTarget {
	browser, extensionID = strings.TrimSpace(browser), strings.TrimSpace(extensionID)
	if !toolingApprovalBrowser[browser] || !toolingApprovalExtensionIDPattern.MatchString(extensionID) {
		return nil
	}
	b, id := browser, extensionID
	return &ToolingApprovalTarget{Type: softwaregov.TypeBrowserExtension, Browser: &b, ExtensionID: &id}
}

var (
	toolingApprovalTeamIDPattern      = regexp.MustCompile(`^[A-Z0-9]{10}$`)
	toolingApprovalExtensionIDPattern = regexp.MustCompile(`^[A-Za-z0-9@._{}\-]{1,255}$`)
	toolingApprovalBrowser            = map[string]bool{"chrome": true, "edge": true, "firefox": true, "safari": true, "any": true}
)

const taggedToolingAppsSQL = `
	SELECT DISTINCT ON (si.id) si.id::text,si.device_id::text,COALESCE(d.hostname,''),si.platform,
	       si.identity_kind,si.identity_value_normalized,COALESCE(so.observed_identifier,''),
	       COALESCE(so.observed_identifier_kind,''),COALESCE(so.observed_team_id,''),
	       si.current_name,si.current_version,si.current_publisher,si.last_seen_at,
	       usage.last_used_at,usage.last_seen,usage.metering_status
	FROM software_category_tags t
	JOIN software_installations si ON si.id=t.installation_id AND si.tenant_id=t.tenant_id
	JOIN devices d ON d.id=si.device_id AND d.tenant_id=si.tenant_id
	LEFT JOIN software_observations so ON so.id=si.latest_observation_id AND so.tenant_id=si.tenant_id
	LEFT JOIN software_category_rules r ON r.id=t.rule_id
	LEFT JOIN software_category_product_tags pt ON pt.id=t.product_tag_id
	LEFT JOIN LATERAL (
		SELECT CASE WHEN da.usage_evidence IS NULL OR da.usage_evidence = 'recorded' THEN da.last_used_at END AS last_used_at,
		       COALESCE(da.usage_evidence_at, da.last_seen) AS last_seen,
		       CASE WHEN da.usage_evidence IN ('unmapped', 'unavailable') THEN 'unavailable' ELSE d.metering_status END AS metering_status
		FROM device_apps da
		WHERE da.device_id=si.device_id
		  AND NULLIF(btrim(so.observed_identifier),'') IS NOT NULL
		  AND lower(btrim(da.identifier))=lower(btrim(so.observed_identifier))
		  AND NULLIF(btrim(da.version),'') IS NOT DISTINCT FROM NULLIF(btrim(si.current_version),'')
		  AND da.last_seen >= si.last_seen_at
		ORDER BY da.last_seen DESC,da.id DESC
		LIMIT 1
	) usage ON true
	WHERE t.tenant_id=$1::uuid
	  AND t.retired_at IS NULL
	  AND t.installation_id IS NOT NULL
	  AND si.removed_at IS NULL
	  AND COALESCE(r.state,pt.state)='published'
	  AND COALESCE(r.category_key,pt.category_key)='ai_tooling'
	  AND COALESCE(r.subtype_key,pt.subtype_key)='desktop_app'
	  AND t.observation_kind='app'
	  AND ($3='' OR si.device_id=$3::uuid)
	-- One installation can carry several published category matches. Evidence
	-- has one stable item per current installation, never one per match.
	ORDER BY si.id
	LIMIT $2`

var taggedToolingExtensionsSQL = `
	SELECT DISTINCT ON (dbe.id) dbe.id::text,dbe.device_id::text,COALESCE(d.hostname,''),COALESCE(d.os,''),
	       dbe.browser,dbe.extension_id,dbe.name,dbe.version,dbe.last_seen
	FROM software_category_tags t
	JOIN device_browser_extensions dbe ON dbe.id=t.browser_extension_id AND dbe.device_id=t.device_id
	JOIN devices d ON d.id=t.device_id AND d.tenant_id=t.tenant_id
	JOIN software_category_rules r ON r.id=t.rule_id
	WHERE t.tenant_id=$1::uuid
	  AND t.retired_at IS NULL
	  AND t.observation_kind='browser_extension'
	  AND r.state='published'
	  AND r.category_key='ai_tooling' AND r.subtype_key='browser_extension'
	  AND ` + extpresence.PresentSQL("dbe", "dbe.last_seen >= d.last_seen - interval '30 days'") + `
	  AND ($3='' OR dbe.device_id=$3::uuid)
	-- A browser-extension row can carry several category matches too.
	ORDER BY dbe.id
	LIMIT $2`

func appendTaggedToolingApps(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, now time.Time, policies softwaregov.Policies, out *ToolingEvidenceReport) error {
	limit := ToolingEvidenceMaxItems - len(out.Items) + 1
	rows, err := pool.Query(ctx, taggedToolingAppsSQL, tenantID, limit, deviceID)
	if err != nil {
		return fmt.Errorf("tagged desktop app evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var installationID, identifier, identifierKind, teamID string
		var it ToolingEvidenceItem
		var usageLastSeen, lastUsed *time.Time
		var meteringStatus *string
		if err := rows.Scan(&installationID, &it.DeviceID, &it.Hostname, &it.Platform,
			&it.IdentityKind, &it.Identity, &identifier, &identifierKind, &teamID,
			&it.Name, &it.Version, &it.Publisher, &it.ObservedAt, &lastUsed, &usageLastSeen, &meteringStatus); err != nil {
			return fmt.Errorf("scan tagged desktop app evidence: %w", err)
		}
		it.Block, it.Unit, it.EntryKind, it.CollectionStatus = "desktop_apps", "", "application", "current"
		it.Source, it.LowerBound, it.Assessments = "", false, []ToolingItemAssessment{}
		it.entryKey = "tagged-app:" + installationID
		it.ItemID = portalToolingItemID(tenantID, it.DeviceID, it.entryKey)
		it.ObservedAt = it.ObservedAt.UTC()
		it.ApprovalTarget = toolingAppApprovalTarget(it.Platform, identifier, teamID)
		it.PolicyState = "unreviewed"
		if it.ApprovalTarget != nil {
			// The current installation's platform owns both the approval target
			// and its policy lookup. devices.os is only endpoint context and can
			// be stale or inconsistent with an immutable installation episode.
			it.PolicyState = policies.ResolveApp(teamID, identifier, identifierKind, it.Name, it.Platform)
		}
		it.MeteringState = "unknown"
		if usageLastSeen != nil && meteringStatus != nil {
			switch {
			case *meteringStatus != "ok":
				it.MeteringState = "unmetered"
			case usageLastSeen.Before(now.Add(-SoftwareMeteringEvidenceFreshness)):
				it.MeteringState = "stale"
			default:
				it.MeteringState, it.LastUsedAt = "metered", lastUsed
			}
		}
		out.Items = append(out.Items, it)
	}
	return rows.Err()
}

func appendTaggedToolingExtensions(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, policies softwaregov.Policies, out *ToolingEvidenceReport) error {
	limit := ToolingEvidenceMaxItems - len(out.Items) + 1
	rows, err := pool.Query(ctx, taggedToolingExtensionsSQL, tenantID, limit, deviceID)
	if err != nil {
		return fmt.Errorf("tagged browser extension evidence: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var extensionRowID, osName string
		var it ToolingEvidenceItem
		if err := rows.Scan(&extensionRowID, &it.DeviceID, &it.Hostname, &osName, &it.Source, &it.Identity, &it.Name, &it.Version, &it.ObservedAt); err != nil {
			return fmt.Errorf("scan tagged browser extension evidence: %w", err)
		}
		it.Platform = toolingPlatform(osName)
		it.Block, it.Unit, it.EntryKind, it.CollectionStatus = "browser_extensions", "", "browser_extension", "current"
		it.IdentityKind, it.LowerBound, it.Assessments = "browser_extension", false, []ToolingItemAssessment{}
		it.entryKey = "tagged-extension:" + extensionRowID
		it.ItemID = portalToolingItemID(tenantID, it.DeviceID, it.entryKey)
		it.ObservedAt = it.ObservedAt.UTC()
		it.ApprovalTarget = toolingExtensionApprovalTarget(it.Source, it.Identity)
		it.PolicyState, it.MeteringState = "unreviewed", "not_applicable"
		if it.ApprovalTarget != nil {
			it.PolicyState = policies.ResolveExtension(it.Source, it.Identity)
		}
		out.Items = append(out.Items, it)
	}
	return rows.Err()
}

// BuildToolingEvidence returns every authority-valid current item for one
// tenant. The fixed cap fails closed rather than producing a partial report.
func BuildToolingEvidence(ctx context.Context, pool *pgxpool.Pool, tenantID string, now time.Time) (ToolingEvidenceReport, error) {
	return buildToolingEvidence(ctx, pool, tenantID, "", now)
}

// BuildToolingEvidenceForDevice uses the same authoritative builder while
// bounding the item query and size guard to one tenant-owned device.
func BuildToolingEvidenceForDevice(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, now time.Time) (ToolingEvidenceReport, error) {
	return buildToolingEvidence(ctx, pool, tenantID, deviceID, now)
}

func buildToolingEvidence(ctx context.Context, pool *pgxpool.Pool, tenantID, deviceID string, now time.Time) (ToolingEvidenceReport, error) {
	now = now.UTC()
	out := ToolingEvidenceReport{GeneratedAt: now, Items: []ToolingEvidenceItem{}}
	if err := pool.QueryRow(ctx, `SELECT name FROM tenants WHERE id=$1::uuid`, tenantID).Scan(&out.TenantName); err != nil {
		return out, fmt.Errorf("tooling evidence tenant: %w", err)
	}
	if err := pool.QueryRow(ctx, toolingCurrentCTE+`, state_rollup AS (
		SELECT device_id,count(*)::int AS reported_blocks,bool_or(collection_status='partial') AS lower_bound,
		       bool_or(collection_status='failed') AS failed
		FROM block_state GROUP BY device_id
	), current_rollup AS (
		SELECT device_id FROM current_items GROUP BY device_id
	)
		SELECT count(*)::int,count(c.device_id)::int,
		       count(*) FILTER (WHERE COALESCE(s.lower_bound,false))::int,
		       count(*) FILTER (WHERE COALESCE(s.reported_blocks,0)<4 OR COALESCE(s.failed,false))::int
		FROM tenant_devices d
		LEFT JOIN state_rollup s ON s.device_id=d.id
		LEFT JOIN current_rollup c ON c.device_id=d.id`, tenantID).Scan(&out.Coverage.DevicesTotal, &out.Coverage.DevicesWithTooling,
		&out.Coverage.LowerBoundDevices, &out.Coverage.UnknownDevices); err != nil {
		return out, fmt.Errorf("tooling evidence coverage: %w", err)
	}
	policies, err := softwaregov.LoadPolicies(ctx, pool, tenantID)
	if err != nil {
		return out, fmt.Errorf("tooling evidence policies: %w", err)
	}
	rows, err := pool.Query(ctx, toolingCurrentCTE+`
		SELECT ci.device_id::text,COALESCE(td.hostname,''),COALESCE(td.os,''),ci.block,ci.unit,ci.entry_kind,ci.entry_key,
		       ci.identity_kind,ci.value,ci.companion,ci.observed_name,ci.observed_version,ci.observed_publisher,ci.observed_at,
		       s.collection_status,
		       NULLIF(d.attributes->>'family',''),NULLIF(d.attributes->>'editor',''),NULLIF(d.attributes->>'editor_version',''),
		       NULLIF(d.attributes->>'source',''),NULLIF(d.attributes->>'manager',''),NULLIF(d.attributes->>'scope',''),
		       NULLIF(d.attributes->>'runtime',''),NULLIF(d.attributes->>'tag',''),NULLIF(d.attributes->>'format',''),
		       CASE WHEN d.attributes->>'size_bytes' ~ '^[0-9]+$' THEN (d.attributes->>'size_bytes')::bigint END,
		       NULLIF(d.attributes->>'transport',''),NULLIF(d.attributes->>'transport_source',''),NULLIF(d.attributes->>'runner',''),
		       NULLIF(d.attributes->>'package',''),NULLIF(d.attributes->>'package_status',''),NULLIF(d.attributes->>'host',''),
		       NULLIF(d.attributes->>'version','')
		FROM current_items ci
		JOIN tooling_observation_details d ON d.observation_id=ci.observation_id AND d.tenant_id=$1::uuid
		JOIN block_state s ON s.device_id=ci.device_id AND s.block=ci.block
		JOIN tenant_devices td ON td.id=ci.device_id
		WHERE ($3='' OR ci.device_id=$3::uuid)
		ORDER BY lower(COALESCE(td.hostname,'')),ci.device_id,ci.block,ci.unit,ci.identity_kind,ci.value,ci.entry_key
		LIMIT $2`, tenantID, ToolingEvidenceMaxItems+1, deviceID)
	if err != nil {
		return out, fmt.Errorf("tooling evidence items: %w", err)
	}
	byKey := map[string]int{}
	for rows.Next() {
		var it ToolingEvidenceItem
		var osName string
		var attrVersion *string
		if err := rows.Scan(&it.DeviceID, &it.Hostname, &osName, &it.Block, &it.Unit, &it.EntryKind, &it.entryKey,
			&it.IdentityKind, &it.Identity, &it.Source, &it.Name, &it.Version, &it.Publisher, &it.ObservedAt,
			&it.CollectionStatus, &it.Family, &it.Editor, &it.EditorVersion, &it.MarketplaceSource,
			&it.PackageManager, &it.Scope, &it.Runtime, &it.ModelTag, &it.ModelFormat, &it.SizeBytes,
			&it.Transport, &it.TransportSource, &it.Runner, &it.Package, &it.PackageStatus, &it.Host, &attrVersion); err != nil {
			rows.Close()
			return out, fmt.Errorf("scan tooling evidence item: %w", err)
		}
		if attrVersion != nil {
			it.Version = attrVersion
		}
		it.Platform = toolingPlatform(osName)
		it.LowerBound = it.CollectionStatus == "partial"
		it.ObservedAt = it.ObservedAt.UTC()
		it.ItemID = portalToolingItemID(tenantID, it.DeviceID, it.entryKey)
		it.ApprovalTarget = toolingApprovalTarget(it.IdentityKind, it.Identity, it.Source)
		it.PolicyState = "unreviewed"
		if it.ApprovalTarget != nil {
			it.PolicyState = policies.ResolveObservation(it.IdentityKind, it.Identity, it.Source)
		}
		it.Assessments = []ToolingItemAssessment{}
		byKey[toolingEvidenceEntryRef(it.DeviceID, it.entryKey)] = len(out.Items)
		out.Items = append(out.Items, it)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > ToolingEvidenceMaxItems {
		return ToolingEvidenceReport{}, ErrToolingEvidenceTooLarge
	}
	// PAT-2206: the existing four tooling blocks are supplemented with the
	// present, server-tagged desktop applications and browser extensions. The
	// latter retains its dedicated presence authority; a stored extension is
	// never treated as current merely because it still has a category tag.
	if err := appendTaggedToolingApps(ctx, pool, tenantID, deviceID, now, policies, &out); err != nil {
		return out, err
	}
	if len(out.Items) > ToolingEvidenceMaxItems {
		return ToolingEvidenceReport{}, ErrToolingEvidenceTooLarge
	}
	if err := appendTaggedToolingExtensions(ctx, pool, tenantID, deviceID, policies, &out); err != nil {
		return out, err
	}
	if len(out.Items) > ToolingEvidenceMaxItems {
		return ToolingEvidenceReport{}, ErrToolingEvidenceTooLarge
	}
	// Coverage follows the same all-types row projection as JSON, CSV and PDF.
	// LowerBoundDevices and UnknownDevices remain the four collection-block
	// coverage measures above; desktop-app and extension presence has its own
	// lifecycle authority and is not evidence that those blocks were read.
	devicesWithEvidence := map[string]bool{}
	for _, item := range out.Items {
		devicesWithEvidence[item.DeviceID] = true
	}
	out.Coverage.DevicesWithTooling = len(devicesWithEvidence)
	if len(out.Items) == 0 {
		return out, nil
	}

	keySet := make(map[string]bool, len(byKey))
	for _, item := range out.Items {
		keySet[item.entryKey] = true
	}
	keys := make([]string, 0, len(keySet))
	for key := range keySet {
		keys = append(keys, key)
	}
	rows, err = pool.Query(ctx, `
		SELECT a.id,a.device_id::text,a.current_entry_keys,a.subject_kind,a.ecosystem,a.identity_value,a.companion,a.version,a.state,a.reason,
		       a.finding_count,a.highest_severity,a.input_observed_at,a.assessed_at
		FROM tooling_vulnerability_assessments a
		WHERE a.tenant_id=$1::uuid AND a.active AND a.current_entry_keys && $2::text[]
		ORDER BY a.id`, tenantID, keys)
	if err != nil {
		return out, fmt.Errorf("tooling evidence assessments: %w", err)
	}
	type assessmentLocation struct{ item, assessment int }
	assessmentItems := map[int64][]assessmentLocation{}
	for rows.Next() {
		var a ToolingItemAssessment
		var assessmentDeviceID string
		var entryKeys []string
		if err := rows.Scan(&a.id, &assessmentDeviceID, &entryKeys, &a.SubjectKind, &a.Ecosystem, &a.Identity, &a.Source, &a.Version,
			&a.State, &a.UnsupportedReason, &a.FindingCount, &a.HighestSeverity, &a.Provenance.InputObservedAt, &a.Provenance.AssessedAt); err != nil {
			rows.Close()
			return out, err
		}
		a.Advisories = []ToolingAdvisoryReference{}
		a.Provenance.InputObservedAt = a.Provenance.InputObservedAt.UTC()
		fresh := false
		if a.Provenance.AssessedAt != nil {
			assessed := a.Provenance.AssessedAt.UTC()
			until := assessed.Add(toolingAssessmentFreshness)
			a.Provenance.AssessedAt, a.Provenance.FreshUntil = &assessed, &until
			fresh = !now.After(until)
		}
		a.Provenance.Fresh = fresh
		if a.State == "assessed" && !fresh {
			a.State = "pending"
			reason := "advisory_refresh_stale"
			a.UnsupportedReason, a.FindingCount, a.HighestSeverity = &reason, nil, nil
		}
		for _, key := range entryKeys {
			idx, ok := byKey[toolingEvidenceEntryRef(assessmentDeviceID, key)]
			if !ok {
				continue
			}
			cp := a
			cp.Provenance.ItemID = out.Items[idx].ItemID
			assessmentIndex := len(out.Items[idx].Assessments)
			out.Items[idx].Assessments = append(out.Items[idx].Assessments, cp)
			assessmentItems[a.id] = append(assessmentItems[a.id], assessmentLocation{item: idx, assessment: assessmentIndex})
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(assessmentItems) == 0 {
		SortToolingEvidence(out.Items)
		return out, nil
	}
	ids := make([]int64, 0, len(assessmentItems))
	for id := range assessmentItems {
		ids = append(ids, id)
	}
	rows, err = pool.Query(ctx, `
		SELECT f.assessment_id,f.source,f.advisory_id,f.canonical_cve_id,f.severity,f.score,
		       a.published_at,a.modified_at,a.synced_at
		FROM tooling_vulnerability_findings f
		JOIN tooling_advisories a ON a.source=f.source AND a.advisory_id=f.advisory_id
		WHERE f.assessment_id=ANY($1::bigint[])
		ORDER BY f.assessment_id,f.source,f.advisory_id`, ids)
	if err != nil {
		return out, fmt.Errorf("tooling evidence advisories: %w", err)
	}
	for rows.Next() {
		var assessmentID int64
		var ref ToolingAdvisoryReference
		if err := rows.Scan(&assessmentID, &ref.Source, &ref.AdvisoryID, &ref.CanonicalCVEID, &ref.Severity,
			&ref.Score, &ref.PublishedAt, &ref.ModifiedAt, &ref.SyncedAt); err != nil {
			rows.Close()
			return out, err
		}
		for _, location := range assessmentItems[assessmentID] {
			assessment := &out.Items[location.item].Assessments[location.assessment]
			assessment.Advisories = append(assessment.Advisories, ref)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}
	for i := range out.Items {
		for j := range out.Items[i].Assessments {
			out.Items[i].Assessments[j].id = 0
		}
	}
	SortToolingEvidence(out.Items)
	return out, nil
}

func ToolingEvidenceForDevice(rep ToolingEvidenceReport, deviceID string) []ToolingEvidenceItem {
	out := []ToolingEvidenceItem{}
	for _, item := range rep.Items {
		if item.DeviceID == deviceID {
			out = append(out, item)
		}
	}
	return out
}

func SortToolingEvidence(items []ToolingEvidenceItem) {
	sort.SliceStable(items, func(i, j int) bool {
		return strings.Join([]string{items[i].Hostname, items[i].DeviceID, items[i].Block, items[i].Unit, items[i].Identity, items[i].ItemID}, "\x1f") <
			strings.Join([]string{items[j].Hostname, items[j].DeviceID, items[j].Block, items[j].Unit, items[j].Identity, items[j].ItemID}, "\x1f")
	})
}
