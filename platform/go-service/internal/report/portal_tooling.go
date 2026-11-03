// GET /v1/portal/ai-tooling/* (PAT-2021, for the PAT-2000 AI Tooling tab).
// Read-only views over the IDE extension, package, local model and MCP
// server evidence stored on the software observation seam: per device, the
// newest collection_status per block (tooling_device_state) and the current
// items (tooling_current_entries). Category tags for the same items are the
// PAT-2015 /v1/portal/tagged-products view.
//
// Absence requires authority. A block whose newest report is failed, or a
// device that never reported the block, has null counts, never 0: "we could
// not read it" must not read as "there is none". A partial block's counts
// are marked lower_bound. Current items older than their unit's newest
// authoritative report are never counted (defence in depth beside the
// extractor's prune under the per-device lock).
//
// Every query is scoped to the caller's tenant.
package report

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Tooling blocks, in response order.
var toolingBlocks = []string{"ide_extensions", "package_managers", "local_models", "mcp_servers"}

const toolingAssessmentFreshness = 26 * time.Hour

// toolingCountedStatuses are the statuses whose items are shown.
const toolingCountedStatusesSQL = "('complete','partial','not_present')"

// toolingCurrentCTE: $1 = tenant id. Defines tenant_devices, block_state
// (real reports only) and current_items (items of counted blocks and
// counted units, at or after their unit's authority).
const toolingCurrentCTE = `
	WITH tenant_devices AS (
		SELECT d.id, d.hostname, d.os FROM devices d WHERE d.tenant_id = $1::uuid
	), block_state AS (
		SELECT s.*
		FROM tooling_device_state s
		JOIN tenant_devices td ON td.id = s.device_id
		WHERE s.tenant_id = $1::uuid AND s.reported_at > '-infinity'::timestamptz
	), current_items AS (
		SELECT c.device_id, c.block, c.unit, c.entry_kind, c.entry_key,
		       c.observation_id, c.observed_at,
		       so.identity_kind, so.identity_value_normalized AS value, so.companion_value_normalized AS companion,
		       so.observed_name, so.observed_version, so.observed_publisher
		FROM tooling_current_entries c
		JOIN block_state s ON s.device_id = c.device_id AND s.block = c.block
		JOIN software_observations so ON so.id = c.observation_id AND so.tenant_id = $1::uuid
		WHERE c.tenant_id = $1::uuid
		  AND s.collection_status IN ` + toolingCountedStatusesSQL + `
		  -- a unit whose own newest status is failed shows nothing, not
		  -- its last known items (ide_extensions has no units: its unit is '')
		  AND COALESCE(s.unit_statuses ->> c.unit, s.collection_status) IN ` + toolingCountedStatusesSQL + `
		  AND c.observed_at >= COALESCE((s.authority ->> c.unit)::timestamptz, '-infinity'::timestamptz)
	)`

// ToolingStatusCounts is how many of the tenant's devices report a block in
// each status. not_reported is every device with no report of the block.
type ToolingStatusCounts struct {
	Complete    int `json:"complete"`
	Partial     int `json:"partial"`
	NotPresent  int `json:"not_present"`
	Failed      int `json:"failed"`
	NotReported int `json:"not_reported"`
}

// ToolingItemCounts: installed is item-per-device-per-user rows, distinct is
// distinct identities, devices is devices with at least one.
type ToolingItemCounts struct {
	Installed int `json:"installed"`
	Distinct  int `json:"distinct"`
	Devices   int `json:"devices"`
}

type ToolingModelSummary struct {
	Models               ToolingItemCounts `json:"models"`
	RuntimeInstallations ToolingItemCounts `json:"runtime_installations"`
	// TotalBytes sums each counted device's newest reported store total
	// (blobs shared between models counted once, as the agent reports it).
	TotalBytes int64 `json:"total_bytes"`
	// LowerBoundDevices is how many of those devices reported partial, so
	// their bytes are a floor.
	LowerBoundDevices int `json:"lower_bound_devices"`
}

type ToolingSummary struct {
	GeneratedAt time.Time `json:"generated_at"`
	DeviceCount int       `json:"device_count"`
	// DevicesWithTooling is the exact distinct number with at least one
	// authority-valid current item across all four blocks.
	DevicesWithTooling int                            `json:"devices_with_tooling"`
	CollectionStatus   map[string]ToolingStatusCounts `json:"collection_status"`
	IDEExtensions      ToolingItemCounts              `json:"ide_extensions"`
	Packages           map[string]ToolingItemCounts   `json:"packages"`
	LocalModels        ToolingModelSummary            `json:"local_models"`
	MCPServers         ToolingItemCounts              `json:"mcp_servers"`
	MCPServersByClient map[string]ToolingItemCounts   `json:"mcp_servers_by_client"`
	// VulnerabilityProducts is one exact identity/version assessment rolled
	// up across devices. A pending or not_assessed row always has null counts.
	VulnerabilityProducts []ToolingVulnerabilityProduct `json:"vulnerability_products"`
}

// ToolingVulnerabilityProduct is the additive PAT-2109 assessment contract.
// AdvisorySources carries provenance (osv or nvd); advisory identifiers are
// never represented as CVEs unless canonical_cve_id was present upstream.
type ToolingVulnerabilityProduct struct {
	SubjectKind     string   `json:"subject_kind"`
	Ecosystem       *string  `json:"ecosystem"`
	Identity        string   `json:"identity"`
	Source          string   `json:"source"`
	Version         string   `json:"version"`
	State           string   `json:"state"`
	Reason          *string  `json:"reason"`
	FindingCount    *int     `json:"finding_count"`
	HighestSeverity *string  `json:"highest_severity"`
	DeviceCount     int      `json:"device_count"`
	AdvisorySources []string `json:"advisory_sources"`
}

// FetchToolingSummary returns the estate summary for the AI Tooling tab.
func FetchToolingSummary(ctx context.Context, pool *pgxpool.Pool, tenantID string) (ToolingSummary, error) {
	out := ToolingSummary{
		GeneratedAt: time.Now().UTC(), CollectionStatus: map[string]ToolingStatusCounts{},
		Packages: map[string]ToolingItemCounts{}, MCPServersByClient: map[string]ToolingItemCounts{},
	}
	for _, src := range []string{"npm_global", "pip_user", "pipx"} {
		out.Packages[src] = ToolingItemCounts{}
	}
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM devices WHERE tenant_id = $1::uuid`, tenantID).Scan(&out.DeviceCount); err != nil {
		return out, fmt.Errorf("tooling summary devices: %w", err)
	}
	if err := pool.QueryRow(ctx, toolingCurrentCTE+`
		SELECT count(DISTINCT device_id)::int FROM current_items`, tenantID).Scan(&out.DevicesWithTooling); err != nil {
		return out, fmt.Errorf("tooling summary distinct devices: %w", err)
	}

	for _, b := range toolingBlocks {
		out.CollectionStatus[b] = ToolingStatusCounts{NotReported: out.DeviceCount}
	}
	rows, err := pool.Query(ctx, toolingCurrentCTE+`
		SELECT block, collection_status, count(*)::int FROM block_state GROUP BY 1, 2`, tenantID)
	if err != nil {
		return out, fmt.Errorf("tooling summary statuses: %w", err)
	}
	for rows.Next() {
		var block, status string
		var n int
		if err := rows.Scan(&block, &status, &n); err != nil {
			rows.Close()
			return out, err
		}
		c := out.CollectionStatus[block]
		switch status {
		case "complete":
			c.Complete += n
		case "partial":
			c.Partial += n
		case "not_present":
			c.NotPresent += n
		case "failed":
			c.Failed += n
		}
		c.NotReported -= n
		out.CollectionStatus[block] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	// Item counts: per (block, entry kind, unit) and per (block, entry kind),
	// told apart by GROUPING().
	rows, err = pool.Query(ctx, toolingCurrentCTE+`
		SELECT block, entry_kind, COALESCE(unit, ''), GROUPING(unit)::int,
		       count(*)::int,
		       count(DISTINCT (identity_kind, value, companion))::int,
		       count(DISTINCT device_id)::int
		FROM current_items
		GROUP BY GROUPING SETS ((block, entry_kind, unit), (block, entry_kind))`, tenantID)
	if err != nil {
		return out, fmt.Errorf("tooling summary items: %w", err)
	}
	for rows.Next() {
		var block, kind, unit string
		var whole int
		var c ToolingItemCounts
		if err := rows.Scan(&block, &kind, &unit, &whole, &c.Installed, &c.Distinct, &c.Devices); err != nil {
			rows.Close()
			return out, err
		}
		switch {
		case block == "ide_extensions" && whole == 1:
			out.IDEExtensions = c
		case block == "package_managers" && whole == 0:
			out.Packages[unit] = c
		case block == "local_models" && kind == "model" && whole == 1:
			out.LocalModels.Models = c
		case block == "local_models" && kind == "runtime_installation" && whole == 1:
			out.LocalModels.RuntimeInstallations = c
		case block == "mcp_servers" && whole == 1:
			out.MCPServers = c
		case block == "mcp_servers" && whole == 0:
			out.MCPServersByClient[unit] = c
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return out, err
	}

	if err := pool.QueryRow(ctx, toolingCurrentCTE+`
		SELECT COALESCE(sum((summary -> 'totals' ->> 'total_bytes')::bigint), 0)::bigint,
		       count(*) FILTER (WHERE collection_status = 'partial')::int
		FROM block_state
		WHERE block = 'local_models' AND collection_status IN `+toolingCountedStatusesSQL, tenantID).Scan(
		&out.LocalModels.TotalBytes, &out.LocalModels.LowerBoundDevices); err != nil {
		return out, fmt.Errorf("tooling summary bytes: %w", err)
	}
	products, err := fetchToolingVulnerabilityProducts(ctx, pool, tenantID, nil)
	if err != nil {
		return out, fmt.Errorf("tooling summary vulnerabilities: %w", err)
	}
	out.VulnerabilityProducts = rollupToolingVulnerabilityProducts(products)
	return out, nil
}

// ToolingDeviceBlock is one block on one device. Counts are null unless the
// newest report is complete, partial or not_present.
type ToolingDeviceBlock struct {
	// CollectionStatus is the newest report's status, or not_reported.
	CollectionStatus string `json:"collection_status"`
	// Units are the newest report's per-unit statuses: package sources,
	// model runtimes or MCP clients. Empty for ide_extensions.
	Units      map[string]string `json:"units"`
	ReportedAt *time.Time        `json:"reported_at"`
	// LowerBound: the newest report was partial, so counts are a floor.
	LowerBound bool `json:"lower_bound"`
	// ItemCount: extensions, packages, models or servers.
	ItemCount *int `json:"item_count"`
	// ItemsByUnit: per unit; null for a unit whose own status is failed.
	ItemsByUnit map[string]*int `json:"items_by_unit"`
}

type ToolingDeviceModels struct {
	ToolingDeviceBlock
	RuntimeInstallationCount *int `json:"runtime_installation_count"`
	// TotalBytes is the newest report's total for the device's model stores.
	TotalBytes *int64 `json:"total_bytes"`
}

type ToolingDevice struct {
	DeviceID              string                        `json:"device_id"`
	Hostname              *string                       `json:"hostname"`
	Platform              string                        `json:"platform"`
	IDEExtensions         ToolingDeviceBlock            `json:"ide_extensions"`
	PackageManagers       ToolingDeviceBlock            `json:"package_managers"`
	LocalModels           ToolingDeviceModels           `json:"local_models"`
	MCPServers            ToolingDeviceBlock            `json:"mcp_servers"`
	VulnerabilityProducts []ToolingVulnerabilityProduct `json:"vulnerability_products"`
}

type ToolingDevicePage struct {
	GeneratedAt time.Time       `json:"generated_at"`
	Total       int             `json:"total"`
	Devices     []ToolingDevice `json:"devices"`
}

func toolingPlatform(os string) string {
	o := strings.ToLower(strings.TrimSpace(os))
	switch {
	case strings.HasPrefix(o, "windows"):
		return "windows"
	case strings.HasPrefix(o, "mac"), strings.HasPrefix(o, "darwin"):
		return "macos"
	}
	return "unknown"
}

func newToolingBlock() ToolingDeviceBlock {
	return ToolingDeviceBlock{CollectionStatus: "not_reported", Units: map[string]string{}, ItemsByUnit: map[string]*int{}}
}

func toolingCounted(status string) bool {
	return status == "complete" || status == "partial" || status == "not_present"
}

// FetchToolingDevices returns one page of every tenant device (ordered by
// hostname) with its per-block state and counts.
func FetchToolingDevices(ctx context.Context, pool *pgxpool.Pool, tenantID string, limit, offset int) (ToolingDevicePage, error) {
	page := ToolingDevicePage{GeneratedAt: time.Now().UTC(), Devices: []ToolingDevice{}}
	if err := pool.QueryRow(ctx, `SELECT count(*)::int FROM devices WHERE tenant_id = $1::uuid`, tenantID).Scan(&page.Total); err != nil {
		return page, fmt.Errorf("tooling devices total: %w", err)
	}
	rows, err := pool.Query(ctx, `
		SELECT id::text, hostname, COALESCE(os, '')
		FROM devices WHERE tenant_id = $1::uuid
		ORDER BY hostname ASC NULLS LAST, id ASC
		LIMIT $2 OFFSET $3`, tenantID, limit, offset)
	if err != nil {
		return page, fmt.Errorf("tooling devices page: %w", err)
	}
	index := map[string]int{}
	var ids []string
	for rows.Next() {
		var d ToolingDevice
		var os string
		if err := rows.Scan(&d.DeviceID, &d.Hostname, &os); err != nil {
			rows.Close()
			return page, err
		}
		d.Platform = toolingPlatform(os)
		d.VulnerabilityProducts = []ToolingVulnerabilityProduct{}
		d.IDEExtensions, d.PackageManagers, d.MCPServers = newToolingBlock(), newToolingBlock(), newToolingBlock()
		d.LocalModels = ToolingDeviceModels{ToolingDeviceBlock: newToolingBlock()}
		index[d.DeviceID] = len(page.Devices)
		ids = append(ids, d.DeviceID)
		page.Devices = append(page.Devices, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(ids) == 0 {
		return page, nil
	}

	blockOf := func(d *ToolingDevice, block string) *ToolingDeviceBlock {
		switch block {
		case "ide_extensions":
			return &d.IDEExtensions
		case "package_managers":
			return &d.PackageManagers
		case "local_models":
			return &d.LocalModels.ToolingDeviceBlock
		case "mcp_servers":
			return &d.MCPServers
		}
		return nil
	}

	rows, err = pool.Query(ctx, `
		SELECT device_id::text, block, collection_status, unit_statuses, reported_at,
		       (summary -> 'totals' ->> 'total_bytes')::bigint
		FROM tooling_device_state
		WHERE tenant_id = $1::uuid AND device_id = ANY($2::text[]::uuid[])
		  AND reported_at > '-infinity'::timestamptz`, tenantID, ids)
	if err != nil {
		return page, fmt.Errorf("tooling device states: %w", err)
	}
	for rows.Next() {
		var deviceID, block, status string
		var units []byte
		var reported time.Time
		var bytes *int64
		if err := rows.Scan(&deviceID, &block, &status, &units, &reported, &bytes); err != nil {
			rows.Close()
			return page, err
		}
		d := &page.Devices[index[deviceID]]
		b := blockOf(d, block)
		if b == nil {
			continue
		}
		b.CollectionStatus, b.LowerBound = status, status == "partial"
		r := reported
		b.ReportedAt = &r
		if err := json.Unmarshal(units, &b.Units); err != nil {
			rows.Close()
			return page, fmt.Errorf("tooling device units: %w", err)
		}
		if toolingCounted(status) {
			zero := 0
			b.ItemCount = &zero
			for unit, st := range b.Units {
				if toolingCounted(st) {
					z := 0
					b.ItemsByUnit[unit] = &z
				} else {
					b.ItemsByUnit[unit] = nil
				}
			}
			if block == "local_models" {
				zero := 0
				d.LocalModels.RuntimeInstallationCount = &zero
				d.LocalModels.TotalBytes = bytes
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return page, err
	}

	rows, err = pool.Query(ctx, toolingCurrentCTE+`
		SELECT device_id::text, block, unit, entry_kind, count(*)::int
		FROM current_items
		WHERE device_id = ANY($2::text[]::uuid[])
		GROUP BY 1, 2, 3, 4`, tenantID, ids)
	if err != nil {
		return page, fmt.Errorf("tooling device counts: %w", err)
	}
	for rows.Next() {
		var deviceID, block, unit, kind string
		var n int
		if err := rows.Scan(&deviceID, &block, &unit, &kind, &n); err != nil {
			rows.Close()
			return page, err
		}
		d := &page.Devices[index[deviceID]]
		b := blockOf(d, block)
		if b == nil || b.ItemCount == nil {
			continue
		}
		if kind == "runtime_installation" {
			*d.LocalModels.RuntimeInstallationCount += n
			continue
		}
		*b.ItemCount += n
		if c, ok := b.ItemsByUnit[unit]; ok && c != nil {
			*c += n
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return page, err
	}
	products, err := fetchToolingVulnerabilityProducts(ctx, pool, tenantID, ids)
	if err != nil {
		return page, fmt.Errorf("tooling device vulnerabilities: %w", err)
	}
	for deviceID, ps := range products {
		if i, ok := index[deviceID]; ok {
			page.Devices[i].VulnerabilityProducts = ps
		}
	}
	return page, nil
}

func fetchToolingVulnerabilityProducts(ctx context.Context, pool *pgxpool.Pool, tenantID string, deviceIDs []string) (map[string][]ToolingVulnerabilityProduct, error) {
	rows, err := pool.Query(ctx, `
		SELECT a.device_id::text,a.subject_kind,a.ecosystem,a.identity_value,a.companion,a.version,
		       CASE WHEN a.state='assessed' AND a.assessed_at < now()-($3::bigint * interval '1 second')
		            THEN 'pending' ELSE a.state END,
		       CASE WHEN a.state='assessed' AND a.assessed_at < now()-($3::bigint * interval '1 second')
		            THEN 'advisory_refresh_stale' ELSE a.reason END,
		       CASE WHEN a.state='assessed' AND a.assessed_at >= now()-($3::bigint * interval '1 second')
		            THEN a.finding_count END,
		       CASE WHEN a.state='assessed' AND a.assessed_at >= now()-($3::bigint * interval '1 second')
		            THEN a.highest_severity END,
		       CASE WHEN a.state='assessed' AND a.assessed_at >= now()-($3::bigint * interval '1 second')
		            THEN COALESCE(array_agg(DISTINCT f.source) FILTER (WHERE f.source IS NOT NULL),'{}'::text[])
		            ELSE '{}'::text[] END
		FROM tooling_vulnerability_assessments a
		LEFT JOIN tooling_vulnerability_findings f ON f.assessment_id=a.id
		WHERE a.tenant_id=$1::uuid AND a.active
		  AND ($2::text[] IS NULL OR a.device_id=ANY($2::text[]::uuid[]))
		GROUP BY a.id
		ORDER BY a.device_id,a.subject_kind,a.identity_value,a.companion,a.version`, tenantID, deviceIDs, int64(toolingAssessmentFreshness/time.Second))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]ToolingVulnerabilityProduct{}
	for rows.Next() {
		var deviceID string
		var p ToolingVulnerabilityProduct
		if err := rows.Scan(&deviceID, &p.SubjectKind, &p.Ecosystem, &p.Identity, &p.Source, &p.Version,
			&p.State, &p.Reason, &p.FindingCount, &p.HighestSeverity, &p.AdvisorySources); err != nil {
			return nil, err
		}
		p.DeviceCount = 1
		out[deviceID] = append(out[deviceID], p)
	}
	return out, rows.Err()
}

func rollupToolingVulnerabilityProducts(byDevice map[string][]ToolingVulnerabilityProduct) []ToolingVulnerabilityProduct {
	type productKey struct {
		SubjectKind string
		Ecosystem   string
		Identity    string
		Source      string
		Version     string
	}
	type aggregate struct {
		product           ToolingVulnerabilityProduct
		allAssessed       bool
		assessedSignature string
		inconsistent      bool
	}
	m := map[productKey]*aggregate{}
	for _, products := range byDevice {
		for _, p := range products {
			eco := ""
			if p.Ecosystem != nil {
				eco = *p.Ecosystem
			}
			k := productKey{SubjectKind: p.SubjectKind, Ecosystem: eco, Identity: p.Identity, Source: p.Source, Version: p.Version}
			a := m[k]
			if a == nil {
				cp := p
				cp.DeviceCount = 0
				cp.FindingCount = nil
				cp.HighestSeverity = nil
				a = &aggregate{product: cp, allAssessed: true}
				m[k] = a
			}
			a.product.DeviceCount++
			if p.State != "assessed" {
				a.allAssessed = false
				if p.State == "pending" || a.product.State != "pending" {
					a.product.State = p.State
					a.product.Reason = p.Reason
				}
			}
			if p.State == "assessed" && p.FindingCount != nil {
				sources := append([]string(nil), p.AdvisorySources...)
				sort.Strings(sources)
				severity := normaliseToolingSeverity(p.HighestSeverity)
				signature := fmt.Sprintf("%d\x1f%s\x1f%s", *p.FindingCount, pointerString(severity), strings.Join(sources, "\x1e"))
				if a.assessedSignature == "" {
					a.assessedSignature = signature
					n := *p.FindingCount
					a.product.FindingCount = &n
					a.product.HighestSeverity = severity
					a.product.AdvisorySources = sources
				} else if signature != a.assessedSignature {
					a.inconsistent = true
				}
			}
		}
	}
	out := make([]ToolingVulnerabilityProduct, 0, len(m))
	for _, a := range m {
		if a.allAssessed && a.inconsistent {
			a.product.State = "pending"
			reason := "assessment_results_inconsistent"
			a.product.Reason = &reason
			a.product.FindingCount = nil
			a.product.HighestSeverity = nil
			a.product.AdvisorySources = []string{}
		} else if !a.allAssessed {
			a.product.FindingCount = nil
			a.product.HighestSeverity = nil
			a.product.AdvisorySources = []string{}
		}
		sort.Strings(a.product.AdvisorySources)
		out = append(out, a.product)
	}
	sort.Slice(out, func(i, j int) bool {
		ecosystem := func(p ToolingVulnerabilityProduct) string {
			if p.Ecosystem == nil {
				return ""
			}
			return *p.Ecosystem
		}
		return strings.Join([]string{out[i].SubjectKind, ecosystem(out[i]), out[i].Identity, out[i].Source, out[i].Version}, "\x1f") < strings.Join([]string{out[j].SubjectKind, ecosystem(out[j]), out[j].Identity, out[j].Source, out[j].Version}, "\x1f")
	})
	return out
}

func higherToolingSeverity(a, b *string) *string {
	rank := map[string]int{"UNKNOWN": 1, "NONE": 2, "LOW": 3, "MEDIUM": 4, "HIGH": 5, "CRITICAL": 6}
	a = normaliseToolingSeverity(a)
	b = normaliseToolingSeverity(b)
	if b == nil {
		return a
	}
	if a == nil || rank[*b] > rank[*a] {
		v := *b
		return &v
	}
	return a
}

func normaliseToolingSeverity(v *string) *string {
	if v == nil {
		return nil
	}
	switch *v {
	case "UNKNOWN", "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return v
	default:
		unknown := "UNKNOWN"
		return &unknown
	}
}

func pointerString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}
