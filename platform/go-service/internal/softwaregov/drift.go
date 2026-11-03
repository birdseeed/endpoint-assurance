package softwaregov

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// TrendWeeks is the length of the drift trend.
const TrendWeeks = 26

// TopDevicesLimit caps the "most unapproved software" device list.
const TopDevicesLimit = 10

// MaxDriftProducts caps the JSON product list. The CSV export is uncapped up
// to the estate load cap.
const MaxDriftProducts = 2000

// StateCounts counts distinct products by their worst state across devices.
type StateCounts struct {
	InstalledProducts int `json:"installed_products"`
	Unapproved        int `json:"unapproved"`
	Unreviewed        int `json:"unreviewed"`
	Approved          int `json:"approved"`
	Ignored           int `json:"ignored"`
	Mandatory         int `json:"mandatory"`
	// UnapprovedDevices is the number of distinct devices carrying at least
	// one Unapproved product.
	UnapprovedDevices int `json:"unapproved_devices"`
}

// DriftProduct is one installed product that is Unapproved or Unreviewed.
type DriftProduct struct {
	Product
	ApprovalState    string    `json:"approval_state"`
	DeviceCount      int       `json:"device_count"`
	StaleDeviceCount int       `json:"stale_device_count"`
	ObservedSince    time.Time `json:"observed_since"`
}

// MarkInfo says who marked a product Unapproved and when, as far as the
// record shows. MarkedVia is "portal", "operator" or "unknown".
type MarkInfo struct {
	MarkedBy  *string   `json:"marked_by"`
	MarkedVia string    `json:"marked_via"`
	MarkedAt  time.Time `json:"marked_at"`
	// MarkedAtBasis is "decision" when MarkedAt is a recorded decision time,
	// "policy_last_updated" when it is the policy row's last update, which
	// may be later than the original decision.
	MarkedAtBasis string `json:"marked_at_basis"`
}

// UnapprovedPresent is one Unapproved product currently reported on at least
// one device.
type UnapprovedPresent struct {
	Product
	PolicyKind       string     `json:"policy_kind"`
	PolicyID         int64      `json:"policy_id"`
	DeviceCount      int        `json:"device_count"`
	StaleDeviceCount int        `json:"stale_device_count"`
	Devices          []Presence `json:"devices"`
	MarkInfo
	// PresentSince is the earliest ObservedSince across the devices.
	PresentSince time.Time `json:"present_since"`
	// Since is when this became "unapproved and present": the later of
	// MarkedAt and PresentSince.
	Since time.Time `json:"since"`
}

// TrendPoint is one week of the drift trend. Recorded is false for a week
// with no capture, and then the counts are null: an unrecorded week is
// unknown, not zero.
type TrendPoint struct {
	WeekStart           string `json:"week_start"`
	Recorded            bool   `json:"recorded"`
	Live                bool   `json:"live"`
	UnapprovedProducts  *int   `json:"unapproved_products"`
	UnreviewedProducts  *int   `json:"unreviewed_products"`
	UnapprovedDevices   *int   `json:"unapproved_devices"`
	InstalledProducts   *int   `json:"installed_products"`
	DevicesStaleAtCheck *int   `json:"devices_stale"`
}

// TopDevice is one device ranked by Unapproved product count.
type TopDevice struct {
	DeviceID                string    `json:"device_id"`
	Hostname                string    `json:"hostname"`
	Platform                string    `json:"platform"`
	UnapprovedProductCount  int       `json:"unapproved_product_count"`
	UnapprovedProductSample []string  `json:"unapproved_products"`
	LastSeen                time.Time `json:"last_seen"`
	Stale                   bool      `json:"stale"`
}

// Drift is GET /v1/portal/software/drift.
type Drift struct {
	GeneratedAt       time.Time           `json:"generated_at"`
	Coverage          Coverage            `json:"coverage"`
	Counts            StateCounts         `json:"counts"`
	Products          []DriftProduct      `json:"products"`
	ProductsTotal     int                 `json:"products_total"`
	ProductsTruncated bool                `json:"products_truncated"`
	Trend             []TrendPoint        `json:"trend"`
	TopDevices        []TopDevice         `json:"top_devices"`
	UnapprovedPresent []UnapprovedPresent `json:"unapproved_present"`
}

// CountStates reduces assessments to per-product worst-state counts.
func CountStates(assessments []Assessment) StateCounts {
	worst := map[string]string{}
	unapprovedDevices := map[string]bool{}
	for _, a := range assessments {
		if cur, ok := worst[a.ProductKey]; !ok || stateRank[a.State] > stateRank[cur] {
			worst[a.ProductKey] = a.State
		}
		if a.State == StateUnapproved {
			for _, d := range a.Devices {
				unapprovedDevices[d.DeviceID] = true
			}
		}
	}
	c := StateCounts{InstalledProducts: len(worst), UnapprovedDevices: len(unapprovedDevices)}
	for _, s := range worst {
		switch s {
		case StateUnapproved:
			c.Unapproved++
		case StateUnreviewed:
			c.Unreviewed++
		case StateApproved:
			c.Approved++
		case StateIgnored:
			c.Ignored++
		case StateMandatory:
			c.Mandatory++
		}
	}
	return c
}

// DriftProducts lists every product whose worst state is Unapproved or
// Unreviewed, Unapproved first, then by device count.
func DriftProducts(assessments []Assessment) []DriftProduct {
	worst := map[string]string{}
	for _, a := range assessments {
		if cur, ok := worst[a.ProductKey]; !ok || stateRank[a.State] > stateRank[cur] {
			worst[a.ProductKey] = a.State
		}
	}
	byKey := map[string]*DriftProduct{}
	seenDevice := map[string]map[string]bool{}
	var order []string
	for _, a := range assessments {
		state := worst[a.ProductKey]
		if state != StateUnapproved && state != StateUnreviewed {
			continue
		}
		p, ok := byKey[a.ProductKey]
		if !ok {
			p = &DriftProduct{Product: a.Product, ApprovalState: state}
			byKey[a.ProductKey] = p
			seenDevice[a.ProductKey] = map[string]bool{}
			order = append(order, a.ProductKey)
		}
		for _, d := range a.Devices {
			if seenDevice[a.ProductKey][d.DeviceID] {
				continue
			}
			seenDevice[a.ProductKey][d.DeviceID] = true
			p.DeviceCount++
			if d.Stale {
				p.StaleDeviceCount++
			}
			if p.ObservedSince.IsZero() || d.ObservedSince.Before(p.ObservedSince) {
				p.ObservedSince = d.ObservedSince
			}
		}
	}
	out := make([]DriftProduct, 0, len(order))
	for _, k := range order {
		out = append(out, *byKey[k])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if ri, rj := stateRank[out[i].ApprovalState], stateRank[out[j].ApprovalState]; ri != rj {
			return ri > rj
		}
		if out[i].DeviceCount != out[j].DeviceCount {
			return out[i].DeviceCount > out[j].DeviceCount
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ProductKey < out[j].ProductKey
	})
	return out
}

// TopUnapprovedDevices ranks devices by distinct Unapproved products.
func TopUnapprovedDevices(assessments []Assessment, limit int) []TopDevice {
	type acc struct {
		dev      Presence
		products map[string]string
	}
	byDevice := map[string]*acc{}
	for _, a := range assessments {
		if a.State != StateUnapproved {
			continue
		}
		for _, d := range a.Devices {
			x, ok := byDevice[d.DeviceID]
			if !ok {
				x = &acc{dev: d, products: map[string]string{}}
				byDevice[d.DeviceID] = x
			}
			x.products[a.ProductKey] = a.Name
		}
	}
	out := make([]TopDevice, 0, len(byDevice))
	for _, x := range byDevice {
		names := make([]string, 0, len(x.products))
		for _, n := range x.products {
			names = append(names, n)
		}
		sort.Strings(names)
		if len(names) > 5 {
			names = names[:5]
		}
		out = append(out, TopDevice{
			DeviceID: x.dev.DeviceID, Hostname: x.dev.Hostname, Platform: x.dev.Platform,
			UnapprovedProductCount: len(x.products), UnapprovedProductSample: names,
			LastSeen: x.dev.LastSeen, Stale: x.dev.Stale,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UnapprovedProductCount != out[j].UnapprovedProductCount {
			return out[i].UnapprovedProductCount > out[j].UnapprovedProductCount
		}
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].DeviceID < out[j].DeviceID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// UnapprovedPresentList builds the Unapproved-present list, with who marked
// each product and when.
func UnapprovedPresentList(ctx context.Context, q Querier, tenantID string, assessments []Assessment) ([]UnapprovedPresent, error) {
	var out []UnapprovedPresent
	for _, a := range assessments {
		if a.State != StateUnapproved || len(a.Devices) == 0 {
			continue
		}
		u := UnapprovedPresent{Product: a.Product, PolicyKind: a.PolicyKind, PolicyID: a.PolicyID,
			DeviceCount: len(a.Devices), Devices: a.Devices}
		for _, d := range a.Devices {
			if d.Stale {
				u.StaleDeviceCount++
			}
			if u.PresentSince.IsZero() || d.ObservedSince.Before(u.PresentSince) {
				u.PresentSince = d.ObservedSince
			}
		}
		mark, err := markInfoFor(ctx, q, tenantID, a)
		if err != nil {
			return nil, err
		}
		u.MarkInfo = mark
		u.Since = u.PresentSince
		if u.MarkedAt.After(u.Since) {
			u.Since = u.MarkedAt
		}
		out = append(out, u)
	}
	if out == nil {
		out = []UnapprovedPresent{}
	}
	return out, nil
}

// markInfoFor finds who marked a product Unapproved: the current episode
// first (it records portal, operator and observed marks), then the latest
// portal decision for the product key, then the policy row's own timestamp.
func markInfoFor(ctx context.Context, q Querier, tenantID string, a Assessment) (MarkInfo, error) {
	var info MarkInfo
	var source string
	var by *string
	var at time.Time
	err := q.QueryRow(ctx, `
		SELECT source, marked_by, marked_at
		FROM software_unapproved_episodes
		WHERE tenant_id = $1::uuid AND policy_kind = $2 AND policy_id = $3
		ORDER BY id DESC
		LIMIT 1
	`, tenantID, a.PolicyKind, a.PolicyID).Scan(&source, &by, &at)
	if err == nil && source != SourceObserved && source != SourceBaseline {
		info.MarkedBy, info.MarkedVia, info.MarkedAt, info.MarkedAtBasis = by, source, at.UTC(), "decision"
		return info, nil
	}
	if err != nil && !isNoRows(err) {
		return info, fmt.Errorf("unapproved episode lookup: %w", err)
	}
	var actor, newState string
	var decided time.Time
	derr := q.QueryRow(ctx, `
		SELECT actor_email, decided_at, new_state
		FROM software_approval_decisions
		WHERE tenant_id = $1::uuid AND product_key = $2
		ORDER BY decided_at DESC, id DESC
		LIMIT 1
	`, tenantID, a.ProductKey).Scan(&actor, &decided, &newState)
	if derr != nil && !isNoRows(derr) {
		return info, fmt.Errorf("approval decision lookup: %w", derr)
	}
	// Only a latest decision that set Unapproved describes this state.
	if derr == nil && newState == StateUnapproved {
		info.MarkedBy, info.MarkedVia, info.MarkedAt, info.MarkedAtBasis = &actor, "portal", decided.UTC(), "decision"
		return info, nil
	}
	info.MarkedVia = "unknown"
	info.MarkedAtBasis = "policy_last_updated"
	if a.PolicyUpdatedAt != nil {
		info.MarkedAt = a.PolicyUpdatedAt.UTC()
	}
	return info, nil
}

// WeekStart returns the Monday 00:00 UTC that starts t's ISO week.
func WeekStart(t time.Time) time.Time {
	t = t.UTC()
	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	offset := (int(day.Weekday()) + 6) % 7 // Monday = 0
	return day.AddDate(0, 0, -offset)
}

// Trend reads the recorded weekly captures for the last TrendWeeks weeks and
// fills the current week from the live counts.
func Trend(ctx context.Context, q Querier, tenantID string, asOf time.Time, live StateCounts, liveStale int) ([]TrendPoint, error) {
	current := WeekStart(asOf)
	first := current.AddDate(0, 0, -7*(TrendWeeks-1))
	rows, err := q.Query(ctx, `
		SELECT week_start, installed_products, unapproved_products, unreviewed_products,
		       unapproved_devices, devices_stale
		FROM software_governance_weekly
		WHERE tenant_id = $1::uuid AND week_start >= $2::date AND week_start < $3::date
	`, tenantID, first, current)
	if err != nil {
		return nil, fmt.Errorf("load governance trend: %w", err)
	}
	defer rows.Close()
	type rec struct{ installed, unapproved, unreviewed, devices, stale int }
	recorded := map[string]rec{}
	for rows.Next() {
		var ws time.Time
		var r rec
		if err := rows.Scan(&ws, &r.installed, &r.unapproved, &r.unreviewed, &r.devices, &r.stale); err != nil {
			return nil, fmt.Errorf("scan governance trend: %w", err)
		}
		recorded[ws.UTC().Format("2006-01-02")] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]TrendPoint, 0, TrendWeeks)
	for i := 0; i < TrendWeeks; i++ {
		ws := first.AddDate(0, 0, 7*i)
		key := ws.Format("2006-01-02")
		p := TrendPoint{WeekStart: key}
		if ws.Equal(current) {
			p.Recorded, p.Live = true, true
			p.UnapprovedProducts, p.UnreviewedProducts = intPtr(live.Unapproved), intPtr(live.Unreviewed)
			p.UnapprovedDevices, p.InstalledProducts = intPtr(live.UnapprovedDevices), intPtr(live.InstalledProducts)
			p.DevicesStaleAtCheck = intPtr(liveStale)
		} else if r, ok := recorded[key]; ok {
			p.Recorded = true
			p.UnapprovedProducts, p.UnreviewedProducts = intPtr(r.unapproved), intPtr(r.unreviewed)
			p.UnapprovedDevices, p.InstalledProducts = intPtr(r.devices), intPtr(r.installed)
			p.DevicesStaleAtCheck = intPtr(r.stale)
		}
		out = append(out, p)
	}
	return out, nil
}

// RecordWeek upserts this week's capture from a freshly loaded estate. The
// last capture in a week wins.
func RecordWeek(ctx context.Context, q Querier, tenantID string, e Estate) error {
	c := CountStates(e.Assessments)
	_, err := q.Exec(ctx, `
		INSERT INTO software_governance_weekly
		    (tenant_id, week_start, installed_products, unapproved_products, unreviewed_products,
		     unapproved_devices, devices_total, devices_stale, captured_at)
		VALUES ($1::uuid, $2::date, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, week_start) DO UPDATE SET
		    installed_products  = EXCLUDED.installed_products,
		    unapproved_products = EXCLUDED.unapproved_products,
		    unreviewed_products = EXCLUDED.unreviewed_products,
		    unapproved_devices  = EXCLUDED.unapproved_devices,
		    devices_total       = EXCLUDED.devices_total,
		    devices_stale       = EXCLUDED.devices_stale,
		    captured_at         = EXCLUDED.captured_at
	`, tenantID, WeekStart(e.AsOf), c.InstalledProducts, c.Unapproved, c.Unreviewed,
		c.UnapprovedDevices, e.DevicesTotal, e.DevicesStale, e.AsOf)
	if err != nil {
		return fmt.Errorf("record governance week: %w", err)
	}
	return nil
}

// FetchDrift builds the whole drift view.
func FetchDrift(ctx context.Context, q Querier, tenantID string, asOf time.Time) (Drift, error) {
	e, err := LoadEstate(ctx, q, tenantID, asOf)
	if err != nil {
		return Drift{}, err
	}
	return BuildDrift(ctx, q, tenantID, e)
}

// BuildDrift builds the drift view from an estate already loaded.
func BuildDrift(ctx context.Context, q Querier, tenantID string, e Estate) (Drift, error) {
	d := Drift{GeneratedAt: e.AsOf, Coverage: CoverageOf(e), Counts: CountStates(e.Assessments)}
	products := DriftProducts(e.Assessments)
	d.ProductsTotal = len(products)
	if len(products) > MaxDriftProducts {
		products = products[:MaxDriftProducts]
		d.ProductsTruncated = true
	}
	d.Products = products
	trend, err := Trend(ctx, q, tenantID, e.AsOf, d.Counts, e.DevicesStale)
	if err != nil {
		return d, err
	}
	d.Trend = trend
	d.TopDevices = TopUnapprovedDevices(e.Assessments, TopDevicesLimit)
	present, err := UnapprovedPresentList(ctx, q, tenantID, e.Assessments)
	if err != nil {
		return d, err
	}
	d.UnapprovedPresent = present
	return d, nil
}

func intPtr(v int) *int { return &v }

// OverviewItem is one entry of the portal overview's short Unapproved list.
type OverviewItem struct {
	Type        string    `json:"type"`
	ProductKey  string    `json:"product_key"`
	Name        string    `json:"name"`
	Platform    string    `json:"platform,omitempty"`
	Browser     string    `json:"browser,omitempty"`
	DeviceCount int       `json:"device_count"`
	Since       time.Time `json:"since"`
}

// OverviewSummary is the portal overview's Unapproved-present figure.
type OverviewSummary struct {
	Products int
	Devices  int
	Items    []OverviewItem
}

// UnapprovedOverview counts distinct Unapproved products present on at least
// one device, and returns the most widespread ones. A tenant with no
// Unapproved policy is answered without reading its inventory.
//
// PAT-2095: it reads the Unapproved-present summary (presence.go) in one
// consistent snapshot, resolving dirty devices live, and falls back to the
// full computation (UnapprovedOverviewFull) only while the summary lags a
// policy change or too many devices are dirty. Both give the same answer.
func UnapprovedOverview(ctx context.Context, q Querier, tenantID string, asOf time.Time, limit int) (OverviewSummary, error) {
	var out OverviewSummary
	err := inSnapshot(ctx, q, func(s Querier) error {
		exists, err := hasUnapprovedPolicy(ctx, s, tenantID)
		if err != nil {
			return err
		}
		if !exists {
			out = OverviewSummary{Items: []OverviewItem{}}
			return nil
		}
		out, err = summaryOverview(ctx, s, tenantID, asOf, limit)
		if errors.Is(err, ErrSummaryUnusable) {
			out, err = UnapprovedOverviewFull(ctx, s, tenantID, asOf, limit)
		}
		return err
	})
	if err != nil {
		return OverviewSummary{Items: []OverviewItem{}}, err
	}
	return out, nil
}

func hasUnapprovedPolicy(ctx context.Context, q Querier, tenantID string) (bool, error) {
	var exists bool
	if err := q.QueryRow(ctx, `
		SELECT EXISTS (SELECT 1 FROM tenant_app_policies WHERE tenant_id = $1::uuid AND policy = 'unapproved')
		    OR EXISTS (SELECT 1 FROM tenant_extension_policies WHERE tenant_id = $1::uuid AND policy = 'unapproved')
		    OR EXISTS (SELECT 1 FROM tenant_homebrew_policies WHERE tenant_id = $1::uuid AND policy = 'unapproved')
		    OR EXISTS (SELECT 1 FROM tenant_observation_policies WHERE tenant_id = $1::uuid AND policy = 'unapproved')
	`, tenantID).Scan(&exists); err != nil {
		return false, fmt.Errorf("unapproved policy check: %w", err)
	}
	return exists, nil
}

// UnapprovedOverviewFull is the full computation behind UnapprovedOverview:
// it resolves the whole estate. It is the fallback while the summary is not
// usable, and the oracle the PAT-2095 equivalence tests compare the summary
// against.
func UnapprovedOverviewFull(ctx context.Context, q Querier, tenantID string, asOf time.Time, limit int) (OverviewSummary, error) {
	out := OverviewSummary{Items: []OverviewItem{}}
	exists, err := hasUnapprovedPolicy(ctx, q, tenantID)
	if err != nil {
		return out, err
	}
	if !exists {
		return out, nil
	}
	assessments, err := loadAssessments(ctx, q, tenantID, "", asOf)
	if err != nil {
		return out, err
	}
	var unapproved []Assessment
	products := map[string]bool{}
	devices := map[string]bool{}
	for _, a := range assessments {
		if a.State != StateUnapproved || len(a.Devices) == 0 {
			continue
		}
		unapproved = append(unapproved, a)
		products[a.ProductKey] = true
		for _, d := range a.Devices {
			devices[d.DeviceID] = true
		}
	}
	out.Products, out.Devices = len(products), len(devices)
	// loadAssessments already orders Unapproved first by device count.
	if limit > 0 && len(unapproved) > limit {
		unapproved = unapproved[:limit]
	}
	present, err := UnapprovedPresentList(ctx, q, tenantID, unapproved)
	if err != nil {
		return out, err
	}
	for _, u := range present {
		out.Items = append(out.Items, OverviewItem{Type: u.Type, ProductKey: u.ProductKey, Name: u.Name,
			Platform: u.Platform, Browser: u.Browser, DeviceCount: u.DeviceCount, Since: u.Since})
	}
	return out, nil
}
