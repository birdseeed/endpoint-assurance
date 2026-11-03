package softwaregov

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"patched.im/api/internal/apppolicy"
)

// Read models for the PAT-2097 alert lifecycle: the portal list and detail,
// and the operator's cross-tenant queue. Every query is scoped by an explicit
// tenant id, except OperatorAlerts, which is the admin API's cross-tenant view.

// AlertDeviceRef is the device an alert is about.
type AlertDeviceRef struct {
	DeviceID string     `json:"device_id"`
	Hostname string     `json:"hostname"`
	Platform string     `json:"platform"`
	LastSeen *time.Time `json:"last_seen"`
}

// AlertView is one tracked alert.
type AlertView struct {
	ID     int64  `json:"id"`
	Status string `json:"status"`
	// Trigger is how the (episode, device) pair was first recorded: marked
	// (an admin action listed it), observed (ingest found it), or baseline
	// (already present when 0183 ran; never announced).
	Trigger string         `json:"trigger"`
	Product Product        `json:"product"`
	Policy  AlertPolicy    `json:"policy"`
	Device  AlertDeviceRef `json:"device"`
	// NotificationID is the outbound alert (the webhook payload's alert_id)
	// that reported this pair, null for a baseline row.
	NotificationID  *int64     `json:"notification_id"`
	RaisedAt        time.Time  `json:"raised_at"`
	StatusChangedAt time.Time  `json:"status_changed_at"`
	AcknowledgedAt  *time.Time `json:"acknowledged_at"`
	// AcknowledgedBy is the portal admin's email, or "operator".
	AcknowledgedBy *string    `json:"acknowledged_by"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	ResolvedReason *string    `json:"resolved_reason"`
	ReopenedCount  int        `json:"reopened_count"`
	LastReopenedAt *time.Time `json:"last_reopened_at"`
}

// AlertTransition is one row of an alert's history.
type AlertTransition struct {
	ID        int64     `json:"id"`
	From      *string   `json:"from"`
	To        string    `json:"to"`
	ActorKind string    `json:"actor_kind"`
	Actor     *string   `json:"actor"`
	Reason    *string   `json:"reason"`
	Note      *string   `json:"note"`
	At        time.Time `json:"at"`
}

// AlertFilter narrows a tenant alert list. Empty fields do not filter.
type AlertFilter struct {
	Statuses   []string
	ProductKey string
	DeviceID   string
	Limit      int
	Offset     int
}

// AlertCounts are the tenant's alerts by status, under the product and
// device filters but not the status filter.
type AlertCounts struct {
	Open         int `json:"open"`
	Acknowledged int `json:"acknowledged"`
	Resolved     int `json:"resolved"`
}

// AlertPage is one page of a tenant's alerts.
type AlertPage struct {
	Total  int         `json:"total"`
	Counts AlertCounts `json:"counts"`
	Alerts []AlertView `json:"alerts"`
}

const alertViewColumns = `
	ad.id, ad.status,
	CASE WHEN ad.suppressed_baseline THEN 'baseline' ELSE COALESCE(a.trigger, 'observed') END,
	ad.product::text, e.policy_kind, e.policy_id,
	ad.device_id::text, COALESCE(d.hostname, ''), COALESCE(d.os, ''), d.last_seen,
	ad.alert_id, ad.alerted_at, ad.status_changed_at,
	ad.acknowledged_at,
	CASE ad.acknowledged_by_kind WHEN 'operator' THEN 'operator' ELSE ad.acknowledged_by END,
	ad.resolved_at, ad.resolved_reason, ad.reopened_count, ad.last_reopened_at,
	ap.name, ap.bundle_id, ap.winget_id, ap.team_id, ap.platform,
	xp.browser, xp.extension_id, xp.name`

// Every join is bound to the alert row's own tenant, because the foreign keys
// reference ids alone. A row pointing at another tenant's outbound alert reads
// as an unlinked row (PAT-2442).
const alertViewFrom = `
	FROM software_unapproved_alerted_devices ad
	JOIN software_unapproved_episodes e ON e.id = ad.episode_id AND e.tenant_id = ad.tenant_id
	LEFT JOIN software_unapproved_alerts a ON a.id = ad.alert_id AND a.tenant_id = ad.tenant_id
	LEFT JOIN devices d ON d.id = ad.device_id AND d.tenant_id = ad.tenant_id
	LEFT JOIN tenant_app_policies ap ON e.policy_kind = 'application' AND ap.id = e.policy_id AND ap.tenant_id = e.tenant_id
	LEFT JOIN tenant_extension_policies xp ON e.policy_kind = 'browser_extension' AND xp.id = e.policy_id AND xp.tenant_id = e.tenant_id`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanAlertView(r rowScanner, extra ...any) (AlertView, error) {
	var v AlertView
	var product *string
	var osName string
	var apName, apBundle, apWinget, apTeam, apPlatform, xpBrowser, xpExt, xpName *string
	dest := []any{&v.ID, &v.Status, &v.Trigger, &product, &v.Policy.Kind, &v.Policy.ID,
		&v.Device.DeviceID, &v.Device.Hostname, &osName, &v.Device.LastSeen,
		&v.NotificationID, &v.RaisedAt, &v.StatusChangedAt, &v.AcknowledgedAt, &v.AcknowledgedBy,
		&v.ResolvedAt, &v.ResolvedReason, &v.ReopenedCount, &v.LastReopenedAt,
		&apName, &apBundle, &apWinget, &apTeam, &apPlatform, &xpBrowser, &xpExt, &xpName}
	if err := r.Scan(append(dest, extra...)...); err != nil {
		return v, err
	}
	v.Device.Platform = apppolicy.DevicePlatform(osName)
	if product != nil {
		if err := json.Unmarshal([]byte(*product), &v.Product); err != nil {
			return v, fmt.Errorf("decode alert product: %w", err)
		}
		return v, nil
	}
	// No snapshot yet (a baseline row the device has not reported since):
	// describe the product by its policy row, the evidence held.
	deref := func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	}
	if v.Policy.Kind == TypeBrowserExtension {
		v.Product = Product{Type: TypeBrowserExtension, Name: deref(xpName), Browser: deref(xpBrowser), ExtensionID: deref(xpExt)}
		if v.Product.ExtensionID != "" {
			v.Product.ProductKey = ExtensionKey(v.Product.Browser, v.Product.ExtensionID)
		}
		return v, nil
	}
	ident := deref(apBundle)
	if ident == "" {
		ident = deref(apWinget)
	}
	platform := deref(apPlatform)
	if platform == "any" || platform == "" {
		platform = v.Device.Platform
	}
	team := normalisedTeamID(platform, deref(apTeam))
	v.Product = Product{Type: TypeApplication, Name: deref(apName), Platform: platform, Identifier: ident, TeamID: team}
	if v.Product.Name == "" {
		v.Product.Name = ident
	}
	if ident != "" {
		v.Product.ProductKey = ApplicationKey(platform, ident, team)
	}
	return v, nil
}

// ListAlerts returns one page of the tenant's alerts: open first, then
// acknowledged, then resolved, most recently changed first within each.
func ListAlerts(ctx context.Context, q Querier, tenantID string, f AlertFilter) (AlertPage, error) {
	page := AlertPage{Alerts: []AlertView{}}
	statuses := f.Statuses
	if statuses == nil {
		statuses = []string{}
	}
	where := `
		WHERE ad.tenant_id = $1::uuid
		  AND ($2 = '' OR ad.product->>'product_key' = $2)
		  AND ($3 = '' OR ad.device_id = NULLIF($3, '')::uuid)`
	if err := q.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE ad.status = 'open'),
		       count(*) FILTER (WHERE ad.status = 'acknowledged'),
		       count(*) FILTER (WHERE ad.status = 'resolved'),
		       count(*) FILTER (WHERE cardinality($4::text[]) = 0 OR ad.status = ANY($4::text[]))
		FROM software_unapproved_alerted_devices ad`+where,
		tenantID, f.ProductKey, f.DeviceID, statuses).Scan(
		&page.Counts.Open, &page.Counts.Acknowledged, &page.Counts.Resolved, &page.Total); err != nil {
		return page, fmt.Errorf("count alerts: %w", err)
	}
	rows, err := q.Query(ctx, `
		SELECT `+alertViewColumns+alertViewFrom+where+`
		  AND (cardinality($4::text[]) = 0 OR ad.status = ANY($4::text[]))
		ORDER BY CASE ad.status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END,
		         ad.status_changed_at DESC, ad.id DESC
		LIMIT $5 OFFSET $6
	`, tenantID, f.ProductKey, f.DeviceID, statuses, f.Limit, f.Offset)
	if err != nil {
		return page, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		v, err := scanAlertView(rows)
		if err != nil {
			return page, err
		}
		page.Alerts = append(page.Alerts, v)
	}
	return page, rows.Err()
}

// GetAlert returns one of the tenant's alerts with its full history. An
// alert of another tenant is ErrAlertNotFound.
func GetAlert(ctx context.Context, q Querier, tenantID string, id int64) (AlertView, []AlertTransition, error) {
	v, err := scanAlertView(q.QueryRow(ctx, `
		SELECT `+alertViewColumns+alertViewFrom+`
		WHERE ad.tenant_id = $1::uuid AND ad.id = $2
	`, tenantID, id))
	if isNoRows(err) {
		return v, nil, ErrAlertNotFound
	}
	if err != nil {
		return v, nil, fmt.Errorf("get alert: %w", err)
	}
	rows, err := q.Query(ctx, `
		SELECT id, from_status, to_status, actor_kind, actor, reason, note, created_at
		FROM software_unapproved_alert_transitions
		WHERE tenant_id = $1::uuid AND alert_device_id = $2
		ORDER BY id
	`, tenantID, id)
	if err != nil {
		return v, nil, fmt.Errorf("alert history: %w", err)
	}
	defer rows.Close()
	history := []AlertTransition{}
	for rows.Next() {
		var h AlertTransition
		if err := rows.Scan(&h.ID, &h.From, &h.To, &h.ActorKind, &h.Actor, &h.Reason, &h.Note, &h.At); err != nil {
			return v, nil, err
		}
		history = append(history, h)
	}
	return v, history, rows.Err()
}

// OperatorAlert is one row of the operator's cross-tenant queue.
type OperatorAlert struct {
	TenantID   string `json:"tenant_id"`
	TenantName string `json:"tenant_name"`
	AlertView
	// OpenSince is when the alert last became active: raised, or re-opened.
	OpenSince  time.Time `json:"open_since"`
	AgeSeconds int64     `json:"age_seconds"`
}

// OperatorAlerts lists open and acknowledged alerts (or the statuses given)
// across every active tenant, oldest first.
func OperatorAlerts(ctx context.Context, q Querier, statuses []string, tenantID string, limit, offset int, now time.Time) ([]OperatorAlert, int, error) {
	if len(statuses) == 0 {
		statuses = []string{AlertOpen, AlertAcknowledged}
	}
	where := `
		WHERE ad.status = ANY($1::text[])
		  AND ($2 = '' OR ad.tenant_id = NULLIF($2, '')::uuid)
		  AND EXISTS (SELECT 1 FROM tenants t WHERE t.id = ad.tenant_id AND t.revoked_at IS NULL)`
	var total int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM software_unapproved_alerted_devices ad`+where,
		statuses, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count operator alerts: %w", err)
	}
	rows, err := q.Query(ctx, `
		SELECT `+alertViewColumns+`, ad.tenant_id::text, COALESCE(t.name, ''),
		       COALESCE(ad.last_reopened_at, ad.alerted_at)`+alertViewFrom+`
		JOIN tenants t ON t.id = ad.tenant_id`+where+`
		ORDER BY COALESCE(ad.last_reopened_at, ad.alerted_at), ad.id
		LIMIT $3 OFFSET $4
	`, statuses, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list operator alerts: %w", err)
	}
	defer rows.Close()
	out := []OperatorAlert{}
	for rows.Next() {
		var o OperatorAlert
		v, err := scanAlertView(rows, &o.TenantID, &o.TenantName, &o.OpenSince)
		if err != nil {
			return nil, 0, err
		}
		o.AlertView = v
		o.AgeSeconds = int64(now.Sub(o.OpenSince) / time.Second)
		if o.AgeSeconds < 0 {
			o.AgeSeconds = 0
		}
		out = append(out, o)
	}
	return out, total, rows.Err()
}

// ActiveAlertCounts returns the tenant's open and acknowledged alert counts
// for the portal overview, on the tenant's own existing devices only. A
// deleted device's rows cascade away with it; the join also keeps a row
// whose device is missing or belongs elsewhere out of the count without
// resolving it.
func ActiveAlertCounts(ctx context.Context, q Querier, tenantID string) (open, acknowledged int, err error) {
	err = q.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE ad.status = 'open'), count(*) FILTER (WHERE ad.status = 'acknowledged')
		FROM software_unapproved_alerted_devices ad
		JOIN devices d ON d.id = ad.device_id AND d.tenant_id = ad.tenant_id
		WHERE ad.tenant_id = $1::uuid
	`, tenantID).Scan(&open, &acknowledged)
	return open, acknowledged, err
}
