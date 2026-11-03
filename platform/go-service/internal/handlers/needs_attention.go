package handlers

// GET /admin/tenants/{tenantID}/needs-attention (PAT-458)
//
// Returns per-device app rows that need attention, ranked:
//   0 — vulnerable  (≥1 unresolved CVE from device_cve_findings)
//   1 — out_of_date (update available via provenance state or catalog diff)
//   2 — blocked     (verification_failed in most-recent provenance record)
//
// The rank number is a display-order key (lower sorts first); it is NOT a
// severity score. Categorisation of a multi-matching row follows CASE order,
// which fails closed on verification: a row that is BOTH catalog-out-of-date
// and verification_failed is categorised "blocked", never masked as
// "out_of_date". A verification failure is a supply-chain / endpoint-trust
// signal (bad TeamID/Authenticode) and must always surface — see the GitHub-Non-Author-Review
// endpoint-trust criteria. The verification_failed WHEN clause therefore
// stays ahead of the catalog out_of_date WHEN clause in every CASE below.
//
// Three-way server-side join: device_apps × provenance_records × device_cve_findings.
// catalog_out_of_date CTE is a fallback when no provenance record exists but
// app_catalog_entries shows a newer known-good version.
//
// Platform-neutral contract — both macOS (TeamID signer) and Windows (Authenticode
// publisher) feed the same response shape (PAT-276 parity).
// Blocks PAT-275 (dashboard "Needs attention" view).

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

// -- Response types ----------------------------------------------------------

type needsAttentionItem struct {
	DeviceID         string   `json:"device_id"`
	Hostname         string   `json:"hostname"`
	AppName          string   `json:"app_name"`
	Identifier       string   `json:"identifier"`
	InstalledVersion string   `json:"installed_version"`
	AvailableVersion *string  `json:"available_version"`
	Category         string   `json:"category"` // vulnerable | out_of_date | blocked
	Rank             int      `json:"rank"`     // 0 | 1 | 2
	CVEIDs           []string `json:"cve_ids"`
	MaxCVSS          *float64 `json:"max_cvss"`
	MaxSeverity      *string  `json:"max_severity"`
	VerifiedSigner   *string  `json:"verified_signer"`
	FailureReason    *string  `json:"failure_reason"`
}

type needsAttentionTenantSummary struct {
	Total      int `json:"total"`
	Vulnerable int `json:"vulnerable"`
	OutOfDate  int `json:"out_of_date"`
	Blocked    int `json:"blocked"`
}

type needsAttentionDeviceSummary struct {
	DeviceID   string `json:"device_id"`
	Hostname   string `json:"hostname"`
	Total      int    `json:"total"`
	Vulnerable int    `json:"vulnerable"`
	OutOfDate  int    `json:"out_of_date"`
	Blocked    int    `json:"blocked"`
}

type needsAttentionResp struct {
	Items    []needsAttentionItem          `json:"items"`
	Summary  needsAttentionTenantSummary   `json:"summary"`
	ByDevice []needsAttentionDeviceSummary `json:"by_device"`
}

// -- Injectable function types (for testing) ---------------------------------

type needsAttentionExistsFn func(ctx context.Context, tenantID string) (bool, error)
type needsAttentionFetchFn func(ctx context.Context, tenantID string) ([]needsAttentionItem, error)

// -- Public constructor -------------------------------------------------------

// NeedsAttentionHandler serves GET /admin/tenants/{tenantID}/needs-attention on
// the internal (:8081) router. Network-only auth — no app-layer auth required.
func NeedsAttentionHandler(pool *pgxpool.Pool) http.HandlerFunc {
	existsFn := func(ctx context.Context, tenantID string) (bool, error) {
		var exists bool
		err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid)`,
			tenantID,
		).Scan(&exists)
		return exists, err
	}
	fetchFn := func(ctx context.Context, tenantID string) ([]needsAttentionItem, error) {
		return fetchNeedsAttention(ctx, pool, tenantID)
	}
	return newNeedsAttentionHandler(existsFn, fetchFn)
}

// newNeedsAttentionHandler builds the handler with injectable DB functions so
// tests can pass mock implementations without a live database connection.
func newNeedsAttentionHandler(existsFn needsAttentionExistsFn, fetchFn needsAttentionFetchFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "needs_attention")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		exists, err := existsFn(r.Context(), tenantID)
		if err != nil {
			logger.Error("tenant existence check failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !exists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		items, err := fetchFn(r.Context(), tenantID)
		if err != nil {
			logger.Error("needs-attention query failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if items == nil {
			items = []needsAttentionItem{}
		}

		resp := buildNeedsAttentionResp(items)

		logger.Info("needs-attention computed",
			"tenant_id", tenantID,
			"total", resp.Summary.Total,
			"vulnerable", resp.Summary.Vulnerable,
			"out_of_date", resp.Summary.OutOfDate,
			"blocked", resp.Summary.Blocked,
		)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// buildNeedsAttentionResp assembles tenant-wide + per-device summary counts
// from the flat items slice. Called by the handler and by tests.
func buildNeedsAttentionResp(items []needsAttentionItem) needsAttentionResp {
	summary := needsAttentionTenantSummary{Total: len(items)}
	byDeviceMap := map[string]*needsAttentionDeviceSummary{}
	byDeviceOrder := []string{}

	for i := range items {
		item := &items[i]
		switch item.Category {
		case "vulnerable":
			summary.Vulnerable++
		case "out_of_date":
			summary.OutOfDate++
		case "blocked":
			summary.Blocked++
		}
		if _, ok := byDeviceMap[item.DeviceID]; !ok {
			byDeviceMap[item.DeviceID] = &needsAttentionDeviceSummary{
				DeviceID: item.DeviceID,
				Hostname: item.Hostname,
			}
			byDeviceOrder = append(byDeviceOrder, item.DeviceID)
		}
		d := byDeviceMap[item.DeviceID]
		d.Total++
		switch item.Category {
		case "vulnerable":
			d.Vulnerable++
		case "out_of_date":
			d.OutOfDate++
		case "blocked":
			d.Blocked++
		}
	}

	byDevice := make([]needsAttentionDeviceSummary, 0, len(byDeviceOrder))
	for _, id := range byDeviceOrder {
		byDevice = append(byDevice, *byDeviceMap[id])
	}

	return needsAttentionResp{
		Items:    items,
		Summary:  summary,
		ByDevice: byDevice,
	}
}

// -- DB query ----------------------------------------------------------------

// needsAttentionSQL is the three-way join query (device_apps × provenance_records
// × device_cve_findings) that drives the needs-attention endpoint.
//
// Provenance records are expected to carry device_id (UUID text) and app_name
// in their JSONB body — written by the Patched Updater on each update action.
// catalog_out_of_date is a fallback for apps with no provenance record but a
// known newer version in app_catalog_entries.
//
// Categorisation precedence (first matching CASE branch wins):
//
//	vulnerable > verification_failed(blocked) > out_of_date.
//
// An app that is both vulnerable and out-of-date appears only as vulnerable.
// An app that is both catalog-out-of-date and verification_failed appears as
// blocked — failed verification fails closed and is never masked by a mere
// pending update (GitHub-Non-Author-Review endpoint-trust). Note the rank NUMBER still puts
// blocked last in display order (2); precedence here is about which single
// category a multi-matching row is assigned, not its sort position.
const needsAttentionSQL = `
WITH

latest_provenance AS (
  SELECT DISTINCT ON (body->>'device_id', body->>'app_name')
    body->>'device_id'          AS device_id,
    body->>'app_name'           AS app_name,
    body->>'state'              AS state,
    body->>'available_version'  AS available_version,
    body->>'verified_signer'    AS verified_signer,
    body->>'failure_reason'     AS failure_reason
  FROM provenance_records
  WHERE tenant_id = $1::uuid
    AND body->>'device_id' IS NOT NULL
    AND body->>'app_name'  IS NOT NULL
  ORDER BY body->>'device_id', body->>'app_name', received_at DESC
),

app_cves AS (
  SELECT
    dcf.device_id::text                                   AS device_id,
    dcf.app_name,
    dcf.app_version,
    array_agg(dcf.cve_id ORDER BY dcf.cve_id)            AS cve_ids,
    MAX(dcf.cvss_v3_score)                                AS max_cvss,
    CASE MAX(CASE e.severity
               WHEN 'CRITICAL' THEN 4
               WHEN 'HIGH'     THEN 3
               WHEN 'MEDIUM'   THEN 2
               WHEN 'LOW'      THEN 1
               ELSE 0 END)
      WHEN 4 THEN 'CRITICAL'
      WHEN 3 THEN 'HIGH'
      WHEN 2 THEN 'MEDIUM'
      WHEN 1 THEN 'LOW'
      ELSE 'NONE' END                                        AS max_severity
  FROM device_cve_findings dcf
  JOIN devices d ON d.id = dcf.device_id AND d.tenant_id = $1::uuid
  JOIN cve_feed_entries e ON e.cve_id = dcf.cve_id
  GROUP BY dcf.device_id, dcf.app_name, dcf.app_version
),

catalog_out_of_date AS (
  SELECT DISTINCT ON (d.id, COALESCE(da.identifier, da.name))
    d.id::text      AS device_id,
    COALESCE(da.identifier, da.name) AS app_key,
    da.name         AS app_name,
    ace.latest_version AS available_version
  FROM device_apps da
  JOIN devices d ON d.id = da.device_id AND d.tenant_id = $1::uuid
  JOIN app_catalog_entries ace ON (
    ace.platform = CASE WHEN d.os ILIKE '%windows%' THEN 'Windows' ELSE 'macOS' END
    AND (
      (ace.verified_signer IS NOT NULL AND da.team_id = ace.verified_signer)
      OR (ace.verified_signer IS NULL  AND lower(da.name) = lower(ace.name))
    )
  )
  WHERE da.version IS NOT NULL
    AND da.version < ace.latest_version
  ORDER BY d.id, COALESCE(da.identifier, da.name), ace.latest_version DESC
)

SELECT
  d.id::text                                                   AS device_id,
  d.hostname,
  da.name                                                      AS app_name,
  COALESCE(da.identifier, '')                                  AS identifier,
  COALESCE(da.version,    '')                                  AS installed_version,
  CASE
    WHEN ac.cve_ids   IS NOT NULL                              THEN 0
    WHEN lp.state     = 'update_available'                     THEN 1
    WHEN lp.state     = 'verification_failed'                  THEN 2
    WHEN cod.device_id IS NOT NULL                             THEN 1
  END                                                          AS rank,
  CASE
    WHEN ac.cve_ids   IS NOT NULL                              THEN 'vulnerable'
    WHEN lp.state     = 'update_available'                     THEN 'out_of_date'
    WHEN lp.state     = 'verification_failed'                  THEN 'blocked'
    WHEN cod.device_id IS NOT NULL                             THEN 'out_of_date'
  END                                                          AS category,
  ac.cve_ids,
  ac.max_cvss,
  ac.max_severity,
  COALESCE(lp.available_version, cod.available_version)        AS available_version,
  lp.verified_signer,
  lp.failure_reason
FROM device_apps da
JOIN  devices d              ON d.id         = da.device_id  AND d.tenant_id = $1::uuid
LEFT JOIN latest_provenance  lp  ON lp.device_id = d.id::text    AND lp.app_name   = da.name
LEFT JOIN app_cves           ac  ON ac.device_id = d.id::text    AND ac.app_name   = da.name
                                 AND ac.app_version = da.version
LEFT JOIN catalog_out_of_date cod ON cod.device_id = d.id::text  AND cod.app_name  = da.name
WHERE
  ac.cve_ids IS NOT NULL
  OR lp.state IN ('update_available', 'verification_failed')
  OR cod.device_id IS NOT NULL
ORDER BY
  CASE
    WHEN ac.cve_ids   IS NOT NULL                              THEN 0
    WHEN lp.state     = 'update_available'                     THEN 1
    WHEN lp.state     = 'verification_failed'                  THEN 2
    WHEN cod.device_id IS NOT NULL                             THEN 1
    ELSE 99
  END,
  ac.max_cvss DESC NULLS LAST,
  da.name
`

func fetchNeedsAttention(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]needsAttentionItem, error) {
	rows, err := pool.Query(ctx, needsAttentionSQL, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []needsAttentionItem
	for rows.Next() {
		var item needsAttentionItem
		var rank *int
		var category *string
		if err := rows.Scan(
			&item.DeviceID, &item.Hostname, &item.AppName, &item.Identifier,
			&item.InstalledVersion, &rank, &category,
			&item.CVEIDs, &item.MaxCVSS, &item.MaxSeverity,
			&item.AvailableVersion, &item.VerifiedSigner, &item.FailureReason,
		); err != nil {
			return nil, err
		}
		if rank != nil {
			item.Rank = *rank
		}
		if category != nil {
			item.Category = *category
		}
		if item.CVEIDs == nil {
			item.CVEIDs = []string{}
		}
		items = append(items, item)
	}
	return items, rows.Err()
}
