package handlers

// PAT-1829/PAT-1878: finding action tracking and the evidence-backed
// verification lifecycle. Dashboard UI remains a separate follow-up.
//
// Three finding types exist today with genuinely different identity shapes —
// see migrations/0146_finding_dispositions.sql for the full reasoning:
//
//	CIS findings  — one row per (device, compliance rule). Identity is
//	                (tenant_id, device_id, rule_key).
//	CVE findings  — one row per CVE, aggregated across every affected
//	                device on the tenant (TenantCVEFindingsHandler, cve.go).
//	                Identity is (tenant_id, cve_id).
//	Software      — one policy-drift finding on one device. Identity is
//	                (tenant_id, device_id, software_key).
//
// finding_dispositions carries all three shapes in one append-only-with-supersede
// table, discriminated by finding_kind, same shape and reasoning as
// device_dispositions (PAT-1825, device_dispositions.go).
//
// Routes (internal admin listener, ADMIN_API_TOKEN):
//
//	POST /admin/tenants/{tenantID}/finding-dispositions
//	    Record a disposition for one finding. A finding that already
//	    carries a live disposition is corrected, not duplicated: the
//	    existing row is superseded (superseded_reason "correction") and
//	    the new row's supersedes_id points at it — see this file's
//	    writeFindingDisposition.
//	GET  /admin/tenants/{tenantID}/finding-dispositions
//	    List ACTIVE (non-superseded) dispositions for the tenant,
//	    optionally narrowed by ?finding_kind=cis|cve|software. Unlike
//	    device-dispositions' list, this endpoint never returns superseded
//	    rows — there is no ?active toggle because "active only" is the
//	    only view this ticket needs.
//
// A human action never writes verified_fixed. The extractor and CVE matcher
// append those events only after fresh authoritative endpoint evidence.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/findinglifecycle"
)

const maxFindingDispositionBytes = 65536

var validFindingKinds = map[string]bool{
	"cis":      true,
	"cve":      true,
	"software": true,
}

var validFindingDispositionStatuses = map[string]bool{
	"acknowledged":         true,
	"risk_accepted":        true,
	"guidance_issued":      true,
	"customer_applied":     true,
	"pending_verification": true,
	// Compatibility alias. It is normalised to pending_verification below;
	// an operator-provided "closed" can no longer manufacture closure.
	"closed": true,
}

type findingDispositionCreateReq struct {
	FindingKind string `json:"finding_kind"`
	DeviceID    string `json:"device_id"`
	RuleKey     string `json:"rule_key"`
	CVEID       string `json:"cve_id"`
	SoftwareKey string `json:"software_key"`
	Status      string `json:"status"`
	RecordedBy  string `json:"recorded_by"`
	Reason      string `json:"reason"`
}

type findingDispositionRow struct {
	ID               string     `json:"id"`
	TenantID         string     `json:"tenant_id,omitempty"`
	FindingKind      string     `json:"finding_kind"`
	DeviceID         *string    `json:"device_id,omitempty"`
	RuleKey          *string    `json:"rule_key,omitempty"`
	CVEID            *string    `json:"cve_id,omitempty"`
	SoftwareKey      *string    `json:"software_key,omitempty"`
	Status           string     `json:"status"`
	RecordedBy       string     `json:"recorded_by"`
	Reason           string     `json:"reason,omitempty"`
	RecordedAt       time.Time  `json:"recorded_at"`
	SupersedesID     *string    `json:"supersedes_id,omitempty"`
	SupersededAt     *time.Time `json:"superseded_at,omitempty"`
	SupersededReason *string    `json:"superseded_reason,omitempty"`
}

type findingDispositionCreateResp struct {
	Disposition findingDispositionRow `json:"disposition"`
}

// FindingDispositionCreateHandler serves
// POST /admin/tenants/{tenantID}/finding-dispositions.
//
// 201 findingDispositionCreateResp | 400 bad input (including a
// finding_kind/identity-column mismatch, rejected before it ever reaches
// the DB's own CHECK constraint) | 404 unknown tenant, a device_id not
// owned by this tenant, or a cve_id not in the CVE feed
func FindingDispositionCreateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "finding_disposition_create")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxFindingDispositionBytes+1))
		if err != nil || len(body) > maxFindingDispositionBytes {
			http.Error(w, "cannot read body or body too large", http.StatusBadRequest)
			return
		}
		var req findingDispositionCreateReq
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		req.FindingKind = strings.TrimSpace(req.FindingKind)
		req.DeviceID = strings.TrimSpace(req.DeviceID)
		req.RuleKey = strings.TrimSpace(req.RuleKey)
		req.CVEID = strings.TrimSpace(req.CVEID)
		req.SoftwareKey = strings.TrimSpace(req.SoftwareKey)
		req.Status = strings.TrimSpace(req.Status)
		req.RecordedBy = strings.TrimSpace(req.RecordedBy)
		req.Reason = strings.TrimSpace(req.Reason)

		if !validFindingKinds[req.FindingKind] {
			http.Error(w, "finding_kind must be one of cis, cve, software", http.StatusBadRequest)
			return
		}
		if !validFindingDispositionStatuses[req.Status] {
			http.Error(w, "status must be one of acknowledged, risk_accepted, guidance_issued, customer_applied, pending_verification, closed", http.StatusBadRequest)
			return
		}
		if req.RecordedBy == "" {
			http.Error(w, "recorded_by is required", http.StatusBadRequest)
			return
		}
		if req.Status == "closed" {
			// PAT-1878 compatibility: retain old clients without retaining the
			// unsafe assertion. "closed" now means "please verify".
			req.Status = findinglifecycle.EventPendingVerification
		}

		// Mirror the DB's finding_dispositions_kind_shape CHECK constraint
		// here so a malformed request gets a clean 400, not a raw
		// constraint-violation error from the INSERT.
		switch req.FindingKind {
		case "cis":
			if !looksLikeUUID(req.DeviceID) {
				http.Error(w, "device_id must be a UUID for finding_kind=cis", http.StatusBadRequest)
				return
			}
			if req.RuleKey == "" {
				http.Error(w, "rule_key is required for finding_kind=cis", http.StatusBadRequest)
				return
			}
			if req.CVEID != "" || req.SoftwareKey != "" {
				http.Error(w, "cve_id and software_key must not be set for finding_kind=cis", http.StatusBadRequest)
				return
			}
		case "cve":
			if req.CVEID == "" {
				http.Error(w, "cve_id is required for finding_kind=cve", http.StatusBadRequest)
				return
			}
			if req.DeviceID != "" || req.RuleKey != "" || req.SoftwareKey != "" {
				http.Error(w, "device_id, rule_key and software_key must not be set for finding_kind=cve", http.StatusBadRequest)
				return
			}
		case "software":
			if !looksLikeUUID(req.DeviceID) {
				http.Error(w, "device_id must be a UUID for finding_kind=software", http.StatusBadRequest)
				return
			}
			if req.SoftwareKey == "" {
				http.Error(w, "software_key is required for finding_kind=software", http.StatusBadRequest)
				return
			}
			if req.RuleKey != "" || req.CVEID != "" {
				http.Error(w, "rule_key and cve_id must not be set for finding_kind=software", http.StatusBadRequest)
				return
			}
			driftType, policyID, found := strings.Cut(req.SoftwareKey, ":")
			_, policyErr := strconv.ParseInt(policyID, 10, 64)
			if !found || policyErr != nil ||
				(driftType != "mandatory_missing" && driftType != "unapproved_present" && driftType != "version_below_minimum") {
				http.Error(w, "software_key must be <drift_type>:<policy_id>", http.StatusBadRequest)
				return
			}
		}

		var tenantExists bool
		if err := pool.QueryRow(r.Context(),
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		tx, err := pool.Begin(r.Context())
		if err != nil {
			logger.Error("begin tx failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer func() { _ = tx.Rollback(r.Context()) }()

		switch req.FindingKind {
		case "cis", "software":
			var deviceExists bool
			if err := tx.QueryRow(r.Context(),
				`SELECT EXISTS(SELECT 1 FROM devices WHERE tenant_id = $1::uuid AND id = $2::uuid)`,
				tenantID, req.DeviceID,
			).Scan(&deviceExists); err != nil {
				logger.Error("device ownership check failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if !deviceExists {
				http.Error(w, "device_id does not belong to this tenant", http.StatusNotFound)
				return
			}
		case "cve":
			var cveExists bool
			if err := tx.QueryRow(r.Context(),
				`SELECT EXISTS(SELECT 1 FROM cve_feed_entries WHERE cve_id = $1)`, req.CVEID,
			).Scan(&cveExists); err != nil {
				logger.Error("cve existence check failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if !cveExists {
				http.Error(w, "cve_id not found", http.StatusNotFound)
				return
			}
		}
		if req.FindingKind == "software" {
			_, policyID, _ := strings.Cut(req.SoftwareKey, ":")
			var policyExists bool
			if err := tx.QueryRow(r.Context(), `
				SELECT EXISTS(
					SELECT 1 FROM tenant_app_policies
					WHERE tenant_id = $1::uuid AND id = $2::bigint
				)
			`, tenantID, policyID).Scan(&policyExists); err != nil {
				logger.Error("software policy ownership check failed", "err", err, "tenant_id", tenantID)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			if !policyExists {
				http.Error(w, "software policy does not belong to this tenant", http.StatusNotFound)
				return
			}
		}

		row, err := writeFindingDisposition(r.Context(), tx, tenantID, req, "correction")
		if err != nil {
			logger.Error("finding disposition write failed", "err", err, "tenant_id", tenantID,
				"finding_kind", req.FindingKind)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		identity := findinglifecycle.Identity{
			TenantID:   tenantID,
			Kind:       req.FindingKind,
			FindingKey: req.RuleKey,
		}
		if req.FindingKind == findinglifecycle.KindCVE {
			identity.FindingKey = req.CVEID
		} else {
			identity.DeviceID = &req.DeviceID
			if req.FindingKind == findinglifecycle.KindSoftware {
				identity.FindingKey = req.SoftwareKey
			}
		}
		if err := findinglifecycle.RecordAction(r.Context(), tx, findinglifecycle.Action{
			Identity: identity,
			Type:     req.Status,
			Actor:    req.RecordedBy,
			Reason:   req.Reason,
			Evidence: map[string]any{"disposition_id": row.ID},
		}); err != nil {
			logger.Error("finding lifecycle action write failed", "err", err, "tenant_id", tenantID,
				"finding_kind", req.FindingKind)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := tx.Commit(r.Context()); err != nil {
			logger.Error("commit failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("finding disposition recorded", "tenant_id", tenantID,
			"finding_kind", req.FindingKind, "status", req.Status)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(findingDispositionCreateResp{Disposition: row})
	}
}

// FindingDispositionListHandler serves
// GET /admin/tenants/{tenantID}/finding-dispositions.
//
// Always returns ACTIVE (non-superseded) dispositions only, most-recent
// first (recorded_at DESC) — this endpoint has no audit-trail view.
// ?finding_kind=cis|cve|software narrows to that kind; any other or absent
// value returns all three kinds.
//
// 200 {"dispositions": [...], "total": N} | 400 bad tenantID
func FindingDispositionListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "finding_disposition_list")
		ctx := r.Context()

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		findingKind := strings.TrimSpace(r.URL.Query().Get("finding_kind"))
		if !validFindingKinds[findingKind] {
			findingKind = ""
		}

		rows, err := pool.Query(ctx, `
			SELECT id::text, tenant_id::text, finding_kind, device_id::text, rule_key, cve_id, software_key,
			       status, recorded_by, reason, recorded_at,
			       supersedes_id::text, superseded_at, superseded_reason
			FROM finding_dispositions
			WHERE tenant_id = $1::uuid
			  AND superseded_at IS NULL
			  AND ($2::text = '' OR finding_kind = $2::text)
			ORDER BY recorded_at DESC
		`, tenantID, findingKind)
		if err != nil {
			logger.Error("list query failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		dispositions := []findingDispositionRow{}
		for rows.Next() {
			var d findingDispositionRow
			var deviceID, ruleKey, cveID, softwareKey pgxText
			if err := rows.Scan(
				&d.ID, &d.TenantID, &d.FindingKind, &deviceID, &ruleKey, &cveID, &softwareKey,
				&d.Status, &d.RecordedBy, &d.Reason, &d.RecordedAt,
				&d.SupersedesID, &d.SupersededAt, &d.SupersededReason,
			); err != nil {
				logger.Error("scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			d.DeviceID = deviceID.ptr()
			d.RuleKey = ruleKey.ptr()
			d.CVEID = cveID.ptr()
			d.SoftwareKey = softwareKey.ptr()
			dispositions = append(dispositions, d)
		}
		if err := rows.Err(); err != nil {
			logger.Error("row iteration failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dispositions": dispositions,
			"total":        len(dispositions),
		})
	}
}

// pgxText scans a nullable TEXT column (including a UUID column cast to
// ::text) without forcing every caller to juggle sql.NullString directly.
type pgxText struct {
	s     string
	valid bool
}

func (t *pgxText) Scan(src any) error {
	if src == nil {
		t.s, t.valid = "", false
		return nil
	}
	switch v := src.(type) {
	case string:
		t.s, t.valid = v, true
	case []byte:
		t.s, t.valid = string(v), true
	default:
		t.s, t.valid = "", false
	}
	return nil
}

func (t pgxText) ptr() *string {
	if !t.valid {
		return nil
	}
	s := t.s
	return &s
}

// writeFindingDisposition records one finding's disposition inside tx: it
// first supersedes any existing active (non-superseded) disposition for
// that finding identity — using supersededReason for that transition —
// then inserts the new row with supersedes_id pointing at whatever it just
// superseded (nil if there was nothing live). The identity lookup branches
// on req.FindingKind since CIS and CVE findings key on different columns —
// see migrations/0146_finding_dispositions.sql.
func writeFindingDisposition(ctx context.Context, tx pgx.Tx, tenantID string, req findingDispositionCreateReq, supersededReason string) (findingDispositionRow, error) {
	var supersedesID *string
	var existingID string
	var err error
	switch req.FindingKind {
	case "cis":
		err = tx.QueryRow(ctx, `
			SELECT id::text FROM finding_dispositions
			WHERE tenant_id = $1::uuid AND finding_kind = 'cis'
			  AND device_id = $2::uuid AND rule_key = $3
			  AND superseded_at IS NULL
			FOR UPDATE
		`, tenantID, req.DeviceID, req.RuleKey).Scan(&existingID)
	case "cve":
		err = tx.QueryRow(ctx, `
			SELECT id::text FROM finding_dispositions
			WHERE tenant_id = $1::uuid AND finding_kind = 'cve'
			  AND cve_id = $2
			  AND superseded_at IS NULL
			FOR UPDATE
		`, tenantID, req.CVEID).Scan(&existingID)
	case "software":
		err = tx.QueryRow(ctx, `
			SELECT id::text FROM finding_dispositions
			WHERE tenant_id = $1::uuid AND finding_kind = 'software'
			  AND device_id = $2::uuid AND software_key = $3
			  AND superseded_at IS NULL
			FOR UPDATE
		`, tenantID, req.DeviceID, req.SoftwareKey).Scan(&existingID)
	}
	switch {
	case err == nil:
		if _, uerr := tx.Exec(ctx, `
			UPDATE finding_dispositions SET superseded_at = now(), superseded_reason = $2
			WHERE id = $1::uuid
		`, existingID, supersededReason); uerr != nil {
			return findingDispositionRow{}, uerr
		}
		supersedesID = &existingID
	case err == pgx.ErrNoRows:
		// No active disposition to supersede — a first-time write.
	default:
		return findingDispositionRow{}, err
	}

	var deviceID, ruleKey, cveID, softwareKey *string
	if req.DeviceID != "" {
		deviceID = &req.DeviceID
	}
	if req.RuleKey != "" {
		ruleKey = &req.RuleKey
	}
	if req.CVEID != "" {
		cveID = &req.CVEID
	}
	if req.SoftwareKey != "" {
		softwareKey = &req.SoftwareKey
	}

	row := findingDispositionRow{
		TenantID:     tenantID,
		FindingKind:  req.FindingKind,
		DeviceID:     deviceID,
		RuleKey:      ruleKey,
		CVEID:        cveID,
		SoftwareKey:  softwareKey,
		Status:       req.Status,
		RecordedBy:   req.RecordedBy,
		Reason:       req.Reason,
		SupersedesID: supersedesID,
	}
	if err := tx.QueryRow(ctx, `
		INSERT INTO finding_dispositions
		    (tenant_id, finding_kind, device_id, rule_key, cve_id, software_key, status, recorded_by, reason, supersedes_id)
		VALUES ($1::uuid, $2, $3::uuid, $4, $5, $6, $7, $8, $9, $10::uuid)
		RETURNING id::text, recorded_at
	`, tenantID, req.FindingKind, deviceID, ruleKey, cveID, softwareKey, req.Status, req.RecordedBy, req.Reason, supersedesID,
	).Scan(&row.ID, &row.RecordedAt); err != nil {
		return findingDispositionRow{}, err
	}
	return row, nil
}
