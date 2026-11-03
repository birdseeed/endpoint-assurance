package handlers

// PAT-1549: remediation artefact generation for advisory CIS/config
// findings — per-platform artefacts (a .mobileconfig for macOS, an Intune
// settings-catalogue JSON payload for Windows) the customer applies
// themselves in their own management platform. Patched never touches the
// customer's tenant.
//
// "Signed" caveat: the .mobileconfig content is well-formed and
// content-hashed, but is NOT wrapped in the CMS/PKCS#7 signature macOS/Jamf
// need to show it as Apple-trust "Verified" — see the SIGNING comment on
// internal/remediation's buildMobileconfig for what that would take and why
// it is a follow-up, not part of this ticket's generator.
//
// Routes (all on the internal admin listener):
//
//	POST /admin/tenants/{tenantID}/remediation-artefacts
//	    Generate an artefact for one (device_id, rule_id) finding. The rule
//	    must resolve to a compliance_rules row (CVE findings have no rule_id
//	    at all and cannot reach this path — see internal/remediation's
//	    package doc comment), must currently be FAILING for the device (the
//	    most recent compliance_evaluations row for the pair), and must have
//	    a curated remediation mapping (internal/remediation/mapping.go) —
//	    otherwise this returns 422, never a guessed-at payload. A prior
//	    "current" artefact for the same (device, rule) is superseded (its
//	    id recorded in the new row's supersedes_id); it is never edited or
//	    deleted, so both remain visible in GET history.
//	GET  /admin/tenants/{tenantID}/remediation-artefacts
//	    List artefacts for the tenant (optional ?device_id=, ?rule_id=,
//	    ?status= filters). Payload body is omitted from list rows — fetch
//	    the single-artefact route for the actual .mobileconfig/JSON content.
//	GET  /admin/tenants/{tenantID}/remediation-artefacts/{artefactID}
//	    One artefact, including its generated payload.
//
// There is deliberately no "mark applied" endpoint here: application is
// observed, never asked (ticket ruling 2). See
// internal/extractor/upsert.go's markArtefactsApplied for the only path
// that ever sets status = 'applied'.

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/remediation"
)

// remediationArtefactSummary is the list-row shape — no payload body.
type remediationArtefactSummary struct {
	ID                 string     `json:"id"`
	TenantID           string     `json:"tenant_id"`
	DeviceID           string     `json:"device_id"`
	RuleID             string     `json:"rule_id"`
	RuleKey            string     `json:"rule_key"`
	Platform           string     `json:"platform"`
	RulePackVersion    string     `json:"rule_pack_version"`
	ObservedPriorValue *string    `json:"observed_prior_value"`
	ContentHash        string     `json:"content_hash"`
	GeneratedAt        time.Time  `json:"generated_at"`
	GeneratedBy        string     `json:"generated_by"`
	Status             string     `json:"status"`
	AppliedObservedAt  *time.Time `json:"applied_observed_at"`
	SupersedesID       *string    `json:"supersedes_id"`
}

// remediationArtefactDetail adds the generated payload body itself.
type remediationArtefactDetail struct {
	remediationArtefactSummary
	Payload string `json:"payload"`
}

// RemediationArtefactGenerateHandler serves
// POST /admin/tenants/{tenantID}/remediation-artefacts.
//
// 201 remediationArtefactDetail | 400 bad input | 404 unknown tenant/device/rule
// | 409 rule is not currently failing for this device | 422 no known
// remediation mapping for this rule yet.
func RemediationArtefactGenerateHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "remediation_artefact_generate")
		ctx := r.Context()

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			http.Error(w, "cannot read body", http.StatusBadRequest)
			return
		}
		var req struct {
			DeviceID    string `json:"device_id"`
			RuleID      string `json:"rule_id"`
			GeneratedBy string `json:"generated_by"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		req.DeviceID = strings.TrimSpace(req.DeviceID)
		req.RuleID = strings.TrimSpace(req.RuleID)
		req.GeneratedBy = strings.TrimSpace(req.GeneratedBy)
		if !looksLikeUUID(req.DeviceID) {
			http.Error(w, "device_id must be a UUID", http.StatusBadRequest)
			return
		}
		if !looksLikeUUID(req.RuleID) {
			http.Error(w, "rule_id must be a UUID", http.StatusBadRequest)
			return
		}

		var tenantExists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1::uuid AND revoked_at IS NULL)`, tenantID,
		).Scan(&tenantExists); err != nil || !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}

		var deviceExists bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1::uuid AND tenant_id = $2::uuid)`,
			req.DeviceID, tenantID,
		).Scan(&deviceExists); err != nil || !deviceExists {
			http.Error(w, "device not found for this tenant", http.StatusNotFound)
			return
		}

		var rule remediation.RuleContext
		err = pool.QueryRow(ctx, `
			SELECT id::text, rule_key, benchmark, benchmark_version, title,
			       COALESCE(description, ''), severity, platform, signal_key, comparator
			FROM compliance_rules
			WHERE id = $1::uuid
		`, req.RuleID).Scan(
			&rule.RuleID, &rule.RuleKey, new(string), &rule.BenchmarkVersion, &rule.Title,
			&rule.Description, &rule.Severity, &rule.Platform, &rule.SignalKey, &rule.Comparator,
		)
		if err != nil {
			if err == pgx.ErrNoRows {
				// rule_id does not resolve to a compliance_rules row at all — this
				// is also the outcome for a CVE finding id, since device_cve_findings
				// keys on cve_id (text), never a compliance_rules UUID. There is no
				// separate "is this a CVE finding" branch to write: it structurally
				// cannot match here.
				http.Error(w, "rule not found", http.StatusNotFound)
				return
			}
			logger.Error("rule lookup failed", "err", err, "rule_id", req.RuleID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// The most recent evaluation for this (device, rule) is the only
		// evidence this endpoint trusts. No evaluation on record is not
		// treated as "safe to generate" (absence requires authority) — nor
		// is any status other than a genuine, currently observed 'fail'.
		var latestStatus string
		var observedPriorValue *string
		err = pool.QueryRow(ctx, `
			SELECT status, observed_value
			FROM compliance_evaluations
			WHERE device_id = $1::uuid AND rule_id = $2::uuid
			ORDER BY evaluated_at DESC
			LIMIT 1
		`, req.DeviceID, req.RuleID).Scan(&latestStatus, &observedPriorValue)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "no evaluation on record for this device and rule; cannot generate a remediation artefact without an observed failing state", http.StatusConflict)
				return
			}
			logger.Error("evaluation lookup failed", "err", err, "device_id", req.DeviceID, "rule_id", req.RuleID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if latestStatus != "fail" {
			http.Error(w, "rule is not currently failing for this device (latest status: "+latestStatus+")", http.StatusConflict)
			return
		}

		generatedAt := time.Now().UTC()
		genResult, err := remediation.Generate(remediation.GenerateInput{
			TenantID:           tenantID,
			DeviceID:           req.DeviceID,
			Rule:               rule,
			ObservedPriorValue: observedPriorValue,
			GeneratedAt:        generatedAt,
		})
		if err != nil {
			if err == remediation.ErrNoMapping {
				http.Error(w, "no known remediation payload mapping for this rule yet", http.StatusUnprocessableEntity)
				return
			}
			if err == remediation.ErrUnsupportedPlatform {
				http.Error(w, "rule has no single-platform remediation format", http.StatusBadRequest)
				return
			}
			logger.Error("artefact generation failed", "err", err, "rule_id", req.RuleID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// The current (non-superseded) artefact for this exact (device, rule)
		// pair, if any — a row nothing else's supersedes_id points at.
		var supersedesID *string
		if err := pool.QueryRow(ctx, `
			SELECT a.id::text
			FROM remediation_artefacts a
			WHERE a.device_id = $1::uuid AND a.rule_id = $2::uuid
			  AND NOT EXISTS (SELECT 1 FROM remediation_artefacts b WHERE b.supersedes_id = a.id)
			ORDER BY a.generated_at DESC
			LIMIT 1
		`, req.DeviceID, req.RuleID).Scan(&supersedesID); err != nil && err != pgx.ErrNoRows {
			logger.Error("supersedes lookup failed", "err", err, "device_id", req.DeviceID, "rule_id", req.RuleID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		var row remediationArtefactDetail
		err = pool.QueryRow(ctx, `
			INSERT INTO remediation_artefacts
			    (tenant_id, device_id, rule_id, platform, rule_pack_version,
			     observed_prior_value, payload, content_hash, generated_at, generated_by, supersedes_id)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4, $5, $6, $7, $8, $9, $10, $11::uuid)
			RETURNING id::text, tenant_id::text, device_id::text, rule_id::text, platform,
			          rule_pack_version, observed_prior_value, content_hash,
			          generated_at, generated_by, status, applied_observed_at, supersedes_id::text, payload
		`,
			tenantID, req.DeviceID, req.RuleID, genResult.Platform, rule.BenchmarkVersion,
			observedPriorValue, string(genResult.Payload), genResult.ContentHash, generatedAt, req.GeneratedBy, supersedesID,
		).Scan(
			&row.ID, &row.TenantID, &row.DeviceID, &row.RuleID, &row.Platform,
			&row.RulePackVersion, &row.ObservedPriorValue, &row.ContentHash,
			&row.GeneratedAt, &row.GeneratedBy, &row.Status, &row.AppliedObservedAt, &row.SupersedesID, &row.Payload,
		)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "idx_remediation_artefacts_supersedes_unique" {
				// Lost a race: another regeneration for this exact (device,
				// rule) pair already claimed the same supersedes target
				// between our SELECT and this INSERT. The other request's
				// artefact is now the current tip — retry re-reads it.
				http.Error(w, "concurrent regeneration for this device/rule, retry", http.StatusConflict)
				return
			}
			logger.Error("artefact insert failed", "err", err, "device_id", req.DeviceID, "rule_id", req.RuleID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		row.RuleKey = rule.RuleKey

		supersedesLog := "none"
		if row.SupersedesID != nil {
			supersedesLog = *row.SupersedesID
		}
		logger.Info("remediation artefact generated",
			"tenant_id", tenantID, "device_id", req.DeviceID, "rule_id", req.RuleID,
			"platform", row.Platform, "artefact_id", row.ID, "supersedes_id", supersedesLog)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(row)
	}
}

// RemediationArtefactListHandler serves
// GET /admin/tenants/{tenantID}/remediation-artefacts, with optional
// ?device_id=, ?rule_id=, ?status= filters.
func RemediationArtefactListHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "remediation_artefact_list")
		ctx := r.Context()

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		q := r.URL.Query()
		deviceFilter := strings.TrimSpace(q.Get("device_id"))
		ruleFilter := strings.TrimSpace(q.Get("rule_id"))
		statusFilter := strings.TrimSpace(q.Get("status"))
		if deviceFilter != "" && !looksLikeUUID(deviceFilter) {
			http.Error(w, "device_id must be a UUID", http.StatusBadRequest)
			return
		}
		if ruleFilter != "" && !looksLikeUUID(ruleFilter) {
			http.Error(w, "rule_id must be a UUID", http.StatusBadRequest)
			return
		}
		if statusFilter != "" && statusFilter != "issued" && statusFilter != "applied" {
			http.Error(w, "status must be issued or applied", http.StatusBadRequest)
			return
		}

		rows, err := pool.Query(ctx, `
			SELECT a.id::text, a.tenant_id::text, a.device_id::text, a.rule_id::text, r.rule_key,
			       a.platform, a.rule_pack_version, a.observed_prior_value, a.content_hash,
			       a.generated_at, a.generated_by, a.status, a.applied_observed_at, a.supersedes_id::text
			FROM remediation_artefacts a
			JOIN compliance_rules r ON r.id = a.rule_id
			WHERE a.tenant_id = $1::uuid
			  AND ($2 = '' OR a.device_id = $2::uuid)
			  AND ($3 = '' OR a.rule_id = $3::uuid)
			  AND ($4 = '' OR a.status = $4)
			ORDER BY a.generated_at DESC
		`, tenantID, deviceFilter, ruleFilter, statusFilter)
		if err != nil {
			logger.Error("list query failed", "err", err, "tenant_id", tenantID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		artefacts := []remediationArtefactSummary{}
		for rows.Next() {
			var a remediationArtefactSummary
			if err := rows.Scan(
				&a.ID, &a.TenantID, &a.DeviceID, &a.RuleID, &a.RuleKey,
				&a.Platform, &a.RulePackVersion, &a.ObservedPriorValue, &a.ContentHash,
				&a.GeneratedAt, &a.GeneratedBy, &a.Status, &a.AppliedObservedAt, &a.SupersedesID,
			); err != nil {
				logger.Error("scan failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			artefacts = append(artefacts, a)
		}
		if err := rows.Err(); err != nil {
			logger.Error("row iteration failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"artefacts": artefacts,
			"total":     len(artefacts),
		})
	}
}

// RemediationArtefactGetHandler serves
// GET /admin/tenants/{tenantID}/remediation-artefacts/{artefactID}, including
// the generated payload.
func RemediationArtefactGetHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("req_id", middleware.GetReqID(r.Context()), "handler", "remediation_artefact_get")
		ctx := r.Context()

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		artefactID := strings.TrimSpace(chi.URLParam(r, "artefactID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}
		if !looksLikeUUID(artefactID) {
			http.Error(w, "artefactID must be a UUID", http.StatusBadRequest)
			return
		}

		var row remediationArtefactDetail
		err := pool.QueryRow(ctx, `
			SELECT a.id::text, a.tenant_id::text, a.device_id::text, a.rule_id::text, r.rule_key,
			       a.platform, a.rule_pack_version, a.observed_prior_value, a.content_hash,
			       a.generated_at, a.generated_by, a.status, a.applied_observed_at, a.supersedes_id::text, a.payload
			FROM remediation_artefacts a
			JOIN compliance_rules r ON r.id = a.rule_id
			WHERE a.id = $1::uuid AND a.tenant_id = $2::uuid
		`, artefactID, tenantID).Scan(
			&row.ID, &row.TenantID, &row.DeviceID, &row.RuleID, &row.RuleKey,
			&row.Platform, &row.RulePackVersion, &row.ObservedPriorValue, &row.ContentHash,
			&row.GeneratedAt, &row.GeneratedBy, &row.Status, &row.AppliedObservedAt, &row.SupersedesID, &row.Payload,
		)
		if err != nil {
			if err == pgx.ErrNoRows {
				http.Error(w, "artefact not found for this tenant", http.StatusNotFound)
				return
			}
			logger.Error("get query failed", "err", err, "artefact_id", artefactID)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(row)
	}
}
