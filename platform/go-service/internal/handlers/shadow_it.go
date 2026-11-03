package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ShadowITCatalogueHandler returns the global shadow IT catalogue.
// GET /admin/shadow-it/catalogue
func ShadowITCatalogueHandler(pool *pgxpool.Pool) http.HandlerFunc {
	type entry struct {
		Label      string   `json:"label"`
		Name       string   `json:"name"`
		Category   string   `json:"category"`
		MatchNames []string `json:"match_names"`
		Notes      string   `json:"notes,omitempty"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := pool.Query(r.Context(), `
			SELECT label, name, category, match_names, COALESCE(notes, '') AS notes
			FROM shadow_it_catalogue
			ORDER BY category, name
		`)
		if err != nil {
			slog.Error("shadow_it catalogue query failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var entries []entry
		for rows.Next() {
			var e entry
			if err := rows.Scan(&e.Label, &e.Name, &e.Category, &e.MatchNames, &e.Notes); err != nil {
				continue
			}
			entries = append(entries, e)
		}
		if entries == nil {
			entries = []entry{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"catalogue": entries, "total": len(entries)})
	}
}

// ShadowITFindingsHandler returns devices at a tenant that have shadow IT apps installed.
// GET /admin/tenants/{tenantID}/shadow-it/findings
func ShadowITFindingsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	type finding struct {
		ShadowITLabel string     `json:"shadow_it_label"`
		Category      string     `json:"category"`
		ShadowITName  string     `json:"shadow_it_name"`
		DeviceID      string     `json:"device_id"`
		Hostname      string     `json:"hostname"`
		AppName       string     `json:"app_name"`
		Identifier    string     `json:"identifier"`
		Policy        string     `json:"policy"`
		FirstSeen     time.Time  `json:"first_seen"`
		LastSeen      time.Time  `json:"last_seen"`
		Reason        *string    `json:"reason,omitempty"`
		Actor         *string    `json:"actor,omitempty"`
		ClaimedActor  *string    `json:"claimed_actor,omitempty"`
		PolicyUpdated *time.Time `json:"policy_updated_at,omitempty"`
	}
	type exception struct {
		ShadowITLabel string    `json:"shadow_it_label"`
		Category      string    `json:"category"`
		ShadowITName  string    `json:"shadow_it_name"`
		Reason        *string   `json:"reason,omitempty"`
		Actor         string    `json:"actor"`
		ClaimedActor  *string   `json:"claimed_actor,omitempty"`
		UpdatedAt     time.Time `json:"updated_at"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		rows, err := pool.Query(r.Context(), `
			SELECT
				sic.label        AS shadow_it_label,
				sic.category,
				sic.name         AS shadow_it_name,
				d.id::text       AS device_id,
				COALESCE(d.hostname, d.serial, d.id::text) AS hostname,
				da.name          AS app_name,
				da.identifier,
				COALESCE(tip.policy, 'flag'),
				da.first_seen,
				da.last_seen,
				tip.reason,
				tip.actor,
				tip.claimed_actor,
				tip.updated_at
			FROM shadow_it_catalogue sic
			CROSS JOIN devices d
			JOIN device_apps da ON da.device_id = d.id
			LEFT JOIN tenant_shadow_it_policy tip
				ON tip.tenant_id = d.tenant_id AND tip.label = sic.label
			WHERE d.tenant_id = $1::uuid
			  AND EXISTS (
				SELECT 1 FROM unnest(sic.match_names) AS mn
				WHERE da.name ILIKE '%' || mn || '%'
			  )
			ORDER BY sic.category, sic.label, d.hostname, da.name
		`, tenantID)
		if err != nil {
			slog.Error("shadow_it findings query failed", "tenant_id", tenantID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var findings []finding
		for rows.Next() {
			var f finding
			if err := rows.Scan(
				&f.ShadowITLabel, &f.Category, &f.ShadowITName,
				&f.DeviceID, &f.Hostname, &f.AppName, &f.Identifier,
				&f.Policy, &f.FirstSeen, &f.LastSeen, &f.Reason,
				&f.Actor, &f.ClaimedActor, &f.PolicyUpdated,
			); err != nil {
				slog.Error("shadow_it finding scan failed", "tenant_id", tenantID, "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			findings = append(findings, f)
		}
		if err := rows.Err(); err != nil {
			slog.Error("shadow_it findings rows failed", "tenant_id", tenantID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if findings == nil {
			findings = []finding{}
		}

		exceptionRows, err := pool.Query(r.Context(), `
			SELECT sic.label, sic.category, sic.name, tip.reason, tip.actor,
			       tip.claimed_actor, tip.updated_at
			FROM tenant_shadow_it_policy tip
			JOIN shadow_it_catalogue sic ON sic.label = tip.label
			WHERE tip.tenant_id = $1::uuid AND tip.policy = 'allow'
			ORDER BY sic.category, sic.name
		`, tenantID)
		if err != nil {
			slog.Error("shadow_it exceptions query failed", "tenant_id", tenantID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer exceptionRows.Close()
		exceptions := []exception{}
		for exceptionRows.Next() {
			var e exception
			if err := exceptionRows.Scan(&e.ShadowITLabel, &e.Category, &e.ShadowITName,
				&e.Reason, &e.Actor, &e.ClaimedActor, &e.UpdatedAt); err != nil {
				slog.Error("shadow_it exception scan failed", "tenant_id", tenantID, "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			exceptions = append(exceptions, e)
		}
		if err := exceptionRows.Err(); err != nil {
			slog.Error("shadow_it exceptions rows failed", "tenant_id", tenantID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"findings": findings, "total": len(findings),
			"exceptions": exceptions, "exception_total": len(exceptions),
		})
	}
}

// ShadowITPolicyPutHandler sets per-tenant policy for a shadow IT label.
// PUT /admin/tenants/{tenantID}/shadow-it/{label}
func ShadowITPolicyPutHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		label := strings.TrimSpace(chi.URLParam(r, "label"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var body struct {
			Policy string `json:"policy"`
			Reason string `json:"reason"`
			Actor  string `json:"actor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || (body.Policy != "flag" && body.Policy != "allow") {
			http.Error(w, `{"error":"policy must be flag or allow"}`, http.StatusBadRequest)
			return
		}
		body.Reason = strings.TrimSpace(body.Reason)
		body.Actor = strings.TrimSpace(body.Actor)
		if body.Policy == "allow" && body.Reason == "" {
			http.Error(w, `{"error":"reason is required when allowing an exception"}`, http.StatusBadRequest)
			return
		}
		if len(body.Reason) > 500 || len(body.Actor) > 200 {
			http.Error(w, `{"error":"reason or actor is too long"}`, http.StatusBadRequest)
			return
		}

		tx, err := pool.Begin(r.Context())
		if err != nil {
			slog.Error("shadow_it policy begin failed", "tenant_id", tenantID, "label", label, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer tx.Rollback(r.Context())

		var labelExists bool
		if err := tx.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM shadow_it_catalogue WHERE label = $1)`, label).Scan(&labelExists); err != nil {
			slog.Error("shadow_it label lookup failed", "tenant_id", tenantID, "label", label, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if !labelExists {
			http.Error(w, `{"error":"unknown shadow IT label"}`, http.StatusNotFound)
			return
		}

		var oldPolicy string
		err = tx.QueryRow(r.Context(), `
			SELECT policy FROM tenant_shadow_it_policy
			WHERE tenant_id = $1::uuid AND label = $2
		`, tenantID, label).Scan(&oldPolicy)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			slog.Error("shadow_it old policy lookup failed", "tenant_id", tenantID, "label", label, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var oldPolicyValue interface{}
		if err == nil {
			oldPolicyValue = oldPolicy
		}

		actor, claimedActor, sourceAddr := auditAttribution(r, body.Actor)
		_, err = tx.Exec(r.Context(), `
			INSERT INTO tenant_shadow_it_policy
			    (tenant_id, label, policy, reason, actor, claimed_actor, source_addr, updated_at)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, now())
			ON CONFLICT (tenant_id, label) DO UPDATE
				SET policy = excluded.policy,
				    reason = excluded.reason,
				    actor = excluded.actor,
				    claimed_actor = excluded.claimed_actor,
				    source_addr = excluded.source_addr,
				    updated_at = excluded.updated_at
		`, tenantID, label, body.Policy, nilIfEmpty(body.Reason), actor, claimedActor, sourceAddr)
		if err != nil {
			slog.Error("shadow_it policy put failed", "tenant_id", tenantID, "label", label, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if _, err := tx.Exec(r.Context(), `
			INSERT INTO tenant_shadow_it_policy_changes
			    (tenant_id, label, old_policy, new_policy, reason, actor, claimed_actor, source_addr)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8)
		`, tenantID, label, oldPolicyValue, body.Policy, nilIfEmpty(body.Reason), actor, claimedActor, sourceAddr); err != nil {
			slog.Error("shadow_it policy audit failed", "tenant_id", tenantID, "label", label, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := tx.Commit(r.Context()); err != nil {
			slog.Error("shadow_it policy commit failed", "tenant_id", tenantID, "label", label, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"tenant_id": tenantID, "label": label, "policy": body.Policy,
			"reason": body.Reason, "actor": actor, "claimed_actor": claimedActor,
		})
	}
}
