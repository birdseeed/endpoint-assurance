package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"unicode"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxBlockedVersionValueBytes = 256

var errBlockedVersionTenantNotFound = errors.New("tenant not found")
var errAgentConfigNotInitialised = errors.New("agent config not initialised")

// blockedVersionMutationReq is the deliberately narrow incident-response write
// contract. It changes one label/version pair without asking the operator to
// reconstruct the tenant's complete signed configuration under pressure.
type blockedVersionMutationReq struct {
	Action  string `json:"action"`
	Label   string `json:"label"`
	Version string `json:"version"`
}

type blockedVersionMutationResp struct {
	BlockedVersions map[string][]string `json:"blocked_versions"`
	Changed         bool                `json:"changed"`
	ConfigVersion   int                 `json:"config_version"`
	TenantID        string              `json:"tenant_id"`
}

type blockedVersionMutationResult struct {
	BlockedVersions map[string][]string
	Changed         bool
	ConfigVersion   int
}

type blockedVersionMutateFn func(context.Context, string, blockedVersionMutationReq) (blockedVersionMutationResult, error)

// AdminBlockedVersionsPatchHandler builds the lossless, atomic blocked-version
// mutation route. Authentication is enforced by the internal listener's
// ADMIN_API_TOKEN middleware in addition to its Tailscale-only network boundary.
func AdminBlockedVersionsPatchHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return newAdminBlockedVersionsPatchHandler(func(ctx context.Context, tenantID string, req blockedVersionMutationReq) (blockedVersionMutationResult, error) {
		return dbMutateBlockedVersion(ctx, pool, tenantID, req)
	})
}

func newAdminBlockedVersionsPatchHandler(mutateFn blockedVersionMutateFn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "admin_blocked_versions_patch")

		tenantID := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tenantID) {
			http.Error(w, "tenantID must be a UUID", http.StatusBadRequest)
			return
		}

		var req blockedVersionMutationReq
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		var trailing interface{}
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		if err := validateBlockedVersionMutationReq(req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		result, err := mutateFn(r.Context(), tenantID, req)
		if err != nil {
			if errors.Is(err, errBlockedVersionTenantNotFound) {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}
			if errors.Is(err, errAgentConfigNotInitialised) {
				http.Error(w, "agent config not initialised", http.StatusConflict)
				return
			}
			logger.Error("mutate blocked_versions failed", "err", err, "tenant_id", tenantID,
				"action", req.Action, "label", req.Label, "version", req.Version)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if result.BlockedVersions == nil {
			result.BlockedVersions = map[string][]string{}
		}
		logger.Info("blocked_versions mutation complete", "tenant_id", tenantID,
			"action", req.Action, "label", req.Label, "version", req.Version,
			"changed", result.Changed, "config_version", result.ConfigVersion,
			"updated_by", adminSharedTokenActor)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(blockedVersionMutationResp{
			BlockedVersions: result.BlockedVersions,
			Changed:         result.Changed,
			ConfigVersion:   result.ConfigVersion,
			TenantID:        tenantID,
		})
	}
}

func validateBlockedVersionMutationReq(req blockedVersionMutationReq) error {
	if req.Action != "add" && req.Action != "remove" {
		return fmt.Errorf("action must be \"add\" or \"remove\", got %q", req.Action)
	}
	if err := validateBlockedVersionValue("label", req.Label); err != nil {
		return err
	}
	if strings.ContainsAny(req.Label, "/\\") || strings.Contains(req.Label, "..") {
		return fmt.Errorf("label %q must not contain path separators or \"..\"", req.Label)
	}
	if err := validateBlockedVersionValue("version", req.Version); err != nil {
		return err
	}
	return nil
}

func validateBlockedVersionValue(field, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s must not be empty", field)
	}
	if strings.TrimSpace(value) != value {
		return fmt.Errorf("%s must not have leading or trailing whitespace", field)
	}
	if len(value) > maxBlockedVersionValueBytes || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s must be at most %d bytes and contain no control characters", field, maxBlockedVersionValueBytes)
	}
	return nil
}

// mutateBlockedVersionsBody edits only body.blocked_versions. Every other
// top-level JSON value is retained as json.RawMessage so fields unknown to this
// binary (including fields introduced by a newer writer) survive unchanged in
// JSONB semantics. An empty blocked-version map is omitted from storage, matching
// ConfigBody's omitempty wire contract.
func mutateBlockedVersionsBody(body []byte, action, label, version string) ([]byte, map[string][]string, bool, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil, false, fmt.Errorf("unmarshal agent_config body: %w", err)
	}
	if raw == nil {
		return nil, nil, false, errors.New("agent_config body must be a JSON object")
	}

	blocked := map[string][]string{}
	if blockedRaw, ok := raw["blocked_versions"]; ok && string(blockedRaw) != "null" {
		if err := json.Unmarshal(blockedRaw, &blocked); err != nil {
			return nil, nil, false, fmt.Errorf("unmarshal blocked_versions: %w", err)
		}
		if blocked == nil {
			blocked = map[string][]string{}
		}
	}

	changed := false
	versions := blocked[label]
	switch action {
	case "add":
		for _, existing := range versions {
			if existing == version {
				return body, blocked, false, nil
			}
		}
		blocked[label] = append(versions, version)
		changed = true
	case "remove":
		kept := make([]string, 0, len(versions))
		for _, existing := range versions {
			if existing == version {
				changed = true
				continue
			}
			kept = append(kept, existing)
		}
		if !changed {
			return body, blocked, false, nil
		}
		if len(kept) == 0 {
			delete(blocked, label)
		} else {
			blocked[label] = kept
		}
	default:
		return nil, nil, false, fmt.Errorf("unsupported blocked_versions action %q", action)
	}

	if len(blocked) == 0 {
		delete(raw, "blocked_versions")
	} else {
		blockedRaw, err := json.Marshal(blocked)
		if err != nil {
			return nil, nil, false, fmt.Errorf("marshal blocked_versions: %w", err)
		}
		raw["blocked_versions"] = blockedRaw
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return nil, nil, false, fmt.Errorf("marshal agent_config body: %w", err)
	}
	return out, blocked, true, nil
}

// dbMutateBlockedVersion serialises mutations on the tenant and agent_config
// rows in one transaction. Existing bodies are updated under FOR UPDATE. A
// tenant without an agent_config row is rejected: an incident mutation must not
// guess or synthesise the tenant's baseline configuration.
func dbMutateBlockedVersion(ctx context.Context, pool *pgxpool.Pool, tenantID string, req blockedVersionMutationReq) (blockedVersionMutationResult, error) {
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return blockedVersionMutationResult{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var tenantMarker int
	if err := tx.QueryRow(ctx, `SELECT 1 FROM tenants WHERE id = $1::uuid FOR UPDATE`, tenantID).Scan(&tenantMarker); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return blockedVersionMutationResult{}, errBlockedVersionTenantNotFound
		}
		return blockedVersionMutationResult{}, err
	}

	var configVersion int
	var body []byte
	err = tx.QueryRow(ctx, `
			SELECT config_version, body
			FROM agent_config
			WHERE tenant_id = $1::uuid
			FOR UPDATE
	`, tenantID).Scan(&configVersion, &body)
	if errors.Is(err, pgx.ErrNoRows) {
		return blockedVersionMutationResult{}, errAgentConfigNotInitialised
	}
	if err != nil {
		return blockedVersionMutationResult{}, err
	}

	mutatedBody, blocked, changed, err := mutateBlockedVersionsBody(body, req.Action, req.Label, req.Version)
	if err != nil {
		return blockedVersionMutationResult{}, err
	}
	if !changed {
		if err := tx.Commit(ctx); err != nil {
			return blockedVersionMutationResult{}, err
		}
		return blockedVersionMutationResult{BlockedVersions: blocked, ConfigVersion: configVersion}, nil
	}

	var newVersion int
	if err := tx.QueryRow(ctx, `
			UPDATE agent_config
			SET body = $2::jsonb,
			    config_version = config_version + 1,
			    issued_at = now(),
			    updated_by = $3
			WHERE tenant_id = $1::uuid
			RETURNING config_version
	`, tenantID, mutatedBody, adminSharedTokenActor).Scan(&newVersion); err != nil {
		return blockedVersionMutationResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return blockedVersionMutationResult{}, err
	}
	return blockedVersionMutationResult{BlockedVersions: blocked, Changed: true, ConfigVersion: newVersion}, nil
}
