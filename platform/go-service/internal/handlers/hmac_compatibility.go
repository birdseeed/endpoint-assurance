package handlers

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
)

const (
	unknownHMACCompatibilityValue = "Unknown"
	// Each retained version can produce at most one row per signing form. The
	// database vocabulary contains three accepted forms plus Unknown, so the
	// admin response is structurally capped at (64 + Unknown) * 4 = 260 rows.
	maxHMACCompatibilityVersions = 64
	maxHMACCompatibilityRows     = (maxHMACCompatibilityVersions + 1) * 4
	// PostgreSQL advisory locks are database-global. Use a feature-namespaced
	// text key and hash it in PostgreSQL rather than claiming an unexplained
	// numeric key that could collide with an unrelated feature's lock.
	hmacCompatibilityLockKey = "patched:hmac-compatibility:version-admission:v1"
)

var hmacCompatibilityVersionPattern = regexp.MustCompile(`^v?[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,15})?$`)

// hmacCompatibilityTelemetryEnabled is an independent kill switch for the
// telemetry write path. Authentication compatibility flags are intentionally
// separate and are never read or changed here. Enabled by default; setting
// HMAC_COMPATIBILITY_TELEMETRY_ENABLED=false (also 0/off/no) disables writes
// after a service restart without changing which signatures are accepted.
func hmacCompatibilityTelemetryEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("HMAC_COMPATIBILITY_TELEMETRY_ENABLED"))) {
	case "false", "0", "off", "no":
		return false
	default:
		return true
	}
}

// hmacCompatibilityAgentVersion extracts only the explicitly reported
// top-level version. It never returns the body, parse errors, or any other
// field. Missing, non-string, overlong, and non-version values collapse to a
// single Unknown bucket so attacker-controlled payloads cannot create labels
// or rows containing tokens, signatures, nonces, request bodies, or arbitrary
// high-cardinality text.
func hmacCompatibilityAgentVersion(body []byte) string {
	var envelope struct {
		AgentVersion any `json:"agent_version"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return unknownHMACCompatibilityValue
	}
	version, ok := envelope.AgentVersion.(string)
	if !ok {
		return unknownHMACCompatibilityValue
	}
	version = strings.TrimSpace(version)
	if len(version) > 32 || !hmacCompatibilityVersionPattern.MatchString(version) {
		return unknownHMACCompatibilityValue
	}
	return version
}

// boundedHMACCompatibilityVersion applies the durable distinct-version cap.
// Existing values remain countable after the cap is reached; only a new value
// is folded into Unknown.
func boundedHMACCompatibilityVersion(version string, exists bool, distinctVersions int) string {
	if version == unknownHMACCompatibilityValue || exists || distinctVersions < maxHMACCompatibilityVersions {
		return version
	}
	return unknownHMACCompatibilityValue
}

// recordHMACCompatibility increments one aggregate row. It accepts only the
// already-classified form and sanitised version, never request headers,
// credentials, signature material, nonce, body, tenant id, or device id.
// Callers treat failures as best-effort telemetry failures: this function must
// never influence the HTTP authentication or acceptance result.
func recordHMACCompatibility(ctx context.Context, pool *pgxpool.Pool, form auth.HMACSigningForm, agentVersion string) error {
	if !hmacCompatibilityTelemetryEnabled() {
		return nil
	}
	if form != auth.HMACSigningFormV3 && form != auth.HMACSigningFormTargetlessV2 && form != auth.HMACSigningFormBodyOnly {
		form = auth.HMACSigningFormUnknown
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	// Rollback after a successful Commit is the documented pgx no-op. On an
	// earlier return, the original operation error is more useful to the caller
	// than a secondary cleanup error, so the deferred rollback is intentionally
	// best-effort.
	defer func() { _ = tx.Rollback(ctx) }()

	// Serialize first-seen version admission so concurrent novel values cannot
	// race past the global 64-value cap.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, hmacCompatibilityLockKey); err != nil {
		return err
	}

	var exists bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM hmac_compatibility_telemetry
			WHERE agent_version = $1
		)
	`, agentVersion).Scan(&exists); err != nil {
		return err
	}

	var distinctVersions int
	if !exists && agentVersion != unknownHMACCompatibilityValue {
		if err := tx.QueryRow(ctx, `
			SELECT COUNT(DISTINCT agent_version)
			FROM hmac_compatibility_telemetry
			WHERE agent_version <> $1
		`, unknownHMACCompatibilityValue).Scan(&distinctVersions); err != nil {
			return err
		}
	}
	agentVersion = boundedHMACCompatibilityVersion(agentVersion, exists, distinctVersions)

	if _, err := tx.Exec(ctx, `
		INSERT INTO hmac_compatibility_telemetry
			(signing_form, agent_version, accepted_count, first_seen_at, last_seen_at)
		VALUES ($1, $2, 1, NOW(), NOW())
		ON CONFLICT (signing_form, agent_version) DO UPDATE
		SET accepted_count = hmac_compatibility_telemetry.accepted_count + 1,
			last_seen_at = NOW()
	`, string(form), agentVersion); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

type hmacCompatibilityObservation struct {
	SigningForm  string    `json:"signing_form"`
	AgentVersion string    `json:"agent_version"`
	Accepted     int64     `json:"accepted_count"`
	FirstSeenAt  time.Time `json:"first_seen_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// HMACCompatibilityTelemetryHandler serves a bounded, estate-wide aggregate.
// It is mounted only on the authenticated internal admin router. Tenant and
// device identifiers are deliberately absent: this endpoint answers the
// compatibility question without exposing per-tenant activity.
func HMACCompatibilityTelemetryHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rows, err := pool.Query(r.Context(), `
			SELECT signing_form, agent_version, accepted_count, first_seen_at, last_seen_at
			FROM hmac_compatibility_telemetry
			ORDER BY signing_form, agent_version
			LIMIT $1
		`, maxHMACCompatibilityRows)
		if err != nil {
			slog.Error("query HMAC compatibility telemetry failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		observations := make([]hmacCompatibilityObservation, 0)
		var total int64
		for rows.Next() {
			var item hmacCompatibilityObservation
			if err := rows.Scan(&item.SigningForm, &item.AgentVersion, &item.Accepted, &item.FirstSeenAt, &item.LastSeenAt); err != nil {
				slog.Error("scan HMAC compatibility telemetry failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			total += item.Accepted
			observations = append(observations, item)
		}
		if err := rows.Err(); err != nil {
			slog.Error("iterate HMAC compatibility telemetry failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enabled":                     hmacCompatibilityTelemetryEnabled(),
			"max_distinct_agent_versions": maxHMACCompatibilityVersions,
			"total_accepted":              total,
			"observations":                observations,
		})
	}
}
