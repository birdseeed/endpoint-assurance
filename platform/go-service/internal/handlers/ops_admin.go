package handlers

// PAT-710: Ops panel platform endpoints.
//
// GET /admin/ops/version    — binary build info (git SHA, build time) + schema_migrations version.
// GET /admin/ops/partitions — raw_payloads monthly partition horizon.
// GET /admin/ops/maintenance — PAT-993: patch/reboot/timer-drift facts snapshot.
//
// All three live on the internal :8081 listener; auth via requireAdminToken (same as all /admin/*).

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ─── Version handler ─────────────────────────────────────────────────────────

// OpsVersionHandler serves GET /admin/ops/version.
// Build info is injected at link time by the Makefile / CI:
//
//	go build -ldflags "-X patched.im/api/internal/handlers.OpsBuildSHA=<sha> \
//	                    -X patched.im/api/internal/handlers.OpsBuildTime=<time>"
var (
	OpsBuildSHA  = "dev"
	OpsBuildTime = "dev"
)

type opsVersionResp struct {
	BinarySHA        string `json:"binary_sha"`
	BinaryBuildTime  string `json:"binary_build_time"`
	SchemaMigVersion string `json:"schema_mig_version"`
}

func OpsVersionHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("handler", "ops_version")
		resp := opsVersionResp{
			BinarySHA:       OpsBuildSHA,
			BinaryBuildTime: OpsBuildTime,
		}

		qCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		var migVersion string
		if err := pool.QueryRow(qCtx,
			`SELECT COALESCE(MAX(version), 'none') FROM schema_migrations`,
		).Scan(&migVersion); err != nil {
			logger.Warn("schema_mig query failed", "err", err)
			migVersion = "unknown"
		}
		resp.SchemaMigVersion = migVersion

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// ─── Partitions handler ───────────────────────────────────────────────────────

type partitionInfo struct {
	Name  string `json:"name"`  // e.g. "raw_payloads_2026_07"
	Month string `json:"month"` // e.g. "2026-07"
}

type opsPartitionsResp struct {
	Partitions   []partitionInfo `json:"partitions"`
	MonthsAhead  int             `json:"months_ahead"`
	CurrentMonth string          `json:"current_month"`
	WarnShort    bool            `json:"warn_short"` // true when < 2 months ahead
}

// OpsPartitionsHandler serves GET /admin/ops/partitions.
// Lists the raw_payloads_YYYY_MM child partitions and calculates how many
// calendar months ahead of the current month the horizon reaches.
func OpsPartitionsHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("handler", "ops_partitions")

		qCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		rows, err := pool.Query(qCtx, `
			SELECT tablename
			FROM pg_tables
			WHERE schemaname = 'public'
			  AND tablename LIKE 'raw_payloads_%'
			  AND tablename != 'raw_payloads_default'
			ORDER BY tablename
		`)
		if err != nil {
			logger.Warn("partition query failed", "err", err)
			http.Error(w, `{"error":"db query failed"}`, http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		var partitions []partitionInfo
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				logger.Warn("partition scan failed", "err", err)
				continue
			}
			// raw_payloads_YYYY_MM → "YYYY-MM"
			suffix := strings.TrimPrefix(name, "raw_payloads_")
			if len(suffix) == 7 && suffix[4] == '_' {
				month := suffix[:4] + "-" + suffix[5:]
				partitions = append(partitions, partitionInfo{Name: name, Month: month})
			}
		}
		if err := rows.Err(); err != nil {
			logger.Warn("partition rows iteration failed", "err", err)
		}

		// Sort by month ascending.
		sort.Slice(partitions, func(i, j int) bool {
			return partitions[i].Month < partitions[j].Month
		})

		now := time.Now().UTC()
		currentMonth := fmt.Sprintf("%04d-%02d", now.Year(), now.Month())

		// Count how many months ahead of the current month the latest partition is.
		monthsAhead := 0
		if len(partitions) > 0 {
			latest := partitions[len(partitions)-1].Month
			if latest > currentMonth {
				// Parse latest month and compute delta.
				var ly, lm int
				if _, err := fmt.Sscanf(latest, "%d-%d", &ly, &lm); err == nil {
					monthsAhead = (ly-now.Year())*12 + (lm - int(now.Month()))
				}
			}
		}

		resp := opsPartitionsResp{
			Partitions:   partitions,
			MonthsAhead:  monthsAhead,
			CurrentMonth: currentMonth,
			WarnShort:    monthsAhead < 2,
		}
		if resp.Partitions == nil {
			resp.Partitions = []partitionInfo{}
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// ─── Maintenance handler ───────────────────────────────────────────────────

// opsMaintenanceStaleAfter is how old generated_at may be before a snapshot
// is treated as stale rather than passed through. The emitter timer runs
// hourly (patched-maintenance-facts.timer); 3 hours gives headroom for a
// couple of missed/delayed runs before the panel flags it.
const opsMaintenanceStaleAfter = 3 * time.Hour

// opsMaintenanceErrorResp is returned instead of a passthrough snapshot when
// the file is missing, unparseable, or stale. See OpsMaintenanceHandler's
// doc comment for the full contract.
type opsMaintenanceErrorResp struct {
	Error       string  `json:"error"`
	GeneratedAt *string `json:"generated_at"`
}

// opsMaintenanceGeneratedAtProbe extracts just enough of the facts file to
// judge freshness without needing to know its full shape — the rest is
// passed through verbatim, so this handler never needs to keep its own
// struct in sync with the emitter's field list.
type opsMaintenanceGeneratedAtProbe struct {
	GeneratedAt string `json:"generated_at"`
}

// OpsMaintenanceHandler serves GET /admin/ops/maintenance (PAT-993).
//
// Reads the local maintenance-facts snapshot written by
// patched-maintenance-facts.sh (api-vps-artefacts/patched-maintenance-facts.sh,
// via patched-maintenance-facts.timer) to path — /var/lib/patched/maintenance.json
// in production — on this same box, and returns its contents verbatim.
//
// Contract for the "unconfigured" case (missing file / unparseable JSON /
// stale generated_at): ALWAYS HTTP 200, matching /admin/ops/version and
// /admin/ops/partitions' convention on this panel API of degrading in-band
// rather than returning a non-2xx. The body is instead shaped like:
//
//	{"error": "<reason>", "generated_at": null | "<original generated_at>"}
//
// The healthy passthrough response is the emitter's JSON verbatim and never
// has a top-level "error" key, so a consumer's single check is
// `"error" in response` — independent of parsing any other field. For a
// stale snapshot specifically, generated_at carries the original (stale)
// value from the file rather than null, so a caller that wants to show
// "last known snapshot: <time>" can; for missing/unparseable files there is
// no known timestamp to report, so it is null.
// opsMaintenanceMaxBytes bounds the facts-file read. The emitter writes a
// few KB; a limit two orders of magnitude above that catches a corrupted or
// looping writer without ever touching a legitimately-sized snapshot.
const opsMaintenanceMaxBytes = 1 << 20 // 1 MiB

func OpsMaintenanceHandler(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		logger := slog.With("handler", "ops_maintenance")
		w.Header().Set("Content-Type", "application/json")

		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				logger.Warn("maintenance facts file missing", "path", path)
			} else {
				logger.Warn("maintenance facts file open failed", "path", path, "err", err)
			}
			writeOpsMaintenanceUnconfigured(w, "maintenance facts file not found", nil)
			return
		}
		defer f.Close()

		limited := io.LimitReader(f, opsMaintenanceMaxBytes+1)
		data, err := io.ReadAll(limited)
		if err != nil {
			logger.Warn("maintenance facts file read failed", "path", path, "err", err)
			writeOpsMaintenanceUnconfigured(w, "maintenance facts file not found", nil)
			return
		}
		if len(data) > opsMaintenanceMaxBytes {
			logger.Warn("maintenance facts file exceeds size limit", "path", path, "limit", opsMaintenanceMaxBytes)
			writeOpsMaintenanceUnconfigured(w, "maintenance facts file unparseable", nil)
			return
		}

		var probe opsMaintenanceGeneratedAtProbe
		if err := json.Unmarshal(data, &probe); err != nil || probe.GeneratedAt == "" {
			logger.Warn("maintenance facts file unparseable", "path", path, "err", err)
			writeOpsMaintenanceUnconfigured(w, "maintenance facts file unparseable", nil)
			return
		}

		genAt, err := time.Parse(time.RFC3339, probe.GeneratedAt)
		if err != nil {
			logger.Warn("maintenance facts generated_at unparseable", "path", path, "generated_at", probe.GeneratedAt, "err", err)
			writeOpsMaintenanceUnconfigured(w, "maintenance facts generated_at unparseable", nil)
			return
		}

		if age := time.Since(genAt); age > opsMaintenanceStaleAfter {
			logger.Warn("maintenance facts stale", "path", path, "generated_at", probe.GeneratedAt, "age", age)
			ga := probe.GeneratedAt
			writeOpsMaintenanceUnconfigured(w, "maintenance facts stale", &ga)
			return
		}

		// Healthy: pass the file through byte-for-byte.
		_, _ = w.Write(data)
	}
}

func writeOpsMaintenanceUnconfigured(w http.ResponseWriter, reason string, generatedAt *string) {
	_ = json.NewEncoder(w).Encode(opsMaintenanceErrorResp{Error: reason, GeneratedAt: generatedAt})
}
