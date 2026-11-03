package handlers

// backup_health_ingest.go — POST /v1/backup-health: authenticated HTTPS
// heartbeat ingest for portal-01's backup leg (PAT-954), closing the
// PAT-387 / PAT-410 gap documented in
// api-vps-artefacts/BACKUP_DR.md ("Dashboard backup health monitoring").
//
// patched-portal-01 (tag:portal) has zero outbound tailnet grants by design
// (PAT-410 — tailscale-acl.json says explicitly "Do NOT add src: tag:portal
// accept rules"), so it cannot replicate prod-01's scp-over-Tailscale
// heartbeat channel. This endpoint gives it an HTTPS path on the public
// listener's existing :8080, reachable over the same outbound 443 portal-01
// already uses to call PLATFORM_BASE_URL — no tailnet or ufw change needed
// on portal-01's side.
//
// Auth is a dedicated shared secret (BACKUP_HEARTBEAT_TOKEN) — deliberately
// NOT ADMIN_API_TOKEN and NOT a tenant bearer token, so a compromised
// portal-01 can at most write bogus heartbeat files into
// PATCHED_BACKUP_HEALTH_DIR, never read /admin/* data or forge tenant
// ingestion. Compared in constant time; fails CLOSED (503) when unset,
// matching the ADMIN_API_TOKEN posture in cmd/patched-api/main.go
// (requireAdminToken).
//
// The accepted body is decoded strictly into the exact same backupJobResp
// shape readBackupJobs (health_admin.go) already consumes — unknown fields
// are rejected, not ignored — so no change is needed there. Every string
// field is then length-capped, control-character-checked, AND rejected
// outright if it contains an HTML metacharacter (< > " ' &) before being
// re-marshaled and written atomically (temp file + rename) into
// PATCHED_BACKUP_HEALTH_DIR: treat every field here as untrusted input, since
// it renders on the staff console via raw string concatenation into
// .innerHTML with no escaping (dashboard repo's templates/console.html,
// _opsRow()/`b.detail` — the PAT-854 stored-XSS precedent is exactly this
// shape of data). The "job" field additionally doubles as the filename and
// is restricted to a narrow safe charset — no "../", no absolute paths, no
// non-".json" names are structurally possible — and further constrained to
// an explicit allowlist (BACKUP_HEARTBEAT_ALLOWED_JOBS), since this
// directory is shared with other hosts' legitimately-written heartbeat
// files (see BACKUP_DR.md); without the allowlist this single credential
// could overwrite any other job's file, including painting a genuinely
// failing job green.
//
// Endpoint-trust posture (public, internet-reachable listener):
//   - Constant-time, fail-closed token auth (above).
//   - Dedicated rate limiter, single shared bucket (see backupHeartbeatRateKey).
//   - http.MaxBytesReader body cap — oversized bodies are rejected mid-read,
//     never buffered in full.
//   - Strict JSON decode (DisallowUnknownFields + reject trailing content).
//   - job allowlist — 403 for any job id outside BACKUP_HEARTBEAT_ALLOWED_JOBS.

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/go-chi/chi/v5/middleware"

	"patched.im/api/internal/ratelimit"
)

const (
	// maxBackupHeartbeatBytes caps the request body. The heartbeat JSON is a
	// handful of short fields — well under 1 KiB in practice (see
	// portal-backup.sh's write_health()). 4 KiB leaves generous headroom
	// without ever buffering anything large.
	maxBackupHeartbeatBytes = 4 << 10 // 4 KiB

	backupHeartbeatMaxLabelLen  = 200
	backupHeartbeatMaxStatusLen = 32
	backupHeartbeatMaxDetailLen = 500

	// backupHeartbeatMaxFutureSkew / backupHeartbeatMaxAge bound
	// last_success_at. Without an upper bound, a clock-skewed (or malicious)
	// caller could post one heartbeat with a far-future timestamp and then
	// go silent forever — the dashboard's ageHrs = (now - last) computation
	// would stay negative (i.e. "not stale") indefinitely. Without a lower
	// bound, an absurdly old timestamp is almost certainly a unit/format bug
	// worth rejecting rather than silently accepting.
	backupHeartbeatMaxFutureSkew = 5 * time.Minute
	backupHeartbeatMaxAge        = 365 * 24 * time.Hour
)

// backupHeartbeatJobIDPattern restricts the "job" field to a safe filename
// component: lowercase alnum/hyphen/underscore, 1-64 chars, must start
// alnum. This is what makes filename derivation safe — "../", absolute
// paths, null bytes, and anything-but-".json" are all structurally
// impossible once a value matches this pattern and ".json" is appended
// server-side, never by the caller. It is a necessary but not sufficient
// check — see the allowlist in BackupHeartbeatIngestHandler for the set of
// job ids this credential may actually write.
var backupHeartbeatJobIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// backupHeartbeatHTMLMetacharacters are rejected outright in every untrusted
// string field. The staff console (dashboard repo's templates/console.html)
// renders these fields via raw string concatenation into .innerHTML with no
// escaping, so any of these characters would let a heartbeat body break out
// of its intended text/attribute context and inject markup or script (the
// PAT-854 stored-XSS precedent). The wire contract is machine-generated
// ASCII from portal-backup.sh, so rejecting these costs no legitimate use.
const backupHeartbeatHTMLMetacharacters = `<>"'&`

// backupHeartbeatRateKey is the single token-bucket key for this endpoint.
// There is exactly one legitimate caller (portal-01's
// patched-portal-backup.timer, roughly nightly), so a shared bucket both
// throttles a leaked-token abuser and caps total ingest volume regardless of
// source IP — no per-caller keying is needed.
const backupHeartbeatRateKey = "backup-heartbeat"

// BackupHeartbeatIngestHandler serves POST /v1/backup-health on the public
// :8080 listener. token is BACKUP_HEARTBEAT_TOKEN; backupHealthDir is
// PATCHED_BACKUP_HEALTH_DIR (the same directory readBackupJobs scans);
// allowedJobs is BACKUP_HEARTBEAT_ALLOWED_JOBS split on commas — the only
// job ids this credential may write (see the allowlist rationale above).
func BackupHeartbeatIngestHandler(token, backupHealthDir string, allowedJobs []string, rl *ratelimit.TenantLimiter) http.HandlerFunc {
	// Precompute the expected digest once, mirroring requireAdminToken in
	// cmd/patched-api/main.go: comparing fixed-width SHA-256 digests keeps
	// the compare constant-time and independent of token length.
	want := sha256.Sum256([]byte(token))

	allowed := make(map[string]struct{}, len(allowedJobs))
	for _, j := range allowedJobs {
		j = strings.TrimSpace(j)
		if j != "" {
			allowed[j] = struct{}{}
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "backup_health_ingest")

		// Fail CLOSED when unconfigured — a missing env var must never
		// silently open this surface to unauthenticated writes.
		if token == "" {
			http.Error(w, "backup heartbeat ingest not configured", http.StatusServiceUnavailable)
			return
		}

		presented := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		got := sha256.Sum256([]byte(presented))
		if subtle.ConstantTimeCompare(want[:], got[:]) != 1 {
			logger.Warn("backup heartbeat auth failed")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if allowed, retryAfter := rl.Allow(backupHeartbeatRateKey); !allowed {
			logger.Warn("backup heartbeat rate limit exceeded")
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Oversized bodies are rejected mid-read (MaxBytesReader makes the
		// underlying Read fail once the limit is crossed), never buffered in
		// full first.
		r.Body = http.MaxBytesReader(w, r.Body, maxBackupHeartbeatBytes)

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		var job backupJobResp
		if err := dec.Decode(&job); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				logger.Warn("backup heartbeat body too large")
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			logger.Warn("backup heartbeat decode failed", "err", err)
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		// Decode only consumes a single JSON value — reject trailing content
		// (e.g. a second concatenated object) rather than silently ignoring it.
		if dec.More() {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		safeJobID, err := sanitizeBackupHeartbeatJobID(job.Job)
		if err != nil {
			logger.Warn("backup heartbeat rejected", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if _, ok := allowed[safeJobID]; !ok {
			logger.Warn("backup heartbeat job not allowlisted", "job", safeJobID)
			http.Error(w, "job is not permitted for this credential", http.StatusForbidden)
			return
		}
		if err := validateBackupHeartbeatStrings(job); err != nil {
			logger.Warn("backup heartbeat rejected", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := validateBackupHeartbeatTimestamp(job.LastSuccessAt); err != nil {
			logger.Warn("backup heartbeat rejected", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Re-marshal the validated struct rather than persisting the raw
		// request body — guarantees the file on disk always matches the
		// exact backupJobResp contract readBackupJobs expects, independent
		// of anything unusual (field order, whitespace, duplicate keys) in
		// the caller's raw JSON.
		out, err := json.Marshal(job)
		if err != nil {
			logger.Error("backup heartbeat re-marshal failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		if err := writeBackupHeartbeatFile(backupHealthDir, safeJobID, out); err != nil {
			logger.Error("backup heartbeat write failed", "job", safeJobID, "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("backup heartbeat accepted", "job", safeJobID, "status", job.Status)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
	}
}

// sanitizeBackupHeartbeatJobID validates the caller-supplied "job" field
// against backupHeartbeatJobIDPattern. A value that passes this check can be
// safely joined onto a directory and suffixed with ".json" — no traversal,
// no absolute path, no alternate extension is representable.
func sanitizeBackupHeartbeatJobID(job string) (string, error) {
	if job == "" {
		return "", errors.New("job is required")
	}
	if !backupHeartbeatJobIDPattern.MatchString(job) {
		return "", errors.New("job must be 1-64 lowercase alphanumeric/hyphen/underscore characters, starting with a letter or digit")
	}
	return job, nil
}

// validateBackupHeartbeatStrings enforces length caps and rejects control
// characters on every remaining string field. This data ultimately renders
// on the staff console (AdminHealthHandler serves it verbatim) — see the
// PAT-854 stored-XSS precedent for exactly this shape of untrusted input.
func validateBackupHeartbeatStrings(job backupJobResp) error {
	if job.Status == "" {
		return errors.New("status is required")
	}
	if err := checkUntrustedHeartbeatString("status", job.Status, backupHeartbeatMaxStatusLen); err != nil {
		return err
	}
	if err := checkUntrustedHeartbeatString("label", job.Label, backupHeartbeatMaxLabelLen); err != nil {
		return err
	}
	if err := checkUntrustedHeartbeatString("detail", job.Detail, backupHeartbeatMaxDetailLen); err != nil {
		return err
	}
	return nil
}

func checkUntrustedHeartbeatString(field, value string, maxLen int) error {
	if len(value) > maxLen {
		return fmt.Errorf("%s exceeds maximum length of %d bytes", field, maxLen)
	}
	if strings.ContainsAny(value, backupHeartbeatHTMLMetacharacters) {
		return fmt.Errorf("%s must not contain any of %s", field, backupHeartbeatHTMLMetacharacters)
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return fmt.Errorf("%s must not contain control characters", field)
		}
	}
	return nil
}

// validateBackupHeartbeatTimestamp bounds last_success_at to a plausible
// window around "now": rejecting a timestamp more than
// backupHeartbeatMaxFutureSkew in the future stops a single heartbeat from
// reading as perpetually fresh on the dashboard's staleness calculation;
// rejecting one more than backupHeartbeatMaxAge in the past catches
// obviously-wrong values (unit bugs, garbage input) rather than silently
// accepting them. nil (absent) is valid — it means "never succeeded".
func validateBackupHeartbeatTimestamp(lastSuccessAt *time.Time) error {
	if lastSuccessAt == nil {
		return nil
	}
	now := time.Now().UTC()
	if lastSuccessAt.After(now.Add(backupHeartbeatMaxFutureSkew)) {
		return errors.New("last_success_at must not be in the future")
	}
	if lastSuccessAt.Before(now.Add(-backupHeartbeatMaxAge)) {
		return errors.New("last_success_at is implausibly old")
	}
	return nil
}

// writeBackupHeartbeatFile writes data into dir/jobID.json atomically (temp
// file + rename) so a reader (readBackupJobs) can never observe a partial
// write. jobID must already have passed sanitizeBackupHeartbeatJobID.
func writeBackupHeartbeatFile(dir, jobID string, data []byte) error {
	if dir == "" {
		return errors.New("backup health directory not configured")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}

	cleanDir := filepath.Clean(dir)
	finalPath := filepath.Join(cleanDir, jobID+".json")
	// Belt-and-braces: sanitizeBackupHeartbeatJobID already guarantees jobID
	// contains no path separators or "..", but re-verify the joined path
	// still resolves directly inside dir before writing anything.
	if filepath.Dir(finalPath) != cleanDir {
		return fmt.Errorf("unsafe heartbeat path derived from job id %q", jobID)
	}

	// Deliberately NOT suffixed ".json": readBackupJobs only filters on
	// IsDir() and a ".json" suffix — it does not skip dotfiles. A temp file
	// ending ".json" would match that glob and, if the process died between
	// CreateTemp and Rename (defer os.Remove never running), become a
	// permanent stray "job" with a name derived from the dotfile and a
	// timestamp frozen at creation — a false-green (or false-anything) row
	// that never updates again.
	tmp, err := os.CreateTemp(cleanDir, ".tmp-"+jobID+"-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup: once the rename below succeeds tmpPath no longer
	// exists, so this is a silent no-op in the success path.
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o640); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	return nil
}
