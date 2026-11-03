package handlers

// agent_artifact_store.go — PAT-1260 platform half: authenticated artifact
// storage backing self-update on patched-api-01, closing the gap where the
// signed artifact_url (agent_artifact.go, PAT-1252) pointed at GitHub
// Releases on the private Patched-LTD/updater repo and 404'd for every
// unauthenticated download attempt (confirmed live on WIN-STAGING,
// 2026-08-11 22:12:06Z: metadata resolves "update available 0.13.18 →
// 0.13.19" correctly, then the download itself 404s).
//
// Two routes:
//
//	PUT  /admin/agent-versions/{platform}/{channel}/{version}/artifact
//	     Admin-only, same credential as POST /admin/agent-versions
//	     (ADMIN_API_TOKEN, enforced by requireInternalToken on the internal
//	     router in cmd/patched-api/main.go — this handler performs no auth
//	     of its own). Streams the raw MSI/tarball body straight to disk;
//	     never buffers the ~160MB artifact in memory.
//
//	GET/HEAD /v1/agent/artifact/download?platform=&channel=&version=
//	     Per-device Bearer + HMAC, the identical auth chain as
//	     GET /v1/agent/artifact (AgentArtifactHandler), but bound to its own
//	     endpoint ID (auth.EndpointAgentArtifactDownload) — see that
//	     constant's doc comment for why reusing EndpointAgentArtifact would
//	     have been a replay hole. Streams the file back with io.Copy; never
//	     buffers it either.
//
// Storage layout: <baseDir>/<platform>/<channel>/<version>/artifact.bin.
// baseDir is PATCHED_ARTIFACT_DIR, defaulting to
// /var/lib/patched-api/artifacts (already in the systemd unit's
// ReadWritePaths, owned by patched:patched). platform/channel/version are
// strictly validated — see artifactStoragePath — BEFORE any of them touch a
// filesystem path; path traversal via those three URL-derived components is
// the main risk this file exists to close.
//
// This layer stores and serves OPAQUE bytes. It deliberately does not
// compute, verify, or assert anything about artifact_sha256 — that check is
// AgentArtifactHandler's caller's job, against PAT-1252's signed envelope
// (see validateArtifactMetadataSignature's doc comment in agent_artifact.go).
// Adding an integrity claim here would make this server look like a trust
// anchor for artifact content, which is exactly what PAT-1248's design keeps
// it from being.

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
	"patched.im/api/internal/ratelimit"
)

const (
	// artifactFilename is the fixed on-disk name for every stored artifact.
	// The server treats artifact bytes as opaque (see package doc comment
	// above), so it has no reason to derive or trust a caller-supplied
	// filename — one constant name per (platform, channel, version)
	// directory keeps the write path (admin upload) and read path (device
	// download) trivially in agreement.
	artifactFilename = "artifact.bin"

	// maxArtifactBytes hard-caps PUT .../artifact. Real artifacts are
	// ~160MB (Windows MSI); 512MB leaves generous headroom without ever
	// buffering an unbounded body. A var (not const) so tests can lower it
	// to exercise the 413 path without actually pushing 512MB of bytes.
	maxArtifactBytesDefault = 512 << 20 // 512 MiB
)

var maxArtifactBytes int64 = maxArtifactBytesDefault

// artifactPathComponentPattern is the strict allowlist a channel or version
// value must match before it is used to build a filesystem path. Letters,
// digits, dot, hyphen, underscore only, and the value must both start and
// end on an alphanumeric character — which makes "." and ".." (both
// entirely non-alnum) structurally unmatchable, along with an empty string,
// a leading/trailing dot, and anything containing "/" or "\" (neither is in
// the allowed character class at all, so no path separator — encoded or
// not — can ever survive into a component that matches this pattern). By
// the time chi (path params) or net/url (query params) hand a value to this
// pattern, percent-encoding has already been decoded, so "%2e%2e" arrives
// as the literal ".." string and is rejected exactly like the unencoded
// form; "%2f" arrives as "/" and is rejected the same way.
var artifactPathComponentPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$`)

func isValidArtifactPathComponent(s string) bool {
	return artifactPathComponentPattern.MatchString(s)
}

// artifactStoragePath validates platform/channel/version and returns the
// absolute artifact file path under baseDir, plus its containing directory.
// platform must be one of validAgentVersionPlatforms (reusing
// isValidAgentVersionPlatform — the same allowlist POST /admin/agent-versions
// and GET /v1/agent/artifact already enforce, per PAT-1233); channel and
// version must each match artifactPathComponentPattern.
//
// Belt-and-braces: after joining, it re-derives the relative path with
// filepath.Rel and confirms it still resolves strictly inside baseDir before
// returning — the same defence-in-depth shape as writeBackupHeartbeatFile
// (backup_health_ingest.go). This can only fail if a future edit weakens the
// pattern above without updating this check too; it is a deliberate second
// gate, not dead code. Every caller must check the returned error and touch
// nothing on disk if it is non-nil — validation happens entirely before any
// filesystem access, so an attacker never learns anything about what exists
// on disk from a rejected path.
func artifactStoragePath(baseDir, platform, channel, version string) (path string, dir string, err error) {
	if !isValidAgentVersionPlatform(platform) {
		return "", "", errors.New("platform must be \"macos\", \"windows\", or \"macos-menubar\"")
	}
	if !isValidArtifactPathComponent(channel) {
		return "", "", errors.New("channel is invalid")
	}
	if !isValidArtifactPathComponent(version) {
		return "", "", errors.New("version is invalid")
	}

	cleanBase := filepath.Clean(baseDir)
	dir = filepath.Join(cleanBase, platform, channel, version)
	path = filepath.Join(dir, artifactFilename)

	rel, relErr := filepath.Rel(cleanBase, dir)
	if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", "", errors.New("artifact path escapes base directory")
	}
	return path, dir, nil
}

// AdminUploadAgentArtifactHandler builds
// PUT /admin/agent-versions/{platform}/{channel}/{version}/artifact.
// Auth is enforced entirely by requireInternalToken on the internal router
// (cmd/patched-api/main.go) — the same ADMIN_API_TOKEN as
// POST /admin/agent-versions — this handler performs no auth of its own.
func AdminUploadAgentArtifactHandler(baseDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "admin_upload_agent_artifact")

		platform := strings.TrimSpace(chi.URLParam(r, "platform"))
		channel := strings.TrimSpace(chi.URLParam(r, "channel"))
		version := strings.TrimSpace(chi.URLParam(r, "version"))

		finalPath, dir, err := artifactStoragePath(baseDir, platform, channel, version)
		if err != nil {
			logger.Warn("artifact upload rejected", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := os.MkdirAll(dir, 0o750); err != nil {
			logger.Error("mkdir failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// Cap the body BEFORE reading a single byte — never buffer the full
		// ~160MB artifact (or an attacker-supplied unbounded body) beyond
		// the configured limit.
		r.Body = http.MaxBytesReader(w, r.Body, maxArtifactBytes)

		// Write to a temp file in the SAME directory as the final path (so
		// the later rename is same-filesystem, hence atomic), then rename
		// into place. A half-uploaded artifact is never observable at
		// finalPath: readers see either the prior version or the fully
		// written new one, never a partial file. This also gives idempotent
		// re-upload "for free" — the rename simply replaces whatever was
		// there before.
		tmp, err := os.CreateTemp(dir, ".tmp-artifact-*")
		if err != nil {
			logger.Error("create temp file failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		tmpPath := tmp.Name()
		// Best-effort cleanup: once Rename succeeds below, tmpPath no
		// longer exists and this is a silent no-op; on any earlier failure
		// it removes the partial upload rather than leaving debris.
		defer os.Remove(tmpPath)

		written, copyErr := io.Copy(tmp, r.Body)
		if copyErr != nil {
			tmp.Close()
			var maxErr *http.MaxBytesError
			if errors.As(copyErr, &maxErr) {
				logger.Warn("artifact upload too large", "platform", platform, "channel", channel, "version", version)
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}
			logger.Error("artifact upload stream failed", "err", copyErr)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		// Defence in depth: io.Copy returning a nil error only means the
		// body reader hit EOF without an I/O error, which is what a client
		// disconnecting mid-upload commonly (not always, in principle)
		// surfaces as. A short body caught HERE, before Sync/Chmod/Rename,
		// is what stops a truncated MSI from ever being rename'd into the
		// path GET /v1/agent/artifact/download serves — never rename an
		// upload whose byte count doesn't match what the client itself
		// declared. r.ContentLength is -1 for chunked/unknown-length
		// bodies, in which case there is nothing to compare against and
		// this check is a no-op.
		if r.ContentLength >= 0 && written != r.ContentLength {
			tmp.Close()
			logger.Warn("artifact upload truncated",
				"platform", platform, "channel", channel, "version", version,
				"declared_bytes", r.ContentLength, "written_bytes", written)
			http.Error(w, "uploaded body did not match declared Content-Length", http.StatusBadRequest)
			return
		}
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			logger.Error("sync temp file failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := tmp.Close(); err != nil {
			logger.Error("close temp file failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := os.Chmod(tmpPath, 0o640); err != nil {
			logger.Error("chmod temp file failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if err := os.Rename(tmpPath, finalPath); err != nil {
			logger.Error("rename temp file failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("agent artifact stored",
			"platform", platform, "channel", channel, "version", version, "bytes", written)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"platform":%q,"channel":%q,"version":%q,"bytes":%d}`+"\n",
			platform, channel, version, written)
	}
}

// AgentArtifactDownloadHandler builds GET and HEAD
// /v1/agent/artifact/download. Auth: per-device Bearer + HMAC, identical
// shape to AgentArtifactHandler (agent_artifact.go), but signed over
// auth.EndpointAgentArtifactDownload rather than auth.EndpointAgentArtifact
// — see that constant's doc comment for why. Rate-limited by tenant, same
// as AgentArtifactHandler.
//
// The download route must never leak the existence of an artifact to an
// unauthenticated caller: auth, rate limiting, and replay checks all run
// completely before platform/channel/version are even read from the query
// string, let alone looked up on disk — mirroring AgentArtifactHandler's
// ordering exactly.
func AgentArtifactDownloadHandler(pool *pgxpool.Pool, rl *ratelimit.TenantLimiter, replaySkew time.Duration, baseDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetReqID(r.Context())
		logger := slog.With("req_id", reqID, "handler", "agent_artifact_download")

		// Auth — empty body (GET/HEAD), identical chain to AgentArtifactHandler.
		body := []byte{}
		tenantID, _, err := func() (string, string, error) {
			if tid, did, secret, e := auth.LookupDeviceByBearer(r.Context(), pool, r.Header.Get("Authorization")); e == nil {
				if e2 := auth.VerifyHMACSigned(secret, r.Method, auth.EndpointAgentArtifactDownload, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); e2 != nil {
					return "", "", e2
				}
				return tid, did, nil
			}
			tid, secret, e := auth.LookupTenantByBearer(r.Context(), pool, r.Header.Get("Authorization"))
			if e != nil {
				return "", "", e
			}
			if e2 := auth.VerifyHMACSigned(secret, r.Method, auth.EndpointAgentArtifactDownload, r.Header.Get("X-Patched-Timestamp"), r.Header.Get("X-Patched-Nonce"), body, r.Header.Get("X-Patched-Signature")); e2 != nil {
				return "", "", e2
			}
			return tid, "", nil
		}()
		if err != nil {
			logger.Warn("auth failed", "err", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if rl != nil {
			if allowed, retryAfter := rl.Allow(tenantID); !allowed {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
				http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		if pool != nil {
			if err := auth.ValidateTimestamp(r.Header.Get("X-Patched-Timestamp"), replaySkew); err != nil {
				logger.Warn("timestamp validation failed", "err", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if err := auth.CheckAndStoreNonce(r.Context(), pool, tenantID, r.Header.Get("X-Patched-Nonce"), replaySkew); err != nil {
				logger.Warn("nonce check failed", "err", err)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}

		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		channel := strings.TrimSpace(r.URL.Query().Get("channel"))
		version := strings.TrimSpace(r.URL.Query().Get("version"))
		if channel == "" {
			channel = "stable"
		}

		path, _, err := artifactStoragePath(baseDir, platform, channel, version)
		if err != nil {
			logger.Warn("artifact download rejected", "err", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		f, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				http.Error(w, "no artifact found for platform/channel/version", http.StatusNotFound)
				return
			}
			logger.Error("open artifact failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		defer f.Close()

		info, err := f.Stat()
		if err != nil {
			logger.Error("stat artifact failed", "err", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if info.IsDir() {
			// Cannot occur through artifactStoragePath's fixed filename
			// suffix, but fail closed rather than stream a directory listing
			// if the on-disk layout is ever tampered with out of band.
			logger.Error("artifact path is a directory", "path", path)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		logger.Info("agent artifact download resolved",
			"tenant_id", tenantID, "platform", platform, "channel", channel, "version", version, "bytes", info.Size())

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = io.Copy(w, f)
	}
}
