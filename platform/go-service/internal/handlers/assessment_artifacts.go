package handlers

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const maxAssessmentArtifactBytes = 25 << 20

var assessmentReferenceRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

type assessmentArtifact struct {
	ID                  string    `json:"id"`
	TenantID            string    `json:"tenant_id"`
	EngagementReference string    `json:"engagement_reference"`
	DocumentVersion     string    `json:"document_version"`
	ContentType         string    `json:"content_type"`
	SHA256              string    `json:"sha256"`
	ByteSize            int64     `json:"byte_size"`
	GeneratedAt         time.Time `json:"generated_at"`
	ApprovedAt          time.Time `json:"approved_at"`
	ApprovedBy          string    `json:"approved_by"`
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func assessmentDocumentType(data []byte) (contentType, ext string, err error) {
	if len(data) >= 5 && bytes.HasPrefix(data, []byte("%PDF-")) {
		return "application/pdf", ".pdf", nil
	}
	if len(data) >= 4 && bytes.Equal(data[:4], []byte{'P', 'K', 3, 4}) {
		zr, zipErr := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if zipErr != nil {
			return "", "", errors.New("invalid DOCX archive")
		}
		required := map[string]bool{"[Content_Types].xml": false, "word/document.xml": false}
		for _, f := range zr.File {
			clean := filepath.ToSlash(filepath.Clean(f.Name))
			if strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
				return "", "", errors.New("unsafe DOCX member path")
			}
			if _, ok := required[clean]; ok {
				required[clean] = true
			}
		}
		if required["[Content_Types].xml"] && required["word/document.xml"] {
			return "application/vnd.openxmlformats-officedocument.wordprocessingml.document", ".docx", nil
		}
	}
	return "", "", errors.New("only PDF or DOCX assessment documents are accepted")
}

func secureArtifactPath(root, rel string) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", errors.New("unsafe artifact path")
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("unsafe artifact path")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", err
	}
	abs, err := filepath.Abs(filepath.Join(rootResolved, clean))
	if err != nil {
		return "", err
	}
	if abs != rootResolved && !strings.HasPrefix(abs, rootResolved+string(filepath.Separator)) {
		return "", errors.New("unsafe artifact path")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	if parent != rootResolved && !strings.HasPrefix(parent, rootResolved+string(filepath.Separator)) {
		return "", errors.New("artifact path escapes storage root")
	}
	if info, statErr := os.Lstat(abs); statErr == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("artifact file is a symlink")
	}
	return abs, nil
}

func secureArtifactDir(root, rel string, perm os.FileMode) (string, error) {
	if rel == "" || filepath.IsAbs(rel) {
		return "", errors.New("unsafe artifact directory")
	}
	clean := filepath.Clean(rel)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("unsafe artifact directory")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", err
	}
	current := rootResolved
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			// Two concurrent approvals can both observe ENOENT for a shared
			// path component (e.g. assessments/, or the same tenant's
			// directory for two simultaneous approvals) and race to create
			// it. The loser's Mkdir returns EEXIST — that is not a failure,
			// it just means the other goroutine won the race. Re-Lstat and
			// fall through to the existing symlink/is-dir/escapes-root
			// checks below, which confirm what now exists is genuinely a
			// plain directory (and not something a concurrent malicious
			// process planted in the gap) before we trust it.
			if err := os.Mkdir(current, perm); err != nil && !errors.Is(err, os.ErrExist) {
				return "", err
			}
			info, statErr = os.Lstat(current)
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("artifact directory chain is not a real directory")
		}
		resolved, err := filepath.EvalSymlinks(current)
		if err != nil || (resolved != rootResolved && !strings.HasPrefix(resolved, rootResolved+string(filepath.Separator))) {
			return "", errors.New("artifact directory escapes storage root")
		}
	}
	return current, nil
}

func writeArtifactExclusive(abs string, data []byte) error {
	tmp := abs + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0640)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	// Link is an atomic no-replace publish on the local report filesystem.
	// It cannot follow or overwrite a pre-planted final symlink.
	if err = os.Link(tmp, abs); err != nil {
		return err
	}
	if err = os.Remove(tmp); err != nil {
		_ = os.Remove(abs)
		return err
	}
	dir, err := os.Open(filepath.Dir(abs))
	if err != nil {
		_ = os.Remove(abs)
		return err
	}
	err = dir.Sync()
	closeErr := dir.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(abs)
		if err != nil {
			return err
		}
		return closeErr
	}
	ok = true
	return nil
}

// ApproveAssessmentArtifactHandler accepts bytes from the authenticated staff
// workflow. The storage key is server-derived; callers cannot submit a path.
func ApproveAssessmentArtifactHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid := strings.TrimSpace(chi.URLParam(r, "tenantID"))
		if !looksLikeUUID(tid) {
			http.Error(w, "invalid tenant", http.StatusBadRequest)
			return
		}
		// Postgres always renders a UUID column as lowercase canonical text
		// (used both in the storage_path CHECK constraint and by callers
		// that re-derive the path from the DB row), so normalize here,
		// before tid is used to build any file path or DB value, to keep
		// the on-disk path and the persisted storage_path in agreement
		// regardless of the case the caller supplied in the URL.
		tid = strings.ToLower(tid)
		// Deliberate scope boundary (round 1): the actor identity is
		// whatever this header says, with no allowlist check against a
		// known-staff table. This is safe only because the real trust
		// boundary is the shared admin service token that gates access to
		// this route at all (cmd/patched-api/main.go binds it to
		// 127.0.0.1:8081 behind a Tailscale-only Caddy site and the
		// tag:main -> tag:api ACL); anyone who can reach this handler is
		// already inside that boundary, so the header is provenance
		// metadata within it rather than the access control itself. A
		// proper per-staff allowlist (so a compromised or misconfigured
		// caller cannot impersonate an arbitrary approver in the audit
		// trail) is a follow-up, not required for this ticket.
		actor := strings.TrimSpace(r.Header.Get("X-Patched-Actor-Email"))
		if !emailRE.MatchString(actor) {
			http.Error(w, "approved actor required", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAssessmentArtifactBytes+(1<<20))
		if err := r.ParseMultipartForm(maxAssessmentArtifactBytes + (1 << 20)); err != nil {
			http.Error(w, "invalid or oversized multipart body", http.StatusBadRequest)
			return
		}
		defer r.MultipartForm.RemoveAll() //nolint:errcheck
		engagement, version := strings.TrimSpace(r.FormValue("engagement_reference")), strings.TrimSpace(r.FormValue("document_version"))
		if !assessmentReferenceRE.MatchString(engagement) || !assessmentReferenceRE.MatchString(version) {
			http.Error(w, "invalid engagement_reference or document_version", http.StatusBadRequest)
			return
		}
		generatedAt, err := time.Parse(time.RFC3339, strings.TrimSpace(r.FormValue("generated_at")))
		if err != nil || generatedAt.After(time.Now().UTC()) {
			http.Error(w, "generated_at must be a non-future RFC3339 timestamp", http.StatusBadRequest)
			return
		}
		file, _, err := r.FormFile("document")
		if err != nil {
			http.Error(w, "document is required", http.StatusBadRequest)
			return
		}
		defer file.Close()
		data, err := io.ReadAll(io.LimitReader(file, maxAssessmentArtifactBytes+1))
		if err != nil || len(data) == 0 || len(data) > maxAssessmentArtifactBytes {
			http.Error(w, "invalid document size", http.StatusBadRequest)
			return
		}
		contentType, ext, err := assessmentDocumentType(data)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		artifactID, err := randomUUID()
		if err != nil {
			http.Error(w, "internal error", 500)
			return
		}
		var tenantExists bool
		if err = pool.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1::uuid)`, tid).Scan(&tenantExists); err != nil {
			http.Error(w, "internal error", 500)
			return
		}
		if !tenantExists {
			http.Error(w, "tenant not found", http.StatusNotFound)
			return
		}
		// diskDirRel/diskRel are actual local filesystem paths and must use
		// OS-native separators (filepath) so secureArtifactDir/secureArtifactPath
		// and the raw os calls resolve correctly on this host. dbRel is the
		// portable key persisted to the DB and matched against the
		// migration's forward-slash-only storage_path CHECK constraint, so
		// it is built with path.Join instead, independent of host OS.
		diskDirRel := filepath.Join("assessments", tid, artifactID)
		artifactDir, err := secureArtifactDir(reportStorageRoot(), diskDirRel, 0750)
		if err != nil {
			// Distinguishes this failure (directory-chain creation —
			// disk full, permission denied, missing/misconfigured
			// REPORT_STORAGE_ROOT, or a pre-planted symlink in the
			// chain) from the two other storage failure points below,
			// which previously all surfaced as an identical opaque 500
			// with nothing in the logs to tell them apart.
			slog.Error("approve assessment artifact: create artifact directory", "err", err, "tenant_id", tid, "artifact_id", artifactID)
			http.Error(w, "storage unavailable", 500)
			return
		}
		// cleanupArtifactDir removes the (empty) per-artifact directory created
		// above. os.Remove only succeeds on an empty directory, so it's a safe
		// no-op (just a logged warning) if anything unexpected has been placed
		// inside it. Reused by every pre-commit storage failure path below,
		// including the broader cleanupArtifact defined further down that also
		// removes the written file.
		cleanupArtifactDir := func() {
			if rmErr := os.Remove(artifactDir); rmErr != nil && !os.IsNotExist(rmErr) {
				slog.Warn("assessment artifact directory cleanup failed", "err", rmErr, "dir", artifactDir)
			}
		}
		diskRel := filepath.Join("assessments", tid, artifactID, "assessment"+ext)
		abs, err := secureArtifactPath(reportStorageRoot(), diskRel)
		if err != nil {
			// Distinguishes path-validation failure (e.g. a pre-planted symlink
			// at the final path component) from directory-chain creation and
			// exclusive-write failures. artifactDir was already created above
			// and no file has been written yet, so clean it up rather than
			// orphaning an empty directory.
			slog.Error("approve assessment artifact: validate artifact path", "err", err, "tenant_id", tid, "artifact_id", artifactID)
			cleanupArtifactDir()
			http.Error(w, "storage unavailable", 500)
			return
		}
		if err := writeArtifactExclusive(abs, data); err != nil {
			// Distinguishes exclusive-write failure (disk full mid-write,
			// permission denied, or a pre-planted final-path symlink caught by
			// the O_EXCL/Link no-replace publish) from the two failure points
			// above. The directory was created but no file was durably
			// published, so clean it up here too.
			slog.Error("approve assessment artifact: write artifact file", "err", err, "tenant_id", tid, "artifact_id", artifactID)
			cleanupArtifactDir()
			http.Error(w, "storage unavailable", 500)
			return
		}
		dbRel := path.Join("assessments", tid, artifactID, "assessment"+ext)
		// cleanupArtifact removes the just-written file and its now-empty
		// parent directory. Only call this for errors that are definitely
		// pre-commit / non-ambiguous — never after an errored Commit(),
		// since the DB may have actually committed server-side despite the
		// client seeing an error, and the row (if it exists) is immutable.
		cleanupArtifact := func() {
			_ = os.Remove(abs)
			cleanupArtifactDir()
		}
		sum := sha256.Sum256(data)
		approvedAt := time.Now().UTC()
		tx, err := pool.Begin(r.Context())
		if err != nil {
			cleanupArtifact()
			http.Error(w, "internal error", 500)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck
		_, err = tx.Exec(r.Context(), `INSERT INTO assessment_artifacts
			(id,tenant_id,engagement_reference,document_version,content_type,storage_path,sha256,byte_size,generated_at,approved_at,approved_by)
			VALUES($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, artifactID, tid, engagement, version, contentType, dbRel, sum[:], len(data), generatedAt, approvedAt, actor)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO assessment_artifact_audit(tenant_id,artifact_id,action,actor,sha256) VALUES($1::uuid,$2::uuid,'approved',$3,$4)`, tid, artifactID, actor, sum[:])
		}
		if err != nil {
			// Both Exec calls above are definitely pre-commit: nothing has
			// been committed yet, so it's safe to remove what we wrote.
			cleanupArtifact()
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				http.Error(w, "assessment document version is already approved", http.StatusConflict)
				return
			}
			slog.Error("approve assessment artifact", "err", err, "tenant_id", tid)
			http.Error(w, "internal error", 500)
			return
		}
		if err = tx.Commit(r.Context()); err != nil {
			// Ambiguous: the client sees an error, but the DB may have
			// actually committed (e.g. connection drop after commit, before
			// the ack). If it did, the row is immutable and the
			// (tenant_id, engagement_reference, document_version) unique
			// constraint means this exact version can never be re-approved
			// — so deleting the file here would permanently 404 redemption
			// for an artifact the DB believes exists and was approved. Do
			// NOT delete; log loudly for manual reconciliation instead.
			slog.Error("approve assessment artifact commit ambiguous: file NOT deleted — commit may have failed OR succeeded server-side, needs manual reconciliation",
				"err", err, "tenant_id", tid, "artifact_id", artifactID, "storage_path", dbRel, "disk_path", abs)
			http.Error(w, "internal error", 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(assessmentArtifact{artifactID, tid, engagement, version, contentType, hex.EncodeToString(sum[:]), int64(len(data)), generatedAt, approvedAt, actor})
	}
}

func IssueAssessmentDownloadTokenHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tid, aid := strings.TrimSpace(chi.URLParam(r, "tenantID")), strings.TrimSpace(chi.URLParam(r, "artifactID"))
		if !looksLikeUUID(tid) || !looksLikeUUID(aid) {
			http.Error(w, "invalid UUID", 400)
			return
		}
		actor := strings.TrimSpace(r.Header.Get("X-Patched-Actor-Email"))
		if !emailRE.MatchString(actor) {
			http.Error(w, "actor required", 400)
			return
		}
		var req struct {
			Recipient      string `json:"recipient"`
			ExpiresInHours int    `json:"expires_in_hours"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<14)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "invalid JSON", 400)
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			http.Error(w, "invalid JSON", 400)
			return
		}
		req.Recipient = strings.TrimSpace(strings.ToLower(req.Recipient))
		if !emailRE.MatchString(req.Recipient) {
			http.Error(w, "valid recipient required", 400)
			return
		}
		if req.ExpiresInHours == 0 {
			req.ExpiresInHours = 168
		}
		if req.ExpiresInHours < 1 || req.ExpiresInHours > 720 {
			http.Error(w, "expires_in_hours must be 1..720", 400)
			return
		}
		plain, err := randomUUID()
		if err != nil {
			slog.Error("issue assessment download token: generate token", "err", err, "tenant_id", tid, "artifact_id", aid)
			http.Error(w, "internal error", 500)
			return
		}
		tokenHash := sha256.Sum256([]byte(strings.ToLower(plain)))
		tx, err := pool.Begin(r.Context())
		if err != nil {
			slog.Error("issue assessment download token: begin tx", "err", err, "tenant_id", tid, "artifact_id", aid)
			http.Error(w, "internal error", 500)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck
		var artifactHash []byte
		err = tx.QueryRow(r.Context(), `SELECT sha256 FROM assessment_artifacts WHERE id=$1::uuid AND tenant_id=$2::uuid`, aid, tid).Scan(&artifactHash)
		if err == pgx.ErrNoRows {
			http.Error(w, "artifact not found", 404)
			return
		}
		if err != nil {
			slog.Error("issue assessment download token: lookup artifact", "err", err, "tenant_id", tid, "artifact_id", aid)
			http.Error(w, "internal error", 500)
			return
		}
		// expires_at is computed server-side by the DB itself, from the same
		// NOW() the created_at default uses, rather than from the app's own
		// clock. The migration's CHECK constraint compares expires_at
		// against created_at + INTERVAL '720 hours'; if the app computed an
		// absolute timestamp on its own clock, any skew where the DB host's
		// clock trails the API host's would fail that CHECK on a
		// perfectly valid, documented expires_in_hours=720 request.
		var tokenID int64
		var expires time.Time
		err = tx.QueryRow(r.Context(), `INSERT INTO assessment_download_tokens(artifact_id,tenant_id,recipient_email,token_hash,expires_at,issued_by) VALUES($1::uuid,$2::uuid,$3,$4,NOW() + $5 * INTERVAL '1 hour',$6) RETURNING id, expires_at`, aid, tid, req.Recipient, tokenHash[:], req.ExpiresInHours, actor).Scan(&tokenID, &expires)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO assessment_artifact_audit(tenant_id,artifact_id,token_id,action,actor,recipient_email,sha256) VALUES($1::uuid,$2::uuid,$3,'token_issued',$4,$5,$6)`, tid, aid, tokenID, actor, req.Recipient, artifactHash)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		}
		if err != nil {
			slog.Error("issue assessment download token: insert token or audit row", "err", err, "tenant_id", tid, "artifact_id", aid)
			http.Error(w, "internal error", 500)
			return
		}
		// This response carries the plaintext single-use token, exactly like
		// the redeem response's document body — give it the same no-store
		// treatment so neither a browser nor an intermediary caches it.
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"token": plain, "expires_at": expires, "recipient": req.Recipient, "artifact_id": aid})
	}
}

func RedeemAssessmentDownloadTokenHandler(pool *pgxpool.Pool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimSpace(chi.URLParam(r, "token"))
		if !looksLikeUUID(token) {
			http.Error(w, "invalid token", 400)
			return
		}
		h := sha256.Sum256([]byte(strings.ToLower(token)))
		tx, err := pool.Begin(r.Context())
		if err != nil {
			slog.Error("redeem assessment download token: begin tx", "err", err)
			http.Error(w, "internal error", 500)
			return
		}
		defer tx.Rollback(r.Context()) //nolint:errcheck
		var tokenID int64
		var aid, tid, email, rel, ct, engagement, version string
		var expected []byte
		var expires time.Time
		var used *time.Time
		err = tx.QueryRow(r.Context(), `SELECT t.id,a.id::text,a.tenant_id::text,t.recipient_email,t.expires_at,t.used_at,a.storage_path,a.content_type,a.engagement_reference,a.document_version,a.sha256 FROM assessment_download_tokens t JOIN assessment_artifacts a ON a.id=t.artifact_id AND a.tenant_id=t.tenant_id WHERE t.token_hash=$1 AND t.purpose='assessment_artifact' FOR UPDATE OF t`, h[:]).Scan(&tokenID, &aid, &tid, &email, &expires, &used, &rel, &ct, &engagement, &version, &expected)
		if err == pgx.ErrNoRows {
			http.Error(w, "token not found", 404)
			return
		}
		if err != nil {
			slog.Error("redeem assessment download token: lookup token", "err", err)
			http.Error(w, "internal error", 500)
			return
		}
		if used != nil {
			http.Error(w, "token already used", 410)
			return
		}
		if !time.Now().UTC().Before(expires) {
			http.Error(w, "token expired", 410)
			return
		}
		// NOTE (residual, documented not fixed this round): a missing file
		// (404 below) or a hash mismatch (409 below) is exactly the tamper
		// signal this design exists to detect, but neither writes a row to
		// assessment_artifact_audit — only successful downloads and
		// approvals/issuances are recorded. Adding a failed-attempt action
		// type touches the audit table's CHECK constraint (see migration
		// 0108's action IN ('approved','token_issued','downloaded') and the
		// paired action-shape CHECK) and is bigger than this round's scope.
		// This is a real design gap and should be a dedicated follow-up
		// ticket, not squeezed into this one.
		abs, err := secureArtifactPath(reportStorageRoot(), rel)
		if err != nil {
			slog.Error("unsafe assessment artifact path", "artifact_id", aid, "tenant_id", tid, "err", err)
			http.Error(w, "artifact unavailable", 404)
			return
		}
		data, err := os.ReadFile(abs)
		if err != nil {
			slog.Error("assessment artifact file missing or unreadable", "artifact_id", aid, "tenant_id", tid, "err", err)
			http.Error(w, "artifact unavailable", 404)
			return
		}
		actual := sha256.Sum256(data)
		if !bytes.Equal(actual[:], expected) {
			slog.Error("assessment artifact hash mismatch", "artifact_id", aid, "tenant_id", tid)
			http.Error(w, "artifact integrity check failed", 409)
			return
		}
		_, err = tx.Exec(r.Context(), `UPDATE assessment_download_tokens SET used_at=NOW() WHERE id=$1`, tokenID)
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO assessment_artifact_audit(tenant_id,artifact_id,token_id,action,recipient_email,sha256) VALUES($1::uuid,$2::uuid,$3,'downloaded',$4,$5)`, tid, aid, tokenID, email, expected)
		}
		if err == nil {
			err = tx.Commit(r.Context())
		}
		if err != nil {
			slog.Error("redeem assessment download token: mark used / insert audit row / commit", "err", err, "artifact_id", aid, "tenant_id", tid, "token_id", tokenID)
			http.Error(w, "internal error", 500)
			return
		}
		ext := ".pdf"
		if ct != "application/pdf" {
			ext = ".docx"
		}
		filename := sanitiseFilename("endpoint-assurance-"+engagement+"-"+version) + ext
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.WriteHeader(200)
		_, _ = w.Write(data)
	}
}
