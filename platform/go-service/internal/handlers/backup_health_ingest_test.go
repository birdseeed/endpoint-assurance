package handlers

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"patched.im/api/internal/ratelimit"
)

// newBackupHeartbeatTestRL returns a rate limiter generous enough that it
// never interferes with tests that aren't specifically exercising rate
// limiting.
func newBackupHeartbeatTestRL() *ratelimit.TenantLimiter {
	return ratelimit.New(ratelimit.Config{RPM: 1000, Burst: 1000})
}

func TestBackupHeartbeatIngestHandler_HappyPath(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	body := `{"job":"portal-r2","label":"Portal+scan → R2 (portal-01)","status":"ok","last_success_at":"2026-08-14T03:00:12Z","detail":"snapshot 20260814_030000"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}

	full := filepath.Join(dir, "portal-r2.json")
	data, err := os.ReadFile(full)
	if err != nil {
		t.Fatalf("expected heartbeat file to exist: %v", err)
	}
	var got backupJobResp
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal written file: %v", err)
	}
	if got.Job != "portal-r2" {
		t.Errorf("job: got %q, want portal-r2", got.Job)
	}
	if got.Status != "ok" {
		t.Errorf("status: got %q, want ok", got.Status)
	}
	if got.LastSuccessAt == nil || !got.LastSuccessAt.Equal(time.Date(2026, 8, 14, 3, 0, 12, 0, time.UTC)) {
		t.Errorf("last_success_at: got %v", got.LastSuccessAt)
	}

	// No stray temp files left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly one file in dir, got %d: %v", len(entries), entries)
	}
}

func TestBackupHeartbeatIngestHandler_MissingToken(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	body := `{"job":"portal-r2","status":"ok"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	// No Authorization header at all.
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", w.Code, w.Body.String())
	}
	assertNoFilesWritten(t, dir)
}

func TestBackupHeartbeatIngestHandler_WrongToken(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	body := `{"job":"portal-r2","status":"ok"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", w.Code, w.Body.String())
	}
	assertNoFilesWritten(t, dir)
}

func TestBackupHeartbeatIngestHandler_UnsetTokenFailsClosed(t *testing.T) {
	dir := t.TempDir()
	// Token configured as empty string, matching what loadConfig() produces
	// when BACKUP_HEARTBEAT_TOKEN is unset — must fail closed, never open.
	h := BackupHeartbeatIngestHandler("", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	body := `{"job":"portal-r2","status":"ok"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer anything-at-all")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d: %s", w.Code, w.Body.String())
	}
	assertNoFilesWritten(t, dir)
}

func TestBackupHeartbeatIngestHandler_OversizedBody(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	// A detail field alone that blows well past maxBackupHeartbeatBytes (4 KiB).
	huge := strings.Repeat("A", maxBackupHeartbeatBytes*2)
	body := `{"job":"portal-r2","status":"ok","detail":"` + huge + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("want 413, got %d: %s", w.Code, w.Body.String())
	}
	assertNoFilesWritten(t, dir)
}

func TestBackupHeartbeatIngestHandler_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(`not-json`))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	assertNoFilesWritten(t, dir)
}

func TestBackupHeartbeatIngestHandler_UnknownFieldsRejected(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	body := `{"job":"portal-r2","status":"ok","unexpected_field":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	assertNoFilesWritten(t, dir)
}

func TestBackupHeartbeatIngestHandler_PathTraversalJobID(t *testing.T) {
	cases := []string{
		"../etc/passwd",
		"../../srv/backup/health/x",
		"/etc/passwd",
		"foo/bar",
		"foo.json", // extension smuggled into the identifier itself
		"..",
		".",
		"",
		"UPPERCASE", // outside the allowed charset
		"has space",
		"job\x00null",
	}
	for _, jobID := range cases {
		t.Run(jobID, func(t *testing.T) {
			dir := t.TempDir()
			h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

			payload, err := json.Marshal(backupJobResp{Job: jobID, Status: "ok"})
			if err != nil {
				t.Fatalf("marshal request body: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewReader(payload))
			req.Header.Set("Authorization", "Bearer s3cret")
			w := httptest.NewRecorder()
			h(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("job %q: want 400, got %d: %s", jobID, w.Code, w.Body.String())
			}

			// Nothing must have been written anywhere, in particular not
			// outside dir (walk the parent to be sure a ".." attempt didn't
			// escape).
			assertNoFilesWritten(t, dir)
			parent := filepath.Dir(dir)
			entries, err := os.ReadDir(parent)
			if err != nil {
				t.Fatalf("readdir parent: %v", err)
			}
			for _, e := range entries {
				if e.Name() == "passwd" || e.Name() == "x" {
					t.Fatalf("job %q: traversal escaped tempdir, found %q in %s", jobID, e.Name(), parent)
				}
			}
		})
	}
}

func TestBackupHeartbeatIngestHandler_ControlCharactersRejected(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	payload, err := json.Marshal(backupJobResp{
		Job:    "portal-r2",
		Status: "ok",
		Detail: "snapshot 20260814\x1b[31mINJECTED\x1b[0m",
	})
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	assertNoFilesWritten(t, dir)
}

func TestBackupHeartbeatIngestHandler_RateLimited(t *testing.T) {
	dir := t.TempDir()
	rl := ratelimit.New(ratelimit.Config{RPM: 60, Burst: 1})
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, rl)

	send := func() int {
		body := `{"job":"portal-r2","status":"ok"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer s3cret")
		w := httptest.NewRecorder()
		h(w, req)
		return w.Code
	}

	if code := send(); code != http.StatusOK {
		t.Fatalf("first request: want 200, got %d", code)
	}
	if code := send(); code != http.StatusTooManyRequests {
		t.Fatalf("second request: want 429 (burst=1 exhausted), got %d", code)
	}
}

func TestBackupHeartbeatIngestHandler_AtomicWriteOverwritesCleanly(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	post := func(status string) {
		body := `{"job":"portal-r2","status":"` + status + `"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer s3cret")
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("post status=%s: want 200, got %d: %s", status, w.Code, w.Body.String())
		}
	}

	post("fail")
	post("ok")

	data, err := os.ReadFile(filepath.Join(dir, "portal-r2.json"))
	if err != nil {
		t.Fatalf("read heartbeat file: %v", err)
	}
	var got backupJobResp
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Status != "ok" {
		t.Errorf("status: got %q, want ok (second write should win)", got.Status)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected exactly one file after two writes, got %d: %v", len(entries), entries)
	}
}

// TestBackupHeartbeatIngestHandler_HTMLMetacharactersRejected proves the
// staff-console XSS sink (dashboard repo's templates/console.html, which
// concatenates job/label/status/detail straight into .innerHTML with no
// escaping) can never receive markup or script through this endpoint.
func TestBackupHeartbeatIngestHandler_HTMLMetacharactersRejected(t *testing.T) {
	cases := []struct {
		name string
		job  backupJobResp
	}{
		{"detail img onerror", backupJobResp{Job: "portal-r2", Status: "ok", Detail: `<img src=x onerror=alert(1)>`}},
		{"label script tag", backupJobResp{Job: "portal-r2", Status: "ok", Label: `<script>alert(1)</script>`}},
		{"status quote", backupJobResp{Job: "portal-r2", Status: `ok"><b>`}},
		{"detail ampersand", backupJobResp{Job: "portal-r2", Status: "ok", Detail: "snapshot & more"}},
		{"detail single quote", backupJobResp{Job: "portal-r2", Status: "ok", Detail: "it's fine"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

			payload, err := json.Marshal(tc.job)
			if err != nil {
				t.Fatalf("marshal request body: %v", err)
			}
			req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewReader(payload))
			req.Header.Set("Authorization", "Bearer s3cret")
			w := httptest.NewRecorder()
			h(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
			}
			assertNoFilesWritten(t, dir)
		})
	}
}

// TestBackupHeartbeatIngestHandler_JobNotAllowlisted proves a valid,
// well-formed job id outside BACKUP_HEARTBEAT_ALLOWED_JOBS is rejected —
// otherwise the portal-01 credential could overwrite another host's
// heartbeat file (e.g. prod-01's prod-r2.json) in the shared
// PATCHED_BACKUP_HEALTH_DIR, including painting a genuinely failing job green.
func TestBackupHeartbeatIngestHandler_JobNotAllowlisted(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	body := `{"job":"prod-r2","status":"ok"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d: %s", w.Code, w.Body.String())
	}
	assertNoFilesWritten(t, dir)
}

// TestBackupHeartbeatIngestHandler_MultipleAllowedJobs proves the CSV
// allowlist parsing accepts more than one job id (e.g. an operator adding a
// second portal-01 job in future) and still rejects anything outside it.
func TestBackupHeartbeatIngestHandler_MultipleAllowedJobs(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2", "portal-scan"}, newBackupHeartbeatTestRL())

	for _, job := range []string{"portal-r2", "portal-scan"} {
		body := `{"job":"` + job + `","status":"ok"}`
		req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer s3cret")
		w := httptest.NewRecorder()
		h(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("job %q: want 200, got %d: %s", job, w.Code, w.Body.String())
		}
	}

	body := `{"job":"portal-other","status":"ok"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("job outside allowlist: want 403, got %d: %s", w.Code, w.Body.String())
	}
}

// TestBackupHeartbeatIngestHandler_FutureTimestampRejected proves a
// last_success_at far in the future is rejected — otherwise a single such
// heartbeat would read as perpetually fresh on the dashboard's
// (now - last_success_at) staleness calculation, even if the job never
// reports again.
func TestBackupHeartbeatIngestHandler_FutureTimestampRejected(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	future := time.Now().UTC().Add(48 * time.Hour).Format(time.RFC3339)
	body := `{"job":"portal-r2","status":"ok","last_success_at":"` + future + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	assertNoFilesWritten(t, dir)
}

// TestBackupHeartbeatIngestHandler_SmallClockSkewAllowed proves the future
// check isn't so tight it rejects ordinary clock skew between portal-01 and
// api-01.
func TestBackupHeartbeatIngestHandler_SmallClockSkewAllowed(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	future := time.Now().UTC().Add(30 * time.Second).Format(time.RFC3339)
	body := `{"job":"portal-r2","status":"ok","last_success_at":"` + future + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestBackupHeartbeatIngestHandler_ImplausiblyOldTimestampRejected proves an
// absurdly old last_success_at (a near-certain unit/format bug) is rejected
// rather than silently accepted.
func TestBackupHeartbeatIngestHandler_ImplausiblyOldTimestampRejected(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	body := `{"job":"portal-r2","status":"ok","last_success_at":"1990-01-01T00:00:00Z"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d: %s", w.Code, w.Body.String())
	}
	assertNoFilesWritten(t, dir)
}

// TestReadBackupJobs_IgnoresStrayTempFile proves that a temp file left
// behind by a crash between os.CreateTemp and os.Rename in
// writeBackupHeartbeatFile (using its exact naming scheme, no ".json"
// suffix) is never picked up by readBackupJobs — which filters purely on a
// ".json" suffix and would otherwise treat it as a permanent, frozen "job"
// row on the dashboard.
func TestReadBackupJobs_IgnoresStrayTempFile(t *testing.T) {
	dir := t.TempDir()
	stray := filepath.Join(dir, ".tmp-portal-r2-abc123")
	if err := os.WriteFile(stray, []byte(`{"job":"portal-r2","status":"ok"}`), 0o640); err != nil {
		t.Fatalf("write stray temp file: %v", err)
	}

	h := &AdminHealthHandler{backupHealthDir: dir}
	jobs := h.readBackupJobs(slog.Default())
	if len(jobs) != 0 {
		t.Fatalf("stray temp file should not be picked up by readBackupJobs, got %v", jobs)
	}
}

func assertNoFilesWritten(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files written, found %v", entries)
	}
}

// TestBackupHeartbeatIngestHandler_TrailingNewlineAccepted pins the wire
// contract against the real producer. portal-backup.sh writes its heartbeat
// with printf '...\n', and ship_heartbeat POSTs that file with
// curl --data-binary, so the body genuinely arrives with a trailing newline.
// Every other test here posts without one. Since the decoder rejects trailing
// content after the JSON value, a change that stopped treating that newline as
// insignificant whitespace would reject the only legitimate caller in
// production while this suite stayed green — the same shipped-but-inert
// failure mode PAT-954's review already caught once (PAT-912 / PAT-837).
func TestBackupHeartbeatIngestHandler_TrailingNewlineAccepted(t *testing.T) {
	dir := t.TempDir()
	h := BackupHeartbeatIngestHandler("s3cret", dir, []string{"portal-r2"}, newBackupHeartbeatTestRL())

	// Byte-identical to portal-backup.sh's printf, trailing newline included.
	body := `{"job":"portal-r2","label":"Portal+scan → R2 (portal-01)","status":"ok","last_success_at":"2026-08-14T03:00:12Z","detail":"snapshot 20260814_030000"}` + "\n"

	req := httptest.NewRequest(http.MethodPost, "/v1/backup-health", bytes.NewBufferString(body))
	req.Header.Set("Authorization", "Bearer s3cret")
	w := httptest.NewRecorder()
	h(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("real wire payload rejected: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := os.ReadFile(filepath.Join(dir, "portal-r2.json")); err != nil {
		t.Fatalf("expected heartbeat file to be written: %v", err)
	}
}
