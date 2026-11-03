package handlers

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
)

func testDOCX(t *testing.T, names ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte("x"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestAssessmentDocumentTypeFailsClosed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want string
		ok   bool
	}{
		{"pdf", []byte("%PDF-1.7\nbody"), "application/pdf", true},
		{"docx", testDOCX(t, "[Content_Types].xml", "word/document.xml"), "application/vnd.openxmlformats-officedocument.wordprocessingml.document", true},
		{"generic zip", testDOCX(t, "payload.txt"), "", false},
		{"zip traversal", testDOCX(t, "[Content_Types].xml", "word/document.xml", "../escape"), "", false},
		{"html", []byte("<html>not a PDF</html>"), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := assessmentDocumentType(tt.data)
			if (err == nil) != tt.ok || got != tt.want {
				t.Fatalf("got %q err=%v", got, err)
			}
		})
	}
}

func TestSecureArtifactPathRejectsTraversalAndSymlinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "assessments", "tenant", "artifact")
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if _, err := secureArtifactPath(root, "../outside.pdf"); err == nil {
		t.Fatal("traversal accepted")
	}
	if _, err := secureArtifactPath(root, filepath.Join(dir, "absolute.pdf")); err == nil {
		t.Fatal("absolute path accepted")
	}
	file := filepath.Join(dir, "assessment.pdf")
	if err := os.WriteFile(file, []byte("%PDF-"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := secureArtifactPath(root, filepath.Join("assessments", "tenant", "artifact", "assessment.pdf")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pdf")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := secureArtifactPath(root, filepath.Join("assessments", "tenant", "artifact", "link.pdf")); err == nil {
		t.Fatal("symlink accepted")
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "assessment.pdf"), []byte("%PDF-"), 0600); err != nil {
		t.Fatal(err)
	}
	ancestorLink := filepath.Join(root, "assessments", "linked")
	if err := os.Symlink(outside, ancestorLink); err != nil {
		t.Fatal(err)
	}
	if _, err := secureArtifactPath(root, filepath.Join("assessments", "linked", "assessment.pdf")); err == nil {
		t.Fatal("ancestor symlink escape accepted")
	}
}

func TestSecureArtifactDirAndExclusiveWriteRefusePreplantedPaths(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	if err := os.Symlink(out, filepath.Join(root, "assessments")); err != nil {
		t.Fatal(err)
	}
	if _, err := secureArtifactDir(root, filepath.Join("assessments", "tenant", "artifact"), 0750); err == nil {
		t.Fatal("symlinked storage ancestor accepted")
	}
	if _, err := os.Stat(filepath.Join(out, "tenant")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory was created outside storage root: %v", err)
	}

	root = t.TempDir()
	dir, err := secureArtifactDir(root, filepath.Join("assessments", "tenant", "artifact"), 0750)
	if err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(dir, "assessment.pdf")
	outside := filepath.Join(t.TempDir(), "outside.pdf")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, final); err != nil {
		t.Fatal(err)
	}
	if err := writeArtifactExclusive(final, []byte("replace")); err == nil {
		t.Fatal("exclusive artifact publish overwrote a pre-planted final path")
	}
	got, err := os.ReadFile(outside)
	if err != nil || string(got) != "keep" {
		t.Fatalf("outside target changed: %q err=%v", got, err)
	}
}

func TestAssessmentReferenceContract(t *testing.T) {
	for _, good := range []string{"EA-2026-001", "v1.2", "customer_alpha"} {
		if !assessmentReferenceRE.MatchString(good) {
			t.Errorf("rejected %q", good)
		}
	}
	for _, bad := range []string{"", "../escape", "has space", "x/y", "x\\y"} {
		if assessmentReferenceRE.MatchString(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestIssueAssessmentDownloadTokenRejectsUnknownAndTrailingJSON(t *testing.T) {
	router := chi.NewRouter()
	router.Post("/admin/tenants/{tenantID}/assessment-artifacts/{artifactID}/download-tokens", IssueAssessmentDownloadTokenHandler(nil))
	const tenantID = "11111111-1111-4111-8111-111111111111"
	const artifactID = "22222222-2222-4222-8222-222222222222"
	for _, body := range []string{
		`{"recipient":"recipient@example.com","unexpected":true}`,
		`{"recipient":"recipient@example.com"}{"recipient":"second@example.com"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/assessment-artifacts/"+artifactID+"/download-tokens", strings.NewReader(body))
		req.Header.Set("X-Patched-Actor-Email", "reviewer@patched.im")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("body %q returned %d, want 400", body, rr.Code)
		}
	}
}

func TestApproveAssessmentArtifact_DB_ImmutableProvenance(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool, "pat1405-approve", evUniqueToken("pat1405-approve-token"), evUniqueToken("pat1405-approve-hmac"))
	root := t.TempDir()
	t.Setenv("REPORT_STORAGE_ROOT", root)
	generatedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	approve := func(document []byte) *httptest.ResponseRecorder {
		t.Helper()
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		for name, value := range map[string]string{
			"engagement_reference": "EA-2026-001",
			"document_version":     "v1",
			"generated_at":         generatedAt.Format(time.RFC3339),
		} {
			if err := mw.WriteField(name, value); err != nil {
				t.Fatal(err)
			}
		}
		part, err := mw.CreateFormFile("document", "assessment.pdf")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(document); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		router := chi.NewRouter()
		router.Post("/admin/tenants/{tenantID}/assessment-artifacts/approve", ApproveAssessmentArtifactHandler(pool))
		req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/assessment-artifacts/approve", &body)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.Header.Set("X-Patched-Actor-Email", "specialist@patched.im")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	document := []byte("%PDF-1.7\nbyte-identical approved specialist report\n%%EOF")
	rr := approve(document)
	if rr.Code != http.StatusCreated {
		t.Fatalf("approve = %d: %s", rr.Code, rr.Body.String())
	}
	var got assessmentArtifact
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	wantHash := sha256.Sum256(document)
	if got.TenantID != tenantID || got.ApprovedBy != "specialist@patched.im" || got.SHA256 != fmt.Sprintf("%x", wantHash) || !got.GeneratedAt.Equal(generatedAt) || got.ApprovedAt.Before(generatedAt) {
		t.Fatalf("unexpected immutable provenance: %+v", got)
	}
	var rel, actor, action string
	var storedHash []byte
	if err := pool.QueryRow(ctx, `SELECT storage_path,sha256,approved_by FROM assessment_artifacts WHERE id=$1::uuid`, got.ID).Scan(&rel, &storedHash, &actor); err != nil {
		t.Fatal(err)
	}
	if actor != got.ApprovedBy || !bytes.Equal(storedHash, wantHash[:]) {
		t.Fatalf("stored provenance actor=%q hash=%x", actor, storedHash)
	}
	abs, err := secureArtifactPath(root, rel)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(abs)
	if err != nil || !bytes.Equal(stored, document) {
		t.Fatalf("stored bytes differ: err=%v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT action,actor FROM assessment_artifact_audit WHERE artifact_id=$1::uuid`, got.ID).Scan(&action, &actor); err != nil || action != "approved" || actor != got.ApprovedBy {
		t.Fatalf("approval audit action=%q actor=%q err=%v", action, actor, err)
	}

	// A document version is immutable even if the replacement bytes differ.
	// This is a definitely-pre-commit 23505 unique-violation (the rejected
	// attempt has already had its own file written and its own per-artifact
	// directory created under a fresh random artifact ID before the INSERT
	// runs), so it must also leave no orphaned empty directory behind: only
	// the one directory belonging to the first, successfully approved
	// artifact should remain under assessments/{tenantID}/.
	if duplicate := approve([]byte("%PDF-1.7\ndifferent bytes\n%%EOF")); duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate document version = %d, want 409: %s", duplicate.Code, duplicate.Body.String())
	}
	tenantDir := filepath.Join(root, "assessments", tenantID)
	entries, err := os.ReadDir(tenantDir)
	if err != nil {
		t.Fatalf("read tenant artifact dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != got.ID {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Fatalf("rejected duplicate approval left an orphaned artifact directory: got %v, want only [%s]", names, got.ID)
	}
}

// TestIssueAssessmentDownloadToken_DB_IssuanceSucceeds drives the real
// issuance HTTP handler end-to-end (not a direct SQL INSERT like the
// redemption tests below use to mint their tokens) so a broken issuance
// INSERT — wrong column, wrong CHECK-satisfying value, etc — would actually
// fail a test instead of shipping unnoticed.
func TestIssueAssessmentDownloadToken_DB_IssuanceSucceeds(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool, "pat1405-issue", evUniqueToken("pat1405-issue-token"), evUniqueToken("pat1405-issue-hmac"))
	root := t.TempDir()
	t.Setenv("REPORT_STORAGE_ROOT", root)

	artifactID, _ := randomUUID()
	document := []byte("%PDF-1.7\nissuance coverage artifact\n%%EOF")
	sum := sha256.Sum256(document)
	rel := filepath.Join("assessments", tenantID, artifactID, "assessment.pdf")
	abs := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, document, 0640); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO assessment_artifacts
		(id,tenant_id,engagement_reference,document_version,content_type,storage_path,sha256,byte_size,generated_at,approved_at,approved_by)
		VALUES($1::uuid,$2::uuid,'EA-ISSUE','v1','application/pdf',$3,$4,$5,NOW(),NOW(),'reviewer@patched.im')`,
		artifactID, tenantID, rel, sum[:], len(document)); err != nil {
		t.Fatalf("seed approved artifact (is migration 0108 applied?): %v", err)
	}

	router := chi.NewRouter()
	router.Post("/admin/tenants/{tenantID}/assessment-artifacts/{artifactID}/download-tokens", IssueAssessmentDownloadTokenHandler(pool))
	body, _ := json.Marshal(map[string]any{"recipient": "recipient@example.com", "expires_in_hours": 24})
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/assessment-artifacts/"+artifactID+"/download-tokens", bytes.NewReader(body))
	req.Header.Set("X-Patched-Actor-Email", "reviewer@patched.im")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("issue = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("Pragma") != "no-cache" {
		t.Fatalf("issuance response missing no-store/no-cache headers on a body that carries a plaintext token: %v", rr.Header())
	}

	var resp struct {
		Token      string    `json:"token"`
		ExpiresAt  time.Time `json:"expires_at"`
		Recipient  string    `json:"recipient"`
		ArtifactID string    `json:"artifact_id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode issuance response: %v body=%s", err, rr.Body.String())
	}
	if resp.Token == "" || resp.Recipient != "recipient@example.com" || resp.ArtifactID != artifactID {
		t.Fatalf("unexpected issuance response: %+v body=%s", resp, rr.Body.String())
	}
	if resp.ExpiresAt.Before(time.Now().Add(23*time.Hour)) || resp.ExpiresAt.After(time.Now().Add(25*time.Hour)) {
		t.Fatalf("expires_at not ~24h out from issuance: %v", resp.ExpiresAt)
	}

	var storedHash []byte
	var issuedBy, recipient string
	if err := pool.QueryRow(ctx, `SELECT token_hash, issued_by, recipient_email FROM assessment_download_tokens WHERE artifact_id=$1::uuid`, artifactID).
		Scan(&storedHash, &issuedBy, &recipient); err != nil {
		t.Fatalf("assessment_download_tokens row missing after issuance: %v", err)
	}
	wantHash := sha256.Sum256([]byte(strings.ToLower(resp.Token)))
	if !bytes.Equal(storedHash, wantHash[:]) {
		t.Fatalf("stored token_hash does not match the issued plaintext token")
	}
	if issuedBy != "reviewer@patched.im" || recipient != "recipient@example.com" {
		t.Fatalf("issuance row actor/recipient mismatch: issued_by=%q recipient=%q", issuedBy, recipient)
	}

	var auditAction, auditRecipient string
	if err := pool.QueryRow(ctx, `SELECT action, recipient_email FROM assessment_artifact_audit WHERE artifact_id=$1::uuid AND action='token_issued'`, artifactID).
		Scan(&auditAction, &auditRecipient); err != nil {
		t.Fatalf("token_issued audit row missing after issuance: %v", err)
	}
	if auditRecipient != "recipient@example.com" {
		t.Fatalf("unexpected token_issued audit row recipient: %q", auditRecipient)
	}
}

func TestAssessmentDownload_DB_ExpiryReplayTenantAndHash(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool, "pat1405-tenant", evUniqueToken("pat1405-token"), evUniqueToken("pat1405-hmac"))
	otherTenantID := parSeedTenant(t, ctx, pool, "pat1405-other", evUniqueToken("pat1405-other-token"), evUniqueToken("pat1405-other-hmac"))
	root := t.TempDir()
	t.Setenv("REPORT_STORAGE_ROOT", root)

	artifactID, _ := randomUUID()
	approved := []byte("%PDF-1.7\nbyte-identical approved specialist report")
	sum := sha256.Sum256(approved)
	rel := filepath.Join("assessments", tenantID, artifactID, "assessment.pdf")
	abs := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, approved, 0640); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(ctx, `INSERT INTO assessment_artifacts
		(id,tenant_id,engagement_reference,document_version,content_type,storage_path,sha256,byte_size,generated_at,approved_at,approved_by)
		VALUES($1::uuid,$2::uuid,'EA-TEST','v1','application/pdf',$3,$4,$5,NOW(),NOW(),'reviewer@patched.im')`, artifactID, tenantID, rel, sum[:], len(approved))
	if err != nil {
		t.Fatalf("insert artifact (is migration 0108 applied?): %v", err)
	}
	invalidArtifactID, _ := randomUUID()
	if _, err := pool.Exec(ctx, `INSERT INTO assessment_artifacts
		(id,tenant_id,engagement_reference,document_version,content_type,storage_path,sha256,byte_size,generated_at,approved_at,approved_by)
		VALUES($1::uuid,$2::uuid,'EA-BAD','v1','application/pdf','../outside.pdf',$3,1,NOW(),NOW(),'reviewer@patched.im')`, invalidArtifactID, tenantID, sum[:]); err == nil {
		t.Fatal("database accepted a caller-controlled artifact path")
	}
	if _, err := pool.Exec(ctx, `UPDATE assessment_artifacts SET document_version='mutated' WHERE id=$1::uuid`, artifactID); err == nil {
		t.Fatal("immutable artifact accepted an update")
	}
	badToken, _ := randomUUID()
	badHash := sha256.Sum256([]byte(strings.ToLower(badToken)))
	if _, err := pool.Exec(ctx, `INSERT INTO assessment_download_tokens(artifact_id,tenant_id,recipient_email,token_hash,expires_at,issued_by) VALUES($1::uuid,$2::uuid,'recipient@example.com',$3,NOW()+INTERVAL '1 hour','reviewer@patched.im')`, artifactID, otherTenantID, badHash[:]); err == nil {
		t.Fatal("cross-tenant artifact token accepted by database")
	}
	tooLongToken, _ := randomUUID()
	tooLongHash := sha256.Sum256([]byte(strings.ToLower(tooLongToken)))
	if _, err := pool.Exec(ctx, `INSERT INTO assessment_download_tokens(artifact_id,tenant_id,recipient_email,token_hash,expires_at,issued_by) VALUES($1::uuid,$2::uuid,'recipient@example.com',$3,NOW()+INTERVAL '721 hours','reviewer@patched.im')`, artifactID, tenantID, tooLongHash[:]); err == nil {
		t.Fatal("database accepted a token beyond the 720-hour contract")
	}

	mint := func(expires time.Time) string {
		t.Helper()
		token, _ := randomUUID()
		h := sha256.Sum256([]byte(strings.ToLower(token)))
		created := time.Now()
		if expires.Before(created) {
			created = expires.Add(-time.Hour)
		}
		_, err := pool.Exec(ctx, `INSERT INTO assessment_download_tokens(artifact_id,tenant_id,recipient_email,token_hash,expires_at,issued_by,created_at) VALUES($1::uuid,$2::uuid,'recipient@example.com',$3,$4,'reviewer@patched.im',$5)`, artifactID, tenantID, h[:], expires, created)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	redeem := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		router := chi.NewRouter()
		router.Post("/admin/assessment-download-tokens/{token}/redeem", RedeemAssessmentDownloadTokenHandler(pool))
		req := httptest.NewRequest(http.MethodPost, "/admin/assessment-download-tokens/"+token+"/redeem", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	valid := mint(time.Now().Add(time.Hour))
	validHash := sha256.Sum256([]byte(strings.ToLower(valid)))
	if _, err := pool.Exec(ctx, `UPDATE assessment_download_tokens SET expires_at=expires_at+INTERVAL '1 hour' WHERE token_hash=$1`, validHash[:]); err == nil {
		t.Fatal("token expiry mutation accepted")
	}
	first := redeem(valid)
	if first.Code != 200 || !bytes.Equal(first.Body.Bytes(), approved) {
		t.Fatalf("first redeem %d %q", first.Code, first.Body.Bytes())
	}
	if first.Header().Get("Cache-Control") != "no-store" || first.Header().Get("X-Content-Type-Options") != "nosniff" || first.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("unsafe download headers: %v", first.Header())
	}
	if second := redeem(valid); second.Code != http.StatusGone {
		t.Fatalf("replay = %d, want 410", second.Code)
	}
	if expired := redeem(mint(time.Now().Add(-time.Minute))); expired.Code != http.StatusGone {
		t.Fatalf("expired = %d, want 410", expired.Code)
	}

	corrupt := mint(time.Now().Add(time.Hour))
	if err := os.WriteFile(abs, []byte("%PDF-corrupt"), 0640); err != nil {
		t.Fatal(err)
	}
	if rr := redeem(corrupt); rr.Code != http.StatusConflict {
		t.Fatalf("hash mismatch = %d, want 409", rr.Code)
	}
	var usedAt *time.Time
	h := sha256.Sum256([]byte(strings.ToLower(corrupt)))
	if err := pool.QueryRow(ctx, `SELECT used_at FROM assessment_download_tokens WHERE token_hash=$1`, h[:]).Scan(&usedAt); err != nil || usedAt != nil {
		t.Fatalf("integrity failure burned token: used=%v err=%v", usedAt, err)
	}

	// The artifact belongs to tenantID. Issuing through another tenant route
	// must fail without creating a token.
	router := chi.NewRouter()
	router.Post("/admin/tenants/{tenantID}/assessment-artifacts/{artifactID}/download-tokens", IssueAssessmentDownloadTokenHandler(pool))
	body, _ := json.Marshal(map[string]any{"recipient": "recipient@example.com", "expires_in_hours": 24})
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+otherTenantID+"/assessment-artifacts/"+artifactID+"/download-tokens", bytes.NewReader(body))
	req.Header.Set("X-Patched-Actor-Email", "reviewer@patched.im")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("wrong-tenant issue = %d, want 404: %s", rr.Code, rr.Body.String())
	}
}

// TestApproveAssessmentArtifact_DB_UppercaseTenantIDNormalizes proves an
// uppercase-hex tenant UUID in the URL (looksLikeUUID accepts both cases)
// still approves cleanly: the stored storage_path must match the lowercase
// canonical form Postgres always renders a UUID column as, or the INSERT
// fails the migration's storage_path CHECK constraint as a bare 500, and the
// file on disk must actually live at that lowercase-normalized path.
func TestApproveAssessmentArtifact_DB_UppercaseTenantIDNormalizes(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool, "pat1405-case", evUniqueToken("pat1405-case-token"), evUniqueToken("pat1405-case-hmac"))
	root := t.TempDir()
	t.Setenv("REPORT_STORAGE_ROOT", root)
	upperTenantID := strings.ToUpper(tenantID)

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for name, value := range map[string]string{
		"engagement_reference": "EA-CASE-001",
		"document_version":     "v1",
		"generated_at":         time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	} {
		if err := mw.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := mw.CreateFormFile("document", "assessment.pdf")
	if err != nil {
		t.Fatal(err)
	}
	document := []byte("%PDF-1.7\nuppercase tenant case test\n%%EOF")
	if _, err := part.Write(document); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Post("/admin/tenants/{tenantID}/assessment-artifacts/approve", ApproveAssessmentArtifactHandler(pool))
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+upperTenantID+"/assessment-artifacts/approve", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("X-Patched-Actor-Email", "specialist@patched.im")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("uppercase-tenant approve = %d, want 201: %s", rr.Code, rr.Body.String())
	}
	var rel string
	if err := pool.QueryRow(ctx, `SELECT storage_path FROM assessment_artifacts WHERE tenant_id=$1::uuid`, tenantID).Scan(&rel); err != nil {
		t.Fatalf("stored artifact row missing: %v", err)
	}
	if strings.Contains(rel, upperTenantID) {
		t.Fatalf("storage_path retained caller-supplied uppercase tenant id: %q", rel)
	}
	abs, err := secureArtifactPath(root, rel)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("file not found at lowercase-normalized DB path: %v", err)
	}
}

// TestAssessmentArtifact_DB_DOCXApproveIssueRedeemRoundTrips drives the full
// approve -> issue -> redeem flow end to end with a real DOCX-typed artifact
// against a live DB. Until now DOCX was only unit-tested at the
// assessmentDocumentType classification level (see
// TestAssessmentDocumentTypeFailsClosed) — nothing exercised the migration's
// content_type <-> assessment.docx storage_path CHECK constraint pairing, or
// the redeem handler's file-extension/content-type selection logic, against
// a real DOCX artifact and a live DB.
func TestAssessmentArtifact_DB_DOCXApproveIssueRedeemRoundTrips(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	tenantID := parSeedTenant(t, ctx, pool, "pat1405-docx", evUniqueToken("pat1405-docx-token"), evUniqueToken("pat1405-docx-hmac"))
	root := t.TempDir()
	t.Setenv("REPORT_STORAGE_ROOT", root)
	generatedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	const wantContentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	document := testDOCX(t, "[Content_Types].xml", "word/document.xml")

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for name, value := range map[string]string{
		"engagement_reference": "EA-DOCX-001",
		"document_version":     "v1",
		"generated_at":         generatedAt.Format(time.RFC3339),
	} {
		if err := mw.WriteField(name, value); err != nil {
			t.Fatal(err)
		}
	}
	part, err := mw.CreateFormFile("document", "assessment.docx")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(document); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	approveRouter := chi.NewRouter()
	approveRouter.Post("/admin/tenants/{tenantID}/assessment-artifacts/approve", ApproveAssessmentArtifactHandler(pool))
	approveReq := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/assessment-artifacts/approve", &body)
	approveReq.Header.Set("Content-Type", mw.FormDataContentType())
	approveReq.Header.Set("X-Patched-Actor-Email", "specialist@patched.im")
	approveRR := httptest.NewRecorder()
	approveRouter.ServeHTTP(approveRR, approveReq)
	if approveRR.Code != http.StatusCreated {
		t.Fatalf("approve DOCX = %d: %s", approveRR.Code, approveRR.Body.String())
	}
	var approved assessmentArtifact
	if err := json.Unmarshal(approveRR.Body.Bytes(), &approved); err != nil {
		t.Fatal(err)
	}
	if approved.ContentType != wantContentType {
		t.Fatalf("approved content_type = %q, want %q", approved.ContentType, wantContentType)
	}

	var storagePath string
	if err := pool.QueryRow(ctx, `SELECT storage_path FROM assessment_artifacts WHERE id=$1::uuid`, approved.ID).Scan(&storagePath); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(storagePath, "/assessment.docx") {
		t.Fatalf("storage_path %q did not get the .docx suffix the migration's CHECK constraint pairs with this content_type", storagePath)
	}

	issueRouter := chi.NewRouter()
	issueRouter.Post("/admin/tenants/{tenantID}/assessment-artifacts/{artifactID}/download-tokens", IssueAssessmentDownloadTokenHandler(pool))
	issueBody, _ := json.Marshal(map[string]any{"recipient": "recipient@example.com", "expires_in_hours": 24})
	issueReq := httptest.NewRequest(http.MethodPost, "/admin/tenants/"+tenantID+"/assessment-artifacts/"+approved.ID+"/download-tokens", bytes.NewReader(issueBody))
	issueReq.Header.Set("X-Patched-Actor-Email", "reviewer@patched.im")
	issueRR := httptest.NewRecorder()
	issueRouter.ServeHTTP(issueRR, issueReq)
	if issueRR.Code != http.StatusOK {
		t.Fatalf("issue token for DOCX artifact = %d: %s", issueRR.Code, issueRR.Body.String())
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(issueRR.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	if issued.Token == "" {
		t.Fatalf("issuance response missing token: %s", issueRR.Body.String())
	}

	redeemRouter := chi.NewRouter()
	redeemRouter.Post("/admin/assessment-download-tokens/{token}/redeem", RedeemAssessmentDownloadTokenHandler(pool))
	redeemReq := httptest.NewRequest(http.MethodPost, "/admin/assessment-download-tokens/"+issued.Token+"/redeem", nil)
	redeemRR := httptest.NewRecorder()
	redeemRouter.ServeHTTP(redeemRR, redeemReq)
	if redeemRR.Code != http.StatusOK {
		t.Fatalf("redeem DOCX artifact = %d: %s", redeemRR.Code, redeemRR.Body.String())
	}
	if got := redeemRR.Header().Get("Content-Type"); got != wantContentType {
		t.Fatalf("redeem Content-Type = %q, want %q", got, wantContentType)
	}
	if cd := redeemRR.Header().Get("Content-Disposition"); !strings.Contains(cd, ".docx\"") {
		t.Fatalf("redeem Content-Disposition missing .docx extension: %q", cd)
	}
	if !bytes.Equal(redeemRR.Body.Bytes(), document) {
		t.Fatalf("redeemed bytes did not round-trip: got %d bytes, want %d bytes", redeemRR.Body.Len(), len(document))
	}
}
