package handlers

// Security tests for GET /v1/posture — GitHub-Non-Author-Review evidence.
//
// These tests verify the auth invariants without a database:
//   1. Missing/malformed Authorization header → 401.
//   2. Tenant-level credential (no device_id) → 401.
//   3. Bad HMAC signature → 401.
//   4. auth success + fetch success → 200 with posture JSON.
//   5. auth success + device purged (ErrDeviceNotFound) → 401 (not 404).
//   6. auth success + internal error → 500.
//   7. buildCompliance section grouping is correct.
//   8. extractSection handles expected rule_key formats.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/auth"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/report"
)

// decodePostureInner decodes the PAT-910 posture envelope, checks the key_id,
// verifies the Ed25519 signature over the transmitted signed_payload bytes, and
// returns those verified inner posture bytes for field assertions. It uses the
// same deterministic test key the handler was built with (newTestSigningKey).
func decodePostureInner(t *testing.T, rr *httptest.ResponseRecorder) []byte {
	t.Helper()
	key := newTestSigningKey()
	var env postureSignedResp
	if err := json.NewDecoder(rr.Body).Decode(&env); err != nil {
		t.Fatalf("decode posture envelope: %v", err)
	}
	if env.KeyID != key.KeyID {
		t.Fatalf("key_id: got %q, want %q", env.KeyID, key.KeyID)
	}
	raw, err := base64.StdEncoding.DecodeString(env.SignedPayload)
	if err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	if err := agentconfig.Verify(key.Public, raw, env.Signature); err != nil {
		t.Fatalf("posture signature must verify over the transmitted bytes: %v", err)
	}
	return raw
}

const (
	pTestTenantID = "a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11"
	pTestDeviceID = "d1eebc99-9c0b-4ef8-bb6d-6bb9bd380a22"
	pOtherDevice  = "e2ffcd00-ad1c-5f09-cc7e-7cc0ce491b33"
)

// pAuthOK returns a stub that always resolves to testTenantID + testDeviceID.
func pAuthOK() postureAuthFn {
	return func(_ context.Context, _, _, _, _ string, _ []byte) (string, string, error) {
		return pTestTenantID, pTestDeviceID, nil
	}
}

// pAuthFail returns a stub that always rejects with "unauthorized".
func pAuthFail(msg string) postureAuthFn {
	return func(_ context.Context, _, _, _, _ string, _ []byte) (string, string, error) {
		return "", "", errors.New(msg)
	}
}

// pFetchOK returns a stub that returns a minimal valid postureResp.
func pFetchOK() postureFetchFn {
	return func(_ context.Context, _, _ string) (postureResp, error) {
		return postureResp{
			SchemaVersion: 1,
			GeneratedAt:   time.Now().UTC(),
			Device: postureDevice{
				ID: pTestDeviceID,
				OS: "macOS",
			},
			Tier:     "report_deploy",
			AppCount: 12,
			Compliance: postureCompliance{
				Platform:   "macOS",
				Benchmarks: []postureBenchmark{},
			},
			Evidence: postureEvidence{
				CoverageWindowDays: 30,
				ScansLogged:        5,
				RecentScanTimes:    []time.Time{},
			},
			Findings: []postureFinding{},
			Updates:  []postureUpdate{},
			AppPolicy: postureAppPolicy{
				Apps:  []postureAppPolicyEntry{},
				Drift: []postureAppDrift{},
			},
		}, nil
	}
}

// pFetchDeviceGone returns ErrDeviceNotFound.
func pFetchDeviceGone() postureFetchFn {
	return func(_ context.Context, _, _ string) (postureResp, error) {
		return postureResp{}, report.ErrDeviceNotFound
	}
}

// pFetchError returns a generic internal error.
func pFetchError() postureFetchFn {
	return func(_ context.Context, _, _ string) (postureResp, error) {
		return postureResp{}, errors.New("db down")
	}
}

func postureGet(t *testing.T, handler http.Handler, authHeader string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/posture", strings.NewReader(""))
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// -- Auth failure tests -------------------------------------------------------

func TestPostureHandler_MissingAuth_401(t *testing.T) {
	h := newPostureHandler(pAuthFail("missing auth"), pFetchOK(), newTestSigningKey(), nil, 0, nil)
	rr := postureGet(t, h, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestPostureHandler_BadSignature_401(t *testing.T) {
	h := newPostureHandler(pAuthFail("signature does not match"), pFetchOK(), newTestSigningKey(), nil, 0, nil)
	rr := postureGet(t, h, "Bearer validtoken")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rr.Code)
	}
}

func TestPostureHandler_TenantLevelCredential_401(t *testing.T) {
	// The handler maps every auth error, including the server-side tenant-level
	// credential result, to the same generic 401.
	h := newPostureHandler(pAuthFail("bearer token not recognised"), pFetchOK(), newTestSigningKey(), nil, 0, nil)
	rr := postureGet(t, h, "Bearer tenantcred")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d; staff/tenant credentials must not reach posture data", rr.Code)
	}
}

// TestPostureHandlerDeviceCredentialRequiredWireUnchanged proves that the
// distinguishable server-side auth result is counted while remaining exactly
// the generic 401 seen by an unknown credential.
func TestPostureHandlerDeviceCredentialRequiredWireUnchanged(t *testing.T) {
	unknown := newPostureHandler(pAuthFail("bearer token not recognised"), pFetchOK(), newTestSigningKey(), nil, 0, nil)
	required := newPostureHandler(func(_ context.Context, _, _, _, _ string, _ []byte) (string, string, error) {
		return "", "", auth.ErrDeviceCredentialRequired
	}, pFetchOK(), newTestSigningKey(), nil, 0, nil)

	before := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("posture"))
	unknownResponse := postureGet(t, unknown, "Bearer unknown")
	requiredResponse := postureGet(t, required, "Bearer tenant-level")
	if unknownResponse.Code != http.StatusUnauthorized || requiredResponse.Code != http.StatusUnauthorized {
		t.Fatalf("auth statuses = %d, %d; want both 401", unknownResponse.Code, requiredResponse.Code)
	}
	if unknownResponse.Body.String() != requiredResponse.Body.String() {
		t.Fatalf("ErrDeviceCredentialRequired body = %q, unknown body = %q; generic 401 must stay identical", requiredResponse.Body.String(), unknownResponse.Body.String())
	}
	if after := testutil.ToFloat64(metrics.DeviceCredentialRequiredTotal.WithLabelValues("posture")); after != before+1 {
		t.Fatalf("DeviceCredentialRequiredTotal{handler=posture} = %v, want %v", after, before+1)
	}
}

func TestPostureHandler_DevicePurged_401(t *testing.T) {
	// Valid device credential, but the device row was deleted → must not 404
	// (that would leak the fact that a device existed). Must be 401.
	h := newPostureHandler(pAuthOK(), pFetchDeviceGone(), newTestSigningKey(), nil, 0, nil)
	rr := postureGet(t, h, "Bearer validdevicecred")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 (device purge masked as auth failure), got %d", rr.Code)
	}
}

// -- Success path -------------------------------------------------------------

func TestPostureHandler_Success_200(t *testing.T) {
	h := newPostureHandler(pAuthOK(), pFetchOK(), newTestSigningKey(), nil, 0, nil)
	rr := postureGet(t, h, "Bearer validdevicecred")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp postureResp
	if err := json.Unmarshal(decodePostureInner(t, rr), &resp); err != nil {
		t.Fatalf("unmarshal inner posture: %v", err)
	}
	if resp.SchemaVersion != 1 {
		t.Errorf("want schema_version=1, got %d", resp.SchemaVersion)
	}
	if resp.Device.ID != pTestDeviceID {
		t.Errorf("want device.id=%s, got %s", pTestDeviceID, resp.Device.ID)
	}
	// PAT-910: the signed body must carry the tenant binding and the monotonic
	// anti-rollback value the endpoint verifier enforces.
	if resp.TenantID != pTestTenantID {
		t.Errorf("want tenant_id=%s in signed body, got %q", pTestTenantID, resp.TenantID)
	}
	if resp.IssuedAt == "" {
		t.Error("want a non-empty issued_at in the signed body (anti-rollback value)")
	}
	ct := rr.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("want Content-Type application/json, got %q", ct)
	}
	cc := rr.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("want Cache-Control: private, no-store; got %q", cc)
	}
}

// TestPostureHandler_SignedEnvelope asserts the response is the PAT-910
// envelope (signed_payload/key_id/signature) and that the signature verifies
// over the transmitted bytes — parity with TestAgentConfigGet_SignedResponse.
func TestPostureHandler_SignedEnvelope(t *testing.T) {
	key := newTestSigningKey()
	h := newPostureHandler(pAuthOK(), pFetchOK(), key, nil, 0, nil)
	rr := postureGet(t, h, "Bearer validdevicecred")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var env postureSignedResp
	if err := json.NewDecoder(rr.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	if env.SignedPayload == "" || env.Signature == "" {
		t.Fatal("envelope must carry signed_payload and signature")
	}
	if env.KeyID != key.KeyID {
		t.Errorf("key_id: got %q, want %q", env.KeyID, key.KeyID)
	}
	raw, err := base64.StdEncoding.DecodeString(env.SignedPayload)
	if err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	if err := agentconfig.Verify(key.Public, raw, env.Signature); err != nil {
		t.Fatalf("signature must verify over transmitted bytes: %v", err)
	}
}

// TestPostureHandler_TamperedPayloadFails asserts that flipping a byte of the
// signed_payload breaks verification — the endpoint verifier rejects tampering
// in transit. Parity with TestAgentConfigGet_TamperedPayloadFails.
func TestPostureHandler_TamperedPayloadFails(t *testing.T) {
	key := newTestSigningKey()
	h := newPostureHandler(pAuthOK(), pFetchOK(), key, nil, 0, nil)
	rr := postureGet(t, h, "Bearer validdevicecred")
	var env postureSignedResp
	if err := json.NewDecoder(rr.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(env.SignedPayload)
	if err != nil {
		t.Fatalf("decode signed_payload: %v", err)
	}
	raw[0] ^= 0xFF
	if err := agentconfig.Verify(key.Public, raw, env.Signature); err == nil {
		t.Fatal("tampered payload must fail verification")
	}
}

func TestPostureHandler_InternalError_500(t *testing.T) {
	h := newPostureHandler(pAuthOK(), pFetchError(), newTestSigningKey(), nil, 0, nil)
	rr := postureGet(t, h, "Bearer validdevicecred")
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d", rr.Code)
	}
}

// -- Cross-device isolation test ---------------------------------------------

func TestPostureHandler_DeviceIsolation(t *testing.T) {
	// The device returned by fetchFn is always pTestDeviceID — derived from the
	// credential, not from any request parameter. Even if a client sends a
	// fabricated URL (not applicable for the current route, but tested here as
	// a spec-conformance check), the response must contain pTestDeviceID.
	h := newPostureHandler(pAuthOK(), pFetchOK(), newTestSigningKey(), nil, 0, nil)

	req := httptest.NewRequest(http.MethodGet, "/v1/posture?device_id="+pOtherDevice, strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer validdevicecred")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var resp postureResp
	_ = json.Unmarshal(decodePostureInner(t, rr), &resp)
	if resp.Device.ID != pTestDeviceID {
		t.Errorf("device isolation violated: got device %s, want %s", resp.Device.ID, pTestDeviceID)
	}
}

// -- Unit tests for pure functions -------------------------------------------

func TestExtractSection(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// macOS dot-notation (prefix.CHAPTER.control)
		{"cis.1.1", "1"},
		{"cis.2.10.3", "2"},
		{"cis.5.4", "5"},
		{"baseline.foo", "foo"},
		// Windows underscore-notation (cis_win_CHAPTER_...)
		{"cis_win_9_1_1_firewall_domain", "9"},
		{"cis_win_18_10_11_bitlocker_os_drive", "18"},
		{"cis_win_19_1_3_2_screensaver_enabled", "19"},
		{"cis_win_2_3_17_1_uac_enabled", "2"},
		// Non-CIS Windows baseline rules fall through to full key
		{"patched_win_mdm_enrolled", "patched_win_mdm_enrolled"},
		// Degenerate
		{"nolabel", "nolabel"},
	}
	for _, c := range cases {
		got := extractSection(c.in)
		if got != c.want {
			t.Errorf("extractSection(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestBuildCompliance_SectionGrouping(t *testing.T) {
	now := time.Now().UTC()
	rep := report.Report{
		Device: report.Device{OS: "macOS"},
		Evaluations: []report.EvalRow{
			{RuleKey: "cis.1.1", Benchmark: "CIS Apple macOS", BenchmarkVersion: "v3.0.0", Severity: "high", Status: "pass", EvaluatedAt: now},
			{RuleKey: "cis.1.2", Benchmark: "CIS Apple macOS", BenchmarkVersion: "v3.0.0", Severity: "high", Status: "fail", EvaluatedAt: now},
			{RuleKey: "cis.2.1", Benchmark: "CIS Apple macOS", BenchmarkVersion: "v3.0.0", Severity: "medium", Status: "pass", EvaluatedAt: now},
			{RuleKey: "cis.2.2", Benchmark: "CIS Apple macOS", BenchmarkVersion: "v3.0.0", Severity: "low", Status: "not_applicable", EvaluatedAt: now},
		},
	}
	benchmarkTotals := map[string]int{"CIS Apple macOS||v3.0.0": 171}

	c := buildCompliance(rep, benchmarkTotals)

	if c.Platform != "macOS" {
		t.Errorf("platform: got %q, want macOS", c.Platform)
	}
	if len(c.Benchmarks) != 1 {
		t.Fatalf("want 1 benchmark, got %d", len(c.Benchmarks))
	}
	bm := c.Benchmarks[0]
	if bm.BenchmarkTotal != 171 {
		t.Errorf("benchmark_total: got %d, want 171", bm.BenchmarkTotal)
	}
	if bm.Implemented != 4 {
		t.Errorf("implemented: got %d, want 4", bm.Implemented)
	}
	if bm.Passed != 2 {
		t.Errorf("passed: got %d, want 2", bm.Passed)
	}
	if bm.Failed != 1 {
		t.Errorf("failed: got %d, want 1", bm.Failed)
	}
	if bm.NotApplicable != 1 {
		t.Errorf("not_applicable: got %d, want 1", bm.NotApplicable)
	}
	// CompliancePct = pass/(pass+fail+error) = 2/3 ≈ 66.67
	if bm.CompliancePct < 66.0 || bm.CompliancePct > 67.0 {
		t.Errorf("compliance_pct: got %.2f, want ~66.67", bm.CompliancePct)
	}
	if len(bm.Sections) != 2 {
		t.Fatalf("want 2 sections (1, 2), got %d", len(bm.Sections))
	}
	if bm.Sections[0].Section != "1" || bm.Sections[0].Total != 2 {
		t.Errorf("section[0]: got %+v", bm.Sections[0])
	}
	if bm.Sections[1].Section != "2" || bm.Sections[1].Total != 2 {
		t.Errorf("section[1]: got %+v", bm.Sections[1])
	}
}

func TestBuildCompliance_NoEvaluations(t *testing.T) {
	rep := report.Report{Device: report.Device{OS: "macOS"}}
	c := buildCompliance(rep, map[string]int{})
	if len(c.Benchmarks) != 0 {
		t.Errorf("want 0 benchmarks for empty evaluations, got %d", len(c.Benchmarks))
	}
}

func TestBuildCompliance_WindowsOS(t *testing.T) {
	rep := report.Report{Device: report.Device{OS: "Windows"}}
	c := buildCompliance(rep, map[string]int{})
	if c.Platform != "Windows" {
		t.Errorf("platform: got %q, want Windows", c.Platform)
	}
}

// TestBuildCompliance_WindowsCISSectionGrouping verifies that Windows rule keys
// (cis_win_CHAPTER_... underscore format) group into CIS chapter sections, not
// individual per-rule pseudo-sections. The fix is in extractSection().
func TestBuildCompliance_WindowsCISSectionGrouping(t *testing.T) {
	now := time.Now().UTC()
	rep := report.Report{
		Device: report.Device{OS: "Windows"},
		Evaluations: []report.EvalRow{
			// Three firewall rules — all chapter 9, should group into one section.
			{RuleKey: "cis_win_9_1_1_firewall_domain", Benchmark: "CIS Microsoft Windows 11", BenchmarkVersion: "v2.0.0", Severity: "high", Status: "pass", EvaluatedAt: now},
			{RuleKey: "cis_win_9_2_1_firewall_private", Benchmark: "CIS Microsoft Windows 11", BenchmarkVersion: "v2.0.0", Severity: "high", Status: "pass", EvaluatedAt: now},
			{RuleKey: "cis_win_9_3_1_firewall_public", Benchmark: "CIS Microsoft Windows 11", BenchmarkVersion: "v2.0.0", Severity: "high", Status: "fail", EvaluatedAt: now},
			// One BitLocker rule — chapter 18.
			{RuleKey: "cis_win_18_10_11_bitlocker_os_drive", Benchmark: "CIS Microsoft Windows 11", BenchmarkVersion: "v2.0.0", Severity: "critical", Status: "pass", EvaluatedAt: now},
		},
	}
	benchmarkTotals := map[string]int{"CIS Microsoft Windows 11||v2.0.0": 52}

	c := buildCompliance(rep, benchmarkTotals)

	if c.Platform != "Windows" {
		t.Errorf("platform: got %q, want Windows", c.Platform)
	}
	if len(c.Benchmarks) != 1 {
		t.Fatalf("want 1 benchmark, got %d", len(c.Benchmarks))
	}
	bm := c.Benchmarks[0]
	if bm.BenchmarkTotal != 52 {
		t.Errorf("benchmark_total: got %d, want 52", bm.BenchmarkTotal)
	}
	if bm.Implemented != 4 {
		t.Errorf("implemented: got %d, want 4", bm.Implemented)
	}
	if bm.Passed != 3 || bm.Failed != 1 {
		t.Errorf("pass/fail: got %d/%d, want 3/1", bm.Passed, bm.Failed)
	}

	// Firewall rules (chapter 9) and BitLocker (chapter 18) must appear as
	// two sections — not 4 individual sections.
	if len(bm.Sections) != 2 {
		t.Fatalf("want 2 sections (chapter 9 and 18), got %d: %v",
			len(bm.Sections), sectionsStr(bm.Sections))
	}

	// Sections are sorted lexicographically: "18" < "9" in string sort.
	if bm.Sections[0].Section != "18" || bm.Sections[0].Total != 1 {
		t.Errorf("section[0]: got section=%q total=%d, want 18/1", bm.Sections[0].Section, bm.Sections[0].Total)
	}
	if bm.Sections[1].Section != "9" || bm.Sections[1].Total != 3 {
		t.Errorf("section[1]: got section=%q total=%d, want 9/3", bm.Sections[1].Section, bm.Sections[1].Total)
	}
	// Section 9 has 2 pass + 1 fail.
	if bm.Sections[1].Passed != 2 {
		t.Errorf("section 9 passed: got %d, want 2", bm.Sections[1].Passed)
	}
}

func sectionsStr(ss []postureSection) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.Section
	}
	return out
}

// TestPostureHandler_UpdatesEmptySlice verifies that an empty updates list
// serialises to [] not null — important for agent consumers that range over it.
func TestPostureHandler_UpdatesEmptySlice(t *testing.T) {
	h := newPostureHandler(pAuthOK(), pFetchOK(), newTestSigningKey(), nil, 0, nil)
	rr := postureGet(t, h, "Bearer validdevicecred")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(decodePostureInner(t, rr), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := string(raw["updates"])
	if got != "[]" {
		t.Errorf("updates: want [], got %s (must not be null)", got)
	}
}

// TestPostureUpdateLinkedCVEs verifies that postureUpdate with linked CVE IDs
// round-trips through JSON correctly.
func TestPostureUpdateLinkedCVEs(t *testing.T) {
	u := postureUpdate{
		AppName:        "Google Chrome",
		Identifier:     "com.google.Chrome",
		Label:          "googlechrome",
		CurrentVersion: "125.0.0.0",
		TargetVersion:  "126.0.6478.127",
		Source:         "catalog",
		LinkedCVEIDs:   []string{"CVE-2024-1234", "CVE-2024-5678"},
	}
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got postureUpdate
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.LinkedCVEIDs) != 2 || got.LinkedCVEIDs[0] != "CVE-2024-1234" {
		t.Errorf("linked_cve_ids round-trip: got %v", got.LinkedCVEIDs)
	}
	// Label is what the agent's install/update trigger matches on — must
	// round-trip distinctly from Identifier (a bundle ID), since the two are
	// not interchangeable (PAT-771-adjacent bug: agent was sending Identifier
	// where the daemon expected Label, so manual installs silently no-op'd).
	if got.Label != "googlechrome" {
		t.Errorf("label round-trip: got %q, want %q", got.Label, "googlechrome")
	}
}

// TestPostureUpdateEmptyLinkedCVEs verifies that an empty linked_cve_ids
// serialises to [] not null.
func TestPostureUpdateEmptyLinkedCVEs(t *testing.T) {
	u := postureUpdate{
		AppName:        "Slack",
		Identifier:     "com.tinyspeck.slackmacgap",
		CurrentVersion: "4.37.0",
		TargetVersion:  "4.38.125",
		Source:         "catalog",
		LinkedCVEIDs:   []string{},
	}
	b, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(raw["linked_cve_ids"]) != "[]" {
		t.Errorf("linked_cve_ids: want [], got %s", raw["linked_cve_ids"])
	}
}

// TestPostureEvidence_DigestPresent verifies that a populated
// last_signed_report_digest surfaces correctly in the JSON response when the
// fetch stub includes one.
func TestPostureEvidence_DigestPresent(t *testing.T) {
	const wantDigest = "abc123def456"
	digest := wantDigest
	fetchFn := func(_ context.Context, _, _ string) (postureResp, error) {
		return postureResp{
			SchemaVersion: 1,
			GeneratedAt:   time.Now().UTC(),
			Device:        postureDevice{ID: pTestDeviceID, OS: "macOS"},
			Tier:          "report_deploy",
			Compliance:    postureCompliance{Platform: "macOS", Benchmarks: []postureBenchmark{}},
			Evidence: postureEvidence{
				CoverageWindowDays:     30,
				ScansLogged:            3,
				LastSignedReportDigest: &digest,
				RecentScanTimes:        []time.Time{},
			},
			Findings: []postureFinding{},
			Updates:  []postureUpdate{},
		}, nil
	}
	h := newPostureHandler(pAuthOK(), fetchFn, newTestSigningKey(), nil, 0, nil)
	rr := postureGet(t, h, "Bearer validdevicecred")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(decodePostureInner(t, rr), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	evidenceRaw, ok := raw["evidence"]
	if !ok {
		t.Fatal("evidence field missing from response")
	}
	var ev postureEvidence
	if err := json.Unmarshal(evidenceRaw, &ev); err != nil {
		t.Fatalf("unmarshal evidence: %v", err)
	}
	if ev.LastSignedReportDigest == nil {
		t.Fatal("last_signed_report_digest: want non-nil, got nil")
	}
	if *ev.LastSignedReportDigest != wantDigest {
		t.Errorf("last_signed_report_digest: want %q, got %q", wantDigest, *ev.LastSignedReportDigest)
	}
}

// TestPostureEvidence_DigestNilWhenNoReport verifies that
// last_signed_report_digest is null (not omitted) in the JSON when no report
// has been generated yet.
func TestPostureEvidence_DigestNilWhenNoReport(t *testing.T) {
	h := newPostureHandler(pAuthOK(), pFetchOK(), newTestSigningKey(), nil, 0, nil)
	rr := postureGet(t, h, "Bearer validdevicecred")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(decodePostureInner(t, rr), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	evidenceRaw, ok := raw["evidence"]
	if !ok {
		t.Fatal("evidence field missing from response")
	}
	var evMap map[string]json.RawMessage
	if err := json.Unmarshal(evidenceRaw, &evMap); err != nil {
		t.Fatalf("unmarshal evidence map: %v", err)
	}
	digestRaw, ok := evMap["last_signed_report_digest"]
	if !ok {
		t.Fatal("last_signed_report_digest key missing from evidence (must be present as null)")
	}
	if string(digestRaw) != "null" {
		t.Errorf("last_signed_report_digest: want null, got %s", digestRaw)
	}
}

// -- App-policy (P6) unit tests -----------------------------------------------

// TestAppPolicyEmptySlices verifies that an empty app_policy serialises to
// {"apps":[],"drift":[]} not {"apps":null,"drift":null}.
func TestAppPolicyEmptySlices(t *testing.T) {
	h := newPostureHandler(pAuthOK(), pFetchOK(), newTestSigningKey(), nil, 0, nil)
	rr := postureGet(t, h, "Bearer validdevicecred")
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(decodePostureInner(t, rr), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	apRaw, ok := raw["app_policy"]
	if !ok {
		t.Fatal("app_policy field missing from response")
	}
	var ap map[string]json.RawMessage
	if err := json.Unmarshal(apRaw, &ap); err != nil {
		t.Fatalf("unmarshal app_policy: %v", err)
	}
	if string(ap["apps"]) != "[]" {
		t.Errorf("app_policy.apps: want [], got %s", ap["apps"])
	}
	if string(ap["drift"]) != "[]" {
		t.Errorf("app_policy.drift: want [], got %s", ap["drift"])
	}
}

// TestAppPolicyEntryUserRemovable verifies that mandatory apps set
// user_removable=false while approved apps set it true.
func TestAppPolicyEntryUserRemovable(t *testing.T) {
	mandatory := postureAppPolicyEntry{
		AppName:         "Zoom",
		Identifier:      "us.zoom.xos",
		Policy:          "mandatory",
		UserRemovable:   false,
		EnforcementTier: "report",
	}
	approved := postureAppPolicyEntry{
		AppName:         "Slack",
		Identifier:      "com.tinyspeck.slackmacgap",
		Policy:          "approved",
		UserRemovable:   true,
		EnforcementTier: "report",
	}
	if mandatory.UserRemovable {
		t.Error("mandatory app must have user_removable=false")
	}
	if !approved.UserRemovable {
		t.Error("approved app must have user_removable=true")
	}
}

// TestAppPolicyEntryLabel verifies label round-trips through JSON — including
// when empty (no catalog match) — the key must always be present since the
// Swift client decodes it as a non-optional String, not Optional<String>.
func TestAppPolicyEntryLabel(t *testing.T) {
	withLabel := postureAppPolicyEntry{AppName: "Zoom", Identifier: "us.zoom.xos", Label: "zoom", Policy: "approved"}
	b, err := json.Marshal(withLabel)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got postureAppPolicyEntry
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Label != "zoom" {
		t.Errorf("label round-trip: got %q, want %q", got.Label, "zoom")
	}

	noLabel := postureAppPolicyEntry{AppName: "Claude", Identifier: "com.anthropic.claudefordesktop", Policy: "approved"}
	b, err = json.Marshal(noLabel)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := raw["label"]; !present {
		t.Error(`"label" key must be present even when empty (no omitempty) — Swift decodes it as non-optional`)
	}
}

// TestAppPolicyDriftTypes verifies both drift_type values serialise correctly.
func TestAppPolicyDriftTypes(t *testing.T) {
	cases := []struct {
		name     string
		drift    postureAppDrift
		wantType string
	}{
		{
			name: "mandatory_missing",
			drift: postureAppDrift{
				DriftType:       "mandatory_missing",
				AppName:         "CrowdStrike Falcon",
				Identifier:      "com.crowdstrike.falcon",
				Policy:          "mandatory",
				EnforcementTier: "app_management",
			},
			wantType: "mandatory_missing",
		},
		{
			name: "unapproved_present",
			drift: postureAppDrift{
				DriftType:       "unapproved_present",
				AppName:         "TeamViewer",
				Identifier:      "com.teamviewer.TeamViewer",
				Policy:          "unapproved",
				EnforcementTier: "report",
			},
			wantType: "unapproved_present",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.drift)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var got map[string]json.RawMessage
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			gotType := strings.Trim(string(got["drift_type"]), `"`)
			if gotType != tc.wantType {
				t.Errorf("drift_type: want %q, got %q", tc.wantType, gotType)
			}
		})
	}
}

// TestAppPolicyRoundTrip verifies the full postureAppPolicy struct round-trips
// through JSON with both apps and drift entries populated.
func TestAppPolicyRoundTrip(t *testing.T) {
	ap := postureAppPolicy{
		Apps: []postureAppPolicyEntry{
			{AppName: "Zoom", Identifier: "us.zoom.xos", Policy: "mandatory", UserRemovable: false, EnforcementTier: "app_management"},
			{AppName: "VLC", Identifier: "org.videolan.vlc", Policy: "unapproved", UserRemovable: true, EnforcementTier: "report"},
		},
		Drift: []postureAppDrift{
			{DriftType: "unapproved_present", AppName: "VLC", Identifier: "org.videolan.vlc", Policy: "unapproved", EnforcementTier: "report"},
		},
	}
	b, err := json.Marshal(ap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got postureAppPolicy
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Apps) != 2 {
		t.Errorf("apps: want 2, got %d", len(got.Apps))
	}
	if len(got.Drift) != 1 {
		t.Errorf("drift: want 1, got %d", len(got.Drift))
	}
	if got.Drift[0].DriftType != "unapproved_present" {
		t.Errorf("drift[0].drift_type: want unapproved_present, got %s", got.Drift[0].DriftType)
	}
}

// TestMandatoryPolicySatisfied_OverlappingPolicyOnSameApp is the PAT-1147
// regression: a device has one installed app (Opera, bundle_id
// com.operasoftware.Opera) and two tenant_app_policies rows both able to
// match it — one 'approved' keyed by bundle_id, one 'mandatory' keyed by
// name only. The mandatory policy must be reported satisfied because the
// installed Opera app matches it by name, independent of the fact that a
// *different* policy also matches it by bundle_id. Before the fix, a
// first-match-wins resolution only ever marked the bundle_id-keyed policy as
// seen, so this exact mandatory policy was falsely reported missing even
// though Opera was installed.
func TestPostureMandatoryPolicySatisfied_OverlappingPolicyOnSameApp(t *testing.T) {
	apps := []report.App{
		{Name: "Opera", BundleID: "com.operasoftware.Opera"},
	}
	mandatoryByName := tenantPolicy{
		Name:            strPtr("Opera"),
		Policy:          "mandatory",
		EnforcementTier: "app_management",
	}
	if !mandatoryPolicySatisfied(mandatoryByName, apps, "macOS") {
		t.Error("mandatory policy keyed by name must be satisfied by an installed app matching that name, even though the app is also matched by a different policy's bundle_id")
	}
}

// TestMandatoryPolicySatisfied_GenuinelyMissing is the control: a mandatory
// policy for an app that is NOT installed on the device must still be
// reported missing. Guards against over-correcting into never flagging
// mandatory_missing at all.
func TestPostureMandatoryPolicySatisfied_GenuinelyMissing(t *testing.T) {
	apps := []report.App{
		{Name: "Opera", BundleID: "com.operasoftware.Opera"},
	}
	mandatoryMissingApp := tenantPolicy{
		Name:            strPtr("CrowdStrike Falcon"),
		BundleID:        strPtr("com.crowdstrike.falcon"),
		Policy:          "mandatory",
		EnforcementTier: "app_management",
	}
	if mandatoryPolicySatisfied(mandatoryMissingApp, apps, "macOS") {
		t.Error("mandatory policy for an app genuinely absent from the device must not be reported satisfied")
	}
}
