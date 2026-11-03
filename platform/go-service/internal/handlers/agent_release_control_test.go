package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/graphmail"
	"patched.im/api/internal/releasecontrol"
)

func TestReleaseEvidenceValidation(t *testing.T) {
	now := time.Now()
	req := releaseEvidenceReq{Platform: "windows", Version: "1.2.3", Metric: "enrolment", WindowStart: now.Add(-73 * time.Hour), WindowEnd: now, Attempts: 100, Failures: 1, Provenance: "monitor:run-42"}
	if err := validReleaseEvidence(req, now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*releaseEvidenceReq){func(r *releaseEvidenceReq) { r.Failures = 101 }, func(r *releaseEvidenceReq) { r.Attempts = 1000000001 }, func(r *releaseEvidenceReq) { r.WindowEnd = now.Add(time.Hour) }, func(r *releaseEvidenceReq) { r.Metric = "service_crash" }, func(r *releaseEvidenceReq) { r.Provenance = "\n" }, func(r *releaseEvidenceReq) { r.Version = "../1" }, func(r *releaseEvidenceReq) { r.DeviceID = "00000000-0000-0000-0000-000000000001" }} {
		bad := req
		change(&bad)
		if err := validReleaseEvidence(bad, now); err == nil {
			t.Errorf("accepted %#v", bad)
		}
	}
}

func stableReleaseRequest(t *testing.T, version string) adminRegisterVersionReq {
	t.Helper()
	req := adminRegisterVersionReq{Platform: "macos", Channel: "stable", Version: version, ArtifactURL: "https://cdn.patched.im/stable/" + version, ArtifactSHA256: strings.Repeat("a", 64), ArtifactHMAC: strings.Repeat("b", 64)}
	raw, _ := json.Marshal(map[string]string{"platform": req.Platform, "channel": req.Channel, "version": req.Version, "artifact_url": req.ArtifactURL, "artifact_sha256": req.ArtifactSHA256})
	env, _ := json.Marshal(map[string]string{"signed_payload": base64.StdEncoding.EncodeToString(raw), "signature": base64.StdEncoding.EncodeToString(make([]byte, 64)), "key_id": "aabbccddeeff0011"})
	req.ArtifactMetadataSignature = env
	return req
}

func TestPromotionEnvelopeBinding(t *testing.T) {
	req := stableReleaseRequest(t, "1.2.3")
	if err := validatePromotedArtifact(req); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*adminRegisterVersionReq){func(r *adminRegisterVersionReq) { r.Channel = "beta" }, func(r *adminRegisterVersionReq) { r.ArtifactSHA256 = strings.Repeat("c", 64) }, func(r *adminRegisterVersionReq) { r.ArtifactURL = "https://evil.example/artifact" }, func(r *adminRegisterVersionReq) { r.ArtifactMetadataSignature = nil }, func(r *adminRegisterVersionReq) { r.ArtifactHMAC = "bad" }} {
		bad := req
		change(&bad)
		if err := validatePromotedArtifact(bad); err == nil {
			t.Errorf("accepted changed envelope %#v", bad)
		}
	}
}

func TestReleaseGateAndPromotionDB(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	version := "2004." + suffix
	stable := "2003." + suffix
	tenant := parSeedTenant(t, ctx, pool, "release-test-"+suffix, "release-token-"+suffix, "release-hmac-secret")
	if _, err := pool.Exec(ctx, `UPDATE tenants SET tenant_kind='internal' WHERE id=$1::uuid`, tenant); err != nil {
		t.Fatal(err)
	}
	device := ahtInsertDevice(t, pool, tenant, "00000000-0000-0000-0000-000000002004", "canary")
	now := time.Now().UTC().Truncate(time.Second)
	entered := now.Add(-74 * time.Hour)
	first := now.Add(-73 * time.Hour)
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []struct{ ch, v string }{{"stable", stable}, {"beta", version}} {
		exec(`INSERT INTO agent_versions(platform,channel,version,artifact_url,artifact_sha256,artifact_hmac,published_at) VALUES ('macos',$1,$2,'https://cdn.patched.im/test',$3,$4,$5)`, v.ch, v.v, strings.Repeat("a", 64), strings.Repeat("b", 64), entered.Add(-time.Hour))
		aavtCleanupVersion(t, ctx, pool, "macos", v.ch, v.v)
	}
	exec(`INSERT INTO agent_device_channels(device_id,channel,entered_at,baseline_faults,baseline_health_at,actor) VALUES ($1::uuid,'beta',$2,'[["old","fault"]]',$2,'test')`, device, entered)
	exec(`INSERT INTO agent_release_cohorts(device_id,platform,version,entered_at,baseline_version,baseline_faults,baseline_health_at) VALUES ($1::uuid,'macos',$2,$3,$4,'[["old","fault"]]',$3)`, device, version, entered, stable)
	for i, at := range []time.Time{first, now} {
		exec(`INSERT INTO agent_release_observations(device_id,platform,version,observed_at,received_at,raw_payload_id,health_complete,fault_keys,provenance) VALUES ($1::uuid,'macos',$2,$3,$3,$4,true,'[["old","fault"]]', 'test:' || $4::bigint::text)`, device, version, at, int64(i+1))
	}
	for _, metric := range []string{"artifact_verification", "config_verification", "service_crash", "restart_loop", "enrolment", "upload"} {
		var d any = device
		if metric == "enrolment" || metric == "upload" {
			d = nil
		}
		exec(`INSERT INTO agent_release_evidence(device_id,platform,version,metric,window_start,window_end,attempts,failures,provenance,actor) VALUES ($1::uuid,'macos',$2,$3,$4,$5,100,0,'test-run','test')`, d, version, metric, first, now)
		if d == nil {
			exec(`INSERT INTO agent_release_evidence(platform,version,metric,window_start,window_end,attempts,failures,provenance,actor) VALUES ('macos',$1,$2,$3,$4,100,0,'test-stable','test')`, stable, metric, entered.Add(-73*time.Hour), entered)
		}
	}
	gate := func() releasecontrol.Health {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		h, err := releasecontrol.Gate(ctx, tx, "macos", version, now)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	if h := gate(); !h.Ready {
		t.Fatalf("healthy gate refused %+v", h)
	}
	savedNow := now
	now = first.Add(71 * time.Hour)
	if h := gate(); h.Ready || !strings.Contains(fmt.Sprint(h), "candidate_not_observed_for_72h") {
		t.Fatalf("71h allowed %+v", h)
	}
	now = savedNow
	exec(`UPDATE tenants SET tenant_kind='customer' WHERE id=$1::uuid`, tenant)
	if h := gate(); h.Ready || !strings.Contains(fmt.Sprint(h), "tenant_zero_explicit_beta_missing") {
		t.Fatalf("customer treated as tenant zero %+v", h)
	}
	exec(`UPDATE tenants SET tenant_kind='internal' WHERE id=$1::uuid`, tenant)
	// The audit/evidence ledgers reject mutation, independently of handler policy.
	if _, err := pool.Exec(ctx, `UPDATE agent_release_evidence SET failures=1 WHERE version=$1`, version); err == nil {
		t.Fatal("evidence UPDATE succeeded")
	}
	if _, err := pool.Exec(ctx, `TRUNCATE agent_release_observations`); err == nil {
		t.Fatal("observation TRUNCATE succeeded")
	}
	// An explicit beta device without runtime/evidence must join the gate.
	other := ahtInsertDevice(t, pool, tenant, "00000000-0000-0000-0000-000000002005", "new-canary")
	exec(`INSERT INTO agent_device_channels(device_id,channel,actor) VALUES ($1::uuid,'beta','test')`, other)
	if h := gate(); h.Ready || len(h.Devices) != 2 {
		t.Fatalf("new beta device ignored %+v", h)
	}
	exec(`DELETE FROM agent_device_channels WHERE device_id=$1::uuid`, other)
	req := stableReleaseRequest(t, version)
	raw, _ := json.Marshal(req)
	promote := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		AdminAgentReleasePromoteHandler(pool).ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/admin/agent-releases/promote", strings.NewReader(string(raw))))
		return rr
	}
	rr := promote()
	if rr.Code != 200 {
		t.Fatalf("promote %d %s", rr.Code, rr.Body.String())
	}
	aavtCleanupVersion(t, ctx, pool, "macos", "stable", version)
	if rr = promote(); rr.Code != 200 || !strings.Contains(rr.Body.String(), `"idempotent":true`) {
		t.Fatalf("idempotent %d %s", rr.Code, rr.Body.String())
	}
	var betaExists bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_versions WHERE platform='macos' AND channel='beta' AND version=$1)`, version).Scan(&betaExists); err != nil || !betaExists {
		t.Fatal("beta lost", err)
	}
	// One short failed rate window cannot be hidden by a later clean aggregate.
	exec(`INSERT INTO agent_release_evidence(platform,version,metric,window_start,window_end,attempts,failures,provenance,actor) VALUES ('macos',$1,'upload',$2,$3,10,1,'failed-window','test')`, version, now.Add(-time.Hour), now)
	if h := gate(); h.Ready || !strings.Contains(fmt.Sprint(h), "upload_rate_above_previous_stable") {
		t.Fatalf("rate regression missed %+v", h)
	}
	exec(`INSERT INTO agent_release_observations(device_id,platform,version,observed_at,received_at,raw_payload_id,health_complete,fault_keys,provenance) VALUES ($1::uuid,'macos',$2,$3,$3,99,true,'[["new","fault"]]','test:99')`, device, version, now.Add(time.Second))
	if h := gate(); h.Ready || !strings.Contains(fmt.Sprint(h), "introduced_agent_health_fault") {
		t.Fatalf("introduced fault missed %+v", h)
	}
}

type releaseFakeMail struct {
	calls int
	fail  bool
}

func (s *releaseFakeMail) From() string { return "test@patched.example" }
func (s *releaseFakeMail) Send(_ context.Context, msg graphmail.Message) error {
	s.calls++
	if len(msg.To) != 1 || msg.To[0] != "recipient@example.test" {
		return fmt.Errorf("wrong recipient")
	}
	if s.fail {
		return fmt.Errorf("fake failure")
	}
	return nil
}

func TestP0MailAndProjectionDB(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	tenant := parSeedTenant(t, ctx, pool, "p0-test-"+suffix, "p0-token-"+suffix, "p0-hmac-secret")
	var noticeID int64
	err := pool.QueryRow(ctx, `INSERT INTO agent_release_p0_notices(tenant_id,version,banner,actor,created_at,scheduled_at,email_due_at,email_recipient) VALUES ($1::uuid,'1.2.3','critical notice','test',clock_timestamp()-interval '26 hours',clock_timestamp()-interval '1 hour',clock_timestamp()-interval '26 hours','recipient@example.test') RETURNING id`, tenant).Scan(&noticeID)
	if err != nil {
		t.Fatal(err)
	}
	sender := &releaseFakeMail{}
	var state string
	var attempts int
	for i := 0; i < 100; i++ {
		if err = pool.QueryRow(ctx, `SELECT email_status,email_attempts FROM agent_release_p0_notices WHERE id=$1`, noticeID).Scan(&state, &attempts); err != nil {
			t.Fatal(err)
		}
		if state == "delivered" {
			break
		}
		handled, deliverErr := releasecontrol.DeliverNotice(ctx, pool, sender)
		if deliverErr != nil || !handled {
			t.Fatalf("delivery handled=%v err=%v", handled, deliverErr)
		}
	}
	if state != "delivered" || attempts != 1 {
		t.Fatal("target notice was not delivered exactly once", state, attempts)
	}
	_, err = releasecontrol.DeliverNotice(ctx, pool, sender)
	if err != nil {
		t.Fatal("second delivery pass", err)
	}
	// The worker is global, so a shared test database may contain another due
	// notice and legitimately report handled=true above. Prove idempotency on
	// this notice directly instead of assuming the whole queue is empty.
	if err = pool.QueryRow(ctx, `SELECT email_status,email_attempts FROM agent_release_p0_notices WHERE id=$1`, noticeID).Scan(&state, &attempts); err != nil || state != "delivered" || attempts != 1 {
		t.Fatal(state, attempts, err)
	}
	var failedID int64
	err = pool.QueryRow(ctx, `INSERT INTO agent_release_p0_notices(tenant_id,version,banner,actor,scheduled_at,email_recipient) VALUES ($1::uuid,'1.2.4','next notice','test',clock_timestamp()+interval '25 hours','recipient@example.test') RETURNING id`, tenant).Scan(&failedID)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		if err = pool.QueryRow(ctx, `SELECT email_status FROM agent_release_p0_notices WHERE id=$1`, failedID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state == "failed" {
			break
		}
		handled, deliverErr := releasecontrol.DeliverNotice(ctx, pool, nil)
		if deliverErr != nil || !handled {
			t.Fatalf("missing transport handled=%v err=%v", handled, deliverErr)
		}
	}
	if err = pool.QueryRow(ctx, `SELECT email_status FROM agent_release_p0_notices WHERE id=$1`, failedID).Scan(&state); err != nil || state != "failed" {
		t.Fatal("missing transport falsely succeeded", state, err)
	}
	body := agentconfig.DefaultConfigBody()
	body.UpdateChannel = "beta"
	body.UpdateChannelSource = "tenant"
	pin := "1.0.0"
	body.PinnedVersion = &pin
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if err = releasecontrol.Project(ctx, tx, tenant, "", &body); err != nil {
		t.Fatal(err)
	}
	if body.UpdateChannel != "stable" || body.UpdateChannelSource != "" || body.PinnedVersion == nil || *body.PinnedVersion != "1.2.3" {
		t.Fatalf("P0 not authoritative %+v", body)
	}
	body.UpdateChannel = "stable"
	higher := "1.3.0"
	body.PinnedVersion = &higher
	if err = releasecontrol.Project(ctx, tx, tenant, "", &body); err != nil {
		t.Fatal(err)
	}
	if body.PinnedVersion == nil || *body.PinnedVersion != "1.3.0" {
		t.Fatal("P0 became a ceiling", body.PinnedVersion)
	}
	body.PinnedVersion = nil
	if err = releasecontrol.Project(ctx, tx, tenant, "", &body); err != nil {
		t.Fatal(err)
	}
	if body.PinnedVersion == nil || *body.PinnedVersion != "1.2.3" {
		t.Fatal("clear pin bypassed P0 floor", body.PinnedVersion)
	}
	opaque := "release-unknown"
	body.PinnedVersion = &opaque
	if err = releasecontrol.Project(ctx, tx, tenant, "", &body); err == nil {
		t.Fatal("unordered version passed security floor")
	}
}

func TestReleaseProbeAndEvidenceDB(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	tenant := parSeedTenant(t, ctx, pool, "probe-test-"+suffix, "probe-token-"+suffix, "probe-hmac-secret")
	device := ahtInsertDevice(t, pool, tenant, "00000000-0000-0000-0000-000000002007", "probe-device")
	stable := "2003." + suffix
	beta := "2004." + suffix
	for _, v := range []struct{ ch, v string }{{"stable", stable}, {"beta", beta}} {
		if _, err := pool.Exec(ctx, `INSERT INTO agent_versions(platform,channel,version,artifact_url,artifact_sha256,artifact_hmac) VALUES ('macos-menubar',$1,$2,'https://cdn.patched.im/test','test-sha','test-hmac')`, v.ch, v.v); err != nil {
			t.Fatal(err)
		}
		aavtCleanupVersion(t, ctx, pool, "macos-menubar", v.ch, v.v)
	}
	complete := true
	probe := releaseProbeReq{DeviceID: device, Platform: "macos-menubar", Version: stable, ObservedAt: time.Now().UTC().Truncate(time.Microsecond), HealthComplete: &complete, FaultKeys: [][]string{{"old", "fault"}}, Provenance: "probe-stable"}
	postProbe := func(req releaseProbeReq) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(req)
		rr := httptest.NewRecorder()
		AdminAgentReleaseObservationHandler(pool).ServeHTTP(rr, httptest.NewRequest("POST", "/admin/agent-releases/observations", bytes.NewReader(raw)))
		return rr
	}
	if rr := postProbe(probe); rr.Code != 200 {
		t.Fatalf("stable probe %d %s", rr.Code, rr.Body.String())
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_device_channels(device_id,channel,actor) VALUES ($1::uuid,'beta','test')`, device); err != nil {
		t.Fatal(err)
	}
	probe.Version = beta
	probe.ObservedAt = time.Now().UTC().Truncate(time.Microsecond)
	probe.Provenance = "probe-beta"
	if rr := postProbe(probe); rr.Code != 200 {
		t.Fatalf("beta probe %d %s", rr.Code, rr.Body.String())
	}
	if rr := postProbe(probe); rr.Code != 200 {
		t.Fatalf("idempotent probe %d %s", rr.Code, rr.Body.String())
	}
	var count int
	var baseVersion string
	var baseFaults []byte
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_release_observations WHERE device_id=$1::uuid`, device).Scan(&count); err != nil || count != 2 {
		t.Fatal("probe replay duplicated", count, err)
	}
	if err := pool.QueryRow(ctx, `SELECT baseline_version,baseline_faults FROM agent_release_cohorts WHERE device_id=$1::uuid AND platform='macos-menubar' AND version=$2`, device, beta).Scan(&baseVersion, &baseFaults); err != nil || baseVersion != stable || !strings.Contains(string(baseFaults), "old") {
		t.Fatal("menu baseline missing", baseVersion, string(baseFaults), err)
	}
	probe.FaultKeys = [][]string{{"new", "fault"}}
	if rr := postProbe(probe); rr.Code != 409 {
		t.Fatalf("conflicting probe accepted %d %s", rr.Code, rr.Body.String())
	}
	probe.Provenance = "stale"
	probe.ObservedAt = time.Now().Add(-time.Hour)
	if rr := postProbe(probe); rr.Code != 400 {
		t.Fatalf("stale probe %d", rr.Code)
	}
	probe.ObservedAt = time.Now()
	probe.FaultKeys = [][]string{{"a", "b", "c"}}
	if rr := postProbe(probe); rr.Code != 400 {
		t.Fatalf("oversized pair %d", rr.Code)
	}
	probe.FaultKeys = [][]string{}
	probe.Platform = "macos"
	if rr := postProbe(probe); rr.Code != 400 {
		t.Fatalf("probe overwrote daemon authority %d", rr.Code)
	}
	evidence := releaseEvidenceReq{Platform: "macos-menubar", Version: beta, Metric: "enrolment", WindowStart: time.Now().Add(-73 * time.Hour), WindowEnd: time.Now(), Attempts: 100, Failures: 0, Provenance: "aggregate-monitor"}
	postEvidence := func(req releaseEvidenceReq) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(req)
		rr := httptest.NewRecorder()
		AdminAgentReleaseEvidenceHandler(pool).ServeHTTP(rr, httptest.NewRequest("POST", "/admin/agent-releases/evidence", bytes.NewReader(raw)))
		return rr
	}
	if rr := postEvidence(evidence); rr.Code != 200 {
		t.Fatalf("evidence %d %s", rr.Code, rr.Body.String())
	}
	if rr := postEvidence(evidence); rr.Code != 200 {
		t.Fatalf("evidence replay %d %s", rr.Code, rr.Body.String())
	}
	evidence.Failures = 1
	if rr := postEvidence(evidence); rr.Code != 409 {
		t.Fatalf("changed evidence accepted %d %s", rr.Code, rr.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_release_evidence WHERE platform='macos-menubar' AND version=$1`, beta).Scan(&count); err != nil || count != 1 {
		t.Fatal("aggregate replay duplicated", count, err)
	}
	// Version evidence is channel-independent so previous stable baselines can
	// be supplied. It never supplies the missing beta publication authority.
	evidence.Version = stable
	evidence.Failures = 0
	evidence.Provenance = "stable-monitor"
	if rr := postEvidence(evidence); rr.Code != 200 {
		t.Fatalf("stable baseline evidence %d %s", rr.Code, rr.Body.String())
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	h, err := releasecontrol.Gate(ctx, tx, "macos-menubar", stable, time.Now())
	if err != nil || h.Ready || !strings.Contains(fmt.Sprint(h.Reasons), "beta_candidate_missing") {
		t.Fatalf("stable evidence bypassed beta publication %+v %v", h, err)
	}
}

func TestBetaOverrideRetainsPinCeilingDB(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	tenant := parSeedTenant(t, ctx, pool, "beta-ceiling-"+suffix, "beta-ceiling-token-"+suffix, "beta-ceiling-hmac")
	device := ahtInsertDevice(t, pool, tenant, "00000000-0000-0000-0000-000000002009", "beta-ceiling")
	inheritedDevice := ahtInsertDevice(t, pool, tenant, "00000000-0000-0000-0000-000000002010", "tenant-channel")
	if _, err := pool.Exec(ctx, `INSERT INTO agent_release_settings(tenant_id,hold,pinned_version) VALUES ($1::uuid,true,'1.2.3')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_device_channels(device_id,channel,actor) VALUES ($1::uuid,'beta','test')`, device); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_device_channels SET channel='stable' WHERE device_id=$1::uuid`, device); err == nil {
		t.Fatal("schema accepted stable override")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for _, scope := range []string{device, ""} {
		body := agentconfig.DefaultConfigBody()
		if err = releasecontrol.Project(ctx, tx, tenant, scope, &body); err != nil {
			t.Fatal(err)
		}
		if body.PinnedVersion == nil || *body.PinnedVersion != "1.2.3" {
			t.Fatal("beta bypassed tenant pin ceiling", body.PinnedVersion)
		}
		if scope == device && body.UpdateChannel != "beta" {
			t.Fatal("device beta missing")
		}
		if scope == device && body.UpdateChannelSource != "device_override" {
			t.Fatalf("device source %q", body.UpdateChannelSource)
		}
		if scope == "" && body.DeviceChannelOverrides[device] != "beta" {
			t.Fatal("tenant signed map missing beta")
		}
		if scope == "" && body.UpdateChannelSource != "" {
			t.Fatalf("tenant-wide source fabricated: %q", body.UpdateChannelSource)
		}
	}
	inherited := agentconfig.DefaultConfigBody()
	if err = releasecontrol.Project(ctx, tx, tenant, inheritedDevice, &inherited); err != nil {
		t.Fatal(err)
	}
	if inherited.UpdateChannelSource != "tenant" {
		t.Fatalf("inherited channel source %q", inherited.UpdateChannelSource)
	}
}

func TestReleaseLockScopeDB(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	first, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Rollback(ctx)
	second, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Rollback(ctx)
	if err = releasecontrol.SharedLock(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err = releasecontrol.SharedLock(ctx, second); err != nil {
		t.Fatal(err)
	}
	var acquired bool
	if err = pool.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(2004,1)`).Scan(&acquired); err != nil || acquired {
		t.Fatal("promotion raced shared participants", acquired, err)
	}
	if err = releasecontrol.TenantLock(ctx, first, "tenant-a"); err != nil {
		t.Fatal(err)
	}
	if err = second.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, "tenant-a|agent-releases").Scan(&acquired); err != nil || acquired {
		t.Fatal("same tenant was not serialized", acquired, err)
	}
	if err = releasecontrol.TenantLock(ctx, second, "tenant-b"); err != nil {
		t.Fatal(err)
	}
	if err = first.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = second.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(2004,1)`).Scan(&acquired); err != nil || !acquired {
		t.Fatal("promotion lock not released", acquired, err)
	}
}

func TestReleaseGateDailyCadenceBoundaryDB(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	for i, tc := range []struct {
		name, reason                                 string
		observationExtra, healthExtra, baselineExtra time.Duration
	}{
		{name: "inclusive-boundary"},
		{name: "stale-observation", observationExtra: time.Microsecond, reason: "candidate_observation_missing_or_stale"},
		{name: "stale-health", healthExtra: time.Microsecond, reason: "pre_beta_health_baseline_missing_or_stale"},
		{name: "stale-rate-baseline", baselineExtra: time.Microsecond, reason: "upload_previous_stable_baseline_missing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			suffix := fmt.Sprint(time.Now().UnixNano())
			version, stable := "2004."+suffix, "2003."+suffix
			tenant := parSeedTenant(t, ctx, pool, "cadence-"+suffix, "cadence-token-"+suffix, "cadence-hmac")
			device := ahtInsertDevice(t, pool, tenant, fmt.Sprintf("00000000-0000-0000-0000-%012d", 2030+i), "cadence-canary")
			now := time.Now().UTC().Truncate(time.Microsecond)
			entered, first := now.Add(-101*time.Hour), now.Add(-100*time.Hour)
			last := now.Add(-releasecontrol.InventoryCadenceTolerance - tc.observationExtra)
			health := entered.Add(-releasecontrol.InventoryCadenceTolerance - tc.healthExtra)
			baselineEnd := entered.Add(-releasecontrol.InventoryCadenceTolerance - tc.baselineExtra)
			exec := func(sql string, args ...any) {
				t.Helper()
				if _, err := pool.Exec(ctx, sql, args...); err != nil {
					t.Fatal(err)
				}
			}
			exec(`UPDATE tenants SET tenant_kind='internal' WHERE id=$1::uuid`, tenant)
			for _, v := range []struct{ channel, version string }{{"stable", stable}, {"beta", version}} {
				exec(`INSERT INTO agent_versions(platform,channel,version,artifact_url,artifact_sha256,artifact_hmac,published_at) VALUES ('macos',$1,$2,'https://cdn.patched.im/test','test-sha','test-hmac',$3)`, v.channel, v.version, entered.Add(-time.Hour))
				aavtCleanupVersion(t, ctx, pool, "macos", v.channel, v.version)
			}
			exec(`INSERT INTO agent_device_channels(device_id,channel,entered_at,baseline_health_at,actor) VALUES ($1::uuid,'beta',$2,$3,'test')`, device, entered, health)
			exec(`INSERT INTO agent_release_cohorts(device_id,platform,version,entered_at,baseline_version,baseline_faults,baseline_health_at) VALUES ($1::uuid,'macos',$2,$3,$4,'[]',$5)`, device, version, entered, stable, health)
			for j, at := range []time.Time{first, last} {
				exec(`INSERT INTO agent_release_observations(device_id,platform,version,observed_at,received_at,raw_payload_id,health_complete,fault_keys,provenance) VALUES ($1::uuid,'macos',$2,$3,$3,$4,true,'[]','cadence:' || $4::bigint::text)`, device, version, at, int64(2030+j))
			}
			for _, metric := range []string{"artifact_verification", "config_verification", "service_crash", "restart_loop", "enrolment", "upload"} {
				var d any = device
				if metric == "enrolment" || metric == "upload" {
					d = nil
				}
				exec(`INSERT INTO agent_release_evidence(device_id,platform,version,metric,window_start,window_end,attempts,failures,provenance,actor) VALUES ($1::uuid,'macos',$2,$3,$4,$5,100,0,'cadence-monitor','test')`, d, version, metric, first, now)
				if d == nil {
					exec(`INSERT INTO agent_release_evidence(platform,version,metric,window_start,window_end,attempts,failures,provenance,actor) VALUES ('macos',$1,$2,$3,$4,100,0,'cadence-baseline','test')`, stable, metric, baselineEnd.Add(-72*time.Hour), baselineEnd)
				}
			}
			tx, err := pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback(ctx)
			h, err := releasecontrol.Gate(ctx, tx, "macos", version, now)
			if err != nil {
				t.Fatal(err)
			}
			if tc.reason == "" {
				if !h.Ready {
					t.Fatalf("daily cadence refused %+v", h)
				}
			} else if h.Ready || !strings.Contains(fmt.Sprint(h), tc.reason) {
				t.Fatalf("cadence boundary not enforced %+v", h)
			}
		})
	}
}

func TestAllDueP0NoticesActivateWithOneGenerationDB(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	tenant := parSeedTenant(t, ctx, pool, "activation-"+suffix, "activation-token-"+suffix, "activation-hmac")
	for _, v := range []string{"1.2.3", "1.2.4"} {
		if _, err := pool.Exec(ctx, `INSERT INTO agent_release_p0_notices(tenant_id,version,banner,actor,created_at,scheduled_at,email_due_at,email_recipient) VALUES ($1::uuid,$2,'critical notice','test',clock_timestamp()-interval '26 hours',clock_timestamp()-interval '1 hour',clock_timestamp()-interval '26 hours','recipient@example.test')`, tenant, v); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	before, err := bumpAgentConfigVersionForDecommission(ctx, tx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	row := agentConfigRow{Body: agentconfig.DefaultConfigBody()}
	if err = projectAgentReleaseConfig(ctx, pool, tenant, "", &row); err != nil {
		t.Fatal(err)
	}
	if row.ConfigVersion != before+1 {
		t.Fatalf("generation %d want %d", row.ConfigVersion, before+1)
	}
	var count int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM agent_release_p0_activations WHERE tenant_id=$1::uuid`, tenant).Scan(&count); err != nil || count != 2 {
		t.Fatal("activation provenance", count, err)
	}
	if err = projectAgentReleaseConfig(ctx, pool, tenant, "", &row); err != nil {
		t.Fatal(err)
	}
	if row.ConfigVersion != before+1 {
		t.Fatal("repeat activation bumped generation", row.ConfigVersion)
	}
}

func TestReleaseInventoryObservationDB(t *testing.T) {
	pool := parConnectOrSkip(t)
	t.Cleanup(pool.Close)
	ctx := context.Background()
	suffix := fmt.Sprint(time.Now().UnixNano())
	version := "2004." + suffix
	tenant := parSeedTenant(t, ctx, pool, "inventory-release-"+suffix, "inventory-release-token-"+suffix, "inventory-release-hmac")
	device := ahtInsertDevice(t, pool, tenant, "00000000-0000-0000-0000-000000002008", "inventory-canary")
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := pool.Exec(ctx, `INSERT INTO agent_versions(platform,channel,version,artifact_url,artifact_sha256,artifact_hmac) VALUES ('macos','beta',$1,'https://cdn.patched.im/test','test-sha','test-hmac')`, version); err != nil {
		t.Fatal(err)
	}
	aavtCleanupVersion(t, ctx, pool, "macos", "beta", version)
	if _, err := pool.Exec(ctx, `INSERT INTO device_agent_health_watermark(device_id,collected_at) VALUES ($1::uuid,$2)`, device, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO agent_device_channels(device_id,channel,baseline_health_at,actor) VALUES ($1::uuid,'beta',$2,'test')`, device, now); err != nil {
		t.Fatal(err)
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	for i := 0; i < 2; i++ {
		if err = releasecontrol.Observe(ctx, tx, tenant, device, "macos", version, 4242, now, now, true); err != nil {
			t.Fatal(err)
		}
	}
	if err = releasecontrol.Observe(ctx, tx, tenant, device, "macos", version, 4243, now, now.Add(-time.Hour), true); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	var count int
	var complete bool
	if err = pool.QueryRow(ctx, `SELECT count(*),bool_and(health_complete) FROM agent_release_observations WHERE device_id=$1::uuid AND source='inventory'`, device).Scan(&count, &complete); err != nil || count != 1 || !complete {
		t.Fatal("inventory replay/staleness/health", count, complete, err)
	}
}
