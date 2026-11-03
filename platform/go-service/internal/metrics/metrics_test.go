package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestRegisterExtractorExposesExtractorMetrics guards the PAT-1377 fix
// end-to-end: register the extractor's collectors the same way
// cmd/patched-extractor/main.go does, confirm every "result" label is
// already materialized at zero straight out of registration (so
// DeadLetterRows can match a series from process start, not only after the
// first dead-letter row), then observe them the same way internal/extractor
// does and confirm they actually appear on an HTTP /metrics handler. Before
// PAT-1377 these collectors were registered in patched-api's process (which
// never observed them) while being observed in patched-extractor's process
// (which never registered or served them) — so neither promtool nor a
// registration-only check would have caught the gap; only the full
// register-observe-serve path proves the metric can reach Prometheus at all.
func TestRegisterExtractorExposesExtractorMetrics(t *testing.T) {
	RegisterExtractor()

	// PAT-1377: RegisterExtractor pre-materializes every "result" label so
	// DeadLetterRows (and any other alert rule keyed on a specific result)
	// can match a real, zero-valued series from process start rather than
	// only after the first occurrence of that result — a CounterVec has no
	// series for a label combination until .WithLabelValues has been called
	// for it at least once. Assert this immediately after RegisterExtractor,
	// before the Inc()/Observe() calls below mutate any of these — and
	// before a second call elsewhere in this package could double-register
	// the global collectors and panic, this is the only place that checks it.
	for _, result := range []string{"success", "error", "dead_letter"} {
		if got := testutil.ToFloat64(ExtractorRowsProcessed.WithLabelValues(result)); got != 0 {
			t.Errorf("result=%q: got %v immediately after RegisterExtractor, want 0", result, got)
		}
	}

	ExtractorBatchSize.Observe(7)
	ExtractorRowsProcessed.WithLabelValues("dead_letter").Inc()
	// PAT-2024: the CVE match queue gauges must reach the extractor's own
	// /metrics, or CVEMatchQueueBacklog can never match a series.
	CVEMatchQueueDepth.Set(3)
	CVEMatchQueueOldestAge.Set(1801)
	CVEMatchQueueRefreshed.Set(1700000000)
	// PAT-2030: the per-tenant backlog gauges are served by the same process.
	CVEMatchQueueTenantDepth.WithLabelValues("tenant-a").Set(42)
	CVEMatchQueueTenantOldestAge.WithLabelValues("tenant-a").Set(90)
	CVEMatchQueueTenantDropped.WithLabelValues("tenant-a").Add(2)

	srv := httptest.NewServer(promhttp.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	for _, want := range []string{
		`patched_extractor_batch_size_count 1`,
		`patched_extractor_rows_processed_total{result="dead_letter"} 1`,
		`patched_cve_match_queue_depth 3`,
		`patched_cve_match_queue_oldest_age_seconds 1801`,
		`patched_cve_match_queue_refreshed_timestamp_seconds 1.7e+09`,
		`patched_cve_match_queue_stuck 0`,
		`patched_cve_match_queue_dropped_total 0`,
		`patched_cve_match_queue_tenant_dropped_total{tenant_id="tenant-a"} 2`,
		`patched_cve_match_queue_tenant_depth{tenant_id="tenant-a"} 42`,
		`patched_cve_match_queue_tenant_oldest_age_seconds{tenant_id="tenant-a"} 90`,
		`patched_cve_match_observations_total{result="error"} 0`,
		`patched_cve_match_observations_total{result="matched"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics output missing %q\nfull output:\n%s", want, out)
		}
	}
}

// TestRegisterPreMaterializesDeviceCredentialRequiredHandlers guards the
// PAT-1417 counterpart of the PAT-1377 fix above: Register() must
// pre-materialize a zero series for every "handler" label
// DeviceCredentialRequiredTotal can take, so an alert rule keyed on this
// counter can match a real series from process start rather than only after
// the first rejection — otherwise the alert would be structurally unable to
// fire until the very event it exists to catch had already happened once,
// exactly the class of bug PAT-1389's selector-liveness checker exists to
// catch. Assert this immediately after Register(), before any Inc() call
// below could be mistaken for the pre-materialized state.
func TestRegisterPreMaterializesDeviceCredentialRequiredHandlers(t *testing.T) {
	Register()

	// Collect the vec's ACTUAL children via Collect(), never via
	// WithLabelValues/ToFloat64 — WithLabelValues creates a label's child on
	// demand if it doesn't already exist, so asserting through it here would
	// materialize the very series this test exists to confirm Register()
	// already materialized, making the assertion trivially true whether or
	// not Register()'s pre-materialization loop ever ran. CollectAndCompare
	// only enumerates children that already exist, so this is honest.
	wantVec := `
		# HELP patched_device_credential_required_total Total requests rejected because the matched credential is tenant-level but the endpoint requires a device-scoped credential, by handler.
		# TYPE patched_device_credential_required_total counter
		patched_device_credential_required_total{handler="agent_decommission_status"} 0
		patched_device_credential_required_total{handler="agent_logs_ingest"} 0
		patched_device_credential_required_total{handler="enforcement_audit_ingest"} 0
		patched_device_credential_required_total{handler="removal_tasks_pending"} 0
		patched_device_credential_required_total{handler="removal_tasks_report"} 0
		patched_device_credential_required_total{handler="posture"} 0
		patched_device_credential_required_total{handler="device_identity"} 0
	`
	if err := testutil.CollectAndCompare(DeviceCredentialRequiredTotal, strings.NewReader(wantVec), "patched_device_credential_required_total"); err != nil {
		t.Errorf("collected state immediately after Register() does not match pre-materialized expectation:\n%v", err)
	}

	DeviceCredentialRequiredTotal.WithLabelValues("enforcement_audit_ingest").Inc()

	srv := httptest.NewServer(promhttp.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := string(body)

	for _, want := range []string{
		`patched_device_credential_required_total{handler="enforcement_audit_ingest"} 1`,
		`patched_device_credential_required_total{handler="agent_logs_ingest"} 0`,
		`patched_device_credential_required_total{handler="agent_decommission_status"} 0`,
		`patched_device_credential_required_total{handler="removal_tasks_pending"} 0`,
		`patched_device_credential_required_total{handler="removal_tasks_report"} 0`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("/metrics output missing %q\nfull output:\n%s", want, out)
		}
	}
}
