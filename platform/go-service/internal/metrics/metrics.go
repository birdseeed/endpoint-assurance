// Package metrics centralises Prometheus metric definitions for patched-api.
// Call Register() once at startup; all metrics are exported from this package
// so instrumentation sites import only this package (not prometheus directly).
package metrics

import "github.com/prometheus/client_golang/prometheus"

var (
	// HTTPRequestsTotal counts every HTTP request handled by either server,
	// labelled by the chi route pattern (e.g. "/admin/tenant-rules/{tenantID}")
	// and the numeric status code.
	HTTPRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patched_http_requests_total",
			Help: "Total HTTP requests by route pattern and status code.",
		},
		[]string{"route", "status"},
	)

	// HTTPRequestDuration tracks latency per route pattern + status code.
	// Default buckets cover 1ms–10s, appropriate for ingestion + PDF paths.
	HTTPRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "patched_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds by route pattern and status code.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"route", "status"},
	)

	// ExtractorRowsProcessed counts raw_payload rows the extractor processes,
	// labelled by result: "success" | "error" | "dead_letter". "dead_letter"
	// fires alongside "error" on the specific failed attempt that exhausts
	// extraction_attempts (PAT-1377): it is a rate signal (rows newly
	// hitting dead-letter), distinct from the standing-backlog gauge
	// patched_db_dead_letter_rows.
	ExtractorRowsProcessed = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patched_extractor_rows_processed_total",
			Help: "Total raw_payloads rows processed by the extractor, by result.",
		},
		[]string{"result"},
	)

	// ExtractorBatchSize records how many rows are claimed per poll cycle.
	ExtractorBatchSize = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "patched_extractor_batch_size",
			Help:    "Number of raw_payloads rows claimed per extractor poll cycle.",
			Buckets: []float64{1, 2, 5, 10, 20, 50},
		},
	)

	// PAT-2024: event-driven CVE matching queue, drained by the extractor.
	// Depth and oldest-item age back the CVEMatchQueueBacklog alert (a
	// backlog older than 30 minutes). Stuck rows (retries exhausted) are
	// included in depth and age on purpose so they keep the alert firing.
	CVEMatchQueueDepth = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "patched_cve_match_queue_depth",
		Help: "Rows currently in cve_match_queue (observation and mapping jobs, including stuck rows).",
	})
	CVEMatchQueueStuck = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "patched_cve_match_queue_stuck",
		Help: "cve_match_queue rows whose retries are exhausted and are no longer claimed.",
	})
	CVEMatchQueueOldestAge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "patched_cve_match_queue_oldest_age_seconds",
		Help: "Age in seconds of the oldest cve_match_queue row; 0 when the queue is empty.",
	})
	// CVEMatchQueueRefreshed is the unix time the gauges above were last read
	// from the database. A stale value means the depth/age gauges are stale
	// too, so the backlog alert cannot be trusted to fire.
	CVEMatchQueueRefreshed = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "patched_cve_match_queue_refreshed_timestamp_seconds",
		Help: "Unix time the CVE match queue gauges were last refreshed from the database.",
	})
	CVEMatchQueueDropped = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "patched_cve_match_queue_dropped_total",
		Help: "CVE match requests refused because cve_match_queue was at capacity.",
	})
	// CVEMatchQueueTenantDropped attributes cap refusals to the tenant whose
	// observation could not enter the queue. tenant_id is the sole label: it
	// identifies the bounded tenancy dimension without exposing device or
	// product input as unbounded metric cardinality.
	CVEMatchQueueTenantDropped = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "patched_cve_match_queue_tenant_dropped_total",
		Help: "CVE match observations refused for one tenant because its queue share or the global queue was full; the global dropped counter aggregates all tenants.",
	}, []string{"tenant_id"})
	// PAT-2030: the same backlog per tenant, so one tenant filling its share
	// of the queue is visible. Observation rows only (mapping jobs have no
	// tenant until expanded); stuck rows included, as in the global gauges.
	// A tenant's series is removed once it has no rows queued, so label
	// cardinality is bounded by the tenants with a live backlog.
	CVEMatchQueueTenantDepth = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "patched_cve_match_queue_tenant_depth",
		Help: "Observation rows currently in cve_match_queue for one tenant, including stuck rows.",
	}, []string{"tenant_id"})
	CVEMatchQueueTenantOldestAge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "patched_cve_match_queue_tenant_oldest_age_seconds",
		Help: "Age in seconds of one tenant's oldest cve_match_queue observation row.",
	}, []string{"tenant_id"})
	CVEMatchObservations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "patched_cve_match_observations_total",
		Help: "(device, product) observations re-matched from the CVE match queue, by result.",
	}, []string{"result"})

	// PAT-2138: automatic CPE mapping proposals (internal/cpepropose),
	// exposed by the extractor, which runs the proposer.
	CPEProposals = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "patched_cpe_proposals_total",
		Help: "CPE mapping proposals processed by the proposer, by outcome (auto_published, needs_review, superseded, retry, error).",
	}, []string{"outcome"})
	CPEProposalsAwaitingReview = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "patched_cpe_proposals_awaiting_review",
		Help: "CPE mapping proposals in needs_review, waiting for staff.",
	})
	CPEProposerDegraded = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "patched_cpe_proposer_degraded",
		Help: "1 when the last proposer run was degraded for the labelled reason (model_unavailable: no Anthropic key or the API failed, every proposal goes to staff review; nvd_unavailable: the CPE dictionary search failed).",
	}, []string{"reason"})

	// DeviceCredentialRequiredTotal counts requests rejected because the
	// bearer token matched a live tenant_credentials row that is tenant-level
	// (device_id IS NULL), on an endpoint that requires a device-scoped
	// credential (auth.ErrDeviceCredentialRequired; PAT-1417). Labelled by
	// handler so each of the affected agent endpoints has its own series.
	// Unknown, malformed, expired and revoked tokens never increment it:
	// handlers increment only after LookupDeviceByBearer has found a live
	// tenant-level credential row and returned ErrDeviceCredentialRequired.
	// This is server-side-only detail: the HTTP response for this case is an
	// unchanged, generic 401, identical to a genuinely unknown token.
	DeviceCredentialRequiredTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patched_device_credential_required_total",
			Help: "Total requests rejected because the matched credential is tenant-level but the endpoint requires a device-scoped credential, by handler.",
		},
		[]string{"handler"},
	)

	// MCPPrivacyGuardRejectionsTotal counts POST /v1/inventory payloads
	// rejected because an mcp_servers server entry carried a field outside
	// the PAT-2020 allowlist (env, args, headers, a URL, a command...) or an
	// allowlisted field that was not in its reduced form (PAT-2021). Any
	// increase means an agent regression may be trying to send secrets: the
	// payload was refused before storage, and McpPrivacyGuardRejected pages.
	// A plain Counter, so the series exists at zero from process start.
	MCPPrivacyGuardRejectionsTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "patched_mcp_privacy_guard_rejections_total",
		Help: "Inventory payloads rejected by the mcp_servers privacy guard (fields outside the allowlist or unreduced values).",
	})

	// BrowserExtensionStatusWithheldTotal counts browser_extensions_status
	// blocks the extractor stored with their absence authority withheld
	// because they were structurally valid but inconsistent, with themselves
	// or with the browser_extensions rows (PAT-2055). The payload is still
	// ingested; nothing is concluded from the block. A steady increase means
	// an agent is sending a status it cannot back, for example a user name
	// whose case differs from its rows' user_account. The reason is in the
	// extractor log and browser_extension_device_state.authority_withheld.
	// Extractor process; a plain Counter, so the series exists at zero.
	BrowserExtensionStatusWithheldTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "patched_browser_extension_status_withheld_total",
		Help: "browser_extensions_status blocks stored without absence authority because they were inconsistent.",
	})

	// AppsPruneWithheldTotal counts inventory reports whose apps array the
	// extractor did not treat as evidence that an unreported application is
	// gone (PAT-2063): the device_apps prune was skipped and the application
	// absence scopes withheld. The sent apps are still upserted. reason is
	// one of AppsPruneWithheldReasons: "partial" or "unavailable" (the agent
	// said so in collection_status.apps), "inconsistent" (the status
	// contradicted the array) or "safety_valve" (an agent that sends no
	// status reported a list that would have removed too much at once). A
	// steady safety_valve count on one device means its collector is
	// returning a short list; the device id is in the extractor log.
	// Extractor process.
	AppsPruneWithheldTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "patched_apps_prune_withheld_total",
			Help: "Inventory reports whose apps array was not trusted to prove removals, by reason.",
		},
		[]string{"reason"},
	)
)

// AppsPruneWithheldReasons is the closed label set of AppsPruneWithheldTotal,
// pre-materialised at zero in RegisterExtractor.
var AppsPruneWithheldReasons = []string{"partial", "unavailable", "inconsistent", "safety_valve"}

// deviceCredentialRequiredHandlers is the closed set of "handler" label
// values DeviceCredentialRequiredTotal can ever take, one per endpoint that
// calls auth.LookupDeviceByBearer (PAT-1417). Kept here, next to the metric,
// so the pre-materialized set in Register() and any future addition stay in
// one place. Each value must match the "handler" attribute the same handler
// already sets on its slog logger.
var deviceCredentialRequiredHandlers = []string{
	"enforcement_audit_ingest",
	"agent_logs_ingest",
	"agent_decommission_status",
	"removal_tasks_pending",
	"removal_tasks_report",
	"posture",
	"device_identity",
}

// Register adds patched-api's own metrics (HTTP request instrumentation) to
// the default Prometheus registry. Call once at startup in cmd/patched-api.
//
// PAT-1377: this used to also register ExtractorRowsProcessed and
// ExtractorBatchSize, which looked reasonable since they're defined in this
// shared package, but was silently wrong. Those two are only ever
// Observe()/Inc()'d inside extractor.Worker.Run, which runs exclusively in
// the separate patched-extractor process. Registering them here gave
// patched-api's own :8081 /metrics a permanently-zero copy of both series
// (registered, scraped, but never incremented in this process), while the
// process that actually does the work never registered or served anything.
// promtool and Prometheus's own health checks can't see that gap: the
// series existed, just never moved, which is exactly how ExtractorStalled
// and DeadLetterRows read "healthy" for as long as they'd been shipped.
// See RegisterExtractor below for where these now live.
func Register() {
	prometheus.MustRegister(
		HTTPRequestsTotal,
		HTTPRequestDuration,
		DeviceCredentialRequiredTotal,
		MCPPrivacyGuardRejectionsTotal,
	)
	// Pre-materialize every handler label so an alert rule keyed on this
	// counter can match a real, zero-valued series from process start rather
	// than only after the first rejection — otherwise the alert is
	// structurally unable to fire until the very event it exists to catch
	// has already happened once (PAT-1417, same fix shape as PAT-1377's
	// ExtractorRowsProcessed pre-materialization below). Only the handlers
	// that actually call auth.LookupDeviceByBearer get a series; a
	// speculative or wildcard label would recreate the mirror-image bug of a
	// series that never moves because nothing can ever increment it.
	for _, handler := range deviceCredentialRequiredHandlers {
		DeviceCredentialRequiredTotal.WithLabelValues(handler).Add(0)
	}
}

// RegisterExtractor adds patched-extractor's own metrics (ExtractorRowsProcessed,
// ExtractorBatchSize) to the default Prometheus registry. Call once at
// startup in cmd/patched-extractor, separate from Register() because
// patched-api and patched-extractor are different OS processes with
// independent in-memory registries; instrumentation observed in the
// extractor loop must be registered, and served over HTTP, in that same
// process or it never reaches Prometheus at all (PAT-1377).
func RegisterExtractor() {
	prometheus.MustRegister(
		ExtractorRowsProcessed,
		ExtractorBatchSize,
		CVEMatchQueueDepth,
		CVEMatchQueueStuck,
		CVEMatchQueueOldestAge,
		CVEMatchQueueRefreshed,
		CVEMatchQueueDropped,
		CVEMatchQueueTenantDropped,
		CVEMatchQueueTenantDepth,
		CVEMatchQueueTenantOldestAge,
		CVEMatchObservations,
		CPEProposals,
		CPEProposalsAwaitingReview,
		CPEProposerDegraded,
		BrowserExtensionStatusWithheldTotal,
		AppsPruneWithheldTotal,
	)
	for _, reason := range AppsPruneWithheldReasons {
		AppsPruneWithheldTotal.WithLabelValues(reason).Add(0)
	}
	for _, result := range []string{"matched", "error"} {
		CVEMatchObservations.WithLabelValues(result).Add(0)
	}
	// Pre-materialize every result label so DeadLetterRows (and any other
	// rule keyed on a specific result) can match a real, zero-valued series
	// from process start rather than waiting for the first occurrence of
	// that result. A CounterVec has no series for a label combination until
	// .WithLabelValues is called at least once for it (PAT-1377).
	for _, result := range []string{"success", "error", "dead_letter"} {
		ExtractorRowsProcessed.WithLabelValues(result).Add(0)
	}
}
