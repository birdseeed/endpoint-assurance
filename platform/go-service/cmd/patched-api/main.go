// Package main is the patched.im API ingestion service.
//
// Two HTTP servers run concurrently:
//
//	Public  (127.0.0.1:8080)  — reverse-proxied to by Caddy's api.patched.im site.
//	                            Hosts /health and (Phase 3+) /v1/inventory.
//	Internal (127.0.0.1:8081) — reverse-proxied to by Caddy's Tailscale-bound
//	                            api-internal.patched.im site. Hosts admin
//	                            endpoints (Phase 3+) like /admin/tenants.
//
// Configuration is via environment file /etc/patched-api/env, loaded by
// systemd. No CLI flags.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/db"
	"patched.im/api/internal/envelope"
	"patched.im/api/internal/feedback"
	"patched.im/api/internal/graphmail"
	"patched.im/api/internal/handlers"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/notifications"
	"patched.im/api/internal/notify"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/ratelimit"
	"patched.im/api/internal/releasecontrol"
	"patched.im/api/internal/reportsched"
	"patched.im/api/internal/softwaregov"
	"patched.im/api/internal/webhook"
)

const version = "0.1.0"

// PAT-710: build info injected via -ldflags at compile time.
// Defaults to "dev" so the binary still runs without the flags.
var (
	buildSHA  = "dev"
	buildTime = "dev"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg := loadConfig()
	handlers.PortalFeedbackEnabled = cfg.FeedbackEnabled

	// Database connection pool — used by all handlers in Phase 3+.
	pool, err := db.Connect(context.Background(), cfg.DatabaseURL)
	if err != nil {
		logger.Error("db connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// PAT-687: load the envelope-encryption KEK (PATCHED_KEK). Unset => disabled
	// (secret columns are written in plaintext, so nothing breaks pre-KEK). A set
	// but malformed key is fatal — fail closed rather than silently write plaintext.
	env, err := envelope.Init()
	if err != nil {
		logger.Error("envelope KEK invalid", "err", err)
		os.Exit(1)
	}
	logger.Info("envelope encryption", "enabled", env.Enabled())

	metrics.Register()

	// Ed25519 signing key for GET /v1/agent-config. The env var must be set
	// to a base64-encoded 32-byte seed; see contracts/agent-config-schema.md.
	signingKey, err := agentconfig.LoadSigningKey()
	if err != nil {
		logger.Error("agent config signing key unavailable", "err", err)
		os.Exit(1)
	}
	logger.Info("agent config signing key loaded",
		"key_id", signingKey.KeyID,
		"pubkey_b64", signingKey.PubKeyB64,
	)

	// Per-tenant rate limiter shared across all public ingest endpoints.
	// Limits reset on restart — see API.md "Rate limiting" for details.
	rl := ratelimit.New(ratelimit.Config{
		RPM:   cfg.RateLimitRPM,
		Burst: cfg.RateLimitBurst,
	})

	// Propagate build info to the handlers package so /admin/ops/version can serve it.
	handlers.OpsBuildSHA = buildSHA
	handlers.OpsBuildTime = buildTime

	logger.Info("patched-api starting", "version", version, "sha", buildSHA, "build_time", buildTime)

	if cfg.AdminAPIToken == "" {
		logger.Warn("ADMIN_API_TOKEN is not set — the internal /admin/* API will REFUSE all requests (503). " +
			"Set ADMIN_API_TOKEN in /etc/patched-api/env and send it as 'Authorization: Bearer <token>'.")
	}

	// PAT-954: dedicated credential for POST /v1/backup-health (public
	// listener). Deliberately separate from ADMIN_API_TOKEN and tenant
	// bearer tokens — see internal/handlers/backup_health_ingest.go.
	if cfg.BackupHeartbeatToken == "" {
		logger.Warn("BACKUP_HEARTBEAT_TOKEN is not set — POST /v1/backup-health will REFUSE all requests (503). " +
			"Set BACKUP_HEARTBEAT_TOKEN in /etc/patched-api/env and send it as 'Authorization: Bearer <token>'.")
	}

	// Webhook retry sweeper (PAT-687). The dispatcher's in-memory
	// time.AfterFunc retries are lost on restart; this DB-backed poller recovers
	// pending webhook_deliveries (succeeded_at IS NULL AND next_attempt_at <= now())
	// and re-dispatches them via the same SSRF-hardened client. Tied to a context
	// cancelled in the shutdown path so in-flight retries drain cleanly.
	//
	// PAT-867: bgWG tracks both background sweeper goroutines below so shutdown
	// can actually wait for them to finish (not just cancel their context and
	// hope) — see the Wait() call in the shutdown sequence.
	var bgWG sync.WaitGroup
	sweeperCtx, stopSweeper := context.WithCancel(context.Background())
	// PAT-1888's single Graph sender is shared by every customer-email path so
	// the process has one token cache and one explicit unconfigured failure.
	mailSender := notificationSender(logger)

	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		webhook.NewSweeper(pool).Start(sweeperCtx)
	}()
	bgWG.Add(1)
	go func() { defer bgWG.Done(); feedback.NewSweeper(pool, os.Getenv("LINEAR_API_KEY")).Start(sweeperCtx) }()
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		feedback.NewReconciler(pool, os.Getenv("LINEAR_API_KEY"), cfg.FeedbackEnabled).Start(sweeperCtx)
	}()
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		feedback.NewStatusEmailSweeper(pool, mailSender).Start(sweeperCtx)
	}()

	// PAT-1888 notification delivery sweeper. Raising a finding event only ever
	// writes a notification_deliveries row; this is the one component that
	// sends. Keeping the two apart is what stops a slow or hostile destination
	// from reaching the transaction that established the finding.
	//
	// Email is optional. When the Graph mailer is unconfigured this warns once
	// and webhook channels carry on working; email deliveries then dead-letter
	// with an explicit reason, which an owner can see, rather than silently
	// never being sent.
	//
	// One dispatcher, built once and shared by the sweeper and the test-event
	// route. A second graphmail.Client would mean a second access-token cache,
	// so the two would mint and refresh tokens independently against the same
	// app registration for no benefit.
	notificationDispatcher := notifications.NewDispatcher(pool, mailSender)
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		releasecontrol.RunMail(sweeperCtx, pool, mailSender)
	}()

	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		notifications.NewSweeper(notificationDispatcher).Start(sweeperCtx)
	}()

	// PAT-2009 software governance runner: emails the customer's unapproved
	// software alerts to the tenant contact (immediately for an admin mark, a
	// daily digest for newly observed devices), raises the opt-in daily new
	// software notification into PAT-1888 channels, and records the weekly
	// governance counts behind the drift trend. Shares the one Graph sender,
	// so there is one access-token cache. Webhooks for the alert are sent by
	// the PAT-134 sweeper above, not here.
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		softwaregov.NewRunner(pool, mailSender).Start(sweeperCtx)
	}()

	// Customer-scheduled reports (PAT-703). A per-minute in-process ticker
	// claims due portal_report_schedules rows (FOR UPDATE SKIP LOCKED) and
	// generates the customer-layout report through the same path as
	// POST /v1/portal/reports. Shares the sweeper shutdown context.
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		reportsched.New(pool, handlers.PortalReportGenerator(pool)).Start(sweeperCtx)
	}()

	// PAT-693: customer-portal auth. A nil verifier (env unset) makes the
	// /v1/portal/* surface answer 503 — fail closed, never open.
	portalVerifier, err := portalauth.NewFromEnv()
	if err != nil {
		logger.Error("portal access config invalid", "err", err)
		os.Exit(1)
	}
	if portalVerifier == nil {
		logger.Warn("PORTAL_ACCESS_TEAM_DOMAIN / PORTAL_ACCESS_AUD not set — " +
			"the public /v1/portal/* API will REFUSE all requests (503).")
	}
	// PAT-2257: optional read-only service identity (the authenticated prod
	// walker). A config error leaves it off rather than taking the API down.
	if svc, err := portalauth.ServiceIdentityFromEnv(); err != nil {
		logger.Error("portal service identity config invalid; service identity disabled", "err", err)
	} else if svc != nil && portalVerifier != nil {
		portalVerifier.WithService(svc)
		logger.Info("portal read-only service identity enabled", "tenant_id", svc.TenantID)
	}
	// PAT-1883: say at startup which way the self-service sign-up flag is
	// set, so the box log shows it without anyone reading the env file.
	logger.Info("self-service sign-up", "enabled", cfg.SelfServiceSignup.Enabled,
		"invitation_ttl", cfg.SelfServiceSignup.InvitationTTL.String(),
		"invitations_per_tenant_per_hour", cfg.SelfServiceSignup.InvitationsPerTenantPerHour,
		"org_creations_per_hour", cfg.SelfServiceSignup.OrgCreationsPerHour)
	// Per-identity (verified email) limiter for the portal read surface.
	portalRL := ratelimit.New(ratelimit.Config{
		RPM:   cfg.PortalRateLimitRPM,
		Burst: cfg.PortalRateLimitBurst,
	})

	// PAT-453: separate, much tighter per-TENANT limiter for the enrolment-
	// token mint specifically. Minting is a credential-issuing write, not a
	// read — the general per-identity portal limiter above (120 rpm default)
	// is far too loose for it. Keyed by tenant (not identity), so every
	// portal user at a tenant shares one mint budget.
	portalEnrolRL := ratelimit.New(ratelimit.Config{
		RPM:    cfg.PortalEnrolMintsPerWindow,
		Burst:  cfg.PortalEnrolMintsPerWindow,
		Period: cfg.PortalEnrolWindow,
	})

	// PAT-820: best-effort Slack/email alerts on operator app-restriction
	// actions. Channels with unset env vars are silently disabled.
	notifier := notify.New()

	// PAT-954: dedicated, tight rate limiter for POST /v1/backup-health.
	// There is exactly one legitimate caller (portal-01's backup timer,
	// roughly nightly) sharing a single bucket — see backupHeartbeatRateKey.
	backupHeartbeatRL := ratelimit.New(ratelimit.Config{
		RPM:   cfg.BackupHeartbeatRateLimitRPM,
		Burst: cfg.BackupHeartbeatRateLimitBurst,
	})

	// PAT-2145: Jamf Pro webhook ingest limits. The tenant bucket is
	// charged only after authentication; failed authentication goes to
	// separate global, per-IP and per-ID buckets. See jamf_webhook.go.
	handlers.JamfWebhookPublicBaseURL = cfg.JamfWebhookPublicBaseURL
	jamfWebhookRL := handlers.NewJamfWebhookLimits(handlers.JamfWebhookLimitsConfig{
		TenantRPM: cfg.JamfWebhookRateLimitRPM, TenantBurst: cfg.JamfWebhookRateLimitBurst,
		FailedGlobalRPM: cfg.JamfWebhookFailedGlobalRPM, FailedGlobalBurst: cfg.JamfWebhookFailedGlobalBurst,
		FailedKeyRPM: cfg.JamfWebhookFailedKeyRPM, FailedKeyBurst: cfg.JamfWebhookFailedKeyBurst,
	})
	// Seed the connector cache before serving, so a restart never leaves a
	// working tenant looking unknown during a flood, then keep it fresh.
	if err := jamfWebhookRL.SeedConnectors(context.Background(), pool); err != nil {
		logger.Error("jamf connector cache seed failed after retries; serving anyway, the minute refresh will retry", "err", err)
	}
	bgWG.Add(1)
	go func() {
		defer bgWG.Done()
		jamfWebhookRL.RunConnectorRefresh(sweeperCtx, pool)
	}()

	// PAT-2529: POST /v1/trial/provision is unauthenticated and creates
	// tenants, so it is limited per client address and globally, before the
	// body is read. See internal/handlers/trial_ratelimit.go.
	trialProvisionRL := handlers.NewTrialProvisionLimits(handlers.TrialProvisionLimitsConfig{
		PerIPPerHour:  cfg.TrialProvisionPerIPPerHour,
		GlobalPerHour: cfg.TrialProvisionGlobalPerHour,
	})

	// Retained legacy execution paths are permanently quarantined. A future
	// implementation must introduce a separately reviewed, fresh-state-scoped
	// authority model; configuration cannot re-enable these routes.
	publicRouter := newPublicRouter(pool, signingKey, rl, cfg.ReplaySkew, portalVerifier, portalRL, portalEnrolRL, cfg.BackupHealthDir, cfg.BackupHeartbeatToken, cfg.BackupHeartbeatAllowedJobs, backupHeartbeatRL, cfg.ArtifactDir, jamfWebhookRL, cfg.LinearWebhookSecret, trialProvisionRL, withPortalSignup(cfg.SelfServiceSignup))
	internalRouter := newInternalRouter(pool, signingKey, cfg.CredentialGrace, cfg.BackupHealthDir, cfg.AdminAPIToken, cfg.MaintenanceFactsPath, notifier, cfg.ArtifactDir, notificationDispatcher,
		withOperatorOwnerRole(cfg.SelfServiceSignup.Enabled))

	publicServer := &http.Server{
		Addr:         cfg.ListenPublic,
		Handler:      publicRouter,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	internalServer := &http.Server{
		Addr:         cfg.ListenInternal,
		Handler:      internalRouter,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	errCh := make(chan error, 2)

	go func() {
		logger.Info("public server listening", "addr", cfg.ListenPublic)
		if err := publicServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		logger.Info("internal server listening", "addr", cfg.ListenInternal)
		if err := internalServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		logger.Info("shutdown signal received")
	case err := <-errCh:
		logger.Error("server failed", "err", err)
	}

	// Stop the webhook sweeper and report scheduler, and actually wait (bounded)
	// for them to drain their in-flight work before the process exits — merely
	// cancelling sweeperCtx does not make main() wait for the two goroutines
	// started above to return.
	stopSweeper()
	if waitWithTimeout(&bgWG, bgDrainTimeout) {
		logger.Info("background sweepers drained")
	} else {
		logger.Warn("background sweepers did not drain within timeout; proceeding with shutdown",
			"timeout", bgDrainTimeout.String())
	}

	// PAT-867: separate shutdown contexts per server. These used to share one
	// 10s deadline, so a slow public-listener drain could starve the internal
	// listener's own 60s budget (internalRouter's middleware.Timeout(60s) is
	// there specifically for PDF generation) before it ever got a chance to
	// finish in-flight requests.
	publicCtx, publicCancel := context.WithTimeout(context.Background(), publicShutdownTimeout)
	defer publicCancel()
	_ = publicServer.Shutdown(publicCtx)

	internalCtx, internalCancel := context.WithTimeout(context.Background(), internalShutdownTimeout)
	defer internalCancel()
	_ = internalServer.Shutdown(internalCtx)

	logger.Info("patched-api stopped")
}

// Shutdown timing constants (PAT-867).
const (
	// bgDrainTimeout bounds how long shutdown waits for the webhook sweeper and
	// report scheduler goroutines to finish draining in-flight work before
	// proceeding regardless — a stuck delivery or report render must not hang
	// process exit forever.
	bgDrainTimeout = 15 * time.Second

	// publicShutdownTimeout bounds graceful drain of the public :8080 listener.
	publicShutdownTimeout = 10 * time.Second

	// internalShutdownTimeout bounds graceful drain of the internal :8081
	// listener. Kept longer than the public timeout and than
	// publicShutdownTimeout so a slow public-listener drain can never starve
	// an in-flight PDF report (internalRouter allows up to 60s per request).
	internalShutdownTimeout = 60 * time.Second
)

// waitWithTimeout waits for wg to finish, up to timeout. Returns true if wg
// finished in time, false if the timeout elapsed first (in which case the
// goroutine tracked by wg may still be running in the background).
func waitWithTimeout(wg *sync.WaitGroup, timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// ---------------------------------------------------------------------------
// Routers — handlers stubbed for Phase 2; filled in Phase 3.
// ---------------------------------------------------------------------------

// publicRouterOptions carries the public router's optional configuration.
// Options, not more positional parameters: a caller that passes none gets
// every optional feature at its default, which for self-service sign-up
// (PAT-1883) is off.
type publicRouterOptions struct {
	signup handlers.PortalSignupConfig
}

type publicRouterOption func(*publicRouterOptions)

// withPortalSignup sets the self-service sign-up configuration (PAT-1883).
// Without it the sign-up and access routes are mounted and answer 404.
func withPortalSignup(cfg handlers.PortalSignupConfig) publicRouterOption {
	return func(o *publicRouterOptions) { o.signup = cfg }
}

func newPublicRouter(pool *pgxpool.Pool, signingKey *agentconfig.SigningKey, rl *ratelimit.TenantLimiter, replaySkew time.Duration, portalVerifier *portalauth.Verifier, portalRL *ratelimit.TenantLimiter, portalEnrolRL *ratelimit.TenantLimiter, backupHealthDir, backupHeartbeatToken string, backupHeartbeatAllowedJobs []string, backupHeartbeatRL *ratelimit.TenantLimiter, artifactDir string, jamfWebhookRL *handlers.JamfWebhookLimits, linearWebhookSecret string, trialProvisionRL *handlers.TrialProvisionLimits, opts ...publicRouterOption) http.Handler {
	var ro publicRouterOptions
	for _, opt := range opts {
		opt(&ro)
	}
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(requestMetrics)

	r.Get("/health", healthHandler)
	// PAT-1215: separate readiness check — a real, bounded DB round trip that
	// fails the status code on a hung/unreachable database, unlike /health
	// above (hardcoded, never touches the DB; do not change its contract —
	// see internal/handlers/readiness.go's file doc comment for why).
	r.Get("/ready", handlers.ReadinessHandler(pool))
	// PAT-2036: Linear signs the exact raw body. This route therefore lives
	// outside every JSON- or portal-auth middleware group.
	r.Post("/public/linear-webhook", handlers.LinearWebhookHandler(pool, linearWebhookSecret))
	r.Post("/v1/inventory", handlers.InventoryHandler(pool, rl, replaySkew))
	r.Post("/v1/provenance", handlers.ProvenanceHandler(pool, rl, replaySkew))
	// PAT-1022: durable SIEM-style security audit events (PAT-499 agent side
	// already ships; this was the missing platform handler — see
	// internal/handlers/events.go and migrations/0098_audit_events.sql).
	r.Post("/v1/events", handlers.EventsHandler(pool, rl, replaySkew))
	r.Get("/v1/agent-config", handlers.AgentConfigHandler(pool, signingKey, rl, replaySkew))
	// PAT-1108: two-phase decommission status report — "acknowledged" before
	// the agent attempts removal, the genuine terminal outcome after the
	// attempt finishes, and only then does the agent destroy its own
	// uploader (fourth-round finding P1-B; see contracts/agent-config-schema.md's
	// POST /v1/agent-decommission-status section for the full sequence).
	// Device-scoped bearer + HMAC, same auth chain as the rest of this block;
	// see internal/handlers/agent_decommission.go.
	r.Post("/v1/agent-decommission-status", handlers.AgentDecommissionStatusHandler(pool, rl, replaySkew))
	r.Post("/v1/mandatory-install-status", handlers.MandatoryInstallStatusHandler(pool, rl, replaySkew))
	// PAT-2246: the signed global app catalogue is retired. The route stays
	// mounted only to answer 410 Gone (no auth, no database read) so agents
	// still polling it see a permanent retirement rather than a 404.
	r.Get("/v1/catalogue", handlers.CatalogueHandler())
	r.Get("/v1/allowlist/pending-removals", handlers.PendingRemovalsHandler(pool, rl, replaySkew))
	r.Get("/v1/allowlist/pending-installs", handlers.PendingInstallsHandler(pool, rl, replaySkew))
	r.Get("/v1/posture", handlers.PostureHandler(pool, signingKey, rl, replaySkew))
	r.Post("/v1/agent-logs", handlers.AgentLogsHandler(pool, rl, replaySkew))
	// PAT-2424: which device the presented credential belongs to. Device-scoped
	// credentials only; see internal/handlers/device_identity.go.
	r.Get("/v1/device/identity", handlers.DeviceIdentityHandler(pool, rl, replaySkew))
	r.Get("/v1/agent/artifact", handlers.AgentArtifactHandler(pool, rl, replaySkew))
	// PAT-1260: the artifact bytes GET /v1/agent/artifact's signed
	// artifact_url now points at. Own endpoint ID
	// (auth.EndpointAgentArtifactDownload) — see that constant's doc
	// comment in internal/auth/hmac.go for why reusing "agent_artifact"
	// would have been a replay hole. HEAD registered alongside GET since
	// serving it is cheap (same handler; it short-circuits before writing
	// a body).
	r.Get("/v1/agent/artifact/download", handlers.AgentArtifactDownloadHandler(pool, rl, replaySkew, artifactDir))
	r.Head("/v1/agent/artifact/download", handlers.AgentArtifactDownloadHandler(pool, rl, replaySkew, artifactDir))
	r.Post("/v1/inventory/enforcement-audit", handlers.EnforcementAuditIngestHandler(pool, rl, replaySkew))
	// PAT-781: per-device app-removal task queue — agent poll + state report.
	r.Get("/v1/devices/{deviceID}/removal-tasks/pending", handlers.DeviceRemovalTasksPendingHandler(pool, rl, replaySkew))
	r.Post("/v1/devices/{deviceID}/removal-tasks/report", handlers.DeviceRemovalTasksReportHandler(pool, rl, replaySkew))
	r.Post("/v1/enrol", handlers.EnrolHandler(pool, rl))
	// PAT-668: self-serve trial provisioning (no auth — pre-enrol step).
	// PAT-2529: limited per client and globally; nil limits answers 503.
	r.Post("/v1/trial/provision", handlers.TrialProvisionHandler(pool, trialProvisionRL))
	// PAT-370: token redemption is public (no auth) — external recipients click a link.
	r.Post("/admin/report-download-tokens/{token}/redeem", handlers.RedeemDownloadTokenHandler(pool))
	// PAT-954: portal-01 backup-health heartbeat ingest. Dedicated
	// BACKUP_HEARTBEAT_TOKEN auth (not ADMIN_API_TOKEN, not a tenant
	// bearer) + its own rate limiter — see backup_health_ingest.go.
	r.Post("/v1/backup-health", handlers.BackupHeartbeatIngestHandler(backupHeartbeatToken, backupHealthDir, backupHeartbeatAllowedJobs, backupHeartbeatRL))
	// PAT-2145: Jamf Pro webhook ingest. Outside the /v1/portal group on
	// purpose: its only credential is the tenant's webhook token, and a
	// portal identity grants nothing here. See jamf_webhook.go.
	r.Post("/v1/webhooks/jamf/{webhookID}", handlers.JamfWebhookHandler(pool, jamfWebhookRL))

	// PAT-1883: self-service organisation sign-up and access management.
	// Every handler it returns answers 404 unless SELF_SERVICE_SIGNUP_ENABLED
	// is set (default off).
	signup := handlers.NewPortalSignup(pool, ro.signup)

	// PAT-1883: the pre-membership group. A sibling of /v1/portal below, not
	// a child of it, because that group's middleware requires the verified
	// email to resolve to a tenant and a person signing up has none yet. Same
	// JWT verification, same per-email limiter instance and the same audit
	// log (with no tenant); 503 when the verifier is unconfigured. It mounts
	// the three sign-up handlers and nothing else: no tenant-scoped handler
	// is reachable here, and those handlers would refuse anyway, since this
	// middleware sets a portalauth.Applicant and never an Identity.
	r.Route("/v1/portal/signup", func(sr chi.Router) {
		sr.Use(portalauth.SignupMiddleware(portalVerifier, portalRL, portalauth.DBAudit(pool)))
		sr.Get("/state", signup.StateHandler())
		sr.Post("/organisation", signup.CreateOrganisationHandler())
		sr.Post("/invitations/{invitationID}/accept", signup.AcceptInvitationHandler())
	})

	// PAT-693: customer-portal read API. CF-Access-JWT-authenticated,
	// tenant-scoped via portal_users, per-identity rate-limited, audit-logged.
	// 503 when the verifier is unconfigured (fail closed).
	r.Route("/v1/portal", func(pr chi.Router) {
		pr.Use(portalauth.Middleware(portalVerifier, portalauth.DBLookup(pool), portalRL, portalauth.DBAudit(pool),
			portalauth.WithServiceTenantCheck(portalauth.DBTenantLive(pool))))
		pr.Get("/overview", handlers.PortalOverviewHandler(pool))
		pr.Get("/certificates", handlers.PortalCertificatesGetHandler(pool))
		pr.Post("/certificates", handlers.PortalCertificatesWriteHandler(pool))
		pr.Patch("/certificates/{id}", handlers.PortalCertificatesWriteHandler(pool))
		pr.Delete("/certificates/{id}", handlers.PortalCertificatesWriteHandler(pool))
		pr.Get("/overview/cards", handlers.PortalOverviewCardsHandler(pool))         // PAT-2207
		pr.Get("/ce-readiness", handlers.PortalCEReadinessHandler(pool))             // PAT-1927
		pr.Get("/insurance-evidence", handlers.PortalInsuranceEvidenceHandler(pool)) // PAT-2258
		pr.Get("/agent-releases", handlers.PortalAgentReleaseGetHandler(pool))
		pr.Put("/agent-releases", handlers.PortalAgentReleaseWriteHandler(pool))
		pr.Get("/control-coverage", handlers.PortalControlCoverageHandler(pool)) // PAT-1857
		pr.Get("/devices", handlers.PortalDevicesHandler(pool))
		pr.Get("/devices/{deviceID}", handlers.PortalDeviceDetailHandler(pool))
		// PAT-2135: customer self-service device decisions (admin role only,
		// enforced server-side): Retire device, and the customer's own device
		// list reconciled against the devices Patched has seen.
		pr.Put("/devices/{deviceID}/retirement", handlers.PortalDeviceRetirementPutHandler(pool))
		pr.Get("/devices/{deviceID}/retirement/history", handlers.PortalDeviceRetirementHistoryHandler(pool))
		pr.Get("/device-list", handlers.PortalDeviceListGetHandler(pool))
		pr.Put("/device-list", handlers.PortalDeviceListPutHandler(pool))
		pr.Delete("/device-list", handlers.PortalDeviceListDeleteHandler(pool))
		// PAT-2271: remove one entry from the current list.
		pr.Delete("/device-list/entries/{entryID}", handlers.PortalDeviceListEntryDeleteHandler(pool))
		pr.Get("/findings", handlers.PortalFindingsHandler(pool))
		// PAT-729: unapproved-policy apps aggregated with device counts.
		pr.Get("/unapproved-apps", handlers.PortalUnapprovedAppsHandler(pool))
		// PAT-933: browser extension estate with PAT-826 approval state.
		pr.Get("/extensions", handlers.PortalExtensionsHandler(pool))
		// PAT-1727: applications with a policy state (approved / unapproved /
		// any other configured policy / undecided) — leaves /unapproved-apps
		// above unchanged.
		pr.Get("/applications", handlers.PortalApplicationsHandler(pool))
		// PAT-1869: uncapped, paginated current software inventory and usage
		// evidence. This is deliberately distinct from policy applications.
		pr.Get("/software", handlers.PortalSoftwareHandler(pool))
		// PAT-2009: software governance reporting and notification settings.
		pr.Get("/software/new", handlers.PortalNewSoftwareHandler(pool))
		pr.Get("/software/drift", handlers.PortalSoftwareDriftHandler(pool))
		pr.Get("/software/approved", handlers.PortalApprovedSoftwareHandler(pool))
		pr.Get("/software-notifications", handlers.PortalSoftwareNotificationsGetHandler(pool))
		pr.Put("/software-notifications", handlers.PortalSoftwareNotificationsPutHandler(pool))
		// PAT-2015: software carrying a live category tag (AI tooling first),
		// with device counts and read-only approval state.
		pr.Get("/tagged-products", handlers.PortalTaggedProductsHandler(pool))
		// PAT-2013: Homebrew tab (PAT-1999), tenant-scoped and read-only.
		pr.Get("/homebrew/summary", handlers.PortalHomebrewSummaryHandler(pool))
		pr.Get("/homebrew/formulae", handlers.PortalHomebrewFormulaeHandler(pool))
		pr.Get("/homebrew/casks", handlers.PortalHomebrewCasksHandler(pool))
		pr.Get("/homebrew/taps", handlers.PortalHomebrewTapsHandler(pool))
		pr.Get("/homebrew/devices", handlers.PortalHomebrewDevicesHandler(pool))
		pr.Get("/homebrew/devices/{deviceID}", handlers.PortalHomebrewDeviceHandler(pool))
		// PAT-2021: AI Tooling tab (PAT-2000): IDE extensions, packages,
		// local models and MCP servers, tenant-scoped and read-only.
		pr.Get("/ai-tooling/summary", handlers.PortalToolingSummaryHandler(pool))
		pr.Get("/ai-tooling/devices", handlers.PortalToolingDevicesHandler(pool))
		pr.Get("/ai-tooling/devices/{deviceID}/items", handlers.PortalToolingDeviceItemsHandler(pool))
		// PAT-1823: per-product protection status for the caller's effective
		// protected-software set (disposition flag, not a visibility filter —
		// see protected_software.go's file-level doc comment).
		pr.Get("/protected-software", handlers.PortalProtectedSoftwareHandler(pool))
		// PAT-1824: software exception register (pinned version / accepted
		// risk) — read-only here; writes are admin-only, see below.
		pr.Get("/exceptions", handlers.PortalExceptionsHandler(pool))
		// PAT-2215: standing local-administrator roster (accounts, not just
		// the bare count), admin role only (checked in the handler — account
		// names are personal data).
		pr.Get("/local-admins", handlers.PortalLocalAdminsHandler(pool))
		// PAT-2263: kernel drivers whose hash is on Microsoft's recommended
		// driver block rules or loldrivers.io (every role reads).
		pr.Get("/driver-findings", handlers.PortalDriverFindingsHandler(pool))
		pr.Get("/reports/catalogue", handlers.PortalReportCatalogueHandler(pool))
		pr.Get("/reports", handlers.PortalReportsListHandler(pool))
		pr.Post("/reports", handlers.PortalReportGenerateHandler(pool))
		// PAT-703: static sub-path before {id} to avoid chi routing ambiguity.
		pr.Get("/reports/schedule", handlers.PortalReportScheduleGetHandler(pool))
		pr.Put("/reports/schedule", handlers.PortalReportSchedulePutHandler(pool))
		pr.Get("/reports/schedules", handlers.PortalReportSchedulesListHandler(pool))
		pr.Get("/reports/schedules/{reportType}", handlers.PortalReportScheduleTypeGetHandler(pool))
		pr.Put("/reports/schedules/{reportType}", handlers.PortalReportScheduleTypePutHandler(pool))
		// PAT-2147: SAM unsupported software report (every role reads).
		pr.Get("/reports/software/unsupported", handlers.PortalUnsupportedSoftwareHandler(pool))
		pr.Get("/reports/software/unsupported/devices", handlers.PortalUnsupportedSoftwareDevicesHandler(pool))
		// PAT-2148: SAM remote access / RMM report (every role reads).
		pr.Get("/reports/software/remote-access", handlers.PortalRemoteAccessHandler(pool))
		pr.Get("/reports/software/remote-access/devices", handlers.PortalRemoteAccessDevicesHandler(pool))
		// PAT-2150: SAM version sprawl report (every role reads).
		pr.Get("/reports/software/version-sprawl", handlers.PortalVersionSprawlHandler(pool))
		// PAT-2152: SAM software publisher report (every role reads).
		pr.Get("/reports/software/publishers", handlers.PortalSoftwarePublishersHandler(pool))
		pr.Get("/reports/software/publishers/devices", handlers.PortalSoftwarePublishersDevicesHandler(pool))
		// PAT-2151: SAM duplicate-tools-by-category report (every role reads).
		pr.Get("/reports/software/duplicate-tools", handlers.PortalDuplicateToolsHandler(pool))
		pr.Get("/reports/{id}", handlers.PortalReportDownloadHandler(pool))
		// PAT-2405: renders a table the portal posts (the rows of one of its
		// CSV list exports) as a branded PDF. A POST only because the rows
		// travel in the body: it writes nothing, so every role may call it,
		// except for the local administrators roster (admin only, enforced
		// in the handler). See portal_table_pdf.go.
		pr.Post("/exports/table-pdf", handlers.PortalTablePDFHandler(pool))
		// PAT-1969: portal-facing finding lifecycle read contract, mirroring
		// the admin /admin/tenants/{tenantID}/finding-lifecycle[/history]
		// pair but scoped to the caller's tenant via the authenticated
		// portal identity only — no {tenantID} path segment here.
		pr.Get("/finding-lifecycle", handlers.PortalFindingLifecycleCurrentHandler(pool))
		pr.Get("/finding-lifecycle/history", handlers.PortalFindingLifecycleHistoryHandler(pool))
		// PAT-453: mints a single-use agent enrolment token for the caller's
		// own tenant. Dedicated per-tenant rate limit (portalEnrolRL) on top
		// of the per-identity limit above — see portal_enrolment.go. Admin
		// only (PAT-2407), enforced in the handler.
		pr.Post("/enrolment", handlers.PortalEnrolmentGenerateHandler(pool, portalEnrolRL))
		// PAT-2250: reusable, revocable tenant enrolment keys for estate
		// rollouts (Intune, Jamf, RMM). Create and revoke are admin only
		// (enforced in the handler); create shares portalEnrolRL with the
		// single-use mint above. See enrolment_keys.go.
		pr.Post("/enrolment-keys", handlers.PortalEnrolmentKeyCreateHandler(pool, portalEnrolRL))
		pr.Get("/enrolment-keys", handlers.PortalEnrolmentKeysListHandler(pool))
		pr.Post("/enrolment-keys/{keyID}/revoke", handlers.PortalEnrolmentKeyRevokeHandler(pool))
		pr.Get("/feedback", handlers.PortalFeedbackHandler(pool, handlers.PortalFeedbackEnabled))
		pr.Post("/feedback", handlers.PortalFeedbackHandler(pool, handlers.PortalFeedbackEnabled))
		// PAT-2007: the caller's role, and customer software approval writes
		// (admin role only, enforced server-side) with their audit history.
		pr.Get("/me", handlers.PortalMeHandler(pool))
		// PAT-2393: software declared before any endpoint reports it. Every
		// role reads; only an admin creates or resolves (enforced in the
		// handler inside the write transaction).
		pr.Get("/software-products", handlers.PortalSoftwareProductsHandler(pool))
		pr.Get("/software-declarations", handlers.PortalSoftwareDeclarationsHandler(pool))
		pr.Post("/software-declarations", handlers.PortalSoftwareDeclarationCreateHandler(pool))
		pr.Get("/software-declarations/{declarationID}", handlers.PortalSoftwareDeclarationsHandler(pool))
		pr.Post("/software-declarations/{declarationID}/resolve", handlers.PortalSoftwareDeclarationResolveHandler(pool))
		pr.Get("/software-declarations/{declarationID}/history", handlers.PortalSoftwareDeclarationHistoryHandler(pool))
		pr.Put("/software-approvals", handlers.PortalSoftwareApprovalsPutHandler(pool))
		pr.Get("/software-approvals/history", handlers.PortalSoftwareApprovalHistoryHandler(pool))
		pr.Get("/software-approvals/history/export", handlers.PortalSoftwareApprovalHistoryExportHandler(pool))
		// PAT-2097: unapproved software alert lifecycle. Every role reads;
		// only an admin acknowledges (enforced in the handler).
		pr.Get("/software-alerts", handlers.PortalSoftwareAlertsHandler(pool))
		pr.Get("/software-alerts/{id}", handlers.PortalSoftwareAlertHandler(pool))
		pr.Post("/software-alerts/{id}/acknowledge", handlers.PortalSoftwareAlertAcknowledgeHandler(pool))
		// PAT-2145: Jamf Pro coverage from webhooks. Every role reads; token
		// and event-subscription writes are admin only (enforced in the
		// handler) and audited.
		pr.Get("/mdm/jamf/coverage", handlers.PortalJamfCoverageHandler(pool))
		pr.Get("/mdm/jamf/setup", handlers.PortalJamfSetupGetHandler(pool))
		pr.Put("/mdm/jamf/setup", handlers.PortalJamfSetupPutHandler(pool))
		pr.Post("/mdm/jamf/token", handlers.PortalJamfTokenPostHandler(pool))
		pr.Delete("/mdm/jamf/token", handlers.PortalJamfTokenDeleteHandler(pool))
		pr.Delete("/mdm/jamf/devices", handlers.PortalJamfDevicesDeleteHandler(pool))
		// PAT-1883: who has access to the tenant. Owner and admin read;
		// invitations, role changes and disabling a member are owner only
		// (enforced in the handler, inside the write transaction). The
		// tenant is the caller's; an id or address from another tenant is
		// 404. Flag-gated: 404 unless SELF_SERVICE_SIGNUP_ENABLED.
		pr.Get("/access", signup.AccessListHandler())
		pr.Post("/access/invitations", signup.InvitationCreateHandler())
		pr.Post("/access/invitations/{invitationID}/revoke", signup.InvitationRevokeHandler())
		pr.Put("/access/members/{memberEmail}/role", signup.MemberRoleHandler())
		pr.Post("/access/members/{memberEmail}/disable", signup.MemberDisableHandler())
		pr.Post("/access/members/{memberEmail}/enable", signup.MemberEnableHandler())
	})
	return r
}

// notificationSender resolves the Graph mailer for PAT-1888 email channels, and
// logs the one startup line about its configuration. Call it exactly once.
//
// A missing or partial GRAPH_MAIL_* configuration yields a nil sender rather
// than a failure: webhook channels keep working, and an email delivery records
// a dead-letter naming the missing configuration instead of vanishing. The nil
// is returned explicitly because assigning a typed nil *graphmail.Client into
// the Sender interface would produce a non-nil interface holding a nil pointer.
func notificationSender(logger *slog.Logger) graphmail.Sender {
	mailer, err := graphmail.FromEnv()
	if err != nil {
		logger.Warn("GRAPH_MAIL_* is not fully configured: email notification channels will dead-letter, webhook channels are unaffected",
			"err", err)
		return nil
	}
	return mailer
}

// internalRouterOptions carries the internal router's optional configuration,
// in the same way publicRouterOptions does: a caller that passes none gets
// every option at its default.
type internalRouterOptions struct {
	// operatorOwnerRole: POST /admin/portal-users may grant the owner role.
	operatorOwnerRole bool
}

type internalRouterOption func(*internalRouterOptions)

// withOperatorOwnerRole lets POST /admin/portal-users grant the owner role
// (PAT-1883). main passes SELF_SERVICE_SIGNUP_ENABLED: while self-service
// sign-up is off the route refuses "owner", because the customer portal does
// not yet treat an owner as admin-level. Without the option it is off.
func withOperatorOwnerRole(enabled bool) internalRouterOption {
	return func(o *internalRouterOptions) { o.operatorOwnerRole = enabled }
}

func newInternalRouter(pool *pgxpool.Pool, signingKey *agentconfig.SigningKey, credentialGrace time.Duration, backupHealthDir, adminToken, maintenanceFactsPath string, notifier *notify.Notifier, artifactDir string, notificationDispatcher *notifications.Dispatcher, opts ...internalRouterOption) http.Handler {
	var ro internalRouterOptions
	for _, opt := range opts {
		opt(&ro)
	}
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	// Reports can take longer than 30s in pathological cases (many evaluations,
	// large PDF). Bump the per-request budget on the internal listener only.
	r.Use(middleware.Timeout(60 * time.Second))

	r.Use(requestMetrics)
	// H1: application-layer auth on the internal admin surface, independent of
	// the Tailscale/Caddy network placement. /health and /metrics stay open for
	// liveness probes and Prometheus scraping.
	r.Use(requireInternalToken(adminToken))

	// PAT-650: subscription-tier gates. These check the TARGET tenant's tier
	// (resolved from the {tenantID} URL param) — admin callers are
	// Tailscale-gated operators, not tenants, so gating on the caller makes no
	// sense here. Upgrading a tenant first via PUT /admin/tenant-tier/{tenantID}
	// (ungated, like all tenant-management routes) immediately unlocks the
	// gated configuration routes for that tenant.
	//
	// PAT-1599 (migration 0138): needsPatch used to gate at the middle rung of
	// a three-tier ladder (report < patch < full_endpoint) and needsFullEndpoint
	// at the top. The ladder collapsed to two tiers (assurance < managed), and
	// every one of these routes configures policy that leads to actuation on
	// the endpoint (app-update policy, allowlists, extension policies/removals,
	// execution policies, app-control) — squarely "action under authorisation"
	// per Andy's ruling that assurance "changes nothing on the endpoint, ever".
	// needsPatch and needsFullEndpoint are therefore now the identical gate;
	// both names are kept only because each is wired onto its own route group
	// below and renaming either without the other would make one group's floor
	// silently inconsistent with its neighbour during review.
	needsPatch := handlers.RequireSubscriptionTier(pool, handlers.TierManaged)
	needsFullEndpoint := handlers.RequireSubscriptionTier(pool, handlers.TierManaged)

	r.Handle("/metrics", promhttp.Handler())
	r.Get("/health", healthHandler)
	r.Get("/admin/tenants", handlers.ListTenantsHandler(pool))
	r.Post("/admin/tenants", handlers.CreateTenantHandler(pool))
	// Static sub-paths must be registered before {tenantID} to avoid chi routing ambiguity.
	r.Get("/admin/tenants/revoked", handlers.ListRevokedTenantsHandler(pool))
	// PAT-670 — trial admin endpoints (static sub-path before {tenantID} routes).
	r.Get("/admin/tenants/trials", handlers.TrialTenantsListHandler(pool))
	r.Delete("/admin/tenants/{tenantID}", handlers.RevokeTenantHandler(pool)) // soft-revoke, not a purge
	r.Post("/admin/tenants/{tenantID}/restore", handlers.RestoreTenantHandler(pool))
	r.Delete("/admin/tenants/{tenantID}/purge", handlers.PurgeTenantHandler(pool))
	r.Post("/admin/tenants/{tenantID}/rotate-credentials", handlers.RotateCredentialsHandler(pool, credentialGrace))
	r.Post("/admin/tenants/{tenantID}/trial-notify", handlers.TrialNotifyHandler(pool)) // PAT-670
	r.Put("/admin/tenants/{tenantID}/kind", handlers.TenantKindPutHandler(pool))        // PAT-1562
	r.Get("/admin/reports/catalogue", handlers.ReportCatalogueHandler())
	r.Get("/admin/reports/{deviceID}/compliance.pdf", handlers.ComplianceReportHandler(pool))
	r.Get("/admin/reports/executive-summary/{tenantID}.pdf", handlers.ExecutiveSummaryHandler(pool))
	r.Get("/admin/reports/cve/{tenantID}.pdf", handlers.FreeCVEReportHandler(pool))
	r.Get("/admin/reports/cis-compliance/{tenantID}.pdf", handlers.CISComplianceReportHandler(pool))
	r.Get("/admin/reports/patch-status/{tenantID}.pdf", handlers.PatchStatusReportHandler(pool))
	r.Get("/admin/reports/stale-endpoints/{tenantID}.pdf", handlers.StaleEndpointsReportHandler(pool))
	r.Get("/admin/reports/cert-expiry/{tenantID}.pdf", handlers.CertExpiryReportHandler(pool))
	r.Get("/admin/reports/software-inventory/{tenantID}.pdf", handlers.SoftwareInventoryReportHandler(pool))
	r.Get("/admin/reports/app-policy-drift/{tenantID}.pdf", handlers.AppPolicyDriftReportHandler(pool))
	// PAT-2009 software governance reports.
	r.Get("/admin/reports/new-software/{tenantID}.pdf", handlers.NewSoftwareReportHandler(pool))
	r.Get("/admin/reports/software-drift/{tenantID}.pdf", handlers.SoftwareDriftReportHandler(pool))
	r.Get("/admin/reports/approved-software/{tenantID}.pdf", handlers.ApprovedSoftwareReportHandler(pool))
	r.Get("/admin/reports/browser-extensions/{tenantID}.pdf", handlers.BrowserExtensionsReportHandler(pool))
	r.Get("/admin/tenants/{tenantID}/browser-extensions", handlers.TenantBrowserExtensionsHandler(pool)) // PAT-561
	r.Get("/admin/tenants/{tenantID}/agent-health", handlers.TenantAgentHealthHandler(pool))             // PAT-1064
	// PAT-1108: agent decommissioning — explicit, audited tenant-wide directive
	// (never a side effect of revoke/purge above) plus per-device state,
	// including devices that have never acknowledged. See agent_decommission.go.
	r.Get("/admin/tenants/{tenantID}/decommission", handlers.TenantDecommissionGetHandler(pool))
	r.Put("/admin/tenants/{tenantID}/decommission", handlers.TenantDecommissionPutHandler(pool))
	r.Get("/admin/tenants/{tenantID}/decommission/devices", handlers.TenantDecommissionDevicesHandler(pool))
	r.Get("/admin/reports/edr-coverage/{tenantID}.pdf", handlers.EDRCoverageReportHandler(pool))
	r.Get("/admin/reports/device-health/{tenantID}.pdf", handlers.DeviceHealthReportHandler(pool))
	r.Get("/admin/reports/encryption-posture/{tenantID}.pdf", handlers.EncryptionPostureReportHandler(pool))
	r.Get("/admin/reports/local-admin/{tenantID}.pdf", handlers.LocalAdminReportHandler(pool))
	r.Get("/admin/reports/ai-tooling-evidence/{tenantID}.pdf", handlers.AIToolingEvidenceReportHandler(pool))
	r.Get("/admin/reports/insurance-evidence/{tenantID}.pdf", handlers.InsuranceEvidenceReportHandler(pool)) // PAT-2258
	r.Get("/admin/tenant-rules/{tenantID}", handlers.TenantRulesListHandler(pool))
	r.Put("/admin/tenant-rules/{tenantID}/{ruleID}", handlers.TenantRulesPutHandler(pool))
	r.Delete("/admin/tenant-rules/{tenantID}/{ruleID}", handlers.TenantRulesDeleteHandler(pool))
	r.Get("/admin/tenant-platforms/{tenantID}", handlers.TenantPlatformsGetHandler(pool))
	r.Put("/admin/tenant-platforms/{tenantID}", handlers.TenantPlatformsPutHandler(pool))
	r.Put("/admin/tenant-tier/{tenantID}", handlers.SetTenantTierHandler(pool)) // PAT-397
	r.Get("/admin/tenants/overview", handlers.TenantsOverviewHandler(pool))
	r.Get("/admin/tenants/{tenantID}/devices", handlers.TenantDevicesHandler(pool))
	r.Get("/admin/tenants/{tenantID}/devices/{deviceID}/software-observation-comparison", handlers.SoftwareObservationComparisonHandler(pool))
	r.Delete("/admin/tenants/{tenantID}/devices/{deviceID}", handlers.DeleteDeviceHandler(pool))
	r.Get("/admin/tenants/{tenantID}/findings", handlers.TenantFindingsHandler(pool))
	r.Get("/admin/tenants/{tenantID}/export", handlers.TenantExportHandler(pool)) // PAT-136 — GDPR data export bundle
	r.Get("/admin/tenants/{tenantID}/ce-status", handlers.TenantCEStatusHandler(pool))
	r.Get("/admin/tenants/{tenantID}/os-update-status", handlers.TenantOSUpdateStatusHandler(pool)) // PAT-1806
	r.Put("/admin/tenant-attestations/{tenantID}/{controlID}", handlers.TenantAttestationPutHandler(pool))
	r.Get("/admin/devices/{deviceID}", handlers.DeviceDetailHandler(pool))
	r.Get("/admin/devices/{deviceID}/apps", handlers.DeviceAppsHandler(pool))
	// PAT-781: per-device app-removal task queue — operator list / queue / cancel.
	r.Get("/admin/devices/{deviceID}/removals", handlers.DeviceRemovalsListHandler(pool))
	r.Post("/admin/devices/{deviceID}/removals", handlers.DeviceRemovalsCreateHandler(pool))
	r.Delete("/admin/devices/{deviceID}/removals/{taskID}", handlers.DeviceRemovalsCancelHandler(pool))
	r.Get("/admin/tenant/{tenant_id}/certs", handlers.TenantCertsHandler(pool))
	r.Put("/admin/agent-config/{tenantID}", handlers.AdminAgentConfigPutHandler(pool, signingKey))
	// PAT-1238: incident-safe, lossless mutation of one blocked version. This
	// avoids the general agent-config PUT's full-replace semantics.
	r.Patch("/admin/agent-config/{tenantID}/blocked-versions", handlers.AdminBlockedVersionsPatchHandler(pool))
	r.Post("/admin/agent-versions", handlers.AdminRegisterAgentVersionHandler(pool))
	// PAT-2109: staff-only proposal and explicit review/publish path for exact
	// IDE/runtime CPE mappings. Tenant observations never reach these routes.
	r.Post("/admin/tooling-vulnerability-mappings", handlers.AdminToolingVulnerabilityMappingCreateHandler(pool))
	r.Post("/admin/tooling-vulnerability-mappings/{id}/review", handlers.AdminToolingVulnerabilityMappingReviewHandler(pool))
	r.Post("/admin/agent-releases/promote", handlers.AdminAgentReleasePromoteHandler(pool))
	r.Post("/admin/agent-releases/evidence", handlers.AdminAgentReleaseEvidenceHandler(pool))
	r.Post("/admin/agent-releases/observations", handlers.AdminAgentReleaseObservationHandler(pool))
	r.Post("/admin/tenants/{tenantID}/agent-releases/p0", handlers.AdminAgentReleaseP0Handler(pool))
	// PAT-1260: authenticated artifact upload backing
	// GET /v1/agent/artifact/download above. Same ADMIN_API_TOKEN as the
	// route above it — enforced by requireInternalToken, not by the handler
	// itself. Streams straight to disk; see AdminUploadAgentArtifactHandler.
	r.Put("/admin/agent-versions/{platform}/{channel}/{version}/artifact", handlers.AdminUploadAgentArtifactHandler(artifactDir))
	r.Get("/admin/tenants/{tenantID}/metering", handlers.MeteringFleetHandler(pool))
	r.Get("/admin/tenants/{tenantID}/metering/{appName}", handlers.MeteringBreakdownHandler(pool))
	// PAT-650: app-update policy management requires the Patch tier.
	r.With(needsPatch).Get("/admin/tenant-app-policy/{tenantID}", handlers.AppUpdatePolicyListHandler(pool))
	r.With(needsPatch).Put("/admin/tenant-app-policy/{tenantID}/default", handlers.AppUpdatePolicyDefaultPutHandler(pool))
	r.With(needsPatch).Put("/admin/tenant-app-policy/{tenantID}/apps", handlers.AppUpdatePolicyAppPutHandler(pool))
	r.With(needsPatch).Delete("/admin/tenant-app-policy/{tenantID}/apps/{policyID}", handlers.AppUpdatePolicyAppDeleteHandler(pool))
	r.Get("/admin/tenants/{tenantID}/apps", handlers.TenantAppsHandler(pool))
	// PAT-650: allowlist / uninstall management requires the Patch tier.
	r.With(needsPatch).Get("/admin/tenants/{tenantID}/allowlist", handlers.TenantAllowlistGetHandler(pool))
	r.With(needsPatch).Post("/admin/tenants/{tenantID}/allowlist", handlers.TenantAllowlistAddHandler(pool, notifier))
	r.With(needsPatch).Put("/admin/tenants/{tenantID}/allowlist/{entryID}", handlers.TenantAllowlistUpdateHandler(pool, notifier))
	r.With(needsPatch).Delete("/admin/tenants/{tenantID}/allowlist/{entryID}", handlers.TenantAllowlistDeleteHandler(pool))
	r.With(needsPatch).Put("/admin/tenants/{tenantID}/allowlist-policy", handlers.TenantAllowlistPolicyHandler(pool))
	r.With(needsPatch).Get("/admin/tenants/{tenantID}/allowlist/scan", handlers.TenantAllowlistScanHandler(pool))
	// PAT-826: per-tenant browser-extension policy store + estate scan (pure policy plane).
	r.With(needsPatch).Get("/admin/tenants/{tenantID}/extension-policies", handlers.TenantExtensionPoliciesGetHandler(pool))
	r.With(needsPatch).Post("/admin/tenants/{tenantID}/extension-policies", handlers.TenantExtensionPolicyAddHandler(pool))
	r.With(needsPatch).Put("/admin/tenants/{tenantID}/extension-policies/{entryID}", handlers.TenantExtensionPolicyUpdateHandler(pool))
	r.With(needsPatch).Delete("/admin/tenants/{tenantID}/extension-policies/{entryID}", handlers.TenantExtensionPolicyDeleteHandler(pool))
	r.With(needsPatch).Get("/admin/tenants/{tenantID}/extension-policies/scan", handlers.TenantExtensionPolicyScanHandler(pool))
	// PAT-832: per-tenant browser-extension removal request queue ("Remove now").
	r.With(needsPatch).Get("/admin/tenants/{tenantID}/extension-removals", handlers.TenantExtensionRemovalsGetHandler(pool))
	r.With(needsPatch).Post("/admin/tenants/{tenantID}/extension-removals", handlers.TenantExtensionRemovalCreateHandler(pool))
	r.With(needsPatch).Delete("/admin/tenants/{tenantID}/extension-removals/{requestID}", handlers.TenantExtensionRemovalCancelHandler(pool))
	// PAT-659 / PAT-660: per-tenant Self-Service App Catalogue — retired
	// PAT-1561 (tenant_catalogue dropped; see migrations/0121_retire_tenant_catalogue.sql).
	// PAT-2249: the PAT-1538 tenant execution-policy routes were retired with
	// the rest of the catalogue review pipeline. The table stays, unread,
	// until a separate migration drops it.
	// PAT-631 — Shadow IT detection
	r.Get("/admin/shadow-it/catalogue", handlers.ShadowITCatalogueHandler(pool))
	r.Get("/admin/tenants/{tenantID}/shadow-it/findings", handlers.ShadowITFindingsHandler(pool))
	r.Put("/admin/tenants/{tenantID}/shadow-it/{label}", handlers.ShadowITPolicyPutHandler(pool))
	r.Get("/admin/health", handlers.NewHealthHandler(pool, backupHealthDir, notifier).ServeHTTP)
	r.Get("/admin/service-exceptions", handlers.NewServiceExceptionsHandler(pool, backupHealthDir).ServeHTTP)
	// PAT-710: Ops panel endpoints.
	r.Get("/admin/ops/version", handlers.OpsVersionHandler(pool))
	r.Get("/admin/ops/partitions", handlers.OpsPartitionsHandler(pool))
	// PAT-1872: bounded, estate-wide evidence for retiring HMAC compatibility
	// forms. This inherits the internal router's ADMIN_API_TOKEN middleware and
	// contains no tenant or device identifiers.
	r.Get("/admin/ops/hmac-compatibility", handlers.HMACCompatibilityTelemetryHandler(pool))
	// PAT-993: patch/reboot/timer-drift facts, read from local disk (this
	// binary and patched-maintenance-facts.timer both run on api-01).
	r.Get("/admin/ops/maintenance", handlers.OpsMaintenanceHandler(maintenanceFactsPath))
	r.Get("/admin/metrics/proxy", handlers.PrometheusProxyHandler())
	r.Post("/admin/devices/{deviceID}/credentials", handlers.IssueDeviceCredentialHandler(pool))
	r.Get("/admin/tenants/{tenantID}/enrolled-devices", handlers.TenantEnrolledDevicesHandler(pool))
	r.Post("/admin/devices/{deviceID}/revoke", handlers.RevokeDeviceHandler(pool))
	r.Post("/admin/tenants/{tenantID}/ca", handlers.ProvisionTenantCAHandler(pool))
	r.Post("/admin/tenants/{tenantID}/bootstrap-tokens", handlers.MintBootstrapTokenHandler(pool))
	// PAT-548: contract-spec alias for the enrollment-token mint endpoint.
	r.Post("/v1/admin/tenants/{tenantID}/enrollment-tokens", handlers.MintBootstrapTokenHandler(pool))
	// PAT-2287: list live tokens and revoke an unused one. No /v1/admin alias:
	// the mint's alias exists only because the PAT-548 contract named that
	// path, and no contract names these two.
	r.Get("/admin/tenants/{tenantID}/bootstrap-tokens", handlers.ListBootstrapTokensHandler(pool))
	r.Post("/admin/tenants/{tenantID}/bootstrap-tokens/{tokenID}/revoke", handlers.RevokeBootstrapTokenHandler(pool))
	r.Get("/admin/tenants/{tenantID}/cve-findings", handlers.TenantCVEFindingsHandler(pool))
	r.Get("/admin/tenants/{tenantID}/cve-findings/{cveID}/devices", handlers.TenantCVEFindingDevicesHandler(pool))
	r.Get("/admin/devices/{deviceID}/cve-findings", handlers.DeviceCVEFindingsHandler(pool))
	r.Post("/admin/import-scan/cve.pdf", handlers.ImportCVEScanHandler(pool))
	// PAT-602 — Application Control policy CRUD
	// PAT-650: Application Control requires the Full Endpoint Management tier.
	r.With(needsFullEndpoint).Get("/admin/tenants/{tenantID}/app-control", handlers.AppControlGetHandler(pool))
	r.With(needsFullEndpoint).Put("/admin/tenants/{tenantID}/app-control/admins", handlers.AppControlAdminsPutHandler(pool))
	r.With(needsFullEndpoint).Put("/admin/tenants/{tenantID}/app-control/allowlist", handlers.AppControlAllowlistPutHandler(pool))
	r.Get("/admin/tenants/{tenantID}/app-policies", handlers.TenantAppPoliciesGetHandler(pool))
	r.Put("/admin/tenants/{tenantID}/app-policies", handlers.TenantAppPoliciesPutHandler(pool, notifier))
	r.Delete("/admin/tenants/{tenantID}/app-policies/{entryID}", handlers.TenantAppPoliciesDeleteHandler(pool))
	r.Get("/admin/tenants/{tenantID}/app-policy-drift", handlers.TenantAppPolicyDriftHandler(pool))
	// PAT-1801 — protected software list (server-side enforcement lives at
	// each governance write path, e.g. TenantAppPoliciesPutHandler above;
	// these two routes are the only mutations to the protection list itself).
	r.Post("/admin/tenants/{tenantID}/protected-software", handlers.ProtectedSoftwareAddHandler(pool))
	r.Post("/admin/tenants/{tenantID}/protected-software/{baselineID}/override-remove", handlers.ProtectedSoftwareOverrideRemoveHandler(pool))
	// PAT-1823 — reads for the same list: effective set (baseline merged
	// with tenant additions) and the changelog behind the two writes above.
	r.Get("/admin/tenants/{tenantID}/protected-software", handlers.TenantProtectedSoftwareGetHandler(pool))
	r.Get("/admin/tenants/{tenantID}/protected-software/changes", handlers.TenantProtectedSoftwareChangesHandler(pool))
	// PAT-1824 — software exception register admin surface. Written by a
	// named Patched specialist ("a customer asks, a specialist records");
	// GET /v1/portal/exceptions above is the read-only portal counterpart.
	r.Post("/admin/tenants/{tenantID}/exceptions", handlers.ExceptionCreateHandler(pool))
	r.Post("/admin/tenants/{tenantID}/exceptions/{exceptionID}/accept", handlers.ExceptionAcceptHandler(pool))
	r.Post("/admin/tenants/{tenantID}/exceptions/{exceptionID}/review-date", handlers.ExceptionReviewDateHandler(pool))
	// PAT-1598 — authorised removal, platform data model only. Every route
	// is on the internal listener behind ADMIN_API_TOKEN, and there is
	// deliberately no agent-facing counterpart: an authorised campaign is a
	// governance record for the customer's own management platform to act
	// on, never an instruction queued for an endpoint. See
	// internal/handlers/removal_campaigns.go for why that is a structural
	// property here rather than a capability flag.
	r.Post("/admin/tenants/{tenantID}/removal-campaigns", handlers.RemovalCampaignCreateHandler(pool))
	r.Get("/admin/tenants/{tenantID}/removal-campaigns", handlers.RemovalCampaignListHandler(pool))
	r.Get("/admin/tenants/{tenantID}/removal-campaigns/{campaignID}", handlers.RemovalCampaignGetHandler(pool))
	r.Post("/admin/tenants/{tenantID}/removal-campaigns/{campaignID}/dry-run", handlers.RemovalCampaignDryRunHandler(pool))
	r.Post("/admin/tenants/{tenantID}/removal-campaigns/{campaignID}/authorize", handlers.RemovalCampaignAuthorizeHandler(pool))
	r.Post("/admin/tenants/{tenantID}/removal-campaigns/{campaignID}/cancel", handlers.RemovalCampaignCancelHandler(pool))
	// PAT-1595 — device lifecycle and reconciliation (upload + reconciliation
	// + six-state classification vertical slice).
	r.Post("/admin/tenants/{tenantID}/device-uploads", handlers.DeviceUploadListHandler(pool))
	r.Get("/admin/tenants/{tenantID}/device-lifecycle", handlers.DeviceLifecycleHandler(pool))
	r.Get("/admin/tenants/{tenantID}/device-lifecycle/thresholds", handlers.DeviceLifecycleThresholdsGetHandler(pool))
	r.Put("/admin/tenants/{tenantID}/device-lifecycle/thresholds", handlers.DeviceLifecycleThresholdsPutHandler(pool))
	// PAT-1825 — disposition records (decommissioned/on-leave/lost/
	// unaccounted), append-only-with-supersede. Creating a disposition for a
	// device that already has a live one corrects it (supersede), rather
	// than erroring or duplicating — see internal/handlers/device_dispositions.go.
	r.Post("/admin/tenants/{tenantID}/device-dispositions", handlers.DeviceDispositionCreateHandler(pool))
	r.Get("/admin/tenants/{tenantID}/device-dispositions", handlers.DeviceDispositionListHandler(pool))
	// PAT-1829 — findings disposition tracking (acknowledged/risk_accepted/
	// closed), append-only-with-supersede, covering both CIS and CVE
	// findings via a finding_kind discriminator. Platform half only —
	// dashboard UI is a separate ticket. See
	// internal/handlers/finding_dispositions.go.
	r.Post("/admin/tenants/{tenantID}/finding-dispositions", handlers.FindingDispositionCreateHandler(pool))
	r.Get("/admin/tenants/{tenantID}/finding-dispositions", handlers.FindingDispositionListHandler(pool))
	// PAT-1878 — neutral CIS/CVE/software finding lifecycle. Current state is
	// a projection; history is the immutable audit ledger.
	r.Get("/admin/tenants/{tenantID}/finding-lifecycle", handlers.FindingLifecycleCurrentHandler(pool))
	r.Get("/admin/tenants/{tenantID}/finding-lifecycle/history", handlers.FindingLifecycleHistoryHandler(pool))
	// PAT-1549 — remediation artefact generation for advisory CIS/config
	// findings. "Applied" status is never set by a route here — see
	// internal/extractor/upsert.go's markArtefactsApplied.
	r.Post("/admin/tenants/{tenantID}/remediation-artefacts", handlers.RemediationArtefactGenerateHandler(pool))
	r.Get("/admin/tenants/{tenantID}/remediation-artefacts", handlers.RemediationArtefactListHandler(pool))
	r.Get("/admin/tenants/{tenantID}/remediation-artefacts/{artefactID}", handlers.RemediationArtefactGetHandler(pool))
	r.Get("/admin/tenants/{tenantID}/agent-logs", handlers.AdminAgentLogsListHandler(pool))
	r.Get("/admin/tenants/{tenantID}/agent-logs/{deviceID}/{requestID}", handlers.AdminAgentLogFetchHandler(pool))
	r.Get("/admin/tenants/{tenantID}/enforcement-audit", handlers.EnforcementAuditGetHandler(pool))
	// PAT-1022: tenant-wide, date-range-bounded read over audit_events (POST
	// /v1/events' durable store) — see internal/handlers/audit_events_admin.go.
	r.Get("/admin/tenants/{tenantID}/audit-events", handlers.AuditEventsAdminHandler(pool))
	// PAT-1684: staff-visible read over PAT-1664's Intune config diff engine
	// (internal/intune/diff.go) — filterable by object, kind of change and
	// date range; see internal/handlers/intune_config_changes.go.
	r.Get("/admin/tenants/{tenantID}/intune-config-changes", handlers.IntuneConfigChangesHandler(pool))
	r.Post("/admin/agent-logs/purge", handlers.AdminAgentLogsPurgeHandler(pool))
	r.Get("/admin/tenants/{tenantID}/needs-attention", handlers.NeedsAttentionHandler(pool))
	r.Get("/admin/tenants/{tenantID}/new-apps", handlers.TenantNewAppsGetHandler(pool))
	r.Put("/admin/tenants/{tenantID}/new-apps/{id}", handlers.TenantNewAppsPutHandler(pool))
	// PAT-117 — patching rings
	r.Get("/admin/tenants/{tenantID}/ring-config", handlers.RingConfigGetHandler(pool))
	r.Put("/admin/tenants/{tenantID}/ring-config", handlers.RingConfigPutHandler(pool))
	r.Get("/admin/tenants/{tenantID}/ring-devices", handlers.RingDevicesListHandler(pool))
	r.Put("/admin/tenants/{tenantID}/ring-devices/{deviceID}", handlers.RingDeviceOverridePutHandler(pool))
	r.Get("/admin/tenants/{tenantID}/ring-rollouts", handlers.RingRolloutStatusHandler(pool))
	r.Post("/admin/tenants/{tenantID}/ring-rollouts/{id}/pause", handlers.RingRolloutPauseHandler(pool))
	r.Post("/admin/tenants/{tenantID}/ring-rollouts/{id}/resume", handlers.RingRolloutResumeHandler(pool))
	r.Post("/admin/tenants/{tenantID}/ring-rollouts/{id}/skip", handlers.RingRolloutSkipHandler(pool))
	r.Post("/admin/tenants/{tenantID}/ring-rollouts/{id}/emergency", handlers.RingRolloutEmergencyHandler(pool))
	// PAT-2246: mandatory-install evaluation, emergency and retry were
	// retired with the signed catalogue they verified against. The read-only
	// history of intents already recorded stays until the tables are dropped.
	r.Get("/admin/tenants/{tenantID}/mandatory-install-intents", handlers.MandatoryInstallIntentsGetHandler(pool))
	// PAT-595 / PAT-642 — automations
	r.Get("/admin/automations", handlers.AutomationsListHandler(pool, backupHealthDir))
	r.Get("/admin/automations/{jobName}/runs", handlers.AutomationRunsHandler(pool))
	r.Post("/admin/automations/{jobName}/record", handlers.AutomationRecordHandler(pool))
	// PAT-370 — report delivery infrastructure
	// Delivery contacts
	r.Get("/admin/tenants/{tenantID}/delivery-contacts", handlers.ListDeliveryContactsHandler(pool))
	r.Post("/admin/tenants/{tenantID}/delivery-contacts", handlers.CreateDeliveryContactHandler(pool))
	r.Put("/admin/tenants/{tenantID}/delivery-contacts/{id}", handlers.UpdateDeliveryContactHandler(pool))
	r.Delete("/admin/tenants/{tenantID}/delivery-contacts/{id}", handlers.DeleteDeliveryContactHandler(pool))
	// Report schedules
	r.Get("/admin/tenants/{tenantID}/report-schedules", handlers.ListReportSchedulesHandler(pool))
	r.Post("/admin/tenants/{tenantID}/report-schedules", handlers.CreateReportScheduleHandler(pool))
	r.Put("/admin/tenants/{tenantID}/report-schedules/{id}", handlers.UpdateReportScheduleHandler(pool))
	r.Delete("/admin/tenants/{tenantID}/report-schedules/{id}", handlers.DeleteReportScheduleHandler(pool))
	// Report records — static sub-paths before {id} to avoid chi ambiguity
	r.Post("/admin/tenants/{tenantID}/report-records/generate", handlers.GenerateReportHandler(pool))
	r.Get("/admin/tenants/{tenantID}/report-records", handlers.ListReportRecordsHandler(pool))
	r.Get("/admin/tenants/{tenantID}/report-records/{id}/download", handlers.DownloadReportHandler(pool))
	// PAT-1405: staff-only authored assessment approval and recipient-link issue.
	r.Post("/admin/tenants/{tenantID}/assessment-artifacts/approve", handlers.ApproveAssessmentArtifactHandler(pool))
	r.Post("/admin/tenants/{tenantID}/assessment-artifacts/{artifactID}/download-tokens", handlers.IssueAssessmentDownloadTokenHandler(pool))
	// The Access-bypassed dashboard recipient route redeems over this
	// Tailscale/admin-token boundary. Do not expose a second public platform
	// redemption surface.
	//
	// Accepted P3 (prior round): the plaintext single-use token travels in
	// the URL path here, so it can land in access/proxy logs. A request
	// body or header would avoid that, but this is accepted for now given
	// the token's single-use (burned on first successful redemption) and
	// short-expiry (<=720h, default 168h) mitigations already in place.
	r.Post("/admin/assessment-download-tokens/{token}/redeem", handlers.RedeemAssessmentDownloadTokenHandler(pool))
	// PAT-2015: software category tags, global match rules and product
	// tags, every write audited. Not under /admin/catalogue/*, which is the
	// quarantined legacy package catalogue.
	handlers.MountSoftwareCategoryAdminRoutes(r, pool)
	// PAT-2404: staff review of an observed, signed software identity into a
	// reviewed catalogue alias, and its retirement. Internal router only;
	// every write audited. Not under /admin/catalogue/*, which is the
	// quarantined legacy package catalogue.
	handlers.MountSoftwareCatalogueAdminRoutes(r, pool)
	// PAT-2046: Homebrew CPE review queue curation (PAT-2023's global,
	// tenant-free backlog), every write audited.
	handlers.MountHomebrewReviewAdminRoutes(r, pool)
	handlers.MountCPEProposalAdminRoutes(r, pool) // PAT-2138
	// PAT-2147: software lifecycle mappings (staff review) and the
	// endoflife.date refresh, every mapping write audited.
	handlers.MountLifecycleAdminRoutes(r, pool)
	// PAT-2249: the catalogue review, hosting and discovery pipeline
	// (/admin/catalogue/{candidates,products,target-operations,review,
	// review/bulk,add,dismiss,revoke,pipeline-ready,state,promote,demote,
	// vendor-origins} and /admin/discovery/*) is retired. Its tables stay,
	// unread, until a separate migration drops them.
	// PAT-134 — outbound webhooks for tenant integrations
	r.Get("/admin/tenants/{tenantID}/webhooks", handlers.WebhookListHandler(pool))
	r.Post("/admin/tenants/{tenantID}/webhooks", handlers.WebhookCreateHandler(pool))
	r.Put("/admin/tenants/{tenantID}/webhooks/{webhookID}", handlers.WebhookUpdateHandler(pool))
	r.Delete("/admin/tenants/{tenantID}/webhooks/{webhookID}", handlers.WebhookDeleteHandler(pool))
	r.Get("/admin/tenants/{tenantID}/webhooks/{webhookID}/deliveries", handlers.WebhookDeliveriesHandler(pool))
	r.Post("/admin/tenants/{tenantID}/webhooks/{webhookID}/test", handlers.WebhookTestHandler(pool))
	// PAT-1888 — tenant notification channels for finding, stale-evidence and
	// verification events. Separate from the PAT-134 routes above: those
	// configure the v1 score/vulnerability webhooks, these configure the
	// finding-event channels (webhook or email) that internal/notifications
	// delivers, with per-channel severity thresholds and a dead-letter view.
	// PAT-2009: per-tenant unapproved software alert and new software
	// notification settings.
	r.Get("/admin/tenants/{tenantID}/software-notifications", handlers.AdminSoftwareNotificationsGetHandler(pool))
	r.Put("/admin/tenants/{tenantID}/software-notifications", handlers.AdminSoftwareNotificationsPutHandler(pool))
	// PAT-2097: operator queue of unapproved software alerts across tenants,
	// and the operator acknowledgement.
	r.Get("/admin/software-alerts", handlers.AdminSoftwareAlertsHandler(pool))
	r.Post("/admin/tenants/{tenantID}/software-alerts/{id}/acknowledge", handlers.AdminSoftwareAlertAcknowledgeHandler(pool))
	r.Get("/admin/tenants/{tenantID}/notification-channels", handlers.NotificationChannelListHandler(pool))
	r.Post("/admin/tenants/{tenantID}/notification-channels", handlers.NotificationChannelCreateHandler(pool))
	r.Put("/admin/tenants/{tenantID}/notification-channels/{channelID}", handlers.NotificationChannelUpdateHandler(pool))
	r.Delete("/admin/tenants/{tenantID}/notification-channels/{channelID}", handlers.NotificationChannelDeleteHandler(pool))
	r.Get("/admin/tenants/{tenantID}/notification-channels/{channelID}/deliveries", handlers.NotificationChannelDeliveriesHandler(pool))
	r.Post("/admin/tenants/{tenantID}/notification-channels/{channelID}/test", handlers.NotificationChannelTestHandler(pool, notificationDispatcher))
	r.Get("/admin/tenants/{tenantID}/notification-deliveries", handlers.NotificationDeliveriesHandler(pool))
	// PAT-693 — portal user (email → tenant) mapping CRUD
	r.Get("/admin/portal-users", handlers.PortalUsersListHandler(pool))
	r.Post("/admin/portal-users", handlers.PortalUserCreateHandler(pool, ro.operatorOwnerRole))
	r.Delete("/admin/portal-users/{email}", handlers.PortalUserDisableHandler(pool))
	// PAT-127 — tenant email-domain (domain → tenant) auto-binding CRUD for portal SSO
	r.Get("/admin/tenant-email-domains", handlers.TenantEmailDomainsListHandler(pool))
	r.Post("/admin/tenant-email-domains", handlers.TenantEmailDomainCreateHandler(pool))
	r.Delete("/admin/tenant-email-domains/{domain}", handlers.TenantEmailDomainDisableHandler(pool))
	// PAT-676: dashboard-login signal receiver and on-demand health-signals recompute.
	r.Put("/admin/tenant/{tenantID}/signal", handlers.HealthSignalHandler(pool))
	return r
}

// requireInternalToken guards the internal /admin/* surface with a shared
// ADMIN_API_TOKEN, presented as "Authorization: Bearer <token>" and compared
// in constant time behind the existing Tailscale/Caddy boundary. The Bearer
// scheme is required (PAT-2408): the token on its own is refused with 401. The dedicated catalogue-publisher credential and
// its route were retired with the signed catalogue (PAT-2246); every admin
// route now takes the admin token.
//
//   - /health and /metrics remain open (liveness + Prometheus scraping).
//   - If the token is unset the protected surface fails CLOSED (503) rather
//     than open, so a missing config can never silently expose a route.
func requireInternalToken(adminToken string) func(http.Handler) http.Handler {
	// Precompute a fixed-width SHA-256 digest once. This keeps each comparison
	// constant-time and independent of the supplied token length.
	adminWant := sha256.Sum256([]byte(adminToken))
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/health" || r.URL.Path == "/metrics" {
				next.ServeHTTP(w, r)
				return
			}

			if adminToken == "" {
				http.Error(w, "admin API auth not configured", http.StatusServiceUnavailable)
				return
			}
			presented, schemeOK := bearerCredential(r.Header.Get("Authorization"))
			got := sha256.Sum256([]byte(presented))
			// The digest comparison runs whether or not the scheme was
			// present, and both results are combined without branching on
			// the comparison, so the scheme check adds no early exit.
			if subtle.ConstantTimeCompare(adminWant[:], got[:])&schemeOK != 1 {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// bearerCredential splits an Authorization header value into the credential
// that follows the Bearer scheme. ok is 1 only when the value begins with the
// scheme name "Bearer" (case-insensitive, RFC 9110 section 11.1) followed by
// exactly one space; the credential is everything after that space, verbatim,
// with no whitespace trimmed.
//
// PAT-2408: the scheme is required. A bare token used to be accepted because
// the prefix was stripped only if present. When the scheme is absent the whole
// value is returned with ok == 0, so the caller still hashes and compares the
// same amount of input as before and rejects on ok, never on a shortcut.
//
// Only the fixed, public scheme prefix is inspected here, and the header is
// the caller's own input, so nothing in this function depends on the
// configured secret. The header is never logged.
func bearerCredential(header string) (credential string, ok int) {
	const prefix = "Bearer "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return header, 0
	}
	return header[len(prefix):], 1
}

// requestMetrics records per-request Prometheus metrics.
// Uses the chi route pattern as the "route" label so UUIDs in paths don't
// explode cardinality (e.g. "/admin/tenant-rules/{tenantID}/{ruleID}" not
// "/admin/tenant-rules/65a88424-.../f3b2...").
func requestMetrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		route := "other"
		if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
			route = rc.RoutePattern()
		}
		status := strconv.Itoa(ww.Status())
		metrics.HTTPRequestsTotal.WithLabelValues(route, status).Inc()
		metrics.HTTPRequestDuration.WithLabelValues(route, status).Observe(time.Since(start).Seconds())
	})
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","version":"` + version + `"}` + "\n"))
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

type config struct {
	DatabaseURL     string
	ListenPublic    string
	ListenInternal  string
	RateLimitRPM    int           // per-tenant sustained requests per minute
	RateLimitBurst  int           // per-tenant burst size
	ReplaySkew      time.Duration // ±window for timestamp freshness
	CredentialGrace time.Duration // grace window when rotating credentials
	BackupHealthDir string        // dir of per-job backup heartbeat JSON files

	// ArtifactDir (PAT-1260) is PATCHED_ARTIFACT_DIR — the root
	// <platform>/<channel>/<version>/artifact.bin now lives under, backing
	// PUT /admin/agent-versions/.../artifact and
	// GET /v1/agent/artifact/download. Already in the systemd unit's
	// ReadWritePaths and owned by patched:patched on patched-api-01.
	ArtifactDir   string
	AdminAPIToken string // shared secret required on the internal /admin/* routes

	// PAT-993 — path to the local maintenance-facts snapshot written hourly
	// by patched-maintenance-facts.timer on this same box; served verbatim
	// by GET /admin/ops/maintenance.
	MaintenanceFactsPath string

	// PAT-693 — per-identity limits on the public /v1/portal/* surface.
	PortalRateLimitRPM   int
	PortalRateLimitBurst int
	// FeedbackEnabled gates both portal feedback routes. Default false keeps the
	// surface absent until Linear delivery is explicitly configured.
	FeedbackEnabled bool
	// PAT-2036: shared secret configured on the Linear Issue webhook. Unset
	// fails closed with 503 before the body is parsed or any database write.
	LinearWebhookSecret string

	// PAT-453 — dedicated per-tenant limit on POST /v1/portal/enrolment,
	// separate from (and much tighter than) PortalRateLimitRPM above.
	PortalEnrolMintsPerWindow int           // cap per PortalEnrolWindow
	PortalEnrolWindow         time.Duration // window the cap above applies over

	// PAT-954 — dedicated credential + rate limit for POST /v1/backup-health
	// (portal-01's backup-heartbeat HTTPS ingest path). Deliberately separate
	// from AdminAPIToken and from tenant bearer tokens.
	BackupHeartbeatToken          string
	BackupHeartbeatRateLimitRPM   int
	BackupHeartbeatRateLimitBurst int
	// BackupHeartbeatAllowedJobs is the exhaustive set of "job" ids this
	// credential may write. PATCHED_BACKUP_HEALTH_DIR is shared with other
	// hosts' heartbeat files (e.g. prod-01's prod-r2.json, shipped over its
	// own scp channel) — without this allowlist the portal-01 credential
	// could overwrite any of them, including painting a genuinely failing
	// job green.
	BackupHeartbeatAllowedJobs []string

	// PAT-2145 — Jamf Pro webhook ingest. The public origin the portal's
	// setup page builds the webhook URL from, and the per-webhook-ID limit
	// applied before any database read.
	JamfWebhookPublicBaseURL  string
	JamfWebhookRateLimitRPM   int
	JamfWebhookRateLimitBurst int
	// Failed webhook authentication: one global bucket, and one bucket per
	// client IP, per real webhook ID and for unknown IDs. Never the tenant's.
	JamfWebhookFailedGlobalRPM   int
	JamfWebhookFailedGlobalBurst int
	JamfWebhookFailedKeyRPM      int
	JamfWebhookFailedKeyBurst    int

	// PAT-2529: POST /v1/trial/provision volume limits, in requests per
	// hour: per client address (CF-Connecting-IP) and for the whole route.
	TrialProvisionPerIPPerHour  int
	TrialProvisionGlobalPerHour int

	// PAT-1883: self-service organisation sign-up and access management.
	// Enabled is SELF_SERVICE_SIGNUP_ENABLED, default false: every route the
	// feature adds answers 404 until it is switched on. Disabling it again is
	// the rollback; no tenant, membership or audit row is touched.
	SelfServiceSignup handlers.PortalSignupConfig
}

func loadConfig() config {
	return config{
		DatabaseURL:     getenv("DATABASE_URL", ""),
		ListenPublic:    getenv("LISTEN_PUBLIC", "127.0.0.1:8080"),
		ListenInternal:  getenv("LISTEN_INTERNAL", "127.0.0.1:8081"),
		RateLimitRPM:    getenvInt("RATE_LIMIT_RPM", 60),
		RateLimitBurst:  getenvInt("RATE_LIMIT_BURST", 10),
		ReplaySkew:      time.Duration(getenvInt("REPLAY_SKEW_SECONDS", 300)) * time.Second,
		CredentialGrace: time.Duration(getenvInt("CREDENTIAL_GRACE_HOURS", 24)) * time.Hour,
		BackupHealthDir: getenv("PATCHED_BACKUP_HEALTH_DIR", "/srv/backup/health"),
		ArtifactDir:     getenv("PATCHED_ARTIFACT_DIR", "/var/lib/patched-api/artifacts"),
		AdminAPIToken:   getenv("ADMIN_API_TOKEN", ""),

		MaintenanceFactsPath: getenv("PATCHED_MAINTENANCE_FACTS_PATH", "/var/lib/patched/maintenance.json"),

		PortalRateLimitRPM:   getenvInt("PORTAL_RATE_LIMIT_RPM", 120),
		PortalRateLimitBurst: getenvInt("PORTAL_RATE_LIMIT_BURST", 30),
		FeedbackEnabled:      getenvBool("FEEDBACK_ENABLED", false),
		LinearWebhookSecret:  getenv("LINEAR_WEBHOOK_SECRET", ""),

		PortalEnrolMintsPerWindow: getenvInt("PORTAL_ENROL_MINTS_PER_HOUR", 10),
		PortalEnrolWindow:         time.Duration(getenvInt("PORTAL_ENROL_WINDOW_MINUTES", 60)) * time.Minute,

		BackupHeartbeatToken:          getenv("BACKUP_HEARTBEAT_TOKEN", ""),
		BackupHeartbeatRateLimitRPM:   getenvInt("BACKUP_HEARTBEAT_RATE_LIMIT_RPM", 6),
		BackupHeartbeatRateLimitBurst: getenvInt("BACKUP_HEARTBEAT_RATE_LIMIT_BURST", 3),
		BackupHeartbeatAllowedJobs:    getenvCSV("BACKUP_HEARTBEAT_ALLOWED_JOBS", []string{"portal-r2"}),

		JamfWebhookPublicBaseURL:     getenv("JAMF_WEBHOOK_PUBLIC_BASE_URL", "https://api.patched.im"),
		JamfWebhookRateLimitRPM:      getenvInt("JAMF_WEBHOOK_RATE_LIMIT_RPM", 300),
		JamfWebhookRateLimitBurst:    getenvInt("JAMF_WEBHOOK_RATE_LIMIT_BURST", 100),
		JamfWebhookFailedGlobalRPM:   getenvInt("JAMF_WEBHOOK_FAILED_AUTH_GLOBAL_RPM", 600),
		JamfWebhookFailedGlobalBurst: getenvInt("JAMF_WEBHOOK_FAILED_AUTH_GLOBAL_BURST", 200),
		JamfWebhookFailedKeyRPM:      getenvInt("JAMF_WEBHOOK_FAILED_AUTH_RPM", 30),
		JamfWebhookFailedKeyBurst:    getenvInt("JAMF_WEBHOOK_FAILED_AUTH_BURST", 20),

		TrialProvisionPerIPPerHour:  getenvInt("TRIAL_PROVISION_PER_IP_PER_HOUR", handlers.DefaultTrialProvisionPerIPPerHour),
		TrialProvisionGlobalPerHour: getenvInt("TRIAL_PROVISION_GLOBAL_PER_HOUR", handlers.DefaultTrialProvisionGlobalPerHour),

		SelfServiceSignup: handlers.PortalSignupConfig{
			Enabled:                     getenvBool("SELF_SERVICE_SIGNUP_ENABLED", false),
			InvitationTTL:               time.Duration(getenvInt("PORTAL_INVITATION_TTL_HOURS", 168)) * time.Hour,
			InvitationsPerTenantPerHour: getenvInt("PORTAL_INVITATIONS_PER_HOUR", 20),
			OrgCreationsPerHour:         getenvInt("SIGNUP_ORG_CREATIONS_PER_HOUR", 20),
		},
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

// getenvCSV reads a comma-separated env var into a trimmed, non-empty-entry
// slice, falling back to fallback when the var is unset.
func getenvCSV(key string, fallback []string) []string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}
