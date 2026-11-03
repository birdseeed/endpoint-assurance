//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/agentconfig"
	"patched.im/api/internal/db"
	"patched.im/api/internal/handlers"
	"patched.im/api/internal/metrics"
	"patched.im/api/internal/portalauth"
	"patched.im/api/internal/ratelimit"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// testEnv holds the live HTTP test servers and the DB credentials for a test
// tenant created during TestMain.
type testEnv struct {
	pool        *pgxpool.Pool
	publicSrv   *httptest.Server
	internalSrv *httptest.Server

	tenantID      string
	bearerToken   string
	hmacSecretRaw []byte // raw bytes, not b64

	// PAT-693: fake Cloudflare Access IdP for the portal surface. Signs
	// RS256 JWTs that the portalauth.Verifier (pointed at idp.srv's JWKS)
	// accepts — same trust chain as production, minus Cloudflare.
	idp *portalIdP
}

var env *testEnv

const integrationLinearWebhookSecret = "low-entropy-integration-test-secret"

// TestMain spins up a real Postgres (using TEST_DATABASE_URL), applies all
// migrations, creates a test tenant, starts two httptest.Servers (one per
// listener), and runs the test suite.
func TestMain(m *testing.M) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		fmt.Fprintln(os.Stderr, "TEST_DATABASE_URL not set — skipping integration tests")
		os.Exit(0)
	}

	ctx := context.Background()

	pool, err := db.Connect(ctx, dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "db connect: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	if err := applyMigrations(ctx, pool); err != nil {
		fmt.Fprintf(os.Stderr, "migrations: %v\n", err)
		os.Exit(1)
	}

	// Deterministic Ed25519 key for tests — same approach as agent_config_test.go.
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	signingKey, err := agentconfig.KeyFromSeed(seed)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signing key: %v\n", err)
		os.Exit(1)
	}

	metrics.Register()

	rl := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})
	replaySkew := 5 * time.Minute

	// PAT-693: portal surface — fake IdP, verifier, per-identity limiter,
	// and a temp dir for portal-generated report PDFs.
	reportDir, err := os.MkdirTemp("", "patched-portal-reports-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "report temp dir: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(reportDir)
	os.Setenv("REPORT_STORAGE_ROOT", reportDir)

	idp, err := startPortalIdP()
	if err != nil {
		fmt.Fprintf(os.Stderr, "portal idp: %v\n", err)
		os.Exit(1)
	}
	defer idp.srv.Close()
	portalVerifier := portalauth.New(idp.issuer, idp.audience, idp.srv.URL)
	portalRL := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})

	publicRouter := buildPublicRouter(pool, signingKey, rl, replaySkew, portalVerifier, portalRL)
	internalRouter := buildInternalRouterWithLegacyExecutionCompatibilityTestRoutes(pool, signingKey, 24*time.Hour, "")

	publicSrv := httptest.NewServer(publicRouter)
	internalSrv := httptest.NewServer(internalRouter)

	// Create a throw-away test tenant via the internal server.
	tenantID, bearerToken, hmacSecretRaw, err := createTestTenant(internalSrv.URL, "integration-test")
	if err != nil {
		publicSrv.Close()
		internalSrv.Close()
		fmt.Fprintf(os.Stderr, "create test tenant: %v\n", err)
		os.Exit(1)
	}

	env = &testEnv{
		pool:          pool,
		publicSrv:     publicSrv,
		internalSrv:   internalSrv,
		tenantID:      tenantID,
		bearerToken:   bearerToken,
		hmacSecretRaw: hmacSecretRaw,
		idp:           idp,
	}

	code := m.Run()

	publicSrv.Close()
	internalSrv.Close()
	os.Exit(code)
}

// applyMigrations runs all forward migration SQL files in alphabetical order.
// Files ending in _rollback.sql are skipped.
func applyMigrations(ctx context.Context, pool *pgxpool.Pool) error {
	migrationsDir := filepath.Join("..", "migrations")
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	var files []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		if strings.HasSuffix(name, "_rollback.sql") {
			continue
		}
		files = append(files, filepath.Join(migrationsDir, name))
	}
	sort.Strings(files)

	slog.Info("applying migrations", "count", len(files))
	for _, f := range files {
		sql, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read %s: %w", f, err)
		}
		if err := execMigration(ctx, pool, string(sql)); err != nil {
			return fmt.Errorf("exec %s: %w", f, err)
		}
		slog.Info("migration applied", "file", filepath.Base(f))
	}
	return nil
}

// createTestTenant POSTs to /admin/tenants on the internal server, returns
// the raw credentials.
func createTestTenant(internalBase, name string) (tenantID, bearerToken string, hmacSecretRaw []byte, err error) {
	body, _ := json.Marshal(map[string]string{"name": name})
	resp, err := http.Post(internalBase+"/admin/tenants", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return "", "", nil, fmt.Errorf("create tenant returned %d: %s", resp.StatusCode, b)
	}
	var out struct {
		TenantID      string `json:"tenant_id"`
		BearerToken   string `json:"bearer_token"`
		HMACSecretB64 string `json:"hmac_secret_b64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(out.HMACSecretB64)
	if err != nil {
		return "", "", nil, fmt.Errorf("decode hmac secret: %w", err)
	}
	return out.TenantID, out.BearerToken, raw, nil
}

// signedInventoryRequest builds an http.Request for POST /v1/inventory with
// all required auth headers populated from env's test-tenant credentials.
// Each call generates a fresh nonce so multiple calls with the same body are
// all accepted (no replay collisions within the test suite).
func signedInventoryRequest(t *testing.T, body []byte) *http.Request {
	t.Helper()

	nonce := randomHex(16)
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	mac := hmac.New(sha256.New, env.hmacSecretRaw)
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	req, err := http.NewRequest(http.MethodPost, env.publicSrv.URL+"/v1/inventory", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+env.bearerToken)
	req.Header.Set("X-Patched-Signature", sig)
	req.Header.Set("X-Patched-Timestamp", ts)
	req.Header.Set("X-Patched-Nonce", nonce)
	return req
}

// randomHex returns n random bytes as a lowercase hex string.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("rand.Read: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// fixtureData reads a fixture file relative to the integration package dir.
func fixtureData(t *testing.T, dir, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "testdata", "payload-fixtures", dir, name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s/%s: %v", dir, name, err)
	}
	return data
}

// fixtureFiles returns the sorted list of .json filenames in a fixture dir.
func fixtureFiles(t *testing.T, dir string) []string {
	t.Helper()
	dirPath := filepath.Join("..", "testdata", "payload-fixtures", dir)
	entries, err := os.ReadDir(dirPath)
	if err != nil {
		t.Fatalf("read fixture dir %s: %v", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	return names
}

// postInventory sends a pre-built request and returns the response.
func postInventory(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/inventory: %v", err)
	}
	return resp
}

// --------------------------------------------------------------------------
// Router constructors — mirrors main.go but without the Ed25519 key loader
// requirement (we pass a pre-built key). PAT-2539 checks the public route set
// against the production constructor with chi.Walk.
// --------------------------------------------------------------------------

func buildPublicRouter(
	pool *pgxpool.Pool,
	signingKey *agentconfig.SigningKey,
	rl *ratelimit.TenantLimiter,
	replaySkew time.Duration,
	portalVerifier *portalauth.Verifier,
	portalRL *ratelimit.TenantLimiter,
) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	r.Get("/ready", handlers.ReadinessHandler(pool))
	r.Post("/public/linear-webhook", handlers.LinearWebhookHandler(pool, integrationLinearWebhookSecret))
	r.Post("/v1/inventory", handlers.InventoryHandler(pool, rl, replaySkew))
	r.Post("/v1/inventory/enforcement-audit", handlers.EnforcementAuditIngestHandler(pool, rl, replaySkew))
	r.Post("/v1/provenance", handlers.ProvenanceHandler(pool, rl, replaySkew))
	r.Post("/v1/events", handlers.EventsHandler(pool, rl, replaySkew))
	r.Post("/v1/agent-decommission-status", handlers.AgentDecommissionStatusHandler(pool, rl, replaySkew))
	r.Get("/v1/catalogue", handlers.CatalogueHandler())
	r.Get("/v1/posture", handlers.PostureHandler(pool, signingKey, rl, replaySkew))
	r.Post("/v1/agent-logs", handlers.AgentLogsHandler(pool, rl, replaySkew))
	r.Get("/v1/agent/artifact", handlers.AgentArtifactHandler(pool, rl, replaySkew))
	// Artifact storage and backup heartbeat credentials are unconfigured in
	// this harness. Mount the real handlers with their production auth guards.
	r.Get("/v1/agent/artifact/download", handlers.AgentArtifactDownloadHandler(pool, rl, replaySkew, ""))
	r.Head("/v1/agent/artifact/download", handlers.AgentArtifactDownloadHandler(pool, rl, replaySkew, ""))
	r.Post("/v1/backup-health", handlers.BackupHeartbeatIngestHandler("", "", nil, ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})))
	r.Post("/v1/enrol", handlers.EnrolHandler(pool, rl))
	r.Post("/v1/trial/provision", handlers.TrialProvisionHandler(pool, handlers.NewTrialProvisionLimits(handlers.TrialProvisionLimitsConfig{})))
	r.Post("/admin/report-download-tokens/{token}/redeem", handlers.RedeemDownloadTokenHandler(pool))
	r.Get("/v1/agent-config", handlers.AgentConfigHandler(pool, signingKey, rl, replaySkew))
	r.Get("/v1/device/identity", handlers.DeviceIdentityHandler(pool, rl, replaySkew)) // PAT-2424, as in cmd/patched-api
	r.Post("/v1/mandatory-install-status", handlers.MandatoryInstallStatusHandler(pool, rl, replaySkew))
	// Retained queue routes deliberately mirror production's permanent false
	// setting. Compatibility-positive tests use the explicitly named internal
	// test router below and must never change this public harness.
	r.Get("/v1/allowlist/pending-removals", handlers.PendingRemovalsHandler(pool, rl, replaySkew))
	r.Get("/v1/allowlist/pending-installs", handlers.PendingInstallsHandler(pool, rl, replaySkew))
	r.Get("/v1/devices/{deviceID}/removal-tasks/pending", handlers.DeviceRemovalTasksPendingHandler(pool, rl, replaySkew))
	r.Post("/v1/devices/{deviceID}/removal-tasks/report", handlers.DeviceRemovalTasksReportHandler(pool, rl, replaySkew))

	// Enrolment keeps its own per-tenant bucket, shared by both mint routes.
	portalEnrolRL := ratelimit.New(ratelimit.Config{RPM: 6000, Burst: 1000})

	// PAT-1883: self-service sign-up, mounted as in cmd/patched-api and at its
	// production default, which is off: every one of these routes is 404
	// here. The feature's behaviour is tested through the production router
	// in cmd/patched-api, not through this copy.
	signup := handlers.NewPortalSignup(pool, handlers.PortalSignupConfig{})
	r.Route("/v1/portal/signup", func(sr chi.Router) {
		sr.Use(portalauth.SignupMiddleware(portalVerifier, portalRL, portalauth.DBAudit(pool)))
		sr.Get("/state", signup.StateHandler())
		sr.Post("/organisation", signup.CreateOrganisationHandler())
		sr.Post("/invitations/{invitationID}/accept", signup.AcceptInvitationHandler())
	})

	// PAT-693: portal read surface — must mirror main.go exactly.
	r.Route("/v1/portal", func(pr chi.Router) {
		pr.Use(portalauth.Middleware(portalVerifier, portalauth.DBLookup(pool), portalRL, portalauth.DBAudit(pool),
			portalauth.WithServiceTenantCheck(portalauth.DBTenantLive(pool))))
		pr.Get("/overview", handlers.PortalOverviewHandler(pool))
		pr.Get("/ce-readiness", handlers.PortalCEReadinessHandler(pool))
		pr.Get("/protected-software", handlers.PortalProtectedSoftwareHandler(pool))
		pr.Get("/exceptions", handlers.PortalExceptionsHandler(pool))
		pr.Get("/local-admins", handlers.PortalLocalAdminsHandler(pool))
		pr.Get("/driver-findings", handlers.PortalDriverFindingsHandler(pool))
		pr.Post("/enrolment", handlers.PortalEnrolmentGenerateHandler(pool, portalEnrolRL))
		pr.Post("/enrolment-keys", handlers.PortalEnrolmentKeyCreateHandler(pool, portalEnrolRL))
		pr.Get("/enrolment-keys", handlers.PortalEnrolmentKeysListHandler(pool))
		pr.Post("/enrolment-keys/{keyID}/revoke", handlers.PortalEnrolmentKeyRevokeHandler(pool))
		pr.Get("/feedback", handlers.PortalFeedbackHandler(pool, handlers.PortalFeedbackEnabled))
		pr.Post("/feedback", handlers.PortalFeedbackHandler(pool, handlers.PortalFeedbackEnabled))
		pr.Get("/certificates", handlers.PortalCertificatesGetHandler(pool))
		pr.Post("/certificates", handlers.PortalCertificatesWriteHandler(pool))
		pr.Patch("/certificates/{id}", handlers.PortalCertificatesWriteHandler(pool))
		pr.Delete("/certificates/{id}", handlers.PortalCertificatesWriteHandler(pool))
		pr.Get("/insurance-evidence", handlers.PortalInsuranceEvidenceHandler(pool)) // PAT-2258
		pr.Get("/overview/cards", handlers.PortalOverviewCardsHandler(pool))         // PAT-2207
		pr.Get("/control-coverage", handlers.PortalControlCoverageHandler(pool))     // PAT-1857
		pr.Get("/devices", handlers.PortalDevicesHandler(pool))
		pr.Get("/devices/{deviceID}", handlers.PortalDeviceDetailHandler(pool))
		// PAT-2135, mounted as in cmd/patched-api.
		pr.Put("/devices/{deviceID}/retirement", handlers.PortalDeviceRetirementPutHandler(pool))
		pr.Get("/devices/{deviceID}/retirement/history", handlers.PortalDeviceRetirementHistoryHandler(pool))
		pr.Get("/device-list", handlers.PortalDeviceListGetHandler(pool))
		pr.Get("/agent-releases", handlers.PortalAgentReleaseGetHandler(pool))
		pr.Put("/agent-releases", handlers.PortalAgentReleaseWriteHandler(pool))
		pr.Put("/device-list", handlers.PortalDeviceListPutHandler(pool))
		pr.Delete("/device-list", handlers.PortalDeviceListDeleteHandler(pool))
		pr.Delete("/device-list/entries/{entryID}", handlers.PortalDeviceListEntryDeleteHandler(pool))
		pr.Get("/findings", handlers.PortalFindingsHandler(pool))
		// PAT-1969, mounted as in cmd/patched-api (PAT-2107 reads it).
		pr.Get("/finding-lifecycle", handlers.PortalFindingLifecycleCurrentHandler(pool))
		pr.Get("/finding-lifecycle/history", handlers.PortalFindingLifecycleHistoryHandler(pool))
		// PAT-729: unapproved-policy apps aggregated with device counts.
		pr.Get("/unapproved-apps", handlers.PortalUnapprovedAppsHandler(pool))
		// PAT-933: browser extension estate with PAT-826 approval state.
		pr.Get("/extensions", handlers.PortalExtensionsHandler(pool))
		// PAT-1727: applications with a policy state (approved / unapproved /
		// any other configured policy / undecided).
		pr.Get("/applications", handlers.PortalApplicationsHandler(pool))
		// PAT-1869: uncapped, paginated current software inventory and usage
		// evidence. This mirrors the public production route above.
		pr.Get("/software", handlers.PortalSoftwareHandler(pool))
		// PAT-2009: software governance reporting and notification settings.
		pr.Get("/software/new", handlers.PortalNewSoftwareHandler(pool))
		pr.Get("/software/drift", handlers.PortalSoftwareDriftHandler(pool))
		pr.Get("/software/approved", handlers.PortalApprovedSoftwareHandler(pool))
		pr.Get("/software-notifications", handlers.PortalSoftwareNotificationsGetHandler(pool))
		pr.Put("/software-notifications", handlers.PortalSoftwareNotificationsPutHandler(pool))
		pr.Get("/tagged-products", handlers.PortalTaggedProductsHandler(pool)) // PAT-2015
		// PAT-2013: Homebrew tab (PAT-1999), tenant-scoped and read-only.
		pr.Get("/homebrew/summary", handlers.PortalHomebrewSummaryHandler(pool))
		pr.Get("/homebrew/formulae", handlers.PortalHomebrewFormulaeHandler(pool))
		pr.Get("/homebrew/casks", handlers.PortalHomebrewCasksHandler(pool))
		pr.Get("/homebrew/taps", handlers.PortalHomebrewTapsHandler(pool))
		pr.Get("/homebrew/devices", handlers.PortalHomebrewDevicesHandler(pool))
		pr.Get("/homebrew/devices/{deviceID}", handlers.PortalHomebrewDeviceHandler(pool))
		pr.Get("/ai-tooling/summary", handlers.PortalToolingSummaryHandler(pool)) // PAT-2021
		pr.Get("/ai-tooling/devices", handlers.PortalToolingDevicesHandler(pool)) // PAT-2021
		pr.Get("/ai-tooling/devices/{deviceID}/items", handlers.PortalToolingDeviceItemsHandler(pool))
		pr.Get("/reports/catalogue", handlers.PortalReportCatalogueHandler(pool))
		pr.Get("/reports", handlers.PortalReportsListHandler(pool))
		pr.Post("/reports", handlers.PortalReportGenerateHandler(pool))
		// PAT-703: static sub-path before {id} to avoid chi routing ambiguity.
		pr.Get("/reports/schedule", handlers.PortalReportScheduleGetHandler(pool))
		pr.Put("/reports/schedule", handlers.PortalReportSchedulePutHandler(pool))
		pr.Get("/reports/schedules", handlers.PortalReportSchedulesListHandler(pool))
		pr.Get("/reports/schedules/{reportType}", handlers.PortalReportScheduleTypeGetHandler(pool))
		pr.Put("/reports/schedules/{reportType}", handlers.PortalReportScheduleTypePutHandler(pool))
		pr.Get("/reports/software/unsupported", handlers.PortalUnsupportedSoftwareHandler(pool))                // PAT-2147
		pr.Get("/reports/software/unsupported/devices", handlers.PortalUnsupportedSoftwareDevicesHandler(pool)) // PAT-2147
		pr.Get("/reports/software/remote-access", handlers.PortalRemoteAccessHandler(pool))                     // PAT-2148
		pr.Get("/reports/software/remote-access/devices", handlers.PortalRemoteAccessDevicesHandler(pool))      // PAT-2148
		pr.Get("/reports/software/version-sprawl", handlers.PortalVersionSprawlHandler(pool))                   // PAT-2150
		pr.Get("/reports/software/publishers", handlers.PortalSoftwarePublishersHandler(pool))                  // PAT-2152
		pr.Get("/reports/software/publishers/devices", handlers.PortalSoftwarePublishersDevicesHandler(pool))   // PAT-2152
		pr.Get("/reports/software/duplicate-tools", handlers.PortalDuplicateToolsHandler(pool))                 // PAT-2151
		pr.Get("/reports/{id}", handlers.PortalReportDownloadHandler(pool))
		pr.Post("/exports/table-pdf", handlers.PortalTablePDFHandler(pool)) // PAT-2405
		// PAT-2007: the caller's role, and customer software approval writes
		// (admin role only, enforced server-side) with their audit history.
		pr.Get("/me", handlers.PortalMeHandler(pool))
		pr.Get("/software-products", handlers.PortalSoftwareProductsHandler(pool))
		pr.Get("/software-declarations", handlers.PortalSoftwareDeclarationsHandler(pool))
		pr.Post("/software-declarations", handlers.PortalSoftwareDeclarationCreateHandler(pool))
		pr.Get("/software-declarations/{declarationID}", handlers.PortalSoftwareDeclarationsHandler(pool))
		pr.Post("/software-declarations/{declarationID}/resolve", handlers.PortalSoftwareDeclarationResolveHandler(pool))
		pr.Get("/software-declarations/{declarationID}/history", handlers.PortalSoftwareDeclarationHistoryHandler(pool))
		pr.Put("/software-approvals", handlers.PortalSoftwareApprovalsPutHandler(pool))
		pr.Get("/software-approvals/history", handlers.PortalSoftwareApprovalHistoryHandler(pool))
		pr.Get("/software-approvals/history/export", handlers.PortalSoftwareApprovalHistoryExportHandler(pool))
		pr.Get("/software-alerts", handlers.PortalSoftwareAlertsHandler(pool))                             // PAT-2097
		pr.Get("/software-alerts/{id}", handlers.PortalSoftwareAlertHandler(pool))                         // PAT-2097
		pr.Post("/software-alerts/{id}/acknowledge", handlers.PortalSoftwareAlertAcknowledgeHandler(pool)) // PAT-2097
		// PAT-2145, mounted as in cmd/patched-api.
		pr.Get("/mdm/jamf/coverage", handlers.PortalJamfCoverageHandler(pool))
		pr.Get("/mdm/jamf/setup", handlers.PortalJamfSetupGetHandler(pool))
		pr.Put("/mdm/jamf/setup", handlers.PortalJamfSetupPutHandler(pool))
		pr.Post("/mdm/jamf/token", handlers.PortalJamfTokenPostHandler(pool))
		pr.Delete("/mdm/jamf/token", handlers.PortalJamfTokenDeleteHandler(pool))
		pr.Delete("/mdm/jamf/devices", handlers.PortalJamfDevicesDeleteHandler(pool))
		// PAT-1883, mounted as in cmd/patched-api (flag off here: 404).
		pr.Get("/access", signup.AccessListHandler())
		pr.Post("/access/invitations", signup.InvitationCreateHandler())
		pr.Post("/access/invitations/{invitationID}/revoke", signup.InvitationRevokeHandler())
		pr.Put("/access/members/{memberEmail}/role", signup.MemberRoleHandler())
		pr.Post("/access/members/{memberEmail}/disable", signup.MemberDisableHandler())
		pr.Post("/access/members/{memberEmail}/enable", signup.MemberEnableHandler())
	})
	// PAT-2145: Jamf Pro webhook ingest, outside the portal group as in
	// cmd/patched-api. The rate-limit test builds its own tight limiter.
	r.Post("/v1/webhooks/jamf/{webhookID}", handlers.JamfWebhookHandler(pool, handlers.NewJamfWebhookLimits(handlers.JamfWebhookLimitsConfig{
		TenantRPM: 6000, TenantBurst: 1000, FailedGlobalRPM: 6000, FailedGlobalBurst: 1000, FailedKeyRPM: 6000, FailedKeyBurst: 1000,
	})))
	return r
}

// buildInternalRouterWithLegacyExecutionCompatibilityTestRoutes exists only
// for historical integration cases. Production wiring, and buildPublicRouter
// above, always pass false. Do not reuse this router as production evidence.
func buildInternalRouterWithLegacyExecutionCompatibilityTestRoutes(
	pool *pgxpool.Pool,
	signingKey *agentconfig.SigningKey,
	credentialGrace time.Duration,
	backupHealthDir string,
) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Handle("/metrics", promhttp.Handler())
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	r.Get("/admin/service-exceptions", handlers.NewServiceExceptionsHandler(pool, backupHealthDir).ServeHTTP)
	r.Get("/admin/tenants", handlers.ListTenantsHandler(pool))
	r.Post("/admin/tenants", handlers.CreateTenantHandler(pool))
	r.Get("/admin/tenants/revoked", handlers.ListRevokedTenantsHandler(pool))
	r.Delete("/admin/tenants/{tenantID}", handlers.RevokeTenantHandler(pool))
	r.Post("/admin/tenants/{tenantID}/restore", handlers.RestoreTenantHandler(pool))
	r.Delete("/admin/tenants/{tenantID}/purge", handlers.PurgeTenantHandler(pool))
	r.Post("/admin/tenants/{tenantID}/rotate-credentials", handlers.RotateCredentialsHandler(pool, credentialGrace))
	r.Get("/admin/tenant/{tenant_id}/certs", handlers.TenantCertsHandler(pool))
	r.Put("/admin/agent-config/{tenantID}", handlers.AdminAgentConfigPutHandler(pool, signingKey))
	r.Get("/admin/tenants/{tenantID}/devices", handlers.TenantDevicesHandler(pool))
	r.Get("/admin/tenants/{tenantID}/devices/{deviceID}/software-observation-comparison", handlers.SoftwareObservationComparisonHandler(pool))
	r.Get("/admin/tenants/{tenantID}/findings", handlers.TenantFindingsHandler(pool))
	r.Get("/admin/tenants/{tenantID}/export", handlers.TenantExportHandler(pool)) // PAT-136
	r.Get("/admin/tenants/overview", handlers.TenantsOverviewHandler(pool))
	r.Get("/admin/tenants/{tenantID}/cve-findings", handlers.TenantCVEFindingsHandler(pool))
	// PAT-659 / PAT-660 — per-tenant Self-Service App Catalogue CRUD — retired
	// PAT-1561 (tenant_catalogue dropped).
	// PAT-2089: the tier switch that turns App Control on, and the operator
	// extension-policy list and update, as production mounts them.
	r.Put("/admin/tenant-tier/{tenantID}", handlers.SetTenantTierHandler(pool))
	r.Get("/admin/tenants/{tenantID}/extension-policies", handlers.TenantExtensionPoliciesGetHandler(pool))
	r.Put("/admin/tenants/{tenantID}/extension-policies/{entryID}", handlers.TenantExtensionPolicyUpdateHandler(pool))
	r.Get("/admin/tenants/{tenantID}/extension-removals", handlers.TenantExtensionRemovalsGetHandler(pool))
	r.Post("/admin/tenants/{tenantID}/extension-removals", handlers.TenantExtensionRemovalCreateHandler(pool))
	r.Delete("/admin/tenants/{tenantID}/extension-removals/{requestID}", handlers.TenantExtensionRemovalCancelHandler(pool))
	// PAT-1888 — tenant notification channels. The dispatcher here uses the
	// fake transport in notifications_test.go, because the production one is
	// SSRF-hardened and refuses loopback, which is where httptest lives. The
	// SSRF behaviour itself is covered in internal/webhook.
	r.Get("/admin/tenants/{tenantID}/software-notifications", handlers.AdminSoftwareNotificationsGetHandler(pool))            // PAT-2009
	r.Put("/admin/tenants/{tenantID}/software-notifications", handlers.AdminSoftwareNotificationsPutHandler(pool))            // PAT-2009
	r.Get("/admin/software-alerts", handlers.AdminSoftwareAlertsHandler(pool))                                                // PAT-2097
	r.Post("/admin/tenants/{tenantID}/software-alerts/{id}/acknowledge", handlers.AdminSoftwareAlertAcknowledgeHandler(pool)) // PAT-2097
	r.Get("/admin/reports/new-software/{tenantID}.pdf", handlers.NewSoftwareReportHandler(pool))                              // PAT-2009
	r.Get("/admin/reports/software-drift/{tenantID}.pdf", handlers.SoftwareDriftReportHandler(pool))                          // PAT-2009
	r.Get("/admin/reports/approved-software/{tenantID}.pdf", handlers.ApprovedSoftwareReportHandler(pool))                    // PAT-2009
	r.Get("/admin/tenants/{tenantID}/notification-channels", handlers.NotificationChannelListHandler(pool))
	r.Post("/admin/tenants/{tenantID}/notification-channels", handlers.NotificationChannelCreateHandler(pool))
	r.Put("/admin/tenants/{tenantID}/notification-channels/{channelID}", handlers.NotificationChannelUpdateHandler(pool))
	r.Delete("/admin/tenants/{tenantID}/notification-channels/{channelID}", handlers.NotificationChannelDeleteHandler(pool))
	r.Get("/admin/tenants/{tenantID}/notification-channels/{channelID}/deliveries", handlers.NotificationChannelDeliveriesHandler(pool))
	r.Post("/admin/tenants/{tenantID}/notification-channels/{channelID}/test", handlers.NotificationChannelTestHandler(pool, testNotificationDispatcher(pool)))
	r.Get("/admin/tenants/{tenantID}/notification-deliveries", handlers.NotificationDeliveriesHandler(pool))
	// PAT-693 — portal user (email → tenant) mapping CRUD
	r.Get("/admin/portal-users", handlers.PortalUsersListHandler(pool))
	r.Post("/admin/agent-versions", handlers.AdminRegisterAgentVersionHandler(pool))
	r.Post("/admin/agent-releases/promote", handlers.AdminAgentReleasePromoteHandler(pool))
	r.Post("/admin/agent-releases/evidence", handlers.AdminAgentReleaseEvidenceHandler(pool))
	r.Post("/admin/agent-releases/observations", handlers.AdminAgentReleaseObservationHandler(pool))
	r.Post("/admin/tenants/{tenantID}/agent-releases/p0", handlers.AdminAgentReleaseP0Handler(pool))
	// false: SELF_SERVICE_SIGNUP_ENABLED is unset in this harness, so the
	// operator route does not grant the owner role (PAT-1883).
	r.Post("/admin/portal-users", handlers.PortalUserCreateHandler(pool, false))
	r.Delete("/admin/portal-users/{email}", handlers.PortalUserDisableHandler(pool))
	// PAT-127 — tenant email-domain (domain → tenant) auto-binding CRUD
	r.Get("/admin/tenant-email-domains", handlers.TenantEmailDomainsListHandler(pool))
	r.Post("/admin/tenant-email-domains", handlers.TenantEmailDomainCreateHandler(pool))
	r.Delete("/admin/tenant-email-domains/{domain}", handlers.TenantEmailDomainDisableHandler(pool))
	handlers.MountSoftwareCategoryAdminRoutes(r, pool) // PAT-2015
	handlers.MountHomebrewReviewAdminRoutes(r, pool)   // PAT-2046
	handlers.MountCPEProposalAdminRoutes(r, pool)      // PAT-2138
	handlers.MountLifecycleAdminRoutes(r, pool)        // PAT-2147
	r.Post("/admin/tooling-vulnerability-mappings", handlers.AdminToolingVulnerabilityMappingCreateHandler(pool))
	r.Post("/admin/tooling-vulnerability-mappings/{id}/review", handlers.AdminToolingVulnerabilityMappingReviewHandler(pool))
	// PAT-1399 / PAT-2246: keep the real-HTTP integration router aligned with
	// the internal production surface; only the read-only intent history
	// survives the signed catalogue's retirement.
	r.Get("/admin/tenants/{tenantID}/mandatory-install-intents", handlers.MandatoryInstallIntentsGetHandler(pool))
	return r
}

// getAdminJSON issues a GET against the internal (admin) test server.
// PAT-2249: moved here from the retired catalogue_pipeline_test.go, whose
// only surviving caller is homebrew_review_admin_test.go.
func getAdminJSON(t *testing.T, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(env.internalSrv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

// execMigration applies one migration file. A file whose first line is
// "-- migrate:statement-by-statement" holds a statement that cannot run in a
// transaction block (CREATE INDEX CONCURRENTLY, PAT-2021 0167); a
// multi-statement Exec would run it in an implicit transaction, so such a
// file runs one statement at a time on one connection, the way psql -f does
// in deploy.sh. Statements end with ";" at the end of a line.
func execMigration(ctx context.Context, pool *pgxpool.Pool, sql string) error {
	if !strings.HasPrefix(sql, "-- migrate:statement-by-statement") {
		_, err := pool.Exec(ctx, sql)
		return err
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	var stmt strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "--") {
			continue
		}
		stmt.WriteString(line)
		stmt.WriteString("\n")
		if strings.HasSuffix(trimmed, ";") {
			if _, err := conn.Exec(ctx, stmt.String()); err != nil {
				return err
			}
			stmt.Reset()
		}
	}
	if strings.TrimSpace(stmt.String()) != "" {
		_, err := conn.Exec(ctx, stmt.String())
		return err
	}
	return nil
}
