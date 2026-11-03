package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"patched.im/api/internal/auth"
)

func TestHMACCompatibilityAgentVersion_RedactsEverythingExceptBoundedVersion(t *testing.T) {
	const bearer = "bearer-secret-must-not-survive"
	const signature = "signature-must-not-survive"
	const nonce = "nonce-must-not-survive"
	const secret = "hmac-secret-must-not-survive"
	body := []byte(`{
		"agent_version":"0.17.0-rc.1",
		"bearer_token":"` + bearer + `",
		"signature":"` + signature + `",
		"nonce":"` + nonce + `",
		"hmac_secret":"` + secret + `",
		"body":"request-body-must-not-survive"
	}`)

	got := hmacCompatibilityAgentVersion(body)
	if got != "0.17.0-rc.1" {
		t.Fatalf("version = %q, want %q", got, "0.17.0-rc.1")
	}
	for _, sensitive := range []string{bearer, signature, nonce, secret, "request-body-must-not-survive"} {
		if strings.Contains(got, sensitive) {
			t.Fatalf("sanitized telemetry value retained sensitive input %q", sensitive)
		}
	}
}

func TestHMACCompatibilityAgentVersion_UnknownForMissingOrUnsafeValues(t *testing.T) {
	for name, body := range map[string]string{
		"missing":        `{}`,
		"null":           `{"agent_version":null}`,
		"not string":     `{"agent_version":17}`,
		"blank":          `{"agent_version":" "}`,
		"not semver":     `{"agent_version":"bearer super-secret"}`,
		"too long":       `{"agent_version":"123456789012345678901234567890123"}`,
		"malformed json": `{`,
	} {
		t.Run(name, func(t *testing.T) {
			if got := hmacCompatibilityAgentVersion([]byte(body)); got != unknownHMACCompatibilityValue {
				t.Fatalf("got %q, want Unknown", got)
			}
		})
	}
}

func TestBoundedHMACCompatibilityVersion_CapsNovelValues(t *testing.T) {
	if got := boundedHMACCompatibilityVersion("0.17.0", false, maxHMACCompatibilityVersions-1); got != "0.17.0" {
		t.Fatalf("value below cap = %q, want retained", got)
	}
	if got := boundedHMACCompatibilityVersion("0.17.0", false, maxHMACCompatibilityVersions); got != unknownHMACCompatibilityValue {
		t.Fatalf("novel value at cap = %q, want Unknown", got)
	}
	if got := boundedHMACCompatibilityVersion("0.17.0", true, maxHMACCompatibilityVersions); got != "0.17.0" {
		t.Fatalf("existing value at cap = %q, want retained", got)
	}
	if maxHMACCompatibilityRows != 260 {
		t.Fatalf("admin row cap = %d, want 260", maxHMACCompatibilityRows)
	}
}

func TestHMACCompatibilityTelemetryKillSwitch(t *testing.T) {
	t.Setenv("HMAC_COMPATIBILITY_TELEMETRY_ENABLED", "false")
	if hmacCompatibilityTelemetryEnabled() {
		t.Fatal("false must disable telemetry")
	}
	t.Setenv("HMAC_COMPATIBILITY_TELEMETRY_ENABLED", "true")
	if !hmacCompatibilityTelemetryEnabled() {
		t.Fatal("true must enable telemetry")
	}
	t.Setenv("HMAC_COMPATIBILITY_TELEMETRY_ENABLED", "")
	if !hmacCompatibilityTelemetryEnabled() {
		t.Fatal("unset must preserve the default-enabled rollout")
	}
}

func TestHMACCompatibilityTelemetry_DBRecordAndBoundedAdminRead(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping HMAC compatibility telemetry DB test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	const version = "9999.1872.0"
	if _, err := pool.Exec(ctx, `DELETE FROM hmac_compatibility_telemetry WHERE agent_version = $1`, version); err != nil {
		t.Fatalf("cleanup before test: %v", err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM hmac_compatibility_telemetry WHERE agent_version = $1`, version)
	}()
	t.Setenv("HMAC_COMPATIBILITY_TELEMETRY_ENABLED", "true")

	for i := 0; i < 2; i++ {
		if err := recordHMACCompatibility(ctx, pool, auth.HMACSigningFormV3, version); err != nil {
			t.Fatalf("record %d: %v", i+1, err)
		}
	}
	var count int64
	if err := pool.QueryRow(ctx, `
		SELECT accepted_count FROM hmac_compatibility_telemetry
		WHERE signing_form = 'v3' AND agent_version = $1
	`, version).Scan(&count); err != nil {
		t.Fatalf("read aggregate: %v", err)
	}
	if count != 2 {
		t.Fatalf("accepted_count = %d, want 2", count)
	}

	rr := httptest.NewRecorder()
	HMACCompatibilityTelemetryHandler(pool).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/ops/hmac-compatibility", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("admin status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var response struct {
		Observations []hmacCompatibilityObservation `json:"observations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode admin response: %v", err)
	}
	if len(response.Observations) > maxHMACCompatibilityRows {
		t.Fatalf("admin returned %d rows, cap is %d", len(response.Observations), maxHMACCompatibilityRows)
	}
	found := false
	for _, observation := range response.Observations {
		if observation.AgentVersion == version && observation.SigningForm == "v3" && observation.Accepted == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("admin response omitted recorded aggregate: %s", rr.Body.String())
	}

	// The persisted schema itself is the final redaction boundary. Pin the
	// exact columns so a future migration cannot quietly add tenant identity or
	// raw authentication/request material without breaking this security test.
	rows, err := pool.Query(ctx, `
		SELECT column_name
		FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = 'hmac_compatibility_telemetry'
		ORDER BY ordinal_position
	`)
	if err != nil {
		t.Fatalf("read telemetry schema: %v", err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var column string
		if err := rows.Scan(&column); err != nil {
			t.Fatalf("scan telemetry schema: %v", err)
		}
		columns = append(columns, column)
	}
	wantColumns := []string{"signing_form", "agent_version", "accepted_count", "first_seen_at", "last_seen_at"}
	if strings.Join(columns, ",") != strings.Join(wantColumns, ",") {
		t.Fatalf("telemetry columns = %v, want exactly %v", columns, wantColumns)
	}

	var formConstraint string
	if err := pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(oid)
		FROM pg_constraint
		WHERE conname = 'hmac_compatibility_telemetry_form_valid'
	`).Scan(&formConstraint); err != nil {
		t.Fatalf("read signing-form constraint: %v", err)
	}
	matches := regexp.MustCompile(`'([^']+)'`).FindAllStringSubmatch(formConstraint, -1)
	var databaseForms []string
	for _, match := range matches {
		databaseForms = append(databaseForms, match[1])
	}
	wantForms := []string{
		string(auth.HMACSigningFormV3),
		string(auth.HMACSigningFormTargetlessV2),
		string(auth.HMACSigningFormBodyOnly),
		string(auth.HMACSigningFormUnknown),
	}
	slices.Sort(databaseForms)
	slices.Sort(wantForms)
	if strings.Join(databaseForms, ",") != strings.Join(wantForms, ",") {
		t.Fatalf("database signing forms = %v, Go forms = %v", databaseForms, wantForms)
	}
}

func TestHMACCompatibilityTelemetry_ConcurrentNovelVersionsRespectCap(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping HMAC compatibility concurrency test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	t.Setenv("HMAC_COMPATIBILITY_TELEMETRY_ENABLED", "true")

	// Reserve version prefixes used only by this test and restore the shared
	// Unknown aggregate exactly, so the DB-gated package suite remains
	// repeatable even when run against a reused scratch database.
	if _, err := pool.Exec(ctx, `
		DELETE FROM hmac_compatibility_telemetry
		WHERE agent_version LIKE '9900.%' OR agent_version LIKE '9901.%'
	`); err != nil {
		t.Fatalf("clear test versions: %v", err)
	}
	type unknownSnapshot struct {
		count       int64
		first, last time.Time
	}
	var baseline unknownSnapshot
	unknownExisted := true
	err = pool.QueryRow(ctx, `
		SELECT accepted_count, first_seen_at, last_seen_at
		FROM hmac_compatibility_telemetry
		WHERE signing_form = 'v3' AND agent_version = 'Unknown'
	`).Scan(&baseline.count, &baseline.first, &baseline.last)
	if errors.Is(err, pgx.ErrNoRows) {
		unknownExisted = false
	} else if err != nil {
		t.Fatalf("snapshot Unknown aggregate: %v", err)
	}
	defer func() {
		cleanupCtx := context.Background()
		_, _ = pool.Exec(cleanupCtx, `
			DELETE FROM hmac_compatibility_telemetry
			WHERE agent_version LIKE '9900.%' OR agent_version LIKE '9901.%'
		`)
		if unknownExisted {
			_, _ = pool.Exec(cleanupCtx, `
				UPDATE hmac_compatibility_telemetry
				SET accepted_count = $1, first_seen_at = $2, last_seen_at = $3
				WHERE signing_form = 'v3' AND agent_version = 'Unknown'
			`, baseline.count, baseline.first, baseline.last)
		} else {
			_, _ = pool.Exec(cleanupCtx, `
				DELETE FROM hmac_compatibility_telemetry
				WHERE signing_form = 'v3' AND agent_version = 'Unknown'
			`)
		}
	}()

	var existing int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT agent_version)
		FROM hmac_compatibility_telemetry
		WHERE agent_version <> 'Unknown'
	`).Scan(&existing); err != nil {
		t.Fatalf("count existing versions: %v", err)
	}
	if existing > maxHMACCompatibilityVersions {
		t.Fatalf("pre-existing version cardinality %d already exceeds cap %d", existing, maxHMACCompatibilityVersions)
	}
	for i := existing; i < maxHMACCompatibilityVersions; i++ {
		version := fmt.Sprintf("9900.%d.0", i)
		if _, err := pool.Exec(ctx, `
			INSERT INTO hmac_compatibility_telemetry
				(signing_form, agent_version, accepted_count)
			VALUES ('v3', $1, 1)
		`, version); err != nil {
			t.Fatalf("fill version cap at %s: %v", version, err)
		}
	}

	const writers = 20
	errCh := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errCh <- recordHMACCompatibility(ctx, pool, auth.HMACSigningFormV3, fmt.Sprintf("9901.%d.0", i))
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent recorder: %v", err)
		}
	}

	var distinct, escaped int
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT agent_version)
		FROM hmac_compatibility_telemetry
		WHERE agent_version <> 'Unknown'
	`).Scan(&distinct); err != nil {
		t.Fatalf("count versions after concurrency: %v", err)
	}
	if distinct != maxHMACCompatibilityVersions {
		t.Fatalf("distinct versions after concurrency = %d, want exactly cap %d", distinct, maxHMACCompatibilityVersions)
	}
	if err := pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM hmac_compatibility_telemetry
		WHERE agent_version LIKE '9901.%'
	`).Scan(&escaped); err != nil {
		t.Fatalf("count versions admitted past cap: %v", err)
	}
	if escaped != 0 {
		t.Fatalf("%d concurrent novel versions escaped the cap", escaped)
	}

	var unknownAfter int64
	if err := pool.QueryRow(ctx, `
		SELECT accepted_count FROM hmac_compatibility_telemetry
		WHERE signing_form = 'v3' AND agent_version = 'Unknown'
	`).Scan(&unknownAfter); err != nil {
		t.Fatalf("read overflow aggregate: %v", err)
	}
	if unknownAfter-baseline.count != writers {
		t.Fatalf("Unknown overflow increment = %d, want %d", unknownAfter-baseline.count, writers)
	}
}
