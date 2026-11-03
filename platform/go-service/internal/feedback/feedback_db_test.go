package feedback

// DB acceptance expects the real forward migrations already applied, as CI's
// integration TestMain does. No production or remote database is permitted.
import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

func feedbackDBPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	missing := func(reason string) {
		if os.Getenv("PATCHED_DB_TESTS_REQUIRED") != "" {
			t.Fatalf("PATCHED_DB_TESTS_REQUIRED: %s", reason)
		}
		t.Skip(reason)
	}
	if dsn == "" {
		missing("TEST_DATABASE_URL unset; feedback DB acceptance needs a migrated scratch database")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("invalid TEST_DATABASE_URL")
	}
	host := strings.ToLower(strings.Trim(cfg.ConnConfig.Host, "[]"))
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		t.Fatal("feedback tests require loopback TEST_DATABASE_URL")
	}
	for _, fallback := range cfg.ConnConfig.Fallbacks {
		host := strings.ToLower(strings.Trim(fallback.Host, "[]"))
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			t.Fatal("feedback tests require loopback fallback hosts too")
		}
	}
	name := strings.ToLower(cfg.ConnConfig.Database)
	if !strings.Contains(name, "test") && !strings.Contains(name, "scratch") {
		t.Fatal("feedback tests require an explicitly test/scratch-named database")
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	cfg.MaxConns = 16
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("feedback scratch DB unavailable: %v", err)
	}
	var ready bool
	if err := pool.QueryRow(ctx, `SELECT to_regclass('public.tenants') IS NOT NULL AND to_regclass('public.feedback') IS NOT NULL AND to_regclass('public.schema_migrations') IS NOT NULL`).Scan(&ready); err != nil {
		t.Fatal(err)
	}
	if !ready {
		missing("feedback DB acceptance requires migration 0206; apply full forward migrations first")
	}
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version='0206_portal_feedback')`).Scan(&ready); err != nil {
		t.Fatal(err)
	}
	if !ready {
		missing("migration 0206 bookkeeping absent; feedback DB acceptance skipped")
	}
	return pool
}

func feedbackDBSuffix(t *testing.T) string {
	t.Helper()
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b[:])
}
func feedbackDBTenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `INSERT INTO tenants(name,bearer_token_hash,hmac_secret) VALUES($1,$2,$3) RETURNING id::text`, "pat2035-feedback-test-"+feedbackDBSuffix(t), []byte("test-only-hash"), []byte("test-only-secret")).Scan(&id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1::uuid`, id); err != nil {
			t.Errorf("cleanup feedback test tenant: %v", err)
		}
	})
	return id
}
func feedbackDBSubmission(tenant, email string) Submission {
	return Submission{TenantID: tenant, TenantDisplaySlug: "test-tenant", ReporterEmail: email, ReporterRole: "viewer", Type: TypeQuestion, Title: "Acceptance test title", Description: "private customer description", Route: "/devices?private=secret#private", PortalBuild: "test-build", BrowserUserAgent: "test-browser"}
}
func feedbackDBCreate(t *testing.T, pool *pgxpool.Pool, in Submission) Record {
	t.Helper()
	r, d, err := (Store{Pool: pool}).Create(context.Background(), in)
	if err != nil || !d.Allowed {
		t.Fatalf("create acceptance row: %v decision%+v", err, d)
	}
	return r
}
func feedbackDBClaim(t *testing.T, pool *pgxpool.Pool, id int64, attempt int, expired bool) {
	t.Helper()
	interval := "10 minutes"
	if expired {
		interval = "-1 minute"
	}
	if _, err := pool.Exec(context.Background(), `UPDATE feedback SET sync_state='syncing',sync_attempts=$2,lease_until=clock_timestamp()+$3::interval,updated_at=clock_timestamp() WHERE id=$1`, id, attempt, interval); err != nil {
		t.Fatal(err)
	}
}

func TestFeedbackDBMigrationShapeAndConstraints(t *testing.T) {
	pool := feedbackDBPool(t)
	tenant := feedbackDBTenant(t, pool)
	r := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "shape@example.test"))
	ctx := context.Background()
	if r.Reference != fmt.Sprintf("FB-%d", r.ID) || r.LinearState != nil || r.Status != "received" {
		t.Fatalf("wrong initial model:%+v", r)
	}
	for _, privilege := range []string{"SELECT", "INSERT", "UPDATE", "DELETE"} {
		var granted bool
		if err := pool.QueryRow(ctx, `SELECT has_table_privilege('patched','public.feedback',$1)`, privilege).Scan(&granted); err != nil || !granted {
			t.Fatalf("missing table grant%s: %v", privilege, err)
		}
	}
	for _, privilege := range []string{"USAGE", "SELECT"} {
		var granted bool
		if err := pool.QueryRow(ctx, `SELECT has_sequence_privilege('patched','public.feedback_id_seq',$1)`, privilege).Scan(&granted); err != nil || !granted {
			t.Fatalf("missing sequence grant%s: %v", privilege, err)
		}
	}
	var generated, nullable bool
	if err := pool.QueryRow(ctx, `SELECT (SELECT attgenerated='s' FROM pg_attribute WHERE attrelid='public.feedback'::regclass AND attname='reference'),(SELECT is_nullable='YES' AND column_default IS NULL FROM information_schema.columns WHERE table_schema='public' AND table_name='feedback' AND column_name='linear_state')`).Scan(&generated, &nullable); err != nil || !generated || !nullable {
		t.Fatalf("generated reference/nullable workflow state: %v %t %t", err, generated, nullable)
	}
	// reporter_role: 'owner' was the invalid example here until migration 0229
	// (PAT-1883) made it a real portal role; an unknown role is still refused.
	for _, assignment := range []string{"title='tiny'", "description=''", "type='bug',severity=NULL", "type='question',severity='low'", "reporter_role='superuser'", "reporter_role='Owner'", "route='/devices?secret=yes'", "route='/devices#secret'", "route=repeat('x',513)", "portal_build=repeat('x',129)", "user_agent=repeat('x',513)", "screenshot_attempts=6", "screenshot_content_type='image/png'"} {
		_, err := pool.Exec(ctx, `UPDATE feedback SET `+assignment+` WHERE id=$1`, r.ID)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Errorf("constraint accepted%s or wrong error:%v", assignment, err)
		}
	}
	// PAT-1883: every role a portal user can hold is a role a reporter can have.
	for _, role := range []string{"viewer", "admin", "owner"} {
		if _, err := pool.Exec(ctx, `UPDATE feedback SET reporter_role=$2 WHERE id=$1`, r.ID, role); err != nil {
			t.Errorf("constraint refused reporter_role %q: %v", role, err)
		}
	}
}

func TestFeedbackDBCreateListTenantIsolationAndPublicProjection(t *testing.T) {
	pool := feedbackDBPool(t)
	a, b := feedbackDBTenant(t, pool), feedbackDBTenant(t, pool)
	ra := feedbackDBCreate(t, pool, feedbackDBSubmission(a, "private-a@example.test"))
	rb := feedbackDBCreate(t, pool, feedbackDBSubmission(b, "private-b@example.test"))
	for _, tc := range []struct{ tenant, reference, other string }{{a, ra.Reference, rb.Reference}, {b, rb.Reference, ra.Reference}} {
		rows, err := (Store{Pool: pool}).List(context.Background(), tc.tenant, "")
		if err != nil || len(rows) != 1 || rows[0].Reference != tc.reference {
			t.Fatalf("cross-tenant list:%+v %v", rows, err)
		}
		raw, err := json.Marshal(rows)
		if err != nil {
			t.Fatal(err)
		}
		var projection []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &projection); err != nil {
			t.Fatal(err)
		}
		if len(projection[0]) != 7 {
			t.Fatalf("unexpected GET projection fields: %s", raw)
		}
		for _, key := range []string{"reference", "type", "door", "title", "status", "created_at", "last_status_change"} {
			if _, ok := projection[0][key]; !ok {
				t.Errorf("missing public field%s", key)
			}
		}
		for _, forbidden := range []string{tc.other, "private-a@example.test", "private-b@example.test", "private customer description", "reporter_email", "description", "sync_state", "sync_attempts", "linear_state", "screenshot", "lease_until", "last_error"} {
			if strings.Contains(string(raw), forbidden) {
				t.Errorf("GET-shaped output leaked %q: %s", forbidden, raw)
			}
		}
	}
	var route string
	if err := pool.QueryRow(context.Background(), `SELECT route FROM feedback WHERE id=$1`, ra.ID).Scan(&route); err != nil || route != "/devices" {
		t.Fatalf("captured private URL:%q %v", route, err)
	}
}

func TestFeedbackDBEmptyListSerializesArray(t *testing.T) {
	pool := feedbackDBPool(t)
	tenant := feedbackDBTenant(t, pool)
	rows, err := (Store{Pool: pool}).List(context.Background(), tenant, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rows)
	if err != nil || string(raw) != "[]" {
		t.Fatalf("empty list JSON=%s err=%v; want[]", raw, err)
	}
}

func TestFeedbackDBRejectsNULIdentityWithoutPersistence(t *testing.T) {
	pool := feedbackDBPool(t)
	tenant := feedbackDBTenant(t, pool)
	for _, field := range []string{"tenant", "email"} {
		in := feedbackDBSubmission(tenant, "nul@example.test")
		if field == "tenant" {
			in.TenantID += "\x00"
		} else {
			in.ReporterEmail += "\x00"
		}
		_, _, err := (Store{Pool: pool}).Create(context.Background(), in)
		var pgerr *pgconn.PgError
		if err == nil || !strings.Contains(err.Error(), "NUL") || errors.As(err, &pgerr) {
			t.Fatalf("NUL identity reached PostgreSQL:%v", err)
		}
	}
	var count int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM feedback WHERE tenant_id=$1::uuid`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid identity persisted rows:%d %v", count, err)
	}
}

func TestFeedbackDBRateLimiterUses64BitAdvisoryLocks(t *testing.T) {
	pool := feedbackDBPool(t)
	tenant := feedbackDBTenant(t, pool)
	for _, scope := range []string{"reporter", "tenant"} {
		t.Run(scope, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			blocker, err := pool.Begin(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer blocker.Rollback(context.Background())
			email := "lock-" + scope + "@example.test"
			key := tenant
			if scope == "reporter" {
				key = tenant + "\\x00" + email
			}
			if _, err := blocker.Exec(context.Background(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, key); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				_, _, err := (Store{Pool: pool}).Create(ctx, feedbackDBSubmission(tenant, email))
				result <- err
			}()
			deadline := time.NewTimer(2 * time.Second)
			defer deadline.Stop()
			ticker := time.NewTicker(10 * time.Millisecond)
			defer ticker.Stop()
			for {
				var blocked bool
				if err := pool.QueryRow(context.Background(), `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND NOT granted AND objsubid=1 AND classid::bigint=((hashtextextended($1,0)>>32)&4294967295) AND objid::bigint=(hashtextextended($1,0)&4294967295))`, key).Scan(&blocked); err != nil {
					t.Fatal(err)
				}
				if blocked {
					break
				}
				select {
				case err := <-result:
					t.Fatalf("create did not wait on64-bit%slock:%v", scope, err)
				case <-deadline.C:
					t.Fatal("64-bit advisory waiter did not appear")
				case <-ticker.C:
				}
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("blocked create cancellation:%v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("blocked create ignored cancellation")
			}
		})
	}
}

func TestFeedbackDBConcurrentRateLimits(t *testing.T) {
	for _, tc := range []struct {
		name           string
		count, allowed int
		distinct       bool
		reason         RateLimitReason
	}{{"same user allows ten", 11, 10, false, RateLimitUserHourly}, {"distinct users allow fifty", 51, 50, true, RateLimitTenantDaily}} {
		t.Run(tc.name, func(t *testing.T) {
			pool := feedbackDBPool(t)
			tenant := feedbackDBTenant(t, pool)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			var wg sync.WaitGroup
			results := make(chan RateDecision, tc.count)
			errs := make(chan error, tc.count)
			start := make(chan struct{})
			for i := 0; i < tc.count; i++ {
				email := "same@example.test"
				if tc.distinct {
					email = fmt.Sprintf("reporter-%d@example.test", i)
				}
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					_, decision, err := (Store{Pool: pool}).Create(ctx, feedbackDBSubmission(tenant, email))
					if err != nil {
						errs <- err
					} else {
						results <- decision
					}
				}()
			}
			close(start)
			wg.Wait()
			close(results)
			close(errs)
			for err := range errs {
				t.Errorf("concurrent create:%v", err)
			}
			allowed, refused := 0, 0
			for d := range results {
				if d.Allowed {
					allowed++
				} else {
					refused++
					if d.Reason != tc.reason {
						t.Errorf("wrong limiter:%+v", d)
					}
				}
			}
			var stored int
			if err := pool.QueryRow(ctx, `SELECT count(*) FROM feedback WHERE tenant_id=$1::uuid`, tenant).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if allowed != tc.allowed || refused != 1 || stored != tc.allowed {
				t.Fatalf("rate/advisory result: allowed%d refused%d stored%d want%d/1", allowed, refused, stored, tc.allowed)
			}
		})
	}
}

func TestFeedbackDBScreenshotPersistenceCompletionAndFallback(t *testing.T) {
	pool := feedbackDBPool(t)
	tenant := feedbackDBTenant(t, pool)
	ctx := context.Background()
	store := postgresDeliveryStore{pool: pool}
	for _, withAsset := range []bool{true, false} {
		t.Run(fmt.Sprintf("asset-%t", withAsset), func(t *testing.T) {
			in := feedbackDBSubmission(tenant, fmt.Sprintf("shot-%t@example.test", withAsset))
			in.Screenshot = &Screenshot{Bytes: []byte("sanitised test image bytes"), ContentType: "image/png", Filename: "intake.png"}
			r := feedbackDBCreate(t, pool, in)
			feedbackDBClaim(t, pool, r.ID, 1, false)
			d, err := store.load(ctx, r.ID, 1)
			if err != nil || d.Screenshot == nil || d.Screenshot.Filename != r.Reference+".png" || d.Screenshot.ContentType != "image/png" {
				t.Fatalf("stored screenshot:%+v %v", d, err)
			}
			for i := 1; i <= 5; i++ {
				n, err := store.reserveUpload(ctx, r.ID, 1)
				if err != nil || n != i {
					t.Fatalf("durable upload reservation%d: %d %v", i, n, err)
				}
			}
			if _, err := store.reserveUpload(ctx, r.ID, 1); !errors.Is(err, ErrStaleFeedbackClaim) {
				t.Fatalf("sixth upload reserved:%v", err)
			}
			if withAsset {
				if err := store.persistAsset(ctx, r.ID, 1, "https://cdn.example.test/a.png"); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := store.uploadFailed(ctx, r.ID, 1, "Screenshot upload failed"); err != nil {
					t.Fatal(err)
				}
			}
			state := "Backlog"
			if err := store.complete(ctx, r.ID, 1, fmt.Sprintf("issue-asset-%t", withAsset), "PAT-1", &state); err != nil {
				t.Fatal(err)
			}
			var syncState, linearState string
			var retained bool
			var lastError *string
			if err := pool.QueryRow(ctx, `SELECT sync_state,linear_state,screenshot IS NOT NULL AND screenshot_content_type IS NOT NULL AND screenshot_filename IS NOT NULL,last_error FROM feedback WHERE id=$1`, r.ID).Scan(&syncState, &linearState, &retained, &lastError); err != nil {
				t.Fatal(err)
			}
			if syncState != "synced" || linearState != "Backlog" || retained == withAsset || (withAsset && lastError != nil) || (!withAsset && (lastError == nil || *lastError != "Screenshot upload failed")) {
				t.Fatalf("wrong final screenshot state: %s %s retained%t error%v", syncState, linearState, retained, lastError)
			}
		})
	}
}

func TestFeedbackDBRetryBudgetAndStaleLeaseGuards(t *testing.T) {
	pool := feedbackDBPool(t)
	tenant := feedbackDBTenant(t, pool)
	ctx := context.Background()
	store := postgresDeliveryStore{pool: pool}
	sweeper := &Sweeper{pool: pool}
	r := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "retry@example.test"))
	feedbackDBClaim(t, pool, r.ID, 9, false)
	sweeper.retry(r.ID, 9, "ninth failure")
	var state string
	var attempts int
	var delay float64
	var leaseNull bool
	var lastError *string
	if err := pool.QueryRow(ctx, `SELECT sync_state,sync_attempts,extract(epoch FROM next_sync_at-clock_timestamp()),lease_until IS NULL,last_error FROM feedback WHERE id=$1`, r.ID).Scan(&state, &attempts, &delay, &leaseNull, &lastError); err != nil {
		t.Fatal(err)
	}
	if state != "pending" || attempts != 9 || delay < 3590 || delay > 3601 || !leaseNull {
		t.Fatalf("ninth retry:%s %d delay%.2f leaseNull%t", state, attempts, delay, leaseNull)
	}
	feedbackDBClaim(t, pool, r.ID, 10, false)
	sweeper.retry(r.ID, 10, "tenth failure")
	if err := pool.QueryRow(ctx, `SELECT sync_state,sync_attempts,lease_until IS NULL,last_error FROM feedback WHERE id=$1`, r.ID).Scan(&state, &attempts, &leaseNull, &lastError); err != nil {
		t.Fatal(err)
	}
	if state != "failed" || attempts != 10 || !leaseNull || lastError == nil || *lastError != "tenth failure" {
		t.Fatalf("tenth retry not retained failed:%s/%d/%v", state, attempts, lastError)
	}
	in := feedbackDBSubmission(tenant, "stale@example.test")
	in.Screenshot = &Screenshot{Bytes: []byte("retained"), ContentType: "image/png", Filename: "intake.png"}
	stale := feedbackDBCreate(t, pool, in)
	for _, expired := range []bool{false, true} {
		feedbackDBClaim(t, pool, stale.ID, 2, expired)
		oldAttempt := 1
		if expired {
			oldAttempt = 2
		}
		if _, err := store.load(ctx, stale.ID, oldAttempt); !errors.Is(err, ErrStaleFeedbackClaim) {
			t.Errorf("stale load:%v", err)
		}
		if _, err := store.reserveUpload(ctx, stale.ID, oldAttempt); !errors.Is(err, ErrStaleFeedbackClaim) {
			t.Errorf("stale reserve:%v", err)
		}
		for _, err := range []error{store.persistAsset(ctx, stale.ID, oldAttempt, "https://cdn.example.test/no.png"), store.uploadFailed(ctx, stale.ID, oldAttempt, "must not persist"), store.complete(ctx, stale.ID, oldAttempt, "no", "PAT-0", nil)} {
			if !errors.Is(err, ErrStaleFeedbackClaim) {
				t.Errorf("stale mutation:%v", err)
			}
		}
		sweeper.retry(stale.ID, oldAttempt, "must not retry")
		var untouched bool
		if err := pool.QueryRow(ctx, `SELECT sync_state='syncing' AND sync_attempts=2 AND screenshot_attempts=0 AND linear_asset_url IS NULL AND linear_issue_id IS NULL AND last_error IS NULL AND screenshot IS NOT NULL FROM feedback WHERE id=$1`, stale.ID).Scan(&untouched); err != nil || !untouched {
			t.Fatalf("stale worker overwrote current row:%t %v", untouched, err)
		}
	}
}

func TestFeedbackDBRealMigrationRollbackRetainsNonEmptyTable(t *testing.T) {
	pool := feedbackDBPool(t)
	ctx := context.Background()
	schema := "pat2035_feedback_rb_" + feedbackDBSuffix(t)
	quoted := pgx.Identifier{schema}.Sanitize()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	created := false
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = conn.Exec(cleanup, "ROLLBACK")
		_, _ = conn.Exec(cleanup, "SET search_path TO public")
		if created {
			if _, err := conn.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
				t.Errorf("cleanup isolated rollback schema:%v", err)
			}
		}
		conn.Release()
	})
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	created = true
	for _, sql := range []string{"CREATE TABLE " + quoted + ".tenants (LIKE public.tenants INCLUDING ALL)", "CREATE TABLE " + quoted + ".schema_migrations (LIKE public.schema_migrations INCLUDING ALL)", "SET search_path TO " + quoted} {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	forward, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0206_portal_feedback.sql"))
	if err != nil {
		t.Fatal(err)
	}
	rollback, err := os.ReadFile(filepath.Join("..", "..", "migrations", "0206_portal_feedback_rollback.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, string(forward)); err != nil {
		t.Fatalf("apply actual migration in isolated schema:%v", err)
	}
	var tenant string
	if err := conn.QueryRow(ctx, `INSERT INTO tenants(name,bearer_token_hash,hmac_secret) VALUES('rollback-test','\x00','\x00') RETURNING id::text`).Scan(&tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `INSERT INTO feedback(tenant_id,tenant_display_slug,reporter_email,reporter_role,type,title,description) VALUES($1::uuid,'test','test@example.test','viewer','question','Rollback acceptance','retained text')`, tenant); err != nil {
		t.Fatal(err)
	}
	_, err = conn.Exec(ctx, string(rollback))
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) || pgerr.Code != "P0001" {
		t.Fatalf("nonempty rollback was not refused:%v", err)
	}
	if _, err := conn.Exec(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	var retained bool
	if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM feedback) AND EXISTS(SELECT 1 FROM schema_migrations WHERE version='0206_portal_feedback')`).Scan(&retained); err != nil || !retained {
		t.Fatalf("rollback guard lost rows/bookkeeping:%v retained%t", err, retained)
	}
	if _, err := conn.Exec(ctx, "DELETE FROM feedback"); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, string(rollback)); err != nil {
		t.Fatalf("empty rollback failed:%v", err)
	}
	var clean, publicIntact bool
	if err := conn.QueryRow(ctx, `SELECT to_regclass('feedback') IS NULL AND to_regclass('feedback_id_seq') IS NULL AND NOT EXISTS(SELECT 1 FROM schema_migrations WHERE version='0206_portal_feedback'),to_regclass('public.feedback') IS NOT NULL`).Scan(&clean, &publicIntact); err != nil || !clean || !publicIntact {
		t.Fatalf("rollback isolation:clean%t public%t err%v", clean, publicIntact, err)
	}
}

// PAT-2347: one list per portal door. Support holds support requests and the
// retired bug and question types; Feedback holds feature and design requests;
// no door returns everything, as before the split.
func TestFeedbackDBListFiltersByDoorAndCarriesCategory(t *testing.T) {
	pool := feedbackDBPool(t)
	tenant := feedbackDBTenant(t, pool)
	other := feedbackDBTenant(t, pool)
	create := func(tenantID, email, typ, severity, category string) Record {
		in := feedbackDBSubmission(tenantID, email)
		in.Type, in.Severity, in.Category = typ, severity, category
		return feedbackDBCreate(t, pool, in)
	}
	feature := create(tenant, "door-a@example.test", TypeFeature, "", "")
	design := create(tenant, "door-b@example.test", TypeDesign, "", "")
	support := create(tenant, "door-c@example.test", TypeSupport, "", CategoryAccount)
	bug := create(tenant, "door-d@example.test", TypeBug, SeverityLow, "")
	create(other, "door-e@example.test", TypeSupport, "", CategoryNotWorking)
	refs := func(door string) map[string]ListItem {
		rows, err := (Store{Pool: pool}).List(context.Background(), tenant, door)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]ListItem{}
		for _, r := range rows {
			out[r.Reference] = r
		}
		return out
	}
	if all := refs(""); len(all) != 4 {
		t.Fatalf("no door must return every item for the tenant, got %d", len(all))
	}
	fb := refs(DoorFeedback)
	if len(fb) != 2 || fb[feature.Reference].Type != TypeFeature || fb[design.Reference].Type != TypeDesign {
		t.Fatalf("feedback door: %+v", fb)
	}
	sp := refs(DoorSupport)
	if len(sp) != 2 || sp[support.Reference].Type != TypeSupport || sp[bug.Reference].Type != TypeBug {
		t.Fatalf("support door: %+v", sp)
	}
	if got := sp[support.Reference]; got.Door != DoorSupport || got.Category == nil || *got.Category != CategoryAccount {
		t.Fatalf("support item door or category: %+v", got)
	}
	if got := fb[design.Reference]; got.Door != DoorFeedback || got.Category != nil {
		t.Fatalf("design item door or category: %+v", got)
	}
}

func TestFeedbackDBRejectsCategoryOutsideSupport(t *testing.T) {
	pool := feedbackDBPool(t)
	tenant := feedbackDBTenant(t, pool)
	r := feedbackDBCreate(t, pool, feedbackDBSubmission(tenant, "category@example.test"))
	for _, assignment := range []string{"category='account_billing'", "type='support'", "type='support',severity=NULL,category='bogus'", "type='design',severity='low'"} {
		_, err := pool.Exec(context.Background(), `UPDATE feedback SET `+assignment+` WHERE id=$1`, r.ID)
		var pgerr *pgconn.PgError
		if !errors.As(err, &pgerr) || pgerr.Code != "23514" {
			t.Errorf("constraint accepted %s or wrong error: %v", assignment, err)
		}
	}
}
