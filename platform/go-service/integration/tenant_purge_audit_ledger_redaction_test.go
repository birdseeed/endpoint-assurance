//go:build integration

package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// PAT-2403: the ticket's six audit ledgers, and tenant_shadow_it_policy_changes
// (found by the ticket's survey with the same defect), have no cascading
// tenant foreign key, so their rows outlive a tenant purge. Each must keep its
// non-identifying event shape and lose the actor identifier and identifying
// free text, for the purged tenant only, through the real admin purge
// endpoint, while staying append-only for every other path. Same contract as
// PAT-2380's tenant_purge_software_alert_redaction_test.go. Synthetic data only.

const (
	pat2403Marker   = "tenant_purge_anonymized_at"
	pat2403PurgeGUC = "patched.audit_ledger_purge_tenant"

	pat2403Actor     = "actor@example.invalid"
	pat2403Creator   = "creator@example.invalid"
	pat2403FreeText  = "pat2403 identifying free text"
	pat2403Hostname  = "pat2403-host.example.invalid"
	pat2403Serial    = "PAT2403SERIAL"
	pat2403SnapText  = "pat2403 snapshot justification"
	pat2403FutureKey = "pat2403 unreviewed snapshot text"
	pat2403Addr      = "192.0.2.44" // TEST-NET-1, documentation only
)

// Every synthetic identifying value a fixture writes. None may remain anywhere
// in a purged tenant's retained rows, whichever column or JSON key held it.
var pat2403Sentinels = []string{
	pat2403Actor, pat2403Creator, pat2403FreeText, pat2403Hostname,
	pat2403Serial, pat2403SnapText, pat2403FutureKey, pat2403Addr,
}

type pat2403Ledger struct {
	table string
	// inserts each take the tenant id as $1 and write one row.
	inserts []string
	// actorCol is the identifying actor column the purge must null. Every
	// fixture row sets it to pat2403Actor.
	actorCol string
	// redacted are the columns the purge nulls (actorCol included).
	redacted []string
	// rewritten are retained columns the purge replaces with a fixed
	// non-identifying value; excluded from the unchanged-shape comparison and
	// asserted by check instead.
	rewritten []string
	// forge is a SET clause imitating exactly what the purge writes.
	forge string
	// markedInsert writes a row that already carries the purge marker.
	markedInsert string
	// check holds the per-table assertions on the purged tenant's rows.
	check func(t *testing.T, tenant string)
}

func pat2403Ledgers() []pat2403Ledger {
	ctx := context.Background()
	return []pat2403Ledger{
		{
			table: "software_approval_decisions",
			inserts: []string{
				`INSERT INTO software_approval_decisions (tenant_id,batch_id,product_type,product_key,platform,identifier,team_id,previous_state,new_state,reason,actor_email,protected_warning)
				 VALUES ($1::uuid,gen_random_uuid(),'application','application:macos:invalid.example.pat2403:TEAM2403','macos','invalid.example.pat2403','TEAM2403','unreviewed','approved','` + pat2403FreeText + `','` + pat2403Actor + `',true)`,
				`INSERT INTO software_approval_decisions (tenant_id,batch_id,product_type,product_key,browser,identifier,previous_state,new_state,actor_email)
				 VALUES ($1::uuid,gen_random_uuid(),'browser_extension','browser_extension:chrome:pat2403extension','chrome','pat2403extension','approved','unapproved','` + pat2403Actor + `')`,
			},
			actorCol: "actor_email",
			redacted: []string{"actor_email", "reason"},
			forge:    `actor_email=NULL,reason=NULL,` + pat2403Marker + `=transaction_timestamp()`,
			markedInsert: `INSERT INTO software_approval_decisions (tenant_id,batch_id,product_type,product_key,platform,identifier,previous_state,new_state,` + pat2403Marker + `)
				 VALUES ($1::uuid,gen_random_uuid(),'application','application:macos:invalid.example.forged','macos','invalid.example.forged','unreviewed','approved',now())`,
		},
		{
			table: "device_retirement_decisions",
			inserts: []string{
				`INSERT INTO device_retirement_decisions (tenant_id,device_id,action,reason,actor_email)
				 VALUES ($1::uuid,gen_random_uuid(),'retire','` + pat2403FreeText + `','` + pat2403Actor + `')`,
				`INSERT INTO device_retirement_decisions (tenant_id,device_id,action,actor_email)
				 VALUES ($1::uuid,gen_random_uuid(),'unretire','` + pat2403Actor + `')`,
			},
			actorCol: "actor_email",
			redacted: []string{"actor_email", "reason"},
			forge:    `actor_email=NULL,reason=NULL,` + pat2403Marker + `=transaction_timestamp()`,
			markedInsert: `INSERT INTO device_retirement_decisions (tenant_id,device_id,action,` + pat2403Marker + `)
				 VALUES ($1::uuid,gen_random_uuid(),'retire',now())`,
		},
		{
			table: "jamf_webhook_audit",
			inserts: []string{
				`INSERT INTO jamf_webhook_audit (tenant_id,action,affected_rows,actor_email)
				 VALUES ($1::uuid,'token_revoked',7,'` + pat2403Actor + `')`,
				`INSERT INTO jamf_webhook_audit (tenant_id,action,actor_email)
				 VALUES ($1::uuid,'token_created','` + pat2403Actor + `')`,
			},
			actorCol: "actor_email",
			redacted: []string{"actor_email"},
			forge:    `actor_email=NULL,` + pat2403Marker + `=transaction_timestamp()`,
			markedInsert: `INSERT INTO jamf_webhook_audit (tenant_id,action,` + pat2403Marker + `)
				 VALUES ($1::uuid,'token_created',now())`,
		},
		{
			table: "device_list_entry_deletions",
			inserts: []string{
				`INSERT INTO device_list_entry_deletions (tenant_id,upload_id,entry_id,position,hostname,serial,actor_email)
				 VALUES ($1::uuid,2403,24031,3,'` + pat2403Hostname + `','` + pat2403Serial + `','` + pat2403Actor + `')`,
				`INSERT INTO device_list_entry_deletions (tenant_id,upload_id,entry_id,position,serial,actor_email)
				 VALUES ($1::uuid,2403,24032,4,'` + pat2403Serial + `','` + pat2403Actor + `')`,
			},
			actorCol: "actor_email",
			redacted: []string{"actor_email", "hostname", "serial"},
			forge:    `actor_email=NULL,hostname=NULL,serial=NULL,` + pat2403Marker + `=transaction_timestamp()`,
			markedInsert: `INSERT INTO device_list_entry_deletions (tenant_id,upload_id,entry_id,position,` + pat2403Marker + `)
				 VALUES ($1::uuid,2403,24039,9,now())`,
		},
		{
			table: "agent_release_audit",
			inserts: []string{
				`INSERT INTO agent_release_audit (tenant_id,actor,source,action,details)
				 VALUES ($1::uuid,'` + pat2403Actor + `','portal','hold',
				         jsonb_build_object('request',jsonb_build_object('action','hold','note','` + pat2403FreeText + `'),'pinned_version','1.2.3','requested_by','` + pat2403Creator + `'))`,
				`INSERT INTO agent_release_audit (tenant_id,actor,source,action,details)
				 VALUES ($1::uuid,'internal-admin','internal','p0_scheduled',
				         jsonb_build_object('notice_id',2403,'schedule',jsonb_build_object('version','1.2.4','banner','` + pat2403FreeText + `')))`,
			},
			actorCol:  "actor",
			redacted:  []string{"actor"},
			rewritten: []string{"details"},
			forge:     `actor=NULL,details='{}'::jsonb,` + pat2403Marker + `=transaction_timestamp()`,
			markedInsert: `INSERT INTO agent_release_audit (tenant_id,source,action,details,` + pat2403Marker + `)
				 VALUES ($1::uuid,'portal','hold','{}'::jsonb,now())`,
			check: func(t *testing.T, tenant string) {
				t.Helper()
				var total, emptied int
				if err := env.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE details = '{}'::jsonb)
					FROM agent_release_audit WHERE tenant_id=$1::uuid`, tenant).Scan(&total, &emptied); err != nil {
					t.Fatal(err)
				}
				if total == 0 || emptied != total {
					t.Errorf("agent_release_audit: %d of %d purged rows have details emptied to {}", emptied, total)
				}
			},
		},
		{
			table: "software_declaration_decisions",
			inserts: []string{
				`INSERT INTO software_declaration_decisions (tenant_id,declaration_id,action,actor_email,justification,declaration)
				 VALUES ($1::uuid,'00000000-0000-4000-8000-000000002403','created','` + pat2403Actor + `','` + pat2403FreeText + `',
				         jsonb_build_object('id','00000000-0000-4000-8000-000000002403','tenant_id',$1::text,'name','PAT-2403 Synthetic App',
				           'publisher','PAT-2403 Synthetic Publisher','platform','windows','justification','` + pat2403SnapText + `',
				           'min_version','1.2','created_by','` + pat2403Creator + `','created_at','2026-10-01T00:00:00Z',
				           'unreviewed_future_column','` + pat2403FutureKey + `'))`,
				`INSERT INTO software_declaration_decisions (tenant_id,declaration_id,action,actor_email,justification,declaration)
				 VALUES ($1::uuid,'00000000-0000-4000-8000-000000002403','resolved','` + pat2403Actor + `','` + pat2403FreeText + `',
				         jsonb_build_object('id','00000000-0000-4000-8000-000000002403','tenant_id',$1::text,'name','PAT-2403 Synthetic App',
				           'publisher','PAT-2403 Synthetic Publisher','platform','windows','justification','` + pat2403SnapText + `',
				           'resolved_identifier','pat2403 synthetic app','resolved_kind','windows_display_name','policy_id',2403,
				           'created_by','` + pat2403Creator + `','created_at','2026-10-01T00:00:00Z','resolved_at','2026-10-02T00:00:00Z'))`,
			},
			actorCol:  "actor_email",
			redacted:  []string{"actor_email", "justification"},
			rewritten: []string{"declaration"},
			forge:     `actor_email=NULL,justification=NULL,declaration=public.software_declaration_purge_snapshot(declaration),` + pat2403Marker + `=transaction_timestamp()`,
			markedInsert: `INSERT INTO software_declaration_decisions (tenant_id,declaration_id,action,declaration,` + pat2403Marker + `)
				 VALUES ($1::uuid,gen_random_uuid(),'created','{}'::jsonb,now())`,
			check: func(t *testing.T, tenant string) {
				t.Helper()
				var total, stripped, retained int
				if err := env.pool.QueryRow(ctx, `SELECT count(*),
					count(*) FILTER (WHERE NOT declaration ?| array['created_by','justification','unreviewed_future_column']),
					count(*) FILTER (WHERE declaration->>'name'='PAT-2403 Synthetic App'
					                   AND declaration->>'publisher'='PAT-2403 Synthetic Publisher'
					                   AND declaration->>'platform'='windows'
					                   AND declaration->>'id'='00000000-0000-4000-8000-000000002403'
					                   AND declaration->>'tenant_id'=$1
					                   AND declaration->>'created_at'='2026-10-01T00:00:00Z')
					FROM software_declaration_decisions WHERE tenant_id=$1::uuid`, tenant).Scan(&total, &stripped, &retained); err != nil {
					t.Fatal(err)
				}
				if total == 0 || stripped != total {
					t.Errorf("software_declaration_decisions: %d of %d purged snapshots lost created_by, justification and unreviewed keys", stripped, total)
				}
				if retained != total {
					t.Errorf("software_declaration_decisions: %d of %d purged snapshots kept the non-identifying declaration shape", retained, total)
				}
				var resolved int
				if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM software_declaration_decisions
					WHERE tenant_id=$1::uuid AND action='resolved' AND declaration->>'resolved_identifier'='pat2403 synthetic app'
					  AND declaration->>'resolved_kind'='windows_display_name' AND declaration->>'policy_id'='2403'
					  AND declaration->>'resolved_at'='2026-10-02T00:00:00Z'`, tenant).Scan(&resolved); err != nil {
					t.Fatal(err)
				}
				if resolved != 1 {
					t.Errorf("software_declaration_decisions: resolution snapshot fields were not retained (%d rows)", resolved)
				}
			},
		},
		{
			// actor holds a fixed sentinel (admin_shared_token), never an
			// identity, so it is retained; the caller's claim, their address
			// and the free-text reason are what identify someone.
			table: "tenant_shadow_it_policy_changes",
			inserts: []string{
				`INSERT INTO tenant_shadow_it_policy_changes (tenant_id,label,old_policy,new_policy,reason,actor,claimed_actor,source_addr)
				 VALUES ($1::uuid,'pat2403-label','flag','allow','` + pat2403FreeText + `','admin_shared_token','` + pat2403Actor + `','` + pat2403Addr + `')`,
				`INSERT INTO tenant_shadow_it_policy_changes (tenant_id,label,new_policy,actor,claimed_actor,source_addr)
				 VALUES ($1::uuid,'pat2403-label','flag','admin_shared_token','` + pat2403Actor + `','` + pat2403Addr + `')`,
			},
			actorCol: "claimed_actor",
			redacted: []string{"claimed_actor", "source_addr", "reason"},
			forge:    `claimed_actor=NULL,source_addr=NULL,reason=NULL,` + pat2403Marker + `=transaction_timestamp()`,
			markedInsert: `INSERT INTO tenant_shadow_it_policy_changes (tenant_id,label,new_policy,actor,` + pat2403Marker + `)
				 VALUES ($1::uuid,'pat2403-forged','allow','admin_shared_token',now())`,
		},
	}
}

func pat2403Tenant(t *testing.T, name string) string {
	t.Helper()
	id, _, _, err := createTestTenant(env.internalSrv.URL, name)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func pat2403Request(t *testing.T, tenant, method, suffix string, want int) string {
	t.Helper()
	req, err := http.NewRequest(method, env.internalSrv.URL+"/admin/tenants/"+tenant+suffix, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != want {
		t.Fatalf("%s %s: %d want %d: %s", method, suffix, resp.StatusCode, want, body)
	}
	return string(body)
}

func pat2403Seed(t *testing.T, l pat2403Ledger, tenant string) {
	t.Helper()
	for _, sql := range l.inserts {
		if _, err := env.pool.Exec(context.Background(), sql, tenant); err != nil {
			t.Fatalf("%s fixture: %v", l.table, err)
		}
	}
}

// pat2403Rows is every column of a tenant's rows, in id order.
func pat2403Rows(t *testing.T, table, tenant string) string {
	t.Helper()
	var rows string
	if err := env.pool.QueryRow(context.Background(), `SELECT coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY id), '') FROM `+table+` t WHERE tenant_id=$1::uuid`, tenant).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// pat2403Shape is the part of a tenant's rows the purge must leave untouched.
func pat2403Shape(t *testing.T, l pat2403Ledger, tenant string) string {
	t.Helper()
	minus := ""
	for _, col := range append(append([]string{pat2403Marker}, l.redacted...), l.rewritten...) {
		minus += " - '" + col + "'"
	}
	var shape string
	if err := env.pool.QueryRow(context.Background(), `SELECT coalesce(string_agg((to_jsonb(t)`+minus+`)::text, '|' ORDER BY id), '') FROM `+l.table+` t WHERE tenant_id=$1::uuid`, tenant).Scan(&shape); err != nil {
		t.Fatal(err)
	}
	return shape
}

// pat2403Refused asserts a mutation fails as the owner and as the app role,
// even with the purge scope setting imitated for the tenant.
func pat2403Refused(t *testing.T, tenant, sql string) {
	t.Helper()
	ctx := context.Background()
	for _, role := range []string{"owner", "patched"} {
		tx, err := env.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if role == "patched" {
			if _, err := tx.Exec(ctx, "SET LOCAL ROLE patched"); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := tx.Exec(ctx, `SELECT set_config($1,$2,true)`, pat2403PurgeGUC, tenant); err != nil {
			t.Fatal(err)
		}
		var mutErr error
		if strings.Contains(sql, "$1") {
			_, mutErr = tx.Exec(ctx, sql, tenant)
		} else {
			_, mutErr = tx.Exec(ctx, sql)
		}
		if mutErr == nil {
			t.Errorf("ordinary mutation unexpectedly succeeded as %s: %s", role, sql)
		}
		_ = tx.Rollback(ctx)
	}
}

func pat2403OrdinaryMutations(l pat2403Ledger) []string {
	return []string{
		`UPDATE ` + l.table + ` SET ` + l.actorCol + `=NULL WHERE tenant_id=$1::uuid`,
		`UPDATE ` + l.table + ` SET ` + l.actorCol + `='forged@example.invalid' WHERE tenant_id=$1::uuid`,
		`UPDATE ` + l.table + ` SET ` + l.forge + ` WHERE tenant_id=$1::uuid`,
		`DELETE FROM ` + l.table + ` WHERE tenant_id=$1::uuid`,
		`TRUNCATE ` + l.table,
		l.markedInsert,
	}
}

func pat2403ReportRoot(t *testing.T) {
	t.Helper()
	reportRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("REPORT_STORAGE_ROOT", reportRoot)
}

func testTenantPurgeRedactsLedger(t *testing.T, table string) {
	ctx := context.Background()
	var l pat2403Ledger
	for _, candidate := range pat2403Ledgers() {
		if candidate.table == table {
			l = candidate
		}
	}
	if l.table == "" {
		t.Fatalf("no ledger case for %s", table)
	}
	pat2403ReportRoot(t)
	a := pat2403Tenant(t, "PAT-2403 disposable A "+table)
	b := pat2403Tenant(t, "PAT-2403 preserved B "+table)
	pat2403Seed(t, l, a)
	pat2403Seed(t, l, b)

	// agent_release_audit also holds global rows with no tenant: a purge must
	// never reach them.
	globalAction := ""
	globalRow := func() string {
		t.Helper()
		var row string
		if err := env.pool.QueryRow(ctx, `SELECT coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY id), '') FROM agent_release_audit t WHERE tenant_id IS NULL AND action=$1`, globalAction).Scan(&row); err != nil {
			t.Fatal(err)
		}
		return row
	}
	if table == "agent_release_audit" {
		globalAction = "pat2403_global_" + a
		if _, err := env.pool.Exec(ctx, `INSERT INTO agent_release_audit (tenant_id,actor,source,action,details)
			VALUES (NULL,'internal-admin','internal',$1,jsonb_build_object('platform','macos','version','1.2.3'))`, globalAction); err != nil {
			t.Fatal(err)
		}
	}
	beforeGlobal := ""
	if globalAction != "" {
		if beforeGlobal = globalRow(); beforeGlobal == "" {
			t.Fatal("global fixture row missing")
		}
	}

	beforeRowsA, beforeShapeA, beforeB := pat2403Rows(t, table, a), pat2403Shape(t, l, a), pat2403Rows(t, table, b)
	if beforeRowsA == "" || beforeShapeA == "" || beforeB == "" {
		t.Fatal("fixture rows missing")
	}
	if !strings.Contains(beforeRowsA, pat2403Actor) {
		t.Fatal("fixture does not carry the synthetic actor identifier")
	}
	var beforeCount int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM `+table+` WHERE tenant_id=$1::uuid`, a).Scan(&beforeCount); err != nil {
		t.Fatal(err)
	}

	// Ordinary mutation stays refused, even imitating the purge scope.
	for _, sql := range pat2403OrdinaryMutations(l) {
		pat2403Refused(t, a, sql)
	}
	if pat2403Rows(t, table, a) != beforeRowsA || pat2403Rows(t, table, b) != beforeB {
		t.Fatal("refused mutations changed ledger rows")
	}

	pat2403Request(t, a, http.MethodDelete, "", http.StatusOK) // disable before purge
	if body := pat2403Request(t, a, http.MethodDelete, "/purge", http.StatusOK); !strings.Contains(body, `"purged":true`) {
		t.Fatalf("purge did not commit: %s", body)
	}
	var n int
	if err := env.pool.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id=$1::uuid`, a).Scan(&n); err != nil || n != 0 {
		t.Fatalf("tenant A still present: %d %v", n, err)
	}

	// The purged tenant's rows survive, redacted and marked. Read through
	// to_jsonb so a missing marker column reports as a missing marker.
	nulls := ""
	for _, col := range l.redacted {
		nulls += ` AND (to_jsonb(t)->>'` + col + `') IS NULL`
	}
	var total, redacted int
	if err := env.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE (to_jsonb(t)->>'`+pat2403Marker+`') IS NOT NULL`+nulls+`)
		FROM `+table+` t WHERE tenant_id=$1::uuid`, a).Scan(&total, &redacted); err != nil {
		t.Fatal(err)
	}
	if total != beforeCount {
		t.Fatalf("purge deleted or duplicated A ledger rows: %d want %d", total, beforeCount)
	}
	if redacted != total {
		t.Errorf("%s: purged tenant retained %v, or lacks the purge marker (%d of %d rows redacted)", table, l.redacted, redacted, total)
	}
	afterRowsA := pat2403Rows(t, table, a)
	for _, sentinel := range pat2403Sentinels {
		if strings.Contains(afterRowsA, sentinel) {
			t.Errorf("%s: purged tenant's retained rows still contain %q", table, sentinel)
		}
	}
	if got := pat2403Shape(t, l, a); got != beforeShapeA {
		t.Errorf("%s: purge changed non-identifying event fields:\nbefore=%s\nafter=%s", table, beforeShapeA, got)
	}
	if l.check != nil {
		l.check(t, a)
	}
	if afterB := pat2403Rows(t, table, b); afterB != beforeB {
		t.Fatalf("purge of A changed tenant B rows:\nbefore=%s\nafter=%s", beforeB, afterB)
	}
	if globalAction != "" {
		if got := globalRow(); got != beforeGlobal {
			t.Fatalf("purge of A changed a global agent_release_audit row:\nbefore=%s\nafter=%s", beforeGlobal, got)
		}
	}

	// Still append-only afterwards: for the surviving tenant, and for the
	// redacted rows themselves (no un-marking, no rewrite, no delete).
	for _, sql := range pat2403OrdinaryMutations(l) {
		pat2403Refused(t, b, sql)
	}
	for _, sql := range []string{
		`UPDATE ` + table + ` SET ` + l.actorCol + `='forged@example.invalid' WHERE tenant_id=$1::uuid`,
		`UPDATE ` + table + ` SET ` + pat2403Marker + `=NULL WHERE tenant_id=$1::uuid`,
		`UPDATE ` + table + ` SET ` + l.forge + ` WHERE tenant_id=$1::uuid`,
		`DELETE FROM ` + table + ` WHERE tenant_id=$1::uuid`,
	} {
		pat2403Refused(t, a, sql)
	}
	if pat2403Rows(t, table, a) != afterRowsA || pat2403Rows(t, table, b) != beforeB {
		t.Fatal("refused mutations after the purge changed ledger rows")
	}
}

func TestTenantPurgeRedactsSoftwareApprovalDecisions(t *testing.T) {
	testTenantPurgeRedactsLedger(t, "software_approval_decisions")
}

func TestTenantPurgeRedactsDeviceRetirementDecisions(t *testing.T) {
	testTenantPurgeRedactsLedger(t, "device_retirement_decisions")
}

func TestTenantPurgeRedactsJamfWebhookAudit(t *testing.T) {
	testTenantPurgeRedactsLedger(t, "jamf_webhook_audit")
}

func TestTenantPurgeRedactsDeviceListEntryDeletions(t *testing.T) {
	testTenantPurgeRedactsLedger(t, "device_list_entry_deletions")
}

func TestTenantPurgeRedactsAgentReleaseAudit(t *testing.T) {
	testTenantPurgeRedactsLedger(t, "agent_release_audit")
}

func TestTenantPurgeRedactsSoftwareDeclarationDecisions(t *testing.T) {
	testTenantPurgeRedactsLedger(t, "software_declaration_decisions")
}

func TestTenantPurgeRedactsShadowITPolicyChanges(t *testing.T) {
	testTenantPurgeRedactsLedger(t, "tenant_shadow_it_policy_changes")
}

// A redaction that fails in any one ledger must abort the whole purge: the
// tenant, its data and every ledger (including those the purge had already
// redacted earlier in the same transaction) stay exactly as they were.
func TestTenantPurgeAuditLedgerRedactionFailureAbortsPurge(t *testing.T) {
	ctx := context.Background()
	pat2403ReportRoot(t)
	ledgers := pat2403Ledgers()
	c := pat2403Tenant(t, "PAT-2403 failing-cleanup C")
	for _, l := range ledgers {
		pat2403Seed(t, l, c)
	}
	if _, err := env.pool.Exec(ctx, `INSERT INTO devices (tenant_id, serial, os) VALUES ($1::uuid, $1, 'macOS')`, c); err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		t.Helper()
		var all []string
		for _, l := range ledgers {
			all = append(all, l.table+"="+pat2403Rows(t, l.table, c))
		}
		return strings.Join(all, "\n")
	}
	before := snapshot()
	pat2403Request(t, c, http.MethodDelete, "", http.StatusOK) // disable before purge

	for _, l := range ledgers {
		t.Run(l.table, func(t *testing.T) {
			// A constraint that rejects the NULL actor the redaction writes.
			constraint := "pat2403_force_cleanup_failure"
			if _, err := env.pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s ADD CONSTRAINT %s
				CHECK (tenant_id IS DISTINCT FROM '%s'::uuid OR %s IS NOT NULL) NOT VALID`, l.table, constraint, c, l.actorCol)); err != nil {
				t.Fatal(err)
			}
			dropped := false
			drop := func() {
				if dropped {
					return
				}
				dropped = true
				if _, err := env.pool.Exec(ctx, `ALTER TABLE `+l.table+` DROP CONSTRAINT `+constraint); err != nil {
					t.Fatal(err)
				}
			}
			defer drop()
			failed := pat2403Request(t, c, http.MethodDelete, "/purge", http.StatusInternalServerError)
			if strings.Contains(failed, `"purged":true`) || !strings.Contains(failed, "precommit_failed_restored") {
				t.Fatalf("purge did not report a restored pre-commit failure: %s", failed)
			}
			drop()
			var tenantRows, deviceRows int
			if err := env.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM tenants WHERE id=$1::uuid), (SELECT count(*) FROM devices WHERE tenant_id=$1::uuid)`, c).Scan(&tenantRows, &deviceRows); err != nil || tenantRows != 1 || deviceRows != 1 {
				t.Fatalf("failed redaction did not roll back the purge: tenants=%d devices=%d err=%v", tenantRows, deviceRows, err)
			}
			if after := snapshot(); after != before {
				t.Fatalf("failed redaction left a partial purge behind:\nbefore=%s\nafter=%s", before, after)
			}
		})
	}
	if t.Failed() {
		return
	}

	// With nothing forcing a failure the same tenant purges, and every ledger
	// is redacted in the one transaction.
	if body := pat2403Request(t, c, http.MethodDelete, "/purge", http.StatusOK); !strings.Contains(body, `"purged":true`) {
		t.Fatalf("purge did not commit: %s", body)
	}
	after := snapshot()
	for _, sentinel := range pat2403Sentinels {
		if strings.Contains(after, sentinel) {
			t.Errorf("purged tenant's retained ledger rows still contain %q", sentinel)
		}
	}
	for _, l := range ledgers {
		var total, marked int
		if err := env.pool.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE (to_jsonb(t)->>'`+pat2403Marker+`') IS NOT NULL)
			FROM `+l.table+` t WHERE tenant_id=$1::uuid`, c).Scan(&total, &marked); err != nil {
			t.Fatal(err)
		}
		if total != len(l.inserts) || marked != total {
			t.Errorf("%s: %d rows retained, %d marked, want %d of each", l.table, total, marked, len(l.inserts))
		}
	}
}
